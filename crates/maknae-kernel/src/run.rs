//! The `maknaed` run-loop orchestration (T3, spec §6/§6a/§10). This module is I/O
//! and control-flow ONLY — every mutation-gated *decision* lives in `handler.rs`
//! (T1: verb dispatch, whoami view, audit-then-respond gate) or the already-committed
//! `authz.rs`/`groupres.rs` (connection admission). Kept out of the T1 mutation cohort
//! deliberately: it is a driver, not a decision.
//!
//! Three layers, smallest-blast-radius first:
//!
//! - [`handle`] serves ONE authenticated connection (authorize → read → audit →
//!   respond, or fail-closed close). Generic over the stream + audit sink so the
//!   run-loop integration tests drive it over a `duplex`.
//! - [`accept_loop`] is the anti-DoS accept loop: bound concurrency with a semaphore,
//!   audit-and-continue on a surfaced cert-half rejection (NEVER `?` — a bad handshake
//!   must not kill the daemon), fast-close at capacity. Generic over a [`PlaneAccept`]
//!   source so it is testable without a live Vault-backed `PlaneListener`.
//! - [`run`] is the process entrypoint: FIPS install/assert → boot → sink → plane
//!   client → mint → supervisor → bind → accept loop → graceful shutdown.

use std::future::Future;
use std::path::Path;
use std::process::ExitCode;
use std::sync::Arc;
use std::time::Duration;

use maknae_audit_append::{
    AuditEmit, AuditRecord, Integrity, Outcome, Seq, SessionIds, Source, Subject, Where,
};
use maknae_config::TransportConfig;
use maknae_proto::{
    decode_request, encode_response, read_frame, write_frame, Payload, RespResult, Response, Verb,
    PROTOCOL_VERSION,
};
use maknae_vault::{AcceptRejection, AuthenticatedStream, PlaneListener, RejectReason};
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt};
use tokio::sync::Semaphore;
use tokio::task::JoinSet;

use crate::authz::{authorize_connection, ConnDecision};
use crate::groupres::uid_in_maknae_group;
use crate::handler::{build_whoami, dispatch_verb, may_respond, Dispatch};

// ---------------------------------------------------------------------------
// Audit-record construction (AU-3, ADR-0019). These stamp the run-loop's own
// `where`/outcome facts onto the schema owned by `maknae-audit-append`.
// ---------------------------------------------------------------------------

/// The listener-level `where` facts (AU-3c) shared by every record a connection emits.
/// Exposed so the accept-loop integration tests can build one directly.
#[derive(Clone, Debug)]
pub struct WhereCtx {
    pub host: String,
    pub socket: String,
    /// The deployer's AU-3(1) extension object (ADR-0019, `AuditConfig.au3_1`).
    /// Carried here — the accept loop's only handle on the boot-time `AuditConfig` —
    /// so it can be stamped onto every record `accept_loop` builds directly, and
    /// cloned into each spawned [`handle`] call, instead of `make_record` hardcoding
    /// it to an empty object.
    pub au3_1: serde_json::Value,
}

const COMPONENT: &str = "kernel";

#[allow(clippy::too_many_arguments)]
fn make_record(
    event: &str,
    host: &str,
    socket: &str,
    uid: u32,
    gid: Option<u32>,
    pid: Option<u32>,
    peer_uri: Option<&str>,
    session_id: u64,
    seq: u64,
    action: &str,
    result: &str,
    reason: &str,
    posture: &str,
    au3_1: &serde_json::Value,
) -> AuditRecord {
    AuditRecord {
        ts: rfc3339_now(),
        event: event.to_string(),
        where_: Where {
            host: host.to_string(),
            component: COMPONENT.to_string(),
            socket: socket.to_string(),
        },
        source: Source {
            uid,
            gid,
            pid,
            plane_uri_san: peer_uri.map(str::to_string),
        },
        subject: Subject {
            user: None,
            plane_uri_san: peer_uri.map(str::to_string),
        },
        action: action.to_string(),
        outcome: Outcome {
            result: result.to_string(),
            reason: reason.to_string(),
            posture: posture.to_string(),
        },
        session_id,
        seq,
        au3_1: au3_1.clone(),
        integrity: Integrity {
            prev_hash: None,
            sig: None,
        },
    }
}

/// A stable, non-leaky label for each surfaced cert-half rejection (Boundary A: the
/// transport reports the reason; the daemon audits it).
fn reject_reason_str(reason: &RejectReason) -> &'static str {
    match reason {
        RejectReason::Handshake => "tls handshake failed",
        RejectReason::HandshakeTimeout => "handshake timeout",
        RejectReason::WrongPlane => "wrong plane uri-san",
        RejectReason::ExpiredOrInvalidCert => "expired or not-yet-valid cert",
        RejectReason::ChainOrCa => "chain/ca validation failed",
        RejectReason::PeerCredCapture => "peer-credential capture failed",
        RejectReason::Io => "socket accept io error",
    }
}

fn verb_action(verb: &Verb) -> &'static str {
    match verb {
        Verb::Ping => "ping",
        Verb::Whoami => "whoami",
    }
}

// ---------------------------------------------------------------------------
// Layer 1: serve one connection.
// ---------------------------------------------------------------------------

/// Serve exactly ONE request on an already-authenticated `stream`, then close
/// (one-request-per-connection is an anti-DoS cap, spec §6a). Owned arguments so a
/// `tokio::spawn`ed call is `'static`.
///
/// Sequence (spec §6):
/// 1. `authorize_connection(cert_verified = true, in_group)` — the stream exists only
///    because the mTLS cert half already verified, so `cert_verified` is `true`; the
///    group half is the caller-supplied `in_group`. On `Deny` → emit an AU-3
///    `connection`/`deny` record and close WITHOUT reading a verb.
/// 2. Read one frame within `read_timeout_ms`; a timeout / truncation / decode failure
///    emits a `deny` record and closes (no response).
/// 3. Audit-then-respond (ADR-0019): emit the `request` record FIRST; only if that
///    append succeeded (`may_respond(true)`) is the response released. An audit-append
///    failure withholds the response (fail-closed).
#[allow(clippy::too_many_arguments)]
pub async fn handle<S, E>(
    mut stream: S,
    peer_uri: String,
    peer_uid: u32,
    in_group: bool,
    emit: Arc<E>,
    session_id: u64,
    cfg: TransportConfig,
    au3_1: serde_json::Value,
) where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    E: AuditEmit + Send + Sync + 'static,
{
    let seq = Seq::new();
    let host = hostname();
    let socket = cfg.socket_path.display().to_string();

    // 1. Connection admission (cert half already verified by the transport).
    if let ConnDecision::Deny { reason } = authorize_connection(true, in_group) {
        let rec = make_record(
            "connection",
            &host,
            &socket,
            peer_uid,
            None,
            None,
            Some(&peer_uri),
            session_id,
            seq.next(),
            "connect",
            "deny",
            &reason,
            "unauthorized",
            &au3_1,
        );
        if let Err(e) = emit.emit(&rec).await {
            // Mid-life audit-write failure on a deny path is logged but does not change
            // the already-fail-closed outcome (the connection is refused); the permit
            // path gates on audit success, deny paths already deny.
            eprintln!(
                "maknaed: AUDIT WRITE FAILED on connection-deny (group check) for peer_uid={peer_uid} peer_uri={peer_uri} — rejection proceeded without a durable record: {e}"
            );
        }
        let _ = stream.shutdown().await;
        return;
    }

    // 2. Read exactly one request frame, bounded by read_timeout + the frame cap.
    let read = tokio::time::timeout(
        Duration::from_millis(cfg.read_timeout_ms),
        read_frame(&mut stream, cfg.frame_max_bytes),
    )
    .await;
    let body = match read {
        Err(_elapsed) => {
            emit_request_deny(
                &emit,
                &host,
                &socket,
                peer_uid,
                &peer_uri,
                session_id,
                seq.next(),
                "read",
                "read timeout",
                &au3_1,
            )
            .await;
            let _ = stream.shutdown().await;
            return;
        }
        Ok(Err(e)) => {
            emit_request_deny(
                &emit,
                &host,
                &socket,
                peer_uid,
                &peer_uri,
                session_id,
                seq.next(),
                "read",
                &format!("frame read failed: {e}"),
                &au3_1,
            )
            .await;
            let _ = stream.shutdown().await;
            return;
        }
        Ok(Ok(b)) => b,
    };

    let request = match decode_request(&body) {
        Ok(r) => r,
        Err(e) => {
            emit_request_deny(
                &emit,
                &host,
                &socket,
                peer_uid,
                &peer_uri,
                session_id,
                seq.next(),
                "decode",
                &format!("malformed request: {e}"),
                &au3_1,
            )
            .await;
            let _ = stream.shutdown().await;
            return;
        }
    };

    // 3. Audit-then-respond: append the request record, then gate the response on it.
    let rec = make_record(
        "request",
        &host,
        &socket,
        peer_uid,
        None,
        None,
        Some(&peer_uri),
        session_id,
        seq.next(),
        verb_action(&request.verb),
        "permit",
        "served",
        "authorized",
        &au3_1,
    );
    let audit_ok = emit.emit(&rec).await.is_ok();
    if !may_respond(audit_ok) {
        // The audit trail does not durably contain this request — withhold the response.
        let _ = stream.shutdown().await;
        return;
    }

    let payload = match dispatch_verb(&request.verb) {
        Dispatch::Pong => Payload::Pong,
        Dispatch::WhoamiRequested => build_whoami(&peer_uri, peer_uid),
    };
    let response = Response {
        protocol_version: PROTOCOL_VERSION,
        result: RespResult::Ok(payload),
    };
    if let Ok(bytes) = encode_response(&response) {
        let _ = write_frame(&mut stream, &bytes).await;
    }
    let _ = stream.shutdown().await;
}

#[allow(clippy::too_many_arguments)]
async fn emit_request_deny<E: AuditEmit + Send + Sync>(
    emit: &Arc<E>,
    host: &str,
    socket: &str,
    uid: u32,
    peer_uri: &str,
    session_id: u64,
    seq: u64,
    action: &str,
    reason: &str,
    au3_1: &serde_json::Value,
) {
    let rec = make_record(
        "request",
        host,
        socket,
        uid,
        None,
        None,
        Some(peer_uri),
        session_id,
        seq,
        action,
        "deny",
        reason,
        "unauthorized",
        au3_1,
    );
    if let Err(e) = emit.emit(&rec).await {
        // See the group-check deny above: logged, not control-flow-changing — the
        // caller already closes the connection regardless.
        eprintln!(
            "maknaed: AUDIT WRITE FAILED on request-deny ({action}) for peer_uid={uid} peer_uri={peer_uri} — rejection proceeded without a durable record: {e}"
        );
    }
}

// ---------------------------------------------------------------------------
// Layer 2: the accept loop.
// ---------------------------------------------------------------------------

/// One accepted, authenticated connection with the peer facts the daemon polices.
pub struct Conn<S> {
    pub stream: S,
    pub peer_uri: String,
    pub peer_uid: u32,
}

/// The accept surface the run-loop consumes. `PlaneListener` is the production impl;
/// the accept-loop integration tests supply a scripted fake (no live Vault needed).
pub trait PlaneAccept {
    type Stream: AsyncRead + AsyncWrite + Unpin + Send + 'static;
    fn accept(
        &self,
        handshake_timeout: Duration,
    ) -> impl Future<Output = Result<Conn<Self::Stream>, AcceptRejection>> + Send;
}

impl PlaneAccept for PlaneListener {
    type Stream = AuthenticatedStream;
    // `async fn` (not a manual `-> impl Future`): its anonymous future satisfies the
    // trait's `+ Send` bound because the only await (`PlaneListener::accept`) is `Send`.
    async fn accept(
        &self,
        handshake_timeout: Duration,
    ) -> Result<Conn<AuthenticatedStream>, AcceptRejection> {
        let stream = PlaneListener::accept(self, handshake_timeout).await?;
        let peer_uri = stream.peer_uri_san().to_string();
        let peer_uid = stream.peer_creds().uid;
        Ok(Conn {
            stream,
            peer_uri,
            peer_uid,
        })
    }
}

/// The anti-DoS accept loop (spec §6a/§10). Bounds live handlers with a
/// `cfg.max_connections` semaphore; audits-and-continues on a surfaced cert-half
/// rejection (never `?` — a bad handshake must not kill the daemon); fast-closes at
/// capacity. Returns when `shutdown` resolves, after draining in-flight handlers.
pub async fn accept_loop<A, E>(
    acceptor: A,
    emit: Arc<E>,
    session_ids: Arc<SessionIds>,
    cfg: TransportConfig,
    wctx: WhereCtx,
    shutdown: impl Future<Output = ()> + Send,
) where
    A: PlaneAccept + Send + Sync,
    E: AuditEmit + Send + Sync + 'static,
{
    let sem = Arc::new(Semaphore::new(cfg.max_connections as usize));
    let handshake_timeout = Duration::from_millis(cfg.handshake_timeout_ms);
    let mut handlers: JoinSet<()> = JoinSet::new();
    tokio::pin!(shutdown);

    loop {
        tokio::select! {
            biased;
            _ = &mut shutdown => break,
            outcome = acceptor.accept(handshake_timeout) => {
                match outcome {
                    // A surfaced cert-half rejection: audit WHO/WHY and continue (Boundary A).
                    Err(rej) => {
                        let uid = rej.peer_creds.map(|c| c.uid).unwrap_or(0);
                        let gid = rej.peer_creds.and_then(|c| c.gid);
                        let pid = rej.peer_creds.and_then(|c| c.pid);
                        let rec = make_record(
                            "connection", &wctx.host, &wctx.socket, uid, gid, pid, None,
                            session_ids.next_session(), 1, "connect", "deny",
                            reject_reason_str(&rej.reason), "unauthorized", &wctx.au3_1,
                        );
                        if let Err(e) = emit.emit(&rec).await {
                            eprintln!(
                                "maknaed: AUDIT WRITE FAILED on accept-reject (cert half) for peer_uid={uid} — rejection proceeded without a durable record: {e}"
                            );
                        }
                    }
                    Ok(conn) => {
                        let session_id = session_ids.next_session();
                        match Arc::clone(&sem).try_acquire_owned() {
                            // At capacity: fast-close + audit, do NOT serve (anti-DoS).
                            Err(_) => {
                                let rec = make_record(
                                    "connection", &wctx.host, &wctx.socket, conn.peer_uid, None,
                                    None, Some(&conn.peer_uri), session_id, 1, "connect", "deny",
                                    "at capacity", "unauthorized", &wctx.au3_1,
                                );
                                if let Err(e) = emit.emit(&rec).await {
                                    eprintln!(
                                        "maknaed: AUDIT WRITE FAILED on accept-reject (at capacity) for peer_uid={} peer_uri={} — rejection proceeded without a durable record: {e}",
                                        conn.peer_uid, conn.peer_uri
                                    );
                                }
                                let mut stream = conn.stream;
                                let _ = stream.shutdown().await;
                            }
                            Ok(permit) => {
                                // Group half resolved here; fail-closed to false on any
                                // resolution error (handle then Denies + audits).
                                let in_group =
                                    uid_in_maknae_group(conn.peer_uid).unwrap_or(false);
                                let emit = Arc::clone(&emit);
                                let cfg = cfg.clone();
                                let au3_1 = wctx.au3_1.clone();
                                let Conn { stream, peer_uri, peer_uid } = conn;
                                handlers.spawn(async move {
                                    let _permit = permit; // held for the connection's life
                                    handle(stream, peer_uri, peer_uid, in_group, emit,
                                           session_id, cfg, au3_1).await;
                                });
                            }
                        }
                    }
                }
            }
        }
        // Reap finished handlers so the set does not grow unbounded over the daemon's life.
        while handlers.try_join_next().is_some() {}
    }

    // Graceful shutdown: stop accepting (done — we broke the loop), drain in-flight.
    while handlers.join_next().await.is_some() {}
}

// ---------------------------------------------------------------------------
// Layer 3: the process entrypoint.
// ---------------------------------------------------------------------------

/// The `maknaed` entrypoint. Builds a Tokio runtime and drives the async orchestration;
/// any boot/config/credential failure fails closed to [`ExitCode::FAILURE`] (the daemon
/// refuses to start rather than serve without audit or a plane credential). `bins/maknaed`
/// stays a plain `fn main` that returns this `ExitCode`.
pub fn run(config_dir: &Path) -> ExitCode {
    let runtime = match tokio::runtime::Runtime::new() {
        Ok(rt) => rt,
        Err(e) => {
            eprintln!("maknaed: cannot build async runtime: {e}");
            return ExitCode::FAILURE;
        }
    };
    runtime.block_on(async move {
        match run_inner(config_dir).await {
            Ok(()) => ExitCode::SUCCESS,
            Err(e) => {
                eprintln!("maknaed: refusing to start: {e}");
                ExitCode::FAILURE
            }
        }
    })
}

async fn run_inner(config_dir: &Path) -> Result<(), String> {
    // FIPS first (spec §6.1): install the aws-lc-rs FIPS default (once), then assert it —
    // before any crypto/Vault client is built. The assert stays authoritative: on a
    // non-FIPS build the installed default's `.fips()` is false and the daemon refuses.
    maknae_vault::install_default_crypto_provider();
    maknae_vault::assert_fips_provider().map_err(|e| e.to_string())?;

    // Boot Maknae's own config (registers transport/audit as optional — see boot.rs).
    let boot = crate::boot(config_dir).map_err(|e| e.to_string())?;
    let transport = maknae_config::transport_from_section(boot.section("transport"))
        .map_err(|e| e.to_string())?;
    let audit_cfg = maknae_config::audit_from_section(boot.section("audit"), config_dir)
        .map_err(|e| e.to_string())?;

    // Fail-closed audit sink: no durable audit path → do not start (AU-5).
    let sink =
        Arc::new(maknae_audit_append::AuditSink::open(&audit_cfg).map_err(|e| e.to_string())?);

    // Plane credential: authenticate → mint a memory-only leaf, then run the credential
    // supervisor concurrently (renewal + leaf rotation; rotation cadence is checked once
    // per renewal cycle — Task-6 review note).
    let client =
        maknae_vault::PlaneClient::from_config_dir(config_dir, maknae_vault::Plane::Kernel)
            .map_err(|e| e.to_string())?;
    let ca = maknae_vault::load_ca_pin(config_dir).map_err(|e| e.to_string())?;
    client.mint().await.map_err(|e| e.to_string())?;
    let _supervisor = client.spawn_supervisor();

    // Bind the group-gated plane listener and serve.
    let listener =
        PlaneListener::bind(&transport.socket_path, &client, &ca).map_err(|e| e.to_string())?;
    let session_ids = Arc::new(SessionIds::new());
    let wctx = WhereCtx {
        host: hostname(),
        socket: transport.socket_path.display().to_string(),
        au3_1: audit_cfg.au3_1.clone(),
    };
    accept_loop(
        listener,
        Arc::clone(&sink),
        session_ids,
        transport,
        wctx,
        shutdown_signal(),
    )
    .await;

    // Retire the plane credential (revoke token, clear leaf) on the way out.
    client.shutdown().await;
    Ok(())
}

/// Resolve on the first SIGTERM/SIGINT (graceful-shutdown trigger, spec §6).
async fn shutdown_signal() {
    use tokio::signal::unix::{signal, SignalKind};
    let mut term = match signal(SignalKind::terminate()) {
        Ok(s) => s,
        Err(_) => return, // cannot install → treat as immediate shutdown request
    };
    let mut intr = match signal(SignalKind::interrupt()) {
        Ok(s) => s,
        Err(_) => return,
    };
    tokio::select! {
        _ = term.recv() => {}
        _ = intr.recv() => {}
    }
}

/// Best-effort host label for AU-3c. Not security-load-bearing (the security-relevant
/// AU-3 facts are the peer uid / plane URI-SAN / outcome); a missing hostname degrades
/// only correlation, so this never fails the daemon.
fn hostname() -> String {
    std::env::var("HOSTNAME")
        .ok()
        .filter(|h| !h.is_empty())
        .unwrap_or_else(|| "maknaed".to_string())
}

/// RFC3339 UTC timestamp (millisecond precision) with no date-library dependency, via
/// Howard Hinnant's days-from-civil algorithm. `ts` is an AU-3 correlation field, not a
/// security decision — but it is pinned by a unit test so a drift is caught.
fn rfc3339_now() -> String {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default();
    epoch_to_rfc3339(now.as_secs(), now.subsec_millis())
}

fn epoch_to_rfc3339(secs: u64, millis: u32) -> String {
    let days = (secs / 86_400) as i64;
    let rem = secs % 86_400;
    let (hh, mm, ss) = (rem / 3_600, (rem % 3_600) / 60, rem % 60);
    // days since 1970-01-01 → civil (y, m, d).
    let z = days + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = z - era * 146_097; // [0, 146096]
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365; // [0, 399]
    let year = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100); // [0, 365]
    let mp = (5 * doy + 2) / 153; // [0, 11]
    let day = doy - (153 * mp + 2) / 5 + 1; // [1, 31]
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = if month <= 2 { year + 1 } else { year };
    format!("{year:04}-{month:02}-{day:02}T{hh:02}:{mm:02}:{ss:02}.{millis:03}Z")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn epoch_zero_is_unix_epoch() {
        assert_eq!(epoch_to_rfc3339(0, 0), "1970-01-01T00:00:00.000Z");
    }

    #[test]
    fn known_epoch_formats_correctly() {
        // 1_700_000_000 == 2023-11-14T22:13:20Z (a fixed, verifiable instant).
        assert_eq!(
            epoch_to_rfc3339(1_700_000_000, 250),
            "2023-11-14T22:13:20.250Z"
        );
    }

    #[test]
    fn reject_reason_labels_are_distinct_and_nonempty() {
        let all = [
            RejectReason::Handshake,
            RejectReason::HandshakeTimeout,
            RejectReason::WrongPlane,
            RejectReason::ExpiredOrInvalidCert,
            RejectReason::ChainOrCa,
            RejectReason::PeerCredCapture,
            RejectReason::Io,
        ];
        let labels: Vec<&str> = all.iter().map(reject_reason_str).collect();
        for l in &labels {
            assert!(!l.is_empty());
        }
        let mut sorted = labels.clone();
        sorted.sort_unstable();
        sorted.dedup();
        assert_eq!(sorted.len(), labels.len(), "reject labels must be distinct");
    }

    #[test]
    fn verb_action_labels() {
        assert_eq!(verb_action(&Verb::Ping), "ping");
        assert_eq!(verb_action(&Verb::Whoami), "whoami");
    }
}
