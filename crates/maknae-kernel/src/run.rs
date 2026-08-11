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
//! - [`accept_loop`] is the anti-DoS accept loop: accept the raw socket PROMPTLY, then run
//!   the bounded TLS handshake per-connection UNDER the concurrency semaphore (so a stalled
//!   handshake occupies one permit for at most `handshake_timeout`, never the loop itself);
//!   audit-and-continue on a surfaced cert-half rejection (NEVER `?` — a bad handshake must
//!   not kill the daemon), fast-close at capacity. Generic over a [`PlaneAccept`] source so
//!   it is testable without a live Vault-backed `PlaneListener`.
//! - [`run`] is the process entrypoint: FIPS install/assert → boot → sink → plane
//!   client → mint → supervisor → bind → accept loop → graceful shutdown.
//!
//! The accept loop also `select!`s on the credential supervisor's `JoinHandle`
//! (codex round-5 P1, ADR-0018): when token renewal or leaf rotation exhausts its
//! retry window, the supervisor clears the listener's cert slot + identity and its
//! handle resolves. Left unobserved, the accept loop would keep running as a zombie —
//! every new TLS handshake fails (no cert to present) and nothing re-mints. Observing
//! it stops the loop and threads a [`crate::handler::ServeOutcome::SupervisorExited`]
//! out to [`run`], which maps it to `ExitCode::FAILURE` so process supervision
//! restarts the daemon and re-mints on the next boot — NOT an in-place
//! re-authentication.

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
use maknae_vault::{
    AcceptRejection, AuthenticatedStream, PeerCreds, PlaneListener, RawPlaneConn, RejectReason,
};
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt};
use tokio::sync::mpsc;
use tokio::sync::Semaphore;
use tokio::task::JoinSet;

use crate::authz::{authorize_connection, ConnDecision};
use crate::groupres::{maknae_gid, uid_in_maknae_group};
use crate::handler::{build_whoami, dispatch_verb, may_respond, Dispatch, ServeOutcome};

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

/// Bounded depth of the at-capacity audit offload channel (codex round-4 P2). The
/// accept loop hands each capacity-denial audit record to a background drain task via a
/// channel of this depth instead of awaiting the append+fsync inline — so slow/blocked
/// audit storage can never serialize the accept / fast-close path (a held-permit DoS).
/// Small and bounded: if it fills, the loop drops the record (the connection is STILL
/// refused — the raw socket is already closed) rather than block, and counts the drop.
const ATCAP_AUDIT_QUEUE_DEPTH: usize = 256;

/// Bound on awaiting the at-capacity audit drain task during shutdown (codex round-10
/// P1). `ATCAP_AUDIT_QUEUE_DEPTH` bounds how many records can be QUEUED, but not how
/// long each append can TAKE: a stalled audit filesystem (unresponsive network/FUSE
/// mount) can block `emit`/`sync_data` inside the drain task indefinitely, so an
/// unbounded `.await` on it would hang shutdown forever — preventing graceful
/// termination and blocking the supervisor-failure restart path from ever reaching
/// `client.shutdown()` (token revoke) and process exit. On elapse the drain task is
/// aborted so shutdown can proceed; the normal (fast) case still drains fully.
const AUDIT_DRAIN_SHUTDOWN_TIMEOUT: Duration = Duration::from_secs(5);

/// Bound on draining IN-FLIGHT connection handlers at the end of the accept loop.
/// Same class as `AUDIT_DRAIN_SHUTDOWN_TIMEOUT`: each handler performs audit appends
/// (`spawn_blocking` write+fsync under the hood), so a wedged audit filesystem can
/// block a handler indefinitely — an unbounded `join_next()` drain would then hang
/// shutdown BEFORE the at-capacity drain bound is even reached. Sized above the
/// per-connection work bounds (handshake_timeout + read_timeout + response write
/// bound, each ≤ 60s only in pathological configs; defaults total ≤ ~15s).
const HANDLER_DRAIN_SHUTDOWN_TIMEOUT: Duration = Duration::from_secs(10);

/// Bound on the final TLS close (`AsyncWriteExt::shutdown` → close_notify write) of a
/// connection stream. A peer that stops reading can otherwise block the close on a
/// full socket buffer forever, holding the handler (and its semaphore permit) — the
/// same slow-drip permit exhaustion the response-write bound closes. Closing is
/// best-effort (the socket is dropped either way); 1s is generous for ~30 bytes.
const STREAM_CLOSE_TIMEOUT: Duration = Duration::from_secs(1);

/// Bound on the Tokio runtime's own teardown in [`run`] (the LAST line of defense for
/// codex round-11 P1). Aborting an async task can NEVER cancel a `spawn_blocking`
/// operation already running (blocking threads are not abortable), and a dropped
/// `Runtime` waits for them INDEFINITELY by default — so a wedged audit `write_all`/
/// `sync_data` would hang process exit even after every bounded drain above gave up.
/// `Runtime::shutdown_timeout` caps that wait; on elapse the process exits anyway and
/// the OS reclaims the stuck thread. This backstop is what makes every shutdown bound
/// above *terminal* rather than advisory.
const RUNTIME_SHUTDOWN_TIMEOUT: Duration = Duration::from_secs(3);

/// Close `stream` (TLS close_notify + FIN) within [`STREAM_CLOSE_TIMEOUT`], abandoning
/// the close on elapse (the stream is dropped regardless, which closes the fd). Every
/// exit path of [`handle`] funnels through this so no path can hang on a peer that
/// stopped reading.
async fn close_bounded<S: AsyncWrite + Unpin>(stream: &mut S) {
    let _ = tokio::time::timeout(STREAM_CLOSE_TIMEOUT, stream.shutdown()).await;
}

/// How [`await_drain_with_timeout`] resolved.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DrainOutcome {
    /// The drain task finished within the bound (successfully or with an
    /// already-logged internal error) — every queued record was handled.
    Completed,
    /// The drain task did not finish within the bound; it was aborted so the caller
    /// can proceed with shutdown. Some queued audit records may be lost.
    Aborted,
}

/// Await `handle` for at most `timeout`; on elapse, abort it and report so a stalled
/// drain task (e.g. blocked on a wedged audit filesystem) can never hang the caller's
/// shutdown indefinitely. Takes `&mut` (not by value) so a timeout leaves the handle
/// intact to abort — `tokio::time::timeout` only drops its future on elapse, which
/// would merely detach an owned `JoinHandle` and leave the task running unobserved.
async fn await_drain_with_timeout(
    handle: &mut tokio::task::JoinHandle<()>,
    timeout: Duration,
) -> DrainOutcome {
    match tokio::time::timeout(timeout, &mut *handle).await {
        Ok(_joined) => DrainOutcome::Completed,
        Err(_elapsed) => {
            handle.abort();
            DrainOutcome::Aborted
        }
    }
}

/// Drain the in-flight handler `JoinSet` within `timeout`; on elapse, `abort_all` and
/// reap the (now-cancelling) tasks so shutdown can proceed. A handler stuck in a wedged
/// audit append cannot be truly cancelled mid-`spawn_blocking` — the abort stops the
/// async wrapper, and [`RUNTIME_SHUTDOWN_TIMEOUT`] in [`run`] caps the runtime's final
/// wait on the blocking thread itself.
async fn drain_handlers_bounded(handlers: &mut JoinSet<()>, timeout: Duration) -> DrainOutcome {
    let all_joined = tokio::time::timeout(timeout, async {
        while handlers.join_next().await.is_some() {}
    })
    .await;
    match all_joined {
        Ok(()) => DrainOutcome::Completed,
        Err(_elapsed) => {
            handlers.abort_all();
            // Reap the aborted tasks; each resolves promptly with a cancellation
            // JoinError unless it is pinned inside non-abortable blocking I/O — which
            // the runtime-level shutdown bound then caps.
            let _ = tokio::time::timeout(Duration::from_secs(1), async {
                while handlers.join_next().await.is_some() {}
            })
            .await;
            DrainOutcome::Aborted
        }
    }
}

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
/// 2. On `Permit`, emit the `connection`/permit admission record (seq 1) and GATE on
///    it (codex round-8 P1, same `may_respond` gate as step 4): a failed admission
///    append closes the connection WITHOUT reading the request or serving — a session
///    whose admission cannot be durably recorded must never be served, even if the
///    later request-record append would have succeeded.
/// 3. Read one frame within `read_timeout_ms`; a timeout / truncation / decode failure
///    emits a `deny` record and closes (no response).
/// 4. Audit-then-respond (ADR-0019): emit the `request` record; only if that append
///    ALSO succeeded (`may_respond(true)`) is the response released. Both the
///    admission record (step 2) and the request record (step 4) must be durably
///    appended before any response frame is written.
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

    // 1. Connection admission (cert half already verified by the transport). ADR-0019's
    //    scheme audits admission at seq 1 for BOTH outcomes: a deny closes here; a permit
    //    emits a `connection`/permit AU-3 record (seq 1) BEFORE the request is read, and
    //    (codex round-8 P1) GATES on it — the request record follows at seq 2 only once
    //    the admission record is durably written, so a served session's trail is always
    //    complete.
    match authorize_connection(true, in_group) {
        ConnDecision::Deny { reason } => {
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
            close_bounded(&mut stream).await;
            return;
        }
        ConnDecision::Permit => {
            // Admission record at seq 1 (ADR-0019). HARD GATE (codex round-8 P1): unlike
            // the deny paths (nothing to serve there), a permit connection WILL serve a
            // response — so the admission append must succeed before the request is even
            // read, exactly like the request-record gate below. A failed admission append
            // must not be papered over by a later-successful request append.
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
                "permit",
                "admitted",
                "authorized",
                &au3_1,
            );
            let admission_result = emit.emit(&rec).await;
            if !may_respond(admission_result.is_ok()) {
                if let Err(e) = admission_result {
                    eprintln!(
                        "maknaed: admission audit write failed for peer_uid={peer_uid} peer_uri={peer_uri} session_id={session_id} — closing without serving: {e}"
                    );
                }
                close_bounded(&mut stream).await;
                return;
            }
        }
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
            close_bounded(&mut stream).await;
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
            close_bounded(&mut stream).await;
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
            close_bounded(&mut stream).await;
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
        // "authorized", NOT "served": this record is appended BEFORE the response write
        // (audit-then-respond), so it must claim only the authorization + audit-gate
        // facts that are true at append time — a later response-write failure (peer
        // vanished mid-reply) must not leave a durable record over-claiming delivery
        // (codex round-11 P2). Delivery success is observable to the CLIENT, not the trail.
        "authorized",
        "authorized",
        &au3_1,
    );
    let audit_ok = emit.emit(&rec).await.is_ok();
    if !may_respond(audit_ok) {
        // The audit trail does not durably contain this request — withhold the response.
        close_bounded(&mut stream).await;
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
    // Bound the response write by read_timeout_ms (it doubles as the write bound —
    // both cap "how long one peer may hold this connection's permit"): a peer that
    // sends a request and then never reads would otherwise block this write on a full
    // socket buffer forever — a slow-drip permit exhaustion (same DoS class as the
    // inline-handshake and inline-fsync findings). On elapse the connection is simply
    // closed; the request record above already (accurately) says "authorized".
    if let Ok(bytes) = encode_response(&response) {
        let _ = tokio::time::timeout(
            Duration::from_millis(cfg.read_timeout_ms),
            write_frame(&mut stream, &bytes),
        )
        .await;
    }
    close_bounded(&mut stream).await;
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

/// The accept surface the run-loop consumes, split into a prompt raw-accept and a bounded
/// handshake so a stalled TLS handshake cannot serialize acceptance (anti-DoS, spec §6a).
/// `PlaneListener` is the production impl; the accept-loop integration tests supply a
/// scripted fake (no live Vault needed).
pub trait PlaneAccept {
    /// The raw, pre-handshake connection handle (opaque; carried from `accept_raw` into
    /// `finish_handshake`).
    type Raw: Send + 'static;
    type Stream: AsyncRead + AsyncWrite + Unpin + Send + 'static;

    /// Prompt half: take the next raw socket + its peer-creds. Only a raw-accept syscall
    /// error surfaces (`io::Error`); the loop logs-and-continues on it (never `?`).
    fn accept_raw(
        &self,
    ) -> impl Future<Output = Result<(Self::Raw, PeerCreds), std::io::Error>> + Send;

    /// Bounded half: run the mTLS handshake within `handshake_timeout` and report the
    /// authenticated peer, or an `AcceptRejection` carrying the passed-through creds. Run
    /// per-connection UNDER the accept loop's semaphore.
    fn finish_handshake(
        &self,
        raw: Self::Raw,
        peer_creds: PeerCreds,
        handshake_timeout: Duration,
    ) -> impl Future<Output = Result<Conn<Self::Stream>, AcceptRejection>> + Send;
}

impl PlaneAccept for PlaneListener {
    type Raw = RawPlaneConn;
    type Stream = AuthenticatedStream;

    // `async fn` (not a manual `-> impl Future`): its anonymous future satisfies the trait's
    // `+ Send` bound because the only awaits are `Send`.
    async fn accept_raw(&self) -> Result<(RawPlaneConn, PeerCreds), std::io::Error> {
        PlaneListener::accept_raw(self).await
    }

    async fn finish_handshake(
        &self,
        raw: RawPlaneConn,
        peer_creds: PeerCreds,
        handshake_timeout: Duration,
    ) -> Result<Conn<AuthenticatedStream>, AcceptRejection> {
        let stream =
            PlaneListener::finish_handshake(self, raw, peer_creds, handshake_timeout).await?;
        let peer_uri = stream.peer_uri_san().to_string();
        let peer_uid = stream.peer_creds().uid;
        Ok(Conn {
            stream,
            peer_uri,
            peer_uid,
        })
    }
}

/// Turn the credential supervisor's joined outcome into the `VaultError` that caused
/// it to stop — the direct error the supervisor's own future resolved to (e.g.
/// `RenewalExpired`), or, if the task panicked or was cancelled instead of returning
/// normally, a synthesized reason carrying the `JoinError`'s detail. Either way the
/// caller always has a concrete `VaultError` to log and build
/// [`ServeOutcome::SupervisorExited`] from — the accept loop never has to special-case
/// "the handle didn't even resolve to an error value."
fn supervisor_exit_reason(
    joined: Result<maknae_vault::VaultError, tokio::task::JoinError>,
) -> maknae_vault::VaultError {
    match joined {
        Ok(e) => e,
        Err(join_err) => maknae_vault::VaultError::Renew(format!(
            "credential supervisor task did not complete cleanly: {join_err}"
        )),
    }
}

/// The anti-DoS accept loop (spec §6a/§10). Bounds live handlers with a
/// `cfg.max_connections` semaphore; audits-and-continues on a surfaced cert-half
/// rejection (never `?` — a bad handshake must not kill the daemon); fast-closes at
/// capacity. Also `select!`s on `supervisor` (codex round-5 P1): the credential
/// supervisor's handle resolving means it gave up (retry window exhausted) and cleared
/// the listener's cert slot + identity, so continuing to accept would only serve
/// handshakes that can never succeed. Returns the [`ServeOutcome`] that ended the loop
/// — `GracefulShutdown` when `shutdown` resolved first, `SupervisorExited` when the
/// supervisor resolved first — AFTER EITHER WAY draining in-flight handlers (this is
/// itself the graceful-shutdown drain; the caller does not additionally distinguish).
pub async fn accept_loop<A, E>(
    acceptor: A,
    emit: Arc<E>,
    session_ids: Arc<SessionIds>,
    cfg: TransportConfig,
    wctx: WhereCtx,
    shutdown: impl Future<Output = ()> + Send,
    supervisor: tokio::task::JoinHandle<maknae_vault::VaultError>,
) -> ServeOutcome
where
    A: PlaneAccept + Send + Sync + 'static,
    E: AuditEmit + Send + Sync + 'static,
{
    let sem = Arc::new(Semaphore::new(cfg.max_connections as usize));
    let handshake_timeout = Duration::from_millis(cfg.handshake_timeout_ms);
    // Shared so each spawned task can drive the bounded handshake off the accept path.
    let acceptor = Arc::new(acceptor);
    let mut handlers: JoinSet<()> = JoinSet::new();

    // At-capacity audit offload (codex round-4 P2). A capacity denial has NO permit to
    // spawn a per-connection task under, so the pre-fix code appended+fsync'd the audit
    // record INLINE on the accept loop — slow audit storage would then serialize the
    // fast-close path (a few held permits + repeated connections = DoS). Instead: a
    // bounded channel drained by ONE background task does the append off the loop. The
    // accept branch only `try_send`s (never awaits I/O); a full queue drops the record
    // (the connection is already refused) and is counted.
    let (atcap_audit_tx, mut atcap_audit_rx) =
        mpsc::channel::<AuditRecord>(ATCAP_AUDIT_QUEUE_DEPTH);
    let atcap_audit_emit = Arc::clone(&emit);
    let mut atcap_audit_task = tokio::spawn(async move {
        while let Some(rec) = atcap_audit_rx.recv().await {
            if let Err(e) = atcap_audit_emit.emit(&rec).await {
                eprintln!(
                    "maknaed: AUDIT WRITE FAILED on at-capacity denial (background) for peer_uid={} — rejection proceeded without a durable record: {e}",
                    rec.source.uid
                );
            }
        }
    });
    let mut atcap_audit_dropped: u64 = 0;

    tokio::pin!(shutdown);
    tokio::pin!(supervisor);

    let outcome = loop {
        tokio::select! {
            biased;
            _ = &mut shutdown => break ServeOutcome::GracefulShutdown,
            // The credential supervisor gave up (or panicked/was cancelled): it already
            // cleared the listener's cert slot + identity, so every handshake from here
            // on would fail anyway. Stop accepting and surface WHY so the caller can log
            // + exit non-zero (process supervision restarts + re-mints, ADR-0018) instead
            // of running on as a zombie that fast-closes every new connection.
            joined = &mut supervisor => {
                let reason = supervisor_exit_reason(joined);
                eprintln!(
                    "maknaed: credential supervisor exited ({reason}); shutting down so process supervision can restart and re-mint"
                );
                break ServeOutcome::SupervisorExited(reason);
            }
            // Prompt raw accept ONLY: no TLS handshake happens on the loop's thread, so a
            // peer that stalls its handshake can never serialize acceptance (anti-DoS).
            accepted = acceptor.accept_raw() => {
                match accepted {
                    // A raw-accept syscall error (no peer, or peer-cred capture failed): log
                    // and continue. NEVER `?` — a transient accept error must not kill the
                    // daemon. This is the ONLY thing the loop handles inline.
                    Err(e) => {
                        eprintln!("maknaed: raw accept failed (continuing): {e}");
                    }
                    Ok((raw, peer_creds)) => {
                        let session_id = session_ids.next_session();
                        match Arc::clone(&sem).try_acquire_owned() {
                            // At capacity: fast-close + audit from the captured peer-creds
                            // (no handshake ran, so there is no verified URI-SAN yet). Do NOT
                            // serve (anti-DoS). Drop `raw` IMMEDIATELY to close the socket, then
                            // hand the audit record to the BOUNDED background drain (P2): the
                            // accept loop must NEVER await the append+fsync here — with no permit
                            // to spawn under, an inline await would let slow audit storage
                            // serialize the fast-close path (held-permit DoS). `try_send` is
                            // non-blocking; a full queue drops the record (connection already
                            // refused) rather than block, and is counted/logged.
                            Err(_) => {
                                drop(raw);
                                let rec = make_record(
                                    "connection", &wctx.host, &wctx.socket, peer_creds.uid,
                                    peer_creds.gid, peer_creds.pid, None, session_id, 1,
                                    "connect", "deny", "at capacity", "unauthorized", &wctx.au3_1,
                                );
                                if let Err(err) = atcap_audit_tx.try_send(rec) {
                                    atcap_audit_dropped = atcap_audit_dropped.saturating_add(1);
                                    eprintln!(
                                        "maknaed: at-capacity audit offload {} for peer_uid={} — connection still refused, record dropped (total dropped: {atcap_audit_dropped}): {err}",
                                        match err { mpsc::error::TrySendError::Full(_) => "queue full", mpsc::error::TrySendError::Closed(_) => "channel closed" },
                                        peer_creds.uid
                                    );
                                }
                            }
                            Ok(permit) => {
                                let acceptor = Arc::clone(&acceptor);
                                let emit = Arc::clone(&emit);
                                let cfg = cfg.clone();
                                let wctx = wctx.clone();
                                handlers.spawn(async move {
                                    let _permit = permit; // held for the connection's life
                                    // The bounded TLS handshake runs HERE, under the permit —
                                    // a stalled handshake occupies ONE slot for at most
                                    // handshake_timeout, never the accept loop.
                                    match acceptor
                                        .finish_handshake(raw, peer_creds, handshake_timeout)
                                        .await
                                    {
                                        Ok(conn) => {
                                            // Group half resolved here — on the BLOCKING pool, not
                                            // this async worker: `uid_in_maknae_group` makes
                                            // synchronous NSS calls (getgrnam/getpwuid), and a
                                            // stalled directory backend (SSS/LDAP) would otherwise
                                            // pin worker threads until a handful of stuck lookups
                                            // starve the whole runtime — accept loop included
                                            // (same inline-blocking DoS class as the handshake and
                                            // fsync findings). Fail-closed to false on any
                                            // resolution OR join error (handle then Denies+audits).
                                            let uid = conn.peer_uid;
                                            let in_group =
                                                tokio::task::spawn_blocking(move || {
                                                    uid_in_maknae_group(uid)
                                                })
                                                .await
                                                .map(|r| r.unwrap_or(false))
                                                .unwrap_or(false);
                                            handle(
                                                conn.stream, conn.peer_uri, conn.peer_uid, in_group,
                                                emit, session_id, cfg, wctx.au3_1,
                                            )
                                            .await;
                                        }
                                        // A surfaced cert-half rejection: audit WHO/WHY and drop
                                        // (Boundary A — the transport reports, the daemon audits).
                                        Err(rej) => {
                                            let uid = rej.peer_creds.map(|c| c.uid).unwrap_or(0);
                                            let gid = rej.peer_creds.and_then(|c| c.gid);
                                            let pid = rej.peer_creds.and_then(|c| c.pid);
                                            let rec = make_record(
                                                "connection", &wctx.host, &wctx.socket, uid, gid,
                                                pid, None, session_id, 1, "connect", "deny",
                                                reject_reason_str(&rej.reason), "unauthorized",
                                                &wctx.au3_1,
                                            );
                                            if let Err(e) = emit.emit(&rec).await {
                                                eprintln!(
                                                    "maknaed: AUDIT WRITE FAILED on accept-reject (cert half) for peer_uid={uid} — rejection proceeded without a durable record: {e}"
                                                );
                                            }
                                        }
                                    }
                                });
                            }
                        }
                    }
                }
            }
        }
        // Reap finished handlers so the set does not grow unbounded over the daemon's life.
        while handlers.try_join_next().is_some() {}
    };

    // Stopped accepting (done — we broke the loop, either way). Drain in-flight
    // handlers: this IS the graceful-shutdown drain regardless of which outcome ended
    // the loop, so a supervisor exit still lets already-admitted requests finish rather
    // than dropping them mid-flight. BOUNDED (same class as the audit drain below): a
    // handler stuck in a wedged audit append would otherwise hang shutdown here before
    // the at-capacity drain bound is even reached.
    if drain_handlers_bounded(&mut handlers, HANDLER_DRAIN_SHUTDOWN_TIMEOUT).await
        == DrainOutcome::Aborted
    {
        eprintln!(
            "maknaed: in-flight handler drain did not complete within {}s during shutdown; aborting remaining handlers to allow exit",
            HANDLER_DRAIN_SHUTDOWN_TIMEOUT.as_secs()
        );
    }

    // Drain the bounded at-capacity audit offload (P2): drop the sender so the drain
    // task's `recv()` returns `None` once the queue empties, then await it. The queue
    // depth bounds how many records remain, but NOT how long each append can take
    // (codex round-10 P1) — a stalled audit filesystem can block the drain task
    // indefinitely, so the await itself is bounded by `AUDIT_DRAIN_SHUTDOWN_TIMEOUT`
    // and the task aborted on elapse. This single drain point is reached by BOTH
    // outcomes that can end the loop above (`GracefulShutdown` and
    // `SupervisorExited` share it), so bounding it here bounds both shutdown paths:
    // neither can hang here, and both still reach the caller's `client.shutdown()`
    // (token revoke) and process exit.
    drop(atcap_audit_tx);
    if await_drain_with_timeout(&mut atcap_audit_task, AUDIT_DRAIN_SHUTDOWN_TIMEOUT).await
        == DrainOutcome::Aborted
    {
        eprintln!(
            "maknaed: audit drain did not complete within {}s during shutdown; aborting drain to allow exit — some queued audit records may be lost",
            AUDIT_DRAIN_SHUTDOWN_TIMEOUT.as_secs()
        );
    }
    if atcap_audit_dropped > 0 {
        eprintln!(
            "maknaed: at-capacity audit offload dropped {atcap_audit_dropped} record(s) over the daemon's life (audit queue saturation)"
        );
    }

    outcome
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
    let code = runtime.block_on(async move {
        match run_inner(config_dir).await {
            // The T1 `ServeOutcome` → `ExitCode` mapping (codex round-5 P1) decides:
            // `GracefulShutdown` → SUCCESS, `SupervisorExited` → FAILURE (so process
            // supervision restarts the daemon and re-mints; the diagnostic was already
            // logged by the accept loop when the supervisor's handle resolved).
            Ok(outcome) => crate::handler::serve_outcome_to_exit_code(&outcome),
            Err(e) => {
                eprintln!("maknaed: refusing to start: {e}");
                ExitCode::FAILURE
            }
        }
    });
    // TERMINAL shutdown bound (codex round-11 P1). Dropping the runtime would wait
    // INDEFINITELY for outstanding `spawn_blocking` work — and a wedged audit
    // filesystem can pin a blocking thread in `write_all`/`sync_data` forever (task
    // aborts never cancel blocking threads). Cap the wait so SIGTERM handling and the
    // supervisor-failure restart path always reach process exit; on elapse the stuck
    // thread is abandoned to the OS (the fd is closed at process exit anyway).
    runtime.shutdown_timeout(RUNTIME_SHUTDOWN_TIMEOUT);
    code
}

async fn run_inner(config_dir: &Path) -> Result<ServeOutcome, String> {
    // FIPS first (spec §6.1): install the aws-lc-rs FIPS default (once), then assert it —
    // before any crypto/Vault client is built. The assert stays authoritative: on a
    // non-FIPS build the installed default's `.fips()` is false and the daemon refuses.
    maknae_vault::install_default_crypto_provider();
    maknae_vault::assert_fips_provider().map_err(|e| e.to_string())?;

    // Boot Maknae's own config ONCE, registering every section the daemon uses (core +
    // lake + vault + transport + audit — see boot.rs). The booted document backs the
    // plane client below, so no incompatible per-call reload rejects a combined config.
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
    let client = maknae_vault::PlaneClient::from_document(
        boot.document(),
        config_dir,
        maknae_vault::Plane::Kernel,
    )
    .map_err(|e| e.to_string())?;
    let ca = maknae_vault::load_ca_pin(config_dir).map_err(|e| e.to_string())?;
    client.mint().await.map_err(|e| e.to_string())?;
    // Retained (not `let _`, codex round-5 P1): the serve loop selects on this handle
    // alongside the accept path and shutdown, so a supervisor exit (renewal/rotation
    // retry window exhausted → `RenewalExpired`, or a panic/cancellation) stops the
    // daemon instead of leaving the accept loop running as a zombie against a listener
    // whose cert slot the supervisor already cleared.
    let supervisor = client.spawn_supervisor();

    // Once `mint()` succeeds the privileged kernel-plane Vault token is LIVE until
    // lease expiry — so EVERY post-mint startup step (bind, and anything before the
    // serve loop) must revoke it on failure, or the token leaks. Capture the whole
    // post-mint outcome, revoke UNCONDITIONALLY, THEN propagate. (A pre-mint failure
    // above skips revoke — there is nothing minted to revoke. Mirrors `cli.rs::execute`.)
    let outcome = serve_after_mint(&client, &ca, &sink, transport, &audit_cfg, supervisor).await;

    // Retire the plane credential (revoke token, clear leaf) on the way out — on the
    // graceful-shutdown path AND on any post-mint startup failure (e.g. bind).
    client.shutdown().await;
    outcome
}

/// The post-mint startup + serve: bind the group-gated plane listener, then run the
/// accept loop until shutdown OR the credential supervisor exits. Split out so
/// [`run_inner`] can revoke the minted Vault token on EVERY return path (a
/// bind/startup failure here, a graceful shutdown, or a supervisor exit) before
/// propagating — a `?` return from this function still runs the caller's
/// unconditional `client.shutdown().await`. Returns the [`ServeOutcome`] the accept
/// loop stopped on so [`run`] can map it to the process `ExitCode`.
async fn serve_after_mint(
    client: &maknae_vault::PlaneClient,
    ca: &maknae_vault::CaBundle,
    sink: &Arc<maknae_audit_append::AuditSink>,
    transport: maknae_config::TransportConfig,
    audit_cfg: &maknae_config::AuditConfig,
    supervisor: tokio::task::JoinHandle<maknae_vault::VaultError>,
) -> Result<ServeOutcome, String> {
    // Resolve the `maknae` gid BEFORE bind (codex round-7 P1) and fail closed if it can't:
    // under the normal service-account setup `maknaed`'s PRIMARY group is NOT `maknae`
    // (it's a supplementary member), so a bare bind would group-own the 0660 socket by the
    // wrong group and block authorized `maknae`-group peers at the socket layer, before
    // mTLS/`uid_in_maknae_group` ever runs. This `?` propagates through the SAME post-mint
    // failure path as a bind error (see this fn's doc comment): the caller's unconditional
    // `client.shutdown().await` revokes the minted token before returning `ExitCode::FAILURE`.
    let gid =
        maknae_gid().map_err(|e| format!("resolving `maknae` group for the socket: {e:?}"))?;
    let listener = PlaneListener::bind(&transport.socket_path, client, ca, Some(gid))
        .map_err(|e| e.to_string())?;
    let session_ids = Arc::new(SessionIds::new());
    let wctx = WhereCtx {
        host: hostname(),
        socket: transport.socket_path.display().to_string(),
        au3_1: audit_cfg.au3_1.clone(),
    };
    // Install the shutdown-signal handlers EAGERLY, before serving: a failure here is a
    // post-mint startup failure like a bind error (the caller revokes the token and
    // exits non-zero) — never a silently-resolving future that would masquerade as an
    // instant graceful shutdown.
    let shutdown = install_shutdown_signal()?;
    let outcome = accept_loop(
        listener,
        Arc::clone(sink),
        session_ids,
        transport,
        wctx,
        shutdown,
        supervisor,
    )
    .await;
    Ok(outcome)
}

/// Install the SIGTERM/SIGINT handlers EAGERLY and return the future that resolves on
/// the first signal (graceful-shutdown trigger, spec §6). Installation failure is a
/// hard `Err` for the caller to fail closed on: the previous shape installed lazily
/// inside the future and, on failure, RESOLVED it immediately — making the daemon boot
/// and then instantly "gracefully" exit with SUCCESS, which process supervision
/// (Restart=on-failure) would not restart. A daemon that cannot arrange orderly
/// shutdown must refuse to start (revoking its token via the post-mint failure path),
/// not silently morph the failure into a clean exit.
fn install_shutdown_signal() -> Result<impl Future<Output = ()> + Send, String> {
    use tokio::signal::unix::{signal, SignalKind};
    let mut term = signal(SignalKind::terminate())
        .map_err(|e| format!("cannot install SIGTERM handler: {e}"))?;
    let mut intr = signal(SignalKind::interrupt())
        .map_err(|e| format!("cannot install SIGINT handler: {e}"))?;
    Ok(async move {
        tokio::select! {
            _ = term.recv() => {}
            _ = intr.recv() => {}
        }
    })
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

    // codex round-10 P1: `await_drain_with_timeout` must bound the wait on a stalled
    // drain task (abort + report) while still fully draining the normal, fast case.
    // A short real timeout (no `tokio::time::pause`/test-util needed) keeps this
    // deterministic: the never-completing task cannot finish before the bound no
    // matter how slow the test runner is, and the ready task finishes essentially
    // instantly, well inside it.
    #[tokio::test]
    async fn drain_with_timeout_aborts_a_task_that_never_completes() {
        let mut handle = tokio::spawn(std::future::pending::<()>());
        let outcome = await_drain_with_timeout(&mut handle, Duration::from_millis(20)).await;
        assert_eq!(outcome, DrainOutcome::Aborted);
        // The abort() request lands asynchronously; give the runtime a moment to
        // observe it so the assertion isn't racing task teardown.
        for _ in 0..50 {
            if handle.is_finished() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
        assert!(
            handle.is_finished(),
            "aborted task should be finished shortly after Aborted is reported"
        );
    }

    #[tokio::test]
    async fn drain_with_timeout_completes_when_task_finishes_promptly() {
        let mut handle = tokio::spawn(async {});
        let outcome = await_drain_with_timeout(&mut handle, Duration::from_secs(5)).await;
        assert_eq!(outcome, DrainOutcome::Completed);
    }

    // The in-flight HANDLER drain must be bounded for the same reason as the audit
    // drain: a handler wedged in blocking audit I/O would otherwise hang shutdown
    // before any later bound is reached.
    #[tokio::test]
    async fn handler_drain_aborts_handlers_that_never_complete() {
        let mut handlers: JoinSet<()> = JoinSet::new();
        handlers.spawn(std::future::pending::<()>());
        handlers.spawn(async {}); // one completes promptly; one never does
        let outcome = drain_handlers_bounded(&mut handlers, Duration::from_millis(50)).await;
        assert_eq!(outcome, DrainOutcome::Aborted);
        assert!(
            handlers.is_empty(),
            "aborted handlers must be reaped so shutdown proceeds"
        );
    }

    #[tokio::test]
    async fn handler_drain_completes_when_all_handlers_finish() {
        let mut handlers: JoinSet<()> = JoinSet::new();
        handlers.spawn(async {});
        handlers.spawn(async {});
        let outcome = drain_handlers_bounded(&mut handlers, Duration::from_secs(5)).await;
        assert_eq!(outcome, DrainOutcome::Completed);
        assert!(handlers.is_empty());
    }
}
