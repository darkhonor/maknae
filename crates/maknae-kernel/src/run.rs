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
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::sync::{Arc, OnceLock};
use std::time::{Duration, Instant};

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
use crate::blocking_guard::{BlockingBreaker, BreakerAdmission, BreakerTransition};
use crate::boot_gate::authz_boot_gate;
use crate::groupres::{maknae_gid, uid_in_maknae_group};
use crate::handler::{
    build_authz_request, build_whoami, discharge_plan, dispatch_verb, lexical_pregate, may_respond,
    read_refusal_disposition, verb_to_action, Dispatch, ReadRefusal, ServeOutcome,
    AUTHZ_DECIDE_TIMEOUT,
};
use maknae_config::Principal;
use maknae_io::{open_anchor_resolved, AnchorRequired, StrategyPref, Zeroizing};
use maknae_proto::{encode_response_zeroizing, Bytes, ProtoErrCode, ProtoError};
use maknae_security::{combine, finalize, guarded_decide, Authorizer, Decision};

static AUTHZ_DECIDE_BREAKER: OnceLock<Arc<tokio::sync::Mutex<BlockingBreaker>>> = OnceLock::new();
static READ_PEP_BREAKER: OnceLock<Arc<tokio::sync::Mutex<BlockingBreaker>>> = OnceLock::new();
static GROUP_LOOKUP_BREAKER: OnceLock<Arc<tokio::sync::Mutex<BlockingBreaker>>> = OnceLock::new();

fn authz_decide_breaker() -> Arc<tokio::sync::Mutex<BlockingBreaker>> {
    Arc::clone(AUTHZ_DECIDE_BREAKER.get_or_init(|| Arc::new(Default::default())))
}

fn read_pep_breaker() -> Arc<tokio::sync::Mutex<BlockingBreaker>> {
    Arc::clone(READ_PEP_BREAKER.get_or_init(|| Arc::new(Default::default())))
}

fn group_lookup_breaker() -> Arc<tokio::sync::Mutex<BlockingBreaker>> {
    Arc::clone(GROUP_LOOKUP_BREAKER.get_or_init(|| Arc::new(Default::default())))
}

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

/// The effective configuration as `admin.config.show` may disclose it:
/// section → (dotted field path → rendered value).
///
/// **Computed ONCE at boot, already redacted** by
/// `maknae_config::effective_view` — which is the file walk
/// (`Document::disclosable_view`) PLUS the resolved-defaults folds, and is the
/// whole of what the wire carries. Following the pointer to `disclosable_view`
/// alone would miss the folds, `NOT_SET`, and `Disclosure::Omit`. The
/// unredacted `Document` is not reachable from the request path.
///
/// **That is the whole of the claim, and it is narrower than it looks.**
/// `handle` still holds raw configuration in the same scope as the arm that
/// answers `admin.config.show`: `cfg` (the whole `transport` section --
/// `socket_path`, `frame_max_bytes`, `read_timeout_ms`), `au3_1` (the raw
/// `audit.au3_1` object), and `principal` (`name`, `uid`, `home`). That debt has since been
/// PAID once: the `admin.status` arm wanting "which socket am I on?" found
/// `cfg.socket_path` sitting right there, and `listener` is disclosed under
/// ADR-0010 decision 16 with its own argument and its own gate row. **Any
/// further arm that reaches for one of those owes the same argument** -- the boot-time redaction protects
/// the `Document`, not the request path in general.
///
/// It is also a BOOT SNAPSHOT. The authz policy is deliberately re-read per
/// request; this is not. When a config reload lands, this reports stale
/// settings until restart.
pub type ConfigView =
    std::collections::BTreeMap<String, std::collections::BTreeMap<String, String>>;

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

/// Bound on the `maknae`-group membership lookup (NSS: getgrnam/getpwuid, possibly
/// backed by SSSD/LDAP). `spawn_blocking` keeps a stalled lookup off the async workers
/// (so the accept loop stays live), but the handler still awaits the join while holding
/// its connection permit — unbounded, `max_connections` stalled lookups would pin every
/// permit and the daemon would fast-close all further connections until NSS recovered.
/// On elapse the handler FAILS CLOSED (not-a-member → deny + audit) and returns,
/// releasing the permit; the blocking thread finishes in the background (capped at
/// process exit by [`RUNTIME_SHUTDOWN_TIMEOUT`]). 5s is far above any healthy NSS
/// round-trip and below the per-connection read/handshake bounds' order.
const GROUP_LOOKUP_TIMEOUT: Duration = Duration::from_secs(5);

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
    object: Option<&str>,
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
        object: object.map(str::to_string),
        object_requested: None,
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
pub async fn handle<S, E, P>(
    mut stream: S,
    peer_uri: String,
    peer_uid: u32,
    in_group: bool,
    emit: Arc<E>,
    session_id: u64,
    cfg: TransportConfig,
    au3_1: serde_json::Value,
    authorizer: Arc<P>,
    principal: Arc<Principal>,
    config_view: Arc<ConfigView>,
    authz_decide_timeout: Duration,
    // Which boundary accepted this connection. Supplied by the accept loop that owns
    // the listener — never inferred here, and never readable from the request
    // (ADR-0009 decision 8).
    lane: maknae_security::Lane,
    // The descriptors this connection's peer delegated, oldest first. Correlation is
    // FIFO. Exact on Linux (no merging across `sendmsg` boundaries); weaker on
    // macOS, which coalesces — measured. Correct either way for ONE fd-bearing
    // request per connection, which is what today's per-invocation CLI sends;
    // pipelining on macOS is uncharacterised (ADR-0009).
    delegated: maknae_io::DelegatedFds,
) where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    E: AuditEmit + Send + Sync + 'static,
    P: Authorizer + Send + Sync + 'static,
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
                None,
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
                None,
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

    // 2½. THE PDP (spec D2, #77): every request is decided through the seam
    // before the audit-then-respond step. For a Read, the lexical pre-gate
    // runs FIRST — a malformed path is the BadRequest class (like a decode
    // failure), and the PDP is never consulted for it.
    if let Verb::Read { path } = &request.verb {
        if let Err(why) = lexical_pregate(path) {
            let appended = emit_request_outcome(
                &emit,
                &host,
                &socket,
                peer_uid,
                &peer_uri,
                session_id,
                seq.next(),
                verb_to_action(&request.verb),
                Some(path),
                None,
                "deny",
                &format!("path fails canonical pre-gate: {why}"),
                "unauthorized",
                &au3_1,
            )
            .await;
            if may_respond(appended) {
                write_error_bounded(
                    &mut stream,
                    &cfg,
                    ProtoErrCode::BadRequest,
                    "malformed path",
                )
                .await;
            }
            close_bounded(&mut stream).await;
            return;
        }
    }

    // Decide on the BLOCKING pool (the per-request policy re-read is sync file
    // I/O; a stalled /etc/maknae must not pin async workers — the same offload
    // discipline as accept_loop's group lookup), bounded, composed per the
    // parent contract: combine([guarded_decide]) + finalize. Timeout or join
    // failure converts AT THE CALL SITE to a Deny with its own reason
    // (finalize(Indeterminate) would hardcode a different string).
    // ADR-0009: for a term that names an object, the subject's OWN descriptor is the
    // OS's answer. Take and verify it BEFORE the decision — the PDP must decide on the
    // kernel-reported path, not on the string the client chose to send, so the shipped
    // deny list evaluates the object rather than an alias for it (decision 6).
    //
    // Absent or unverifiable means the OS was never established. That is a `Deny` at
    // the PDP (decision 2), never a fallback to a daemon-side open — the fallback IS
    // the confused deputy this ADR exists to close.
    let verified_read: Option<(std::os::fd::OwnedFd, String)> = match &request.verb {
        maknae_proto::Verb::Read { .. } => delegated.take().and_then(|fd| {
            // No budget here: oversize must not become an authorization failure.
            let plan = crate::handler::delegated_plan(&principal.home, principal.uid, None);
            maknae_io::verify_delegated(std::os::fd::AsFd::as_fd(&fd), plan)
                .ok()
                .map(|v| (fd, v.path.to_string_lossy().into_owned()))
        }),
        _ => None,
    };
    let sec_req = build_authz_request(
        &request.verb,
        peer_uid,
        lane,
        verified_read.as_ref().map(|(_, p)| p.as_str()),
    );
    let authz_breaker = authz_decide_breaker();
    let authz_admission = { authz_breaker.lock().await.begin_attempt_at(Instant::now()) };
    let verdict = match authz_admission {
        BreakerAdmission::RefuseOpen => maknae_security::Verdict::Deny {
            reason: "authorization decision circuit breaker open".into(),
        },
        BreakerAdmission::RefuseAtCapacity => maknae_security::Verdict::Deny {
            reason: "authorization decision blocking worker budget exhausted".into(),
        },
        BreakerAdmission::Admit => {
            let decided = {
                let a = Arc::clone(&authorizer);
                tokio::time::timeout(
                    authz_decide_timeout,
                    tokio::task::spawn_blocking(move || {
                        combine(vec![guarded_decide(&*a, &sec_req)])
                    }),
                )
                .await
            };
            match decided {
                Ok(Ok(v)) => {
                    authz_breaker.lock().await.record_success();
                    v
                }
                Ok(Err(_join)) => {
                    // Join failure means the blocking worker ended instead of
                    // being orphaned; fail closed for this request, but do not
                    // count it against the timeout breaker.
                    authz_breaker.lock().await.record_success();
                    maknae_security::Verdict::Deny {
                        reason: "authorization decision failed (join)".into(),
                    }
                }
                Err(_elapsed) => {
                    if authz_breaker.lock().await.record_timeout_at(Instant::now())
                        == BreakerTransition::Tripped
                    {
                        eprintln!(
                        "maknaed: authorization decision circuit breaker tripped after repeated {}s blocking timeouts — failing closed without spawning more policy work",
                        authz_decide_timeout.as_secs()
                    );
                    }
                    maknae_security::Verdict::Deny {
                        reason: "authorization decision timed out".into(),
                    }
                }
            }
        }
    };
    // The trail's AU-3 object is the path the DECISION was made on — the kernel's
    // answer for the subject's delegated descriptor (ADR-0009 decision 6) — falling
    // back to the client's own string when no descriptor was established, which is
    // then all the trail has to record.
    let object_path = match &request.verb {
        Verb::Read { path } => Some(
            verified_read
                .as_ref()
                .map(|(_, real)| real.clone())
                .unwrap_or_else(|| path.clone()),
        ),
        _ => None,
    };
    // Recorded ONLY on divergence, so its presence stays a signal rather than noise:
    // a client naming one object while a different one is evaluated is either
    // following a symlink it did not expect, or probing for one.
    let object_asked = match (&request.verb, &object_path) {
        (Verb::Read { path }, Some(decided)) if decided != path => Some(path.clone()),
        _ => None,
    };
    let obligations = match finalize(verdict) {
        Decision::Deny { reason } => {
            // Deny: the reason goes to the TRAIL, never the wire (spec D3);
            // the generic Unauthorized frame is released only after the deny
            // record is durably appended — no frame without a record of the
            // decision that produced it.
            let appended = emit_request_outcome(
                &emit,
                &host,
                &socket,
                peer_uid,
                &peer_uri,
                session_id,
                seq.next(),
                verb_to_action(&request.verb),
                object_path.as_deref(),
                object_asked.as_deref(),
                "deny",
                &reason,
                "unauthorized",
                &au3_1,
            )
            .await;
            if may_respond(appended) {
                write_error_bounded(
                    &mut stream,
                    &cfg,
                    ProtoErrCode::Unauthorized,
                    "not authorized",
                )
                .await;
            }
            close_bounded(&mut stream).await;
            return;
        }
        Decision::Permit { obligations } => obligations,
    };

    // Obligation discharge (spec D3): the registered handler set is exactly
    // {"audit"} — honored by the audit-then-respond gate below. Anything else
    // fails closed to the same deny path.
    if let Err(unhonorable) = discharge_plan(&obligations) {
        let appended = emit_request_outcome(
            &emit,
            &host,
            &socket,
            peer_uid,
            &peer_uri,
            session_id,
            seq.next(),
            verb_to_action(&request.verb),
            object_path.as_deref(),
            object_asked.as_deref(),
            "deny",
            &format!("unhonorable obligation: {}", unhonorable.0),
            "unauthorized",
            &au3_1,
        )
        .await;
        if may_respond(appended) {
            write_error_bounded(
                &mut stream,
                &cfg,
                ProtoErrCode::Unauthorized,
                "not authorized",
            )
            .await;
        }
        close_bounded(&mut stream).await;
        return;
    }

    // 3. Dispatch + audit-then-respond. The request record is appended BEFORE
    // the response write and claims only authorization facts true at append
    // time; for reads the record additionally carries the outcome the PEP
    // actually produced (the invariant gates DISCLOSURE — content read into
    // daemon memory whose record cannot append is dropped undisclosed).
    match dispatch_verb(&request.verb) {
        Dispatch::NoBehaviour => {
            // Decided and PERMITTED above; the term simply has no behaviour.
            // Same audit-then-respond gate as every sibling path — the record
            // must be durable before any frame is released (ADR-0019).
            let appended = emit_request_outcome(
                &emit,
                &host,
                &socket,
                peer_uid,
                &peer_uri,
                session_id,
                seq.next(),
                verb_to_action(&request.verb),
                object_path.as_deref(),
                object_asked.as_deref(),
                "permit",
                "permitted; term not implemented",
                "not-implemented",
                &au3_1,
            )
            .await;
            if may_respond(appended) {
                write_error_bounded(
                    &mut stream,
                    &cfg,
                    ProtoErrCode::NotImplemented,
                    "not implemented",
                )
                .await;
            }
            close_bounded(&mut stream).await;
            return;
        }
        Dispatch::Pong
        | Dispatch::WhoamiRequested
        | Dispatch::ConfigShowRequested
        | Dispatch::StatusRequested
        | Dispatch::SubjectListRequested => {
            let appended = emit_request_outcome(
                &emit,
                &host,
                &socket,
                peer_uid,
                &peer_uri,
                session_id,
                seq.next(),
                verb_to_action(&request.verb),
                None,
                None,
                "permit",
                "authorized",
                "authorized",
                &au3_1,
            )
            .await;
            if !may_respond(appended) {
                close_bounded(&mut stream).await;
                return;
            }
            let payload = match dispatch_verb(&request.verb) {
                Dispatch::Pong => Payload::Pong,
                Dispatch::WhoamiRequested => build_whoami(&peer_uri, peer_uid),
                // Already redacted at boot; this arm only hands it over. No
                // redaction happens here, deliberately -- see `ConfigView`.
                Dispatch::ConfigShowRequested => Payload::ConfigView((*config_view).clone()),
                Dispatch::StatusRequested => Payload::Status(maknae_proto::StatusView {
                    version: env!("CARGO_PKG_VERSION").to_string(),
                    protocol_version: PROTOCOL_VERSION,
                    listener: cfg.socket_path.display().to_string(),
                    // Asked of the PDP, not hardcoded: with the classification
                    // library present the deciding backend is not `-basic`, and
                    // an operator debugging a verdict needs to know which one
                    // produced it.
                    // Behind the panic boundary, like every other direct
                    // backend invocation: this is inline on the async worker,
                    // and an unguarded panic here unwinds AFTER the audit
                    // record already said permit/authorized.
                    authz_backend: maknae_security::guarded_backend_name(&*authorizer),
                }),
                // LIVE, via the seam. `None` means the backend cannot
                // enumerate, and that is reported as unavailable below --
                // never as an empty list, which would claim "no bindings
                // exist" and is a different, dangerous answer.
                // OFFLOADED, bounded, and breaker-admitted -- the SAME
                // discipline the decide path gets 250 lines above, and for the
                // same reason stated there: `subjects()` reaches
                // `load_authz`, which is sync file I/O on /etc/maknae. Called
                // inline it pins a tokio worker for as long as that read
                // blocks, and N granted calls against a wedged NFS/FUSE mount
                // starve the runtime -- with the breaker unable to trip,
                // because it never sees them.
                //
                // The seam's `-> Option<..>` signature is what made this look
                // synchronous-and-cheap at the call site. It is a policy file
                // read.
                Dispatch::SubjectListRequested => {
                    let subj_breaker = authz_decide_breaker();
                    let admission = { subj_breaker.lock().await.begin_attempt_at(Instant::now()) };
                    let enumerated = match admission {
                        BreakerAdmission::RefuseOpen | BreakerAdmission::RefuseAtCapacity => None,
                        BreakerAdmission::Admit => {
                            let a = Arc::clone(&authorizer);
                            let out = tokio::time::timeout(
                                authz_decide_timeout,
                                tokio::task::spawn_blocking(move || {
                                    maknae_security::guarded_subjects(&*a)
                                }),
                            )
                            .await;
                            match out {
                                Ok(Ok(v)) => {
                                    subj_breaker.lock().await.record_success();
                                    v
                                }
                                // A JOIN failure is not counted against the
                                // breaker -- same as the decide path, where a
                                // panicked/cancelled task is not evidence that
                                // the filesystem is wedged.
                                Ok(Err(_join)) => {
                                    subj_breaker.lock().await.record_success();
                                    None
                                }
                                // A TIMEOUT is, and it is the signal that
                                // trips: repeated blocking reads against a
                                // stalled mount must stop spawning more.
                                Err(_elapsed) => {
                                    if subj_breaker.lock().await.record_timeout_at(Instant::now())
                                        == BreakerTransition::Tripped
                                    {
                                        eprintln!(
                                            "maknaed: authorization decision circuit breaker tripped after repeated {}s blocking timeouts — failing closed without spawning more policy work",
                                            authz_decide_timeout.as_secs()
                                        );
                                    }
                                    None
                                }
                            }
                        }
                    };
                    match enumerated {
                        Some(mut b) => {
                            b.sort_by(|x, y| x.role.cmp(&y.role));
                            Payload::SubjectList(
                                b.into_iter()
                                    .map(|s| maknae_proto::RoleBindingView {
                                        role: s.role,
                                        members: s.members,
                                    })
                                    .collect(),
                            )
                        }
                        None => {
                            // A SECOND record, correcting the posture.
                            //
                            // The record for this request was appended as
                            // `permit / authorized` before dispatch, and the
                            // enumeration then refused -- so the trail asserted
                            // an authorized-and-SERVED admin.subject.list for a
                            // request whose caller received `Internal`.
                            // ADR-0019 pins `unavailable` in the posture domain
                            // precisely so a Permit-then-not-performed cannot
                            // read as a completed action, and the read PEP maps
                            // these same four conditions -- breaker open, at
                            // capacity, timeout, join failure -- to
                            // `deny`/`unavailable`.
                            let _ = emit_request_outcome(
                                &emit,
                                &host,
                                &socket,
                                peer_uid,
                                &peer_uri,
                                session_id,
                                seq.next(),
                                verb_to_action(&request.verb),
                                None,
                                None,
                                "deny",
                                "binding enumeration unavailable",
                                "unavailable",
                                &au3_1,
                            )
                            .await;
                            // No `may_respond(true)` guard here: it is a literal
                            // `if true` -- control only reaches this arm after the
                            // `!may_respond(appended)` return above, so `appended`
                            // is already true. A constant-true call shaped like an
                            // audit gate is worse than no gate; it reads as a
                            // control on a security surface and gates nothing.
                            write_error_bounded(
                                &mut stream,
                                &cfg,
                                ProtoErrCode::Internal,
                                "binding enumeration unavailable",
                            )
                            .await;
                            close_bounded(&mut stream).await;
                            return;
                        }
                    }
                }
                Dispatch::ReadRequested(_) => unreachable!("outer match excludes reads"),
                Dispatch::NoBehaviour => unreachable!("outer match routes NoBehaviour"),
            };
            let response = Response {
                protocol_version: PROTOCOL_VERSION,
                result: RespResult::Ok(payload),
            };
            // Bound the response write by read_timeout_ms (it doubles as the
            // write bound — both cap how long one peer may hold this permit).
            if let Ok(bytes) = encode_response(&response) {
                // SIZE-BOUNDED, like the read path. TWO payloads here scale
                // with input: `ConfigView` (one entry per config leaf) and
                // `SubjectList` (one per `bindings:` entry). `Pong` and
                // `Whoami` never approach the cap, so the check is free for
                // them and load-bearing for the other two.
                //
                // Without it the daemon writes an oversized frame that the
                // client's own `read_frame(frame_max_bytes)` refuses as a
                // framing `Oversize` — an authorized request failing with an
                // undiagnosable transport error, after its audit record already
                // said "permit / authorized". The read PEP's stance applies
                // unchanged: a PERMIT whose delivery is refused is refused
                // EXPLICITLY, never truncated and never silently oversized.
                if bytes.len() > cfg.frame_max_bytes {
                    // A CORRECTIVE record, the same shape the enumeration-
                    // unavailable branch uses 60 lines above -- and for the
                    // identical reason, which this arm missed because it emits
                    // the record BEFORE discovering the oversize. (The read PEP
                    // never has this problem: `read_budget` bounds the read, so
                    // it computes the refusal first and emits once.)
                    //
                    // Without it the trail asserts an authorized-and-SERVED
                    // disclosure for a caller that received TooLarge. ADR-0019
                    // pins `refused-oversize` for exactly this, and the read
                    // PEP already uses it; `permit` is retained because the
                    // decision WAS a permit -- only the delivery was refused.
                    let _ = emit_request_outcome(
                        &emit,
                        &host,
                        &socket,
                        peer_uid,
                        &peer_uri,
                        session_id,
                        seq.next(),
                        verb_to_action(&request.verb),
                        None,
                        None,
                        "permit",
                        "delivery refused: response exceeds the frame limit",
                        "refused-oversize",
                        &au3_1,
                    )
                    .await;
                    write_error_bounded(
                        &mut stream,
                        &cfg,
                        ProtoErrCode::TooLarge,
                        "response exceeds the configured frame limit",
                    )
                    .await;
                    close_bounded(&mut stream).await;
                    return;
                }
                let _ = tokio::time::timeout(
                    Duration::from_millis(cfg.read_timeout_ms),
                    write_frame(&mut stream, &bytes),
                )
                .await;
            }
        }
        // UNUSED, and that is the design showing through: the read arm no longer
        // touches the client's string for anything. The object it reads is the
        // descriptor the subject delegated, and the path it audits is the kernel's
        // answer for that descriptor (`object_path`, computed before the decision).
        // If this binding is ever needed again, something has started trusting the
        // client's name (ADR-0009 decision 6).
        Dispatch::ReadRequested(_client_path) => {
            // The read PEP (spec D5): per-request anchor at the enrolled home,
            // named requirements, bounded on the blocking pool like the decide.
            let budget = crate::handler::read_budget(cfg.frame_max_bytes);
            let read_breaker = read_pep_breaker();
            let read_admission = { read_breaker.lock().await.begin_attempt_at(Instant::now()) };
            let read_result = match read_admission {
                BreakerAdmission::RefuseOpen => {
                    Err(ReadRefusal::Unavailable("read circuit breaker open".into()))
                }
                BreakerAdmission::RefuseAtCapacity => Err(ReadRefusal::Unavailable(
                    "read blocking worker budget exhausted".into(),
                )),
                BreakerAdmission::Admit => {
                    let outcome = {
                        let home = principal.home.clone();
                        let owner = principal.uid;
                        // Permitted implies verified: the PDP only says yes on this
                        // term when a descriptor was established above.
                        let fd = verified_read.map(|(fd, _)| fd);
                        tokio::time::timeout(
                            authz_decide_timeout,
                            tokio::task::spawn_blocking(move || read_pep(fd, &home, owner, budget)),
                        )
                        .await
                    };
                    match outcome {
                        Ok(Ok(r)) => {
                            read_breaker.lock().await.record_success();
                            r
                        }
                        Ok(Err(_join)) => {
                            // The read worker ended instead of being orphaned;
                            // fail closed without tripping the timeout breaker.
                            read_breaker.lock().await.record_success();
                            Err(ReadRefusal::JoinFailed)
                        }
                        Err(_elapsed) => {
                            if read_breaker.lock().await.record_timeout_at(Instant::now())
                                == BreakerTransition::Tripped
                            {
                                eprintln!(
                                "maknaed: read PEP circuit breaker tripped after repeated {}s blocking timeouts — failing closed without spawning more target-read work",
                                authz_decide_timeout.as_secs()
                            );
                            }
                            Err(ReadRefusal::TimedOut)
                        }
                    }
                }
            };
            match read_result {
                Ok(content) => {
                    let content_len = content.len();
                    let appended = emit_request_outcome(
                        &emit,
                        &host,
                        &socket,
                        peer_uid,
                        &peer_uri,
                        session_id,
                        seq.next(),
                        verb_to_action(&request.verb),
                        object_path.as_deref(),
                        object_asked.as_deref(),
                        "permit",
                        "authorized",
                        "authorized",
                        &au3_1,
                    )
                    .await;
                    if !may_respond(appended) {
                        // Content stays in daemon memory and is dropped
                        // (zeroized) undisclosed — the invariant holds.
                        close_bounded(&mut stream).await;
                        return;
                    }
                    let response = Response {
                        protocol_version: PROTOCOL_VERSION,
                        result: RespResult::Ok(Payload::ReadContent(Bytes::new(content))),
                    };
                    // Zeroizing, pre-sized encode (spec D5): no realloc, no
                    // un-zeroized partial copies; buffer zeroizes after write.
                    if let Ok(bytes) = encode_response_zeroizing(
                        &response,
                        content_len + crate::handler::FRAME_ENVELOPE_MARGIN as usize,
                    ) {
                        let _ = tokio::time::timeout(
                            Duration::from_millis(cfg.read_timeout_ms),
                            write_frame(&mut stream, &bytes),
                        )
                        .await;
                    }
                }
                Err(refusal) => {
                    let (result, reason, posture, code, msg) = read_refusal_disposition(&refusal);
                    let appended = emit_request_outcome(
                        &emit,
                        &host,
                        &socket,
                        peer_uid,
                        &peer_uri,
                        session_id,
                        seq.next(),
                        verb_to_action(&request.verb),
                        object_path.as_deref(),
                        object_asked.as_deref(),
                        result,
                        &reason,
                        posture,
                        &au3_1,
                    )
                    .await;
                    if may_respond(appended) {
                        write_error_bounded(&mut stream, &cfg, code, msg).await;
                    }
                }
            }
        }
    }
    close_bounded(&mut stream).await;
}

/// The blocking half of the read PEP: THIN orchestration over the T1
/// decision logic (`handler::delegated_plan` names every requirement;
/// `handler::map_read_error` types every refusal) — this fn only performs
/// the two maknae-io calls the plan prescribes. Per-request anchor open:
/// the same Zero-Trust cadence as the policy re-read.
fn read_pep(
    fd: Option<std::os::fd::OwnedFd>,
    home: &std::path::Path,
    owner_uid: u32,
    budget: u64,
) -> Result<Zeroizing<Vec<u8>>, ReadRefusal> {
    // Unreachable on a permit — the gate denies without a verified descriptor — but
    // named rather than unwrapped, because "cannot happen" is how fail-open arrives.
    let fd = fd.ok_or_else(|| ReadRefusal::Refused("no delegated descriptor".into()))?;
    // Re-verified inside `read_delegated`, immediately before the bytes are taken. If
    // the object changed between the decision and the read, the read refuses: this is
    // the TOCTOU backstop, adapted — there is no second OPEN to enforce at, so the
    // check rides the descriptor that was already pinned.
    maknae_io::read_delegated(
        &fd,
        crate::handler::delegated_plan(home, owner_uid, Some(budget)),
    )
    .map(|(_path, bytes)| bytes)
    .map_err(crate::handler::map_read_error)
}

/// Write one generic error frame, bounded like every response write. The
/// message is ALWAYS a fixed generic string — reasons live in the trail.
async fn write_error_bounded<S>(
    stream: &mut S,
    cfg: &TransportConfig,
    code: ProtoErrCode,
    msg: &str,
) where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let response = Response {
        protocol_version: PROTOCOL_VERSION,
        result: RespResult::Err(ProtoError {
            code,
            message: msg.to_string(),
        }),
    };
    if let Ok(bytes) = encode_response(&response) {
        let _ = tokio::time::timeout(
            Duration::from_millis(cfg.read_timeout_ms),
            write_frame(stream, &bytes),
        )
        .await;
    }
}

/// The RESULT-RETURNING request-record emitter the decision paths gate on
/// (spec D3): unlike `emit_request_deny` (deliberately fire-and-forget for
/// the pre-decision paths, where nothing is served), every caller here has a
/// frame to release and must know the append landed. Returns append success.
#[allow(clippy::too_many_arguments)]
async fn emit_request_outcome<E: AuditEmit + Send + Sync>(
    emit: &Arc<E>,
    host: &str,
    socket: &str,
    uid: u32,
    peer_uri: &str,
    session_id: u64,
    seq: u64,
    action: &str,
    object: Option<&str>,
    // What the client asked for, when it is NOT what was decided. `None` in the
    // ordinary case so presence stays meaningful (ADR-0009 decision 6).
    object_requested: Option<&str>,
    result: &str,
    reason: &str,
    posture: &str,
    au3_1: &serde_json::Value,
) -> bool {
    let mut rec = make_record(
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
        object,
        result,
        reason,
        posture,
        au3_1,
    );
    rec.object_requested = object_requested.map(str::to_string);
    match emit.emit(&rec).await {
        Ok(()) => true,
        Err(e) => {
            eprintln!(
                "maknaed: AUDIT WRITE FAILED on request outcome ({action}/{result}) for peer_uid={uid} peer_uri={peer_uri} session_id={session_id} — withholding the frame: {e}"
            );
            false
        }
    }
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
        None,
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
    /// Descriptors this peer delegated over `SCM_RIGHTS`, collected beneath the TLS
    /// layer (ADR-0009). A property of the accepted CONNECTION, like the peer facts
    /// above — and like them, established by the door rather than read off the wire.
    pub delegated: maknae_io::DelegatedFds,
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
        let delegated = stream.delegated();
        Ok(Conn {
            stream,
            peer_uri,
            peer_uid,
            delegated,
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
#[allow(clippy::too_many_arguments)]
pub async fn accept_loop<A, E, P>(
    acceptor: A,
    emit: Arc<E>,
    session_ids: Arc<SessionIds>,
    cfg: TransportConfig,
    wctx: WhereCtx,
    shutdown: impl Future<Output = ()> + Send,
    supervisor: tokio::task::JoinHandle<maknae_vault::VaultError>,
    authorizer: Arc<P>,
    principal: Arc<Principal>,
    config_view: Arc<ConfigView>,
) -> ServeOutcome
where
    A: PlaneAccept + Send + Sync + 'static,
    E: AuditEmit + Send + Sync + 'static,
    P: Authorizer + Send + Sync + 'static,
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
                                    "connect", None, "deny", "at capacity", "unauthorized", &wctx.au3_1,
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
                                let authorizer = Arc::clone(&authorizer);
                                let principal = Arc::clone(&principal);
                                let config_view = Arc::clone(&config_view);
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
                                            // Bounded join: a stalled NSS backend must not
                                            // pin this permit indefinitely — on elapse,
                                            // fail closed (deny + audit) and release the
                                            // permit; the orphaned blocking lookup finishes
                                            // in the background.
                                            let group_breaker = group_lookup_breaker();
                                            let now = Instant::now();
                                            let admission =
                                                group_breaker.lock().await.begin_attempt_at(now);
                                            let in_group = match admission {
                                                BreakerAdmission::RefuseOpen => {
                                                    if group_breaker
                                                        .lock()
                                                        .await
                                                        .should_log_refusal_at(now)
                                                    {
                                                        eprintln!(
                                                            "maknaed: `maknae` group lookup circuit breaker open for uid={uid} — failing closed without spawning more NSS work"
                                                        );
                                                    }
                                                    false
                                                }
                                                BreakerAdmission::RefuseAtCapacity => false,
                                                BreakerAdmission::Admit => match tokio::time::timeout(
                                                    GROUP_LOOKUP_TIMEOUT,
                                                    tokio::task::spawn_blocking(move || {
                                                        uid_in_maknae_group(uid)
                                                    }),
                                                )
                                                .await
                                                {
                                                    Ok(join) => {
                                                        // The NSS worker returned or panicked;
                                                        // either way it is no longer an orphan.
                                                        group_breaker.lock().await.record_success();
                                                        join.map(|r| r.unwrap_or(false))
                                                            .unwrap_or(false)
                                                    }
                                                    Err(_elapsed) => {
                                                        if group_breaker
                                                            .lock()
                                                            .await
                                                            .record_timeout_at(Instant::now())
                                                            == BreakerTransition::Tripped
                                                        {
                                                            eprintln!(
                                                                "maknaed: `maknae` group lookup circuit breaker tripped after repeated {}s blocking timeouts — failing closed without spawning more NSS work",
                                                                GROUP_LOOKUP_TIMEOUT.as_secs()
                                                            );
                                                        } else {
                                                            eprintln!(
                                                                "maknaed: `maknae` group lookup for uid={uid} stalled past {}s — failing closed (deny)",
                                                                GROUP_LOOKUP_TIMEOUT.as_secs()
                                                            );
                                                        }
                                                        false
                                                    }
                                                },
                                            };
                                            // The one production binding of the
                                            // T1-pinned decide-timeout const —
                                            // accepted-documented as ungated T3
                                            // (value pinned in handler.rs, behavior
                                            // proven in the handle() suite).
                                            handle(
                                                conn.stream, conn.peer_uri, conn.peer_uid, in_group,
                                                emit, session_id, cfg, wctx.au3_1,
                                                authorizer, principal,
                                                config_view,
                                                AUTHZ_DECIDE_TIMEOUT,
                                                // THIS accept loop owns the on-host
                                                // client listener, so every connection
                                                // it yields is local by construction.
                                                // When #114 splits listeners, the
                                                // machine/gateway loop passes its own —
                                                // the lane is a property of the door,
                                                // not of anything read off the wire.
                                                maknae_security::Lane::Local,
                                                conn.delegated,
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
                                                pid, None, session_id, 1, "connect", None, "deny",
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

/// Boot-time failures [`run_inner`] can return (spec §5.4). Two arms, not one,
/// so [`run`] can map the fail-closed **authz-config boot gate** to its OWN
/// distinct non-zero `ExitCode` — separable at the process level from every
/// other startup failure (FIPS/config/vault/audit-sink/bind/...), which all
/// remain generically `Other`.
#[derive(Debug)]
enum RunError {
    /// The boot-time authz gate (#77, boot_gate.rs) refused to start: the
    /// `principal` section is absent or malformed, or the PDP refused
    /// construction (hardened policy load / bindings semantics). An AU-3
    /// refusal record has already been emitted (peer-less mapping) before
    /// this is constructed.
    Authz(String),
    /// Any other startup failure.
    Other(String),
}

impl std::fmt::Display for RunError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RunError::Authz(m) | RunError::Other(m) => write!(f, "{m}"),
        }
    }
}

/// The distinct process exit code for [`RunError::Authz`] (spec §5.4: "distinct
/// non-zero exit"). Deliberately not [`ExitCode::FAILURE`] (1) — an operator or
/// process-supervision script can tell "refused: unauthorized/unresolvable authz
/// policy" apart from every other startup failure without parsing stderr.
const AUTHZ_REFUSAL_EXIT_CODE: u8 = 3;

/// The `maknaed` entrypoint. Builds a Tokio runtime and drives the async orchestration;
/// any boot/config/credential failure fails closed to a non-zero `ExitCode` (the daemon
/// refuses to start rather than serve without audit, a constructed PDP, or a
/// plane credential). `bins/maknaed` stays a plain `fn main` that returns this `ExitCode`.
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
            Err(RunError::Authz(e)) => {
                eprintln!("maknaed: refusing to start: {e}");
                ExitCode::from(AUTHZ_REFUSAL_EXIT_CODE)
            }
            Err(RunError::Other(e)) => {
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

/// The peer-less `session_id` every boot-level AU-3 record shares (spec §5.3):
/// the boot nonce alone, ctr floor 0 — never `session_ids.next_session()`, which
/// would consume ctr 1 and collide with the first real connection's id.
fn boot_session_id(session_ids: &SessionIds) -> u64 {
    (session_ids.boot_nonce() as u64) << 32
}

/// Emit the AU-3 boot-refusal record for the authz gate (spec §5.4) — peer-less
/// field mapping (spec §5.3) — then build the [`RunError::Authz`] `run()` maps to
/// its own exit code. A failure to durably append the refusal record itself is
/// logged but never additionally fatal (the boot is refused either way).
#[allow(clippy::too_many_arguments)]
async fn refuse_authz_boot<E: AuditEmit + Send + Sync>(
    sink: &E,
    host: &str,
    socket: &str,
    uid: u32,
    session_id: u64,
    seq: u64,
    au3_1: &serde_json::Value,
    reason: String,
) -> RunError {
    let rec = make_record(
        "boot",
        host,
        socket,
        uid,
        None,
        None,
        None,
        session_id,
        seq,
        "authz",
        None,
        "deny",
        &reason,
        "unauthorized",
        au3_1,
    );
    if let Err(e) = sink.emit(&rec).await {
        eprintln!(
            "maknaed: AUDIT WRITE FAILED on boot authz refusal — refusal proceeded without a durable record: {e}"
        );
    }
    let catalog = maknae_msgs::msg(
        maknae_msgs::detect_locale(),
        maknae_msgs::MsgId::AuthzConfigRefused,
    );
    RunError::Authz(format!("{catalog}: {reason}"))
}

/// Read the root-owned boot posture marker (`<config_dir>/private/posture.yaml`,
/// spec §4.6/§5.2) — the daemon can read it but never modify it. A MISSING file
/// (never provisioned) or a MALFORMED one (bad YAML, wrong shape, a missing
/// field) both parse to `None`: [`crate::posture::determine`] then treats an
/// absent attestation exactly like a contradicting one (`Unverified`) — this
/// read is deliberately fail-SOFT (`None`, not a hard boot error) because the
/// marker is provisioning-time EVIDENCE, not a load-bearing config section; its
/// absence degrades the reported posture, it never blocks boot.
///
/// A file that EXISTS but is *refused* (wrong owner/permissions per
/// `load_root_file`'s root-owned requirement — e.g. `_maknae:_maknae 0640`
/// from config management — or unparseable/malformed content once opened) is
/// a distinct, loggable condition from a file that was simply never
/// provisioned (issue #135): both still degrade posture to `Unverified`
/// (fail-soft, boot never blocks on this path), but only the refused case
/// emits one `eprintln!` naming the path and the reason, so an operator can
/// tell "never enrolled" from "enrolled but broken" instead of both looking
/// identical in the boot posture record.
fn read_posture_marker(config_dir: &Path) -> Option<crate::posture::PostureMarker> {
    let path = config_dir.join("private").join("posture.yaml");
    match classify_marker_load(maknae_config::load_root_file(&path)) {
        MarkerOutcome::Absent => None,
        MarkerOutcome::Refused(reason) => {
            eprintln!(
                "maknaed: posture marker present but refused at {}: {reason}",
                path.display()
            );
            None
        }
        MarkerOutcome::Loaded(value) => parse_posture_marker(&value),
    }
}

/// The three outcomes a `load_root_file` attempt on the posture marker path
/// classifies into — split out as a pure function (no I/O, no logging) so it
/// is unit-testable independent of `eprintln!`, which is not capturable from
/// a test.
#[derive(Debug)]
enum MarkerOutcome {
    /// The file does not exist. Quiet — never provisioned is the common,
    /// expected case (e.g. a host that has not run `maknae enroll`).
    Absent,
    /// The file exists but `load_root_file` would not hand back its content:
    /// wrong owner, insecure permissions, a symlink, or content that failed
    /// to parse. `String` is the `ConfigError`'s `Display` text.
    Refused(String),
    /// The file was read and parsed into a generic YAML `Value`; still needs
    /// `parse_posture_marker` to confirm the marker shape.
    Loaded(maknae_config::Value),
}

/// Classify a `load_root_file` result for the posture marker. Absence is
/// derived from the error itself — never from a separate `Path::exists()` (or
/// similar) stat, which would re-introduce a TOCTOU-shaped decision between
/// the check and `load_root_file`'s own open.
///
/// `load_root_file` funnels a missing file through
/// `maknae_io::checks::kind_of` (`Errno::ENOENT => IoKind::NotFound`), which
/// `maknae_config::loader::map_io` maps to the STRUCTURED
/// `ConfigError::NotFound` variant. Only that variant classifies as `Absent`;
/// every other error — ownership/permission refusals, parse failures, any
/// other I/O error — is a present-or-indeterminate marker and classifies as
/// `Refused` (one log line, never silent). The earlier substring match on the
/// rendered message was rejected in PR #139 review: the rendering includes
/// the path, so a refused marker under a path containing "NotFound" was
/// misclassified as absent — matching the error KIND makes that impossible
/// by construction.
fn classify_marker_load(
    result: Result<maknae_config::Value, maknae_config::ConfigError>,
) -> MarkerOutcome {
    match result {
        Ok(value) => MarkerOutcome::Loaded(value),
        Err(maknae_config::ConfigError::NotFound { .. }) => MarkerOutcome::Absent,
        Err(e) => MarkerOutcome::Refused(e.to_string()),
    }
}

fn parse_posture_marker(value: &maknae_config::Value) -> Option<crate::posture::PostureMarker> {
    let entries = match &value {
        maknae_config::Value::Map(entries) => entries,
        _ => return None,
    };
    let get = |key: &str| -> Option<String> {
        entries
            .iter()
            .find(|(k, _)| k == key)
            .and_then(|(_, v)| match v {
                maknae_config::Value::Str(s) => Some(s.clone()),
                _ => None,
            })
    };
    Some(crate::posture::PostureMarker {
        mechanism: get("mechanism")?,
        target: get("target")?,
        timestamp: get("timestamp")?,
    })
}

async fn run_inner(config_dir: &Path) -> Result<ServeOutcome, RunError> {
    // FIPS first (spec §6.1): install the aws-lc-rs FIPS default (once), then assert it —
    // before any crypto/Vault client is built. The assert stays authoritative: on a
    // non-FIPS build the installed default's `.fips()` is false and the daemon refuses.
    maknae_vault::install_default_crypto_provider();
    maknae_vault::assert_fips_provider().map_err(|e| RunError::Other(e.to_string()))?;

    // Boot Maknae's own config ONCE, registering every section the daemon uses (core +
    // lake + vault + transport + audit + principal — see boot.rs). The booted document
    // backs the plane client below, so no incompatible per-call reload rejects a
    // combined config.
    let boot = crate::boot(config_dir).map_err(|e| RunError::Other(e.to_string()))?;
    let transport = maknae_config::transport_from_section(boot.section("transport"))
        .map_err(|e| RunError::Other(e.to_string()))?;
    let audit_cfg = maknae_config::audit_from_section(boot.section("audit"), config_dir)
        .map_err(|e| RunError::Other(e.to_string()))?;

    // Fail-closed audit sink: no durable audit path → do not start (AU-5).
    let sink = Arc::new(
        maknae_audit_append::AuditSink::open(&audit_cfg)
            .map_err(|e| RunError::Other(e.to_string()))?,
    );

    // The boot-level session id (spec §5.3) — shared by every AU-3 record this boot
    // emits BEFORE any connection (the authz refusal, the posture record) and by every
    // real connection's `next_session()` afterward, so they all derive from the SAME
    // per-boot nonce.
    let session_ids = Arc::new(SessionIds::new());
    let host = hostname();
    let socket = transport.socket_path.display().to_string();
    let euid = nix::unistd::geteuid().as_raw();

    // --- AUTHZ GATE (#77, spec D1): the daemon constructs its PDP at boot or
    // refuses to start. Ordering: audit sink first (above), so the refusal is
    // itself auditable. Refusal triggers (exactly two — boot_gate.rs is the
    // T1 authority): a malformed OR ABSENT `principal` section (a daemon with
    // no principal can authorize no one — operator ruling 2026-08-28), or any
    // PDP construction refusal (hardened policy load, bindings semantics).
    // Each → peer-less AU-3 refusal record → RunError::Authz → exit code 3.
    let principal_opt = match maknae_config::principal_from_section(boot.section("principal")) {
        Ok(p) => p,
        Err(e) => {
            return Err(refuse_authz_boot(
                sink.as_ref(),
                &host,
                &socket,
                euid,
                boot_session_id(&session_ids),
                Seq::new().next(),
                &audit_cfg.au3_1,
                e.to_string(),
            )
            .await);
        }
    };
    let (authorizer, principal) = match authz_boot_gate(config_dir, principal_opt) {
        Ok(pair) => pair,
        Err(e) => {
            return Err(refuse_authz_boot(
                sink.as_ref(),
                &host,
                &socket,
                euid,
                boot_session_id(&session_ids),
                Seq::new().next(),
                &audit_cfg.au3_1,
                e.to_string(),
            )
            .await);
        }
    };
    let authorizer = Arc::new(authorizer);
    let principal = Arc::new(principal);

    // Read-path anchor PROBE (spec D1/D5a): warn-only — an unreachable home
    // (missing ACL, unmounted) degrades the READ VERB, it must never
    // crash-loop the trust plane; ping/whoami keep serving and the anchor is
    // re-opened per request anyway (reads deny until the condition clears).
    if let Err(e) = open_anchor_resolved(
        &principal.home,
        AnchorRequired {
            owner: Some(principal.uid),
            mode_mask: Some(0o022),
        },
        StrategyPref::Auto,
    ) {
        eprintln!(
            "maknaed: read verb unavailable — home anchor probe failed for {}: {e} (ping/whoami unaffected; fix the home ACL/mode and reads recover without restart)",
            principal.home.display()
        );
    }

    // Plane credential: resolve + read this plane's SecretID source (spec §5.1),
    // authenticate, then mint a memory-only leaf below; the credential supervisor then
    // runs concurrently (renewal + leaf rotation; rotation cadence is checked once per
    // renewal cycle — Task-6 review note).
    let client = maknae_vault::PlaneClient::from_document(
        boot.document(),
        config_dir,
        maknae_vault::Plane::Kernel,
    )
    .map_err(|e| RunError::Other(e.to_string()))?;
    let ca = maknae_vault::load_ca_pin(config_dir).map_err(|e| RunError::Other(e.to_string()))?;

    // --- BOOT POSTURE RECORD (spec §5.2/§5.3): stated BEFORE mint, right after the
    // plane client resolved which SecretID source it actually used. A durable-append
    // failure here is logged but non-fatal (mirrors every other boot-record emit) —
    // credential posture is an audit STATEMENT, not itself a gate.
    //
    // `expected_target` is the deterministic sealed-credential path THIS boot's
    // config implies — `<config_dir>/private/maknaed-secret-id.{cred,sep}`, the
    // SAME path enroll's `artifact_table` writes to (bins/maknae's
    // `artifact_table.rs`) and the systemd unit's `LoadCredentialEncrypted=`
    // pins (spec §9.6) — computed here from the same `config_dir` base every
    // other boot artifact resolves against. `posture::determine` requires the
    // marker's `target` to match this, closing the "marker's mechanism is
    // right but its target is a stale/foreign path" gap (spec §5.2).
    let secret_source_kind = client.secret_source();
    let expected_target = match secret_source_kind {
        maknae_vault::CredentialSourceKind::CredentialsDirectory => {
            config_dir.join("private").join("maknaed-secret-id.cred")
        }
        maknae_vault::CredentialSourceKind::SepSealed => {
            config_dir.join("private").join("maknaed-secret-id.sep")
        }
        // Unused by `determine` for the plaintext branch (it ignores both the
        // marker and the target unconditionally) — an empty path is fine.
        maknae_vault::CredentialSourceKind::PlaintextPath => PathBuf::new(),
    };
    let marker = read_posture_marker(config_dir);
    let posture = crate::posture::determine(
        secret_source_kind.into(),
        marker.as_ref(),
        &expected_target.to_string_lossy(),
    );
    let posture_rec = make_record(
        "boot",
        &host,
        &socket,
        euid,
        None,
        None,
        None,
        boot_session_id(&session_ids),
        Seq::new().next(),
        "posture",
        None,
        "permit",
        "boot credential posture recorded",
        posture.as_str(),
        &audit_cfg.au3_1,
    );
    if let Err(e) = sink.emit(&posture_rec).await {
        eprintln!(
            "maknaed: AUDIT WRITE FAILED on boot posture record — boot proceeded without a durable record: {e}"
        );
    }
    if posture != crate::posture::Posture::HrotSealed {
        eprintln!(
            "maknaed: {}",
            maknae_msgs::msg(
                maknae_msgs::detect_locale(),
                maknae_msgs::MsgId::PostureDegraded
            )
        );
    }

    client
        .mint()
        .await
        .map_err(|e| RunError::Other(e.to_string()))?;
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
    // The fold lives in `maknae-config::effective_view`, not here: this file is
    // T3 and mutation-excluded, and "which fields to fold, and what to present
    // for an absent one" is a disclosure decision that earns a gated crate.
    // Built before `transport` is moved.
    let config_view = {
        let vc = maknae_vault::vault_config_from_document(boot.document()).ok();
        Arc::new(maknae_config::effective_view(
            boot.document(),
            &maknae_config::ResolvedSettings {
                transport: &transport,
                audit: &audit_cfg,
                vault_approle_mount: vc.as_ref().map(|c| c.approle_mount.clone()),
                vault_pki_int_mount: vc.as_ref().map(|c| c.pki_int_mount.clone()),
            },
        ))
    };
    let outcome = serve_after_mint(
        &client,
        &ca,
        &sink,
        transport,
        &audit_cfg,
        Arc::clone(&session_ids),
        supervisor,
        Arc::clone(&authorizer),
        Arc::clone(&principal),
        // Redact ONCE, here, at boot. The run loop receives only the view;
        // the unredacted Document does not travel with it.
        config_view,
    )
    .await;

    // Retire the plane credential (revoke token, clear leaf) on the way out — on the
    // graceful-shutdown path AND on any post-mint startup failure (e.g. bind).
    client.shutdown().await;
    outcome.map_err(RunError::Other)
}

/// The post-mint startup + serve: bind the group-gated plane listener, then run the
/// accept loop until shutdown OR the credential supervisor exits. Split out so
/// [`run_inner`] can revoke the minted Vault token on EVERY return path (a
/// bind/startup failure here, a graceful shutdown, or a supervisor exit) before
/// propagating — a `?` return from this function still runs the caller's
/// unconditional `client.shutdown().await`. Returns the [`ServeOutcome`] the accept
/// loop stopped on so [`run`] can map it to the process `ExitCode`.
#[allow(clippy::too_many_arguments)]
async fn serve_after_mint(
    client: &maknae_vault::PlaneClient,
    ca: &maknae_vault::CaBundle,
    sink: &Arc<maknae_audit_append::AuditSink>,
    transport: maknae_config::TransportConfig,
    audit_cfg: &maknae_config::AuditConfig,
    session_ids: Arc<SessionIds>,
    supervisor: tokio::task::JoinHandle<maknae_vault::VaultError>,
    authorizer: Arc<maknae_authz_basic::BasicAuthorizer>,
    principal: Arc<Principal>,
    // Already redacted at boot — the raw Document never reaches the run loop.
    config_view: Arc<ConfigView>,
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
    // `session_ids` is the SAME allocator `run_inner` used for this boot's AU-3
    // boot-level records (spec §5.3): every real connection's `next_session()`
    // therefore shares the one per-boot nonce, starting its counter at 1.
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
        authorizer,
        principal,
        config_view,
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

#[cfg(test)]
mod subject_list_offload_tripwire {
    /// STRUCTURAL TRIPWIRE, deliberately — not a behavioural test.
    ///
    /// The property: `authorizer.subjects()` reaches `load_authz`, which is
    /// sync file I/O on `/etc/maknae`, so it must run on the blocking pool
    /// under the decide breaker and timeout. Called inline it pins a tokio
    /// worker for as long as that read blocks, and N granted calls against a
    /// wedged NFS/FUSE mount starve the runtime with the breaker unable to
    /// trip, because it never sees them.
    ///
    /// That failure is not reproducible at unit scale — it needs a hung
    /// filesystem and runtime saturation. A behavioural test that "passes"
    /// against an inline call would be FALSE COVERAGE, which is worse than no
    /// test: reverting the offload leaves it green. Verified: reverting to the
    /// inline call keeps the whole e2e suite green.
    ///
    /// So this asserts the SHAPE instead, and says so in its name. It is the
    /// labelled-tripwire form the project's standing rule prescribes for
    /// exactly this case.
    #[test]
    fn subject_list_enumeration_is_offloaded_not_inline() {
        let src = include_str!("run.rs");
        // Cut this module off first: it reads its own file, so its own needle
        // strings would otherwise be found as if they were the production arm.
        // (They were: an index-based split landed between the shared-arm
        // pattern and the payload arm, and the tripwire failed on clean source.)
        // Cut at the FIRST test module, not just this one. `rfind` over
        // everything above would silently retarget onto the first future unit
        // test that writes the same arm pattern, where it would pass or fail
        // for reasons unrelated to the offload.
        let cut = src
            .find("\nmod tests {")
            .or_else(|| src.find("mod subject_list_offload_tripwire"))
            .expect("a test module");
        let prod = &src[..cut];
        let arm_start = prod
            .rfind("Dispatch::SubjectListRequested => {")
            .expect("the payload arm exists");
        let arm = &prod[arm_start..];
        let with_comments = &arm[..arm.find("match enumerated {").expect("arm shape")];
        // CODE only -- forward defence, and the rationale is corrected here
        // rather than left overstated. An earlier version claimed this arm
        // "carries a long explanatory comment naming every one of them, so a
        // regression that kept the prose would have satisfied the loop". That
        // was never true of any version: the long comment sits ABOVE the
        // `rfind` anchor and is excluded by construction, and none of the five
        // needles appears in the seven comment lines actually scanned. The
        // strip is cheap insurance against a future comment that does; the
        // claim that it was already load-bearing was argued, not measured.
        let body: String = with_comments
            .lines()
            .filter(|l| !l.trim_start().starts_with("//"))
            .collect::<Vec<_>>()
            .join("\n");
        let body = body.as_str();
        for needle in [
            "authz_decide_breaker()",
            "begin_attempt_at",
            "tokio::time::timeout",
            "spawn_blocking",
            "record_timeout_at",
        ] {
            assert!(
                body.contains(needle),
                "`subjects()` must run under the same offload discipline as the \
                 decide path — missing `{needle}`. If this is a deliberate \
                 change, the sync policy read is back on the async worker."
            );
        }
        assert!(
            !body.contains("= authorizer.subjects();"),
            "a bare inline `authorizer.subjects()` is the exact regression this \
             tripwire exists to catch"
        );
    }
}

// ---------------------------------------------------------------------------
// Boot-gate integration tests (spec §5.4/§5.2-§5.3, Task 7). Full `run_inner`
// over a real temp config dir (the boot.rs / maknae-vault client.rs fixture
// pattern) — the authz gate now sits BEFORE the plane client is even
// constructed, so cases (a)/(b) need no live Vault at all; case (c) reaches
// past the gate into client construction + the posture record and is expected
// to fail LATER, at `mint()` (no live Vault in a unit test), which proves it
// got past the gate.
#[cfg(unix)]
#[cfg(test)]
mod boot_gate_tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;
    use std::sync::Mutex;

    // `$CREDENTIALS_DIRECTORY` is process-wide; serialize the one test that sets it
    // against any other test in THIS crate's test binary that might touch it.
    static ENV_LOCK: Mutex<()> = Mutex::new(());

    // A real, self-signed P-384 CA certificate (generated once via `openssl req
    // -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-384 ...`) — `load_ca_pin` and
    // `PlaneClient::from_document` both parse-validate whatever sits at
    // `tls/*.crt`, so a placeholder string would fail closed before ever reaching
    // the authz gate this suite exercises.
    const SELF_SIGNED_PEM: &str = "-----BEGIN CERTIFICATE-----\n\
MIIB1TCCAVqgAwIBAgIUHomPebdT3IeSlE93a8ShvhfFJmcwCgYIKoZIzj0EAwIw\n\
IDEeMBwGA1UEAwwVbWFrbmFlLWtlcm5lbC10ZXN0LWNhMCAXDTI2MDgxMjE3NDYy\n\
MloYDzIxMjYwNzE5MTc0NjIyWjAgMR4wHAYDVQQDDBVtYWtuYWUta2VybmVsLXRl\n\
c3QtY2EwdjAQBgcqhkjOPQIBBgUrgQQAIgNiAASmE05K4ZU2QMMCNKPnA8UhRC4/\n\
wR5qqSAZWTnfBTJ8J3ld5APC5p6QsORvYOt8/bQGTC5MgFZ+GmfZGubJCeExdsRB\n\
8o7s8lbNapU4nyYsO2M0pB2wu3w+AE9RYiGIewqjUzBRMB0GA1UdDgQWBBS0R8fb\n\
RZzvJKR13WnrvryhhbsGrTAfBgNVHSMEGDAWgBS0R8fbRZzvJKR13WnrvryhhbsG\n\
rTAPBgNVHRMBAf8EBTADAQH/MAoGCCqGSM49BAMCA2kAMGYCMQCAXllf9eXJGbU4\n\
xc1T6LHIdEHkxzkIaXC/fBpSxtTrVL9JSVGMBLQgMHs6aNp8gRgCMQDU2GhtZkJI\n\
kyIISfxBPHa6GyZY9EYUWd3r0F3e1wkXaIrmVN4PPnYiwUE5D1gD1iI=\n\
-----END CERTIFICATE-----\n";

    struct Dir(std::path::PathBuf);
    impl Dir {
        fn new(tag: &str) -> Self {
            let p = std::env::temp_dir().join(format!(
                "maknae_kernel_rungate_{}_{tag}",
                std::process::id()
            ));
            let _ = std::fs::remove_dir_all(&p);
            std::fs::create_dir_all(p.join("tls")).unwrap();
            std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o750)).unwrap();
            Dir(p)
        }
    }
    impl Drop for Dir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    fn put(dir: &Path, name: &str, body: &str, mode: u32) {
        let p = dir.join(name);
        if let Some(parent) = p.parent() {
            std::fs::create_dir_all(parent).unwrap();
        }
        std::fs::write(&p, body).unwrap();
        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(mode)).unwrap();
    }

    /// Everything `run_inner` needs on disk EXCEPT `authz.yaml` (each test writes
    /// its own, or omits it): `maknae.yaml` (core+vault+transport+audit[+principal]),
    /// the CA trio, and the daemon's AppRole id.
    fn write_common_fixture(d: &Dir, principal_block: &str) {
        let yaml = format!(
            "core:\n  deployment_id: dev-01\n\
             vault:\n  addr: https://v.example:8200\n\
             transport:\n  socket_path: {}\n\
             audit:\n  jsonl_path: {}\n\
             {}",
            d.0.join("maknaed.sock").display(),
            d.0.join("audit.jsonl").display(),
            principal_block,
        );
        put(&d.0, "maknae.yaml", &yaml, 0o640);
        for f in [
            "tls/vault-ca.crt",
            "tls/maknae-root-ca.crt",
            "tls/maknae-int-ca.crt",
        ] {
            put(&d.0, f, SELF_SIGNED_PEM, 0o640);
        }
        put(&d.0, "maknaed-approle-id", "maknaed-role-id\n", 0o640);
    }

    /// Run `run_inner` to completion on a FRESH single-threaded runtime, entirely
    /// synchronously from the caller's point of view — deliberately NOT
    /// `#[tokio::test]`/`.await`: these tests hold `ENV_LOCK` (a plain
    /// `std::sync::Mutex`) across the call to serialize `$CREDENTIALS_DIRECTORY`
    /// mutation against any other test in this binary, and holding a
    /// `MutexGuard` across a syntactic `.await` point trips
    /// `clippy::await_holding_lock`. Calling `Runtime::block_on` from a plain
    /// (non-async) test function has no such suspend point in the CALLER's own
    /// frame, so the guard is just an ordinary stack value — matches `run()`'s
    /// own runtime-construction pattern.
    fn block_on_run_inner(dir: &Path) -> Result<ServeOutcome, RunError> {
        tokio::runtime::Runtime::new()
            .unwrap()
            .block_on(run_inner(dir))
    }

    // (a) A missing `authz.yaml` refuses to start with the NEW distinct error
    // variant, having written a durable AU-3 refusal record — spec §5.4.
    #[test]
    fn missing_authz_yaml_refuses_and_audits() {
        let _g = ENV_LOCK.lock().unwrap();
        std::env::remove_var("CREDENTIALS_DIRECTORY");
        let d = Dir::new("missing_authz");
        write_common_fixture(
            &d,
            "principal:\n  name: op\n  uid: 1000\n  home: /home/op\n",
        );
        // Deliberately no authz.yaml written.

        match block_on_run_inner(&d.0) {
            Err(RunError::Authz(msg)) => assert!(!msg.is_empty()),
            other => panic!("expected Err(RunError::Authz), got {other:?}"),
        }

        let audit = std::fs::read_to_string(d.0.join("audit.jsonl")).unwrap();
        let lines: Vec<&str> = audit.lines().collect();
        assert_eq!(lines.len(), 1, "exactly one boot-refusal record: {audit}");
        let rec: maknae_audit_append::AuditRecord = serde_json::from_str(lines[0]).unwrap();
        assert_eq!(rec.event, "boot");
        assert_eq!(rec.action, "authz");
        assert_eq!(rec.outcome.result, "deny");
        assert_eq!(rec.outcome.posture, "unauthorized");
        assert_eq!(rec.subject.user, None, "boot records are peer-less");
        assert_eq!(rec.subject.plane_uri_san, None);
        assert_eq!(rec.source.gid, None);
        assert_eq!(rec.source.pid, None);
        assert_eq!(rec.seq, 1);
    }

    // (b) NO enrolled principal refuses at the boot gate (#77, ruling 2: a
    // daemon that can authorize no one does not boot). Renamed from
    // `tilde_pattern_without_principal_refuses` — the `~`-resolution refusal
    // it once named is now structurally unreachable (the principal gate fires
    // before authz.yaml is ever opened), and off-root it had already been
    // passing on `NotRootOwned` rather than `~` anyway.
    #[test]
    fn config_without_principal_refuses_boot() {
        let _g = ENV_LOCK.lock().unwrap();
        std::env::remove_var("CREDENTIALS_DIRECTORY");
        let d = Dir::new("no_principal_gate");
        write_common_fixture(&d, ""); // no `principal:` section at all
        put(
            &d.0,
            "authz.yaml",
            "schema_version: 1\npermissions:\n  allow: []\n  deny: []\n",
            0o640,
        );

        match block_on_run_inner(&d.0) {
            Err(RunError::Authz(msg)) => assert!(
                msg.to_string().contains("principal"),
                "the refusal must name the missing section: {msg}"
            ),
            other => panic!("expected Err(RunError::Authz), got {other:?}"),
        }
    }

    // (c) A valid default `authz.yaml` + an enrolled principal gets PAST the
    // authz gate: the boot posture record is emitted (client construct + source
    // resolve succeeded), and boot only fails later, at `mint()` (no live Vault
    // in this unit test) — a `RunError::Other`, never `RunError::Authz`.
    //
    // **Root-gated (best-effort):** `maknae_config::load_authz` asserts
    // `authz.yaml` is owned by uid 0 (spec §4.6/§7, `maknae-config/src/authz.rs`)
    // — a control this task does not touch. A non-privileged test process can
    // never create a root-owned fixture file (documented at
    // `authz.rs::security_load`'s own doc comment: "the SUCCESS path is
    // unit-testable [only] without an actual root-owned fixture file" via
    // dependency injection, which `load_authz`'s public entrypoint does not
    // expose). This test therefore only exercises the real success path when
    // it happens to run AS root (`sudo cargo test -p maknae-kernel`); under an
    // unprivileged runner (every CI lane) it degrades to proving the SAME
    // fixture fails via the authz gate for the expected reason
    // (`NotRootOwned`) rather than silently no-op'ing. The individual pieces
    // the success path would exercise (`boot_session_id`, `read_posture_marker`,
    // the `make_record("boot", ..., "posture", ...)` shape) are pinned by the
    // focused unit tests below, independent of root.
    #[test]
    fn valid_authz_and_principal_reaches_posture_record() {
        let _g = ENV_LOCK.lock().unwrap();
        let d = Dir::new("valid_reaches_posture");
        write_common_fixture(
            &d,
            "principal:\n  name: op\n  uid: 1000\n  home: /home/op\n",
        );
        put(
            &d.0,
            "authz.yaml",
            "schema_version: 1\npermissions:\n  allow:\n    - \"Read(~/**)\"\n",
            0o640,
        );
        let creds_dir = std::env::temp_dir().join(format!(
            "maknae_kernel_rungate_creds_{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&creds_dir);
        std::fs::create_dir_all(&creds_dir).unwrap();
        std::fs::write(creds_dir.join("maknaed-secret-id"), "secret-value").unwrap();
        std::env::set_var("CREDENTIALS_DIRECTORY", &creds_dir);

        let result = block_on_run_inner(&d.0);

        std::env::remove_var("CREDENTIALS_DIRECTORY");
        let _ = std::fs::remove_dir_all(&creds_dir);

        if nix::unistd::geteuid().as_raw() == 0 {
            // Running as root: `authz.yaml` (written above by this same, now-root,
            // process) is genuinely root-owned — the real success path runs.
            match &result {
                Err(RunError::Other(_)) => {}
                other => panic!(
                    "expected Err(RunError::Other) (a later, non-authz failure), got {other:?}"
                ),
            }
            let audit = std::fs::read_to_string(d.0.join("audit.jsonl")).unwrap();
            let recs: Vec<maknae_audit_append::AuditRecord> = audit
                .lines()
                .map(|l| serde_json::from_str(l).unwrap())
                .collect();
            let posture_rec = recs
                .iter()
                .find(|r| r.action == "posture")
                .unwrap_or_else(|| panic!("no posture record in: {audit}"));
            assert_eq!(posture_rec.event, "boot");
            assert_eq!(posture_rec.outcome.result, "permit");
            // $CREDENTIALS_DIRECTORY resolves to CredentialsDirectory; with no
            // posture marker file present that's Unverified (spec §5.2 closed map).
            assert_eq!(posture_rec.outcome.posture, "unverified");
            assert_eq!(posture_rec.subject.user, None);
            assert_eq!(posture_rec.source.uid, nix::unistd::geteuid().as_raw());
        } else {
            // Unprivileged (every CI lane, this dev host): the authz gate still
            // refuses — for `NotRootOwned` specifically (checked below via its
            // exact Display text, `authz.rs`'s `AuthzError::NotRootOwned` arm),
            // not a grammar/tilde problem — proving the gate is reached and
            // enforced, not silently bypassed.
            match &result {
                Err(RunError::Authz(msg)) => assert!(
                    msg.contains("not owned by root"),
                    "expected a NotRootOwned refusal, got: {msg}"
                ),
                other => panic!("expected Err(RunError::Authz), got {other:?}"),
            }
        }
    }

    // ---- focused unit coverage for the pieces the root-gated happy path above
    // cannot exercise without root ----

    #[test]
    fn boot_session_id_is_nonce_shifted_with_ctr_floor_zero() {
        let ids = SessionIds::with_nonce(0x1234_5678);
        assert_eq!(boot_session_id(&ids), 0x1234_5678_0000_0000);
        // Distinct from the first REAL connection's session id (ctr=1), so a
        // boot-level record and the first connection's admission record never
        // collide on `session_id`.
        assert_ne!(boot_session_id(&ids), ids.next_session());
    }

    #[test]
    fn read_posture_marker_missing_file_is_none() {
        let d = Dir::new("marker_missing");
        assert_eq!(read_posture_marker(&d.0), None);
    }

    // ---- issue #135: a present-but-refused marker must classify distinctly
    // from a genuinely absent one, so boot can log the refusal instead of
    // silently collapsing both into the same `Unverified` degrade. ----

    #[test]
    fn classify_marker_load_missing_file_is_absent() {
        // Drive the REAL `load_root_file` over a path that was never created —
        // the actual error shape `classify_marker_load` must recognize as
        // absence, not a hand-built stand-in `ConfigError`.
        let d = Dir::new("classify_absent");
        let path = d.0.join("private").join("posture.yaml");
        let result = maknae_config::load_root_file(&path);
        assert!(
            matches!(classify_marker_load(result), MarkerOutcome::Absent),
            "a never-created posture.yaml must classify as Absent"
        );
    }

    #[test]
    fn classify_marker_load_present_non_root_owned_file_is_refused_not_absent() {
        // The exact regression from issue #135: a posture.yaml that EXISTS but
        // fails `load_root_file`'s root-owned requirement (e.g. `_maknae:_maknae
        // 0640` from config management, or — as here — this test process's own
        // uid on any unprivileged dev box/CI runner) must classify as Refused,
        // never silently as Absent.
        let d = Dir::new("classify_refused");
        put(
            &d.0,
            "private/posture.yaml",
            "mechanism: tpm2\ntarget: /x\ntimestamp: \"1\"\n",
            0o640,
        );
        let path = d.0.join("private").join("posture.yaml");
        if nix::unistd::geteuid().as_raw() == 0 {
            // If this test process itself runs as root (rare, but possible —
            // e.g. `sudo cargo test`), the fixture above is root-owned by
            // construction and would NOT trigger the ownership refusal this
            // test targets. Force a non-root owner so the refusal path is
            // exercised deterministically regardless of the runner's privilege
            // (mirrors the root/non-root split in
            // `valid_authz_and_principal_reaches_posture_record` above).
            std::os::unix::fs::chown(&path, Some(65534), None)
                .expect("root can chown the fixture to a non-root uid");
        }
        let result = maknae_config::load_root_file(&path);
        assert!(
            matches!(result, Err(maknae_config::ConfigError::Io(_))),
            "expected load_root_file to refuse a non-root-owned file, got {result:?}"
        );
        match classify_marker_load(result) {
            MarkerOutcome::Refused(reason) => {
                assert!(!reason.is_empty(), "refusal reason must not be empty");
            }
            other => panic!(
                "a present-but-refused marker must classify as Refused, not {other:?} — \
                 collapsing it to Absent is exactly the issue #135 regression"
            ),
        }
    }

    #[test]
    fn classify_marker_load_refused_marker_under_a_notfound_named_path_is_refused() {
        // PR #139 review finding (Hobi): absence must be derived from the
        // structured error kind, never from substring-matching the rendered
        // message — the rendering includes the PATH, so a present-but-refused
        // marker under a directory whose name contains "NotFound" would
        // otherwise classify as Absent and skip the issue-#135 refusal log.
        let d = Dir::new("NotFound-case");
        put(
            &d.0,
            "private/posture.yaml",
            "mechanism: tpm2\ntarget: /x\ntimestamp: \"1\"\n",
            0o640,
        );
        let path = d.0.join("private").join("posture.yaml");
        if nix::unistd::geteuid().as_raw() == 0 {
            std::os::unix::fs::chown(&path, Some(65534), None)
                .expect("root can chown the fixture to a non-root uid");
        }
        let result = maknae_config::load_root_file(&path);
        assert!(result.is_err(), "non-root-owned fixture must be refused");
        assert!(
            matches!(classify_marker_load(result), MarkerOutcome::Refused(_)),
            "a refused marker must classify as Refused even when its path \
             contains the substring \"NotFound\""
        );
    }

    #[test]
    fn classify_marker_load_non_io_error_is_refused() {
        // A `Parse`/`DuplicateKey`/etc. error (content read fine, past the
        // owner/permission check, but malformed YAML) is also a present file
        // that failed — Refused, not Absent.
        let err = maknae_config::load_str("x: [1, 2\n").unwrap_err();
        assert!(matches!(err, maknae_config::ConfigError::Parse { .. }));
        assert!(matches!(
            classify_marker_load(Err(err)),
            MarkerOutcome::Refused(_)
        ));
    }

    #[test]
    fn classify_marker_load_ok_is_loaded() {
        let value = maknae_config::load_str("x: 1\n").unwrap();
        assert!(matches!(
            classify_marker_load(Ok(value)),
            MarkerOutcome::Loaded(_)
        ));
    }

    #[test]
    fn read_posture_marker_refused_non_root_owned_file_is_none() {
        // End-to-end: `read_posture_marker` still degrades to `None` on a
        // refused marker (fail-soft, boot never blocks on this path) — the
        // fix only adds a log line at the call site, it does not change this
        // return value. The distinguishing behavior (Refused vs Absent) is
        // pinned above at the `classify_marker_load` level, since the
        // `eprintln!` emitted here is not capturable from a test.
        let d = Dir::new("read_marker_refused");
        put(
            &d.0,
            "private/posture.yaml",
            "mechanism: tpm2\ntarget: /x\ntimestamp: \"1\"\n",
            0o640,
        );
        if nix::unistd::geteuid().as_raw() == 0 {
            std::os::unix::fs::chown(d.0.join("private").join("posture.yaml"), Some(65534), None)
                .expect("root can chown the fixture to a non-root uid");
        }
        assert_eq!(read_posture_marker(&d.0), None);
    }

    #[test]
    fn read_posture_marker_unparseable_yaml_is_none() {
        assert!(maknae_config::load_str("x: [1, 2\n").is_err());
    }

    #[test]
    fn read_posture_marker_scalar_root_is_none() {
        let value = maknae_config::load_str("just a scalar\n").unwrap();
        assert_eq!(parse_posture_marker(&value), None);
    }

    #[test]
    fn read_posture_marker_missing_field_is_none() {
        // `timestamp` is absent — the whole marker must not be fabricated from a
        // partial record.
        let value = maknae_config::load_str(
            "mechanism: tpm2\ntarget: /etc/maknae/private/maknaed-secret-id.cred\n",
        )
        .unwrap();
        assert_eq!(parse_posture_marker(&value), None);
    }

    #[test]
    fn read_posture_marker_valid_parses() {
        let value = maknae_config::load_str("mechanism: tpm2\ntarget: /etc/maknae/private/maknaed-secret-id.cred\ntimestamp: 2026-08-12T00:00:00.000Z\n").unwrap();
        let m = parse_posture_marker(&value).expect("valid marker parses");
        assert_eq!(m.mechanism, "tpm2");
        assert_eq!(m.target, "/etc/maknae/private/maknaed-secret-id.cred");
        assert_eq!(m.timestamp, "2026-08-12T00:00:00.000Z");
    }

    // ---- final-fix wave, Fix 1: posture-marker key/type contract pin -------
    // (reader half — see `bins/maknae/src/enroll/mod.rs`'s
    // `build_posture_yaml_emits_the_three_reader_keys_as_strings` for the
    // writer-side half of this same cross-crate pin. `bins/maknae` cannot
    // depend on `maknae-kernel` (bin/lib layering), so there is no single
    // shared test crate; this fixture closes the gap by being
    // BYTE-IDENTICAL to `build_posture_yaml`'s actual emitted output —
    // captured by literally running that function and copying its output,
    // not hand-typed from the format string.)

    #[test]
    fn posture_marker_matches_enroll_writer_output() {
        // Exact byte-for-byte capture of
        // `bins/maknae/src/enroll/mod.rs::build_posture_yaml("tpm2",
        // "/etc/maknae/private/maknaed-secret-id.cred")`'s output (its
        // `yaml_rust2::YamlEmitter` quotes the all-digit `timestamp` scalar
        // to preserve its string type — confirmed by actually running the
        // writer, not assumed). If enroll's writer format ever drifts from
        // this, this test — not just the reader's own schema tests — must
        // be the one that catches it.
        let fixture = "---\nmechanism: tpm2\ntarget: /etc/maknae/private/maknaed-secret-id.cred\ntimestamp: \"1786563711\"\n";
        let value = maknae_config::load_str(fixture).unwrap();
        let marker = parse_posture_marker(&value).expect("enroll's real writer output parses");
        assert_eq!(marker.mechanism, "tpm2");
        assert_eq!(marker.target, "/etc/maknae/private/maknaed-secret-id.cred");
        assert_eq!(marker.timestamp, "1786563711");
    }

    #[test]
    fn enroll_writer_fixture_determines_hrot_sealed() {
        // The actual regression this fix closes: feed the enroll writer's
        // real output through BOTH `read_posture_marker` AND
        // `posture::determine` and assert a healthy sealed boot yields
        // `HrotSealed` — not `Unverified`, which is what the pre-fix key
        // mismatch produced on every real `maknae enroll` + boot.
        let fixture = "---\nmechanism: tpm2\ntarget: /etc/maknae/private/maknaed-secret-id.cred\ntimestamp: \"1786563711\"\n";
        let value = maknae_config::load_str(fixture).unwrap();
        let marker = parse_posture_marker(&value);
        // The expected target matches enroll's ALWAYS-`/etc/maknae` write
        // target (bins/maknae's `artifact_table.rs` hardcodes `/etc/maknae`,
        // not the daemon's `config_dir` argument) — the real daemon's default
        // `config_dir` is also `/etc/maknae` (bins/maknaed/src/main.rs), so
        // this fixture models the default-deployment case where the two
        // agree. A non-default `--config-dir` daemon boot is a legitimate,
        // documented case where they would NOT agree — out of scope here.
        let posture = crate::posture::determine(
            crate::posture::CredentialSource::CredentialsDirectory,
            marker.as_ref(),
            "/etc/maknae/private/maknaed-secret-id.cred",
        );
        assert_eq!(
            posture,
            crate::posture::Posture::HrotSealed,
            "enroll's real writer output must determine HrotSealed on a \
             healthy CredentialsDirectory boot, not Unverified"
        );
    }

    #[test]
    fn enroll_writer_sep_fixture_determines_hrot_sealed() {
        // The macOS mirror: `build_posture_yaml("sep", ...)`'s output must
        // determine HrotSealed for a SepSealed boot.
        let fixture = "---\nmechanism: sep\ntarget: /etc/maknae/private/maknaed-secret-id.sep\ntimestamp: \"1786563711\"\n";
        let value = maknae_config::load_str(fixture).unwrap();
        let marker = parse_posture_marker(&value);
        let posture = crate::posture::determine(
            crate::posture::CredentialSource::SepSealed,
            marker.as_ref(),
            "/etc/maknae/private/maknaed-secret-id.sep",
        );
        assert_eq!(posture, crate::posture::Posture::HrotSealed);
    }

    #[test]
    fn enroll_writer_fixture_with_foreign_target_is_unverified() {
        // The regression pin for the finding at the cross-crate (enroll-writer
        // fixture) level: same mechanism (tpm2) as the healthy fixture above,
        // but a target that does NOT match this boot's expected sealed-
        // credential path (e.g. a marker copied from another host) — must
        // yield Unverified, not HrotSealed.
        let fixture = "---\nmechanism: tpm2\ntarget: /etc/maknae/private/maknaed-secret-id.cred\ntimestamp: \"1786563711\"\n";
        let value = maknae_config::load_str(fixture).unwrap();
        let marker = parse_posture_marker(&value);
        let posture = crate::posture::determine(
            crate::posture::CredentialSource::CredentialsDirectory,
            marker.as_ref(),
            "/etc/maknae/private/some-other-host-secret-id.cred",
        );
        assert_eq!(
            posture,
            crate::posture::Posture::Unverified,
            "a marker with the right mechanism but the wrong target must not \
             determine HrotSealed"
        );
    }
}
