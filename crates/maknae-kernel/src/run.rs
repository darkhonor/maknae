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
use std::sync::atomic::{AtomicU64, Ordering as AtomicOrdering};
use std::sync::{Arc, OnceLock};
use std::time::{Duration, Instant};

use maknae_audit_append::{
    AuditEmit, AuditRecord, EgressAudit, EgressStatus, GraphAudit, Integrity, Outcome, Seq,
    SessionIds, Source, Subject, Where,
};
use maknae_config::TransportConfig;
use maknae_graph::baseline::BaselineLayer;
use maknae_proto::{
    admits, class_of, decode_request, encode_response, read_frame_zeroizing, write_frame,
    FrameCaps, FrameClass, Payload, RespResult, Response, Verb, CONTROL_REQUEST_MAX,
    PROTOCOL_VERSION,
};
use maknae_state::anchor::{parse_checkpoint, CHECKPOINT_ACTION};
use maknae_state::envelope::WrappingKey;
use maknae_state::store::{
    remedy, BootAudit, BootInputs, BootOutcome, BootReport, Remedy, StateDir, StoreError,
    ANCHOR_RESEEDED, ANCHOR_SEEDED, ANCHOR_SEEDING, MARKER_FILE, STORE_FILE,
};
use maknae_vault::{
    AcceptRejection, AuthenticatedStream, PeerCreds, PlaneListener, RawPlaneConn, RejectReason,
};
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt};
use tokio::sync::mpsc;
use tokio::sync::Semaphore;
use tokio::task::JoinSet;

use crate::authz::{admission_facts, authorize_connection, ConnDecision, HOME_RESOLVE_TIMEOUT};
use crate::baseline_check::{Invalid, Mode};
use crate::blocking_guard::{
    within_blocking, BlockingBreaker, BreakerAdmission, BreakerTransition, AUDIT_APPEND_TIMEOUT,
    BLOCKING_OPERATION_TIMEOUT, SCAN_BACK_TIMEOUT,
};
use crate::boot_gate::authz_boot_gate;
use crate::groupres::{maknae_gid, uid_in_maknae_group};
use crate::handler::{
    build_authz_request, build_whoami, discharge_plan, dispatch_verb, lexical_pregate, may_respond,
    verb_to_action, Dispatch, Drain, ServeOutcome, AUTHZ_DECIDE_TIMEOUT,
};
use maknae_proto::{encode_response_zeroizing, ProtoErrCode, ProtoError};
use maknae_security::{
    combine, finalize, guarded_decide_cited, Authorizer, Decision, RuleCitation,
};

static AUTHZ_DECIDE_BREAKER: OnceLock<Arc<tokio::sync::Mutex<BlockingBreaker>>> = OnceLock::new();
static GROUP_LOOKUP_BREAKER: OnceLock<Arc<tokio::sync::Mutex<BlockingBreaker>>> = OnceLock::new();
// #240a: the egress send's own breaker. It is admitted BEFORE `spawn_blocking`,
// like its siblings — that ordering IS the control ("failing closed
// WITHOUT spawning more blocking work"). A breaker consulted inside
// `Egress::send` runs on a thread that is already spawned and, on deadline
// expiry, already abandoned.
static EGRESS_SEND_BREAKER: OnceLock<Arc<tokio::sync::Mutex<BlockingBreaker>>> = OnceLock::new();

fn authz_decide_breaker() -> Arc<tokio::sync::Mutex<BlockingBreaker>> {
    Arc::clone(AUTHZ_DECIDE_BREAKER.get_or_init(|| Arc::new(Default::default())))
}

fn group_lookup_breaker() -> Arc<tokio::sync::Mutex<BlockingBreaker>> {
    Arc::clone(GROUP_LOOKUP_BREAKER.get_or_init(|| Arc::new(Default::default())))
}

fn egress_send_breaker() -> Arc<tokio::sync::Mutex<BlockingBreaker>> {
    Arc::clone(EGRESS_SEND_BREAKER.get_or_init(|| Arc::new(Default::default())))
}

static BASELINE_BREAKER: OnceLock<Arc<tokio::sync::Mutex<BlockingBreaker>>> = OnceLock::new();

fn baseline_breaker() -> Arc<tokio::sync::Mutex<BlockingBreaker>> {
    Arc::clone(BASELINE_BREAKER.get_or_init(|| Arc::new(Default::default())))
}

pub type BoxFuture<'a, T> = std::pin::Pin<Box<dyn Future<Output = T> + Send + 'a>>;

#[derive(Debug)]
pub enum AcceptAnswer {
    /// Respond with this view; `corrective` is the deny record's reason when the accept was refused.
    View {
        view: maknae_proto::BaselineView,
        corrective: Option<String>,
    },
    /// Answer Internal with `reply` after a `deny`/`unavailable` corrective record
    /// carrying `why`, which never reaches the requester.
    Unavailable { reply: &'static str, why: String },
}

const ACCEPT_BUSY: &str = "baseline accept refused: busy; a reload holds the turn";
const ACCEPT_STOPPING: &str = "baseline accept refused: shutting down";
const ACCEPT_UNAVAILABLE: &str = "baseline accept unavailable";

fn accept_unavailable(reply: &'static str, why: String) -> AcceptAnswer {
    eprintln!("maknaed: {why}");
    AcceptAnswer::Unavailable { reply, why }
}

/// Turns a drain an accept left at `Begun` (a panic or an abort before its persist
/// landed) into `Failed`, so the daemon stops with exit 1 instead of refusing forever.
/// Dropped while the accept still holds the reload turn. `live_unsettled`: a live
/// baseline is persisted and its install has not reported.
struct DrainGuard<'a> {
    drain: &'a tokio::sync::watch::Sender<Drain>,
    live_unsettled: bool,
}

impl Drop for DrainGuard<'_> {
    fn drop(&mut self) {
        if *self.drain.borrow() == Drain::Begun {
            self.drain.send_replace(Drain::Failed);
            eprintln!("maknaed: a baseline accept ended without its persist; exiting on the unchanged baseline");
        } else if self.live_unsettled && *self.drain.borrow() == Drain::Serving {
            self.drain.send_replace(Drain::Applied);
            eprintln!(
                "maknaed: a live baseline accept ended without its install; restarting to apply it"
            );
        }
    }
}

/// `admin.baseline.show` and `admin.baseline.accept`, as a request reaches them.
pub trait BaselineOps: Send + Sync {
    fn show(&self) -> BoxFuture<'_, Result<maknae_proto::BaselineView, String>>;
    fn accept<'a>(&'a self, hash: &'a str) -> BoxFuture<'a, AcceptAnswer>;
}

/// Blocking baseline work: admitted by the baseline breaker, bounded, a timeout counted.
async fn baseline_blocking<T: Send + 'static>(
    work: impl FnOnce() -> T + Send + 'static,
) -> Result<T, String> {
    let breaker = baseline_breaker();
    let admission = { breaker.lock().await.begin_attempt_at(Instant::now()) };
    match admission {
        BreakerAdmission::RefuseOpen => Err("the baseline circuit breaker is open".into()),
        BreakerAdmission::RefuseAtCapacity => {
            Err("the baseline blocking worker budget is exhausted".into())
        }
        BreakerAdmission::Admit => {
            match tokio::time::timeout(
                BLOCKING_OPERATION_TIMEOUT,
                tokio::task::spawn_blocking(work),
            )
            .await
            {
                Ok(joined) => {
                    breaker.lock().await.record_success();
                    joined.map_err(|e| format!("the baseline check failed: {e}"))
                }
                Err(_elapsed) => {
                    if breaker.lock().await.record_timeout_at(Instant::now())
                        == BreakerTransition::Tripped
                    {
                        eprintln!(
                            "maknaed: baseline circuit breaker tripped after repeated {}s blocking timeouts",
                            BLOCKING_OPERATION_TIMEOUT.as_secs()
                        );
                    }
                    Err(format!(
                        "the baseline check did not finish within {}s",
                        BLOCKING_OPERATION_TIMEOUT.as_secs()
                    ))
                }
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Audit-record construction (AU-3, ADR-0019). These stamp the run-loop's own
// `where`/outcome facts onto the schema owned by `maknae-audit-append`.
// ---------------------------------------------------------------------------

/// The listener-level `where` facts (AU-3c) shared by every record a connection emits.
/// Exposed so the accept-loop integration tests can build one directly.
/// `Debug` withholds `au3_1`.
#[derive(Clone)]
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

impl std::fmt::Debug for WhereCtx {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("WhereCtx")
            .field("host", &self.host)
            .field("socket", &self.socket)
            .finish_non_exhaustive()
    }
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
/// `socket_path`, `prompt_max_bytes`, `read_timeout_ms`), `au3_1` (the raw
/// `audit.au3_1` object), and `principal` (`name`, `uid`). That debt has since been
/// PAID once: the `admin.status` arm wanting "which socket am I on?" found
/// `cfg.socket_path` sitting right there, and `listener` is disclosed under
/// ADR-0010 decision 16 with its own argument and its own gate row. **Any
/// further arm that reaches for one of those owes the same argument** -- the boot-time redaction protects
/// the `Document`, not the request path in general.
///
/// It is the accepted baseline's view: an accept of a live change replaces it
/// (`crate::live`); a reload does not.
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

/// The MARGIN on draining IN-FLIGHT connection handlers at the end of the accept
/// loop, on top of the per-connection bounds `handler_drain_bound` adds up
/// explicitly. Same class as `AUDIT_DRAIN_SHUTDOWN_TIMEOUT`: each handler performs
/// audit appends (`spawn_blocking` write+fsync under the hood), so a wedged audit
/// filesystem can block a handler indefinitely — an unbounded `join_next()` drain
/// would then hang shutdown BEFORE the at-capacity drain bound is even reached.
/// (Corrected 2026-09-15, review round 5: this constant used to BE the whole
/// drain bound, with a comment that said the per-connection work "totals ≤ ~15s"
/// — it is 26 s at the defaults and 191 s at the transport ceiling, and the
/// handshake runs inside the handler. Those terms are now named below.)
const HANDLER_DRAIN_SHUTDOWN_TIMEOUT: Duration = Duration::from_secs(10);

/// The bound actually used for that drain: every per-connection bound the
/// transport configuration sets, the egress backend's own deadline (#240 — a
/// permitted `session.prompt` holds its handler for up to `egress.deadline_ms`,
/// 280 s by default and 600 s at most, while the provider answers; with no
/// provider the backend is `Unavailable` and its deadline is zero), and the
/// margin above. A drain shorter than this aborts a handler mid-work on a
/// restart that races it — for a prompt: content left, `IntentOnly` in the
/// trail, no outcome record. The units give the supervisor the matching
/// patience (`TimeoutStopSec=`, launchd's `ExitTimeOut`), held to this sum at
/// both ceilings by a test.
fn handler_drain_bound(cfg: &TransportConfig, egress_deadline: Duration) -> Duration {
    // One connection's bounded work, in the order the handler performs it:
    // the mTLS handshake (inside the handler, not on the loop), the peer's
    // group lookup, the admission audit append, the frame read, the requester home's resolution (filesystem
    // verbs only), the PDP decision, the verb's own blocking step under the
    // same bound (the subject enumeration — a second `AUTHZ_DECIDE_TIMEOUT`,
    // review round 6), the provider call, the response write (bounded by the
    // read timeout), the close — then the margin for the audit appends.
    Duration::from_millis(cfg.handshake_timeout_ms)
        + Duration::from_millis(maknae_config::GROUP_LOOKUP_TIMEOUT_MS)
        + Duration::from_millis(maknae_config::ADMISSION_AUDIT_TIMEOUT_MS)
        + Duration::from_millis(cfg.read_timeout_ms)
        + HOME_RESOLVE_TIMEOUT
        + crate::handler::AUTHZ_DECIDE_TIMEOUT
        + crate::handler::AUTHZ_DECIDE_TIMEOUT
        + egress_deadline
        + Duration::from_millis(cfg.read_timeout_ms)
        + STREAM_CLOSE_TIMEOUT
        + HANDLER_DRAIN_SHUTDOWN_TIMEOUT
}

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

/// Bound on draining queued diagnostics to stderr before [`run`] returns; for admission
/// audit failures stderr is the only record.
const DIAG_FLUSH_TIMEOUT: Duration = Duration::from_secs(1);

/// Bound on reaping the credential supervisor after it is aborted at the end of
/// the accept loop (#240, review round 3). Detached, the supervisor could be
/// holding the plane client's lock across a Vault call — `renew_token_once`,
/// `rotate_leaf` — while `client.shutdown()` waits for that lock before its
/// `revoke-self`: a further 30 s the walked stop chain did not carry, and a
/// rotation finishing after retirement could re-install a leaf. Aborting drops
/// any held guard; the reap is bounded like every other drain here.
const SUPERVISOR_ABORT_REAP_TIMEOUT: Duration = Duration::from_secs(1);

/// Bound on reaping the handlers `drain_handlers_bounded` aborts on elapse. A
/// term of the shutdown chain in its own right (review round 4 found it
/// unnamed and uncounted): the drain's bound plus this is what a handler
/// drain can take.
const DRAIN_ABORT_REAP_TIMEOUT: Duration = Duration::from_secs(1);

/// Bound on shutdown's wait for a reload's turn. A reload committing past it may still
/// publish and append its records after the stop record.
const RELOAD_STOP_TIMEOUT: Duration = Duration::from_secs(5);

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
            let _ = tokio::time::timeout(DRAIN_ABORT_REAP_TIMEOUT, async {
                while handlers.join_next().await.is_some() {}
            })
            .await;
            DrainOutcome::Aborted
        }
    }
}

/// The bound on `subject.user` (#275): `maknae_vault::MAX_USERNAME_BYTES`, sized to the measured syslog worst case.
///
/// An over-long name is refused to `None`, never truncated: a truncated
/// identity in an audit trail is a WRONG identity, which is worse than an
/// absent one. A new field must also not be unbounded — that is the class of
/// defect the mirror's budget test exists to catch.
pub const MAX_SUBJECT_USER_BYTES: usize = maknae_vault::MAX_USERNAME_BYTES;

/// The decided subject identity stamped onto a record (#275). Audit-only:
/// nothing here is an authorization input.
pub(crate) fn admitted_user_pub(user: Option<&str>) -> Option<String> {
    admitted_user(user)
}

fn admitted_user(user: Option<&str>) -> Option<String> {
    user.filter(|u| u.len() <= MAX_SUBJECT_USER_BYTES)
        .map(str::to_string)
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
            role: None,
            plane_uri_san: peer_uri.map(str::to_string),
        },
        action: action.to_string(),
        object: object.map(str::to_string),
        object_requested: None,
        mutation: None,
        egress: None,
        conversation: None,
        graph: None,
        rule: None,
        policy_sha256: None,
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

#[allow(clippy::too_many_arguments)]
pub async fn handle<S, E, P>(
    stream: S,
    peer_uri: String,
    peer_uid: u32,
    in_group: bool,
    peer_user: Option<String>,
    peer_dir: Option<PathBuf>,
    emit: Arc<E>,
    session_id: u64,
    cfg: TransportConfig,
    au3_1: serde_json::Value,
    authorizer: Arc<P>,
    live: Arc<crate::live::LiveConfig>,
    authz_backend_name: Arc<String>,
    classification_policy_name: Arc<String>,
    kernel_graph: Arc<Option<KernelGraphStatus>>,
    egress: Arc<dyn crate::egress::Egress>,
    authz_decide_timeout: Duration,
    lane: maknae_security::Lane,
    delegated: maknae_io::DelegatedFds,
    baseline: Arc<dyn BaselineOps>,
) where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    E: AuditEmit + Send + Sync + 'static,
    P: Authorizer + Send + Sync + 'static,
{
    handle_with_attempt_caps(
        stream,
        peer_uri,
        peer_uid,
        in_group,
        peer_user,
        peer_dir,
        emit,
        session_id,
        cfg,
        au3_1,
        authorizer,
        live,
        authz_backend_name,
        classification_policy_name,
        kernel_graph,
        egress,
        authz_decide_timeout,
        lane,
        delegated,
        baseline,
        crate::mutation::AttemptCaps::default(),
    )
    .await
}

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
pub async fn handle_with_attempt_caps<S, E, P>(
    mut stream: S,
    peer_uri: String,
    peer_uid: u32,
    in_group: bool,
    // #275: the peer OS username, resolved on the blocking pool alongside the
    // group check. `None` on every fail-closed accept-loop arm, where not
    // spawning NSS work is the point -- the record then renders
    // `subject=unknown`, which is honest.
    // It also chooses the key path's `<username>` segment (ADR-0028 §3), so it
    // must stay kernel-resolved from the peer uid, never taken from the request.
    peer_user: Option<String>,
    peer_dir: Option<PathBuf>,
    emit: Arc<E>,
    session_id: u64,
    cfg: TransportConfig,
    au3_1: serde_json::Value,
    authorizer: Arc<P>,
    // The accepted baseline's view and providers authority, read per request.
    live: Arc<crate::live::LiveConfig>,
    // Captured ONCE at boot from the same authorizer (static TCB: the backend
    // set cannot change in-process, so per-request asking could only repeat
    // this string while running operand code inline on the worker).
    authz_backend_name: Arc<String>,
    // Captured ONCE at boot from the booted config (ADR-0022): the system
    // `core.handling.policy` selected, by name.
    classification_policy_name: Arc<String>,
    kernel_graph: Arc<Option<KernelGraphStatus>>,
    // #172: the egress backend behind the seam. `Unavailable` in Cooky.
    egress: Arc<dyn crate::egress::Egress>,
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
    // `admin.baseline.show` and `admin.baseline.accept`.
    baseline: Arc<dyn BaselineOps>,
    attempt_caps: crate::mutation::AttemptCaps,
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
            let mut rec = make_record(
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
            // #275: the peer identity, bounded and audit-only.
            rec.subject.user = admitted_user(peer_user.as_deref());
            if let Err(e) = emit
                .emit_within(
                    &rec,
                    Duration::from_millis(maknae_config::ADMISSION_AUDIT_TIMEOUT_MS),
                )
                .await
            {
                // Mid-life audit-write failure on a deny path is logged but does not change
                // the already-fail-closed outcome (the connection is refused); the permit
                // path gates on audit success, deny paths already deny.
                crate::diag::report(format!(
                    "maknaed: admission audit append failed or is unconfirmed on connection-deny (group check) for peer_uid={peer_uid} peer_uri={peer_uri} — the rejection proceeded: {e}"
                ));
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
            let mut rec = make_record(
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
            // #275: the peer identity, bounded and audit-only.
            rec.subject.user = admitted_user(peer_user.as_deref());
            let admission_result = emit
                .emit_within(
                    &rec,
                    Duration::from_millis(maknae_config::ADMISSION_AUDIT_TIMEOUT_MS),
                )
                .await;
            if !may_respond(admission_result.is_ok()) {
                if let Err(e) = admission_result {
                    crate::diag::report(format!(
                        "maknaed: admission audit write failed for peer_uid={peer_uid} peer_uri={peer_uri} session_id={session_id} — closing without serving: {e}"
                    ));
                }
                close_bounded(&mut stream).await;
                return;
            }
        }
    }

    // 2. Read exactly one request frame, bounded by read_timeout + the frame cap.
    let read = tokio::time::timeout(
        Duration::from_millis(cfg.read_timeout_ms),
        read_frame_zeroizing(&mut stream, &request_caps(&cfg, attempt_caps)),
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
                peer_user.as_deref(),
                None,
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
                peer_user.as_deref(),
                None,
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
        Ok(Ok(frame)) => frame,
    };
    let (class, body) = body;

    let request = match decode_request(&body) {
        Ok(r) => r,
        Err(e) => {
            emit_request_deny(
                &emit,
                &host,
                &socket,
                peer_uid,
                &peer_uri,
                peer_user.as_deref(),
                None,
                session_id,
                seq.next(),
                "decode",
                // The CLASS only (#172): serde's diagnostic quotes the offending
                // value, so a malformed prompt would carry prompt text into the
                // trail through `{e}`.
                &format!("malformed request: {}", e.category()),
                &au3_1,
            )
            .await;
            close_bounded(&mut stream).await;
            return;
        }
    };
    if !admits(class, &request.verb) {
        emit_request_deny(
            &emit,
            &host,
            &socket,
            peer_uid,
            &peer_uri,
            peer_user.as_deref(),
            None,
            session_id,
            seq.next(),
            "decode",
            &format!(
                "frame class mismatch: declared {class:?}, {} is {:?}",
                verb_to_action(&request.verb),
                class_of(&request.verb)
            ),
            &au3_1,
        )
        .await;
        close_bounded(&mut stream).await;
        return;
    }

    // 2½. THE PDP (spec D2, #77): every request is decided through the seam
    // before the audit-then-respond step. For a Read, the lexical pre-gate
    // runs FIRST — a malformed path is the BadRequest class (like a decode
    // failure -- though a decode failure itself is audited and CLOSED, never
    // answered; only this post-decode gate writes BadRequest), and the PDP is never consulted for it.
    if let Verb::Read { path, .. } = &request.verb {
        if let Err(why) = lexical_pregate(path) {
            let appended = emit_request_outcome(
                &emit,
                &host,
                &socket,
                peer_uid,
                &peer_uri,
                peer_user.as_deref(),
                None,
                None,
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
                    class,
                    ProtoErrCode::BadRequest,
                    "malformed path",
                )
                .await;
            }
            close_bounded(&mut stream).await;
            return;
        }
    }

    // #172, #265: the operand pre-gate, the same shape as the Read one — a
    // malformed conversation id or an inadmissible content kind is the
    // BadRequest class and never reaches the PDP. Result-returning emit, frame
    // gated on the append: `emit_request_deny` is for legs that serve nothing.
    let pregate = match &request.verb {
        Verb::SessionPrompt {
            output_tokens: Some(n),
            ..
        } if !maknae_proto::output_tokens_is_acceptable(*n) => {
            Some(("prompt", "reply cap not acceptable".to_string()))
        }
        Verb::SessionPrompt {
            conversation,
            turns,
            ..
        } => if !maknae_proto::conversation_id_is_acceptable(conversation) {
            Err("conversation identifier not acceptable".to_string())
        } else {
            crate::egress::admitted_turns(turns)
        }
        .err()
        .map(|reason| ("prompt", reason)),
        Verb::FsWrite {
            conversation: Some(conversation),
            ..
        } if !maknae_proto::conversation_id_is_acceptable(conversation) => Some((
            "write",
            "conversation identifier not acceptable".to_string(),
        )),
        Verb::Read {
            conversation: Some(conversation),
            ..
        } if !maknae_proto::conversation_id_is_acceptable(conversation) => {
            Some(("read", "conversation identifier not acceptable".to_string()))
        }
        Verb::Read { page: Some(p), .. } if !maknae_proto::page_request_is_acceptable(p) => {
            Some(("read", "page request not acceptable".to_string()))
        }
        _ => None,
    };
    if let Some((noun, reason)) = pregate {
        let appended = emit_request_outcome(
            &emit,
            &host,
            &socket,
            peer_uid,
            &peer_uri,
            peer_user.as_deref(),
            None,
            None,
            session_id,
            seq.next(),
            verb_to_action(&request.verb),
            None,
            None,
            "deny",
            &format!("{noun} fails operand pre-gate: {reason}"),
            "unauthorized",
            &au3_1,
        )
        .await;
        if may_respond(appended) {
            write_error_bounded(
                &mut stream,
                &cfg,
                class,
                ProtoErrCode::BadRequest,
                "invalid request",
            )
            .await;
        }
        close_bounded(&mut stream).await;
        return;
    }

    if crate::handler::is_filesystem_verb(&request.verb) {
        let mut record = make_record(
            "request",
            &host,
            &socket,
            peer_uid,
            None,
            None,
            Some(&peer_uri),
            session_id,
            seq.next(),
            verb_to_action(&request.verb),
            None,
            "deny",
            "mutation not prepared",
            "unauthorized",
            &au3_1,
        );
        // #275: the peer identity, bounded and audit-only.
        record.subject.user = admitted_user(peer_user.as_deref());
        if let Verb::FsWrite { conversation, .. } | Verb::Read { conversation, .. } = &request.verb
        {
            record.conversation.clone_from(conversation);
        }
        crate::mutation::handle(
            &mut stream,
            &request.verb,
            peer_uid,
            lane,
            &delegated,
            Arc::clone(&authorizer),
            Arc::clone(&emit),
            crate::authz::admitted_home(peer_uid, peer_dir).await,
            &cfg,
            &seq,
            record,
            authz_decide_timeout,
            attempt_caps,
            &classification_policy_name,
        )
        .await;
        close_bounded(&mut stream).await;
        return;
    }

    let no_providers = maknae_config::ProviderSet::empty();
    let (admitted_view, providers, admitted_generation) = live.admission();
    let admitted = match &request.verb {
        Verb::SessionPrompt { choice, .. } => {
            let (set, user_prefix) = match &*providers {
                Some(a) => (&a.set, a.user_prefix.as_str()),
                None => (&no_providers, ""),
            };
            match crate::provider_choice::admit_choice(
                set,
                choice.as_ref(),
                peer_user.as_deref(),
                user_prefix,
            ) {
                Ok(a) => Some(a),
                Err(refusal) => {
                    let appended = emit_request_outcome(
                        &emit,
                        &host,
                        &socket,
                        peer_uid,
                        &peer_uri,
                        peer_user.as_deref(),
                        None,
                        None,
                        session_id,
                        seq.next(),
                        verb_to_action(&request.verb),
                        None,
                        None,
                        "deny",
                        refusal.reason(),
                        "unauthorized",
                        &au3_1,
                    )
                    .await;
                    if may_respond(appended) {
                        write_error_bounded(
                            &mut stream,
                            &cfg,
                            class,
                            ProtoErrCode::Unauthorized,
                            "not authorized",
                        )
                        .await;
                    }
                    close_bounded(&mut stream).await;
                    return;
                }
            }
        }
        _ => None,
    };

    // Decide on the BLOCKING pool (the seam permits a backend that blocks; a
    // stall must not pin async workers — the same offload discipline as
    // accept_loop's group lookup), bounded, composed per the
    // parent contract: combine([guarded_decide]) + finalize. Timeout or join
    // failure converts AT THE CALL SITE to a Deny with its own reason
    // (finalize(Indeterminate) would hardcode a different string).
    let sec_req = build_authz_request(&request.verb, peer_uid, None, lane, admitted.as_ref());
    let authz_breaker = authz_decide_breaker();
    let authz_admission = { authz_breaker.lock().await.begin_attempt_at(Instant::now()) };
    // #275: the role rides out WITH the verdict so the audit record attests the
    // role this very decision was made on. `combine(vec![..])` is preserved
    // deliberately: it is what turns an Indeterminate into the
    // "indeterminate operand blocks (fail-closed)" trail string, and dropping
    // the wrapper would change that string silently.
    let mut decided_role: Option<&'static str> = None;
    let mut decided_rule: Option<RuleCitation> = None;
    let verdict = match authz_admission {
        BreakerAdmission::RefuseOpen => maknae_security::Verdict::Deny {
            reason: "authorization decision circuit breaker open".into(),
        },
        BreakerAdmission::RefuseAtCapacity => maknae_security::Verdict::Deny {
            reason: "authorization decision blocking worker budget exhausted".into(),
        },
        BreakerAdmission::Admit => {
            let decided = {
                let (a, live) = (Arc::clone(&authorizer), Arc::clone(&live));
                tokio::time::timeout(
                    authz_decide_timeout,
                    tokio::task::spawn_blocking(move || {
                        let d = guarded_decide_cited(&*a, &sec_req);
                        (combine(vec![d.verdict]), d.role, d.rule, live.generation())
                    }),
                )
                .await
            };
            match decided {
                // A live install landed between admission and the decision: the
                // request was admitted on values the decision did not see.
                Ok(Ok((_, role, _, generation))) if generation != admitted_generation => {
                    authz_breaker.lock().await.record_success();
                    decided_role = role;
                    maknae_security::Verdict::Deny {
                        reason: "the live baseline changed between admission and decision".into(),
                    }
                }
                Ok(Ok((v, role, rule, _))) => {
                    authz_breaker.lock().await.record_success();
                    decided_role = role;
                    decided_rule = rule;
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
                peer_user.as_deref(),
                decided_role,
                decided_rule.as_ref(),
                session_id,
                seq.next(),
                verb_to_action(&request.verb),
                None,
                None,
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
                    class,
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
            peer_user.as_deref(),
            decided_role,
            None,
            session_id,
            seq.next(),
            verb_to_action(&request.verb),
            None,
            None,
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
                class,
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
    // time.
    match dispatch_verb(&request.verb) {
        Dispatch::MutationRequested => {
            let appended = emit_request_outcome(
                &emit,
                &host,
                &socket,
                peer_uid,
                &peer_uri,
                peer_user.as_deref(),
                decided_role,
                None,
                session_id,
                seq.next(),
                verb_to_action(&request.verb),
                None,
                None,
                "deny",
                "mutation dispatch reached without prepared evidence",
                "unauthorized",
                &au3_1,
            )
            .await;
            if may_respond(appended) {
                write_error_bounded(
                    &mut stream,
                    &cfg,
                    class,
                    ProtoErrCode::Unauthorized,
                    "not authorized",
                )
                .await;
            }
            close_bounded(&mut stream).await;
            return;
        }
        Dispatch::NoBehaviour => {
            // Decided and PERMITTED above; the term simply has no behaviour.
            // (#181, 2026-09-02: only an EXTENSION grant can produce that
            // Permit — ADR-0008 D2 — since `-basic` cannot permit an unbuilt
            // term; with `-basic` alone this arm is unreachable and an
            // unpermitted unbuilt term answers Unauthorized upstream.)
            // Same audit-then-respond gate as every sibling path — the record
            // must be durable before any frame is released (ADR-0019).
            let appended = emit_request_outcome(
                &emit,
                &host,
                &socket,
                peer_uid,
                &peer_uri,
                peer_user.as_deref(),
                decided_role,
                decided_rule.as_ref(),
                session_id,
                seq.next(),
                verb_to_action(&request.verb),
                None,
                None,
                "permit",
                "permitted; term not implemented",
                "not-implemented",
                &au3_1,
            )
            .await;
            if may_respond(appended) {
                // The SAME wire answer as every refusal (operator ruling
                // 2026-09-02, #181: "unauthorized is all that is published to
                // the wire" — superseding the #67 NOOP contract's wire half).
                // Build state is not a wire disclosure on ANY path; the trail
                // above carries the truth (permit / not-implemented), and an
                // extension that wants to expose implementation state to its
                // callers does so through its own channel.
                write_error_bounded(
                    &mut stream,
                    &cfg,
                    class,
                    ProtoErrCode::Unauthorized,
                    "not authorized",
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
        | Dispatch::SubjectListRequested
        | Dispatch::BaselineShowRequested
        | Dispatch::BaselineAcceptRequested => {
            let appended = emit_request_outcome(
                &emit,
                &host,
                &socket,
                peer_uid,
                &peer_uri,
                peer_user.as_deref(),
                decided_role,
                decided_rule.as_ref(),
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
                // Redacted when installed, and taken at admission with the
                // providers the decision was generation-checked against.
                Dispatch::ConfigShowRequested => Payload::ConfigView((*admitted_view).clone()),
                Dispatch::StatusRequested => Payload::Status(maknae_proto::StatusView {
                    version: env!("CARGO_PKG_VERSION").to_string(),
                    protocol_version: PROTOCOL_VERSION,
                    listener: cfg.socket_path.display().to_string(),
                    // Asked of the PDP, not hardcoded -- ONCE, at boot, where
                    // a blocking backend hangs startup loudly instead of
                    // eating a tokio worker per granted request (the seam doc's
                    // "MUST NOT block" is a contract, not an enforcement).
                    // Panic-guarded and sanitized at capture; the request path
                    // runs no operand code for this field.
                    authz_backend: (*authz_backend_name).clone(),
                    classification_policy: (*classification_policy_name).clone(),
                    kernel_graph_revision: kernel_graph
                        .as_ref()
                        .as_ref()
                        .map(KernelGraphStatus::revision),
                    kernel_graph_anchor: kernel_graph.as_ref().as_ref().map(|k| k.anchor.clone()),
                    identity_problem_counts: kernel_graph
                        .as_ref()
                        .as_ref()
                        .map(|k| k.identity.counts())
                        .unwrap_or_default(),
                    baseline_pending: kernel_graph
                        .as_ref()
                        .as_ref()
                        .map(|k| k.baseline.lines())
                        .unwrap_or_default(),
                }),
                // The current snapshot, via the seam. `None` means the backend cannot
                // enumerate, and that is reported as unavailable below --
                // never as an empty list, which would claim "no bindings
                // exist" and is a different, dangerous answer.
                // OFFLOADED, bounded, and breaker-admitted -- the SAME
                // discipline the decide path gets 250 lines above, and for the
                // same reason stated there: the seam permits a backend whose
                // `subjects()` blocks. Called inline such a backend pins a
                // tokio worker for as long as it blocks, and N granted calls
                // starve the runtime -- with the breaker unable to trip,
                // because it never sees them.
                Dispatch::SubjectListRequested => {
                    let subj_breaker = authz_decide_breaker();
                    let admission = { subj_breaker.lock().await.begin_attempt_at(Instant::now()) };
                    let enumerated = match admission {
                        BreakerAdmission::RefuseOpen => Err("enumeration circuit breaker open"),
                        BreakerAdmission::RefuseAtCapacity => {
                            Err("enumeration blocking worker budget exhausted")
                        }
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
                                Ok(Ok(Some(v))) => {
                                    subj_breaker.lock().await.record_success();
                                    Ok(v)
                                }
                                // The backend ANSWERED, and its answer is "I
                                // cannot enumerate" -- permanent, benign, and
                                // the shipped default's state. An auditor must
                                // be able to tell it from a wedged mount.
                                Ok(Ok(None)) => {
                                    subj_breaker.lock().await.record_success();
                                    Err("backend does not enumerate bindings")
                                }
                                // A JOIN failure is not counted against the
                                // breaker -- same as the decide path, where a
                                // panicked/cancelled task is not evidence that
                                // the filesystem is wedged.
                                Ok(Err(_join)) => {
                                    subj_breaker.lock().await.record_success();
                                    Err("enumeration failed (join)")
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
                                    Err("enumeration timed out")
                                }
                            }
                        }
                    };
                    match enumerated {
                        Ok(b) => Payload::SubjectList(crate::identity_report::subject_views(
                            b,
                            &kernel_graph
                                .as_ref()
                                .as_ref()
                                .map(|k| k.identity.subjects())
                                .unwrap_or_default(),
                        )),
                        Err(why) => {
                            // A SECOND record, correcting the posture.
                            //
                            // The record for this request was appended as
                            // `permit / authorized` before dispatch, and the
                            // enumeration then refused -- so the trail asserted
                            // an authorized-and-SERVED admin.subject.list for a
                            // request whose caller received `Internal`.
                            // ADR-0019 pins `unavailable` in the posture domain
                            // precisely so a Permit-then-not-performed cannot
                            // read as a completed action.
                            let corrected = emit_request_outcome(
                                &emit,
                                &host,
                                &socket,
                                peer_uid,
                                &peer_uri,
                                peer_user.as_deref(),
                                decided_role,
                                decided_rule.as_ref(),
                                session_id,
                                seq.next(),
                                verb_to_action(&request.verb),
                                None,
                                None,
                                "deny",
                                // The SPECIFIC condition. Five paths reach
                                // here and only one is benign: "this backend
                                // does not enumerate" is the shipped default's
                                // permanent state, while "the breaker is open"
                                // is an incident.
                                &format!("binding enumeration unavailable: {why}"),
                                "unavailable",
                                &au3_1,
                            )
                            .await;
                            // Gated on the CORRECTIVE record's own result, not
                            // the admission record's. An earlier comment here
                            // argued a guard would be a literal `if true` --
                            // which is true of `appended`, and irrelevant: the
                            // value in hand is a SECOND, freshly meaningful
                            // bool. Discarding it left the degraded-sink case
                            // with a trail whose only surviving record says
                            // `permit / authorized / authorized` -- affirming a
                            // disclosure that did not happen, the exact failure
                            // this corrective record was added to prevent --
                            // while `emit_request_outcome` printed "withholding
                            // the frame" and the frame went out anyway.
                            if may_respond(corrected) {
                                write_error_bounded(
                                    &mut stream,
                                    &cfg,
                                    class,
                                    ProtoErrCode::Internal,
                                    "binding enumeration unavailable",
                                )
                                .await;
                            }
                            close_bounded(&mut stream).await;
                            return;
                        }
                    }
                }
                Dispatch::BaselineShowRequested => match baseline.show().await {
                    Ok(view) => Payload::Baseline(view),
                    Err(why) => {
                        let corrected = emit_request_outcome(
                            &emit,
                            &host,
                            &socket,
                            peer_uid,
                            &peer_uri,
                            peer_user.as_deref(),
                            decided_role,
                            decided_rule.as_ref(),
                            session_id,
                            seq.next(),
                            verb_to_action(&request.verb),
                            None,
                            None,
                            "deny",
                            &format!("baseline show unavailable: {why}"),
                            "unavailable",
                            &au3_1,
                        )
                        .await;
                        if may_respond(corrected) {
                            write_error_bounded(
                                &mut stream,
                                &cfg,
                                class,
                                ProtoErrCode::Internal,
                                "baseline show unavailable",
                            )
                            .await;
                        }
                        close_bounded(&mut stream).await;
                        return;
                    }
                },
                Dispatch::BaselineAcceptRequested => {
                    let Verb::AdminBaselineAccept { hash } = &request.verb else {
                        unreachable!("dispatch keyed on the verb")
                    };
                    match baseline.accept(hash).await {
                        AcceptAnswer::View {
                            view,
                            corrective: None,
                        } => Payload::Baseline(view),
                        AcceptAnswer::View {
                            view,
                            corrective: Some(why),
                        } => {
                            let corrected = emit_request_outcome(
                                &emit,
                                &host,
                                &socket,
                                peer_uid,
                                &peer_uri,
                                peer_user.as_deref(),
                                decided_role,
                                decided_rule.as_ref(),
                                session_id,
                                seq.next(),
                                verb_to_action(&request.verb),
                                None,
                                None,
                                "deny",
                                &why,
                                "unauthorized",
                                &au3_1,
                            )
                            .await;
                            if !may_respond(corrected) {
                                close_bounded(&mut stream).await;
                                return;
                            }
                            Payload::Baseline(view)
                        }
                        AcceptAnswer::Unavailable { reply, why } => {
                            let corrected = emit_request_outcome(
                                &emit,
                                &host,
                                &socket,
                                peer_uid,
                                &peer_uri,
                                peer_user.as_deref(),
                                decided_role,
                                decided_rule.as_ref(),
                                session_id,
                                seq.next(),
                                verb_to_action(&request.verb),
                                None,
                                None,
                                "deny",
                                &why,
                                "unavailable",
                                &au3_1,
                            )
                            .await;
                            if may_respond(corrected) {
                                write_error_bounded(
                                    &mut stream,
                                    &cfg,
                                    class,
                                    ProtoErrCode::Internal,
                                    reply,
                                )
                                .await;
                            }
                            close_bounded(&mut stream).await;
                            return;
                        }
                    }
                }
                Dispatch::NoBehaviour | Dispatch::MutationRequested | Dispatch::PromptRequested => {
                    unreachable!("outer match routes unprepared operations")
                }
            };
            let response = Response {
                protocol_version: PROTOCOL_VERSION,
                result: RespResult::Ok(payload),
            };
            // Bound the response write by read_timeout_ms (it doubles as the
            // write bound — both cap how long one peer may hold this permit).
            // UNCHANGED encoder for these payloads (#172 extracted the write
            // and its two corrective records into helpers; only the prompt arm
            // uses the zeroizing, pre-sized encoder).
            match encode_response(&response) {
                Ok(bytes) => {
                    write_frame_bounded(
                        &mut stream,
                        &cfg,
                        class,
                        &bytes,
                        &emit,
                        &host,
                        &socket,
                        peer_uid,
                        &peer_uri,
                        peer_user.as_deref(),
                        decided_role,
                        decided_rule.as_ref(),
                        session_id,
                        &seq,
                        verb_to_action(&request.verb),
                        &au3_1,
                    )
                    .await
                }
                Err(_) => {
                    refuse_unencodable_bounded(
                        &mut stream,
                        &cfg,
                        class,
                        &emit,
                        &host,
                        &socket,
                        peer_uid,
                        &peer_uri,
                        peer_user.as_deref(),
                        decided_role,
                        decided_rule.as_ref(),
                        session_id,
                        &seq,
                        verb_to_action(&request.verb),
                        &au3_1,
                    )
                    .await
                }
            }
        }
        Dispatch::PromptRequested => {
            let Verb::SessionPrompt {
                conversation,
                turns,
                output_tokens,
                ..
            } = &request.verb
            else {
                unreachable!("dispatch keyed on the verb")
            };
            let Some(chosen) = admitted.as_ref() else {
                let appended = emit_request_outcome(
                    &emit,
                    &host,
                    &socket,
                    peer_uid,
                    &peer_uri,
                    peer_user.as_deref(),
                    decided_role,
                    None,
                    session_id,
                    seq.next(),
                    "session.prompt",
                    None,
                    None,
                    "deny",
                    "session.prompt reached dispatch without an admitted provider choice",
                    "unauthorized",
                    &au3_1,
                )
                .await;
                if may_respond(appended) {
                    write_error_bounded(
                        &mut stream,
                        &cfg,
                        class,
                        ProtoErrCode::Unauthorized,
                        "not authorized",
                    )
                    .await;
                }
                close_bounded(&mut stream).await;
                return;
            };
            let name = chosen.provider.name.as_str();
            let destination = format!("provider:{name}");
            let m = crate::egress::content_measure(turns);
            let egress_meta = |status| EgressAudit {
                status,
                content_length: m.length,
                content_digest: m.digest32.clone(),
                conversation: conversation.clone(),
                model: Some(chosen.model.to_string()),
                reply_length: None,
                output_tokens: *output_tokens,
                prompt_tokens: None,
                completion_tokens: None,
            };
            // 1. readiness BEFORE any intent: a refusal is not a send.
            if let Err(_f) = egress.ready() {
                let mut rec = make_record(
                    "request",
                    &host,
                    &socket,
                    peer_uid,
                    None,
                    None,
                    Some(&peer_uri),
                    session_id,
                    seq.next(),
                    "session.prompt",
                    Some(&destination),
                    "deny",
                    "egress backend not ready",
                    "unavailable",
                    &au3_1,
                );
                // #275: the peer identity AND the role this very decision was
                // made on. The egress records are permitted decisions, so
                // omitting the role would make every prompt say role=none.
                rec.subject.user = admitted_user(peer_user.as_deref());
                rec.subject.role = decided_role.map(str::to_string);
                rec.egress = Some(egress_meta(EgressStatus::BackendUnavailable));
                let appended =
                    emit_or_report(&emit, &rec, "egress refusal", peer_uid, session_id).await;
                // Build state is not a wire disclosure (ruling 2026-09-02).
                if may_respond(appended) {
                    write_error_bounded(
                        &mut stream,
                        &cfg,
                        class,
                        ProtoErrCode::Unauthorized,
                        "not authorized",
                    )
                    .await;
                }
                close_bounded(&mut stream).await;
                return;
            }
            // 2. the write-ahead intent; the TYPE of `send` makes step 3
            //    impossible without it (egress.rs).
            let mut intent = make_record(
                "request",
                &host,
                &socket,
                peer_uid,
                None,
                None,
                Some(&peer_uri),
                session_id,
                seq.next(),
                "session.prompt",
                Some(&destination),
                "permit",
                "intent recorded",
                "authorized",
                &au3_1,
            );
            // #275: identity AND role. The OUTCOME record is derived from this
            // intent by clone, so an omission here propagates to both halves of
            // the write-ahead pair.
            intent.subject.user = admitted_user(peer_user.as_deref());
            intent.subject.role = decided_role.map(str::to_string);
            intent.rule = decided_rule.as_ref().map(rule_audit);
            intent.egress = Some(egress_meta(EgressStatus::IntentOnly));
            let intent = match crate::egress::commit_intent(&*emit, intent).await {
                Ok(i) => i,
                Err(e) => {
                    eprintln!(
                        "maknaed: AUDIT WRITE FAILED on egress intent (peer_uid={peer_uid} session_id={session_id}) — withholding the send: {e}"
                    );
                    close_bounded(&mut stream).await;
                    return;
                }
            };
            // 3. the send, on a blocking worker, under the BACKEND's own
            //    deadline (`egress.deadline()`, #240 — the transport read
            //    timeout was never a provider bound) and the egress breaker.
            //    The intent is shared by Arc so the outcome record can be
            //    derived from it even if the worker is abandoned on expiry.
            let intent = Arc::new(intent);
            // #240a: admitted BEFORE the spawn, matching its siblings.
            // `run.rs` handed #240 this obligation by name; the ordering is the
            // whole control, not the presence of a breaker.
            let egress_breaker = egress_send_breaker();
            let egress_admission = { egress_breaker.lock().await.begin_attempt_at(Instant::now()) };
            let sent = match egress_admission {
                // Refused without spawning anything. Delivery did not happen,
                // so this is a `Failed` — the content never left.
                BreakerAdmission::RefuseOpen => {
                    // Rate-limited, like the siblings': the trail says
                    // `send failed`; the journal must say why.
                    if egress_breaker
                        .lock()
                        .await
                        .should_log_refusal_at(Instant::now())
                    {
                        eprintln!(
                            "maknaed: egress circuit breaker open (peer_uid={peer_uid} session_id={session_id}) — refusing the send without spawning more egress work"
                        );
                    }
                    Ok(Ok(Err(crate::egress::EgressFailure::Transport(
                        "egress circuit breaker open".into(),
                    ))))
                }
                BreakerAdmission::RefuseAtCapacity => {
                    if egress_breaker
                        .lock()
                        .await
                        .should_log_refusal_at(Instant::now())
                    {
                        eprintln!(
                            "maknaed: egress blocking worker budget exhausted (peer_uid={peer_uid} session_id={session_id}) — refusing the send"
                        );
                    }
                    Ok(Ok(Err(crate::egress::EgressFailure::Transport(
                        "egress blocking worker budget exhausted".into(),
                    ))))
                }
                BreakerAdmission::Admit => {
                    let egress = Arc::clone(&egress);
                    let intent = Arc::clone(&intent);
                    let req = crate::egress::EgressRequest::for_choice(
                        chosen,
                        destination.clone(),
                        conversation.clone(),
                        turns.clone(),
                        *output_tokens,
                    );
                    let deadline = egress.deadline();
                    let sent = tokio::time::timeout(
                        deadline,
                        tokio::task::spawn_blocking(move || egress.send(&intent, req)),
                    )
                    .await;
                    // The OTHER half of admission (#240, critical review): a
                    // worker that returned — reply, failure or panic — gives its
                    // slot back; an expired one counts toward the trip, so a
                    // stalled deputy opens the breaker after three orphaned
                    // workers instead of pinning one per prompt. Without this
                    // the daemon refused every prompt after its first
                    // thirty-two, for the rest of its life.
                    // The backend's own expiry is an expiry: the request left
                    // and no reply came within the budget. Counting it as a
                    // success would reset the breaker on the very stall it
                    // exists to trip on (codex on #240). Which failures count
                    // is `failure_counts_as_expiry`'s decision, T1-pinned.
                    let expired = match &sent {
                        Err(_elapsed) => true,
                        Ok(Ok(Err(f))) => crate::egress::failure_counts_as_expiry(f),
                        Ok(_) => false,
                    };
                    match expired {
                        true => {
                            if egress_breaker
                                .lock()
                                .await
                                .record_timeout_at(Instant::now())
                                == BreakerTransition::Tripped
                            {
                                eprintln!(
                                    "maknaed: egress circuit breaker tripped after repeated {}s send deadlines — failing closed without spawning more egress work",
                                    deadline.as_secs()
                                );
                            }
                        }
                        false => egress_breaker.lock().await.record_success(),
                    }
                    sent
                }
            };
            let (send_outcome, reply) = match sent {
                Ok(Ok(Ok(r))) => {
                    // Admission and the cap check happen HERE, before the
                    // outcome record, so the trail names the refusal with the
                    // reply's length (ADR-0023 decision 3: landed, undelivered)
                    // and no un-zeroized copy is ever made (reply_capacity is
                    // checked before encoding, and only on a text-only reply).
                    let n = crate::egress::reply_text_length(&r.reply);
                    match crate::egress::admitted_reply(&r.reply) {
                        Err(refusal) => (
                            crate::egress::SendOutcome::LandedUndelivered {
                                reply_length: n,
                                refusal,
                                usage: r.reply.usage,
                            },
                            None,
                        ),
                        Ok(())
                            if crate::egress::reply_capacity(&r.reply) > cfg.prompt_max_bytes =>
                        {
                            (
                                crate::egress::SendOutcome::LandedUndelivered {
                                    reply_length: n,
                                    refusal: crate::egress::ReplyRefusal::Oversize,
                                    usage: r.reply.usage,
                                },
                                None,
                            )
                        }
                        Ok(()) => (
                            crate::egress::SendOutcome::Sent {
                                reply_length: n,
                                usage: r.reply.usage,
                            },
                            Some(r.reply),
                        ),
                    }
                }
                Ok(Ok(Err(f))) => (crate::egress::outcome_for_failure(&f), None),
                Ok(Err(join)) => {
                    // The blocking worker was LOST (it panicked). Whether bytes
                    // left before the panic is unknowable to the kernel.
                    // Recorded `Failed` by an explicit collapse: #240's backend
                    // contract is that `send` does not panic, so a lost worker
                    // is a DEFECT surfaced here, not an outcome class the trail
                    // models (ADR-0019 amendment, #172).
                    // NOT `{join}`: JoinError's Display interpolates the panic
                    // payload verbatim, and a backend panic message could carry
                    // prompt text; the trail and the journal are
                    // length-and-digest only. Id and kind are enough.
                    eprintln!(
                        "maknaed: egress worker lost during send (peer_uid={peer_uid} session_id={session_id} task={} panic={})",
                        join.id(),
                        join.is_panic()
                    );
                    (crate::egress::SendOutcome::Failed, None)
                }
                // The worker keeps running detached; its late reply is dropped.
                Err(_elapsed) => (crate::egress::SendOutcome::DeadlineExpired, None),
            };
            // 4. the outcome record, then the reply: audit-then-respond on the
            //    release leg (#146).
            let outcome =
                crate::egress::outcome_for(&intent, seq.next(), rfc3339_now(), send_outcome);
            let appended =
                emit_or_report(&emit, &outcome, "egress outcome", peer_uid, session_id).await;
            if may_respond(appended) {
                match (send_outcome, reply) {
                    (_, Some(reply)) => {
                        // 5. within-cap: encode into a buffer that never grows
                        //    (no un-zeroized partial copies in freed heap).
                        let cap = crate::egress::reply_capacity(&reply);
                        let response = Response {
                            protocol_version: PROTOCOL_VERSION,
                            result: RespResult::Ok(Payload::PromptReply(reply)),
                        };
                        match encode_response_zeroizing(&response, cap) {
                            Ok(bytes) => {
                                write_frame_bounded(
                                    &mut stream,
                                    &cfg,
                                    class,
                                    &bytes,
                                    &emit,
                                    &host,
                                    &socket,
                                    peer_uid,
                                    &peer_uri,
                                    peer_user.as_deref(),
                                    decided_role,
                                    decided_rule.as_ref(),
                                    session_id,
                                    &seq,
                                    "session.prompt",
                                    &au3_1,
                                )
                                .await
                            }
                            Err(_) => {
                                refuse_unencodable_bounded(
                                    &mut stream,
                                    &cfg,
                                    class,
                                    &emit,
                                    &host,
                                    &socket,
                                    peer_uid,
                                    &peer_uri,
                                    peer_user.as_deref(),
                                    decided_role,
                                    decided_rule.as_ref(),
                                    session_id,
                                    &seq,
                                    "session.prompt",
                                    &au3_1,
                                )
                                .await
                            }
                        }
                    }
                    // The outcome record above already names the refusal; no
                    // second corrective record.
                    (
                        crate::egress::SendOutcome::LandedUndelivered {
                            refusal: crate::egress::ReplyRefusal::Oversize,
                            ..
                        },
                        None,
                    ) => {
                        write_error_bounded(
                            &mut stream,
                            &cfg,
                            class,
                            ProtoErrCode::TooLarge,
                            "response exceeds the configured frame limit",
                        )
                        .await
                    }
                    // Failed, DeadlineExpired, and the non-text / empty refusals.
                    (_, None) => {
                        write_error_bounded(
                            &mut stream,
                            &cfg,
                            class,
                            ProtoErrCode::Unauthorized,
                            "not authorized",
                        )
                        .await
                    }
                }
            }
            close_bounded(&mut stream).await;
            return;
        }
    }
    close_bounded(&mut stream).await;
}

/// Append a pre-built record and say so in the journal if it fails, like every
/// result-returning emitter on this loop; returns append success for `may_respond`.
async fn emit_or_report<E: AuditEmit + Send + Sync>(
    emit: &Arc<E>,
    rec: &AuditRecord,
    what: &str,
    peer_uid: u32,
    session_id: u64,
) -> bool {
    match emit.emit_within(rec, AUDIT_APPEND_TIMEOUT).await {
        Ok(()) => true,
        Err(e) => {
            eprintln!(
                "maknaed: AUDIT WRITE FAILED on {what} (peer_uid={peer_uid} session_id={session_id}) — withholding the frame: {e}"
            );
            false
        }
    }
}

/// The over-cap refusal of a PERMITTED payload: a CORRECTIVE record (`permit`
/// stays because the decision WAS a permit; only the delivery was refused,
/// ADR-0019's `refused-oversize`), then `TooLarge`, gated on the append like
/// every other outcome record on this loop. Never closes the stream and never
/// returns on `handle`'s behalf: the caller closes.
#[allow(clippy::too_many_arguments)]
async fn refuse_oversize_bounded<S, E: AuditEmit + Send + Sync>(
    stream: &mut S,
    cfg: &TransportConfig,
    class: FrameClass,
    emit: &Arc<E>,
    host: &str,
    socket: &str,
    peer_uid: u32,
    peer_uri: &str,
    // #275: the peer's OS username, already bounded.
    peer_user: Option<&str>,
    role: Option<&'static str>,
    rule: Option<&RuleCitation>,
    session_id: u64,
    seq: &Seq,
    action: &str,
    au3_1: &serde_json::Value,
) where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    // Without it the trail asserts an authorized-and-SERVED disclosure for a
    // caller that received TooLarge.
    let corrected = emit_request_outcome(
        emit,
        host,
        socket,
        peer_uid,
        peer_uri,
        peer_user,
        role,
        rule,
        session_id,
        seq.next(),
        action,
        None,
        None,
        "permit",
        "delivery refused: response exceeds the frame limit",
        "refused-oversize",
        au3_1,
    )
    .await;
    // Same gate as every other outcome record on this loop: if the correction
    // cannot be recorded, the trail still reads `permit / authorized /
    // authorized`, so nothing may go back to the caller.
    if may_respond(corrected) {
        write_error_bounded(
            stream,
            cfg,
            class,
            ProtoErrCode::TooLarge,
            "response exceeds the configured frame limit",
        )
        .await;
    }
}

/// The encode-failure corrective: practically unreachable (ciborium into a
/// Vec, for owned types), but NO PATH may have recorded `authorized` without
/// delivering. Never closes the stream.
#[allow(clippy::too_many_arguments)]
async fn refuse_unencodable_bounded<S, E: AuditEmit + Send + Sync>(
    stream: &mut S,
    cfg: &TransportConfig,
    class: FrameClass,
    emit: &Arc<E>,
    host: &str,
    socket: &str,
    peer_uid: u32,
    peer_uri: &str,
    // #275: the peer's OS username, already bounded.
    peer_user: Option<&str>,
    role: Option<&'static str>,
    rule: Option<&RuleCitation>,
    session_id: u64,
    seq: &Seq,
    action: &str,
    au3_1: &serde_json::Value,
) where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let corrected = emit_request_outcome(
        emit,
        host,
        socket,
        peer_uid,
        peer_uri,
        peer_user,
        role,
        rule,
        session_id,
        seq.next(),
        action,
        None,
        None,
        "permit",
        "delivery failed: response could not be encoded",
        "unavailable",
        au3_1,
    )
    .await;
    if may_respond(corrected) {
        write_error_bounded(
            stream,
            cfg,
            class,
            ProtoErrCode::Internal,
            "response encoding failed",
        )
        .await;
    }
}

/// SIZE-BOUNDED write of an already-encoded response: a
/// PERMIT whose delivery is refused is refused EXPLICITLY (`TooLarge` with a
/// corrective record), never truncated and never silently oversized. The write
/// is bounded by `read_timeout_ms`, which doubles as the write bound (both cap
/// how long one peer may hold this permit). `seq` is consumed ONLY on the
/// corrective branch; a successful write burns no sequence number. Never
/// closes the stream.
#[allow(clippy::too_many_arguments)]
async fn write_frame_bounded<S, E: AuditEmit + Send + Sync>(
    stream: &mut S,
    cfg: &TransportConfig,
    class: FrameClass,
    bytes: &[u8],
    emit: &Arc<E>,
    host: &str,
    socket: &str,
    peer_uid: u32,
    peer_uri: &str,
    peer_user: Option<&str>,
    role: Option<&'static str>,
    rule: Option<&RuleCitation>,
    session_id: u64,
    seq: &Seq,
    action: &str,
    au3_1: &serde_json::Value,
) where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    if bytes.len() > FrameCaps::responses(cfg.prompt_max_bytes).cap(class) {
        refuse_oversize_bounded(
            stream, cfg, class, emit, host, socket, peer_uid, peer_uri, peer_user, role, rule,
            session_id, seq, action, au3_1,
        )
        .await;
        return;
    }
    let _ = tokio::time::timeout(
        Duration::from_millis(cfg.read_timeout_ms),
        write_frame(stream, class, bytes),
    )
    .await;
}

/// Write one generic error frame, bounded like every response write. The
/// message is ALWAYS a fixed generic string — reasons live in the trail.
async fn write_error_bounded<S>(
    stream: &mut S,
    cfg: &TransportConfig,
    class: FrameClass,
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
            write_frame(stream, class, &bytes),
        )
        .await;
    }
}

fn request_caps(cfg: &TransportConfig, attempt_caps: crate::mutation::AttemptCaps) -> FrameCaps {
    FrameCaps {
        control: CONTROL_REQUEST_MAX,
        attempt: attempt_caps.request,
        prompt: cfg.prompt_max_bytes,
    }
}

pub(crate) fn rule_audit(c: &RuleCitation) -> maknae_audit_append::RuleAudit {
    maknae_audit_append::RuleAudit {
        node: c.node,
        key: c.key.clone(),
        section: c.section.clone(),
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
    // #275: the peer's OS username, already bounded by `admitted_user`.
    peer_user: Option<&str>,
    // #275: the role the decision was MADE ON, or None on records that
    // carry no decision (connection/transport pseudo-actions).
    role: Option<&'static str>,
    // The rule the same decision cites, beside its role.
    rule: Option<&RuleCitation>,
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
    // #275: the peer identity, bounded and audit-only.
    rec.subject.user = admitted_user(peer_user);
    rec.subject.role = role.map(str::to_string);
    rec.rule = rule.map(rule_audit);
    rec.object_requested = object_requested.map(str::to_string);
    match emit.emit_within(&rec, AUDIT_APPEND_TIMEOUT).await {
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
    // #275: the peer's OS username, already bounded by `admitted_user`.
    peer_user: Option<&str>,
    // #275: the role the decision was MADE ON, or None on records that
    // carry no decision (connection/transport pseudo-actions).
    role: Option<&'static str>,
    session_id: u64,
    seq: u64,
    action: &str,
    reason: &str,
    au3_1: &serde_json::Value,
) {
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
        None,
        "deny",
        reason,
        "unauthorized",
        au3_1,
    );
    // #275: the peer identity, bounded and audit-only.
    rec.subject.user = admitted_user(peer_user);
    rec.subject.role = role.map(str::to_string);
    if let Err(e) = emit.emit_within(&rec, AUDIT_APPEND_TIMEOUT).await {
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

    /// Prompt half: take the next raw socket + its peer-creds. The loop continues on
    /// either error (never `?`).
    fn accept_raw(
        &self,
    ) -> impl Future<Output = Result<(Self::Raw, PeerCreds), maknae_vault::RawAcceptError>> + Send;

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
    async fn accept_raw(&self) -> Result<(RawPlaneConn, PeerCreds), maknae_vault::RawAcceptError> {
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

async fn audit_cert_half_reject<E: AuditEmit>(emit: &E, rec: &AuditRecord, uid: u32) {
    if let Err(e) = emit
        .emit_within(
            rec,
            Duration::from_millis(maknae_config::ADMISSION_AUDIT_TIMEOUT_MS),
        )
        .await
    {
        crate::diag::report(format!(
            "maknaed: AUDIT WRITE FAILED on accept-reject (cert half) for peer_uid={uid} — rejection proceeded without a durable record: {e}"
        ));
    }
}

/// Hand a connection-refusal record to the bounded background drain; a full
/// queue counts it for the drain's aggregate record (#265 A6).
fn offload_refusal(
    tx: &mpsc::Sender<AuditRecord>,
    rec: AuditRecord,
    dropped: &std::sync::atomic::AtomicU64,
) {
    if let Err(err) = tx.try_send(rec) {
        dropped.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        eprintln!("maknaed: connection-refusal audit offload dropped a record: {err}");
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

async fn drain_refusal_audit<E: AuditEmit + Send + Sync + 'static>(
    mut rx: mpsc::Receiver<AuditRecord>,
    emit: Arc<E>,
    dropped: Arc<std::sync::atomic::AtomicU64>,
    ids: Arc<SessionIds>,
    wctx: WhereCtx,
) {
    let bound = Duration::from_millis(maknae_config::ADMISSION_AUDIT_TIMEOUT_MS);
    let append = |rec: AuditRecord| {
        let emit = Arc::clone(&emit);
        async move {
            if let Err(e) = emit.emit_within(&rec, bound).await {
                eprintln!(
                    "maknaed: AUDIT WRITE FAILED on a connection refusal (background) for peer_uid={} — rejection proceeded without a durable record: {e}",
                    rec.source.uid
                );
            }
        }
    };
    let flush_dropped = || {
        let n = dropped.swap(0, std::sync::atomic::Ordering::Relaxed);
        (n > 0).then(|| {
            make_record(
                "connection",
                &wctx.host,
                &wctx.socket,
                maknae_audit_append::NO_PEER_UID,
                None,
                None,
                None,
                ids.next_session(),
                1,
                "connect",
                None,
                "deny",
                &format!("audit queue full: {n} connection-refusal records dropped"),
                "unauthorized",
                &wctx.au3_1,
            )
        })
    };
    while let Some(rec) = rx.recv().await {
        append(rec).await;
        if let Some(summary) = flush_dropped() {
            append(summary).await;
        }
    }
    if let Some(summary) = flush_dropped() {
        append(summary).await;
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
    live: Arc<crate::live::LiveConfig>,
    authz_backend_name: Arc<String>,
    classification_policy_name: Arc<String>,
    kernel_graph: Arc<Option<KernelGraphStatus>>,
    egress: Arc<dyn crate::egress::Egress>,
    baseline: Arc<dyn BaselineOps>,
    drain: tokio::sync::watch::Receiver<Drain>,
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
    let (atcap_audit_tx, atcap_audit_rx) = mpsc::channel::<AuditRecord>(ATCAP_AUDIT_QUEUE_DEPTH);
    let atcap_audit_emit = Arc::clone(&emit);
    // #265 A6: records the full queue refused are counted here and written by the
    // drain as one aggregate record.
    let atcap_audit_dropped = Arc::new(std::sync::atomic::AtomicU64::new(0));
    let (drain_dropped, drain_ids, drain_wctx) = (
        Arc::clone(&atcap_audit_dropped),
        Arc::clone(&session_ids),
        wctx.clone(),
    );
    let mut atcap_audit_task = tokio::spawn(drain_refusal_audit(
        atcap_audit_rx,
        atcap_audit_emit,
        drain_dropped,
        drain_ids,
        drain_wctx,
    ));

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
                    Err(maknae_vault::RawAcceptError::PeerCreds(detail)) => {
                        let rec = make_record(
                            "connection", &wctx.host, &wctx.socket, maknae_audit_append::NO_PEER_UID,
                            None, None, None, session_ids.next_session(), 1, "connect", None, "deny",
                            &format!("peer credentials not captured: {detail}"), "unauthorized", &wctx.au3_1,
                        );
                        offload_refusal(&atcap_audit_tx, rec, &atcap_audit_dropped);
                    }
                    Err(maknae_vault::RawAcceptError::Accept(e)) => {
                        eprintln!("maknaed: raw accept failed (continuing): {e}");
                    }
                    Ok((raw, peer_creds)) => {
                        let session_id = session_ids.next_session();
                        if !crate::handler::admits(*drain.borrow()) {
                            drop(raw);
                            let rec = make_record(
                                "connection", &wctx.host, &wctx.socket, peer_creds.uid,
                                peer_creds.gid, peer_creds.pid, None, session_id, 1,
                                "connect", None, "deny", "draining to apply an accepted baseline",
                                "unavailable", &wctx.au3_1,
                            );
                            offload_refusal(&atcap_audit_tx, rec, &atcap_audit_dropped);
                            continue;
                        }
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
                                offload_refusal(&atcap_audit_tx, rec, &atcap_audit_dropped);
                            }
                            Ok(permit) => {
                                let acceptor = Arc::clone(&acceptor);
                                let emit = Arc::clone(&emit);
                                let cfg = cfg.clone();
                                let wctx = wctx.clone();
                                let authorizer = Arc::clone(&authorizer);
                                let live = Arc::clone(&live);
                                let authz_backend_name = Arc::clone(&authz_backend_name);
                                let classification_policy_name =
                                    Arc::clone(&classification_policy_name);
                                let kernel_graph = Arc::clone(&kernel_graph);
                                let egress = Arc::clone(&egress);
                                let baseline = Arc::clone(&baseline);
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
                                            // #275, #435: the peer's username and
                                            // raw home ride the SAME blocking lookup
                                            // as membership. Absent on every
                                            // fail-closed arm.
                                            let (in_group, peer_user, peer_dir) = match admission {
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
                                                    admission_facts(None)
                                                }
                                                BreakerAdmission::RefuseAtCapacity => admission_facts(None),
                                                BreakerAdmission::Admit => match tokio::time::timeout(
                                                    Duration::from_millis(maknae_config::GROUP_LOOKUP_TIMEOUT_MS),
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
                                                        match join {
                                                            Ok(Ok(m)) => admission_facts(Some(m)),
                                                            _ => admission_facts(None),
                                                        }
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
                                                                maknae_config::GROUP_LOOKUP_TIMEOUT_MS / 1_000
                                                            );
                                                        } else {
                                                            eprintln!(
                                                                "maknaed: `maknae` group lookup for uid={uid} stalled past {}s — failing closed (deny)",
                                                                maknae_config::GROUP_LOOKUP_TIMEOUT_MS / 1_000
                                                            );
                                                        }
                                                        admission_facts(None)
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
                                                peer_user,
                                                peer_dir,
                                                emit, session_id, cfg, wctx.au3_1,
                                                authorizer,
                                                live,
                                                authz_backend_name,
                                                classification_policy_name,
                                                kernel_graph,
                                                egress,
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
                                                baseline,
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
                                            audit_cert_half_reject(&*emit, &rec, uid).await;
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

    // #265 A1 (AU-2): the stop, with its reason. Bounded like the drains below.
    let (result, reason, posture) = match (&outcome, *drain.borrow()) {
        (ServeOutcome::SupervisorExited(e), _) => (
            "deny",
            format!("shutdown: credential supervisor exited: {e}"),
            "unavailable",
        ),
        (_, Drain::Applied) => (
            "permit",
            "shutdown: restarting to apply an accepted baseline".to_string(),
            "stopped",
        ),
        (_, Drain::Begun | Drain::Failed) => (
            "deny",
            "shutdown: an accepted baseline was not applied".to_string(),
            "unavailable",
        ),
        _ => ("permit", "shutdown: signal received".to_string(), "stopped"),
    };
    let stop = make_record(
        "shutdown",
        &wctx.host,
        &wctx.socket,
        nix::unistd::geteuid().as_raw(),
        None,
        None,
        None,
        session_ids.next_session(),
        1,
        "serve",
        None,
        result,
        &reason,
        posture,
        &wctx.au3_1,
    );
    match tokio::time::timeout(AUDIT_DRAIN_SHUTDOWN_TIMEOUT, emit.emit(&stop)).await {
        Ok(Ok(())) => {}
        Ok(Err(e)) => eprintln!("maknaed: AUDIT WRITE FAILED on the shutdown record: {e}"),
        Err(_) => eprintln!(
            "maknaed: the shutdown record did not append within {}s",
            AUDIT_DRAIN_SHUTDOWN_TIMEOUT.as_secs()
        ),
    }

    // #240: the credential supervisor is stopped HERE, before the drains and the
    // caller's `client.shutdown()` (see `SUPERVISOR_ABORT_REAP_TIMEOUT`). Not on
    // the path where it already exited — that handle has been polled to
    // completion and must not be polled again.
    if !matches!(outcome, ServeOutcome::SupervisorExited(_)) {
        supervisor.abort();
        match tokio::time::timeout(SUPERVISOR_ABORT_REAP_TIMEOUT, &mut supervisor).await {
            // The expected outcome of an abort; anything else is an exit the
            // select above did not get to report (both ready in one wakeup).
            Ok(Err(e)) if e.is_cancelled() => {}
            Ok(joined) => {
                let reason = supervisor_exit_reason(joined);
                eprintln!(
                    "maknaed: credential supervisor had already exited at shutdown ({reason})"
                );
            }
            Err(_elapsed) => {
                eprintln!(
                    "maknaed: credential supervisor did not stop within {}s of abort; the plane token revoke may wait on its lock (bounded)",
                    SUPERVISOR_ABORT_REAP_TIMEOUT.as_secs()
                );
            }
        }
    }

    // Stopped accepting (done — we broke the loop, either way). Drain in-flight
    // handlers: this IS the graceful-shutdown drain regardless of which outcome ended
    // the loop, so a supervisor exit still lets already-admitted requests finish rather
    // than dropping them mid-flight. BOUNDED (same class as the audit drain below): a
    // handler stuck in a wedged audit append would otherwise hang shutdown here before
    // the at-capacity drain bound is even reached.
    let handler_drain = handler_drain_bound(&cfg, egress.deadline());
    if drain_handlers_bounded(&mut handlers, handler_drain).await == DrainOutcome::Aborted {
        eprintln!(
            "maknaed: in-flight handler drain did not complete within {}s during shutdown; aborting remaining handlers to allow exit",
            handler_drain.as_secs()
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
    let unrecorded = atcap_audit_dropped.load(std::sync::atomic::Ordering::Relaxed);
    if unrecorded > 0 {
        eprintln!(
            "maknaed: {unrecorded} dropped connection-refusal record(s) were not counted on the trail before exit"
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
    /// #189: `audit.siem` is configured but off-host offload is unimplemented
    /// (#223). Its own variant, so it maps to its own exit code.
    AuditOffload(String),
    /// #488: the kernel graph store could not be booted. `hint` is the operator's
    /// next step for this class of failure.
    Graph {
        reason: String,
        hint: String,
    },
    Other(String),
}

impl std::fmt::Display for RunError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RunError::Authz(m) | RunError::AuditOffload(m) | RunError::Other(m) => {
                write!(f, "{m}")
            }
            RunError::Graph { reason, .. } => write!(f, "{reason}"),
        }
    }
}

/// The distinct process exit code for [`RunError::Authz`] (spec §5.4: "distinct
/// non-zero exit"). Deliberately not [`ExitCode::FAILURE`] (1) — an operator or
/// process-supervision script can tell "refused: unauthorized/unresolvable authz
/// policy" apart from every other startup failure without parsing stderr.
const AUTHZ_REFUSAL_EXIT_CODE: u8 = 3;

/// The distinct process exit code for [`RunError::AuditOffload`] (#189). Same
/// reasoning as the authz code above: an operator scripting startup can tell
/// "config promises an audit control that is not implemented" apart from every
/// other startup failure without parsing stderr.
const AUDIT_OFFLOAD_REFUSAL_EXIT_CODE: u8 = 4;

const GRAPH_REFUSAL_EXIT_CODE: u8 = 5;

/// Boot-evidence append failures, graph records included, exit 1; every other graph refusal exits 5.
fn refusal_exit_code(e: &RunError) -> u8 {
    match e {
        RunError::Authz(_) => AUTHZ_REFUSAL_EXIT_CODE,
        RunError::AuditOffload(_) => AUDIT_OFFLOAD_REFUSAL_EXIT_CODE,
        RunError::Graph { .. } => GRAPH_REFUSAL_EXIT_CODE,
        RunError::Other(_) => 1,
    }
}

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
    let seams = BootSeams {
        graph_key: production_graph_key,
        state_dir_open: StateDir::open,
        files: crate::boot::read_files,
        env: Arc::new(crate::host_env::HostEnv {
            config_dir: config_dir.to_path_buf(),
        }),
        open_prepared: maknae_audit_append::AuditSink::open_prepared,
        scan: production_scan,
        policy_load: maknae_authz_basic::PolicySource::load,
    };
    let code = runtime.block_on(async move {
        match run_inner(
            config_dir,
            Path::new(maknae_state::store::STATE_DIR),
            &seams,
        )
        .await
        {
            // The T1 `ServeOutcome` → `ExitCode` mapping (codex round-5 P1) decides:
            // `GracefulShutdown` → SUCCESS, `SupervisorExited` → FAILURE (so process
            // supervision restarts the daemon and re-mints; the diagnostic was already
            // logged by the accept loop when the supervisor's handle resolved).
            Ok(outcome) => crate::handler::serve_outcome_to_exit_code(&outcome),
            Err(e) => {
                eprintln!("maknaed: refusing to start: {e}");
                if let RunError::Graph { hint, .. } = &e {
                    eprintln!("maknaed: {hint}");
                }
                ExitCode::from(refusal_exit_code(&e))
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
    crate::diag::flush_within(DIAG_FLUSH_TIMEOUT);
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
    if let Err(e) = sink.emit_within(&rec, AUDIT_APPEND_TIMEOUT).await {
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

#[allow(clippy::too_many_arguments)]
/// #189: the AU-3 boot refusal record for a configured-but-unimplemented
/// `audit.siem`. Mirrors [`refuse_authz_boot`]'s shape exactly — same record
/// fields, same emit-failure handling — differing only in the action it records
/// and the catalog string it renders. Placed AFTER the audit sink opens, per the
/// ordering rule stated for the authz gate: a fail-closed refusal that emits no
/// record is a refusal with no trail.
async fn refuse_audit_offload_boot<E: AuditEmit + Send + Sync>(
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
        "audit.offload",
        None,
        "deny",
        &reason,
        "unauthorized",
        au3_1,
    );
    if let Err(e) = sink.emit_within(&rec, AUDIT_APPEND_TIMEOUT).await {
        eprintln!(
            "maknaed: AUDIT WRITE FAILED on boot audit-offload refusal — refusal proceeded without a durable record: {e}"
        );
    }
    let catalog = maknae_msgs::msg(
        maknae_msgs::detect_locale(),
        maknae_msgs::MsgId::AuditOffloadUnsupported,
    );
    RunError::AuditOffload(format!("{catalog}: {reason}"))
}

/// #265 C2: boot evidence that cannot be durably appended refuses boot.
fn boot_evidence_refused(what: &str, e: impl std::fmt::Display) -> RunError {
    RunError::Other(format!(
        "the boot {what} record was not durably appended: {e}"
    ))
}

/// #265 A2: one boot `start` deny record for a post-sink startup failure no
/// other refusal already recorded.
#[allow(clippy::too_many_arguments)]
async fn record_start_refusal<E: AuditEmit + Send + Sync>(
    sink: &E,
    host: &str,
    socket: &str,
    uid: u32,
    session_id: u64,
    seq: u64,
    au3_1: &serde_json::Value,
    result: &Result<ServeOutcome, RunError>,
) {
    let (action, reason) = match result {
        Err(RunError::Other(reason)) => ("start", reason),
        Err(RunError::Graph { reason, .. }) => (GRAPH_LOAD_ACTION, reason),
        _ => return,
    };
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
        action,
        None,
        "deny",
        reason,
        "unauthorized",
        au3_1,
    );
    if let Err(e) = sink.emit_within(&rec, AUDIT_APPEND_TIMEOUT).await {
        eprintln!("maknaed: AUDIT WRITE FAILED on the boot start refusal: {e}");
    }
}

const GRAPH_LOAD_ACTION: &str = "graph.load";
const GRAPH_SEED_ACTION: &str = "graph.seed";
const GRAPH_RESEED_ACTION: &str = "graph.reseed";
const GRAPH_REJECTED_ACTION: &str = "graph.rejected";
const GRAPH_MIGRATE_ACTION: &str = "graph.migrate";
const GRAPH_TRANSITION_ACTION: &str = "graph.transition";
const GRAPH_RELOAD_ACTION: &str = "graph.reload";
const GRAPH_BASELINE_ACTION: &str = "graph.baseline";
use crate::identity_report::GRAPH_IDENTITY_ACTION;

/// Every `graph.*` pseudo-action this file emits; no verb's action string may equal one.
#[cfg_attr(not(test), allow(dead_code))]
pub(crate) const GRAPH_PSEUDO_ACTIONS: [&str; 10] = [
    GRAPH_SEED_ACTION,
    GRAPH_RESEED_ACTION,
    GRAPH_REJECTED_ACTION,
    CHECKPOINT_ACTION,
    GRAPH_LOAD_ACTION,
    GRAPH_MIGRATE_ACTION,
    GRAPH_TRANSITION_ACTION,
    GRAPH_RELOAD_ACTION,
    GRAPH_IDENTITY_ACTION,
    GRAPH_BASELINE_ACTION,
];

/// The fields every peer-less boot record shares (spec §5.3).
struct BootCtx<'a> {
    event: &'a str,
    host: &'a str,
    socket: &'a str,
    euid: u32,
    session_id: u64,
    seq: &'a Seq,
    au3_1: &'a serde_json::Value,
}

impl BootCtx<'_> {
    fn record(
        &self,
        action: &str,
        result: &str,
        reason: &str,
        posture: &str,
        graph: Option<GraphAudit>,
    ) -> AuditRecord {
        let mut rec = make_record(
            self.event,
            self.host,
            self.socket,
            self.euid,
            None,
            None,
            None,
            self.session_id,
            self.seq.next(),
            action,
            None,
            result,
            reason,
            posture,
            self.au3_1,
        );
        rec.graph = graph;
        rec
    }
}

fn lower_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// Write-ahead: a record that cannot be appended fails the boot step it describes.
struct GraphBootAudit<'a, E> {
    sink: &'a E,
    ctx: &'a BootCtx<'a>,
    scanned_bytes: u64,
    bound: Duration,
    /// A restart-class accept: the drain begins once its transition intent is recorded.
    drain: Option<&'a tokio::sync::watch::Sender<Drain>>,
}

impl<'a, E: AuditEmit + Send + Sync> GraphBootAudit<'a, E> {
    fn write_ahead(
        &self,
        rec: AuditRecord,
    ) -> impl Future<Output = Result<(), StoreError>> + Send + 'a {
        let (sink, bound) = (self.sink, self.bound);
        async move {
            sink.emit_within(&rec, bound)
                .await
                .map_err(|e| StoreError::Audit(e.to_string()))
        }
    }
}

impl<E: AuditEmit + Send + Sync> BootAudit for GraphBootAudit<'_, E> {
    fn intent_seed(
        &mut self,
        revision: u64,
        authorized: bool,
    ) -> impl Future<Output = Result<(), StoreError>> + Send {
        let reason = if authorized {
            "intent recorded (reseed-authorized)"
        } else {
            "intent recorded (first-boot)"
        };
        let rec = self.ctx.record(
            GRAPH_SEED_ACTION,
            "permit",
            reason,
            "authorized",
            Some(GraphAudit {
                revision,
                ciphertext_sha256: String::new(),
                anchor: ANCHOR_SEEDING.to_string(),
                scanned_bytes: self.scanned_bytes,
            }),
        );
        self.write_ahead(rec)
    }

    fn checkpoint(
        &mut self,
        revision: u64,
        digest: [u8; 32],
        anchor: &str,
    ) -> impl Future<Output = Result<(), StoreError>> + Send {
        let rec = self.ctx.record(
            CHECKPOINT_ACTION,
            "permit",
            anchor,
            "authorized",
            Some(GraphAudit {
                revision,
                ciphertext_sha256: lower_hex(&digest),
                anchor: anchor.to_string(),
                scanned_bytes: self.scanned_bytes,
            }),
        );
        if let Some(drain) = self.drain {
            drain.send_replace(Drain::Applied);
        }
        self.write_ahead(rec)
    }

    fn intent_migrate(
        &mut self,
        revision: u64,
        from: Option<[u8; 32]>,
        to: [u8; 32],
        unbound: &[u32],
    ) -> impl Future<Output = Result<(), StoreError>> + Send {
        let from = from.map_or_else(|| "none".to_string(), |d| lower_hex(&d));
        let reason = format!(
            "intent recorded (vocabulary {from} -> {}; unbound: {unbound:?})",
            lower_hex(&to)
        );
        let rec = self.intent(GRAPH_MIGRATE_ACTION, &reason, revision, "migrating");
        self.write_ahead(rec)
    }

    fn intent_transition(
        &mut self,
        revision: u64,
        initiator: &'static str,
    ) -> impl Future<Output = Result<(), StoreError>> + Send {
        let reason = format!("intent recorded ({initiator})");
        let rec = self.intent(GRAPH_TRANSITION_ACTION, &reason, revision, "transitioning");
        let (recorded, drain) = (self.write_ahead(rec), self.drain);
        async move {
            recorded.await?;
            if let Some(drain) = drain {
                drain.send_replace(Drain::Begun);
            }
            Ok(())
        }
    }

    fn released(
        &mut self,
        revision: u64,
        released: &[maknae_graph::identity::Released],
    ) -> impl Future<Output = Result<(), StoreError>> + Send {
        let recs: Vec<(String, AuditRecord)> = released
            .iter()
            .map(|r| {
                let reason = maknae_authz_basic::IdentityProblem::from(r).to_string();
                let rec = self.intent(GRAPH_IDENTITY_ACTION, &reason, revision, "releasing");
                (reason, rec)
            })
            .collect();
        let (sink, bound) = (self.sink, self.bound);
        async move {
            for (reason, rec) in recs {
                eprintln!(
                    "maknaed: identity: {reason} (pending the store commit of revision {revision})"
                );
                sink.emit_within(&rec, bound)
                    .await
                    .map_err(|e| StoreError::Audit(e.to_string()))?;
            }
            Ok(())
        }
    }

    fn principal_admin(
        &mut self,
        revision: u64,
        uid: u32,
    ) -> impl Future<Output = Result<(), StoreError>> + Send {
        let reason = maknae_authz_basic::IdentityProblem::PrincipalAdmin { uid }.to_string();
        let rec = self.intent(GRAPH_IDENTITY_ACTION, &reason, revision, "promoting");
        eprintln!("maknaed: identity: {reason} (pending the store commit of revision {revision})");
        self.write_ahead(rec)
    }

    fn baseline(
        &mut self,
        revision: u64,
        events: &[String],
    ) -> impl Future<Output = Result<(), StoreError>> + Send {
        let recs: Vec<AuditRecord> = events
            .iter()
            .map(|e| self.intent(GRAPH_BASELINE_ACTION, e, revision, "baselining"))
            .collect();
        let (sink, bound) = (self.sink, self.bound);
        async move {
            for rec in recs {
                sink.emit_within(&rec, bound)
                    .await
                    .map_err(|e| StoreError::Audit(e.to_string()))?;
            }
            Ok(())
        }
    }
}

impl<E> GraphBootAudit<'_, E> {
    fn intent(&self, action: &str, reason: &str, revision: u64, anchor: &str) -> AuditRecord {
        self.ctx.record(
            action,
            "permit",
            reason,
            "authorized",
            Some(GraphAudit {
                revision,
                ciphertext_sha256: String::new(),
                anchor: anchor.to_string(),
                scanned_bytes: self.scanned_bytes,
            }),
        )
    }
}

/// The graph boot's inputs as this binary has them: the vocabulary labelled with the
/// system's lowest level, and the identity layer the policy declares (its bindings
/// digest is SHA-256).
struct GraphInputs {
    vocabulary: crate::vocabulary::Vocabulary,
    identity: maknae_graph::identity::IdentityLayer,
    unresolved: Vec<String>,
    bindings_missing: bool,
    bindings_lists_nobody: bool,
    principal_uid: u32,
    baseline: BaselineLayer,
    accepted_seen: Option<[u8; 32]>,
    baseline_events: Vec<String>,
}

/// The baseline this start runs, as the store records it: a performed move is cleared.
fn run_baseline(
    run: &maknae_config::BaselineSections,
    (system, ceiling): (String, String),
) -> BaselineLayer {
    BaselineLayer {
        sha256: crate::baseline::accepted_digest(run),
        sections: run.clone().into_inner(),
        system,
        ceiling,
        moved_from: None,
    }
}

impl GraphInputs {
    fn new(
        source: &maknae_authz_basic::PolicySource,
        label: &str,
        baseline: BaselineLayer,
    ) -> Result<Self, StoreError> {
        let vocabulary = crate::vocabulary::kernel_vocabulary(label)
            .map_err(|e| StoreError::Identity(e.to_string()))?;
        let sections = source.section_digests(maknae_state::envelope::sha256);
        let identity = source.identity_layer(label, sections.get("bindings").copied());
        Ok(GraphInputs {
            vocabulary,
            identity,
            unresolved: source.unresolved_adversaries(),
            bindings_missing: source.bindings().is_missing(),
            bindings_lists_nobody: source.bindings().lists_nobody(),
            principal_uid: source.principal().uid,
            baseline,
            accepted_seen: None,
            baseline_events: Vec::new(),
        })
    }

    fn boot(&self) -> BootInputs<'_> {
        BootInputs {
            compiled: &self.vocabulary.persisted,
            vocabulary_sha256: self.vocabulary.digest,
            identity: &self.identity,
            unresolved_adversaries: &self.unresolved,
            bindings_missing: self.bindings_missing,
            bindings_lists_nobody: self.bindings_lists_nobody,
            principal_uid: self.principal_uid,
            baseline: &self.baseline,
            accepted_seen: self.accepted_seen,
            baseline_events: &self.baseline_events,
        }
    }
}

#[derive(Debug)]
enum GraphFailure {
    Key(maknae_vault::VaultError),
    Store(StoreError),
    ScanElapsed(String),
    Inconsistent(String),
}

/// The refusal for a graph-store boot failure, with the operator's next step for its
/// class; `maknae_state::store::remedy` decides the step.
fn graph_refusal(failure: GraphFailure, state_dir: &Path) -> RunError {
    let hint = match &failure {
        GraphFailure::Key(maknae_vault::VaultError::GraphKeyAbsent(_)) => {
            "run `sudo maknae enroll` to create the kernel graph key".to_string()
        }
        GraphFailure::Key(maknae_vault::VaultError::GraphKey(_)) => {
            "replace the key as the runbook's \"Replace a malformed key\" says: remove it, run \
             `sudo maknae enroll`, then `sudo maknae reseed`"
                .to_string()
        }
        GraphFailure::ScanElapsed(_) => format!(
            "the trail after its last {CHECKPOINT_ACTION} did not scan within {}s; rotate it as \
             the runbook's \"Rotate, restore or recreate the trail\" says, then restart",
            SCAN_BACK_TIMEOUT.as_secs()
        ),
        GraphFailure::Inconsistent(_) => format!(
            "no automatic remedy; keep {} as it is and investigate",
            state_dir.display()
        ),
        GraphFailure::Key(_) => "the kernel graph key could not be read; check the credential \
             `sudo maknae enroll` created (enroll never replaces an existing key)"
            .to_string(),
        GraphFailure::Store(e) => match remedy(e) {
            Remedy::Reinstall => "this store was written by a newer maknaed; reinstall that \
                 version (do not reseed: that replaces a valid store)"
                .to_string(),
            Remedy::Reseed => format!(
                "if this is expected, run `sudo maknae reseed` and restart; a readable current \
                 {STORE_FILE} is kept for forensics"
            ),
            Remedy::CheckStoreFile => format!(
                "fix the ownership and mode of {}/{STORE_FILE} (it must be _maknae, 0600, one \
                 link, ≤64 MiB), then restart; do not reseed — the store may be valid",
                state_dir.display()
            ),
            Remedy::ClearRejectedName => {
                let name = match e {
                    StoreError::RejectedNameInUse { name, .. } => name.as_str(),
                    _ => "the rejected-copy name",
                };
                format!(
                    "move {}/{name} aside (the current store is intact), then restart; the \
                     authorized reseed will complete",
                    state_dir.display()
                )
            }
            Remedy::CheckStateDir => format!(
                "check the ownership and mode of {}: it must be owned by the maknaed user, \
                 mode 0700",
                state_dir.display()
            ),
            Remedy::StopOtherInstance => format!(
                "another maknaed is already running against {}; stop it before starting this one",
                state_dir.display()
            ),
            Remedy::CheckAudit => "the audit trail anchors the graph store; check that the \
                 audit file is readable"
                .to_string(),
            Remedy::Investigate if matches!(e, StoreError::Identity(_)) => {
                "the identity layer is built from bindings.yaml in the configuration \
                 directory (/etc/maknae/bindings.yaml by default); correct it, then restart; do \
                 not reseed"
                    .to_string()
            }
            Remedy::Investigate => format!(
                "no automatic remedy; keep {} as it is and investigate",
                state_dir.display()
            ),
        },
    };
    let reason = match failure {
        GraphFailure::Key(e) => format!("kernel graph key: {e}"),
        GraphFailure::Store(e) => format!("kernel graph store: {e}"),
        GraphFailure::ScanElapsed(e) | GraphFailure::Inconsistent(e) => {
            format!("kernel graph store: {e}")
        }
    };
    RunError::Graph { reason, hint }
}

fn store_refusal(e: StoreError, state_dir: &Path) -> RunError {
    match e {
        StoreError::Audit(cause) => boot_evidence_refused("graph", cause),
        StoreError::BindingsRefused(m) => RunError::Authz(m.into()),
        e => graph_refusal(GraphFailure::Store(e), state_dir),
    }
}

/// The kernel graph store as `admin.status` reports it (#488): the revision follows
/// every applied reload; the anchor is the one boot established.
#[derive(Debug, Clone)]
pub struct KernelGraphStatus {
    revision: Arc<AtomicU64>,
    pub anchor: String,
    pub identity: crate::identity_report::IdentityStatus,
    pub baseline: crate::baseline::BaselineStatus,
}

impl KernelGraphStatus {
    pub fn new(revision: u64, anchor: impl Into<String>) -> Self {
        Self {
            revision: Arc::new(AtomicU64::new(revision)),
            anchor: anchor.into(),
            identity: crate::identity_report::IdentityStatus::default(),
            baseline: crate::baseline::BaselineStatus::new(crate::baseline::BaselineState {
                accepted: Default::default(),
                pending: None,
            }),
        }
    }

    pub fn revision(&self) -> u64 {
        self.revision.load(AtomicOrdering::Acquire)
    }
}

fn kernel_graph_status(report: &BootReport) -> KernelGraphStatus {
    let anchor = match report.outcome {
        BootOutcome::Seeded {
            authorized: true, ..
        } => ANCHOR_RESEEDED,
        BootOutcome::Seeded {
            authorized: false, ..
        } => ANCHOR_SEEDED,
        BootOutcome::Loaded(state) => state.as_str(),
    };
    KernelGraphStatus::new(report.revision, anchor)
}

fn unix_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

/// Publishes the boot load's problems, releases and principal promotion; records its
/// problems after the composition record. The store already recorded the rest.
async fn publish_boot_identity<E: AuditEmit + Send + Sync>(
    status: &crate::identity_report::IdentityStatus,
    snapshot: &maknae_authz_basic::snapshot::Snapshot,
    released: &[maknae_graph::identity::Released],
    principal_admin: Option<u32>,
    sink: &Arc<E>,
    ctx: &BootCtx<'_>,
) -> Result<(), RunError> {
    crate::identity_report::publish_and_record(
        status,
        crate::identity_report::Published::of(
            snapshot,
            crate::identity_report::transition_problems(released, principal_admin),
        ),
        snapshot.identity_problems(),
        |result, reason, posture| {
            let rec = ctx.record(GRAPH_IDENTITY_ACTION, result, &reason, posture, None);
            async move { sink.emit_within(&rec, AUDIT_APPEND_TIMEOUT).await }
        },
    )
    .await
    .map_err(|e| boot_evidence_refused("identity", e))
}

/// The booted store: the directory holds the one-maknaed state-dir lock and, with the
/// key, is what a reload commits through.
struct BootedGraph {
    dir: StateDir,
    key: WrappingKey,
    status: KernelGraphStatus,
    graph: maknae_graph::graph::Graph,
    released: Vec<maknae_graph::identity::Released>,
    principal_admin: Option<u32>,
}

async fn scan_anchor(
    bound: Duration,
    scan: impl FnOnce() -> Result<maknae_audit_append::ScanResult, maknae_audit_append::AuditError>
        + Send
        + 'static,
) -> Result<maknae_audit_append::ScanResult, GraphFailure> {
    within_blocking(bound, scan)
        .await
        .map_err(|e| GraphFailure::ScanElapsed(format!("rollback anchor scan {e}")))?
        .map_err(|e| GraphFailure::Store(StoreError::Audit(e.to_string())))
}

/// The latest checkpoint in `sink`'s trail and the bytes scanned to find it, bounded.
fn production_scan(
    sink: &maknae_audit_append::AuditSink,
) -> Result<maknae_audit_append::ScanResult, maknae_audit_append::AuditError> {
    sink.scan_back(maknae_state::anchor::is_checkpoint)
}

async fn last_checkpoint(
    sink: &Arc<maknae_audit_append::AuditSink>,
    state_dir: &Path,
    scan: TrailScanner,
) -> Result<(Option<maknae_state::anchor::Checkpoint>, u64), RunError> {
    let scan_sink = Arc::clone(sink);
    let scan = scan_anchor(SCAN_BACK_TIMEOUT, move || scan(&scan_sink))
        .await
        .map_err(|e| graph_refusal(e, state_dir))?;
    Ok((
        scan.line.as_deref().and_then(parse_checkpoint),
        scan.scanned_bytes,
    ))
}

/// Runs before the accept loop, so the blocking audit scan contends with no append.
/// `scanned` is the anchor a trail move already found; `None` scans `sink`.
async fn boot_kernel_graph(
    state_dir: &Path,
    dir: Result<StateDir, StoreError>,
    key: Result<WrappingKey, maknae_vault::VaultError>,
    sink: &Arc<maknae_audit_append::AuditSink>,
    ctx: &BootCtx<'_>,
    inputs: &BootInputs<'_>,
    scanned: Option<(Option<maknae_state::anchor::Checkpoint>, u64)>,
) -> Result<BootedGraph, RunError> {
    let key = key.map_err(|e| graph_refusal(GraphFailure::Key(e), state_dir))?;
    let dir = dir.map_err(|e| graph_refusal(GraphFailure::Store(e), state_dir))?;
    let (checkpoint, scanned_bytes) = match scanned {
        Some(found) => found,
        None => last_checkpoint(sink, state_dir, production_scan).await?,
    };
    let mut audit = GraphBootAudit {
        sink: sink.as_ref(),
        ctx,
        scanned_bytes,
        bound: AUDIT_APPEND_TIMEOUT,
        drain: None,
    };
    let report = maknae_state::store::boot(&dir, &key, checkpoint, &mut audit, unix_now(), inputs)
        .await
        .map_err(|e| store_refusal(e, state_dir))?;
    report_graph_boot(sink.as_ref(), ctx, state_dir, &report).await?;
    Ok(BootedGraph {
        status: kernel_graph_status(&report),
        graph: report.graph,
        released: report.released,
        principal_admin: report.principal_admin,
        dir,
        key,
    })
}

/// What the boot did that the operator did not ask for: an ignored reseed marker, and
/// where the replaced store went.
async fn report_graph_boot<E: AuditEmit + Send + Sync>(
    sink: &E,
    ctx: &BootCtx<'_>,
    state_dir: &Path,
    report: &BootReport,
) -> Result<(), RunError> {
    if let Some(cause) = &report.marker_ignored {
        let reason = format!("reseed marker ignored: {cause}");
        eprintln!(
            "maknaed: {reason}; only a root-owned {} in {} written by `sudo maknae reseed` \
             authorizes a reseed",
            MARKER_FILE,
            state_dir.display()
        );
        sink.emit_within(
            &ctx.record(GRAPH_RESEED_ACTION, "deny", &reason, "unauthorized", None),
            AUDIT_APPEND_TIMEOUT,
        )
        .await
        .map_err(|e| boot_evidence_refused("graph reseed", e))?;
    }
    if let Some(cause) = &report.durability_error {
        eprintln!(
            "maknaed: kernel graph store revision {} is in place but may not survive a crash: {cause}",
            report.revision
        );
    }
    if let BootOutcome::Seeded {
        rejected: Some(previous),
        ..
    } = &report.outcome
    {
        let reason = format!("previous kernel graph store: {previous}");
        eprintln!("maknaed: {reason}");
        sink.emit_within(
            &ctx.record(GRAPH_REJECTED_ACTION, "permit", &reason, "authorized", None),
            AUDIT_APPEND_TIMEOUT,
        )
        .await
        .map_err(|e| boot_evidence_refused("graph rejected-store", e))?;
    }
    Ok(())
}

/// The `SIGHUP` policy reload. `lock` serializes reloads; shutdown waits on it for at
/// most `RELOAD_STOP_TIMEOUT`; `stopping` abandons a reload that has not reached its commit.
struct Reloader<B: maknae_authz_basic::Baseline, E> {
    dir: StateDir,
    key: WrappingKey,
    authorizer: Arc<crate::composition::Composition<B>>,
    label: String,
    vocabulary: crate::vocabulary::Vocabulary,
    revision: Arc<AtomicU64>,
    lock: tokio::sync::Mutex<()>,
    sink: Arc<E>,
    session_ids: Arc<SessionIds>,
    host: String,
    socket: String,
    euid: u32,
    au3_1: serde_json::Value,
    identity: crate::identity_report::IdentityStatus,
    stopping: tokio::sync::watch::Sender<bool>,
    append_bound: Duration,
    /// The stored graph: replaced by every commit, the base every reload extracts and plans from.
    persisted: std::sync::RwLock<Arc<maknae_graph::graph::Graph>>,
    config_dir: PathBuf,
    files: FileReader,
    env: Arc<dyn crate::baseline_check::Env>,
    baseline: crate::baseline::BaselineStatus,
    /// Where a restart-class accept stands; the serve stops once it is applied or failed.
    drain: tokio::sync::watch::Sender<Drain>,
    /// How long an accept waits for a reload holding the turn.
    turn_wait: Duration,
    #[cfg(test)]
    load_gate: Option<Arc<std::sync::Mutex<std::sync::mpsc::Receiver<()>>>>,
}

type ReloadCandidate = (
    Arc<maknae_graph::graph::Graph>,
    Arc<maknae_authz_basic::snapshot::Snapshot>,
    Arc<[maknae_graph::identity::Released]>,
    Option<u32>,
    Option<crate::baseline::PendingSet>,
);

impl<B, E> Reloader<B, E>
where
    B: maknae_authz_basic::Baseline,
    E: AuditEmit + Send + Sync + 'static,
{
    async fn run(self: &Arc<Self>) -> Result<crate::reload::Applied, crate::reload::Refusal> {
        let _turn = self.lock.lock().await;
        let stopping = *self.stopping.borrow() || *self.drain.borrow() != Drain::Serving;
        crate::reload::turn(stopping, &self.revision, |store_revision| async move {
            let seq = Seq::new();
            let ctx = BootCtx {
                event: "reload",
                host: &self.host,
                socket: &self.socket,
                euid: self.euid,
                session_id: self.session_ids.next_session(),
                seq: &seq,
                au3_1: &self.au3_1,
            };
            let io = ReloadIo {
                reloader: self,
                ctx: &ctx,
                store_revision,
                committed: std::sync::Mutex::new(None),
                replaced: std::sync::Mutex::default(),
                newly_pending: std::sync::Mutex::default(),
            };
            let mut stopping = self.stopping.subscribe();
            let stopped = async move {
                let _ = stopping.wait_for(|stop| *stop).await;
            };
            crate::reload::run_reload(store_revision, &io, &io, &io, &io, stopped).await
        })
        .await
    }

    /// Abandons a reload still loading and waits up to `RELOAD_STOP_TIMEOUT` for one
    /// already committing, then stops the reload task; on elapse it leaves that reload
    /// running. Only the first call waits, even if it was dropped mid-wait.
    async fn stop(&self, reloads: &tokio::task::AbortHandle) {
        let already = self.stopping.send_replace(true);
        match crate::reload::stop(already, self.lock.lock(), RELOAD_STOP_TIMEOUT).await {
            crate::reload::Stop::Abort(_turn) => reloads.abort(),
            crate::reload::Stop::LeaveRunning => eprintln!(
                "maknaed: a reload still held its turn after {}s; stopping without it",
                RELOAD_STOP_TIMEOUT.as_secs()
            ),
            crate::reload::Stop::Repeated => {}
        }
    }
}

impl<B, E> Reloader<B, E>
where
    B: maknae_authz_basic::Baseline,
    E: AuditEmit + Send + Sync + 'static,
{
    /// The published accepted baseline and the set the files hold against it, read now.
    async fn read_pending(
        &self,
    ) -> Result<
        (
            Arc<crate::baseline::BaselineState>,
            Option<crate::baseline::PendingSet>,
        ),
        String,
    > {
        let state = self.baseline.current();
        let trail = accepted_trail(&state.accepted, &self.config_dir);
        let (dir, files, env) = (self.config_dir.clone(), self.files, Arc::clone(&self.env));
        let file =
            baseline_blocking(move || baseline_file(&dir, files, env.as_ref(), trail.as_deref()))
                .await?;
        let set = crate::baseline::pending(&state.accepted, &file);
        Ok((state, set))
    }

    async fn accept_named(&self, hash: &str) -> AcceptAnswer {
        let Ok(turn) = tokio::time::timeout(self.turn_wait, self.lock.lock()).await else {
            return accept_unavailable(ACCEPT_BUSY, ACCEPT_BUSY.into());
        };
        if *self.stopping.borrow() || *self.drain.borrow() != Drain::Serving {
            return accept_unavailable(ACCEPT_STOPPING, ACCEPT_STOPPING.into());
        }
        let mut guard = DrainGuard {
            drain: &self.drain,
            live_unsettled: false,
        };
        let (state, current) = match self.read_pending().await {
            Ok(read) => read,
            Err(why) => {
                return accept_unavailable(
                    ACCEPT_UNAVAILABLE,
                    format!("baseline accept refused: {why}"),
                )
            }
        };
        let (plan, set) = match (
            crate::baseline::decide_accept(current.as_ref(), hash),
            current,
        ) {
            (Ok(plan), Some(set)) => (plan, set),
            (Err(r), current) => {
                let (view, reason) = crate::baseline::refused_view(&r, current.as_ref());
                return AcceptAnswer::View {
                    view,
                    corrective: Some(reason),
                };
            }
            (Ok(_), None) => {
                return accept_unavailable(
                    ACCEPT_UNAVAILABLE,
                    "baseline accept refused: nothing is pending".into(),
                )
            }
        };
        let (accepted, proposed) = (state.accepted.clone(), plan.proposed.clone());
        let (dir, env) = (self.config_dir.clone(), Arc::clone(&self.env));
        let checked = baseline_blocking(move || {
            let doc =
                maknae_config::Document::from_baseline(&proposed).map_err(|e| e.to_string())?;
            let v = crate::baseline_check::validate(doc, Mode::Accept, &dir, env.as_ref())
                .map_err(|e| e.cause().to_string())?;
            crate::baseline_check::check_sockets(&accepted, &v, env.as_ref())
                .map_err(|e| e.cause().to_string())?;
            Ok::<_, String>(v)
        })
        .await;
        let v = match checked {
            Err(why) => {
                return accept_unavailable(
                    ACCEPT_UNAVAILABLE,
                    format!("baseline accept refused: {why}"),
                )
            }
            Ok(Err(cause)) => {
                eprintln!("maknaed: baseline accept refused: {} {cause}", set.source);
                let (view, _) = crate::baseline::refused_view(
                    &crate::baseline::AcceptRefusal::Invalid,
                    Some(&set),
                );
                return AcceptAnswer::View {
                    view,
                    corrective: Some(format!("baseline accept refused: {cause}")),
                };
            }
            Ok(Ok(v)) => v,
        };
        let persisted = Arc::clone(
            &self
                .persisted
                .read()
                .unwrap_or_else(std::sync::PoisonError::into_inner),
        );
        let stored = match maknae_graph::identity::extract(&persisted) {
            Ok(stored) => stored,
            Err(e) => {
                return accept_unavailable(
                    ACCEPT_UNAVAILABLE,
                    format!("baseline accept refused: {e}"),
                )
            }
        };
        let (system, ceiling) = crate::baseline_check::classification_of(&v);
        let moved_from = accepted_trail(&state.accepted, &self.config_dir)
            .filter(|running| *running != v.audit.jsonl_path)
            .map(|running| running.display().to_string());
        let next_baseline = BaselineLayer {
            sha256: crate::baseline::accepted_digest(&plan.proposed),
            sections: plan.proposed.clone().into_inner(),
            system,
            ceiling,
            moved_from,
        };
        let store_revision = self.revision.load(AtomicOrdering::Acquire);
        let next = match maknae_graph::identity::build(
            &stored.layer,
            Some(&next_baseline),
            &self.vocabulary.persisted,
            self.vocabulary.digest,
            store_revision.saturating_add(1),
            maknae_graph::record::ProvenanceKind::Operator,
        ) {
            Ok(next) => next,
            Err(e) => {
                return accept_unavailable(
                    ACCEPT_UNAVAILABLE,
                    format!("baseline accept refused: {e}"),
                )
            }
        };
        let restart = plan.apply == crate::baseline::Apply::Restart;
        let class = if restart { "restart" } else { "live" };
        let short = crate::baseline::short(&set.hash);
        let intent = format!(
            "accept intent recorded (operator): sha256:{short}; apply: {class}; sections: {}",
            plan.sections.join(",")
        );
        let seq = Seq::new();
        let ctx = BootCtx {
            event: "accept",
            host: &self.host,
            socket: &self.socket,
            euid: self.euid,
            session_id: self.session_ids.next_session(),
            seq: &seq,
            au3_1: &self.au3_1,
        };
        let mut audit = GraphBootAudit {
            sink: self.sink.as_ref(),
            ctx: &ctx,
            scanned_bytes: 0,
            bound: self.append_bound,
            drain: restart.then_some(&self.drain),
        };
        eprintln!(
            "maknaed: baseline: accepting the {} change set (apply: {class})",
            set.source
        );
        let committed = match maknae_state::store::commit_accept(
            &self.dir,
            &self.key,
            &next,
            &[intent],
            &mut audit,
        )
        .await
        {
            Ok(committed) => committed,
            Err(e) if *self.drain.borrow() == Drain::Begun => {
                self.drain.send_replace(Drain::Failed);
                return accept_unavailable(
                    ACCEPT_UNAVAILABLE,
                    format!(
                        "baseline accept failed: persist: {e}; exiting on the unchanged baseline"
                    ),
                );
            }
            Err(e) => {
                let why = match e {
                    StoreError::Audit(m) => format!("the intent was not recorded: {m}"),
                    e => format!("persist: {e}"),
                };
                return accept_unavailable(
                    ACCEPT_UNAVAILABLE,
                    format!("baseline accept refused: {why}"),
                );
            }
        };
        for e in [&committed.durability_error, &committed.checkpoint_error]
            .into_iter()
            .flatten()
        {
            eprintln!(
                "maknaed: baseline accept at revision {}: {e}",
                committed.revision
            );
        }
        *self
            .persisted
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = Arc::new(next);
        guard.live_unsettled = !restart;
        self.revision
            .store(committed.revision, AtomicOrdering::Release);
        self.baseline.publish(crate::baseline::BaselineState {
            accepted: plan.proposed.clone(),
            pending: None,
        });
        let applied = if restart {
            Ok("restarting to apply")
        } else {
            let before = self.authorizer.baseline().principal().uid;
            let principal = v.principal.uid;
            let pdp = Arc::clone(&self.authorizer);
            let deadline = std::time::Instant::now() + BLOCKING_OPERATION_TIMEOUT;
            match within_blocking(2 * BLOCKING_OPERATION_TIMEOUT, move || {
                crate::live::install(&pdp, &v, deadline)
            })
            .await
            .and_then(|installed| installed)
            {
                Ok(()) => {
                    if principal != before {
                        self.republish_principal_admin(&ctx, principal).await;
                    }
                    Ok("applied live")
                }
                Err(e) => {
                    self.drain.send_replace(Drain::Applied);
                    Err(e)
                }
            }
        };
        guard.live_unsettled = false;
        drop(guard);
        drop(turn);
        let revision = committed.revision;
        let (result, reason, posture) = match &applied {
            Ok(how) => (
                "permit",
                format!("accepted sha256:{short} at revision {revision}; {how}"),
                "authorized",
            ),
            Err(e) => (
                "deny",
                format!(
                    "accepted sha256:{short} at revision {revision}; not installed live: {e}; restarting to apply"
                ),
                "unavailable",
            ),
        };
        eprintln!(
            "maknaed: baseline: {}",
            reason.replace(&format!("sha256:{short} "), "")
        );
        let rec = ctx.record(GRAPH_BASELINE_ACTION, result, &reason, posture, None);
        if let Err(e) = self.sink.emit_within(&rec, self.append_bound).await {
            eprintln!("maknaed: AUDIT WRITE FAILED on the baseline accept outcome: {e}");
        }
        let mut view = crate::baseline::accepted_view(&set, &state.accepted);
        if applied.is_err() {
            view.apply = "restart".into();
        }
        AcceptAnswer::View {
            view,
            corrective: None,
        }
    }

    /// With no explicit bindings the principal holds admin, so a new principal is
    /// published and recorded as the identity it now is.
    async fn republish_principal_admin(&self, ctx: &BootCtx<'_>, uid: u32) {
        let snapshot = self.authorizer.baseline().snapshot();
        if snapshot.subjects().is_some() {
            return;
        }
        let promoted = maknae_authz_basic::IdentityProblem::PrincipalAdmin { uid };
        let carried: Vec<_> = self
            .identity
            .current()
            .iter()
            .filter(|p| matches!(p, maknae_authz_basic::IdentityProblem::Released { .. }))
            .cloned()
            .chain([promoted.clone()])
            .collect();
        self.identity
            .publish(crate::identity_report::Published::of(&snapshot, carried));
        let (result, reason, posture) = crate::identity_report::record_fields(&promoted);
        eprintln!("maknaed: identity: {reason}");
        let rec = ctx.record(GRAPH_IDENTITY_ACTION, result, &reason, posture, None);
        if let Err(e) = self.sink.emit_within(&rec, self.append_bound).await {
            eprintln!("maknaed: AUDIT WRITE FAILED on an identity record ({reason}): {e}");
        }
    }
}

impl<B, E> BaselineOps for Reloader<B, E>
where
    B: maknae_authz_basic::Baseline,
    E: AuditEmit + Send + Sync + 'static,
{
    fn show(&self) -> BoxFuture<'_, Result<maknae_proto::BaselineView, String>> {
        Box::pin(async move {
            let (state, set) = self.read_pending().await?;
            crate::baseline::show_view(set.as_ref(), &state.accepted)
        })
    }

    fn accept<'a>(&'a self, hash: &'a str) -> BoxFuture<'a, AcceptAnswer> {
        Box::pin(self.accept_named(hash))
    }
}

struct ReloadIo<'a, B: maknae_authz_basic::Baseline, E> {
    reloader: &'a Arc<Reloader<B, E>>,
    ctx: &'a BootCtx<'a>,
    store_revision: u64,
    committed: std::sync::Mutex<Option<[u8; 32]>>,
    replaced: std::sync::Mutex<Arc<[maknae_authz_basic::IdentityProblem]>>,
    /// The pending set an install published with a new hash, to be recorded.
    newly_pending: std::sync::Mutex<Option<crate::baseline::PendingSet>>,
}

/// The files read and validated as a start reads them: the sections, or why they
/// cannot start and, when they parsed, the sections refused.
fn read_file_baseline(
    config_dir: &Path,
    files: FileReader,
    env: &dyn crate::baseline_check::Env,
) -> Result<
    (
        crate::baseline_check::Validated,
        maknae_config::BaselineSections,
    ),
    (Invalid, Option<maknae_config::BaselineSections>),
> {
    let doc = files(config_dir).map_err(|e| (Invalid::Document(e.to_string()), None))?;
    let sections = maknae_config::document_sections(&doc);
    match crate::baseline_check::validate_file(doc, Mode::Boot, config_dir, env) {
        Ok(v) => Ok((v, sections)),
        Err(e) => Err((e, Some(sections))),
    }
}

/// Blocking: reads `maknae.yaml`/`config.d` and validates them as boot does.
fn baseline_file(
    config_dir: &Path,
    files: FileReader,
    env: &dyn crate::baseline_check::Env,
    accepted_trail: Option<&Path>,
) -> Result<maknae_config::BaselineSections, crate::baseline::InvalidFile> {
    let (v, sections) =
        read_file_baseline(config_dir, files, env).map_err(|(e, s)| e.into_file(s))?;
    match crate::baseline_check::check_move(accepted_trail, &v.audit.jsonl_path, env) {
        Ok(()) => Ok(sections),
        Err(cause) => Err(crate::baseline::InvalidFile {
            cause,
            proposed: Some(sections),
        }),
    }
}

/// Blocking: the policy load resolves usernames, and the baseline files are read
/// only to compute the pending set.
fn load_candidate<B: maknae_authz_basic::Baseline, E>(
    reloader: &Reloader<B, E>,
    persisted_graph: &Arc<maknae_graph::graph::Graph>,
    store_revision: u64,
) -> Result<(crate::reload::Plan, ReloadCandidate), crate::reload::Refusal> {
    use crate::reload::Refusal;
    let (baseline, vocabulary, label) = (
        reloader.authorizer.baseline(),
        &reloader.vocabulary,
        reloader.label.as_str(),
    );
    let compile_refused = |m: String| Refusal::Compile(m);
    let persisted = maknae_graph::identity::extract(persisted_graph)
        .map_err(|e| compile_refused(e.to_string()))?;
    let Some(stored_baseline) = persisted.baseline.as_ref() else {
        return Err(compile_refused(
            "the running graph carries no baseline".into(),
        ));
    };
    let source = baseline
        .load_source()
        .map_err(|e| Refusal::Load(e.to_string()))?;
    let digests = source.section_digests(baseline.digest());
    let (next, released) = crate::reload::next_layer(
        &source.identity_layer(label, digests.get("bindings").copied()),
        &source.unresolved_adversaries(),
        &persisted.layer,
        source.bindings().is_missing(),
        source.bindings().lists_nobody(),
    )?;
    let principal_admin = maknae_graph::identity::promotes_principal(&persisted.layer, &next)
        .then_some(source.principal().uid);
    let (plan, graph) = crate::reload::plan_candidate(
        &persisted.layer,
        &next,
        store_revision,
        persisted_graph,
        |revision| {
            maknae_graph::identity::build(
                &next,
                Some(stored_baseline),
                &vocabulary.persisted,
                vocabulary.digest,
                revision,
                maknae_graph::record::ProvenanceKind::RootFile,
            )
            .map(Arc::new)
            .map_err(|e| compile_refused(e.to_string()))
        },
    )?;
    let snapshot = maknae_authz_basic::snapshot::compile(
        Arc::clone(&graph),
        &source,
        &vocabulary.full,
        &digests,
    )
    .map_err(|e| compile_refused(e.to_string()))?;
    let accepted = reloader.baseline.current();
    let trail = accepted_trail(&accepted.accepted, &reloader.config_dir);
    let file = baseline_file(
        &reloader.config_dir,
        reloader.files,
        reloader.env.as_ref(),
        trail.as_deref(),
    );
    let pending = crate::baseline::pending(&accepted.accepted, &file);
    Ok((
        plan,
        (
            graph,
            Arc::new(snapshot),
            released.into(),
            principal_admin,
            pending,
        ),
    ))
}

impl<B, E> crate::reload::Load for ReloadIo<'_, B, E>
where
    B: maknae_authz_basic::Baseline,
    E: AuditEmit + Send + Sync + 'static,
{
    type Candidate = ReloadCandidate;

    fn load(
        &self,
        store_revision: u64,
    ) -> impl Future<Output = Result<(crate::reload::Plan, ReloadCandidate), crate::reload::Refusal>>
           + Send {
        let reloader = Arc::clone(self.reloader);
        async move {
            let persisted = Arc::clone(
                &reloader
                    .persisted
                    .read()
                    .unwrap_or_else(std::sync::PoisonError::into_inner),
            );
            tokio::task::spawn_blocking(move || {
                #[cfg(test)]
                if let Some(gate) = &reloader.load_gate {
                    let _ = gate.lock().unwrap().recv();
                }
                load_candidate(&reloader, &persisted, store_revision)
            })
            .await
            .map_err(|e| crate::reload::Refusal::Load(format!("load task: {e}")))?
        }
    }
}

impl<B, E> crate::reload::Store for ReloadIo<'_, B, E>
where
    B: maknae_authz_basic::Baseline,
    E: AuditEmit + Send + Sync + 'static,
{
    type Candidate = ReloadCandidate;

    fn commit(
        &self,
        candidate: &ReloadCandidate,
    ) -> impl Future<Output = Result<crate::reload::Committed, crate::reload::Refusal>> + Send {
        let graph = Arc::clone(&candidate.0);
        let released = Arc::clone(&candidate.2);
        let principal_admin = candidate.3;
        async move {
            let mut audit = GraphBootAudit {
                sink: self.reloader.sink.as_ref(),
                ctx: self.ctx,
                scanned_bytes: 0,
                bound: self.reloader.append_bound,
                drain: None,
            };
            let committed = maknae_state::store::commit(
                &self.reloader.dir,
                &self.reloader.key,
                &graph,
                &released,
                principal_admin,
                &mut audit,
                maknae_state::store::INITIATOR_ROOT_FILE,
            )
            .await
            .map_err(|e| match e {
                StoreError::BaselineUnrecorded => crate::reload::Refusal::BaselineChanged,
                e => crate::reload::Refusal::Persist(e.to_string()),
            })?;
            *self
                .reloader
                .persisted
                .write()
                .unwrap_or_else(std::sync::PoisonError::into_inner) = Arc::clone(&graph);
            *self
                .committed
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(committed.digest);
            Ok(crate::reload::Committed {
                revision: committed.revision,
                durability_error: committed.durability_error,
                checkpoint_error: committed.checkpoint_error,
            })
        }
    }
}

impl<B, E> crate::reload::Swap for ReloadIo<'_, B, E>
where
    B: maknae_authz_basic::Baseline,
    E: AuditEmit + Send + Sync + 'static,
{
    type Candidate = ReloadCandidate;

    /// The published set follows the snapshot, not atomically with it: for that
    /// instant `admin.status` and the subject list's unbound and unresolved rows
    /// report the previous load.
    fn install(&self, candidate: ReloadCandidate) {
        let published = crate::identity_report::Published::of(
            &candidate.1,
            crate::identity_report::transition_problems(&candidate.2, candidate.3),
        );
        self.reloader.authorizer.baseline().install(candidate.1);
        let current = self.reloader.baseline.current();
        let pending = candidate.4;
        let hash = |p: &Option<crate::baseline::PendingSet>| p.as_ref().map(|p| p.hash.clone());
        // A new set is published by `outcome` once its record is appended.
        if pending.is_some() && hash(&pending) != hash(&current.pending) {
            *self
                .newly_pending
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner) = pending;
        } else {
            self.reloader
                .baseline
                .publish(crate::baseline::BaselineState {
                    accepted: current.accepted.clone(),
                    pending,
                });
        }
        *self
            .replaced
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) =
            self.reloader.identity.publish(published);
    }
}

impl<B, E> crate::reload::Audit for ReloadIo<'_, B, E>
where
    B: maknae_authz_basic::Baseline,
    E: AuditEmit + Send + Sync + 'static,
{
    fn intent(
        &self,
        store_revision: u64,
    ) -> impl Future<Output = Result<(), crate::reload::Refusal>> + Send {
        let rec = self.ctx.record(
            GRAPH_RELOAD_ACTION,
            "permit",
            "intent recorded (SIGHUP)",
            "authorized",
            Some(GraphAudit {
                revision: store_revision,
                ciphertext_sha256: String::new(),
                anchor: "reloading".to_string(),
                scanned_bytes: 0,
            }),
        );
        let sink = Arc::clone(&self.reloader.sink);
        let bound = self.reloader.append_bound;
        async move {
            sink.emit_within(&rec, bound).await.map_err(|e| {
                eprintln!("maknaed: AUDIT WRITE FAILED on the reload intent: {e}");
                crate::reload::Refusal::Audit(e.to_string())
            })
        }
    }

    fn outcome(
        &self,
        r: &Result<crate::reload::Applied, crate::reload::Refusal>,
    ) -> impl Future<Output = ()> + Send {
        let (result, reason, posture) = crate::reload::outcome(r);
        let digest = *self
            .committed
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let (revision, anchor) = match r {
            Ok(applied) => (applied.revision, "reloaded"),
            Err(_) => (self.store_revision, "reload-refused"),
        };
        let mut rec = self.ctx.record(
            GRAPH_RELOAD_ACTION,
            result,
            &reason,
            posture,
            Some(GraphAudit {
                revision,
                ciphertext_sha256: digest.map_or_else(String::new, |d| lower_hex(&d)),
                anchor: anchor.to_string(),
                scanned_bytes: 0,
            }),
        );
        rec.policy_sha256 = Some(self.reloader.authorizer.baseline().policy_sha256());
        let replaced = Arc::clone(
            &self
                .replaced
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner),
        );
        let problems: Vec<(String, AuditRecord)> =
            crate::identity_report::recorded_after(r, &replaced, &self.reloader.identity.current())
                .iter()
                .map(|p| {
                    let (result, reason, posture) = crate::identity_report::record_fields(p);
                    let rec =
                        self.ctx
                            .record(GRAPH_IDENTITY_ACTION, result, &reason, posture, None);
                    (reason, rec)
                })
                .collect();
        let pending = self
            .newly_pending
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .take()
            .map(|p| {
                let (result, reason, posture) = crate::baseline::record_fields(&p);
                let rec = self
                    .ctx
                    .record(GRAPH_BASELINE_ACTION, result, &reason, posture, None);
                (p.clone(), crate::baseline::journal_line(&p), rec)
            });
        let sink = Arc::clone(&self.reloader.sink);
        let bound = self.reloader.append_bound;
        let status = self.reloader.baseline.clone();
        async move {
            if let Err(e) = sink.emit_within(&rec, bound).await {
                eprintln!("maknaed: AUDIT WRITE FAILED on the reload outcome ({reason}): {e}");
            }
            let mut appending = true;
            for (reason, rec) in problems {
                eprintln!("maknaed: identity: {reason}");
                if let Err(e) = sink.emit_within(&rec, bound).await {
                    eprintln!("maknaed: AUDIT WRITE FAILED on an identity record ({reason}): {e}");
                    appending = false;
                    break;
                }
            }
            if let Some((set, line, rec)) = pending.filter(|_| appending) {
                eprintln!("maknaed: baseline: {line}");
                match sink.emit_within(&rec, bound).await {
                    Ok(()) => {
                        status.publish(crate::baseline::BaselineState {
                            accepted: status.current().accepted.clone(),
                            pending: Some(set),
                        });
                    }
                    Err(e) => {
                        eprintln!("maknaed: AUDIT WRITE FAILED on the baseline pending record: {e}")
                    }
                }
            }
        }
    }
}

async fn shutdown_after_reloads<B, E>(
    signalled: impl Future<Output = ()> + Send,
    reloader: Arc<Reloader<B, E>>,
    reloads: tokio::task::AbortHandle,
) where
    B: maknae_authz_basic::Baseline,
    E: AuditEmit + Send + Sync + 'static,
{
    signalled.await;
    reloader.stop(&reloads).await;
}

/// One reload per received `SIGHUP`, in turn; a burst delivered while one runs
/// coalesces into one more.
async fn reload_task<F, Fut>(mut hup: tokio::signal::unix::Signal, on_hup: F)
where
    F: Fn() -> Fut,
    Fut: Future<Output = ()>,
{
    while hup.recv().await.is_some() {
        on_hup().await;
    }
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

/// Where the kernel graph key comes from. Production reads the enrolled credential;
/// the boot tests inject a fixed key.
type GraphKeyReader = fn(&Path) -> Result<maknae_vault::GraphKey, maknae_vault::VaultError>;
type FileReader = fn(&Path) -> Result<maknae_config::Document, maknae_config::ConfigError>;
type TrailOpener = fn(
    &maknae_config::AuditConfig,
) -> Result<maknae_audit_append::AuditSink, maknae_audit_append::AuditError>;
type TrailScanner = fn(
    &maknae_audit_append::AuditSink,
) -> Result<maknae_audit_append::ScanResult, maknae_audit_append::AuditError>;
type PolicyLoader =
    fn(
        maknae_authz_basic::PolicyPaths,
        maknae_config::Principal,
    ) -> Result<maknae_authz_basic::PolicySource, maknae_authz_basic::AuthzBasicError>;

/// What boot reads from the host. Production passes the real readers; the boot
/// tests pass their own.
struct BootSeams {
    graph_key: GraphKeyReader,
    state_dir_open: fn(&Path, u32) -> Result<StateDir, StoreError>,
    files: FileReader,
    env: Arc<dyn crate::baseline_check::Env>,
    open_prepared: TrailOpener,
    scan: TrailScanner,
    policy_load: PolicyLoader,
}

fn production_graph_key(
    config_dir: &Path,
) -> Result<maknae_vault::GraphKey, maknae_vault::VaultError> {
    let creds = maknae_vault::credentials_directory_env()?;
    maknae_vault::read_graph_key(creds.as_deref(), config_dir)
}

async fn run_inner(
    config_dir: &Path,
    state_dir: &Path,
    seams: &BootSeams,
) -> Result<ServeOutcome, RunError> {
    // An unregistered SIGHUP terminates the process; registered, one pending signal
    // is buffered until the reload task drains it after mint.
    let hup = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::hangup())
        .map_err(|e| RunError::Other(format!("cannot install SIGHUP handler: {e}")))?;
    // FIPS first (spec §6.1): install the aws-lc-rs FIPS default (once), then assert it —
    // before any crypto/Vault client is built. The assert stays authoritative: on a
    // non-FIPS build the installed default's `.fips()` is false and the daemon refuses.
    maknae_vault::install_default_crypto_provider();
    maknae_vault::assert_fips_provider().map_err(|e| RunError::Other(e.to_string()))?;

    let env = &*seams.env;
    let euid = nix::unistd::geteuid().as_raw();
    let (candidate, file_sections) = match read_file_baseline(config_dir, seams.files, env) {
        Ok((_, sections)) => (Ok(sections.clone()), Some(sections)),
        Err((refused, sections)) => (Err(refused), sections),
    };

    // The accepted baseline is read before anything is appended; the store is booted later.
    let key = (seams.graph_key)(config_dir).map(|k| WrappingKey::new(k.into_bytes()));
    let dir = (seams.state_dir_open)(state_dir, euid);
    let reseeding = matches!(&dir, Ok(d) if d.reseed_authorized());
    let peeked = match (&dir, &key) {
        (Ok(d), Ok(k)) => maknae_state::store::peek_baseline(d, k).map_err(|e| e.to_string()),
        (Err(e), _) => Err(e.to_string()),
        (_, Err(e)) => Err(e.to_string()),
    };
    let inconsistent = match &peeked {
        Ok(Some(b)) => inconsistency(b),
        _ => None,
    };
    let stored = match &peeked {
        Ok(Some(b)) if inconsistent.is_none() => Some(b),
        _ => None,
    };
    // Only a store that holds no baseline may have its trail created on first open.
    let create = matches!(peeked, Ok(None));
    let store_unread = peeked
        .as_ref()
        .err()
        .cloned()
        .or_else(|| inconsistent.clone());
    // Untrusted when inconsistent: used only to locate the trail and name what a reseed sets aside.
    let peeked_layer = match &peeked {
        Ok(Some(b)) => Some(b),
        _ => None,
    };
    let prior_trail = peeked_layer.and_then(|b| {
        b.moved_from
            .as_ref()
            .map(PathBuf::from)
            .or_else(|| accepted_trail(&sections_of(b), config_dir))
    });
    let accepted = if reseeding { None } else { stored };
    let accepted_sections = accepted.map(sections_of);

    let session_ids = Arc::new(SessionIds::new());
    let host = hostname();
    // ONE sequence for every boot-session record (#154 review): the boot
    // session id is a constant per boot, so two records minted from separate
    // `Seq::new()`s would both carry seq 1 and collide on (session_id, seq).
    let boot_seq = Seq::new();
    let ids = BootIds {
        host: &host,
        session_ids: &session_ids,
        seq: &boot_seq,
        euid,
    };

    let first_refusal = candidate.as_ref().err().cloned();
    let file = candidate.map_err(|e| e.into_file(file_sections.clone()));
    let start = crate::baseline::at_boot(accepted_sections.as_ref(), file, |mix| {
        let doc = maknae_config::Document::from_baseline(mix).map_err(|e| e.to_string())?;
        let v = crate::baseline_check::validate(doc, Mode::Boot, config_dir, env)
            .map_err(|e| e.cause().to_string())?;
        crate::baseline_check::check_move(prior_trail.as_deref(), &v.audit.jsonl_path, env)
    });
    let start = match start {
        Ok(start) => start,
        Err(cause) => {
            let cause = match &store_unread {
                Some(e) => format!("{cause}; and the kernel graph store could not be read: {e}"),
                None => cause,
            };
            let refused = first_refusal.unwrap_or_else(|| Invalid::Document(cause.clone()));
            let sections = file_sections.as_ref();
            let trail = prior_trail.as_deref();
            return Err(refuse_start(
                refused, cause, sections, trail, create, config_dir, seams, &ids,
            )
            .await);
        }
    };
    let run_doc = maknae_config::Document::from_baseline(&start.run)
        .map_err(|e| RunError::Other(e.to_string()))?;
    let validated = match crate::baseline_check::validate(run_doc, Mode::Boot, config_dir, env) {
        Ok(v) => v,
        Err(refused) => {
            let cause = match accepted {
                Some(_) => format!("accepted baseline cannot start: {}", refused.cause()),
                None => refused.cause().to_string(),
            };
            let trail = prior_trail.as_deref();
            return Err(refuse_start(
                refused,
                cause,
                Some(&start.run),
                trail,
                create,
                config_dir,
                seams,
                &ids,
            )
            .await);
        }
    };
    if reseeding {
        if let Err(e) = crate::baseline_check::check_move(
            prior_trail.as_deref(),
            &validated.audit.jsonl_path,
            env,
        ) {
            let cause = format!("{e}; see the runbook's \"Move the audit trail\"");
            return Err(refuse_start(
                Invalid::Environment(cause.clone()),
                cause,
                Some(&start.run),
                prior_trail.as_deref(),
                create,
                config_dir,
                seams,
                &ids,
            )
            .await);
        }
    }

    let socket = validated.transport.socket_path.display().to_string();
    let au3_1 = validated.audit.au3_1.clone();
    let ctx = BootCtx {
        event: "boot",
        host: &host,
        socket: &socket,
        euid,
        session_id: boot_session_id(&session_ids),
        seq: &boot_seq,
        au3_1: &au3_1,
    };
    // Fail-closed audit sink: no durable audit path → do not start (AU-5).
    let trail = open_trail(
        prior_trail.as_deref(),
        &validated.audit,
        create,
        seams.open_prepared,
        seams.scan,
        state_dir,
        &ctx,
    )
    .await?;
    let sink = trail.sink;
    let mut events = match (reseeding, peeked_layer) {
        (true, Some(replaced)) => vec![crate::baseline::reseeded_event(&replaced.sha256)],
        _ => start.events,
    };
    if let Some(m) = &trail.moved {
        events.push(crate::baseline::moved_event(&m.from, &m.to));
    }
    let started = Started {
        validated,
        run: start.run,
        pending: start.pending,
        accepted_seen: accepted.map(|b| b.sha256),
        events,
        inconsistent: inconsistent.filter(|_| !reseeding),
        dir,
        key,
        scanned: trail.scanned,
    };
    let result = boot_after_sink(
        config_dir,
        state_dir,
        seams,
        started,
        &sink,
        &session_ids,
        &host,
        &socket,
        euid,
        &boot_seq,
        hup,
    )
    .await;
    record_start_refusal(
        sink.as_ref(),
        &host,
        &socket,
        euid,
        boot_session_id(&session_ids),
        boot_seq.next(),
        &au3_1,
        &result,
    )
    .await;
    result
}

/// What the boot decided before the sink opened, for the steps after it.
struct Started {
    validated: crate::baseline_check::Validated,
    run: maknae_config::BaselineSections,
    pending: Option<crate::baseline::PendingSet>,
    accepted_seen: Option<[u8; 32]>,
    events: Vec<String>,
    inconsistent: Option<String>,
    dir: Result<StateDir, StoreError>,
    key: Result<WrappingKey, maknae_vault::VaultError>,
    scanned: Option<(Option<maknae_state::anchor::Checkpoint>, u64)>,
}

struct BootIds<'a> {
    host: &'a str,
    session_ids: &'a Arc<SessionIds>,
    seq: &'a Seq,
    euid: u32,
}

/// Why a stored baseline does not match its own record: the digest it carries, or
/// the system and ceiling its sections declare.
fn inconsistency(b: &BaselineLayer) -> Option<String> {
    let sections = sections_of(b);
    if b.sha256 != crate::baseline::accepted_digest(&sections) {
        return Some(
            "the accepted baseline's recorded digest does not match its sections".to_string(),
        );
    }
    let declared =
        match maknae_config::Document::from_baseline(&sections).and_then(crate::boot::assemble) {
            Ok(declared) => declared,
            Err(e) => {
                return Some(format!(
                    "the accepted baseline's sections do not assemble: {e}"
                ))
            }
        };
    let (system, ceiling) = (
        declared.classification_policy_name(),
        &declared.ceiling().classification.name,
    );
    (system != b.system || *ceiling != b.ceiling).then(|| {
        format!(
            "the accepted baseline records {}:{} but its sections declare {system}:{ceiling}; \
             it does not match its own record",
            b.system, b.ceiling
        )
    })
}

fn sections_of(b: &BaselineLayer) -> maknae_config::BaselineSections {
    b.sections.clone().into()
}

fn accepted_trail(
    sections: &maknae_config::BaselineSections,
    config_dir: &Path,
) -> Option<PathBuf> {
    let doc = maknae_config::Document::from_baseline(sections).ok()?;
    crate::baseline_check::audit_of(&doc, config_dir)
        .ok()
        .map(|a| a.jsonl_path)
}

fn open_or_create(
    cfg: &maknae_config::AuditConfig,
    create: bool,
) -> Result<maknae_audit_append::AuditSink, RunError> {
    let opened = if create {
        maknae_audit_append::AuditSink::open(cfg)
    } else {
        maknae_audit_append::AuditSink::open_existing(cfg)
    };
    opened.map_err(|e| match e {
        maknae_audit_append::AuditError::Missing(path) => RunError::Other(format!(
            "the audit trail {} is missing; prepare it as the runbook's \"Move the audit trail\" \
             step does, then start",
            path.display()
        )),
        e => RunError::Other(e.to_string()),
    })
}

/// A start the validator refused, recorded in `trail` (or the document's own) with
/// today's exit code; a document refusal is recorded only in a known `trail`.
#[allow(clippy::too_many_arguments)]
async fn refuse_start(
    refused: Invalid,
    cause: String,
    sections: Option<&maknae_config::BaselineSections>,
    trail: Option<&Path>,
    create: bool,
    config_dir: &Path,
    seams: &BootSeams,
    ids: &BootIds<'_>,
) -> RunError {
    let document = matches!(refused, Invalid::Document(_));
    if document && trail.is_none() {
        return RunError::Other(cause);
    }
    let located = sections
        .ok_or_else(|| "nothing was read to record it in".to_string())
        .and_then(|s| {
            let doc = maknae_config::Document::from_baseline(s).map_err(|e| e.to_string())?;
            let audit = crate::baseline_check::audit_of(&doc, config_dir)
                .map_err(|e| e.cause().to_string())?;
            let transport =
                crate::baseline_check::transport_of(&doc).map_err(|e| e.cause().to_string())?;
            Ok((audit, transport))
        });
    let (audit, socket) = match (located, trail) {
        (Ok((audit, transport)), _) => (audit, transport.socket_path.display().to_string()),
        (Err(_), Some(trail)) if document => (
            maknae_config::AuditConfig {
                readers: Vec::new(),
                jsonl_path: trail.to_path_buf(),
                siem: None,
                au3_1: serde_json::Value::Null,
            },
            String::new(),
        ),
        (Err(e), _) => return RunError::Other(format!("{cause}; {e}")),
    };
    let audit = maknae_config::AuditConfig {
        jsonl_path: trail.map_or_else(|| audit.jsonl_path.clone(), Path::to_path_buf),
        ..audit
    };
    let sink = match open_or_create(&audit, create) {
        Ok(sink) => sink,
        Err(_) if document => return RunError::Other(cause),
        Err(e) => return e,
    };
    let (session, seq) = (boot_session_id(ids.session_ids), ids.seq.next());
    let (host, euid, au3_1) = (ids.host, ids.euid, &audit.au3_1);
    let reason = match refused {
        Invalid::Offload(_) => {
            return refuse_audit_offload_boot(
                &sink, host, &socket, euid, session, seq, au3_1, cause,
            )
            .await
        }
        Invalid::Principal(_) => {
            return refuse_authz_boot(&sink, host, &socket, euid, session, seq, au3_1, cause).await
        }
        Invalid::Vault { principal, .. } => match crate::boot_gate::authz_policy_source_with(
            config_dir,
            Some(principal),
            seams.policy_load,
        ) {
            Err(e) => {
                return refuse_authz_boot(
                    &sink,
                    host,
                    &socket,
                    euid,
                    session,
                    seq,
                    au3_1,
                    e.to_string(),
                )
                .await
            }
            Ok(_) => cause,
        },
        Invalid::Environment(_) | Invalid::Document(_) => cause,
    };
    let refused = Err(RunError::Other(reason.clone()));
    record_start_refusal(&sink, host, &socket, euid, session, seq, au3_1, &refused).await;
    RunError::Other(reason)
}

struct OpenedTrail {
    sink: Arc<maknae_audit_append::AuditSink>,
    scanned: Option<(Option<maknae_state::anchor::Checkpoint>, u64)>,
    moved: Option<crate::baseline::Move>,
}

/// A start refused before the move record is written is no part of the move: it is
/// recorded in the old trail, the one still live.
async fn refused_before_move(
    old: &Result<Arc<maknae_audit_append::AuditSink>, String>,
    ctx: &BootCtx<'_>,
    e: RunError,
) -> RunError {
    let refused = Err(e);
    if let Ok(old) = old {
        record_start_refusal(
            old.as_ref(),
            ctx.host,
            ctx.socket,
            ctx.euid,
            ctx.session_id,
            ctx.seq.next(),
            ctx.au3_1,
            &refused,
        )
        .await;
    }
    refused.map(drop).unwrap_err()
}

/// The trail this start appends to, with the move from `prior` performed when the
/// path changed: the old trail records the move first, the new one links back, and
/// the anchor is the newer of the two trails' checkpoints.
async fn open_trail(
    prior: Option<&Path>,
    cfg: &maknae_config::AuditConfig,
    create: bool,
    open_prepared: TrailOpener,
    scan: TrailScanner,
    state_dir: &Path,
    ctx: &BootCtx<'_>,
) -> Result<OpenedTrail, RunError> {
    let m = match crate::baseline::move_of(prior, &cfg.jsonl_path) {
        Err(e) => {
            return Err(RunError::Other(format!(
                "{e}; see the runbook's \"Move the audit trail\""
            )))
        }
        Ok(None) => {
            return Ok(OpenedTrail {
                sink: Arc::new(open_or_create(cfg, create)?),
                scanned: None,
                moved: None,
            })
        }
        Ok(Some(m)) => m,
    };
    let old = maknae_audit_append::AuditSink::open_existing(&maknae_config::AuditConfig {
        jsonl_path: m.from.clone(),
        ..cfg.clone()
    })
    .map(Arc::new)
    .map_err(|e| e.to_string());
    let new = match open_prepared(cfg) {
        Ok(new) => Arc::new(new),
        Err(e) => return Err(refused_before_move(&old, ctx, RunError::Other(e.to_string())).await),
    };
    let scanned = match &old {
        Ok(old) => last_checkpoint(old, state_dir, scan).await,
        Err(_) => Ok((None, 0)),
    };
    let ((old_checkpoint, old_bytes), (new_checkpoint, new_bytes)) = match scanned {
        Ok(o) => match last_checkpoint(&new, state_dir, scan).await {
            Ok(n) => (o, n),
            Err(e) => return Err(refused_before_move(&old, ctx, e).await),
        },
        Err(e) => return Err(refused_before_move(&old, ctx, e).await),
    };
    let carried = maknae_state::anchor::newer(old_checkpoint, new_checkpoint);
    let record =
        |reason: &str| ctx.record(GRAPH_BASELINE_ACTION, "permit", reason, "authorized", None);
    if let Ok(old) = &old {
        old.emit_within(
            &record(&crate::baseline::move_record(&m.to)),
            AUDIT_APPEND_TIMEOUT,
        )
        .await
        .map_err(|e| boot_evidence_refused("audit move", e))?;
    }
    let old_unopened = old.err();
    let link = crate::baseline::back_link_record(
        &m.from,
        carried.map(|c| c.revision),
        old_unopened.as_deref(),
    );
    new.emit_within(&record(&link), AUDIT_APPEND_TIMEOUT)
        .await
        .map_err(|e| boot_evidence_refused("audit move", e))?;
    Ok(OpenedTrail {
        sink: new,
        scanned: Some((carried, old_bytes + new_bytes)),
        moved: Some(m),
    })
}

/// Everything `run_inner` does once the audit sink is open, so that a startup
/// failure here reaches [`record_start_refusal`] (#265 A2).
#[allow(clippy::too_many_arguments)]
async fn boot_after_sink(
    config_dir: &Path,
    state_dir: &Path,
    seams: &BootSeams,
    started: Started,
    sink: &Arc<maknae_audit_append::AuditSink>,
    session_ids: &Arc<SessionIds>,
    host: &str,
    socket: &str,
    euid: u32,
    boot_seq: &Seq,
    hup: tokio::signal::unix::Signal,
) -> Result<ServeOutcome, RunError> {
    let classification = crate::baseline_check::classification_of(&started.validated);
    let live = crate::live::LiveConfig::of(&started.validated);
    let Started {
        validated,
        run,
        pending,
        accepted_seen,
        events,
        inconsistent,
        dir,
        key,
        scanned,
    } = started;
    let crate::baseline_check::Validated {
        boot,
        transport,
        egress: egress_cfg,
        audit,
        principal,
        ..
    } = validated;
    if let Some(why) = inconsistent {
        return Err(graph_refusal(GraphFailure::Inconsistent(why), state_dir));
    }
    let audit_cfg = &audit;
    let egress = crate::egress::production_egress_with(boot.providers(), &egress_cfg, |_| {
        seams.env.egress_account()
    })
    .map_err(|e| RunError::Other(e.to_string()))?;

    // --- AUTHZ GATE (#77, spec D1): the daemon constructs its PDP at boot or
    // refuses to start, after the validator passed the principal. Any PDP
    // construction refusal (hardened policy load, bindings semantics) →
    // peer-less AU-3 refusal record → RunError::Authz → exit code 3.
    let refuse = |reason: String| {
        refuse_authz_boot(
            sink.as_ref(),
            host,
            socket,
            euid,
            boot_session_id(session_ids),
            boot_seq.next(),
            &audit_cfg.au3_1,
            reason,
        )
    };
    let source = match crate::boot_gate::authz_policy_source_with(
        config_dir,
        Some(principal),
        seams.policy_load,
    ) {
        Ok(source) => source,
        Err(e) => return Err(refuse(e.to_string()).await),
    };
    let label = boot.policy().unmarked().name.clone();
    let mut graph_inputs = GraphInputs::new(&source, &label, run_baseline(&run, classification))
        .map_err(|e| graph_refusal(GraphFailure::Store(e), state_dir))?;
    graph_inputs.accepted_seen = accepted_seen;
    graph_inputs.baseline_events = events;
    // The kernel graph boots before the PDP is built from it.
    let mut booted = match boot_kernel_graph(
        state_dir,
        dir,
        key,
        sink,
        &BootCtx {
            event: "boot",
            host,
            socket,
            euid,
            session_id: boot_session_id(session_ids),
            seq: boot_seq,
            au3_1: &audit_cfg.au3_1,
        },
        &graph_inputs.boot(),
        scanned,
    )
    .await
    {
        Ok(booted) => booted,
        Err(RunError::Authz(reason)) => return Err(refuse(reason).await),
        Err(e) => return Err(e),
    };
    booted.status.baseline = crate::baseline::BaselineStatus::new(crate::baseline::BaselineState {
        accepted: run,
        pending: pending.clone(),
    });
    let persisted_graph = Arc::new(booted.graph);
    let authorizer = match authz_boot_gate(
        source,
        Arc::clone(&persisted_graph),
        &graph_inputs.vocabulary.full,
    ) {
        Ok(authorizer) => authorizer,
        Err(e) => return Err(refuse(e.to_string()).await),
    };
    // ADR-0008 decision 1 (#154) + #148: the PDP is the COMPOSITION, and both
    // floors are named fields of it -- the sealed `Baseline` (-basic, from the
    // gate above) and the booted classification ceiling, evaluated through the
    // classification SYSTEM boot selected (ADR-0022). Neither can be absent:
    // the type has no constructor without them. Built HERE, unconditionally,
    // from the gate's own return value; `ci/gates/authz-composition-drift.sh`
    // pins this call site so a future selection key fails CI.
    let authorizer = crate::composition::build_pdp(&boot, authorizer);
    let authorizer = authorizer.with_live(live);
    // Boot-time EVIDENCE (ADR-0008 decision 1, fourth layer): the trail
    // records which operands this process composes, so the property is
    // auditable at runtime and not only at build time. Same record shape as
    // the authz refusal above; the action is the `authz` pseudo-action.
    let composition_name = maknae_security::guarded_backend_name(&authorizer);
    let mut composition_rec = make_record(
        "boot",
        host,
        socket,
        euid,
        None,
        None,
        None,
        boot_session_id(session_ids),
        boot_seq.next(),
        "authz",
        None,
        "permit",
        // The reason ALSO records the classification SYSTEM and the booted
        // ceiling LEVEL -- the two values the operand enforces -- so the
        // trail says what this process will refuse (content marked above
        // that level, in that system), not only which operands it composes.
        &format!(
            "authorization composition: {composition_name}; system: {}; ceiling: {}",
            boot.classification_policy_name(),
            boot.ceiling().classification.name
        ),
        "authorized",
        &audit_cfg.au3_1,
    );
    composition_rec.policy_sha256 = Some(maknae_authz_basic::Baseline::policy_sha256(
        authorizer.baseline(),
    ));
    sink.emit_within(&composition_rec, AUDIT_APPEND_TIMEOUT)
        .await
        .map_err(|e| boot_evidence_refused("composition", e))?;
    let identity_ctx = BootCtx {
        event: "boot",
        host,
        socket,
        euid,
        session_id: boot_session_id(session_ids),
        seq: boot_seq,
        au3_1: &audit_cfg.au3_1,
    };
    publish_boot_identity(
        &booted.status.identity,
        &maknae_authz_basic::Baseline::snapshot(authorizer.baseline()),
        &booted.released,
        booted.principal_admin,
        sink,
        &identity_ctx,
    )
    .await?;
    if let Some(p) = &pending {
        let (result, reason, posture) = crate::baseline::record_fields(p);
        sink.emit_within(
            &identity_ctx.record(GRAPH_BASELINE_ACTION, result, &reason, posture, None),
            AUDIT_APPEND_TIMEOUT,
        )
        .await
        .map_err(|e| boot_evidence_refused("baseline pending", e))?;
        eprintln!("maknaed: baseline: {}", crate::baseline::journal_line(p));
    }
    let authorizer = Arc::new(authorizer);
    let identity = booted.status.identity.clone();
    let graph_revision = Arc::clone(&booted.status.revision);
    let baseline_status = booted.status.baseline.clone();
    let kernel_graph = Arc::new(Some(booted.status));

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
    // plane client resolved which SecretID source it actually used. An append
    // failure refuses boot (#265 C2).
    //
    // `expected_target` is `<config_dir>/private/maknaed-secret-id.{cred,keychain}`;
    // `posture::determine` requires the marker's `target` to match it (spec §5.2).
    let secret_source_kind = client.secret_source();
    let expected_target = match secret_source_kind {
        maknae_vault::CredentialSourceKind::CredentialsDirectory => {
            config_dir.join("private").join("maknaed-secret-id.cred")
        }
        maknae_vault::CredentialSourceKind::Keychain => {
            maknae_vault::daemon_keychain_pointer(config_dir)
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
        host,
        socket,
        euid,
        None,
        None,
        None,
        boot_session_id(session_ids),
        boot_seq.next(),
        "posture",
        None,
        "permit",
        "boot credential posture recorded",
        posture.as_str(),
        &audit_cfg.au3_1,
    );
    sink.emit_within(&posture_rec, AUDIT_APPEND_TIMEOUT)
        .await
        .map_err(|e| boot_evidence_refused("posture", e))?;
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
    // #240 (review round 4): the abort that MUST precede `client.shutdown()`
    // lives here, on the one path every exit takes — the accept loop's own
    // abort-and-reap covers the graceful path and the ordering; this covers
    // the post-mint `?` exits (gid, bind, signal install) that never reach it.
    let supervisor_abort = supervisor.abort_handle();

    // Once `mint()` succeeds the privileged kernel-plane Vault token is LIVE until
    // lease expiry — so EVERY post-mint startup step (bind, and anything before the
    // serve loop) must revoke it on failure, or the token leaks. Capture the whole
    // post-mint outcome, revoke UNCONDITIONALLY, THEN propagate. (A pre-mint failure
    // above skips revoke — there is nothing minted to revoke. Mirrors `cli.rs::execute`.)
    // Asked of the PDP ONCE, at boot -- not per request. The backend set is
    // fixed for the life of the process (static TCB, ADR-0002: no hot-swap),
    // so a per-request call could only ever return the same string, while
    // handing every granted `admin.status` an unbounded inline invocation of
    // operand code on a tokio worker -- the seam doc's "MUST NOT block" is a
    // contract, not an enforcement (codex round-11 P2). A backend that blocks
    // here hangs BOOT, loudly, instead of quietly eating workers in service.
    let authz_backend_name = Arc::new(maknae_security::guarded_backend_name(&*authorizer));
    // The classification system this enclave runs under, as boot selected it
    // from `core.handling.policy` (ADR-0022) -- captured here for the same
    // reason as the backend name: fixed for the life of the process.
    let classification_policy_name = Arc::new(boot.classification_policy_name().to_string());
    // Holds the one-maknaed state-dir lock for the serve's lifetime.
    let reloader = Reloader {
        dir: booted.dir,
        key: booted.key,
        authorizer: Arc::clone(&authorizer),
        label,
        vocabulary: graph_inputs.vocabulary,
        revision: graph_revision,
        lock: tokio::sync::Mutex::new(()),
        sink: Arc::clone(sink),
        session_ids: Arc::clone(session_ids),
        host: host.to_string(),
        socket: socket.to_string(),
        euid,
        au3_1: audit_cfg.au3_1.clone(),
        identity,
        stopping: tokio::sync::watch::channel(false).0,
        append_bound: AUDIT_APPEND_TIMEOUT,
        persisted: std::sync::RwLock::new(persisted_graph),
        config_dir: config_dir.to_path_buf(),
        files: seams.files,
        env: Arc::clone(&seams.env),
        baseline: baseline_status,
        drain: tokio::sync::watch::channel(Drain::Serving).0,
        turn_wait: BLOCKING_OPERATION_TIMEOUT,
        #[cfg(test)]
        load_gate: None,
    };
    let outcome = serve_after_mint(
        &client,
        &ca,
        sink,
        transport,
        audit_cfg,
        Arc::clone(session_ids),
        supervisor,
        Arc::clone(&authorizer),
        authz_backend_name,
        classification_policy_name,
        kernel_graph,
        egress,
        hup,
        Arc::new(reloader),
    )
    .await;

    // Retire the plane credential (revoke token, clear leaf) on the way out — on the
    // graceful-shutdown path AND on any post-mint startup failure (e.g. bind).
    // The supervisor is aborted first, on EVERY path (idempotent on the
    // graceful one): detached, it could hold the client lock across a Vault
    // call while `shutdown()` waits, or re-install a leaf after retirement.
    supervisor_abort.abort();
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
async fn serve_after_mint<B>(
    client: &maknae_vault::PlaneClient,
    ca: &maknae_vault::CaBundle,
    sink: &Arc<maknae_audit_append::AuditSink>,
    transport: maknae_config::TransportConfig,
    audit_cfg: &maknae_config::AuditConfig,
    session_ids: Arc<SessionIds>,
    supervisor: tokio::task::JoinHandle<maknae_vault::VaultError>,
    // The COMPOSITION, by type -- not `Arc<P: Authorizer>`. A generic here would
    // accept a bare baseline, and the drift gate inspects only the construction
    // statement, so a run.rs that composes, audits the composition, then serves
    // the baseline alone would pass every gate (critical-review round 3). This
    // signature is the type-level pin: what is served is what was composed.
    authorizer: Arc<crate::composition::Composition<B>>,
    // Captured at boot (see run_inner).
    authz_backend_name: Arc<String>,
    classification_policy_name: Arc<String>,
    kernel_graph: Arc<Option<KernelGraphStatus>>,
    egress: Arc<dyn crate::egress::Egress>,
    hup: tokio::signal::unix::Signal,
    reloader: Arc<Reloader<B, maknae_audit_append::AuditSink>>,
) -> Result<ServeOutcome, String>
where
    B: maknae_authz_basic::Baseline,
{
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
    let signalled = install_shutdown_signal()?;
    let reloads = tokio::spawn(reload_task(hup, {
        let reloader = Arc::clone(&reloader);
        move || {
            let reloader = Arc::clone(&reloader);
            async move {
                if let Err(refusal) = reloader.run().await {
                    eprintln!("maknaed: reload refused: {refusal}; the previous policy stands");
                }
            }
        }
    }));
    let reloads = reloads.abort_handle();
    let drain = reloader.drain.subscribe();
    let shutdown = shutdown_after_reloads(
        shutdown_on(signalled, drain.clone()),
        Arc::clone(&reloader),
        reloads.clone(),
    );
    let live = Arc::clone(authorizer.live());
    let baseline: Arc<dyn BaselineOps> = Arc::clone(&reloader) as _;
    let outcome = accept_loop(
        listener,
        Arc::clone(sink),
        session_ids,
        transport,
        wctx,
        shutdown,
        supervisor,
        authorizer,
        live,
        authz_backend_name,
        classification_policy_name,
        kernel_graph,
        egress,
        baseline,
        drain.clone(),
    )
    .await;
    reloader.stop(&reloads).await;
    let drained = *drain.borrow();
    Ok(crate::handler::after_drain(outcome, drained))
}

/// Resolves on a signal, or once a restart-class accept has persisted or failed; a
/// dropped drain sender never resolves it.
async fn shutdown_on(
    signalled: impl Future<Output = ()>,
    mut drain: tokio::sync::watch::Receiver<Drain>,
) {
    tokio::select! {
        _ = signalled => {}
        Ok(_) = drain.wait_for(|d| crate::handler::may_stop(*d)) => {}
    }
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
pub(crate) fn rfc3339_now() -> String {
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
pub(crate) mod baseline_stub {
    use super::*;

    pub(crate) struct NoBaseline;

    impl BaselineOps for NoBaseline {
        fn show(&self) -> BoxFuture<'_, Result<maknae_proto::BaselineView, String>> {
            Box::pin(async { Err("no baseline service".to_string()) })
        }
        fn accept<'a>(&'a self, _: &'a str) -> BoxFuture<'a, AcceptAnswer> {
            Box::pin(async {
                AcceptAnswer::Unavailable {
                    reply: "no baseline service",
                    why: "no baseline service".into(),
                }
            })
        }
    }

    pub(crate) fn no_baseline() -> Arc<dyn BaselineOps> {
        Arc::new(NoBaseline)
    }

    pub(crate) fn serving() -> tokio::sync::watch::Receiver<Drain> {
        tokio::sync::watch::channel(Drain::Serving).1
    }
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

    /// #240: the drain must outlast a provider call in flight, or a restart
    /// that races a prompt aborts the handler before its outcome record —
    /// content left, `IntentOnly` in the trail. With no provider (the
    /// `Unavailable` backend's zero deadline) the bound is the old one.
    #[test]
    fn the_handler_drain_bound_covers_the_egress_deadline() {
        // at the transport defaults (5 s handshake, 5 s read): 5 + 5 + 5 + 5
        // + 5 + 5 + 5 + 0 + 5 + 1 + 10 = 51 s with no provider, plus the deadline with one
        let cfg = maknae_config::transport_from_section(None).unwrap();
        assert_eq!(
            handler_drain_bound(&cfg, Duration::ZERO),
            Duration::from_secs(51)
        );
        assert_eq!(
            handler_drain_bound(&cfg, Duration::from_secs(120)),
            Duration::from_secs(171)
        );
    }

    /// How far above the walked shutdown chain the shipped units' stop
    /// timeouts may sit. Two-sided on purpose: a unit BELOW the chain
    /// SIGKILLs inside the token revoke; a unit far ABOVE it means a term
    /// was dropped from the chain expression while the unit kept the old
    /// sum — the failure four review rounds found in a row.
    const STOP_TIMEOUT_SLACK: Duration = Duration::from_secs(10);

    /// Once the drain is applied an accept still appends the checkpoint and its
    /// outcome, writes the reply and closes the stream.
    #[test]
    fn the_accept_worst_case_fits_the_handler_drain() {
        let cfg = maknae_config::transport_from_section(None).unwrap();
        let egress = maknae_config::egress_from_section(None).unwrap();
        let remaining = 2 * AUDIT_APPEND_TIMEOUT
            + Duration::from_millis(cfg.read_timeout_ms)
            + STREAM_CLOSE_TIMEOUT;
        for deadline in [Duration::from_millis(egress.deadline_ms), Duration::ZERO] {
            let bound = handler_drain_bound(&cfg, deadline);
            assert!(remaining < bound, "{remaining:?} {bound:?}");
        }
    }

    #[test]
    fn the_supervisors_restart_on_the_apply_by_restart_exit_code() {
        let unit = include_str!("../../../packaging/common/maknaed.service");
        let lines: Vec<&str> = unit.lines().map(str::trim).collect();
        assert!(lines.contains(&"Restart=on-failure"));
        for key in ["RestartPreventExitStatus=", "SuccessExitStatus="] {
            assert!(
                !lines
                    .iter()
                    .any(|l| l.starts_with(key) && l.split(['=', ' ']).any(|t| t == "6")),
                "{key} must not name 6"
            );
        }
        for l in lines.iter().filter(|l| l.starts_with("StartLimitBurst=")) {
            assert!(
                l["StartLimitBurst=".len()..].parse::<u32>().unwrap() >= 2,
                "{l}"
            );
        }
        let plist = include_str!("../../../packaging/macos/io.maknae.maknaed.plist");
        let keep = plist.split("<key>KeepAlive</key>").nth(1).unwrap();
        let dict = &keep[..keep.find("</dict>").unwrap()];
        assert!(
            dict.contains("<key>SuccessfulExit</key>") && dict.contains("<false/>"),
            "{dict}"
        );
        let throttle = plist.split("<key>ThrottleInterval</key>").nth(1).unwrap();
        let secs: u32 = throttle
            .split("<integer>")
            .nth(1)
            .unwrap()
            .split("</integer>")
            .next()
            .unwrap()
            .trim()
            .parse()
            .unwrap();
        assert!(secs <= 10, "launchd restarts within {secs} s");
        assert_eq!(crate::handler::APPLY_BY_RESTART_EXIT_CODE, 6);
    }

    /// #240 (review rounds 2–4): the shipped units' stop timeouts are held to
    /// the shutdown chain at the deadline CEILING, term by term and in the
    /// order `accept_loop` and `run_inner` execute them — the reload wait, the stop record's
    /// append (#265), the supervisor abort-reap, the handler drain (deadline + its own bound) and the reap
    /// of what it aborts, the audit drain, the plane client's shutdown (a
    /// bounded lock wait, then revoke-self), the runtime teardown and the diagnostics
    /// flush. TWO-SIDED:
    /// four rounds each found a term the expression had skipped while the
    /// unit kept the old sum, so a unit more than `STOP_TIMEOUT_SLACK` above
    /// the chain is as red as one below it.
    #[test]
    fn the_units_stop_timeouts_cover_the_shutdown_chain_at_the_deadline_ceiling() {
        // BOTH ceilings: the transport timeouts at their maximum and the
        // egress deadline at its maximum — the configuration the units must
        // survive, not the defaults (review round 5).
        let ceiling = maknae_config::TransportConfig {
            handshake_timeout_ms: maknae_config::TRANSPORT_TIMEOUT_MS_MAX,
            read_timeout_ms: maknae_config::TRANSPORT_TIMEOUT_MS_MAX,
            ..maknae_config::transport_from_section(None).unwrap()
        };
        let chain = RELOAD_STOP_TIMEOUT
            + AUDIT_DRAIN_SHUTDOWN_TIMEOUT
            + SUPERVISOR_ABORT_REAP_TIMEOUT
            + handler_drain_bound(
                &ceiling,
                Duration::from_millis(maknae_config::EGRESS_DEADLINE_MS_MAX),
            )
            + DRAIN_ABORT_REAP_TIMEOUT
            + AUDIT_DRAIN_SHUTDOWN_TIMEOUT
            + maknae_vault::PLANE_SHUTDOWN_BOUND
            + RUNTIME_SHUTDOWN_TIMEOUT
            + DIAG_FLUSH_TIMEOUT;
        let unit = include_str!("../../../packaging/common/maknaed.service");
        let stop: u64 = unit
            .lines()
            .find_map(|l| l.strip_prefix("TimeoutStopSec="))
            .expect("maknaed.service states TimeoutStopSec=")
            .trim()
            .parse()
            .unwrap();
        let stop = Duration::from_secs(stop);
        assert!(
            stop >= chain,
            "TimeoutStopSec={stop:?} is below the shutdown chain at the ceiling, {chain:?}"
        );
        assert!(
            stop <= chain + STOP_TIMEOUT_SLACK,
            "TimeoutStopSec={stop:?} is more than {STOP_TIMEOUT_SLACK:?} above the chain {chain:?}: a term was dropped from the expression"
        );
        let plist = include_str!("../../../packaging/macos/io.maknae.maknaed.plist");
        let after = &plist[plist
            .find("<key>ExitTimeOut</key>")
            .expect("the launchd plist states ExitTimeOut")..];
        let s = after.find("<integer>").unwrap() + "<integer>".len();
        let e = s + after[s..].find("</integer>").unwrap();
        let exit: u64 = after[s..e].parse().unwrap();
        let exit = Duration::from_secs(exit);
        assert!(
            exit >= chain,
            "ExitTimeOut={exit:?} is below the shutdown chain at the ceiling, {chain:?}"
        );
        assert!(
            exit <= chain + STOP_TIMEOUT_SLACK,
            "ExitTimeOut={exit:?} is more than {STOP_TIMEOUT_SLACK:?} above the chain {chain:?}: a term was dropped from the expression"
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
    /// The property: the seam permits a backend whose `subjects()` blocks, so
    /// enumeration runs on the blocking pool under the decide breaker and
    /// timeout. The shipped backend now reads its installed snapshot; a backend
    /// that blocks, called inline, pins a tokio worker for as long as it blocks,
    /// and N granted calls starve the runtime with the breaker unable to trip,
    /// because it never sees them.
    ///
    /// That failure is not reproducible at unit scale — it needs a blocking
    /// backend and runtime saturation. A behavioural test that "passes"
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

    #[tokio::test]
    async fn a_document_refusal_is_recorded_only_in_a_known_trail() {
        let d = Dir::new("document-refusal");
        let trail = d.0.join("audit.jsonl");
        let (session_ids, seq) = (Arc::new(SessionIds::new()), Seq::new());
        let ids = BootIds {
            host: "h",
            session_ids: &session_ids,
            seq: &seq,
            euid: 0,
        };
        let refuse = |trail: Option<PathBuf>| {
            let (d, ids) = (&d, &ids);
            async move {
                refuse_start(
                    Invalid::Document("document-refusal-sentinel".into()),
                    "document-refusal-sentinel".into(),
                    None,
                    trail.as_deref(),
                    true,
                    &d.0,
                    &test_seams(),
                    ids,
                )
                .await
            }
        };
        let none = refuse(None).await;
        assert!(matches!(&none, RunError::Other(c) if c == "document-refusal-sentinel"));
        assert!(!trail.exists(), "no trail is opened when none is known");
        let known = refuse(Some(trail.clone())).await;
        assert!(matches!(&known, RunError::Other(c) if c == "document-refusal-sentinel"));
        let recs = trail_of(&d, "audit.jsonl");
        assert_eq!(recs.len(), 1);
        assert_eq!(
            (
                recs[0].action.as_str(),
                recs[0].outcome.result.as_str(),
                recs[0].outcome.reason.as_str()
            ),
            ("start", "deny", "document-refusal-sentinel")
        );
    }

    pub(super) fn test_baseline() -> BaselineLayer {
        let sections: maknae_config::BaselineSections = [(
            "core".to_string(),
            r#"{"deployment_id":"test"}"#.to_string(),
        )]
        .into();
        BaselineLayer {
            sha256: crate::baseline::accepted_digest(&sections),
            sections: sections.into_inner(),
            system: "US".into(),
            ceiling: "UNCLASSIFIED".into(),
            moved_from: None,
        }
    }
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
        block_on_run_inner_with(dir, test_seams())
    }

    /// The graph boot as a start decides it: a stored baseline is passed back with
    /// nothing to record; with none, the given one is seeded.
    pub(super) async fn boot_graph_at(
        state_dir: &Path,
        key: Result<maknae_vault::GraphKey, maknae_vault::VaultError>,
        sink: &Arc<maknae_audit_append::AuditSink>,
        ctx: &BootCtx<'_>,
        inputs: &BootInputs<'_>,
    ) -> Result<BootedGraph, RunError> {
        let key = key.map(|k| WrappingKey::new(k.into_bytes()));
        let dir = StateDir::open(state_dir, ctx.euid);
        let stored = match (&dir, &key) {
            (Ok(d), Ok(k)) if !d.reseed_authorized() => {
                maknae_state::store::peek_baseline(d, k).ok().flatten()
            }
            _ => None,
        };
        let seeded = [crate::baseline::SEEDED_EVENT.to_string()];
        let inputs = match &stored {
            Some(accepted) => BootInputs {
                baseline: accepted,
                accepted_seen: Some(accepted.sha256),
                baseline_events: &[],
                ..*inputs
            },
            None => BootInputs {
                accepted_seen: None,
                baseline_events: &seeded,
                ..*inputs
            },
        };
        boot_kernel_graph(state_dir, dir, key, sink, ctx, &inputs, None).await
    }

    fn test_graph_key(_: &Path) -> Result<maknae_vault::GraphKey, maknae_vault::VaultError> {
        maknae_vault::graph_key_from_bytes(&[0x5a; 32])
    }

    fn state_dir(config_dir: &Path) -> PathBuf {
        let state = config_dir.join("state");
        std::fs::create_dir_all(&state).unwrap();
        std::fs::set_permissions(&state, std::fs::Permissions::from_mode(0o700)).unwrap();
        state
    }

    struct TestEmit {
        fail: bool,
        recs: Mutex<Vec<AuditRecord>>,
    }
    impl TestEmit {
        fn new(fail: bool) -> Self {
            TestEmit {
                fail,
                recs: Mutex::new(Vec::new()),
            }
        }
    }
    impl AuditEmit for TestEmit {
        fn emit(
            &self,
            rec: &AuditRecord,
        ) -> impl Future<Output = Result<(), maknae_audit_append::AuditError>> + Send {
            let r = if self.fail {
                Err(maknae_audit_append::AuditError::WritePrimary(
                    "injected".into(),
                ))
            } else {
                self.recs.lock().unwrap().push(rec.clone());
                Ok(())
            };
            async move { r }
        }
    }
    fn evidence() -> AuditRecord {
        make_record(
            "boot",
            "h",
            "s",
            0,
            None,
            None,
            None,
            1,
            1,
            "posture",
            None,
            "permit",
            "r",
            "p",
            &serde_json::Value::Null,
        )
    }
    fn block_on<F: Future>(f: F) -> F::Output {
        tokio::runtime::Runtime::new().unwrap().block_on(f)
    }

    #[test]
    fn boot_evidence_that_cannot_be_appended_refuses_boot() {
        let refused = block_on(TestEmit::new(true).emit(&evidence()))
            .map_err(|e| boot_evidence_refused("posture", e));
        match refused {
            Err(RunError::Other(m)) => {
                assert!(m.contains("posture") && m.contains("injected"), "{m}")
            }
            other => panic!("expected Err(RunError::Other), got {other:?}"),
        }
    }

    #[test]
    fn a_post_sink_startup_failure_is_recorded_once_and_a_recorded_refusal_is_not() {
        let rec = |result: Result<ServeOutcome, RunError>| {
            let e = TestEmit::new(false);
            block_on(record_start_refusal(
                &e,
                "h",
                "s",
                0,
                7 << 32,
                4,
                &serde_json::Value::Null,
                &result,
            ));
            e.recs.into_inner().unwrap()
        };
        let recs = rec(Err(RunError::Other("bind: address in use".into())));
        assert_eq!(recs.len(), 1);
        assert_eq!(
            (
                recs[0].event.as_str(),
                recs[0].action.as_str(),
                recs[0].outcome.result.as_str()
            ),
            ("boot", "start", "deny")
        );
        assert!(recs[0].outcome.reason.contains("bind: address in use"));
        assert_eq!((recs[0].session_id, recs[0].seq), (7 << 32, 4));
        let graph = rec(Err(RunError::Graph {
            reason: "kernel graph store: substituted".into(),
            hint: "h".into(),
        }));
        assert_eq!(graph.len(), 1);
        assert_eq!(
            (
                graph[0].action.as_str(),
                graph[0].outcome.result.as_str(),
                graph[0].outcome.reason.as_str()
            ),
            ("graph.load", "deny", "kernel graph store: substituted")
        );
        assert!(rec(Err(RunError::Authz("a".into()))).is_empty());
        assert!(rec(Err(RunError::AuditOffload("o".into()))).is_empty());
        assert!(rec(Ok(ServeOutcome::GracefulShutdown)).is_empty());
    }

    // (a) A missing `authz.yaml` refuses to start with the NEW distinct error
    // variant, having written a durable AU-3 refusal record — spec §5.4.
    #[test]
    fn missing_authz_yaml_refuses_and_audits() {
        let _g = ENV_LOCK.lock().unwrap();
        std::env::remove_var("CREDENTIALS_DIRECTORY");
        let d = Dir::new("missing_authz");
        write_common_fixture(&d, "principal:\n  name: op\n  uid: 1000\n");
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
        let d = Dir::new("no_enrolled_gate");
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

    #[test]
    fn a_shadowed_principal_carrying_home_refuses_boot() {
        let _g = ENV_LOCK.lock().unwrap();
        std::env::remove_var("CREDENTIALS_DIRECTORY");
        let d = Dir::new("shadowed_home");
        write_common_fixture(
            &d,
            "principal:\n  name: op\n  uid: 1000\n  home: /home/op\n",
        );
        let cd = d.0.join("config.d");
        std::fs::create_dir(&cd).unwrap();
        std::fs::set_permissions(&cd, std::fs::Permissions::from_mode(0o750)).unwrap();
        put(
            &cd,
            "10-principal.yaml",
            "principal:\n  name: op\n  uid: 1000\n",
            0o640,
        );
        put(
            &d.0,
            "authz.yaml",
            "schema_version: 1\npermissions:\n  allow: []\n  deny: []\n",
            0o640,
        );

        match block_on_run_inner(&d.0) {
            Err(RunError::Authz(msg)) => assert_eq!(
                msg.to_string(),
                "maknae daemon refused to start: the authorization policy could not be loaded: \
                 unknown key 'home' in 'principal'"
            ),
            other => panic!("expected Err(RunError::Authz), got {other:?}"),
        }
    }

    #[test]
    fn a_partial_principal_shadowed_by_a_complete_member_still_boots() {
        let _g = ENV_LOCK.lock().unwrap();
        std::env::remove_var("CREDENTIALS_DIRECTORY");
        let d = Dir::new("shadowed_partial");
        write_common_fixture(&d, "principal: {}\n");
        let cd = d.0.join("config.d");
        std::fs::create_dir(&cd).unwrap();
        std::fs::set_permissions(&cd, std::fs::Permissions::from_mode(0o750)).unwrap();
        put(
            &cd,
            "10-principal.yaml",
            "principal:\n  name: alice\n  uid: 1000\n",
            0o640,
        );
        put(
            &d.0,
            "authz.yaml",
            "schema_version: 1\npermissions:\n  allow: []\n  deny: []\n",
            0o640,
        );

        let result = block_on_run_inner(&d.0);
        if let Err(RunError::Authz(msg)) = &result {
            assert!(
                !msg.to_string().contains("principal"),
                "a partial shadowed principal must not refuse boot: {msg}"
            );
        }
        if !nix::unistd::geteuid().is_root() {
            match result {
                Err(RunError::Authz(msg)) => assert!(msg
                    .to_string()
                    .contains("holding authz.yaml must be owned by root")),
                other => panic!("expected the authz.yaml directory refusal, got {other:?}"),
            }
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
        write_common_fixture(&d, "principal:\n  name: op\n  uid: 1000\n");
        put(
            &d.0,
            "authz.yaml",
            "schema_version: 1\npermissions:\n  allow:\n    - \"Read(~/**)\"\n",
            0o640,
        );
        put(
            &d.0,
            "bindings.yaml",
            "schema_version: 1\nbindings:\n  user: [\"no-such-user-maknae-496\"]\n",
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
            // ADR-0008 decision 1, fourth layer (#154): the trail records the
            // composition. Asserted on the real success path (root only --
            // run this on a test host, see the plan).
            let comp_rec = recs
                .iter()
                .find(|r| r.action == "authz" && r.outcome.result == "permit")
                .unwrap_or_else(|| panic!("no boot composition record in: {audit}"));
            assert_eq!(comp_rec.event, "boot");
            assert_eq!(
                comp_rec.outcome.reason,
                "authorization composition: maknae-authz-basic+maknae-ceiling; system: US; ceiling: UNCLASSIFIED"
            );
            assert_eq!(comp_rec.outcome.posture, "authorized");
            assert_eq!(comp_rec.policy_sha256.as_ref().map(String::len), Some(64));
            // #488/#489: the first boot seeds the graph store before the PDP is
            // built from it, so before the composition record; intent before
            // checkpoint.
            let at = |action: &str| {
                recs.iter()
                    .position(|r| r.action == action)
                    .unwrap_or_else(|| panic!("no {action} record in: {audit}"))
            };
            let (seed, ckpt) = (at("graph.seed"), at("graph.checkpoint"));
            assert!(seed < ckpt && ckpt < at("authz") && at("authz") < at("posture"));
            let identity = at("graph.identity");
            assert_eq!(
                identity,
                at("authz") + 1,
                "#496: after the composition record"
            );
            assert!(identity < at("posture"));
            assert_eq!(
                (
                    recs[identity].event.as_str(),
                    recs[identity].outcome.result.as_str(),
                    recs[identity].outcome.reason.as_str()
                ),
                (
                    "boot",
                    "deny",
                    "'no-such-user-maknae-496' under user has no account on this host; it holds no role"
                )
            );
            assert_eq!(recs[seed].outcome.posture, "authorized");
            assert_eq!(recs[seed].graph.as_ref().unwrap().revision, 1);
            let g = recs[ckpt].graph.as_ref().unwrap();
            assert_eq!((g.revision, g.anchor.as_str()), (1, "seeded"));
            assert_eq!(g.ciphertext_sha256.len(), 64);
            // Both boot records share the boot session; they must NOT share a
            // sequence number (the collision the review found).
            assert_eq!(comp_rec.session_id, posture_rec.session_id);
            assert_ne!(
                comp_rec.seq, posture_rec.seq,
                "boot records collided on seq"
            );
            // #265 A2: the later failure is itself on the trail, last.
            let start = recs.last().unwrap();
            assert_eq!(
                (
                    start.event.as_str(),
                    start.action.as_str(),
                    start.outcome.result.as_str()
                ),
                ("boot", "start", "deny")
            );
            let Err(RunError::Other(reason)) = &result else {
                unreachable!()
            };
            assert_eq!(&start.outcome.reason, reason);
            assert_eq!(start.session_id, posture_rec.session_id);
            assert!(start.seq > posture_rec.seq);
        } else {
            // Unprivileged: the policy directory's ownership check refuses first.
            match &result {
                Err(RunError::Authz(msg)) => assert!(
                    msg.contains("holding authz.yaml must be owned by root"),
                    "expected the directory refusal, got: {msg}"
                ),
                other => panic!("expected Err(RunError::Authz), got {other:?}"),
            }
        }
    }

    // #488, root-gated like the test above: a store that does not decrypt refuses
    // boot with exit 5, and the one refusal record is `graph.load`.
    #[test]
    fn a_corrupt_graph_store_refuses_boot_with_a_graph_load_record() {
        let _g = ENV_LOCK.lock().unwrap();
        std::env::remove_var("CREDENTIALS_DIRECTORY");
        let d = Dir::new("corrupt_graph");
        write_common_fixture(&d, "principal:\n  name: op\n  uid: 1000\n");
        put(
            &d.0,
            "authz.yaml",
            "schema_version: 1\npermissions:\n  allow:\n    - \"Read(~/**)\"\n",
            0o640,
        );
        put(&state_dir(&d.0), "kernel.graph", "not an envelope", 0o600);
        put(&d.0, "audit.jsonl", "", 0o640);

        let result = block_on_run_inner(&d.0);

        if nix::unistd::geteuid().as_raw() != 0 {
            assert!(matches!(result, Err(RunError::Authz(_))), "{result:?}");
            return;
        }
        let Err(e @ RunError::Graph { .. }) = &result else {
            panic!("expected Err(RunError::Graph), got {result:?}");
        };
        assert_eq!(refusal_exit_code(e), 5);
        let audit = std::fs::read_to_string(d.0.join("audit.jsonl")).unwrap();
        let recs: Vec<AuditRecord> = audit
            .lines()
            .map(|l| serde_json::from_str(l).unwrap())
            .collect();
        let last = recs.last().unwrap();
        assert_eq!(
            (last.action.as_str(), last.outcome.result.as_str()),
            ("graph.load", "deny")
        );
        assert_eq!(last.outcome.reason, e.to_string());
        assert!(!recs
            .iter()
            .any(|r| r.action == "start" || r.action == "posture" || r.action == "authz"));
    }

    #[test]
    fn an_upgrade_without_the_pasted_block_refuses_boot_with_the_authz_record() {
        let _g = ENV_LOCK.lock().unwrap();
        std::env::remove_var("CREDENTIALS_DIRECTORY");
        let d = Dir::new("not_moved");
        write_common_fixture(&d, "principal:\n  name: op\n  uid: 1000\n");
        put(&d.0, "authz.yaml", "schema_version: 1\n", 0o640);
        put(&d.0, "bindings.yaml", "schema_version: 1\n", 0o640);
        let vocabulary = crate::vocabulary::kernel_vocabulary("UNCLASSIFIED").unwrap();
        let old = maknae_graph::identity::build(
            &maknae_graph::identity::IdentityLayer {
                aliases: Default::default(),
                source: d.0.join("authz.yaml").to_str().unwrap().to_string(),
                label: "UNCLASSIFIED".into(),
                bindings_sha256: Some([1; 32]),
                subjects: vec![maknae_graph::identity::SubjectEntry {
                    uid: 4242,
                    name: "mallory".into(),
                    role: "adversary".into(),
                }],
            },
            None,
            &vocabulary.persisted,
            vocabulary.digest,
            1,
            maknae_graph::record::ProvenanceKind::Seed,
        )
        .unwrap();
        let k = WrappingKey::new(test_graph_key(&d.0).unwrap().into_bytes());
        let sealed = maknae_state::envelope::seal(&maknae_graph::format::encode(&old), &k).unwrap();
        put(&state_dir(&d.0), STORE_FILE, "", 0o600);
        std::fs::write(state_dir(&d.0).join(STORE_FILE), &sealed).unwrap();

        let result = block_on_run_inner(&d.0);

        if nix::unistd::geteuid().as_raw() != 0 {
            match &result {
                Err(RunError::Authz(msg)) => assert!(
                    msg.contains("holding authz.yaml must be owned by root"),
                    "root-only: off root the policy read refuses first, got: {msg}"
                ),
                other => panic!("expected Err(RunError::Authz), got {other:?}"),
            }
            return;
        }
        let Err(e @ RunError::Authz(msg)) = &result else {
            panic!("expected Err(RunError::Authz), got {result:?}");
        };
        assert_eq!(refusal_exit_code(e), 3);
        assert!(
            msg.ends_with(maknae_graph::identity::BINDINGS_NOT_MOVED),
            "{msg}"
        );
        assert_eq!(
            std::fs::read(state_dir(&d.0).join(STORE_FILE)).unwrap(),
            sealed
        );
        let recs: Vec<AuditRecord> = std::fs::read_to_string(d.0.join("audit.jsonl"))
            .unwrap()
            .lines()
            .map(|l| serde_json::from_str(l).unwrap())
            .collect();
        let last = recs.last().unwrap();
        assert_eq!(
            (
                last.action.as_str(),
                last.outcome.result.as_str(),
                last.outcome.reason.as_str()
            ),
            ("authz", "deny", maknae_graph::identity::BINDINGS_NOT_MOVED)
        );
        assert!(!recs.iter().any(|r| r.action.starts_with("graph.")));
    }

    // ---- #488: the graph boot step over a real audit sink and a real state
    // directory, unprivileged ----

    struct GraphFixture {
        dir: Dir,
        state: PathBuf,
        sink: Arc<maknae_audit_append::AuditSink>,
    }

    fn graph_fixture(tag: &str) -> GraphFixture {
        let dir = Dir::new(tag);
        let state = state_dir(&dir.0);
        let sink = Arc::new(
            maknae_audit_append::AuditSink::open(&maknae_config::AuditConfig {
                readers: Vec::new(),
                jsonl_path: dir.0.join("audit.jsonl"),
                siem: None,
                au3_1: serde_json::Value::Null,
            })
            .unwrap(),
        );
        GraphFixture { dir, state, sink }
    }

    fn boot_graph(
        fx: &GraphFixture,
        key: Result<maknae_vault::GraphKey, maknae_vault::VaultError>,
    ) -> Result<KernelGraphStatus, RunError> {
        boot_graph_held(fx, key).map(|(_, status)| status)
    }

    fn boot_graph_held(
        fx: &GraphFixture,
        key: Result<maknae_vault::GraphKey, maknae_vault::VaultError>,
    ) -> Result<(StateDir, KernelGraphStatus), RunError> {
        boot_graph_from(fx, key, &fx.dir.0)
    }

    /// The identity layer of a `bindings.yaml` with no `bindings:` key, at `config_dir`.
    fn bare_inputs(config_dir: &Path) -> GraphInputs {
        let source = maknae_authz_basic::PolicySource::from_parts(
            maknae_config::parse_authz("schema_version: 1\n").unwrap(),
            maknae_config::parse_bindings("schema_version: 1\n").unwrap(),
            Default::default(),
            maknae_config::Principal {
                name: "op".into(),
                uid: 1000,
            },
            maknae_authz_basic::PolicyPaths::in_dir(config_dir),
        )
        .unwrap();
        GraphInputs::new(&source, "UNCLASSIFIED", test_baseline()).unwrap()
    }

    fn boot_graph_from(
        fx: &GraphFixture,
        key: Result<maknae_vault::GraphKey, maknae_vault::VaultError>,
        config_dir: &Path,
    ) -> Result<(StateDir, KernelGraphStatus), RunError> {
        let seq = Seq::new();
        let au3_1 = serde_json::Value::Null;
        let ctx = BootCtx {
            event: "boot",
            host: "h",
            socket: "s",
            euid: nix::unistd::geteuid().as_raw(),
            session_id: 9 << 32,
            seq: &seq,
            au3_1: &au3_1,
        };
        let inputs = bare_inputs(config_dir);
        block_on(boot_graph_at(
            &fx.state,
            key,
            &fx.sink,
            &ctx,
            &inputs.boot(),
        ))
        .map(|b| (b.dir, b.status))
    }

    fn trail(fx: &GraphFixture) -> Vec<(AuditRecord, String)> {
        std::fs::read_to_string(fx.dir.0.join("audit.jsonl"))
            .unwrap()
            .lines()
            .map(|l| (serde_json::from_str(l).unwrap(), l.to_string()))
            .collect()
    }

    fn key() -> Result<maknae_vault::GraphKey, maknae_vault::VaultError> {
        test_graph_key(Path::new("/unused"))
    }

    /// The store seeds the identity layer the policy file declares, and the PDP
    /// compiles over the graph the store booted.
    #[test]
    fn the_graph_boots_the_policys_identity_layer_and_the_pdp_compiles_over_it() {
        use maknae_security::Authorizer;
        let fx = graph_fixture("graph_real_layer");
        let source = maknae_authz_basic::PolicySource::from_parts(
            maknae_config::parse_authz("schema_version: 1\n").unwrap(),
            maknae_config::parse_bindings(
                "schema_version: 1\nbindings:\n  adversary: [\"root\"]\n",
            )
            .unwrap(),
            [("root".to_string(), 0)].into_iter().collect(),
            maknae_config::Principal {
                name: "op".into(),
                uid: 1000,
            },
            maknae_authz_basic::PolicyPaths::in_dir(&fx.dir.0),
        )
        .unwrap();
        let inputs = GraphInputs::new(&source, "UNCLASSIFIED", test_baseline()).unwrap();
        assert!(inputs.identity.bindings_sha256.is_some());
        let seq = Seq::new();
        let au3_1 = serde_json::Value::Null;
        let ctx = BootCtx {
            event: "boot",
            host: "h",
            socket: "s",
            euid: nix::unistd::geteuid().as_raw(),
            session_id: 9 << 32,
            seq: &seq,
            au3_1: &au3_1,
        };
        let BootedGraph {
            dir: _held,
            status,
            graph,
            ..
        } = block_on(boot_graph_at(
            &fx.state,
            key(),
            &fx.sink,
            &ctx,
            &inputs.boot(),
        ))
        .unwrap();
        assert_eq!(status.revision(), 1);
        let stored = maknae_graph::identity::extract(&graph).unwrap();
        assert_eq!(stored.layer, inputs.identity);
        assert_eq!(stored.layer.subjects.len(), 1);
        let pdp = authz_boot_gate(source, Arc::new(graph), &inputs.vocabulary.full).unwrap();
        let req = crate::handler::build_authz_request(
            &maknae_proto::Verb::Whoami,
            0,
            None,
            maknae_security::Lane::Local,
            None,
        );
        assert_eq!(
            pdp.decide(&req),
            maknae_security::Verdict::Deny {
                reason: "subject contained: role=adversary".into()
            }
        );
    }

    fn bound_source(config_dir: &Path, bindings: &str) -> maknae_authz_basic::PolicySource {
        maknae_authz_basic::PolicySource::from_parts(
            maknae_config::parse_authz(
                "schema_version: 1\npermissions:\n  allow: []\n  deny: []\n",
            )
            .unwrap(),
            maknae_config::parse_bindings(bindings).unwrap(),
            [("root".to_string(), 0), ("seven".to_string(), 7)]
                .into_iter()
                .collect(),
            maknae_config::Principal {
                name: "op".into(),
                uid: 1000,
            },
            maknae_authz_basic::PolicyPaths::in_dir(config_dir),
        )
        .unwrap()
    }

    /// Boots the store under `source`'s identity layer, then compiles the PDP
    /// over the graph the store booted and composes it with the US ceiling.
    fn boot_and_compose(
        fx: &GraphFixture,
        source: maknae_authz_basic::PolicySource,
    ) -> (
        KernelGraphStatus,
        crate::composition::Composition<maknae_authz_basic::BasicAuthorizer>,
    ) {
        let inputs = GraphInputs::new(&source, "UNCLASSIFIED", test_baseline()).unwrap();
        let seq = Seq::new();
        let au3_1 = serde_json::Value::Null;
        let ctx = BootCtx {
            event: "boot",
            host: "h",
            socket: "s",
            euid: nix::unistd::geteuid().as_raw(),
            session_id: 9 << 32,
            seq: &seq,
            au3_1: &au3_1,
        };
        let BootedGraph {
            dir: _held,
            status,
            graph,
            ..
        } = block_on(boot_graph_at(
            &fx.state,
            key(),
            &fx.sink,
            &ctx,
            &inputs.boot(),
        ))
        .unwrap();
        let baseline = authz_boot_gate(source, Arc::new(graph), &inputs.vocabulary.full).unwrap();
        let us = &maknae_config::BasicPolicy;
        let pdp = crate::composition::Composition::new(
            baseline,
            crate::ceiling_authz::CeilingAuthorizer::new(
                maknae_config::Ceiling::baseline_for(us),
                us,
            ),
        );
        (status, pdp)
    }

    fn decide_as_root(
        pdp: &impl maknae_security::Authorizer,
        verb: maknae_proto::Verb,
    ) -> maknae_security::Verdict {
        pdp.decide(&crate::handler::build_authz_request(
            &verb,
            0,
            None,
            maknae_security::Lane::Local,
            None,
        ))
    }

    /// A store written before #489 (empty graph, no vocabulary digest) migrates, then takes the
    /// file's bindings as an identity transition, and the PDP compiles over the
    /// result.
    #[test]
    fn a_store_from_before_identity_with_a_bindings_file_migrates_and_the_pdp_compiles_over_it() {
        let fx = graph_fixture("graph_pre_identity_bound");
        let k = WrappingKey::new(key().unwrap().into_bytes());
        let old =
            maknae_graph::graph::GraphBuilder::new(maknae_graph::record::GraphSpace::Kernel, 4)
                .build(
                    &maknae_graph::kernel::SCHEMA,
                    &maknae_graph::schema::CompiledSet::default(),
                )
                .unwrap();
        let file = maknae_state::envelope::seal(&maknae_graph::format::encode(&old), &k).unwrap();
        let path = fx.state.join(STORE_FILE);
        std::fs::write(&path, file).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();

        let source = bound_source(
            &fx.dir.0,
            "schema_version: 1\nbindings:\n  admin: [\"root\"]\n  adversary: [\"seven\"]\n",
        );
        let (status, pdp) = boot_and_compose(&fx, source);
        assert_eq!(status.revision(), 6);
        let actions: Vec<String> = trail(&fx).into_iter().map(|(r, _)| r.action).collect();
        assert_eq!(
            actions,
            [
                "graph.checkpoint",
                "graph.migrate",
                "graph.checkpoint",
                "graph.baseline",
                "graph.transition",
                "graph.checkpoint"
            ]
        );
        assert!(matches!(
            decide_as_root(&pdp, maknae_proto::Verb::Whoami),
            maknae_security::Verdict::Permit { .. }
        ));
        let contained = crate::handler::build_authz_request(
            &maknae_proto::Verb::Ping,
            7,
            None,
            maknae_security::Lane::Local,
            None,
        );
        assert_eq!(
            maknae_security::Authorizer::decide(&pdp, &contained),
            maknae_security::Verdict::Deny {
                reason: "subject contained: role=adversary".into()
            }
        );
    }

    /// A rebinding between boots is a root-file identity transition, and the PDP
    /// compiles over the transitioned graph: the rebound uid is contained.
    #[test]
    fn a_rebinding_between_boots_transitions_and_the_pdp_compiles_over_it() {
        let fx = graph_fixture("graph_rebind");
        let admin = "schema_version: 1\nbindings:\n  admin: [\"root\"]\n";
        let (first, pdp) = boot_and_compose(&fx, bound_source(&fx.dir.0, admin));
        assert_eq!(first.revision(), 1);
        assert!(matches!(
            decide_as_root(&pdp, maknae_proto::Verb::Ping),
            maknae_security::Verdict::Permit { .. }
        ));
        drop(pdp);
        let (second, pdp) = boot_and_compose(
            &fx,
            bound_source(&fx.dir.0, &admin.replace("admin: [", "adversary: [")),
        );
        assert_eq!((second.revision(), second.anchor.as_str()), (2, "verified"));
        assert!(trail(&fx)
            .iter()
            .any(|(r, _)| r.action == "graph.transition"));
        assert_eq!(
            decide_as_root(&pdp, maknae_proto::Verb::Ping),
            maknae_security::Verdict::Deny {
                reason: "subject contained: role=adversary".into()
            }
        );
    }

    #[test]
    fn a_store_from_before_identity_migrates_under_an_audited_intent() {
        let fx = graph_fixture("graph_pre_identity_migrate");
        let k = WrappingKey::new(key().unwrap().into_bytes());
        let old =
            maknae_graph::graph::GraphBuilder::new(maknae_graph::record::GraphSpace::Kernel, 4)
                .build(
                    &maknae_graph::kernel::SCHEMA,
                    &maknae_graph::schema::CompiledSet::default(),
                )
                .unwrap();
        let file = maknae_state::envelope::seal(&maknae_graph::format::encode(&old), &k).unwrap();
        let path = fx.state.join(STORE_FILE);
        std::fs::write(&path, file).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();

        let status = boot_graph(&fx, key()).unwrap();
        assert_eq!(
            (status.revision(), status.anchor.as_str()),
            (6, "rollback-anchor-unavailable")
        );
        let recs = trail(&fx);
        let actions: Vec<&str> = recs.iter().map(|(r, _)| r.action.as_str()).collect();
        assert_eq!(
            actions,
            [
                "graph.checkpoint",
                "graph.migrate",
                "graph.checkpoint",
                "graph.baseline",
                "graph.transition",
                "graph.checkpoint"
            ]
        );
        let to = bare_inputs(&fx.dir.0).vocabulary.digest;
        let (m, _) = &recs[1];
        assert_eq!(
            (
                m.outcome.result.as_str(),
                m.outcome.reason.clone(),
                m.outcome.posture.as_str()
            ),
            (
                "permit",
                format!(
                    "intent recorded (vocabulary none -> {}; unbound: [])",
                    lower_hex(&to)
                ),
                "authorized"
            )
        );
        let g = m.graph.as_ref().unwrap();
        assert_eq!(
            (g.revision, g.anchor.as_str(), g.ciphertext_sha256.as_str()),
            (5, "migrating", "")
        );
        assert_eq!(recs[2].0.graph.as_ref().unwrap().anchor, "migrated");
    }

    #[test]
    fn a_changed_policy_source_is_a_root_file_transition_under_an_audited_intent() {
        let fx = graph_fixture("graph_transition");
        boot_graph_from(&fx, key(), Path::new("/elsewhere")).unwrap();
        let (_held, status) = boot_graph_held(&fx, key()).unwrap();
        assert_eq!((status.revision(), status.anchor.as_str()), (2, "verified"));
        let recs = trail(&fx);
        let actions: Vec<&str> = recs.iter().map(|(r, _)| r.action.as_str()).collect();
        assert_eq!(
            actions,
            [
                "graph.seed",
                "graph.baseline",
                "graph.checkpoint",
                "graph.checkpoint",
                "graph.transition",
                "graph.checkpoint"
            ]
        );
        let (t, _) = &recs[4];
        assert_eq!(
            (t.outcome.result.as_str(), t.outcome.reason.as_str()),
            ("permit", "intent recorded (root-file)")
        );
        let g = t.graph.as_ref().unwrap();
        assert_eq!((g.revision, g.anchor.as_str()), (2, "transitioning"));
        assert_eq!(recs[5].0.graph.as_ref().unwrap().anchor, "transitioned");
    }

    #[test]
    fn a_store_whose_identity_came_from_authz_yaml_moves_to_bindings_yaml_in_one_transition() {
        let fx = graph_fixture("graph_moved_source");
        let paths = maknae_authz_basic::PolicyPaths::in_dir(&fx.dir.0);
        let source = maknae_authz_basic::PolicySource::from_parts(
            maknae_config::parse_authz("schema_version: 1\n").unwrap(),
            maknae_config::parse_bindings(
                "schema_version: 1\nbindings:\n  adversary: [\"root\"]\n",
            )
            .unwrap(),
            [("root".to_string(), 0)].into_iter().collect(),
            maknae_config::Principal {
                name: "op".into(),
                uid: 1000,
            },
            paths.clone(),
        )
        .unwrap();
        let inputs = GraphInputs::new(&source, "UNCLASSIFIED", test_baseline()).unwrap();
        let old = maknae_graph::identity::IdentityLayer {
            aliases: Default::default(),
            source: paths.authz.to_str().unwrap().to_string(),
            label: "UNCLASSIFIED".into(),
            bindings_sha256: inputs.identity.bindings_sha256,
            subjects: vec![maknae_graph::identity::SubjectEntry {
                uid: 0,
                name: "root".into(),
                role: "adversary".into(),
            }],
        };
        assert!(old.bindings_sha256.is_some());
        assert_ne!(old.source, inputs.identity.source);
        let seq = Seq::new();
        let au3_1 = serde_json::Value::Null;
        let ctx = BootCtx {
            event: "boot",
            host: "h",
            socket: "s",
            euid: nix::unistd::geteuid().as_raw(),
            session_id: 9 << 32,
            seq: &seq,
            au3_1: &au3_1,
        };
        let boot = |identity: &maknae_graph::identity::IdentityLayer| {
            block_on(boot_graph_at(
                &fx.state,
                key(),
                &fx.sink,
                &ctx,
                &BootInputs {
                    identity,
                    ..inputs.boot()
                },
            ))
            .unwrap()
        };
        let first = boot(&old);
        assert_eq!(first.status.revision(), 1);
        drop(first);
        let seeded = trail(&fx).len();
        let second = boot(&inputs.identity);
        assert_eq!(
            (second.status.revision(), second.status.anchor.as_str()),
            (2, "verified")
        );
        let recs = trail(&fx);
        let after: Vec<(&str, &str)> = recs[seeded..]
            .iter()
            .map(|(r, _)| {
                (
                    r.action.as_str(),
                    r.graph.as_ref().map_or("", |g| g.anchor.as_str()),
                )
            })
            .collect();
        assert_eq!(
            after,
            [
                ("graph.checkpoint", "verified"),
                ("graph.transition", "transitioning"),
                ("graph.checkpoint", "transitioned")
            ]
        );
        assert_eq!(
            recs[seeded + 1].0.outcome.reason,
            "intent recorded (root-file)"
        );
        assert!(!recs.iter().any(|(r, _)| r.action == "graph.migrate"));
        let stored = maknae_graph::identity::extract(&second.graph).unwrap();
        assert_eq!(stored.layer.source, paths.bindings.to_str().unwrap());
        assert_eq!(stored.layer.subjects, old.subjects);
    }

    /// Boots `seed` into a fresh store, then boots `inputs` over it.
    fn boot_over_seed(
        fx: &GraphFixture,
        inputs: &GraphInputs,
        seed: &maknae_graph::identity::IdentityLayer,
    ) -> (usize, Result<BootedGraph, RunError>) {
        let seq = Seq::new();
        let au3_1 = serde_json::Value::Null;
        let ctx = BootCtx {
            event: "boot",
            host: "h",
            socket: "s",
            euid: nix::unistd::geteuid().as_raw(),
            session_id: 9 << 32,
            seq: &seq,
            au3_1: &au3_1,
        };
        drop(
            block_on(boot_graph_at(
                &fx.state,
                key(),
                &fx.sink,
                &ctx,
                &BootInputs {
                    identity: seed,
                    ..inputs.boot()
                },
            ))
            .unwrap(),
        );
        let seeded = trail(fx).len();
        let booted = block_on(boot_graph_at(
            &fx.state,
            key(),
            &fx.sink,
            &ctx,
            &inputs.boot(),
        ));
        (seeded, booted)
    }

    fn explicit(
        inputs: &GraphInputs,
        source: &Path,
        subjects: &[(u32, &str)],
    ) -> maknae_graph::identity::IdentityLayer {
        maknae_graph::identity::IdentityLayer {
            source: source.to_str().unwrap().to_string(),
            bindings_sha256: Some([1; 32]),
            subjects: subjects
                .iter()
                .map(|(uid, name)| maknae_graph::identity::SubjectEntry {
                    uid: *uid,
                    name: (*name).into(),
                    role: "adversary".into(),
                })
                .collect(),
            ..inputs.identity.clone()
        }
    }

    #[test]
    fn a_keyless_boot_records_each_released_containment() {
        let fx = graph_fixture("graph_keyless_release");
        let paths = maknae_authz_basic::PolicyPaths::in_dir(&fx.dir.0);
        let inputs = bare_inputs(&fx.dir.0);
        let seed = explicit(&inputs, &paths.bindings, &[(0, "root"), (7, "seven")]);
        let (seeded, booted) = boot_over_seed(&fx, &inputs, &seed);
        let booted = booted.unwrap();
        assert_eq!(booted.released.len(), 2);
        let after: Vec<(String, String, String, String)> = trail(&fx)[seeded..]
            .iter()
            .map(|(r, _)| {
                (
                    r.action.clone(),
                    r.outcome.result.clone(),
                    r.outcome.posture.clone(),
                    r.outcome.reason.clone(),
                )
            })
            .collect();
        let why = "bindings.yaml has no bindings: key, so the enrolled principal is admin and nobody else holds a role";
        assert_eq!(
            after[..3],
            [
                (
                    "graph.checkpoint".to_string(),
                    "permit".to_string(),
                    "authorized".to_string(),
                    "verified".to_string()
                ),
                (
                    "graph.identity".to_string(),
                    "permit".to_string(),
                    "authorized".to_string(),
                    format!("uid 0 ('root') is no longer contained: {why}")
                ),
                (
                    "graph.identity".to_string(),
                    "permit".to_string(),
                    "authorized".to_string(),
                    format!("uid 7 ('seven') is no longer contained: {why}")
                ),
            ]
        );
        assert_eq!(after[3].3, PRINCIPAL_ADMIN_1000);
        assert_eq!(after[4].0, "graph.transition");
        assert_eq!(after.len(), 6);
        for (r, _) in &trail(&fx)[seeded + 1..seeded + 3] {
            let g = r.graph.as_ref().unwrap();
            assert_eq!((g.revision, g.anchor.as_str()), (2, "releasing"));
        }
        let g = trail(&fx)[seeded + 3].0.graph.clone().unwrap();
        assert_eq!((g.revision, g.anchor.as_str()), (2, "promoting"));
        assert_eq!(booted.principal_admin, Some(1000));
        let stored = maknae_graph::identity::extract(&booted.graph).unwrap();
        assert!(stored.layer.subjects.is_empty());
    }

    #[test]
    fn a_boot_that_releases_nothing_writes_no_release_record() {
        let fx = graph_fixture("graph_no_release");
        let inputs = bare_inputs(&fx.dir.0);
        boot_graph(&fx, key()).unwrap();
        boot_graph(&fx, key()).unwrap();
        assert!(!trail(&fx).iter().any(|(r, _)| r.action == "graph.identity"));
        let paths = maknae_authz_basic::PolicyPaths::in_dir(&fx.dir.0);
        let fx = graph_fixture("graph_no_release_bound");
        let bound = maknae_graph::identity::IdentityLayer {
            subjects: vec![maknae_graph::identity::SubjectEntry {
                uid: 7,
                name: "seven".into(),
                role: "user".into(),
            }],
            ..explicit(&inputs, &paths.bindings, &[])
        };
        let (seeded, booted) = boot_over_seed(&fx, &inputs, &bound);
        let booted = booted.unwrap();
        assert!(booted.released.is_empty());
        assert_eq!(booted.principal_admin, Some(1000));
        let after: Vec<(String, String, String, String)> = trail(&fx)[seeded..]
            .iter()
            .map(|(r, _)| {
                (
                    r.action.clone(),
                    r.outcome.result.clone(),
                    r.outcome.posture.clone(),
                    r.graph
                        .as_ref()
                        .map_or_else(String::new, |g| g.anchor.clone()),
                )
            })
            .collect();
        assert_eq!(
            after[1..3],
            [
                (
                    "graph.identity".to_string(),
                    "permit".to_string(),
                    "authorized".to_string(),
                    "promoting".to_string()
                ),
                (
                    "graph.transition".to_string(),
                    "permit".to_string(),
                    "authorized".to_string(),
                    "transitioning".to_string()
                ),
            ],
            "explicit bindings ending is recorded ahead of the transition"
        );
        assert_eq!(
            trail(&fx)[seeded + 1].0.outcome.reason,
            PRINCIPAL_ADMIN_1000
        );
    }

    const PRINCIPAL_ADMIN_1000: &str =
        "uid 1000, the enrolled principal, now holds admin: bindings.yaml has no bindings: key";

    #[test]
    fn an_upgrade_without_the_pasted_block_exits_3() {
        let fx = graph_fixture("graph_not_moved");
        let paths = maknae_authz_basic::PolicyPaths::in_dir(&fx.dir.0);
        let inputs = bare_inputs(&fx.dir.0);
        let seed = explicit(&inputs, &paths.authz, &[(0, "root")]);
        let store = || std::fs::read(fx.state.join(STORE_FILE)).unwrap();
        let (seeded, booted) = boot_over_seed(&fx, &inputs, &seed);
        let Err(e) = booted else {
            panic!("the upgrade without the block booted");
        };
        assert_eq!(refusal_exit_code(&e), 3);
        assert!(
            matches!(&e, RunError::Authz(m) if m == maknae_graph::identity::BINDINGS_NOT_MOVED),
            "{e:?}"
        );
        assert_eq!(trail(&fx).len(), seeded, "nothing recorded");
        let before = store();
        let pasted = maknae_graph::identity::IdentityLayer {
            source: inputs.identity.source.clone(),
            ..seed.clone()
        };
        let booted = block_on(boot_graph_at(
            &fx.state,
            key(),
            &fx.sink,
            &BootCtx {
                event: "boot",
                host: "h",
                socket: "s",
                euid: nix::unistd::geteuid().as_raw(),
                session_id: 9 << 32,
                seq: &Seq::new(),
                au3_1: &serde_json::Value::Null,
            },
            &BootInputs {
                identity: &pasted,
                ..inputs.boot()
            },
        ))
        .unwrap();
        assert!(booted.released.is_empty());
        assert_ne!(store(), before);
        let stored = maknae_graph::identity::extract(&booted.graph).unwrap();
        assert_eq!(stored.layer.subjects, seed.subjects, "still contained");
        assert!(!trail(&fx).iter().any(|(r, _)| r.action == "graph.identity"));
    }

    #[test]
    fn a_missing_bindings_file_over_explicit_bindings_exits_3() {
        let fx = graph_fixture("graph_bindings_missing");
        let paths = maknae_authz_basic::PolicyPaths::in_dir(&fx.dir.0);
        let source = maknae_authz_basic::PolicySource::from_parts(
            maknae_config::parse_authz("schema_version: 1\n").unwrap(),
            maknae_config::Bindings::missing(),
            Default::default(),
            maknae_config::Principal {
                name: "op".into(),
                uid: 1000,
            },
            paths.clone(),
        )
        .unwrap();
        let inputs = GraphInputs::new(&source, "UNCLASSIFIED", test_baseline()).unwrap();
        assert!(inputs.bindings_missing);
        let seed = explicit(&inputs, &paths.bindings, &[]);
        let (seeded, booted) = boot_over_seed(&fx, &inputs, &seed);
        let Err(e) = booted else {
            panic!("a missing file over explicit bindings booted");
        };
        assert_eq!(refusal_exit_code(&e), 3);
        assert!(
            matches!(&e, RunError::Authz(m) if m == maknae_graph::identity::BINDINGS_MISSING),
            "{e:?}"
        );
        assert_eq!(trail(&fx).len(), seeded);
    }

    #[test]
    fn first_boot_seeds_then_checkpoints_and_a_restart_verifies() {
        let fx = graph_fixture("graph_first_boot");
        let status = boot_graph(&fx, key()).unwrap();
        assert_eq!((status.revision(), status.anchor.as_str()), (1, "seeded"));

        let recs = trail(&fx);
        let actions: Vec<&str> = recs.iter().map(|(r, _)| r.action.as_str()).collect();
        assert_eq!(
            actions,
            ["graph.seed", "graph.baseline", "graph.checkpoint"]
        );
        let (seed, _) = &recs[0];
        assert_eq!(
            (
                seed.event.as_str(),
                seed.outcome.result.as_str(),
                seed.outcome.reason.as_str(),
                seed.outcome.posture.as_str()
            ),
            (
                "boot",
                "permit",
                "intent recorded (first-boot)",
                "authorized"
            )
        );
        assert_eq!(
            seed.graph,
            Some(GraphAudit {
                revision: 1,
                ciphertext_sha256: String::new(),
                anchor: "seeding".into(),
                scanned_bytes: 0,
            })
        );
        let (baseline, _) = &recs[1];
        assert_eq!(
            (
                baseline.outcome.result.as_str(),
                baseline.outcome.reason.as_str(),
                baseline.outcome.posture.as_str()
            ),
            ("permit", crate::baseline::SEEDED_EVENT, "authorized")
        );
        assert_eq!(
            baseline.graph,
            Some(GraphAudit {
                revision: 1,
                ciphertext_sha256: String::new(),
                anchor: "baselining".into(),
                scanned_bytes: 0,
            })
        );
        let (ckpt, line) = &recs[2];
        assert_eq!(
            (ckpt.outcome.result.as_str(), ckpt.outcome.reason.as_str()),
            ("permit", "seeded")
        );
        let g = ckpt.graph.as_ref().unwrap();
        assert_eq!((g.revision, g.anchor.as_str()), (1, "seeded"));
        let parsed = parse_checkpoint(line.as_bytes()).expect("the checkpoint parses");
        assert_eq!(lower_hex(&parsed.digest), g.ciphertext_sha256);
        assert_ne!(seed.seq, ckpt.seq);

        let status = boot_graph(&fx, key()).unwrap();
        assert_eq!((status.revision(), status.anchor.as_str()), (1, "verified"));
        let recs = trail(&fx);
        assert_eq!(recs.len(), 4);
        let g = recs[3].0.graph.as_ref().unwrap();
        assert_eq!((g.revision, g.anchor.as_str()), (1, "verified"));
        assert_eq!(
            g.ciphertext_sha256,
            recs[2].0.graph.as_ref().unwrap().ciphertext_sha256
        );
        assert!(g.scanned_bytes > 0, "the restart scanned the trail");
    }

    #[test]
    fn a_second_boot_while_the_first_holds_the_state_dir_refuses_with_exit_5() {
        let fx = graph_fixture("graph_in_use");
        let (_held, status) = boot_graph_held(&fx, key()).unwrap();
        assert_eq!(status.revision(), 1);
        let result = boot_graph(&fx, key()).map(|_| ServeOutcome::GracefulShutdown);
        let Err(e @ RunError::Graph { reason, hint }) = &result else {
            panic!("expected Err(RunError::Graph), got {result:?}");
        };
        assert_eq!(
            reason,
            "kernel graph store: another maknaed holds the kernel graph state directory"
        );
        assert_eq!(
            hint,
            &format!(
                "another maknaed is already running against {}; stop it before starting this one",
                fx.state.display()
            )
        );
        assert_eq!(refusal_exit_code(e), GRAPH_REFUSAL_EXIT_CODE);
        assert_eq!(trail(&fx).len(), 3, "the refused boot appended nothing");
    }

    #[test]
    fn a_corrupt_store_refuses_with_the_reseed_hint_and_records_graph_load() {
        let fx = graph_fixture("graph_corrupt");
        put(&fx.state, "kernel.graph", "not an envelope", 0o600);
        let result = boot_graph(&fx, key()).map(|_| ServeOutcome::GracefulShutdown);
        let Err(e @ RunError::Graph { hint, .. }) = &result else {
            panic!("expected Err(RunError::Graph), got {result:?}");
        };
        assert!(hint.contains("sudo maknae reseed"), "{hint}");
        assert_eq!(refusal_exit_code(e), GRAPH_REFUSAL_EXIT_CODE);
        assert!(trail(&fx).is_empty(), "nothing was seeded or checkpointed");

        block_on(record_start_refusal(
            fx.sink.as_ref(),
            "h",
            "s",
            0,
            9 << 32,
            1,
            &serde_json::Value::Null,
            &result,
        ));
        let recs = trail(&fx);
        assert_eq!(recs.len(), 1);
        assert_eq!(
            (recs[0].0.action.as_str(), recs[0].0.outcome.result.as_str()),
            ("graph.load", "deny")
        );
        assert_eq!(recs[0].0.outcome.reason, e.to_string());
        assert!(e.to_string().starts_with("kernel graph store: "), "{e}");
    }

    #[test]
    fn a_missing_key_refuses_naming_enroll_before_touching_the_store() {
        let fx = graph_fixture("graph_no_key");
        let result = boot_graph(
            &fx,
            Err(maknae_vault::VaultError::GraphKeyAbsent(
                "no credential".into(),
            )),
        );
        match &result {
            Err(RunError::Graph { reason, hint }) => {
                assert!(reason.starts_with("kernel graph key: "), "{reason}");
                assert!(hint.contains("sudo maknae enroll"), "{hint}");
            }
            other => panic!("expected Err(RunError::Graph), got {other:?}"),
        }
        assert!(trail(&fx).is_empty());
        assert_eq!(std::fs::read_dir(&fx.state).unwrap().count(), 0);
    }

    #[test]
    fn a_state_dir_with_a_loose_mode_refuses_naming_the_directory() {
        let fx = graph_fixture("graph_loose_mode");
        std::fs::set_permissions(&fx.state, std::fs::Permissions::from_mode(0o755)).unwrap();
        match boot_graph(&fx, key()) {
            Err(RunError::Graph { hint, .. }) => {
                assert!(hint.contains("ownership and mode"), "{hint}");
                assert!(hint.contains(&*fx.state.to_string_lossy()), "{hint}");
            }
            other => panic!("expected Err(RunError::Graph), got {other:?}"),
        }
        assert!(trail(&fx).is_empty());
    }

    fn boot_with_baseline(fx: &GraphFixture, baseline: BaselineLayer) -> BootedGraph {
        let mut inputs = bare_inputs(&fx.dir.0);
        inputs.baseline = baseline;
        block_on(boot_graph_at(
            &fx.state,
            key(),
            &fx.sink,
            &BootCtx {
                event: "boot",
                host: "h",
                socket: "s",
                euid: nix::unistd::geteuid().as_raw(),
                session_id: 9 << 32,
                seq: &Seq::new(),
                au3_1: &serde_json::Value::Null,
            },
            &inputs.boot(),
        ))
        .unwrap()
    }

    fn edited_baseline() -> BaselineLayer {
        let sections: maknae_config::BaselineSections = [(
            "core".to_string(),
            r#"{"deployment_id":"edited"}"#.to_string(),
        )]
        .into();
        BaselineLayer {
            sha256: crate::baseline::accepted_digest(&sections),
            sections: sections.into_inner(),
            ..test_baseline()
        }
    }

    fn stored_baseline(g: &maknae_graph::graph::Graph) -> Option<BaselineLayer> {
        maknae_graph::identity::extract(g).unwrap().baseline
    }

    #[test]
    fn a_first_boot_stores_the_files_baseline_and_a_restart_holds_a_file_edit() {
        let fx = graph_fixture("graph_baseline_held");
        let first = boot_with_baseline(&fx, test_baseline());
        assert_eq!(stored_baseline(&first.graph), Some(test_baseline()));
        drop(first);
        let seeded = trail(&fx).len();
        let again = boot_with_baseline(&fx, edited_baseline());
        assert_eq!(
            (again.status.revision(), again.status.anchor.as_str()),
            (1, "verified")
        );
        assert_eq!(stored_baseline(&again.graph), Some(test_baseline()));
        let actions: Vec<String> = trail(&fx)[seeded..]
            .iter()
            .map(|(r, _)| r.action.clone())
            .collect();
        assert_eq!(actions, ["graph.checkpoint"]);
    }

    #[test]
    fn an_upgrade_store_gains_the_files_baseline_in_a_recorded_transition() {
        let fx = graph_fixture("graph_baseline_upgrade");
        let inputs = bare_inputs(&fx.dir.0);
        let old = maknae_graph::identity::build(
            &inputs.identity,
            None,
            &inputs.vocabulary.persisted,
            inputs.vocabulary.digest,
            3,
            maknae_graph::record::ProvenanceKind::Seed,
        )
        .unwrap();
        let k = WrappingKey::new(key().unwrap().into_bytes());
        let file = maknae_state::envelope::seal(&maknae_graph::format::encode(&old), &k).unwrap();
        let path = fx.state.join(STORE_FILE);
        std::fs::write(&path, file).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        let booted = boot_with_baseline(&fx, edited_baseline());
        assert_eq!(booted.status.revision(), 4);
        assert_eq!(stored_baseline(&booted.graph), Some(edited_baseline()));
        let recs = trail(&fx);
        let actions: Vec<&str> = recs.iter().map(|(r, _)| r.action.as_str()).collect();
        assert_eq!(
            actions,
            [
                "graph.checkpoint",
                "graph.baseline",
                "graph.transition",
                "graph.checkpoint"
            ]
        );
        assert_eq!(recs[1].0.outcome.reason, crate::baseline::SEEDED_EVENT);
    }

    #[test]
    fn an_authorized_reseed_takes_the_files_baseline() {
        if !nix::unistd::geteuid().is_root() {
            return;
        }
        let fx = graph_fixture("graph_baseline_reseed");
        drop(boot_with_baseline(&fx, test_baseline()));
        put(&fx.state, MARKER_FILE, "", 0o644);
        let booted = boot_with_baseline(&fx, edited_baseline());
        assert_eq!(booted.status.anchor, "reseeded");
        assert_eq!(stored_baseline(&booted.graph), Some(edited_baseline()));
    }

    #[test]
    fn a_marker_not_owned_by_root_is_ignored_and_audited() {
        if nix::unistd::geteuid().is_root() {
            return;
        }
        let fx = graph_fixture("graph_marker_ignored");
        put(&fx.state, "reseed.authorized", "planted\n", 0o644);
        let status = boot_graph(&fx, key()).unwrap();
        assert_eq!(
            status.anchor, "seeded",
            "the planted marker authorized nothing"
        );
        let recs = trail(&fx);
        let actions: Vec<&str> = recs.iter().map(|(r, _)| r.action.as_str()).collect();
        assert_eq!(
            actions,
            [
                "graph.seed",
                "graph.baseline",
                "graph.checkpoint",
                "graph.reseed"
            ]
        );
        assert_eq!(recs[0].0.outcome.reason, "intent recorded (first-boot)");
        let ignored = &recs[3].0;
        assert_eq!(ignored.outcome.result, "deny");
        assert!(
            ignored
                .outcome
                .reason
                .starts_with("reseed marker ignored: "),
            "{}",
            ignored.outcome.reason
        );
    }

    #[test]
    fn each_graph_failure_class_carries_its_own_hint() {
        let dir = Path::new("/var/lib/maknae");
        let hint = |f| match graph_refusal(f, dir) {
            RunError::Graph { hint, .. } => hint,
            other => panic!("expected RunError::Graph, got {other:?}"),
        };
        let reseed = "sudo maknae reseed";
        let newer = hint(GraphFailure::Store(StoreError::NewerStore("v2".into())));
        assert!(
            newer.contains("reinstall") && !newer.contains(reseed),
            "{newer}"
        );
        for f in [
            GraphFailure::Store(StoreError::Refused(
                maknae_state::anchor::Refusal::Substituted { revision: 3 },
            )),
            GraphFailure::Store(StoreError::Format("bad".into())),
            GraphFailure::Store(StoreError::Envelope(
                maknae_state::envelope::EnvelopeError::Decrypt,
            )),
        ] {
            assert!(hint(f).contains(reseed));
        }
        let refused = hint(GraphFailure::Store(StoreError::StoreFileRefused(
            "too large".into(),
        )));
        assert_eq!(
            refused,
            "fix the ownership and mode of /var/lib/maknae/kernel.graph (it must be _maknae, \
             0600, one link, ≤64 MiB), then restart; do not reseed — the store may be valid"
        );
        assert!(!refused.contains(reseed), "{refused}");
        let in_use = hint(GraphFailure::Store(StoreError::RejectedNameInUse {
            name: "kernel.graph.rejected.1.00".into(),
            cause: "it holds other bytes".into(),
        }));
        assert_eq!(
            in_use,
            "move /var/lib/maknae/kernel.graph.rejected.1.00 aside (the current store is \
             intact), then restart; the authorized reseed will complete"
        );
        assert!(!in_use.contains(reseed), "{in_use}");
        for f in [
            GraphFailure::Store(StoreError::Io("EACCES".into())),
            GraphFailure::Store(StoreError::StateDir("mode".into())),
        ] {
            let h = hint(f);
            assert!(
                h.contains("ownership and mode of /var/lib/maknae") && !h.contains(reseed),
                "{h}"
            );
        }
        let exhausted = hint(GraphFailure::Store(StoreError::Refused(
            maknae_state::anchor::Refusal::RevisionExhausted,
        )));
        assert!(
            exhausted.contains("investigate") && !exhausted.contains(reseed),
            "{exhausted}"
        );
        let identity = hint(GraphFailure::Store(StoreError::Identity(
            "role `superadmin` is not compiled in".into(),
        )));
        assert!(
            identity.contains("built from bindings.yaml")
                && identity.contains("/etc/maknae/bindings.yaml")
                && !identity.contains("authz.yaml")
                && !identity.contains("/var/lib/maknae")
                && !identity.contains(reseed),
            "{identity}"
        );
        let stale = hint(GraphFailure::Store(StoreError::StaleRevision {
            store: 2,
            attempted: 2,
        }));
        assert!(
            stale.contains("investigate") && !stale.contains(reseed),
            "{stale}"
        );
        let audit = hint(GraphFailure::Store(StoreError::Audit("EIO".into())));
        assert!(
            audit.contains("audit") && !audit.contains(reseed),
            "{audit}"
        );
        let absent = hint(GraphFailure::Key(maknae_vault::VaultError::GraphKeyAbsent(
            "x".into(),
        )));
        assert!(absent.contains("sudo maknae enroll"), "{absent}");
        let malformed = hint(GraphFailure::Key(maknae_vault::VaultError::GraphKey(
            "not exactly 32 bytes",
        )));
        assert!(
            malformed.contains("Replace a malformed key")
                && malformed.contains("sudo maknae enroll`, then `sudo maknae reseed"),
            "{malformed}"
        );
        let unreadable_key = hint(GraphFailure::Key(maknae_vault::VaultError::Io {
            path: "/run/credentials/maknaed.service/maknaed-graph-key".into(),
            source: std::io::Error::other("EACCES"),
        }));
        assert!(
            !unreadable_key.contains(reseed) && unreadable_key != absent,
            "{unreadable_key}"
        );
    }

    #[test]
    fn a_graph_record_append_failure_is_boot_evidence_not_a_graph_refusal() {
        let dir = Path::new("/var/lib/maknae");
        match store_refusal(StoreError::Audit("intent refused".into()), dir) {
            e @ RunError::Other(_) => {
                assert_eq!(refusal_exit_code(&e), 1);
                assert_eq!(
                    e.to_string(),
                    "the boot graph record was not durably appended: intent refused"
                );
            }
            other => panic!("expected RunError::Other, got {other:?}"),
        }
        let refused = store_refusal(StoreError::Format("bad".into()), dir);
        assert!(matches!(refused, RunError::Graph { .. }), "{refused:?}");
        assert_eq!(refusal_exit_code(&refused), GRAPH_REFUSAL_EXIT_CODE);
    }

    #[test]
    fn an_unreadable_store_file_refuses_naming_it_and_never_reseed() {
        let fx = graph_fixture("graph_unreadable");
        put(&fx.state, "kernel.graph", "anything", 0o644);
        match boot_graph(&fx, key()) {
            Err(e @ RunError::Graph { .. }) => {
                assert_eq!(refusal_exit_code(&e), GRAPH_REFUSAL_EXIT_CODE);
                let RunError::Graph { reason, hint } = e else {
                    unreachable!()
                };
                assert!(
                    reason
                        .starts_with("kernel graph store: graph store file kernel.graph refused: "),
                    "{reason}"
                );
                assert!(hint.contains("do not reseed"), "{hint}");
                assert!(!hint.contains("sudo maknae reseed"), "{hint}");
            }
            other => panic!("expected Err(RunError::Graph), got {other:?}"),
        }
        assert!(trail(&fx).is_empty());
        assert_eq!(
            std::fs::read_to_string(fx.state.join("kernel.graph")).unwrap(),
            "anything"
        );
    }

    #[test]
    fn each_refusal_class_has_its_own_exit_code() {
        let graph = RunError::Graph {
            reason: "r".into(),
            hint: "h".into(),
        };
        assert_eq!(
            [
                refusal_exit_code(&RunError::Authz("a".into())),
                refusal_exit_code(&RunError::AuditOffload("o".into())),
                refusal_exit_code(&graph),
                refusal_exit_code(&RunError::Other("x".into())),
            ],
            [3, 4, 5, 1]
        );
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
    fn keychain_marker_fixture_determines_code_bound() {
        let fixture = "---\nmechanism: keychain\ntarget: /etc/maknae/private/maknaed-secret-id.keychain\ntimestamp: \"1786563711\"\n";
        let value = maknae_config::load_str(fixture).unwrap();
        let marker = parse_posture_marker(&value);
        let posture = crate::posture::determine(
            crate::posture::CredentialSource::Keychain,
            marker.as_ref(),
            "/etc/maknae/private/maknaed-secret-id.keychain",
        );
        assert_eq!(posture, crate::posture::Posture::CodeBound);
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
    // ---- #490: the boot starts from the accepted baseline ----

    fn env_lock() -> std::sync::MutexGuard<'static, ()> {
        ENV_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    #[derive(Default)]
    pub(super) struct Counts {
        binds: std::sync::atomic::AtomicUsize,
        connects: std::sync::atomic::AtomicUsize,
        lookups: std::sync::atomic::AtomicUsize,
    }

    #[derive(Clone)]
    pub(super) struct TestEnv {
        pub(super) prepared: Result<(), String>,
        pub(super) bounds: Option<maknae_config::EgressBounds>,
        pub(super) bindable: Result<(), String>,
        /// Answers every reader name with an unprivileged account instead of asking NSS.
        pub(super) any_reader: bool,
        pub(super) counts: Arc<Counts>,
    }

    impl Default for TestEnv {
        fn default() -> Self {
            TestEnv {
                prepared: Ok(()),
                bounds: None,
                bindable: Ok(()),
                any_reader: false,
                counts: Arc::default(),
            }
        }
    }

    impl TestEnv {
        pub(super) fn counting() -> Self {
            TestEnv {
                any_reader: true,
                ..TestEnv::default()
            }
        }
        pub(super) fn with_bounds() -> Self {
            TestEnv {
                bounds: Some(maknae_config::EgressBounds {
                    kv_mount: "kv".into(),
                    user_prefix: "users".into(),
                    vault_addr: "https://v.example:8200".into(),
                }),
                ..TestEnv::default()
            }
        }
        fn count(n: &std::sync::atomic::AtomicUsize) -> usize {
            n.load(std::sync::atomic::Ordering::SeqCst)
        }
        pub(super) fn binds(&self) -> usize {
            Self::count(&self.counts.binds)
        }
        pub(super) fn connects(&self) -> usize {
            Self::count(&self.counts.connects)
        }
        pub(super) fn reader_lookups(&self) -> usize {
            Self::count(&self.counts.lookups)
        }
    }

    impl maknae_config::ReaderLookup for TestEnv {
        fn account(&self, name: &str) -> Result<Option<maknae_config::ReaderAccount>, String> {
            self.counts
                .lookups
                .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            if self.any_reader {
                return Ok(Some(maknae_config::ReaderAccount {
                    name: name.into(),
                    uid: 4100,
                    gid: 4100,
                    groups: Vec::new(),
                }));
            }
            maknae_vault::NssAccounts.account(name)
        }
        fn daemon_gid(&self) -> Result<Option<u32>, String> {
            maknae_vault::NssAccounts.daemon_gid()
        }
        fn service_uids(&self) -> Result<Vec<u32>, String> {
            maknae_vault::NssAccounts.service_uids()
        }
    }

    impl crate::baseline_check::Env for TestEnv {
        fn egress_bounds(&self) -> Result<maknae_config::EgressBounds, maknae_config::ConfigError> {
            self.bounds
                .clone()
                .ok_or_else(|| maknae_config::ConfigError::NotFound {
                    path: maknae_config::EGRESS_BOUNDS_FILE.into(),
                })
        }
        fn egress_account(&self) -> Result<Option<u32>, String> {
            Ok(Some(65534))
        }
        fn trail_prepared(&self, _: &Path) -> Result<(), String> {
            self.prepared.clone()
        }
        fn listener_bindable(&self, _: &Path) -> Result<(), String> {
            self.counts
                .binds
                .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            self.bindable.clone()
        }
        fn deputy_reachable(&self, _: &Path) -> Result<(), String> {
            self.counts
                .connects
                .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            Ok(())
        }
    }

    fn test_seams() -> BootSeams {
        BootSeams {
            graph_key: test_graph_key,
            state_dir_open: StateDir::open,
            files: crate::boot::read_files_as_owner,
            env: Arc::new(TestEnv::default()),
            open_prepared: maknae_audit_append::AuditSink::open_existing,
            scan: production_scan,
            policy_load: maknae_authz_basic::PolicySource::load,
        }
    }

    fn euid_owned_policy(
        paths: maknae_authz_basic::PolicyPaths,
        principal: maknae_config::Principal,
    ) -> Result<maknae_authz_basic::PolicySource, maknae_authz_basic::AuthzBasicError> {
        maknae_authz_basic::PolicySource::load_with_requirement(
            paths,
            principal,
            maknae_config::TargetRequired {
                owner: None,
                mode_mask: Some(0o022),
                nlink_exactly_one: false,
                regular_file: true,
                max_bytes: None,
            },
        )
    }

    fn own_marker(path: &Path, owner: u32) -> Result<StateDir, StoreError> {
        StateDir::open_with_marker_owner(path, owner, nix::unistd::geteuid().as_raw())
    }

    /// The test seams with the policy files read under the test's own ownership.
    fn seams_with(env: TestEnv) -> BootSeams {
        BootSeams {
            env: Arc::new(env),
            policy_load: euid_owned_policy,
            ..test_seams()
        }
    }

    /// As [`seams_with`], with the test playing root's reseed marker.
    fn seams_with_own_marker(env: TestEnv) -> BootSeams {
        BootSeams {
            state_dir_open: own_marker,
            ..seams_with(env)
        }
    }

    fn refusing_prepared(
        _: &maknae_config::AuditConfig,
    ) -> Result<maknae_audit_append::AuditSink, maknae_audit_append::AuditError> {
        Err(maknae_audit_append::AuditError::OpenPrimary {
            path: PathBuf::from("/prepared"),
            detail: "not append-only".into(),
        })
    }

    fn block_on_run_inner_with(dir: &Path, seams: BootSeams) -> Result<ServeOutcome, RunError> {
        tokio::runtime::Runtime::new()
            .unwrap()
            .block_on(run_inner(dir, &state_dir(dir), &seams))
    }

    fn trail_of(d: &Dir, name: &str) -> Vec<AuditRecord> {
        std::fs::read_to_string(d.0.join(name))
            .unwrap_or_default()
            .lines()
            .map(|l| serde_json::from_str(l).unwrap())
            .collect()
    }

    fn baseline_records(recs: &[AuditRecord]) -> Vec<(String, String)> {
        recs.iter()
            .filter(|r| r.action == GRAPH_BASELINE_ACTION)
            .map(|r| (r.outcome.result.clone(), r.outcome.reason.clone()))
            .collect()
    }

    fn composition(recs: &[AuditRecord]) -> String {
        recs.iter()
            .rev()
            .find(|r| r.action == "authz" && r.outcome.result == "permit")
            .unwrap_or_else(|| panic!("no composition record in {recs:?}"))
            .outcome
            .reason
            .clone()
    }

    const PRINCIPAL_BLOCK: &str = "principal:\n  name: op\n  uid: 1000\n";
    const UNCLASSIFIED_CEILING: &str = "  handling:\n    ceiling:\n      classification: UNCLASSIFIED\n      sci: false\n      releasable_to: []\n      cui_permitted: false\n      cui_categories_permitted: []\n      dissemination_permitted: [\"Distribution Statement A\"]\n    accreditation_ref: null\n";
    const SECRET_CEILING: &str = "  handling:\n    ceiling:\n      classification: SECRET\n      sci: false\n      releasable_to: []\n      cui_permitted: false\n      cui_categories_permitted: []\n      dissemination_permitted: [\"Distribution Statement A\"]\n    accreditation_ref: null\n";
    const PROVIDERS_BLOCK: &str = "providers:\n  - name: openai\n    endpoint: https://api.example.test/v1\n    models: [m]\n";

    /// The common fixture's maknae.yaml with `core_extra` under `core:`, the trail at `audit`, and `tail` appended.
    fn write_yaml(d: &Dir, core_extra: &str, vault_addr: &str, audit: &Path, tail: &str) {
        let yaml = format!(
            "core:\n  deployment_id: dev-01\n{core_extra}vault:\n  addr: {vault_addr}\ntransport:\n  socket_path: {}\naudit:\n  jsonl_path: {}\n{PRINCIPAL_BLOCK}{tail}",
            d.0.join("maknaed.sock").display(),
            audit.display(),
        );
        put(&d.0, "maknae.yaml", &yaml, 0o640);
    }

    fn fixture(tag: &str) -> Dir {
        let d = Dir::new(tag);
        write_common_fixture(&d, PRINCIPAL_BLOCK);
        put(
            &d.0,
            "authz.yaml",
            "schema_version: 1\npermissions:\n  allow: []\n  deny: []\n",
            0o640,
        );
        d
    }

    fn boot(d: &Dir) -> Result<ServeOutcome, RunError> {
        block_on_run_inner_with(&d.0, seams_with(TestEnv::default()))
    }

    fn store_graph(d: &Dir) -> maknae_graph::graph::Graph {
        let key = WrappingKey::new(test_graph_key(&d.0).unwrap().into_bytes());
        maknae_graph::format::decode_stored_compiled(
            &maknae_state::envelope::open(&store_bytes(d), &key).unwrap(),
            maknae_graph::record::GraphSpace::Kernel,
            &maknae_graph::kernel::SCHEMA,
        )
        .unwrap()
        .0
    }

    fn accepted(d: &Dir) -> BaselineLayer {
        maknae_graph::identity::extract(&store_graph(d))
            .unwrap()
            .baseline
            .unwrap()
    }

    fn revision_of_store(d: &Dir) -> u64 {
        store_graph(d).revision()
    }

    fn store_bytes(d: &Dir) -> Vec<u8> {
        std::fs::read(state_dir(&d.0).join(STORE_FILE)).unwrap()
    }

    fn write_store(d: &Dir, graph: &maknae_graph::graph::Graph) -> Vec<u8> {
        let key = WrappingKey::new(test_graph_key(&d.0).unwrap().into_bytes());
        let sealed =
            maknae_state::envelope::seal(&maknae_graph::format::encode(graph), &key).unwrap();
        put(&state_dir(&d.0), STORE_FILE, "", 0o600);
        std::fs::write(state_dir(&d.0).join(STORE_FILE), &sealed).unwrap();
        sealed
    }

    fn append_checkpoint(d: &Dir, revision: u64, sealed: &[u8]) {
        let mut rec = make_record(
            "boot",
            "h",
            "s",
            0,
            None,
            None,
            None,
            1,
            1,
            CHECKPOINT_ACTION,
            None,
            "permit",
            "transitioned",
            "authorized",
            &serde_json::Value::Null,
        );
        rec.graph = Some(GraphAudit {
            revision,
            ciphertext_sha256: lower_hex(&maknae_state::envelope::ciphertext_digest(sealed)),
            anchor: "transitioned".into(),
            scanned_bytes: 0,
        });
        let line = format!("{}\n", serde_json::to_string(&rec).unwrap());
        assert!(maknae_state::anchor::is_checkpoint(
            line.trim_end().as_bytes()
        ));
        use std::io::Write;
        std::fs::OpenOptions::new()
            .append(true)
            .open(d.0.join("audit.jsonl"))
            .unwrap()
            .write_all(line.as_bytes())
            .unwrap();
    }

    /// The seeded store rewritten one revision on with `baseline` in place of its own.
    fn rewrite_baseline(d: &Dir, baseline: Option<&BaselineLayer>) {
        let graph = store_graph(d);
        let e = maknae_graph::identity::extract(&graph).unwrap();
        let vocab = crate::vocabulary::kernel_vocabulary(&e.layer.label).unwrap();
        let next = maknae_graph::identity::build(
            &e.layer,
            baseline,
            &vocab.persisted,
            vocab.digest,
            graph.revision() + 1,
            maknae_graph::record::ProvenanceKind::Seed,
        )
        .unwrap();
        let sealed = write_store(d, &next);
        append_checkpoint(d, next.revision(), &sealed);
    }

    fn audit_section(b: &BaselineLayer) -> String {
        b.sections["audit"].clone()
    }

    fn prepare_trail(d: &Dir, name: &str) -> PathBuf {
        put(&d.0, name, "", 0o640);
        d.0.join(name)
    }

    #[test]
    fn a_first_start_seeds_the_baseline_with_no_accept() {
        let _g = env_lock();
        let d = fixture("seed");
        let _ = boot(&d);
        let recs = trail_of(&d, "audit.jsonl");
        let seeded = recs
            .iter()
            .position(|r| r.action == GRAPH_BASELINE_ACTION)
            .expect("a seed record");
        assert_eq!(recs[seeded].outcome.reason, crate::baseline::SEEDED_EVENT);
        let checkpoint = recs
            .iter()
            .position(|r| r.action == CHECKPOINT_ACTION)
            .unwrap();
        assert!(
            seeded < checkpoint,
            "the seed record is written ahead of the persist's checkpoint"
        );
        assert_eq!(
            accepted(&d).sections["core"],
            r#"{"deployment_id":"dev-01"}"#
        );
    }

    #[test]
    fn an_upgrade_seeds_the_baseline_from_the_files() {
        let _g = env_lock();
        let d = fixture("upgrade");
        let _ = boot(&d);
        rewrite_baseline(&d, None);
        let before = trail_of(&d, "audit.jsonl").len();
        let _ = boot(&d);
        let recs = trail_of(&d, "audit.jsonl");
        let new: Vec<(&str, &str)> = recs[before..]
            .iter()
            .map(|r| (r.action.as_str(), r.outcome.reason.as_str()))
            .collect();
        let seeded = new
            .iter()
            .position(|(a, r)| *a == GRAPH_BASELINE_ACTION && *r == crate::baseline::SEEDED_EVENT)
            .expect("seeded");
        let transition = new
            .iter()
            .position(|(a, r)| *a == GRAPH_TRANSITION_ACTION && r.contains("root-file"))
            .expect("transition");
        assert!(seeded < transition, "{new:?}");
        assert!(
            !new.iter().any(|(a, _)| *a == GRAPH_MIGRATE_ACTION),
            "{new:?}"
        );
        assert_eq!(
            accepted(&d).sections["core"],
            r#"{"deployment_id":"dev-01"}"#
        );
    }

    #[test]
    fn a_pending_change_survives_a_restart_unapplied() {
        let _g = env_lock();
        let d = fixture("pending");
        write_yaml(
            &d,
            UNCLASSIFIED_CEILING,
            "https://v.example:8200",
            &d.0.join("audit.jsonl"),
            "",
        );
        let _ = boot(&d);
        let revision_after_seed = revision_of_store(&d);
        write_yaml(
            &d,
            SECRET_CEILING,
            "https://v.example:8200",
            &d.0.join("audit.jsonl"),
            "",
        );
        let mut hashes = Vec::new();
        for _ in 0..2 {
            let before = trail_of(&d, "audit.jsonl").len();
            let _ = boot(&d);
            let recs = trail_of(&d, "audit.jsonl")[before..].to_vec();
            assert!(
                composition(&recs).contains("ceiling: UNCLASSIFIED"),
                "{}",
                composition(&recs)
            );
            let pending = baseline_records(&recs);
            assert_eq!(pending.len(), 1, "{pending:?}");
            assert_eq!(pending[0].0, "deny");
            assert!(
                pending[0]
                    .1
                    .starts_with("baseline change pending acceptance: root-file "),
                "{}",
                pending[0].1
            );
            assert!(
                pending[0].1.ends_with("(apply: live; sections: core)"),
                "{}",
                pending[0].1
            );
            hashes.push(pending[0].1.clone());
        }
        assert_eq!(hashes[0], hashes[1]);
        assert_eq!(revision_of_store(&d), revision_after_seed);
    }

    #[test]
    fn an_invalid_file_without_a_baseline_exits_one_and_appends_nothing() {
        let _g = env_lock();
        let d = fixture("invalid-first");
        put(&d.0, "maknae.yaml", "core:\n  deployment_id: [\n", 0o640);
        let r = boot(&d);
        assert!(matches!(r, Err(RunError::Other(_))), "{r:?}");
        assert_eq!(refusal_exit_code(&r.unwrap_err()), 1);
        assert!(trail_of(&d, "audit.jsonl").is_empty());
        assert!(!d.0.join("audit.jsonl").exists());
    }

    #[test]
    fn an_invalid_file_with_a_baseline_keeps_running_it_and_records_why() {
        let _g = env_lock();
        let d = fixture("invalid-later");
        let _ = boot(&d);
        let revision = revision_of_store(&d);
        write_yaml(
            &d,
            "  unknown_key: 1\n",
            "https://v.example:8200",
            &d.0.join("audit.jsonl"),
            "",
        );
        let before = trail_of(&d, "audit.jsonl").len();
        let _ = boot(&d);
        let recs = trail_of(&d, "audit.jsonl")[before..].to_vec();
        assert!(composition(&recs).contains("ceiling: UNCLASSIFIED"));
        let b = baseline_records(&recs);
        assert_eq!(b.len(), 1, "{b:?}");
        assert!(
            b[0].1.starts_with("baseline change refused: invalid: ")
                && b[0].1.contains("unknown_key"),
            "{}",
            b[0].1
        );
        assert_eq!(
            recs.iter()
                .find(|r| r.action == GRAPH_BASELINE_ACTION)
                .unwrap()
                .outcome
                .posture,
            "unavailable"
        );
        assert_eq!(revision_of_store(&d), revision);
    }

    #[test]
    fn vault_follows_the_file_at_start_and_is_recorded() {
        let _g = env_lock();
        let d = fixture("vault-follows");
        let _ = boot(&d);
        write_yaml(
            &d,
            "",
            "https://w.example:8200",
            &d.0.join("audit.jsonl"),
            "",
        );
        let before = trail_of(&d, "audit.jsonl").len();
        let _ = boot(&d);
        let recs = trail_of(&d, "audit.jsonl")[before..].to_vec();
        let follow = recs
            .iter()
            .position(|r| {
                r.action == GRAPH_BASELINE_ACTION
                    && r.outcome.reason == "vault follows maknae.yaml at start"
            })
            .expect("follow record");
        let transition = recs
            .iter()
            .position(|r| r.action == GRAPH_TRANSITION_ACTION)
            .expect("transition");
        assert!(follow < transition);
        assert!(accepted(&d).sections["vault"].contains("w.example"));
        assert!(
            baseline_records(&recs)
                .iter()
                .all(|(result, _)| result == "permit"),
            "no pending record"
        );
    }

    #[test]
    fn a_move_records_in_the_old_trail_first_and_links_back() {
        let _g = env_lock();
        let d = fixture("move");
        let _ = boot(&d);
        let new = prepare_trail(&d, "audit-2.jsonl");
        write_yaml(&d, "", "https://v.example:8200", &new, "");
        let old_before = trail_of(&d, "audit.jsonl").len();
        let _ = boot(&d);
        let old = trail_of(&d, "audit.jsonl");
        assert_eq!(
            old.len(),
            old_before + 1,
            "exactly one record is added to the old trail"
        );
        assert_eq!(
            old.last().unwrap().outcome.reason,
            format!("audit trail moves to {} at start", new.display())
        );
        let moved = trail_of(&d, "audit-2.jsonl");
        assert_eq!(moved[0].action, GRAPH_BASELINE_ACTION);
        assert_eq!(
            moved[0].outcome.reason,
            format!(
                "audit trail continues from {}; last checkpoint revision 1",
                d.0.join("audit.jsonl").display()
            )
        );
        let (moving, linked) = (old.last().unwrap(), &moved[0]);
        assert_eq!(moving.session_id, linked.session_id);
        assert!(
            moving.seq < linked.seq,
            "the old trail records the move before the new trail's first record"
        );
        assert!(moved.iter().any(|r| r.action == CHECKPOINT_ACTION));
        assert!(baseline_records(&moved)
            .iter()
            .any(|(_, why)| *why == crate::baseline::moved_event(&d.0.join("audit.jsonl"), &new)));
        assert!(audit_section(&accepted(&d)).contains("audit-2.jsonl"));
    }

    #[test]
    fn an_unprepared_target_keeps_the_old_trail() {
        let _g = env_lock();
        let d = fixture("unprepared");
        let _ = boot(&d);
        let new = prepare_trail(&d, "audit-2.jsonl");
        write_yaml(&d, "", "https://v.example:8200", &new, "");
        let before = trail_of(&d, "audit.jsonl").len();
        let _ = block_on_run_inner_with(
            &d.0,
            seams_with(TestEnv {
                prepared: Err("not append-only".into()),
                ..TestEnv::default()
            }),
        );
        assert!(trail_of(&d, "audit-2.jsonl").is_empty());
        let b = baseline_records(&trail_of(&d, "audit.jsonl")[before..]);
        assert!(
            b.iter()
                .any(|(r, why)| r == "deny" && why.contains("not append-only")),
            "{b:?}"
        );
        assert!(!audit_section(&accepted(&d)).contains("audit-2.jsonl"));
    }

    #[test]
    fn a_move_outside_the_trail_directory_is_refused_as_invalid() {
        let _g = env_lock();
        let d = fixture("outside");
        let other = Dir::new("outside-other");
        let _ = boot(&d);
        let elsewhere = other.0.join("audit.jsonl");
        put(&other.0, "audit.jsonl", "", 0o640);
        write_yaml(&d, "", "https://v.example:8200", &elsewhere, "");
        let before = trail_of(&d, "audit.jsonl").len();
        let _ = boot(&d);
        let b = baseline_records(&trail_of(&d, "audit.jsonl")[before..]);
        assert!(
            b.iter()
                .any(|(r, why)| r == "deny" && why.contains("may move only within")),
            "{b:?}"
        );
        assert!(std::fs::read_to_string(&elsewhere).unwrap().is_empty());
    }

    #[test]
    fn a_target_that_does_not_open_prepared_is_refused_in_the_old_trail_only() {
        let _g = env_lock();
        let d = fixture("prepared-race");
        let _ = boot(&d);
        let new = prepare_trail(&d, "audit-2.jsonl");
        write_yaml(&d, "", "https://v.example:8200", &new, "");
        let before = trail_of(&d, "audit.jsonl").len();
        let r = block_on_run_inner_with(
            &d.0,
            BootSeams {
                open_prepared: refusing_prepared,
                ..seams_with(TestEnv::default())
            },
        );
        assert!(
            matches!(r, Err(RunError::Other(ref m)) if m.contains("not append-only")),
            "{r:?}"
        );
        assert!(trail_of(&d, "audit-2.jsonl").is_empty());
        let old = trail_of(&d, "audit.jsonl")[before..].to_vec();
        assert_eq!(old.len(), 1, "{old:?}");
        assert_eq!(old[0].action, "start");
        assert!(old[0].outcome.reason.contains("not append-only"));
    }

    static SCANS: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
    static FAIL_SCAN: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);

    fn failing_scan(
        sink: &maknae_audit_append::AuditSink,
    ) -> Result<maknae_audit_append::ScanResult, maknae_audit_append::AuditError> {
        use std::sync::atomic::Ordering::SeqCst;
        if SCANS.fetch_add(1, SeqCst) + 1 == FAIL_SCAN.load(SeqCst) {
            return Err(maknae_audit_append::AuditError::ReadPrimary(
                "injected scan failure".into(),
            ));
        }
        production_scan(sink)
    }

    #[test]
    fn a_trail_scan_that_fails_during_a_move_is_refused_in_the_old_trail_only() {
        use std::sync::atomic::Ordering::SeqCst;
        let _g = env_lock();
        for (nth, which) in [(1, "old"), (2, "new")] {
            let d = fixture(&format!("scan-fails-{which}"));
            let _ = boot(&d);
            let new = prepare_trail(&d, "audit-2.jsonl");
            write_yaml(&d, "", "https://v.example:8200", &new, "");
            let before = trail_of(&d, "audit.jsonl").len();
            SCANS.store(0, SeqCst);
            FAIL_SCAN.store(nth, SeqCst);
            let r = block_on_run_inner_with(
                &d.0,
                BootSeams {
                    scan: failing_scan,
                    ..seams_with(TestEnv::default())
                },
            );
            FAIL_SCAN.store(0, SeqCst);
            assert!(matches!(r, Err(RunError::Graph { .. })), "{which}: {r:?}");
            assert!(trail_of(&d, "audit-2.jsonl").is_empty(), "{which}");
            let old = trail_of(&d, "audit.jsonl")[before..].to_vec();
            assert_eq!(old.len(), 1, "{which}: {old:?}");
            assert_eq!(old[0].action, GRAPH_LOAD_ACTION, "{which}");
            assert!(
                old[0].outcome.reason.contains("injected scan failure"),
                "{which}: {}",
                old[0].outcome.reason
            );
        }
    }

    fn yaml_with_offload(d: &Dir, trail: &Path) {
        let yaml = format!(
            "core:\n  deployment_id: dev-01\nvault:\n  addr: https://v.example:8200\ntransport:\n  socket_path: {}\naudit:\n  jsonl_path: {}\n  siem: https://siem.example:6514\n{PRINCIPAL_BLOCK}",
            d.0.join("maknaed.sock").display(),
            trail.display(),
        );
        put(&d.0, "maknae.yaml", &yaml, 0o640);
    }

    #[test]
    fn a_reseed_refused_at_start_is_recorded_in_the_stored_trail() {
        let _g = env_lock();
        let d = fixture("reseed-refused");
        let _ = boot(&d);
        let new = prepare_trail(&d, "audit-2.jsonl");
        yaml_with_offload(&d, &new);
        put(&state_dir(&d.0), MARKER_FILE, "", 0o644);
        let before = trail_of(&d, "audit.jsonl").len();
        let r = block_on_run_inner_with(&d.0, seams_with_own_marker(TestEnv::default()));
        assert!(r.is_err(), "{r:?}");
        assert!(
            trail_of(&d, "audit-2.jsonl").is_empty(),
            "the new trail is unverified"
        );
        assert_eq!(trail_of(&d, "audit.jsonl").len(), before + 1);
    }

    fn forge_digest(d: &Dir) -> BaselineLayer {
        let mut forged = accepted(d);
        forged.sha256 = [7; 32];
        rewrite_baseline(d, Some(&forged));
        forged
    }

    #[test]
    fn an_inconsistent_store_is_refused_where_its_trail_is() {
        let _g = env_lock();
        let d = fixture("inconsistent-trail");
        let _ = boot(&d);
        forge_digest(&d);
        let new = prepare_trail(&d, "audit-2.jsonl");
        write_yaml(&d, "", "https://v.example:8200", &new, "");
        let before = trail_of(&d, "audit.jsonl").len();
        let r = boot(&d);
        assert!(matches!(r, Err(RunError::Graph { .. })), "{r:?}");
        let old = trail_of(&d, "audit.jsonl")[before..].to_vec();
        assert_eq!(
            old.last().unwrap().outcome.reason,
            format!("audit trail moves to {} at start", new.display())
        );
        let moved = trail_of(&d, "audit-2.jsonl");
        assert!(moved[0]
            .outcome
            .reason
            .starts_with("audit trail continues from "));
        assert_eq!(moved.last().unwrap().action, GRAPH_LOAD_ACTION);
    }

    #[test]
    fn a_reseed_over_an_inconsistent_store_records_what_it_set_aside() {
        let _g = env_lock();
        let d = fixture("reseed-inconsistent");
        let _ = boot(&d);
        let forged = forge_digest(&d);
        put(&state_dir(&d.0), MARKER_FILE, "", 0o644);
        let before = trail_of(&d, "audit.jsonl").len();
        let _ = block_on_run_inner_with(&d.0, seams_with_own_marker(TestEnv::default()));
        let recs = trail_of(&d, "audit.jsonl")[before..].to_vec();
        assert_eq!(
            baseline_records(&recs),
            vec![(
                "permit".to_string(),
                crate::baseline::reseeded_event(&forged.sha256)
            )]
        );
    }

    #[test]
    fn stored_sections_that_do_not_assemble_are_an_inconsistent_store() {
        let _g = env_lock();
        let d = fixture("unassembled");
        let _ = boot(&d);
        let mut forged = accepted(&d);
        forged.sections.insert(
            "core".into(),
            r#"{"deployment_id":"dev-01","handling":{"policy":"nope"}}"#.into(),
        );
        forged.sha256 = crate::baseline::accepted_digest(&forged.sections.clone().into());
        rewrite_baseline(&d, Some(&forged));
        let before = trail_of(&d, "audit.jsonl").len();
        let r = boot(&d);
        let Err(e @ RunError::Graph { .. }) = &r else {
            panic!("expected the store refusal, got {r:?}");
        };
        assert_eq!(refusal_exit_code(e), GRAPH_REFUSAL_EXIT_CODE);
        let recs = trail_of(&d, "audit.jsonl")[before..].to_vec();
        assert_eq!(recs.last().unwrap().action, GRAPH_LOAD_ACTION);
    }

    #[test]
    fn an_inconsistent_store_is_refused_before_the_policy_loads() {
        let _g = env_lock();
        let d = fixture("inconsistent-policy");
        let _ = boot(&d);
        forge_digest(&d);
        put(&d.0, "authz.yaml", "schema_version: [\n", 0o640);
        let r = boot(&d);
        let Err(e) = &r else { panic!("{r:?}") };
        assert_eq!(refusal_exit_code(e), GRAPH_REFUSAL_EXIT_CODE, "{e}");
    }

    #[test]
    fn a_rolled_back_store_naming_the_old_trail_is_refused_across_a_move() {
        let _g = env_lock();
        let d = fixture("rollback-move");
        let _ = boot(&d);
        let me = nix::unistd::User::from_uid(nix::unistd::geteuid())
            .unwrap()
            .unwrap()
            .name;
        put(
            &d.0,
            "bindings.yaml",
            &format!("schema_version: 1\nbindings:\n  admin: [\"{me}\"]\n"),
            0o640,
        );
        let _ = boot(&d);
        assert_eq!(revision_of_store(&d), 2);
        let s2 = store_bytes(&d);
        let new = prepare_trail(&d, "audit-2.jsonl");
        write_yaml(&d, "", "https://v.example:8200", &new, "");
        let _ = boot(&d);
        assert_eq!(revision_of_store(&d), 3);
        std::fs::write(state_dir(&d.0).join(STORE_FILE), &s2).unwrap();
        match boot(&d) {
            Err(RunError::Graph { reason, .. }) => {
                assert!(reason.contains('2') && reason.contains('3'), "{reason}")
            }
            other => panic!("expected the rollback refusal, got {other:?}"),
        }
    }

    /// Accepts the set `admin.baseline.show` shows for `d`'s files, from a fixture over its directories.
    fn accept_shown(d: &Dir) -> String {
        tokio::runtime::Runtime::new().unwrap().block_on(async {
            let principal = maknae_config::Principal {
                name: "op".into(),
                uid: 1000,
            };
            let fx = super::reload_fixture::over(&d.0, principal).await;
            let shown = BaselineOps::show(fx.reloader.as_ref()).await.unwrap();
            assert_eq!(
                (shown.state.as_str(), shown.apply.as_str()),
                ("pending", "restart")
            );
            match BaselineOps::accept(fx.reloader.as_ref(), &shown.hash).await {
                AcceptAnswer::View {
                    corrective: None, ..
                } => {}
                other => panic!("{other:?}"),
            }
            assert_eq!(*fx.reloader.drain.borrow(), Drain::Applied);
            shown.hash
        })
    }

    #[test]
    fn an_accepted_move_is_performed_by_the_restart_boot_through_the_one_seam() {
        let _g = env_lock();
        let d = fixture("accepted-move");
        let _ = boot(&d);
        let (old, new) = (d.0.join("audit.jsonl"), prepare_trail(&d, "audit-2.jsonl"));
        write_yaml(&d, "", "https://v.example:8200", &new, "");
        accept_shown(&d);
        assert_eq!(accepted(&d).moved_from.as_deref(), old.to_str());

        let refused = block_on_run_inner_with(
            &d.0,
            BootSeams {
                open_prepared: refusing_prepared,
                ..seams_with(TestEnv::default())
            },
        );
        let Err(e) = &refused else {
            panic!("{refused:?}")
        };
        assert_eq!(refusal_exit_code(e), 1, "{e}");
        assert!(
            trail_of(&d, "audit-2.jsonl").is_empty(),
            "the prepared open is the only open of a moved trail"
        );

        let _ = boot(&d);
        assert_eq!(
            trail_of(&d, "audit.jsonl").last().unwrap().outcome.reason,
            crate::baseline::move_record(&new)
        );
        let moved = trail_of(&d, "audit-2.jsonl");
        assert!(moved[0].outcome.reason.starts_with(&format!(
            "audit trail continues from {}; last checkpoint revision ",
            old.display()
        )));
        assert!(moved.iter().any(|r| r.action == CHECKPOINT_ACTION));
        let stored = accepted(&d);
        assert_eq!(stored.moved_from, None);
        assert!(audit_section(&stored).contains("audit-2.jsonl"));
    }

    #[test]
    fn an_accepted_restart_baseline_boots_and_applies() {
        let _g = env_lock();
        let d = fixture("accepted-restart");
        let _ = boot(&d);
        let yaml = format!(
            "core:\n  deployment_id: dev-01\nvault:\n  addr: https://v.example:8200\ntransport:\n  socket_path: {}\n  max_connections: 7\naudit:\n  jsonl_path: {}\n{PRINCIPAL_BLOCK}",
            d.0.join("maknaed.sock").display(),
            d.0.join("audit.jsonl").display(),
        );
        put(&d.0, "maknae.yaml", &yaml, 0o640);
        accept_shown(&d);
        let revision = revision_of_store(&d);
        let before = trail_of(&d, "audit.jsonl").len();
        let _ = boot(&d);
        let this_boot = &trail_of(&d, "audit.jsonl")[before..];
        assert!(
            this_boot.iter().any(|r| r.action == CHECKPOINT_ACTION),
            "{this_boot:?}"
        );
        assert!(
            !baseline_records(this_boot)
                .iter()
                .any(|(result, _)| result == "deny"),
            "nothing is pending: {this_boot:?}"
        );
        assert!(!this_boot
            .iter()
            .any(|r| r.action == GRAPH_TRANSITION_ACTION));
        assert_eq!(revision_of_store(&d), revision);
        assert!(accepted(&d).sections["transport"].contains("\"max_connections\":7"));
    }

    #[test]
    fn once_a_baseline_exists_a_missing_trail_refuses_and_is_not_created() {
        let _g = env_lock();
        let d = fixture("no-recreate");
        let _ = boot(&d);
        std::fs::remove_file(d.0.join("audit.jsonl")).unwrap();
        let r = boot(&d);
        assert!(
            matches!(r, Err(RunError::Other(ref m)) if m.contains("is missing") && m.contains("Move the audit trail")),
            "{r:?}"
        );
        assert!(!d.0.join("audit.jsonl").exists());
    }

    #[test]
    fn a_reseed_replaces_an_accepted_baseline_from_the_files() {
        let _g = env_lock();
        let d = fixture("reseed");
        let _ = boot(&d);
        let accepted_before = accepted(&d);
        write_yaml(
            &d,
            SECRET_CEILING,
            "https://w.example:8200",
            &d.0.join("audit.jsonl"),
            "",
        );
        put(&state_dir(&d.0), MARKER_FILE, "", 0o644);
        let before = trail_of(&d, "audit.jsonl").len();
        let _ = block_on_run_inner_with(&d.0, seams_with_own_marker(TestEnv::default()));
        let recs = trail_of(&d, "audit.jsonl")[before..].to_vec();
        assert!(
            recs.iter()
                .any(|r| r.action == GRAPH_SEED_ACTION
                    && r.outcome.reason.contains("reseed-authorized")),
            "{:?}",
            recs.iter().map(|r| &r.outcome.reason).collect::<Vec<_>>()
        );
        assert_eq!(
            baseline_records(&recs),
            vec![(
                "permit".to_string(),
                crate::baseline::reseeded_event(&accepted_before.sha256)
            )]
        );
        assert!(accepted(&d).sections["vault"].contains("w.example"));
        assert_eq!(
            accepted(&d).ceiling,
            "SECRET",
            "the files replaced the accepted ceiling without an accept"
        );
    }

    #[test]
    fn a_reseed_still_moves_the_trail_through_the_one_seam() {
        let _g = env_lock();
        let d = fixture("reseed-move");
        let _ = boot(&d);
        let new = prepare_trail(&d, "audit-2.jsonl");
        write_yaml(&d, "", "https://v.example:8200", &new, "");
        put(&state_dir(&d.0), MARKER_FILE, "", 0o644);
        let old_before = trail_of(&d, "audit.jsonl").len();
        let _ = block_on_run_inner_with(&d.0, seams_with_own_marker(TestEnv::default()));
        let old = trail_of(&d, "audit.jsonl");
        assert_eq!(old.len(), old_before + 1);
        assert_eq!(
            old.last().unwrap().outcome.reason,
            format!("audit trail moves to {} at start", new.display())
        );
        assert!(trail_of(&d, "audit-2.jsonl")[0]
            .outcome
            .reason
            .starts_with("audit trail continues from "));

        let e = fixture("reseed-unprepared");
        let _ = boot(&e);
        let sibling = e.0.join("audit-3.jsonl");
        write_yaml(&e, "", "https://v.example:8200", &sibling, "");
        put(&state_dir(&e.0), MARKER_FILE, "", 0o644);
        let before = trail_of(&e, "audit.jsonl").len();
        let r = block_on_run_inner_with(
            &e.0,
            seams_with_own_marker(TestEnv {
                prepared: Err("no such file".into()),
                ..TestEnv::default()
            }),
        );
        assert!(
            matches!(r, Err(RunError::Other(ref m)) if m.contains("Move the audit trail")),
            "{r:?}"
        );
        assert!(!sibling.exists(), "nothing created");
        let stored = trail_of(&e, "audit.jsonl")[before..].to_vec();
        assert_eq!(
            stored.len(),
            1,
            "the refusal is recorded in the stored trail"
        );
        assert_eq!(stored[0].action, "start");
        assert!(stored[0].outcome.reason.contains("no such file"));
    }

    #[test]
    fn an_unreadable_store_with_an_invalid_file_names_both() {
        let _g = env_lock();
        let d = fixture("unreadable");
        let _ = boot(&d);
        put(&state_dir(&d.0), STORE_FILE, "not a store", 0o600);
        put(&d.0, "maknae.yaml", "core:\n  deployment_id: [\n", 0o640);
        match boot(&d) {
            Err(RunError::Other(m)) => assert!(m.contains("could not be read"), "{m}"),
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn an_unreadable_store_opens_the_files_trail_existing_only_and_refuses_audited() {
        let _g = env_lock();
        let d = fixture("unreadable-valid");
        let _ = boot(&d);
        put(&state_dir(&d.0), STORE_FILE, "not a store", 0o600);
        let before = trail_of(&d, "audit.jsonl").len();
        let r = boot(&d);
        assert!(matches!(r, Err(RunError::Graph { .. })), "{r:?}");
        let recs = trail_of(&d, "audit.jsonl")[before..].to_vec();
        assert_eq!(recs.last().unwrap().action, GRAPH_LOAD_ACTION);
        std::fs::remove_file(d.0.join("audit.jsonl")).unwrap();
        let r = boot(&d);
        assert!(
            matches!(r, Err(RunError::Other(ref m)) if m.contains("is missing")),
            "{r:?}"
        );
        assert!(!d.0.join("audit.jsonl").exists(), "never created");
    }

    #[test]
    fn a_stored_baseline_that_does_not_match_its_own_record_refuses() {
        let _g = env_lock();
        for (tag, forge) in [
            (
                "forged-digest",
                (|b: &mut BaselineLayer| b.sha256 = [7; 32]) as fn(&mut BaselineLayer),
            ),
            ("forged-system", |b: &mut BaselineLayer| {
                b.system = "AUS".into()
            }),
            ("forged-ceiling", |b: &mut BaselineLayer| {
                b.ceiling = "SECRET".into()
            }),
        ] {
            let d = fixture(tag);
            let _ = boot(&d);
            let mut forged = accepted(&d);
            forge(&mut forged);
            rewrite_baseline(&d, Some(&forged));
            let revision = revision_of_store(&d);
            let before = trail_of(&d, "audit.jsonl").len();
            match boot(&d) {
                Err(e @ RunError::Graph { .. }) => {
                    assert!(e.to_string().contains("does not match"), "{tag}: {e}");
                    assert_eq!(refusal_exit_code(&e), GRAPH_REFUSAL_EXIT_CODE);
                }
                other => panic!("{tag}: expected the store refusal, got {other:?}"),
            }
            let recs = trail_of(&d, "audit.jsonl")[before..].to_vec();
            assert!(!recs.iter().any(|r| r.action == "authz"), "{tag}: {recs:?}");
            assert_eq!(recs.last().unwrap().action, GRAPH_LOAD_ACTION, "{tag}");
            assert_eq!(revision_of_store(&d), revision, "{tag}");
        }
    }

    #[test]
    fn an_accepted_baseline_that_no_longer_validates_refuses_to_start() {
        let _g = env_lock();
        let d = fixture("drift");
        write_yaml(
            &d,
            "",
            "https://v.example:8200",
            &d.0.join("audit.jsonl"),
            PROVIDERS_BLOCK,
        );
        let bounds = TestEnv {
            bounds: Some(maknae_config::EgressBounds {
                kv_mount: "kv".into(),
                user_prefix: "users".into(),
                vault_addr: "https://v.example:8200".into(),
            }),
            ..TestEnv::default()
        };
        let _ = block_on_run_inner_with(&d.0, seams_with(bounds));
        assert!(accepted(&d).sections.contains_key("providers"));
        let revision = revision_of_store(&d);
        let before = trail_of(&d, "audit.jsonl").len();
        let r = boot(&d);
        let Err(e @ RunError::Other(m)) = &r else {
            panic!("expected the start refusal, got {r:?}");
        };
        assert!(
            m.starts_with("accepted baseline cannot start: ") && m.contains("egress-bounds"),
            "{m}"
        );
        assert_eq!(refusal_exit_code(e), 1);
        let recs = trail_of(&d, "audit.jsonl")[before..].to_vec();
        assert_eq!(recs.len(), 1, "{recs:?}");
        assert_eq!(
            (recs[0].action.as_str(), recs[0].outcome.reason.as_str()),
            ("start", m.as_str())
        );
        assert_eq!(revision_of_store(&d), revision);
    }

    #[test]
    fn an_environment_refusal_at_a_first_start_is_audited() {
        let _g = env_lock();
        let d = fixture("first-env");
        write_yaml(
            &d,
            "",
            "https://v.example:8200",
            &d.0.join("audit.jsonl"),
            PROVIDERS_BLOCK,
        );
        let r = boot(&d);
        let Err(e @ RunError::Other(m)) = &r else {
            panic!("expected the start refusal, got {r:?}");
        };
        assert_eq!(refusal_exit_code(e), 1);
        let recs = trail_of(&d, "audit.jsonl");
        assert_eq!(recs.len(), 1, "{recs:?}");
        assert_eq!(
            (recs[0].action.as_str(), recs[0].outcome.reason.as_str()),
            ("start", m.as_str())
        );
        assert!(!state_dir(&d.0).join(STORE_FILE).exists());
    }

    #[test]
    fn a_vault_block_that_does_not_parse_refuses_after_the_policy_loads() {
        let _g = env_lock();
        let d = fixture("vault-after-policy");
        write_yaml(
            &d,
            "",
            "https://v.example:8200\n  colour: red",
            &d.0.join("audit.jsonl"),
            "",
        );
        let r = boot(&d);
        let Err(e @ RunError::Other(m)) = &r else {
            panic!("expected the start refusal, got {r:?}");
        };
        assert!(m.contains("colour"), "{m}");
        assert_eq!(refusal_exit_code(e), 1);
        assert_eq!(trail_of(&d, "audit.jsonl").last().unwrap().action, "start");
        put(&d.0, "authz.yaml", "schema_version: [\n", 0o640);
        let r = boot(&d);
        assert!(matches!(r, Err(RunError::Authz(_))), "{r:?}");
        assert_eq!(trail_of(&d, "audit.jsonl").last().unwrap().action, "authz");
    }

    #[test]
    fn a_first_start_offload_or_principal_refusal_is_audited_as_today() {
        let _g = env_lock();
        let d = fixture("first-offload");
        write_yaml(
            &d,
            "",
            "https://v.example:8200",
            &d.0.join("audit.jsonl"),
            "",
        );
        let yaml = std::fs::read_to_string(d.0.join("maknae.yaml"))
            .unwrap()
            .replace("audit:\n", "audit:\n  siem: https://siem.example\n");
        put(&d.0, "maknae.yaml", &yaml, 0o640);
        let r = boot(&d);
        assert!(matches!(r, Err(RunError::AuditOffload(_))), "{r:?}");
        assert_eq!(
            trail_of(&d, "audit.jsonl").last().unwrap().action,
            "audit.offload"
        );
    }

    #[test]
    fn the_run_baseline_records_the_declared_system_and_ceiling() {
        let sections: maknae_config::BaselineSections =
            [("core".to_string(), "{}".to_string())].into();
        assert_eq!(
            run_baseline(&sections, ("US".into(), "UNCLASSIFIED".into())),
            BaselineLayer {
                sections: sections.clone().into_inner(),
                system: "US".into(),
                ceiling: "UNCLASSIFIED".into(),
                sha256: maknae_state::envelope::sha256(br#"{"core":"{}"}"#),
                moved_from: None,
            }
        );
    }
}

#[cfg(test)]
mod home_resolution_tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    #[derive(Default)]
    struct Recorder(std::sync::Mutex<Vec<AuditRecord>>);
    impl AuditEmit for Recorder {
        fn emit(
            &self,
            record: &AuditRecord,
        ) -> impl std::future::Future<Output = Result<(), maknae_audit_append::AuditError>> + Send
        {
            self.0.lock().unwrap().push(record.clone());
            async { Ok(()) }
        }
    }

    struct Dir(PathBuf);
    impl Drop for Dir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    async fn serve(
        verb: Verb,
        uid: u32,
        user: &str,
        home: &Path,
        authorizer: Arc<crate::Composition<maknae_authz_basic::HermeticAuthorizer>>,
    ) -> (RespResult, Vec<AuditRecord>) {
        let (mut client, server) = tokio::io::duplex(256 * 1024);
        let body = maknae_proto::encode_request(&maknae_proto::Request {
            protocol_version: PROTOCOL_VERSION,
            verb: verb.clone(),
        })
        .unwrap();
        maknae_proto::write_frame(&mut client, maknae_proto::class_of(&verb), &body)
            .await
            .unwrap();
        let emit = Arc::new(Recorder::default());
        let backend_name = Arc::new(maknae_security::guarded_backend_name(&*authorizer));
        handle(
            server,
            "maknae://d/plane/cli".to_string(),
            uid,
            true,
            Some(user.to_string()),
            Some(home.to_path_buf()),
            emit.clone(),
            1,
            maknae_config::transport_from_section(None).unwrap(),
            serde_json::json!({}),
            authorizer,
            std::sync::Arc::new(crate::live::LiveConfig::new(ConfigView::default(), None)),
            backend_name,
            Arc::new("US".to_string()),
            Arc::new(None),
            crate::egress::unavailable_egress(),
            Duration::from_secs(10),
            maknae_security::Lane::Local,
            maknae_io::DelegatedFds::new(1),
            baseline_stub::no_baseline(),
        )
        .await;
        let caps = maknae_proto::FrameCaps {
            control: 1 << 20,
            attempt: 1 << 20,
            prompt: 1 << 20,
        };
        let (_, reply) = tokio::time::timeout(
            Duration::from_secs(10),
            maknae_proto::read_frame_zeroizing(&mut client, &caps),
        )
        .await
        .expect("a reply in time")
        .expect("a reply frame");
        let records = emit.0.lock().unwrap().clone();
        (
            maknae_proto::decode_response(&reply).unwrap().result,
            records,
        )
    }

    #[tokio::test]
    async fn only_a_filesystem_verb_resolves_the_requesters_home() {
        let uid = nix::unistd::geteuid().as_raw();
        let user = nix::unistd::User::from_uid(nix::unistd::geteuid())
            .expect("NSS")
            .expect("the test euid has a passwd entry")
            .name;
        let raw = std::env::temp_dir().join(format!("run_home_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&raw);
        std::fs::create_dir(&raw).unwrap();
        let dir = Dir(raw.canonicalize().unwrap());
        std::fs::set_permissions(&dir.0, std::fs::Permissions::from_mode(0o700)).unwrap();
        let policy = dir.0.join("authz.yaml");
        std::fs::write(
            &policy,
            "schema_version: 1\npermissions:\n  allow:\n    - \"Read(~/**)\"\n  deny: []\n",
        )
        .unwrap();
        std::fs::set_permissions(&policy, std::fs::Permissions::from_mode(0o640)).unwrap();
        let us = &maknae_config::BasicPolicy;
        let authorizer = Arc::new(crate::Composition::new(
            maknae_authz_basic::HermeticAuthorizer::new(
                maknae_authz_basic::PolicyPaths::in_dir(&dir.0),
                maknae_config::Principal {
                    name: "operator".into(),
                    uid,
                },
                maknae_config::TargetRequired {
                    owner: None,
                    mode_mask: Some(0o022),
                    nlink_exactly_one: false,
                    regular_file: true,
                    max_bytes: None,
                },
                maknae_state::envelope::sha256,
            )
            .unwrap(),
            crate::CeilingAuthorizer::new(maknae_config::Ceiling::baseline_for(us), us),
        ));
        let held = crate::authz::home_resolver()
            .claim(uid)
            .expect("the euid's home slot is free");

        for verb in [Verb::Ping, Verb::Whoami] {
            let before = crate::authz::home_resolver().entered(uid);
            let (result, _) = serve(verb.clone(), uid, &user, &dir.0, authorizer.clone()).await;
            assert!(
                matches!(
                    result,
                    RespResult::Ok(maknae_proto::Payload::Pong)
                        | RespResult::Ok(maknae_proto::Payload::Whoami(_))
                ),
                "{verb:?}: {result:?}"
            );
            assert_eq!(
                crate::authz::home_resolver().entered(uid),
                before,
                "{verb:?} never resolves the home"
            );
        }

        let before = crate::authz::home_resolver().entered(uid);
        let read = Verb::Read {
            path: dir.0.join("x").to_str().unwrap().into(),
            conversation: None,
            page: None,
        };
        let (result, records) = serve(read, uid, &user, &dir.0, authorizer).await;
        assert!(matches!(result, RespResult::Err(_)), "{result:?}");
        assert_eq!(crate::authz::home_resolver().entered(uid), before + 1);
        assert_eq!(
            records.last().expect("a request record").outcome.reason,
            crate::authz::HomeUnavailable::RequesterAtCapacity.reason()
        );
        drop(held);
    }
}

#[cfg(test)]
mod admission_bound_tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use tokio::io::AsyncReadExt;

    struct SlowAdmission {
        delay: Duration,
        bounded_calls: AtomicUsize,
    }
    impl AuditEmit for SlowAdmission {
        fn emit(
            &self,
            rec: &AuditRecord,
        ) -> impl std::future::Future<Output = Result<(), maknae_audit_append::AuditError>> + Send
        {
            let admission = rec.event == "connection";
            async move {
                if admission {
                    std::future::pending::<()>().await;
                }
                Ok(())
            }
        }
        fn emit_within(
            &self,
            rec: &AuditRecord,
            bound: Duration,
        ) -> impl std::future::Future<Output = Result<(), maknae_audit_append::AuditError>> + Send
        {
            self.bounded_calls.fetch_add(1, Ordering::SeqCst);
            let delay = if rec.event == "connection" {
                self.delay
            } else {
                Duration::ZERO
            };
            async move {
                match tokio::time::timeout(bound, tokio::time::sleep(delay)).await {
                    Ok(()) => Ok(()),
                    Err(_) => Err(maknae_audit_append::AuditError::WritePrimary(
                        "unconfirmed".into(),
                    )),
                }
            }
        }
    }

    fn bound() -> Duration {
        Duration::from_millis(maknae_config::ADMISSION_AUDIT_TIMEOUT_MS)
    }

    async fn drive(in_group: bool, delay: Duration) -> (Vec<u8>, usize, Duration) {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path().canonicalize().unwrap();
        std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700)).unwrap();
        let policy = root.join("authz.yaml");
        std::fs::write(
            &policy,
            "schema_version: 1\npermissions:\n  allow: []\n  deny: []\n",
        )
        .unwrap();
        std::fs::set_permissions(&policy, std::fs::Permissions::from_mode(0o640)).unwrap();
        let uid = nix::unistd::geteuid().as_raw();
        let us = &maknae_config::BasicPolicy;
        let authorizer = Arc::new(crate::Composition::new(
            maknae_authz_basic::HermeticAuthorizer::new(
                maknae_authz_basic::PolicyPaths::in_dir(&root),
                maknae_config::Principal {
                    name: "operator".into(),
                    uid,
                },
                maknae_config::TargetRequired {
                    owner: None,
                    mode_mask: Some(0o022),
                    nlink_exactly_one: false,
                    regular_file: true,
                    max_bytes: None,
                },
                maknae_state::envelope::sha256,
            )
            .unwrap(),
            crate::CeilingAuthorizer::new(maknae_config::Ceiling::baseline_for(us), us),
        ));
        let (mut client, server) = tokio::io::duplex(256 * 1024);
        let verb = Verb::Ping;
        let body = maknae_proto::encode_request(&maknae_proto::Request {
            protocol_version: PROTOCOL_VERSION,
            verb: verb.clone(),
        })
        .unwrap();
        maknae_proto::write_frame(&mut client, maknae_proto::class_of(&verb), &body)
            .await
            .unwrap();
        let emit = Arc::new(SlowAdmission {
            delay,
            bounded_calls: AtomicUsize::new(0),
        });
        let backend_name = Arc::new(maknae_security::guarded_backend_name(&*authorizer));
        let t0 = tokio::time::Instant::now();
        tokio::time::timeout(
            Duration::from_secs(120),
            handle(
                server,
                "maknae://d/plane/cli".to_string(),
                uid,
                in_group,
                Some("operator".to_string()),
                Some(root.clone()),
                emit.clone(),
                1,
                maknae_config::transport_from_section(None).unwrap(),
                serde_json::json!({}),
                authorizer,
                std::sync::Arc::new(crate::live::LiveConfig::new(ConfigView::default(), None)),
                backend_name,
                Arc::new("US".to_string()),
                Arc::new(None),
                crate::egress::unavailable_egress(),
                Duration::from_secs(10),
                maknae_security::Lane::Local,
                maknae_io::DelegatedFds::new(1),
                baseline_stub::no_baseline(),
            ),
        )
        .await
        .expect("handle returns within the wrapper");
        let elapsed = t0.elapsed();
        let mut rest = Vec::new();
        client.read_to_end(&mut rest).await.unwrap();
        let calls = emit.bounded_calls.load(Ordering::SeqCst);
        (rest, calls, elapsed)
    }

    #[tokio::test(start_paused = true)]
    async fn an_admission_append_slower_than_its_bound_closes_without_serving() {
        let (buf, calls, elapsed) = drive(true, Duration::from_secs(60)).await;
        assert!(elapsed < bound() + Duration::from_secs(1), "{elapsed:?}");
        assert!(buf.is_empty(), "no response frame was written");
        assert!(calls >= 1);
    }

    #[tokio::test(start_paused = true)]
    async fn an_admission_append_inside_its_bound_is_served() {
        let (buf, calls, _) = drive(true, bound() - Duration::from_millis(1)).await;
        assert!(!buf.is_empty(), "a reply frame was written");
        assert!(calls >= 1);
    }

    #[tokio::test(start_paused = true)]
    async fn a_deny_paths_admission_append_is_bounded_too() {
        let (buf, calls, elapsed) = drive(false, Duration::from_secs(60)).await;
        assert!(elapsed < bound() + Duration::from_secs(1), "{elapsed:?}");
        assert!(buf.is_empty());
        assert!(calls >= 1);
    }

    struct StalledPlain {
        bounded: std::sync::Mutex<Vec<String>>,
    }
    impl AuditEmit for StalledPlain {
        fn emit(
            &self,
            _rec: &AuditRecord,
        ) -> impl std::future::Future<Output = Result<(), maknae_audit_append::AuditError>> + Send
        {
            std::future::pending()
        }
        fn emit_within(
            &self,
            rec: &AuditRecord,
            _bound: Duration,
        ) -> impl std::future::Future<Output = Result<(), maknae_audit_append::AuditError>> + Send
        {
            self.bounded
                .lock()
                .unwrap()
                .push(rec.outcome.reason.clone());
            std::future::ready(Ok(()))
        }
    }

    #[tokio::test(start_paused = true)]
    async fn a_stalled_refusal_append_does_not_stop_later_records_or_the_summary() {
        let emit = Arc::new(StalledPlain {
            bounded: std::sync::Mutex::new(Vec::new()),
        });
        let (tx, rx) = mpsc::channel::<AuditRecord>(4);
        let rec = |msg: &str| {
            make_record(
                "connection",
                "h",
                "s",
                1,
                None,
                None,
                None,
                1,
                1,
                "connect",
                None,
                "deny",
                msg,
                "unauthorized",
                &serde_json::json!({}),
            )
        };
        tx.send(rec("first")).await.unwrap();
        tx.send(rec("second")).await.unwrap();
        drop(tx);
        let dropped = Arc::new(std::sync::atomic::AtomicU64::new(3));
        let wctx = WhereCtx {
            host: "h".into(),
            socket: "s".into(),
            au3_1: serde_json::json!({}),
        };
        tokio::time::timeout(
            Duration::from_secs(60),
            drain_refusal_audit(
                rx,
                Arc::clone(&emit),
                dropped,
                Arc::new(SessionIds::new()),
                wctx,
            ),
        )
        .await
        .expect("the drain finishes despite a plain emit that never resolves");
        let seen = emit.bounded.lock().unwrap().clone();
        assert_eq!(seen.len(), 3, "{seen:?}");
        assert_eq!(seen[0], "first");
        assert!(seen[1].contains("3 connection-refusal records dropped"));
        assert_eq!(seen[2], "second");
    }

    #[tokio::test(start_paused = true)]
    async fn a_cert_half_rejection_append_is_bounded() {
        let emit = SlowAdmission {
            delay: Duration::from_secs(60),
            bounded_calls: AtomicUsize::new(0),
        };
        let rec = make_record(
            "connection",
            "h",
            "s",
            1,
            None,
            None,
            None,
            1,
            1,
            "connect",
            None,
            "deny",
            "r",
            "unauthorized",
            &serde_json::json!({}),
        );
        let t0 = tokio::time::Instant::now();
        tokio::time::timeout(
            Duration::from_secs(120),
            audit_cert_half_reject(&emit, &rec, 1),
        )
        .await
        .expect("returns within the wrapper");
        assert!(t0.elapsed() < bound() + Duration::from_secs(1));
        assert_eq!(emit.bounded_calls.load(Ordering::SeqCst), 1);
    }
}

#[cfg(test)]
mod graph_audit_bound_tests {
    use super::*;
    use maknae_audit_append::AuditError;

    struct Stall;

    impl AuditEmit for Stall {
        fn emit(&self, _: &AuditRecord) -> impl Future<Output = Result<(), AuditError>> + Send {
            std::future::pending()
        }
    }

    const OUTER: Duration = Duration::from_secs(60);

    fn audit<'a>(ctx: &'a BootCtx<'a>) -> GraphBootAudit<'a, Stall> {
        GraphBootAudit {
            sink: &Stall,
            ctx,
            scanned_bytes: 0,
            bound: Duration::from_millis(100),
            drain: None,
        }
    }

    /// Production lines of `files` that call `.emit(`, `::emit(` or `.append(`;
    /// column-0 `#[cfg(test)]` modules and comment lines are skipped.
    fn unbounded_appends(files: &[(String, String)]) -> Vec<(String, String)> {
        let mut found = Vec::new();
        for (name, src) in files {
            let lines: Vec<&str> = src.lines().collect();
            let mut i = 0;
            while i < lines.len() {
                let mut j = i;
                while j < lines.len() && lines[j].starts_with("#[") {
                    j += 1;
                }
                let test_mod = j > i
                    && lines[i..j].contains(&"#[cfg(test)]")
                    && lines
                        .get(j)
                        .is_some_and(|l| l.starts_with("mod ") && l.ends_with('{'));
                if test_mod {
                    i = j + lines[j..]
                        .iter()
                        .position(|l| *l == "}")
                        .map_or(lines.len(), |k| k + 1);
                    continue;
                }
                let line = lines[i].trim();
                if !line.starts_with("//")
                    && [".emit(", "::emit(", ".append("]
                        .iter()
                        .any(|p| line.contains(p))
                {
                    found.push((name.clone(), line.to_string()));
                }
                i += 1;
            }
        }
        found
    }

    fn kernel_sources(dir: &Path, out: &mut Vec<(String, String)>) {
        let mut entries: Vec<_> = std::fs::read_dir(dir)
            .unwrap()
            .map(|e| e.unwrap().path())
            .collect();
        entries.sort();
        for path in entries {
            if path.is_dir() {
                kernel_sources(&path, out);
            } else if path.extension().is_some_and(|e| e == "rs") {
                out.push((
                    path.strip_prefix(env!("CARGO_MANIFEST_DIR"))
                        .unwrap()
                        .display()
                        .to_string(),
                    std::fs::read_to_string(&path).unwrap(),
                ));
            }
        }
    }

    #[test]
    fn every_unbounded_append_in_the_kernel_is_one_bounded_by_its_caller() {
        let mut files = Vec::new();
        kernel_sources(
            &Path::new(env!("CARGO_MANIFEST_DIR")).join("src"),
            &mut files,
        );
        assert!(files.len() > 10, "{files:?}");
        let found = unbounded_appends(&files);
        let found: Vec<(&str, &str)> = found
            .iter()
            .map(|(f, l)| (f.as_str(), l.as_str()))
            .collect();
        assert_eq!(
            found,
            [
                ("src/mutation.rs", "tokio::time::timeout_at(deadline, emit.emit(&record)).await,"),
                ("src/mutation.rs", "emit.emit(&record),"),
                (
                    "src/run.rs",
                    "match tokio::time::timeout(AUDIT_DRAIN_SHUTDOWN_TIMEOUT, emit.emit(&stop)).await {"
                ),
            ]
        );
    }

    #[test]
    fn the_append_scan_sees_every_spelling_in_any_file_and_skips_test_modules() {
        let files = [
            (
                "src/other.rs".to_string(),
                "fn f() {\n    AuditEmit::emit(&*sink, &rec).await;\n    sink.append(&rec).await?;\n    // sink.emit(&rec)\n    sink.emit_within(&rec, b).await?;\n}\n#[cfg(unix)]\n#[cfg(test)]\nmod tests {\n    fn t() { sink.emit(&rec); }\n}\nfn g() { s.emit(&r); }\n".to_string(),
            ),
        ];
        let found = unbounded_appends(&files);
        let found: Vec<&str> = found.iter().map(|(_, l)| l.as_str()).collect();
        assert_eq!(
            found,
            [
                "AuditEmit::emit(&*sink, &rec).await;",
                "sink.append(&rec).await?;",
                "fn g() { s.emit(&r); }"
            ]
        );
    }

    #[tokio::test(start_paused = true)]
    async fn a_stalled_boot_record_refuses_within_the_bound() {
        let seq = Seq::new();
        let au3 = serde_json::json!({});
        let ctx = BootCtx {
            event: "boot",
            host: "h",
            socket: "s",
            euid: 0,
            session_id: 1,
            seq: &seq,
            au3_1: &au3,
        };
        let released = [maknae_graph::identity::Released {
            uid: 7,
            name: "mallory".into(),
            cause: maknae_graph::identity::ReleaseCause::NotListed,
        }];
        let events = ["baseline seeded".to_string()];
        let mut a = audit(&ctx);
        let got = tokio::time::timeout(OUTER, a.checkpoint(1, [0; 32], "seeded")).await;
        assert!(matches!(got, Ok(Err(StoreError::Audit(_)))), "{got:?}");
        let got = tokio::time::timeout(OUTER, a.released(1, &released)).await;
        assert!(matches!(got, Ok(Err(StoreError::Audit(_)))), "{got:?}");
        let got = tokio::time::timeout(OUTER, a.baseline(1, &events)).await;
        assert!(matches!(got, Ok(Err(StoreError::Audit(_)))), "{got:?}");
    }

    #[tokio::test(start_paused = true)]
    async fn every_boot_refusal_record_gives_up_after_the_append_bound() {
        let au3 = serde_json::json!({});
        let authz = tokio::time::timeout(
            OUTER,
            refuse_authz_boot(&Stall, "h", "s", 0, 1, 1, &au3, "no principal".into()),
        )
        .await;
        assert!(matches!(authz, Ok(RunError::Authz(_))), "{authz:?}");
        let offload = tokio::time::timeout(
            OUTER,
            refuse_audit_offload_boot(&Stall, "h", "s", 0, 1, 2, &au3, "siem".into()),
        )
        .await;
        assert!(
            matches!(offload, Ok(RunError::AuditOffload(_))),
            "{offload:?}"
        );
        let failed: Result<ServeOutcome, RunError> = Err(RunError::Other("bind".into()));
        let start = tokio::time::timeout(
            OUTER,
            record_start_refusal(&Stall, "h", "s", 0, 1, 3, &au3, &failed),
        )
        .await;
        assert!(start.is_ok(), "the start refusal waited past its bound");
    }

    #[tokio::test(start_paused = true)]
    async fn every_request_record_gives_up_after_the_append_bound_and_withholds_the_frame() {
        let au3 = serde_json::json!({});
        let stall = Arc::new(Stall);
        let rec = make_record(
            "request",
            "h",
            "s",
            7,
            None,
            None,
            Some("uri"),
            1,
            1,
            "whoami",
            None,
            "permit",
            "ok",
            "authorized",
            &au3,
        );
        let reported =
            tokio::time::timeout(OUTER, emit_or_report(&stall, &rec, "a response", 7, 1)).await;
        assert_eq!(reported, Ok(false));
        let outcome = tokio::time::timeout(
            OUTER,
            emit_request_outcome(
                &stall,
                "h",
                "s",
                7,
                "uri",
                None,
                None,
                None,
                1,
                2,
                "whoami",
                None,
                None,
                "permit",
                "ok",
                "authorized",
                &au3,
            ),
        )
        .await;
        assert_eq!(outcome, Ok(false));
        let deny = tokio::time::timeout(
            OUTER,
            emit_request_deny(
                &stall, "h", "s", 7, "uri", None, None, 1, 3, "whoami", "no", &au3,
            ),
        )
        .await;
        assert!(deny.is_ok(), "the deny record waited past its bound");
    }

    fn report(marker_ignored: Option<String>, rejected: Option<String>) -> BootReport {
        BootReport {
            revision: 1,
            digest: [0; 32],
            outcome: BootOutcome::Seeded {
                authorized: false,
                rejected,
            },
            graph: maknae_graph::graph::GraphBuilder::new(
                maknae_graph::record::GraphSpace::Kernel,
                1,
            )
            .build(
                &maknae_graph::kernel::SCHEMA,
                &maknae_graph::schema::CompiledSet::default(),
            )
            .unwrap(),
            marker_ignored,
            migration: None,
            identity_transition: false,
            baseline_transition: false,
            released: Vec::new(),
            principal_admin: None,
            durability_error: None,
        }
    }

    #[tokio::test(start_paused = true)]
    async fn the_boot_reseed_and_rejected_store_records_give_up_after_the_append_bound() {
        let seq = Seq::new();
        let au3 = serde_json::json!({});
        let ctx = BootCtx {
            event: "boot",
            host: "h",
            socket: "s",
            euid: 0,
            session_id: 1,
            seq: &seq,
            au3_1: &au3,
        };
        for r in [
            report(Some("not root-owned".into()), None),
            report(None, Some("moved aside".into())),
        ] {
            let got =
                tokio::time::timeout(OUTER, report_graph_boot(&Stall, &ctx, Path::new("/s"), &r))
                    .await;
            assert!(matches!(got, Ok(Err(RunError::Other(_)))), "{got:?}");
        }
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_stalled_rollback_anchor_scan_refuses_within_the_bound() {
        let (tx, rx) = std::sync::mpsc::channel::<()>();
        let got = tokio::time::timeout(
            Duration::from_secs(2),
            scan_anchor(Duration::from_millis(50), move || {
                let _ = rx.recv_timeout(Duration::from_secs(5));
                Err(AuditError::ReadPrimary("released".into()))
            }),
        )
        .await;
        drop(tx);
        let refused = got.expect("the scan must give up within its bound");
        assert!(
            matches!(&refused, Err(GraphFailure::ScanElapsed(m)) if m.starts_with("rollback anchor scan")),
            "{refused:?}"
        );
        let RunError::Graph { reason, hint } = graph_refusal(refused.unwrap_err(), Path::new("/s"))
        else {
            panic!("a scan elapse is a graph refusal");
        };
        assert!(
            reason.starts_with("kernel graph store: rollback anchor scan"),
            "{reason}"
        );
        assert!(
            hint.contains("did not scan within 30s")
                && hint.contains("Rotate, restore or recreate the trail"),
            "{hint}"
        );
    }

    #[tokio::test]
    async fn a_completed_scan_passes_its_result_and_its_error_through() {
        let ok = scan_anchor(Duration::from_secs(5), || {
            Ok(maknae_audit_append::ScanResult {
                line: None,
                scanned_bytes: 9,
            })
        })
        .await
        .unwrap();
        assert_eq!(ok.scanned_bytes, 9);
        let err = scan_anchor(Duration::from_secs(5), || {
            Err(AuditError::ReadPrimary("eio".into()))
        })
        .await
        .unwrap_err();
        assert!(
            matches!(&err, GraphFailure::Store(StoreError::Audit(m)) if m.contains("eio")),
            "{err:?}"
        );
    }
}

#[cfg(unix)]
#[cfg(test)]
mod reload_fixture {
    use super::boot_gate_tests::{boot_graph_at, TestEnv};
    use super::*;
    use maknae_authz_basic::{Baseline, HermeticAuthorizer};
    use std::os::unix::fs::PermissionsExt;

    pub(super) const AUTHZ: &str = "schema_version: 1\n";
    pub(super) const ROOT_ADMIN: &str = "schema_version: 1\nbindings:\n  admin: [\"root\"]\n";
    const VAULT_ADDR_MARKER: &str = "vault_addr_marker: ";

    pub(super) struct Fx {
        pub(super) dir: PathBuf,
        pub(super) reloader: Arc<Reloader<HermeticAuthorizer, ReloadSink>>,
        pub(super) status: KernelGraphStatus,
        pub(super) booted_released: usize,
        pub(super) _guard: Guard,
    }

    /// A record the reload forwarded, with the store file's sha256 at that moment.
    #[derive(Debug, Clone)]
    pub(super) struct Seen {
        pub(super) action: String,
        pub(super) reason: String,
        pub(super) drain: Drain,
        pub(super) store: String,
    }

    pub(super) struct ReloadSink {
        pub(super) inner: Arc<maknae_audit_append::AuditSink>,
        pub(super) fail_identity: std::sync::atomic::AtomicBool,
        pub(super) fail_baseline: std::sync::atomic::AtomicBool,
        pub(super) stall: std::sync::Mutex<fn(&AuditRecord) -> bool>,
        pub(super) stalled: std::sync::atomic::AtomicUsize,
        store: PathBuf,
        seen: std::sync::Mutex<Vec<Seen>>,
        /// Refuses every record of this action.
        pub(super) refuse: std::sync::Mutex<Option<&'static str>>,
        /// Each record waits this long before it is appended.
        pub(super) delay: Duration,
        drain: std::sync::Mutex<Option<tokio::sync::watch::Receiver<Drain>>>,
    }

    impl ReloadSink {
        pub(super) fn stall_when(&self, when: fn(&AuditRecord) -> bool) {
            *self.stall.lock().unwrap() = when;
        }
    }

    pub(super) fn never(_: &AuditRecord) -> bool {
        false
    }

    pub(super) fn is_reload(r: &AuditRecord) -> bool {
        r.action == GRAPH_RELOAD_ACTION
    }

    pub(super) fn is_reload_outcome(r: &AuditRecord) -> bool {
        r.action == GRAPH_RELOAD_ACTION && r.graph.as_ref().is_some_and(|g| g.anchor != "reloading")
    }

    pub(super) fn is_transition(r: &AuditRecord) -> bool {
        r.action == GRAPH_TRANSITION_ACTION
    }

    pub(super) fn is_identity(r: &AuditRecord) -> bool {
        r.action == GRAPH_IDENTITY_ACTION
    }

    fn file_sha(path: &Path) -> String {
        std::fs::read(path)
            .map(|b| lower_hex(&maknae_state::envelope::sha256(&b)))
            .unwrap_or_default()
    }

    impl AuditEmit for ReloadSink {
        fn emit(
            &self,
            rec: &AuditRecord,
        ) -> impl std::future::Future<Output = Result<(), maknae_audit_append::AuditError>> + Send
        {
            let fail = (rec.action == GRAPH_IDENTITY_ACTION
                && self.fail_identity.load(std::sync::atomic::Ordering::SeqCst))
                || (rec.action == GRAPH_BASELINE_ACTION
                    && self.fail_baseline.load(std::sync::atomic::Ordering::SeqCst))
                || *self.refuse.lock().unwrap() == Some(rec.action.as_str());
            let stall = (*self.stall.lock().unwrap())(rec);
            if stall {
                self.stalled
                    .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            }
            if !stall && !fail {
                self.seen.lock().unwrap().push(Seen {
                    action: rec.action.clone(),
                    reason: rec.outcome.reason.clone(),
                    drain: self
                        .drain
                        .lock()
                        .unwrap()
                        .as_ref()
                        .map_or(Drain::Serving, |d| *d.borrow()),
                    store: file_sha(&self.store),
                });
            }
            let inner = Arc::clone(&self.inner);
            let rec = rec.clone();
            let delay = self.delay;
            async move {
                tokio::time::sleep(delay).await;
                if stall {
                    std::future::pending::<()>().await;
                }
                if fail {
                    return Err(maknae_audit_append::AuditError::WritePrimary(
                        "identity append refused".into(),
                    ));
                }
                inner.emit(&rec).await
            }
        }
    }

    /// Removes the fixture's directory, unless it belongs to another fixture.
    pub(super) struct Guard(Option<PathBuf>);

    impl Drop for Guard {
        fn drop(&mut self) {
            if let Some(dir) = &self.0 {
                let _ = std::fs::remove_dir_all(dir);
            }
        }
    }

    pub(super) fn requirement() -> maknae_config::TargetRequired {
        maknae_config::TargetRequired {
            owner: None,
            mode_mask: Some(0o022),
            nlink_exactly_one: false,
            regular_file: true,
            max_bytes: None,
        }
    }

    pub(super) fn principal() -> maknae_config::Principal {
        maknae_config::Principal {
            name: "op".into(),
            uid: nix::unistd::geteuid().as_raw(),
        }
    }

    /// The fixture's `maknae.yaml`: `core_extra` under `core:`, then `tail`, whose lines
    /// named by a marker (`vault_addr_marker: `, `socket_path_marker: `, ...) set that
    /// value instead of being appended.
    fn yaml(dir: &Path, core_extra: &str, tail: &str) -> String {
        yaml_for(dir, core_extra, tail, nix::unistd::geteuid().as_raw())
    }

    fn yaml_for(dir: &Path, core_extra: &str, tail: &str, uid: u32) -> String {
        let mut vault_addr = "https://v.example:8200".to_string();
        let mut socket = dir.join("maknaed.sock").display().to_string();
        let mut trail = dir.join("audit.jsonl").display().to_string();
        let (mut transport, mut audit, mut rest) = (String::new(), String::new(), String::new());
        for line in tail.lines() {
            if let Some(v) = line.strip_prefix(VAULT_ADDR_MARKER) {
                vault_addr = v.to_string();
            } else if let Some(v) = line.strip_prefix("transport_tail_max_connections: ") {
                transport.push_str(&format!("  max_connections: {v}\n"));
            } else if let Some(v) = line.strip_prefix("socket_path_marker: ") {
                socket = v.to_string();
            } else if let Some(v) = line.strip_prefix("audit_path_marker: ") {
                trail = v.to_string();
            } else if let Some(v) = line.strip_prefix("audit_readers_marker: ") {
                audit.push_str(&format!("  readers: {v}\n"));
            } else {
                rest.push_str(line);
                rest.push('\n');
            }
        }
        format!(
            "core:\n  deployment_id: dev-01\n{core_extra}vault:\n  addr: {vault_addr}\ntransport:\n  socket_path: {socket}\n{transport}audit:\n  jsonl_path: {trail}\n{audit}principal:\n  name: op\n  uid: {uid}\n{rest}",
        )
    }

    impl Fx {
        pub(super) async fn with_baseline(tag: &str) -> Fx {
            fixture(tag, AUTHZ, Some(ROOT_ADMIN)).await
        }

        /// Boots with `core_extra` (a full `handling:` block) already accepted.
        pub(super) async fn with_core(tag: &str, core_extra: &str) -> Fx {
            let opts = Opts {
                core: core_extra,
                ..Opts::default()
            };
            fixture_with(tag, opts).await
        }

        pub(super) async fn with_baseline_env(tag: &str, env: TestEnv) -> Fx {
            let opts = Opts {
                env,
                ..Opts::default()
            };
            fixture_with(tag, opts).await
        }

        /// Boots with `tail` already in the file, the egress bounds in place.
        pub(super) async fn with_baseline_yaml(tag: &str, tail: &str) -> Fx {
            let opts = Opts {
                env: TestEnv::with_bounds(),
                tail,
                ..Opts::default()
            };
            fixture_with(tag, opts).await
        }

        /// Every record waits `delay` before it appends, bounded by `bound`.
        pub(super) async fn with_baseline_and_delay(
            tag: &str,
            delay: Duration,
            bound: Duration,
        ) -> Fx {
            let opts = Opts {
                delay,
                bound,
                ..Opts::default()
            };
            fixture_with(tag, opts).await
        }

        pub(super) async fn show(&self) -> maknae_proto::BaselineView {
            BaselineOps::show(self.reloader.as_ref()).await.unwrap()
        }

        pub(super) async fn accept(&self, hash: &str) -> AcceptAnswer {
            BaselineOps::accept(self.reloader.as_ref(), hash).await
        }

        pub(super) fn drain(&self) -> Drain {
            *self.reloader.drain.borrow()
        }

        pub(super) fn refuse(&self, action: &'static str) {
            *self.reloader.sink.refuse.lock().unwrap() = Some(action);
        }

        pub(super) fn composition(&self) -> &crate::Composition<HermeticAuthorizer> {
            &self.reloader.authorizer
        }

        pub(super) fn live(&self) -> &Arc<crate::live::LiveConfig> {
            self.reloader.authorizer.live()
        }

        pub(super) fn write_yaml_principal(&self, uid: u32, tail: &str) {
            write_0640(
                &self.dir.join("maknae.yaml"),
                &yaml_for(&self.dir, "", tail, uid),
            );
        }

        /// An empty, 0640 trail beside the fixture's own; the test env reports it prepared.
        pub(super) fn prepare_trail(&self, name: &str) -> PathBuf {
            let path = self.dir.join(name);
            write_0640(&path, "");
            path
        }

        pub(super) fn state_dir(&self) -> PathBuf {
            self.dir.join("state")
        }

        pub(super) fn policy(&self) -> PathBuf {
            self.dir.join("authz.yaml")
        }

        pub(super) fn bindings(&self) -> PathBuf {
            self.dir.join("bindings.yaml")
        }

        pub(super) fn write_policy(&self, body: &str) {
            write_0640(&self.policy(), body);
        }

        pub(super) fn write_bindings(&self, body: &str) {
            write_0640(&self.bindings(), body);
        }

        pub(super) fn write_yaml(&self, core_extra: &str, tail: &str) {
            write_0640(
                &self.dir.join("maknae.yaml"),
                &yaml(&self.dir, core_extra, tail),
            );
        }

        pub(super) fn store_bytes(&self) -> Vec<u8> {
            std::fs::read(self.dir.join("state").join(STORE_FILE)).unwrap()
        }

        pub(super) fn store_sha(&self) -> String {
            file_sha(&self.dir.join("state").join(STORE_FILE))
        }

        pub(super) fn stored(&self) -> Option<BaselineLayer> {
            maknae_state::store::peek_baseline(&self.reloader.dir, &self.reloader.key).unwrap()
        }

        pub(super) fn seen(&self) -> Vec<Seen> {
            self.reloader.sink.seen.lock().unwrap().clone()
        }

        pub(super) fn status_lines(&self) -> Vec<String> {
            self.reloader.baseline.lines()
        }

        pub(super) fn set_persisted(&self, graph: Arc<maknae_graph::graph::Graph>) {
            *self.reloader.persisted.write().unwrap() = graph;
        }

        pub(super) fn reload_records(&self) -> Vec<AuditRecord> {
            std::fs::read_to_string(self.dir.join("audit.jsonl"))
                .unwrap()
                .lines()
                .map(|l| serde_json::from_str::<AuditRecord>(l).unwrap())
                .filter(|r| r.event == "reload")
                .collect()
        }

        pub(super) fn baseline(&self) -> &HermeticAuthorizer {
            self.reloader.authorizer.baseline()
        }

        pub(super) fn root_whoami(&self) -> maknae_security::Verdict {
            self.reloader
                .authorizer
                .decide(&crate::handler::build_authz_request(
                    &Verb::Whoami,
                    0,
                    None,
                    maknae_security::Lane::Local,
                    None,
                ))
        }
    }

    pub(super) fn write_0640(path: &Path, body: &str) {
        std::fs::write(path, body).unwrap();
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o640)).unwrap();
    }

    pub(super) async fn fixture(tag: &str, authz: &str, bindings: Option<&str>) -> Fx {
        fixture_gated(tag, authz, bindings, None).await
    }

    pub(super) async fn fixture_gated(
        tag: &str,
        authz: &str,
        bindings: Option<&str>,
        load_gate: Option<std::sync::mpsc::Receiver<()>>,
    ) -> Fx {
        fixture_seeded(tag, authz, bindings, load_gate, None).await
    }

    pub(super) type Seed =
        fn(&maknae_graph::identity::IdentityLayer) -> maknae_graph::identity::IdentityLayer;

    /// The baseline a start over the fixture's files would seed.
    pub(super) fn files_baseline(
        dir: &Path,
        env: &dyn crate::baseline_check::Env,
    ) -> BaselineLayer {
        let file = baseline_file(dir, crate::boot::read_files_as_owner, env, None).unwrap();
        let start = crate::baseline::at_boot(None, Ok(file), |_| Ok(())).unwrap();
        let doc = maknae_config::Document::from_baseline(&start.run).unwrap();
        let v = crate::baseline_check::validate(doc, crate::baseline_check::Mode::Boot, dir, env)
            .unwrap();
        run_baseline(&start.run, crate::baseline_check::classification_of(&v))
    }

    /// `seed` first boots the store with the layer it returns for the file's own.
    pub(super) async fn fixture_seeded(
        tag: &str,
        authz: &str,
        bindings: Option<&str>,
        load_gate: Option<std::sync::mpsc::Receiver<()>>,
        seed: Option<Seed>,
    ) -> Fx {
        let opts = Opts {
            authz,
            bindings,
            load_gate,
            seed,
            ..Opts::default()
        };
        fixture_with(tag, opts).await
    }

    pub(super) struct Opts<'a> {
        pub(super) authz: &'a str,
        pub(super) bindings: Option<&'a str>,
        pub(super) load_gate: Option<std::sync::mpsc::Receiver<()>>,
        pub(super) seed: Option<Seed>,
        pub(super) env: TestEnv,
        pub(super) core: &'a str,
        pub(super) tail: &'a str,
        pub(super) delay: Duration,
        pub(super) bound: Duration,
    }

    impl Default for Opts<'_> {
        fn default() -> Self {
            Opts {
                authz: AUTHZ,
                bindings: Some(ROOT_ADMIN),
                load_gate: None,
                seed: None,
                env: TestEnv::default(),
                core: "",
                tail: "",
                delay: Duration::ZERO,
                bound: Duration::from_millis(200),
            }
        }
    }

    pub(super) async fn fixture_with(tag: &str, opts: Opts<'_>) -> Fx {
        let raw = std::env::temp_dir().join(format!("maknae_reload_{tag}_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&raw);
        std::fs::create_dir_all(raw.join("state")).unwrap();
        let dir = raw.canonicalize().unwrap();
        for d in [&dir, &dir.join("state")] {
            std::fs::set_permissions(d, std::fs::Permissions::from_mode(0o700)).unwrap();
        }
        let sink = Arc::new(
            maknae_audit_append::AuditSink::open(&maknae_config::AuditConfig {
                readers: Vec::new(),
                jsonl_path: dir.join("audit.jsonl"),
                siem: None,
                au3_1: serde_json::Value::Null,
            })
            .unwrap(),
        );
        write_0640(&dir.join("maknae.yaml"), &yaml(&dir, opts.core, opts.tail));
        let layer = files_baseline(&dir, &opts.env);
        let paths = maknae_authz_basic::PolicyPaths::in_dir(&dir);
        write_0640(&paths.authz, opts.authz);
        if let Some(b) = opts.bindings {
            write_0640(&paths.bindings, b);
        }
        assemble(dir.clone(), Some(dir), sink, layer, principal(), opts).await
    }

    /// A fixture over a start's existing configuration and state directories, running
    /// the baseline its store holds.
    pub(super) async fn over(dir: &Path, principal: maknae_config::Principal) -> Fx {
        let sink = Arc::new(
            maknae_audit_append::AuditSink::open_existing(&maknae_config::AuditConfig {
                readers: Vec::new(),
                jsonl_path: dir.join("audit.jsonl"),
                siem: None,
                au3_1: serde_json::Value::Null,
            })
            .unwrap(),
        );
        let state = StateDir::open(&dir.join("state"), nix::unistd::geteuid().as_raw()).unwrap();
        let key = WrappingKey::new(
            maknae_vault::graph_key_from_bytes(&[0x5a; 32])
                .unwrap()
                .into_bytes(),
        );
        let layer = maknae_state::store::peek_baseline(&state, &key)
            .unwrap()
            .unwrap();
        drop(state);
        let opts = Opts {
            bindings: None,
            ..Opts::default()
        };
        assemble(dir.to_path_buf(), None, sink, layer, principal, opts).await
    }

    async fn assemble(
        dir: PathBuf,
        owned: Option<PathBuf>,
        sink: Arc<maknae_audit_append::AuditSink>,
        layer: BaselineLayer,
        principal: maknae_config::Principal,
        opts: Opts<'_>,
    ) -> Fx {
        let paths = maknae_authz_basic::PolicyPaths::in_dir(&dir);
        let source = maknae_authz_basic::PolicySource::load_with_requirement(
            paths.clone(),
            principal.clone(),
            requirement(),
        )
        .unwrap();
        let inputs = GraphInputs::new(&source, "UNCLASSIFIED", layer.clone()).unwrap();
        let seq = Seq::new();
        let au3_1 = serde_json::Value::Null;
        let euid = nix::unistd::geteuid().as_raw();
        let ctx = BootCtx {
            event: "boot",
            host: "h",
            socket: "s",
            euid,
            session_id: 9 << 32,
            seq: &seq,
            au3_1: &au3_1,
        };
        if let Some(seed) = opts.seed {
            let seeded = seed(&inputs.identity);
            drop(
                boot_graph_at(
                    &dir.join("state"),
                    maknae_vault::graph_key_from_bytes(&[0x5a; 32]),
                    &sink,
                    &ctx,
                    &BootInputs {
                        identity: &seeded,
                        ..inputs.boot()
                    },
                )
                .await
                .unwrap(),
            );
        }
        let booted = boot_graph_at(
            &dir.join("state"),
            maknae_vault::graph_key_from_bytes(&[0x5a; 32]),
            &sink,
            &ctx,
            &inputs.boot(),
        )
        .await
        .unwrap();
        let booted_released = booted.released.len();
        let graph = Arc::new(booted.graph);
        let baseline = HermeticAuthorizer::new_over_graph(
            paths,
            principal,
            requirement(),
            maknae_state::envelope::sha256,
            Arc::clone(&graph),
        )
        .unwrap();
        publish_boot_identity(
            &booted.status.identity,
            &baseline.snapshot(),
            &booted.released,
            booted.principal_admin,
            &sink,
            &ctx,
        )
        .await
        .unwrap();
        let us = &maknae_config::BasicPolicy;
        let authorizer = Arc::new(crate::Composition::new(
            baseline,
            crate::CeilingAuthorizer::new(maknae_config::Ceiling::baseline_for(us), us),
        ));
        let mut status = booted.status;
        status.baseline = crate::baseline::BaselineStatus::new(crate::baseline::BaselineState {
            accepted: layer.sections.clone().into(),
            pending: None,
        });
        let drain = tokio::sync::watch::channel(Drain::Serving).0;
        let reloader = Arc::new(Reloader {
            dir: booted.dir,
            key: booted.key,
            authorizer,
            label: "UNCLASSIFIED".into(),
            vocabulary: inputs.vocabulary,
            revision: Arc::clone(&status.revision),
            lock: tokio::sync::Mutex::new(()),
            sink: Arc::new(ReloadSink {
                inner: sink,
                fail_identity: std::sync::atomic::AtomicBool::new(false),
                fail_baseline: std::sync::atomic::AtomicBool::new(false),
                stall: std::sync::Mutex::new(never),
                stalled: std::sync::atomic::AtomicUsize::new(0),
                store: dir.join("state").join(STORE_FILE),
                seen: std::sync::Mutex::default(),
                refuse: std::sync::Mutex::new(None),
                delay: opts.delay,
                drain: std::sync::Mutex::new(Some(drain.subscribe())),
            }),
            session_ids: Arc::new(SessionIds::new()),
            host: "h".into(),
            socket: "s".into(),
            euid,
            au3_1,
            identity: status.identity.clone(),
            stopping: tokio::sync::watch::channel(false).0,
            append_bound: opts.bound,
            persisted: std::sync::RwLock::new(graph),
            config_dir: dir.clone(),
            files: crate::boot::read_files_as_owner,
            env: Arc::new(opts.env),
            baseline: status.baseline.clone(),
            drain,
            turn_wait: Duration::from_millis(200),
            load_gate: opts.load_gate.map(|g| Arc::new(std::sync::Mutex::new(g))),
        });
        Fx {
            _guard: Guard(owned),
            dir,
            reloader,
            status,
            booted_released,
        }
    }
}

#[cfg(unix)]
#[cfg(test)]
mod baseline_accept_tests {
    use super::boot_gate_tests::TestEnv;
    use super::reload_fixture::*;
    use super::*;
    use maknae_authz_basic::Baseline;
    use std::os::unix::fs::PermissionsExt;

    const SECRET: &str = "  handling:\n    ceiling:\n      classification: SECRET\n      sci: false\n      releasable_to: []\n      cui_permitted: false\n      cui_categories_permitted: []\n      dissemination_permitted: [\"Distribution Statement A\"]\n    accreditation_ref: null\n";
    const ROOT_ADMIN_OTHER: &str =
        "schema_version: 1\nbindings:\n  admin: [\"root\"]\n  guest: []\n";
    const RESTART: &str = "transport_tail_max_connections: 7\n";

    fn unclassified() -> String {
        SECRET.replace("SECRET", "UNCLASSIFIED")
    }

    fn accepted(a: AcceptAnswer) -> maknae_proto::BaselineView {
        match a {
            AcceptAnswer::View {
                view,
                corrective: None,
            } => view,
            other => panic!("expected an accepted view, got {other:?}"),
        }
    }

    fn secret_read() -> maknae_security::Request {
        let mut resource = maknae_security::Attributes::new();
        resource.insert(
            maknae_security::RESOURCE_CLASSIFICATION,
            maknae_security::AttrValue::Str("SECRET".into()),
        );
        maknae_security::Request {
            subject: maknae_security::Subject(maknae_security::Attributes::new()),
            resource: maknae_security::Resource(resource),
            action: maknae_security::Action("fs.read".into()),
            context: maknae_security::Context(maknae_security::Attributes::new()),
        }
    }

    fn ceiling_name(fx: &Fx) -> String {
        fx.composition()
            .ceiling()
            .ceiling()
            .classification
            .name
            .clone()
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_live_ceiling_accept_governs_the_next_decision() {
        let fx = Fx::with_core("live-ceiling", &unclassified()).await;
        let refused =
            maknae_security::Authorizer::decide(fx.composition().ceiling(), &secret_read());
        assert!(
            matches!(refused, maknae_security::Verdict::Deny { .. }),
            "{refused:?}"
        );
        fx.write_yaml(SECRET, "");
        let shown = fx.show().await;
        assert_eq!(
            (shown.state.as_str(), shown.apply.as_str()),
            ("pending", "live")
        );
        let view = accepted(fx.accept(&shown.hash).await);
        assert_eq!(
            (view.state.as_str(), view.apply.as_str()),
            ("accepted", "live")
        );
        assert_eq!(ceiling_name(&fx), "SECRET");
        assert_eq!(
            maknae_security::Authorizer::decide(fx.composition().ceiling(), &secret_read()),
            maknae_security::Verdict::NotApplicable { note: None }
        );
        assert_eq!(fx.drain(), Drain::Serving);
        assert_eq!(fx.stored().unwrap().ceiling, "SECRET");
        assert!(fx.status_lines().is_empty());
        assert_eq!(fx.show().await.state, "none");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_live_principal_and_providers_accept_swaps_both() {
        let one = "providers:\n  - name: openai\n    endpoint: https://api.example.test/v1\n    models: [m]\n";
        let two = "providers:\n  - name: openai\n    endpoint: https://api.example.test/v1\n    models: [m]\n  - name: other\n    endpoint: https://other.example.test/v1\n    models: [n]\n";
        let fx = Fx::with_baseline_yaml("live-principal", one).await;
        let generation = fx.live().generation();
        fx.write_yaml_principal(4242, two);
        let shown = fx.show().await;
        assert_eq!(shown.apply, "live");
        accepted(fx.accept(&shown.hash).await);
        assert_eq!(fx.composition().baseline().principal().uid, 4242);
        assert_eq!(
            fx.live().generation(),
            generation + 1,
            "the request path's holder moved"
        );
        let names: Vec<String> = fx
            .live()
            .providers()
            .as_ref()
            .as_ref()
            .unwrap()
            .set
            .iter()
            .map(|p| p.name.clone())
            .collect();
        assert_eq!(names, ["openai", "other"]);
        assert_eq!(fx.live().view()["principal"]["uid"], "4242");
        fx.write_yaml_principal(4242, "");
        assert_eq!(
            fx.show().await.apply,
            "restart",
            "non-empty to empty providers applies by restart"
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_live_principal_accept_republishes_the_principal_admin() {
        let opts = Opts {
            bindings: None,
            ..Opts::default()
        };
        let fx = fixture_with("principal-admin", opts).await;
        let uid = nix::unistd::geteuid().as_raw().wrapping_add(1);
        fx.write_yaml_principal(uid, "");
        let shown = fx.show().await;
        accepted(fx.accept(&shown.hash).await);
        let promoted = maknae_authz_basic::IdentityProblem::PrincipalAdmin { uid };
        assert!(fx.status.identity.current().contains(&promoted));
        assert!(fx
            .seen()
            .iter()
            .any(|s| s.action == GRAPH_IDENTITY_ACTION && s.reason == promoted.to_string()));
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn an_accept_is_written_ahead() {
        let fx = Fx::with_core("ahead", &unclassified()).await;
        fx.write_yaml(SECRET, "");
        let shown = fx.show().await;
        let before = fx.store_sha();
        accepted(fx.accept(&shown.hash).await);
        let seen = fx.seen();
        let at = |action: &str, prefix: &str| {
            seen.iter()
                .position(|s| s.action == action && s.reason.starts_with(prefix))
                .unwrap_or_else(|| panic!("{action} {prefix}: {seen:?}"))
        };
        let short = crate::baseline::short(&shown.hash);
        let intent = at(
            GRAPH_BASELINE_ACTION,
            &format!(
                "accept intent recorded (operator): sha256:{short}; apply: live; sections: core"
            ),
        );
        let transition = at(GRAPH_TRANSITION_ACTION, "intent recorded (operator)");
        let checkpoint = at(CHECKPOINT_ACTION, "transitioned");
        let outcome = at(
            GRAPH_BASELINE_ACTION,
            &format!("accepted sha256:{short} at revision "),
        );
        assert!(
            !seen.iter().any(|s| s.reason.contains(&shown.hash)),
            "no record carries the full hash"
        );
        assert!(intent < transition && transition < checkpoint && checkpoint < outcome);
        assert_eq!(seen[intent].store, before);
        assert_eq!(seen[transition].store, before);
        assert_ne!(seen[checkpoint].store, before);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_failed_intent_persists_nothing() {
        let fx = Fx::with_core("failed-intent", &unclassified()).await;
        fx.write_yaml(SECRET, "");
        let shown = fx.show().await;
        let before = fx.store_sha();
        fx.refuse(GRAPH_BASELINE_ACTION);
        let got = fx.accept(&shown.hash).await;
        assert!(
            matches!(got, AcceptAnswer::Unavailable { reply: ACCEPT_UNAVAILABLE, ref why } if why.contains("intent")),
            "{got:?}"
        );
        assert_eq!(fx.store_sha(), before);
        assert_eq!(fx.drain(), Drain::Serving);
        assert_eq!(ceiling_name(&fx), "UNCLASSIFIED");
        assert_eq!(fx.status_lines().len(), 0, "status was not published");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_stale_hash_is_refused_and_the_store_is_unchanged() {
        let fx = Fx::with_core("stale", &unclassified()).await;
        fx.write_yaml(SECRET, "");
        let shown = fx.show().await;
        fx.write_yaml(&SECRET.replace("SECRET", "CONFIDENTIAL"), "");
        let before = fx.store_sha();
        match fx.accept(&shown.hash).await {
            AcceptAnswer::View {
                view,
                corrective: Some(why),
            } => {
                assert_eq!(view.state, "stale");
                assert!(view.hash.is_empty());
                assert!(why.contains("show it again"), "{why}");
            }
            other => panic!("{other:?}"),
        }
        match fx.accept("nope").await {
            AcceptAnswer::View {
                view,
                corrective: Some(_),
            } => assert_eq!(view.state, "stale"),
            other => panic!("{other:?}"),
        }
        assert!(!fx
            .seen()
            .iter()
            .any(|s| s.action == GRAPH_TRANSITION_ACTION));
        assert_eq!(fx.store_sha(), before);
        fx.write_yaml(&unclassified(), "");
        match fx.accept(&shown.hash).await {
            AcceptAnswer::View { view, .. } => assert_eq!(view.state, "none"),
            other => panic!("{other:?}"),
        }
        fx.write_yaml(&format!("{}  unknown_key: 1\n", unclassified()), "");
        let invalid = fx.show().await;
        assert_eq!(invalid.state, "invalid");
        match fx.accept(&invalid.hash).await {
            AcceptAnswer::View { view, .. } => assert_eq!(view.state, "invalid"),
            other => panic!("{other:?}"),
        }
        assert_eq!(fx.store_sha(), before);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn nothing_is_admitted_after_a_restart_accept_begins_its_drain() {
        let fx = Fx::with_baseline("restart").await;
        fx.write_yaml("", RESTART);
        let shown = fx.show().await;
        assert_eq!(shown.apply, "restart");
        let before = fx.store_sha();
        let view = accepted(fx.accept(&shown.hash).await);
        assert_eq!(
            (view.state.as_str(), view.apply.as_str()),
            ("accepted", "restart")
        );
        let seen = fx.seen();
        let transition = seen
            .iter()
            .find(|s| s.action == GRAPH_TRANSITION_ACTION && s.reason.contains("operator"))
            .unwrap();
        assert_eq!(
            transition.store, before,
            "nothing was persisted before the transition intent"
        );
        let checkpoint = seen
            .iter()
            .find(|s| s.action == CHECKPOINT_ACTION && s.reason == "transitioned")
            .unwrap();
        assert_eq!(transition.drain, Drain::Serving);
        assert_eq!(
            checkpoint.drain,
            Drain::Applied,
            "the drain is applied as soon as the persist has landed"
        );
        assert_ne!(checkpoint.store, before);
        assert_eq!(fx.drain(), Drain::Applied);
        assert!(!crate::handler::admits(fx.drain()));
        assert_eq!(ceiling_name(&fx), "UNCLASSIFIED");
        assert!(fx.stored().unwrap().sections["transport"].contains("\"max_connections\":7"));
    }

    fn is_checkpoint(r: &AuditRecord) -> bool {
        r.action == CHECKPOINT_ACTION
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_restart_accepts_stop_record_can_precede_its_checkpoint_and_outcome() {
        let opts = Opts {
            bound: Duration::from_secs(2),
            ..Opts::default()
        };
        let fx = Arc::new(fixture_with("restart-order", opts).await);
        fx.write_yaml("", RESTART);
        let shown = fx.show().await;
        assert_eq!(shown.apply, "restart");
        fx.reloader.sink.stall_when(is_checkpoint);
        let stopper = {
            let fx = Arc::clone(&fx);
            let rx = fx.reloader.drain.subscribe();
            tokio::spawn(async move {
                shutdown_on(std::future::pending::<()>(), rx).await;
                let stop = make_record(
                    "shutdown",
                    "h",
                    "s",
                    0,
                    None,
                    None,
                    None,
                    0,
                    1,
                    "serve",
                    None,
                    "permit",
                    "shutdown: restarting to apply an accepted baseline",
                    "stopped",
                    &serde_json::Value::Null,
                );
                fx.reloader.sink.emit(&stop).await.unwrap();
            })
        };
        let accept = {
            let fx = Arc::clone(&fx);
            tokio::spawn(async move { fx.accept(&shown.hash).await })
        };
        tokio::time::timeout(Duration::from_secs(1), stopper)
            .await
            .expect("the stop is released while the checkpoint append is still pending")
            .unwrap();
        assert!(!accept.is_finished());
        tokio::time::timeout(Duration::from_secs(1), async {
            while fx
                .reloader
                .sink
                .stalled
                .load(std::sync::atomic::Ordering::SeqCst)
                == 0
            {
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        })
        .await
        .expect("the checkpoint append is the one held");
        let view = accepted(accept.await.unwrap());
        assert_eq!(view.apply, "restart");
        let seen = fx.seen();
        let at = |pred: &dyn Fn(&Seen) -> bool| seen.iter().position(pred).unwrap();
        let transition =
            at(&|s| s.action == GRAPH_TRANSITION_ACTION && s.reason.contains("operator"));
        let stop = at(&|s| s.action == "serve");
        let outcome =
            at(&|s| s.action == GRAPH_BASELINE_ACTION && s.reason.starts_with("accepted sha256:"));
        assert!(
            transition < stop && stop < outcome,
            "transition, then the stop, then the outcome: {seen:?}"
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_restart_accept_whose_persist_fails_is_abandoned() {
        if nix::unistd::geteuid().is_root() {
            eprintln!("skipped: root writes through a 0500 directory");
            return;
        }
        let fx = Fx::with_baseline("abandoned").await;
        fx.write_yaml("", RESTART);
        let shown = fx.show().await;
        std::fs::set_permissions(fx.state_dir(), std::fs::Permissions::from_mode(0o500)).unwrap();
        let got = fx.accept(&shown.hash).await;
        std::fs::set_permissions(fx.state_dir(), std::fs::Permissions::from_mode(0o700)).unwrap();
        assert!(
            matches!(got, AcceptAnswer::Unavailable { reply: ACCEPT_UNAVAILABLE, ref why } if why.contains("persist")),
            "{got:?}"
        );
        assert_eq!(fx.drain(), Drain::Failed);
        assert!(matches!(
            crate::handler::after_drain(ServeOutcome::GracefulShutdown, fx.drain()),
            ServeOutcome::AcceptAbandoned
        ));
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_reload_after_a_live_accept_keeps_the_accepted_baseline() {
        let fx = Fx::with_core("reload-after-accept", &unclassified()).await;
        fx.write_yaml(SECRET, "");
        let shown = fx.show().await;
        accepted(fx.accept(&shown.hash).await);
        fx.write_bindings(ROOT_ADMIN_OTHER);
        let before = fx.stored().unwrap().sha256;
        fx.reloader.run().await.unwrap();
        assert_ne!(fx.store_sha(), "", "the reload persisted");
        let stored = fx.stored().unwrap();
        assert_eq!((stored.ceiling.as_str(), stored.sha256), ("SECRET", before));
        assert!(fx.status_lines().is_empty());
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn an_accepted_trail_move_is_recorded_for_the_restart_boot_to_perform() {
        let fx = Fx::with_baseline("accept-move").await;
        let old = fx.dir.join("audit.jsonl");
        let new = fx.prepare_trail("audit-2.jsonl");
        fx.write_yaml("", &format!("audit_path_marker: {}\n", new.display()));
        let shown = fx.show().await;
        assert_eq!(shown.apply, "restart");
        accepted(fx.accept(&shown.hash).await);
        let stored = fx.stored().unwrap();
        assert_eq!(stored.moved_from.as_deref(), Some(old.to_str().unwrap()));
        assert!(stored.sections["audit"].contains("audit-2.jsonl"));
        assert!(
            std::fs::read_to_string(&new).unwrap().is_empty(),
            "the accept itself appends nothing to the new trail"
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn an_accept_whose_new_socket_cannot_bind_is_refused() {
        let env = TestEnv {
            bindable: Err("EACCES".into()),
            ..TestEnv::default()
        };
        let fx = Fx::with_baseline_env("bind-probe", env).await;
        let other = fx.dir.join("other.sock");
        fx.write_yaml("", &format!("socket_path_marker: {}\n", other.display()));
        let shown = fx.show().await;
        let before = fx.store_sha();
        match fx.accept(&shown.hash).await {
            AcceptAnswer::View {
                view,
                corrective: Some(why),
            } => {
                assert_eq!(view.state, "invalid");
                assert!(
                    why.contains("other.sock") && why.contains("EACCES"),
                    "{why}"
                );
            }
            other => panic!("{other:?}"),
        }
        assert_eq!(fx.store_sha(), before);
        assert_eq!(fx.drain(), Drain::Serving);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_stale_or_garbage_hash_never_resolves_or_probes() {
        let env = TestEnv::counting();
        let fx = Fx::with_baseline_env("no-probe", env.clone()).await;
        let other = fx.dir.join("other.sock");
        fx.write_yaml(
            "",
            &format!(
                "socket_path_marker: {}\naudit_readers_marker: [vector]\n",
                other.display()
            ),
        );
        let shown = fx.show().await;
        for named in ["0".repeat(64), "garbage".to_string()] {
            assert!(matches!(
                fx.accept(&named).await,
                AcceptAnswer::View {
                    corrective: Some(_),
                    ..
                }
            ));
        }
        assert_eq!(
            (env.binds(), env.connects(), env.reader_lookups()),
            (0, 0, 0)
        );
        accepted(fx.accept(&shown.hash).await);
        assert_eq!(env.binds(), 1, "the valid hash is the first to probe");
        assert_eq!(
            env.reader_lookups(),
            1,
            "and the first to resolve the readers"
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_restart_accept_with_slow_appends_still_applies() {
        let fx = Fx::with_baseline_and_delay(
            "slow-accept",
            Duration::from_millis(500),
            Duration::from_secs(1),
        )
        .await;
        fx.write_yaml("", RESTART);
        let shown = fx.show().await;
        accepted(fx.accept(&shown.hash).await);
        assert_eq!(fx.drain(), Drain::Applied);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn an_accept_waits_for_a_reload_and_gives_up_after_the_bound() {
        let fx = Fx::with_core("busy", &unclassified()).await;
        fx.write_yaml(SECRET, "");
        let shown = fx.show().await;
        let held = fx.reloader.lock.lock().await;
        let got = tokio::time::timeout(Duration::from_secs(3), fx.accept(&shown.hash))
            .await
            .expect("bounded");
        drop(held);
        assert!(
            matches!(
                got,
                AcceptAnswer::Unavailable {
                    reply: ACCEPT_BUSY,
                    ..
                }
            ),
            "{got:?}"
        );
        assert_eq!(ceiling_name(&fx), "UNCLASSIFIED");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn an_accept_is_refused_once_shutdown_has_begun() {
        let fx = Fx::with_core("stopping", &unclassified()).await;
        fx.write_yaml(SECRET, "");
        let shown = fx.show().await;
        fx.reloader.stopping.send_replace(true);
        let got = fx.accept(&shown.hash).await;
        assert!(
            matches!(
                got,
                AcceptAnswer::Unavailable {
                    reply: ACCEPT_STOPPING,
                    ..
                }
            ),
            "{got:?}"
        );
        assert!(!fx.seen().iter().any(|s| s.action == GRAPH_BASELINE_ACTION));
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn an_accept_is_refused_unless_the_drain_is_serving() {
        for drain in [Drain::Begun, Drain::Applied, Drain::Failed] {
            let fx = Fx::with_core(&format!("draining-{drain:?}"), &unclassified()).await;
            fx.write_yaml(SECRET, "");
            let shown = fx.show().await;
            let before = fx.store_sha();
            fx.reloader.drain.send_replace(drain);
            let got = fx.accept(&shown.hash).await;
            assert!(
                matches!(
                    got,
                    AcceptAnswer::Unavailable {
                        reply: ACCEPT_STOPPING,
                        ..
                    }
                ),
                "{drain:?}: {got:?}"
            );
            assert_eq!(fx.drain(), drain);
            assert_eq!(fx.store_sha(), before, "{drain:?}");
            assert_eq!(ceiling_name(&fx), "UNCLASSIFIED");
            assert!(!fx.seen().iter().any(|s| s.action == GRAPH_BASELINE_ACTION));
        }
    }

    #[test]
    fn a_drain_left_begun_by_an_accept_becomes_failed() {
        for (at, live_unsettled, after) in [
            (Drain::Begun, false, Drain::Failed),
            (Drain::Serving, false, Drain::Serving),
            (Drain::Applied, false, Drain::Applied),
            (Drain::Failed, false, Drain::Failed),
            (Drain::Serving, true, Drain::Applied),
            (Drain::Applied, true, Drain::Applied),
            (Drain::Failed, true, Drain::Failed),
        ] {
            let (tx, rx) = tokio::sync::watch::channel(Drain::Serving);
            let guard = DrainGuard {
                drain: &tx,
                live_unsettled,
            };
            tx.send_replace(at);
            drop(guard);
            assert_eq!(*rx.borrow(), after, "{at:?} {live_unsettled}");
        }
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_lowered_ceiling_whose_install_times_out_is_applied_by_restart() {
        let fx = Fx::with_core("install-fails", SECRET).await;
        fx.write_yaml(&unclassified(), "");
        let shown = fx.show().await;
        assert_eq!(shown.apply, "live");
        let (held_tx, held) = std::sync::mpsc::channel();
        let (release_tx, release) = std::sync::mpsc::channel::<()>();
        let holder = {
            let pdp = Arc::clone(&fx.reloader.authorizer);
            std::thread::spawn(move || {
                let _decision = pdp.hold_live_turn();
                let _ = held_tx.send(());
                let _ = release.recv_timeout(Duration::from_secs(20));
            })
        };
        held.recv_timeout(Duration::from_secs(5))
            .expect("the turn is held");
        let got = fx.accept(&shown.hash).await;
        let _ = release_tx.send(());
        holder.join().unwrap();
        let view = accepted(got);
        assert_eq!(
            (view.state.as_str(), view.apply.as_str()),
            ("accepted", "restart")
        );
        assert_eq!(fx.drain(), Drain::Applied);
        assert!(!crate::handler::admits(fx.drain()));
        assert!(matches!(
            crate::handler::after_drain(ServeOutcome::GracefulShutdown, fx.drain()),
            ServeOutcome::ApplyByRestart
        ));
        let outcome = fx
            .seen()
            .into_iter()
            .rfind(|s| s.action == GRAPH_BASELINE_ACTION)
            .unwrap();
        assert!(
            outcome.reason.contains("not installed live: ")
                && outcome.reason.contains("live turn")
                && outcome.reason.ends_with("restarting to apply"),
            "{outcome:?}"
        );
        assert!(!view.changes.iter().any(|c| c.contains("live turn")));
        assert_eq!(
            fx.stored().unwrap().ceiling,
            "UNCLASSIFIED",
            "the store holds the accepted baseline the restart applies"
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_reload_is_refused_unless_the_drain_is_serving() {
        let fx = Fx::with_core("reload-drain", &unclassified()).await;
        let revision = fx.reloader.revision.load(AtomicOrdering::Acquire);
        for state in [Drain::Begun, Drain::Applied, Drain::Failed] {
            fx.reloader.drain.send_replace(state);
            assert_eq!(
                fx.reloader.run().await.err(),
                Some(crate::reload::Refusal::Shutdown),
                "{state:?}"
            );
            assert_eq!(fx.reloader.revision.load(AtomicOrdering::Acquire), revision);
        }
        fx.reloader.drain.send_replace(Drain::Serving);
        assert!(fx.reloader.run().await.is_ok());
    }

    fn is_accept_outcome(r: &AuditRecord) -> bool {
        r.action == GRAPH_BASELINE_ACTION && r.outcome.reason.starts_with("accepted sha256:")
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_finished_live_accept_leaves_the_next_accepts_drain_alone() {
        let fx = Arc::new(Fx::with_core("guard-turn", &unclassified()).await);
        fx.write_yaml(SECRET, "");
        let shown = fx.show().await;
        assert_eq!(shown.apply, "live");
        fx.reloader.sink.stall_when(is_accept_outcome);
        let first = {
            let fx = Arc::clone(&fx);
            tokio::spawn(async move { fx.accept(&shown.hash).await })
        };
        let next = tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                if fx
                    .reloader
                    .sink
                    .stalled
                    .load(std::sync::atomic::Ordering::SeqCst)
                    > 0
                {
                    if let Ok(turn) = fx.reloader.lock.try_lock() {
                        break turn;
                    }
                }
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        })
        .await
        .expect("the live accept releases the turn while its outcome is appended");
        fx.reloader.drain.send_replace(Drain::Begun);
        accepted(
            tokio::time::timeout(Duration::from_secs(5), first)
                .await
                .expect("the live accept finishes")
                .unwrap(),
        );
        assert_eq!(
            fx.drain(),
            Drain::Begun,
            "the finished accept rewrote the drain the turn's holder began"
        );
        fx.reloader.drain.send_replace(Drain::Serving);
        drop(next);
    }

    #[tokio::test]
    async fn the_shutdown_future_waits_for_the_accept_to_finish() {
        let (tx, rx) = tokio::sync::watch::channel(Drain::Serving);
        let fut = shutdown_on(std::future::pending::<()>(), rx);
        tokio::pin!(fut);
        assert!(
            tokio::time::timeout(Duration::from_millis(100), &mut fut)
                .await
                .is_err(),
            "not before the drain"
        );
        tx.send_replace(Drain::Begun);
        assert!(
            tokio::time::timeout(Duration::from_millis(100), &mut fut)
                .await
                .is_err(),
            "not while the accept is still committing"
        );
        tx.send_replace(Drain::Applied);
        tokio::time::timeout(Duration::from_secs(1), fut)
            .await
            .expect("resolves once the accept has persisted");
    }

    #[tokio::test]
    async fn a_dropped_drain_sender_never_resolves_shutdown() {
        let (tx, rx) = tokio::sync::watch::channel(Drain::Serving);
        drop(tx);
        let fut = shutdown_on(std::future::pending::<()>(), rx);
        assert!(tokio::time::timeout(Duration::from_millis(200), fut)
            .await
            .is_err());
    }

    #[tokio::test]
    async fn a_signal_resolves_shutdown_while_serving() {
        let (_tx, rx) = tokio::sync::watch::channel(Drain::Serving);
        tokio::time::timeout(Duration::from_secs(1), shutdown_on(async {}, rx))
            .await
            .expect("a signal stops the serve");
    }
}

#[cfg(unix)]
#[cfg(test)]
mod reload_tests {
    use super::boot_gate_tests::boot_graph_at;
    use super::reload_fixture::*;
    use super::*;
    use maknae_authz_basic::Baseline;
    use maknae_graph::record::ProvenanceKind;

    const ROOT_ADMIN_OTHER: &str =
        "schema_version: 1\nbindings:\n  admin: [\"root\"]\n  guest: []\n";

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_reload_carries_the_persisted_baseline_unchanged() {
        let fx = Fx::with_baseline("carry").await;
        let before = fx.stored();
        assert!(before.is_some());
        fx.write_bindings(ROOT_ADMIN_OTHER);
        let applied = fx.reloader.run().await.unwrap();
        assert!(applied.persisted);
        assert_eq!(fx.stored(), before);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_reload_never_applies_a_baseline_change_and_records_the_set_once() {
        let fx = Fx::with_baseline("vault-at-reload").await;
        let before = fx.stored();
        fx.write_yaml("", "vault_addr_marker: https://w.example:8200\n");
        fx.reloader.run().await.unwrap();
        assert_eq!(fx.stored(), before, "a reload does not move vault");
        let pending: Vec<_> = fx
            .seen()
            .into_iter()
            .filter(|s| s.action == GRAPH_BASELINE_ACTION)
            .collect();
        assert_eq!(pending.len(), 1, "{pending:?}");
        assert!(pending[0]
            .reason
            .starts_with("baseline change pending acceptance: root-file "));
        assert!(
            pending[0]
                .reason
                .ends_with("(apply: restart; sections: vault)"),
            "{}",
            pending[0].reason
        );
        assert_eq!(
            fx.status_lines(),
            vec!["baseline: 1 pending (restart)".to_string()]
        );
        fx.reloader.run().await.unwrap();
        assert_eq!(
            fx.seen()
                .iter()
                .filter(|s| s.action == GRAPH_BASELINE_ACTION)
                .count(),
            1,
            "an unchanged set is not recorded again"
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_pending_set_whose_record_failed_is_recorded_by_the_next_reload() {
        use std::sync::atomic::Ordering::SeqCst;
        let fx = Fx::with_baseline("pending-retry").await;
        fx.write_yaml("", "vault_addr_marker: https://w.example:8200\n");
        fx.reloader.sink.fail_baseline.store(true, SeqCst);
        fx.reloader.run().await.unwrap();
        let recorded = |fx: &Fx| {
            fx.seen()
                .iter()
                .filter(|s| s.action == GRAPH_BASELINE_ACTION)
                .count()
        };
        assert_eq!(recorded(&fx), 0);
        assert!(
            fx.status_lines().is_empty(),
            "an unrecorded set is not published"
        );
        fx.reloader.sink.fail_baseline.store(false, SeqCst);
        fx.reloader.run().await.unwrap();
        assert_eq!(recorded(&fx), 1, "the next reload records it");
        assert_eq!(
            fx.status_lines(),
            vec!["baseline: 1 pending (restart)".to_string()]
        );
        fx.reloader.run().await.unwrap();
        assert_eq!(recorded(&fx), 1, "and only once");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn the_pending_record_follows_the_reload_outcome() {
        let fx = Fx::with_baseline("pending-order").await;
        fx.write_yaml("", "vault_addr_marker: https://w.example:8200\n");
        fx.reloader.run().await.unwrap();
        let actions: Vec<String> = fx.seen().into_iter().map(|s| s.action).collect();
        assert_eq!(
            actions,
            [
                GRAPH_RELOAD_ACTION,
                GRAPH_RELOAD_ACTION,
                GRAPH_BASELINE_ACTION
            ]
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn an_invalid_baseline_file_does_not_refuse_the_reload() {
        let fx = Fx::with_baseline("invalid-at-reload").await;
        fx.write_yaml("  unknown_key: 1\n", "");
        fx.write_bindings(ROOT_ADMIN_OTHER);
        let applied = fx.reloader.run().await.unwrap();
        assert!(applied.persisted, "the policy edit applied");
        let rec = fx
            .seen()
            .into_iter()
            .find(|s| s.action == GRAPH_BASELINE_ACTION)
            .unwrap();
        assert!(
            rec.reason.starts_with("baseline change refused: invalid: "),
            "{}",
            rec.reason
        );
        assert_eq!(
            fx.status_lines(),
            vec!["baseline: 1 pending (invalid)".to_string()]
        );
        assert_eq!(rec.store, fx.store_sha(), "recorded after the commit");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn every_edit_of_an_invalid_file_that_parses_is_a_new_set() {
        let fx = Fx::with_baseline("invalid-edits").await;
        let providers = |model: &str| {
            format!("providers:\n  - name: openai\n    endpoint: https://api.example.test/v1\n    models: [{model}]\n")
        };
        let mut hashes = Vec::new();
        for model in ["m", "n"] {
            fx.write_yaml("", &providers(model));
            fx.reloader.run().await.unwrap();
            let p = fx.reloader.baseline.current().pending.clone().unwrap();
            let crate::baseline::PendingState::Invalid { proposed, .. } = &p.state else {
                panic!("{p:?}")
            };
            assert!(proposed.as_ref().unwrap().contains_key("providers"));
            hashes.push(p.hash.clone());
        }
        assert_ne!(hashes[0], hashes[1], "the proposal is bound into the hash");
        let refused = fx
            .seen()
            .iter()
            .filter(|s| s.action == GRAPH_BASELINE_ACTION)
            .count();
        assert_eq!(refused, 2);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_reload_over_a_graph_without_a_baseline_is_refused() {
        let fx = Fx::with_baseline("no-baseline").await;
        let current = fx.reloader.persisted.read().unwrap().clone();
        let e = maknae_graph::identity::extract(&current).unwrap();
        let vocab = &fx.reloader.vocabulary;
        let bare = maknae_graph::identity::build(
            &e.layer,
            None,
            &vocab.persisted,
            vocab.digest,
            current.revision(),
            ProvenanceKind::RootFile,
        )
        .unwrap();
        fx.set_persisted(Arc::new(bare));
        let before = fx.store_sha();
        let r = fx.reloader.run().await;
        assert!(
            matches!(r, Err(crate::reload::Refusal::Compile(ref m)) if m.contains("carries no baseline")),
            "{r:?}"
        );
        assert_eq!(fx.store_sha(), before);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_commit_whose_baseline_differs_from_the_store_is_refused_as_a_baseline_change() {
        let fx = Fx::with_baseline("baseline-mismatch").await;
        let current = fx.reloader.persisted.read().unwrap().clone();
        let e = maknae_graph::identity::extract(&current).unwrap();
        let mut other = e.baseline.clone().unwrap();
        other.sections.insert("lake".into(), "{}".into());
        let vocab = &fx.reloader.vocabulary;
        let forged = maknae_graph::identity::build(
            &e.layer,
            Some(&other),
            &vocab.persisted,
            vocab.digest,
            current.revision(),
            ProvenanceKind::RootFile,
        )
        .unwrap();
        fx.set_persisted(Arc::new(forged));
        fx.write_bindings(ROOT_ADMIN_OTHER);
        let before = fx.store_sha();
        let r = fx.reloader.run().await;
        assert_eq!(r, Err(crate::reload::Refusal::BaselineChanged), "{r:?}");
        assert_eq!(fx.store_sha(), before);
        let outcome = fx.reload_records().pop().unwrap().outcome.reason;
        assert!(
            outcome.contains("only an accept changes the accepted baseline"),
            "{outcome}"
        );
        assert!(!outcome.contains("persist:"), "{outcome}");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_commit_replaces_the_graph_the_next_reload_plans_from() {
        let fx = Fx::with_baseline("replaced-graph").await;
        fx.write_bindings(ROOT_ADMIN_OTHER);
        assert!(fx.reloader.run().await.unwrap().persisted);
        assert_eq!(fx.reloader.persisted.read().unwrap().revision(), 2);
        let again = fx.reloader.run().await.unwrap();
        assert!(!again.persisted, "{again:?}");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_file_reverted_to_the_baseline_clears_the_pending_set() {
        let fx = Fx::with_baseline("revert").await;
        fx.write_yaml("", "vault_addr_marker: https://w.example:8200\n");
        fx.reloader.run().await.unwrap();
        assert_eq!(fx.status_lines().len(), 1);
        fx.write_yaml("", "");
        let records_before = fx.seen().len();
        fx.reloader.run().await.unwrap();
        assert!(fx.status_lines().is_empty());
        assert!(!fx.seen()[records_before..]
            .iter()
            .any(|s| s.action == GRAPH_BASELINE_ACTION));
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_refused_reload_publishes_no_pending_set() {
        let fx = Fx::with_baseline("refused-publishes-nothing").await;
        fx.write_yaml("", "vault_addr_marker: https://w.example:8200\n");
        fx.write_bindings("schema_version: [\n");
        assert!(fx.reloader.run().await.is_err());
        assert!(fx.status_lines().is_empty());
        assert!(!fx.seen().iter().any(|s| s.action == GRAPH_BASELINE_ACTION));
    }

    const ROOT_ADVERSARY: &str = "schema_version: 1\nbindings:\n  adversary: [\"root\"]\n";

    fn outcomes(recs: &[AuditRecord]) -> Vec<(String, String, String)> {
        recs.iter()
            .map(|r| {
                (
                    r.action.clone(),
                    r.outcome.result.clone(),
                    r.outcome.reason.clone(),
                )
            })
            .collect()
    }

    async fn bounded<T>(f: impl std::future::Future<Output = T>) -> T {
        tokio::time::timeout(std::time::Duration::from_secs(60), f)
            .await
            .expect("the reload finished within its bound")
    }

    fn adversary() -> maknae_security::Verdict {
        maknae_security::Verdict::Deny {
            reason: "subject contained: role=adversary".into(),
        }
    }

    async fn within(
        f: impl std::future::Future<Output = Result<crate::reload::Applied, crate::reload::Refusal>>,
    ) -> Result<crate::reload::Applied, crate::reload::Refusal> {
        tokio::time::timeout(Duration::from_secs(3), f)
            .await
            .expect("the reload must return within its bound, not hold the turn")
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_stalled_sink_refuses_the_reload_within_the_bound_and_a_second_reload_runs() {
        let fx = fixture("stalled-reload", AUTHZ, Some(ROOT_ADMIN)).await;
        fx.reloader.sink.stall_when(is_reload);
        let refused = within(fx.reloader.run()).await;
        assert!(
            matches!(refused, Err(crate::reload::Refusal::Audit(_))),
            "{refused:?}"
        );
        fx.reloader.sink.stall_when(never);
        let second = tokio::time::timeout(Duration::from_secs(3), fx.reloader.run()).await;
        assert!(second.expect("the turn lock was released").is_ok());
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_stalled_transition_record_refuses_the_commit_within_the_bound() {
        let fx = fixture("stalled-commit", AUTHZ, Some(ROOT_ADMIN)).await;
        let before = fx.store_bytes();
        fx.reloader.sink.stall_when(is_transition);
        fx.write_bindings(ROOT_ADVERSARY);
        let refused = within(fx.reloader.run()).await;
        assert!(
            matches!(&refused, Err(crate::reload::Refusal::Persist(_))),
            "{refused:?}"
        );
        assert_eq!(fx.store_bytes(), before);
        fx.reloader.sink.stall_when(never);
        assert!(within(fx.reloader.run()).await.unwrap().persisted);
        assert_eq!(fx.root_whoami(), adversary());
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_stalled_outcome_record_lets_the_applied_reload_return_within_the_bound() {
        let fx = fixture("stalled-outcome", AUTHZ, Some(ROOT_ADMIN)).await;
        fx.reloader.sink.stall_when(is_reload_outcome);
        fx.write_bindings(ROOT_ADVERSARY);
        assert!(within(fx.reloader.run()).await.unwrap().persisted);
        assert_eq!(fx.root_whoami(), adversary());
        fx.reloader.sink.stall_when(never);
        assert!(within(fx.reloader.run()).await.is_ok());
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn the_identity_records_after_a_reload_stop_at_the_first_that_elapses() {
        let fx = fixture("stalled-identities", AUTHZ, Some(ROOT_ADMIN)).await;
        fx.reloader.sink.stall_when(is_identity);
        fx.write_bindings(
            "schema_version: 1\nbindings:\n  admin: [\"root\"]\n  user: [\"no-such-user-maknae-497\"]\n  adversary: [\"no-such-user-maknae-497b\"]\n",
        );
        assert!(within(fx.reloader.run()).await.unwrap().persisted);
        assert_eq!(fx.status.identity.counts().len(), 2);
        assert_eq!(
            fx.reloader
                .sink
                .stalled
                .load(std::sync::atomic::Ordering::SeqCst),
            1
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_stalled_identity_record_after_a_reload_returns_within_the_bound() {
        let fx = fixture("stalled-identity", AUTHZ, Some(ROOT_ADMIN)).await;
        fx.reloader.sink.stall_when(is_identity);
        fx.write_bindings(GHOST_USER);
        assert!(within(fx.reloader.run()).await.unwrap().persisted);
        assert_eq!(fx.status.identity.counts(), ["unresolved=1"]);
        fx.reloader.sink.stall_when(never);
        assert!(within(fx.reloader.run()).await.is_ok());
    }

    #[tokio::test]
    async fn a_reload_applies_a_file_edit_and_records_intent_then_outcome() {
        let fx = fixture("apply", AUTHZ, Some(ROOT_ADMIN)).await;
        assert!(matches!(
            fx.root_whoami(),
            maknae_security::Verdict::Permit { .. }
        ));
        fx.write_bindings(ROOT_ADVERSARY);
        let applied = fx.reloader.run().await.unwrap();
        assert_eq!(
            applied,
            crate::reload::Applied {
                revision: 2,
                persisted: true,
                durability_error: None,
                checkpoint_error: None,
            }
        );
        assert_eq!(fx.root_whoami(), adversary());
        assert_eq!(fx.baseline().snapshot().revision(), 2);
        let recs = fx.reload_records();
        let actions: Vec<&str> = recs.iter().map(|r| r.action.as_str()).collect();
        assert_eq!(
            actions,
            [
                "graph.reload",
                "graph.transition",
                "graph.checkpoint",
                "graph.reload"
            ]
        );
        assert_eq!(
            (
                recs[0].outcome.result.as_str(),
                recs[0].outcome.reason.as_str()
            ),
            ("permit", "intent recorded (SIGHUP)")
        );
        assert_eq!(recs[0].graph.as_ref().unwrap().revision, 1);
        assert_eq!(
            recs[2].graph.as_ref().unwrap().anchor,
            maknae_state::store::ANCHOR_TRANSITIONED
        );
        let last = &recs[3];
        assert_eq!(
            (
                last.outcome.result.as_str(),
                last.outcome.reason.as_str(),
                last.outcome.posture.as_str()
            ),
            (
                "permit",
                "reload applied: revision 2; identity persisted",
                "authorized"
            )
        );
        let graph = last.graph.as_ref().unwrap();
        assert_eq!((graph.revision, graph.anchor.as_str()), (2, "reloaded"));
        assert_eq!(
            graph.ciphertext_sha256,
            recs[2].graph.as_ref().unwrap().ciphertext_sha256
        );
        assert!(recs.iter().all(|r| r.session_id == recs[0].session_id));
        let seqs: Vec<u64> = recs.iter().map(|r| r.seq).collect();
        assert_eq!(seqs, [1, 2, 3, 4]);
    }

    const GHOST: &str = "no-such-user-maknae-496c";
    const GHOST_ADVERSARY: &str =
        "schema_version: 1\nbindings:\n  adversary: [\"no-such-user-maknae-496c\"]\n";

    fn ghost_contained(
        file: &maknae_graph::identity::IdentityLayer,
    ) -> maknae_graph::identity::IdentityLayer {
        let mut l = file.clone();
        l.subjects.push(maknae_graph::identity::SubjectEntry {
            uid: 4242,
            name: GHOST.into(),
            role: "adversary".into(),
        });
        l
    }

    fn whoami_as(fx: &Fx, uid: u32) -> (maknae_security::Verdict, Option<&'static str>) {
        fx.reloader
            .authorizer
            .decide_reporting_role(&crate::handler::build_authz_request(
                &Verb::Whoami,
                uid,
                None,
                maknae_security::Lane::Local,
                None,
            ))
    }

    fn identity_records(recs: &[AuditRecord]) -> Vec<(String, String, String)> {
        recs.iter()
            .filter(|r| r.action == "graph.identity")
            .map(|r| {
                (
                    r.outcome.result.clone(),
                    r.outcome.posture.clone(),
                    r.outcome.reason.clone(),
                )
            })
            .collect()
    }

    #[tokio::test]
    async fn a_contained_name_that_stops_resolving_is_carried_through_boot_and_reload() {
        let fx = fixture_seeded(
            "carried",
            AUTHZ,
            Some(GHOST_ADVERSARY),
            None,
            Some(ghost_contained),
        )
        .await;
        assert_eq!(fx.booted_released, 0);
        assert_eq!(
            fx.status.revision(),
            1,
            "the carried layer is the stored one"
        );
        assert_eq!(whoami_as(&fx, 4242).1, Some("adversary"));
        assert_eq!(
            fx.baseline().snapshot().identity_problems().as_ref(),
            [maknae_authz_basic::IdentityProblem::CarriedForward {
                uid: 4242,
                name: GHOST.into(),
                overrides: vec![],
            }]
        );
        let before = fx.store_bytes();
        let applied = bounded(fx.reloader.run()).await.unwrap();
        assert!(!applied.persisted);
        assert_eq!(fx.store_bytes(), before);
        assert_eq!(whoami_as(&fx, 4242).1, Some("adversary"));
        assert!(identity_records(&fx.reload_records()).is_empty());

        fx.write_bindings("schema_version: 1\nbindings:\n  admin: [\"root\"]\n");
        bounded(fx.reloader.run()).await.unwrap();
        assert_eq!(
            whoami_as(&fx, 4242).1,
            None,
            "removing the name releases it"
        );
        let recs = fx.reload_records();
        assert_eq!(
            identity_records(&recs),
            [(
                "permit".to_string(),
                "authorized".to_string(),
                format!(
                    "uid 4242 ('{GHOST}') is no longer contained: its name is no longer listed under adversary"
                )
            )]
        );
        let tail: Vec<&str> = recs[recs.len() - 4..]
            .iter()
            .map(|r| r.action.as_str())
            .collect();
        assert_eq!(
            tail,
            [
                "graph.identity",
                "graph.transition",
                "graph.checkpoint",
                "graph.reload"
            ]
        );
    }

    #[tokio::test]
    async fn removing_bindings_yaml_over_explicit_bindings_is_a_refused_reload() {
        let fx = fixture("rm_bindings", AUTHZ, Some(ROOT_ADVERSARY)).await;
        let before = fx.store_bytes();
        std::fs::remove_file(fx.bindings()).unwrap();
        let refused = bounded(fx.reloader.run()).await.unwrap_err();
        assert_eq!(
            refused,
            crate::reload::Refusal::Load(maknae_graph::identity::BINDINGS_MISSING.into())
        );
        assert_eq!(fx.store_bytes(), before);
        assert_eq!(whoami_as(&fx, 0).1, Some("adversary"));
        let recs = fx.reload_records();
        let last = recs.last().unwrap();
        assert_eq!(
            (
                last.action.as_str(),
                last.outcome.result.as_str(),
                last.outcome.reason.clone()
            ),
            (
                "graph.reload",
                "deny",
                format!(
                    "reload refused: policy load: {}",
                    maknae_graph::identity::BINDINGS_MISSING
                )
            )
        );
        assert!(identity_records(&recs).is_empty());
        fx.write_bindings("schema_version: 1\n");
        let applied = bounded(fx.reloader.run()).await.unwrap();
        assert!(applied.persisted, "root's keyless file applies");
    }

    #[tokio::test]
    async fn a_keyless_reload_records_each_released_containment() {
        let fx = fixture("keyless_release", AUTHZ, Some(ROOT_ADVERSARY)).await;
        assert_eq!(whoami_as(&fx, 0).1, Some("adversary"));
        fx.write_bindings("schema_version: 1\n");
        bounded(fx.reloader.run()).await.unwrap();
        assert_ne!(whoami_as(&fx, 0).1, Some("adversary"));
        let recs = fx.reload_records();
        let actions: Vec<&str> = recs.iter().map(|r| r.action.as_str()).collect();
        assert_eq!(
            actions,
            [
                "graph.reload",
                "graph.identity",
                "graph.identity",
                "graph.transition",
                "graph.checkpoint",
                "graph.reload"
            ]
        );
        assert_eq!(
            identity_records(&recs),
            [
                (
                    "permit".to_string(),
                    "authorized".to_string(),
                    "uid 0 ('root') is no longer contained: bindings.yaml has no bindings: key, so the enrolled principal is admin and nobody else holds a role".to_string()
                ),
                (
                    "permit".to_string(),
                    "authorized".to_string(),
                    principal_admin_reason()
                )
            ]
        );
        let g = recs[1].graph.as_ref().unwrap();
        assert_eq!((g.revision, g.anchor.as_str()), (2, "releasing"));
        let g = recs[2].graph.as_ref().unwrap();
        assert_eq!((g.revision, g.anchor.as_str()), (2, "promoting"));
        assert_eq!(recs[3].graph.as_ref().unwrap().revision, 2);
        assert!(recs.iter().all(|r| r.session_id == recs[0].session_id));
        assert_eq!(
            fx.status.identity.counts(),
            ["principal_admin=1", "released=1"]
        );
        bounded(fx.reloader.run()).await.unwrap();
        assert_eq!(
            identity_records(&fx.reload_records()).len(),
            2,
            "an unchanged reload releases nothing"
        );
        assert!(
            fx.status.identity.counts().is_empty(),
            "a release is reported by the load that made it"
        );
    }

    fn principal_admin_reason() -> String {
        format!(
            "uid {}, the enrolled principal, now holds admin: bindings.yaml has no bindings: key",
            principal().uid
        )
    }

    #[tokio::test]
    async fn a_keyless_reload_over_explicit_bindings_records_the_principal_admin() {
        let fx = fixture("keyless_promote", AUTHZ, Some(ROOT_ADMIN)).await;
        fx.write_bindings("schema_version: 1\n");
        let applied = bounded(fx.reloader.run()).await.unwrap();
        assert!(applied.persisted);
        let recs = fx.reload_records();
        let actions: Vec<&str> = recs.iter().map(|r| r.action.as_str()).collect();
        assert_eq!(
            actions,
            [
                "graph.reload",
                "graph.identity",
                "graph.transition",
                "graph.checkpoint",
                "graph.reload"
            ]
        );
        assert_eq!(
            identity_records(&recs),
            [(
                "permit".to_string(),
                "authorized".to_string(),
                principal_admin_reason()
            )]
        );
        let g = recs[1].graph.as_ref().unwrap();
        assert_eq!((g.revision, g.anchor.as_str()), (2, "promoting"));
        assert_eq!(fx.status.identity.counts(), ["principal_admin=1"]);
        bounded(fx.reloader.run()).await.unwrap();
        assert_eq!(identity_records(&fx.reload_records()).len(), 1, "once");
        assert!(fx.status.identity.counts().is_empty());
        fx.write_bindings(ROOT_ADMIN);
        bounded(fx.reloader.run()).await.unwrap();
        assert_eq!(
            identity_records(&fx.reload_records()).len(),
            1,
            "keyless to explicit promotes nobody"
        );
    }

    const GHOST_USER: &str =
        "schema_version: 1\nbindings:\n  admin: [\"root\"]\n  user: [\"no-such-user-maknae-496\"]\n";

    #[tokio::test]
    async fn an_applied_reload_records_and_publishes_its_identity_problems() {
        let fx = fixture("probs", AUTHZ, Some(ROOT_ADMIN)).await;
        assert!(fx.status.identity.current().is_empty());
        fx.write_bindings(GHOST_USER);
        bounded(fx.reloader.run()).await.unwrap();
        let recs = fx.reload_records();
        let n = recs.len();
        assert_eq!(recs[n - 2].action, "graph.reload");
        assert_eq!(
            (
                recs[n - 1].action.as_str(),
                recs[n - 1].outcome.result.as_str(),
                recs[n - 1].outcome.posture.as_str(),
                recs[n - 1].outcome.reason.as_str()
            ),
            (
                "graph.identity",
                "deny",
                "unauthorized",
                "'no-such-user-maknae-496' under user has no account on this host; it holds no role"
            )
        );
        assert_eq!(recs[n - 1].seq, recs[n - 2].seq + 1);
        assert_eq!(recs[n - 1].session_id, recs[n - 2].session_id);
        assert_eq!(fx.status.identity.counts(), ["unresolved=1"]);
        let listed = fx.status.identity.subjects();
        assert_eq!(
            listed
                .iter()
                .map(crate::identity_report::label)
                .collect::<Vec<_>>(),
            ["root (uid 0)", "no-such-user-maknae-496 (no account)"]
        );
        assert!(
            matches!(fx.root_whoami(), maknae_security::Verdict::Permit { .. }),
            "the rest loads"
        );
    }

    #[tokio::test]
    async fn a_problem_is_recorded_once_across_boot_and_reloads() {
        let fx = fixture("probs_once", AUTHZ, Some(GHOST_USER)).await;
        let boot: Vec<AuditRecord> = std::fs::read_to_string(fx.dir.join("audit.jsonl"))
            .unwrap()
            .lines()
            .map(|l| serde_json::from_str::<AuditRecord>(l).unwrap())
            .filter(|r| r.action == "graph.identity")
            .collect();
        assert_eq!(boot.len(), 1);
        assert_eq!(boot[0].event, "boot");
        assert_eq!(fx.status.identity.counts(), ["unresolved=1"]);
        bounded(fx.reloader.run()).await.unwrap();
        bounded(fx.reloader.run()).await.unwrap();
        assert!(
            identity_records(&fx.reload_records()).is_empty(),
            "the boot's problem is not recorded again by an unchanged reload, nor by the next"
        );
        fx.write_bindings(
            "schema_version: 1\nbindings:\n  admin: [\"root\"]\n  user: [\"no-such-user-maknae-496\", \"no-such-user-maknae-496b\"]\n",
        );
        bounded(fx.reloader.run()).await.unwrap();
        let added = identity_records(&fx.reload_records());
        assert_eq!(added.len(), 1, "{added:?}");
        assert!(added[0].2.contains("no-such-user-maknae-496b"));
        assert_eq!(fx.status.identity.counts(), ["unresolved=2"]);
    }

    #[tokio::test]
    async fn a_refused_reload_records_no_identity_problems_and_keeps_the_published_set() {
        let fx = fixture("probs2", AUTHZ, Some(ROOT_ADMIN)).await;
        fx.write_bindings(GHOST_USER);
        bounded(fx.reloader.run()).await.unwrap();
        let before = fx.reload_records().len();
        let published = fx.status.identity.current();
        fx.write_bindings(
            "schema_version: 1\nbindings:\n  admin: [\"root\"]\n  user: [\"no-such-user-maknae-496c\"]\n  nosuchrole: []\n",
        );
        assert!(bounded(fx.reloader.run()).await.is_err());
        let after = fx.reload_records();
        assert_eq!(
            after[before..]
                .iter()
                .map(|r| r.action.as_str())
                .collect::<Vec<_>>(),
            ["graph.reload", "graph.reload"]
        );
        assert_eq!(fx.status.identity.current(), published);
        assert_eq!(fx.status.identity.counts(), ["unresolved=1"]);
    }

    #[tokio::test]
    async fn an_unresolved_adversary_is_recorded_unavailable() {
        let fx = fixture("adv", AUTHZ, Some(ROOT_ADMIN)).await;
        fx.write_bindings(
            "schema_version: 1\nbindings:\n  admin: [\"root\"]\n  adversary: [\"no-such-user-maknae-496\", {uid: 4242}]\n",
        );
        bounded(fx.reloader.run()).await.unwrap();
        let last = fx.reload_records().pop().unwrap();
        assert_eq!(
            (
                last.action.as_str(),
                last.outcome.result.as_str(),
                last.outcome.posture.as_str()
            ),
            ("graph.identity", "deny", "unavailable")
        );
        assert_eq!(fx.status.identity.counts(), ["unresolved_adversary=1"]);
        let subjects = fx.baseline().snapshot().subjects().unwrap();
        assert!(subjects
            .iter()
            .any(|b| b.role == "adversary" && b.members == ["uid:4242"]));
        let views = crate::identity_report::subject_views(subjects, &fx.status.identity.subjects());
        assert_eq!(
            views
                .iter()
                .map(|v| (v.uid, v.label.as_str(), v.state.as_str()))
                .collect::<Vec<_>>(),
            [
                (Some(0), "root (uid 0)", "bound admin"),
                (Some(4242), "uid 4242", "contained"),
                (
                    None,
                    "no-such-user-maknae-496 (no account)",
                    "unresolved adversary (no account, not contained)"
                ),
            ]
        );
    }

    #[tokio::test]
    async fn a_stalled_boot_identity_record_refuses_the_boot_after_the_append_bound() {
        let fx = fixture(
            "boot_probs_stalled",
            AUTHZ,
            Some("schema_version: 1\nbindings:\n  user: [\"no-such-user-maknae-496\"]\n"),
        )
        .await;
        let snapshot = fx.baseline().snapshot();
        let seq = Seq::new();
        let au3_1 = serde_json::Value::Null;
        let ctx = BootCtx {
            event: "boot",
            host: "h",
            socket: "s",
            euid: 0,
            session_id: 7 << 32,
            seq: &seq,
            au3_1: &au3_1,
        };
        fx.reloader.sink.stall_when(is_identity);
        tokio::time::pause();
        let status = crate::identity_report::IdentityStatus::default();
        let refused = tokio::time::timeout(
            Duration::from_secs(60),
            publish_boot_identity(&status, &snapshot, &[], None, &fx.reloader.sink, &ctx),
        )
        .await
        .expect("the identity record must give up within its bound");
        assert!(
            matches!(&refused, Err(RunError::Other(m)) if m.contains("identity")),
            "{refused:?}"
        );
    }

    #[tokio::test]
    async fn boot_identity_records_follow_the_composition_record_and_a_failed_append_refuses() {
        let fx = fixture(
            "boot_probs",
            AUTHZ,
            Some("schema_version: 1\nbindings:\n  user: [\"no-such-user-maknae-496\"]\n  adversary: [\"no-such-user-maknae-496b\"]\n"),
        )
        .await;
        let snapshot = fx.baseline().snapshot();
        let seq = Seq::new();
        let au3_1 = serde_json::Value::Null;
        let ctx = BootCtx {
            event: "boot",
            host: "h",
            socket: "s",
            euid: 0,
            session_id: 7 << 32,
            seq: &seq,
            au3_1: &au3_1,
        };
        let sink = &fx.reloader.sink;
        sink.emit(&ctx.record(
            "authz",
            "permit",
            "authorization composition: x",
            "authorized",
            None,
        ))
        .await
        .unwrap();
        let status = crate::identity_report::IdentityStatus::default();
        publish_boot_identity(&status, &snapshot, &[], None, sink, &ctx)
            .await
            .unwrap();
        let recs: Vec<AuditRecord> = std::fs::read_to_string(fx.dir.join("audit.jsonl"))
            .unwrap()
            .lines()
            .map(|l| serde_json::from_str::<AuditRecord>(l).unwrap())
            .filter(|r| r.session_id == 7 << 32)
            .collect();
        assert_eq!(
            recs.iter()
                .map(|r| (
                    r.action.as_str(),
                    r.event.as_str(),
                    r.outcome.posture.as_str(),
                    r.seq
                ))
                .collect::<Vec<_>>(),
            [
                ("authz", "boot", "authorized", recs[0].seq),
                ("graph.identity", "boot", "unavailable", recs[0].seq + 1),
                ("graph.identity", "boot", "unauthorized", recs[0].seq + 2),
            ]
        );
        assert_eq!(status.counts(), ["unresolved=1", "unresolved_adversary=1"]);
        sink.fail_identity
            .store(true, std::sync::atomic::Ordering::SeqCst);
        let refused = publish_boot_identity(&status, &snapshot, &[], None, sink, &ctx).await;
        assert!(
            matches!(&refused, Err(e) if e.to_string().contains("identity append refused")),
            "{refused:?}"
        );
    }

    #[tokio::test]
    async fn an_applied_reload_whose_identity_record_does_not_append_still_applies() {
        let fx = fixture("probs_append_fails", AUTHZ, Some(ROOT_ADMIN)).await;
        fx.reloader
            .sink
            .fail_identity
            .store(true, std::sync::atomic::Ordering::SeqCst);
        fx.write_bindings(GHOST_USER);
        let applied = bounded(fx.reloader.run()).await.unwrap();
        assert!(applied.persisted);
        let recs = fx.reload_records();
        assert_eq!(
            (
                recs.last().unwrap().action.as_str(),
                recs.last().unwrap().outcome.result.as_str()
            ),
            ("graph.reload", "permit")
        );
        assert!(identity_records(&recs).is_empty());
        assert_eq!(fx.status.identity.counts(), ["unresolved=1"]);
        assert!(matches!(
            fx.root_whoami(),
            maknae_security::Verdict::Permit { .. }
        ));
    }

    #[tokio::test]
    async fn a_reload_whose_release_record_does_not_append_persists_nothing() {
        let fx = fixture("release_append_fails", AUTHZ, Some(ROOT_ADVERSARY)).await;
        let before = fx.store_bytes();
        let policy = fx
            .baseline()
            .snapshot()
            .policy_sha256(maknae_state::envelope::sha256);
        fx.reloader
            .sink
            .fail_identity
            .store(true, std::sync::atomic::Ordering::SeqCst);
        fx.write_bindings("schema_version: 1\n");
        let refused = bounded(fx.reloader.run()).await.unwrap_err();
        assert!(
            matches!(&refused, crate::reload::Refusal::Persist(m) if m.contains("identity append refused")),
            "{refused:?}"
        );
        assert_eq!(fx.store_bytes(), before);
        assert_eq!(fx.status.revision(), 1);
        assert_eq!(
            fx.baseline()
                .snapshot()
                .policy_sha256(maknae_state::envelope::sha256),
            policy
        );
        assert_eq!(
            whoami_as(&fx, 0).1,
            Some("adversary"),
            "the old snapshot stands"
        );
        let actions: Vec<String> = fx.reload_records().into_iter().map(|r| r.action).collect();
        assert_eq!(actions, ["graph.reload", "graph.reload"]);
    }

    #[tokio::test]
    async fn the_next_boot_verifies_a_reloaded_store_against_its_checkpoint() {
        let fx = fixture("reboot", AUTHZ, Some(ROOT_ADMIN)).await;
        fx.write_bindings(ROOT_ADVERSARY);
        fx.reloader.run().await.unwrap();
        let accepted = fx.stored().unwrap();
        let before = fx.dir.join("audit.jsonl");
        let reloaded = std::fs::read_to_string(&before).unwrap().lines().count();
        let Fx {
            dir,
            reloader,
            _guard,
            ..
        } = fx;
        drop(reloader);
        let sink = Arc::new(
            maknae_audit_append::AuditSink::open(&maknae_config::AuditConfig {
                readers: Vec::new(),
                jsonl_path: dir.join("audit.jsonl"),
                siem: None,
                au3_1: serde_json::Value::Null,
            })
            .unwrap(),
        );
        let source = maknae_authz_basic::PolicySource::load_with_requirement(
            maknae_authz_basic::PolicyPaths::in_dir(&dir),
            principal(),
            requirement(),
        )
        .unwrap();
        let inputs = GraphInputs::new(&source, "UNCLASSIFIED", accepted.clone()).unwrap();
        let seq = Seq::new();
        let au3_1 = serde_json::Value::Null;
        let booted = boot_graph_at(
            &dir.join("state"),
            maknae_vault::graph_key_from_bytes(&[0x5a; 32]),
            &sink,
            &BootCtx {
                event: "boot",
                host: "h",
                socket: "s",
                euid: nix::unistd::geteuid().as_raw(),
                session_id: 10 << 32,
                seq: &seq,
                au3_1: &au3_1,
            },
            &inputs.boot(),
        )
        .await
        .unwrap();
        assert_eq!(
            (booted.status.revision(), booted.status.anchor.as_str()),
            (2, "verified")
        );
        assert_eq!(
            maknae_graph::identity::extract(&booted.graph)
                .unwrap()
                .baseline,
            Some(accepted)
        );
        let after: Vec<String> = std::fs::read_to_string(&before)
            .unwrap()
            .lines()
            .skip(reloaded)
            .map(|l| serde_json::from_str::<AuditRecord>(l).unwrap().action)
            .collect();
        assert_eq!(after, ["graph.checkpoint"]);
    }

    #[tokio::test]
    async fn kernel_graph_revision_follows_a_reload() {
        let fx = fixture("status", AUTHZ, Some(ROOT_ADMIN)).await;
        assert_eq!(fx.status.revision(), 1);
        fx.write_bindings(ROOT_ADVERSARY);
        fx.reloader.run().await.unwrap();
        assert_eq!(fx.status.revision(), 2);
        assert_eq!(fx.reloader.dir.store_revision(), 2);
    }

    #[tokio::test]
    async fn a_bindings_yaml_edit_applies_at_reload() {
        let fx = fixture("bedit", AUTHZ, Some(ROOT_ADMIN)).await;
        assert!(matches!(
            fx.root_whoami(),
            maknae_security::Verdict::Permit { .. }
        ));
        let before = fx.status.revision();
        fx.write_bindings(ROOT_ADVERSARY);
        assert!(
            matches!(fx.root_whoami(), maknae_security::Verdict::Permit { .. }),
            "nothing re-reads the file per request"
        );
        let applied = bounded(fx.reloader.run()).await.unwrap();
        assert!(applied.persisted);
        assert_eq!(fx.root_whoami(), adversary());
        assert_eq!(fx.status.revision(), before + 1);
    }

    #[tokio::test]
    async fn an_authz_yaml_edit_that_adds_bindings_is_a_refused_reload() {
        let fx = fixture("authz_adds_bindings", AUTHZ, Some(ROOT_ADMIN)).await;
        let store = fx.store_bytes();
        fx.write_policy("schema_version: 1\nbindings:\n  adversary: [\"root\"]\n");
        let got = bounded(fx.reloader.run()).await;
        assert!(
            matches!(&got, Err(crate::reload::Refusal::Load(m)) if m.contains("bindings.yaml")),
            "{got:?}"
        );
        assert!(matches!(
            fx.root_whoami(),
            maknae_security::Verdict::Permit { .. }
        ));
        assert_eq!(fx.store_bytes(), store);
        let last = outcomes(&fx.reload_records()).pop().unwrap();
        assert_eq!((last.0.as_str(), last.1.as_str()), ("graph.reload", "deny"));
        assert!(
            last.2.starts_with("reload refused: policy load:") && last.2.contains("bindings.yaml"),
            "{}",
            last.2
        );
    }

    #[tokio::test]
    async fn an_invalid_bindings_yaml_refuses_the_whole_reload() {
        let fx = fixture("bbad", AUTHZ, Some(ROOT_ADMIN)).await;
        let store = fx.store_bytes();
        let digest = fx
            .baseline()
            .snapshot()
            .policy_sha256(maknae_state::envelope::sha256);
        fx.write_policy("schema_version: 1\nroles:\n  admin:\n    allow: [admin.status]\n");
        fx.write_bindings("schema_version: 1\nbindings: [\n");
        let got = bounded(fx.reloader.run()).await;
        assert!(
            matches!(&got, Err(crate::reload::Refusal::Load(m)) if m.contains("bindings.yaml")),
            "{got:?}"
        );
        assert_eq!(fx.store_bytes(), store);
        assert_eq!(
            fx.baseline()
                .snapshot()
                .policy_sha256(maknae_state::envelope::sha256),
            digest,
            "the authz.yaml edit made with it is not applied either"
        );
    }

    #[tokio::test]
    async fn a_bindings_yaml_without_the_key_is_bindings_absent_at_reload() {
        let fx = fixture("brm", AUTHZ, Some("schema_version: 1\nbindings: {}\n")).await;
        assert_eq!(fx.baseline().snapshot().subjects(), Some(vec![]));
        fx.write_bindings("schema_version: 1\n");
        let applied = bounded(fx.reloader.run()).await.unwrap();
        assert!(applied.persisted, "the bindings Section node goes away");
        assert_eq!(fx.baseline().snapshot().subjects(), None);
    }

    #[tokio::test]
    async fn invalid_reload_keeps_old_snapshot_and_store() {
        let fx = fixture("invalid", AUTHZ, Some(ROOT_ADMIN)).await;
        let before = fx.baseline().snapshot();
        let bytes = fx.store_bytes();
        fx.write_policy("not: [valid");
        let refused = fx.reloader.run().await.unwrap_err();
        assert!(
            matches!(refused, crate::reload::Refusal::Load(_)),
            "{refused:?}"
        );
        assert!(Arc::ptr_eq(&before, &fx.baseline().snapshot()));
        assert_eq!(fx.store_bytes(), bytes);
        assert_eq!(fx.status.revision(), 1);
        let recs = fx.reload_records();
        let o = outcomes(&recs);
        assert_eq!(o.len(), 2, "{o:?}");
        assert_eq!(o[0].0, "graph.reload");
        assert_eq!(o[0].1, "permit");
        assert_eq!((o[1].0.as_str(), o[1].1.as_str()), ("graph.reload", "deny"));
        assert!(
            o[1].2.starts_with("reload refused: policy load: "),
            "{}",
            o[1].2
        );
        assert_eq!(recs[1].outcome.posture, "unavailable");
        let graph = recs[1].graph.as_ref().unwrap();
        assert_eq!(
            (
                graph.revision,
                graph.anchor.as_str(),
                graph.ciphertext_sha256.as_str()
            ),
            (1, "reload-refused", "")
        );
        assert_eq!(
            recs[1].policy_sha256,
            Some(before.policy_sha256(maknae_state::envelope::sha256))
        );
        assert!(matches!(
            fx.root_whoami(),
            maknae_security::Verdict::Permit { .. }
        ));
    }

    #[tokio::test]
    async fn a_refused_persist_installs_nothing() {
        let fx = fixture("persist", AUTHZ, Some(ROOT_ADMIN)).await;
        let before = fx.baseline().snapshot();
        let bytes = fx.store_bytes();
        fx.write_bindings(ROOT_ADVERSARY);
        fx.reloader.revision.store(0, AtomicOrdering::Release);
        let refused = fx.reloader.run().await.unwrap_err();
        assert!(
            matches!(refused, crate::reload::Refusal::Persist(_)),
            "{refused:?}"
        );
        assert!(Arc::ptr_eq(&before, &fx.baseline().snapshot()));
        assert_eq!(fx.store_bytes(), bytes);
        assert!(matches!(
            fx.root_whoami(),
            maknae_security::Verdict::Permit { .. }
        ));
        let o = outcomes(&fx.reload_records());
        assert_eq!(o.len(), 2, "{o:?}");
        assert!(
            o[1].2.starts_with("reload refused: persist: "),
            "{}",
            o[1].2
        );
    }

    #[tokio::test]
    async fn a_reload_whose_store_sync_fails_is_applied_and_says_so() {
        let fx = fixture("unsynced", AUTHZ, Some(ROOT_ADMIN)).await;
        fx.write_bindings(ROOT_ADVERSARY);
        fx.reloader.dir.fail_next_directory_sync();
        let cause = "published, but the directory sync failed (Other { raw: 5 }): kernel.graph";
        let applied = fx.reloader.run().await.unwrap();
        assert_eq!(
            applied,
            crate::reload::Applied {
                revision: 2,
                persisted: true,
                durability_error: Some(cause.into()),
                checkpoint_error: None,
            }
        );
        assert_eq!(fx.root_whoami(), adversary());
        assert_eq!(fx.baseline().snapshot().revision(), 2);
        assert_eq!(fx.reloader.dir.store_revision(), 2);
        let recs = fx.reload_records();
        let last = recs.last().unwrap();
        assert_eq!(
            (
                last.outcome.result.as_str(),
                last.outcome.reason.as_str(),
                last.outcome.posture.as_str()
            ),
            (
                "permit",
                format!(
                    "reload applied: revision 2; identity persisted; store not durable: {cause}"
                )
                .as_str(),
                "authorized"
            )
        );
        fx.write_bindings(ROOT_ADMIN);
        let next = fx.reloader.run().await.unwrap();
        assert_eq!((next.revision, next.durability_error), (3, None));
    }

    #[tokio::test]
    async fn an_unchanged_file_reloads_without_a_persist() {
        let fx = fixture("unchanged", AUTHZ, Some(ROOT_ADMIN)).await;
        let before = fx.baseline().snapshot();
        let bytes = fx.store_bytes();
        fx.write_policy("schema_version: 1\npermissions:\n  allow: [\"Read(~/**)\"]\n  deny: []\n");
        let applied = fx.reloader.run().await.unwrap();
        assert_eq!(
            applied,
            crate::reload::Applied {
                revision: 1,
                persisted: false,
                durability_error: None,
                checkpoint_error: None,
            }
        );
        let after = fx.baseline().snapshot();
        assert!(
            !Arc::ptr_eq(&before, &after),
            "the recompiled snapshot is installed"
        );
        assert!(Arc::ptr_eq(before.persisted(), after.persisted()));
        assert_eq!(fx.store_bytes(), bytes);
        let recs = fx.reload_records();
        let o = outcomes(&recs);
        assert_eq!(
            o.iter().map(|r| r.0.as_str()).collect::<Vec<_>>(),
            ["graph.reload", "graph.reload"]
        );
        assert_eq!(o[1].2, "reload applied: revision 1; identity unchanged");
        let digest = maknae_state::envelope::sha256;
        assert_eq!(recs[0].policy_sha256, None);
        assert_eq!(
            recs[1].policy_sha256.as_deref(),
            Some(after.policy_sha256(digest).as_str())
        );
        assert_ne!(after.policy_sha256(digest), before.policy_sha256(digest));
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn two_hups_in_flight_run_in_turn() {
        let fx = fixture("turns", AUTHZ, Some(ROOT_ADMIN)).await;
        fx.write_bindings(ROOT_ADVERSARY);
        let (a, b) = tokio::join!(fx.reloader.run(), fx.reloader.run());
        let mut revisions = [a.unwrap().revision, b.unwrap().revision];
        revisions.sort_unstable();
        assert_eq!(revisions, [2, 2]);
        let recs = fx.reload_records();
        let actions: Vec<&str> = recs.iter().map(|r| r.action.as_str()).collect();
        assert_eq!(
            actions,
            [
                "graph.reload",
                "graph.transition",
                "graph.checkpoint",
                "graph.reload",
                "graph.reload",
                "graph.reload"
            ]
        );
        assert_eq!(recs[0].session_id, recs[3].session_id);
        assert_eq!(recs[4].session_id, recs[5].session_id);
        assert_ne!(recs[0].session_id, recs[4].session_id);
        assert_eq!(
            recs[5].outcome.reason,
            "reload applied: revision 2; identity unchanged"
        );
        assert_eq!(fx.status.revision(), 2);
    }

    #[tokio::test]
    async fn sighup_during_boot_is_buffered_not_fatal() {
        let hup = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::hangup()).unwrap();
        let sent = std::process::Command::new("kill")
            .args(["-HUP", &std::process::id().to_string()])
            .status()
            .unwrap();
        assert!(sent.success());
        let seen = Arc::new(AtomicU64::new(0));
        let task = tokio::spawn(reload_task(hup, {
            let seen = Arc::clone(&seen);
            move || {
                seen.fetch_add(1, AtomicOrdering::SeqCst);
                async {}
            }
        }));
        let deadline = Instant::now() + Duration::from_secs(5);
        while seen.load(AtomicOrdering::SeqCst) == 0 && Instant::now() < deadline {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
        assert_eq!(seen.load(AtomicOrdering::SeqCst), 1);
        task.abort();
    }

    struct IdleAccept;

    impl PlaneAccept for IdleAccept {
        type Raw = ();
        type Stream = tokio::io::DuplexStream;

        async fn accept_raw(&self) -> Result<((), PeerCreds), maknae_vault::RawAcceptError> {
            std::future::pending().await
        }

        async fn finish_handshake(
            &self,
            _raw: (),
            _peer_creds: PeerCreds,
            _handshake_timeout: Duration,
        ) -> Result<Conn<tokio::io::DuplexStream>, AcceptRejection> {
            unreachable!("nothing is accepted")
        }
    }

    fn all_records(fx: &Fx) -> Vec<AuditRecord> {
        std::fs::read_to_string(fx.dir.join("audit.jsonl"))
            .unwrap()
            .lines()
            .map(|l| serde_json::from_str::<AuditRecord>(l).unwrap())
            .collect()
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_reload_stuck_loading_does_not_hold_up_shutdown() {
        let (_release, gate) = std::sync::mpsc::channel::<()>();
        let fx = fixture_gated("stuck", AUTHZ, Some(ROOT_ADMIN), Some(gate)).await;
        fx.write_bindings(ROOT_ADVERSARY);
        let before = fx.baseline().snapshot();
        let bytes = fx.store_bytes();
        let reload = tokio::spawn({
            let reloader = Arc::clone(&fx.reloader);
            async move { reloader.run().await }
        });
        let deadline = Instant::now() + Duration::from_secs(5);
        while fx.reload_records().is_empty() && Instant::now() < deadline {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        assert_eq!(fx.reload_records().len(), 1, "the reload is loading");

        let shutdown =
            shutdown_after_reloads(async {}, Arc::clone(&fx.reloader), reload.abort_handle());
        let outcome = tokio::time::timeout(
            Duration::from_secs(5),
            accept_loop(
                IdleAccept,
                Arc::clone(&fx.reloader.sink),
                Arc::new(SessionIds::new()),
                maknae_config::transport_from_section(None).unwrap(),
                WhereCtx {
                    host: "h".into(),
                    socket: "s".into(),
                    au3_1: serde_json::Value::Null,
                },
                shutdown,
                tokio::spawn(std::future::pending()),
                Arc::clone(&fx.reloader.authorizer),
                std::sync::Arc::new(crate::live::LiveConfig::new(ConfigView::default(), None)),
                Arc::new("b".into()),
                Arc::new("US".into()),
                Arc::new(None),
                crate::egress::unavailable_egress(),
                baseline_stub::no_baseline(),
                baseline_stub::serving(),
            ),
        )
        .await
        .expect("shutdown completes while the load is stuck");
        assert!(matches!(outcome, ServeOutcome::GracefulShutdown));

        let recs = all_records(&fx);
        let tail: Vec<(&str, &str, &str)> = recs
            .iter()
            .skip_while(|r| r.event != "reload")
            .map(|r| {
                (
                    r.action.as_str(),
                    r.outcome.result.as_str(),
                    r.outcome.reason.as_str(),
                )
            })
            .collect();
        assert_eq!(
            tail,
            [
                ("graph.reload", "permit", "intent recorded (SIGHUP)"),
                ("graph.reload", "deny", "reload refused: shutdown"),
                ("serve", "permit", "shutdown: signal received"),
            ]
        );
        assert!(Arc::ptr_eq(&before, &fx.baseline().snapshot()));
        assert_eq!(fx.store_bytes(), bytes);
        assert!(matches!(
            reload.await,
            Ok(Err(crate::reload::Refusal::Shutdown))
        ));
    }

    #[tokio::test]
    async fn shutdown_waits_for_a_reload_holding_the_turn() {
        let fx = fixture("turn", AUTHZ, Some(ROOT_ADMIN)).await;
        let reloads = tokio::spawn(std::future::pending::<()>());
        let turn = fx.reloader.lock.lock().await;
        let mut shutdown = Box::pin(shutdown_after_reloads(
            async {},
            Arc::clone(&fx.reloader),
            reloads.abort_handle(),
        ));
        assert!(
            tokio::time::timeout(Duration::from_millis(200), &mut shutdown)
                .await
                .is_err(),
            "shutdown must not pass a reload that holds the turn"
        );
        assert!(!reloads.is_finished());
        drop(turn);
        tokio::time::timeout(Duration::from_secs(5), shutdown)
            .await
            .expect("shutdown proceeds once the turn is released");
        assert!(reloads.await.unwrap_err().is_cancelled());
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_reload_that_never_releases_its_turn_does_not_hold_up_the_stop_record() {
        let fx = fixture("wedged", AUTHZ, Some(ROOT_ADMIN)).await;
        let reloads = tokio::spawn(std::future::pending::<()>());
        let reloader = Arc::clone(&fx.reloader);
        let (held, turn_held) = tokio::sync::oneshot::channel();
        let wedged = tokio::spawn(async move {
            let _turn = reloader.lock.lock().await;
            let _ = held.send(());
            std::future::pending::<()>().await;
        });
        turn_held.await.unwrap();
        let shutdown =
            shutdown_after_reloads(async {}, Arc::clone(&fx.reloader), reloads.abort_handle());
        let outcome = tokio::time::timeout(
            RELOAD_STOP_TIMEOUT + Duration::from_secs(5),
            accept_loop(
                IdleAccept,
                Arc::clone(&fx.reloader.sink),
                Arc::new(SessionIds::new()),
                maknae_config::transport_from_section(None).unwrap(),
                WhereCtx {
                    host: "h".into(),
                    socket: "s".into(),
                    au3_1: serde_json::Value::Null,
                },
                shutdown,
                tokio::spawn(std::future::pending()),
                Arc::clone(&fx.reloader.authorizer),
                std::sync::Arc::new(crate::live::LiveConfig::new(ConfigView::default(), None)),
                Arc::new("b".into()),
                Arc::new("US".into()),
                Arc::new(None),
                crate::egress::unavailable_egress(),
                baseline_stub::no_baseline(),
                baseline_stub::serving(),
            ),
        )
        .await
        .expect("the stop record is not ordered behind a turn that is never released");
        assert!(matches!(outcome, ServeOutcome::GracefulShutdown));
        let last = all_records(&fx).pop().unwrap();
        assert_eq!(
            (last.action.as_str(), last.outcome.reason.as_str()),
            ("serve", "shutdown: signal received")
        );
        tokio::time::timeout(
            Duration::from_secs(1),
            fx.reloader.stop(&reloads.abort_handle()),
        )
        .await
        .expect("a second stop does not wait again");
        assert!(
            !reloads.is_finished(),
            "a reload past the bound is left to finish"
        );
        wedged.abort();
        reloads.abort();
    }

    #[tokio::test]
    async fn a_reload_queued_behind_shutdown_records_nothing() {
        let fx = fixture("queued", AUTHZ, Some(ROOT_ADMIN)).await;
        fx.reloader.stopping.send_replace(true);
        assert_eq!(
            fx.reloader.run().await,
            Err(crate::reload::Refusal::Shutdown)
        );
        assert!(fx.reload_records().is_empty());
    }

    /// Structural tripwire: no runtime test can tell where the registration sits.
    #[test]
    fn sighup_is_registered_before_anything_else_in_run_inner() {
        let src = include_str!("run.rs");
        let prod = &src[..src.find("\nmod tests {").expect("a test module")];
        let start = prod.find("\nasync fn run_inner(").expect("run_inner");
        let body = &prod[start..];
        let body = &body[body
            .find(") -> Result<ServeOutcome, RunError> {\n")
            .expect("signature")..];
        let first = body
            .lines()
            .skip(1)
            .map(str::trim)
            .find(|l| !l.is_empty() && !l.starts_with("//"))
            .expect("a statement");
        assert_eq!(
            first,
            "let hup = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::hangup())"
        );
    }
}

#[cfg(test)]
mod unencodable_tests {
    use super::*;

    #[derive(Default)]
    struct Recorder(std::sync::Mutex<Vec<AuditRecord>>);
    impl AuditEmit for Recorder {
        fn emit(
            &self,
            record: &AuditRecord,
        ) -> impl std::future::Future<Output = Result<(), maknae_audit_append::AuditError>> + Send
        {
            self.0.lock().unwrap().push(record.clone());
            async { Ok(()) }
        }
    }

    #[tokio::test]
    async fn an_unencodable_permit_keeps_the_rule_that_permitted_it() {
        let (mut client, mut server) = tokio::io::duplex(64 * 1024);
        let emit = Arc::new(Recorder::default());
        let rule = RuleCitation {
            node: 7,
            key: "sentinel-unencodable-rule".into(),
            section: "authz.yaml#permissions".into(),
        };
        refuse_unencodable_bounded(
            &mut server,
            &maknae_config::transport_from_section(None).unwrap(),
            maknae_proto::FrameClass::Control,
            &emit,
            "h",
            "s",
            1000,
            "maknae://d/plane/cli",
            Some("alice"),
            Some("user"),
            Some(&rule),
            1,
            &Seq::new(),
            "fs.read",
            &serde_json::json!({}),
        )
        .await;
        let records = emit.0.lock().unwrap().clone();
        assert_eq!(records.len(), 1);
        assert_eq!(
            records[0].outcome.reason,
            "delivery failed: response could not be encoded"
        );
        assert_eq!(records[0].rule, Some(rule_audit(&rule)));
        let caps = maknae_proto::FrameCaps {
            control: 1 << 20,
            attempt: 1 << 20,
            prompt: 1 << 20,
        };
        let (_, reply) = tokio::time::timeout(
            std::time::Duration::from_secs(5),
            maknae_proto::read_frame_zeroizing(&mut client, &caps),
        )
        .await
        .expect("the error frame is released")
        .expect("an error frame");
        assert!(matches!(
            maknae_proto::decode_response(&reply).unwrap().result,
            RespResult::Err(_)
        ));
    }
}
