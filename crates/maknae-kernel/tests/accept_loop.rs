//! Accept-loop integration suite (spec §10). Exercises the run-loop's accept-level
//! behaviour — audit-and-continue on a surfaced cert-half rejection (NEVER kill the
//! daemon), fast-close at capacity, and audit of a handshake-timeout rejection —
//! against a SCRIPTED [`maknae_kernel::PlaneAccept`] fake.
//!
//! Why a fake instead of a live `PlaneListener`: a real listener requires a
//! Vault-minted plane leaf (`PlaneClient::mint`), unavailable in CI. The transport's
//! own rejection *classification* (wrong-plane → `AcceptRejection` with peer-creds) is
//! already proven in `maknae-vault`'s `transport_tests::accept_reject_wrong_plane_
//! carries_peer_creds`; this suite proves what the KERNEL does with those outcomes:
//! audit them and keep serving. Real peer-creds are synthesised via `PeerCreds`'s public
//! fields (the same struct the transport attaches).
mod common;
use common::fixture_principal;

use std::collections::VecDeque;
use std::future::Future;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use maknae_audit_append::{AuditEmit, AuditError, AuditRecord, SessionIds};
use maknae_kernel::{Conn, PlaneAccept, ServeOutcome, WhereCtx};
use maknae_vault::{AcceptRejection, PeerCreds, RejectReason, VaultError};
use tokio::io::DuplexStream;
use tokio::time::Instant;

/// Recording sink (never fails) shared with the accept loop.
struct RecEmit {
    recs: Mutex<Vec<AuditRecord>>,
}
impl RecEmit {
    fn new() -> Arc<Self> {
        Arc::new(RecEmit {
            recs: Mutex::new(Vec::new()),
        })
    }
    fn records(&self) -> Vec<AuditRecord> {
        self.recs.lock().unwrap().clone()
    }
}
impl AuditEmit for RecEmit {
    fn emit(&self, rec: &AuditRecord) -> impl Future<Output = Result<(), AuditError>> + Send {
        self.recs.lock().unwrap().push(rec.clone());
        async move { Ok(()) }
    }
}

/// A scripted accept source. Each `accept_raw()` pops the next outcome; when the script is
/// exhausted it parks forever (so the loop blocks in `accept_raw` until shutdown fires).
/// A `Reject`/`Stall` is realised in `finish_handshake` (the bounded half the run-loop now
/// runs UNDER its semaphore) — proving the loop's new prompt-accept / deferred-handshake
/// split behaves: rejections still audit, and a stalled handshake does not block the loop.
enum Scripted {
    Ok(DuplexStream, String, u32),
    Reject(AcceptRejection),
    /// `accept_raw` succeeds, but `finish_handshake` sleeps this long before yielding an OK
    /// connection — simulating a peer that stalls the TLS handshake.
    Stall(Duration, DuplexStream, String, u32),
}

/// The raw handle `accept_raw` hands to `finish_handshake` (opaque, like `RawPlaneConn`).
enum FakeRaw {
    Conn(DuplexStream, String, u32),
    Reject(AcceptRejection),
    Stall(Duration, DuplexStream, String, u32),
}

struct FakeAccept {
    queue: Mutex<VecDeque<Scripted>>,
    /// Count of scripted items actually consumed by `accept_raw` — a clone of this Arc is
    /// taken BEFORE the acceptor is moved into `accept_loop`, so a test can observe how
    /// far the loop has progressed (P2: proving the loop keeps accepting even while the
    /// at-capacity audit sink is slow).
    popped: Arc<std::sync::atomic::AtomicUsize>,
}
impl FakeAccept {
    fn new(items: Vec<Scripted>) -> Self {
        FakeAccept {
            queue: Mutex::new(items.into_iter().collect()),
            popped: Arc::new(std::sync::atomic::AtomicUsize::new(0)),
        }
    }
    fn pop_counter(&self) -> Arc<std::sync::atomic::AtomicUsize> {
        Arc::clone(&self.popped)
    }
}
impl PlaneAccept for FakeAccept {
    type Raw = FakeRaw;
    type Stream = DuplexStream;

    // Pop INSIDE the future so a `select!` that loses to shutdown (dropping this future
    // unpolled) does not silently consume a scripted item. The std MutexGuard is released
    // before the only await, so the future stays `Send` (satisfying the trait bound).
    async fn accept_raw(&self) -> Result<(FakeRaw, PeerCreds), std::io::Error> {
        let item = self.queue.lock().unwrap().pop_front();
        if item.is_some() {
            self.popped
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        }
        match item {
            Some(Scripted::Ok(stream, uri, uid)) => {
                Ok((FakeRaw::Conn(stream, uri, uid), creds(uid)))
            }
            Some(Scripted::Reject(rej)) => {
                let c = rej.peer_creds.unwrap_or_else(|| creds(0));
                Ok((FakeRaw::Reject(rej), c))
            }
            Some(Scripted::Stall(d, stream, uri, uid)) => {
                Ok((FakeRaw::Stall(d, stream, uri, uid), creds(uid)))
            }
            None => {
                std::future::pending::<()>().await;
                unreachable!()
            }
        }
    }

    async fn finish_handshake(
        &self,
        raw: FakeRaw,
        _peer_creds: PeerCreds,
        _handshake_timeout: Duration,
    ) -> Result<Conn<DuplexStream>, AcceptRejection> {
        match raw {
            FakeRaw::Conn(stream, uri, uid) => Ok(Conn {
                delegated: maknae_io::DelegatedFds::new(0),
                stream,
                peer_uri: uri,
                peer_uid: uid,
            }),
            FakeRaw::Reject(rej) => Err(rej),
            FakeRaw::Stall(d, stream, uri, uid) => {
                tokio::time::sleep(d).await;
                Ok(Conn {
                    delegated: maknae_io::DelegatedFds::new(0),
                    stream,
                    peer_uri: uri,
                    peer_uid: uid,
                })
            }
        }
    }
}

fn creds(uid: u32) -> PeerCreds {
    PeerCreds {
        uid,
        gid: Some(uid),
        pid: Some(4242),
    }
}

fn wctx() -> WhereCtx {
    WhereCtx {
        host: "test-host".to_string(),
        socket: "/run/maknae/test.sock".to_string(),
        au3_1: serde_json::json!({}),
    }
}

fn cfg_with(max_connections: u32, read_timeout_ms: u64) -> maknae_config::TransportConfig {
    let mut c = maknae_config::transport_from_section(None).unwrap();
    c.max_connections = max_connections;
    c.read_timeout_ms = read_timeout_ms;
    c
}

/// A credential-supervisor handle that never resolves — used by every test in this
/// suite that exercises OTHER accept-loop behavior, so the new supervisor-exit `select!`
/// branch (codex round-5 P1) never fires and cannot interfere.
fn pending_supervisor() -> tokio::task::JoinHandle<VaultError> {
    tokio::spawn(std::future::pending())
}

/// An OK connection whose peer end we DROP (so the served handle sees EOF and closes).
fn ok_conn(uri: &str, uid: u32) -> Scripted {
    let (client, server) = tokio::io::duplex(1024);
    drop(client);
    Scripted::Ok(server, uri.to_string(), uid)
}

/// Run the loop over a script until it drains, then fire shutdown and join. Returns the
/// recorded audit records.
async fn drive(script: Vec<Scripted>, cfg: maknae_config::TransportConfig) -> Vec<AuditRecord> {
    let emit = RecEmit::new();
    let acceptor = FakeAccept::new(script);
    let session_ids = Arc::new(SessionIds::with_nonce(1));
    let (tx, rx) = tokio::sync::oneshot::channel::<()>();
    let shutdown = async move {
        let _ = rx.await;
    };

    let emit_for_loop = emit.clone();
    let loop_task = tokio::spawn(async move {
        maknae_kernel::accept_loop(
            acceptor,
            emit_for_loop,
            session_ids,
            cfg,
            wctx(),
            shutdown,
            pending_supervisor(),
            std::sync::Arc::new(common::AlwaysPermit),
            std::sync::Arc::new(fixture_principal()),
        )
        .await;
    });

    // Give the loop time to consume the whole script (and spawn/settle its handlers).
    tokio::time::sleep(Duration::from_millis(300)).await;
    let _ = tx.send(());
    loop_task.await.unwrap();
    emit.records()
}

#[tokio::test]
async fn cert_half_rejection_audits() {
    // A wrong-plane rejection (peer-creds present) THEN a good connection: the loop must
    // audit the rejection AND keep serving (process the second connection).
    let script = vec![
        Scripted::Reject(AcceptRejection {
            peer_creds: Some(creds(1001)),
            reason: RejectReason::WrongPlane,
        }),
        ok_conn("maknae://d/plane/cli", 1002),
    ];
    let recs = drive(script, cfg_with(64, 150)).await;

    let reject = recs
        .iter()
        .find(|r| r.event == "connection" && r.outcome.reason.contains("wrong plane"))
        .expect("the wrong-plane rejection must be audited");
    assert_eq!(reject.outcome.result, "deny");
    assert_eq!(
        reject.source.uid, 1001,
        "the rejected peer's uid must be recorded"
    );

    // The loop CONTINUED: the good connection was processed and produced its own record.
    assert!(
        recs.len() >= 2,
        "loop must keep serving after a rejection (got records: {recs:?})"
    );
    assert!(
        recs.iter().any(|r| r.source.uid == 1002),
        "the connection accepted after the rejection must have been processed"
    );
}

#[tokio::test]
async fn at_capacity_fast_closes() {
    // max_connections = 1. The first connection's handler holds the only permit (it blocks
    // in read for read_timeout_ms because we keep its peer end open); the second is accepted
    // while the permit is held → at-capacity fast-close + audit.
    let (client1, server1) = tokio::io::duplex(1024);
    let script = vec![
        Scripted::Ok(server1, "maknae://d/plane/cli".to_string(), 2001),
        ok_conn("maknae://d/plane/cli", 2002),
    ];
    // read_timeout_ms = 1000 so the first handler keeps the permit long enough.
    let recs = drive(script, cfg_with(1, 1000)).await;
    drop(client1); // keep client1's peer end open across the loop's processing window

    let at_cap = recs
        .iter()
        .find(|r| r.event == "connection" && r.outcome.reason.contains("at capacity"))
        .expect("the second connection must be audited as at-capacity");
    assert_eq!(at_cap.outcome.result, "deny");
    assert_eq!(at_cap.source.uid, 2002);
    assert_eq!(at_cap.outcome.posture, "unauthorized");
}

#[tokio::test]
async fn handshake_timeout_audits() {
    // A handshake-timeout rejection (peer-creds present) THEN a good connection: the loop
    // audits the timeout with the surfaced reason AND continues.
    let script = vec![
        Scripted::Reject(AcceptRejection {
            peer_creds: Some(creds(3001)),
            reason: RejectReason::HandshakeTimeout,
        }),
        ok_conn("maknae://d/plane/cli", 3002),
    ];
    let recs = drive(script, cfg_with(64, 150)).await;

    let timeout = recs
        .iter()
        .find(|r| r.event == "connection" && r.outcome.reason.contains("handshake timeout"))
        .expect("the handshake-timeout rejection must be audited");
    assert_eq!(timeout.outcome.result, "deny");
    assert_eq!(
        timeout.source.uid, 3001,
        "peer-creds must be present on a timeout deny"
    );

    // Loop continued past the timeout.
    assert!(
        recs.iter().any(|r| r.source.uid == 3002),
        "the connection accepted after the handshake timeout must have been processed"
    );
}

#[tokio::test]
async fn stalled_handshake_does_not_block_next_connection() {
    // The anti-DoS property (P1-A): connection A stalls its TLS handshake for a long time;
    // connection B handshakes instantly. Because the handshake now runs per-connection UNDER
    // the semaphore (NOT inline on the accept loop), B is accepted and SERVED while A is
    // still stalled — the loop is never serialized on A's handshake. We observe B's records
    // WITHOUT waiting for A (a graceful drain would block on A's 30s stall), then abort.
    // Keep A's peer end open (bound, not dropped) so, even if A ever finished, it would just
    // block in read — the point is only that B is served first.
    let (_a_client, a_server) = tokio::io::duplex(1024);
    let script = vec![
        Scripted::Stall(
            Duration::from_secs(30),
            a_server,
            "maknae://d/plane/cli".to_string(),
            7001,
        ),
        ok_conn("maknae://d/plane/cli", 7002),
    ];

    let emit = RecEmit::new();
    let acceptor = FakeAccept::new(script);
    let session_ids = Arc::new(SessionIds::with_nonce(1));
    // Capacity for BOTH so A's stall does not starve B on the semaphore (this test isolates
    // loop-serialization, not the capacity cap — that is `at_capacity_fast_closes`).
    let cfg = cfg_with(64, 150);
    let emit_for_loop = emit.clone();
    let loop_task = tokio::spawn(async move {
        maknae_kernel::accept_loop(
            acceptor,
            emit_for_loop,
            session_ids,
            cfg,
            wctx(),
            std::future::pending::<()>(),
            pending_supervisor(),
            std::sync::Arc::new(common::AlwaysPermit),
            std::sync::Arc::new(fixture_principal()),
        )
        .await;
    });

    // Poll until B (uid 7002) is served, WITHOUT draining A.
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        if emit.records().iter().any(|r| r.source.uid == 7002) {
            break;
        }
        assert!(
            Instant::now() < deadline,
            "connection B was NOT served while A stalled its handshake — the accept loop \
             appears serialized on the handshake (DoS regression)"
        );
        tokio::time::sleep(Duration::from_millis(20)).await;
    }

    // A is still stalled (30s) — abort rather than gracefully drain.
    loop_task.abort();
}

/// A sink whose every `emit` blocks for `delay` before recording — models slow/blocked
/// audit storage. Used to prove the at-capacity audit offload (P2) never serializes the
/// accept loop.
struct SlowEmit {
    delay: Duration,
    recs: Mutex<Vec<AuditRecord>>,
}
impl SlowEmit {
    fn new(delay: Duration) -> Arc<Self> {
        Arc::new(SlowEmit {
            delay,
            recs: Mutex::new(Vec::new()),
        })
    }
    fn records(&self) -> Vec<AuditRecord> {
        self.recs.lock().unwrap().clone()
    }
}
impl AuditEmit for SlowEmit {
    fn emit(&self, rec: &AuditRecord) -> impl Future<Output = Result<(), AuditError>> + Send {
        let delay = self.delay;
        let rec = rec.clone();
        // The returned future borrows `&self` (RPITIT) but takes the lock ONLY
        // synchronously, AFTER the await — never held across the await point.
        async move {
            tokio::time::sleep(delay).await;
            self.recs.lock().unwrap().push(rec);
            Ok(())
        }
    }
}

/// P2 (DoS): an at-capacity denial must NOT block the accept loop on audit I/O. With the
/// only permit held by a long-lived first connection, every later connection is an
/// at-capacity denial whose audit is handed to the BOUNDED BACKGROUND drain. Even though
/// the audit sink is slow (250ms/record), the accept loop must consume the WHOLE script
/// promptly (dropping each raw socket immediately) instead of serializing on the append.
#[tokio::test]
async fn at_capacity_audit_does_not_block_accept_loop() {
    // Hold the single permit with a first connection (read_timeout long so it lingers),
    // then a burst of at-capacity connections whose audit goes to the slow background sink.
    let (_c1, server1) = tokio::io::duplex(1024); // keep peer end open so handler holds the permit
    let mut script = vec![Scripted::Ok(
        server1,
        "maknae://d/plane/cli".to_string(),
        9000,
    )];
    for i in 0..8 {
        script.push(ok_conn("maknae://d/plane/cli", 9001 + i));
    }
    let n_items = script.len();

    let emit = SlowEmit::new(Duration::from_millis(250));
    let acceptor = FakeAccept::new(script);
    let popped = acceptor.pop_counter();
    let session_ids = Arc::new(SessionIds::with_nonce(1));
    let cfg = cfg_with(1, 2000); // capacity 1; first handler holds it for 2s

    let emit_for_loop = emit.clone();
    let loop_task = tokio::spawn(async move {
        maknae_kernel::accept_loop(
            acceptor,
            emit_for_loop,
            session_ids,
            cfg,
            wctx(),
            std::future::pending::<()>(),
            pending_supervisor(),
            std::sync::Arc::new(common::AlwaysPermit),
            std::sync::Arc::new(fixture_principal()),
        )
        .await;
    });

    // The loop must consume the ENTIRE script quickly — well before even ONE slow (250ms)
    // at-capacity audit could complete if it were awaited inline. If the loop serialized
    // on audit I/O, consuming 8 at-capacity denials would take ~2s; here it is ~instant.
    let deadline = Instant::now() + Duration::from_millis(150);
    loop {
        if popped.load(std::sync::atomic::Ordering::Relaxed) == n_items {
            break;
        }
        assert!(
            Instant::now() < deadline,
            "accept loop did not consume the script promptly ({} of {n_items}) — it appears \
             serialized on the slow at-capacity audit (DoS regression)",
            popped.load(std::sync::atomic::Ordering::Relaxed)
        );
        tokio::time::sleep(Duration::from_millis(5)).await;
    }

    loop_task.abort();
    let _ = emit.records(); // touch the sink so the type is exercised
}

/// P1 (codex round-5): when the credential supervisor's `JoinHandle` resolves (token
/// renewal / leaf rotation exhausted its retry window, or the task panicked/was
/// cancelled), the accept loop must STOP — not keep running as a zombie against a
/// listener whose cert slot the supervisor already cleared. No connection is queued
/// (the fake acceptor's `accept_raw` would otherwise block forever), so the ONLY way
/// this test can complete is via the new supervisor `select!` branch — proving it is
/// actually wired in, carries the real exit reason, and the loop does not continue
/// past it (nothing is ever served).
#[tokio::test]
async fn supervisor_exit_stops_the_loop_and_reports_failure() {
    let emit = RecEmit::new();
    let acceptor = FakeAccept::new(vec![]);
    let session_ids = Arc::new(SessionIds::with_nonce(1));
    let cfg = cfg_with(64, 150);
    // A supervisor future that resolves immediately with the SAME error the real
    // credential supervisor surfaces on retry-window exhaustion (ADR-0018).
    let supervisor = tokio::spawn(async { VaultError::RenewalExpired });

    let outcome = tokio::time::timeout(
        Duration::from_secs(5),
        maknae_kernel::accept_loop(
            acceptor,
            emit.clone(),
            session_ids,
            cfg,
            wctx(),
            std::future::pending::<()>(), // shutdown never fires in this test
            supervisor,
            std::sync::Arc::new(common::AlwaysPermit),
            std::sync::Arc::new(fixture_principal()),
        ),
    )
    .await
    .expect("accept_loop must return once the supervisor exits, not hang forever");

    match outcome {
        ServeOutcome::SupervisorExited(e) => {
            assert!(
                matches!(e, VaultError::RenewalExpired),
                "must carry the supervisor's ACTUAL exit reason, got {e:?}"
            );
        }
        other => panic!("expected ServeOutcome::SupervisorExited, got {other:?}"),
    }
    assert!(
        emit.records().is_empty(),
        "no connection should ever have been processed — the accept loop must not \
         continue past the supervisor exit"
    );
}

/// Companion to the supervisor-exit test: the OTHER legitimate way the loop stops
/// (SIGTERM/SIGINT, modeled here by firing the shutdown future) must yield the
/// opposite, distinct outcome — `GracefulShutdown` — so `run_inner`'s `ExitCode`
/// mapping (`handler::serve_outcome_to_exit_code`) can tell a clean stop from a
/// credential-supervisor failure.
#[tokio::test]
async fn shutdown_signal_yields_graceful_outcome() {
    let emit = RecEmit::new();
    let acceptor = FakeAccept::new(vec![]);
    let session_ids = Arc::new(SessionIds::with_nonce(1));
    let cfg = cfg_with(64, 150);
    let (tx, rx) = tokio::sync::oneshot::channel::<()>();
    let shutdown = async move {
        let _ = rx.await;
    };

    let loop_task = tokio::spawn(maknae_kernel::accept_loop(
        acceptor,
        emit.clone(),
        session_ids,
        cfg,
        wctx(),
        shutdown,
        pending_supervisor(),
        std::sync::Arc::new(common::AlwaysPermit),
        std::sync::Arc::new(fixture_principal()),
    ));
    tx.send(()).expect("shutdown receiver must still be alive");
    let outcome = tokio::time::timeout(Duration::from_secs(5), loop_task)
        .await
        .expect("accept_loop must return promptly once shutdown fires")
        .expect("accept_loop task must not panic");

    assert!(
        matches!(outcome, ServeOutcome::GracefulShutdown),
        "expected ServeOutcome::GracefulShutdown, got {outcome:?}"
    );
}
