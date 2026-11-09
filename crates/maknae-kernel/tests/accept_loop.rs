//! Accept-loop integration suite (spec §10). Exercises the run-loop's accept-level
//! behaviour — audit-and-continue on a surfaced handshake rejection (NEVER kill the
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

use std::collections::VecDeque;
use std::future::Future;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use maknae_audit_append::{AuditEmit, AuditError, AuditRecord, SessionIds};
use maknae_kernel::session_facts::{AccountFact, AccountState, NotCheckedWhy};
use maknae_kernel::FactsGate;
use maknae_kernel::{Admission, ChannelClass, Conn, PlaneAccept, ServeOutcome, WhereCtx};
use maknae_vault::{
    AcceptRejection, ChannelPeer, PeerAuth, PeerCreds, RejectReason, SenderVerdict, VaultError,
};
use tokio::io::DuplexStream;
use tokio::time::Instant;

/// Recording sink (never fails) shared with the accept loop.
struct RecEmit {
    recs: Mutex<Vec<AuditRecord>>,
    /// Appends of this event are offered (recorded) and then refused.
    refuse: Option<&'static str>,
}
impl RecEmit {
    fn new() -> Arc<Self> {
        Self::refusing(None)
    }
    fn refusing(refuse: Option<&'static str>) -> Arc<Self> {
        Arc::new(RecEmit {
            recs: Mutex::new(Vec::new()),
            refuse,
        })
    }
    fn records(&self) -> Vec<AuditRecord> {
        self.recs.lock().unwrap().clone()
    }
}
impl AuditEmit for RecEmit {
    fn emit(&self, rec: &AuditRecord) -> impl Future<Output = Result<(), AuditError>> + Send {
        self.recs.lock().unwrap().push(rec.clone());
        let refused = self.refuse == Some(rec.event.as_str());
        async move {
            if refused {
                Err(AuditError::WritePrimary("refused".into()))
            } else {
                Ok(())
            }
        }
    }
}

/// A scripted accept source. Each `accept_raw()` pops the next outcome; when the script is
/// exhausted it parks forever (so the loop blocks in `accept_raw` until shutdown fires).
/// A `Reject`/`Stall` is realised in `finish_handshake` (the bounded half the run-loop now
/// runs UNDER its semaphore) — proving the loop's new prompt-accept / deferred-handshake
/// split behaves: rejections still audit, and a stalled handshake does not block the loop.
enum Scripted {
    Ok(DuplexStream, ChannelPeer, u32),
    /// An OK connection whose sender verdict is given.
    OkWith(DuplexStream, ChannelPeer, u32, SenderVerdict),
    Reject(AcceptRejection),
    /// `accept_raw` succeeds, but `finish_handshake` sleeps this long before yielding an OK
    /// connection — simulating a peer that stalls the TLS handshake.
    Stall(Duration, DuplexStream, ChannelPeer, u32),
    RawFail(maknae_vault::RawAcceptError),
    /// An OK connection that delegated these descriptors.
    Delegating(DuplexStream, ChannelPeer, u32, maknae_io::DelegatedFds),
}

/// The raw handle `accept_raw` hands to `finish_handshake` (opaque, like `RawPlaneConn`).
enum FakeRaw {
    Conn(DuplexStream, ChannelPeer, u32, SenderVerdict),
    Reject(AcceptRejection),
    Stall(Duration, DuplexStream, ChannelPeer, u32),
    Delegating(DuplexStream, ChannelPeer, u32, maknae_io::DelegatedFds),
}

fn conn(
    stream: DuplexStream,
    peer: ChannelPeer,
    uid: u32,
    sender: SenderVerdict,
) -> Conn<DuplexStream> {
    Conn {
        delegated: maknae_io::DelegatedFds::new(0),
        stream,
        peer,
        peer_uid: uid,
        sender,
    }
}

struct FakeAccept {
    queue: Mutex<VecDeque<Scripted>>,
    /// Count of scripted items actually consumed by `accept_raw` — a clone of this Arc is
    /// taken BEFORE the acceptor is moved into `accept_loop`, so a test can observe how
    /// far the loop has progressed (P2: proving the loop keeps accepting even while the
    /// at-capacity audit sink is slow).
    popped: Arc<std::sync::atomic::AtomicUsize>,
    peer_auth: PeerAuth,
}
impl FakeAccept {
    fn new(items: Vec<Scripted>) -> Self {
        Self::authenticating(items, PeerAuth::Certless)
    }
    fn authenticating(items: Vec<Scripted>, peer_auth: PeerAuth) -> Self {
        FakeAccept {
            queue: Mutex::new(items.into_iter().collect()),
            popped: Arc::new(std::sync::atomic::AtomicUsize::new(0)),
            peer_auth,
        }
    }
    fn pop_counter(&self) -> Arc<std::sync::atomic::AtomicUsize> {
        Arc::clone(&self.popped)
    }
}
impl PlaneAccept for FakeAccept {
    type Raw = FakeRaw;
    type Stream = DuplexStream;

    fn peer_auth(&self) -> &PeerAuth {
        &self.peer_auth
    }

    // Pop INSIDE the future so a `select!` that loses to shutdown (dropping this future
    // unpolled) does not silently consume a scripted item. The std MutexGuard is released
    // before the only await, so the future stays `Send` (satisfying the trait bound).
    async fn accept_raw(&self) -> Result<(FakeRaw, PeerCreds), maknae_vault::RawAcceptError> {
        let item = self.queue.lock().unwrap().pop_front();
        if item.is_some() {
            self.popped
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        }
        match item {
            Some(Scripted::Ok(stream, peer, uid)) => Ok((
                FakeRaw::Conn(stream, peer, uid, SenderVerdict::default()),
                creds(uid),
            )),
            Some(Scripted::OkWith(stream, peer, uid, sender)) => {
                Ok((FakeRaw::Conn(stream, peer, uid, sender), creds(uid)))
            }
            Some(Scripted::Reject(rej)) => {
                let c = rej.peer_creds.unwrap_or_else(|| creds(0));
                Ok((FakeRaw::Reject(rej), c))
            }
            Some(Scripted::Stall(d, stream, peer, uid)) => {
                Ok((FakeRaw::Stall(d, stream, peer, uid), creds(uid)))
            }
            Some(Scripted::RawFail(e)) => Err(e),
            Some(Scripted::Delegating(stream, peer, uid, fds)) => {
                Ok((FakeRaw::Delegating(stream, peer, uid, fds), creds(uid)))
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
            FakeRaw::Conn(stream, peer, uid, sender) => Ok(conn(stream, peer, uid, sender)),
            FakeRaw::Reject(rej) => Err(rej),
            FakeRaw::Stall(d, stream, peer, uid) => {
                tokio::time::sleep(d).await;
                Ok(conn(stream, peer, uid, SenderVerdict::default()))
            }
            FakeRaw::Delegating(stream, peer, uid, delegated) => Ok(Conn {
                delegated,
                ..conn(stream, peer, uid, SenderVerdict::default())
            }),
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
        socket: TEST_SOCKET.to_string(),
        au3_1: serde_json::json!({}),
    }
}

const TEST_SOCKET: &str = "/run/maknae/test.sock";

fn client_class() -> ChannelClass {
    class_on(TEST_SOCKET)
}

fn class_on(socket: &str) -> ChannelClass {
    ChannelClass {
        peer_auth: PeerAuth::Certless,
        admission: Admission::MaknaeGroupMember,
        lane: maknae_security::Lane::Local,
        socket: socket.into(),
    }
}

fn certified(san: &str) -> ChannelPeer {
    ChannelPeer::Certified(san.to_string())
}

fn capacity(cfg: &maknae_config::TransportConfig) -> Arc<tokio::sync::Semaphore> {
    Arc::new(tokio::sync::Semaphore::new(cfg.max_connections as usize))
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
    Scripted::Ok(server, certified(uri), uid)
}

/// Run the loop over a script until it drains, then fire shutdown and join. Returns the
/// recorded audit records.
async fn drive(script: Vec<Scripted>, cfg: maknae_config::TransportConfig) -> Vec<AuditRecord> {
    drive_with(script, cfg, common::serving()).await
}

async fn drive_with(
    script: Vec<Scripted>,
    cfg: maknae_config::TransportConfig,
    drain: tokio::sync::watch::Receiver<maknae_kernel::Drain>,
) -> Vec<AuditRecord> {
    drive_class(client_class(), script, cfg, drain).await
}

async fn drive_class(
    class: ChannelClass,
    script: Vec<Scripted>,
    cfg: maknae_config::TransportConfig,
    drain: tokio::sync::watch::Receiver<maknae_kernel::Drain>,
) -> Vec<AuditRecord> {
    drive_gated(class, script, cfg, drain, host_gate(), Duration::MAX).await
}

/// The host's own sources, with no account source declared: the membership the
/// accept loop always asked.
fn host_gate() -> Arc<FactsGate> {
    FactsGate::for_test(
        Arc::new(maknae_kernel::session_facts::HostSessionFacts {
            account_source: maknae_config::AccountSource::None,
        }),
        Duration::from_millis(maknae_config::GROUP_LOOKUP_TIMEOUT_MS),
    )
}

async fn drive_facts(script: Vec<Scripted>, gate: Arc<FactsGate>) -> Vec<AuditRecord> {
    drive_gated(
        client_class(),
        script,
        cfg_with(8, 150),
        common::serving(),
        gate,
        Duration::MAX,
    )
    .await
}

async fn drive_gated(
    class: ChannelClass,
    script: Vec<Scripted>,
    cfg: maknae_config::TransportConfig,
    drain: tokio::sync::watch::Receiver<maknae_kernel::Drain>,
    gate: Arc<FactsGate>,
    lifetime: Duration,
) -> Vec<AuditRecord> {
    drive_into(RecEmit::new(), class, script, cfg, drain, gate, lifetime).await
}

async fn drive_into(
    emit: Arc<RecEmit>,
    class: ChannelClass,
    script: Vec<Scripted>,
    cfg: maknae_config::TransportConfig,
    drain: tokio::sync::watch::Receiver<maknae_kernel::Drain>,
    gate: Arc<FactsGate>,
    lifetime: Duration,
) -> Vec<AuditRecord> {
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
            class,
            emit_for_loop,
            session_ids,
            cfg.clone(),
            capacity(&cfg),
            wctx(),
            shutdown,
            pending_supervisor(),
            std::sync::Arc::new(common::AlwaysPermit),
            std::sync::Arc::new(maknae_kernel::LiveConfig::new(Default::default(), None)),
            std::sync::Arc::new("test-backend".to_string()),
            std::sync::Arc::new("US".to_string()),
            std::sync::Arc::new("ml-dsa-87".to_string()),
            std::sync::Arc::new(None),
            maknae_kernel::unavailable_egress(),
            common::no_baseline(),
            drain,
            gate,
            lifetime,
            common::conversations(),
            maknae_kernel::AgentAdmission::none(),
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
        ok_conn("spiffe://d/plane/cli", 1002),
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
async fn a_peer_is_audited_with_its_san_or_none() {
    let class = class_on("/run/maknae/client-class.sock");
    let socket = class.socket.display().to_string();
    let certless = {
        let (client, server) = tokio::io::duplex(1024);
        drop(client);
        Scripted::Ok(server, ChannelPeer::Certless, 2001)
    };
    let recs = drive_class(
        class,
        vec![certless, ok_conn("spiffe://d/plane/cli", 2002)],
        cfg_with(64, 150),
        common::serving(),
    )
    .await;
    let connection = |uid: u32| {
        recs.iter()
            .find(|r| r.source.uid == uid && r.event == "connection")
            .unwrap_or_else(|| panic!("uid {uid}'s connection record: {recs:?}"))
    };

    let none = connection(2001);
    assert_eq!(none.source.plane_uri_san, None);
    assert_eq!(none.subject.plane_uri_san, None);
    assert_eq!(none.where_.socket, socket);

    let some = connection(2002);
    assert_eq!(
        some.source.plane_uri_san.as_deref(),
        Some("spiffe://d/plane/cli")
    );
    assert_eq!(
        some.subject.plane_uri_san.as_deref(),
        Some("spiffe://d/plane/cli")
    );
    assert_eq!(some.where_.socket, socket);
}

#[tokio::test]
async fn at_capacity_fast_closes() {
    // max_connections = 1. The first connection's handler holds the only permit (it blocks
    // in read for read_timeout_ms because we keep its peer end open); the second is accepted
    // while the permit is held → at-capacity fast-close + audit.
    let (client1, server1) = tokio::io::duplex(1024);
    let script = vec![
        Scripted::Ok(server1, certified("spiffe://d/plane/cli"), 2001),
        ok_conn("spiffe://d/plane/cli", 2002),
    ];
    // read_timeout_ms = 1000 so the first handler keeps the permit long enough.
    let class = class_on("/run/maknae/at-capacity.sock");
    let recs = drive_class(class, script, cfg_with(1, 1000), common::serving()).await;
    drop(client1); // keep client1's peer end open across the loop's processing window

    let at_cap = recs
        .iter()
        .find(|r| r.event == "connection" && r.outcome.reason.contains("at capacity"))
        .expect("the second connection must be audited as at-capacity");
    assert_eq!(at_cap.outcome.result, "deny");
    assert_eq!(at_cap.source.uid, 2002);
    assert_eq!(at_cap.outcome.posture, "unauthorized");
    assert_eq!(at_cap.where_.socket, "/run/maknae/at-capacity.sock");
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
        ok_conn("spiffe://d/plane/cli", 3002),
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
            certified("spiffe://d/plane/cli"),
            7001,
        ),
        ok_conn("spiffe://d/plane/cli", 7002),
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
            client_class(),
            emit_for_loop,
            session_ids,
            cfg.clone(),
            capacity(&cfg),
            wctx(),
            std::future::pending::<()>(),
            pending_supervisor(),
            std::sync::Arc::new(common::AlwaysPermit),
            std::sync::Arc::new(maknae_kernel::LiveConfig::new(Default::default(), None)),
            std::sync::Arc::new("test-backend".to_string()),
            std::sync::Arc::new("US".to_string()),
            std::sync::Arc::new("ml-dsa-87".to_string()),
            std::sync::Arc::new(None),
            maknae_kernel::unavailable_egress(),
            common::no_baseline(),
            common::serving(),
            host_gate(),
            Duration::MAX,
            common::conversations(),
            maknae_kernel::AgentAdmission::none(),
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
        certified("spiffe://d/plane/cli"),
        9000,
    )];
    for i in 0..8 {
        script.push(ok_conn("spiffe://d/plane/cli", 9001 + i));
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
            client_class(),
            emit_for_loop,
            session_ids,
            cfg.clone(),
            capacity(&cfg),
            wctx(),
            std::future::pending::<()>(),
            pending_supervisor(),
            std::sync::Arc::new(common::AlwaysPermit),
            std::sync::Arc::new(maknae_kernel::LiveConfig::new(Default::default(), None)),
            std::sync::Arc::new("test-backend".to_string()),
            std::sync::Arc::new("US".to_string()),
            std::sync::Arc::new("ml-dsa-87".to_string()),
            std::sync::Arc::new(None),
            maknae_kernel::unavailable_egress(),
            common::no_baseline(),
            common::serving(),
            host_gate(),
            Duration::MAX,
            common::conversations(),
            maknae_kernel::AgentAdmission::none(),
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

/// #265 A4: a peer whose credentials cannot be captured is a recorded connection
/// deny with no peer identity; an `accept()` syscall error is not (A5, #354).
#[tokio::test]
async fn a_peer_credential_failure_is_a_recorded_deny_and_an_accept_error_is_not() {
    let recs = drive(
        vec![
            Scripted::RawFail(maknae_vault::RawAcceptError::PeerCreds("EPERM".into())),
            Scripted::RawFail(maknae_vault::RawAcceptError::Accept(std::io::Error::other(
                "EMFILE",
            ))),
        ],
        cfg_with(64, 150),
    )
    .await;
    let recs: Vec<_> = recs.iter().filter(|r| r.event != "shutdown").collect();
    assert_eq!(recs.len(), 1, "{recs:?}");
    let r = recs[0];
    assert_eq!(
        (
            r.event.as_str(),
            r.action.as_str(),
            r.outcome.result.as_str()
        ),
        ("connection", "connect", "deny")
    );
    assert!(r.outcome.reason.contains("EPERM"), "{:?}", r.outcome);
    assert_eq!(r.source.uid, maknae_audit_append::NO_PEER_UID);
    assert_eq!((r.source.gid, r.source.pid), (None, None));
    assert_eq!(r.subject.user, None);
}

/// #265 A6: every at-capacity refusal is on the trail — individually, or counted
/// in an aggregate record when the offload queue was full.
#[tokio::test]
async fn every_at_capacity_refusal_is_recorded_or_counted() {
    const REFUSED: usize = 500;
    let (_c1, server1) = tokio::io::duplex(1024);
    let mut script = vec![Scripted::Ok(
        server1,
        certified("spiffe://d/plane/cli"),
        9000,
    )];
    for i in 0..REFUSED {
        script.push(ok_conn("spiffe://d/plane/cli", 10_000 + i as u32));
    }
    let emit = SlowEmit::new(Duration::from_millis(10));
    let acceptor = FakeAccept::new(script);
    let popped = acceptor.pop_counter();
    let (tx, rx) = tokio::sync::oneshot::channel::<()>();
    let emit_for_loop = emit.clone();
    let loop_task = tokio::spawn(async move {
        maknae_kernel::accept_loop(
            acceptor,
            client_class(),
            emit_for_loop,
            Arc::new(SessionIds::with_nonce(1)),
            cfg_with(1, 150),
            capacity(&cfg_with(1, 150)),
            wctx(),
            async move {
                let _ = rx.await;
            },
            pending_supervisor(),
            std::sync::Arc::new(common::AlwaysPermit),
            std::sync::Arc::new(maknae_kernel::LiveConfig::new(Default::default(), None)),
            std::sync::Arc::new("test-backend".to_string()),
            std::sync::Arc::new("US".to_string()),
            std::sync::Arc::new("ml-dsa-87".to_string()),
            std::sync::Arc::new(None),
            maknae_kernel::unavailable_egress(),
            common::no_baseline(),
            common::serving(),
            host_gate(),
            Duration::MAX,
            common::conversations(),
            maknae_kernel::AgentAdmission::none(),
        )
        .await;
    });
    while popped.load(std::sync::atomic::Ordering::Relaxed) < REFUSED + 1 {
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
    let _ = tx.send(());
    loop_task.await.unwrap();

    let recs = emit.records();
    let individual = recs
        .iter()
        .filter(|r| r.outcome.reason == "at capacity")
        .count();
    let counted: usize = recs
        .iter()
        .filter_map(|r| r.outcome.reason.strip_prefix("audit queue full: "))
        .map(|rest| rest.split(' ').next().unwrap().parse::<usize>().unwrap())
        .sum();
    assert!(
        counted > 0,
        "the queue never filled; the test proves nothing"
    );
    assert_eq!(individual + counted, REFUSED);
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
            client_class(),
            emit.clone(),
            session_ids,
            cfg.clone(),
            capacity(&cfg),
            wctx(),
            std::future::pending::<()>(), // shutdown never fires in this test
            supervisor,
            std::sync::Arc::new(common::AlwaysPermit),
            std::sync::Arc::new(maknae_kernel::LiveConfig::new(Default::default(), None)),
            std::sync::Arc::new("test-backend".to_string()),
            std::sync::Arc::new("US".to_string()),
            std::sync::Arc::new("ml-dsa-87".to_string()),
            std::sync::Arc::new(None),
            maknae_kernel::unavailable_egress(),
            common::no_baseline(),
            common::serving(),
            host_gate(),
            Duration::MAX,
            common::conversations(),
            maknae_kernel::AgentAdmission::none(),
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
    let recs = emit.records();
    assert_eq!(
        recs.len(),
        1,
        "only the stop record — no connection was processed past the supervisor exit: {recs:?}"
    );
    assert_eq!(recs[0].event, "shutdown");
    assert_eq!(recs[0].outcome.result, "deny");
    assert!(
        recs[0]
            .outcome
            .reason
            .contains("credential supervisor exited"),
        "{:?}",
        recs[0].outcome
    );
}

#[tokio::test]
async fn a_listener_that_authenticates_otherwise_than_its_class_serves_nothing() {
    let emit = RecEmit::new();
    let mut acceptor = FakeAccept::new(vec![ok_conn("spiffe://d/plane/cli", 4001)]);
    acceptor.peer_auth = PeerAuth::PlaneLeaf {
        accept: maknae_vault::SanRule::Exact("spiffe://d/plane/cli".to_string()),
    };
    let popped = acceptor.pop_counter();
    let shutdown = tokio::time::sleep(Duration::from_millis(300));

    let outcome = tokio::time::timeout(
        Duration::from_secs(5),
        maknae_kernel::accept_loop(
            acceptor,
            client_class(),
            emit.clone(),
            Arc::new(SessionIds::with_nonce(1)),
            cfg_with(64, 150),
            capacity(&cfg_with(64, 150)),
            wctx(),
            shutdown,
            pending_supervisor(),
            std::sync::Arc::new(common::AlwaysPermit),
            std::sync::Arc::new(maknae_kernel::LiveConfig::new(Default::default(), None)),
            std::sync::Arc::new("test-backend".to_string()),
            std::sync::Arc::new("US".to_string()),
            std::sync::Arc::new("ml-dsa-87".to_string()),
            std::sync::Arc::new(None),
            maknae_kernel::unavailable_egress(),
            common::no_baseline(),
            common::serving(),
            host_gate(),
            Duration::MAX,
            common::conversations(),
            maknae_kernel::AgentAdmission::none(),
        ),
    )
    .await
    .expect("accept_loop must return");

    assert!(
        matches!(outcome, ServeOutcome::ChannelMismatch),
        "expected ServeOutcome::ChannelMismatch, got {outcome:?}"
    );
    assert_eq!(popped.load(std::sync::atomic::Ordering::Relaxed), 0);
    let recs = emit.records();
    assert!(
        recs.iter().all(|r| r.event != "connection"),
        "no connection was served: {recs:?}"
    );
    assert!(
        recs.iter().any(|r| r.event == "shutdown"),
        "the mismatch exit writes the shutdown record: {recs:?}"
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
        client_class(),
        emit.clone(),
        session_ids,
        cfg.clone(),
        capacity(&cfg),
        wctx(),
        shutdown,
        pending_supervisor(),
        std::sync::Arc::new(common::AlwaysPermit),
        std::sync::Arc::new(maknae_kernel::LiveConfig::new(Default::default(), None)),
        std::sync::Arc::new("test-backend".to_string()),
        std::sync::Arc::new("US".to_string()),
        std::sync::Arc::new("ml-dsa-87".to_string()),
        std::sync::Arc::new(None),
        maknae_kernel::unavailable_egress(),
        common::no_baseline(),
        common::serving(),
        host_gate(),
        Duration::MAX,
        common::conversations(),
        maknae_kernel::AgentAdmission::none(),
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
    let recs = emit.records();
    assert_eq!(recs.len(), 1, "{recs:?}");
    assert_eq!(recs[0].event, "shutdown");
    assert_eq!(recs[0].outcome.result, "permit");
    assert!(
        recs[0].outcome.reason.contains("signal"),
        "{:?}",
        recs[0].outcome
    );
}

/// #275: the record carries the OS username the accept loop resolved, and it
/// survives a group lookup that fails.
///
/// **Scripts the RUNNING EUID, deliberately.** Every other uid in this file is
/// synthetic (1001, 2001, 3001, …) and resolves to no user on macOS and to
/// `runner` on ubuntu CI — so an assertion over those is either host-divergent
/// or vacuously `None`, which is exactly the class of test this slice exists to
/// kill. The expectation comes from an INDEPENDENT `User::from_uid` of the same
/// uid, so this is not the harness asserting its own input back at itself.
///
/// **No `maknae`-group precondition.** An earlier form skipped when the group
/// was absent — which is PRECISELY the identity-loss scenario this test exists
/// to pin, so restoring that defect would have left it green.
///
/// Honest about what discriminates: on a host that HAS the group, both the
/// correct resolution order and the old group-first one produce the name, so
/// this assertion cannot separate them here (measured — reinstating the old
/// order leaves it green on the dev Mac). It discriminates on CI's
/// ubuntu-latest, which has no `maknae` group. The unit-level companion is
/// `groupres::tests::the_username_is_resolved_whatever_the_membership_answer_is`.
#[tokio::test]
async fn the_record_carries_the_username_even_when_the_group_lookup_fails() {
    let me = nix::unistd::geteuid().as_raw();
    let Ok(Some(u)) = nix::unistd::User::from_uid(nix::unistd::Uid::from_raw(me)) else {
        eprintln!("SKIP: euid {me} does not resolve to a user on this host");
        return;
    };
    let recs = drive(vec![ok_conn("spiffe://d/plane/cli", me)], cfg_with(8, 500)).await;
    let conn = recs
        .iter()
        .find(|r| r.event == "connection")
        .expect("a connection record");
    assert_eq!(
        conn.subject.user.as_deref(),
        Some(u.name.as_str()),
        "the record must carry the resolved name whether or not the group resolved"
    );
}

/// A uid that resolves to NO user carries no username — there is nothing to
/// carry, and `uid_in_maknae_group` fails closed on it.
///
/// Named for what it actually proves. An earlier form was called
/// `a_refused_connection_carries_no_username_because_nss_was_not_spawned`,
/// which was false: uid 999999 takes the ordinary blocking lookup path, so the
/// test passed while its name described a breaker arm it never reached. The
/// no-NSS-on-the-breaker-arm property is held by the accept loop's own
/// structure (`run.rs`: the refuse arms return before `spawn_blocking`), not by
/// this test.
#[tokio::test]
async fn an_unresolvable_uid_carries_no_username_and_no_role() {
    let recs = drive(
        vec![ok_conn("spiffe://d/plane/cli", 999_999)],
        cfg_with(8, 500),
    )
    .await;
    let conn = recs
        .iter()
        .find(|r| r.event == "connection")
        .expect("a connection record");
    assert_eq!(conn.subject.user, None, "no user resolves for this uid");
    assert_eq!(conn.subject.role, None, "a connection is not a decision");
}

const DRAINING: &str = "draining to apply an accepted baseline";

#[tokio::test]
async fn a_connection_during_the_drain_is_closed_unserved() {
    let (_tx, begun) = tokio::sync::watch::channel(maknae_kernel::Drain::Begun);
    let recs = drive_with(
        vec![ok_conn("spiffe://d/plane/cli", 1002)],
        cfg_with(64, 150),
        begun,
    )
    .await;
    let refused: Vec<&AuditRecord> = recs.iter().filter(|r| r.source.uid == 1002).collect();
    assert_eq!(refused.len(), 1, "no handler ran: {recs:?}");
    assert_eq!(
        (
            refused[0].event.as_str(),
            refused[0].action.as_str(),
            refused[0].outcome.result.as_str(),
            refused[0].outcome.reason.as_str(),
            refused[0].outcome.posture.as_str(),
        ),
        ("connection", "connect", "deny", DRAINING, "unavailable")
    );
    let stop = recs.iter().rfind(|r| r.action == "serve").unwrap();
    assert_eq!(
        stop.outcome.reason,
        "shutdown: an accepted baseline was not applied"
    );

    let served = drive(
        vec![ok_conn("spiffe://d/plane/cli", 1002)],
        cfg_with(64, 150),
    )
    .await;
    assert!(served.iter().any(|r| r.source.uid == 1002));
    assert!(!served.iter().any(|r| r.outcome.reason == DRAINING));
}

const SESSION_UID: u32 = 11_500;

/// A connection that has written one ping and closed its write side; the
/// client end stays readable.
async fn pinging() -> (Scripted, DuplexStream) {
    let (mut client, server) = tokio::io::duplex(4096);
    let ping = maknae_proto::encode_request(&maknae_proto::Request {
        task: None,
        protocol_version: maknae_proto::PROTOCOL_VERSION,
        verb: maknae_proto::Verb::Ping,
    })
    .unwrap();
    common::write_frame(&mut client, &ping).await.unwrap();
    tokio::io::AsyncWriteExt::shutdown(&mut client)
        .await
        .unwrap();
    (
        Scripted::Ok(server, certified("spiffe://d/plane/cli"), SESSION_UID),
        client,
    )
}

/// What the client read back, as the CLI reads a control reply; `None` when the
/// daemon closed without a frame.
async fn answer(mut client: DuplexStream) -> Option<maknae_proto::RespResult> {
    let mut bytes = Vec::new();
    tokio::time::timeout(
        Duration::from_secs(2),
        tokio::io::AsyncReadExt::read_to_end(&mut client, &mut bytes),
    )
    .await
    .expect("the daemon closed the connection")
    .unwrap();
    if bytes.is_empty() {
        return None;
    }
    let body = maknae_proto::read_frame_of_class(
        &mut bytes.as_slice(),
        maknae_proto::FrameClass::Control,
        &maknae_proto::FrameCaps::responses(1 << 20),
    )
    .await
    .expect("a control-class reply");
    Some(maknae_proto::decode_response(&body).unwrap().result)
}

fn assert_unauthorized(got: Option<maknae_proto::RespResult>) {
    match got {
        Some(maknae_proto::RespResult::Err(e)) => {
            assert_eq!(
                (e.code, e.message.as_str()),
                (maknae_proto::ProtoErrCode::Unauthorized, "not authorized")
            );
        }
        other => panic!("expected the generic Unauthorized frame, got {other:?}"),
    }
}

fn of_session(recs: &[AuditRecord]) -> Vec<&AuditRecord> {
    recs.iter()
        .filter(|r| r.source.uid == SESSION_UID)
        .collect()
}

/// `(event, action, result, reason)` of each record, in order.
fn trail(recs: &[&AuditRecord]) -> Vec<(String, String, String, String)> {
    recs.iter()
        .map(|r| {
            (
                r.event.clone(),
                r.action.clone(),
                r.outcome.result.clone(),
                r.outcome.reason.clone(),
            )
        })
        .collect()
}

fn row(event: &str, action: &str, result: &str, reason: &str) -> (String, String, String, String) {
    (event.into(), action.into(), result.into(), reason.into())
}

fn admitted(account: &str) -> (String, String, String, String) {
    row(
        "connection",
        "connect",
        "permit",
        &format!("admitted (account: {account})"),
    )
}

fn terminated(result: &str, reason: &str) -> (String, String, String, String) {
    row("session", "terminate", result, reason)
}

/// A session refused at its request: admitted, the request refused for `reason`
/// and answered with the generic frame, the session ended for the same reason.
async fn refused_at_the_request(request: maknae_kernel::Facts, reason: &str) -> Vec<AuditRecord> {
    let (conn, client) = pinging().await;
    let recs = drive_facts(
        vec![conn],
        common::ScriptedFacts::gate(vec![common::active_member(), request]),
    )
    .await;
    let session = of_session(&recs);
    assert_eq!(
        trail(&session),
        vec![
            admitted("active"),
            row("request", "liveness.ping", "deny", reason),
            terminated("deny", reason),
        ],
        "{session:?}"
    );
    assert_eq!(
        session.iter().map(|r| r.seq).collect::<Vec<_>>(),
        vec![1, 2, 3]
    );
    assert_unauthorized(answer(client).await);
    recs
}

#[tokio::test]
async fn a_non_member_is_refused_at_connect() {
    let (conn, client) = pinging().await;
    let recs = drive_facts(
        vec![conn],
        common::ScriptedFacts::gate(vec![common::non_member()]),
    )
    .await;
    let session = of_session(&recs);
    assert_eq!(
        trail(&session),
        vec![row("connection", "connect", "deny", "not-member")]
    );
    let deny = session[0];
    assert_eq!(
        (deny.seq, deny.outcome.posture.as_str()),
        (1, "unauthorized")
    );
    assert_eq!(deny.subject.user.as_deref(), Some("scripted"));
    assert_eq!(
        deny.source.plane_uri_san.as_deref(),
        Some("spiffe://d/plane/cli")
    );
    assert_eq!(
        answer(client).await,
        None,
        "a connect-time deny writes no frame"
    );
}

#[tokio::test]
async fn a_deleted_account_is_refused_as_not_a_member() {
    let mut deleted = common::active_member();
    deleted.membership = Err(maknae_kernel::AuthzError::NoUser);
    let (conn, client) = pinging().await;
    let recs = drive_facts(vec![conn], common::ScriptedFacts::gate(vec![deleted])).await;
    let session = of_session(&recs);
    assert_eq!(
        trail(&session),
        vec![row("connection", "connect", "deny", "not-member")]
    );
    assert_eq!(session[0].outcome.posture, "unauthorized");
    assert_eq!(answer(client).await, None);
}

#[tokio::test]
async fn a_member_de_enrolled_before_the_request_is_refused_at_the_request() {
    refused_at_the_request(common::non_member(), "not-member").await;
}

#[tokio::test]
async fn a_member_whose_account_was_deleted_is_refused_at_the_request() {
    let mut deleted = common::active_member();
    deleted.membership = Err(maknae_kernel::AuthzError::NoUser);
    refused_at_the_request(deleted, "not-member").await;
}

#[tokio::test]
async fn a_locked_local_account_is_refused() {
    let locked = || common::member_facts(AccountFact::Checked(AccountState::Locked));
    refused_at_the_request(locked(), "account-locked").await;
    let (conn, client) = pinging().await;
    let recs = drive_facts(vec![conn], common::ScriptedFacts::gate(vec![locked()])).await;
    assert_eq!(
        trail(&of_session(&recs)),
        vec![row("connection", "connect", "deny", "account-locked")]
    );
    assert_eq!(answer(client).await, None);
}

#[tokio::test]
async fn an_unanswerable_source_is_an_infrastructure_denial() {
    let mut unanswered = common::active_member();
    unanswered.membership = Err(maknae_kernel::AuthzError::Resolve("nss".into()));
    let recs = refused_at_the_request(unanswered, "infrastructure:group").await;
    let session = of_session(&recs);
    assert_eq!(session[1].outcome.posture, "unavailable");
    assert_eq!(session[2].outcome.posture, "unavailable");
}

#[tokio::test]
async fn a_request_gather_past_its_bound_names_the_session_facts() {
    let (conn, client) = pinging().await;
    let recs = drive_facts(
        vec![conn],
        common::ScriptedFacts::gate_with(
            vec![
                (Duration::ZERO, common::active_member()),
                (Duration::from_millis(300), common::active_member()),
            ],
            Duration::from_millis(100),
        ),
    )
    .await;
    let session = of_session(&recs);
    assert_eq!(
        trail(&session),
        vec![
            admitted("active"),
            row(
                "request",
                "liveness.ping",
                "deny",
                "infrastructure:session-facts"
            ),
            terminated("deny", "infrastructure:session-facts"),
        ]
    );
    assert_eq!(session[1].outcome.posture, "unavailable");
    assert_eq!(session[2].outcome.posture, "unavailable");
    assert_unauthorized(answer(client).await);
}

#[tokio::test]
async fn a_refusal_whose_record_cannot_be_appended_writes_no_frame() {
    let (conn, client) = pinging().await;
    let recs = drive_into(
        RecEmit::refusing(Some("request")),
        client_class(),
        vec![conn],
        cfg_with(8, 150),
        common::serving(),
        common::ScriptedFacts::gate(vec![common::active_member(), common::non_member()]),
        Duration::MAX,
    )
    .await;
    assert_eq!(
        trail(&of_session(&recs)),
        vec![
            admitted("active"),
            row("request", "liveness.ping", "deny", "not-member"),
            terminated("deny", "not-member"),
        ]
    );
    assert_eq!(answer(client).await, None);
}

#[tokio::test]
async fn a_failed_admission_append_ends_the_session_as_an_infrastructure_denial() {
    let (conn, client) = pinging().await;
    let recs = drive_into(
        RecEmit::refusing(Some("connection")),
        client_class(),
        vec![conn],
        cfg_with(8, 150),
        common::serving(),
        common::ScriptedFacts::gate(vec![common::active_member()]),
        Duration::MAX,
    )
    .await;
    let session = of_session(&recs);
    assert_eq!(
        trail(&session),
        vec![
            admitted("active"),
            terminated("deny", "infrastructure:audit")
        ]
    );
    assert_eq!(session[1].outcome.posture, "unavailable");
    assert_eq!(answer(client).await, None);
}

#[tokio::test]
async fn a_directory_account_is_served_and_says_not_checked() {
    let directory =
        || common::member_facts(AccountFact::NotChecked(NotCheckedWhy::DirectoryAccount));
    let (conn, _client) = pinging().await;
    let recs = drive_facts(
        vec![conn],
        common::ScriptedFacts::gate(vec![directory(), directory()]),
    )
    .await;
    assert_eq!(
        trail(&of_session(&recs)),
        vec![
            admitted("not-checked:directory"),
            row("request", "liveness.ping", "permit", "authorized"),
            terminated("permit", "disconnect"),
        ]
    );
}

#[tokio::test]
async fn a_group_source_that_fails_is_an_infrastructure_denial_that_keeps_the_name() {
    let mut failed = common::active_member();
    failed.membership = Err(maknae_kernel::AuthzError::Unanswered {
        user: "scripted".into(),
        why: "EIO".into(),
    });
    let (conn, client) = pinging().await;
    let recs = drive_facts(vec![conn], common::ScriptedFacts::gate(vec![failed])).await;
    let session = of_session(&recs);
    assert_eq!(session.len(), 1, "{session:?}");
    let deny = session[0];
    assert_eq!(
        (
            deny.event.as_str(),
            deny.outcome.result.as_str(),
            deny.outcome.posture.as_str(),
            deny.subject.user.as_deref(),
        ),
        ("connection", "deny", "unavailable", Some("scripted"))
    );
    assert!(
        deny.outcome.reason.starts_with("infrastructure"),
        "{:?}",
        deny.outcome.reason
    );
    assert_eq!(answer(client).await, None);
}

#[tokio::test]
async fn a_user_renamed_between_connect_and_request_is_served_under_the_new_name() {
    let mut renamed = common::active_member();
    if let Ok(m) = renamed.membership.as_mut() {
        m.user = "renamed-115".into();
        m.dir = "/home/renamed-115".into();
    }
    let (conn, client) = pinging().await;
    let recs = drive_facts(
        vec![conn],
        common::ScriptedFacts::gate(vec![common::active_member(), renamed]),
    )
    .await;
    assert_eq!(
        of_session(&recs)
            .iter()
            .map(|r| (r.event.as_str(), r.subject.user.as_deref()))
            .collect::<Vec<_>>(),
        vec![
            ("connection", Some("scripted")),
            ("request", Some("renamed-115")),
            ("session", Some("scripted")),
        ]
    );
    assert!(matches!(
        answer(client).await,
        Some(maknae_proto::RespResult::Ok(maknae_proto::Payload::Pong))
    ));
}

#[tokio::test]
async fn a_served_connection_ends_with_a_disconnect_record() {
    let (conn, client) = pinging().await;
    let recs = drive_facts(
        vec![conn],
        common::ScriptedFacts::gate(vec![common::active_member(), common::active_member()]),
    )
    .await;
    let session = of_session(&recs);
    let last = session.last().expect("records for the session");
    assert_eq!(
        (
            last.event.as_str(),
            last.action.as_str(),
            last.outcome.result.as_str(),
            last.outcome.reason.as_str(),
            last.outcome.posture.as_str(),
        ),
        ("session", "terminate", "permit", "disconnect", "stopped")
    );
    assert_eq!(last.seq, session[session.len() - 2].seq + 1);
    assert_eq!(last.session_id, session[0].session_id);
    assert_eq!(last.subject.user.as_deref(), Some("scripted"));
    assert!(matches!(
        answer(client).await,
        Some(maknae_proto::RespResult::Ok(maknae_proto::Payload::Pong))
    ));
}

#[tokio::test]
async fn a_connection_past_its_lifetime_ends_with_a_lifetime_record() {
    let ended_by_lifetime = vec![
        admitted("active"),
        row("request", "liveness.ping", "deny", "lifetime"),
        terminated("deny", "lifetime"),
    ];
    let (conn, client) = pinging().await;
    let slow_request_gather = drive_gated(
        client_class(),
        vec![conn],
        cfg_with(8, 150),
        common::serving(),
        common::ScriptedFacts::gate_with(
            vec![
                (Duration::ZERO, common::active_member()),
                (Duration::from_millis(100), common::active_member()),
            ],
            Duration::from_secs(1),
        ),
        Duration::from_millis(50),
    )
    .await;
    assert_eq!(trail(&of_session(&slow_request_gather)), ended_by_lifetime);
    assert_unauthorized(answer(client).await);

    let (conn, client) = pinging().await;
    let spent_before_the_request = drive_gated(
        client_class(),
        vec![conn],
        cfg_with(8, 150),
        common::serving(),
        common::ScriptedFacts::gate(vec![common::active_member()]),
        Duration::ZERO,
    )
    .await;
    assert_eq!(
        trail(&of_session(&spent_before_the_request)),
        ended_by_lifetime
    );
    assert_unauthorized(answer(client).await);
}

/// A verdict the real per-read check set: a read whose bytes carry no
/// credentials naming the expected sender.
async fn mismatched_sender() -> SenderVerdict {
    let (writer, reader) = tokio::net::UnixStream::pair().unwrap();
    let mut collector = maknae_plane::FdCollector::new(
        reader,
        1,
        Some(maknae_io::ExpectedSender {
            pid: 1,
            uid: u32::MAX,
        }),
    );
    let verdict = collector.sender_verdict();
    writer.writable().await.unwrap();
    writer.try_write(b"x").unwrap();
    let mut buf = [0u8; 1];
    let refused = tokio::io::AsyncReadExt::read(&mut collector, &mut buf).await;
    assert!(refused.is_err(), "{refused:?}");
    assert!(verdict.mismatched());
    verdict
}

async fn refused_for_its_sender(server: DuplexStream, client: DuplexStream) {
    let recs = drive_facts(
        vec![Scripted::OkWith(
            server,
            certified("spiffe://d/plane/cli"),
            SESSION_UID,
            mismatched_sender().await,
        )],
        common::ScriptedFacts::gate(vec![common::active_member()]),
    )
    .await;
    assert_eq!(
        trail(&of_session(&recs)),
        vec![
            admitted("active"),
            row("request", "read", "deny", "sender-mismatch"),
            terminated("deny", "sender-mismatch"),
        ]
    );
    assert_unauthorized(answer(client).await);
}

#[tokio::test]
async fn a_sender_mismatch_read_is_refused() {
    let (mut client, server) = tokio::io::duplex(1024);
    tokio::io::AsyncWriteExt::shutdown(&mut client)
        .await
        .unwrap();
    refused_for_its_sender(server, client).await;
}

#[tokio::test]
async fn a_sender_mismatch_that_reaches_the_read_timeout_is_refused() {
    let (client, server) = tokio::io::duplex(1024);
    refused_for_its_sender(server, client).await;
}

#[tokio::test]
async fn a_frame_read_timeout_ends_idle() {
    let (client, server) = tokio::io::duplex(1024);
    let recs = drive_facts(
        vec![Scripted::Ok(
            server,
            certified("spiffe://d/plane/cli"),
            SESSION_UID,
        )],
        common::ScriptedFacts::gate(vec![common::active_member()]),
    )
    .await;
    assert_eq!(
        trail(&of_session(&recs)),
        vec![
            admitted("active"),
            row("request", "read", "deny", "read timeout"),
            terminated("deny", "idle"),
        ]
    );
    assert_eq!(answer(client).await, None);
}

/// An active member on every gather, whatever process the connection came from.
struct AlwaysActiveMember;

impl maknae_kernel::SessionFacts for AlwaysActiveMember {
    fn membership(
        &self,
        _admission: maknae_kernel::Admission,
        _uid: u32,
    ) -> Result<maknae_kernel::Membership, maknae_kernel::AuthzError> {
        common::active_member().membership
    }

    fn account(&self, _uid: u32) -> AccountFact {
        common::active_member().account
    }
}

#[tokio::test]
async fn an_active_member_is_admitted_and_served_without_a_login_session() {
    let (conn, client) = pinging().await;
    let recs = drive_facts(
        vec![conn],
        FactsGate::for_test(Arc::new(AlwaysActiveMember), Duration::from_secs(5)),
    )
    .await;
    assert_eq!(
        trail(&of_session(&recs)),
        vec![
            admitted("active"),
            row("request", "liveness.ping", "permit", "authorized"),
            terminated("permit", "disconnect"),
        ]
    );
    assert!(matches!(
        answer(client).await,
        Some(maknae_proto::RespResult::Ok(maknae_proto::Payload::Pong))
    ));
}

const AGENT_SOCKET: &str = "/run/maknae/test-agent.sock";
const TD: &str = "d";
const HOBI: u32 = 12_001;
const JIN: u32 = 12_002;
const MEMBER: u32 = 12_500;

fn agent_id(id: &str) -> maknae_config::AgentId {
    maknae_config::AgentId::parse(id).unwrap()
}

fn agent_leaf(id: &str) -> ChannelPeer {
    ChannelPeer::Agent {
        san: maknae_vault::agent_uri_san(TD, &agent_id(id)),
        agent: agent_id(id),
        not_after: std::time::SystemTime::now() + Duration::from_secs(3600),
    }
}

fn agents(pairs: &[(&str, u32)]) -> maknae_kernel::AgentAdmission {
    maknae_kernel::AgentAdmission {
        view: Arc::new(maknae_kernel::FixedEnrollment(
            pairs.iter().map(|(a, u)| (agent_id(a), *u)).collect(),
        )),
        tasks: Arc::new(maknae_kernel::TaskStore::new()),
    }
}

struct AccountFacts {
    user: &'static str,
    dir: std::path::PathBuf,
    in_group: bool,
}

impl maknae_kernel::SessionFacts for AccountFacts {
    fn membership(
        &self,
        _admission: maknae_kernel::Admission,
        _uid: u32,
    ) -> Result<maknae_kernel::Membership, maknae_kernel::AuthzError> {
        Ok(maknae_kernel::Membership {
            in_group: self.in_group,
            user: self.user.into(),
            dir: self.dir.clone(),
        })
    }

    fn account(&self, _uid: u32) -> AccountFact {
        AccountFact::NotChecked(NotCheckedWhy::Platform)
    }
}

fn account_gate(user: &'static str, dir: std::path::PathBuf, in_group: bool) -> Arc<FactsGate> {
    FactsGate::for_test(
        Arc::new(AccountFacts {
            user,
            dir,
            in_group,
        }),
        Duration::from_secs(5),
    )
}

struct Seen<P> {
    inner: Arc<P>,
    asked: Mutex<Vec<maknae_security::Request>>,
}

impl<P> Seen<P> {
    fn new(inner: Arc<P>) -> Arc<Self> {
        Arc::new(Seen {
            inner,
            asked: Mutex::new(Vec::new()),
        })
    }
    fn asked(&self, action: &str) -> Vec<maknae_security::Request> {
        self.asked
            .lock()
            .unwrap()
            .iter()
            .filter(|r| r.action.0 == action)
            .cloned()
            .collect()
    }
}

impl<P: maknae_security::Authorizer> maknae_security::Authorizer for Seen<P> {
    fn decide(&self, req: &maknae_security::Request) -> maknae_security::Verdict {
        self.decide_cited(req).verdict
    }
    fn decide_reporting_role(
        &self,
        req: &maknae_security::Request,
    ) -> (maknae_security::Verdict, Option<&'static str>) {
        let d = self.decide_cited(req);
        (d.verdict, d.role)
    }
    fn decide_cited(&self, req: &maknae_security::Request) -> maknae_security::Decided {
        self.asked.lock().unwrap().push(req.clone());
        self.inner.decide_cited(req)
    }
    fn decide_cited_all(&self, reqs: &[maknae_security::Request]) -> Vec<maknae_security::Decided> {
        self.asked.lock().unwrap().extend(reqs.iter().cloned());
        self.inner.decide_cited_all(reqs)
    }
}

async fn drive_channel<P>(
    class: ChannelClass,
    script: Vec<Scripted>,
    gate: Arc<FactsGate>,
    authorizer: Arc<P>,
    agents: maknae_kernel::AgentAdmission,
) -> Vec<AuditRecord>
where
    P: maknae_security::Authorizer + Send + Sync + 'static,
{
    let emit = RecEmit::new();
    let acceptor = FakeAccept::authenticating(script, class.peer_auth.clone());
    let (tx, rx) = tokio::sync::oneshot::channel::<()>();
    let emit_for_loop = emit.clone();
    let loop_task = tokio::spawn(async move {
        maknae_kernel::accept_loop(
            acceptor,
            class,
            emit_for_loop,
            Arc::new(SessionIds::with_nonce(1)),
            cfg_with(8, 500),
            capacity(&cfg_with(8, 500)),
            wctx(),
            async move {
                let _ = rx.await;
            },
            pending_supervisor(),
            authorizer,
            Arc::new(maknae_kernel::LiveConfig::new(Default::default(), None)),
            Arc::new("test-backend".to_string()),
            Arc::new("US".to_string()),
            Arc::new("ml-dsa-87".to_string()),
            Arc::new(None),
            maknae_kernel::unavailable_egress(),
            common::no_baseline(),
            common::serving(),
            gate,
            Duration::MAX,
            common::conversations(),
            agents,
        )
        .await;
    });
    tokio::time::sleep(Duration::from_millis(500)).await;
    let _ = tx.send(());
    loop_task.await.unwrap();
    emit.records()
}

fn agent_socket() -> ChannelClass {
    maknae_kernel::agent_class(AGENT_SOCKET.into(), TD)
}

async fn asking(
    peer: ChannelPeer,
    uid: u32,
    verb: maknae_proto::Verb,
    task: Option<maknae_proto::TaskId>,
    fds: maknae_io::DelegatedFds,
) -> (Scripted, DuplexStream) {
    let (mut client, server) = tokio::io::duplex(65536);
    let body = maknae_proto::encode_request(&maknae_proto::Request {
        task,
        protocol_version: maknae_proto::PROTOCOL_VERSION,
        verb,
    })
    .unwrap();
    common::write_frame(&mut client, &body).await.unwrap();
    (Scripted::Delegating(server, peer, uid, fds), client)
}

fn uid_records(recs: &[AuditRecord], uid: u32) -> Vec<&AuditRecord> {
    recs.iter().filter(|r| r.source.uid == uid).collect()
}

#[tokio::test]
async fn an_enrolled_agent_is_admitted_on_the_agent_socket() {
    let (conn, client) = asking(
        agent_leaf("hobi"),
        HOBI,
        maknae_proto::Verb::Ping,
        None,
        maknae_io::DelegatedFds::new(0),
    )
    .await;
    let recs = drive_channel(
        agent_socket(),
        vec![conn],
        account_gate("hobi-svc", "/var/empty".into(), false),
        Arc::new(common::AlwaysPermit),
        agents(&[("hobi", HOBI)]),
    )
    .await;
    drop(client);
    let session = uid_records(&recs, HOBI);
    let connect = session
        .iter()
        .find(|r| r.event == "connection")
        .expect("a connection record");
    assert_eq!(
        (
            connect.outcome.result.as_str(),
            connect.source.plane_uri_san.as_deref(),
            connect.subject.agent.as_deref(),
            connect.where_.socket.as_str(),
        ),
        (
            "permit",
            Some("spiffe://d/plane/agent/hobi"),
            Some("hobi"),
            AGENT_SOCKET
        ),
        "{session:?}"
    );
    assert!(
        session
            .iter()
            .all(|r| r.subject.agent.as_deref() == Some("hobi")),
        "every record of the session names its agent: {session:?}"
    );
    assert!(session.iter().any(|r| r.event == "session"), "{session:?}");
}

#[tokio::test]
async fn an_enrolled_leaf_from_another_agents_uid_is_refused() {
    let (conn, client) = asking(
        agent_leaf("hobi"),
        JIN,
        maknae_proto::Verb::Ping,
        None,
        maknae_io::DelegatedFds::new(0),
    )
    .await;
    let recs = drive_channel(
        agent_socket(),
        vec![conn],
        account_gate("jin-svc", "/var/empty".into(), false),
        Arc::new(common::AlwaysPermit),
        agents(&[("hobi", HOBI), ("jin", JIN)]),
    )
    .await;
    assert_eq!(
        trail(&uid_records(&recs, JIN)),
        vec![row("connection", "connect", "deny", "not-enrolled")]
    );
    assert_eq!(answer(client).await, None);
}

#[tokio::test]
async fn a_maknae_member_presenting_an_enrolled_agents_leaf_is_refused() {
    let (conn, client) = asking(
        agent_leaf("hobi"),
        MEMBER,
        maknae_proto::Verb::Ping,
        None,
        maknae_io::DelegatedFds::new(0),
    )
    .await;
    let recs = drive_channel(
        agent_socket(),
        vec![conn],
        account_gate("ann", "/var/empty".into(), true),
        Arc::new(common::AlwaysPermit),
        agents(&[("hobi", HOBI)]),
    )
    .await;
    assert_eq!(
        trail(&uid_records(&recs, MEMBER)),
        vec![row("connection", "connect", "deny", "not-enrolled")]
    );
    assert_eq!(answer(client).await, None);
}

#[tokio::test]
async fn a_cron_job_under_a_humans_uid_acts_only_as_that_human_on_the_client_socket() {
    let fx = common::Fixture::new("cron-on-client-609", "Read");
    let pdp = Seen::new(fx.authorizer());
    let (conn, client) = asking(
        ChannelPeer::Certless,
        fx.peer_uid,
        maknae_proto::Verb::Ping,
        None,
        maknae_io::DelegatedFds::new(0),
    )
    .await;
    let recs = drive_channel(
        client_class(),
        vec![conn],
        account_gate("cron-human", "/var/empty".into(), true),
        Arc::clone(&pdp),
        agents(&[("hobi", HOBI)]),
    )
    .await;
    drop(client);
    let asked = pdp.asked("liveness.ping");
    assert_eq!(asked.len(), 1, "{asked:?}");
    let subject = &asked[0].subject.0;
    assert_eq!(
        subject.get(maknae_security::SUBJECT_CHANNEL),
        Some(&maknae_security::AttrValue::Str(
            maknae_security::CHANNEL_CLIENT.into()
        ))
    );
    for k in [
        maknae_security::SUBJECT_AGENT,
        maknae_security::SUBJECT_TASK,
        maknae_security::SUBJECT_TASKER,
    ] {
        assert_eq!(subject.get(k), None, "{k}");
    }
    let request = recs
        .iter()
        .find(|r| r.event == "request" && r.action == "liveness.ping")
        .expect("the ping request record");
    assert_eq!(
        (
            request.outcome.result.as_str(),
            request.subject.role.as_deref(),
            request.subject.agent.as_deref()
        ),
        ("permit", Some("user"), None),
        "{request:?}"
    );
    std::fs::remove_dir_all(&fx.root).ok();
}

/// A composed PDP whose one enrolled agent, `hobi`, is the test euid's account and
/// whose `policy.yaml` grants `Read` and `Write` over its home.
fn agent_pdp(
    tag: &str,
) -> (
    common::DirGuard,
    Arc<maknae_kernel::Composition<maknae_authz_basic::HermeticAuthorizer>>,
) {
    agent_pdp_over(
        tag,
        "schema_version: 1\npermissions:\n  allow: []\n  deny: []\n",
    )
}

fn agent_pdp_over(
    tag: &str,
    authz: &str,
) -> (
    common::DirGuard,
    Arc<maknae_kernel::Composition<maknae_authz_basic::HermeticAuthorizer>>,
) {
    use std::os::unix::fs::PermissionsExt;
    let root = std::env::temp_dir().join(format!("agent609_{tag}_{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&root);
    std::fs::create_dir_all(&root).unwrap();
    std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700)).unwrap();
    let root = common::DirGuard(root.canonicalize().unwrap());
    let paths = maknae_authz_basic::PolicyPaths::in_dir(&root);
    common::write_0640(&paths.authz, authz);
    common::write_0640(&paths.sensitive, common::EMPTY_SENSITIVE);
    common::write_0640(
        &paths.bindings,
        "schema_version: 1\nbindings:\n  admin: [\"root\"]\n",
    );
    let agents = root.join(maknae_config::AGENTS_DIR);
    let hobi = agents.join("hobi");
    std::fs::create_dir_all(&hobi).unwrap();
    for d in [&agents, &hobi] {
        std::fs::set_permissions(d, std::fs::Permissions::from_mode(0o750)).unwrap();
    }
    let me = nix::unistd::geteuid().as_raw();
    common::write_0640(
        &hobi.join(maknae_config::ENROLLMENT_FILE),
        &format!("agent_id: hobi\naccount: hobi-svc\nuid: {me}\nrole: user\n"),
    );
    common::write_0640(
        &hobi.join(maknae_config::POLICY_FILE),
        "schema_version: 1\npermissions:\n  allow: [\"Read(~/**)\", \"Write(~/**)\"]\n  deny: []\n",
    );
    let basic = maknae_authz_basic::HermeticAuthorizer::new(
        paths,
        maknae_config::Principal {
            name: "operator".into(),
            uid: me + 1,
        },
        maknae_config::TargetRequired {
            owner: None,
            mode_mask: Some(0o022),
            nlink_exactly_one: false,
            regular_file: true,
            max_bytes: None,
        },
        maknae_crypto::sha256,
    )
    .unwrap();
    basic.set_hosts(maknae_authz_basic::HostLookups {
        account: |uid| {
            Ok(
                (uid == nix::unistd::geteuid().as_raw()).then(|| maknae_io::HostAccount {
                    uid,
                    name: "hobi-svc".into(),
                    primary_gid: uid,
                    shell: "/usr/sbin/nologin".into(),
                    dir: "/var/empty".into(),
                    named_groups: Vec::new(),
                }),
            )
        },
        daemons: || {
            Ok(maknae_io::DaemonFacts {
                uids: Vec::new(),
                gids: Vec::new(),
            })
        },
        group: |_| Ok(None),
    });
    basic.reload_from_file().unwrap();
    let us = &maknae_config::BasicPolicy;
    let pdp = Arc::new(maknae_kernel::Composition::new(
        basic,
        maknae_kernel::CeilingAuthorizer::new(maknae_config::Ceiling::baseline_for(us), us),
    ));
    assert_eq!(
        maknae_authz_basic::Baseline::snapshot(pdp.baseline()).agent_uid("hobi"),
        Some(me)
    );
    (root, pdp)
}

fn signed_for(agent: &str) -> maknae_proto::SignedTask {
    use maknae_kernel::TaskObjectForTest;
    maknae_proto::SignedTask {
        task: maknae_proto::TaskObject::for_test(agent, 1002),
        signature: maknae_proto::TaskSignature {
            alg: "test".into(),
            leaf: maknae_proto::Bytes::new(vec![1].into()),
            chain: Vec::new(),
            sig: maknae_proto::Bytes::new(vec![2].into()),
        },
    }
}

fn euid_hobi(held: &[(maknae_proto::SignedTask, u32)]) -> maknae_kernel::AgentAdmission {
    let a = agents(&[("hobi", nix::unistd::geteuid().as_raw())]);
    for (task, uid) in held {
        a.tasks.insert_for_test(task.clone(), *uid);
    }
    a
}

static FS_TURN: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

async fn first_answer(client: &mut DuplexStream) -> Option<maknae_proto::RespResult> {
    tokio::time::timeout(Duration::from_secs(2), common::read_frame(client, 1 << 20))
        .await
        .ok()?
        .ok()
        .and_then(|b| maknae_proto::decode_response(&b).ok())
        .map(|r| r.result)
}

fn directory_fd(dir: &std::path::Path) -> maknae_io::DelegatedFds {
    let fds = maknae_io::DelegatedFds::new(4);
    fds.push(std::fs::File::open(dir).unwrap().into());
    fds
}

fn create_in(dir: &std::path::Path) -> maknae_proto::Verb {
    maknae_proto::Verb::FsWrite {
        path: dir.join("agent-609-created").to_str().unwrap().into(),
        content_length: 7,
        mode: maknae_proto::WriteMode::CreateExclusive,
        conversation: None,
    }
}

#[tokio::test]
async fn an_agent_write_in_its_home_is_permitted_on_the_agent_channel() {
    let _turn = FS_TURN.lock().await;
    let (_root, pdp) = agent_pdp("write-home");
    let home = common::second_home("agent609-write");
    let me = nix::unistd::geteuid().as_raw();
    let (conn, mut client) = asking(
        agent_leaf("hobi"),
        me,
        create_in(&home),
        None,
        directory_fd(&home),
    )
    .await;
    let (recs, answered) = tokio::join!(
        drive_channel(
            agent_socket(),
            vec![conn],
            account_gate("hobi-svc", home.to_path_buf(), false),
            pdp,
            euid_hobi(&[]),
        ),
        async {
            let got = first_answer(&mut client).await;
            drop(client);
            got
        }
    );
    assert!(
        matches!(
            answered,
            Some(maknae_proto::RespResult::Ok(
                maknae_proto::Payload::MutationAttempt(_)
            ))
        ),
        "the agent's own policy grants the write: {answered:?} {recs:?}"
    );
    let write = recs
        .iter()
        .find(|r| r.action == "fs.write")
        .expect("the fs.write record");
    assert_eq!(write.subject.agent.as_deref(), Some("hobi"), "{write:?}");
}

#[tokio::test]
async fn an_fs_write_citing_another_agents_task_is_refused() {
    let _turn = FS_TURN.lock().await;
    let (_root, pdp) = agent_pdp("write-other-task");
    let pdp = Seen::new(pdp);
    let home = common::second_home("agent609-other-task");
    let me = nix::unistd::geteuid().as_raw();
    let jins = signed_for("jin");
    let cited = jins.task.task_id;
    let (conn, client) = asking(
        agent_leaf("hobi"),
        me,
        create_in(&home),
        Some(jins.task.task_id),
        directory_fd(&home),
    )
    .await;
    let recs = drive_channel(
        agent_socket(),
        vec![conn],
        account_gate("hobi-svc", home.to_path_buf(), false),
        Arc::clone(&pdp),
        euid_hobi(&[(jins, JIN)]),
    )
    .await;
    let session: Vec<&AuditRecord> = recs
        .iter()
        .filter(|r| r.source.uid == me && r.event != "shutdown")
        .collect();
    let reason = format!("task-other-agent:{cited}");
    assert_eq!(
        trail(&session),
        vec![
            admitted("not-checked:platform"),
            row("request", "fs.write", "deny", &reason),
            terminated("deny", &reason),
        ]
    );
    assert!(pdp.asked("fs.write").is_empty(), "refused before the PDP");
    assert!(!home.join("agent-609-created").exists());
    let mut client = client;
    match first_answer(&mut client).await {
        Some(maknae_proto::RespResult::Err(e)) => assert_eq!(
            (e.code, e.message.as_str()),
            (maknae_proto::ProtoErrCode::Unauthorized, "not authorized")
        ),
        other => panic!("expected the generic Unauthorized frame, got {other:?}"),
    }
}

#[tokio::test]
async fn a_read_citing_the_agents_own_task_carries_subject_task() {
    let _turn = FS_TURN.lock().await;
    let (_root, pdp) = agent_pdp("read-own-task");
    let pdp = Seen::new(pdp);
    let home = common::second_home("agent609-read");
    let file = home.join("notes");
    common::write_0640(&file, "agent-609-notes");
    let me = nix::unistd::geteuid().as_raw();
    let own = signed_for("hobi");
    let id = own.task.task_id;
    let fds = maknae_io::DelegatedFds::new(4);
    fds.push(maknae_io::open_path_for_delegation(&file).unwrap());
    let (conn, mut client) = asking(
        agent_leaf("hobi"),
        me,
        maknae_proto::Verb::Read {
            path: file.to_str().unwrap().into(),
            conversation: None,
            page: None,
        },
        Some(id),
        fds,
    )
    .await;
    let (recs, _) = tokio::join!(
        drive_channel(
            agent_socket(),
            vec![conn],
            account_gate("hobi-svc", home.to_path_buf(), false),
            Arc::clone(&pdp),
            euid_hobi(&[(own, me)]),
        ),
        async {
            let got = first_answer(&mut client).await;
            drop(client);
            got
        }
    );
    let asked = pdp.asked("fs.read");
    assert_eq!(asked.len(), 1, "{asked:?}");
    assert_eq!(
        asked[0].subject.0.get(maknae_security::SUBJECT_TASK),
        Some(&maknae_security::AttrValue::Str(id.to_string()))
    );
    let read = recs
        .iter()
        .find(|r| r.action == "fs.read")
        .expect("the fs.read record");
    assert_eq!(
        (
            read.subject.task_id.as_deref(),
            read.subject.agent.as_deref()
        ),
        (Some(id.to_string().as_str()), Some("hobi")),
        "{read:?}"
    );
}

#[tokio::test]
async fn an_agent_channel_request_meets_the_host_list() {
    let _turn = FS_TURN.lock().await;
    let (root, pdp) = agent_pdp("read-sensitive");
    let home = common::second_home("agent617-sensitive");
    let file = home.join("notes");
    common::write_0640(&file, "maknae-617-sensitive-sentinel");
    common::write_0640(
        &maknae_authz_basic::PolicyPaths::in_dir(&root).sensitive,
        &format!(
            "schema_version: 1\nsensitive:\n  - \"{}\"\n",
            file.display()
        ),
    );
    pdp.baseline().reload_from_file().unwrap();
    let pdp = Seen::new(pdp);
    let me = nix::unistd::geteuid().as_raw();
    let own = signed_for("hobi");
    let fds = maknae_io::DelegatedFds::new(4);
    fds.push(maknae_io::open_path_for_delegation(&file).unwrap());
    let (conn, mut client) = asking(
        agent_leaf("hobi"),
        me,
        maknae_proto::Verb::Read {
            path: file.to_str().unwrap().into(),
            conversation: None,
            page: None,
        },
        Some(own.task.task_id),
        fds,
    )
    .await;
    let (recs, answer) = tokio::join!(
        drive_channel(
            agent_socket(),
            vec![conn],
            account_gate("hobi-svc", home.to_path_buf(), false),
            Arc::clone(&pdp),
            euid_hobi(&[(own, me)]),
        ),
        async {
            let got = first_answer(&mut client).await;
            drop(client);
            got
        }
    );
    let asked = pdp.asked("fs.read");
    assert_eq!(asked.len(), 1, "{asked:?}");
    assert_eq!(
        asked[0].subject.0.get(maknae_security::SUBJECT_CHANNEL),
        Some(&maknae_security::AttrValue::Str(
            maknae_security::CHANNEL_AGENT.into()
        ))
    );
    let read = recs
        .iter()
        .find(|r| r.action == "fs.read")
        .expect("the fs.read record");
    assert_eq!(
        (
            read.outcome.result.as_str(),
            read.outcome.reason.clone(),
            read.subject.agent.as_deref()
        ),
        (
            "deny",
            format!("sensitive: host {}", file.display()),
            Some("hobi")
        ),
        "{read:?}"
    );
    match answer {
        Some(maknae_proto::RespResult::Err(e)) => {
            assert_eq!(e.code, maknae_proto::ProtoErrCode::Unauthorized)
        }
        other => panic!("expected a refusal, got {other:?}"),
    }
}

#[tokio::test]
async fn an_agent_request_citing_its_task_is_stamped_and_audited() {
    let (_root, pdp) = agent_pdp("whoami-own-task");
    let pdp = Seen::new(pdp);
    let me = nix::unistd::geteuid().as_raw();
    let own = signed_for("hobi");
    let id = own.task.task_id;
    let (conn, client) = asking(
        agent_leaf("hobi"),
        me,
        maknae_proto::Verb::Whoami,
        Some(id),
        maknae_io::DelegatedFds::new(0),
    )
    .await;
    let recs = drive_channel(
        agent_socket(),
        vec![conn],
        account_gate("hobi-svc", "/var/empty".into(), false),
        Arc::clone(&pdp),
        euid_hobi(&[(own, me)]),
    )
    .await;
    drop(client);
    let asked = pdp.asked("admin.whoami");
    assert_eq!(asked.len(), 1, "{asked:?}");
    let s = |v: &str| Some(maknae_security::AttrValue::Str(v.into()));
    let subject = &asked[0].subject.0;
    assert_eq!(
        (
            subject.get(maknae_security::SUBJECT_CHANNEL).cloned(),
            subject.get(maknae_security::SUBJECT_AGENT).cloned(),
            subject.get(maknae_security::SUBJECT_TASK).cloned(),
            subject.get(maknae_security::SUBJECT_TASKER).cloned(),
        ),
        (
            s(maknae_security::CHANNEL_AGENT),
            s("hobi"),
            s(&id.to_string()),
            s("uid:1002")
        )
    );
    let request = recs
        .iter()
        .find(|r| r.event == "request" && r.action == "admin.whoami")
        .expect("the whoami request record");
    assert_eq!(
        (
            request.outcome.result.as_str(),
            request.subject.agent.as_deref(),
            request.subject.task_id.as_deref(),
            request.subject.tasker.as_deref(),
        ),
        (
            "permit",
            Some("hobi"),
            Some(id.to_string().as_str()),
            Some("uid:1002")
        ),
        "{request:?}"
    );
    let terminate = recs
        .iter()
        .find(|r| r.event == "session" && r.source.uid == me)
        .expect("the terminate record");
    assert_eq!(
        (
            terminate.subject.agent.as_deref(),
            terminate.subject.task_id.as_deref(),
            terminate.subject.tasker.as_deref(),
        ),
        (
            Some("hobi"),
            Some(id.to_string().as_str()),
            Some("uid:1002")
        ),
        "{terminate:?}"
    );
}

#[tokio::test]
async fn agents_are_denied_session_new_by_default() {
    let _turn = FS_TURN.lock().await;
    let (_root, pdp) = agent_pdp_over(
        "session-new-default",
        "schema_version: 1\npermissions:\n  allow: []\n  deny: []\nroles:\n  user:\n    allow: [\"session.new\"]\n",
    );
    let pdp = Seen::new(pdp);
    let home = common::second_home("agent609-session-new");
    let me = nix::unistd::geteuid().as_raw();
    let (conn, mut client) = asking(
        agent_leaf("hobi"),
        me,
        maknae_proto::Verb::SessionNew {
            cwd: home.to_str().unwrap().into(),
        },
        None,
        directory_fd(&home),
    )
    .await;
    let (recs, answered) = tokio::join!(
        drive_channel(
            agent_socket(),
            vec![conn],
            account_gate("hobi-svc", home.to_path_buf(), false),
            Arc::clone(&pdp),
            euid_hobi(&[]),
        ),
        async {
            let got = first_answer(&mut client).await;
            drop(client);
            got
        }
    );
    match answered {
        Some(maknae_proto::RespResult::Err(e)) => assert_eq!(
            (e.code, e.message.as_str()),
            (maknae_proto::ProtoErrCode::Unauthorized, "not authorized")
        ),
        other => panic!("expected the generic Unauthorized frame, got {other:?} {recs:?}"),
    }
    let asked = pdp.asked("session.new");
    assert_eq!(asked.len(), 1, "{asked:?}");
    assert_eq!(
        asked[0].subject.0.get(maknae_security::SUBJECT_AGENT),
        Some(&maknae_security::AttrValue::Str("hobi".into()))
    );
    let new = recs
        .iter()
        .find(|r| r.event == "request" && r.action == "session.new")
        .expect("the session.new record");
    assert_eq!(
        (
            new.outcome.result.as_str(),
            new.outcome.reason.as_str(),
            new.subject.agent.as_deref()
        ),
        (
            "deny",
            "agent hobi: session.new needs a grant in its policy.yaml",
            Some("hobi")
        ),
        "{new:?}"
    );
}
