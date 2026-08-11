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
use std::collections::VecDeque;
use std::future::Future;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use maknae_audit_append::{AuditEmit, AuditError, AuditRecord, SessionIds};
use maknae_kernel::{Conn, PlaneAccept, WhereCtx};
use maknae_vault::{AcceptRejection, PeerCreds, RejectReason};
use tokio::io::DuplexStream;

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

/// A scripted accept source. Each `accept()` pops the next outcome; when the script is
/// exhausted it parks forever (so the loop blocks in `accept` until shutdown fires).
enum Scripted {
    Ok(DuplexStream, String, u32),
    Reject(AcceptRejection),
}

struct FakeAccept {
    queue: Mutex<VecDeque<Scripted>>,
}
impl FakeAccept {
    fn new(items: Vec<Scripted>) -> Self {
        FakeAccept {
            queue: Mutex::new(items.into_iter().collect()),
        }
    }
}
impl PlaneAccept for FakeAccept {
    type Stream = DuplexStream;
    // Pop INSIDE the future so a `select!` that loses to shutdown (dropping this future
    // unpolled) does not silently consume a scripted item. The std MutexGuard is released
    // before the only await, so the future stays `Send` (satisfying the trait bound).
    async fn accept(
        &self,
        _handshake_timeout: Duration,
    ) -> Result<Conn<DuplexStream>, AcceptRejection> {
        let item = self.queue.lock().unwrap().pop_front();
        match item {
            Some(Scripted::Ok(stream, uri, uid)) => Ok(Conn {
                stream,
                peer_uri: uri,
                peer_uid: uid,
            }),
            Some(Scripted::Reject(rej)) => Err(rej),
            None => {
                std::future::pending::<()>().await;
                unreachable!()
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
        maknae_kernel::accept_loop(acceptor, emit_for_loop, session_ids, cfg, wctx(), shutdown)
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
