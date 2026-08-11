//! Run-loop integration suite (spec §10 — AUTOMATED this PR, NOT deferred to the live
//! smoke). Drives `maknae_kernel::handle` directly over an in-process `tokio::io::duplex`
//! with a recording/failing `AuditEmit` impl, so the audit-then-respond ordering, the
//! fail-closed withhold, the group-half deny, and the read-timeout close are all pinned
//! without a live Vault or a real socket.
use std::future::Future;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use maknae_audit_append::{AuditEmit, AuditError, AuditRecord};

/// A recording `AuditEmit`: appends every record synchronously (so ordering assertions
/// see it before any response is written) and optionally forces the append future to err.
struct RecEmit {
    recs: Mutex<Vec<AuditRecord>>,
    fail: bool,
}

impl RecEmit {
    fn new(fail: bool) -> Arc<Self> {
        Arc::new(RecEmit {
            recs: Mutex::new(Vec::new()),
            fail,
        })
    }
    fn records(&self) -> Vec<AuditRecord> {
        self.recs.lock().unwrap().clone()
    }
}

impl AuditEmit for RecEmit {
    fn emit(&self, rec: &AuditRecord) -> impl Future<Output = Result<(), AuditError>> + Send {
        self.recs.lock().unwrap().push(rec.clone()); // record synchronously
        let fail = self.fail;
        async move {
            if fail {
                Err(AuditError::WritePrimary("forced".into()))
            } else {
                Ok(())
            }
        }
    }
}

fn default_cfg() -> maknae_config::TransportConfig {
    maknae_config::transport_from_section(None).unwrap()
}

fn ping_frame_bytes() -> Vec<u8> {
    maknae_proto::encode_request(&maknae_proto::Request {
        protocol_version: maknae_proto::PROTOCOL_VERSION,
        verb: maknae_proto::Verb::Ping,
    })
    .unwrap()
}

async fn write_ping(c: &mut tokio::io::DuplexStream) {
    maknae_proto::write_frame(c, &ping_frame_bytes())
        .await
        .unwrap();
}

#[tokio::test]
async fn audit_failure_withholds_response() {
    let (mut c, s) = tokio::io::duplex(4096);
    let emit = RecEmit::new(true); // audit append fails
    write_ping(&mut c).await;

    maknae_kernel::handle(
        s,
        "maknae://d/plane/cli".to_string(),
        501,
        true,
        emit.clone(),
        1,
        default_cfg(),
    )
    .await;

    // The request WAS recorded (the record is what the failing append refused to persist)...
    assert!(
        emit.records().iter().any(|r| r.event == "request"),
        "the request should have been offered to the audit sink"
    );
    // ...but NO response frame may be released once that append failed.
    let r = tokio::time::timeout(
        Duration::from_millis(200),
        maknae_proto::read_frame(&mut c, 65536),
    )
    .await;
    assert!(
        r.is_err() || r.unwrap().is_err(),
        "response MUST be withheld when audit append fails"
    );
}

#[tokio::test]
async fn deny_audits_then_closes() {
    let (mut c, s) = tokio::io::duplex(4096);
    let emit = RecEmit::new(false);
    // A client that is NOT in the maknae group: no verb is even read.
    write_ping(&mut c).await;

    maknae_kernel::handle(
        s,
        "maknae://d/plane/cli".to_string(),
        501,
        false, // in_group = false → Deny
        emit.clone(),
        7,
        default_cfg(),
    )
    .await;

    let recs = emit.records();
    let deny = recs
        .iter()
        .find(|r| r.event == "connection")
        .expect("a connection/deny record must be emitted");
    assert_eq!(deny.outcome.result, "deny");
    assert_eq!(deny.outcome.posture, "unauthorized");
    assert!(
        deny.outcome.reason.contains("maknae"),
        "deny reason should name the maknae-group check, got {:?}",
        deny.outcome.reason
    );
    assert_eq!(deny.session_id, 7);

    // No response frame.
    let r = tokio::time::timeout(
        Duration::from_millis(200),
        maknae_proto::read_frame(&mut c, 65536),
    )
    .await;
    assert!(
        r.is_err() || r.unwrap().is_err(),
        "deny must write no response"
    );
}

#[tokio::test]
async fn happy_ping_responds() {
    let (mut c, s) = tokio::io::duplex(4096);
    let emit = RecEmit::new(false);
    write_ping(&mut c).await;

    maknae_kernel::handle(
        s,
        "maknae://d/plane/cli".to_string(),
        501,
        true,
        emit.clone(),
        1,
        default_cfg(),
    )
    .await;

    // The request record was recorded (before the response — RecEmit records synchronously,
    // and handle emits before writing the frame).
    let recs = emit.records();
    let req = recs
        .iter()
        .find(|r| r.event == "request")
        .expect("a request record must be emitted");
    assert_eq!(req.outcome.result, "permit");
    assert_eq!(req.action, "ping");

    // ...and a readable Pong frame follows.
    let frame = maknae_proto::read_frame(&mut c, 65536).await.unwrap();
    let resp = maknae_proto::decode_response(&frame).unwrap();
    assert_eq!(resp.protocol_version, maknae_proto::PROTOCOL_VERSION);
    match resp.result {
        maknae_proto::RespResult::Ok(maknae_proto::Payload::Pong) => {}
        other => panic!("expected Ok(Pong), got {other:?}"),
    }
}

#[tokio::test]
async fn happy_whoami_carries_peer_facts() {
    let (mut c, s) = tokio::io::duplex(4096);
    let emit = RecEmit::new(false);
    let whoami = maknae_proto::encode_request(&maknae_proto::Request {
        protocol_version: maknae_proto::PROTOCOL_VERSION,
        verb: maknae_proto::Verb::Whoami,
    })
    .unwrap();
    maknae_proto::write_frame(&mut c, &whoami).await.unwrap();

    maknae_kernel::handle(
        s,
        "maknae://d/plane/cli".to_string(),
        501,
        true,
        emit.clone(),
        1,
        default_cfg(),
    )
    .await;

    let frame = maknae_proto::read_frame(&mut c, 65536).await.unwrap();
    match maknae_proto::decode_response(&frame).unwrap().result {
        maknae_proto::RespResult::Ok(maknae_proto::Payload::Whoami(w)) => {
            assert_eq!(w.peer_uid, 501);
            assert_eq!(w.peer_plane_uri_san, "maknae://d/plane/cli");
        }
        other => panic!("expected Ok(Whoami), got {other:?}"),
    }
}

#[tokio::test]
async fn read_timeout_closes() {
    // A short read timeout so the test is quick; send NOTHING.
    let mut cfg = default_cfg();
    cfg.read_timeout_ms = 150;
    let (mut c, s) = tokio::io::duplex(4096);
    let emit = RecEmit::new(false);

    let start = std::time::Instant::now();
    maknae_kernel::handle(
        s,
        "maknae://d/plane/cli".to_string(),
        501,
        true,
        emit.clone(),
        1,
        cfg,
    )
    .await;
    let elapsed = start.elapsed();

    // Returned within a small multiple of read_timeout_ms.
    assert!(
        elapsed < Duration::from_secs(2),
        "handle should return shortly after the read timeout, took {elapsed:?}"
    );
    let recs = emit.records();
    let timeout_rec = recs
        .iter()
        .find(|r| r.outcome.reason.contains("read timeout"))
        .expect("a read-timeout record must be emitted");
    assert_eq!(timeout_rec.outcome.result, "deny");

    // No response frame.
    let r = tokio::time::timeout(
        Duration::from_millis(200),
        maknae_proto::read_frame(&mut c, 65536),
    )
    .await;
    assert!(
        r.is_err() || r.unwrap().is_err(),
        "timeout must write no response"
    );
}
