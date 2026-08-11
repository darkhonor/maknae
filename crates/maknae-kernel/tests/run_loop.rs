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

/// Like `RecEmit`, but fails ONLY the first `emit()` call and succeeds on every call
/// after — so a test can pin exactly WHICH append failed (admission vs. request) by
/// controlling how many prior successful calls preceded it. Used to prove the
/// admission-record append (codex round-8 P1) gates the response on its own, not just
/// on a later request-record failure.
struct FailFirstEmit {
    recs: Mutex<Vec<AuditRecord>>,
    calls: Mutex<u32>,
}

impl FailFirstEmit {
    fn new() -> Arc<Self> {
        Arc::new(FailFirstEmit {
            recs: Mutex::new(Vec::new()),
            calls: Mutex::new(0),
        })
    }
    fn records(&self) -> Vec<AuditRecord> {
        self.recs.lock().unwrap().clone()
    }
}

impl AuditEmit for FailFirstEmit {
    fn emit(&self, rec: &AuditRecord) -> impl Future<Output = Result<(), AuditError>> + Send {
        self.recs.lock().unwrap().push(rec.clone()); // record synchronously
        let mut calls = self.calls.lock().unwrap();
        *calls += 1;
        let is_first_call = *calls == 1;
        drop(calls);
        async move {
            if is_first_call {
                Err(AuditError::WritePrimary("forced (first call only)".into()))
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
        serde_json::json!({}),
    )
    .await;

    // The admission record WAS offered (the record is what the failing append refused
    // to persist) — codex round-8 P1: with EVERY append failing, the admission gate
    // (seq 1) now trips first, before the request is even read, so no `request` record
    // is ever offered in this scenario.
    assert!(
        emit.records().iter().any(|r| r.event == "connection"),
        "the admission record should have been offered to the audit sink"
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
async fn admission_audit_failure_withholds_response_without_reading_request() {
    // codex round-8 P1: the permit-admission record (seq 1) must gate the response
    // exactly like the request record (seq 2) does. Only the FIRST append (the
    // admission record) fails here; a later request-record append would have
    // succeeded — proving the gate trips on the admission append itself, not merely
    // as a side effect of the request append also failing.
    let (mut c, s) = tokio::io::duplex(4096);
    let emit = FailFirstEmit::new();
    write_ping(&mut c).await;

    maknae_kernel::handle(
        s,
        "maknae://d/plane/cli".to_string(),
        501,
        true, // in_group -> Permit
        emit.clone(),
        99,
        default_cfg(),
        serde_json::json!({}),
    )
    .await;

    let recs = emit.records();
    // Exactly one record: the admission append failed, so `handle` closed BEFORE ever
    // reading the request frame — no `request` record exists at all.
    assert_eq!(
        recs.len(),
        1,
        "handle must close immediately after the failed admission append, before reading \
         the request; got records: {recs:?}"
    );
    assert_eq!(recs[0].event, "connection");
    assert_eq!(recs[0].outcome.result, "permit");
    assert!(
        !recs.iter().any(|r| r.event == "request"),
        "the request must never be read once the admission append failed"
    );

    // No response frame.
    let r = tokio::time::timeout(
        Duration::from_millis(200),
        maknae_proto::read_frame(&mut c, 65536),
    )
    .await;
    assert!(
        r.is_err() || r.unwrap().is_err(),
        "response MUST be withheld when the admission audit append fails"
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
        serde_json::json!({}),
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
        serde_json::json!({}),
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
async fn permit_admission_precedes_request_record() {
    // P2-A (ADR-0019 audit completeness): a SUCCESSFUL admission must emit a `connection`/
    // permit record at seq 1 BEFORE the request is read, with the `request` record following
    // at seq 2 — so a served session's trail is admission-then-request, not request-only.
    let (mut c, s) = tokio::io::duplex(4096);
    let emit = RecEmit::new(false);
    write_ping(&mut c).await;

    maknae_kernel::handle(
        s,
        "maknae://d/plane/cli".to_string(),
        501,
        true, // in_group -> Permit
        emit.clone(),
        42,
        default_cfg(),
        serde_json::json!({}),
    )
    .await;

    let recs = emit.records();
    // Exactly two records, in order: connection/permit (seq 1), then request/permit (seq 2).
    let conn = recs
        .iter()
        .find(|r| r.event == "connection")
        .expect("a connection/permit admission record must be emitted");
    let req = recs
        .iter()
        .find(|r| r.event == "request")
        .expect("a request record must follow admission");
    assert_eq!(conn.outcome.result, "permit");
    assert_eq!(conn.outcome.posture, "authorized");
    assert_eq!(conn.action, "connect");
    assert_eq!(conn.session_id, 42);
    assert_eq!(conn.seq, 1, "admission must be seq 1");
    assert_eq!(req.outcome.result, "permit");
    assert_eq!(req.action, "ping");
    assert_eq!(req.seq, 2, "the request record must follow at seq 2");
    // Ordering in the emitted stream: admission strictly before the request.
    let conn_idx = recs.iter().position(|r| r.event == "connection").unwrap();
    let req_idx = recs.iter().position(|r| r.event == "request").unwrap();
    assert!(
        conn_idx < req_idx,
        "the connection/permit record must be emitted BEFORE the request record"
    );
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
        serde_json::json!({}),
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
        serde_json::json!({}),
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

#[tokio::test]
async fn configured_au3_1_is_stamped_onto_every_record() {
    // I-1 (Stage-3a final review): `audit.au3_1` (ADR-0019, AuditConfig) must be
    // threaded onto EVERY emitted `AuditRecord.au3_1` — not hardcoded to an empty
    // object. Exercise both a permit record (happy ping) and a deny record (group
    // check) with a non-empty, distinguishable `au3_1` value.
    let au3_1 = serde_json::json!({"deployer": "x"});

    // Permit path.
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
        au3_1.clone(),
    )
    .await;
    let recs = emit.records();
    assert!(!recs.is_empty(), "at least one record must be emitted");
    for r in &recs {
        assert_eq!(
            r.au3_1, au3_1,
            "every permit-path record's au3_1 must carry the configured value, got {:?}",
            r.au3_1
        );
    }

    // Deny path (group check fails, no verb even read).
    let (mut c2, s2) = tokio::io::duplex(4096);
    let emit2 = RecEmit::new(false);
    write_ping(&mut c2).await;
    maknae_kernel::handle(
        s2,
        "maknae://d/plane/cli".to_string(),
        501,
        false, // in_group = false -> Deny
        emit2.clone(),
        1,
        default_cfg(),
        au3_1.clone(),
    )
    .await;
    let recs2 = emit2.records();
    let deny = recs2
        .iter()
        .find(|r| r.event == "connection")
        .expect("a connection/deny record must be emitted");
    assert_eq!(
        deny.au3_1, au3_1,
        "the deny-path record's au3_1 must carry the configured value, not the hardcoded \
         empty map, got {:?}",
        deny.au3_1
    );
}

// A peer that sends a valid request and then NEVER reads the response must not hold
// the handler (and, in production, its semaphore permit) forever: the response write
// is bounded by `read_timeout_ms` and the close by the stream-close bound, so `handle`
// returns on its own. duplex(1) forces byte-at-a-time transfer: the request drains
// through the 1-byte pipe as `handle` reads it, then the response write fills the pipe
// and blocks — with no reader ever draining it — until the write bound fires.
#[tokio::test]
async fn unread_response_does_not_hang_the_handler() {
    let (mut client, server) = tokio::io::duplex(1);
    let emit = RecEmit::new(false);
    let mut cfg = default_cfg();
    cfg.read_timeout_ms = 300; // also the response-write bound
    let req = ping_frame_bytes();

    // Feed the request byte-by-byte from a side task (the 1-byte pipe can't hold it
    // all), then keep `client` alive WITHOUT ever reading the response.
    let writer = tokio::spawn(async move {
        use tokio::io::AsyncWriteExt;
        let mut framed = (u32::try_from(req.len()).unwrap().to_be_bytes()).to_vec();
        framed.extend_from_slice(&req);
        let _ = client.write_all(&framed).await;
        // Hold the pipe open (no read, no drop) long past the write bound.
        tokio::time::sleep(std::time::Duration::from_secs(5)).await;
        drop(client);
    });

    let done = tokio::time::timeout(
        std::time::Duration::from_secs(3),
        maknae_kernel::handle(
            server,
            "maknae://d/plane/cli".to_string(),
            501,
            true,
            emit.clone(),
            7,
            cfg,
            serde_json::json!({}),
        ),
    )
    .await;
    assert!(
        done.is_ok(),
        "handle must return within the write bound even though the peer never reads"
    );
    // Both records (admission + request) were still durably offered before the write.
    let recs = emit.records();
    assert_eq!(recs.len(), 2, "admission + request records expected");
    assert_eq!(recs[1].outcome.reason, "authorized");
    writer.abort();
}
