//! AU-5 fail-closed integration coverage for `AuditSink` (ADR-0019, task-3
//! brief Step 7): the daemon must refuse to start if the primary JSONL sink
//! cannot be opened, and a successful append must produce exactly one
//! well-formed JSONL line, durably flushed.
use maknae_audit_append::{AuditRecord, Integrity, Outcome, Source, Subject, Where};

fn sample_record() -> AuditRecord {
    AuditRecord {
        ts: "2026-08-11T00:00:00.000Z".into(),
        event: "connection.accept".into(),
        where_: Where {
            host: "maknaed-01".into(),
            component: "kernel".into(),
            socket: "/run/maknae/plane.sock".into(),
        },
        source: Source {
            uid: 1000,
            gid: Some(1000),
            pid: Some(4242),
            plane_uri_san: Some("urn:maknae:plane:cli".into()),
        },
        subject: Subject {
            user: Some("aackerman".into()),
            plane_uri_san: Some("urn:maknae:plane:cli".into()),
        },
        action: "connect".into(),
        outcome: Outcome {
            result: "permit".into(),
            reason: "group membership: maknae-ops".into(),
            posture: "authorized".into(),
        },
        session_id: 42,
        seq: 1,
        au3_1: serde_json::json!({}),
        integrity: Integrity {
            prev_hash: None,
            sig: None,
        },
    }
}

#[tokio::test]
async fn open_fails_closed_on_unwritable_dir() {
    let cfg = maknae_config::AuditConfig {
        jsonl_path: "/nonexistent-root-xyz/audit.jsonl".into(),
        siem: None,
        au3_1: serde_json::json!({}),
    };
    assert!(maknae_audit_append::AuditSink::open(&cfg).is_err());
}

#[tokio::test]
async fn append_writes_one_jsonl_line_then_flushes() {
    let dir = tempfile::tempdir().unwrap();
    let cfg = maknae_config::AuditConfig {
        jsonl_path: dir.path().join("audit.jsonl"),
        siem: None,
        au3_1: serde_json::json!({}),
    };
    let sink = maknae_audit_append::AuditSink::open(&cfg).unwrap();
    sink.append(&sample_record()).await.unwrap();
    let contents = std::fs::read_to_string(dir.path().join("audit.jsonl")).unwrap();
    assert_eq!(contents.lines().count(), 1);
}
