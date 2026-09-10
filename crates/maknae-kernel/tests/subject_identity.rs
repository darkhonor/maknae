//! #275: the audit record carries the subject's resolved username and the role
//! the decision was MADE ON, proven through the REAL `handle()` path against the
//! real composed PDP — the compensating control for mutation-excluded `run.rs`.
mod common;
use common::{Fixture, Records};
use maknae_proto::Verb;
use std::sync::Arc;

fn last_request(records: &Records) -> maknae_audit_append::AuditRecord {
    records
        .snapshot()
        .into_iter()
        .rev()
        .find(|r| r.event == "request")
        .expect("a request record")
}

/// The record's role is the role the PDP actually decided on — for every one of
/// the four shipped roles, driven through the real composition.
#[tokio::test]
async fn the_record_carries_the_role_the_decision_was_made_on_for_every_shipped_role() {
    for role in ["admin", "user", "guest", "adversary"] {
        let fx = Fixture::with_policy_bound_to(&format!("role_{role}"), "Read", role, "");
        let records = Records::new(0);
        let _ = fx
            .roundtrip(
                Verb::Ping,
                Arc::clone(&records),
                None,
                Arc::new(maknae_kernel::Unavailable),
            )
            .await;
        let rec = last_request(&records);
        assert_eq!(
            rec.subject.role.as_deref(),
            Some(role),
            "the record must attest the role the decision was made on"
        );
    }
}

/// #275 (codex C1): the EGRESS records carry the role too. The backend-refusal
/// record and the write-ahead intent are permitted decisions, and the outcome
/// record is derived from the intent by clone — so an omission on the intent
/// propagates to both halves of the write-ahead pair and every prompt in the
/// trail reads `role=none`.
#[tokio::test]
async fn the_egress_refusal_record_carries_the_decided_role() {
    const GRANTED: &str = "roles:\n  user:\n    allow: [\"session.prompt\"]\ndestinations:\n  user:\n    allow: [\"provider:openai\"]\n";
    let fx = Fixture::with_policy("prompt-role", "Read", GRANTED);
    let records = Records::new(0);
    let _ = fx
        .roundtrip(
            Verb::SessionPrompt {
                conversation: "conv-1".into(),
                content: vec![maknae_proto::ContentBlock::Text {
                    text: maknae_proto::SecretText(maknae_io::Zeroizing::new("hi".into())),
                }],
            },
            Arc::clone(&records),
            Some("openai"),
            Arc::new(maknae_kernel::Unavailable),
        )
        .await;
    let rec = records
        .snapshot()
        .into_iter()
        .rev()
        .find(|r| r.action == "session.prompt")
        .expect("a session.prompt record");
    assert_eq!(
        rec.subject.role.as_deref(),
        Some("user"),
        "a permitted prompt must attest the role it was decided under"
    );
}

/// A record with no decision behind it carries no role, and renders the NAMED
/// absence rather than borrowing the subject's `unknown`.
#[tokio::test]
async fn a_record_without_a_decision_carries_no_role() {
    let fx = Fixture::with_policy("norole", "Read", "");
    let records = Records::new(0);
    let _ = fx
        .roundtrip(
            Verb::Ping,
            Arc::clone(&records),
            None,
            Arc::new(maknae_kernel::Unavailable),
        )
        .await;
    let conn = records
        .snapshot()
        .into_iter()
        .find(|r| r.event == "connection")
        .expect("a connection record");
    assert_eq!(conn.subject.role, None, "a connection is not a decision");
}

/// An over-long username is REFUSED to `None`, never truncated: a truncated
/// identity in an audit trail is a wrong identity, which is worse than none.
///
/// Drives the REAL admission function over the boundary. An earlier form
/// asserted only that the constant equals 32, which a removed filter or a
/// switch to truncation would both have survived (codex).
#[test]
fn an_over_long_username_is_refused_and_the_boundary_is_exact() {
    let at = "u".repeat(maknae_kernel::MAX_SUBJECT_USER_BYTES);
    let over = "u".repeat(maknae_kernel::MAX_SUBJECT_USER_BYTES + 1);
    assert_eq!(
        maknae_kernel::admitted_user_for_test(Some(&at)).as_deref(),
        Some(at.as_str()),
        "exactly at the bound must be admitted UNCHANGED"
    );
    assert_eq!(
        maknae_kernel::admitted_user_for_test(Some(&over)),
        None,
        "over the bound must be REFUSED, never truncated"
    );
    // Multi-byte: 11 three-byte characters = 33 bytes, over the bound. The
    // check is on BYTES, and refusing avoids ever clipping mid-codepoint.
    let multi = "한".repeat(11);
    assert_eq!(multi.len(), 33);
    assert_eq!(maknae_kernel::admitted_user_for_test(Some(&multi)), None);
    let fits = "한".repeat(10);
    assert_eq!(fits.len(), 30);
    assert_eq!(
        maknae_kernel::admitted_user_for_test(Some(&fits)).as_deref(),
        Some(fits.as_str())
    );
    assert_eq!(maknae_kernel::admitted_user_for_test(None), None);
}
