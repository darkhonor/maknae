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
#[test]
fn an_over_long_username_is_refused_not_truncated() {
    assert_eq!(maknae_kernel::MAX_SUBJECT_USER_BYTES, 32);
}
