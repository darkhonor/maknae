//! ADR-0019 audit record schema: the six mandatory AU-3 elements + AU-3(1)
//! additional info + AU-12(1) correlation, plus a reserved `integrity`
//! envelope so ADR-0007 signing bolts on without a format break.
//!
//! T1 (`coverage-tiers.toml`): a mis-canonicalized record (wrong key, wrong
//! order, non-determinism) silently degrades AU-9(3)-readiness — the
//! canonicalization must be exhaustively pinned.
use crate::error::AuditError;
use serde::{Deserialize, Serialize};

/// AU-3d: the connecting peer — kernel-verified uid/gid/pid + plane identity.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Source {
    pub uid: u32,
    pub gid: Option<u32>,
    pub pid: Option<u32>,
    pub plane_uri_san: Option<String>,
}

/// AU-3f: the resolvable acting identity (group-based authz per ADR-0018 —
/// `user` is the specific member, satisfying AU-3(1)'s group-account intent).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Subject {
    /// The peer's OS username, resolved from the peer uid (#275). Bounded at
    /// `MAX_SUBJECT_USER_BYTES`; an over-long name is refused to `None` rather
    /// than truncated, because a truncated identity in an audit trail is a
    /// WRONG identity, which is worse than an absent one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub user: Option<String>,
    /// The role the decision was MADE ON (#275) — never a second resolution.
    /// `None` when the PDP resolved no role, or on records that carry no
    /// decision at all (the connection and boot pseudo-actions).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub role: Option<String>,
    pub plane_uri_san: Option<String>,
}

/// AU-3c: where the event occurred.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Where {
    pub host: String,
    pub component: String,
    pub socket: String,
}

/// AU-3e: the result, the access-control rule invoked (AU-3(1)), and the
/// resulting posture.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Outcome {
    pub result: String,
    pub reason: String,
    pub posture: String,
}

/// Reserved for ADR-0007 (deferred): a hash-chain link and/or signature.
/// Present-and-empty on every Stage-3a record (both fields `None`) —
/// round-trips today, populated once ADR-0007 lands, no format break.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Integrity {
    pub prev_hash: Option<String>,
    pub sig: Option<String>,
}

/// `IntentOnly` proves nothing was sent yet; `BackendUnavailable` is the Cooky
/// refusal recorded WITHOUT an intent (nothing was sent); `Failed` is a send
/// the backend reported as failed; `DeadlineExpired` is a send that ran past
/// the transport deadline, so whether it reached the provider is UNKNOWN (the
/// mutation trail's `DurabilityUnknown` shape); `LandedUndelivered` keeps
/// ADR-0023 decision 3's meaning: the egress went out, the reply arrived, and
/// it never reached the loop. In #172 the kernel itself refuses delivery for
/// three reasons, each named in `reason`: over the frame cap (`TooLarge` on
/// the wire), carrying a block kind this deployment does not admit, or empty
/// (both `Unauthorized`). A response-write timeout or a closed connection is
/// not detected on any verb yet and is #240's.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum EgressStatus {
    IntentOnly,
    Sent,
    Failed,
    DeadlineExpired,
    LandedUndelivered,
    BackendUnavailable,
}

/// What the trail holds about one egress (#172). Deliberately minimal: the
/// macOS unified-log mirror drops lines over `MACOS_SYSLOG_MAX`, and every
/// field here was measured against that cap. The destination is the record's
/// `object`; the ceiling is the boot record's; the phase is `status`.
/// `content_digest` is the first 32 hex characters (128 bits) of the SHA-256
/// of the concatenated text blocks: an identifier for matching, not an
/// integrity control (the cap is why it is not the full 64).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct EgressAudit {
    pub status: EgressStatus,
    pub content_length: u64,
    pub content_digest: String,
    pub conversation: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reply_length: Option<u64>,
}

impl EgressAudit {
    pub fn is_intent(&self) -> bool {
        self.status == EgressStatus::IntentOnly
    }
}

/// Provenance of mutation facts; a validated report is still a client claim.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum MutationOrigin {
    KernelObserved,
    ClientReported,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum MutationPhase {
    Intent,
    Progress,
    Completion,
}
/// Authorization and effects are independent. IntentOnly proves no execution.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum MutationStatus {
    IntentOnly,
    Applied,
    NoEffect,
    Partial,
    DurabilityUnknown,
    Incomplete,
    ReportedProgress,
    ReportedSuccess,
    ReportedOsRefused,
    ReportedPartial,
    ReportedLimitReached,
    ReportedPathChanged,
    ReportedUnsupportedName,
    ReportedDurabilityUnknown,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum MutationEffectKind {
    CreatedFile,
    ReplacedFile,
    CreatedDirectory,
    DeletedEntry,
}
/// Immutable prepared operation; distinguishes subtree authorization from one entry.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum MutationOperation {
    WriteExisting,
    WriteCreate,
    DeleteEntry,
    DeleteTree,
    Mkdir,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct MutationEffectRecord {
    pub path: String,
    pub effect: MutationEffectKind,
}
/// Trusted schema outside the deployer's free-form AU-3(1) extension. Session ID
/// lives on AuditRecord; intent_seq correlates every phase within that session.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct MutationAudit {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub operation: Option<MutationOperation>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub authorized_paths: Vec<String>,
    pub intent_seq: u64,
    pub phase: MutationPhase,
    pub origin: MutationOrigin,
    pub status: MutationStatus,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub content_length: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub first_index: Option<u32>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub effects: Vec<MutationEffectRecord>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub stopped_at: Option<String>,
}

/// The full AU-3/AU-3(1)-complete audit record (ADR-0019 Decision 1).
///
/// `where_` carries `#[serde(rename = "where")]`: `where` is a Rust keyword
/// and cannot be a field identifier, but the emitted JSON key MUST be
/// `where` verbatim (AU-3c) — downstream SIEM ingestion depends on the exact
/// key name, not Rust's spelling workaround.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AuditRecord {
    pub ts: String,
    pub event: String,
    #[serde(rename = "where")]
    pub where_: Where,
    pub source: Source,
    pub subject: Subject,
    pub action: String,
    /// AU-3 "objects involved" (#77 / ADR-0019 amendment): the canonical
    /// decided resource path for resource-bearing verbs (`fs.read`);
    /// absent for resource-free verbs (Ping/Whoami) — additive for them.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub object: Option<String>,
    /// What the CLIENT asked for, recorded **only when it differs from `object`**
    /// (ADR-0009 decision 6).
    ///
    /// The two can legitimately differ: the decision is made on the kernel-reported
    /// path of the subject's delegated descriptor, so a client naming `~/innocent`
    /// has `~/.ssh/id_rsa` evaluated when that is what the descriptor points at. A
    /// trail carrying only one of them cannot be reconstructed.
    ///
    /// **Absent in the ordinary case, so its PRESENCE is the signal.** A client that
    /// names one object while a different one is evaluated is either following a
    /// symlink it did not know about or probing for one — and either way that is the
    /// divergence a reviewer, or a future detection rule, wants to key on. Diluting
    /// it by emitting it always would destroy exactly that property.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub object_requested: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mutation: Option<MutationAudit>,
    /// The egress block of a `session.prompt` record (#172); absent on every
    /// other record and on a prompt refused before any send was considered.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub egress: Option<EgressAudit>,
    pub outcome: Outcome,
    pub session_id: u64,
    pub seq: u64,
    pub au3_1: serde_json::Value,
    pub integrity: Integrity,
}

/// Deterministic canonical JSON for `rec`: every object's keys are emitted in
/// sorted order (recursively, including nested `au3_1` extension content),
/// array element order is preserved. Determinism is what lets ADR-0007 hang a
/// hash-chain/signature off this exact byte sequence later.
///
/// Implementation note: we serialize through `serde_json::Value` and walk it
/// with our own writer rather than relying on `serde_json::to_string`'s
/// current default key order. `serde_json::Map` happens to sort keys today
/// (it's a `BTreeMap` unless the `preserve_order` feature is enabled), but
/// that is an implementation detail of a transitive dependency graph we do
/// not fully control — a sibling crate enabling `preserve_order` would
/// silently flip it to insertion order. Sorting explicitly here is robust
/// against that.
pub fn canonical_json(rec: &AuditRecord) -> Result<String, AuditError> {
    let value = serde_json::to_value(rec).map_err(|e| AuditError::Serialize(e.to_string()))?;
    let mut out = String::new();
    write_canonical(&value, &mut out);
    Ok(out)
}

fn write_canonical(v: &serde_json::Value, out: &mut String) {
    match v {
        serde_json::Value::Null => out.push_str("null"),
        serde_json::Value::Bool(b) => out.push_str(if *b { "true" } else { "false" }),
        serde_json::Value::Number(n) => out.push_str(&n.to_string()),
        serde_json::Value::String(s) => {
            // serde_json's string serializer is infallible for a `String`
            // target (no I/O, no non-representable input).
            out.push_str(&serde_json::to_string(s).expect("string serialization is infallible"));
        }
        serde_json::Value::Array(items) => {
            out.push('[');
            for (i, item) in items.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                write_canonical(item, out);
            }
            out.push(']');
        }
        serde_json::Value::Object(map) => {
            out.push('{');
            let mut keys: Vec<&String> = map.keys().collect();
            keys.sort();
            for (i, k) in keys.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                out.push_str(
                    &serde_json::to_string(k).expect("string serialization is infallible"),
                );
                out.push(':');
                write_canonical(&map[k.as_str()], out);
            }
            out.push('}');
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> AuditRecord {
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
                user: Some("alice".into()),
                role: None,
                plane_uri_san: Some("urn:maknae:plane:cli".into()),
            },
            action: "connect".into(),
            object: None,
            object_requested: None,
            mutation: None,
            egress: None,
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

    #[test]
    fn mutation_origin_is_typed_and_independent_of_untrusted_extension() {
        let mut rec = sample();
        assert!(!canonical_json(&rec).unwrap().contains("\"mutation\""));
        rec.au3_1 = serde_json::json!({"mutation": {"origin": "KernelObserved"}});
        rec.mutation = Some(MutationAudit {
            operation: Some(MutationOperation::WriteCreate),
            authorized_paths: vec!["/sentinel".into()],
            intent_seq: 17,
            phase: MutationPhase::Completion,
            origin: MutationOrigin::ClientReported,
            status: MutationStatus::ReportedSuccess,
            content_length: None,
            first_index: Some(1),
            effects: vec![MutationEffectRecord {
                path: "/sentinel".into(),
                effect: MutationEffectKind::CreatedFile,
            }],
            stopped_at: None,
        });
        let encoded = canonical_json(&rec).unwrap();
        let decoded: AuditRecord = serde_json::from_str(&encoded).unwrap();
        assert_eq!(decoded.mutation, rec.mutation);
        assert_eq!(
            decoded.mutation.unwrap().origin,
            MutationOrigin::ClientReported
        );
        let invalid = encoded.replace("ClientReported", "VerifiedClient");
        assert!(serde_json::from_str::<AuditRecord>(&invalid).is_err());
    }

    #[test]
    fn where_serializes_as_keyword_key() {
        let s = canonical_json(&sample()).unwrap();
        assert!(
            s.contains("\"where\":"),
            "AU-3c key must be `where`, not `where_`"
        );
        assert!(!s.contains("where_"));
    }

    #[test]
    fn canonical_is_deterministic() {
        let a = canonical_json(&sample()).unwrap();
        let b = canonical_json(&sample()).unwrap();
        assert_eq!(a, b);
    }

    #[test]
    fn egress_audit_round_trips_and_is_absent_by_default() {
        let mut rec = sample();
        assert!(!serde_json::to_string(&rec).unwrap().contains("\"egress\""));
        rec.egress = Some(EgressAudit {
            status: EgressStatus::IntentOnly,
            content_length: 12,
            content_digest: "ab".repeat(16),
            conversation: "conv-1".into(),
            reply_length: None,
        });
        let s = serde_json::to_string(&rec).unwrap();
        assert!(!s.contains("reply_length"), "None is absent, not null: {s}");
        let back: AuditRecord = serde_json::from_str(&s).unwrap();
        let e = back.egress.unwrap();
        assert!(e.is_intent());
        assert_eq!(e.status, EgressStatus::IntentOnly);
        let mut sent = e.clone();
        sent.status = EgressStatus::Sent;
        assert!(!sent.is_intent());
    }

    #[test]
    fn integrity_round_trips_empty() {
        let s = canonical_json(&sample()).unwrap();
        assert!(s.contains("\"integrity\""));
        assert!(s.contains("\"integrity\":{\"prev_hash\":null,\"sig\":null}"));
    }

    #[test]
    fn integrity_round_trips_present() {
        let mut rec = sample();
        rec.integrity = Integrity {
            prev_hash: Some("deadbeef".into()),
            sig: Some("sig-bytes-b64".into()),
        };
        let s = canonical_json(&rec).unwrap();
        let back: AuditRecord = serde_json::from_str(&s).unwrap();
        assert_eq!(back.integrity.prev_hash.as_deref(), Some("deadbeef"));
        assert_eq!(back.integrity.sig.as_deref(), Some("sig-bytes-b64"));
    }

    #[test]
    fn canonical_json_sorts_top_level_keys_alphabetically() {
        // Struct declaration order is ts, event, where, source, subject,
        // action, outcome, session_id, seq, au3_1, integrity — none of
        // that. A mutant that skips the sort (emits declaration/insertion
        // order instead) must fail this.
        let s = canonical_json(&sample()).unwrap();
        let expected_order = [
            "\"action\"",
            "\"au3_1\"",
            "\"event\"",
            "\"integrity\"",
            "\"outcome\"",
            "\"seq\"",
            "\"session_id\"",
            "\"source\"",
            "\"subject\"",
            "\"ts\"",
            "\"where\"",
        ];
        let positions: Vec<usize> = expected_order
            .iter()
            .map(|k| {
                s.find(k)
                    .unwrap_or_else(|| panic!("missing key {k} in {s}"))
            })
            .collect();
        let mut sorted_positions = positions.clone();
        sorted_positions.sort();
        assert_eq!(positions, sorted_positions, "keys not in sorted order: {s}");
    }

    #[test]
    fn canonical_json_sorts_nested_au3_1_object_keys() {
        let mut rec = sample();
        rec.au3_1 = serde_json::json!({"zeta": 1, "alpha": 2, "mid": 3});
        let s = canonical_json(&rec).unwrap();
        let alpha = s.find("\"alpha\"").unwrap();
        let mid = s.find("\"mid\"").unwrap();
        let zeta = s.find("\"zeta\"").unwrap();
        assert!(
            alpha < mid && mid < zeta,
            "nested object keys not sorted: {s}"
        );
    }

    #[test]
    fn canonical_json_preserves_array_element_order() {
        let mut rec = sample();
        rec.au3_1 = serde_json::json!({"tags": ["zeta", "alpha", "mid"]});
        let s = canonical_json(&rec).unwrap();
        assert!(
            s.contains("\"tags\":[\"zeta\",\"alpha\",\"mid\"]"),
            "array element order must be preserved (not sorted): {s}"
        );
    }

    #[test]
    fn canonical_json_escapes_and_round_trips_special_characters() {
        let mut rec = sample();
        rec.outcome.reason = "quote\" backslash\\ newline\n tab\t unicode\u{2603}".into();
        let s = canonical_json(&rec).unwrap();
        let back: AuditRecord = serde_json::from_str(&s).unwrap();
        assert_eq!(back.outcome.reason, rec.outcome.reason);
    }

    #[test]
    fn canonical_json_numeric_fields_unquoted() {
        let s = canonical_json(&sample()).unwrap();
        assert!(s.contains("\"session_id\":42"), "{s}");
        assert!(s.contains("\"seq\":1"), "{s}");
    }

    #[test]
    fn canonical_json_bool_and_null_render_bare() {
        let mut rec = sample();
        rec.au3_1 = serde_json::json!({"flag": true, "absent": null});
        let s = canonical_json(&rec).unwrap();
        assert!(s.contains("\"absent\":null"), "{s}");
        assert!(s.contains("\"flag\":true"), "{s}");
    }

    #[test]
    fn clone_is_independent_of_original() {
        let rec = sample();
        let mut cloned = rec.clone();
        cloned.event = "different".into();
        assert_eq!(rec.event, "connection.accept");
        assert_eq!(cloned.event, "different");
    }
    mod object_tests {
        use super::super::*;

        fn rec(object: Option<String>) -> AuditRecord {
            AuditRecord {
                ts: "2026-08-28T00:00:00Z".into(),
                event: "request".into(),
                where_: Where {
                    host: "h".into(),
                    component: "maknaed".into(),
                    socket: "/run/s".into(),
                },
                source: Source {
                    uid: 0,
                    gid: None,
                    pid: None,
                    plane_uri_san: None,
                },
                subject: Subject {
                    user: None,
                    role: None,
                    plane_uri_san: None,
                },
                action: "fs.read".into(),
                object,
                object_requested: None,
                mutation: None,
                egress: None,
                outcome: Outcome {
                    result: "deny".into(),
                    reason: "r".into(),
                    posture: "unauthorized".into(),
                },
                session_id: 1,
                seq: 2,
                au3_1: serde_json::Value::Null,
                integrity: Integrity {
                    prev_hash: None,
                    sig: None,
                },
            }
        }

        #[test]
        fn object_present_serializes_the_key() {
            let j = canonical_json(&rec(Some("/home/op/.ssh/id_rsa".into()))).unwrap();
            assert!(j.contains("\"object\":\"/home/op/.ssh/id_rsa\""), "{j}");
        }

        #[test]
        fn object_absent_omits_the_key_entirely() {
            let j = canonical_json(&rec(None)).unwrap();
            assert!(
                !j.contains("\"object\""),
                "resource-free verbs stay additive: {j}"
            );
        }
    }
}
