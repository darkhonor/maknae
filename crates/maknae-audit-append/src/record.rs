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
    pub user: Option<String>,
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
                out.push_str(&serde_json::to_string(k).expect("string serialization is infallible"));
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

    #[test]
    fn where_serializes_as_keyword_key() {
        let s = canonical_json(&sample()).unwrap();
        assert!(s.contains("\"where\":"), "AU-3c key must be `where`, not `where_`");
        assert!(!s.contains("where_"));
    }

    #[test]
    fn canonical_is_deterministic() {
        let a = canonical_json(&sample()).unwrap();
        let b = canonical_json(&sample()).unwrap();
        assert_eq!(a, b);
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
            .map(|k| s.find(k).unwrap_or_else(|| panic!("missing key {k} in {s}")))
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
        assert!(alpha < mid && mid < zeta, "nested object keys not sorted: {s}");
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
}
