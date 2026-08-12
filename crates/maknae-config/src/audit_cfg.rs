//! The `audit` section (Stage-3a, ADR-0019) — the audit sink config consumed by
//! `maknae-audit-append` (later task): the append-only JSONL sink path, an
//! optional external SIEM offload endpoint (AU-9(2)), and the caller-supplied
//! `au3_1` structured extension, pre-converted to `serde_json::Value` so it
//! matches `AuditRecord.au3_1` end-to-end with no run-loop conversion glue.

use crate::{ConfigError, Value};
use std::path::{Path, PathBuf};

/// The registered section name for `audit` (spec/task-brief §Interfaces).
pub const AUDIT_SECTION: &str = "audit";

/// The audit-sink configuration (ADR-0019).
#[derive(Clone, Debug)]
pub struct AuditConfig {
    pub jsonl_path: PathBuf,
    pub siem: Option<String>,
    pub au3_1: serde_json::Value,
}

fn get<'a>(v: &'a Value, key: &str) -> Option<&'a Value> {
    match v {
        Value::Map(entries) => entries.iter().find(|(k, _)| k == key).map(|(_, v)| v),
        _ => None,
    }
}

fn as_str(v: &Value) -> Option<&str> {
    match v {
        Value::Str(s) => Some(s.as_str()),
        _ => None,
    }
}

/// Convert a `maknae_config::Value` tree into a `serde_json::Value` tree,
/// field-for-field. A non-finite `Float` (NaN/±inf — `serde_json::Number`
/// cannot represent these) maps to JSON `null` rather than failing, since
/// `au3_1` is an open-ended extension field, not a validated schema.
fn to_json(v: &Value) -> serde_json::Value {
    match v {
        Value::Null => serde_json::Value::Null,
        Value::Bool(b) => serde_json::Value::Bool(*b),
        Value::Int(n) => serde_json::Value::Number((*n).into()),
        Value::Float(f) => serde_json::Number::from_f64(*f)
            .map(serde_json::Value::Number)
            .unwrap_or(serde_json::Value::Null),
        Value::Str(s) => serde_json::Value::String(s.clone()),
        Value::Seq(items) => serde_json::Value::Array(items.iter().map(to_json).collect()),
        Value::Map(entries) => serde_json::Value::Object(
            entries
                .iter()
                .map(|(k, v)| (k.clone(), to_json(v)))
                .collect(),
        ),
    }
}

/// Read the `audit` section (ADR-0019, spec/task-brief §Interfaces, spec §11).
/// `None` (section ABSENT) → `Err(ConfigError::MissingSection)`: an always-written
/// section (enroll writes it explicitly, per §4.6) plus packaging make this
/// satisfiable, so a host lacking it fails closed loudly at parse rather than
/// landing the sink's default path inside `/etc/maknae` (unwritable by `_maknae`
/// per §4.6 — first boot would otherwise fail closed anyway, just later and less
/// legibly, at `AuditSink::open`). A present-but-non-map section (e.g.
/// `audit: disabled`) is rejected (`ConfigError::InvalidAudit`) rather than
/// silently falling through to all defaults (codex round-6 P2 — mirrors
/// `transport`'s guard). Within a present MAP section, a per-field wrong shape
/// (e.g. a non-string `jsonl_path`) still defaults that ONE field rather than
/// refusing the whole section — this is deliberate, not an asymmetry to fix: a
/// present-but-mistyped field still resolves to `runtime_dir/audit.jsonl`, and
/// THAT path is then independently fail-closed-checked later at sink-open (the
/// §4.6 mode/owner/MAC-append-not-create checks) — only an ABSENT section is
/// caught here, at parse.
pub fn audit_from_section(
    v: Option<&Value>,
    runtime_dir: &Path,
) -> Result<AuditConfig, ConfigError> {
    let default_jsonl_path = runtime_dir.join("audit.jsonl");
    let section = match v {
        None => {
            return Err(ConfigError::MissingSection {
                section: AUDIT_SECTION.to_string(),
            })
        }
        Some(section) => section,
    };
    if !matches!(section, Value::Map(_)) {
        return Err(ConfigError::InvalidAudit(
            "audit section must be a map".into(),
        ));
    }

    let jsonl_path = get(section, "jsonl_path")
        .and_then(as_str)
        .map(PathBuf::from)
        .unwrap_or(default_jsonl_path);
    let siem = get(section, "siem").and_then(as_str).map(String::from);
    let au3_1 = get(section, "au3_1")
        .map(to_json)
        .unwrap_or_else(|| serde_json::Value::Object(serde_json::Map::new()));

    Ok(AuditConfig {
        jsonl_path,
        siem,
        au3_1,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rt() -> PathBuf {
        PathBuf::from("/var/lib/maknae")
    }

    #[test]
    fn absent_audit_section_fails_closed() {
        // spec §11 / round-1 C12: an ABSENT `audit` section must refuse to load
        // rather than silently default into the (possibly-unwritable) config dir.
        match audit_from_section(None, &rt()) {
            Err(ConfigError::MissingSection { section }) => {
                assert_eq!(section, AUDIT_SECTION);
            }
            other => panic!("expected Err(MissingSection), got {other:?}"),
        }
    }

    #[test]
    fn defaults_when_section_present_but_empty() {
        let v = Value::Map(vec![]);
        let c = audit_from_section(Some(&v), &rt()).unwrap();
        assert_eq!(c.jsonl_path, PathBuf::from("/var/lib/maknae/audit.jsonl"));
        assert_eq!(c.siem, None);
        assert_eq!(c.au3_1, serde_json::json!({}));
    }

    #[test]
    fn rejects_non_map_scalar_section() {
        let v = Value::Str("disabled".into());
        assert!(matches!(
            audit_from_section(Some(&v), &rt()),
            Err(ConfigError::InvalidAudit(_))
        ));
    }

    #[test]
    fn rejects_non_map_seq_section() {
        let v = Value::Seq(vec![Value::Str("a".into())]);
        assert!(matches!(
            audit_from_section(Some(&v), &rt()),
            Err(ConfigError::InvalidAudit(_))
        ));
    }

    #[test]
    fn jsonl_path_override_respected() {
        let v = Value::Map(vec![(
            "jsonl_path".into(),
            Value::Str("/var/log/maknae/audit.jsonl".into()),
        )]);
        let c = audit_from_section(Some(&v), &rt()).unwrap();
        assert_eq!(c.jsonl_path, PathBuf::from("/var/log/maknae/audit.jsonl"));
    }

    #[test]
    fn siem_parsed_when_present() {
        let v = Value::Map(vec![(
            "siem".into(),
            Value::Str("https://siem.example.mil:8443/ingest".into()),
        )]);
        let c = audit_from_section(Some(&v), &rt()).unwrap();
        assert_eq!(
            c.siem,
            Some("https://siem.example.mil:8443/ingest".to_string())
        );
    }

    #[test]
    fn wrong_type_jsonl_path_falls_back_to_default() {
        let v = Value::Map(vec![("jsonl_path".into(), Value::Int(1))]);
        let c = audit_from_section(Some(&v), &rt()).unwrap();
        assert_eq!(c.jsonl_path, PathBuf::from("/var/lib/maknae/audit.jsonl"));
    }

    #[test]
    fn wrong_type_siem_is_none() {
        let v = Value::Map(vec![("siem".into(), Value::Bool(true))]);
        let c = audit_from_section(Some(&v), &rt()).unwrap();
        assert_eq!(c.siem, None);
    }

    #[test]
    fn au3_1_defaults_to_empty_map_when_absent() {
        let v = Value::Map(vec![("siem".into(), Value::Str("x".into()))]);
        let c = audit_from_section(Some(&v), &rt()).unwrap();
        assert_eq!(c.au3_1, serde_json::json!({}));
    }

    #[test]
    fn au3_1_scalars_convert() {
        for (input, want) in [
            (Value::Null, serde_json::json!(null)),
            (Value::Bool(true), serde_json::json!(true)),
            (Value::Int(-7), serde_json::json!(-7)),
            (Value::Str("hi".into()), serde_json::json!("hi")),
        ] {
            let v = Value::Map(vec![("au3_1".into(), input)]);
            let c = audit_from_section(Some(&v), &rt()).unwrap();
            assert_eq!(c.au3_1, want);
        }
    }

    #[test]
    fn au3_1_float_converts() {
        let v = Value::Map(vec![("au3_1".into(), Value::Float(2.5))]);
        let c = audit_from_section(Some(&v), &rt()).unwrap();
        assert_eq!(c.au3_1, serde_json::json!(2.5));
    }

    #[test]
    fn au3_1_non_finite_float_becomes_null() {
        let v = Value::Map(vec![("au3_1".into(), Value::Float(f64::NAN))]);
        let c = audit_from_section(Some(&v), &rt()).unwrap();
        assert_eq!(c.au3_1, serde_json::json!(null));
    }

    #[test]
    fn au3_1_nested_seq_and_map_convert() {
        let v = Value::Map(vec![(
            "au3_1".into(),
            Value::Map(vec![
                ("actor".into(), Value::Str("cn=svc-maknae".into())),
                (
                    "tags".into(),
                    Value::Seq(vec![Value::Str("AU-3(1)".into()), Value::Int(1)]),
                ),
            ]),
        )]);
        let c = audit_from_section(Some(&v), &rt()).unwrap();
        assert_eq!(
            c.au3_1,
            serde_json::json!({"actor": "cn=svc-maknae", "tags": ["AU-3(1)", 1]})
        );
    }
}
