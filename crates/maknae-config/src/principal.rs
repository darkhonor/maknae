//! The `principal` section (PR-J1 Task 5) — the enrolled operator identity
//! (`name`/`uid`) that `maknae enroll` writes into `/etc/maknae/maknae.yaml`.
//!
//! The daemon runs as `_maknae`, not the operator, and ADR-0018 removed the old
//! single-operator record. `uid` is the default-admin subject.
//!
//! Fail-closed, but NOT the `transport`/`audit` shape: those sections default
//! every field when absent-or-partial. `principal` has no safe default identity
//! to fall back to, so **absent → `Ok(None)`** (no principal configured; callers
//! that need one — the authz boot gate, for `uid` — fail closed themselves when they find `None`),
//! while **present-but-malformed → `Err`** and never collapses to `Ok(None)` — a
//! malformed section must never be silently treated as "no principal enrolled".

use crate::{ConfigError, Value};

/// The registered section name for `principal` (spec §7/§5.5).
pub const PRINCIPAL_SECTION: &str = "principal";

/// #210: the keys this section's parser reads — the closed vocabulary.
pub(crate) const PRINCIPAL_KEYS: [&str; 2] = ["name", "uid"];

/// The enrolled operator identity written by `maknae enroll`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Principal {
    pub name: String,
    pub uid: u32,
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

/// A local `u32` accessor (this crate's own precedent — `audit_cfg.rs`'s
/// `get`/`as_str` pair — not `maknae-vault`'s `config.rs::get_str`, a
/// different crate). Rejects non-integers and out-of-`u32`-range integers
/// (negative or > `u32::MAX`) rather than truncating/wrapping.
fn as_u32(v: &Value) -> Option<u32> {
    match v {
        Value::Int(n) => u32::try_from(*n).ok(),
        _ => None,
    }
}

fn err(field: &str, reason: impl std::fmt::Display) -> ConfigError {
    ConfigError::InvalidPrincipal(format!("principal.{field}: {reason}"))
}

/// The closed-key check alone, for a shadowed `config.d/` contribution: whole-section
/// replacement means its required fields are never read, but an unknown key still refuses.
pub fn principal_keys_known(section: &Value) -> Result<(), ConfigError> {
    match section {
        Value::Map(entries) => {
            crate::reject_unknown_keys(PRINCIPAL_SECTION, entries, &PRINCIPAL_KEYS)
        }
        _ => Ok(()),
    }
}

/// Read the `principal` section (spec §7/§5.5). `None` (the section is
/// absent) → `Ok(None)` — no principal enrolled yet (pre-`enroll`, or a
/// pre-Jackrabbit config). A present section is fail-closed: it must be a
/// map with a non-empty string `name` and an integer `uid` in `0..=u32::MAX`
/// — any violation is `Err(InvalidPrincipal)`, never silently downgraded to
/// `Ok(None)`.
pub fn principal_from_section(v: Option<&Value>) -> Result<Option<Principal>, ConfigError> {
    let section = match v {
        None => return Ok(None),
        Some(section) => section,
    };
    // #210: closed vocabulary — every key below is one this function reads.
    principal_keys_known(section)?;
    if !matches!(section, Value::Map(_)) {
        return Err(ConfigError::InvalidPrincipal(
            "principal section must be a map".into(),
        ));
    }

    let name = get(section, "name")
        .and_then(as_str)
        .ok_or_else(|| err("name", "missing or not a string"))?;
    if name.is_empty() {
        return Err(err("name", "must not be empty"));
    }

    let uid = get(section, "uid")
        .ok_or_else(|| err("uid", "missing"))
        .and_then(|v| as_u32(v).ok_or_else(|| err("uid", "must be an integer in 0..=u32::MAX")))?;

    Ok(Some(Principal {
        name: name.to_string(),
        uid,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn valid_map() -> Value {
        Value::Map(vec![
            ("name".into(), Value::Str("alice".into())),
            ("uid".into(), Value::Int(1000)),
        ])
    }

    #[test]
    fn absent_is_ok_none() {
        assert_eq!(principal_from_section(None), Ok(None));
    }

    #[test]
    fn fully_valid_parses() {
        let v = valid_map();
        let p = principal_from_section(Some(&v)).unwrap().unwrap();
        assert_eq!(p.name, "alice");
        assert_eq!(p.uid, 1000);
    }

    #[test]
    fn rejects_non_map_scalar_section() {
        let v = Value::Str("nope".into());
        assert!(matches!(
            principal_from_section(Some(&v)),
            Err(ConfigError::InvalidPrincipal(_))
        ));
    }

    #[test]
    fn rejects_non_map_seq_section() {
        let v = Value::Seq(vec![Value::Str("a".into())]);
        assert!(matches!(
            principal_from_section(Some(&v)),
            Err(ConfigError::InvalidPrincipal(_))
        ));
    }

    #[test]
    fn missing_name_errs() {
        let v = Value::Map(vec![("uid".into(), Value::Int(1000))]);
        assert!(matches!(
            principal_from_section(Some(&v)),
            Err(ConfigError::InvalidPrincipal(_))
        ));
    }

    #[test]
    fn empty_name_errs() {
        let v = Value::Map(vec![
            ("name".into(), Value::Str("".into())),
            ("uid".into(), Value::Int(1000)),
        ]);
        assert!(matches!(
            principal_from_section(Some(&v)),
            Err(ConfigError::InvalidPrincipal(_))
        ));
    }

    #[test]
    fn missing_uid_errs() {
        let v = Value::Map(vec![("name".into(), Value::Str("a".into()))]);
        assert!(matches!(
            principal_from_section(Some(&v)),
            Err(ConfigError::InvalidPrincipal(_))
        ));
    }

    #[test]
    fn non_integer_uid_errs() {
        let v = Value::Map(vec![
            ("name".into(), Value::Str("a".into())),
            ("uid".into(), Value::Str("1000".into())),
        ]);
        assert!(matches!(
            principal_from_section(Some(&v)),
            Err(ConfigError::InvalidPrincipal(_))
        ));
    }

    #[test]
    fn negative_uid_errs() {
        let v = Value::Map(vec![
            ("name".into(), Value::Str("a".into())),
            ("uid".into(), Value::Int(-1)),
        ]);
        assert!(matches!(
            principal_from_section(Some(&v)),
            Err(ConfigError::InvalidPrincipal(_))
        ));
    }

    #[test]
    fn overflow_uid_errs() {
        // u32::MAX + 1, well within i64 range but out of u32 range.
        let v = Value::Map(vec![
            ("name".into(), Value::Str("a".into())),
            ("uid".into(), Value::Int(i64::from(u32::MAX) + 1)),
        ]);
        assert!(matches!(
            principal_from_section(Some(&v)),
            Err(ConfigError::InvalidPrincipal(_))
        ));
    }

    #[test]
    fn uid_zero_is_accepted() {
        // 0 is a legitimate uid (root); the guard is int-and-in-range, not "positive".
        let v = Value::Map(vec![
            ("name".into(), Value::Str("root".into())),
            ("uid".into(), Value::Int(0)),
        ]);
        let p = principal_from_section(Some(&v)).unwrap().unwrap();
        assert_eq!(p.uid, 0);
    }

    #[test]
    fn uid_max_u32_is_accepted() {
        let v = Value::Map(vec![
            ("name".into(), Value::Str("a".into())),
            ("uid".into(), Value::Int(i64::from(u32::MAX))),
        ]);
        let p = principal_from_section(Some(&v)).unwrap().unwrap();
        assert_eq!(p.uid, u32::MAX);
    }

    #[test]
    fn non_string_name_errs() {
        let v = Value::Map(vec![
            ("name".into(), Value::Int(1)),
            ("uid".into(), Value::Int(1000)),
        ]);
        assert!(matches!(
            principal_from_section(Some(&v)),
            Err(ConfigError::InvalidPrincipal(_))
        ));
    }
    /// #210: a key this parser does not read must REFUSE, not leave its field
    /// at the default. An ignored key silently substitutes the DEFAULT for what
    /// the operator wrote — sometimes weaker, sometimes STRICTER (a raised
    /// `max_connections` falls back to 64 from a ceiling of 4096) — and either
    /// way their stated intent is discarded without a word.
    #[test]
    fn a_key_this_parser_does_not_read_refuses() {
        let v = Value::Map(vec![("hom".into(), Value::Str("x".into()))]);
        match principal_from_section(Some(&v)) {
            Err(ConfigError::UnknownKey { section, key }) => {
                assert_eq!(section, PRINCIPAL_SECTION);
                assert_eq!(key, "hom");
            }
            other => panic!("expected Err(UnknownKey), got {other:?}"),
        }
    }

    #[test]
    fn principal_keys_known_accepts_a_partial_section_and_refuses_home() {
        let partial = Value::Map(vec![("uid".into(), Value::Int(1000))]);
        assert_eq!(principal_keys_known(&partial), Ok(()));
        let with_home = Value::Map(vec![
            ("name".into(), Value::Str("alice".into())),
            ("home".into(), Value::Str("/Users/alice".into())),
        ]);
        assert_eq!(
            principal_keys_known(&with_home),
            Err(ConfigError::UnknownKey {
                section: PRINCIPAL_SECTION.into(),
                key: "home".into(),
            })
        );
    }

    #[test]
    fn a_principal_carrying_home_is_refused() {
        let v = Value::Map(vec![
            ("name".into(), Value::Str("alice".into())),
            ("uid".into(), Value::Int(1000)),
            ("home".into(), Value::Str("/Users/alice".into())),
        ]);
        match principal_from_section(Some(&v)) {
            Err(ConfigError::UnknownKey { section, key }) => {
                assert_eq!(section, PRINCIPAL_SECTION);
                assert_eq!(key, "home");
            }
            other => panic!("expected Err(UnknownKey), got {other:?}"),
        }
    }

    /// Companion: every key the parser DOES read still loads, so closing the
    /// vocabulary cannot silently reject a valid config.
    #[test]
    fn every_key_the_parser_reads_is_accepted() {
        let v = Value::Map(vec![
            ("name".into(), Value::Null),
            ("uid".into(), Value::Null),
        ]);
        let e = principal_from_section(Some(&v));
        assert!(
            !matches!(e, Err(ConfigError::UnknownKey { .. })),
            "a key the parser reads was rejected: {e:?}"
        );
    }
}
