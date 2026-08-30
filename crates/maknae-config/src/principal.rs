//! The `principal` section (PR-J1 Task 5) — the enrolled operator identity
//! (`name`/`uid`/`home`) that `maknae enroll` writes into `/etc/maknae/maknae.yaml`.
//!
//! The daemon runs as `_maknae`, not the operator, and ADR-0018 removed the old
//! single-operator record — so a later task's capability-grant policy needs an explicit
//! referent for `~` (the enrolled operator's home). This section supplies it.
//!
//! Fail-closed, but NOT the `transport`/`audit` shape: those sections default
//! every field when absent-or-partial. `principal` has no safe default identity
//! to fall back to, so **absent → `Ok(None)`** (no principal configured; callers
//! that need one — the capability-grant policy — fail closed themselves when they find `None`),
//! while **present-but-malformed → `Err`** and never collapses to `Ok(None)` — a
//! malformed section must never be silently treated as "no principal enrolled".

use crate::{ConfigError, Value};
use std::path::PathBuf;

/// The registered section name for `principal` (spec §7/§5.5).
pub const PRINCIPAL_SECTION: &str = "principal";

/// The enrolled operator identity written by `maknae enroll`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Principal {
    pub name: String,
    pub uid: u32,
    pub home: PathBuf,
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

/// Read the `principal` section (spec §7/§5.5). `None` (the section is
/// absent) → `Ok(None)` — no principal enrolled yet (pre-`enroll`, or a
/// pre-Jackrabbit config). A present section is fail-closed: it must be a
/// map with a non-empty string `name`, an integer `uid` in `0..=u32::MAX`,
/// and a non-empty, ABSOLUTE `home` path — any violation is
/// `Err(InvalidPrincipal)`, never silently downgraded to `Ok(None)`.
pub fn principal_from_section(v: Option<&Value>) -> Result<Option<Principal>, ConfigError> {
    let section = match v {
        None => return Ok(None),
        Some(section) => section,
    };
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

    let home_str = get(section, "home")
        .and_then(as_str)
        .ok_or_else(|| err("home", "missing or not a string"))?;
    if home_str.is_empty() {
        return Err(err("home", "must not be empty"));
    }
    let home = PathBuf::from(home_str);
    if !home.is_absolute() {
        return Err(err("home", "must be an absolute path"));
    }

    Ok(Some(Principal {
        name: name.to_string(),
        uid,
        home,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn valid_map() -> Value {
        Value::Map(vec![
            ("name".into(), Value::Str("alice".into())),
            ("uid".into(), Value::Int(1000)),
            ("home".into(), Value::Str("/Users/alice".into())),
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
        assert_eq!(p.home, PathBuf::from("/Users/alice"));
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
        let v = Value::Map(vec![
            ("uid".into(), Value::Int(1000)),
            ("home".into(), Value::Str("/home/a".into())),
        ]);
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
            ("home".into(), Value::Str("/home/a".into())),
        ]);
        assert!(matches!(
            principal_from_section(Some(&v)),
            Err(ConfigError::InvalidPrincipal(_))
        ));
    }

    #[test]
    fn missing_uid_errs() {
        let v = Value::Map(vec![
            ("name".into(), Value::Str("a".into())),
            ("home".into(), Value::Str("/home/a".into())),
        ]);
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
            ("home".into(), Value::Str("/home/a".into())),
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
            ("home".into(), Value::Str("/home/a".into())),
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
            ("home".into(), Value::Str("/home/a".into())),
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
            ("home".into(), Value::Str("/root".into())),
        ]);
        let p = principal_from_section(Some(&v)).unwrap().unwrap();
        assert_eq!(p.uid, 0);
    }

    #[test]
    fn uid_max_u32_is_accepted() {
        let v = Value::Map(vec![
            ("name".into(), Value::Str("a".into())),
            ("uid".into(), Value::Int(i64::from(u32::MAX))),
            ("home".into(), Value::Str("/home/a".into())),
        ]);
        let p = principal_from_section(Some(&v)).unwrap().unwrap();
        assert_eq!(p.uid, u32::MAX);
    }

    #[test]
    fn missing_home_errs() {
        let v = Value::Map(vec![
            ("name".into(), Value::Str("a".into())),
            ("uid".into(), Value::Int(1000)),
        ]);
        assert!(matches!(
            principal_from_section(Some(&v)),
            Err(ConfigError::InvalidPrincipal(_))
        ));
    }

    #[test]
    fn empty_home_errs() {
        let v = Value::Map(vec![
            ("name".into(), Value::Str("a".into())),
            ("uid".into(), Value::Int(1000)),
            ("home".into(), Value::Str("".into())),
        ]);
        assert!(matches!(
            principal_from_section(Some(&v)),
            Err(ConfigError::InvalidPrincipal(_))
        ));
    }

    #[test]
    fn relative_home_errs() {
        let v = Value::Map(vec![
            ("name".into(), Value::Str("a".into())),
            ("uid".into(), Value::Int(1000)),
            ("home".into(), Value::Str("relative/path".into())),
        ]);
        assert!(matches!(
            principal_from_section(Some(&v)),
            Err(ConfigError::InvalidPrincipal(_))
        ));
    }

    #[test]
    fn non_string_home_errs() {
        let v = Value::Map(vec![
            ("name".into(), Value::Str("a".into())),
            ("uid".into(), Value::Int(1000)),
            ("home".into(), Value::Int(1)),
        ]);
        assert!(matches!(
            principal_from_section(Some(&v)),
            Err(ConfigError::InvalidPrincipal(_))
        ));
    }

    #[test]
    fn non_string_name_errs() {
        let v = Value::Map(vec![
            ("name".into(), Value::Int(1)),
            ("uid".into(), Value::Int(1000)),
            ("home".into(), Value::Str("/home/a".into())),
        ]);
        assert!(matches!(
            principal_from_section(Some(&v)),
            Err(ConfigError::InvalidPrincipal(_))
        ));
    }
}
