//! The `egress` section (#240) — where `maknaed` finds the deputy, and the
//! outer bound on a provider call.
//!
//! Two keys, both optional, both defaulted to what the packaging ships:
//! `socket_path` (the deputy's activation socket, `maknae-egress.socket`) and
//! `deadline_ms`, the kernel's outer bound on one `session.prompt` send — the
//! egress-specific deadline #172 handed to #240 by name. Before this section
//! the outer bound was `transport.read_timeout_ms`, five seconds by default,
//! which was never a provider deadline. The default matches the deputy's own
//! `CallBounds` timeout so the two ends agree; an operator with a slower
//! provider raises both. Fail-closed like `transport`: a present field is
//! range-checked, a present-but-non-map section is refused, an unknown key is
//! refused by name.

use crate::{ConfigError, Value};
use std::path::PathBuf;

/// The registered section name.
pub const EGRESS_SECTION: &str = "egress";

const DEFAULT_SOCKET_PATH: &str = "/run/maknae-egress/egress.sock";
/// Matches `bins/maknae-egress`'s `CallBounds::default().timeout`.
const DEFAULT_DEADLINE_MS: u64 = 120_000;
const DEADLINE_MS_RANGE: std::ops::RangeInclusive<i64> = 1_000..=600_000;

/// Where the deputy is, and how long one send may take.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EgressConfig {
    pub socket_path: PathBuf,
    pub deadline_ms: u64,
}

impl Default for EgressConfig {
    fn default() -> Self {
        EgressConfig {
            socket_path: PathBuf::from(DEFAULT_SOCKET_PATH),
            deadline_ms: DEFAULT_DEADLINE_MS,
        }
    }
}

fn get<'a>(v: &'a Value, key: &str) -> Option<&'a Value> {
    match v {
        Value::Map(entries) => entries.iter().find(|(k, _)| k == key).map(|(_, v)| v),
        _ => None,
    }
}

fn err(field: &str, reason: impl std::fmt::Display) -> ConfigError {
    ConfigError::InvalidEgress(format!("egress.{field}: {reason}"))
}

/// Read the `egress` section. `None` → all defaults.
pub fn egress_from_section(v: Option<&Value>) -> Result<EgressConfig, ConfigError> {
    let section = match v {
        None => return Ok(EgressConfig::default()),
        Some(section) => section,
    };
    let Value::Map(entries) = section else {
        return Err(ConfigError::InvalidEgress(
            "egress section must be a map".into(),
        ));
    };
    for (k, _) in entries {
        if k != "socket_path" && k != "deadline_ms" {
            return Err(ConfigError::InvalidEgress(format!(
                "unknown key '{k}' under 'egress' (no registered spec)"
            )));
        }
    }
    let socket_path = match get(section, "socket_path") {
        None => PathBuf::from(DEFAULT_SOCKET_PATH),
        Some(Value::Str(s)) if !s.is_empty() => PathBuf::from(s),
        Some(Value::Str(_)) => return Err(err("socket_path", "must not be empty")),
        Some(_) => return Err(err("socket_path", "must be a string")),
    };
    let deadline_ms = match get(section, "deadline_ms") {
        None => DEFAULT_DEADLINE_MS,
        Some(Value::Int(n)) if DEADLINE_MS_RANGE.contains(n) => *n as u64,
        Some(Value::Int(n)) => {
            return Err(err(
                "deadline_ms",
                format!(
                    "{n} out of range {}..={}",
                    DEADLINE_MS_RANGE.start(),
                    DEADLINE_MS_RANGE.end()
                ),
            ))
        }
        Some(_) => return Err(err("deadline_ms", "must be an integer")),
    };
    Ok(EgressConfig {
        socket_path,
        deadline_ms,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Value;

    fn sec(entries: Vec<(&str, Value)>) -> Value {
        Value::Map(
            entries
                .into_iter()
                .map(|(k, v)| (k.to_string(), v))
                .collect(),
        )
    }

    /// Absent section → the packaged defaults: the unit's socket path and a
    /// deadline that matches the deputy's own provider timeout.
    #[test]
    fn an_absent_section_is_the_packaged_defaults() {
        let c = egress_from_section(None).unwrap();
        assert_eq!(
            c.socket_path,
            PathBuf::from("/run/maknae-egress/egress.sock")
        );
        assert_eq!(c.deadline_ms, 120_000);
        assert_eq!(c, EgressConfig::default());
    }

    #[test]
    fn both_keys_are_honoured() {
        let c = egress_from_section(Some(&sec(vec![
            (
                "socket_path",
                Value::Str("/usr/local/var/run/maknae-egress/egress.sock".into()),
            ),
            ("deadline_ms", Value::Int(30_000)),
        ])))
        .unwrap();
        assert_eq!(
            c.socket_path,
            PathBuf::from("/usr/local/var/run/maknae-egress/egress.sock")
        );
        assert_eq!(c.deadline_ms, 30_000);
    }

    /// The deadline is bounded at BOTH ends, and at the bound is accepted —
    /// the measured-gap shape the transport tests record.
    #[test]
    fn the_deadline_is_bounded_and_the_bounds_are_inclusive() {
        for ok in [1_000, 600_000] {
            assert_eq!(
                egress_from_section(Some(&sec(vec![("deadline_ms", Value::Int(ok))])))
                    .unwrap()
                    .deadline_ms as i64,
                ok
            );
        }
        for bad in [999, 600_001, 0, -1] {
            let e = egress_from_section(Some(&sec(vec![("deadline_ms", Value::Int(bad))])))
                .unwrap_err()
                .to_string();
            assert!(e.contains("egress.deadline_ms"), "{bad}: {e}");
        }
    }

    /// Fail closed on every malformed shape, naming the key.
    #[test]
    fn malformed_shapes_are_refused_by_name() {
        assert!(egress_from_section(Some(&Value::Str("disabled".into()))).is_err());
        let e = egress_from_section(Some(&sec(vec![("socket_path", Value::Int(1))])))
            .unwrap_err()
            .to_string();
        assert!(e.contains("egress.socket_path"), "{e}");
        let e = egress_from_section(Some(&sec(vec![("socket_path", Value::Str("".into()))])))
            .unwrap_err()
            .to_string();
        assert!(e.contains("egress.socket_path"), "{e}");
        let e = egress_from_section(Some(&sec(vec![("deadline_ms", Value::Str("5s".into()))])))
            .unwrap_err()
            .to_string();
        assert!(e.contains("egress.deadline_ms"), "{e}");
        let e = egress_from_section(Some(&sec(vec![("mystery", Value::Bool(true))])))
            .unwrap_err()
            .to_string();
        assert!(e.contains("'mystery'"), "{e}");
    }
}
