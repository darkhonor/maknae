//! The `transport` section (Stage-3a) — the anti-DoS caps + Unix-socket path
//! consumed by the run-loop (later task). Fail-closed: absent section/field →
//! documented default; present-and-out-of-range → [`ConfigError::InvalidTransport`].

use crate::{ConfigError, Value};
use std::path::PathBuf;

/// The registered section name for `transport` (spec/task-brief §Interfaces).
pub const TRANSPORT_SECTION: &str = "transport";

/// #210: the keys this section's parser reads — the closed vocabulary.
pub(crate) const TRANSPORT_KEYS: [&str; 5] = [
    "socket_path",
    "max_connections",
    "prompt_max_bytes",
    "handshake_timeout_ms",
    "read_timeout_ms",
];

const DEFAULT_MAX_CONNECTIONS: u32 = 64;
const DEFAULT_PROMPT_MAX_BYTES: usize = 1_048_576;
const DEFAULT_HANDSHAKE_TIMEOUT_MS: u64 = 5000;
const DEFAULT_READ_TIMEOUT_MS: u64 = 5000;
const DEFAULT_SOCKET_PATH: &str = "/run/maknae/maknaed.sock";

/// The macOS daemon's socket path.
pub const MACOS_DAEMON_SOCKET_PATH: &str = "/usr/local/var/run/maknae/maknaed.sock";

const MAX_CONNECTIONS_RANGE: std::ops::RangeInclusive<i64> = 1..=4096;
/// The smallest `prompt_max_bytes` an operator can set. Exported because the
/// tool-call argument bound is derived from it (`maknae-kernel` pins the fit).
pub const PROMPT_MAX_BYTES_FLOOR: usize = 65_536;
const PROMPT_MAX_BYTES_RANGE: std::ops::RangeInclusive<i64> =
    PROMPT_MAX_BYTES_FLOOR as i64..=16_777_216;
/// The ceiling on both transport timeouts. Named and exported because the
/// shipped units' stop timeouts are derived from it (`maknae-kernel`'s
/// shutdown-chain test evaluates the handler drain at this ceiling too).
pub const TRANSPORT_TIMEOUT_MS_MAX: u64 = 60_000;
const TIMEOUT_MS_RANGE: std::ops::RangeInclusive<i64> = 100..=TRANSPORT_TIMEOUT_MS_MAX as i64;
/// How long the daemon waits for a requester's home to resolve before a
/// filesystem verb. Shared so the CLI's attempt reply wait covers it.
pub const HOME_RESOLVE_TIMEOUT_MS: u64 = 5_000;
/// How long the daemon waits for the peer's `maknae`-group lookup (NSS,
/// possibly SSSD/LDAP) before failing closed. Shared so the client's
/// request-write bound can cover it.
pub const GROUP_LOOKUP_TIMEOUT_MS: u64 = 5_000;
/// How long the daemon waits for the admission audit append before failing
/// closed (#421). A design bound, not a measurement. Shared for the same reason.
pub const ADMISSION_AUDIT_TIMEOUT_MS: u64 = 5_000;

/// The transport-layer configuration: connection/frame caps + timeouts + the
/// Unix-domain socket path. `Clone` — the run-loop clones this per accepted
/// connection.
#[derive(Clone, Debug)]
pub struct TransportConfig {
    pub socket_path: PathBuf,
    pub max_connections: u32,
    pub prompt_max_bytes: usize,
    pub handshake_timeout_ms: u64,
    pub read_timeout_ms: u64,
}

impl Default for TransportConfig {
    fn default() -> Self {
        TransportConfig {
            socket_path: PathBuf::from(DEFAULT_SOCKET_PATH),
            max_connections: DEFAULT_MAX_CONNECTIONS,
            prompt_max_bytes: DEFAULT_PROMPT_MAX_BYTES,
            handshake_timeout_ms: DEFAULT_HANDSHAKE_TIMEOUT_MS,
            read_timeout_ms: DEFAULT_READ_TIMEOUT_MS,
        }
    }
}

fn get<'a>(v: &'a Value, key: &str) -> Option<&'a Value> {
    match v {
        Value::Map(entries) => entries.iter().find(|(k, _)| k == key).map(|(_, v)| v),
        _ => None,
    }
}

fn as_i64(v: &Value) -> Option<i64> {
    match v {
        Value::Int(n) => Some(*n),
        _ => None,
    }
}

fn as_str(v: &Value) -> Option<&str> {
    match v {
        Value::Str(s) => Some(s.as_str()),
        _ => None,
    }
}

fn err(field: &str, reason: impl std::fmt::Display) -> ConfigError {
    ConfigError::InvalidTransport(format!("transport.{field}: {reason}"))
}

/// Parse a bounded `u32` field: absent → `default`; present → must be an
/// integer within `range`, else `Err(InvalidTransport)`.
fn bounded_u32(
    section: &Value,
    field: &str,
    range: std::ops::RangeInclusive<i64>,
    default: u32,
) -> Result<u32, ConfigError> {
    match get(section, field) {
        None => Ok(default),
        Some(v) => {
            let n = as_i64(v).ok_or_else(|| err(field, "must be an integer"))?;
            if range.contains(&n) {
                Ok(n as u32)
            } else {
                Err(err(
                    field,
                    format!("{n} out of range {}..={}", range.start(), range.end()),
                ))
            }
        }
    }
}

/// Parse a bounded `usize` field: absent → `default`; present → must be an
/// integer within `range`, else `Err(InvalidTransport)`.
fn bounded_usize(
    section: &Value,
    field: &str,
    range: std::ops::RangeInclusive<i64>,
    default: usize,
) -> Result<usize, ConfigError> {
    match get(section, field) {
        None => Ok(default),
        Some(v) => {
            let n = as_i64(v).ok_or_else(|| err(field, "must be an integer"))?;
            if range.contains(&n) {
                Ok(n as usize)
            } else {
                Err(err(
                    field,
                    format!("{n} out of range {}..={}", range.start(), range.end()),
                ))
            }
        }
    }
}

/// Parse a bounded `u64` field: absent → `default`; present → must be an
/// integer within `range`, else `Err(InvalidTransport)`.
fn bounded_u64(
    section: &Value,
    field: &str,
    range: std::ops::RangeInclusive<i64>,
    default: u64,
) -> Result<u64, ConfigError> {
    match get(section, field) {
        None => Ok(default),
        Some(v) => {
            let n = as_i64(v).ok_or_else(|| err(field, "must be an integer"))?;
            if range.contains(&n) {
                Ok(n as u64)
            } else {
                Err(err(
                    field,
                    format!("{n} out of range {}..={}", range.start(), range.end()),
                ))
            }
        }
    }
}

/// Read the `transport` section (spec/task-brief §Interfaces). `None` (the
/// section is absent) → all-default [`TransportConfig`]. Each field is
/// independently range-validated when present; absent-field default fills in
/// otherwise. Fail-closed: any present-and-out-of-range field is
/// `Err(InvalidTransport)`.
pub fn transport_from_section(v: Option<&Value>) -> Result<TransportConfig, ConfigError> {
    let section = match v {
        None => return Ok(TransportConfig::default()),
        Some(section) => section,
    };
    // A present-but-non-map section (e.g. `transport: disabled`) must NOT silently
    // fall through to all-defaults: `get()` returns `None` for every field against a
    // non-`Map` value, which would otherwise bind the production default socket/limits
    // to a malformed section (codex round-6 P2). Fail closed instead.
    // #210: closed vocabulary — every key below is one this function reads.
    if let Value::Map(entries) = section {
        crate::reject_unknown_keys(TRANSPORT_SECTION, entries, &TRANSPORT_KEYS)?;
    }
    if !matches!(section, Value::Map(_)) {
        return Err(ConfigError::InvalidTransport(
            "transport section must be a map".into(),
        ));
    }

    let socket_path = match get(section, "socket_path") {
        None => PathBuf::from(DEFAULT_SOCKET_PATH),
        Some(v) => PathBuf::from(as_str(v).ok_or_else(|| err("socket_path", "must be a string"))?),
    };
    let max_connections = bounded_u32(
        section,
        "max_connections",
        MAX_CONNECTIONS_RANGE,
        DEFAULT_MAX_CONNECTIONS,
    )?;
    let prompt_max_bytes = bounded_usize(
        section,
        "prompt_max_bytes",
        PROMPT_MAX_BYTES_RANGE,
        DEFAULT_PROMPT_MAX_BYTES,
    )?;
    let handshake_timeout_ms = bounded_u64(
        section,
        "handshake_timeout_ms",
        TIMEOUT_MS_RANGE,
        DEFAULT_HANDSHAKE_TIMEOUT_MS,
    )?;
    let read_timeout_ms = bounded_u64(
        section,
        "read_timeout_ms",
        TIMEOUT_MS_RANGE,
        DEFAULT_READ_TIMEOUT_MS,
    )?;

    Ok(TransportConfig {
        socket_path,
        max_connections,
        prompt_max_bytes,
        handshake_timeout_ms,
        read_timeout_ms,
    })
}

/// The client's bound on writing an attempt or prompt frame (#421). Such a
/// frame can exceed the socket buffer and so finishes only once `maknaed`
/// reads, which it does after its group lookup and admission audit append.
/// The server's client-certificate check may still be running too; it is
/// short and not a term. Control frames keep `read_timeout_ms`.
pub fn content_write_bound(transport: &TransportConfig) -> std::time::Duration {
    std::time::Duration::from_millis(
        transport.read_timeout_ms + GROUP_LOOKUP_TIMEOUT_MS + ADMISSION_AUDIT_TIMEOUT_MS,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_when_absent() {
        let c = transport_from_section(None).unwrap();
        assert_eq!(c.max_connections, 64);
        assert_eq!(c.prompt_max_bytes, 1_048_576);
        assert_eq!(c.handshake_timeout_ms, 5000);
        assert_eq!(c.read_timeout_ms, 5000);
        assert_eq!(
            c.socket_path,
            std::path::PathBuf::from("/run/maknae/maknaed.sock")
        );
    }

    #[test]
    fn defaults_when_section_present_but_empty() {
        let v = crate::Value::Map(vec![]);
        let c = transport_from_section(Some(&v)).unwrap();
        assert_eq!(c.max_connections, 64);
        assert_eq!(c.prompt_max_bytes, 1_048_576);
        assert_eq!(c.handshake_timeout_ms, 5000);
        assert_eq!(c.read_timeout_ms, 5000);
        assert_eq!(
            c.socket_path,
            std::path::PathBuf::from("/run/maknae/maknaed.sock")
        );
    }

    #[test]
    fn accepts_all_fields_within_range() {
        let v = crate::Value::Map(vec![
            (
                "socket_path".into(),
                crate::Value::Str("/tmp/x.sock".into()),
            ),
            ("max_connections".into(), crate::Value::Int(1)),
            ("prompt_max_bytes".into(), crate::Value::Int(1_048_576)),
            ("handshake_timeout_ms".into(), crate::Value::Int(100)),
            ("read_timeout_ms".into(), crate::Value::Int(60_000)),
        ]);
        let c = transport_from_section(Some(&v)).unwrap();
        assert_eq!(c.socket_path, std::path::PathBuf::from("/tmp/x.sock"));
        assert_eq!(c.max_connections, 1);
        assert_eq!(c.prompt_max_bytes, 1_048_576);
        assert_eq!(c.handshake_timeout_ms, 100);
        assert_eq!(c.read_timeout_ms, 60_000);
    }

    #[test]
    fn accepts_upper_boundary_max_connections() {
        let v = crate::Value::Map(vec![("max_connections".into(), crate::Value::Int(4096))]);
        assert_eq!(
            transport_from_section(Some(&v)).unwrap().max_connections,
            4096
        );
    }

    #[test]
    fn rejects_zero_max_connections() {
        let v = crate::Value::Map(vec![("max_connections".into(), crate::Value::Int(0))]);
        assert!(matches!(
            transport_from_section(Some(&v)),
            Err(ConfigError::InvalidTransport(_))
        ));
    }

    #[test]
    fn rejects_max_connections_above_ceiling() {
        let v = crate::Value::Map(vec![("max_connections".into(), crate::Value::Int(4097))]);
        assert!(transport_from_section(Some(&v)).is_err());
    }

    #[test]
    fn prompt_max_bytes_defaults_to_1_mib_and_is_bounded() {
        assert_eq!(TransportConfig::default().prompt_max_bytes, 1_048_576);
        for ok in [65_536, 1_048_576, 16_777_216] {
            let v = crate::Value::Map(vec![("prompt_max_bytes".into(), crate::Value::Int(ok))]);
            assert_eq!(
                transport_from_section(Some(&v)).unwrap().prompt_max_bytes,
                ok as usize
            );
        }
        for bad in [65_535, 16_777_217] {
            let v = crate::Value::Map(vec![("prompt_max_bytes".into(), crate::Value::Int(bad))]);
            assert!(matches!(
                transport_from_section(Some(&v)),
                Err(ConfigError::InvalidTransport(_))
            ));
        }
    }

    #[test]
    fn frame_max_bytes_is_now_an_unknown_key() {
        let v = crate::Value::Map(vec![("frame_max_bytes".into(), crate::Value::Int(65_536))]);
        match transport_from_section(Some(&v)) {
            Err(ConfigError::UnknownKey { section, key }) => {
                assert_eq!(
                    (section.as_str(), key.as_str()),
                    ("transport", "frame_max_bytes")
                );
            }
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn rejects_oversize_frame_cap() {
        let v = crate::Value::Map(vec![(
            "prompt_max_bytes".into(),
            crate::Value::Int(32 * 1024 * 1024),
        )]);
        assert!(transport_from_section(Some(&v)).is_err());
    }

    #[test]
    fn rejects_zero_frame_cap() {
        let v = crate::Value::Map(vec![("prompt_max_bytes".into(), crate::Value::Int(0))]);
        assert!(matches!(
            transport_from_section(Some(&v)),
            Err(ConfigError::InvalidTransport(_))
        ));
    }

    #[test]
    fn accepts_prompt_max_bytes_floor() {
        let v = crate::Value::Map(vec![("prompt_max_bytes".into(), crate::Value::Int(65_536))]);
        assert_eq!(
            transport_from_section(Some(&v)).unwrap().prompt_max_bytes,
            65_536
        );
    }

    #[test]
    fn rejects_prompt_max_bytes_above_ceiling() {
        let v = crate::Value::Map(vec![(
            "prompt_max_bytes".into(),
            crate::Value::Int(16_777_217),
        )]);
        assert!(matches!(
            transport_from_section(Some(&v)),
            Err(ConfigError::InvalidTransport(_))
        ));
    }

    #[test]
    fn rejects_handshake_timeout_below_floor() {
        let v = crate::Value::Map(vec![("handshake_timeout_ms".into(), crate::Value::Int(99))]);
        assert!(matches!(
            transport_from_section(Some(&v)),
            Err(ConfigError::InvalidTransport(_))
        ));
    }

    #[test]
    fn rejects_handshake_timeout_above_ceiling() {
        let v = crate::Value::Map(vec![(
            "handshake_timeout_ms".into(),
            crate::Value::Int(60_001),
        )]);
        assert!(matches!(
            transport_from_section(Some(&v)),
            Err(ConfigError::InvalidTransport(_))
        ));
    }

    #[test]
    fn rejects_read_timeout_below_floor() {
        let v = crate::Value::Map(vec![("read_timeout_ms".into(), crate::Value::Int(99))]);
        assert!(matches!(
            transport_from_section(Some(&v)),
            Err(ConfigError::InvalidTransport(_))
        ));
    }

    #[test]
    fn rejects_read_timeout_above_ceiling() {
        let v = crate::Value::Map(vec![("read_timeout_ms".into(), crate::Value::Int(60_001))]);
        assert!(matches!(
            transport_from_section(Some(&v)),
            Err(ConfigError::InvalidTransport(_))
        ));
    }

    #[test]
    fn rejects_wrong_type_integer_field() {
        let v = crate::Value::Map(vec![(
            "max_connections".into(),
            crate::Value::Str("64".into()),
        )]);
        assert!(matches!(
            transport_from_section(Some(&v)),
            Err(ConfigError::InvalidTransport(_))
        ));
    }

    #[test]
    fn rejects_wrong_type_socket_path() {
        let v = crate::Value::Map(vec![("socket_path".into(), crate::Value::Int(1))]);
        assert!(matches!(
            transport_from_section(Some(&v)),
            Err(ConfigError::InvalidTransport(_))
        ));
    }

    #[test]
    fn rejects_non_map_scalar_section() {
        let v = crate::Value::Str("disabled".into());
        assert!(matches!(
            transport_from_section(Some(&v)),
            Err(ConfigError::InvalidTransport(_))
        ));
    }

    #[test]
    fn rejects_non_map_seq_section() {
        let v = crate::Value::Seq(vec![crate::Value::Str("a".into())]);
        assert!(matches!(
            transport_from_section(Some(&v)),
            Err(ConfigError::InvalidTransport(_))
        ));
    }

    #[test]
    fn the_pre_read_bounds_are_five_seconds_and_nonzero() {
        assert_eq!(GROUP_LOOKUP_TIMEOUT_MS, 5_000);
        assert_eq!(ADMISSION_AUDIT_TIMEOUT_MS, 5_000);
        assert_ne!(GROUP_LOOKUP_TIMEOUT_MS, 0);
        assert_ne!(ADMISSION_AUDIT_TIMEOUT_MS, 0);
    }

    #[test]
    fn socket_path_override_respected() {
        let v = crate::Value::Map(vec![(
            "socket_path".into(),
            crate::Value::Str("/var/run/other.sock".into()),
        )]);
        let c = transport_from_section(Some(&v)).unwrap();
        assert_eq!(
            c.socket_path,
            std::path::PathBuf::from("/var/run/other.sock")
        );
    }
    /// #210: a key this parser does not read must REFUSE, not leave its field
    /// at the default. An ignored key silently substitutes the DEFAULT for what
    /// the operator wrote — sometimes weaker, sometimes STRICTER (a raised
    /// `max_connections` falls back to 64 from a ceiling of 4096) — and either
    /// way their stated intent is discarded without a word.
    #[test]
    fn a_key_this_parser_does_not_read_refuses() {
        let v = Value::Map(vec![("sockt_path".into(), Value::Str("x".into()))]);
        match transport_from_section(Some(&v)) {
            Err(ConfigError::UnknownKey { section, key }) => {
                assert_eq!(section, TRANSPORT_SECTION);
                assert_eq!(key, "sockt_path");
            }
            other => panic!("expected Err(UnknownKey), got {other:?}"),
        }
    }

    /// Companion: every key the parser DOES read still loads, so closing the
    /// vocabulary cannot silently reject a valid config.
    #[test]
    fn every_key_the_parser_reads_is_accepted() {
        let v = Value::Map(vec![
            ("socket_path".into(), Value::Null),
            ("max_connections".into(), Value::Null),
            ("prompt_max_bytes".into(), Value::Null),
            ("handshake_timeout_ms".into(), Value::Null),
            ("read_timeout_ms".into(), Value::Null),
        ]);
        let e = transport_from_section(Some(&v));
        assert!(
            !matches!(e, Err(ConfigError::UnknownKey { .. })),
            "a key the parser reads was rejected: {e:?}"
        );
    }

    #[test]
    fn the_content_write_bound_is_the_read_timeout_plus_the_daemons_pre_read_bounds() {
        let t = TransportConfig {
            read_timeout_ms: 7_000,
            ..TransportConfig::default()
        };
        assert_eq!(
            content_write_bound(&t),
            std::time::Duration::from_millis(
                7_000 + GROUP_LOOKUP_TIMEOUT_MS + ADMISSION_AUDIT_TIMEOUT_MS
            )
        );
        assert_eq!(
            content_write_bound(&t),
            std::time::Duration::from_millis(17_000)
        );
    }
}
