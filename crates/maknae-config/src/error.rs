//! The fail-closed error type (spec §6). A real error type (not `Result<_, ()>`)
//! so `clippy::result_unit_err` stays quiet under `-D warnings`. `col` is 0-based
//! (yaml-rust2 `Marker::col`), consistent across every variant.

#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum ConfigError {
    /// File read / not-found / invalid UTF-8.
    Io(String),
    /// Malformed / rejected YAML (tags, aliases, multi-doc, depth, bad scalar…).
    Parse {
        message: String,
        line: usize,
        col: usize,
    },
    /// A repeated mapping key — never last-wins.
    DuplicateKey {
        key: String,
        line: usize,
        col: usize,
    },
    /// A config path carries world/other permission bits (spec §3). `mode` is
    /// masked to `0o7777` for Display so file-type bits don't leak.
    InsecurePermissions { path: String, mode: u32 },
    /// A config file or the `config.d/` subdir is a symlink (spec §3).
    Symlink { path: String },
    /// Non-Unix target: the permission model is unavailable, refuse to load (spec §3).
    PermissionsUnsupported,
    /// A config file's document root is not a mapping (spec §2/§6).
    NotAMap { source_path: String },
    /// A top-level key matches no registered section spec (spec §5).
    UnknownSection {
        section: String,
        source_path: String,
    },
    /// The same section is defined in two `config.d/` files (spec §4).
    DuplicateSection { section: String },
    /// A required section has no definition in any source (spec §5).
    MissingSection { section: String },
    /// A `config.d/` file defines the reserved `core` section (spec §4).
    CoreOverride,
    /// A caller registered a reserved section name (spec §5).
    ReservedSection { section: String },
    /// Duplicate section names within the caller's specs (spec §5).
    DuplicateSpec { section: String },
    /// The `core.handling` classification ceiling is present but invalid (spec ②c §4).
    InvalidCeiling { reason: String },
    /// The `transport` section is present but a field is malformed or out of
    /// its fail-closed range (Stage-3a task-2).
    InvalidTransport(String),
}

impl std::fmt::Display for ConfigError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ConfigError::Io(m) => write!(f, "config i/o error: {m}"),
            ConfigError::Parse { message, line, col } => {
                write!(f, "config parse error at {line}:{col}: {message}")
            }
            ConfigError::DuplicateKey { key, line, col } => {
                write!(f, "duplicate config key '{key}' at {line}:{col}")
            }
            ConfigError::InsecurePermissions { path, mode } => {
                write!(
                    f,
                    "insecure permissions on '{path}': mode {:o} has world/other bits",
                    mode & 0o7777
                )
            }
            ConfigError::Symlink { path } => {
                write!(f, "config path is a symlink (refused): '{path}'")
            }
            ConfigError::PermissionsUnsupported => {
                write!(f, "config permission enforcement is unavailable on this platform; refusing to load")
            }
            ConfigError::NotAMap { source_path } => {
                write!(f, "config root is not a mapping: '{source_path}'")
            }
            ConfigError::UnknownSection {
                section,
                source_path,
            } => {
                write!(
                    f,
                    "unknown config section '{section}' in '{source_path}' (no registered spec)"
                )
            }
            ConfigError::DuplicateSection { section } => {
                write!(
                    f,
                    "section '{section}' defined in more than one config.d file"
                )
            }
            ConfigError::MissingSection { section } => {
                write!(f, "required config section '{section}' is missing")
            }
            ConfigError::CoreOverride => {
                write!(
                    f,
                    "the 'core' section may only be defined in maknae.yaml, not config.d"
                )
            }
            ConfigError::ReservedSection { section } => {
                write!(
                    f,
                    "section name '{section}' is reserved and cannot be registered"
                )
            }
            ConfigError::DuplicateSpec { section } => {
                write!(f, "section '{section}' registered more than once")
            }
            ConfigError::InvalidCeiling { reason } => {
                write!(f, "invalid core classification ceiling: {reason}")
            }
            ConfigError::InvalidTransport(reason) => {
                write!(f, "invalid transport config: {reason}")
            }
        }
    }
}

impl std::error::Error for ConfigError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn display_and_error_impl() {
        let e = ConfigError::DuplicateKey {
            key: "x".into(),
            line: 3,
            col: 1,
        };
        assert!(format!("{e}").contains('x'));
        let _: &dyn std::error::Error = &e;
    }

    #[test]
    fn display_covers_io_and_parse() {
        assert!(format!("{}", ConfigError::Io("boom".into())).contains("boom"));
        let p = ConfigError::Parse {
            message: "bad".into(),
            line: 2,
            col: 4,
        };
        assert!(format!("{p}").contains("bad") && format!("{p}").contains("2:4"));
    }

    #[test]
    fn display_covers_invalid_ceiling() {
        let e = ConfigError::InvalidCeiling {
            reason: "classification: unrecognized level 'SEKRET'".into(),
        };
        let s = format!("{e}");
        assert!(
            s.contains("ceiling") && s.contains("SEKRET"),
            "Display was: {s}"
        );
        let _: &dyn std::error::Error = &e;
    }

    #[test]
    fn display_covers_invalid_transport() {
        let e = ConfigError::InvalidTransport(
            "transport.max_connections: 0 out of range 1..=4096".into(),
        );
        let s = format!("{e}");
        assert!(
            s.contains("transport") && s.contains("max_connections"),
            "Display was: {s}"
        );
        let _: &dyn std::error::Error = &e;
    }

    #[test]
    fn display_covers_2a_variants() {
        let cases: Vec<ConfigError> = vec![
            ConfigError::InsecurePermissions {
                path: "/etc/maknae/x.yaml".into(),
                mode: 0o644,
            },
            ConfigError::Symlink {
                path: "/etc/maknae/config.d/a.yaml".into(),
            },
            ConfigError::PermissionsUnsupported,
            ConfigError::NotAMap {
                source_path: "/etc/maknae/maknae.yaml".into(),
            },
            ConfigError::UnknownSection {
                section: "authz".into(),
                source_path: "cfg.yaml".into(),
            },
            ConfigError::DuplicateSection {
                section: "llm".into(),
            },
            ConfigError::MissingSection {
                section: "channels".into(),
            },
            ConfigError::CoreOverride,
            ConfigError::ReservedSection {
                section: "core".into(),
            },
            ConfigError::DuplicateSpec {
                section: "authz".into(),
            },
        ];
        for e in &cases {
            let s = format!("{e}");
            assert!(!s.is_empty(), "empty Display for {e:?}");
            let _: &dyn std::error::Error = e;
        }
        // mode is masked to 0o7777 for Display (no file-type bits leak)
        let ip = ConfigError::InsecurePermissions {
            path: "p".into(),
            mode: 0o100644,
        };
        assert!(
            format!("{ip}").contains("644"),
            "masked mode should render as 644"
        );
        assert!(
            !format!("{ip}").contains("100644"),
            "raw st_mode must not leak"
        );
    }
}
