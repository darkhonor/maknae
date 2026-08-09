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
}
