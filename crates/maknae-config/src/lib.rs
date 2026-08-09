//! maknae-config — Maknae's configuration backbone.
//!
//! Cycle ①: the fail-closed YAML **loading core** — bytes → an owned [`Value`]
//! tree via a restricted, reject-exotic subset (duplicate-key rejection, no
//! aliases/tags/multi-doc/non-string-keys, depth-bounded, panic-boundaried).
//! Spec: `2026-08-09-maknae-config-loading-core.md`.
//!
//! **`panic = "unwind"` is load-bearing:** the parser has internal
//! `assert!`/`unreachable!` paths and the depth ceiling deliberately panics; both
//! are converted to [`ConfigError::Parse`] by the `catch_unwind` boundary in
//! [`load_str`]. Under `panic = "abort"` that boundary is disarmed (a CI gate
//! asserts no profile sets `abort`).
#![forbid(unsafe_code)]

mod builder;
mod error;
mod scalar;
mod value;

pub use error::ConfigError;
pub use value::Value;

use builder::Builder;

/// Parse a YAML string into a [`Value`], fail-closed. Strips a single leading BOM.
pub fn load_str(input: &str) -> Result<Value, ConfigError> {
    let input = input.strip_prefix('\u{feff}').unwrap_or(input);
    // `builder` is constructed here and *borrowed* into the closure, so its
    // recorded first-violation error and the depth marker survive an unwind.
    let mut builder = Builder::new();
    let scan = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let mut parser = yaml_rust2::parser::Parser::new(input.chars());
        parser.load(&mut builder, true) // multi = true → we count DocumentStart ourselves
    }));
    match scan {
        // Caught unwind. Our depth panic is the only panic reached in practice
        // (extensive fuzzing surfaced no yaml-rust2 internal panic), and `depth_loc`
        // holds its location. A hypothetical parser-internal panic would also be
        // caught here and reported as a depth error — fail-closed, if imprecise.
        Err(_) => {
            let (line, col) = builder.depth_loc();
            Err(ConfigError::Parse {
                message: "nesting depth exceeded".into(),
                line,
                col,
            })
        }
        Ok(Err(scan_err)) => Err(ConfigError::Parse {
            message: scan_err.to_string(),
            line: scan_err.marker().line(),
            col: scan_err.marker().col(),
        }),
        // Recorded violation (if any) is preferred over the built tree.
        Ok(Ok(())) => builder.finish(),
    }
}

/// Read a file and parse it. Invalid UTF-8 or an I/O failure → [`ConfigError::Io`].
pub fn load_file(path: &std::path::Path) -> Result<Value, ConfigError> {
    let bytes = std::fs::read(path).map_err(|e| ConfigError::Io(e.to_string()))?;
    let text =
        std::str::from_utf8(&bytes).map_err(|e| ConfigError::Io(format!("invalid UTF-8: {e}")))?;
    load_str(text)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dup_key_rejected_not_lastwin() {
        assert!(matches!(
            load_str("a: 1\na: 2\n"),
            Err(ConfigError::DuplicateKey { .. })
        ));
    }

    #[test]
    fn plain_vs_quoted_scalar() {
        assert_eq!(
            load_str("x: 1").unwrap(),
            Value::Map(vec![("x".into(), Value::Int(1))])
        );
        assert_eq!(
            load_str("x: \"1\"").unwrap(),
            Value::Map(vec![("x".into(), Value::Str("1".into()))])
        );
    }

    #[test]
    fn alias_rejected() {
        // anchor &x builds; alias *x rejects (reaches the Alias arm)
        assert!(matches!(
            load_str("a: &x 1\nb: *x\n"),
            Err(ConfigError::Parse { .. })
        ));
    }

    #[test]
    fn lone_anchor_builds() {
        assert_eq!(
            load_str("a: &x 1\n").unwrap(),
            Value::Map(vec![("a".into(), Value::Int(1))])
        );
    }

    #[test]
    fn multi_doc_rejected() {
        assert!(matches!(
            load_str("a: 1\n---\nb: 2\n"),
            Err(ConfigError::Parse { .. })
        ));
    }

    #[test]
    fn empty_is_null() {
        assert_eq!(load_str("").unwrap(), Value::Null);
    }

    #[test]
    fn bom_stripped() {
        assert_eq!(
            load_str("\u{feff}x: 1").unwrap(),
            Value::Map(vec![("x".into(), Value::Int(1))])
        );
    }

    #[test]
    fn deep_129_is_parse_not_panic() {
        let deep = "[".repeat(129) + &"]".repeat(129);
        assert!(matches!(load_str(&deep), Err(ConfigError::Parse { .. })));
    }

    #[test]
    fn boundary_128_accepted() {
        let ok = "[".repeat(128) + &"]".repeat(128);
        assert!(load_str(&ok).is_ok());
    }

    #[test]
    fn wide_shallow_ok() {
        // 200 flat sibling keys — depth stays shallow. Pins the depth *decrement*:
        // a dropped `-= 1` would accumulate depth across siblings and falsely panic.
        let mut s = String::new();
        for i in 0..200 {
            s.push_str(&format!("k{i}: {i}\n"));
        }
        assert!(load_str(&s).is_ok());
    }

    #[test]
    fn depth_error_carries_real_location() {
        // The 129th `[` sits at col ~128 on line 1. Asserting the message + a
        // large col pins depth_mark()'s real value → kills the constant-return mutants.
        let deep = "[".repeat(129) + &"]".repeat(129);
        match load_str(&deep) {
            Err(ConfigError::Parse { message, col, .. }) => {
                assert!(message.contains("nesting depth exceeded"), "msg: {message}");
                assert!(col >= 100, "col was {col}");
            }
            other => panic!("expected depth Parse, got {other:?}"),
        }
    }

    #[test]
    fn scan_error_is_parse() {
        // unclosed flow sequence → yaml-rust2 ScanError → the Ok(Err) branch → Parse
        assert!(matches!(
            load_str("x: [1, 2\n"),
            Err(ConfigError::Parse { .. })
        ));
    }

    #[test]
    fn load_file_reads_and_parses() {
        let path = std::env::temp_dir().join("maknae_config_ok.yaml");
        std::fs::write(&path, "x: 1\n").unwrap();
        let got = load_file(&path);
        let _ = std::fs::remove_file(&path);
        assert_eq!(got.unwrap(), Value::Map(vec![("x".into(), Value::Int(1))]));
    }

    #[test]
    fn load_file_missing_is_io() {
        let path = std::path::Path::new("/nonexistent/maknae_config_nope.yaml");
        assert!(matches!(load_file(path), Err(ConfigError::Io(_))));
    }

    #[test]
    fn load_file_bad_utf8_is_io() {
        let path = std::env::temp_dir().join("maknae_config_badutf8.yaml");
        std::fs::write(&path, [0xff, 0xfe, 0x00]).unwrap();
        let r = load_file(&path);
        let _ = std::fs::remove_file(&path);
        assert!(matches!(r, Err(ConfigError::Io(_))));
    }
}
