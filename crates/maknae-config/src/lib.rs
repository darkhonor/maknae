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
//! [`load_str`]. A CI gate asserts no profile sets `abort` — but the gate is
//! best-effort (a downstream workspace / `RUSTFLAGS=-Cpanic=abort` can override).
//! Even then the failure mode is a **process abort (fail-closed)** on a malformed/
//! deep config: no wrong `Value` is ever produced — never a fail-open.
//!
//! Cycle ②a: the **document model + extension registry** — a config *directory*
//! (`maknae.yaml` + `config.d/*.{yaml,yml}`) → a [`Document`] of named sections,
//! permission-gated (`cfg(unix)`; non-Unix refuses), merge/precedence-resolved,
//! with a schema-agnostic registry ([`SectionSpec`]/[`load_config`]). `core` is a
//! reserved, base-only, optional section owned internally.
//!
//! Cycle ②c: the **core-section classification ceiling** — [`ceiling_from_core`]
//! reads `core.handling.ceiling` (the lake's vocabulary, verbatim) into a typed
//! [`Ceiling`] and projects it to the coarse ingest gate ([`Ceiling::ingest_posture`]
//! → [`IngestPosture`]). Absent → Public baseline; present → strictly validated
//! (`lake.schema.json` port); present-but-invalid → [`ConfigError::InvalidCeiling`].
#![forbid(unsafe_code)]

mod audit_cfg;
mod authz;
mod builder;
mod ceiling;
mod document;
mod error;
mod loader;
mod principal;
mod scalar;
mod transport;
mod value;

pub use loader::load_config;

pub use audit_cfg::{audit_from_section, AuditConfig, AUDIT_SECTION};
pub use authz::{load_authz, AuthzError, AuthzPolicy, Decision, PathGlob, Pattern, Request};
pub use ceiling::{ceiling_from_core, Ceiling, Classification, IngestPosture};
pub use document::{Document, Override, SectionSpec, Source};
pub use error::ConfigError;
pub use principal::{principal_from_section, Principal, PRINCIPAL_SECTION};
pub use transport::{transport_from_section, TransportConfig, TRANSPORT_SECTION};
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
    #[cfg(not(unix))]
    {
        let _ = path;
        Err(ConfigError::PermissionsUnsupported)
    }
    #[cfg(unix)]
    {
        let text = loader::read_secure(path)?;
        load_str(&text)
    }
}

/// Read and parse a root-controlled host artifact. The opened file must be regular,
/// root-owned, and not writable by group or other users.
pub fn load_root_file(path: &std::path::Path) -> Result<Value, ConfigError> {
    #[cfg(not(unix))]
    {
        let _ = path;
        Err(ConfigError::PermissionsUnsupported)
    }
    #[cfg(unix)]
    {
        load_required_file(path, loader::ROOT_ARTIFACT)
    }
}

/// [`load_root_file`] with the artifact requirement supplied by the caller rather than
/// fixed at `ROOT_ARTIFACT`.
///
/// It is split out for a testability reason worth stating plainly (issue #138). The
/// public entry point requires `owner: Some(0)`, which an unprivileged test process
/// can never satisfy, so the read-succeeds-then-parse half of this path used to be
/// covered by loading the host's real root-owned `/etc/hosts` — a security control
/// whose result depended on host state. This helper lets a test name a requirement its
/// own fixture genuinely meets (the current euid), so the SAME production code runs
/// against a real inode with a real owner comparison.
///
/// It is deliberately NOT a seam that fakes the check: there is no injected uid and no
/// stand-in. `load_root_file` still hardcodes `ROOT_ARTIFACT`, and nothing outside this
/// crate can choose a weaker requirement.
#[cfg(unix)]
fn load_required_file(
    path: &std::path::Path,
    target: maknae_io::TargetRequired,
) -> Result<Value, ConfigError> {
    let text = loader::read_secure_required(path, target)?;
    load_str(&text)
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
    fn wide_shallow_container_siblings_ok() {
        // 200 sibling *containers* (`k{i}: [i]`), each opening+closing a sequence.
        // Depth returns to baseline after every sibling, so this stays well under
        // the 128 ceiling — but ONLY if the decrement works. A dropped `-= 1` would
        // accumulate depth across siblings and falsely panic around the 127th.
        // (cargo-mutants does not mutate `saturating_sub`, so this test is the guard.)
        let mut s = String::new();
        for i in 0..200 {
            s.push_str(&format!("k{i}: [{i}]\n"));
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

    #[cfg(unix)]
    #[test]
    fn load_file_reads_and_parses() {
        use std::os::unix::fs::PermissionsExt;
        let path = std::env::temp_dir().join("maknae_config_ok.yaml");
        std::fs::write(&path, "x: 1\n").unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o640)).unwrap();
        let got = load_file(&path);
        let _ = std::fs::remove_file(&path);
        assert_eq!(got.unwrap(), Value::Map(vec![("x".into(), Value::Int(1))]));
    }

    #[cfg(unix)]
    #[test]
    fn load_file_missing_is_not_found() {
        let path = std::path::Path::new("/nonexistent/maknae_config_nope.yaml");
        assert!(matches!(load_file(path), Err(ConfigError::NotFound { .. })));
    }

    #[cfg(unix)]
    #[test]
    fn load_file_bad_utf8_is_io() {
        use std::os::unix::fs::PermissionsExt;
        let path = std::env::temp_dir().join("maknae_config_badutf8.yaml");
        std::fs::write(&path, [0xff, 0xfe, 0x00]).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o640)).unwrap();
        let r = load_file(&path);
        let _ = std::fs::remove_file(&path);
        assert!(matches!(r, Err(ConfigError::Io(_))));
    }

    #[cfg(unix)]
    #[test]
    fn load_file_resolves_a_symlinked_parent_once() {
        use std::os::unix::fs::{symlink, PermissionsExt};
        let base = std::env::temp_dir().join("maknae_config_symlink_parent");
        let real = base.join("real");
        let link = base.join("current");
        let _ = std::fs::remove_dir_all(&base);
        std::fs::create_dir_all(&real).unwrap();
        std::fs::write(real.join("config.yaml"), "x: 1\n").unwrap();
        std::fs::set_permissions(
            real.join("config.yaml"),
            std::fs::Permissions::from_mode(0o640),
        )
        .unwrap();
        symlink(&real, &link).unwrap();
        let got = load_file(&link.join("config.yaml"));
        let _ = std::fs::remove_dir_all(&base);
        assert_eq!(got.unwrap(), Value::Map(vec![("x".into(), Value::Int(1))]));
    }

    #[cfg(not(unix))]
    #[test]
    fn filesystem_loaders_refuse_without_unix_permissions() {
        let path = std::path::Path::new("config.yaml");
        assert_eq!(load_file(path), Err(ConfigError::PermissionsUnsupported));
        assert_eq!(
            load_root_file(path),
            Err(ConfigError::PermissionsUnsupported)
        );
    }

    /// The root-artifact loader's SUCCESS path — read clears every requirement, then
    /// the bytes are parsed (issue #138). Hermetic: the requirement names the current
    /// euid, which the fixture this test just wrote genuinely has, so the real owner
    /// comparison runs against a real inode. The `/etc/hosts` load that used to cover
    /// this asserted on host state and told us nothing about the loader.
    #[cfg(unix)]
    #[test]
    fn root_artifact_loader_parses_when_every_requirement_is_met() {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        let path =
            std::env::temp_dir().join(format!("maknae_config_owned_{}.yaml", std::process::id()));
        std::fs::write(&path, "x: 1\n").unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o640)).unwrap();
        let me = std::fs::metadata(&path).unwrap().uid();
        let got = load_required_file(
            &path,
            maknae_io::TargetRequired {
                owner: Some(me),
                mode_mask: Some(0o022),
                nlink_exactly_one: false,
                regular_file: true,
            },
        );
        let _ = std::fs::remove_file(&path);
        assert_eq!(got.unwrap(), Value::Map(vec![("x".into(), Value::Int(1))]));
    }

    #[cfg(unix)]
    #[test]
    fn load_root_file_refuses_non_root_owned_artifact() {
        use std::os::unix::fs::PermissionsExt;
        let path = std::env::temp_dir().join("maknae_config_nonroot.yaml");
        std::fs::write(&path, "x: 1\n").unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o640)).unwrap();
        let got = load_root_file(&path);
        let _ = std::fs::remove_file(&path);
        assert!(matches!(got, Err(ConfigError::Io(message)) if message.contains("require 0")));
    }
}
