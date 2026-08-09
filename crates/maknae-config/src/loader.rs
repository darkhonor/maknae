//! `load_config` — directory → `Document` (spec §2–§6). Spec validation and the
//! registry are platform-independent; the secure read/scan is `cfg(unix)`.

// Imports land incrementally per task so each task passes `clippy -D warnings`
// (unused-import is an error under CI's `-D warnings`): Task 3 needs only
// `SectionSpec`; Task 5 adds `Source`; Task 6 adds `Document`/`Override` +
// `load_str`/`Value`.
use crate::document::SectionSpec;
use crate::ConfigError;
use std::path::Path;

pub(crate) const CORE_SECTION: &str = "core";

/// Collapse any `Display` error (I/O, non-UTF-8) into `ConfigError::Io`. A single
/// named fn (not a per-site closure) so every `.map_err(io_err)` call sits on the
/// always-executed path and only *this one* body region needs a covering test —
/// keeps `loader.rs`'s defensive fs-error arms from sinking the T1 95% floor.
#[cfg(unix)]
pub(crate) fn io_err(e: impl std::fmt::Display) -> ConfigError {
    ConfigError::Io(e.to_string())
}

#[cfg(unix)]
pub(crate) fn mode_is_secure(mode: u32) -> bool {
    mode & 0o007 == 0
}

/// Secure read (spec §3): lstat symlink screen → open → fstat mode on the open
/// fd → read from that same fd. The checked inode and the read inode are one
/// open fd — the read-reopen TOCTOU is closed. Symlink *detection* is a bounded
/// lstat→open race within the trusted-group dir boundary (spec §3, honest scope).
// `allow(dead_code)`: sole non-test caller is `scan_dir` (Task 5); removed there.
#[cfg(unix)]
#[allow(dead_code)]
pub(crate) fn read_secure(path: &Path) -> Result<String, ConfigError> {
    use std::io::Read;
    use std::os::unix::fs::MetadataExt;

    let lst = std::fs::symlink_metadata(path).map_err(io_err)?; // missing → Io (cycle ① contract)
    if lst.file_type().is_symlink() {
        return Err(ConfigError::Symlink { path: path.display().to_string() });
    }
    let mut file = std::fs::File::open(path).map_err(io_err)?;
    let meta = file.metadata().map_err(io_err)?;
    if !mode_is_secure(meta.mode()) {
        return Err(ConfigError::InsecurePermissions {
            path: path.display().to_string(),
            mode: meta.mode(),
        });
    }
    let mut buf = String::new();
    file.read_to_string(&mut buf).map_err(io_err)?; // non-UTF-8 → InvalidData → Io
    Ok(buf)
}

/// Validate the caller's specs before any file is read (spec §5): reject a
/// reserved name and duplicate names. Fail-closed on caller misuse.
// `allow(dead_code)`: sole non-test caller is `load_config` (Task 7); removed there.
#[allow(dead_code)]
pub(crate) fn validate_specs(specs: &[SectionSpec]) -> Result<(), ConfigError> {
    for (i, s) in specs.iter().enumerate() {
        if s.name == CORE_SECTION {
            return Err(ConfigError::ReservedSection { section: s.name.clone() });
        }
        if specs[..i].iter().any(|p| p.name == s.name) {
            return Err(ConfigError::DuplicateSpec { section: s.name.clone() });
        }
    }
    Ok(())
}

/// Name lookups over the validated extension specs plus the reserved `core`.
// `allow(dead_code)`: sole non-test caller is `assemble` (Task 6); removed there.
#[allow(dead_code)]
pub(crate) struct Registry<'a> {
    pub(crate) specs: &'a [SectionSpec],
}

#[allow(dead_code)]
impl<'a> Registry<'a> {
    pub(crate) fn is_reserved(&self, name: &str) -> bool {
        name == CORE_SECTION
    }
    pub(crate) fn is_known(&self, name: &str) -> bool {
        name == CORE_SECTION || self.specs.iter().any(|s| s.name == name)
    }
    pub(crate) fn required_extensions(&self) -> impl Iterator<Item = &str> {
        self.specs.iter().filter(|s| s.required).map(|s| s.name.as_str())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn spec(name: &str, required: bool) -> SectionSpec {
        SectionSpec { name: name.into(), required }
    }

    #[test]
    fn validate_rejects_reserved_name() {
        let specs = [spec("core", false)];
        assert!(matches!(
            validate_specs(&specs),
            Err(ConfigError::ReservedSection { section }) if section == "core"
        ));
    }

    #[test]
    fn validate_rejects_duplicate_specs() {
        let specs = [spec("authz", true), spec("authz", false)];
        assert!(matches!(
            validate_specs(&specs),
            Err(ConfigError::DuplicateSpec { section }) if section == "authz"
        ));
    }

    #[test]
    fn validate_accepts_distinct_extensions() {
        let specs = [spec("authz", true), spec("llm", false)];
        assert!(validate_specs(&specs).is_ok());
    }

    #[test]
    fn registry_knows_core_and_specs_only() {
        let specs = [spec("authz", true)];
        let reg = Registry { specs: &specs };
        assert!(reg.is_known("core") && reg.is_reserved("core"));
        assert!(reg.is_known("authz") && !reg.is_reserved("authz"));
        assert!(!reg.is_known("nope"));
        assert_eq!(reg.required_extensions().collect::<Vec<_>>(), vec!["authz"]);
    }
}

#[cfg(all(test, unix))]
mod unix_read_tests {
    use super::*;
    use std::io::Write;
    use std::os::unix::fs::PermissionsExt;
    use std::path::PathBuf;

    // Each test uses a unique temp path (no external tempdir dep).
    fn tmp(name: &str) -> PathBuf {
        std::env::temp_dir().join(format!("maknae_2a_{}_{name}", std::process::id()))
    }

    fn write_mode(path: &std::path::Path, body: &str, mode: u32) {
        let mut f = std::fs::File::create(path).unwrap();
        f.write_all(body.as_bytes()).unwrap();
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode)).unwrap();
    }

    #[test]
    fn secure_read_ok_640() {
        let p = tmp("ok");
        write_mode(&p, "x: 1\n", 0o640);
        let got = read_secure(&p);
        let _ = std::fs::remove_file(&p);
        assert_eq!(got.unwrap(), "x: 1\n");
    }

    #[test]
    fn world_readable_file_rejected() {
        let p = tmp("644");
        write_mode(&p, "x: 1\n", 0o644);
        let got = read_secure(&p);
        let _ = std::fs::remove_file(&p);
        assert!(matches!(got, Err(ConfigError::InsecurePermissions { mode, .. }) if mode & 0o007 != 0));
    }

    #[test]
    fn symlink_rejected() {
        let target = tmp("sl_target");
        let link = tmp("sl_link");
        write_mode(&target, "x: 1\n", 0o640);
        let _ = std::fs::remove_file(&link);
        std::os::unix::fs::symlink(&target, &link).unwrap();
        let got = read_secure(&link);
        let _ = std::fs::remove_file(&link);
        let _ = std::fs::remove_file(&target);
        assert!(matches!(got, Err(ConfigError::Symlink { .. })));
    }

    #[test]
    fn missing_file_is_io() {
        let got = read_secure(&tmp("nope_never_created"));
        assert!(matches!(got, Err(ConfigError::Io(_))));
    }

    #[test]
    fn non_utf8_at_secure_mode_is_io() {
        // A 0o640 file with invalid UTF-8: passes the symlink + mode checks, fails
        // at read_to_string (InvalidData) → Io. Covers read_secure's read arm; the
        // spec §3 non-UTF-8→Io claim is a NEW path (does not reuse cycle ①'s load_file).
        let p = tmp("badutf8");
        std::fs::write(&p, [0xff, 0xfe, 0x00]).unwrap();
        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o640)).unwrap();
        let got = read_secure(&p);
        let _ = std::fs::remove_file(&p);
        assert!(matches!(got, Err(ConfigError::Io(_))));
    }

    #[test]
    fn mode_mask_helper() {
        assert!(mode_is_secure(0o640) && mode_is_secure(0o600));
        assert!(!mode_is_secure(0o644) && !mode_is_secure(0o642) && !mode_is_secure(0o641));
    }
}
