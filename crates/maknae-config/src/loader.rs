//! `load_config` — directory → `Document` (spec §2–§6). Spec validation and the
//! registry are platform-independent; the secure read/scan is `cfg(unix)`.

// Imports land incrementally per task so each task passes `clippy -D warnings`
// (unused-import is an error under CI's `-D warnings`): Task 3 needs only
// `SectionSpec`; Task 5 adds `Source`; Task 6 adds `Document`/`Override` +
// `load_str`/`Value`.
use crate::document::{SectionSpec, Source};
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
#[cfg(unix)]
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

#[cfg(unix)]
fn is_yaml_ext(name: &str) -> bool {
    let lower = name.to_ascii_lowercase();
    lower.ends_with(".yaml") || lower.ends_with(".yml")
}

/// Canonicalize the dir, permission-check the dir + `config.d/` **first**, classify
/// each entry (spec §2 ordered sequence), then read buffered contents: base first,
/// then `config.d/` files lexically by filename. All perm/symlink/io violations
/// abort here, before any parse (spec §4(1): dir + config.d checked, *then* files
/// read — so a world-writable `config.d/` is caught before a bad base is opened).
// `allow(dead_code)`: sole non-test caller is `load_config_impl` (Task 7); removed there.
#[cfg(unix)]
#[allow(dead_code)]
pub(crate) fn scan_dir(dir: &Path) -> Result<Vec<(Source, String)>, ConfigError> {
    use std::os::unix::fs::MetadataExt;

    // Top-level dir MAY be a symlink → canonicalize, then perm-check the target.
    let root = std::fs::canonicalize(dir).map_err(io_err)?;
    let root_meta = std::fs::metadata(&root).map_err(io_err)?;
    if !mode_is_secure(root_meta.mode()) {
        return Err(ConfigError::InsecurePermissions {
            path: root.display().to_string(),
            mode: root_meta.mode(),
        });
    }

    // config.d/ (optional): permission/symlink-check the subdir and enumerate its
    // candidate files BEFORE any file content is read (spec §4(1)). Contents are
    // read below (base first), so the buffer order stays base-then-config.d.
    let cd = root.join("config.d");
    let mut cd_files: Vec<std::path::PathBuf> = Vec::new();
    match std::fs::symlink_metadata(&cd) {
        Err(_) => { /* absent → base only */ }
        Ok(m) if m.file_type().is_symlink() => {
            return Err(ConfigError::Symlink { path: cd.display().to_string() });
        }
        Ok(m) if !m.is_dir() => {
            // NB: these two arms *synthesize* an Io message (config.d exists but is
            // the wrong kind of thing) rather than *converting* an io::Error — so
            // `io_err` deliberately does NOT apply here. Don't "unify" them with it.
            return Err(ConfigError::Io(format!("config.d is not a directory: {}", cd.display())));
        }
        Ok(m) => {
            if !mode_is_secure(m.mode()) {
                return Err(ConfigError::InsecurePermissions {
                    path: cd.display().to_string(),
                    mode: m.mode(),
                });
            }
            // Enumerate immediate entries; classify by the §2 ordered sequence.
            let rd = std::fs::read_dir(&cd).map_err(io_err)?;
            for ent in rd {
                let ent = ent.map_err(io_err)?;
                let name = ent.file_name().to_string_lossy().into_owned();
                // (1) dotfile → skip
                if name.starts_with('.') {
                    continue;
                }
                let ft = ent.file_type().map_err(io_err)?;
                // (2) symlink or subdirectory → error (checked before extension)
                if ft.is_symlink() {
                    return Err(ConfigError::Symlink { path: ent.path().display().to_string() });
                }
                if ft.is_dir() {
                    return Err(ConfigError::Io(format!(
                        "config.d entry is a directory: {}",
                        ent.path().display()
                    )));
                }
                // (3) regular .yaml/.yml → load; (4) other regular → ignore
                if ft.is_file() && is_yaml_ext(&name) {
                    cd_files.push(ent.path());
                }
            }
            cd_files.sort(); // lexical by full path (same parent → by filename)
        }
    }

    // Now read contents in one buffer-before-parse pass: base (required — missing
    // → Io) first, then each config.d file in lexical order. First violation aborts.
    let mut out: Vec<(Source, String)> = Vec::new();
    out.push((Source::Base, read_secure(&root.join("maknae.yaml"))?));
    for p in cd_files {
        let body = read_secure(&p)?;
        out.push((Source::ConfigD(p), body));
    }
    Ok(out)
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

#[cfg(all(test, unix))]
mod unix_scan_tests {
    use super::*;
    use std::io::Write;
    use std::os::unix::fs::PermissionsExt;
    use std::path::PathBuf;

    struct Dir(PathBuf);
    impl Drop for Dir {
        fn drop(&mut self) { let _ = std::fs::remove_dir_all(&self.0); }
    }
    fn new_dir(tag: &str) -> Dir {
        let p = std::env::temp_dir().join(format!("maknae_2a_scan_{}_{tag}", std::process::id()));
        let _ = std::fs::remove_dir_all(&p);
        std::fs::create_dir_all(&p).unwrap();
        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o750)).unwrap();
        Dir(p)
    }
    fn put(dir: &std::path::Path, name: &str, body: &str, mode: u32) {
        let p = dir.join(name);
        let mut f = std::fs::File::create(&p).unwrap();
        f.write_all(body.as_bytes()).unwrap();
        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(mode)).unwrap();
    }

    #[test]
    fn base_only_when_no_config_d() {
        let d = new_dir("baseonly");
        put(&d.0, "maknae.yaml", "core:\n  a: 1\n", 0o640);
        let bufs = scan_dir(&d.0).unwrap();
        assert_eq!(bufs.len(), 1);
        assert!(matches!(bufs[0].0, Source::Base));
    }

    #[test]
    fn config_d_files_sorted_and_yml_included() {
        let d = new_dir("sorted");
        put(&d.0, "maknae.yaml", "core:\n  a: 1\n", 0o640);
        let cd = d.0.join("config.d");
        std::fs::create_dir(&cd).unwrap();
        std::fs::set_permissions(&cd, std::fs::Permissions::from_mode(0o750)).unwrap();
        put(&cd, "b.yml", "llm:\n  x: 1\n", 0o640);
        put(&cd, "a.yaml", "authz:\n  y: 1\n", 0o640);
        put(&cd, "README.md", "ignore me\n", 0o640);   // ignored
        put(&cd, ".#a.yaml", "dotfile\n", 0o640);       // skipped (dotfile)
        let bufs = scan_dir(&d.0).unwrap();
        // base, then a.yaml, then b.yml
        assert_eq!(bufs.len(), 3);
        assert!(matches!(bufs[0].0, Source::Base));
        match (&bufs[1].0, &bufs[2].0) {
            (Source::ConfigD(p1), Source::ConfigD(p2)) => {
                assert!(p1.ends_with("a.yaml") && p2.ends_with("b.yml"));
            }
            _ => panic!("expected two ConfigD sources in lexical order"),
        }
    }

    #[test]
    fn world_writable_config_d_rejected() {
        let d = new_dir("wwcd");
        put(&d.0, "maknae.yaml", "core:\n  a: 1\n", 0o640);
        let cd = d.0.join("config.d");
        std::fs::create_dir(&cd).unwrap();
        std::fs::set_permissions(&cd, std::fs::Permissions::from_mode(0o772)).unwrap();
        assert!(matches!(scan_dir(&d.0), Err(ConfigError::InsecurePermissions { .. })));
    }

    #[test]
    fn symlinked_config_d_entry_rejected() {
        let d = new_dir("slentry");
        put(&d.0, "maknae.yaml", "core:\n  a: 1\n", 0o640);
        let cd = d.0.join("config.d");
        std::fs::create_dir(&cd).unwrap();
        std::fs::set_permissions(&cd, std::fs::Permissions::from_mode(0o750)).unwrap();
        let target = d.0.join("outside.yaml");
        put(&d.0, "outside.yaml", "authz:\n  y: 1\n", 0o640);
        std::os::unix::fs::symlink(&target, cd.join("evil.yaml")).unwrap();
        assert!(matches!(scan_dir(&d.0), Err(ConfigError::Symlink { .. })));
    }

    #[test]
    fn subdir_in_config_d_rejected() {
        let d = new_dir("subdir");
        put(&d.0, "maknae.yaml", "core:\n  a: 1\n", 0o640);
        let cd = d.0.join("config.d");
        std::fs::create_dir(&cd).unwrap();
        std::fs::set_permissions(&cd, std::fs::Permissions::from_mode(0o750)).unwrap();
        let sub = cd.join("nested.yaml"); // a *directory* named like a yaml file
        std::fs::create_dir(&sub).unwrap();
        std::fs::set_permissions(&sub, std::fs::Permissions::from_mode(0o750)).unwrap();
        assert!(matches!(scan_dir(&d.0), Err(ConfigError::Io(_))));
    }

    #[test]
    fn config_d_itself_a_symlink_rejected() {
        // LOCKED §3 control: the config.d SUBDIR must be a real dir, not a symlink.
        // (Distinct from an entry INSIDE config.d being a symlink.)
        let d = new_dir("cdsymlink");
        put(&d.0, "maknae.yaml", "core:\n  a: 1\n", 0o640);
        let real = d.0.join("real_confd");
        std::fs::create_dir(&real).unwrap();
        std::fs::set_permissions(&real, std::fs::Permissions::from_mode(0o750)).unwrap();
        std::os::unix::fs::symlink(&real, d.0.join("config.d")).unwrap();
        assert!(matches!(scan_dir(&d.0), Err(ConfigError::Symlink { .. })));
    }

    #[test]
    fn config_d_is_a_regular_file_rejected() {
        // The `!m.is_dir()` arm: a plain file named config.d.
        let d = new_dir("cdfile");
        put(&d.0, "maknae.yaml", "core:\n  a: 1\n", 0o640);
        put(&d.0, "config.d", "not a dir\n", 0o640);
        assert!(matches!(scan_dir(&d.0), Err(ConfigError::Io(_))));
    }

    #[test]
    fn missing_base_is_io() {
        let d = new_dir("nobase");
        // no maknae.yaml
        assert!(matches!(scan_dir(&d.0), Err(ConfigError::Io(_))));
    }

    #[test]
    fn nonexistent_dir_is_io() {
        // canonicalize() fails on a non-existent path → Io (covers the canonicalize
        // error arm + io_err's body; root-safe, unlike a File::open EACCES test).
        let p = std::env::temp_dir().join(format!("maknae_2a_nope_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&p);
        assert!(matches!(scan_dir(&p), Err(ConfigError::Io(_))));
    }
}
