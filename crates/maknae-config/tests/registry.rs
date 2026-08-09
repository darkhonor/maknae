//! Cycle ②a end-to-end golden vectors (spec §7). Unix-only filesystem vectors
//! behind `#[cfg(unix)]`; the non-unix refusal has its own assert.

use maknae_config::{load_config, ConfigError, SectionSpec, Value};

fn spec(name: &str, required: bool) -> SectionSpec {
    SectionSpec { name: name.into(), required }
}

#[test]
fn reserved_registration_rejected_before_any_read() {
    // Non-existent dir: if validation runs first, we get ReservedSection, not Io.
    let specs = [spec("core", false)];
    let r = load_config(std::path::Path::new("/nonexistent/maknae"), &specs);
    assert!(matches!(r, Err(ConfigError::ReservedSection { .. })));
}

#[cfg(not(unix))]
#[test]
fn non_unix_refuses_to_load() {
    let specs: [SectionSpec; 0] = [];
    // Even a well-formed registration refuses on non-unix.
    let r = load_config(std::path::Path::new("."), &specs);
    assert!(matches!(r, Err(ConfigError::PermissionsUnsupported)));
}

#[cfg(unix)]
mod unix {
    use super::*;
    use std::io::Write;
    use std::os::unix::fs::PermissionsExt;
    use std::path::{Path, PathBuf};

    struct Dir(PathBuf);
    impl Drop for Dir { fn drop(&mut self) { let _ = std::fs::remove_dir_all(&self.0); } }
    fn new_dir(tag: &str) -> Dir {
        let p = std::env::temp_dir().join(format!("maknae_2a_it_{}_{tag}", std::process::id()));
        let _ = std::fs::remove_dir_all(&p);
        std::fs::create_dir_all(&p).unwrap();
        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o750)).unwrap();
        Dir(p)
    }
    fn put(dir: &Path, name: &str, body: &str, mode: u32) {
        let p = dir.join(name);
        let mut f = std::fs::File::create(&p).unwrap();
        f.write_all(body.as_bytes()).unwrap();
        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(mode)).unwrap();
    }
    fn config_d(dir: &Path) -> PathBuf {
        let cd = dir.join("config.d");
        std::fs::create_dir(&cd).unwrap();
        std::fs::set_permissions(&cd, std::fs::Permissions::from_mode(0o750)).unwrap();
        cd
    }

    #[test]
    fn happy_path_base_plus_extension() {
        let d = new_dir("happy");
        put(&d.0, "maknae.yaml", "core:\n  ceiling: public\nauthz:\n  a: 1\n", 0o640);
        let cd = config_d(&d.0);
        put(&cd, "llm.yaml", "llm:\n  provider: x\n", 0o640);
        let doc = load_config(&d.0, &[spec("authz", true), spec("llm", false)]).unwrap();
        assert_eq!(doc.section("authz"), Some(&Value::Map(vec![("a".into(), Value::Int(1))])));
        assert_eq!(doc.section("llm"), Some(&Value::Map(vec![("provider".into(), Value::Str("x".into()))])));
        assert_eq!(doc.section("core").map(|_| ()), Some(()));
    }

    #[test]
    fn empty_base_optional_core_ok() {
        let d = new_dir("emptycore");
        put(&d.0, "maknae.yaml", "", 0o640);
        let doc = load_config(&d.0, &[]).unwrap();
        assert_eq!(doc.section("core"), None);
    }

    #[test]
    fn world_readable_file_refused() {
        let d = new_dir("644");
        put(&d.0, "maknae.yaml", "core: {}\n", 0o644);
        assert!(matches!(load_config(&d.0, &[]), Err(ConfigError::InsecurePermissions { .. })));
    }

    #[test]
    fn config_d_override_recorded() {
        let d = new_dir("override");
        put(&d.0, "maknae.yaml", "authz:\n  a: 1\n", 0o640);
        let cd = config_d(&d.0);
        put(&cd, "z.yaml", "authz:\n  a: 2\n", 0o640);
        let doc = load_config(&d.0, &[spec("authz", false)]).unwrap();
        assert_eq!(doc.section("authz"), Some(&Value::Map(vec![("a".into(), Value::Int(2))])));
        assert_eq!(doc.overrides().len(), 1);
    }

    #[test]
    fn core_override_refused() {
        let d = new_dir("coreov");
        put(&d.0, "maknae.yaml", "core:\n  a: 1\n", 0o640);
        let cd = config_d(&d.0);
        put(&cd, "z.yaml", "core:\n  a: 2\n", 0o640);
        assert!(matches!(load_config(&d.0, &[]), Err(ConfigError::CoreOverride)));
    }

    #[test]
    fn symlinked_config_file_refused() {
        let d = new_dir("sl");
        put(&d.0, "maknae.yaml", "core: {}\n", 0o640);
        let cd = config_d(&d.0);
        put(&d.0, "outside.yaml", "authz:\n  a: 1\n", 0o640);
        std::os::unix::fs::symlink(d.0.join("outside.yaml"), cd.join("a.yaml")).unwrap();
        assert!(matches!(load_config(&d.0, &[spec("authz", false)]), Err(ConfigError::Symlink { .. })));
    }

    #[test]
    fn dotfile_in_config_d_skipped_not_error() {
        let d = new_dir("dotfile");
        put(&d.0, "maknae.yaml", "core: {}\n", 0o640);
        let cd = config_d(&d.0);
        // an editor lockfile-style symlink; must be skipped, not tripped
        put(&d.0, "real.yaml", "authz:\n  a: 1\n", 0o640);
        std::os::unix::fs::symlink(d.0.join("real.yaml"), cd.join(".#authz.yaml")).unwrap();
        let doc = load_config(&d.0, &[]).unwrap();
        assert!(doc.section("authz").is_none());
    }

    #[test]
    fn unknown_section_refused() {
        let d = new_dir("unknown");
        put(&d.0, "maknae.yaml", "mystery:\n  a: 1\n", 0o640);
        assert!(matches!(load_config(&d.0, &[]), Err(ConfigError::UnknownSection { .. })));
    }

    #[test]
    fn missing_required_extension_refused() {
        let d = new_dir("missing");
        put(&d.0, "maknae.yaml", "core: {}\n", 0o640);
        assert!(matches!(load_config(&d.0, &[spec("authz", true)]), Err(ConfigError::MissingSection { .. })));
    }

    #[test]
    fn missing_base_is_io() {
        let d = new_dir("nobase");
        assert!(matches!(load_config(&d.0, &[]), Err(ConfigError::Io(_))));
    }
}
