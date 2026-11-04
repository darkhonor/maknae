//! A home's canonical form. `canonical_home` serves the kernel's per-request
//! requester home (#435) and, through `session_home`, a session's `~` (#596),
//! so the two are the same string. Enroll keeps its own fallback to the raw
//! passwd value (`bins/maknae/src/enroll`) on purpose.
use std::path::{Path, PathBuf};

fn confinable_home(resolved: PathBuf) -> Option<PathBuf> {
    (resolved != Path::new("/") && resolved.to_str().is_some()).then_some(resolved)
}

/// An absolute home, resolved once through its symlinks and required to be a
/// directory, that is not `/` and is valid UTF-8. `None` otherwise.
pub fn canonical_home(dir: &Path) -> Option<PathBuf> {
    if !dir.is_absolute() {
        return None;
    }
    confinable_home(crate::resolve_dir(dir).ok()?)
}

/// The calling process's own home: the passwd record for its effective uid,
/// never `$HOME` and never a lookup by name.
pub fn session_home() -> Option<PathBuf> {
    nix::unistd::User::from_uid(nix::unistd::geteuid())
        .ok()
        .flatten()
        .and_then(|u| canonical_home(&u.dir))
}

#[cfg(test)]
mod tests {
    use super::*;
    use nix::unistd::{geteuid, User};

    fn scratch(tag: &str) -> std::path::PathBuf {
        let d = std::env::temp_dir().join(format!("maknae_io_home_{tag}_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    #[test]
    fn only_a_utf8_home_below_the_root_is_confinable() {
        use std::os::unix::ffi::OsStrExt;
        assert_eq!(confinable_home("/home/b".into()), Some("/home/b".into()));
        assert_eq!(confinable_home("/".into()), None);
        let odd = std::path::PathBuf::from(std::ffi::OsStr::from_bytes(&[0x2f, 0x68, 0xff]));
        assert_eq!(confinable_home(odd), None);
    }

    #[test]
    fn a_real_directory_resolves_to_its_kernel_form() {
        let d = scratch("real");
        let canon = Some(crate::resolve_dir(&d).unwrap().into_os_string());
        let doubled = std::path::PathBuf::from(format!("/{}", d.display()));
        for form in [d.clone(), d.join(""), doubled] {
            assert_eq!(
                canonical_home(&form).map(|p| p.into_os_string()),
                canon,
                "{form:?}"
            );
        }
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn a_trailing_slash_in_the_passwd_home_is_canonical() {
        let d = scratch("trailing");
        let got = canonical_home(&d.join("")).unwrap();
        assert_eq!(Some(got.clone()), canonical_home(&d));
        assert!(!got.to_str().unwrap().ends_with('/'), "{got:?}");
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn a_symlinked_home_resolves_to_its_target() {
        let d = scratch("linktarget");
        let link = d.with_extension("link");
        let _ = std::fs::remove_file(&link);
        std::os::unix::fs::symlink(&d, &link).unwrap();
        assert_eq!(canonical_home(&link), canonical_home(&d));
        let _ = std::fs::remove_file(&link);
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn an_unusable_home_is_none() {
        let d = scratch("unusable");
        let file = d.join("f");
        std::fs::write(&file, b"").unwrap();
        for bad in [
            std::path::PathBuf::from("relative/home"),
            d.join("missing"),
            file.clone(),
            std::path::PathBuf::from("/"),
        ] {
            assert_eq!(canonical_home(&bad), None, "{bad:?}");
        }
        let _ = std::fs::remove_dir_all(&d);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn a_non_utf8_home_is_none() {
        use std::os::unix::ffi::OsStrExt;
        let d = scratch("nonutf8");
        let odd = d.join(std::ffi::OsStr::from_bytes(&[0x68, 0xff]));
        std::fs::create_dir_all(&odd).unwrap();
        assert_eq!(canonical_home(&odd), None);
        let _ = std::fs::remove_dir_all(&d);
    }

    fn passwd_home() -> Option<std::path::PathBuf> {
        User::from_uid(geteuid()).ok().flatten().map(|u| u.dir)
    }

    #[test]
    fn session_home_resolves_the_effective_uids_home() {
        let Some(dir) = passwd_home().filter(|d| canonical_home(d).is_some()) else {
            eprintln!("SKIP: the effective uid's passwd home does not resolve on this host");
            return;
        };
        let got = session_home();
        assert!(got.is_some(), "a resolvable passwd home must be returned");
        assert_eq!(got, canonical_home(&dir));
    }

    const PROBE: &str = "MAKNAE_IO_HOME_PROBE";

    /// Run only by `session_home_ignores_the_home_variable`, in a child
    /// process, so `HOME` is never changed in this test process.
    #[test]
    #[ignore = "run only by session_home_ignores_the_home_variable"]
    fn session_home_probe() {
        if std::env::var_os(PROBE).is_none() {
            return;
        }
        println!("PROBE-HOME={:?}", session_home());
    }

    #[test]
    fn session_home_ignores_the_home_variable() {
        if passwd_home()
            .filter(|d| canonical_home(d).is_some())
            .is_none()
        {
            eprintln!("SKIP: the effective uid's passwd home does not resolve on this host");
            return;
        }
        let decoy = scratch("decoy");
        let out = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "home::tests::session_home_probe",
                "--ignored",
                "--nocapture",
            ])
            .env(PROBE, "1")
            .env("HOME", &decoy)
            .output()
            .unwrap();
        let stdout = String::from_utf8_lossy(&out.stdout);
        assert!(out.status.success(), "{stdout}");
        let want = format!("PROBE-HOME={:?}", session_home());
        assert!(stdout.contains(&want), "{stdout}");
        assert!(!stdout.contains(decoy.to_str().unwrap()), "{stdout}");
        let _ = std::fs::remove_dir_all(&decoy);
    }
}
