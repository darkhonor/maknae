use crate::keychain_policy::KeychainPlane;
#[cfg(target_os = "macos")]
use crate::keychain_policy::{read_gated, KeychainItem};
use crate::VaultError;
use std::path::{Path, PathBuf};
use zeroize::Zeroizing;

#[cfg(target_os = "macos")]
pub(crate) fn read_plane_secret(
    pointer: &Path,
    plane: KeychainPlane,
) -> Result<Zeroizing<String>, VaultError> {
    let expected_uid = nix::unistd::User::from_name(plane.account_name())
        .ok()
        .flatten()
        .map(|u| u.uid.as_raw());
    read_gated(
        plane,
        nix::unistd::geteuid().as_raw(),
        expected_uid,
        || maknae_config::load_root_file(pointer).map_err(VaultError::from),
        |item| read_item_from(Path::new(crate::SYSTEM_KEYCHAIN), item),
    )
}

#[cfg(target_os = "macos")]
static KEYCHAIN_READ: std::sync::Mutex<()> = std::sync::Mutex::new(());

#[cfg(target_os = "macos")]
fn read_item_from(keychain: &Path, item: &KeychainItem) -> Result<Zeroizing<String>, VaultError> {
    use security_framework::os::macos::keychain::SecKeychain;
    use security_framework::os::macos::passwords::find_generic_password;
    let status = |e: security_framework::base::Error| VaultError::Keychain { status: e.code() };
    let _serial = KEYCHAIN_READ.lock().unwrap_or_else(|e| e.into_inner());
    let _no_ui = SecKeychain::disable_user_interaction().map_err(status)?;
    let kc = SecKeychain::open(keychain).map_err(status)?;
    let (password, _) =
        find_generic_password(Some(&[kc]), item.service, item.account).map_err(status)?;
    let raw = Zeroizing::new(password.to_vec());
    let text = std::str::from_utf8(&raw)
        .map_err(|_| VaultError::CredentialSource("the keychain item is not UTF-8".to_string()))?;
    Ok(Zeroizing::new(text.trim().to_string()))
}

#[cfg(not(target_os = "macos"))]
pub(crate) fn read_plane_secret(
    _pointer: &Path,
    _plane: KeychainPlane,
) -> Result<Zeroizing<String>, VaultError> {
    Err(VaultError::CredentialSource(
        "the keychain source exists only on macOS".to_string(),
    ))
}

/// #76: `dir` is anchored without following a symlink at it; only `NotFound` is absence.
#[cfg(target_os = "macos")]
pub(crate) fn observe_pointer(
    dir: &Path,
    plane: KeychainPlane,
) -> Result<Option<PathBuf>, VaultError> {
    use maknae_io::{IoError, IoKind};
    let dir = &std::path::absolute(dir)
        .map_err(|e| VaultError::KeychainPointer(format!("{}: {e}", dir.display())))?;
    let refuse = |e: IoError| VaultError::KeychainPointer(format!("{}: {e}", dir.display()));
    let anchor = match maknae_io::open_anchor(
        dir,
        maknae_io::AnchorRequired::OS_DAC,
        maknae_io::StrategyPref::Auto,
    ) {
        Ok(a) => a,
        Err(IoError::Io {
            kind: IoKind::NotFound,
            ..
        }) => return Ok(None),
        Err(e) => return Err(refuse(e)),
    };
    match anchor.read(
        Path::new(plane.pointer_file()),
        None,
        maknae_io::TargetRequired::OS_DAC_REGULAR,
    ) {
        Ok(_) => Ok(Some(dir.join(plane.pointer_file()))),
        Err(IoError::Io {
            kind: IoKind::NotFound,
            ..
        }) => Ok(None),
        Err(e) => Err(refuse(e)),
    }
}

#[cfg(not(target_os = "macos"))]
pub(crate) fn observe_pointer(
    _dir: &Path,
    _plane: KeychainPlane,
) -> Result<Option<PathBuf>, VaultError> {
    Ok(None)
}

#[cfg(all(test, target_os = "macos"))]
mod tests {
    use super::*;
    use std::process::Command;
    use std::sync::Mutex;

    static KEYCHAIN_UI: Mutex<()> = Mutex::new(());

    struct Scratch {
        path: PathBuf,
        _dir: tempfile::TempDir,
    }

    impl Drop for Scratch {
        fn drop(&mut self) {
            let _ = Command::new("/usr/bin/security")
                .arg("delete-keychain")
                .arg(&self.path)
                .status();
        }
    }

    fn scratch_with_item_not_trusting_us() -> Scratch {
        let dir = tempfile::tempdir().unwrap();
        let kc = Scratch {
            path: dir.path().join("t76.keychain"),
            _dir: dir,
        };
        let run = |args: &[&str]| {
            let s = Command::new("/usr/bin/security")
                .args(args)
                .status()
                .unwrap();
            assert!(s.success(), "security {args:?}");
        };
        let p = kc.path.to_str().unwrap();
        run(&["create-keychain", "-p", "t76", p]);
        run(&["unlock-keychain", "-p", "t76", p]);
        run(&[
            "add-generic-password",
            "-a",
            "secret-id",
            "-s",
            "io.maknae.maknaed",
            "-T",
            "/usr/bin/true",
            "-w",
            "sentinel-t76",
            p,
        ]);
        kc
    }

    #[test]
    fn an_untrusted_binary_is_refused_by_the_acl() {
        let _serial = KEYCHAIN_UI.lock().unwrap_or_else(|e| e.into_inner());
        let kc = scratch_with_item_not_trusting_us();
        let item = KeychainItem {
            service: "io.maknae.maknaed",
            account: "secret-id",
        };
        match read_item_from(&kc.path, &item) {
            Err(VaultError::Keychain { status: -25293 }) => {}
            other => panic!("expected the ACL refusal, got {other:?}"),
        }
    }

    #[test]
    fn an_absent_item_is_named() {
        let _serial = KEYCHAIN_UI.lock().unwrap_or_else(|e| e.into_inner());
        let kc = scratch_with_item_not_trusting_us();
        let item = KeychainItem {
            service: "io.maknae.absent",
            account: "secret-id",
        };
        assert!(matches!(
            read_item_from(&kc.path, &item),
            Err(VaultError::Keychain { status: -25300 })
        ));
    }

    fn pointer_in(dir: &tempfile::TempDir) -> PathBuf {
        dir.path().join(KeychainPlane::Daemon.pointer_file())
    }

    /// #76: a symlinked pointer is refused, not followed.
    #[test]
    fn a_symlinked_pointer_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let real = dir.path().join("real");
        std::fs::write(&real, "").unwrap();
        let p = pointer_in(&dir);
        std::os::unix::fs::symlink(&real, &p).unwrap();
        assert!(matches!(
            observe_pointer(dir.path(), KeychainPlane::Daemon),
            Err(VaultError::KeychainPointer(_))
        ));
    }

    /// #76: a dangling symlinked pointer is refused, not read as absent.
    #[test]
    fn a_dangling_symlinked_pointer_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let p = pointer_in(&dir);
        std::os::unix::fs::symlink(dir.path().join("gone"), &p).unwrap();
        assert!(matches!(
            observe_pointer(dir.path(), KeychainPlane::Daemon),
            Err(VaultError::KeychainPointer(_))
        ));
    }

    /// #76: a directory at the pointer path is refused.
    #[test]
    fn a_directory_pointer_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let p = pointer_in(&dir);
        std::fs::create_dir(&p).unwrap();
        assert!(matches!(
            observe_pointer(dir.path(), KeychainPlane::Daemon),
            Err(VaultError::KeychainPointer(_))
        ));
    }

    /// #76: an unopenable pointer is refused, not read as absent.
    #[test]
    fn an_unreadable_pointer_is_refused() {
        use std::os::unix::fs::PermissionsExt;
        assert!(!nix::unistd::geteuid().is_root(), "root opens mode 000");
        let dir = tempfile::tempdir().unwrap();
        let p = pointer_in(&dir);
        std::fs::write(&p, "").unwrap();
        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o000)).unwrap();
        assert!(matches!(
            observe_pointer(dir.path(), KeychainPlane::Daemon),
            Err(VaultError::KeychainPointer(_))
        ));
    }

    /// #76: only a missing pointer reads as absent.
    #[test]
    fn an_absent_pointer_is_none() {
        let dir = tempfile::tempdir().unwrap();
        assert!(matches!(
            observe_pointer(dir.path(), KeychainPlane::Daemon),
            Ok(None)
        ));
    }

    /// #76: a regular pointer file is observed at its own path.
    #[test]
    fn a_regular_pointer_is_observed() {
        let dir = tempfile::tempdir().unwrap();
        let p = pointer_in(&dir);
        std::fs::write(&p, "").unwrap();
        assert_eq!(
            observe_pointer(dir.path(), KeychainPlane::Daemon).unwrap(),
            Some(p)
        );
    }

    #[test]
    fn a_test_process_is_not_the_daemon_account() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join(KeychainPlane::Daemon.pointer_file());
        assert!(matches!(
            read_plane_secret(&p, KeychainPlane::Daemon),
            Err(VaultError::WrongAccount { .. })
        ));
    }
}
