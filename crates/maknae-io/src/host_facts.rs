//! Host facts (#115): whether a path is present.

use std::io;
use std::path::Path;

use nix::errno::Errno;

use crate::syscall;

/// Whether an entry exists at the absolute `path`, without following a final symlink.
/// Only `ENOENT` is absence; any other failure is an error, never `false`.
pub fn presence(path: &Path) -> io::Result<bool> {
    if !path.is_absolute() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("{} is not an absolute path", path.display()),
        ));
    }
    match syscall::lstat_path(path) {
        Ok(_) => Ok(true),
        Err(Errno::ENOENT) => Ok(false),
        Err(e) => Err(e.into()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    fn private_dir() -> tempfile::TempDir {
        let d = tempfile::tempdir().expect("tempdir");
        std::fs::set_permissions(d.path(), std::fs::Permissions::from_mode(0o700)).expect("chmod");
        d
    }

    #[test]
    fn presence_reports_absent_and_present() {
        let d = private_dir();
        assert!(!presence(&d.path().join("missing")).expect("absent"));
        let f = d.path().join("f");
        std::fs::write(&f, b"x").expect("write");
        assert!(presence(&f).expect("present"));
        let link = d.path().join("dangling");
        std::os::unix::fs::symlink(d.path().join("nowhere"), &link).expect("symlink");
        assert!(presence(&link).expect("a dangling symlink is an entry"));
        assert_eq!(
            presence(Path::new("relative"))
                .expect_err("relative")
                .kind(),
            std::io::ErrorKind::InvalidInput
        );
    }

    #[test]
    fn presence_refuses_on_eacces() {
        crate::testutil::unprivileged("host_facts::tests::presence_refuses_on_eacces", || {
            let d = private_dir();
            let locked = d.path().join("locked");
            std::fs::create_dir(&locked).expect("mkdir");
            std::fs::set_permissions(&locked, std::fs::Permissions::from_mode(0o000))
                .expect("lock");
            let got = presence(&locked.join("inner"));
            std::fs::set_permissions(&locked, std::fs::Permissions::from_mode(0o700))
                .expect("restore");
            assert_eq!(
                got.expect_err("EACCES is not absence").kind(),
                std::io::ErrorKind::PermissionDenied
            );
        });
    }
}
