//! Host facts the kernel's per-session checks read (#115): kernel pseudo-files,
//! a peer's process handle, the console owner, path presence and the login records.

use std::io;
use std::path::Path;

use nix::errno::Errno;
use zeroize::Zeroizing;

use crate::checks::{map_errno_no_disambiguation, require_regular_file, AnchorRequired};
use crate::error::IoError;
use crate::syscall;

const PSEUDO_FILE_PARENT: AnchorRequired = AnchorRequired {
    owner: None,
    mode_mask: Some(0o022),
};

/// Read a kernel or runtime pseudo-file whole: an absolute path to a regular file,
/// opened without following a final symlink beneath a parent no group or other
/// may write. Reads to EOF rather than trusting `st_size`, which procfs reports as
/// 0. More than `cap` bytes is `TargetTooLarge`, whose `actual` is then `cap + 1`.
pub fn read_pseudo_file(path: &Path, cap: usize) -> Result<Zeroizing<Vec<u8>>, IoError> {
    let parent = path.parent().ok_or(IoError::RootAnchor)?;
    let name = match path.file_name() {
        None => {
            return Err(IoError::AnchorEndsInDotDot {
                path: path.to_path_buf(),
            })
        }
        Some(os) => os.to_str().ok_or_else(|| IoError::NonUtf8Component {
            path: path.to_path_buf(),
        })?,
    };
    let anchor =
        crate::open_anchor_resolved(parent, PSEUDO_FILE_PARENT, crate::StrategyPref::Auto)?;
    let fd = syscall::open_read_target(anchor.fd(), name)
        .map_err(|e| map_errno_no_disambiguation(e, path))?;
    let st = syscall::fstat(&fd).map_err(|e| map_errno_no_disambiguation(e, path))?;
    require_regular_file(&st, path)?;

    let mut buf = Zeroizing::new(vec![0u8; cap.saturating_add(1)]);
    let mut n = 0;
    while n < buf.len() {
        match nix::unistd::read(&fd, &mut buf[n..]) {
            Ok(0) => break,
            Err(Errno::EINTR) => continue,
            Err(e) => return Err(map_errno_no_disambiguation(e, path)),
            Ok(k) => n += k,
        }
    }
    if n > cap {
        return Err(IoError::TargetTooLarge {
            path: path.to_path_buf(),
            limit: cap as u64,
            actual: n as u64,
        });
    }
    buf.truncate(n);
    Ok(buf)
}

/// A process handle for `pid`, which stays bound to that process after it exits.
#[cfg(target_os = "linux")]
pub fn pidfd_open(pid: i32) -> io::Result<std::os::fd::OwnedFd> {
    let pid = (pid > 0)
        .then(|| rustix::process::Pid::from_raw(pid))
        .flatten()
        .ok_or_else(|| io::Error::from_raw_os_error(nix::libc::EINVAL))?;
    Ok(rustix::process::pidfd_open(
        pid,
        rustix::process::PidfdFlags::empty(),
    )?)
}

/// The uid that owns `/dev/console`, which loginwindow assigns to the console user.
pub fn console_owner_uid() -> io::Result<u32> {
    char_device_owner(Path::new("/dev/console"))
}

fn char_device_owner(path: &Path) -> io::Result<u32> {
    let st = syscall::lstat_path(path)?;
    let fmt = syscall::mode_bits(st.st_mode) & syscall::mode_bits(nix::libc::S_IFMT);
    if fmt != syscall::mode_bits(nix::libc::S_IFCHR) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("{} is not a character device", path.display()),
        ));
    }
    Ok(st.st_uid)
}

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

/// The user names of the current `USER_PROCESS` login records.
#[cfg(target_os = "macos")]
pub fn logged_in_users() -> io::Result<Vec<String>> {
    maknae_sys::utmpx_user_processes()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    #[cfg(target_os = "linux")]
    #[test]
    fn a_proc_file_reads_despite_zero_size() {
        let p = Path::new("/proc/self/cgroup");
        assert_eq!(std::fs::metadata(p).expect("stat").len(), 0);
        let got = read_pseudo_file(p, 64 * 1024).expect("read");
        assert!(!got.is_empty());
    }

    #[test]
    fn a_file_within_cap_reads_whole() {
        let d = tempfile::tempdir().expect("tempdir");
        let p = d.path().join("f");
        std::fs::write(&p, [7u8; 100]).expect("write");
        assert_eq!(
            read_pseudo_file(&p, 100).expect("read").as_slice(),
            &[7u8; 100]
        );
    }

    #[test]
    fn a_file_over_cap_is_refused() {
        let d = tempfile::tempdir().expect("tempdir");
        let p = d.path().join("f");
        std::fs::write(&p, [7u8; 100]).expect("write");
        match read_pseudo_file(&p, 10) {
            Err(IoError::TargetTooLarge { path, limit, .. }) => {
                assert_eq!((path, limit), (p, 10));
            }
            other => panic!("over cap must be refused: {other:?}"),
        }
    }

    #[test]
    fn a_symlink_leaf_is_refused() {
        let d = tempfile::tempdir().expect("tempdir");
        let real = d.path().join("real");
        std::fs::write(&real, b"x").expect("write");
        let link = d.path().join("link");
        std::os::unix::fs::symlink(&real, &link).expect("symlink");
        match read_pseudo_file(&link, 64) {
            Err(IoError::Symlink { path }) => assert_eq!(path, link),
            other => panic!("a symlink leaf must be refused: {other:?}"),
        }
    }

    #[test]
    fn a_non_regular_leaf_is_refused() {
        let d = tempfile::tempdir().expect("tempdir");
        let pipe = d.path().join("pipe");
        nix::unistd::mkfifo(&pipe, nix::sys::stat::Mode::S_IRUSR).expect("mkfifo");
        match read_pseudo_file(&pipe, 64) {
            Err(IoError::NotRegularFile { path }) => assert_eq!(path, pipe),
            other => panic!("a fifo must be refused: {other:?}"),
        }
    }

    #[test]
    fn a_writable_parent_is_refused() {
        let d = tempfile::tempdir().expect("tempdir");
        let p = d.path().join("f");
        std::fs::write(&p, b"x").expect("write");
        std::fs::set_permissions(d.path(), std::fs::Permissions::from_mode(0o777)).expect("chmod");
        let got = read_pseudo_file(&p, 64);
        std::fs::set_permissions(d.path(), std::fs::Permissions::from_mode(0o700))
            .expect("restore");
        match got {
            Err(IoError::InsecurePermissions { .. }) => {}
            other => panic!("a group- or world-writable parent must be refused: {other:?}"),
        }
    }

    #[test]
    fn a_path_with_no_usable_leaf_is_refused() {
        use std::os::unix::ffi::OsStrExt;
        assert_eq!(
            read_pseudo_file(Path::new("/"), 64),
            Err(IoError::RootAnchor)
        );
        let dotdot = Path::new("/proc/..");
        assert_eq!(
            read_pseudo_file(dotdot, 64),
            Err(IoError::AnchorEndsInDotDot {
                path: dotdot.to_path_buf()
            })
        );
        let odd = Path::new(std::ffi::OsStr::from_bytes(b"/tmp/\xff"));
        assert_eq!(
            read_pseudo_file(odd, 64),
            Err(IoError::NonUtf8Component {
                path: odd.to_path_buf()
            })
        );
    }

    #[test]
    fn a_relative_path_is_refused() {
        match read_pseudo_file(Path::new("relative"), 64) {
            Err(IoError::RelativeAnchor { .. }) => {}
            other => panic!("a relative path must be refused: {other:?}"),
        }
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn pidfd_open_of_self_succeeds() {
        assert!(pidfd_open(std::process::id() as i32).is_ok());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn pidfd_open_of_unused_pid_fails() {
        assert!(pidfd_open(i32::MAX).is_err());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn pidfd_open_of_a_non_positive_pid_fails() {
        for pid in [0, -1] {
            assert_eq!(
                pidfd_open(pid).expect_err("refused").raw_os_error(),
                Some(nix::libc::EINVAL),
                "{pid}"
            );
        }
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn console_owner_is_a_uid() {
        assert!(console_owner_uid().is_ok());
    }

    #[test]
    fn a_character_device_reports_its_owner() {
        assert_eq!(char_device_owner(Path::new("/dev/null")).expect("owner"), 0);
    }

    #[test]
    fn a_non_device_has_no_console_owner() {
        let d = tempfile::tempdir().expect("tempdir");
        let f = d.path().join("console");
        std::fs::write(&f, b"x").expect("write");
        assert_eq!(
            char_device_owner(&f).expect_err("refused").kind(),
            std::io::ErrorKind::InvalidData
        );
        let link = d.path().join("link");
        std::os::unix::fs::symlink("/dev/null", &link).expect("symlink");
        assert_eq!(
            char_device_owner(&link)
                .expect_err("a symlink is not followed")
                .kind(),
            std::io::ErrorKind::InvalidData
        );
    }

    #[test]
    fn presence_reports_absent_present_and_refuses_on_eacces() {
        let d = tempfile::tempdir().expect("tempdir");
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
        if nix::unistd::geteuid().is_root() {
            eprintln!("SKIP: root ignores the permission bits the EACCES probe sets");
            return;
        }
        let locked = d.path().join("locked");
        std::fs::create_dir(&locked).expect("mkdir");
        std::fs::set_permissions(&locked, std::fs::Permissions::from_mode(0o000)).expect("lock");
        let got = presence(&locked.join("inner"));
        std::fs::set_permissions(&locked, std::fs::Permissions::from_mode(0o700)).expect("restore");
        assert_eq!(
            got.expect_err("EACCES is not absence").kind(),
            std::io::ErrorKind::PermissionDenied
        );
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn logged_in_users_lists() {
        assert!(logged_in_users().is_ok());
    }
}
