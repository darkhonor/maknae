use std::fs::File;
use std::io;
#[cfg(target_os = "macos")]
use std::os::macos::fs::MetadataExt;

const FS_APPEND_FL: libc::c_int = 0x0000_0020;
const SF_APPEND: u32 = 0x0004_0000;
const UNSUPPORTED: [libc::c_int; 4] = [libc::ENOTTY, libc::ENOTSUP, libc::EOPNOTSUPP, libc::EINVAL];

/// Whether the open file carries an append-only flag only root can clear
/// (`FS_APPEND_FL`; macOS `SF_APPEND`). A filesystem that cannot report flags answers `Ok(false)`.
pub fn is_append_only(file: &File) -> io::Result<bool> {
    #[cfg(target_os = "linux")]
    return crate::linux::inode_flags(file)
        .map_or_else(unsupported_is_false, |f| Ok(append_bit(f)));
    #[cfg(target_os = "macos")]
    return file.metadata().map(|m| system_append_bit(m.st_flags()));
}

#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
fn append_bit(flags: libc::c_int) -> bool {
    flags & FS_APPEND_FL != 0
}

#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
fn unsupported_is_false(e: io::Error) -> io::Result<bool> {
    match e.raw_os_error() {
        Some(errno) if UNSUPPORTED.contains(&errno) => Ok(false),
        _ => Err(e),
    }
}

#[cfg_attr(not(target_os = "macos"), allow(dead_code))]
fn system_append_bit(st_flags: u32) -> bool {
    st_flags & SF_APPEND != 0
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp(tag: &str) -> (std::path::PathBuf, File) {
        let p = std::env::temp_dir().join(format!("maknae_sys_flags_{}_{tag}", std::process::id()));
        let _ = std::fs::remove_file(&p);
        let f = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&p)
            .unwrap();
        (p, f)
    }

    #[test]
    fn a_plain_file_is_not_append_only() {
        let (p, f) = temp("plain");
        assert!(!is_append_only(&f).unwrap());
        std::fs::remove_file(p).unwrap();
    }

    #[test]
    fn a_descriptor_that_cannot_report_flags_answers_false() {
        let (socket, _peer) = std::os::unix::net::UnixStream::pair().unwrap();
        let f = File::from(std::os::fd::OwnedFd::from(socket));
        assert!(!is_append_only(&f).unwrap());
    }

    #[test]
    fn the_flag_parser_reads_only_the_append_bit() {
        assert!(append_bit(0x20));
        assert!(append_bit(0x20 | 0x10));
        assert!(!append_bit(0x10));
        assert!(!append_bit(0));
        assert!(!append_bit(!0x20));
    }

    #[test]
    fn the_stat_parser_reads_only_the_system_append_bit() {
        assert!(system_append_bit(0x0004_0000));
        assert!(system_append_bit(0x0004_0000 | 0x0002_0000));
        assert!(!system_append_bit(0x0000_0004));
        assert!(!system_append_bit(0));
        assert!(!system_append_bit(!0x0004_0000));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn the_flag_value_is_the_kernel_header_value() {
        assert_eq!(FS_APPEND_FL, 0x20);
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn the_stat_flag_values_are_the_system_header_values() {
        assert_eq!(SF_APPEND, libc::SF_APPEND);
        assert!(!system_append_bit(libc::UF_APPEND));
    }

    #[test]
    fn an_unsupported_filesystem_answers_false() {
        for errno in [libc::ENOTTY, libc::ENOTSUP, libc::EOPNOTSUPP, libc::EINVAL] {
            assert!(
                !unsupported_is_false(io::Error::from_raw_os_error(errno)).unwrap(),
                "{errno}"
            );
        }
        for errno in [libc::EIO, libc::EBADF, libc::EACCES] {
            assert_eq!(
                unsupported_is_false(io::Error::from_raw_os_error(errno))
                    .unwrap_err()
                    .raw_os_error(),
                Some(errno)
            );
        }
        assert!(unsupported_is_false(io::Error::other("no errno")).is_err());
    }

    /// Kernel reference: `chattr +a` then `lsattr`, as root only (setting the flag needs
    /// CAP_LINUX_IMMUTABLE). Run with `sudo cargo test -p maknae-sys -- --ignored`.
    #[cfg(target_os = "linux")]
    #[test]
    #[ignore = "root: sets the append-only attribute with chattr"]
    fn agrees_with_lsattr_on_a_file_root_made_append_only() {
        let (p, f) = temp("chattr");
        assert!(std::process::Command::new("chattr")
            .arg("+a")
            .arg(&p)
            .status()
            .unwrap()
            .success());
        let lsattr = std::process::Command::new("lsattr")
            .arg("-d")
            .arg(&p)
            .output()
            .unwrap();
        let flags = String::from_utf8(lsattr.stdout).unwrap();
        let answer = is_append_only(&f).unwrap();
        assert!(std::process::Command::new("chattr")
            .arg("-a")
            .arg(&p)
            .status()
            .unwrap()
            .success());
        std::fs::remove_file(p).unwrap();
        assert!(answer);
        assert_eq!(
            answer,
            flags.split_whitespace().next().unwrap().contains('a')
        );
    }

    /// The owner can set and clear `uappnd`, so it does not count.
    #[cfg(target_os = "macos")]
    #[test]
    fn a_user_append_only_flag_is_not_enough() {
        let (p, f) = temp("uappnd");
        assert!(std::process::Command::new("chflags")
            .arg("uappnd")
            .arg(&p)
            .status()
            .unwrap()
            .success());
        let flagged = f.metadata().unwrap().st_flags() & libc::UF_APPEND != 0;
        let answer = is_append_only(&f).unwrap();
        assert!(std::process::Command::new("chflags")
            .arg("nouappnd")
            .arg(&p)
            .status()
            .unwrap()
            .success());
        std::fs::remove_file(p).unwrap();
        assert!(flagged);
        assert!(!answer);
    }

    /// Kernel reference: `chflags sappnd` then `stat -f %Sf`; root only.
    /// Run with `sudo cargo test -p maknae-sys -- --ignored`.
    #[cfg(target_os = "macos")]
    #[test]
    #[ignore = "root: sets the system append-only flag with chflags sappnd"]
    fn agrees_with_stat_on_a_file_flagged_sappnd() {
        let (p, f) = temp("sappnd");
        assert!(std::process::Command::new("chflags")
            .arg("sappnd")
            .arg(&p)
            .status()
            .unwrap()
            .success());
        let out = std::process::Command::new("stat")
            .args(["-f", "%Sf"])
            .arg(&p)
            .output()
            .unwrap();
        let answer = is_append_only(&f).unwrap();
        assert!(std::process::Command::new("chflags")
            .arg("nosappnd")
            .arg(&p)
            .status()
            .unwrap()
            .success());
        std::fs::remove_file(p).unwrap();
        assert!(answer);
        assert_eq!(
            answer,
            String::from_utf8(out.stdout).unwrap().contains("sappnd")
        );
    }
}
