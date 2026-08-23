//! Fd-relative enumeration. Returns entries RAW — `.`/`..`, dotfiles, dirs and
//! symlinks all included, nothing refused or filtered.
//!
//! Classification and precedence stay with the parser (spec §8 Q2): dotfile-skip,
//! symlink/dir refusal, extension filtering and lexical sort are all `maknae-config`
//! policy. This crate's contribution is that `kind` is TRUSTWORTHY — resolved
//! fd-relatively and WITHOUT following the link. Given a correct kind, the caller's
//! policy is one match arm.

use crate::anchor::{Entry, Kind};
use crate::error::IoError;
use nix::sys::stat::FileStat;
use std::os::fd::AsFd;
use std::path::Path;

/// Map a `nix::dir::Type` to `Kind`. `nix::dir::Type` has seven variants; Fifo,
/// CharacterDevice, BlockDevice and Socket all collapse to `Other` — the caller
/// refuses what it must, and a FIFO or device is refused at read time by
/// `TargetRequired.regular_file`.
fn kind_of_type(t: nix::dir::Type) -> Kind {
    use nix::dir::Type;
    match t {
        Type::File => Kind::File,
        Type::Directory => Kind::Dir,
        Type::Symlink => Kind::Symlink,
        Type::Fifo | Type::CharacterDevice | Type::BlockDevice | Type::Socket => Kind::Other,
    }
}

/// Map an `S_IFMT` to `Kind`, for the `d_type == DT_UNKNOWN` fallback.
fn kind_of_mode(mode: u32) -> Kind {
    let fmt = mode & nix::libc::S_IFMT as u32;
    if fmt == nix::libc::S_IFREG as u32 {
        Kind::File
    } else if fmt == nix::libc::S_IFDIR as u32 {
        Kind::Dir
    } else if fmt == nix::libc::S_IFLNK as u32 {
        Kind::Symlink
    } else {
        Kind::Other
    }
}

/// Classify one entry. Pure over `(Option<Type>, stat_fn)` so the `None` arm is
/// reachable in a unit test: `d_type` is populated on ext4 and APFS alike (measured:
/// DT_UNKNOWN=0, xfs ftype=1), so the real fallback never runs on CI.
///
/// The fallback MUST use AT_SYMLINK_NOFOLLOW. Without it the stat follows the link and
/// a symlinked entry classifies as whatever it points at — the exact refusal this
/// exists to preserve.
pub(crate) fn classify_entry<S>(
    ty: Option<nix::dir::Type>,
    stat_fn: S,
) -> Result<Kind, nix::errno::Errno>
where
    S: FnOnce() -> nix::Result<FileStat>,
{
    match ty {
        Some(t) => Ok(kind_of_type(t)),
        None => Ok(kind_of_mode(stat_fn()?.st_mode as u32)),
    }
}

/// Enumerate a directory relative to a pinned dirfd, raw.
pub(crate) fn enumerate_fd<F: AsFd>(dirfd: &F, at: &Path) -> Result<Vec<Entry>, IoError> {
    // One conversion at the boundary: the inner fn propagates plain errnos, so the
    // three unprovokable failure points need one exception between them rather than
    // three, and none of them is a decision.
    enumerate_raw(dirfd).map_err(|e| crate::checks::map_errno_no_disambiguation(e, at))
}

fn enumerate_raw<F: AsFd>(dirfd: &F) -> nix::Result<Vec<Entry>> {
    // Dir::openat re-opens `.` rather than consuming the pinned fd: Dir::from_fd takes
    // the OwnedFd by value and its Drop closes it, which would destroy the pin.
    let mut d = crate::syscall::open_dir_handle(dirfd)?;

    let mut out = Vec::new();
    for ent in d.iter() {
        let ent = ent?;
        let name = std::ffi::OsStr::from_encoded_bytes_unchecked_shim(ent.file_name().to_bytes());
        let kind = classify_entry(ent.file_type(), || {
            crate::syscall::fstatat_nofollow(dirfd, &name.to_string_lossy())
        })?;
        out.push(Entry {
            name,
            kind,
            ino: ent.ino(),
        });
    }
    Ok(out)
}

/// `nix::dir::Entry::file_name()` returns `&CStr`, not `&OsStr`.
trait OsStrShim {
    fn from_encoded_bytes_unchecked_shim(b: &[u8]) -> std::ffi::OsString;
}
impl OsStrShim for std::ffi::OsStr {
    fn from_encoded_bytes_unchecked_shim(b: &[u8]) -> std::ffi::OsString {
        use std::os::unix::ffi::OsStrExt;
        std::ffi::OsStr::from_bytes(b).to_os_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn stat_of(p: &Path) -> nix::Result<FileStat> {
        let f = std::fs::File::open(p).unwrap();
        crate::syscall::fstat(&f)
    }

    /// d_type is populated on ext4 and APFS alike (measured: DT_UNKNOWN=0, xfs
    /// ftype=1), so the None arm never runs on CI. The seam is how it is reachable —
    /// exclude_globs would hide it, and a gate excuse is not a control.
    #[test]
    fn none_arm_falls_back_to_the_stat() {
        let d = tempfile::tempdir().unwrap();
        let f = d.path().join("regular");
        std::fs::write(&f, b"x").unwrap();
        let k = classify_entry(None, || stat_of(&f)).unwrap();
        assert_eq!(k, Kind::File);
    }

    #[test]
    fn none_arm_propagates_a_failing_stat() {
        let e = classify_entry(None, || Err(nix::errno::Errno::ENOENT)).unwrap_err();
        assert_eq!(e, nix::errno::Errno::ENOENT);
    }

    #[test]
    fn every_dir_type_maps() {
        use nix::dir::Type;
        assert_eq!(kind_of_type(Type::File), Kind::File);
        assert_eq!(kind_of_type(Type::Directory), Kind::Dir);
        assert_eq!(kind_of_type(Type::Symlink), Kind::Symlink);
        for t in [
            Type::Fifo,
            Type::CharacterDevice,
            Type::BlockDevice,
            Type::Socket,
        ] {
            assert_eq!(kind_of_type(t), Kind::Other, "{t:?}");
        }
    }

    /// The S_IFMT fallback must agree with the d_type mapping, or the two paths
    /// disagree on exactly the filesystems where only one of them runs.
    #[test]
    fn mode_mapping_agrees_with_type_mapping() {
        assert_eq!(kind_of_mode(nix::libc::S_IFREG as u32 | 0o644), Kind::File);
        assert_eq!(kind_of_mode(nix::libc::S_IFDIR as u32 | 0o755), Kind::Dir);
        assert_eq!(
            kind_of_mode(nix::libc::S_IFLNK as u32 | 0o777),
            Kind::Symlink
        );
        assert_eq!(kind_of_mode(nix::libc::S_IFIFO as u32 | 0o600), Kind::Other);
    }
}
