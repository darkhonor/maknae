//! Fd-relative enumeration. Returns entries RAW — `.`/`..`, dotfiles, dirs and
//! symlinks all included, nothing refused or filtered.
//!
//! Classification and precedence stay with the parser (spec §8 Q2): dotfile-skip,
//! symlink/dir refusal, extension filtering and lexical sort are all `maknae-config`
//! policy.
//!
//! WHAT `kind` GUARANTEES — narrowed from "TRUSTWORTHY" after external review. Where
//! the filesystem supplies `d_type`, `kind` and `ino` originate in the SAME directory
//! record. On the `DT_UNKNOWN` fallback the `fstatat` result is accepted only if its
//! inode MATCHES the dirent's — a mismatch (the name repointed between readdir and
//! stat) is refused as ESTALE rather than classified from the wrong inode. What no
//! enumeration API can promise: the name may be repointed AFTER `Entry` is returned.
//! Enumeration is therefore ADVISORY — a caller acting on an entry must go through
//! `Anchor::read`/`append`/`publish` with a `TargetRequired`, which re-checks on the
//! opened fd. That is the crate's actual guarantee; `Entry` alone is not one.

use crate::anchor::{Entry, Kind};
use crate::error::IoError;
use crate::syscall::mode_bits;
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
    let fmt = mode & mode_bits(nix::libc::S_IFMT);
    if fmt == mode_bits(nix::libc::S_IFREG) {
        Kind::File
    } else if fmt == mode_bits(nix::libc::S_IFDIR) {
        Kind::Dir
    } else if fmt == mode_bits(nix::libc::S_IFLNK) {
        Kind::Symlink
    } else {
        Kind::Other
    }
}

/// Classify one entry from its `d_type`, falling back to `fstatat` when the filesystem
/// returns `DT_UNKNOWN`. Takes `dirfd`, the entry's `raw` name, and `expected_ino` (the
/// dirent's inode) directly; the fallback arm is reachable in a unit test by passing
/// `None` for `ty`. `d_type` is populated on ext4 and APFS alike (measured:
/// DT_UNKNOWN=0, xfs ftype=1), so the fallback rarely runs on CI.
///
/// The fallback MUST use AT_SYMLINK_NOFOLLOW. Without it the stat follows the link and
/// a symlinked entry classifies as whatever it points at — the exact refusal this
/// exists to preserve. It also verifies the stat'd inode matches `expected_ino`,
/// refusing a name repointed between readdir and stat as ESTALE.
pub(crate) fn classify_entry<F: AsFd>(
    ty: Option<nix::dir::Type>,
    dirfd: &F,
    raw: &std::ffi::CStr,
    expected_ino: u64,
) -> Result<Kind, nix::errno::Errno> {
    match ty {
        Some(t) => Ok(kind_of_type(t)),
        None => {
            let st = crate::syscall::fstatat_nofollow(dirfd, raw)?;
            // The dirent gave us an inode; the fallback stat gives us another. If they
            // differ, the name was repointed between readdir and this stat, and the
            // mode we hold belongs to an inode the Entry does not name. Classifying
            // from it would resurrect the checked-vs-used-inode confusion INSIDE the
            // enumeration contract. Refuse instead: ESTALE, the stale-handle errno.
            if st.st_ino != expected_ino {
                return Err(nix::errno::Errno::ESTALE);
            }
            Ok(kind_of_mode(mode_bits(st.st_mode)))
        }
    }
}

/// Enumerate a directory relative to a pinned dirfd, raw.
pub(crate) fn enumerate_fd<F: AsFd>(dirfd: &F, at: &Path) -> Result<Vec<Entry>, IoError> {
    // One CONVERSION at the boundary: the inner fn propagates plain errnos, so each
    // exception downstream names an arm rather than a `map_err` closure. (It does not
    // reduce the exception COUNT — the contract now carries this boundary plus three
    // interior arms — which is what an earlier version of this comment claimed.)
    enumerate_raw(dirfd).map_err(|e| crate::checks::map_errno_no_disambiguation(e, at))
}

fn enumerate_raw<F: AsFd>(dirfd: &F) -> nix::Result<Vec<Entry>> {
    // Dir::openat re-opens `.` rather than consuming the pinned fd: Dir::from_fd takes
    // the OwnedFd by value and its Drop closes it, which would destroy the pin.
    let mut d = crate::syscall::open_dir_handle(dirfd)?;

    let mut out = Vec::new();
    for ent in d.iter() {
        let ent = ent?;
        // Stat the entry's RAW name, never a UTF-8 rendering of it. `to_string_lossy`
        // replaces each invalid byte with U+FFFD, so for a name like b"\xff\xfe" --
        // legal on ext4 and xfs -- the bytes handed to fstatat are
        // b"\xef\xbf\xbd\xef\xbf\xbd", a DIFFERENT path. Either it does not exist and
        // one odd filename fails the whole listing, or an attacker who can write into
        // the directory plants a decoy at that literal U+FFFD name and the symlink is
        // classified from the DECOY's st_mode -- reported as Kind::File. That falsifies
        // this module's central claim that `kind` is trustworthy. `CStr: NixPath`, so
        // the raw bytes go to the syscall untouched.
        let raw = ent.file_name();
        let name = std::ffi::OsStr::from_encoded_bytes_unchecked_shim(raw.to_bytes());
        let kind = classify_entry(ent.file_type(), dirfd, raw, ent.ino())?;
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

    fn dirfd_of(p: &Path) -> std::os::fd::OwnedFd {
        crate::syscall::open_parent_by_path(p).unwrap()
    }

    fn cstr(bytes: &[u8]) -> std::ffi::CString {
        std::ffi::CString::new(bytes).unwrap()
    }

    /// d_type is populated on ext4 and APFS alike (measured: DT_UNKNOWN=0, xfs
    /// ftype=1), so the None arm never runs on CI. The seam is how it is reachable —
    /// exclude_globs would hide it, and a gate excuse is not a control.
    #[test]
    fn none_arm_falls_back_to_the_stat() {
        let d = tempfile::tempdir().unwrap();
        std::fs::write(d.path().join("regular"), b"x").unwrap();
        let fd = dirfd_of(d.path());
        let ino = std::os::unix::fs::MetadataExt::ino(
            &std::fs::symlink_metadata(d.path().join("regular")).unwrap(),
        );
        let k = classify_entry(None, &fd, cstr(b"regular").as_c_str(), ino).unwrap();
        assert_eq!(k, Kind::File);
    }

    #[test]
    fn none_arm_propagates_a_failing_stat() {
        let d = tempfile::tempdir().unwrap();
        let fd = dirfd_of(d.path());
        let e = classify_entry(None, &fd, cstr(b"missing").as_c_str(), 0).unwrap_err();
        assert_eq!(e, nix::errno::Errno::ENOENT);
    }

    /// The DT_UNKNOWN fallback must refuse a repointed name, not classify the wrong
    /// inode. The dirent said inode A; if the stat comes back with inode B, the name
    /// changed between readdir and stat, and returning B's kind under A's ino is a
    /// self-contradictory Entry — the checked-vs-used confusion inside the enumeration
    /// contract. External review (Codex) found exactly this; the race itself cannot be
    /// staged deterministically, but the DECISION can: hand the fallback a dirent ino
    /// that does not match, and it must come back ESTALE.
    #[test]
    fn fallback_refuses_a_repointed_name_as_estale() {
        let d = tempfile::tempdir().unwrap();
        std::fs::write(d.path().join("x"), b"a").unwrap();
        let fd = dirfd_of(d.path());
        let real = std::os::unix::fs::MetadataExt::ino(
            &std::fs::symlink_metadata(d.path().join("x")).unwrap(),
        );
        let e = classify_entry(None, &fd, cstr(b"x").as_c_str(), real + 1).unwrap_err();
        assert_eq!(e, nix::errno::Errno::ESTALE);
        // And the matching ino still classifies.
        let k = classify_entry(None, &fd, cstr(b"x").as_c_str(), real).unwrap();
        assert_eq!(k, Kind::File);
    }

    /// A non-UTF-8 entry name must be stat'd as its RAW bytes.
    ///
    /// This is the control the `to_string_lossy` fix went in without. Measured: with
    /// the fix reverted, the whole suite stayed green, because the old signature took
    /// an injected `stat_fn` and so held `kind_of_mode` rather than the name that was
    /// actually being passed to the syscall. The fallback now takes the dirfd and the
    /// raw `CStr` directly, which is what makes the bug reachable from a test.
    ///
    /// Fixture is the attack: `\xff\xfe` is a SYMLINK; a decoy REGULAR FILE sits at
    /// the literal U+FFFD U+FFFD name that `to_string_lossy` would have produced.
    /// Classifying the symlink must not consult the decoy.
    ///
    /// Linux-only, and not for convenience: APFS ENFORCES valid UTF-8 in filenames and
    /// rejects the fixture with EILSEQ, so the attack cannot even be staged on darwin.
    /// ext4 and xfs accept arbitrary bytes, and those are what this project deploys on
    /// (Rocky/RHEL), so the exposure is real where it counts. The skip below is loud
    /// rather than silent -- a quiet `return` would make a green run indistinguishable
    /// from a run that never tested anything.
    #[cfg(target_os = "linux")]
    #[test]
    fn a_non_utf8_entry_is_stat_by_its_raw_bytes_not_a_lossy_rendering() {
        use std::os::unix::ffi::OsStrExt;
        let d = tempfile::tempdir().unwrap();
        let odd = std::ffi::OsStr::from_bytes(b"\xff\xfe");
        if std::os::unix::fs::symlink("/etc/hostname", d.path().join(odd)).is_err() {
            crate::testutil::skip_or_fail(
                "a_non_utf8_entry_is_stat_by_its_raw_bytes_not_a_lossy_rendering",
                "the filesystem refuses non-UTF-8 names (EILSEQ), so the raw-name \
                 classification has no fixture",
            );
            return;
        }
        // The decoy: exactly what to_string_lossy(b"\xff\xfe") renders to.
        let decoy = String::from_utf8_lossy(b"\xff\xfe").into_owned();
        std::fs::write(d.path().join(&decoy), b"decoy").unwrap();

        let fd = dirfd_of(d.path());
        let odd_ino = std::os::unix::fs::MetadataExt::ino(
            &std::fs::symlink_metadata(d.path().join(odd)).unwrap(),
        );
        let k = classify_entry(None, &fd, cstr(b"\xff\xfe").as_c_str(), odd_ino).unwrap();
        assert_eq!(
            k,
            Kind::Symlink,
            "classified from the decoy inode, not the entry"
        );

        // And the decoy itself really is a regular file, so the assertion above
        // discriminates rather than passing for an unrelated reason.
        let decoy_ino = std::os::unix::fs::MetadataExt::ino(
            &std::fs::symlink_metadata(d.path().join(&decoy)).unwrap(),
        );
        let dk = classify_entry(None, &fd, cstr(decoy.as_bytes()).as_c_str(), decoy_ino).unwrap();
        assert_eq!(dk, Kind::File);
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
        assert_eq!(
            kind_of_mode(mode_bits(nix::libc::S_IFREG) | 0o644),
            Kind::File
        );
        assert_eq!(
            kind_of_mode(mode_bits(nix::libc::S_IFDIR) | 0o755),
            Kind::Dir
        );
        assert_eq!(
            kind_of_mode(mode_bits(nix::libc::S_IFLNK) | 0o777),
            Kind::Symlink
        );
        assert_eq!(
            kind_of_mode(mode_bits(nix::libc::S_IFIFO) | 0o600),
            Kind::Other
        );
    }
}
