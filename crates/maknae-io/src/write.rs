//! Mode A (atomic publish) and Mode B (append-only).
//!
//! Both are unconditionally portable: Mode A needs a **dirfd to `renameat` against**,
//! which the whole-remainder `openat2` lane never yields.

use crate::anchor::{Mode, Strategy};
use crate::error::IoError;
use crate::syscall;
use std::os::fd::{AsFd, OwnedFd};
use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};

/// Process-global, not per-`Anchor`: two `Anchor`s in one process would otherwise
/// both start at 0 and collide on the same temp name with `O_EXCL` and no retry.
static TEMP_COUNTER: AtomicU64 = AtomicU64::new(0);

/// `.<name>.tmp.<pid>.<counter>`. The pid is not decoration: without it a counter
/// restarting at 0 each process means one temp orphaned by SIGKILL between `openat`
/// and `renameat` collides on the FIRST publish of every subsequent process — publish
/// wedged permanently. With it, a stale temp from a dead process cannot be re-hit.
pub(crate) fn temp_name(final_name: &str) -> String {
    format!(
        ".{}.tmp.{}.{}",
        final_name,
        std::process::id(),
        TEMP_COUNTER.fetch_add(1, Ordering::Relaxed)
    )
}

/// Publish bytes atomically into the directory `dirfd` names.
///
/// openat(O_CREAT|O_EXCL) temp -> write -> fsync temp -> renameat -> fsync dirfd.
/// The temp is unlinked on any failure after create, best-effort: the caller always
/// gets the ORIGINAL error, never a masking unlink error.
pub(crate) fn publish_at<F: AsFd>(
    dirfd: &F,
    final_name: &str,
    at: &Path,
    bytes: &[u8],
    mode: Mode,
) -> Result<Strategy, IoError> {
    // One CONVERSION at the boundary: the inner fn propagates plain errnos, so each
    // exception downstream names an arm rather than a `map_err` closure. It does not
    // reduce the exception count.
    publish_raw(dirfd, final_name, bytes, mode)
        .map(|()| Strategy::Portable)
        .map_err(|e| crate::checks::map_errno_no_disambiguation(e, at))
}

fn publish_raw<F: AsFd>(dirfd: &F, final_name: &str, bytes: &[u8], mode: Mode) -> nix::Result<()> {
    let tmp = temp_name(final_name);
    let fd = syscall::open_temp_excl(dirfd, &tmp, mode)?;

    // Cleanup is best-effort and deliberately `let _ =`: the caller must keep the
    // ORIGINAL error, never a masking unlink error.
    if let Err(write_err) = write_all_sync(&fd, bytes) {
        let _ = syscall::unlink_at(dirfd, &tmp);
        return Err(write_err);
    }
    drop(fd);

    if let Err(e) = syscall::rename_at(dirfd, &tmp, final_name) {
        let _ = syscall::unlink_at(dirfd, &tmp);
        return Err(e);
    }

    syscall::fsync_fd(dirfd)
}

/// The shared write loop. Both modes need it, and duplicating it would duplicate its
/// unprovokable non-progress arms — and make the exception anchor ambiguous.
fn write_all(fd: &OwnedFd, bytes: &[u8]) -> nix::Result<()> {
    // Advance a SLICE rather than an index. The index form (`n += k`, loop on
    // `n != bytes.len()`) carries an arithmetic operator that cargo-mutants
    // rewrites to `n *= k`; that pins n at zero, the write keeps succeeding, and
    // the loop cannot terminate -- reported as a TIMEOUT, on which cargo-mutants
    // exits 3 and the mutation gate goes red. Re-slicing has no arithmetic to
    // mutate and is the idiom std::io::Write::write_all itself uses.
    let mut rest = bytes;
    while !rest.is_empty() {
        match nix::unistd::write(fd, rest) {
            // Non-progress arms first, covered progress arm last -- see the read
            // loop in anchor.rs for why ordering rather than a guard.
            Ok(0) => break,
            Err(nix::errno::Errno::EINTR) => continue,
            Err(e) => return Err(e),
            Ok(k) => rest = &rest[k..],
        }
    }
    // `Ok(0)` breaks the loop with the write incomplete. Reporting success there
    // would let `publish` fsync and `renameat` a TRUNCATED file into the final
    // name, and let `append` report a partial audit record as written -- both
    // silent. A function named write_all does not return Ok having written less.
    if rest.is_empty() {
        Ok(())
    } else {
        Err(nix::errno::Errno::EIO)
    }
}

fn write_all_sync(fd: &OwnedFd, bytes: &[u8]) -> nix::Result<()> {
    // The trailing comments on this line and its Mode B twin are LOAD-BEARING: they
    // are what makes each line unique, and coverage-tiers.toml anchors an exception on
    // each. Deleting one makes its anchor match zero lines and the gate hard-fails —
    // fail-closed, but surprising if you do not know.
    write_all(fd, bytes)?; // Mode A: a temp file this function just created
    syscall::fsync_fd(fd)
}

/// Append bytes to a file in the directory `dirfd` names, creating it if absent.
///
/// The fstat after the open is not a formality: `grants.d` is daemon-writable by
/// design, so a compromised writer can hard-link a file from outside the anchor into
/// the overlay, and `st_nlink == 1` is the only detector.
pub(crate) fn append_at<F: AsFd>(
    dirfd: &F,
    name: &str,
    at: &Path,
    bytes: &[u8],
    mode: Mode,
    target: &crate::checks::TargetRequired,
) -> Result<Strategy, IoError> {
    let fd = syscall::open_append(dirfd, name, mode)
        .map_err(|e| crate::checks::map_errno_no_disambiguation(e, at))?;

    let st = syscall::fstat(&fd).map_err(|e| crate::checks::map_errno_no_disambiguation(e, at))?;
    crate::checks::check_target(&st, at, target)?;

    append_raw(&fd, bytes).map_err(|e| crate::checks::map_errno_no_disambiguation(e, at))?;
    Ok(Strategy::Portable)
}

fn append_raw(fd: &OwnedFd, bytes: &[u8]) -> nix::Result<()> {
    write_all(fd, bytes)?; // Mode B: a caller-supplied inode
                           // sync_data per append; NO parent fsync — maknae-audit-append's sink has none
                           // today (only sync_data), so adding one would be a change, not the preservation
                           // the spec claims, and with O_CREAT and no O_EXCL "at create" is not detectable
                           // from the open anyway.
    syscall::sync_data(fd)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn temp_open_refuses_a_preexisting_name() {
        let d = tempfile::tempdir().unwrap();
        let dirfd = std::fs::File::open(d.path()).unwrap();
        std::fs::write(d.path().join("squat"), b"there first").unwrap();
        let e = crate::syscall::open_temp_excl(&dirfd, "squat", Mode(0o600)).unwrap_err();
        assert_eq!(e, nix::errno::Errno::EEXIST);
    }

    #[test]
    fn temp_open_refuses_a_preexisting_symlink() {
        let d = tempfile::tempdir().unwrap();
        let dirfd = std::fs::File::open(d.path()).unwrap();
        std::os::unix::fs::symlink("/etc/passwd", d.path().join("squat")).unwrap();
        let e = crate::syscall::open_temp_excl(&dirfd, "squat", Mode(0o600)).unwrap_err();
        assert_eq!(
            e,
            nix::errno::Errno::EEXIST,
            "O_EXCL must refuse a symlink too"
        );
    }

    /// The pid is not decoration: without it a counter restarting at 0 each process
    /// makes one orphaned temp collide on the first publish of every later process.
    #[test]
    fn temp_names_carry_the_pid_and_are_monotonic() {
        let a = temp_name("f.yaml");
        let b = temp_name("f.yaml");
        assert_ne!(a, b, "counter must advance");
        let pid = std::process::id().to_string();
        assert!(a.contains(&pid) && b.contains(&pid), "{a} / {b}");
        assert!(a.starts_with(".f.yaml.tmp."), "{a}");
    }
}
