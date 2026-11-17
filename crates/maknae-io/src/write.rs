//! Mode A (atomic publish) and Mode B (append-only).
//!
//! Both are unconditionally portable: Mode A needs a **dirfd to `renameat` against**,
//! which the whole-remainder `openat2` lane never yields.

use crate::anchor::{FileOwner, Mode, Strategy};
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
/// A failed dirfd fsync is `IoError::PublishedNotDurable`: the rename has happened.
/// The temp is unlinked on any failure after create, best-effort: the caller always
/// gets the ORIGINAL error, never a masking unlink error.
pub(crate) fn publish_at<F: AsFd>(
    dirfd: &F,
    final_name: &str,
    at: &Path,
    bytes: &[u8],
    mode: Mode,
    owner: Option<FileOwner>,
) -> Result<Strategy, IoError> {
    // One CONVERSION at the boundary: the inner fn propagates plain errnos, so each
    // exception downstream names an arm rather than a `map_err` closure. It does not
    // reduce the exception count.
    publish_synced(dirfd, final_name, at, bytes, mode, owner, syscall::fsync_fd)
}

/// After the rename the final name holds the new bytes, so a failed directory sync is
/// `PublishedNotDurable`, never a not-published error.
fn publish_synced<F: AsFd>(
    dirfd: &F,
    final_name: &str,
    at: &Path,
    bytes: &[u8],
    mode: Mode,
    owner: Option<FileOwner>,
    sync_dir: impl FnOnce(&F) -> nix::Result<()>,
) -> Result<Strategy, IoError> {
    publish_raw(
        dirfd,
        final_name,
        bytes,
        mode,
        owner,
        true,
        syscall::unlink_at,
    )
    .map_err(|e| crate::checks::map_errno_no_disambiguation(e, at))?;
    sync_dir(dirfd).map_err(|e| IoError::PublishedNotDurable {
        path: at.to_path_buf(),
        kind: crate::checks::kind_of_errno(e),
    })?;
    Ok(Strategy::Portable)
}

/// `publish_at` that never replaces: an existing `final_name` is left untouched and reported as `false`.
pub(crate) fn publish_new_at<F: AsFd>(
    dirfd: &F,
    final_name: &str,
    at: &Path,
    bytes: &[u8],
    mode: Mode,
    owner: FileOwner,
) -> Result<bool, IoError> {
    publish_new_synced(
        dirfd,
        final_name,
        at,
        bytes,
        mode,
        owner,
        Seams {
            sync_dir: syscall::fsync_fd,
            unlink_linked: syscall::unlink_at,
        },
    )
}

struct Seams<S, U> {
    sync_dir: S,
    unlink_linked: U,
}

fn publish_new_synced<F: AsFd>(
    dirfd: &F,
    final_name: &str,
    at: &Path,
    bytes: &[u8],
    mode: Mode,
    owner: FileOwner,
    seams: Seams<impl FnOnce(&F) -> nix::Result<()>, impl Fn(&F, &str) -> nix::Result<()>>,
) -> Result<bool, IoError> {
    let created = publish_raw(
        dirfd,
        final_name,
        bytes,
        mode,
        Some(owner),
        false,
        seams.unlink_linked,
    )
    .map_err(|e| crate::checks::map_errno_no_disambiguation(e, at))?;
    if !created {
        settle_existing(dirfd, final_name, at)?;
    }
    (seams.sync_dir)(dirfd).map_err(|e| IoError::PublishedNotDurable {
        path: at.to_path_buf(),
        kind: crate::checks::kind_of_errno(e),
    })?;
    Ok(created)
}

/// Removes only publish temp names that share the final's inode; any other link is refused.
fn settle_existing<F: AsFd>(dirfd: &F, final_name: &str, at: &Path) -> Result<(), IoError> {
    let map = |e| crate::checks::map_errno_no_disambiguation(e, at);
    let multiply_linked = |nlink| IoError::MultiplyLinked {
        path: at.to_path_buf(),
        nlink,
    };
    let st = syscall::fstatat_nofollow(dirfd, final_name).map_err(map)?;
    let nlink = syscall::nlink_count(st.st_nlink);
    if nlink <= 1 {
        return Ok(());
    }
    let mut dir = syscall::open_dir_handle(dirfd).map_err(map)?;
    let mut leftovers = Vec::new();
    for ent in dir.iter() {
        let ent = ent.map_err(map)?;
        if !is_temp_name_of(ent.file_name().to_bytes(), final_name) {
            continue;
        }
        let Ok(t) = syscall::fstatat_nofollow(dirfd, ent.file_name()) else {
            continue;
        };
        if (t.st_dev, t.st_ino) == (st.st_dev, st.st_ino) {
            leftovers.push(ent.file_name().to_owned());
        }
    }
    if leftovers.is_empty() {
        return Err(multiply_linked(nlink));
    }
    for name in &leftovers {
        syscall::unlink_at(dirfd, name.as_c_str()).map_err(map)?;
    }
    let left = syscall::fstatat_nofollow(dirfd, final_name).map_err(map)?;
    match syscall::nlink_count(left.st_nlink) {
        1 => Ok(()),
        n => Err(multiply_linked(n)),
    }
}

fn is_temp_name_of(name: &[u8], final_name: &str) -> bool {
    let Some(rest) = name
        .strip_prefix(b".")
        .and_then(|n| n.strip_prefix(final_name.as_bytes()))
        .and_then(|n| n.strip_prefix(b".tmp."))
    else {
        return false;
    };
    let mut parts = rest.split(|b| *b == b'.');
    let digits =
        |p: Option<&[u8]>| p.is_some_and(|p| !p.is_empty() && p.iter().all(u8::is_ascii_digit));
    digits(parts.next()) && digits(parts.next()) && parts.next().is_none()
}

/// With `settle`, the directory is synced even when the name was already absent, so
/// `Ok` proves it absent.
pub(crate) fn remove_at_durable<F: AsFd>(
    dirfd: &F,
    name: &str,
    at: &Path,
    settle: bool,
) -> Result<bool, IoError> {
    remove_synced(dirfd, name, at, settle, syscall::fsync_fd)
}

fn remove_synced<F: AsFd>(
    dirfd: &F,
    name: &str,
    at: &Path,
    settle: bool,
    sync_dir: impl FnOnce(&F) -> nix::Result<()>,
) -> Result<bool, IoError> {
    let removed = match syscall::remove_at(dirfd, name, false) {
        Ok(()) => true,
        Err(nix::errno::Errno::ENOENT) if settle => false,
        Err(nix::errno::Errno::ENOENT) => return Ok(false),
        Err(e) => return Err(crate::checks::map_errno_no_disambiguation(e, at)),
    };
    sync_dir(dirfd).map_err(|e| IoError::RemovedNotDurable {
        path: at.to_path_buf(),
        kind: crate::checks::kind_of_errno(e),
    })?;
    Ok(removed)
}

pub(crate) fn move_aside_durable<F: AsFd>(
    dirfd: &F,
    from: &std::ffi::OsStr,
    to: &std::ffi::OsStr,
    dir: &Path,
) -> Result<(), IoError> {
    move_aside_synced(dirfd, from, to, dir, syscall::fsync_fd)
}

/// `linkat` then `unlinkat`, so an existing `to` is refused with `EEXIST`, never replaced.
fn move_aside_synced<F: AsFd>(
    dirfd: &F,
    from: &std::ffi::OsStr,
    to: &std::ffi::OsStr,
    dir: &Path,
    sync_dir: impl FnOnce(&F) -> nix::Result<()>,
) -> Result<(), IoError> {
    syscall::link_at(dirfd, from, to).map_err(|e| {
        let named = if e == nix::errno::Errno::EEXIST {
            to
        } else {
            from
        };
        crate::checks::map_errno_no_disambiguation(e, &dir.join(named))
    })?;
    if let Err(e) = syscall::unlink_at(dirfd, from) {
        let _ = syscall::unlink_at(dirfd, to);
        return Err(crate::checks::map_errno_no_disambiguation(
            e,
            &dir.join(from),
        ));
    }
    sync_dir(dirfd).map_err(|e| IoError::PublishedNotDurable {
        path: dir.join(to),
        kind: crate::checks::kind_of_errno(e),
    })
}

fn publish_raw<F: AsFd>(
    dirfd: &F,
    final_name: &str,
    bytes: &[u8],
    mode: Mode,
    owner: Option<FileOwner>,
    replace: bool,
    unlink_linked: impl Fn(&F, &str) -> nix::Result<()>,
) -> nix::Result<bool> {
    // CONTRACT LIMIT (external review): the temp adds "." + ".tmp.<pid>.<counter>" to
    // the caller's name, so a final name a filesystem accepts (up to 255 bytes on
    // ext4/xfs) can exceed NAME_MAX in its temp form and be REFUSED — ENAMETOOLONG
    // from the openat, on every filesystem this project targets. Pinned by
    // a_name_whose_temp_form_exceeds_name_max_is_refused. No pre-check: one was tried
    // and is behaviourally unobservable (the filesystem returns the identical errno),
    // which made its comparison an unkillable mutant. A temp-name redesign
    // (fixed-size hash) would lift the limit and change this contract; that is PR-B+
    // work, and until then the limit is stated rather than silent.
    let tmp = temp_name(final_name);
    let fd = syscall::open_temp_excl(dirfd, &tmp, mode)?;
    if let Some(owner) = owner {
        if let Err(e) = syscall::set_owner_and_mode(&fd, owner, mode) {
            let _ = syscall::unlink_at(dirfd, tmp.as_str());
            return Err(e);
        }
    }

    // Cleanup is best-effort and deliberately `let _ =`: the caller must keep the
    // ORIGINAL error, never a masking unlink error.
    if let Err(write_err) = write_all_sync(&fd, bytes) {
        let _ = syscall::unlink_at(dirfd, tmp.as_str());
        return Err(write_err);
    }
    drop(fd);

    if replace {
        if let Err(e) = syscall::rename_at(dirfd, &tmp, final_name) {
            let _ = syscall::unlink_at(dirfd, tmp.as_str());
            return Err(e);
        }
        return Ok(true);
    }
    let linked = syscall::link_at(dirfd, tmp.as_ref(), final_name.as_ref());
    let unlinked = unlink_linked(dirfd, tmp.as_str());
    match linked {
        Ok(()) => unlinked.map(|()| true),
        Err(nix::errno::Errno::EEXIST) => Ok(false),
        Err(e) => Err(e),
    }
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
    // Load-bearing trailing comment, same as its Mode A twin in write_all_sync:
    // coverage-tiers.toml anchors an exception on this exact line, and deleting the
    // comment makes that anchor match zero lines and hard-fails the gate.
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
    use nix::errno::Errno;

    #[test]
    fn temp_open_refuses_a_preexisting_name() {
        let d = tempfile::tempdir().unwrap();
        let dirfd = std::fs::File::open(d.path()).unwrap();
        std::fs::write(d.path().join("squat"), b"there first").unwrap();
        let e = crate::syscall::open_temp_excl(&dirfd, "squat", Mode(0o600)).unwrap_err();
        assert_eq!(e, Errno::EEXIST);
    }

    #[test]
    fn temp_open_refuses_a_preexisting_symlink() {
        let d = tempfile::tempdir().unwrap();
        let dirfd = std::fs::File::open(d.path()).unwrap();
        std::os::unix::fs::symlink("/etc/passwd", d.path().join("squat")).unwrap();
        let e = crate::syscall::open_temp_excl(&dirfd, "squat", Mode(0o600)).unwrap_err();
        assert_eq!(e, Errno::EEXIST, "O_EXCL must refuse a symlink too");
    }

    #[test]
    fn a_failed_directory_sync_after_the_rename_is_published_not_durable() {
        let d = tempfile::tempdir().unwrap();
        let dirfd = std::fs::File::open(d.path()).unwrap();
        std::fs::write(d.path().join("f"), b"old").unwrap();
        let at = d.path().join("f");
        let e = publish_synced(&dirfd, "f", &at, b"new", Mode(0o600), None, |_| {
            Err(Errno::EIO)
        })
        .unwrap_err();
        assert_eq!(
            e,
            IoError::PublishedNotDurable {
                path: at.clone(),
                kind: crate::IoKind::Other {
                    raw: Errno::EIO as i32
                },
            }
        );
        assert_eq!(std::fs::read(&at).unwrap(), b"new");
    }

    #[test]
    fn a_failure_before_the_rename_never_runs_the_directory_sync() {
        let d = tempfile::tempdir().unwrap();
        let dirfd = std::fs::File::open(d.path()).unwrap();
        std::fs::create_dir(d.path().join("busy")).unwrap();
        let at = d.path().join("busy");
        let e = publish_synced(&dirfd, "busy", &at, b"new", Mode(0o600), None, |_| {
            panic!("nothing was renamed, so nothing is synced")
        })
        .unwrap_err();
        assert!(matches!(e, IoError::Io { .. }), "{e:?}");
    }

    #[test]
    fn a_failed_directory_sync_after_the_unlink_is_removed_not_durable() {
        let d = tempfile::tempdir().unwrap();
        let dirfd = std::fs::File::open(d.path()).unwrap();
        std::fs::write(d.path().join("f"), b"old").unwrap();
        let at = d.path().join("f");
        let e = remove_synced(&dirfd, "f", &at, false, |_| Err(Errno::EIO)).unwrap_err();
        assert_eq!(
            e,
            IoError::RemovedNotDurable {
                path: at.clone(),
                kind: crate::IoKind::Other {
                    raw: Errno::EIO as i32
                },
            }
        );
        assert!(std::fs::symlink_metadata(&at).is_err());
    }

    #[test]
    fn a_failed_directory_sync_after_a_move_aside_is_published_not_durable() {
        let d = tempfile::tempdir().unwrap();
        let dirfd = std::fs::File::open(d.path()).unwrap();
        std::fs::write(d.path().join("f"), b"old").unwrap();
        let from = std::ffi::OsStr::new("f");
        let to = std::ffi::OsStr::new("g");
        let e = move_aside_synced(&dirfd, from, to, d.path(), |_| Err(Errno::EIO)).unwrap_err();
        assert_eq!(
            e,
            IoError::PublishedNotDurable {
                path: d.path().join("g"),
                kind: crate::IoKind::Other {
                    raw: Errno::EIO as i32
                },
            }
        );
        assert_eq!(std::fs::read(d.path().join("g")).unwrap(), b"old");
        assert!(std::fs::symlink_metadata(d.path().join("f")).is_err());
    }

    #[test]
    fn an_unlink_is_synced_before_it_is_reported_removed() {
        let d = tempfile::tempdir().unwrap();
        let dirfd = std::fs::File::open(d.path()).unwrap();
        std::fs::write(d.path().join("f"), b"old").unwrap();
        let at = d.path().join("f");
        let mut synced = false;
        let removed = remove_synced(&dirfd, "f", &at, false, |_| {
            synced = true;
            Ok(())
        })
        .unwrap();
        assert!(removed && synced);
    }

    #[test]
    fn an_absent_name_or_a_failed_unlink_never_runs_the_directory_sync() {
        let d = tempfile::tempdir().unwrap();
        let dirfd = std::fs::File::open(d.path()).unwrap();
        let absent = d.path().join("absent");
        assert_eq!(
            remove_synced(&dirfd, "absent", &absent, false, |_| panic!(
                "nothing was unlinked"
            )),
            Ok(false)
        );
        std::fs::create_dir(d.path().join("busy")).unwrap();
        let busy = d.path().join("busy");
        let e = remove_synced(&dirfd, "busy", &busy, false, |_| {
            panic!("nothing was unlinked")
        })
        .unwrap_err();
        assert!(matches!(e, IoError::Io { .. }), "{e:?}");
        assert!(busy.is_dir());
    }

    #[test]
    fn a_settled_removal_syncs_the_directory_whether_or_not_the_name_was_there() {
        let d = tempfile::tempdir().unwrap();
        let dirfd = std::fs::File::open(d.path()).unwrap();
        std::fs::write(d.path().join("f"), b"old").unwrap();
        let at = d.path().join("f");
        for was_there in [true, false] {
            let mut synced = false;
            let removed = remove_synced(&dirfd, "f", &at, true, |_| {
                synced = true;
                Ok(())
            });
            assert_eq!(removed, Ok(was_there));
            assert!(synced);
            assert!(std::fs::symlink_metadata(&at).is_err());
        }
    }

    #[test]
    fn a_settled_removal_whose_sync_fails_is_not_durable_and_a_failed_unlink_never_syncs() {
        let d = tempfile::tempdir().unwrap();
        let dirfd = std::fs::File::open(d.path()).unwrap();
        let absent = d.path().join("absent");
        assert_eq!(
            remove_synced(&dirfd, "absent", &absent, true, |_| Err(Errno::EIO)),
            Err(IoError::RemovedNotDurable {
                path: absent.clone(),
                kind: crate::checks::kind_of_errno(Errno::EIO),
            })
        );
        std::fs::create_dir(d.path().join("busy")).unwrap();
        let busy = d.path().join("busy");
        let e = remove_synced(&dirfd, "busy", &busy, true, |_| {
            panic!("nothing was unlinked")
        })
        .unwrap_err();
        assert!(matches!(e, IoError::Io { .. }), "{e:?}");
        assert!(busy.is_dir());
    }

    fn own_ids() -> crate::anchor::FileOwner {
        crate::anchor::FileOwner {
            uid: nix::unistd::geteuid().as_raw(),
            gid: nix::unistd::getegid().as_raw(),
        }
    }

    fn no_temp_left(dir: &Path) {
        let left: Vec<_> = std::fs::read_dir(dir)
            .unwrap()
            .map(|e| e.unwrap().file_name())
            .filter(|n| n.to_string_lossy().contains(".tmp."))
            .collect();
        assert!(left.is_empty(), "{left:?}");
    }

    fn real_unlink(d: &std::fs::File, n: &str) -> nix::Result<()> {
        syscall::unlink_at(d, n)
    }

    fn publish_new(
        dirfd: &std::fs::File,
        name: &str,
        at: &Path,
        bytes: &[u8],
        owner: crate::anchor::FileOwner,
        sync: impl FnOnce(&std::fs::File) -> nix::Result<()>,
    ) -> Result<bool, IoError> {
        publish_new_synced(
            dirfd,
            name,
            at,
            bytes,
            Mode(0o640),
            owner,
            Seams {
                sync_dir: sync,
                unlink_linked: real_unlink,
            },
        )
    }

    fn io_eio(at: &Path) -> IoError {
        IoError::PublishedNotDurable {
            path: at.to_path_buf(),
            kind: crate::IoKind::Other {
                raw: Errno::EIO as i32,
            },
        }
    }

    fn temp_links(dir: &Path) -> Vec<std::ffi::OsString> {
        std::fs::read_dir(dir)
            .unwrap()
            .map(|e| e.unwrap().file_name())
            .filter(|n| n.to_string_lossy().contains(".tmp."))
            .collect()
    }

    #[test]
    fn a_new_publish_creates_then_syncs_the_directory_and_reports_created() {
        let d = tempfile::tempdir().unwrap();
        let dirfd = std::fs::File::open(d.path()).unwrap();
        let at = d.path().join("f");
        let mut synced = false;
        let created = publish_new(&dirfd, "f", &at, b"one", own_ids(), |_| {
            synced = true;
            Ok(())
        });
        assert_eq!(created, Ok(true));
        assert!(synced);
        assert_eq!(std::fs::read(&at).unwrap(), b"one");
        no_temp_left(d.path());
    }

    #[test]
    fn a_new_publish_onto_an_existing_name_leaves_it_and_syncs_the_directory() {
        let d = tempfile::tempdir().unwrap();
        let dirfd = std::fs::File::open(d.path()).unwrap();
        let at = d.path().join("f");
        std::fs::write(&at, b"old").unwrap();
        let mut synced = false;
        let created = publish_new(&dirfd, "f", &at, b"new", own_ids(), |_| {
            synced = true;
            Ok(())
        });
        assert_eq!(created, Ok(false));
        assert!(synced, "a retry settles an earlier failed directory sync");
        assert_eq!(std::fs::read(&at).unwrap(), b"old");
        no_temp_left(d.path());
    }

    #[test]
    fn a_failed_directory_sync_on_an_existing_name_is_published_not_durable() {
        let d = tempfile::tempdir().unwrap();
        let dirfd = std::fs::File::open(d.path()).unwrap();
        let at = d.path().join("f");
        std::fs::write(&at, b"old").unwrap();
        let e = publish_new(&dirfd, "f", &at, b"new", own_ids(), |_| Err(Errno::EIO)).unwrap_err();
        assert_eq!(e, io_eio(&at));
        assert_eq!(std::fs::read(&at).unwrap(), b"old");
    }

    #[test]
    fn a_failed_directory_sync_after_a_new_publish_is_published_not_durable() {
        let d = tempfile::tempdir().unwrap();
        let dirfd = std::fs::File::open(d.path()).unwrap();
        let at = d.path().join("f");
        let e = publish_new(&dirfd, "f", &at, b"new", own_ids(), |_| Err(Errno::EIO)).unwrap_err();
        assert_eq!(e, io_eio(&at));
        assert_eq!(std::fs::read(&at).unwrap(), b"new");
    }

    #[test]
    fn a_failed_temp_unlink_after_the_link_is_an_error_not_success() {
        let d = tempfile::tempdir().unwrap();
        let dirfd = std::fs::File::open(d.path()).unwrap();
        let at = d.path().join("f");
        let e = publish_new_synced(
            &dirfd,
            "f",
            &at,
            b"new",
            Mode(0o640),
            own_ids(),
            Seams {
                sync_dir: |_: &std::fs::File| -> nix::Result<()> {
                    panic!("an unsettled publication is not synced")
                },
                unlink_linked: |_: &std::fs::File, _: &str| Err(Errno::EIO),
            },
        )
        .unwrap_err();
        assert_eq!(
            e,
            IoError::Io {
                path: at.clone(),
                kind: crate::IoKind::Other {
                    raw: Errno::EIO as i32
                },
            }
        );
        assert_eq!(temp_links(d.path()).len(), 1);
    }

    #[test]
    fn a_leftover_temp_link_is_settled_by_the_next_call() {
        use std::os::unix::fs::MetadataExt;
        let d = tempfile::tempdir().unwrap();
        let dirfd = std::fs::File::open(d.path()).unwrap();
        let at = d.path().join("f");
        let first = publish_new_synced(
            &dirfd,
            "f",
            &at,
            b"one",
            Mode(0o640),
            own_ids(),
            Seams {
                sync_dir: |_: &std::fs::File| Ok(()),
                unlink_linked: |_: &std::fs::File, _: &str| Err(Errno::EIO),
            },
        );
        assert!(first.is_err());
        assert_eq!(std::fs::metadata(&at).unwrap().nlink(), 2);
        let mut synced = false;
        let again = publish_new(&dirfd, "f", &at, b"two", own_ids(), |_| {
            synced = true;
            Ok(())
        });
        assert_eq!(again, Ok(false));
        assert!(synced);
        assert_eq!(std::fs::metadata(&at).unwrap().nlink(), 1);
        assert_eq!(std::fs::read(&at).unwrap(), b"one");
        no_temp_left(d.path());
    }

    #[test]
    fn a_settled_leftover_is_refused_when_the_sync_fails() {
        use std::os::unix::fs::MetadataExt;
        let d = tempfile::tempdir().unwrap();
        let dirfd = std::fs::File::open(d.path()).unwrap();
        let at = d.path().join("f");
        std::fs::write(&at, b"one").unwrap();
        std::fs::hard_link(&at, d.path().join(".f.tmp.4242.7")).unwrap();
        let e = publish_new(&dirfd, "f", &at, b"two", own_ids(), |_| Err(Errno::EIO)).unwrap_err();
        assert_eq!(e, io_eio(&at));
        assert_eq!(std::fs::metadata(&at).unwrap().nlink(), 1);
    }

    #[test]
    fn an_unrelated_extra_hard_link_is_refused_and_left_alone() {
        use std::os::unix::fs::MetadataExt;
        let d = tempfile::tempdir().unwrap();
        let dirfd = std::fs::File::open(d.path()).unwrap();
        let at = d.path().join("f");
        std::fs::write(&at, b"one").unwrap();
        std::fs::hard_link(&at, d.path().join("other")).unwrap();
        std::fs::hard_link(&at, d.path().join(".f.tmp.notdigits.1")).unwrap();
        let e = publish_new(&dirfd, "f", &at, b"two", own_ids(), |_| Ok(())).unwrap_err();
        assert_eq!(
            e,
            IoError::MultiplyLinked {
                path: at.clone(),
                nlink: 3
            }
        );
        assert_eq!(std::fs::metadata(&at).unwrap().nlink(), 3);
        assert!(d.path().join("other").exists());
        assert!(d.path().join(".f.tmp.notdigits.1").exists());
    }

    #[test]
    fn names_that_are_not_exact_publish_temps_are_refused_and_left_alone() {
        for name in [
            ".f.tmp.1.x",
            ".f.tmp.x.1",
            ".f.tmp..1",
            ".f.tmp.1.",
            ".f.tmp.1.2.3",
            ".f.tmp.1",
            "f.tmp.1.2",
            ".g.tmp.1.2",
            ".f.tmpx.1.2",
        ] {
            let d = tempfile::tempdir().unwrap();
            let dirfd = std::fs::File::open(d.path()).unwrap();
            let at = d.path().join("f");
            std::fs::write(&at, b"one").unwrap();
            std::fs::hard_link(&at, d.path().join(name)).unwrap();
            let e = publish_new(&dirfd, "f", &at, b"two", own_ids(), |_| Ok(())).unwrap_err();
            assert_eq!(
                e,
                IoError::MultiplyLinked {
                    path: at.clone(),
                    nlink: 2
                },
                "{name}"
            );
            assert!(d.path().join(name).exists(), "{name}");
        }
    }

    #[test]
    fn a_temp_link_beside_an_unrelated_link_is_removed_and_the_call_still_errs() {
        let d = tempfile::tempdir().unwrap();
        let dirfd = std::fs::File::open(d.path()).unwrap();
        let at = d.path().join("f");
        std::fs::write(&at, b"one").unwrap();
        std::fs::hard_link(&at, d.path().join(".f.tmp.4242.7")).unwrap();
        std::fs::hard_link(&at, d.path().join("other")).unwrap();
        let e = publish_new(&dirfd, "f", &at, b"two", own_ids(), |_| {
            panic!("an unsettled name is not synced")
        })
        .unwrap_err();
        assert_eq!(
            e,
            IoError::MultiplyLinked {
                path: at.clone(),
                nlink: 2
            }
        );
        assert!(!d.path().join(".f.tmp.4242.7").exists());
        assert!(d.path().join("other").exists());
    }

    #[test]
    fn a_temp_named_file_of_another_inode_is_not_taken_for_the_leftover() {
        let d = tempfile::tempdir().unwrap();
        let dirfd = std::fs::File::open(d.path()).unwrap();
        let at = d.path().join("f");
        std::fs::write(&at, b"one").unwrap();
        std::fs::hard_link(&at, d.path().join("other")).unwrap();
        std::fs::write(d.path().join(".f.tmp.1.1"), b"x").unwrap();
        let e = publish_new(&dirfd, "f", &at, b"two", own_ids(), |_| Ok(())).unwrap_err();
        assert_eq!(
            e,
            IoError::MultiplyLinked {
                path: at.clone(),
                nlink: 2
            }
        );
        assert!(d.path().join(".f.tmp.1.1").exists());
    }

    #[test]
    fn a_temp_named_file_of_another_inode_is_never_touched() {
        let d = tempfile::tempdir().unwrap();
        let dirfd = std::fs::File::open(d.path()).unwrap();
        let at = d.path().join("f");
        std::fs::write(&at, b"one").unwrap();
        std::fs::write(d.path().join(".f.tmp.1.1"), b"x").unwrap();
        let again = publish_new(&dirfd, "f", &at, b"two", own_ids(), |_| Ok(()));
        assert_eq!(again, Ok(false));
        assert!(d.path().join(".f.tmp.1.1").exists());
    }

    #[test]
    fn a_new_publish_whose_link_fails_other_than_by_existing_errs_and_removes_its_temp() {
        let d = tempfile::tempdir().unwrap();
        let dirfd = std::fs::File::open(d.path()).unwrap();
        let temp_dir = d.path().join(".d");
        std::fs::create_dir(&temp_dir).unwrap();
        let at = d.path().join("d/x");
        let e = publish_new(&dirfd, "d/x", &at, b"new", own_ids(), |_| {
            panic!("nothing was created, so nothing is synced")
        })
        .unwrap_err();
        assert!(matches!(e, IoError::Io { .. }), "{e:?}");
        no_temp_left(&temp_dir);
        assert!(!d.path().join("d").exists());
    }

    #[test]
    fn a_new_publish_that_cannot_take_its_owner_errs_and_removes_its_temp() {
        if nix::unistd::geteuid().is_root() {
            return;
        }
        let d = tempfile::tempdir().unwrap();
        let dirfd = std::fs::File::open(d.path()).unwrap();
        let at = d.path().join("f");
        let other = crate::anchor::FileOwner {
            uid: nix::unistd::geteuid().as_raw() + 1,
            gid: nix::unistd::getegid().as_raw(),
        };
        let e = publish_new(&dirfd, "f", &at, b"new", other, |_| {
            panic!("nothing was created, so nothing is synced")
        })
        .unwrap_err();
        assert!(matches!(e, IoError::Io { .. }), "{e:?}");
        assert!(!at.exists());
        no_temp_left(d.path());
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
