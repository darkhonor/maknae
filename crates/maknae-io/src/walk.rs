//! The per-component `openat` chain — the crate's most security-critical loop.
//!
//! Each component is opened relative to the previous fd with `O_NOFOLLOW`, so a
//! symlink anywhere on the path is refused rather than followed. The remainder handed
//! here is already lexically normalized (§ normalize), so it contains no `.` or `..`.

use crate::checks::{check_owner_mode, map_errno, DescendantRequired};
use crate::error::IoError;
use crate::syscall;
use std::os::fd::{AsFd, OwnedFd};
use std::path::{Path, PathBuf};

/// Walk `rel`'s directory components from `start`, returning the fd of the last
/// directory. `rel` must be normalized and must name only directories.
///
/// `req` is applied to every directory this opens — intermediate or terminal.
pub(crate) fn walk_dirs<F: AsFd>(
    start: &F,
    anchor: &Path,
    rel: &Path,
    req: Option<&DescendantRequired>,
) -> Result<OwnedFd, IoError> {
    let mut cur: Option<OwnedFd> = None;
    let mut sofar: PathBuf = anchor.to_path_buf();

    for comp in rel.components() {
        let name = match comp.as_os_str().to_str() {
            Some(n) => n,
            None => {
                // `sofar` is the anchor-absolute path built as the walk descends, and
                // every SIBLING error in this loop already uses it -- open_child's and
                // check_owner_mode's below. This one returned the bare relative
                // remainder, so the payload convention differed by which error fired,
                // on all four verbs. Naming the offending component absolutely is both
                // consistent and more useful.
                return Err(IoError::NonUtf8Component {
                    path: sofar.join(comp.as_os_str()),
                });
            }
        };
        sofar.push(name);

        let next = match &cur {
            None => open_child(start, name, &sofar)?,
            Some(fd) => open_child(fd, name, &sofar)?,
        };

        if let Some(r) = req {
            let st = syscall::fstat(&next)
                .map_err(|e| crate::checks::map_errno_no_disambiguation(e, &sofar))?;
            check_owner_mode(&st, &sofar, r.owner, r.mode_mask)?;
        }
        cur = Some(next);
    }

    match cur {
        Some(fd) => Ok(fd),
        // Zero components: the caller already holds the anchor fd. Verbs that cannot
        // act on a directory refuse this before calling here.
        None => Err(IoError::EmptyRemainder),
    }
}

fn open_child<F: AsFd>(dirfd: &F, name: &str, sofar: &Path) -> Result<OwnedFd, IoError> {
    syscall::open_dir_at(dirfd, name)
        .map_err(|e| map_errno(e, sofar, || syscall::fstatat_nofollow(dirfd, name)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::ffi::OsStrExt;
    use std::os::unix::fs::PermissionsExt;

    fn tmp(mode: u32) -> tempfile::TempDir {
        let d = tempfile::tempdir().unwrap();
        std::fs::set_permissions(d.path(), std::fs::Permissions::from_mode(mode)).unwrap();
        d
    }

    /// A component whose bytes are not UTF-8 is refused rather than lossily converted,
    /// AND is reported as what it is. It used to come back as `EscapesAnchor`, which
    /// fails closed but tells the operator something false -- the path does not escape
    /// the anchor, it simply is not UTF-8.
    #[test]
    fn non_utf8_component_refused() {
        let d = tmp(0o750);
        let fd = std::fs::File::open(d.path()).unwrap();
        let bad = std::ffi::OsStr::from_bytes(b"\xff\xfe");
        let rel = std::path::PathBuf::from(bad);
        let e = walk_dirs(&fd, d.path(), &rel, None).unwrap_err();
        assert!(matches!(e, IoError::NonUtf8Component { .. }), "got {e:?}");
    }

    /// Defensive guard: the verbs check before calling, but a zero-component walk
    /// must not silently hand back a directory the caller did not ask for.
    #[test]
    fn zero_component_walk_is_empty_remainder() {
        let d = tmp(0o750);
        let fd = std::fs::File::open(d.path()).unwrap();
        let e = walk_dirs(&fd, d.path(), std::path::Path::new(""), None).unwrap_err();
        assert_eq!(e, IoError::EmptyRemainder);
    }

    /// Covers the chained arm's Err propagation (a symlink at the SECOND component,
    /// not the first) — the Ok path alone leaves that `?` region uncovered.
    #[test]
    fn symlink_at_second_component_refused() {
        let d = tmp(0o750);
        let first = d.path().join("a");
        std::fs::create_dir(&first).unwrap();
        std::fs::set_permissions(&first, std::fs::Permissions::from_mode(0o750)).unwrap();
        let real = first.join("real");
        std::fs::create_dir(&real).unwrap();
        std::os::unix::fs::symlink(&real, first.join("b")).unwrap();
        let fd = std::fs::File::open(d.path()).unwrap();
        let e = walk_dirs(&fd, d.path(), std::path::Path::new("a/b"), None).unwrap_err();
        assert!(matches!(e, IoError::Symlink { .. }), "got {e:?}");
    }
}
