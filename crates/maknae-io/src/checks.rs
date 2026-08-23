//! Requirement declarations, their predicates, and the errno -> `IoError` map.
//!
//! The map lives here rather than in `error.rs` or `syscall.rs` because it *branches*,
//! and both of those are `[[t3]]` + `exclude_globs` where a branch would carry zero
//! automated control.

use crate::error::{IoError, IoKind};
use crate::syscall::{mode_bits, nlink_count};
use nix::errno::Errno;
use nix::sys::stat::FileStat;
use std::path::Path;

/// `None` on the *parameter* means "this caller requires no such check". `None` on a
/// *field* means "no requirement on that property". Both levels are meaningful.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AnchorRequired {
    pub owner: Option<u32>,
    pub mode_mask: Option<u32>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DescendantRequired {
    pub owner: Option<u32>,
    pub mode_mask: Option<u32>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TargetRequired {
    pub owner: Option<u32>,
    pub mode_mask: Option<u32>,
    pub nlink_exactly_one: bool,
    pub regular_file: bool,
}

/// Refuse when `st_mode & mask != 0` — `0o007` refuses any other-class bit.
fn mode_violates(st: &FileStat, mask: u32) -> bool {
    mode_bits(st.st_mode) & mask != 0
}

/// Owner/mode predicate shared by the anchor and descendant scopes. Takes a
/// `&FileStat` obtained from an fd, never a path.
pub(crate) fn check_owner_mode(
    st: &FileStat,
    path: &Path,
    owner: Option<u32>,
    mode_mask: Option<u32>,
) -> Result<(), IoError> {
    if let Some(mask) = mode_mask {
        if mode_violates(st, mask) {
            return Err(IoError::InsecurePermissions {
                path: path.to_path_buf(),
                mode: mode_bits(st.st_mode),
            });
        }
    }
    if let Some(want) = owner {
        if st.st_uid != want {
            return Err(IoError::NotOwned {
                path: path.to_path_buf(),
                uid: st.st_uid,
                want,
            });
        }
    }
    Ok(())
}

/// The fused target check, in the PINNED order:
///   symlink -> regular-file -> mode -> owner -> nlink
///
/// The order is observable through the error variant, so it is contract, not an
/// implementation detail. `maknae-config`'s world_accessible_authz_refused fixtures a
/// 0o666 file owned by the test user: mode-before-owner yields InsecurePermissions
/// (today's behaviour), owner-before-mode yields NotOwned. `symlink` is not an fstat
/// predicate at all — it is O_NOFOLLOW at open time, structurally before any fstat —
/// so only three of the four adjacent pairs are reorderable.
pub(crate) fn check_target(
    st: &FileStat,
    path: &Path,
    req: &TargetRequired,
) -> Result<(), IoError> {
    if req.regular_file {
        let fmt = mode_bits(st.st_mode) & mode_bits(nix::libc::S_IFMT);
        if fmt != mode_bits(nix::libc::S_IFREG) {
            return Err(IoError::NotRegularFile {
                path: path.to_path_buf(),
            });
        }
    }
    check_owner_mode(st, path, req.owner, req.mode_mask)?;
    if req.nlink_exactly_one && nlink_count(st.st_nlink) != 1 {
        return Err(IoError::MultiplyLinked {
            path: path.to_path_buf(),
            nlink: nlink_count(st.st_nlink),
        });
    }
    Ok(())
}

/// Errno -> `IoError` where no dirfd/single-component pair is available to
/// disambiguate an ENOTDIR (§4 row 0, and every write-path syscall failure).
pub(crate) fn map_errno_no_disambiguation(e: Errno, path: &Path) -> IoError {
    match e {
        Errno::ELOOP => IoError::Symlink {
            path: path.to_path_buf(),
        },
        _ => IoError::Io {
            path: path.to_path_buf(),
            kind: kind_of(e),
        },
    }
}

/// Errno -> `IoError` for a single-component `openat` with a dirfd in hand.
///
/// `O_NOFOLLOW|O_DIRECTORY` on a symlink returns **ENOTDIR, not ELOOP** — measured on
/// Linux and darwin — and a real regular file gives the same ENOTDIR. So ENOTDIR alone
/// cannot tell a symlinked `config.d` from a regular-file `config.d`, which is exactly
/// the pair PR B's preserved-bar tests depend on. `stat_fn` is injected so every arm is
/// reachable in a unit test; a failing stat cannot confirm a symlink, so it does not
/// claim one.
pub(crate) fn map_errno<S>(e: Errno, path: &Path, stat_fn: S) -> IoError
where
    S: FnOnce() -> nix::Result<FileStat>,
{
    match e {
        Errno::ELOOP => IoError::Symlink {
            path: path.to_path_buf(),
        },
        Errno::ENOTDIR => match stat_fn() {
            Ok(st)
                if mode_bits(st.st_mode) & mode_bits(nix::libc::S_IFMT)
                    == mode_bits(nix::libc::S_IFLNK) =>
            {
                IoError::Symlink {
                    path: path.to_path_buf(),
                }
            }
            _ => IoError::Io {
                path: path.to_path_buf(),
                kind: IoKind::NotADirectory,
            },
        },
        _ => IoError::Io {
            path: path.to_path_buf(),
            kind: kind_of(e),
        },
    }
}

pub(crate) fn kind_of_errno(e: Errno) -> IoKind {
    kind_of(e)
}

fn kind_of(e: Errno) -> IoKind {
    match e {
        Errno::ENOENT => IoKind::NotFound,
        Errno::ENOTDIR => IoKind::NotADirectory,
        Errno::EACCES => IoKind::PermissionDenied,
        other => IoKind::Other { raw: other as i32 },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use nix::errno::Errno;
    use std::path::Path;

    fn no_stat() -> nix::Result<FileStat> {
        Err(Errno::ENOENT)
    }

    /// The ELOOP arm has no natural producer in this crate — every walk open carries
    /// `O_DIRECTORY`, which turns a symlink into ENOTDIR (measured, both platforms).
    /// It exists for the openat2 lane (`RESOLVE_NO_SYMLINKS` does return ELOOP) and is
    /// covered here directly, or it would be an unkillable region.
    #[test]
    fn eloop_maps_to_symlink() {
        let e = map_errno(Errno::ELOOP, Path::new("/a/b"), no_stat);
        assert!(matches!(e, IoError::Symlink { .. }), "got {e:?}");
    }

    #[test]
    fn enotdir_with_failing_stat_does_not_claim_a_symlink() {
        let e = map_errno(Errno::ENOTDIR, Path::new("/a/b"), no_stat);
        assert!(
            matches!(
                e,
                IoError::Io {
                    kind: IoKind::NotADirectory,
                    ..
                }
            ),
            "got {e:?}"
        );
    }

    #[test]
    fn enoent_maps_to_not_found() {
        let e = map_errno(Errno::ENOENT, Path::new("/a/b"), no_stat);
        assert!(
            matches!(
                e,
                IoError::Io {
                    kind: IoKind::NotFound,
                    ..
                }
            ),
            "got {e:?}"
        );
    }

    #[test]
    fn eacces_maps_to_permission_denied() {
        let e = map_errno(Errno::EACCES, Path::new("/a/b"), no_stat);
        assert!(
            matches!(
                e,
                IoError::Io {
                    kind: IoKind::PermissionDenied,
                    ..
                }
            ),
            "got {e:?}"
        );
    }

    /// `raw` is diagnostics only — asserted via the constant, never a numeric literal
    /// (ELOOP is 40 on Linux, 62 on darwin).
    #[test]
    fn unknown_errno_carries_raw() {
        let e = map_errno(Errno::EIO, Path::new("/a/b"), no_stat);
        assert!(
            matches!(e, IoError::Io { kind: IoKind::Other { raw }, .. } if raw == Errno::EIO as i32),
            "got {e:?}"
        );
    }

    /// The path-based variant (§4 row 0) has no dirfd, so ENOTDIR cannot disambiguate.
    #[test]
    fn no_disambiguation_variant_leaves_enotdir_alone() {
        let e = map_errno_no_disambiguation(Errno::ENOTDIR, Path::new("/a/b"));
        assert!(
            matches!(
                e,
                IoError::Io {
                    kind: IoKind::NotADirectory,
                    ..
                }
            ),
            "got {e:?}"
        );
    }

    fn st(mode: u32, uid: u32) -> FileStat {
        // SAFETY-free: FileStat is a plain repr(C) struct of integers.
        let mut s: FileStat = unsafe_free_zeroed();
        s.st_mode = mode as _;
        s.st_uid = uid;
        s
    }

    fn unsafe_free_zeroed() -> FileStat {
        // nix::sys::stat::FileStat is Copy + all-integer; Default is not implemented,
        // so build one from a real fstat on a known fd and overwrite the two fields.
        let f = std::fs::File::open("/").unwrap();
        crate::syscall::fstat(&f).unwrap()
    }

    /// Kills `replace mode_violates -> bool with true` and both `&`->`|`/`^` mutants:
    /// a compliant mode must PASS. Without a passing case those mutants are invisible.
    #[test]
    fn compliant_mode_passes() {
        let s = st(0o040750, 1000);
        assert!(check_owner_mode(&s, Path::new("/a"), None, Some(0o007)).is_ok());
    }

    #[test]
    fn other_writable_mode_refused() {
        let s = st(0o040757, 1000);
        let e = check_owner_mode(&s, Path::new("/a"), None, Some(0o007)).unwrap_err();
        assert!(matches!(e, IoError::InsecurePermissions { mode, .. } if mode & 0o007 != 0));
    }

    #[test]
    fn matching_owner_passes() {
        let s = st(0o040750, 1000);
        assert!(check_owner_mode(&s, Path::new("/a"), Some(1000), None).is_ok());
    }

    /// Kills `delete match arm Errno::ELOOP` in the no-disambiguation variant.
    #[test]
    fn no_disambiguation_eloop_is_symlink() {
        let e = map_errno_no_disambiguation(Errno::ELOOP, Path::new("/a/b"));
        assert!(matches!(e, IoError::Symlink { .. }), "got {e:?}");
    }

    /// Kills `replace match guard S_ISLNK with true`: a non-symlink ENOTDIR must NOT
    /// be reported as a symlink.
    #[test]
    fn enotdir_on_a_regular_file_is_not_a_symlink() {
        let d = tempfile::tempdir().unwrap();
        let f = d.path().join("regular");
        std::fs::write(&f, b"x").unwrap();
        let dirfd = std::fs::File::open(d.path()).unwrap();
        let e = map_errno(Errno::ENOTDIR, &f, || {
            crate::syscall::fstatat_nofollow(&dirfd, "regular")
        });
        assert!(
            matches!(
                e,
                IoError::Io {
                    kind: IoKind::NotADirectory,
                    ..
                }
            ),
            "got {e:?}"
        );
    }

    fn stat_of(path: &std::path::Path) -> FileStat {
        let f = std::fs::File::open(path).unwrap();
        crate::syscall::fstat(&f).unwrap()
    }

    fn target(
        mode_mask: Option<u32>,
        owner: Option<u32>,
        nlink: bool,
        reg: bool,
    ) -> TargetRequired {
        TargetRequired {
            owner,
            mode_mask,
            nlink_exactly_one: nlink,
            regular_file: reg,
        }
    }

    /// Pair 1 of 3 — (regular-file, mode). Both predicates must fail and every EARLIER
    /// stage must pass, or the test does not discriminate the order.
    #[test]
    fn regular_file_precedes_mode() {
        let d = tempfile::tempdir().unwrap();
        let fifo = d.path().join("f");
        nix::unistd::mkfifo(&fifo, nix::sys::stat::Mode::from_bits_truncate(0o666)).unwrap();
        std::fs::set_permissions(&fifo, std::os::unix::fs::PermissionsExt::from_mode(0o666))
            .unwrap();
        let st = {
            let fd = nix::fcntl::open(
                &fifo,
                nix::fcntl::OFlag::O_RDONLY | nix::fcntl::OFlag::O_NONBLOCK,
                nix::sys::stat::Mode::empty(),
            )
            .unwrap();
            crate::syscall::fstat(&fd).unwrap()
        };
        // Both regular_file and mode_mask are violated; regular-file must win.
        let e = check_target(&st, &fifo, &target(Some(0o007), None, false, true)).unwrap_err();
        assert!(
            matches!(e, IoError::NotRegularFile { .. }),
            "order: got {e:?}"
        );
    }

    /// Pair 2 of 3 — (mode, owner). Requirement is caller-named so the fixture stays
    /// owned by the test user: a foreign-owner fixture needs root (chown -> EPERM).
    #[test]
    fn mode_precedes_owner() {
        assert_ne!(
            nix::unistd::geteuid().as_raw(),
            0,
            "fixture requires a non-root user"
        );
        let d = tempfile::tempdir().unwrap();
        let f = d.path().join("m");
        std::fs::write(&f, b"x").unwrap();
        std::fs::set_permissions(&f, std::os::unix::fs::PermissionsExt::from_mode(0o666)).unwrap();
        let st = stat_of(&f);
        let other = nix::unistd::geteuid().as_raw() + 1;
        let e = check_target(&st, &f, &target(Some(0o007), Some(other), false, true)).unwrap_err();
        assert!(
            matches!(e, IoError::InsecurePermissions { .. }),
            "order: got {e:?}"
        );
    }

    /// Pair 3 of 3 — (owner, nlink). Mode is pinned to 0o600 so the EARLIER mode stage
    /// passes; without that, mode fires first and the test proves nothing about order.
    #[test]
    fn owner_precedes_nlink() {
        assert_ne!(
            nix::unistd::geteuid().as_raw(),
            0,
            "fixture requires a non-root user"
        );
        let d = tempfile::tempdir().unwrap();
        let f = d.path().join("h");
        std::fs::write(&f, b"x").unwrap();
        std::fs::set_permissions(&f, std::os::unix::fs::PermissionsExt::from_mode(0o600)).unwrap();
        std::fs::hard_link(&f, d.path().join("h2")).unwrap();
        let st = stat_of(&f);
        let other = nix::unistd::geteuid().as_raw() + 1;
        let e = check_target(&st, &f, &target(Some(0o007), Some(other), true, true)).unwrap_err();
        assert!(matches!(e, IoError::NotOwned { .. }), "order: got {e:?}");
    }

    /// The nlink arm itself, with every earlier stage passing.
    #[test]
    fn hard_linked_target_refused() {
        let d = tempfile::tempdir().unwrap();
        let f = d.path().join("h");
        std::fs::write(&f, b"x").unwrap();
        std::fs::set_permissions(&f, std::os::unix::fs::PermissionsExt::from_mode(0o600)).unwrap();
        std::fs::hard_link(&f, d.path().join("h2")).unwrap();
        let st = stat_of(&f);
        let e = check_target(&st, &f, &target(Some(0o007), None, true, true)).unwrap_err();
        assert!(
            matches!(e, IoError::MultiplyLinked { nlink, .. } if nlink == 2),
            "got {e:?}"
        );
    }

    /// A compliant target passes every stage — without this, several predicates'
    /// "always refuse" mutants are invisible.
    #[test]
    fn compliant_target_passes_every_stage() {
        let d = tempfile::tempdir().unwrap();
        let f = d.path().join("ok");
        std::fs::write(&f, b"x").unwrap();
        std::fs::set_permissions(&f, std::os::unix::fs::PermissionsExt::from_mode(0o600)).unwrap();
        let st = stat_of(&f);
        let me = nix::unistd::geteuid().as_raw();
        assert!(check_target(&st, &f, &target(Some(0o007), Some(me), true, true)).is_ok());
    }
}
