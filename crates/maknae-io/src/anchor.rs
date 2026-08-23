//! Anchor validation, `open_anchor`, the verb entry points, and the type declarations
//! they need. The declarations live here (not `strategy.rs`) because `open_anchor`'s
//! signature names `StrategyPref` at commit 2, while `strategy.rs` does not land until
//! commit 5.

use crate::checks::{check_owner_mode, AnchorRequired};
use crate::error::IoError;
use crate::syscall;
use std::os::fd::OwnedFd;
use std::path::{Path, PathBuf};

/// Injection may only force the WEAKER lane. There is deliberately no `Openat2`
/// variant: "demand the stronger lane" is unrepresentable rather than a runtime `Err`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StrategyPref {
    Auto,
    ForcePortable,
}

/// Observable only — never a request.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Strategy {
    Openat2,
    Portable,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Outcome<T> {
    pub value: T,
    pub effective_strategy: Strategy,
}

/// Owned mode, same reason as `IoKind`: `nix::sys::stat::Mode` in a public signature
/// would force a nix pin on `maknae-config`, which has none.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Mode(pub u32);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Kind {
    File,
    Dir,
    Symlink,
    Other,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Entry {
    pub name: std::ffi::OsString,
    pub kind: Kind,
    pub ino: u64,
}

/// A pinned anchor directory. `Drop` closes the fd. `AnchorRequired` is checked ONCE,
/// at construction — an attacker who `chmod`s the anchor afterwards faces no re-check,
/// which is the deliberate consequence of pinning.
#[derive(Debug)]
pub struct Anchor {
    // Read by the walk at commit 4; the pin itself is the point of holding them here.
    #[allow(dead_code)]
    fd: OwnedFd,
    #[allow(dead_code)]
    path: PathBuf,
    #[allow(dead_code)]
    pref: StrategyPref,
    probed: Strategy,
}

impl Anchor {
    /// What the capability probe found, once, at construction. Hard-coded `Portable`
    /// until the probe lands at commit 5.
    pub fn probed_capability(&self) -> Strategy {
        self.probed
    }
}

/// Open the anchor once and hold it.
///
/// The parent/basename split has three degenerate forms and the set is closed:
/// non-absolute, `parent()==None` (`/`, `/.`), and `file_name()==None` with a `Some`
/// parent (`/etc/maknae/..`, `/..`). Absoluteness is tested first, so a bare `..` is
/// `RelativeAnchor`. A trailing `.` needs no arm — `Path::components` absorbs it.
pub fn open_anchor(
    path: &Path,
    req: AnchorRequired,
    pref: StrategyPref,
) -> Result<Anchor, IoError> {
    if !path.is_absolute() {
        return Err(IoError::RelativeAnchor {
            path: path.to_path_buf(),
        });
    }
    let parent = match path.parent() {
        None => return Err(IoError::RootAnchor),
        Some(p) => p,
    };
    let basename = match path.file_name().and_then(|s| s.to_str()) {
        None => {
            return Err(IoError::AnchorEndsInDotDot {
                path: path.to_path_buf(),
            })
        }
        Some(b) => b,
    };

    // Row 0: parent BY PATH, symlink-following by design (spec:155/:157).
    let pfd =
        syscall::open_parent_by_path(parent).map_err(|e| syscall::map_open_errno(e, parent))?;
    // Row 1: the anchor itself, refusing a symlink at the final component.
    let afd = syscall::open_dir_at(&pfd, basename).map_err(|e| {
        crate::checks::map_errno(e, path, || syscall::fstatat_nofollow(&pfd, basename))
    })?;

    let st =
        syscall::fstat(&afd).map_err(|e| crate::checks::map_errno_no_disambiguation(e, path))?;
    check_owner_mode(&st, path, req.owner, req.mode_mask)?;

    Ok(Anchor {
        fd: afd,
        path: path.to_path_buf(),
        pref,
        probed: Strategy::Portable,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::checks::AnchorRequired;
    use std::os::unix::fs::{symlink, PermissionsExt};

    fn none_req() -> AnchorRequired {
        AnchorRequired {
            owner: None,
            mode_mask: None,
        }
    }

    /// Fixtures must never sit directly in $TMPDIR (1777 on the ubuntu lane).
    fn dir(mode: u32) -> tempfile::TempDir {
        let d = tempfile::tempdir().unwrap();
        std::fs::set_permissions(d.path(), std::fs::Permissions::from_mode(mode)).unwrap();
        d
    }

    #[test]
    fn relative_anchor_refused() {
        let e = open_anchor(Path::new("somedir"), none_req(), StrategyPref::Auto).unwrap_err();
        assert!(matches!(e, IoError::RelativeAnchor { .. }), "got {e:?}");
    }

    #[test]
    fn root_anchor_refused() {
        let e = open_anchor(Path::new("/"), none_req(), StrategyPref::Auto).unwrap_err();
        assert_eq!(e, IoError::RootAnchor);
    }

    /// `parent()` is Some here, so the RootAnchor guard does NOT fire — this is the
    /// third degenerate form, and it is operator-reachable via argv[1]/MAKNAE_CONFIG_DIR.
    #[test]
    fn anchor_ending_in_dotdot_refused() {
        for p in ["/etc/maknae/..", "/.."] {
            let e = open_anchor(Path::new(p), none_req(), StrategyPref::Auto).unwrap_err();
            assert!(
                matches!(e, IoError::AnchorEndsInDotDot { .. }),
                "{p}: got {e:?}"
            );
        }
    }

    /// Absoluteness is tested first, so bare `..` is RelativeAnchor, not AnchorEndsInDotDot.
    #[test]
    fn bare_dotdot_is_relative_not_dotdot() {
        let e = open_anchor(Path::new(".."), none_req(), StrategyPref::Auto).unwrap_err();
        assert!(matches!(e, IoError::RelativeAnchor { .. }), "got {e:?}");
    }

    /// Trailing `.` needs no arm: Path::components absorbs it.
    #[test]
    fn trailing_dot_anchor_opens() {
        let d = dir(0o750);
        let a = d.path().join("cfg");
        std::fs::create_dir(&a).unwrap();
        std::fs::set_permissions(&a, std::fs::Permissions::from_mode(0o750)).unwrap();
        let with_dot = a.join(".");
        open_anchor(&with_dot, none_req(), StrategyPref::Auto).expect("trailing dot opens");
    }

    /// spec:155/:157 — the pair that make the model correct rather than merely strict.
    #[test]
    fn symlinked_ancestor_permitted_and_resolved_once() {
        let d = dir(0o750);
        let real = d.path().join("real");
        std::fs::create_dir(&real).unwrap();
        let cfg = real.join("cfg");
        std::fs::create_dir(&cfg).unwrap();
        std::fs::set_permissions(&cfg, std::fs::Permissions::from_mode(0o750)).unwrap();
        let link = d.path().join("link");
        symlink(&real, &link).unwrap();
        open_anchor(&link.join("cfg"), none_req(), StrategyPref::Auto)
            .expect("symlinked ancestor is permitted");
    }

    /// A symlink AT the final component is refused — and as `Symlink`, not
    /// `Io{NotADirectory}`. An `is_err()` assertion would pass under the ENOTDIR
    /// collapse and would not catch a missing disambiguation.
    #[test]
    fn symlink_at_final_component_refused_as_symlink() {
        let d = dir(0o750);
        let real = d.path().join("real");
        std::fs::create_dir(&real).unwrap();
        let link = d.path().join("link");
        symlink(&real, &link).unwrap();
        let e = open_anchor(&link, none_req(), StrategyPref::Auto).unwrap_err();
        assert!(
            matches!(e, IoError::Symlink { .. }),
            "expected Symlink, got {e:?}"
        );
    }

    #[test]
    fn anchor_required_mode_refused() {
        let d = dir(0o750);
        let a = d.path().join("cfg");
        std::fs::create_dir(&a).unwrap();
        std::fs::set_permissions(&a, std::fs::Permissions::from_mode(0o777)).unwrap();
        let req = AnchorRequired {
            owner: None,
            mode_mask: Some(0o007),
        };
        let e = open_anchor(&a, req, StrategyPref::Auto).unwrap_err();
        assert!(
            matches!(e, IoError::InsecurePermissions { mode, .. } if mode & 0o007 != 0),
            "got {e:?}"
        );
    }

    #[test]
    fn anchor_required_owner_refused() {
        assert_ne!(
            nix::unistd::geteuid().as_raw(),
            0,
            "fixture requires a non-root test user"
        );
        let d = dir(0o750);
        let a = d.path().join("cfg");
        std::fs::create_dir(&a).unwrap();
        std::fs::set_permissions(&a, std::fs::Permissions::from_mode(0o750)).unwrap();
        let other = nix::unistd::geteuid().as_raw() + 1;
        let req = AnchorRequired {
            owner: Some(other),
            mode_mask: None,
        };
        let e = open_anchor(&a, req, StrategyPref::Auto).unwrap_err();
        assert!(
            matches!(e, IoError::NotOwned { want, .. } if want == other),
            "got {e:?}"
        );
    }

    /// Hard-coded until commit 5; becomes the flip observable there. This is the
    /// region's only cover at this boundary.
    #[test]
    fn probed_capability_is_portable_before_the_probe() {
        let d = dir(0o750);
        let a = d.path().join("cfg");
        std::fs::create_dir(&a).unwrap();
        std::fs::set_permissions(&a, std::fs::Permissions::from_mode(0o750)).unwrap();
        let anchor = open_anchor(&a, none_req(), StrategyPref::Auto).unwrap();
        assert_eq!(anchor.probed_capability(), Strategy::Portable);
    }
}
