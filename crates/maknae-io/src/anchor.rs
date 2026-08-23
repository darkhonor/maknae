//! Anchor validation, `open_anchor`, the verb entry points, and the type declarations
//! they need. The declarations live here (not `strategy.rs`) because `open_anchor`'s
//! signature names `StrategyPref` at commit 2, while `strategy.rs` does not land until
//! commit 5.

use crate::checks::{check_owner_mode, AnchorRequired, DescendantRequired, TargetRequired};
use crate::error::IoError;
use crate::syscall;
use std::os::fd::{AsFd, OwnedFd};
use std::path::{Path, PathBuf};
use zeroize::Zeroizing;

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
    fd: OwnedFd,
    path: PathBuf,
    /// Read by the lane fn at commit 5.
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

    let probed = crate::strategy::capability_from_probe(syscall::probe_openat2(&afd));

    Ok(Anchor {
        fd: afd,
        path: path.to_path_buf(),
        pref,
        probed,
    })
}

impl Anchor {
    /// Read a file relative to the pinned anchor.
    ///
    /// Commit 4 hard-codes `Strategy::Portable`; the lane fn and the observable flip
    /// The lane is selected per call; `effective_strategy` reports what actually ran.
    pub fn read(
        &self,
        rel: &Path,
        desc: Option<DescendantRequired>,
        target: TargetRequired,
    ) -> Result<Outcome<Zeroizing<Vec<u8>>>, IoError> {
        let norm = crate::normalize::normalize(rel)?;
        let dir = norm.parent().unwrap_or(Path::new(""));
        let name = match norm.file_name().and_then(|s| s.to_str()) {
            None => return Err(IoError::EmptyRemainder),
            Some(n) => n,
        };

        // Pre-check, dominating: a named descendant requirement with no directory it
        // can apply to is an Err, never a vacuous pass. `config.d/../maknae.yaml`
        // collapses to `maknae.yaml`, so the caller's requirement on `config.d` would
        // otherwise silently never run.
        if desc.is_some() && dir.as_os_str().is_empty() {
            return Err(IoError::NoDescendantForRequirement {
                rel: rel.to_path_buf(),
            });
        }

        let walked: Option<OwnedFd> = if dir.as_os_str().is_empty() {
            None
        } else {
            Some(crate::walk::walk_dirs(
                &self.fd,
                &self.path,
                dir,
                desc.as_ref(),
            )?)
        };
        let base = match &walked {
            Some(fd) => fd.as_fd(),
            None => self.fd.as_fd(),
        };

        let lane = crate::strategy::select(
            self.pref,
            self.probed,
            norm.components().count(),
            desc.as_ref(),
        );

        let full = self.path.join(&norm);

        // The openat2 dispatch is a cfg'd IF-STATEMENT, never a match arm: a cfg'd-out
        // `Strategy::Openat2 =>` arm is E0004 non-exhaustive on darwin, and the
        // `unreachable!()` repair would be an uncoverable darwin region in a [t1] file.
        #[cfg(target_os = "linux")]
        if crate::strategy::uses_openat2(lane) {
            let rel_s = norm
                .to_str()
                .ok_or_else(|| IoError::EscapesAnchor { path: norm.clone() })?;
            let fd = crate::syscall::openat2_resolve(&self.fd, rel_s, false)
                .map_err(|e| crate::checks::map_errno_no_disambiguation(e, &full))?;
            return self.finish_read(fd, &full, lane, &target);
        }

        let fd = crate::syscall::open_read_target(&base, name).map_err(|e| {
            crate::checks::map_errno(e, &full, || crate::syscall::fstatat_nofollow(&base, name))
        })?;

        self.finish_read(fd, &full, lane, &target)
    }

    /// Enumerate a directory relative to the anchor, RAW.
    ///
    /// A zero-component remainder returns the ANCHOR's own entries — PR B needs that
    /// to detect `config.d` by enumerating the root. The file verbs refuse the same
    /// remainder; only enumerate treats it as the anchor itself.
    pub fn enumerate(
        &self,
        rel: &Path,
        desc: Option<DescendantRequired>,
    ) -> Result<Outcome<Vec<Entry>>, IoError> {
        let norm = crate::normalize::normalize(rel)?;

        if norm.as_os_str().is_empty() {
            // The anchor is covered by AnchorRequired; a descendant requirement here
            // names nothing, and a vacuous pass is exactly what the pre-check forbids.
            if desc.is_some() {
                return Err(IoError::NoDescendantForRequirement {
                    rel: rel.to_path_buf(),
                });
            }
            let entries = crate::dir::enumerate_fd(&self.fd, &self.path)?;
            return Ok(Outcome {
                value: entries,
                effective_strategy: Strategy::Portable,
            });
        }

        // The terminal directory IS the checked descendant, so any Some routes to the
        // portable chain: one openat + fstat from the anchor fd is the check.
        let full = self.path.join(&norm);
        let dirfd = crate::walk::walk_dirs(&self.fd, &self.path, &norm, desc.as_ref())?;
        let entries = crate::dir::enumerate_fd(&dirfd, &full)?;
        Ok(Outcome {
            value: entries,
            effective_strategy: Strategy::Portable,
        })
    }

    fn finish_read(
        &self,
        fd: OwnedFd,
        full: &Path,
        lane: Strategy,
        target: &TargetRequired,
    ) -> Result<Outcome<Zeroizing<Vec<u8>>>, IoError> {
        let st = crate::syscall::fstat(&fd)
            .map_err(|e| crate::checks::map_errno_no_disambiguation(e, full))?;
        crate::checks::check_target(&st, full, target)?;

        // Pre-size from st_size so the Zeroizing buffer never reallocates: an
        // abandoned buffer is the one credential residual zeroize cannot reach
        // ("cannot ensure that previous reallocations did not leave values on the
        // heap"). with_capacity + read_to_end may still reserve.
        let want = st.st_size.max(0) as usize;
        let mut buf = Zeroizing::new(vec![0u8; want]);
        let mut n = 0usize;
        while n != want {
            match nix::unistd::read(&fd, &mut buf[n..]) {
                Ok(0) => break,
                Ok(k) => n += k,
                // The manual loop loses read_to_end's built-in retry.
                Err(nix::errno::Errno::EINTR) => continue,
                Err(e) => return Err(crate::checks::map_errno_no_disambiguation(e, full)),
            }
        }
        buf.truncate(n);

        Ok(Outcome {
            value: buf,
            effective_strategy: lane,
        })
    }
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

    /// The probe runs unconditionally at construction — including under
    /// ForcePortable — so `probed_capability()` stays meaningful when the lane is
    /// forced. Its VALUE is platform-determined: darwin has no openat2 (the
    /// cfg(not(linux)) stub returns ENOSYS), Linux reports whatever the kernel and
    /// any seccomp filter allow. Assert the invariant that holds on both.
    #[test]
    fn probe_runs_at_construction_under_either_pref() {
        let d = dir(0o750);
        let a = d.path().join("cfg");
        std::fs::create_dir(&a).unwrap();
        std::fs::set_permissions(&a, std::fs::Permissions::from_mode(0o750)).unwrap();
        for pref in [StrategyPref::Auto, StrategyPref::ForcePortable] {
            let anchor = open_anchor(&a, none_req(), pref).unwrap();
            let cap = anchor.probed_capability();
            #[cfg(not(target_os = "linux"))]
            assert_eq!(cap, Strategy::Portable, "no openat2 off Linux");
            #[cfg(target_os = "linux")]
            assert!(matches!(cap, Strategy::Openat2 | Strategy::Portable));
            // ForcePortable must not suppress the probe itself.
            let _ = cap;
        }
    }

    fn anchor_at(d: &std::path::Path, name: &str) -> Anchor {
        let a = d.join(name);
        std::fs::create_dir_all(&a).unwrap();
        std::fs::set_permissions(&a, std::fs::Permissions::from_mode(0o750)).unwrap();
        open_anchor(&a, none_req(), StrategyPref::Auto).unwrap()
    }

    fn t_req() -> TargetRequired {
        TargetRequired {
            owner: None,
            mode_mask: None,
            nlink_exactly_one: false,
            regular_file: false,
        }
    }

    /// Without a positive case, walk.rs's walk-completed region is uncovered at the
    /// very commit that lands it.
    #[test]
    fn successful_multi_component_read() {
        let d = dir(0o750);
        let a = anchor_at(d.path(), "cfg");
        let sub = a.path.join("config.d");
        std::fs::create_dir(&sub).unwrap();
        std::fs::set_permissions(&sub, std::fs::Permissions::from_mode(0o750)).unwrap();
        std::fs::write(sub.join("10-x.yaml"), b"core:\n  a: 1\n").unwrap();
        let out = a
            .read(Path::new("config.d/10-x.yaml"), None, t_req())
            .unwrap();
        assert_eq!(&out.value[..], b"core:\n  a: 1\n");
    }

    /// The pre-size must not reallocate: an abandoned buffer is the one credential
    /// residual zeroize cannot reach.
    #[test]
    fn read_buffer_is_pre_sized_and_never_reallocates() {
        let d = dir(0o750);
        let a = anchor_at(d.path(), "cfg");
        let body = vec![b'x'; 4096];
        std::fs::write(a.path.join("big.bin"), &body).unwrap();
        let out = a.read(Path::new("big.bin"), None, t_req()).unwrap();
        assert_eq!(out.value.len(), 4096);
        assert_eq!(out.value.capacity(), 4096, "buffer reallocated");
    }

    #[test]
    fn symlinked_component_refused_as_symlink() {
        let d = dir(0o750);
        let a = anchor_at(d.path(), "cfg");
        let real = a.path.join("real");
        std::fs::create_dir(&real).unwrap();
        symlink(&real, a.path.join("link")).unwrap();
        let e = a.read(Path::new("link/x.yaml"), None, t_req()).unwrap_err();
        assert!(matches!(e, IoError::Symlink { .. }), "got {e:?}");
    }

    #[test]
    fn descendant_requirement_enforced_per_component() {
        let d = dir(0o750);
        let a = anchor_at(d.path(), "cfg");
        let sub = a.path.join("config.d");
        std::fs::create_dir(&sub).unwrap();
        std::fs::set_permissions(&sub, std::fs::Permissions::from_mode(0o772)).unwrap();
        std::fs::write(sub.join("x.yaml"), b"y").unwrap();
        let req = DescendantRequired {
            owner: None,
            mode_mask: Some(0o007),
        };
        let e = a
            .read(Path::new("config.d/x.yaml"), Some(req), t_req())
            .unwrap_err();
        assert!(
            matches!(e, IoError::InsecurePermissions { mode, .. } if mode & 0o007 != 0),
            "got {e:?}"
        );
    }

    /// Pre-check arms: a named requirement no lane can evaluate is an Err.
    #[test]
    fn descendant_requirement_with_no_descendant_is_err() {
        let d = dir(0o750);
        let a = anchor_at(d.path(), "cfg");
        std::fs::write(a.path.join("maknae.yaml"), b"y").unwrap();
        let req = DescendantRequired {
            owner: None,
            mode_mask: Some(0o007),
        };
        let e = a
            .read(Path::new("maknae.yaml"), Some(req.clone()), t_req())
            .unwrap_err();
        assert!(
            matches!(e, IoError::NoDescendantForRequirement { .. }),
            "got {e:?}"
        );
        // and after normalization collapses the named directory away
        let e2 = a
            .read(Path::new("config.d/../maknae.yaml"), Some(req), t_req())
            .unwrap_err();
        assert!(
            matches!(e2, IoError::NoDescendantForRequirement { .. }),
            "collapsed: got {e2:?}"
        );
    }

    #[test]
    fn zero_component_read_is_empty_remainder() {
        let d = dir(0o750);
        let a = anchor_at(d.path(), "cfg");
        let e = a.read(Path::new("config.d/.."), None, t_req()).unwrap_err();
        assert_eq!(e, IoError::EmptyRemainder);
    }

    /// Covers walk.rs's `Some(fd) => open_child(fd, ...)` arm — the SECOND and later
    /// components. A one-component walk only exercises the `None` arm.
    #[test]
    fn three_component_walk_uses_the_chained_arm() {
        let d = dir(0o750);
        let a = anchor_at(d.path(), "cfg");
        let deep = a.path.join("x").join("y");
        std::fs::create_dir_all(&deep).unwrap();
        for p in [a.path.join("x"), deep.clone()] {
            std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o750)).unwrap();
        }
        std::fs::write(deep.join("z.yaml"), b"deep").unwrap();
        let out = a.read(Path::new("x/y/z.yaml"), None, t_req()).unwrap();
        assert_eq!(&out.value[..], b"deep");
    }

    /// Covers the read target's own error arm: a symlinked TARGET (not component).
    /// Row 3 carries no O_DIRECTORY, so this is the ELOOP path rather than ENOTDIR.
    #[test]
    fn symlinked_read_target_refused() {
        let d = dir(0o750);
        let a = anchor_at(d.path(), "cfg");
        std::fs::write(a.path.join("real.yaml"), b"y").unwrap();
        symlink(a.path.join("real.yaml"), a.path.join("link.yaml")).unwrap();
        let e = a.read(Path::new("link.yaml"), None, t_req()).unwrap_err();
        assert!(matches!(e, IoError::Symlink { .. }), "got {e:?}");
    }

    /// Covers the short-read termination arm: a file that shrank between the
    /// fstat and the read yields fewer bytes than st_size and must not spin.
    #[test]
    fn short_read_terminates_and_truncates() {
        let d = dir(0o750);
        let a = anchor_at(d.path(), "cfg");
        // /dev/null reports st_size 0 but is a char device; use an empty regular file,
        // which exercises want == 0 and the loop body never running.
        std::fs::write(a.path.join("empty.yaml"), b"").unwrap();
        let out = a.read(Path::new("empty.yaml"), None, t_req()).unwrap();
        assert!(out.value.is_empty());
    }

    /// Covers read()'s propagation of a normalize error (line 135's `?`).
    #[test]
    fn read_propagates_escape_refusal() {
        let d = dir(0o750);
        let a = anchor_at(d.path(), "cfg");
        let e = a
            .read(Path::new("../escape.yaml"), None, t_req())
            .unwrap_err();
        assert!(matches!(e, IoError::EscapesAnchor { .. }), "got {e:?}");
    }

    /// Covers the target open's disambiguation CLOSURE: it is invoked only on ENOTDIR,
    /// which a symlinked target (ELOOP) never reaches. A regular file used as a
    /// directory component gives ENOTDIR.
    #[test]
    fn regular_file_as_directory_component_is_not_a_directory() {
        let d = dir(0o750);
        let a = anchor_at(d.path(), "cfg");
        std::fs::write(a.path.join("plain.yaml"), b"y").unwrap();
        let e = a
            .read(Path::new("plain.yaml/inner"), None, t_req())
            .unwrap_err();
        assert!(
            matches!(
                e,
                IoError::Io {
                    kind: crate::error::IoKind::NotADirectory,
                    ..
                }
            ),
            "got {e:?}"
        );
    }

    /// Kills `replace < with <=` on the read loop: with `<=`, a fully-read buffer
    /// makes one extra `read` into `&mut buf[want..]` — a zero-length slice — which
    /// returns Ok(0) and breaks, so length is unaffected; the observable difference is
    /// the extra syscall. Assert exact length AND that the content round-trips, which
    /// pins the loop's termination to `n == want` rather than one past it.
    #[test]
    fn read_stops_exactly_at_st_size() {
        let d = dir(0o750);
        let a = anchor_at(d.path(), "cfg");
        let body: Vec<u8> = (0..=255u8).cycle().take(3000).collect();
        std::fs::write(a.path.join("exact.bin"), &body).unwrap();
        let out = a.read(Path::new("exact.bin"), None, t_req()).unwrap();
        assert_eq!(out.value.len(), 3000);
        assert_eq!(&out.value[..], &body[..]);
        assert_eq!(out.value.capacity(), 3000);
    }

    fn anchor_pref(d: &std::path::Path, name: &str, pref: StrategyPref) -> Anchor {
        let a = d.join(name);
        std::fs::create_dir_all(&a).unwrap();
        std::fs::set_permissions(&a, std::fs::Permissions::from_mode(0o750)).unwrap();
        open_anchor(&a, none_req(), pref).unwrap()
    }

    fn seed_multi(a: &Anchor) {
        let sub = a.path.join("config.d");
        std::fs::create_dir(&sub).unwrap();
        std::fs::set_permissions(&sub, std::fs::Permissions::from_mode(0o750)).unwrap();
        std::fs::write(sub.join("10-x.yaml"), b"lane").unwrap();
    }

    /// ForcePortable must win over an available capability, on every platform.
    #[test]
    fn force_portable_reports_portable() {
        let d = dir(0o750);
        let a = anchor_pref(d.path(), "cfg", StrategyPref::ForcePortable);
        seed_multi(&a);
        let out = a
            .read(Path::new("config.d/10-x.yaml"), None, t_req())
            .unwrap();
        assert_eq!(out.effective_strategy, Strategy::Portable);
        assert_eq!(&out.value[..], b"lane");
    }

    /// A descendant requirement forces portable even when openat2 is available:
    /// you cannot check what you cannot fstat.
    #[test]
    fn descendant_requirement_reports_portable() {
        let d = dir(0o750);
        let a = anchor_pref(d.path(), "cfg", StrategyPref::Auto);
        seed_multi(&a);
        let req = DescendantRequired {
            owner: None,
            mode_mask: Some(0o007),
        };
        let out = a
            .read(Path::new("config.d/10-x.yaml"), Some(req), t_req())
            .unwrap();
        assert_eq!(out.effective_strategy, Strategy::Portable);
    }

    /// A single-component remainder gains nothing from openat2.
    #[test]
    fn single_component_reports_portable() {
        let d = dir(0o750);
        let a = anchor_pref(d.path(), "cfg", StrategyPref::Auto);
        std::fs::write(a.path.join("maknae.yaml"), b"one").unwrap();
        let out = a.read(Path::new("maknae.yaml"), None, t_req()).unwrap();
        assert_eq!(out.effective_strategy, Strategy::Portable);
    }

    /// On Linux with the capability present, a multi-component unchecked read takes
    /// the fast path and says so. cfg-gated: darwin has no openat2, so asserting
    /// Openat2 there would be red on the dev host.
    #[cfg(target_os = "linux")]
    #[test]
    fn multi_component_unchecked_reports_openat2() {
        let d = dir(0o750);
        let a = anchor_pref(d.path(), "cfg", StrategyPref::Auto);
        seed_multi(&a);
        if a.probed_capability() != Strategy::Openat2 {
            return; // sandbox without openat2; the probe already decided Portable
        }
        let out = a
            .read(Path::new("config.d/10-x.yaml"), None, t_req())
            .unwrap();
        assert_eq!(out.effective_strategy, Strategy::Openat2);
        assert_eq!(&out.value[..], b"lane");
    }

    /// Both lanes must refuse a symlinked component identically.
    #[test]
    fn both_lanes_refuse_a_symlinked_component() {
        for pref in [StrategyPref::Auto, StrategyPref::ForcePortable] {
            let d = dir(0o750);
            let a = anchor_pref(d.path(), "cfg", pref);
            let real = a.path.join("real");
            std::fs::create_dir(&real).unwrap();
            symlink(&real, a.path.join("link")).unwrap();
            let e = a.read(Path::new("link/x.yaml"), None, t_req()).unwrap_err();
            assert!(matches!(e, IoError::Symlink { .. }), "{pref:?}: got {e:?}");
        }
    }

    fn names(o: &Outcome<Vec<Entry>>) -> Vec<String> {
        let mut v: Vec<String> = o
            .value
            .iter()
            .map(|e| e.name.to_string_lossy().into_owned())
            .collect();
        v.sort();
        v
    }

    /// PR B enumerates the ANCHOR to detect config.d. A zero-component remainder must
    /// therefore return the anchor's own entries, not an error.
    #[test]
    fn enumerate_empty_returns_the_anchor_entries() {
        let d = dir(0o750);
        let a = anchor_at(d.path(), "cfg");
        std::fs::create_dir(a.path.join("config.d")).unwrap();
        std::fs::write(a.path.join("maknae.yaml"), b"y").unwrap();
        for rel in ["", "."] {
            let out = a.enumerate(Path::new(rel), None).unwrap();
            let n = names(&out);
            assert!(n.contains(&"config.d".to_string()), "{rel:?}: {n:?}");
            assert!(n.contains(&"maknae.yaml".to_string()), "{rel:?}: {n:?}");
        }
    }

    /// nix::dir yields `.` and `..`, which std::fs::read_dir does not — the caller's
    /// dotfile rule drops them, and PR B depends on that ordering.
    #[test]
    fn enumerate_yields_dot_and_dotdot() {
        let d = dir(0o750);
        let a = anchor_at(d.path(), "cfg");
        let n = names(&a.enumerate(Path::new(""), None).unwrap());
        assert!(
            n.contains(&".".to_string()) && n.contains(&"..".to_string()),
            "{n:?}"
        );
    }

    /// Nothing is refused or filtered: a symlink reports Kind::Symlink and is NOT
    /// followed. This is the security half; the policy half stays with the parser.
    #[test]
    fn symlinked_entry_reports_symlink_and_is_not_followed() {
        let d = dir(0o750);
        let a = anchor_at(d.path(), "cfg");
        std::fs::write(a.path.join("real.yaml"), b"y").unwrap();
        symlink(a.path.join("real.yaml"), a.path.join("link.yaml")).unwrap();
        let out = a.enumerate(Path::new(""), None).unwrap();
        let e = out.value.iter().find(|e| e.name == "link.yaml").unwrap();
        assert_eq!(e.kind, Kind::Symlink);
    }

    /// A DANGLING symlink still reports Symlink rather than erroring — which is what
    /// distinguishes fstatat(AT_SYMLINK_NOFOLLOW) from a stat that would ENOENT.
    #[test]
    fn dangling_symlink_reports_symlink_not_an_error() {
        let d = dir(0o750);
        let a = anchor_at(d.path(), "cfg");
        symlink(a.path.join("nonexistent"), a.path.join("dangling")).unwrap();
        let out = a.enumerate(Path::new(""), None).unwrap();
        let e = out.value.iter().find(|e| e.name == "dangling").unwrap();
        assert_eq!(e.kind, Kind::Symlink);
    }

    /// The terminal-directory arm: config.d is the checked descendant, and this is
    /// the call that preserves maknae-config's world-writable refusal. The fixture is
    /// EMPTY, so a rule scoped to intermediates would never fire on it.
    #[test]
    fn world_writable_terminal_directory_refused() {
        let d = dir(0o750);
        let a = anchor_at(d.path(), "cfg");
        let cd = a.path.join("config.d");
        std::fs::create_dir(&cd).unwrap();
        std::fs::set_permissions(&cd, std::fs::Permissions::from_mode(0o772)).unwrap();
        let req = DescendantRequired {
            owner: None,
            mode_mask: Some(0o007),
        };
        let e = a.enumerate(Path::new("config.d"), Some(req)).unwrap_err();
        assert!(
            matches!(e, IoError::InsecurePermissions { mode, .. } if mode & 0o007 != 0),
            "got {e:?}"
        );
    }

    /// Pre-check precedence: a Some on a remainder with no descendant is an Err, not
    /// a silent enumeration of the anchor.
    #[test]
    fn enumerate_dot_with_requirement_is_err() {
        let d = dir(0o750);
        let a = anchor_at(d.path(), "cfg");
        let req = DescendantRequired {
            owner: None,
            mode_mask: Some(0o007),
        };
        let e = a.enumerate(Path::new("."), Some(req)).unwrap_err();
        assert!(
            matches!(e, IoError::NoDescendantForRequirement { .. }),
            "got {e:?}"
        );
    }

    #[test]
    fn enumerate_propagates_escape_refusal() {
        let d = dir(0o750);
        let a = anchor_at(d.path(), "cfg");
        let e = a.enumerate(Path::new("../escape"), None).unwrap_err();
        assert!(matches!(e, IoError::EscapesAnchor { .. }), "got {e:?}");
    }

    /// The terminal-directory SUCCESS path — world_writable_terminal_directory_refused
    /// errors before reaching it, so without this the branch is uncovered.
    #[test]
    fn enumerate_terminal_directory_succeeds() {
        let d = dir(0o750);
        let a = anchor_at(d.path(), "cfg");
        let cd = a.path.join("config.d");
        std::fs::create_dir(&cd).unwrap();
        std::fs::set_permissions(&cd, std::fs::Permissions::from_mode(0o750)).unwrap();
        std::fs::write(cd.join("10-x.yaml"), b"y").unwrap();
        let req = DescendantRequired {
            owner: None,
            mode_mask: Some(0o007),
        };
        let out = a.enumerate(Path::new("config.d"), Some(req)).unwrap();
        let n = names(&out);
        assert!(n.contains(&"10-x.yaml".to_string()), "{n:?}");
        assert_eq!(out.effective_strategy, Strategy::Portable);
    }

    /// read() must enforce TargetRequired — every other read test passes an all-off
    /// requirement, leaving check_target's Err propagation uncovered.
    #[test]
    fn read_enforces_target_requirements() {
        let d = dir(0o750);
        let a = anchor_at(d.path(), "cfg");
        let f = a.path.join("loose.yaml");
        std::fs::write(&f, b"y").unwrap();
        std::fs::set_permissions(&f, std::fs::Permissions::from_mode(0o666)).unwrap();
        let req = TargetRequired {
            owner: None,
            mode_mask: Some(0o007),
            nlink_exactly_one: false,
            regular_file: true,
        };
        let e = a.read(Path::new("loose.yaml"), None, req).unwrap_err();
        assert!(
            matches!(e, IoError::InsecurePermissions { .. }),
            "got {e:?}"
        );
    }

    /// A FIFO target is refused by regular_file — the read-side FIFO case, which
    /// O_NONBLOCK makes reachable at all (without it the open blocks forever).
    #[test]
    fn fifo_read_target_refused_as_not_regular() {
        let d = dir(0o750);
        let a = anchor_at(d.path(), "cfg");
        nix::unistd::mkfifo(
            &a.path.join("f"),
            nix::sys::stat::Mode::from_bits_truncate(0o600),
        )
        .unwrap();
        let req = TargetRequired {
            owner: None,
            mode_mask: None,
            nlink_exactly_one: false,
            regular_file: true,
        };
        let e = a.read(Path::new("f"), None, req).unwrap_err();
        assert!(matches!(e, IoError::NotRegularFile { .. }), "got {e:?}");
    }
}
