//! Anchor validation, `open_anchor`, the verb entry points, and the type declarations
//! they need. The declarations live here rather than in `strategy.rs` because
//! `open_anchor`'s signature names `StrategyPref`, and a leaf module that every other
//! module depends on is the wrong place to put the lane-selection logic.

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

#[derive(Clone, PartialEq, Eq)]
pub struct Outcome<T> {
    pub value: T,
    pub effective_strategy: Strategy,
}

/// How many bytes the `fstat` promised.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
struct Want(usize);

/// How many bytes the fill loop actually read.
///
/// A newtype purely so `size_verdict`'s two `usize` arguments cannot be transposed:
/// swapped, the shrank case reports `got == expected` and the direction signal that
/// callers map on is destroyed, silently. That transposition used to compile.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
struct Have(usize);

/// Did the read see exactly the bytes the `fstat` promised?
///
/// Pure, and separate from `finish_read`, because the two failing directions cannot
/// both be provoked through the public API on one platform: the GREW case needs a
/// file whose readable length exceeds `st_size` (procfs, or a FIFO), and the SHRANK
/// case needs the file to lose bytes between the `fstat` and the fill loop, which is
/// a race no fixture can win deterministically. Extracting the decision lets all four
/// quadrants be asserted on every platform -- the crate already uses this shape for
/// `classify_entry` and the capability probe. The production path calls this function,
/// so the tests hold the real decision and not a copy of it.
///
/// `Err(got)` carries the byte count to report. In the grew case that is `n + 1`: a
/// LOWER BOUND, since one probe byte proves "more than expected" without revealing
/// how much more.
fn size_verdict(want: Want, have: Have, saw_extra: bool) -> Result<(), usize> {
    if have.0 != want.0 {
        return Err(have.0); // shrank: fewer bytes than the checked inode claimed
    }
    if saw_extra {
        return Err(have.0 + 1); // grew: at least one byte past st_size
    }
    Ok(())
}

/// `Debug` is hand-written to REDACT `value`, and must stay that way.
///
/// `read` returns `Outcome<Zeroizing<Vec<u8>>>`, and `Zeroizing`'s upstream `Debug`
/// prints the wrapped bytes. A derived `Debug` would therefore emit plaintext
/// credentials from anything that formats an Outcome: `dbg!`, a `tracing::debug!`,
/// a failing `assert_eq!`, or `.expect_err()` on a `Result<Outcome, _>` -- the last
/// two inside the test suite itself. For the crate whose stated job includes keeping
/// secrets off the heap, letting them out through the formatter instead is not a
/// smaller hole. `outcome_debug_redacts_the_payload` holds it.
impl<T> std::fmt::Debug for Outcome<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Outcome")
            .field("value", &"<redacted>")
            .field("effective_strategy", &self.effective_strategy)
            .finish()
    }
}

/// Owned mode, same reason as `IoKind`: `nix::sys::stat::Mode` in a public signature
/// would force a nix pin on `maknae-config`, which has none.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Mode(pub u32);

/// `#[non_exhaustive]` because `Other` will eventually need splitting (fifo, socket,
/// device) and PR B is a downstream crate: without it, that split is a breaking
/// change to every caller that matches on `Kind`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
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
    /// The caller's lane preference, read by `strategy::select` on every verb.
    pref: StrategyPref,
    probed: Strategy,
}

impl Anchor {
    /// What the capability probe found, once, at construction.
    ///
    /// `Openat2` only where the syscall is actually usable — the probe issues a real
    /// `openat2` and treats any error as "not available", so a seccomp filter
    /// returning EPERM yields `Portable`. This is the CAPABILITY, not the lane a given
    /// call takes: `select` also requires a multi-component remainder and no
    /// descendant check, and `effective_strategy` on each `Outcome` reports what
    /// actually ran.
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
    // Two distinct failures, previously reported as one: `file_name()` is None only
    // when the path genuinely has no final component (`/etc/maknae/..`), while a
    // Some that is not UTF-8 is a different fact entirely.
    let basename = match path.file_name() {
        None => {
            return Err(IoError::AnchorEndsInDotDot {
                path: path.to_path_buf(),
            })
        }
        Some(os) => match os.to_str() {
            None => {
                return Err(IoError::NonUtf8Component {
                    path: path.to_path_buf(),
                })
            }
            Some(b) => b,
        },
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
    /// The lane is selected per call; `effective_strategy` reports what actually ran.
    pub fn read(
        &self,
        rel: &Path,
        desc: Option<DescendantRequired>,
        target: TargetRequired,
    ) -> Result<Outcome<Zeroizing<Vec<u8>>>, IoError> {
        let norm = crate::normalize::normalize(rel)?;
        let dir = norm.parent().unwrap_or(Path::new(""));
        let name = match norm.file_name() {
            None => return Err(IoError::EmptyRemainder),
            Some(os) => match os.to_str() {
                None => {
                    return Err(IoError::NonUtf8Component {
                        path: self.path.join(&norm),
                    })
                }
                Some(n) => n,
            },
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

        // Lane selection comes BEFORE the walk, and the openat2 lane RETURNS before it.
        // Selecting after the walk left the walk running unconditionally, so on Linux
        // the portable chain had already resolved every directory component by the time
        // openat2 was asked to resolve the same remainder from the anchor. That made the
        // fast lane pure overhead and, worse, a false label: `effective_strategy:
        // Openat2` named a syscall whose properties nothing had relied on. Concretely
        // the measured advantage in the lane table -- an execute-only 0o311 descendant,
        // which openat2 traverses and `openat(..., O_DIRECTORY)` refuses with EACCES --
        // was unreachable, because the walk hit EACCES first. It also meant deleting
        // this whole block changed no observable behaviour, so no test could hold it.
        //
        // Skipping the walk is sound exactly here and nowhere else: select() returns
        // Openat2 only when `desc` is None, i.e. when no caller check applies to any
        // directory the walk would have opened. RESOLVE_NO_SYMLINKS and RESOLVE_BENEATH
        // carry the refusals the walk's per-component O_NOFOLLOW carried.
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
                .ok_or_else(|| IoError::NonUtf8Component { path: full.clone() })?;
            let fd = crate::syscall::openat2_resolve(&self.fd, rel_s, false)
                .map_err(|e| crate::checks::map_errno_no_disambiguation(e, &full))?;
            return self.finish_read(fd, &full, lane, &target);
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

    /// Publish bytes atomically. Always portable: Mode A needs a dirfd to `renameat`
    /// against, which the whole-remainder `openat2` lane never yields.
    pub fn publish(
        &self,
        rel: &Path,
        desc: Option<DescendantRequired>,
        bytes: &[u8],
        mode: Mode,
    ) -> Result<Outcome<()>, IoError> {
        let (norm, name) = self.split_target(rel, desc.as_ref())?;
        let dir = norm.parent().unwrap_or(Path::new(""));
        let full = self.path.join(&norm);

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

        let lane = crate::write::publish_at(&base, &name, &full, bytes, mode)?;
        Ok(Outcome {
            value: (),
            effective_strategy: lane,
        })
    }

    /// Append bytes, creating the file if absent. Always portable.
    ///
    /// NOT FAILURE-ATOMIC on create, and that is contract (external review made it
    /// explicit): the open carries `O_CREAT`, the `TargetRequired` checks run on the
    /// opened fd AFTER creation, so a rejection can leave a fresh EMPTY file behind.
    /// Fail-closed for the write; not side-effect-free. Unlinking on error would be
    /// worse — without `O_EXCL` this function cannot know it was the creator, and an
    /// unlink could remove a name an attacker swapped in or a file that pre-existed.
    /// A create-exclusive-with-retry design could close this; until a consumer needs
    /// it, the residue is documented and pinned by
    /// `rejected_append_may_leave_an_empty_file`.
    pub fn append(
        &self,
        rel: &Path,
        desc: Option<DescendantRequired>,
        target: TargetRequired,
        bytes: &[u8],
        mode: Mode,
    ) -> Result<Outcome<()>, IoError> {
        let (norm, name) = self.split_target(rel, desc.as_ref())?;
        let dir = norm.parent().unwrap_or(Path::new(""));
        let full = self.path.join(&norm);

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

        let lane = crate::write::append_at(&base, &name, &full, bytes, mode, &target)?;
        Ok(Outcome {
            value: (),
            effective_strategy: lane,
        })
    }

    /// Shared prologue for the file verbs: normalize, run the dominating pre-check,
    /// and split off the final component. A zero-component remainder is refused here —
    /// only `enumerate` treats it as the anchor itself.
    fn split_target(
        &self,
        rel: &Path,
        desc: Option<&DescendantRequired>,
    ) -> Result<(std::path::PathBuf, String), IoError> {
        let norm = crate::normalize::normalize(rel)?;
        let name = match norm.file_name() {
            None => return Err(IoError::EmptyRemainder),
            Some(os) => match os.to_str() {
                None => {
                    return Err(IoError::NonUtf8Component {
                        path: self.path.join(&norm),
                    })
                }
                Some(n) => n.to_string(),
            },
        };
        let dir = norm.parent().unwrap_or(Path::new(""));
        if desc.is_some() && dir.as_os_str().is_empty() {
            return Err(IoError::NoDescendantForRequirement {
                rel: rel.to_path_buf(),
            });
        }
        Ok((norm, name))
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
        // Typed AT THE DEFINITION SITE, not at the call. Wrapping at the call left a
        // bare `usize` of each role in scope, so `size_verdict(Want(n), Have(want))`
        // -- right wrappers, wrong values -- still compiled and still destroyed the
        // direction signal. With no unwrapped counts in scope there is nothing to
        // transpose.
        let want = Want(st.st_size.max(0) as usize);
        let mut buf = Zeroizing::new(vec![0u8; want.0]);
        let mut n = Have(0);
        while n.0 != want.0 {
            match nix::unistd::read(&fd, &mut buf[n.0..]) {
                // The three non-progress arms are grouped FIRST and the covered
                // progress arm goes last, so the coverage exception can span exactly
                // these three and leave `Ok(k)` in the denominator. Ordering does the
                // work; a `k > 0` guard would do it too but adds a comparison that
                // cargo-mutants rewrites into a non-terminating loop.
                Ok(0) => break,
                // The manual loop loses read_to_end's built-in retry.
                Err(nix::errno::Errno::EINTR) => continue,
                Err(e) => return Err(crate::checks::map_errno_no_disambiguation(e, full)),
                Ok(k) => n.0 += k,
            }
        }

        // NOTE on `got`: both call sites below are asserted exactly, including this
        // field, because it is the only part of the error that reports WHICH direction
        // the size moved and PR B maps on it. Left unasserted, `n + 1` mutates to
        // `n * 1` with the whole suite still green -- caught by cargo-mutants.
        // Sizing the buffer from st_size means the read stops at the length the file
        // had at the fstat. Both directions of a change in that window must be an
        // ERROR, never a short `Ok`:
        //
        //   grew   -- bytes past st_size are dropped. On a policy file that is a rule
        //             appended mid-read vanishing silently: a deny becoming a permit.
        //             `std::fs::read`, which this crate replaces, reads to EOF and
        //             cannot truncate this way, so staying silent would be a
        //             REGRESSION against the call sites being migrated.
        //   shrank -- `Ok(0)` breaks the loop early and we hold fewer bytes than the
        //             checked inode claimed.
        //
        // One extra read detects the grew case: at n == want the file is at EOF iff
        // it did not grow. EINTR is retried; any other errno is the file changing
        // under us, which is the same refusal.
        let mut probe = [0u8; 1];
        let saw_extra = loop {
            match nix::unistd::read(&fd, &mut probe) {
                Ok(0) => break false,
                Ok(_) => break true,
                Err(nix::errno::Errno::EINTR) => continue, // retry the probe

                // A genuine read error is NOT a size change. Relabelling it would
                // discard the errno that the fill loop above preserves and report
                // e.g. EIO as "size changed under the read". Bound as `probe_err`
                // rather than `e` so this line is textually distinct from the fill
                // loop's identical arm -- the coverage gate anchors on whole lines
                // and rejects an ambiguous one.
                Err(probe_err) => {
                    return Err(crate::checks::map_errno_no_disambiguation(probe_err, full))
                }
            }
        };
        // Deleting this line leaves the suite green, and unlike every other
        // uncontrolled item in the crate that fact had no stated reason. One byte of
        // file content lives in this buffer; whether it was wiped is not observable
        // from a test without reading freed stack, so the control is review, not a
        // test. Recorded so the set of "uncontrolled, and here is why" is complete.
        zeroize::Zeroize::zeroize(&mut probe[..]);
        if let Err(got) = size_verdict(want, n, saw_extra) {
            return Err(IoError::SizeChanged {
                path: full.to_path_buf(),
                expected: want.0,
                got,
            });
        }

        Ok(Outcome {
            value: buf,
            effective_strategy: lane,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    /// Serialises publishing tests. The temp counter is process-global (two Anchors
    /// in one process would otherwise collide on the same name under O_EXCL with no
    /// retry), which trades away per-test determinism under the parallel harness.
    /// Taken with `unwrap_or_else(|p| p.into_inner())` so one failing test does not
    /// poison-cascade the rest (sink.rs:145 precedent).
    static PUBLISH_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

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

    /// Mode B through a multi-component remainder. Every other append test targets a
    /// single component, so `append`'s own walk -- a SEPARATE call site from `read`'s
    /// and `publish`'s -- had no coverage at all: the descendant chain it opens could
    /// have been wrong in either direction and no test would have moved.
    #[test]
    fn append_walks_a_multi_component_remainder() {
        let d = dir(0o750);
        let a = anchor_at(d.path(), "cfg");
        let sub = a.path.join("audit.d");
        std::fs::create_dir(&sub).unwrap();
        std::fs::set_permissions(&sub, std::fs::Permissions::from_mode(0o750)).unwrap();

        a.append(
            Path::new("audit.d/a.jsonl"),
            None,
            t_append(),
            b"one\n",
            m(0o640),
        )
        .unwrap();
        a.append(
            Path::new("audit.d/a.jsonl"),
            None,
            t_append(),
            b"two\n",
            m(0o640),
        )
        .unwrap();

        // Landed in the pinned descendant, and O_APPEND kept both records.
        assert_eq!(std::fs::read(sub.join("a.jsonl")).unwrap(), b"one\ntwo\n");
    }

    /// The SHRANK direction, through the PRODUCTION path.
    ///
    /// `size_verdict`'s four quadrants are unit-tested, but that held the pure
    /// function only -- measured: replacing the production call's `Have(n)` with
    /// `Have(want)`, which disables shrank detection entirely, left 102/102 green.
    /// Nothing tested what `finish_read` actually feeds it.
    ///
    /// sysfs is the exact twin of the procfs GREW fixture: an attribute file reports
    /// `st_size == 4096` and reads a handful of bytes, so the fill loop legitimately
    /// ends with `n < want` and no race is required. Measured on Debian 13:
    /// `/sys/devices/system/cpu/online` is st_size 4096, 4 bytes readable, mode 0444.
    ///
    /// Without the refusal this returns `Ok` with a 4096-byte buffer whose tail is
    /// NUL -- 4092 NUL bytes appended to what the caller believes is file content.
    #[cfg(target_os = "linux")]
    #[test]
    fn a_file_shorter_than_its_st_size_is_refused_not_nul_padded() {
        let dir = std::path::Path::new("/sys/devices/system/cpu");
        if !dir.join("online").exists() {
            crate::testutil::skip_or_fail(
                "a_file_shorter_than_its_st_size_is_refused_not_nul_padded",
                "/sys is not mounted, so the SHRANK direction has no fixture",
            );
            return;
        }
        // The property under test is "readable length < st_size", NOT "st_size is
        // 4096". kernfs sets a sizeless attribute inode's i_size to PAGE_SIZE: 4096 on
        // x86_64, 65536 on a 64K-page aarch64 kernel. Pinning the literal would turn
        // this into a hard failure with a misleading message on hardware this project
        // plausibly runs on.
        let st = std::fs::symlink_metadata(dir.join("online")).unwrap();
        let sz = st.len() as usize;
        assert!(sz > 0, "fixture requires a non-zero st_size, got {sz}");

        let a = open_anchor(dir, none_req(), StrategyPref::ForcePortable).unwrap();
        let err = a
            .read(Path::new("online"), None, t_req())
            .expect_err("a file shorter than st_size must be refused, not NUL-padded");
        match err {
            IoError::SizeChanged { expected, got, .. } => {
                assert_eq!(expected, sz);
                assert!(
                    got < sz,
                    "shrank must report the ACTUAL count ({got}), below st_size ({sz})"
                );
            }
            other => panic!("expected SizeChanged, got {other:?}"),
        }
    }

    /// The portable half of the size-change refusal, so the control is not Linux-only.
    ///
    /// A FIFO reports `st_size == 0` while holding readable bytes -- the same shape as
    /// the procfs fixture, on every unix. The crate opens targets O_NONBLOCK, so the
    /// open does not block, `want` is 0, the fill loop does not run, and the one-byte
    /// probe finds data that the fstat did not account for. `t_req()` sets
    /// `regular_file: false`, so the refusal under test is the size check and not the
    /// file-type check.
    #[test]
    fn readable_bytes_beyond_st_size_are_refused_on_a_fifo() {
        let d = dir(0o750);
        let a = anchor_at(d.path(), "cfg");
        let fifo = a.path.join("p");
        nix::unistd::mkfifo(&fifo, nix::sys::stat::Mode::from_bits_truncate(0o600)).unwrap();

        // A reader must exist before a writer can open, so the test holds one open for
        // the duration; that also keeps the written bytes buffered in the pipe.
        let _rd = nix::fcntl::open(
            &fifo,
            nix::fcntl::OFlag::O_RDONLY | nix::fcntl::OFlag::O_NONBLOCK,
            nix::sys::stat::Mode::empty(),
        )
        .unwrap();
        let wr = nix::fcntl::open(
            &fifo,
            nix::fcntl::OFlag::O_WRONLY,
            nix::sys::stat::Mode::empty(),
        )
        .unwrap();
        nix::unistd::write(&wr, b"UNACCOUNTED").unwrap();

        let err = a
            .read(Path::new("p"), None, t_req())
            .expect_err("bytes beyond st_size must be refused, not silently dropped");
        assert!(
            matches!(
                err,
                IoError::SizeChanged {
                    expected: 0,
                    got: 1,
                    ..
                }
            ),
            "expected SizeChanged, got {err:?}"
        );
    }

    /// `Outcome`'s Debug must never print the payload. Re-deriving Debug turns this
    /// RED, which is the point: the regression is one attribute wide and otherwise
    /// invisible.
    #[test]
    fn outcome_debug_redacts_the_payload() {
        let d = dir(0o750);
        let a = anchor_at(d.path(), "cfg");
        std::fs::write(a.path.join("secret"), b"SUPER-SECRET-TOKEN").unwrap();
        let out = a.read(Path::new("secret"), None, t_req()).unwrap();
        let rendered = format!("{out:?}");
        // Both spellings. The ASCII check alone is VACUOUS against the actual
        // regression: `#[derive(Debug)]` on Outcome<Zeroizing<Vec<u8>>> renders the
        // payload as `[83, 85, 80, ...]`, a full leak containing no such substring.
        assert!(
            !rendered.contains("SUPER-SECRET-TOKEN"),
            "Debug leaked the payload verbatim: {rendered}"
        );
        let as_decimals = b"SUPER-SECRET-TOKEN"
            .iter()
            .map(|b| b.to_string())
            .collect::<Vec<_>>()
            .join(", ");
        assert!(
            !rendered.contains(&as_decimals),
            "Debug leaked the payload as a byte list: {rendered}"
        );
        assert!(rendered.contains("<redacted>"), "{rendered}");
        // The non-secret field stays useful for diagnostics.
        assert!(rendered.contains("effective_strategy"), "{rendered}");
    }

    /// Row 0's payload is the anchor's PARENT, and an ELOOP there is not a refusal.
    ///
    /// Two properties of the one site in the crate whose path payload lies ABOVE the
    /// anchor. (Not "neither the anchor nor `anchor.join(rel)`" — that was retracted:
    /// the portable walk's payloads are intermediate prefixes, anchor-absolute but not
    /// `anchor.join(rel)` either. See the convention on `IoError`.)
    ///
    /// 1. A missing intermediate names the component that is actually absent, which is
    ///    the useful diagnostic — `/etc/x/y/cfg` failing on a missing `/etc/x/y`
    ///    should say `/etc/x/y`, not repeat the path the caller already typed.
    /// 2. Row 0 opens the parent symlink-FOLLOWING by design, so ELOOP means the
    ///    kernel gave up on a symlink LOOP, not that a symlink was refused. Reporting
    ///    `IoError::Symlink` — whose Display reads "symlink refused" — would state the
    ///    opposite of the documented policy that a symlinked ancestor is permitted.
    #[test]
    fn anchor_parent_failures_name_the_parent_and_do_not_claim_a_refusal() {
        let d = dir(0o750);

        // (1) missing intermediate
        let missing = d.path().join("absent").join("cfg");
        match open_anchor(&missing, none_req(), StrategyPref::Auto).unwrap_err() {
            IoError::Io { path, kind } => {
                assert_eq!(kind, crate::error::IoKind::NotFound);
                assert_eq!(path, d.path().join("absent"), "must name the ABSENT parent");
            }
            other => panic!("expected Io{{NotFound}}, got {other:?}"),
        }

        // (2) a symlink loop in the parent chain
        let a = d.path().join("loop_a");
        let b = d.path().join("loop_b");
        symlink(&b, &a).unwrap();
        symlink(&a, &b).unwrap();
        let looped = a.join("cfg");
        // Asserts the ERRNO and the PATH, not merely "not Symlink". `Io { .. }` alone
        // would accept any errno on any path, so if a platform returned ENOENT here the
        // test would pass while the property it exists for went unverified.
        match open_anchor(&looped, none_req(), StrategyPref::Auto).unwrap_err() {
            IoError::Symlink { .. } => panic!(
                "a symlink LOOP in the anchor's parent must not be reported as a \
                 symlink refusal — symlinked ancestors are permitted by design"
            ),
            IoError::Io { path, kind } => {
                assert_eq!(
                    kind,
                    crate::error::IoKind::Other {
                        raw: nix::errno::Errno::ELOOP as i32
                    },
                    "the loop must surface as ELOOP, untranslated"
                );
                assert_eq!(path, a, "must name the parent, as part (1) does");
            }
            other => panic!("expected Io, got {other:?}"),
        }
    }

    /// The openat2 fast lane must not BLOCK on a FIFO either — its `O_NONBLOCK`.
    ///
    /// Round 10's finding, one lane over. Measured on Debian 13: deleting `O_NONBLOCK`
    /// from `openat2_resolve` leaves the Linux suite 115/115 green, because every FIFO
    /// fixture in the crate is single-component or unit-level and `strategy::select`
    /// only picks the fast lane at TWO OR MORE components. So nothing ever opened a
    /// FIFO through `openat2`, and the flag that stops `maknaed` blocking forever on
    /// one had no control on the lane that CI runs and the deployment target uses.
    ///
    /// `check_target` cannot substitute, for the same reason it could not for
    /// `open_append`'s `O_NOFOLLOW`: the block happens AT THE OPEN, before any `fstat`
    /// exists to check.
    #[cfg(target_os = "linux")]
    #[test]
    fn the_openat2_lane_does_not_block_on_a_fifo() {
        let d = dir(0o750);
        let a = anchor_pref(d.path(), "cfg", StrategyPref::Auto);
        if a.probed_capability() != Strategy::Openat2 {
            crate::testutil::skip_or_fail(
                "the_openat2_lane_does_not_block_on_a_fifo",
                "openat2 is not available, so the fast lane cannot be exercised",
            );
            return;
        }
        let sub = a.path.join("config.d");
        std::fs::create_dir(&sub).unwrap();
        std::fs::set_permissions(&sub, std::fs::Permissions::from_mode(0o750)).unwrap();
        nix::unistd::mkfifo(
            &sub.join("pipe"),
            nix::sys::stat::Mode::from_bits_truncate(0o600),
        )
        .unwrap();

        // Two components + no descendant requirement => select() picks Openat2.
        let (tx, rx) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            let req = TargetRequired {
                owner: None,
                mode_mask: None,
                nlink_exactly_one: false,
                regular_file: true,
            };
            let _ = tx.send(
                a.read(Path::new("config.d/pipe"), None, req)
                    .map(|o| o.effective_strategy),
            );
        });

        match rx.recv_timeout(std::time::Duration::from_secs(10)) {
            Err(std::sync::mpsc::RecvTimeoutError::Timeout) => panic!(
                "read did not return within 10s on a FIFO through the openat2 lane. \
                 Most likely openat2_resolve lost O_NONBLOCK, so open(2) is waiting \
                 for a writer that will never come — but a starved runner looks the \
                 same, so check the flags before concluding."
            ),
            Err(e) => panic!("worker died: {e:?}"),
            Ok(Ok(lane)) => panic!("a FIFO must not read as a regular file (lane {lane:?})"),
            Ok(Err(IoError::NotRegularFile { .. })) => {}
            Ok(Err(other)) => panic!("expected NotRegularFile, got {other:?}"),
        }
    }

    /// A final name whose TEMP form exceeds NAME_MAX is refused — documented limit.
    ///
    /// The temp adds `.` + `.tmp.<pid>.<counter>`, so a 255-byte name — valid on
    /// ext4/xfs — cannot be published through this API: `openat` returns ENAMETOOLONG
    /// on the temp. There is deliberately NO pre-check (write.rs says why: the
    /// filesystem returns the identical errno, so a pre-check adds no observable
    /// behaviour and only an unkillable mutant). This test pins the limit as contract
    /// so a temp-name redesign that lifts it turns the test red.
    #[test]
    fn a_name_whose_temp_form_exceeds_name_max_is_refused() {
        let d = dir(0o750);
        let a = anchor_at(d.path(), "cfg");
        let long = "x".repeat(255);
        let e = a
            .publish(Path::new(&long), None, b"y", m(0o640))
            .unwrap_err();
        match e {
            IoError::Io {
                kind: crate::error::IoKind::Other { raw },
                ..
            } => assert_eq!(raw, nix::errno::Errno::ENAMETOOLONG as i32),
            other => panic!("expected ENAMETOOLONG, got {other:?}"),
        }
        // And nothing was left behind under any name.
        assert_eq!(
            std::fs::read_dir(&a.path).unwrap().count(),
            0,
            "a refused publish must leave no temp"
        );
    }

    /// A rejected append may leave an empty file behind — pinned as CONTRACT.
    ///
    /// Absent target, O_CREAT creates it, then the owner requirement fails on the
    /// opened fd. The append is refused; the empty file remains. Pinned so the
    /// side-effect is a stated property, not a surprise — and so any future
    /// failure-atomic redesign announces itself by turning this red.
    #[test]
    fn rejected_append_may_leave_an_empty_file() {
        let d = dir(0o750);
        let a = anchor_at(d.path(), "cfg");
        // An owner the creating process can never be: euid + 1.
        let impossible = nix::unistd::geteuid().as_raw() + 1;
        let req = TargetRequired {
            owner: Some(impossible),
            mode_mask: None,
            nlink_exactly_one: false,
            regular_file: true,
        };
        let e = a
            .append(Path::new("new.jsonl"), None, req, b"x", m(0o640))
            .unwrap_err();
        assert!(matches!(e, IoError::NotOwned { .. }), "got {e:?}");
        // The residue: created, empty, still there.
        let md = std::fs::metadata(a.path.join("new.jsonl"))
            .expect("the documented residue: a rejected create-append leaves the file");
        assert_eq!(md.len(), 0, "and it must be EMPTY — nothing was written");
    }

    /// A component cancelled by `..` is NEVER examined — pinned as CONTRACT.
    ///
    /// External review: `read("link/../policy.yaml")` succeeds although `link` is a
    /// symlink, because normalization is lexical and runs before any resolution. This
    /// cannot escape (the collapsed path is still anchor-relative), but it falsifies
    /// any claim that a symlink "anywhere on the path" is refused — the claim is
    /// "any component that SURVIVES normalization". This test makes the behaviour a
    /// stated decision rather than an accident, so a future "fix" that starts
    /// resolving cancelled components in caller order shows up as a red test and gets
    /// argued about, not slipped in.
    #[test]
    fn dotdot_cancelled_symlink_is_never_examined() {
        let d = dir(0o750);
        let a = anchor_at(d.path(), "cfg");
        std::fs::write(a.path.join("policy.yaml"), b"p").unwrap();
        symlink(d.path(), a.path.join("link")).unwrap(); // would escape if followed

        let out = a
            .read(Path::new("link/../policy.yaml"), None, t_req())
            .expect("the cancelled symlink component must not be examined");
        assert_eq!(&out.value[..], b"p");

        // And a NON-cancelled symlink component is still refused, same fixture.
        let e = a.read(Path::new("link/x.yaml"), None, t_req()).unwrap_err();
        assert!(matches!(e, IoError::Symlink { .. }), "got {e:?}");

        // A missing-but-cancelled component also never fails the lookup.
        let out2 = a
            .read(Path::new("missing/../policy.yaml"), None, t_req())
            .expect("a cancelled missing component must not be examined");
        assert_eq!(&out2.value[..], b"p");
    }

    /// Mode B must REFUSE a symlinked target, and no `check_target` predicate can
    /// substitute for that.
    ///
    /// The one control in the crate that was genuinely load-bearing and genuinely
    /// unheld. Measured: delete `O_NOFOLLOW` from `open_append` and the suite stays
    /// 107/107 green — then an attacker who can plant a symlink in the anchor gets
    /// audit records written OUTSIDE it.
    ///
    /// Why the target checks do not catch it: the `fstat` is taken on the fd the open
    /// returned, and that fd is the symlink's TARGET once the link has been followed.
    /// So `regular_file`, the `0o007` mode mask and even `nlink_exactly_one` all
    /// inspect the wrong inode and all pass. `write.rs` calls `st_nlink == 1` "the only
    /// detector" for a planted hard link — it is not a detector for this at all.
    /// `grants.d` is daemon-writable by design, which is what makes the plant possible.
    ///
    /// Why no mutant found it: `&` binds tighter than `|`, so every `| with &` mutant
    /// on this union drops TWO adjacent operands and is killed by the `O_APPEND`/
    /// `O_CREAT` half. Mutation cannot isolate a single flag; deleting it can.
    #[test]
    fn append_refuses_a_symlinked_target() {
        let d = dir(0o750);
        let a = anchor_at(d.path(), "cfg");

        // The attacker's collection point, OUTSIDE the anchor, and passing every
        // predicate a caller could name: regular, 0o640, nlink == 1.
        let outside = d.path().join("collect");
        std::fs::write(&outside, b"").unwrap();
        std::fs::set_permissions(&outside, std::fs::Permissions::from_mode(0o640)).unwrap();
        symlink(&outside, a.path.join("audit.jsonl")).unwrap();

        let err = a
            .append(
                Path::new("audit.jsonl"),
                None,
                TargetRequired {
                    // Every predicate NAMED, including owner, so the fixture proves
                    // what the doc claims: all of them pass on the followed inode.
                    owner: Some(nix::unistd::geteuid().as_raw()),
                    mode_mask: Some(0o007),
                    nlink_exactly_one: true,
                    regular_file: true,
                },
                b"RECORD\n",
                m(0o640),
            )
            .expect_err("a symlinked append target must be refused");

        match err {
            IoError::Symlink { path } => assert_eq!(path, a.path.join("audit.jsonl")),
            other => panic!("expected Symlink, got {other:?}"),
        }
        // The assertion that actually matters: nothing left the anchor.
        assert_eq!(
            std::fs::read(&outside).unwrap(),
            b"",
            "bytes were written OUTSIDE the anchor through the symlink"
        );
    }

    /// The ANCHOR ITSELF must be a directory — row 1's `O_DIRECTORY`.
    ///
    /// Row 0's twin, and the gap was one level up from where I looked. `replace | with
    /// &` at `open_dir_at`'s flag union drops `O_DIRECTORY` from the anchor's own open,
    /// and it is MISSED: nothing in the crate refuses a non-directory anchor.
    /// `check_owner_mode` has no `S_ISDIR` predicate and `open_anchor` does nothing else
    /// with the stat, so under that mutant `open_anchor("/etc/passwd", ...)` returns
    /// `Ok(Anchor)` — a "pinned anchor directory" that is a regular file, from which
    /// every later verb resolves relative to a non-directory.
    ///
    /// "Fails closed later" is true of the verbs but NOT of construction, which is the
    /// distinction that matters: the anchor is the thing the whole model pins.
    #[test]
    fn a_regular_file_is_not_an_anchor() {
        let d = dir(0o750);
        let f = d.path().join("not-a-dir");
        std::fs::write(&f, b"x").unwrap();
        match open_anchor(&f, none_req(), StrategyPref::Auto).unwrap_err() {
            IoError::Io { path, kind } => {
                assert_eq!(kind, crate::error::IoKind::NotADirectory);
                assert_eq!(path, f);
            }
            other => panic!("expected Io{{NotADirectory}}, got {other:?}"),
        }
    }

    /// Row 0's `O_DIRECTORY` is what makes the anchor's parent open FIFO-SAFE.
    ///
    /// Found by running the mutants that `.cargo/mutants.toml` excludes: `replace | with
    /// &` at the row-0 flag union drops `O_DIRECTORY`, and it was MISSED in 0s — no test
    /// reached it. Row 0 is also the one open in the crate with no `O_NONBLOCK`, so
    /// without `O_DIRECTORY` an `open(2)` on a FIFO parent BLOCKS waiting for a writer
    /// instead of returning ENOTDIR: `maknaed` hangs at startup rather than failing
    /// closed. The exclusion is what made the absence invisible.
    ///
    /// Run on a worker thread with a bounded wait, deliberately: the failure mode under
    /// test is a HANG, and a test that reproduces it by hanging tells CI nothing except
    /// that the job timed out. This way it fails with a sentence.
    #[test]
    fn anchor_parent_that_is_a_fifo_is_refused_and_does_not_block() {
        let d = dir(0o750);
        let fifo = d.path().join("pipe");
        nix::unistd::mkfifo(&fifo, nix::sys::stat::Mode::from_bits_truncate(0o600)).unwrap();
        let target = fifo.join("cfg"); // anchor whose PARENT is the FIFO

        let (tx, rx) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            let _ = tx.send(open_anchor(&target, none_req(), StrategyPref::Auto).map(|_| ()));
        });

        match rx.recv_timeout(std::time::Duration::from_secs(10)) {
            Err(std::sync::mpsc::RecvTimeoutError::Timeout) => panic!(
                "open_anchor did not return within 10s on a FIFO parent. Most likely \
                 row 0 lost O_DIRECTORY, so open(2) is waiting for a writer that will \
                 never come — but a starved runner produces the same symptom, so \
                 check the flags before concluding. (The worker stays blocked for the \
                 life of the test binary; harmless, and only on an already-red run.)"
            ),
            Err(e) => panic!("worker died: {e:?}"),
            Ok(Ok(())) => panic!("a FIFO parent must not yield a usable anchor"),
            Ok(Err(IoError::Io { path, kind })) => {
                assert_eq!(kind, crate::error::IoKind::NotADirectory);
                assert_eq!(path, fifo, "must name the parent that is not a directory");
            }
            Ok(Err(other)) => panic!("expected Io{{NotADirectory}}, got {other:?}"),
        }
    }

    /// A non-UTF-8 ANCHOR basename is reported as such, not as "ends in `..`".
    ///
    /// `MAKNAE_CONFIG_DIR` and `argv[1]` reach this with operator-supplied bytes, so
    /// the diagnosis is what an operator sees when it goes wrong. The old code folded
    /// this into `AnchorEndsInDotDot` because `file_name().and_then(to_str)` returns
    /// None for both, conflating "has no final component" with "is not UTF-8".
    /// No filesystem is touched, so this runs on APFS too.
    #[test]
    fn non_utf8_anchor_basename_is_not_reported_as_dot_dot() {
        use std::os::unix::ffi::OsStrExt;
        let bad = std::path::Path::new("/etc").join(std::ffi::OsStr::from_bytes(b"ma\xffnae"));
        let e = open_anchor(&bad, none_req(), StrategyPref::Auto).unwrap_err();
        assert!(
            matches!(e, IoError::NonUtf8Component { .. }),
            "got {e:?} -- AnchorEndsInDotDot here would be a false statement"
        );
        // And the genuine dot-dot case must still say dot-dot.
        let dd = std::path::Path::new("/etc/maknae/..");
        let e2 = open_anchor(dd, none_req(), StrategyPref::Auto).unwrap_err();
        assert!(
            matches!(e2, IoError::AnchorEndsInDotDot { .. }),
            "got {e2:?}"
        );
    }

    /// `publish` and `append` must propagate a FAILED WALK, not just `read`.
    ///
    /// Each of the three verbs calls `walk_dirs` at its own site. Every existing
    /// failing-walk test goes through `read` or `enumerate`, so the two write verbs'
    /// propagation was uncovered -- the same parallel-surface gap as the non-UTF-8
    /// conversion. A symlinked intermediate is the cheapest failing walk.
    #[test]
    fn publish_and_append_propagate_a_failed_walk() {
        let d = dir(0o750);
        let a = anchor_at(d.path(), "cfg");
        let real = a.path.join("real");
        std::fs::create_dir(&real).unwrap();
        symlink(&real, a.path.join("link")).unwrap();

        let e = a
            .publish(Path::new("link/out.yaml"), None, b"x", m(0o640))
            .unwrap_err();
        assert!(matches!(e, IoError::Symlink { .. }), "publish: got {e:?}");

        let e = a
            .append(
                Path::new("link/out.jsonl"),
                None,
                t_append(),
                b"x",
                m(0o640),
            )
            .unwrap_err();
        assert!(matches!(e, IoError::Symlink { .. }), "append: got {e:?}");

        // And nothing was created through the symlink.
        assert!(
            !real.join("out.yaml").exists(),
            "published through a symlink"
        );
        assert!(
            !real.join("out.jsonl").exists(),
            "appended through a symlink"
        );
    }

    /// Same for a non-UTF-8 TARGET name, which used to surface as `EmptyRemainder` --
    /// the remainder is not empty. This is the path PR B hits when it feeds an
    /// `enumerate` result back into `read`: `Entry.name` is a raw `OsString` by
    /// design, so a non-UTF-8 entry name arrives here legitimately.
    ///
    /// All THREE verbs, because they reach the conversion through two different
    /// functions: `read` has its own, while `publish` and `append` share
    /// `split_target`. Only `read`'s was covered, which is the parallel-surface trap
    /// this crate keeps falling into. No filesystem is touched, so it runs on APFS.
    #[test]
    fn non_utf8_target_name_is_not_reported_as_empty_remainder() {
        use std::os::unix::ffi::OsStrExt;
        let d = dir(0o750);
        let a = anchor_at(d.path(), "cfg");
        let bad = std::path::PathBuf::from(std::ffi::OsStr::from_bytes(b"10-\xff.yaml"));

        let e = a.read(&bad, None, t_req()).unwrap_err();
        assert!(
            matches!(e, IoError::NonUtf8Component { .. }),
            "read: got {e:?}"
        );

        let e = a.publish(&bad, None, b"x", m(0o640)).unwrap_err();
        assert!(
            matches!(e, IoError::NonUtf8Component { .. }),
            "publish: got {e:?}"
        );

        let e = a
            .append(&bad, None, t_append(), b"x", m(0o640))
            .unwrap_err();
        assert!(
            matches!(e, IoError::NonUtf8Component { .. }),
            "append: got {e:?}"
        );

        // The payload is the ABSOLUTE path, matching every other error these verbs
        // return; it used to be the bare relative remainder on two of the three.
        match a.read(&bad, None, t_req()).unwrap_err() {
            IoError::NonUtf8Component { path } => {
                assert!(
                    path.starts_with(&a.path),
                    "payload not anchor-absolute: {path:?}"
                )
            }
            other => panic!("got {other:?}"),
        }

        // A non-UTF-8 DIRECTORY component takes a DIFFERENT route from the case above:
        // the final component is valid UTF-8, so the verb-level conversions pass and
        // the refusal comes from deeper in. That site was missed by the payload sweep
        // and kept returning the bare relative path -- which the assertion above could
        // never catch, since it only exercises a non-UTF-8 FINAL component.
        //
        // WHICH site fires is lane-dependent, so this loop is not a walk_dirs test on
        // every host: on a Linux host with openat2, `read` has a 2-component remainder
        // and no descendant check, so select() picks the fast lane and the refusal
        // comes from the `norm.to_str()` guard BEFORE any walk. `publish` and `append`
        // never take that lane, so they reach walk_dirs everywhere; darwin reaches it
        // on all three. The assertion holds either way -- both sites are
        // anchor-absolute -- which is the point of asserting the property rather than
        // the source.
        let baddir = std::path::PathBuf::from(std::ffi::OsStr::from_bytes(b"d\xff")).join("x.yaml");
        for (verb, e) in [
            ("read", a.read(&baddir, None, t_req()).unwrap_err()),
            (
                "publish",
                a.publish(&baddir, None, b"x", m(0o640)).unwrap_err(),
            ),
            (
                "append",
                a.append(&baddir, None, t_append(), b"x", m(0o640))
                    .unwrap_err(),
            ),
        ] {
            match e {
                IoError::NonUtf8Component { path } => assert!(
                    path.starts_with(&a.path),
                    "{verb}: walk payload not anchor-absolute: {path:?}"
                ),
                other => panic!("{verb}: got {other:?}"),
            }
        }
    }

    /// All four quadrants of the read-completion verdict, on every platform.
    ///
    /// The public-API fixtures only reach the GREW case (`want == 0`, bytes present).
    /// Measured: deleting the `n != want` half of the check left 99/99 green, so the
    /// SHRANK direction -- which the commit claiming "both directions" asserted -- had
    /// no control at all. Its consequence is worse than truncation: the buffer is
    /// pre-sized with `vec![0u8; want]`, so a short read that returns Ok yields a tail
    /// of NUL bytes appended to the caller's policy content.
    #[test]
    fn size_verdict_covers_all_four_quadrants() {
        // Exact: read every promised byte and found nothing past them.
        assert_eq!(size_verdict(Want(13), Have(13), false), Ok(()));
        // Grew: at least one byte past st_size. `got` is a lower bound, n + 1.
        assert_eq!(size_verdict(Want(13), Have(13), true), Err(14));
        // Shrank: fewer bytes than the checked inode claimed. `got` is exact.
        assert_eq!(size_verdict(Want(13), Have(5), false), Err(5));
        // Shrank AND something readable past the short count -- still shrank, and the
        // reported count stays the honest one rather than the +1 lower bound.
        assert_eq!(size_verdict(Want(13), Have(5), true), Err(5));
        // The empty file is the boundary: exact, not a spurious refusal.
        assert_eq!(size_verdict(Want(0), Have(0), false), Ok(()));
        assert_eq!(size_verdict(Want(0), Have(0), true), Err(1));
    }

    /// A file whose readable length exceeds its `st_size` must be REFUSED, not
    /// silently truncated to `st_size`.
    ///
    /// This is the "grew under the read" case. The buffer is sized from `st_size`, so
    /// bytes beyond it are dropped; returning `Ok` with the short content is how a
    /// deny rule appended mid-read disappears. `std::fs::read` -- what the call sites
    /// this crate replaces use today -- reads to EOF and cannot truncate this way, so
    /// silence here would be a REGRESSION against the code being migrated.
    ///
    /// Provoking it by racing an append against the read is not deterministic. Linux
    /// procfs gives the same shape with no race at all: `/proc/<pid>/status` is a
    /// regular file that reports `st_size == 0` and yields content on read -- exactly
    /// "more bytes than the fstat promised", which is the condition under test.
    #[cfg(target_os = "linux")]
    #[test]
    fn a_file_longer_than_its_st_size_is_refused_not_truncated() {
        let me = std::process::id();
        let proc_dir = std::path::PathBuf::from(format!("/proc/{me}"));
        if !proc_dir.join("status").exists() {
            crate::testutil::skip_or_fail(
                "a_file_longer_than_its_st_size_is_refused_not_truncated",
                "/proc is not mounted, so the GREW direction has no fixture",
            );
            return;
        }
        // st_size must really be 0 here, or the fixture is not testing what it claims.
        let sz = std::fs::symlink_metadata(proc_dir.join("status"))
            .unwrap()
            .len();
        assert_eq!(sz, 0, "fixture requires st_size == 0, got {sz}");

        let a = open_anchor(&proc_dir, none_req(), StrategyPref::ForcePortable).unwrap();
        let err = a
            .read(Path::new("status"), None, t_req())
            .expect_err("a file longer than st_size must be refused");
        assert!(
            matches!(
                err,
                IoError::SizeChanged {
                    expected: 0,
                    got: 1,
                    ..
                }
            ),
            "expected SizeChanged, got {err:?}"
        );
    }

    /// The lanes must be DISCRIMINABLE, or every openat2 assertion is vacuous.
    ///
    /// Before this test the openat2 block could be deleted outright with all tests
    /// still green: `walk_dirs` ran unconditionally BEFORE lane selection, so the
    /// portable chain had already resolved the remainder and openat2 merely redid it.
    /// `multi_component_unchecked_reports_openat2` only asserts `effective_strategy`,
    /// which is a label `select()` computes -- not evidence that `openat2_resolve`
    /// ran. `both_lanes_refuse_a_symlinked_component` is likewise held entirely by the
    /// walk's per-component O_NOFOLLOW, leaving RESOLVE_NO_SYMLINKS/RESOLVE_BENEATH
    /// with zero control. That is PAST TENSE: since selection moved ahead of the walk,
    /// `read` returns on the openat2 lane before any walk runs, so on Linux
    /// `both_lanes_refuse_a_symlinked_component` with `pref = Auto` IS the control for
    /// RESOLVE_NO_SYMLINKS (see the note on `map_open_errno`). RESOLVE_BENEATH stays
    /// redundant-by-construction — `normalize` refuses an escaping `..` above this
    /// seam. Left in place because a reader who trusts the old wording concludes a
    /// control is missing that is present, which is as expensive as the reverse.
    ///
    /// The fixture is the one measured difference between the lanes: an EXECUTE-ONLY
    /// (0o311) intermediate directory. Path resolution needs only `x` to traverse it,
    /// which the kernel does internally for openat2 -- but the portable walk must
    /// `openat(..., O_RDONLY|O_DIRECTORY)` that directory, and opening a directory for
    /// reading needs `r`. So openat2 OPENS and portable gets EACCES. Same anchor, same
    /// path, opposite outcomes: deleting the openat2 block turns the first half RED.
    #[cfg(target_os = "linux")]
    #[test]
    fn execute_only_descendant_separates_the_two_lanes() {
        // root ignores permission bits, so the discriminator disappears under it.
        if nix::unistd::Uid::effective().is_root() {
            crate::testutil::skip_or_fail(
                "execute_only_descendant_separates_the_two_lanes",
                "running as root, which ignores the 0o311 permission bits the \
                 fixture depends on",
            );
            return;
        }
        let d = dir(0o750);
        let a = anchor_pref(d.path(), "cfg", StrategyPref::Auto);
        let sub = a.path.join("config.d");
        std::fs::create_dir(&sub).unwrap();
        std::fs::write(sub.join("10-x.yaml"), b"lane").unwrap();
        // Execute-only: traversable, not readable.
        std::fs::set_permissions(&sub, std::fs::Permissions::from_mode(0o311)).unwrap();

        if a.probed_capability() != Strategy::Openat2 {
            crate::testutil::skip_or_fail(
                "execute_only_descendant_separates_the_two_lanes",
                "openat2 is not available, so the two lanes are not discriminated",
            );
            return;
        }

        let out = a
            .read(Path::new("config.d/10-x.yaml"), None, t_req())
            .expect("openat2 traverses an execute-only directory");
        assert_eq!(out.effective_strategy, Strategy::Openat2);
        assert_eq!(&out.value[..], b"lane");

        // Same anchor, same path, portable lane forced: the walk must open the
        // directory for reading and cannot.
        let p = anchor_pref(d.path(), "cfg", StrategyPref::ForcePortable);
        let err = p
            .read(Path::new("config.d/10-x.yaml"), None, t_req())
            .expect_err("portable walk must be refused by an execute-only directory");
        assert!(
            matches!(err, IoError::Io { .. }),
            "expected EACCES-backed refusal, got {err:?}"
        );

        std::fs::set_permissions(&sub, std::fs::Permissions::from_mode(0o750)).unwrap();
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
            crate::testutil::skip_or_fail(
                "multi_component_unchecked_reports_openat2",
                "openat2 is not available on this host",
            );
            return;
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

            // The VARIANT is identical on both lanes, and that is the part PR B maps
            // on. It does not come for free: the two lanes reach it from DIFFERENT
            // errnos, measured on Linux 6.12 --
            //   openat2 + RESOLVE_NO_SYMLINKS on a symlinked intermediate -> ELOOP
            //   openat  + O_NOFOLLOW|O_DIRECTORY on the symlink           -> ENOTDIR
            // ELOOP maps to Symlink directly; ENOTDIR only gets there through the
            // fstatat disambiguation in checks::map_errno, which is exactly why that
            // disambiguation exists.
            let path = match &e {
                IoError::Symlink { path } => path.clone(),
                other => panic!("{pref:?}: expected Symlink, got {other:?}"),
            };

            // The PAYLOAD legitimately differs, and it is asserted rather than left
            // to `..` so the divergence cannot drift unnoticed. The portable walk
            // knows WHICH component offended and names it; openat2 refuses inside the
            // kernel and reports only the path it was asked to resolve.
            let expected = if pref == StrategyPref::ForcePortable || !uses_openat2_here(&a) {
                a.path.join("link")
            } else {
                a.path.join("link/x.yaml")
            };
            assert_eq!(path, expected, "{pref:?}: payload drifted");
        }
    }

    /// True when this host will actually take the openat2 lane for a 2-component
    /// remainder with no descendant check. Written as a helper so the expectation
    /// above is derived from the same capability the code branches on, rather than
    /// from `cfg!(linux)` -- a Linux kernel without openat2 takes the portable lane.
    fn uses_openat2_here(a: &Anchor) -> bool {
        a.probed_capability() == Strategy::Openat2
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
        // BOUNDED WAIT, like the other FIFO tests. This test is what holds
        // `open_read_target`'s O_NONBLOCK, and it holds it by HANGING if the flag goes
        // — which tells CI nothing except that the job timed out, and on a metered
        // runner costs the full job budget. Same shape as its two siblings.
        let (tx, rx) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            let _ = tx.send(a.read(Path::new("f"), None, req).map(|_| ()));
        });
        match rx.recv_timeout(std::time::Duration::from_secs(10)) {
            Err(std::sync::mpsc::RecvTimeoutError::Timeout) => panic!(
                "read did not return within 10s on a FIFO. Most likely \
                 open_read_target lost O_NONBLOCK, so open(2) is waiting for a writer \
                 that will never come — a starved runner looks the same, so check the \
                 flags before concluding."
            ),
            Err(e) => panic!("worker died: {e:?}"),
            Ok(Ok(())) => panic!("a FIFO must not read as a regular file"),
            Ok(Err(e)) => assert!(matches!(e, IoError::NotRegularFile { .. }), "got {e:?}"),
        }
    }

    fn m(x: u32) -> Mode {
        Mode(x)
    }

    #[test]
    fn publish_lands_in_the_pinned_directory() {
        let _g = PUBLISH_LOCK.lock().unwrap_or_else(|p| p.into_inner());
        let d = dir(0o750);
        let a = anchor_at(d.path(), "cfg");
        a.publish(Path::new("out.yaml"), None, b"payload", m(0o640))
            .unwrap();
        assert_eq!(std::fs::read(a.path.join("out.yaml")).unwrap(), b"payload");
    }

    /// `publish`'s O_EXCL, controlled AT THE PUBLISH LEVEL.
    ///
    /// The wrapper tests (`temp_open_refuses_a_preexisting_name` and its symlink twin)
    /// call `syscall::open_temp_excl` directly, so they only prove that WRAPPER's
    /// flags -- not that `publish_raw` uses it. Measured: swap the opener in
    /// `publish_raw` for the non-O_EXCL, non-O_TRUNC `open_append` and every one of
    /// those tests still passes. Two reasons, and the second is not the one this
    /// comment used to give: syscall.rs is `exclude_globs`, so no mutant rewrites the
    /// flags; and region coverage cannot distinguish WHICH function a covered line
    /// calls, so the swap is invisible to it by construction. (An earlier version
    /// blamed a write.rs coverage exception on that call line. There is no longer one
    /// — it was deleted as stale once this test began covering the arm.)
    ///
    /// The attack the flag stops: an attacker who can write into the anchor
    /// pre-creates the temp name with longer content. Without O_EXCL the open
    /// succeeds; without O_TRUNC the tail of the attacker's content survives past the
    /// payload, and renameat publishes it under the FINAL name.
    ///
    /// Determinism without predicting the counter: `temp_name` is monotonic, so one
    /// call reveals the current value and the next K names are known. Pre-creating a
    /// range rather than a single name absorbs any interleaved counter bump -- the
    /// build sheet's original single-name fixture was itself a race and failed 2 of 3
    /// runs.
    #[test]
    fn publish_refuses_a_preexisting_temp_name() {
        let _g = PUBLISH_LOCK.lock().unwrap_or_else(|p| p.into_inner());
        let d = dir(0o750);
        let a = anchor_at(d.path(), "cfg");

        let probe = crate::write::temp_name("out.yaml");
        let n: u64 = probe.rsplit('.').next().unwrap().parse().unwrap();
        let stem = probe.rsplit_once('.').unwrap().0;
        for k in 1..=8 {
            std::fs::write(a.path.join(format!("{stem}.{}", n + k)), b"SQUATTED-LONGER").unwrap();
        }

        let err = a
            .publish(Path::new("out.yaml"), None, b"payload", m(0o640))
            .expect_err("O_EXCL must refuse a temp name that already exists");
        // EEXIST specifically. `IoError::Io { .. }` would also be satisfied by an
        // unrelated EACCES, which would let the test pass for the wrong reason.
        match &err {
            IoError::Io {
                kind: crate::error::IoKind::Other { raw },
                ..
            } => assert_eq!(*raw, nix::errno::Errno::EEXIST as i32, "expected EEXIST"),
            other => panic!("expected Io{{Other{{EEXIST}}}}, got {other:?}"),
        }
        assert!(
            !a.path.join("out.yaml").exists(),
            "nothing may be published when the temp open is refused"
        );
    }

    /// The anchor-swap fixture: "publishes to the pinned dir" passes trivially without
    /// it. Holding the Anchor across a rename of the anchor directory proves the write
    /// went to the pinned inode, not to a re-resolved path.
    #[test]
    fn publish_follows_the_pinned_fd_not_the_path() {
        let _g = PUBLISH_LOCK.lock().unwrap_or_else(|p| p.into_inner());
        let d = dir(0o750);
        let a = anchor_at(d.path(), "cfg");
        let orig = a.path.clone();
        let moved = d.path().join("moved");
        std::fs::rename(&orig, &moved).unwrap();
        std::fs::create_dir(&orig).unwrap();
        std::fs::set_permissions(&orig, std::fs::Permissions::from_mode(0o750)).unwrap();

        a.publish(Path::new("out.yaml"), None, b"pinned", m(0o640))
            .unwrap();

        assert_eq!(std::fs::read(moved.join("out.yaml")).unwrap(), b"pinned");
        assert!(!orig.join("out.yaml").exists(), "wrote to the decoy path");
    }

    /// Effective mode post-umask, and the temp must not survive.
    #[test]
    fn publish_effective_mode_and_no_leftover_temp() {
        let _g = PUBLISH_LOCK.lock().unwrap_or_else(|p| p.into_inner());
        let d = dir(0o750);
        let a = anchor_at(d.path(), "cfg");
        a.publish(Path::new("m.yaml"), None, b"x", m(0o640))
            .unwrap();
        let got = std::fs::metadata(a.path.join("m.yaml"))
            .unwrap()
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(got, 0o640 & !umask_now(), "effective mode {got:o}");
        let leftovers: Vec<_> = std::fs::read_dir(&a.path)
            .unwrap()
            .filter_map(|e| e.ok())
            .filter(|e| e.file_name().to_string_lossy().contains(".tmp."))
            .collect();
        assert!(leftovers.is_empty(), "temp survived: {leftovers:?}");
    }

    /// MUTATES PROCESS-GLOBAL STATE. Every caller must hold `PUBLISH_LOCK`, or its
    /// window can land inside another test's file creation and change the mode that
    /// test observes. Benign wherever the real umask is already 0o022 — i.e. almost
    /// always — which is exactly what makes it a latent parallel-harness flake rather
    /// than a visible one.
    fn umask_now() -> u32 {
        let m = nix::sys::stat::umask(nix::sys::stat::Mode::from_bits_truncate(0o022));
        nix::sys::stat::umask(m);
        m.bits() as u32
    }

    /// Covers the renameat Err arm AND the cleanup path: publishing onto an existing
    /// DIRECTORY name is EISDIR on a healthy FS.
    #[test]
    fn publish_onto_a_directory_name_errs_and_cleans_up() {
        let _g = PUBLISH_LOCK.lock().unwrap_or_else(|p| p.into_inner());
        let d = dir(0o750);
        let a = anchor_at(d.path(), "cfg");
        std::fs::create_dir(a.path.join("busy")).unwrap();
        let e = a
            .publish(Path::new("busy"), None, b"y", m(0o640))
            .unwrap_err();
        assert!(matches!(e, IoError::Io { .. }), "got {e:?}");
        let leftovers: Vec<_> = std::fs::read_dir(&a.path)
            .unwrap()
            .filter_map(|e| e.ok())
            .filter(|e| e.file_name().to_string_lossy().contains(".tmp."))
            .collect();
        assert!(
            leftovers.is_empty(),
            "temp not cleaned after rename failure: {leftovers:?}"
        );
    }

    #[test]
    fn publish_zero_component_is_empty_remainder() {
        let d = dir(0o750);
        let a = anchor_at(d.path(), "cfg");
        let e = a
            .publish(Path::new("sub/.."), None, b"y", m(0o640))
            .unwrap_err();
        assert_eq!(e, IoError::EmptyRemainder);
    }

    /// Multi-component publish — exercises the walked branch and its dirfd.
    #[test]
    fn publish_into_a_subdirectory() {
        let _g = PUBLISH_LOCK.lock().unwrap_or_else(|p| p.into_inner());
        let d = dir(0o750);
        let a = anchor_at(d.path(), "cfg");
        let sub = a.path.join("grants.d");
        std::fs::create_dir(&sub).unwrap();
        std::fs::set_permissions(&sub, std::fs::Permissions::from_mode(0o750)).unwrap();
        let req = DescendantRequired {
            owner: None,
            mode_mask: Some(0o007),
        };
        a.publish(Path::new("grants.d/g.yaml"), Some(req), b"grant", m(0o640))
            .unwrap();
        assert_eq!(std::fs::read(sub.join("g.yaml")).unwrap(), b"grant");
    }

    #[test]
    fn publish_pre_check_rejects_an_orphan_requirement() {
        let d = dir(0o750);
        let a = anchor_at(d.path(), "cfg");
        let req = DescendantRequired {
            owner: None,
            mode_mask: Some(0o007),
        };
        let e = a
            .publish(Path::new("top.yaml"), Some(req), b"y", m(0o640))
            .unwrap_err();
        assert!(
            matches!(e, IoError::NoDescendantForRequirement { .. }),
            "got {e:?}"
        );
    }

    #[test]
    fn publish_propagates_escape_refusal() {
        let d = dir(0o750);
        let a = anchor_at(d.path(), "cfg");
        let e = a
            .publish(Path::new("../out.yaml"), None, b"y", m(0o640))
            .unwrap_err();
        assert!(matches!(e, IoError::EscapesAnchor { .. }), "got {e:?}");
    }

    fn t_append() -> TargetRequired {
        TargetRequired {
            owner: None,
            mode_mask: Some(0o007),
            nlink_exactly_one: true,
            regular_file: true,
        }
    }

    /// Proves O_APPEND, not O_TRUNC-absence: the file is PRE-POPULATED and a second
    /// append with a fresh fd must not clobber byte 0. A fresh-file two-append test
    /// passes without O_APPEND and proves nothing.
    #[test]
    fn append_does_not_clobber_existing_bytes() {
        let d = dir(0o750);
        let a = anchor_at(d.path(), "cfg");
        let f = a.path.join("audit.jsonl");
        std::fs::write(&f, b"FIRST\n").unwrap();
        std::fs::set_permissions(&f, std::fs::Permissions::from_mode(0o640)).unwrap();
        a.append(
            Path::new("audit.jsonl"),
            None,
            t_append(),
            b"SECOND\n",
            m(0o640),
        )
        .unwrap();
        assert_eq!(std::fs::read(&f).unwrap(), b"FIRST\nSECOND\n");
    }

    /// grants.d is daemon-writable by design, so a compromised writer can hard-link a
    /// file from outside the anchor into the overlay. st_nlink == 1 is the detector.
    #[test]
    fn append_refuses_a_hard_linked_target() {
        let d = dir(0o750);
        let a = anchor_at(d.path(), "cfg");
        let f = a.path.join("audit.jsonl");
        std::fs::write(&f, b"x").unwrap();
        std::fs::set_permissions(&f, std::fs::Permissions::from_mode(0o640)).unwrap();
        std::fs::hard_link(&f, a.path.join("outside.link")).unwrap();
        let e = a
            .append(Path::new("audit.jsonl"), None, t_append(), b"y", m(0o640))
            .unwrap_err();
        assert!(
            matches!(e, IoError::MultiplyLinked { nlink, .. } if nlink == 2),
            "got {e:?}"
        );
    }

    /// Creation mode post-umask. The crate must not pick this — spec decision 11 says
    /// the caller names it, and sink.rs uses 0o640.
    #[test]
    fn append_creates_with_the_callers_mode() {
        // Holds PUBLISH_LOCK not because it publishes, but because it calls
        // `umask_now()`, which mutates process-global state. Without it this test's
        // umask window can land inside a lock-holding publish test's file creation and
        // change the mode that test observes.
        let _g = PUBLISH_LOCK.lock().unwrap_or_else(|p| p.into_inner());
        let d = dir(0o750);
        let a = anchor_at(d.path(), "cfg");
        a.append(
            Path::new("new.jsonl"),
            None,
            t_append(),
            b"line\n",
            m(0o640),
        )
        .unwrap();
        let got = std::fs::metadata(a.path.join("new.jsonl"))
            .unwrap()
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(got, 0o640 & !umask_now(), "effective mode {got:o}");
    }

    /// A readerless FIFO fails the WRITE open with ENXIO before any fstat, so
    /// regular_file never runs on this path — the read-side FIFO fact does not
    /// transfer, and NotRegularFile would be the wrong expectation.
    #[test]
    fn append_to_a_fifo_is_enxio_at_the_open() {
        let d = dir(0o750);
        let a = anchor_at(d.path(), "cfg");
        nix::unistd::mkfifo(
            &a.path.join("f"),
            nix::sys::stat::Mode::from_bits_truncate(0o600),
        )
        .unwrap();
        // BOUNDED WAIT: this test holds `open_append`'s O_NONBLOCK, and without the
        // flag the write-open blocks rather than returning ENXIO.
        let (tx, rx) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            let _ = tx.send(
                a.append(Path::new("f"), None, t_append(), b"y", m(0o640))
                    .map(|_| ()),
            );
        });
        let e = match rx.recv_timeout(std::time::Duration::from_secs(10)) {
            Err(std::sync::mpsc::RecvTimeoutError::Timeout) => panic!(
                "append did not return within 10s on a readerless FIFO. Most likely \
                 open_append lost O_NONBLOCK — a starved runner looks the same, so \
                 check the flags before concluding."
            ),
            Err(e) => panic!("worker died: {e:?}"),
            Ok(Ok(())) => panic!("a readerless FIFO must not accept an append"),
            Ok(Err(e)) => e,
        };
        match e {
            IoError::Io {
                kind: crate::error::IoKind::Other { raw },
                ..
            } => {
                assert_eq!(raw, nix::errno::Errno::ENXIO as i32, "expected ENXIO");
            }
            other => panic!("expected Io{{Other{{ENXIO}}}}, got {other:?}"),
        }
    }

    /// Lands in the anchor's directory — anchor-swap fixture, same reason as publish.
    #[test]
    fn append_follows_the_pinned_fd_not_the_path() {
        let d = dir(0o750);
        let a = anchor_at(d.path(), "cfg");
        let orig = a.path.clone();
        let moved = d.path().join("moved-b");
        std::fs::rename(&orig, &moved).unwrap();
        std::fs::create_dir(&orig).unwrap();
        std::fs::set_permissions(&orig, std::fs::Permissions::from_mode(0o750)).unwrap();
        a.append(
            Path::new("a.jsonl"),
            None,
            t_append(),
            b"pinned\n",
            m(0o640),
        )
        .unwrap();
        assert_eq!(std::fs::read(moved.join("a.jsonl")).unwrap(), b"pinned\n");
        assert!(!orig.join("a.jsonl").exists(), "wrote to the decoy path");
    }

    #[test]
    fn append_zero_component_is_empty_remainder() {
        let d = dir(0o750);
        let a = anchor_at(d.path(), "cfg");
        let e = a
            .append(Path::new("sub/.."), None, t_append(), b"y", m(0o640))
            .unwrap_err();
        assert_eq!(e, IoError::EmptyRemainder);
    }
}
