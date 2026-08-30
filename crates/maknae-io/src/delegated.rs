//! Verification of a file descriptor delegated by a subject (ADR-0009).
//!
//! The subject's own `open(2)` already ran the kernel's whole permission check --
//! DAC bits, POSIX ACLs, supplementary groups, SELinux/AppArmor. **The descriptor
//! IS the OS's answer**, which is why nothing here recomputes the mode algebra and
//! why `TargetRequired { owner, mode_mask }` stay `None` on this path.
//!
//! What the descriptor does NOT prove is *where* the object is. Confinement is a
//! separate, Maknae-owned proof, and it is taken from the daemon's OWN fd table --
//! never by resolving a client-supplied name, which would need traversal permission
//! on the subject's home that a `0700` home does not grant (#194).

use std::os::fd::BorrowedFd;
use std::path::PathBuf;

use crate::checks::TargetRequired;
use crate::error::IoError;

/// What a caller requires of a delegated descriptor. Callers **name** what they
/// require; `None` is a named, greppable absence, never a silent one.
#[derive(Debug)]
pub struct DelegatedRequired {
    /// The object must resolve beneath this **absolute, canonical** directory.
    /// Canonical because the kernel reports a resolved path; a root behind a
    /// symlink would never match.
    ///
    /// **Not an `Option`, deliberately.** Elsewhere in this crate `None` is a
    /// named "this caller requires no such check". Here there is no such caller:
    /// ADR-0009 decision 3 makes confinement one of the two proofs a delegated
    /// descriptor always needs, and the descriptor itself proves only *access*,
    /// never *where*. Making the unconfined state inexpressible is stronger than
    /// documenting that nobody should ask for it — the same reasoning ADR-0008
    /// decision 1 applies to the baseline authorizer.
    pub confined_beneath: PathBuf,
    /// The usual target checks, applied to this descriptor by `fstat`.
    pub target: TargetRequired,
}

/// What the kernel says about a delegated descriptor.
#[derive(Debug)]
pub struct Delegated {
    /// The path the kernel reports -- **ground truth**, and what the PDP decides
    /// on (ADR-0009 decision 6), never the client-supplied string.
    pub path: PathBuf,
}

/// Verify a subject-delegated descriptor. Does not consume the fd: the caller
/// still reads from the very descriptor that was checked, so there is no
/// check-then-reopen window.
pub fn verify_delegated(fd: BorrowedFd<'_>, req: DelegatedRequired) -> Result<Delegated, IoError> {
    let path = crate::syscall::fd_path(&fd).map_err(|e| IoError::FdPathUnavailable {
        kind: crate::checks::kind_of_errno(e),
    })?;
    // Component-wise. NEVER `str::strip_prefix`: `/home/opx` is a string prefix
    // of `/home/op` and must not match. Confinement is checked FIRST: for an
    // object outside the enrolled root, "not beneath your home" is the truthful
    // reason, whatever kind of object it turns out to be.
    if path.strip_prefix(&req.confined_beneath).is_err() {
        return Err(IoError::EscapesAnchor { path });
    }
    // The named requirements, taken from the SAME descriptor the caller will read
    // -- no reopen, so no check-then-use window. `owner`/`mode_mask` stay `None`
    // on this path by design (ADR-0009 decision 1): the descriptor is already the
    // OS's answer, and recomputing the mode algebra here is what the operator
    // forbade.
    let st = crate::syscall::fstat(&fd)
        .map_err(|e| crate::checks::map_errno_no_disambiguation(e, &path))?;
    crate::checks::check_target(&st, &path, &req.target)?;
    Ok(Delegated { path })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{IoError, TargetRequired};
    use std::os::fd::AsFd;
    use std::path::PathBuf;
    use std::os::unix::fs::PermissionsExt;

    fn target() -> TargetRequired {
        TargetRequired {
            owner: None,
            mode_mask: None,
            nlink_exactly_one: true,
            regular_file: true,
            max_bytes: Some(4096),
        }
    }

    /// The diagnostic surface is what an operator reads when a read was refused
    /// and they need to know WHICH object and WHICH root disagreed. A `Debug`
    /// that omitted either would make a denial unreconstructable, which is the
    /// same failure ADR-0019 names for the audit trail.
    #[test]
    fn the_diagnostic_surface_names_the_object_and_the_confinement_root() {
        let req = DelegatedRequired {
            confined_beneath: PathBuf::from("/home/operator"),
            target: target(),
        };
        let rendered = format!("{req:?}");
        assert!(
            rendered.contains("/home/operator"),
            "the requirement must name its confinement root: {rendered}"
        );

        let rendered = format!(
            "{:?}",
            Delegated {
                path: PathBuf::from("/home/operator/notes"),
            }
        );
        assert!(
            rendered.contains("/home/operator/notes"),
            "the outcome must name the kernel-reported path: {rendered}"
        );
    }

    /// Confinement is COMPONENT-wise, and this is the assertion that says so.
    ///
    /// Found by mutation, not by design review: swapping `Path::strip_prefix` for
    /// a string `starts_with` survived every other test in this module. `/home/opx`
    /// IS a string prefix of `/home/op`, so the string form hands a subject every
    /// object in a sibling home whose name merely extends their own -- silently,
    /// and only for unlucky username pairs.
    #[test]
    fn a_sibling_root_whose_name_extends_the_confinement_root_does_not_match() {
        let root = tempfile::tempdir().expect("tempdir");
        let base = root.path().canonicalize().expect("canonicalize");
        let confined = base.join("op");
        let sibling = base.join("opx");
        std::fs::create_dir_all(&confined).expect("mkdir op");
        std::fs::create_dir_all(&sibling).expect("mkdir opx");
        let secret = sibling.join("secret");
        std::fs::write(&secret, b"another subject's file").expect("write");
        let f = std::fs::File::open(&secret).expect("open");

        match verify_delegated(
            f.as_fd(),
            DelegatedRequired {
                confined_beneath: confined,
                target: target(),
            },
        ) {
            Err(IoError::EscapesAnchor { path }) => assert_eq!(path, secret),
            other => panic!(
                "`opx` is a STRING prefix of `op` but not a COMPONENT prefix; \
                 it must be refused: {other:?}"
            ),
        }
    }

    /// A delegated fd is honest authority over an OBJECT -- it says nothing about
    /// what KIND of object. A fifo would block the read forever and a device would
    /// stream unboundedly, so the named `regular_file` requirement is enforced on
    /// the descriptor itself (ADR-0009 Consequences).
    #[test]
    fn a_delegated_fd_to_a_non_regular_file_is_refused() {
        let root = tempfile::tempdir().expect("tempdir");
        let home = root.path().canonicalize().expect("canonicalize");
        let pipe = home.join("pipe");
        nix::unistd::mkfifo(&pipe, nix::sys::stat::Mode::S_IRUSR | nix::sys::stat::Mode::S_IWUSR)
            .expect("mkfifo");
        // O_NONBLOCK: a reader on a writerless fifo blocks forever otherwise --
        // which is precisely the denial-of-service this requirement refuses.
        let f = nix::fcntl::open(
            &pipe,
            nix::fcntl::OFlag::O_RDONLY | nix::fcntl::OFlag::O_NONBLOCK,
            nix::sys::stat::Mode::empty(),
        )
        .expect("open fifo");

        match verify_delegated(
            f.as_fd(),
            DelegatedRequired {
                confined_beneath: home,
                target: target(),
            },
        ) {
            Err(IoError::NotRegularFile { path }) => assert_eq!(path, pipe),
            other => panic!("a fifo must be refused: {other:?}"),
        }
    }

    /// `nlink_exactly_one` is load-bearing for CONFINEMENT under ADR-0009 D5, not
    /// merely for alias refusal: with a second link the kernel reports *a* path
    /// rather than *the* path, and prefix-checking one of several names proves
    /// nothing about the others.
    #[test]
    fn a_delegated_fd_with_a_second_link_is_refused() {
        let root = tempfile::tempdir().expect("tempdir");
        let home = root.path().canonicalize().expect("canonicalize");
        let real = home.join("notes");
        std::fs::write(&real, b"one object, two names").expect("write");
        std::fs::hard_link(&real, home.join("alias")).expect("hard link");
        let f = std::fs::File::open(&real).expect("open");

        match verify_delegated(
            f.as_fd(),
            DelegatedRequired {
                confined_beneath: home,
                target: target(),
            },
        ) {
            Err(IoError::MultiplyLinked { nlink, .. }) => assert_eq!(nlink, 2),
            other => panic!("a multiply-linked object must be refused: {other:?}"),
        }
    }

    /// The frame budget is a named bound, refused BEFORE any buffer is allocated:
    /// a permitted 20 GiB file must not OOM the TCB.
    #[test]
    fn a_delegated_fd_over_the_named_budget_is_refused() {
        let root = tempfile::tempdir().expect("tempdir");
        let home = root.path().canonicalize().expect("canonicalize");
        let big = home.join("big");
        std::fs::write(&big, b"more than four bytes").expect("write");
        let f = std::fs::File::open(&big).expect("open");

        match verify_delegated(
            f.as_fd(),
            DelegatedRequired {
                confined_beneath: home,
                target: TargetRequired {
                    max_bytes: Some(4),
                    ..target()
                },
            },
        ) {
            Err(IoError::TargetTooLarge { limit, actual, .. }) => {
                assert_eq!((limit, actual), (4, 20))
            }
            other => panic!("an oversize target must be refused: {other:?}"),
        }
    }

    /// The ENVIRONMENT PROPERTY the whole confinement design rests on, measured
    /// rather than assumed: the kernel-reported path is read from the daemon's OWN
    /// fd table, so it survives a directory that grants the reader nothing at all.
    ///
    /// This is the STIG `0700`-home case (#194) reduced to its essence. Sabotage
    /// `syscall::fd_path` into ANY name-resolving form and this goes red with
    /// EACCES -- which is the whole reason ADR-0009 decision 4 exists.
    #[test]
    fn the_kernel_reported_path_survives_a_directory_the_reader_cannot_traverse() {
        if nix::unistd::geteuid().is_root() {
            crate::testutil::skip_or_fail(
                "the_kernel_reported_path_survives_a_directory_the_reader_cannot_traverse",
                "running as root, which traverses a 0000 directory and voids the premise",
            );
            return;
        }
        let root = tempfile::tempdir().expect("tempdir");
        let home = root.path().join("home");
        std::fs::create_dir_all(&home).expect("mkdir home");
        let secret = home.join("notes");
        std::fs::write(&secret, b"beneath the home").expect("write");
        let home_c = home.canonicalize().expect("canonicalize home");
        let secret_c = secret.canonicalize().expect("canonicalize target");

        let f = std::fs::File::open(&secret).expect("the subject opens it while it still can");

        // 0000: no read, no search, for ANYONE -- stricter than a STIG 0700 home
        // is to a non-owner, so it subsumes the case we actually care about.
        std::fs::set_permissions(&home, std::fs::Permissions::from_mode(0o000)).expect("lock");
        let name_reach = std::fs::metadata(&secret).is_err();
        let got = verify_delegated(
            f.as_fd(),
            DelegatedRequired {
                confined_beneath: home_c,
                target: target(),
            },
        );
        // Restore BEFORE asserting, so a failure still leaves a removable tempdir.
        std::fs::set_permissions(&home, std::fs::Permissions::from_mode(0o700)).expect("restore");

        assert!(
            name_reach,
            "premise: the directory must be untraversable, or this control proves nothing"
        );
        assert_eq!(
            got.expect("the fd table needs NO permission on the object's directory").path,
            secret_c,
        );
    }

    /// Confinement is a MAKNAE control, independent of what OS DAC permits: the
    /// subject here legitimately opens a file it owns and can read, so the
    /// delegated fd is honest authority -- and it is still refused, because the
    /// object does not lie beneath the enrolled root (ADR-0009 decision 3).
    #[test]
    fn a_delegated_fd_outside_the_confinement_root_is_refused() {
        let root = tempfile::tempdir().expect("tempdir");
        let home = root.path().join("home");
        let elsewhere = root.path().join("elsewhere");
        std::fs::create_dir_all(&home).expect("mkdir home");
        std::fs::create_dir_all(&elsewhere).expect("mkdir elsewhere");
        let secret = elsewhere.join("secret");
        std::fs::write(&secret, b"NOT BENEATH THE HOME").expect("write");

        // Canonical, because the kernel reports the resolved path and a
        // tempdir root may itself sit behind a symlink.
        let home = home.canonicalize().expect("canonicalize home");
        let secret = secret.canonicalize().expect("canonicalize target");

        let f = std::fs::File::open(&secret).expect("the subject opens its own file");

        let got = verify_delegated(
            f.as_fd(),
            DelegatedRequired {
                confined_beneath: home,
                target: target(),
            },
        );

        match got {
            Err(IoError::EscapesAnchor { path }) => assert_eq!(
                path, secret,
                "the refusal names the object's REAL path, not a client-supplied string"
            ),
            other => panic!("an fd outside the confinement root must be refused: {other:?}"),
        }
    }
}
