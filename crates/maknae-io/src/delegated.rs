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
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DelegatedRequired {
    /// The object must resolve beneath this **absolute, canonical** directory.
    /// Canonical because the kernel reports a resolved path; a root behind a
    /// symlink would never match. `None` = no confinement requirement.
    pub confined_beneath: Option<PathBuf>,
    /// The usual target checks, applied to this descriptor by `fstat`.
    pub target: TargetRequired,
}

/// What the kernel says about a delegated descriptor.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Delegated {
    /// The path the kernel reports -- **ground truth**, and what the PDP decides
    /// on (ADR-0009 decision 6), never the client-supplied string.
    pub path: PathBuf,
}

/// Verify a subject-delegated descriptor. Does not consume the fd: the caller
/// still reads from the very descriptor that was checked, so there is no
/// check-then-reopen window.
pub fn verify_delegated(fd: BorrowedFd<'_>, req: DelegatedRequired) -> Result<Delegated, IoError> {
    let path = crate::syscall::fd_path(&fd).map_err(|e| {
        crate::checks::map_errno_no_disambiguation(e, std::path::Path::new("/proc/self/fd"))
    })?;
    if let Some(root) = req.confined_beneath.as_deref() {
        // Component-wise. NEVER `str::strip_prefix`: `/home/opx` is a string
        // prefix of `/home/op` and must not match.
        if path.strip_prefix(root).is_err() {
            return Err(IoError::EscapesAnchor { path });
        }
    }
    Ok(Delegated { path })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{IoError, TargetRequired};
    use std::os::fd::AsFd;
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
                confined_beneath: Some(home_c),
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
                confined_beneath: Some(home),
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
