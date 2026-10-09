//! Durable audit-file admission through a pinned parent directory.
//!
//! Once the file and its parent have synchronized, the returned file can be
//! appended and synchronized without retaining the directory handle. This checks
//! only the terminal JSONL delimiter, not JSON syntax or the audit hash chain.

use crate::checks::{check_owner_mode, check_target, AnchorRequired, TargetRequired};
use crate::{syscall, Mode};
use nix::fcntl::OFlag;
use std::ffi::OsStr;
use std::fs::File;
use std::io::{self, Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};

#[derive(Clone, Copy)]
enum AuditOpenKind {
    Existing,
    CreateExclusive,
}

fn flags(kind: AuditOpenKind) -> OFlag {
    let base =
        OFlag::O_RDWR | OFlag::O_APPEND | OFlag::O_NOFOLLOW | OFlag::O_NONBLOCK | OFlag::O_CLOEXEC;
    match kind {
        AuditOpenKind::Existing => base,
        AuditOpenKind::CreateExclusive => base | OFlag::O_CREAT | OFlag::O_EXCL,
    }
}

fn open_leaf(parent: &File, name: &OsStr, mode: Mode, kind: AuditOpenKind) -> io::Result<File> {
    nix::fcntl::openat(
        parent,
        name,
        flags(kind),
        nix::sys::stat::Mode::from_bits_truncate(mode.0 as _),
    )
    .map(File::from)
    .map_err(io::Error::from)
}

fn sync_file(file: &File) -> io::Result<()> {
    syscall::fsync_fd(file).map_err(io::Error::from)
}

/// Open an existing append file without O_CREAT, or exclusively create it. Pin
/// its resolved parent BEFORE either attempt; a create race retries the existing
/// open against that same descriptor. Validate the opened inode under the named
/// requirements and refuse a nonempty file without a terminal newline.
///
/// File fsync precedes parent fsync, including for an existing name: a previous
/// interrupted first open may have created that name without synchronizing it.
/// Success therefore admits a durable name, including first boot. Read access
/// under service credentials is required to inspect the existing terminal byte.
/// Parent paths retain the configured-path adapter's symlink-following behavior;
/// the leaf is always opened with O_NOFOLLOW.
pub fn open_audit_append(
    path: &Path,
    parent_required: &AnchorRequired,
    target_required: &TargetRequired,
    create_mode: Mode,
) -> io::Result<File> {
    let (parent, absolute) = pin_parent(path, parent_required)?;
    open_pinned(
        parent,
        leaf_name(&absolute)?,
        &absolute,
        target_required,
        Some(create_mode),
        sync_file,
    )
}

/// As [`open_audit_append`], but the file must already exist: a missing name is
/// `NotFound` and is never created. With `require_append_only`, the opened
/// descriptor must carry the append-only flag only root can clear.
pub fn open_existing_audit_append(
    path: &Path,
    parent_required: &AnchorRequired,
    target_required: &TargetRequired,
    require_append_only: bool,
) -> io::Result<File> {
    let (parent, absolute) = pin_parent(path, parent_required)?;
    let file = open_pinned(
        parent,
        leaf_name(&absolute)?,
        &absolute,
        target_required,
        None,
        sync_file,
    )?;
    if require_append_only && !maknae_sys::is_append_only(&file)? {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            format!(
                "{} is not append-only; prepare it with chattr +a (Linux) or chflags sappnd (macOS) as root",
                absolute.display()
            ),
        ));
    }
    Ok(file)
}

fn leaf_name(absolute: &Path) -> io::Result<&OsStr> {
    absolute
        .file_name()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "audit path has no file name"))
}

fn pin_parent(path: &Path, parent_required: &AnchorRequired) -> io::Result<(File, PathBuf)> {
    let absolute = std::path::absolute(path)?;
    leaf_name(&absolute)?;
    // A file name was established above, so removing it leaves its absolute parent.
    let parent_path = absolute.with_file_name("");
    let parent = File::from(syscall::open_parent_by_path(&parent_path).map_err(io::Error::from)?);
    let st = syscall::fstat(&parent).map_err(io::Error::from)?;
    check_owner_mode(
        &st,
        &parent_path,
        parent_required.owner,
        parent_required.mode_mask,
    )
    .map_err(io::Error::other)?;
    Ok((parent, absolute))
}

fn open_pinned(
    parent: File,
    name: &OsStr,
    path: &Path,
    required: &TargetRequired,
    create_mode: Option<Mode>,
    mut synchronize: impl FnMut(&File) -> io::Result<()>,
) -> io::Result<File> {
    open_pinned_with(
        parent,
        name,
        path,
        required,
        create_mode,
        &mut synchronize,
        open_leaf,
    )
}

// Private syscall boundary: tests coordinate real create races here rather than
// replacing their outcomes with fabricated descriptors or error values.
fn open_pinned_with(
    parent: File,
    name: &OsStr,
    path: &Path,
    required: &TargetRequired,
    create_mode: Option<Mode>,
    mut synchronize: impl FnMut(&File) -> io::Result<()>,
    mut open: impl FnMut(&File, &OsStr, Mode, AuditOpenKind) -> io::Result<File>,
) -> io::Result<File> {
    let existing_mode = create_mode.unwrap_or(Mode(0));
    let mut file = match open(&parent, name, existing_mode, AuditOpenKind::Existing) {
        Ok(file) => file,
        Err(e) if e.kind() == io::ErrorKind::NotFound => {
            let Some(create_mode) = create_mode else {
                return Err(e);
            };
            match open(&parent, name, create_mode, AuditOpenKind::CreateExclusive) {
                Ok(file) => file,
                Err(e) if e.kind() == io::ErrorKind::AlreadyExists => {
                    open(&parent, name, create_mode, AuditOpenKind::Existing)?
                }
                Err(e) => return Err(e),
            }
        }
        Err(e) => return Err(e),
    };
    let st = syscall::fstat(&file).map_err(io::Error::from)?;
    check_target(&st, path, required).map_err(io::Error::other)?;
    if st.st_size > 0 {
        file.seek(SeekFrom::End(-1))?;
        let mut last = [0];
        file.read_exact(&mut last)?;
        if last[0] != b'\n' {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "audit file has a torn terminal JSONL line; recovery required",
            ));
        }
    }
    synchronize(&file)?;
    synchronize(&parent)?;
    Ok(file)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::MetadataExt;

    fn required() -> TargetRequired {
        TargetRequired {
            owner: Some(nix::unistd::geteuid().as_raw()),
            mode_mask: Some(0o037),
            nlink_exactly_one: false,
            regular_file: true,
            max_bytes: None,
        }
    }

    fn seed(path: &Path, bytes: &[u8]) {
        use std::os::unix::fs::PermissionsExt;
        std::fs::write(path, bytes).unwrap();
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o640)).unwrap();
    }

    #[test]
    fn invalid_paths_and_parent_requirements_are_refused_before_creation() {
        for path in [Path::new(""), Path::new("/")] {
            assert_eq!(
                open_audit_append(path, &AnchorRequired::OS_DAC, &required(), Mode(0o600))
                    .unwrap_err()
                    .kind(),
                io::ErrorKind::InvalidInput
            );
        }
        let d = tempfile::tempdir().unwrap();
        let path = d.path().join("missing-parent/audit");
        assert_eq!(
            open_audit_append(&path, &AnchorRequired::OS_DAC, &required(), Mode(0o600))
                .unwrap_err()
                .kind(),
            io::ErrorKind::NotFound
        );
        let path = d.path().join("audit");
        let parent_required = AnchorRequired {
            owner: Some(nix::unistd::geteuid().as_raw().wrapping_add(1)),
            mode_mask: None,
        };
        assert!(open_audit_append(&path, &parent_required, &required(), Mode(0o600)).is_err());
        assert!(!path.exists());
        seed(&path, b"sentinel\n");
        let mut target = required();
        target.owner = parent_required.owner;
        assert!(open_audit_append(&path, &AnchorRequired::OS_DAC, &target, Mode(0o600)).is_err());
        assert_eq!(std::fs::read(&path).unwrap(), b"sentinel\n");
    }

    #[test]
    fn audit_xor_equivalence_requires_disjoint_flag_bits() {
        let mut bits = OFlag::empty();
        for flag in [
            OFlag::O_RDWR,
            OFlag::O_APPEND,
            OFlag::O_NOFOLLOW,
            OFlag::O_NONBLOCK,
            OFlag::O_CLOEXEC,
            OFlag::O_CREAT,
            OFlag::O_EXCL,
        ] {
            assert!(
                !bits.intersects(flag),
                "XOR exemption requires disjoint flags"
            );
            assert_eq!(bits | flag, bits ^ flag);
            bits |= flag;
        }
    }

    #[test]
    fn audit_handle_appends_even_after_seek_and_is_cloexec() {
        use std::io::Write;
        let d = tempfile::tempdir().unwrap();
        let path = d.path().join("append-sentinel");
        seed(&path, b"first\n");
        let mut file =
            open_audit_append(&path, &AnchorRequired::OS_DAC, &required(), Mode(0o640)).unwrap();
        let flags = nix::fcntl::fcntl(&file, nix::fcntl::FcntlArg::F_GETFD).unwrap();
        assert_ne!(flags & nix::fcntl::FdFlag::FD_CLOEXEC.bits(), 0);
        file.seek(SeekFrom::Start(0)).unwrap();
        file.write_all(b"second\n").unwrap();
        file.sync_all().unwrap();
        assert_eq!(std::fs::read(path).unwrap(), b"first\nsecond\n");
    }

    #[test]
    fn audit_tail_and_symlink_refusals_preserve_real_sentinels() {
        let d = tempfile::tempdir().unwrap();
        let path = d.path().join("tail-sentinel");
        seed(&path, b"complete\npartial");
        assert_eq!(
            open_audit_append(&path, &AnchorRequired::OS_DAC, &required(), Mode(0o640))
                .unwrap_err()
                .kind(),
            io::ErrorKind::InvalidData
        );
        assert_eq!(std::fs::read(&path).unwrap(), b"complete\npartial");
        seed(&path, b"complete\n");
        open_audit_append(&path, &AnchorRequired::OS_DAC, &required(), Mode(0o640)).unwrap();
        let link = d.path().join("link");
        std::os::unix::fs::symlink(&path, &link).unwrap();
        assert!(
            open_audit_append(&link, &AnchorRequired::OS_DAC, &required(), Mode(0o640)).is_err()
        );
        assert_eq!(std::fs::read(path).unwrap(), b"complete\n");
    }

    #[test]
    fn racing_exclusive_audit_create_reopens_the_winning_inode() {
        let d = tempfile::tempdir().unwrap();
        let path = d.path().join("winner");
        let parent = File::from(syscall::open_parent_by_path(d.path()).unwrap());
        let file = open_pinned_with(
            parent,
            OsStr::new("winner"),
            &path,
            &required(),
            Some(Mode(0o640)),
            sync_file,
            |parent, name, mode, kind| {
                if matches!(kind, AuditOpenKind::CreateExclusive) {
                    seed(&path, b"winner\n");
                }
                open_leaf(parent, name, mode, kind)
            },
        )
        .unwrap();
        assert_eq!(
            file.metadata().unwrap().ino(),
            std::fs::metadata(&path).unwrap().ino()
        );
        assert_eq!(std::fs::read(path).unwrap(), b"winner\n");
    }

    #[test]
    fn unexpected_initial_open_error_cannot_turn_into_create_after_a_race() {
        let d = tempfile::tempdir().unwrap();
        let path = d.path().join("entry");
        let sentinel = d.path().join("outside-sentinel");
        seed(&sentinel, b"untouched\n");
        std::os::unix::fs::symlink(&sentinel, &path).unwrap();
        let parent = File::from(syscall::open_parent_by_path(d.path()).unwrap());
        let mut calls = 0;
        let result = open_pinned_with(
            parent,
            OsStr::new("entry"),
            &path,
            &required(),
            Some(Mode(0o640)),
            sync_file,
            |parent, name, mode, kind| {
                calls += 1;
                let result = open_leaf(parent, name, mode, kind);
                if calls == 1 {
                    assert!(result.is_err());
                    std::fs::remove_file(&path).unwrap();
                }
                result
            },
        );
        assert!(result.is_err());
        assert_eq!(calls, 1);
        assert!(!path.exists());
        assert_eq!(std::fs::read(sentinel).unwrap(), b"untouched\n");
    }

    #[test]
    fn unexpected_exclusive_create_error_cannot_be_retried_after_permission_change() {
        crate::testutil::unprivileged(
            "audit_append::tests::unexpected_exclusive_create_error_cannot_be_retried_after_permission_change",
            || {
        use std::os::unix::fs::PermissionsExt;
        let d = tempfile::tempdir().unwrap();
        let path = d.path().join("entry");
        let parent = File::from(syscall::open_parent_by_path(d.path()).unwrap());
        let mut calls = 0;
        let result = open_pinned_with(
            parent,
            OsStr::new("entry"),
            &path,
            &required(),
            Some(Mode(0o640)),
            sync_file,
            |parent, name, mode, kind| {
                calls += 1;
                if matches!(kind, AuditOpenKind::CreateExclusive) {
                    std::fs::set_permissions(d.path(), std::fs::Permissions::from_mode(0o500))
                        .unwrap();
                    let result = open_leaf(parent, name, mode, kind);
                    std::fs::set_permissions(d.path(), std::fs::Permissions::from_mode(0o700))
                        .unwrap();
                    assert_eq!(
                        result.as_ref().unwrap_err().kind(),
                        io::ErrorKind::PermissionDenied
                    );
                    seed(&path, b"later winner\n");
                    return result;
                }
                open_leaf(parent, name, mode, kind)
            },
        );
        assert_eq!(result.unwrap_err().kind(), io::ErrorKind::PermissionDenied);
        assert_eq!(calls, 2);
        assert_eq!(std::fs::read(path).unwrap(), b"later winner\n");
            },
        );
    }

    #[test]
    fn first_open_syncs_file_then_its_pinned_parent() {
        let dir = tempfile::tempdir().unwrap();
        let parent = File::from(syscall::open_parent_by_path(dir.path()).unwrap());
        let parent_ino = parent.metadata().unwrap().ino();
        let mut seen = Vec::new();
        let handle = open_pinned(
            parent,
            std::ffi::OsStr::new("audit.jsonl"),
            &dir.path().join("audit.jsonl"),
            &required(),
            Some(Mode(0o640)),
            |file| {
                let st = file.metadata()?;
                seen.push((st.is_dir(), st.ino()));
                sync_file(file)
            },
        )
        .unwrap();
        assert_eq!(
            seen,
            vec![
                (false, handle.metadata().unwrap().ino()),
                (true, parent_ino)
            ]
        );
    }

    #[test]
    fn parent_rename_before_leaf_open_uses_and_syncs_the_original_directory() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("parent");
        std::fs::create_dir(&path).unwrap();
        let parent = File::from(syscall::open_parent_by_path(&path).unwrap());
        let original_ino = parent.metadata().unwrap().ino();
        let moved = dir.path().join("moved");
        std::fs::rename(&path, &moved).unwrap();
        std::fs::create_dir(&path).unwrap();
        let mut synced_parent = None;
        open_pinned(
            parent,
            std::ffi::OsStr::new("audit.jsonl"),
            &path.join("audit.jsonl"),
            &required(),
            Some(Mode(0o640)),
            |file| {
                let st = file.metadata()?;
                if st.is_dir() {
                    synced_parent = Some(st.ino());
                }
                sync_file(file)
            },
        )
        .unwrap();
        assert_eq!(synced_parent, Some(original_ino));
        assert!(moved.join("audit.jsonl").is_file());
        assert!(!path.join("audit.jsonl").exists());
    }

    #[test]
    fn boot_refuses_real_file_or_parent_sync_failure() {
        for fail_on in [1, 2] {
            let dir = tempfile::tempdir().unwrap();
            let parent = File::from(syscall::open_parent_by_path(dir.path()).unwrap());
            let (socket, _peer) = std::os::unix::net::UnixStream::pair().unwrap();
            let fault = File::from(std::os::fd::OwnedFd::from(socket));
            let expected = sync_file(&fault).unwrap_err().kind();
            let mut calls = 0;
            let result = open_pinned(
                parent,
                std::ffi::OsStr::new("audit.jsonl"),
                &dir.path().join("audit.jsonl"),
                &required(),
                Some(Mode(0o640)),
                |file| {
                    calls += 1;
                    sync_file(if calls == fail_on { &fault } else { file })
                },
            );
            assert_eq!(
                result
                    .expect_err("open must refuse uncertain durability")
                    .kind(),
                expected
            );
            assert_eq!(
                calls, fail_on,
                "later synchronization must not mask a failure"
            );
        }
    }

    #[test]
    fn an_existing_open_never_creates() {
        let d = tempfile::tempdir().unwrap();
        let path = d.path().join("audit.jsonl");
        for require in [false, true] {
            assert_eq!(
                open_existing_audit_append(&path, &AnchorRequired::OS_DAC, &required(), require)
                    .unwrap_err()
                    .kind(),
                io::ErrorKind::NotFound
            );
            assert!(!path.exists());
        }
    }

    #[test]
    fn an_existing_open_of_a_plain_file_succeeds_without_the_flag_requirement() {
        use std::io::Write;
        let d = tempfile::tempdir().unwrap();
        let path = d.path().join("audit.jsonl");
        seed(&path, b"first\n");
        let mut file =
            open_existing_audit_append(&path, &AnchorRequired::OS_DAC, &required(), false).unwrap();
        file.write_all(b"second\n").unwrap();
        assert_eq!(std::fs::read(&path).unwrap(), b"first\nsecond\n");
    }

    #[test]
    fn an_existing_open_holds_the_parent_and_target_requirements() {
        let d = tempfile::tempdir().unwrap();
        let path = d.path().join("audit.jsonl");
        seed(&path, b"complete\npartial");
        assert_eq!(
            open_existing_audit_append(&path, &AnchorRequired::OS_DAC, &required(), false)
                .unwrap_err()
                .kind(),
            io::ErrorKind::InvalidData
        );
        seed(&path, b"complete\n");
        let parent_required = AnchorRequired {
            owner: Some(nix::unistd::geteuid().as_raw().wrapping_add(1)),
            mode_mask: None,
        };
        assert!(open_existing_audit_append(&path, &parent_required, &required(), false).is_err());
        let mut target = required();
        target.owner = parent_required.owner;
        assert!(
            open_existing_audit_append(&path, &AnchorRequired::OS_DAC, &target, false).is_err()
        );
        assert_eq!(
            open_existing_audit_append(Path::new("/"), &AnchorRequired::OS_DAC, &required(), false)
                .unwrap_err()
                .kind(),
            io::ErrorKind::InvalidInput
        );
        assert_eq!(std::fs::read(&path).unwrap(), b"complete\n");
    }

    #[test]
    fn a_prepared_open_of_a_plain_file_is_refused_as_not_append_only() {
        let d = tempfile::tempdir().unwrap();
        let path = d.path().join("audit.jsonl");
        seed(&path, b"sentinel\n");
        let e = open_existing_audit_append(&path, &AnchorRequired::OS_DAC, &required(), true)
            .unwrap_err();
        assert_eq!(e.kind(), io::ErrorKind::PermissionDenied);
        assert!(e.to_string().contains("not append-only"), "{e}");
        assert_eq!(std::fs::read(&path).unwrap(), b"sentinel\n");
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn a_prepared_open_of_a_uappnd_file_is_refused() {
        let d = tempfile::tempdir().unwrap();
        let path = d.path().join("audit.jsonl");
        seed(&path, b"sentinel\n");
        let chflags = |flag: &str| {
            assert!(std::process::Command::new("chflags")
                .arg(flag)
                .arg(&path)
                .status()
                .unwrap()
                .success());
        };
        chflags("uappnd");
        let result = open_existing_audit_append(&path, &AnchorRequired::OS_DAC, &required(), true);
        chflags("nouappnd");
        let e = result.unwrap_err();
        assert_eq!(e.kind(), io::ErrorKind::PermissionDenied);
        assert!(e.to_string().contains("not append-only"), "{e}");
    }

    #[test]
    fn existing_open_excludes_create_and_first_create_is_exclusive() {
        let existing = flags(AuditOpenKind::Existing);
        assert!(!existing.intersects(OFlag::O_CREAT | OFlag::O_EXCL));
        let create = flags(AuditOpenKind::CreateExclusive);
        assert!(create.contains(OFlag::O_CREAT | OFlag::O_EXCL));
    }
}
