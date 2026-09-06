//! Descriptor-bound filesystem mutations. Directory evidence proves location only;
//! it never proves the subject can create or remove a child. Namespace syscalls run
//! under the caller's credentials. Callers must commit authorization and durable
//! intent before invoking an effect.
//!
//! Each effect rechecks the held descriptor's kernel path. This does not make a
//! pathname decision atomic with the syscall: concurrent rename, mount aliases and
//! another holder changing a shared open description remain residual limitations.
//! The device guard refuses different filesystems, not same-filesystem bind mounts.
//! Namespace success observes a completed syscall; it does not promise namespace
//! metadata will persist after a crash. Audit intent/completion durability is the
//! caller's separate obligation. File contents are synchronized on their writable fd.
//! An attached deadline is checked after potentially blocking path revalidation,
//! immediately before namespace syscalls. Scheduling delays after that cooperative
//! check and a syscall already in progress cannot be preempted by this API.

use crate::checks::map_errno_no_disambiguation as io_error;
use crate::syscall;
use crate::{AnchorRequired, DelegatedRequired, Entry, IoError, TargetRequired};
use std::os::fd::{AsFd, BorrowedFd, OwnedFd};
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};
use std::time::Instant;

/// Location and confinement-root requirements; no child mutation permission claim.
#[derive(Clone, Debug)]
pub struct MutationRequired {
    pub confined_beneath: PathBuf,
    pub root_required: AnchorRequired,
}

/// A held directory whose kernel path was verified. Fields cannot be forged.
#[derive(Debug)]
pub struct MutationDirectory {
    fd: OwnedFd,
    path: PathBuf,
    required: MutationRequired,
    device: nix::libc::dev_t,
    deadline: Option<Instant>,
}

/// A non-append writable regular descriptor, never opened with truncation here.
#[derive(Debug)]
pub struct WritableObject {
    fd: OwnedFd,
    path: PathBuf,
    required: DelegatedRequired,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EffectState {
    NoEffect,
    Applied,
    Partial,
    DurabilityUnknown,
}

#[derive(Debug)]
pub struct MutationFailure {
    pub state: EffectState,
    pub at: PathBuf,
    pub source: IoError,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MutationEffectKind {
    CreatedFile,
    CreatedDirectory,
    DeletedEntry,
}

/// One observed namespace syscall effect, not a crash-persistence guarantee.
/// File-content sync failure is reported with a non-NoEffect state.
#[derive(Debug)]
pub struct MutationEffect {
    pub path: PathBuf,
    pub kind: MutationEffectKind,
}

/// Owns an incremental directory stream, not a collected tree or a shared offset.
pub struct DirectoryCursor {
    directory: MutationDirectory,
    entries: nix::dir::OwningIter,
}

fn failure(at: &Path, state: EffectState, source: IoError) -> MutationFailure {
    MutationFailure {
        state,
        at: at.to_path_buf(),
        source,
    }
}

// Share path-preserving errno conversion across the descriptor operations.
fn at(path: &Path) -> impl FnOnce(nix::errno::Errno) -> IoError + '_ {
    move |error| io_error(error, path)
}

fn no_effect(path: &Path) -> impl FnOnce(IoError) -> MutationFailure + '_ {
    move |error| failure(path, EffectState::NoEffect, error)
}

fn directory_requirements(req: &MutationRequired) -> DelegatedRequired {
    DelegatedRequired {
        confined_beneath: req.confined_beneath.clone(),
        root_required: req.root_required.clone(),
        target: TargetRequired {
            owner: None,
            mode_mask: None,
            nlink_exactly_one: false,
            regular_file: false,
            max_bytes: None,
        },
    }
}

// Bound the leaf before allocating its joined path; the complete path has its
// own independent encoding budget. Neither validator normalizes away traversal.
fn valid_leaf(leaf: &str) -> bool {
    !leaf.is_empty()
        && leaf != "."
        && leaf != ".."
        && !leaf.contains('/')
        && !leaf.contains('\0')
        && leaf.len() <= 4096
}

fn checked_path(path: &Path) -> Result<(), IoError> {
    let text = path.to_str().ok_or_else(|| IoError::NonUtf8Component {
        path: path.to_path_buf(),
    })?;
    if !path.is_absolute() || text.len() > 4096 || text.contains('\0') {
        return Err(IoError::InvalidMutationPath {
            path: path.to_path_buf(),
        });
    }
    Ok(())
}

fn check_root(path: &Path) -> Result<(), IoError> {
    checked_path(path)?;
    let st = syscall::stat_path(path).map_err(at(path))?;
    if st.st_mode & nix::libc::S_IFMT != nix::libc::S_IFDIR {
        return Err(io_error(nix::errno::Errno::ENOTDIR, path));
    }
    Ok(())
}

fn ensure_directory(fd: &OwnedFd, path: &Path) -> Result<nix::sys::stat::FileStat, IoError> {
    let st = syscall::fstat(fd).map_err(at(path))?;
    if st.st_mode & nix::libc::S_IFMT != nix::libc::S_IFDIR {
        return Err(io_error(nix::errno::Errno::ENOTDIR, path));
    }
    if st.st_nlink == 0 {
        return Err(IoError::MutationPathChanged {
            path: path.to_path_buf(),
        });
    }
    Ok(st)
}

pub fn verify_mutation_directory(
    fd: OwnedFd,
    required: MutationRequired,
) -> Result<MutationDirectory, IoError> {
    check_root(&required.confined_beneath)?;
    let verified = crate::verify_delegated(fd.as_fd(), directory_requirements(&required))?;
    checked_path(&verified.path)?;
    let st = ensure_directory(&fd, &verified.path)?;
    Ok(MutationDirectory {
        fd,
        path: verified.path,
        required,
        device: st.st_dev,
        deadline: None,
    })
}

fn verify_write(fd: &OwnedFd, required: &DelegatedRequired) -> Result<PathBuf, IoError> {
    check_root(&required.confined_beneath)?;
    // The public target requirements may tighten but never waive these invariants.
    let mut target = required.target.clone();
    target.regular_file = true;
    target.nlink_exactly_one = true;
    let verified = crate::verify_delegated(
        fd.as_fd(),
        DelegatedRequired {
            confined_beneath: required.confined_beneath.clone(),
            root_required: required.root_required.clone(),
            target,
        },
    )?;
    checked_path(&verified.path)?;
    if !syscall::is_nonappend_writable(fd).map_err(at(&verified.path))? {
        return Err(IoError::NotWritableDescriptor {
            path: verified.path,
        });
    }
    Ok(verified.path)
}

pub fn verify_writable_object(
    fd: OwnedFd,
    required: DelegatedRequired,
) -> Result<WritableObject, IoError> {
    let path = verify_write(&fd, &required)?;
    Ok(WritableObject { fd, path, required })
}

fn same_path(actual: &Path, expected: &Path) -> Result<(), IoError> {
    if actual != expected {
        return Err(IoError::MutationPathChanged {
            path: expected.to_path_buf(),
        });
    }
    Ok(())
}

/// Replace through the exact checked descriptor. pwrite leaves a shared cursor
/// untouched; no daemon-owned temp/rename changes the inode, owner or mode.
/// Another holder can still change O_APPEND after a check or write concurrently.
pub fn replace_existing(object: WritableObject, bytes: &[u8]) -> Result<(), MutationFailure> {
    let check = || {
        let path = verify_write(&object.fd, &object.required)?;
        same_path(&path, &object.path)
    };
    replace_bytes(
        &object.fd,
        &object.path,
        bytes,
        check,
        syscall::write_at,
        syscall::fsync_fd,
    )
}

fn replace_bytes(
    fd: &OwnedFd,
    path: &Path,
    bytes: &[u8],
    check: impl Fn() -> Result<(), IoError>,
    write: impl Fn(&OwnedFd, &[u8], i64) -> nix::Result<usize>,
    sync: impl Fn(&OwnedFd) -> nix::Result<()>,
) -> Result<(), MutationFailure> {
    let mut offset = 0;
    while offset < bytes.len() {
        let state = if offset == 0 {
            EffectState::NoEffect
        } else {
            EffectState::Partial
        };
        check().map_err(|e| failure(path, state, e))?;
        let count = match write(fd, &bytes[offset..], offset as i64) {
            Err(nix::errno::Errno::EINTR) => continue,
            result => result.map_err(|e| failure(path, state, io_error(e, path)))?,
        };
        if count == 0 {
            return Err(failure(path, state, io_error(nix::errno::Errno::EIO, path)));
        }
        offset += count;
    }
    let state = if offset == 0 {
        EffectState::NoEffect
    } else {
        EffectState::Partial
    };
    check().map_err(|e| failure(path, state, e))?;
    // A valid slice is bounded by isize::MAX; both supported targets have 64-bit
    // pointers, so its length is always representable by the syscall offset.
    let length = bytes.len() as i64;
    syscall::truncate_fd(fd, length).map_err(|e| failure(path, state, io_error(e, path)))?;
    sync(fd).map_err(|e| failure(path, EffectState::DurabilityUnknown, io_error(e, path)))
}

impl MutationDirectory {
    /// Bound namespace syscall starts by a cooperative monotonic deadline.
    pub fn with_deadline(mut self, deadline: Instant) -> Self {
        self.deadline = Some(deadline);
        self
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    fn check_deadline(&self, path: &Path) -> Result<(), MutationFailure> {
        if self
            .deadline
            .is_some_and(|deadline| Instant::now() >= deadline)
        {
            return Err(failure(
                path,
                EffectState::NoEffect,
                IoError::DeadlineElapsed {
                    path: path.to_path_buf(),
                },
            ));
        }
        Ok(())
    }

    /// Compare with both the immutable verified path and the grant's expected path.
    pub fn reverify(&self, expected: &Path) -> Result<(), IoError> {
        same_path(&self.path, expected)?;
        check_root(&self.required.confined_beneath)?;
        let actual =
            crate::verify_delegated(self.fd.as_fd(), directory_requirements(&self.required))?.path;
        same_path(&actual, expected)?;
        ensure_directory(&self.fd, expected)?;
        Ok(())
    }

    fn child_path(&self, leaf: &str) -> Result<PathBuf, IoError> {
        if !valid_leaf(leaf) {
            return Err(IoError::InvalidMutationPath {
                path: self.path.clone(),
            });
        }
        let path = self.path.join(leaf);
        checked_path(&path)?;
        self.reverify(&self.path)?;
        Ok(path)
    }

    pub fn create_exclusive(
        &self,
        leaf: &str,
        bytes: &[u8],
    ) -> Result<MutationEffect, MutationFailure> {
        self.create_exclusive_with(leaf, |fd, path| {
            replace_bytes(
                fd,
                path,
                bytes,
                || {
                    self.reverify(&self.path)?;
                    let actual = syscall::fd_path(fd).map_err(at(path))?;
                    same_path(&actual, path)
                },
                syscall::write_at,
                syscall::fsync_fd,
            )
        })
    }

    fn create_exclusive_with(
        &self,
        leaf: &str,
        write: impl FnOnce(&OwnedFd, &Path) -> Result<(), MutationFailure>,
    ) -> Result<MutationEffect, MutationFailure> {
        let path = self.child_path(leaf).map_err(no_effect(&self.path))?;
        self.check_deadline(&path)?;
        let fd = syscall::open_temp_excl(&self.fd, leaf, crate::Mode(0o600))
            .map_err(|e| failure(&path, EffectState::NoEffect, io_error(e, &path)))?;
        // A fresh entry already exists, even when the first content write fails.
        let result = write(&fd, &path);
        result.map_err(|mut e| {
            if e.state == EffectState::NoEffect {
                e.state = EffectState::Partial;
            }
            e
        })?;
        Ok(MutationEffect {
            path,
            kind: MutationEffectKind::CreatedFile,
        })
    }

    pub fn mkdir_one(&self, leaf: &str) -> Result<MutationEffect, MutationFailure> {
        let path = self.child_path(leaf).map_err(no_effect(&self.path))?;
        self.check_deadline(&path)?;
        syscall::mkdir_at(&self.fd, leaf)
            .map_err(|e| failure(&path, EffectState::NoEffect, io_error(e, &path)))?;
        Ok(MutationEffect {
            path,
            kind: MutationEffectKind::CreatedDirectory,
        })
    }

    /// Remove the entry itself, including symlinks. A directory must be empty;
    /// this function never falls back to recursive removal.
    pub fn remove_entry(&self, leaf: &str) -> Result<MutationEffect, MutationFailure> {
        let path = self.child_path(leaf).map_err(no_effect(&self.path))?;
        let st = syscall::fstatat_nofollow(&self.fd, leaf)
            .map_err(|e| failure(&path, EffectState::NoEffect, io_error(e, &path)))?;
        let directory = st.st_mode & nix::libc::S_IFMT == nix::libc::S_IFDIR;
        self.reverify(&self.path).map_err(no_effect(&path))?;
        self.check_deadline(&path)?;
        syscall::remove_at(&self.fd, leaf, directory)
            .map_err(|e| failure(&path, EffectState::NoEffect, io_error(e, &path)))?;
        Ok(MutationEffect {
            path,
            kind: MutationEffectKind::DeletedEntry,
        })
    }

    pub fn open_child_directory(&self, leaf: &str) -> Result<Self, IoError> {
        let path = self.child_path(leaf)?;
        let fd = syscall::open_mutation_directory_at(&self.fd, leaf).map_err(|e| {
            crate::checks::map_errno(e, &path, || syscall::fstatat_nofollow(&self.fd, leaf))
        })?;
        let mut child = verify_mutation_directory(fd, self.required.clone())?;
        child.deadline = self.deadline;
        same_path(child.path(), &path)?;
        if child.device != self.device {
            return Err(IoError::DifferentFilesystem { path });
        }
        Ok(child)
    }

    pub fn cursor(&self) -> Result<DirectoryCursor, IoError> {
        self.reverify(&self.path)?;
        let fd = syscall::open_dir_at(&self.fd, ".").map_err(at(&self.path))?;
        let directory = verify_mutation_directory(fd, self.required.clone())?;
        same_path(directory.path(), self.path())?;
        let entries = syscall::open_dir_handle(&directory.fd)
            .map_err(at(&self.path))?
            .into_iter();
        Ok(DirectoryCursor { directory, entries })
    }
}

impl AsFd for MutationDirectory {
    fn as_fd(&self) -> BorrowedFd<'_> {
        self.fd.as_fd()
    }
}
impl WritableObject {
    pub fn path(&self) -> &Path {
        &self.path
    }
}
impl AsFd for WritableObject {
    fn as_fd(&self) -> BorrowedFd<'_> {
        self.fd.as_fd()
    }
}

impl DirectoryCursor {
    pub fn next_entry(&mut self) -> Result<Option<Entry>, IoError> {
        self.directory.reverify(self.directory.path())?;
        loop {
            let Some(entry) = self.entries.next() else {
                return Ok(None);
            };
            let entry = entry.map_err(at(self.directory.path()))?;
            let raw = entry.file_name();
            let name = raw.to_str().map_err(|_| IoError::NonUtf8Component {
                path: self
                    .directory
                    .path()
                    .join(std::ffi::OsStr::from_bytes(raw.to_bytes())),
            })?;
            if name == "." || name == ".." {
                continue;
            }
            self.directory.child_path(name)?;
            let kind =
                crate::dir::classify_entry(entry.file_type(), &self.directory.fd, raw, entry.ino())
                    .map_err(at(self.directory.path()))?;
            return Ok(Some(Entry {
                name: name.into(),
                kind,
                ino: entry.ino(),
            }));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs::{File, OpenOptions};
    use std::io::{Seek, SeekFrom};
    use std::os::unix::fs::{symlink, PermissionsExt};
    fn root(d: &tempfile::TempDir) -> PathBuf {
        d.path().canonicalize().unwrap()
    }
    fn directory(d: &tempfile::TempDir) -> MutationDirectory {
        verify_mutation_directory(
            File::open(d.path()).unwrap().into(),
            MutationRequired {
                confined_beneath: root(d),
                root_required: AnchorRequired::OS_DAC,
            },
        )
        .unwrap()
    }
    fn req(d: &tempfile::TempDir) -> DelegatedRequired {
        DelegatedRequired {
            confined_beneath: root(d),
            root_required: AnchorRequired::OS_DAC,
            target: crate::TargetRequired::OS_DAC_REGULAR,
        }
    }
    fn writable(p: &Path) -> OwnedFd {
        OpenOptions::new().write(true).open(p).unwrap().into()
    }
    #[test]
    fn real_descriptor_accessors_and_disappearing_root_preserve_identity() {
        let d = tempfile::tempdir().unwrap();
        let dir = directory(&d);
        assert_eq!(
            syscall::fstat(&dir).unwrap().st_ino,
            syscall::fstat(&dir.fd).unwrap().st_ino
        );
        let p = root(&d).join("fd-sentinel");
        std::fs::write(&p, b"unchanged").unwrap();
        let object = verify_writable_object(writable(&p), req(&d)).unwrap();
        assert_eq!(object.path(), p);
        assert_eq!(
            syscall::fstat(&object).unwrap().st_ino,
            syscall::fstat(&object.fd).unwrap().st_ino
        );
        let missing = root(&d).join("missing-root");
        assert!(matches!(
            check_root(&missing),
            Err(IoError::Io {
                kind: crate::IoKind::NotFound,
                ..
            })
        ));
        let raw = PathBuf::from(std::ffi::OsStr::from_bytes(b"/nonutf8-\xff"));
        assert_eq!(
            checked_path(&raw),
            Err(IoError::NonUtf8Component { path: raw })
        );
        let empty = root(&d).join("unlinked-dir");
        std::fs::create_dir(&empty).unwrap();
        let fd: OwnedFd = File::open(&empty).unwrap().into();
        std::fs::remove_dir(&empty).unwrap();
        // Linux reports zero links for this held removed directory; Darwin can
        // retain one, so the independent kernel-path revalidation is required.
        #[cfg(target_os = "linux")]
        assert!(matches!(
            ensure_directory(&fd, &empty),
            Err(IoError::MutationPathChanged { .. })
        ));
        #[cfg(target_os = "macos")]
        {
            let held = verify_mutation_directory(
                fd,
                MutationRequired {
                    confined_beneath: root(&d),
                    root_required: AnchorRequired::OS_DAC,
                },
            )
            .unwrap();
            assert_eq!(
                held.mkdir_one("detached-sentinel").unwrap_err().state,
                EffectState::NoEffect
            );
            assert!(!empty.join("detached-sentinel").exists());
        }
        assert_eq!(std::fs::read(p).unwrap(), b"unchanged");
    }

    #[test]
    fn cursor_and_reverify_refuse_a_renamed_or_missing_root() {
        let d = tempfile::tempdir().unwrap();
        let parent = root(&d);
        std::fs::create_dir(parent.join("original")).unwrap();
        let original = parent.join("original");
        let dir = verify_mutation_directory(
            File::open(&original).unwrap().into(),
            MutationRequired {
                confined_beneath: original.clone(),
                root_required: AnchorRequired::OS_DAC,
            },
        )
        .unwrap();
        let mut cursor = dir.cursor().unwrap();
        std::fs::rename(&original, parent.join("moved")).unwrap();
        assert!(matches!(
            dir.reverify(&original),
            Err(IoError::Io {
                kind: crate::IoKind::NotFound,
                ..
            })
        ));
        assert!(cursor.next_entry().is_err());
        assert!(dir.cursor().is_err());
        assert!(verify_mutation_directory(
            File::open(parent.join("moved")).unwrap().into(),
            MutationRequired {
                confined_beneath: original,
                root_required: AnchorRequired::OS_DAC
            }
        )
        .is_err());
        assert!(check_root(Path::new("relative-root")).is_err());
    }

    #[test]
    fn write_retry_zero_progress_and_real_truncate_failure() {
        crate::testutil::isolated(
            "mutation::tests::write_retry_zero_progress_and_real_truncate_failure",
            || {
                let d = tempfile::tempdir().unwrap();
                let p = root(&d).join("write-sentinel");
                std::fs::write(&p, b"ORIGINAL").unwrap();
                let fd = writable(&p);
                let interrupted = std::cell::Cell::new(false);
                replace_bytes(
                    &fd,
                    &p,
                    b"NEW",
                    || Ok(()),
                    |fd, bytes, offset| {
                        if !interrupted.replace(true) {
                            Err(nix::errno::Errno::EINTR)
                        } else {
                            syscall::write_at(fd, bytes, offset)
                        }
                    },
                    syscall::fsync_fd,
                )
                .unwrap();
                assert_eq!(std::fs::read(&p).unwrap(), b"NEW");
                let err = replace_bytes(
                    &fd,
                    &p,
                    b"bad",
                    || Ok(()),
                    |_, _, _| Ok(0),
                    syscall::fsync_fd,
                )
                .unwrap_err();
                assert_eq!(err.state, EffectState::NoEffect);
                assert_eq!(std::fs::read(&p).unwrap(), b"NEW");
                let readonly: OwnedFd = File::open(&p).unwrap().into();
                let err = replace_bytes(
                    &readonly,
                    &p,
                    b"",
                    || Ok(()),
                    syscall::write_at,
                    syscall::fsync_fd,
                )
                .unwrap_err();
                assert_eq!(err.state, EffectState::NoEffect);
                assert_eq!(std::fs::read(&p).unwrap(), b"NEW");
            },
        );
    }

    #[test]
    fn expired_deadline_refuses_each_namespace_effect_and_child_effect() {
        let d = tempfile::tempdir().unwrap();
        std::fs::write(d.path().join("keep-sentinel"), b"KEEP").unwrap();
        std::fs::create_dir(d.path().join("child")).unwrap();
        let dir = directory(&d).with_deadline(Instant::now());
        let child = dir.open_child_directory("child").unwrap();
        let outcomes = [
            dir.create_exclusive("new-file", b"NEW"),
            dir.mkdir_one("new-directory"),
            dir.remove_entry("keep-sentinel"),
            child.create_exclusive("child-new", b"NEW"),
        ];
        for outcome in outcomes {
            let err =
                outcome.expect_err("expired authorization must not start a namespace syscall");
            assert_eq!(err.state, EffectState::NoEffect);
            assert!(matches!(err.source, IoError::DeadlineElapsed { .. }));
        }
        assert!(!d.path().join("new-file").exists());
        assert!(!d.path().join("new-directory").exists());
        assert!(!d.path().join("child/child-new").exists());
        assert_eq!(
            std::fs::read(d.path().join("keep-sentinel")).unwrap(),
            b"KEEP"
        );
        let allowed =
            directory(&d).with_deadline(Instant::now() + std::time::Duration::from_secs(60));
        allowed.mkdir_one("in-time").unwrap();
        assert!(d.path().join("in-time").is_dir());
    }
    #[test]
    fn path_and_leaf_validation_hold_independent_encoding_budgets() {
        for leaf in ["", ".", "..", "a/b", "nul\0name"] {
            assert!(!valid_leaf(leaf));
        }
        assert!(valid_leaf(&"x".repeat(4096)));
        assert!(!valid_leaf(&"x".repeat(4097)));
        assert!(valid_leaf(&"é".repeat(2048)));
        assert!(!valid_leaf(&"é".repeat(2049)));
        let exact = format!("/{}", "x".repeat(4095));
        assert!(checked_path(Path::new(&exact)).is_ok());
        for path in [
            "relative".to_owned(),
            "/nul\0name".to_owned(),
            format!("/{}/x", "x".repeat(4095)),
        ] {
            assert!(matches!(
                checked_path(Path::new(&path)),
                Err(IoError::InvalidMutationPath { .. })
            ));
        }
    }

    #[test]
    fn pretruncate_failure_keeps_effect_state() {
        // A mutated nonadvancing write loop must be killed and reaped, not hang the suite.
        crate::testutil::isolated(
            "mutation::tests::pretruncate_failure_keeps_effect_state",
            || {
                use std::cell::Cell;
                let d = tempfile::tempdir().unwrap();
                let path = d.path().join("truncate-sentinel");
                for bytes in [b"".as_slice(), b"new".as_slice()] {
                    std::fs::write(&path, b"original").unwrap();
                    let fd = writable(&path);
                    let count = Cell::new(0);
                    let error = replace_bytes(
                        &fd,
                        &path,
                        bytes,
                        || {
                            let check = count.get();
                            count.set(check + 1);
                            if check == usize::from(!bytes.is_empty()) {
                                Err(io_error(nix::errno::Errno::EACCES, &path))
                            } else {
                                Ok(())
                            }
                        },
                        syscall::write_at,
                        syscall::fsync_fd,
                    )
                    .unwrap_err();
                    if bytes.is_empty() {
                        assert_eq!(error.state, EffectState::NoEffect);
                        assert_eq!(std::fs::read(&path).unwrap(), b"original");
                    } else {
                        assert_eq!(error.state, EffectState::Partial);
                        assert_eq!(std::fs::read(&path).unwrap(), b"newginal");
                    }
                }
            },
        );
    }

    #[test]
    fn created_entry_survives_content_failure_with_an_honest_state() {
        // A mutated nonadvancing write loop must be killed and reaped, not hang the suite.
        crate::testutil::isolated(
            "mutation::tests::created_entry_survives_content_failure_with_an_honest_state",
            || {
                let d = tempfile::tempdir().unwrap();
                let dir = directory(&d);
                let error = dir
                    .create_exclusive_with("failed-write", |fd, path| {
                        replace_bytes(
                            fd,
                            path,
                            b"new",
                            || Ok(()),
                            |_, _, _| Err(nix::errno::Errno::EIO),
                            syscall::fsync_fd,
                        )
                    })
                    .unwrap_err();
                assert_eq!(error.state, EffectState::Partial);
                assert_eq!(std::fs::read(d.path().join("failed-write")).unwrap(), b"");
                let error = dir
                    .create_exclusive_with("failed-sync", |fd, path| {
                        replace_bytes(
                            fd,
                            path,
                            b"present",
                            || Ok(()),
                            syscall::write_at,
                            |_| Err(nix::errno::Errno::EIO),
                        )
                    })
                    .unwrap_err();
                assert_eq!(error.state, EffectState::DurabilityUnknown);
                assert_eq!(
                    std::fs::read(d.path().join("failed-sync")).unwrap(),
                    b"present"
                );
            },
        );
    }

    #[test]
    fn directory_link_counts_are_not_regular_file_requirements() {
        let d = tempfile::tempdir().unwrap();
        std::fs::create_dir(d.path().join("child")).unwrap();
        assert_eq!(directory(&d).path(), root(&d));
        let p = d.path().join("not-directory");
        std::fs::write(&p, b"sentinel").unwrap();
        assert!(verify_mutation_directory(
            File::open(&p).unwrap().into(),
            MutationRequired {
                confined_beneath: root(&d),
                root_required: AnchorRequired::OS_DAC
            }
        )
        .is_err());
        let outside = tempfile::tempdir().unwrap();
        assert!(verify_mutation_directory(
            File::open(outside.path()).unwrap().into(),
            MutationRequired {
                confined_beneath: root(&d),
                root_required: AnchorRequired::OS_DAC
            }
        )
        .is_err());
    }
    #[test]
    fn writable_proof_and_nontruncating_offset_independent_replacement() {
        // A mutated nonadvancing write loop must be killed and reaped, not hang the suite.
        crate::testutil::isolated(
            "mutation::tests::writable_proof_and_nontruncating_offset_independent_replacement",
            || {
                let d = tempfile::tempdir().unwrap();
                let p = d.path().join("offset-sentinel");
                std::fs::write(&p, b"original long bytes").unwrap();
                let mut shared = OpenOptions::new().write(true).open(&p).unwrap();
                shared.seek(SeekFrom::Start(9)).unwrap();
                let object =
                    verify_writable_object(shared.try_clone().unwrap().into(), req(&d)).unwrap();
                assert_eq!(std::fs::read(&p).unwrap(), b"original long bytes");
                replace_existing(object, b"new").unwrap();
                assert_eq!(std::fs::read(&p).unwrap(), b"new");
                assert_eq!(shared.stream_position().unwrap(), 9);
                replace_existing(verify_writable_object(writable(&p), req(&d)).unwrap(), b"")
                    .unwrap();
                assert!(std::fs::read(&p).unwrap().is_empty());
            },
        );
    }
    #[test]
    fn readonly_append_and_hardlinked_writable_descriptors_are_refused() {
        let d = tempfile::tempdir().unwrap();
        let p = d.path().join("writable-sentinel");
        std::fs::write(&p, b"untouched").unwrap();
        assert!(verify_writable_object(File::open(&p).unwrap().into(), req(&d)).is_err());
        assert!(verify_writable_object(
            OpenOptions::new().append(true).open(&p).unwrap().into(),
            req(&d)
        )
        .is_err());
        std::fs::hard_link(&p, d.path().join("alias")).unwrap();
        assert!(verify_writable_object(writable(&p), req(&d)).is_err());
        assert_eq!(std::fs::read(&p).unwrap(), b"untouched");
    }
    #[test]
    fn exclusive_collision_preserves_intervening_sentinel() {
        let d = tempfile::tempdir().unwrap();
        let dir = directory(&d);
        let p = d.path().join("collision-sentinel");
        std::fs::write(&p, b"intervening").unwrap();
        let result = dir.create_exclusive("collision-sentinel", b"attacker");
        assert_eq!(std::fs::read(&p).unwrap(), b"intervening");
        assert_eq!(result.unwrap_err().state, EffectState::NoEffect);
    }
    #[test]
    fn symlink_child_is_not_followed_and_outside_sentinel_survives() {
        let d = tempfile::tempdir().unwrap();
        let outside = tempfile::tempdir().unwrap();
        let p = outside.path().join("outside-sentinel");
        std::fs::write(&p, b"safe").unwrap();
        symlink(outside.path(), d.path().join("link")).unwrap();
        assert!(directory(&d).open_child_directory("link").is_err());
        assert_eq!(std::fs::read(&p).unwrap(), b"safe");
    }
    #[test]
    fn namespace_effects_use_private_modes_and_remove_entry_not_referent() {
        // A mutated nonadvancing write loop must be killed and reaped, not hang the suite.
        crate::testutil::isolated(
            "mutation::tests::namespace_effects_use_private_modes_and_remove_entry_not_referent",
            || {
                let d = tempfile::tempdir().unwrap();
                let dir = directory(&d);
                assert_eq!(
                    dir.create_exclusive("new", b"body").unwrap().kind,
                    MutationEffectKind::CreatedFile
                );
                assert_eq!(std::fs::read(d.path().join("new")).unwrap(), b"body");
                assert_eq!(
                    std::fs::metadata(d.path().join("new"))
                        .unwrap()
                        .permissions()
                        .mode()
                        & 0o777,
                    0o600
                );
                dir.mkdir_one("child").unwrap();
                assert_eq!(
                    std::fs::metadata(d.path().join("child"))
                        .unwrap()
                        .permissions()
                        .mode()
                        & 0o777,
                    0o700
                );
                let child = dir.open_child_directory("child").unwrap();
                child.create_exclusive("inside", b"keep").unwrap();
                assert_eq!(
                    dir.remove_entry("child").unwrap_err().state,
                    EffectState::NoEffect
                );
                symlink(d.path().join("new"), d.path().join("link")).unwrap();
                dir.remove_entry("link").unwrap();
                assert_eq!(std::fs::read(d.path().join("new")).unwrap(), b"body");
                child.remove_entry("inside").unwrap();
                dir.remove_entry("child").unwrap();
                dir.remove_entry("new").unwrap();
                assert_eq!(dir.cursor().unwrap().next_entry().unwrap(), None);
            },
        );
    }
    #[test]
    fn malformed_leaves_and_renamed_parent_have_no_effect() {
        let d = tempfile::tempdir().unwrap();
        let dir = directory(&d);
        for leaf in ["", ".", "..", "a/b", "/abs", "a\0b", "a/"] {
            assert_eq!(
                dir.create_exclusive(leaf, b"bad").unwrap_err().state,
                EffectState::NoEffect
            );
            assert!(dir.mkdir_one(leaf).is_err());
            assert!(dir.remove_entry(leaf).is_err());
            assert!(dir.open_child_directory(leaf).is_err());
        }
        std::fs::create_dir(d.path().join("parent")).unwrap();
        let child = dir.open_child_directory("parent").unwrap();
        std::fs::rename(d.path().join("parent"), d.path().join("moved")).unwrap();
        assert_eq!(
            child
                .create_exclusive("renamed-sentinel", b"bad")
                .unwrap_err()
                .state,
            EffectState::NoEffect
        );
        assert!(!d.path().join("moved/renamed-sentinel").exists());
    }
    #[test]
    fn cursor_is_incremental_and_rejects_non_utf8_without_lossy_names() {
        #[cfg(target_os = "linux")]
        use std::os::unix::ffi::OsStrExt;
        let d = tempfile::tempdir().unwrap();
        std::fs::write(d.path().join("one"), b"1").unwrap();
        std::fs::write(d.path().join("two"), b"2").unwrap();
        let dir = directory(&d);
        let mut cursor = dir.cursor().unwrap();
        let a = cursor.next_entry().unwrap().unwrap();
        let b = cursor.next_entry().unwrap().unwrap();
        assert_ne!(a.name, b.name);
        assert!(cursor.next_entry().unwrap().is_none());
        #[cfg(target_os = "linux")]
        {
            let bad = std::ffi::OsStr::from_bytes(b"bad-\xff");
            std::fs::write(d.path().join(bad), b"preserved").unwrap();
            let mut cursor = dir.cursor().unwrap();
            loop {
                match cursor.next_entry() {
                    Err(IoError::NonUtf8Component { .. }) => break,
                    Ok(Some(_)) => {}
                    other => panic!("expected unsupported name: {other:?}"),
                }
            }
            assert_eq!(std::fs::read(d.path().join(bad)).unwrap(), b"preserved");
        }
    }

    #[test]
    fn wx_only_parent_supports_namespace_effects_without_read_permission() {
        // A mutated nonadvancing write loop must be killed and reaped, not hang the suite.
        crate::testutil::isolated(
            "mutation::tests::wx_only_parent_supports_namespace_effects_without_read_permission",
            || {
                let d = tempfile::tempdir().unwrap();
                let path = root(&d);
                struct RestoreMode(PathBuf);
                impl Drop for RestoreMode {
                    fn drop(&mut self) {
                        std::fs::set_permissions(&self.0, std::fs::Permissions::from_mode(0o700))
                            .unwrap();
                    }
                }
                let _restore = RestoreMode(path.clone());
                std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o300)).unwrap();
                // Demonstrate actual subject namespace permission independent of delegation.
                assert_eq!(
                    File::open(&path).unwrap_err().kind(),
                    std::io::ErrorKind::PermissionDenied
                );
                std::fs::write(path.join("os-probe"), b"subject permitted").unwrap();
                std::fs::remove_file(path.join("os-probe")).unwrap();
                std::fs::create_dir(path.join("os-dir")).unwrap();
                std::fs::remove_dir(path.join("os-dir")).unwrap();
                let fd = crate::open_directory_for_delegation(&path)
                    .expect("wx-only directory must be delegatable");
                let directory = verify_mutation_directory(
                    fd,
                    MutationRequired {
                        confined_beneath: path.clone(),
                        root_required: AnchorRequired::OS_DAC,
                    },
                )
                .unwrap();
                directory
                    .create_exclusive("wx-sentinel", b"written")
                    .unwrap();
                assert_eq!(std::fs::read(path.join("wx-sentinel")).unwrap(), b"written");
                directory.mkdir_one("child").unwrap();
                assert!(path.join("child").is_dir());
                std::fs::set_permissions(
                    path.join("child"),
                    std::fs::Permissions::from_mode(0o300),
                )
                .unwrap();
                let child = directory
                    .open_child_directory("child")
                    .expect("wx-only descent must not require read");
                assert!(
                    child.cursor().is_err(),
                    "enumeration still requires read permission"
                );
                for leaf in ["wx-sentinel", "child"] {
                    directory.remove_entry(leaf).unwrap();
                    assert!(!path.join(leaf).exists());
                }
            },
        );
    }

    #[test]
    fn different_filesystem_descent_is_refused() {
        let root_fd = File::open("/").unwrap();
        let dev_fd = File::open("/dev").unwrap();
        // /dev is a separately mounted device filesystem on both supported OSes.
        assert_ne!(
            syscall::fstat(&root_fd).unwrap().st_dev,
            syscall::fstat(&dev_fd).unwrap().st_dev
        );
        let directory = verify_mutation_directory(
            root_fd.into(),
            MutationRequired {
                confined_beneath: PathBuf::from("/"),
                root_required: AnchorRequired::OS_DAC,
            },
        )
        .unwrap();
        assert!(matches!(
            directory.open_child_directory("dev"),
            Err(IoError::DifferentFilesystem { .. })
        ));
    }

    #[test]
    fn real_namespace_collisions_and_nonempty_directories_have_typed_errors() {
        // A mutated nonadvancing write loop must be killed and reaped, not hang the suite.
        crate::testutil::isolated(
            "mutation::tests::real_namespace_collisions_and_nonempty_directories_have_typed_errors",
            || {
                let d = tempfile::tempdir().unwrap();
                let dir = directory(&d);
                dir.create_exclusive("collision", b"unchanged sentinel")
                    .unwrap();
                let collision = dir
                    .create_exclusive("collision", b"replacement")
                    .unwrap_err();
                assert_eq!(collision.state, EffectState::NoEffect);
                assert!(matches!(
                    collision.source,
                    IoError::Io {
                        kind: crate::IoKind::AlreadyExists,
                        ..
                    }
                ));
                assert_eq!(
                    std::fs::read(d.path().join("collision")).unwrap(),
                    b"unchanged sentinel"
                );
                dir.mkdir_one("nonempty").unwrap();
                let collision = dir.mkdir_one("nonempty").unwrap_err();
                assert_eq!(collision.state, EffectState::NoEffect);
                assert!(matches!(
                    collision.source,
                    IoError::Io {
                        kind: crate::IoKind::AlreadyExists,
                        ..
                    }
                ));
                let child = dir.open_child_directory("nonempty").unwrap();
                child.create_exclusive("sentinel", b"still here").unwrap();
                let nonempty = dir.remove_entry("nonempty").unwrap_err();
                assert_eq!(nonempty.state, EffectState::NoEffect);
                assert!(matches!(
                    nonempty.source,
                    IoError::Io {
                        kind: crate::IoKind::DirectoryNotEmpty,
                        ..
                    }
                ));
                assert_eq!(
                    std::fs::read(d.path().join("nonempty/sentinel")).unwrap(),
                    b"still here"
                );
            },
        );
    }

    #[test]
    fn refused_namespace_syscalls_leave_no_effect() {
        let d = tempfile::tempdir().unwrap();
        let dir = directory(&d);
        dir.mkdir_one("exists").unwrap();
        assert_eq!(
            dir.mkdir_one("exists").unwrap_err().state,
            EffectState::NoEffect
        );
        assert_eq!(
            dir.remove_entry("missing").unwrap_err().state,
            EffectState::NoEffect
        );
        assert!(dir.open_child_directory("missing").is_err());
        assert!(dir.reverify(&root(&d).join("wrong")).is_err());
        let too_long = "x".repeat(4097);
        assert_eq!(
            dir.create_exclusive(&too_long, b"bad").unwrap_err().state,
            EffectState::NoEffect
        );
        let fitting_leaf = "x".repeat(4096);
        assert_eq!(
            dir.create_exclusive(&fitting_leaf, b"bad")
                .unwrap_err()
                .state,
            EffectState::NoEffect
        );
    }

    #[test]
    fn confinement_root_must_be_a_directory_even_for_writable_evidence() {
        let d = tempfile::tempdir().unwrap();
        let p = root(&d).join("root-file-sentinel");
        std::fs::write(&p, b"safe").unwrap();
        let mut required = req(&d);
        required.confined_beneath = p.clone();
        assert!(verify_writable_object(writable(&p), required).is_err());
        assert_eq!(std::fs::read(p).unwrap(), b"safe");
    }

    #[test]
    fn preparation_open_is_nontruncating_and_never_creates() {
        let d = tempfile::tempdir().unwrap();
        let p = d.path().join("prepare-sentinel");
        std::fs::write(&p, b"original").unwrap();
        let fd = crate::open_writable_for_delegation(&p).unwrap();
        verify_writable_object(fd, req(&d)).unwrap();
        assert_eq!(std::fs::read(&p).unwrap(), b"original");
        assert!(crate::open_writable_for_delegation(&d.path().join("absent")).is_err());
        assert!(!d.path().join("absent").exists());
        let fd = crate::open_directory_for_delegation(d.path()).unwrap();
        assert!(verify_mutation_directory(
            fd,
            MutationRequired {
                confined_beneath: root(&d),
                root_required: AnchorRequired::OS_DAC
            }
        )
        .is_ok());
        assert!(crate::open_directory_for_delegation(&p).is_err());
    }

    #[test]
    fn writable_reverification_refuses_renames_and_late_append_without_effect() {
        let d = tempfile::tempdir().unwrap();
        let p = d.path().join("recheck-sentinel");
        std::fs::write(&p, b"unchanged").unwrap();
        let object = verify_writable_object(writable(&p), req(&d)).unwrap();
        std::fs::rename(&p, d.path().join("moved")).unwrap();
        assert_eq!(
            replace_existing(object, b"bad").unwrap_err().state,
            EffectState::NoEffect
        );
        assert_eq!(std::fs::read(d.path().join("moved")).unwrap(), b"unchanged");
        let shared = writable(&d.path().join("moved"));
        let object = verify_writable_object(shared.try_clone().unwrap(), req(&d)).unwrap();
        nix::fcntl::fcntl(
            &shared,
            nix::fcntl::FcntlArg::F_SETFL(nix::fcntl::OFlag::O_APPEND),
        )
        .unwrap();
        assert_eq!(
            replace_existing(object, b"bad").unwrap_err().state,
            EffectState::NoEffect
        );
        assert_eq!(std::fs::read(d.path().join("moved")).unwrap(), b"unchanged");
    }

    #[test]
    fn write_and_sync_errors_preserve_honest_effect_state() {
        // A mutated nonadvancing write loop must be killed and reaped, not hang the suite.
        crate::testutil::isolated(
            "mutation::tests::write_and_sync_errors_preserve_honest_effect_state",
            || {
                let d = tempfile::tempdir().unwrap();
                let p = d.path().join("partial-sentinel");
                std::fs::write(&p, b"original").unwrap();
                let fd = writable(&p);
                let error = replace_bytes(
                    &fd,
                    &p,
                    b"new",
                    || Ok(()),
                    |_, _, _| Err(nix::errno::Errno::EIO),
                    syscall::fsync_fd,
                )
                .unwrap_err();
                assert_eq!(error.state, EffectState::NoEffect);
                assert_eq!(std::fs::read(&p).unwrap(), b"original");
                let error = replace_bytes(
                    &fd,
                    &p,
                    b"new",
                    || Ok(()),
                    |fd, bytes, offset| {
                        if offset == 0 {
                            syscall::write_at(fd, &bytes[..1], offset)
                        } else {
                            Err(nix::errno::Errno::EIO)
                        }
                    },
                    syscall::fsync_fd,
                )
                .unwrap_err();
                assert_eq!(error.state, EffectState::Partial);
                assert_eq!(std::fs::read(&p).unwrap(), b"nriginal");
                let error = replace_bytes(
                    &fd,
                    &p,
                    b"changed",
                    || Ok(()),
                    syscall::write_at,
                    |_| Err(nix::errno::Errno::EIO),
                )
                .unwrap_err();
                assert_eq!(error.state, EffectState::DurabilityUnknown);
                assert_eq!(std::fs::read(&p).unwrap(), b"changed");
            },
        );
    }
}
