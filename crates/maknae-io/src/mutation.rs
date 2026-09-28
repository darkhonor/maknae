//! Descriptor-bound subject-side filesystem attempts. Directory evidence proves location only;
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
    pub version: Option<FileVersion>,
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

fn same_path(actual: &Path, expected: &Path) -> Result<(), IoError> {
    if actual != expected {
        return Err(IoError::MutationPathChanged {
            path: expected.to_path_buf(),
        });
    }
    Ok(())
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

const SINGLE_LINK_REGULAR: TargetRequired = TargetRequired {
    nlink_exactly_one: true,
    ..TargetRequired::OS_DAC_REGULAR
};

fn same_object(a: &nix::sys::stat::FileStat, b: &nix::sys::stat::FileStat) -> bool {
    a.st_dev == b.st_dev && a.st_ino == b.st_ino
}

fn pin(
    held: BorrowedFd<'_>,
    expected: &Path,
    required: &TargetRequired,
) -> Result<nix::sys::stat::FileStat, MutationFailure> {
    checked_path(expected).map_err(no_effect(expected))?;
    let pinned = syscall::fstat(&held)
        .map_err(at(expected))
        .map_err(no_effect(expected))?;
    crate::checks::check_target(&pinned, expected, required).map_err(no_effect(expected))?;
    Ok(pinned)
}

fn reopen_failure(e: nix::errno::Errno, expected: &Path) -> MutationFailure {
    let source = if e == nix::errno::Errno::ENOENT {
        IoError::MutationPathChanged {
            path: expected.to_path_buf(),
        }
    } else {
        io_error(e, expected)
    };
    failure(expected, EffectState::NoEffect, source)
}

fn bound_to(
    fd: &OwnedFd,
    pinned: &nix::sys::stat::FileStat,
    expected: &Path,
    required: &TargetRequired,
) -> Result<(), IoError> {
    let st = syscall::fstat(fd).map_err(at(expected))?;
    crate::checks::check_target(&st, expected, required)?;
    if !same_object(&st, pinned) {
        return Err(IoError::MutationPathChanged {
            path: expected.to_path_buf(),
        });
    }
    same_path(&syscall::fd_path(fd).map_err(at(expected))?, expected)
}

/// What a replacement must find before it writes (#388).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WriteBase {
    Any,
    Unread,
    Version(FileVersion),
}

/// Replace a held file's bytes. The base is checked on the descriptor being
/// written, after the ordinary refusals; the written version is `None` only when
/// the final `fstat` fails, the bytes being written and synced by then.
pub fn replace_held_file(
    held: BorrowedFd<'_>,
    expected: &Path,
    bytes: &[u8],
    base: WriteBase,
) -> Result<Option<FileVersion>, MutationFailure> {
    replace_held_file_with(held, expected, bytes, base, syscall::fstat)
}

fn replace_held_file_with(
    held: BorrowedFd<'_>,
    expected: &Path,
    bytes: &[u8],
    base: WriteBase,
    mut fstat: impl FnMut(&OwnedFd) -> nix::Result<nix::sys::stat::FileStat>,
) -> Result<Option<FileVersion>, MutationFailure> {
    let pinned = pin(held, expected, &SINGLE_LINK_REGULAR)?;
    let fd = syscall::reopen_writable(&held, expected).map_err(|e| reopen_failure(e, expected))?;
    let check = || bound_to(&fd, &pinned, expected, &SINGLE_LINK_REGULAR);
    let stale = || {
        failure(
            expected,
            EffectState::NoEffect,
            IoError::StaleBase {
                path: expected.to_path_buf(),
            },
        )
    };
    match base {
        WriteBase::Any => {}
        WriteBase::Unread => {
            check().map_err(no_effect(expected))?;
            return Err(stale());
        }
        WriteBase::Version(b) => {
            check().map_err(no_effect(expected))?;
            let st = fstat(&fd)
                .map_err(at(expected))
                .map_err(no_effect(expected))?;
            if !FileVersion::of(&st).same_content(&b) {
                return Err(stale());
            }
        }
    }
    replace_bytes(
        &fd,
        expected,
        bytes,
        check,
        syscall::write_at,
        syscall::fsync_fd,
    )?;
    Ok(fstat(&fd).ok().map(|st| FileVersion::of(&st)))
}

pub fn read_held_file(
    held: BorrowedFd<'_>,
    expected: &Path,
    max_bytes: u64,
) -> Result<crate::Zeroizing<Vec<u8>>, MutationFailure> {
    let required = TargetRequired {
        max_bytes: Some(max_bytes),
        ..SINGLE_LINK_REGULAR
    };
    let pinned = pin(held, expected, &required)?;
    let fd = syscall::reopen_readable(&held, expected).map_err(|e| reopen_failure(e, expected))?;
    bound_to(&fd, &pinned, expected, &required).map_err(no_effect(expected))?;
    crate::anchor::read_checked_fd(&fd, expected, &required).map_err(no_effect(expected))
}

struct HeldReader<'f> {
    fd: &'f OwnedFd,
    deadline: Instant,
}

impl std::io::Read for HeldReader<'_> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        if Instant::now() >= self.deadline {
            return Err(std::io::ErrorKind::TimedOut.into());
        }
        nix::unistd::read(self.fd, buf).map_err(|e| std::io::Error::from_raw_os_error(e as i32))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct FileVersion {
    pub dev: u64,
    pub ino: u64,
    pub size: i64,
    pub mtime: i64,
    pub mtime_nsec: i64,
    pub ctime: i64,
    pub ctime_nsec: i64,
}

impl FileVersion {
    // The stat field types differ on macOS, where these casts are not no-ops.
    #[allow(clippy::unnecessary_cast)]
    pub fn of(s: &nix::sys::stat::FileStat) -> Self {
        Self {
            dev: s.st_dev as u64,
            ino: s.st_ino as u64,
            size: s.st_size as i64,
            mtime: s.st_mtime as i64,
            mtime_nsec: s.st_mtime_nsec as i64,
            ctime: s.st_ctime as i64,
            ctime_nsec: s.st_ctime_nsec as i64,
        }
    }
    pub fn from_key(k: [i64; 7]) -> Self {
        Self {
            dev: k[0] as u64,
            ino: k[1] as u64,
            size: k[2],
            mtime: k[3],
            mtime_nsec: k[4],
            ctime: k[5],
            ctime_nsec: k[6],
        }
    }
    /// ctime is left out: it moves on `chmod`, xattr writes and overlayfs
    /// copy-up, none of which change the content (#388).
    pub fn same_content(&self, other: &Self) -> bool {
        self.dev == other.dev
            && self.ino == other.ino
            && self.size == other.size
            && self.mtime == other.mtime
            && self.mtime_nsec == other.mtime_nsec
    }
    /// `maknae-agent`'s `same_content` compares these indices; keep the order.
    pub fn key(&self) -> [i64; 7] {
        [
            self.dev as i64,
            self.ino as i64,
            self.size,
            self.mtime,
            self.mtime_nsec,
            self.ctime,
            self.ctime_nsec,
        ]
    }
}

pub fn read_held_page(
    held: BorrowedFd<'_>,
    expected: &Path,
    window: crate::PageWindow,
    cap: u64,
    deadline: Instant,
) -> Result<crate::Page, MutationFailure> {
    read_held_page_with(held, expected, window, cap, deadline, syscall::fstat)
}

fn read_held_page_with(
    held: BorrowedFd<'_>,
    expected: &Path,
    window: crate::PageWindow,
    cap: u64,
    deadline: Instant,
    mut fstat: impl FnMut(&OwnedFd) -> nix::Result<nix::sys::stat::FileStat>,
) -> Result<crate::Page, MutationFailure> {
    let pinned = pin(held, expected, &SINGLE_LINK_REGULAR)?;
    let fd = syscall::reopen_readable(&held, expected).map_err(|e| reopen_failure(e, expected))?;
    bound_to(&fd, &pinned, expected, &SINGLE_LINK_REGULAR).map_err(no_effect(expected))?;
    let mut stat = |fd: &OwnedFd| fstat(fd).map_err(|e| no_effect(expected)(io_error(e, expected)));
    let before = stat(&fd)?;
    let mut reader = HeldReader { fd: &fd, deadline };
    let page = crate::page::read_page(&mut reader, window, cap as usize).map_err(|e| {
        no_effect(expected)(match e.kind() {
            std::io::ErrorKind::TimedOut => IoError::DeadlineElapsed {
                path: expected.to_path_buf(),
            },
            _ => io_error(
                nix::errno::Errno::from_raw(e.raw_os_error().unwrap_or(nix::libc::EIO)),
                expected,
            ),
        })
    })?;
    let after = stat(&fd)?;
    if FileVersion::of(&before) != FileVersion::of(&after) {
        return Err(no_effect(expected)(IoError::MutationPathChanged {
            path: expected.to_path_buf(),
        }));
    }
    Ok(crate::Page {
        version: FileVersion::of(&before),
        ..page
    })
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
        self.create_exclusive_with(
            leaf,
            |fd, path| {
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
            },
            syscall::fstat,
        )
    }

    fn create_exclusive_with(
        &self,
        leaf: &str,
        write: impl FnOnce(&OwnedFd, &Path) -> Result<(), MutationFailure>,
        fstat: impl FnOnce(&OwnedFd) -> nix::Result<nix::sys::stat::FileStat>,
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
            version: fstat(&fd).ok().map(|st| FileVersion::of(&st)),
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
            version: None,
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
            version: None,
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
    fn far() -> Instant {
        Instant::now() + std::time::Duration::from_secs(60)
    }
    fn held(p: &Path) -> OwnedFd {
        crate::open_path_for_delegation(p).unwrap()
    }
    #[test]
    fn held_replacement_truncates_through_a_fresh_writable_open_and_keeps_identity() {
        crate::testutil::isolated(
            "mutation::tests::held_replacement_truncates_through_a_fresh_writable_open_and_keeps_identity",
            || {
                let d = tempfile::tempdir().unwrap();
                let p = root(&d).join("held-replace-sentinel");
                std::fs::write(&p, b"original long bytes").unwrap();
                let mut shared = OpenOptions::new().write(true).open(&p).unwrap();
                shared.seek(SeekFrom::Start(9)).unwrap();
                let before = syscall::stat_path(&p).unwrap();
                let fd = held(&p);
                replace_held_file(fd.as_fd(), &p, b"new", WriteBase::Any).unwrap();
                assert_eq!(std::fs::read(&p).unwrap(), b"new");
                assert_eq!(shared.stream_position().unwrap(), 9);
                assert!(same_object(&before, &syscall::stat_path(&p).unwrap()));
                replace_held_file(fd.as_fd(), &p, b"", WriteBase::Any).unwrap();
                assert!(std::fs::read(&p).unwrap().is_empty());
            },
        );
    }
    #[test]
    fn held_replacement_refuses_directories_links_and_moved_objects_without_effect() {
        let d = tempfile::tempdir().unwrap();
        let dir = root(&d);
        let e = replace_held_file(held(&dir).as_fd(), &dir, b"bad", WriteBase::Any).unwrap_err();
        assert_eq!(e.state, EffectState::NoEffect);
        assert!(matches!(e.source, IoError::NotRegularFile { .. }), "{e:?}");
        let p = dir.join("linked-sentinel");
        std::fs::write(&p, b"untouched").unwrap();
        std::fs::hard_link(&p, dir.join("second-name")).unwrap();
        let e = replace_held_file(held(&p).as_fd(), &p, b"bad", WriteBase::Any).unwrap_err();
        assert!(matches!(e.source, IoError::MultiplyLinked { .. }), "{e:?}");
        std::fs::remove_file(dir.join("second-name")).unwrap();
        let fd = held(&p);
        std::fs::rename(&p, dir.join("moved")).unwrap();
        let e = replace_held_file(fd.as_fd(), &p, b"bad", WriteBase::Any).unwrap_err();
        assert_eq!(e.state, EffectState::NoEffect);
        assert!(
            matches!(e.source, IoError::MutationPathChanged { .. }),
            "{e:?}"
        );
        std::fs::write(&p, b"newcomer").unwrap();
        let e = replace_held_file(fd.as_fd(), &p, b"bad", WriteBase::Any).unwrap_err();
        assert_eq!(e.state, EffectState::NoEffect);
        assert_eq!(std::fs::read(&p).unwrap(), b"newcomer");
        assert_eq!(std::fs::read(dir.join("moved")).unwrap(), b"untouched");
    }
    fn version(p: &Path) -> FileVersion {
        FileVersion::of(&syscall::stat_path(p).unwrap())
    }
    #[test]
    fn a_matching_base_replaces_and_returns_the_written_version() {
        let d = tempfile::tempdir().unwrap();
        let p = root(&d).join("matching-base-sentinel");
        std::fs::write(&p, b"old").unwrap();
        let base = version(&p);
        let written = replace_held_file(held(&p).as_fd(), &p, b"newer!", WriteBase::Version(base))
            .unwrap()
            .expect("the written version");
        assert_eq!(std::fs::read(&p).unwrap(), b"newer!");
        assert_eq!(written, version(&p));
        assert!(!written.same_content(&base));
    }
    #[test]
    fn a_base_whose_file_grew_is_refused_with_no_effect() {
        // Every "changed" fixture changes the length: two same-size writes can
        // share a coarse-clock timestamp tick and leave the version identical.
        let d = tempfile::tempdir().unwrap();
        let p = root(&d).join("grown-base-sentinel");
        std::fs::write(&p, b"old").unwrap();
        let base = version(&p);
        std::fs::write(&p, b"edited out of band").unwrap();
        let e = replace_held_file(
            held(&p).as_fd(),
            &p,
            b"stale content",
            WriteBase::Version(base),
        )
        .unwrap_err();
        assert_eq!(e.state, EffectState::NoEffect);
        assert!(matches!(e.source, IoError::StaleBase { .. }), "{e:?}");
        assert_eq!(std::fs::read(&p).unwrap(), b"edited out of band");
    }
    #[test]
    fn an_unread_base_refuses_an_existing_file_with_no_effect() {
        let d = tempfile::tempdir().unwrap();
        let p = root(&d).join("unread-base-sentinel");
        std::fs::write(&p, b"never read").unwrap();
        let e = replace_held_file(held(&p).as_fd(), &p, b"blind", WriteBase::Unread).unwrap_err();
        assert_eq!(e.state, EffectState::NoEffect);
        assert!(matches!(e.source, IoError::StaleBase { .. }), "{e:?}");
        assert_eq!(std::fs::read(&p).unwrap(), b"never read");
    }
    #[test]
    fn an_unread_base_keeps_the_ordinary_refusals() {
        let d = tempfile::tempdir().unwrap();
        let dir = root(&d);
        let p = dir.join("linked-unread-sentinel");
        std::fs::write(&p, b"untouched").unwrap();
        std::fs::hard_link(&p, dir.join("second-name")).unwrap();
        let e = replace_held_file(held(&p).as_fd(), &p, b"bad", WriteBase::Unread).unwrap_err();
        assert!(matches!(e.source, IoError::MultiplyLinked { .. }), "{e:?}");
        std::fs::remove_file(dir.join("second-name")).unwrap();
        let fd = held(&p);
        std::fs::rename(&p, dir.join("moved")).unwrap();
        let e = replace_held_file(fd.as_fd(), &p, b"bad", WriteBase::Unread).unwrap_err();
        assert!(
            matches!(e.source, IoError::MutationPathChanged { .. }),
            "{e:?}"
        );
        assert_eq!(std::fs::read(dir.join("moved")).unwrap(), b"untouched");
    }
    #[test]
    fn a_ctime_only_change_does_not_refuse() {
        let d = tempfile::tempdir().unwrap();
        let p = root(&d).join("ctime-only-sentinel");
        std::fs::write(&p, b"content").unwrap();
        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o600)).unwrap();
        let base = version(&p);
        std::thread::sleep(std::time::Duration::from_millis(20));
        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o640)).unwrap();
        let now = version(&p);
        assert_ne!(
            (now.ctime, now.ctime_nsec),
            (base.ctime, base.ctime_nsec),
            "precondition: chmod must move ctime"
        );
        assert_eq!((now.mtime, now.mtime_nsec), (base.mtime, base.mtime_nsec));
        replace_held_file(held(&p).as_fd(), &p, b"rewritten", WriteBase::Version(base)).unwrap();
        assert_eq!(std::fs::read(&p).unwrap(), b"rewritten");
    }
    #[test]
    fn same_content_compares_everything_but_ctime() {
        let base = FileVersion {
            dev: 1,
            ino: 2,
            size: 3,
            mtime: 4,
            mtime_nsec: 5,
            ctime: 6,
            ctime_nsec: 7,
        };
        assert!(base.same_content(&base));
        let changed: [fn(&mut FileVersion); 5] = [
            |v| v.dev += 1,
            |v| v.ino += 1,
            |v| v.size += 1,
            |v| v.mtime += 1,
            |v| v.mtime_nsec += 1,
        ];
        for (i, change) in changed.iter().enumerate() {
            let mut v = base;
            change(&mut v);
            assert!(!base.same_content(&v), "field {i}");
        }
        let ignored: [fn(&mut FileVersion); 2] = [|v| v.ctime += 1, |v| v.ctime_nsec += 1];
        for change in ignored {
            let mut v = base;
            change(&mut v);
            assert!(base.same_content(&v));
        }
    }
    #[test]
    fn from_key_inverts_key() {
        let v = FileVersion {
            dev: u64::MAX,
            ino: 9,
            size: -1,
            mtime: 4,
            mtime_nsec: 5,
            ctime: 6,
            ctime_nsec: 7,
        };
        assert_eq!(FileVersion::from_key(v.key()), v);
    }
    #[test]
    fn a_failed_post_write_fstat_is_ok_none_with_the_bytes_written() {
        let d = tempfile::tempdir().unwrap();
        let p = root(&d).join("post-fstat-sentinel");
        std::fs::write(&p, b"old").unwrap();
        let got = replace_held_file_with(held(&p).as_fd(), &p, b"written", WriteBase::Any, |_| {
            Err(nix::errno::Errno::EIO)
        })
        .unwrap();
        assert_eq!(got, None);
        assert_eq!(std::fs::read(&p).unwrap(), b"written");
    }
    #[test]
    fn a_failed_post_create_fstat_is_a_created_file_with_no_version() {
        let d = tempfile::tempdir().unwrap();
        let effect = directory(&d)
            .create_exclusive_with(
                "post-fstat-created",
                |fd, path| {
                    replace_bytes(
                        fd,
                        path,
                        b"kept",
                        || Ok(()),
                        syscall::write_at,
                        syscall::fsync_fd,
                    )
                },
                |_| Err(nix::errno::Errno::EIO),
            )
            .unwrap();
        assert_eq!(effect.version, None);
        assert_eq!(effect.kind, MutationEffectKind::CreatedFile);
        assert_eq!(
            std::fs::read(d.path().join("post-fstat-created")).unwrap(),
            b"kept"
        );
    }
    #[test]
    fn a_failed_pre_write_fstat_is_an_ordinary_refusal_never_stale() {
        let d = tempfile::tempdir().unwrap();
        let p = root(&d).join("pre-fstat-sentinel");
        std::fs::write(&p, b"kept").unwrap();
        let base = version(&p);
        let e = replace_held_file_with(
            held(&p).as_fd(),
            &p,
            b"not written",
            WriteBase::Version(base),
            |_| Err(nix::errno::Errno::EIO),
        )
        .unwrap_err();
        assert_eq!(e.state, EffectState::NoEffect);
        assert!(matches!(e.source, IoError::Io { .. }), "{e:?}");
        assert_eq!(std::fs::read(&p).unwrap(), b"kept");
    }
    #[test]
    fn create_exclusive_returns_the_created_files_version() {
        let d = tempfile::tempdir().unwrap();
        let effect = directory(&d)
            .create_exclusive("created-version", b"fresh")
            .unwrap();
        assert_eq!(
            effect.version,
            Some(version(&d.path().join("created-version")))
        );
    }
    #[test]
    fn identity_is_device_and_inode_together() {
        let d = tempfile::tempdir().unwrap();
        let (a, b) = (root(&d).join("a"), root(&d).join("b"));
        std::fs::write(&a, b"a").unwrap();
        std::fs::write(&b, b"b").unwrap();
        let sa = syscall::stat_path(&a).unwrap();
        assert!(same_object(
            &sa,
            &syscall::fstat(&File::open(&a).unwrap()).unwrap()
        ));
        assert!(!same_object(&sa, &syscall::stat_path(&b).unwrap()));
        let mut elsewhere = sa;
        elsewhere.st_dev = sa.st_dev.wrapping_add(1);
        assert!(!same_object(&sa, &elsewhere));
    }
    #[test]
    fn held_replacement_is_refused_by_the_subjects_own_permissions() {
        if nix::unistd::geteuid().is_root() {
            crate::testutil::skip_or_fail(
                "held_replacement_is_refused_by_the_subjects_own_permissions",
                "running as root, which writes a 0444 file and voids the premise",
            );
            return;
        }
        let d = tempfile::tempdir().unwrap();
        let p = root(&d).join("read-only-sentinel");
        std::fs::write(&p, b"untouched").unwrap();
        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o444)).unwrap();
        let e = replace_held_file(held(&p).as_fd(), &p, b"bad", WriteBase::Any).unwrap_err();
        assert_eq!(e.state, EffectState::NoEffect);
        assert!(
            matches!(
                e.source,
                IoError::Io {
                    kind: crate::IoKind::PermissionDenied,
                    ..
                }
            ),
            "{e:?}"
        );
        assert_eq!(std::fs::read(&p).unwrap(), b"untouched");
    }
    #[cfg(target_os = "linux")]
    #[test]
    fn linux_reopen_reaches_the_held_inode_without_walking_its_path() {
        if nix::unistd::geteuid().is_root() {
            crate::testutil::skip_or_fail(
                "linux_reopen_reaches_the_held_inode_without_walking_its_path",
                "running as root, which traverses a 0600 directory and voids the premise",
            );
            return;
        }
        crate::testutil::isolated(
            "mutation::tests::linux_reopen_reaches_the_held_inode_without_walking_its_path",
            || {
                let d = tempfile::tempdir().unwrap();
                let dir = root(&d).join("sub");
                std::fs::create_dir(&dir).unwrap();
                let p = dir.join("held-sentinel");
                std::fs::write(&p, b"old").unwrap();
                let fd = held(&p);
                std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o600)).unwrap();
                let result = replace_held_file(fd.as_fd(), &p, b"new", WriteBase::Any);
                std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700)).unwrap();
                result.unwrap();
                assert_eq!(std::fs::read(&p).unwrap(), b"new");
            },
        );
    }
    #[test]
    fn held_read_returns_the_bytes_through_a_fresh_readable_open_and_keeps_identity() {
        crate::testutil::isolated(
            "mutation::tests::held_read_returns_the_bytes_through_a_fresh_readable_open_and_keeps_identity",
            || {
                let d = tempfile::tempdir().unwrap();
                let p = root(&d).join("held-read-sentinel");
                std::fs::write(&p, b"read me exactly").unwrap();
                let fd = held(&p);
                assert_eq!(&*read_held_file(fd.as_fd(), &p, 15).unwrap(), b"read me exactly");
                assert_eq!(&*read_held_file(fd.as_fd(), &p, 15).unwrap(), b"read me exactly");
                std::fs::write(&p, b"").unwrap();
                assert!(read_held_file(fd.as_fd(), &p, 0).unwrap().is_empty());
            },
        );
    }
    #[test]
    fn a_held_file_pages_from_the_line_asked_for() {
        crate::testutil::isolated(
            "mutation::tests::a_held_file_pages_from_the_line_asked_for",
            || {
                let d = tempfile::tempdir().unwrap();
                let p = root(&d).join("paged-sentinel");
                std::fs::write(&p, b"one\ntwo\nthree\n").unwrap();
                let fd = held(&p);
                let w = crate::PageWindow {
                    offset_line: 2,
                    limit_lines: 1,
                    column: 0,
                };
                let page = read_held_page(fd.as_fd(), &p, w, 64, far()).unwrap();
                assert_eq!(
                    (&page.content[..], page.start, page.lines),
                    (&b"two\n"[..], 4, Some((2, 2)))
                );
                assert_ne!(page.version, FileVersion::default());
            },
        );
    }
    #[test]
    fn a_page_whose_file_changes_under_the_read_is_refused() {
        crate::testutil::isolated(
            "mutation::tests::a_page_whose_file_changes_under_the_read_is_refused",
            || {
                let d = tempfile::tempdir().unwrap();
                let p = root(&d).join("changing-sentinel");
                std::fs::write(&p, b"one\ntwo\n").unwrap();
                let fd = held(&p);
                let w = crate::PageWindow {
                    offset_line: 1,
                    limit_lines: 9,
                    column: 0,
                };
                for field in 0..7 {
                    let mut calls = 0;
                    let changed = read_held_page_with(fd.as_fd(), &p, w, 64, far(), |f| {
                        calls += 1;
                        let mut s = syscall::fstat(f)?;
                        if calls == 2 {
                            match field {
                                0 => s.st_size += 1,
                                1 => s.st_mtime += 1,
                                2 => s.st_mtime_nsec += 1,
                                3 => s.st_ctime += 1,
                                4 => s.st_ctime_nsec += 1,
                                5 => s.st_dev += 1,
                                _ => s.st_ino += 1,
                            }
                        }
                        Ok(s)
                    });
                    let e = changed.unwrap_err();
                    assert!(
                        matches!(e.source, IoError::MutationPathChanged { .. }),
                        "field {field}: {e:?}"
                    );
                    assert_eq!(e.state, EffectState::NoEffect);
                }
                let failed = read_held_page_with(fd.as_fd(), &p, w, 64, far(), |_| {
                    Err(nix::errno::Errno::EIO)
                });
                assert_eq!(failed.unwrap_err().state, EffectState::NoEffect);
                let mut calls = 0;
                let second = read_held_page_with(fd.as_fd(), &p, w, 64, far(), |f| {
                    calls += 1;
                    if calls == 2 {
                        return Err(nix::errno::Errno::EIO);
                    }
                    syscall::fstat(f)
                });
                assert_eq!(second.unwrap_err().state, EffectState::NoEffect);
                let dir = root(&d);
                assert_eq!(
                    read_held_page(held(&dir).as_fd(), &dir, w, 64, far())
                        .unwrap_err()
                        .state,
                    EffectState::NoEffect
                );
            },
        );
    }
    #[test]
    fn a_page_read_past_its_deadline_stops_with_nothing() {
        crate::testutil::isolated(
            "mutation::tests::a_page_read_past_its_deadline_stops_with_nothing",
            || {
                let d = tempfile::tempdir().unwrap();
                let p = root(&d).join("deadline-sentinel");
                std::fs::write(&p, b"one\ntwo\n").unwrap();
                let w = crate::PageWindow {
                    offset_line: 1,
                    limit_lines: 9,
                    column: 0,
                };
                let e = read_held_page(held(&p).as_fd(), &p, w, 64, Instant::now()).unwrap_err();
                assert!(matches!(e.source, IoError::DeadlineElapsed { .. }), "{e:?}");
                assert_eq!(e.state, EffectState::NoEffect);
                let later = Instant::now() + std::time::Duration::from_secs(60);
                assert_eq!(
                    &read_held_page(held(&p).as_fd(), &p, w, 64, later)
                        .unwrap()
                        .content[..],
                    b"one\ntwo\n"
                );
            },
        );
    }
    #[test]
    fn a_file_versions_key_is_its_seven_fields_in_order() {
        let v = FileVersion {
            dev: 1,
            ino: 2,
            size: 3,
            mtime: 4,
            mtime_nsec: 5,
            ctime: 6,
            ctime_nsec: 7,
        };
        assert_eq!(v.key(), [1, 2, 3, 4, 5, 6, 7]);
    }
    #[test]
    fn a_held_files_version_holds_until_the_file_changes() {
        crate::testutil::isolated(
            "mutation::tests::a_held_files_version_holds_until_the_file_changes",
            || {
                let d = tempfile::tempdir().unwrap();
                let p = root(&d).join("versioned-sentinel");
                std::fs::write(&p, b"one\ntwo\n").unwrap();
                let fd = held(&p);
                let w = crate::PageWindow {
                    offset_line: 1,
                    limit_lines: 1,
                    column: 0,
                };
                let first = read_held_page(fd.as_fd(), &p, w, 64, far())
                    .unwrap()
                    .version;
                assert_eq!(
                    read_held_page(fd.as_fd(), &p, w, 64, far())
                        .unwrap()
                        .version,
                    first
                );
                use std::io::Write;
                std::fs::OpenOptions::new()
                    .append(true)
                    .open(&p)
                    .unwrap()
                    .write_all(b"three\n")
                    .unwrap();
                let later = read_held_page(fd.as_fd(), &p, w, 64, far())
                    .unwrap()
                    .version;
                assert_ne!(later, first);
                assert_eq!(first.key()[..2], later.key()[..2]);
            },
        );
    }
    #[test]
    fn held_read_refuses_directories_links_oversize_and_moved_objects_without_reading() {
        crate::testutil::isolated(
            "mutation::tests::held_read_refuses_directories_links_oversize_and_moved_objects_without_reading",
            || {
                let d = tempfile::tempdir().unwrap();
                let dir = root(&d);
                assert_eq!(read_held_file(held(&dir).as_fd(), &dir, 64).unwrap_err().state, EffectState::NoEffect);
                let p = dir.join("read-linked-sentinel");
                std::fs::write(&p, b"sixteen bytes!!!").unwrap();
                assert!(matches!(
                    read_held_file(held(&p).as_fd(), &p, 15).unwrap_err().source,
                    IoError::TargetTooLarge { .. }
                ));
                assert_eq!(&*read_held_file(held(&p).as_fd(), &p, 16).unwrap(), b"sixteen bytes!!!");
                std::fs::hard_link(&p, dir.join("second-name")).unwrap();
                let e = read_held_file(held(&p).as_fd(), &p, 64).unwrap_err();
                assert!(matches!(e.source, IoError::MultiplyLinked { .. }), "{e:?}");
                std::fs::remove_file(dir.join("second-name")).unwrap();
                let fd = held(&p);
                std::fs::rename(&p, dir.join("moved")).unwrap();
                let e = read_held_file(fd.as_fd(), &p, 64).unwrap_err();
                assert!(matches!(e.source, IoError::MutationPathChanged { .. }), "{e:?}");
                std::fs::write(&p, b"newcomer").unwrap();
                let e = read_held_file(fd.as_fd(), &p, 64).unwrap_err();
                assert!(matches!(e.source, IoError::MutationPathChanged { .. }), "{e:?}");
                assert_eq!(e.state, EffectState::NoEffect);
            },
        );
    }
    #[test]
    fn held_read_is_refused_by_the_subjects_own_permissions() {
        if nix::unistd::geteuid().is_root() {
            crate::testutil::skip_or_fail(
                "held_read_is_refused_by_the_subjects_own_permissions",
                "running as root, which reads a 0000 file and voids the premise",
            );
            return;
        }
        crate::testutil::isolated(
            "mutation::tests::held_read_is_refused_by_the_subjects_own_permissions",
            || {
                let d = tempfile::tempdir().unwrap();
                let p = root(&d).join("unreadable-sentinel");
                std::fs::write(&p, b"secret").unwrap();
                let fd = held(&p);
                std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o000)).unwrap();
                let e = read_held_file(fd.as_fd(), &p, 64).unwrap_err();
                let oversize = read_held_file(fd.as_fd(), &p, 5).unwrap_err();
                std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o600)).unwrap();
                assert_eq!(e.state, EffectState::NoEffect);
                assert!(
                    matches!(
                        e.source,
                        IoError::Io {
                            kind: crate::IoKind::PermissionDenied,
                            ..
                        }
                    ),
                    "{e:?}"
                );
                assert!(
                    matches!(oversize.source, IoError::TargetTooLarge { .. }),
                    "{oversize:?}"
                );
            },
        );
    }
    #[cfg(target_os = "linux")]
    #[test]
    fn linux_read_reopen_reaches_the_held_inode_without_walking_its_path() {
        if nix::unistd::geteuid().is_root() {
            crate::testutil::skip_or_fail(
                "linux_read_reopen_reaches_the_held_inode_without_walking_its_path",
                "running as root, which traverses a 0600 directory and voids the premise",
            );
            return;
        }
        crate::testutil::isolated(
            "mutation::tests::linux_read_reopen_reaches_the_held_inode_without_walking_its_path",
            || {
                let d = tempfile::tempdir().unwrap();
                let dir = root(&d).join("sub");
                std::fs::create_dir(&dir).unwrap();
                let p = dir.join("held-read-sentinel");
                std::fs::write(&p, b"old").unwrap();
                let fd = held(&p);
                std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o600)).unwrap();
                let result = read_held_file(fd.as_fd(), &p, 64);
                std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700)).unwrap();
                assert_eq!(&*result.unwrap(), b"old");
            },
        );
    }

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
                    .create_exclusive_with(
                        "failed-write",
                        |fd, path| {
                            replace_bytes(
                                fd,
                                path,
                                b"new",
                                || Ok(()),
                                |_, _, _| Err(nix::errno::Errno::EIO),
                                syscall::fsync_fd,
                            )
                        },
                        syscall::fstat,
                    )
                    .unwrap_err();
                assert_eq!(error.state, EffectState::Partial);
                assert_eq!(std::fs::read(d.path().join("failed-write")).unwrap(), b"");
                let error = dir
                    .create_exclusive_with(
                        "failed-sync",
                        |fd, path| {
                            replace_bytes(
                                fd,
                                path,
                                b"present",
                                || Ok(()),
                                syscall::write_at,
                                |_| Err(nix::errno::Errno::EIO),
                            )
                        },
                        syscall::fstat,
                    )
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
    fn preparation_open_is_nontruncating_and_never_creates() {
        let d = tempfile::tempdir().unwrap();
        let p = d.path().join("prepare-sentinel");
        std::fs::write(&p, b"original").unwrap();
        let fd = crate::open_path_for_delegation(&p).unwrap();
        crate::verify_delegated(fd.as_fd(), req(&d)).unwrap();
        assert_eq!(std::fs::read(&p).unwrap(), b"original");
        assert!(crate::open_path_for_delegation(&d.path().join("absent")).is_err());
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
