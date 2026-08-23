//! All flag composition and raw syscall invocation. Nothing here makes a decision.
//!
//! Isolated because the crate's defining controls are carried by bitflag unions
//! (`OFlag`, `Mode`, `ResolveFlag`, `AtFlags` are four `libc_bitflags!` families) and
//! by *which* syscall variant is called. `cargo-mutants`' `replace | with ^` on a
//! disjoint union is behaviourally identical — an *equivalent* mutant: unkillable,
//! reported MISSED, gate fails. So this file is `exclude_globs`.

use crate::error::IoError;
use nix::fcntl::{AtFlags, OFlag};
use nix::sys::stat::{FileStat, Mode as NixMode};
use std::os::fd::{AsFd, OwnedFd};
use std::path::Path;

/// Open the anchor's parent BY PATH. Deliberately symlink-following: `spec:155`/`:157`
/// make a symlinked ancestor permitted and resolved once. `O_DIRECTORY` is what makes
/// this FIFO-safe; `O_CLOEXEC` because std::fs sets FD_CLOEXEC implicitly and nix does
/// not — an inherited dirfd is `openat`-reachable across exec.
pub(crate) fn open_parent_by_path(p: &Path) -> nix::Result<OwnedFd> {
    nix::fcntl::open(
        p,
        OFlag::O_RDONLY | OFlag::O_DIRECTORY | OFlag::O_CLOEXEC,
        NixMode::empty(),
    )
}

/// Open a directory relative to a pinned dirfd, refusing symlinks at this component.
pub(crate) fn open_dir_at<F: AsFd>(dirfd: &F, name: &str) -> nix::Result<OwnedFd> {
    nix::fcntl::openat(
        dirfd,
        name,
        OFlag::O_RDONLY
            | OFlag::O_DIRECTORY
            | OFlag::O_NOFOLLOW
            | OFlag::O_NONBLOCK
            | OFlag::O_CLOEXEC,
        NixMode::empty(),
    )
}

/// Open a read target relative to a pinned dirfd. O_NONBLOCK because a planted FIFO
/// blocks forever otherwise (measured: killed at 2s without it).
pub(crate) fn open_read_target<F: AsFd>(dirfd: &F, name: &str) -> nix::Result<OwnedFd> {
    nix::fcntl::openat(
        dirfd,
        name,
        OFlag::O_RDONLY | OFlag::O_NOFOLLOW | OFlag::O_NONBLOCK | OFlag::O_CLOEXEC,
        NixMode::empty(),
    )
}

/// Re-open the pinned directory as a Dir handle. Dir::openat BORROWS the dirfd;
/// Dir::from_fd would consume and Drop-close it, destroying the anchor pin.
pub(crate) fn open_dir_handle<F: AsFd>(dirfd: &F) -> nix::Result<nix::dir::Dir> {
    nix::dir::Dir::openat(
        dirfd,
        ".",
        OFlag::O_RDONLY
            | OFlag::O_DIRECTORY
            | OFlag::O_NOFOLLOW
            | OFlag::O_NONBLOCK
            | OFlag::O_CLOEXEC,
        NixMode::empty(),
    )
}

/// The crate's ONLY `fstat` call site, and it takes an fd — never a path. The
/// spec:160 build requirement greps for exactly this.
pub(crate) fn fstat<F: AsFd>(fd: &F) -> nix::Result<FileStat> {
    nix::sys::stat::fstat(fd)
}

/// `fstatat` with `AT_SYMLINK_NOFOLLOW` — used only to disambiguate an ENOTDIR from a
/// single-component `openat`, and only with a dirfd in hand. Never a multi-component
/// path: that would re-resolve through intermediate symlinks.
pub(crate) fn fstatat_nofollow<F: AsFd>(dirfd: &F, name: &str) -> nix::Result<FileStat> {
    nix::sys::stat::fstatat(dirfd, name, AtFlags::AT_SYMLINK_NOFOLLOW)
}

/// Errno -> IoError for a *path-based* open (§4 row 0): no dirfd and no single
/// component, so the ENOTDIR disambiguation cannot apply here.
pub(crate) fn map_open_errno(e: nix::Error, path: &Path) -> IoError {
    crate::checks::map_errno_no_disambiguation(e, path)
}

/// The `openat2` fast path. Linux-only — the `use` sits inside the cfg'd fn, because
/// `openat2`/`OpenHow`/`ResolveFlag` are gated behind `cfg(target_os = "linux")` in nix
/// and a top-level import breaks the darwin dev build.
///
/// `RESOLVE_BENEATH` is used alongside `RESOLVE_NO_SYMLINKS`: measured, it rejects only
/// an ESCAPING `..` (in-bounds `..` still resolves), and the remainder is relative by
/// the time this is called, so its absolute-path refusal is unreachable. It gives
/// kernel-enforced containment for free.
#[cfg(target_os = "linux")]
pub(crate) fn openat2_resolve<F: AsFd>(
    dirfd: &F,
    rel: &str,
    want_dir: bool,
) -> nix::Result<OwnedFd> {
    use nix::fcntl::{openat2, OpenHow, ResolveFlag};
    let mut flags = OFlag::O_RDONLY | OFlag::O_NONBLOCK | OFlag::O_CLOEXEC;
    if want_dir {
        flags |= OFlag::O_DIRECTORY;
    }
    let how = OpenHow::new()
        .flags(flags)
        .resolve(ResolveFlag::RESOLVE_NO_SYMLINKS | ResolveFlag::RESOLVE_BENEATH);
    openat2(dirfd, rel, how)
}

/// One-shot capability probe against the anchor fd itself — never AT_FDCWD, which
/// under chdir("/") or a systemd RootDirectory= can return errnos that say nothing
/// about openat2 availability. Uses the full production flag set: a probe under a
/// weaker set does not establish that the real call succeeds.
#[cfg(target_os = "linux")]
pub(crate) fn probe_openat2<F: AsFd>(dirfd: &F) -> Result<(), nix::errno::Errno> {
    openat2_resolve(dirfd, ".", true).map(|_| ())
}

#[cfg(not(target_os = "linux"))]
pub(crate) fn probe_openat2<F: AsFd>(_dirfd: &F) -> Result<(), nix::errno::Errno> {
    Err(nix::errno::Errno::ENOSYS)
}

/// Mode A's temp. O_EXCL makes a pre-existing name (regular file OR symlink) EEXIST
/// regardless of O_NOFOLLOW, so O_NOFOLLOW here is redundant-but-harmless rather than
/// a separately observable control.
pub(crate) fn open_temp_excl<F: AsFd>(
    dirfd: &F,
    name: &str,
    mode: crate::anchor::Mode,
) -> nix::Result<OwnedFd> {
    nix::fcntl::openat(
        dirfd,
        name,
        OFlag::O_WRONLY
            | OFlag::O_NOFOLLOW
            | OFlag::O_CREAT
            | OFlag::O_EXCL
            | OFlag::O_NONBLOCK
            | OFlag::O_CLOEXEC,
        NixMode::from_bits_truncate(mode.0 as _),
    )
}

pub(crate) fn rename_at<F: AsFd>(dirfd: &F, from: &str, to: &str) -> nix::Result<()> {
    nix::fcntl::renameat(dirfd, from, dirfd, to)
}

pub(crate) fn unlink_at<F: AsFd>(dirfd: &F, name: &str) -> nix::Result<()> {
    nix::unistd::unlinkat(dirfd, name, nix::unistd::UnlinkatFlags::NoRemoveDir)
}

pub(crate) fn fsync_fd<F: AsFd>(fd: &F) -> nix::Result<()> {
    nix::unistd::fsync(fd)
}

/// Mode B's append open. O_NONBLOCK because a planted FIFO otherwise blocks — and on
/// the WRITE side a readerless FIFO is ENXIO at the open (measured), before any fstat,
/// so `regular_file` never runs on this path.
pub(crate) fn open_append<F: AsFd>(
    dirfd: &F,
    name: &str,
    mode: crate::anchor::Mode,
) -> nix::Result<OwnedFd> {
    nix::fcntl::openat(
        dirfd,
        name,
        OFlag::O_WRONLY
            | OFlag::O_APPEND
            | OFlag::O_NOFOLLOW
            | OFlag::O_CREAT
            | OFlag::O_NONBLOCK
            | OFlag::O_CLOEXEC,
        NixMode::from_bits_truncate(mode.0 as _),
    )
}

pub(crate) fn sync_data<F: AsFd>(fd: &F) -> nix::Result<()> {
    nix::unistd::fdatasync(fd)
}
