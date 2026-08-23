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
