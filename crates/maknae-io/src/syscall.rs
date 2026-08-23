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

/// Widen `mode_t` to `u32`. The cast is load-bearing on darwin, where `mode_t` is
/// `u16`, and a no-op on Linux, where it is already `u32` -- so `unnecessary_cast`
/// fires on Linux ONLY. Found by running clippy on Linux (Debian 13, rustc 1.94.1):
/// 19 `-D warnings` errors that darwin cannot produce, which would have failed CI on
/// push — CI runs on `ubuntu-latest` (Rocky 10 is the deployment target, not the CI
/// runner; conflating the two is what made this comment wrong the first time). Centralized here so the one `allow`
/// sits on two lines instead of nineteen call sites, and never at crate root where it
/// would mask a genuinely unnecessary cast.
#[allow(clippy::unnecessary_cast)]
#[inline]
pub(crate) fn mode_bits(m: nix::libc::mode_t) -> u32 {
    m as u32
}

/// Widen `nlink_t` to `u64`: `u64` on Linux, `u16` on darwin. Same rationale as
/// `mode_bits`, same measurement.
#[allow(clippy::unnecessary_cast)]
#[inline]
pub(crate) fn nlink_count(n: nix::libc::nlink_t) -> u64 {
    n as u64
}

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
pub(crate) fn fstatat_nofollow<F: AsFd, P: ?Sized + nix::NixPath>(
    dirfd: &F,
    name: &P,
) -> nix::Result<FileStat> {
    nix::sys::stat::fstatat(dirfd, name, AtFlags::AT_SYMLINK_NOFOLLOW)
}

/// Errno -> IoError for a *path-based* open (§4 row 0): no dirfd and no single
/// component, so the ENOTDIR disambiguation cannot apply here.
///
/// ELOOP is deliberately NOT translated to `IoError::Symlink`. Row 0 opens the
/// anchor's parent symlink-FOLLOWING by design — `lib.rs` documents a symlinked
/// ancestor as permitted and resolved once — so an ELOOP here means the kernel gave
/// up following a symlink LOOP, not that a symlink was refused. Reporting "symlink
/// refused" for it would tell an operator the opposite of the crate's actual policy.
/// The invariant that actually holds — and it is NOT "every other open carries
/// `O_NOFOLLOW`", which is false: every other open refuses symlinks STRUCTURALLY,
/// five of them via `O_NOFOLLOW` and `openat2_resolve` via `RESOLVE_NO_SYMLINKS`
/// (which carries no `O_NOFOLLOW` because the resolve flags subsume it). ELOOP means
/// "refused" at all six, which is why `map_errno_no_disambiguation` translates it and
/// this function does not. Row 0 is the sole symlink-FOLLOWING open in the crate.
///
/// Stated this way deliberately: the `O_NOFOLLOW` phrasing, applied literally, says
/// the openat2 lane should use THIS mapper — and making that change turns
/// `IoError::Symlink` into `IoError::Io{Other{ELOOP}}` on the fast lane with the
/// darwin suite still fully green, because the only control
/// (`both_lanes_refuse_a_symlinked_component`) takes the portable lane twice there.
/// The site that rule protects is `anchor.rs`'s openat2 dispatch.
pub(crate) fn map_open_errno(e: nix::Error, path: &Path) -> IoError {
    IoError::Io {
        path: path.to_path_buf(),
        kind: crate::checks::kind_of_errno(e),
    }
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

#[cfg(test)]
mod tests {
    //! Every open verb must set `FD_CLOEXEC`.
    //!
    //! This file composes the flags that ARE the crate's security model, and it is
    //! `exclude_globs` (no mutants, because bitflag unions yield equivalent mutants),
    //! so until these tests existed the flag unions had NO automated control at all:
    //! stripping `O_CLOEXEC` from all seven opens left 89/89 green. It was also
    //! `[[t3]]` then — report-only, no floor — and has since been promoted to `[t1]`,
    //! so a coverage floor now backs these assertions.
    //!
    //! Why it matters here specifically: `std::fs` sets `FD_CLOEXEC` implicitly and
    //! `nix` does NOT. `maknae-vault` execs `systemd-creds`, and the agent runtime is
    //! untrusted by design -- an anchor dirfd inherited across that exec is
    //! `openat`-reachable by the child, which walks straight past every path-based
    //! confinement the anchor model buys. Its absence is silent: nothing fails, the
    //! guarantee is just gone.
    //!
    //! Probe used to size these: stripping `O_CLOEXEC` from every open in this file
    //! turns 5 of the 6 darwin-visible tests below RED — 6 of 7 on Linux, where the
    //! openat2 assertion also compiles. The one that does NOT go red is
    //! `open_dir_handle`, and its limitation is stated on the test itself: read that
    //! before trusting it. Counts are lane-specific here on purpose; an unlabelled
    //! "5 of 6" describes the dev host, not the lane CI enforces.

    use super::*;
    use std::os::fd::AsRawFd;

    fn is_cloexec<F: AsFd>(fd: &F) -> bool {
        let bits = nix::fcntl::fcntl(fd.as_fd(), nix::fcntl::FcntlArg::F_GETFD)
            .expect("F_GETFD on a live fd");
        nix::fcntl::FdFlag::from_bits_truncate(bits).contains(nix::fcntl::FdFlag::FD_CLOEXEC)
    }

    fn tmp() -> tempfile::TempDir {
        tempfile::tempdir().expect("tempdir")
    }

    #[test]
    fn open_parent_by_path_sets_cloexec() {
        let d = tmp();
        let fd = open_parent_by_path(d.path()).expect("open parent");
        assert!(is_cloexec(&fd), "anchor parent dirfd must be FD_CLOEXEC");
    }

    #[test]
    fn open_dir_at_sets_cloexec() {
        let d = tmp();
        std::fs::create_dir(d.path().join("sub")).expect("mkdir");
        let parent = open_parent_by_path(d.path()).expect("open parent");
        let fd = open_dir_at(&parent, "sub").expect("open dir");
        assert!(
            is_cloexec(&fd),
            "walked descendant dirfd must be FD_CLOEXEC"
        );
    }

    #[test]
    fn open_read_target_sets_cloexec() {
        let d = tmp();
        std::fs::write(d.path().join("f"), b"x").expect("write");
        let parent = open_parent_by_path(d.path()).expect("open parent");
        let fd = open_read_target(&parent, "f").expect("open target");
        assert!(is_cloexec(&fd), "read target fd must be FD_CLOEXEC");
    }

    /// Pins the END STATE only, and CANNOT detect a missing `O_CLOEXEC` at the call
    /// site -- measured: strip the flag from `open_dir_handle` and this test still
    /// passes, because `nix::dir::Dir::openat` forwards flags verbatim to `openat`
    /// and then `fdopendir` sets `FD_CLOEXEC` itself, afterwards. The gap that
    /// creates is real -- between those two calls the fd is exec-inheritable -- but
    /// it is not observable from outside the function, so no assertion here can hold
    /// it. The call-site flag is held by review and by the comment on
    /// `open_dir_handle`, NOT by this test. Do not read a green here as covering it.
    #[test]
    fn open_dir_handle_ends_up_cloexec() {
        let d = tmp();
        let parent = open_parent_by_path(d.path()).expect("open parent");
        let dir = open_dir_handle(&parent).expect("open dir handle");
        let raw = dir.as_fd().as_raw_fd();
        assert!(raw >= 0, "live dir handle");
        assert!(is_cloexec(&dir), "Dir::openat fd must be FD_CLOEXEC");
    }

    #[test]
    fn open_temp_excl_sets_cloexec() {
        let d = tmp();
        let parent = open_parent_by_path(d.path()).expect("open parent");
        let fd = open_temp_excl(&parent, ".t.tmp", crate::anchor::Mode(0o600)).expect("open temp");
        assert!(is_cloexec(&fd), "publish temp fd must be FD_CLOEXEC");
    }

    #[test]
    fn open_append_sets_cloexec() {
        let d = tmp();
        let parent = open_parent_by_path(d.path()).expect("open parent");
        let fd = open_append(&parent, "log", crate::anchor::Mode(0o600)).expect("open append");
        assert!(is_cloexec(&fd), "append fd must be FD_CLOEXEC");
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn openat2_resolve_sets_cloexec() {
        let d = tmp();
        std::fs::create_dir_all(d.path().join("a")).expect("mkdir");
        std::fs::write(d.path().join("a/f"), b"x").expect("write");
        let parent = open_parent_by_path(d.path()).expect("open parent");
        if probe_openat2(&parent).is_err() {
            crate::testutil::skip_or_fail(
                "openat2_resolve_sets_cloexec",
                "openat2 is not available on this kernel",
            );
            return;
        }
        let fd = openat2_resolve(&parent, "a/f", false).expect("openat2 resolve");
        assert!(is_cloexec(&fd), "openat2 fd must be FD_CLOEXEC");
    }
}
