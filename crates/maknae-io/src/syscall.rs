//! All flag composition and raw syscall invocation. Nothing here makes a decision.
//!
//! Isolated because the crate's defining controls are carried by bitflag unions
//! (`OFlag`, `Mode`, `ResolveFlag`, `AtFlags` are four `libc_bitflags!` families) and
//! by *which* syscall variant is called. `cargo-mutants`' `replace | with ^` on a
//! disjoint union is behaviourally identical — an *equivalent* mutant: unkillable,
//! reported MISSED. Only that replacement family is excluded; the rest of this
//! file is mutation-gated on its native platform (corrected 2026-09-06, #126).

use crate::error::IoError;
use nix::fcntl::{AtFlags, OFlag};
use nix::sys::stat::{FileStat, Mode as NixMode};
use std::os::fd::{AsFd, OwnedFd};
use std::path::Path;

// Unique implementation names let the mutation gate exclude only code absent
// from the native build. Aliases preserve the callers' platform-neutral API.
#[cfg(target_os = "macos")]
pub(crate) use macos_fd_path as fd_path;
#[cfg(not(target_os = "linux"))]
pub(crate) use portable_probe_openat2 as probe_openat2;
#[cfg(not(any(target_os = "linux", target_os = "macos")))]
pub(crate) use unsupported_fd_path as fd_path;
#[cfg(target_os = "linux")]
pub(crate) use {linux_fd_path as fd_path, linux_probe_openat2 as probe_openat2};

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

// FLAG-DELETION SWEEP — the complete result, both lanes, 2026-08-24.
//
// Mutation cannot isolate a single flag: `&` binds tighter than `|`, so every
// `| with &` mutant drops the TWO ADJACENT operands and is killed by whichever half
// happens to be covered. To know whether an individual flag is HELD, delete it
// and run its behavioral control, in addition to the automatic mutation suite. Three real defects
// were found exactly this way -- row 0's O_DIRECTORY (FIFO hang at startup),
// open_append's O_NOFOLLOW (audit records written outside the anchor), and
// openat2_resolve's O_NONBLOCK (FIFO hang on the fast read lane) -- so the sweep is
// recorded rather than repeated from scratch each time.
//
// Method: substitute `OFlag::empty()` (NOT a regex delete -- an earlier probe matched
// only `| OFlag::X` forms, silently no-opped on multi-line LEADING operands, and scored
// two phantom survivors). The substitution must be asserted to differ from the original.
//
// Every GREEN below is redundant BY CONSTRUCTION, not an untested control:
//
//   O_RDONLY, everywhere            O_RDONLY IS 0 -- `empty()` is the same value, so
//                                   this is a no-op, not a survivor.
//   open_dir_at O_NONBLOCK          O_DIRECTORY makes a FIFO ENOTDIR before any block.
//   open_dir_handle, all five       Historical duplicate union targeting `.`.
//                                   Corrected 2026-09-06 (#126): now reuses
//                                   open_dir_at before Dir::from_fd; its flags
//                                   are held before fdopendir changes the fd.
//   open_temp_excl O_NOFOLLOW,      O_CREAT|O_EXCL means a freshly created regular
//     O_NONBLOCK                    inode -- a planted name is EEXIST, nothing blocks.
//   openat2_resolve O_DIRECTORY     Only the want_dir branch, reached solely by
//     (want_dir arm)                probe_openat2 against `.`.
//   RESOLVE_BENEATH                 `normalize` also refuses an escaping `..`.
//                                   Corrected 2026-09-06 (#126): the raw wrapper
//                                   now has a direct escape control, independently
//                                   holding the kernel's containment guarantee.
//
// Everything else is RED or HANGs, i.e. held. Two are held by HANGING rather than
// failing -- open_read_target's and open_append's O_NONBLOCK -- which is why the FIFO
// tests now use killable, reaped child processes (corrected 2026-09-06, #126).
//
// LANE MATTERS. Lines inside `#[cfg(target_os = "linux")]` are dead code on darwin, so
// a darwin sweep reports them GREEN whatever the truth is. Probed separately on Debian
// 13: openat2_resolve's O_NONBLOCK and O_CLOEXEC and RESOLVE_NO_SYMLINKS are all RED
// there. A darwin-only sweep would have called all of them survivors -- which is the
// mistake that hid the third defect.

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

#[cfg(target_os = "linux")]
use linux_mutation_directory_flags as mutation_directory_flags;
#[cfg(target_os = "macos")]
use macos_mutation_directory_flags as mutation_directory_flags;

// Mutation pins must not require permission to enumerate a directory. nix 0.31's
// typed flags expose Linux O_PATH and Apple's O_SEARCH; the installed Apple SDK
// sys/fcntl.h and open(2) document O_SEARCH as directory search access. Config/read
// anchors keep their O_RDONLY lane. Neither flag proves child mutation permission.
#[cfg(target_os = "linux")]
fn linux_mutation_directory_flags() -> OFlag {
    OFlag::O_PATH | OFlag::O_DIRECTORY | OFlag::O_CLOEXEC
}

#[cfg(target_os = "macos")]
fn macos_mutation_directory_flags() -> OFlag {
    // O_SEARCH already includes O_DIRECTORY on Apple.
    OFlag::O_SEARCH | OFlag::O_CLOEXEC
}

/// Open a subject directory for pathname operations, following its final alias so
/// the kernel-reported path is what the daemon decides. This performs no effect.
pub(crate) fn open_mutation_directory(path: &Path) -> nix::Result<OwnedFd> {
    nix::fcntl::open(path, mutation_directory_flags(), NixMode::empty())
}

/// Mutation descent needs search/path access; only directory enumeration needs read.
pub(crate) fn open_mutation_directory_at<F: AsFd>(fd: &F, leaf: &str) -> nix::Result<OwnedFd> {
    nix::fcntl::openat(
        fd,
        leaf,
        mutation_directory_flags() | OFlag::O_NOFOLLOW,
        NixMode::empty(),
    )
}

/// Open a directory relative to a pinned dirfd, refusing symlinks at this component.
///
/// `O_NONBLOCK` here is redundant BY CONSTRUCTION and deliberately kept: `O_DIRECTORY`
/// turns a FIFO component into ENOTDIR before any blocking open can happen, so deleting
/// `O_NONBLOCK` leaves the suite green. Recorded because "no test holds it" and
/// "nothing needs it" look identical from a flag-deletion sweep, and the difference is
/// the whole point — `open_append`'s `O_NOFOLLOW` looked the same and was load-bearing.
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

/// Open a fresh directory descriptor, then transfer only that descriptor to Dir.
/// The anchor remains borrowed. Reusing open_dir_at also gives enumeration the
/// same atomic O_CLOEXEC acquisition as directory walks, before fdopendir can
/// obscure a missing flag by setting FD_CLOEXEC afterwards.
pub(crate) fn open_dir_handle<F: AsFd>(dirfd: &F) -> nix::Result<nix::dir::Dir> {
    nix::dir::Dir::from_fd(open_dir_at(dirfd, ".")?)
}

/// The crate's ONLY `fstat` call site, and it takes an fd — never a path. The
/// spec:160 build requirement greps for exactly this.
/// The path the KERNEL reports for an open descriptor (ADR-0009 decision 4).
///
/// This is the confinement primitive, and it is deliberately NOT a resolution of
/// any caller-supplied name: it reads the daemon's OWN fd table, so it needs no
/// permission on the object's directories at all. That is what lets a subject's
/// `0700` home be served without granting the daemon `+x` or `+r` on it (#194).
#[cfg(target_os = "linux")]
pub(crate) fn linux_fd_path<F: AsFd>(fd: &F) -> nix::Result<std::path::PathBuf> {
    use std::os::fd::AsRawFd;
    let link = format!("/proc/self/fd/{}", fd.as_fd().as_raw_fd());
    nix::fcntl::readlink(link.as_str()).map(std::path::PathBuf::from)
}

/// The macOS lane: `fcntl(fd, F_GETPATH)`, the platform equivalent of reading
/// `/proc/self/fd`. Same property — it interrogates the process's OWN descriptor table
/// and needs no permission on the object's directories.
///
/// **`F_GETPATH`, deliberately, not `F_GETPATH_NOFIRMLINK`.** On APFS `/Users` is a
/// firmlink to `/System/Volumes/Data/Users`, and the two calls return the two forms.
/// The user-visible form is the one an operator writes in `principal.home` and the one
/// `realpath` reports, so it is the form the confinement prefix-check compares against.
///
/// **If that reasoning is wrong, the failure is fail-closed, not a bypass.** A form
/// mismatch makes `strip_prefix` fail, which is `EscapesAnchor`, which denies — the
/// same outcome macOS has today with no lane at all. A wrong-direction MATCH would
/// need two roots in a prefix relationship across the firmlink boundary, which is a
/// misconfiguration rather than a firmlink artifact.
///
/// Corrected 2026-09-06 (#126): this lane runs on native macOS CI and the
/// operator's Apple Silicon host. The delegated suite exercises F_GETPATH.
#[cfg(target_os = "macos")]
pub(crate) fn macos_fd_path<F: AsFd>(fd: &F) -> nix::Result<std::path::PathBuf> {
    let mut buf = std::path::PathBuf::new();
    nix::fcntl::fcntl(fd.as_fd(), nix::fcntl::FcntlArg::F_GETPATH(&mut buf))?;
    Ok(buf)
}

/// Fail closed on any platform with no lane: the kernel cannot be asked, so the answer
/// is UNKNOWN, and ADR-0009 decision 8 makes unknown deny.
#[cfg(not(any(target_os = "linux", target_os = "macos")))]
pub(crate) fn unsupported_fd_path<F: AsFd>(_fd: &F) -> nix::Result<std::path::PathBuf> {
    Err(nix::errno::Errno::ENOSYS)
}

pub(crate) fn stat_path(path: &Path) -> nix::Result<FileStat> {
    nix::sys::stat::stat(path)
}

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
pub(crate) fn linux_probe_openat2<F: AsFd>(dirfd: &F) -> Result<(), nix::errno::Errno> {
    openat2_resolve(dirfd, ".", true).map(|_| ())
}

#[cfg(not(target_os = "linux"))]
pub(crate) fn portable_probe_openat2<F: AsFd>(_dirfd: &F) -> Result<(), nix::errno::Errno> {
    Err(nix::errno::Errno::ENOSYS)
}

/// Mode A's temp. O_EXCL makes a pre-existing name (regular file OR symlink) EEXIST
/// regardless of O_NOFOLLOW, so O_NOFOLLOW here is redundant-but-harmless rather than
/// a separately observable control.
///
/// `O_NONBLOCK` is redundant here for the same reason and is likewise kept: with
/// `O_CREAT|O_EXCL` the inode is always freshly created and regular, so nothing can
/// block. Both survive deletion green BECAUSE NOTHING NEEDS THEM, not for want of a
/// test — a distinction that matters, since `open_append`'s `O_NOFOLLOW` looked
/// identical from a deletion sweep and was load-bearing.
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

/// Subject open follows aliases so policy decides the kernel-reported target.
/// No create/truncate: preparation must have no effect before durable intent.
pub(crate) fn open_writable_delegation(path: &Path) -> nix::Result<OwnedFd> {
    nix::fcntl::open(
        path,
        OFlag::O_WRONLY | OFlag::O_NONBLOCK | OFlag::O_CLOEXEC,
        NixMode::empty(),
    )
}

/// Inspect the access mode without changing the shared file description's flags.
pub(crate) fn is_nonappend_writable<F: AsFd>(fd: &F) -> nix::Result<bool> {
    let flags = OFlag::from_bits_truncate(nix::fcntl::fcntl(fd, nix::fcntl::FcntlArg::F_GETFL)?);
    let access = flags & OFlag::O_ACCMODE;
    Ok((access == OFlag::O_WRONLY || access == OFlag::O_RDWR) && !flags.contains(OFlag::O_APPEND))
}

pub(crate) fn write_at<F: AsFd>(fd: &F, bytes: &[u8], offset: i64) -> nix::Result<usize> {
    nix::sys::uio::pwrite(fd, bytes, offset)
}

pub(crate) fn truncate_fd<F: AsFd>(fd: &F, length: i64) -> nix::Result<()> {
    nix::unistd::ftruncate(fd, length)
}

pub(crate) fn mkdir_at<F: AsFd>(fd: &F, leaf: &str) -> nix::Result<()> {
    nix::sys::stat::mkdirat(fd, leaf, NixMode::S_IRWXU)
}

pub(crate) fn remove_at<F: AsFd>(fd: &F, leaf: &str, directory: bool) -> nix::Result<()> {
    let flags = if directory {
        nix::unistd::UnlinkatFlags::RemoveDir
    } else {
        nix::unistd::UnlinkatFlags::NoRemoveDir
    };
    nix::unistd::unlinkat(fd, leaf, flags)
}

#[cfg(test)]
mod tests {
    //! Every open verb must set `FD_CLOEXEC`.
    //!
    //! This file composes the flags that ARE the crate's security model. Before
    //! these tests existed, its whole-file mutation exclusion left the flag unions
    //! without an automated control:
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
    fn nofollow_directory_open_refuses_outside_sentinel_parent() {
        let d = tmp();
        let outside = tmp();
        let sentinel = outside.path().join("nofollow-sentinel");
        std::fs::write(&sentinel, b"safe").unwrap();
        std::os::unix::fs::symlink(outside.path(), d.path().join("link")).unwrap();
        let fd = open_parent_by_path(d.path()).unwrap();
        assert!(open_dir_at(&fd, "link").is_err());
        assert!(open_mutation_directory_at(&fd, "link").is_err());
        assert_eq!(std::fs::read(sentinel).unwrap(), b"safe");
    }

    #[test]
    fn mutation_xor_equivalence_requires_disjoint_platform_flag_bits() {
        // This is the executable algebra supporting the narrowly named XOR
        // exemptions; the descriptor tests separately hold actual behavior.
        let mut groups = vec![
            vec![OFlag::O_WRONLY, OFlag::O_NONBLOCK, OFlag::O_CLOEXEC],
            vec![mutation_directory_flags(), OFlag::O_NOFOLLOW],
        ];
        #[cfg(target_os = "macos")]
        groups.push(vec![OFlag::O_SEARCH, OFlag::O_CLOEXEC]);
        #[cfg(target_os = "linux")]
        groups.push(vec![OFlag::O_PATH, OFlag::O_DIRECTORY, OFlag::O_CLOEXEC]);
        for group in groups {
            let mut bits = OFlag::empty();
            for flag in group {
                assert!(
                    !bits.intersects(flag),
                    "XOR exemption requires disjoint flags"
                );
                assert_eq!(bits | flag, bits ^ flag);
                bits |= flag;
            }
        }
    }

    #[test]
    fn mutation_directory_pins_set_cloexec() {
        let d = tmp();
        let fd = open_mutation_directory(d.path()).unwrap();
        assert!(is_cloexec(&fd));
        std::fs::create_dir(d.path().join("child")).unwrap();
        let child = open_mutation_directory_at(&fd, "child").unwrap();
        assert!(is_cloexec(&child));
    }

    #[test]
    fn writable_delegation_open_sets_cloexec_and_never_creates() {
        let d = tmp();
        let p = d.path().join("flags");
        std::fs::write(&p, b"safe").unwrap();
        let fd = open_writable_delegation(&p).unwrap();
        assert!(is_cloexec(&fd));
        assert!(is_nonappend_writable(&fd).unwrap());
        assert!(open_writable_delegation(&d.path().join("absent")).is_err());
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

    /// This checks the converted handle's end state. Acquisition is separately
    /// held by open_dir_at_sets_cloexec, before Dir::from_fd invokes fdopendir.
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

    /// A live socket is writable but cannot be synchronized to storage. These
    /// assertions hold the error contract; they do not claim crash durability.
    #[test]
    fn synchronization_refuses_a_live_socket() {
        let (socket, _peer) = std::os::unix::net::UnixStream::pair().unwrap();
        assert_eq!(fsync_fd(&socket), Err(nix::errno::Errno::EINVAL));
        assert_eq!(sync_data(&socket), Err(nix::errno::Errno::EINVAL));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn openat2_directory_requirement_rejects_a_regular_file() {
        let d = tmp();
        std::fs::write(d.path().join("file"), b"not a directory").unwrap();
        let parent = open_parent_by_path(d.path()).unwrap();
        assert_eq!(
            openat2_resolve(&parent, "file", true).unwrap_err(),
            nix::errno::Errno::ENOTDIR
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn openat2_refuses_escape_without_a_symlink() {
        let d = tmp();
        std::fs::create_dir(d.path().join("anchor")).unwrap();
        std::fs::write(d.path().join("outside"), b"outside sentinel").unwrap();
        let parent = open_parent_by_path(&d.path().join("anchor")).unwrap();
        assert_eq!(
            openat2_resolve(&parent, "../outside", false).unwrap_err(),
            nix::errno::Errno::EXDEV
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn probe_reports_an_unusable_directory_descriptor() {
        let d = tmp();
        let file = std::fs::File::create(d.path().join("file")).unwrap();
        assert_eq!(probe_openat2(&file), Err(nix::errno::Errno::ENOTDIR));
    }

    #[test]
    fn directory_handle_owns_a_new_descriptor_and_preserves_the_anchor() {
        let d = tmp();
        std::fs::write(d.path().join("sentinel"), b"anchor remains usable").unwrap();
        let parent = open_parent_by_path(d.path()).unwrap();
        {
            let directory = open_dir_handle(&parent).unwrap();
            assert_ne!(parent.as_raw_fd(), directory.as_fd().as_raw_fd());
        }
        let fd = open_read_target(&parent, "sentinel").unwrap();
        let mut file = std::fs::File::from(fd);
        let mut bytes = String::new();
        std::io::Read::read_to_string(&mut file, &mut bytes).unwrap();
        assert_eq!(bytes, "anchor remains usable");
    }

    #[test]
    fn directory_handle_refuses_a_regular_file_descriptor() {
        let file = tempfile::tempfile().unwrap();
        assert_eq!(
            open_dir_handle(&file).unwrap_err(),
            nix::errno::Errno::ENOTDIR
        );
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn fd_path_refuses_a_descriptor_without_a_filesystem_path() {
        let (socket, _peer) = std::os::unix::net::UnixStream::pair().unwrap();
        assert_eq!(fd_path(&socket).unwrap_err(), nix::errno::Errno::EBADF);
    }
}
