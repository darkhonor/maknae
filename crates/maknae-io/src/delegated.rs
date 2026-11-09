//! Verification of a file descriptor delegated by a subject (ADR-0009, ADR-0034).
//!
//! The subject's own open is where the OS answers; nothing here recomputes the mode
//! algebra, which is why `TargetRequired { owner, mode_mask }` stay `None` on this path.
//! Where the object is comes from the daemon's OWN fd table, never by resolving a
//! client-supplied name, which would need traversal permission on a directory that a
//! `0700` home does not grant (#194).

use std::collections::VecDeque;
use std::mem::MaybeUninit;
use std::os::fd::{BorrowedFd, OwnedFd};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use crate::checks::TargetRequired;
use crate::error::IoError;

/// What a caller requires of a delegated descriptor. Callers **name** what they
/// require; `None` is a named, greppable absence, never a silent one.
///
/// There is no confinement root (ADR-0034). The path the kernel reports for the open
/// object is the decided path, and `target.nlink_exactly_one` is what makes deciding
/// on it sound: an object with a second name could be reached under a path no grant
/// or deny names.
#[derive(Debug)]
pub struct DelegatedRequired {
    /// The target checks, applied to this descriptor by `fstat`.
    pub target: TargetRequired,
}

/// What the kernel says about a delegated descriptor.
#[derive(Debug)]
pub struct Delegated {
    /// The path the kernel reports -- **ground truth**, and what the PDP decides
    /// on (ADR-0009 decision 6), never the client-supplied string.
    pub path: PathBuf,
    /// Taken from the same `fstat` the target checks ran on.
    pub meta: DelegatedMeta,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DelegatedMeta {
    pub size: u64,
    pub mtime: SystemTime,
    pub kind: FileKind,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FileKind {
    File,
    Directory,
    Symlink,
    /// A fifo, socket or device.
    Other,
}

impl DelegatedMeta {
    fn of(st: &nix::sys::stat::FileStat) -> Self {
        let kind = match st.st_mode & nix::libc::S_IFMT {
            nix::libc::S_IFREG => FileKind::File,
            nix::libc::S_IFDIR => FileKind::Directory,
            nix::libc::S_IFLNK => FileKind::Symlink,
            _ => FileKind::Other,
        };
        Self {
            size: u64::try_from(st.st_size).unwrap_or(0),
            mtime: mtime(st.st_mtime, st.st_mtime_nsec),
            kind,
        }
    }
}

fn mtime(secs: i64, nsec: i64) -> SystemTime {
    let whole = Duration::from_secs(secs.unsigned_abs());
    let base = if secs < 0 {
        UNIX_EPOCH - whole
    } else {
        UNIX_EPOCH + whole
    };
    base + Duration::from_nanos(u64::try_from(nsec.clamp(0, 999_999_999)).unwrap_or(0))
}

/// How many delegated descriptors one connection may hold at once.
///
/// The protocol delegates exactly one per request and today's CLI is per-invocation,
/// so this is headroom, not a working set. Received descriptors count against the
/// daemon's `RLIMIT_NOFILE`, so it is a resource control: over the cap a descriptor is
/// dropped (and closed), and the request that wanted it is denied for want of one.
pub const DELEGATED_FDS_PER_CONNECTION: usize = 8;

/// The per-connection queue of descriptors the peer delegated.
///
/// Cloning shares the queue: the collector pushes, the request loop takes. Dropping
/// the last handle closes every descriptor still queued -- the close-on-drop the
/// refusal path needs, since the refusal path is the one an attacker controls.
#[derive(Clone)]
pub struct DelegatedFds {
    queue: Arc<Mutex<VecDeque<OwnedFd>>>,
    cap: usize,
}

impl DelegatedFds {
    /// A queue bounded at `cap` descriptors.
    pub fn new(cap: usize) -> Self {
        Self {
            queue: Arc::new(Mutex::new(VecDeque::new())),
            cap,
        }
    }

    /// Take the oldest unconsumed descriptor. `None` means the peer delegated none --
    /// which ADR-0009 decision 2 makes a `Deny`, never a fallback to a daemon-side open.
    pub fn take(&self) -> Option<OwnedFd> {
        self.lock().pop_front()
    }

    /// A poisoned mutex means a panic while holding the queue. Recover the guard
    /// rather than propagating: the descriptors are still valid, and refusing to
    /// serve them would turn one panicked request into a dead connection.
    pub(crate) fn lock(&self) -> std::sync::MutexGuard<'_, VecDeque<OwnedFd>> {
        self.queue.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// Queue a descriptor, or drop it -- closing it -- when the connection is already
    /// at its cap. Dropping is fail-closed: the request that wanted it finds none and
    /// is denied. Received descriptors count against the daemon's `RLIMIT_NOFILE`, so
    /// the bound is a resource control, not a style choice.
    pub fn push(&self, fd: OwnedFd) {
        let mut q = self.lock();
        if q.len() < self.cap {
            q.push_back(fd);
        }
    }
}

/// How many descriptors one message may carry; a message with more is refused and
/// every descriptor it brought is closed.
///
/// The protocol delegates exactly one per request; the rest is headroom. The receive
/// buffer is sized so that whatever the peer sends arrives owned:
///
/// - **Linux** sizes it for this many plus credentials. A larger message raises
///   `MSG_CTRUNC`, and the kernel itself closes the descriptors it did not deliver.
/// - **macOS** installs every descriptor of a truncated message in the receiver and
///   returns only those that fit, so the rest would be open with no owner. The buffer
///   is therefore [`XNU_MAX_CONTROL`], the largest control data XNU accepts on send,
///   so truncation cannot occur and the cap is applied to descriptors already owned.
const MAX_DELEGATED_FDS_PER_MESSAGE: usize = 4;

/// XNU's `sockargs` refuses control data larger than `MCLBYTES`.
#[cfg(not(target_os = "linux"))]
const XNU_MAX_CONTROL: usize = 2048;

/// What one `recvmsg` yielded: stream bytes, plus any descriptors the peer delegated
/// alongside them.
#[derive(Debug)]
pub struct Received {
    /// Bytes read into the caller's buffer.
    pub bytes: usize,
    /// Descriptors the peer delegated with those bytes, owned — so dropping them
    /// closes them, including on the refusal path, which is the path an attacker
    /// controls.
    pub fds: Vec<OwnedFd>,
    /// The sender's credentials, present when the receiving socket has `SO_PASSCRED`
    /// set. Linux only; always `None` elsewhere.
    pub creds: Option<SenderCreds>,
}

/// What the kernel attached to a message as `SCM_CREDENTIALS`.
///
/// When the sender attaches none, these are its thread-group id and real uid and gid.
/// A sender may attach its own; the kernel (`scm_check_creds`) then accepts any of
/// its real, effective or saved uid and gid (any value when the sender holds
/// `CAP_SETUID` / `CAP_SETGID`), and a pid naming any process when the sender holds
/// `CAP_SYS_ADMIN` in its pid namespace, its own tgid otherwise.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SenderCreds {
    pub pid: i32,
    pub uid: u32,
    pub gid: u32,
}

/// The process every read on a connection must come from: the connecting process's
/// pid and its `SO_PEERCRED` uid.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ExpectedSender {
    pub pid: i32,
    pub uid: u32,
}

/// Whether a read of `bytes` with `creds` attached may be taken as the connection's.
/// With no expectation every read is; with one, a read that returned bytes must carry
/// credentials naming that pid and uid. End of stream carries none and needs none.
pub fn sender_admitted(
    expected: Option<ExpectedSender>,
    creds: Option<SenderCreds>,
    bytes: usize,
) -> bool {
    match (expected, creds) {
        (None, _) => true,
        (Some(_), _) if bytes == 0 => true,
        (Some(e), Some(c)) => c.pid == e.pid && c.uid == e.uid,
        (Some(_), None) => false,
    }
}

/// The subject's own open for delegation: location only (Linux `O_PATH`; macOS `O_RDONLY` pending #368).
pub fn open_path_for_delegation(path: &std::path::Path) -> std::io::Result<OwnedFd> {
    crate::syscall::open_path_delegation(path).map_err(Into::into)
}

/// Subject-side directory open. Proves no permission to mutate its children.
pub fn open_directory_for_delegation(path: &std::path::Path) -> std::io::Result<OwnedFd> {
    crate::syscall::open_mutation_directory(path).map_err(Into::into)
}

/// Write to a socket, delegating one descriptor alongside the bytes.
///
/// The mirror of [`recv_delegated`], and the SUBJECT's half of ADR-0009: the client
/// has already opened the object under its own credentials, so the kernel has run the
/// whole permission check, and this hands the resulting authority to the daemon.
///
/// **The descriptor rides the message these bytes are in**, so it arrives with the
/// frame it accompanied and never with a later one — which is what the receiving
/// side's FIFO take relies on.
///
/// On **Linux** that is exact: the kernel does not merge ancillary data across
/// `sendmsg` boundaries. On **macOS** it is weaker — measured on a `macos-26` runner,
/// two writes coalesced into one stream segment carrying both frames' bytes and the
/// single descriptor. The take is still correct for one fd-bearing request per
/// connection (the descriptor never arrives *after* its frame's bytes); pipelining on
/// macOS is not characterised. See ADR-0009.
///
/// Returns how many bytes were accepted. A short write means the caller must send the
/// remainder WITHOUT re-attaching — the descriptor has already been transferred, and
/// sending it twice would install two descriptors for one request.
pub fn send_delegated(
    sock: BorrowedFd<'_>,
    buf: &[u8],
    fd: BorrowedFd<'_>,
) -> std::io::Result<usize> {
    let mut space = [MaybeUninit::uninit(); rustix::cmsg_space!(ScmRights(1))];
    let mut anc = rustix::net::SendAncillaryBuffer::new(&mut space);
    let fds = [fd];
    if !anc.push(rustix::net::SendAncillaryMessage::ScmRights(&fds)) {
        // The buffer is sized for exactly one descriptor by the macro above, so this
        // is unreachable — named rather than unwrapped, because "cannot happen" is how
        // a silent partial send arrives.
        return Err(std::io::Error::other(
            "ancillary buffer rejected the descriptor",
        ));
    }
    Ok(rustix::net::sendmsg(
        sock,
        &[std::io::IoSlice::new(buf)],
        &mut anc,
        rustix::net::SendFlags::empty(),
    )?)
}

/// Read from a socket, collecting any descriptors the peer delegated over `SCM_RIGHTS`.
///
/// **This exists because a plain `read(2)` silently destroys them.** Measured on RHEL
/// 10.2: a 5-byte `recv()` closed the attached descriptor outright while the frame
/// bytes arrived intact, and the following `recvmsg` reported zero ancillary
/// descriptors. There is no error and no signal — so any read path that is not this
/// one loses every delegated descriptor, and (ADR-0009 decision 2) denies every read.
///
/// `CMSG_CLOEXEC` is set so a received descriptor can never leak across an exec.
///
/// Returns `std::io::Result` rather than [`IoError`]: this is a socket operation with
/// no path to name, and its caller is an `AsyncRead` that needs `io::Error` anyway.
/// A `WouldBlock` propagates unchanged so a non-blocking caller can retry.
pub fn recv_delegated(sock: BorrowedFd<'_>, buf: &mut [u8]) -> std::io::Result<Received> {
    #[cfg(target_os = "linux")]
    let mut space = [MaybeUninit::uninit();
        rustix::cmsg_space!(ScmRights(MAX_DELEGATED_FDS_PER_MESSAGE), ScmCredentials(1))];
    #[cfg(not(target_os = "linux"))]
    let mut space =
        [MaybeUninit::uninit(); XNU_MAX_CONTROL + std::mem::align_of::<nix::libc::cmsghdr>()];
    let mut anc = rustix::net::RecvAncillaryBuffer::new(&mut space);
    let mut iov = [std::io::IoSliceMut::new(buf)];
    // `MSG_CMSG_CLOEXEC` is a Linux extension. Where it exists it closes the window
    // entirely — the descriptor is close-on-exec the instant the kernel installs it.
    #[cfg(target_os = "linux")]
    let flags = rustix::net::RecvFlags::CMSG_CLOEXEC;
    #[cfg(not(target_os = "linux"))]
    let flags = rustix::net::RecvFlags::empty();
    let msg = rustix::net::recvmsg(sock, &mut iov, &mut anc, flags)?;
    let mut fds = Vec::new();
    #[cfg_attr(not(target_os = "linux"), allow(unused_mut))]
    let mut creds = None;
    for message in anc.drain() {
        #[cfg(target_os = "linux")]
        if let rustix::net::RecvAncillaryMessage::ScmCredentials(ucred) = message {
            creds = Some(SenderCreds {
                pid: ucred.pid.as_raw_nonzero().get(),
                uid: ucred.uid.as_raw(),
                gid: ucred.gid.as_raw(),
            });
            continue;
        }
        if let rustix::net::RecvAncillaryMessage::ScmRights(received) = message {
            for fd in received {
                // PLATFORM DELTA, stated rather than silently accepted: without
                // `MSG_CMSG_CLOEXEC` a received descriptor arrives WITHOUT
                // close-on-exec, so it is set here instead. The residual is the window
                // between the `recvmsg` above and this `fcntl` — an exec inside it
                // would leak the descriptor to the child. `maknaed` execs nothing on
                // this path, which bounds it, but the window is real and is the reason
                // the Linux flag is preferred where it exists.
                #[cfg(not(target_os = "linux"))]
                nix::fcntl::fcntl(
                    &fd,
                    nix::fcntl::FcntlArg::F_SETFD(nix::fcntl::FdFlag::FD_CLOEXEC),
                )
                .map_err(std::io::Error::from)?;
                fds.push(fd);
            }
        }
    }
    if msg.flags.contains(rustix::net::ReturnFlags::CTRUNC) {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "control data truncated: the peer sent more ancillary data than one message may carry",
        ));
    }
    if fds.len() > MAX_DELEGATED_FDS_PER_MESSAGE {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!(
                "the peer delegated {} descriptors in one message; at most {MAX_DELEGATED_FDS_PER_MESSAGE} are accepted",
                fds.len()
            ),
        ));
    }
    Ok(Received {
        bytes: msg.bytes,
        fds,
        creds,
    })
}

pub fn refuse_access_bearing(fd: BorrowedFd<'_>, path: &std::path::Path) -> Result<(), IoError> {
    if crate::syscall::confers_no_write(&fd)
        .map_err(|e| crate::checks::map_errno_no_disambiguation(e, path))?
    {
        Ok(())
    } else {
        Err(IoError::AccessBearingDescriptor { path: path.into() })
    }
}

pub(crate) fn delegated_path(fd: BorrowedFd<'_>) -> Result<std::path::PathBuf, IoError> {
    crate::syscall::fd_path(&fd).map_err(|e| IoError::FdPathUnavailable {
        kind: crate::checks::kind_of_errno(e),
    })
}

/// Verify a subject-delegated descriptor's location and kind. Does not consume the fd.
pub fn verify_delegated(fd: BorrowedFd<'_>, req: DelegatedRequired) -> Result<Delegated, IoError> {
    let path = delegated_path(fd)?;
    crate::mutation::checked_path(&path)?;
    let st = crate::syscall::fstat(&fd)
        .map_err(|e| crate::checks::map_errno_no_disambiguation(e, &path))?;
    crate::checks::check_target(&st, &path, &req.target)?;
    Ok(Delegated {
        path,
        meta: DelegatedMeta::of(&st),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sender_admitted_decides_every_case() {
        let e = ExpectedSender { pid: 10, uid: 20 };
        let c = |pid, uid| Some(SenderCreds { pid, uid, gid: 0 });
        let rows: [(Option<ExpectedSender>, Option<SenderCreds>, usize, bool); 9] = [
            (None, None, 5, true),
            (None, c(1, 2), 5, true),
            (Some(e), c(10, 20), 5, true),
            (Some(e), c(10, 20), 1, true),
            (Some(e), c(11, 20), 5, false),
            (Some(e), c(10, 21), 5, false),
            (Some(e), c(11, 21), 1, false),
            (Some(e), None, 1, false),
            (Some(e), None, 0, true),
        ];
        for (expected, creds, bytes, want) in rows {
            assert_eq!(
                sender_admitted(expected, creds, bytes),
                want,
                "{expected:?} {creds:?} {bytes}"
            );
        }
        assert!(sender_admitted(Some(e), c(11, 21), 0));
    }
    use crate::{IoError, TargetRequired};
    use std::os::fd::{AsFd, OwnedFd};
    use std::os::unix::fs::PermissionsExt;
    use std::path::PathBuf;

    fn target() -> TargetRequired {
        TargetRequired {
            owner: None,
            mode_mask: None,
            nlink_exactly_one: true,
            regular_file: true,
            max_bytes: Some(4096),
        }
    }

    #[test]
    fn the_diagnostic_surface_names_the_kernel_reported_path() {
        let rendered = format!(
            "{:?}",
            Delegated {
                path: PathBuf::from("/home/operator/notes"),
                meta: DelegatedMeta {
                    size: 0,
                    mtime: std::time::UNIX_EPOCH,
                    kind: FileKind::File,
                },
            }
        );
        assert!(
            rendered.contains("/home/operator/notes"),
            "the outcome must name the kernel-reported path: {rendered}"
        );
    }

    #[test]
    fn a_descriptor_outside_any_home_verifies_with_its_kernel_path() {
        let (_dir, base) = crate::testutil::outside_any_home();
        let body = b"maknae-617-outside-home-sentinel";
        let file = a_file(&base, "notes", body);
        let fd = open_path_for_delegation(&file).expect("delegation open");
        let verified = verify_delegated(fd.as_fd(), DelegatedRequired { target: target() })
            .expect("no confinement root refuses it");
        assert_eq!(verified.path, file);
        assert_eq!(verified.meta.size, body.len() as u64);
        assert_eq!(verified.meta.kind, FileKind::File);
        assert_eq!(
            verified.meta.mtime,
            std::fs::metadata(&file)
                .expect("stat")
                .modified()
                .expect("mtime")
        );
    }

    /// `nlink_exactly_one` makes path matching sound (ADR-0034): a second name is a
    /// path no grant or deny was decided on.
    #[test]
    fn a_multiply_linked_file_is_still_refused() {
        let (_dir, base) = crate::testutil::outside_any_home();
        let real = a_file(&base, "notes", b"one object, two names");
        std::fs::hard_link(&real, base.join("alias")).expect("hard link");
        let fd = open_path_for_delegation(&real).expect("delegation open");
        match verify_delegated(fd.as_fd(), DelegatedRequired { target: target() }) {
            Err(IoError::MultiplyLinked { path, nlink }) => assert_eq!((path, nlink), (real, 2)),
            other => panic!("a multiply-linked object must be refused: {other:?}"),
        }
    }

    #[test]
    fn a_directory_descriptor_reports_its_kind() {
        let (_dir, base) = crate::testutil::outside_any_home();
        let fd = open_directory_for_delegation(&base).expect("directory open");
        let verified = verify_delegated(
            fd.as_fd(),
            DelegatedRequired {
                target: TargetRequired {
                    nlink_exactly_one: false,
                    regular_file: false,
                    max_bytes: None,
                    ..target()
                },
            },
        )
        .expect("a directory verifies when no regular file is required");
        assert_eq!(verified.meta.kind, FileKind::Directory);
    }

    #[test]
    fn mtime_keeps_the_sign_and_the_nanoseconds() {
        use std::time::{Duration, UNIX_EPOCH};
        assert_eq!(mtime(5, 7), UNIX_EPOCH + Duration::new(5, 7));
        assert_eq!(
            mtime(-5, 7),
            UNIX_EPOCH - Duration::from_secs(5) + Duration::from_nanos(7)
        );
        assert_eq!(mtime(0, 0), UNIX_EPOCH);
    }

    /// MEASURED on RHEL 10.2 before this was written: a plain `read(2)` on a socket
    /// DESTROYS attached ancillary data with no error whatsoever -- the bytes arrive
    /// intact and the kernel closes the descriptor. `recvmsg` is therefore not an
    /// optimisation; it is the only way a delegated descriptor reaches the daemon at
    /// all (ADR-0009 decision 1).
    #[test]
    fn a_descriptor_delegated_over_a_socket_is_received_with_its_bytes() {
        use std::io::IoSlice;
        use std::mem::MaybeUninit;
        use std::os::unix::fs::MetadataExt;

        let dir = tempfile::tempdir().expect("tempdir");
        let (tx, rx) = std::os::unix::net::UnixStream::pair().expect("socketpair");
        let f = std::fs::File::open(a_file(dir.path(), "obj", b"delegated")).expect("open");
        let want = f.metadata().expect("stat").ino();

        let mut space = [MaybeUninit::uninit(); rustix::cmsg_space!(ScmRights(1))];
        let mut anc = rustix::net::SendAncillaryBuffer::new(&mut space);
        let fds = [f.as_fd()];
        assert!(anc.push(rustix::net::SendAncillaryMessage::ScmRights(&fds)));
        rustix::net::sendmsg(
            &tx,
            &[IoSlice::new(b"FRAME")],
            &mut anc,
            rustix::net::SendFlags::empty(),
        )
        .expect("sendmsg");

        let mut buf = [0u8; 64];
        let got = recv_delegated(rx.as_fd(), &mut buf).expect("recvmsg");
        assert_eq!(&buf[..got.bytes], b"FRAME", "the byte stream is unaffected");
        assert_eq!(got.fds.len(), 1, "the descriptor must survive the read");
        let received = std::fs::File::from(got.fds.into_iter().next().expect("one fd"));
        assert_eq!(
            received.metadata().expect("stat received").ino(),
            want,
            "the received descriptor names the same object"
        );
    }

    /// The queue recovers from a poisoned mutex rather than propagating, and `lock`'s
    /// doc claims exactly that. A panic in one request must not take a whole
    /// connection's descriptors down with it -- they are still valid handles.
    #[test]
    fn a_panic_while_holding_the_queue_does_not_disable_it() {
        let fds = DelegatedFds::new(4);
        let poisoner = fds.clone();
        let joined = std::thread::spawn(move || {
            let _held = poisoner.lock();
            panic!("a request panicked while holding the queue");
        })
        .join();
        assert!(joined.is_err(), "the helper must actually have panicked");
        assert!(
            fds.take().is_none(),
            "a poisoned queue still answers; it must not propagate the panic"
        );
    }

    /// Pins a fixture directory's mode against the host umask, which differs across
    /// the test hosts (`0002` on Debian, `0077` on a STIG'd host).
    fn pinned(dir: &std::path::Path) -> std::path::PathBuf {
        std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700))
            .expect("pin the fixture's mode against the host umask");
        dir.canonicalize().expect("canonicalize")
    }

    /// A real file to delegate, CREATED rather than borrowed from the host.
    ///
    /// This was `/etc/hostname`, which does not exist on macOS — caught by the
    /// darwin-native CI job on its first run, after the whole delegated suite had
    /// been green on three Linux distributions. A fixture that depends on a system
    /// file is testing the distribution, not the code.
    fn a_file(dir: &std::path::Path, name: &str, body: &[u8]) -> std::path::PathBuf {
        let p = dir.join(name);
        std::fs::write(&p, body).expect("write fixture");
        p
    }

    /// The queue's own bound, asserted where the queue lives. Received descriptors
    /// count against the daemon's `RLIMIT_NOFILE`, so this is a resource control: over
    /// the cap a descriptor is DROPPED (and thereby closed), and the request that
    /// wanted it finds none and is denied. Fail-closed, never an unbounded queue.
    #[test]
    fn the_queue_is_bounded_and_hands_back_the_oldest_first() {
        let dir = tempfile::tempdir().expect("tempdir");
        let obj = a_file(dir.path(), "obj", b"queued");
        let fds = DelegatedFds::new(2);
        let open = || OwnedFd::from(std::fs::File::open(&obj).expect("open"));
        for _ in 0..4 {
            fds.push(open());
        }
        assert!(fds.take().is_some());
        assert!(fds.take().is_some());
        assert!(
            fds.take().is_none(),
            "everything past the cap must have been dropped, not queued"
        );
    }

    /// The two primitives are each other's inverse, and asserting them as a ROUND
    /// TRIP is what keeps them so: a send that attached the descriptor to the wrong
    /// message, or a receive that dropped it, fails here rather than in an
    /// integration test that would blame the transport.
    #[test]
    fn a_descriptor_survives_a_round_trip_through_both_primitives() {
        use std::os::unix::fs::MetadataExt;
        let dir = tempfile::tempdir().expect("tempdir");
        let (tx, rx) = std::os::unix::net::UnixStream::pair().expect("socketpair");
        let f = std::fs::File::open(a_file(dir.path(), "obj", b"delegated")).expect("open");
        let want = f.metadata().expect("stat").ino();

        let sent = send_delegated(tx.as_fd(), b"FRAME", f.as_fd()).expect("sendmsg");
        assert_eq!(
            sent, 5,
            "the whole frame went in one message with the descriptor"
        );

        let mut buf = [0u8; 64];
        let got = recv_delegated(rx.as_fd(), &mut buf).expect("recvmsg");
        assert_eq!(&buf[..got.bytes], b"FRAME");
        assert_eq!(got.fds.len(), 1);
        let flags = nix::fcntl::fcntl(&got.fds[0], nix::fcntl::FcntlArg::F_GETFD)
            .expect("inspect the received descriptor before any wrapper can change its flags");
        assert!(
            nix::fcntl::FdFlag::from_bits_truncate(flags).contains(nix::fcntl::FdFlag::FD_CLOEXEC),
            "delegated authority must not leak across exec"
        );
        let received = std::fs::File::from(got.fds.into_iter().next().expect("one fd"));
        assert_eq!(received.metadata().expect("stat").ino(), want);
    }

    /// A full nonblocking socket must report its OS error without transferring the
    /// descriptor. Claiming success would lose the request; transferring on failure
    /// would duplicate its authority when the caller retries.
    #[test]
    fn a_backpressured_send_can_retry_without_losing_or_duplicating_the_descriptor() {
        use std::io::Write;
        use std::os::unix::fs::MetadataExt;

        let dir = tempfile::tempdir().expect("tempdir");
        let file = std::fs::File::open(a_file(dir.path(), "obj", b"retry sentinel")).expect("open");
        let (mut tx, rx) = std::os::unix::net::UnixStream::pair().expect("socketpair");
        tx.set_nonblocking(true).expect("nonblocking sender");
        rx.set_nonblocking(true).expect("nonblocking receiver");
        let mut queued = 0;
        loop {
            match tx.write(&[0x5a; 4096]) {
                Ok(0) => panic!("socket made no progress"),
                Ok(n) => queued += n,
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => break,
                Err(e) => panic!("fill socket: {e}"),
            }
            assert!(
                queued < 16 * 1024 * 1024,
                "socket never reached backpressure"
            );
        }
        assert!(
            queued > 0,
            "premise: the socket accepted data before filling"
        );
        let blocked = send_delegated(tx.as_fd(), b"FRAME", file.as_fd())
            .expect_err("a full socket must not claim it sent the frame");
        // Darwin reports EMSGSIZE for ancillary data on a full Unix socket,
        // even though the plain write that filled it reported WouldBlock.
        #[cfg(target_os = "macos")]
        assert_eq!(
            blocked.raw_os_error(),
            Some(nix::errno::Errno::EMSGSIZE as i32)
        );
        #[cfg(not(target_os = "macos"))]
        assert_eq!(
            blocked.kind(),
            std::io::ErrorKind::WouldBlock,
            "{blocked:?}"
        );

        let mut buf = [0; 4096];
        let mut drained = 0;
        while drained < queued {
            let got = recv_delegated(rx.as_fd(), &mut buf).expect("drain queued bytes");
            assert!(got.bytes > 0, "peer must remain connected");
            assert!(
                got.fds.is_empty(),
                "failed send must not transfer authority"
            );
            assert!(buf[..got.bytes].iter().all(|b| *b == 0x5a));
            drained += got.bytes;
        }
        assert_eq!(drained, queued);
        assert_eq!(
            recv_delegated(rx.as_fd(), &mut buf)
                .expect_err("failed send must leave no extra frame or descriptor queued")
                .kind(),
            std::io::ErrorKind::WouldBlock
        );
        assert_eq!(
            send_delegated(tx.as_fd(), b"FRAME", file.as_fd()).expect("retry after draining"),
            5
        );
        let got = recv_delegated(rx.as_fd(), &mut buf).expect("receive the retry");
        assert_eq!(&buf[..got.bytes], b"FRAME");
        assert_eq!(
            got.fds.len(),
            1,
            "retry must transfer exactly one descriptor"
        );
        let received = std::fs::File::from(got.fds.into_iter().next().expect("one fd"));
        assert_eq!(
            received.metadata().expect("received inode").ino(),
            file.metadata().expect("sent inode").ino()
        );
        assert_eq!(
            recv_delegated(rx.as_fd(), &mut buf)
                .expect_err("retry must leave no duplicate frame or descriptor queued")
                .kind(),
            std::io::ErrorKind::WouldBlock
        );
    }

    #[test]
    fn open_path_for_delegation_does_not_block_on_a_writerless_fifo() {
        let root = tempfile::tempdir().expect("tempdir");
        let pipe = root.path().join("waiting");
        nix::unistd::mkfifo(
            &pipe,
            nix::sys::stat::Mode::S_IRUSR | nix::sys::stat::Mode::S_IWUSR,
        )
        .expect("mkfifo");
        let (tx, rx) = std::sync::mpsc::channel();
        let probe = pipe.clone();
        std::thread::spawn(move || {
            let _ = tx.send(open_path_for_delegation(&probe).map(|_| ()));
        });
        assert!(rx.recv_timeout(std::time::Duration::from_secs(2)).is_ok());
    }

    #[test]
    fn a_no_access_descriptor_is_enough_to_verify_location_and_kind() {
        let root = tempfile::tempdir().expect("tempdir");
        let home = pinned(root.path());
        let p = home.join("held");
        std::fs::write(&p, b"x").expect("write");
        let fd = open_path_for_delegation(&p).expect("no-access open");
        let verified = verify_delegated(
            fd.as_fd(),
            DelegatedRequired {
                target: TargetRequired {
                    max_bytes: None,
                    ..target()
                },
            },
        )
        .expect("location and kind verify through a no-access descriptor");
        assert_eq!(verified.path, p);
    }

    /// A delegated fd is honest authority over an OBJECT -- it says nothing about
    /// what KIND of object. A fifo would block the read forever and a device would
    /// stream unboundedly, so the named `regular_file` requirement is enforced on
    /// the descriptor itself (ADR-0009 Consequences).
    #[test]
    fn a_delegated_fd_to_a_non_regular_file_is_refused() {
        let root = tempfile::tempdir().expect("tempdir");
        let home = pinned(root.path());
        let pipe = home.join("pipe");
        nix::unistd::mkfifo(
            &pipe,
            nix::sys::stat::Mode::S_IRUSR | nix::sys::stat::Mode::S_IWUSR,
        )
        .expect("mkfifo");
        // O_NONBLOCK: a reader on a writerless fifo blocks forever otherwise --
        // which is precisely the denial-of-service this requirement refuses.
        let f = nix::fcntl::open(
            &pipe,
            nix::fcntl::OFlag::O_RDONLY | nix::fcntl::OFlag::O_NONBLOCK,
            nix::sys::stat::Mode::empty(),
        )
        .expect("open fifo");

        match verify_delegated(f.as_fd(), DelegatedRequired { target: target() }) {
            Err(IoError::NotRegularFile { path }) => assert_eq!(path, pipe),
            other => panic!("a fifo must be refused: {other:?}"),
        }
    }

    /// The frame budget is a named bound, refused BEFORE any buffer is allocated:
    /// a permitted 20 GiB file must not OOM the reader.
    #[test]
    fn a_delegated_fd_over_the_named_budget_is_refused() {
        let root = tempfile::tempdir().expect("tempdir");
        let home = pinned(root.path());
        let big = home.join("big");
        std::fs::write(&big, b"more than four bytes").expect("write");
        let f = std::fs::File::open(&big).expect("open");

        match verify_delegated(
            f.as_fd(),
            DelegatedRequired {
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

    /// The ENVIRONMENT PROPERTY the decided path rests on, measured
    /// rather than assumed: the kernel-reported path is read from the daemon's OWN
    /// fd table, so it survives a directory that grants the reader nothing at all.
    ///
    /// This is the STIG `0700`-home case (#194) reduced to its essence. Sabotage
    /// `syscall::fd_path` into ANY name-resolving form and this goes red with
    /// EACCES -- which is the whole reason ADR-0009 decision 4 exists.
    #[test]
    fn the_kernel_reported_path_survives_a_directory_the_reader_cannot_traverse() {
        crate::testutil::unprivileged(
            "delegated::tests::the_kernel_reported_path_survives_a_directory_the_reader_cannot_traverse",
            || {
        let root = tempfile::tempdir().expect("tempdir");
        let home = root.path().join("home");
        std::fs::create_dir_all(&home).expect("mkdir home");
        let secret = home.join("notes");
        std::fs::write(&secret, b"beneath the home").expect("write");
        pinned(&home);
        let secret_c = secret.canonicalize().expect("canonicalize target");

        let f = std::fs::File::open(&secret).expect("the subject opens it while it still can");

        // 0000: no read, no search, for ANYONE -- stricter than a STIG 0700 home
        // is to a non-owner, so it subsumes the case we actually care about.
        std::fs::set_permissions(&home, std::fs::Permissions::from_mode(0o000)).expect("lock");
        let name_reach = std::fs::metadata(&secret).is_err();
        let got = verify_delegated(
            f.as_fd(),
            DelegatedRequired {
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
            got.expect("the fd table needs NO permission on the object's directory")
                .path,
            secret_c,
        );
            },
        );
    }

    #[test]
    fn only_a_location_descriptor_is_accepted_as_object_evidence() {
        let d = tempfile::tempdir().expect("tempdir");
        let p = d.path().join("held");
        std::fs::write(&p, b"safe").expect("write");
        let held = open_path_for_delegation(&p).expect("no-access open");
        assert_eq!(refuse_access_bearing(held.as_fd(), &p), Ok(()));
        for (read, write) in [(false, true), (true, true)] {
            let fd: OwnedFd = std::fs::OpenOptions::new()
                .read(read)
                .write(write)
                .open(&p)
                .expect("writable open")
                .into();
            assert_eq!(
                refuse_access_bearing(fd.as_fd(), &p),
                Err(IoError::AccessBearingDescriptor { path: p.clone() })
            );
        }
        #[cfg(target_os = "linux")]
        {
            let readable: OwnedFd = std::fs::File::open(&p).expect("readable open").into();
            assert_eq!(
                refuse_access_bearing(readable.as_fd(), &p),
                Err(IoError::AccessBearingDescriptor { path: p.clone() })
            );
        }
        assert_eq!(std::fs::read(&p).expect("read"), b"safe");
    }

    fn send_fds(tx: BorrowedFd<'_>, fds: &[BorrowedFd<'_>]) {
        let mut space = [MaybeUninit::uninit(); rustix::cmsg_space!(ScmRights(32))];
        let mut anc = rustix::net::SendAncillaryBuffer::new(&mut space);
        assert!(anc.push(rustix::net::SendAncillaryMessage::ScmRights(fds)));
        rustix::net::sendmsg(
            tx,
            &[std::io::IoSlice::new(b"FRAME")],
            &mut anc,
            rustix::net::SendFlags::empty(),
        )
        .expect("sendmsg");
    }

    fn descriptors_open_on(obj: &std::path::Path) -> usize {
        use std::os::unix::fs::MetadataExt;
        let want = std::fs::metadata(obj).expect("stat obj");
        std::fs::read_dir("/dev/fd")
            .expect("list /dev/fd")
            .filter_map(|e| std::fs::File::open(e.ok()?.path()).ok()?.metadata().ok())
            .filter(|m| m.dev() == want.dev() && m.ino() == want.ino())
            .count()
    }

    fn over_send(count: usize) -> (std::io::Error, usize) {
        let dir = tempfile::tempdir().expect("tempdir");
        let obj = a_file(dir.path(), "obj", b"x");
        let (tx, rx) = std::os::unix::net::UnixStream::pair().expect("socketpair");
        #[cfg(target_os = "linux")]
        rustix::net::sockopt::set_socket_passcred(&rx, true).expect("passcred");
        let files: Vec<std::fs::File> = (0..count)
            .map(|_| std::fs::File::open(&obj).expect("open"))
            .collect();
        let fds: Vec<BorrowedFd<'_>> = files.iter().map(|f| f.as_fd()).collect();
        send_fds(tx.as_fd(), &fds);
        assert_eq!(
            descriptors_open_on(&obj),
            count,
            "premise: the count sees them"
        );
        drop(fds);
        drop(files);

        let mut buf = [0u8; 64];
        let err = recv_delegated(rx.as_fd(), &mut buf)
            .expect_err("a message carrying more descriptors than the cap must be refused");
        (err, descriptors_open_on(&obj))
    }

    #[test]
    fn an_over_send_is_refused_and_leaves_no_descriptor_open() {
        for count in [
            4 * MAX_DELEGATED_FDS_PER_MESSAGE + 1,
            MAX_DELEGATED_FDS_PER_MESSAGE + 1,
        ] {
            let (err, open) = over_send(count);
            assert_eq!(
                err.kind(),
                std::io::ErrorKind::InvalidData,
                "{count}: {err:?}"
            );
            assert_eq!(open, 0, "{count}: every received descriptor must be closed");
        }
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn control_truncation_is_refused() {
        let (err, open) = over_send(4 * MAX_DELEGATED_FDS_PER_MESSAGE + 1);
        assert!(err.to_string().contains("truncat"), "{err}");
        assert_eq!(open, 0);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn a_descriptor_and_credentials_arrive_together() {
        let dir = tempfile::tempdir().expect("tempdir");
        let obj = a_file(dir.path(), "obj", b"x");
        let (tx, rx) = std::os::unix::net::UnixStream::pair().expect("socketpair");
        rustix::net::sockopt::set_socket_passcred(&rx, true).expect("passcred");
        let f = std::fs::File::open(&obj).expect("open");
        send_fds(tx.as_fd(), &[f.as_fd()]);
        let mut buf = [0u8; 64];
        let got = recv_delegated(rx.as_fd(), &mut buf).expect("recvmsg");
        assert_eq!(got.fds.len(), 1);
        assert_eq!(got.creds, Some(own_creds()));
    }

    #[cfg(target_os = "linux")]
    fn own_creds() -> SenderCreds {
        SenderCreds {
            pid: std::process::id() as i32,
            uid: nix::unistd::getuid().as_raw(),
            gid: nix::unistd::getgid().as_raw(),
        }
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn credentials_arrive_when_the_receiver_passes_creds() {
        use std::io::Write;
        let (mut tx, rx) = std::os::unix::net::UnixStream::pair().expect("socketpair");
        rustix::net::sockopt::set_socket_passcred(&rx, true).expect("passcred");
        tx.write_all(b"abc").expect("write");
        let mut buf = [0u8; 64];
        let got = recv_delegated(rx.as_fd(), &mut buf).expect("recvmsg");
        assert_eq!(got.bytes, 3);
        assert_eq!(got.creds, Some(own_creds()));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn no_credentials_without_passcred() {
        use std::io::Write;
        let (mut tx, rx) = std::os::unix::net::UnixStream::pair().expect("socketpair");
        tx.write_all(b"abc").expect("write");
        let mut buf = [0u8; 64];
        let got = recv_delegated(rx.as_fd(), &mut buf).expect("recvmsg");
        assert_eq!(got.bytes, 3);
        assert_eq!(got.creds, None);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn credentials_survive_a_write_before_accept() {
        use std::io::Write;
        let dir = tempfile::tempdir().expect("tempdir");
        let sock = dir.path().join("s");
        let listener = std::os::unix::net::UnixListener::bind(&sock).expect("bind");
        rustix::net::sockopt::set_socket_passcred(&listener, true).expect("passcred");
        let mut tx = std::os::unix::net::UnixStream::connect(&sock).expect("connect");
        tx.write_all(b"abc").expect("write");
        let (rx, _) = listener.accept().expect("accept");
        let mut buf = [0u8; 64];
        let got = recv_delegated(rx.as_fd(), &mut buf).expect("recvmsg");
        assert_eq!(got.bytes, 3);
        assert_eq!(got.creds, Some(own_creds()));
    }
}
