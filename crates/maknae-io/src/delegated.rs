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

use std::collections::VecDeque;
use std::mem::MaybeUninit;
use std::os::fd::{AsFd, BorrowedFd, OwnedFd};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

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
    /// What the confinement root itself must satisfy (ADR-0009 decision 7).
    ///
    /// **The anchor REQUIREMENT survives even though the anchor OPEN does not.** A
    /// home any non-principal can write is where aliases get planted, and the
    /// descriptor proves nothing about that — it proves the subject could open the
    /// object, not that the tree it sits in is sound. Enforced by `stat` on the root
    /// PATH, which needs only search on its parent and no permission on the root
    /// itself, which is exactly why a STIG `0700` home stays servable (#194).
    pub root_required: crate::AnchorRequired,
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

/// How many descriptors one message may carry.
///
/// The protocol delegates exactly one per request. The headroom exists so an
/// over-eager peer is *seen* rather than silently truncated: `MSG_CTRUNC` is the only
/// signal that the kernel dropped descriptors it had already installed, and a control
/// buffer sized to exactly one would raise it for an honest client that sent two.
const MAX_DELEGATED_FDS_PER_MESSAGE: usize = 4;

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
}

/// Open an object the caller intends to **delegate** to the trust plane (ADR-0009).
///
/// The first step of the delegation lifecycle, performed by the SUBJECT under its own
/// credentials — which is the whole point: the kernel runs the complete permission
/// check here (DAC bits, POSIX ACLs, supplementary groups, SELinux/AppArmor), and the
/// resulting descriptor IS that answer, carried to a daemon that never has to resolve
/// the name to find the object.
///
/// **It names NO requirements, and that absence is the design rather than an
/// oversight.** Everywhere else in this crate the caller names what it requires and
/// `None` is a named, greppable value. Here the honest requirement is *nothing*:
///
/// - **Symlinks are followed, deliberately.** ADR-0009 decision 6 has the daemon decide
///   on the resolved path, so `~/current -> ~/versions/v3` must work and
///   `~/innocent -> ~/.ssh/id_rsa` must resolve to the object the deny list names.
///   `O_NOFOLLOW` here would break the first and hide the second.
/// - **Object kind, link count and size are the DAEMON's to require.** It applies them
///   to this very descriptor ([`verify_delegated`], [`read_delegated`]). Duplicating
///   them client-side would put policy in an untrusted process and give two places to
///   disagree.
///
/// So the client's job is to open, honestly, as itself — and to send the request even
/// when this fails, so the refusal is DECIDED and audited rather than lost (decision 2).
///
/// Returns `std::io::Result` because the OS's refusal is the meaningful outcome and
/// this function applies no requirement of its own to fail.
pub fn open_for_delegation(path: &std::path::Path) -> std::io::Result<OwnedFd> {
    Ok(OwnedFd::from(std::fs::File::open(path)?))
}

/// Write to a socket, delegating one descriptor alongside the bytes.
///
/// The mirror of [`recv_delegated`], and the SUBJECT's half of ADR-0009: the client
/// has already opened the object under its own credentials, so the kernel has run the
/// whole permission check, and this hands the resulting authority to the daemon.
///
/// **The descriptor rides the message these bytes are in**, which is what makes FIFO
/// correlation sound on the receiving side: the kernel does not merge ancillary data
/// across `sendmsg` boundaries, so a descriptor arrives with the frame it accompanied
/// and not with some later one.
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
    let mut space =
        [MaybeUninit::uninit(); rustix::cmsg_space!(ScmRights(MAX_DELEGATED_FDS_PER_MESSAGE))];
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
    for message in anc.drain() {
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
    Ok(Received {
        bytes: msg.bytes,
        fds,
    })
}

/// Verify a subject-delegated descriptor and read it, in one step.
///
/// **This is what replaces the daemon's own `open` on the read path.** The subject
/// already opened the object, so the kernel has already run the whole permission
/// check for that subject -- DAC bits, POSIX ACLs, supplementary groups,
/// SELinux/AppArmor. The daemon adds confinement (a Maknae control the descriptor
/// says nothing about) and the named target requirements, then reads from the very
/// descriptor it checked. No name is resolved, so no permission on the subject's
/// directories is required at any level, and a STIG `0700` home is servable (#194).
///
/// Returns the KERNEL-REPORTED path alongside the bytes: that is ground truth and
/// what the PDP decides on (ADR-0009 decision 6), never the client-supplied string.
pub fn read_delegated(
    fd: &OwnedFd,
    req: DelegatedRequired,
) -> Result<(PathBuf, crate::Zeroizing<Vec<u8>>), IoError> {
    // Cloned before `req` is consumed: the read re-applies the named requirements to
    // the SAME descriptor immediately before use. Cheap, and it means no window
    // exists between "checked" and "read" for a caller to widen by accident.
    let target = req.target.clone();
    let verified = verify_delegated(fd.as_fd(), req)?;
    let bytes = crate::anchor::read_checked_fd(fd, &verified.path, &target)?;
    Ok((verified.path, bytes))
}

/// Verify a subject-delegated descriptor. Does not consume the fd: the caller
/// still reads from the very descriptor that was checked, so there is no
/// check-then-reopen window.
pub fn verify_delegated(fd: BorrowedFd<'_>, req: DelegatedRequired) -> Result<Delegated, IoError> {
    let path = crate::syscall::fd_path(&fd).map_err(|e| IoError::FdPathUnavailable {
        kind: crate::checks::kind_of_errno(e),
    })?;
    // The confinement root's OWN soundness, before it is used as a boundary: a root
    // that any non-principal can write is not a boundary at all. `stat` by path, not
    // an open — the open is what a `0700` home refuses (ADR-0009 decision 7).
    let root_st = nix::sys::stat::stat(&req.confined_beneath)
        .map_err(|e| crate::checks::map_errno_no_disambiguation(e, &req.confined_beneath))?;
    crate::checks::check_owner_mode(
        &root_st,
        &req.confined_beneath,
        req.root_required.owner,
        req.root_required.mode_mask,
    )?;
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

    /// The diagnostic surface is what an operator reads when a read was refused
    /// and they need to know WHICH object and WHICH root disagreed. A `Debug`
    /// that omitted either would make a denial unreconstructable, which is the
    /// same failure ADR-0019 names for the audit trail.
    #[test]
    fn the_diagnostic_surface_names_the_object_and_the_confinement_root() {
        let req = DelegatedRequired {
            confined_beneath: PathBuf::from("/home/operator"),
            root_required: maknae_io_root_req(),
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
        let base = confinement_root(root.path());
        let confined = base.join("op");
        let sibling = base.join("opx");
        std::fs::create_dir_all(&confined).expect("mkdir op");
        std::fs::create_dir_all(&sibling).expect("mkdir opx");
        let confined = confinement_root(&confined);
        let secret = sibling.join("secret");
        std::fs::write(&secret, b"another subject's file").expect("write");
        let f = std::fs::File::open(&secret).expect("open");

        match verify_delegated(
            f.as_fd(),
            DelegatedRequired {
                confined_beneath: confined,
                root_required: maknae_io_root_req(),
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

        let (tx, rx) = std::os::unix::net::UnixStream::pair().expect("socketpair");
        let f = std::fs::File::open("/etc/hostname").expect("a file to delegate");
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

    /// The whole mechanism end to end: the subject's descriptor is verified and then
    /// READ FROM DIRECTLY. The daemon never resolves the name, so it needs no
    /// permission on the subject's directories -- and the bytes come from the very
    /// inode that was checked, with no reopen in between.
    #[test]
    fn a_delegated_fd_is_verified_then_read_from_directly() {
        let root = tempfile::tempdir().expect("tempdir");
        let home = confinement_root(root.path());
        let notes = home.join("notes.bin");
        let content: &[u8] = &[0x4d, 0x41, 0x4b, 0xff, 0x00, 0x4e]; // non-UTF-8 is legal
        std::fs::write(&notes, content).expect("write");
        let f = std::fs::File::open(&notes).expect("the subject opens it");

        let (path, bytes) = read_delegated(
            &OwnedFd::from(f),
            DelegatedRequired {
                confined_beneath: home,
                root_required: maknae_io_root_req(),
                target: target(),
            },
        )
        .expect("verified and read");
        assert_eq!(path, notes, "the PDP decides on the kernel-reported path");
        assert_eq!(&*bytes, content);
    }

    /// Confinement is enforced BEFORE a single byte is read: an fd outside the root
    /// must never reach the read at all.
    #[test]
    fn an_unconfined_delegated_fd_is_refused_before_any_bytes_are_read() {
        let root = tempfile::tempdir().expect("tempdir");
        let base = confinement_root(root.path());
        let home = base.join("home");
        std::fs::create_dir_all(&home).expect("mkdir");
        let home = confinement_root(&home);
        let outside = base.join("secret");
        std::fs::write(&outside, b"NOT YOURS").expect("write");
        let f = std::fs::File::open(&outside).expect("open");

        match read_delegated(
            &OwnedFd::from(f),
            DelegatedRequired {
                confined_beneath: home,
                root_required: maknae_io_root_req(),
                target: target(),
            },
        ) {
            Err(IoError::EscapesAnchor { .. }) => {}
            other => panic!("an unconfined fd must be refused before the read: {other:?}"),
        }
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

    /// ADR-0009 decision 7, and the removed-behavior obligation ADR-0021 imposes:
    /// dropping the anchor OPEN must not drop the anchor REQUIREMENT. A home any
    /// non-principal can write is where aliases get planted, and the descriptor says
    /// nothing about that -- it proves the subject could open the object, not that
    /// the tree it sits in is sound.
    ///
    /// Re-established by `stat` on the home PATH, which needs only search on its
    /// parent (`/home`, universally `0755`) and NO permission on the home itself --
    /// which is why a `0700` home stays servable (#194).
    #[test]
    fn a_group_writable_confinement_root_is_refused() {
        let root = tempfile::tempdir().expect("tempdir");
        let home = confinement_root(root.path());
        let notes = home.join("notes");
        std::fs::write(&notes, b"planted?").expect("write");
        std::fs::set_permissions(&home, std::fs::Permissions::from_mode(0o770))
            .expect("group-writable home");
        let f = std::fs::File::open(&notes).expect("open");

        let got = verify_delegated(
            f.as_fd(),
            DelegatedRequired {
                confined_beneath: home.clone(),
                root_required: maknae_io_root_req(),
                target: target(),
            },
        );
        std::fs::set_permissions(&home, std::fs::Permissions::from_mode(0o700)).expect("restore");
        match got {
            Err(IoError::InsecurePermissions { path, .. }) => assert_eq!(path, home),
            other => panic!("a group-writable root must be refused: {other:?}"),
        }
    }

    /// A tempdir that is a VALID confinement root **regardless of the host umask**.
    ///
    /// `tempfile` inherits the umask, so on a user-private-group host the directory is
    /// `0775` — group-writable — and `root_required`'s `0o022` mask correctly refuses
    /// it. A fixture that only works under one umask is testing the host, not the code.
    ///
    /// MEASURED 2026-08-30 across the standing test hosts, which is how this was
    /// found: umask `0022` on RHEL 10 and Rocky 9, **`0002` on Debian 13**, `0077` on
    /// the STIG'd el10 box. Eight tests passed locally and failed on Debian. CI runs
    /// `ubuntu-latest`, whose umask is `0022`, so CI would have stayed green while any
    /// Debian/Ubuntu developer hit it on the first run.
    fn confinement_root(dir: &std::path::Path) -> std::path::PathBuf {
        std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700))
            .expect("pin the confinement root's mode against the host umask");
        dir.canonicalize().expect("canonicalize")
    }

    fn maknae_io_root_req() -> crate::AnchorRequired {
        crate::AnchorRequired {
            owner: Some(nix::unistd::geteuid().as_raw()),
            mode_mask: Some(0o022),
        }
    }

    /// The queue's own bound, asserted where the queue lives. Received descriptors
    /// count against the daemon's `RLIMIT_NOFILE`, so this is a resource control: over
    /// the cap a descriptor is DROPPED (and thereby closed), and the request that
    /// wanted it finds none and is denied. Fail-closed, never an unbounded queue.
    #[test]
    fn the_queue_is_bounded_and_hands_back_the_oldest_first() {
        let fds = DelegatedFds::new(2);
        let open = || OwnedFd::from(std::fs::File::open("/etc/hostname").expect("open"));
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

    /// A confinement root that cannot be stat'd is not a boundary, and refusing is the
    /// only safe reading: "the root is missing" must never mean "nothing to confine to".
    #[test]
    fn a_confinement_root_that_cannot_be_stat_is_refused() {
        let root = tempfile::tempdir().expect("tempdir");
        let home = confinement_root(root.path());
        let notes = home.join("notes");
        std::fs::write(&notes, b"x").expect("write");
        let f = std::fs::File::open(&notes).expect("open");

        match verify_delegated(
            f.as_fd(),
            DelegatedRequired {
                confined_beneath: home.join("does-not-exist"),
                root_required: maknae_io_root_req(),
                target: target(),
            },
        ) {
            Err(IoError::Io { kind, .. }) => assert_eq!(kind, crate::IoKind::NotFound),
            other => panic!("an unstattable confinement root must be refused: {other:?}"),
        }
    }

    /// Oversize is enforced at READ time, not decision time -- so it must refuse here,
    /// after verification has already passed. #77 spec D5: a permitted object that
    /// will not fit is a delivery refusal, never truncation.
    #[test]
    fn read_delegated_refuses_an_object_past_the_read_time_budget() {
        let root = tempfile::tempdir().expect("tempdir");
        let home = confinement_root(root.path());
        let big = home.join("big");
        std::fs::write(&big, b"more than four bytes").expect("write");
        let f = std::fs::File::open(&big).expect("open");

        match read_delegated(
            &OwnedFd::from(f),
            DelegatedRequired {
                confined_beneath: home,
                root_required: maknae_io_root_req(),
                target: TargetRequired {
                    max_bytes: Some(4),
                    ..target()
                },
            },
        ) {
            Err(IoError::TargetTooLarge { limit, actual, .. }) => {
                assert_eq!((limit, actual), (4, 20))
            }
            other => panic!("an oversize object must be refused at the read: {other:?}"),
        }
    }

    /// The two primitives are each other's inverse, and asserting them as a ROUND
    /// TRIP is what keeps them so: a send that attached the descriptor to the wrong
    /// message, or a receive that dropped it, fails here rather than in an
    /// integration test that would blame the transport.
    #[test]
    fn a_descriptor_survives_a_round_trip_through_both_primitives() {
        use std::os::unix::fs::MetadataExt;
        let (tx, rx) = std::os::unix::net::UnixStream::pair().expect("socketpair");
        let f = std::fs::File::open("/etc/hostname").expect("a file to delegate");
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
        let received = std::fs::File::from(got.fds.into_iter().next().expect("one fd"));
        assert_eq!(received.metadata().expect("stat").ino(), want);
    }

    /// The SUBJECT's open — the first step of the delegation lifecycle, and the one
    /// that makes the kernel the decider. It is deliberately unconstrained.
    #[test]
    fn open_for_delegation_yields_a_descriptor_for_a_readable_object() {
        use std::os::unix::fs::MetadataExt;
        let root = tempfile::tempdir().expect("tempdir");
        let notes = root.path().join("notes");
        std::fs::write(&notes, b"content").expect("write");
        let want = std::fs::metadata(&notes).expect("stat").ino();

        let fd = open_for_delegation(&notes).expect("the subject can open its own file");
        assert_eq!(
            std::fs::File::from(fd).metadata().expect("stat").ino(),
            want
        );
    }

    /// When the OS refuses the SUBJECT, there is nothing to delegate — and the caller
    /// must still send its request so the refusal is DECIDED and audited rather than
    /// failing silently client-side (ADR-0009 decision 2). This asserts the error is
    /// surfaced rather than swallowed.
    #[test]
    fn open_for_delegation_surfaces_the_os_refusal() {
        if nix::unistd::geteuid().is_root() {
            crate::testutil::skip_or_fail(
                "open_for_delegation_surfaces_the_os_refusal",
                "running as root, which opens a 0000 file and voids the premise",
            );
            return;
        }
        let root = tempfile::tempdir().expect("tempdir");
        let secret = root.path().join("secret");
        std::fs::write(&secret, b"x").expect("write");
        std::fs::set_permissions(&secret, std::fs::Permissions::from_mode(0o000)).expect("chmod");

        let got = open_for_delegation(&secret);
        assert_eq!(
            got.expect_err("a 0000 file must not open").kind(),
            std::io::ErrorKind::PermissionDenied
        );
    }

    /// A delegated fd is honest authority over an OBJECT -- it says nothing about
    /// what KIND of object. A fifo would block the read forever and a device would
    /// stream unboundedly, so the named `regular_file` requirement is enforced on
    /// the descriptor itself (ADR-0009 Consequences).
    #[test]
    fn a_delegated_fd_to_a_non_regular_file_is_refused() {
        let root = tempfile::tempdir().expect("tempdir");
        let home = confinement_root(root.path());
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

        match verify_delegated(
            f.as_fd(),
            DelegatedRequired {
                confined_beneath: home,
                root_required: maknae_io_root_req(),
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
        let home = confinement_root(root.path());
        let real = home.join("notes");
        std::fs::write(&real, b"one object, two names").expect("write");
        std::fs::hard_link(&real, home.join("alias")).expect("hard link");
        let f = std::fs::File::open(&real).expect("open");

        match verify_delegated(
            f.as_fd(),
            DelegatedRequired {
                confined_beneath: home,
                root_required: maknae_io_root_req(),
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
        let home = confinement_root(root.path());
        let big = home.join("big");
        std::fs::write(&big, b"more than four bytes").expect("write");
        let f = std::fs::File::open(&big).expect("open");

        match verify_delegated(
            f.as_fd(),
            DelegatedRequired {
                confined_beneath: home,
                root_required: maknae_io_root_req(),
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
        let home_c = confinement_root(&home);
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
                root_required: maknae_io_root_req(),
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
        let home = confinement_root(&home);
        let secret = elsewhere.join("secret");
        std::fs::write(&secret, b"NOT BENEATH THE HOME").expect("write");

        // Canonical, because the kernel reports the resolved path and a
        // tempdir root may itself sit behind a symlink.
        let secret = secret.canonicalize().expect("canonicalize target");

        let f = std::fs::File::open(&secret).expect("the subject opens its own file");

        let got = verify_delegated(
            f.as_fd(),
            DelegatedRequired {
                confined_beneath: home,
                root_required: maknae_io_root_req(),
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
