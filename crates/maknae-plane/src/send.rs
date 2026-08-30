//! Attaching a subject-delegated descriptor to the write that carries its request.
//!
//! The mirror of [`crate::fd`], and the SUBJECT's half of ADR-0009: the client opens
//! the object under its own credentials, so the kernel has already run the whole
//! permission check, and this hands the resulting authority across.
//!
//! **It must sit BENEATH the TLS layer**, for the same reason the collector does:
//! `SCM_RIGHTS` is ancillary data on the raw socket and is not part of any byte
//! stream, so rustls can neither carry it nor see it.
//!
//! **Arming is per REQUEST, not per connection.** The descriptor is attached to the
//! first write that follows, then cleared. That ordering is why arming happens after
//! the handshake: the handshake's own writes would otherwise consume it.
//!
//! Like the collector, this crate contributes no security decision -- the `sendmsg`
//! itself lives in [`maknae_io`], per AGENTS.md's rule that descriptor I/O goes there.

use std::os::fd::{AsFd, OwnedFd};
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};

use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::UnixStream;

/// A handle for arming the descriptor that the next write will carry.
#[derive(Clone)]
pub struct FdArmer(Arc<Mutex<Option<OwnedFd>>>);

impl FdArmer {
    /// Arm `fd` for the next write. Returns any previously armed descriptor, which is
    /// dropped (and closed) by the caller if ignored -- a second arm before a write
    /// means a request was abandoned, and its descriptor must not linger to be
    /// attached to someone else's frame.
    pub fn arm(&self, fd: OwnedFd) -> Option<OwnedFd> {
        self.0.lock().unwrap_or_else(|e| e.into_inner()).replace(fd)
    }
}

/// An `AsyncWrite` over a `UnixStream` that attaches an armed descriptor to the next
/// write. Interposed between the socket and rustls on the client side.
pub struct FdSender {
    inner: UnixStream,
    pending: Arc<Mutex<Option<OwnedFd>>>,
}

impl FdSender {
    pub fn new(inner: UnixStream) -> Self {
        Self {
            inner,
            pending: Arc::new(Mutex::new(None)),
        }
    }

    /// A handle for arming this connection's next write.
    pub fn armer(&self) -> FdArmer {
        FdArmer(Arc::clone(&self.pending))
    }
}

/// One write, attaching the armed descriptor if there is one.
///
/// **The descriptor is taken BEFORE the send and not restored on failure.** A retry
/// that re-attached it could install two descriptors for one request, and the daemon's
/// FIFO take would then hand the orphan to the NEXT request — a subject reading an
/// object it never asked for. Losing the descriptor instead means the request is
/// denied for want of one, which is the fail-closed direction.
fn send_once(
    sock: &UnixStream,
    pending: &Arc<Mutex<Option<OwnedFd>>>,
    buf: &[u8],
) -> std::io::Result<usize> {
    let armed = pending.lock().unwrap_or_else(|e| e.into_inner()).take();
    match armed {
        Some(fd) => maknae_io::send_delegated(sock.as_fd(), buf, fd.as_fd()),
        None => sock.try_write(buf),
    }
}

impl AsyncWrite for FdSender {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        let me = self.get_mut();
        loop {
            std::task::ready!(me.inner.poll_write_ready(cx))?;
            let attempt = me.inner.try_io(tokio::io::Interest::WRITABLE, || {
                send_once(&me.inner, &me.pending, buf)
            });
            match crate::fd::classify(attempt) {
                crate::fd::Step::Done(r) => return Poll::Ready(r),
                crate::fd::Step::Retry => continue,
            }
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_shutdown(cx)
    }
}

impl AsyncRead for FdSender {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_read(cx, buf)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::fd::{AsFd, OwnedFd};
    use std::os::unix::fs::MetadataExt;
    use tokio::io::AsyncWriteExt;

    /// The client's half of ADR-0009. The descriptor must ride the message carrying
    /// the request frame -- not an earlier one and not a later one -- because that is
    /// what makes the daemon's FIFO correlation sound.
    #[tokio::test]
    async fn an_armed_descriptor_rides_the_next_write() {
        let (client, server) = tokio::net::UnixStream::pair().expect("socketpair");
        let f = std::fs::File::open("/etc/hostname").expect("a file to delegate");
        let want = f.metadata().expect("stat").ino();

        let mut sender = FdSender::new(client);
        sender.armer().arm(OwnedFd::from(f));
        sender.write_all(b"FRAME").await.expect("write");
        sender.flush().await.expect("flush");

        let mut buf = [0u8; 64];
        let got = maknae_io::recv_delegated(server.as_fd(), &mut buf).expect("recvmsg");
        assert_eq!(&buf[..got.bytes], b"FRAME");
        assert_eq!(got.fds.len(), 1, "the descriptor rode the frame");
        let received = std::fs::File::from(got.fds.into_iter().next().expect("one fd"));
        assert_eq!(received.metadata().expect("stat").ino(), want);
    }

    /// Arming is per-request, not per-connection: once a descriptor has gone it must
    /// NOT be attached again. Two descriptors for one request would leave the daemon
    /// holding an orphan that its FIFO take would hand to the NEXT request.
    #[tokio::test]
    async fn a_descriptor_is_attached_once_and_only_once() {
        let (client, server) = tokio::net::UnixStream::pair().expect("socketpair");
        let f = std::fs::File::open("/etc/hostname").expect("open");
        let mut sender = FdSender::new(client);
        sender.armer().arm(OwnedFd::from(f));
        sender.write_all(b"AA").await.expect("first write");
        sender.write_all(b"BB").await.expect("second write");
        sender.flush().await.expect("flush");

        let mut buf = [0u8; 64];
        let first = maknae_io::recv_delegated(server.as_fd(), &mut buf).expect("recvmsg");
        assert_eq!(first.fds.len(), 1, "the first write carries it");
        let second = maknae_io::recv_delegated(server.as_fd(), &mut buf).expect("recvmsg");
        assert!(
            second.fds.is_empty(),
            "the second write must carry nothing — a re-attach would orphan a \
             descriptor onto the next request"
        );
    }

    /// TLS is duplex over this adapter, so the read and shutdown halves must work
    /// even though delegation only ever flows outward. Reads are plain passthrough:
    /// a client never RECEIVES a descriptor.
    #[tokio::test]
    async fn the_read_and_shutdown_halves_pass_through() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let (client, mut server) = tokio::net::UnixStream::pair().expect("socketpair");
        let mut sender = FdSender::new(client);
        server.write_all(b"REPLY").await.expect("peer writes");

        let mut buf = [0u8; 5];
        sender
            .read_exact(&mut buf)
            .await
            .expect("read through the adapter");
        assert_eq!(&buf, b"REPLY");

        // Asserted by its EFFECT, not its return value. `shutdown().await.is_ok()`
        // is satisfied by a poll_shutdown that does nothing at all — mutation caught
        // exactly that, replacing the delegation with `Ok(())` and surviving. The peer
        // seeing EOF is the only thing that distinguishes them.
        sender.shutdown().await.expect("shutdown passes through");
        let mut after = [0u8; 1];
        assert_eq!(
            server.read(&mut after).await.expect("peer read"),
            0,
            "the peer must see EOF — a shutdown that returns Ok without shutting down \
             leaves the connection half-open and the daemon waiting"
        );
    }

    /// An un-armed connection writes plainly. Ping and whoami name no object, so they
    /// delegate nothing, and the write path must not manufacture a descriptor.
    #[tokio::test]
    async fn an_unarmed_write_carries_no_descriptor() {
        let (client, server) = tokio::net::UnixStream::pair().expect("socketpair");
        let mut sender = FdSender::new(client);
        sender.write_all(b"PING").await.expect("write");
        sender.flush().await.expect("flush");

        let mut buf = [0u8; 64];
        let got = maknae_io::recv_delegated(server.as_fd(), &mut buf).expect("recvmsg");
        assert_eq!(&buf[..got.bytes], b"PING");
        assert!(got.fds.is_empty(), "nothing armed, nothing attached");
    }
}
