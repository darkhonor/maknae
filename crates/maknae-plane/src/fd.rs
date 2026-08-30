//! Collecting subject-delegated file descriptors from the client-plane socket.
//!
//! **Deliberately thin.** Every security-relevant decision -- the `recvmsg` itself,
//! `CMSG_CLOEXEC`, the per-message descriptor bound, and everything a received
//! descriptor must satisfy -- lives in [`maknae_io`], the crate AGENTS.md makes the
//! single home for file and descriptor I/O. What is here is transport plumbing: call
//! the primitive inside tokio's readiness machinery and hold the results for the
//! request loop.
//!
//! It is here rather than in `maknae-io` because it needs `tokio::net::UnixStream`,
//! and that crate is deliberately synchronous with a minimal dependency surface. It is
//! here rather than in `maknae-kernel` because `RawPlaneConn` deliberately keeps
//! `tokio::net` out of that crate. And it is here rather than in `maknae-vault`
//! because that crate is about talking to the Vault server (operator ruling,
//! 2026-08-30).
//!
//! **It must sit BENEATH the TLS layer.** `SCM_RIGHTS` is ancillary data on the raw
//! socket and is not part of any byte stream, so rustls never sees it -- and tokio's
//! own `poll_read` uses `read(2)`, which destroys attached descriptors with no error
//! at all. Measured on RHEL 10.2: a 5-byte `recv()` closed the descriptor outright
//! while the frame bytes arrived intact. The failure is fail-closed (an absent
//! descriptor is a `Deny`), but it is total and silent.
//!
//! Correlation is FIFO, and that is sound: the kernel does not merge ancillary data
//! across `sendmsg` boundaries, so descriptors arrive in the same order as the frames
//! they accompanied.

use std::os::fd::AsFd;
use std::pin::Pin;
use std::task::{Context, Poll};

use maknae_io::DelegatedFds;
use tokio::io::{AsyncRead, ReadBuf};
use tokio::net::UnixStream;

/// An `AsyncRead` over a `UnixStream` that collects delegated descriptors instead of
/// letting `read(2)` destroy them. Interposed between the socket and rustls.
pub struct FdCollector {
    inner: UnixStream,
    fds: DelegatedFds,
}

impl FdCollector {
    /// Wrap a stream, bounding how many descriptors this connection may hold at once.
    pub fn new(inner: UnixStream, cap: usize) -> Self {
        Self {
            inner,
            fds: DelegatedFds::new(cap),
        }
    }

    /// A handle onto this connection's delegated descriptors.
    pub fn delegated(&self) -> DelegatedFds {
        self.fds.clone()
    }
}

fn recv_once(sock: &UnixStream, fds: &DelegatedFds, buf: &mut ReadBuf<'_>) -> std::io::Result<()> {
    // `initialize_unfilled` rather than `unfilled_mut`: the latter hands out
    // `MaybeUninit` and every way to read into it is `unsafe`, forbidden workspace-wide.
    let got = maknae_io::recv_delegated(sock.as_fd(), buf.initialize_unfilled())?;
    for fd in got.fds {
        fds.push(fd);
    }
    buf.advance(got.bytes);
    Ok(())
}

/// What the read loop does with one attempt's result.
#[derive(Debug)]
pub(crate) enum Step<T> {
    /// Hand this to the caller.
    Done(std::io::Result<T>),
    /// Readiness was spurious -- tokio signalled readable and the socket then said
    /// `EAGAIN`. Wait for readiness again rather than reporting a failure the caller
    /// would have to interpret.
    Retry,
}

/// The read loop's only decision, split out so it can be asserted directly.
///
/// Both `poll_read` here and `poll_write` in [`crate::send`] are thin orchestration
/// over it -- the same shape `run.rs::read_pep` uses over `handler::delegated_plan`.
/// Inlined into either loop this branch is reachable only by racing tokio's readiness
/// against the kernel, which no unit test can do deterministically; separated, all
/// three arms are ordinary inputs, and BOTH directions share one tested decision
/// rather than two copies of it.
pub(crate) fn classify<T>(attempt: std::io::Result<T>) -> Step<T> {
    match attempt {
        Ok(v) => Step::Done(Ok(v)),
        Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => Step::Retry,
        Err(e) => Step::Done(Err(e)),
    }
}

impl tokio::io::AsyncWrite for FdCollector {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        b: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        Pin::new(&mut self.get_mut().inner).poll_write(cx, b)
    }
    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_flush(cx)
    }
    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_shutdown(cx)
    }
}

impl AsyncRead for FdCollector {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        let me = self.get_mut();
        loop {
            std::task::ready!(me.inner.poll_read_ready(cx))?;
            let attempt = me.inner.try_io(tokio::io::Interest::READABLE, || {
                recv_once(&me.inner, &me.fds, buf)
            });
            match classify(attempt) {
                Step::Done(r) => return Poll::Ready(r),
                Step::Retry => continue,
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::IoSlice;
    use std::mem::MaybeUninit;
    use std::os::fd::{AsFd, OwnedFd};
    use std::os::unix::fs::MetadataExt;
    use tokio::io::AsyncReadExt;

    fn send_with_fd(sock: &tokio::net::UnixStream, bytes: &[u8], fd: std::os::fd::BorrowedFd<'_>) {
        let mut space = [MaybeUninit::uninit(); rustix::cmsg_space!(ScmRights(1))];
        let mut anc = rustix::net::SendAncillaryBuffer::new(&mut space);
        let fds = [fd];
        assert!(anc.push(rustix::net::SendAncillaryMessage::ScmRights(&fds)));
        rustix::net::sendmsg(
            sock,
            &[IoSlice::new(bytes)],
            &mut anc,
            rustix::net::SendFlags::empty(),
        )
        .expect("sendmsg");
    }

    fn delegate(sock: &tokio::net::UnixStream, bytes: &[u8], path: &str) -> u64 {
        use std::os::unix::fs::MetadataExt;
        let f = std::fs::File::open(path).expect("a file to delegate");
        let ino = f.metadata().expect("stat").ino();
        send_with_fd(sock, bytes, f.as_fd());
        ino
    }

    /// Received descriptors count against the daemon's `RLIMIT_NOFILE`, so the bound
    /// is a resource control. Over the cap a descriptor is DROPPED -- which closes it
    /// -- and the request that wanted it then finds none and is denied (ADR-0009
    /// decision 2). Fail-closed, never an unbounded queue.
    #[tokio::test]
    async fn descriptors_beyond_the_connection_cap_are_dropped_not_queued() {
        let (client, server) = tokio::net::UnixStream::pair().expect("socketpair");
        delegate(&client, b"AA", "/etc/hostname");
        delegate(&client, b"BB", "/etc/os-release");

        let mut collector = FdCollector::new(server, 1);
        let delegated = collector.delegated();
        let mut buf = [0u8; 4];
        collector.read_exact(&mut buf).await.expect("both frames");

        assert!(delegated.take().is_some(), "the first descriptor is queued");
        assert!(
            delegated.take().is_none(),
            "the second exceeded the cap and must have been dropped, not queued"
        );
    }

    /// ADR-0009 correlation is FIFO, and it is only sound because the kernel does not
    /// merge ancillary data across `sendmsg` boundaries. This asserts the ordering the
    /// request loop relies on to hand each request the descriptor that accompanied it.
    #[tokio::test]
    async fn descriptors_are_taken_in_the_order_their_frames_arrived() {
        let (client, server) = tokio::net::UnixStream::pair().expect("socketpair");
        let first = delegate(&client, b"AA", "/etc/hostname");
        let second = delegate(&client, b"BB", "/etc/os-release");
        assert_ne!(first, second, "the fixture files must be distinguishable");

        let mut collector = FdCollector::new(server, 4);
        let delegated = collector.delegated();
        let mut buf = [0u8; 4];
        collector.read_exact(&mut buf).await.expect("both frames");

        use std::os::unix::fs::MetadataExt;
        let ino = |fd: OwnedFd| std::fs::File::from(fd).metadata().expect("stat").ino();
        assert_eq!(ino(delegated.take().expect("first")), first);
        assert_eq!(ino(delegated.take().expect("second")), second);
    }

    /// TLS sits ON this adapter, so it must be a full duplex stream, not a reader.
    /// Writes carry no ancillary data and are plain passthrough -- delegation is
    /// one-directional, subject to daemon.
    #[tokio::test]
    async fn writes_pass_through_untouched() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let (mut client, server) = tokio::net::UnixStream::pair().expect("socketpair");
        let mut collector = FdCollector::new(server, 4);
        collector.write_all(b"RESPONSE").await.expect("write");
        collector.flush().await.expect("flush");

        let mut buf = [0u8; 8];
        client
            .read_exact(&mut buf)
            .await
            .expect("peer reads what was written");
        assert_eq!(&buf, b"RESPONSE");

        // By EFFECT: a poll_shutdown that returns Ok without shutting down leaves the
        // peer waiting forever. Mutation survives the return-value-only assertion.
        collector.shutdown().await.expect("shutdown passes through");
        let mut after = [0u8; 1];
        assert_eq!(
            client.read(&mut after).await.expect("peer read"),
            0,
            "the peer must see EOF"
        );
    }

    /// The read loop's only branch, asserted directly. A spurious readiness must
    /// RETRY, never surface as an error the caller has to interpret -- and a genuine
    /// error must surface rather than spin the loop forever.
    #[test]
    fn a_spurious_readiness_retries_and_a_real_error_surfaces() {
        use std::io::ErrorKind;
        assert!(matches!(classify(Ok(())), Step::Done(Ok(()))));
        assert!(matches!(
            classify::<()>(Err(std::io::Error::from(ErrorKind::WouldBlock))),
            Step::Retry
        ));
        match classify::<()>(Err(std::io::Error::from(ErrorKind::ConnectionReset))) {
            Step::Done(Err(e)) => assert_eq!(e.kind(), ErrorKind::ConnectionReset),
            other => panic!("a real error must surface, not spin the loop: {other:?}"),
        }
    }

    /// MEASURED on RHEL 10.2 before this was written: tokio's `UnixStream::poll_read`
    /// uses `read(2)`, which DESTROYS attached ancillary data with no error at all --
    /// the bytes arrive intact and the descriptor is simply closed by the kernel. So
    /// this is not a nicety: without the `recvmsg` lane every delegated descriptor is
    /// lost beneath rustls and every read denies (ADR-0009 decision 2).
    #[tokio::test]
    async fn a_descriptor_sent_with_a_frame_survives_the_read_path() {
        let (client, server) = tokio::net::UnixStream::pair().expect("socketpair");
        let f = std::fs::File::open("/etc/hostname").expect("open a file to delegate");
        let want = f.metadata().expect("stat").ino();
        send_with_fd(&client, b"FRAME", f.as_fd());

        let mut collector = FdCollector::new(server, 4);
        let delegated = collector.delegated();

        let mut buf = [0u8; 5];
        collector
            .read_exact(&mut buf)
            .await
            .expect("frame bytes read");
        assert_eq!(&buf, b"FRAME", "the byte stream is unaffected");

        let got = delegated
            .take()
            .expect("the descriptor must SURVIVE the read; read(2) would have destroyed it");
        let got = std::fs::File::from(got).metadata().expect("stat received");
        assert_eq!(
            got.ino(),
            want,
            "the received descriptor names the same object"
        );
    }
}
