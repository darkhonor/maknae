//! Length-delimited framing over any AsyncRead+AsyncWrite (spec §3): u32-BE length ∥ CBOR body.
use crate::error::ProtoFrameError;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

pub async fn write_frame<W: AsyncWrite + Unpin>(
    w: &mut W,
    body: &[u8],
) -> Result<(), ProtoFrameError> {
    let len = u32::try_from(body.len()).map_err(|_| ProtoFrameError::Oversize {
        declared: body.len(),
        max: u32::MAX as usize,
    })?;
    w.write_all(&len.to_be_bytes())
        .await
        .map_err(|e| ProtoFrameError::Io(e.to_string()))?;
    w.write_all(body)
        .await
        .map_err(|e| ProtoFrameError::Io(e.to_string()))?;
    w.flush()
        .await
        .map_err(|e| ProtoFrameError::Io(e.to_string()))?;
    Ok(())
}

pub async fn read_frame<R: AsyncRead + Unpin>(
    r: &mut R,
    max: usize,
) -> Result<Vec<u8>, ProtoFrameError> {
    let mut len_buf = [0u8; 4];
    r.read_exact(&mut len_buf)
        .await
        .map_err(|_| ProtoFrameError::Truncated)?;
    let declared = u32::from_be_bytes(len_buf) as usize;
    if declared > max {
        return Err(ProtoFrameError::Oversize { declared, max });
    } // BEFORE allocation
    let mut body = vec![0u8; declared];
    r.read_exact(&mut body)
        .await
        .map_err(|_| ProtoFrameError::Truncated)?;
    Ok(body)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::pin::Pin;
    use std::task::{Context, Poll};
    use std::time::Duration;

    /// Bound an awaited future so a mutant that silently drops I/O (e.g.
    /// `write_frame` becoming a no-op, or the oversize check becoming a
    /// no-op so `read_frame` blocks on bytes that will never arrive) fails
    /// the test promptly instead of hanging until cargo-mutants' own
    /// (much longer) watchdog timeout fires.
    async fn bounded<T>(fut: impl std::future::Future<Output = T>) -> T {
        tokio::time::timeout(Duration::from_secs(2), fut)
            .await
            .expect("operation did not complete within the test bound")
    }

    /// A hand-rolled `AsyncWrite` that fails its Nth `poll_write` call and/or its
    /// `poll_flush` call — the only way to exercise `write_frame`'s `Io` error
    /// branches (a `tokio::io::duplex` half never errors on write/flush).
    struct FailingWriter {
        fail_write_on_call: u32,
        fail_flush: bool,
        calls: u32,
    }
    impl FailingWriter {
        fn fail_write(fail_write_on_call: u32) -> Self {
            FailingWriter {
                fail_write_on_call,
                fail_flush: false,
                calls: 0,
            }
        }
        fn fail_flush() -> Self {
            FailingWriter {
                fail_write_on_call: 0,
                fail_flush: true,
                calls: 0,
            }
        }
    }
    impl AsyncWrite for FailingWriter {
        fn poll_write(
            mut self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            buf: &[u8],
        ) -> Poll<std::io::Result<usize>> {
            self.calls += 1;
            if self.calls == self.fail_write_on_call {
                return Poll::Ready(Err(std::io::Error::other("deliberate test write failure")));
            }
            Poll::Ready(Ok(buf.len()))
        }
        fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
            if self.fail_flush {
                Poll::Ready(Err(std::io::Error::other("deliberate test flush failure")))
            } else {
                Poll::Ready(Ok(()))
            }
        }
        fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
            Poll::Ready(Ok(()))
        }
    }

    #[tokio::test]
    async fn write_frame_surfaces_io_error_on_header_write() {
        let mut w = FailingWriter::fail_write(1); // fails the length-prefix write
        assert!(matches!(
            write_frame(&mut w, b"x").await,
            Err(ProtoFrameError::Io(_))
        ));
    }
    #[tokio::test]
    async fn write_frame_surfaces_io_error_on_body_write() {
        let mut w = FailingWriter::fail_write(2); // header write ok, body write fails
        assert!(matches!(
            write_frame(&mut w, b"x").await,
            Err(ProtoFrameError::Io(_))
        ));
    }
    #[tokio::test]
    async fn write_frame_surfaces_io_error_on_flush() {
        let mut w = FailingWriter::fail_flush();
        assert!(matches!(
            write_frame(&mut w, b"x").await,
            Err(ProtoFrameError::Io(_))
        ));
    }

    #[tokio::test]
    async fn round_trip_frame() {
        let (mut a, mut b) = tokio::io::duplex(4096);
        let payload = b"hello".to_vec();
        bounded(write_frame(&mut a, &payload)).await.unwrap();
        let got = bounded(read_frame(&mut b, 1024)).await.unwrap();
        assert_eq!(got, payload);
    }
    #[tokio::test]
    async fn oversize_fails_before_alloc() {
        // Hand-craft a length prefix of 10 MiB with max 1 KiB.
        let (mut a, mut b) = tokio::io::duplex(64);
        let big: u32 = 10 * 1024 * 1024;
        tokio::io::AsyncWriteExt::write_all(&mut a, &big.to_be_bytes())
            .await
            .unwrap();
        // Close the write half: the correct code path returns Oversize
        // BEFORE ever touching `b` again, so this has no effect there; a
        // mutant that lets the oversize check fall through would otherwise
        // block forever on `read_exact` waiting for body bytes that will
        // never arrive — dropping `a` turns that into a prompt EOF instead.
        drop(a);
        let e = bounded(read_frame(&mut b, 1024)).await.unwrap_err();
        assert!(
            matches!(e, ProtoFrameError::Oversize { declared, max } if declared == big as usize && max == 1024)
        );
    }
    #[tokio::test]
    async fn truncated_length_fails() {
        let (mut a, mut b) = tokio::io::duplex(64);
        tokio::io::AsyncWriteExt::write_all(&mut a, &[0u8, 0u8])
            .await
            .unwrap(); // only 2 of 4 length bytes
        drop(a);
        assert!(matches!(
            read_frame(&mut b, 1024).await,
            Err(ProtoFrameError::Truncated)
        ));
    }
    #[tokio::test]
    async fn truncated_body_fails() {
        let (mut a, mut b) = tokio::io::duplex(64);
        let declared: u32 = 8;
        tokio::io::AsyncWriteExt::write_all(&mut a, &declared.to_be_bytes())
            .await
            .unwrap();
        tokio::io::AsyncWriteExt::write_all(&mut a, &[0u8, 1u8, 2u8])
            .await
            .unwrap(); // only 3 of 8 body bytes
        drop(a);
        assert!(matches!(
            read_frame(&mut b, 1024).await,
            Err(ProtoFrameError::Truncated)
        ));
    }
    #[tokio::test]
    async fn exact_max_succeeds() {
        let (mut a, mut b) = tokio::io::duplex(4096);
        let payload = vec![0xabu8; 1024];
        bounded(write_frame(&mut a, &payload)).await.unwrap();
        let got = bounded(read_frame(&mut b, 1024)).await.unwrap();
        assert_eq!(got, payload);
    }
}
