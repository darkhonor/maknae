//! Length-delimited framing over any AsyncRead+AsyncWrite (spec §3): u32-BE length ∥ CBOR body.
use crate::error::ProtoFrameError;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum FrameClass {
    Control = 1,
    Attempt = 2,
    Prompt = 3,
}

impl TryFrom<u8> for FrameClass {
    type Error = ProtoFrameError;
    fn try_from(b: u8) -> Result<Self, Self::Error> {
        match b {
            1 => Ok(FrameClass::Control),
            2 => Ok(FrameClass::Attempt),
            3 => Ok(FrameClass::Prompt),
            other => Err(ProtoFrameError::UnknownClass(other)),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FrameCaps {
    pub control: usize,
    pub attempt: usize,
    pub prompt: usize,
}

impl FrameCaps {
    pub fn cap(&self, class: FrameClass) -> usize {
        match class {
            FrameClass::Control => self.control,
            FrameClass::Attempt => self.attempt,
            FrameClass::Prompt => self.prompt,
        }
    }
}

pub const CONTROL_REQUEST_MAX: usize = 1024;
pub const CONTROL_RESPONSE_MAX: usize = 65536;
pub const ATTEMPT_REQUEST_MAX: usize = 65536;
pub const ATTEMPT_RESPONSE_MAX: usize =
    crate::mutation::MAX_MUTATION_DEPTH as usize * crate::mutation::MAX_MUTATION_PATH_BYTES;

fn frame_len(body: &[u8]) -> Result<u32, ProtoFrameError> {
    u32::try_from(body.len()).map_err(|_| ProtoFrameError::Oversize {
        declared: body.len(),
        max: u32::MAX as usize,
    })
}

pub async fn write_classed_frame<W: AsyncWrite + Unpin>(
    w: &mut W,
    class: FrameClass,
    body: &[u8],
) -> Result<(), ProtoFrameError> {
    let mut header = [0u8; 5];
    header[..4].copy_from_slice(&frame_len(body)?.to_be_bytes());
    header[4] = class as u8;
    w.write_all(&header)
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

pub async fn read_classed_frame_zeroizing<R: AsyncRead + Unpin>(
    r: &mut R,
    caps: &FrameCaps,
) -> Result<(FrameClass, zeroize::Zeroizing<Vec<u8>>), ProtoFrameError> {
    let mut header = [0u8; 5];
    r.read_exact(&mut header)
        .await
        .map_err(|_| ProtoFrameError::Truncated)?;
    let class = FrameClass::try_from(header[4])?;
    let declared = u32::from_be_bytes([header[0], header[1], header[2], header[3]]) as usize;
    let max = caps.cap(class);
    if declared > max {
        return Err(ProtoFrameError::Oversize { declared, max });
    }
    let mut body = zeroize::Zeroizing::new(vec![0u8; declared]);
    r.read_exact(&mut body)
        .await
        .map_err(|_| ProtoFrameError::Truncated)?;
    Ok((class, body))
}

pub async fn write_frame<W: AsyncWrite + Unpin>(
    w: &mut W,
    body: &[u8],
) -> Result<(), ProtoFrameError> {
    let len = frame_len(body)?;
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
    read_frame_zeroizing(r, max)
        .await
        .map(|mut body| std::mem::take(&mut *body))
}

/// Keep incoming content zeroizing even when the read errors or its future is
/// dropped mid-frame. The length is checked before allocating the body.
pub async fn read_frame_zeroizing<R: AsyncRead + Unpin>(
    r: &mut R,
    max: usize,
) -> Result<zeroize::Zeroizing<Vec<u8>>, ProtoFrameError> {
    let mut len_buf = [0u8; 4];
    r.read_exact(&mut len_buf)
        .await
        .map_err(|_| ProtoFrameError::Truncated)?;
    let declared = u32::from_be_bytes(len_buf) as usize;
    if declared > max {
        return Err(ProtoFrameError::Oversize { declared, max });
    } // BEFORE allocation
    let mut body = zeroize::Zeroizing::new(vec![0u8; declared]);
    r.read_exact(&mut body)
        .await
        .map_err(|_| ProtoFrameError::Truncated)?;
    Ok(body)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[tokio::test]
    async fn secret_frames_are_bounded_and_zeroizing_from_allocation() {
        let mut bytes = &b"\0\0\0\x03\x00\xff\x17"[..];
        let body: zeroize::Zeroizing<Vec<u8>> = read_frame_zeroizing(&mut bytes, 3).await.unwrap();
        assert_eq!(&*body, &[0, 255, 23]);
        assert!(matches!(
            read_frame_zeroizing(&mut &b"\0\0\0\x03"[..], 2).await,
            Err(ProtoFrameError::Oversize {
                declared: 3,
                max: 2
            })
        ));
        assert!(matches!(
            read_frame_zeroizing(&mut &b"\0\0\0\x03x"[..], 3).await,
            Err(ProtoFrameError::Truncated)
        ));
    }
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

    fn caps(control: usize) -> FrameCaps {
        FrameCaps {
            control,
            attempt: 65536,
            prompt: 1 << 20,
        }
    }

    #[tokio::test]
    async fn a_classed_frame_round_trips() {
        let mut buf = Vec::new();
        write_classed_frame(&mut buf, FrameClass::Attempt, b"abc")
            .await
            .unwrap();
        assert_eq!(&buf[..5], &[0, 0, 0, 3, 2]);
        let (class, body) = read_classed_frame_zeroizing(&mut &buf[..], &caps(1024))
            .await
            .unwrap();
        assert_eq!((class, &body[..]), (FrameClass::Attempt, &b"abc"[..]));
    }

    #[tokio::test]
    async fn over_its_class_cap_is_refused_before_the_body_is_read() {
        let mut bytes: &[u8] = &[0, 0, 0, 5, 1, b'x'];
        assert_eq!(
            read_classed_frame_zeroizing(&mut bytes, &caps(4))
                .await
                .unwrap_err(),
            ProtoFrameError::Oversize {
                declared: 5,
                max: 4
            }
        );
        assert_eq!(bytes, b"x");
    }

    #[tokio::test]
    async fn an_unknown_class_byte_is_refused_before_the_body_is_read() {
        for bad in [0u8, 4, 255] {
            let frame = [0, 0, 0, 1, bad, b'x'];
            let mut bytes: &[u8] = &frame;
            assert_eq!(
                read_classed_frame_zeroizing(&mut bytes, &caps(1024))
                    .await
                    .unwrap_err(),
                ProtoFrameError::UnknownClass(bad)
            );
            assert_eq!(bytes, b"x");
        }
    }

    #[test]
    fn the_fixed_caps_by_value() {
        assert_eq!(
            (
                CONTROL_REQUEST_MAX,
                CONTROL_RESPONSE_MAX,
                ATTEMPT_REQUEST_MAX
            ),
            (1024, 65536, 65536)
        );
    }

    #[tokio::test]
    async fn a_classed_write_surfaces_io_errors() {
        let mut w = FailingWriter::fail_write(1);
        assert!(matches!(
            write_classed_frame(&mut w, FrameClass::Control, b"x").await,
            Err(ProtoFrameError::Io(_))
        ));
        let mut w = FailingWriter::fail_write(2);
        assert!(matches!(
            write_classed_frame(&mut w, FrameClass::Control, b"x").await,
            Err(ProtoFrameError::Io(_))
        ));
        let mut w = FailingWriter::fail_flush();
        assert!(matches!(
            write_classed_frame(&mut w, FrameClass::Control, b"x").await,
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
