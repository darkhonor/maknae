//! Length-delimited framing over any AsyncRead+AsyncWrite (spec §3): u32-BE length ∥ CBOR body.
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use crate::error::ProtoFrameError;

pub async fn write_frame<W: AsyncWrite + Unpin>(w: &mut W, body: &[u8]) -> Result<(), ProtoFrameError> {
    let len = u32::try_from(body.len()).map_err(|_| ProtoFrameError::Oversize { declared: body.len(), max: u32::MAX as usize })?;
    w.write_all(&len.to_be_bytes()).await.map_err(|e| ProtoFrameError::Io(e.to_string()))?;
    w.write_all(body).await.map_err(|e| ProtoFrameError::Io(e.to_string()))?;
    w.flush().await.map_err(|e| ProtoFrameError::Io(e.to_string()))?;
    Ok(())
}

pub async fn read_frame<R: AsyncRead + Unpin>(r: &mut R, max: usize) -> Result<Vec<u8>, ProtoFrameError> {
    let mut len_buf = [0u8; 4];
    r.read_exact(&mut len_buf).await.map_err(|_| ProtoFrameError::Truncated)?;
    let declared = u32::from_be_bytes(len_buf) as usize;
    if declared > max { return Err(ProtoFrameError::Oversize { declared, max }); } // BEFORE allocation
    let mut body = vec![0u8; declared];
    r.read_exact(&mut body).await.map_err(|_| ProtoFrameError::Truncated)?;
    Ok(body)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[tokio::test]
    async fn round_trip_frame() {
        let (mut a, mut b) = tokio::io::duplex(4096);
        let payload = b"hello".to_vec();
        write_frame(&mut a, &payload).await.unwrap();
        let got = read_frame(&mut b, 1024).await.unwrap();
        assert_eq!(got, payload);
    }
    #[tokio::test]
    async fn oversize_fails_before_alloc() {
        // Hand-craft a length prefix of 10 MiB with max 1 KiB.
        let (mut a, mut b) = tokio::io::duplex(64);
        let big: u32 = 10 * 1024 * 1024;
        tokio::io::AsyncWriteExt::write_all(&mut a, &big.to_be_bytes()).await.unwrap();
        let e = read_frame(&mut b, 1024).await.unwrap_err();
        assert!(matches!(e, ProtoFrameError::Oversize { declared, max } if declared == big as usize && max == 1024));
    }
    #[tokio::test]
    async fn truncated_length_fails() {
        let (mut a, mut b) = tokio::io::duplex(64);
        tokio::io::AsyncWriteExt::write_all(&mut a, &[0u8, 0u8]).await.unwrap(); // only 2 of 4 length bytes
        drop(a);
        assert!(matches!(read_frame(&mut b, 1024).await, Err(ProtoFrameError::Truncated)));
    }
    #[tokio::test]
    async fn truncated_body_fails() {
        let (mut a, mut b) = tokio::io::duplex(64);
        let declared: u32 = 8;
        tokio::io::AsyncWriteExt::write_all(&mut a, &declared.to_be_bytes()).await.unwrap();
        tokio::io::AsyncWriteExt::write_all(&mut a, &[0u8, 1u8, 2u8]).await.unwrap(); // only 3 of 8 body bytes
        drop(a);
        assert!(matches!(read_frame(&mut b, 1024).await, Err(ProtoFrameError::Truncated)));
    }
    #[tokio::test]
    async fn exact_max_succeeds() {
        let (mut a, mut b) = tokio::io::duplex(4096);
        let payload = vec![0xabu8; 1024];
        write_frame(&mut a, &payload).await.unwrap();
        let got = read_frame(&mut b, 1024).await.unwrap();
        assert_eq!(got, payload);
    }
}
