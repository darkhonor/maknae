//! The accept loop and one connection's worth of I/O (#240a D2/D3).
//!
//! **Peer credentials are checked before a byte is read.** The kernel is the
//! only process allowed to speak here; a socket path is not a boundary,
//! because anything that can write the directory can replace it. A uid cannot
//! be forged.
//!
//! **One request per connection.** The kernel opens a fresh connection per
//! request, so the credential check runs per request rather than once on a
//! long-lived socket.

use crate::handle::{decide, Refusal};
use maknae_config::EgressBounds;
use std::io::{Read, Write};
use std::os::unix::net::UnixStream;

/// The largest request frame the deputy will ACCEPT. Checked against the
/// declared length BEFORE allocation: the kernel is trusted, but a bug there
/// must not be able to make the deputy reserve four gigabytes on a four-byte
/// prefix. Defence in depth, in the direction the kernel already applies to us.
pub const MAX_REQUEST_FRAME_BYTES: usize = 1024 * 1024;

#[derive(Debug, PartialEq, Eq)]
pub enum ServeError {
    /// The connected peer is not the kernel, or could not be identified at
    /// all. One variant, because the deputy treats them identically: a peer we
    /// cannot police is refused exactly like a peer we can and shouldn't. The
    /// uid is deliberately not carried — nothing is disclosed to the peer.
    WrongPeer,
    OversizeFrame(usize),
    Io(String),
    Refused(Refusal),
}

/// One mapping for every I/O failure on this path. A helper rather than four
/// inline closures: one place to change the shape, and one thing to cover.
fn io(e: impl std::fmt::Display) -> ServeError {
    ServeError::Io(e.to_string())
}

/// Serve exactly one connection: authenticate, read one frame, answer, close.
pub fn serve_one(
    mut stream: UnixStream,
    expected_uid: u32,
    bounds: &EgressBounds,
) -> Result<(), ServeError> {
    // BEFORE the first read. A peer we have not authenticated does not get to
    // hand us bytes to parse.
    if !maknae_vault::peer_uid_is(&stream, expected_uid).map_err(|_| ServeError::WrongPeer)? {
        return Err(ServeError::WrongPeer);
    }

    let mut len = [0u8; 4];
    stream.read_exact(&mut len).map_err(io)?;
    let n = u32::from_be_bytes(len) as usize;
    if n > MAX_REQUEST_FRAME_BYTES {
        return Err(ServeError::OversizeFrame(n));
    }
    let mut body = vec![0u8; n];
    stream.read_exact(&mut body).map_err(io)?;

    let req = maknae_proto::decode_egress_frame_request(&body).map_err(io)?;
    let reply = decide(&req, bounds).map_err(ServeError::Refused)?;

    let out = maknae_proto::encode_egress_frame_reply(&reply).map_err(io)?;
    stream
        .write_all(&(out.len() as u32).to_be_bytes())
        .map_err(io)?;
    stream.write_all(&out).map_err(io)?;
    stream.flush().map_err(io)
}

#[cfg(test)]
mod tests {
    use super::*;
    use maknae_proto::{ContentBlock, EgressFrameRequest, SecretText};
    use std::os::unix::net::UnixListener;

    fn bounds() -> EgressBounds {
        EgressBounds {
            key_vault_path_prefix: "secret/data/maknae/providers".into(),
        }
    }

    fn frame(key: &str) -> Vec<u8> {
        let r = EgressFrameRequest {
            destination: "provider:openai".into(),
            endpoint: "https://api.example.test/v1".into(),
            model: "m".into(),
            key_vault_path: key.into(),
            conversation: "conv1".into(),
            content: vec![ContentBlock::Text {
                text: SecretText(zeroize::Zeroizing::new("hi".into())),
            }],
        };
        maknae_proto::encode_egress_frame_request(&r)
            .unwrap()
            .to_vec()
    }

    /// A peer that is not the kernel is refused, and — the part that matters —
    /// refused BEFORE its bytes are consumed.
    ///
    /// An earlier version asserted only that the connection was refused, and a
    /// mutation moving the credential check below the read SURVIVED it.
    /// Asserting a refusal proves nothing about ordering. This proves it by
    /// CONSUMPTION: the client writes a full frame, the deputy refuses, and the
    /// frame is still sitting unread in the socket afterwards. A deputy that
    /// read first would have drained it.
    #[test]
    fn a_peer_that_is_not_the_kernel_is_refused_before_its_bytes_are_read() {
        let (a, b) = UnixStream::pair().unwrap();
        let me = nix::unistd::getuid().as_raw();
        let f = frame("secret/data/maknae/providers/openai");
        let expected_len = f.len() as u32;
        let h = std::thread::spawn(move || {
            let mut c = a;
            c.write_all(&expected_len.to_be_bytes()).unwrap();
            c.write_all(&f).unwrap();
        });
        h.join().unwrap();

        let mut keep = b.try_clone().unwrap();
        assert_eq!(
            serve_one(b, me.wrapping_add(1), &bounds()),
            Err(ServeError::WrongPeer)
        );

        keep.set_read_timeout(Some(std::time::Duration::from_millis(500)))
            .unwrap();
        let mut len = [0u8; 4];
        keep.read_exact(&mut len)
            .expect("the frame was consumed — the credential check ran AFTER the read");
        assert_eq!(u32::from_be_bytes(len), expected_len);
    }

    #[test]
    fn an_authenticated_peer_within_bounds_gets_a_reply() {
        let (a, b) = UnixStream::pair().unwrap();
        let me = nix::unistd::getuid().as_raw();
        let h = std::thread::spawn(move || {
            let mut c = a;
            let f = frame("secret/data/maknae/providers/openai");
            c.write_all(&(f.len() as u32).to_be_bytes()).unwrap();
            c.write_all(&f).unwrap();
            let mut len = [0u8; 4];
            c.read_exact(&mut len).unwrap();
            let mut body = vec![0u8; u32::from_be_bytes(len) as usize];
            c.read_exact(&mut body).unwrap();
            maknae_proto::decode_egress_frame_reply(&body).unwrap()
        });
        serve_one(b, me, &bounds()).unwrap();
        let reply = h.join().unwrap();
        assert!(reply.reply.blocks.is_empty() && reply.reply.tool_calls.is_empty());
    }

    #[test]
    fn a_key_path_outside_bounds_is_refused() {
        let (a, b) = UnixStream::pair().unwrap();
        let me = nix::unistd::getuid().as_raw();
        std::thread::spawn(move || {
            let mut c = a;
            let f = frame("secret/data/maknae/providers-evil/key");
            let _ = c.write_all(&(f.len() as u32).to_be_bytes());
            let _ = c.write_all(&f);
        });
        assert_eq!(
            serve_one(b, me, &bounds()),
            Err(ServeError::Refused(Refusal::KeyPathOutsideBounds))
        );
    }

    /// The same denial-of-service class the kernel side carries, applied in the
    /// other direction: a four-byte prefix must not become a 4 GiB allocation.
    #[test]
    fn an_enormous_declared_frame_is_refused_before_allocating() {
        let (a, b) = UnixStream::pair().unwrap();
        let me = nix::unistd::getuid().as_raw();
        std::thread::spawn(move || {
            let mut c = a;
            let _ = c.write_all(&u32::MAX.to_be_bytes());
        });
        assert_eq!(
            serve_one(b, me, &bounds()),
            Err(ServeError::OversizeFrame(u32::MAX as usize))
        );
    }

    /// Bytes that are not a frame are a refusal, never a silent success. The
    /// kernel is trusted, but a bug there must not be answered as if it were
    /// a request.
    #[test]
    fn a_body_that_is_not_a_frame_is_refused() {
        let (a, b) = UnixStream::pair().unwrap();
        let me = nix::unistd::getuid().as_raw();
        std::thread::spawn(move || {
            let mut c = a;
            let junk = [0xffu8, 0xff, 0xff];
            let _ = c.write_all(&(junk.len() as u32).to_be_bytes());
            let _ = c.write_all(&junk);
        });
        assert!(matches!(
            serve_one(b, me, &bounds()),
            Err(ServeError::Io(_))
        ));
    }

    /// A peer that hangs up mid-frame is a refusal, not a hang.
    #[test]
    fn a_peer_that_hangs_up_mid_frame_is_refused() {
        let (a, b) = UnixStream::pair().unwrap();
        let me = nix::unistd::getuid().as_raw();
        std::thread::spawn(move || {
            let mut c = a;
            let _ = c.write_all(&64u32.to_be_bytes());
            drop(c);
        });
        assert!(matches!(
            serve_one(b, me, &bounds()),
            Err(ServeError::Io(_))
        ));
    }

    /// The accept loop survives a bad connection and keeps serving: one hostile
    /// or broken peer must not take the deputy down.
    #[test]
    fn the_accept_loop_survives_a_refused_connection_and_serves_the_next() {
        let d = tempfile::tempdir().unwrap();
        let path = d.path().join("egress.sock");
        let l = UnixListener::bind(&path).unwrap();
        let me = nix::unistd::getuid().as_raw();
        let p2 = path.clone();
        let h = std::thread::spawn(move || {
            // 1: hang up immediately -> refused, loop continues
            drop(UnixStream::connect(&p2).unwrap());
            // 2: a real request -> answered
            let mut c = UnixStream::connect(&p2).unwrap();
            let f = frame("secret/data/maknae/providers/openai");
            c.write_all(&(f.len() as u32).to_be_bytes()).unwrap();
            c.write_all(&f).unwrap();
            let mut len = [0u8; 4];
            c.read_exact(&mut len).unwrap();
            let mut body = vec![0u8; u32::from_be_bytes(len) as usize];
            c.read_exact(&mut body).unwrap();
            maknae_proto::decode_egress_frame_reply(&body).unwrap()
        });
        let b = bounds();
        let mut served = 0;
        for conn in l.incoming() {
            let _ = serve_one(conn.unwrap(), me, &b);
            served += 1;
            if served == 2 {
                break;
            }
        }
        h.join().unwrap();
    }

    /// The kernel sends a request and hangs up before reading the answer. The
    /// deputy's write fails, and that is a refusal it reports rather than a
    /// panic or a silent drop. This is the deputy-side shape of #172's
    /// closed-connection case.
    #[test]
    fn a_peer_that_hangs_up_before_the_reply_is_a_reported_io_failure() {
        let (a, b) = UnixStream::pair().unwrap();
        let me = nix::unistd::getuid().as_raw();
        let h = std::thread::spawn(move || {
            let mut c = a;
            let f = frame("secret/data/maknae/providers/openai");
            c.write_all(&(f.len() as u32).to_be_bytes()).unwrap();
            c.write_all(&f).unwrap();
            c.shutdown(std::net::Shutdown::Both).unwrap();
        });
        h.join().unwrap();
        // The request is buffered; the peer is gone. Writing the reply fails.
        assert!(matches!(
            serve_one(b, me, &bounds()),
            Err(ServeError::Io(_))
        ));
    }
}
