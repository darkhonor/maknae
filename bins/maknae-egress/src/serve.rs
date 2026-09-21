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
/// The VALUE is `maknae-proto`'s, shared with the kernel's pre-send check so
/// the two ends cannot drift (#240, review round 4).
pub const MAX_REQUEST_FRAME_BYTES: usize = maknae_proto::EGRESS_REQUEST_FRAME_MAX_BYTES;

#[derive(Debug, PartialEq, Eq)]
pub enum ServeError {
    /// The frame was admitted and the provider call failed. Distinct from
    /// `Refused`: the deputy was WILLING, and something downstream did not
    /// work — the kernel needs to tell those apart.
    Fulfil(String),
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

/// Read one length-prefixed body, ZEROIZING from allocation.
///
/// The return type is the property: this buffer holds the prompt in plaintext,
/// and the `SecretText` fields decoded out of it wipe their OWN allocations
/// without ever touching this original serialized copy. Wrapping at allocation
/// — rather than after a successful decode — is what covers the error paths: a
/// truncated read, an over-cap declaration, or a failed decode all drop it the
/// same way. Matches `maknae_proto::read_frame_zeroizing`.
///
/// The length is checked BEFORE the allocation: a four-byte prefix must not be
/// able to make the deputy reserve four gigabytes.
fn read_body_zeroizing(stream: &mut UnixStream) -> Result<zeroize::Zeroizing<Vec<u8>>, ServeError> {
    let mut len = [0u8; 4];
    stream.read_exact(&mut len).map_err(io)?;
    let n = u32::from_be_bytes(len) as usize;
    if n > MAX_REQUEST_FRAME_BYTES {
        return Err(ServeError::OversizeFrame(n));
    }
    let mut body = zeroize::Zeroizing::new(vec![0u8; n]);
    stream.read_exact(&mut body).map_err(io)?;
    Ok(body)
}

/// Serve exactly one connection: authenticate, read one frame, answer, close.
///
/// `fulfil` is what turns an admitted frame into a provider call. It is passed
/// in rather than constructed here so the transport can be tested without a
/// provider or a Vault — this project has no Vault stub and deliberately uses
/// none, so the seam is a function, not a fake server.
pub fn serve_one<F>(
    mut stream: UnixStream,
    expected_uid: u32,
    bounds: &EgressBounds,
    fulfil: F,
) -> Result<(), ServeError>
where
    F: FnOnce(&crate::handle::Admitted<'_>) -> Result<maknae_proto::EgressFrameReply, ServeError>,
{
    // BEFORE the first read. A peer we have not authenticated does not get to
    // hand us bytes to parse.
    if !maknae_vault::peer_uid_is(&stream, expected_uid).map_err(|_| ServeError::WrongPeer)? {
        return Err(ServeError::WrongPeer);
    }

    let body = read_body_zeroizing(&mut stream)?;

    let req = maknae_proto::decode_egress_frame_request(&body).map_err(io)?;
    let admitted = decide(&req, bounds).map_err(ServeError::Refused)?;
    let reply = fulfil(&admitted)?;

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

    /// A fulfiller that answers without a provider, so these tests exercise
    /// the TRANSPORT alone. The provider path has its own tests in `call.rs`
    /// and `maknae-llm`'s hermetic stub suite.
    fn canned(
        _a: &crate::handle::Admitted<'_>,
    ) -> Result<maknae_proto::EgressFrameReply, ServeError> {
        Ok(maknae_proto::EgressFrameReply {
            reply: maknae_proto::PromptReply {
                blocks: vec![],
                tool_calls: vec![],
            },
        })
    }

    fn bounds() -> EgressBounds {
        EgressBounds {
            kv_mount: "maknae-kv".into(),
            key_vault_path_prefix: "maknae/providers".into(),
            vault_addr: "https://vault.example:8200".into(),
            approle_mount: None,
        }
    }

    fn frame(key: &str) -> Vec<u8> {
        let r = EgressFrameRequest {
            destination: "provider:openai".into(),
            endpoint: "https://api.example.test/v1".into(),
            model: "m".into(),
            key_vault_path: key.into(),
            key_field: "api-key".into(),
            conversation: "conv1".into(),
            turns: vec![maknae_proto::Turn::User {
                content: vec![ContentBlock::Text {
                    text: SecretText(zeroize::Zeroizing::new("hi".into())),
                }],
            }],
        };
        maknae_proto::encode_egress_frame_request(&r)
            .unwrap()
            .to_vec()
    }

    /// Serve one connection from a peer that writes `bytes`, optionally
    /// half-closes its write side, and STAYS CONNECTED until `serve_one` has
    /// returned.
    ///
    /// The earlier shape — a spawned thread that wrote and returned — dropped
    /// the peer's end before `serve_one` captured its credentials. On macOS
    /// LOCAL_PEERCRED fails once the peer has closed, so the refusal under
    /// test came back as `WrongPeer` instead: measured 1–2 failures in 40 runs
    /// on the dev host, and macOS is a production target. The same
    /// hazard was already fixed once, by hand, in
    /// `a_peer_that_is_not_the_kernel_is_refused_before_its_bytes_are_read`;
    /// this helper is that fix applied to the pattern rather than the instance.
    fn served_by_a_peer_that_stays_connected(
        bytes: Vec<u8>,
        half_close: bool,
        expected_uid: u32,
    ) -> Result<(), ServeError> {
        let (a, b) = UnixStream::pair().unwrap();
        let (done_tx, done_rx) = std::sync::mpsc::channel::<()>();
        let h = std::thread::spawn(move || {
            let mut c = a;
            let _ = c.write_all(&bytes);
            if half_close {
                let _ = c.shutdown(std::net::Shutdown::Write);
            }
            // Hold the socket open until the reader is done with it.
            let _ = done_rx.recv();
        });
        let out = serve_one(b, expected_uid, &bounds(), canned);
        let _ = done_tx.send(());
        h.join().unwrap();
        out
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
    /// The deputy's check of the CONNECTING daemon is the exact-uid one, by
    /// name: an accepted connection reports the connecting process's own
    /// credentials, so the listener predicate (which also accepts root) has
    /// no place here. Pinned at the source, patterns composed so this test
    /// does not match itself.
    #[test]
    fn the_accept_path_checks_the_exact_uid_not_the_listener_predicate() {
        let src = include_str!("serve.rs");
        let exact = format!("maknae_vault::{}(&stream,", "peer_uid_is");
        let listener = format!("{}(&stream", "listener_uid_is");
        assert!(
            src.contains(&exact),
            "the accept path must check the exact uid"
        );
        assert!(
            !src.contains(&listener),
            "root is not the kernel; the listener predicate must not be used here"
        );
    }

    #[test]
    fn a_peer_that_is_not_the_kernel_is_refused_before_its_bytes_are_read() {
        let (a, b) = UnixStream::pair().unwrap();
        let me = nix::unistd::getuid().as_raw();
        let f = frame("maknae/providers/openai");
        let expected_len = f.len() as u32;
        // `a` is kept alive for the whole test. An earlier version moved it
        // into a thread and joined before asserting, which made the assertion
        // depend on whether the platform preserves buffered data after the
        // peer closes: Linux does, macOS does not, and macOS is a production
        // target. Writing from this thread keeps the question out of it.
        let mut writer = a;
        writer.write_all(&expected_len.to_be_bytes()).unwrap();
        writer.write_all(&f).unwrap();

        let mut keep = b.try_clone().unwrap();
        assert_eq!(
            serve_one(b, me.wrapping_add(1), &bounds(), canned),
            Err(ServeError::WrongPeer)
        );

        keep.set_read_timeout(Some(std::time::Duration::from_millis(500)))
            .unwrap();
        let mut len = [0u8; 4];
        keep.read_exact(&mut len)
            .expect("the frame was consumed — the credential check ran AFTER the read");
        assert_eq!(u32::from_be_bytes(len), expected_len);
        drop(writer);
    }

    #[test]
    fn an_authenticated_peer_within_bounds_gets_a_reply() {
        let (a, b) = UnixStream::pair().unwrap();
        let me = nix::unistd::getuid().as_raw();
        let h = std::thread::spawn(move || {
            let mut c = a;
            let f = frame("maknae/providers/openai");
            c.write_all(&(f.len() as u32).to_be_bytes()).unwrap();
            c.write_all(&f).unwrap();
            let mut len = [0u8; 4];
            c.read_exact(&mut len).unwrap();
            let mut body = vec![0u8; u32::from_be_bytes(len) as usize];
            c.read_exact(&mut body).unwrap();
            maknae_proto::decode_egress_frame_reply(&body).unwrap()
        });
        serve_one(b, me, &bounds(), canned).unwrap();
        let reply = h.join().unwrap();
        assert!(reply.reply.blocks.is_empty() && reply.reply.tool_calls.is_empty());
    }

    #[test]
    fn a_key_path_outside_bounds_is_refused() {
        let me = nix::unistd::getuid().as_raw();
        let f = frame("maknae/providers-evil/key");
        let mut bytes = (f.len() as u32).to_be_bytes().to_vec();
        bytes.extend_from_slice(&f);
        assert_eq!(
            served_by_a_peer_that_stays_connected(bytes, false, me),
            Err(ServeError::Refused(Refusal::KeyPathOutsideBounds))
        );
    }

    /// The same denial-of-service class the kernel side carries, applied in the
    /// other direction: a four-byte prefix must not become a 4 GiB allocation.
    #[test]
    fn an_enormous_declared_frame_is_refused_before_allocating() {
        let me = nix::unistd::getuid().as_raw();
        assert_eq!(
            served_by_a_peer_that_stays_connected(u32::MAX.to_be_bytes().to_vec(), false, me),
            Err(ServeError::OversizeFrame(u32::MAX as usize))
        );
    }

    /// Bytes that are not a frame are a refusal, never a silent success. The
    /// kernel is trusted, but a bug there must not be answered as if it were
    /// a request.
    #[test]
    fn a_body_that_is_not_a_frame_is_refused() {
        let me = nix::unistd::getuid().as_raw();
        let junk = [0xffu8, 0xff, 0xff];
        let mut bytes = (junk.len() as u32).to_be_bytes().to_vec();
        bytes.extend_from_slice(&junk);
        let e = served_by_a_peer_that_stays_connected(bytes, false, me).unwrap_err();
        assert!(matches!(e, ServeError::Io(_)), "{e:?}");
    }

    /// A peer that hangs up mid-frame is a refusal, not a hang.
    #[test]
    fn a_peer_that_hangs_up_mid_frame_is_refused() {
        let me = nix::unistd::getuid().as_raw();
        // Half-close after the length: the reader sees EOF mid-frame while the
        // peer's credentials are still capturable.
        let e = served_by_a_peer_that_stays_connected(64u32.to_be_bytes().to_vec(), true, me)
            .unwrap_err();
        assert!(matches!(e, ServeError::Io(_)), "{e:?}");
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
            let f = frame("maknae/providers/openai");
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
            let _ = serve_one(conn.unwrap(), me, &b, canned);
            served += 1;
            if served == 2 {
                break;
            }
        }
        h.join().unwrap();
    }

    /// The receive buffer is `Zeroizing` FROM ALLOCATION, not after decode.
    /// This binding is the regression guard: if `read_body_zeroizing` is ever
    /// changed to hand back a plain `Vec<u8>`, the prompt's serialized copy
    /// would be left in freed heap and this stops compiling.
    #[test]
    fn the_receive_buffer_is_zeroizing_from_allocation() {
        let (a, b) = UnixStream::pair().unwrap();
        let f = frame("maknae/providers/openai");
        let mut writer = a;
        writer.write_all(&(f.len() as u32).to_be_bytes()).unwrap();
        writer.write_all(&f).unwrap();
        let mut b = b;
        let body: zeroize::Zeroizing<Vec<u8>> = read_body_zeroizing(&mut b).unwrap();
        assert_eq!(&*body, &f[..]);
        // And the over-cap refusal happens before any allocation on this path.
        let (mut c, mut d) = UnixStream::pair().unwrap();
        c.write_all(&u32::MAX.to_be_bytes()).unwrap();
        assert_eq!(
            read_body_zeroizing(&mut d),
            Err(ServeError::OversizeFrame(u32::MAX as usize))
        );
    }

    /// THE BOUNDARY, deputy side. Same class as #295 on the kernel side: the
    /// over-cap test declares `u32::MAX`, where `>` and `>=` refuse alike, so
    /// it cannot pin which operator the check uses. At EXACTLY the cap the
    /// frame must be admitted past the cap check and fail at DECODE instead —
    /// a different error, which is the discriminator.
    #[test]
    fn the_request_cap_refuses_above_it_and_admits_at_it() {
        let me = nix::unistd::getuid().as_raw();

        // n == MAX: past the cap, so the failure comes from decoding junk.
        let n = MAX_REQUEST_FRAME_BYTES as u32;
        let mut bytes = n.to_be_bytes().to_vec();
        bytes.extend_from_slice(&vec![0u8; n as usize]);
        match served_by_a_peer_that_stays_connected(bytes, false, me) {
            Err(ServeError::Io(_)) => {}
            Err(ServeError::OversizeFrame(n)) => panic!(
                "a frame EXACTLY at the cap ({n}) was refused as oversize — the check is `>=`, not `>`"
            ),
            other => panic!("expected a decode-stage failure, got {other:?}"),
        }

        // n == MAX + 1: refused by the cap, before any allocation.
        assert_eq!(
            served_by_a_peer_that_stays_connected(
                ((MAX_REQUEST_FRAME_BYTES + 1) as u32)
                    .to_be_bytes()
                    .to_vec(),
                false,
                me
            ),
            Err(ServeError::OversizeFrame(MAX_REQUEST_FRAME_BYTES + 1))
        );
    }

    /// TWO SERVED CONNECTIONS SHARING A DESTINATION read the credential ONCE.
    ///
    /// Reviewed finding (#296): the cache was constructed inside the
    /// per-connection closure, so "read on first use, cached per destination"
    /// lasted exactly one request. `keys.rs`'s unit test passed because IT held
    /// a cache across calls — the deputy did not. This drives the real serving
    /// path twice and counts reads, which is the assertion that was missing.
    #[test]
    fn two_served_connections_sharing_a_destination_read_the_key_once() {
        use std::sync::Mutex;

        struct Counting {
            reads: Mutex<usize>,
        }
        impl crate::keys::KeySource for Counting {
            async fn read(
                &self,
                _m: &str,
                _p: &str,
                _f: &str,
            ) -> Result<zeroize::Zeroizing<String>, String> {
                *self.reads.lock().unwrap() += 1;
                Ok(zeroize::Zeroizing::new("k".into()))
            }
        }

        let d = tempfile::tempdir().unwrap();
        let path = d.path().join("egress.sock");
        let l = UnixListener::bind(&path).unwrap();
        let me = nix::unistd::getuid().as_raw();
        let p2 = path.clone();
        let h = std::thread::spawn(move || {
            for _ in 0..2 {
                let mut c = UnixStream::connect(&p2).unwrap();
                let f = frame("maknae/providers/openai");
                c.write_all(&(f.len() as u32).to_be_bytes()).unwrap();
                c.write_all(&f).unwrap();
                let mut len = [0u8; 4];
                let _ = c.read_exact(&mut len);
            }
        });

        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        // ONE cache, outside the loop — exactly as main.rs holds it.
        let mut keys = crate::keys::KeyCache::new(Counting {
            reads: Mutex::new(0),
        });
        let b = bounds();
        let mut served = 0;
        for conn in l.incoming() {
            let _ = serve_one(conn.unwrap(), me, &b, |admitted| {
                rt.block_on(crate::call::fulfil(
                    admitted,
                    &mut keys,
                    crate::call::CallBounds::default(),
                    &b.kv_mount,
                ))
                .map_err(|e| ServeError::Fulfil(e.to_string()))
            });
            served += 1;
            if served == 2 {
                break;
            }
        }
        h.join().unwrap();
        assert_eq!(
            *keys.source().reads.lock().unwrap(),
            1,
            "two connections to the SAME destination must read the credential once; \
             a cache the serving path rebuilds per request is not a cache"
        );
    }
}
