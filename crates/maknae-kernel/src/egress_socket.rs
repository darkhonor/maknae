//! The kernel's egress backend: one decided request, over one connection, to
//! the `maknae-egress` deputy (#240a D2/D3).
//!
//! **One connection per request** (D2). Case-4 orchestration means concurrent
//! fan-out to several conduits at once — `Egress` is `Send + Sync` and `send`
//! takes `&self` on a blocking worker, so the signature already admits it. One
//! connection per request is naturally concurrent, needs no correlation id and
//! no reply demuxer, and — the stronger reason — makes the peer-credential
//! check run **per request** rather than once on a long-lived connection.
//!
//! **Peer credentials are checked BEFORE the first write** (D3). The request
//! carries prompt content and the Vault path naming where the provider
//! credential lives; writing first and checking after would defeat the point.
//! The path is not the boundary — a socket path can be replaced by anything
//! that can write the directory; a uid cannot be forged.

use crate::egress::DurableEgressIntent;
use crate::egress::{Egress, EgressFailure, EgressReply, EgressRequest};
use maknae_proto::{decode_egress_frame_reply, encode_egress_frame_request, EgressFrameRequest};
use std::io::{Read, Write};
use std::os::unix::net::UnixStream;
use std::path::PathBuf;
use std::time::Duration;

/// The deputy's socket, and the uid it must be running as.
pub struct SocketEgress {
    path: PathBuf,
    /// Resolved ONCE at construction, on the blocking path, fail-closed if
    /// unresolvable — never per request on an async worker. That is the arm
    /// whose own message reads "failing closed without spawning more NSS work".
    expected_uid: u32,
    timeout: Duration,
    /// The largest reply frame this kernel will ACCEPT from the deputy.
    /// Checked against the declared length BEFORE any allocation: the deputy
    /// is authenticated but untrusted, and a four-byte prefix must not be able
    /// to make the kernel reserve four gigabytes.
    max_frame_bytes: usize,
}

impl SocketEgress {
    /// `expected_uid` is `_maknae-egress`'s, resolved by the caller at
    /// construction. Taking it as a value rather than resolving here keeps the
    /// NSS lookup on the caller's blocking path and makes the refusal testable
    /// on a host that has no such account.
    pub fn new(
        path: PathBuf,
        expected_uid: u32,
        timeout: Duration,
        max_frame_bytes: usize,
    ) -> Self {
        Self {
            path,
            expected_uid,
            timeout,
            max_frame_bytes,
        }
    }

    fn transport(e: impl std::fmt::Display) -> EgressFailure {
        EgressFailure::Transport(e.to_string())
    }
}

impl Egress for SocketEgress {
    fn ready(&self) -> Result<(), EgressFailure> {
        if self.path.exists() {
            Ok(())
        } else {
            Err(EgressFailure::NotConfigured)
        }
    }

    fn send(
        &self,
        _intent: &DurableEgressIntent,
        req: EgressRequest,
    ) -> Result<EgressReply, EgressFailure> {
        let stream = UnixStream::connect(&self.path).map_err(Self::transport)?;

        // BEFORE the first write. Moving this below the write hands prompt
        // content and a Vault path to an unauthenticated peer. A capture error
        // refuses too: a peer we cannot identify cannot be policed.
        if !maknae_vault::peer_uid_is(&stream, self.expected_uid).map_err(Self::transport)? {
            return Err(EgressFailure::Transport(
                "egress peer is not the expected uid".into(),
            ));
        }

        stream
            .set_read_timeout(Some(self.timeout))
            .map_err(Self::transport)?;
        stream
            .set_write_timeout(Some(self.timeout))
            .map_err(Self::transport)?;

        let frame = EgressFrameRequest {
            destination: req.destination,
            endpoint: req.endpoint,
            model: req.model,
            key_vault_path: req.key_vault_path,
            conversation: req.conversation,
            content: req.content,
        };
        let buf = encode_egress_frame_request(&frame).map_err(Self::transport)?;

        let mut s = stream;
        s.write_all(&(buf.len() as u32).to_be_bytes())
            .map_err(Self::transport)?;
        s.write_all(&buf).map_err(Self::transport)?;
        s.flush().map_err(Self::transport)?;

        let mut len = [0u8; 4];
        s.read_exact(&mut len).map_err(Self::transport)?;
        let n = u32::from_be_bytes(len) as usize;
        // BEFORE the allocation. The deputy is authenticated but untrusted (see
        // this module's header), so a four-byte length prefix must not be able
        // to make the kernel reserve up to 4 GiB. The CBOR decode and
        // `admitted_reply` run later and would never see it.
        if n > self.max_frame_bytes {
            return Err(EgressFailure::Transport(format!(
                "deputy declared a {n}-byte reply frame over the {}-byte cap",
                self.max_frame_bytes
            )));
        }
        // ZEROIZING from allocation, not after decode. The decoded `SecretText`
        // fields wipe their OWN allocations; they do not touch this original
        // serialized copy, which holds the provider's reply in plaintext. The
        // wrapper covers the error paths too — a truncated read or a failed
        // decode drops this buffer just the same. Matches
        // `maknae_proto::read_frame_zeroizing`.
        let mut body = maknae_io::Zeroizing::new(vec![0u8; n]);
        s.read_exact(&mut body).map_err(Self::transport)?;
        let reply = decode_egress_frame_reply(&body).map_err(Self::transport)?;
        Ok(EgressReply { reply: reply.reply })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use maknae_proto::{ContentBlock, SecretText};
    use std::os::unix::net::UnixListener;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc as StdArc;

    fn req() -> EgressRequest {
        EgressRequest {
            destination: "provider:openai".into(),
            endpoint: "https://api.example.test/v1".into(),
            model: "m".into(),
            key_vault_path: "secret/data/maknae/providers/openai".into(),
            conversation: "conv1".into(),
            content: vec![ContentBlock::Text {
                text: SecretText(maknae_io::Zeroizing::new(
                    "the president flies at 0300".into(),
                )),
            }],
        }
    }

    /// A fake deputy. Returns how many bytes it ever read, so a test can assert
    /// that a refused connection wrote NOTHING.
    fn fake_deputy(
        dir: &std::path::Path,
        reply: Option<maknae_proto::PromptReply>,
    ) -> (PathBuf, StdArc<AtomicUsize>) {
        let path = dir.join("egress.sock");
        let l = UnixListener::bind(&path).unwrap();
        let seen = StdArc::new(AtomicUsize::new(0));
        let s2 = StdArc::clone(&seen);
        std::thread::spawn(move || {
            if let Ok((mut c, _)) = l.accept() {
                let mut len = [0u8; 4];
                if c.read_exact(&mut len).is_ok() {
                    let n = u32::from_be_bytes(len) as usize;
                    let mut body = vec![0u8; n];
                    if c.read_exact(&mut body).is_ok() {
                        s2.fetch_add(4 + n, Ordering::SeqCst);
                        if let Some(r) = reply {
                            let out = maknae_proto::encode_egress_frame_reply(
                                &maknae_proto::EgressFrameReply { reply: r },
                            )
                            .unwrap();
                            let _ = c.write_all(&(out.len() as u32).to_be_bytes());
                            let _ = c.write_all(&out);
                        }
                    }
                }
            }
        });
        (path, seen)
    }

    /// THE control. The listener runs under the test's own uid, so expecting a
    /// different one is a REAL mismatch, not a stub. What it proves precisely:
    /// a uid that is not the expected one is refused — and refused BEFORE the
    /// prompt content and the Vault key path reach the socket.
    #[test]
    fn a_peer_whose_uid_is_not_expected_is_refused_before_anything_is_written() {
        let d = tempfile::tempdir().unwrap();
        let (path, seen) = fake_deputy(d.path(), None);
        let me = nix::unistd::getuid().as_raw();
        let e = SocketEgress::new(path, me.wrapping_add(1), Duration::from_secs(2), 64 * 1024);
        let intent = crate::egress::DurableEgressIntent::canned_for_test();
        let out = e.send(&intent, req());
        assert!(
            matches!(out, Err(EgressFailure::Transport(_))),
            "expected refusal, got {out:?}"
        );
        std::thread::sleep(Duration::from_millis(120));
        assert_eq!(
            seen.load(Ordering::SeqCst),
            0,
            "bytes reached an unauthenticated peer — the peercred check is after the write"
        );
    }

    #[test]
    fn a_peer_with_the_expected_uid_completes_a_round_trip() {
        let d = tempfile::tempdir().unwrap();
        let reply = maknae_proto::PromptReply {
            blocks: vec![ContentBlock::Text {
                text: SecretText(maknae_io::Zeroizing::new("ok".into())),
            }],
            tool_calls: vec![],
        };
        let (path, seen) = fake_deputy(d.path(), Some(reply.clone()));
        let me = nix::unistd::getuid().as_raw();
        let e = SocketEgress::new(path, me, Duration::from_secs(2), 64 * 1024);
        let intent = crate::egress::DurableEgressIntent::canned_for_test();
        let got = e.send(&intent, req()).unwrap();
        assert_eq!(got.reply, reply);
        assert!(seen.load(Ordering::SeqCst) > 0);
    }

    /// `ready()` is cheap and side-effect-free, and fails closed when there is
    /// no deputy to talk to.
    #[test]
    fn ready_fails_closed_with_no_socket() {
        let d = tempfile::tempdir().unwrap();
        let e = SocketEgress::new(
            d.path().join("absent.sock"),
            0,
            Duration::from_secs(1),
            64 * 1024,
        );
        assert_eq!(e.ready(), Err(EgressFailure::NotConfigured));
    }

    #[test]
    fn ready_succeeds_once_the_deputy_socket_exists() {
        let d = tempfile::tempdir().unwrap();
        let (path, _seen) = fake_deputy(d.path(), None);
        let e = SocketEgress::new(path, 0, Duration::from_secs(1), 64 * 1024);
        assert_eq!(e.ready(), Ok(()));
    }

    #[test]
    fn a_connect_to_no_deputy_is_a_transport_failure() {
        let d = tempfile::tempdir().unwrap();
        let e = SocketEgress::new(
            d.path().join("absent.sock"),
            0,
            Duration::from_secs(1),
            64 * 1024,
        );
        let intent = crate::egress::DurableEgressIntent::canned_for_test();
        assert!(matches!(
            e.send(&intent, req()),
            Err(EgressFailure::Transport(_))
        ));
    }

    /// A deputy that answers with bytes that are not a frame is a transport
    /// failure, never a silent empty success. The kernel does not trust the
    /// process on the other end of the socket.
    #[test]
    fn a_deputy_that_answers_with_garbage_is_a_transport_failure() {
        let d = tempfile::tempdir().unwrap();
        let path = d.path().join("egress.sock");
        let l = UnixListener::bind(&path).unwrap();
        std::thread::spawn(move || {
            if let Ok((mut c, _)) = l.accept() {
                let mut len = [0u8; 4];
                if c.read_exact(&mut len).is_ok() {
                    let n = u32::from_be_bytes(len) as usize;
                    let mut body = vec![0u8; n];
                    let _ = c.read_exact(&mut body);
                    let junk = [0xffu8, 0xff, 0xff];
                    let _ = c.write_all(&(junk.len() as u32).to_be_bytes());
                    let _ = c.write_all(&junk);
                }
            }
        });
        let me = nix::unistd::getuid().as_raw();
        let e = SocketEgress::new(path, me, Duration::from_secs(2), 64 * 1024);
        let intent = crate::egress::DurableEgressIntent::canned_for_test();
        assert!(matches!(
            e.send(&intent, req()),
            Err(EgressFailure::Transport(_))
        ));
    }

    /// A deputy that hangs up before answering is a transport failure too —
    /// the content left, and the kernel must not invent a reply.
    #[test]
    fn a_deputy_that_hangs_up_is_a_transport_failure() {
        let d = tempfile::tempdir().unwrap();
        let path = d.path().join("egress.sock");
        let l = UnixListener::bind(&path).unwrap();
        std::thread::spawn(move || {
            if let Ok((mut c, _)) = l.accept() {
                let mut len = [0u8; 4];
                let _ = c.read_exact(&mut len);
                drop(c);
            }
        });
        let me = nix::unistd::getuid().as_raw();
        let e = SocketEgress::new(path, me, Duration::from_secs(2), 64 * 1024);
        let intent = crate::egress::DurableEgressIntent::canned_for_test();
        assert!(matches!(
            e.send(&intent, req()),
            Err(EgressFailure::Transport(_))
        ));
    }

    /// A four-byte length prefix from the deputy must NOT become a
    /// four-gigabyte allocation. The deputy is authenticated but untrusted —
    /// this file says so in its own header — so a compromised or faulty one
    /// exhausting the kernel with four bytes is a denial of service the
    /// protocol admission never sees, because the allocation happens first.
    #[test]
    fn a_deputy_declaring_an_enormous_frame_is_refused_before_allocating() {
        let d = tempfile::tempdir().unwrap();
        let path = d.path().join("egress.sock");
        let l = UnixListener::bind(&path).unwrap();
        std::thread::spawn(move || {
            if let Ok((mut c, _)) = l.accept() {
                let mut len = [0u8; 4];
                if c.read_exact(&mut len).is_ok() {
                    let n = u32::from_be_bytes(len) as usize;
                    let mut body = vec![0u8; n];
                    let _ = c.read_exact(&mut body);
                    // Declare the largest frame a u32 can express, and send
                    // nothing after it. A kernel that pre-allocates dies here.
                    let _ = c.write_all(&u32::MAX.to_be_bytes());
                }
            }
        });
        let me = nix::unistd::getuid().as_raw();
        let e = SocketEgress::new(path, me, Duration::from_secs(2), 64 * 1024);
        let intent = crate::egress::DurableEgressIntent::canned_for_test();
        let out = e.send(&intent, req());
        match out {
            Err(EgressFailure::Transport(m)) => {
                assert!(
                    m.contains("frame"),
                    "expected a frame-cap refusal, got: {m}"
                )
            }
            other => panic!("expected a refusal, got {other:?}"),
        }
    }
}
