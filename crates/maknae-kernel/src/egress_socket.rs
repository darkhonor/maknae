//! The kernel's egress backend: one decided request, over one connection, to
//! the `maknae-egress` deputy (#240a D2/D3).
//!
//! **One connection per request** (D2). Case-4 orchestration means concurrent
//! fan-out to several conduits at once — `Egress` is `Send + Sync` and `send`
//! takes `&self` on a blocking worker, so the signature already admits it. One
//! connection per request is naturally concurrent, needs no correlation id and
//! no reply demuxer, and — the stronger reason — makes the peer-credential
//! check run **per request** rather than once on a long-lived connection.
//! What the OTHER end does with that: the deputy today serves one connection
//! to completion before accepting the next (`bins/maknae-egress/src/main.rs`),
//! so two concurrent prompts queue head-to-tail behind one provider call and
//! the deadline below is a queueing bound as well as a call bound (#321).
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
use std::time::{Duration, Instant};

/// The deputy's socket, and the uid its listener must have been created
/// under — the deputy's own, or root's on its behalf (socket activation).
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

    /// Every failure from the first written byte on is `AfterSend`: the
    /// request has left the kernel, so "nothing left" (`Transport` →
    /// `Failed`) would be a false record. The budget's own refusal passes
    /// through — it already means delivery-unknown.
    fn after_send(e: EgressFailure) -> EgressFailure {
        match e {
            EgressFailure::Transport(m) => EgressFailure::AfterSend(m),
            other => other,
        }
    }

    /// What is left of the wall-clock budget, as the next socket timeout —
    /// a refusal once it is spent. (`None` would tell the socket to block
    /// forever and a zero timeout is refused by the platform; neither can
    /// reach it from here.)
    fn remaining(deadline_at: Instant) -> Result<Duration, EgressFailure> {
        let left = deadline_at.saturating_duration_since(Instant::now());
        if left.is_zero() {
            return Err(EgressFailure::DeadlineExpired);
        }
        Ok(left)
    }

    fn arm(s: &UnixStream, deadline_at: Instant) -> Result<(), EgressFailure> {
        let left = Self::remaining(deadline_at)?;
        s.set_read_timeout(Some(left)).map_err(Self::transport)?;
        s.set_write_timeout(Some(left)).map_err(Self::transport)?;
        Ok(())
    }

    /// Wait for readability within what is left of the budget; a timeout is
    /// `DeadlineExpired` — the request is already on the wire by the time any
    /// read happens, so this is delivery-unknown, never "nothing left". `poll` rather than a re-armed `SO_RCVTIMEO`:
    /// macOS refuses `setsockopt` (EINVAL) on a socket whose peer has
    /// already disconnected even while its buffered bytes are still
    /// readable, and `poll` reports exactly those as readable at once.
    fn wait_readable(s: &UnixStream, deadline_at: Instant) -> Result<(), EgressFailure> {
        Self::wait_for(s, nix::poll::PollFlags::POLLIN, deadline_at)
    }

    /// The write side of the same wait.
    fn wait_writable(s: &UnixStream, deadline_at: Instant) -> Result<(), EgressFailure> {
        Self::wait_for(s, nix::poll::PollFlags::POLLOUT, deadline_at)
    }

    fn wait_for(
        s: &UnixStream,
        flags: nix::poll::PollFlags,
        deadline_at: Instant,
    ) -> Result<(), EgressFailure> {
        use nix::poll::{poll, PollFd, PollTimeout};
        use std::os::fd::AsFd;
        loop {
            let left = Self::remaining(deadline_at)?;
            let timeout = PollTimeout::try_from(left.max(Duration::from_millis(1)))
                .unwrap_or(PollTimeout::MAX);
            let mut fds = [PollFd::new(s.as_fd(), flags)];
            match poll(&mut fds, timeout) {
                Ok(0) => return Err(EgressFailure::DeadlineExpired),
                Ok(_) => return Ok(()),
                Err(nix::errno::Errno::EINTR) => continue,
                Err(e) => return Err(Self::transport(format!("poll: {e}"))),
            }
        }
    }

    /// `write_all` under the budget: NON-BLOCKING writes, each preceded by a
    /// `poll` for what is left. A blocking write under `SO_SNDTIMEO` is not
    /// bounded by that timer against a peer that drains one byte per
    /// interval — macOS restarts the timer every time a byte of space frees,
    /// inside the one syscall (measured: 1.7 s past a 400 ms budget) — and
    /// std's `write_all` would loop over such writes besides. This is the leg
    /// that carries the prompt plaintext, to an untrusted peer (module
    /// header). The socket is returned to blocking for the read leg.
    fn write_all_by(
        s: &mut UnixStream,
        buf: &[u8],
        deadline_at: Instant,
    ) -> Result<(), EgressFailure> {
        s.set_nonblocking(true).map_err(Self::transport)?;
        let mut written = 0;
        let out = loop {
            if written >= buf.len() {
                break Ok(());
            }
            if let Err(e) = Self::wait_writable(s, deadline_at) {
                break Err(e);
            }
            match s.write(&buf[written..]) {
                Ok(n) => written += n,
                Err(e) if Self::write_is_retried(&e) => continue,
                Err(e) => break Err(Self::transport(format!("write: {e}"))),
            }
        };
        s.set_nonblocking(false).map_err(Self::transport)?;
        out
    }

    /// The write errors the budget loop absorbs: a signal mid-syscall, and a
    /// non-blocking write with no space yet (`poll` reported writability a
    /// moment ago; the next `poll` re-asks the budget).
    fn write_is_retried(e: &std::io::Error) -> bool {
        matches!(
            e.kind(),
            std::io::ErrorKind::Interrupted | std::io::ErrorKind::WouldBlock
        )
    }

    /// `read_exact` under the budget: readability is awaited before EVERY
    /// read. std's own loops over reads that each get the full socket
    /// timeout, so a deputy dribbling one byte per interval would never be
    /// cut off by it — the deputy is authenticated but untrusted (this
    /// module's header).
    fn read_exact_by(
        s: &mut UnixStream,
        buf: &mut [u8],
        deadline_at: Instant,
    ) -> Result<(), EgressFailure> {
        let mut filled = 0;
        while filled < buf.len() {
            Self::wait_readable(s, deadline_at)?;
            match s.read(&mut buf[filled..]) {
                Ok(0) => {
                    return Err(EgressFailure::Transport(
                        "deputy closed the connection mid-frame".into(),
                    ))
                }
                Ok(n) => filled += n,
                Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
                Err(e) => return Err(Self::transport(e)),
            }
        }
        Ok(())
    }
}

impl Egress for SocketEgress {
    /// The configured `egress.deadline_ms`: a WALL-CLOCK budget over the whole
    /// exchange — every write is sent under a timer re-armed to what is left
    /// (`write_all_by`) and every read is preceded by a `poll` for what is
    /// left (`read_exact_by`), so per-operation timers cannot be strung
    /// together past it in either direction. The one step outside it is `connect`, which on a Unix socket
    /// completes or fails at once unless the listener's backlog is full; the
    /// kernel's outer `tokio::time::timeout` on the same value then abandons
    /// the worker and the egress breaker counts the expiry.
    fn deadline(&self) -> Duration {
        self.timeout
    }
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
        let deadline_at = Instant::now() + self.timeout;
        let stream = UnixStream::connect(&self.path).map_err(Self::transport)?;

        // BEFORE the first write. Moving this below the write hands prompt
        // content and a Vault path to an unauthenticated peer. A capture error
        // refuses too: a peer we cannot identify cannot be policed. The
        // credentials seen here are the LISTENER's at listen(2): the deputy's
        // own for a self-bound listener, or root's for the one the init
        // system creates and hands over (ADR-0023 correction 1, prototyped
        // here) — `listener_uid_is` accepts exactly those two.
        if !maknae_vault::listener_uid_is(&stream, self.expected_uid).map_err(Self::transport)? {
            return Err(EgressFailure::Transport(
                "egress peer is not the expected uid".into(),
            ));
        }

        let frame = EgressFrameRequest {
            destination: req.destination,
            endpoint: req.endpoint,
            model: req.model,
            key_vault_path: req.key_vault_path,
            key_field: req.key_field,
            conversation: req.conversation,
            content: req.content,
        };
        let buf = encode_egress_frame_request(&frame).map_err(Self::transport)?;
        // BEFORE the first write, so an over-cap request is a pre-send failure
        // (`Failed`, nothing left) and never "outcome unknown" (the deputy
        // would refuse it as oversize only after reading it).
        // The comparison is the T1 predicate's (`frame_len_within_cap`, proven
        // at the boundary), the same one the reply cap uses below.
        if !crate::egress::frame_len_within_cap(
            buf.len(),
            crate::egress::EGRESS_MAX_REQUEST_FRAME_BYTES,
        ) {
            eprintln!(
                "maknaed: egress request frame of {} bytes over the {}-byte cap — refused before sending",
                buf.len(),
                crate::egress::EGRESS_MAX_REQUEST_FRAME_BYTES
            );
            return Err(EgressFailure::Transport(format!(
                "request frame of {} bytes over the {}-byte cap",
                buf.len(),
                crate::egress::EGRESS_MAX_REQUEST_FRAME_BYTES
            )));
        }

        let mut s = stream;
        Self::arm(&s, deadline_at)?;
        // FROM HERE ON the request is leaving: every failure below is
        // `AfterSend`, recorded as delivery-unknown (codex on #240 — the
        // deputy closes the connection when its provider call fails or times
        // out, and the provider may already have the prompt).
        Self::write_all_by(&mut s, &(buf.len() as u32).to_be_bytes(), deadline_at)
            .map_err(Self::after_send)?;
        Self::write_all_by(&mut s, &buf, deadline_at).map_err(Self::after_send)?;
        s.flush()
            .map_err(Self::transport)
            .map_err(Self::after_send)?;

        let mut len = [0u8; 4];
        Self::read_exact_by(&mut s, &mut len, deadline_at).map_err(Self::after_send)?;
        let n = u32::from_be_bytes(len) as usize;
        // BEFORE the allocation. The deputy is authenticated but untrusted (see
        // this module's header), so a four-byte length prefix must not be able
        // to make the kernel reserve up to 4 GiB. The CBOR decode and
        // `admitted_reply` run later and would never see it.
        //
        // The comparison itself lives in the T1 module as a pure predicate, and
        // is proven there on a table of integers (`u32::MAX` included). Inline
        // here it was only reachable through a socket, so the operators `>` vs
        // `==`/`<` could only be distinguished by a test that declared
        // `u32::MAX` — and a mutant that removed the guard allocated and
        // zeroized 4 GiB, timing the mutation lane out instead of failing an
        // assertion. Do not inline it back.
        if !crate::egress::frame_len_within_cap(n, self.max_frame_bytes) {
            return Err(EgressFailure::AfterSend(format!(
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
        Self::read_exact_by(&mut s, &mut body, deadline_at).map_err(Self::after_send)?;
        let reply = decode_egress_frame_reply(&body)
            .map_err(Self::transport)
            .map_err(Self::after_send)?;
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
            key_vault_path: "maknae/providers/openai".into(),
            key_field: "api-key".into(),
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
        if me == 0 {
            // A root-created listener is the init system's delegation and is
            // accepted by design (`listener_uid_is`); the refusal cannot be
            // shown from under root. The pure predicate is pinned in
            // maknae-vault's peer_identity tests regardless of the runner.
            eprintln!("skipped: running as root");
            return;
        }
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

    /// The deadline is a WALL-CLOCK budget over the whole exchange, not a
    /// per-`recv` timer: a deputy that dribbles one byte at a time, each
    /// inside the socket timeout, must still be cut off at the deadline.
    /// (Authenticated but untrusted — this module's header.) The listener
    /// here answers a valid length prefix and then one body byte per 150 ms
    /// against a 400 ms deadline.
    #[test]
    fn a_dribbling_deputy_is_cut_off_at_the_deadline_not_per_read() {
        let d = tempfile::tempdir().unwrap();
        let path = d.path().join("egress.sock");
        let l = UnixListener::bind(&path).unwrap();
        std::thread::spawn(move || {
            if let Ok((mut c, _)) = l.accept() {
                let mut len = [0u8; 4];
                if c.read_exact(&mut len).is_ok() {
                    let n = u32::from_be_bytes(len) as usize;
                    let mut body = vec![0u8; n];
                    if c.read_exact(&mut body).is_ok() {
                        let _ = c.write_all(&8u32.to_be_bytes());
                        for _ in 0..8 {
                            std::thread::sleep(Duration::from_millis(150));
                            if c.write_all(&[0u8]).is_err() {
                                break;
                            }
                        }
                    }
                }
            }
        });
        let me = nix::unistd::getuid().as_raw();
        let e = SocketEgress::new(path, me, Duration::from_millis(400), 64 * 1024);
        let intent = crate::egress::DurableEgressIntent::canned_for_test();
        let started = std::time::Instant::now();
        let out = e.send(&intent, req());
        let took = started.elapsed();
        assert_eq!(
            out,
            Err(EgressFailure::DeadlineExpired),
            "an inner expiry is delivery-unknown, never a plain failure"
        );
        assert!(
            took < Duration::from_millis(900),
            "the dribble was allowed to run past the deadline: {took:?}"
        );
    }

    /// A budget already spent is `DeadlineExpired` at every step that consults
    /// it — before arming the socket, before waiting, before reading — and a
    /// live budget arms the socket with what is left.
    #[test]
    fn a_spent_budget_is_deadline_expired_at_every_step() {
        let past = Instant::now() - Duration::from_secs(1);
        let (a, _b) = UnixStream::pair().unwrap();
        assert_eq!(
            SocketEgress::remaining(past).unwrap_err(),
            EgressFailure::DeadlineExpired
        );
        assert_eq!(
            SocketEgress::arm(&a, past).unwrap_err(),
            EgressFailure::DeadlineExpired
        );
        assert_eq!(
            SocketEgress::wait_readable(&a, past).unwrap_err(),
            EgressFailure::DeadlineExpired
        );
        let mut a = a;
        let mut buf = [0u8; 1];
        assert_eq!(
            SocketEgress::read_exact_by(&mut a, &mut buf, past).unwrap_err(),
            EgressFailure::DeadlineExpired
        );
        let live = Instant::now() + Duration::from_secs(5);
        assert!(SocketEgress::remaining(live).unwrap() > Duration::from_secs(4));
        SocketEgress::arm(&a, live).unwrap();
        assert!(a.read_timeout().unwrap().unwrap() > Duration::from_secs(4));
    }

    /// The same budget on the WRITE leg — the one carrying the prompt
    /// plaintext. A peer that drains one byte per interval (eight of them,
    /// then nothing) against a request larger than any socket buffer must be
    /// cut off at the deadline, as `DeadlineExpired`, not strung along one
    /// full send timer per `write`.
    #[test]
    fn a_peer_that_drains_the_request_a_byte_at_a_time_is_cut_off_at_the_deadline() {
        let d = tempfile::tempdir().unwrap();
        let path = d.path().join("egress.sock");
        let l = UnixListener::bind(&path).unwrap();
        std::thread::spawn(move || {
            if let Ok((mut c, _)) = l.accept() {
                let mut b = [0u8; 1];
                for _ in 0..8 {
                    std::thread::sleep(Duration::from_millis(150));
                    if c.read(&mut b).is_err() {
                        break;
                    }
                }
                std::thread::sleep(Duration::from_secs(3));
            }
        });
        let me = nix::unistd::getuid().as_raw();
        let e = SocketEgress::new(path, me, Duration::from_millis(400), 64 * 1024);
        let intent = crate::egress::DurableEgressIntent::canned_for_test();
        let mut big = req();
        // under the request cap, over any socket buffer
        big.content = vec![ContentBlock::Text {
            text: SecretText(maknae_io::Zeroizing::new("x".repeat(900 * 1024))),
        }];
        let started = std::time::Instant::now();
        let out = e.send(&intent, big);
        let took = started.elapsed();
        assert_eq!(out, Err(EgressFailure::DeadlineExpired), "got {out:?}");
        assert!(
            took < Duration::from_millis(900),
            "the write leg was allowed to run past the deadline: {took:?}"
        );
    }

    /// A request over the deputy's frame cap is refused BEFORE the first
    /// write — a pre-send `Transport` (`Failed`), and the peer sees nothing —
    /// rather than written, refused by the deputy as oversize, and recorded
    /// "outcome unknown" for a prompt no provider ever saw.
    #[test]
    fn an_over_cap_request_is_refused_before_anything_is_written() {
        let d = tempfile::tempdir().unwrap();
        let (path, seen) = fake_deputy(d.path(), None);
        let me = nix::unistd::getuid().as_raw();
        let e = SocketEgress::new(path, me, Duration::from_secs(2), 64 * 1024);
        let intent = crate::egress::DurableEgressIntent::canned_for_test();
        let mut big = req();
        big.content = vec![ContentBlock::Text {
            text: SecretText(maknae_io::Zeroizing::new(
                "x".repeat(crate::egress::EGRESS_MAX_REQUEST_FRAME_BYTES),
            )),
        }];
        match e.send(&intent, big) {
            Err(EgressFailure::Transport(m)) => {
                assert!(m.contains("request frame"), "{m}")
            }
            other => panic!("expected a pre-send cap refusal, got {other:?}"),
        }
        std::thread::sleep(Duration::from_millis(120));
        assert_eq!(seen.load(Ordering::SeqCst), 0, "bytes reached the peer");
    }

    /// The client-side check is the LISTENER predicate, by name. Reverting it
    /// to the exact-uid one leaves every socket test green — they bind their
    /// listeners in-process, so listener and connector share a uid — and
    /// refuses every production send under socket activation (ADR-0023
    /// correction 1). Pinned at the source, the way boot_gate.rs pins its
    /// ordering; the patterns are composed so this test does not match itself.
    #[test]
    fn the_send_path_checks_the_listener_predicate_not_the_exact_uid() {
        let src = include_str!("egress_socket.rs");
        let listener = format!("maknae_vault::{}(&stream,", "listener_uid_is");
        let exact = format!("{}(&stream", "peer_uid_is");
        assert!(
            src.contains(&listener),
            "the send path must check the listener predicate"
        );
        assert!(
            !src.contains(&exact),
            "the exact-uid check refuses every socket-activated listener"
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
    fn a_deputy_that_answers_with_garbage_is_a_post_send_failure_outcome_unknown() {
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
            Err(EgressFailure::AfterSend(_))
        ));
    }

    /// A deputy that hangs up before answering is a transport failure too —
    /// the content left, and the kernel must not invent a reply.
    #[test]
    fn a_deputy_that_hangs_up_is_a_post_send_failure_outcome_unknown() {
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
            Err(EgressFailure::AfterSend(_))
        ));
    }

    /// A four-byte length prefix from the deputy must NOT become a giant
    /// allocation. The deputy is authenticated but untrusted — this file says
    /// so in its own header — so a compromised or faulty one exhausting the
    /// kernel with four bytes is a denial of service the protocol admission
    /// never sees, because the allocation happens first.
    ///
    /// This test's job is the WIRING: that `send` consults the cap predicate at
    /// all, on the real socket path. The predicate's operators are proven on a
    /// table in `egress::tests` — `u32::MAX` included, at no cost.
    ///
    /// It declares 8 MiB over a 64 KiB cap rather than `u32::MAX`
    /// DELIBERATELY. With `u32::MAX`, a mutant that neutralises the guard makes
    /// the kernel allocate and zeroize 4 GiB, so the mutation lane reported
    /// TIMEOUT (a clock result, machine-dependent, `cargo mutants` exit 3)
    /// instead of an assertion failure. 128x over the cap proves the refusal
    /// just as well and, when the guard is gone, fails in milliseconds.
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
                    // Declare far more than the cap and send nothing after
                    // it. A kernel that pre-allocates reads EOF instead of the
                    // cap refusal, which is the discriminator below.
                    let _ = c.write_all(&(8u32 * 1024 * 1024).to_be_bytes());
                }
            }
        });
        let me = nix::unistd::getuid().as_raw();
        let e = SocketEgress::new(path, me, Duration::from_secs(2), 64 * 1024);
        let intent = crate::egress::DurableEgressIntent::canned_for_test();
        let out = e.send(&intent, req());
        match out {
            Err(EgressFailure::AfterSend(m)) => {
                // The CAP message specifically, not merely any post-send
                // failure: a kernel that allocated first and then hit EOF also
                // returns AfterSend, and that is exactly the defect.
                assert!(
                    m.contains("over the") && m.contains("cap"),
                    "expected the frame-cap refusal, got: {m}"
                )
            }
            other => panic!("expected a refusal, got {other:?}"),
        }
    }

    /// A deputy that declares `declared` bytes and sends `declared` bytes of
    /// junk. Used to probe the cap AT its boundary.
    fn deputy_declaring(dir: &std::path::Path, declared: u32) -> PathBuf {
        let path = dir.join("egress.sock");
        let l = UnixListener::bind(&path).unwrap();
        std::thread::spawn(move || {
            if let Ok((mut c, _)) = l.accept() {
                let mut len = [0u8; 4];
                if c.read_exact(&mut len).is_ok() {
                    let n = u32::from_be_bytes(len) as usize;
                    let mut body = vec![0u8; n];
                    let _ = c.read_exact(&mut body);
                    let _ = c.write_all(&declared.to_be_bytes());
                    let _ = c.write_all(&vec![0u8; declared as usize]);
                }
            }
        });
        path
    }

    /// THE BOUNDARY. #295: `>` → `>=` at the cap survived mutation because the
    /// only test ever declared `u32::MAX`, where both operators refuse alike. A
    /// test that never approaches the limit cannot distinguish them — the
    /// PRIORITIES lesson verbatim, *a test that validates a mechanism at a
    /// value the production path never produces*.
    ///
    /// At EXACTLY the cap the frame must be ACCEPTED by the cap check (it then
    /// fails to decode, because it is junk — a different error, which is the
    /// discriminator). At cap+1 it must be refused as over-cap.
    #[test]
    fn the_frame_cap_refuses_above_it_and_admits_at_it() {
        let cap = 4096usize;
        let me = nix::unistd::getuid().as_raw();

        // n == cap: past the cap check, so the failure is a DECODE failure.
        let d1 = tempfile::tempdir().unwrap();
        let e1 = SocketEgress::new(
            deputy_declaring(d1.path(), cap as u32),
            me,
            Duration::from_secs(2),
            cap,
        );
        match e1.send(&crate::egress::DurableEgressIntent::canned_for_test(), req()) {
            Err(EgressFailure::AfterSend(m)) => assert!(
                !m.contains("over the"),
                "a frame EXACTLY at the cap was refused as over-cap — the check is `>=`, not `>`: {m}"
            ),
            other => panic!("expected a decode-stage transport failure, got {other:?}"),
        }

        // n == cap + 1: refused by the cap, before any allocation.
        let d2 = tempfile::tempdir().unwrap();
        let e2 = SocketEgress::new(
            deputy_declaring(d2.path(), cap as u32 + 1),
            me,
            Duration::from_secs(2),
            cap,
        );
        match e2.send(
            &crate::egress::DurableEgressIntent::canned_for_test(),
            req(),
        ) {
            Err(EgressFailure::AfterSend(m)) => assert!(
                m.contains("over the"),
                "a frame one byte over the cap was NOT refused as over-cap: {m}"
            ),
            other => panic!("expected an over-cap refusal, got {other:?}"),
        }
    }
}
