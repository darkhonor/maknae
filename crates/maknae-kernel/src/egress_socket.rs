//! The kernel's egress backend: one decided request, over one connection, to
//! the `maknae-egress` deputy (#240a D2/D3).
//!
//! **One connection per request** (D2). Case-4 orchestration means concurrent
//! fan-out to several conduits at once — `Egress` is `Send + Sync` and `send`
//! takes `&self` on a blocking worker, so the signature already admits it. One
//! connection per request is naturally concurrent, needs no correlation id and
//! no reply demuxer, and — the stronger reason — makes the peer-credential
//! check run **per request** rather than once on a long-lived connection.
//! The deputy serves connections concurrently up to its capacity and answers
//! one past it `AtCapacity` at once (`bins/maknae-egress/src/serve.rs`, #321),
//! so the deadline below bounds one call, not a queue. Past its refusal slots
//! as well, it closes the connection unanswered: recorded delivery unknown,
//! or `Failed` on macOS when the close lands before `arm`.
//!
//! **Peer credentials are checked BEFORE the first write** (D3). The request
//! carries prompt content and the Vault path naming where the provider
//! credential lives; writing first and checking after would defeat the point.
//! The path is not the boundary — a socket path can be replaced by anything
//! that can write the directory; a uid cannot be forged.

use crate::egress::DurableEgressIntent;
use crate::egress::{Egress, EgressFailure, EgressReply, EgressRequest};
use maknae_proto::{
    decode_egress_socket_reply, encode_egress_frame, EgressFrame, EgressFrameReply,
    EgressFrameRequest, EgressSocketReply, ReachRefusal, ReachReply, ReachRequest,
};
use std::io::{Read, Write};
use std::os::unix::net::UnixStream;
use std::path::PathBuf;
use std::sync::Arc;
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
                // A plain `if`, not a match guard: the retry decision is
                // mutated and proven once, in the predicate (#295).
                Err(e) => {
                    if Self::write_is_retried(&e) {
                        continue; // EAGAIN or EINTR: re-ask the budget
                    }
                    break Err(Self::transport(format!("write: {e}")));
                }
            }
        };
        s.set_nonblocking(false).map_err(Self::transport)?;
        out
    }

    /// Write errors the budget loop absorbs: EINTR, and EAGAIN after `poll`
    /// reported writable. Anything else is fatal and reported at once.
    fn write_is_retried(e: &std::io::Error) -> bool {
        matches!(
            e.kind(),
            std::io::ErrorKind::Interrupted | std::io::ErrorKind::WouldBlock
        )
    }

    /// Read errors the budget loop absorbs: EINTR only, as `read_exact`
    /// does. `WouldBlock` is `SO_RCVTIMEO` firing after `poll` reported
    /// readable; refused (#349).
    fn read_is_retried(e: &std::io::Error) -> bool {
        matches!(e.kind(), std::io::ErrorKind::Interrupted)
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
                // Same shape as the write leg, for the same reason: the
                // decision lives in `read_is_retried`, proven on a table.
                Err(e) => {
                    if Self::read_is_retried(&e) {
                        continue; // EINTR: re-ask the budget
                    }
                    return Err(Self::transport(e));
                }
            }
        }
        Ok(())
    }

    /// One frame over one connection, under the wall-clock `deadline_at`: connect, the
    /// listener's uid before the first write, the request cap, then the reply.
    fn exchange(
        &self,
        frame: &EgressFrame,
        deadline_at: Instant,
    ) -> Result<EgressSocketReply, EgressFailure> {
        let stream = UnixStream::connect(&self.path).map_err(connect_failure)?;

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

        // MEASURED FIRST, allocated second (#241, codex round 2 item C). The
        // counting pass serializes through a sink that stores nothing, so the
        // exact encoded length is known before a byte of frame content is
        // held anywhere — including for a frame far too large to encode.
        //
        // The ordering is the fix: with the encode buffer sized at the cap
        // plus one page, the cap refusal below was reachable only inside that
        // 4 KiB band, and anything further over died in the encoder as an
        // opaque `failed to write whole buffer` — no size, no cap, and none of
        // the operator line below. Now every over-cap size meets this
        // refusal, and the buffer needs no headroom to avoid shadowing it.
        let len = maknae_proto::egress_frame_encoded_len(frame).map_err(Self::transport)?;
        // BEFORE the first write, so an over-cap request is a pre-send failure
        // (`Failed`, nothing left) and never "outcome unknown" (the deputy
        // would refuse it as oversize only after reading it).
        // The comparison is the T1 predicate's (`frame_len_within_cap`, proven
        // at the boundary), the same one the reply cap uses below.
        if !crate::egress::frame_len_within_cap(len, crate::egress::EGRESS_MAX_REQUEST_FRAME_BYTES)
        {
            eprintln!(
                "maknaed: egress request frame of {len} bytes over the {}-byte cap — refused before sending",
                crate::egress::EGRESS_MAX_REQUEST_FRAME_BYTES
            );
            return Err(EgressFailure::Transport(format!(
                "request frame of {len} bytes over the {}-byte cap",
                crate::egress::EGRESS_MAX_REQUEST_FRAME_BYTES
            )));
        }
        // Into ONE fixed preallocation, at EXACTLY the measured length, that
        // never grows (#241, codex round 1 critical 3): a `Tool` turn carries
        // kernel-served file content, and the growing buffer this replaces
        // freed a partly-written copy of it on every realloc. The encode
        // cannot overflow — it was measured — and an `Encode` here would still
        // be pre-send: nothing written, nothing left with the peer.
        let buf = encode_egress_frame(frame, len).map_err(Self::transport)?;

        let mut s = stream;
        Self::arm(&s, deadline_at)?;
        // FROM HERE ON the request is leaving: every failure below is
        // `AfterSend`, recorded as delivery-unknown (codex on #240).
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
        // decode drops this buffer just the same.
        let mut body = maknae_io::Zeroizing::new(vec![0u8; n]);
        Self::read_exact_by(&mut s, &mut body, deadline_at).map_err(Self::after_send)?;
        decode_egress_socket_reply(&body)
            .map_err(Self::transport)
            .map_err(Self::after_send)
    }
}

impl Egress for SocketEgress {
    /// The configured `egress.deadline_ms`: a WALL-CLOCK budget over the whole
    /// exchange — every non-blocking write is preceded by a `poll` for what is
    /// left (`write_all_by`) and every read is preceded by a `poll` for what is
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
        let frame = EgressFrame::Prompt(frame_of(req, self.timeout));
        match self.exchange(&frame, deadline_at)? {
            EgressSocketReply::Prompt(EgressFrameReply::Reply(reply)) => Ok(EgressReply { reply }),
            EgressSocketReply::Prompt(EgressFrameReply::Unusable { defect, usage }) => {
                Err(EgressFailure::ReplyUnusable { defect, usage })
            }
            EgressSocketReply::RefusedBeforeSend => Err(EgressFailure::RefusedBeforeSend),
            EgressSocketReply::AtCapacity => Err(EgressFailure::DeputyAtCapacity),
            EgressSocketReply::Mint(_)
            | EgressSocketReply::Revoke(_)
            | EgressSocketReply::Reach(_) => Err(Self::after_send(Self::transport(
                maknae_proto::ProtoCodecError::Decode(
                    "a credential reply to a prompt frame".into(),
                ),
            ))),
        }
    }
}

/// What became of one reach frame: the deputy's reach reply, or no reach reply at all.
#[derive(Debug, PartialEq, Eq)]
pub enum ReachOutcome {
    Reply(ReachReply),
    Unanswered(Unanswered),
}

/// Why a reach frame has no reach reply. Each refuses as [`ReachRefusal::Unanswered`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Unanswered {
    /// The deputy answered the generic `AtCapacity` before reading the frame.
    AtCapacity,
    /// Nothing reached the deputy: no socket, no deputy, or a peer that is not it.
    NotSent(String),
    /// The frame left and no reach reply came back.
    Unknown(String),
}

impl Unanswered {
    pub fn class(&self) -> ReachRefusal {
        ReachRefusal::Unanswered
    }

    pub fn trail(&self) -> String {
        match self {
            Self::AtCapacity => "reach outcome unknown: at capacity".into(),
            Self::NotSent(why) => format!("reach not sent: {why}"),
            Self::Unknown(why) => format!("reach outcome unknown: {why}"),
        }
    }

    fn of(e: EgressFailure) -> Self {
        match e {
            EgressFailure::Transport(m) | EgressFailure::DeputyUnreachable(m) => Self::NotSent(m),
            EgressFailure::NotConfigured => Self::NotSent("no egress socket".into()),
            EgressFailure::AfterSend(m) => Self::Unknown(m),
            EgressFailure::DeadlineExpired => Self::Unknown("the socket wait expired".into()),
            EgressFailure::DeputyAtCapacity => Self::AtCapacity,
            EgressFailure::RefusedBeforeSend
            | EgressFailure::KernelAtCapacity
            | EgressFailure::CircuitOpen
            | EgressFailure::ReplyUnusable { .. } => Self::Unknown(format!("{e:?}")),
        }
    }
}

/// How long the kernel waits on one reach frame: its `deadline_ms`, then one more forge call
/// for the revokes the Egress Daemon makes on exit, then the deadline margin.
pub fn reach_socket_wait(deadline_ms: u64) -> Duration {
    Duration::from_millis(
        deadline_ms
            .saturating_add(maknae_config::FORGE_CALL_TIMEOUT_MS)
            .saturating_add(maknae_config::DEADLINE_MARGIN_MS),
    )
}

/// Observes reach through the Egress Daemon, one frame per call.
pub trait ReachEgress: Send + Sync {
    /// Whether the Egress Daemon's socket is there to ask; without it no reach is observed.
    fn has_socket(&self) -> bool;
    fn reach(&self, req: ReachRequest) -> ReachOutcome;
}

impl ReachEgress for SocketEgress {
    fn has_socket(&self) -> bool {
        self.path.exists()
    }

    fn reach(&self, req: ReachRequest) -> ReachOutcome {
        let deadline_at = Instant::now() + reach_socket_wait(req.deadline_ms());
        match self.exchange(&EgressFrame::Reach(req), deadline_at) {
            Ok(EgressSocketReply::Reach(reply)) => ReachOutcome::Reply(reply),
            Ok(EgressSocketReply::AtCapacity) => ReachOutcome::Unanswered(Unanswered::AtCapacity),
            Ok(
                EgressSocketReply::Prompt(_)
                | EgressSocketReply::RefusedBeforeSend
                | EgressSocketReply::Mint(_)
                | EgressSocketReply::Revoke(_),
            ) => ReachOutcome::Unanswered(Unanswered::Unknown(
                "a non-reach reply to a reach frame".into(),
            )),
            Err(e) => ReachOutcome::Unanswered(Unanswered::of(e)),
        }
    }
}

/// The handle when the Egress Daemon's account is not there to check the socket against.
struct NoReachSocket(String);

impl ReachEgress for NoReachSocket {
    fn has_socket(&self) -> bool {
        false
    }

    fn reach(&self, _req: ReachRequest) -> ReachOutcome {
        ReachOutcome::Unanswered(Unanswered::NotSent(self.0.clone()))
    }
}

/// A reach handle that sends nothing, saying `why`.
pub fn no_reach(why: &str) -> Arc<dyn ReachEgress> {
    Arc::new(NoReachSocket(why.to_owned()))
}

/// The reach handle on `egress.socket_path`, whether or not any provider is authorized.
pub fn production_reach_with(
    cfg: &maknae_config::EgressConfig,
    resolve_uid: impl FnOnce(&str) -> Result<Option<u32>, String>,
) -> Arc<dyn ReachEgress> {
    match resolve_uid(crate::egress::EGRESS_USER) {
        Ok(Some(uid)) => Arc::new(SocketEgress::new(
            cfg.socket_path.clone(),
            uid,
            Duration::from_millis(cfg.deadline_ms),
            crate::egress::EGRESS_MAX_REPLY_FRAME_BYTES,
        )),
        Ok(None) => Arc::new(NoReachSocket(format!(
            "the egress deputy's account '{}' does not exist on this host",
            crate::egress::EGRESS_USER
        ))),
        Err(e) => Arc::new(NoReachSocket(format!(
            "the egress deputy's account could not be resolved: {e}"
        ))),
    }
}

pub fn production_reach(cfg: &maknae_config::EgressConfig) -> Arc<dyn ReachEgress> {
    production_reach_with(cfg, crate::egress::resolve_account_uid)
}

/// Only a deputy that is not running (refused, socket gone, backlog full) is
/// unavailability; any other connect error is a deployment fault and stays a
/// generic transport failure (#321).
fn connect_failure(e: std::io::Error) -> EgressFailure {
    use std::io::ErrorKind as K;
    match e.kind() {
        K::ConnectionRefused | K::NotFound | K::WouldBlock => {
            EgressFailure::DeputyUnreachable(e.to_string())
        }
        _ => EgressFailure::Transport(e.to_string()),
    }
}

fn frame_of(req: EgressRequest, deadline: Duration) -> EgressFrameRequest {
    EgressFrameRequest {
        deadline_ms: Some(deadline.as_millis() as u64),
        destination: req.destination,
        endpoint: req.endpoint,
        model: req.model,
        key_vault_path: req.key_vault_path,
        key_field: req.key_field,
        sealed_key: req.sealed_key,
        reasoning_effort: req.reasoning_effort,
        conversation: req.conversation,
        turns: req.turns,
        output_tokens: req.output_tokens,
        output_tokens_field: req.output_tokens_field,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use maknae_proto::{ContentBlock, SecretText, Turn};
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
            sealed_key: maknae_proto::SealedKey::new(vec![
                0x5a;
                maknae_proto::SEALED_KEY_MIN_BYTES
            ])
            .unwrap(),
            reasoning_effort: Some("none".into()),
            output_tokens: None,
            output_tokens_field: None,
            conversation: "conv1".into(),
            turns: vec![Turn::User {
                content: vec![ContentBlock::Text {
                    text: SecretText::from(maknae_io::Zeroizing::new(
                        "the president flies at 0300".into(),
                    )),
                }],
            }],
        }
    }

    #[test]
    fn the_frame_carries_every_field_of_the_request() {
        let mut r = req();
        r.output_tokens = Some(4_096);
        r.output_tokens_field = Some(maknae_proto::OutputTokensField::MaxTokens);
        let f = frame_of(r.clone(), Duration::from_secs(1));
        assert_eq!(f.destination, r.destination);
        assert_eq!(f.endpoint, r.endpoint);
        assert_eq!(f.model, r.model);
        assert_eq!(f.key_vault_path, r.key_vault_path);
        assert_eq!(f.key_field, r.key_field);
        assert_eq!(f.sealed_key, r.sealed_key);
        assert_eq!(f.reasoning_effort.as_deref(), Some("none"));
        assert_eq!(f.conversation, r.conversation);
        assert_eq!(f.turns, r.turns);
        assert_eq!(f.output_tokens, Some(4_096));
        assert_eq!(
            f.output_tokens_field,
            Some(maknae_proto::OutputTokensField::MaxTokens)
        );
    }

    /// A fake deputy. Returns how many bytes it ever read, so a test can assert
    /// that a refused connection wrote NOTHING.
    fn fake_deputy(
        dir: &std::path::Path,
        reply: Option<EgressSocketReply>,
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
                            let out = maknae_proto::encode_egress_socket_reply(
                                &r,
                                maknae_proto::EGRESS_REPLY_FRAME_ENCODE_BYTES,
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
        big.turns = vec![Turn::User {
            content: vec![ContentBlock::Text {
                text: SecretText::from(maknae_io::Zeroizing::new("x".repeat(900 * 1024))),
            }],
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
    ///
    /// A TABLE OF SIZES, and that is the point (codex round 2, item C). With
    /// the fixed encode buffer sized at the cap plus one page, this refusal
    /// was reachable only inside that 4 KiB band: anything further over died
    /// in the encoder as `Transport("proto encode: failed to write whole
    /// buffer")` — no size, no cap, and none of the operator `eprintln!`
    /// below. A counting pass now gives the exact encoded length BEFORE
    /// anything is allocated, so every over-cap size meets this one message.
    /// The 2-MiB-over row is the one that was RED.
    #[test]
    fn an_over_cap_request_is_refused_before_anything_is_written() {
        let cap = crate::egress::EGRESS_MAX_REQUEST_FRAME_BYTES;
        for over in [cap, cap + 2 * 1024 * 1024] {
            let d = tempfile::tempdir().unwrap();
            let (path, seen) = fake_deputy(d.path(), None);
            let me = nix::unistd::getuid().as_raw();
            let e = SocketEgress::new(path, me, Duration::from_secs(2), 64 * 1024);
            let intent = crate::egress::DurableEgressIntent::canned_for_test();
            let mut big = req();
            big.turns = vec![Turn::User {
                content: vec![ContentBlock::Text {
                    text: SecretText::from(maknae_io::Zeroizing::new("x".repeat(over))),
                }],
            }];
            match e.send(&intent, big) {
                Err(EgressFailure::Transport(m)) => {
                    // The OPERATOR-READABLE refusal, not the codec's string:
                    // it names the measured size and the cap it exceeded.
                    assert!(m.contains("request frame"), "{over}: {m}");
                    assert!(m.contains(&cap.to_string()), "{over}: {m}");
                    assert!(
                        !m.contains("proto encode"),
                        "{over}: the encoder answered first, shadowing the cap refusal: {m}"
                    );
                }
                other => panic!("expected a pre-send cap refusal at {over}, got {other:?}"),
            }
            std::thread::sleep(Duration::from_millis(120));
            assert_eq!(
                seen.load(Ordering::SeqCst),
                0,
                "{over}: bytes reached the peer"
            );
        }
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
            reasoning: None,
            blocks: vec![ContentBlock::Text {
                text: SecretText::from(maknae_io::Zeroizing::new("ok".into())),
            }],
            tool_calls: vec![],
            usage: None,
        };
        let (path, seen) = fake_deputy(
            d.path(),
            Some(EgressSocketReply::Prompt(EgressFrameReply::Reply(
                reply.clone(),
            ))),
        );
        let me = nix::unistd::getuid().as_raw();
        let e = SocketEgress::new(path, me, Duration::from_secs(2), 64 * 1024);
        let intent = crate::egress::DurableEgressIntent::canned_for_test();
        let got = e.send(&intent, req()).unwrap();
        assert_eq!(got.reply, reply);
        assert!(seen.load(Ordering::SeqCst) > 0);
    }

    #[test]
    fn a_deputy_that_refuses_before_any_provider_io_is_refused_before_send() {
        let d = tempfile::tempdir().unwrap();
        let (path, seen) = fake_deputy(d.path(), Some(EgressSocketReply::RefusedBeforeSend));
        let me = nix::unistd::getuid().as_raw();
        let e = SocketEgress::new(path, me, Duration::from_secs(2), 64 * 1024);
        let intent = crate::egress::DurableEgressIntent::canned_for_test();
        assert_eq!(
            e.send(&intent, req()).unwrap_err(),
            EgressFailure::RefusedBeforeSend
        );
        assert!(seen.load(Ordering::SeqCst) > 0);
    }

    #[test]
    fn a_deputy_at_capacity_is_a_named_refusal_not_a_lost_send() {
        let d = tempfile::tempdir().unwrap();
        let (path, seen) = fake_deputy(d.path(), Some(EgressSocketReply::AtCapacity));
        let me = nix::unistd::getuid().as_raw();
        let e = SocketEgress::new(path, me, Duration::from_secs(2), 64 * 1024);
        let intent = crate::egress::DurableEgressIntent::canned_for_test();
        assert_eq!(
            e.send(&intent, req()).unwrap_err(),
            EgressFailure::DeputyAtCapacity
        );
        assert!(seen.load(Ordering::SeqCst) > 0);
    }

    #[test]
    fn a_deputy_that_finds_the_reply_unusable_is_a_reply_unusable_failure() {
        let d = tempfile::tempdir().unwrap();
        let (path, _seen) = fake_deputy(
            d.path(),
            Some(EgressSocketReply::Prompt(EgressFrameReply::Unusable {
                defect: maknae_proto::ReplyDefect::ProviderRateLimit,
                usage: None,
            })),
        );
        let me = nix::unistd::getuid().as_raw();
        let e = SocketEgress::new(path, me, Duration::from_secs(2), 64 * 1024);
        let intent = crate::egress::DurableEgressIntent::canned_for_test();
        assert_eq!(
            e.send(&intent, req()).unwrap_err(),
            EgressFailure::ReplyUnusable {
                defect: maknae_proto::ReplyDefect::ProviderRateLimit,
                usage: None,
            }
        );
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
    fn only_a_deputy_that_is_not_running_is_unreachable() {
        use std::io::{Error, ErrorKind as K};
        for k in [K::ConnectionRefused, K::NotFound, K::WouldBlock] {
            assert!(
                matches!(
                    connect_failure(Error::from(k)),
                    EgressFailure::DeputyUnreachable(_)
                ),
                "{k:?}"
            );
        }
        for k in [
            K::PermissionDenied,
            K::NotADirectory,
            K::InvalidInput,
            K::Other,
        ] {
            assert!(
                matches!(connect_failure(Error::from(k)), EgressFailure::Transport(_)),
                "{k:?}"
            );
        }
    }

    #[test]
    fn a_connect_to_no_deputy_is_unreachable_not_a_refusal() {
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
            Err(EgressFailure::DeputyUnreachable(_))
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

    /// A table, not a socket: neither retryable kind can be produced through
    /// a real `UnixStream` on demand (EINTR needs a signal; EAGAIN cannot
    /// follow `poll`). The hard-error direction is covered on the wire below.
    #[test]
    fn a_retryable_write_error_is_retried_and_a_hard_one_is_not() {
        use std::io::{Error, ErrorKind};
        for kind in [ErrorKind::Interrupted, ErrorKind::WouldBlock] {
            assert!(
                SocketEgress::write_is_retried(&Error::from(kind)),
                "{kind:?} must be retried"
            );
        }
        for kind in [
            ErrorKind::BrokenPipe,
            ErrorKind::ConnectionReset,
            ErrorKind::TimedOut,
            ErrorKind::NotConnected,
            ErrorKind::Other,
        ] {
            assert!(
                !SocketEgress::write_is_retried(&Error::from(kind)),
                "{kind:?} must NOT be retried"
            );
        }
    }

    /// EINTR only. `WouldBlock` is the socket timer; refused, pinned so it
    /// cannot drift (#349).
    #[test]
    fn only_an_interrupted_read_is_retried() {
        use std::io::{Error, ErrorKind};
        assert!(
            SocketEgress::read_is_retried(&Error::from(ErrorKind::Interrupted)),
            "Interrupted must be retried"
        );
        for kind in [
            ErrorKind::WouldBlock,
            ErrorKind::TimedOut,
            ErrorKind::ConnectionReset,
            ErrorKind::UnexpectedEof,
            ErrorKind::Other,
        ] {
            assert!(
                !SocketEgress::read_is_retried(&Error::from(kind)),
                "{kind:?} must NOT be retried"
            );
        }
    }

    /// The deputy hangs up mid-body. The write failure must be reported,
    /// not the deadline: a loop that retried hard errors would spin until
    /// the budget is spent. The deputy reads the prefix first because the
    /// peer-credential check needs a live peer (macOS: `ENOTCONN` otherwise).
    #[test]
    fn a_peer_that_hangs_up_mid_write_is_reported_at_once_not_at_the_deadline() {
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
        // 2 s, like the sibling hang-up test: a tight budget gives a spurious
        // DeadlineExpired on a loaded runner.
        let e = SocketEgress::new(path, me, Duration::from_secs(2), 64 * 1024);
        let intent = crate::egress::DurableEgressIntent::canned_for_test();
        let mut big = req();
        // over the default socket buffers, under the request cap
        big.turns = vec![Turn::User {
            content: vec![ContentBlock::Text {
                text: SecretText::from(maknae_io::Zeroizing::new("x".repeat(900 * 1024))),
            }],
        }];
        match e.send(&intent, big) {
            Err(EgressFailure::AfterSend(m)) => assert!(
                m.starts_with("write: "),
                "expected the write failure to be reported, got: {m}"
            ),
            other => {
                panic!("a hard write error must be reported as AfterSend(write …), not {other:?}")
            }
        }
    }

    #[test]
    fn the_frame_carries_the_kernels_egress_deadline() {
        let f = frame_of(req(), Duration::from_millis(280_000));
        assert_eq!(f.deadline_ms, Some(280_000));
    }

    fn deputy_answering(dir: &std::path::Path, reply: Vec<u8>) -> PathBuf {
        let path = dir.join("egress.sock");
        let l = UnixListener::bind(&path).unwrap();
        std::thread::spawn(move || {
            if let Ok((mut c, _)) = l.accept() {
                let mut len = [0u8; 4];
                if c.read_exact(&mut len).is_ok() {
                    let mut body = vec![0u8; u32::from_be_bytes(len) as usize];
                    let _ = c.read_exact(&mut body);
                    let _ = c.write_all(&(reply.len() as u32).to_be_bytes());
                    let _ = c.write_all(&reply);
                }
            }
        });
        path
    }

    fn cbor(v: &impl serde::Serialize) -> Vec<u8> {
        let mut out = Vec::new();
        ciborium::into_writer(v, &mut out).unwrap();
        out
    }

    fn turn_of(n: usize) -> Turn {
        Turn::User {
            content: vec![ContentBlock::Text {
                text: SecretText::from(maknae_io::Zeroizing::new("x".repeat(n))),
            }],
        }
    }

    const CAP_TEST_TIMEOUT: Duration = Duration::from_secs(20);

    fn tagged_len(r: &EgressRequest) -> usize {
        maknae_proto::egress_frame_encoded_len(&EgressFrame::Prompt(frame_of(
            r.clone(),
            CAP_TEST_TIMEOUT,
        )))
        .unwrap()
    }

    /// A request whose TAGGED frame is exactly `target` bytes.
    fn request_of_tagged_len(target: usize) -> EgressRequest {
        let mut r = req();
        let probe = 1 << 20;
        r.turns = vec![turn_of(probe)];
        let base = tagged_len(&r) - probe;
        r.turns = vec![turn_of(target - base)];
        assert_eq!(tagged_len(&r), target);
        r
    }

    #[test]
    fn the_cap_counts_the_tagged_frame() {
        let cap = crate::egress::EGRESS_MAX_REQUEST_FRAME_BYTES;
        let me = nix::unistd::getuid().as_raw();
        let intent = crate::egress::DurableEgressIntent::canned_for_test();

        let at = request_of_tagged_len(cap);
        let d = tempfile::tempdir().unwrap();
        let (path, seen) = fake_deputy(d.path(), Some(EgressSocketReply::AtCapacity));
        let e = SocketEgress::new(path, me, CAP_TEST_TIMEOUT, 64 * 1024);
        assert_eq!(
            e.send(&intent, at).unwrap_err(),
            EgressFailure::DeputyAtCapacity
        );
        assert_eq!(
            seen.load(Ordering::SeqCst),
            4 + cap,
            "the bytes sent are the bytes measured"
        );

        let over = request_of_tagged_len(cap + 1);
        let bare = cbor(&frame_of(over.clone(), CAP_TEST_TIMEOUT)).len();
        assert!(bare <= cap, "the bare request alone fits: {bare}");
        let d = tempfile::tempdir().unwrap();
        let (path, seen) = fake_deputy(d.path(), None);
        let e = SocketEgress::new(path, me, CAP_TEST_TIMEOUT, 64 * 1024);
        match e.send(&intent, over) {
            Err(EgressFailure::Transport(m)) => assert!(
                m.contains(&format!("request frame of {} bytes", cap + 1)),
                "{m}"
            ),
            other => panic!("the tagged frame is over the cap, got {other:?}"),
        }
        std::thread::sleep(Duration::from_millis(120));
        assert_eq!(seen.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn an_at_capacity_reply_is_top_level_and_maps_to_the_prompts_at_capacity() {
        let me = nix::unistd::getuid().as_raw();
        let intent = crate::egress::DurableEgressIntent::canned_for_test();
        let top = maknae_proto::encode_egress_socket_reply(
            &EgressSocketReply::AtCapacity,
            maknae_proto::EGRESS_REPLY_FRAME_ENCODE_BYTES,
        )
        .unwrap();
        assert_eq!(&top[..], &cbor(&"at_capacity")[..]);
        for (bytes, want) in [
            (top.to_vec(), EgressFailure::DeputyAtCapacity),
            (
                cbor(&"refused_before_send"),
                EgressFailure::RefusedBeforeSend,
            ),
        ] {
            let d = tempfile::tempdir().unwrap();
            let e = SocketEgress::new(
                deputy_answering(d.path(), bytes),
                me,
                Duration::from_secs(2),
                64 * 1024,
            );
            let got = e.send(&intent, req()).unwrap_err();
            assert_eq!(
                crate::egress::outcome_for_failure(&got),
                crate::egress::SendOutcome::Failed
            );
            assert_eq!(got, want);
        }
        for nested in ["at_capacity", "refused_before_send"] {
            let d = tempfile::tempdir().unwrap();
            let bytes = cbor(&std::collections::BTreeMap::from([("prompt", nested)]));
            let e = SocketEgress::new(
                deputy_answering(d.path(), bytes),
                me,
                Duration::from_secs(2),
                64 * 1024,
            );
            assert!(
                matches!(e.send(&intent, req()), Err(EgressFailure::AfterSend(m)) if m.starts_with("proto decode")),
                "{nested} is no longer a prompt reply"
            );
        }
    }

    #[test]
    fn a_credential_reply_to_a_prompt_is_a_post_send_codec_failure() {
        let me = nix::unistd::getuid().as_raw();
        let intent = crate::egress::DurableEgressIntent::canned_for_test();
        for reply in [
            EgressSocketReply::Mint(maknae_proto::MintReply::Refused(
                maknae_proto::MintRefusal::Request,
            )),
            EgressSocketReply::Revoke(maknae_proto::RevokeReply::Revoked),
        ] {
            let d = tempfile::tempdir().unwrap();
            let (path, _seen) = fake_deputy(d.path(), Some(reply));
            let e = SocketEgress::new(path, me, Duration::from_secs(2), 64 * 1024);
            match e.send(&intent, req()) {
                Err(EgressFailure::AfterSend(m)) => {
                    assert_eq!(m, "proto decode: a credential reply to a prompt frame")
                }
                other => panic!("expected a post-send codec failure, got {other:?}"),
            }
        }
    }

    fn reach_req(deadline_ms: u64) -> maknae_proto::ReachRequest {
        maknae_proto::ReachRequest::new(
            "github.com".into(),
            "github".into(),
            deadline_ms,
            maknae_proto::ReachSide::Agent {
                agent: "hobi".into(),
                credentials: vec![maknae_proto::CredentialRef {
                    kind: "github-app-installation".into(),
                    name: "maknae-github-read".into(),
                }],
            },
            vec![maknae_proto::RepoAsk {
                base: "o/r".into(),
                change: Some(7),
                head: None,
            }],
        )
        .unwrap()
    }

    fn observed() -> maknae_proto::ReachReply {
        maknae_proto::ReachReply::Observed(
            maknae_proto::Observations::new(vec![maknae_proto::RepoObservation::new(
                [maknae_proto::ForgeOp::Read].into_iter().collect(),
                None,
                maknae_proto::ForgeOps::EMPTY,
                false,
                true,
            )
            .unwrap()])
            .unwrap(),
        )
    }

    fn reach_through(reply: EgressSocketReply) -> ReachOutcome {
        let d = tempfile::tempdir().unwrap();
        let (path, seen) = fake_deputy(d.path(), Some(reply));
        let me = nix::unistd::getuid().as_raw();
        let e = SocketEgress::new(path, me, Duration::from_secs(2), 64 * 1024);
        let out = e.reach(reach_req(1_000));
        assert!(seen.load(Ordering::SeqCst) > 0);
        out
    }

    #[test]
    fn each_reach_reply_reaches_the_caller_as_sent() {
        for reply in [
            observed(),
            maknae_proto::ReachReply::NoForgeCredential,
            maknae_proto::ReachReply::Refused(maknae_proto::ReachRefusal::NotFound),
            maknae_proto::ReachReply::Refused(maknae_proto::ReachRefusal::Unanswered),
        ] {
            let want = format!("{reply:?}");
            match reach_through(EgressSocketReply::Reach(reply)) {
                ReachOutcome::Reply(got) => assert_eq!(format!("{got:?}"), want),
                other => panic!("expected the reply, got {other:?}"),
            }
        }
    }

    #[test]
    fn the_reach_frame_is_what_the_deputy_reads() {
        let d = tempfile::tempdir().unwrap();
        let path = d.path().join("egress.sock");
        let l = UnixListener::bind(&path).unwrap();
        let got = std::thread::spawn(move || {
            let (mut c, _) = l.accept().unwrap();
            let mut len = [0u8; 4];
            c.read_exact(&mut len).unwrap();
            let mut body = vec![0u8; u32::from_be_bytes(len) as usize];
            c.read_exact(&mut body).unwrap();
            body
        });
        let me = nix::unistd::getuid().as_raw();
        let _ =
            SocketEgress::new(path, me, Duration::from_secs(2), 64 * 1024).reach(reach_req(1_000));
        let body = got.join().unwrap();
        let want = EgressFrame::Reach(reach_req(1_000));
        let len = maknae_proto::egress_frame_encoded_len(&want).unwrap();
        assert_eq!(body, encode_egress_frame(&want, len).unwrap().to_vec());
    }

    #[test]
    fn a_reach_at_capacity_is_unanswered_at_capacity() {
        let out = reach_through(EgressSocketReply::AtCapacity);
        assert_eq!(out, ReachOutcome::Unanswered(Unanswered::AtCapacity));
        let ReachOutcome::Unanswered(u) = out else {
            unreachable!()
        };
        assert_eq!(u.trail(), "reach outcome unknown: at capacity");
        assert_eq!(u.class(), maknae_proto::ReachRefusal::Unanswered);
    }

    #[test]
    fn a_non_reach_reply_to_a_reach_frame_is_outcome_unknown() {
        for reply in [
            EgressSocketReply::RefusedBeforeSend,
            EgressSocketReply::Mint(maknae_proto::MintReply::Refused(
                maknae_proto::MintRefusal::Request,
            )),
            EgressSocketReply::Revoke(maknae_proto::RevokeReply::Revoked),
            EgressSocketReply::Prompt(EgressFrameReply::Reply(maknae_proto::PromptReply {
                reasoning: None,
                blocks: vec![],
                tool_calls: vec![],
                usage: None,
            })),
        ] {
            match reach_through(reply) {
                ReachOutcome::Unanswered(u @ Unanswered::Unknown(_)) => {
                    assert!(u.trail().starts_with("reach outcome unknown: "), "{u:?}");
                    assert_eq!(u.class(), maknae_proto::ReachRefusal::Unanswered);
                }
                other => panic!("expected outcome unknown, got {other:?}"),
            }
        }
    }

    #[test]
    fn a_reach_connection_closed_with_no_reply_is_outcome_unknown() {
        let d = tempfile::tempdir().unwrap();
        let (path, seen) = fake_deputy(d.path(), None);
        let me = nix::unistd::getuid().as_raw();
        let out =
            SocketEgress::new(path, me, Duration::from_secs(2), 64 * 1024).reach(reach_req(1_000));
        assert!(seen.load(Ordering::SeqCst) > 0);
        assert!(
            matches!(out, ReachOutcome::Unanswered(Unanswered::Unknown(_))),
            "{out:?}"
        );
    }

    #[test]
    fn a_reach_frame_to_an_unexpected_peer_writes_nothing() {
        let me = nix::unistd::getuid().as_raw();
        if me == 0 {
            eprintln!("skipped: running as root");
            return;
        }
        let d = tempfile::tempdir().unwrap();
        let (path, seen) = fake_deputy(d.path(), Some(EgressSocketReply::Reach(observed())));
        let e = SocketEgress::new(path, me.wrapping_add(1), Duration::from_secs(2), 64 * 1024);
        let out = e.reach(reach_req(1_000));
        assert!(
            matches!(&out, ReachOutcome::Unanswered(u @ Unanswered::NotSent(_)) if u.trail().starts_with("reach not sent: ")),
            "{out:?}"
        );
        std::thread::sleep(Duration::from_millis(120));
        assert_eq!(seen.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn the_reach_socket_wait_allows_egress_exit_revokes() {
        assert_eq!(
            reach_socket_wait(1_000),
            Duration::from_millis(
                1_000 + maknae_config::FORGE_CALL_TIMEOUT_MS + maknae_config::DEADLINE_MARGIN_MS
            )
        );
        assert_eq!(reach_socket_wait(u64::MAX), Duration::from_millis(u64::MAX));
        let d = tempfile::tempdir().unwrap();
        let path = d.path().join("egress.sock");
        let l = UnixListener::bind(&path).unwrap();
        std::thread::spawn(move || {
            if let Ok((mut c, _)) = l.accept() {
                let mut len = [0u8; 4];
                if c.read_exact(&mut len).is_ok() {
                    let mut body = vec![0u8; u32::from_be_bytes(len) as usize];
                    let _ = c.read_exact(&mut body);
                    std::thread::sleep(Duration::from_millis(400));
                    let out = maknae_proto::encode_egress_socket_reply(
                        &EgressSocketReply::Reach(maknae_proto::ReachReply::NoForgeCredential),
                        maknae_proto::EGRESS_REPLY_FRAME_ENCODE_BYTES,
                    )
                    .unwrap();
                    let _ = c.write_all(&(out.len() as u32).to_be_bytes());
                    let _ = c.write_all(&out);
                }
            }
        });
        let me = nix::unistd::getuid().as_raw();
        let e = SocketEgress::new(path, me, Duration::from_millis(50), 64 * 1024);
        assert_eq!(
            e.reach(reach_req(100)),
            ReachOutcome::Reply(maknae_proto::ReachReply::NoForgeCredential),
            "a reply after the frame's deadline but within the revoke allowance is kept"
        );
    }

    #[test]
    fn the_reach_handle_is_built_without_providers_and_reports_its_socket() {
        let d = tempfile::tempdir().unwrap();
        let me = nix::unistd::getuid().as_raw();
        let cfg = |p: PathBuf| maknae_config::EgressConfig {
            socket_path: p,
            ..Default::default()
        };
        let missing = production_reach_with(&cfg(d.path().join("none.sock")), |_| Ok(Some(me)));
        assert!(!missing.has_socket());
        assert!(matches!(
            missing.reach(reach_req(1_000)),
            ReachOutcome::Unanswered(Unanswered::NotSent(_))
        ));

        let (path, _seen) = fake_deputy(d.path(), Some(EgressSocketReply::Reach(observed())));
        let present = production_reach_with(&cfg(path.clone()), |_| Ok(Some(me)));
        assert!(present.has_socket());
        assert_eq!(
            present.reach(reach_req(1_000)),
            ReachOutcome::Reply(observed())
        );

        for resolve in [Ok(None), Err("nss down".to_string())] {
            let r = resolve.clone();
            let no_account = production_reach_with(&cfg(path.clone()), move |_| r);
            assert!(!no_account.has_socket(), "{resolve:?}");
            assert!(matches!(
                no_account.reach(reach_req(1_000)),
                ReachOutcome::Unanswered(Unanswered::NotSent(_))
            ));
        }
    }
}
