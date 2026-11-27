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
//!
//! **Connections are served concurrently, up to the deputy's capacity**
//! (#321). Each holds a slot on its own thread; past capacity the frame is read
//! and answered `AtCapacity` on a refusal thread, never left queued in the
//! backlog against the kernel's deadline. The frame read and the reply write
//! are each bounded as a whole, not per call.

use crate::capacity::{Slot, Slots};
use maknae_config::{AgentId, EgressBounds, GithubAppConfig, MintingConfig};
use maknae_deputy::call::FulfilError;
use maknae_deputy::handle::{decide, Refusal};
use maknae_deputy::mint::admit::{admit_mint, admit_revoke, AdmittedMint};
use maknae_deputy::mint::minter::LiveTokens;
use maknae_deputy::unseal::OpenFailure;
use maknae_proto::{
    EgressFrame, EgressFrameReply, EgressSocketReply, MintRefusal, MintReply, MintRequest,
    ReachReply, ReachRequest, RevokeReply, RevokeRequest,
};
use nix::poll::{poll, PollFd, PollFlags, PollTimeout};
use std::io::{Read, Write};
use std::os::fd::AsFd;
use std::os::unix::net::{UnixListener, UnixStream};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

/// The largest request frame the deputy will ACCEPT. Checked against the
/// declared length BEFORE allocation: the kernel is trusted, but a bug there
/// must not be able to make the deputy reserve four gigabytes on a four-byte
/// prefix. Defence in depth, in the direction the kernel already applies to us.
/// The VALUE is `maknae-proto`'s, shared with the kernel's pre-send check so
/// the two ends cannot drift (#240, review round 4).
pub const MAX_REQUEST_FRAME_BYTES: usize = maknae_proto::EGRESS_REQUEST_FRAME_MAX_BYTES;

/// The bound on each blocking read and write of a connection. The kernel
/// writes its frame as soon as it connects, so only a stalled peer meets it.
pub const FRAME_IO_TIMEOUT: Duration = Duration::from_secs(30);

#[derive(Debug, PartialEq, Eq)]
pub enum ServeError {
    /// The provider call failed after admission; the connection closes with no reply.
    Fulfil(String),
    Unusable {
        defect: maknae_proto::ReplyDefect,
        usage: Option<maknae_proto::Usage>,
    },
    OpenFailed(OpenFailure),
    /// The connected peer is not the kernel, or could not be identified at
    /// all. One variant, because the deputy treats them identically: a peer we
    /// cannot police is refused exactly like a peer we can and shouldn't. The
    /// uid is deliberately not carried — nothing is disclosed to the peer.
    WrongPeer,
    OversizeFrame(usize),
    Io(String),
    Refused(Refusal),
}

/// Egress's minting, driven on the connection's own thread. Absent, every
/// mint and revoke frame is refused `Request`; unavailable (`config` is `Err`),
/// every one is refused `Signer` before admission.
pub trait MintFrames: Send + Sync {
    fn config(&self) -> Result<&MintingConfig, &'static str>;
    fn mint(&self, admitted: &AdmittedMint<'_>) -> (MintReply, LiveTokens);
    fn revoke(&self, req: &RevokeRequest, agent: &AgentId, app: &GithubAppConfig) -> RevokeReply;
    fn revoke_all(&self, live: LiveTokens);
}

/// Egress's reach exchanges, driven on the connection's own thread. Admission,
/// the exchange, any revoke and the journal line are all inside `reach`.
pub trait ReachFrames: Send + Sync {
    fn reach(&self, req: &ReachRequest) -> ReachReply;
}

/// The one `FulfilError` mapping, shared by `main` and the tests.
pub fn serve_error(e: FulfilError) -> ServeError {
    match e {
        FulfilError::Open(f) => ServeError::OpenFailed(f),
        FulfilError::Unusable {
            defect,
            usage,
            journal,
        } => {
            eprintln!("{}", journal.as_str());
            ServeError::Unusable { defect, usage }
        }
        FulfilError::Provider { summary } => ServeError::Fulfil(summary),
    }
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
/// same way.
///
/// The length is checked BEFORE the allocation: a four-byte prefix must not be
/// able to make the deputy reserve four gigabytes.
fn read_body_zeroizing(
    stream: &mut UnixStream,
    by: Instant,
) -> Result<zeroize::Zeroizing<Vec<u8>>, ServeError> {
    let mut len = [0u8; 4];
    read_exact_by(stream, &mut len, by)?;
    let n = u32::from_be_bytes(len) as usize;
    if n > MAX_REQUEST_FRAME_BYTES {
        return Err(ServeError::OversizeFrame(n));
    }
    let mut body = zeroize::Zeroizing::new(vec![0u8; n]);
    read_exact_by(stream, &mut body, by)?;
    Ok(body)
}

/// Waits for `flags` within what is left of `by`. `poll`, not a re-armed
/// socket timeout: one blocking call under `SO_SNDTIMEO` or `SO_RCVTIMEO` can
/// run far past it against a peer that frees space or sends bytes a little at
/// a time, and macOS refuses `setsockopt` once the peer has closed (the
/// kernel's side, `egress_socket.rs`, measured both).
fn wait_for(stream: &UnixStream, flags: PollFlags, by: Instant) -> Result<(), ServeError> {
    loop {
        let left = by.saturating_duration_since(Instant::now());
        if left.is_zero() {
            return Err(io("the connection's I/O bound expired"));
        }
        let timeout =
            PollTimeout::try_from(left.max(Duration::from_millis(1))).unwrap_or(PollTimeout::MAX);
        match poll(&mut [PollFd::new(stream.as_fd(), flags)], timeout) {
            Ok(0) => return Err(io("the connection's I/O bound expired")),
            Ok(_) => return Ok(()),
            Err(nix::errno::Errno::EINTR) => continue,
            Err(e) => return Err(io(format!("poll: {e}"))),
        }
    }
}

/// `read_exact` under one deadline for the whole buffer.
fn read_exact_by(stream: &mut UnixStream, buf: &mut [u8], by: Instant) -> Result<(), ServeError> {
    let mut filled = 0;
    while filled < buf.len() {
        wait_for(stream, PollFlags::POLLIN, by)?;
        match stream.read(&mut buf[filled..]) {
            Ok(0) => return Err(io("the peer closed the connection mid-frame")),
            Ok(n) => filled += n,
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {}
            Err(e) => return Err(io(e)),
        }
    }
    Ok(())
}

/// `write_all` under one deadline: non-blocking writes, each after a `poll`.
fn write_all_by(stream: &mut UnixStream, buf: &[u8], by: Instant) -> Result<(), ServeError> {
    stream.set_nonblocking(true).map_err(io)?;
    let mut written = 0;
    let out = loop {
        if written >= buf.len() {
            break Ok(());
        }
        if let Err(e) = wait_for(stream, PollFlags::POLLOUT, by) {
            break Err(e);
        }
        match stream.write(&buf[written..]) {
            Ok(0) => break Err(io("the peer stopped accepting the reply")),
            Ok(n) => written += n,
            Err(e)
                if matches!(
                    e.kind(),
                    std::io::ErrorKind::Interrupted | std::io::ErrorKind::WouldBlock
                ) => {}
            Err(e) => break Err(io(e)),
        }
    };
    out.and(stream.set_nonblocking(false).map_err(io))
}

pub struct Frames {
    pub mint: Option<Arc<dyn MintFrames>>,
    pub reach: Arc<dyn ReachFrames>,
}

#[derive(Clone, Copy)]
pub struct FrameRefs<'a> {
    pub mint: Option<&'a dyn MintFrames>,
    pub reach: &'a dyn ReachFrames,
}

/// Serve exactly one connection: authenticate, read one frame, answer, close.
///
/// `fulfil` is what turns an admitted frame into a provider call. It is passed
/// in rather than constructed here so the transport can be tested without a
/// provider or a Vault — this project has no Vault stub and deliberately uses
/// none, so the seam is a function, not a fake server.
///
/// `committed` is set once the provider call or a reply has begun: from then
/// on a contained panic must not answer the peer again.
pub fn serve_one<F>(
    mut stream: UnixStream,
    expected_uid: u32,
    bounds: &EgressBounds,
    io_timeout: Duration,
    committed: &AtomicBool,
    frames: FrameRefs<'_>,
    fulfil: F,
) -> Result<(), ServeError>
where
    F: FnOnce(&maknae_deputy::handle::Admitted<'_>) -> Result<EgressFrameReply, ServeError>,
{
    authenticate(&stream, expected_uid, io_timeout)?;

    let body = read_body_zeroizing(&mut stream, Instant::now() + io_timeout)?;

    let req = match maknae_proto::decode_egress_frame(&body).map_err(io)? {
        EgressFrame::Prompt(req) => req,
        EgressFrame::Mint(req) => {
            return serve_mint(&mut stream, &req, frames.mint, io_timeout, committed)
        }
        EgressFrame::Revoke(req) => {
            return serve_revoke(&mut stream, &req, frames.mint, io_timeout, committed)
        }
        EgressFrame::Reach(req) => {
            committed.store(true, Ordering::Release);
            let reply = frames.reach.reach(&req);
            return write_reply(
                &mut stream,
                &EgressSocketReply::Reach(reply),
                io_timeout,
                committed,
            );
        }
    };
    let admitted = match decide(&req, bounds) {
        Ok(a) => a,
        Err(r) => {
            return refuse_before_send(&mut stream, ServeError::Refused(r), io_timeout, committed)
        }
    };
    committed.store(true, Ordering::Release);
    match fulfil(&admitted) {
        Ok(reply) => write_reply(
            &mut stream,
            &EgressSocketReply::Prompt(reply),
            io_timeout,
            committed,
        ),
        Err(e @ ServeError::OpenFailed(_)) => {
            refuse_before_send(&mut stream, e, io_timeout, committed)
        }
        Err(ServeError::Unusable { defect, usage }) => write_reply(
            &mut stream,
            &EgressSocketReply::Prompt(EgressFrameReply::Unusable { defect, usage }),
            io_timeout,
            committed,
        ),
        Err(e) => Err(e),
    }
}

/// The minted tokens are held until the reply is delivered; undelivered, they are revoked.
fn serve_mint(
    stream: &mut UnixStream,
    req: &MintRequest,
    minting: Option<&dyn MintFrames>,
    io_timeout: Duration,
    committed: &AtomicBool,
) -> Result<(), ServeError> {
    let refused = |stream: &mut UnixStream, r| {
        write_reply(
            stream,
            &EgressSocketReply::Mint(MintReply::Refused(r)),
            io_timeout,
            committed,
        )
    };
    let Some(m) = minting else {
        return refused(stream, MintRefusal::Request);
    };
    let config = match m.config() {
        Ok(c) => c,
        Err(why) => {
            unavailable("mint", &req.task, &req.agent, why);
            return refused(stream, MintRefusal::Signer);
        }
    };
    let admitted = match admit_mint(req, Some(config)) {
        Ok(a) => a,
        Err(r) => return refused(stream, r),
    };
    committed.store(true, Ordering::Release);
    let (reply, live) = m.mint(&admitted);
    let written = write_reply(
        stream,
        &EgressSocketReply::Mint(reply),
        io_timeout,
        committed,
    );
    if written.is_err() {
        m.revoke_all(live);
    }
    written
}

fn unavailable(verb: &str, task: &str, agent: &str, why: &str) {
    eprintln!("{}", unavailable_line(verb, task, agent, why));
}

fn unavailable_line(verb: &str, task: &str, agent: &str, why: &str) -> String {
    let (task, agent) = (bounded(task), bounded(agent));
    format!(
        "maknae-egress: {verb} task={task} agent={agent}: refused, minting is unavailable: {why}"
    )
}

fn bounded(field: &str) -> String {
    if field.len() > maknae_seal::MAX_AAD_FIELD_BYTES {
        format!("<{} bytes>", field.len())
    } else {
        format!("{field:?}")
    }
}

fn serve_revoke(
    stream: &mut UnixStream,
    req: &RevokeRequest,
    minting: Option<&dyn MintFrames>,
    io_timeout: Duration,
    committed: &AtomicBool,
) -> Result<(), ServeError> {
    let reply = match minting.map(|m| (m, m.config())) {
        None => RevokeReply::Refused(MintRefusal::Request),
        Some((_, Err(why))) => {
            unavailable("revoke", &req.task, &req.agent, why);
            RevokeReply::Refused(MintRefusal::Signer)
        }
        Some((m, Ok(config))) => match admit_revoke(req, Some(config)) {
            Err(r) => RevokeReply::Refused(r),
            Ok((agent, _, app)) => {
                committed.store(true, Ordering::Release);
                m.revoke(req, &agent, app)
            }
        },
    };
    write_reply(
        stream,
        &EgressSocketReply::Revoke(reply),
        io_timeout,
        committed,
    )
}

/// The peer check, BEFORE the first read: a peer we have not authenticated
/// does not get to hand us bytes to parse.
fn authenticate(
    stream: &UnixStream,
    expected_uid: u32,
    io_timeout: Duration,
) -> Result<(), ServeError> {
    if !maknae_vault::peer_uid_is(&stream, expected_uid).map_err(|_| ServeError::WrongPeer)? {
        return Err(ServeError::WrongPeer);
    }
    // A backstop under `poll`: a read woken without a readable byte still ends.
    stream.set_read_timeout(Some(io_timeout)).map_err(io)
}

/// Answer a connection that found no free slot. The frame is read before the
/// reply so the kernel's write completes and it reads a named refusal; closed
/// unread, the kernel would record delivery unknown for content that never left.
fn refuse_at_capacity_committing(
    mut stream: UnixStream,
    expected_uid: u32,
    io_timeout: Duration,
    committed: &AtomicBool,
) -> Result<(), ServeError> {
    authenticate(&stream, expected_uid, io_timeout)?;
    drop(read_body_zeroizing(
        &mut stream,
        Instant::now() + io_timeout,
    )?);
    write_reply(
        &mut stream,
        &EgressSocketReply::AtCapacity,
        io_timeout,
        committed,
    )
}

/// Accept forever. A failed connection is refused and the loop continues: one
/// bad or hostile peer must not take the deputy down, and neither may one
/// connection's panic.
pub fn accept_loop<H>(
    listener: UnixListener,
    slots: Arc<Slots>,
    expected_uid: u32,
    bounds: Arc<EgressBounds>,
    io_timeout: Duration,
    frames: Frames,
    handler: Arc<H>,
) where
    H: Fn(&maknae_deputy::handle::Admitted<'_>) -> Result<EgressFrameReply, ServeError>
        + Send
        + Sync
        + 'static,
{
    let refusals = Slots::new(slots.cap());
    for conn in listener.incoming() {
        let stream = match conn {
            Ok(s) => s,
            Err(e) => {
                eprintln!("maknae-egress: accept failed: {e}");
                continue;
            }
        };
        let Some(slot) = slots.try_take() else {
            answer_at_capacity(stream, &refusals, expected_uid, io_timeout);
            continue;
        };
        let fallback = stream.try_clone();
        let (bounds, handler, minting, reach) = (
            Arc::clone(&bounds),
            Arc::clone(&handler),
            frames.mint.clone(),
            Arc::clone(&frames.reach),
        );
        let spawned = spawn_contained(
            "maknae-egress-conn",
            slot,
            stream,
            io_timeout,
            EgressSocketReply::RefusedBeforeSend,
            move |stream, committed| {
                if let Err(e) = serve_one(
                    stream,
                    expected_uid,
                    &bounds,
                    io_timeout,
                    committed,
                    FrameRefs {
                        mint: minting.as_deref(),
                        reach: &*reach,
                    },
                    |a| handler(a),
                ) {
                    eprintln!("maknae-egress: connection refused: {e:?}");
                }
            },
        );
        if let Err(e) = spawned {
            eprintln!("maknae-egress: cannot start a connection thread: {e}");
            if let Ok(s) = fallback {
                answer_at_capacity(s, &refusals, expected_uid, io_timeout);
            }
        }
    }
}

/// Off the accept thread, so a stalled peer here never delays the next
/// accept. Refusals hold their own slots; past those, the connection closes
/// unanswered rather than queueing.
fn answer_at_capacity(
    stream: UnixStream,
    refusals: &Arc<Slots>,
    expected_uid: u32,
    io_timeout: Duration,
) {
    let Some(slot) = refusals.try_take() else {
        eprintln!(
            "maknae-egress: at capacity and no refusal slot free; closed a connection unanswered"
        );
        return;
    };
    let spawned = spawn_contained(
        "maknae-egress-refuse",
        slot,
        stream,
        io_timeout,
        EgressSocketReply::AtCapacity,
        move |stream, committed| match refuse_at_capacity_committing(
            stream,
            expected_uid,
            io_timeout,
            committed,
        ) {
            Ok(()) => eprintln!("maknae-egress: at capacity; answered a connection AtCapacity"),
            Err(e) => eprintln!("maknae-egress: connection refused: {e:?}"),
        },
    );
    if let Err(e) = spawned {
        eprintln!(
            "maknae-egress: cannot start a refusal thread; closed a connection unanswered: {e}"
        );
    }
}

/// Runs one connection on its own thread, holding `slot`. A panic ends that
/// connection alone: the others in flight are untouched (#321). Unless `work`
/// had set `committed` (the provider call or a reply had begun), the peer is
/// answered `unsent`, since nothing left; otherwise it is closed.
fn spawn_contained(
    name: &str,
    slot: Slot,
    stream: UnixStream,
    io_timeout: Duration,
    unsent: EgressSocketReply,
    work: impl FnOnce(UnixStream, &AtomicBool) + Send + 'static,
) -> std::io::Result<()> {
    let spare = stream.try_clone();
    std::thread::Builder::new()
        .name(name.into())
        .spawn(move || {
            let _slot = slot;
            let committed = AtomicBool::new(false);
            let worked =
                std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| work(stream, &committed)));
            if let Err(payload) = worked {
                // A plain write: `eprintln!` panics when stderr fails.
                let _ = writeln!(
                    std::io::stderr(),
                    "maknae-egress: a connection panicked; only that connection was affected"
                );
                if !committed.load(Ordering::Acquire) {
                    if let Ok(mut s) = spare {
                        let _ = write_reply(&mut s, &unsent, io_timeout, &committed);
                    }
                }
                // Last: a payload whose destructor panics ends only this thread.
                drop(payload);
            }
        })
        .map(drop)
}

fn refuse_before_send(
    stream: &mut UnixStream,
    why: ServeError,
    io_timeout: Duration,
    committed: &AtomicBool,
) -> Result<(), ServeError> {
    if let Err(w) = write_reply(
        stream,
        &EgressSocketReply::RefusedBeforeSend,
        io_timeout,
        committed,
    ) {
        eprintln!("maknae-egress: the refused-before-send reply was not delivered: {w:?}");
    }
    Err(why)
}

fn write_reply(
    stream: &mut UnixStream,
    reply: &EgressSocketReply,
    io_timeout: Duration,
    committed: &AtomicBool,
) -> Result<(), ServeError> {
    committed.store(true, Ordering::Release);
    let by = Instant::now() + io_timeout;
    // Into ONE fixed preallocation that never grows (#241, codex round 2 item
    // B): a reply carries whatever kernel-served content the model quoted
    // back, and the growing buffer this replaces freed a partly-written copy
    // of it on every realloc. A reply past the headroom is a codec error
    // here — before the length prefix, so the kernel reads nothing.
    let out = maknae_proto::encode_egress_socket_reply(
        reply,
        maknae_proto::EGRESS_REPLY_FRAME_ENCODE_BYTES,
    )
    .map_err(io)?;
    write_all_by(stream, &(out.len() as u32).to_be_bytes(), by)?;
    write_all_by(stream, &out, by)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_unadmitted_frame_s_task_and_agent_reach_the_journal_bounded() {
        let at = "t".repeat(maknae_seal::MAX_AAD_FIELD_BYTES);
        let line = unavailable_line("mint", &at, "coder", "no SecretID");
        assert!(line.contains(&format!("task={at:?}")), "{line}");
        assert!(line.contains("agent=\"coder\""), "{line}");

        let huge = "t".repeat(1 << 20);
        for (task, agent) in [(huge.as_str(), "coder"), ("task-1", huge.as_str())] {
            let line = unavailable_line("revoke", task, agent, "no SecretID");
            assert!(line.len() < 512, "{} bytes", line.len());
            assert!(!line.contains(&"t".repeat(65)), "{line}");
            assert!(line.contains(&format!("<{} bytes>", 1 << 20)), "{line}");
            assert!(
                line.ends_with("minting is unavailable: no SecretID"),
                "{line}"
            );
        }
    }
    use crate::test_frames::{
        bounds, canned, encoded_frame, no_reach, prefixed, request, served_frame_reaching,
        tasker_reach, CannedReach, ALICE,
    };
    use maknae_deputy::call::{fulfil, CallBounds};
    use maknae_deputy::unseal::{KeyOpener, OpenRequest};
    use maknae_proto::{ContentBlock, EgressFrameRequest, ReplyDefect, SecretText};
    use std::path::PathBuf;

    fn serve_one_unmarked<F>(
        stream: UnixStream,
        expected_uid: u32,
        bounds: &EgressBounds,
        io_timeout: Duration,
        fulfil: F,
    ) -> Result<(), ServeError>
    where
        F: FnOnce(&maknae_deputy::handle::Admitted<'_>) -> Result<EgressFrameReply, ServeError>,
    {
        serve_one(
            stream,
            expected_uid,
            bounds,
            io_timeout,
            &AtomicBool::new(false),
            FrameRefs {
                mint: None,
                reach: &no_reach(),
            },
            fulfil,
        )
    }

    fn refuse_at_capacity(
        stream: UnixStream,
        expected_uid: u32,
        io_timeout: Duration,
    ) -> Result<(), ServeError> {
        refuse_at_capacity_committing(stream, expected_uid, io_timeout, &AtomicBool::new(false))
    }

    const DEAD_PROVIDER: &str = "http://127.0.0.1:1/v1/chat/completions";

    fn encoded(r: &EgressFrameRequest) -> Vec<u8> {
        encoded_frame(&EgressFrame::Prompt(r.clone()))
    }

    fn frame(key: &str) -> Vec<u8> {
        encoded(&request(key))
    }

    fn fips() {
        static ONCE: std::sync::Once = std::sync::Once::new();
        ONCE.call_once(|| maknae_crypto::init().unwrap());
    }

    fn runtime() -> tokio::runtime::Runtime {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap()
    }

    struct Opens(Result<&'static str, OpenFailure>);
    impl KeyOpener for Opens {
        async fn open(
            &self,
            _s: &[u8],
            _r: &OpenRequest<'_>,
        ) -> Result<maknae_io::MaknaeSecret, OpenFailure> {
            self.0.map(|k| {
                maknae_io::MaknaeSecret::new(zeroize::Zeroizing::new(k.to_string())).unwrap()
            })
        }
    }

    fn served_with<F>(
        bytes: Vec<u8>,
        fulfil: F,
    ) -> (Result<(), ServeError>, Option<EgressSocketReply>)
    where
        F: FnOnce(&maknae_deputy::handle::Admitted<'_>) -> Result<EgressFrameReply, ServeError>,
    {
        let (a, b) = UnixStream::pair().unwrap();
        let me = nix::unistd::getuid().as_raw();
        let h = std::thread::spawn(move || {
            let mut c = a;
            c.write_all(&bytes).unwrap();
            let mut back = Vec::new();
            c.read_to_end(&mut back).unwrap();
            back
        });
        let out = serve_one_unmarked(b, me, &bounds(), FRAME_IO_TIMEOUT, fulfil);
        let back = h.join().unwrap();
        let reply = (!back.is_empty()).then(|| {
            let n = u32::from_be_bytes(back[..4].try_into().unwrap()) as usize;
            assert_eq!(back.len(), 4 + n, "one reply frame and nothing after it");
            maknae_proto::decode_egress_socket_reply(&back[4..]).unwrap()
        });
        (out, reply)
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
        let out = serve_one_unmarked(b, expected_uid, &bounds(), FRAME_IO_TIMEOUT, canned);
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
        let f = frame(ALICE);
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
            serve_one_unmarked(b, me.wrapping_add(1), &bounds(), FRAME_IO_TIMEOUT, canned),
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
            let f = frame(ALICE);
            c.write_all(&(f.len() as u32).to_be_bytes()).unwrap();
            c.write_all(&f).unwrap();
            let mut len = [0u8; 4];
            c.read_exact(&mut len).unwrap();
            let mut body = vec![0u8; u32::from_be_bytes(len) as usize];
            c.read_exact(&mut body).unwrap();
            maknae_proto::decode_egress_socket_reply(&body).unwrap()
        });
        serve_one_unmarked(b, me, &bounds(), FRAME_IO_TIMEOUT, canned).unwrap();
        let reply = h.join().unwrap();
        assert_eq!(
            reply,
            EgressSocketReply::Prompt(EgressFrameReply::Reply(maknae_proto::PromptReply {
                reasoning: None,
                blocks: vec![],
                tool_calls: vec![],
                usage: None,
            }))
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
        let (_d, path, slots) = looping(4, canned);
        drop(UnixStream::connect(&path).unwrap());
        assert!(matches!(
            ask(&path),
            EgressSocketReply::Prompt(EgressFrameReply::Reply(_))
        ));
        eventually("the served connection kept its slot", || {
            slots.in_use() == 0
        });
    }

    fn looping<H>(cap: usize, handler: H) -> (tempfile::TempDir, PathBuf, Arc<Slots>)
    where
        H: Fn(&maknae_deputy::handle::Admitted<'_>) -> Result<EgressFrameReply, ServeError>
            + Send
            + Sync
            + 'static,
    {
        looping_reaching(cap, handler, Arc::new(no_reach()))
    }

    fn looping_reaching<H>(
        cap: usize,
        handler: H,
        reach: Arc<dyn ReachFrames>,
    ) -> (tempfile::TempDir, PathBuf, Arc<Slots>)
    where
        H: Fn(&maknae_deputy::handle::Admitted<'_>) -> Result<EgressFrameReply, ServeError>
            + Send
            + Sync
            + 'static,
    {
        let d = tempfile::tempdir().unwrap();
        let path = d.path().join("egress.sock");
        let l = UnixListener::bind(&path).unwrap();
        let me = nix::unistd::getuid().as_raw();
        let slots = Slots::new(cap);
        let held = Arc::clone(&slots);
        std::thread::spawn(move || {
            accept_loop(
                l,
                held,
                me,
                Arc::new(bounds()),
                Duration::from_secs(5),
                Frames { mint: None, reach },
                Arc::new(handler),
            )
        });
        (d, path, slots)
    }

    fn ask(path: &std::path::Path) -> EgressSocketReply {
        ask_with(path, &prefixed(&frame(ALICE)))
    }

    fn ask_with(path: &std::path::Path, request: &[u8]) -> EgressSocketReply {
        let mut c = UnixStream::connect(path).unwrap();
        c.set_read_timeout(Some(Duration::from_secs(20))).unwrap();
        c.write_all(request).unwrap();
        let mut len = [0u8; 4];
        c.read_exact(&mut len).unwrap();
        let mut body = vec![0u8; u32::from_be_bytes(len) as usize];
        c.read_exact(&mut body).unwrap();
        maknae_proto::decode_egress_socket_reply(&body).unwrap()
    }

    fn eventually(what: &str, cond: impl Fn() -> bool) {
        let until = std::time::Instant::now() + Duration::from_secs(10);
        while !cond() {
            assert!(std::time::Instant::now() < until, "{what}");
            std::thread::sleep(Duration::from_millis(10));
        }
    }

    /// #321: the second connection is served while the first is still in its
    /// provider call. Each handler waits until both are inside it; a serial
    /// loop never lets the second in, so each waits out its bound and fails.
    #[test]
    fn two_connections_are_served_at_the_same_time() {
        let inside = Arc::new((std::sync::Mutex::new(0usize), std::sync::Condvar::new()));
        let both_seen = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let (i, seen) = (Arc::clone(&inside), Arc::clone(&both_seen));
        let (_d, path, _slots) = looping(4, move |a| {
            let (m, cv) = &*i;
            let mut n = m.lock().unwrap();
            *n += 1;
            cv.notify_all();
            let (n, _) = cv
                .wait_timeout_while(n, Duration::from_secs(20), |n| *n < 2)
                .unwrap();
            if *n >= 2 {
                seen.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            }
            canned(a)
        });
        let p = path.clone();
        let other = std::thread::spawn(move || ask(&p));
        assert!(matches!(
            ask(&path),
            EgressSocketReply::Prompt(EgressFrameReply::Reply(_))
        ));
        assert!(matches!(
            other.join().unwrap(),
            EgressSocketReply::Prompt(EgressFrameReply::Reply(_))
        ));
        assert_eq!(
            both_seen.load(std::sync::atomic::Ordering::SeqCst),
            2,
            "the connections were served one after the other"
        );
    }

    /// Past capacity a connection is answered `AtCapacity` at once, not left in
    /// the backlog; the held connection still completes, and its slot comes back.
    #[test]
    fn a_connection_past_capacity_is_answered_at_capacity_at_once() {
        let (release_tx, release_rx) = std::sync::mpsc::channel::<()>();
        let release_rx = std::sync::Mutex::new(release_rx);
        let (_d, path, slots) = looping(1, move |a| {
            let _ = release_rx
                .lock()
                .unwrap()
                .recv_timeout(Duration::from_secs(10));
            canned(a)
        });
        let p = path.clone();
        let held = std::thread::spawn(move || ask(&p));
        eventually("the first connection never took its slot", || {
            slots.in_use() == 1
        });
        assert_eq!(ask(&path), EgressSocketReply::AtCapacity);
        release_tx.send(()).unwrap();
        assert!(matches!(
            held.join().unwrap(),
            EgressSocketReply::Prompt(EgressFrameReply::Reply(_))
        ));
        eventually("the slot was not given back", || slots.in_use() == 0);
        release_tx.send(()).unwrap();
        assert!(matches!(
            ask(&path),
            EgressSocketReply::Prompt(EgressFrameReply::Reply(_))
        ));
    }

    /// #321: one connection's panic is that connection's alone. B, in flight
    /// beside it, is answered; A, whose provider call had begun, is closed
    /// (delivery unknown); the deputy serves the next connection; the slots
    /// all come back.
    #[test]
    fn a_panicking_connection_leaves_the_others_in_flight_untouched() {
        let order = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let a_done = Arc::new((std::sync::Mutex::new(false), std::sync::Condvar::new()));
        let (o, done) = (Arc::clone(&order), Arc::clone(&a_done));
        let (_d, path, slots) = looping(4, move |a| {
            let n = o.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            if n == 0 {
                struct Signal(Arc<(std::sync::Mutex<bool>, std::sync::Condvar)>);
                impl Drop for Signal {
                    fn drop(&mut self) {
                        *self.0 .0.lock().unwrap_or_else(|p| p.into_inner()) = true;
                        self.0 .1.notify_all();
                    }
                }
                let _signal = Signal(Arc::clone(&done));
                let until = std::time::Instant::now() + Duration::from_secs(10);
                while o.load(std::sync::atomic::Ordering::SeqCst) < 2
                    && std::time::Instant::now() < until
                {
                    std::thread::sleep(Duration::from_millis(5));
                }
                panic!("the first connection panics while the second is in flight");
            }
            if n == 1 {
                let (m, cv) = &*done;
                let (finished, _) = cv
                    .wait_timeout_while(m.lock().unwrap(), Duration::from_secs(10), |d| !*d)
                    .unwrap();
                assert!(*finished, "the first connection never panicked");
            }
            canned(a)
        });
        let request = prefixed(&frame(ALICE));
        let mut first = UnixStream::connect(&path).unwrap();
        first.write_all(&request).unwrap();
        eventually("the first connection never started", || {
            order.load(std::sync::atomic::Ordering::SeqCst) == 1
        });
        let p = path.clone();
        let second = std::thread::spawn(move || ask(&p));
        let mut back = Vec::new();
        let _ = first.read_to_end(&mut back);
        assert!(
            back.is_empty(),
            "a call that began must not be answered as unsent"
        );
        assert!(matches!(
            second.join().unwrap(),
            EgressSocketReply::Prompt(EgressFrameReply::Reply(_))
        ));
        assert!(matches!(
            ask(&path),
            EgressSocketReply::Prompt(EgressFrameReply::Reply(_))
        ));
        eventually("a slot was kept", || slots.in_use() == 0);
    }

    /// A panic after the reply was written answers nothing more: one frame,
    /// then the close.
    #[test]
    fn a_panic_after_a_reply_writes_no_second_frame() {
        let (a, b) = UnixStream::pair().unwrap();
        let slots = Slots::new(1);
        spawn_contained(
            "t",
            slots.try_take().unwrap(),
            b,
            FRAME_IO_TIMEOUT,
            EgressSocketReply::AtCapacity,
            |stream, committed| {
                let mut s = stream;
                write_reply(
                    &mut s,
                    &EgressSocketReply::AtCapacity,
                    FRAME_IO_TIMEOUT,
                    committed,
                )
                .unwrap();
                panic!("the log after the reply failed");
            },
        )
        .unwrap();
        let mut c = a;
        c.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
        let mut back = Vec::new();
        c.read_to_end(&mut back).unwrap();
        let n = u32::from_be_bytes(back[..4].try_into().unwrap()) as usize;
        assert_eq!(back.len(), 4 + n, "a second frame followed the reply");
    }

    /// Before the provider call began, a panicking connection is answered as
    /// refused before send: nothing left, so the kernel records `Failed`.
    #[test]
    fn a_panic_before_the_call_began_is_answered_refused_before_send() {
        let (a, b) = UnixStream::pair().unwrap();
        let slots = Slots::new(1);
        spawn_contained(
            "t",
            slots.try_take().unwrap(),
            b,
            FRAME_IO_TIMEOUT,
            EgressSocketReply::RefusedBeforeSend,
            |_stream, _began| panic!("before the call"),
        )
        .unwrap();
        let mut c = a;
        c.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
        let mut len = [0u8; 4];
        c.read_exact(&mut len).unwrap();
        let mut body = vec![0u8; u32::from_be_bytes(len) as usize];
        c.read_exact(&mut body).unwrap();
        assert_eq!(
            maknae_proto::decode_egress_socket_reply(&body).unwrap(),
            EgressSocketReply::RefusedBeforeSend
        );
        eventually("the slot was kept", || slots.in_use() == 0);
    }

    /// A payload is freed, not leaked, even one whose destructor panics: that
    /// ends only the connection's own thread, and the deputy keeps serving.
    #[test]
    fn a_panic_whose_payload_panics_on_drop_is_freed_and_still_contained() {
        static DROPPED: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);
        struct Bomb;
        impl Drop for Bomb {
            fn drop(&mut self) {
                DROPPED.store(true, std::sync::atomic::Ordering::SeqCst);
                panic!("payload dropped");
            }
        }
        let first = Arc::new(std::sync::atomic::AtomicBool::new(true));
        let (_d, path, slots) = looping(1, move |a| {
            if first.swap(false, std::sync::atomic::Ordering::SeqCst) {
                std::panic::panic_any(Bomb);
            }
            canned(a)
        });
        let request = prefixed(&frame(ALICE));
        let mut c = UnixStream::connect(&path).unwrap();
        c.write_all(&request).unwrap();
        let mut rest = Vec::new();
        let _ = c.read_to_end(&mut rest);
        eventually("the slot was kept", || slots.in_use() == 0);
        assert!(matches!(
            ask(&path),
            EgressSocketReply::Prompt(EgressFrameReply::Reply(_))
        ));
        assert!(
            DROPPED.load(std::sync::atomic::Ordering::SeqCst),
            "the payload was leaked"
        );
    }

    #[test]
    fn the_at_capacity_answer_consumes_the_frame_and_names_itself() {
        let (a, b) = UnixStream::pair().unwrap();
        let me = nix::unistd::getuid().as_raw();
        let h = std::thread::spawn(move || {
            let mut c = a;
            c.write_all(&prefixed(&frame(ALICE))).unwrap();
            let mut back = Vec::new();
            c.read_to_end(&mut back).unwrap();
            back
        });
        assert_eq!(refuse_at_capacity(b, me, FRAME_IO_TIMEOUT), Ok(()));
        let back = h.join().unwrap();
        let n = u32::from_be_bytes(back[..4].try_into().unwrap()) as usize;
        assert_eq!(back.len(), 4 + n);
        assert_eq!(
            maknae_proto::decode_egress_socket_reply(&back[4..]).unwrap(),
            EgressSocketReply::AtCapacity
        );
    }

    #[test]
    fn the_at_capacity_path_refuses_a_wrong_peer_before_reading() {
        let (a, b) = UnixStream::pair().unwrap();
        let me = nix::unistd::getuid().as_raw();
        let f = frame(ALICE);
        let mut writer = a;
        writer.write_all(&(f.len() as u32).to_be_bytes()).unwrap();
        writer.write_all(&f).unwrap();
        let mut keep = b.try_clone().unwrap();
        assert_eq!(
            refuse_at_capacity(b, me.wrapping_add(1), FRAME_IO_TIMEOUT),
            Err(ServeError::WrongPeer)
        );
        keep.set_read_timeout(Some(Duration::from_millis(500)))
            .unwrap();
        let mut len = [0u8; 4];
        keep.read_exact(&mut len)
            .expect("the frame was consumed before the peer check");
        assert_eq!(u32::from_be_bytes(len), f.len() as u32);
        drop(writer);
    }

    /// The bound covers the whole frame, not each read: a peer that trickles
    /// one byte at a time, each well inside the bound, is still released.
    #[test]
    fn a_peer_that_trickles_its_frame_is_released_by_the_whole_frame_bound() {
        let me = nix::unistd::getuid().as_raw();
        let bound = Duration::from_millis(300);
        for at_capacity in [false, true] {
            let (a, b) = UnixStream::pair().unwrap();
            let (tx, rx) = std::sync::mpsc::channel();
            std::thread::spawn(move || {
                let out = if at_capacity {
                    refuse_at_capacity(b, me, bound)
                } else {
                    serve_one_unmarked(b, me, &bounds(), bound, canned)
                };
                let _ = tx.send(out);
            });
            let started = std::time::Instant::now();
            let mut w = a;
            w.write_all(&1000u32.to_be_bytes()).unwrap();
            let out = loop {
                if let Ok(out) = rx.recv_timeout(Duration::from_millis(50)) {
                    break out;
                }
                assert!(
                    started.elapsed() < Duration::from_secs(5),
                    "a trickling peer held the connection past the bound"
                );
                let _ = w.write_all(&[0u8]);
            };
            assert!(matches!(out, Err(ServeError::Io(_))), "{out:?}");
        }
    }

    /// The reply write is bounded as a whole too: one blocking write under a
    /// send timeout is not, against a peer that drains a little at a time.
    #[test]
    fn a_peer_that_drains_the_reply_slowly_is_released_by_the_bound() {
        let me = nix::unistd::getuid().as_raw();
        let (a, b) = UnixStream::pair().unwrap();
        let mut r = a;
        r.write_all(&prefixed(&frame(ALICE))).unwrap();
        let (tx, rx) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            let big = |_a: &maknae_deputy::handle::Admitted<'_>| {
                Ok(EgressFrameReply::Reply(maknae_proto::PromptReply {
                    reasoning: None,
                    blocks: vec![ContentBlock::Text {
                        text: SecretText::from(zeroize::Zeroizing::new("a".repeat(900_000))),
                    }],
                    tool_calls: vec![],
                    usage: None,
                }))
            };
            let _ = tx.send(serve_one_unmarked(
                b,
                me,
                &bounds(),
                Duration::from_millis(300),
                big,
            ));
        });
        let started = std::time::Instant::now();
        let mut chunk = [0u8; 16 * 1024];
        let mut drained = 0;
        let out = loop {
            if let Ok(out) = rx.recv_timeout(Duration::from_millis(50)) {
                break out;
            }
            assert!(
                started.elapsed() < Duration::from_secs(5),
                "a slowly draining peer held the reply write past the bound"
            );
            drained += r.read(&mut chunk).unwrap_or(0);
        };
        r.set_nonblocking(true).unwrap();
        drained += r.read(&mut chunk).unwrap_or(0);
        assert!(drained > 0, "the reply write never began: {out:?}");
        assert!(matches!(out, Err(ServeError::Io(_))), "{out:?}");
        assert!(
            started.elapsed() < Duration::from_secs(3),
            "{:?}",
            started.elapsed()
        );
    }

    /// Past both the serving and the refusal slots, a connection is closed
    /// with nothing written, rather than queued behind the others.
    #[test]
    fn past_every_slot_a_connection_is_closed_unanswered() {
        let (release_tx, release_rx) = std::sync::mpsc::channel::<()>();
        let release_rx = std::sync::Mutex::new(release_rx);
        let (_d, path, slots) = looping(1, move |a| {
            let _ = release_rx
                .lock()
                .unwrap()
                .recv_timeout(Duration::from_secs(10));
            canned(a)
        });
        let p = path.clone();
        let held = std::thread::spawn(move || ask(&p));
        eventually("the first connection never took its slot", || {
            slots.in_use() == 1
        });
        let request = prefixed(&frame(ALICE));
        let stalled = UnixStream::connect(&path).unwrap();
        let mut c = UnixStream::connect(&path).unwrap();
        // macOS refuses setsockopt once the deputy has closed, which is the outcome under test.
        let _ = c.set_read_timeout(Some(Duration::from_secs(3)));
        let _ = c.write_all(&request);
        let mut back = Vec::new();
        match c.read_to_end(&mut back) {
            Ok(_) => assert!(back.is_empty(), "a reply was written: {} bytes", back.len()),
            Err(e) => assert_ne!(
                e.kind(),
                std::io::ErrorKind::WouldBlock,
                "the connection was queued, not closed"
            ),
        }
        release_tx.send(()).unwrap();
        assert!(matches!(
            held.join().unwrap(),
            EgressSocketReply::Prompt(EgressFrameReply::Reply(_))
        ));
        drop(stalled);
    }

    /// A stalled connection past capacity is answered off the accept thread,
    /// so the connections behind it are still accepted and answered.
    #[test]
    fn a_stalled_peer_past_capacity_does_not_stop_accepting() {
        let (release_tx, release_rx) = std::sync::mpsc::channel::<()>();
        let release_rx = std::sync::Mutex::new(release_rx);
        let (_d, path, slots) = looping(2, move |a| {
            let _ = release_rx
                .lock()
                .unwrap()
                .recv_timeout(Duration::from_secs(10));
            canned(a)
        });
        let held: Vec<_> = (0..2)
            .map(|_| {
                let p = path.clone();
                std::thread::spawn(move || ask(&p))
            })
            .collect();
        eventually("the first connections never took their slots", || {
            slots.in_use() == 2
        });
        let request = prefixed(&frame(ALICE));
        let stalled = UnixStream::connect(&path).unwrap();
        let started = std::time::Instant::now();
        assert_eq!(ask_with(&path, &request), EgressSocketReply::AtCapacity);
        assert!(
            started.elapsed() < Duration::from_secs(3),
            "the answer waited behind the stalled connection"
        );
        for _ in 0..2 {
            release_tx.send(()).unwrap();
        }
        for h in held {
            assert!(matches!(
                h.join().unwrap(),
                EgressSocketReply::Prompt(EgressFrameReply::Reply(_))
            ));
        }
        drop(stalled);
    }

    /// A peer that connects and sends nothing is released by the bound, on
    /// both paths, rather than holding the connection forever.
    #[test]
    fn a_peer_that_stalls_is_released_by_the_io_bound() {
        let me = nix::unistd::getuid().as_raw();
        let bound = Duration::from_millis(200);
        for at_capacity in [false, true] {
            let (a, b) = UnixStream::pair().unwrap();
            let (tx, rx) = std::sync::mpsc::channel();
            std::thread::spawn(move || {
                let out = if at_capacity {
                    refuse_at_capacity(b, me, bound)
                } else {
                    serve_one_unmarked(b, me, &bounds(), bound, canned)
                };
                let _ = tx.send(out);
            });
            let out = rx
                .recv_timeout(Duration::from_secs(5))
                .expect("a stalled peer held the connection past the bound");
            assert!(matches!(out, Err(ServeError::Io(_))), "{out:?}");
            drop(a);
        }
    }

    /// The receive buffer is `Zeroizing` FROM ALLOCATION, not after decode.
    /// This binding is the regression guard: if `read_body_zeroizing` is ever
    /// changed to hand back a plain `Vec<u8>`, the prompt's serialized copy
    /// would be left in freed heap and this stops compiling.
    #[test]
    fn the_receive_buffer_is_zeroizing_from_allocation() {
        let (a, b) = UnixStream::pair().unwrap();
        let f = frame(ALICE);
        let mut writer = a;
        writer.write_all(&(f.len() as u32).to_be_bytes()).unwrap();
        writer.write_all(&f).unwrap();
        let mut b = b;
        let body: zeroize::Zeroizing<Vec<u8>> =
            read_body_zeroizing(&mut b, std::time::Instant::now() + FRAME_IO_TIMEOUT).unwrap();
        assert_eq!(&*body, &f[..]);
        // And the over-cap refusal happens before any allocation on this path.
        let (mut c, mut d) = UnixStream::pair().unwrap();
        c.write_all(&u32::MAX.to_be_bytes()).unwrap();
        assert_eq!(
            read_body_zeroizing(&mut d, std::time::Instant::now() + FRAME_IO_TIMEOUT),
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

    #[test]
    fn a_decide_refusal_is_answered_refused_before_send() {
        let (out, reply) = served_with(prefixed(&frame("maknae/users-evil/alice/key")), canned);
        assert_eq!(out, Err(ServeError::Refused(Refusal::KeyPathOutsideBounds)));
        assert_eq!(reply, Some(EgressSocketReply::RefusedBeforeSend));
    }

    #[test]
    fn an_opener_failure_is_answered_refused_before_send() {
        let rt = runtime();
        let (out, reply) = served_with(prefixed(&frame(ALICE)), |admitted| {
            rt.block_on(fulfil(
                admitted,
                &Opens(Err(OpenFailure::Seal)),
                CallBounds::default(),
                &mut |_| {},
            ))
            .map_err(serve_error)
        });
        assert_eq!(out, Err(ServeError::OpenFailed(OpenFailure::Seal)));
        assert_eq!(reply, Some(EgressSocketReply::RefusedBeforeSend));
    }

    #[test]
    fn a_provider_failure_closes_the_connection_without_a_reply() {
        fips();
        let rt = runtime();
        let mut r = request(ALICE);
        r.endpoint = DEAD_PROVIDER.into();
        let (out, reply) = served_with(prefixed(&encoded(&r)), |admitted| {
            rt.block_on(fulfil(
                admitted,
                &Opens(Ok("sk-test-not-real")),
                CallBounds::default(),
                &mut |_| {},
            ))
            .map_err(serve_error)
        });
        assert!(matches!(out, Err(ServeError::Fulfil(_))), "{out:?}");
        assert_eq!(reply, None);
    }

    fn one_shot_provider(status_line: &'static str, body: &'static str) -> String {
        use std::io::{Read, Write};
        let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = l.local_addr().unwrap();
        std::thread::spawn(move || {
            let (mut s, _) = l.accept().unwrap();
            let mut seen = Vec::new();
            let mut buf = [0u8; 8192];
            loop {
                let n = s.read(&mut buf).unwrap();
                seen.extend_from_slice(&buf[..n]);
                let Some(brk) = seen.windows(4).position(|w| w == b"\r\n\r\n") else {
                    if n == 0 {
                        break;
                    } else {
                        continue;
                    }
                };
                let head = String::from_utf8_lossy(&seen[..brk]).to_lowercase();
                let want = head
                    .lines()
                    .find_map(|l| l.strip_prefix("content-length:"))
                    .and_then(|v| v.trim().parse::<usize>().ok())
                    .unwrap_or(0);
                if n == 0 || seen.len() - (brk + 4) >= want {
                    break;
                }
            }
            let resp = format!(
                "HTTP/1.1 {status_line}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                body.len()
            );
            s.write_all(resp.as_bytes()).unwrap();
        });
        format!("http://{addr}/v1/chat/completions")
    }

    #[test]
    fn an_unusable_provider_answer_is_written_as_a_frame_and_carries_no_provider_text() {
        fips();
        let rt = runtime();
        for (status, body, want) in [
            (
                "401 Unauthorized",
                r#"{"error":"SENTINEL-524"}"#,
                ReplyDefect::ProviderAuth,
            ),
            (
                "200 OK",
                r#"{"choices":[{"finish_reason":"stop","message":{"content":null,"reasoning":"SENTINEL-524 thoughts"}}]}"#,
                ReplyDefect::ReasoningOnly,
            ),
        ] {
            let mut r = request(ALICE);
            r.endpoint = one_shot_provider(status, body);
            let (out, reply) = served_with(prefixed(&encoded(&r)), |admitted| {
                rt.block_on(fulfil(
                    admitted,
                    &Opens(Ok("sk-test-not-real")),
                    CallBounds::default(),
                    &mut |_| {},
                ))
                .map_err(serve_error)
            });
            assert!(matches!(out, Ok(())), "{status}: {out:?}");
            assert_eq!(
                reply,
                Some(EgressSocketReply::Prompt(EgressFrameReply::Unusable {
                    defect: want,
                    usage: None
                })),
                "{status}"
            );
        }
    }

    #[test]
    fn a_second_connection_opens_its_own_sealed_key() {
        struct Recording {
            sealed: std::sync::Mutex<Vec<Vec<u8>>>,
        }
        impl KeyOpener for Recording {
            async fn open(
                &self,
                sealed: &[u8],
                _r: &OpenRequest<'_>,
            ) -> Result<maknae_io::MaknaeSecret, OpenFailure> {
                self.sealed.lock().unwrap().push(sealed.to_vec());
                Ok(
                    maknae_io::MaknaeSecret::new(zeroize::Zeroizing::new(
                        "sk-test-not-real".into(),
                    ))
                    .unwrap(),
                )
            }
        }
        fips();
        let rt = runtime();
        let opener = Recording {
            sealed: std::sync::Mutex::new(vec![]),
        };
        let mut first = request(ALICE);
        first.endpoint = DEAD_PROVIDER.into();
        let mut second = first.clone();
        second.sealed_key =
            maknae_proto::SealedKey::new(vec![9u8; maknae_proto::SEALED_KEY_MIN_BYTES]).unwrap();
        for r in [&first, &second] {
            let (out, reply) = served_with(prefixed(&encoded(r)), |admitted| {
                rt.block_on(fulfil(
                    admitted,
                    &opener,
                    CallBounds::default(),
                    &mut |_| {},
                ))
                .map_err(serve_error)
            });
            assert!(matches!(out, Err(ServeError::Fulfil(_))), "{out:?}");
            assert_eq!(reply, None);
        }
        assert_eq!(
            *opener.sealed.lock().unwrap(),
            vec![
                vec![7u8; maknae_proto::SEALED_KEY_MIN_BYTES],
                vec![9u8; maknae_proto::SEALED_KEY_MIN_BYTES]
            ],
            "each connection opens the sealed key its own frame carries"
        );
    }

    #[test]
    fn a_refusal_whose_reply_cannot_be_written_still_returns_the_refusal() {
        let (a, mut b) = UnixStream::pair().unwrap();
        drop(a);
        assert_eq!(
            refuse_before_send(
                &mut b,
                ServeError::Refused(Refusal::KeyPathOutsideBounds),
                FRAME_IO_TIMEOUT,
                &AtomicBool::new(false),
            ),
            Err(ServeError::Refused(Refusal::KeyPathOutsideBounds))
        );
    }

    #[test]
    fn a_mint_or_revoke_frame_is_refused_as_a_request_and_never_fulfilled() {
        let sealed = || {
            maknae_proto::SealedCredentialBytes::new(vec![5; maknae_proto::SEALED_KEY_MIN_BYTES])
                .unwrap()
        };
        let mint = EgressFrame::Mint(maknae_proto::MintRequest {
            task: "task-1".into(),
            agent: "coder".into(),
            class: "github".into(),
            kind: "github-app-installation".into(),
            app: "maknae-bot".into(),
            sets: vec![],
        });
        let revoke = EgressFrame::Revoke(maknae_proto::RevokeRequest {
            task: "task-1".into(),
            agent: "coder".into(),
            class: "github".into(),
            kind: "github-app-installation".into(),
            app: "maknae-bot".into(),
            set: 0,
            for_revocation: sealed(),
        });
        for (frame, want) in [
            (
                mint,
                EgressSocketReply::Mint(MintReply::Refused(MintRefusal::Request)),
            ),
            (
                revoke,
                EgressSocketReply::Revoke(RevokeReply::Refused(MintRefusal::Request)),
            ),
        ] {
            let (out, reply) = served_with(prefixed(&encoded_frame(&frame)), |_| {
                panic!("a credential frame reached the provider path")
            });
            assert_eq!(out, Ok(()));
            assert_eq!(reply, Some(want));
        }
    }

    fn reach_bytes() -> Vec<u8> {
        prefixed(&encoded_frame(&EgressFrame::Reach(tasker_reach(
            "github.com",
        ))))
    }

    #[test]
    fn a_reach_frame_is_served_after_the_peer_check() {
        let reach = CannedReach::answering(|| ReachReply::NoForgeCredential);
        let (a, b) = UnixStream::pair().unwrap();
        let me = nix::unistd::getuid().as_raw();
        let bytes = reach_bytes();
        let mut writer = a;
        writer.write_all(&bytes).unwrap();
        let mut keep = b.try_clone().unwrap();
        assert_eq!(
            serve_one(
                b,
                me.wrapping_add(1),
                &bounds(),
                FRAME_IO_TIMEOUT,
                &AtomicBool::new(false),
                FrameRefs {
                    mint: None,
                    reach: &reach,
                },
                |_| panic!("a reach frame reached the provider path"),
            ),
            Err(ServeError::WrongPeer)
        );
        assert_eq!(reach.calls(), 0);
        keep.set_nonblocking(true).unwrap();
        let mut unread = vec![0u8; bytes.len()];
        keep.read_exact(&mut unread).unwrap();
        assert_eq!(unread, bytes, "the frame was left unread");

        let (out, reply) = served_frame_reaching(
            &EgressFrame::Reach(tasker_reach("github.com")),
            None,
            &reach,
        );
        assert_eq!(out, Ok(()));
        assert_eq!(
            reply,
            Some(EgressSocketReply::Reach(ReachReply::NoForgeCredential))
        );
        assert_eq!(reach.calls(), 1);
    }

    #[test]
    fn a_reach_frame_at_capacity_is_answered_at_capacity() {
        let reach = Arc::new(CannedReach::answering(|| ReachReply::NoForgeCredential));
        let (release_tx, release_rx) = std::sync::mpsc::channel::<()>();
        let release_rx = std::sync::Mutex::new(release_rx);
        let (_d, path, slots) = looping_reaching(
            1,
            move |a| {
                let _ = release_rx
                    .lock()
                    .unwrap()
                    .recv_timeout(Duration::from_secs(10));
                canned(a)
            },
            Arc::clone(&reach) as Arc<dyn ReachFrames>,
        );
        let p = path.clone();
        let held = std::thread::spawn(move || ask(&p));
        eventually("the prompt never took its slot", || slots.in_use() == 1);
        assert_eq!(
            ask_with(&path, &reach_bytes()),
            EgressSocketReply::AtCapacity
        );
        assert_eq!(reach.calls(), 0);
        release_tx.send(()).unwrap();
        assert!(matches!(
            held.join().unwrap(),
            EgressSocketReply::Prompt(EgressFrameReply::Reply(_))
        ));
        eventually("the slot was not given back", || slots.in_use() == 0);
        assert_eq!(
            ask_with(&path, &reach_bytes()),
            EgressSocketReply::Reach(ReachReply::NoForgeCredential)
        );
        assert_eq!(reach.calls(), 1);
        eventually("the reach frame kept its slot", || slots.in_use() == 0);
    }

    mod minting {
        use super::*;
        use maknae_config::{ApiBase, MintVault};
        use maknae_deputy::mint::github::GithubClient;
        use maknae_deputy::mint::minter::{self, MintDeps};
        use maknae_deputy::mint::signer::FakeSigner;
        use maknae_proto::{AccessLevel, GithubPermission, PermissionSet, SealedCredentialBytes};
        use maknae_seal::{
            open_credential, CredentialDirection, CredentialSealContext, SealPrivateKey,
        };
        use std::collections::BTreeMap;
        use std::os::unix::fs::PermissionsExt;
        use std::sync::atomic::AtomicUsize;
        use std::sync::Mutex;

        const KIND: &str = "github-app-installation";

        struct TestMinting {
            config: MintingConfig,
            signer: FakeSigner,
            github: GithubClient,
            own: SealPrivateKey,
            egress: tempfile::TempDir,
            rt: tokio::runtime::Runtime,
            mints: AtomicUsize,
            minting_started: std::sync::Arc<AtomicBool>,
            peer_closed: std::sync::Arc<AtomicBool>,
            hold_until_peer_closed: AtomicBool,
            revoke_alls: AtomicUsize,
            journal: Mutex<Vec<String>>,
        }

        impl TestMinting {
            fn new(github_base: &str) -> (Self, SealPrivateKey) {
                fips();
                let egress = tempfile::tempdir().unwrap();
                let agents = egress.path().join("agents");
                std::fs::create_dir(&agents).unwrap();
                for d in [egress.path(), agents.as_path()] {
                    std::fs::set_permissions(d, std::fs::Permissions::from_mode(0o750)).unwrap();
                }
                let agent_key = SealPrivateKey::generate().unwrap();
                let file = agents.join("coder.seal.pub");
                std::fs::write(&file, agent_key.public_key().to_pem()).unwrap();
                std::fs::set_permissions(&file, std::fs::Permissions::from_mode(0o640)).unwrap();
                let app = GithubAppConfig {
                    app_id: 5834363,
                    installation_id: 77,
                    host: "github.example".into(),
                    api: ApiBase::parse("https://api.github.example").unwrap(),
                    transit_mount: "transit".into(),
                    transit_key: "deploy-app".into(),
                };
                let m = Self {
                    config: MintingConfig {
                        vault: MintVault {
                            approle_mount: "approle".into(),
                        },
                        github_apps: BTreeMap::from([("deploy".to_string(), app)]),
                    },
                    signer: FakeSigner::signing(b"sig"),
                    github: GithubClient::loopback_for_tests(github_base),
                    own: SealPrivateKey::generate().unwrap(),
                    egress,
                    rt: runtime(),
                    mints: AtomicUsize::new(0),
                    minting_started: std::sync::Arc::new(AtomicBool::new(false)),
                    peer_closed: std::sync::Arc::new(AtomicBool::new(false)),
                    hold_until_peer_closed: AtomicBool::new(false),
                    revoke_alls: AtomicUsize::new(0),
                    journal: Mutex::new(Vec::new()),
                };
                (m, agent_key)
            }

            fn record(&self) -> impl FnMut(&str) + '_ {
                |l: &str| self.journal.lock().unwrap().push(l.to_string())
            }
        }

        impl MintFrames for TestMinting {
            fn config(&self) -> Result<&MintingConfig, &'static str> {
                Ok(&self.config)
            }

            fn mint(&self, admitted: &AdmittedMint<'_>) -> (MintReply, LiveTokens) {
                self.mints.fetch_add(1, Ordering::SeqCst);
                self.minting_started.store(true, Ordering::SeqCst);
                if self.hold_until_peer_closed.load(Ordering::SeqCst) {
                    let by = Instant::now() + Duration::from_secs(10);
                    while !self.peer_closed.load(Ordering::SeqCst) && Instant::now() < by {
                        std::thread::sleep(Duration::from_millis(1));
                    }
                }
                let mut journal = self.record();
                let mut d = MintDeps {
                    signer: &self.signer,
                    github: &self.github,
                    own_pub: self.own.public_key(),
                    own_key: &self.own,
                    egress_dir: self.egress.path(),
                    clock: &|| Some(1_800_000_000),
                    journal: &mut journal,
                };
                let owner = nix::unistd::getuid().as_raw();
                self.rt
                    .block_on(minter::mint_with_recipient_owner(admitted, &mut d, owner))
            }

            fn revoke(
                &self,
                req: &RevokeRequest,
                agent: &AgentId,
                app: &GithubAppConfig,
            ) -> RevokeReply {
                let mut journal = self.record();
                let mut d = MintDeps {
                    signer: &self.signer,
                    github: &self.github,
                    own_pub: self.own.public_key(),
                    own_key: &self.own,
                    egress_dir: self.egress.path(),
                    clock: &|| Some(1_800_000_000),
                    journal: &mut journal,
                };
                self.rt.block_on(minter::revoke(req, agent, app, &mut d))
            }

            fn revoke_all(&self, live: LiveTokens) {
                self.revoke_alls.fetch_add(1, Ordering::SeqCst);
                let mut journal = self.record();
                self.rt
                    .block_on(minter::revoke_all(&self.github, live, &mut journal));
            }
        }

        fn read_http(s: &mut std::net::TcpStream) -> String {
            let mut seen = Vec::new();
            let mut buf = [0u8; 4096];
            loop {
                let n = s.read(&mut buf).unwrap();
                if n == 0 {
                    break;
                }
                seen.extend_from_slice(&buf[..n]);
                let Some(brk) = seen.windows(4).position(|w| w == b"\r\n\r\n") else {
                    continue;
                };
                let head = String::from_utf8_lossy(&seen[..brk]).to_lowercase();
                let want = head
                    .lines()
                    .find_map(|l| l.strip_prefix("content-length:"))
                    .and_then(|v| v.trim().parse::<usize>().ok())
                    .unwrap_or(0);
                if seen.len() - (brk + 4) >= want {
                    break;
                }
            }
            String::from_utf8_lossy(&seen).to_string()
        }

        fn github_stub(script: Vec<String>) -> (String, std::thread::JoinHandle<Vec<String>>) {
            let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
            l.set_nonblocking(true).unwrap();
            let base = format!("http://{}", l.local_addr().unwrap());
            let h = std::thread::spawn(move || {
                let mut seen = Vec::new();
                for resp in script {
                    let by = Instant::now() + Duration::from_secs(5);
                    let mut s = loop {
                        match l.accept() {
                            Ok((s, _)) => break s,
                            Err(_) if Instant::now() < by => {
                                std::thread::sleep(Duration::from_millis(10))
                            }
                            Err(_) => return seen,
                        }
                    };
                    s.set_nonblocking(false).unwrap();
                    seen.push(read_http(&mut s));
                    let _ = s.write_all(resp.as_bytes());
                }
                seen
            });
            (base, h)
        }

        fn http(status: &str, body: &str) -> String {
            format!(
                "HTTP/1.1 {status}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                body.len()
            )
        }

        fn granted(token: &str, repo: &str) -> String {
            http(
                "201 Created",
                &format!(
                    r#"{{"token":"{token}","expires_at":"2026-11-19T01:00:00Z","permissions":{{"contents":"write"}},"repository_selection":"selected","repositories":[{{"name":"{repo}"}}]}}"#
                ),
            )
        }

        fn revoked() -> String {
            "HTTP/1.1 204 No Content\r\nConnection: close\r\n\r\n".into()
        }

        fn bearers(seen: &[String], method: &str) -> Vec<String> {
            seen.iter()
                .filter(|r| r.starts_with(method))
                .filter_map(|r| {
                    r.lines().find_map(|l| {
                        l.strip_prefix("authorization: Bearer ")
                            .or_else(|| l.strip_prefix("Authorization: Bearer "))
                            .map(|t| t.trim().to_string())
                    })
                })
                .collect()
        }

        fn set(repo: &str) -> PermissionSet {
            PermissionSet {
                repositories: vec![repo.into()],
                permissions: BTreeMap::from([(GithubPermission::Contents, AccessLevel::Write)]),
            }
        }

        fn mint_frame(sets: Vec<PermissionSet>) -> EgressFrame {
            EgressFrame::Mint(MintRequest {
                task: "task-1".into(),
                agent: "coder".into(),
                class: "git-write".into(),
                kind: KIND.into(),
                app: "deploy".into(),
                sets,
            })
        }

        fn revoke_frame(set: u8, blob: SealedCredentialBytes) -> EgressFrame {
            EgressFrame::Revoke(RevokeRequest {
                task: "task-1".into(),
                agent: "coder".into(),
                class: "git-write".into(),
                kind: KIND.into(),
                app: "deploy".into(),
                set,
                for_revocation: blob,
            })
        }

        /// The peer writes its frame and, given `close_once_minting`, closes the
        /// connection after minting has begun, so the peer check has already
        /// passed and only the reply write fails.
        fn served_minting(
            frame: &EgressFrame,
            m: &dyn MintFrames,
            close_once_minting: Option<(std::sync::Arc<AtomicBool>, std::sync::Arc<AtomicBool>)>,
        ) -> (Result<(), ServeError>, Option<EgressSocketReply>) {
            let (a, b) = UnixStream::pair().unwrap();
            let bytes = prefixed(&encoded_frame(frame));
            let (done_tx, done_rx) = std::sync::mpsc::channel::<()>();
            let h = std::thread::spawn(move || {
                let mut c = a;
                c.write_all(&bytes).unwrap();
                let mut back = Vec::new();
                if let Some((started, closed)) = close_once_minting {
                    let by = Instant::now() + Duration::from_secs(10);
                    while !started.load(Ordering::SeqCst) && Instant::now() < by {
                        std::thread::sleep(Duration::from_millis(5));
                    }
                    drop(c);
                    closed.store(true, Ordering::SeqCst);
                } else {
                    c.read_to_end(&mut back).unwrap();
                }
                let _ = done_rx.recv();
                back
            });
            let me = nix::unistd::getuid().as_raw();
            let out = serve_one(
                b,
                me,
                &bounds(),
                FRAME_IO_TIMEOUT,
                &AtomicBool::new(false),
                FrameRefs {
                    mint: Some(m),
                    reach: &no_reach(),
                },
                |_| panic!("a credential frame reached the provider path"),
            );
            let _ = done_tx.send(());
            let back = h.join().unwrap();
            let reply = (!back.is_empty()).then(|| {
                let n = u32::from_be_bytes(back[..4].try_into().unwrap()) as usize;
                assert_eq!(back.len(), 4 + n);
                maknae_proto::decode_egress_socket_reply(&back[4..]).unwrap()
            });
            (out, reply)
        }

        #[test]
        fn a_failed_reply_write_revokes_every_minted_token() {
            let (base, stub) = github_stub(vec![
                granted("ghs_one", "a"),
                granted("ghs_two", "b"),
                revoked(),
                revoked(),
            ]);
            let (m, _agent) = TestMinting::new(&base);
            m.hold_until_peer_closed.store(true, Ordering::SeqCst);
            let (out, reply) = served_minting(
                &mint_frame(vec![set("a"), set("b")]),
                &m,
                Some((m.minting_started.clone(), m.peer_closed.clone())),
            );
            assert!(matches!(out, Err(ServeError::Io(_))), "{out:?}");
            assert_eq!(reply, None);
            assert_eq!(m.mints.load(Ordering::SeqCst), 1);
            assert_eq!(m.revoke_alls.load(Ordering::SeqCst), 1);
            let seen = stub.join().unwrap();
            assert_eq!(bearers(&seen, "DELETE"), ["ghs_one", "ghs_two"]);
            let journal = m.journal.lock().unwrap();
            assert!(
                !journal.iter().any(|l| l.contains("could not be revoked")),
                "{journal:?}"
            );
        }

        #[test]
        fn a_delivered_mint_reply_keeps_its_tokens_live() {
            let (base, stub) = github_stub(vec![granted("ghs_one", "a"), granted("ghs_two", "b")]);
            let (m, agent) = TestMinting::new(&base);
            let (out, reply) = served_minting(&mint_frame(vec![set("a"), set("b")]), &m, None);
            assert_eq!(out, Ok(()));
            let Some(EgressSocketReply::Mint(MintReply::Minted(creds))) = reply else {
                panic!("expected Minted, got {reply:?}");
            };
            assert_eq!(m.revoke_alls.load(Ordering::SeqCst), 0);
            let seen = stub.join().unwrap();
            assert_eq!(bearers(&seen, "DELETE").len(), 0);
            for (i, want) in [(0u8, "ghs_one"), (1, "ghs_two")] {
                let ctx = CredentialSealContext {
                    direction: CredentialDirection::ToAgent,
                    agent: "coder",
                    task: "task-1",
                    class: "git-write",
                    kind: KIND,
                    app: "deploy",
                    set: i,
                };
                let c = &creds[usize::from(i)];
                assert_eq!(c.set, i);
                assert_eq!(
                    open_credential(&agent, &ctx, c.for_agent.as_bytes())
                        .unwrap()
                        .expose(),
                    want
                );
            }
        }

        #[test]
        fn an_inadmissible_mint_with_minting_configured_is_refused_and_never_minted() {
            let (base, stub) = github_stub(vec![]);
            let (m, _agent) = TestMinting::new(&base);
            for frame in [
                mint_frame(vec![]),
                EgressFrame::Mint(MintRequest {
                    app: "unknown".into(),
                    ..match mint_frame(vec![set("a")]) {
                        EgressFrame::Mint(r) => r,
                        _ => unreachable!(),
                    }
                }),
            ] {
                let (out, reply) = served_minting(&frame, &m, None);
                assert_eq!(out, Ok(()));
                assert_eq!(
                    reply,
                    Some(EgressSocketReply::Mint(MintReply::Refused(
                        MintRefusal::Request
                    )))
                );
            }
            assert_eq!(m.mints.load(Ordering::SeqCst), 0);
            assert!(m.signer.calls().is_empty());
            assert!(stub.join().unwrap().is_empty());
        }

        #[test]
        fn a_revoke_frame_opens_its_blob_and_deletes_that_token() {
            let (base, stub) = github_stub(vec![granted("ghs_one", "a"), revoked()]);
            let (m, _agent) = TestMinting::new(&base);
            let (_, reply) = served_minting(&mint_frame(vec![set("a")]), &m, None);
            let Some(EgressSocketReply::Mint(MintReply::Minted(mut creds))) = reply else {
                panic!("expected Minted, got {reply:?}");
            };
            let blob = creds.pop().unwrap().for_revocation;
            let (out, reply) = served_minting(&revoke_frame(9, blob.clone()), &m, None);
            assert_eq!(out, Ok(()));
            assert_eq!(
                reply,
                Some(EgressSocketReply::Revoke(RevokeReply::Refused(
                    MintRefusal::Request
                )))
            );
            let (out, reply) = served_minting(&revoke_frame(0, blob), &m, None);
            assert_eq!(out, Ok(()));
            assert_eq!(reply, Some(EgressSocketReply::Revoke(RevokeReply::Revoked)));
            let seen = stub.join().unwrap();
            assert_eq!(bearers(&seen, "DELETE"), ["ghs_one"]);
        }
    }
}
