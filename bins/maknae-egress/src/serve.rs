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
use maknae_config::EgressBounds;
use maknae_deputy::call::FulfilError;
use maknae_deputy::handle::{decide, Refusal};
use maknae_deputy::unseal::OpenFailure;
use maknae_proto::EgressFrameReply;
use nix::poll::{poll, PollFd, PollFlags, PollTimeout};
use std::io::{Read, Write};
use std::os::fd::AsFd;
use std::os::unix::net::{UnixListener, UnixStream};
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
    io_timeout: Duration,
    fulfil: F,
) -> Result<(), ServeError>
where
    F: FnOnce(&maknae_deputy::handle::Admitted<'_>) -> Result<EgressFrameReply, ServeError>,
{
    authenticate(&stream, expected_uid, io_timeout)?;

    let body = read_body_zeroizing(&mut stream, Instant::now() + io_timeout)?;

    let req = maknae_proto::decode_egress_frame_request(&body).map_err(io)?;
    let admitted = match decide(&req, bounds) {
        Ok(a) => a,
        Err(r) => return refuse_before_send(&mut stream, ServeError::Refused(r), io_timeout),
    };
    match fulfil(&admitted) {
        Ok(reply) => write_reply(&mut stream, &reply, io_timeout),
        Err(e @ ServeError::OpenFailed(_)) => refuse_before_send(&mut stream, e, io_timeout),
        Err(ServeError::Unusable { defect, usage }) => write_reply(
            &mut stream,
            &EgressFrameReply::Unusable { defect, usage },
            io_timeout,
        ),
        Err(e) => Err(e),
    }
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
pub fn refuse_at_capacity(
    mut stream: UnixStream,
    expected_uid: u32,
    io_timeout: Duration,
) -> Result<(), ServeError> {
    authenticate(&stream, expected_uid, io_timeout)?;
    drop(read_body_zeroizing(
        &mut stream,
        Instant::now() + io_timeout,
    )?);
    write_reply(&mut stream, &EgressFrameReply::AtCapacity, io_timeout)
}

/// Accept forever. A failed connection is refused and the loop continues: one
/// bad or hostile peer must not take the deputy down. A connection that
/// panics calls `on_panic` instead.
pub fn accept_loop<H, P>(
    listener: UnixListener,
    slots: Arc<Slots>,
    expected_uid: u32,
    bounds: Arc<EgressBounds>,
    io_timeout: Duration,
    handler: Arc<H>,
    on_panic: Arc<P>,
) where
    H: Fn(&maknae_deputy::handle::Admitted<'_>) -> Result<EgressFrameReply, ServeError>
        + Send
        + Sync
        + 'static,
    P: Fn() + Send + Sync + 'static,
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
            answer_at_capacity(stream, &refusals, expected_uid, io_timeout, &on_panic);
            continue;
        };
        let spare = stream.try_clone();
        let (bounds, handler) = (Arc::clone(&bounds), Arc::clone(&handler));
        let spawned = spawn_guarded("maknae-egress-conn", slot, &on_panic, move || {
            if let Err(e) = serve_one(stream, expected_uid, &bounds, io_timeout, |a| handler(a)) {
                eprintln!("maknae-egress: connection refused: {e:?}");
            }
        });
        if let Err(e) = spawned {
            eprintln!("maknae-egress: cannot start a connection thread: {e}");
            if let Ok(s) = spare {
                answer_at_capacity(s, &refusals, expected_uid, io_timeout, &on_panic);
            }
        }
    }
}

/// Off the accept thread, so a stalled peer here never delays the next
/// accept. Refusals hold their own slots; past those, the connection closes
/// unanswered rather than queueing.
fn answer_at_capacity<P: Fn() + Send + Sync + 'static>(
    stream: UnixStream,
    refusals: &Arc<Slots>,
    expected_uid: u32,
    io_timeout: Duration,
    on_panic: &Arc<P>,
) {
    let Some(slot) = refusals.try_take() else {
        eprintln!(
            "maknae-egress: at capacity and no refusal slot free; closed a connection unanswered"
        );
        return;
    };
    let spawned =
        spawn_guarded(
            "maknae-egress-refuse",
            slot,
            on_panic,
            move || match refuse_at_capacity(stream, expected_uid, io_timeout) {
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

/// Every connection and refusal thread starts here. The log is a plain write,
/// because `eprintln!` panics when stderr fails and would skip `on_panic`.
fn spawn_guarded<P: Fn() + Send + Sync + 'static>(
    name: &str,
    slot: Slot,
    on_panic: &Arc<P>,
    work: impl FnOnce() + Send + 'static,
) -> std::io::Result<()> {
    let on_panic = Arc::clone(on_panic);
    std::thread::Builder::new()
        .name(name.into())
        .spawn(move || {
            let _slot = slot;
            if let Err(payload) = std::panic::catch_unwind(std::panic::AssertUnwindSafe(work)) {
                let _ = writeln!(
                    std::io::stderr(),
                    "maknae-egress: a connection panicked; exiting so a clean deputy is restarted"
                );
                on_panic();
                // Never dropped: a payload whose destructor panics would unwind past `on_panic`.
                std::mem::forget(payload);
            }
        })
        .map(drop)
}

fn refuse_before_send(
    stream: &mut UnixStream,
    why: ServeError,
    io_timeout: Duration,
) -> Result<(), ServeError> {
    if let Err(w) = write_reply(stream, &EgressFrameReply::RefusedBeforeSend, io_timeout) {
        eprintln!("maknae-egress: the refused-before-send reply was not delivered: {w:?}");
    }
    Err(why)
}

fn write_reply(
    stream: &mut UnixStream,
    reply: &EgressFrameReply,
    io_timeout: Duration,
) -> Result<(), ServeError> {
    let by = Instant::now() + io_timeout;
    // Into ONE fixed preallocation that never grows (#241, codex round 2 item
    // B): a reply carries whatever kernel-served content the model quoted
    // back, and the growing buffer this replaces freed a partly-written copy
    // of it on every realloc. A reply past the headroom is a codec error
    // here — before the length prefix, so the kernel reads nothing.
    let out = maknae_proto::encode_egress_frame_reply(
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
    use maknae_deputy::call::{fulfil, CallBounds};
    use maknae_deputy::unseal::{KeyOpener, OpenRequest};
    use maknae_proto::{ContentBlock, EgressFrameRequest, ReplyDefect, SecretText};
    use std::path::PathBuf;

    const ALICE: &str = "maknae/users/alice/openai/personal";
    const DEAD_PROVIDER: &str = "http://127.0.0.1:1/v1/chat/completions";

    fn canned(_a: &maknae_deputy::handle::Admitted<'_>) -> Result<EgressFrameReply, ServeError> {
        Ok(EgressFrameReply::Reply(maknae_proto::PromptReply {
            reasoning: None,
            blocks: vec![],
            tool_calls: vec![],
            usage: None,
        }))
    }

    fn bounds() -> EgressBounds {
        EgressBounds {
            call_timeout_ms: maknae_config::DEFAULT_CALL_TIMEOUT_MS,
            kv_mount: "maknae-kv".into(),
            user_prefix: "maknae/users".into(),
            vault_addr: "https://vault.example:8200".into(),
        }
    }

    fn request(key: &str) -> EgressFrameRequest {
        EgressFrameRequest {
            deadline_ms: None,
            destination: "provider:openai".into(),
            endpoint: "https://api.example.test/v1".into(),
            model: "m".into(),
            key_vault_path: key.into(),
            key_field: "api_key".into(),
            reasoning_effort: None,
            conversation: "conv1".into(),
            turns: vec![maknae_proto::Turn::User {
                content: vec![ContentBlock::Text {
                    text: SecretText(zeroize::Zeroizing::new("hi".into())),
                }],
            }],
            output_tokens: None,
            output_tokens_field: None,
            sealed_key: maknae_proto::SealedKey::new(vec![7u8; maknae_proto::SEALED_KEY_MIN_BYTES])
                .unwrap(),
        }
    }

    fn encoded(r: &EgressFrameRequest) -> Vec<u8> {
        maknae_proto::encode_egress_frame_request(
            r,
            maknae_proto::EGRESS_REQUEST_FRAME_ENCODE_BYTES,
        )
        .unwrap()
        .to_vec()
    }

    fn frame(key: &str) -> Vec<u8> {
        encoded(&request(key))
    }

    fn prefixed(body: &[u8]) -> Vec<u8> {
        let mut out = (body.len() as u32).to_be_bytes().to_vec();
        out.extend_from_slice(body);
        out
    }

    fn fips() {
        static ONCE: std::sync::Once = std::sync::Once::new();
        ONCE.call_once(maknae_vault::install_default_crypto_provider);
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
        ) -> Result<zeroize::Zeroizing<String>, OpenFailure> {
            self.0.map(|k| zeroize::Zeroizing::new(k.to_string()))
        }
    }

    fn served_with<F>(
        bytes: Vec<u8>,
        fulfil: F,
    ) -> (Result<(), ServeError>, Option<EgressFrameReply>)
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
        let out = serve_one(b, me, &bounds(), FRAME_IO_TIMEOUT, fulfil);
        let back = h.join().unwrap();
        let reply = (!back.is_empty()).then(|| {
            let n = u32::from_be_bytes(back[..4].try_into().unwrap()) as usize;
            assert_eq!(back.len(), 4 + n, "one reply frame and nothing after it");
            maknae_proto::decode_egress_frame_reply(&back[4..]).unwrap()
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
        let out = serve_one(b, expected_uid, &bounds(), FRAME_IO_TIMEOUT, canned);
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
            serve_one(b, me.wrapping_add(1), &bounds(), FRAME_IO_TIMEOUT, canned),
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
            maknae_proto::decode_egress_frame_reply(&body).unwrap()
        });
        serve_one(b, me, &bounds(), FRAME_IO_TIMEOUT, canned).unwrap();
        let reply = h.join().unwrap();
        assert_eq!(
            reply,
            maknae_proto::EgressFrameReply::Reply(maknae_proto::PromptReply {
                reasoning: None,
                blocks: vec![],
                tool_calls: vec![],
                usage: None,
            })
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
        let (_d, path, slots, panics) = looping_counting_panics(4, canned);
        drop(UnixStream::connect(&path).unwrap());
        assert!(matches!(ask(&path), EgressFrameReply::Reply(_)));
        eventually("the served connection kept its slot", || {
            slots.in_use() == 0
        });
        assert_eq!(panics.load(std::sync::atomic::Ordering::SeqCst), 0);
    }

    fn looping<H>(cap: usize, handler: H) -> (tempfile::TempDir, PathBuf, Arc<Slots>)
    where
        H: Fn(&maknae_deputy::handle::Admitted<'_>) -> Result<EgressFrameReply, ServeError>
            + Send
            + Sync
            + 'static,
    {
        let (d, path, slots, _) = looping_counting_panics(cap, handler);
        (d, path, slots)
    }

    fn looping_counting_panics<H>(
        cap: usize,
        handler: H,
    ) -> (
        tempfile::TempDir,
        PathBuf,
        Arc<Slots>,
        Arc<std::sync::atomic::AtomicUsize>,
    )
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
        let panics = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let counted = Arc::clone(&panics);
        std::thread::spawn(move || {
            accept_loop(
                l,
                held,
                me,
                Arc::new(bounds()),
                Duration::from_secs(5),
                Arc::new(handler),
                Arc::new(move || {
                    counted.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                }),
            )
        });
        (d, path, slots, panics)
    }

    fn ask(path: &std::path::Path) -> EgressFrameReply {
        ask_with(path, &prefixed(&frame(ALICE)))
    }

    fn ask_with(path: &std::path::Path, request: &[u8]) -> EgressFrameReply {
        let mut c = UnixStream::connect(path).unwrap();
        c.set_read_timeout(Some(Duration::from_secs(20))).unwrap();
        c.write_all(request).unwrap();
        let mut len = [0u8; 4];
        c.read_exact(&mut len).unwrap();
        let mut body = vec![0u8; u32::from_be_bytes(len) as usize];
        c.read_exact(&mut body).unwrap();
        maknae_proto::decode_egress_frame_reply(&body).unwrap()
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
        assert!(matches!(ask(&path), EgressFrameReply::Reply(_)));
        assert!(matches!(other.join().unwrap(), EgressFrameReply::Reply(_)));
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
        assert_eq!(ask(&path), EgressFrameReply::AtCapacity);
        release_tx.send(()).unwrap();
        assert!(matches!(held.join().unwrap(), EgressFrameReply::Reply(_)));
        eventually("the slot was not given back", || slots.in_use() == 0);
        release_tx.send(()).unwrap();
        assert!(matches!(ask(&path), EgressFrameReply::Reply(_)));
    }

    #[test]
    fn a_panic_whose_payload_panics_on_drop_is_still_fatal() {
        struct Bomb;
        impl Drop for Bomb {
            fn drop(&mut self) {
                panic!("payload dropped");
            }
        }
        let (_d, path, _slots, panics) =
            looping_counting_panics(1, |_a| std::panic::panic_any(Bomb));
        let request = prefixed(&frame(ALICE));
        let mut c = UnixStream::connect(&path).unwrap();
        c.write_all(&request).unwrap();
        let mut rest = Vec::new();
        let _ = c.read_to_end(&mut rest);
        eventually("the payload's drop skipped on_panic", || {
            panics.load(std::sync::atomic::Ordering::SeqCst) == 1
        });
    }

    #[test]
    fn a_panicking_connection_is_fatal_and_gives_its_slot_back() {
        let (_d, path, slots, panics) = looping_counting_panics(1, |_a| panic!("handler panicked"));
        let request = prefixed(&frame(ALICE));
        let mut c = UnixStream::connect(&path).unwrap();
        c.write_all(&request).unwrap();
        let mut rest = Vec::new();
        let _ = c.read_to_end(&mut rest);
        eventually("a panicking connection was not reported fatal", || {
            panics.load(std::sync::atomic::Ordering::SeqCst) == 1
        });
        eventually("a panicking handler kept its slot", || slots.in_use() == 0);
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
            maknae_proto::decode_egress_frame_reply(&back[4..]).unwrap(),
            EgressFrameReply::AtCapacity
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
                    serve_one(b, me, &bounds(), bound, canned)
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
                        text: SecretText(zeroize::Zeroizing::new("a".repeat(900_000))),
                    }],
                    tool_calls: vec![],
                    usage: None,
                }))
            };
            let _ = tx.send(serve_one(b, me, &bounds(), Duration::from_millis(300), big));
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
        assert!(matches!(held.join().unwrap(), EgressFrameReply::Reply(_)));
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
        assert_eq!(ask_with(&path, &request), EgressFrameReply::AtCapacity);
        assert!(
            started.elapsed() < Duration::from_secs(3),
            "the answer waited behind the stalled connection"
        );
        for _ in 0..2 {
            release_tx.send(()).unwrap();
        }
        for h in held {
            assert!(matches!(h.join().unwrap(), EgressFrameReply::Reply(_)));
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
                    serve_one(b, me, &bounds(), bound, canned)
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
        assert_eq!(reply, Some(EgressFrameReply::RefusedBeforeSend));
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
        assert_eq!(reply, Some(EgressFrameReply::RefusedBeforeSend));
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
                Some(EgressFrameReply::Unusable {
                    defect: want,
                    usage: None
                }),
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
            ) -> Result<zeroize::Zeroizing<String>, OpenFailure> {
                self.sealed.lock().unwrap().push(sealed.to_vec());
                Ok(zeroize::Zeroizing::new("sk-test-not-real".into()))
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
                FRAME_IO_TIMEOUT
            ),
            Err(ServeError::Refused(Refusal::KeyPathOutsideBounds))
        );
    }
}
