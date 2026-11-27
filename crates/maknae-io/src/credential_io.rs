use std::io;
use std::os::fd::AsFd;
use std::os::unix::net::UnixStream;
use std::sync::OnceLock;
use std::time::{Duration, Instant};

use nix::fcntl::{fcntl, FcntlArg, OFlag};
use nix::poll::{poll, PollFd, PollFlags, PollTimeout};
use rustix::net::{recv, send, RecvFlags, SendFlags};
use rustix::process::{getrlimit, setrlimit, Resource, Rlimit};
use zeroize::Zeroizing;

use crate::credential::{LaunchCredentials, ReceiveError, MAX_FRAME};

// POLLOUT promises the send low-water mark (2048 by default) is free, and Darwin's send ignores
// MSG_DONTWAIT, so a larger write could block past the deadline.
const SEND_CHUNK: usize = 2048;

static CORE_DUMPS_DENIED_FAILED: OnceLock<i32> = OnceLock::new();

/// Lowers the soft core limit to 0 and, on Linux, makes the process non-dumpable. It reapplies
/// on every call, since a uid or gid change resets dumpability; a failure is sticky. A holder
/// calls it before fetching a credential. Only the soft limit moves, so no `process:setrlimit`
/// permission is needed under a confined domain.
pub fn deny_core_dumps() -> io::Result<()> {
    if let Some(code) = CORE_DUMPS_DENIED_FAILED.get() {
        return Err(io::Error::from_raw_os_error(*code));
    }
    deny().map_err(|e| {
        io::Error::from_raw_os_error(*CORE_DUMPS_DENIED_FAILED.get_or_init(|| e.raw_os_error()))
    })
}

fn deny() -> rustix::io::Result<()> {
    let hard = getrlimit(Resource::Core).maximum;
    setrlimit(
        Resource::Core,
        Rlimit {
            current: Some(0),
            maximum: hard,
        },
    )?;
    #[cfg(target_os = "linux")]
    rustix::process::set_dumpable_behavior(rustix::process::DumpableBehavior::NotDumpable)?;
    Ok(())
}

impl LaunchCredentials {
    /// Writes the credentials frame. The stream must be blocking with a write timeout set; that
    /// timeout bounds the whole frame, and the stream's options are left as they were. #755
    /// writes the signed obligation's frame first, then this one. A failed send leaves the
    /// stream mid-frame, so the caller closes it.
    pub fn send(self, stream: &mut UnixStream) -> io::Result<()> {
        let budget = match stream.write_timeout() {
            Ok(Some(budget)) if blocking(stream) => budget,
            _ => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "a blocking stream with a write timeout is required",
                ))
            }
        };
        let at = deadline(budget)?;
        let body = self.encode();
        write_by(stream, &(body.len() as u32).to_be_bytes(), at)?;
        write_by(stream, &body, at)
    }

    /// Reads one credentials frame into a buffer that is zeroized from allocation. The read
    /// timeout bounds the whole frame, and the stream's options are left as they were. Core
    /// dumps are denied before the first byte is read. A failed receive leaves the stream
    /// mid-frame, so the caller closes it.
    pub fn receive(stream: &mut UnixStream) -> Result<Self, ReceiveError> {
        if !blocking(stream) {
            return Err(ReceiveError::NotBlocking);
        }
        let Ok(Some(budget)) = stream.read_timeout() else {
            return Err(ReceiveError::NoTimeout);
        };
        deny_core_dumps().map_err(ReceiveError::Io)?;
        let at = deadline(budget).map_err(ReceiveError::Io)?;
        let mut len = [0u8; 4];
        read_by(stream, &mut len, at).map_err(ReceiveError::Io)?;
        let len = u32::from_be_bytes(len) as usize;
        if len > MAX_FRAME {
            return Err(ReceiveError::TooLong);
        }
        let mut body = Zeroizing::new(vec![0u8; len]);
        read_by(stream, &mut body, at).map_err(ReceiveError::Io)?;
        Self::decode(&body).map_err(ReceiveError::Decode)
    }
}

fn blocking(stream: &UnixStream) -> bool {
    fcntl(stream, FcntlArg::F_GETFL)
        .is_ok_and(|flags| !OFlag::from_bits_truncate(flags).contains(OFlag::O_NONBLOCK))
}

fn deadline(budget: Duration) -> io::Result<Instant> {
    Instant::now().checked_add(budget).ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "the stream timeout is out of range",
        )
    })
}

fn wait(stream: &UnixStream, flags: PollFlags, at: Instant) -> io::Result<()> {
    loop {
        let left = at.saturating_duration_since(Instant::now());
        if left.is_zero() {
            return Err(io::Error::from(io::ErrorKind::TimedOut));
        }
        let timeout =
            PollTimeout::try_from(left.max(Duration::from_millis(1))).unwrap_or(PollTimeout::MAX);
        match poll(&mut [PollFd::new(stream.as_fd(), flags)], timeout) {
            Ok(0) | Err(nix::errno::Errno::EINTR) => {}
            Ok(_) => return Ok(()),
            Err(e) => return Err(e.into()),
        }
    }
}

fn read_by(stream: &UnixStream, mut buf: &mut [u8], at: Instant) -> io::Result<()> {
    while !buf.is_empty() {
        wait(stream, PollFlags::POLLIN, at)?;
        match recv(stream, &mut *buf, RecvFlags::DONTWAIT) {
            Ok((0, _)) => return Err(io::Error::from(io::ErrorKind::UnexpectedEof)),
            Ok((n, _)) => buf = &mut buf[n..],
            Err(rustix::io::Errno::AGAIN | rustix::io::Errno::INTR) => {}
            Err(e) => return Err(e.into()),
        }
    }
    Ok(())
}

fn write_by(stream: &UnixStream, mut buf: &[u8], at: Instant) -> io::Result<()> {
    while !buf.is_empty() {
        wait(stream, PollFlags::POLLOUT, at)?;
        match send(
            stream,
            &buf[..buf.len().min(SEND_CHUNK)],
            SendFlags::DONTWAIT,
        ) {
            Ok(0) => return Err(io::Error::from(io::ErrorKind::WriteZero)),
            Ok(n) => buf = &buf[n..],
            Err(rustix::io::Errno::AGAIN | rustix::io::Errno::INTR) => {}
            Err(e) => return Err(e.into()),
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    #[test]
    fn deny_core_dumps_lowers_only_the_soft_core_limit() {
        let before = getrlimit(Resource::Core);
        deny_core_dumps().unwrap();
        let after = getrlimit(Resource::Core);
        assert_eq!(after.current, Some(0));
        assert_eq!(after.maximum, before.maximum);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn deny_core_dumps_makes_the_process_non_dumpable() {
        deny_core_dumps().unwrap();
        assert_eq!(
            rustix::process::dumpable_behavior().unwrap(),
            rustix::process::DumpableBehavior::NotDumpable
        );
    }

    use crate::credential::CredentialSlot;

    fn pair() -> (UnixStream, UnixStream) {
        let (a, b) = UnixStream::pair().unwrap();
        for s in [&a, &b] {
            s.set_read_timeout(Some(Duration::from_millis(500)))
                .unwrap();
            s.set_write_timeout(Some(Duration::from_millis(500)))
                .unwrap();
        }
        (a, b)
    }

    fn big() -> LaunchCredentials {
        let mut lc = LaunchCredentials::new([4; 16]);
        for i in 0..crate::credential::MAX_CREDENTIALS {
            crate::MaknaeSecretBytes::new(Zeroizing::new(vec![b'v'; crate::MAX_SECRET_BYTES]))
                .unwrap()
                .into_delivered()
                .deliver_to(&mut lc, CredentialSlot::env_var(&format!("T{i}")).unwrap())
                .unwrap();
        }
        lc
    }

    fn one() -> LaunchCredentials {
        let mut lc = LaunchCredentials::new([9; 16]);
        crate::MaknaeSecretBytes::new(Zeroizing::new(b"secret-751".to_vec()))
            .unwrap()
            .into_delivered()
            .deliver_to(&mut lc, CredentialSlot::env_var("GH_TOKEN").unwrap())
            .unwrap();
        lc
    }

    #[test]
    fn send_then_receive_carries_the_credentials() {
        let (mut a, mut b) = pair();
        one().send(&mut a).unwrap();
        let got = LaunchCredentials::receive(&mut b).unwrap();
        assert_eq!(got.invocation(), [9; 16]);
        assert_eq!(got.slots().count(), 1);
    }

    #[test]
    fn a_non_blocking_stream_is_refused() {
        let (mut a, mut b) = pair();
        a.set_nonblocking(true).unwrap();
        b.set_nonblocking(true).unwrap();
        assert_eq!(
            one().send(&mut a).unwrap_err().kind(),
            io::ErrorKind::InvalidInput
        );
        assert!(matches!(
            LaunchCredentials::receive(&mut b),
            Err(ReceiveError::NotBlocking)
        ));
    }

    #[test]
    fn a_stream_without_a_timeout_is_refused() {
        let (mut a, mut b) = UnixStream::pair().unwrap();
        assert_eq!(
            one().send(&mut a).unwrap_err().kind(),
            io::ErrorKind::InvalidInput
        );
        assert!(matches!(
            LaunchCredentials::receive(&mut b),
            Err(ReceiveError::NoTimeout)
        ));
    }

    #[test]
    fn a_peer_that_stalls_after_the_length_times_out() {
        let (mut a, mut b) = pair();
        a.write_all(&100u32.to_be_bytes()).unwrap();
        match LaunchCredentials::receive(&mut b) {
            Err(ReceiveError::Io(e)) => assert!(
                matches!(
                    e.kind(),
                    io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
                ),
                "{e:?}"
            ),
            other => panic!("expected a timeout, got {other:?}"),
        }
    }

    #[test]
    fn a_length_over_the_frame_bound_is_refused_before_reading() {
        let (mut a, mut b) = pair();
        a.write_all(&u32::MAX.to_be_bytes()).unwrap();
        assert!(matches!(
            LaunchCredentials::receive(&mut b),
            Err(ReceiveError::TooLong)
        ));
    }

    #[test]
    fn a_malformed_frame_is_a_decode_error() {
        let (mut a, mut b) = pair();
        a.write_all(&4u32.to_be_bytes()).unwrap();
        a.write_all(b"XXXX").unwrap();
        assert!(matches!(
            LaunchCredentials::receive(&mut b),
            Err(ReceiveError::Decode(_))
        ));
    }

    #[test]
    fn sending_to_a_closed_peer_fails() {
        let (mut a, b) = pair();
        drop(b);
        assert!(one().send(&mut a).is_err());
    }

    #[test]
    fn send_needs_a_write_timeout_not_only_a_read_timeout() {
        let (mut a, _b) = UnixStream::pair().unwrap();
        a.set_read_timeout(Some(Duration::from_millis(500)))
            .unwrap();
        assert_eq!(
            one().send(&mut a).unwrap_err().kind(),
            io::ErrorKind::InvalidInput
        );
    }

    #[test]
    fn a_peer_that_closes_mid_body_is_an_unexpected_eof() {
        let (mut a, mut b) = pair();
        a.write_all(&100u32.to_be_bytes()).unwrap();
        a.write_all(b"MKLC").unwrap();
        drop(a);
        match LaunchCredentials::receive(&mut b) {
            Err(ReceiveError::Io(e)) => assert_eq!(e.kind(), io::ErrorKind::UnexpectedEof),
            other => panic!("expected EOF, got {other:?}"),
        }
    }

    #[test]
    fn a_peer_that_trickles_bytes_hits_the_deadline_not_just_the_idle_timeout() {
        let (mut a, mut b) = UnixStream::pair().unwrap();
        b.set_read_timeout(Some(Duration::from_millis(300)))
            .unwrap();
        let trickle = std::thread::spawn(move || {
            let _ = a.write_all(&8u32.to_be_bytes());
            for _ in 0..8 {
                std::thread::sleep(Duration::from_millis(150));
                if a.write_all(b"X").is_err() {
                    break;
                }
            }
        });
        let started = std::time::Instant::now();
        let got = LaunchCredentials::receive(&mut b);
        let took = started.elapsed();
        drop(b);
        trickle.join().unwrap();
        match got {
            Err(ReceiveError::Io(e)) => assert_eq!(e.kind(), io::ErrorKind::TimedOut, "{e:?}"),
            other => panic!("expected the deadline, got {other:?}"),
        }
        assert!(took < Duration::from_millis(900), "{took:?}");
    }

    #[test]
    fn send_and_receive_leave_the_callers_timeouts_as_they_were() {
        let (mut a, mut b) = UnixStream::pair().unwrap();
        a.set_write_timeout(Some(Duration::from_secs(5))).unwrap();
        b.set_read_timeout(Some(Duration::from_secs(7))).unwrap();
        let sender = std::thread::spawn(move || {
            big().send(&mut a).unwrap();
            a
        });
        std::thread::sleep(Duration::from_millis(100));
        LaunchCredentials::receive(&mut b).unwrap();
        let a = sender.join().unwrap();
        assert_eq!(a.write_timeout().unwrap(), Some(Duration::from_secs(5)));
        assert_eq!(b.read_timeout().unwrap(), Some(Duration::from_secs(7)));
    }

    #[test]
    fn receive_restores_the_read_timeout_after_a_peer_pauses_mid_frame() {
        let (mut a, mut b) = UnixStream::pair().unwrap();
        b.set_read_timeout(Some(Duration::from_secs(7))).unwrap();
        let body = one().encode();
        let peer = std::thread::spawn(move || {
            a.write_all(&(body.len() as u32).to_be_bytes()).unwrap();
            std::thread::sleep(Duration::from_millis(100));
            a.write_all(&body).unwrap();
        });
        LaunchCredentials::receive(&mut b).unwrap();
        peer.join().unwrap();
        assert_eq!(b.read_timeout().unwrap(), Some(Duration::from_secs(7)));
    }

    fn slow_drain(mut b: UnixStream) -> std::thread::JoinHandle<()> {
        std::thread::spawn(move || {
            let mut chunk = [0u8; 4096];
            for _ in 0..40 {
                std::thread::sleep(Duration::from_millis(25));
                if std::io::Read::read(&mut b, &mut chunk).unwrap_or(0) == 0 {
                    break;
                }
            }
        })
    }

    #[test]
    fn a_slow_draining_peer_cannot_hold_the_write_loop_past_its_deadline() {
        let (a, b) = UnixStream::pair().unwrap();
        let drain = slow_drain(b);
        let payload = vec![0u8; MAX_FRAME];
        let started = Instant::now();
        let got = write_by(&a, &payload, deadline(Duration::from_millis(300)).unwrap());
        let took = started.elapsed();
        drop(a);
        drain.join().unwrap();
        assert_eq!(got.unwrap_err().kind(), io::ErrorKind::TimedOut);
        assert!(took < Duration::from_millis(450), "{took:?}");
    }

    #[test]
    fn send_to_a_slow_draining_peer_times_out() {
        let (mut a, b) = UnixStream::pair().unwrap();
        a.set_write_timeout(Some(Duration::from_millis(300)))
            .unwrap();
        let drain = slow_drain(b);
        let got = big().send(&mut a);
        drop(a);
        drain.join().unwrap();
        assert_eq!(got.unwrap_err().kind(), io::ErrorKind::TimedOut);
    }
    #[test]
    fn a_budget_past_the_clock_is_refused() {
        assert_eq!(
            deadline(Duration::MAX).unwrap_err().kind(),
            io::ErrorKind::InvalidInput
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn a_peer_that_resets_the_connection_is_an_io_error() {
        let (a, mut b) = pair();
        b.write_all(b"unread").unwrap();
        drop(a);
        match LaunchCredentials::receive(&mut b) {
            Err(ReceiveError::Io(e)) => assert_eq!(e.kind(), io::ErrorKind::ConnectionReset),
            other => panic!("expected a reset, got {other:?}"),
        }
    }
}
