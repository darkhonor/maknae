use std::io::{self, Read, Write};
use std::os::unix::net::UnixStream;
use std::sync::OnceLock;

use nix::fcntl::{fcntl, FcntlArg, OFlag};
use zeroize::Zeroizing;

use rustix::process::{getrlimit, setrlimit, Resource, Rlimit};

use crate::credential::{LaunchCredentials, ReceiveError, MAX_FRAME};

static CORE_DUMPS_DENIED: OnceLock<Result<(), i32>> = OnceLock::new();

/// Lowers the soft core limit to 0 and, on Linux, makes the process non-dumpable, once; a
/// failure is sticky. A holder calls it before fetching a credential. Only the soft limit
/// moves, so no `process:setrlimit` permission is needed under a confined domain.
pub fn deny_core_dumps() -> io::Result<()> {
    (*CORE_DUMPS_DENIED.get_or_init(|| deny().map_err(|e| e.raw_os_error())))
        .map_err(io::Error::from_raw_os_error)
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
    /// Writes the credentials frame. The stream must be blocking with a write timeout set;
    /// #755 writes the signed obligation's frame first, then this one, on the same stream.
    pub fn send(self, stream: &UnixStream) -> io::Result<()> {
        if !blocking(stream)? || stream.write_timeout()?.is_none() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "a blocking stream with a write timeout is required",
            ));
        }
        let body = self.encode();
        let mut writer = stream;
        writer.write_all(&(body.len() as u32).to_be_bytes())?;
        writer.write_all(&body)
    }

    /// Reads one credentials frame into a buffer that is zeroized from allocation.
    pub fn receive(stream: &UnixStream) -> Result<Self, ReceiveError> {
        if !blocking(stream).map_err(ReceiveError::Io)? {
            return Err(ReceiveError::NotBlocking);
        }
        if stream.read_timeout().map_err(ReceiveError::Io)?.is_none() {
            return Err(ReceiveError::NoTimeout);
        }
        let mut reader = stream;
        let mut len = [0u8; 4];
        reader.read_exact(&mut len).map_err(ReceiveError::Io)?;
        let len = u32::from_be_bytes(len) as usize;
        if len > MAX_FRAME {
            return Err(ReceiveError::TooLong);
        }
        let mut body = Zeroizing::new(vec![0u8; len]);
        reader.read_exact(&mut body).map_err(ReceiveError::Io)?;
        Self::decode(&body).map_err(ReceiveError::Decode)
    }
}

fn blocking(stream: &UnixStream) -> io::Result<bool> {
    let flags = fcntl(stream, FcntlArg::F_GETFL).map_err(io::Error::from)?;
    Ok(!OFlag::from_bits_truncate(flags).contains(OFlag::O_NONBLOCK))
}

#[cfg(test)]
mod tests {
    use super::*;

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

    use crate::credential::{CredentialSlot, DeliveredCredential};
    use std::time::Duration;

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

    fn one() -> LaunchCredentials {
        let mut lc = LaunchCredentials::new([9; 16]);
        DeliveredCredential::new(Zeroizing::new(b"secret-751".to_vec()))
            .unwrap()
            .deliver_to(&mut lc, CredentialSlot::env_var("GH_TOKEN").unwrap())
            .unwrap();
        lc
    }

    #[test]
    fn send_then_receive_carries_the_credentials() {
        let (a, b) = pair();
        one().send(&a).unwrap();
        let got = LaunchCredentials::receive(&b).unwrap();
        assert_eq!(got.invocation(), [9; 16]);
        assert_eq!(got.slots().count(), 1);
    }

    #[test]
    fn a_non_blocking_stream_is_refused() {
        let (a, b) = pair();
        a.set_nonblocking(true).unwrap();
        b.set_nonblocking(true).unwrap();
        assert_eq!(
            one().send(&a).unwrap_err().kind(),
            io::ErrorKind::InvalidInput
        );
        assert!(matches!(
            LaunchCredentials::receive(&b),
            Err(ReceiveError::NotBlocking)
        ));
    }

    #[test]
    fn a_stream_without_a_timeout_is_refused() {
        let (a, b) = UnixStream::pair().unwrap();
        assert_eq!(
            one().send(&a).unwrap_err().kind(),
            io::ErrorKind::InvalidInput
        );
        assert!(matches!(
            LaunchCredentials::receive(&b),
            Err(ReceiveError::NoTimeout)
        ));
    }

    #[test]
    fn a_peer_that_stalls_after_the_length_times_out() {
        let (mut a, b) = pair();
        a.write_all(&100u32.to_be_bytes()).unwrap();
        match LaunchCredentials::receive(&b) {
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
        let (mut a, b) = pair();
        a.write_all(&u32::MAX.to_be_bytes()).unwrap();
        assert!(matches!(
            LaunchCredentials::receive(&b),
            Err(ReceiveError::TooLong)
        ));
    }

    #[test]
    fn a_malformed_frame_is_a_decode_error() {
        let (mut a, b) = pair();
        a.write_all(&4u32.to_be_bytes()).unwrap();
        a.write_all(b"XXXX").unwrap();
        assert!(matches!(
            LaunchCredentials::receive(&b),
            Err(ReceiveError::Decode(_))
        ));
    }

    #[test]
    fn sending_to_a_closed_peer_fails() {
        let (a, b) = pair();
        drop(b);
        assert!(one().send(&a).is_err());
    }
}
