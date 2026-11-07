//! One Varlink call over a Unix socket: a NUL-terminated request and the first
//! NUL-terminated reply, all under one wall-clock deadline.

use std::io::{self, Read, Write};
use std::os::fd::{AsFd, AsRawFd};
use std::os::unix::net::UnixStream;
use std::path::Path;
use std::time::{Duration, Instant};

use maknae_io::Zeroizing;
use nix::errno::Errno;
use nix::poll::{poll, PollFd, PollFlags, PollTimeout};
use nix::sys::socket::{connect, socket, AddressFamily, SockFlag, SockType, UnixAddr};

pub(super) fn call(
    path: &Path,
    listener_uid: u32,
    request: &[u8],
    deadline: Duration,
    cap: usize,
) -> io::Result<Zeroizing<Vec<u8>>> {
    let deadline_at = Instant::now()
        .checked_add(deadline)
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "deadline overflows"))?;
    let mut stream = connect_nonblocking(path)?;
    match maknae_vault::listener_uid_is(&stream, listener_uid) {
        Ok(true) => {}
        Ok(false) => {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                format!("{} is not served by uid {listener_uid}", path.display()),
            ))
        }
        Err(e) => return Err(io::Error::other(format!("listener credentials: {e}"))),
    }
    write_all_by(&mut stream, request, deadline_at)?;
    read_frame_by(&mut stream, cap, deadline_at)
}

fn connect_nonblocking(path: &Path) -> io::Result<UnixStream> {
    let addr = UnixAddr::new(path)?;
    let fd = match socket(
        AddressFamily::Unix,
        SockType::Stream,
        SockFlag::SOCK_NONBLOCK | SockFlag::SOCK_CLOEXEC,
        None,
    ) {
        Ok(fd) => fd,
        Err(e) => return Err(io::Error::other(format!("socket: {e}"))),
    };
    connect(fd.as_raw_fd(), &addr)?;
    Ok(UnixStream::from(fd))
}

fn wait_for<S: AsFd>(stream: &S, flags: PollFlags, deadline_at: Instant) -> io::Result<()> {
    loop {
        let left = deadline_at.saturating_duration_since(Instant::now());
        if left.is_zero() {
            return Err(io::ErrorKind::TimedOut.into());
        }
        let timeout =
            PollTimeout::try_from(left.max(Duration::from_millis(1))).unwrap_or(PollTimeout::MAX);
        let mut fds = [PollFd::new(stream.as_fd(), flags)];
        match poll(&mut fds, timeout) {
            Ok(0) | Err(Errno::EINTR) => continue,
            Ok(_) => return Ok(()),
            Err(e) => return Err(io::Error::other(format!("poll: {e}"))),
        }
    }
}

fn write_retried(e: &io::Error) -> bool {
    matches!(
        e.kind(),
        io::ErrorKind::Interrupted | io::ErrorKind::WouldBlock
    )
}

fn read_retried(e: &io::Error) -> bool {
    matches!(e.kind(), io::ErrorKind::Interrupted)
}

fn frame_end(chunk: &[u8]) -> Option<usize> {
    chunk.iter().position(|&b| b == 0)
}

fn write_all_by<S: Write + AsFd>(
    stream: &mut S,
    buf: &[u8],
    deadline_at: Instant,
) -> io::Result<()> {
    let mut written = 0;
    while written < buf.len() {
        wait_for(stream, PollFlags::POLLOUT, deadline_at)?;
        match stream.write(&buf[written..]) {
            Ok(0) => return Err(io::ErrorKind::WriteZero.into()),
            Ok(n) => written += n,
            Err(e) => {
                if !write_retried(&e) {
                    return Err(e);
                }
            }
        }
    }
    Ok(())
}

fn read_frame_by<S: Read + AsFd>(
    stream: &mut S,
    cap: usize,
    deadline_at: Instant,
) -> io::Result<Zeroizing<Vec<u8>>> {
    let mut buf = Zeroizing::new(vec![0u8; cap]);
    let mut filled = 0;
    while filled < cap {
        wait_for(stream, PollFlags::POLLIN, deadline_at)?;
        match stream.read(&mut buf[filled..]) {
            Ok(0) => return Err(io::ErrorKind::UnexpectedEof.into()),
            Ok(n) => {
                if let Some(end) = frame_end(&buf[filled..filled + n]) {
                    buf.truncate(filled + end);
                    return Ok(buf);
                }
                filled += n;
            }
            Err(e) => {
                if !read_retried(&e) {
                    return Err(e);
                }
            }
        }
    }
    Err(io::Error::new(
        io::ErrorKind::InvalidData,
        format!("reply exceeds {cap} bytes"),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::VecDeque;
    use std::os::fd::BorrowedFd;

    fn soon() -> Instant {
        Instant::now() + Duration::from_secs(2)
    }

    fn pair() -> (UnixStream, UnixStream) {
        let (a, b) = UnixStream::pair().expect("pair");
        a.set_nonblocking(true).expect("nonblocking");
        (a, b)
    }

    struct Scripted {
        fd: std::fs::File,
        reads: VecDeque<io::Result<Vec<u8>>>,
        writes: VecDeque<io::Result<usize>>,
    }

    impl Scripted {
        fn new() -> Self {
            Scripted {
                fd: std::fs::File::open("/dev/null").expect("/dev/null"),
                reads: VecDeque::new(),
                writes: VecDeque::new(),
            }
        }
    }

    impl AsFd for Scripted {
        fn as_fd(&self) -> BorrowedFd<'_> {
            self.fd.as_fd()
        }
    }

    impl Read for Scripted {
        fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
            let bytes = self.reads.pop_front().expect("scripted read")?;
            out[..bytes.len()].copy_from_slice(&bytes);
            Ok(bytes.len())
        }
    }

    impl Write for Scripted {
        fn write(&mut self, _: &[u8]) -> io::Result<usize> {
            self.writes.pop_front().expect("scripted write")
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    #[test]
    fn the_write_leg_retries_only_interruption_and_would_block() {
        assert!(write_retried(&io::ErrorKind::Interrupted.into()));
        assert!(write_retried(&io::ErrorKind::WouldBlock.into()));
        assert!(!write_retried(&io::ErrorKind::BrokenPipe.into()));
    }

    #[test]
    fn the_read_leg_retries_only_interruption() {
        assert!(read_retried(&io::ErrorKind::Interrupted.into()));
        assert!(!read_retried(&io::ErrorKind::WouldBlock.into()));
        assert!(!read_retried(&io::ErrorKind::ConnectionReset.into()));
    }

    #[test]
    fn a_frame_ends_at_the_first_nul() {
        assert_eq!(frame_end(b""), None);
        assert_eq!(frame_end(b"abc"), None);
        assert_eq!(frame_end(b"\0"), Some(0));
        assert_eq!(frame_end(b"ab\0c\0"), Some(2));
    }

    #[test]
    fn a_frame_in_one_read_is_returned_without_its_terminator() {
        let (mut a, mut b) = pair();
        b.write_all(b"{}\0trailing").expect("write");
        assert_eq!(&**read_frame_by(&mut a, 64, soon()).expect("frame"), b"{}");
    }

    #[test]
    fn a_frame_split_across_reads_is_reassembled() {
        let (mut a, mut b) = pair();
        b.write_all(b"abc").expect("write");
        let late = std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(50));
            b.write_all(b"de\0").expect("write");
            b
        });
        assert_eq!(
            &**read_frame_by(&mut a, 64, soon()).expect("frame"),
            b"abcde"
        );
        late.join().expect("writer");
    }

    #[test]
    fn a_frame_filling_the_cap_is_read_and_one_byte_more_is_refused() {
        let (mut a, mut b) = pair();
        b.write_all(b"1234567\0").expect("write");
        assert_eq!(
            &**read_frame_by(&mut a, 8, soon()).expect("frame"),
            b"1234567"
        );
        let (mut a, mut b) = pair();
        b.write_all(b"12345678\0").expect("write");
        let e = read_frame_by(&mut a, 8, soon()).expect_err("over the cap");
        assert_eq!(e.kind(), io::ErrorKind::InvalidData);
    }

    #[test]
    fn end_of_stream_before_the_terminator_is_refused() {
        let (mut a, mut b) = pair();
        b.write_all(b"abc").expect("write");
        drop(b);
        let e = read_frame_by(&mut a, 64, soon()).expect_err("eof");
        assert_eq!(e.kind(), io::ErrorKind::UnexpectedEof);
    }

    #[test]
    fn a_silent_peer_times_out_at_the_deadline() {
        let (mut a, _b) = pair();
        let started = Instant::now();
        let e =
            read_frame_by(&mut a, 64, started + Duration::from_millis(100)).expect_err("silent");
        assert_eq!(e.kind(), io::ErrorKind::TimedOut);
        assert!(started.elapsed() >= Duration::from_millis(100));
        assert!(started.elapsed() < Duration::from_millis(900));
    }

    #[test]
    fn a_spent_deadline_refuses_before_waiting() {
        let (mut a, mut b) = pair();
        b.write_all(b"{}\0").expect("write");
        let e = read_frame_by(&mut a, 64, Instant::now()).expect_err("spent");
        assert_eq!(e.kind(), io::ErrorKind::TimedOut);
    }

    #[test]
    fn an_interrupted_read_is_retried_and_a_would_block_is_not() {
        let mut s = Scripted::new();
        s.reads.push_back(Err(io::ErrorKind::Interrupted.into()));
        s.reads.push_back(Ok(b"ok\0".to_vec()));
        assert_eq!(&**read_frame_by(&mut s, 64, soon()).expect("frame"), b"ok");
        let mut s = Scripted::new();
        s.reads.push_back(Err(io::ErrorKind::WouldBlock.into()));
        let e = read_frame_by(&mut s, 64, soon()).expect_err("would block");
        assert_eq!(e.kind(), io::ErrorKind::WouldBlock);
    }

    #[test]
    fn the_write_leg_retries_and_finishes_partial_writes() {
        let mut s = Scripted::new();
        s.writes.push_back(Err(io::ErrorKind::WouldBlock.into()));
        s.writes.push_back(Ok(2));
        s.writes.push_back(Err(io::ErrorKind::Interrupted.into()));
        s.writes.push_back(Ok(3));
        write_all_by(&mut s, b"hello", soon()).expect("written");
        assert!(s.writes.is_empty());
    }

    #[test]
    fn a_zero_write_and_a_hard_write_error_are_refused() {
        let mut s = Scripted::new();
        s.writes.push_back(Ok(0));
        let e = write_all_by(&mut s, b"x", soon()).expect_err("zero");
        assert_eq!(e.kind(), io::ErrorKind::WriteZero);
        let (mut a, b) = pair();
        drop(b);
        let e = write_all_by(&mut a, b"x", soon()).expect_err("closed peer");
        assert_eq!(e.kind(), io::ErrorKind::BrokenPipe);
    }

    #[test]
    fn an_overflowing_deadline_is_refused() {
        let e = call(Path::new("/nonexistent"), 0, b"", Duration::MAX, 64).expect_err("overflow");
        assert_eq!(e.kind(), io::ErrorKind::InvalidInput);
    }

    #[test]
    fn a_socket_path_too_long_for_sun_path_is_refused() {
        let long = format!("/{}", "a".repeat(200));
        assert!(call(Path::new(&long), 0, b"", Duration::from_secs(1), 64).is_err());
    }

    #[test]
    fn a_deadline_spent_by_the_connect_refuses_the_write() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("sock");
        let _listener = std::os::unix::net::UnixListener::bind(&path).expect("bind");
        let me = nix::unistd::getuid().as_raw();
        let e = call(&path, me, b"x\0", Duration::from_nanos(1), 64).expect_err("spent");
        assert_eq!(e.kind(), io::ErrorKind::TimedOut);
    }
}
