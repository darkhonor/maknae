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
    if !maknae_vault::listener_uid_is(&stream, listener_uid).map_err(io::Error::other)? {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            format!("{} is not served by uid {listener_uid}", path.display()),
        ));
    }
    write_all_by(&mut stream, request, deadline_at)?;
    read_frame_by(&mut stream, cap, deadline_at)
}

fn connect_nonblocking(path: &Path) -> io::Result<UnixStream> {
    let fd = socket(
        AddressFamily::Unix,
        SockType::Stream,
        SockFlag::SOCK_NONBLOCK | SockFlag::SOCK_CLOEXEC,
        None,
    )?;
    connect(fd.as_raw_fd(), &UnixAddr::new(path)?)?;
    Ok(UnixStream::from(fd))
}

fn wait_for(stream: &UnixStream, flags: PollFlags, deadline_at: Instant) -> io::Result<()> {
    loop {
        let left = deadline_at.saturating_duration_since(Instant::now());
        if left.is_zero() {
            return Err(io::ErrorKind::TimedOut.into());
        }
        let timeout =
            PollTimeout::try_from(left.max(Duration::from_millis(1))).unwrap_or(PollTimeout::MAX);
        let mut fds = [PollFd::new(stream.as_fd(), flags)];
        match poll(&mut fds, timeout) {
            Ok(0) => return Err(io::ErrorKind::TimedOut.into()),
            Ok(_) => return Ok(()),
            Err(Errno::EINTR) => continue,
            Err(e) => return Err(e.into()),
        }
    }
}

fn retried(e: &io::Error) -> bool {
    matches!(
        e.kind(),
        io::ErrorKind::Interrupted | io::ErrorKind::WouldBlock
    )
}

fn write_all_by(stream: &mut UnixStream, buf: &[u8], deadline_at: Instant) -> io::Result<()> {
    let mut written = 0;
    while written < buf.len() {
        wait_for(stream, PollFlags::POLLOUT, deadline_at)?;
        match stream.write(&buf[written..]) {
            Ok(0) => return Err(io::ErrorKind::WriteZero.into()),
            Ok(n) => written += n,
            Err(e) => {
                if !retried(&e) {
                    return Err(e);
                }
            }
        }
    }
    Ok(())
}

fn read_frame_by(
    stream: &mut UnixStream,
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
                if let Some(end) = buf[filled..filled + n].iter().position(|&b| b == 0) {
                    buf.truncate(filled + end);
                    return Ok(buf);
                }
                filled += n;
            }
            Err(e) => {
                if !retried(&e) {
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
