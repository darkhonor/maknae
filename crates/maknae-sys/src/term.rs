use std::io;
use std::os::fd::{AsRawFd, BorrowedFd};

/// `(rows, cols)` of the terminal open on `tty`, from `ioctl(TIOCGWINSZ)`.
#[allow(unsafe_code)]
pub fn window_size(tty: BorrowedFd<'_>) -> io::Result<(u16, u16)> {
    let mut size = libc::winsize {
        ws_row: 0,
        ws_col: 0,
        ws_xpixel: 0,
        ws_ypixel: 0,
    };
    // SAFETY: the descriptor is borrowed, so it stays open for the whole call. TIOCGWINSZ
    // copies out exactly one `struct winsize`, and the pointer is to `size`, an initialised
    // local `libc::winsize` that outlives the call.
    let rc = unsafe { libc::ioctl(tty.as_raw_fd(), libc::TIOCGWINSZ, &raw mut size) };
    if rc == -1 {
        return Err(io::Error::last_os_error());
    }
    Ok((size.ws_row, size.ws_col))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::fd::AsFd;

    #[test]
    fn window_size_of_a_pty_is_what_was_set() {
        let size = nix::pty::Winsize {
            ws_row: 37,
            ws_col: 101,
            ws_xpixel: 0,
            ws_ypixel: 0,
        };
        let pty = nix::pty::openpty(&size, None).unwrap();
        assert_eq!(window_size(pty.slave.as_fd()).unwrap(), (37, 101));
        assert_eq!(window_size(pty.master.as_fd()).unwrap(), (37, 101));
    }

    #[test]
    fn window_size_of_a_regular_file_is_an_error() {
        let file = std::fs::File::open(concat!(env!("CARGO_MANIFEST_DIR"), "/Cargo.toml")).unwrap();
        let got = window_size(file.as_fd()).map_err(|e| e.raw_os_error());
        assert_eq!(got, Err(Some(libc::ENOTTY)));
    }
}
