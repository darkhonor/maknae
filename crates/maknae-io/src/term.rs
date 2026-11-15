use std::io;
use std::os::fd::AsFd;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TerminalSize {
    pub rows: u16,
    pub cols: u16,
}

/// The size of the terminal open on `tty`; a zero dimension is `InvalidData`.
pub fn terminal_size(tty: &impl AsFd) -> io::Result<TerminalSize> {
    let (rows, cols) = maknae_sys::window_size(tty.as_fd())?;
    nonzero(rows, cols)
}

fn nonzero(rows: u16, cols: u16) -> io::Result<TerminalSize> {
    if rows == 0 || cols == 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("terminal reports a {rows}x{cols} window"),
        ));
    }
    Ok(TerminalSize { rows, cols })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pty(rows: u16, cols: u16) -> nix::pty::OpenptyResult {
        let size = nix::pty::Winsize {
            ws_row: rows,
            ws_col: cols,
            ws_xpixel: 0,
            ws_ypixel: 0,
        };
        nix::pty::openpty(&size, None).unwrap()
    }

    #[test]
    fn terminal_size_of_a_pty_is_what_was_set() {
        let pty = pty(37, 101);
        assert_eq!(
            terminal_size(&pty.slave).unwrap(),
            TerminalSize {
                rows: 37,
                cols: 101
            }
        );
    }

    #[test]
    fn terminal_size_refuses_zero_dimensions() {
        for (rows, cols) in [(0, 0), (0, 80), (24, 0)] {
            let err = terminal_size(&pty(rows, cols).slave).unwrap_err();
            assert_eq!(err.kind(), io::ErrorKind::InvalidData, "{rows}x{cols}");
            assert_eq!(err.raw_os_error(), None, "{rows}x{cols}");
            assert_eq!(
                nonzero(rows, cols).unwrap_err().kind(),
                io::ErrorKind::InvalidData
            );
        }
        assert_eq!(nonzero(1, 1).unwrap(), TerminalSize { rows: 1, cols: 1 });
    }

    #[test]
    fn terminal_size_of_a_regular_file_passes_the_errno_through() {
        let file = tempfile::tempfile().unwrap();
        let err = terminal_size(&file).unwrap_err();
        assert_eq!(err.raw_os_error(), Some(nix::errno::Errno::ENOTTY as i32));
    }
}
