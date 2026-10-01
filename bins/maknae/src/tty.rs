use maknae_vault::{Password, PasswordFeed, PasswordLine, VaultError};
use nix::errno::Errno;
use nix::sys::termios::{
    tcgetattr, tcsetattr, LocalFlags, SetArg, SpecialCharacterIndices, Termios,
};
use std::io::{IsTerminal, Write};
use std::os::fd::{AsFd, BorrowedFd};
use zeroize::Zeroizing;

#[derive(Debug)]
pub(crate) enum PromptError {
    NotATerminal,
    EchoStillOn,
    Interrupted,
    NoPassword,
    TooLong,
    Terminal(Errno),
    Read(Errno),
    Password(VaultError),
}

impl std::fmt::Display for PromptError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PromptError::NotATerminal => f.write_str(
                "no terminal on standard input: run it interactively; the password is read only \
                 from a hidden prompt, never from arguments, the environment or a pipe",
            ),
            PromptError::EchoStillOn => {
                f.write_str("the terminal kept echo on, so no password was read")
            }
            PromptError::Interrupted => f.write_str("interrupted"),
            PromptError::NoPassword => f.write_str("no password was entered"),
            PromptError::TooLong => f.write_str("the password is longer than 1024 bytes"),
            PromptError::Terminal(e) => {
                write!(f, "the terminal could not be switched to hidden input: {e}")
            }
            PromptError::Read(e) => write!(f, "the terminal could not be read: {e}"),
            PromptError::Password(e) => write!(f, "{e}"),
        }
    }
}

struct Restore<'a> {
    fd: BorrowedFd<'a>,
    saved: Termios,
}

impl Drop for Restore<'_> {
    fn drop(&mut self) {
        if tcsetattr(self.fd, SetArg::TCSAFLUSH, &self.saved) == Err(Errno::EINTR) {
            let _ = tcsetattr(self.fd, SetArg::TCSAFLUSH, &self.saved);
        }
    }
}

fn hidden(saved: &Termios) -> Termios {
    let mut t = saved.clone();
    t.local_flags.remove(
        LocalFlags::ECHO
            | LocalFlags::ECHONL
            | LocalFlags::ICANON
            | LocalFlags::ISIG
            | LocalFlags::IEXTEN,
    );
    t.control_chars[SpecialCharacterIndices::VMIN as usize] = 1;
    t.control_chars[SpecialCharacterIndices::VTIME as usize] = 0;
    t
}

pub(crate) fn stdin_is_terminal() -> bool {
    std::io::stdin().is_terminal()
}

pub(crate) fn read_password(prompt: &str) -> Result<Password, PromptError> {
    if !stdin_is_terminal() {
        return Err(PromptError::NotATerminal);
    }
    let stdin = std::io::stdin();
    read_password_on(stdin.as_fd(), &mut std::io::stderr(), prompt)
}

pub(crate) fn read_password_on(
    fd: BorrowedFd<'_>,
    out: &mut impl Write,
    prompt: &str,
) -> Result<Password, PromptError> {
    let saved = tcgetattr(fd).map_err(PromptError::Terminal)?;
    tcsetattr(fd, SetArg::TCSAFLUSH, &hidden(&saved)).map_err(PromptError::Terminal)?;
    let restore = Restore { fd, saved };
    let applied = tcgetattr(fd).map_err(PromptError::Terminal)?;
    if applied.local_flags.contains(LocalFlags::ECHO) {
        return Err(PromptError::EchoStillOn);
    }
    let _ = write!(out, "{prompt}").and_then(|()| out.flush());
    let mut line = PasswordLine::new();
    let fed = feed_until_end(fd, &mut line);
    drop(restore);
    let _ = writeln!(out);
    match fed? {
        Ended::Done => line.finish().map_err(PromptError::Password),
        Ended::Interrupted => Err(PromptError::Interrupted),
        Ended::TooLong => Err(PromptError::TooLong),
        Ended::Eof => Err(PromptError::NoPassword),
    }
}

enum Ended {
    Done,
    Interrupted,
    TooLong,
    Eof,
}

fn feed_until_end(fd: BorrowedFd<'_>, line: &mut PasswordLine) -> Result<Ended, PromptError> {
    let mut byte = Zeroizing::new([0u8; 1]);
    loop {
        match nix::unistd::read(fd, &mut byte[..]) {
            Ok(0) => return Ok(Ended::Eof),
            Ok(_) => match line.feed(byte[0]) {
                PasswordFeed::More => {}
                PasswordFeed::Done => return Ok(Ended::Done),
                PasswordFeed::Interrupted => return Ok(Ended::Interrupted),
                PasswordFeed::TooLong => return Ok(Ended::TooLong),
                PasswordFeed::Eof => return Ok(Ended::Eof),
            },
            Err(Errno::EINTR) => {}
            Err(e) => return Err(PromptError::Read(e)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use nix::sys::termios::{ControlFlags, InputFlags, OutputFlags};
    use std::os::fd::OwnedFd;
    use std::sync::mpsc;
    use std::time::{Duration, Instant};

    struct Prompted(mpsc::Sender<()>);

    impl Write for Prompted {
        fn write(&mut self, b: &[u8]) -> std::io::Result<usize> {
            Ok(b.len())
        }

        fn flush(&mut self) -> std::io::Result<()> {
            let _ = self.0.send(());
            Ok(())
        }
    }

    fn pty() -> (OwnedFd, OwnedFd) {
        let p = nix::pty::openpty(None, None).unwrap();
        let mut t = tcgetattr(&p.slave).unwrap();
        t.local_flags
            .insert(LocalFlags::ECHO | LocalFlags::ICANON | LocalFlags::ISIG);
        tcsetattr(&p.slave, SetArg::TCSANOW, &t).unwrap();
        (p.master, p.slave)
    }

    type Mode = (InputFlags, OutputFlags, ControlFlags, LocalFlags, Vec<u8>);

    fn modes(fd: impl AsFd) -> Mode {
        let t = tcgetattr(fd).unwrap();
        (
            t.input_flags,
            t.output_flags,
            t.control_flags,
            t.local_flags - LocalFlags::PENDIN,
            t.control_chars.to_vec(),
        )
    }

    const MARKER: &[u8] = b"END-OF-ECHO";

    type Typed = (Result<Password, PromptError>, Mode, Mode, Vec<u8>);

    fn type_at_prompt(keys: &[u8]) -> Typed {
        let (master, slave) = pty();
        let before = modes(&slave);
        let drain = master.try_clone().unwrap();
        let (echo_tx, echo_rx) = mpsc::channel();
        std::thread::spawn(move || {
            let mut chunk = [0u8; 256];
            while let Ok(n @ 1..) = nix::unistd::read(&drain, &mut chunk) {
                if echo_tx.send(chunk[..n].to_vec()).is_err() {
                    break;
                }
            }
        });
        let (prompted_tx, prompted_rx) = mpsc::channel();
        let (done_tx, done_rx) = mpsc::channel();
        std::thread::spawn(move || {
            let got = read_password_on(slave.as_fd(), &mut Prompted(prompted_tx), "Password: ");
            let after = modes(&slave);
            let _ = done_tx.send((got, after, slave));
        });
        let _ = prompted_rx.recv_timeout(Duration::from_secs(10));
        nix::unistd::write(&master, keys).unwrap();
        let (got, after, _slave) = done_rx
            .recv_timeout(Duration::from_secs(10))
            .expect("the prompt did not return within 10 s");
        nix::unistd::write(&master, MARKER).unwrap();
        let deadline = Instant::now() + Duration::from_secs(10);
        let mut seen = Vec::new();
        while !seen.windows(MARKER.len()).any(|w| w == MARKER) {
            let left = deadline.saturating_duration_since(Instant::now());
            let chunk = echo_rx
                .recv_timeout(left)
                .expect("the marker was never echoed back");
            seen.extend_from_slice(&chunk);
        }
        let at = seen
            .windows(MARKER.len())
            .position(|w| w == MARKER)
            .unwrap();
        seen.truncate(at);
        (got, before, after, seen)
    }

    #[test]
    fn a_typed_password_is_read_hidden_and_the_terminal_restored() {
        let (got, before, after, echoed) = type_at_prompt(b"s3cret\r");
        assert_eq!(got.unwrap().len(), 6);
        assert_eq!(after, before);
        assert!(!echoed.windows(6).any(|w| w == b"s3cret"), "{echoed:?}");
    }

    #[test]
    fn ctrl_c_interrupts_and_restores_the_terminal() {
        let (got, before, after, _) = type_at_prompt(b"ab\x03");
        assert!(matches!(got, Err(PromptError::Interrupted)));
        assert_eq!(after, before);
    }

    #[test]
    fn ctrl_backslash_interrupts_and_restores_the_terminal() {
        let (got, before, after, _) = type_at_prompt(b"ab\x1c");
        assert!(matches!(got, Err(PromptError::Interrupted)));
        assert_eq!(after, before);
    }

    #[test]
    fn an_over_long_password_is_refused_and_the_terminal_restored() {
        let (got, before, after, _) = type_at_prompt(&[b'a'; 1025]);
        assert!(matches!(got, Err(PromptError::TooLong)));
        assert_eq!(after, before);
    }

    #[test]
    fn ctrl_d_on_an_empty_line_is_no_password() {
        let (got, before, after, _) = type_at_prompt(b"\x04");
        assert!(matches!(got, Err(PromptError::NoPassword)));
        assert_eq!(after, before);
    }

    #[test]
    fn a_descriptor_that_is_not_a_terminal_is_refused_before_any_prompt() {
        let (r, _w) = nix::unistd::pipe().unwrap();
        let mut out = Vec::new();
        assert!(matches!(
            read_password_on(r.as_fd(), &mut out, "Password: "),
            Err(PromptError::Terminal(_))
        ));
        assert!(out.is_empty());
    }

    #[test]
    fn every_refusal_reads_as_a_sentence() {
        for e in [
            PromptError::NotATerminal,
            PromptError::EchoStillOn,
            PromptError::Interrupted,
            PromptError::NoPassword,
            PromptError::TooLong,
            PromptError::Terminal(nix::errno::Errno::ENOTTY),
            PromptError::Read(nix::errno::Errno::EIO),
        ] {
            assert!(!e.to_string().is_empty());
        }
        assert!(PromptError::NotATerminal
            .to_string()
            .contains("never from arguments, the environment or a pipe"));
    }
}
