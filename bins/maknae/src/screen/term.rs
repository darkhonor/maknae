use crate::tty::{self, Restore};
use maknae_agent::screen::frame::{FrameError, TerminalSize};
use nix::errno::Errno;
use nix::poll::{poll, PollFd, PollFlags, PollTimeout};
use nix::sys::signal::{raise, Signal};
use nix::sys::termios::{tcgetattr, tcsetattr, LocalFlags, SetArg, Termios};
use std::io::IsTerminal;
use std::os::fd::{AsFd, BorrowedFd, OwnedFd};
use std::panic::PanicHookInfo;
use std::sync::{Arc, Mutex, PoisonError, TryLockError};
use tokio::task::JoinHandle;

pub(crate) const ENTER: &[u8] = b"\x1b[?1049h\x1b[?7l\x1b[?2004h\x1b[?1007h\x1b[?25l";
pub(crate) const LEAVE: &[u8] = b"\x1b[?1007l\x1b[?2004l\x1b[?7h\x1b[?25h\x1b[?1049l";

#[derive(Debug)]
pub(crate) enum TermError {
    Terminal(Errno),
    EchoStillOn,
    Size(std::io::Error),
    Read(Errno),
    Write(Errno),
    Signals(std::io::Error),
    Stop(Errno),
    Frame(FrameError),
    Waiter,
}

impl std::fmt::Display for TermError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TermError::Terminal(e) => {
                write!(f, "the terminal could not be switched to raw input: {e}")
            }
            TermError::EchoStillOn => f.write_str("the terminal kept line editing or echo on"),
            TermError::Size(e) => write!(f, "the terminal's size could not be read: {e}"),
            TermError::Read(e) => write!(f, "the terminal could not be read: {e}"),
            TermError::Write(e) => write!(f, "the terminal could not be written: {e}"),
            TermError::Signals(e) => {
                write!(f, "the session's signals could not be registered: {e}")
            }
            TermError::Stop(e) => write!(f, "the session could not be suspended: {e}"),
            TermError::Frame(e) => write!(f, "{e}"),
            TermError::Waiter => f.write_str("the wait for input stopped unexpectedly"),
        }
    }
}

type Hook = Box<dyn Fn(&PanicHookInfo<'_>) + Sync + Send + 'static>;

struct Restorer {
    output: OwnedFd,
    termios: Restore<OwnedFd>,
}

impl Restorer {
    fn leave(&self) {
        let _ = write_all(&self.output, LEAVE);
        self.termios.restore();
    }
}

type Shared = Arc<Mutex<Option<Restorer>>>;

/// The terminal in raw mode and the session's modes until dropped, a panic or
/// a stop puts it back.
pub(crate) struct Session {
    input: OwnedFd,
    output: OwnedFd,
    raw: Termios,
    restorer: Shared,
    previous_hook: Option<Arc<Hook>>,
}

impl Session {
    pub(crate) fn enter() -> Result<Session, TermError> {
        let dup = |fd: BorrowedFd<'_>| {
            fd.try_clone_to_owned()
                .map_err(|e| TermError::Terminal(Errno::from_raw(e.raw_os_error().unwrap_or(0))))
        };
        Self::enter_on(
            dup(std::io::stdin().as_fd())?,
            dup(std::io::stdout().as_fd())?,
        )
    }

    pub(crate) fn enter_on(input: OwnedFd, output: OwnedFd) -> Result<Session, TermError> {
        let saved = tcgetattr(&input).map_err(TermError::Terminal)?;
        let raw = tty::raw(&saved);
        let dup = |fd: &OwnedFd| {
            fd.try_clone()
                .map_err(|e| TermError::Terminal(Errno::from_raw(e.raw_os_error().unwrap_or(0))))
        };
        let restorer = Restorer {
            output: dup(&output)?,
            termios: Restore::new(dup(&input)?, saved),
        };
        if let Err(e) = set_raw(&input, &raw) {
            drop(restorer);
            return Err(e);
        }
        if let Err(e) = write_all(&output, ENTER) {
            restorer.leave();
            return Err(TermError::Write(e));
        }
        let restorer = Arc::new(Mutex::new(Some(restorer)));
        let previous_hook = Some(install_hook(&restorer));
        Ok(Session {
            input,
            output,
            raw,
            restorer,
            previous_hook,
        })
    }

    pub(crate) fn input(&self) -> &OwnedFd {
        &self.input
    }

    pub(crate) fn size(&self) -> Result<TerminalSize, TermError> {
        let size = maknae_io::terminal_size(&self.output).map_err(TermError::Size)?;
        Ok(TerminalSize {
            rows: size.rows,
            cols: size.cols,
        })
    }

    pub(crate) fn write(&self, bytes: &[u8]) -> Result<(), TermError> {
        write_all(&self.output, bytes).map_err(TermError::Write)
    }

    /// Ctrl-Z: puts the terminal back, stops the process, and on SIGCONT
    /// takes the terminal again. The caller redraws.
    pub(crate) fn suspend(&self) -> Result<(), TermError> {
        if let Some(restorer) = self
            .restorer
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .as_ref()
        {
            restorer.leave();
        }
        raise(Signal::SIGSTOP).map_err(TermError::Stop)?;
        set_raw(&self.input, &self.raw)?;
        self.write(ENTER)
    }
}

impl Drop for Session {
    fn drop(&mut self) {
        let taken = self
            .restorer
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .take();
        if let Some(restorer) = taken {
            restorer.leave();
        }
        if std::thread::panicking() {
            return;
        }
        drop(std::panic::take_hook());
        if let Some(previous) = self.previous_hook.take().and_then(Arc::into_inner) {
            std::panic::set_hook(previous);
        }
    }
}

fn install_hook(restorer: &Shared) -> Arc<Hook> {
    let previous: Arc<Hook> = Arc::new(std::panic::take_hook());
    let (chained, shared) = (Arc::clone(&previous), Arc::clone(restorer));
    std::panic::set_hook(Box::new(move |info| {
        let slot = match shared.try_lock() {
            Ok(slot) => Some(slot),
            Err(TryLockError::Poisoned(slot)) => Some(slot.into_inner()),
            Err(TryLockError::WouldBlock) => None,
        };
        if let Some(restorer) = slot.and_then(|mut slot| slot.take()) {
            restorer.leave();
        }
        chained(info);
    }));
    previous
}

fn set_raw(fd: &OwnedFd, raw: &Termios) -> Result<(), TermError> {
    tcsetattr(fd, SetArg::TCSAFLUSH, raw).map_err(TermError::Terminal)?;
    let applied = tcgetattr(fd).map_err(TermError::Terminal)?;
    if applied
        .local_flags
        .intersects(LocalFlags::ECHO | LocalFlags::ICANON)
    {
        return Err(TermError::EchoStillOn);
    }
    Ok(())
}

pub(crate) fn both_terminals() -> bool {
    std::io::stdin().is_terminal() && std::io::stdout().is_terminal()
}

pub(crate) fn write_all(fd: &impl AsFd, mut bytes: &[u8]) -> Result<(), Errno> {
    while !bytes.is_empty() {
        match nix::unistd::write(fd, bytes) {
            Ok(0) => return Err(Errno::EIO),
            Ok(n) => bytes = &bytes[n..],
            Err(Errno::EINTR) => {}
            Err(e) => return Err(e),
        }
    }
    Ok(())
}

/// Waits until a descriptor has input, carrying no bytes: a blocking `poll`
/// on the blocking pool, kept across cancelled waits and woken on drop.
pub(crate) struct Readable {
    fd: Arc<OwnedFd>,
    wake: Arc<OwnedFd>,
    waker: OwnedFd,
    pending: Option<JoinHandle<Result<(), Errno>>>,
}

impl Readable {
    pub(crate) fn new(fd: &impl AsFd) -> Result<Readable, TermError> {
        let fd = fd
            .as_fd()
            .try_clone_to_owned()
            .map_err(|e| TermError::Read(Errno::from_raw(e.raw_os_error().unwrap_or(0))))?;
        let (wake, waker) = nix::unistd::pipe().map_err(TermError::Read)?;
        Ok(Readable {
            fd: Arc::new(fd),
            wake: Arc::new(wake),
            waker,
            pending: None,
        })
    }

    pub(crate) async fn wait(&mut self) -> Result<(), TermError> {
        let pending = self.pending.get_or_insert_with(|| {
            let (fd, wake) = (Arc::clone(&self.fd), Arc::clone(&self.wake));
            tokio::task::spawn_blocking(move || wait_readable(&fd, &wake))
        });
        let waited = pending.await;
        self.pending = None;
        match waited {
            Ok(polled) => polled.map_err(TermError::Read),
            Err(_) => Err(TermError::Waiter),
        }
    }
}

impl Drop for Readable {
    fn drop(&mut self) {
        let _ = nix::unistd::write(&self.waker, &[1]);
    }
}

fn wait_readable(fd: &OwnedFd, wake: &OwnedFd) -> Result<(), Errno> {
    loop {
        let mut fds = [
            PollFd::new(fd.as_fd(), PollFlags::POLLIN),
            PollFd::new(wake.as_fd(), PollFlags::POLLIN),
        ];
        match poll(&mut fds, PollTimeout::NONE) {
            Ok(_) => return Ok(()),
            Err(Errno::EINTR) => {}
            Err(e) => return Err(e),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::screen::testing::{modes, one_session, pty};
    use nix::sys::termios::{tcgetattr, InputFlags, LocalFlags, OutputFlags};
    use std::sync::{Arc, Mutex};

    #[test]
    fn entering_and_dropping_restores_the_exact_termios_and_modes() {
        let _one = one_session();
        let mut pty = pty(24, 80);
        let before = modes(&pty.slave);
        let session = Session::enter_on(pty.slave(), pty.slave()).unwrap();
        let inside = tcgetattr(&pty.slave).unwrap();
        assert!(!inside.local_flags.intersects(
            LocalFlags::ECHO | LocalFlags::ICANON | LocalFlags::ISIG | LocalFlags::IEXTEN
        ));
        assert!(!inside.input_flags.intersects(
            InputFlags::ICRNL
                | InputFlags::INLCR
                | InputFlags::IXON
                | InputFlags::ISTRIP
                | InputFlags::BRKINT
        ));
        assert!(inside.output_flags.contains(OutputFlags::OPOST));
        drop(session);
        let leave = b"\x1b[?1007l\x1b[?2004l\x1b[?7h\x1b[?25h\x1b[?1049l";
        assert!(pty.out.wait_for(leave), "the modes were never left");
        assert_eq!(modes(&pty.slave), before);
        assert_eq!(
            pty.out.seen,
            [
                &b"\x1b[?1049h\x1b[?7l\x1b[?2004h\x1b[?1007h\x1b[?25l"[..],
                &leave[..]
            ]
            .concat()
        );
    }

    #[test]
    fn a_panic_inside_the_session_restores_the_terminal() {
        let _one = one_session();
        let mut pty = pty(24, 80);
        let before = modes(&pty.slave);
        let at_panic = Arc::new(Mutex::new(None));
        let (probe, record) = (pty.slave(), Arc::clone(&at_panic));
        let original = std::panic::take_hook();
        std::panic::set_hook(Box::new(move |_| {
            *record.lock().unwrap() = Some(modes(&probe));
        }));
        let (input, output) = (pty.slave(), pty.slave());
        let unwound = std::panic::catch_unwind(move || {
            let _session = Session::enter_on(input, output).unwrap();
            panic!("inside the session");
        });
        std::panic::set_hook(original);
        assert!(unwound.is_err());
        assert_eq!(
            at_panic.lock().unwrap().take(),
            Some(before.clone()),
            "the terminal was still raw when the panic was reported"
        );
        assert!(pty.out.wait_for(LEAVE), "the modes were never left");
        assert_eq!(modes(&pty.slave), before);
    }

    #[test]
    fn every_failure_reads_as_a_sentence() {
        for e in [
            TermError::Terminal(Errno::ENOTTY),
            TermError::EchoStillOn,
            TermError::Size(std::io::Error::other("x")),
            TermError::Read(Errno::EIO),
            TermError::Write(Errno::EIO),
            TermError::Signals(std::io::Error::other("x")),
            TermError::Stop(Errno::EPERM),
            TermError::Frame(FrameError::Overflow),
            TermError::Waiter,
        ] {
            assert!(!e.to_string().is_empty());
        }
    }
}
