use crate::tty::{self, Restore};
use maknae_agent::screen::frame::{FrameError, TerminalSize};
use nix::errno::Errno;
use nix::poll::{poll, PollFd, PollFlags, PollTimeout};
use nix::sys::signal::{raise, Signal};
use nix::sys::termios::{tcgetattr, tcsetattr, LocalFlags, SetArg, Termios};
use std::io::IsTerminal;
use std::os::fd::{AsFd, BorrowedFd, OwnedFd};
use std::panic::PanicHookInfo;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError, TryLockError};
use tokio::sync::Notify;
use tokio::task::JoinHandle;

pub(crate) const ENTER: &[u8] = b"\x1b[?1049h\x1b[?7l\x1b[?2004h\x1b[?1007h\x1b[?25l";
pub(crate) const LEAVE: &[u8] = b"\x1b[?1007l\x1b[?2004l\x1b[?7h\x1b[?25h\x1b[?1049l";
const SYNC_OFF: &[u8] = b"\x1b[?2026l";
const HOOK_TRIES: usize = 1000;

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
    Ended,
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
            TermError::Ended => f.write_str("a panic put the terminal back, so the session ended"),
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
/// a stop puts it back. A panic on any thread ends the session: the restorer is
/// gone and [`Session::ended`] fires. Dropping it drops any panic hook installed
/// after it, and after an unwind the previous hook stays chained, not reinstalled.
pub(crate) struct Session {
    input: OwnedFd,
    output: OwnedFd,
    raw: Termios,
    restorer: Shared,
    ended: Arc<Notify>,
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
        if let Err(e) = set_raw(&input, &raw, SetArg::TCSAFLUSH) {
            drop(restorer);
            return Err(e);
        }
        if let Err(e) = write_all(&output, ENTER) {
            restorer.leave();
            return Err(TermError::Write(e));
        }
        let restorer = Arc::new(Mutex::new(Some(restorer)));
        let ended = Arc::new(Notify::new());
        let previous_hook = Some(install_hook(&restorer, &ended));
        Ok(Session {
            input,
            output,
            raw,
            restorer,
            ended,
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

    fn slot(&self) -> MutexGuard<'_, Option<Restorer>> {
        self.restorer.lock().unwrap_or_else(PoisonError::into_inner)
    }

    pub(crate) fn is_ended(&self) -> bool {
        self.slot().is_none()
    }

    /// Completes once a panic has put the terminal back.
    pub(crate) async fn ended(&self) {
        self.ended.notified().await;
    }

    /// Ctrl-Z or SIGTSTP: puts the terminal back, stops the process and takes
    /// the terminal again when continued. `false`, with nothing changed, when no
    /// shell could continue it (an orphaned process group). The caller redraws.
    pub(crate) fn suspend(&self) -> Result<bool, TermError> {
        if !job_control() {
            return Ok(false);
        }
        match self.slot().as_ref() {
            Some(restorer) => restorer.leave(),
            None => return Err(TermError::Ended),
        }
        raise(Signal::SIGSTOP).map_err(TermError::Stop)?;
        self.reenter()?;
        Ok(true)
    }

    /// SIGCONT: raw mode and the session's modes again, keeping typed input;
    /// harmless when they are on.
    pub(crate) fn reenter(&self) -> Result<(), TermError> {
        let slot = self.slot();
        if slot.is_none() {
            return Err(TermError::Ended);
        }
        set_raw(&self.input, &self.raw, SetArg::TCSANOW)?;
        self.write(ENTER)
    }
}

/// Whether a stop can be undone: the parent is in this session but another
/// process group, as a job-control shell's job is. A group whose leader's
/// parent is in another session is orphaned, and SIGSTOP there never ends.
fn job_control() -> bool {
    use nix::unistd::{getpgid, getpgrp, getppid, getsid};
    let parent = getppid();
    match (getpgid(Some(parent)), getsid(Some(parent)), getsid(None)) {
        (Ok(group), Ok(session), Ok(own)) => group != getpgrp() && session == own,
        _ => false,
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

fn install_hook(restorer: &Shared, ended: &Arc<Notify>) -> Arc<Hook> {
    let previous: Arc<Hook> = Arc::new(std::panic::take_hook());
    let (chained, shared, ended) = (
        Arc::clone(&previous),
        Arc::clone(restorer),
        Arc::clone(ended),
    );
    std::panic::set_hook(Box::new(move |info| {
        if let Some(restorer) = take_for_hook(&shared) {
            let _ = write_all(&restorer.output, SYNC_OFF);
            restorer.leave();
            ended.notify_one();
        }
        chained(info);
    }));
    previous
}

/// Bounded, so a panic on a thread that holds the slot cannot deadlock its hook.
fn take_for_hook(shared: &Shared) -> Option<Restorer> {
    for _ in 0..HOOK_TRIES {
        match shared.try_lock() {
            Ok(mut slot) => return slot.take(),
            Err(TryLockError::Poisoned(slot)) => return slot.into_inner().take(),
            Err(TryLockError::WouldBlock) => std::thread::yield_now(),
        }
    }
    None
}

fn set_raw(fd: &OwnedFd, raw: &Termios, when: SetArg) -> Result<(), TermError> {
    tcsetattr(fd, when, raw).map_err(TermError::Terminal)?;
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
/// on the blocking pool, kept across cancelled waits. Dropping it closes the
/// wake pipe's only write end, which ends the `poll`.
pub(crate) struct Readable {
    fd: Arc<OwnedFd>,
    wake: Arc<OwnedFd>,
    _waker: OwnedFd,
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
            _waker: waker,
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
    use crate::screen::testing::{modes, one_session, pty, WAIT};
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
                | InputFlags::IGNCR
                | InputFlags::PARMRK
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
    fn dropping_a_readable_frees_its_waiting_thread() {
        let (r, _w) = nix::unistd::pipe().unwrap();
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let held = rt.block_on(async {
            let mut readable = Readable::new(&r).unwrap();
            let held = Arc::downgrade(&readable.fd);
            let waited =
                tokio::time::timeout(std::time::Duration::from_millis(100), readable.wait()).await;
            assert!(waited.is_err(), "the pipe was readable");
            held
        });
        let deadline = std::time::Instant::now() + WAIT;
        while held.upgrade().is_some() && std::time::Instant::now() < deadline {
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
        let released = held.upgrade().is_none();
        rt.shutdown_timeout(std::time::Duration::ZERO);
        assert!(released, "the waiting thread still holds the descriptor");
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
            TermError::Ended,
        ] {
            assert!(!e.to_string().is_empty());
        }
    }
}
