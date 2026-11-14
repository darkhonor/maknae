use crate::tty;
use maknae_agent::screen::frame::{FrameError, TerminalSize};
use nix::errno::Errno;
use nix::poll::{poll, PollFd, PollFlags, PollTimeout};
use nix::sys::signal::{raise, Signal};
use nix::sys::termios::{tcgetattr, tcsetattr, LocalFlags, SetArg, Termios};
use std::io::IsTerminal;
use std::os::fd::{AsFd, OwnedFd};
use std::panic::PanicHookInfo;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError, TryLockError};
use std::time::{Duration, Instant};
use tokio::sync::{mpsc, Notify};
use tokio::task::JoinHandle;
use zeroize::{Zeroize, Zeroizing};

pub(crate) const ENTER: &[u8] = b"\x1b[?1049h\x1b[?7l\x1b[?2004h\x1b[?1007h\x1b[?25l";
pub(crate) const LEAVE: &[u8] = b"\x1b[?2026l\x1b[?1007l\x1b[?2004l\x1b[?7h\x1b[?25h\x1b[?1049l";
const HOOK_TRIES: usize = 1000;
/// How long the modes' reset waits for the terminal to take output.
pub(crate) const LEAVE_WAIT: Duration = Duration::from_millis(100);

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
    input: OwnedFd,
    output: OwnedFd,
    saved: Termios,
}

impl Restorer {
    fn leave(&self) {
        put_back(&self.input, &self.saved, &self.output);
    }
}

/// The saved termios at once, then the modes' reset if the terminal takes it
/// within [`LEAVE_WAIT`].
fn put_back(input: &OwnedFd, saved: &Termios, output: &OwnedFd) {
    restore_termios(input, saved);
    let _ = write_bounded(output, LEAVE, LEAVE_WAIT);
}

fn restore_termios(input: &OwnedFd, saved: &Termios) {
    if tcsetattr(input, SetArg::TCSANOW, saved) == Err(Errno::EINTR) {
        let _ = tcsetattr(input, SetArg::TCSANOW, saved);
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
    saved: Termios,
    raw: Termios,
    restorer: Shared,
    ended: Arc<Notify>,
    previous_hook: Option<Arc<Hook>>,
}

impl Session {
    pub(crate) fn enter() -> Result<Session, TermError> {
        let dup = |fd| super::dup(fd, TermError::Terminal);
        Self::enter_on(
            dup(std::io::stdin().as_fd())?,
            dup(std::io::stdout().as_fd())?,
        )
    }

    pub(crate) fn enter_on(input: OwnedFd, output: OwnedFd) -> Result<Session, TermError> {
        let saved = tcgetattr(&input).map_err(TermError::Terminal)?;
        let raw = tty::raw(&saved);
        let dup = |fd: &OwnedFd| super::dup(fd.as_fd(), TermError::Terminal);
        let restorer = Restorer {
            input: dup(&input)?,
            output: dup(&output)?,
            saved: saved.clone(),
        };
        if let Err(e) = set_raw(&input, &raw, SetArg::TCSAFLUSH) {
            restore_termios(&restorer.input, &restorer.saved);
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
            saved,
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

    /// A writer of frames to this session's terminal.
    pub(crate) fn writer(&self) -> Result<Writer, TermError> {
        Writer::new(super::dup(self.output.as_fd(), TermError::Write)?)
    }

    /// Puts the saved termios back without the modes' reset, which a write still
    /// blocked on the terminal would interleave with.
    pub(crate) fn restore_termios_only(&self) {
        if let Some(restorer) = self.slot().take() {
            restore_termios(&restorer.input, &restorer.saved);
        }
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
        if self.is_ended() {
            return Err(TermError::Ended);
        }
        self.put_back();
        raise(Signal::SIGSTOP).map_err(TermError::Stop)?;
        self.reenter()?;
        Ok(true)
    }

    /// SIGCONT: raw mode again, keeping typed input; harmless when it is on. The
    /// caller writes [`ENTER`] before its next frame.
    pub(crate) fn reenter(&self) -> Result<(), TermError> {
        if self.is_ended() {
            return Err(TermError::Ended);
        }
        set_raw(&self.input, &self.raw, SetArg::TCSANOW)?;
        if self.is_ended() {
            self.put_back();
            return Err(TermError::Ended);
        }
        Ok(())
    }

    fn put_back(&self) {
        put_back(&self.input, &self.saved, &self.output);
    }
}

/// Whether a stop can be undone: the parent is in this session but another
/// process group, as a job-control shell's job is. A group whose leader's
/// parent is in another session is orphaned, and SIGSTOP there never ends.
/// It assumes such a parent waits for stops, as a shell does.
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

/// Writes `bytes` while the terminal takes them within `wait`, and gives up
/// otherwise.
fn write_bounded(fd: &impl AsFd, bytes: &[u8], wait: Duration) -> Result<(), Errno> {
    let deadline = Instant::now() + wait;
    // One byte per write: POLLOUT promises room for one, so no write blocks.
    for byte in bytes.chunks(1) {
        loop {
            let left = deadline.saturating_duration_since(Instant::now());
            let mut fds = [PollFd::new(fd.as_fd(), PollFlags::POLLOUT)];
            match poll(
                &mut fds,
                PollTimeout::try_from(left).unwrap_or(PollTimeout::ZERO),
            ) {
                Ok(0) => return Err(Errno::EAGAIN),
                Ok(_)
                    if fds[0]
                        .revents()
                        .is_some_and(|r| r.contains(PollFlags::POLLOUT)) => {}
                Ok(_) => return Err(Errno::EIO),
                Err(Errno::EINTR) => continue,
                Err(e) => return Err(e),
            }
            match nix::unistd::write(fd, byte) {
                Ok(1) => break,
                Ok(_) => return Err(Errno::EIO),
                Err(Errno::EINTR) => {}
                Err(e) => return Err(e),
            }
        }
    }
    Ok(())
}

/// A frame written, or not, and its buffer back, wiped.
pub(crate) struct Written {
    pub(crate) frame: Zeroizing<Vec<u8>>,
    pub(crate) result: Result<(), Errno>,
}

struct Job {
    enter: bool,
    frame: Zeroizing<Vec<u8>>,
}

/// Writes frames on a thread of its own, so a terminal that takes no output
/// blocks that thread and never the session's loop. One frame at a time.
pub(crate) struct Writer {
    jobs: std::sync::mpsc::SyncSender<Job>,
    written: mpsc::UnboundedReceiver<Written>,
}

impl Writer {
    fn new(output: OwnedFd) -> Result<Writer, TermError> {
        let (jobs, todo) = std::sync::mpsc::sync_channel::<Job>(1);
        let (done, written) = mpsc::unbounded_channel();
        std::thread::Builder::new()
            .name("maknae-screen-writer".into())
            .spawn(move || {
                for Job { enter, mut frame } in todo {
                    let enter = if enter { ENTER } else { &[] };
                    let result =
                        write_all(&output, enter).and_then(|()| write_all(&output, &frame));
                    frame.zeroize();
                    if done.send(Written { frame, result }).is_err() {
                        return;
                    }
                }
            })
            .map_err(|e| TermError::Write(Errno::from_raw(e.raw_os_error().unwrap_or(0))))?;
        Ok(Writer { jobs, written })
    }

    /// Hands `frame` over, after [`ENTER`] when `enter`. Called only once the
    /// previous frame is [`Writer::written`].
    pub(crate) fn send(&self, enter: bool, frame: Zeroizing<Vec<u8>>) -> Result<(), TermError> {
        self.jobs
            .try_send(Job { enter, frame })
            .map_err(|_| TermError::Write(Errno::EIO))
    }

    /// The next frame done with; `None` once the thread is gone.
    pub(crate) async fn written(&mut self) -> Option<Written> {
        self.written.recv().await
    }
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
        let fd = super::dup(fd.as_fd(), TermError::Read)?;
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
        let leave = b"\x1b[?2026l\x1b[?1007l\x1b[?2004l\x1b[?7h\x1b[?25h\x1b[?1049l";
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

    /// Stops the pty's output and fills its queue, so a write to it blocks.
    fn stopped(pty: &crate::screen::testing::Pty) -> std::thread::JoinHandle<()> {
        use nix::sys::termios::{tcflow, FlowArg};
        tcflow(&pty.slave, FlowArg::TCOOFF).unwrap();
        let filler = pty.slave();
        let filled = std::thread::spawn(move || {
            let _ = write_all(&filler, &[b'.'; 1 << 20]);
        });
        std::thread::sleep(std::time::Duration::from_millis(200));
        filled
    }

    fn resumed(pty: &crate::screen::testing::Pty, filled: std::thread::JoinHandle<()>) {
        use nix::sys::termios::{tcflow, FlowArg};
        tcflow(&pty.slave, FlowArg::TCOON).unwrap();
        filled.join().unwrap();
    }

    const PROMPTLY: std::time::Duration = std::time::Duration::from_secs(3);

    #[test]
    fn a_panic_while_output_is_stopped_restores_termios_at_once() {
        let _one = one_session();
        let mut pty = pty(24, 80);
        let before = modes(&pty.slave);
        let original = std::panic::take_hook();
        std::panic::set_hook(Box::new(|_| {}));
        let session = Session::enter_on(pty.slave(), pty.slave()).unwrap();
        assert!(pty.out.wait_for(ENTER));
        let filled = stopped(&pty);
        let (tx, hooked) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            let _ = std::thread::spawn(|| panic!("a network task")).join();
            let _ = tx.send(());
        });
        let hooked = hooked.recv_timeout(PROMPTLY);
        let after = modes(&pty.slave);
        resumed(&pty, filled);
        std::panic::set_hook(original);
        assert!(hooked.is_ok(), "the hook waited on the stopped output");
        assert_eq!(after, before, "the terminal was left raw");
        assert!(session.is_ended());
    }

    #[test]
    fn dropping_the_session_while_output_is_stopped_restores_termios_at_once() {
        let _one = one_session();
        let mut pty = pty(24, 80);
        let before = modes(&pty.slave);
        let session = Session::enter_on(pty.slave(), pty.slave()).unwrap();
        assert!(pty.out.wait_for(ENTER));
        let filled = stopped(&pty);
        let (tx, dropped) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            drop(session);
            let _ = tx.send(());
        });
        let dropped = dropped.recv_timeout(PROMPTLY);
        let after = modes(&pty.slave);
        resumed(&pty, filled);
        assert!(dropped.is_ok(), "the drop waited on the stopped output");
        assert_eq!(after, before, "the terminal was left raw");
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
