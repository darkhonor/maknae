use super::term::{Readable, Session, TermError};
use maknae_agent::screen::blocks::{Conversation, EntryKind};
use maknae_agent::screen::editor::{EditOutcome, Editor};
use maknae_agent::screen::frame::{compose, frame_capacity, ScreenState, TerminalSize, Viewport};
use maknae_agent::screen::keys::{Decoder, Key};
use maknae_agent::screen::Commands;
use maknae_proto::BannerSpec;
use nix::errno::Errno;
use nix::sys::signal::Signal;
use std::os::fd::AsFd;
use tokio::signal::unix::{signal, SignalKind};
use tokio::sync::mpsc;
use tokio::time::{sleep_until, Duration, Instant};
use zeroize::{Zeroize, Zeroizing};

pub(crate) const READ_BYTES: usize = 4096;
const ESCAPE_WAIT: Duration = Duration::from_millis(100);
const LEAVE_WINDOW: Duration = Duration::from_secs(2);
const SPINNER_TICK: Duration = Duration::from_millis(100);
const CLOCK_TICK: Duration = Duration::from_secs(1);
const NO_SUSPEND: &str = "Ctrl-Z is not available here: nothing could resume a stopped session";

/// How often the caller's [`Caller::tick`] runs: never, each second while
/// something is open, or at the spinner's rate while a status line animates.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(crate) enum Pace {
    Idle,
    Open,
    Animating,
}

impl Pace {
    fn period(self) -> Option<Duration> {
        match self {
            Pace::Idle => None,
            Pace::Open => Some(CLOCK_TICK),
            Pace::Animating => Some(SPINNER_TICK),
        }
    }
}

/// What a caller's handler did: nothing on screen, something to redraw, or leave.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(crate) enum Step {
    Unchanged,
    Changed,
    Leave,
}

/// The screen's user. The driver owns the conversation and calls these on its
/// one task; the caller's network work runs elsewhere and arrives as events.
pub(crate) trait Caller: Commands {
    type Event: Send + 'static;
    /// One line per open task.
    fn status(&self) -> &[String];
    fn pace(&self) -> Pace;
    fn tick(&mut self, conversation: &mut Conversation) -> Step;
    fn event(&mut self, event: Self::Event, conversation: &mut Conversation) -> Step;
    /// An entered line: a request or a `/` command.
    fn submit(&mut self, text: Zeroizing<String>, conversation: &mut Conversation) -> Step;
    /// Ctrl-D on an empty line, or a second Ctrl-C.
    fn leave(&mut self, _conversation: &mut Conversation) -> Step {
        Step::Leave
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(crate) enum Exit {
    /// `/bye` (a caller's [`Step::Leave`]), Ctrl-D on an empty line, or a second Ctrl-C.
    Bye,
    /// SIGTERM, SIGHUP, SIGINT or SIGQUIT from outside, by number.
    Signal(i32),
    /// The terminal hung up.
    InputClosed,
}

pub(crate) struct Driver<C: Caller> {
    signals: Signals,
    session: Session,
    readable: Readable,
    input: Input,
    caller: C,
    events: Option<mpsc::Receiver<C::Event>>,
    banner: Option<BannerSpec>,
    conversation: Conversation,
    viewport: Viewport,
    editor: Editor,
    size: TerminalSize,
    frame: Zeroizing<Vec<u8>>,
    dirty: bool,
    full_shown: bool,
    leave_until: Option<Instant>,
    tick: Option<(Instant, Duration)>,
}

enum Wake<E> {
    Input(Result<(), TermError>),
    Event(Option<E>),
    Tick,
    Escape,
    LeaveWindow,
    Resize,
    Suspend,
    Continued,
    Ended,
    Leave(i32),
}

impl<C: Caller> Driver<C> {
    /// Registers the session's signals, then calls `enter` (normally
    /// [`Session::enter`]). `input_cap` is the request bound in bytes (the
    /// host's `prompt_max_bytes`). The signal handlers stay installed for the
    /// rest of the process, so the caller owns exit after `run` returns.
    pub(crate) fn new(
        enter: impl FnOnce() -> Result<Session, TermError>,
        caller: C,
        events: mpsc::Receiver<C::Event>,
        banner: Option<BannerSpec>,
        conversation: Conversation,
        input_cap: usize,
    ) -> Result<Self, TermError> {
        let signals = Signals::register()?;
        let session = enter()?;
        let size = session.size()?;
        Ok(Self {
            signals,
            readable: Readable::new(session.input())?,
            session,
            input: Input::new(),
            caller,
            events: Some(events),
            banner,
            conversation,
            viewport: Viewport::new(),
            editor: Editor::new(input_cap),
            size,
            frame: Zeroizing::new(Vec::with_capacity(frame_capacity(size))),
            dirty: true,
            full_shown: false,
            leave_until: None,
            tick: None,
        })
    }

    /// Runs until the person leaves or a signal ends it; the terminal is
    /// restored before this returns, and the caller handed back.
    pub(crate) async fn run(mut self) -> (C, Result<Exit, TermError>) {
        let result = self.drive().await;
        let Driver {
            session,
            readable,
            caller,
            signals,
            ..
        } = self;
        drop(readable);
        drop(session);
        drop(signals);
        (caller, result)
    }

    async fn drive(&mut self) -> Result<Exit, TermError> {
        loop {
            if self.session.is_ended() {
                return Err(TermError::Ended);
            }
            if self.dirty {
                self.draw()?;
            }
            self.schedule();
            let escape_at = self.input.pending_since().map(|at| at + ESCAPE_WAIT);
            let wake = tokio::select! {
                waited = self.readable.wait() => Wake::Input(waited),
                event = recv(&mut self.events) => Wake::Event(event),
                () = at(self.tick.map(|(at, _)| at)) => Wake::Tick,
                () = at(escape_at) => Wake::Escape,
                () = at(self.leave_until) => Wake::LeaveWindow,
                wake = self.signals.next() => wake,
                () = self.session.ended() => Wake::Ended,
            };
            if let Some(exit) = self.wake(wake)? {
                return Ok(exit);
            }
        }
    }

    fn wake(&mut self, wake: Wake<C::Event>) -> Result<Option<Exit>, TermError> {
        match wake {
            Wake::Input(waited) => {
                waited?;
                match self.input.fill(self.session.input())? {
                    Filled::End => Ok(Some(Exit::InputClosed)),
                    Filled::Bytes => self.keys(false),
                }
            }
            Wake::Escape => self.keys(true),
            Wake::Event(Some(event)) => {
                let step = self.caller.event(event, &mut self.conversation);
                Ok(self.step(step))
            }
            Wake::Event(None) => {
                self.events = None;
                Ok(None)
            }
            Wake::Tick => {
                self.tick = None;
                let step = self.caller.tick(&mut self.conversation);
                Ok(self.step(step))
            }
            Wake::LeaveWindow => {
                self.editor.disarm_leave();
                self.leave_until = None;
                Ok(None)
            }
            Wake::Resize => {
                self.resize(false)?;
                Ok(None)
            }
            Wake::Suspend => {
                self.suspend()?;
                Ok(None)
            }
            Wake::Continued => {
                self.session.reenter()?;
                self.resize(true)?;
                Ok(None)
            }
            Wake::Ended => Err(TermError::Ended),
            Wake::Leave(signal) => Ok(Some(Exit::Signal(signal))),
        }
    }

    fn suspend(&mut self) -> Result<(), TermError> {
        if !self.session.suspend()? {
            let _ = self.conversation.push(EntryKind::Notice, NO_SUSPEND);
        }
        self.resize(true)
    }

    fn step(&mut self, step: Step) -> Option<Exit> {
        match step {
            Step::Unchanged => None,
            Step::Changed => {
                self.dirty = true;
                None
            }
            Step::Leave => Some(Exit::Bye),
        }
    }

    fn schedule(&mut self) {
        self.tick = match (self.caller.pace().period(), self.tick) {
            (None, _) => None,
            (Some(period), Some((at, was))) if period == was => Some((at, was)),
            (Some(period), _) => Some((Instant::now() + period, period)),
        };
    }

    fn keys(&mut self, flush: bool) -> Result<Option<Exit>, TermError> {
        let mut exit = None;
        while let Some(key) = self.input.next_key(flush) {
            exit = self.key(key)?;
            if exit.is_some() {
                break;
            }
        }
        self.input.compact();
        Ok(exit)
    }

    fn key(&mut self, key: Key) -> Result<Option<Exit>, TermError> {
        if key == Key::Ctrl('z') {
            self.suspend()?;
            return Ok(None);
        }
        if self.viewport.key(&mut self.conversation, &key) {
            self.dirty = true;
            return Ok(None);
        }
        let outcome = self.editor.apply(&key);
        let full = matches!(outcome, EditOutcome::Full);
        let exit = match outcome {
            EditOutcome::Submitted(text) => {
                self.dirty = true;
                let step = self.caller.submit(text, &mut self.conversation);
                self.step(step)
            }
            EditOutcome::Changed | EditOutcome::Cleared => {
                self.dirty = true;
                None
            }
            EditOutcome::Full if !self.full_shown => {
                let notice = format!(
                    "the request is at its limit of {} bytes",
                    self.editor.capacity()
                );
                let _ = self.conversation.push(EntryKind::Notice, &notice);
                self.dirty = true;
                None
            }
            EditOutcome::Full | EditOutcome::Nothing => None,
            EditOutcome::LeaveRequested => {
                let step = self.caller.leave(&mut self.conversation);
                self.step(step)
            }
        };
        self.full_shown = full;
        self.leave_until = match (self.editor.leave_armed(), self.leave_until) {
            (false, _) => None,
            (true, Some(until)) => Some(until),
            (true, None) => Some(Instant::now() + LEAVE_WINDOW),
        };
        Ok(exit)
    }

    fn resize(&mut self, required: bool) -> Result<(), TermError> {
        match self.session.size() {
            Ok(size) => {
                if size != self.size {
                    self.frame = Zeroizing::new(Vec::with_capacity(frame_capacity(size)));
                    self.size = size;
                }
            }
            Err(e) if required => return Err(e),
            Err(_) => {}
        }
        self.dirty = true;
        Ok(())
    }

    fn draw(&mut self) -> Result<(), TermError> {
        let header = self.caller.header();
        let menu = self
            .editor
            .slash_prefix()
            .map(|prefix| self.caller.menu(prefix))
            .unwrap_or_default();
        let mut state = ScreenState {
            banner: self.banner.as_ref(),
            header: &header,
            conversation: &mut self.conversation,
            viewport: &mut self.viewport,
            status: self.caller.status(),
            editor: &self.editor,
            menu: &menu,
        };
        let drawn = compose(&mut state, self.size, &mut self.frame).map_err(TermError::Frame)?;
        let written = self.session.write(&self.frame);
        self.frame.zeroize();
        written?;
        drawn.mark(&mut self.conversation);
        self.dirty = false;
        Ok(())
    }
}

async fn at(deadline: Option<Instant>) {
    match deadline {
        Some(deadline) => sleep_until(deadline).await,
        None => std::future::pending().await,
    }
}

async fn recv<E>(events: &mut Option<mpsc::Receiver<E>>) -> Option<E> {
    match events {
        Some(events) => events.recv().await,
        None => std::future::pending().await,
    }
}

fn one(kind: SignalKind) -> Result<tokio::signal::unix::Signal, TermError> {
    signal(kind).map_err(TermError::Signals)
}

/// The signals that end a session: SIGTERM, SIGHUP, SIGINT and SIGQUIT.
pub(crate) struct Ending {
    term: tokio::signal::unix::Signal,
    hup: tokio::signal::unix::Signal,
    int: tokio::signal::unix::Signal,
    quit: tokio::signal::unix::Signal,
}

impl Ending {
    pub(crate) fn register() -> Result<Self, TermError> {
        Ok(Self {
            term: one(SignalKind::terminate())?,
            hup: one(SignalKind::hangup())?,
            int: one(SignalKind::interrupt())?,
            quit: one(SignalKind::quit())?,
        })
    }

    /// The number of the next one to arrive.
    pub(crate) async fn next(&mut self) -> i32 {
        tokio::select! {
            Some(()) = self.term.recv() => Signal::SIGTERM as i32,
            Some(()) = self.hup.recv() => Signal::SIGHUP as i32,
            Some(()) = self.int.recv() => Signal::SIGINT as i32,
            Some(()) = self.quit.recv() => Signal::SIGQUIT as i32,
        }
    }
}

struct Signals {
    winch: tokio::signal::unix::Signal,
    tstp: tokio::signal::unix::Signal,
    cont: tokio::signal::unix::Signal,
    ending: Ending,
}

impl Signals {
    fn register() -> Result<Self, TermError> {
        Ok(Self {
            winch: one(SignalKind::window_change())?,
            tstp: one(SignalKind::from_raw(Signal::SIGTSTP as i32))?,
            cont: one(SignalKind::from_raw(Signal::SIGCONT as i32))?,
            ending: Ending::register()?,
        })
    }

    async fn next<E>(&mut self) -> Wake<E> {
        tokio::select! {
            Some(()) = self.winch.recv() => Wake::Resize,
            Some(()) = self.tstp.recv() => Wake::Suspend,
            Some(()) = self.cont.recv() => Wake::Continued,
            signal = self.ending.next() => Wake::Leave(signal),
        }
    }
}

/// The stdin read buffer: one zeroizing allocation, never grown; an incomplete
/// sequence at its end carries over to the next read.
struct Input {
    buf: Zeroizing<Vec<u8>>,
    decoder: Decoder,
    start: usize,
    filled: usize,
    read_at: Option<Instant>,
}

enum Filled {
    Bytes,
    End,
}

impl Input {
    fn new() -> Self {
        Self {
            buf: Zeroizing::new(vec![0; READ_BYTES]),
            decoder: Decoder::new(),
            start: 0,
            filled: 0,
            read_at: None,
        }
    }

    fn fill(&mut self, fd: &impl AsFd) -> Result<Filled, TermError> {
        self.compact();
        if self.filled == self.buf.len() {
            return Ok(Filled::Bytes);
        }
        match nix::unistd::read(fd.as_fd(), &mut self.buf[self.filled..]) {
            Ok(0) | Err(Errno::EIO) => Ok(Filled::End),
            Ok(n) => {
                self.filled += n;
                self.read_at = Some(Instant::now());
                Ok(Filled::Bytes)
            }
            Err(Errno::EINTR | Errno::EAGAIN) => Ok(Filled::Bytes),
            Err(e) => Err(TermError::Read(e)),
        }
    }

    /// When the bytes left over are an incomplete sequence, the time they arrived.
    fn pending_since(&self) -> Option<Instant> {
        (self.start < self.filled).then_some(self.read_at).flatten()
    }

    fn next_key(&mut self, flush: bool) -> Option<Key> {
        let flush = flush || (self.start == 0 && self.filled == self.buf.len());
        while self.start < self.filled {
            let pending = &self.buf[self.start..self.filled];
            let (key, used) = if flush {
                self.decoder.flush(pending)
            } else {
                self.decoder.next(pending)
            };
            if used == 0 {
                return None;
            }
            self.start += used;
            if key.is_some() {
                return key;
            }
        }
        None
    }

    fn compact(&mut self) {
        let left = self.filled - self.start;
        self.buf.copy_within(self.start..self.filled, 0);
        self.buf[left..self.filled].zeroize();
        self.start = 0;
        self.filled = left;
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::disallowed_methods)]
    use super::*;
    use crate::screen::term::{ENTER, LEAVE};
    use crate::screen::testing::{modes, one_session, pty, Mode, Pty, FRAME_END, WAIT};
    use maknae_agent::screen::{HeaderLine, MenuItem};
    use nix::sys::signal::{kill, Signal};
    use nix::sys::termios::{tcgetattr, tcsetattr, SetArg};
    use nix::sys::wait::{waitpid, WaitPidFlag, WaitStatus};
    use nix::unistd::Pid;
    use std::sync::{mpsc as std_mpsc, Arc, Mutex};
    use std::time::Duration;

    #[derive(Default)]
    struct Seen {
        submitted: Vec<String>,
        ticks: u32,
        leaves: u32,
    }

    struct Fake {
        pace: Pace,
        on_tick: Step,
        seen: Arc<Mutex<Seen>>,
        status: Vec<String>,
        refused_leaves: u32,
    }

    impl Fake {
        fn new(pace: Pace, on_tick: Step) -> (Self, Arc<Mutex<Seen>>) {
            let seen = Arc::new(Mutex::new(Seen::default()));
            (
                Self {
                    pace,
                    on_tick,
                    seen: Arc::clone(&seen),
                    status: Vec::new(),
                    refused_leaves: 0,
                },
                seen,
            )
        }
    }

    impl Commands for Fake {
        fn header(&self) -> HeaderLine {
            HeaderLine {
                left: "fake".into(),
                right: String::new(),
            }
        }

        fn menu(&self, _prefix: &str) -> Vec<MenuItem> {
            Vec::new()
        }
    }

    impl Caller for Fake {
        type Event = ();

        fn status(&self) -> &[String] {
            &self.status
        }

        fn pace(&self) -> Pace {
            self.pace
        }

        fn tick(&mut self, _conversation: &mut Conversation) -> Step {
            self.seen.lock().unwrap().ticks += 1;
            self.on_tick
        }

        fn event(&mut self, _event: (), _conversation: &mut Conversation) -> Step {
            Step::Unchanged
        }

        fn submit(&mut self, text: Zeroizing<String>, _conversation: &mut Conversation) -> Step {
            self.seen.lock().unwrap().submitted.push(text.to_string());
            Step::Changed
        }

        fn leave(&mut self, _conversation: &mut Conversation) -> Step {
            let mut seen = self.seen.lock().unwrap();
            seen.leaves += 1;
            if seen.leaves > self.refused_leaves {
                Step::Leave
            } else {
                Step::Changed
            }
        }
    }

    type Ran = Result<Exit, String>;

    fn run_on(enter: impl FnOnce() -> Result<Session, TermError>, caller: Fake) -> Ran {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        rt.block_on(async {
            let (_tx, rx) = mpsc::channel(1);
            let driver = Driver::new(
                enter,
                caller,
                rx,
                None,
                Conversation::new(1 << 20, 64 * 1024),
                4096,
            )
            .map_err(|e| e.to_string())?;
            driver.run().await.1.map_err(|e| e.to_string())
        })
    }

    fn drive(pty: &Pty, caller: Fake) -> std_mpsc::Receiver<Ran> {
        let (input, output) = (pty.slave(), pty.slave());
        let (tx, rx) = std_mpsc::channel();
        std::thread::spawn(move || {
            let _ = tx.send(run_on(move || Session::enter_on(input, output), caller));
        });
        rx
    }

    fn ended(done: &std_mpsc::Receiver<Ran>) -> Ran {
        done.recv_timeout(WAIT)
            .unwrap_or_else(|_| Err("the session did not end within 10 s".into()))
    }

    #[test]
    fn cr_is_enter_and_lf_is_ctrl_j_through_the_real_line_discipline() {
        let _one = one_session();
        let mut pty = pty(24, 80);
        let (caller, seen) = Fake::new(Pace::Idle, Step::Unchanged);
        let done = drive(&pty, caller);
        assert!(pty.out.wait_for(FRAME_END), "no first frame");
        pty.type_keys(b"a\r");
        pty.type_keys(b"b\nc\r");
        pty.type_keys(b"\x13d");
        let shown = pty.out.wait_for(b"> d");
        if !shown {
            pty.type_keys(b"\x11");
        }
        assert!(shown, "Ctrl-S froze the output");
        pty.type_keys(b"\r\x04");
        assert_eq!(ended(&done), Ok(Exit::Bye));
        assert_eq!(seen.lock().unwrap().submitted, ["a", "b\nc", "d"]);
    }

    #[test]
    fn ctrl_d_and_a_second_ctrl_c_ask_the_caller_before_leaving() {
        let _one = one_session();
        let mut pty = pty(24, 80);
        let (mut caller, seen) = Fake::new(Pace::Idle, Step::Unchanged);
        caller.refused_leaves = 1;
        let done = drive(&pty, caller);
        assert!(pty.out.wait_for(FRAME_END), "no first frame");
        pty.type_keys(b"\x04");
        assert!(
            done.recv_timeout(Duration::from_millis(500)).is_err(),
            "a refused leave ended the session"
        );
        assert_eq!(seen.lock().unwrap().leaves, 1);
        pty.type_keys(b"\x03\x03");
        assert_eq!(ended(&done), Ok(Exit::Bye));
        assert_eq!(seen.lock().unwrap().leaves, 2);
    }

    #[test]
    fn sigwinch_produces_a_resize_and_a_redraw_at_the_new_size() {
        let _one = one_session();
        let mut pty = pty(24, 80);
        let (caller, _seen) = Fake::new(Pace::Idle, Step::Unchanged);
        let done = drive(&pty, caller);
        assert!(pty.out.wait_for(FRAME_END), "no first frame");
        assert!(!pty.out.seen.windows(7).any(|w| w == b"\x1b[30;1H"));
        let resized = std::process::Command::new("/bin/stty")
            .args(["rows", "30", "cols", "100"])
            .stdin(pty.slave())
            .status()
            .unwrap();
        assert!(resized.success());
        kill(Pid::this(), Signal::SIGWINCH).unwrap();
        assert!(
            pty.out.wait_for(b"\x1b[30;1H"),
            "no row 30 after the resize"
        );
        assert!(pty.out.wait_for(FRAME_END));
        pty.type_keys(b"\x04");
        assert_eq!(ended(&done), Ok(Exit::Bye));
    }

    #[test]
    fn nothing_is_written_when_nothing_changed() {
        let _one = one_session();
        let mut pty = pty(24, 80);
        let (caller, _seen) = Fake::new(Pace::Idle, Step::Unchanged);
        let done = drive(&pty, caller);
        assert!(pty.out.wait_for(FRAME_END), "no first frame");
        assert_eq!(pty.out.arriving_within(Duration::from_secs(2)), 0);
        pty.type_keys(b"\x04");
        assert_eq!(ended(&done), Ok(Exit::Bye));
    }

    #[test]
    fn a_tick_that_changes_nothing_writes_nothing() {
        let _one = one_session();
        let mut pty = pty(24, 80);
        let (caller, seen) = Fake::new(Pace::Open, Step::Unchanged);
        let done = drive(&pty, caller);
        assert!(pty.out.wait_for(FRAME_END), "no first frame");
        assert_eq!(pty.out.arriving_within(Duration::from_millis(2500)), 0);
        assert!(seen.lock().unwrap().ticks >= 1, "the clock never ticked");
        pty.type_keys(b"\x04");
        assert_eq!(ended(&done), Ok(Exit::Bye));
    }

    #[test]
    fn an_animating_status_line_is_redrawn_on_the_spinner_tick() {
        let _one = one_session();
        let mut pty = pty(24, 80);
        let (caller, seen) = Fake::new(Pace::Animating, Step::Changed);
        let done = drive(&pty, caller);
        for frame in 0..5 {
            assert!(pty.out.wait_for(FRAME_END), "frame {frame} never came");
        }
        assert!(seen.lock().unwrap().ticks >= 4);
        pty.type_keys(b"\x04");
        assert_eq!(ended(&done), Ok(Exit::Bye));
    }

    #[test]
    fn sighup_leaves_and_restores_the_terminal() {
        let _one = one_session();
        let mut pty = pty(24, 80);
        let before = modes(&pty.slave);
        let (caller, _seen) = Fake::new(Pace::Idle, Step::Unchanged);
        let done = drive(&pty, caller);
        assert!(pty.out.wait_for(FRAME_END), "no first frame");
        kill(Pid::this(), Signal::SIGHUP).unwrap();
        assert_eq!(ended(&done), Ok(Exit::Signal(Signal::SIGHUP as i32)));
        assert!(pty.out.wait_for(LEAVE));
        assert_eq!(modes(&pty.slave), before);
    }

    #[test]
    fn sigterm_sigint_and_sigquit_leave_and_restore_the_terminal() {
        let _one = one_session();
        for sig in [Signal::SIGTERM, Signal::SIGINT, Signal::SIGQUIT] {
            let mut pty = pty(24, 80);
            let before = modes(&pty.slave);
            let (caller, _seen) = Fake::new(Pace::Idle, Step::Unchanged);
            let done = drive(&pty, caller);
            assert!(pty.out.wait_for(FRAME_END), "no first frame before {sig:?}");
            kill(Pid::this(), sig).unwrap();
            assert_eq!(ended(&done), Ok(Exit::Signal(sig as i32)), "{sig:?}");
            assert!(pty.out.wait_for(LEAVE), "{sig:?} left the modes on");
            assert_eq!(modes(&pty.slave), before, "{sig:?} left the terminal raw");
        }
    }

    #[test]
    fn a_hung_up_terminal_ends_the_session_as_input_closed() {
        let _one = one_session();
        let mut pty = pty(24, 80);
        let (caller, _seen) = Fake::new(Pace::Idle, Step::Unchanged);
        let done = drive(&pty, caller);
        assert!(pty.out.wait_for(FRAME_END), "no first frame");
        drop(pty.hang_up());
        assert_eq!(ended(&done), Ok(Exit::InputClosed));
    }

    #[test]
    fn a_panic_on_another_thread_ends_the_session_with_the_terminal_restored() {
        let _one = one_session();
        let mut pty = pty(24, 80);
        let before = modes(&pty.slave);
        let original = std::panic::take_hook();
        std::panic::set_hook(Box::new(|_| {}));
        let (caller, _seen) = Fake::new(Pace::Idle, Step::Unchanged);
        let done = drive(&pty, caller);
        let first = pty.out.wait_for(FRAME_END);
        let _ = std::thread::spawn(|| panic!("a network task")).join();
        let result = ended(&done);
        std::panic::set_hook(original);
        assert!(first, "no first frame");
        assert_eq!(result, Err(TermError::Ended.to_string()));
        assert!(
            pty.out.wait_for(LEAVE),
            "the hook did not end synchronized output and leave the modes"
        );
        assert_eq!(modes(&pty.slave), before);
    }

    #[test]
    fn the_read_buffer_never_moves_or_grows() {
        let (r, w) = nix::unistd::pipe().unwrap();
        let mut input = Input::new();
        let (ptr, cap) = (input.buf.as_ptr(), input.buf.capacity());
        let mut paste = b"\x1b[200~".to_vec();
        paste.extend(std::iter::repeat_n(b'x', 3 * READ_BYTES));
        paste.extend_from_slice(b"\x1b[201~");
        let writer = std::thread::spawn(move || {
            crate::screen::term::write_all(&w, &paste).unwrap();
        });
        let deadline = std::time::Instant::now() + WAIT;
        let mut chars = 0;
        while chars < 3 * READ_BYTES {
            assert!(
                std::time::Instant::now() < deadline,
                "the paste was not read within 10 s"
            );
            assert!(matches!(input.fill(&r).unwrap(), Filled::Bytes));
            while let Some(key) = input.next_key(false) {
                if key == Key::Char('x') {
                    chars += 1;
                }
            }
            assert_eq!((input.buf.as_ptr(), input.buf.capacity()), (ptr, cap));
        }
        writer.join().unwrap();
    }

    const CHILD: &str = "MAKNAE_TEST_SCREEN_CHILD";
    const JOB: &str = "job";
    const ORPHAN: &str = "orphan";

    #[test]
    #[ignore = "the child process of the stop and continue tests"]
    fn screen_child() {
        let Some(mode) = std::env::var_os(CHILD) else {
            return;
        };
        if mode == ORPHAN {
            nix::unistd::setsid().unwrap();
        }
        let (caller, _seen) = Fake::new(Pace::Idle, Step::Unchanged);
        assert_eq!(run_on(Session::enter, caller), Ok(Exit::Bye));
    }

    /// A session in a child process; killed on drop unless it was seen to exit.
    struct Child {
        pid: Pid,
        statuses: std_mpsc::Receiver<WaitStatus>,
        exited: bool,
    }

    impl Drop for Child {
        fn drop(&mut self) {
            if !self.exited {
                let _ = kill(self.pid, Signal::SIGKILL);
            }
        }
    }

    impl Child {
        /// `JOB`: its own process group in this session, as a shell runs a job.
        /// `ORPHAN`: a session of its own, which nothing can continue once stopped.
        fn spawn(pty: &mut Pty, mode: &str) -> Child {
            use std::os::unix::process::CommandExt;
            let mut command = std::process::Command::new(std::env::current_exe().unwrap());
            command
                .args([
                    "--ignored",
                    "--exact",
                    "screen::run::tests::screen_child",
                    "--test-threads=1",
                ])
                .env(CHILD, mode)
                .stdin(pty.slave())
                .stdout(pty.slave());
            if mode == JOB {
                command.process_group(0);
            }
            #[allow(clippy::zombie_processes, reason = "reaped by waitpid below")]
            let child = command.spawn().unwrap();
            let pid = Pid::from_raw(i32::try_from(child.id()).unwrap());
            let (tx, statuses) = std_mpsc::channel();
            std::thread::spawn(move || loop {
                match waitpid(pid, Some(WaitPidFlag::WUNTRACED)) {
                    Ok(status) => {
                        let last =
                            matches!(status, WaitStatus::Exited(..) | WaitStatus::Signaled(..));
                        if tx.send(status).is_err() || last {
                            break;
                        }
                    }
                    Err(nix::errno::Errno::EINTR) => {}
                    Err(_) => break,
                }
            });
            let child = Child {
                pid,
                statuses,
                exited: false,
            };
            assert!(
                pty.out.wait_for(ENTER),
                "the child never entered the session"
            );
            assert!(pty.out.wait_for(FRAME_END), "no first frame");
            child
        }

        fn status(&self, within: Duration) -> Option<WaitStatus> {
            self.statuses.recv_timeout(within).ok()
        }

        fn leave(mut self, pty: &Pty) {
            pty.type_keys(b"\x04");
            assert_eq!(self.status(WAIT), Some(WaitStatus::Exited(self.pid, 0)));
            self.exited = true;
        }
    }

    fn stopped_restored_then_continued(pty: &mut Pty, child: &Child, before: &Mode) {
        assert_eq!(
            child.status(WAIT),
            Some(WaitStatus::Stopped(child.pid, Signal::SIGSTOP))
        );
        assert!(
            pty.out.wait_for(LEAVE),
            "the modes were not left before the stop"
        );
        assert_eq!(&modes(&pty.slave), before);
        kill(child.pid, Signal::SIGCONT).unwrap();
        assert!(pty.out.wait_for(ENTER), "the modes were not entered again");
        assert!(pty.out.wait_for(FRAME_END), "no redraw after SIGCONT");
        assert_ne!(&modes(&pty.slave), before);
    }

    #[test]
    fn ctrl_z_restores_the_terminal_and_stops_and_sigcont_redraws() {
        let mut pty = pty(24, 80);
        let before = modes(&pty.slave);
        let child = Child::spawn(&mut pty, JOB);
        assert_ne!(modes(&pty.slave), before);
        pty.type_keys(b"\x1a");
        stopped_restored_then_continued(&mut pty, &child, &before);
        child.leave(&pty);
        assert!(pty.out.wait_for(LEAVE));
        assert_eq!(modes(&pty.slave), before);
    }

    #[test]
    fn an_outside_sigtstp_stops_like_ctrl_z_and_sigcont_redraws() {
        let mut pty = pty(24, 80);
        let before = modes(&pty.slave);
        let child = Child::spawn(&mut pty, JOB);
        kill(child.pid, Signal::SIGTSTP).unwrap();
        stopped_restored_then_continued(&mut pty, &child, &before);
        child.leave(&pty);
        assert_eq!(modes(&pty.slave), before);
    }

    #[test]
    fn an_outside_sigstop_then_sigcont_reenters_raw_mode_and_redraws() {
        let mut pty = pty(24, 80);
        let cooked = tcgetattr(&pty.slave).unwrap();
        let before = modes(&pty.slave);
        let child = Child::spawn(&mut pty, JOB);
        kill(child.pid, Signal::SIGSTOP).unwrap();
        assert_eq!(
            child.status(WAIT),
            Some(WaitStatus::Stopped(child.pid, Signal::SIGSTOP))
        );
        tcsetattr(&pty.slave, SetArg::TCSANOW, &cooked).unwrap();
        assert_eq!(modes(&pty.slave), before);
        kill(child.pid, Signal::SIGCONT).unwrap();
        assert!(pty.out.wait_for(ENTER), "the modes were not entered again");
        assert!(pty.out.wait_for(FRAME_END), "no redraw after SIGCONT");
        assert_ne!(
            modes(&pty.slave),
            before,
            "SIGCONT left the terminal cooked"
        );
        child.leave(&pty);
        assert_eq!(modes(&pty.slave), before);
    }

    #[test]
    fn ctrl_z_in_an_orphaned_group_does_not_stop_the_session() {
        let mut pty = pty(24, 80);
        let before = modes(&pty.slave);
        let child = Child::spawn(&mut pty, ORPHAN);
        pty.type_keys(b"\x1a");
        assert!(
            pty.out.wait_for(b"Ctrl-Z is not available"),
            "no notice that Ctrl-Z cannot stop the session"
        );
        assert_eq!(
            child.status(Duration::from_secs(1)),
            None,
            "the session stopped"
        );
        assert_ne!(modes(&pty.slave), before);
        child.leave(&pty);
        assert_eq!(modes(&pty.slave), before);
    }
}
