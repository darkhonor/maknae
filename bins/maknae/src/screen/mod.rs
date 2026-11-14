//! The session screen's terminal driver (#630): raw mode and the full-screen
//! modes, signals, the run loop over the pure core in `maknae_agent::screen`,
//! and the plain-line reader and writer for a session without a terminal.
pub(crate) mod plain;
pub(crate) mod run;
pub(crate) mod term;

#[cfg(test)]
pub(crate) mod testing {
    use nix::poll::{poll, PollFd, PollFlags, PollTimeout};
    use nix::sys::termios::{
        tcgetattr, tcsetattr, ControlFlags, InputFlags, LocalFlags, OutputFlags, SetArg,
    };
    use std::os::fd::{AsFd, OwnedFd};
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::{mpsc, Arc, Mutex, MutexGuard, PoisonError};
    use std::thread::JoinHandle;
    use std::time::{Duration, Instant};

    pub(crate) const WAIT: Duration = Duration::from_secs(10);
    pub(crate) const FRAME_END: &[u8] = b"\x1b[?2026l";

    static ONE_SESSION: Mutex<()> = Mutex::new(());

    /// Sessions install a process-wide panic hook, and some tests signal the
    /// whole test process, so every test that does either takes its turn.
    pub(crate) fn one_session() -> MutexGuard<'static, ()> {
        ONE_SESSION.lock().unwrap_or_else(PoisonError::into_inner)
    }

    pub(crate) type Mode = (InputFlags, OutputFlags, ControlFlags, LocalFlags, Vec<u8>);

    pub(crate) fn modes(fd: impl AsFd) -> Mode {
        let t = tcgetattr(fd).unwrap();
        (
            t.input_flags,
            t.output_flags,
            t.control_flags,
            t.local_flags - LocalFlags::PENDIN,
            t.control_chars.to_vec(),
        )
    }

    pub(crate) struct Output {
        rx: mpsc::Receiver<Vec<u8>>,
        pub(crate) seen: Vec<u8>,
        at: usize,
    }

    impl Output {
        /// Waits up to [`WAIT`] for `needle` after the last match and moves past it.
        pub(crate) fn wait_for(&mut self, needle: &[u8]) -> bool {
            let deadline = Instant::now() + WAIT;
            loop {
                if let Some(at) = self.seen[self.at..]
                    .windows(needle.len())
                    .position(|w| w == needle)
                {
                    self.at += at + needle.len();
                    return true;
                }
                let left = deadline.saturating_duration_since(Instant::now());
                match self.rx.recv_timeout(left) {
                    Ok(chunk) => self.seen.extend_from_slice(&chunk),
                    Err(_) => return false,
                }
            }
        }

        /// The bytes that arrive within `window`.
        pub(crate) fn arriving_within(&mut self, window: Duration) -> usize {
            let deadline = Instant::now() + window;
            let start = self.seen.len();
            while let Ok(chunk) = self
                .rx
                .recv_timeout(deadline.saturating_duration_since(Instant::now()))
            {
                self.seen.extend_from_slice(&chunk);
            }
            self.seen.len() - start
        }
    }

    pub(crate) struct Pty {
        pub(crate) master: OwnedFd,
        pub(crate) slave: OwnedFd,
        pub(crate) out: Output,
        stop: Arc<AtomicBool>,
        drain: Option<JoinHandle<()>>,
    }

    impl Pty {
        /// Closes every descriptor of the master side, as a closed terminal window does.
        pub(crate) fn hang_up(&mut self) -> OwnedFd {
            self.stop.store(true, Ordering::SeqCst);
            if let Some(drain) = self.drain.take() {
                drain.join().unwrap();
            }
            let (spare, _) = nix::unistd::pipe().unwrap();
            std::mem::replace(&mut self.master, spare)
        }

        pub(crate) fn slave(&self) -> OwnedFd {
            self.slave.try_clone().unwrap()
        }

        pub(crate) fn type_keys(&self, keys: &[u8]) {
            nix::unistd::write(&self.master, keys).unwrap();
        }
    }

    impl Drop for Pty {
        fn drop(&mut self) {
            self.stop.store(true, Ordering::SeqCst);
        }
    }

    /// A pseudo-terminal in the cooked mode a shell leaves, its output drained.
    pub(crate) fn pty(rows: u16, cols: u16) -> Pty {
        let size = nix::pty::Winsize {
            ws_row: rows,
            ws_col: cols,
            ws_xpixel: 0,
            ws_ypixel: 0,
        };
        let p = nix::pty::openpty(Some(&size), None).unwrap();
        let mut t = tcgetattr(&p.slave).unwrap();
        t.local_flags
            .insert(LocalFlags::ECHO | LocalFlags::ICANON | LocalFlags::ISIG | LocalFlags::IEXTEN);
        t.input_flags.insert(
            InputFlags::ICRNL
                | InputFlags::IXON
                | InputFlags::BRKINT
                | InputFlags::IGNCR
                | InputFlags::PARMRK,
        );
        t.input_flags.remove(InputFlags::IXANY);
        t.output_flags.insert(OutputFlags::OPOST);
        tcsetattr(&p.slave, SetArg::TCSANOW, &t).unwrap();
        let master = p.master.try_clone().unwrap();
        let stop = Arc::new(AtomicBool::new(false));
        let stopped = Arc::clone(&stop);
        let (tx, rx) = mpsc::channel();
        let drain = std::thread::spawn(move || {
            let mut chunk = [0u8; 4096];
            while !stopped.load(Ordering::SeqCst) {
                let mut fds = [PollFd::new(master.as_fd(), PollFlags::POLLIN)];
                match poll(&mut fds, PollTimeout::from(50u16)) {
                    Ok(0) | Err(nix::errno::Errno::EINTR) => continue,
                    Ok(_) => {}
                    Err(_) => break,
                }
                match nix::unistd::read(&master, &mut chunk) {
                    Ok(n @ 1..) if tx.send(chunk[..n].to_vec()).is_ok() => {}
                    _ => break,
                }
            }
        });
        Pty {
            master: p.master,
            slave: p.slave,
            out: Output {
                rx,
                seen: Vec::new(),
                at: 0,
            },
            stop,
            drain: Some(drain),
        }
    }
}
