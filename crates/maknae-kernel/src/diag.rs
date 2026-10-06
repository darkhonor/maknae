use std::io::Write;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc::{channel, sync_channel, Sender, SyncSender, TrySendError};
use std::sync::{Arc, OnceLock};
use std::time::{Duration, Instant};

/// Lines queued for the writer thread before further lines are dropped and counted.
const DIAG_QUEUE_CAPACITY: usize = 256;

enum Msg {
    Line(String),
    Flush(Sender<()>),
}

struct Sink {
    tx: SyncSender<Msg>,
    dropped: Arc<AtomicU64>,
}

impl Sink {
    fn new(capacity: usize, mut writer: Box<dyn Write + Send>) -> Self {
        let (tx, rx) = sync_channel::<Msg>(capacity);
        let dropped = Arc::new(AtomicU64::new(0));
        let counter = Arc::clone(&dropped);
        let _ = std::thread::Builder::new()
            .name("maknaed-diag".into())
            .spawn(move || {
                let notice = |writer: &mut Box<dyn Write + Send>| {
                    let n = counter.swap(0, Ordering::Relaxed);
                    if n > 0 {
                        let _ = writeln!(
                            writer,
                            "maknaed: {n} diagnostic lines dropped while stderr was slow"
                        );
                        let _ = writer.flush();
                    }
                };
                while let Ok(msg) = rx.recv() {
                    match msg {
                        Msg::Line(line) => {
                            notice(&mut writer);
                            let _ = writeln!(writer, "{line}");
                            let _ = writer.flush();
                            notice(&mut writer);
                        }
                        Msg::Flush(ack) => {
                            notice(&mut writer);
                            let _ = ack.send(());
                        }
                    }
                }
            });
        Self { tx, dropped }
    }

    fn report(&self, line: String) {
        if self.tx.try_send(Msg::Line(line)).is_err() {
            self.dropped.fetch_add(1, Ordering::Relaxed);
        }
    }

    fn flush_within(&self, bound: Duration) {
        let deadline = Instant::now() + bound;
        let (ack_tx, ack_rx) = channel();
        let mut msg = Msg::Flush(ack_tx);
        loop {
            match self.tx.try_send(msg) {
                Ok(()) => break,
                Err(TrySendError::Disconnected(_)) => return,
                Err(TrySendError::Full(m)) => {
                    if Instant::now() >= deadline {
                        return;
                    }
                    msg = m;
                    std::thread::sleep(Duration::from_millis(1));
                }
            }
        }
        let _ = ack_rx.recv_timeout(deadline.saturating_duration_since(Instant::now()));
    }
}

fn sink() -> &'static Sink {
    static SINK: OnceLock<Sink> = OnceLock::new();
    SINK.get_or_init(|| Sink::new(DIAG_QUEUE_CAPACITY, process_writer()))
}

/// Queue one diagnostic line for stderr without ever blocking the caller.
pub(crate) fn report(line: String) {
    sink().report(line);
}

/// Wait up to `bound` for every line queued so far to reach the writer.
pub(crate) fn flush_within(bound: Duration) {
    sink().flush_within(bound);
}

fn process_writer() -> Box<dyn Write + Send> {
    #[cfg(test)]
    {
        Box::new(tests::Capture)
    }
    #[cfg(not(test))]
    {
        Box::new(std::io::stderr())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Condvar, Mutex};
    use std::time::{Duration, Instant};

    pub(super) static CAPTURED: Mutex<Vec<u8>> = Mutex::new(Vec::new());

    pub(super) struct Capture;

    impl Write for Capture {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            CAPTURED.lock().unwrap().extend_from_slice(buf);
            Ok(buf.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    #[derive(Default)]
    struct Gate {
        open: Mutex<bool>,
        entered: Mutex<bool>,
        cv: Condvar,
    }

    struct GatedWriter {
        gate: Arc<Gate>,
        out: Arc<Mutex<Vec<u8>>>,
    }

    impl Write for GatedWriter {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            *self.gate.entered.lock().unwrap() = true;
            let mut open = self.gate.open.lock().unwrap();
            while !*open {
                open = self.gate.cv.wait(open).unwrap();
            }
            self.out.lock().unwrap().extend_from_slice(buf);
            Ok(buf.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    fn wait_until(mut cond: impl FnMut() -> bool) {
        let deadline = Instant::now() + Duration::from_secs(5);
        while !cond() {
            assert!(Instant::now() < deadline, "condition never held");
            std::thread::sleep(Duration::from_millis(2));
        }
    }

    fn text(out: &Arc<Mutex<Vec<u8>>>) -> String {
        String::from_utf8(out.lock().unwrap().clone()).unwrap()
    }

    #[test]
    fn a_blocked_writer_never_blocks_the_caller_and_overflow_is_counted() {
        const CAP: usize = 4;
        let gate = Arc::new(Gate::default());
        let out = Arc::new(Mutex::new(Vec::new()));
        let sink = Sink::new(
            CAP,
            Box::new(GatedWriter {
                gate: Arc::clone(&gate),
                out: Arc::clone(&out),
            }),
        );

        sink.report("line-0".into());
        wait_until(|| *gate.entered.lock().unwrap());

        let sink = Arc::new(sink);
        let flooder = Arc::clone(&sink);
        let (done_tx, done_rx) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            for i in 1..=(CAP + 5) {
                flooder.report(format!("line-{i}"));
            }
            let _ = done_tx.send(());
        });
        let finished = done_rx.recv_timeout(Duration::from_millis(500));
        if finished.is_err() {
            *gate.open.lock().unwrap() = true;
            gate.cv.notify_all();
        }
        assert!(finished.is_ok(), "report blocked on a stalled writer");
        assert_eq!(sink.dropped.load(Ordering::Relaxed), 5);

        *gate.open.lock().unwrap() = true;
        gate.cv.notify_all();
        wait_until(|| text(&out).contains("line-4"));

        let written = text(&out);
        assert!(
            written.contains("5 diagnostic lines dropped while stderr was slow"),
            "{written}"
        );
        assert!(written.starts_with("line-0\n"), "{written}");
        for i in 1..=CAP {
            assert!(written.contains(&format!("line-{i}\n")), "{written}");
        }
        assert!(!written.contains("line-5"), "{written}");
        assert_eq!(sink.dropped.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn a_drop_that_lands_after_the_last_dequeue_is_still_reported() {
        let gate = Arc::new(Gate::default());
        let out = Arc::new(Mutex::new(Vec::new()));
        let sink = Sink::new(
            4,
            Box::new(GatedWriter {
                gate: Arc::clone(&gate),
                out: Arc::clone(&out),
            }),
        );
        sink.report("last".into());
        wait_until(|| *gate.entered.lock().unwrap());
        sink.dropped.fetch_add(3, Ordering::Relaxed);

        *gate.open.lock().unwrap() = true;
        gate.cv.notify_all();
        wait_until(|| text(&out).contains("3 diagnostic lines dropped while stderr was slow\n"));
        assert!(text(&out).starts_with("last\n"));
    }

    #[test]
    fn flush_returns_after_queued_lines_are_written() {
        let gate = Arc::new(Gate::default());
        *gate.open.lock().unwrap() = true;
        let out = Arc::new(Mutex::new(Vec::new()));
        let sink = Sink::new(
            8,
            Box::new(GatedWriter {
                gate,
                out: Arc::clone(&out),
            }),
        );
        sink.report("one".into());
        sink.report("two".into());
        sink.flush_within(Duration::from_secs(5));
        assert_eq!(text(&out), "one\ntwo\n");
    }

    #[test]
    fn flush_gives_up_at_its_bound_when_the_writer_is_stalled() {
        let gate = Arc::new(Gate::default());
        let out = Arc::new(Mutex::new(Vec::new()));
        let sink = Sink::new(
            2,
            Box::new(GatedWriter {
                gate: Arc::clone(&gate),
                out,
            }),
        );
        sink.report("stuck".into());
        wait_until(|| *gate.entered.lock().unwrap());
        sink.report("q1".into());
        sink.report("q2".into());

        let started = Instant::now();
        sink.flush_within(Duration::from_millis(100));
        let took = started.elapsed();
        *gate.open.lock().unwrap() = true;
        gate.cv.notify_all();
        assert!(took >= Duration::from_millis(100), "{took:?}");
        assert!(took < Duration::from_millis(400), "{took:?}");
    }

    #[test]
    fn flush_gives_up_at_its_bound_when_the_marker_is_acknowledged_late() {
        let gate = Arc::new(Gate::default());
        let out = Arc::new(Mutex::new(Vec::new()));
        let sink = Sink::new(
            4,
            Box::new(GatedWriter {
                gate: Arc::clone(&gate),
                out,
            }),
        );
        sink.report("stuck".into());
        wait_until(|| *gate.entered.lock().unwrap());

        let started = Instant::now();
        sink.flush_within(Duration::from_millis(100));
        let took = started.elapsed();
        *gate.open.lock().unwrap() = true;
        gate.cv.notify_all();
        assert!(took >= Duration::from_millis(100), "{took:?}");
        assert!(took < Duration::from_millis(400), "{took:?}");
    }

    #[test]
    fn an_unstalled_writer_reports_every_line_and_no_drop_notice() {
        let gate = Arc::new(Gate::default());
        *gate.open.lock().unwrap() = true;
        let out = Arc::new(Mutex::new(Vec::new()));
        let sink = Sink::new(
            8,
            Box::new(GatedWriter {
                gate,
                out: Arc::clone(&out),
            }),
        );
        sink.report("only".into());
        wait_until(|| text(&out) == "only\n");
        assert_eq!(sink.dropped.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn the_process_wide_report_returns_immediately() {
        let started = Instant::now();
        report("maknaed: diag self-test line".into());
        assert!(started.elapsed() < Duration::from_millis(200));
        flush_within(Duration::from_secs(5));
        assert!(String::from_utf8_lossy(&CAPTURED.lock().unwrap())
            .contains("maknaed: diag self-test line\n"));
    }
}
