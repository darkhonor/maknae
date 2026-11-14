//! SIGTERM: stop claiming, let the exchange in flight finish within
//! [`AGENTD_EXCHANGE_DRAIN`], then revoke the plane login within
//! `PLANE_SHUTDOWN_BOUND`. A task left `Working` is reported at the next start.
use maknae_agent::task_driver::Clock;
use std::future::Future;
use std::time::Duration;
use tokio::sync::watch;

pub const AGENTD_EXCHANGE_DRAIN: Duration = Duration::from_secs(30);
pub const RUNTIME_SHUTDOWN_TIMEOUT: Duration = Duration::from_secs(1);

pub fn stop_signal() -> (watch::Sender<bool>, watch::Receiver<bool>) {
    watch::channel(false)
}

pub async fn stopped(mut stop: watch::Receiver<bool>) {
    let _ = stop.wait_for(|s| *s).await;
}

/// Monotonic; a sleep ends early once the stop signal is sent.
pub struct TokioClock {
    origin: tokio::time::Instant,
    stop: watch::Receiver<bool>,
}

impl TokioClock {
    pub fn new(stop: watch::Receiver<bool>) -> Self {
        TokioClock {
            origin: tokio::time::Instant::now(),
            stop,
        }
    }
}

impl Clock for TokioClock {
    fn now(&self) -> Duration {
        self.origin.elapsed()
    }

    fn sleep(&mut self, d: Duration) -> impl Future<Output = ()> + Send {
        let stop = self.stop.clone();
        async move {
            tokio::select! {
                () = tokio::time::sleep(d) => {}
                () = stopped(stop) => {}
            }
        }
    }
}

#[derive(Debug, PartialEq, Eq)]
pub enum Ended {
    Finished,
    Drained,
    Abandoned,
}

/// Runs `work` until `signal`; then calls `on_signal` and gives `work` `drain` to finish.
/// The signal is polled first, so a sleep it wakes resumes with `on_signal` already run.
pub async fn run_until_drained<W, S>(
    work: W,
    signal: S,
    on_signal: impl FnOnce(),
    drain: Duration,
) -> Ended
where
    W: Future<Output = ()>,
    S: Future<Output = ()>,
{
    let mut work = std::pin::pin!(work);
    tokio::select! {
        biased;
        () = signal => {}
        () = &mut work => return Ended::Finished,
    }
    on_signal();
    match tokio::time::timeout(drain, work).await {
        Ok(()) => Ended::Drained,
        Err(_) => Ended::Abandoned,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use maknae_agent::task_driver::UNDECODABLE_WAIT;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::Arc;

    fn only(text: &str, key: &str, value: impl Fn(&str) -> Option<u64>) -> Duration {
        let found: Vec<u64> = text
            .match_indices(key)
            .filter_map(|(at, _)| value(&text[at + key.len()..]))
            .collect();
        assert_eq!(found.len(), 1, "{key}: {found:?}");
        Duration::from_secs(found[0])
    }

    /// A SIGTERM inside the first mint waits out its login and leaf signing, then
    /// the drain, the leaf supervisor's stop, the revoke and the runtime teardown.
    /// Two-sided, as the kernel's unit test is: a unit far above the chain means a
    /// term was dropped from this expression. The launchd job's `ExitTimeOut` is
    /// the same bound.
    #[test]
    fn the_agent_units_stop_timeout_covers_its_shutdown_chain() {
        const SLACK: Duration = Duration::from_secs(10);
        const MINT_REQUESTS: u32 = 2;
        let chain = maknae_vault::PLANE_HTTP_TIMEOUT * MINT_REQUESTS
            + AGENTD_EXCHANGE_DRAIN
            + crate::plane_impl::LEAF_STOP_WAIT
            + maknae_vault::PLANE_SHUTDOWN_BOUND
            + RUNTIME_SHUTDOWN_TIMEOUT;
        let unit = include_str!("../../../packaging/common/maknae-agent@.service");
        let plist = include_str!("../../../packaging/macos/io.maknae.maknae-agentd.template.plist");
        let systemd = only(unit, "\nTimeoutStopSec=", |v| {
            v.lines().next()?.trim().parse().ok()
        });
        let launchd = only(plist, "<key>ExitTimeOut</key>", |v| {
            v.trim_start()
                .strip_prefix("<integer>")?
                .split_once("</integer>")?
                .0
                .parse()
                .ok()
        });
        for (name, stop) in [("TimeoutStopSec", systemd), ("ExitTimeOut", launchd)] {
            assert!(
                stop >= chain,
                "{name}={stop:?} is below the chain {chain:?}"
            );
            assert!(
                stop <= chain + SLACK,
                "{name}={stop:?} is more than {SLACK:?} above the chain {chain:?}"
            );
        }
    }

    #[tokio::test(start_paused = true)]
    async fn a_sleep_runs_its_length_when_nothing_stops_it() {
        let (_tx, rx) = stop_signal();
        let mut clock = TokioClock::new(rx);
        let start = clock.now();
        clock.sleep(Duration::from_secs(5)).await;
        assert_eq!(clock.now() - start, Duration::from_secs(5));
    }

    #[tokio::test(start_paused = true)]
    async fn the_stop_signal_ends_the_undecodable_wait_at_once() {
        let (tx, rx) = stop_signal();
        let mut clock = TokioClock::new(rx);
        let start = clock.now();
        let sleeping = tokio::spawn(async move {
            clock.sleep(UNDECODABLE_WAIT).await;
            clock.now()
        });
        tokio::time::sleep(Duration::from_secs(7)).await;
        tx.send(true).unwrap();
        let woke = sleeping.await.unwrap();
        assert_eq!(woke - start, Duration::from_secs(7));
    }

    #[tokio::test(start_paused = true)]
    async fn a_sleep_begun_after_the_stop_signal_does_not_wait() {
        let (tx, rx) = stop_signal();
        tx.send(true).unwrap();
        let mut clock = TokioClock::new(rx);
        let start = clock.now();
        clock.sleep(UNDECODABLE_WAIT).await;
        assert_eq!(clock.now(), start);
    }

    #[tokio::test(start_paused = true)]
    async fn work_that_ends_on_its_own_is_finished_and_never_signalled() {
        let signalled = AtomicBool::new(false);
        let ended = run_until_drained(
            tokio::time::sleep(Duration::from_secs(3)),
            std::future::pending(),
            || signalled.store(true, Ordering::SeqCst),
            AGENTD_EXCHANGE_DRAIN,
        )
        .await;
        assert_eq!(ended, Ended::Finished);
        assert!(!signalled.load(Ordering::SeqCst));
    }

    #[tokio::test(start_paused = true)]
    async fn the_exchange_in_flight_finishes_within_the_drain() {
        let flag = Arc::new(AtomicBool::new(false));
        let seen = Arc::clone(&flag);
        let work = async move {
            while !seen.load(Ordering::SeqCst) {
                tokio::time::sleep(Duration::from_secs(1)).await;
            }
            tokio::time::sleep(AGENTD_EXCHANGE_DRAIN - Duration::from_secs(2)).await;
        };
        let start = tokio::time::Instant::now();
        let ended = run_until_drained(
            work,
            tokio::time::sleep(Duration::from_secs(10)),
            || flag.store(true, Ordering::SeqCst),
            AGENTD_EXCHANGE_DRAIN,
        )
        .await;
        assert_eq!(ended, Ended::Drained);
        assert!(start.elapsed() < Duration::from_secs(10) + AGENTD_EXCHANGE_DRAIN);
    }

    #[tokio::test(start_paused = true)]
    async fn an_exchange_that_outlasts_the_drain_is_abandoned_at_the_bound() {
        let start = tokio::time::Instant::now();
        let ended = run_until_drained(
            std::future::pending(),
            tokio::time::sleep(Duration::from_secs(10)),
            || {},
            AGENTD_EXCHANGE_DRAIN,
        )
        .await;
        assert_eq!(ended, Ended::Abandoned);
        assert_eq!(
            start.elapsed(),
            Duration::from_secs(10) + AGENTD_EXCHANGE_DRAIN
        );
    }

    #[tokio::test(start_paused = true)]
    async fn work_woken_by_the_stop_resumes_after_on_signal_has_run() {
        let (tx, rx) = stop_signal();
        let handle = Arc::new(AtomicBool::new(false));
        let seen = Arc::new(AtomicBool::new(false));
        let (h, s) = (Arc::clone(&handle), Arc::clone(&seen));
        let mut clock = TokioClock::new(rx.clone());
        let work = async move {
            clock.sleep(UNDECODABLE_WAIT).await;
            s.store(h.load(Ordering::SeqCst), Ordering::SeqCst);
        };
        tx.send(true).unwrap();
        let ended = run_until_drained(
            work,
            stopped(rx),
            || handle.store(true, Ordering::SeqCst),
            AGENTD_EXCHANGE_DRAIN,
        )
        .await;
        assert_eq!(ended, Ended::Drained);
        assert!(
            seen.load(Ordering::SeqCst),
            "the driver saw no shutdown when it woke"
        );
    }
}
