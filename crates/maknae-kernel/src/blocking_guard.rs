//! Pure circuit-breaker state for bounded blocking work.
//!
//! The run-loop owns the async orchestration and the actual `spawn_blocking`
//! calls; this module owns the mutation-gated decision state: when a timeout
//! is counted, when success resets the counter, and when a call must be refused
//! before another non-cancellable blocking task is spawned.
//!
//! The policy, read, and NSS guards bound short-horizon orphan bursts to
//! [`BLOCKING_BREAKER_MAX_IN_FLIGHT`] per guarded surface, then admit one
//! half-open recovery probe per [`BLOCKING_BREAKER_RESET_AFTER`]. If the
//! backend remains persistently wedged, that probe can orphan one additional
//! worker per cooldown. That is an intentional recovery tradeoff: unlike the
//! primary audit sink, these kernel surfaces keep probing so transient
//! infrastructure stalls self-heal without requiring process restart.

use std::time::{Duration, Instant};

/// Consecutive timed-out blocking operations allowed before refusing new work.
/// Pinned here because the binding sites in `run.rs` are T3 orchestration.
pub const BLOCKING_BREAKER_TRIP_AFTER: u8 = 3;

/// Maximum concurrent blocking operations per guarded surface. This is
/// intentionally separate from [`BLOCKING_BREAKER_TRIP_AFTER`]: ordinary
/// concurrency pressure refuses only the excess request, while repeated
/// timeouts trip the circuit breaker.
pub const BLOCKING_BREAKER_MAX_IN_FLIGHT: u8 = 32;
const _: () = assert!(BLOCKING_BREAKER_MAX_IN_FLIGHT > BLOCKING_BREAKER_TRIP_AFTER);

/// Shared operation timeout for policy/read/group blocking guards. Equal to the
/// pre-existing per-request decision bound: a healthy local filesystem or NSS
/// lookup is far below this, while wedged infrastructure fails closed promptly.
pub const BLOCKING_OPERATION_TIMEOUT: Duration =
    Duration::from_millis(maknae_config::BLOCKING_STAGE_TIMEOUT_MS);

/// Bound on each boot, reload and request audit append; one that elapses is
/// unconfirmed and handled as a failed append.
pub const AUDIT_APPEND_TIMEOUT: Duration = BLOCKING_OPERATION_TIMEOUT;

/// Bound on the boot's backward scan of the trail for the rollback anchor.
pub const SCAN_BACK_TIMEOUT: Duration = Duration::from_secs(30);

/// Runs `f` on the blocking pool and gives up waiting after `bound`; the thread is
/// left to finish on its own.
pub async fn within_blocking<T: Send + 'static>(
    bound: Duration,
    f: impl FnOnce() -> T + Send + 'static,
) -> Result<T, String> {
    match tokio::time::timeout(bound, tokio::task::spawn_blocking(f)).await {
        Ok(Ok(v)) => Ok(v),
        Ok(Err(join)) => Err(format!("blocking task failed: {join}")),
        Err(_) => Err(format!("did not complete within {}ms", bound.as_millis())),
    }
}

/// Why [`admit_blocking`] produced no value.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Offload {
    Open,
    AtCapacity,
    Join,
    TimedOut,
}

/// `work` on the blocking pool, admitted by `breaker` and bounded by `bound`: a
/// timeout is counted against the breaker; an answer or a join failure is not.
pub async fn admit_blocking<T: Send + 'static>(
    breaker: &tokio::sync::Mutex<BlockingBreaker>,
    bound: Duration,
    label: &str,
    work: impl FnOnce() -> T + Send + 'static,
) -> Result<T, Offload> {
    let admission = { breaker.lock().await.begin_attempt_at(Instant::now()) };
    match admission {
        BreakerAdmission::RefuseOpen => return Err(Offload::Open),
        BreakerAdmission::RefuseAtCapacity => return Err(Offload::AtCapacity),
        BreakerAdmission::Admit => {}
    }
    match tokio::time::timeout(bound, tokio::task::spawn_blocking(work)).await {
        Ok(Ok(v)) => {
            breaker.lock().await.record_success();
            Ok(v)
        }
        Ok(Err(_join)) => {
            breaker.lock().await.record_success();
            Err(Offload::Join)
        }
        Err(_elapsed) => {
            if breaker.lock().await.record_timeout_at(Instant::now()) == BreakerTransition::Tripped
            {
                eprintln!(
                    "maknaed: {label} circuit breaker tripped after repeated {}s blocking timeouts — failing closed without spawning more policy work",
                    bound.as_secs()
                );
            }
            Err(Offload::TimedOut)
        }
    }
}

/// Fixed recovery delay before one half-open probe may be admitted. This is not
/// configurable: policy, read, and NSS blocking guards must not be operator-
/// weakenable at runtime.
pub const BLOCKING_BREAKER_RESET_AFTER: Duration = Duration::from_secs(30);

/// Fixed per-breaker interval for open/refusal diagnostics. Timeout diagnostics
/// remain one-line-per-timeout; immediate refusal diagnostics need their own
/// cap so an open breaker cannot become a journal flood amplifier.
pub const BLOCKING_BREAKER_REFUSAL_LOG_EVERY: Duration = Duration::from_secs(30);

/// Admission decision for a guarded blocking operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BreakerAdmission {
    /// Start the blocking operation.
    Admit,
    /// Refuse because the breaker is open after repeated timeouts.
    RefuseOpen,
    /// Refuse because the fixed in-flight worker budget is full.
    RefuseAtCapacity,
}

/// State transition emitted after observing one blocking operation outcome.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BreakerTransition {
    /// The breaker remains closed and future work may still be attempted.
    RemainsClosed,
    /// This observation reached the trip threshold.
    Tripped,
}

/// Pure consecutive-timeout circuit breaker.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BlockingBreaker {
    consecutive_timeouts: u8,
    in_flight: u8,
    opened_at: Option<Instant>,
    last_refusal_logged_at: Option<Instant>,
    trip_after: u8,
    max_in_flight: u8,
    reset_after: Duration,
    refusal_log_every: Duration,
}

impl Default for BlockingBreaker {
    fn default() -> Self {
        Self::new(BLOCKING_BREAKER_TRIP_AFTER)
    }
}

impl BlockingBreaker {
    /// Build a breaker with a fixed threshold. A zero threshold starts open so
    /// tests can prove the pre-spawn refusal path directly.
    pub fn new(trip_after: u8) -> Self {
        Self {
            consecutive_timeouts: 0,
            in_flight: 0,
            opened_at: None,
            last_refusal_logged_at: None,
            trip_after,
            max_in_flight: BLOCKING_BREAKER_MAX_IN_FLIGHT,
            reset_after: BLOCKING_BREAKER_RESET_AFTER,
            refusal_log_every: BLOCKING_BREAKER_REFUSAL_LOG_EVERY,
        }
    }

    /// Whether callers must refuse before spawning more blocking work at `now`.
    pub fn is_open_at(&self, now: Instant) -> bool {
        self.opened_at
            .is_some_and(|opened_at| now.duration_since(opened_at) < self.reset_after)
    }

    /// Reserve capacity for a guarded blocking operation. Closed breakers admit
    /// work until the fixed timeout budget is already consumed by prior
    /// timeouts plus in-flight operations. An open breaker admits exactly one
    /// half-open probe after cooldown; all other callers fail closed before
    /// spawning non-cancellable blocking work.
    pub fn begin_attempt_at(&mut self, now: Instant) -> BreakerAdmission {
        if self.trip_after == 0 {
            return BreakerAdmission::RefuseOpen;
        }

        if self.is_open_at(now) {
            return BreakerAdmission::RefuseOpen;
        }

        if self.opened_at.is_some() {
            if self.in_flight == 0 {
                self.in_flight = 1;
                BreakerAdmission::Admit
            } else {
                BreakerAdmission::RefuseOpen
            }
        } else if self.in_flight < self.max_in_flight {
            self.in_flight += 1;
            BreakerAdmission::Admit
        } else {
            BreakerAdmission::RefuseAtCapacity
        }
    }

    /// Whether the immediate refusal path may emit its out-of-band diagnostic.
    pub fn should_log_refusal_at(&mut self, now: Instant) -> bool {
        let should_log = self
            .last_refusal_logged_at
            .is_none_or(|logged_at| now.duration_since(logged_at) >= self.refusal_log_every);
        if should_log {
            self.last_refusal_logged_at = Some(now);
        }
        should_log
    }

    /// Record a completed operation and close the breaker.
    pub fn record_success(&mut self) {
        self.in_flight = self.in_flight.saturating_sub(1);
        self.consecutive_timeouts = 0;
        self.opened_at = None;
    }

    /// Record an elapsed operation. The counter saturates at the threshold.
    pub fn record_timeout_at(&mut self, now: Instant) -> BreakerTransition {
        self.in_flight = self.in_flight.saturating_sub(1);
        self.consecutive_timeouts = self.consecutive_timeouts.saturating_add(1);
        if self.consecutive_timeouts >= self.trip_after {
            self.consecutive_timeouts = self.trip_after;
            self.opened_at = Some(now);
            BreakerTransition::Tripped
        } else {
            BreakerTransition::RemainsClosed
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_admin_reply_stage_is_bounded_by_the_bound_the_cli_waits_out() {
        let stage = Duration::from_millis(maknae_config::BLOCKING_STAGE_TIMEOUT_MS);
        assert_eq!(BLOCKING_OPERATION_TIMEOUT, stage);
        assert_eq!(AUDIT_APPEND_TIMEOUT, stage);
        assert_eq!(crate::handler::AUTHZ_DECIDE_TIMEOUT, stage);
    }

    /// The egress deputy cannot depend on this crate, so it states the
    /// kernel's egress admission itself; this holds the two equal (#321).
    #[test]
    fn the_egress_deputy_states_this_admission() {
        let deputy = include_str!("../../../bins/maknae-egress/src/capacity.rs");
        let stated = format!(
            "pub const KERNEL_ADMISSION: usize = {};",
            BLOCKING_BREAKER_MAX_IN_FLIGHT
        );
        assert!(
            deputy.contains(&stated),
            "expected `{stated}` in capacity.rs"
        );
    }

    #[test]
    fn threshold_and_timeout_values_are_pinned() {
        assert_eq!(BLOCKING_BREAKER_TRIP_AFTER, 3);
        assert_ne!(BLOCKING_BREAKER_TRIP_AFTER, 0);
        assert_eq!(BLOCKING_BREAKER_MAX_IN_FLIGHT, 32);
        assert_eq!(BLOCKING_OPERATION_TIMEOUT, Duration::from_secs(5));
        assert!(!BLOCKING_OPERATION_TIMEOUT.is_zero());
        assert_eq!(BLOCKING_BREAKER_RESET_AFTER, Duration::from_secs(30));
        assert!(!BLOCKING_BREAKER_RESET_AFTER.is_zero());
        assert_eq!(BLOCKING_BREAKER_REFUSAL_LOG_EVERY, Duration::from_secs(30));
        assert!(!BLOCKING_BREAKER_REFUSAL_LOG_EVERY.is_zero());
    }

    #[tokio::test]
    async fn within_blocking_gives_up_after_the_bound() {
        let got = within_blocking(Duration::from_millis(50), || {
            std::thread::sleep(Duration::from_millis(500))
        })
        .await;
        assert_eq!(got, Err("did not complete within 50ms".to_string()));
        assert_eq!(within_blocking(Duration::from_secs(1), || 7).await, Ok(7));
    }

    #[tokio::test]
    async fn within_blocking_reports_a_task_that_panicked() {
        let got = within_blocking(Duration::from_secs(5), || -> u8 { panic!("boom") }).await;
        assert!(
            got.as_ref()
                .is_err_and(|e| e.starts_with("blocking task failed: ")),
            "{got:?}"
        );
    }

    fn breaker(trip_after: u8) -> tokio::sync::Mutex<BlockingBreaker> {
        tokio::sync::Mutex::new(BlockingBreaker::new(trip_after))
    }

    #[tokio::test]
    async fn admit_blocking_returns_the_work_and_releases_its_slot() {
        let b = breaker(BLOCKING_BREAKER_TRIP_AFTER);
        for _ in 1..BLOCKING_BREAKER_MAX_IN_FLIGHT {
            b.lock().await.begin_attempt_at(Instant::now());
        }
        for n in 0..3u8 {
            assert_eq!(
                admit_blocking(&b, Duration::from_secs(5), "test", move || n).await,
                Ok(n)
            );
        }
    }

    #[tokio::test]
    async fn admit_blocking_refuses_an_open_breaker_without_running_the_work() {
        let ran = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let r = ran.clone();
        let got = admit_blocking(&breaker(0), Duration::from_secs(5), "test", move || {
            r.store(true, std::sync::atomic::Ordering::SeqCst)
        })
        .await;
        assert_eq!(got, Err(Offload::Open));
        assert!(!ran.load(std::sync::atomic::Ordering::SeqCst));
    }

    #[tokio::test]
    async fn admit_blocking_refuses_at_capacity_without_running_the_work() {
        let b = breaker(BLOCKING_BREAKER_TRIP_AFTER);
        for _ in 0..BLOCKING_BREAKER_MAX_IN_FLIGHT {
            b.lock().await.begin_attempt_at(Instant::now());
        }
        let ran = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let r = ran.clone();
        let got = admit_blocking(&b, Duration::from_secs(5), "test", move || {
            r.store(true, std::sync::atomic::Ordering::SeqCst)
        })
        .await;
        assert_eq!(got, Err(Offload::AtCapacity));
        assert!(!ran.load(std::sync::atomic::Ordering::SeqCst));
    }

    #[tokio::test]
    async fn admit_blocking_reports_a_join_failure_without_counting_it() {
        let b = breaker(1);
        for _ in 1..BLOCKING_BREAKER_MAX_IN_FLIGHT {
            b.lock().await.begin_attempt_at(Instant::now());
        }
        let got = admit_blocking(&b, Duration::from_secs(5), "test", || -> u8 {
            panic!("admit_blocking join probe")
        })
        .await;
        assert_eq!(got, Err(Offload::Join));
        assert!(!b.lock().await.is_open_at(Instant::now()));
        assert_eq!(
            admit_blocking(&b, Duration::from_secs(5), "test", || 9u8).await,
            Ok(9)
        );
    }

    #[tokio::test]
    async fn admit_blocking_counts_a_timeout_and_trips() {
        let b = breaker(2);
        for tripped in [false, true] {
            let got = admit_blocking(&b, Duration::from_millis(20), "test", || {
                std::thread::sleep(Duration::from_millis(300))
            })
            .await;
            assert_eq!(got, Err(Offload::TimedOut));
            assert_eq!(b.lock().await.is_open_at(Instant::now()), tripped);
        }
        assert_eq!(
            admit_blocking(&b, Duration::from_secs(5), "test", || 1u8).await,
            Err(Offload::Open)
        );
    }

    #[test]
    fn the_audit_and_scan_bounds_are_pinned() {
        assert_eq!(AUDIT_APPEND_TIMEOUT, Duration::from_secs(5));
        assert_eq!(SCAN_BACK_TIMEOUT, Duration::from_secs(30));
    }

    #[test]
    fn breaker_reserves_before_spawning_and_caps_concurrent_work_without_opening() {
        let mut breaker = BlockingBreaker::default();
        let now = Instant::now();
        for _ in 0..BLOCKING_BREAKER_MAX_IN_FLIGHT {
            assert_eq!(breaker.begin_attempt_at(now), BreakerAdmission::Admit);
        }
        assert_eq!(
            breaker.begin_attempt_at(now),
            BreakerAdmission::RefuseAtCapacity
        );
        assert!(!breaker.is_open_at(now));
    }

    #[test]
    fn success_resets_accumulated_timeouts() {
        let mut breaker = BlockingBreaker::default();
        let now = Instant::now();
        assert_eq!(breaker.begin_attempt_at(now), BreakerAdmission::Admit);
        assert_eq!(
            breaker.record_timeout_at(now),
            BreakerTransition::RemainsClosed
        );
        assert_eq!(breaker.begin_attempt_at(now), BreakerAdmission::Admit);
        assert_eq!(
            breaker.record_timeout_at(now),
            BreakerTransition::RemainsClosed
        );
        assert_eq!(breaker.begin_attempt_at(now), BreakerAdmission::Admit);
        breaker.record_success();
        assert!(!breaker.is_open_at(now));
        assert_eq!(breaker.begin_attempt_at(now), BreakerAdmission::Admit);
        assert_eq!(
            breaker.record_timeout_at(now),
            BreakerTransition::RemainsClosed
        );
        assert_eq!(breaker.begin_attempt_at(now), BreakerAdmission::Admit);
        assert_eq!(
            breaker.record_timeout_at(now),
            BreakerTransition::RemainsClosed
        );
        assert_eq!(breaker.begin_attempt_at(now), BreakerAdmission::Admit);
        assert_eq!(breaker.record_timeout_at(now), BreakerTransition::Tripped);
    }

    #[test]
    fn zero_threshold_is_open_without_observation() {
        let mut breaker = BlockingBreaker::new(0);
        assert_eq!(
            breaker.begin_attempt_at(Instant::now()),
            BreakerAdmission::RefuseOpen
        );
    }

    #[test]
    fn tripped_breaker_half_opens_for_one_probe_after_cooldown() {
        let mut breaker = BlockingBreaker::default();
        let now = Instant::now();
        for _ in 0..3 {
            assert_eq!(breaker.begin_attempt_at(now), BreakerAdmission::Admit);
            breaker.record_timeout_at(now);
        }
        assert!(breaker.is_open_at(now));
        assert_eq!(
            breaker.begin_attempt_at(now + BLOCKING_BREAKER_RESET_AFTER),
            BreakerAdmission::Admit
        );
        assert_eq!(
            breaker.begin_attempt_at(now + BLOCKING_BREAKER_RESET_AFTER),
            BreakerAdmission::RefuseOpen
        );
        breaker.record_success();
        assert_eq!(
            breaker.begin_attempt_at(now + BLOCKING_BREAKER_RESET_AFTER),
            BreakerAdmission::Admit
        );
    }

    #[test]
    fn refusal_logging_is_rate_limited_per_breaker() {
        let mut breaker = BlockingBreaker::default();
        let now = Instant::now();
        assert!(breaker.should_log_refusal_at(now));
        assert!(!breaker.should_log_refusal_at(now));
        assert!(!breaker.should_log_refusal_at(
            now + BLOCKING_BREAKER_REFUSAL_LOG_EVERY - Duration::from_millis(1)
        ));
        assert!(breaker.should_log_refusal_at(now + BLOCKING_BREAKER_REFUSAL_LOG_EVERY));
    }
}
