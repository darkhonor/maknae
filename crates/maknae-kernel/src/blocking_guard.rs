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
pub const BLOCKING_OPERATION_TIMEOUT: Duration = Duration::from_secs(5);

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
