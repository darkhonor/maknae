//! Pure circuit-breaker state for the audit sink's blocking append worker.
//!
//! The sink performs the async `spawn_blocking`; this module owns the
//! mutation-gated decision state used to stop spawning once filesystem stalls
//! consume the fixed in-flight append budget.

use std::collections::VecDeque;
use std::time::{Duration, Instant};

/// Consecutive timed-out audit appends allowed before refusing new appends.
/// Pinned here because the async append binding is I/O orchestration.
pub const AUDIT_APPEND_BREAKER_TRIP_AFTER: u8 = 3;

/// Maximum concurrent primary audit appends before refusing new work. This is
/// a concurrency budget, not the orphan budget: stale recovery below carries
/// the separate lifetime bound for additional wedged attempts.
pub const AUDIT_APPEND_BREAKER_MAX_IN_FLIGHT: u8 = 32;

/// Age after which a still-unfinished audit append is treated as stale for
/// admission purposes. The original append future still awaits completion, so
/// this does not create a false durable outcome; it only permits a bounded
/// recovery probe after the primary sink has had time to heal.
pub const AUDIT_APPEND_STALE_AFTER: Duration = Duration::from_secs(30);

/// Maximum stale slots that may be reclaimed over one sink lifetime. This
/// bounds total non-cancellable audit append workers under a persistent wedge
/// to `MAX_IN_FLIGHT + MAX_STALE_RECLAIMS`.
pub const AUDIT_APPEND_MAX_STALE_RECLAIMS: u8 = 3;

/// Fixed per-breaker interval for open/refusal diagnostics so a wedged primary
/// audit sink cannot turn fail-closed refusals into an unbounded journal flood.
pub const AUDIT_APPEND_BREAKER_REFUSAL_LOG_EVERY: Duration = Duration::from_secs(30);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BreakerAdmission {
    Admit(AuditAttempt),
    RefuseOpen,
    RefuseAtCapacity,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AuditAttempt(u64);

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BlockingBreaker {
    in_flight: VecDeque<(AuditAttempt, Instant)>,
    last_refusal_logged_at: Option<Instant>,
    stale_reclaims: u8,
    next_attempt_id: u64,
    trip_after: u8,
    max_in_flight: u8,
    stale_after: Duration,
    max_stale_reclaims: u8,
    refusal_log_every: Duration,
}

impl Default for BlockingBreaker {
    fn default() -> Self {
        Self::new(AUDIT_APPEND_BREAKER_TRIP_AFTER)
    }
}

impl BlockingBreaker {
    pub fn new(trip_after: u8) -> Self {
        Self {
            in_flight: VecDeque::new(),
            last_refusal_logged_at: None,
            stale_reclaims: 0,
            next_attempt_id: 0,
            trip_after,
            max_in_flight: AUDIT_APPEND_BREAKER_MAX_IN_FLIGHT,
            stale_after: AUDIT_APPEND_STALE_AFTER,
            max_stale_reclaims: AUDIT_APPEND_MAX_STALE_RECLAIMS,
            refusal_log_every: AUDIT_APPEND_BREAKER_REFUSAL_LOG_EVERY,
        }
    }

    pub fn begin_attempt_at(&mut self, now: Instant) -> BreakerAdmission {
        if self.trip_after == 0 {
            return BreakerAdmission::RefuseOpen;
        }

        while self.stale_reclaims < self.max_stale_reclaims
            && self
                .in_flight
                .front()
                .is_some_and(|(_, started_at)| now.duration_since(*started_at) >= self.stale_after)
        {
            self.in_flight.pop_front();
            self.stale_reclaims += 1;
        }

        if self.in_flight.len() < usize::from(self.max_in_flight) {
            let attempt = AuditAttempt(self.next_attempt_id);
            self.next_attempt_id = self.next_attempt_id.saturating_add(1);
            self.in_flight.push_back((attempt, now));
            BreakerAdmission::Admit(attempt)
        } else if self.stale_reclaims >= self.max_stale_reclaims {
            BreakerAdmission::RefuseOpen
        } else {
            BreakerAdmission::RefuseAtCapacity
        }
    }

    pub fn should_log_refusal_at(&mut self, now: Instant) -> bool {
        let should_log = self
            .last_refusal_logged_at
            .is_none_or(|logged_at| now.duration_since(logged_at) >= self.refusal_log_every);
        if should_log {
            self.last_refusal_logged_at = Some(now);
        }
        should_log
    }

    pub fn record_success(&mut self, attempt: AuditAttempt) {
        if let Some(pos) = self
            .in_flight
            .iter()
            .position(|(in_flight, _)| *in_flight == attempt)
        {
            self.in_flight.remove(pos);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn audit_threshold_and_refusal_log_values_are_pinned() {
        assert_eq!(AUDIT_APPEND_BREAKER_TRIP_AFTER, 3);
        assert_ne!(AUDIT_APPEND_BREAKER_TRIP_AFTER, 0);
        assert_eq!(AUDIT_APPEND_BREAKER_MAX_IN_FLIGHT, 32);
        assert_eq!(AUDIT_APPEND_STALE_AFTER, Duration::from_secs(30));
        assert_eq!(AUDIT_APPEND_MAX_STALE_RECLAIMS, 3);
        assert_eq!(
            AUDIT_APPEND_BREAKER_REFUSAL_LOG_EVERY,
            Duration::from_secs(30)
        );
        assert!(!AUDIT_APPEND_BREAKER_REFUSAL_LOG_EVERY.is_zero());
    }

    #[test]
    fn breaker_reserves_before_spawning_and_caps_concurrent_work() {
        let mut breaker = BlockingBreaker::default();
        let now = Instant::now();
        for _ in 0..AUDIT_APPEND_BREAKER_MAX_IN_FLIGHT {
            assert!(matches!(
                breaker.begin_attempt_at(now),
                BreakerAdmission::Admit(_)
            ));
        }
        assert_eq!(
            breaker.begin_attempt_at(now),
            BreakerAdmission::RefuseAtCapacity
        );
    }

    #[test]
    fn success_releases_one_in_flight_slot() {
        let mut breaker = BlockingBreaker::default();
        let now = Instant::now();
        let BreakerAdmission::Admit(first) = breaker.begin_attempt_at(now) else {
            panic!("first attempt should admit");
        };
        for _ in 1..AUDIT_APPEND_BREAKER_MAX_IN_FLIGHT {
            assert!(matches!(
                breaker.begin_attempt_at(now),
                BreakerAdmission::Admit(_)
            ));
        }
        assert_eq!(
            breaker.begin_attempt_at(now),
            BreakerAdmission::RefuseAtCapacity
        );
        breaker.record_success(first);
        assert!(matches!(
            breaker.begin_attempt_at(now),
            BreakerAdmission::Admit(_)
        ));
    }

    #[test]
    fn zero_threshold_refuses_before_spawn() {
        assert_eq!(
            BlockingBreaker::new(0).begin_attempt_at(Instant::now()),
            BreakerAdmission::RefuseOpen
        );
    }

    #[test]
    fn unknown_success_observations_do_not_release_capacity() {
        let mut breaker = BlockingBreaker::default();
        let now = Instant::now();
        breaker.record_success(AuditAttempt(999));
        for _ in 0..AUDIT_APPEND_BREAKER_MAX_IN_FLIGHT {
            assert!(matches!(
                breaker.begin_attempt_at(now),
                BreakerAdmission::Admit(_)
            ));
        }
        assert_eq!(
            breaker.begin_attempt_at(now),
            BreakerAdmission::RefuseAtCapacity
        );
    }

    #[test]
    fn stale_slots_age_out_with_a_lifetime_cap() {
        let mut breaker = BlockingBreaker::default();
        let now = Instant::now();
        let BreakerAdmission::Admit(first) = breaker.begin_attempt_at(now) else {
            panic!("first attempt should admit");
        };
        for _ in 1..AUDIT_APPEND_BREAKER_MAX_IN_FLIGHT {
            assert!(matches!(
                breaker.begin_attempt_at(now),
                BreakerAdmission::Admit(_)
            ));
        }
        assert_eq!(
            breaker.begin_attempt_at(now),
            BreakerAdmission::RefuseAtCapacity
        );

        let later = now + AUDIT_APPEND_STALE_AFTER;
        assert!(matches!(
            breaker.begin_attempt_at(later),
            BreakerAdmission::Admit(_)
        ));
        assert!(matches!(
            breaker.begin_attempt_at(later),
            BreakerAdmission::Admit(_)
        ));
        assert!(matches!(
            breaker.begin_attempt_at(later),
            BreakerAdmission::Admit(_)
        ));
        assert_eq!(
            breaker.begin_attempt_at(later + AUDIT_APPEND_STALE_AFTER),
            BreakerAdmission::RefuseOpen
        );
        breaker.record_success(first);
        assert_eq!(
            breaker.begin_attempt_at(later + AUDIT_APPEND_STALE_AFTER),
            BreakerAdmission::RefuseOpen
        );
    }

    #[test]
    fn refusal_logging_is_rate_limited_per_breaker() {
        let mut breaker = BlockingBreaker::default();
        let now = Instant::now();
        assert!(breaker.should_log_refusal_at(now));
        assert!(!breaker.should_log_refusal_at(now));
        assert!(!breaker.should_log_refusal_at(
            now + AUDIT_APPEND_BREAKER_REFUSAL_LOG_EVERY - Duration::from_millis(1)
        ));
        assert!(breaker.should_log_refusal_at(now + AUDIT_APPEND_BREAKER_REFUSAL_LOG_EVERY));
    }
}
