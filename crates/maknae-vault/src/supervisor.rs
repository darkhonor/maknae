//! Credential supervisor decisions (spec §7, ADR-0018 Decision 3). Pure T1 — no I/O,
//! no Vault, no locks. The driver (`supervisor_run.rs`, T3) consults these to decide
//! whether to retry a failed token renewal within the token's remaining validity
//! window (rather than failing closed on the first transient error) and when to
//! rotate the plane leaf ahead of its TTL.
use std::time::Duration;

/// What the renewal-retry loop should do next.
#[derive(Debug, PartialEq, Eq)]
pub enum RetryAction {
    /// Back off this long, then retry — the token is still renewable within its
    /// remaining validity window.
    Wait(Duration),
    /// Retry immediately (no backoff). Part of the decision contract (the driver in
    /// `supervisor_run.rs` matches it exhaustively); the current `retry_action`
    /// formula never returns it — reserved for a future zero-backoff policy.
    #[allow(dead_code, reason = "reserved decision output, not yet produced")]
    RetryNow,
    /// The retry budget is exhausted — clear the identity (fail closed).
    FailClosed,
}

/// Decide the next renewal-retry step after a failed `renew_self`.
///
/// - `remaining_secs`: the token's actual remaining validity (time left before it
///   would expire outright if no renewal succeeds).
/// - `elapsed_in_window`: time already spent retrying in the current failure window.
/// - `attempt`: 1-based count of consecutive failures in the current window.
///
/// Backs off exponentially (capped at 30s) but ONLY while there is enough headroom
/// left to complete one more renewal attempt before the token actually expires —
/// once the remaining validity would not survive the next backoff-plus-attempt, fail
/// closed rather than risk retrying past expiry.
pub fn retry_action(remaining_secs: u64, elapsed_in_window: u64, attempt: u32) -> RetryAction {
    // Need headroom to complete a renewal before expiry; back off but never past the window.
    let backoff = (2u64.saturating_pow(attempt.min(6))).min(30);
    if remaining_secs <= backoff.saturating_add(2) {
        return RetryAction::FailClosed;
    }
    let _ = elapsed_in_window;
    RetryAction::Wait(Duration::from_secs(backoff))
}

/// Rotate once the leaf has used ≥ 2/3 of its TTL.
pub fn rotate_now(leaf_age_secs: u64, leaf_ttl_secs: u64) -> bool {
    leaf_ttl_secs > 0 && leaf_age_secs.saturating_mul(3) >= leaf_ttl_secs.saturating_mul(2)
}

#[cfg(test)]
mod tests {
    use super::*;

    // ---- retry_action: the brief's baseline cases -----------------------------

    #[test]
    fn retries_within_window() {
        // window remains, first failure → wait/retry, not fail-closed
        assert!(!matches!(retry_action(600, 10, 1), RetryAction::FailClosed));
    }

    #[test]
    fn fails_closed_when_window_exhausted() {
        assert!(matches!(retry_action(2, 5, 4), RetryAction::FailClosed));
    }

    // ---- retry_action: exact backoff/Wait payload, every attempt 1..=8 --------
    // Pins the FULL formula (base, cap, attempt-clamp) so a mutant touching any
    // constant changes an assertion, not just the Wait-vs-FailClosed branch.

    #[test]
    fn backoff_doubles_and_caps_at_30() {
        let cases: [(u32, u64); 8] = [
            (1, 2),
            (2, 4),
            (3, 8),
            (4, 16),
            (5, 30), // 2^5=32, capped to 30
            (6, 30), // 2^6=64, capped to 30
            (7, 30), // attempt.min(6) — 7 behaves like 6
            (8, 30),
        ];
        for (attempt, want_backoff) in cases {
            // remaining well above the fail-closed threshold for every case above.
            assert_eq!(
                retry_action(1_000, 0, attempt),
                RetryAction::Wait(Duration::from_secs(want_backoff)),
                "attempt {attempt}"
            );
        }
    }

    #[test]
    fn attempt_zero_backs_off_one_second() {
        // 2^0 = 1 — the driver's first call is always attempt=1, but the function
        // itself must not special-case 0 differently from the formula.
        assert_eq!(
            retry_action(1_000, 0, 0),
            RetryAction::Wait(Duration::from_secs(1))
        );
    }

    // ---- retry_action: the FailClosed boundary is EXACTLY remaining <= backoff+2

    #[test]
    fn fail_closed_boundary_is_inclusive_at_backoff_plus_two() {
        // attempt=1 -> backoff=2 -> boundary constant = 4.
        assert_eq!(retry_action(4, 0, 1), RetryAction::FailClosed); // == boundary
        assert_eq!(
            retry_action(5, 0, 1),
            RetryAction::Wait(Duration::from_secs(2))
        ); // one above boundary -> still retries
        assert_eq!(retry_action(3, 0, 1), RetryAction::FailClosed); // one below
    }

    #[test]
    fn fail_closed_boundary_tracks_backoff_at_a_different_attempt() {
        // attempt=4 -> backoff=16 -> boundary constant = 18 (asymmetric from the
        // attempt=1 case above — kills a mutant that hardcodes the attempt=1 bound).
        assert_eq!(retry_action(18, 0, 4), RetryAction::FailClosed); // == boundary
        assert_eq!(
            retry_action(19, 0, 4),
            RetryAction::Wait(Duration::from_secs(16))
        );
        assert_eq!(retry_action(17, 0, 4), RetryAction::FailClosed);
    }

    #[test]
    fn zero_remaining_always_fails_closed() {
        assert_eq!(retry_action(0, 0, 1), RetryAction::FailClosed);
    }

    // ---- rotate_now: the brief's baseline cases --------------------------------

    #[test]
    fn rotate_at_two_thirds_ttl() {
        assert!(!rotate_now(1000, 259200)); // ~0.4% of 72h → no
        assert!(rotate_now(48 * 3600, 72 * 3600)); // ⅔ of 72h → yes
    }

    // ---- rotate_now: exact boundary, asymmetric values (age*3 == ttl*2) -------

    #[test]
    fn rotate_boundary_is_inclusive() {
        // ttl=300 -> 2/3 boundary age=200 exactly (300*2=600, 200*3=600).
        assert!(rotate_now(200, 300));
        assert!(!rotate_now(199, 300)); // one second short of 2/3 -> no
    }

    #[test]
    fn rotate_boundary_asymmetric_ttl() {
        // A DIFFERENT ttl than the 72h/300s cases above, so a mutant that hardcodes
        // one boundary's numbers can't slip through. ttl=97 -> 2*97=194; age=65 ->
        // 3*65=195 >= 194 (yes); age=64 -> 3*64=192 < 194 (no).
        assert!(rotate_now(65, 97));
        assert!(!rotate_now(64, 97));
    }

    #[test]
    fn rotate_now_false_at_zero_age() {
        assert!(!rotate_now(0, 259200));
    }

    #[test]
    fn rotate_now_false_when_ttl_is_zero() {
        // Guards the `leaf_ttl_secs > 0` clause — without it, 0 >= 0 would be true.
        assert!(!rotate_now(0, 0));
        assert!(!rotate_now(100, 0));
    }

    #[test]
    fn rotate_now_true_well_past_ttl() {
        assert!(rotate_now(1_000_000, 259200));
    }
}
