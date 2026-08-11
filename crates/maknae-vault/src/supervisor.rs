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

/// The absolute wall-clock second at which the CURRENT leaf reaches its 2/3-TTL
/// rotation point, given `now_secs` and the leaf's age/TTL off its ACTUAL issued
/// validity window (`SupervisorCtx::leaf_age_and_ttl_secs`).
///
/// The threshold age is EXACTLY `rotate_now`'s boundary — the smallest age with
/// `age*3 >= ttl*2`, i.e. `ceil(2*ttl/3)` — so waking at this deadline and calling
/// `rotate_now` there agree (no off-by-one that would wake a second too early/late).
/// A `leaf_ttl_secs == 0` (no leaf minted yet, or an unknown window) yields
/// `u64::MAX` — "no leaf deadline", so only the token deadline governs the wake.
pub fn leaf_rotate_deadline(now_secs: u64, leaf_age_secs: u64, leaf_ttl_secs: u64) -> u64 {
    if leaf_ttl_secs == 0 {
        return u64::MAX;
    }
    // Smallest age satisfying rotate_now (age*3 >= ttl*2): ceil(ttl*2 / 3).
    let rotate_age = leaf_ttl_secs.saturating_mul(2).div_ceil(3);
    let secs_until = rotate_age.saturating_sub(leaf_age_secs);
    now_secs.saturating_add(secs_until)
}

/// The next wake instant (absolute wall-clock seconds): the EARLIER of the
/// token-renewal deadline and the leaf-rotation deadline, but never in the past
/// (clamped to `now_secs`, so the caller's `sleep(wake - now)` is non-negative and a
/// deadline already reached wakes immediately to act). Extracted as a pure decision so
/// the "sleep until the earlier of two deadlines" choice — the P1-C fix that stops a
/// leaf shorter than ⅓ of the token period from expiring unchecked — is exhaustively
/// boundary-tested independently of the T3 driver that consults it.
pub fn next_wake(now_secs: u64, token_deadline_secs: u64, leaf_deadline_secs: u64) -> u64 {
    token_deadline_secs.min(leaf_deadline_secs).max(now_secs)
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

    // ---- next_wake: the earlier of two deadlines, clamped to now (P1-C) ---------

    #[test]
    fn next_wake_token_sooner() {
        // token_deadline (100) < leaf_deadline (500) → wake at the token deadline.
        assert_eq!(next_wake(50, 100, 500), 100);
    }

    #[test]
    fn next_wake_leaf_sooner() {
        // leaf_deadline (120) < token_deadline (900) → wake at the leaf deadline.
        // This is the P1-C case: a short leaf under a long token period must wake
        // the loop BEFORE the token's ⅔ point so the leaf rotates before it expires.
        assert_eq!(next_wake(50, 900, 120), 120);
    }

    #[test]
    fn next_wake_equal_deadlines() {
        // Equal deadlines → that instant (min of equals; neither branch is favored).
        assert_eq!(next_wake(50, 300, 300), 300);
    }

    #[test]
    fn next_wake_clamps_a_past_deadline_to_now() {
        // The earlier deadline already elapsed (80 < now=100) → clamp to now so the
        // caller sleeps 0 and acts immediately, never computes a past (underflowing)
        // sleep. The OTHER deadline is still future.
        assert_eq!(next_wake(100, 80, 400), 100);
    }

    #[test]
    fn next_wake_both_past_clamps_to_now() {
        // Both deadlines behind now → wake now (act on whatever is due; forward
        // progress comes from acting, which advances the deadlines).
        assert_eq!(next_wake(100, 10, 20), 100);
    }

    #[test]
    fn next_wake_leaf_none_uses_token() {
        // leaf_deadline == u64::MAX ("no leaf") → the token deadline always wins.
        assert_eq!(next_wake(50, 300, u64::MAX), 300);
    }

    // ---- leaf_rotate_deadline: exact boundary, agrees with rotate_now -----------

    #[test]
    fn leaf_deadline_matches_rotate_now_boundary() {
        // ttl=300 → rotate_age = ceil(600/3) = 200 (rotate_now(200,300) is true).
        // At age 150 the deadline is now + (200-150) = now+50.
        assert_eq!(leaf_rotate_deadline(1_000, 150, 300), 1_050);
        // At exactly the rotate age, the deadline is now (secs_until == 0).
        assert_eq!(leaf_rotate_deadline(1_000, 200, 300), 1_000);
    }

    #[test]
    fn leaf_deadline_ceils_not_floors() {
        // ttl=97 → ttl*2 = 194; ceil(194/3) = 65 (a FLOOR would give 64 and wake a
        // second early, disagreeing with rotate_now(65,97)==true / rotate_now(64,97)==false).
        assert_eq!(leaf_rotate_deadline(0, 0, 97), 65);
        assert!(rotate_now(65, 97));
        assert!(!rotate_now(64, 97));
    }

    #[test]
    fn leaf_deadline_past_the_threshold_is_now() {
        // Age already beyond the 2/3 point → secs_until saturates to 0 → deadline == now.
        assert_eq!(leaf_rotate_deadline(500, 1_000_000, 300), 500);
    }

    #[test]
    fn leaf_deadline_zero_ttl_is_never() {
        // No leaf minted yet (ttl == 0) → u64::MAX so only the token deadline governs.
        assert_eq!(leaf_rotate_deadline(1_000, 0, 0), u64::MAX);
        assert_eq!(leaf_rotate_deadline(1_000, 5, 0), u64::MAX);
    }
}
