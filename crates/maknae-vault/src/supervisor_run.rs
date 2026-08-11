//! Credential supervisor driver (T3, ADR-0018 Decision 3). The scheduling decisions —
//! `retry_action` (renewal-retry-within-window), `rotate_now`/`leaf_rotate_deadline`
//! (leaf rotation), `next_wake` (earliest-deadline sleep) and `retry_deadline`
//! (RetryAction → next single-attempt deadline) — live in `supervisor.rs` (T1, pure,
//! mutation-tested to 0-missed); this module is the I/O loop that consults them and
//! calls back into `PlaneClient`/`SupervisorCtx` for the actual Vault work. Excluded
//! from mutation testing (`.cargo/mutants.toml`) — it is a driver, not a decision; the
//! decisions it drives ARE mutation-tested.
//!
//! **Token renewal and leaf rotation are INDEPENDENTLY scheduled, single-attempt-per-
//! wake, on one shared loop (codex round-4 P1).** On each wake the loop attempts at
//! most ONE `rotate_leaf` (if its deadline is due) and at most ONE `renew_token_once`
//! (if ITS deadline is due). Neither operation retries inline; a failure just re-arms
//! that operation's own deadline (via `retry_deadline`) to a sooner wake, and
//! `next_wake` mins over both. So a persistently-failing rotation can NEVER block a due
//! token renewal from being attempted — the self-inflicted outage ADR-0018's periodic-
//! token design exists to avoid. Fail-closed (`expire_now`) still fires when a deadline
//! genuinely cannot be met (token unrenewable before expiry, or leaf un-rotatable
//! before expiry).
use crate::client::{PlaneClient, SupervisorCtx};
use crate::error::VaultError;
use crate::supervisor::{
    leaf_rotate_deadline, next_wake, retry_action, retry_deadline, rotate_now,
};
use std::time::Duration;
use tokio::time::Instant;

/// Renew at ~2/3 of the token's ACTUAL lease — always STRICTLY below the lease so even
/// a sub-60s TTL renews before it expires (`.max(1)` guarantees forward progress on a
/// tiny lease). Pulled out so the outer loop and the deadline recompute after a renewal
/// use the identical cadence.
fn token_renew_after(lease_secs: u64) -> u64 {
    (lease_secs * 2 / 3).max(1)
}

impl PlaneClient {
    /// Spawn the background credential-supervisor loop on a SHARED handle (not
    /// `&mut self`, so serving, renewal, and rotation all proceed concurrently).
    /// **MUST be called after a successful `mint()`** — there is no token to renew
    /// before minting; a zero lease fails closed immediately rather than guessing an
    /// interval (mirrors the removed `spawn_renewal`, which this replaces).
    ///
    /// Two INDEPENDENTLY-scheduled responsibilities, both driven by the T1 pure
    /// decisions in `supervisor.rs` (ADR-0018 Decision 3), each attempted at most ONCE
    /// per wake so neither can starve the other:
    ///
    /// - **Token renewal.** When its own deadline (~2/3 of the current lease) is due,
    ///   attempt `renew_self` ONCE. On success the lease + next deadline recompute from
    ///   the fresh lease; on a transient failure `retry_action` → `retry_deadline`
    ///   re-arms the renewal deadline to a sooner wake (identity left intact — a Vault
    ///   blip is absorbed); `FailClosed` (the token's remaining validity is exhausted)
    ///   expires. Renewal is attempted WHENEVER its deadline is due, regardless of
    ///   rotation state.
    /// - **Leaf rotation.** Independently tracks leaf age off the ACTUAL issued
    ///   validity window (`SupervisorCtx::leaf_age_and_ttl_secs`); once
    ///   `leaf_rotate_deadline` is due, attempt `rotate_leaf()` ONCE on the still-valid
    ///   token. A rotation failure does NOT loop inline: `retry_action` →
    ///   `retry_deadline` re-arms the rotation deadline to a sooner wake and control
    ///   returns to the loop (so a due renewal is still attempted); sustained failure
    ///   past the leaf's own remaining validity fails closed.
    ///
    /// The handle resolves to `RenewalExpired` when either loop gives up; at that
    /// point the shared identity is CLEARED (`SupervisorCtx::expire_now`) so
    /// `current_identity()` returns `None` (fail closed) whether or not the caller
    /// observes the handle.
    pub fn spawn_supervisor(&self) -> tokio::task::JoinHandle<VaultError> {
        let ctx = self.supervisor_ctx();
        tokio::spawn(async move { supervisor_loop(ctx).await })
    }
}

/// Seam so the FULL supervisor loop (both token renewal AND leaf rotation) is
/// unit-testable without a live Vault. `SupervisorCtx` (Vault-backed) is the real
/// implementation used by `spawn_supervisor`; tests substitute a fake that tracks call
/// counts instead of talking to Vault — letting a test drive a persistently-failing
/// rotation and assert a due token renewal is STILL attempted on its own deadline.
trait SupervisorDriver {
    /// The last-known token lease (seconds); 0 before the first mint.
    fn current_lease_secs(&self) -> u64;
    /// `(leaf_age_secs, leaf_ttl_secs)` off the current leaf's ACTUAL issued
    /// validity window — `rotate_now`/`leaf_rotate_deadline`'s inputs.
    fn leaf_age_and_ttl_secs(&self) -> (u64, u64);
    /// One token-renewal attempt on the current token; returns the fresh lease.
    async fn renew_token_once(&self) -> Result<u64, VaultError>;
    /// Re-mint the leaf on the current token.
    async fn rotate_leaf(&self) -> Result<(), VaultError>;
    /// Fail-closed retirement (clears the shared identity).
    fn expire_now(&self) -> VaultError;
}

impl SupervisorDriver for SupervisorCtx {
    fn current_lease_secs(&self) -> u64 {
        SupervisorCtx::current_lease_secs(self)
    }
    fn leaf_age_and_ttl_secs(&self) -> (u64, u64) {
        SupervisorCtx::leaf_age_and_ttl_secs(self)
    }
    async fn renew_token_once(&self) -> Result<u64, VaultError> {
        SupervisorCtx::renew_token_once(self).await
    }
    async fn rotate_leaf(&self) -> Result<(), VaultError> {
        SupervisorCtx::rotate_leaf(self).await
    }
    fn expire_now(&self) -> VaultError {
        SupervisorCtx::expire_now(self)
    }
}

/// The loop body, split out from `spawn_supervisor` so it's a plain `async fn` (no
/// `tokio::spawn` boilerplate) and GENERIC over the [`SupervisorDriver`] seam, so tests
/// drive the whole loop against a fake (no live Vault).
///
/// Token renewal and leaf rotation are INDEPENDENTLY scheduled, single-attempt-per-wake
/// (codex round-4 P1). Each holds its own absolute wall-clock deadline; a failed single
/// attempt re-arms only THAT operation's deadline (via `retry_deadline`) to a sooner
/// wake — it never loops inline, so the other operation's due attempt is never blocked.
/// `next_wake` sleeps until the earliest of the two deadlines (each already folding in
/// any pending retry-backoff deadline).
async fn supervisor_loop<D: SupervisorDriver>(ctx: D) -> VaultError {
    // Fail closed if spawned before mint() — no token to renew, and we must never
    // guess an interval that could outlast a short lease.
    let mut lease = ctx.current_lease_secs();
    if lease == 0 {
        return ctx.expire_now();
    }
    // The scheduling clock is a MONOTONIC `tokio::time::Instant` (not wall-clock): it
    // advances at the same rate as `tokio::time::sleep` — the two agree in production
    // AND under `#[tokio::test(start_paused)]` (where sleeps auto-advance virtual time)
    // — and it is immune to wall-clock steps (NTP/leap-second) that could otherwise jump
    // a deadline. `now()` is whole seconds since loop start; every deadline below is in
    // that same "seconds since start" base. The leaf's age/ttl are RELATIVE durations
    // (`leaf_age_and_ttl_secs`), so mixing them with this relative clock is sound.
    let clock = Instant::now();
    let now = || clock.elapsed().as_secs();

    // Token-renewal schedule, in seconds-since-start:
    // - `token_deadline`  : when to attempt the next renewal (~2/3 of the lease; on a
    //   transient failure re-armed sooner by `retry_deadline`).
    // - `token_expires_at`: the token's hard expiry — the retry budget `retry_action`
    //   reasons about (recomputed from each successful renewal's fresh lease, which
    //   Vault may shorten near token_max_ttl).
    let mut token_deadline = now().saturating_add(token_renew_after(lease));
    let mut token_expires_at = now().saturating_add(lease);
    let mut token_attempt: u32 = 0;
    // Leaf-rotation schedule: `leaf_backoff_until` is `Some` only while backing off a
    // failed rotation (so the loop waits the backoff instead of busy-retrying an
    // already-past natural rotation deadline); otherwise the natural
    // `leaf_rotate_deadline` (constant until a rotation issues a fresh leaf) governs.
    let mut leaf_backoff_until: Option<u64> = None;
    let mut leaf_attempt: u32 = 0;

    loop {
        // Wake at the EARLIER of the token-renewal deadline and the leaf-rotation
        // deadline (each already folding in any pending retry-backoff). A leaf shorter
        // than ~1/3 of the token period would otherwise expire during a single 2/3-of-
        // token sleep (P1-C); an independent retry-backoff deadline likewise pulls the
        // wake sooner without blocking the other operation (P1 round-4).
        let t = now();
        let (leaf_age, leaf_ttl) = ctx.leaf_age_and_ttl_secs();
        // The leaf's effective wake deadline: while backing off a failed rotation, that
        // backoff deadline; otherwise the natural 2/3-TTL rotation point.
        let leaf_deadline =
            leaf_backoff_until.unwrap_or_else(|| leaf_rotate_deadline(t, leaf_age, leaf_ttl));
        let wake = next_wake(t, token_deadline, leaf_deadline);
        tokio::time::sleep(Duration::from_secs(wake.saturating_sub(t))).await;

        // --- Leaf rotation: at most ONE attempt when it is due. --------------------
        // Due = rotation is warranted (`rotate_now`, the mutation-tested T1 decision)
        // AND we are past any retry-backoff. Gating on both means waking early for the
        // TOKEN (while a rotation backoff is still pending) does NOT trigger a premature
        // rotation. A failure re-arms `leaf_backoff_until` and returns to the loop — it
        // does NOT retry inline, so a due token renewal below is still attempted.
        let (leaf_age, leaf_ttl) = ctx.leaf_age_and_ttl_secs();
        let backoff_elapsed = leaf_backoff_until.is_none_or(|d| now() >= d);
        if backoff_elapsed && rotate_now(leaf_age, leaf_ttl) {
            match ctx.rotate_leaf().await {
                Ok(()) => {
                    // Fresh leaf: clear any backoff and let the natural deadline (far in
                    // the future now) govern again.
                    leaf_backoff_until = None;
                    leaf_attempt = 0;
                }
                Err(_) => {
                    leaf_attempt += 1;
                    // Budget = the leaf's own remaining validity (ttl - age), recomputed
                    // from the live clock so it shrinks as real time passes.
                    let (age_now, ttl_now) = ctx.leaf_age_and_ttl_secs();
                    let remaining = ttl_now.saturating_sub(age_now);
                    match retry_deadline(now(), &retry_action(remaining, 0, leaf_attempt)) {
                        Some(d) => leaf_backoff_until = Some(d),
                        // Leaf genuinely un-rotatable before it expires → fail closed.
                        None => return ctx.expire_now(),
                    }
                }
            }
        }

        // --- Token renewal: at most ONE attempt when ITS deadline is due. ----------
        // Attempted whenever `token_deadline` is due, INDEPENDENT of the rotation
        // outcome above — a failing rotation can never starve renewal (the ADR-0018
        // self-inflicted-outage this fix removes).
        if now() >= token_deadline {
            match ctx.renew_token_once().await {
                // A "successful" renewal with a ZERO lease means Vault has nothing left
                // to give (token at max_ttl / no remaining lease) — treat it exactly
                // like the fail-closed cases below, NOT like a real renewal: retaining
                // the identity and scheduling a retry would keep the daemon serving on
                // an effectively-expired token (mirrors the initial-zero-lease check at
                // the top of this function).
                Ok(0) => return ctx.expire_now(),
                Ok(new_lease) => {
                    lease = new_lease;
                    token_attempt = 0;
                    let n = now();
                    token_deadline = n.saturating_add(token_renew_after(lease));
                    token_expires_at = n.saturating_add(lease);
                }
                Err(_) => {
                    token_attempt += 1;
                    // Budget = the token's remaining validity before its hard expiry.
                    let remaining = token_expires_at.saturating_sub(now());
                    match retry_deadline(now(), &retry_action(remaining, 0, token_attempt)) {
                        Some(d) => token_deadline = d,
                        // Token unrenewable before expiry → fail closed.
                        None => return ctx.expire_now(),
                    }
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};
    use std::sync::Arc;

    /// Shared, `Arc`-backed observable state for [`FakeDriver`] — cloned out before the
    /// driver is moved into `supervisor_loop`, so a test can inspect call counts and the
    /// `expired` flag after the loop returns. No Vault, no locks.
    ///
    /// - `renew_ok_budget`: `renew_token_once` returns `Ok(lease)` for the first N calls,
    ///   then `Err` forever (drives the token toward its own FailClosed).
    /// - `renew_zero_lease`: when `true`, a within-budget `renew_token_once` success
    ///   returns `Ok(0)` instead of `Ok(current lease)` — simulates Vault answering
    ///   `renew-self` successfully but with `lease_duration == 0` (codex round-6 P1).
    /// - `rotate_fail_first`: `rotate_leaf` fails for the first N calls, then succeeds; a
    ///   successful rotation resets `leaf_age` to 0 (a FRESH leaf, so the natural rotation
    ///   deadline moves far out — matching a real re-mint and avoiding a busy-loop).
    /// - `leaf_age`/`leaf_ttl`: fixed inputs whose `rotate_now`/`retry_action` outcome does
    ///   not depend on wall-clock elapsed time.
    #[derive(Clone)]
    struct Shared {
        lease: Arc<AtomicU64>,
        leaf_age: Arc<AtomicU64>,
        leaf_ttl: Arc<AtomicU64>,
        renew_calls: Arc<AtomicU32>,
        rotate_calls: Arc<AtomicU32>,
        renew_ok_budget: Arc<AtomicU32>,
        renew_zero_lease: Arc<AtomicBool>,
        rotate_fail_first: Arc<AtomicU32>,
        expired: Arc<AtomicBool>,
    }

    impl Shared {
        fn new(lease: u64, leaf_age: u64, leaf_ttl: u64) -> Self {
            Self {
                lease: Arc::new(AtomicU64::new(lease)),
                leaf_age: Arc::new(AtomicU64::new(leaf_age)),
                leaf_ttl: Arc::new(AtomicU64::new(leaf_ttl)),
                renew_calls: Arc::new(AtomicU32::new(0)),
                rotate_calls: Arc::new(AtomicU32::new(0)),
                renew_ok_budget: Arc::new(AtomicU32::new(u32::MAX)),
                renew_zero_lease: Arc::new(AtomicBool::new(false)),
                rotate_fail_first: Arc::new(AtomicU32::new(0)),
                expired: Arc::new(AtomicBool::new(false)),
            }
        }
    }

    struct FakeDriver(Shared);

    impl SupervisorDriver for FakeDriver {
        fn current_lease_secs(&self) -> u64 {
            self.0.lease.load(Ordering::Relaxed)
        }
        fn leaf_age_and_ttl_secs(&self) -> (u64, u64) {
            (
                self.0.leaf_age.load(Ordering::Relaxed),
                self.0.leaf_ttl.load(Ordering::Relaxed),
            )
        }
        async fn renew_token_once(&self) -> Result<u64, VaultError> {
            let n = self.0.renew_calls.fetch_add(1, Ordering::Relaxed) + 1;
            if n <= self.0.renew_ok_budget.load(Ordering::Relaxed) {
                if self.0.renew_zero_lease.load(Ordering::Relaxed) {
                    Ok(0)
                } else {
                    Ok(self.0.lease.load(Ordering::Relaxed))
                }
            } else {
                Err(VaultError::Renew("fake renew failure".into()))
            }
        }
        async fn rotate_leaf(&self) -> Result<(), VaultError> {
            let n = self.0.rotate_calls.fetch_add(1, Ordering::Relaxed) + 1;
            if n <= self.0.rotate_fail_first.load(Ordering::Relaxed) {
                Err(VaultError::Sign("fake rotate_leaf failure".into()))
            } else {
                // A fresh leaf: age resets, so the natural rotation deadline moves far
                // out (no busy-loop of instantly-due rotations).
                self.0.leaf_age.store(0, Ordering::Relaxed);
                Ok(())
            }
        }
        fn expire_now(&self) -> VaultError {
            self.0.expired.store(true, Ordering::Relaxed);
            VaultError::RenewalExpired
        }
    }

    #[tokio::test(start_paused = true)]
    async fn spawn_before_mint_fails_closed() {
        // Lease 0 (spawned before mint()) → expire immediately, no renew/rotate attempts.
        let shared = Shared::new(0, 48 * 3600, 72 * 3600);
        let probe = shared.clone();
        let err = supervisor_loop(FakeDriver(shared)).await;
        assert!(matches!(err, VaultError::RenewalExpired));
        assert!(probe.expired.load(Ordering::Relaxed));
        assert_eq!(probe.renew_calls.load(Ordering::Relaxed), 0);
        assert_eq!(probe.rotate_calls.load(Ordering::Relaxed), 0);
    }

    /// THE codex round-4 P1 property: a persistently-failing leaf rotation must NOT
    /// starve a due token renewal. The rotator fails EVERY call; renewal succeeds once
    /// then fails (so the loop still terminates via the token's own FailClosed). We
    /// assert renewal was attempted MULTIPLE times on its own deadline while rotation
    /// kept failing — proving the two schedules are independent (no self-inflicted
    /// outage). `start_paused` auto-advances virtual time so this runs instantly.
    #[tokio::test(start_paused = true)]
    async fn failing_rotation_does_not_starve_token_renewal() {
        // lease 100 → renew at ~66s, hard expiry ~100s. Leaf at 2/3 of a 72h TTL: ample
        // remaining validity, so rotation NEVER self-FailCloses — it just keeps failing
        // and backing off, which must not block the token's renewal deadline.
        let shared = Shared::new(100, 48 * 3600, 72 * 3600);
        shared.rotate_fail_first.store(u32::MAX, Ordering::Relaxed); // rotation always fails
        shared.renew_ok_budget.store(1, Ordering::Relaxed); // 1 renew Ok, then fail → token FailClosed
        let probe = shared.clone();

        let err = supervisor_loop(FakeDriver(shared)).await;
        assert!(matches!(err, VaultError::RenewalExpired));
        // The loop ended via the TOKEN's fail-closed (its budget), not the leaf's.
        assert!(probe.expired.load(Ordering::Relaxed));
        // Renewal was attempted on its own deadline (>= 2: the first Ok + at least one
        // retry) DESPITE rotation failing every single wake — the anti-starvation proof.
        assert!(
            probe.renew_calls.load(Ordering::Relaxed) >= 2,
            "token renewal must be attempted on its own deadline even while rotation fails (got {})",
            probe.renew_calls.load(Ordering::Relaxed)
        );
        // And rotation really was failing repeatedly in the same window.
        assert!(
            probe.rotate_calls.load(Ordering::Relaxed) >= 2,
            "the rotation was expected to fail repeatedly (got {})",
            probe.rotate_calls.load(Ordering::Relaxed)
        );
    }

    #[tokio::test(start_paused = true)]
    async fn sustained_rotation_failure_fails_closed_independently() {
        // Leaf with only 5s remaining validity (age 95 / ttl 100) → rotate_now fires and
        // the retry budget is exhausted within a couple of attempts → leaf fail-closed,
        // WITHOUT the token ever coming due (huge lease). Proves leaf rotation fails
        // closed on its own schedule.
        let shared = Shared::new(1_000_000, 95, 100);
        shared.rotate_fail_first.store(u32::MAX, Ordering::Relaxed);
        let probe = shared.clone();

        let err = supervisor_loop(FakeDriver(shared)).await;
        assert!(matches!(err, VaultError::RenewalExpired));
        assert!(probe.expired.load(Ordering::Relaxed));
        assert!(probe.rotate_calls.load(Ordering::Relaxed) >= 1);
        assert_eq!(
            probe.renew_calls.load(Ordering::Relaxed),
            0,
            "the token was never due — its renewal must not have been attempted"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn healthy_rotation_succeeds_then_token_governs() {
        // Rotation succeeds on the FIRST attempt (fresh leaf → far-future rotation
        // deadline); the loop then terminates via the token's own fail-closed (renewal
        // fails on the first attempt, short lease). Exercises the rotate_leaf Ok path and
        // proves a successful rotation clears its schedule (rotate_leaf called exactly
        // once, not busy-looped).
        let shared = Shared::new(6, 48 * 3600, 72 * 3600);
        shared.rotate_fail_first.store(0, Ordering::Relaxed); // succeeds immediately
        shared.renew_ok_budget.store(0, Ordering::Relaxed); // renewal always fails → token FailClosed
        let probe = shared.clone();

        let err = supervisor_loop(FakeDriver(shared)).await;
        assert!(matches!(err, VaultError::RenewalExpired));
        assert!(probe.expired.load(Ordering::Relaxed));
        assert_eq!(
            probe.rotate_calls.load(Ordering::Relaxed),
            1,
            "a successful rotation must not be retried or busy-looped"
        );
        assert!(probe.renew_calls.load(Ordering::Relaxed) >= 1);
    }

    /// Codex round-6 P1: a `renew_self` that "succeeds" but reports
    /// `lease_duration == 0` (token at max_ttl / no remaining lease) must fail closed
    /// exactly like the initial-zero-lease case at loop start — NOT be treated as a
    /// real renewal that leaves the identity installed and schedules a retry ~1s
    /// later. Rotation is given an effectively-infinite TTL so it never fires,
    /// isolating the renewal path.
    #[tokio::test(start_paused = true)]
    async fn zero_lease_renewal_fails_closed() {
        let shared = Shared::new(6, 0, u64::MAX);
        shared.renew_zero_lease.store(true, Ordering::Relaxed);
        let probe = shared.clone();

        let err = supervisor_loop(FakeDriver(shared)).await;
        assert!(matches!(err, VaultError::RenewalExpired));
        assert!(
            probe.expired.load(Ordering::Relaxed),
            "a zero-lease renewal must clear the identity (fail closed)"
        );
        assert_eq!(
            probe.renew_calls.load(Ordering::Relaxed),
            1,
            "the loop must expire on the FIRST zero-lease renewal, not retain the \
             identity and schedule another attempt"
        );
        assert_eq!(
            probe.rotate_calls.load(Ordering::Relaxed),
            0,
            "rotation must never have been due in this scenario"
        );
    }
}
