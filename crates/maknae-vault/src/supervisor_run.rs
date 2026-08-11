//! Credential supervisor driver (T3, ADR-0018 Decision 3). The two decisions —
//! `retry_action` (renewal-retry-within-window) and `rotate_now` (leaf rotation) —
//! live in `supervisor.rs` (T1, pure, mutation-tested to 0-missed); this module is
//! the I/O loop that consults them and calls back into `PlaneClient`/`SupervisorCtx`
//! for the actual Vault work. Excluded from mutation testing (`.cargo/mutants.toml`)
//! — it is a driver, not a decision; the decisions it drives ARE mutation-tested.
use crate::client::{PlaneClient, SupervisorCtx};
use crate::error::VaultError;
use crate::supervisor::{leaf_rotate_deadline, next_wake, retry_action, rotate_now, RetryAction};
use std::time::{Duration, Instant};

/// Current wall-clock time as unix seconds — the common base for the token-renewal
/// and leaf-rotation deadlines (`leaf_age_and_ttl_secs` already reads `SystemTime`).
/// A clock read failure (pre-epoch) saturates to 0, which only ever makes a deadline
/// look sooner → wake earlier → act, never later (fail-safe).
fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

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
    /// Two independent responsibilities, both driven by the T1 pure decisions in
    /// `supervisor.rs` (ADR-0018 Decision 3):
    ///
    /// - **Renewal-retry-within-window.** A failed `renew_self` no longer clears the
    ///   identity on the FIRST error. It consults
    ///   `retry_action(remaining, elapsed, attempt)`: `Wait(d)` backs off and retries
    ///   — the identity is left alone, so a transient Vault blip is absorbed;
    ///   `FailClosed` fires only once the token's actual remaining validity (tracked
    ///   as a real deadline, not a static estimate — backoff sleeps correctly shrink
    ///   the budget) is exhausted.
    /// - **Leaf rotation.** Independently tracks leaf age off the ACTUAL issued
    ///   validity window (`SupervisorCtx::leaf_age_and_ttl_secs`); once `rotate_now`
    ///   fires, `rotate_leaf()` re-signs on the still-valid token. A rotation failure
    ///   retries within the SAME retry-window discipline as token renewal (budgeted
    ///   against the leaf's own remaining validity); sustained failure also fails
    ///   closed.
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

/// The loop body, split out from `spawn_supervisor` so it's a plain `async fn` (no
/// `tokio::spawn` boilerplate) — easier to reason about and, if ever needed, to test
/// directly against a fake `SupervisorCtx` seam.
async fn supervisor_loop(ctx: SupervisorCtx) -> VaultError {
    // Fail closed if spawned before mint() — no token to renew, and we must never
    // guess an interval that could outlast a short lease.
    let mut lease = ctx.current_lease_secs();
    if lease == 0 {
        return ctx.expire_now();
    }
    // The token-renewal deadline as an ABSOLUTE wall-clock second (~2/3 of the current
    // lease from now). Recomputed after every successful renewal from that renewal's
    // fresh lease (Vault may shorten it near token_max_ttl).
    let mut token_deadline = now_secs().saturating_add(token_renew_after(lease));

    loop {
        // Wake at the EARLIER of the token-renewal deadline and the leaf-rotation
        // deadline (P1-C): a leaf shorter than ~1/3 of the token period would otherwise
        // expire during a single 2/3-of-token sleep, silently breaking TLS handshakes.
        // Both deadlines share the wall-clock base `leaf_age_and_ttl_secs` already uses.
        let now = now_secs();
        let (leaf_age, leaf_ttl) = ctx.leaf_age_and_ttl_secs();
        let leaf_deadline = leaf_rotate_deadline(now, leaf_age, leaf_ttl);
        let wake = next_wake(now, token_deadline, leaf_deadline);
        tokio::time::sleep(Duration::from_secs(wake.saturating_sub(now))).await;

        // On wake, perform whichever action(s) are now due. Leaf rotation first
        // (maybe_rotate_leaf is a no-op when rotate_now is false, i.e. we woke for the
        // token); its own retry-within-window discipline is unchanged.
        if let Err(e) = maybe_rotate_leaf(&ctx).await {
            return e;
        }

        // Token renewal ONLY once its own deadline has arrived — waking early for the
        // leaf must not burn a renewal cycle. When due, renew within the token's
        // remaining validity window, then recompute the next deadline from the fresh
        // lease. Sustained renewal failure fails closed.
        if now_secs() >= token_deadline {
            match renew_token_with_retry(&ctx, lease).await {
                Ok(new_lease) => {
                    lease = new_lease;
                    token_deadline = now_secs().saturating_add(token_renew_after(lease));
                }
                Err(e) => return e,
            }
        }
    }
}

/// Renew the token, retrying transient failures within the token's remaining validity
/// window (~1/3 of the lease at the ⅔ renewal point) — a blip is absorbed rather than
/// clearing the identity on the first error; sustained failure fails closed. Returns
/// the fresh lease so the caller recomputes the next renewal deadline from it.
///
/// The retry budget is a real monotonic `Instant` deadline (not a static estimate) so
/// backoff sleeps correctly shrink the budget `retry_action` reasons about.
async fn renew_token_with_retry(ctx: &SupervisorCtx, lease: u64) -> Result<u64, VaultError> {
    let remaining = lease.saturating_sub(token_renew_after(lease));
    let deadline = Instant::now() + Duration::from_secs(remaining);
    let retry_started = Instant::now();
    let mut attempt: u32 = 0;
    loop {
        match ctx.renew_token_once().await {
            Ok(new_lease) => return Ok(new_lease),
            Err(_) => {
                attempt += 1;
                let remaining = deadline.saturating_duration_since(Instant::now()).as_secs();
                let elapsed = retry_started.elapsed().as_secs();
                match retry_action(remaining, elapsed, attempt) {
                    RetryAction::Wait(d) => tokio::time::sleep(d).await,
                    RetryAction::RetryNow => {}
                    RetryAction::FailClosed => return Err(ctx.expire_now()),
                }
            }
        }
    }
}

/// Seam so "the decision loop calls `rotate_leaf` when `rotate_now` fires" is
/// unit-testable without a live Vault. `SupervisorCtx` (Vault-backed) is the real
/// implementation used by `spawn_supervisor`; tests substitute a fake that tracks
/// call counts instead of talking to Vault.
trait LeafRotator {
    /// `(leaf_age_secs, leaf_ttl_secs)` off the current leaf's ACTUAL issued
    /// validity window — `rotate_now`'s two inputs.
    fn leaf_age_and_ttl_secs(&self) -> (u64, u64);
    /// Re-mint the leaf on the current token.
    async fn rotate_leaf(&self) -> Result<(), VaultError>;
    /// Fail-closed retirement (clears the shared identity).
    fn expire_now(&self) -> VaultError;
}

impl LeafRotator for SupervisorCtx {
    fn leaf_age_and_ttl_secs(&self) -> (u64, u64) {
        SupervisorCtx::leaf_age_and_ttl_secs(self)
    }
    async fn rotate_leaf(&self) -> Result<(), VaultError> {
        SupervisorCtx::rotate_leaf(self).await
    }
    fn expire_now(&self) -> VaultError {
        SupervisorCtx::expire_now(self)
    }
}

/// Rotate the leaf if `rotate_now` fires, retrying rotation failures within the SAME
/// retry-window discipline as token renewal (budgeted against the leaf's own
/// remaining validity, recomputed each attempt); sustained failure fails closed.
async fn maybe_rotate_leaf<R: LeafRotator>(ctx: &R) -> Result<(), VaultError> {
    let (age, ttl) = ctx.leaf_age_and_ttl_secs();
    if !rotate_now(age, ttl) {
        return Ok(());
    }
    let retry_started = Instant::now();
    let mut attempt: u32 = 0;
    loop {
        match ctx.rotate_leaf().await {
            Ok(()) => return Ok(()),
            Err(_) => {
                attempt += 1;
                // Recompute from the live clock each attempt — the leaf's remaining
                // validity (ttl - age) is the retry budget, shrinking as real time
                // (including backoff sleeps) passes.
                let (age_now, ttl_now) = ctx.leaf_age_and_ttl_secs();
                let remaining = ttl_now.saturating_sub(age_now);
                let elapsed = retry_started.elapsed().as_secs();
                match retry_action(remaining, elapsed, attempt) {
                    RetryAction::Wait(d) => tokio::time::sleep(d).await,
                    RetryAction::RetryNow => {}
                    RetryAction::FailClosed => return Err(ctx.expire_now()),
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};

    /// A `LeafRotator` fake — no Vault, no locks. `age`/`ttl` are fixed (the tests
    /// pick values whose `retry_action` outcome doesn't depend on wall-clock elapsed
    /// time); `fail_first_n` controls how many `rotate_leaf` calls fail before one
    /// succeeds (a large value never succeeds, exercising sustained failure).
    struct FakeRotator {
        age: u64,
        ttl: u64,
        fail_first_n: u32,
        calls: AtomicU32,
        expired: AtomicBool,
    }

    impl FakeRotator {
        fn new(age: u64, ttl: u64, fail_first_n: u32) -> Self {
            Self {
                age,
                ttl,
                fail_first_n,
                calls: AtomicU32::new(0),
                expired: AtomicBool::new(false),
            }
        }
    }

    impl LeafRotator for FakeRotator {
        fn leaf_age_and_ttl_secs(&self) -> (u64, u64) {
            (self.age, self.ttl)
        }
        async fn rotate_leaf(&self) -> Result<(), VaultError> {
            let n = self.calls.fetch_add(1, Ordering::Relaxed) + 1;
            if n <= self.fail_first_n {
                Err(VaultError::Sign("fake rotate_leaf failure".into()))
            } else {
                Ok(())
            }
        }
        fn expire_now(&self) -> VaultError {
            self.expired.store(true, Ordering::Relaxed);
            VaultError::RenewalExpired
        }
    }

    #[tokio::test(start_paused = true)]
    async fn rotates_when_rotate_now_fires() {
        // age/ttl at exactly the 2/3 boundary (rotate_now's own boundary test) —
        // the decision loop must call rotate_leaf, not skip it.
        let fake = FakeRotator::new(48 * 3600, 72 * 3600, 0);
        assert!(maybe_rotate_leaf(&fake).await.is_ok());
        assert_eq!(
            fake.calls.load(Ordering::Relaxed),
            1,
            "rotate_leaf called once"
        );
        assert!(!fake.expired.load(Ordering::Relaxed));
    }

    #[tokio::test(start_paused = true)]
    async fn does_not_rotate_before_the_threshold() {
        let fake = FakeRotator::new(1_000, 259_200, 0); // ~0.4% of 72h
        assert!(maybe_rotate_leaf(&fake).await.is_ok());
        assert_eq!(
            fake.calls.load(Ordering::Relaxed),
            0,
            "rotate_leaf NOT called below the 2/3 threshold"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn retries_a_transient_rotation_failure_then_succeeds() {
        // Ample remaining validity (72h leaf at 2/3 age still has 24h left) — two
        // transient failures must retry, not fail closed, and the identity must
        // stay intact (expire_now NOT called).
        let fake = FakeRotator::new(48 * 3600, 72 * 3600, 2);
        assert!(maybe_rotate_leaf(&fake).await.is_ok());
        assert_eq!(
            fake.calls.load(Ordering::Relaxed),
            3,
            "2 failures + 1 success"
        );
        assert!(!fake.expired.load(Ordering::Relaxed));
    }

    #[tokio::test(start_paused = true)]
    async fn sustained_rotation_failure_fails_closed() {
        // A small fixed remaining-validity budget (5s) — retry_action's threshold
        // (backoff+2) grows past it as `attempt` increases even though `remaining`
        // itself never shrinks in this fake, so this always converges to
        // FailClosed without needing to simulate elapsed wall-clock time.
        let fake = FakeRotator::new(95, 100, u32::MAX);
        let err = maybe_rotate_leaf(&fake).await.unwrap_err();
        assert!(matches!(err, VaultError::RenewalExpired));
        assert!(
            fake.expired.load(Ordering::Relaxed),
            "expire_now called on sustained failure"
        );
    }
}
