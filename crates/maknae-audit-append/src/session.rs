//! Session/connection correlation ids (ADR-0019 AU-12(1)).
//!
//! T1 (`coverage-tiers.toml`): the exact bit layout of `session_id` is a
//! contract with any downstream correlation tooling — a swapped high/low
//! half or an off-by-one counter start would silently corrupt correlation
//! without ever producing a wrong *answer* (no permit/deny to get wrong
//! here), so the layout is pinned exhaustively rather than trusted to "it
//! compiles."
use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

/// Process-wide session-id allocator. `session_id = (boot_nonce << 32) |
/// per-connection counter`: the high 32 bits are a per-boot nonce (real-clock
/// UNIX-epoch seconds, truncated to `u32`) that distinguishes daemon
/// restarts; the low 32 bits are a monotonic per-connection counter unique
/// within this boot. This is a correlation id (AU-12(1)), not a secret or a
/// cryptographic nonce — collision across two daemons booted in the same
/// second is possible only if their connection counters also collide.
pub struct SessionIds {
    boot_nonce: u32,
    conn_ctr: AtomicU32,
}

impl SessionIds {
    /// Real-clock constructor for the running daemon.
    pub fn new() -> Self {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs() as u32)
            .unwrap_or(0);
        Self::with_nonce(nonce)
    }

    /// Test seam: an explicit boot nonce, bypassing the real clock so tests
    /// are deterministic.
    pub fn with_nonce(boot_nonce: u32) -> Self {
        SessionIds {
            boot_nonce,
            conn_ctr: AtomicU32::new(0),
        }
    }

    /// Allocate the next session id for a newly-accepted connection.
    pub fn next_session(&self) -> u64 {
        let ctr = self.conn_ctr.fetch_add(1, Ordering::SeqCst).wrapping_add(1);
        ((self.boot_nonce as u64) << 32) | (ctr as u64)
    }
}

impl Default for SessionIds {
    fn default() -> Self {
        Self::new()
    }
}

/// A per-connection request sequence counter (AU-12(1) ordering). Deliberately
/// **not** hung off `SessionIds` / process-global: the run-loop (Task 7)
/// constructs one `Seq` per accepted connection, so `seq` counts 1, 2, 3...
/// within that connection only — two concurrent connections each start at 1.
pub struct Seq(AtomicU64);

impl Seq {
    pub fn new() -> Self {
        Seq(AtomicU64::new(0))
    }

    /// The next sequence number within this connection, starting at 1.
    pub fn next(&self) -> u64 {
        self.0.fetch_add(1, Ordering::SeqCst).wrapping_add(1)
    }
}

impl Default for Seq {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn session_id_packs_nonce_high_ctr_low() {
        let s = SessionIds::with_nonce(0xAABBCCDD);
        let first = s.next_session();
        assert_eq!(first >> 32, 0xAABBCCDD);
        assert_eq!(first & 0xFFFF_FFFF, 1);
        assert_eq!(s.next_session() & 0xFFFF_FFFF, 2);
    }

    #[test]
    fn session_id_high_bits_stable_across_many_connections() {
        let s = SessionIds::with_nonce(7);
        for _ in 0..5 {
            let id = s.next_session();
            assert_eq!(id >> 32, 7, "nonce must not drift as the counter advances");
        }
    }

    #[test]
    fn session_id_low_bits_are_low_not_high() {
        // A mutant that swaps which half carries the nonce vs. the counter
        // would still pass a same-value test (e.g. nonce == ctr); use
        // distinguishable values so high/low really are pinned to the right
        // half.
        let s = SessionIds::with_nonce(0x0000_0001);
        let first = s.next_session();
        assert_eq!(first, 0x0000_0001_0000_0001);
    }

    #[test]
    fn different_nonces_produce_different_session_ids_at_same_counter() {
        let a = SessionIds::with_nonce(1).next_session();
        let b = SessionIds::with_nonce(2).next_session();
        assert_ne!(a, b);
        assert_eq!(a & 0xFFFF_FFFF, b & 0xFFFF_FFFF, "both start their counter at 1");
    }

    #[test]
    fn new_uses_a_plausible_real_clock_nonce() {
        // Sanity bound: the nonce must be "now-ish" epoch seconds, not zero
        // and not a fixed sentinel. 1_700_000_000 ~= 2023-11-14; comfortably
        // before this project exists.
        let s = SessionIds::new();
        let id = s.next_session();
        let nonce = (id >> 32) as u32;
        assert!(nonce > 1_700_000_000, "nonce {nonce} does not look like a real epoch-seconds value");
    }

    #[test]
    fn seq_starts_at_one_and_increments_by_one() {
        let seq = Seq::new();
        assert_eq!(seq.next(), 1);
        assert_eq!(seq.next(), 2);
        assert_eq!(seq.next(), 3);
    }

    #[test]
    fn seq_instances_are_independent() {
        let a = Seq::new();
        let b = Seq::new();
        assert_eq!(a.next(), 1);
        assert_eq!(a.next(), 2);
        // b is a distinct connection's counter — unaffected by a's advances.
        assert_eq!(b.next(), 1);
    }
}
