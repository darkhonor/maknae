//! How many connections the deputy serves at once (#321).

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

/// The kernel's egress admission (`maknae_kernel::BLOCKING_BREAKER_MAX_IN_FLIGHT`).
pub const KERNEL_ADMISSION: usize = 32;

/// Covers slots still held just after a reply, or by calls the kernel abandoned (#321).
pub const HEADROOM: usize = 4;

/// Not measured; to be derived from the host's limits over the measured per-call cost (#321).
pub const UNMEASURED_CEILING: usize = KERNEL_ADMISSION + HEADROOM;

pub fn deputy_capacity() -> usize {
    UNMEASURED_CEILING
}

pub struct Slots {
    in_use: AtomicUsize,
    cap: usize,
}

/// Held for the life of one connection; dropping it, on any path, frees the slot.
pub struct Slot(Arc<Slots>);

impl Slots {
    pub fn new(cap: usize) -> Arc<Self> {
        Arc::new(Self {
            in_use: AtomicUsize::new(0),
            cap,
        })
    }

    pub fn try_take(self: &Arc<Self>) -> Option<Slot> {
        self.in_use
            .try_update(Ordering::AcqRel, Ordering::Acquire, |n| {
                (n < self.cap).then_some(n + 1)
            })
            .ok()
            .map(|_| Slot(Arc::clone(self)))
    }

    pub fn cap(&self) -> usize {
        self.cap
    }

    #[cfg(test)]
    pub fn in_use(&self) -> usize {
        self.in_use.load(Ordering::Acquire)
    }
}

impl Drop for Slot {
    fn drop(&mut self) {
        self.0.in_use.fetch_sub(1, Ordering::AcqRel);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn slots_are_taken_up_to_the_cap_and_refused_beyond_it() {
        let s = Slots::new(2);
        let a = s.try_take().expect("first");
        let b = s.try_take().expect("second");
        assert!(s.try_take().is_none());
        assert_eq!(s.in_use(), 2);
        drop(a);
        assert_eq!(s.in_use(), 1);
        let c = s.try_take().expect("a released slot is taken again");
        assert!(s.try_take().is_none());
        drop((b, c));
        assert_eq!(s.in_use(), 0);
    }

    #[test]
    fn the_deputy_serves_more_than_the_kernel_admits() {
        assert!(deputy_capacity() > KERNEL_ADMISSION);
    }

    #[test]
    fn a_zero_cap_admits_nothing() {
        assert!(Slots::new(0).try_take().is_none());
    }

    #[test]
    fn a_panicking_holder_still_frees_its_slot() {
        let s = Slots::new(1);
        let held = Arc::clone(&s);
        let r = std::panic::catch_unwind(std::panic::AssertUnwindSafe(move || {
            let _slot = held.try_take().expect("free");
            panic!("connection handler panicked");
        }));
        assert!(r.is_err());
        assert_eq!(s.in_use(), 0);
        assert!(s.try_take().is_some());
    }
}
