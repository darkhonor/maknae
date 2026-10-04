//! Per-uid in-flight accounting inside a global blocking capacity (#435).
//!
//! Concurrency accounting only: it records which uids hold a slot, never a
//! value produced in one.
use std::collections::HashSet;
use std::sync::{Arc, Mutex, PoisonError};
use tokio::sync::{OwnedSemaphorePermit, Semaphore};

#[derive(Clone, Default)]
pub(crate) struct UidGate(Arc<Mutex<HashSet<u32>>>);

pub(crate) struct UidClaim {
    gate: UidGate,
    uid: u32,
}

pub(crate) struct Slot {
    claim: UidClaim,
    permit: OwnedSemaphorePermit,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Busy {
    Requester,
    Global,
}

impl UidGate {
    pub(crate) fn try_claim(&self, uid: u32) -> Option<UidClaim> {
        self.0
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .insert(uid)
            .then(|| UidClaim {
                gate: self.clone(),
                uid,
            })
    }

    pub(crate) fn try_admit(&self, uid: u32, capacity: &Arc<Semaphore>) -> Result<Slot, Busy> {
        let claim = self.try_claim(uid).ok_or(Busy::Requester)?;
        let permit = Arc::clone(capacity)
            .try_acquire_owned()
            .map_err(|_| Busy::Global)?;
        Ok(Slot { claim, permit })
    }
}

impl Slot {
    pub(crate) fn split(self) -> (UidClaim, OwnedSemaphorePermit) {
        (self.claim, self.permit)
    }
}

impl Drop for UidClaim {
    fn drop(&mut self) {
        self.gate
            .0
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .remove(&self.uid);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn slots(n: usize) -> Arc<Semaphore> {
        Arc::new(Semaphore::new(n))
    }

    #[test]
    fn one_claim_per_uid_and_other_uids_are_independent() {
        let gate = UidGate::default();
        let a = gate.try_claim(1001).expect("the first claim succeeds");
        assert!(gate.try_claim(1001).is_none(), "a second claim is refused");
        let b = gate.try_claim(1002).expect("another uid is independent");
        drop(a);
        assert!(
            gate.try_claim(1001).is_some(),
            "the claim returns when released"
        );
        drop(b);
    }

    #[test]
    fn releasing_one_uid_leaves_the_other_claimed() {
        let gate = UidGate::default();
        let a = gate.try_claim(1001).unwrap();
        let _b = gate.try_claim(1002).unwrap();
        drop(a);
        assert!(gate.try_claim(1002).is_none());
    }

    #[test]
    fn a_busy_uid_is_refused_without_taking_a_global_slot() {
        let gate = UidGate::default();
        let cap = slots(2);
        let held = gate.try_admit(7, &cap).expect("admitted");
        assert_eq!(cap.available_permits(), 1);
        assert_eq!(gate.try_admit(7, &cap).err(), Some(Busy::Requester));
        assert_eq!(cap.available_permits(), 1, "the refusal took no slot");
        let other = gate.try_admit(8, &cap).expect("another uid admitted");
        assert_eq!(cap.available_permits(), 0);
        drop(held);
        drop(other);
        assert_eq!(cap.available_permits(), 2);
        assert!(gate.try_claim(7).is_some(), "the slot releases its claim");
    }

    #[test]
    fn a_full_capacity_refuses_and_leaves_the_uid_unclaimed() {
        let gate = UidGate::default();
        let cap = slots(1);
        let _held = gate.try_admit(7, &cap).unwrap();
        assert_eq!(gate.try_admit(8, &cap).err(), Some(Busy::Global));
        assert!(
            gate.try_claim(8).is_some(),
            "a global refusal leaves no claim behind"
        );
    }
}
