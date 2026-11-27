#![cfg(target_os = "linux")]

use rustix::process::{dumpable_behavior, set_dumpable_behavior, DumpableBehavior};

#[test]
fn deny_core_dumps_reapplies_after_dumpability_is_reset() {
    maknae_io::deny_core_dumps().unwrap();
    set_dumpable_behavior(DumpableBehavior::Dumpable).unwrap();
    assert_eq!(dumpable_behavior().unwrap(), DumpableBehavior::Dumpable);
    maknae_io::deny_core_dumps().unwrap();
    assert_eq!(dumpable_behavior().unwrap(), DumpableBehavior::NotDumpable);
}
