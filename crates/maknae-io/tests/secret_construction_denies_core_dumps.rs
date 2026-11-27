#![cfg(target_os = "linux")]

use maknae_io::{MaknaeSecret, Zeroizing};
use rustix::process::{
    dumpable_behavior, getrlimit, set_dumpable_behavior, setrlimit, DumpableBehavior, Resource,
    Rlimit,
};

#[test]
fn construction_denies_core_dumps() {
    let hard = getrlimit(Resource::Core).maximum;
    let rlimit_checked = hard != Some(0);
    set_dumpable_behavior(DumpableBehavior::Dumpable).unwrap();
    assert_eq!(dumpable_behavior().unwrap(), DumpableBehavior::Dumpable);
    if rlimit_checked {
        setrlimit(
            Resource::Core,
            Rlimit {
                current: hard,
                maximum: hard,
            },
        )
        .unwrap();
        assert_ne!(getrlimit(Resource::Core).current, Some(0));
    } else {
        eprintln!("host hard RLIMIT_CORE is 0: checking dumpability only");
    }
    MaknaeSecret::new(Zeroizing::new(String::from("SENTINEL-752"))).unwrap();
    if rlimit_checked {
        assert_eq!(getrlimit(Resource::Core).current, Some(0));
    }
    assert_eq!(
        dumpable_behavior().unwrap(),
        DumpableBehavior::NotDumpable,
        "host hard RLIMIT_CORE is {hard:?}"
    );
}
