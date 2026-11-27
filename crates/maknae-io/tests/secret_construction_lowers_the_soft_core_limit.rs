#![cfg(not(target_os = "linux"))]

use maknae_io::{MaknaeSecret, Zeroizing};
use rustix::process::{getrlimit, setrlimit, Resource, Rlimit};

#[test]
fn construction_lowers_the_soft_core_limit() {
    let hard = getrlimit(Resource::Core).maximum;
    if hard == Some(0) {
        eprintln!("host hard RLIMIT_CORE is 0: nothing to check");
        return;
    }
    setrlimit(
        Resource::Core,
        Rlimit {
            current: hard,
            maximum: hard,
        },
    )
    .unwrap();
    assert_ne!(getrlimit(Resource::Core).current, Some(0));
    MaknaeSecret::new(Zeroizing::new(String::from("SENTINEL-752"))).unwrap();
    assert_eq!(getrlimit(Resource::Core).current, Some(0));
}
