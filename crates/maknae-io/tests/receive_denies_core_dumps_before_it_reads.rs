use std::io::Write;
use std::os::unix::net::UnixStream;
use std::time::Duration;

use maknae_io::credential::{LaunchCredentials, ReceiveError};
use rustix::process::{getrlimit, setrlimit, Resource, Rlimit};

#[test]
fn receive_denies_core_dumps_before_it_reads_even_a_malformed_frame() {
    let hard = getrlimit(Resource::Core).maximum;
    let rlimit_checked = hard != Some(0);
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
        eprintln!("host hard RLIMIT_CORE is 0: nothing to raise first");
    }
    let (mut a, mut b) = UnixStream::pair().unwrap();
    b.set_read_timeout(Some(Duration::from_millis(500)))
        .unwrap();
    a.write_all(&4u32.to_be_bytes()).unwrap();
    a.write_all(b"XXXX").unwrap();
    assert!(matches!(
        LaunchCredentials::receive(&mut b),
        Err(ReceiveError::Decode(_))
    ));
    assert_eq!(getrlimit(Resource::Core).current, Some(0));
}
