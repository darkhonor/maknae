use std::io;
use std::sync::OnceLock;

use rustix::process::{setrlimit, Resource, Rlimit};

static CORE_DUMPS_DENIED: OnceLock<Result<(), i32>> = OnceLock::new();

/// Makes this process write no core file and, on Linux, non-dumpable, once; a failure is sticky.
pub fn deny_core_dumps() -> io::Result<()> {
    (*CORE_DUMPS_DENIED.get_or_init(|| deny().map_err(|e| e.raw_os_error())))
        .map_err(io::Error::from_raw_os_error)
}

fn deny() -> rustix::io::Result<()> {
    setrlimit(
        Resource::Core,
        Rlimit {
            current: Some(0),
            maximum: Some(0),
        },
    )?;
    #[cfg(target_os = "linux")]
    rustix::process::set_dumpable_behavior(rustix::process::DumpableBehavior::NotDumpable)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use rustix::process::{getrlimit, Resource};

    #[test]
    fn deny_core_dumps_sets_a_zero_core_limit() {
        deny_core_dumps().unwrap();
        let limit = getrlimit(Resource::Core);
        assert_eq!((limit.current, limit.maximum), (Some(0), Some(0)));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn deny_core_dumps_makes_the_process_non_dumpable() {
        deny_core_dumps().unwrap();
        assert_eq!(
            rustix::process::dumpable_behavior().unwrap(),
            rustix::process::DumpableBehavior::NotDumpable
        );
    }
}
