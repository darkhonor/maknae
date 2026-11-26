use std::io;
use std::sync::OnceLock;

use rustix::process::{getrlimit, setrlimit, Resource, Rlimit};

static CORE_DUMPS_DENIED: OnceLock<Result<(), i32>> = OnceLock::new();

/// Lowers the soft core limit to 0 and, on Linux, makes the process non-dumpable, once; a
/// failure is sticky. A holder calls it before fetching a credential. Only the soft limit
/// moves, so no `process:setrlimit` permission is needed under a confined domain.
pub fn deny_core_dumps() -> io::Result<()> {
    (*CORE_DUMPS_DENIED.get_or_init(|| deny().map_err(|e| e.raw_os_error())))
        .map_err(io::Error::from_raw_os_error)
}

fn deny() -> rustix::io::Result<()> {
    let hard = getrlimit(Resource::Core).maximum;
    setrlimit(
        Resource::Core,
        Rlimit {
            current: Some(0),
            maximum: hard,
        },
    )?;
    #[cfg(target_os = "linux")]
    rustix::process::set_dumpable_behavior(rustix::process::DumpableBehavior::NotDumpable)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deny_core_dumps_lowers_only_the_soft_core_limit() {
        let before = getrlimit(Resource::Core);
        deny_core_dumps().unwrap();
        let after = getrlimit(Resource::Core);
        assert_eq!(after.current, Some(0));
        assert_eq!(after.maximum, before.maximum);
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
