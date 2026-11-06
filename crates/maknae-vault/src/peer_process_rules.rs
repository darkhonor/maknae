//! The decisions behind `peer_process::capture`, apart from the syscalls that feed
//! them, so they are mutation-tested on every platform.
use nix::errno::Errno;

/// What `SO_PEERPIDFD`'s failure says to do next.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Next {
    Gone,
    Fallback,
    Unavailable,
}

/// `ENOPROTOOPT` is a kernel without the option (before 6.5); `ESRCH` and `EINVAL`
/// are a peer that has exited. Anything else is a failure to classify.
pub(crate) fn classify_peer_pidfd_errno(e: Errno) -> Next {
    match e {
        Errno::ESRCH | Errno::EINVAL => Next::Gone,
        Errno::ENOPROTOOPT => Next::Fallback,
        _ => Next::Unavailable,
    }
}

/// `pidfd_open` failing with `ESRCH` means no process holds the peer's pid.
pub(crate) fn pidfd_open_says_gone(e: Errno) -> bool {
    e == Errno::ESRCH
}

/// The fallback admits a pidfd only when the process it names has the peer uid as
/// both its real and effective uid and was alive after that was read.
pub(crate) fn fallback_admits(status_uids: Option<(u32, u32)>, uid: u32, alive: bool) -> bool {
    status_uids == Some((uid, uid)) && alive
}

/// The real and effective uid from a `/proc/<pid>/status` `Uid:` line.
pub(crate) fn status_uids(status: &[u8]) -> Option<(u32, u32)> {
    let text = std::str::from_utf8(status).ok()?;
    let line = text.lines().find_map(|l| l.strip_prefix("Uid:"))?;
    let mut ids = line.split_whitespace().map(str::parse::<u32>);
    match (ids.next(), ids.next()) {
        (Some(Ok(real)), Some(Ok(effective))) => Some((real, effective)),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_peer_pidfd_errno_is_classified() {
        assert_eq!(classify_peer_pidfd_errno(Errno::ESRCH), Next::Gone);
        assert_eq!(classify_peer_pidfd_errno(Errno::EINVAL), Next::Gone);
        assert_eq!(
            classify_peer_pidfd_errno(Errno::ENOPROTOOPT),
            Next::Fallback
        );
        for e in [Errno::ENODATA, Errno::EPERM, Errno::EBADF, Errno::EMFILE] {
            assert_eq!(classify_peer_pidfd_errno(e), Next::Unavailable, "{e}");
        }
    }

    #[test]
    fn only_esrch_from_pidfd_open_is_gone() {
        assert!(pidfd_open_says_gone(Errno::ESRCH));
        for e in [Errno::EINVAL, Errno::EMFILE, Errno::ENOSYS, Errno::EPERM] {
            assert!(!pidfd_open_says_gone(e), "{e}");
        }
    }

    #[test]
    fn the_fallback_admits_only_a_live_process_of_the_peer_uid() {
        assert!(fallback_admits(Some((7, 7)), 7, true));
        assert!(!fallback_admits(Some((7, 7)), 7, false));
        assert!(!fallback_admits(Some((8, 7)), 7, true));
        assert!(!fallback_admits(Some((7, 8)), 7, true));
        assert!(!fallback_admits(Some((8, 8)), 7, true));
        assert!(!fallback_admits(None, 7, true));
    }

    #[test]
    fn status_uids_reads_the_real_and_effective_uid() {
        let status = b"Name:\tx\nPid:\t7\nUid:\t1001\t1002\t1003\t1004\nGid:\t5\t5\t5\t5\n";
        assert_eq!(status_uids(status), Some((1001, 1002)));
        assert_eq!(status_uids(b"Name:\tx\n"), None);
        assert_eq!(status_uids(b"Uid:\t1001\n"), None);
        assert_eq!(status_uids(b"Uid:\tx\t1\t1\t1\n"), None);
        assert_eq!(status_uids(b"Uid:\t1\tx\t1\t1\n"), None);
        assert_eq!(status_uids(b"XUid:\t1\t1\t1\t1\n"), None);
        assert_eq!(status_uids(b"Uid:\t1\t1\t1\t1\xff\n"), None);
    }
}
