//! A handle on the connecting process itself, taken once per connection, so later
//! checks name that process rather than a pid that may since have been reused.
//! Linux: a pidfd (`SO_PEERPIDFD`, else `pidfd_open` on the `SO_PEERCRED` pid,
//! verified after the open). macOS: the connection's audit token.
use crate::PeerCreds;
use std::os::fd::BorrowedFd;
#[cfg(target_os = "linux")]
use std::os::fd::OwnedFd;

#[derive(Debug)]
pub enum PeerProcess {
    #[cfg(target_os = "linux")]
    Pidfd(OwnedFd),
    #[cfg(target_os = "macos")]
    AuditToken([u32; 8]),
    /// The connecting process has already exited.
    Gone,
    /// No handle could be taken or verified.
    Unavailable,
}

#[cfg(target_os = "linux")]
const STATUS_CAP: usize = 16 * 1024;

#[cfg(target_os = "linux")]
pub fn capture(fd: BorrowedFd<'_>, creds: &PeerCreds) -> PeerProcess {
    use crate::peer_process_rules::{classify_peer_pidfd_errno, Next};
    use nix::sys::socket::{getsockopt, sockopt::PeerPidfd};
    match getsockopt(&fd, PeerPidfd) {
        Ok(pidfd) if pidfd_alive(&pidfd) => PeerProcess::Pidfd(pidfd),
        Ok(_) => PeerProcess::Gone,
        Err(e) => match classify_peer_pidfd_errno(e) {
            Next::Gone => PeerProcess::Gone,
            Next::Fallback => pidfd_fallback(creds),
            Next::Unavailable => PeerProcess::Unavailable,
        },
    }
}

/// Kernels before 6.5: open a pidfd on the `SO_PEERCRED` pid, then confirm the
/// process it names has the peer's uid and was still alive after that read.
#[cfg(target_os = "linux")]
fn pidfd_fallback(creds: &PeerCreds) -> PeerProcess {
    use crate::peer_process_rules::{fallback_admits, pidfd_open_says_gone, status_uids};
    let Some(pid) = creds.pid.and_then(|p| i32::try_from(p).ok()) else {
        return PeerProcess::Unavailable;
    };
    let pidfd = match maknae_io::pidfd_open(pid) {
        Ok(pidfd) => pidfd,
        Err(e) => {
            let errno = nix::errno::Errno::from_raw(e.raw_os_error().unwrap_or(0));
            return if pidfd_open_says_gone(errno) {
                PeerProcess::Gone
            } else {
                PeerProcess::Unavailable
            };
        }
    };
    let status_path = std::path::PathBuf::from(format!("/proc/{pid}/status"));
    let Ok(status) = maknae_io::read_pseudo_file(&status_path, STATUS_CAP) else {
        return PeerProcess::Unavailable;
    };
    if fallback_admits(status_uids(&status), creds.uid, pidfd_alive(&pidfd)) {
        PeerProcess::Pidfd(pidfd)
    } else {
        PeerProcess::Unavailable
    }
}

/// A pidfd polls readable once its process has exited.
#[cfg(target_os = "linux")]
pub(crate) fn pidfd_alive(pidfd: &OwnedFd) -> bool {
    use nix::poll::{poll, PollFd, PollFlags, PollTimeout};
    use std::os::fd::AsFd;
    let mut fds = [PollFd::new(pidfd.as_fd(), PollFlags::POLLIN)];
    matches!(poll(&mut fds, PollTimeout::ZERO), Ok(0))
}

#[cfg(target_os = "macos")]
pub fn capture(fd: BorrowedFd<'_>, _creds: &PeerCreds) -> PeerProcess {
    use nix::sys::socket::{getsockopt, sockopt::LocalPeerToken};
    match getsockopt(&fd, LocalPeerToken) {
        Ok(token) => PeerProcess::AuditToken(token.val),
        Err(_) => PeerProcess::Unavailable,
    }
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
pub fn capture(_fd: BorrowedFd<'_>, _creds: &PeerCreds) -> PeerProcess {
    PeerProcess::Unavailable
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::fd::AsFd;

    fn own_creds() -> PeerCreds {
        PeerCreds {
            uid: nix::unistd::geteuid().as_raw(),
            gid: None,
            pid: Some(std::process::id()),
        }
    }

    #[cfg(target_os = "linux")]
    fn assert_live_pidfd(got: PeerProcess) {
        match got {
            PeerProcess::Pidfd(fd) => assert!(pidfd_alive(&fd), "the handle names a live process"),
            other => panic!("expected a pidfd, got {other:?}"),
        }
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn capture_yields_a_live_pidfd_for_a_connected_peer() {
        let (a, _b) = std::os::unix::net::UnixStream::pair().expect("socketpair");
        let creds = crate::peercred::capture(&a).expect("peer creds");
        assert_live_pidfd(capture(a.as_fd(), &creds));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn the_fallback_takes_a_handle_on_a_live_peer() {
        assert_live_pidfd(pidfd_fallback(&own_creds()));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn the_fallback_refuses_a_uid_mismatch() {
        let creds = PeerCreds {
            uid: own_creds().uid + 1,
            ..own_creds()
        };
        assert!(matches!(pidfd_fallback(&creds), PeerProcess::Unavailable));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn the_fallback_reports_a_reaped_pid_as_gone() {
        let mut child = std::process::Command::new("true").spawn().expect("spawn");
        let pid = child.id();
        child.wait().expect("reap");
        let creds = PeerCreds {
            pid: Some(pid),
            ..own_creds()
        };
        assert!(matches!(pidfd_fallback(&creds), PeerProcess::Gone));
    }

    #[cfg(target_os = "linux")]
    fn wait_until_zombie(pid: u32) {
        let status = format!("/proc/{pid}/status");
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
        while !std::fs::read_to_string(&status)
            .expect("the zombie keeps its status")
            .contains("State:\tZ")
        {
            assert!(std::time::Instant::now() < deadline, "child never exited");
            std::thread::sleep(std::time::Duration::from_millis(5));
        }
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn the_fallback_refuses_an_exited_unreaped_child() {
        let mut child = std::process::Command::new("true").spawn().expect("spawn");
        let pid = child.id();
        wait_until_zombie(pid);
        let creds = PeerCreds {
            pid: Some(pid),
            ..own_creds()
        };
        let got = pidfd_fallback(&creds);
        child.wait().expect("reap");
        assert!(matches!(got, PeerProcess::Unavailable));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn the_fallback_refuses_a_missing_pid() {
        let creds = PeerCreds {
            pid: None,
            ..own_creds()
        };
        assert!(matches!(pidfd_fallback(&creds), PeerProcess::Unavailable));
    }

    #[cfg(target_os = "linux")]
    const CONNECT_TO: &str = "MAKNAE_PEER_PROCESS_TEST_CONNECT_TO";

    #[cfg(target_os = "linux")]
    #[test]
    fn connect_then_exit_helper() {
        if let Some(path) = std::env::var_os(CONNECT_TO) {
            let _ = std::os::unix::net::UnixStream::connect(path).expect("helper connect");
        }
    }

    /// The test binary re-run as a process that connects to `path` and exits.
    #[cfg(target_os = "linux")]
    fn spawn_connecting_helper(path: &std::path::Path) -> std::process::Child {
        std::process::Command::new(std::env::current_exe().expect("test binary"))
            .args([
                "--exact",
                "peer_process::tests::connect_then_exit_helper",
                "--test-threads=1",
            ])
            .env(CONNECT_TO, path)
            .stdout(std::process::Stdio::null())
            .spawn()
            .expect("run the helper")
    }

    #[cfg(target_os = "linux")]
    fn kernel_has_peer_pidfd() -> bool {
        use nix::sys::socket::{getsockopt, sockopt::PeerPidfd};
        let (a, _b) = std::os::unix::net::UnixStream::pair().expect("socketpair");
        getsockopt(&a, PeerPidfd).is_ok()
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn a_reaped_peer_is_gone() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("s.sock");
        let listener = std::os::unix::net::UnixListener::bind(&path).expect("bind");
        let status = spawn_connecting_helper(&path)
            .wait()
            .expect("reap the helper");
        assert!(status.success(), "the helper connected and exited");
        let (accepted, _) = listener.accept().expect("accept the exited peer");
        let creds = crate::peercred::capture(&accepted).expect("peer creds");
        let got = capture(accepted.as_fd(), &creds);
        assert!(matches!(got, PeerProcess::Gone), "{got:?}");
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn an_exited_unreaped_peer_yields_no_handle() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("s.sock");
        let listener = std::os::unix::net::UnixListener::bind(&path).expect("bind");
        let mut helper = spawn_connecting_helper(&path);
        wait_until_zombie(helper.id());
        let (accepted, _) = listener.accept().expect("accept the exited peer");
        let creds = crate::peercred::capture(&accepted).expect("peer creds");
        let got = capture(accepted.as_fd(), &creds);
        assert!(helper.wait().expect("reap the helper").success());
        match got {
            PeerProcess::Gone => assert!(kernel_has_peer_pidfd()),
            PeerProcess::Unavailable => assert!(!kernel_has_peer_pidfd()),
            other => panic!("an exited peer must yield no handle, got {other:?}"),
        }
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn the_audit_token_names_the_peer() {
        let (a, _b) = std::os::unix::net::UnixStream::pair().expect("socketpair");
        match capture(a.as_fd(), &own_creds()) {
            PeerProcess::AuditToken(v) => {
                assert_eq!(v[5], std::process::id(), "word 5 is the pid");
                assert_eq!(v[1], nix::unistd::geteuid().as_raw(), "word 1 is the euid");
            }
            other => panic!("expected an audit token, got {other:?}"),
        }
    }
}
