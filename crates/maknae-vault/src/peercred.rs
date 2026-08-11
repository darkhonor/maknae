//! Cross-platform Unix-socket peer-credential capture (Layer 2, T3). Linux uses
//! `SO_PEERCRED` (pid/uid/gid in one call); macOS uses `LOCAL_PEERCRED` (uid+groups) plus
//! `LOCAL_PEERPID` (pid). `uid` is guaranteed on both platforms and is the only
//! security-relevant field — the daemon polices it. This is a Layer-2 *connectivity*
//! signal, never identity (identity is the mTLS URI-SAN). **Supported platforms: Linux +
//! macOS only** (the two first-class targets); on any other unix, `capture` fails closed.
use crate::VaultError;
use std::os::fd::AsFd;

/// Kernel-reported credentials of the connected UDS peer.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PeerCreds {
    /// Effective uid of the peer process — guaranteed on Linux + macOS.
    pub uid: u32,
    /// Primary gid — Linux `SO_PEERCRED`; macOS primary group (first of `groups()`).
    pub gid: Option<u32>,
    /// Peer pid — Linux `SO_PEERCRED`; macOS `LOCAL_PEERPID`.
    pub pid: Option<u32>,
}

#[cfg(target_os = "linux")]
pub(crate) fn capture<Fd: AsFd>(fd: &Fd) -> Result<PeerCreds, VaultError> {
    use nix::sys::socket::getsockopt;
    use nix::sys::socket::sockopt::PeerCredentials;
    let ucred = getsockopt(fd, PeerCredentials).map_err(|e| VaultError::PeerCred(e.to_string()))?;
    Ok(PeerCreds {
        uid: ucred.uid(),
        gid: Some(ucred.gid()),
        pid: Some(ucred.pid() as u32),
    })
}

#[cfg(target_vendor = "apple")]
pub(crate) fn capture<Fd: AsFd>(fd: &Fd) -> Result<PeerCreds, VaultError> {
    use nix::sys::socket::getsockopt;
    use nix::sys::socket::sockopt::{LocalPeerCred, LocalPeerPid};
    let xucred = getsockopt(fd, LocalPeerCred).map_err(|e| VaultError::PeerCred(e.to_string()))?;
    let pid = getsockopt(fd, LocalPeerPid).map_err(|e| VaultError::PeerCred(e.to_string()))?;
    Ok(PeerCreds {
        uid: xucred.uid(),
        gid: xucred.groups().first().copied(),
        pid: Some(pid as u32),
    })
}

// Any other unix (BSD/illumos): out of scope for the local plane transport → fail closed
// (a peer we cannot identify cannot be policed). Keeps the crate compiling on all unix
// targets while making the unsupported case an explicit, localized refusal.
#[cfg(all(unix, not(any(target_os = "linux", target_vendor = "apple"))))]
pub(crate) fn capture<Fd: AsFd>(_fd: &Fd) -> Result<PeerCreds, VaultError> {
    Err(VaultError::PeerCred(
        "peer-credential capture is only supported on Linux and macOS".into(),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn captures_own_uid_over_socketpair() {
        let (a, _b) = std::os::unix::net::UnixStream::pair().unwrap();
        let creds = capture(&a).expect("capture peer creds");
        // The peer of `a` is `_b`, held by THIS process → our euid.
        let me = nix::unistd::geteuid().as_raw();
        assert_eq!(creds.uid, me);
        // pid is present on both Linux and macOS (SO_PEERCRED / LOCAL_PEERPID).
        assert_eq!(creds.pid, Some(std::process::id()));
    }
}
