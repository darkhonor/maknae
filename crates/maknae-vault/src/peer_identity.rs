//! Peer-identity decisions over captured UDS credentials (#240a D3-A).
//!
//! **Why this is a separate file from `peercred.rs`.** `peercred.rs` is the
//! `getsockopt` syscall wrapper and is whole-file **mutation-excluded**
//! (`.cargo/mutants.toml`, `# nix getsockopt peer-creds — syscall I/O (T3)`).
//! A T1 tier there would generate zero mutants, so "0 missed" would be
//! vacuous — on the control that decides whether an arbitrary local process
//! can reach the egress deputy and spend the operator's provider key. The
//! syscall stays excluded; the DECISION lives here, pure and mutation-visible.
//! This is the split the crate already uses: `secret_io` / `secret_source`,
//! `syslog_io` / `syslog_fmt`, `journal_io` / `journal`.
//!
//! The comparison lives inside the crate that owns the control rather than
//! being re-derived by each caller — the `maknae-io` lesson, one layer out.

use crate::{PeerCreds, VaultError};
use std::os::fd::AsFd;

/// Is the connected peer running as `expected_uid`?
///
/// Fail-closed in both directions: a capture error is a refusal, never an
/// assumption, and the comparison is exact — there is no "close enough" uid.
pub fn peer_uid_is<Fd: AsFd>(fd: &Fd, expected_uid: u32) -> Result<bool, VaultError> {
    Ok(crate::peercred::capture(fd)?.uid == expected_uid)
}

/// The pure decision, separated from the syscall so it is mutation-visible.
/// Used by [`peer_uid_is`] and directly by tests that build `PeerCreds`.
pub fn creds_match_uid(creds: &PeerCreds, expected_uid: u32) -> bool {
    creds.uid == expected_uid
}

/// Is the LISTENER this fd is connected to created by `expected_uid` — or
/// by root, the init system that creates a socket-activated listener on the
/// service's behalf?
///
/// The client side of a connection sees the credentials in effect at the
/// peer's `listen(2)` (`SO_PEERCRED` on Linux, `LOCAL_PEERCRED` on macOS).
/// Under socket activation that is the init system, uid 0, not the account
/// the service later runs as — so an exact check would refuse the very
/// listener the packaging ships (ADR-0023's correction 1, prototyped by
/// #240). A root-created listener at the service's path is the init
/// system's delegation: root needs no impersonation to read what a client
/// sends. Every other uid but the expected one is refused, and a capture
/// error is a refusal. Use [`peer_uid_is`] on an ACCEPTED connection, where
/// the credentials are the connecting process's own.
pub fn listener_uid_is<Fd: AsFd>(fd: &Fd, expected_uid: u32) -> Result<bool, VaultError> {
    Ok(creds_match_listener_uid(
        &crate::peercred::capture(fd)?,
        expected_uid,
    ))
}

/// The pure decision behind [`listener_uid_is`].
pub fn creds_match_listener_uid(creds: &PeerCreds, expected_uid: u32) -> bool {
    creds.uid == expected_uid || creds.uid == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    fn creds(uid: u32) -> PeerCreds {
        PeerCreds {
            uid,
            gid: None,
            pid: None,
        }
    }

    /// A uid that is not the expected one is refused. This is the whole
    /// control: without it any local process that can reach the socket gets
    /// provider replies paid for with the operator's key.
    #[test]
    fn a_peer_whose_uid_differs_is_refused() {
        assert!(creds_match_uid(&creds(1000), 1000));
        assert!(!creds_match_uid(&creds(1001), 1000));
        // uid 0 is not special-cased: root is not exempt from the check.
        assert!(!creds_match_uid(&creds(0), 1000));
    }

    /// Over a real socketpair, with a real uid, through the real syscall: the
    /// process's own uid matches and a neighbouring uid does not. This uses
    /// the value the production path actually produces, not a stand-in.
    #[test]
    fn peer_uid_is_agrees_with_the_running_uid_over_a_real_socket() {
        let (a, _b) = std::os::unix::net::UnixStream::pair().unwrap();
        let me = nix::unistd::getuid().as_raw();
        assert!(peer_uid_is(&a, me).unwrap());
        assert!(!peer_uid_is(&a, me.wrapping_add(1)).unwrap());
    }

    /// A capture error is a REFUSAL, never an assumption: a peer we cannot
    /// identify cannot be policed. Exercised over a non-socket fd.
    #[test]
    fn a_peer_we_cannot_identify_is_an_error_not_a_pass() {
        let f = std::fs::File::open("/dev/null").unwrap();
        assert!(peer_uid_is(&f, 0).is_err());
    }

    /// The CLIENT side of an init-system-created listener: `SO_PEERCRED` /
    /// `LOCAL_PEERCRED` report the credentials in effect at `listen(2)`,
    /// which under socket activation are the init system's — uid 0 — not
    /// the service's. So a listener created by root at the deputy's path is
    /// accepted as the init system's delegation to the deputy; every other
    /// uid but the deputy's own is refused, exactly as before.
    #[test]
    fn a_listener_created_by_the_deputy_or_by_root_is_accepted_and_nothing_else() {
        assert!(creds_match_listener_uid(&creds(1000), 1000));
        assert!(creds_match_listener_uid(&creds(0), 1000));
        assert!(!creds_match_listener_uid(&creds(1001), 1000));
        assert!(!creds_match_listener_uid(&creds(1000), 1001));
        // and the plain check is UNCHANGED: root is not exempt from it
        assert!(!creds_match_uid(&creds(0), 1000));
    }

    /// Through the real syscall: the running uid is accepted as the listener's
    /// creator, a neighbouring uid is not (unless the test itself runs as
    /// root, whose listener is accepted by design), and a fd that is not a
    /// socket is an error, never a pass.
    #[test]
    fn listener_uid_is_agrees_with_the_running_uid_over_a_real_socket() {
        let (a, _b) = std::os::unix::net::UnixStream::pair().unwrap();
        let me = nix::unistd::getuid().as_raw();
        assert!(listener_uid_is(&a, me).unwrap());
        if me != 0 {
            assert!(!listener_uid_is(&a, me.wrapping_add(1)).unwrap());
        }
        let f = std::fs::File::open("/dev/null").unwrap();
        assert!(listener_uid_is(&f, me).is_err());
    }
}
