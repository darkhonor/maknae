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
}
