//! Peer-uid → `maknae`-group membership (spec §5). T3 I/O; fail-closed. CROSS-PLATFORM.
use maknae_io::{AccountLookupError, MAKNAE_AGENTS_GROUP, MAKNAE_GROUP};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuthzError {
    Resolve(String),
    /// The user database answered: no account has this uid.
    NoUser,
    /// The user resolved, but the group source failed, so membership is undecided.
    Unanswered {
        user: String,
        why: String,
    },
}

/// The `maknae` group's gid — used to group-own the daemon's UDS (codex round-7 P1) so the
/// 0660 mode actually gates on the `maknae` group rather than the daemon process's PRIMARY
/// group (which, under the normal service-account setup, is NOT `maknae`; `maknae` is a
/// supplementary group there). Fails closed (`Err`) if the group cannot be resolved — the
/// caller must refuse to serve rather than bind a socket group-owned by the wrong group.
pub fn maknae_gid() -> Result<nix::unistd::Gid, AuthzError> {
    named_gid(MAKNAE_GROUP, maknae_io::group_gid(MAKNAE_GROUP))
}

/// The `maknae-agents` gid that group-owns the agent socket; a missing group refuses start.
pub fn maknae_agents_gid() -> Result<nix::unistd::Gid, AuthzError> {
    named_gid(MAKNAE_AGENTS_GROUP, maknae_io::maknae_agents_gid())
}

fn named_gid(
    name: &str,
    found: Result<Option<u32>, AccountLookupError>,
) -> Result<nix::unistd::Gid, AuthzError> {
    found
        .map_err(|e| AuthzError::Resolve(lookup_why(e)))?
        .map(nix::unistd::Gid::from_raw)
        .ok_or_else(|| AuthzError::Resolve(format!("no `{name}` group")))
}

fn lookup_why(e: AccountLookupError) -> String {
    match e {
        AccountLookupError::Resolve(why) | AccountLookupError::Unanswered { why, .. } => why,
    }
}

pub use crate::membership::Membership;
pub use maknae_io::canonical_home;

pub fn uid_in_maknae_group(uid: u32) -> Result<Membership, AuthzError> {
    let account = maknae_io::host_account(uid)
        .map_err(|e| match e {
            AccountLookupError::Resolve(why) => AuthzError::Resolve(why),
            AccountLookupError::Unanswered { user, why } => AuthzError::Unanswered { user, why },
        })?
        .ok_or(AuthzError::NoUser)?;
    let gid = maknae_io::group_gid(MAKNAE_GROUP).map_err(|e| AuthzError::Unanswered {
        user: account.name.clone(),
        why: lookup_why(e),
    })?;
    Ok(crate::membership::membership(account, gid))
}

#[cfg(test)]
mod tests {
    use super::*;
    use nix::unistd::{Uid, User};

    #[test]
    fn resolves_self_without_panic() {
        let uid = nix::unistd::getuid().as_raw();
        let _ = uid_in_maknae_group(uid); // Ok(_) or Err(Resolve) — never panics/UB
    }

    /// `maknae_gid` never panics/UB on a host without a `maknae` group (this dev host):
    /// it must resolve to a `Resolve` error, not crash — matching `uid_in_maknae_group`'s
    /// documented fail-closed contract.
    #[test]
    fn maknae_gid_resolves_or_fails_closed_without_panic() {
        match maknae_gid() {
            Ok(_gid) => {} // a host that DOES have `maknae` — fine, resolved.
            Err(AuthzError::Resolve(msg)) => assert!(!msg.is_empty()),
            Err(AuthzError::NoUser | AuthzError::Unanswered { .. }) => {
                panic!("the gid lookup names no user")
            }
        }
    }

    #[test]
    fn a_missing_or_unanswered_group_refuses_the_socket() {
        assert_eq!(
            named_gid(MAKNAE_AGENTS_GROUP, Ok(Some(4242))),
            Ok(nix::unistd::Gid::from_raw(4242))
        );
        assert_eq!(
            named_gid(MAKNAE_AGENTS_GROUP, Ok(None)),
            Err(AuthzError::Resolve("no `maknae-agents` group".into()))
        );
        assert_eq!(
            named_gid(
                MAKNAE_AGENTS_GROUP,
                Err(AccountLookupError::Resolve("EIO".into()))
            ),
            Err(AuthzError::Resolve("EIO".into()))
        );
    }

    /// #275: the username is a property of the PEER UID and must be populated
    /// whatever the membership answer is.
    ///
    /// **Honest about what discriminates.** On a host that HAS a `maknae` group
    /// both the correct order (user first) and the old one (group first) resolve
    /// the name, so this assertion cannot tell them apart here. It discriminates
    /// on a host WITHOUT the group -- CI's ubuntu-latest, where
    /// `packaging/deb/postinst` is the only creator -- which is exactly the
    /// deployment where the old order returned early and blanked the identity on
    /// the connection-deny record. The invariant is asserted on both kinds of
    /// host; only one kind can fail it.
    #[test]
    fn the_username_is_resolved_whatever_the_membership_answer_is() {
        let me = nix::unistd::geteuid().as_raw();
        let Ok(Some(u)) = User::from_uid(Uid::from_raw(me)) else {
            eprintln!("SKIP: euid {me} does not resolve to a user on this host");
            return;
        };
        let m = uid_in_maknae_group(me).expect("a resolvable uid must not error");
        assert_eq!(
            m.user, u.name,
            "the name must be carried regardless of in_group={}",
            m.in_group
        );
    }

    /// A uid that resolves to no user is still an ERROR -- fail closed. The
    /// reordering must not have turned an unresolvable peer into a non-member
    /// with an empty name.
    #[test]
    fn an_unresolvable_uid_is_still_an_error_not_a_silent_non_member() {
        assert!(
            uid_in_maknae_group(999_999).is_err(),
            "an unresolvable uid must fail closed, not resolve to a nameless non-member"
        );
    }

    #[test]
    fn the_membership_carries_the_callers_raw_home() {
        let me = nix::unistd::geteuid().as_raw();
        let Ok(Some(u)) = User::from_uid(Uid::from_raw(me)) else {
            eprintln!("SKIP: euid {me} does not resolve to a user on this host");
            return;
        };
        let m = uid_in_maknae_group(me).expect("a resolvable uid must not error");
        assert_eq!(m.dir, u.dir);
    }
}
