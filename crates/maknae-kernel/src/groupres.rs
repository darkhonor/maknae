//! Peer-uid → `maknae`-group membership (spec §5). T3 I/O; fail-closed. CROSS-PLATFORM.
use nix::unistd::{Group, Uid, User};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuthzError {
    Resolve(String),
}

/// Resolve the `maknae` group by name — shared by [`uid_in_maknae_group`] and
/// [`maknae_gid`] so the group name is hardcoded in exactly one place.
fn resolve_maknae_group() -> Result<Group, AuthzError> {
    Group::from_name("maknae")
        .map_err(|e| AuthzError::Resolve(e.to_string()))?
        .ok_or_else(|| AuthzError::Resolve("no `maknae` group".into()))
}

/// The `maknae` group's gid — used to group-own the daemon's UDS (codex round-7 P1) so the
/// 0660 mode actually gates on the `maknae` group rather than the daemon process's PRIMARY
/// group (which, under the normal service-account setup, is NOT `maknae`; `maknae` is a
/// supplementary group there). Fails closed (`Err`) if the group cannot be resolved — the
/// caller must refuse to serve rather than bind a socket group-owned by the wrong group.
pub fn maknae_gid() -> Result<nix::unistd::Gid, AuthzError> {
    Ok(resolve_maknae_group()?.gid)
}

/// Membership AND the peer's OS username, from the ONE `User::from_uid` this
/// function already performs (#275).
///
/// The name rides along rather than being fetched by a sibling helper for two
/// reasons. First, this function needs `user.name` for `gr_mem` AND `user.gid`
/// for the primary and supplementary tests, so a name-only helper could not
/// substitute for it — an edit that tried would silently delete the primary-gid
/// and `getgrouplist` branches and deny every member whose membership is not
/// explicit. Second, the caller runs this on the BLOCKING pool under a timeout
/// and a circuit breaker precisely because NSS can stall; resolving the name
/// anywhere else would put an unbounded `getpwuid` back on the async worker.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Membership {
    pub in_group: bool,
    pub user: String,
}

pub fn uid_in_maknae_group(uid: u32) -> Result<Membership, AuthzError> {
    // The USER is resolved FIRST, and deliberately so (#275). Resolving the
    // group first meant a host without a `maknae` group -- CI's ubuntu-latest
    // has none -- returned early and the connection-deny record rendered
    // `subject=unknown`, discarding an identity that was independently
    // available. The membership answer may fail; the identity should survive it.
    let user = User::from_uid(Uid::from_raw(uid))
        .map_err(|e| AuthzError::Resolve(e.to_string()))?
        .ok_or_else(|| AuthzError::Resolve(format!("no user for uid {uid}")))?;
    let name = user.name.clone();
    let member = |in_group: bool| {
        Ok(Membership {
            in_group,
            user: name.clone(),
        })
    };
    // A group that cannot be resolved is NOT a member -- fail closed -- but the
    // username stands.
    let Ok(grp) = resolve_maknae_group() else {
        return member(false);
    };
    // Explicit membership (gr_mem) — populated on both Linux and macOS (Directory Services).
    if grp.mem.contains(&user.name) {
        return member(true);
    }
    // Primary group.
    if user.gid == grp.gid {
        return member(true);
    }
    // Supplementary groups: getgrouplist exists on Linux; nix cfg-gates it OUT on Apple targets.
    #[cfg(target_os = "linux")]
    {
        use std::ffi::CString;
        let cname =
            CString::new(user.name.clone()).map_err(|e| AuthzError::Resolve(e.to_string()))?;
        // A failed supplementary-group lookup is NOT a member -- fail closed --
        // but it must not discard the username we already have (#275).
        match nix::unistd::getgrouplist(&cname, user.gid) {
            Ok(groups) if groups.contains(&grp.gid) => return member(true),
            Ok(_) => {}
            Err(_) => return member(false),
        }
    }
    member(false)
}

#[cfg(test)]
mod tests {
    use super::*;

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
        }
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
}
