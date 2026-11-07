//! Peer-uid → `maknae`-group membership (spec §5). T3 I/O; fail-closed. CROSS-PLATFORM.
use nix::unistd::{Gid, Group, Uid, User};

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

/// Shared by [`uid_in_maknae_group`] and [`maknae_gid`] so the group name is
/// hardcoded in exactly one place.
const MAKNAE_GROUP: &str = "maknae";

fn resolve_maknae_group() -> Result<Group, AuthzError> {
    Group::from_name(MAKNAE_GROUP)
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
///
/// The raw home rides the same record so that the PDP and the PEP get one value (#435).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Membership {
    pub in_group: bool,
    pub user: String,
    pub dir: std::path::PathBuf,
}

pub use maknae_io::canonical_home;

pub fn uid_in_maknae_group(uid: u32) -> Result<Membership, AuthzError> {
    // The USER is resolved FIRST, and deliberately so (#275). Resolving the
    // group first meant a host without a `maknae` group -- CI's ubuntu-latest
    // has none -- returned early and the connection-deny record rendered
    // `subject=unknown`, discarding an identity that was independently
    // available. The membership answer may fail; the identity should survive it.
    let user = User::from_uid(Uid::from_raw(uid))
        .map_err(|e| AuthzError::Resolve(e.to_string()))?
        .ok_or(AuthzError::NoUser)?;
    membership_of(
        &user.name,
        user.gid,
        user.dir,
        Group::from_name(MAKNAE_GROUP).map_err(|e| e.to_string()),
        supplementary_groups,
    )
}

/// A failed group source leaves membership undecided (an infrastructure denial)
/// and keeps the username; a host with no `maknae` group is an answer.
fn membership_of(
    name: &str,
    gid: Gid,
    dir: std::path::PathBuf,
    group: Result<Option<Group>, String>,
    supplementary: impl FnOnce(&str, Gid) -> Result<Vec<Gid>, String>,
) -> Result<Membership, AuthzError> {
    let member = |in_group: bool| {
        Ok(Membership {
            in_group,
            user: name.to_string(),
            dir,
        })
    };
    let unanswered = |why: String| {
        Err(AuthzError::Unanswered {
            user: name.to_string(),
            why,
        })
    };
    let grp = match group {
        Ok(Some(grp)) => grp,
        Ok(None) => return member(false),
        Err(why) => return unanswered(why),
    };
    // Explicit membership (gr_mem) — populated on both Linux and macOS (Directory Services).
    if grp.mem.iter().any(|m| m == name) || gid == grp.gid {
        return member(true);
    }
    match supplementary(name, gid) {
        Ok(groups) => member(groups.contains(&grp.gid)),
        Err(why) => unanswered(why),
    }
}

#[cfg(target_os = "linux")]
fn supplementary_groups(name: &str, gid: Gid) -> Result<Vec<Gid>, String> {
    let cname = std::ffi::CString::new(name).map_err(|e| e.to_string())?;
    nix::unistd::getgrouplist(&cname, gid).map_err(|e| e.to_string())
}

// nix cfg-gates getgrouplist out on Apple targets; gr_mem carries membership there.
#[cfg(not(target_os = "linux"))]
fn supplementary_groups(_name: &str, _gid: Gid) -> Result<Vec<Gid>, String> {
    Ok(Vec::new())
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
            Err(AuthzError::NoUser | AuthzError::Unanswered { .. }) => {
                panic!("the gid lookup names no user")
            }
        }
    }

    fn group(gid: u32, mem: &[&str]) -> Group {
        Group {
            name: MAKNAE_GROUP.into(),
            passwd: std::ffi::CString::new("x").unwrap(),
            gid: Gid::from_raw(gid),
            mem: mem.iter().map(|m| m.to_string()).collect(),
        }
    }

    fn decide(
        primary: u32,
        lookup: Result<Option<Group>, String>,
        supplementary: Result<Vec<u32>, String>,
    ) -> Result<Membership, AuthzError> {
        membership_of(
            "ann",
            Gid::from_raw(primary),
            "/home/ann".into(),
            lookup,
            |name, gid| {
                assert_eq!((name, gid), ("ann", Gid::from_raw(primary)));
                supplementary.map(|g| g.into_iter().map(Gid::from_raw).collect())
            },
        )
    }

    fn answered(in_group: bool) -> Result<Membership, AuthzError> {
        Ok(Membership {
            in_group,
            user: "ann".into(),
            dir: "/home/ann".into(),
        })
    }

    fn unanswered(why: &str) -> Result<Membership, AuthzError> {
        Err(AuthzError::Unanswered {
            user: "ann".into(),
            why: why.into(),
        })
    }

    #[test]
    fn each_group_source_answer_decides_membership_or_leaves_it_undecided() {
        let never = || Err::<Vec<u32>, _>("not asked".to_string());
        assert_eq!(decide(100, Ok(None), never()), answered(false));
        assert_eq!(decide(100, Err("EIO".into()), never()), unanswered("EIO"));
        assert_eq!(
            decide(100, Ok(Some(group(900, &["ann"]))), never()),
            answered(true)
        );
        assert_eq!(
            decide(900, Ok(Some(group(900, &[]))), never()),
            answered(true)
        );
        assert_eq!(
            decide(100, Ok(Some(group(900, &["bob"]))), Ok(vec![100, 900])),
            answered(true)
        );
        assert_eq!(
            decide(100, Ok(Some(group(900, &[]))), Ok(vec![100])),
            answered(false)
        );
        assert_eq!(
            decide(100, Ok(Some(group(900, &[]))), Err("ENOMEM".into())),
            unanswered("ENOMEM")
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn a_name_the_supplementary_lookup_cannot_carry_is_undecided() {
        assert!(supplementary_groups("a\0b", Gid::from_raw(0)).is_err());
        assert!(supplementary_groups(
            &nix::unistd::User::from_uid(nix::unistd::geteuid())
                .unwrap()
                .unwrap()
                .name,
            nix::unistd::getegid()
        )
        .is_ok());
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
