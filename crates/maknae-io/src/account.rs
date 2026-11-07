//! Host account and group facts: the one place a uid becomes an account and its groups.
use crate::account_facts::{
    account_of, named_group_db, AccountLookupError, DaemonFacts, HostAccount, Passwd,
    MAKNAE_AGENTS_GROUP, MAKNAE_DAEMON_ACCOUNTS, MAKNAE_GROUP,
};
use nix::errno::Errno;
use nix::unistd::{Gid, Group, Uid, User};

/// The passwd and group lookups report "not found" as `Ok(None)`, `ENOENT`, `ESRCH`,
/// `EBADF` or `EPERM`; every other errno, `ERANGE` and errno 0 included, is a failure.
pub fn not_found_is_none<T>(r: Result<Option<T>, Errno>) -> Result<Option<T>, Errno> {
    match r {
        Ok(found) => Ok(found),
        Err(Errno::ENOENT | Errno::ESRCH | Errno::EBADF | Errno::EPERM) => Ok(None),
        Err(e) => Err(e),
    }
}

// nix reads errno on a non-zero return; macOS getpw*_r returns ERANGE without setting
// it, so a stale not-found errno must not survive to the classification.
fn getpwuid(uid: u32) -> Result<Option<User>, Errno> {
    Errno::clear();
    User::from_uid(Uid::from_raw(uid))
}

pub fn user_by_uid(uid: u32) -> Result<Option<User>, Errno> {
    not_found_is_none(getpwuid(uid))
}

pub fn user_by_name(name: &str) -> Result<Option<User>, Errno> {
    Errno::clear();
    not_found_is_none(User::from_name(name))
}

pub fn group_by_name(name: &str) -> Result<Option<Group>, Errno> {
    Errno::clear();
    not_found_is_none(Group::from_name(name))
}

pub fn group_by_gid(gid: u32) -> Result<Option<Group>, Errno> {
    Errno::clear();
    not_found_is_none(Group::from_gid(Gid::from_raw(gid)))
}

impl From<User> for Passwd {
    fn from(u: User) -> Self {
        Passwd {
            uid: u.uid.as_raw(),
            name: u.name,
            gid: u.gid.as_raw(),
            shell: u.shell.to_string_lossy().into_owned(),
            dir: u.dir,
        }
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

fn maknae_groups(daemon_gids: &[u32]) -> Result<Vec<Group>, String> {
    let named = [MAKNAE_GROUP, MAKNAE_AGENTS_GROUP]
        .into_iter()
        .map(|n| group_by_name(n).map_err(|e| e.to_string()));
    let daemon = daemon_gids
        .iter()
        .map(|g| group_by_gid(*g).map_err(|e| e.to_string()));
    let mut found = Vec::new();
    for group in named.chain(daemon) {
        found.extend(group?);
    }
    Ok(found)
}

pub fn host_account(uid: u32) -> Result<Option<HostAccount>, AccountLookupError> {
    account_with(uid, getpwuid)
}

fn account_with(
    uid: u32,
    lookup: fn(u32) -> Result<Option<User>, Errno>,
) -> Result<Option<HostAccount>, AccountLookupError> {
    let Some(user) =
        not_found_is_none(lookup(uid)).map_err(|e| AccountLookupError::Resolve(e.to_string()))?
    else {
        return Ok(None);
    };
    let groups_db = named_group_db(&user.name, daemon_facts(), maknae_groups)?;
    account_of(user.into(), Ok(groups_db), supplementary_groups).map(Some)
}

pub fn group_gid(name: &str) -> Result<Option<u32>, AccountLookupError> {
    Ok(group_by_name(name)
        .map_err(|e| AccountLookupError::Resolve(e.to_string()))?
        .map(|g| g.gid.as_raw()))
}

pub fn daemon_facts() -> Result<DaemonFacts, AccountLookupError> {
    let resolve = |e: nix::Error| AccountLookupError::Resolve(e.to_string());
    let mut users = Vec::new();
    let mut groups = Vec::new();
    for name in MAKNAE_DAEMON_ACCOUNTS {
        if let Some(user) = user_by_name(name).map_err(resolve)? {
            users.push((user.uid.as_raw(), user.gid.as_raw()));
        }
        if let Some(group) = group_by_name(name).map_err(resolve)? {
            groups.push(group.gid.as_raw());
        }
    }
    Ok(DaemonFacts::assemble(&users, &groups))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn each_not_found_errno_is_none_and_any_other_errno_is_a_failure() {
        for e in [Errno::ENOENT, Errno::ESRCH, Errno::EBADF, Errno::EPERM] {
            assert_eq!(not_found_is_none::<u32>(Err(e)), Ok(None), "{e}");
        }
        for e in [Errno::ERANGE, Errno::EIO, Errno::UnknownErrno] {
            assert_eq!(not_found_is_none::<u32>(Err(e)), Err(e), "{e}");
        }
        assert_eq!(not_found_is_none(Ok(Some(7))), Ok(Some(7)));
        assert_eq!(not_found_is_none::<u32>(Ok(None)), Ok(None));
    }

    #[test]
    fn a_uid_whose_lookup_says_enoent_has_no_account() {
        assert_eq!(account_with(2001, |_| Err(Errno::ENOENT)), Ok(None));
        assert!(matches!(
            account_with(2001, |_| Err(Errno::EIO)),
            Err(AccountLookupError::Resolve(_))
        ));
    }

    #[test]
    fn an_unknown_uid_is_none() {
        assert_eq!(host_account(4_000_000_000), Ok(None));
    }

    #[test]
    fn an_unknown_group_has_no_gid() {
        assert_eq!(group_gid("no-such-group-maknae-609"), Ok(None));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn a_name_the_supplementary_lookup_cannot_carry_is_undecided() {
        assert!(supplementary_groups("a\0b", Gid::from_raw(0)).is_err());
    }
}
