//! Host account and group facts: the one place a uid becomes an account and its groups.
use crate::account_facts::{
    account_of, named_group_db, AccountLookupError, DaemonFacts, HostAccount, Passwd,
    MAKNAE_AGENTS_GROUP, MAKNAE_DAEMON_ACCOUNTS, MAKNAE_GROUP,
};
use nix::unistd::{Gid, Group, Uid, User};

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
        .map(|n| Group::from_name(n).map_err(|e| e.to_string()));
    let daemon = daemon_gids
        .iter()
        .map(|g| Group::from_gid(Gid::from_raw(*g)).map_err(|e| e.to_string()));
    let mut found = Vec::new();
    for group in named.chain(daemon) {
        found.extend(group?);
    }
    Ok(found)
}

pub fn host_account(uid: u32) -> Result<Option<HostAccount>, AccountLookupError> {
    let Some(user) = User::from_uid(Uid::from_raw(uid))
        .map_err(|e| AccountLookupError::Resolve(e.to_string()))?
    else {
        return Ok(None);
    };
    let groups_db = named_group_db(&user.name, daemon_facts(), maknae_groups)?;
    account_of(user.into(), Ok(groups_db), supplementary_groups).map(Some)
}

pub fn group_gid(name: &str) -> Result<Option<u32>, AccountLookupError> {
    Ok(Group::from_name(name)
        .map_err(|e| AccountLookupError::Resolve(e.to_string()))?
        .map(|g| g.gid.as_raw()))
}

pub fn daemon_facts() -> Result<DaemonFacts, AccountLookupError> {
    let resolve = |e: nix::Error| AccountLookupError::Resolve(e.to_string());
    let mut users = Vec::new();
    let mut groups = Vec::new();
    for name in MAKNAE_DAEMON_ACCOUNTS {
        if let Some(user) = User::from_name(name).map_err(resolve)? {
            users.push((user.uid.as_raw(), user.gid.as_raw()));
        }
        if let Some(group) = Group::from_name(name).map_err(resolve)? {
            groups.push(group.gid.as_raw());
        }
    }
    Ok(DaemonFacts::assemble(&users, &groups))
}

#[cfg(test)]
mod tests {
    use super::*;

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
