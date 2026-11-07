//! Host account and group facts: the one place a uid becomes an account and its groups.
use nix::unistd::{Gid, Group, Uid, User};
use std::path::PathBuf;

pub const MAKNAE_GROUP: &str = "maknae";
pub const MAKNAE_AGENTS_GROUP: &str = "maknae-agents";
pub const MAKNAE_DAEMON_ACCOUNTS: [&str; 2] = ["_maknae", "_maknae-egress"];

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HostAccount {
    pub uid: u32,
    pub name: String,
    pub primary_gid: u32,
    pub shell: String,
    pub dir: PathBuf,
    pub groups: Vec<u32>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AccountLookupError {
    Resolve(String),
    Unanswered { user: String, why: String },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DaemonFacts {
    pub uids: Vec<u32>,
    pub gids: Vec<u32>,
}

struct Passwd {
    uid: u32,
    name: String,
    gid: u32,
    shell: String,
    dir: PathBuf,
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

fn account_of(
    user: Passwd,
    groups_db: Result<Vec<Group>, String>,
    supplementary: impl FnOnce(&str, Gid) -> Result<Vec<Gid>, String>,
) -> Result<HostAccount, AccountLookupError> {
    let unanswered = |why: String| AccountLookupError::Unanswered {
        user: user.name.clone(),
        why,
    };
    let known = groups_db.map_err(unanswered)?;
    let listed = supplementary(&user.name, Gid::from_raw(user.gid)).map_err(unanswered)?;
    let mut groups = vec![user.gid];
    let named = known
        .iter()
        .filter(|g| g.mem.iter().any(|m| m == &user.name))
        .map(|g| g.gid);
    for gid in named.chain(listed).map(Gid::as_raw) {
        if !groups.contains(&gid) {
            groups.push(gid);
        }
    }
    Ok(HostAccount {
        uid: user.uid,
        name: user.name,
        primary_gid: user.gid,
        shell: user.shell,
        dir: user.dir,
        groups,
    })
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

/// `groups` carries gr_mem membership of the Maknae groups and the daemon accounts'
/// groups only; Linux `getgrouplist` adds every other supplementary group.
pub fn host_account(uid: u32) -> Result<Option<HostAccount>, AccountLookupError> {
    let Some(user) = User::from_uid(Uid::from_raw(uid))
        .map_err(|e| AccountLookupError::Resolve(e.to_string()))?
    else {
        return Ok(None);
    };
    let daemon = daemon_facts()?;
    account_of(
        user.into(),
        maknae_groups(&daemon.gids),
        supplementary_groups,
    )
    .map(Some)
}

pub fn group_gid(name: &str) -> Result<Option<u32>, AccountLookupError> {
    Ok(Group::from_name(name)
        .map_err(|e| AccountLookupError::Resolve(e.to_string()))?
        .map(|g| g.gid.as_raw()))
}

pub fn daemon_facts() -> Result<DaemonFacts, AccountLookupError> {
    let mut facts = DaemonFacts {
        uids: Vec::new(),
        gids: Vec::new(),
    };
    for name in MAKNAE_DAEMON_ACCOUNTS {
        let user = User::from_name(name).map_err(|e| AccountLookupError::Resolve(e.to_string()))?;
        if let Some(user) = user {
            facts.uids.push(user.uid.as_raw());
            facts.gids.push(user.gid.as_raw());
        }
    }
    Ok(facts)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn passwd() -> Passwd {
        Passwd {
            uid: 1000,
            name: "ann".into(),
            gid: 100,
            shell: "/usr/sbin/nologin".into(),
            dir: "/home/ann".into(),
        }
    }

    fn group(gid: u32, mem: &[&str]) -> Group {
        Group {
            name: "g".into(),
            passwd: std::ffi::CString::new("x").unwrap(),
            gid: Gid::from_raw(gid),
            mem: mem.iter().map(|m| m.to_string()).collect(),
        }
    }

    fn account(
        db: Result<Vec<Group>, String>,
        supplementary: Result<Vec<u32>, String>,
    ) -> Result<HostAccount, AccountLookupError> {
        account_of(passwd(), db, |name, gid| {
            assert_eq!((name, gid), ("ann", Gid::from_raw(100)));
            supplementary.map(|g| g.into_iter().map(Gid::from_raw).collect())
        })
    }

    #[test]
    fn primary_gid_is_a_group() {
        assert_eq!(account(Ok(vec![]), Ok(vec![])).unwrap().groups, vec![100]);
    }

    #[test]
    fn gr_mem_membership_is_a_group() {
        let db = Ok(vec![group(900, &["ann"]), group(901, &["bob"])]);
        assert_eq!(account(db, Ok(vec![])).unwrap().groups, vec![100, 900]);
    }

    #[test]
    fn supplementary_membership_is_a_group() {
        let got = account(Ok(vec![]), Ok(vec![100, 700, 701])).unwrap();
        assert_eq!(got.groups, vec![100, 700, 701]);
    }

    #[test]
    fn a_failing_group_source_is_unanswered() {
        let unanswered = |why: &str| {
            Err(AccountLookupError::Unanswered {
                user: "ann".into(),
                why: why.into(),
            })
        };
        assert_eq!(account(Err("EIO".into()), Ok(vec![])), unanswered("EIO"));
        assert_eq!(
            account(Ok(vec![]), Err("ENOMEM".into())),
            unanswered("ENOMEM")
        );
    }

    #[test]
    fn the_shell_is_carried_verbatim() {
        let mut user = passwd();
        user.shell = "/bin/zsh -l".into();
        let got = account_of(user, Ok(vec![]), |_, _| Ok(vec![])).unwrap();
        assert_eq!(got.shell, "/bin/zsh -l");
        assert_eq!(got.dir, PathBuf::from("/home/ann"));
        assert_eq!((got.uid, got.name.as_str()), (1000, "ann"));
    }

    #[test]
    fn an_unknown_uid_is_none() {
        assert_eq!(host_account(4_000_000_000), Ok(None));
    }

    #[test]
    fn an_unknown_group_has_no_gid() {
        assert_eq!(group_gid("no-such-group-maknae-609"), Ok(None));
    }

    #[test]
    fn root_is_an_account_in_its_primary_group() {
        let root = host_account(0).unwrap().unwrap();
        assert_eq!(root.name, "root");
        assert!(root.groups.contains(&root.primary_gid));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn a_name_the_supplementary_lookup_cannot_carry_is_undecided() {
        assert!(supplementary_groups("a\0b", Gid::from_raw(0)).is_err());
    }
}
