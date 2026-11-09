//! The pure assembly of a host account from its passwd record and group sources.
use nix::unistd::{Gid, Group};
use std::path::PathBuf;

pub const MAKNAE_GROUP: &str = "maknae";
pub const MAKNAE_AGENTS_GROUP: &str = "maknae-agents";
pub const MAKNAE_DAEMON_ACCOUNTS: [&str; 2] = ["_maknae", "_maknae-egress"];

/// `named_groups` is the account's membership among the groups Maknae names (`maknae`,
/// `maknae-agents`, the daemon accounts' primary groups) plus its primary gid. It is
/// not the account's complete group list, on either platform.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HostAccount {
    pub uid: u32,
    pub name: String,
    pub primary_gid: u32,
    pub shell: String,
    pub dir: PathBuf,
    pub named_groups: Vec<u32>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AccountLookupError {
    Resolve(String),
    Unanswered { user: String, why: String },
}

impl std::fmt::Display for AccountLookupError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Resolve(why) => write!(f, "host account lookup failed: {why}"),
            Self::Unanswered { user, why } => {
                write!(f, "the groups of account {user} could not be read: {why}")
            }
        }
    }
}

impl std::error::Error for AccountLookupError {}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DaemonFacts {
    pub uids: Vec<u32>,
    pub gids: Vec<u32>,
}

impl DaemonFacts {
    /// `users` is each daemon user's `(uid, primary gid)`; `groups` is each daemon
    /// group's gid, which need not equal its user's primary gid.
    pub fn assemble(users: &[(u32, u32)], groups: &[u32]) -> DaemonFacts {
        let mut gids: Vec<u32> = Vec::new();
        for gid in users.iter().map(|u| u.1).chain(groups.iter().copied()) {
            if !gids.contains(&gid) {
                gids.push(gid);
            }
        }
        DaemonFacts {
            uids: users.iter().map(|u| u.0).collect(),
            gids,
        }
    }
}

pub(crate) struct Passwd {
    pub uid: u32,
    pub name: String,
    pub gid: u32,
    pub shell: String,
    pub dir: PathBuf,
}

pub(crate) fn named_group_db(
    user: &str,
    daemon: Result<DaemonFacts, AccountLookupError>,
    load: impl FnOnce(&[u32]) -> Result<Vec<Group>, String>,
) -> Result<Vec<Group>, AccountLookupError> {
    let unanswered = |why: String| AccountLookupError::Unanswered {
        user: user.to_string(),
        why,
    };
    let daemon = daemon.map_err(|e| match e {
        AccountLookupError::Resolve(why) | AccountLookupError::Unanswered { why, .. } => {
            unanswered(why)
        }
    })?;
    load(&daemon.gids).map_err(unanswered)
}

pub(crate) fn account_of(
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
    let named_gids: Vec<Gid> = known.iter().map(|g| g.gid).collect();
    let mut groups = vec![user.gid];
    let members = known
        .iter()
        .filter(|g| g.mem.iter().any(|m| m == &user.name))
        .map(|g| g.gid);
    let listed = listed.into_iter().filter(|g| named_gids.contains(g));
    for gid in members.chain(listed).map(Gid::as_raw) {
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
        named_groups: groups,
    })
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

    fn unanswered(why: &str) -> AccountLookupError {
        AccountLookupError::Unanswered {
            user: "ann".into(),
            why: why.into(),
        }
    }

    #[test]
    fn primary_gid_is_a_group() {
        let got = account(Ok(vec![]), Ok(vec![])).unwrap();
        assert_eq!(got.named_groups, vec![100]);
    }

    #[test]
    fn gr_mem_membership_is_a_group() {
        let db = Ok(vec![group(900, &["ann"]), group(901, &["bob"])]);
        assert_eq!(
            account(db, Ok(vec![])).unwrap().named_groups,
            vec![100, 900]
        );
    }

    #[test]
    fn supplementary_membership_is_a_group_when_the_group_is_named() {
        let db = Ok(vec![group(700, &[]), group(701, &[])]);
        let got = account(db, Ok(vec![100, 700, 701, 555])).unwrap();
        assert_eq!(got.named_groups, vec![100, 700, 701]);
    }

    #[test]
    fn a_supplementary_group_nobody_named_is_not_reported() {
        let got = account(Ok(vec![]), Ok(vec![100, 555])).unwrap();
        assert_eq!(got.named_groups, vec![100]);
    }

    #[test]
    fn a_failing_group_source_is_unanswered() {
        assert_eq!(
            account(Err("EIO".into()), Ok(vec![])),
            Err(unanswered("EIO"))
        );
        assert_eq!(
            account(Ok(vec![]), Err("ENOMEM".into())),
            Err(unanswered("ENOMEM"))
        );
    }

    #[test]
    fn a_failing_daemon_source_keeps_the_user_name() {
        let load = |_: &[u32]| -> Result<Vec<Group>, String> { Ok(vec![]) };
        for e in [
            AccountLookupError::Resolve("EIO".into()),
            AccountLookupError::Unanswered {
                user: "x".into(),
                why: "EIO".into(),
            },
        ] {
            assert_eq!(
                named_group_db("ann", Err(e), load).map(|_| ()),
                Err(unanswered("EIO"))
            );
        }
        let failing = |_: &[u32]| -> Result<Vec<Group>, String> { Err("EBUSY".into()) };
        let daemon = DaemonFacts {
            uids: vec![],
            gids: vec![7],
        };
        assert_eq!(
            named_group_db("ann", Ok(daemon), failing).map(|_| ()),
            Err(unanswered("EBUSY"))
        );
    }

    #[test]
    fn a_daemon_group_whose_gid_differs_from_its_users_is_a_daemon_gid() {
        assert_eq!(
            DaemonFacts::assemble(&[(970, 970), (971, 971)], &[970, 975]),
            DaemonFacts {
                uids: vec![970, 971],
                gids: vec![970, 971, 975],
            }
        );
    }

    #[test]
    fn a_daemon_group_without_its_user_is_a_daemon_gid() {
        assert_eq!(
            DaemonFacts::assemble(&[], &[975]),
            DaemonFacts {
                uids: vec![],
                gids: vec![975],
            }
        );
        assert_eq!(
            DaemonFacts::assemble(&[(970, 970)], &[]),
            DaemonFacts {
                uids: vec![970],
                gids: vec![970],
            }
        );
    }

    #[test]
    fn a_lookup_error_renders_its_cause() {
        assert_eq!(
            AccountLookupError::Resolve("EIO".into()).to_string(),
            "host account lookup failed: EIO"
        );
        assert_eq!(
            unanswered("EIO").to_string(),
            "the groups of account ann could not be read: EIO"
        );
    }

    #[test]
    fn the_daemon_gids_reach_the_group_loader() {
        let daemon = DaemonFacts {
            uids: vec![],
            gids: vec![7, 8],
        };
        let got = named_group_db("ann", Ok(daemon), |gids| {
            assert_eq!(gids, [7, 8]);
            Ok(vec![group(7, &[])])
        });
        assert_eq!(got.unwrap().len(), 1);
    }

    #[test]
    fn the_shell_is_carried_verbatim() {
        let mut user = passwd();
        user.shell = "/bin/zsh -l".into();
        let got = account_of(user, Ok(vec![]), |_, _| Ok(vec![])).unwrap();
        assert_eq!(got.shell, "/bin/zsh -l");
        assert_eq!(got.dir, PathBuf::from("/home/ann"));
        assert_eq!((got.uid, got.name.as_str()), (1000, "ann"));
        assert_eq!(got.primary_gid, 100);
    }
}
