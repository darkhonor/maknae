//! The production [`ReaderLookup`]: the host's account database through NSS.

use maknae_config::{ReaderAccount, ReaderLookup};
use nix::errno::Errno;
use nix::unistd::{Group, User};

const DAEMON_ACCOUNT: &str = "_maknae";
const EGRESS_ACCOUNT: &str = "_maknae-egress";

pub struct NssAccounts {
    daemon: &'static str,
    egress: &'static str,
}

impl NssAccounts {
    pub const HOST: Self = Self {
        daemon: DAEMON_ACCOUNT,
        egress: EGRESS_ACCOUNT,
    };
}

/// getpwnam(3)'s "not found" spellings are `Ok(None)`, `ENOENT`, `ESRCH`, `EBADF`
/// and `EPERM`; every other errno, `ERANGE` and errno 0 included, is a failed lookup.
fn found<T>(r: Result<Option<T>, Errno>) -> Result<Option<T>, String> {
    match r {
        Ok(found) => Ok(found),
        Err(Errno::ENOENT | Errno::ESRCH | Errno::EBADF | Errno::EPERM) => Ok(None),
        Err(e) => Err(format!("account lookup failed (errno {})", e as i32)),
    }
}

// nix reads errno on a non-zero return; macOS getpwnam_r returns ERANGE without
// setting it, so a stale not-found errno must not survive to the classification.
fn user(name: &str) -> Result<Option<User>, String> {
    Errno::clear();
    found(User::from_name(name))
}

/// An account's uid, `Ok(None)` when it does not exist, classified as every lookup here is.
pub fn account_uid(name: &str) -> Result<Option<u32>, String> {
    Ok(user(name)?.map(|u| u.uid.as_raw()))
}

fn group(gid: nix::unistd::Gid) -> Result<Option<Group>, String> {
    Errno::clear();
    found(Group::from_gid(gid))
}

fn daemon_members(daemon: &str, g: Option<Group>) -> Result<Vec<String>, String> {
    g.map(|g| g.mem)
        .ok_or_else(|| format!("{daemon}'s primary group has no group entry"))
}

fn daemon_membership(
    resolved: &str,
    daemon_gid: u32,
    members: &[String],
    listed: &[u32],
) -> Vec<u32> {
    if members.iter().any(|m| m == resolved) || listed.contains(&daemon_gid) {
        vec![daemon_gid]
    } else {
        Vec::new()
    }
}

fn listed_groups(u: &User) -> Result<Vec<u32>, String> {
    #[cfg(target_os = "linux")]
    {
        let name = std::ffi::CString::new(u.name.as_bytes()).map_err(|e| e.to_string())?;
        nix::unistd::getgrouplist(&name, u.gid)
            .map(|gids| gids.into_iter().map(|g| g.as_raw()).collect())
            .map_err(|e| format!("group list lookup failed (errno {})", e as i32))
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = u;
        Ok(Vec::new())
    }
}

impl ReaderLookup for NssAccounts {
    fn account(&self, name: &str) -> Result<Option<ReaderAccount>, String> {
        let Some(u) = user(name)? else {
            return Ok(None);
        };
        let groups = match user(self.daemon)? {
            Some(daemon) => {
                let members = daemon_members(self.daemon, group(daemon.gid)?)?;
                daemon_membership(&u.name, daemon.gid.as_raw(), &members, &listed_groups(&u)?)
            }
            None => Vec::new(),
        };
        Ok(Some(ReaderAccount {
            name: u.name,
            uid: u.uid.as_raw(),
            gid: u.gid.as_raw(),
            groups,
        }))
    }

    fn daemon_gid(&self) -> Result<Option<u32>, String> {
        Ok(user(self.daemon)?.map(|u| u.gid.as_raw()))
    }

    fn service_uids(&self) -> Result<Vec<u32>, String> {
        let mut uids = Vec::new();
        for name in [self.daemon, self.egress] {
            if let Some(u) = user(name)? {
                uids.push(u.uid.as_raw());
            }
        }
        Ok(uids)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn root_resolves_to_uid_zero() {
        let root = NssAccounts::HOST
            .account("root")
            .unwrap()
            .expect("root exists");
        assert_eq!((root.name.as_str(), root.uid), ("root", 0));
    }

    #[test]
    fn an_account_uid_is_classified_like_every_other_lookup() {
        assert_eq!(account_uid("root"), Ok(Some(0)));
        assert_eq!(account_uid("no-such-user-maknae-490"), Ok(None));
    }

    #[test]
    fn a_daemon_group_with_no_entry_refuses() {
        assert_eq!(
            daemon_members(DAEMON_ACCOUNT, None),
            Err("_maknae's primary group has no group entry".to_string())
        );
        let g = Group {
            name: "_maknae".into(),
            passwd: std::ffi::CString::default(),
            gid: nix::unistd::Gid::from_raw(7),
            mem: vec!["alice".into()],
        };
        assert_eq!(
            daemon_members(DAEMON_ACCOUNT, Some(g)),
            Ok(vec!["alice".to_string()])
        );
    }

    #[test]
    fn a_missing_account_is_none() {
        assert_eq!(
            NssAccounts::HOST
                .account("no-such-user-maknae-490")
                .unwrap(),
            None
        );
    }

    const MISSING: &str = "no-such-user-maknae-490";

    fn host(name: &str) -> Option<User> {
        User::from_name(name).unwrap()
    }

    #[test]
    fn the_service_lookups_are_the_named_accounts_ids() {
        let nobody = host("nobody").expect("nobody exists");
        let (uid, gid) = (nobody.uid.as_raw(), nobody.gid.as_raw());
        assert!(uid > 1 && gid > 1, "{uid} {gid}");
        let present = NssAccounts {
            daemon: "nobody",
            egress: "root",
        };
        assert_eq!(present.daemon_gid(), Ok(Some(gid)));
        assert_eq!(present.service_uids(), Ok(vec![uid, 0]));
        let absent = NssAccounts {
            daemon: MISSING,
            egress: MISSING,
        };
        assert_eq!(absent.daemon_gid(), Ok(None));
        assert_eq!(absent.service_uids(), Ok(Vec::new()));
        assert_eq!(
            absent.account("root").unwrap().unwrap().groups,
            Vec::<u32>::new()
        );
    }

    #[test]
    fn the_production_lookups_name_the_maknae_accounts() {
        let accounts = NssAccounts::HOST;
        let daemon = host(DAEMON_ACCOUNT);
        assert_eq!(
            accounts.daemon_gid(),
            Ok(daemon.as_ref().map(|u| u.gid.as_raw()))
        );
        let uids: Vec<u32> = [daemon, host(EGRESS_ACCOUNT)]
            .into_iter()
            .flatten()
            .map(|u| u.uid.as_raw())
            .collect();
        assert_eq!(accounts.service_uids(), Ok(uids));
    }

    #[test]
    fn only_the_not_found_spellings_are_absent() {
        for e in [Errno::ENOENT, Errno::ESRCH, Errno::EBADF, Errno::EPERM] {
            assert_eq!(found::<u32>(Err(e)), Ok(None), "{e}");
        }
        assert_eq!(found(Ok(Some(7))), Ok(Some(7)));
        assert_eq!(found::<u32>(Ok(None)), Ok(None));
        for e in [Errno::ERANGE, Errno::UnknownErrno, Errno::EIO] {
            assert_eq!(
                found::<u32>(Err(e)),
                Err(format!("account lookup failed (errno {})", e as i32))
            );
        }
    }

    #[test]
    fn membership_is_judged_on_the_resolved_name_and_the_host_group_list() {
        let members = ["realname".to_string()];
        assert_eq!(daemon_membership("realname", 970, &members, &[]), vec![970]);
        assert_eq!(
            daemon_membership("alias", 970, &members, &[]),
            Vec::<u32>::new()
        );
        assert_eq!(daemon_membership("other", 970, &[], &[20, 970]), vec![970]);
        assert_eq!(
            daemon_membership("other", 970, &[], &[20]),
            Vec::<u32>::new()
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn the_host_group_list_includes_the_primary_group() {
        let root = host("root").unwrap();
        assert!(listed_groups(&root).unwrap().contains(&0));
        let nobody = host("nobody").unwrap();
        let listed = listed_groups(&nobody).unwrap();
        assert!(listed.contains(&nobody.gid.as_raw()), "{listed:?}");
        assert!(!listed.contains(&0) && !listed.contains(&1), "{listed:?}");
    }

    #[cfg(not(target_os = "linux"))]
    #[test]
    fn the_host_group_list_is_empty_off_linux() {
        assert_eq!(listed_groups(&host("root").unwrap()), Ok(Vec::new()));
    }
}
