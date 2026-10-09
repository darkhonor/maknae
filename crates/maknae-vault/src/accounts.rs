//! The production [`ReaderLookup`]: the host's account database through NSS.

use maknae_config::{ReaderAccount, ReaderLookup};
use nix::errno::Errno;
use nix::unistd::{Group, User};

const DAEMON_ACCOUNT: &str = "_maknae";
const EGRESS_ACCOUNT: &str = "_maknae-egress";

pub struct NssAccounts;

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

fn daemon_members(g: Option<Group>) -> Result<Vec<String>, String> {
    g.map(|g| g.mem)
        .ok_or_else(|| format!("{DAEMON_ACCOUNT}'s primary group has no group entry"))
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

#[cfg(target_os = "linux")]
fn listed_groups(u: &User) -> Result<Vec<u32>, String> {
    let name = std::ffi::CString::new(u.name.as_bytes()).map_err(|e| e.to_string())?;
    nix::unistd::getgrouplist(&name, u.gid)
        .map(|gids| gids.into_iter().map(|g| g.as_raw()).collect())
        .map_err(|e| format!("group list lookup failed (errno {})", e as i32))
}

#[cfg(not(target_os = "linux"))]
fn listed_groups(_: &User) -> Result<Vec<u32>, String> {
    Ok(Vec::new())
}

impl ReaderLookup for NssAccounts {
    fn account(&self, name: &str) -> Result<Option<ReaderAccount>, String> {
        let Some(u) = user(name)? else {
            return Ok(None);
        };
        let groups = match user(DAEMON_ACCOUNT)? {
            Some(daemon) => {
                let members = daemon_members(group(daemon.gid)?)?;
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
        Ok(user(DAEMON_ACCOUNT)?.map(|u| u.gid.as_raw()))
    }

    fn service_uids(&self) -> Result<Vec<u32>, String> {
        let mut uids = Vec::new();
        for name in [DAEMON_ACCOUNT, EGRESS_ACCOUNT] {
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
        let root = NssAccounts.account("root").unwrap().expect("root exists");
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
            daemon_members(None),
            Err("_maknae's primary group has no group entry".to_string())
        );
        let g = Group {
            name: "_maknae".into(),
            passwd: std::ffi::CString::default(),
            gid: nix::unistd::Gid::from_raw(7),
            mem: vec!["alice".into()],
        };
        assert_eq!(daemon_members(Some(g)), Ok(vec!["alice".to_string()]));
    }

    #[test]
    fn a_missing_account_is_none() {
        assert_eq!(
            NssAccounts.account("no-such-user-maknae-490").unwrap(),
            None
        );
    }

    #[test]
    fn the_service_lookups_answer() {
        assert!(NssAccounts.daemon_gid().is_ok());
        assert!(NssAccounts.service_uids().is_ok());
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
        let root = User::from_name("root").unwrap().unwrap();
        assert!(listed_groups(&root).unwrap().contains(&0));
    }
}
