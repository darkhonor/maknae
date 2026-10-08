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

fn group(gid: nix::unistd::Gid) -> Result<Option<Group>, String> {
    Errno::clear();
    found(Group::from_gid(gid))
}

impl ReaderLookup for NssAccounts {
    fn account(&self, name: &str) -> Result<Option<ReaderAccount>, String> {
        let Some(u) = user(name)? else {
            return Ok(None);
        };
        let groups = match user(DAEMON_ACCOUNT)? {
            Some(daemon) => match group(daemon.gid)? {
                Some(g) if g.mem.iter().any(|m| m == name) => vec![g.gid.as_raw()],
                _ => Vec::new(),
            },
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
}
