//! Host facts the kernel re-reads for a bound session (#115): the local
//! account's state.

#[cfg(target_os = "linux")]
mod userdb;
#[cfg(target_os = "linux")]
mod varlink;

#[cfg(target_os = "linux")]
pub use userdb::{account_linux, is_local_linux, USERDB_DEADLINE};

pub(crate) const USERDB_MULTIPLEXER: &str = "/run/systemd/userdb/io.systemd.Multiplexer";

/// The state of a local account as its source reports it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AccountState {
    Active,
    Disabled,
    Locked,
    Expired,
    Unknown(String),
}

/// An account state, or the stated reason none was read.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AccountFact {
    Checked(AccountState),
    NotChecked(NotCheckedWhy),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NotCheckedWhy {
    DirectoryAccount,
    Platform,
    Configured,
}

/// The facts as this host's own sources report them.
pub struct HostSessionFacts {
    pub account_source: maknae_config::AccountSource,
}

impl crate::session::SessionFacts for HostSessionFacts {
    fn membership(
        &self,
        admission: crate::handler::Admission,
        uid: u32,
    ) -> Result<crate::groupres::Membership, crate::groupres::AuthzError> {
        match admission {
            crate::handler::Admission::MaknaeGroupMember => {
                crate::groupres::uid_in_maknae_group(uid)
            }
        }
    }

    fn account(&self, uid: u32) -> AccountFact {
        host_account(self.account_source, uid)
    }
}

#[cfg(target_os = "linux")]
fn host_account(source: maknae_config::AccountSource, uid: u32) -> AccountFact {
    account_from(
        source,
        || is_local_linux(uid),
        || account_linux(uid, USERDB_DEADLINE),
    )
}

#[cfg(target_os = "linux")]
fn account_from(
    source: maknae_config::AccountSource,
    local: impl FnOnce() -> Result<bool, String>,
    state: impl FnOnce() -> AccountState,
) -> AccountFact {
    match source {
        maknae_config::AccountSource::None => AccountFact::NotChecked(NotCheckedWhy::Configured),
        maknae_config::AccountSource::Userdb => match local() {
            Ok(true) => AccountFact::Checked(state()),
            Ok(false) => AccountFact::NotChecked(NotCheckedWhy::DirectoryAccount),
            Err(_) => AccountFact::Checked(AccountState::Unknown("passwd unreadable".into())),
        },
    }
}

#[cfg(target_os = "macos")]
fn host_account(_source: maknae_config::AccountSource, _uid: u32) -> AccountFact {
    AccountFact::NotChecked(NotCheckedWhy::Platform)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::session::SessionFacts;
    use maknae_config::AccountSource;

    fn host(account_source: AccountSource) -> HostSessionFacts {
        HostSessionFacts { account_source }
    }

    #[test]
    fn membership_is_the_hosts_user_database() {
        let me = nix::unistd::geteuid();
        let name = nix::unistd::User::from_uid(me)
            .expect("NSS")
            .expect("the test euid has a passwd entry")
            .name;
        let got = host(AccountSource::None)
            .membership(crate::handler::Admission::MaknaeGroupMember, me.as_raw())
            .expect("the euid resolves");
        assert_eq!(got.user, name);
        assert_eq!(
            host(AccountSource::None)
                .membership(crate::handler::Admission::MaknaeGroupMember, 4_000_000_000),
            Err(crate::groupres::AuthzError::NoUser)
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn only_a_local_account_is_checked_and_only_when_a_source_is_declared() {
        let never = || -> Result<bool, String> { panic!("no source is declared") };
        assert_eq!(
            account_from(AccountSource::None, never, || AccountState::Active),
            AccountFact::NotChecked(NotCheckedWhy::Configured)
        );
        assert_eq!(
            account_from(AccountSource::Userdb, || Ok(true), || AccountState::Locked),
            AccountFact::Checked(AccountState::Locked)
        );
        assert_eq!(
            account_from(
                AccountSource::Userdb,
                || Ok(false),
                || panic!("a directory account is not asked of userdb")
            ),
            AccountFact::NotChecked(NotCheckedWhy::DirectoryAccount)
        );
        assert_eq!(
            account_from(
                AccountSource::Userdb,
                || Err("EACCES".into()),
                || AccountState::Active
            ),
            AccountFact::Checked(AccountState::Unknown("passwd unreadable".into()))
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn the_host_account_follows_the_declared_source() {
        assert_eq!(
            host(AccountSource::None).account(0),
            AccountFact::NotChecked(NotCheckedWhy::Configured)
        );
        assert_eq!(
            host(AccountSource::Userdb).account(4_000_000_000),
            AccountFact::NotChecked(NotCheckedWhy::DirectoryAccount)
        );
        assert!(matches!(
            host(AccountSource::Userdb).account(0),
            AccountFact::Checked(_)
        ));
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn macos_reads_no_account_state() {
        for source in [AccountSource::None, AccountSource::Userdb] {
            assert_eq!(
                host(source).account(0),
                AccountFact::NotChecked(NotCheckedWhy::Platform)
            );
        }
    }
}
