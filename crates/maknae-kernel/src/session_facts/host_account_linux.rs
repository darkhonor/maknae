use super::{
    account_linux, is_local_linux, AccountFact, AccountState, NotCheckedWhy, USERDB_DEADLINE,
};

pub(super) fn host_account(source: maknae_config::AccountSource, uid: u32) -> AccountFact {
    account_from(
        source,
        || is_local_linux(uid),
        || account_linux(uid, USERDB_DEADLINE),
    )
}

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

#[cfg(test)]
mod tests {
    use super::*;
    use maknae_config::AccountSource;

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
}
