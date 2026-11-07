use super::{AccountFact, NotCheckedWhy};

pub(super) fn host_account(_source: maknae_config::AccountSource, _uid: u32) -> AccountFact {
    AccountFact::NotChecked(NotCheckedWhy::Platform)
}
