//! Host facts the kernel re-reads for a bound session (#115): the peer's login
//! session and the local account's state.

#[cfg(target_os = "linux")]
mod logind;
#[cfg(target_os = "macos")]
mod macos_login;
#[cfg(target_os = "linux")]
mod userdb;
#[cfg(target_os = "linux")]
mod varlink;

#[cfg(target_os = "linux")]
pub use logind::login_linux;
#[cfg(target_os = "macos")]
pub use macos_login::login_macos;
#[cfg(target_os = "linux")]
pub use userdb::{account_linux, is_local_linux, USERDB_DEADLINE};

/// Whether the peer process is in a qualifying login session.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum LoginFact {
    Live,
    NoSession,
    NotUserClass,
    NotActive,
    ProcessGone,
    Unavailable(String),
}

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
