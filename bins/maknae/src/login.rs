use crate::tty::{read_password, stdin_is_terminal, PromptError};
use maknae_vault::{
    check_vault_addr, custody_for_store, custody_label, erase_user_token, observe_systemd_creds,
    read_user_token, store_user_token, userpass_username_is_acceptable, vault_config_from_document,
    StoredToken, SystemdCreds, UserAuth, VaultApi, VaultError,
};
use std::path::PathBuf;
use std::process::ExitCode;
use std::time::{SystemTime, UNIX_EPOCH};

const INTERRUPTED: u8 = 130;

enum Failure {
    Interrupted,
    Refused(String),
}

impl From<String> for Failure {
    fn from(m: String) -> Self {
        Failure::Refused(m)
    }
}

struct Session {
    dir: PathBuf,
    api: VaultApi,
    auth: UserAuth,
}

fn now_unix() -> Result<u64, String> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .map_err(|_| "the system clock reads before 1970; set the clock, then retry".to_string())
}

fn local_username() -> Result<String, String> {
    let uid = nix::unistd::geteuid();
    let user = nix::unistd::User::from_uid(uid)
        .map_err(|e| format!("cannot look up uid {uid}: {e}"))?
        .ok_or_else(|| format!("uid {uid} has no account name"))?;
    userpass_username_is_acceptable(&user.name).map_err(|why| {
        format!(
            "your account name {:?} {why}; Vault userpass needs 1-64 bytes of [a-z0-9._-] \
             starting and ending with [a-z0-9_]",
            user.name
        )
    })?;
    Ok(user.name)
}

fn session() -> Result<Session, String> {
    maknae_vault::install_default_crypto_provider();
    let dir = crate::cli::resolve_config_dir();
    let doc = maknae_config::load_config(&dir, &crate::cli::cli_config_specs())
        .map_err(|e| e.to_string())?;
    let vault = vault_config_from_document(&doc).map_err(|e| e.to_string())?;
    let auth = vault.user_auth.resolve().map_err(|e| e.to_string())?;
    let api = VaultApi::new(&vault.addr, &dir.join("tls").join("vault-ca.crt"))
        .map_err(|e| e.to_string())?;
    Ok(Session { dir, api, auth })
}

pub(crate) fn lifetime(secs: u64) -> String {
    if secs < 60 {
        return format!("{secs}s");
    }
    format!("{}h {}m", secs / 3600, secs % 3600 / 60)
}

#[derive(Debug)]
pub(crate) enum Previous {
    Nothing,
    OtherVault(String),
    SameVault(StoredToken),
}

pub(crate) fn previous_token(
    read: Result<StoredToken, VaultError>,
    vault_addr: &str,
    now: u64,
) -> Previous {
    match read {
        Ok(old) if !old.revocable_at(now) => Previous::Nothing,
        Ok(old) if !old.issued_by(vault_addr) => Previous::OtherVault(old.vault_addr().to_string()),
        Ok(old) => Previous::SameVault(old),
        Err(_) => Previous::Nothing,
    }
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) struct LoginSteps {
    pub(crate) erase_older: bool,
    pub(crate) revoke_new: bool,
    pub(crate) revoke_previous: bool,
}

pub(crate) fn login_steps(stored: bool, previous: &Previous) -> LoginSteps {
    LoginSteps {
        erase_older: stored,
        revoke_new: !stored,
        revoke_previous: matches!(previous, Previous::SameVault(_)),
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum PreviousFate {
    Erased,
    MaybeErased,
}

pub(crate) fn previous_fate(stored: bool, erased: bool) -> PreviousFate {
    if stored && erased {
        PreviousFate::Erased
    } else {
        PreviousFate::MaybeErased
    }
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Revocation {
    Revoked,
    AlreadyInvalid,
    Failed(String),
}

pub(crate) fn revocation(revoked: Result<(), VaultError>) -> Revocation {
    match revoked {
        Ok(()) => Revocation::Revoked,
        Err(VaultError::VaultStatus { status: 403, .. }) => Revocation::AlreadyInvalid,
        Err(e) => Revocation::Failed(e.to_string()),
    }
}

pub(crate) fn previous_note(
    previous: &Previous,
    fate: PreviousFate,
    revoked: Option<Revocation>,
    now: u64,
) -> Option<String> {
    let maybe = fate == PreviousFate::MaybeErased;
    match (previous, revoked) {
        (Previous::Nothing, _) => None,
        (Previous::OtherVault(addr), _) if maybe => Some(format!(
            "a token from a different Vault ({addr}) may have been erased here and was not revoked"
        )),
        (Previous::OtherVault(addr), _) => Some(format!(
            "a token from a different Vault ({addr}) was erased here, not revoked"
        )),
        (Previous::SameVault(_), None) => None,
        (Previous::SameVault(_), Some(Revocation::Revoked)) if maybe => {
            Some("the previous token may have been erased, so it was revoked".into())
        }
        (Previous::SameVault(_), Some(Revocation::AlreadyInvalid)) if maybe => {
            Some("the previous token may have been erased; Vault reports it already invalid".into())
        }
        (Previous::SameVault(_), Some(Revocation::Revoked | Revocation::AlreadyInvalid)) => None,
        (Previous::SameVault(old), Some(Revocation::Failed(why))) => Some(format!(
            "the previous token {}could not be revoked: {why}; it expires on its own within {}",
            if maybe {
                "may have been erased and "
            } else {
                ""
            },
            lifetime(old.expires_at().saturating_sub(now))
        )),
    }
}

pub(crate) fn new_token_note(revoked: Revocation, lease_secs: u64) -> String {
    match revoked {
        Revocation::Revoked => "the new token was revoked at Vault".into(),
        Revocation::AlreadyInvalid => "Vault reports the new token already invalid".into(),
        Revocation::Failed(why) => format!(
            "the new token could not be revoked ({why}) and stays valid for up to {}",
            lifetime(lease_secs)
        ),
    }
}

pub(crate) fn root_refusal(euid: u32) -> Result<(), String> {
    if euid == 0 {
        return Err("run `maknae login` as your own user, not root".into());
    }
    Ok(())
}

fn joined(head: String, note: Option<String>) -> String {
    match note {
        Some(note) => format!("{head}; {note}"),
        None => head,
    }
}

pub(crate) async fn run_login() -> ExitCode {
    match login().await {
        Ok(line) => {
            println!("{line}");
            ExitCode::SUCCESS
        }
        Err(Failure::Interrupted) => {
            eprintln!("maknae login: interrupted");
            ExitCode::from(INTERRUPTED)
        }
        Err(Failure::Refused(m)) => {
            eprintln!("maknae login: {m}");
            ExitCode::FAILURE
        }
    }
}

async fn login() -> Result<String, Failure> {
    if !stdin_is_terminal() {
        return Err(PromptError::NotATerminal.to_string().into());
    }
    root_refusal(nix::unistd::geteuid().as_raw())?;
    let name = local_username()?;
    let s = session()?;
    check_vault_addr(s.api.vault_addr()).map_err(|e| e.to_string())?;
    let macos = cfg!(target_os = "macos");
    let creds = if macos {
        SystemdCreds::Absent
    } else {
        observe_systemd_creds().map_err(|e| e.to_string())?
    };
    let custody = custody_for_store(&s.dir, macos, creds);
    let password = read_password(&format!("Vault password for {name} (will be hidden): "))
        .map_err(|e| match e {
            PromptError::Interrupted => Failure::Interrupted,
            other => Failure::Refused(other.to_string()),
        })?;
    let previous = read_user_token(&s.dir);
    let issued_before = now_unix()?;
    let login = s
        .api
        .login(&s.auth, &name, &password)
        .await
        .map_err(|e| e.to_string())?;
    drop(password);
    let previous = previous_token(previous, s.api.vault_addr(), issued_before);
    let lease = login.lease.as_secs();
    let stored =
        StoredToken::from_login(login, issued_before, s.api.vault_addr()).map_err(|e| {
            format!(
                "{e}; the new token was not stored and stays valid at Vault for up to {}",
                lifetime(lease)
            )
        })?;
    let store = store_user_token(&custody, &stored);
    let steps = login_steps(store.is_ok(), &previous);
    let erased = if steps.erase_older {
        erase_user_token(&s.dir, Some(&custody)).map(drop)
    } else {
        Ok(())
    };
    let new_revoked = if steps.revoke_new {
        Some(revoke(&s.api, &stored).await)
    } else {
        None
    };
    let previous_revoked = match (&previous, steps.revoke_previous) {
        (Previous::SameVault(old), true) => Some(revoke(&s.api, old).await),
        _ => None,
    };
    let fate = previous_fate(store.is_ok(), erased.is_ok());
    let note = previous_note(&previous, fate, previous_revoked, issued_before);
    if let Err(e) = store {
        let new = new_revoked.map(|r| new_token_note(r, lease));
        return Err(joined(joined(e.to_string(), new), note).into());
    }
    if let Err(e) = erased {
        let head =
            format!("the new token is stored, but erasing an older stored token failed: {e}");
        return Err(joined(head, note).into());
    }
    Ok(joined(
        format!(
            "maknae: logged in to Vault as {name}; the token is held in {} and is valid for {}",
            custody_label(&custody),
            lifetime(lease)
        ),
        note,
    ))
}

async fn revoke(api: &VaultApi, stored: &StoredToken) -> Revocation {
    revocation(api.revoke_self(stored.token()).await)
}

pub(crate) enum LogoutOutcome {
    NothingStored,
    Expired,
    Unreadable(String),
    OtherVault(String),
    Uncontacted { why: String, left_secs: u64 },
    Revoked,
    AlreadyInvalid,
    NotRevoked { why: String, left_secs: u64 },
}

pub(crate) fn revoke_outcome(revoked: Result<(), VaultError>, left_secs: u64) -> LogoutOutcome {
    match revocation(revoked) {
        Revocation::Revoked => LogoutOutcome::Revoked,
        Revocation::AlreadyInvalid => LogoutOutcome::AlreadyInvalid,
        Revocation::Failed(why) => LogoutOutcome::NotRevoked { why, left_secs },
    }
}

pub(crate) fn logout_erase_failure(outcome: &LogoutOutcome, e: &VaultError) -> String {
    match outcome {
        LogoutOutcome::NothingStored => format!("erasing any stored Vault token failed: {e}"),
        LogoutOutcome::Revoked => {
            format!("the token was revoked at Vault, but erasing it here failed: {e}")
        }
        _ => format!("erasing the stored Vault token failed: {e}"),
    }
}

pub(crate) fn logout_line(outcome: &LogoutOutcome) -> String {
    match outcome {
        LogoutOutcome::NothingStored => "maknae: no Vault token was stored".into(),
        LogoutOutcome::Expired => {
            "maknae: logged out; the stored Vault token had already expired and was erased".into()
        }
        LogoutOutcome::Unreadable(why) => format!(
            "maknae: logged out; the stored Vault token was unreadable ({why}), so it could not \
             be revoked; it was erased here and may stay valid at Vault until it expires"
        ),
        LogoutOutcome::OtherVault(addr) => format!(
            "maknae: logged out; the stored Vault token was issued by a different Vault ({addr}), \
             so it was erased here, not revoked; it may stay valid there until it expires"
        ),
        LogoutOutcome::Uncontacted { why, left_secs } => format!(
            "maknae: logged out; Vault was not contacted to revoke the token ({why}); it was \
             erased here and may stay valid for up to {}",
            lifetime(*left_secs)
        ),
        LogoutOutcome::Revoked => {
            "maknae: logged out; the Vault token was revoked and erased".into()
        }
        LogoutOutcome::AlreadyInvalid => {
            "maknae: logged out; Vault reports the token already invalid; it was erased here".into()
        }
        LogoutOutcome::NotRevoked { why, left_secs } => format!(
            "maknae: logged out; the token was erased here, but Vault did not confirm its \
             revocation ({why}), so it stays valid for up to {}",
            lifetime(*left_secs)
        ),
    }
}

#[derive(Debug)]
pub(crate) enum LogoutPlan {
    NothingStored,
    Expired,
    Unreadable(String),
    OtherVault(String),
    Uncontacted { why: String, left_secs: u64 },
    Revoke { stored: StoredToken, left_secs: u64 },
}

pub(crate) fn logout_plan(
    read: Result<StoredToken, VaultError>,
    vault_addr: Result<&str, &str>,
    now: u64,
) -> LogoutPlan {
    match read {
        Err(VaultError::TokenAbsent) => LogoutPlan::NothingStored,
        Err(VaultError::TokenRecord(why)) => LogoutPlan::Unreadable(why.to_string()),
        Err(VaultError::TokenUnreadable(m) | VaultError::TokenStore(m)) => {
            LogoutPlan::Unreadable(m)
        }
        Err(other) => LogoutPlan::Unreadable(other.to_string()),
        Ok(stored) if !stored.revocable_at(now) => LogoutPlan::Expired,
        Ok(stored) => {
            let left_secs = stored.expires_at() - now;
            match vault_addr {
                Err(why) => LogoutPlan::Uncontacted {
                    why: why.to_string(),
                    left_secs,
                },
                Ok(addr) if !stored.issued_by(addr) => {
                    LogoutPlan::OtherVault(stored.vault_addr().to_string())
                }
                Ok(_) => LogoutPlan::Revoke { stored, left_secs },
            }
        }
    }
}

async fn logout() -> Result<LogoutOutcome, String> {
    let dir = crate::cli::resolve_config_dir();
    let now = now_unix()?;
    let read = read_user_token(&dir);
    let session = match &read {
        Ok(_) => session(),
        Err(_) => Err(String::new()),
    };
    let vault_addr = session.as_ref().map(|s| s.api.vault_addr());
    let outcome = match logout_plan(read, vault_addr.map_err(String::as_str), now) {
        LogoutPlan::NothingStored => LogoutOutcome::NothingStored,
        LogoutPlan::Expired => LogoutOutcome::Expired,
        LogoutPlan::Unreadable(why) => LogoutOutcome::Unreadable(why),
        LogoutPlan::OtherVault(addr) => LogoutOutcome::OtherVault(addr),
        LogoutPlan::Uncontacted { why, left_secs } => LogoutOutcome::Uncontacted { why, left_secs },
        LogoutPlan::Revoke { stored, left_secs } => match &session {
            Ok(s) => revoke_outcome(s.api.revoke_self(stored.token()).await, left_secs),
            Err(why) => LogoutOutcome::Uncontacted {
                why: why.clone(),
                left_secs,
            },
        },
    };
    erase_user_token(&dir, None).map_err(|e| logout_erase_failure(&outcome, &e))?;
    Ok(outcome)
}

pub(crate) async fn run_logout() -> ExitCode {
    match logout().await {
        Ok(outcome) => {
            println!("{}", logout_line(&outcome));
            ExitCode::SUCCESS
        }
        Err(m) => {
            eprintln!("maknae logout: {m}");
            ExitCode::FAILURE
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_lifetime_reads_sensibly_at_every_scale() {
        assert_eq!(lifetime(28_800), "8h 0m");
        assert_eq!(lifetime(5_399), "1h 29m");
        assert_eq!(lifetime(60), "0h 1m");
        assert_eq!(lifetime(59), "59s");
        assert_eq!(lifetime(0), "0s");
    }

    #[test]
    fn each_logout_outcome_says_what_happened() {
        assert_eq!(
            logout_line(&LogoutOutcome::NothingStored),
            "maknae: no Vault token was stored"
        );
        assert_eq!(
            logout_line(&LogoutOutcome::Expired),
            "maknae: logged out; the stored Vault token had already expired and was erased"
        );
        assert_eq!(
            logout_line(&LogoutOutcome::Revoked),
            "maknae: logged out; the Vault token was revoked and erased"
        );
        assert_eq!(
            logout_line(&LogoutOutcome::AlreadyInvalid),
            "maknae: logged out; Vault reports the token already invalid; it was erased here"
        );
        assert_eq!(
            logout_line(&LogoutOutcome::NotRevoked {
                why: "Vault token revoke-self failed: x".into(),
                left_secs: 5_399
            }),
            "maknae: logged out; the token was erased here, but Vault did not confirm its \
             revocation (Vault token revoke-self failed: x), so it stays valid for up to 1h 29m"
        );
        assert_eq!(
            logout_line(&LogoutOutcome::Unreadable("keychain status -25293".into())),
            "maknae: logged out; the stored Vault token was unreadable (keychain status -25293), \
             so it could not be revoked; it was erased here and may stay valid at Vault until it expires"
        );
        assert_eq!(
            logout_line(&LogoutOutcome::OtherVault(ADDR.into())),
            "maknae: logged out; the stored Vault token was issued by a different Vault \
             (https://vault.example:8200/v1/), so it was erased here, not revoked; it may stay \
             valid there until it expires"
        );
        assert_eq!(
            logout_line(&LogoutOutcome::Uncontacted {
                why: "config error: x".into(),
                left_secs: 5_399
            }),
            "maknae: logged out; Vault was not contacted to revoke the token (config error: x); \
             it was erased here and may stay valid for up to 1h 29m"
        );
    }

    fn stored(expires_at: u64) -> StoredToken {
        let login = maknae_vault::UserLogin {
            token: maknae_vault::UserToken::new(zeroize::Zeroizing::new("hvs.plan".into()))
                .unwrap(),
            lease: std::time::Duration::from_secs(expires_at),
            renewable: true,
        };
        StoredToken::from_login(login, 0, ADDR).unwrap()
    }

    const ADDR: &str = "https://vault.example:8200/v1/";
    const OTHER: &str = "https://vault.other:8200/v1/";

    #[test]
    fn logout_revokes_any_token_that_has_not_expired_even_inside_the_freshness_margin() {
        let here = Ok(ADDR);
        assert!(matches!(
            logout_plan(Err(VaultError::TokenAbsent), here, 1_000),
            LogoutPlan::NothingStored
        ));
        assert!(matches!(
            logout_plan(Err(VaultError::TokenRecord("no expiry")), here, 1_000),
            LogoutPlan::Unreadable(why) if why == "no expiry"
        ));
        assert!(matches!(
            logout_plan(Err(VaultError::TokenUnreadable("keychain status -25293".into())), here, 1_000),
            LogoutPlan::Unreadable(why) if why == "keychain status -25293"
        ));
        assert!(matches!(
            logout_plan(Ok(stored(1_000)), here, 1_000),
            LogoutPlan::Expired
        ));
        assert!(matches!(
            logout_plan(Ok(stored(1_000)), here, 2_000),
            LogoutPlan::Expired
        ));
        assert!(matches!(
            logout_plan(Ok(stored(1_030)), here, 1_000),
            LogoutPlan::Revoke { left_secs: 30, .. }
        ));
        assert!(matches!(
            logout_plan(Ok(stored(10_000)), here, 1_000),
            LogoutPlan::Revoke {
                left_secs: 9_000,
                ..
            }
        ));
    }

    #[test]
    fn a_revoke_maps_403_to_already_invalid_and_anything_else_to_not_confirmed() {
        assert!(matches!(revoke_outcome(Ok(()), 9), LogoutOutcome::Revoked));
        let forbidden = VaultError::VaultStatus {
            op: "token revoke-self",
            status: 403,
            hint: "the token is already expired or revoked",
        };
        assert!(matches!(
            revoke_outcome(Err(forbidden), 9),
            LogoutOutcome::AlreadyInvalid
        ));
        for e in [
            VaultError::VaultStatus {
                op: "token revoke-self",
                status: 500,
                hint: "",
            },
            VaultError::VaultStatus {
                op: "token revoke-self",
                status: 401,
                hint: "",
            },
            VaultError::VaultTransport {
                op: "token revoke-self",
                detail: "connection refused".into(),
            },
        ] {
            let want = e.to_string();
            assert!(matches!(
                revoke_outcome(Err(e), 9),
                LogoutOutcome::NotRevoked { why, left_secs: 9 } if why == want
            ));
        }
    }

    #[test]
    fn a_logout_erase_failure_says_what_was_and_was_not_done() {
        let e = VaultError::TokenStore("erasing the token: x".into());
        assert_eq!(
            logout_erase_failure(&LogoutOutcome::NothingStored, &e),
            "erasing any stored Vault token failed: Vault token storage failed: erasing the token: x"
        );
        assert_eq!(
            logout_erase_failure(&LogoutOutcome::Revoked, &e),
            "the token was revoked at Vault, but erasing it here failed: Vault token storage \
             failed: erasing the token: x"
        );
        for outcome in [
            LogoutOutcome::Expired,
            LogoutOutcome::AlreadyInvalid,
            LogoutOutcome::Unreadable("x".into()),
            LogoutOutcome::OtherVault(ADDR.into()),
        ] {
            assert_eq!(
                logout_erase_failure(&outcome, &e),
                "erasing the stored Vault token failed: Vault token storage failed: erasing the \
                 token: x"
            );
        }
    }

    #[test]
    fn logout_never_sends_a_token_to_a_vault_that_did_not_issue_it() {
        assert!(matches!(
            logout_plan(Ok(stored(10_000)), Ok(OTHER), 1_000),
            LogoutPlan::OtherVault(addr) if addr == ADDR
        ));
        assert!(matches!(
            logout_plan(Ok(stored(1_000)), Ok(OTHER), 1_000),
            LogoutPlan::Expired
        ));
        assert!(matches!(
            logout_plan(Ok(stored(10_000)), Err("config error: x"), 1_000),
            LogoutPlan::Uncontacted { why, left_secs: 9_000 } if why == "config error: x"
        ));
        assert!(matches!(
            logout_plan(Err(VaultError::TokenAbsent), Err("config error: x"), 1_000),
            LogoutPlan::NothingStored
        ));
    }

    #[test]
    fn login_revokes_only_a_live_previous_token_from_the_same_vault() {
        assert!(matches!(
            previous_token(Ok(stored(10_000)), ADDR, 1_000),
            Previous::SameVault(old) if old.token().expose() == "hvs.plan"
        ));
        assert!(matches!(
            previous_token(Ok(stored(10_000)), OTHER, 1_000),
            Previous::OtherVault(addr) if addr == ADDR
        ));
        assert!(matches!(
            previous_token(Ok(stored(1_000)), ADDR, 1_000),
            Previous::Nothing
        ));
        assert!(matches!(
            previous_token(Ok(stored(1_000)), OTHER, 1_000),
            Previous::Nothing
        ));
        for read in [
            VaultError::TokenAbsent,
            VaultError::TokenRecord("no expiry"),
            VaultError::TokenUnreadable("x".into()),
        ] {
            assert!(matches!(
                previous_token(Err(read), ADDR, 1_000),
                Previous::Nothing
            ));
        }
    }

    #[test]
    fn login_stores_then_erases_older_copies_and_revokes_new_on_a_failed_store() {
        let same = Previous::SameVault(stored(10_000));
        let other = Previous::OtherVault(OTHER.into());
        let rows = [
            (true, &same, (true, false, true)),
            (true, &other, (true, false, false)),
            (true, &Previous::Nothing, (true, false, false)),
            (false, &same, (false, true, true)),
            (false, &other, (false, true, false)),
            (false, &Previous::Nothing, (false, true, false)),
        ];
        for (stored_ok, previous, (erase_older, revoke_new, revoke_previous)) in rows {
            assert_eq!(
                login_steps(stored_ok, previous),
                LoginSteps {
                    erase_older,
                    revoke_new,
                    revoke_previous
                },
                "{stored_ok} {previous:?}"
            );
        }
        assert_eq!(previous_fate(true, true), PreviousFate::Erased);
        assert_eq!(previous_fate(true, false), PreviousFate::MaybeErased);
        assert_eq!(previous_fate(false, true), PreviousFate::MaybeErased);
        assert_eq!(previous_fate(false, false), PreviousFate::MaybeErased);
    }

    type NoteRow<'a> = (
        &'a Previous,
        PreviousFate,
        Option<Revocation>,
        Option<&'a str>,
    );

    #[test]
    fn each_login_note_says_what_happened_to_the_previous_and_new_tokens() {
        use PreviousFate::{Erased, MaybeErased};
        let same = Previous::SameVault(stored(6_399));
        let other = Previous::OtherVault(ADDR.into());
        let failed = || {
            Some(Revocation::Failed(
                "Vault revoke-self failed: x".to_string(),
            ))
        };
        let rows: [NoteRow; 12] = [
            (&Previous::Nothing, Erased, None, None),
            (&Previous::Nothing, MaybeErased, None, None),
            (
                &other,
                Erased,
                None,
                Some("a token from a different Vault (https://vault.example:8200/v1/) was erased here, not revoked"),
            ),
            (
                &other,
                MaybeErased,
                None,
                Some("a token from a different Vault (https://vault.example:8200/v1/) may have been erased here and was not revoked"),
            ),
            (&same, Erased, Some(Revocation::Revoked), None),
            (&same, Erased, Some(Revocation::AlreadyInvalid), None),
            (&same, Erased, None, None),
            (&same, MaybeErased, None, None),
            (
                &same,
                MaybeErased,
                Some(Revocation::Revoked),
                Some("the previous token may have been erased, so it was revoked"),
            ),
            (
                &same,
                MaybeErased,
                Some(Revocation::AlreadyInvalid),
                Some("the previous token may have been erased; Vault reports it already invalid"),
            ),
            (
                &same,
                Erased,
                failed(),
                Some("the previous token could not be revoked: Vault revoke-self failed: x; it expires on its own within 1h 29m"),
            ),
            (
                &same,
                MaybeErased,
                failed(),
                Some("the previous token may have been erased and could not be revoked: Vault revoke-self failed: x; it expires on its own within 1h 29m"),
            ),
        ];
        for (previous, fate, revoked, want) in rows {
            assert_eq!(
                previous_note(previous, fate, revoked, 1_000).as_deref(),
                want,
                "{previous:?} {fate:?}"
            );
        }
        assert_eq!(
            previous_note(&Previous::SameVault(stored(500)), Erased, failed(), 1_000).as_deref(),
            Some("the previous token could not be revoked: Vault revoke-self failed: x; it expires on its own within 0s")
        );
        assert_eq!(
            new_token_note(Revocation::Revoked, 28_800),
            "the new token was revoked at Vault"
        );
        assert_eq!(
            new_token_note(Revocation::AlreadyInvalid, 28_800),
            "Vault reports the new token already invalid"
        );
        assert_eq!(
            new_token_note(Revocation::Failed("Vault revoke-self failed: x".into()), 28_800),
            "the new token could not be revoked (Vault revoke-self failed: x) and stays valid for up to 8h 0m"
        );
        assert_eq!(joined("a".into(), None), "a");
        assert_eq!(joined("a".into(), Some("b".into())), "a; b");
    }

    #[test]
    fn root_is_refused_before_anything_else() {
        assert_eq!(
            root_refusal(0).unwrap_err(),
            "run `maknae login` as your own user, not root"
        );
        assert!(root_refusal(1).is_ok());
        assert!(root_refusal(501).is_ok());
    }

    #[test]
    fn the_password_path_in_login_rs_and_tty_rs_reads_no_environment_variable() {
        for src in [include_str!("login.rs"), include_str!("tty.rs")] {
            for needle in [
                concat!("env::", "var"),
                concat!("env", "!("),
                concat!("option_", "env"),
            ] {
                assert!(!src.contains(needle), "{needle}");
            }
        }
    }
}
