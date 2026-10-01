use crate::tty::{read_password, stdin_is_terminal, PromptError};
use maknae_vault::{
    custody_for_store, custody_label, erase_user_token, observe_systemd_creds, read_user_token,
    store_user_token, userpass_username_is_acceptable, vault_config_from_document, StoredToken,
    SystemdCreds, UserAuth, VaultApi, VaultError,
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
    let name = local_username()?;
    let s = session()?;
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
    let previous = read_user_token(&s.dir).ok();
    let issued_before = now_unix()?;
    let login = s
        .api
        .login(&s.auth, &name, &password)
        .await
        .map_err(|e| e.to_string())?;
    drop(password);
    let lease = login.lease.as_secs();
    let stored = StoredToken::from_login(login, issued_before);
    store_user_token(&custody, &stored).map_err(|e| e.to_string())?;
    let erased = erase_user_token(&s.dir, Some(&custody));
    if let Some(old) = previous {
        let _ = s.api.revoke_self(old.token()).await;
    }
    erased.map_err(|e| {
        format!("the new token is stored, but erasing an older stored token failed: {e}")
    })?;
    Ok(format!(
        "maknae: logged in to Vault as {name}; the token is held in {} and is valid for {}",
        custody_label(&custody),
        lifetime(lease)
    ))
}

pub(crate) enum LogoutOutcome {
    NothingStored,
    Expired,
    Unreadable(String),
    Revoked,
    NotRevoked { why: String, left_secs: u64 },
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
        LogoutOutcome::Revoked => {
            "maknae: logged out; the Vault token was revoked and erased".into()
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
    Revoke { stored: StoredToken, left_secs: u64 },
}

pub(crate) fn logout_plan(read: Result<StoredToken, VaultError>, now: u64) -> LogoutPlan {
    match read {
        Err(VaultError::TokenAbsent) => LogoutPlan::NothingStored,
        Err(VaultError::TokenRecord(why)) => LogoutPlan::Unreadable(why.to_string()),
        Err(VaultError::TokenUnreadable(m) | VaultError::TokenStore(m)) => {
            LogoutPlan::Unreadable(m)
        }
        Err(other) => LogoutPlan::Unreadable(other.to_string()),
        Ok(stored) if !stored.revocable_at(now) => LogoutPlan::Expired,
        Ok(stored) => LogoutPlan::Revoke {
            left_secs: stored.expires_at() - now,
            stored,
        },
    }
}

async fn revoke(stored: &StoredToken) -> Result<(), String> {
    let s = session()?;
    s.api
        .revoke_self(stored.token())
        .await
        .map_err(|e| e.to_string())
}

async fn logout() -> Result<LogoutOutcome, String> {
    let dir = crate::cli::resolve_config_dir();
    let now = now_unix()?;
    let outcome = match logout_plan(read_user_token(&dir), now) {
        LogoutPlan::NothingStored => LogoutOutcome::NothingStored,
        LogoutPlan::Expired => LogoutOutcome::Expired,
        LogoutPlan::Unreadable(why) => LogoutOutcome::Unreadable(why),
        LogoutPlan::Revoke { stored, left_secs } => match revoke(&stored).await {
            Ok(()) => LogoutOutcome::Revoked,
            Err(why) => LogoutOutcome::NotRevoked { why, left_secs },
        },
    };
    erase_user_token(&dir, None).map_err(|e| match outcome {
        LogoutOutcome::Revoked => {
            format!("the token was revoked at Vault, but erasing it here failed: {e}")
        }
        _ => format!("erasing the stored Vault token failed: {e}"),
    })?;
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
    }

    fn stored(expires_at: u64) -> StoredToken {
        let login = maknae_vault::UserLogin {
            token: maknae_vault::UserToken::new(zeroize::Zeroizing::new("hvs.plan".into()))
                .unwrap(),
            lease: std::time::Duration::from_secs(expires_at),
            renewable: true,
        };
        StoredToken::from_login(login, 0)
    }

    #[test]
    fn logout_revokes_any_token_that_has_not_expired_even_inside_the_freshness_margin() {
        assert!(matches!(
            logout_plan(Err(VaultError::TokenAbsent), 1_000),
            LogoutPlan::NothingStored
        ));
        assert!(matches!(
            logout_plan(Err(VaultError::TokenRecord("no expiry")), 1_000),
            LogoutPlan::Unreadable(why) if why == "no expiry"
        ));
        assert!(matches!(
            logout_plan(Err(VaultError::TokenUnreadable("keychain status -25293".into())), 1_000),
            LogoutPlan::Unreadable(why) if why == "keychain status -25293"
        ));
        assert!(matches!(
            logout_plan(Ok(stored(1_000)), 1_000),
            LogoutPlan::Expired
        ));
        assert!(matches!(
            logout_plan(Ok(stored(1_000)), 2_000),
            LogoutPlan::Expired
        ));
        assert!(matches!(
            logout_plan(Ok(stored(1_030)), 1_000),
            LogoutPlan::Revoke { left_secs: 30, .. }
        ));
        assert!(matches!(
            logout_plan(Ok(stored(10_000)), 1_000),
            LogoutPlan::Revoke {
                left_secs: 9_000,
                ..
            }
        ));
    }

    #[test]
    fn login_rs_and_tty_rs_call_no_environment_reader() {
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
