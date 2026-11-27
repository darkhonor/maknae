use crate::api_shape::{json_refusal, VaultOp};
use crate::error::secret_error;
use crate::{UserAuth, VaultError};
use maknae_io::MaknaeSecret;
use serde::Deserialize;
use std::time::Duration;
use zeroize::Zeroizing;

/// The audit trail's subject bound, so every user who can log in is named in the trail.
pub const MAX_USERNAME_BYTES: usize = 32;
pub const MAX_PASSWORD_BYTES: usize = 1024;

pub fn password(secret: Zeroizing<String>) -> Result<MaknaeSecret, VaultError> {
    if !(1..=MAX_PASSWORD_BYTES).contains(&secret.len()) {
        return Err(VaultError::InvalidSecret {
            what: "password",
            why: "must be 1..=1024 bytes",
        });
    }
    MaknaeSecret::new(secret).map_err(|e| secret_error("password", e))
}

pub fn user_token(secret: Zeroizing<String>) -> Result<MaknaeSecret, VaultError> {
    MaknaeSecret::vault_token(secret).map_err(|e| secret_error("user token", e))
}

#[derive(Debug)]
pub struct UserLogin {
    pub token: MaknaeSecret,
    pub lease: Duration,
    pub renewable: bool,
}

pub fn userpass_username_is_acceptable(name: &str) -> Result<(), String> {
    if name.is_empty() {
        return Err("is empty".into());
    }
    if name.len() > MAX_USERNAME_BYTES {
        return Err(format!("exceeds {MAX_USERNAME_BYTES} bytes"));
    }
    if name.bytes().any(|b| b.is_ascii_uppercase()) {
        return Err("has an upper-case letter; userpass stores usernames lower-cased".into());
    }
    if !name
        .bytes()
        .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || matches!(b, b'.' | b'_' | b'-'))
    {
        return Err("has a character outside [a-z0-9._-]".into());
    }
    let word = |b: u8| b.is_ascii_alphanumeric() || b == b'_';
    let bytes = name.as_bytes();
    if !word(bytes[0]) || !word(bytes[bytes.len() - 1]) {
        return Err("must start and end with [a-z0-9_]".into());
    }
    Ok(())
}

pub(crate) fn login_path(auth: &UserAuth, username: &str) -> Result<String, VaultError> {
    userpass_username_is_acceptable(username)
        .map_err(|why| VaultError::InvalidUsername(format!("{username:?} {why}")))?;
    Ok(format!("auth/{}/login/{username}", auth.mount()))
}

#[derive(Deserialize)]
struct LoginDto {
    auth: Option<LoginAuthDto>,
}

#[derive(Deserialize)]
pub(crate) struct LoginAuthDto {
    #[serde(deserialize_with = "maknae_io::secret::de_zeroizing_string")]
    pub(crate) client_token: Zeroizing<String>,
    pub(crate) lease_duration: u64,
    renewable: bool,
    metadata: Option<LoginMetaDto>,
}

#[derive(Deserialize)]
struct LoginMetaDto {
    username: Option<String>,
}

pub(crate) fn parse_auth(body: &[u8], op: VaultOp) -> Result<Option<LoginAuthDto>, VaultError> {
    let dto: LoginDto = serde_json::from_slice(body).map_err(|e| json_refusal(op, &e))?;
    Ok(dto.auth)
}

pub(crate) fn parse_login(body: &[u8], username: &str) -> Result<UserLogin, VaultError> {
    let auth = parse_auth(body, VaultOp::UserpassLogin)?.ok_or(VaultError::UserpassLogin(
        "the response carried no auth block",
    ))?;
    let echoed = auth.metadata.and_then(|m| m.username);
    if echoed.as_deref() != Some(username) {
        return Err(VaultError::UserpassLogin(
            "Vault authenticated a different user than the one requested",
        ));
    }
    if auth.lease_duration == 0 {
        return Err(VaultError::UserpassLogin(
            "the token has no expiry; set token_ttl on the userpass user",
        ));
    }
    Ok(UserLogin {
        token: user_token(auth.client_token)?,
        lease: Duration::from_secs(auth.lease_duration),
        renewable: auth.renewable,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn secret(s: &str) -> Zeroizing<String> {
        Zeroizing::new(s.to_string())
    }

    const OK: &str = r#"{"request_id":"r","lease_id":"","renewable":false,"lease_duration":0,"data":null,"wrap_info":null,"auth":{"client_token":"hvs.USERTOKEN","accessor":"a","policies":["default"],"metadata":{"username":"alice"},"lease_duration":28800,"renewable":true,"entity_id":"e","token_type":"service","orphan":true}}"#;

    #[test]
    fn a_username_is_lower_case_portable_and_bounded() {
        for ok in ["alice", "a", "svc_agent", "a.b-c_d", "_x_", "0day"] {
            assert_eq!(userpass_username_is_acceptable(ok), Ok(()), "{ok:?}");
        }
        assert_eq!(MAX_USERNAME_BYTES, 32);
        assert_eq!(userpass_username_is_acceptable(&"a".repeat(32)), Ok(()));
        let refusals = [
            ("", "is empty"),
            ("Alice", "upper-case"),
            ("al ice", "outside"),
            ("al/ice", "outside"),
            ("al@ice", "outside"),
            ("-alice", "start and end"),
            ("alice.", "start and end"),
            ("..", "start and end"),
        ];
        for (bad, why) in refusals {
            let e = userpass_username_is_acceptable(bad).unwrap_err();
            assert!(e.contains(why), "{bad:?}: {e}");
        }
        assert!(userpass_username_is_acceptable(&"a".repeat(33))
            .unwrap_err()
            .contains("exceeds 32 bytes"));
    }

    #[test]
    fn the_login_path_uses_the_configured_mount() {
        let corp = UserAuth::new(crate::UserAuthMethod::Userpass, "corp-userpass").unwrap();
        assert_eq!(
            login_path(&corp, "alice").unwrap(),
            "auth/corp-userpass/login/alice"
        );
        assert_eq!(
            login_path(&UserAuth::userpass_default(), "bob").unwrap(),
            "auth/maknae-userpass/login/bob"
        );
        assert!(matches!(
            login_path(&corp, "../root"),
            Err(VaultError::InvalidUsername(_))
        ));
    }

    #[test]
    fn the_password_length_bound_is_one_to_1024_bytes_inclusive() {
        for (len, ok) in [(0, false), (1, true), (1024, true), (1025, false)] {
            assert_eq!(password(secret(&"p".repeat(len))).is_ok(), ok, "{len}");
        }
    }

    #[test]
    fn a_password_is_non_empty_bounded_and_redacted() {
        assert!(password(secret("")).is_err());
        assert!(matches!(
            password(secret(&"p".repeat(MAX_PASSWORD_BYTES + 1))),
            Err(VaultError::InvalidSecret {
                what: "password",
                why: "must be 1..=1024 bytes"
            })
        ));
        let p = password(secret(&"p".repeat(MAX_PASSWORD_BYTES))).unwrap();
        assert!(p.expose().len() == MAX_PASSWORD_BYTES);
        let p = password(secret("hunter2-SENTINEL")).unwrap();
        assert!(format!("{p:?}") == "MaknaeSecret(<redacted>)");
    }

    #[test]
    fn a_password_debug_does_not_show_its_length() {
        let p = password(secret("s3cret")).unwrap();
        let shown = format!("{p:?}");
        assert!(shown == "MaknaeSecret(<redacted>)" && !shown.contains('6'));
    }

    #[test]
    fn a_login_token_is_shape_checked_and_redacted() {
        let bad = parse_login(
            &OK.replace("hvs.USERTOKEN", "hvs.a b").into_bytes(),
            "alice",
        );
        assert!(matches!(
            bad,
            Err(VaultError::InvalidSecret {
                what: "user token",
                ..
            })
        ));
        let t = parse_login(OK.as_bytes(), "alice").unwrap().token;
        assert!(t.expose() == "hvs.USERTOKEN");
        assert!(format!("{t:?}") == "MaknaeSecret(<redacted>)");
    }

    #[test]
    fn a_login_response_yields_the_token_and_its_lease() {
        let login = parse_login(OK.as_bytes(), "alice").unwrap();
        assert!(login.token.expose() == "hvs.USERTOKEN");
        assert_eq!(login.lease, Duration::from_secs(28800));
        assert!(login.renewable);
        assert!(!format!("{login:?}").contains("USERTOKEN"));
        let fixed = OK.replace(r#""renewable":true"#, r#""renewable":false"#);
        assert!(!parse_login(fixed.as_bytes(), "alice").unwrap().renewable);
    }

    #[test]
    fn a_login_for_another_user_is_refused() {
        assert!(matches!(
            parse_login(OK.as_bytes(), "bob"),
            Err(VaultError::UserpassLogin(m)) if m.contains("different user")
        ));
        let no_meta = OK.replace(r#""metadata":{"username":"alice"},"#, "");
        assert!(matches!(
            parse_login(no_meta.as_bytes(), "alice"),
            Err(VaultError::UserpassLogin(_))
        ));
    }

    #[test]
    fn a_non_expiring_token_is_refused() {
        let forever = OK.replace(r#""lease_duration":28800"#, r#""lease_duration":0"#);
        assert!(matches!(
            parse_login(forever.as_bytes(), "alice"),
            Err(VaultError::UserpassLogin(m)) if m.contains("no expiry")
        ));
    }

    #[test]
    fn a_response_without_auth_or_with_a_bad_token_is_refused() {
        assert!(matches!(
            parse_login(br#"{"auth":null}"#, "alice"),
            Err(VaultError::UserpassLogin(m)) if m.contains("no auth block")
        ));
        let spaced = OK.replace("hvs.USERTOKEN", "hvs.USER TOKEN");
        assert!(matches!(
            parse_login(spaced.as_bytes(), "alice"),
            Err(VaultError::InvalidSecret {
                what: "user token",
                ..
            })
        ));
    }

    #[test]
    fn a_malformed_login_body_is_refused_without_echoing_it() {
        let bad = OK.replace(
            r#""lease_duration":28800"#,
            r#""lease_duration":"SENTINEL-LEASE""#,
        );
        let e = parse_login(bad.as_bytes(), "alice")
            .unwrap_err()
            .to_string();
        assert!(!e.contains("SENTINEL"), "{e}");
        assert!(
            e.starts_with("Vault userpass login response refused"),
            "{e}"
        );
    }
}
