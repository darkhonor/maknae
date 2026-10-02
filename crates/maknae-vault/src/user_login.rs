use crate::api_shape::{de_secret, json_refusal, token_is_acceptable, VaultOp};
use crate::{UserAuth, VaultError};
use serde::Deserialize;
use std::fmt;
use std::time::Duration;
use zeroize::Zeroizing;

/// The audit trail's subject bound, so every user who can log in is named in the trail.
pub const MAX_USERNAME_BYTES: usize = 32;
pub const MAX_PASSWORD_BYTES: usize = 1024;

pub struct Password(Zeroizing<String>);

fn password_len_ok(len: usize) -> bool {
    (1..=MAX_PASSWORD_BYTES).contains(&len)
}

impl Password {
    pub fn new(secret: Zeroizing<String>) -> Result<Self, VaultError> {
        if !password_len_ok(secret.len()) {
            return Err(VaultError::InvalidSecret {
                what: "password",
                why: "must be 1..=1024 bytes",
            });
        }
        Ok(Self(secret))
    }

    pub fn len(&self) -> usize {
        self.0.len()
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    pub(crate) fn expose(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for Password {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Password(<redacted>)")
    }
}

pub struct UserToken(Zeroizing<String>);

impl UserToken {
    pub fn new(secret: Zeroizing<String>) -> Result<Self, VaultError> {
        token_is_acceptable(&secret).map_err(|why| VaultError::InvalidSecret {
            what: "user token",
            why,
        })?;
        Ok(Self(secret))
    }

    pub fn expose(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for UserToken {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("UserToken(<redacted>)")
    }
}

#[derive(Debug)]
pub struct UserLogin {
    pub token: UserToken,
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
struct LoginAuthDto {
    #[serde(deserialize_with = "de_secret")]
    client_token: Zeroizing<String>,
    lease_duration: u64,
    renewable: bool,
    metadata: Option<LoginMetaDto>,
}

#[derive(Deserialize)]
struct LoginMetaDto {
    username: Option<String>,
}

pub(crate) fn parse_login(body: &[u8], username: &str) -> Result<UserLogin, VaultError> {
    let dto: LoginDto =
        serde_json::from_slice(body).map_err(|e| json_refusal(VaultOp::UserpassLogin, &e))?;
    let auth = dto.auth.ok_or(VaultError::UserpassLogin(
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
        token: UserToken::new(auth.client_token)?,
        lease: Duration::from_secs(auth.lease_duration),
        renewable: auth.renewable,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_password_reports_only_its_length() {
        let p = Password::new(Zeroizing::new("s3cret".into())).unwrap();
        assert_eq!((p.len(), p.is_empty()), (6, false));
    }

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
            assert_eq!(password_len_ok(len), ok, "{len}");
        }
    }

    #[test]
    fn a_password_is_non_empty_bounded_and_redacted() {
        assert!(Password::new(secret("")).is_err());
        assert!(Password::new(secret(&"p".repeat(MAX_PASSWORD_BYTES + 1))).is_err());
        let p = Password::new(secret(&"p".repeat(MAX_PASSWORD_BYTES))).unwrap();
        assert!(p.expose().len() == MAX_PASSWORD_BYTES);
        let p = Password::new(secret("hunter2-SENTINEL")).unwrap();
        assert!(format!("{p:?}") == "Password(<redacted>)");
    }

    #[test]
    fn a_user_token_is_shape_checked_and_redacted() {
        assert!(UserToken::new(secret("hvs.a b")).is_err());
        let t = UserToken::new(secret("hvs.SENTINEL")).unwrap();
        assert!(t.expose() == "hvs.SENTINEL");
        assert!(format!("{t:?}") == "UserToken(<redacted>)");
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
