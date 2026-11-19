use crate::api_shape::{de_secret, json_refusal, token_is_acceptable, url_path_is_safe, VaultOp};
use crate::user_login::parse_auth;
use crate::VaultError;
use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use serde::Deserialize;
use std::fmt;
use std::time::Duration;
use zeroize::Zeroizing;

const TRANSIT_HASH: &str = "sha2-256";
const SIGNATURE_PREFIX: &str = "vault:v";
pub const TRANSIT_SIGN_INPUT_MAX_BYTES: usize = 8192;
const RSA_SIGNATURE_BYTES: [usize; 3] = [256, 384, 512];

pub struct ServiceToken(Zeroizing<String>);

impl ServiceToken {
    pub fn new(secret: Zeroizing<String>) -> Result<Self, VaultError> {
        token_is_acceptable(&secret).map_err(|why| VaultError::InvalidSecret {
            what: "service token",
            why,
        })?;
        Ok(Self(secret))
    }

    pub fn expose(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for ServiceToken {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("ServiceToken(<redacted>)")
    }
}

pub struct ServiceLogin {
    pub token: ServiceToken,
    pub ttl: Duration,
}

impl fmt::Debug for ServiceLogin {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ServiceLogin")
            .field("token", &self.token)
            .field("ttl", &self.ttl)
            .finish()
    }
}

fn service_mount(what: &'static str, mount: &str) -> Result<(), VaultError> {
    maknae_config::mount_path_is_acceptable(mount)
        .map_err(|why| VaultError::InvalidMount(format!("{what} {why}")))?;
    if !url_path_is_safe(mount) {
        return Err(VaultError::InvalidMount(format!(
            "{what} has a character outside [A-Za-z0-9._/-]"
        )));
    }
    Ok(())
}

pub(crate) fn approle_login_path(mount: &str) -> Result<String, VaultError> {
    service_mount("AppRole mount", mount)?;
    Ok(format!("auth/{mount}/login"))
}

pub(crate) fn transit_sign_path(mount: &str, key: &str) -> Result<String, VaultError> {
    service_mount("Transit mount", mount)?;
    service_mount("Transit key", key)?;
    if key.contains('/') {
        return Err(VaultError::InvalidMount(
            "Transit key must be a single path segment".into(),
        ));
    }
    Ok(format!("{mount}/sign/{key}/{TRANSIT_HASH}"))
}

pub(crate) fn approle_credential(what: &'static str, value: &str) -> Result<(), VaultError> {
    token_is_acceptable(value).map_err(|why| VaultError::InvalidSecret { what, why })
}

pub(crate) fn parse_service_login(body: &[u8]) -> Result<ServiceLogin, VaultError> {
    let auth = parse_auth(body, VaultOp::AppRoleLogin)?.ok_or_else(|| VaultError::VaultBody {
        op: VaultOp::AppRoleLogin.as_str(),
        why: "the response carried no auth block".into(),
    })?;
    if auth.lease_duration == 0 {
        return Err(VaultError::VaultBody {
            op: VaultOp::AppRoleLogin.as_str(),
            why: "the token has no expiry; set token_ttl on the AppRole role".into(),
        });
    }
    Ok(ServiceLogin {
        token: ServiceToken::new(auth.client_token)?,
        ttl: Duration::from_secs(auth.lease_duration),
    })
}

#[derive(Deserialize)]
struct SignDto {
    data: Option<SignDataDto>,
}

#[derive(Deserialize)]
struct SignDataDto {
    #[serde(deserialize_with = "de_secret")]
    signature: Zeroizing<String>,
}

pub(crate) fn parse_sign_reply(body: &[u8]) -> Result<Zeroizing<Vec<u8>>, VaultError> {
    let dto: SignDto =
        serde_json::from_slice(body).map_err(|e| json_refusal(VaultOp::TransitSign, &e))?;
    let data = dto.data.ok_or_else(|| VaultError::VaultBody {
        op: VaultOp::TransitSign.as_str(),
        why: "the response carried no data block".into(),
    })?;
    let signature = parse_transit_signature(&data.signature)?;
    if !RSA_SIGNATURE_BYTES.contains(&signature.len()) {
        return Err(VaultError::VaultBody {
            op: VaultOp::TransitSign.as_str(),
            why: "the signature length is not RSA-2048, 3072 or 4096; the Transit key is not RSA"
                .into(),
        });
    }
    Ok(signature)
}

fn malformed_signature() -> VaultError {
    VaultError::VaultBody {
        op: VaultOp::TransitSign.as_str(),
        why: "the signature is not vault:v<N>:<base64>".into(),
    }
}

pub fn parse_transit_signature(s: &str) -> Result<Zeroizing<Vec<u8>>, VaultError> {
    let (version, encoded) = s
        .strip_prefix(SIGNATURE_PREFIX)
        .and_then(|rest| rest.split_once(':'))
        .ok_or_else(malformed_signature)?;
    let version_ok = !version.is_empty()
        && !version.starts_with('0')
        && version.bytes().all(|b| b.is_ascii_digit());
    if !version_ok || encoded.is_empty() {
        return Err(malformed_signature());
    }
    let mut signature = Zeroizing::new(vec![0u8; base64::decoded_len_estimate(encoded.len())]);
    let len = STANDARD
        .decode_slice(encoded, &mut signature[..])
        .map_err(|_| malformed_signature())?;
    signature.truncate(len);
    Ok(signature)
}

#[cfg(test)]
mod tests {
    use super::*;

    const LOGIN: &str = r#"{"request_id":"r","lease_id":"","renewable":false,"lease_duration":0,"data":null,"wrap_info":null,"auth":{"client_token":"hvs.SERVICETOKEN","accessor":"a","policies":["maknae-egress"],"metadata":{"role_name":"maknae-egress"},"lease_duration":1200,"renewable":true,"entity_id":"e","token_type":"service","orphan":true}}"#;

    #[test]
    fn a_service_token_is_shape_checked_and_redacted() {
        assert!(ServiceToken::new(Zeroizing::new("hvs.a b".into())).is_err());
        let t = ServiceToken::new(Zeroizing::new("hvs.SENTINEL".into())).unwrap();
        assert!(t.expose() == "hvs.SENTINEL");
        assert_eq!(format!("{t:?}"), "ServiceToken(<redacted>)");
    }

    #[test]
    fn an_approle_reply_yields_the_token_and_its_lease_as_the_ttl() {
        let login = parse_service_login(LOGIN.as_bytes()).unwrap();
        assert!(login.token.expose() == "hvs.SERVICETOKEN");
        assert_eq!(login.ttl, Duration::from_secs(1200));
        let shown = format!("{login:?}");
        assert!(
            !shown.contains("SERVICETOKEN") && shown.contains("1200"),
            "{shown}"
        );
    }

    #[test]
    fn an_approle_reply_without_auth_with_no_expiry_or_a_bad_token_is_refused() {
        assert!(matches!(
            parse_service_login(br#"{"auth":null}"#),
            Err(VaultError::VaultBody { op: "AppRole login", why }) if why.contains("no auth block")
        ));
        let forever = LOGIN.replace(r#""lease_duration":1200"#, r#""lease_duration":0"#);
        assert!(matches!(
            parse_service_login(forever.as_bytes()),
            Err(VaultError::VaultBody { why, .. }) if why.contains("no expiry")
        ));
        let spaced = LOGIN.replace("hvs.SERVICETOKEN", "hvs.SERVICE TOKEN");
        assert!(matches!(
            parse_service_login(spaced.as_bytes()),
            Err(VaultError::InvalidSecret {
                what: "service token",
                ..
            })
        ));
        let bad = LOGIN.replace(r#""lease_duration":1200"#, r#""lease_duration":"SENTINEL""#);
        let e = parse_service_login(bad.as_bytes()).unwrap_err().to_string();
        assert!(
            !e.contains("SENTINEL") && e.starts_with("Vault AppRole login response refused"),
            "{e}"
        );
    }

    #[test]
    fn the_sign_path_pins_the_hash_and_refuses_a_malformed_mount_or_key() {
        assert_eq!(
            transit_sign_path("maknae-transit", "github-app").unwrap(),
            "maknae-transit/sign/github-app/sha2-256"
        );
        assert_eq!(
            transit_sign_path("ops/transit", "k.1_a-b").unwrap(),
            "ops/transit/sign/k.1_a-b/sha2-256"
        );
        for (mount, key) in [
            ("", "k"),
            ("/transit", "k"),
            ("transit/", "k"),
            ("a/../b", "k"),
            ("tran sit", "k"),
            ("transit?x", "k"),
            ("transit", ""),
            ("transit", ".."),
            ("transit", "."),
            ("transit", "a/b"),
            ("transit", "k%2f"),
            ("transit", "k#"),
        ] {
            assert!(
                matches!(
                    transit_sign_path(mount, key),
                    Err(VaultError::InvalidMount(_))
                ),
                "{mount:?} {key:?}"
            );
        }
    }

    #[test]
    fn the_approle_path_uses_the_configured_mount() {
        assert_eq!(
            approle_login_path("maknae-approle").unwrap(),
            "auth/maknae-approle/login"
        );
        for bad in ["", "..", "a/../b", "a?b", "/a"] {
            assert!(
                matches!(approle_login_path(bad), Err(VaultError::InvalidMount(_))),
                "{bad:?}"
            );
        }
    }

    #[test]
    fn a_signature_not_shaped_vault_v_n_base64_is_refused() {
        for bad in [
            "",
            "AAAA",
            "v1:AAAA",
            "vault:AAAA",
            "vault:1:AAAA",
            "vault:v0:AAAA",
            "vault:v01:AAAA",
            "vault:vx:AAAA",
            "vault:v:AAAA",
            "vault:v1x:AAAA",
            "vault:v-1:AAAA",
            "vault:v1:",
            "vault:v1",
            "vault:v1:AAA",
            "vault:v1:AA-_",
            "vault:v1:AAAA AAAA",
            "vault:v1:!!!!",
            "Vault:v1:AAAA",
            " vault:v1:AAAA",
        ] {
            assert!(
                matches!(
                    parse_transit_signature(bad),
                    Err(VaultError::VaultBody {
                        op: "Transit sign",
                        ..
                    })
                ),
                "{bad:?}"
            );
        }
        let e = parse_transit_signature("vault:v1:SENTINEL!")
            .unwrap_err()
            .to_string();
        assert!(!e.contains("SENTINEL"), "{e}");
    }

    #[test]
    fn a_well_formed_signature_decodes_to_its_bytes() {
        let got = parse_transit_signature("vault:v1:3q2+7w==").unwrap();
        assert_eq!(got.as_slice(), &[0xde, 0xad, 0xbe, 0xef]);
        let got = parse_transit_signature("vault:v12:AAEC").unwrap();
        assert_eq!(got.as_slice(), &[0, 1, 2]);
        let sig = [0xa5u8; 256];
        let text = format!(
            "vault:v3:{}",
            base64::Engine::encode(&base64::engine::general_purpose::STANDARD, sig)
        );
        assert_eq!(parse_transit_signature(&text).unwrap().as_slice(), sig);
    }

    #[test]
    fn a_decoded_signature_is_allocated_once_and_never_grows() {
        let got = parse_transit_signature("vault:v1:3q2+7w==").unwrap();
        assert_eq!(
            got.capacity(),
            base64::decoded_len_estimate("3q2+7w==".len())
        );
    }

    fn reply_of(len: usize) -> String {
        let sig = vec![0x5au8; len];
        format!(
            r#"{{"data":{{"signature":"vault:v1:{}"}}}}"#,
            base64::Engine::encode(&base64::engine::general_purpose::STANDARD, sig)
        )
    }

    #[test]
    fn a_non_rsa_length_signature_is_refused() {
        for len in [64, 1, 255, 257, 383, 511, 513] {
            let e = parse_sign_reply(reply_of(len).as_bytes()).unwrap_err();
            assert!(
                matches!(&e, VaultError::VaultBody { op: "Transit sign", why } if why.contains("not RSA")),
                "{len}: {e}"
            );
        }
        for len in [256, 384, 512] {
            assert_eq!(
                parse_sign_reply(reply_of(len).as_bytes()).unwrap().len(),
                len
            );
        }
    }

    #[test]
    fn a_sign_reply_yields_the_signature_bytes() {
        let sig = [0xa5u8; 256];
        let body = format!(
            r#"{{"request_id":"r","data":{{"key_version":1,"signature":"vault:v1:{}"}}}}"#,
            base64::Engine::encode(&base64::engine::general_purpose::STANDARD, sig)
        );
        assert_eq!(parse_sign_reply(body.as_bytes()).unwrap().as_slice(), sig);
        assert!(matches!(
            parse_sign_reply(br#"{"data":null}"#),
            Err(VaultError::VaultBody { why, .. }) if why.contains("no data block")
        ));
        let e = parse_sign_reply(br#"{"data":{"signature":12345678}}"#)
            .unwrap_err()
            .to_string();
        assert!(
            !e.contains("12345678") && e.starts_with("Vault Transit sign response refused"),
            "{e}"
        );
    }
}
