use crate::api_shape::{
    de_secret, json_refusal, token_is_acceptable, url_path_is_safe, SecretStr, VaultOp,
    WrapMismatch,
};
use crate::user_login::UserToken;
use crate::VaultError;
use serde::de::{DeserializeSeed, Deserializer, IgnoredAny, MapAccess, Visitor};
use serde::Deserialize;
use std::fmt;
use std::future::Future;
use std::time::Duration;
use zeroize::Zeroizing;

pub const MAX_WRAP_TTL: Duration = Duration::from_secs(300);
pub const USER_KEY_WRAP_TTL: Duration = Duration::from_secs(60);
pub const MAX_KV_DATA_PATH_BYTES: usize = 1024;
const LEAF_DEPTH: u8 = 2;
const KV_DATA_SEGMENT: &str = "/data/";

pub struct WrappingToken(Zeroizing<String>);

impl WrappingToken {
    pub fn new(secret: Zeroizing<String>) -> Result<Self, VaultError> {
        token_is_acceptable(&secret).map_err(|why| VaultError::InvalidSecret {
            what: "wrapping token",
            why,
        })?;
        Ok(Self(secret))
    }

    pub fn from_opened(mut bytes: Zeroizing<Vec<u8>>) -> Result<Self, VaultError> {
        match String::from_utf8(std::mem::take(&mut *bytes)) {
            Ok(s) => Self::new(Zeroizing::new(s)),
            Err(e) => {
                let _wiped = Zeroizing::new(e.into_bytes());
                Err(VaultError::InvalidSecret {
                    what: "wrapping token",
                    why: "not UTF-8",
                })
            }
        }
    }

    pub fn expose(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for WrappingToken {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("WrappingToken(<redacted>)")
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KvDataPath(String);

impl KvDataPath {
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

pub fn kv_data_path(kv_mount: &str, secret_path: &str) -> Result<KvDataPath, VaultError> {
    let composed = kv_mount
        .len()
        .saturating_add(KV_DATA_SEGMENT.len())
        .saturating_add(secret_path.len());
    if composed > MAX_KV_DATA_PATH_BYTES {
        return Err(VaultError::InvalidKeyVaultPath(format!(
            "the full path exceeds {MAX_KV_DATA_PATH_BYTES} bytes"
        )));
    }
    for (key, value) in [("kv_mount", kv_mount), ("secret path", secret_path)] {
        maknae_config::kv_fragment_is_acceptable(value)
            .map_err(|why| VaultError::InvalidKeyVaultPath(format!("{key} {why}")))?;
        if !url_path_is_safe(value) {
            return Err(VaultError::InvalidKeyVaultPath(format!(
                "{key} has a character outside [A-Za-z0-9._/-]"
            )));
        }
    }
    Ok(KvDataPath(format!(
        "{kv_mount}{KV_DATA_SEGMENT}{secret_path}"
    )))
}

pub(crate) fn wrap_ttl_value(ttl: Duration) -> Result<String, VaultError> {
    if ttl.subsec_nanos() != 0 {
        return Err(VaultError::InvalidWrapTtl("must be whole seconds"));
    }
    let secs = ttl.as_secs();
    if !(1..=MAX_WRAP_TTL.as_secs()).contains(&secs) {
        return Err(VaultError::InvalidWrapTtl("must be 1s..=300s"));
    }
    Ok(format!("{secs}s"))
}

fn missing_client_token() -> VaultError {
    VaultError::InvalidSecret {
        what: "client token",
        why: "absent for a call that needs one",
    }
}

pub(crate) fn client_token<'a>(
    op: VaultOp,
    user: Option<&'a UserToken>,
    wrapping: Option<&'a WrappingToken>,
) -> Result<Option<&'a str>, VaultError> {
    match op {
        VaultOp::UserpassLogin | VaultOp::WrapLookup => Ok(None),
        VaultOp::WrappedRead | VaultOp::RevokeSelf => user
            .map(|t| Some(t.expose()))
            .ok_or_else(missing_client_token),
        VaultOp::Unwrap => wrapping
            .map(|t| Some(t.expose()))
            .ok_or_else(missing_client_token),
    }
}

fn kv_field_is_acceptable(field: &str) -> bool {
    !field.is_empty()
        && field.len() <= maknae_config::MAX_KEY_FIELD_BYTES
        && !field.chars().any(char::is_whitespace)
}

fn field_echo(field: &str) -> &str {
    let end = field
        .char_indices()
        .map(|(i, c)| i + c.len_utf8())
        .take_while(|&end| end <= maknae_config::MAX_KEY_FIELD_BYTES)
        .last()
        .unwrap_or(0);
    &field[..end]
}

pub struct WrapExpectation {
    creation_path: KvDataPath,
    field: String,
    max_ttl: Duration,
}

impl WrapExpectation {
    pub fn new(
        kv_mount: &str,
        secret_path: &str,
        field: &str,
        max_ttl: Duration,
    ) -> Result<Self, VaultError> {
        let creation_path = kv_data_path(kv_mount, secret_path)?;
        if !kv_field_is_acceptable(field) {
            return Err(VaultError::KvField {
                field: field_echo(field).to_string(),
                why: "malformed: empty, whitespace, or over 64 bytes",
            });
        }
        wrap_ttl_value(max_ttl)?;
        Ok(Self {
            creation_path,
            field: field.to_string(),
            max_ttl,
        })
    }

    pub fn creation_path(&self) -> &str {
        self.creation_path.as_str()
    }

    pub fn field(&self) -> &str {
        &self.field
    }

    pub fn max_ttl(&self) -> Duration {
        self.max_ttl
    }
}

#[derive(Debug)]
pub struct WrappedSecret {
    pub token: WrappingToken,
    pub ttl: Duration,
    pub creation_path: String,
    pub creation_time: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WrapLookup {
    pub creation_path: String,
    pub creation_ttl: Duration,
    pub creation_time: String,
}

fn check_ttl(ttl_secs: u64, max: Duration) -> Result<(), VaultError> {
    if !(1..=max.as_secs()).contains(&ttl_secs) {
        return Err(VaultError::WrapMismatch(WrapMismatch::CreationTtl {
            ttl_secs,
            max_secs: max.as_secs(),
        }));
    }
    Ok(())
}

#[derive(Deserialize)]
struct WrappedReadDto {
    data: Option<IgnoredAny>,
    wrap_info: Option<WrapInfoDto>,
}

#[derive(Deserialize)]
struct WrapInfoDto {
    #[serde(deserialize_with = "de_secret")]
    token: Zeroizing<String>,
    ttl: u64,
    creation_time: String,
    creation_path: String,
}

pub(crate) fn parse_wrapped_read(
    body: &[u8],
    expected: &KvDataPath,
    requested_ttl: Duration,
) -> Result<WrappedSecret, VaultError> {
    let dto: WrappedReadDto =
        serde_json::from_slice(body).map_err(|e| json_refusal(VaultOp::WrappedRead, &e))?;
    if dto.data.is_some() {
        return Err(VaultError::WrapMismatch(WrapMismatch::NotWrapped));
    }
    let info = dto
        .wrap_info
        .ok_or(VaultError::WrapMismatch(WrapMismatch::NotWrapped))?;
    if info.creation_path != expected.as_str() {
        return Err(VaultError::WrapMismatch(WrapMismatch::CreationPath));
    }
    check_ttl(info.ttl, requested_ttl)?;
    Ok(WrappedSecret {
        token: WrappingToken::new(info.token)?,
        ttl: Duration::from_secs(info.ttl),
        creation_path: info.creation_path,
        creation_time: info.creation_time,
    })
}

#[derive(Deserialize)]
struct LookupDto {
    data: Option<LookupDataDto>,
}

#[derive(Deserialize)]
struct LookupDataDto {
    creation_path: String,
    creation_ttl: u64,
    creation_time: String,
}

pub(crate) fn parse_lookup(body: &[u8]) -> Result<WrapLookup, VaultError> {
    let dto: LookupDto =
        serde_json::from_slice(body).map_err(|e| json_refusal(VaultOp::WrapLookup, &e))?;
    let data = dto
        .data
        .ok_or(VaultError::WrapMismatch(WrapMismatch::Invalid))?;
    Ok(WrapLookup {
        creation_path: data.creation_path,
        creation_ttl: Duration::from_secs(data.creation_ttl),
        creation_time: data.creation_time,
    })
}

pub(crate) struct CheckedLookup(());

pub(crate) fn check_lookup(
    lookup: &WrapLookup,
    expect: &WrapExpectation,
) -> Result<CheckedLookup, VaultError> {
    if lookup.creation_path != expect.creation_path() {
        return Err(VaultError::WrapMismatch(WrapMismatch::CreationPath));
    }
    check_ttl(lookup.creation_ttl.as_secs(), expect.max_ttl)?;
    Ok(CheckedLookup(()))
}

struct Level<'f> {
    field: &'f str,
    depth: u8,
}

impl<'de> DeserializeSeed<'de> for Level<'_> {
    type Value = Option<Zeroizing<String>>;

    fn deserialize<D: Deserializer<'de>>(self, d: D) -> Result<Self::Value, D::Error> {
        d.deserialize_map(self)
    }
}

impl<'de> Visitor<'de> for Level<'_> {
    type Value = Option<Zeroizing<String>>;

    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("a JSON object")
    }

    fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Self::Value, A::Error> {
        let want = if self.depth == LEAF_DEPTH {
            self.field
        } else {
            "data"
        };
        let mut found: Option<Option<Zeroizing<String>>> = None;
        while let Some(key) = map.next_key::<String>()? {
            if key != want {
                map.next_value::<IgnoredAny>()?;
                continue;
            }
            if found.is_some() {
                return Err(<A::Error as serde::de::Error>::custom("duplicate key"));
            }
            found = Some(if self.depth == LEAF_DEPTH {
                Some(map.next_value::<SecretStr>()?.0)
            } else {
                map.next_value_seed(Level {
                    field: self.field,
                    depth: self.depth + 1,
                })?
            });
        }
        Ok(found.flatten())
    }
}

pub(crate) fn select_kv_field(body: &[u8], field: &str) -> Result<Zeroizing<String>, VaultError> {
    let mut de = serde_json::Deserializer::from_slice(body);
    let picked = Level { field, depth: 0 }
        .deserialize(&mut de)
        .map_err(|e| json_refusal(VaultOp::Unwrap, &e))?;
    de.end().map_err(|e| json_refusal(VaultOp::Unwrap, &e))?;
    picked.ok_or_else(|| VaultError::KvField {
        field: field.to_string(),
        why: "absent",
    })
}

pub(crate) trait UnwrapOps {
    fn lookup(
        &self,
        token: &WrappingToken,
    ) -> impl Future<Output = Result<WrapLookup, VaultError>> + Send;
    fn unwrap_body(
        &self,
        token: WrappingToken,
        checked: &CheckedLookup,
    ) -> impl Future<Output = Result<Zeroizing<Vec<u8>>, VaultError>> + Send;
}

pub(crate) async fn unwrap_checked<O: UnwrapOps>(
    ops: &O,
    token: WrappingToken,
    expect: &WrapExpectation,
) -> Result<Zeroizing<String>, VaultError> {
    let lookup = ops.lookup(&token).await?;
    let checked = check_lookup(&lookup, expect)?;
    let body = ops.unwrap_body(token, &checked).await?;
    select_kv_field(&body, expect.field())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    const ALICE: &str = "maknae-kv/data/maknae/users/alice/openai/personal";
    const BOB: &str = "maknae-kv/data/maknae/users/bob/openai/personal";
    const KV_BODY: &[u8] = br#"{"request_id":"r","lease_id":"","renewable":false,"lease_duration":0,"data":{"data":{"api_key":"sk-ALICE-SENTINEL","org":"o-1"},"metadata":{"version":3}},"wrap_info":null,"warnings":null,"auth":null}"#;

    fn expect() -> WrapExpectation {
        WrapExpectation::new(
            "maknae-kv",
            "maknae/users/alice/openai/personal",
            "api_key",
            Duration::from_secs(60),
        )
        .unwrap()
    }

    fn wrapping(s: &str) -> WrappingToken {
        WrappingToken::new(Zeroizing::new(s.to_string())).unwrap()
    }

    fn wrapped_body(path: &str, ttl: u64, data: &str) -> String {
        format!(
            r#"{{"request_id":"","lease_id":"","renewable":false,"lease_duration":0,"data":{data},"wrap_info":{{"token":"hvs.WRAP","accessor":"x","ttl":{ttl},"creation_time":"2026-10-01T00:00:00Z","creation_path":"{path}"}},"warnings":null,"auth":null}}"#
        )
    }

    #[test]
    fn a_kv_data_path_is_mount_data_path_and_refuses_url_or_traversal_characters() {
        assert_eq!(
            kv_data_path("maknae-kv", "maknae/users/alice/openai/personal")
                .unwrap()
                .as_str(),
            ALICE
        );
        for (mount, path) in [
            ("maknae-kv", "a?b"),
            ("maknae-kv", "a#b"),
            ("maknae-kv", "a%2e"),
            ("maknae-kv", "../bob/x"),
            ("maknae-kv", "data/x"),
            ("maknae-kv", "a//b"),
            ("maknae-kv", "/a"),
            ("maknae kv", "a"),
            ("kv#", "a"),
            ("", "a"),
        ] {
            assert!(
                matches!(
                    kv_data_path(mount, path),
                    Err(VaultError::InvalidKeyVaultPath(_))
                ),
                "{mount:?} {path:?}"
            );
        }
    }

    #[test]
    fn each_call_carries_only_its_own_token_and_lookup_carries_none() {
        let user = UserToken::new(Zeroizing::new("hvs.user".into())).unwrap();
        let wrap = wrapping("hvs.wrap");
        let (u, w) = (Some(&user), Some(&wrap));
        let pick = |op| client_token(op, u, w).unwrap();
        assert_eq!(pick(VaultOp::UserpassLogin), None);
        assert_eq!(pick(VaultOp::WrapLookup), None);
        assert!(pick(VaultOp::WrappedRead) == Some("hvs.user"));
        assert!(pick(VaultOp::Unwrap) == Some("hvs.wrap"));
        assert!(pick(VaultOp::RevokeSelf) == Some("hvs.user"));
        assert!(matches!(
            client_token(VaultOp::RevokeSelf, None, Some(&wrap)),
            Err(VaultError::InvalidSecret {
                what: "client token",
                ..
            })
        ));
        assert!(matches!(
            client_token(VaultOp::WrappedRead, None, Some(&wrap)),
            Err(VaultError::InvalidSecret {
                what: "client token",
                ..
            })
        ));
        assert!(matches!(
            client_token(VaultOp::Unwrap, Some(&user), None),
            Err(VaultError::InvalidSecret {
                what: "client token",
                ..
            })
        ));
    }

    #[test]
    fn a_wrap_ttl_is_whole_seconds_within_bounds() {
        assert_eq!(wrap_ttl_value(Duration::from_secs(60)).unwrap(), "60s");
        assert_eq!(wrap_ttl_value(Duration::from_secs(1)).unwrap(), "1s");
        assert_eq!(wrap_ttl_value(MAX_WRAP_TTL).unwrap(), "300s");
        for bad in [
            Duration::ZERO,
            Duration::from_secs(301),
            Duration::from_millis(1500),
        ] {
            assert!(
                matches!(wrap_ttl_value(bad), Err(VaultError::InvalidWrapTtl(_))),
                "{bad:?}"
            );
        }
    }

    #[test]
    fn the_user_key_wrap_ttl_is_sixty_seconds_and_a_valid_wrap_ttl() {
        assert_eq!(USER_KEY_WRAP_TTL, Duration::from_secs(60));
        assert_eq!(wrap_ttl_value(USER_KEY_WRAP_TTL).unwrap(), "60s");
        assert!(USER_KEY_WRAP_TTL <= MAX_WRAP_TTL);
    }

    #[test]
    fn an_expectation_refuses_a_malformed_field_or_ttl() {
        assert_eq!(expect().creation_path(), ALICE);
        assert_eq!(expect().field(), "api_key");
        assert_eq!(expect().max_ttl(), Duration::from_secs(60));
        let long = "f".repeat(maknae_config::MAX_KEY_FIELD_BYTES + 1);
        for field in ["", "api key", long.as_str()] {
            assert!(
                matches!(
                    WrapExpectation::new("kv", "a", field, Duration::from_secs(60)),
                    Err(VaultError::KvField { .. })
                ),
                "{field:?}"
            );
        }
        assert!(WrapExpectation::new(
            "kv",
            "a",
            &"f".repeat(maknae_config::MAX_KEY_FIELD_BYTES),
            Duration::from_secs(60)
        )
        .is_ok());
        assert!(WrapExpectation::new("kv", "a", "f", Duration::ZERO).is_err());
        assert!(matches!(
            WrapExpectation::new("kv", "../bob", "f", Duration::from_secs(60)),
            Err(VaultError::InvalidKeyVaultPath(_))
        ));
    }

    #[test]
    fn a_malformed_wrapped_read_or_lookup_body_is_refused_without_echoing_it() {
        let path = kv_data_path("maknae-kv", "maknae/users/alice/openai/personal").unwrap();
        let e = parse_wrapped_read(
            br#"{"wrap_info":{"token":"hvs.SENTINEL""#,
            &path,
            Duration::from_secs(60),
        )
        .unwrap_err()
        .to_string();
        assert!(
            e.starts_with("Vault wrapped KV read response refused") && !e.contains("SENTINEL"),
            "{e}"
        );
        let e = parse_lookup(br#"{"data":{"creation_path":"SENTINEL","creation_ttl":"x"}}"#)
            .unwrap_err()
            .to_string();
        assert!(
            e.starts_with("Vault wrapping lookup response refused") && !e.contains("SENTINEL"),
            "{e}"
        );
    }

    #[test]
    fn a_multibyte_field_is_echoed_only_up_to_the_byte_bound() {
        let field = "é".repeat(maknae_config::MAX_KEY_FIELD_BYTES);
        let Err(VaultError::KvField { field: echoed, .. }) =
            WrapExpectation::new("kv", "a", &field, Duration::from_secs(60))
        else {
            panic!("expected KvField");
        };
        assert_eq!(echoed.len(), maknae_config::MAX_KEY_FIELD_BYTES);
        assert!(field.starts_with(&echoed));
        let odd = format!("a{}", "é".repeat(40));
        let Err(VaultError::KvField { field: echoed, .. }) =
            WrapExpectation::new("kv", "a", &odd, Duration::from_secs(60))
        else {
            panic!("expected KvField");
        };
        assert_eq!(echoed.len(), 63);
        assert!(odd.starts_with(&echoed));
    }

    #[test]
    fn field_echo_is_the_largest_char_boundary_prefix_within_the_bound() {
        let odd = format!("a{}", "é".repeat(40));
        let long = "f".repeat(65);
        let rows: [(&str, usize); 6] = [
            ("", 0),
            ("api key", 7),
            (&long, 64),
            (&odd, 63),
            ("é", 2),
            ("日本", 6),
        ];
        for (field, want) in rows {
            assert_eq!(field_echo(field).len(), want, "{field:?}");
            assert!(field.starts_with(field_echo(field)));
        }
    }

    #[test]
    fn a_kv_field_is_non_empty_bounded_and_free_of_whitespace() {
        let max = "f".repeat(maknae_config::MAX_KEY_FIELD_BYTES);
        let over = "f".repeat(maknae_config::MAX_KEY_FIELD_BYTES + 1);
        let rows: [(&str, bool); 7] = [
            ("api_key", true),
            ("f", true),
            (&max, true),
            ("", false),
            (&over, false),
            ("api key", false),
            ("api\tkey", false),
        ];
        for (field, ok) in rows {
            assert_eq!(kv_field_is_acceptable(field), ok, "{field:?}");
        }
    }

    fn exceeds(r: Result<KvDataPath, VaultError>) -> bool {
        matches!(r, Err(VaultError::InvalidKeyVaultPath(m)) if m == "the full path exceeds 1024 bytes")
    }

    #[test]
    fn the_composed_bound_counts_the_mount_the_data_segment_and_the_path() {
        let mount = "m".repeat(MAX_KV_DATA_PATH_BYTES - "/data/a".len());
        assert_eq!(
            kv_data_path(&mount, "a").unwrap().as_str().len(),
            MAX_KV_DATA_PATH_BYTES
        );
        assert!(exceeds(kv_data_path(&format!("{mount}m"), "a")));
        assert!(exceeds(kv_data_path("kv", &format!("{mount}mm"))));
    }

    #[test]
    fn an_oversized_input_is_refused_by_length_before_it_is_parsed() {
        let mib = "a/".repeat(512 * 1024);
        assert!(exceeds(kv_data_path("kv", &format!("{mib}a"))));
        assert!(exceeds(kv_data_path("kv", &mib)));
        assert!(exceeds(kv_data_path(&mib, "a")));
        assert!(exceeds(kv_data_path("kv", &"../".repeat(512))));
        assert!(exceeds(kv_data_path("k v", &"a ".repeat(1024))));
    }

    #[test]
    fn a_kv_data_path_is_bounded_to_the_seal_field_length() {
        assert_eq!(MAX_KV_DATA_PATH_BYTES, maknae_seal::MAX_AAD_FIELD_BYTES);
        let fits = "a".repeat(MAX_KV_DATA_PATH_BYTES - "kv/data/".len());
        assert_eq!(
            kv_data_path("kv", &fits).unwrap().as_str().len(),
            MAX_KV_DATA_PATH_BYTES
        );
        let over = format!("{fits}a");
        assert!(matches!(
            kv_data_path("kv", &over),
            Err(VaultError::InvalidKeyVaultPath(m)) if m == "the full path exceeds 1024 bytes"
        ));
    }

    #[test]
    fn a_wrapped_read_with_a_malformed_token_is_refused() {
        let path = kv_data_path("maknae-kv", "maknae/users/alice/openai/personal").unwrap();
        let body = wrapped_body(ALICE, 60, "null").replace("hvs.WRAP", "hvs.WR AP");
        assert!(matches!(
            parse_wrapped_read(body.as_bytes(), &path, Duration::from_secs(60)),
            Err(VaultError::InvalidSecret {
                what: "wrapping token",
                ..
            })
        ));
    }

    #[test]
    fn the_field_selector_names_what_it_expects() {
        let expected: &dyn serde::de::Expected = &Level {
            field: "k",
            depth: 0,
        };
        assert_eq!(expected.to_string(), "a JSON object");
    }

    #[test]
    fn a_wrapping_token_from_opened_bytes_is_utf8_and_shape_checked() {
        let t = WrappingToken::from_opened(Zeroizing::new(b"hvs.OPENED".to_vec())).unwrap();
        assert!(t.expose() == "hvs.OPENED");
        assert!(format!("{t:?}") == "WrappingToken(<redacted>)");
        assert!(matches!(
            WrappingToken::from_opened(Zeroizing::new(vec![0xff, 0xfe])),
            Err(VaultError::InvalidSecret {
                why: "not UTF-8",
                ..
            })
        ));
        assert!(WrappingToken::from_opened(Zeroizing::new(b"hvs. x".to_vec())).is_err());
    }

    #[test]
    fn a_wrapped_read_returns_only_the_wrapping_token() {
        let path = kv_data_path("maknae-kv", "maknae/users/alice/openai/personal").unwrap();
        let body = wrapped_body(ALICE, 60, "null");
        let w = parse_wrapped_read(body.as_bytes(), &path, Duration::from_secs(60)).unwrap();
        assert!(w.token.expose() == "hvs.WRAP");
        assert_eq!(
            (w.ttl, w.creation_path.as_str(), w.creation_time.as_str()),
            (Duration::from_secs(60), ALICE, "2026-10-01T00:00:00Z")
        );
        assert!(!format!("{w:?}").contains("hvs.WRAP"));
    }

    #[test]
    fn an_unwrapped_response_is_refused() {
        let path = kv_data_path("maknae-kv", "maknae/users/alice/openai/personal").unwrap();
        let leaked = wrapped_body(ALICE, 60, r#"{"data":{"api_key":"sk-LEAK"}}"#);
        let e = parse_wrapped_read(leaked.as_bytes(), &path, Duration::from_secs(60)).unwrap_err();
        assert!(matches!(
            e,
            VaultError::WrapMismatch(WrapMismatch::NotWrapped)
        ));
        assert!(!e.to_string().contains("sk-LEAK"));
        assert!(matches!(
            parse_wrapped_read(KV_BODY, &path, Duration::from_secs(60)),
            Err(VaultError::WrapMismatch(WrapMismatch::NotWrapped))
        ));
        assert!(matches!(
            parse_wrapped_read(
                br#"{"data":null,"wrap_info":null}"#,
                &path,
                Duration::from_secs(60)
            ),
            Err(VaultError::WrapMismatch(WrapMismatch::NotWrapped))
        ));
    }

    #[test]
    fn a_wrapped_read_for_another_path_or_ttl_is_refused() {
        let path = kv_data_path("maknae-kv", "maknae/users/alice/openai/personal").unwrap();
        assert!(matches!(
            parse_wrapped_read(
                wrapped_body(BOB, 60, "null").as_bytes(),
                &path,
                Duration::from_secs(60)
            ),
            Err(VaultError::WrapMismatch(WrapMismatch::CreationPath))
        ));
        for ttl in [0, 61] {
            assert!(
                matches!(
                    parse_wrapped_read(
                        wrapped_body(ALICE, ttl, "null").as_bytes(),
                        &path,
                        Duration::from_secs(60)
                    ),
                    Err(VaultError::WrapMismatch(WrapMismatch::CreationTtl { .. }))
                ),
                "{ttl}"
            );
        }
        assert!(parse_wrapped_read(
            wrapped_body(ALICE, 1, "null").as_bytes(),
            &path,
            Duration::from_secs(60)
        )
        .is_ok());
    }

    #[test]
    fn a_lookup_parses_and_checks_path_and_ttl() {
        let body = br#"{"data":{"creation_path":"maknae-kv/data/maknae/users/alice/openai/personal","creation_time":"2026-10-01T00:00:00Z","creation_ttl":60}}"#;
        let l = parse_lookup(body).unwrap();
        assert_eq!(
            l,
            WrapLookup {
                creation_path: ALICE.into(),
                creation_ttl: Duration::from_secs(60),
                creation_time: "2026-10-01T00:00:00Z".into()
            }
        );
        assert!(check_lookup(&l, &expect()).is_ok());
        let bob = WrapLookup {
            creation_path: BOB.into(),
            ..l.clone()
        };
        assert!(matches!(
            check_lookup(&bob, &expect()),
            Err(VaultError::WrapMismatch(WrapMismatch::CreationPath))
        ));
        let long = WrapLookup {
            creation_ttl: Duration::from_secs(61),
            ..l
        };
        assert!(matches!(
            check_lookup(&long, &expect()),
            Err(VaultError::WrapMismatch(WrapMismatch::CreationTtl {
                ttl_secs: 61,
                max_secs: 60
            }))
        ));
        assert!(matches!(
            parse_lookup(br#"{"data":null}"#),
            Err(VaultError::WrapMismatch(WrapMismatch::Invalid))
        ));
    }

    #[test]
    fn field_selection_returns_only_the_named_field() {
        let v = select_kv_field(KV_BODY, "api_key").unwrap();
        assert!(v.as_str() == "sk-ALICE-SENTINEL");
        assert_eq!(v.capacity(), 17);
        let escaped =
            select_kv_field(br#"{"data":{"data":{"data":"d","k":"sk\u002dX"}}}"#, "k").unwrap();
        assert!(escaped.as_str() == "sk-X");
        let named_data = select_kv_field(br#"{"data":{"data":{"data":"d"}}}"#, "data").unwrap();
        assert!(named_data.as_str() == "d");
    }

    #[test]
    fn field_selection_refuses_absent_duplicate_or_non_string_values() {
        assert!(matches!(
            select_kv_field(KV_BODY, "missing"),
            Err(VaultError::KvField { why: "absent", .. })
        ));
        let bodies: [&[u8]; 9] = [
            br#"{"data":{"data":{"api_key":"a","api_key":"b"}}}"#,
            br#"{"data":{"data":{"api_key":"a"}},"data":{"data":{"api_key":"b"}}}"#,
            br#"{"data":{"data":{"api_key":"a"},"data":{}}}"#,
            br#"{"data":null}"#,
            br#"{"data":5}"#,
            br#"{"data":{"data":{"api_key":"a"}}} trailing"#,
            br#"{"data":{1:"a"}}"#,
            br#"{"other":[1,,2],"data":{"data":{"api_key":"a"}}}"#,
            br#"{"data":{"data":{"api_key":"a"#,
        ];
        for body in bodies {
            assert!(
                matches!(
                    select_kv_field(body, "api_key"),
                    Err(VaultError::VaultBody { .. })
                ),
                "{}",
                String::from_utf8_lossy(body)
            );
        }
        let Err(e) = select_kv_field(br#"{"data":{"data":{"api_key":98765432}}}"#, "api_key")
        else {
            panic!("a non-string field must be refused");
        };
        let e = e.to_string();
        assert!(!e.contains("98765432"), "{e}");
    }

    struct Scripted {
        path: &'static str,
        ttl_secs: u64,
        lookup_ok: bool,
        unwrap_ok: bool,
        body: &'static [u8],
        calls: Mutex<Vec<&'static str>>,
    }

    impl Scripted {
        fn new(path: &'static str, ttl_secs: u64, lookup_ok: bool) -> Self {
            Self {
                path,
                ttl_secs,
                lookup_ok,
                unwrap_ok: true,
                body: KV_BODY,
                calls: Mutex::new(vec![]),
            }
        }
        fn calls(&self) -> Vec<&'static str> {
            self.calls.lock().unwrap().clone()
        }
    }

    impl UnwrapOps for Scripted {
        async fn lookup(&self, token: &WrappingToken) -> Result<WrapLookup, VaultError> {
            assert!(token.expose() == "hvs.wrap");
            self.calls.lock().unwrap().push("lookup");
            if !self.lookup_ok {
                return Err(VaultError::WrapMismatch(WrapMismatch::Invalid));
            }
            Ok(WrapLookup {
                creation_path: self.path.to_string(),
                creation_ttl: Duration::from_secs(self.ttl_secs),
                creation_time: "2026-10-01T00:00:00Z".into(),
            })
        }

        async fn unwrap_body(
            &self,
            token: WrappingToken,
            _checked: &CheckedLookup,
        ) -> Result<Zeroizing<Vec<u8>>, VaultError> {
            assert!(token.expose() == "hvs.wrap");
            self.calls.lock().unwrap().push("unwrap");
            if !self.unwrap_ok {
                return Err(VaultError::WrapMismatch(WrapMismatch::Invalid));
            }
            Ok(Zeroizing::new(self.body.to_vec()))
        }
    }

    fn run<F: Future>(f: F) -> F::Output {
        tokio::runtime::Builder::new_current_thread()
            .build()
            .unwrap()
            .block_on(f)
    }

    #[test]
    fn a_matching_token_is_looked_up_then_unwrapped_and_yields_only_the_field() {
        let ops = Scripted::new(ALICE, 60, true);
        let key = run(unwrap_checked(&ops, wrapping("hvs.wrap"), &expect())).unwrap();
        assert!(key.as_str() == "sk-ALICE-SENTINEL");
        assert_eq!(ops.calls(), ["lookup", "unwrap"]);
    }

    #[test]
    fn another_users_token_is_refused_before_it_is_unwrapped() {
        let ops = Scripted::new(BOB, 60, true);
        assert!(matches!(
            run(unwrap_checked(&ops, wrapping("hvs.wrap"), &expect())),
            Err(VaultError::WrapMismatch(WrapMismatch::CreationPath))
        ));
        assert_eq!(ops.calls(), ["lookup"]);
    }

    #[test]
    fn a_token_outside_the_ttl_bound_is_refused_before_it_is_unwrapped() {
        for ttl in [0, 61] {
            let ops = Scripted::new(ALICE, ttl, true);
            assert!(matches!(
                run(unwrap_checked(&ops, wrapping("hvs.wrap"), &expect())),
                Err(VaultError::WrapMismatch(WrapMismatch::CreationTtl { .. }))
            ));
            assert_eq!(ops.calls(), ["lookup"], "{ttl}");
        }
    }

    #[test]
    fn a_failed_lookup_stops_before_unwrap() {
        let ops = Scripted::new(ALICE, 60, false);
        assert!(matches!(
            run(unwrap_checked(&ops, wrapping("hvs.wrap"), &expect())),
            Err(VaultError::WrapMismatch(WrapMismatch::Invalid))
        ));
        assert_eq!(ops.calls(), ["lookup"]);
    }

    #[test]
    fn a_failed_unwrap_is_reported_after_a_passing_lookup() {
        let ops = Scripted {
            unwrap_ok: false,
            ..Scripted::new(ALICE, 60, true)
        };
        assert!(matches!(
            run(unwrap_checked(&ops, wrapping("hvs.wrap"), &expect())),
            Err(VaultError::WrapMismatch(WrapMismatch::Invalid))
        ));
        assert_eq!(ops.calls(), ["lookup", "unwrap"]);
    }

    #[test]
    fn a_missing_field_after_unwrap_is_named() {
        let ops = Scripted::new(ALICE, 60, true);
        let other = WrapExpectation::new(
            "maknae-kv",
            "maknae/users/alice/openai/personal",
            "token",
            Duration::from_secs(60),
        )
        .unwrap();
        assert!(matches!(
            run(unwrap_checked(&ops, wrapping("hvs.wrap"), &other)),
            Err(VaultError::KvField { .. })
        ));
        assert_eq!(ops.calls(), ["lookup", "unwrap"]);
    }
}
