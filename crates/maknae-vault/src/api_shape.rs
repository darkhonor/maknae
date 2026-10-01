use crate::VaultError;
use serde::de::{Deserialize, Deserializer, Visitor};
use std::fmt;
use zeroize::Zeroizing;

pub const MAX_VAULT_BODY_BYTES: usize = 64 * 1024;
pub const MAX_TOKEN_BYTES: usize = 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WrapMismatch {
    NotWrapped,
    CreationPath,
    CreationTtl { ttl_secs: u64, max_secs: u64 },
    Invalid,
}

impl fmt::Display for WrapMismatch {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            WrapMismatch::NotWrapped => {
                f.write_str("Vault did not wrap the response; it was refused and not kept")
            }
            WrapMismatch::CreationPath => {
                f.write_str("the token wraps a different path than this request names")
            }
            WrapMismatch::CreationTtl { ttl_secs, max_secs } => {
                write!(f, "the token's TTL {ttl_secs}s is outside 1..={max_secs}s")
            }
            WrapMismatch::Invalid => {
                f.write_str("the token is expired, already used, or not a wrapping token")
            }
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum VaultOp {
    UserpassLogin,
    WrappedRead,
    WrapLookup,
    Unwrap,
}

impl VaultOp {
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            VaultOp::UserpassLogin => "userpass login",
            VaultOp::WrappedRead => "wrapped KV read",
            VaultOp::WrapLookup => "wrapping lookup",
            VaultOp::Unwrap => "unwrap",
        }
    }
}

pub(crate) fn refuse_status(op: VaultOp, status: u16) -> VaultError {
    let hint = match (op, status) {
        (VaultOp::UserpassLogin, 400) => {
            return VaultError::UserpassLogin("wrong username or password")
        }
        (VaultOp::WrapLookup | VaultOp::Unwrap, 400 | 403) => {
            return VaultError::WrapMismatch(WrapMismatch::Invalid)
        }
        (VaultOp::WrappedRead, 403) => {
            "the token is expired or revoked (run `maknae login`), or the path is outside your grant"
        }
        (VaultOp::WrappedRead, 404) => "no secret at this path",
        _ => "",
    };
    VaultError::VaultStatus {
        op: op.as_str(),
        status,
        hint,
    }
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) struct BodyOverflow;

pub(crate) fn append_bounded(
    buf: &mut Zeroizing<Vec<u8>>,
    chunk: &[u8],
) -> Result<(), BodyOverflow> {
    if chunk.len() > buf.capacity() - buf.len() {
        return Err(BodyOverflow);
    }
    buf.extend_from_slice(chunk);
    Ok(())
}

pub(crate) fn url_path_is_safe(s: &str) -> bool {
    !s.is_empty()
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-' | b'/'))
}

pub(crate) fn token_is_acceptable(s: &str) -> Result<(), &'static str> {
    if !(1..=MAX_TOKEN_BYTES).contains(&s.len()) {
        return Err("must be 1..=1024 bytes");
    }
    if !s
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'))
    {
        return Err("has a character outside [A-Za-z0-9._-]");
    }
    Ok(())
}

pub(crate) struct SecretStr(pub(crate) Zeroizing<String>);

struct SecretStrVisitor;

impl Visitor<'_> for SecretStrVisitor {
    type Value = Zeroizing<String>;

    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("a string")
    }

    fn visit_str<E: serde::de::Error>(self, v: &str) -> Result<Self::Value, E> {
        Ok(Zeroizing::new(v.to_owned()))
    }
}

impl<'de> Deserialize<'de> for SecretStr {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        d.deserialize_str(SecretStrVisitor).map(SecretStr)
    }
}

pub(crate) fn de_secret<'de, D: Deserializer<'de>>(d: D) -> Result<Zeroizing<String>, D::Error> {
    d.deserialize_str(SecretStrVisitor)
}

pub(crate) fn json_refusal(op: VaultOp, e: &serde_json::Error) -> VaultError {
    let (line, column) = (e.line(), e.column());
    VaultError::VaultBody {
        op: op.as_str(),
        why: format!("{:?} error at line {line} column {column}", e.classify()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn append_bounded_fills_to_capacity_and_never_grows() {
        let mut buf = Zeroizing::new(Vec::with_capacity(8));
        assert_eq!(append_bounded(&mut buf, b"12345"), Ok(()));
        assert_eq!(append_bounded(&mut buf, b"678"), Ok(()));
        assert_eq!(append_bounded(&mut buf, b"9"), Err(BodyOverflow));
        assert_eq!((buf.len(), buf.capacity()), (8, 8));
        let mut fresh = Zeroizing::new(Vec::with_capacity(8));
        assert_eq!(append_bounded(&mut fresh, b"123456789"), Err(BodyOverflow));
        assert!(fresh.is_empty());
    }

    #[test]
    fn url_path_is_safe_admits_only_the_vault_path_alphabet() {
        assert!(url_path_is_safe(
            "maknae-kv/data/maknae/users/alice_1/openai.v2"
        ));
        for bad in ["", "a?b", "a#b", "a%2eb", "a b", "a\\b", "ä", "a;b"] {
            assert!(!url_path_is_safe(bad), "{bad:?}");
        }
    }

    #[test]
    fn token_shape_is_bounded_and_header_safe() {
        assert_eq!(token_is_acceptable("hvs.CAESIabc_-9"), Ok(()));
        assert_eq!(token_is_acceptable(&"a".repeat(MAX_TOKEN_BYTES)), Ok(()));
        assert!(token_is_acceptable("").is_err());
        assert!(token_is_acceptable(&"a".repeat(MAX_TOKEN_BYTES + 1)).is_err());
        for bad in ["hvs.a b", "hvs.a\nb", "hvs.\"", "hvs.a/b"] {
            assert!(token_is_acceptable(bad).is_err(), "{bad:?}");
        }
    }

    #[test]
    fn op_names_are_stable() {
        assert_eq!(
            [
                VaultOp::UserpassLogin.as_str(),
                VaultOp::WrappedRead.as_str(),
                VaultOp::WrapLookup.as_str(),
                VaultOp::Unwrap.as_str(),
            ],
            [
                "userpass login",
                "wrapped KV read",
                "wrapping lookup",
                "unwrap"
            ]
        );
    }

    #[test]
    fn each_status_maps_to_its_named_refusal() {
        assert!(matches!(
            refuse_status(VaultOp::UserpassLogin, 400),
            VaultError::UserpassLogin("wrong username or password")
        ));
        assert!(matches!(
            refuse_status(VaultOp::WrappedRead, 403),
            VaultError::VaultStatus { status: 403, hint, .. } if hint.contains("maknae login")
        ));
        assert!(matches!(
            refuse_status(VaultOp::WrappedRead, 404),
            VaultError::VaultStatus { status: 404, hint, .. } if hint.contains("no secret")
        ));
        for op in [VaultOp::WrapLookup, VaultOp::Unwrap] {
            for status in [400, 403] {
                assert!(
                    matches!(
                        refuse_status(op, status),
                        VaultError::WrapMismatch(WrapMismatch::Invalid)
                    ),
                    "{op:?} {status}"
                );
            }
        }
        assert!(matches!(
            refuse_status(VaultOp::UserpassLogin, 500),
            VaultError::VaultStatus {
                status: 500,
                hint: "",
                ..
            }
        ));
        assert!(matches!(
            refuse_status(VaultOp::WrappedRead, 400),
            VaultError::VaultStatus {
                status: 400,
                hint: "",
                ..
            }
        ));
    }

    #[test]
    fn a_secret_string_deserializes_plain_and_escaped_at_exact_size() {
        let s: SecretStr = serde_json::from_slice(br#""plain""#).unwrap();
        assert!(s.0.as_str() == "plain" && s.0.capacity() == 5);
        let s: SecretStr = serde_json::from_slice(br#""sk\u002dA""#).unwrap();
        assert!(s.0.as_str() == "sk-A" && s.0.capacity() == 4);
        assert!(serde_json::from_slice::<SecretStr>(b"12").is_err());
    }

    #[test]
    fn the_secret_visitor_names_what_it_expects() {
        let expected: &dyn serde::de::Expected = &SecretStrVisitor;
        assert_eq!(expected.to_string(), "a string");
    }

    #[test]
    fn de_secret_reads_a_field_into_a_zeroizing_string() {
        #[derive(serde::Deserialize)]
        struct T {
            #[serde(deserialize_with = "de_secret")]
            v: Zeroizing<String>,
        }
        let t: T = serde_json::from_slice(br#"{"v":"hvs.x"}"#).unwrap();
        assert!(t.v.as_str() == "hvs.x");
    }

    #[test]
    fn a_json_refusal_never_echoes_the_body() {
        let e = serde_json::from_slice::<SecretStr>(b"12345678")
            .err()
            .unwrap();
        let msg = json_refusal(VaultOp::Unwrap, &e).to_string();
        assert!(!msg.contains("12345678"), "{msg}");
        assert!(msg.contains("Data error at line 1"), "{msg}");
        assert!(msg.starts_with("Vault unwrap response refused"), "{msg}");
    }

    #[test]
    fn wrap_mismatch_lines_carry_no_path() {
        assert_eq!(
            WrapMismatch::CreationTtl {
                ttl_secs: 600,
                max_secs: 60
            }
            .to_string(),
            "the token's TTL 600s is outside 1..=60s"
        );
        for m in [
            WrapMismatch::NotWrapped,
            WrapMismatch::CreationPath,
            WrapMismatch::Invalid,
        ] {
            let line = m.to_string();
            assert!(!line.is_empty() && !line.contains('/'), "{line}");
        }
    }
}
