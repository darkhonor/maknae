use crate::SealError;
use std::fmt;

pub const AAD_DOMAIN: &[u8] = b"maknae-seal-aad-v1";
pub const MAX_AAD_FIELD_BYTES: usize = 1024;

#[derive(Clone, Copy)]
pub struct SealContext<'a> {
    pub conversation: &'a str,
    pub provider: &'a str,
    pub model: &'a str,
    pub expected_path: &'a str,
    pub key_field: &'a str,
}

#[derive(Clone, PartialEq, Eq)]
pub struct SealAad(Vec<u8>);

impl SealAad {
    pub fn new(ctx: &SealContext<'_>) -> Result<Self, SealError> {
        let fields = [
            ctx.conversation,
            ctx.provider,
            ctx.model,
            ctx.expected_path,
            ctx.key_field,
        ];
        let mut len = AAD_DOMAIN.len();
        for field in fields {
            if !(1..=MAX_AAD_FIELD_BYTES).contains(&field.len()) {
                return Err(SealError::AadField);
            }
            len += 2 + field.len();
        }
        let mut out = Vec::with_capacity(len);
        out.extend_from_slice(AAD_DOMAIN);
        for field in fields {
            out.extend_from_slice(&(field.len() as u16).to_be_bytes());
            out.extend_from_slice(field.as_bytes());
        }
        Ok(Self(out))
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

impl fmt::Debug for SealAad {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "SealAad(<{} bytes>)", self.0.len())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ctx() -> SealContext<'static> {
        SealContext {
            conversation: "c-1",
            provider: "openai",
            model: "gpt-5.6-luna",
            expected_path: "maknae-kv/data/maknae/users/alice/openai/personal",
            key_field: "api_key",
        }
    }

    #[test]
    fn the_encoding_is_domain_then_length_prefixed_fields_in_fixed_order() {
        let aad = SealAad::new(&SealContext {
            conversation: "c",
            provider: "p",
            model: "m",
            expected_path: "e/x",
            key_field: "k",
        })
        .unwrap();
        let mut want = AAD_DOMAIN.to_vec();
        for f in ["c", "p", "m", "e/x", "k"] {
            want.extend_from_slice(&(f.len() as u16).to_be_bytes());
            want.extend_from_slice(f.as_bytes());
        }
        assert_eq!(aad.as_bytes(), &want[..]);
    }

    #[test]
    fn the_encoding_is_exactly_sized_and_its_debug_hides_the_path() {
        let aad = SealAad::new(&ctx()).unwrap();
        assert_eq!(aad.as_bytes().len(), aad.0.capacity());
        let shown = format!("{aad:?}");
        assert_eq!(shown, format!("SealAad(<{} bytes>)", aad.as_bytes().len()));
        assert!(!shown.contains("alice"));
    }

    #[test]
    fn shifting_bytes_between_fields_changes_the_encoding() {
        let a = SealAad::new(&SealContext {
            provider: "ab",
            model: "c",
            ..ctx()
        })
        .unwrap();
        let b = SealAad::new(&SealContext {
            provider: "a",
            model: "bc",
            ..ctx()
        })
        .unwrap();
        assert_ne!(a, b);
    }

    #[test]
    fn every_field_changes_the_encoding() {
        let base = SealAad::new(&ctx()).unwrap();
        let changed = [
            SealContext {
                conversation: "c-2",
                ..ctx()
            },
            SealContext {
                provider: "other",
                ..ctx()
            },
            SealContext {
                model: "gpt-5.6",
                ..ctx()
            },
            SealContext {
                expected_path: "maknae-kv/data/maknae/users/bob/openai/personal",
                ..ctx()
            },
            SealContext {
                key_field: "org",
                ..ctx()
            },
        ];
        for (i, c) in changed.iter().enumerate() {
            assert_ne!(SealAad::new(c).unwrap(), base, "field {i}");
        }
    }

    #[test]
    fn an_empty_or_oversize_field_is_refused_and_the_bound_is_inclusive() {
        let long = "x".repeat(MAX_AAD_FIELD_BYTES);
        let aad = SealAad::new(&SealContext {
            key_field: &long,
            ..ctx()
        })
        .unwrap();
        let tail = &aad.as_bytes()[aad.as_bytes().len() - MAX_AAD_FIELD_BYTES - 2..][..2];
        assert_eq!(tail, &[0x04, 0x00]);
        let over = "x".repeat(MAX_AAD_FIELD_BYTES + 1);
        let bad = [
            SealContext {
                conversation: "",
                ..ctx()
            },
            SealContext {
                provider: "",
                ..ctx()
            },
            SealContext { model: "", ..ctx() },
            SealContext {
                expected_path: "",
                ..ctx()
            },
            SealContext {
                key_field: "",
                ..ctx()
            },
            SealContext {
                model: &over,
                ..ctx()
            },
        ];
        for (i, c) in bad.iter().enumerate() {
            assert_eq!(
                SealAad::new(c).unwrap_err(),
                SealError::AadField,
                "case {i}"
            );
        }
    }
}
