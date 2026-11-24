use crate::SealError;
use std::fmt;

pub const AAD_DOMAIN: &[u8] = b"maknae-seal-aad-v1";
pub const CREDENTIAL_AAD_DOMAIN: &[u8] = b"maknae-seal-aad-credential-v1";
pub const FORGE_AAD_DOMAIN: &[u8] = b"maknae-seal-aad-forge-v1";
pub const MAX_AAD_FIELD_BYTES: usize = 1024;

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum CredentialDirection {
    ToAgent,
    ToRevoke,
}

impl CredentialDirection {
    fn as_str(self) -> &'static str {
        match self {
            CredentialDirection::ToAgent => "to-agent",
            CredentialDirection::ToRevoke => "to-revoke",
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum ForgePurpose {
    TaskerReach,
}

impl ForgePurpose {
    fn as_str(self) -> &'static str {
        match self {
            ForgePurpose::TaskerReach => "tasker-reach",
        }
    }
}

#[derive(Clone, Copy)]
pub struct ForgeSealContext<'a> {
    pub purpose: ForgePurpose,
    pub nonce: &'a str,
    pub server: &'a str,
    pub expected_path: &'a str,
    pub key_field: &'a str,
}

#[derive(Clone, Copy)]
pub struct CredentialSealContext<'a> {
    pub direction: CredentialDirection,
    pub agent: &'a str,
    pub task: &'a str,
    pub class: &'a str,
    pub kind: &'a str,
    pub app: &'a str,
    pub set: u8,
}

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

fn aad_field_ok(field: &[u8]) -> bool {
    (1..=MAX_AAD_FIELD_BYTES).contains(&field.len())
}

fn encode(domain: &[u8], fields: &[&str]) -> Vec<u8> {
    let len = domain.len() + fields.iter().map(|f| 2 + f.len()).sum::<usize>();
    let mut out = Vec::with_capacity(len);
    out.extend_from_slice(domain);
    for field in fields {
        out.extend_from_slice(&(field.len() as u16).to_be_bytes());
        out.extend_from_slice(field.as_bytes());
    }
    out
}

impl SealAad {
    pub fn new(ctx: &SealContext<'_>) -> Result<Self, SealError> {
        let fields = [
            ctx.conversation,
            ctx.provider,
            ctx.model,
            ctx.expected_path,
            ctx.key_field,
        ];
        if !fields.iter().all(|f| aad_field_ok(f.as_bytes())) {
            return Err(SealError::AadField);
        }
        Ok(Self(encode(AAD_DOMAIN, &fields)))
    }

    pub fn credential(ctx: &CredentialSealContext<'_>) -> Result<Self, SealError> {
        let set = ctx.set.to_string();
        let fields = [
            ctx.direction.as_str(),
            ctx.agent,
            ctx.task,
            ctx.class,
            ctx.kind,
            ctx.app,
            &set,
        ];
        if !fields.iter().all(|f| aad_field_ok(f.as_bytes())) {
            return Err(SealError::AadField);
        }
        Ok(Self(encode(CREDENTIAL_AAD_DOMAIN, &fields)))
    }

    pub fn forge(ctx: &ForgeSealContext<'_>) -> Result<Self, SealError> {
        let fields = [
            ctx.purpose.as_str(),
            ctx.nonce,
            ctx.server,
            ctx.expected_path,
            ctx.key_field,
        ];
        if !fields.iter().all(|f| aad_field_ok(f.as_bytes())) {
            return Err(SealError::AadField);
        }
        Ok(Self(encode(FORGE_AAD_DOMAIN, &fields)))
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
    fn an_aad_field_is_one_to_1024_bytes_inclusive() {
        for (len, ok) in [(0, false), (1, true), (1024, true), (1025, false)] {
            assert_eq!(aad_field_ok(&vec![b'x'; len]), ok, "{len}");
        }
    }

    #[test]
    fn encode_writes_the_domain_and_each_length_prefixed_field_at_exact_capacity() {
        let out = encode(AAD_DOMAIN, &["ab", "c", "", "def", "g"]);
        let mut want = AAD_DOMAIN.to_vec();
        want.extend_from_slice(b"\x00\x02ab\x00\x01c\x00\x00\x00\x03def\x00\x01g");
        assert_eq!(out, want);
        assert_eq!(out.capacity(), AAD_DOMAIN.len() + 2 * 5 + 7);
        let long = "y".repeat(300);
        let out = encode(AAD_DOMAIN, &[&long, "a", "b", "c", "d"]);
        assert_eq!(&out[AAD_DOMAIN.len()..AAD_DOMAIN.len() + 2], &[0x01, 0x2c]);
        assert_eq!(out.len(), out.capacity());
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

    fn cctx() -> CredentialSealContext<'static> {
        CredentialSealContext {
            direction: CredentialDirection::ToAgent,
            agent: "agent-1",
            task: "task-1",
            class: "git-write",
            kind: "github-app-installation",
            app: "app-1",
            set: 3,
        }
    }

    #[test]
    fn credential_encoding_is_its_domain_then_fields_in_fixed_order() {
        let aad = SealAad::credential(&cctx()).unwrap();
        let mut want = CREDENTIAL_AAD_DOMAIN.to_vec();
        for f in [
            "to-agent",
            "agent-1",
            "task-1",
            "git-write",
            "github-app-installation",
            "app-1",
            "3",
        ] {
            want.extend_from_slice(&(f.len() as u16).to_be_bytes());
            want.extend_from_slice(f.as_bytes());
        }
        assert_eq!(aad.as_bytes(), &want[..]);
        assert_eq!(aad.as_bytes().len(), aad.0.capacity());
        let revoke = SealAad::credential(&CredentialSealContext {
            direction: CredentialDirection::ToRevoke,
            ..cctx()
        })
        .unwrap();
        assert_eq!(
            &revoke.as_bytes()[CREDENTIAL_AAD_DOMAIN.len()..][..11],
            b"\x00\x09to-revoke"
        );
    }

    #[test]
    fn the_two_directions_and_the_provider_domain_never_collide() {
        let a = SealAad::credential(&cctx()).unwrap();
        let r = SealAad::credential(&CredentialSealContext {
            direction: CredentialDirection::ToRevoke,
            ..cctx()
        })
        .unwrap();
        let p = SealAad::new(&ctx()).unwrap();
        assert_ne!(a, r);
        assert_ne!(a, p);
        assert_ne!(r, p);
        assert!(!CREDENTIAL_AAD_DOMAIN.starts_with(AAD_DOMAIN));
        assert!(!AAD_DOMAIN.starts_with(CREDENTIAL_AAD_DOMAIN));
    }

    #[test]
    fn an_empty_or_oversized_credential_field_is_refused() {
        let over = "x".repeat(MAX_AAD_FIELD_BYTES + 1);
        let ok = "x".repeat(MAX_AAD_FIELD_BYTES);
        assert!(SealAad::credential(&CredentialSealContext { app: &ok, ..cctx() }).is_ok());
        let bad = [
            CredentialSealContext {
                agent: "",
                ..cctx()
            },
            CredentialSealContext { task: "", ..cctx() },
            CredentialSealContext {
                class: "",
                ..cctx()
            },
            CredentialSealContext { kind: "", ..cctx() },
            CredentialSealContext { app: "", ..cctx() },
            CredentialSealContext {
                agent: &over,
                ..cctx()
            },
            CredentialSealContext {
                task: &over,
                ..cctx()
            },
            CredentialSealContext {
                class: &over,
                ..cctx()
            },
            CredentialSealContext {
                kind: &over,
                ..cctx()
            },
            CredentialSealContext {
                app: &over,
                ..cctx()
            },
        ];
        for (i, c) in bad.iter().enumerate() {
            assert_eq!(
                SealAad::credential(c).unwrap_err(),
                SealError::AadField,
                "case {i}"
            );
        }
    }

    fn fctx() -> ForgeSealContext<'static> {
        ForgeSealContext {
            purpose: ForgePurpose::TaskerReach,
            nonce: "0123456789abcdef0123456789abcdef",
            server: "github.com",
            expected_path: "maknae-kv/data/maknae/users/alice/forge/github.com",
            key_field: "token",
        }
    }

    #[test]
    fn forge_encoding_is_its_domain_then_fields_in_fixed_order() {
        let aad = SealAad::forge(&fctx()).unwrap();
        let mut want = FORGE_AAD_DOMAIN.to_vec();
        for f in [
            "tasker-reach",
            "0123456789abcdef0123456789abcdef",
            "github.com",
            "maknae-kv/data/maknae/users/alice/forge/github.com",
            "token",
        ] {
            want.extend_from_slice(&(f.len() as u16).to_be_bytes());
            want.extend_from_slice(f.as_bytes());
        }
        assert_eq!(aad.as_bytes(), &want[..]);
        assert_eq!(aad.as_bytes().len(), aad.0.capacity());
        assert_eq!(FORGE_AAD_DOMAIN, b"maknae-seal-aad-forge-v1");
    }

    #[test]
    fn every_forge_field_changes_the_encoding() {
        let base = SealAad::forge(&fctx()).unwrap();
        let changed = [
            ForgeSealContext {
                nonce: "fedcba9876543210fedcba9876543210",
                ..fctx()
            },
            ForgeSealContext {
                server: "ghe.example.com",
                ..fctx()
            },
            ForgeSealContext {
                expected_path: "maknae-kv/data/maknae/users/bob/forge/github.com",
                ..fctx()
            },
            ForgeSealContext {
                key_field: "pat",
                ..fctx()
            },
        ];
        for (i, c) in changed.iter().enumerate() {
            assert_ne!(SealAad::forge(c).unwrap(), base, "field {i}");
        }
        let shifted = SealAad::forge(&ForgeSealContext {
            server: "github.co",
            expected_path: "mmaknae-kv/data/maknae/users/alice/forge/github.com",
            ..fctx()
        })
        .unwrap();
        assert_ne!(shifted, base);
    }

    #[test]
    fn the_three_domains_never_collide() {
        let f = SealAad::forge(&fctx()).unwrap();
        let c = SealAad::credential(&cctx()).unwrap();
        let p = SealAad::new(&ctx()).unwrap();
        assert_ne!(f, c);
        assert_ne!(f, p);
        assert_ne!(c, p);
        let domains = [AAD_DOMAIN, CREDENTIAL_AAD_DOMAIN, FORGE_AAD_DOMAIN];
        for (i, a) in domains.iter().enumerate() {
            for (j, b) in domains.iter().enumerate() {
                if i != j {
                    assert!(!a.starts_with(b), "{i} starts with {j}");
                }
            }
        }
        let same_fields = SealAad::new(&SealContext {
            conversation: "tasker-reach",
            provider: fctx().nonce,
            model: fctx().server,
            expected_path: fctx().expected_path,
            key_field: fctx().key_field,
        })
        .unwrap();
        assert_ne!(f, same_fields);
        assert_eq!(
            &f.as_bytes()[FORGE_AAD_DOMAIN.len()..],
            &same_fields.as_bytes()[AAD_DOMAIN.len()..]
        );
    }

    #[test]
    fn a_forge_blob_opens_only_under_the_exact_context() {
        use crate::{open, seal, SealPrivateKey};
        const TOKEN: &[u8] = b"github_pat_forgeSentinel0123456789";
        let key = SealPrivateKey::generate().unwrap();
        let aad = SealAad::forge(&fctx()).unwrap();
        let blob = seal(key.public_key(), &aad, TOKEN).unwrap();
        assert_eq!(open(&key, &aad, blob.as_bytes()).unwrap().as_slice(), TOKEN);
        let changed = [
            ForgeSealContext {
                nonce: "fedcba9876543210fedcba9876543210",
                ..fctx()
            },
            ForgeSealContext {
                server: "ghe.example.com",
                ..fctx()
            },
            ForgeSealContext {
                expected_path: "maknae-kv/data/maknae/users/bob/forge/github.com",
                ..fctx()
            },
            ForgeSealContext {
                key_field: "pat",
                ..fctx()
            },
        ];
        for (i, c) in changed.iter().enumerate() {
            let other = SealAad::forge(c).unwrap();
            assert_eq!(
                open(&key, &other, blob.as_bytes()).unwrap_err(),
                SealError::Open,
                "case {i}"
            );
        }
        let f = fctx();
        let provider = SealAad::new(&SealContext {
            conversation: "tasker-reach",
            provider: f.nonce,
            model: f.server,
            expected_path: f.expected_path,
            key_field: f.key_field,
        })
        .unwrap();
        assert_eq!(
            open(&key, &provider, blob.as_bytes()).unwrap_err(),
            SealError::Open
        );
        let pblob = seal(key.public_key(), &provider, TOKEN).unwrap();
        assert_eq!(
            open(&key, &aad, pblob.as_bytes()).unwrap_err(),
            SealError::Open
        );
    }

    #[test]
    fn an_empty_or_oversized_forge_field_is_refused() {
        let ok = "x".repeat(MAX_AAD_FIELD_BYTES);
        let over = "x".repeat(MAX_AAD_FIELD_BYTES + 1);
        for c in [
            ForgeSealContext {
                nonce: &ok,
                ..fctx()
            },
            ForgeSealContext {
                server: &ok,
                ..fctx()
            },
            ForgeSealContext {
                expected_path: &ok,
                ..fctx()
            },
            ForgeSealContext {
                key_field: &ok,
                ..fctx()
            },
        ] {
            assert!(SealAad::forge(&c).is_ok());
        }
        let bad = [
            ForgeSealContext {
                nonce: "",
                ..fctx()
            },
            ForgeSealContext {
                server: "",
                ..fctx()
            },
            ForgeSealContext {
                expected_path: "",
                ..fctx()
            },
            ForgeSealContext {
                key_field: "",
                ..fctx()
            },
            ForgeSealContext {
                nonce: &over,
                ..fctx()
            },
            ForgeSealContext {
                server: &over,
                ..fctx()
            },
            ForgeSealContext {
                expected_path: &over,
                ..fctx()
            },
            ForgeSealContext {
                key_field: &over,
                ..fctx()
            },
        ];
        for (i, c) in bad.iter().enumerate() {
            assert_eq!(
                SealAad::forge(c).unwrap_err(),
                SealError::AadField,
                "case {i}"
            );
        }
    }
}
