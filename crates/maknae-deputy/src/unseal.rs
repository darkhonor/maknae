//! Opening a turn's sealed key into its provider key, behind the `KeyOpener` seam (#153).
use crate::handle::Refusal;
use maknae_config::EgressBounds;
use maknae_proto::EgressFrameRequest;
use std::fmt;
use std::future::Future;
use zeroize::Zeroizing;

const DESTINATION_PREFIX: &str = "provider:";

#[derive(Clone, Copy)]
pub struct OpenRequest<'a> {
    pub conversation: &'a str,
    pub provider: &'a str,
    pub model: &'a str,
    pub kv_mount: &'a str,
    pub key_vault_path: &'a str,
    pub key_field: &'a str,
}

impl fmt::Debug for OpenRequest<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("OpenRequest")
            .field("conversation", &self.conversation)
            .field("provider", &self.provider)
            .field("model", &self.model)
            .field("kv_mount", &self.kv_mount)
            .field("key_vault_path", &"<omitted>")
            .field("key_field", &"<omitted>")
            .finish()
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum OpenFailure {
    Request,
    Seal,
    Token,
    WrongPath,
    Ttl,
    Invalid,
    Field,
    Vault,
}

impl OpenFailure {
    pub fn reason(&self) -> &'static str {
        match self {
            OpenFailure::Request => "the request cannot name a Vault key path",
            OpenFailure::Seal => "the sealed key does not match this request",
            OpenFailure::Token => "the sealed key does not hold a wrapping token",
            OpenFailure::WrongPath => {
                "the wrapping token wraps a different path than this request names"
            }
            OpenFailure::Ttl => "the wrapping token's TTL is outside the allowed bound",
            OpenFailure::Invalid => {
                "the wrapping token is expired, already used, or not a wrapping token"
            }
            OpenFailure::Field => "the key field is absent from the secret",
            OpenFailure::Vault => "the Vault unwrap failed",
        }
    }
}

pub trait KeyOpener {
    fn open(
        &self,
        sealed: &[u8],
        req: &OpenRequest<'_>,
    ) -> impl Future<Output = Result<Zeroizing<String>, OpenFailure>> + Send;
}

pub fn open_request<'a>(
    req: &'a EgressFrameRequest,
    bounds: &'a EgressBounds,
) -> Result<OpenRequest<'a>, Refusal> {
    match req.destination.strip_prefix(DESTINATION_PREFIX) {
        Some(provider) if maknae_config::provider_name_is_acceptable(provider) => Ok(OpenRequest {
            conversation: &req.conversation,
            provider,
            model: &req.model,
            kv_mount: &bounds.kv_mount,
            key_vault_path: &req.key_vault_path,
            key_field: &req.key_field,
        }),
        _ => Err(Refusal::MalformedFrame),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use maknae_proto::{ContentBlock, SecretText, Turn};

    fn bounds() -> EgressBounds {
        EgressBounds {
            kv_mount: "maknae-kv".into(),
            user_prefix: "maknae/users".into(),
            vault_addr: "https://vault.example:8200".into(),
        }
    }

    fn frame(destination: &str) -> EgressFrameRequest {
        EgressFrameRequest {
            destination: destination.into(),
            endpoint: "https://api.example.test/v1".into(),
            model: "gpt-5.6-luna".into(),
            key_vault_path: "maknae/users/alice/openai/personal".into(),
            key_field: "api_key".into(),
            reasoning_effort: None,
            conversation: "conv1".into(),
            turns: vec![Turn::User {
                content: vec![ContentBlock::Text {
                    text: SecretText(Zeroizing::new("hello".into())),
                }],
            }],
            output_tokens: None,
            output_tokens_field: None,
            sealed_key: maknae_proto::SealedKey::new(vec![7u8; maknae_proto::SEALED_KEY_MIN_BYTES])
                .unwrap(),
        }
    }

    #[test]
    fn the_open_request_names_the_bare_provider_and_the_daemons_own_mount() {
        let f = frame("provider:openai");
        let b = bounds();
        let r = open_request(&f, &b).unwrap();
        assert_eq!(
            [
                r.conversation,
                r.provider,
                r.model,
                r.kv_mount,
                r.key_vault_path,
                r.key_field
            ],
            [
                "conv1",
                "openai",
                "gpt-5.6-luna",
                "maknae-kv",
                "maknae/users/alice/openai/personal",
                "api_key"
            ]
        );
    }

    #[test]
    fn a_destination_that_is_not_a_provider_name_is_a_malformed_frame() {
        let long = format!(
            "provider:{}",
            "n".repeat(maknae_config::MAX_PROVIDER_NAME_BYTES + 1)
        );
        for bad in [
            "openai",
            "provider:",
            "providers:openai",
            "Provider:openai",
            "provider:open ai",
            long.as_str(),
        ] {
            assert_eq!(
                open_request(&frame(bad), &bounds()).map(|_| ()),
                Err(Refusal::MalformedFrame),
                "{bad}"
            );
        }
        let edge = format!(
            "provider:{}",
            "n".repeat(maknae_config::MAX_PROVIDER_NAME_BYTES)
        );
        assert_eq!(
            open_request(&frame(&edge), &bounds()).map(|r| r.provider.len()),
            Ok(maknae_config::MAX_PROVIDER_NAME_BYTES)
        );
    }

    #[test]
    fn an_open_request_debug_omits_where_the_key_lives() {
        let f = frame("provider:openai");
        let b = bounds();
        assert_eq!(
            format!("{:?}", open_request(&f, &b).unwrap()),
            r#"OpenRequest { conversation: "conv1", provider: "openai", model: "gpt-5.6-luna", kv_mount: "maknae-kv", key_vault_path: "<omitted>", key_field: "<omitted>" }"#
        );
    }

    #[test]
    fn each_open_failure_has_its_own_content_free_reason() {
        use OpenFailure::*;
        assert_eq!(
            [Request, Seal, Token, WrongPath, Ttl, Invalid, Field, Vault].map(|f| f.reason()),
            [
                "the request cannot name a Vault key path",
                "the sealed key does not match this request",
                "the sealed key does not hold a wrapping token",
                "the wrapping token wraps a different path than this request names",
                "the wrapping token's TTL is outside the allowed bound",
                "the wrapping token is expired, already used, or not a wrapping token",
                "the key field is absent from the secret",
                "the Vault unwrap failed",
            ]
        );
    }
}
