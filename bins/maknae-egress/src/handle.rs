//! The deputy's decision, separated from its I/O (#240a).
//!
//! Pure and mutation-visible. `serve.rs` owns the socket; this owns what the
//! deputy is willing to do with a frame once it has one. The split is the
//! crate convention — `peercred`/`peer_identity`, `secret_io`/`secret_source`.

use maknae_config::EgressBounds;
use maknae_proto::{EgressFrameReply, EgressFrameRequest, PromptReply};

/// Why the deputy refused a frame. Every variant is a refusal the kernel sees;
/// there is no "carry on anyway".
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Refusal {
    /// The frame named a Vault path outside the deputy's granted prefix. The
    /// Vault policy is the real bound; this turns a kernel BUG into a named
    /// refusal instead of a confusing Vault 403.
    KeyPathOutsideBounds,
    /// Shape admission failed — an empty field, an over-long conversation.
    MalformedFrame,
}

/// Decide what to do with one decoded frame.
///
/// **The deputy never chains.** It does not read `content` for instructions,
/// does not follow anything a reply might suggest, and has no way to originate
/// a request of its own. Under the orchestrator case a model reply may say
/// "now call provider:X"; the deputy must be structurally incapable of acting
/// on it, and the absence of any such path here is that property.
pub fn decide(
    req: &EgressFrameRequest,
    bounds: &EgressBounds,
) -> Result<EgressFrameReply, Refusal> {
    if !maknae_proto::egress_frame_request_is_acceptable(req) {
        return Err(Refusal::MalformedFrame);
    }
    if !maknae_config::path_is_within_prefix(&req.key_vault_path, &bounds.key_vault_path_prefix) {
        return Err(Refusal::KeyPathOutsideBounds);
    }
    // #240a is the CONDUIT. The provider call, its TLS, and the reply
    // validation are #240b; until then the deputy proves the whole path
    // end-to-end with a canned reply and makes no network access at all.
    Ok(EgressFrameReply {
        reply: PromptReply {
            blocks: vec![],
            tool_calls: vec![],
        },
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use maknae_proto::{ContentBlock, SecretText};

    fn bounds() -> EgressBounds {
        EgressBounds {
            key_vault_path_prefix: "secret/data/maknae/providers".into(),
        }
    }

    fn req(key_vault_path: &str) -> EgressFrameRequest {
        EgressFrameRequest {
            destination: "provider:openai".into(),
            endpoint: "https://api.example.test/v1".into(),
            model: "m".into(),
            key_vault_path: key_vault_path.into(),
            conversation: "conv1".into(),
            content: vec![ContentBlock::Text {
                text: SecretText(zeroize::Zeroizing::new("hello".into())),
            }],
        }
    }

    #[test]
    fn a_frame_within_bounds_is_accepted() {
        assert!(decide(&req("secret/data/maknae/providers/openai"), &bounds()).is_ok());
    }

    /// The containment check, from the deputy's side. A sibling path that
    /// merely begins with the prefix is refused BY NAME.
    #[test]
    fn a_key_path_outside_the_prefix_is_refused_by_name() {
        assert_eq!(
            decide(&req("secret/data/maknae/providers-evil/key"), &bounds()),
            Err(Refusal::KeyPathOutsideBounds)
        );
        assert_eq!(
            decide(&req("secret/data/other/key"), &bounds()),
            Err(Refusal::KeyPathOutsideBounds)
        );
    }

    #[test]
    fn a_malformed_frame_is_refused_before_the_bounds_check() {
        let mut r = req("secret/data/maknae/providers/openai");
        r.content.clear();
        assert_eq!(decide(&r, &bounds()), Err(Refusal::MalformedFrame));
    }
}
