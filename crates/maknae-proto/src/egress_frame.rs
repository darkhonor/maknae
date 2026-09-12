//! The `maknaed` ↔ `maknae-egress` socket frames (#240a).
//!
//! The kernel resolves `provider:<name>` and puts the RESOLVED record on the
//! frame (#240a D1): egress parses no provider registry and therefore cannot
//! drift from the kernel's view of it. One parser, one source of truth — the
//! failure that created `maknae-io` was each site re-implementing the checks.
//!
//! `destination` rides on EVERY request and is never process-global (#240a
//! I1). The kernel already computes it per request, and per-request selection
//! is what lets several providers — and several per-user endpoints — work
//! without reshaping anything here.
//!
//! There is deliberately NO `delegated_from` field. Request origin has no
//! carrier today (ADR-0024) and #241 owns closing that; a slot for an unbuilt
//! mechanism is the ADR-0023 failure.


use serde::{Deserialize, Serialize};

/// What the kernel hands the egress deputy for one decided `session.prompt`.
///
/// `Debug` is hand-written: it must reproduce neither the prompt content nor
/// `key_vault_path`, which names where the provider credential lives and is
/// marked `omit` on `ProviderConfig`. `destination` IS shown — it is the
/// audit-correlation handle and appears in records already.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EgressFrameRequest {
    /// `provider:<name>`, per request, never process-global (#240a I1).
    pub destination: String,
    /// The resolved OpenAI-compatible base URL.
    pub endpoint: String,
    /// The resolved model identifier.
    pub model: String,
    /// The resolved Vault KV path holding this provider's key. Egress
    /// validates it against its own configured prefix before reading.
    pub key_vault_path: String,
    /// The loop's identifier (#241). Informational, never decided on.
    pub conversation: String,
    /// The content leaving the trust plane.
    pub content: Vec<crate::ContentBlock>,
}

impl std::fmt::Debug for EgressFrameRequest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EgressFrameRequest")
            .field("destination", &self.destination)
            .field("endpoint", &self.endpoint)
            .field("model", &self.model)
            .field("key_vault_path", &"<omitted>")
            .field("conversation", &self.conversation)
            .field("content", &format_args!("<{} blocks>", self.content.len()))
            .finish()
    }
}

/// The deputy's answer. Nothing but the reply: egress returns bytes to the
/// kernel and does nothing with them (#240a D4).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct EgressFrameReply {
    pub reply: crate::PromptReply,
}

/// Shape admission, applied by the kernel before a byte reaches the socket.
/// Deliberately shape-only: whether this subject may reach this destination
/// was decided by the PDP long before the frame existed.
pub fn egress_frame_request_is_acceptable(r: &EgressFrameRequest) -> bool {
    crate::conversation_id_is_acceptable(&r.conversation)
        && !r.destination.is_empty()
        && !r.endpoint.is_empty()
        && !r.model.is_empty()
        && !r.key_vault_path.is_empty()
        && !r.content.is_empty()
}

#[cfg(test)]
mod tests {
    use super::*;
    use zeroize::Zeroizing;

    fn text(s: &str) -> crate::ContentBlock {
        crate::ContentBlock::Text {
            text: crate::SecretText(Zeroizing::new(s.into())),
        }
    }

    fn req(conversation: &str, content: Vec<crate::ContentBlock>) -> EgressFrameRequest {
        EgressFrameRequest {
            destination: "provider:openai".into(),
            endpoint: "https://api.example.test/v1".into(),
            model: "some-model".into(),
            key_vault_path: "secret/data/maknae/providers/openai".into(),
            conversation: conversation.into(),
            content,
        }
    }

    /// The frame carries prompt content out of the trust plane. Its `Debug`
    /// must not reproduce it — nor the Vault path that names where the
    /// provider credential lives (`ProviderConfig` marks that `omit`).
    #[test]
    fn an_egress_frame_debug_redacts_prompt_content_and_the_key_path() {
        let r = req("conv1", vec![text("the president flies at 0300")]);
        let d = format!("{r:?}");
        assert!(!d.contains("0300"), "prompt content leaked: {d}");
        assert!(!d.contains("secret/data"), "key path leaked: {d}");
        assert!(d.contains("provider:openai"), "destination should be visible: {d}");
    }

    #[test]
    fn a_frame_round_trips() {
        let r = req("conv1", vec![text("hello")]);
        let mut buf = Vec::new();
        ciborium::into_writer(&r, &mut buf).unwrap();
        let back: EgressFrameRequest = ciborium::from_reader(&buf[..]).unwrap();
        assert_eq!(back, r);
    }

    /// Shape admission is the kernel's, applied before anything is written to
    /// the socket. `conversation` reuses the existing bound rather than
    /// inventing a second one.
    #[test]
    fn an_over_long_conversation_is_refused() {
        let ok = req(&"a".repeat(crate::MAX_CONVERSATION_ID_BYTES), vec![text("x")]);
        assert!(egress_frame_request_is_acceptable(&ok));
        let bad = req(
            &"a".repeat(crate::MAX_CONVERSATION_ID_BYTES + 1),
            vec![text("x")],
        );
        assert!(!egress_frame_request_is_acceptable(&bad));
    }

    #[test]
    fn an_empty_content_frame_is_refused() {
        assert!(!egress_frame_request_is_acceptable(&req("conv1", vec![])));
    }
}
