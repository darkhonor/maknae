//! The deputy's decision, separated from its I/O (#240a).
//!
//! Pure and mutation-visible. `serve.rs` owns the socket; this owns what the
//! deputy is willing to do with a frame once it has one. The split is the
//! crate convention — `peercred`/`peer_identity`, `secret_io`/`secret_source`.
//!
//! What is re-checked here and what is not: the key path is held inside the
//! deputy's own bounds (the one thing the deputy alone knows); the endpoint's
//! scheme and host are NOT re-checked — that decision is the kernel's, the
//! PDP, over root-owned configuration (`maknae-config`'s
//! `endpoint_is_acceptable`: HTTPS anywhere, HTTP to loopback only), and the
//! deputy originates nothing (ADR-0023 decision 3).

use maknae_config::EgressBounds;
use maknae_proto::EgressFrameRequest;

/// Why the deputy refused a frame. Every variant is a refusal the kernel sees;
/// there is no "carry on anyway".
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Refusal {
    /// The frame named a Vault path outside the deputy's granted prefix. The
    /// Vault policy is the real bound; this turns a kernel BUG into a named
    /// refusal instead of a confusing Vault 403.
    KeyPathOutsideBounds,
    /// The frame's Vault path is not a well-formed KV fragment — a `.` or `..`
    /// segment, whitespace, an empty segment. The prefix test alone accepts
    /// `<prefix>/../../x` (review round 5); the kernel's config path refuses
    /// it, and this is the same predicate, so a kernel bug is named here too.
    KeyPathMalformed,
    /// Shape admission failed — an empty field, an over-long conversation.
    MalformedFrame,
}

/// Proof that a frame passed admission.
///
/// There is **no public constructor**: a value exists only because [`decide`]
/// returned `Ok`. `call::fulfil` takes one, so a provider call cannot be made
/// on a frame whose bounds were never checked — the property is in the type
/// rather than in a comment someone has to keep reading.
#[derive(Debug)]
pub struct Admitted<'a> {
    req: &'a EgressFrameRequest,
}

impl<'a> Admitted<'a> {
    pub fn request(&self) -> &'a EgressFrameRequest {
        self.req
    }
}

/// Decide whether the deputy will act on one decoded frame.
///
/// **The deputy never chains.** It does not read `content` for instructions,
/// does not follow anything a reply might suggest, and has no way to originate
/// a request of its own. Under the orchestrator case a model reply may say
/// "now call provider:X"; the deputy must be structurally incapable of acting
/// on it, and the absence of any such path here is that property.
pub fn decide<'a>(
    req: &'a EgressFrameRequest,
    bounds: &EgressBounds,
) -> Result<Admitted<'a>, Refusal> {
    if !maknae_proto::egress_frame_request_is_acceptable(req) {
        return Err(Refusal::MalformedFrame);
    }
    if maknae_config::kv_fragment_is_acceptable(&req.key_vault_path).is_err() {
        return Err(Refusal::KeyPathMalformed);
    }
    // The field inside the secret, held to the same shape the kernel's config
    // path holds it to (no whitespace, bounded) — the other half of the
    // secret-store address (review round 6).
    if req.key_field.chars().any(char::is_whitespace)
        || req.key_field.len() > maknae_config::MAX_KEY_FIELD_BYTES
    {
        return Err(Refusal::MalformedFrame);
    }
    if !maknae_config::path_is_within_prefix(&req.key_vault_path, &bounds.key_vault_path_prefix) {
        return Err(Refusal::KeyPathOutsideBounds);
    }
    Ok(Admitted { req })
}

#[cfg(test)]
mod tests {
    use super::*;
    use maknae_proto::{ContentBlock, SecretText};

    fn bounds() -> EgressBounds {
        EgressBounds {
            kv_mount: "maknae-kv".into(),
            key_vault_path_prefix: "maknae/providers".into(),
            vault_addr: "https://vault.example:8200".into(),
            approle_mount: None,
        }
    }

    fn req(key_vault_path: &str) -> EgressFrameRequest {
        EgressFrameRequest {
            destination: "provider:openai".into(),
            endpoint: "https://api.example.test/v1".into(),
            model: "m".into(),
            key_vault_path: key_vault_path.into(),
            key_field: "api-key".into(),
            conversation: "conv1".into(),
            content: vec![ContentBlock::Text {
                text: SecretText(zeroize::Zeroizing::new("hello".into())),
            }],
        }
    }

    #[test]
    fn a_frame_within_bounds_is_accepted() {
        assert!(decide(&req("maknae/providers/openai"), &bounds()).is_ok());
    }

    /// The containment check, from the deputy's side. A sibling path that
    /// merely begins with the prefix is refused BY NAME.
    #[test]
    fn a_key_path_outside_the_prefix_is_refused_by_name() {
        // well-formed fragments (the malformed ones are refused by name
        // first, in their own test) that merely begin with, or miss, the prefix
        for bad in ["maknae/providers-evil/key", "other/key"] {
            assert_eq!(
                decide(&req(bad), &bounds()).unwrap_err(),
                Refusal::KeyPathOutsideBounds
            );
        }
    }

    /// The key FIELD is held to the kernel's shape too: whitespace or an
    /// over-long name is a malformed frame, not a lookup miss in the deputy.
    #[test]
    fn a_key_field_with_whitespace_or_over_length_is_a_malformed_frame() {
        let long = "f".repeat(maknae_config::MAX_KEY_FIELD_BYTES + 1);
        for bad in ["api key", long.as_str()] {
            let mut r = req("maknae/providers/openai");
            r.key_field = bad.into();
            assert_eq!(
                decide(&r, &bounds()).map(|_| ()),
                Err(Refusal::MalformedFrame),
                "{bad}"
            );
        }
        let mut ok = req("maknae/providers/openai");
        ok.key_field = "f".repeat(maknae_config::MAX_KEY_FIELD_BYTES);
        assert!(decide(&ok, &bounds()).is_ok());
    }

    /// A dot-segment under the prefix passes the prefix test and would reach
    /// Vault as `<prefix>/../../x`; it is refused by name first.
    #[test]
    fn a_dot_segment_under_the_prefix_is_refused_as_malformed_not_admitted() {
        for bad in [
            "maknae/providers/../../secret",
            "maknae/providers/./x",
            "maknae/providers//x",
        ] {
            assert_eq!(
                decide(&req(bad), &bounds()).map(|_| ()),
                Err(Refusal::KeyPathMalformed),
                "{bad}"
            );
        }
    }

    #[test]
    fn a_malformed_frame_is_refused_before_the_bounds_check() {
        let mut r = req("maknae/providers/openai");
        r.content.clear();
        assert_eq!(decide(&r, &bounds()).unwrap_err(), Refusal::MalformedFrame);
    }
}
