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
    /// The frame carried a non-text block on the prompt leg. Cooky is text
    /// only (#153, #229) and the kernel refuses non-text long before here, so
    /// this names a kernel BUG rather than dropping the block silently — a
    /// silent drop would send the remainder and let the model answer a
    /// truncated prompt (#264 review round 2).
    NonTextBlock,
    /// The frame carried no text to send. `maknae_kernel::egress::
    /// admitted_blocks` refuses this at the PDP, so this names a kernel bug
    /// too — and it is load-bearing rather than cosmetic: since #264 prepends
    /// a trusted preamble, a prompt with nothing in it would otherwise become
    /// a well-formed request the provider ANSWERS from the system prompt
    /// alone. The preamble must never be the whole request (review round 2).
    NoTextToSend,
    /// The transcript does not begin with a user turn. Names a kernel bug
    /// (`admitted_turns` refuses it at the PDP); a record must never call a
    /// transcript-shape fault "no text" (#241 R6).
    TranscriptShape,
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
    // #264 review round 4: the CONTENT judgement belongs here, not in
    // `call.rs`. Two reasons, and NEITHER is mutation coverage: this function
    // is PURE and directly testable (no socket, no credential, no provider),
    // and `Refusal` is the right taxonomy — `serve.rs` documents its `Fulfil`
    // lane as "the deputy was WILLING", which a pre-send refusal is not.
    //
    // On coverage, stated accurately because an earlier version of this
    // comment got it wrong: **`maknae-egress` is not in `mutants_crates` at
    // all** (`coverage-tiers.toml`), so #297's blind spot covers this file too
    // — this module's own header calling itself "mutation-visible" is
    // aspirational. The new predicates were hand-mutated instead.
    //
    // Both checks name a kernel bug: the PDP refuses non-text and text-less
    // prompts before a frame exists. They are defence in depth, and they are
    // the reason `Admitted` can be handed to `fulfil` without `fulfil` needing
    // to re-judge content.
    fn content_of(t: &maknae_proto::Turn) -> &[maknae_proto::ContentBlock] {
        match t {
            maknae_proto::Turn::User { content }
            | maknae_proto::Turn::Assistant { content, .. }
            | maknae_proto::Turn::Tool { content, .. } => content,
        }
    }
    if req
        .turns
        .iter()
        .flat_map(|t| content_of(t).iter())
        .any(|b| !matches!(b, maknae_proto::ContentBlock::Text { .. }))
    {
        return Err(Refusal::NonTextBlock);
    }
    // NEVER `turns[0]`: an index panic in the deputy is a DoS surface, and the
    // emptiness invariant lives forty-odd lines away in
    // `egress_frame_request_is_acceptable`.
    match req.turns.first() {
        Some(maknae_proto::Turn::User { .. }) => {}
        _ => return Err(Refusal::TranscriptShape),
    }
    // EVERY user turn and every tool turn — the same set the kernel's
    // `admitted_turns` checks (#241 R14), so the "defence in depth" claim is
    // about the same predicate rather than a looser one. An assistant turn may
    // legitimately be tool calls with no text at all.
    let blank = |content: &[maknae_proto::ContentBlock]| {
        content.iter().all(|b| match b {
            maknae_proto::ContentBlock::Text { text } => text.0.trim().is_empty(),
            _ => false,
        })
    };
    if req.turns.iter().any(|t| match t {
        maknae_proto::Turn::User { content } | maknae_proto::Turn::Tool { content, .. } => {
            blank(content)
        }
        maknae_proto::Turn::Assistant { .. } => false,
    }) {
        return Err(Refusal::NoTextToSend);
    }
    Ok(Admitted { req })
}

#[cfg(test)]
mod tests {
    use super::*;
    use maknae_proto::{ContentBlock, SecretText, Turn};

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
            turns: vec![Turn::User {
                content: vec![ContentBlock::Text {
                    text: SecretText(zeroize::Zeroizing::new("hello".into())),
                }],
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
        r.turns.clear();
        assert_eq!(decide(&r, &bounds()).unwrap_err(), Refusal::MalformedFrame);
    }

    /// #264 review rounds 2-4: THE PREAMBLE MUST NEVER BE THE WHOLE REQUEST.
    ///
    /// Frame admission requires each turn to carry a non-empty content VEC,
    /// not a `Text` block bearing text. Before #264 that was harmless — the
    /// deputy produced no messages and the provider rejected the request.
    /// After #264 prepends a trusted preamble it stops being harmless: the
    /// request becomes well formed and the provider ANSWERS it from the system
    /// prompt alone, so "sent nothing" would masquerade as a turn.
    ///
    /// Round 1 guarded only the image-only case; round 2 guarded a COUNT of
    /// mapped messages rather than content; round 4 moved the judgement here,
    /// where it is pure, mutation-visible, and carries the right taxonomy.
    ///
    /// #241 extends the property across ROLES: a blank tool RESULT is just as
    /// much "nothing to send", and a transcript that does not begin with a
    /// user turn is `TranscriptShape`, never "no text".
    #[test]
    fn no_frame_shape_can_make_the_preamble_the_whole_request() {
        let text = |t: &str| ContentBlock::Text {
            text: SecretText(zeroize::Zeroizing::new(t.into())),
        };
        let image = || ContentBlock::Image {
            data: "AAAA".into(),
            mime_type: "image/png".into(),
        };
        let user = |c: Vec<ContentBlock>| Turn::User { content: c };
        let call = || maknae_proto::ProposedToolCall {
            name: "read_file".into(),
            call_id: "c1".into(),
            arguments: SecretText(zeroize::Zeroizing::new("{}".into())),
        };
        let cases: Vec<(&str, Vec<Turn>, Refusal)> = vec![
            (
                "image only",
                vec![user(vec![image()])],
                Refusal::NonTextBlock,
            ),
            (
                "text + image",
                vec![user(vec![text("real"), image()])],
                Refusal::NonTextBlock,
            ),
            (
                "image + text",
                vec![user(vec![image(), text("real")])],
                Refusal::NonTextBlock,
            ),
            (
                "empty text",
                vec![user(vec![text("")])],
                Refusal::NoTextToSend,
            ),
            (
                "whitespace only",
                vec![user(vec![text("   \n\t ")])],
                Refusal::NoTextToSend,
            ),
            (
                "carriage return",
                vec![user(vec![text("\r\n")])],
                Refusal::NoTextToSend,
            ),
            (
                "several blank texts",
                vec![user(vec![text(""), text("  "), text("\n")])],
                Refusal::NoTextToSend,
            ),
            // #241: the same property across ROLES. A blank tool RESULT is
            // just as much "nothing to send" as a blank user turn, and a
            // transcript that does not begin with a user turn names a kernel
            // bug that must not be recorded as "no text".
            (
                "blank tool result",
                vec![
                    user(vec![text("q")]),
                    Turn::Assistant {
                        content: vec![],
                        tool_calls: vec![call()],
                    },
                    Turn::Tool {
                        call_id: "c1".into(),
                        content: vec![text("  ")],
                    },
                ],
                Refusal::NoTextToSend,
            ),
            (
                "no leading user turn",
                vec![
                    Turn::Assistant {
                        content: vec![],
                        tool_calls: vec![call()],
                    },
                    Turn::Tool {
                        call_id: "c1".into(),
                        content: vec![text("r")],
                    },
                ],
                Refusal::TranscriptShape,
            ),
            (
                "non-text in an assistant turn",
                vec![
                    user(vec![text("q")]),
                    Turn::Assistant {
                        content: vec![image()],
                        tool_calls: vec![call()],
                    },
                ],
                Refusal::NonTextBlock,
            ),
            (
                "non-text in a tool turn",
                vec![
                    user(vec![text("q")]),
                    Turn::Assistant {
                        content: vec![],
                        tool_calls: vec![call()],
                    },
                    Turn::Tool {
                        call_id: "c1".into(),
                        content: vec![image()],
                    },
                ],
                Refusal::NonTextBlock,
            ),
        ];
        for (name, turns, want) in cases {
            let mut f = req("maknae/providers/openai");
            f.turns = turns;
            assert_eq!(decide(&f, &bounds()).unwrap_err(), want, "{name}");
        }

        // ADMITTED: one content-bearing block is enough, wherever it sits, and
        // a blank alongside it is NOT the deputy's to drop — the kernel's
        // `content_measure` digested it into the intent record, so dropping it
        // would make the trail attest bytes that never left.
        for (name, turns) in [
            (
                "blank then real",
                vec![user(vec![text("  "), text("real")])],
            ),
            (
                "real then blank",
                vec![user(vec![text("real"), text("  ")])],
            ),
            // A zero-width character is NOT Unicode White_Space and is
            // therefore content. Asserted so the boundary is recorded rather
            // than discovered: this refuses "nothing to send", it is not a
            // meaningfulness judgement about the prompt.
            ("zero-width", vec![user(vec![text("\u{200b}")])]),
            (
                "a full tool-calling round",
                vec![
                    user(vec![text("q")]),
                    Turn::Assistant {
                        content: vec![],
                        tool_calls: vec![call()],
                    },
                    Turn::Tool {
                        call_id: "c1".into(),
                        content: vec![text("r")],
                    },
                ],
            ),
        ] {
            let mut f = req("maknae/providers/openai");
            f.turns = turns;
            assert!(decide(&f, &bounds()).is_ok(), "{name} must be admitted");
        }
    }
}
