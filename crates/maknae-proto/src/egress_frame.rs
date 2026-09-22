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
    /// The KV v2 secret path holding this provider's key, **RELATIVE to the
    /// mount the deputy has in its own `egress-bounds.yaml`** and without the
    /// `data/` segment (#308). The deputy validates it against its configured
    /// prefix and then composes `<mount>/data/<path>` itself — so the mount is
    /// never on the wire, and the KV v2 API artifact appears in no
    /// configuration file.
    pub key_vault_path: String,
    /// The field name inside that secret (#308). **Per request, not a deputy
    /// constant**, for the same reason `destination` is: two providers may
    /// store their keys under different field names, and a constant fails the
    /// moment there are two. Before #308 the only field name in the tree was a
    /// test fixture's `api_key`.
    pub key_field: String,
    /// The loop's identifier (#241). Informational, never decided on.
    pub conversation: String,
    /// The transcript leaving the trust plane (#241). Roles per `crate::Turn`;
    /// there is no `System` variant, so the trusted preamble the deputy
    /// prepends is the only system message.
    pub turns: Vec<crate::Turn>,
}

impl std::fmt::Debug for EgressFrameRequest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EgressFrameRequest")
            .field("destination", &self.destination)
            .field("endpoint", &self.endpoint)
            .field("model", &self.model)
            .field("key_vault_path", &"<omitted>")
            // Omitted for the same reason as the path: a field NAME is not a
            // secret, but together with the path it describes exactly where a
            // credential is kept, and nothing needs it in a log line.
            .field("key_field", &"<omitted>")
            .field("conversation", &self.conversation)
            .field("turns", &format_args!("<{} turns>", self.turns.len()))
            .finish()
    }
}

/// The deputy's answer. Nothing but the reply: egress returns bytes to the
/// kernel and does nothing with them (#240a D4).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct EgressFrameReply {
    pub reply: crate::PromptReply,
}

/// The largest request frame that crosses the kernel→deputy socket, stated
/// ONCE for both ends (#240, review round 4): the kernel refuses to WRITE a
/// larger one (a pre-send failure, so the trail says nothing left), and the
/// deputy refuses to READ one (checked against the declared length before
/// any allocation). Two copies of `1024 * 1024` drifted apart in review.
pub const EGRESS_REQUEST_FRAME_MAX_BYTES: usize = 1024 * 1024;

/// The fixed buffer a request frame is encoded INTO when the caller has not
/// measured the frame itself: allocated once, written once, never grown
/// (#241, codex round 1 critical 3). The encoder began at
/// `Zeroizing<Vec::new()>` and grew, and every realloc frees a partly-written
/// buffer while `Zeroizing` wipes only the allocation that survives to the
/// drop — measured 18850 bytes of capacity for an 18434-byte frame, so a
/// dozen intermediate buffers each holding a prefix of the content. Harmless
/// while a frame was one short prompt; not harmless once a step's `Tool` turns
/// carry kernel-served file content, which is what the runtime loop routes
/// through here.
///
/// **It is the cap EXACTLY.** *(Corrected 2026-09-22, codex round 2 item C:
/// this was the cap plus one page, `1_052_672`, and the page was there so an
/// over-cap frame would meet the KERNEL's operator-readable cap refusal rather
/// than dying inside the encoder. That worked only within the page: a frame
/// further over the cap — 2 MiB over, say — still died in the encoder as
/// `failed to write whole buffer`, with no size, no cap and no operator line.
/// Measured and observed RED. The kernel now calls
/// [`crate::egress_frame_request_encoded_len`] BEFORE it allocates, so its own
/// refusal is what every over-cap size meets and the headroom has nothing left
/// to protect.)*
///
/// The production caller no longer uses this const at all — it passes the
/// measured length. It remains as the bound for a caller that cannot measure
/// first, and the cap is the only defensible value for one: a buffer larger
/// than the cap can only produce a frame nobody may send.
pub const EGRESS_REQUEST_FRAME_ENCODE_BYTES: usize = EGRESS_REQUEST_FRAME_MAX_BYTES;

/// The largest reply frame that crosses the deputy→kernel socket, stated ONCE
/// for both ends: the kernel refuses to READ a larger one (checked against the
/// declared length before any allocation, `maknae-kernel`'s
/// `EGRESS_MAX_REPLY_FRAME_BYTES`, which aliases this const so the two cannot
/// drift). Mirrors [`EGRESS_REQUEST_FRAME_MAX_BYTES`] on the other leg.
pub const EGRESS_REPLY_FRAME_MAX_BYTES: usize = 1024 * 1024;

/// The fixed buffer a reply frame is encoded INTO: allocated once, written
/// once, never grown (#241, codex round 2 item B). The reply encoder began at
/// `Zeroizing<Vec::new()>` and grew, and every realloc frees a partly-written
/// buffer while `Zeroizing` wipes only the allocation that survives to the
/// drop. The reply is not just provider prose: `ContentBlock::Text.text` is
/// `SecretText` because a model that read a file quotes that content straight
/// back, so the same finding the request encoder carried applies here.
///
/// The cap PLUS one page, for the reason [`EGRESS_REQUEST_FRAME_ENCODE_BYTES`]
/// gave before its counting pass removed the need there — and which still
/// holds on this leg, because the reply's cap is refused by the KERNEL, on the
/// declared length, with its own operator-readable message
/// (`deputy declared a N-byte reply frame over the M-byte cap`). Sized at
/// exactly the cap this buffer would shadow that refusal: a marginally-over
/// reply would die inside the deputy's encoder and the kernel's branch would
/// answer only a lying length prefix. One page of headroom keeps the kernel's
/// refusal the one a marginally-over reply meets; a reply past the headroom is
/// a [`crate::ProtoCodecError::Encode`] in the deputy, before a byte is
/// written, so nothing fails open either way.
///
/// Written OUT rather than as `EGRESS_REPLY_FRAME_MAX_BYTES + 4096`, which is
/// what it is, for the measurement the request const records: `cargo mutants`
/// replaces that `+` with `*`, and a 4 GiB `vec![0; …]` in the encoder times
/// the whole test binary out instead of failing an assertion. The relation to
/// the cap is pinned in the tests below, where no mutation reaches.
pub const EGRESS_REPLY_FRAME_ENCODE_BYTES: usize = 1_052_672;

/// Shape admission, applied by the kernel before a byte reaches the socket.
/// Deliberately shape-only: whether this subject may reach this destination
/// was decided by the PDP long before the frame existed.
pub fn egress_frame_request_is_acceptable(r: &EgressFrameRequest) -> bool {
    crate::conversation_id_is_acceptable(&r.conversation)
        && !r.destination.is_empty()
        && !r.endpoint.is_empty()
        && !r.model.is_empty()
        && !r.key_vault_path.is_empty()
        && !r.key_field.is_empty()
        && !r.turns.is_empty()
        && r.turns.iter().all(crate::turn_is_acceptable)
}

#[cfg(test)]
mod tests {
    use super::*;
    use zeroize::Zeroizing;

    /// By VALUE: a mutant turning `1024 * 1024` into 2048 or 1 survives every
    /// symbolic use on both ends.
    #[test]
    fn the_request_frame_cap_is_one_mebibyte_by_value() {
        assert_eq!(EGRESS_REQUEST_FRAME_MAX_BYTES, 1_048_576);
        // By VALUE too, and its relation to the cap stated separately
        // (corrected 2026-09-22, codex round 2 item C: this asserted the cap
        // plus one page, and the page is gone — the kernel measures the frame
        // before it allocates, so no headroom is needed to keep the kernel's
        // own cap refusal from being shadowed by an encoder overflow).
        assert_eq!(EGRESS_REQUEST_FRAME_ENCODE_BYTES, 1_048_576);
        assert_eq!(
            EGRESS_REQUEST_FRAME_ENCODE_BYTES, EGRESS_REQUEST_FRAME_MAX_BYTES,
            "a buffer larger than the cap can only produce a frame nobody may send"
        );
    }

    /// The reply's bound, pinned by the SAME three relations as the request's
    /// above and for the same reasons: by value, as the cap plus one page, and
    /// by the difference. The kernel's own `EGRESS_MAX_REPLY_FRAME_BYTES` IS
    /// this cap (it aliases this const), so the two ends cannot drift.
    #[test]
    fn the_reply_frame_cap_is_one_mebibyte_by_value() {
        assert_eq!(EGRESS_REPLY_FRAME_MAX_BYTES, 1_048_576);
        assert_eq!(EGRESS_REPLY_FRAME_ENCODE_BYTES, 1_048_576 + 4096);
        assert_eq!(
            EGRESS_REPLY_FRAME_ENCODE_BYTES,
            EGRESS_REPLY_FRAME_MAX_BYTES + 4096,
            "the encode buffer IS the cap plus one page; the const is spelled out, so this is what ties the two together"
        );
        assert_eq!(
            EGRESS_REPLY_FRAME_ENCODE_BYTES - EGRESS_REPLY_FRAME_MAX_BYTES,
            4096,
            "one page of headroom, so the KERNEL's named reply-cap refusal is what a marginally-over reply meets"
        );
    }

    fn text(s: &str) -> crate::ContentBlock {
        crate::ContentBlock::Text {
            text: crate::SecretText(Zeroizing::new(s.into())),
        }
    }

    fn req(conversation: &str, turns: Vec<crate::Turn>) -> EgressFrameRequest {
        EgressFrameRequest {
            destination: "provider:openai".into(),
            endpoint: "https://api.example.test/v1".into(),
            model: "some-model".into(),
            key_vault_path: "maknae/providers/openai".into(),
            key_field: "api-key".into(),
            conversation: conversation.into(),
            turns,
        }
    }

    /// The frame carries prompt content out of the trust plane. Its `Debug`
    /// must not reproduce it — nor the Vault path that names where the
    /// provider credential lives (`ProviderConfig` marks that `omit`).
    #[test]
    fn an_egress_frame_debug_redacts_prompt_content_and_the_key_path() {
        let r = req(
            "conv1",
            vec![crate::Turn::User {
                content: vec![text("the president flies at 0300")],
            }],
        );
        let d = format!("{r:?}");
        assert!(!d.contains("0300"), "prompt content leaked: {d}");
        assert!(!d.contains("secret/data"), "key path leaked: {d}");
        assert!(
            d.contains("provider:openai"),
            "destination should be visible: {d}"
        );
        assert!(
            d.contains("<1 turns>"),
            "the turn count should be shown: {d}"
        );
    }

    #[test]
    fn a_frame_round_trips() {
        let r = req(
            "conv1",
            vec![crate::Turn::User {
                content: vec![text("hello")],
            }],
        );
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
        let ok = req(
            &"a".repeat(crate::MAX_CONVERSATION_ID_BYTES),
            vec![crate::Turn::User {
                content: vec![text("x")],
            }],
        );
        assert!(egress_frame_request_is_acceptable(&ok));
        let bad = req(
            &"a".repeat(crate::MAX_CONVERSATION_ID_BYTES + 1),
            vec![crate::Turn::User {
                content: vec![text("x")],
            }],
        );
        assert!(!egress_frame_request_is_acceptable(&bad));
    }

    #[test]
    fn an_empty_turns_frame_is_refused() {
        assert!(!egress_frame_request_is_acceptable(&req("conv1", vec![])));
    }

    /// The new `all(turn_is_acceptable)` conjunct, on its own. Every other
    /// `req()` site carries only `User` turns, which always pass shape
    /// admission, and cargo-mutants emits no operator on the `all(..)`
    /// sub-expression — so without this row the conjunct could be deleted with
    /// the suite green (AGENTS.md principle 5).
    #[test]
    fn a_frame_whose_turn_fails_shape_admission_is_refused() {
        let over = crate::ProposedToolCall {
            name: "read_file".into(),
            call_id: "c1".into(),
            arguments: crate::SecretText(zeroize::Zeroizing::new(
                "a".repeat(crate::MAX_TOOL_CALL_ARGS_BYTES + 1),
            )),
        };
        let mut r = req(
            "conv1",
            vec![crate::Turn::User {
                content: vec![text("q")],
            }],
        );
        r.turns.push(crate::Turn::Assistant {
            content: vec![],
            tool_calls: vec![over],
        });
        assert!(!egress_frame_request_is_acceptable(&r));
    }

    /// codex round 1, critical 3. The request encoder began at
    /// `Zeroizing<Vec::new()>` and GREW: every realloc frees a partly-written
    /// buffer, and `Zeroizing` wipes only the allocation that survives to the
    /// drop. Harmless while a frame was one short prompt; not harmless once a
    /// step's `Tool` turns carry kernel-served file content, which is exactly
    /// what the runtime loop routes through here. One fixed preallocation, no
    /// growth, and the bytes on the wire unchanged.
    #[test]
    fn the_request_encoder_writes_one_preallocation_and_never_grows() {
        // Two results in one step, each over 8 KiB — the trace codex gave.
        let big = "x".repeat(9 * 1024);
        let r = req(
            "conv1",
            vec![
                crate::Turn::Tool {
                    call_id: "c1".into(),
                    content: vec![text(&big)],
                },
                crate::Turn::Tool {
                    call_id: "c2".into(),
                    content: vec![text(&big)],
                },
            ],
        );
        let buf =
            crate::encode_egress_frame_request(&r, EGRESS_REQUEST_FRAME_ENCODE_BYTES).unwrap();
        // Byte-identical to what the growing encoder produced: this is a
        // buffer change, not a wire change.
        let mut reference = Vec::new();
        ciborium::into_writer(&r, &mut reference).unwrap();
        assert_eq!(&buf[..], &reference[..]);
        assert!(
            buf.len() > 18 * 1024,
            "both results must be in there: {}",
            buf.len()
        );
        // The ONE allocation it was given, still — a grown buffer reports the
        // doubling sequence it climbed, never the preallocation.
        assert_eq!(buf.capacity(), EGRESS_REQUEST_FRAME_ENCODE_BYTES);
        // The bound is enforced, not decorative: one byte short of what the
        // frame needs is the codec's own error, never a silent realloc. The
        // exact length is the discriminator — it is the largest bound that
        // fails under a `<`-shaped mutant and the smallest that succeeds.
        assert!(matches!(
            crate::encode_egress_frame_request(&r, buf.len() - 1),
            Err(crate::ProtoCodecError::Encode(_))
        ));
        assert_eq!(
            crate::encode_egress_frame_request(&r, buf.len())
                .unwrap()
                .len(),
            buf.len()
        );
    }

    /// codex round 2, item C. The kernel's cap refusal carries the measured
    /// size and the cap, and an operator `eprintln!`; the encoder's overflow
    /// carries `failed to write whole buffer` and nothing else. Which one an
    /// over-cap frame meets was decided by 4 KiB of buffer headroom, so a
    /// frame 2 MiB over the cap got the codec string. The counting pass is
    /// what makes the length knowable before anything is allocated.
    #[test]
    fn the_counting_pass_is_the_encoder_length_at_every_size() {
        // Small, and a frame FAR over the cap — the case the fixed buffer
        // cannot encode at all, and the reason this function exists.
        for n in [
            8usize,
            9 * 1024,
            EGRESS_REQUEST_FRAME_MAX_BYTES + 2 * 1024 * 1024,
        ] {
            let r = req(
                "conv1",
                vec![crate::Turn::Tool {
                    call_id: "c1".into(),
                    content: vec![text(&"x".repeat(n))],
                }],
            );
            let counted = crate::egress_frame_request_encoded_len(&r).unwrap();
            // The oracle is the ENCODER, not a second length formula: any
            // divergence would put the kernel's refusal on the wrong side of
            // the cap by exactly that amount.
            let mut reference = Vec::new();
            ciborium::into_writer(&r, &mut reference).unwrap();
            assert_eq!(counted, reference.len(), "n = {n}");
            assert!(counted > n, "n = {n}: the content must be in the count");
            // And the count is what the fixed-buffer encoder needs: exactly
            // the measured length succeeds, one byte less does not.
            if n <= 9 * 1024 {
                assert_eq!(
                    crate::encode_egress_frame_request(&r, counted)
                        .unwrap()
                        .len(),
                    counted
                );
                assert!(matches!(
                    crate::encode_egress_frame_request(&r, counted - 1),
                    Err(crate::ProtoCodecError::Encode(_))
                ));
            }
        }
    }

    #[test]
    fn the_request_codec_round_trips_and_refuses_garbage() {
        let r = req(
            "conv1",
            vec![crate::Turn::User {
                content: vec![text("hello")],
            }],
        );
        let buf =
            crate::encode_egress_frame_request(&r, EGRESS_REQUEST_FRAME_ENCODE_BYTES).unwrap();
        assert_eq!(crate::decode_egress_frame_request(&buf).unwrap(), r);
        assert!(crate::decode_egress_frame_request(&[0xffu8, 0xff, 0xff]).is_err());
    }

    /// codex round 2, item B — the request encoder's finding, on the reply.
    /// The reply carries the provider's prose AND whatever kernel-served
    /// content the model quoted back (`ContentBlock::Text.text` is already
    /// `SecretText`), and this encoder still began at `Zeroizing<Vec::new()>`
    /// and grew: every realloc frees a partly-written copy, and `Zeroizing`
    /// wipes only the allocation that lives to the drop.
    #[test]
    fn the_reply_encoder_writes_one_preallocation_and_never_grows() {
        // Over 8 KiB of quoted content — the size codex's trace used on the
        // request leg, and what a model echoing a read file produces here.
        let big = "y".repeat(9 * 1024);
        let r = EgressFrameReply {
            reply: crate::PromptReply {
                blocks: vec![text(&big), text(&big)],
                tool_calls: vec![],
            },
        };
        let buf = crate::encode_egress_frame_reply(&r, EGRESS_REPLY_FRAME_ENCODE_BYTES).unwrap();
        // Byte-identical to what the growing encoder produced: a buffer
        // change, not a wire change.
        let mut reference = Vec::new();
        ciborium::into_writer(&r, &mut reference).unwrap();
        assert_eq!(&buf[..], &reference[..]);
        assert!(
            buf.len() > 18 * 1024,
            "both blocks must be in there: {}",
            buf.len()
        );
        // The ONE allocation it was given, still — a grown buffer reports the
        // doubling sequence it climbed, never the preallocation.
        assert_eq!(buf.capacity(), EGRESS_REPLY_FRAME_ENCODE_BYTES);
        // The bound is enforced, not decorative: one byte short of what the
        // frame needs is the codec's own error — never a panic, and never a
        // silent realloc. The exact length is the discriminator.
        assert!(matches!(
            crate::encode_egress_frame_reply(&r, buf.len() - 1),
            Err(crate::ProtoCodecError::Encode(_))
        ));
        assert_eq!(
            crate::encode_egress_frame_reply(&r, buf.len())
                .unwrap()
                .len(),
            buf.len()
        );
    }

    #[test]
    fn the_reply_codec_round_trips_and_refuses_garbage() {
        let r = EgressFrameReply {
            reply: crate::PromptReply {
                blocks: vec![text("ok")],
                tool_calls: vec![],
            },
        };
        let buf = crate::encode_egress_frame_reply(&r, EGRESS_REPLY_FRAME_ENCODE_BYTES).unwrap();
        assert_eq!(crate::decode_egress_frame_reply(&buf).unwrap(), r);
        assert!(crate::decode_egress_frame_reply(&[0xffu8, 0xff, 0xff]).is_err());
    }

    /// Every field of the shape check earns its place: drop any one and a
    /// malformed frame reaches the deputy.
    #[test]
    fn every_required_field_is_checked() {
        let base = req(
            "conv1",
            vec![crate::Turn::User {
                content: vec![text("x")],
            }],
        );
        for (label, bad) in [
            (
                "destination",
                EgressFrameRequest {
                    destination: String::new(),
                    ..base.clone()
                },
            ),
            (
                "endpoint",
                EgressFrameRequest {
                    endpoint: String::new(),
                    ..base.clone()
                },
            ),
            (
                "model",
                EgressFrameRequest {
                    model: String::new(),
                    ..base.clone()
                },
            ),
            (
                "key_vault_path",
                EgressFrameRequest {
                    key_vault_path: String::new(),
                    ..base.clone()
                },
            ),
            (
                "key_field",
                EgressFrameRequest {
                    key_field: String::new(),
                    ..base.clone()
                },
            ),
        ] {
            assert!(
                !egress_frame_request_is_acceptable(&bad),
                "{label} unchecked"
            );
        }
        assert!(egress_frame_request_is_acceptable(&base));
    }
}
