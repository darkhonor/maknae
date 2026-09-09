//! The seam between the PDP and the egress process (#172, ADR-0023 decision 3).
//! `maknaed` never terminates outbound TLS and never holds the provider key; a
//! permitted `session.prompt` is handed to an [`Egress`] backend. The
//! write-ahead ordering (ADR-0019 §41) is a TYPE here, not a statement order:
//! [`Egress::send`] takes a [`DurableEgressIntent`], which only
//! [`commit_intent`] constructs, and only after the audit append succeeded.
//! Reversing the order does not compile. In Cooky the only production backend
//! is [`Unavailable`]; it fails `ready()` BEFORE any intent exists, so a
//! refusal is never recorded as a send. #240 supplies the real backend.

use maknae_audit_append::{AuditEmit, AuditError, AuditRecord, EgressStatus};
use maknae_proto::{ContentBlock, PromptReply};
use std::sync::Arc;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EgressRequest {
    pub destination: String,
    pub conversation: String,
    pub content: Vec<ContentBlock>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EgressReply {
    pub reply: PromptReply,
}

/// Why a backend did not send. Deadline expiry is NOT a variant: the kernel
/// bounds the call and maps expiry to [`SendOutcome::DeadlineExpired`]
/// (delivery unknown); [`SendOutcome::LandedUndelivered`] is the kernel's own
/// refusal to deliver a reply that DID arrive, for one of [`ReplyRefusal`]'s
/// reasons (over the cap, non-text, empty).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum EgressFailure {
    NotConfigured,
    Transport(String),
}

/// Proof of a durable intent. No public constructor: a value exists only
/// because `commit_intent` appended its record and the sink said Ok.
pub struct DurableEgressIntent {
    record: AuditRecord,
}

impl DurableEgressIntent {
    pub fn record(&self) -> &AuditRecord {
        &self.record
    }
}

pub async fn commit_intent<E: AuditEmit>(
    emit: &E,
    record: AuditRecord,
) -> Result<DurableEgressIntent, AuditError> {
    emit.emit(&record).await?;
    Ok(DurableEgressIntent { record })
}

pub trait Egress: Send + Sync {
    /// Cheap and side-effect-free: may this backend be asked to send at all?
    fn ready(&self) -> Result<(), EgressFailure>;
    /// Send. The intent is the caller's proof that the trail already holds it.
    /// Blocking is allowed: the kernel calls this on a blocking worker under a deadline.
    fn send(
        &self,
        intent: &DurableEgressIntent,
        req: EgressRequest,
    ) -> Result<EgressReply, EgressFailure>;
}

/// Cooky's production backend: there is no egress process yet.
pub struct Unavailable;

impl Egress for Unavailable {
    fn ready(&self) -> Result<(), EgressFailure> {
        Err(EgressFailure::NotConfigured)
    }
    fn send(
        &self,
        _: &DurableEgressIntent,
        _: EgressRequest,
    ) -> Result<EgressReply, EgressFailure> {
        Err(EgressFailure::NotConfigured)
    }
}

/// The one production choice, in one place, so a test can pin it.
pub fn production_egress() -> Arc<dyn Egress> {
    Arc::new(Unavailable)
}

/// Text only in Cooky (#153, #229). Names the FIRST non-text kind; an empty
/// prompt is refused too, so "sent nothing" cannot masquerade as a turn.
pub fn admitted_blocks(content: &[ContentBlock]) -> Result<(), String> {
    if content.is_empty() {
        return Err("prompt carries no content".into());
    }
    match content
        .iter()
        .find(|b| !matches!(b, ContentBlock::Text { .. }))
    {
        None => Ok(()),
        Some(b) => Err(format!(
            "content block type not admitted in this deployment: {}",
            b.kind()
        )),
    }
}

/// What the trail holds about content. Never the text; the digest is fed
/// incrementally so no second copy of secret text is made, and truncated to
/// 32 hex characters for the macOS unified-log cap (record.rs says why).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ContentMeasure {
    pub length: u64,
    pub digest32: String,
}

pub fn content_measure(content: &[ContentBlock]) -> ContentMeasure {
    let mut length = 0u64;
    let mut h = maknae_vault::Sha256::new();
    for b in content {
        if let ContentBlock::Text { text } = b {
            length += text.0.len() as u64;
            h.update(text.0.as_bytes());
        }
    }
    let mut digest32 = h.finish_hex();
    digest32.truncate(32);
    ContentMeasure { length, digest32 }
}

/// Why the kernel refused to deliver a reply that arrived: over the frame
/// cap (`TooLarge` on the wire), carrying a block kind this deployment does
/// not admit, or empty (both `Unauthorized`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ReplyRefusal {
    Oversize,
    NonText,
    Empty,
}

/// The reply-direction admission. `admitted_blocks` is the prompt direction
/// and says "prompt" in its reason; a reply gets its own so the record never
/// calls an empty reply "non-text". Text only, at least one block.
pub fn admitted_reply(reply: &PromptReply) -> Result<(), ReplyRefusal> {
    if reply.blocks.is_empty() {
        return Err(ReplyRefusal::Empty);
    }
    if reply
        .blocks
        .iter()
        .any(|b| !matches!(b, ContentBlock::Text { .. }))
    {
        return Err(ReplyRefusal::NonText);
    }
    Ok(())
}

/// What a send came back as, AFTER the kernel's admission and cap checks on
/// the reply. Narrower than `EgressStatus` on purpose: `IntentOnly` and
/// `BackendUnavailable` are never outcomes of a send, so no arm below is
/// unreachable (T1: every arm must be killable). `DeadlineExpired`: the
/// transport deadline passed with no answer, delivery to the provider
/// unknown. `LandedUndelivered`: the reply arrived and the kernel refuses to
/// deliver it, ADR-0023 decision 3's meaning, for the [`ReplyRefusal`] named.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SendOutcome {
    Sent {
        reply_length: u64,
    },
    Failed,
    DeadlineExpired,
    LandedUndelivered {
        reply_length: u64,
        refusal: ReplyRefusal,
    },
}

/// The outcome record derived from the intent: same identity, new seq and ts,
/// `result`/`reason`/`posture` per outcome. A send that did NOT go out
/// (`Failed`, `DeadlineExpired`) is a `deny`, never a `permit` that reads
/// "send failed"; a reply the kernel refused to deliver (`LandedUndelivered`)
/// stays `permit`, because the content DID leave and the trail must say so
/// (the `refused-oversize` pairing of `read_refusal_disposition`). Every
/// posture is inside ADR-0019's pinned domain; the egress-specific fact is
/// `egress.status`. The strings are the ones the syslog cap test measures;
/// changing one means re-measuring.
pub fn outcome_for(
    intent: &DurableEgressIntent,
    seq: u64,
    ts: String,
    outcome: SendOutcome,
) -> AuditRecord {
    let mut r = intent.record.clone();
    r.seq = seq;
    r.ts = ts;
    let (status, reply_length, result, reason, posture) = match outcome {
        SendOutcome::Sent { reply_length } => (
            EgressStatus::Sent,
            Some(reply_length),
            "permit",
            "sent",
            "authorized",
        ),
        SendOutcome::Failed => (
            EgressStatus::Failed,
            None,
            "deny",
            "send failed",
            "unavailable",
        ),
        SendOutcome::DeadlineExpired => (
            EgressStatus::DeadlineExpired,
            None,
            "deny",
            "send deadline expired",
            "unavailable",
        ),
        // `permit` + `refused-oversize`: the pairing ADR-0019 pins for a permit
        // whose delivery is refused (the Read path's TooLarge corrective).
        SendOutcome::LandedUndelivered {
            reply_length,
            refusal: ReplyRefusal::Oversize,
        } => (
            EgressStatus::LandedUndelivered,
            Some(reply_length),
            "permit",
            "reply refused: oversize",
            "refused-oversize",
        ),
        // `permit` + `unauthorized`: the content left; the reply is not
        // admissible in this deployment (#153).
        SendOutcome::LandedUndelivered {
            reply_length,
            refusal: ReplyRefusal::NonText,
        } => (
            EgressStatus::LandedUndelivered,
            Some(reply_length),
            "permit",
            "reply refused: non-text",
            "unauthorized",
        ),
        SendOutcome::LandedUndelivered {
            reply_length,
            refusal: ReplyRefusal::Empty,
        } => (
            EgressStatus::LandedUndelivered,
            Some(reply_length),
            "permit",
            "reply refused: empty",
            "unauthorized",
        ),
    };
    r.outcome.result = result.into();
    r.outcome.reason = reason.into();
    r.outcome.posture = posture.into();
    if let Some(e) = r.egress.as_mut() {
        e.status = status;
        e.reply_length = reply_length;
    }
    r
}

/// CBOR envelope allowance per content block (variant tag, map header, field
/// name, text-string header): generous, and pinned by a test that encodes
/// replies of many shapes and asserts the buffer never grew.
pub const REPLY_BLOCK_ENVELOPE: usize = 32;

/// The reply's TEXT length: the audit `reply_length`.
pub fn reply_text_length(reply: &PromptReply) -> u64 {
    reply
        .blocks
        .iter()
        .map(|b| match b {
            ContentBlock::Text { text } => text.0.len() as u64,
            _ => 0,
        })
        .sum()
}

/// The zeroizing encode buffer's capacity for a TEXT-ONLY reply (the kernel
/// refuses any other before consulting this): an upper bound, so
/// `encode_response_zeroizing` never reallocates (the Read path's rule,
/// applied to a multi-block payload). Compared against `frame_max_bytes`
/// BEFORE encoding: an over-cap reply is refused without ever being copied.
/// The bound is padded, so the effective ceiling is
/// `frame_max_bytes - 512 - 32*blocks` of text: fail-closed by a margin,
/// deliberately (#240 inherits this boundary; `write_frame_bounded` re-checks
/// the encoded length as defence in depth).
pub fn reply_capacity(reply: &PromptReply) -> usize {
    reply_text_length(reply) as usize
        + reply.blocks.len() * REPLY_BLOCK_ENVELOPE
        + crate::handler::FRAME_ENVELOPE_MARGIN as usize
}

#[cfg(test)]
mod tests {
    use super::*;
    use maknae_audit_append::{AuditEmit, AuditError, AuditRecord, EgressAudit, EgressStatus};
    use maknae_proto::{ContentBlock, SecretText};
    // `Arc` arrives via `use super::*`; a second import is `unused_imports` under -D warnings.
    use std::sync::Mutex;

    // The kernel has no `zeroize` dependency; `maknae_io::Zeroizing` is the same type, re-exported.
    fn text(s: &str) -> ContentBlock {
        ContentBlock::Text {
            text: SecretText(maknae_io::Zeroizing::new(s.into())),
        }
    }

    struct Sink {
        records: Mutex<Vec<AuditRecord>>,
        fail: bool,
    }
    impl AuditEmit for Sink {
        fn emit(
            &self,
            r: &AuditRecord,
        ) -> impl std::future::Future<Output = Result<(), AuditError>> + Send {
            self.records.lock().unwrap().push(r.clone());
            let fail = self.fail;
            async move {
                if fail {
                    Err(AuditError::WritePrimary("injected".into()))
                } else {
                    Ok(())
                }
            }
        }
    }

    #[derive(Default)]
    struct Recording {
        calls: Mutex<Vec<&'static str>>,
    }
    impl Egress for Recording {
        fn ready(&self) -> Result<(), EgressFailure> {
            self.calls.lock().unwrap().push("ready");
            Ok(())
        }
        fn send(
            &self,
            _i: &DurableEgressIntent,
            _r: EgressRequest,
        ) -> Result<EgressReply, EgressFailure> {
            self.calls.lock().unwrap().push("send");
            Ok(EgressReply {
                reply: maknae_proto::PromptReply {
                    blocks: vec![text("ok")],
                },
            })
        }
    }

    fn intent_record() -> AuditRecord {
        // record.rs's test module is private to its crate, so the literal is
        // written here from the exported types.
        use maknae_audit_append::{Integrity, Outcome, Source, Subject, Where};
        AuditRecord {
            ts: "2026-09-09T00:00:00.000Z".into(),
            event: "request".into(),
            where_: Where {
                host: "maknaed-01".into(),
                component: "maknaed".into(),
                socket: "/run/maknae/plane.sock".into(),
            },
            source: Source {
                uid: 1002,
                gid: None,
                pid: None,
                plane_uri_san: Some("maknae://d/plane/cli".into()),
            },
            subject: Subject {
                user: None,
                role: None,
                plane_uri_san: Some("maknae://d/plane/cli".into()),
            },
            action: "session.prompt".into(),
            object: Some("provider:openai".into()),
            object_requested: None,
            mutation: None,
            outcome: Outcome {
                result: "permit".into(),
                reason: "intent recorded".into(),
                posture: "authorized".into(),
            },
            session_id: 718,
            seq: 2,
            au3_1: serde_json::json!({"mutation": "untrusted extension"}),
            integrity: Integrity {
                prev_hash: None,
                sig: None,
            },
            egress: Some(EgressAudit {
                status: EgressStatus::IntentOnly,
                content_length: 3,
                content_digest: "a".repeat(32),
                conversation: "c".into(),
                reply_length: None,
            }),
        }
    }

    fn req() -> EgressRequest {
        EgressRequest {
            destination: "provider:x".into(),
            conversation: "c".into(),
            content: vec![text("a")],
        }
    }

    #[test]
    fn unavailable_is_the_production_backend_and_neither_readies_nor_sends() {
        assert_eq!(Unavailable.ready(), Err(EgressFailure::NotConfigured));
        assert_eq!(
            production_egress().ready(),
            Err(EgressFailure::NotConfigured)
        );
        // same module: the private constructor is reachable here only
        let i = DurableEgressIntent {
            record: intent_record(),
        };
        assert_eq!(
            Unavailable.send(&i, req()).unwrap_err(),
            EgressFailure::NotConfigured
        );
        // The other production-reachable failure is constructed and compared
        // here too (T1 regions on the derives).
        assert_ne!(
            EgressFailure::Transport("peer reset".into()),
            EgressFailure::NotConfigured
        );
        assert!(
            format!("{:?}", EgressFailure::Transport("peer reset".into())).contains("peer reset")
        );
    }

    #[tokio::test]
    async fn a_failed_append_yields_no_intent_and_a_successful_one_yields_the_record() {
        let bad = Sink {
            records: Mutex::new(vec![]),
            fail: true,
        };
        assert!(
            matches!(commit_intent(&bad, intent_record()).await, Err(AuditError::WritePrimary(ref m)) if m == "injected"),
            "the sink's error is carried, not discarded"
        );
        let good = Sink {
            records: Mutex::new(vec![]),
            fail: false,
        };
        let i = commit_intent(&good, intent_record()).await.unwrap();
        assert!(i.record().egress.as_ref().unwrap().is_intent());
        assert_eq!(good.records.lock().unwrap().len(), 1);
    }

    #[tokio::test]
    async fn send_takes_a_durable_intent_by_type() {
        // The order proof is the COMPILER: `send` has no overload without a
        // `DurableEgressIntent`, and the struct has no public constructor, so a
        // send before the append does not compile. This test only shows the
        // happy path type-checks and the backend is reached. `ready()` is NOT
        // called here on purpose: the readiness gate is the kernel's, this
        // test is the type gate, so `calls == ["send"]` is the expectation.
        let good = Sink {
            records: Mutex::new(vec![]),
            fail: false,
        };
        let e = Recording::default();
        let i = commit_intent(&good, intent_record()).await.unwrap();
        assert!(e.send(&i, req()).is_ok());
        assert_eq!(e.calls.lock().unwrap().clone(), vec!["send"]);
    }

    #[test]
    fn only_text_blocks_are_admitted_and_the_first_offender_is_named() {
        assert_eq!(admitted_blocks(&[text("a")]), Ok(()));
        let err = admitted_blocks(&[
            text("a"),
            ContentBlock::Image {
                data: "".into(),
                mime_type: "image/png".into(),
            },
            ContentBlock::Audio {
                data: "".into(),
                mime_type: "audio/wav".into(),
            },
        ])
        .unwrap_err();
        assert_eq!(
            err,
            "content block type not admitted in this deployment: image"
        );
        assert_eq!(
            admitted_blocks(&[]).unwrap_err(),
            "prompt carries no content"
        );
    }

    #[test]
    fn content_measure_is_length_and_a_32_hex_digest_never_the_text() {
        let m = content_measure(&[text("abc"), text("de")]);
        assert_eq!(m.length, 5);
        assert_eq!(m.digest32, &maknae_vault::sha256_hex(b"abcde")[..32]);
        assert_eq!(m.digest32.len(), 32);
        let m2 = content_measure(&[text("the secret plan")]);
        assert!(
            !format!("{m2:?}").contains("secret"),
            "a Debug of the measure must not carry plaintext"
        );
        // A non-text block contributes no length and no digest input (the
        // pre-gate refuses it before this runs; the measure must still not lie
        // if it ever saw one).
        let m = content_measure(&[
            text("abc"),
            ContentBlock::ResourceLink {
                uri: "https://x".into(),
                name: "x".into(),
            },
        ]);
        assert_eq!(
            (m.length, m.digest32.as_str()),
            (3, &maknae_vault::sha256_hex(b"abc")[..32])
        );
    }

    #[test]
    fn reply_capacity_holds_for_many_small_and_few_large_blocks_so_encoding_never_grows() {
        // A realloc during a zeroizing encode leaves an un-zeroized copy of the
        // reply in freed heap; the capacity hint must therefore be an upper bound
        // for every reply shape. Text-only shapes only: the kernel refuses a reply
        // with a non-text block BEFORE reply_capacity is consulted.
        for blocks in [
            vec![text("")],
            vec![text("x")],
            (0..200).map(|_| text("ab")).collect::<Vec<_>>(),
            vec![text(&"y".repeat(70_000))],
            (0..50).map(|i| text(&"z".repeat(i * 100))).collect(),
        ] {
            let reply = maknae_proto::PromptReply {
                blocks: blocks.clone(),
            };
            let cap = reply_capacity(&reply);
            let resp = maknae_proto::Response {
                protocol_version: maknae_proto::PROTOCOL_VERSION,
                result: maknae_proto::RespResult::Ok(maknae_proto::Payload::PromptReply(
                    reply.clone(),
                )),
            };
            let buf = maknae_proto::encode_response_zeroizing(&resp, cap).unwrap();
            assert_eq!(
                buf.capacity(),
                cap,
                "the encoder grew the buffer for {} blocks: len {} > hint {cap}",
                blocks.len(),
                buf.len()
            );
            assert_eq!(
                reply_text_length(&reply),
                blocks
                    .iter()
                    .map(|b| match b {
                        ContentBlock::Text { text } => text.0.len() as u64,
                        _ => 0,
                    })
                    .sum::<u64>()
            );
        }
        // The non-text arm of reply_text_length is still a region: it contributes nothing.
        assert_eq!(
            reply_text_length(&maknae_proto::PromptReply {
                blocks: vec![
                    text("ab"),
                    ContentBlock::ResourceLink {
                        uri: "https://x".into(),
                        name: "x".into(),
                    },
                ],
            }),
            2
        );
        assert_eq!(
            reply_capacity(&maknae_proto::PromptReply { blocks: vec![] }),
            crate::handler::FRAME_ENVELOPE_MARGIN as usize
        );
        // EXACT arithmetic on a multi-block reply: `buf.capacity() == cap` above
        // compares the buffer against the function's own output, so an
        // OVER-estimating mutant (`+` → `*` between the text length and the
        // block term: 5*64+512 = 832) would survive it. 581 kills that one and
        // re-kills the other operator mutants; an over-estimate is a real
        // defect, it refuses replies that fit.
        assert_eq!(
            reply_capacity(&maknae_proto::PromptReply {
                blocks: vec![text("abc"), text("de")],
            }),
            5 + 2 * REPLY_BLOCK_ENVELOPE + crate::handler::FRAME_ENVELOPE_MARGIN as usize
        );
    }

    #[test]
    fn a_reply_is_admitted_only_when_text_only_and_non_empty_and_the_refusal_is_named() {
        let ok = maknae_proto::PromptReply {
            blocks: vec![text("a"), text("b")],
        };
        assert_eq!(admitted_reply(&ok), Ok(()));
        assert_eq!(
            admitted_reply(&maknae_proto::PromptReply { blocks: vec![] }),
            Err(ReplyRefusal::Empty)
        );
        assert_eq!(
            admitted_reply(&maknae_proto::PromptReply {
                blocks: vec![
                    text("a"),
                    ContentBlock::Image {
                        data: "".into(),
                        mime_type: "image/png".into(),
                    },
                ],
            }),
            Err(ReplyRefusal::NonText)
        );
    }

    #[test]
    fn outcome_for_sets_status_result_reason_and_posture_per_send_outcome() {
        let i = DurableEgressIntent {
            record: intent_record(),
        };
        for (outcome, status, result, reason, posture, reply_length) in [
            (
                SendOutcome::Sent { reply_length: 2 },
                EgressStatus::Sent,
                "permit",
                "sent",
                "authorized",
                Some(2),
            ),
            (
                SendOutcome::Failed,
                EgressStatus::Failed,
                "deny",
                "send failed",
                "unavailable",
                None,
            ),
            (
                SendOutcome::DeadlineExpired,
                EgressStatus::DeadlineExpired,
                "deny",
                "send deadline expired",
                "unavailable",
                None,
            ),
            // permit: the decision WAS a permit and the content DID leave; only
            // delivery back was refused (the same pairing as the Read path's
            // refused-oversize corrective, locked by enforce_loop.rs).
            (
                SendOutcome::LandedUndelivered {
                    reply_length: 7,
                    refusal: ReplyRefusal::Oversize,
                },
                EgressStatus::LandedUndelivered,
                "permit",
                "reply refused: oversize",
                "refused-oversize",
                Some(7),
            ),
            (
                SendOutcome::LandedUndelivered {
                    reply_length: 7,
                    refusal: ReplyRefusal::NonText,
                },
                EgressStatus::LandedUndelivered,
                "permit",
                "reply refused: non-text",
                "unauthorized",
                Some(7),
            ),
            (
                SendOutcome::LandedUndelivered {
                    reply_length: 0,
                    refusal: ReplyRefusal::Empty,
                },
                EgressStatus::LandedUndelivered,
                "permit",
                "reply refused: empty",
                "unauthorized",
                Some(0),
            ),
        ] {
            let o = outcome_for(&i, 9, "2026-09-08T00:00:00Z".into(), outcome);
            assert_eq!((o.seq, o.ts.as_str()), (9, "2026-09-08T00:00:00Z"));
            assert_eq!(
                (
                    o.outcome.result.as_str(),
                    o.outcome.reason.as_str(),
                    o.outcome.posture.as_str()
                ),
                (result, reason, posture),
                "{status:?}"
            );
            let e = o.egress.as_ref().unwrap();
            assert_eq!(
                (e.status, e.reply_length, e.is_intent()),
                (status, reply_length, false)
            );
            assert_eq!(
                (
                    e.content_length,
                    e.content_digest.as_str(),
                    e.conversation.as_str()
                ),
                (3, "a".repeat(32).as_str(), "c"),
                "identity carried from the intent"
            );
        }
    }
}
