//! `session.prompt` through the REAL `handle()` over the real composed PDP
//! (#172): the compensating control for mutation-excluded `run.rs`. Every leg
//! that lands there — ready-before-intent, the destination handed to both the
//! PDP and the backend, outcome-before-reply, the audit-failure closes — is
//! exercised here against a recording backend.
mod common;
use common::{Fixture, Records};
use maknae_audit_append::EgressStatus;
use maknae_proto::{ContentBlock, Payload, ProtoErrCode, RespResult, SecretText, Verb};
use std::sync::{Arc, Mutex};
use std::time::Duration;

/// The test backend: a public-trait implementation, no crate feature needed.
/// It records every request it is handed, so a test can assert the backend saw
/// exactly what the PDP decided on.
#[derive(Default)]
pub struct Recording {
    calls: Mutex<Vec<&'static str>>,
    seen: Mutex<Vec<(String, String, u64)>>,
    pub fail_send: bool,
    pub sleep: Option<Duration>,
}
impl Recording {
    pub fn calls(&self) -> Vec<&'static str> {
        self.calls.lock().unwrap().clone()
    }
    /// (destination, conversation, total text bytes) per send.
    pub fn seen(&self) -> Vec<(String, String, u64)> {
        self.seen.lock().unwrap().clone()
    }
}
impl maknae_kernel::Egress for Recording {
    fn ready(&self) -> Result<(), maknae_kernel::EgressFailure> {
        self.calls.lock().unwrap().push("ready");
        Ok(())
    }
    fn send(
        &self,
        _i: &maknae_kernel::DurableEgressIntent,
        r: maknae_kernel::EgressRequest,
    ) -> Result<maknae_kernel::EgressReply, maknae_kernel::EgressFailure> {
        self.calls.lock().unwrap().push("send");
        let text_len = r
            .content
            .iter()
            .map(|b| match b {
                ContentBlock::Text { text } => text.0.len() as u64,
                _ => 0,
            })
            .sum();
        self.seen
            .lock()
            .unwrap()
            .push((r.destination.clone(), r.conversation.clone(), text_len));
        if let Some(d) = self.sleep {
            std::thread::sleep(d);
        }
        if self.fail_send {
            return Err(maknae_kernel::EgressFailure::Transport("hermetic".into()));
        }
        Ok(maknae_kernel::EgressReply {
            reply: maknae_proto::PromptReply {
                tool_calls: vec![],
                blocks: vec![text("ok")],
            },
        })
    }
}

// No `zeroize` dep in the kernel: `maknae_io::Zeroizing` is the same type.
fn text(s: &str) -> ContentBlock {
    ContentBlock::Text {
        text: SecretText(maknae_io::Zeroizing::new(s.into())),
    }
}
fn prompt(s: &str) -> Verb {
    Verb::SessionPrompt {
        conversation: "conv-1".into(),
        content: vec![text(s)],
    }
}
fn last_prompt_record(records: &Records) -> maknae_audit_append::AuditRecord {
    records
        .snapshot()
        .into_iter()
        .rev()
        .find(|r| r.action == "session.prompt")
        .expect("a session.prompt record")
}

/// A PDP wrapper that COUNTS decisions and delegates everything to the real
/// composition, so a test can prove a path never consulted the PDP.
struct Counting<A> {
    inner: Arc<A>,
    decisions: std::sync::atomic::AtomicUsize,
}
impl<A: maknae_security::Authorizer> maknae_security::Authorizer for Counting<A> {
    fn decide(&self, req: &maknae_security::Request) -> maknae_security::Verdict {
        self.decide_reporting_role(req).0
    }
    /// Delegates the role too (#275). A wrapper that forwards only `decide`
    /// inherits the trait default and reports `None`, so the records this
    /// harness observes would say `role=none` while the real composed PDP
    /// underneath had resolved one -- the wrapper would be manufacturing the
    /// very defect the suite exists to detect. Counting happens HERE, once, so
    /// the observer stays exact.
    fn decide_reporting_role(
        &self,
        req: &maknae_security::Request,
    ) -> (maknae_security::Verdict, Option<&'static str>) {
        self.decisions
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        self.inner.decide_reporting_role(req)
    }
    fn subjects(&self) -> Option<Vec<maknae_security::SubjectBinding>> {
        self.inner.subjects()
    }
    fn backend_name(&self) -> String {
        self.inner.backend_name()
    }
}

const GRANTED: &str =
    "roles:\n  user:\n    allow: [\"session.prompt\"]\ndestinations:\n  user:\n    allow: [\"provider:openai\"]\n";

// Record sequence on the recorder for one prompt: admission (1), then the
// intent (2) and the outcome (3); the Unavailable leg emits admission then one
// BackendUnavailable record; a pre-gate refusal emits admission then one deny.

#[tokio::test]
async fn unavailable_backend_refuses_a_permitted_prompt_with_no_intent_and_answers_unauthorized() {
    let fx = Fixture::with_policy("prompt-unavail", "Read", GRANTED);
    let records = Records::new(0);
    let resp = fx
        .roundtrip(
            prompt("hello"),
            Arc::clone(&records),
            Some("openai"),
            Arc::new(maknae_kernel::Unavailable),
        )
        .await
        .expect("a refusal frame");
    assert!(
        matches!(resp.result, RespResult::Err(ref e) if e.code == ProtoErrCode::Unauthorized),
        "{resp:?}"
    );
    let trail = records.snapshot();
    let rec = last_prompt_record(&records);
    assert_eq!(
        (
            rec.outcome.result.as_str(),
            rec.outcome.reason.as_str(),
            rec.outcome.posture.as_str()
        ),
        ("deny", "egress backend not ready", "unavailable")
    );
    assert_eq!(rec.object.as_deref(), Some("provider:openai"));
    assert_eq!(
        rec.egress.as_ref().unwrap().status,
        EgressStatus::BackendUnavailable
    );
    assert!(
        trail
            .iter()
            .all(|r| r.egress.as_ref().is_none_or(|e| !e.is_intent())),
        "no intent may exist for a refused send"
    );
}

#[tokio::test]
async fn a_permitted_prompt_writes_the_intent_before_the_send_and_the_outcome_after() {
    let fx = Fixture::with_policy("prompt-ok", "Read", GRANTED);
    let records = Records::new(0);
    let eg = Arc::new(Recording::default());
    let resp = fx
        .roundtrip(
            prompt("hello world"),
            Arc::clone(&records),
            Some("openai"),
            eg.clone(),
        )
        .await
        .expect("a reply frame");
    assert!(
        matches!(resp.result, RespResult::Ok(Payload::PromptReply(_))),
        "{resp:?}"
    );
    let trail = records.snapshot();
    let intent = trail
        .iter()
        .find(|r| r.egress.as_ref().is_some_and(|e| e.is_intent()))
        .expect("an intent record");
    let outcome = trail
        .iter()
        .find(|r| {
            r.egress
                .as_ref()
                .is_some_and(|e| e.status == EgressStatus::Sent)
        })
        .expect("an outcome record");
    // NOTE: `intent.seq < outcome.seq` would hold even with the append moved
    // after the send (both come from the same counter); the ORDER proof is
    // `a_failed_intent_append_means_nothing_is_sent`.
    let e = intent.egress.as_ref().unwrap();
    assert_eq!(intent.object.as_deref(), Some("provider:openai"));
    assert_eq!(
        (
            intent.outcome.result.as_str(),
            intent.outcome.reason.as_str()
        ),
        ("permit", "intent recorded")
    );
    assert_eq!(e.content_length, 11);
    assert_eq!(
        e.content_digest,
        &maknae_vault::sha256_hex(b"hello world")[..32]
    );
    assert_eq!(e.conversation, "conv-1");
    assert!(
        !serde_json::to_string(&trail)
            .unwrap()
            .contains("hello world"),
        "prompt text must never reach the trail"
    );
    assert_eq!(
        (
            outcome.outcome.result.as_str(),
            outcome.egress.as_ref().unwrap().reply_length
        ),
        ("permit", Some(2))
    );
    assert_eq!(eg.calls(), vec!["ready", "send"]);
    // The backend was handed exactly what the PDP decided on: the kernel's
    // destination, the request's conversation, the prompt's bytes (run.rs is
    // mutation-excluded; this is the control).
    assert_eq!(
        eg.seen(),
        vec![("provider:openai".to_string(), "conv-1".to_string(), 11)]
    );
}

#[tokio::test]
async fn a_failed_outcome_append_withholds_the_reply_after_the_content_left() {
    // Record 1 admission, 2 intent, 3 OUTCOME: fail exactly the outcome. The
    // content has left (the backend was called); the reply must still be
    // withheld, audit-then-respond on the release leg (#146). Deleting
    // `if may_respond(appended)` from the arm turns this red; nothing else does.
    let fx = Fixture::with_policy("prompt-outcome-fail", "Read", GRANTED);
    let records = Records::new(3);
    let eg = Arc::new(Recording::default());
    let resp = fx
        .roundtrip(
            prompt("hello"),
            Arc::clone(&records),
            Some("openai"),
            eg.clone(),
        )
        .await;
    assert!(
        resp.is_none(),
        "a failed outcome append must close frameless: {resp:?}"
    );
    let trail = records.snapshot();
    assert_eq!(trail.len(), 3);
    assert!(trail[1].egress.as_ref().unwrap().is_intent());
    assert_eq!(
        trail[2].egress.as_ref().unwrap().status,
        EgressStatus::Sent,
        "the failed append was the outcome"
    );
    assert_eq!(eg.calls(), vec!["ready", "send"]);
}

#[tokio::test]
async fn a_non_text_reply_is_refused_for_delivery_and_recorded_landed_undelivered() {
    struct Picture;
    impl maknae_kernel::Egress for Picture {
        fn ready(&self) -> Result<(), maknae_kernel::EgressFailure> {
            Ok(())
        }
        fn send(
            &self,
            _: &maknae_kernel::DurableEgressIntent,
            _: maknae_kernel::EgressRequest,
        ) -> Result<maknae_kernel::EgressReply, maknae_kernel::EgressFailure> {
            Ok(maknae_kernel::EgressReply {
                reply: maknae_proto::PromptReply {
                    tool_calls: vec![],
                    blocks: vec![
                        text("ok"),
                        ContentBlock::Image {
                            data: "AA==".into(),
                            mime_type: "image/png".into(),
                        },
                    ],
                },
            })
        }
    }
    let fx = Fixture::with_policy("prompt-nontext-reply", "Read", GRANTED);
    let records = Records::new(0);
    let resp = fx
        .roundtrip(
            prompt("hello"),
            Arc::clone(&records),
            Some("openai"),
            Arc::new(Picture),
        )
        .await
        .expect("a refusal frame");
    assert!(
        matches!(resp.result, RespResult::Err(ref e) if e.code == ProtoErrCode::Unauthorized),
        "{resp:?}"
    );
    let outcome = last_prompt_record(&records);
    let e = outcome.egress.as_ref().unwrap();
    assert_eq!(
        (e.status, e.reply_length),
        (EgressStatus::LandedUndelivered, Some(2))
    );
    assert_eq!(
        (
            outcome.outcome.result.as_str(),
            outcome.outcome.reason.as_str(),
            outcome.outcome.posture.as_str()
        ),
        ("permit", "reply refused: non-text", "unauthorized")
    );
    // And an EMPTY reply (legal in ACP) is refused by name, not called non-text.
    struct Silence;
    impl maknae_kernel::Egress for Silence {
        fn ready(&self) -> Result<(), maknae_kernel::EgressFailure> {
            Ok(())
        }
        fn send(
            &self,
            _: &maknae_kernel::DurableEgressIntent,
            _: maknae_kernel::EgressRequest,
        ) -> Result<maknae_kernel::EgressReply, maknae_kernel::EgressFailure> {
            Ok(maknae_kernel::EgressReply {
                reply: maknae_proto::PromptReply {
                    tool_calls: vec![],
                    blocks: vec![],
                },
            })
        }
    }
    let records = Records::new(0);
    let resp = fx
        .roundtrip(
            prompt("hello"),
            Arc::clone(&records),
            Some("openai"),
            Arc::new(Silence),
        )
        .await
        .expect("a refusal frame");
    assert!(matches!(resp.result, RespResult::Err(ref e) if e.code == ProtoErrCode::Unauthorized));
    let outcome = last_prompt_record(&records);
    assert_eq!(
        (
            outcome.egress.as_ref().unwrap().reply_length,
            outcome.outcome.reason.as_str()
        ),
        (Some(0), "reply refused: empty")
    );
}

#[tokio::test]
async fn a_failed_intent_append_means_nothing_is_sent() {
    // Record 1 is admission, record 2 is the intent: fail exactly that one.
    let fx = Fixture::with_policy("prompt-append-fail", "Read", GRANTED);
    let records = Records::new(2);
    let eg = Arc::new(Recording::default());
    let resp = fx
        .roundtrip(
            prompt("hello"),
            Arc::clone(&records),
            Some("openai"),
            eg.clone(),
        )
        .await;
    assert!(
        resp.is_none(),
        "a failed intent append must close frameless, like every audit failure: {resp:?}"
    );
    let trail = records.snapshot();
    assert!(
        trail[1].egress.as_ref().unwrap().is_intent(),
        "the injected failure must hit the intent, not admission"
    );
    assert_eq!(eg.calls(), vec!["ready"]);
}

#[tokio::test]
async fn a_failed_send_is_an_outcome_deny_after_a_real_intent() {
    let fx = Fixture::with_policy("prompt-send-fail", "Read", GRANTED);
    let records = Records::new(0);
    let eg = Arc::new(Recording {
        fail_send: true,
        ..Default::default()
    });
    let resp = fx
        .roundtrip(
            prompt("hello"),
            Arc::clone(&records),
            Some("openai"),
            eg.clone(),
        )
        .await
        .expect("a refusal frame");
    assert!(matches!(resp.result, RespResult::Err(ref e) if e.code == ProtoErrCode::Unauthorized));
    let outcome = last_prompt_record(&records);
    assert_eq!(outcome.egress.unwrap().status, EgressStatus::Failed);
    assert_eq!(
        (
            outcome.outcome.result.as_str(),
            outcome.outcome.posture.as_str()
        ),
        ("deny", "unavailable")
    );
    assert_eq!(eg.calls(), vec!["ready", "send"]);
}

#[tokio::test]
async fn a_send_past_the_transport_deadline_is_deadline_expired_delivery_unknown() {
    let fx = Fixture::with_policy("prompt-deadline", "Read", GRANTED);
    let records = Records::new(0);
    let mut cfg = maknae_config::transport_from_section(None).unwrap();
    cfg.read_timeout_ms = 200;
    // The abandoned blocking worker keeps sleeping after the handler returns
    // at 200ms; the tokio test runtime waits for it on drop (~1.3s).
    // Deliberate: do not "optimise" the sleep away.
    let eg = Arc::new(Recording {
        sleep: Some(Duration::from_millis(1500)),
        ..Default::default()
    });
    let resp = fx
        .roundtrip_with_config(
            prompt("hello"),
            Arc::clone(&records),
            Some("openai"),
            eg.clone(),
            cfg,
        )
        .await
        .expect("a refusal frame");
    assert!(matches!(resp.result, RespResult::Err(ref e) if e.code == ProtoErrCode::Unauthorized));
    let outcome = last_prompt_record(&records);
    assert_eq!(
        outcome.egress.unwrap().status,
        EgressStatus::DeadlineExpired
    );
    assert_eq!(
        (
            outcome.outcome.result.as_str(),
            outcome.outcome.reason.as_str()
        ),
        ("deny", "send deadline expired")
    );
}

#[tokio::test]
async fn non_text_content_and_a_bad_conversation_id_are_refused_before_any_decision() {
    let fx = Fixture::with_policy("prompt-shape", "Read", GRANTED);
    for (verb, needle) in [
        (
            Verb::SessionPrompt {
                conversation: "c".into(),
                content: vec![ContentBlock::Image {
                    data: "AA==".into(),
                    mime_type: "image/png".into(),
                }],
            },
            "image",
        ),
        (
            Verb::SessionPrompt {
                conversation: "has space".into(),
                content: vec![text("x")],
            },
            "conversation",
        ),
        (
            Verb::SessionPrompt {
                conversation: "c".repeat(33),
                content: vec![text("x")],
            },
            "conversation",
        ),
        (
            Verb::SessionPrompt {
                conversation: "c".into(),
                content: vec![],
            },
            "no content",
        ),
    ] {
        let records = Records::new(0);
        let eg = Arc::new(Recording::default());
        let resp = fx
            .roundtrip(verb, Arc::clone(&records), Some("openai"), eg.clone())
            .await
            .expect("a BadRequest frame");
        assert!(
            matches!(resp.result, RespResult::Err(ref e) if e.code == ProtoErrCode::BadRequest),
            "{needle}: {resp:?}"
        );
        let rec = last_prompt_record(&records);
        assert!(
            rec.outcome.reason.contains(needle),
            "{}",
            rec.outcome.reason
        );
        assert!(
            rec.egress.is_none(),
            "a pre-gate refusal carries no egress block"
        );
        assert!(eg.calls().is_empty());
    }
}

#[tokio::test]
async fn the_operand_pre_gate_never_consults_the_pdp_and_the_observer_is_live() {
    // The Composition, wrapped so its decisions can be counted. First prove the
    // observer works: a well-formed prompt is decided exactly once.
    let fx = Fixture::with_policy("prompt-pdp-count", "Read", GRANTED);
    let counting = Arc::new(Counting {
        inner: fx.authorizer(),
        decisions: std::sync::atomic::AtomicUsize::new(0),
    });
    let resp = fx
        .roundtrip_with_authorizer(
            Arc::clone(&counting),
            prompt("hello"),
            Records::new(0),
            Some("openai"),
            Arc::new(Recording::default()),
        )
        .await
        .expect("a frame");
    assert!(matches!(
        resp.result,
        RespResult::Ok(Payload::PromptReply(_))
    ));
    assert_eq!(
        counting.decisions.load(std::sync::atomic::Ordering::SeqCst),
        1,
        "the observer must see the one decision a well-formed prompt gets"
    );
    // Now every malformed shape: BadRequest, and ZERO decisions.
    for verb in [
        Verb::SessionPrompt {
            conversation: "c".into(),
            content: vec![ContentBlock::Image {
                data: "AA==".into(),
                mime_type: "image/png".into(),
            }],
        },
        Verb::SessionPrompt {
            conversation: "has space".into(),
            content: vec![text("x")],
        },
        Verb::SessionPrompt {
            conversation: "c".into(),
            content: vec![],
        },
    ] {
        let counting = Arc::new(Counting {
            inner: fx.authorizer(),
            decisions: std::sync::atomic::AtomicUsize::new(0),
        });
        let resp = fx
            .roundtrip_with_authorizer(
                Arc::clone(&counting),
                verb,
                Records::new(0),
                Some("openai"),
                Arc::new(Recording::default()),
            )
            .await
            .expect("a BadRequest frame");
        assert!(
            matches!(resp.result, RespResult::Err(ref e) if e.code == ProtoErrCode::BadRequest)
        );
        assert_eq!(
            counting.decisions.load(std::sync::atomic::Ordering::SeqCst),
            0,
            "a malformed operand must be refused BEFORE the PDP"
        );
    }
}

#[tokio::test]
async fn a_malformed_prompt_frame_never_carries_its_bytes_into_the_trail() {
    // A decode failure's diagnostic quotes the offending value (serde: `invalid
    // type: string "…"`). A block shaped `{"Text": "<sentinel>"}` is malformed
    // (Text is a map), and the sentinel must not reach any record.
    // Hand-emitted CBOR (the kernel's test crate carries no CBOR dependency):
    // {"protocol_version": 1, "verb": {"SessionPrompt": {"conversation": "c",
    //  "content": [{"Text": "<sentinel>"}]}}}. `Text` must be a map; a bare
    // string is what makes the decoder quote the value in its diagnostic.
    let sentinel = "PROMPT_PLAINTEXT_REVIEW_SENTINEL";
    fn tstr(out: &mut Vec<u8>, s: &str) {
        let n = s.len();
        if n < 24 {
            out.push(0x60 | n as u8);
        } else {
            out.push(0x78);
            out.push(n as u8);
        }
        out.extend_from_slice(s.as_bytes());
    }
    let mut raw = Vec::new();
    raw.push(0xa2);
    tstr(&mut raw, "protocol_version");
    raw.push(0x01);
    tstr(&mut raw, "verb");
    raw.push(0xa1);
    tstr(&mut raw, "SessionPrompt");
    raw.push(0xa2);
    tstr(&mut raw, "conversation");
    tstr(&mut raw, "c");
    tstr(&mut raw, "content");
    raw.push(0x81);
    raw.push(0xa1);
    tstr(&mut raw, "Text");
    tstr(&mut raw, sentinel);
    // Prove the frame is the malformed shape intended: it must NOT decode.
    assert!(maknae_proto::decode_request(&raw).is_err());
    let fx = Fixture::with_policy("prompt-sentinel", "Read", GRANTED);
    let records = Records::new(0);
    let resp = fx
        .roundtrip_raw(
            &raw,
            Arc::clone(&records),
            Some("openai"),
            Arc::new(Recording::default()),
        )
        .await;
    assert!(
        resp.is_none(),
        "a decode failure is audited and CLOSED, never answered: {resp:?}"
    );
    let trail = serde_json::to_string(&records.snapshot()).unwrap();
    assert!(
        !trail.contains(sentinel),
        "client bytes reached the trail: {trail}"
    );
    assert!(
        trail.contains("malformed request: decode"),
        "the class is recorded, not the diagnostic: {trail}"
    );
}

#[tokio::test]
async fn a_pre_gate_refusal_whose_record_cannot_be_appended_is_closed_frameless() {
    let fx = Fixture::with_policy("prompt-shape-nofr", "Read", GRANTED);
    let records = Records::new(2); // admission lands; the pre-gate deny record fails
    let resp = fx
        .roundtrip(
            Verb::SessionPrompt {
                conversation: "c".into(),
                content: vec![],
            },
            Arc::clone(&records),
            Some("openai"),
            Arc::new(Recording::default()),
        )
        .await;
    assert!(resp.is_none(), "{resp:?}");
}

#[tokio::test]
async fn a_prompt_outside_the_allowlist_is_a_deny_recorded_as_an_attempted_redirect() {
    let fx = Fixture::with_policy(
        "prompt-redirect",
        "Read",
        &GRANTED.replace("provider:openai", "provider:other"),
    );
    let records = Records::new(0);
    let eg = Arc::new(Recording::default());
    let resp = fx
        .roundtrip(
            prompt("hello"),
            Arc::clone(&records),
            Some("openai"),
            eg.clone(),
        )
        .await
        .expect("a refusal frame");
    assert!(matches!(resp.result, RespResult::Err(ref e) if e.code == ProtoErrCode::Unauthorized));
    let rec = last_prompt_record(&records);
    assert_eq!(rec.outcome.result, "deny");
    assert!(rec.outcome.reason.contains("destination not allowlisted"));
    assert!(eg.calls().is_empty());
}

#[tokio::test]
async fn an_ungranted_prompt_is_unauthorized_on_the_wire_and_an_absence_then_deny_in_the_trail() {
    // Spec §6: destination without the action grant → NotApplicable, then finalize → Deny.
    let fx = Fixture::with_policy(
        "prompt-ungranted",
        "Read",
        "destinations:\n  user:\n    allow: [\"provider:openai\"]\n",
    );
    let records = Records::new(0);
    let eg = Arc::new(Recording::default());
    let resp = fx
        .roundtrip(
            prompt("hello"),
            Arc::clone(&records),
            Some("openai"),
            eg.clone(),
        )
        .await
        .expect("a refusal frame");
    assert!(matches!(resp.result, RespResult::Err(ref e) if e.code == ProtoErrCode::Unauthorized));
    let rec = last_prompt_record(&records);
    assert_eq!(rec.outcome.result, "deny");
    // finalize renders the ABSENCE's note as the reason; an implementation that
    // made NoMatch a direct Deny would carry a different reason and fail here.
    assert_eq!(rec.outcome.reason, "role user: no rule for session.prompt");
    assert!(eg.calls().is_empty());
}

#[tokio::test]
async fn no_provider_registered_is_a_deny_not_a_crash() {
    let fx = Fixture::with_policy("prompt-noprov", "Read", GRANTED);
    let records = Records::new(0);
    let resp = fx
        .roundtrip(
            prompt("hello"),
            Arc::clone(&records),
            None,
            Arc::new(Recording::default()),
        )
        .await
        .expect("a refusal frame");
    assert!(matches!(resp.result, RespResult::Err(ref e) if e.code == ProtoErrCode::Unauthorized));
    assert!(records.snapshot().iter().any(
        |r| r.action == "session.prompt" && r.outcome.reason.contains("no provider registered")
    ));
}

#[tokio::test]
async fn an_oversize_reply_is_refused_as_too_large_never_truncated() {
    struct Huge;
    impl maknae_kernel::Egress for Huge {
        fn ready(&self) -> Result<(), maknae_kernel::EgressFailure> {
            Ok(())
        }
        fn send(
            &self,
            _: &maknae_kernel::DurableEgressIntent,
            _: maknae_kernel::EgressRequest,
        ) -> Result<maknae_kernel::EgressReply, maknae_kernel::EgressFailure> {
            Ok(maknae_kernel::EgressReply {
                reply: maknae_proto::PromptReply {
                    tool_calls: vec![],
                    blocks: vec![text(&"x".repeat(1 << 20))],
                },
            })
        }
    }
    let fx = Fixture::with_policy("prompt-huge", "Read", GRANTED);
    let records = Records::new(0);
    let resp = fx
        .roundtrip(
            prompt("hello"),
            Arc::clone(&records),
            Some("openai"),
            Arc::new(Huge),
        )
        .await
        .expect("a TooLarge frame");
    assert!(
        matches!(resp.result, RespResult::Err(ref e) if e.code == ProtoErrCode::TooLarge),
        "{resp:?}"
    );
    // ADR-0023 decision 3: the egress went out, the reply arrived, the loop never got it.
    let outcome = last_prompt_record(&records);
    let e = outcome.egress.as_ref().unwrap();
    assert_eq!(
        (e.status, e.reply_length),
        (EgressStatus::LandedUndelivered, Some(1 << 20))
    );
    // permit: the content left; only delivery back was refused.
    assert_eq!(
        (
            outcome.outcome.result.as_str(),
            outcome.outcome.reason.as_str(),
            outcome.outcome.posture.as_str()
        ),
        ("permit", "reply refused: oversize", "refused-oversize")
    );
    assert!(
        !serde_json::to_string(&records.snapshot())
            .unwrap()
            .contains("xxxxxxxx"),
        "the refused reply must not reach the trail"
    );
}
