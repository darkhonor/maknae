//! The agent's task verbs: claim, heartbeat and report, one connection each.
//! Claims and heartbeats never cite: the kernel ends a connection whose cited
//! task is not `Working`. A report carries the loop's cite. Answers are read at
//! the ceiling cap, because the kernel's task text bound is not the agent's to know.
use crate::plane::{Dial, Link, PlaneDial};
use maknae_agent::task::{
    beat_answer, claim_answer, report_answer, BeatAnswer, ClaimAnswer, ReportOutcome,
};
use maknae_agent::task_driver::VerifyClass;
use maknae_agent::wire::WireOutcome;
use maknae_proto::{SecretText, Verb};
use maknae_vault::task_sig::TaskSignatureError;
use std::sync::Arc;

pub struct TaskClient<D: Dial = PlaneDial> {
    link: Arc<Link<D>>,
}

impl<D: Dial> TaskClient<D> {
    pub(crate) fn over(link: Arc<Link<D>>) -> Self {
        Self { link }
    }

    pub async fn claim(&self) -> Result<ClaimAnswer, String> {
        claim_answer(
            self.send(Verb::TaskClaim {
                seen_follow_ups: None,
            })
            .await,
        )
    }

    pub async fn heartbeat(&self, seen: u32) -> Result<BeatAnswer, String> {
        beat_answer(
            self.send(Verb::TaskClaim {
                seen_follow_ups: Some(seen),
            })
            .await,
        )
    }

    pub async fn report(&self, text: SecretText) -> Result<ReportOutcome, String> {
        if text.0.len() > self.link.transport().prompt_max_bytes {
            return Ok(ReportOutcome::TooLarge);
        }
        report_answer(self.send(Verb::TaskReport { text }).await)
    }

    async fn send(&self, verb: Verb) -> Result<WireOutcome, String> {
        self.link
            .send(
                verb,
                None,
                crate::mutation::WriteCheck::Unchecked,
                &mut |_| {},
            )
            .await
            .map(WireOutcome::from)
    }
}

/// Total: a new `TaskSignatureError` variant does not compile until it is classed.
pub fn verify_class(e: TaskSignatureError) -> VerifyClass {
    match e {
        TaskSignatureError::AgentMismatch => VerifyClass::Agent,
        TaskSignatureError::Algorithm => VerifyClass::Algorithm,
        TaskSignatureError::NotKernel => VerifyClass::NotKernel,
        TaskSignatureError::KeyMismatch => VerifyClass::Key,
        TaskSignatureError::BadSignature => VerifyClass::Signature,
        TaskSignatureError::Encoding => VerifyClass::Encoding,
    }
}

#[cfg(test)]
mod tests {
    use crate::keys::KeySupply;
    use crate::plane::fake::{refused, FakeKernel};
    use crate::plane::LoopPlane;
    use maknae_agent::task::{BeatAnswer, ClaimAnswer, Refused, ReportOutcome};
    use maknae_proto::{
        Payload, ProtoErrCode, ProviderChoice, RespResult, SecretText, TaskDelivery, TaskId,
        TaskState, Verb,
    };

    struct Keys;
    impl KeySupply for Keys {
        async fn choice(&mut self, _c: &str, _now: u64) -> Result<ProviderChoice, String> {
            Ok(ProviderChoice {
                provider: "p".into(),
                model: "m".into(),
                key_subpath: "k".into(),
                key_field: "f".into(),
                sealed_key: maknae_proto::SealedKey::new(vec![
                    7;
                    maknae_proto::SEALED_KEY_MIN_BYTES
                ])
                .unwrap(),
            })
        }
    }

    fn plane_with(
        transport: maknae_config::TransportConfig,
        answers: Vec<RespResult>,
    ) -> LoopPlane<Keys, FakeKernel> {
        LoopPlane::with_dial(FakeKernel::answering(answers), transport, None, 4096, Keys)
    }

    fn plane(answers: Vec<RespResult>) -> LoopPlane<Keys, FakeKernel> {
        plane_with(maknae_config::TransportConfig::default(), answers)
    }

    fn text(s: &str) -> SecretText {
        SecretText(zeroize::Zeroizing::new(s.into()))
    }

    fn view(state: TaskState) -> maknae_proto::TaskView {
        maknae_proto::TaskView {
            task: maknae_proto::TaskRef::from_id(&TaskId([3; 16])),
            agent: "hobi".into(),
            state,
            close: None,
            submitted_secs: 0,
            elapsed_secs: 0,
            actions: 0,
            last_action_secs: None,
        }
    }

    #[tokio::test]
    async fn claims_and_heartbeats_are_never_cited() {
        let id = TaskId([0x29; 16]);
        let plane = plane(vec![
            RespResult::Ok(Payload::TaskIdle),
            RespResult::Ok(Payload::TaskState(view(TaskState::Held))),
            RespResult::Ok(Payload::TaskAcknowledged(view(TaskState::Reported))),
        ]);
        plane.cite(Some(id));
        let tasks = plane.tasks();
        assert_eq!(tasks.claim().await, Ok(ClaimAnswer::Idle));
        assert_eq!(
            tasks.heartbeat(5).await,
            Ok(BeatAnswer::State(view(TaskState::Held)))
        );
        assert_eq!(
            tasks.report(text("done")).await,
            Ok(ReportOutcome::Acknowledged)
        );
        let seen = plane.link_for_test().finish().await;
        let sent: Vec<_> = seen
            .requests
            .iter()
            .map(|r| match &r.verb {
                Verb::TaskClaim { seen_follow_ups } => (Some(*seen_follow_ups), r.task),
                Verb::TaskReport { text } => {
                    assert_eq!(text.0.as_str(), "done");
                    (None, r.task)
                }
                other => panic!("unexpected verb {other:?}"),
            })
            .collect();
        assert_eq!(
            sent,
            [(Some(None), None), (Some(Some(5)), None), (None, Some(id))]
        );
    }

    #[tokio::test]
    async fn task_answers_are_read_with_the_ceiling_cap() {
        let transport = maknae_config::TransportConfig {
            prompt_max_bytes: maknae_config::PROMPT_MAX_BYTES_FLOOR,
            ..Default::default()
        };
        let over = maknae_proto::prompt_response_cap(transport.prompt_max_bytes) + 1024;
        let delivery = TaskDelivery {
            signed: maknae_proto::Bytes::new(zeroize::Zeroizing::new(vec![0x5a; over])),
            partition: "tasks/users/1000".into(),
        };
        let big_reply = maknae_proto::PromptReply {
            reasoning: None,
            blocks: vec![maknae_proto::ContentBlock::Text {
                text: text(&"y".repeat(over)),
            }],
            tool_calls: vec![],
            usage: None,
        };
        let mut plane = plane_with(
            transport,
            vec![
                RespResult::Ok(Payload::TaskDelivered(delivery.clone())),
                RespResult::Ok(Payload::PromptReply(big_reply)),
            ],
        );
        assert_eq!(
            plane.tasks().claim().await,
            Ok(ClaimAnswer::Delivered(delivery))
        );
        let prompt = maknae_agent::plane::Plane::prompt(
            &mut plane,
            "c",
            &[maknae_proto::Turn::User {
                content: vec![maknae_proto::ContentBlock::Text { text: text("q") }],
            }],
        )
        .await;
        assert!(
            matches!(&prompt, Err(maknae_agent::plane::PlaneError::Transport(m)) if m.contains("oversize")),
            "{prompt:?}"
        );
    }

    #[tokio::test]
    async fn a_refused_claim_is_refused_not_a_client_error() {
        let plane = plane(vec![refused(), refused(), refused()]);
        let tasks = plane.tasks();
        let no = Refused {
            code: ProtoErrCode::Unauthorized,
            message: "sentinel-629-refused".into(),
        };
        assert_eq!(tasks.claim().await, Ok(ClaimAnswer::Refused(no.clone())));
        assert_eq!(
            tasks.heartbeat(0).await,
            Ok(BeatAnswer::Refused(no.clone()))
        );
        assert_eq!(
            tasks.report(text("r")).await,
            Ok(ReportOutcome::Refused(no))
        );
        let unanswered = plane.tasks().claim().await;
        assert!(unanswered.is_err(), "{unanswered:?}");
    }

    #[tokio::test]
    async fn a_task_answer_over_the_ceiling_is_refused_as_oversize() {
        let over = maknae_proto::prompt_response_cap(maknae_config::PROMPT_MAX_CEILING) + 1;
        let delivery = TaskDelivery {
            signed: maknae_proto::Bytes::new(zeroize::Zeroizing::new(vec![0x5a; over])),
            partition: "tasks/users/1000".into(),
        };
        let plane = plane(vec![RespResult::Ok(Payload::TaskDelivered(delivery))]);
        let got = plane.tasks().claim().await;
        assert!(matches!(&got, Err(m) if m.contains("oversize")), "{got:?}");
    }

    #[tokio::test]
    async fn a_report_too_large_for_the_frame_is_not_sent() {
        let transport = maknae_config::TransportConfig {
            prompt_max_bytes: maknae_config::PROMPT_MAX_BYTES_FLOOR,
            ..Default::default()
        };
        let plane = plane_with(transport.clone(), vec![refused()]);
        let fits = "r".repeat(transport.prompt_max_bytes / 2);
        let over = "r".repeat(maknae_proto::prompt_request_cap(transport.prompt_max_bytes));
        assert_eq!(
            plane.tasks().report(text(&over)).await,
            Ok(ReportOutcome::TooLarge)
        );
        assert!(matches!(
            plane.tasks().report(text(&fits)).await,
            Ok(ReportOutcome::Refused(_))
        ));
        assert_eq!(plane.link_for_test().finish().await.requests.len(), 1);
    }

    #[tokio::test]
    async fn a_report_longer_than_the_kernels_text_bound_is_not_sent() {
        let transport = maknae_config::TransportConfig {
            prompt_max_bytes: maknae_config::PROMPT_MAX_BYTES_FLOOR,
            ..Default::default()
        };
        let plane = plane_with(transport.clone(), vec![refused()]);
        let over = "r".repeat(transport.prompt_max_bytes + 1);
        let at = "r".repeat(transport.prompt_max_bytes);
        assert_eq!(
            plane.tasks().report(text(&over)).await,
            Ok(ReportOutcome::TooLarge)
        );
        assert!(matches!(
            plane.tasks().report(text(&at)).await,
            Ok(ReportOutcome::Refused(_))
        ));
        assert_eq!(plane.link_for_test().finish().await.requests.len(), 1);
    }

    #[test]
    fn every_verify_error_maps_to_a_class() {
        use super::verify_class;
        use maknae_agent::task_driver::VerifyClass;
        use maknae_vault::task_sig::TaskSignatureError;
        let all = [
            TaskSignatureError::AgentMismatch,
            TaskSignatureError::Algorithm,
            TaskSignatureError::NotKernel,
            TaskSignatureError::KeyMismatch,
            TaskSignatureError::BadSignature,
            TaskSignatureError::Encoding,
        ];
        for e in all {
            let want = match e {
                TaskSignatureError::AgentMismatch => (VerifyClass::Agent, "agent"),
                TaskSignatureError::Algorithm => (VerifyClass::Algorithm, "algorithm"),
                TaskSignatureError::NotKernel => (VerifyClass::NotKernel, "not-kernel"),
                TaskSignatureError::KeyMismatch => (VerifyClass::Key, "key"),
                TaskSignatureError::BadSignature => (VerifyClass::Signature, "signature"),
                TaskSignatureError::Encoding => (VerifyClass::Encoding, "encoding"),
            };
            assert_eq!(verify_class(e), want.0, "{e:?}");
            assert_eq!(verify_class(e).as_str(), want.1, "{e:?}");
        }
    }
}
