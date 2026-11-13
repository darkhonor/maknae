//! The kernel's answers to an agent's task verbs, as the task driver reads them.
//! Pure, for the same reason as [`crate::wire`]: the client converts into
//! [`WireOutcome`], and the decisions stay here, where they are mutation-tested.
use crate::wire::WireOutcome;
use maknae_proto::{Payload, ProtoErrCode, SecretText, TaskDelivery, TaskId, TaskView};

/// The kernel answered, and the answer was no. Not a transport failure: the
/// connection completed and the refusal is on the trail.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Refused {
    pub code: ProtoErrCode,
    pub message: String,
}

#[derive(Debug, PartialEq, Eq)]
pub enum ClaimAnswer {
    Delivered(TaskDelivery),
    Idle,
    Refused(Refused),
}

#[derive(Debug, PartialEq, Eq)]
pub enum BeatAnswer {
    FollowUps {
        task: TaskId,
        from: u32,
        items: Vec<SecretText>,
    },
    State(TaskView),
    Idle,
    Refused(Refused),
}

#[derive(Debug, PartialEq, Eq)]
pub enum ReportOutcome {
    Acknowledged,
    Refused(Refused),
    /// The report is longer than `prompt_max_bytes`, the kernel's bound; nothing was sent.
    TooLarge,
}

/// `Err` is a transport or protocol failure: whether the kernel decided anything is unknown.
pub fn claim_answer(sent: Result<WireOutcome, String>) -> Result<ClaimAnswer, String> {
    match sent? {
        WireOutcome::Payload(Payload::TaskDelivered(d)) => Ok(ClaimAnswer::Delivered(d)),
        WireOutcome::Payload(Payload::TaskIdle) => Ok(ClaimAnswer::Idle),
        WireOutcome::Refused { code, message, .. } => {
            Ok(ClaimAnswer::Refused(Refused { code, message }))
        }
        other => Err(unexpected("task.claim", &other)),
    }
}

pub fn beat_answer(sent: Result<WireOutcome, String>) -> Result<BeatAnswer, String> {
    match sent? {
        WireOutcome::Payload(Payload::TaskFollowUps(f)) => Ok(BeatAnswer::FollowUps {
            task: f.task.to_id(),
            from: f.from,
            items: f.items,
        }),
        WireOutcome::Payload(Payload::TaskState(v)) => Ok(BeatAnswer::State(v)),
        WireOutcome::Payload(Payload::TaskIdle) => Ok(BeatAnswer::Idle),
        WireOutcome::Refused { code, message, .. } => {
            Ok(BeatAnswer::Refused(Refused { code, message }))
        }
        other => Err(unexpected("task.heartbeat", &other)),
    }
}

pub fn report_answer(sent: Result<WireOutcome, String>) -> Result<ReportOutcome, String> {
    match sent? {
        WireOutcome::Payload(Payload::TaskAcknowledged(_)) => Ok(ReportOutcome::Acknowledged),
        WireOutcome::Refused { code, message, .. } => {
            Ok(ReportOutcome::Refused(Refused { code, message }))
        }
        other => Err(unexpected("task.report", &other)),
    }
}

fn unexpected(verb: &str, other: &WireOutcome) -> String {
    format!("protocol error: unexpected reply to {verb}: {other:?}")
}

#[cfg(test)]
mod tests {
    use super::*;
    use maknae_proto::{TaskFollowUps, TaskRef, TaskState};

    fn view(state: TaskState) -> TaskView {
        TaskView {
            task: TaskRef::from_id(&TaskId([9; 16])),
            agent: "hobi".into(),
            state,
            close: None,
            submitted_secs: 1,
            elapsed_secs: 2,
            actions: 3,
            last_action_secs: None,
        }
    }

    fn delivery() -> TaskDelivery {
        TaskDelivery {
            signed: maknae_proto::Bytes::new(zeroize::Zeroizing::new(vec![1, 2, 3])),
            partition: "tasks/users/1000".into(),
        }
    }

    fn refusal(code: ProtoErrCode) -> Result<WireOutcome, String> {
        Ok(WireOutcome::Refused {
            code,
            message: "sentinel-629-refused".into(),
            armed: true,
        })
    }

    fn payload(p: Payload) -> Result<WireOutcome, String> {
        Ok(WireOutcome::Payload(p))
    }

    fn text(s: &str) -> SecretText {
        SecretText(zeroize::Zeroizing::new(s.into()))
    }

    #[test]
    fn a_claim_reads_delivered_idle_and_every_refusal() {
        assert_eq!(
            claim_answer(payload(Payload::TaskDelivered(delivery()))),
            Ok(ClaimAnswer::Delivered(delivery()))
        );
        assert_eq!(
            claim_answer(payload(Payload::TaskIdle)),
            Ok(ClaimAnswer::Idle)
        );
        for code in [ProtoErrCode::Unauthorized, ProtoErrCode::Internal] {
            assert_eq!(
                claim_answer(refusal(code.clone())),
                Ok(ClaimAnswer::Refused(Refused {
                    code,
                    message: "sentinel-629-refused".into()
                }))
            );
        }
    }

    #[test]
    fn a_heartbeat_reads_follow_ups_state_idle_and_refusal() {
        assert_eq!(
            beat_answer(payload(Payload::TaskFollowUps(TaskFollowUps {
                task: TaskRef::from_id(&TaskId([9; 16])),
                from: 4,
                items: vec![text("more")],
            }))),
            Ok(BeatAnswer::FollowUps {
                task: TaskId([9; 16]),
                from: 4,
                items: vec![text("more")]
            })
        );
        assert_eq!(
            beat_answer(payload(Payload::TaskState(view(TaskState::Held)))),
            Ok(BeatAnswer::State(view(TaskState::Held)))
        );
        assert_eq!(
            beat_answer(payload(Payload::TaskIdle)),
            Ok(BeatAnswer::Idle)
        );
        assert_eq!(
            beat_answer(refusal(ProtoErrCode::Unauthorized)),
            Ok(BeatAnswer::Refused(Refused {
                code: ProtoErrCode::Unauthorized,
                message: "sentinel-629-refused".into()
            }))
        );
    }

    #[test]
    fn a_report_is_done_only_when_acknowledged() {
        assert_eq!(
            report_answer(payload(Payload::TaskAcknowledged(view(
                TaskState::Reported
            )))),
            Ok(ReportOutcome::Acknowledged)
        );
        assert_eq!(
            report_answer(refusal(ProtoErrCode::Unauthorized)),
            Ok(ReportOutcome::Refused(Refused {
                code: ProtoErrCode::Unauthorized,
                message: "sentinel-629-refused".into()
            }))
        );
    }

    #[test]
    fn an_answer_to_another_question_is_a_protocol_error_not_a_task_answer() {
        let wrong = [
            Payload::Pong,
            Payload::TaskState(view(TaskState::Working)),
            Payload::TaskDelivered(delivery()),
        ];
        assert!(claim_answer(payload(Payload::Pong))
            .unwrap_err()
            .contains("unexpected reply to task.claim"));
        assert!(claim_answer(payload(Payload::TaskState(view(TaskState::Working)))).is_err());
        assert!(beat_answer(payload(Payload::TaskDelivered(delivery())))
            .unwrap_err()
            .contains("unexpected reply to task.heartbeat"));
        for p in wrong {
            assert!(report_answer(payload(p))
                .unwrap_err()
                .contains("unexpected reply to task.report"));
        }
        assert!(report_answer(payload(Payload::TaskIdle)).is_err());
    }

    #[test]
    fn a_transport_failure_is_never_an_answer() {
        let lost = || Err::<WireOutcome, _>("connection reset".to_string());
        assert_eq!(claim_answer(lost()), Err("connection reset".into()));
        assert_eq!(beat_answer(lost()), Err("connection reset".into()));
        assert_eq!(report_answer(lost()), Err("connection reset".into()));
    }
}
