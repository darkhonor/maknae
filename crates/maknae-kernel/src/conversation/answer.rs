use super::bounds::BoundRefusal;
use super::facts::DeleteEffect;
use super::store::StoreError;
use super::turn::TurnRefusal;
use crate::egress::ReplyRefusal;
use crate::mutation::Blocked;
use maknae_proto::ProtoErrCode;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Answer {
    pub reason: String,
    pub posture: &'static str,
    pub code: ProtoErrCode,
    pub message: &'static str,
}

fn unauthorized(reason: String, posture: &'static str) -> Answer {
    Answer {
        reason,
        posture,
        code: ProtoErrCode::Unauthorized,
        message: "not authorized",
    }
}

fn bound(b: BoundRefusal) -> Answer {
    Answer {
        reason: b.message().into(),
        posture: "refused-oversize",
        code: b.wire_code(),
        message: b.message(),
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EffectFailure {
    Store(StoreError),
    Blocked(Blocked),
}

pub fn effect_answer(f: &EffectFailure) -> Answer {
    match f {
        EffectFailure::Store(e) => match BoundRefusal::from_store(e) {
            Some(b) => bound(b),
            None => unauthorized(format!("not done: {e}"), "unavailable"),
        },
        EffectFailure::Blocked(Blocked::NotStarted) => {
            unauthorized(format!("not done: {}", Blocked::NotStarted), "unavailable")
        }
        EffectFailure::Blocked(Blocked::Unknown) => unauthorized(
            format!("outcome unknown: {}", Blocked::Unknown),
            "unavailable",
        ),
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StepFailure {
    NoConversation,
    Turn(TurnRefusal),
    Store(StoreError),
    Blocked(Blocked),
}

pub fn advance_answer(f: &StepFailure) -> Answer {
    match f {
        StepFailure::NoConversation => unauthorized(
            "prompt permitted without an active conversation".into(),
            "unauthorized",
        ),
        StepFailure::Turn(TurnRefusal::Bound(b)) => bound(*b),
        StepFailure::Turn(TurnRefusal::Rewrite) => {
            unauthorized("history rewrite refused".into(), "unauthorized")
        }
        StepFailure::Turn(TurnRefusal::Unencodable) => unauthorized(
            "conversation turns cannot be encoded".into(),
            "unauthorized",
        ),
        StepFailure::Store(e) => unauthorized(
            format!("conversation changed before the send: {e}"),
            "unauthorized",
        ),
        StepFailure::Blocked(b) => unauthorized(
            format!("conversation update unavailable: {b}"),
            "unauthorized",
        ),
    }
}

pub fn reply_refusal(f: &StepFailure) -> (bool, ReplyRefusal) {
    match f {
        StepFailure::Turn(TurnRefusal::Bound(_)) => (true, ReplyRefusal::ConversationFull),
        StepFailure::NoConversation
        | StepFailure::Turn(TurnRefusal::Rewrite | TurnRefusal::Unencodable)
        | StepFailure::Store(_)
        | StepFailure::Blocked(_) => (false, ReplyRefusal::ConversationChanged),
    }
}

pub fn sweep_outcome(r: &Result<(), EffectFailure>) -> (String, &'static str) {
    match r {
        Ok(()) => ("idle; conversation closed".into(), "authorized"),
        Err(EffectFailure::Store(StoreError::NotFound | StoreError::StaleFence)) => (
            "idle; conversation moved on, not closed".into(),
            "authorized",
        ),
        Err(f) => (format!("idle; {}", effect_answer(f).reason), "unavailable"),
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeleteStep {
    Remove,
    NothingHeld,
    Refuse,
}

pub fn delete_step(effect: DeleteEffect, held: bool) -> DeleteStep {
    match (effect, held) {
        (DeleteEffect::RemoveActive, true) => DeleteStep::Remove,
        (DeleteEffect::RecordArchived, _) => DeleteStep::NothingHeld,
        (DeleteEffect::RemoveActive, false) | (DeleteEffect::Refuse, _) => DeleteStep::Refuse,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const DENIED: (ProtoErrCode, &str) = (ProtoErrCode::Unauthorized, "not authorized");

    fn wire(a: &Answer) -> (ProtoErrCode, &'static str) {
        (a.code.clone(), a.message)
    }

    #[test]
    fn a_bound_is_too_large_and_every_other_store_failure_is_not_done() {
        let full = effect_answer(&EffectFailure::Store(StoreError::OwnerFull));
        assert_eq!(
            (full.reason.as_str(), full.posture, wire(&full)),
            (
                "too many active conversations",
                "refused-oversize",
                (ProtoErrCode::TooLarge, "too many active conversations")
            )
        );
        let stale = effect_answer(&EffectFailure::Store(StoreError::StaleFence));
        assert_eq!(
            (stale.reason.as_str(), stale.posture, wire(&stale)),
            (
                "not done: conversation changed since it was read",
                "unavailable",
                DENIED
            )
        );
    }

    #[test]
    fn work_that_never_started_is_not_done_and_work_that_overran_is_unknown() {
        let never = effect_answer(&EffectFailure::Blocked(Blocked::NotStarted));
        assert!(never.reason.starts_with("not done: "), "{never:?}");
        assert_eq!((never.posture, wire(&never)), ("unavailable", DENIED));
        let overran = effect_answer(&EffectFailure::Blocked(Blocked::Unknown));
        assert!(
            overran.reason.starts_with("outcome unknown: "),
            "{overran:?}"
        );
        assert_eq!((overran.posture, wire(&overran)), ("unavailable", DENIED));
    }

    #[test]
    fn each_advance_failure_has_its_own_answer() {
        let full = advance_answer(&StepFailure::Turn(TurnRefusal::Bound(
            BoundRefusal::ConversationFull,
        )));
        assert_eq!(
            (full.reason.as_str(), full.posture, wire(&full)),
            (
                "conversation is full",
                "refused-oversize",
                (ProtoErrCode::TooLarge, "conversation is full")
            )
        );
        for (f, reason) in [
            (
                StepFailure::NoConversation,
                "prompt permitted without an active conversation",
            ),
            (
                StepFailure::Turn(TurnRefusal::Rewrite),
                "history rewrite refused",
            ),
            (
                StepFailure::Turn(TurnRefusal::Unencodable),
                "conversation turns cannot be encoded",
            ),
            (
                StepFailure::Store(StoreError::StaleFence),
                "conversation changed before the send: conversation changed since it was read",
            ),
            (
                StepFailure::Blocked(Blocked::NotStarted),
                &format!("conversation update unavailable: {}", Blocked::NotStarted),
            ),
            (
                StepFailure::Blocked(Blocked::Unknown),
                &format!("conversation update unavailable: {}", Blocked::Unknown),
            ),
        ] {
            let a = advance_answer(&f);
            assert_eq!(
                (a.reason.as_str(), a.posture, wire(&a)),
                (reason, "unauthorized", DENIED),
                "{f:?}"
            );
        }
    }

    #[test]
    fn only_a_bound_marks_the_conversation_full() {
        assert_eq!(
            reply_refusal(&StepFailure::Turn(TurnRefusal::Bound(
                BoundRefusal::ConversationFull
            ))),
            (true, ReplyRefusal::ConversationFull)
        );
        for f in [
            StepFailure::NoConversation,
            StepFailure::Turn(TurnRefusal::Rewrite),
            StepFailure::Turn(TurnRefusal::Unencodable),
            StepFailure::Store(StoreError::StaleFence),
            StepFailure::Store(StoreError::NotFound),
            StepFailure::Blocked(Blocked::Unknown),
        ] {
            assert_eq!(
                reply_refusal(&f),
                (false, ReplyRefusal::ConversationChanged),
                "{f:?}"
            );
        }
    }

    #[test]
    fn the_sweep_skips_a_record_that_moved_on_and_reports_every_other_failure() {
        assert_eq!(
            sweep_outcome(&Ok(())),
            ("idle; conversation closed".into(), "authorized")
        );
        for e in [StoreError::NotFound, StoreError::StaleFence] {
            assert_eq!(
                sweep_outcome(&Err(EffectFailure::Store(e))),
                (
                    "idle; conversation moved on, not closed".into(),
                    "authorized"
                )
            );
        }
        assert_eq!(
            sweep_outcome(&Err(EffectFailure::Store(StoreError::Corrupt))),
            (
                "idle; not done: conversation record cannot be opened".into(),
                "unavailable"
            )
        );
        let (reason, posture) = sweep_outcome(&Err(EffectFailure::Blocked(Blocked::Unknown)));
        assert!(reason.starts_with("idle; outcome unknown: "), "{reason}");
        assert_eq!(posture, "unavailable");
    }

    #[test]
    fn delete_removes_only_a_held_active_record() {
        assert_eq!(
            delete_step(DeleteEffect::RemoveActive, true),
            DeleteStep::Remove
        );
        assert_eq!(
            delete_step(DeleteEffect::RemoveActive, false),
            DeleteStep::Refuse
        );
        for held in [true, false] {
            assert_eq!(
                delete_step(DeleteEffect::RecordArchived, held),
                DeleteStep::NothingHeld
            );
            assert_eq!(delete_step(DeleteEffect::Refuse, held), DeleteStep::Refuse);
        }
    }
}
