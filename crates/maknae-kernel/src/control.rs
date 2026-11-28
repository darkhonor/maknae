//! The agent control channel's exchange (#746): one notice poll per connection, decided
//! like any request and answered only as `crate::handler::control_reply` allows.
use std::sync::Arc;
use std::time::Duration;

use maknae_audit_append::{AuditEmit, AuditRecord, NoticeAudit};
use maknae_config::TransportConfig;
use maknae_proto::{
    AgentNotice, ControlResponse, FrameCaps, FrameClass, Notice, NoticeBody, ProtoErrCode,
    ProtoError, CONTROL_REQUEST_MAX, PROTOCOL_VERSION,
};
use maknae_security::{finalize, Authorizer, Decision};
use tokio::io::{AsyncRead, AsyncWrite};

use crate::authz::{admission_facts, revalidate, DenyCause, Ending, Revalidation};
use crate::blocking_guard::BlockingBreaker;
use crate::handler::{
    build_control_request, control_reply, discharge_plan, may_respond, ControlOutcome, ControlReply,
};
use crate::run::{
    close_bounded, decide_on, emit_or_report, emit_request_deny, end_session, report_unanswered,
    request_outcome_record, AgentAdmission,
};
use crate::session::{gather, FactsGate, SessionRecord};

type Breaker = Arc<tokio::sync::Mutex<BlockingBreaker>>;

/// The control path's own breakers, so data-plane load can neither trip nor exhaust them.
#[derive(Clone, Default)]
pub struct ControlBreakers {
    pub(crate) decide: Breaker,
    pub(crate) lookup: Breaker,
}

pub(crate) fn control_request_caps() -> FrameCaps {
    FrameCaps {
        control: CONTROL_REQUEST_MAX,
        attempt: 0,
        prompt: 0,
    }
}

pub(crate) async fn decide_control<P: Authorizer + Send + Sync + 'static>(
    breaker: &Breaker,
    authorizer: &Arc<P>,
    live: &Arc<crate::live::LiveConfig>,
    req: maknae_security::Request,
    admitted_generation: u64,
    timeout: Duration,
) -> ControlOutcome {
    match decide_on(breaker, authorizer, live, req, admitted_generation, timeout).await {
        Ok((verdict, role, _)) => ControlOutcome::Decided { verdict, role },
        Err((reason, role)) => ControlOutcome::Unavailable { reason, role },
    }
}

fn outcome_role(outcome: &ControlOutcome) -> Option<&'static str> {
    match outcome {
        ControlOutcome::Decided { role, .. } | ControlOutcome::Unavailable { role, .. } => *role,
    }
}

fn refusal_posture(outcome: &ControlOutcome) -> &'static str {
    match outcome {
        ControlOutcome::Unavailable { .. } => "unavailable",
        ControlOutcome::Decided { .. } => "unauthorized",
    }
}

fn outcome_reason(outcome: &ControlOutcome) -> String {
    match outcome {
        ControlOutcome::Unavailable { reason, .. } => (*reason).to_string(),
        ControlOutcome::Decided { verdict, .. } => match finalize(verdict.clone()) {
            Decision::Deny { reason } => reason,
            Decision::Permit { obligations } => match discharge_plan(&obligations) {
                Ok(()) => "authorized".into(),
                Err(unhonorable) => format!("unhonorable obligation: {}", unhonorable.0),
            },
        },
    }
}

/// A poll's request record: its operation, and each notice by id, kind and task only.
#[allow(clippy::too_many_arguments)]
pub(crate) fn poll_record(
    (host, socket): (&str, &str),
    uid: u32,
    peer_uri: Option<&str>,
    user: Option<&str>,
    role: Option<&'static str>,
    (session_id, seq): (u64, u64),
    (result, reason, posture): (&str, &str, &str),
    notices: &[Notice<AgentNotice>],
    au3_1: &serde_json::Value,
) -> AuditRecord {
    let mut rec = request_outcome_record(
        host,
        socket,
        uid,
        peer_uri,
        user,
        role,
        None,
        session_id,
        seq,
        (maknae_security::ACTION_AGENT_CONTROL, None, None),
        (result, reason, posture),
        au3_1,
    );
    rec.subject.control_op = Some(maknae_security::CONTROL_OP_NOTICE_POLL.into());
    rec.notices = notices
        .iter()
        .map(|n| NoticeAudit {
            id: n.id.to_string(),
            kind: n.body.kind().into(),
            task: n.task.map(|t| t.to_string()),
        })
        .collect();
    rec
}

async fn write_reply<S: AsyncWrite + Unpin>(
    stream: &mut S,
    cfg: &TransportConfig,
    result: Result<Vec<Notice<AgentNotice>>, ProtoError>,
) -> bool {
    let response = ControlResponse {
        protocol_version: PROTOCOL_VERSION,
        result,
    };
    let Ok(bytes) = maknae_proto::encode_control_response(&response) else {
        return false;
    };
    let written = tokio::time::timeout(
        Duration::from_millis(cfg.read_timeout_ms),
        maknae_proto::write_frame(stream, FrameClass::Control, &bytes),
    )
    .await;
    matches!(written, Ok(Ok(())))
}

/// The session checks the data plane makes before a decision, and the agent its leaf names.
async fn still_admitted<'s>(
    session: &'s SessionRecord,
    gate: &FactsGate,
) -> Result<(Option<String>, &'s maknae_config::AgentId), (Option<String>, Ending)> {
    if let Some(e) = session.expiry() {
        return Err((session.user.clone(), e));
    }
    let facts = gather(gate, session.admission, session.uid).await;
    let (_, user, _) = admission_facts(session.admission, &facts.membership);
    if let Revalidation::Deny(cause) =
        revalidate(session.admission, session.uid, session.uid, &facts)
    {
        report_unanswered(&cause, session.uid, session.session_id);
        return Err((user, Ending::Denied(cause)));
    }
    if let Some(e) = session.expiry() {
        return Err((user, e));
    }
    match session.agent() {
        Some(agent) => Ok((user, agent)),
        None => Err((user, Ending::Denied(DenyCause::NotEnrolled))),
    }
}

/// Serves one control frame on an admitted control-plane session, then closes. Nothing is
/// written except a notice list after its record lands, or `Unauthorized` per
/// `control_reply`.
#[allow(clippy::too_many_arguments)]
pub(crate) async fn serve_control<S, E, P>(
    stream: &mut S,
    session: &SessionRecord,
    (class, body): (FrameClass, &[u8]),
    emit: &Arc<E>,
    (host, socket): (&str, &str),
    peer_uri: Option<&str>,
    gate: &FactsGate,
    cfg: &TransportConfig,
    au3_1: &serde_json::Value,
    authorizer: &Arc<P>,
    live: &Arc<crate::live::LiveConfig>,
    timeout: Duration,
    agents: &AgentAdmission,
) where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    E: AuditEmit + Send + Sync,
    P: Authorizer + Send + Sync + 'static,
{
    let (uid, session_id) = (session.uid, session.session_id);
    let refuse = |reason: String| async move {
        emit_request_deny(
            emit,
            host,
            socket,
            uid,
            peer_uri,
            session.user.as_deref(),
            None,
            session_id,
            session.seq.next(),
            "decode",
            &reason,
            "unauthorized",
            au3_1,
        )
        .await;
    };
    if class != FrameClass::Control {
        refuse("frame class mismatch: the control plane takes Control".into()).await;
        close_bounded(stream).await;
        return;
    }
    let request = match maknae_proto::decode_control_request(body) {
        Ok(r) => r,
        Err(e) => {
            refuse(format!("malformed request: {}", e.category())).await;
            close_bounded(stream).await;
            return;
        }
    };
    let action = maknae_security::ACTION_AGENT_CONTROL;
    let (user, agent) = match still_admitted(session, gate).await {
        Ok(admitted) => admitted,
        Err((user, ending)) => {
            end_session(
                stream,
                emit,
                (host, socket),
                (session, user.as_deref()),
                peer_uri,
                (cfg, class),
                action,
                ending,
                au3_1,
            )
            .await;
            return;
        }
    };
    let (_, _, admitted_generation) = live.admission();
    let outcome = decide_control(
        &agents.control.decide,
        authorizer,
        live,
        build_control_request(uid, agent, &request.verb, session.lane),
        admitted_generation,
        timeout,
    )
    .await;
    let enrolled_now = agents.view.agent_uid(agent) == Some(uid);
    let reply = control_reply(&outcome, enrolled_now);
    let role = outcome_role(&outcome);
    let reason = outcome_reason(&outcome);
    let said = |(result, reason, posture): (&str, &str, &str), notices: &[Notice<AgentNotice>]| {
        poll_record(
            (host, socket),
            uid,
            peer_uri,
            user.as_deref(),
            role,
            (session_id, session.seq.next()),
            (result, reason, posture),
            notices,
            au3_1,
        )
    };
    let record = |result, posture, notices: &[Notice<AgentNotice>]| {
        said((result, &reason, posture), notices)
    };
    match reply {
        ControlReply::Notices => {
            let notices = agents.tasks.notices_for(agent);
            let rec = record("permit", "authorized", &notices);
            if may_respond(emit_or_report(emit, &rec, action, uid, session_id).await)
                && !write_reply(stream, cfg, Ok(notices.clone())).await
            {
                let undelivered = said(
                    (
                        "permit",
                        "delivery failed: response not written",
                        "undelivered",
                    ),
                    &notices,
                );
                emit_or_report(emit, &undelivered, action, uid, session_id).await;
            }
        }
        ControlReply::Unauthorized => {
            let rec = record("deny", "unauthorized", &[]);
            if may_respond(emit_or_report(emit, &rec, action, uid, session_id).await) {
                let refused = ProtoError {
                    code: ProtoErrCode::Unauthorized,
                    message: "not authorized".into(),
                };
                write_reply(stream, cfg, Err(refused)).await;
            }
        }
        ControlReply::None => {
            let rec = record("deny", refusal_posture(&outcome), &[]);
            emit_or_report(emit, &rec, action, uid, session_id).await;
        }
    }
    close_bounded(stream).await;
}

#[cfg(test)]
mod tests {
    use super::*;
    use maknae_security::Verdict;
    use std::time::Instant;

    struct Fixed(Verdict, Option<&'static str>);

    impl Authorizer for Fixed {
        fn decide(&self, _req: &maknae_security::Request) -> Verdict {
            self.0.clone()
        }
        fn decide_reporting_role(
            &self,
            _req: &maknae_security::Request,
        ) -> (Verdict, Option<&'static str>) {
            (self.0.clone(), self.1)
        }
        fn decide_cited_all(
            &self,
            reqs: &[maknae_security::Request],
        ) -> Vec<maknae_security::Decided> {
            maknae_security::decide_each_cited(self, reqs)
        }
    }

    struct Panics;

    impl Authorizer for Panics {
        fn decide(&self, _req: &maknae_security::Request) -> Verdict {
            panic!("sentinel-746-decide-panics")
        }
        fn decide_cited_all(
            &self,
            reqs: &[maknae_security::Request],
        ) -> Vec<maknae_security::Decided> {
            maknae_security::decide_each_cited(self, reqs)
        }
    }

    struct Waits(std::sync::Mutex<std::sync::mpsc::Receiver<()>>);

    impl Authorizer for Waits {
        fn decide(&self, _req: &maknae_security::Request) -> Verdict {
            let _ = self.0.lock().unwrap().recv();
            Verdict::Indeterminate
        }
        fn decide_cited_all(
            &self,
            reqs: &[maknae_security::Request],
        ) -> Vec<maknae_security::Decided> {
            maknae_security::decide_each_cited(self, reqs)
        }
    }

    fn poll() -> maknae_security::Request {
        build_control_request(
            2001,
            &maknae_config::AgentId::parse("hobi").unwrap(),
            &maknae_proto::ControlVerb::NoticePoll {},
            maknae_security::Lane::Local,
        )
    }

    fn live() -> Arc<crate::live::LiveConfig> {
        Arc::new(crate::live::LiveConfig::new(Default::default(), None))
    }

    fn breaker(trip_after: u8) -> Breaker {
        Arc::new(tokio::sync::Mutex::new(BlockingBreaker::new(trip_after)))
    }

    async fn decided<P: Authorizer + Send + Sync + 'static>(
        breaker: &Breaker,
        authorizer: P,
        generation_moves: bool,
    ) -> ControlOutcome {
        decided_within(
            breaker,
            authorizer,
            generation_moves,
            Duration::from_secs(5),
        )
        .await
    }

    async fn decided_within<P: Authorizer + Send + Sync + 'static>(
        breaker: &Breaker,
        authorizer: P,
        generation_moves: bool,
        timeout: Duration,
    ) -> ControlOutcome {
        let live = live();
        let admitted = live.generation() + u64::from(generation_moves);
        decide_control(
            breaker,
            &Arc::new(authorizer),
            &live,
            poll(),
            admitted,
            timeout,
        )
        .await
    }

    fn deny(reason: &str) -> Verdict {
        Verdict::Deny {
            reason: reason.into(),
        }
    }

    #[test]
    fn the_control_plane_reads_control_frames_only() {
        let caps = control_request_caps();
        assert_eq!(
            (caps.control, caps.attempt, caps.prompt),
            (CONTROL_REQUEST_MAX, 0, 0)
        );
    }

    #[tokio::test]
    async fn an_open_breaker_is_unavailable() {
        assert_eq!(
            decided(&breaker(0), Fixed(deny("r"), None), false).await,
            ControlOutcome::Unavailable {
                reason: "authorization decision circuit breaker open",
                role: None
            }
        );
    }

    #[tokio::test]
    async fn an_exhausted_worker_budget_is_unavailable() {
        let b = breaker(3);
        for _ in 0..crate::blocking_guard::BLOCKING_BREAKER_MAX_IN_FLIGHT {
            b.lock().await.begin_attempt_at(Instant::now());
        }
        assert_eq!(
            decided(&b, Fixed(deny("r"), None), false).await,
            ControlOutcome::Unavailable {
                reason: "authorization decision blocking worker budget exhausted",
                role: None
            }
        );
    }

    #[tokio::test]
    async fn a_decision_past_its_timeout_is_unavailable() {
        let (release, waiting) = std::sync::mpsc::channel();
        let got = decided_within(
            &breaker(3),
            Waits(std::sync::Mutex::new(waiting)),
            false,
            Duration::from_millis(50),
        )
        .await;
        let _ = release.send(());
        assert_eq!(
            got,
            ControlOutcome::Unavailable {
                reason: "authorization decision timed out",
                role: None
            }
        );
    }

    #[tokio::test]
    async fn a_baseline_change_during_the_decision_is_unavailable() {
        assert_eq!(
            decided(&breaker(3), Fixed(deny("r"), Some("user")), true).await,
            ControlOutcome::Unavailable {
                reason: "the live baseline changed between admission and decision",
                role: Some("user")
            }
        );
    }

    #[tokio::test]
    async fn a_decided_deny_is_decided() {
        assert_eq!(
            decided(
                &breaker(3),
                Fixed(deny("sentinel-746"), Some("adversary")),
                false
            )
            .await,
            ControlOutcome::Decided {
                verdict: deny("sentinel-746"),
                role: Some("adversary"),
            }
        );
        let permit = Verdict::Permit {
            obligations: Vec::new(),
        };
        assert_eq!(
            decided(&breaker(3), Fixed(permit.clone(), Some("user")), false).await,
            ControlOutcome::Decided {
                verdict: permit,
                role: Some("user"),
            }
        );
    }

    #[tokio::test]
    async fn a_panicking_operand_is_decided_not_unavailable() {
        assert_eq!(
            decided(&breaker(3), Panics, false).await,
            ControlOutcome::Decided {
                verdict: deny("indeterminate operand blocks (fail-closed)"),
                role: None,
            }
        );
    }

    #[test]
    fn each_outcome_names_the_role_it_was_decided_on() {
        for role in [None, Some("user"), Some("adversary")] {
            assert_eq!(
                outcome_role(&ControlOutcome::Unavailable { reason: "r", role }),
                role
            );
            assert_eq!(
                outcome_role(&ControlOutcome::Decided {
                    verdict: deny("r"),
                    role
                }),
                role
            );
        }
    }

    #[test]
    fn an_undecided_poll_is_unavailable_and_a_decided_refusal_unauthorized() {
        assert_eq!(
            refusal_posture(&ControlOutcome::Unavailable {
                reason: "r",
                role: None
            }),
            "unavailable"
        );
        assert_eq!(
            refusal_posture(&ControlOutcome::Decided {
                verdict: deny("r"),
                role: Some("user")
            }),
            "unauthorized"
        );
    }

    #[test]
    fn each_outcome_names_its_reason() {
        let ob = |id: &str| maknae_security::Obligation {
            id: id.into(),
            params: Default::default(),
        };
        let of = |verdict| {
            outcome_reason(&ControlOutcome::Decided {
                verdict,
                role: None,
            })
        };
        assert_eq!(
            outcome_reason(&ControlOutcome::Unavailable {
                reason: "sentinel-746",
                role: None
            }),
            "sentinel-746"
        );
        assert_eq!(of(deny("sentinel-746-deny")), "sentinel-746-deny");
        assert_eq!(of(Verdict::Indeterminate), "indeterminate (fail-closed)");
        assert_eq!(
            of(Verdict::Permit {
                obligations: vec![ob("audit")]
            }),
            "authorized"
        );
        assert_eq!(
            of(Verdict::Permit {
                obligations: vec![ob("audit"), ob("notify")]
            }),
            "unhonorable obligation: notify"
        );
    }
}
