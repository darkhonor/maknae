//! The agent's control-channel poller (#746): one notice poll every
//! [`NOTICE_POLL_EVERY`], in every state. A `Stop` halts only the task it names; a
//! refused poll halts whatever is worked; every other failure halts nothing.
use crate::halt::HaltSender;
use crate::task_driver::Clock;
use maknae_proto::{AgentNotice, ControlResponse, Notice, ProtoErrCode};
use std::future::Future;
use std::time::Duration;

pub const NOTICE_POLL_EVERY: Duration = Duration::from_secs(5);

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PollFailure {
    Dial,
    Handshake,
    Timeout,
    Write,
    Undecodable,
    Code(ProtoErrCode),
}

impl PollFailure {
    pub fn class(&self) -> &'static str {
        match self {
            PollFailure::Dial => "dial",
            PollFailure::Handshake => "handshake",
            PollFailure::Timeout => "timeout",
            PollFailure::Write => "write",
            PollFailure::Undecodable => "undecodable",
            PollFailure::Code(_) => "refused-other",
        }
    }
}

#[derive(Clone, Debug, PartialEq)]
pub enum PollAnswer {
    Notices(Vec<Notice<AgentNotice>>),
    Refused,
    Failed(PollFailure),
}

pub fn read_reply(reply: ControlResponse<AgentNotice>) -> PollAnswer {
    match reply.result {
        Ok(notices) => PollAnswer::Notices(notices),
        Err(e) => match e.code {
            ProtoErrCode::Unauthorized => PollAnswer::Refused,
            code @ (ProtoErrCode::UnknownVerb
            | ProtoErrCode::BadRequest
            | ProtoErrCode::Internal
            | ProtoErrCode::TooLarge
            | ProtoErrCode::NotImplemented
            | ProtoErrCode::ReplyUnusable(_)
            | ProtoErrCode::BoardRefused(_)
            | ProtoErrCode::EgressUnavailable
            | ProtoErrCode::Protected) => PollAnswer::Failed(PollFailure::Code(code)),
        },
    }
}

/// How often a failure or refusal of an unchanged class is logged again while it persists.
pub const FAILURE_LOG_EVERY: Duration = Duration::from_secs(60);

/// The poller's log: a failure class or a refusal when it starts or changes, again at most
/// once per [`FAILURE_LOG_EVERY`] while it persists, and a notices answer after either once.
#[derive(Debug, Default)]
pub struct PollLog {
    failing: Option<(&'static str, Duration)>,
}

impl PollLog {
    pub fn observe(&mut self, now: Duration, answer: &PollAnswer) -> Option<String> {
        let class = match answer {
            PollAnswer::Notices(_) => {
                return self.failing.take().map(|_| "notice poll recovered".into());
            }
            PollAnswer::Refused => "refused",
            PollAnswer::Failed(f) => f.class(),
        };
        if let Some((was, at)) = self.failing {
            if was == class && now.saturating_sub(at) < FAILURE_LOG_EVERY {
                return None;
            }
        }
        self.failing = Some((class, now));
        Some(match answer {
            PollAnswer::Refused => "notice poll refused: ceasing work".into(),
            PollAnswer::Notices(_) | PollAnswer::Failed(_) => {
                format!("notice poll failed: {class}")
            }
        })
    }
}

pub trait ControlPlane {
    fn notice_poll(&mut self) -> impl Future<Output = PollAnswer> + Send;
}

pub async fn poll_notices<CP: ControlPlane, C: Clock>(
    plane: &mut CP,
    clock: &mut C,
    halts: &HaltSender,
    log: &mut (impl FnMut(String) + Send),
) {
    let mut said = PollLog::default();
    loop {
        let mark = halts.mark();
        let answer = plane.notice_poll().await;
        if let Some(line) = said.observe(clock.now(), &answer) {
            log(line);
        }
        match answer {
            PollAnswer::Notices(notices) => {
                for n in notices {
                    match n.body {
                        AgentNotice::Stop => {
                            if let Some(task) = n.task {
                                halts.stop(task, mark);
                            }
                        }
                    }
                }
            }
            PollAnswer::Refused => {
                halts.refused(mark);
            }
            PollAnswer::Failed(_) => {}
        }
        clock.sleep(NOTICE_POLL_EVERY).await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::halt::{halts, Halt, Until};
    use crate::task_driver::POLL_EVERY;
    use maknae_proto::{BoardDefect, NoticeId, ProtoError, ReplyDefect, TaskId, PROTOCOL_VERSION};
    use std::collections::VecDeque;
    use std::pin::{pin, Pin};
    use std::sync::{Arc, Mutex};
    use std::task::{Context, Poll, Waker};

    type Log = Arc<Mutex<Vec<String>>>;

    fn id(n: u8) -> TaskId {
        TaskId([n; 16])
    }

    fn stop(task: Option<TaskId>) -> Notice<AgentNotice> {
        Notice {
            id: NoticeId([0x46; 16]),
            task,
            body: AgentNotice::Stop,
        }
    }

    /// Answers each poll with the next scripted answer, then never answers again.
    struct Script {
        answers: VecDeque<PollAnswer>,
        log: Log,
    }

    impl ControlPlane for Script {
        fn notice_poll(&mut self) -> impl Future<Output = PollAnswer> + Send {
            self.log.lock().unwrap().push("poll".into());
            let next = self.answers.pop_front();
            async move {
                match next {
                    Some(answer) => answer,
                    None => std::future::pending().await,
                }
            }
        }
    }

    struct FakeClock {
        now: Duration,
        log: Log,
    }

    impl Clock for FakeClock {
        fn now(&self) -> Duration {
            self.now
        }
        fn sleep(&mut self, d: Duration) -> impl Future<Output = ()> + Send {
            self.now += d;
            self.log
                .lock()
                .unwrap()
                .push(format!("sleep {}ms", d.as_millis()));
            std::future::ready(())
        }
    }

    fn run(answers: Vec<PollAnswer>, sender: &HaltSender) -> Vec<String> {
        let log = Log::default();
        let mut plane = Script {
            answers: answers.into(),
            log: Arc::clone(&log),
        };
        let mut clock = FakeClock {
            now: Duration::ZERO,
            log: Arc::clone(&log),
        };
        let lines = Arc::clone(&log);
        let mut said = move |line: String| lines.lock().unwrap().push(line);
        {
            let mut cx = Context::from_waker(Waker::noop());
            let polling = pin!(poll_notices(&mut plane, &mut clock, sender, &mut said));
            assert!(polling.poll(&mut cx).is_pending(), "the poller returned");
        }
        let got = log.lock().unwrap().clone();
        got
    }

    fn pending(w: &mut Until<'_>) -> bool {
        let mut cx = Context::from_waker(Waker::noop());
        Pin::new(w).poll(&mut cx).is_pending()
    }

    fn taken(mut w: Until<'_>) -> Poll<Halt> {
        let mut cx = Context::from_waker(Waker::noop());
        Pin::new(&mut w).poll(&mut cx)
    }

    fn every_code() -> Vec<ProtoErrCode> {
        let all = vec![
            ProtoErrCode::UnknownVerb,
            ProtoErrCode::Unauthorized,
            ProtoErrCode::BadRequest,
            ProtoErrCode::Internal,
            ProtoErrCode::TooLarge,
            ProtoErrCode::NotImplemented,
            ProtoErrCode::ReplyUnusable(ReplyDefect::Malformed),
            ProtoErrCode::BoardRefused(BoardDefect::Full),
            ProtoErrCode::EgressUnavailable,
            ProtoErrCode::Protected,
        ];
        for code in &all {
            match code {
                ProtoErrCode::UnknownVerb
                | ProtoErrCode::Unauthorized
                | ProtoErrCode::BadRequest
                | ProtoErrCode::Internal
                | ProtoErrCode::TooLarge
                | ProtoErrCode::NotImplemented
                | ProtoErrCode::ReplyUnusable(_)
                | ProtoErrCode::BoardRefused(_)
                | ProtoErrCode::EgressUnavailable
                | ProtoErrCode::Protected => {}
            }
        }
        all
    }

    #[test]
    fn notice_poll_every_equals_the_claim_poll() {
        assert_eq!(NOTICE_POLL_EVERY, POLL_EVERY);
        assert_eq!(NOTICE_POLL_EVERY, Duration::from_secs(5));
    }

    #[test]
    fn a_stop_notice_halts_its_task() {
        let (sender, halts) = halts();
        let w = halts.until(id(1));
        let log = run(
            vec![PollAnswer::Notices(vec![
                stop(Some(id(2))),
                stop(Some(id(1))),
            ])],
            &sender,
        );
        assert_eq!(log, ["poll", "sleep 5000ms", "poll"]);
        assert_eq!(taken(w), Poll::Ready(Halt::Stop));
    }

    #[test]
    fn a_stop_without_a_task_halts_nothing() {
        let (sender, halts) = halts();
        let mut w = halts.until(id(1));
        let log = run(vec![PollAnswer::Notices(vec![stop(None)])], &sender);
        assert_eq!(log, ["poll", "sleep 5000ms", "poll"]);
        assert!(pending(&mut w));
        assert!(sender.stop(id(1), sender.mark()), "the wait is still live");
    }

    #[test]
    fn a_stop_for_another_task_halts_nothing() {
        let (sender, halts) = halts();
        let mut w = halts.until(id(1));
        run(vec![PollAnswer::Notices(vec![stop(Some(id(2)))])], &sender);
        assert!(pending(&mut w));
    }

    #[test]
    fn a_refused_poll_halts_whatever_is_worked() {
        for n in [1, 7] {
            let (sender, halts) = halts();
            let w = halts.until(id(n));
            let log = run(vec![PollAnswer::Refused], &sender);
            assert_eq!(
                log,
                [
                    "poll",
                    "notice poll refused: ceasing work",
                    "sleep 5000ms",
                    "poll"
                ]
            );
            assert_eq!(taken(w), Poll::Ready(Halt::Refused));
        }
    }

    #[test]
    fn a_failed_poll_halts_nothing_and_polls_again_next_tick() {
        let failures = [
            PollFailure::Dial,
            PollFailure::Handshake,
            PollFailure::Timeout,
            PollFailure::Write,
            PollFailure::Undecodable,
            PollFailure::Code(ProtoErrCode::Internal),
        ];
        for f in failures {
            let (sender, halts) = halts();
            let mut w = halts.until(id(1));
            let log = run(vec![PollAnswer::Failed(f.clone())], &sender);
            assert_eq!(
                log,
                [
                    "poll".to_string(),
                    format!("notice poll failed: {}", f.class()),
                    "sleep 5000ms".into(),
                    "poll".into()
                ],
                "{f:?}"
            );
            assert!(pending(&mut w), "{f:?}");
        }
    }

    #[test]
    fn the_poller_sleeps_the_poll_interval_between_polls() {
        let (sender, _halts) = halts();
        let log = run(
            vec![
                PollAnswer::Notices(vec![]),
                PollAnswer::Refused,
                PollAnswer::Failed(PollFailure::Dial),
                PollAnswer::Notices(vec![stop(Some(id(3)))]),
            ],
            &sender,
        );
        let sleeps: Vec<_> = log.iter().filter(|l| l.starts_with("sleep")).collect();
        assert_eq!(sleeps, ["sleep 5000ms"; 4]);
        assert_eq!(log.iter().filter(|l| *l == "poll").count(), 5);
    }

    #[test]
    fn a_halt_reaches_only_a_wait_registered_before_its_poll_was_sent() {
        let (sender, halts) = halts();
        struct Late<'a> {
            halts: &'a crate::halt::Halts,
            wait: Option<Until<'a>>,
        }
        impl ControlPlane for Late<'_> {
            fn notice_poll(&mut self) -> impl Future<Output = PollAnswer> + Send {
                let answer = match self.wait {
                    None => {
                        self.wait = Some(self.halts.until(id(1)));
                        Some(PollAnswer::Notices(vec![stop(Some(id(1)))]))
                    }
                    Some(_) => None,
                };
                async move {
                    match answer {
                        Some(a) => a,
                        None => std::future::pending().await,
                    }
                }
            }
        }
        let mut plane = Late {
            halts: &halts,
            wait: None,
        };
        let mut clock = FakeClock {
            now: Duration::ZERO,
            log: Log::default(),
        };
        let mut ignore = |_| {};
        {
            let mut cx = Context::from_waker(Waker::noop());
            let polling = pin!(poll_notices(&mut plane, &mut clock, &sender, &mut ignore));
            assert!(polling.poll(&mut cx).is_pending());
        }
        let mut w = plane.wait.take().unwrap();
        assert!(
            pending(&mut w),
            "a Stop read by an earlier poll halted a later wait"
        );
    }

    #[test]
    fn an_unauthorized_reply_is_refused_and_any_other_code_is_failed() {
        for code in every_code() {
            let reply = ControlResponse::<AgentNotice> {
                protocol_version: PROTOCOL_VERSION,
                result: Err(ProtoError {
                    code: code.clone(),
                    message: "sentinel-746-refused".into(),
                }),
            };
            let want = match code {
                ProtoErrCode::Unauthorized => PollAnswer::Refused,
                ref other => PollAnswer::Failed(PollFailure::Code(other.clone())),
            };
            assert_eq!(read_reply(reply), want, "{code:?}");
        }
    }

    #[test]
    fn a_notices_reply_is_its_notices() {
        let notices = vec![stop(Some(id(4))), stop(None)];
        let reply = ControlResponse::<AgentNotice> {
            protocol_version: PROTOCOL_VERSION,
            result: Ok(notices.clone()),
        };
        assert_eq!(read_reply(reply), PollAnswer::Notices(notices));
    }

    #[test]
    fn a_failure_is_logged_on_a_class_change_then_once_a_minute_and_its_recovery_once() {
        let at = Duration::from_secs;
        let failed = |f: PollFailure| PollAnswer::Failed(f);
        let ok = || PollAnswer::Notices(vec![]);
        let mut log = PollLog::default();
        let mut seen = |now: Duration, a: PollAnswer| log.observe(now, &a);
        assert_eq!(seen(at(0), ok()), None);
        assert_eq!(
            seen(at(5), failed(PollFailure::Dial)).as_deref(),
            Some("notice poll failed: dial")
        );
        assert_eq!(seen(at(10), failed(PollFailure::Dial)), None);
        assert_eq!(seen(at(64), failed(PollFailure::Dial)), None);
        assert_eq!(
            seen(at(65), failed(PollFailure::Dial)).as_deref(),
            Some("notice poll failed: dial")
        );
        assert_eq!(seen(at(70), failed(PollFailure::Dial)), None);
        assert_eq!(
            seen(at(75), failed(PollFailure::Timeout)).as_deref(),
            Some("notice poll failed: timeout")
        );
        assert_eq!(seen(at(80), failed(PollFailure::Timeout)), None);
        assert_eq!(seen(at(85), ok()).as_deref(), Some("notice poll recovered"));
        assert_eq!(seen(at(90), ok()), None);
        assert_eq!(
            seen(at(95), failed(PollFailure::Timeout)).as_deref(),
            Some("notice poll failed: timeout")
        );
    }

    #[test]
    fn a_refusal_is_its_own_line_logged_like_a_failure_class() {
        let at = Duration::from_secs;
        let mut log = PollLog::default();
        let mut seen = |now: Duration, a: PollAnswer| log.observe(now, &a);
        let refused = "notice poll refused: ceasing work";
        assert_eq!(seen(at(0), PollAnswer::Refused).as_deref(), Some(refused));
        assert_eq!(seen(at(5), PollAnswer::Refused), None);
        assert_eq!(seen(at(60), PollAnswer::Refused).as_deref(), Some(refused));
        assert_eq!(
            seen(at(65), PollAnswer::Failed(PollFailure::Dial)).as_deref(),
            Some("notice poll failed: dial")
        );
        assert_eq!(seen(at(70), PollAnswer::Refused).as_deref(), Some(refused));
        assert_eq!(
            seen(at(75), PollAnswer::Notices(vec![])).as_deref(),
            Some("notice poll recovered")
        );
    }

    #[test]
    fn the_poller_logs_a_persisting_failure_once_then_the_refusal_then_the_recovery() {
        let (sender, _halts) = halts();
        let mut answers = vec![PollAnswer::Failed(PollFailure::Dial); 3];
        answers.push(PollAnswer::Refused);
        answers.push(PollAnswer::Notices(vec![]));
        let log = run(answers, &sender);
        let said: Vec<_> = log
            .iter()
            .filter(|l| l.starts_with("notice poll"))
            .collect();
        assert_eq!(
            said,
            [
                "notice poll failed: dial",
                "notice poll refused: ceasing work",
                "notice poll recovered"
            ]
        );
    }

    #[test]
    fn each_failure_names_its_class() {
        let got: Vec<_> = [
            PollFailure::Dial,
            PollFailure::Handshake,
            PollFailure::Timeout,
            PollFailure::Write,
            PollFailure::Undecodable,
            PollFailure::Code(ProtoErrCode::Internal),
        ]
        .iter()
        .map(PollFailure::class)
        .collect();
        assert_eq!(
            got,
            [
                "dial",
                "handshake",
                "timeout",
                "write",
                "undecodable",
                "refused-other"
            ]
        );
    }
}
