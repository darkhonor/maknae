//! `task_agent` (#609): gives a task to another agent under the task this agent is
//! working, and waits for its report or its end. Agent Daemon only; every request
//! carries the working task's cite, so each poll renews that task's lease.
use crate::hints::{choose, Links};
use crate::plane::{ReadBasis, TaskAgentOutcome, WriteOutcome};
use crate::task::TaskerFail;
use crate::task_driver::{Clock, TaskPlane};
use maknae_proto::{Binding, SecretText, TaskRef, TaskReportView, TaskState};
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

pub const POLL_FIRST: Duration = Duration::from_secs(5);
pub const POLL_MAX: Duration = Duration::from_secs(30);
pub const REPORTS_DIR: &str = "reports";
/// Consecutive unreachable collects retried before the wait ends.
pub const COLLECT_RETRIES: usize = 10;

/// The driver's clock and shutdown flag, for as long as the call waits.
pub struct Wait<'a, C> {
    pub clock: &'a mut C,
    pub shutdown: &'a AtomicBool,
}

/// `cwd` is the working task's partition, where the report is stored; `parent` is
/// the working task's bindings, the only ones the sub-task may carry.
pub async fn run<P: TaskPlane + Send, C: Clock + Send>(
    plane: &mut P,
    mut wait: Wait<'_, C>,
    cwd: &str,
    parent: &[Binding],
    conversation: &str,
    agent: &str,
    prompt: SecretText,
) -> TaskAgentOutcome {
    let forges = plane.forges();
    let bindings = choose(&[&Links], &prompt.0, forges.as_deref(), Some(parent)).bindings;
    let given = match plane.submit(agent, prompt, bindings).await {
        Ok(view) => view,
        Err(TaskerFail::Refused | TaskerFail::Unreachable { after_write: false }) => {
            return TaskAgentOutcome::NotAccepted
        }
        Err(TaskerFail::Unreachable { after_write: true } | TaskerFail::Protocol) => {
            return TaskAgentOutcome::OutcomeUnknown
        }
    };
    let (task, target) = (given.task, given.agent);
    let mut state = given.state;
    let mut every = POLL_FIRST;
    let mut lost = 0;
    loop {
        if !wait.idle(&mut every).await {
            plane.end_sub(&task, state == TaskState::Queued).await;
            return TaskAgentOutcome::WaitEnded;
        }
        match plane.sub_status(&task).await {
            Ok(view) => match view.state {
                TaskState::Queued | TaskState::Working => state = view.state,
                TaskState::Held => return TaskAgentOutcome::OnHold,
                TaskState::Reported => match entry(plane, &target, &task).await {
                    Ok(Some(entry)) => {
                        return reported(plane, &wait, cwd, conversation, &target, &task, entry)
                            .await
                    }
                    Ok(None) | Err(TaskerFail::Refused | TaskerFail::Protocol) => {
                        return TaskAgentOutcome::WaitEnded
                    }
                    Err(TaskerFail::Unreachable { .. }) if lost == COLLECT_RETRIES => {
                        return TaskAgentOutcome::WaitEnded
                    }
                    Err(TaskerFail::Unreachable { .. }) => lost += 1,
                },
                TaskState::Closed => {
                    let closed = view
                        .close
                        .map_or(TaskAgentOutcome::WaitEnded, TaskAgentOutcome::Closed);
                    match entry(plane, &target, &task).await {
                        Ok(Some(entry)) => {
                            let _ = plane.collect_one(&target, &task, Some(entry.cursor)).await;
                            return closed;
                        }
                        Ok(None) | Err(TaskerFail::Refused) => return closed,
                        Err(TaskerFail::Protocol) => return TaskAgentOutcome::WaitEnded,
                        Err(TaskerFail::Unreachable { .. }) if lost == COLLECT_RETRIES => {
                            return TaskAgentOutcome::WaitEnded
                        }
                        Err(TaskerFail::Unreachable { .. }) => lost += 1,
                    }
                }
            },
            Err(TaskerFail::Refused) => return TaskAgentOutcome::WaitEnded,
            Err(TaskerFail::Unreachable { .. } | TaskerFail::Protocol) => {}
        }
    }
}

impl<C: Clock> Wait<'_, C> {
    /// Sleeps one poll interval, the next one longer up to [`POLL_MAX`]; false once
    /// the daemon is shutting down.
    async fn idle(&mut self, every: &mut Duration) -> bool {
        if self.shutdown.load(Ordering::Acquire) {
            return false;
        }
        self.clock.sleep(*every).await;
        *every = (*every * 2).min(POLL_MAX);
        !self.shutdown.load(Ordering::Acquire)
    }
}

async fn entry<P: TaskPlane + Send>(
    plane: &mut P,
    agent: &str,
    task: &TaskRef,
) -> Result<Option<TaskReportView>, TaskerFail> {
    let page = plane.collect_one(agent, task, None).await?;
    Ok(page.entries.into_iter().find(|e| e.task == *task))
}

/// Stores the whole report under the partition, never over an existing file, and
/// acknowledges it only once stored; an unstored report stays with the kernel.
async fn reported<P: TaskPlane + Send, C: Clock>(
    plane: &mut P,
    wait: &Wait<'_, C>,
    cwd: &str,
    conversation: &str,
    agent: &str,
    task: &TaskRef,
    entry: TaskReportView,
) -> TaskAgentOutcome {
    let dir = format!("{cwd}/{REPORTS_DIR}");
    let path = format!("{dir}/{}.md", task.to_id());
    let made = matches!(
        plane.make_partition_dir(&dir).await,
        WriteOutcome::Applied(_)
    );
    let stored = made
        && !wait.shutdown.load(Ordering::Acquire)
        && matches!(
            plane
                .write(
                    conversation,
                    &path,
                    entry.text.0.as_bytes(),
                    ReadBasis::Unread
                )
                .await,
            WriteOutcome::Applied(_)
        );
    if stored {
        let _ = plane.collect_one(agent, task, Some(entry.cursor)).await;
    }
    TaskAgentOutcome::Report {
        agent: agent.to_string(),
        stored: stored.then_some(path),
        text: entry.text,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::plane::{
        DeleteOutcome, ListOutcome, MkdirOutcome, Plane, PlaneError, ReadBasis, ReadOutcome,
        StatOutcome, WriteOutcome,
    };
    use crate::task::{BeatAnswer, ClaimAnswer, ReportOutcome, TaskerFail};
    use crate::task_driver::{PersonaAt, Unverified};
    use maknae_proto::{
        Bytes, ConversationId, ConversationView, PromptReply, SignedTask, TaskClose, TaskCursor,
        TaskId, TaskRef, TaskReportPage, TaskReportView, TaskState, TaskView, Turn,
    };
    use std::collections::VecDeque;
    use std::future::Future;
    use std::path::Path;
    use std::sync::atomic::Ordering;
    use zeroize::Zeroizing;

    const CWD: &str = "/home/hobi/tasks/users/1000";
    const CONV: &str = "00112233445566778899aabbccddeeff";

    fn sub() -> TaskRef {
        TaskRef::from_id(&TaskId([0x51; 16]))
    }

    fn secret(s: &str) -> SecretText {
        SecretText(Zeroizing::new(s.into()))
    }

    fn view(state: TaskState, close: Option<TaskClose>) -> TaskView {
        TaskView {
            task: sub(),
            agent: "jin".into(),
            state,
            close,
            submitted_secs: 0,
            elapsed_secs: 0,
            actions: 0,
            last_action_secs: None,
            cursor: TaskCursor::from_seq(1),
            bindings: vec![],
        }
    }

    fn page(text: &str, close: Option<TaskClose>) -> TaskReportPage {
        TaskReportPage {
            entries: vec![TaskReportView {
                task: sub(),
                agent: "jin".into(),
                close,
                text: secret(text),
                at_secs: 0,
                cursor: TaskCursor::from_seq(7),
            }],
            next: None,
        }
    }

    struct Clocked {
        now: Duration,
        log: Vec<String>,
        stop_after: Option<usize>,
        shutdown: std::sync::Arc<AtomicBool>,
    }

    impl Clock for Clocked {
        fn now(&self) -> Duration {
            self.now
        }
        fn sleep(&mut self, d: Duration) -> impl Future<Output = ()> + Send {
            self.now += d;
            self.log.push(format!("sleep {}", d.as_secs()));
            let slept = self.log.len();
            if self.stop_after.is_some_and(|n| slept >= n) {
                self.shutdown.store(true, Ordering::Release);
            }
            std::future::ready(())
        }
    }

    #[derive(Default)]
    struct Fake {
        log: Vec<String>,
        cited: bool,
        submits: VecDeque<Result<TaskView, TaskerFail>>,
        polls: VecDeque<Result<TaskView, TaskerFail>>,
        collects: VecDeque<Result<TaskReportPage, TaskerFail>>,
        mkdir: Option<WriteOutcome>,
        write: Option<WriteOutcome>,
        written: Option<Zeroizing<Vec<u8>>>,
    }

    impl Fake {
        fn cite(&mut self, what: String) {
            let marked = if self.cited { "cited" } else { "uncited" };
            self.log.push(format!("{what} {marked}"));
        }
    }

    impl Plane for Fake {
        async fn open(&mut self, _: &Path, _: &[String]) -> Result<ConversationId, PlaneError> {
            unreachable!()
        }
        async fn close(&mut self, _: &ConversationId) -> Result<ConversationView, PlaneError> {
            unreachable!()
        }
        async fn prompt(&mut self, _: &str, _: &[Turn]) -> Result<PromptReply, PlaneError> {
            unreachable!()
        }
        async fn read(&mut self, _: &str, _: &str, _: maknae_proto::PageRequest) -> ReadOutcome {
            unreachable!()
        }
        async fn write(
            &mut self,
            conversation: &str,
            path: &str,
            content: &[u8],
            basis: ReadBasis,
        ) -> WriteOutcome {
            assert_eq!(conversation, CONV);
            assert_eq!(basis, ReadBasis::Unread, "never over an existing file");
            self.cite(format!("write {path} {}", content.len()));
            self.written = Some(Zeroizing::new(content.to_vec()));
            self.write.clone().unwrap_or(WriteOutcome::Applied(None))
        }
        async fn list(&mut self, _: &str, _: &str, _: Option<&str>) -> ListOutcome {
            unreachable!()
        }
        async fn stat(&mut self, _: &str, _: &str) -> StatOutcome {
            unreachable!()
        }
        async fn mkdir(&mut self, _: &str, _: &str) -> MkdirOutcome {
            unreachable!()
        }
        async fn delete(&mut self, _: &str, _: &str, _: bool) -> DeleteOutcome {
            unreachable!()
        }
    }

    impl TaskPlane for Fake {
        async fn claim(&mut self) -> Result<ClaimAnswer, String> {
            unreachable!()
        }
        async fn heartbeat(&mut self, _: u32) -> Result<BeatAnswer, String> {
            unreachable!()
        }
        async fn report(&mut self, _: SecretText, _: Option<u32>) -> Result<ReportOutcome, String> {
            unreachable!()
        }
        fn cite(&mut self, task: Option<TaskId>) {
            self.cited = task.is_some();
        }
        async fn make_partition_dir(&mut self, path: &str) -> WriteOutcome {
            self.cite(format!("mkdir {path}"));
            self.mkdir.clone().unwrap_or(WriteOutcome::Applied(None))
        }
        fn verify(&mut self, _: &Bytes) -> Result<SignedTask, Unverified> {
            unreachable!()
        }
        async fn persona(&mut self, _: PersonaAt<'_>) -> Result<Option<SecretText>, String> {
            unreachable!()
        }
        fn forges(&self) -> Option<Vec<crate::hints::Forge>> {
            None
        }
        async fn submit(
            &mut self,
            agent: &str,
            prompt: SecretText,
            _: Vec<maknae_proto::BindingRequest>,
        ) -> Result<TaskView, TaskerFail> {
            self.cite(format!("submit {agent} {}", *prompt.0));
            self.submits.pop_front().expect("a scripted submit")
        }
        async fn sub_status(&mut self, task: &TaskRef) -> Result<TaskView, TaskerFail> {
            assert_eq!(*task, sub());
            self.cite("status".into());
            self.polls.pop_front().expect("a scripted poll")
        }
        async fn collect_one(
            &mut self,
            agent: &str,
            task: &TaskRef,
            after: Option<TaskCursor>,
        ) -> Result<TaskReportPage, TaskerFail> {
            assert_eq!((agent, task), ("jin", &sub()));
            match after {
                None => {
                    self.cite("collect".into());
                    self.collects.pop_front().expect("a scripted collect")
                }
                Some(c) => {
                    self.cite(format!("ack {}", c.seq()));
                    Ok(TaskReportPage {
                        entries: Vec::new(),
                        next: None,
                    })
                }
            }
        }
        async fn end_sub(&mut self, task: &TaskRef, queued: bool) {
            assert_eq!(*task, sub());
            self.cite(if queued { "drop".into() } else { "stop".into() });
        }
    }

    fn fake() -> Fake {
        Fake {
            cited: true,
            submits: [Ok(view(TaskState::Queued, None))].into(),
            ..Fake::default()
        }
    }

    struct Ran {
        got: TaskAgentOutcome,
        log: Vec<String>,
        sleeps: Vec<String>,
        written: Option<Zeroizing<Vec<u8>>>,
    }

    async fn ran(mut plane: Fake, stop_after: Option<usize>) -> Ran {
        let shutdown = std::sync::Arc::new(AtomicBool::new(false));
        let mut clock = Clocked {
            now: Duration::ZERO,
            log: Vec::new(),
            stop_after,
            shutdown: std::sync::Arc::clone(&shutdown),
        };
        let got = run(
            &mut plane,
            Wait {
                clock: &mut clock,
                shutdown: &shutdown,
            },
            CWD,
            &[],
            CONV,
            "jin",
            secret("sentinel-609-prompt"),
        )
        .await;
        Ran {
            got,
            log: plane.log,
            sleeps: clock.log,
            written: plane.written,
        }
    }

    const PATH: &str = "/home/hobi/tasks/users/1000/reports/51515151515151515151515151515151.md";

    #[tokio::test]
    async fn a_report_is_stored_whole_then_acknowledged_alone_and_its_head_returned() {
        let mut p = fake();
        p.polls = [
            Ok(view(TaskState::Queued, None)),
            Ok(view(TaskState::Working, None)),
            Ok(view(TaskState::Reported, None)),
        ]
        .into();
        p.collects = [Ok(page("sentinel-609-report", None))].into();
        let r = ran(p, None).await;
        assert_eq!(
            r.got,
            TaskAgentOutcome::Report {
                agent: "jin".into(),
                stored: Some(PATH.into()),
                text: secret("sentinel-609-report"),
            }
        );
        let dir = "/home/hobi/tasks/users/1000/reports";
        assert_eq!(
            r.log,
            [
                "submit jin sentinel-609-prompt cited".to_string(),
                "status cited".into(),
                "status cited".into(),
                "status cited".into(),
                "collect cited".into(),
                format!("mkdir {dir} cited"),
                format!("write {PATH} 19 cited"),
                "ack 7 cited".into(),
            ]
        );
        assert_eq!(r.sleeps, ["sleep 5", "sleep 10", "sleep 20"]);
    }

    #[tokio::test]
    async fn a_one_mebibyte_report_is_written_whole_and_its_head_cut_on_a_character() {
        let big = format!("{}é{}", "x".repeat(4095), "x".repeat(1 << 20));
        let mut p = fake();
        p.polls = [Ok(view(TaskState::Reported, None))].into();
        p.collects = [Ok(page(&big, None))].into();
        let r = ran(p, None).await;
        assert_eq!(r.written.as_deref().map(|w| w.len()), Some(big.len()));
        assert_eq!(
            r.written.as_deref().map(Vec::as_slice),
            Some(big.as_bytes())
        );
        let ack = r.log.iter().position(|l| l.starts_with("ack")).unwrap();
        let write = r.log.iter().position(|l| l.starts_with("write")).unwrap();
        assert!(
            write < ack,
            "acknowledged only after the write: {:?}",
            r.log
        );
        let text = crate::render::render(&crate::render::ToolOutcome::TaskAgent(r.got), 3);
        assert!(text.starts_with(&format!(
            "Report from agent jin (shown up to 4096 bytes; all of it is in {PATH}):\nxx"
        )));
        assert!(
            text.ends_with("x\n[cut here — read the rest with read_file]\n\nsteps remaining: 3")
        );
        let head = text.split('\n').nth(1).unwrap();
        assert_eq!(
            head.len(),
            4095,
            "cut before the 4096th byte, inside no character"
        );
    }

    #[tokio::test]
    async fn a_refused_write_is_not_acknowledged() {
        for (mkdir, write) in [
            (Some(WriteOutcome::Unavailable), None),
            (None, Some(WriteOutcome::Stale)),
            (None, Some(WriteOutcome::Unknown)),
        ] {
            let mut p = fake();
            p.polls = [Ok(view(TaskState::Reported, None))].into();
            p.collects = [Ok(page(&"y".repeat(5000), None))].into();
            p.mkdir = mkdir;
            p.write = write;
            let r = ran(p, None).await;
            assert!(!r.log.iter().any(|l| l.starts_with("ack")), "{:?}", r.log);
            let TaskAgentOutcome::Report { stored: None, .. } = &r.got else {
                panic!("{:?}", r.got);
            };
            let text = crate::render::render(&crate::render::ToolOutcome::TaskAgent(r.got), 1);
            assert!(text.starts_with("Report from agent jin (shown up to 4096 bytes):\n"));
            assert!(text.ends_with(
                "\n[cut here — the rest of the report could not be stored and is not shown]\n\nsteps remaining: 1"
            ));
        }
    }

    fn arms() -> [(TaskState, Option<TaskClose>, TaskAgentOutcome); 2] {
        [
            (
                TaskState::Reported,
                None,
                TaskAgentOutcome::Report {
                    agent: "jin".into(),
                    stored: Some(PATH.into()),
                    text: secret("sentinel-609-late"),
                },
            ),
            (
                TaskState::Closed,
                Some(TaskClose::Stopped),
                TaskAgentOutcome::Closed(TaskClose::Stopped),
            ),
        ]
    }

    fn scripted(state: TaskState, close: Option<TaskClose>, lost: usize, then: bool) -> Fake {
        let mut p = fake();
        p.polls = std::iter::repeat_with(|| Ok(view(state, close)))
            .take(lost + 1)
            .collect();
        p.collects = std::iter::repeat_with(|| Err(TaskerFail::Unreachable { after_write: true }))
            .take(lost)
            .collect();
        if then {
            let text = if close.is_some() {
                ""
            } else {
                "sentinel-609-late"
            };
            p.collects.push_back(Ok(page(text, close)));
        }
        p
    }

    fn collects(log: &[String]) -> usize {
        log.iter().filter(|l| l.starts_with("collect")).count()
    }

    #[tokio::test]
    async fn a_lost_collect_is_polled_again_up_to_its_bound() {
        for (state, close, arrived) in arms() {
            let r = ran(scripted(state, close, COLLECT_RETRIES, true), None).await;
            assert_eq!(r.got, arrived, "{state:?}");
            assert_eq!(collects(&r.log), COLLECT_RETRIES + 1, "{state:?}");
            let r = ran(scripted(state, close, COLLECT_RETRIES + 1, false), None).await;
            assert_eq!(r.got, TaskAgentOutcome::WaitEnded, "{state:?}");
            assert_eq!(collects(&r.log), COLLECT_RETRIES + 1, "{state:?}");
        }
    }

    #[tokio::test]
    async fn a_collect_answered_with_a_protocol_failure_ends_the_wait() {
        for (state, close, _) in arms() {
            let mut p = fake();
            p.polls = [Ok(view(state, close))].into();
            p.collects = [Err(TaskerFail::Protocol)].into();
            let r = ran(p, None).await;
            assert_eq!(r.got, TaskAgentOutcome::WaitEnded, "{state:?}");
            assert_eq!(collects(&r.log), 1, "{state:?}");
        }
    }

    #[tokio::test]
    async fn a_close_is_acknowledged_alone_and_answered_with_its_fixed_text() {
        for (close, said) in [
            (TaskClose::Stopped, "stopped"),
            (TaskClose::Dropped, "dropped"),
            (TaskClose::AgentGone, "the agent was removed"),
            (TaskClose::AgentLost, "the agent stopped responding"),
            (TaskClose::Withdrawn, "withdrawn"),
        ] {
            let mut p = fake();
            p.polls = [Ok(view(TaskState::Closed, Some(close)))].into();
            p.collects = [Ok(page("", Some(close)))].into();
            let r = ran(p, None).await;
            assert_eq!(r.got, TaskAgentOutcome::Closed(close));
            assert_eq!(
                r.log[1..],
                ["status cited", "collect cited", "ack 7 cited"],
                "{close:?}"
            );
            let text = crate::render::render(&crate::render::ToolOutcome::TaskAgent(r.got), 0);
            assert_eq!(text.as_str(), format!("{said}\n\nsteps remaining: 0"));
        }
    }

    #[tokio::test]
    async fn a_held_sub_task_or_a_refused_poll_ends_the_wait_with_its_fixed_text() {
        let mut p = fake();
        p.polls = [Ok(view(TaskState::Held, None))].into();
        let r = ran(p, None).await;
        assert_eq!(r.got, TaskAgentOutcome::OnHold);
        let mut p = fake();
        p.polls = [Ok(view(TaskState::Working, None)), Err(TaskerFail::Refused)].into();
        let r = ran(p, None).await;
        assert_eq!(r.got, TaskAgentOutcome::WaitEnded);
        assert!(!r
            .log
            .iter()
            .any(|l| l.starts_with("stop") || l.starts_with("drop")));
    }

    #[tokio::test]
    async fn an_unreachable_kernel_is_polled_again_and_every_poll_is_cited() {
        let mut p = fake();
        let lost = Err(TaskerFail::Unreachable { after_write: true });
        let mut polls: VecDeque<_> = std::iter::repeat_with(|| lost.clone()).take(12).collect();
        polls.push_back(Ok(view(TaskState::Closed, Some(TaskClose::Stopped))));
        p.polls = polls;
        p.collects = [Ok(page("", Some(TaskClose::Stopped)))].into();
        let r = ran(p, None).await;
        assert_eq!(r.got, TaskAgentOutcome::Closed(TaskClose::Stopped));
        let polls: Vec<_> = r.log.iter().filter(|l| l.starts_with("status")).collect();
        assert_eq!(polls.len(), 13);
        assert!(r.log.iter().all(|l| l.ends_with(" cited")), "{:?}", r.log);
        assert_eq!(
            r.sleeps[..5],
            ["sleep 5", "sleep 10", "sleep 20", "sleep 30", "sleep 30"]
        );
        assert!(r.sleeps.iter().all(|s| s != "sleep 0"));
    }

    #[tokio::test]
    async fn a_submit_refused_or_lost_answers_without_waiting() {
        for (fail, want) in [
            (TaskerFail::Refused, TaskAgentOutcome::NotAccepted),
            (
                TaskerFail::Unreachable { after_write: false },
                TaskAgentOutcome::NotAccepted,
            ),
            (
                TaskerFail::Unreachable { after_write: true },
                TaskAgentOutcome::OutcomeUnknown,
            ),
            (TaskerFail::Protocol, TaskAgentOutcome::OutcomeUnknown),
        ] {
            let mut p = fake();
            p.submits = [Err(fail)].into();
            let r = ran(p, None).await;
            assert_eq!(r.got, want, "{fail:?}");
            assert_eq!(r.log.len(), 1);
            assert!(r.sleeps.is_empty());
        }
    }

    #[tokio::test]
    async fn shutdown_stops_a_working_sub_task_and_drops_a_queued_one() {
        for (state, sent) in [
            (TaskState::Working, "stop cited"),
            (TaskState::Queued, "drop cited"),
        ] {
            let mut p = fake();
            p.polls = [Ok(view(state, None))].into();
            let r = ran(p, Some(2)).await;
            assert_eq!(r.got, TaskAgentOutcome::WaitEnded);
            assert_eq!(r.log.last().map(String::as_str), Some(sent), "{:?}", r.log);
        }
    }

    #[test]
    fn the_outcome_never_prints_the_report() {
        let got = TaskAgentOutcome::Report {
            agent: "jin".into(),
            stored: None,
            text: secret("sentinel-609-debug"),
        };
        for shown in [
            format!("{got:?}"),
            format!("{:?}", crate::render::ToolOutcome::TaskAgent(got.clone())),
        ] {
            assert!(!shown.contains("sentinel-609-debug"), "{shown}");
        }
    }
}
