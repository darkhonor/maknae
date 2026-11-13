//! The agent's task driver (#629): claims kernel-signed tasks, works each through
//! the loop inside its tasker's partition, and ends every one with a report or with
//! the kernel's own answer that the task is no longer this agent's to report.
//! Pure: every effect goes through [`TaskPlane`] and [`Clock`].
use crate::budget::ContextBudget;
use crate::drive::{Budget, LoopEvent, StepControl, StepHook, StopReason};
use crate::plane::{Plane, PlaneError, WriteOutcome};
use crate::session::Session;
use crate::task::{BeatAnswer, ClaimAnswer, ReportOutcome};
use crate::transcript::Transcript;
use maknae_proto::{Ask, Bytes, SecretText, SignedTask, TaskId, TaskState};
use std::future::Future;
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;
use zeroize::Zeroizing;

pub const POLL_EVERY: Duration = Duration::from_secs(5);
/// A third of the kernel's `CLAIM_LEASE`.
pub const HEARTBEAT_EVERY: Duration = Duration::from_secs(5 * 60);
/// The kernel's `CLAIM_LEASE + TASK_SWEEP_EVERY + 30 s`.
pub const UNDECODABLE_WAIT: Duration = Duration::from_secs(990);
pub const BACKOFF_FIRST: Duration = Duration::from_secs(1);
pub const BACKOFF_MAX: Duration = Duration::from_secs(60);

pub const RESTARTED: &str = "stopped: agent restarted";
pub const TOO_LARGE: &str = "report too large";
pub const REPORT_REFUSED: &str = "report refused";
/// Resumes after a lost connection, per task, before it is reported `stopped: transport`.
pub const MAX_RESUMES: u32 = 3;
pub const PARTITION_UNAVAILABLE: &str = "partition-unavailable";
pub const PERSONA_UNAVAILABLE: &str = "persona-unavailable";
pub const SESSION_UNAVAILABLE: &str = "session-unavailable";

/// Total over `maknae_vault::task_sig::TaskSignatureError`; the mapping is
/// `maknae_loop::task::verify_class`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VerifyClass {
    Agent,
    Algorithm,
    NotKernel,
    Key,
    Signature,
    Encoding,
}

impl VerifyClass {
    pub fn as_str(self) -> &'static str {
        match self {
            VerifyClass::Agent => "agent",
            VerifyClass::Algorithm => "algorithm",
            VerifyClass::NotKernel => "not-kernel",
            VerifyClass::Key => "key",
            VerifyClass::Signature => "signature",
            VerifyClass::Encoding => "encoding",
        }
    }
}

/// The fixed refusal report. The task's own text is never echoed.
pub fn refusal_report(class: VerifyClass) -> String {
    format!(
        "refused: this task's kernel signature did not verify ({})",
        class.as_str()
    )
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Unverified {
    /// `TaskDelivery.signed` is not a `SignedTask`: there is no id to cite.
    Undecodable,
    Failed {
        task: TaskId,
        class: VerifyClass,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PersonaAt<'a> {
    /// `/etc/maknae/agents/<id>/persona.md`.
    Etc,
    /// `<home>/persona.md`.
    Home,
    /// `<home>/<partition>/persona.md`, for the task being started only.
    Partition(&'a str),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PersonaMode {
    Admin,
    Own,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Ending {
    Answered,
    Unverified(VerifyClass),
    Undecodable,
    /// The class of a fixed, content-free `stopped:` report.
    Stopped(&'static str),
    Held,
    Gone,
    Restarted,
    Shutdown,
    /// Not even the fixed report fits a request frame: left to lapse, as `Undecodable` is.
    Unsendable,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DriverEvent {
    Ended {
        task: Option<TaskId>,
        ending: Ending,
    },
    Loop(LoopEvent),
    CloseFailed(PlaneError),
}

pub trait Clock {
    /// Monotonic.
    fn now(&self) -> Duration;
    fn sleep(&mut self, d: Duration) -> impl Future<Output = ()> + Send;
}

/// Claims and heartbeats are never cited; every other request carries the cite.
pub trait TaskPlane: Plane {
    fn claim(&mut self) -> impl Future<Output = Result<ClaimAnswer, String>> + Send;
    fn heartbeat(&mut self, seen: u32) -> impl Future<Output = Result<BeatAnswer, String>> + Send;
    fn report(
        &mut self,
        text: SecretText,
    ) -> impl Future<Output = Result<ReportOutcome, String>> + Send;
    fn cite(&mut self, task: Option<TaskId>);
    /// Creates mode 0700. An existing directory is `Applied`.
    fn mkdir(&mut self, path: &str, parents: bool) -> impl Future<Output = WriteOutcome> + Send;
    fn verify(&mut self, signed: &Bytes) -> Result<SignedTask, Unverified>;
    fn persona(&mut self, at: PersonaAt<'_>) -> Result<Option<SecretText>, String>;
    fn note(&mut self, _event: DriverEvent) {}
}

#[derive(Debug, Clone)]
pub struct DriverConfig {
    /// The agent's home: absolute, canonical, no trailing `/`.
    pub home: String,
    pub persona: PersonaMode,
    pub budget: Budget,
    pub context: ContextBudget,
}

#[derive(Clone)]
pub struct ShutdownHandle(Arc<AtomicBool>);

impl ShutdownHandle {
    pub fn shut_down(&self) {
        self.0.store(true, Ordering::Release);
    }
}

struct Held {
    id: TaskId,
    session: Session,
    seen: u32,
    last_beat: Duration,
    answer: Option<String>,
    resumes: u32,
}

enum Beat {
    /// The task is still `Working`; the items not yet seen, possibly none.
    More(Vec<SecretText>),
    Held,
    Gone,
    Refused,
    Lost,
}

fn read_beat(answer: Result<BeatAnswer, String>, seen: &mut u32) -> Beat {
    match answer {
        Ok(BeatAnswer::FollowUps { from, items }) => {
            let skip = seen.saturating_sub(from) as usize;
            let end = from.saturating_add(u32::try_from(items.len()).unwrap_or(u32::MAX));
            *seen = (*seen).max(end);
            Beat::More(items.into_iter().skip(skip).collect())
        }
        Ok(BeatAnswer::State(view)) => match view.state {
            TaskState::Working => Beat::More(vec![]),
            TaskState::Held => Beat::Held,
            TaskState::Queued | TaskState::Reported | TaskState::Closed => Beat::Gone,
        },
        Ok(BeatAnswer::Idle) => Beat::Gone,
        Ok(BeatAnswer::Refused(_)) => Beat::Refused,
        Err(_) => Beat::Lost,
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum HookEnd {
    Held,
    Gone,
}

struct TaskHook<'a, C> {
    clock: &'a C,
    shutdown: &'a AtomicBool,
    seen: &'a mut u32,
    last_beat: &'a mut Duration,
    end: Option<HookEnd>,
}

impl<P: TaskPlane + Send, C: Clock + Sync> StepHook<P> for TaskHook<'_, C> {
    async fn after_step(&mut self, plane: &mut P, transcript: &mut Transcript) -> StepControl {
        if self.shutdown.load(Ordering::Acquire) {
            return StepControl::Stop;
        }
        let now = self.clock.now();
        if now.saturating_sub(*self.last_beat) < HEARTBEAT_EVERY {
            return StepControl::Continue;
        }
        match read_beat(plane.heartbeat(*self.seen).await, self.seen) {
            Beat::More(items) => {
                *self.last_beat = now;
                for item in &items {
                    transcript.push_user(&item.0);
                }
                StepControl::Continue
            }
            Beat::Held => {
                self.end = Some(HookEnd::Held);
                StepControl::Stop
            }
            Beat::Gone => {
                self.end = Some(HookEnd::Gone);
                StepControl::Stop
            }
            Beat::Refused | Beat::Lost => StepControl::Continue,
        }
    }
}

enum Reported {
    /// `Some` names the fixed report sent in place of the one asked for.
    Done(Option<&'static str>),
    FollowUps(Vec<SecretText>),
    Held,
    Gone,
    Unsendable,
    Shutdown,
}

enum Reconnected {
    Resume(Vec<SecretText>),
    Ended(Ending),
    Hold,
}

enum Then {
    Run,
    Resume(Vec<SecretText>),
}

struct Backoff(Duration);

impl Backoff {
    fn next(&mut self) -> Duration {
        let d = self.0;
        self.0 = (self.0 * 2).min(BACKOFF_MAX);
        d
    }
}

/// A fixed report of a stop's class, with no content.
pub fn stop_report(class: &str) -> String {
    format!("stopped: {class}")
}

fn partition_is_relative_and_canonical(partition: &str) -> bool {
    !partition.is_empty()
        && partition
            .split('/')
            .all(|s| !s.is_empty() && s != "." && s != "..")
}

fn first_turn(persona: Option<&SecretText>, prompt: &str) -> Zeroizing<String> {
    let Some(persona) = persona else {
        return Zeroizing::new(prompt.to_string());
    };
    let mut text = Zeroizing::new(String::with_capacity(persona.0.len() + 2 + prompt.len()));
    text.push_str(&persona.0);
    text.push_str("\n\n");
    text.push_str(prompt);
    text
}

fn secret(text: &str) -> SecretText {
    SecretText(Zeroizing::new(text.to_string()))
}

pub struct TaskDriver<P, C> {
    plane: P,
    clock: C,
    config: DriverConfig,
    shutdown: Arc<AtomicBool>,
    held: Option<Held>,
    leftover: bool,
    backoff: Backoff,
}

impl<P: TaskPlane + Send, C: Clock + Send + Sync> TaskDriver<P, C> {
    pub fn new(plane: P, clock: C, config: DriverConfig) -> Self {
        TaskDriver {
            plane,
            clock,
            config,
            shutdown: Arc::new(AtomicBool::new(false)),
            held: None,
            leftover: false,
            backoff: Backoff(BACKOFF_FIRST),
        }
    }

    pub fn shutdown_handle(&self) -> ShutdownHandle {
        ShutdownHandle(Arc::clone(&self.shutdown))
    }

    fn stopping(&self) -> bool {
        self.shutdown.load(Ordering::Acquire)
    }

    fn ended(&mut self, task: Option<TaskId>, ending: Ending) {
        self.plane.note(DriverEvent::Ended { task, ending });
    }

    async fn pause(&mut self, d: Duration) {
        self.clock.sleep(d).await;
    }

    async fn back_off(&mut self) {
        let d = self.backoff.next();
        self.clock.sleep(d).await;
    }

    /// Returns when the shutdown handle is used.
    pub async fn run(&mut self) {
        self.startup().await;
        while !self.stopping() {
            match self.plane.claim().await {
                Ok(ClaimAnswer::Delivered(d)) => {
                    self.backoff = Backoff(BACKOFF_FIRST);
                    self.delivered(&d.signed, &d.partition).await;
                }
                Ok(ClaimAnswer::Idle) => {
                    self.leftover = false;
                    self.backoff = Backoff(BACKOFF_FIRST);
                    self.pause(POLL_EVERY).await;
                }
                Ok(ClaimAnswer::Refused(_)) => {
                    self.backoff = Backoff(BACKOFF_FIRST);
                    self.pause(POLL_EVERY).await;
                }
                Err(_) => self.back_off().await,
            }
        }
        self.plane.cite(None);
    }

    async fn startup(&mut self) {
        while !self.stopping() {
            let mut seen = 0;
            match read_beat(self.plane.heartbeat(0).await, &mut seen) {
                Beat::More(_) => {
                    self.leftover = true;
                    return;
                }
                Beat::Held | Beat::Gone => return,
                Beat::Refused => self.pause(POLL_EVERY).await,
                Beat::Lost => self.back_off().await,
            }
        }
    }

    async fn delivered(&mut self, signed: &Bytes, partition: &str) {
        let leftover = std::mem::take(&mut self.leftover);
        let task = match self.plane.verify(signed) {
            Ok(task) => task,
            Err(Unverified::Undecodable) => {
                self.ended(None, Ending::Undecodable);
                self.pause(UNDECODABLE_WAIT).await;
                return;
            }
            Err(Unverified::Failed { task, class }) => {
                self.held.take_if(|h| h.id == task);
                self.cite_and_report(task, refusal_report(class), Ending::Unverified(class))
                    .await;
                return;
            }
        };
        let id = task.task.task_id;
        if let Some(held) = self.held.take() {
            if held.id == id {
                self.plane.cite(Some(id));
                self.work(held, Then::Resume(vec![])).await;
                return;
            }
        }
        if leftover {
            self.cite_and_report(id, RESTARTED.into(), Ending::Restarted)
                .await;
            return;
        }
        self.start(task, partition).await;
    }

    async fn cite_and_report(&mut self, id: TaskId, text: String, ending: Ending) {
        self.plane.cite(Some(id));
        let done = self.report(secret(&text), false, &mut 0).await;
        self.conclude(id, None, fixed_ending(done, ending)).await;
    }

    /// Uncites, then closes the conversation of a task that was reported or is
    /// gone. A close the kernel refuses is noted, never fatal.
    async fn conclude(&mut self, id: TaskId, session: Option<&Session>, ending: Ending) {
        self.plane.cite(None);
        self.ended(Some(id), ending);
        let closes = match ending {
            Ending::Answered | Ending::Stopped(_) | Ending::Gone => true,
            Ending::Unverified(_)
            | Ending::Undecodable
            | Ending::Held
            | Ending::Restarted
            | Ending::Shutdown
            | Ending::Unsendable => false,
        };
        if let (true, Some(session)) = (closes, session) {
            if let Some(Err(e)) = session.close(&mut self.plane).await {
                self.plane.note(DriverEvent::CloseFailed(e));
            }
        }
        if ending == Ending::Unsendable {
            self.pause(UNDECODABLE_WAIT).await;
        }
    }

    /// One content report. When it is not acknowledged and the task is still
    /// `Working` with nothing new, the content-free `stopped: report refused`
    /// follows once; a fixed report that is not acknowledged is `Unsendable`.
    async fn report(&mut self, text: SecretText, content: bool, seen: &mut u32) -> Reported {
        let mut text = text;
        let mut content = content;
        let mut fixed = None;
        loop {
            if self.stopping() {
                return Reported::Shutdown;
            }
            match self.plane.report(text.clone()).await {
                Ok(ReportOutcome::Acknowledged) => {
                    self.backoff = Backoff(BACKOFF_FIRST);
                    return Reported::Done(fixed);
                }
                Ok(ReportOutcome::TooLarge) if content => {
                    text = secret(&stop_report(TOO_LARGE));
                    content = false;
                    fixed = Some(TOO_LARGE);
                    continue;
                }
                Ok(ReportOutcome::TooLarge) => return Reported::Unsendable,
                Ok(ReportOutcome::Refused(_)) | Err(_) => {}
            }
            loop {
                if self.stopping() {
                    return Reported::Shutdown;
                }
                match read_beat(self.plane.heartbeat(*seen).await, seen) {
                    Beat::More(items) if content && !items.is_empty() => {
                        return Reported::FollowUps(items)
                    }
                    Beat::More(_) => break,
                    Beat::Held => return Reported::Held,
                    Beat::Gone => return Reported::Gone,
                    Beat::Refused | Beat::Lost => self.back_off().await,
                }
            }
            if !content {
                return Reported::Unsendable;
            }
            text = secret(&stop_report(REPORT_REFUSED));
            content = false;
            fixed = Some(REPORT_REFUSED);
        }
    }

    async fn start(&mut self, task: SignedTask, partition: &str) {
        let id = task.task.task_id;
        self.plane.cite(Some(id));
        let cwd = format!("{}/{partition}", self.config.home);
        if !partition_is_relative_and_canonical(partition) || !self.make_partition(&cwd).await {
            return self
                .stop_cited(id, None, PARTITION_UNAVAILABLE, &mut 0)
                .await;
        }
        let Ok(persona) = self.persona(partition) else {
            return self.stop_cited(id, None, PERSONA_UNAVAILABLE, &mut 0).await;
        };
        let Ask::Prompt { prompt } = &task.task.ask;
        let first = first_turn(persona.as_ref(), &prompt.0);
        let opened = Session::open(
            &mut self.plane,
            Path::new(&cwd),
            &[],
            &first,
            self.config.budget,
            self.config.context,
            Some(self.config.home.clone()),
        )
        .await;
        let Ok(mut session) = opened else {
            return self.stop_cited(id, None, SESSION_UNAVAILABLE, &mut 0).await;
        };
        session.share_stop(Arc::clone(&self.shutdown));
        let held = Held {
            id,
            session,
            seen: 0,
            last_beat: self.clock.now(),
            answer: None,
            resumes: 0,
        };
        self.work(held, Then::Run).await;
    }

    async fn make_partition(&mut self, cwd: &str) -> bool {
        for dir in [cwd.to_string(), format!("{cwd}/tmp")] {
            match self.plane.mkdir(&dir, true).await {
                WriteOutcome::Applied(_) => {}
                WriteOutcome::Stale
                | WriteOutcome::Unavailable
                | WriteOutcome::Unknown
                | WriteOutcome::NotSent
                | WriteOutcome::Protected(_) => return false,
            }
        }
        true
    }

    fn persona(&mut self, partition: &str) -> Result<Option<SecretText>, String> {
        let order: &[PersonaAt<'_>] = match self.config.persona {
            PersonaMode::Admin => &[PersonaAt::Etc],
            PersonaMode::Own => &[
                PersonaAt::Partition(partition),
                PersonaAt::Home,
                PersonaAt::Etc,
            ],
        };
        for at in order {
            if let Some(text) = self.plane.persona(*at)? {
                return Ok(Some(text));
            }
        }
        Ok(None)
    }

    async fn stop_cited(
        &mut self,
        id: TaskId,
        session: Option<&Session>,
        class: &'static str,
        seen: &mut u32,
    ) {
        let done = self.report(secret(&stop_report(class)), false, seen).await;
        self.conclude(id, session, fixed_ending(done, Ending::Stopped(class)))
            .await;
    }

    async fn work(&mut self, mut held: Held, then: Then) {
        let mut then = then;
        loop {
            let mut events = vec![];
            let mut hook = TaskHook {
                clock: &self.clock,
                shutdown: &self.shutdown,
                seen: &mut held.seen,
                last_beat: &mut held.last_beat,
                end: None,
            };
            let outcome = match then {
                Then::Run => {
                    held.session
                        .run_with(&mut self.plane, &mut hook, &mut |e| events.push(e))
                        .await
                }
                Then::Resume(items) => {
                    held.session
                        .resume(&mut self.plane, &items, &mut hook, &mut |e| events.push(e))
                        .await
                }
            };
            let end = hook.end;
            for e in events {
                self.plane.note(DriverEvent::Loop(e));
            }
            if let Some(answer) = outcome.answer {
                held.answer = Some(answer);
            }
            let stopped = match outcome.stopped {
                None | Some(StopReason::NothingPending) if held.answer.is_some() => {
                    match self.done(&mut held).await {
                        Ok(items) => {
                            then = Then::Resume(items);
                            continue;
                        }
                        Err(ending) => {
                            return self.conclude(held.id, Some(&held.session), ending).await
                        }
                    }
                }
                None => StopReason::NothingPending,
                Some(reason) => reason,
            };
            let class = match stopped {
                StopReason::Stopped => {
                    let ending = match end {
                        Some(HookEnd::Held) => Ending::Held,
                        Some(HookEnd::Gone) => Ending::Gone,
                        None => Ending::Shutdown,
                    };
                    return self.conclude(held.id, Some(&held.session), ending).await;
                }
                StopReason::Transport(_) if held.resumes < MAX_RESUMES => {
                    held.resumes += 1;
                    match self.reconnect(&mut held).await {
                        Reconnected::Resume(items) => {
                            then = Then::Resume(items);
                            continue;
                        }
                        Reconnected::Ended(ending) => {
                            return self.conclude(held.id, Some(&held.session), ending).await
                        }
                        Reconnected::Hold => {
                            self.plane.cite(None);
                            self.held = Some(held);
                            return;
                        }
                    }
                }
                reason @ (StopReason::Transport(_)
                | StopReason::StepBudget
                | StopReason::TooManyToolCalls(_)
                | StopReason::FrameBound
                | StopReason::PromptRefused
                | StopReason::PromptMalformed
                | StopReason::ReplyUnusable(_)
                | StopReason::EgressUnavailable
                | StopReason::ContextBudget
                | StopReason::NothingPending) => stop_class(&reason),
            };
            let id = held.id;
            return self
                .stop_cited(id, Some(&held.session), class, &mut held.seen)
                .await;
        }
    }

    /// Ending 1. `Ok` carries follow-ups to continue the session with.
    async fn done(&mut self, held: &mut Held) -> Result<Vec<SecretText>, Ending> {
        let answer = held.answer.clone().unwrap_or_default();
        loop {
            if self.stopping() {
                return Err(Ending::Shutdown);
            }
            match read_beat(self.plane.heartbeat(held.seen).await, &mut held.seen) {
                Beat::More(items) if !items.is_empty() => {
                    held.answer = None;
                    return Ok(items);
                }
                Beat::More(_) => break,
                Beat::Held => return Err(Ending::Held),
                Beat::Gone => return Err(Ending::Gone),
                Beat::Refused => self.pause(POLL_EVERY).await,
                Beat::Lost => self.back_off().await,
            }
        }
        match self
            .report(SecretText(Zeroizing::new(answer)), true, &mut held.seen)
            .await
        {
            Reported::FollowUps(items) => {
                held.answer = None;
                Ok(items)
            }
            done => Err(fixed_ending(done, Ending::Answered)),
        }
    }

    /// Ending 9. A refused heartbeat holds the task for the claim that re-delivers it.
    async fn reconnect(&mut self, held: &mut Held) -> Reconnected {
        self.backoff = Backoff(BACKOFF_FIRST);
        loop {
            self.back_off().await;
            if self.stopping() {
                return Reconnected::Ended(Ending::Shutdown);
            }
            match read_beat(self.plane.heartbeat(held.seen).await, &mut held.seen) {
                Beat::More(items) => return Reconnected::Resume(items),
                Beat::Held => return Reconnected::Ended(Ending::Held),
                Beat::Gone => return Reconnected::Ended(Ending::Gone),
                Beat::Refused => return Reconnected::Hold,
                Beat::Lost => {}
            }
        }
    }
}

/// `asked` is the ending of a report acknowledged as it was sent.
fn fixed_ending(done: Reported, asked: Ending) -> Ending {
    match done {
        Reported::Done(None) | Reported::FollowUps(_) => asked,
        Reported::Done(Some(class)) => Ending::Stopped(class),
        Reported::Held => Ending::Held,
        Reported::Gone => Ending::Gone,
        Reported::Shutdown => Ending::Shutdown,
        Reported::Unsendable => Ending::Unsendable,
    }
}

fn stop_class(reason: &StopReason) -> &'static str {
    match reason {
        StopReason::StepBudget => "step-budget",
        StopReason::TooManyToolCalls(_) => "too-many-tool-calls",
        StopReason::FrameBound => "frame-bound",
        StopReason::PromptRefused => "prompt-refused",
        StopReason::PromptMalformed => "prompt-malformed",
        StopReason::ReplyUnusable(_) => "reply-unusable",
        StopReason::EgressUnavailable => "egress-unavailable",
        StopReason::ContextBudget => "context-budget",
        StopReason::NothingPending => "nothing-pending",
        StopReason::Transport(_) => "transport",
        StopReason::Stopped => "stopped",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::plane::{ListOutcome, PlaneError, ReadBasis, ReadOutcome, StatOutcome};
    use crate::task::Refused;
    use maknae_proto::{
        ContentBlock, ConversationId, ConversationView, Labels, PromptReply, ProposedToolCall,
        ProtoErrCode, TaskDelivery, TaskObject, TaskRef, TaskSignature, TaskView, Tasker, Turn,
    };
    use std::collections::{HashMap, VecDeque};
    use std::sync::Mutex;

    const HOME: &str = "/home/hobi";
    const PART: &str = "tasks/users/1000";
    const CONV: &str = "00112233445566778899aabbccddeeff";

    #[derive(Default)]
    struct World {
        log: Vec<String>,
        events: Vec<DriverEvent>,
        now: Duration,
        shutdown: Option<ShutdownHandle>,
        sent: Vec<Vec<Turn>>,
    }
    type Shared = Arc<Mutex<World>>;

    struct FakeClock(Shared);
    impl Clock for FakeClock {
        fn now(&self) -> Duration {
            self.0.lock().unwrap().now
        }
        fn sleep(&mut self, d: Duration) -> impl Future<Output = ()> + Send {
            let mut w = self.0.lock().unwrap();
            w.now += d;
            w.log.push(format!("sleep {}", d.as_secs()));
            std::future::ready(())
        }
    }

    #[derive(Default)]
    struct Fake {
        w: Shared,
        claims: VecDeque<Result<ClaimAnswer, String>>,
        beats: VecDeque<Result<BeatAnswer, String>>,
        reports: VecDeque<Result<ReportOutcome, String>>,
        mkdirs: VecDeque<WriteOutcome>,
        tasks: HashMap<u8, Result<SignedTask, Unverified>>,
        personas: HashMap<String, Result<Option<SecretText>, String>>,
        replies: VecDeque<Result<PromptReply, PlaneError>>,
        step_cost: Duration,
        shutdown_at_prompt: Option<usize>,
        shutdown_on_report: bool,
        open_error: Option<PlaneError>,
        close_error: Option<PlaneError>,
        calls: usize,
    }

    impl Fake {
        fn log(&mut self, line: String) {
            self.calls += 1;
            assert!(self.calls < 400, "the driver did not settle");
            self.w.lock().unwrap().log.push(line);
        }
    }

    fn tag(id: &TaskId) -> String {
        format!("t{}", id.0[0])
    }

    impl Plane for Fake {
        async fn open(&mut self, cwd: &Path, s: &[String]) -> Result<ConversationId, PlaneError> {
            assert!(s.is_empty());
            self.log(format!("open {}", cwd.display()));
            match self.open_error.take() {
                Some(e) => Err(e),
                None => Ok(ConversationId::parse(CONV).unwrap()),
            }
        }
        async fn close(&mut self, c: &ConversationId) -> Result<ConversationView, PlaneError> {
            self.log(format!("close {}", c.as_str()));
            match self.close_error.take() {
                Some(e) => Err(e),
                None => Ok(ConversationView {
                    conversation: c.clone(),
                    cwd: format!("{HOME}/{PART}"),
                    opened_at: 0,
                    last_active: 0,
                    turns: 0,
                    bytes: 0,
                    chain_head: String::new(),
                }),
            }
        }
        async fn prompt(&mut self, _: &str, turns: &[Turn]) -> Result<PromptReply, PlaneError> {
            self.log(format!("prompt {}", turns.len()));
            let n = {
                let mut w = self.w.lock().unwrap();
                w.now += self.step_cost;
                w.sent.push(turns.to_vec());
                w.sent.len()
            };
            if self.shutdown_at_prompt == Some(n) {
                let w = self.w.lock().unwrap();
                w.shutdown.as_ref().unwrap().shut_down();
            }
            self.replies.pop_front().expect("prompt script exhausted")
        }
        async fn read(&mut self, _: &str, p: &str, _: maknae_proto::PageRequest) -> ReadOutcome {
            self.log(format!("read {p}"));
            ReadOutcome::Unavailable
        }
        async fn write(&mut self, _: &str, p: &str, _: &[u8], _: ReadBasis) -> WriteOutcome {
            self.log(format!("write {p}"));
            WriteOutcome::Unavailable
        }
        async fn list(&mut self, _: &str, p: &str, _: Option<&str>) -> ListOutcome {
            self.log(format!("list {p}"));
            ListOutcome::Unavailable
        }
        async fn stat(&mut self, _: &str, p: &str) -> StatOutcome {
            self.log(format!("stat {p}"));
            StatOutcome::Unavailable
        }
    }

    impl TaskPlane for Fake {
        async fn claim(&mut self) -> Result<ClaimAnswer, String> {
            self.log("claim".into());
            match self.claims.pop_front() {
                Some(a) => a,
                None => {
                    let w = self.w.lock().unwrap();
                    w.shutdown.as_ref().unwrap().shut_down();
                    Ok(ClaimAnswer::Idle)
                }
            }
        }
        async fn heartbeat(&mut self, seen: u32) -> Result<BeatAnswer, String> {
            self.log(format!("beat {seen}"));
            self.beats.pop_front().unwrap_or(Ok(BeatAnswer::FollowUps {
                from: seen,
                items: vec![],
            }))
        }
        async fn report(&mut self, text: SecretText) -> Result<ReportOutcome, String> {
            self.log(format!("report {}", *text.0));
            if self.shutdown_on_report {
                let w = self.w.lock().unwrap();
                w.shutdown.as_ref().unwrap().shut_down();
            }
            self.reports
                .pop_front()
                .unwrap_or(Ok(ReportOutcome::Acknowledged))
        }
        fn cite(&mut self, task: Option<TaskId>) {
            self.log(match task {
                Some(id) => format!("cite {}", tag(&id)),
                None => "uncite".into(),
            });
        }
        async fn mkdir(&mut self, path: &str, parents: bool) -> WriteOutcome {
            self.log(format!("mkdir {path} {parents}"));
            self.mkdirs
                .pop_front()
                .unwrap_or(WriteOutcome::Applied(None))
        }
        fn verify(&mut self, signed: &Bytes) -> Result<SignedTask, Unverified> {
            self.log("verify".into());
            self.tasks[&signed.0[0]].clone()
        }
        fn persona(&mut self, at: PersonaAt<'_>) -> Result<Option<SecretText>, String> {
            let key = match at {
                PersonaAt::Etc => "etc".to_string(),
                PersonaAt::Home => "home".to_string(),
                PersonaAt::Partition(p) => format!("partition {p}"),
            };
            self.log(format!("persona {key}"));
            self.personas.get(&key).cloned().unwrap_or(Ok(None))
        }
        fn note(&mut self, event: DriverEvent) {
            if let DriverEvent::Ended { .. } = event {
                self.w.lock().unwrap().events.push(event);
            }
        }
    }

    fn st(s: &str) -> SecretText {
        SecretText(Zeroizing::new(s.into()))
    }
    fn id(n: u8) -> TaskId {
        TaskId([n; 16])
    }
    fn signed(n: u8, prompt: &str) -> SignedTask {
        SignedTask {
            task: TaskObject {
                schema: maknae_proto::TASK_SCHEMA.into(),
                version: maknae_proto::TASK_VERSION,
                task_id: id(n),
                tasker: Tasker::Uid(1000),
                parent: None,
                agent: "hobi".into(),
                ask: Ask::Prompt { prompt: st(prompt) },
                labels: Labels {},
            },
            signature: TaskSignature {
                alg: "alg".into(),
                leaf: Bytes::new(Zeroizing::new(vec![1])),
                chain: vec![],
                sig: Bytes::new(Zeroizing::new(vec![2])),
            },
        }
    }
    fn delivered(n: u8, partition: &str) -> Result<ClaimAnswer, String> {
        Ok(ClaimAnswer::Delivered(TaskDelivery {
            signed: Bytes::new(Zeroizing::new(vec![n])),
            partition: partition.into(),
        }))
    }
    fn view(state: TaskState) -> TaskView {
        TaskView {
            task: TaskRef::from_id(&id(1)),
            agent: "hobi".into(),
            state,
            close: None,
            submitted_secs: 0,
            elapsed_secs: 0,
            actions: 0,
            last_action_secs: None,
        }
    }
    fn refused() -> Refused {
        Refused {
            code: ProtoErrCode::Unauthorized,
            message: "no".into(),
        }
    }
    fn follow_ups(from: u32, items: &[&str]) -> Result<BeatAnswer, String> {
        Ok(BeatAnswer::FollowUps {
            from,
            items: items.iter().map(|s| st(s)).collect(),
        })
    }
    fn answer(s: &str) -> Result<PromptReply, PlaneError> {
        Ok(PromptReply {
            reasoning: None,
            blocks: vec![ContentBlock::Text { text: st(s) }],
            tool_calls: vec![],
            usage: None,
        })
    }
    fn read(call: &str, path: &str) -> Result<PromptReply, PlaneError> {
        Ok(PromptReply {
            reasoning: None,
            blocks: vec![],
            tool_calls: vec![ProposedToolCall {
                name: "read_file".into(),
                call_id: call.into(),
                arguments: st(&format!(r#"{{"path":"{path}"}}"#)),
                refused: None,
            }],
            usage: None,
        })
    }

    /// A fake whose startup heartbeat finds nothing left over, with tasks 1 to 3 valid.
    fn fake() -> Fake {
        let mut f = Fake::default();
        f.beats.push_back(Ok(BeatAnswer::Idle));
        for n in 1..=3 {
            f.tasks.insert(n, Ok(signed(n, &format!("prompt-{n}"))));
        }
        f
    }

    fn config(persona: PersonaMode) -> DriverConfig {
        DriverConfig {
            home: HOME.into(),
            persona,
            budget: Budget {
                max_steps: 8,
                max_tool_calls_per_step: 2,
            },
            context: ContextBudget::new(maknae_proto::MAX_CONTEXT_TOKENS, None).unwrap(),
        }
    }

    fn driver(f: Fake, persona: PersonaMode) -> (TaskDriver<Fake, FakeClock>, Shared) {
        let w = Arc::clone(&f.w);
        let d = TaskDriver::new(f, FakeClock(Arc::clone(&w)), config(persona));
        w.lock().unwrap().shutdown = Some(d.shutdown_handle());
        (d, w)
    }

    async fn run_with(f: Fake, persona: PersonaMode) -> (Vec<String>, Vec<DriverEvent>, Shared) {
        let (mut d, w) = driver(f, persona);
        d.run().await;
        let (log, events) = {
            let g = w.lock().unwrap();
            (g.log.clone(), g.events.clone())
        };
        (log, events, w)
    }

    async fn run(f: Fake) -> (Vec<String>, Vec<DriverEvent>) {
        let (log, events, _) = run_with(f, PersonaMode::Own).await;
        (log, events)
    }

    fn ended(n: u8, ending: Ending) -> DriverEvent {
        DriverEvent::Ended {
            task: Some(id(n)),
            ending,
        }
    }

    fn strs(v: &[&str]) -> Vec<String> {
        v.iter().map(|s| s.to_string()).collect()
    }

    fn part() -> String {
        format!("{HOME}/{PART}")
    }

    /// From verification of a fresh task through `open`, persona found nowhere.
    fn fresh_start(n: u8) -> Vec<String> {
        let p = part();
        vec![
            "verify".into(),
            format!("cite t{n}"),
            format!("mkdir {p} true"),
            format!("mkdir {p}/tmp true"),
            format!("persona partition {PART}"),
            "persona home".into(),
            "persona etc".into(),
            format!("open {p}"),
        ]
    }

    fn tail() -> Vec<String> {
        strs(&["claim", "sleep 5", "uncite"])
    }

    fn user_text(t: &Turn) -> String {
        match t {
            Turn::User { content } => match &content[0] {
                ContentBlock::Text { text } => text.0.to_string(),
                other => panic!("{other:?}"),
            },
            other => panic!("not a user turn: {other:?}"),
        }
    }

    fn reports(log: &[String]) -> Vec<String> {
        log.iter()
            .filter(|l| l.starts_with("report "))
            .cloned()
            .collect()
    }

    #[test]
    fn the_quiet_wait_and_heartbeat_period_are_the_rulings_values() {
        assert_eq!(UNDECODABLE_WAIT, Duration::from_secs(900 + 60 + 30));
        assert_eq!(HEARTBEAT_EVERY, Duration::from_secs(900 / 3));
        assert_eq!(POLL_EVERY, Duration::from_secs(5));
        assert_eq!(
            (BACKOFF_FIRST, BACKOFF_MAX),
            (Duration::from_secs(1), Duration::from_secs(60))
        );
    }

    #[test]
    fn every_verify_class_names_itself_in_the_fixed_refusal() {
        let all = [
            (VerifyClass::Agent, "agent"),
            (VerifyClass::Algorithm, "algorithm"),
            (VerifyClass::NotKernel, "not-kernel"),
            (VerifyClass::Key, "key"),
            (VerifyClass::Signature, "signature"),
            (VerifyClass::Encoding, "encoding"),
        ];
        for (class, name) in all {
            assert_eq!(
                refusal_report(class),
                format!("refused: this task's kernel signature did not verify ({name})")
            );
        }
    }

    #[test]
    fn every_stop_reason_has_its_own_class() {
        let all = [
            (StopReason::StepBudget, "step-budget"),
            (StopReason::TooManyToolCalls(3), "too-many-tool-calls"),
            (StopReason::FrameBound, "frame-bound"),
            (StopReason::PromptRefused, "prompt-refused"),
            (StopReason::PromptMalformed, "prompt-malformed"),
            (
                StopReason::ReplyUnusable(maknae_proto::ReplyDefect::Empty),
                "reply-unusable",
            ),
            (StopReason::EgressUnavailable, "egress-unavailable"),
            (StopReason::ContextBudget, "context-budget"),
            (StopReason::NothingPending, "nothing-pending"),
            (StopReason::Transport("x".into()), "transport"),
            (StopReason::Stopped, "stopped"),
        ];
        for (reason, class) in all {
            assert_eq!(stop_class(&reason), class);
        }
        assert_eq!(stop_report("step-budget"), "stopped: step-budget");
    }

    #[test]
    fn a_heartbeat_reads_only_the_follow_ups_not_yet_seen() {
        let mut seen = 2;
        let Beat::More(items) = read_beat(follow_ups(1, &["a", "b", "c"]), &mut seen) else {
            panic!()
        };
        assert_eq!(items, vec![st("b"), st("c")]);
        assert_eq!(seen, 4);
        let Beat::More(items) = read_beat(follow_ups(4, &[]), &mut seen) else {
            panic!()
        };
        assert!(items.is_empty());
        assert_eq!(seen, 4);
        assert!(matches!(
            read_beat(Ok(BeatAnswer::State(view(TaskState::Working))), &mut seen),
            Beat::More(v) if v.is_empty()
        ));
        assert!(matches!(
            read_beat(Ok(BeatAnswer::State(view(TaskState::Held))), &mut seen),
            Beat::Held
        ));
        for s in [TaskState::Queued, TaskState::Reported, TaskState::Closed] {
            assert!(matches!(
                read_beat(Ok(BeatAnswer::State(view(s))), &mut seen),
                Beat::Gone
            ));
        }
        assert!(matches!(
            read_beat(Ok(BeatAnswer::Idle), &mut seen),
            Beat::Gone
        ));
        assert!(matches!(
            read_beat(Ok(BeatAnswer::Refused(refused())), &mut seen),
            Beat::Refused
        ));
        assert!(matches!(
            read_beat(Err("reset".into()), &mut seen),
            Beat::Lost
        ));
        assert_eq!(seen, 4);
    }

    #[test]
    fn backoff_doubles_from_one_second_to_a_minute() {
        let mut b = Backoff(BACKOFF_FIRST);
        let got: Vec<u64> = (0..9).map(|_| b.next().as_secs()).collect();
        assert_eq!(got, vec![1, 2, 4, 8, 16, 32, 60, 60, 60]);
    }

    #[tokio::test]
    async fn startup_sends_one_uncited_heartbeat_before_the_first_claim() {
        let (log, _) = run(fake()).await;
        assert_eq!(log, strs(&["beat 0", "claim", "sleep 5", "uncite"]));
    }

    #[tokio::test]
    async fn a_startup_heartbeat_that_is_not_answered_is_retried_before_any_claim() {
        let f = Fake {
            beats: VecDeque::from([
                Ok(BeatAnswer::Refused(refused())),
                Err("reset".into()),
                Ok(BeatAnswer::Idle),
            ]),
            ..Fake::default()
        };
        let (log, _) = run(f).await;
        assert_eq!(
            log,
            strs(&[
                "beat 0", "sleep 5", "beat 0", "sleep 1", "beat 0", "claim", "sleep 5", "uncite"
            ])
        );
    }

    #[tokio::test]
    async fn idle_polls_every_five_seconds_and_does_nothing_else_on_idle_or_refused() {
        let mut f = fake();
        f.claims = VecDeque::from([
            Ok(ClaimAnswer::Idle),
            Ok(ClaimAnswer::Refused(refused())),
            Err("reset".into()),
            Err("reset".into()),
            Ok(ClaimAnswer::Idle),
            Err("reset".into()),
        ]);
        let (log, events) = run(f).await;
        assert_eq!(
            log,
            strs(&[
                "beat 0", "claim", "sleep 5", "claim", "sleep 5", "claim", "sleep 1", "claim",
                "sleep 2", "claim", "sleep 5", "claim", "sleep 1", "claim", "sleep 5", "uncite"
            ])
        );
        assert!(events.is_empty());
    }

    #[tokio::test]
    async fn a_refused_claim_is_retried_at_the_next_poll_and_never_verified_closed_or_reported() {
        let mut f = fake();
        f.claims = VecDeque::from([Ok(ClaimAnswer::Refused(refused())), delivered(1, PART)]);
        f.replies = VecDeque::from([answer("a1")]);
        let (log, _) = run(f).await;
        assert_eq!(&log[..4], &strs(&["beat 0", "claim", "sleep 5", "claim"]));
        assert_eq!(log.iter().filter(|l| *l == "verify").count(), 1);
        assert_eq!(reports(&log), strs(&["report a1"]));
    }

    #[tokio::test]
    async fn a_delivered_task_is_cited_before_its_partition_is_made_and_runs_in_it() {
        let mut f = fake();
        f.claims = VecDeque::from([delivered(1, PART)]);
        f.replies = VecDeque::from([answer("a1")]);
        let (log, _, w) = run_with(f, PersonaMode::Own).await;
        assert_eq!(&log[..2], &strs(&["beat 0", "claim"]));
        assert_eq!(&log[2..10], &fresh_start(1)[..]);
        assert_eq!(log[10], "prompt 1");
        assert_eq!(user_text(&w.lock().unwrap().sent[0][0]), "prompt-1");
    }

    #[tokio::test]
    async fn ending_1_an_answer_is_reported_after_an_uncited_heartbeat_then_uncited() {
        let mut f = fake();
        f.claims = VecDeque::from([delivered(1, PART)]);
        f.replies = VecDeque::from([answer("answer-629-sentinel")]);
        let (log, events) = run(f).await;
        let mut want = strs(&["beat 0", "claim"]);
        want.extend(fresh_start(1));
        want.extend(strs(&[
            "prompt 1",
            "beat 0",
            "report answer-629-sentinel",
            "uncite",
        ]));
        want.push(format!("close {CONV}"));
        want.extend(tail());
        assert_eq!(log, want);
        assert_eq!(events, vec![ended(1, Ending::Answered)]);
    }

    #[tokio::test]
    async fn an_existing_partition_is_made_again_without_error_and_the_next_task_runs_in_it() {
        let mut f = fake();
        f.claims = VecDeque::from([delivered(1, PART), delivered(2, PART)]);
        f.mkdirs = VecDeque::from([
            WriteOutcome::Applied(None),
            WriteOutcome::Applied(None),
            WriteOutcome::Applied(None),
            WriteOutcome::Applied(Some([0; 7])),
        ]);
        f.replies = VecDeque::from([answer("a1"), answer("a2")]);
        let (log, events) = run(f).await;
        assert_eq!(reports(&log), strs(&["report a1", "report a2"]));
        assert_eq!(log.iter().filter(|l| l.starts_with("mkdir")).count(), 4);
        assert_eq!(
            events,
            vec![ended(1, Ending::Answered), ended(2, Ending::Answered)]
        );
    }

    #[tokio::test]
    async fn a_partition_that_cannot_be_made_is_reported_stopped_and_never_reaches_the_model() {
        for (outcome, mkdirs) in [
            (WriteOutcome::Unavailable, 1),
            (WriteOutcome::Unknown, 1),
            (WriteOutcome::Stale, 1),
            (WriteOutcome::NotSent, 1),
            (
                WriteOutcome::Protected(crate::plane::ProtectedBy {
                    list: "l".into(),
                    entry: "e".into(),
                }),
                1,
            ),
        ] {
            let mut f = fake();
            f.claims = VecDeque::from([delivered(1, PART)]);
            f.mkdirs = VecDeque::from([outcome.clone()]);
            let (log, events) = run(f).await;
            assert_eq!(
                log.iter().filter(|l| l.starts_with("mkdir")).count(),
                mkdirs
            );
            assert_eq!(
                reports(&log),
                strs(&["report stopped: partition-unavailable"]),
                "{outcome:?}"
            );
            assert!(!log.iter().any(|l| l.starts_with("open")
                || l.starts_with("prompt")
                || l.starts_with("persona")));
            assert_eq!(
                events,
                vec![ended(1, Ending::Stopped(PARTITION_UNAVAILABLE))]
            );
        }
        let mut f = fake();
        f.claims = VecDeque::from([delivered(1, PART)]);
        f.mkdirs = VecDeque::from([WriteOutcome::Applied(None), WriteOutcome::Unavailable]);
        let (log, _) = run(f).await;
        assert_eq!(log.iter().filter(|l| l.starts_with("mkdir")).count(), 2);
        assert_eq!(
            reports(&log),
            strs(&["report stopped: partition-unavailable"])
        );
    }

    #[tokio::test]
    async fn a_partition_that_is_not_relative_and_canonical_is_never_made() {
        for bad in [
            "",
            "/etc",
            "tasks/../../etc",
            "tasks//users",
            "tasks/./u",
            "tasks/users/",
        ] {
            let mut f = fake();
            f.claims = VecDeque::from([delivered(1, bad)]);
            let (log, _) = run(f).await;
            assert!(!log.iter().any(|l| l.starts_with("mkdir")), "{bad}");
            assert_eq!(
                reports(&log),
                strs(&["report stopped: partition-unavailable"]),
                "{bad}"
            );
        }
    }

    #[tokio::test]
    async fn an_admin_persona_is_read_only_from_etc() {
        let mut f = fake();
        f.claims = VecDeque::from([delivered(1, PART)]);
        f.personas
            .insert("etc".into(), Ok(Some(st("You are hobi."))));
        f.personas
            .insert("home".into(), Ok(Some(st("home persona"))));
        f.replies = VecDeque::from([answer("a1")]);
        let (log, _, w) = run_with(f, PersonaMode::Admin).await;
        let reads: Vec<_> = log
            .iter()
            .filter(|l| l.starts_with("persona"))
            .cloned()
            .collect();
        assert_eq!(reads, strs(&["persona etc"]));
        assert_eq!(
            user_text(&w.lock().unwrap().sent[0][0]),
            "You are hobi.\n\nprompt-1"
        );
    }

    #[tokio::test]
    async fn a_self_persona_is_the_partitions_then_the_homes_then_etc() {
        let mut f = fake();
        f.claims = VecDeque::from([delivered(1, PART)]);
        f.personas
            .insert("home".into(), Ok(Some(st("home persona"))));
        f.personas.insert("etc".into(), Ok(Some(st("etc persona"))));
        f.replies = VecDeque::from([answer("a1")]);
        let (log, _, w) = run_with(f, PersonaMode::Own).await;
        let reads: Vec<_> = log
            .iter()
            .filter(|l| l.starts_with("persona"))
            .cloned()
            .collect();
        assert_eq!(
            reads,
            strs(&["persona partition tasks/users/1000", "persona home"])
        );
        assert_eq!(
            user_text(&w.lock().unwrap().sent[0][0]),
            "home persona\n\nprompt-1"
        );

        let mut f = fake();
        f.claims = VecDeque::from([delivered(1, PART)]);
        f.personas.insert(
            format!("partition {PART}"),
            Ok(Some(st("partition persona"))),
        );
        f.replies = VecDeque::from([answer("a1")]);
        let (_, _, w) = run_with(f, PersonaMode::Own).await;
        assert_eq!(
            user_text(&w.lock().unwrap().sent[0][0]),
            "partition persona\n\nprompt-1"
        );
    }

    #[tokio::test]
    async fn a_persona_is_never_read_from_another_taskers_partition() {
        let mut f = fake();
        f.claims = VecDeque::from([
            delivered(1, "tasks/users/1000"),
            delivered(2, "tasks/agents/suga"),
        ]);
        f.personas.insert(
            "partition tasks/users/1000".into(),
            Ok(Some(st("user-1000-persona"))),
        );
        f.replies = VecDeque::from([answer("a1"), answer("a2")]);
        let (log, _, w) = run_with(f, PersonaMode::Own).await;
        let reads: Vec<_> = log
            .iter()
            .filter(|l| l.starts_with("persona"))
            .cloned()
            .collect();
        assert_eq!(
            reads,
            strs(&[
                "persona partition tasks/users/1000",
                "persona partition tasks/agents/suga",
                "persona home",
                "persona etc"
            ])
        );
        let w = w.lock().unwrap();
        assert_eq!(user_text(&w.sent[1][0]), "prompt-2");
    }

    #[tokio::test]
    async fn a_persona_that_cannot_be_read_is_reported_stopped_not_skipped() {
        let mut f = fake();
        f.claims = VecDeque::from([delivered(1, PART)]);
        f.personas.insert("home".into(), Err("mode 0666".into()));
        let (log, events) = run(f).await;
        assert!(!log
            .iter()
            .any(|l| l.starts_with("open") || l == "persona etc"));
        assert_eq!(
            reports(&log),
            strs(&["report stopped: persona-unavailable"])
        );
        assert_eq!(events, vec![ended(1, Ending::Stopped(PERSONA_UNAVAILABLE))]);
    }

    #[tokio::test]
    async fn the_heartbeat_is_sent_when_five_minutes_of_wall_time_have_passed_checked_after_every_step(
    ) {
        let mut f = fake();
        f.claims = VecDeque::from([delivered(1, PART)]);
        f.step_cost = Duration::from_secs(120);
        f.replies = (1..=5)
            .map(|i| read(&format!("c{i}"), &format!("/w/{i}")))
            .chain([answer("a1")])
            .collect();
        let (log, _) = run(f).await;
        let after_open = log.iter().position(|l| l.starts_with("open")).unwrap();
        let steps: Vec<&str> = log[after_open + 1..]
            .iter()
            .map(String::as_str)
            .filter(|l| l.starts_with("prompt") || l.starts_with("beat"))
            .collect();
        assert_eq!(
            steps,
            vec![
                "prompt 1",
                "prompt 3",
                "prompt 5",
                "beat 0",
                "prompt 7",
                "prompt 9",
                "prompt 11",
                "beat 0"
            ]
        );
    }

    #[tokio::test]
    async fn a_follow_up_appended_mid_task_follows_the_tool_turns() {
        let mut f = fake();
        f.claims = VecDeque::from([delivered(1, PART)]);
        f.step_cost = HEARTBEAT_EVERY;
        f.beats
            .push_back(follow_ups(0, &["follow-up-629-sentinel"]));
        f.replies = VecDeque::from([read("c1", "/w/a"), answer("a1")]);
        let (log, _, w) = run_with(f, PersonaMode::Own).await;
        let w = w.lock().unwrap();
        let second = &w.sent[1];
        assert_eq!(second.len(), 4);
        assert!(matches!(&second[2], Turn::Tool { call_id, .. } if call_id == "c1"));
        assert_eq!(user_text(&second[3]), "follow-up-629-sentinel");
        let beats: Vec<_> = log
            .iter()
            .filter(|l| l.starts_with("beat"))
            .cloned()
            .collect();
        assert_eq!(beats, strs(&["beat 0", "beat 0", "beat 1"]));
    }

    #[tokio::test]
    async fn a_held_answer_mid_step_stops_work_with_no_report_and_no_further_request() {
        let mut f = fake();
        f.claims = VecDeque::from([delivered(1, PART)]);
        f.step_cost = HEARTBEAT_EVERY;
        f.beats
            .push_back(Ok(BeatAnswer::State(view(TaskState::Held))));
        f.replies = VecDeque::from([read("c1", "/w/a"), read("c2", "/w/b")]);
        let (log, events) = run(f).await;
        let at = log.iter().position(|l| l == "read /w/a").unwrap();
        let mut want = strs(&["read /w/a", "beat 0", "uncite"]);
        want.extend(tail());
        assert_eq!(&log[at..], &want[..]);
        assert!(reports(&log).is_empty());
        assert_eq!(events, vec![ended(1, Ending::Held)]);
    }

    #[tokio::test]
    async fn a_closed_or_idle_answer_mid_step_stops_work_with_no_report() {
        for answer_ in [
            Ok(BeatAnswer::State(view(TaskState::Closed))),
            Ok(BeatAnswer::State(view(TaskState::Reported))),
            Ok(BeatAnswer::Idle),
        ] {
            let mut f = fake();
            f.claims = VecDeque::from([delivered(1, PART)]);
            f.step_cost = HEARTBEAT_EVERY;
            f.beats.push_back(answer_);
            f.replies = VecDeque::from([read("c1", "/w/a"), read("c2", "/w/b")]);
            let (log, events) = run(f).await;
            assert!(reports(&log).is_empty());
            assert!(!log.iter().any(|l| l == "read /w/b"));
            assert_eq!(events, vec![ended(1, Ending::Gone)]);
        }
    }

    #[tokio::test]
    async fn a_refused_heartbeat_mid_task_continues_and_beats_again_at_the_next_step() {
        let mut f = fake();
        f.claims = VecDeque::from([delivered(1, PART)]);
        f.step_cost = HEARTBEAT_EVERY / 2;
        f.beats.push_back(Ok(BeatAnswer::Refused(refused())));
        f.beats.push_back(Err("reset".into()));
        f.replies = ["/w/a", "/w/b", "/w/c", "/w/d", "/w/e"]
            .iter()
            .enumerate()
            .map(|(i, p)| read(&format!("c{i}"), p))
            .chain([answer("a1")])
            .collect();
        let (log, events) = run(f).await;
        let after_open = log.iter().position(|l| l.starts_with("open")).unwrap();
        let steps: Vec<&str> = log[after_open + 1..]
            .iter()
            .map(String::as_str)
            .filter(|l| l.starts_with("read") || l.starts_with("beat"))
            .collect();
        assert_eq!(
            steps,
            vec![
                "read /w/a",
                "read /w/b",
                "beat 0",
                "read /w/c",
                "beat 0",
                "read /w/d",
                "beat 0",
                "read /w/e",
                "beat 0"
            ]
        );
        assert_eq!(events, vec![ended(1, Ending::Answered)]);
    }

    #[tokio::test]
    async fn follow_ups_at_the_done_heartbeat_are_folded_in_and_the_session_continues() {
        let mut f = fake();
        f.claims = VecDeque::from([delivered(1, PART)]);
        f.beats.push_back(follow_ups(0, &["more-629"]));
        f.replies = VecDeque::from([answer("first"), answer("second")]);
        let (log, events, w) = run_with(f, PersonaMode::Own).await;
        assert_eq!(reports(&log), strs(&["report second"]));
        assert_eq!(log.iter().filter(|l| l.starts_with("open")).count(), 1);
        let w = w.lock().unwrap();
        assert_eq!(user_text(&w.sent[1][2]), "more-629");
        assert_eq!(events, vec![ended(1, Ending::Answered)]);
    }

    #[tokio::test]
    async fn a_refused_answer_is_followed_once_by_the_content_free_report_refused() {
        let mut f = fake();
        f.claims = VecDeque::from([delivered(1, PART), Err("reset".into())]);
        f.reports = VecDeque::from([Ok(ReportOutcome::Refused(refused()))]);
        f.beats
            .extend([follow_ups(0, &[]), Err("reset".into()), follow_ups(0, &[])]);
        f.replies = VecDeque::from([answer("a1")]);
        let (log, events) = run(f).await;
        let at = log.iter().position(|l| l == "prompt 1").unwrap();
        let mut want = strs(&[
            "prompt 1",
            "beat 0",
            "report a1",
            "beat 0",
            "sleep 1",
            "beat 0",
            "report stopped: report refused",
            "uncite",
        ]);
        want.push(format!("close {CONV}"));
        want.extend(strs(&["claim", "sleep 1"]));
        want.extend(tail());
        assert_eq!(&log[at..], &want[..]);
        assert_eq!(events, vec![ended(1, Ending::Stopped(REPORT_REFUSED))]);
    }

    #[tokio::test]
    async fn a_lost_answer_report_is_not_resent_either() {
        let mut f = fake();
        f.claims = VecDeque::from([delivered(1, PART)]);
        f.reports = VecDeque::from([Err("reset".into())]);
        f.replies = VecDeque::from([answer("a1")]);
        let (log, _) = run(f).await;
        assert_eq!(
            reports(&log),
            strs(&["report a1", "report stopped: report refused"])
        );
    }

    #[tokio::test]
    async fn a_fixed_report_refused_while_the_task_is_working_goes_quiet_for_the_lease() {
        let mut f = fake();
        f.claims = VecDeque::from([delivered(1, PART)]);
        f.reports = VecDeque::from([
            Ok(ReportOutcome::Refused(refused())),
            Ok(ReportOutcome::Refused(refused())),
        ]);
        f.replies = VecDeque::from([answer("a1")]);
        let (log, events) = run(f).await;
        let at = log
            .iter()
            .position(|l| l == "report stopped: report refused")
            .unwrap();
        let mut want = strs(&[
            "report stopped: report refused",
            "beat 0",
            "uncite",
            "sleep 990",
        ]);
        want.extend(tail());
        assert_eq!(&log[at..], &want[..]);
        assert_eq!(events, vec![ended(1, Ending::Unsendable)]);

        for fixed in [Err(Unverified::Failed {
            task: id(9),
            class: VerifyClass::Key,
        })] {
            let mut f = fake();
            f.tasks.insert(9, fixed);
            f.claims = VecDeque::from([delivered(9, PART)]);
            f.reports = VecDeque::from([Err("reset".into())]);
            let (log, events) = run(f).await;
            let mut want = strs(&[
                "beat 0",
                "claim",
                "verify",
                "cite t9",
                "report refused: this task's kernel signature did not verify (key)",
                "beat 0",
                "uncite",
                "sleep 990",
            ]);
            want.extend(tail());
            assert_eq!(log, want);
            assert_eq!(events, vec![ended(9, Ending::Unsendable)]);
        }
    }

    #[tokio::test]
    async fn a_reconnect_backs_off_to_at_most_a_minute() {
        let mut f = fake();
        f.claims = VecDeque::from([delivered(1, PART)]);
        f.beats
            .extend((0..9).map(|_| Err::<BeatAnswer, String>("reset".into())));
        f.replies = VecDeque::from([Err(PlaneError::Transport("x".into())), answer("a1")]);
        let (log, _) = run(f).await;
        let sleeps: Vec<u64> = log
            .iter()
            .filter_map(|l| l.strip_prefix("sleep "))
            .map(|n| n.parse().unwrap())
            .collect();
        assert_eq!(sleeps, vec![1, 2, 4, 8, 16, 32, 60, 60, 60, 60, 5]);
    }

    #[tokio::test]
    async fn a_task_whose_connection_keeps_failing_is_resumed_at_most_three_times() {
        let mut f = fake();
        f.claims = VecDeque::from([delivered(1, PART)]);
        f.replies = (0..4)
            .map(|_| Err(PlaneError::Transport("ended".into())))
            .collect();
        let (log, events) = run(f).await;
        assert_eq!(log.iter().filter(|l| l.starts_with("prompt")).count(), 4);
        assert_eq!(reports(&log), strs(&["report stopped: transport"]));
        assert_eq!(events, vec![ended(1, Ending::Stopped("transport"))]);
    }

    #[tokio::test]
    async fn a_resume_through_the_claim_counts_against_the_same_bound() {
        let mut f = fake();
        f.claims = (0..4).map(|_| delivered(1, PART)).collect();
        f.beats
            .extend((0..4).map(|_| Ok(BeatAnswer::Refused(refused()))));
        f.replies = (0..4)
            .map(|_| Err(PlaneError::Transport("ended".into())))
            .collect();
        let (log, _) = run(f).await;
        assert_eq!(log.iter().filter(|l| l.starts_with("prompt")).count(), 4);
        assert_eq!(reports(&log), strs(&["report stopped: transport"]));
    }

    #[tokio::test]
    async fn the_conversation_is_closed_uncited_after_a_report_or_when_the_task_is_gone() {
        let close = format!("close {CONV}");
        let mut f = fake();
        f.claims = VecDeque::from([delivered(1, PART)]);
        f.replies = VecDeque::from([answer("a1")]);
        let (log, _) = run(f).await;
        let at = log.iter().position(|l| l == "report a1").unwrap();
        assert_eq!(log[at + 1..at + 3], [String::from("uncite"), close.clone()]);

        let mut f = fake();
        f.claims = VecDeque::from([delivered(1, PART)]);
        f.replies = VecDeque::from([Err(PlaneError::Refused)]);
        let (log, _) = run(f).await;
        let at = log.iter().position(|l| l.starts_with("report")).unwrap();
        assert_eq!(log[at + 1..at + 3], [String::from("uncite"), close.clone()]);

        let mut f = fake();
        f.claims = VecDeque::from([delivered(1, PART)]);
        f.beats.push_back(Ok(BeatAnswer::Idle));
        f.replies = VecDeque::from([answer("a1")]);
        let (log, _) = run(f).await;
        let at = log.iter().position(|l| l == "prompt 1").unwrap();
        assert_eq!(log[at + 1..at + 4], strs(&["beat 0", "uncite", &close])[..]);
    }

    #[tokio::test]
    async fn a_refused_close_is_noted_and_the_next_claim_still_follows() {
        let mut f = fake();
        f.claims = VecDeque::from([delivered(1, PART), delivered(2, PART)]);
        f.close_error = Some(PlaneError::Refused);
        f.replies = VecDeque::from([answer("a1"), answer("a2")]);
        let (log, events) = run(f).await;
        assert_eq!(reports(&log), strs(&["report a1", "report a2"]));
        assert_eq!(log.iter().filter(|l| l.starts_with("close")).count(), 2);
        assert_eq!(
            events,
            vec![ended(1, Ending::Answered), ended(2, Ending::Answered)]
        );
    }

    #[tokio::test]
    async fn a_held_task_or_a_resumed_one_keeps_its_conversation() {
        let mut f = fake();
        f.claims = VecDeque::from([delivered(1, PART)]);
        f.beats
            .push_back(Ok(BeatAnswer::State(view(TaskState::Held))));
        f.replies = VecDeque::from([answer("a1")]);
        let (log, _) = run(f).await;
        assert!(!log.iter().any(|l| l.starts_with("close")));

        let mut f = fake();
        f.claims = VecDeque::from([delivered(1, PART)]);
        f.step_cost = HEARTBEAT_EVERY;
        f.beats
            .push_back(Ok(BeatAnswer::State(view(TaskState::Held))));
        f.replies = VecDeque::from([read("c1", "/w/a")]);
        let (log, _) = run(f).await;
        assert!(!log.iter().any(|l| l.starts_with("close")));

        let mut f = fake();
        f.claims = VecDeque::from([delivered(1, PART)]);
        f.replies = VecDeque::from([Err(PlaneError::Transport("x".into())), answer("a1")]);
        let (log, _) = run(f).await;
        let closes: Vec<usize> = log
            .iter()
            .enumerate()
            .filter(|(_, l)| l.starts_with("close"))
            .map(|(i, _)| i)
            .collect();
        assert_eq!(closes.len(), 1);
        assert!(closes[0] > log.iter().position(|l| l == "report a1").unwrap());
    }

    #[tokio::test]
    async fn an_idle_claim_clears_the_mark_left_by_the_startup_heartbeat() {
        let mut f = Fake::default();
        f.beats.push_back(follow_ups(0, &[]));
        f.tasks.insert(1, Ok(signed(1, "prompt-1")));
        f.claims = VecDeque::from([Ok(ClaimAnswer::Idle), delivered(1, PART)]);
        f.replies = VecDeque::from([answer("a1")]);
        let (log, events) = run(f).await;
        assert_eq!(reports(&log), strs(&["report a1"]));
        assert_eq!(events, vec![ended(1, Ending::Answered)]);

        let mut f = Fake::default();
        f.beats.push_back(follow_ups(0, &[]));
        f.tasks.insert(1, Ok(signed(1, "prompt-1")));
        f.claims = VecDeque::from([Ok(ClaimAnswer::Refused(refused())), delivered(1, PART)]);
        let (log, events) = run(f).await;
        assert_eq!(reports(&log), strs(&["report stopped: agent restarted"]));
        assert_eq!(events, vec![ended(1, Ending::Restarted)]);
    }

    #[tokio::test]
    async fn a_refused_report_with_new_follow_ups_continues_the_session() {
        let mut f = fake();
        f.claims = VecDeque::from([delivered(1, PART)]);
        f.reports = VecDeque::from([Ok(ReportOutcome::Refused(refused()))]);
        f.beats
            .extend([follow_ups(0, &[]), follow_ups(0, &["late-629"])]);
        f.replies = VecDeque::from([answer("a1"), answer("a2")]);
        let (log, _, w) = run_with(f, PersonaMode::Own).await;
        assert_eq!(reports(&log), strs(&["report a1", "report a2"]));
        assert_eq!(user_text(&w.lock().unwrap().sent[1][2]), "late-629");
    }

    #[tokio::test]
    async fn a_refused_report_then_idle_or_state_stops_without_reporting_again() {
        for (beat, ending) in [
            (Ok(BeatAnswer::Idle), Ending::Gone),
            (Ok(BeatAnswer::State(view(TaskState::Closed))), Ending::Gone),
            (Ok(BeatAnswer::State(view(TaskState::Held))), Ending::Held),
        ] {
            let mut f = fake();
            f.claims = VecDeque::from([delivered(1, PART)]);
            f.reports = VecDeque::from([Ok(ReportOutcome::Refused(refused()))]);
            f.beats.extend([follow_ups(0, &[]), beat]);
            f.replies = VecDeque::from([answer("a1")]);
            let (log, events) = run(f).await;
            assert_eq!(reports(&log), strs(&["report a1"]));
            let at = log.iter().position(|l| l == "report a1").unwrap();
            assert_eq!(log[at + 1..at + 3], strs(&["beat 0", "uncite"])[..]);
            assert_eq!(events, vec![ended(1, ending)]);
        }
    }

    #[tokio::test]
    async fn an_answer_too_large_to_report_is_reported_too_large_with_no_content() {
        let mut f = fake();
        f.claims = VecDeque::from([delivered(1, PART)]);
        f.reports = VecDeque::from([Ok(ReportOutcome::TooLarge)]);
        f.replies = VecDeque::from([answer("huge-629-sentinel")]);
        let (log, events) = run(f).await;
        assert_eq!(
            reports(&log),
            strs(&[
                "report huge-629-sentinel",
                "report stopped: report too large"
            ])
        );
        let at = log
            .iter()
            .position(|l| l == "report huge-629-sentinel")
            .unwrap();
        assert_eq!(log[at + 1], "report stopped: report too large");
        assert_eq!(events, vec![ended(1, Ending::Stopped(TOO_LARGE))]);
    }

    #[tokio::test]
    async fn a_fixed_report_that_does_not_fit_is_left_to_lapse_quietly() {
        let mut f = fake();
        f.claims = VecDeque::from([delivered(1, PART)]);
        f.reports = VecDeque::from([Ok(ReportOutcome::TooLarge), Ok(ReportOutcome::TooLarge)]);
        f.replies = VecDeque::from([answer("a1")]);
        let (log, events) = run(f).await;
        let at = log
            .iter()
            .position(|l| l == "report stopped: report too large")
            .unwrap();
        assert_eq!(log[at + 1..at + 3], strs(&["uncite", "sleep 990"])[..]);
        assert_eq!(events, vec![ended(1, Ending::Unsendable)]);
    }

    #[tokio::test]
    async fn a_task_that_fails_verification_is_reported_refused_and_the_next_queued_task_follows() {
        let mut f = fake();
        f.tasks.insert(
            9,
            Err(Unverified::Failed {
                task: id(9),
                class: VerifyClass::Signature,
            }),
        );
        f.claims = VecDeque::from([delivered(9, PART), delivered(1, PART)]);
        f.replies = VecDeque::from([answer("a1")]);
        let (log, events) = run(f).await;
        let mut want = strs(&[
            "beat 0",
            "claim",
            "verify",
            "cite t9",
            "report refused: this task's kernel signature did not verify (signature)",
            "uncite",
            "claim",
        ]);
        want.extend(fresh_start(1));
        assert_eq!(&log[..want.len()], &want[..]);
        assert_eq!(log.iter().filter(|l| l.starts_with("mkdir")).count(), 2);
        assert_eq!(log.iter().filter(|l| l.starts_with("prompt")).count(), 1);
        assert_eq!(
            events,
            vec![
                ended(9, Ending::Unverified(VerifyClass::Signature)),
                ended(1, Ending::Answered)
            ]
        );
    }

    #[tokio::test]
    async fn ending_3_an_undecodable_delivery_goes_quiet_for_the_lease_and_a_sweep() {
        let mut f = fake();
        f.tasks.insert(7, Err(Unverified::Undecodable));
        f.claims = VecDeque::from([delivered(7, PART)]);
        let (log, events) = run(f).await;
        assert_eq!(
            log,
            strs(&[
                "beat 0",
                "claim",
                "verify",
                "sleep 990",
                "claim",
                "sleep 5",
                "uncite"
            ])
        );
        assert_eq!(
            events,
            vec![DriverEvent::Ended {
                task: None,
                ending: Ending::Undecodable
            }]
        );
    }

    #[tokio::test]
    async fn ending_4_a_stop_that_is_not_an_answer_is_reported_by_class_with_no_content() {
        for (err, class) in [
            (PlaneError::Refused, "prompt-refused"),
            (
                PlaneError::Declined {
                    code: ProtoErrCode::Unauthorized,
                    reason: "secret-reason".into(),
                },
                "prompt-refused",
            ),
            (PlaneError::Malformed, "prompt-malformed"),
            (PlaneError::Unavailable, "egress-unavailable"),
            (PlaneError::FrameTooLarge, "frame-bound"),
            (
                PlaneError::ReplyUnusable(maknae_proto::ReplyDefect::Empty),
                "reply-unusable",
            ),
        ] {
            let mut f = fake();
            f.claims = VecDeque::from([delivered(1, PART)]);
            f.replies = VecDeque::from([Err(err)]);
            let (log, events) = run(f).await;
            let at = log.iter().position(|l| l == "prompt 1").unwrap();
            let mut want = vec![
                format!("report stopped: {class}"),
                "uncite".into(),
                format!("close {CONV}"),
            ];
            want.extend(tail());
            assert_eq!(&log[at + 1..], &want[..]);
            assert_eq!(
                events,
                vec![ended(1, Ending::Stopped(stop_class_static(class)))]
            );
        }
    }

    fn stop_class_static(class: &str) -> &'static str {
        [
            "prompt-refused",
            "prompt-malformed",
            "egress-unavailable",
            "frame-bound",
            "reply-unusable",
            "step-budget",
            "too-many-tool-calls",
        ]
        .into_iter()
        .find(|c| *c == class)
        .unwrap()
    }

    #[tokio::test]
    async fn ending_4_a_budget_stop_is_reported_and_a_refused_stop_report_follows_the_refused_report_rule(
    ) {
        let mut f = fake();
        f.claims = VecDeque::from([delivered(1, PART)]);
        f.replies = (1..=8).map(|i| read(&format!("c{i}"), "/w/a")).collect();
        let (log, events) = run(f).await;
        assert_eq!(reports(&log), strs(&["report stopped: step-budget"]));
        assert_eq!(events, vec![ended(1, Ending::Stopped("step-budget"))]);

        let mut f = fake();
        f.claims = VecDeque::from([delivered(1, PART)]);
        let mut three = read("c1", "/w/a").unwrap();
        three.tool_calls = vec![three.tool_calls[0].clone(); 3];
        f.replies = VecDeque::from([Ok(three)]);
        f.reports = VecDeque::from([Ok(ReportOutcome::Refused(refused()))]);
        f.beats.push_back(Ok(BeatAnswer::Idle));
        let (log, events) = run(f).await;
        assert_eq!(
            reports(&log),
            strs(&["report stopped: too-many-tool-calls"])
        );
        let at = log.iter().position(|l| l.starts_with("report")).unwrap();
        assert_eq!(log[at + 1..at + 3], strs(&["beat 0", "uncite"])[..]);
        assert_eq!(events, vec![ended(1, Ending::Gone)]);
    }

    #[tokio::test]
    async fn ending_5_a_held_task_at_the_done_heartbeat_is_never_reported_and_its_partition_is_left_alone(
    ) {
        let mut f = fake();
        f.claims = VecDeque::from([delivered(1, PART)]);
        f.beats
            .push_back(Ok(BeatAnswer::State(view(TaskState::Held))));
        f.replies = VecDeque::from([answer("a1")]);
        let (log, events) = run(f).await;
        let at = log.iter().position(|l| l == "prompt 1").unwrap();
        let mut want = strs(&["beat 0", "uncite"]);
        want.extend(tail());
        assert_eq!(&log[at + 1..], &want[..]);
        assert_eq!(events, vec![ended(1, Ending::Held)]);
    }

    #[tokio::test]
    async fn ending_6_a_closed_or_idle_task_at_the_done_heartbeat_is_never_reported() {
        for beat in [
            Ok(BeatAnswer::State(view(TaskState::Closed))),
            Ok(BeatAnswer::Idle),
        ] {
            let mut f = fake();
            f.claims = VecDeque::from([delivered(1, PART)]);
            f.beats.push_back(beat);
            f.replies = VecDeque::from([answer("a1")]);
            let (log, events) = run(f).await;
            assert!(reports(&log).is_empty());
            assert_eq!(events, vec![ended(1, Ending::Gone)]);
        }
    }

    #[tokio::test]
    async fn the_done_heartbeat_is_retried_until_it_is_answered() {
        let mut f = fake();
        f.claims = VecDeque::from([delivered(1, PART)]);
        f.beats
            .extend([Ok(BeatAnswer::Refused(refused())), Err("reset".into())]);
        f.replies = VecDeque::from([answer("a1")]);
        let (log, _) = run(f).await;
        let at = log.iter().position(|l| l == "prompt 1").unwrap();
        assert_eq!(
            log[at + 1..at + 7],
            strs(&[
                "beat 0",
                "sleep 5",
                "beat 0",
                "sleep 1",
                "beat 0",
                "report a1"
            ])[..]
        );
    }

    #[tokio::test]
    async fn ending_7_a_task_left_over_from_before_a_restart_is_reported_and_never_rerun() {
        let mut f = Fake::default();
        f.beats.push_back(follow_ups(0, &[]));
        for n in 1..=2 {
            f.tasks.insert(n, Ok(signed(n, &format!("prompt-{n}"))));
        }
        f.claims = VecDeque::from([delivered(1, PART), delivered(2, PART)]);
        f.replies = VecDeque::from([answer("a2")]);
        let (log, events) = run(f).await;
        let mut want = strs(&[
            "beat 0",
            "claim",
            "verify",
            "cite t1",
            "report stopped: agent restarted",
            "uncite",
            "claim",
        ]);
        want.extend(fresh_start(2));
        assert_eq!(&log[..want.len()], &want[..]);
        assert_eq!(log.iter().filter(|l| l.starts_with("prompt")).count(), 1);
        assert_eq!(
            events,
            vec![ended(1, Ending::Restarted), ended(2, Ending::Answered)]
        );
    }

    #[tokio::test]
    async fn a_leftover_that_fails_verification_is_refused_not_reported_restarted() {
        let mut f = Fake::default();
        f.beats.push_back(follow_ups(0, &[]));
        f.tasks.insert(
            1,
            Err(Unverified::Failed {
                task: id(1),
                class: VerifyClass::NotKernel,
            }),
        );
        f.tasks.insert(2, Ok(signed(2, "prompt-2")));
        f.claims = VecDeque::from([delivered(1, PART), delivered(2, PART)]);
        f.replies = VecDeque::from([answer("a2")]);
        let (log, events) = run(f).await;
        assert_eq!(
            reports(&log),
            strs(&[
                "report refused: this task's kernel signature did not verify (not-kernel)",
                "report a2"
            ])
        );
        assert_eq!(
            events,
            vec![
                ended(1, Ending::Unverified(VerifyClass::NotKernel)),
                ended(2, Ending::Answered)
            ]
        );
    }

    #[tokio::test]
    async fn ending_8_shutdown_mid_task_sends_no_report() {
        let mut f = fake();
        f.claims = VecDeque::from([delivered(1, PART)]);
        f.shutdown_at_prompt = Some(1);
        f.replies = VecDeque::from([read("c1", "/w/a")]);
        let (log, events) = run(f).await;
        let at = log.iter().position(|l| l == "prompt 1").unwrap();
        assert_eq!(log[at + 1..], strs(&["uncite", "uncite"])[..]);
        assert!(reports(&log).is_empty());
        assert!(!log.iter().any(|l| l.starts_with("read")));
        assert_eq!(events, vec![ended(1, Ending::Shutdown)]);
    }

    #[tokio::test]
    async fn ending_9_a_lost_connection_reconnects_with_backoff_and_resumes_the_same_conversation()
    {
        let mut f = fake();
        f.claims = VecDeque::from([delivered(1, PART)]);
        f.beats.extend([
            Err("reset".into()),
            Err("reset".into()),
            follow_ups(0, &["fu-629"]),
        ]);
        f.replies = VecDeque::from([
            read("c1", "/w/a"),
            Err(PlaneError::Transport("kernel restarted".into())),
            answer("a1"),
        ]);
        let (log, events, w) = run_with(f, PersonaMode::Own).await;
        let at = log.iter().position(|l| l == "prompt 3").unwrap();
        assert_eq!(
            log[at + 1..at + 9],
            strs(&[
                "sleep 1", "beat 0", "sleep 2", "beat 0", "sleep 4", "beat 0", "prompt 4", "beat 1"
            ])[..]
        );
        assert_eq!(log.iter().filter(|l| l.starts_with("open")).count(), 1);
        assert_eq!(user_text(&w.lock().unwrap().sent[2][3]), "fu-629");
        assert_eq!(reports(&log), strs(&["report a1"]));
        assert_eq!(events, vec![ended(1, Ending::Answered)]);
    }

    #[tokio::test]
    async fn ending_9_a_reconnect_that_finds_the_task_held_or_gone_ends_it_without_a_report() {
        for (beat, ending) in [
            (Ok(BeatAnswer::State(view(TaskState::Held))), Ending::Held),
            (Ok(BeatAnswer::State(view(TaskState::Closed))), Ending::Gone),
            (Ok(BeatAnswer::Idle), Ending::Gone),
        ] {
            let mut f = fake();
            f.claims = VecDeque::from([delivered(1, PART)]);
            f.beats.push_back(beat);
            f.replies = VecDeque::from([Err(PlaneError::Transport("leaf expired".into()))]);
            let (log, events) = run(f).await;
            let at = log.iter().position(|l| l == "prompt 1").unwrap();
            let mut want = strs(&["sleep 1", "beat 0", "uncite"]);
            if ending == Ending::Gone {
                want.push(format!("close {CONV}"));
            }
            want.extend(tail());
            assert_eq!(&log[at + 1..], &want[..]);
            assert_eq!(events, vec![ended(1, ending)]);
        }
    }

    #[tokio::test]
    async fn ending_9_a_redelivery_of_the_held_id_resumes_it_and_does_not_start_a_new_one() {
        let mut f = fake();
        f.claims = VecDeque::from([delivered(1, PART), delivered(1, PART)]);
        f.beats.push_back(Ok(BeatAnswer::Refused(refused())));
        f.replies = VecDeque::from([
            Err(PlaneError::Transport("leaf expired".into())),
            answer("a1"),
        ]);
        let (log, events) = run(f).await;
        let at = log.iter().position(|l| l == "prompt 1").unwrap();
        assert_eq!(
            log[at + 1..at + 10],
            strs(&[
                "sleep 1",
                "beat 0",
                "uncite",
                "claim",
                "verify",
                "cite t1",
                "prompt 1",
                "beat 0",
                "report a1"
            ])[..]
        );
        assert_eq!(log.iter().filter(|l| l.starts_with("open")).count(), 1);
        assert_eq!(log.iter().filter(|l| l.starts_with("mkdir")).count(), 2);
        assert_eq!(events, vec![ended(1, Ending::Answered)]);
    }

    #[tokio::test]
    async fn a_redelivery_of_another_id_drops_the_held_task_and_starts_fresh() {
        let mut f = fake();
        f.claims = VecDeque::from([delivered(1, PART), delivered(2, PART)]);
        f.beats.push_back(Ok(BeatAnswer::Refused(refused())));
        f.replies = VecDeque::from([Err(PlaneError::Transport("x".into())), answer("a2")]);
        let (log, events) = run(f).await;
        assert_eq!(log.iter().filter(|l| l.starts_with("open")).count(), 2);
        assert_eq!(reports(&log), strs(&["report a2"]));
        assert_eq!(events, vec![ended(2, Ending::Answered)]);
    }

    #[tokio::test]
    async fn a_held_task_that_fails_verification_on_redelivery_is_refused_and_dropped() {
        let mut f = fake();
        f.claims = VecDeque::from([delivered(1, PART), delivered(8, PART)]);
        f.tasks.insert(
            8,
            Err(Unverified::Failed {
                task: id(1),
                class: VerifyClass::Key,
            }),
        );
        f.beats.push_back(Ok(BeatAnswer::Refused(refused())));
        f.replies = VecDeque::from([Err(PlaneError::Transport("x".into()))]);
        let (mut d, w) = driver(f, PersonaMode::Own);
        d.run().await;
        assert!(d.held.is_none());
        let log = w.lock().unwrap().log.clone();
        assert_eq!(
            reports(&log),
            strs(&["report refused: this task's kernel signature did not verify (key)"])
        );
    }

    #[tokio::test]
    async fn ending_1_a_resume_that_finds_the_answer_already_held_reports_it() {
        let f = Fake {
            replies: VecDeque::from([answer("held-629")]),
            ..Fake::default()
        };
        let (mut d, w) = driver(f, PersonaMode::Own);
        let mut session = Session::new(CONV, "q", d.config.budget, d.config.context, None);
        let first = session.run(&mut d.plane, &mut |_| {}).await;
        assert_eq!(first.answer.as_deref(), Some("held-629"));
        let held = Held {
            id: id(1),
            session,
            seen: 0,
            last_beat: Duration::ZERO,
            answer: first.answer,
            resumes: 0,
        };
        d.work(held, Then::Resume(vec![])).await;
        let log = w.lock().unwrap().log.clone();
        assert_eq!(
            log,
            strs(&["prompt 1", "beat 0", "report held-629", "uncite"])
        );
        assert_eq!(w.lock().unwrap().events, vec![ended(1, Ending::Answered)]);
    }

    #[tokio::test]
    async fn a_session_the_kernel_will_not_open_is_reported_stopped() {
        for e in [PlaneError::Refused, PlaneError::Transport("reset".into())] {
            let mut f = fake();
            f.claims = VecDeque::from([delivered(1, PART)]);
            f.open_error = Some(e);
            let (log, events) = run(f).await;
            let at = log.iter().position(|l| l.starts_with("open")).unwrap();
            let mut want = strs(&["report stopped: session-unavailable", "uncite"]);
            want.extend(tail());
            assert_eq!(&log[at + 1..], &want[..]);
            assert_eq!(events, vec![ended(1, Ending::Stopped(SESSION_UNAVAILABLE))]);
        }
    }

    #[tokio::test]
    async fn a_fixed_report_refused_then_held_is_not_sent_again() {
        let mut f = fake();
        f.tasks.insert(
            9,
            Err(Unverified::Failed {
                task: id(9),
                class: VerifyClass::Agent,
            }),
        );
        f.claims = VecDeque::from([delivered(9, PART)]);
        f.reports = VecDeque::from([Ok(ReportOutcome::Refused(refused()))]);
        f.beats
            .push_back(Ok(BeatAnswer::State(view(TaskState::Held))));
        let (log, events) = run(f).await;
        assert_eq!(reports(&log).len(), 1);
        assert_eq!(events, vec![ended(9, Ending::Held)]);
    }

    #[tokio::test]
    async fn a_fixed_report_that_does_not_fit_is_never_retried() {
        let mut f = Fake::default();
        f.beats.push_back(follow_ups(0, &[]));
        f.tasks.insert(1, Ok(signed(1, "p")));
        f.claims = VecDeque::from([delivered(1, PART)]);
        f.reports = VecDeque::from([Ok(ReportOutcome::TooLarge)]);
        let (log, events) = run(f).await;
        assert_eq!(
            log,
            strs(&[
                "beat 0",
                "claim",
                "verify",
                "cite t1",
                "report stopped: agent restarted",
                "uncite",
                "sleep 990",
                "claim",
                "sleep 5",
                "uncite"
            ])
        );
        assert_eq!(events, vec![ended(1, Ending::Unsendable)]);
    }

    #[tokio::test]
    async fn shutdown_while_reporting_or_reconnecting_ends_with_no_further_request() {
        let mut f = fake();
        f.claims = VecDeque::from([delivered(1, PART)]);
        f.shutdown_on_report = true;
        f.reports = VecDeque::from([Ok(ReportOutcome::Refused(refused()))]);
        f.replies = VecDeque::from([answer("a1")]);
        let (log, events) = run(f).await;
        assert_eq!(
            &log[log.len() - 3..],
            &strs(&["report a1", "uncite", "uncite"])[..]
        );
        assert_eq!(events, vec![ended(1, Ending::Shutdown)]);

        for reply in [answer("a1"), Err(PlaneError::Transport("reset".into()))] {
            let mut f = fake();
            f.claims = VecDeque::from([delivered(1, PART)]);
            f.shutdown_at_prompt = Some(1);
            f.replies = VecDeque::from([reply]);
            let (log, events) = run(f).await;
            assert!(!log
                .iter()
                .skip(1)
                .any(|l| l.starts_with("beat") || l.starts_with("report")));
            assert_eq!(events, vec![ended(1, Ending::Shutdown)]);
        }
    }
}
