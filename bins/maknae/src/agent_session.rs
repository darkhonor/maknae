//! `maknae agent list` and `maknae agent <name>` (#630): the agent list, the
//! full-screen session over `screen::run`, and the plain-line session, wired
//! to the kernel's tasker verbs. What the session decides is
//! `maknae_agent::tasking::Book`'s.
use crate::screen::plain::{Line, Lines};
use crate::screen::run::{Caller, Driver, Exit, Pace, Step};
use crate::screen::term::{both_terminals, Session, TermError};
use crate::stderr::errln;
use maknae_agent::screen::blocks::{Conversation, EntryId, EntryKind};
use maknae_agent::screen::{Commands, HeaderLine, MenuItem};
use maknae_agent::tasking::book::{Answer, Book, Entered, Failure, Op, Standing};
use maknae_agent::tasking::text;
use maknae_config::AgentId;
use maknae_loop::tasker::{AgentRoster, TaskerClient, TaskerError};
use maknae_proto::{SecretText, TaskCursor, TaskPage, TaskRef, TaskReportPage, TaskView};
use maknae_vault::PlaneClient;
use std::process::ExitCode;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::mpsc;
use tokio::time::Instant;
use zeroize::Zeroizing;

/// A leaf this close to its NotAfter is minted again before the next verb.
const REMINT_WITHIN_SECS: u64 = 60;
const PLAIN_TICK: Duration = Duration::from_millis(250);

/// The tasker verbs the session sends, so tests can stand in for the kernel.
pub(crate) trait Tasker {
    async fn agents(&self) -> Result<AgentRoster, TaskerError>;
    async fn submit(&self, agent: &AgentId, text: SecretText) -> Result<TaskView, TaskerError>;
    async fn add(&self, task: &TaskRef, text: SecretText) -> Result<TaskView, TaskerError>;
    async fn status(&self, task: &TaskRef) -> Result<TaskView, TaskerError>;
    async fn stop(&self, task: &TaskRef) -> Result<TaskView, TaskerError>;
    async fn drop(&self, task: &TaskRef) -> Result<TaskView, TaskerError>;
    async fn list_page(
        &self,
        agent: &AgentId,
        after: Option<TaskCursor>,
    ) -> Result<TaskPage, TaskerError>;
    async fn list(&self, agent: &AgentId) -> Result<Vec<TaskView>, TaskerError>;
    async fn collect(
        &self,
        agent: &AgentId,
        after: Option<TaskCursor>,
    ) -> Result<TaskReportPage, TaskerError>;
}

impl Tasker for TaskerClient {
    async fn agents(&self) -> Result<AgentRoster, TaskerError> {
        self.all_agents().await
    }
    async fn submit(&self, agent: &AgentId, text: SecretText) -> Result<TaskView, TaskerError> {
        TaskerClient::submit(self, agent, text).await
    }
    async fn add(&self, task: &TaskRef, text: SecretText) -> Result<TaskView, TaskerError> {
        TaskerClient::add(self, task, text).await
    }
    async fn status(&self, task: &TaskRef) -> Result<TaskView, TaskerError> {
        TaskerClient::status(self, task).await
    }
    async fn stop(&self, task: &TaskRef) -> Result<TaskView, TaskerError> {
        TaskerClient::stop(self, task).await
    }
    async fn drop(&self, task: &TaskRef) -> Result<TaskView, TaskerError> {
        TaskerClient::drop(self, task).await
    }
    async fn list_page(
        &self,
        agent: &AgentId,
        after: Option<TaskCursor>,
    ) -> Result<TaskPage, TaskerError> {
        TaskerClient::list_page(self, agent, after).await
    }
    async fn list(&self, agent: &AgentId) -> Result<Vec<TaskView>, TaskerError> {
        TaskerClient::list(self, agent).await
    }
    async fn collect(
        &self,
        agent: &AgentId,
        after: Option<TaskCursor>,
    ) -> Result<TaskReportPage, TaskerError> {
        TaskerClient::collect(self, agent, after).await
    }
}

/// The session's plane leaf, minted once and again only near its NotAfter.
pub(crate) trait Leaf {
    /// Unix seconds; `None` before a mint.
    fn not_after(&self) -> Option<u64>;
    async fn remint(&self) -> Result<(), String>;
}

struct PlaneLeaf(Arc<PlaneClient>);

impl Leaf for PlaneLeaf {
    fn not_after(&self) -> Option<u64> {
        self.0.leaf_not_after_secs()
    }
    async fn remint(&self) -> Result<(), String> {
        self.0.mint().await.map(|_| ()).map_err(|e| e.to_string())
    }
}

#[derive(Debug)]
pub(crate) enum Event {
    Done(Result<Answer, Failure>),
    LoginExpired,
}

/// One agent's verbs over one tasker client and leaf.
pub(crate) struct Kernel<T, L> {
    tasker: T,
    leaf: L,
    login_expires_at: u64,
    agent: AgentId,
}

impl<T: Tasker, L: Leaf> Kernel<T, L> {
    async fn send(&self, op: Op, now: u64) -> Event {
        let fresh = self
            .leaf
            .not_after()
            .is_some_and(|at| now.saturating_add(REMINT_WITHIN_SECS) < at);
        if !fresh {
            if crate::agent::login_expired(self.login_expires_at, now) {
                return Event::LoginExpired;
            }
            if self.leaf.remint().await.is_err() {
                return Event::Done(Err(Failure::Unreachable { after_write: false }));
            }
        }
        Event::Done(self.perform(op).await)
    }

    async fn perform(&self, op: Op) -> Result<Answer, Failure> {
        let (t, a) = (&self.tasker, &self.agent);
        let answer = match op {
            Op::Collect { after } => t.collect(a, after).await.map(Answer::Reports),
            Op::Poll { after } => t.list_page(a, after).await.map(Answer::Page),
            Op::ListAll => t.list(a).await.map(Answer::Tasks),
            Op::Submit { text } => t.submit(a, text).await.map(Answer::View),
            Op::Add { task, text } => t.add(&task, text).await.map(Answer::View),
            Op::Stop { task } => t.stop(&task).await.map(Answer::View),
            Op::Drop { task } => t.drop(&task).await.map(Answer::View),
            Op::Status { task } => t.status(&task).await.map(Answer::View),
        };
        answer.map_err(failure)
    }

    /// Sends each op in turn until the session drops its sender.
    async fn serve(&self, mut ops: mpsc::UnboundedReceiver<Op>, events: mpsc::Sender<Event>) {
        while let Some(op) = ops.recv().await {
            if events.send(self.send(op, unix_now()).await).await.is_err() {
                return;
            }
        }
    }
}

fn failure(e: TaskerError) -> Failure {
    match e {
        TaskerError::Refused { outcome_unknown } => Failure::Refused { outcome_unknown },
        TaskerError::Unreachable { after_write, .. } => Failure::Unreachable { after_write },
        TaskerError::Protocol(why) => Failure::Protocol(why),
    }
}

fn unix_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

/// The roster's entry for `name`, or the line that refuses it.
pub(crate) fn admit(roster: &AgentRoster, name: &str) -> Result<(AgentId, Standing), String> {
    let Ok(agent) = AgentId::parse(name) else {
        return Err(text::not_an_agent(name));
    };
    match roster.entries.iter().find(|e| e.agent == name) {
        Some(entry) => match Standing::of(entry.standing) {
            Some(standing) => Ok((agent, standing)),
            None => Err(text::undecided_agent(name)),
        },
        None if roster.undecided > 0 => Err(text::LIST_INCOMPLETE_REFUSAL.into()),
        None => Err(text::not_an_agent(name)),
    }
}

fn roster_failure(e: &TaskerError) -> String {
    match e {
        TaskerError::Refused { .. } => "maknae: the kernel refused the agent list".into(),
        TaskerError::Unreachable { why, .. } => {
            format!("maknae: the kernel could not be reached: {why}")
        }
        TaskerError::Protocol(why) => format!("maknae: {why}"),
    }
}

/// The CLI's plane client, minted, and the session's input bound.
struct Plane {
    client: Arc<PlaneClient>,
    tasker: TaskerClient,
    input_cap: usize,
    login_expires_at: u64,
}

async fn connect() -> Result<Plane, String> {
    maknae_crypto::init().map_err(|e| maknae_vault::crypto_refusal_message(&e))?;
    let dir = crate::cli::resolve_config_dir();
    let document = maknae_config::load_config(&dir, &crate::cli::cli_config_specs())
        .map_err(|e| e.to_string())?;
    let transport =
        maknae_config::transport_from_section(document.section(maknae_config::TRANSPORT_SECTION))
            .map_err(|e| e.to_string())?;
    let session = crate::login::user_session(&document, &dir)?;
    let client =
        Arc::new(PlaneClient::for_user(&document, &dir, session.token).map_err(|e| e.to_string())?);
    let ca = maknae_vault::load_ca_pin(&dir).map_err(|e| e.to_string())?;
    let trust = maknae_vault::TrustBundle::from_pins(&[&ca]).map_err(|e| e.to_string())?;
    client.mint().await.map_err(|e| e.to_string())?;
    let input_cap = transport.prompt_max_bytes;
    Ok(Plane {
        tasker: TaskerClient::new(transport, Arc::clone(&client), trust),
        client,
        input_cap,
        login_expires_at: session.expires_at,
    })
}

async fn retire(client: &PlaneClient) {
    if let Err(e) = client.shutdown().await {
        errln!("maknae-vault: {e}");
    }
}

pub(crate) async fn run_list() -> ExitCode {
    let plane = match connect().await {
        Ok(plane) => plane,
        Err(e) => {
            errln!("maknae: {e}");
            return ExitCode::FAILURE;
        }
    };
    let roster = plane.tasker.all_agents().await;
    retire(&plane.client).await;
    match roster {
        Ok(roster) => {
            let mut out = std::io::stdout().lock();
            for line in text::agent_list_lines(&roster.entries, roster.undecided) {
                crate::stderr::line(&mut out, format_args!("{line}"));
            }
            ExitCode::SUCCESS
        }
        Err(e) => {
            errln!("{}", roster_failure(&e));
            ExitCode::FAILURE
        }
    }
}

pub(crate) async fn run_session(name: &str, wait: bool) -> ExitCode {
    let plane = match connect().await {
        Ok(plane) => plane,
        Err(e) => {
            errln!("maknae: {e}");
            return ExitCode::FAILURE;
        }
    };
    let io = if both_terminals() {
        Io::Screen(Box::new(Session::enter))
    } else {
        match Lines::stdio(plane.input_cap) {
            Ok(lines) => Io::Plain(lines),
            Err(e) => {
                retire(&plane.client).await;
                errln!("maknae: {e}");
                return ExitCode::FAILURE;
            }
        }
    };
    let leaf = PlaneLeaf(Arc::clone(&plane.client));
    let end = open(
        plane.tasker,
        leaf,
        plane.login_expires_at,
        name,
        wait,
        plane.input_cap,
        io,
    )
    .await;
    if !matches!(end, End::Signal(_)) {
        retire(&plane.client).await;
    }
    end.exit_code()
}

pub(crate) type Enter = Box<dyn FnOnce() -> Result<Session, TermError>>;

pub(crate) enum Io {
    Screen(Enter),
    Plain(Lines),
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) enum End {
    Left,
    Signal(i32),
    Failed,
}

impl End {
    fn exit_code(&self) -> ExitCode {
        match self {
            End::Left => ExitCode::SUCCESS,
            End::Signal(signal) => {
                ExitCode::from(u8::try_from(128i32.saturating_add(*signal)).unwrap_or(u8::MAX))
            }
            End::Failed => ExitCode::FAILURE,
        }
    }
}

/// Checks `name` against the agent list and runs the session with it.
pub(crate) async fn open<T: Tasker, L: Leaf>(
    tasker: T,
    leaf: L,
    login_expires_at: u64,
    name: &str,
    wait: bool,
    input_cap: usize,
    io: Io,
) -> End {
    let roster = match tasker.agents().await {
        Ok(roster) => roster,
        Err(e) => {
            errln!("{}", roster_failure(&e));
            return End::Failed;
        }
    };
    let (agent, standing) = match admit(&roster, name) {
        Ok(admitted) => admitted,
        Err(refusal) => {
            errln!("{refusal}");
            return End::Failed;
        }
    };
    if let Some(Err(e)) = roster.banner.as_ref().map(maknae_proto::check_banner) {
        errln!("maknae: the kernel's banner is not valid ({e}); the session was not opened");
        return End::Failed;
    }
    let kernel = Kernel {
        tasker,
        leaf,
        login_expires_at,
        agent,
    };
    match io {
        Io::Screen(enter) => full_screen(&kernel, standing, roster.banner, input_cap, enter).await,
        Io::Plain(mut lines) => plain(&kernel, standing, wait, &mut lines).await,
    }
}

fn ms(start: Instant) -> u64 {
    u64::try_from(start.elapsed().as_millis()).unwrap_or(u64::MAX)
}

/// Sends the book's next due op, if any.
fn pump(book: &mut Book, ops: &mpsc::UnboundedSender<Op>, now: u64, conv: &mut Conversation) {
    if let Some(op) = book.next_op(now, conv) {
        if ops.send(op).is_err() {
            book.done(Err(Failure::Unreachable { after_write: false }), now, conv);
        }
    }
}

fn apply(book: &mut Book, event: Event, now: u64, conv: &mut Conversation) {
    match event {
        Event::Done(answer) => book.done(answer, now, conv),
        Event::LoginExpired => book.stop(crate::agent::LOGIN_EXPIRED, conv),
    }
}

struct Screen {
    book: Book,
    ops: mpsc::UnboundedSender<Op>,
    start: Instant,
}

impl Commands for Screen {
    fn header(&self) -> HeaderLine {
        self.book.header()
    }
    fn menu(&self, prefix: &str) -> Vec<MenuItem> {
        text::menu(prefix)
    }
}

impl Caller for Screen {
    type Event = Event;

    fn status(&self) -> &[String] {
        self.book.status()
    }

    fn pace(&self) -> Pace {
        if self.book.stopped() {
            Pace::Idle
        } else if self.book.animating() {
            Pace::Animating
        } else {
            Pace::Open
        }
    }

    fn tick(&mut self, conversation: &mut Conversation) -> Step {
        let now = ms(self.start);
        let changed = self.book.tick(now, conversation);
        pump(&mut self.book, &self.ops, now, conversation);
        if changed {
            Step::Changed
        } else {
            Step::Unchanged
        }
    }

    fn event(&mut self, event: Event, conversation: &mut Conversation) -> Step {
        let now = ms(self.start);
        apply(&mut self.book, event, now, conversation);
        pump(&mut self.book, &self.ops, now, conversation);
        Step::Changed
    }

    fn submit(&mut self, text: Zeroizing<String>, conversation: &mut Conversation) -> Step {
        let now = ms(self.start);
        match self.book.enter(text, now, conversation) {
            Entered::Leave => Step::Leave,
            Entered::Stay => {
                pump(&mut self.book, &self.ops, now, conversation);
                Step::Changed
            }
        }
    }
}

async fn full_screen<T: Tasker, L: Leaf>(
    kernel: &Kernel<T, L>,
    standing: Standing,
    banner: Option<maknae_proto::BannerSpec>,
    input_cap: usize,
    enter: Enter,
) -> End {
    let (op_tx, op_rx) = mpsc::unbounded_channel();
    let (event_tx, event_rx) = mpsc::channel(4);
    let start = Instant::now();
    let mut conversation = Conversation::for_prompt_ceiling(maknae_config::PROMPT_MAX_CEILING);
    let mut book = Book::new(kernel.agent.as_str(), standing, false);
    pump(&mut book, &op_tx, 0, &mut conversation);
    let screen = Screen {
        book,
        ops: op_tx,
        start,
    };
    let driver = match Driver::new(enter, screen, event_rx, banner, conversation, input_cap) {
        Ok(driver) => driver,
        Err(e) => {
            errln!("maknae: {e}");
            return End::Failed;
        }
    };
    let run = driver.run();
    tokio::pin!(run);
    let (screen, result) = tokio::select! {
        out = &mut run => out,
        () = kernel.serve(op_rx, event_tx) => run.await,
    };
    let stopped = screen.book.stopped();
    drop(screen);
    screen_end(result, stopped)
}

fn screen_end(result: Result<Exit, TermError>, stopped: bool) -> End {
    match result {
        Ok(Exit::Signal(signal)) => End::Signal(signal),
        Ok(Exit::Bye | Exit::InputClosed) if stopped => {
            errln!("maknae: {}", crate::agent::LOGIN_EXPIRED);
            End::Failed
        }
        Ok(Exit::Bye | Exit::InputClosed) => End::Left,
        Err(e) => {
            errln!("maknae: {e}");
            End::Failed
        }
    }
}

/// Writes every entry after `printed` but the person's own requests, and
/// counts it seen.
fn print_new(
    conv: &mut Conversation,
    printed: &mut Option<EntryId>,
    lines: &mut Lines,
) -> Result<(), TermError> {
    let Some(last) = conv.last() else {
        return Ok(());
    };
    let mut at = match *printed {
        Some(p) if p >= last => return Ok(()),
        Some(p) if conv.has_item(p) => conv.next_item(p),
        Some(_) => conv.first(),
        None => conv.first(),
    };
    while let Some(id) = at {
        if conv.kind(id) != Some(EntryKind::Request) {
            let len = conv.segments(id).map(str::len).sum();
            let mut entry = Zeroizing::new(String::with_capacity(len));
            conv.segments(id).for_each(|s| entry.push_str(s));
            lines.write_line(&entry)?;
        }
        conv.mark_seen(id..=id);
        *printed = Some(id);
        at = conv.next_item(id).filter(|next| *next <= last);
    }
    Ok(())
}

async fn plain<T: Tasker, L: Leaf>(
    kernel: &Kernel<T, L>,
    standing: Standing,
    wait: bool,
    lines: &mut Lines,
) -> End {
    let (op_tx, op_rx) = mpsc::unbounded_channel();
    let (event_tx, mut event_rx) = mpsc::channel(4);
    let serve = kernel.serve(op_rx, event_tx);
    tokio::pin!(serve);
    let start = Instant::now();
    let mut conv = Conversation::for_prompt_ceiling(maknae_config::PROMPT_MAX_CEILING);
    let mut book = Book::new(kernel.agent.as_str(), standing, true);
    let mut printed = None;
    let (mut ended, mut bye, mut served) = (false, false, false);
    loop {
        let now = ms(start);
        pump(&mut book, &op_tx, now, &mut conv);
        if let Err(e) = print_new(&mut conv, &mut printed, lines) {
            errln!("maknae: {e}");
            return End::Failed;
        }
        if ended && book.settled(wait && !bye) {
            return if book.stopped() {
                End::Failed
            } else {
                End::Left
            };
        }
        if ended {
            book.hurry();
        }
        tokio::select! {
            line = lines.next_line(), if !ended => match line {
                Ok(Line::Text(text)) => {
                    if book.enter(text, ms(start), &mut conv) == Entered::Leave {
                        (ended, bye) = (true, true);
                    }
                }
                Ok(Line::Refused) => {}
                Ok(Line::End) => ended = true,
                Err(e) => {
                    errln!("maknae: {e}");
                    return End::Failed;
                }
            },
            Some(event) = event_rx.recv() => apply(&mut book, event, ms(start), &mut conv),
            () = tokio::time::sleep(PLAIN_TICK) => {
                book.tick(ms(start), &mut conv);
            }
            () = &mut serve, if !served => served = true,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use maknae_proto::{AgentEntry, AgentStanding, BannerSpec, TaskId, TaskReportView, TaskState};
    use std::os::fd::OwnedFd;
    use std::sync::atomic::{AtomicU32, Ordering};
    use std::sync::Mutex;

    const BOUND: Duration = Duration::from_secs(20);

    #[derive(Default)]
    struct State {
        calls: Vec<&'static str>,
        tasks: Vec<TaskView>,
        reports: Vec<TaskReportView>,
        seq: u64,
        report_with: Option<&'static str>,
    }

    #[derive(Clone)]
    struct Fake {
        roster: AgentRoster,
        state: Arc<Mutex<State>>,
    }

    impl Fake {
        fn new(entries: &[(&str, AgentStanding)], undecided: u32) -> Fake {
            Fake {
                roster: AgentRoster {
                    entries: entries
                        .iter()
                        .map(|(agent, standing)| AgentEntry {
                            agent: (*agent).into(),
                            standing: *standing,
                            waiting: 0,
                        })
                        .collect(),
                    undecided,
                    banner: None,
                },
                state: Arc::default(),
            }
        }

        fn calls(&self) -> Vec<&'static str> {
            self.state.lock().unwrap().calls.clone()
        }

        fn note(&self, name: &'static str) {
            self.state.lock().unwrap().calls.push(name);
        }

        fn call(&self, name: &'static str) -> std::sync::MutexGuard<'_, State> {
            let mut state = self.state.lock().unwrap();
            state.calls.push(name);
            state
        }
    }

    fn view(seq: u64, state: TaskState) -> TaskView {
        TaskView {
            task: TaskRef::from_id(&TaskId([seq as u8; 16])),
            agent: "hobi".into(),
            state,
            close: None,
            submitted_secs: 0,
            elapsed_secs: 0,
            actions: 0,
            last_action_secs: None,
            cursor: TaskCursor::from_seq(seq),
        }
    }

    impl Tasker for Fake {
        async fn agents(&self) -> Result<AgentRoster, TaskerError> {
            self.note("agents");
            Ok(self.roster.clone())
        }
        async fn submit(&self, _: &AgentId, _: SecretText) -> Result<TaskView, TaskerError> {
            let mut s = self.call("submit");
            s.seq += 1;
            let seq = s.seq;
            let mut v = view(seq, TaskState::Working);
            if let Some(text) = s.report_with {
                v.state = TaskState::Reported;
                s.reports.push(TaskReportView {
                    task: v.task.clone(),
                    agent: "hobi".into(),
                    close: None,
                    text: SecretText(Zeroizing::new(text.into())),
                    at_secs: 0,
                    cursor: TaskCursor::from_seq(seq),
                });
            }
            s.tasks.push(v.clone());
            Ok(v)
        }
        async fn add(&self, _: &TaskRef, _: SecretText) -> Result<TaskView, TaskerError> {
            self.note("add");
            Err(TaskerError::Protocol("unused".into()))
        }
        async fn status(&self, _: &TaskRef) -> Result<TaskView, TaskerError> {
            self.note("status");
            Err(TaskerError::Protocol("unused".into()))
        }
        async fn stop(&self, _: &TaskRef) -> Result<TaskView, TaskerError> {
            self.note("stop");
            Err(TaskerError::Protocol("unused".into()))
        }
        async fn drop(&self, _: &TaskRef) -> Result<TaskView, TaskerError> {
            self.note("drop");
            Err(TaskerError::Protocol("unused".into()))
        }
        async fn list_page(
            &self,
            _: &AgentId,
            after: Option<TaskCursor>,
        ) -> Result<TaskPage, TaskerError> {
            let s = self.call("list_page");
            let after = after.map_or(0, |a| a.seq());
            let entries = s
                .tasks
                .iter()
                .filter(|t| t.cursor.seq() > after)
                .cloned()
                .collect();
            Ok(TaskPage {
                entries,
                next: None,
            })
        }
        async fn list(&self, _: &AgentId) -> Result<Vec<TaskView>, TaskerError> {
            Ok(self.call("list").tasks.clone())
        }
        async fn collect(
            &self,
            _: &AgentId,
            after: Option<TaskCursor>,
        ) -> Result<TaskReportPage, TaskerError> {
            let mut s = self.call("collect");
            if let Some(after) = after {
                let upto = after.seq();
                s.reports.retain(|r| r.cursor.seq() > upto);
                s.tasks.retain(|t| t.cursor.seq() > upto);
            }
            Ok(TaskReportPage {
                entries: s.reports.clone(),
                next: None,
            })
        }
    }

    struct FakeLeaf {
        not_after: Mutex<Option<u64>>,
        mints: AtomicU32,
    }

    impl FakeLeaf {
        fn expiring_at(at: u64) -> FakeLeaf {
            FakeLeaf {
                not_after: Mutex::new(Some(at)),
                mints: AtomicU32::new(0),
            }
        }
    }

    impl Leaf for FakeLeaf {
        fn not_after(&self) -> Option<u64> {
            *self.not_after.lock().unwrap()
        }
        async fn remint(&self) -> Result<(), String> {
            self.mints.fetch_add(1, Ordering::SeqCst);
            *self.not_after.lock().unwrap() = Some(unix_now() + 3600);
            Ok(())
        }
    }

    fn fresh_leaf() -> FakeLeaf {
        FakeLeaf::expiring_at(unix_now() + 3600)
    }

    fn agent() -> AgentId {
        AgentId::parse("hobi").unwrap()
    }

    /// A plain-line session's descriptors: input already written and closed,
    /// output and diagnostics read back after it ends.
    struct Pipes {
        lines: Option<Lines>,
        output: OwnedFd,
    }

    fn pipes(input: &str) -> Pipes {
        let (in_r, in_w) = nix::unistd::pipe().unwrap();
        let (out_r, out_w) = nix::unistd::pipe().unwrap();
        let (_err_r, err_w) = nix::unistd::pipe().unwrap();
        nix::unistd::write(&in_w, input.as_bytes()).unwrap();
        drop(in_w);
        Pipes {
            lines: Some(Lines::new(in_r, out_w, err_w, 4096).unwrap()),
            output: out_r,
        }
    }

    impl Pipes {
        fn io(&mut self) -> Io {
            Io::Plain(self.lines.take().unwrap())
        }

        fn output(self) -> String {
            nix::fcntl::fcntl(
                &self.output,
                nix::fcntl::FcntlArg::F_SETFL(nix::fcntl::OFlag::O_NONBLOCK),
            )
            .unwrap();
            let mut out = Vec::new();
            let mut chunk = [0u8; 4096];
            while let Ok(n @ 1..) = nix::unistd::read(&self.output, &mut chunk) {
                out.extend_from_slice(&chunk[..n]);
            }
            String::from_utf8(out).unwrap()
        }
    }

    async fn bounded<F: std::future::Future>(f: F) -> F::Output {
        tokio::time::timeout(BOUND, f)
            .await
            .expect("the session did not end in time")
    }

    #[test]
    fn a_name_missing_from_an_incomplete_list_says_try_again() {
        let mut fake = Fake::new(&[("hobi", AgentStanding::Enrolled)], 1);
        assert_eq!(
            admit(&fake.roster, "jin"),
            Err("maknae: could not check every agent right now; try again".into())
        );
        assert_eq!(
            admit(&fake.roster, "summarize my files"),
            Err(text::not_an_agent("summarize my files")),
            "a name no agent can have is never 'try again'"
        );
        assert_eq!(
            admit(&fake.roster, "hobi"),
            Ok((agent(), Standing::Enrolled))
        );
        fake.roster.entries.push(AgentEntry {
            agent: "v".into(),
            standing: AgentStanding::Undecided,
            waiting: 0,
        });
        assert_eq!(
            admit(&fake.roster, "v"),
            Err("maknae: the kernel could not decide whether you can task v; try again".into())
        );
        fake.roster.undecided = 0;
        assert_eq!(
            admit(&fake.roster, "jin"),
            Err("maknae: jin is not an agent you can task; see maknae agent list".into())
        );
    }

    #[tokio::test]
    async fn a_name_off_the_list_is_refused_and_never_run_as_a_prompt() {
        let fake = Fake::new(&[("hobi", AgentStanding::Enrolled)], 0);
        let mut io = pipes("");
        let end = bounded(open(
            fake.clone(),
            fresh_leaf(),
            u64::MAX,
            "summarize my files",
            false,
            4096,
            io.io(),
        ))
        .await;
        assert_eq!(end, End::Failed);
        assert_eq!(fake.calls(), ["agents"], "nothing was submitted");
        assert_eq!(io.output(), "");
        for name in ["jin", "list", "help"] {
            assert_eq!(
                admit(&fake.roster, name),
                Err(text::not_an_agent(name)),
                "{name}"
            );
        }
    }

    #[tokio::test]
    async fn an_invalid_banner_refuses_to_open_the_session() {
        let mut fake = Fake::new(&[("hobi", AgentStanding::Enrolled)], 0);
        fake.roster.banner = Some(BannerSpec {
            text: "SECRET\u{1b}[2J".into(),
            color: None,
        });
        let mut io = pipes("hello\n");
        let end = bounded(open(
            fake.clone(),
            fresh_leaf(),
            u64::MAX,
            "hobi",
            false,
            4096,
            io.io(),
        ))
        .await;
        assert_eq!(end, End::Failed);
        assert_eq!(fake.calls(), ["agents"]);
    }

    #[tokio::test]
    async fn plain_mode_exits_after_acknowledgement_and_wait_waits_for_reports() {
        let fake = Fake::new(&[("hobi", AgentStanding::Enrolled)], 0);
        let mut io = pipes("tidy my downloads\n");
        let end = bounded(open(
            fake.clone(),
            fresh_leaf(),
            u64::MAX,
            "hobi",
            false,
            4096,
            io.io(),
        ))
        .await;
        assert_eq!(end, End::Left);
        let out = io.output();
        assert!(out.contains("#1 submitted\n"), "{out}");
        assert!(
            !out.contains("tidy my downloads"),
            "the request is not echoed: {out}"
        );
        assert_eq!(fake.calls().iter().filter(|c| **c == "submit").count(), 1);

        let fake = Fake::new(&[("hobi", AgentStanding::Enrolled)], 0);
        fake.state.lock().unwrap().report_with = Some("moved 3 files\u{1b}[2J");
        let mut io = pipes("tidy my downloads\n");
        let end = bounded(open(
            fake.clone(),
            fresh_leaf(),
            u64::MAX,
            "hobi",
            true,
            4096,
            io.io(),
        ))
        .await;
        assert_eq!(end, End::Left);
        let out = io.output();
        assert!(
            out.contains("hobi #1\nmoved 3 files\\u{001b}[2J\n"),
            "the report arrives, escaped: {out}"
        );
        let state = fake.state.lock().unwrap();
        assert!(
            state.reports.is_empty(),
            "the report was acknowledged before exit"
        );
        assert_eq!(state.calls.iter().filter(|c| **c == "submit").count(), 1);
    }

    #[tokio::test]
    async fn an_expiring_leaf_is_reminted_and_an_expired_login_says_so() {
        let now = unix_now();
        let kernel = Kernel {
            tasker: Fake::new(&[], 0),
            leaf: FakeLeaf::expiring_at(now + 3600),
            login_expires_at: now + 7200,
            agent: agent(),
        };
        assert!(matches!(
            kernel.send(Op::Collect { after: None }, now).await,
            Event::Done(Ok(Answer::Reports(_)))
        ));
        assert_eq!(
            kernel.leaf.mints.load(Ordering::SeqCst),
            0,
            "a fresh leaf is reused"
        );

        *kernel.leaf.not_after.lock().unwrap() = Some(now + REMINT_WITHIN_SECS);
        assert!(matches!(
            kernel.send(Op::Collect { after: None }, now).await,
            Event::Done(Ok(_))
        ));
        assert_eq!(
            kernel.leaf.mints.load(Ordering::SeqCst),
            1,
            "a leaf within 60 s is reminted"
        );

        let expired = Kernel {
            tasker: Fake::new(&[], 0),
            leaf: FakeLeaf::expiring_at(now + 10),
            login_expires_at: now,
            agent: agent(),
        };
        assert!(matches!(
            expired.send(Op::Collect { after: None }, now).await,
            Event::LoginExpired
        ));
        assert!(
            expired.tasker.calls().is_empty(),
            "nothing is sent on an expired login"
        );
        assert_eq!(expired.leaf.mints.load(Ordering::SeqCst), 0);

        let fake = Fake::new(&[("hobi", AgentStanding::Enrolled)], 0);
        let mut io = pipes("tidy my downloads\n");
        let end = bounded(open(
            fake,
            FakeLeaf::expiring_at(now),
            now,
            "hobi",
            true,
            4096,
            io.io(),
        ))
        .await;
        assert_eq!(end, End::Failed);
        let out = io.output();
        assert!(out.contains(crate::agent::LOGIN_EXPIRED), "{out}");
        assert!(!out.contains(text::UNREACHABLE), "{out}");
    }

    #[test]
    fn the_full_screen_session_tasks_the_agent_and_leaves_on_bye() {
        use crate::screen::testing::{one_session, pty, WAIT};
        let _one = one_session();
        let mut pty = pty(24, 80);
        let mut fake = Fake::new(&[("hobi", AgentStanding::Enrolled)], 0);
        fake.roster.banner = Some(BannerSpec {
            text: "TEST BANNER 630".into(),
            color: None,
        });
        let (input, output) = (pty.slave(), pty.slave());
        let (tx, done) = std::sync::mpsc::channel();
        let session = fake.clone();
        std::thread::spawn(move || {
            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap();
            let enter: Enter = Box::new(move || Session::enter_on(input, output));
            let end = rt.block_on(open(
                session,
                fresh_leaf(),
                u64::MAX,
                "hobi",
                false,
                4096,
                Io::Screen(enter),
            ));
            let _ = tx.send(end);
        });
        assert!(pty.out.wait_for(b"TEST BANNER 630"), "no banner");
        assert!(
            pty.out.wait_for(b"connected"),
            "the header never said connected"
        );
        pty.type_keys(b"tidy my downloads\r");
        assert!(pty.out.wait_for(b"#1 submitted"), "no echo");
        pty.type_keys(b"/bye\r");
        let end = done.recv_timeout(WAIT);
        if end.is_err() {
            pty.hang_up();
        }
        assert_eq!(end, Ok(End::Left));
        assert_eq!(fake.calls().iter().filter(|c| **c == "submit").count(), 1);
    }

    #[test]
    fn a_signal_ends_the_process_with_128_plus_its_number() {
        assert_eq!(End::Signal(15).exit_code(), ExitCode::from(143));
        assert_eq!(End::Signal(1).exit_code(), ExitCode::from(129));
        assert_eq!(End::Left.exit_code(), ExitCode::SUCCESS);
        assert_eq!(End::Failed.exit_code(), ExitCode::FAILURE);
        assert_eq!(screen_end(Ok(Exit::Signal(2)), false), End::Signal(2));
        assert_eq!(screen_end(Ok(Exit::Bye), false), End::Left);
        assert_eq!(screen_end(Ok(Exit::InputClosed), false), End::Left);
        assert_eq!(screen_end(Ok(Exit::Bye), true), End::Failed);
        assert_eq!(screen_end(Err(TermError::Ended), false), End::Failed);
    }
}
