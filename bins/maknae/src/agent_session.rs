//! `maknae agent list` and `maknae agent <name>` (#630): the agent list, the
//! full-screen session over `screen::run`, and the plain-line session, wired
//! to the kernel's tasker verbs. What the session decides is
//! `maknae_agent::tasking::Book`'s.
use crate::screen::plain::{Line, Lines};
use crate::screen::run::{Caller, Driver, Ending, Exit, Pace, Step};
use crate::screen::term::{both_terminals, Session, TermError};
use crate::stderr::errln;
use maknae_agent::hints::{choose, token_servers, Forge, Links, RemoteUrl, Remotes};
use maknae_agent::screen::blocks::{Conversation, EntryId, EntryKind};
use maknae_agent::screen::{Commands, HeaderLine, MenuItem};
use maknae_agent::tasking::book::{joined, Alloc, Answer, Book, Entered, Failure, Op, Standing};
use maknae_agent::tasking::text;
use maknae_config::AgentId;
use maknae_loop::tasker::{AgentRoster, TaskerClient, TaskerError};
use maknae_loop::workdir::Unreadable;
use maknae_proto::{
    Binding, BindingRequest, ForgeTokens, SecretText, TaskCursor, TaskPage, TaskRef,
    TaskReportPage, TaskView,
};
use maknae_vault::PlaneClient;
use std::path::Path;
use std::process::ExitCode;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::mpsc;
use tokio::time::Instant;
use zeroize::Zeroizing;

/// A leaf this close to its NotAfter is minted again before the next verb.
const REMINT_WITHIN_SECS: u64 = 60;
const PLAIN_TICK: Duration = Duration::from_millis(250);
const CUT_OFF: &str =
    "a request was still being sent when the session ended; its outcome is unknown";

/// The tasker verbs the session sends, so tests can stand in for the kernel.
pub(crate) trait Tasker {
    async fn agents(&self) -> Result<AgentRoster, TaskerError>;
    async fn forges(&self) -> Result<Vec<Forge>, TaskerError>;
    async fn submit(
        &self,
        agent: &AgentId,
        text: SecretText,
        bindings: Vec<BindingRequest>,
        tokens: ForgeTokens,
    ) -> Result<TaskView, TaskerError>;
    async fn add(
        &self,
        task: &TaskRef,
        text: SecretText,
        bindings: Vec<BindingRequest>,
        tokens: ForgeTokens,
    ) -> Result<TaskView, TaskerError>;
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
    async fn forges(&self) -> Result<Vec<Forge>, TaskerError> {
        TaskerClient::forges(self).await
    }
    async fn submit(
        &self,
        agent: &AgentId,
        text: SecretText,
        bindings: Vec<BindingRequest>,
        tokens: ForgeTokens,
    ) -> Result<TaskView, TaskerError> {
        TaskerClient::submit(self, agent, text, bindings, tokens).await
    }
    async fn add(
        &self,
        task: &TaskRef,
        text: SecretText,
        bindings: Vec<BindingRequest>,
        tokens: ForgeTokens,
    ) -> Result<TaskView, TaskerError> {
        TaskerClient::add(self, task, text, bindings, tokens).await
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

/// The tasker's forge tokens for the servers a request binds, so tests can stand in for Vault.
pub(crate) trait TokenSupply {
    async fn tokens(&self, servers: &[&str], now: u64) -> Result<ForgeTokens, String>;
}

impl TokenSupply for crate::agent::ForgeLogins {
    async fn tokens(&self, servers: &[&str], now: u64) -> Result<ForgeTokens, String> {
        crate::agent::ForgeLogins::tokens(self, servers, now).await
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
pub(crate) struct Kernel<T, L, S> {
    tasker: T,
    leaf: L,
    logins: S,
    login_expires_at: u64,
    agent: AgentId,
    hints: Hints,
}

pub(crate) struct Hints {
    forges: Option<Vec<Forge>>,
    remotes: Remotes,
}

pub(crate) struct Opening {
    pub(crate) wait: bool,
    pub(crate) input_cap: usize,
    pub(crate) workdir: Workdir,
    pub(crate) notes: Box<dyn std::io::Write + Send>,
}

pub(crate) struct Workdir {
    remotes: Vec<RemoteUrl>,
    note: Option<&'static str>,
}

const CHECKOUT_UNREADABLE: &str = "this directory's git checkout could not be read (not owned by you, unreadable or malformed): its repository is not bound";

impl Workdir {
    fn of(read: Result<Option<Vec<RemoteUrl>>, Unreadable>) -> Workdir {
        match read {
            Ok(remotes) => Workdir {
                remotes: remotes.unwrap_or_default(),
                note: None,
            },
            Err(_) => Workdir {
                remotes: Vec::new(),
                note: Some(CHECKOUT_UNREADABLE),
            },
        }
    }

    pub(crate) fn read(cwd: &Path, uid: u32) -> Workdir {
        Workdir::of(maknae_loop::workdir::remotes(cwd, uid))
    }
}

impl<T: Tasker, L: Leaf, S: TokenSupply> Kernel<T, L, S> {
    async fn send(&self, op: Op, now: u64) -> Event {
        let not_after = self.leaf.not_after();
        let fresh = not_after.is_some_and(|at| now.saturating_add(REMINT_WITHIN_SECS) < at);
        if !fresh {
            if crate::agent::login_expired(self.login_expires_at, now) {
                return Event::LoginExpired;
            }
            let valid = not_after.is_some_and(|at| now < at);
            if self.leaf.remint().await.is_err() && !valid {
                return Event::Done(Err(Failure::NoIdentity));
            }
        }
        Event::Done(self.perform(op, now).await)
    }

    async fn tokens(&self, bindings: &[BindingRequest], now: u64) -> Result<ForgeTokens, Failure> {
        let forges = self.hints.forges.as_deref().unwrap_or_default();
        self.logins
            .tokens(&token_servers(bindings, forges), now)
            .await
            .map_err(Failure::NotSent)
    }

    async fn perform(&self, op: Op, now: u64) -> Result<Answer, Failure> {
        let (t, a) = (&self.tasker, &self.agent);
        let answer = match op {
            Op::Collect { after } => t.collect(a, after).await.map(Answer::Reports),
            Op::Poll { after } => t.list_page(a, after).await.map(Answer::Page),
            Op::ListAll => t.list(a).await.map(Answer::Tasks),
            Op::Submit { text } => {
                let remotes = &self.hints.remotes;
                let chosen = choose(
                    &[&Links, remotes],
                    text.0.as_str(),
                    self.hints.forges.as_deref(),
                    None,
                );
                let tokens = self.tokens(&chosen.bindings, now).await?;
                t.submit(a, text, chosen.bindings, tokens)
                    .await
                    .map(|view| Answer::Submitted(view, chosen.unbound))
            }
            Op::Add { task, text, bound } => {
                let mut chosen = choose(
                    &[&Links],
                    text.0.as_str(),
                    self.hints.forges.as_deref(),
                    None,
                );
                chosen
                    .bindings
                    .retain(|BindingRequest::Git(g)| !bound.iter().any(|b| same(b, g)));
                let tokens = self.tokens(&chosen.bindings, now).await?;
                let echo = !chosen.bindings.is_empty() || !chosen.unbound.is_empty();
                t.add(&task, text, chosen.bindings, tokens)
                    .await
                    .map(|view| {
                        if echo {
                            Answer::Added(view, chosen.unbound)
                        } else {
                            Answer::View(view)
                        }
                    })
            }
            Op::Stop { task } => t.stop(&task).await.map(Answer::View),
            Op::Drop { task } => t.drop(&task).await.map(Answer::View),
            Op::Status { task } => t.status(&task).await.map(Answer::View),
        };
        answer.map_err(failure)
    }

    /// Sends each op in turn until the session drops its sender. Without a clock
    /// the leaf cannot be judged, so nothing is sent.
    async fn serve(&self, mut ops: mpsc::UnboundedReceiver<Op>, events: mpsc::Sender<Event>) {
        while let Some(op) = ops.recv().await {
            let event = match maknae_io::now_unix() {
                Ok(now) => self.send(op, now).await,
                Err(_) => Event::Done(Err(Failure::Clock)),
            };
            if events.send(event).await.is_err() {
                return;
            }
        }
    }
}

fn same(bound: &Binding, asked: &maknae_proto::GitRef) -> bool {
    let Binding::Git(b) = bound;
    b.server == asked.server && b.base == asked.base && b.change == asked.change
}

fn failure(e: TaskerError) -> Failure {
    match e {
        TaskerError::Refused { outcome_unknown } => Failure::Refused { outcome_unknown },
        TaskerError::Unreachable { after_write, .. } => Failure::Unreachable { after_write },
        TaskerError::Protocol(why) => Failure::Protocol(why),
    }
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
    logins: crate::agent::ForgeLogins,
    input_cap: usize,
    login_expires_at: u64,
}

async fn connect() -> Result<Plane, String> {
    let (dir, document, transport) = crate::cli::cli_config()?;
    let session = crate::login::user_session(&document, &dir)?;
    let (client, trust) = crate::cli::minted_plane(&document, &dir, &session.token).await?;
    let client = Arc::new(client);
    let input_cap = transport.prompt_max_bytes;
    Ok(Plane {
        tasker: TaskerClient::new(transport, Arc::clone(&client), trust),
        client,
        logins: crate::agent::ForgeLogins {
            api: session.api,
            token: session.token,
            expires_at: session.expires_at,
            place: crate::agent::ForgePlace::of(&document),
        },
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
        Ok(roster) => print_list(&mut std::io::stdout().lock(), &roster),
        Err(e) => {
            errln!("{}", roster_failure(&e));
            ExitCode::FAILURE
        }
    }
}

fn print_list(out: &mut impl std::io::Write, roster: &AgentRoster) -> ExitCode {
    let written = text::agent_list_lines(&roster.entries, roster.undecided)
        .iter()
        .try_for_each(|line| writeln!(out, "{line}"))
        .and_then(|()| out.flush());
    match written {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            errln!("maknae: the agent list could not be written: {e}");
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
    let workdir = match std::env::current_dir() {
        Ok(cwd) => Workdir::read(&cwd, nix::unistd::geteuid().as_raw()),
        Err(_) => Workdir::of(Ok(None)),
    };
    let (end, left) = open(
        plane.tasker,
        leaf,
        plane.logins,
        plane.login_expires_at,
        name,
        Opening {
            wait,
            input_cap: plane.input_cap,
            workdir,
            notes: Box::new(std::io::stderr()),
        },
        io,
    )
    .await;
    for line in left.lines(name) {
        errln!("maknae: {line}");
    }
    let end = match end {
        End::Signal(_) => end,
        end => retire_unless_signalled(retire(&plane.client), end).await,
    };
    end.exit_code()
}

/// `end`, unless a signal arrives while the plane client retires.
async fn retire_unless_signalled(retiring: impl std::future::Future<Output = ()>, end: End) -> End {
    let Ok(mut ending) = Ending::register() else {
        retiring.await;
        return end;
    };
    tokio::select! {
        () = retiring => end,
        signal = ending.next() => End::Signal(signal),
    }
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
            End::Signal(signal) => ExitCode::from(crate::agent::interrupted_status(*signal)),
            End::Failed => ExitCode::FAILURE,
        }
    }
}

/// What a session left behind when it ended: a steering request sent and not
/// answered, requests never sent, and requests the kernel did not take.
#[derive(Debug, Default, PartialEq, Eq)]
pub(crate) struct Left {
    cut: bool,
    unsent: usize,
    not_taken: usize,
}

impl Left {
    fn of(book: &Book) -> Left {
        Left {
            cut: book.steering_in_flight(),
            unsent: book.unsent(),
            not_taken: book.not_taken(),
        }
    }

    /// A session that left anything behind did not end cleanly.
    fn end(&self, end: End) -> End {
        match end {
            End::Left if self.cut || self.unsent > 0 || self.not_taken > 0 => End::Failed,
            end => end,
        }
    }

    fn lines(&self, agent: &str) -> Vec<String> {
        let mut lines = Vec::new();
        if self.cut {
            lines.push(CUT_OFF.to_owned());
        }
        if self.unsent > 0 {
            lines.push(text::not_sent(self.unsent, agent));
        }
        if self.not_taken > 0 {
            lines.push(text::not_taken(self.not_taken));
        }
        lines
    }
}

/// Checks `name` against the agent list and runs the session with it.
pub(crate) async fn open<T: Tasker, L: Leaf, S: TokenSupply>(
    tasker: T,
    leaf: L,
    logins: S,
    login_expires_at: u64,
    name: &str,
    opening: Opening,
    io: Io,
) -> (End, Left) {
    let Opening {
        wait,
        input_cap,
        workdir,
        mut notes,
    } = opening;
    let refused = (End::Failed, Left::default());
    let roster = match tasker.agents().await {
        Ok(roster) => roster,
        Err(e) => {
            errln!("{}", roster_failure(&e));
            return refused;
        }
    };
    let (agent, standing) = match admit(&roster, name) {
        Ok(admitted) => admitted,
        Err(refusal) => {
            errln!("{refusal}");
            return refused;
        }
    };
    if let Some(Err(e)) = roster.banner.as_ref().map(maknae_proto::check_banner) {
        errln!("maknae: the kernel's banner is not valid ({e}); the session was not opened");
        return refused;
    }
    let forges = tasker.forges().await.ok();
    if let Some(note) = workdir.note {
        crate::stderr::line(&mut notes, format_args!("maknae: {note}"));
    }
    let kernel = Kernel {
        tasker,
        leaf,
        logins,
        login_expires_at,
        agent,
        hints: Hints {
            forges,
            remotes: Remotes(workdir.remotes),
        },
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

    fn leave(&mut self, conversation: &mut Conversation) -> Step {
        match self.book.leave(conversation) {
            Entered::Leave => Step::Leave,
            Entered::Stay => Step::Changed,
        }
    }
}

async fn full_screen<T: Tasker, L: Leaf, S: TokenSupply>(
    kernel: &Kernel<T, L, S>,
    standing: Standing,
    banner: Option<maknae_proto::BannerSpec>,
    input_cap: usize,
    enter: Enter,
) -> (End, Left) {
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
            return (End::Failed, Left::default());
        }
    };
    let run = driver.run();
    tokio::pin!(run);
    let (screen, result) = tokio::select! {
        out = &mut run => out,
        () = kernel.serve(op_rx, event_tx) => run.await,
    };
    let end = screen_end(result, screen.book.stopped());
    let left = Left::of(&screen.book);
    drop(screen);
    (left.end(end), left)
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
            let (entry, _) = entry_text(conv, id);
            lines.write_line(&entry)?;
        }
        conv.mark_seen(id..=id);
        *printed = Some(id);
        at = conv.next_item(id).filter(|next| *next <= last);
    }
    Ok(())
}

fn entry_text(conv: &Conversation, id: EntryId) -> (Zeroizing<String>, Alloc) {
    let segments: Vec<&str> = conv.segments(id).collect();
    joined(segments.iter().map(|s| s.len()).sum(), &segments)
}

async fn plain<T: Tasker, L: Leaf, S: TokenSupply>(
    kernel: &Kernel<T, L, S>,
    standing: Standing,
    wait: bool,
    lines: &mut Lines,
) -> (End, Left) {
    let mut ending = match Ending::register() {
        Ok(ending) => ending,
        Err(e) => {
            errln!("maknae: {e}");
            return (End::Failed, Left::default());
        }
    };
    let mut book = Book::new(kernel.agent.as_str(), standing, true);
    let end = plain_lines(kernel, &mut book, wait, lines, &mut ending).await;
    let left = Left::of(&book);
    (left.end(end), left)
}

/// What a session without a screen says on stderr as it happens: the connection
/// changing and a task put on hold, each once.
struct Said {
    link: &'static str,
    held: Vec<u32>,
}

impl Said {
    fn new() -> Said {
        Said {
            link: text::CONNECTING,
            held: Vec::new(),
        }
    }

    fn say(&mut self, book: &Book, lines: &mut Lines) -> Result<(), TermError> {
        let link = book.link();
        if link != self.link {
            let first = self.link == text::CONNECTING && link == text::CONNECTED;
            self.link = link;
            if !first {
                lines.say(&format!("maknae: {} · {link}", book.agent()))?;
            }
        }
        let held = book.held();
        for n in held.iter().filter(|n| !self.held.contains(n)) {
            lines.say(&format!(
                "maknae: {} #{n} {}",
                book.agent(),
                text::held_line()
            ))?;
        }
        self.held = held;
        Ok(())
    }
}

async fn plain_lines<T: Tasker, L: Leaf, S: TokenSupply>(
    kernel: &Kernel<T, L, S>,
    book: &mut Book,
    wait: bool,
    lines: &mut Lines,
    ending: &mut Ending,
) -> End {
    let (op_tx, op_rx) = mpsc::unbounded_channel();
    let (event_tx, mut event_rx) = mpsc::channel(4);
    let serve = kernel.serve(op_rx, event_tx);
    tokio::pin!(serve);
    let start = Instant::now();
    let mut conv = Conversation::for_prompt_ceiling(maknae_config::PROMPT_MAX_CEILING);
    let mut said = Said::new();
    let mut printed = None;
    let (mut ended, mut bye, mut served) = (false, false, false);
    loop {
        let now = ms(start);
        pump(book, &op_tx, now, &mut conv);
        let shown = print_new(&mut conv, &mut printed, lines).and_then(|()| said.say(book, lines));
        if let Err(e) = shown {
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
            line = lines.next_line(), if !ended && !book.busy() => match line {
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
            Some(event) = event_rx.recv() => apply(book, event, ms(start), &mut conv),
            () = tokio::time::sleep(PLAIN_TICK) => {
                book.tick(ms(start), &mut conv);
            }
            () = &mut serve, if !served => served = true,
            signal = ending.next() => return End::Signal(signal),
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
        refuse_submit: bool,
        forges: Option<Vec<Forge>>,
        submitted: Vec<Vec<BindingRequest>>,
        added: Vec<Vec<BindingRequest>>,
        tokens: Vec<ForgeTokens>,
        /// Every collect waits while this is set.
        hold: bool,
        holding: bool,
        unreachable: bool,
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
                            board: false,
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

        fn set(&self, f: impl FnOnce(&mut State)) {
            f(&mut self.state.lock().unwrap());
        }

        fn hold_collects(&self) {
            self.set(|s| s.hold = true);
        }

        /// Waits up to [`BOUND`] for a collect to be held.
        fn held_collect(&self) {
            let deadline = std::time::Instant::now() + BOUND;
            while !self.state.lock().unwrap().holding {
                assert!(std::time::Instant::now() < deadline, "no collect was held");
                std::thread::sleep(Duration::from_millis(10));
            }
        }

        async fn gate(&self) {
            loop {
                {
                    let mut s = self.state.lock().unwrap();
                    if !s.hold {
                        s.holding = false;
                        return;
                    }
                    s.holding = true;
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
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
            bindings: vec![],
            reach: vec![],
        }
    }

    impl Tasker for Fake {
        async fn agents(&self) -> Result<AgentRoster, TaskerError> {
            self.note("agents");
            Ok(self.roster.clone())
        }
        async fn forges(&self) -> Result<Vec<Forge>, TaskerError> {
            self.note("forges");
            self.state
                .lock()
                .unwrap()
                .forges
                .clone()
                .ok_or(TaskerError::Refused {
                    outcome_unknown: false,
                })
        }
        async fn submit(
            &self,
            _: &AgentId,
            _: SecretText,
            bindings: Vec<BindingRequest>,
            tokens: ForgeTokens,
        ) -> Result<TaskView, TaskerError> {
            let mut s = self.call("submit");
            s.submitted.push(bindings);
            s.tokens.push(tokens);
            if s.refuse_submit {
                return Err(TaskerError::Refused {
                    outcome_unknown: false,
                });
            }
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
        async fn add(
            &self,
            task: &TaskRef,
            _: SecretText,
            bindings: Vec<BindingRequest>,
            tokens: ForgeTokens,
        ) -> Result<TaskView, TaskerError> {
            let mut s = self.call("add");
            s.added.push(bindings);
            s.tokens.push(tokens);
            let mut v = view(1, TaskState::Working);
            v.task = task.clone();
            Ok(v)
        }
        async fn status(&self, _: &TaskRef) -> Result<TaskView, TaskerError> {
            self.note("status");
            Err(TaskerError::Protocol("unused".into()))
        }
        async fn stop(&self, _: &TaskRef) -> Result<TaskView, TaskerError> {
            self.note("stop");
            Err(TaskerError::Protocol("unused".into()))
        }
        async fn drop(&self, task: &TaskRef) -> Result<TaskView, TaskerError> {
            let mut s = self.call("drop");
            let at = s.tasks.iter().position(|t| t.task == *task);
            let Some(at) = at else {
                return Err(TaskerError::Refused {
                    outcome_unknown: true,
                });
            };
            let mut v = s.tasks.remove(at);
            v.state = TaskState::Closed;
            v.close = Some(maknae_proto::TaskClose::Dropped);
            Ok(v)
        }
        async fn list_page(
            &self,
            _: &AgentId,
            after: Option<TaskCursor>,
        ) -> Result<TaskPage, TaskerError> {
            let s = self.call("list_page");
            if s.unreachable {
                return Err(TaskerError::Unreachable {
                    after_write: false,
                    why: "test".into(),
                });
            }
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
            self.gate().await;
            let mut s = self.call("collect");
            if s.unreachable {
                return Err(TaskerError::Unreachable {
                    after_write: false,
                    why: "test".into(),
                });
            }
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
            *self.not_after.lock().unwrap() = Some(now() + 3600);
            Ok(())
        }
    }

    impl Leaf for Arc<FakeLeaf> {
        fn not_after(&self) -> Option<u64> {
            FakeLeaf::not_after(self)
        }
        async fn remint(&self) -> Result<(), String> {
            FakeLeaf::remint(self).await
        }
    }

    fn now() -> u64 {
        maknae_io::now_unix().unwrap()
    }

    /// No forge logins: a request that needs a token is refused.
    struct NoLogins;

    impl TokenSupply for NoLogins {
        async fn tokens(&self, servers: &[&str], _: u64) -> Result<ForgeTokens, String> {
            match servers {
                [] => Ok(ForgeTokens::default()),
                _ => Err(format!("no forge login in this test for {servers:?}")),
            }
        }
    }

    /// The real seal over a scripted Vault: each read answers `status`, or a wrapping token.
    struct Logins {
        key: maknae_seal::SealPrivateKey,
        status: Option<u16>,
        asked: Mutex<Vec<String>>,
    }

    impl Logins {
        fn new(status: Option<u16>) -> Logins {
            maknae_crypto::init().unwrap();
            Logins {
                key: maknae_seal::SealPrivateKey::generate().unwrap(),
                status,
                asked: Mutex::default(),
            }
        }

        fn asked(&self) -> Vec<String> {
            self.asked.lock().unwrap().clone()
        }

        fn opens(&self, token: &maknae_proto::SealedForgeToken, path: &str) -> Vec<u8> {
            let aad = maknae_seal::SealAad::forge(&maknae_seal::ForgeSealContext {
                purpose: maknae_seal::ForgePurpose::TaskerReach,
                nonce: token.nonce(),
                server: token.server(),
                expected_path: path,
                key_field: "token",
            })
            .unwrap();
            maknae_seal::open(&self.key, &aad, token.sealed().as_bytes())
                .unwrap()
                .to_vec()
        }
    }

    impl TokenSupply for Logins {
        async fn tokens(&self, servers: &[&str], now: u64) -> Result<ForgeTokens, String> {
            let key = crate::agent::ForgeKeyContext {
                kv_mount: "maknae-kv",
                user_prefix: "maknae/users",
                username: "alice",
                seal_key: self.key.public_key(),
                expires_at: u64::MAX,
            };
            crate::agent::forge_tokens(&key, servers, now, |path| {
                self.asked.lock().unwrap().push(path.clone());
                let status = self.status;
                async move {
                    match status {
                        Some(status) => Err(maknae_vault::VaultError::VaultStatus {
                            op: "read",
                            status,
                            hint: "",
                        }),
                        None => Ok(maknae_vault::WrappedSecret {
                            token: maknae_vault::WrappingToken::new(Zeroizing::new(
                                "hvs.forge-wrap-sentinel-168".into(),
                            ))
                            .unwrap(),
                            ttl: Duration::from_secs(60),
                            creation_path: format!("maknae-kv/data/{path}"),
                            creation_time: "2026-11-23T00:00:00Z".into(),
                        }),
                    }
                }
            })
            .await
        }
    }

    fn fresh_leaf() -> FakeLeaf {
        FakeLeaf::expiring_at(now() + 3600)
    }

    fn no_hints() -> Hints {
        Hints {
            forges: None,
            remotes: Remotes(Vec::new()),
        }
    }

    fn github() -> Forge {
        Forge {
            host: "github.com".into(),
            provider: maknae_config::ForgeProvider::Github,
        }
    }

    fn git(server: &str, base: &str, change: Option<u64>) -> BindingRequest {
        BindingRequest::Git(maknae_proto::GitRef {
            server: server.into(),
            base: base.into(),
            change,
        })
    }

    fn remote_of(url: &str) -> Remotes {
        let config = format!("[remote \"origin\"]\nurl = {url}\n");
        Remotes(maknae_agent::hints::git_config_remotes(config.as_bytes()).unwrap())
    }

    fn submit_op(prompt: &str) -> Op {
        Op::Submit {
            text: SecretText(Zeroizing::new(prompt.into())),
        }
    }

    #[tokio::test]
    async fn perform_submits_the_hinted_bindings_and_returns_the_unbound() {
        let fake = Fake::new(&[("hobi", AgentStanding::Enrolled)], 0);
        let kernel = Kernel {
            tasker: fake.clone(),
            leaf: fresh_leaf(),
            logins: Logins::new(None),
            login_expires_at: u64::MAX,
            agent: agent(),
            hints: Hints {
                forges: Some(vec![github()]),
                remotes: remote_of("git@github.com:darkhonor/maknae.git"),
            },
        };
        let prompt = "review https://github.com/o/r/pull/7 and https://elsewhere.example/x/y";
        let Ok(Answer::Submitted(_, unbound)) = kernel.perform(submit_op(prompt), now()).await
        else {
            panic!("not submitted");
        };
        assert_eq!(
            fake.state.lock().unwrap().submitted,
            [vec![
                git("github.com", "o/r", Some(7)),
                git("github.com", "darkhonor/maknae", None),
            ]]
        );
        assert_eq!(unbound.len(), 1, "{unbound:?}");
        assert_eq!(
            unbound[0].reason,
            maknae_agent::hints::Reason::UnknownServer
        );
    }

    fn forge(host: &str, provider: maknae_config::ForgeProvider) -> Forge {
        Forge {
            host: host.into(),
            provider,
        }
    }

    fn bound_kernel<S: TokenSupply>(fake: &Fake, logins: S) -> Kernel<Fake, FakeLeaf, S> {
        use maknae_config::ForgeProvider::{Github, Gitlab};
        Kernel {
            tasker: fake.clone(),
            leaf: fresh_leaf(),
            logins,
            login_expires_at: u64::MAX,
            agent: agent(),
            hints: Hints {
                forges: Some(vec![
                    github(),
                    forge("ghe.example:8443", Github),
                    forge("gitlab.lab.local:8443", Gitlab),
                ]),
                remotes: Remotes(Vec::new()),
            },
        }
    }

    const BOUND_PROMPT: &str = "review https://github.com/o/r/pull/7, https://github.com/o/s, \
        https://gitlab.lab.local:8443/g/p/-/merge_requests/3 and https://ghe.example:8443/o/t/pull/2";

    #[tokio::test]
    async fn submit_seals_one_token_per_github_server_and_none_for_gitlab() {
        let fake = Fake::new(&[("hobi", AgentStanding::Enrolled)], 0);
        let kernel = bound_kernel(&fake, Logins::new(None));
        let answer = kernel.perform(submit_op(BOUND_PROMPT), now()).await;
        assert!(matches!(answer, Ok(Answer::Submitted(..))), "{answer:?}");
        let state = fake.state.lock().unwrap();
        assert_eq!(
            state.submitted,
            [vec![
                git("github.com", "o/r", Some(7)),
                git("github.com", "o/s", None),
                git("gitlab.lab.local:8443", "g/p", Some(3)),
                git("ghe.example:8443", "o/t", Some(2)),
            ]]
        );
        let paths = [
            "maknae/users/alice/forges/github.com",
            "maknae/users/alice/forges/ghe.example_8443",
        ];
        assert_eq!(kernel.logins.asked(), paths);
        let tokens = state.tokens[0].as_slice();
        let servers: Vec<_> = tokens.iter().map(|t| t.server()).collect();
        assert_eq!(servers, ["github.com", "ghe.example:8443"]);
        for (token, path) in tokens.iter().zip(paths) {
            assert_eq!(
                kernel.logins.opens(token, path),
                b"hvs.forge-wrap-sentinel-168"
            );
        }
    }

    #[tokio::test]
    async fn a_missing_login_refuses_before_submitting_and_names_the_command() {
        let fake = Fake::new(&[("hobi", AgentStanding::Enrolled)], 0);
        let kernel = bound_kernel(&fake, Logins::new(Some(404)));
        let answer = kernel.perform(submit_op(BOUND_PROMPT), now()).await;
        let Err(Failure::NotSent(why)) = answer else {
            panic!("{answer:?}");
        };
        assert_eq!(
            why,
            "no forge login is stored for github.com: run `maknae forge login github.com`, then retry"
        );
        assert!(fake.calls().is_empty(), "{:?}", fake.calls());
        let gitlab_only = "see https://gitlab.lab.local:8443/g/p/-/merge_requests/3";
        let answer = kernel.perform(submit_op(gitlab_only), now()).await;
        assert!(matches!(answer, Ok(Answer::Submitted(..))), "{answer:?}");
        assert!(fake.state.lock().unwrap().tokens[0].is_empty());
    }

    #[tokio::test]
    async fn submit_runs_no_program() {
        use maknae_io::program::Program;
        let fake = Fake::new(&[("hobi", AgentStanding::Enrolled)], 0);
        let kernel = bound_kernel(&fake, Logins::new(None));
        assert!(kernel.perform(submit_op(BOUND_PROMPT), now()).await.is_ok());
        let paths: Vec<_> = Program::ALL
            .iter()
            .map(|p| p.path().to_str().unwrap())
            .collect();
        assert_eq!(
            paths,
            [
                "/usr/bin/systemd-creds",
                "/usr/bin/setfacl",
                "/usr/bin/getfacl",
                "/usr/sbin/restorecon",
                "/usr/sbin/apparmor_parser",
                "/usr/sbin/usermod",
                "/usr/sbin/dseditgroup",
                "/usr/bin/sudo",
                "/usr/bin/env",
                "/usr/bin/id",
                "/usr/bin/security",
                "/usr/bin/codesign",
                "/bin/chmod",
                "/bin/ls",
                "/usr/bin/systemctl",
                "/bin/launchctl",
                "/usr/bin/stat",
            ]
        );
    }

    #[tokio::test]
    async fn add_binds_links_in_its_text_and_seals_their_tokens() {
        let fake = Fake::new(&[("hobi", AgentStanding::Enrolled)], 0);
        let kernel = bound_kernel(&fake, Logins::new(None));
        let already = Binding::Git(maknae_proto::GitBinding {
            server: "github.com".into(),
            base: "o/r".into(),
            head: Some("o/r-fork".into()),
            change: Some(7),
        });
        let task = TaskRef::from_id(&TaskId([9; 16]));
        let add = |text: &str| Op::Add {
            task: task.clone(),
            text: SecretText(Zeroizing::new(text.into())),
            bound: vec![already.clone()],
        };
        let answer = kernel
            .perform(
                add("also https://github.com/o/r/pull/7 and https://ghe.example:8443/o/t/pull/2 and https://elsewhere.example/x/y"),
                now(),
            )
            .await;
        let Ok(Answer::Added(view, unbound)) = answer else {
            panic!("{answer:?}");
        };
        assert_eq!(view.task, task);
        assert_eq!(unbound.len(), 1, "{unbound:?}");
        assert!(matches!(
            kernel.perform(add("just more words"), now()).await,
            Ok(Answer::View(_))
        ));
        let state = fake.state.lock().unwrap();
        assert_eq!(
            state.added,
            [vec![git("ghe.example:8443", "o/t", Some(2))], vec![]]
        );
        assert_eq!(
            kernel.logins.asked(),
            ["maknae/users/alice/forges/ghe.example_8443"]
        );
        let servers: Vec<_> = state.tokens[0]
            .as_slice()
            .iter()
            .map(|t| t.server())
            .collect();
        assert_eq!(servers, ["ghe.example:8443"]);
        assert!(state.tokens[1].is_empty());
        assert!(state.submitted.is_empty());
    }

    #[tokio::test]
    async fn a_refused_catalog_leaves_each_candidate_not_bound_with_no_forge_list() {
        let fake = Fake::new(&[("hobi", AgentStanding::Enrolled)], 0);
        let mut io = pipes("see https://github.com/o/r\n");
        let (end, _) = bounded(open(
            fake.clone(),
            fresh_leaf(),
            NoLogins,
            u64::MAX,
            "hobi",
            Opening {
                wait: false,
                input_cap: 4096,
                workdir: Workdir::of(Ok(None)),
                notes: Box::new(std::io::sink()),
            },
            io.io(),
        ))
        .await;
        assert_eq!(end, End::Left);
        assert_eq!(fake.state.lock().unwrap().submitted, [vec![]]);
        assert!(
            io.output().contains("not bound: github.com: no forge list"),
            "{}",
            io.output()
        );
    }

    #[derive(Clone, Default)]
    struct Captured(Arc<Mutex<Vec<u8>>>);

    impl std::io::Write for Captured {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            self.0.lock().unwrap().extend_from_slice(bytes);
            Ok(bytes.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    #[tokio::test]
    async fn an_unreadable_checkout_says_so_once_without_its_path_and_binds_nothing() {
        use std::os::unix::fs::PermissionsExt;
        struct Scratch(std::path::PathBuf);
        impl Drop for Scratch {
            fn drop(&mut self) {
                let _ = std::fs::remove_dir_all(&self.0);
            }
        }
        let t =
            Scratch(std::env::temp_dir().join(format!("maknae-checkout-{}", std::process::id())));
        let checkout = t.0.join("fixture-checkout-168");
        std::fs::create_dir_all(checkout.join(".git")).unwrap();
        std::fs::write(
            checkout.join(".git/config"),
            "[remote \"o\"]\nurl = https://github.com/o/r\n",
        )
        .unwrap();
        std::fs::set_permissions(&checkout, std::fs::Permissions::from_mode(0o777)).unwrap();
        let workdir = Workdir::read(&checkout, nix::unistd::geteuid().as_raw());
        assert!(workdir.remotes.is_empty());
        let fake = Fake::new(&[("hobi", AgentStanding::Enrolled)], 0);
        let mut io = pipes("see o/r\n");
        let notes = Captured::default();
        let (end, _) = bounded(open(
            fake.clone(),
            fresh_leaf(),
            NoLogins,
            u64::MAX,
            "hobi",
            Opening {
                wait: false,
                input_cap: 4096,
                workdir,
                notes: Box::new(notes.clone()),
            },
            io.io(),
        ))
        .await;
        assert_eq!(end, End::Left);
        let said = String::from_utf8(notes.0.lock().unwrap().clone()).unwrap();
        assert_eq!(said, format!("maknae: {CHECKOUT_UNREADABLE}\n"));
        assert!(!said.contains("fixture-checkout-168"));
        assert!(!io.output().contains("fixture-checkout-168"));
        assert!(!io.output().contains(CHECKOUT_UNREADABLE));
    }

    #[test]
    fn outside_a_checkout_nothing_is_said() {
        let outside = Workdir::of(Ok(None));
        assert_eq!(outside.note, None);
        assert!(outside.remotes.is_empty());
    }

    fn agent() -> AgentId {
        AgentId::parse("hobi").unwrap()
    }

    /// A plain-line session's descriptors: input written, and closed unless the
    /// test keeps writing; output and diagnostics read back.
    struct Pipes {
        lines: Option<Lines>,
        input: Option<OwnedFd>,
        output: OwnedFd,
        diagnostics: OwnedFd,
    }

    fn pipes(input: &str) -> Pipes {
        let mut pipes = open_pipes(input);
        pipes.input = None;
        pipes
    }

    fn open_pipes(input: &str) -> Pipes {
        let (in_r, in_w) = nix::unistd::pipe().unwrap();
        let (out_r, out_w) = nix::unistd::pipe().unwrap();
        let (err_r, err_w) = nix::unistd::pipe().unwrap();
        nix::unistd::write(&in_w, input.as_bytes()).unwrap();
        Pipes {
            lines: Some(Lines::new(in_r, out_w, err_w, 4096).unwrap()),
            input: Some(in_w),
            output: out_r,
            diagnostics: err_r,
        }
    }

    fn drain(fd: &OwnedFd) -> String {
        nix::fcntl::fcntl(
            fd,
            nix::fcntl::FcntlArg::F_SETFL(nix::fcntl::OFlag::O_NONBLOCK),
        )
        .unwrap();
        let mut out = Vec::new();
        let mut chunk = [0u8; 4096];
        while let Ok(n @ 1..) = nix::unistd::read(fd, &mut chunk) {
            out.extend_from_slice(&chunk[..n]);
        }
        String::from_utf8(out).unwrap()
    }

    impl Pipes {
        fn io(&mut self) -> Io {
            Io::Plain(self.lines())
        }

        fn lines(&mut self) -> Lines {
            self.lines.take().unwrap()
        }

        fn type_line(&self, line: &str) {
            nix::unistd::write(self.input.as_ref().unwrap(), line.as_bytes()).unwrap();
        }

        fn output(&self) -> String {
            drain(&self.output)
        }

        /// Waits up to [`BOUND`] for `needle` on the output.
        fn shows(&self, needle: &str) -> bool {
            let mut seen = String::new();
            let deadline = std::time::Instant::now() + BOUND;
            loop {
                seen.push_str(&self.output());
                if seen.contains(needle) {
                    return true;
                }
                if std::time::Instant::now() >= deadline {
                    eprintln!("timed out waiting for {needle:?}; saw {seen:?}");
                    return false;
                }
                std::thread::sleep(Duration::from_millis(10));
            }
        }

        /// Waits up to [`BOUND`] for `needle` on the diagnostics.
        fn said(&self, seen: &mut String, needle: &str) -> bool {
            let deadline = std::time::Instant::now() + BOUND;
            loop {
                seen.push_str(&drain(&self.diagnostics));
                if seen.contains(needle) {
                    return true;
                }
                if std::time::Instant::now() >= deadline {
                    eprintln!("timed out waiting for {needle:?}; saw {seen:?}");
                    return false;
                }
                std::thread::sleep(Duration::from_millis(10));
            }
        }
    }

    async fn bounded<F: std::future::Future>(f: F) -> F::Output {
        tokio::time::timeout(BOUND, f)
            .await
            .expect("the session did not end in time")
    }

    /// Runs a session on a thread of its own while the caller holds the one-session
    /// turn: a session registers the ending signals, which other tests send to the
    /// whole process.
    fn spawn_session(
        fake: &Fake,
        leaf: Arc<FakeLeaf>,
        login_expires_at: u64,
        wait: bool,
        io: impl FnOnce() -> Io + Send + 'static,
    ) -> std::sync::mpsc::Receiver<(End, Left)> {
        let (tx, done) = std::sync::mpsc::channel();
        let session = fake.clone();
        std::thread::spawn(move || {
            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap();
            let ended = rt.block_on(open(
                session,
                leaf,
                NoLogins,
                login_expires_at,
                "hobi",
                Opening {
                    wait,
                    input_cap: 4096,
                    workdir: Workdir::of(Ok(None)),
                    notes: Box::new(std::io::sink()),
                },
                io(),
            ));
            let _ = tx.send(ended);
        });
        done
    }

    fn in_turn(
        fake: &Fake,
        leaf: FakeLeaf,
        login_expires_at: u64,
        wait: bool,
        lines: Lines,
    ) -> (End, Left) {
        let _one = crate::screen::testing::one_session();
        spawn_session(fake, Arc::new(leaf), login_expires_at, wait, move || {
            Io::Plain(lines)
        })
        .recv_timeout(BOUND)
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
            board: false,
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
        let ended = bounded(open(
            fake.clone(),
            fresh_leaf(),
            NoLogins,
            u64::MAX,
            "summarize my files",
            Opening {
                wait: false,
                input_cap: 4096,
                workdir: Workdir::of(Ok(None)),
                notes: Box::new(std::io::sink()),
            },
            io.io(),
        ))
        .await;
        assert_eq!(ended, (End::Failed, Left::default()));
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
        let (end, _) = bounded(open(
            fake.clone(),
            fresh_leaf(),
            NoLogins,
            u64::MAX,
            "hobi",
            Opening {
                wait: false,
                input_cap: 4096,
                workdir: Workdir::of(Ok(None)),
                notes: Box::new(std::io::sink()),
            },
            io.io(),
        ))
        .await;
        assert_eq!(end, End::Failed);
        assert_eq!(fake.calls(), ["agents"]);
    }

    #[test]
    fn plain_mode_exits_after_acknowledgement_and_wait_waits_for_reports() {
        let fake = Fake::new(&[("hobi", AgentStanding::Enrolled)], 0);
        let mut io = pipes("tidy my downloads\n");
        let ended = in_turn(&fake, fresh_leaf(), u64::MAX, false, io.lines());
        assert_eq!(ended, (End::Left, Left::default()));
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
        let (end, _) = in_turn(&fake, fresh_leaf(), u64::MAX, true, io.lines());
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
    async fn an_expiring_leaf_is_reminted_and_an_expired_login_sends_nothing() {
        let now = now();
        let kernel = Kernel {
            tasker: Fake::new(&[], 0),
            leaf: FakeLeaf::expiring_at(now + 3600),
            logins: NoLogins,
            login_expires_at: now + 7200,
            agent: agent(),
            hints: no_hints(),
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
            logins: NoLogins,
            login_expires_at: now,
            agent: agent(),
            hints: no_hints(),
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
    }

    #[test]
    fn an_expired_login_ends_a_plain_session_and_says_so() {
        let now = now();
        let fake = Fake::new(&[("hobi", AgentStanding::Enrolled)], 0);
        let mut io = pipes("tidy my downloads\n");
        let (end, _) = in_turn(&fake, FakeLeaf::expiring_at(now), now, true, io.lines());
        assert_eq!(end, End::Failed);
        let out = io.output();
        assert!(out.contains(crate::agent::LOGIN_EXPIRED), "{out}");
        assert!(!out.contains(text::UNREACHABLE), "{out}");
    }

    /// Opens a full-screen session on a pty with `fake`.
    fn full_screen(
        fake: &Fake,
        leaf: Arc<FakeLeaf>,
        login_expires_at: u64,
    ) -> (
        crate::screen::testing::Pty,
        std::sync::mpsc::Receiver<(End, Left)>,
    ) {
        use crate::screen::testing::pty;
        let pty = pty(24, 80);
        let (input, output) = (pty.slave(), pty.slave());
        let done = spawn_session(fake, leaf, login_expires_at, false, move || {
            Io::Screen(Box::new(move || Session::enter_on(input, output)))
        });
        (pty, done)
    }

    fn submit_one_behind_a_collect(pty: &mut crate::screen::testing::Pty, fake: &Fake) {
        assert!(pty.out.wait_for(b"connected"), "never connected");
        pty.type_keys(b"one\r");
        assert!(pty.out.wait_for(b"#1 submitted"), "no echo");
        fake.hold_collects();
        fake.held_collect();
    }

    fn type_one_then_two(pty: &mut crate::screen::testing::Pty, fake: &Fake) {
        submit_one_behind_a_collect(pty, fake);
        pty.type_keys(b"two\r/x\r");
        assert!(
            pty.out.wait_for(b"unknown command"),
            "the lines after the request were not read"
        );
    }

    fn leave_with_one_unsent(
        pty: &mut crate::screen::testing::Pty,
        done: &std::sync::mpsc::Receiver<(End, Left)>,
    ) {
        pty.type_keys(b"/status 1\r/x\r");
        assert!(
            pty.out.wait_for(b"unknown command"),
            "the lines were not read"
        );
        pty.type_keys(b"/bye\r");
        assert!(pty.out.wait_for(b"1 request is not yet sent or answered"));
        pty.type_keys(b"/bye\r");
        assert_eq!(ended(pty, done), (End::Left, Left::default()));
    }

    fn ended(
        pty: &mut crate::screen::testing::Pty,
        done: &std::sync::mpsc::Receiver<(End, Left)>,
    ) -> (End, Left) {
        let ended = done.recv_timeout(crate::screen::testing::WAIT);
        if ended.is_err() {
            pty.hang_up();
        }
        ended.expect("the session did not end in time")
    }

    #[test]
    fn a_request_queued_behind_a_collect_holds_the_first_bye_and_is_named_on_the_second() {
        let _one = crate::screen::testing::one_session();
        let fake = Fake::new(&[("hobi", AgentStanding::Enrolled)], 0);
        let (mut pty, done) = full_screen(&fake, Arc::new(fresh_leaf()), u64::MAX);
        type_one_then_two(&mut pty, &fake);
        pty.type_keys(b"/bye\r");
        assert!(
            pty.out.wait_for(b"1 request is not yet sent or answered"),
            "the first /bye was not held"
        );
        pty.type_keys(b"/bye\r");
        let ended = ended(&mut pty, &done);
        assert_eq!(
            ended,
            (
                End::Failed,
                Left {
                    cut: false,
                    unsent: 1,
                    not_taken: 0,
                }
            )
        );
        assert_eq!(
            ended.1.lines("hobi"),
            ["1 request was not sent; it was not given to hobi"]
        );
        assert_eq!(fake.calls().iter().filter(|c| **c == "submit").count(), 1);
    }

    #[test]
    fn a_request_queued_behind_a_collect_is_named_after_a_signal() {
        use nix::sys::signal::{kill, Signal};
        let _one = crate::screen::testing::one_session();
        let fake = Fake::new(&[("hobi", AgentStanding::Enrolled)], 0);
        let (mut pty, done) = full_screen(&fake, Arc::new(fresh_leaf()), u64::MAX);
        type_one_then_two(&mut pty, &fake);
        kill(nix::unistd::Pid::this(), Signal::SIGTERM).unwrap();
        assert_eq!(
            ended(&mut pty, &done),
            (
                End::Signal(Signal::SIGTERM as i32),
                Left {
                    cut: false,
                    unsent: 1,
                    not_taken: 0,
                }
            )
        );
    }

    #[test]
    fn a_request_queued_when_the_login_expires_is_named() {
        let _one = crate::screen::testing::one_session();
        let fake = Fake::new(&[("hobi", AgentStanding::Enrolled)], 0);
        let leaf = Arc::new(fresh_leaf());
        let (mut pty, done) = full_screen(&fake, Arc::clone(&leaf), now());
        type_one_then_two(&mut pty, &fake);
        *leaf.not_after.lock().unwrap() = Some(0);
        fake.set(|s| s.hold = false);
        assert!(pty.out.wait_for(b"login expired"), "the login never ended");
        pty.type_keys(b"/bye\r");
        assert_eq!(
            ended(&mut pty, &done),
            (
                End::Failed,
                Left {
                    cut: false,
                    unsent: 1,
                    not_taken: 0,
                }
            )
        );
        assert_eq!(fake.calls().iter().filter(|c| **c == "submit").count(), 1);
    }

    #[test]
    fn a_plain_session_names_a_request_queued_behind_a_collect_after_a_signal() {
        use nix::sys::signal::{kill, Signal};
        let _one = crate::screen::testing::one_session();
        let fake = Fake::new(&[("hobi", AgentStanding::Enrolled)], 0);
        let mut io = open_pipes("one\n");
        let done = spawn_session(&fake, Arc::new(fresh_leaf()), u64::MAX, false, {
            let lines = io.lines();
            move || Io::Plain(lines)
        });
        assert!(io.shows("#1 submitted"), "nothing was submitted");
        fake.hold_collects();
        fake.held_collect();
        io.type_line("two\n");
        std::thread::sleep(Duration::from_millis(500));
        kill(nix::unistd::Pid::this(), Signal::SIGTERM).unwrap();
        assert_eq!(
            done.recv_timeout(BOUND).expect("the session did not end"),
            (
                End::Signal(Signal::SIGTERM as i32),
                Left {
                    cut: false,
                    unsent: 1,
                    not_taken: 0,
                }
            )
        );
    }

    #[test]
    fn a_plain_session_names_a_request_queued_when_the_login_expires() {
        let _one = crate::screen::testing::one_session();
        let fake = Fake::new(&[("hobi", AgentStanding::Enrolled)], 0);
        let leaf = Arc::new(fresh_leaf());
        let mut io = open_pipes("one\n");
        let done = spawn_session(&fake, Arc::clone(&leaf), now(), false, {
            let lines = io.lines();
            move || Io::Plain(lines)
        });
        assert!(io.shows("#1 submitted"), "nothing was submitted");
        fake.hold_collects();
        fake.held_collect();
        io.type_line("two\n");
        std::thread::sleep(Duration::from_millis(500));
        *leaf.not_after.lock().unwrap() = Some(0);
        fake.set(|s| s.hold = false);
        let deadline = std::time::Instant::now() + BOUND;
        while !io.output().contains(crate::agent::LOGIN_EXPIRED) {
            assert!(
                std::time::Instant::now() < deadline,
                "the login never ended"
            );
            std::thread::sleep(Duration::from_millis(10));
        }
        io.input = None;
        assert_eq!(
            done.recv_timeout(BOUND).expect("the session did not end"),
            (
                End::Failed,
                Left {
                    cut: false,
                    unsent: 1,
                    not_taken: 0,
                }
            )
        );
    }

    #[test]
    fn a_plain_session_says_on_stderr_when_the_kernel_is_lost_and_back_and_a_task_is_held() {
        let _one = crate::screen::testing::one_session();
        let fake = Fake::new(&[("hobi", AgentStanding::Enrolled)], 0);
        let mut io = open_pipes("one\n");
        let done = spawn_session(&fake, Arc::new(fresh_leaf()), u64::MAX, false, {
            let lines = io.lines();
            move || Io::Plain(lines)
        });
        let mut seen = String::new();
        let deadline = std::time::Instant::now() + BOUND;
        while !fake.calls().contains(&"submit") {
            assert!(
                std::time::Instant::now() < deadline,
                "nothing was submitted"
            );
            std::thread::sleep(Duration::from_millis(10));
        }
        fake.set(|s| s.unreachable = true);
        assert!(
            io.said(&mut seen, "maknae: hobi · kernel unreachable, retrying\n"),
            "{seen:?}"
        );
        fake.set(|s| s.unreachable = false);
        assert!(io.said(&mut seen, "maknae: hobi · connected\n"), "{seen:?}");
        fake.set(|s| s.tasks[0].state = TaskState::Held);
        let held = format!("maknae: hobi #1 {}\n", text::held_line());
        assert!(io.said(&mut seen, &held), "{seen:?}");
        io.input = None;
        assert_eq!(
            done.recv_timeout(BOUND).expect("the session did not end").0,
            End::Left
        );
        assert_eq!(seen.matches(&held).count(), 1, "said once: {seen:?}");
        assert_eq!(
            seen.matches("unreachable").count(),
            1,
            "said once: {seen:?}"
        );
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
        let done = spawn_session(&fake, Arc::new(fresh_leaf()), u64::MAX, false, move || {
            Io::Screen(Box::new(move || Session::enter_on(input, output)))
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
        assert_eq!(end, Ok((End::Left, Left::default())));
        assert_eq!(fake.calls().iter().filter(|c| **c == "submit").count(), 1);
    }

    #[test]
    fn wait_ends_once_a_dropped_task_is_closed() {
        let fake = Fake::new(&[("hobi", AgentStanding::Enrolled)], 0);
        let mut io = pipes("tidy my downloads\n/drop\n");
        let (end, _) = in_turn(&fake, fresh_leaf(), u64::MAX, true, io.lines());
        assert_eq!(end, End::Left);
        let out = io.output();
        assert!(out.contains("dropped #1\n"), "{out}");
        assert_eq!(fake.calls().iter().filter(|c| **c == "drop").count(), 1);
    }

    #[test]
    fn a_printed_entry_never_grows() {
        let mut conv = Conversation::new(1 << 16, 64);
        let id = conv
            .push(EntryKind::Report, &"report text ✓ ".repeat(20))
            .unwrap();
        let (entry, at) = entry_text(&conv, id);
        assert_eq!(
            maknae_agent::tasking::book::alloc_of(&entry, entry.capacity()),
            at
        );
        assert_eq!(entry.as_str(), "report text ✓ ".repeat(20));
    }

    #[tokio::test]
    async fn a_failed_remint_keeps_a_valid_leaf_and_says_no_identity_once_it_expires() {
        struct Refusing(Mutex<Option<u64>>, AtomicU32);
        impl Leaf for Refusing {
            fn not_after(&self) -> Option<u64> {
                *self.0.lock().unwrap()
            }
            async fn remint(&self) -> Result<(), String> {
                self.1.fetch_add(1, Ordering::SeqCst);
                Err("vault refused".into())
            }
        }
        let now = now();
        let kernel = Kernel {
            tasker: Fake::new(&[], 0),
            leaf: Refusing(Mutex::new(Some(now + 30)), AtomicU32::new(0)),
            logins: NoLogins,
            login_expires_at: now + 7200,
            agent: agent(),
            hints: no_hints(),
        };
        assert!(matches!(
            kernel.send(Op::Collect { after: None }, now).await,
            Event::Done(Ok(_))
        ));
        assert_eq!(kernel.tasker.calls(), ["collect"], "the valid leaf is used");
        assert!(matches!(
            kernel.send(Op::Collect { after: None }, now).await,
            Event::Done(Ok(_))
        ));
        assert_eq!(
            kernel.leaf.1.load(Ordering::SeqCst),
            2,
            "the mint is retried each time"
        );
        *kernel.leaf.0.lock().unwrap() = Some(now);
        assert!(matches!(
            kernel.send(Op::Collect { after: None }, now).await,
            Event::Done(Err(Failure::NoIdentity))
        ));
        assert_eq!(
            kernel.tasker.calls().len(),
            2,
            "nothing is sent without a leaf"
        );
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

    #[test]
    fn an_agent_list_that_cannot_be_written_fails() {
        struct Closed;
        impl std::io::Write for Closed {
            fn write(&mut self, _: &[u8]) -> std::io::Result<usize> {
                Err(std::io::Error::from(std::io::ErrorKind::BrokenPipe))
            }
            fn flush(&mut self) -> std::io::Result<()> {
                Ok(())
            }
        }
        let roster = Fake::new(&[("hobi", AgentStanding::Enrolled)], 0).roster;
        assert_eq!(print_list(&mut Closed, &roster), ExitCode::FAILURE);
        let mut out = Vec::new();
        assert_eq!(print_list(&mut out, &roster), ExitCode::SUCCESS);
        assert_eq!(out, b"hobi\n");
    }

    #[test]
    fn a_plain_wait_session_whose_request_was_refused_exits_1() {
        let fake = Fake::new(&[("hobi", AgentStanding::Enrolled)], 0);
        fake.set(|s| s.refuse_submit = true);
        let mut io = pipes("tidy my downloads\n");
        let ended = in_turn(&fake, fresh_leaf(), u64::MAX, true, io.lines());
        assert_eq!(
            ended,
            (
                End::Failed,
                Left {
                    cut: false,
                    unsent: 0,
                    not_taken: 1,
                }
            )
        );
        assert_eq!(
            ended.1.lines("hobi"),
            ["1 request was refused, not sent, or of unknown outcome"]
        );
    }

    #[test]
    fn a_plain_wait_session_against_a_contained_agent_exits_1() {
        let fake = Fake::new(&[("hobi", AgentStanding::Contained)], 0);
        let mut io = pipes("tidy my downloads\n");
        let ended = in_turn(&fake, fresh_leaf(), u64::MAX, true, io.lines());
        assert_eq!(
            ended,
            (
                End::Failed,
                Left {
                    cut: false,
                    unsent: 0,
                    not_taken: 1,
                }
            )
        );
        assert_eq!(
            ended.1.lines("hobi"),
            ["1 request was refused, not sent, or of unknown outcome"]
        );
        assert!(!fake.calls().contains(&"submit"));
        assert_eq!(io.output(), "hobi is on hold because it was contained\n");
    }

    #[test]
    fn a_queued_read_on_leaving_names_nothing_and_exits_0() {
        let _one = crate::screen::testing::one_session();
        let fake = Fake::new(&[("hobi", AgentStanding::Enrolled)], 0);
        let (mut pty, done) = full_screen(&fake, Arc::new(fresh_leaf()), u64::MAX);
        submit_one_behind_a_collect(&mut pty, &fake);
        leave_with_one_unsent(&mut pty, &done);
    }

    #[test]
    fn a_submit_typed_after_a_collect_falls_due_is_still_sent() {
        use maknae_agent::tasking::book::{COLLECT_IDLE_MS, COLLECT_OPEN_MS};
        let _one = crate::screen::testing::one_session();
        let fake = Fake::new(&[("hobi", AgentStanding::Enrolled)], 0);
        let (mut pty, done) = full_screen(&fake, Arc::new(fresh_leaf()), u64::MAX);
        assert!(pty.out.wait_for(b"connected"), "never connected");
        std::thread::sleep(Duration::from_millis(COLLECT_IDLE_MS + COLLECT_OPEN_MS));
        pty.type_keys(b"one\r");
        assert!(pty.out.wait_for(b"#1 submitted"), "no echo");
        fake.hold_collects();
        fake.held_collect();
        leave_with_one_unsent(&mut pty, &done);
    }

    #[test]
    fn a_signal_while_retiring_still_ends_with_its_status() {
        use nix::sys::signal::{kill, Signal};
        let _one = crate::screen::testing::one_session();
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        assert_eq!(
            rt.block_on(retire_unless_signalled(async {}, End::Left)),
            End::Left
        );
        let end = rt.block_on(async {
            let retiring = retire_unless_signalled(std::future::pending(), End::Left);
            tokio::pin!(retiring);
            tokio::select! {
                end = &mut retiring => end,
                () = async {
                    tokio::time::sleep(Duration::from_millis(200)).await;
                    kill(nix::unistd::Pid::this(), Signal::SIGINT).unwrap();
                    std::future::pending::<()>().await;
                } => unreachable!(),
            }
        });
        assert_eq!(end, End::Signal(Signal::SIGINT as i32));
    }

    #[test]
    fn what_a_session_left_behind_fails_it_and_is_named() {
        let clean = Left::default();
        assert_eq!(clean.end(End::Left), End::Left);
        assert!(clean.lines("hobi").is_empty());
        let unsent = Left {
            cut: false,
            unsent: 2,
            not_taken: 0,
        };
        assert_eq!(unsent.end(End::Left), End::Failed);
        assert_eq!(unsent.end(End::Signal(15)), End::Signal(15));
        assert_eq!(
            unsent.lines("hobi"),
            ["2 requests were not sent; they were not given to hobi"]
        );
        let cut = Left {
            cut: true,
            unsent: 0,
            not_taken: 0,
        };
        assert_eq!(cut.end(End::Left), End::Failed);
        assert_eq!(cut.lines("hobi"), [CUT_OFF]);
    }
}
