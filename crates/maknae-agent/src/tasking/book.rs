use super::commands::{parse, Parsed};
use super::text::{self, Unknown};
use crate::render::display_safe_len;
use crate::screen::blocks::{Conversation, EntryId, EntryKind};
use crate::screen::HeaderLine;
use maknae_proto::{
    AgentStanding, SecretText, TaskCursor, TaskPage, TaskRef, TaskReportPage, TaskReportView,
    TaskState, TaskView,
};
use std::collections::{BTreeSet, VecDeque};
use zeroize::Zeroizing;

pub const POLL_EVERY_MS: u64 = 1_000;
pub const COLLECT_OPEN_MS: u64 = 2_000;
pub const COLLECT_IDLE_MS: u64 = 5_000;
/// The most `TaskList` pages one poll follows before the next poll starts over.
pub const SWEEP_PAGES: u32 = 16;
const SPINNER: [char; 10] = ['⠋', '⠙', '⠹', '⠸', '⠼', '⠴', '⠦', '⠧', '⠇', '⠏'];
const SPIN_MS: u64 = 100;

/// The caller's standing with the agent, as the agent list said when the session opened.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Standing {
    Enrolled,
    Contained,
    Withdrawn,
    Removed,
}

impl Standing {
    /// `None` for an undecided entry, which opens no session.
    pub fn of(standing: AgentStanding) -> Option<Standing> {
        match standing {
            AgentStanding::Enrolled => Some(Standing::Enrolled),
            AgentStanding::Contained => Some(Standing::Contained),
            AgentStanding::Withdrawn => Some(Standing::Withdrawn),
            AgentStanding::Removed => Some(Standing::Removed),
            AgentStanding::Undecided => None,
        }
    }
}

/// One tasker verb for the caller's client to send.
#[derive(Debug)]
pub enum Op {
    Collect {
        after: Option<TaskCursor>,
    },
    /// One `TaskList` page.
    Poll {
        after: Option<TaskCursor>,
    },
    /// Every `TaskList` page.
    ListAll,
    Submit {
        text: SecretText,
    },
    Add {
        task: TaskRef,
        text: SecretText,
    },
    Stop {
        task: TaskRef,
    },
    Drop {
        task: TaskRef,
    },
    Status {
        task: TaskRef,
    },
}

#[derive(Debug)]
pub enum Answer {
    Reports(TaskReportPage),
    Page(TaskPage),
    Tasks(Vec<TaskView>),
    View(TaskView),
}

#[derive(Clone, PartialEq, Eq, Debug)]
pub enum Failure {
    Refused { outcome_unknown: bool },
    Unreachable { after_write: bool },
    Protocol(String),
}

impl Failure {
    /// Whether the verb may have taken effect although no answer says so.
    fn unknown(&self) -> bool {
        match self {
            Failure::Refused { outcome_unknown } => *outcome_unknown,
            Failure::Unreachable { after_write } => *after_write,
            Failure::Protocol(_) => true,
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Entered {
    Stay,
    Leave,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Connection {
    Connecting,
    Connected,
    Unreachable,
    Unreadable,
}

/// What the verb in flight was, to read its answer.
#[derive(Debug)]
enum Asked {
    Collect { after: Option<u64>, away: bool },
    Poll { from: Option<u64>, pages: u32 },
    ListAll { opening: bool },
    Submit,
    Add(u32),
    Stop(u32),
    Drop(u32),
    Status(u32),
}

struct Task {
    number: u32,
    task: TaskRef,
    view: Option<TaskView>,
    polled_at: u64,
    /// Its report or close notice is in the conversation.
    placed: bool,
    /// A finished poll no longer returns it.
    gone: bool,
    /// Submitted in this session.
    mine: bool,
}

impl Task {
    fn state(&self) -> Option<TaskState> {
        self.view.as_ref().map(|v| v.state)
    }

    /// Shown with an indicator.
    fn shown(&self) -> bool {
        !self.placed
            && !self.gone
            && matches!(
                self.state(),
                Some(
                    TaskState::Queued | TaskState::Working | TaskState::Held | TaskState::Reported
                )
            )
    }

    /// What a command with no number may act on.
    fn open(&self) -> bool {
        !self.gone
            && matches!(
                self.state(),
                Some(TaskState::Queued | TaskState::Working | TaskState::Held)
            )
    }

    fn cursor(&self) -> Option<u64> {
        self.view.as_ref().map(|v| v.cursor.seq())
    }
}

/// A collected report not yet in the conversation.
struct Held {
    report: TaskReportView,
    away: bool,
}

/// The session's tasks and the verbs that keep them current: numbering, the
/// poll and collect plan, the acknowledgement cursor, and what the person is
/// told. Sends nothing itself: the caller takes each [`Op`] from
/// [`Book::next_op`] and hands its answer to [`Book::done`].
pub struct Book {
    agent: String,
    standing: Standing,
    announce: bool,
    tasks: Vec<Task>,
    queue: VecDeque<(Op, Asked)>,
    flight: Option<Asked>,
    connection: Connection,
    reread: bool,
    sweep: Option<(TaskCursor, Option<u64>, u32)>,
    swept: BTreeSet<TaskRef>,
    next_poll: u64,
    collected_at: u64,
    collect_soon: bool,
    acked: Option<u64>,
    placed: VecDeque<(u64, EntryId)>,
    high: Option<u64>,
    held: VecDeque<Held>,
    collect_refusal_said: bool,
    stopped: bool,
    status: Vec<String>,
}

impl std::fmt::Debug for Book {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Book")
            .field("tasks", &self.tasks.len())
            .field("queued", &self.queue.len())
            .field("held", &self.held.len())
            .finish()
    }
}

impl Book {
    /// `announce` prints each task's state changes as lines, for a session
    /// without a screen.
    pub fn new(agent: &str, standing: Standing, announce: bool) -> Book {
        let mut queue = VecDeque::new();
        queue.push_back((
            Op::Collect { after: None },
            Asked::Collect {
                after: None,
                away: true,
            },
        ));
        queue.push_back((Op::ListAll, Asked::ListAll { opening: true }));
        Book {
            agent: text::safe(agent),
            standing,
            announce,
            tasks: Vec::new(),
            queue,
            flight: None,
            connection: Connection::Connecting,
            reread: false,
            sweep: None,
            swept: BTreeSet::new(),
            next_poll: 0,
            collected_at: 0,
            collect_soon: false,
            acked: None,
            placed: VecDeque::new(),
            high: None,
            held: VecDeque::new(),
            collect_refusal_said: false,
            stopped: false,
            status: Vec::new(),
        }
    }

    pub fn status(&self) -> &[String] {
        &self.status
    }

    pub fn header(&self) -> HeaderLine {
        let state = match (self.stopped, self.connection, self.standing) {
            (true, _, _) => text::LOGIN_ENDED,
            (_, Connection::Unreachable, _) => text::UNREACHABLE,
            (_, Connection::Unreadable, _) => text::UNREADABLE,
            (_, _, Standing::Removed) => "removed",
            (_, _, Standing::Contained) => "on hold (contained)",
            (_, _, Standing::Withdrawn) => "you can no longer task this agent",
            (_, Connection::Connecting, Standing::Enrolled) => text::CONNECTING,
            (_, Connection::Connected, Standing::Enrolled) => text::CONNECTED,
        };
        let right = match self.held.len() {
            0 => String::new(),
            1 => "1 report waiting: scroll down to read on".into(),
            n => format!("{n} reports waiting: scroll down to read on"),
        };
        HeaderLine {
            left: format!("{} · {state}", self.agent),
            right,
        }
    }

    /// Whether an indicator is on screen, so the spinner turns.
    pub fn animating(&self) -> bool {
        !self.stopped && self.tasks.iter().any(Task::shown)
    }

    /// Whether the session polls no more (its login ended).
    pub fn stopped(&self) -> bool {
        self.stopped
    }

    pub fn in_flight(&self) -> bool {
        self.flight.is_some()
    }

    /// An entered line: a request, a command, or nothing.
    pub fn enter(&mut self, line: Zeroizing<String>, now: u64, conv: &mut Conversation) -> Entered {
        let parsed = parse(&line);
        let entered = match parsed {
            Parsed::Empty => Entered::Stay,
            Parsed::Request => {
                if let Some(refusal) = self.refuse_tasking() {
                    say(conv, &refusal);
                } else if conv.push(EntryKind::Request, &line).is_err() {
                    say(conv, text::CONVERSATION_FULL);
                } else {
                    let text = SecretText(line);
                    self.queue.push_back((Op::Submit { text }, Asked::Submit));
                    return self.after_entry(now);
                }
                Entered::Stay
            }
            Parsed::Add { number, text } => {
                self.add(number, text, &line, conv);
                Entered::Stay
            }
            Parsed::Stop(number) => {
                self.steer(number, conv, true);
                Entered::Stay
            }
            Parsed::Drop(number) => {
                self.steer(number, conv, false);
                Entered::Stay
            }
            Parsed::Status(Some(n)) => {
                match self.task_index(n) {
                    Some(at) => {
                        let task = self.tasks[at].task.clone();
                        self.queue
                            .push_back((Op::Status { task }, Asked::Status(n)));
                    }
                    None => say(conv, &format!("there is no task #{n}")),
                }
                Entered::Stay
            }
            Parsed::Status(None) => {
                let lines: Vec<String> = self
                    .tasks
                    .iter()
                    .filter(|t| t.shown())
                    .map(|t| self.status_of(t, now))
                    .collect();
                if lines.is_empty() {
                    say(conv, "no open tasks");
                }
                for line in lines {
                    say(conv, &line);
                }
                Entered::Stay
            }
            Parsed::List => {
                self.queue
                    .push_back((Op::ListAll, Asked::ListAll { opening: false }));
                Entered::Stay
            }
            Parsed::Bye => Entered::Leave,
            Parsed::Help => {
                for line in text::help_lines() {
                    say(conv, &line);
                }
                Entered::Stay
            }
            Parsed::Unknown(word) => {
                let word = text::safe(word);
                say(
                    conv,
                    &format!("{word} is not a command and was not sent: /help lists the commands"),
                );
                Entered::Stay
            }
            Parsed::Usage(usage) => {
                say(conv, usage);
                Entered::Stay
            }
        };
        self.refresh(now);
        entered
    }

    fn after_entry(&mut self, now: u64) -> Entered {
        self.refresh(now);
        Entered::Stay
    }

    fn refuse_tasking(&self) -> Option<String> {
        match self.standing {
            Standing::Enrolled => None,
            Standing::Withdrawn => Some(format!("you can no longer task {}", self.agent)),
            Standing::Removed | Standing::Contained => self.refuse_steering(),
        }
    }

    fn refuse_steering(&self) -> Option<String> {
        match self.standing {
            Standing::Enrolled | Standing::Withdrawn => None,
            Standing::Removed => Some(format!("{} was removed", self.agent)),
            Standing::Contained => Some(format!(
                "{} is on hold because it was contained",
                self.agent
            )),
        }
    }

    fn add(&mut self, number: Option<u32>, add: &str, line: &str, conv: &mut Conversation) {
        if let Some(refusal) = self.refuse_tasking() {
            return say(conv, &refusal);
        }
        let Some((n, task)) = self.target(number, conv, "add to") else {
            return;
        };
        if conv.push(EntryKind::Request, line).is_err() {
            return say(conv, text::CONVERSATION_FULL);
        }
        let mut copy = Zeroizing::new(String::with_capacity(add.len()));
        copy.push_str(add);
        self.queue.push_back((
            Op::Add {
                task,
                text: SecretText(copy),
            },
            Asked::Add(n),
        ));
    }

    fn steer(&mut self, number: Option<u32>, conv: &mut Conversation, stop: bool) {
        if let Some(refusal) = self.refuse_steering() {
            return say(conv, &refusal);
        }
        let verb = if stop { "stop" } else { "drop" };
        let Some((n, task)) = self.target(number, conv, verb) else {
            return;
        };
        let op = if stop {
            (Op::Stop { task }, Asked::Stop(n))
        } else {
            (Op::Drop { task }, Asked::Drop(n))
        };
        self.queue.push_back(op);
    }

    /// Task `number`, or with none the newest open task.
    fn target(
        &self,
        number: Option<u32>,
        conv: &mut Conversation,
        verb: &str,
    ) -> Option<(u32, TaskRef)> {
        let found = match number {
            Some(n) => self.task_index(n).map(|at| &self.tasks[at]),
            None => self
                .tasks
                .iter()
                .filter(|t| t.open())
                .max_by_key(|t| t.cursor()),
        };
        match (found, number) {
            (Some(t), _) => Some((t.number, t.task.clone())),
            (None, Some(n)) => {
                say(conv, &format!("there is no task #{n}"));
                None
            }
            (None, None) => {
                say(conv, &format!("there is no open task to {verb}"));
                None
            }
        }
    }

    fn task_index(&self, n: u32) -> Option<usize> {
        let at = usize::try_from(n).ok()?.checked_sub(1)?;
        (at < self.tasks.len()).then_some(at)
    }

    /// The next verb to send, or `None` while one is in flight or none is due.
    pub fn next_op(&mut self, now: u64, conv: &Conversation) -> Option<Op> {
        if self.flight.is_some() || self.stopped {
            return None;
        }
        if let Some((op, asked)) = self.queue.pop_front() {
            self.flight = Some(asked);
            return Some(op);
        }
        if let Some((after, from, pages)) = self.sweep.take() {
            self.flight = Some(Asked::Poll { from, pages });
            return Some(Op::Poll { after: Some(after) });
        }
        let shown = self.tasks.iter().any(Task::shown);
        if (self.reread || shown) && now >= self.next_poll {
            self.reread = false;
            self.next_poll = now + POLL_EVERY_MS;
            let from = self.poll_from();
            self.swept.clear();
            self.flight = Some(Asked::Poll { from, pages: 1 });
            return Some(Op::Poll {
                after: from.map(TaskCursor::from_seq),
            });
        }
        let every = if shown {
            COLLECT_OPEN_MS
        } else {
            COLLECT_IDLE_MS
        };
        if self.held.is_empty() && (self.collect_soon || now >= self.collected_at + every) {
            self.collect_soon = false;
            self.collected_at = now;
            let after = self.ack_upto(conv);
            self.flight = Some(Asked::Collect { after, away: false });
            return Some(Op::Collect {
                after: after.map(TaskCursor::from_seq),
            });
        }
        None
    }

    /// The submission ordinal a poll lists after: just before the oldest shown
    /// task, or with none shown after the newest known one, so a task a lost
    /// answer may have created is still found.
    fn poll_from(&self) -> Option<u64> {
        match self
            .tasks
            .iter()
            .filter(|t| t.shown())
            .filter_map(Task::cursor)
            .min()
        {
            Some(oldest) => oldest.checked_sub(1),
            None => self.tasks.iter().filter_map(Task::cursor).max(),
        }
    }

    /// The newest report cursor every report up to which has been on screen.
    fn ack_upto(&self, conv: &Conversation) -> Option<u64> {
        let mut upto = self.acked;
        for (cursor, id) in &self.placed {
            if conv.is_seen(*id) == Some(false) {
                break;
            }
            upto = Some(*cursor);
        }
        upto
    }

    /// The answer to the verb [`Book::next_op`] last gave.
    pub fn done(&mut self, answer: Result<Answer, Failure>, now: u64, conv: &mut Conversation) {
        let Some(asked) = self.flight.take() else {
            return;
        };
        match &answer {
            Ok(_) | Err(Failure::Refused { .. }) => self.connection = Connection::Connected,
            Err(Failure::Unreachable { .. }) => self.connection = Connection::Unreachable,
            Err(Failure::Protocol(_)) => self.connection = Connection::Unreadable,
        }
        match (asked, answer) {
            (Asked::Collect { after, away }, Ok(Answer::Reports(page))) => {
                self.collected(after, away, page, now, conv)
            }
            (Asked::Collect { .. }, Err(e)) => self.collect_failed(&e, conv),
            (Asked::Poll { from, pages }, Ok(Answer::Page(page))) => {
                self.polled(from, pages, page, now, conv)
            }
            (Asked::Poll { .. }, Err(_)) => {
                self.sweep = None;
                self.reread = true;
            }
            (Asked::ListAll { opening }, Ok(Answer::Tasks(all))) => {
                self.listed(opening, all, now, conv)
            }
            (Asked::ListAll { opening: false } | Asked::Status(_), Err(e)) => {
                say(conv, &read_failure(&e))
            }
            (Asked::ListAll { opening: true }, Err(_)) => self.reread = true,
            (Asked::Submit, Ok(Answer::View(view))) => self.submitted(view, now, conv),
            (Asked::Add(n), Ok(Answer::View(view))) => {
                self.update(view, now, conv);
                say(conv, &format!("added to #{n}"));
            }
            (Asked::Stop(n), Ok(Answer::View(view))) => {
                self.update(view, now, conv);
                say(conv, &format!("stopped #{n}"));
            }
            (Asked::Drop(n), Ok(Answer::View(view))) => {
                self.update(view, now, conv);
                say(conv, &format!("dropped #{n}"));
            }
            (Asked::Status(n), Ok(Answer::View(view))) => {
                self.update(view, now, conv);
                if let Some(at) = self.task_index(n) {
                    let line = self.full_status(&self.tasks[at], now);
                    say(conv, &line);
                }
            }
            (Asked::Submit, Err(e)) => self.steer_failed(Unknown::Submit, &e, conv),
            (Asked::Add(n), Err(e)) => self.steer_failed(Unknown::Add(n), &e, conv),
            (Asked::Stop(n), Err(e)) => self.steer_failed(Unknown::Stop(n), &e, conv),
            (Asked::Drop(n), Err(e)) => self.steer_failed(Unknown::Drop(n), &e, conv),
            (_, Ok(_)) => {
                self.connection = Connection::Unreadable;
                say(
                    conv,
                    "the kernel answered with something other than what was asked",
                );
                self.reread = true;
            }
        }
        self.refresh(now);
    }

    fn steer_failed(&mut self, op: Unknown, e: &Failure, conv: &mut Conversation) {
        if e.unknown() {
            say(conv, &text::outcome_unknown_line(op));
            self.reread = true;
            return;
        }
        let line = match (op, e) {
            (Unknown::Submit, Failure::Unreachable { .. }) => {
                "the kernel could not be reached; your request was not sent".to_string()
            }
            (_, Failure::Unreachable { .. }) => {
                "the kernel could not be reached; nothing was sent".to_string()
            }
            _ => "the kernel refused it".to_string(),
        };
        say(conv, &line);
    }

    fn collected(
        &mut self,
        after: Option<u64>,
        away: bool,
        page: TaskReportPage,
        now: u64,
        conv: &mut Conversation,
    ) {
        self.collect_refusal_said = false;
        if after.is_some() {
            self.acked = after;
            self.placed.retain(|(cursor, _)| Some(*cursor) > after);
        }
        let more = page.next.is_some();
        let mut fresh = false;
        for report in page.entries {
            let seq = report.cursor.seq();
            if self.high.is_some_and(|high| seq <= high) {
                continue;
            }
            self.high = Some(seq);
            fresh = true;
            self.held.push_back(Held { report, away });
        }
        self.collect_soon = more && fresh;
        self.place(now, conv);
    }

    fn collect_failed(&mut self, e: &Failure, conv: &mut Conversation) {
        if !e.unknown() {
            return;
        }
        if !self.collect_refusal_said {
            say(conv, &text::outcome_unknown_line(Unknown::Collect));
            self.collect_refusal_said = true;
        }
        self.high = self.acked;
        self.placed.clear();
    }

    /// Moves collected reports into the conversation, oldest first, stopping
    /// before one that would push out a report not yet seen.
    fn place(&mut self, now: u64, conv: &mut Conversation) {
        while let Some((task, away)) = self.held.front().map(|h| (h.report.task.clone(), h.away)) {
            let n = self.number_of(&task, now);
            let Some(front) = self.held.front() else {
                return;
            };
            let report = &front.report;
            let mut head = format!("{} #{n}", self.agent);
            if away {
                head.push_str(" · ");
                head.push_str(text::AWAY);
            }
            let body: &str = match report.close {
                Some(close) => text::close_line(close),
                None => &report.text.0,
            };
            let len = head.len() + 1 + body.len();
            if conv.would_drop_unseen(display_safe_len(&head) + 1 + display_safe_len(body)) {
                return;
            }
            let mut entry = Zeroizing::new(String::with_capacity(len));
            entry.push_str(&head);
            entry.push('\n');
            entry.push_str(body);
            let Ok(id) = conv.push(EntryKind::Report, &entry) else {
                return;
            };
            let Some(Held { report, .. }) = self.held.pop_front() else {
                return;
            };
            self.placed.push_back((report.cursor.seq(), id));
            if let Some(at) = self.index_of(&report.task) {
                let task = &mut self.tasks[at];
                task.placed = true;
                if let (Some(close), Some(view)) = (report.close, task.view.as_mut()) {
                    view.state = TaskState::Closed;
                    view.close = Some(close);
                }
            }
        }
    }

    fn index_of(&self, task: &TaskRef) -> Option<usize> {
        self.tasks.iter().position(|t| t.task == *task)
    }

    /// The task's number, numbering it now when it is new.
    fn number_of(&mut self, task: &TaskRef, now: u64) -> u32 {
        match self.index_of(task) {
            Some(at) => self.tasks[at].number,
            None => self.number(task.clone(), None, now, false),
        }
    }

    fn number(&mut self, task: TaskRef, view: Option<TaskView>, now: u64, mine: bool) -> u32 {
        let number = u32::try_from(self.tasks.len() + 1).unwrap_or(u32::MAX);
        self.tasks.push(Task {
            number,
            task,
            view,
            polled_at: now,
            placed: false,
            gone: false,
            mine,
        });
        number
    }

    fn polled(
        &mut self,
        from: Option<u64>,
        pages: u32,
        page: TaskPage,
        now: u64,
        conv: &mut Conversation,
    ) {
        for view in page.entries {
            self.swept.insert(view.task.clone());
            self.see(view, now, conv);
        }
        match page.next {
            Some(next) if pages < SWEEP_PAGES => self.sweep = Some((next, from, pages + 1)),
            Some(_) => {}
            None => {
                for task in &mut self.tasks {
                    let listed_range = task.cursor().is_some_and(|c| from.is_none_or(|f| c > f));
                    if task.shown() && listed_range && !self.swept.contains(&task.task) {
                        task.gone = true;
                    }
                }
            }
        }
    }

    /// A view from a poll: an update, or a task first shown now when it is open.
    fn see(&mut self, view: TaskView, now: u64, conv: &mut Conversation) {
        if self.index_of(&view.task).is_some() {
            return self.update(view, now, conv);
        }
        if matches!(
            view.state,
            TaskState::Queued | TaskState::Working | TaskState::Held | TaskState::Reported
        ) {
            let n = self.number(view.task.clone(), None, now, false);
            self.update(view, now, conv);
            debug_assert!(n > 0);
        }
    }

    fn update(&mut self, view: TaskView, now: u64, conv: &mut Conversation) {
        let Some(at) = self.index_of(&view.task) else {
            return;
        };
        let task = &mut self.tasks[at];
        let was = task.state();
        let state = view.state;
        task.view = Some(view);
        task.polled_at = now;
        task.gone = false;
        if was == Some(state) || task.placed {
            return;
        }
        let n = task.number;
        if state == TaskState::Held {
            say(conv, &format!("#{n} {}", text::held_line()));
        } else if self.announce {
            say(conv, &format!("#{n} {}", text::state_word(state)));
        }
    }

    fn listed(&mut self, opening: bool, all: Vec<TaskView>, now: u64, conv: &mut Conversation) {
        if opening {
            for view in all {
                self.see(view, now, conv);
            }
            return;
        }
        if all.is_empty() {
            say(conv, &format!("you have no tasks with {}", self.agent));
        }
        for view in all {
            let n = match self.index_of(&view.task) {
                Some(at) => self.tasks[at].number,
                None => self.number(view.task.clone(), None, now, false),
            };
            let mut line = format!("#{n} {}", text::state_word(view.state));
            if let Some(close) = view.close {
                line.push_str(": ");
                line.push_str(text::close_line(close));
            }
            self.update(view, now, conv);
            say(conv, &line);
        }
    }

    fn submitted(&mut self, view: TaskView, now: u64, conv: &mut Conversation) {
        let others = self.tasks.iter().any(Task::open);
        let n = match self.index_of(&view.task) {
            Some(at) => {
                self.tasks[at].mine = true;
                self.tasks[at].number
            }
            None => self.number(view.task.clone(), None, now, true),
        };
        let quiet = self.announce;
        self.announce = false;
        self.update(view, now, conv);
        self.announce = quiet;
        if others {
            say(
                conv,
                &format!("started a new task #{n} (use /add {n} to add to a running one)"),
            );
        } else {
            say(conv, &format!("#{n} submitted"));
        }
    }

    /// Advances the clock: the spinner, the elapsed times, and any report
    /// waiting for room. True when the screen changed.
    pub fn tick(&mut self, now: u64, conv: &mut Conversation) -> bool {
        let waiting = self.held.len();
        if waiting > 0 {
            self.place(now, conv);
        }
        let before = std::mem::take(&mut self.status);
        self.refresh(now);
        before != self.status || waiting != self.held.len()
    }

    /// The login ended: say so once and poll no more.
    pub fn stop(&mut self, line: &str, conv: &mut Conversation) {
        if !self.stopped {
            say(conv, line);
        }
        self.stopped = true;
        self.flight = None;
        self.queue.clear();
        self.status.clear();
    }

    /// Whether a session without a screen may end: nothing sent is unanswered,
    /// and with `wait` every task it submitted has its report or close shown
    /// and acknowledged.
    pub fn settled(&self, wait: bool) -> bool {
        if self.stopped {
            return true;
        }
        if self.flight.is_some() || !self.queue.is_empty() || self.sweep.is_some() {
            return false;
        }
        let unacked = !self.placed.is_empty() && self.connection == Connection::Connected;
        if !wait {
            return !unacked;
        }
        let pending = self.tasks.iter().any(|t| t.mine && !t.placed && !t.gone);
        !pending && !unacked && self.held.is_empty()
    }

    /// Asks for the acknowledging collect now rather than at its time.
    pub fn hurry(&mut self) {
        if !self.placed.is_empty() {
            self.collect_soon = true;
        }
    }

    fn refresh(&mut self, now: u64) {
        let lines: Vec<String> = self
            .tasks
            .iter()
            .filter(|t| t.shown())
            .map(|t| self.status_of(t, now))
            .collect();
        self.status = lines;
    }

    fn running(task: &Task) -> bool {
        matches!(task.state(), Some(TaskState::Queued | TaskState::Working))
    }

    fn elapsed_of(task: &Task, now: u64) -> u64 {
        let base = task.view.as_ref().map_or(0, |v| v.elapsed_secs);
        if Self::running(task) {
            base + now.saturating_sub(task.polled_at) / 1000
        } else {
            base
        }
    }

    fn status_of(&self, task: &Task, now: u64) -> String {
        let glyph = if Self::running(task) {
            let at = usize::try_from(now / SPIN_MS).unwrap_or(0) % SPINNER.len();
            SPINNER[at]
        } else {
            '·'
        };
        let state = task.state().map_or("", text::state_word);
        format!(
            "{glyph} #{} {state} {}",
            task.number,
            text::elapsed(Self::elapsed_of(task, now))
        )
    }

    fn full_status(&self, task: &Task, now: u64) -> String {
        let Some(view) = task.view.as_ref() else {
            return format!("#{}", task.number);
        };
        let mut line = format!("#{} {}", task.number, text::state_word(view.state));
        if let Some(close) = view.close {
            line.push_str(": ");
            line.push_str(text::close_line(close));
        }
        line.push_str(&format!(
            " · {} elapsed · {} action{}",
            text::elapsed(Self::elapsed_of(task, now)),
            view.actions,
            if view.actions == 1 { "" } else { "s" }
        ));
        line
    }
}

fn say(conv: &mut Conversation, line: &str) {
    let _ = conv.push(EntryKind::Notice, line);
}

fn read_failure(e: &Failure) -> String {
    match e {
        Failure::Refused { .. } => "the kernel refused it".into(),
        Failure::Unreachable { .. } => "the kernel could not be reached; try again".into(),
        Failure::Protocol(_) => "the kernel's answer could not be read; try again".into(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use maknae_proto::{TaskClose, TaskId};

    fn task(n: u8) -> TaskRef {
        TaskRef::from_id(&TaskId([n; 16]))
    }

    fn view(n: u8, seq: u64, state: TaskState) -> TaskView {
        TaskView {
            task: task(n),
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

    fn report(n: u8, seq: u64, text: &str, close: Option<TaskClose>) -> TaskReportView {
        TaskReportView {
            task: task(n),
            agent: "hobi".into(),
            close,
            text: SecretText(Zeroizing::new(text.into())),
            at_secs: 0,
            cursor: TaskCursor::from_seq(seq),
        }
    }

    fn reports(entries: Vec<TaskReportView>) -> Result<Answer, Failure> {
        Ok(Answer::Reports(TaskReportPage {
            entries,
            next: None,
        }))
    }

    fn page(entries: Vec<TaskView>, next: Option<u64>) -> Result<Answer, Failure> {
        Ok(Answer::Page(TaskPage {
            entries,
            next: next.map(TaskCursor::from_seq),
        }))
    }

    const REFUSED: Failure = Failure::Refused {
        outcome_unknown: true,
    };

    struct Run {
        book: Book,
        conv: Conversation,
        now: u64,
    }

    impl Run {
        fn with(
            standing: Standing,
            announce: bool,
            away: Vec<TaskReportView>,
            open: Vec<TaskView>,
        ) -> Run {
            let mut run = Run {
                book: Book::new("hobi", standing, announce),
                conv: Conversation::new(1 << 20, 4096),
                now: 0,
            };
            assert!(matches!(run.op(), Op::Collect { after: None }));
            run.answer(reports(away));
            assert!(matches!(run.op(), Op::ListAll));
            run.answer(Ok(Answer::Tasks(open)));
            run
        }

        fn new(standing: Standing) -> Run {
            Run::with(standing, false, vec![], vec![])
        }

        fn op(&mut self) -> Op {
            match self.book.next_op(self.now, &self.conv) {
                Some(op) => op,
                None => panic!("no op due at {}", self.now),
            }
        }

        fn none_due(&mut self) {
            if let Some(op) = self.book.next_op(self.now, &self.conv) {
                panic!("unexpected {op:?}");
            }
        }

        fn nothing_queued(&self) {
            assert!(self.book.queue.is_empty(), "{:?}", self.book.queue);
        }

        /// Answers the next due poll with `polled` and collect with `collected`.
        fn answer_due(&mut self, polled: Vec<TaskView>, collected: Vec<TaskReportView>) -> bool {
            match self.op() {
                Op::Poll { .. } => {
                    self.answer(page(polled, None));
                    false
                }
                Op::Collect { .. } => {
                    self.answer(reports(collected));
                    true
                }
                other => panic!("{other:?}"),
            }
        }

        fn answer(&mut self, answer: Result<Answer, Failure>) {
            self.book.done(answer, self.now, &mut self.conv);
        }

        fn enter(&mut self, line: &str) -> Entered {
            self.book
                .enter(Zeroizing::new(line.into()), self.now, &mut self.conv)
        }

        fn submit(&mut self, line: &str, n: u8, seq: u64) {
            self.enter(line);
            match self.op() {
                Op::Submit { text } => assert_eq!(text.0.as_str(), line),
                other => panic!("expected a submit, got {other:?}"),
            }
            self.answer(Ok(Answer::View(view(n, seq, TaskState::Queued))));
        }

        fn texts(&self) -> Vec<String> {
            let (Some(first), Some(last)) = (self.conv.first(), self.conv.last()) else {
                return vec![];
            };
            (first.get()..=last.get())
                .map(|n| self.conv.segments(EntryId::nth(n)).collect())
                .collect()
        }

        fn last_text(&self) -> String {
            self.texts().pop().unwrap_or_default()
        }

        fn draw_all(&mut self) {
            if let (Some(first), Some(last)) = (self.conv.first(), self.conv.last()) {
                self.conv.mark_seen(first..=last);
            }
        }

        fn wait(&mut self, ms: u64) {
            self.now += ms;
            self.book.tick(self.now, &mut self.conv);
        }
    }

    #[test]
    fn typing_while_a_task_runs_starts_a_new_numbered_task_and_says_so() {
        let mut run = Run::new(Standing::Enrolled);
        run.submit("tidy my downloads", 1, 1);
        assert_eq!(run.last_text(), "#1 submitted");
        assert_eq!(run.texts()[0], "tidy my downloads");
        run.answer(Ok(Answer::View(view(1, 1, TaskState::Working))));
        run.submit("also email bob", 2, 2);
        assert_eq!(
            run.last_text(),
            "started a new task #2 (use /add 2 to add to a running one)"
        );
        assert_eq!(run.book.status().len(), 2);
        assert!(run.book.status()[0].contains("#1 queued"));
        assert!(run.book.status()[1].contains("#2 queued"));
    }

    #[test]
    fn a_bare_stop_targets_the_newest_open_task_and_echoes_it() {
        let mut run = Run::new(Standing::Enrolled);
        run.submit("one", 1, 1);
        run.submit("two", 2, 2);
        run.enter("/stop");
        match run.op() {
            Op::Stop { task: t } => assert_eq!(t, task(2)),
            other => panic!("{other:?}"),
        }
        let mut stopped = view(2, 2, TaskState::Closed);
        stopped.close = Some(TaskClose::Stopped);
        run.answer(Ok(Answer::View(stopped)));
        assert_eq!(run.last_text(), "stopped #2");
        run.enter("/drop");
        match run.op() {
            Op::Drop { task: t } => assert_eq!(t, task(1)),
            other => panic!("{other:?}"),
        }
        run.answer(Ok(Answer::View(view(1, 1, TaskState::Closed))));
        assert_eq!(run.last_text(), "dropped #1");
        run.enter("/stop");
        run.nothing_queued();
        assert_eq!(run.last_text(), "there is no open task to stop");
    }

    #[test]
    fn stop_2_targets_task_2() {
        let mut run = Run::new(Standing::Enrolled);
        run.submit("one", 1, 1);
        run.submit("two", 2, 2);
        run.submit("three", 3, 3);
        run.enter("/stop 2");
        match run.op() {
            Op::Stop { task: t } => assert_eq!(t, task(2)),
            other => panic!("{other:?}"),
        }
        run.answer(Ok(Answer::View(view(2, 2, TaskState::Closed))));
        assert_eq!(run.last_text(), "stopped #2");
        run.enter("/add 1 the logs too");
        match run.op() {
            Op::Add { task: t, text } => {
                assert_eq!(t, task(1));
                assert_eq!(text.0.as_str(), "the logs too");
            }
            other => panic!("{other:?}"),
        }
        run.answer(Ok(Answer::View(view(1, 1, TaskState::Working))));
        assert_eq!(run.last_text(), "added to #1");
        run.enter("/drop 9");
        run.nothing_queued();
        assert_eq!(run.last_text(), "there is no task #9");
    }

    #[test]
    fn a_bare_stop_never_targets_a_reported_task() {
        let mut run = Run::new(Standing::Enrolled);
        run.submit("one", 1, 1);
        run.submit("two", 2, 2);
        run.now = 1_000;
        assert!(matches!(run.op(), Op::Poll { after: Some(a) } if a.seq() == 0));
        run.answer(page(
            vec![
                view(1, 1, TaskState::Working),
                view(2, 2, TaskState::Reported),
            ],
            None,
        ));
        assert!(run.book.status().iter().any(|s| s.contains("#2 reported")));
        run.enter("/stop");
        match run.op() {
            Op::Stop { task: t } => assert_eq!(t, task(1)),
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn reports_on_open_are_marked_while_you_were_away_and_acknowledged_after_display() {
        let mut run = Run::with(
            Standing::Enrolled,
            false,
            vec![
                report(7, 4, "done: 3 files", None),
                report(8, 5, "also done", None),
            ],
            vec![],
        );
        assert_eq!(
            run.texts(),
            [
                "hobi #1 · while you were away\ndone: 3 files",
                "hobi #2 · while you were away\nalso done"
            ]
        );
        run.now = COLLECT_IDLE_MS;
        assert!(
            matches!(run.op(), Op::Collect { after: None }),
            "nothing is acknowledged before it is drawn"
        );
        run.answer(reports(vec![
            report(7, 4, "done: 3 files", None),
            report(8, 5, "also done", None),
        ]));
        assert_eq!(
            run.texts().len(),
            2,
            "an unacknowledged report is not shown twice"
        );
        let first = run.conv.first().unwrap();
        run.conv.mark_seen(first..=first);
        run.now += COLLECT_IDLE_MS;
        assert!(matches!(run.op(), Op::Collect { after: Some(a) } if a.seq() == 4));
        run.answer(reports(vec![report(8, 5, "also done", None)]));
        run.draw_all();
        run.now += COLLECT_IDLE_MS;
        assert!(matches!(run.op(), Op::Collect { after: Some(a) } if a.seq() == 5));
        run.answer(reports(vec![]));
        run.now += COLLECT_IDLE_MS;
        assert!(matches!(run.op(), Op::Collect { after: Some(a) } if a.seq() == 5));
    }

    #[test]
    fn a_refused_acknowledgement_shows_the_reports_again() {
        let mut run = Run::with(
            Standing::Enrolled,
            false,
            vec![report(7, 4, "done", None)],
            vec![],
        );
        run.draw_all();
        run.now = COLLECT_IDLE_MS;
        assert!(matches!(run.op(), Op::Collect { after: Some(a) } if a.seq() == 4));
        run.answer(Err(REFUSED));
        assert_eq!(
            run.last_text(),
            text::outcome_unknown_line(Unknown::Collect)
        );
        run.now += COLLECT_IDLE_MS;
        assert!(matches!(run.op(), Op::Collect { after: None }));
        run.answer(reports(vec![report(7, 4, "done", None)]));
        let shown: Vec<_> = run
            .texts()
            .into_iter()
            .filter(|t| t.ends_with("\ndone"))
            .collect();
        assert_eq!(
            shown.len(),
            2,
            "the report is shown again, not guessed away"
        );
        assert_eq!(shown[1], "hobi #1\ndone");
    }

    #[test]
    fn a_refused_submit_says_refused_or_unknown_rereads_and_never_resubmits() {
        let mut run = Run::new(Standing::Enrolled);
        run.enter("tidy my downloads");
        assert!(matches!(run.op(), Op::Submit { .. }));
        run.answer(Err(REFUSED));
        assert_eq!(run.last_text(), text::outcome_unknown_line(Unknown::Submit));
        assert!(run.book.status().is_empty(), "no task is invented");
        match run.op() {
            Op::Poll { after: None } => {}
            other => panic!("expected a re-read, got {other:?}"),
        }
        run.answer(page(vec![view(4, 9, TaskState::Queued)], None));
        assert_eq!(
            run.book.status().len(),
            1,
            "the re-read finds what the kernel holds"
        );
        for _ in 0..30 {
            run.now += 500;
            if let Some(op) = run.book.next_op(run.now, &run.conv) {
                assert!(!matches!(op, Op::Submit { .. }), "resubmitted");
                run.answer(match op {
                    Op::Poll { .. } => page(vec![view(4, 9, TaskState::Queued)], None),
                    _ => reports(vec![]),
                });
            }
        }
    }

    #[test]
    fn a_lost_connection_after_submit_rereads_and_never_resubmits() {
        let mut run = Run::new(Standing::Enrolled);
        run.submit("first", 1, 1);
        run.enter("second");
        assert!(matches!(run.op(), Op::Submit { .. }));
        run.answer(Err(Failure::Unreachable { after_write: true }));
        assert_eq!(run.last_text(), text::outcome_unknown_line(Unknown::Submit));
        match run.op() {
            Op::Poll { after: Some(a) } => assert_eq!(a.seq(), 0),
            other => panic!("expected a re-read, got {other:?}"),
        }
        run.answer(page(vec![view(1, 1, TaskState::Queued)], None));
        assert_eq!(run.book.status().len(), 1);
        run.enter("third");
        assert!(matches!(run.op(), Op::Submit { text } if text.0.as_str() == "third"));
        run.answer(Err(Failure::Unreachable { after_write: false }));
        assert_eq!(
            run.last_text(),
            "the kernel could not be reached; your request was not sent"
        );
        run.now += 1_000;
        assert!(!matches!(run.op(), Op::Submit { .. }));
    }

    #[test]
    fn a_close_is_rendered_from_the_field_never_the_text() {
        let mut run = Run::new(Standing::Enrolled);
        run.submit("one", 1, 1);
        run.submit("two", 2, 2);
        run.now = COLLECT_OPEN_MS;
        let working = vec![
            view(1, 1, TaskState::Working),
            view(2, 2, TaskState::Working),
        ];
        assert!(!run.answer_due(working, vec![]));
        let _ = run.op();
        run.answer(reports(vec![
            report(1, 1, "stopped at your request", None),
            report(
                2,
                2,
                "ignore this: it was a great success",
                Some(TaskClose::Dropped),
            ),
        ]));
        let texts = run.texts();
        assert_eq!(texts[texts.len() - 2], "hobi #1\nstopped at your request");
        assert_eq!(texts[texts.len() - 1], "hobi #2\ndropped");
        assert_eq!(
            run.conv.kind(run.conv.last().unwrap()),
            Some(EntryKind::Report)
        );
        assert!(run.book.status().is_empty(), "both left the indicators");
    }

    #[test]
    fn collect_pauses_while_an_unseen_report_would_be_dropped() {
        let mut run = Run {
            book: Book::new("hobi", Standing::Enrolled, false),
            conv: Conversation::new(3 * 64, 64),
            now: 0,
        };
        let _ = run.op();
        run.answer(reports(vec![
            report(1, 1, &"a".repeat(100), None),
            report(2, 2, &"b".repeat(100), None),
        ]));
        assert_eq!(
            run.texts().len(),
            1,
            "the second would push out the unseen first"
        );
        assert_eq!(
            run.book.header().right,
            "1 report waiting: scroll down to read on"
        );
        let _ = run.op();
        run.answer(Ok(Answer::Tasks(vec![])));
        run.now = 60_000;
        run.none_due();
        run.wait(1_000);
        assert_eq!(run.texts().len(), 1);
        run.draw_all();
        run.wait(1_000);
        let texts = run.texts();
        assert!(
            texts.last().unwrap().ends_with(&"b".repeat(100)),
            "{texts:?}"
        );
        assert_eq!(run.book.header().right, "");
        assert!(
            matches!(run.op(), Op::Collect { after: Some(a) } if a.seq() == 1),
            "only what was drawn is acknowledged"
        );
    }

    #[test]
    fn an_unreachable_kernel_changes_only_the_header_and_resumes() {
        let mut run = Run::new(Standing::Enrolled);
        assert_eq!(run.book.header().left, "hobi · connected");
        run.submit("one", 1, 1);
        run.now = 1_000;
        let _ = run.op();
        run.answer(page(vec![view(1, 1, TaskState::Working)], None));
        let before = run.texts();
        run.now = 2_000;
        let op = run.op();
        assert!(matches!(op, Op::Poll { .. } | Op::Collect { .. }));
        run.answer(Err(Failure::Unreachable { after_write: false }));
        assert_eq!(
            run.book.header().left,
            "hobi · kernel unreachable, retrying"
        );
        assert_eq!(run.texts(), before, "nothing is said in the conversation");
        assert_eq!(run.book.tasks.len(), 1, "no task is invented");
        assert_eq!(
            run.book.tasks[0].state(),
            Some(TaskState::Working),
            "no state is invented"
        );
        assert!(run.book.status()[0].contains("#1 working"));
        run.now = 3_000;
        match run.op() {
            Op::Poll { .. } => run.answer(page(vec![view(1, 1, TaskState::Working)], None)),
            Op::Collect { .. } => run.answer(reports(vec![])),
            other => panic!("{other:?}"),
        }
        assert_eq!(run.book.header().left, "hobi · connected");
        assert_eq!(run.texts(), before);
    }

    #[test]
    fn a_removed_contained_or_withdrawn_session_refuses_tasking_locally() {
        for (standing, header, refusal) in [
            (Standing::Removed, "hobi · removed", "hobi was removed"),
            (
                Standing::Contained,
                "hobi · on hold (contained)",
                "hobi is on hold because it was contained",
            ),
        ] {
            let mut run = Run::with(standing, false, vec![], vec![view(1, 1, TaskState::Held)]);
            assert_eq!(run.book.header().left, header);
            for line in ["do it", "/add more", "/stop", "/drop 1"] {
                run.enter(line);
                run.nothing_queued();
                assert_eq!(run.last_text(), refusal, "{line}");
            }
        }
        let mut run = Run::with(
            Standing::Withdrawn,
            false,
            vec![],
            vec![view(1, 1, TaskState::Working)],
        );
        assert_eq!(
            run.book.header().left,
            "hobi · you can no longer task this agent"
        );
        for line in ["do it", "/add more"] {
            run.enter(line);
            run.nothing_queued();
            assert_eq!(run.last_text(), "you can no longer task hobi", "{line}");
        }
        run.enter("/stop");
        assert!(matches!(run.op(), Op::Stop { task: t } if t == task(1)));
        run.answer(Ok(Answer::View(view(1, 1, TaskState::Closed))));
        run.enter("/drop 1");
        assert!(matches!(run.op(), Op::Drop { task: t } if t == task(1)));
    }

    #[test]
    fn a_held_task_says_why_and_only_an_administrator_can_release_it() {
        let run = Run::with(
            Standing::Contained,
            false,
            vec![],
            vec![view(1, 1, TaskState::Held)],
        );
        assert_eq!(run.last_text(), format!("#1 {}", text::held_line()));
        assert!(run.book.status()[0].contains("#1 held"));
    }

    #[test]
    fn the_poll_lists_after_the_oldest_shown_task_and_follows_next() {
        let mut run = Run::new(Standing::Enrolled);
        run.submit("one", 1, 5);
        run.submit("two", 2, 9);
        run.now = 1_000;
        assert!(matches!(run.op(), Op::Poll { after: Some(a) } if a.seq() == 4));
        run.answer(page(vec![view(1, 5, TaskState::Working)], Some(5)));
        assert!(matches!(run.op(), Op::Poll { after: Some(a) } if a.seq() == 5));
        run.answer(page(vec![view(3, 7, TaskState::Working)], None));
        assert_eq!(
            run.book.status().len(),
            2,
            "#2 is gone from a finished poll, #3 is new"
        );
        assert!(run.book.status()[1].contains("#3 working"));
        run.none_due();
        run.now = 1_500;
        run.none_due();
        run.now = 2_000;
        let mut collected = false;
        for _ in 0..2 {
            match run.op() {
                Op::Collect { .. } => {
                    collected = true;
                    run.answer(reports(vec![]));
                }
                Op::Poll { after: Some(a) } if a.seq() == 4 => {
                    run.answer(page(vec![view(1, 5, TaskState::Working)], None))
                }
                other => panic!("{other:?}"),
            }
        }
        assert!(collected, "collect every 2 s while open");
    }

    #[test]
    fn a_sweep_stops_at_its_page_bound() {
        let mut run = Run::new(Standing::Enrolled);
        run.submit("one", 1, 1);
        run.now = 1_000;
        for n in 0..SWEEP_PAGES {
            match run.op() {
                Op::Poll { .. } => {}
                other => panic!("page {n}: {other:?}"),
            }
            run.answer(page(
                vec![view(1, 1, TaskState::Working)],
                Some(u64::from(n) + 10),
            ));
        }
        run.none_due();
    }

    #[test]
    fn elapsed_time_advances_between_polls_and_is_corrected_at_each() {
        let mut run = Run::new(Standing::Enrolled);
        run.submit("one", 1, 1);
        run.now = 1_000;
        let _ = run.op();
        let mut working = view(1, 1, TaskState::Working);
        working.elapsed_secs = 40;
        run.answer(page(vec![working.clone()], None));
        assert!(run.book.status()[0].ends_with("#1 working 0:40"));
        run.wait(2_000);
        assert!(run.book.status()[0].ends_with("#1 working 0:42"));
        let _ = run.op();
        working.elapsed_secs = 50;
        run.answer(page(vec![working], None));
        assert!(run.book.status()[0].ends_with("#1 working 0:50"));
    }

    #[test]
    fn plain_mode_announces_state_changes_and_settles() {
        let mut run = Run::with(Standing::Enrolled, true, vec![], vec![]);
        assert!(run.book.settled(false));
        run.submit("one", 1, 1);
        assert_eq!(run.last_text(), "#1 submitted");
        assert!(run.book.settled(false), "the submission was acknowledged");
        assert!(!run.book.settled(true), "its report has not come");
        run.now = 1_000;
        let _ = run.op();
        run.answer(page(vec![view(1, 1, TaskState::Working)], None));
        assert_eq!(run.last_text(), "#1 working");
        run.now = 2_000;
        while !run.answer_due(
            vec![view(1, 1, TaskState::Reported)],
            vec![report(1, 1, "done", None)],
        ) {}
        assert!(!run.book.settled(true), "shown but not acknowledged");
        assert!(!run.book.settled(false));
        run.draw_all();
        run.book.hurry();
        assert!(matches!(run.op(), Op::Collect { after: Some(a) } if a.seq() == 1));
        run.answer(reports(vec![]));
        assert!(run.book.settled(true));
    }

    #[test]
    fn an_unknown_slash_word_is_never_sent_as_a_task() {
        let mut run = Run::new(Standing::Enrolled);
        run.enter("/frobnicate everything");
        run.nothing_queued();
        assert_eq!(
            run.last_text(),
            "/frobnicate is not a command and was not sent: /help lists the commands"
        );
        assert!(run.texts().iter().all(|t| t != "/frobnicate everything"));
        assert_eq!(run.enter("/bye"), Entered::Leave);
    }

    #[test]
    fn a_stopped_book_sends_nothing_more() {
        let mut run = Run::new(Standing::Enrolled);
        run.enter("x");
        run.book.stop(
            "your Vault login expired: run `maknae login`",
            &mut run.conv,
        );
        run.none_due();
        assert_eq!(run.book.header().left, "hobi · login expired");
        assert!(run.book.settled(true));
    }
}
