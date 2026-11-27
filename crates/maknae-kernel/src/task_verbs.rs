//! The tasker verbs' decision facts, views and pages (#628).
use maknae_config::AgentId;
use maknae_proto::{
    AgentEntry, AgentPage, AgentStanding, SecretText, TaskCursor, TaskId, TaskRef, TaskReportPage,
    TaskReportView, TaskState, TaskSubmission, TaskView, Tasker, Verb, TASK_PAGE_MAX,
};
use maknae_security::{AttrValue, Request};

use maknae_authz_basic::ListedSubject;
use maknae_proto::{HeldCause, HeldView, ReleaseResult};

use crate::handler::Stamp;
use crate::task::{Contained, HeldTask, Holding, ReleaseRefusal, Released};
use crate::task_store::{Hot, TaskRecord};

/// An upper bound on one report entry's encoding beyond its text.
pub(crate) const REPORT_ENTRY_OVERHEAD: usize = 256;

pub(crate) fn state_attr(state: Option<TaskState>) -> &'static str {
    match state {
        None => "none",
        Some(TaskState::Queued) => "queued",
        Some(TaskState::Working) => "working",
        Some(TaskState::Reported) => "reported",
        Some(TaskState::Closed) => "closed",
        Some(TaskState::Held) => "held",
    }
}

/// `state` is the task's state when the caller is its tasker; `None` for any other task.
pub(crate) fn stamp_task(req: &mut Request, state: Option<TaskState>) {
    req.resource.0.insert(
        maknae_security::RESOURCE_TASK_OWNED,
        AttrValue::Bool(state.is_some()),
    );
    req.resource.0.insert(
        maknae_security::RESOURCE_TASK_STATE,
        AttrValue::Str(state_attr(state).into()),
    );
}

/// Whether the request cites the agent's own working task, which the kernel resolved.
pub(crate) fn stamp_held(req: &mut Request, stamp: &Stamp<'_>) {
    let held = match stamp {
        Stamp::Client | Stamp::Agent { task: None, .. } => false,
        Stamp::Agent { task: Some(_), .. } => true,
    };
    req.resource
        .0
        .insert(maknae_security::RESOURCE_TASK_HELD, AttrValue::Bool(held));
}

pub(crate) fn stamp_agent(req: &mut Request, agent: &str) {
    req.resource.0.insert(
        maknae_security::RESOURCE_AGENT,
        AttrValue::Str(agent.into()),
    );
}

/// The tasker the caller is, from the channel it was admitted on.
pub(crate) fn caller(stamp: &Stamp<'_>, uid: u32) -> Tasker {
    match stamp {
        Stamp::Client => Tasker::Uid(uid),
        Stamp::Agent { agent, .. } => Tasker::Agent {
            agent: agent.as_str().to_owned(),
            uid,
        },
    }
}

/// A task verb's operands, read once from the wire verb.
pub(crate) enum TaskVerb<'a> {
    Submit {
        task: &'a TaskSubmission,
        tokens: &'a maknae_proto::ForgeTokens,
    },
    Add {
        task: TaskId,
        text: &'a SecretText,
        bindings: &'a [maknae_proto::BindingRequest],
        tokens: &'a maknae_proto::ForgeTokens,
    },
    Status(TaskId),
    List {
        agent: &'a str,
        after: Option<u64>,
    },
    Stop(TaskId),
    Drop(TaskId),
    Collect {
        agent: &'a str,
        after: Option<u64>,
        task: Option<TaskId>,
    },
    Claim {
        seen: Option<u32>,
    },
    Report {
        text: &'a SecretText,
        seen: Option<u32>,
    },
    Agents {
        after: Option<&'a str>,
    },
}

pub(crate) fn task_verb(verb: &Verb) -> Option<TaskVerb<'_>> {
    match verb {
        Verb::TaskSubmit { task, forge_tokens } => Some(TaskVerb::Submit {
            task,
            tokens: forge_tokens,
        }),
        Verb::TaskAdd {
            task,
            text,
            bindings,
            forge_tokens,
        } => Some(TaskVerb::Add {
            task: task.to_id(),
            text,
            bindings,
            tokens: forge_tokens,
        }),
        Verb::TaskStatus { task } => Some(TaskVerb::Status(task.to_id())),
        Verb::TaskList { agent, after } => Some(TaskVerb::List {
            agent,
            after: after.as_ref().map(TaskCursor::seq),
        }),
        Verb::TaskStop { task } => Some(TaskVerb::Stop(task.to_id())),
        Verb::TaskDrop { task } => Some(TaskVerb::Drop(task.to_id())),
        Verb::TaskCollect { agent, after, task } => Some(TaskVerb::Collect {
            agent,
            after: after.as_ref().map(TaskCursor::seq),
            task: task.as_ref().map(TaskRef::to_id),
        }),
        Verb::TaskClaim { seen_follow_ups } => Some(TaskVerb::Claim {
            seen: *seen_follow_ups,
        }),
        Verb::TaskReport {
            text,
            seen_follow_ups,
        } => Some(TaskVerb::Report {
            text,
            seen: *seen_follow_ups,
        }),
        Verb::AgentList { after } => Some(TaskVerb::Agents {
            after: after.as_deref(),
        }),
        Verb::Ping
        | Verb::Whoami
        | Verb::ToolCatalog {}
        | Verb::BoardPost { .. }
        | Verb::BoardRead { .. }
        | Verb::BoardManage { .. }
        | Verb::BoardList { .. }
        | Verb::AdminStatus
        | Verb::AdminConfigShow
        | Verb::AdminAuditTail
        | Verb::AdminPolicyReload
        | Verb::AdminSubjectList
        | Verb::AdminBaselineShow
        | Verb::AdminBaselineAccept { .. }
        | Verb::AdminSubjectBind
        | Verb::AdminSubjectUnbind
        | Verb::AdminContain { .. }
        | Verb::AdminRelease { .. }
        | Verb::AdminHeldList { .. }
        | Verb::AdminHeldRelease { .. }
        | Verb::AdminCredentialRotate
        | Verb::AdminProviderList
        | Verb::AdminProviderSet
        | Verb::AdminProviderDisable
        | Verb::AdminSessionList
        | Verb::AdminSessionTerminate
        | Verb::SessionNew { .. }
        | Verb::SessionResume
        | Verb::SessionClose { .. }
        | Verb::SessionDelete { .. }
        | Verb::SessionList { .. }
        | Verb::SessionFork
        | Verb::SessionPrompt { .. }
        | Verb::SessionCancel
        | Verb::SessionSetconfigoption
        | Verb::SessionSetmode
        | Verb::SessionLoad
        | Verb::SessionUpdate
        | Verb::SessionRequestpermission
        | Verb::SessionElicitCreate
        | Verb::SessionElicitComplete
        | Verb::SessionCompact
        | Verb::Read { .. }
        | Verb::FsWrite { .. }
        | Verb::FsDelete { .. }
        | Verb::FsMove
        | Verb::FsList { .. }
        | Verb::FsStat { .. }
        | Verb::FsMkdir { .. }
        | Verb::FsLink
        | Verb::FsChmod
        | Verb::FsChown
        | Verb::TerminalCreate
        | Verb::TerminalOutput
        | Verb::TerminalWaitforexit
        | Verb::TerminalKill
        | Verb::TerminalRelease
        | Verb::TerminalInput
        | Verb::McpConnect
        | Verb::McpDisconnect
        | Verb::McpMessage
        | Verb::McpToolCall
        | Verb::McpResourceRead
        | Verb::McpPromptGet
        | Verb::McpSamplingCreate => None,
    }
}

impl TaskVerb<'_> {
    /// The task a tasker verb names.
    pub(crate) fn cited(&self) -> Option<TaskId> {
        match self {
            TaskVerb::Add { task, .. }
            | TaskVerb::Status(task)
            | TaskVerb::Stop(task)
            | TaskVerb::Drop(task) => Some(*task),
            TaskVerb::Submit { .. }
            | TaskVerb::List { .. }
            | TaskVerb::Collect { .. }
            | TaskVerb::Claim { .. }
            | TaskVerb::Report { .. }
            | TaskVerb::Agents { .. } => None,
        }
    }

    /// The agent a submission, list or collect names.
    pub(crate) fn named_agent(&self) -> Option<&str> {
        match self {
            TaskVerb::Submit { task, .. } => Some(&task.agent),
            TaskVerb::List { agent, .. } | TaskVerb::Collect { agent, .. } => Some(agent),
            TaskVerb::Add { .. }
            | TaskVerb::Status(_)
            | TaskVerb::Stop(_)
            | TaskVerb::Drop(_)
            | TaskVerb::Claim { .. }
            | TaskVerb::Report { .. }
            | TaskVerb::Agents { .. } => None,
        }
    }

    /// The trail's object: the named task, or the named agent.
    pub(crate) fn object(&self) -> Option<String> {
        match (self.cited(), self.named_agent()) {
            (Some(id), _) => Some(format!("task:{id}")),
            (None, Some(agent)) => Some(format!("agent:{agent}")),
            (None, None) => None,
        }
    }
}

/// `: id, id` for an audit reason, at most a page of ids, then how many more.
pub(crate) fn named(ids: &[TaskId]) -> String {
    if ids.is_empty() {
        return String::new();
    }
    let shown: Vec<String> = ids
        .iter()
        .take(TASK_PAGE_MAX)
        .map(TaskId::to_string)
        .collect();
    let more = match ids.len().saturating_sub(TASK_PAGE_MAX) {
        0 => String::new(),
        n => format!(" and {n} more"),
    };
    format!(": {}{more}", shown.join(","))
}

/// One `session.task` decision about an agent, as a submission or a collect would make it.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Authority {
    Permit,
    Refused(String),
    Undecided(String),
}

/// What an agent list does with one agent.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Listing {
    /// Not a candidate: no decision is asked.
    Skip,
    /// `None` is left out.
    Decided(Option<AgentStanding>),
    /// Listed with this standing if the caller may collect from the agent.
    Collect(AgentStanding),
}

/// An enrolled agent, from the caller's submit decision. A refused agent is listed only
/// while the caller holds tasks there and may collect from it: contained, or withdrawn
/// while anything is open or waiting.
pub(crate) fn enrolled_listing(
    submit: &Authority,
    contained: bool,
    held: Option<Holding>,
) -> Listing {
    match (submit, held) {
        (Authority::Permit, _) => Listing::Decided(Some(AgentStanding::Enrolled)),
        (Authority::Undecided(_), _) => Listing::Decided(Some(AgentStanding::Undecided)),
        (Authority::Refused(_), None) => Listing::Decided(None),
        (Authority::Refused(_), Some(_)) if contained => Listing::Collect(AgentStanding::Contained),
        (Authority::Refused(_), Some(h)) if h.waiting > 0 || h.open > 0 => {
            Listing::Collect(AgentStanding::Withdrawn)
        }
        (Authority::Refused(_), Some(_)) => Listing::Decided(None),
    }
}

/// An agent no longer enrolled is a candidate only while reports from it wait.
pub(crate) fn removed_listing(held: Option<Holding>) -> Listing {
    match held {
        Some(h) if h.waiting > 0 => Listing::Collect(AgentStanding::Removed),
        Some(_) | None => Listing::Skip,
    }
}

pub(crate) fn collected(collect: &Authority, permitted: AgentStanding) -> Option<AgentStanding> {
    match collect {
        Authority::Permit => Some(permitted),
        Authority::Undecided(_) => Some(AgentStanding::Undecided),
        Authority::Refused(_) => None,
    }
}

pub(crate) fn label(standing: Option<AgentStanding>) -> &'static str {
    match standing {
        None => "refused",
        Some(AgentStanding::Enrolled) => "enrolled",
        Some(AgentStanding::Contained) => "contained",
        Some(AgentStanding::Withdrawn) => "withdrawn",
        Some(AgentStanding::Removed) => "removed",
        Some(AgentStanding::Undecided) => "undecided",
    }
}

/// Adds the agent to `page`; an undecided agent the caller holds nothing with is only
/// counted. `board` is the agent's own switch, carried only for a standing the kernel
/// describes the agent's configuration under.
pub(crate) fn place(
    page: &mut AgentPage,
    agent: &AgentId,
    standing: Option<AgentStanding>,
    held: Option<Holding>,
    board: bool,
) {
    match (standing, held) {
        (None, _) => {}
        (Some(AgentStanding::Undecided), None) => page.undecided = page.undecided.saturating_add(1),
        (Some(standing), held) => page.entries.push(AgentEntry {
            agent: agent.as_str().to_owned(),
            standing,
            waiting: held.map_or(0, |h| h.waiting),
            board: match standing {
                AgentStanding::Enrolled | AgentStanding::Contained => board,
                AgentStanding::Withdrawn | AgentStanding::Removed | AgentStanding::Undecided => {
                    false
                }
            },
        }),
    }
}

/// How many per-agent outcomes an audit reason names before it counts the rest.
pub(crate) const DECIDED_NAMED_MAX: usize = 8;

/// `: agent:outcome, …` for an audit reason, the first [`DECIDED_NAMED_MAX`], then how
/// many more.
pub(crate) fn decided(said: &[String]) -> String {
    if said.is_empty() {
        return String::new();
    }
    let shown = said[..said.len().min(DECIDED_NAMED_MAX)].join(",");
    match said.len().saturating_sub(DECIDED_NAMED_MAX) {
        0 => format!(": {shown}"),
        n => format!(": {shown} and {n} more"),
    }
}

pub(crate) fn view(rec: &TaskRecord, hot: &Hot, now: i64) -> TaskView {
    let bound = rec.bound();
    TaskView {
        task: TaskRef::from_id(&rec.signed.task.task_id),
        agent: rec.agent.as_str().to_owned(),
        state: rec.state,
        close: rec.close,
        submitted_secs: rec.submitted,
        elapsed_secs: now.saturating_sub(rec.submitted).max(0).unsigned_abs(),
        actions: hot.actions,
        last_action_secs: hot.last_action,
        cursor: TaskCursor::from_seq(rec.tseq),
        bindings: bound.bindings.into_iter().cloned().collect(),
        reach: bound
            .reach
            .into_iter()
            .map(maknae_proto::ReachSummary::of)
            .collect(),
    }
}

/// Reports in arrival order, as many as fit `budget` text bytes and the page count, and
/// always the first; only the entries that fit are copied. `next` is the last entry's
/// cursor when more remain.
pub(crate) fn report_page<'a>(
    records: impl Iterator<Item = &'a TaskRecord>,
    budget: usize,
) -> TaskReportPage {
    let mut entries: Vec<TaskReportView> = Vec::new();
    let mut used = 0usize;
    let mut more = false;
    for rec in records {
        let (Some((text, at)), Some(rseq)) = (rec.report.as_ref(), rec.rseq) else {
            continue;
        };
        let size = text.expose().len().saturating_add(REPORT_ENTRY_OVERHEAD);
        if !entries.is_empty()
            && (entries.len() >= TASK_PAGE_MAX || used.saturating_add(size) > budget)
        {
            more = true;
            break;
        }
        used = used.saturating_add(size);
        entries.push(TaskReportView {
            task: TaskRef::from_id(&rec.signed.task.task_id),
            agent: rec.agent.as_str().to_owned(),
            close: rec.close,
            text: text.clone(),
            at_secs: *at,
            cursor: TaskCursor::from_seq(rseq),
        });
    }
    let next = more
        .then(|| entries.last().map(|e| e.cursor.clone()))
        .flatten();
    TaskReportPage { entries, next }
}

pub(crate) const HELD_TASKER_LABEL_MAX: usize = 256;

pub(crate) fn held_cause(c: Contained) -> HeldCause {
    match c {
        Contained::Tasker => HeldCause::Tasker,
        Contained::Root => HeldCause::Root,
        Contained::Agent => HeldCause::Agent,
    }
}

/// From the last applied load, never a live account lookup.
pub(crate) fn tasker_label(tasker: &Tasker, subjects: &[ListedSubject]) -> String {
    match tasker {
        Tasker::Uid(uid) => subjects
            .iter()
            .find(|s| s.uid == Some(*uid))
            .map(crate::identity_report::label)
            .filter(|l| l.len() <= HELD_TASKER_LABEL_MAX)
            .unwrap_or_else(|| format!("uid {uid}")),
        Tasker::Agent { agent, .. } => format!("agent {agent}"),
        Tasker::Remote(id) => Some(format!("remote {id}"))
            .filter(|l| l.len() <= HELD_TASKER_LABEL_MAX)
            .unwrap_or_else(|| "remote".into()),
    }
}

/// The entry's cursor is the store-wide `seq` the page is ordered by.
pub(crate) fn held_view(t: &HeldTask, subjects: &[ListedSubject]) -> HeldView {
    HeldView {
        view: TaskView {
            cursor: TaskCursor::from_seq(t.seq),
            ..t.view.clone()
        },
        tasker: tasker_label(&t.tasker, subjects),
        held_from: t.held_from,
        held_for: t.held_for.map(held_cause),
        held_secs: t.held_at,
    }
}

pub(crate) fn release_result(r: &Result<Released, ReleaseRefusal>) -> ReleaseResult {
    match r {
        Ok(_) => ReleaseResult::Released,
        Err(ReleaseRefusal::StillContained(Contained::Tasker)) => ReleaseResult::TaskerContained,
        Err(ReleaseRefusal::StillContained(Contained::Root)) => ReleaseResult::RootContained,
        Err(ReleaseRefusal::StillContained(Contained::Agent)) => ReleaseResult::AgentContained,
        Err(ReleaseRefusal::TaskerUnresolved) => ReleaseResult::TaskerUnresolved,
        Err(ReleaseRefusal::RootUnresolved) => ReleaseResult::RootUnresolved,
        Err(ReleaseRefusal::ParentHeld(_)) => ReleaseResult::ParentHeld,
        Err(ReleaseRefusal::NotHeld) => ReleaseResult::NotHeld,
        Err(ReleaseRefusal::Unknown) => ReleaseResult::Unknown,
        Err(ReleaseRefusal::NotDone(_)) => ReleaseResult::NotDone,
        Err(ReleaseRefusal::OutcomeUnknown(_)) => ReleaseResult::OutcomeUnknown,
    }
}

pub(crate) fn release_parent(r: &Result<Released, ReleaseRefusal>) -> Option<TaskRef> {
    match r {
        Err(ReleaseRefusal::ParentHeld(p)) => Some(TaskRef::from_id(p)),
        _ => None,
    }
}

pub(crate) fn release_state_after(
    r: &Result<Released, ReleaseRefusal>,
    prior: Option<TaskState>,
) -> Option<TaskState> {
    match r {
        Ok(released) => Some(released.now),
        Err(ReleaseRefusal::Unknown | ReleaseRefusal::OutcomeUnknown(_)) => None,
        Err(_) => prior,
    }
}

pub(crate) fn release_reason(r: &Result<Released, ReleaseRefusal>) -> String {
    let refused = |why: &str| format!("task release refused: {why}");
    match r {
        Ok(released) => format!(
            "task released: held from {}, now {}",
            state_attr(Some(released.from)),
            state_attr(Some(released.now))
        ),
        Err(ReleaseRefusal::StillContained(Contained::Tasker)) => refused("tasker still contained"),
        Err(ReleaseRefusal::StillContained(Contained::Root)) => refused("root still contained"),
        Err(ReleaseRefusal::StillContained(Contained::Agent)) => refused("agent still contained"),
        Err(ReleaseRefusal::TaskerUnresolved) => refused("tasker unresolved"),
        Err(ReleaseRefusal::RootUnresolved) => refused("root unresolved"),
        Err(ReleaseRefusal::ParentHeld(_)) => refused("parent held"),
        Err(ReleaseRefusal::NotHeld) => refused("not held"),
        Err(ReleaseRefusal::Unknown) => refused("no such task"),
        Err(ReleaseRefusal::NotDone(why)) => format!("task release not done: {why}"),
        Err(ReleaseRefusal::OutcomeUnknown(why)) => format!("task release outcome unknown: {why}"),
    }
}

pub(crate) fn release_record_class(
    r: &Result<Released, ReleaseRefusal>,
) -> (&'static str, &'static str) {
    match r {
        Ok(_) => ("permit", "authorized"),
        Err(ReleaseRefusal::NotDone(_) | ReleaseRefusal::OutcomeUnknown(_)) => {
            ("deny", "unavailable")
        }
        Err(
            ReleaseRefusal::StillContained(_)
            | ReleaseRefusal::TaskerUnresolved
            | ReleaseRefusal::RootUnresolved
            | ReleaseRefusal::ParentHeld(_)
            | ReleaseRefusal::NotHeld
            | ReleaseRefusal::Unknown,
        ) => ("deny", "refused"),
    }
}

pub(crate) fn release_unauthorized_reason(why: &str) -> String {
    format!("task release refused: not authorized: {why}")
}

pub(crate) fn requested_by((uid, session): (u32, u64)) -> String {
    format!("; requested by uid {uid} in session {session}")
}

pub(crate) fn release_blocked(b: crate::mutation::Blocked) -> ReleaseRefusal {
    match b {
        crate::mutation::Blocked::NotStarted => ReleaseRefusal::NotDone(crate::task::BUSY.into()),
        crate::mutation::Blocked::Unknown => {
            ReleaseRefusal::OutcomeUnknown(crate::task::LATE.into())
        }
    }
}

/// A page ends at its first failure, resuming at that task; otherwise after its last task
/// while more remain.
pub(crate) fn release_next(
    attempted: &[(u64, ReleaseResult)],
    after: Option<u64>,
    more: bool,
) -> Option<TaskCursor> {
    let resume = match attempted.split_last() {
        Some((
            (
                _,
                ReleaseResult::NotDone
                | ReleaseResult::OutcomeUnknown
                | ReleaseResult::Unauthorized,
            ),
            before,
        )) => before.last().map(|(seq, _)| *seq).or(after),
        Some(((seq, _), _)) if more => Some(*seq),
        None if more => after,
        Some(_) | None => None,
    };
    resume.map(TaskCursor::from_seq)
}

#[cfg(test)]
mod tests {
    use super::*;
    use maknae_io::Zeroizing;
    use maknae_proto::{SecretText, TaskClose};

    fn rec(seq: u64, rseq: Option<u64>, text: &str) -> TaskRecord {
        use crate::task::TaskObjectForTest;
        let mut task = maknae_proto::TaskObject::for_test("hobi", 1000);
        task.task_id = TaskId([seq as u8; 16]);
        TaskRecord {
            signed: std::sync::Arc::new(maknae_proto::SignedTask {
                task,
                signature: maknae_proto::TaskSignature {
                    alg: "t".into(),
                    leaf: maknae_proto::Bytes::new(vec![1].into()),
                    chain: Vec::new(),
                    sig: maknae_proto::Bytes::new(vec![2].into()),
                },
            }),
            agent: maknae_config::AgentId::parse("hobi").unwrap(),
            agent_uid: 2001,
            tasker: Tasker::Uid(1000),
            root: crate::task_store::RootTasker::Person { uid: 1000 },
            parent: None,
            state: TaskState::Reported,
            close: None,
            held_from: None,
            held_at: None,
            held_for: None,
            pending: false,
            removing: false,
            seq,
            tseq: seq,
            rseq,
            submitted: 100,
            claimed: None,
            follow_ups: Vec::new(),
            report: rseq.map(|_| (SecretText::from(Zeroizing::new(text.into())), 150)),
            actions: 0,
            last_action: None,
            unseen: false,
            starts: 0,
            parent_start: None,
            addendum: None,
        }
    }

    fn blank() -> maknae_security::Request {
        crate::handler::build_kernel_request("session.task", 0)
    }

    #[test]
    fn named_ids_are_listed_up_to_a_page_and_the_rest_counted() {
        assert_eq!(named(&[]), "");
        let ids: Vec<TaskId> = (0..34u8).map(|n| TaskId([n; 16])).collect();
        assert_eq!(named(&ids[..2]), format!(": {},{}", ids[0], ids[1]));
        let all = named(&ids);
        assert_eq!(all.matches(',').count(), TASK_PAGE_MAX - 1);
        assert!(all.ends_with(&format!("{} and 2 more", ids[31])), "{all}");
    }

    fn holding(open: usize, waiting: u32) -> Option<Holding> {
        Some(Holding {
            records: open + waiting as usize,
            open,
            waiting,
        })
    }

    #[test]
    fn an_enrolled_agent_is_listed_by_the_submit_decision_and_what_the_caller_holds() {
        use AgentStanding::*;
        let (permit, refused, undecided) = (
            Authority::Permit,
            Authority::Refused("no".into()),
            Authority::Undecided("late".into()),
        );
        for contained in [false, true] {
            for held in [None, holding(0, 0), holding(1, 2)] {
                assert_eq!(
                    enrolled_listing(&permit, contained, held),
                    Listing::Decided(Some(Enrolled))
                );
                assert_eq!(
                    enrolled_listing(&undecided, contained, held),
                    Listing::Decided(Some(Undecided))
                );
            }
            assert_eq!(
                enrolled_listing(&refused, contained, None),
                Listing::Decided(None),
                "nothing held: refused is left out"
            );
        }
        for held in [holding(0, 0), holding(1, 0), holding(0, 1)] {
            assert_eq!(
                enrolled_listing(&refused, true, held),
                Listing::Collect(Contained)
            );
        }
        assert_eq!(
            enrolled_listing(&refused, false, holding(0, 0)),
            Listing::Decided(None),
            "nothing open or waiting"
        );
        for held in [holding(1, 0), holding(0, 1)] {
            assert_eq!(
                enrolled_listing(&refused, false, held),
                Listing::Collect(Withdrawn)
            );
        }
    }

    #[test]
    fn an_agent_no_longer_enrolled_is_a_candidate_only_while_reports_wait() {
        assert_eq!(removed_listing(None), Listing::Skip);
        assert_eq!(removed_listing(holding(3, 0)), Listing::Skip);
        assert_eq!(
            removed_listing(holding(0, 1)),
            Listing::Collect(AgentStanding::Removed)
        );
        for permitted in [
            AgentStanding::Removed,
            AgentStanding::Withdrawn,
            AgentStanding::Contained,
        ] {
            assert_eq!(collected(&Authority::Permit, permitted), Some(permitted));
            assert_eq!(
                collected(&Authority::Undecided("x".into()), permitted),
                Some(AgentStanding::Undecided)
            );
            assert_eq!(collected(&Authority::Refused("x".into()), permitted), None);
        }
    }

    #[test]
    fn each_standing_has_its_trail_label() {
        use AgentStanding::*;
        let labels: Vec<&str> = [
            None,
            Some(Enrolled),
            Some(Contained),
            Some(Withdrawn),
            Some(Removed),
            Some(Undecided),
        ]
        .into_iter()
        .map(label)
        .collect();
        assert_eq!(
            labels,
            [
                "refused",
                "enrolled",
                "contained",
                "withdrawn",
                "removed",
                "undecided"
            ]
        );
    }

    #[test]
    fn an_undecided_agent_is_named_only_when_the_caller_holds_something_there() {
        let mut page = AgentPage {
            entries: Vec::new(),
            next: None,
            undecided: 0,
            banner: None,
        };
        let a = |s: &str| AgentId::parse(s).unwrap();
        place(
            &mut page,
            &a("jin"),
            Some(AgentStanding::Undecided),
            None,
            false,
        );
        place(&mut page, &a("suga"), None, holding(1, 1), true);
        assert!(page.entries.is_empty());
        assert_eq!(page.undecided, 1);
        place(
            &mut page,
            &a("hobi"),
            Some(AgentStanding::Undecided),
            holding(0, 0),
            true,
        );
        place(
            &mut page,
            &a("rm"),
            Some(AgentStanding::Enrolled),
            None,
            false,
        );
        place(
            &mut page,
            &a("v"),
            Some(AgentStanding::Withdrawn),
            holding(1, 3),
            true,
        );
        assert_eq!(page.undecided, 1);
        let got: Vec<(&str, AgentStanding, u32)> = page
            .entries
            .iter()
            .map(|e| (e.agent.as_str(), e.standing, e.waiting))
            .collect();
        assert_eq!(
            got,
            [
                ("hobi", AgentStanding::Undecided, 0),
                ("rm", AgentStanding::Enrolled, 0),
                ("v", AgentStanding::Withdrawn, 3)
            ]
        );
    }

    #[test]
    fn only_an_enrolled_or_contained_agent_carries_its_board_switch() {
        let mut page = AgentPage {
            entries: Vec::new(),
            next: None,
            undecided: 0,
            banner: None,
        };
        let a = |s: &str| AgentId::parse(s).unwrap();
        for (name, standing) in [
            ("a", AgentStanding::Enrolled),
            ("b", AgentStanding::Contained),
            ("c", AgentStanding::Withdrawn),
            ("d", AgentStanding::Removed),
            ("e", AgentStanding::Undecided),
        ] {
            place(&mut page, &a(name), Some(standing), holding(0, 0), true);
        }
        let got: Vec<(&str, bool)> = page
            .entries
            .iter()
            .map(|e| (e.agent.as_str(), e.board))
            .collect();
        assert_eq!(
            got,
            [
                ("a", true),
                ("b", true),
                ("c", false),
                ("d", false),
                ("e", false)
            ]
        );
    }

    #[test]
    fn per_agent_outcomes_are_named_up_to_eight_and_the_rest_counted() {
        let said: Vec<String> = (0..10).map(|n| format!("a{n}:enrolled")).collect();
        assert_eq!(decided(&[]), "");
        assert_eq!(decided(&said[..1]), ": a0:enrolled");
        assert_eq!(
            decided(&said[..DECIDED_NAMED_MAX]),
            format!(": {}", said[..8].join(","))
        );
        assert_eq!(
            decided(&said),
            format!(": {} and 2 more", said[..8].join(","))
        );
    }

    #[test]
    fn every_state_has_its_attribute_and_none_is_not_the_callers() {
        let cases = [
            (None, "none"),
            (Some(TaskState::Queued), "queued"),
            (Some(TaskState::Working), "working"),
            (Some(TaskState::Reported), "reported"),
            (Some(TaskState::Closed), "closed"),
        ];
        for (state, attr) in cases {
            assert_eq!(state_attr(state), attr);
            let mut req = blank();
            stamp_task(&mut req, state);
            assert_eq!(
                req.resource.0.get(maknae_security::RESOURCE_TASK_OWNED),
                Some(&AttrValue::Bool(state.is_some()))
            );
            assert_eq!(
                req.resource.0.str(maknae_security::RESOURCE_TASK_STATE),
                Some(attr)
            );
        }
        let mut req = blank();
        stamp_agent(&mut req, "hobi");
        assert_eq!(
            req.resource.0.str(maknae_security::RESOURCE_AGENT),
            Some("hobi")
        );
    }

    #[test]
    fn the_caller_is_the_channels_tasker() {
        let hobi = maknae_config::AgentId::parse("hobi").unwrap();
        assert_eq!(caller(&Stamp::Client, 7), Tasker::Uid(7));
        assert_eq!(
            caller(
                &Stamp::Agent {
                    agent: &hobi,
                    task: None
                },
                9
            ),
            Tasker::Agent {
                agent: "hobi".into(),
                uid: 9
            }
        );
    }

    #[test]
    fn each_verb_names_its_task_or_its_agent() {
        let id = TaskId([3; 16]);
        let r = TaskRef::from_id(&id);
        for verb in [
            Verb::TaskAdd {
                task: r.clone(),
                text: SecretText::from(Zeroizing::new("x".into())),
                bindings: vec![],
                forge_tokens: maknae_proto::ForgeTokens::default(),
            },
            Verb::TaskStatus { task: r.clone() },
            Verb::TaskStop { task: r.clone() },
            Verb::TaskDrop { task: r.clone() },
        ] {
            let tv = task_verb(&verb).unwrap();
            assert_eq!(tv.cited(), Some(id));
            assert_eq!(tv.named_agent(), None);
            assert_eq!(tv.object(), Some(format!("task:{id}")));
        }
        for verb in [
            Verb::TaskList {
                agent: "suga".into(),
                after: None,
            },
            Verb::TaskCollect {
                agent: "suga".into(),
                after: None,
                task: None,
            },
        ] {
            let tv = task_verb(&verb).unwrap();
            assert_eq!(tv.cited(), None);
            assert_eq!(tv.named_agent(), Some("suga"));
            assert_eq!(tv.object(), Some("agent:suga".into()));
        }
        let sub = Verb::TaskSubmit {
            task: maknae_proto::TaskSubmission {
                schema: maknae_proto::TASK_SCHEMA.into(),
                version: maknae_proto::TASK_VERSION,
                agent: "jin".into(),
                ask: maknae_proto::Ask::Prompt {
                    prompt: SecretText::from(Zeroizing::new("p".into())),
                },
                labels: maknae_proto::Labels {},
                bindings: vec![],
            },
            forge_tokens: maknae_proto::ForgeTokens::default(),
        };
        assert_eq!(task_verb(&sub).unwrap().object(), Some("agent:jin".into()));
        assert!(task_verb(&Verb::Ping).is_none());
        for verb in [
            Verb::TaskClaim {
                seen_follow_ups: None,
            },
            Verb::TaskReport {
                text: SecretText::from(Zeroizing::new("r".into())),
                seen_follow_ups: Some(0),
            },
        ] {
            let tv = task_verb(&verb).unwrap();
            assert!(matches!(
                tv,
                TaskVerb::Claim { .. } | TaskVerb::Report { .. }
            ));
            assert_eq!(
                (tv.cited(), tv.named_agent(), tv.object()),
                (None, None, None)
            );
        }
        let listed = Verb::TaskList {
            agent: "a".into(),
            after: Some(TaskCursor::from_seq(4)),
        };
        assert!(matches!(
            task_verb(&listed),
            Some(TaskVerb::List { after: Some(4), .. })
        ));
        let agents = Verb::AgentList {
            after: Some("hobi".into()),
        };
        let tv = task_verb(&agents).unwrap();
        assert!(matches!(
            tv,
            TaskVerb::Agents {
                after: Some("hobi")
            }
        ));
        assert_eq!(
            (tv.cited(), tv.named_agent(), tv.object()),
            (None, None, None)
        );
    }

    #[test]
    fn a_maximal_report_entry_beyond_its_text_fits_the_overhead() {
        let entry = TaskReportView {
            task: TaskRef::from_id(&TaskId([0xff; 16])),
            agent: "a".repeat(32),
            close: Some(TaskClose::AgentLost),
            text: SecretText::from(Zeroizing::new(String::new())),
            at_secs: i64::MIN,
            cursor: TaskCursor::from_seq(u64::MAX),
        };
        let page = |entries: Vec<TaskReportView>| {
            maknae_proto::encode_response(&maknae_proto::Response::new(
                maknae_proto::PROTOCOL_VERSION,
                maknae_proto::RespResult::Ok(maknae_proto::Payload::TaskReports(TaskReportPage {
                    entries,
                    next: Some(TaskCursor::from_seq(u64::MAX)),
                })),
                None,
            ))
            .unwrap()
            .len()
        };
        let one = page(vec![entry.clone()]) - page(Vec::new());
        let two = page(vec![entry.clone(), entry]) - page(Vec::new());
        assert!(one <= REPORT_ENTRY_OVERHEAD, "{one}");
        assert!(two <= 2 * REPORT_ENTRY_OVERHEAD, "{two}");
    }

    #[test]
    fn a_view_carries_elapsed_time_and_the_hot_facts() {
        let mut r = rec(1, None, "");
        r.tseq = 7;
        r.state = TaskState::Closed;
        r.close = Some(TaskClose::Stopped);
        let hot = Hot {
            actions: 4,
            last_action: Some(140),
            lease_until: 9,
            ..Hot::default()
        };
        let v = view(&r, &hot, 142);
        assert_eq!(
            v,
            TaskView {
                task: TaskRef::from_id(&r.signed.task.task_id),
                agent: "hobi".into(),
                state: TaskState::Closed,
                close: Some(TaskClose::Stopped),
                submitted_secs: 100,
                elapsed_secs: 42,
                actions: 4,
                last_action_secs: Some(140),
                cursor: TaskCursor::from_seq(7),
                bindings: vec![],
                reach: vec![],
            }
        );
        assert_eq!(view(&r, &hot, 50).elapsed_secs, 0);
    }

    #[test]
    fn a_view_shows_each_bindings_effective_reach() {
        use maknae_proto::{
            AgentReach, Binding, BindingReach, EmptyReason, ForgeOp, GitBinding, GitReach,
            SideReach, TaskerBasis,
        };
        let side = |base: &[ForgeOp]| {
            SideReach::new(base.iter().copied().collect(), Default::default()).unwrap()
        };
        let mut r = rec(1, None, "");
        let mut signed = (*r.signed).clone();
        signed.task.bindings = ["o/r", "o/s"]
            .map(|base| {
                Binding::Git(GitBinding {
                    server: "forge.example".into(),
                    base: base.into(),
                    head: None,
                    change: None,
                })
            })
            .to_vec();
        signed.task.reach = vec![
            BindingReach::Git(GitReach {
                tasker: side(&[ForgeOp::Read, ForgeOp::Merge]),
                basis: TaskerBasis::Token,
                agent: AgentReach::Observed(side(&[ForgeOp::Read, ForgeOp::Review])),
                why: None,
            }),
            BindingReach::Git(GitReach {
                tasker: side(&[ForgeOp::Read]),
                basis: TaskerBasis::Token,
                agent: AgentReach::NoForgeCredential,
                why: Some(EmptyReason::NoForgeCredential),
            }),
        ];
        r.signed = std::sync::Arc::new(signed);
        let v = view(&r, &Hot::default(), 100);
        assert_eq!(v.reach.len(), 2);
        assert_eq!(v.reach[0].base(), [ForgeOp::Read].into_iter().collect());
        assert_eq!(v.reach[0].why(), None);
        assert!(v.reach[1].base().is_empty());
        assert_eq!(v.reach[1].why(), Some(EmptyReason::NoForgeCredential));
    }

    #[test]
    fn a_report_page_always_holds_its_first_entry_and_stops_at_the_budget() {
        let recs = [
            rec(1, Some(5), "aaaa"),
            rec(2, None, ""),
            rec(3, Some(6), "bb"),
        ];
        let p = report_page(recs.iter(), 0);
        assert_eq!(p.entries.len(), 1);
        assert_eq!(p.entries[0].cursor, TaskCursor::from_seq(5));
        assert_eq!(p.next, Some(TaskCursor::from_seq(5)));
        let fits = 4 + 2 + 2 * REPORT_ENTRY_OVERHEAD;
        let p = report_page(recs.iter(), fits);
        assert_eq!(p.entries.len(), 2);
        assert_eq!(p.next, None);
        assert_eq!(p.entries[1].at_secs, 150);
        let p = report_page(recs.iter(), fits - 1);
        assert_eq!(p.entries.len(), 1);
        assert!(report_page([].iter(), 10).entries.is_empty());
        let many: Vec<TaskRecord> = (1..=40).map(|i| rec(i, Some(i), "")).collect();
        let p = report_page(many.iter(), usize::MAX);
        assert_eq!(p.entries.len(), TASK_PAGE_MAX);
        assert_eq!(p.next, Some(TaskCursor::from_seq(TASK_PAGE_MAX as u64)));
    }

    fn subject(uid: Option<u32>, names: &[&str]) -> ListedSubject {
        ListedSubject {
            uid,
            names: names.iter().map(|n| (*n).to_owned()).collect(),
            state: maknae_authz_basic::SubjectState::Bound("user"),
        }
    }

    #[test]
    fn tasker_label_comes_from_the_load_and_falls_back_to_the_uid() {
        let long = "n".repeat(HELD_TASKER_LABEL_MAX);
        let subjects = [
            subject(Some(1000), &["alex"]),
            subject(Some(1001), &[long.as_str()]),
            subject(Some(1002), &["mal\u{7}"]),
        ];
        assert_eq!(
            tasker_label(&Tasker::Uid(1000), &subjects),
            "alex (uid 1000)"
        );
        assert_eq!(tasker_label(&Tasker::Uid(1001), &subjects), "uid 1001");
        assert_eq!(
            tasker_label(&Tasker::Uid(1002), &subjects),
            "mal\\u{7} (uid 1002)"
        );
        assert_eq!(tasker_label(&Tasker::Uid(4242), &subjects), "uid 4242");
        let fits = "n".repeat(HELD_TASKER_LABEL_MAX - " (uid 1003)".len());
        let at_max = [subject(Some(1003), &[fits.as_str()])];
        assert_eq!(
            tasker_label(&Tasker::Uid(1003), &at_max).len(),
            HELD_TASKER_LABEL_MAX
        );
        assert_eq!(
            tasker_label(
                &Tasker::Agent {
                    agent: "hobi".into(),
                    uid: 1000
                },
                &subjects
            ),
            "agent hobi"
        );
        let remote_fits = "r".repeat(HELD_TASKER_LABEL_MAX - "remote ".len());
        for (id, want) in [
            ("site-b/ops", "remote site-b/ops".to_string()),
            (remote_fits.as_str(), format!("remote {remote_fits}")),
            (&format!("{remote_fits}r"), "remote".to_string()),
        ] {
            assert_eq!(tasker_label(&Tasker::Remote(id.into()), &subjects), want);
        }
        assert_eq!(
            [Contained::Tasker, Contained::Root, Contained::Agent].map(held_cause),
            [HeldCause::Tasker, HeldCause::Root, HeldCause::Agent]
        );
    }

    #[test]
    fn a_held_view_carries_the_store_sequence_and_no_text() {
        let r = rec(3, None, "SENTINEL-held-text");
        let task = HeldTask {
            seq: 77,
            view: view(&r, &Hot::default(), 50),
            tasker: Tasker::Uid(1000),
            held_from: TaskState::Working,
            held_for: Some(Contained::Root),
            held_at: Some(60),
        };
        let v = held_view(&task, &[subject(Some(1000), &["alex"])]);
        assert_eq!(v.view.cursor, TaskCursor::from_seq(77));
        assert_eq!(v.view.task, task.view.task);
        assert_eq!(
            (v.tasker.as_str(), v.held_from, v.held_for, v.held_secs),
            (
                "alex (uid 1000)",
                TaskState::Working,
                Some(HeldCause::Root),
                Some(60)
            )
        );
        assert!(!format!("{v:?}").contains("SENTINEL"));
    }

    #[test]
    fn every_release_outcome_has_its_result_state_reason_and_class() {
        let id = TaskId([9; 16]);
        let parent = TaskId([8; 16]);
        let released = Ok(Released {
            task: id,
            from: TaskState::Working,
            now: TaskState::Queued,
            rseq: None,
        });
        let reported = Ok(Released {
            task: id,
            from: TaskState::Reported,
            now: TaskState::Reported,
            rseq: Some(4),
        });
        let refused = |r: ReleaseRefusal| Err::<Released, _>(r);
        let held = Some(TaskState::Held);
        type Row<'a> = (
            Result<Released, ReleaseRefusal>,
            ReleaseResult,
            Option<TaskState>,
            &'a str,
            (&'a str, &'a str),
        );
        let rows: [Row; 12] = [
            (
                released,
                ReleaseResult::Released,
                Some(TaskState::Queued),
                "task released: held from working, now queued",
                ("permit", "authorized"),
            ),
            (
                reported,
                ReleaseResult::Released,
                Some(TaskState::Reported),
                "task released: held from reported, now reported",
                ("permit", "authorized"),
            ),
            (
                refused(ReleaseRefusal::StillContained(Contained::Tasker)),
                ReleaseResult::TaskerContained,
                held,
                "task release refused: tasker still contained",
                ("deny", "refused"),
            ),
            (
                refused(ReleaseRefusal::StillContained(Contained::Root)),
                ReleaseResult::RootContained,
                held,
                "task release refused: root still contained",
                ("deny", "refused"),
            ),
            (
                refused(ReleaseRefusal::StillContained(Contained::Agent)),
                ReleaseResult::AgentContained,
                held,
                "task release refused: agent still contained",
                ("deny", "refused"),
            ),
            (
                refused(ReleaseRefusal::TaskerUnresolved),
                ReleaseResult::TaskerUnresolved,
                held,
                "task release refused: tasker unresolved",
                ("deny", "refused"),
            ),
            (
                refused(ReleaseRefusal::RootUnresolved),
                ReleaseResult::RootUnresolved,
                held,
                "task release refused: root unresolved",
                ("deny", "refused"),
            ),
            (
                refused(ReleaseRefusal::ParentHeld(parent)),
                ReleaseResult::ParentHeld,
                held,
                "task release refused: parent held",
                ("deny", "refused"),
            ),
            (
                refused(ReleaseRefusal::NotHeld),
                ReleaseResult::NotHeld,
                held,
                "task release refused: not held",
                ("deny", "refused"),
            ),
            (
                refused(ReleaseRefusal::Unknown),
                ReleaseResult::Unknown,
                None,
                "task release refused: no such task",
                ("deny", "refused"),
            ),
            (
                refused(ReleaseRefusal::NotDone("the disk said no".into())),
                ReleaseResult::NotDone,
                held,
                "task release not done: the disk said no",
                ("deny", "unavailable"),
            ),
            (
                refused(ReleaseRefusal::OutcomeUnknown("late".into())),
                ReleaseResult::OutcomeUnknown,
                None,
                "task release outcome unknown: late",
                ("deny", "unavailable"),
            ),
        ];
        for (r, result, state, reason, class) in rows {
            assert_eq!(release_result(&r), result, "{r:?}");
            assert_eq!(release_state_after(&r, held), state, "{r:?}");
            assert_eq!(release_reason(&r), reason, "{r:?}");
            assert_eq!(release_record_class(&r), class, "{r:?}");
            assert_eq!(
                release_parent(&r),
                (result == ReleaseResult::ParentHeld).then(|| TaskRef::from_id(&parent)),
                "{r:?}"
            );
        }
        assert_eq!(
            release_unauthorized_reason("role admin: no rule for admin.release"),
            "task release refused: not authorized: role admin: no rule for admin.release"
        );
        assert_eq!(requested_by((0, 7)), "; requested by uid 0 in session 7");
    }

    #[test]
    fn a_store_step_that_never_started_is_not_done_and_one_that_never_answered_is_unknown() {
        use crate::mutation::Blocked;
        assert_eq!(
            release_blocked(Blocked::NotStarted),
            ReleaseRefusal::NotDone(crate::task::BUSY.into())
        );
        assert_eq!(
            release_blocked(Blocked::Unknown),
            ReleaseRefusal::OutcomeUnknown(crate::task::LATE.into())
        );
    }

    #[test]
    fn a_release_page_ends_at_its_first_failure() {
        use ReleaseResult as R;
        let c = |s: u64| Some(TaskCursor::from_seq(s));
        type Row<'a> = (
            &'a [(u64, ReleaseResult)],
            Option<u64>,
            bool,
            Option<TaskCursor>,
        );
        let rows: [Row; 13] = [
            (&[], None, false, None),
            (&[], Some(3), false, None),
            (&[], Some(3), true, c(3)),
            (&[(4, R::Released), (6, R::Released)], Some(3), false, None),
            (&[(4, R::Released), (6, R::Released)], Some(3), true, c(6)),
            (&[(4, R::Released), (6, R::NotHeld)], None, true, c(6)),
            (&[(4, R::ParentHeld)], None, false, None),
            (&[(4, R::NotDone)], Some(3), true, c(3)),
            (&[(4, R::NotDone)], None, true, None),
            (&[(4, R::Released), (6, R::NotDone)], Some(3), true, c(4)),
            (
                &[(4, R::Released), (6, R::OutcomeUnknown)],
                Some(3),
                false,
                c(4),
            ),
            (
                &[(4, R::TaskerContained), (6, R::Unauthorized)],
                Some(3),
                true,
                c(4),
            ),
            (&[(4, R::OutcomeUnknown)], Some(3), false, c(3)),
        ];
        for (attempted, after, more, next) in rows {
            assert_eq!(
                release_next(attempted, after, more),
                next,
                "{attempted:?} after {after:?} more {more}"
            );
        }
    }
}
