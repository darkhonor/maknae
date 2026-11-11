//! The tasker verbs' decision facts, views and pages (#628).
use maknae_proto::{
    SecretText, TaskCursor, TaskId, TaskRef, TaskReportPage, TaskReportView, TaskState,
    TaskSubmission, TaskView, Tasker, Verb,
};
use maknae_security::{AttrValue, Request};

use crate::handler::Stamp;
use crate::task_store::{Hot, TaskRecord};

pub(crate) const TASK_PAGE_MAX: usize = 32;

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
    Submit(&'a TaskSubmission),
    Add { task: TaskId, text: &'a SecretText },
    Status(TaskId),
    List { agent: &'a str, after: Option<u64> },
    Stop(TaskId),
    Drop(TaskId),
    Collect { agent: &'a str, after: Option<u64> },
    Claim { seen: Option<u32> },
    Report { text: &'a SecretText },
}

pub(crate) fn task_verb(verb: &Verb) -> Option<TaskVerb<'_>> {
    match verb {
        Verb::TaskSubmit { task } => Some(TaskVerb::Submit(task)),
        Verb::TaskAdd { task, text } => Some(TaskVerb::Add {
            task: task.to_id(),
            text,
        }),
        Verb::TaskStatus { task } => Some(TaskVerb::Status(task.to_id())),
        Verb::TaskList { agent, after } => Some(TaskVerb::List {
            agent,
            after: after.as_ref().map(TaskCursor::seq),
        }),
        Verb::TaskStop { task } => Some(TaskVerb::Stop(task.to_id())),
        Verb::TaskDrop { task } => Some(TaskVerb::Drop(task.to_id())),
        Verb::TaskCollect { agent, after } => Some(TaskVerb::Collect {
            agent,
            after: after.as_ref().map(TaskCursor::seq),
        }),
        Verb::TaskClaim { seen_follow_ups } => Some(TaskVerb::Claim {
            seen: *seen_follow_ups,
        }),
        Verb::TaskReport { text } => Some(TaskVerb::Report { text }),
        Verb::Ping
        | Verb::Whoami
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
            TaskVerb::Submit(_)
            | TaskVerb::List { .. }
            | TaskVerb::Collect { .. }
            | TaskVerb::Claim { .. }
            | TaskVerb::Report { .. } => None,
        }
    }

    /// The agent a submission, list or collect names.
    pub(crate) fn named_agent(&self) -> Option<&str> {
        match self {
            TaskVerb::Submit(sub) => Some(&sub.agent),
            TaskVerb::List { agent, .. } | TaskVerb::Collect { agent, .. } => Some(agent),
            TaskVerb::Add { .. }
            | TaskVerb::Status(_)
            | TaskVerb::Stop(_)
            | TaskVerb::Drop(_)
            | TaskVerb::Claim { .. }
            | TaskVerb::Report { .. } => None,
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

pub(crate) fn view(rec: &TaskRecord, hot: &Hot, now: i64) -> TaskView {
    TaskView {
        task: TaskRef::from_id(&rec.signed.task.task_id),
        agent: rec.agent.as_str().to_owned(),
        state: rec.state,
        close: rec.close,
        submitted_secs: rec.submitted,
        elapsed_secs: now.saturating_sub(rec.submitted).max(0).unsigned_abs(),
        actions: hot.actions,
        last_action_secs: hot.last_action,
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
        let size = text.0.len().saturating_add(REPORT_ENTRY_OVERHEAD);
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
            pending: false,
            removing: false,
            seq,
            tseq: seq,
            rseq,
            submitted: 100,
            claimed: None,
            follow_ups: Vec::new(),
            report: rseq.map(|_| (SecretText(Zeroizing::new(text.into())), 150)),
            actions: 0,
            last_action: None,
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
                text: SecretText(Zeroizing::new("x".into())),
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
                    prompt: SecretText(Zeroizing::new("p".into())),
                },
                labels: maknae_proto::Labels {},
            },
        };
        assert_eq!(task_verb(&sub).unwrap().object(), Some("agent:jin".into()));
        assert!(task_verb(&Verb::Ping).is_none());
        for verb in [
            Verb::TaskClaim {
                seen_follow_ups: None,
            },
            Verb::TaskReport {
                text: SecretText(Zeroizing::new("r".into())),
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
    }

    #[test]
    fn a_maximal_report_entry_beyond_its_text_fits_the_overhead() {
        let entry = TaskReportView {
            task: TaskRef::from_id(&TaskId([0xff; 16])),
            agent: "a".repeat(32),
            close: Some(TaskClose::AgentLost),
            text: SecretText(Zeroizing::new(String::new())),
            at_secs: i64::MIN,
            cursor: TaskCursor::from_seq(u64::MAX),
        };
        let page = |entries: Vec<TaskReportView>| {
            maknae_proto::encode_response(&maknae_proto::Response {
                protocol_version: maknae_proto::PROTOCOL_VERSION,
                result: maknae_proto::RespResult::Ok(maknae_proto::Payload::TaskReports(
                    TaskReportPage {
                        entries,
                        next: Some(TaskCursor::from_seq(u64::MAX)),
                    },
                )),
            })
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
            }
        );
        assert_eq!(view(&r, &hot, 50).elapsed_secs, 0);
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
}
