//! The tasker verbs' decision facts, views and pages (#628).
use maknae_proto::{
    TaskCursor, TaskId, TaskRef, TaskReportPage, TaskReportView, TaskState, TaskView, Tasker, Verb,
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

/// The task a tasker verb names.
pub(crate) fn cited(verb: &Verb) -> Option<TaskId> {
    match verb {
        Verb::TaskAdd { task, .. }
        | Verb::TaskStatus { task }
        | Verb::TaskStop { task }
        | Verb::TaskDrop { task } => Some(task.to_id()),
        _ => None,
    }
}

/// The agent a list or collect names.
pub(crate) fn named_agent(verb: &Verb) -> Option<&str> {
    match verb {
        Verb::TaskList { agent, .. } | Verb::TaskCollect { agent, .. } => Some(agent),
        _ => None,
    }
}

/// The trail's object: the named task, or the agent a submission, list or collect names.
pub(crate) fn object(verb: &Verb) -> Option<String> {
    match (cited(verb), named_agent(verb), verb) {
        (Some(id), _, _) => Some(format!("task:{id}")),
        (None, Some(agent), _) => Some(format!("agent:{agent}")),
        (None, None, Verb::TaskSubmit { task }) => Some(format!("agent:{}", task.agent)),
        (None, None, _) => None,
    }
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

fn report_view(rec: &TaskRecord) -> Option<TaskReportView> {
    let (text, at) = rec.report.as_ref()?;
    Some(TaskReportView {
        task: TaskRef::from_id(&rec.signed.task.task_id),
        agent: rec.agent.as_str().to_owned(),
        close: rec.close,
        text: text.clone(),
        at_secs: *at,
        cursor: TaskCursor::from_seq(rec.rseq?),
    })
}

/// Reports in arrival order, as many as fit `budget` text bytes and the page count, and
/// always the first; `next` is the last entry's cursor when more remain.
pub(crate) fn report_page(records: &[TaskRecord], budget: usize) -> TaskReportPage {
    let mut entries = Vec::new();
    let mut used = 0usize;
    let mut more = false;
    for rec in records {
        let Some(v) = report_view(rec) else {
            continue;
        };
        let size = v.text.0.len().saturating_add(REPORT_ENTRY_OVERHEAD);
        if !entries.is_empty()
            && (entries.len() >= TASK_PAGE_MAX || used.saturating_add(size) > budget)
        {
            more = true;
            break;
        }
        used = used.saturating_add(size);
        entries.push(v);
    }
    let next = more
        .then(|| entries.last().map(|e: &TaskReportView| e.cursor.clone()))
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
            pending: false,
            seq,
            rseq,
            submitted: 100,
            claimed: None,
            follow_ups: Vec::new(),
            report: rseq.map(|_| (SecretText(Zeroizing::new(text.into())), 150)),
        }
    }

    fn blank() -> maknae_security::Request {
        crate::handler::build_kernel_request("session.task", 0)
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
            assert_eq!(cited(&verb), Some(id));
            assert_eq!(named_agent(&verb), None);
            assert_eq!(object(&verb), Some(format!("task:{id}")));
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
            assert_eq!(cited(&verb), None);
            assert_eq!(named_agent(&verb), Some("suga"));
            assert_eq!(object(&verb), Some("agent:suga".into()));
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
        assert_eq!(object(&sub), Some("agent:jin".into()));
        assert_eq!(cited(&Verb::Ping), None);
        assert_eq!(named_agent(&Verb::Ping), None);
        assert_eq!(object(&Verb::Ping), None);
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
        let p = report_page(&recs, 0);
        assert_eq!(p.entries.len(), 1);
        assert_eq!(p.entries[0].cursor, TaskCursor::from_seq(5));
        assert_eq!(p.next, Some(TaskCursor::from_seq(5)));
        let fits = 4 + 2 + 2 * REPORT_ENTRY_OVERHEAD;
        let p = report_page(&recs, fits);
        assert_eq!(p.entries.len(), 2);
        assert_eq!(p.next, None);
        assert_eq!(p.entries[1].at_secs, 150);
        let p = report_page(&recs, fits - 1);
        assert_eq!(p.entries.len(), 1);
        assert!(report_page(&[], 10).entries.is_empty());
        let many: Vec<TaskRecord> = (1..=40).map(|i| rec(i, Some(i), "")).collect();
        let p = report_page(&many, usize::MAX);
        assert_eq!(p.entries.len(), TASK_PAGE_MAX);
        assert_eq!(p.next, Some(TaskCursor::from_seq(TASK_PAGE_MAX as u64)));
    }
}
