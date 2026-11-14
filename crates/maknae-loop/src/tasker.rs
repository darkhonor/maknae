//! The tasker's verbs: submit, follow up, status, list, stop, drop and collect, plus
//! the agent list, one connection each. A tasker's calls can fail with the outcome
//! unknown: the kernel's refusals to a mutating verb are one answer whatever the
//! cause, and a connection lost after the request was written may have been acted on.
use crate::outcome::SentOutcome;
use crate::plane::{Dial, Link, PlaneDial};
use maknae_config::AgentId;
use maknae_proto::{
    AgentEntry, AgentPage, Ask, BannerSpec, Labels, Payload, SecretText, TaskCursor, TaskPage,
    TaskRef, TaskReportPage, TaskSubmission, TaskView, Verb, TASK_SCHEMA, TASK_VERSION,
};
use maknae_vault::{PlaneClient, TrustBundle};
use std::sync::Arc;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum TaskerError {
    /// `outcome_unknown` is true for every verb that changes a task or reads a report:
    /// the wire does not say whether the kernel acted before it refused.
    Refused {
        outcome_unknown: bool,
    },
    /// `after_write` is true when the request had been written, so a mutating verb may have landed.
    Unreachable {
        after_write: bool,
        why: String,
    },
    Protocol(String),
}

/// Every agent the caller may task, the undecided count summed over the pages.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AgentRoster {
    pub entries: Vec<AgentEntry>,
    pub undecided: u32,
    pub banner: Option<BannerSpec>,
}

pub struct TaskerClient<D: Dial = PlaneDial> {
    link: Arc<Link<D>>,
}

impl TaskerClient<PlaneDial> {
    pub fn new(
        transport: maknae_config::TransportConfig,
        client: Arc<PlaneClient>,
        trust: Arc<TrustBundle>,
    ) -> Self {
        let socket = transport.socket_path.clone();
        Self::over(PlaneDial::new(socket, client, trust), transport)
    }
}

impl<D: Dial> TaskerClient<D> {
    pub(crate) fn over(dial: D, transport: maknae_config::TransportConfig) -> Self {
        Self {
            link: Arc::new(Link::new(dial, transport)),
        }
    }

    pub async fn agents(&self, after: Option<String>) -> Result<AgentPage, TaskerError> {
        match self.call(Verb::AgentList { after }, false).await? {
            Payload::Agents(page) => Ok(page),
            other => Err(unexpected("agent.list", &other)),
        }
    }

    pub async fn all_agents(&self) -> Result<AgentRoster, TaskerError> {
        let first = self.agents(None).await?;
        let mut next = first.next;
        let mut roster = AgentRoster {
            entries: first.entries,
            undecided: first.undecided,
            banner: first.banner,
        };
        while let Some(after) = next {
            let page = self.agents(Some(after.clone())).await?;
            if roster.banner != page.banner {
                return Err(TaskerError::Protocol(
                    "the kernel's banner changed between agent pages".into(),
                ));
            }
            if page.next.as_ref() == Some(&after) {
                return Err(TaskerError::Protocol(
                    "the kernel's agent cursor did not advance".into(),
                ));
            }
            roster.entries.extend(page.entries);
            roster.undecided = roster.undecided.saturating_add(page.undecided);
            next = page.next;
        }
        Ok(roster)
    }

    pub async fn submit(
        &self,
        agent: &AgentId,
        prompt: SecretText,
    ) -> Result<TaskView, TaskerError> {
        let task = TaskSubmission {
            schema: TASK_SCHEMA.into(),
            version: TASK_VERSION,
            agent: agent.as_str().into(),
            ask: Ask::Prompt { prompt },
            labels: Labels {},
        };
        match self.call(Verb::TaskSubmit { task }, true).await? {
            Payload::TaskAccepted(view) => Ok(view),
            other => Err(unexpected("task.submit", &other)),
        }
    }

    pub async fn add(&self, task: &TaskRef, text: SecretText) -> Result<TaskView, TaskerError> {
        let verb = Verb::TaskAdd {
            task: task.clone(),
            text,
        };
        self.acknowledged("task.add", verb).await
    }

    pub async fn status(&self, task: &TaskRef) -> Result<TaskView, TaskerError> {
        let verb = Verb::TaskStatus { task: task.clone() };
        match self.call(verb, false).await? {
            Payload::TaskState(view) => Ok(view),
            other => Err(unexpected("task.status", &other)),
        }
    }

    pub async fn list(&self, agent: &AgentId) -> Result<Vec<TaskView>, TaskerError> {
        let mut all = Vec::new();
        let mut after = None;
        loop {
            let verb = Verb::TaskList {
                agent: agent.as_str().into(),
                after: after.clone(),
            };
            let TaskPage { entries, next } = match self.call(verb, false).await? {
                Payload::TaskList(page) => page,
                other => return Err(unexpected("task.list", &other)),
            };
            all.extend(entries);
            match next {
                Some(next) if after.as_ref() == Some(&next) => {
                    return Err(TaskerError::Protocol(
                        "the kernel's task cursor did not advance".into(),
                    ))
                }
                Some(next) => after = Some(next),
                None => return Ok(all),
            }
        }
    }

    pub async fn stop(&self, task: &TaskRef) -> Result<TaskView, TaskerError> {
        self.acknowledged("task.stop", Verb::TaskStop { task: task.clone() })
            .await
    }

    pub async fn drop(&self, task: &TaskRef) -> Result<TaskView, TaskerError> {
        self.acknowledged("task.drop", Verb::TaskDrop { task: task.clone() })
            .await
    }

    pub async fn collect(
        &self,
        agent: &AgentId,
        after: Option<TaskCursor>,
    ) -> Result<TaskReportPage, TaskerError> {
        let verb = Verb::TaskCollect {
            agent: agent.as_str().into(),
            after,
        };
        match self.call(verb, true).await? {
            Payload::TaskReports(page) => Ok(page),
            other => Err(unexpected("task.collect", &other)),
        }
    }

    async fn acknowledged(&self, name: &str, verb: Verb) -> Result<TaskView, TaskerError> {
        match self.call(verb, true).await? {
            Payload::TaskAcknowledged(view) => Ok(view),
            other => Err(unexpected(name, &other)),
        }
    }

    async fn call(&self, verb: Verb, outcome_unknown: bool) -> Result<Payload, TaskerError> {
        match self.link.send_located(verb).await {
            Ok(SentOutcome::Payload(payload)) => Ok(payload),
            Ok(SentOutcome::Refused { .. }) => Err(TaskerError::Refused { outcome_unknown }),
            Ok(other) => Err(TaskerError::Protocol(format!(
                "a tasker verb answered with {other:?}"
            ))),
            Err(f) => Err(TaskerError::Unreachable {
                after_write: f.after_write,
                why: f.why,
            }),
        }
    }
}

fn unexpected(verb: &str, got: &Payload) -> TaskerError {
    TaskerError::Protocol(format!("{verb} answered with {got:?}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::plane::fake::{refused, FakeKernel};
    use maknae_proto::{RespResult, TaskId, TaskReportView, TaskState};

    fn client(
        transport: maknae_config::TransportConfig,
        answers: Vec<RespResult>,
    ) -> TaskerClient<FakeKernel> {
        TaskerClient::over(FakeKernel::answering(answers), transport)
    }

    fn text(s: &str) -> SecretText {
        SecretText(zeroize::Zeroizing::new(s.into()))
    }

    fn agent() -> AgentId {
        AgentId::parse("hobi").unwrap()
    }

    fn task_ref() -> TaskRef {
        TaskRef::from_id(&TaskId([3; 16]))
    }

    fn view(seq: u64) -> TaskView {
        TaskView {
            task: task_ref(),
            agent: "hobi".into(),
            state: TaskState::Queued,
            close: None,
            submitted_secs: 0,
            elapsed_secs: 0,
            actions: 0,
            last_action_secs: None,
            cursor: TaskCursor::from_seq(seq),
        }
    }

    struct Unreachable;
    impl Dial for Unreachable {
        type Stream = tokio::io::DuplexStream;
        async fn dial(&self) -> Result<tokio::io::DuplexStream, maknae_vault::VaultError> {
            Err(maknae_vault::VaultError::MissingKey(
                "sentinel-630-unreachable",
            ))
        }
    }

    #[tokio::test]
    async fn tasker_answers_are_read_at_the_ceiling_cap() {
        let transport = maknae_config::TransportConfig {
            prompt_max_bytes: 4096,
            ..Default::default()
        };
        let cap = maknae_proto::prompt_response_cap(maknae_config::PROMPT_MAX_CEILING);
        let body = "r".repeat(cap - 4096);
        let page = TaskReportPage {
            entries: vec![TaskReportView {
                task: task_ref(),
                agent: "hobi".into(),
                close: None,
                text: text(&body),
                at_secs: 0,
                cursor: TaskCursor::from_seq(1),
            }],
            next: None,
        };
        let c = client(transport, vec![RespResult::Ok(Payload::TaskReports(page))]);
        let got = c.collect(&agent(), None).await.unwrap();
        assert_eq!(got.entries[0].text.0.len(), body.len());
    }

    #[tokio::test]
    async fn a_refused_submit_is_outcome_unknown() {
        let c = client(Default::default(), vec![refused()]);
        assert_eq!(
            c.submit(&agent(), text("p")).await,
            Err(TaskerError::Refused {
                outcome_unknown: true
            })
        );
    }

    #[tokio::test]
    async fn a_refused_status_is_not() {
        let c = client(Default::default(), vec![refused()]);
        assert_eq!(
            c.status(&task_ref()).await,
            Err(TaskerError::Refused {
                outcome_unknown: false
            })
        );
    }

    #[tokio::test]
    async fn list_follows_every_page() {
        let c = client(
            Default::default(),
            vec![
                RespResult::Ok(Payload::TaskList(TaskPage {
                    entries: vec![view(1), view(2)],
                    next: Some(TaskCursor::from_seq(2)),
                })),
                RespResult::Ok(Payload::TaskList(TaskPage {
                    entries: vec![view(3)],
                    next: None,
                })),
            ],
        );
        let all = c.list(&agent()).await.unwrap();
        assert_eq!(all.len(), 3);
        let seen = c.link.dial_for_test().finish().await;
        let afters: Vec<_> = seen
            .requests
            .iter()
            .map(|r| match &r.verb {
                Verb::TaskList { after, .. } => after.clone(),
                other => panic!("unexpected verb {other:?}"),
            })
            .collect();
        assert_eq!(afters, [None, Some(TaskCursor::from_seq(2))]);
        assert_eq!(seen.frames_per_connection, [1, 1]);
    }

    #[tokio::test]
    async fn an_unreachable_kernel_is_unreachable_not_refused() {
        let c = TaskerClient::over(Unreachable, Default::default());
        match c.submit(&agent(), text("p")).await {
            Err(TaskerError::Unreachable { after_write, why }) => {
                assert!(!after_write);
                assert!(why.contains("sentinel-630-unreachable"), "{why}");
            }
            other => panic!("{other:?}"),
        }
    }

    #[tokio::test]
    async fn a_connection_lost_after_a_submit_is_written_is_outcome_unknown() {
        let c = client(Default::default(), vec![]);
        match c.submit(&agent(), text("p")).await {
            Err(TaskerError::Unreachable { after_write, .. }) => assert!(after_write),
            other => panic!("{other:?}"),
        }
    }

    fn agents_page(names: &[&str], next: Option<&str>, undecided: u32, banner: &str) -> RespResult {
        RespResult::Ok(Payload::Agents(AgentPage {
            entries: names
                .iter()
                .map(|n| AgentEntry {
                    agent: (*n).into(),
                    standing: maknae_proto::AgentStanding::Enrolled,
                    waiting: 0,
                })
                .collect(),
            next: next.map(Into::into),
            undecided,
            banner: Some(BannerSpec {
                text: banner.into(),
                color: None,
            }),
        }))
    }

    #[tokio::test]
    async fn all_agents_sums_undecided_and_keeps_the_first_banner() {
        let c = client(
            Default::default(),
            vec![
                agents_page(&["a"], Some("a"), 1, "B"),
                agents_page(&["b"], None, 2, "B"),
            ],
        );
        let roster = c.all_agents().await.unwrap();
        assert_eq!(roster.entries.len(), 2);
        assert_eq!(roster.undecided, 3);
        assert_eq!(roster.banner.unwrap().text, "B");
    }

    #[tokio::test]
    async fn pages_that_disagree_on_the_banner_are_a_protocol_error() {
        let c = client(
            Default::default(),
            vec![
                agents_page(&["a"], Some("a"), 0, "B"),
                agents_page(&["b"], None, 0, "other"),
            ],
        );
        assert!(matches!(
            c.all_agents().await,
            Err(TaskerError::Protocol(_))
        ));
    }

    #[tokio::test]
    async fn a_cursor_that_does_not_advance_ends_the_walk() {
        let c = client(
            Default::default(),
            vec![
                agents_page(&["a"], Some("a"), 0, "B"),
                agents_page(&["a"], Some("a"), 0, "B"),
            ],
        );
        assert!(matches!(
            c.all_agents().await,
            Err(TaskerError::Protocol(_))
        ));
        let c = client(
            Default::default(),
            vec![
                RespResult::Ok(Payload::TaskList(TaskPage {
                    entries: vec![view(1)],
                    next: Some(TaskCursor::from_seq(1)),
                })),
                RespResult::Ok(Payload::TaskList(TaskPage {
                    entries: vec![view(1)],
                    next: Some(TaskCursor::from_seq(1)),
                })),
            ],
        );
        assert!(matches!(
            c.list(&agent()).await,
            Err(TaskerError::Protocol(_))
        ));
    }

    #[tokio::test]
    async fn each_verb_is_sent_as_asked_and_a_wrong_payload_is_a_protocol_error() {
        let c = client(
            Default::default(),
            vec![
                RespResult::Ok(Payload::TaskAccepted(view(1))),
                RespResult::Ok(Payload::TaskAcknowledged(view(1))),
                RespResult::Ok(Payload::TaskAcknowledged(view(1))),
                RespResult::Ok(Payload::TaskAcknowledged(view(1))),
                RespResult::Ok(Payload::TaskState(view(1))),
                RespResult::Ok(Payload::TaskIdle),
            ],
        );
        assert!(c.submit(&agent(), text("ask")).await.is_ok());
        assert!(c.add(&task_ref(), text("more")).await.is_ok());
        assert!(c.stop(&task_ref()).await.is_ok());
        assert!(c.drop(&task_ref()).await.is_ok());
        assert!(c.status(&task_ref()).await.is_ok());
        assert!(matches!(
            c.status(&task_ref()).await,
            Err(TaskerError::Protocol(_))
        ));
        let seen = c.link.dial_for_test().finish().await;
        assert!(matches!(
            &seen.requests[0].verb,
            Verb::TaskSubmit { task } if task.agent == "hobi"
                && matches!(&task.ask, Ask::Prompt { prompt } if prompt.0.as_str() == "ask")
        ));
        assert!(matches!(&seen.requests[1].verb, Verb::TaskAdd { .. }));
        assert!(matches!(&seen.requests[2].verb, Verb::TaskStop { .. }));
        assert!(matches!(&seen.requests[3].verb, Verb::TaskDrop { .. }));
        assert!(matches!(&seen.requests[4].verb, Verb::TaskStatus { .. }));
    }
}
