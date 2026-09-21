//! #241: the loop's BRAIN driven against the REAL kernel — real `handle()`,
//! real composed PDP, real audit records — with a scripted provider. No socket,
//! no Vault, no certificates. The sequence #241's body names: prompt egress
//! (write-ahead + outcome), the read verdict, the second prompt, the write
//! intent and completion, the final answer — in order, in the trail.
mod common;
use common::{Fixture, Records};
use maknae_agent::drive::{drive, Budget, StopReason};
use maknae_agent::plane::{Plane, PlaneError, ReadOutcome, WriteOutcome};
use maknae_agent::transcript::Transcript;
use maknae_io::Zeroizing;
use maknae_proto::{
    ContentBlock, Payload, PromptReply, ProposedToolCall, RespResult, SecretText, Turn, Verb,
};
use std::collections::VecDeque;
use std::sync::{Arc, Mutex};

fn text(s: &str) -> ContentBlock {
    ContentBlock::Text {
        text: SecretText(Zeroizing::new(s.into())),
    }
}
fn call(id: &str, name: &str, args: &str) -> ProposedToolCall {
    ProposedToolCall {
        name: name.into(),
        call_id: id.into(),
        arguments: SecretText(Zeroizing::new(args.into())),
    }
}
fn tool_text(t: &Turn) -> String {
    match t {
        Turn::Tool { content, .. } => match &content[0] {
            ContentBlock::Text { text } => text.0.to_string(),
            _ => panic!(),
        },
        _ => panic!("not a tool turn: {t:?}"),
    }
}

fn role(t: &Turn) -> &'static str {
    match t {
        Turn::User { .. } => "user",
        Turn::Assistant { .. } => "assistant",
        Turn::Tool { .. } => "tool",
    }
}

#[derive(Default)]
struct Scripted {
    replies: Mutex<VecDeque<PromptReply>>,
    seen_roles: Mutex<Vec<Vec<&'static str>>>,
}
impl maknae_kernel::Egress for Scripted {
    fn ready(&self) -> Result<(), maknae_kernel::EgressFailure> {
        Ok(())
    }
    fn deadline(&self) -> std::time::Duration {
        std::time::Duration::from_secs(5)
    }
    fn send(
        &self,
        _i: &maknae_kernel::DurableEgressIntent,
        r: maknae_kernel::EgressRequest,
    ) -> Result<maknae_kernel::EgressReply, maknae_kernel::EgressFailure> {
        // Roles, not a count: a kernel that dropped the assistant turn and
        // duplicated the user turn would still yield 3.
        self.seen_roles
            .lock()
            .unwrap()
            .push(r.turns.iter().map(role).collect());
        let reply = self
            .replies
            .lock()
            .unwrap()
            .pop_front()
            .expect("script exhausted");
        Ok(maknae_kernel::EgressReply { reply })
    }
}

struct FixturePlane {
    fx: Fixture,
    records: Arc<Records>,
    egress: Arc<Scripted>,
}
impl FixturePlane {
    async fn verb(&self, verb: Verb, fd: Option<std::os::fd::OwnedFd>) -> maknae_proto::Response {
        let (client, task, body) = self.fx.start_egress(
            verb,
            fd,
            Arc::clone(&self.records),
            maknae_config::transport_from_section(None).unwrap(),
            Some("openai"),
            self.egress.clone(),
        );
        Fixture::exchange(client, task, &body)
            .await
            .expect("a frame")
    }
}
impl Plane for FixturePlane {
    async fn prompt(
        &mut self,
        conversation: &str,
        turns: &[Turn],
    ) -> Result<PromptReply, PlaneError> {
        match self
            .verb(
                Verb::SessionPrompt {
                    conversation: conversation.into(),
                    turns: turns.to_vec(),
                },
                None,
            )
            .await
            .result
        {
            RespResult::Ok(Payload::PromptReply(r)) => Ok(r),
            RespResult::Err(_) => Err(PlaneError::Refused),
            other => Err(PlaneError::Transport(format!("{other:?}"))),
        }
    }
    async fn read(&mut self, path: &str) -> ReadOutcome {
        // ADR-0009: the subject opens; the kernel decides on the delegated descriptor.
        let fd = std::fs::File::open(path)
            .ok()
            .map(std::os::fd::OwnedFd::from);
        match self.verb(Verb::Read { path: path.into() }, fd).await.result {
            // The buffer is MOVED, never copied out of its `Zeroizing` (R28,
            // `maknae_proto::Bytes::new`) — the same hop `read_outcome` makes.
            RespResult::Ok(Payload::ReadContent(b)) => ReadOutcome::Content(b.0),
            RespResult::Err(_) => ReadOutcome::Refused,
            _ => ReadOutcome::Unavailable,
        }
    }
    async fn write(&mut self, path: &str, content: &[u8]) -> WriteOutcome {
        // Replacement lane: the kernel executes through a delegated writable fd.
        let fd = std::fs::OpenOptions::new()
            .write(true)
            .open(path)
            .ok()
            .map(std::os::fd::OwnedFd::from);
        let verb = Verb::FsWrite {
            path: path.into(),
            content: maknae_proto::Bytes::new(Zeroizing::new(content.to_vec())),
            mode: maknae_proto::WriteMode::Existing,
        };
        match self.verb(verb, fd).await.result {
            RespResult::Ok(Payload::MutationComplete) => WriteOutcome::Applied,
            _ => WriteOutcome::Unknown,
        }
    }
}

// The roles: + destinations: tail that makes session.prompt decidable for the
// `user` role — identical to prompt_loop.rs:143 and subject_identity.rs:49.
const GRANTED: &str =
    "roles:\n  user:\n    allow: [\"session.prompt\"]\ndestinations:\n  user:\n    allow: [\"provider:openai\"]\n";

fn script(egress: &Scripted, replies: impl IntoIterator<Item = PromptReply>) {
    egress.replies.lock().unwrap().extend(replies);
}

#[tokio::test]
async fn read_then_write_then_answer_leaves_the_sequence_the_issue_names_in_the_trail() {
    let fx = Fixture::with_rules("agent-e2e", &["Read", "Write"], &[], GRANTED);
    let target = fx.root.join("notes.txt");
    std::fs::write(&target, "old body").unwrap();
    let egress = Arc::new(Scripted::default());
    script(
        &egress,
        [
            PromptReply {
                blocks: vec![],
                tool_calls: vec![call(
                    "c1",
                    "read_file",
                    &format!(r#"{{"path":"{}"}}"#, target.display()),
                )],
            },
            PromptReply {
                blocks: vec![],
                tool_calls: vec![call(
                    "c2",
                    "write_file",
                    &format!(r#"{{"path":"{}","content":"new body"}}"#, target.display()),
                )],
            },
            PromptReply {
                blocks: vec![text("Edited.")],
                tool_calls: vec![],
            },
        ],
    );
    let records = Records::new(0);
    let mut plane = FixturePlane {
        fx,
        records: Arc::clone(&records),
        egress: egress.clone(),
    };
    let mut transcript = Transcript::new("agent-e2e-conv", "edit notes.txt");
    let out = drive(
        &mut plane,
        &mut transcript,
        &Budget {
            max_steps: 5,
            max_tool_calls_per_step: 2,
        },
    )
    .await;

    assert_eq!(out.answer.as_deref(), Some("Edited."));
    assert_eq!(
        std::fs::read_to_string(&target).unwrap(),
        "new body",
        "exactly the model's bytes"
    );
    assert_eq!(
        egress.seen_roles.lock().unwrap().as_slice(),
        &[
            vec!["user"],
            vec!["user", "assistant", "tool"],
            vec!["user", "assistant", "tool", "assistant", "tool"],
        ],
        "the kernel passes the client's turns through unmodified"
    );

    let recs = records.snapshot();
    let actions: Vec<&str> = recs.iter().map(|r| r.action.as_str()).collect();
    assert_eq!(
        actions.iter().filter(|a| **a == "session.prompt").count(),
        6,
        "three turns × (intent + outcome); got {actions:?}"
    );
    let first_read = actions
        .iter()
        .position(|a| *a == "fs.read")
        .expect("an fs.read record");
    let first_write = actions
        .iter()
        .position(|a| *a == "fs.write")
        .expect("an fs.write record"); // handler.rs:212: a single fixed label
    assert!(
        first_read < first_write,
        "read decided before write: {actions:?}"
    );
    assert!(recs
        .iter()
        .filter(|r| r.action == "session.prompt")
        .all(|r| r.egress.as_ref().map(|e| e.conversation.as_str()) == Some("agent-e2e-conv")));
}

#[tokio::test]
async fn a_denied_read_reaches_the_model_as_not_authorized_and_is_a_deny_in_the_trail() {
    // The shipped deny, written into the fixture policy (R2): the default
    // fixture has an EMPTY deny list, so this must be explicit.
    let fx = Fixture::with_rules("agent-deny", &["Read"], &["Read(~/.ssh/**)"], GRANTED);
    let secret = fx.root.join(".ssh").join("id_rsa");
    std::fs::create_dir_all(secret.parent().unwrap()).unwrap();
    std::fs::write(&secret, "PRIVATE").unwrap();
    let egress = Arc::new(Scripted::default());
    script(
        &egress,
        [
            PromptReply {
                blocks: vec![],
                tool_calls: vec![call(
                    "c1",
                    "read_file",
                    &format!(r#"{{"path":"{}"}}"#, secret.display()),
                )],
            },
            PromptReply {
                blocks: vec![text("refused")],
                tool_calls: vec![],
            },
        ],
    );
    let records = Records::new(0);
    let mut plane = FixturePlane {
        fx,
        records: Arc::clone(&records),
        egress: egress.clone(),
    };
    let mut transcript = Transcript::new("agent-deny-conv", "read my key");
    drive(
        &mut plane,
        &mut transcript,
        &Budget {
            max_steps: 3,
            max_tool_calls_per_step: 2,
        },
    )
    .await;
    assert!(tool_text(&transcript.turns()[2]).starts_with("Not authorized"));
    assert!(
        !tool_text(&transcript.turns()[2]).contains("PRIVATE"),
        "the key bytes never reach the model"
    );
    let read = records
        .snapshot()
        .into_iter()
        .find(|r| r.action == "fs.read")
        .expect("an fs.read record");
    assert_eq!(read.outcome.result, "deny");
}

#[tokio::test]
async fn a_write_outside_the_allow_is_unknown_to_the_model_and_a_deny_in_the_trail() {
    let fx = Fixture::with_rules("agent-write-deny", &["Read"], &[], GRANTED); // no Write grant at all
    let target = fx.root.join("notes.txt");
    std::fs::write(&target, "old body").unwrap();
    let egress = Arc::new(Scripted::default());
    script(
        &egress,
        [
            PromptReply {
                blocks: vec![],
                tool_calls: vec![call(
                    "c1",
                    "write_file",
                    &format!(r#"{{"path":"{}","content":"evil"}}"#, target.display()),
                )],
            },
            PromptReply {
                blocks: vec![text("done?")],
                tool_calls: vec![],
            },
        ],
    );
    let records = Records::new(0);
    let mut plane = FixturePlane {
        fx,
        records: Arc::clone(&records),
        egress: egress.clone(),
    };
    let mut transcript = Transcript::new("agent-wd-conv", "overwrite it");
    drive(
        &mut plane,
        &mut transcript,
        &Budget {
            max_steps: 3,
            max_tool_calls_per_step: 2,
        },
    )
    .await;
    assert!(
        tool_text(&transcript.turns()[2]).starts_with("outcome unknown"),
        "a refused write is unknown, never 'not authorized'"
    );
    assert_eq!(std::fs::read_to_string(&target).unwrap(), "old body");
    let w = records
        .snapshot()
        .into_iter()
        .find(|r| r.action == "fs.write")
        .expect("an fs.write record");
    assert_eq!(w.outcome.result, "deny");
}

#[tokio::test]
async fn the_step_budget_trips_and_no_further_prompt_reaches_the_kernel() {
    let fx = Fixture::with_rules("agent-budget", &["Read"], &[], GRANTED);
    let egress = Arc::new(Scripted::default());
    let looping = PromptReply {
        blocks: vec![],
        tool_calls: vec![call("c", "read_file", r#"{"path":"/nonexistent"}"#)],
    };
    script(&egress, [looping.clone(), looping.clone(), looping]);
    let records = Records::new(0);
    let mut plane = FixturePlane {
        fx,
        records: Arc::clone(&records),
        egress: egress.clone(),
    };
    let mut transcript = Transcript::new("agent-budget-conv", "loop forever");
    let out = drive(
        &mut plane,
        &mut transcript,
        &Budget {
            max_steps: 2,
            max_tool_calls_per_step: 2,
        },
    )
    .await;
    assert!(matches!(out.stopped, Some(StopReason::StepBudget)));
    assert_eq!(
        egress.seen_roles.lock().unwrap().len(),
        2,
        "exactly two prompts reached the provider"
    );
}
