//! #241: the loop's BRAIN driven against the REAL kernel — real `handle()`,
//! real composed PDP, real audit records — with a scripted provider. No socket,
//! no Vault, no certificates. The sequence #241's body names: prompt egress
//! (write-ahead + outcome), the read verdict, the second prompt, the write
//! intent and completion, the final answer — in order, in the trail.
//!
//! Three limits of this file, so its coverage is not read wider than it is.
//! First, the write lane driven here is the REPLACEMENT lane and only that:
//! `FixturePlane::write` sends `WriteMode::Existing`, so the kernel executes
//! through a delegated writable fd and answers `MutationComplete`. The CREATE
//! lane — `WriteMode::CreateExclusive`, a `MutationAttempt` grant,
//! `mutation::execute` — is never driven against the brain from here (#241);
//! its coverage lives where the lane lives, in `bins/maknae`'s `mutation`
//! module (`create_reports_effect_then_distinct_completion_and_preserves_bytes`)
//! and in `crates/maknae-kernel/tests/mutation_loop.rs`
//! (`namespace_grant_requires_durable_intent_and_never_creates_as_daemon`).
//! Second, the unknown-tool refusal is NOT audited and nothing here should be
//! read as proving it is: `maknae-llm`'s `to_prompt_reply` refuses a reply
//! naming an unadvertised tool inside the deputy, a process with no audit sink
//! at all. Third, the egress backend here is a scripted in-process `Egress`;
//! the full chain — brain to kernel to `maknae-egress` to a provider in one
//! process — is #242's evidence, not this file's.
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
impl Scripted {
    /// Replies the loop never asked for.
    fn remaining(&self) -> usize {
        self.replies.lock().unwrap().len()
    }
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
        // Exhaustion is a BACKEND FAILURE, never a panic: a panic here fires
        // inside the spawned kernel task, where it reaches the test only as
        // `verb`'s missing frame and names the wrong cause. As a failure it
        // travels the kernel's own egress-failure path, and each test body
        // asserts what the script had left (`remaining`) — which detects
        // UNDER-consumption. Over-consumption is pinned by `seen_roles`,
        // whose per-prompt role lists the e2e test asserts exactly.
        let Some(reply) = self.replies.lock().unwrap().pop_front() else {
            return Err(maknae_kernel::EgressFailure::Transport(
                "script exhausted".into(),
            ));
        };
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
            // The same split production's `prompt_outcome` makes (#241 CR1
            // SF2): a `BadRequest` on the prompt leg is a pre-gate shape
            // fault that never reached the provider, and the fixture must not
            // be kinder to the loop than the CLI is.
            RespResult::Err(e) if e.code == maknae_proto::ProtoErrCode::BadRequest => {
                Err(PlaneError::Malformed)
            }
            RespResult::Err(_) => Err(PlaneError::Refused),
            other => Err(PlaneError::Transport(format!("{other:?}"))),
        }
    }
    async fn read(&mut self, path: &str) -> ReadOutcome {
        // ADR-0009: the subject opens; the kernel decides on the delegated descriptor.
        let fd = std::fs::File::open(path)
            .ok()
            .map(std::os::fd::OwnedFd::from);
        // Production's `armed` flag, learned from the same trigger: `send_verb`
        // sets it false when its own `open_for_delegation` returned `Err`, or
        // when its stream could not arm a descriptor, and sent the request
        // unarmed anyway — which is this `None`. One real divergence, and it is
        // liveness rather than permission: production sets `O_NONBLOCK` and
        // this does not. A writer-less FIFO opens immediately there — armed —
        // and the daemon's `regular_file` requirement refuses the object; here
        // the same open would block the test forever. Neither open applies a
        // permission check of its own, so the `armed` derivation is faithful.
        let armed = fd.is_some();
        match self.verb(Verb::Read { path: path.into() }, fd).await.result {
            // The buffer is MOVED, never copied out of its `Zeroizing`
            // (`maknae_proto::Bytes::new`) — the same hop `read_outcome` makes.
            RespResult::Ok(Payload::ReadContent(b)) => ReadOutcome::Content(b.0),
            // Exactly as production's `read_outcome` decides it: ONLY an
            // authorization refusal of an ARMED request is `Refused`.
            // Collapsing every code into `Refused` would leave the deny test
            // green for a kernel that answered a PDP deny with `Internal` —
            // the trail records the "deny" class for `Unavailable`/`TimedOut`
            // too (`handler.rs:480-501`) — while the real CLI rendered
            // "read unavailable". And an UNARMED refusal is the subject's own
            // ENOENT/EACCES reaching the kernel's want-of-descriptor deny, not
            // a verdict on content, so it is `Unavailable` here as it is there
            // (#241).
            RespResult::Err(_) if !armed => ReadOutcome::Unavailable,
            RespResult::Err(e) if e.code == maknae_proto::ProtoErrCode::Unauthorized => {
                ReadOutcome::Refused
            }
            RespResult::Err(_) => ReadOutcome::Unavailable,
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
                    &format!(r#"{{"path":"{}","content":"new"}}"#, target.display()),
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
        // SHORTER than "old body" on purpose: an overwrite that wrote the
        // right bytes without truncating would leave "new body" and pass.
        "new",
        "exactly the model's bytes, and nothing of the old ones"
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
    // The drained count, and it detects UNDER-consumption only:
    // `Scripted::send` answers an empty queue with
    // `EgressFailure::Transport("script exhausted")` rather than panicking, so
    // a loop that asked for MORE than was scripted also leaves
    // `remaining() == 0`. Zero means "nothing went unasked", never "exactly
    // these were asked". The same holds at the other two sites in this file
    // that assert zero. Over-consumption is pinned separately by `seen_roles`,
    // whose per-prompt role lists the test below asserts exactly and whose
    // length the budget test asserts — two of this file's four tests. The
    // denied-read and denied-write tests assert neither, so there the zero is
    // the only bound and it is the weaker one.
    assert_eq!(
        egress.remaining(),
        0,
        "the loop asked for every scripted reply"
    );
}

#[tokio::test]
async fn a_denied_read_reaches_the_model_as_not_authorized_and_is_a_deny_in_the_trail() {
    // The shipped deny, written into the fixture policy: the default
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
    // The WHOLE string, literal: `starts_with` would stay green if a refusal
    // reason were appended, and a refusal carries none (ADR-0019, ADR-0023 d4).
    // Pinned as text, not via `maknae_agent::render`'s const, for the reason
    // render.rs's own literal-text test states.
    assert_eq!(
        tool_text(&transcript.turns()[2]),
        "Not authorized\n\nsteps remaining: 2"
    );
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
    assert_eq!(
        egress.remaining(),
        0,
        "the loop asked for every scripted reply"
    );
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
    // The WHOLE string, literal — same reason as the denied-read test.
    assert_eq!(
        tool_text(&transcript.turns()[2]),
        "outcome unknown — the write may have happened: do not retry it, do not assume the previous contents survived, and do not touch that file again\n\nsteps remaining: 2",
        "a refused write is unknown, never 'not authorized'"
    );
    assert_eq!(std::fs::read_to_string(&target).unwrap(), "old body");
    let w = records
        .snapshot()
        .into_iter()
        .find(|r| r.action == "fs.write")
        .expect("an fs.write record");
    assert_eq!(w.outcome.result, "deny");
    assert_eq!(
        egress.remaining(),
        0,
        "the loop asked for every scripted reply"
    );
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
    // The drained count, in the TEST body: a third reply is scripted and the
    // bound must leave it untouched. A loop that ran on would consume it and
    // fail HERE, by name, rather than as a missing frame from the panic inside
    // the kernel task that the old `expect` would have raised.
    assert_eq!(egress.remaining(), 1, "the third reply was never asked for");
    // #241: `/nonexistent` is a path the SUBJECT could not open, so the
    // request went out unarmed and the kernel refused it for want of a
    // descriptor (ADR-0009 d2) — an `Unauthorized` that is not a verdict on
    // any content. The model must be told the read was unavailable, never
    // "Not authorized": the compiled prompt forbids it to diagnose or retry a
    // refusal, and there was no decision to accept.
    let tool_turns: Vec<String> = transcript
        .turns()
        .iter()
        .filter(|t| matches!(t, Turn::Tool { .. }))
        .map(tool_text)
        .collect();
    assert_eq!(
        tool_turns,
        vec!["read unavailable — do not retry\n\nsteps remaining: 1".to_string()],
        "an unarmable read is reported as unavailable, not as a refusal"
    );
}
