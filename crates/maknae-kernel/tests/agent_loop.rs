//! #241: the loop's BRAIN driven against the REAL kernel — real `handle()`,
//! real composed PDP, real audit records — with a scripted provider. No socket,
//! no Vault, no certificates. The sequence #241's body names: prompt egress
//! (write-ahead + outcome), the read verdict, the second prompt, the write
//! intent and completion, the final answer — in order, in the trail.
//!
//! Four limits of this file, so its coverage is not read wider than it is.
//! First, the write lane driven here is the REPLACEMENT lane and only that:
//! `FixturePlane::write` sends `WriteMode::Existing`, and replaces the file
//! itself after a `MutationAttempt` grant, and `FixturePlane::read` reads after
//! a `MutationAttempt` grant through `maknae_io::read_held_page`. The CREATE
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
//! process — is #242's evidence, not this file's. Fourth, and the widest:
//! `FixturePlane` re-implements the CLI's `prompt_outcome` mapping and the
//! post-grant half of `write_outcome` BY HAND (a refused read and a write
//! refused in place of its grant go through the real `maknae_agent::wire`
//! mappers), because the loop's client is unreachable from a kernel
//! integration test. Nothing here can go red if the hand-mapped halves
//! change; their faithfulness to this fixture is by inspection, and the
//! mappers' own discriminating tests live beside them in `maknae_agent::wire`.
mod common;
use common::{Fixture, Records};
use maknae_agent::budget::{ContextBudget, Meter, Notice};
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
        refused: None,
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
    seen_refused: Mutex<Vec<Vec<Option<maknae_proto::CallRefusal>>>>,
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
        self.seen_refused.lock().unwrap().push(
            r.turns
                .iter()
                .flat_map(|t| match t {
                    Turn::Assistant { tool_calls, .. } => tool_calls.as_slice(),
                    _ => &[],
                })
                .map(|c| c.refused)
                .collect(),
        );
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
    async fn open(
        &mut self,
        cwd: &std::path::Path,
        sensitive: &[String],
    ) -> Result<maknae_proto::ConversationId, PlaneError> {
        let fd = maknae_io::open_directory_for_delegation(cwd).ok();
        let verb = Verb::SessionNew {
            cwd: cwd.to_str().unwrap().into(),
            sensitive: sensitive.to_vec(),
        };
        match self.verb(verb, fd).await.result {
            RespResult::Ok(Payload::ConversationOpened(v)) => Ok(v.conversation),
            RespResult::Err(e) if e.code == maknae_proto::ProtoErrCode::Unauthorized => {
                Err(PlaneError::Refused)
            }
            other => Err(PlaneError::Transport(format!("{other:?}"))),
        }
    }
    async fn close(
        &mut self,
        conversation: &maknae_proto::ConversationId,
    ) -> Result<maknae_proto::ConversationView, PlaneError> {
        let verb = Verb::SessionClose {
            conversation: conversation.clone(),
        };
        match self.verb(verb, None).await.result {
            RespResult::Ok(Payload::ConversationClosed(v)) => Ok(v),
            RespResult::Err(e) if e.code == maknae_proto::ProtoErrCode::Unauthorized => {
                Err(PlaneError::Refused)
            }
            other => Err(PlaneError::Transport(format!("{other:?}"))),
        }
    }
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
                    output_tokens: None,
                    choice: Some(common::test_choice()),
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
            RespResult::Err(e) => match e.code {
                maknae_proto::ProtoErrCode::ReplyUnusable(d) => Err(PlaneError::ReplyUnusable(d)),
                maknae_proto::ProtoErrCode::EgressUnavailable => Err(PlaneError::Unavailable),
                _ => Err(PlaneError::Refused),
            },
            other => Err(PlaneError::Transport(format!("{other:?}"))),
        }
    }
    async fn read(
        &mut self,
        conversation: &str,
        path: &str,
        page: maknae_proto::PageRequest,
    ) -> ReadOutcome {
        // Mapped exactly as production's `read_outcome` maps `send_verb`'s outcome.
        let held = maknae_io::open_path_for_delegation(std::path::Path::new(path)).ok();
        let (mut client, task, body) = self.fx.start_egress(
            Verb::Read {
                path: path.into(),
                conversation: Some(conversation.into()),
                page: Some(page),
            },
            held.as_ref().map(|fd| fd.try_clone().unwrap()),
            Arc::clone(&self.records),
            maknae_config::transport_from_section(None).unwrap(),
            Some("openai"),
            self.egress.clone(),
        );
        common::write_frame(&mut client, &body).await.unwrap();
        let run = common::read_page_as_subject(
            &mut client,
            held.as_ref(),
            maknae_io::PageWindow {
                offset_line: page.offset_line,
                limit_lines: page.limit_lines,
                column: page.column,
            },
        )
        .await;
        drop(client);
        task.await.unwrap();
        let first = run
            .first
            .as_deref()
            .and_then(|b| maknae_proto::decode_response(b).ok())
            .map(|r| r.result);
        match (run.content, first, held.is_some()) {
            (Some(b), _, _) => {
                let p = run.page.expect("a released read carries its page");
                ReadOutcome::Content(maknae_agent::plane::ReadPage {
                    content: b,
                    level: run.label.expect("a grant carries its label").level,
                    lines: p.lines,
                    complete_line: p.complete_last,
                    next: p.next.map(|n| (n.line, n.column)),
                    eof: p.eof,
                    version: p.version.key(),
                    changed: false,
                })
            }
            (None, Some(RespResult::Err(e)), armed) => {
                maknae_agent::wire::read_outcome(Ok(maknae_agent::wire::WireOutcome::Refused {
                    code: e.code,
                    message: e.message,
                    armed,
                }))
            }
            _ => ReadOutcome::Unavailable,
        }
    }
    async fn write(
        &mut self,
        conversation: &str,
        path: &str,
        content: &[u8],
        _basis: maknae_agent::plane::ReadBasis,
    ) -> WriteOutcome {
        use maknae_proto::{
            EffectEntry, MutationReport, MutationScope, ReportedEffect, ReportedFinish,
        };
        use std::os::fd::AsFd;
        let target = std::path::Path::new(path);
        let (held, mode) = match maknae_io::open_path_for_delegation(target) {
            Ok(fd) => (Some(fd), maknae_proto::WriteMode::Existing),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => (
                maknae_io::open_directory_for_delegation(target.parent().unwrap()).ok(),
                maknae_proto::WriteMode::CreateExclusive,
            ),
            Err(_) => (None, maknae_proto::WriteMode::Existing),
        };
        let verb = Verb::FsWrite {
            conversation: Some(conversation.into()),
            path: path.into(),
            content_length: content.len() as u64,
            mode,
        };
        let (mut client, task, body) = self.fx.start_egress(
            verb,
            held.as_ref().map(|fd| fd.try_clone().unwrap()),
            Arc::clone(&self.records),
            maknae_config::transport_from_section(None).unwrap(),
            Some("openai"),
            self.egress.clone(),
        );
        common::write_frame(&mut client, &body).await.unwrap();
        let response = common::read_frame(&mut client, 65536)
            .await
            .ok()
            .and_then(|b| maknae_proto::decode_response(&b).ok());
        if let Some(RespResult::Err(e)) = response.as_ref().map(|r| &r.result) {
            let refused =
                maknae_agent::wire::write_outcome(Ok(maknae_agent::wire::WireOutcome::Refused {
                    code: e.code.clone(),
                    message: e.message.clone(),
                    armed: held.is_some(),
                }));
            drop(client);
            task.await.unwrap();
            return refused;
        }
        let applied = match (response.map(|r| r.result), held.as_ref()) {
            (Some(RespResult::Ok(Payload::MutationAttempt(grant))), Some(held)) => {
                match &grant.scope {
                    MutationScope::Exact {
                        path,
                        effect: ReportedEffect::ReplacedFile,
                    } => {
                        maknae_io::replace_held_file(
                            held.as_fd(),
                            std::path::Path::new(path),
                            content,
                            maknae_io::WriteBase::Any,
                        )
                        .is_ok()
                            && acked(
                                &mut client,
                                MutationReport::Batch {
                                    id: grant.id,
                                    first_index: 0,
                                    effects: vec![EffectEntry {
                                        path: path.clone(),
                                        effect: ReportedEffect::ReplacedFile,
                                        length: None,
                                        range: None,
                                        lines: None,
                                    }],
                                },
                                1,
                            )
                            .await
                            && acked(
                                &mut client,
                                MutationReport::Finished {
                                    id: grant.id,
                                    next_index: 1,
                                    outcome: ReportedFinish::Success,
                                    stopped_at: None,
                                },
                                1,
                            )
                            .await
                    }
                    _ => false,
                }
            }
            _ => false,
        };
        drop(client);
        task.await.unwrap();
        if applied {
            WriteOutcome::Applied(None)
        } else {
            WriteOutcome::Unknown
        }
    }
}

async fn acked(
    client: &mut tokio::io::DuplexStream,
    report: maknae_proto::MutationReport,
    next_index: u32,
) -> bool {
    let Ok(body) = maknae_proto::encode_mutation_report(&report) else {
        return false;
    };
    if common::write_frame(client, &body).await.is_err() {
        return false;
    }
    matches!(
        common::read_frame(client, 65536).await.ok().and_then(|b| maknae_proto::decode_mutation_ack(&b).ok()),
        Some(ack) if ack.next_index == next_index
    )
}

// The roles: + destinations: tail that makes session.prompt decidable for the
// `user` role — identical to prompt_loop.rs:143 and subject_identity.rs:49.
const GRANTED: &str =
    "roles:\n  user:\n    allow: [\"session.prompt\", \"session.new\"]\ndestinations:\n  user:\n    allow: [\"provider:openai\"]\n";

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
                reasoning: None,
                blocks: vec![],
                tool_calls: vec![call(
                    "c1",
                    "read_file",
                    &format!(r#"{{"path":"{}"}}"#, target.display()),
                )],
                usage: None,
            },
            PromptReply {
                reasoning: None,
                blocks: vec![],
                tool_calls: vec![call(
                    "c2",
                    "write_file",
                    &format!(r#"{{"path":"{}","content":"new"}}"#, target.display()),
                )],
                usage: None,
            },
            PromptReply {
                reasoning: None,
                blocks: vec![text("Edited.")],
                tool_calls: vec![],
                usage: None,
            },
        ],
    );
    let records = Records::new(0);
    let mut plane = FixturePlane {
        fx,
        records: Arc::clone(&records),
        egress: egress.clone(),
    };
    let conv = plane.fx.open_conversation().await;
    let mut transcript = Transcript::new(conv.as_str(), "edit notes.txt");
    let out = drive(
        &mut plane,
        &mut transcript,
        &Budget {
            max_steps: 5,
            max_tool_calls_per_step: 2,
        },
        &mut unmetered(),
        &mut |_: &Notice| {},
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
    let reads: Vec<_> = recs.iter().filter(|r| r.action == "fs.read").collect();
    assert_eq!(reads.len(), 3, "intent + progress + completion: {reads:?}");
    assert_eq!(
        reads[1].mutation.as_ref().unwrap().effects[0].effect,
        maknae_audit_append::MutationEffectKind::ReadFile
    );
    assert_eq!(
        reads.last().unwrap().mutation.as_ref().unwrap().status,
        maknae_audit_append::MutationStatus::ReportedSuccess
    );
    assert!(reads
        .iter()
        .all(|r| r.conversation.as_deref() == Some(conv.as_str())));
    assert!(recs
        .iter()
        .filter(|r| r.action == "session.prompt")
        .all(|r| r.egress.as_ref().map(|e| e.conversation.as_str()) == Some(conv.as_str())));
    let writes: Vec<_> = recs.iter().filter(|r| r.action == "fs.write").collect();
    assert_eq!(
        writes.len(),
        3,
        "intent + progress + completion: {writes:?}"
    );
    assert_eq!(writes[0].mutation.as_ref().unwrap().content_length, Some(3));
    let last = writes.last().unwrap().mutation.as_ref().unwrap();
    assert_eq!(
        last.origin,
        maknae_audit_append::MutationOrigin::ClientReported
    );
    assert_eq!(
        last.status,
        maknae_audit_append::MutationStatus::ReportedSuccess
    );
    assert!(writes
        .iter()
        .all(|r| r.conversation.as_deref() == Some(conv.as_str())));
    // The drained count, and it detects UNDER-consumption only:
    // `Scripted::send` answers an empty queue with
    // `EgressFailure::Transport("script exhausted")` rather than panicking, so
    // a loop that asked for MORE than was scripted also leaves
    // `remaining() == 0`. Zero means "nothing went unasked", never "exactly
    // these were asked". The same holds at the other two sites in this file
    // that assert zero. Over-consumption is pinned separately by `seen_roles`,
    // whose per-prompt role lists this test asserts exactly (the assertion
    // above) and whose length the budget test asserts — two of this file's
    // four tests. The denied-read and denied-write tests assert neither, so
    // there the zero is the only bound and it is the weaker one.
    assert_eq!(
        egress.remaining(),
        0,
        "the loop asked for every scripted reply"
    );
}

#[tokio::test]
async fn a_denied_read_reaches_the_model_as_unavailable_and_is_a_deny_in_the_trail() {
    // An authz.yaml deny, written into the fixture policy: the default
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
                reasoning: None,
                blocks: vec![],
                tool_calls: vec![call(
                    "c1",
                    "read_file",
                    &format!(r#"{{"path":"{}"}}"#, secret.display()),
                )],
                usage: None,
            },
            PromptReply {
                reasoning: None,
                blocks: vec![text("refused")],
                tool_calls: vec![],
                usage: None,
            },
        ],
    );
    let records = Records::new(0);
    let mut plane = FixturePlane {
        fx,
        records: Arc::clone(&records),
        egress: egress.clone(),
    };
    let conv = plane.fx.open_conversation().await;
    let mut transcript = Transcript::new(conv.as_str(), "read my key");
    drive(
        &mut plane,
        &mut transcript,
        &Budget {
            max_steps: 3,
            max_tool_calls_per_step: 2,
        },
        &mut unmetered(),
        &mut |_: &Notice| {},
    )
    .await;
    // The WHOLE string, literal: `starts_with` would stay green if a refusal
    // reason were appended, and a refusal carries none (ADR-0019, ADR-0023 d4).
    // Pinned as text, not via `maknae_agent::render`'s const, for the reason
    // render.rs's own literal-text test states.
    assert_eq!(
        tool_text(&transcript.turns()[2]),
        "unavailable — do not retry\n\nsteps remaining: 2"
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
async fn a_protected_read_renders_the_same_bytes_whether_or_not_the_file_exists() {
    use std::os::unix::fs::PermissionsExt;
    let fx = Fixture::with_rules("agent-protected", &["Read"], &[], GRANTED);
    let here = fx.root.join("secret-here");
    let gone = fx.root.join("secret-gone");
    let locked = fx.root.join("secret-locked");
    for f in [&here, &locked] {
        std::fs::write(f, "PRIVATE-617").unwrap();
    }
    std::fs::set_permissions(&locked, std::fs::Permissions::from_mode(0o000)).unwrap();
    common::write_0640(
        &fx.paths().sensitive,
        "schema_version: 1\nsensitive:\n  - \"~/secret*\"\n",
    );
    let armed: Vec<bool> = [&here, &gone, &locked]
        .iter()
        .map(|p| maknae_io::open_path_for_delegation(p).is_ok())
        .collect();
    assert!(
        armed[0] && !armed[1],
        "premise: one armed, one unarmed: {armed:?}"
    );
    let egress = Arc::new(Scripted::default());
    let read = |id: &str, p: &std::path::Path| {
        call(id, "read_file", &format!(r#"{{"path":"{}"}}"#, p.display()))
    };
    script(
        &egress,
        [
            PromptReply {
                reasoning: None,
                blocks: vec![],
                tool_calls: vec![read("c1", &here), read("c2", &gone), read("c3", &locked)],
                usage: None,
            },
            PromptReply {
                reasoning: None,
                blocks: vec![text("done")],
                tool_calls: vec![],
                usage: None,
            },
        ],
    );
    let records = Records::new(0);
    let mut plane = FixturePlane {
        fx,
        records: Arc::clone(&records),
        egress: egress.clone(),
    };
    let conv = plane.fx.open_conversation().await;
    let mut transcript = Transcript::new(conv.as_str(), "read my secrets");
    drive(
        &mut plane,
        &mut transcript,
        &Budget {
            max_steps: 3,
            max_tool_calls_per_step: 3,
        },
        &mut unmetered(),
        &mut |_: &Notice| {},
    )
    .await;
    std::fs::set_permissions(&locked, std::fs::Permissions::from_mode(0o600)).unwrap();
    let rendered: Vec<String> = transcript.turns()[2..5].iter().map(tool_text).collect();
    assert_eq!(
        rendered,
        vec![format!("{}\n\nsteps remaining: 2", maknae_agent::render::PROTECTED); 3]
    );
    let reads: Vec<_> = records
        .snapshot()
        .into_iter()
        .filter(|r| r.action == "fs.read")
        .collect();
    assert_eq!(reads.len(), 3, "{reads:?}");
    for r in reads {
        assert_eq!(r.outcome.reason, "sensitive: host ~/secret*");
    }
}

struct Refusals {
    rendered: Vec<(&'static str, String)>,
    trail: Vec<(&'static str, Vec<(String, String)>)>,
}

/// One step of file calls, each refused for a different cause, through the real kernel.
/// The ceiling has no file of its own here: nothing stamps a marking yet (#229), and its
/// deny leaves through the same `refuse` as every PDP deny.
async fn refused_for_every_cause(tag: &str) -> Refusals {
    use std::os::unix::fs::PermissionsExt;
    if nix::unistd::geteuid().is_root() {
        panic!("{tag}: running as root, which reads a 0000 file and voids the premise; run as an unprivileged user");
    }
    let fx = Fixture::with_rules(
        tag,
        &["Read", "Write"],
        &["Read(~/denied/**)", "Write(~/write-denied/**)"],
        GRANTED,
    );
    let missing = fx.root.join("missing-617");
    let denied = fx.root.join("denied").join("file-617");
    let locked = fx.root.join("locked-617");
    let linked = fx.root.join("linked-617");
    let write_denied = fx.root.join("write-denied").join("file-617");
    for (f, body) in [
        (&denied, "SENTINEL-617-DENIED"),
        (&locked, "SENTINEL-617-LOCKED"),
        (&write_denied, "SENTINEL-617-WRITE"),
    ] {
        std::fs::create_dir_all(f.parent().unwrap()).unwrap();
        std::fs::write(f, body).unwrap();
    }
    std::fs::write(fx.root.join("original-617"), "SENTINEL-617-LINKED").unwrap();
    std::fs::hard_link(fx.root.join("original-617"), &linked).unwrap();
    std::fs::set_permissions(&locked, std::fs::Permissions::from_mode(0o000)).unwrap();
    let causes: [(&'static str, &std::path::Path, &str); 5] = [
        ("missing", &missing, "read_file"),
        ("grant-denied", &denied, "read_file"),
        ("os-refused", &locked, "read_file"),
        ("descriptor-refused", &linked, "read_file"),
        ("write-before-effect", &write_denied, "write_file"),
    ];
    let calls = causes
        .iter()
        .enumerate()
        .map(|(i, (_, p, tool))| {
            let args = match *tool {
                "write_file" => format!(r#"{{"path":"{}","content":"evil"}}"#, p.display()),
                _ => format!(r#"{{"path":"{}"}}"#, p.display()),
            };
            call(&format!("c{i}"), tool, &args)
        })
        .collect();
    let egress = Arc::new(Scripted::default());
    script(
        &egress,
        [
            PromptReply {
                reasoning: None,
                blocks: vec![],
                tool_calls: calls,
                usage: None,
            },
            PromptReply {
                reasoning: None,
                blocks: vec![text("done")],
                tool_calls: vec![],
                usage: None,
            },
        ],
    );
    let records = Records::new(0);
    let mut plane = FixturePlane {
        fx,
        records: Arc::clone(&records),
        egress: egress.clone(),
    };
    let conv = plane.fx.open_conversation().await;
    let mut transcript = Transcript::new(conv.as_str(), "try every file");
    drive(
        &mut plane,
        &mut transcript,
        &Budget {
            max_steps: 3,
            max_tool_calls_per_step: 5,
        },
        &mut unmetered(),
        &mut |_: &Notice| {},
    )
    .await;
    std::fs::set_permissions(&locked, std::fs::Permissions::from_mode(0o600)).unwrap();
    assert_eq!(
        std::fs::read_to_string(&write_denied).unwrap(),
        "SENTINEL-617-WRITE"
    );
    assert!(!missing.exists());
    let rendered = causes
        .iter()
        .zip(&transcript.turns()[2..7])
        .map(|((cause, _, _), t)| (*cause, tool_text(t)))
        .collect();
    let all = records.snapshot();
    let trail = causes
        .iter()
        .map(|(cause, p, _)| {
            let p = p.to_str().unwrap();
            let of: Vec<(String, String)> = all
                .iter()
                .filter(|r| r.action.starts_with("fs."))
                .filter(|r| {
                    r.object.as_deref() == Some(p) || r.object_requested.as_deref() == Some(p)
                })
                .map(|r| (r.outcome.result.clone(), r.outcome.reason.clone()))
                .collect();
            assert!(!of.is_empty(), "{cause}: no record");
            (*cause, of)
        })
        .collect();
    Refusals { rendered, trail }
}

#[tokio::test]
async fn every_file_refusal_renders_the_same_bytes() {
    let out = refused_for_every_cause("agent-uniform").await;
    for (cause, said) in &out.rendered {
        assert_eq!(
            said, "unavailable — do not retry\n\nsteps remaining: 2",
            "{cause}"
        );
        assert!(!said.contains("SENTINEL"), "{cause}");
    }
    assert_eq!(out.rendered.len(), 5);
}

#[tokio::test]
async fn the_trail_distinguishes_every_cause() {
    let out = refused_for_every_cause("agent-trail").await;
    let compared: Vec<_> = out
        .trail
        .iter()
        .filter(|(cause, _)| cfg!(target_os = "linux") || *cause != "os-refused")
        .collect();
    for (i, (a, ta)) in compared.iter().enumerate() {
        for (b, tb) in &compared[i + 1..] {
            assert_ne!(ta, tb, "{a} and {b} leave the same trail");
        }
    }
    assert!(compared.len() >= 4);
}

#[tokio::test]
async fn a_write_without_read_is_refused_alike_whether_or_not_the_file_exists() {
    let fx = Fixture::with_rules("agent-write-only", &["Write"], &[], GRANTED);
    let here = fx.root.join("write-only-here");
    let gone = fx.root.join("write-only-gone");
    std::fs::write(&here, "SENTINEL-617-HERE").unwrap();
    let egress = Arc::new(Scripted::default());
    let write = |id: &str, p: &std::path::Path| {
        call(
            id,
            "write_file",
            &format!(r#"{{"path":"{}","content":"new"}}"#, p.display()),
        )
    };
    script(
        &egress,
        [
            PromptReply {
                reasoning: None,
                blocks: vec![],
                tool_calls: vec![write("c1", &here), write("c2", &gone)],
                usage: None,
            },
            PromptReply {
                reasoning: None,
                blocks: vec![text("done")],
                tool_calls: vec![],
                usage: None,
            },
        ],
    );
    let records = Records::new(0);
    let mut plane = FixturePlane {
        fx,
        records: Arc::clone(&records),
        egress: egress.clone(),
    };
    let conv = plane.fx.open_conversation().await;
    let mut transcript = Transcript::new(conv.as_str(), "write both");
    drive(
        &mut plane,
        &mut transcript,
        &Budget {
            max_steps: 3,
            max_tool_calls_per_step: 2,
        },
        &mut unmetered(),
        &mut |_: &Notice| {},
    )
    .await;
    let rendered: Vec<String> = transcript.turns()[2..4].iter().map(tool_text).collect();
    assert_eq!(
        rendered,
        vec!["unavailable — do not retry\n\nsteps remaining: 2".to_string(); 2]
    );
    assert_eq!(std::fs::read_to_string(&here).unwrap(), "SENTINEL-617-HERE");
    assert!(!gone.exists(), "nothing is created");
    let writes: Vec<_> = records
        .snapshot()
        .into_iter()
        .filter(|r| r.action == "fs.write")
        .collect();
    assert_eq!(writes.len(), 2, "{writes:?}");
    for w in writes {
        assert_eq!(w.outcome.result, "deny", "{w:?}");
    }
}

#[tokio::test]
async fn an_over_bound_write_is_a_tool_error_its_sibling_read_runs_and_the_trail_names_it() {
    let fx = Fixture::with_rules("agent-426", &["Read", "Write"], &[], GRANTED);
    let target = fx.root.join("notes.txt");
    std::fs::write(&target, "SENTINEL-426-body").unwrap();
    let egress = Arc::new(Scripted::default());
    let stub = ProposedToolCall {
        name: "write_file".into(),
        call_id: "c1".into(),
        arguments: SecretText(Zeroizing::new(String::new())),
        refused: Some(maknae_proto::CallRefusal::ArgumentsOverBound { bytes: 74_112 }),
    };
    script(
        &egress,
        [
            PromptReply {
                reasoning: None,
                blocks: vec![],
                tool_calls: vec![
                    stub,
                    call(
                        "c2",
                        "read_file",
                        &format!(r#"{{"path":"{}"}}"#, target.display()),
                    ),
                ],
                usage: None,
            },
            PromptReply {
                reasoning: None,
                blocks: vec![text("done")],
                tool_calls: vec![],
                usage: None,
            },
        ],
    );
    let records = Records::new(0);
    let mut plane = FixturePlane {
        fx,
        records: Arc::clone(&records),
        egress: egress.clone(),
    };
    let conv = plane.fx.open_conversation().await;
    let mut transcript = Transcript::new(conv.as_str(), "write a big file");
    drive(
        &mut plane,
        &mut transcript,
        &Budget {
            max_steps: 3,
            max_tool_calls_per_step: 2,
        },
        &mut unmetered(),
        &mut |_: &Notice| {},
    )
    .await;

    assert!(
        tool_text(&transcript.turns()[2]).starts_with("tool error: arguments were 74112 bytes"),
        "{}",
        tool_text(&transcript.turns()[2])
    );
    assert!(tool_text(&transcript.turns()[3]).contains("SENTINEL-426-body"));

    let recs = records.snapshot();
    assert!(
        recs.iter().all(|r| r.action != "fs.write"),
        "the stub never reached the write verb"
    );
    let ops: Vec<_> = recs
        .iter()
        .filter_map(|r| r.mutation.as_ref())
        .filter_map(|m| m.operation)
        .collect();
    assert!(
        !ops.is_empty()
            && ops
                .iter()
                .all(|o| *o == maknae_audit_append::MutationOperation::Read)
    );
    assert!(recs
        .iter()
        .any(|r| r.action == "fs.read" && r.outcome.result == "permit"));
    let first_outcome = recs
        .iter()
        .filter(|r| r.action == "session.prompt")
        .filter_map(|r| r.egress.as_ref())
        .find(|e| !e.is_intent())
        .expect("a session.prompt outcome");
    assert_eq!(
        first_outcome.refused_tool_calls,
        vec![maknae_audit_append::RefusedToolCall {
            index: 0,
            name: "write_file".into(),
            arguments_bytes: 74_112,
        }]
    );
    assert_eq!(
        egress.seen_refused.lock().unwrap()[1],
        vec![
            Some(maknae_proto::CallRefusal::ArgumentsOverBound { bytes: 74_112 }),
            None
        ],
        "the next request still carries the stub"
    );
    assert_eq!(
        egress.remaining(),
        0,
        "the loop asked for every scripted reply"
    );
}

#[tokio::test]
async fn a_write_outside_the_allow_is_unavailable_to_the_model_and_a_deny_in_the_trail() {
    let fx = Fixture::with_rules("agent-write-deny", &["Read"], &[], GRANTED); // no Write grant at all
    let target = fx.root.join("notes.txt");
    std::fs::write(&target, "old body").unwrap();
    let egress = Arc::new(Scripted::default());
    script(
        &egress,
        [
            PromptReply {
                reasoning: None,
                blocks: vec![],
                tool_calls: vec![call(
                    "c1",
                    "write_file",
                    &format!(r#"{{"path":"{}","content":"evil"}}"#, target.display()),
                )],
                usage: None,
            },
            PromptReply {
                reasoning: None,
                blocks: vec![text("done?")],
                tool_calls: vec![],
                usage: None,
            },
        ],
    );
    let records = Records::new(0);
    let mut plane = FixturePlane {
        fx,
        records: Arc::clone(&records),
        egress: egress.clone(),
    };
    let conv = plane.fx.open_conversation().await;
    let mut transcript = Transcript::new(conv.as_str(), "overwrite it");
    drive(
        &mut plane,
        &mut transcript,
        &Budget {
            max_steps: 3,
            max_tool_calls_per_step: 2,
        },
        &mut unmetered(),
        &mut |_: &Notice| {},
    )
    .await;
    assert_eq!(
        tool_text(&transcript.turns()[2]),
        "unavailable — do not retry\n\nsteps remaining: 2",
        "a write refused in place of its grant had no effect"
    );
    assert_eq!(std::fs::read_to_string(&target).unwrap(), "old body");
    let w = records
        .snapshot()
        .into_iter()
        .find(|r| r.action == "fs.write")
        .expect("an fs.write record");
    assert_eq!(w.outcome.result, "deny");
    assert_eq!(w.conversation.as_deref(), Some(conv.as_str()));
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
        reasoning: None,
        blocks: vec![],
        tool_calls: vec![call("c", "read_file", r#"{"path":"/nonexistent"}"#)],
        usage: None,
    };
    script(&egress, [looping.clone(), looping.clone(), looping]);
    let records = Records::new(0);
    let mut plane = FixturePlane {
        fx,
        records: Arc::clone(&records),
        egress: egress.clone(),
    };
    let conv = plane.fx.open_conversation().await;
    let mut transcript = Transcript::new(conv.as_str(), "loop forever");
    let out = drive(
        &mut plane,
        &mut transcript,
        &Budget {
            max_steps: 2,
            max_tool_calls_per_step: 2,
        },
        &mut unmetered(),
        &mut |_: &Notice| {},
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
    let tool_turns: Vec<String> = transcript
        .turns()
        .iter()
        .filter(|t| matches!(t, Turn::Tool { .. }))
        .map(tool_text)
        .collect();
    assert_eq!(
        tool_turns,
        vec!["unavailable — do not retry\n\nsteps remaining: 1".to_string()]
    );
}

fn unmetered() -> Meter {
    Meter::new(ContextBudget::new(maknae_proto::MAX_CONTEXT_TOKENS, None).unwrap())
}

#[tokio::test]
async fn a_session_opens_converses_and_closes_one_kernel_conversation() {
    let granted = "roles:\n  user:\n    allow: [\"session.prompt\", \"session.new\", \"session.close\"]\ndestinations:\n  user:\n    allow: [\"provider:openai\"]\n";
    let fx = Fixture::with_rules("agent-open-close", &["Read"], &[], granted);
    let cwd = fx.root.join("work");
    std::fs::create_dir_all(&cwd).unwrap();
    let egress = Arc::new(Scripted::default());
    script(
        &egress,
        [PromptReply {
            reasoning: None,
            blocks: vec![text("hello")],
            tool_calls: vec![],
            usage: None,
        }],
    );
    let records = Records::new(0);
    let mut plane = FixturePlane {
        fx,
        records: Arc::clone(&records),
        egress: egress.clone(),
    };
    let mut session = maknae_agent::session::Session::open(
        &mut plane,
        &cwd,
        &[],
        "hi",
        Budget {
            max_steps: 2,
            max_tool_calls_per_step: 1,
        },
        ContextBudget::new(maknae_proto::MAX_CONTEXT_TOKENS, None).unwrap(),
        None,
    )
    .await
    .expect("the kernel opens the conversation");
    let conv = session.conversation().to_string();
    assert!(
        maknae_proto::ConversationId::parse(&conv).is_some(),
        "{conv}"
    );
    let (ended, closed) = session
        .converse(
            &mut plane,
            std::future::pending::<()>(),
            std::future::pending::<()>,
            &mut |_| {},
        )
        .await;
    match ended {
        maknae_agent::session::Ended::Ran(o) => assert_eq!(o.answer.as_deref(), Some("hello")),
        maknae_agent::session::Ended::Interrupted(()) => panic!("not interrupted"),
    }
    match closed {
        maknae_agent::session::Closed::Closed(v) => {
            assert_eq!(v.conversation.as_str(), conv);
            assert_eq!(v.turns, 1);
        }
        other => panic!("{other:?}"),
    }
    let recs = records.snapshot();
    let trail: Vec<(&str, &str)> = recs
        .iter()
        .map(|r| (r.action.as_str(), r.outcome.result.as_str()))
        .collect();
    let new = trail
        .iter()
        .position(|a| *a == ("session.new", "permit"))
        .unwrap_or_else(|| panic!("{trail:?}"));
    let prompt = trail
        .iter()
        .position(|(a, _)| *a == "session.prompt")
        .unwrap_or_else(|| panic!("{trail:?}"));
    let close = trail
        .iter()
        .position(|a| *a == ("session.close", "permit"))
        .unwrap_or_else(|| panic!("{trail:?}"));
    assert!(new < prompt && prompt < close, "{trail:?}");
    assert!(recs
        .iter()
        .filter(|r| r.action == "session.prompt")
        .all(|r| r.egress.as_ref().map(|e| e.conversation.as_str()) == Some(conv.as_str())));
}
