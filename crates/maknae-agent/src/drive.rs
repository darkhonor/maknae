//! The loop. `step` is the pure decision — answer, execute, or stop — and
//! `drive` runs it against a [`Plane`] until an answer or a bound. Bounds are
//! ADVISORY by construction (ADR-0023 d7): a well-behaved loop stops early;
//! nothing here fails closed against a hostile loop, and nothing here claims
//! to. The kernel decides every verb this asks for.
use crate::budget::{Gate, Meter, Notice};
use crate::plane::{same_content, Plane, PlaneError, ReadBasis, ReadOutcome, WriteOutcome};
use crate::render::{render, ToolOutcome};
use crate::route::{route, RouteError, ToolRequest};
use crate::transcript::Transcript;
use maknae_proto::{ContentBlock, PromptReply, ProposedToolCall};

pub struct Budget {
    pub max_steps: u32,
    pub max_tool_calls_per_step: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StopReason {
    StepBudget,
    TooManyToolCalls(usize),
    FrameBound,
    PromptRefused,
    PromptMalformed,
    Transport(String),
    ContextBudget,
}

#[derive(Debug)]
pub enum Next {
    Answer(String),
    Execute(Vec<ProposedToolCall>),
    Stop(StopReason),
}

/// The assistant's answer is copied into a PLAIN `String`, unlike the read
/// path's `Zeroizing` buffers — the one deliberate asymmetry: this text is
/// bound for the subject's own stdout, where it is printed in the clear, so a
/// zeroizing buffer would protect nothing the terminal does not already
/// disclose. What does not reach here is served content on the DIRECT path: a
/// `ReadContent` buffer stays zeroizing from [`crate::plane::ReadOutcome`]
/// through the transcript's `SecretText`, and is never copied into this
/// `String`.
///
/// *(Corrected 2026-09-22, #344: this said "Served file content never reaches
/// here". A provider ECHO can bring it: the model is shown what it read, and
/// it may quote those bytes back into the answer, which this function then
/// copies and `agent::run` prints. The asymmetry stays deliberate — the
/// destination is the subject's own terminal, which already discloses it — but
/// it is a statement about the direct path, not about every byte that can
/// arrive in this string.)*
fn text_of(blocks: &[ContentBlock]) -> String {
    let mut s = String::new();
    for b in blocks {
        if let ContentBlock::Text { text } = b {
            s.push_str(&text.0);
        }
    }
    s
}

pub fn step(reply: &PromptReply, steps_remaining: u32, budget: &Budget) -> Next {
    if reply.tool_calls.is_empty() {
        return Next::Answer(text_of(&reply.blocks));
    }
    if steps_remaining == 0 {
        return Next::Stop(StopReason::StepBudget);
    }
    // Never a subset: answering some call_ids and not others hands the model a
    // half-answered turn, and a retried write is the failure ADR-0019 forbids.
    if reply.tool_calls.len() > budget.max_tool_calls_per_step as usize {
        return Next::Stop(StopReason::TooManyToolCalls(reply.tool_calls.len()));
    }
    Next::Execute(reply.tool_calls.clone())
}

pub struct Outcome {
    pub answer: Option<String>,
    pub stopped: Option<StopReason>,
    pub steps_used: u32,
}

pub async fn drive<P: Plane>(
    plane: &mut P,
    transcript: &mut Transcript,
    budget: &Budget,
    meter: &mut Meter,
    notify: &mut impl FnMut(&Notice),
) -> Outcome {
    let mut steps_used = 0u32;
    let mut seen: std::collections::HashMap<String, [i64; 7]> = std::collections::HashMap::new();
    loop {
        if steps_used >= budget.max_steps {
            return Outcome {
                answer: None,
                stopped: Some(StopReason::StepBudget),
                steps_used,
            };
        }
        let bytes = transcript.bytes();
        match meter.gate(bytes) {
            Gate::Stop => {
                return Outcome {
                    answer: None,
                    stopped: Some(StopReason::ContextBudget),
                    steps_used,
                }
            }
            Gate::Send(Some(n)) => notify(&n),
            Gate::Send(None) => {}
        }
        let reply = match plane
            .prompt(transcript.conversation(), transcript.turns())
            .await
        {
            Ok(r) => {
                meter.record(bytes, r.usage);
                r
            }
            Err(PlaneError::FrameTooLarge) => {
                return Outcome {
                    answer: None,
                    stopped: Some(StopReason::FrameBound),
                    steps_used,
                }
            }
            Err(PlaneError::Refused) => {
                return Outcome {
                    answer: None,
                    stopped: Some(StopReason::PromptRefused),
                    steps_used,
                }
            }
            Err(PlaneError::Malformed) => {
                return Outcome {
                    answer: None,
                    stopped: Some(StopReason::PromptMalformed),
                    steps_used,
                }
            }
            Err(PlaneError::Transport(m)) => {
                return Outcome {
                    answer: None,
                    stopped: Some(StopReason::Transport(m)),
                    steps_used,
                }
            }
        };
        steps_used += 1;
        transcript.push_assistant(&reply);
        let steps_remaining = budget.max_steps - steps_used;
        match step(&reply, steps_remaining, budget) {
            Next::Answer(a) => {
                return Outcome {
                    answer: Some(a),
                    stopped: None,
                    steps_used,
                }
            }
            Next::Stop(why) => {
                return Outcome {
                    answer: None,
                    stopped: Some(why),
                    steps_used,
                }
            }
            Next::Execute(calls) => {
                for call in &calls {
                    let outcome = match route(call) {
                        Err(RouteError::UnknownTool(n)) => {
                            ToolOutcome::BadCall(format!("unknown tool {n}"))
                        }
                        Err(RouteError::BadArguments(m)) => ToolOutcome::BadCall(m),
                        Err(RouteError::EmptyPath) => ToolOutcome::BadCall("empty path".into()),
                        Err(RouteError::RelativePath) => {
                            ToolOutcome::BadCall("path must be absolute".into())
                        }
                        // Every cause, by name: the segment rules, AND the
                        // length and NUL rules the router mirrors from the
                        // kernel's write gate, which land on this same
                        // variant. Naming only the segments told a model
                        // that had sent a 5000-byte path to fix its
                        // segments (codex round 1, R44). Built at runtime
                        // so the bound IS the constant's value and cannot
                        // drift from it.
                        Err(RouteError::MalformedPath) => ToolOutcome::BadCall(format!(
                            "path must be canonical: no empty, \".\" or \"..\" segments and no trailing \"/\"; at most {} bytes and no NUL byte",
                            maknae_proto::MAX_MUTATION_PATH_BYTES
                        )),
                        Ok(ToolRequest::Read { path, page, .. }) => match plane.read(transcript.conversation(), &path, page).await {
                            ReadOutcome::Content(mut p) => {
                                p.changed = seen
                                    .insert(path.clone(), p.version)
                                    .is_some_and(|prev| !same_content(&prev, &p.version));
                                ToolOutcome::ReadContent(p)
                            }
                            ReadOutcome::Refused => ToolOutcome::ReadRefused,
                            ReadOutcome::Unavailable => ToolOutcome::ReadUnavailable,
                        },
                        Ok(ToolRequest::Write { path, content, .. }) => {
                            let basis = seen.get(&path).map_or(ReadBasis::Unread, |v| ReadBasis::Read(*v));
                            match plane.write(transcript.conversation(), &path, &content, basis).await {
                                WriteOutcome::Applied(Some(v)) => {
                                    seen.insert(path.clone(), v);
                                    ToolOutcome::WriteApplied
                                }
                                WriteOutcome::Applied(None) => {
                                    seen.remove(&path);
                                    ToolOutcome::WriteApplied
                                }
                                WriteOutcome::Stale => {
                                    seen.remove(&path);
                                    match basis {
                                        ReadBasis::Read(_) => ToolOutcome::WriteStale,
                                        ReadBasis::Unread => ToolOutcome::WriteUnread,
                                    }
                                }
                                WriteOutcome::Unknown => ToolOutcome::WriteUnknown,
                                WriteOutcome::NotSent => ToolOutcome::WriteNotSent,
                            }
                        }
                    };
                    transcript.push_tool_result(&call.call_id, &render(&outcome, steps_remaining));
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::budget::ContextBudget;
    use crate::plane::*;
    use maknae_proto::{ContentBlock, PromptReply, ProposedToolCall, SecretText, Turn};
    use std::collections::VecDeque;
    use zeroize::Zeroizing;
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
    async fn drive_unmetered<P: Plane>(p: &mut P, t: &mut Transcript, b: &Budget) -> Outcome {
        let mut m = Meter::new(ContextBudget::new(maknae_proto::MAX_CONTEXT_TOKENS, None).unwrap());
        drive(p, t, b, &mut m, &mut |_: &Notice| {}).await
    }
    fn budget() -> Budget {
        Budget {
            max_steps: 4,
            max_tool_calls_per_step: 2,
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
    fn tool_call_id(t: &Turn) -> String {
        match t {
            Turn::Tool { call_id, .. } => call_id.clone(),
            _ => panic!("not a tool turn: {t:?}"),
        }
    }

    #[test]
    fn a_text_only_reply_is_the_answer() {
        assert!(
            matches!(step(&PromptReply { blocks: vec![text("done")], tool_calls: vec![], usage: None, }, 3, &budget()), Next::Answer(s) if s == "done")
        );
    }
    #[test]
    fn tool_calls_are_executed_when_steps_remain_and_stop_when_none_do() {
        let r = PromptReply {
            blocks: vec![],
            tool_calls: vec![call("c1", "read_file", "{}")],
            usage: None,
        };
        assert!(matches!(step(&r, 1, &budget()), Next::Execute(c) if c.len() == 1));
        assert!(matches!(
            step(&r, 0, &budget()),
            Next::Stop(StopReason::StepBudget)
        ));
        // The cap ITSELF is acceptable: the predicate is `>`, not `>=`. Every
        // other row sits strictly off the boundary, so without this one the
        // `>` → `>=` mutant survives (measured: 27 mutants, 1 missed).
        let at_cap = PromptReply {
            blocks: vec![],
            tool_calls: vec![call("c1", "read_file", "{}"), call("c2", "read_file", "{}")],
            usage: None,
        };
        assert!(matches!(step(&at_cap, 3, &budget()), Next::Execute(c) if c.len() == 2));
    }
    #[test]
    fn more_calls_than_the_cap_stop_the_whole_step_never_a_subset() {
        let r = PromptReply {
            blocks: vec![],
            tool_calls: vec![
                call("1", "read_file", "{}"),
                call("2", "read_file", "{}"),
                call("3", "read_file", "{}"),
            ],
            usage: None,
        };
        assert!(matches!(
            step(&r, 3, &budget()),
            Next::Stop(StopReason::TooManyToolCalls(3))
        ));
    }

    struct Scripted {
        replies: VecDeque<Result<PromptReply, PlaneError>>,
        reads: Vec<String>,
        writes: Vec<(String, String, Vec<u8>)>,
        bases: Vec<ReadBasis>,
        prompts: usize,
        read_outcome: ReadOutcome,
        read_versions: VecDeque<[i64; 7]>,
        write_outcome: WriteOutcome,
    }
    impl Plane for Scripted {
        async fn prompt(&mut self, _c: &str, _t: &[Turn]) -> Result<PromptReply, PlaneError> {
            self.prompts += 1;
            self.replies.pop_front().expect("script exhausted")
        }
        async fn read(
            &mut self,
            _c: &str,
            p: &str,
            _page: maknae_proto::PageRequest,
        ) -> ReadOutcome {
            self.reads.push(p.into());
            match (self.read_outcome.clone(), self.read_versions.pop_front()) {
                (ReadOutcome::Content(mut page), Some(v)) => {
                    page.version = v;
                    ReadOutcome::Content(page)
                }
                (other, _) => other,
            }
        }
        async fn write(&mut self, conv: &str, p: &str, c: &[u8], basis: ReadBasis) -> WriteOutcome {
            self.writes.push((conv.into(), p.into(), c.to_vec()));
            self.bases.push(basis);
            self.write_outcome.clone()
        }
    }
    fn scripted(replies: Vec<PromptReply>) -> Scripted {
        Scripted {
            replies: replies.into_iter().map(Ok).collect(),
            reads: vec![],
            writes: vec![],
            bases: vec![],
            prompts: 0,
            read_outcome: ReadOutcome::Content(ReadPage {
                content: Zeroizing::new(b"file body".to_vec()),
                level: "UNCLASSIFIED".into(),
                lines: Some((1, 1)),
                complete_line: true,
                next: None,
                eof: true,
                version: [0; 7],
                changed: false,
            }),
            read_versions: VecDeque::new(),
            write_outcome: WriteOutcome::Applied(None),
        }
    }

    #[tokio::test]
    async fn a_page_from_a_changed_file_is_flagged_and_the_agents_own_write_refreshes_it() {
        let read = |id: &str| PromptReply {
            blocks: vec![],
            tool_calls: vec![call(id, "read_file", r#"{"path":"/w/a.txt"}"#)],
            usage: None,
        };
        let mut p = scripted(vec![
            read("c1"),
            read("c2"),
            read("c3"),
            PromptReply {
                blocks: vec![],
                tool_calls: vec![call(
                    "c4",
                    "write_file",
                    r#"{"path":"/w/a.txt","content":"new"}"#,
                )],
                usage: None,
            },
            read("c5"),
            PromptReply {
                blocks: vec![text("done")],
                tool_calls: vec![],
                usage: None,
            },
        ]);
        p.read_versions = VecDeque::from([[1; 7], [1; 7], [2; 7], [3; 7]]);
        p.write_outcome = WriteOutcome::Applied(Some([3; 7]));
        let mut t = Transcript::new("conv", "go");
        let budget = Budget {
            max_steps: 8,
            max_tool_calls_per_step: 2,
        };
        drive_unmetered(&mut p, &mut t, &budget).await;
        let changed: Vec<bool> = [2, 4, 6, 10]
            .iter()
            .map(|&i| {
                let text = tool_text(&t.turns()[i]);
                let json = text
                    .split_once("\n\nsteps remaining: ")
                    .unwrap()
                    .0
                    .to_string();
                serde_json::from_str::<serde_json::Value>(&json).unwrap()["changed"]
                    .as_bool()
                    .unwrap()
            })
            .collect();
        assert_eq!(changed, vec![false, false, true, false]);
    }

    #[tokio::test]
    async fn a_change_after_the_agents_own_write_is_flagged() {
        let mut p = scripted(vec![
            one("c1", "read_file", READ_A),
            one("c2", "write_file", WRITE_A),
            one("c3", "read_file", READ_A),
            done(),
        ]);
        p.read_versions = VecDeque::from([[1; 7], [4; 7]]);
        p.write_outcome = WriteOutcome::Applied(Some([3; 7]));
        let t = run(&mut p).await;
        assert!(changed_at(&t, 6));
    }

    fn one(id: &str, name: &str, args: &str) -> PromptReply {
        PromptReply {
            blocks: vec![],
            tool_calls: vec![call(id, name, args)],
            usage: None,
        }
    }
    fn done() -> PromptReply {
        PromptReply {
            blocks: vec![text("done")],
            tool_calls: vec![],
            usage: None,
        }
    }
    const READ_A: &str = r#"{"path":"/w/a.txt"}"#;
    const WRITE_A: &str = r#"{"path":"/w/a.txt","content":"new"}"#;
    async fn run(p: &mut Scripted) -> Transcript {
        let mut t = Transcript::new("conv", "go");
        let budget = Budget {
            max_steps: 8,
            max_tool_calls_per_step: 2,
        };
        drive_unmetered(p, &mut t, &budget).await;
        t
    }
    fn changed_at(t: &Transcript, i: usize) -> bool {
        let text = tool_text(&t.turns()[i]);
        let json = text
            .split_once("\n\nsteps remaining: ")
            .unwrap()
            .0
            .to_string();
        serde_json::from_str::<serde_json::Value>(&json).unwrap()["changed"]
            .as_bool()
            .unwrap()
    }

    #[tokio::test]
    async fn a_write_after_a_read_sends_the_read_version_and_an_unread_write_sends_unread() {
        let mut p = scripted(vec![
            one("c1", "read_file", READ_A),
            one("c2", "write_file", WRITE_A),
            one("c3", "write_file", r#"{"path":"/w/b.txt","content":"new"}"#),
            done(),
        ]);
        p.read_versions = VecDeque::from([[1; 7]]);
        p.write_outcome = WriteOutcome::Applied(None);
        run(&mut p).await;
        assert_eq!(p.bases, vec![ReadBasis::Read([1; 7]), ReadBasis::Unread]);
    }

    #[tokio::test]
    async fn a_stale_write_tells_the_model_to_read_again_and_an_unread_one_to_read_first() {
        let mut p = scripted(vec![
            one("c1", "read_file", READ_A),
            one("c2", "write_file", WRITE_A),
            one("c3", "write_file", r#"{"path":"/w/b.txt","content":"new"}"#),
            done(),
        ]);
        p.read_versions = VecDeque::from([[1; 7]]);
        p.write_outcome = WriteOutcome::Stale;
        let t = run(&mut p).await;
        assert!(
            tool_text(&t.turns()[4]).starts_with(crate::render::NOT_WRITTEN_STALE),
            "{}",
            tool_text(&t.turns()[4])
        );
        assert!(
            tool_text(&t.turns()[6]).starts_with(crate::render::NOT_WRITTEN_UNREAD),
            "{}",
            tool_text(&t.turns()[6])
        );
    }

    #[tokio::test]
    async fn the_agents_own_write_refreshes_its_record_so_a_second_write_passes() {
        let mut p = scripted(vec![
            one("c1", "write_file", WRITE_A),
            one("c2", "write_file", WRITE_A),
            done(),
        ]);
        p.write_outcome = WriteOutcome::Applied(Some([5; 7]));
        run(&mut p).await;
        assert_eq!(p.bases, vec![ReadBasis::Unread, ReadBasis::Read([5; 7])]);
    }

    #[tokio::test]
    async fn a_write_whose_version_is_unknown_forgets_the_record() {
        let mut p = scripted(vec![
            one("c1", "read_file", READ_A),
            one("c2", "write_file", WRITE_A),
            one("c3", "write_file", WRITE_A),
            done(),
        ]);
        p.read_versions = VecDeque::from([[1; 7]]);
        p.write_outcome = WriteOutcome::Applied(None);
        run(&mut p).await;
        assert_eq!(p.bases, vec![ReadBasis::Read([1; 7]), ReadBasis::Unread]);
    }

    #[tokio::test]
    async fn the_read_after_a_stale_refusal_is_not_flagged_and_bases_the_next_write() {
        let mut p = scripted(vec![
            one("c1", "read_file", READ_A),
            one("c2", "write_file", WRITE_A),
            one("c3", "read_file", READ_A),
            one("c4", "write_file", WRITE_A),
            done(),
        ]);
        p.read_versions = VecDeque::from([[1; 7], [2; 7]]);
        p.write_outcome = WriteOutcome::Stale;
        let t = run(&mut p).await;
        assert!(!changed_at(&t, 6));
        assert_eq!(
            p.bases,
            vec![ReadBasis::Read([1; 7]), ReadBasis::Read([2; 7])]
        );
    }

    #[tokio::test]
    async fn a_ctime_only_difference_is_not_flagged_changed_and_an_mtime_one_is() {
        let mut p = scripted(vec![
            one("c1", "read_file", READ_A),
            one("c2", "read_file", READ_A),
            one("c3", "read_file", READ_A),
            done(),
        ]);
        p.read_versions = VecDeque::from([
            [1, 1, 1, 1, 1, 1, 1],
            [1, 1, 1, 1, 1, 9, 9],
            [1, 1, 1, 9, 1, 9, 9],
        ]);
        let t = run(&mut p).await;
        assert_eq!((changed_at(&t, 4), changed_at(&t, 6)), (false, true));
    }

    #[tokio::test]
    async fn a_write_that_was_not_applied_keeps_change_detection() {
        let read = |id: &str| PromptReply {
            blocks: vec![],
            tool_calls: vec![call(id, "read_file", r#"{"path":"/w/a.txt"}"#)],
            usage: None,
        };
        for outcome in [WriteOutcome::NotSent, WriteOutcome::Unknown] {
            let mut p = scripted(vec![
                read("c1"),
                PromptReply {
                    blocks: vec![],
                    tool_calls: vec![call(
                        "c2",
                        "write_file",
                        r#"{"path":"/w/a.txt","content":"new"}"#,
                    )],
                    usage: None,
                },
                read("c3"),
                PromptReply {
                    blocks: vec![text("done")],
                    tool_calls: vec![],
                    usage: None,
                },
            ]);
            p.write_outcome = outcome.clone();
            p.read_versions = VecDeque::from([[1; 7], [2; 7]]);
            let mut t = Transcript::new("conv", "go");
            let budget = Budget {
                max_steps: 8,
                max_tool_calls_per_step: 2,
            };
            drive_unmetered(&mut p, &mut t, &budget).await;
            let text = tool_text(&t.turns()[6]);
            let json = text
                .split_once("\n\nsteps remaining: ")
                .unwrap()
                .0
                .to_string();
            let v: serde_json::Value = serde_json::from_str(&json).unwrap();
            assert_eq!(v["changed"], true, "{outcome:?}");
        }
    }

    #[tokio::test]
    async fn read_then_write_then_answer_drives_to_completion_with_the_right_transcript() {
        // Absolute paths throughout: `route()` refuses relative ones.
        let mut p = scripted(vec![
            PromptReply {
                blocks: vec![],
                tool_calls: vec![call("c1", "read_file", r#"{"path":"/w/a.txt"}"#)],
                usage: None,
            },
            PromptReply {
                blocks: vec![],
                tool_calls: vec![call(
                    "c2",
                    "write_file",
                    r#"{"path":"/w/a.txt","content":"new"}"#,
                )],
                usage: None,
            },
            PromptReply {
                blocks: vec![text("all done")],
                tool_calls: vec![],
                usage: None,
            },
        ]);
        let mut t = Transcript::new("conv", "edit a.txt");
        let out = drive_unmetered(&mut p, &mut t, &budget()).await;
        assert_eq!(out.answer.as_deref(), Some("all done"));
        assert!(out.stopped.is_none());
        assert_eq!(out.steps_used, 3);
        assert_eq!(p.reads, vec!["/w/a.txt"]);
        assert_eq!(
            p.writes,
            vec![("conv".to_string(), "/w/a.txt".to_string(), b"new".to_vec())]
        );
        assert_eq!(t.turns().len(), 6, "user, asst, tool, asst, tool, asst");
        assert!(tool_text(&t.turns()[2]).contains("\"content\":\"file body\""));
        assert!(tool_text(&t.turns()[4]).starts_with("applied"));
    }
    #[tokio::test]
    async fn each_tool_result_answers_its_own_call_id_in_call_order() {
        // Two calls in ONE step (cap 2), so the correlation is observable:
        // every other row has a single call, where answering `calls[0]` — or
        // the empty string — is indistinguishable from answering `call`.
        // cargo-mutants does not substitute call arguments, so the 0-missed
        // run does not cover this; only this row does.
        let mut p = scripted(vec![
            PromptReply {
                blocks: vec![],
                tool_calls: vec![
                    call("c1", "read_file", r#"{"path":"/w/a"}"#),
                    call("c2", "read_file", r#"{"path":"/w/b"}"#),
                ],
                usage: None,
            },
            PromptReply {
                blocks: vec![text("both read")],
                tool_calls: vec![],
                usage: None,
            },
        ]);
        let mut t = Transcript::new("conv", "read both");
        let out = drive_unmetered(&mut p, &mut t, &budget()).await;
        assert_eq!(out.answer.as_deref(), Some("both read"));
        assert_eq!(p.reads, vec!["/w/a", "/w/b"], "executed in call order");
        assert_eq!(t.turns().len(), 5, "user, asst, tool c1, tool c2, asst");
        assert_eq!(
            [tool_call_id(&t.turns()[2]), tool_call_id(&t.turns()[3])],
            ["c1".to_string(), "c2".to_string()],
            "each tool turn answers ITS OWN call_id, in call order"
        );
        // Both results are rendered with the SAME live count: steps-remaining
        // is per STEP, not per call, and one step spent one step.
        for i in [2, 3] {
            assert!(
                tool_text(&t.turns()[i]).ends_with("steps remaining: 3"),
                "{i}"
            );
        }
    }
    #[tokio::test]
    async fn a_refused_read_reaches_the_model_as_not_authorized_and_the_loop_continues() {
        let mut p = scripted(vec![
            PromptReply {
                blocks: vec![],
                tool_calls: vec![call("c1", "read_file", r#"{"path":"/x/.ssh/id_rsa"}"#)],
                usage: None,
            },
            PromptReply {
                blocks: vec![text("I could not read that")],
                tool_calls: vec![],
                usage: None,
            },
        ]);
        p.read_outcome = ReadOutcome::Refused;
        let mut t = Transcript::new("conv", "q");
        let out = drive_unmetered(&mut p, &mut t, &budget()).await;
        assert_eq!(out.answer.as_deref(), Some("I could not read that"));
        assert!(tool_text(&t.turns()[2]).starts_with("Not authorized"));
    }
    #[tokio::test]
    async fn an_uncertain_write_is_attempted_exactly_once_and_an_unsent_one_is_a_tool_error() {
        for (outcome, want) in [
            (WriteOutcome::Unknown, "outcome unknown"),
            (WriteOutcome::NotSent, "tool error: write not sent"),
        ] {
            let mut p = scripted(vec![
                PromptReply {
                    blocks: vec![],
                    tool_calls: vec![call("c1", "write_file", r#"{"path":"/w/a","content":"x"}"#)],
                    usage: None,
                },
                PromptReply {
                    blocks: vec![text("ok")],
                    tool_calls: vec![],
                    usage: None,
                },
            ]);
            p.write_outcome = outcome;
            let mut t = Transcript::new("conv", "q");
            drive_unmetered(&mut p, &mut t, &budget()).await;
            assert_eq!(p.writes.len(), 1, "exactly one attempt, never a retry");
            assert!(tool_text(&t.turns()[2]).starts_with(want), "{want}");
        }
    }
    #[tokio::test]
    async fn the_step_budget_stops_a_model_that_never_answers() {
        // An absolute path, so this exercises a REAL read on every step, not the BadCall arm.
        let looping = PromptReply {
            blocks: vec![],
            tool_calls: vec![call("c", "read_file", r#"{"path":"/w/a"}"#)],
            usage: None,
        };
        let mut p = scripted(vec![
            looping.clone(),
            looping.clone(),
            looping.clone(),
            looping,
        ]);
        let mut t = Transcript::new("conv", "q");
        let out = drive_unmetered(
            &mut p,
            &mut t,
            &Budget {
                max_steps: 2,
                max_tool_calls_per_step: 2,
            },
        )
        .await;
        assert!(matches!(out.stopped, Some(StopReason::StepBudget)));
        assert_eq!(
            p.prompts, 2,
            "no third model call after the budget is spent"
        );
        // Trace: call 1 → steps_remaining 1 → Execute → ONE read. Call 2 →
        // steps_remaining 0 → Stop BEFORE executing. The last model call's tool
        // calls are never executed by construction — that is the budget.
        assert_eq!(
            p.reads.len(),
            1,
            "only the step with steps left executed its read"
        );
    }
    #[tokio::test]
    async fn a_bad_tool_call_is_answered_as_a_tool_error_with_no_plane_call() {
        // Every RouteError arm, by name and by args (each is a render
        // arm in `drive`, and the T1 floor is measured on this module alone).
        for (name, bad) in [
            ("read_file", "not json"),
            ("read_file", r#"{"path":"relative.txt"}"#),
            ("read_file", r#"{"path":""}"#),
            // Non-canonical: the kernel would answer this `BadRequest` before
            // the PDP, which renders as an unappealable `read unavailable`.
            // The router refuses it as a fixable tool error instead.
            ("read_file", r#"{"path":"/home/u/p/../q/f.txt"}"#),
            ("nope", r#"{"path":"/a"}"#),
            // codex round 1, important 1: serde's derived struct visitor
            // accepts a positional array, so these two USED to reach the
            // plane. Both legs, because the shape check is per-arm.
            ("read_file", r#"["/allowed/file"]"#),
            ("write_file", r#"["/allowed/file","SECRET-POSITIONAL"]"#),
        ] {
            let mut p = scripted(vec![
                PromptReply {
                    blocks: vec![],
                    tool_calls: vec![call("c1", name, bad)],
                    usage: None,
                },
                PromptReply {
                    blocks: vec![text("sorry")],
                    tool_calls: vec![],
                    usage: None,
                },
            ]);
            let mut t = Transcript::new("conv", "q");
            drive_unmetered(&mut p, &mut t, &budget()).await;
            assert!(p.reads.is_empty() && p.writes.is_empty(), "{name} {bad}");
            assert!(
                tool_text(&t.turns()[2]).starts_with("tool error:"),
                "{name} {bad}"
            );
        }
    }
    /// The tool-error TEXT is the whole of what the model is told, so it must
    /// name every rule that actually produces the variant. codex round 1
    /// observed that this line named the segment rules only, while
    /// `MalformedPath` is also how the router refuses an over-length path and
    /// a NUL-bearing one — so a model that sent a 5000-byte path was told to
    /// fix its segments. Pinned by value, on all three causes.
    #[tokio::test]
    async fn the_malformed_path_tool_error_names_every_rule_that_produces_it() {
        let over = format!("/{}", "x".repeat(maknae_proto::MAX_MUTATION_PATH_BYTES));
        for bad in [
            r#"{"path":"/home/u/p/../q/f.txt"}"#.to_string(),
            r#"{"path":"/home/u/a\u0000.txt"}"#.to_string(),
            format!(r#"{{"path":"{over}"}}"#),
        ] {
            let mut p = scripted(vec![
                PromptReply {
                    blocks: vec![],
                    tool_calls: vec![call("c1", "read_file", &bad)],
                    usage: None,
                },
                PromptReply {
                    blocks: vec![text("sorry")],
                    tool_calls: vec![],
                    usage: None,
                },
            ]);
            let mut t = Transcript::new("conv", "q");
            drive_unmetered(&mut p, &mut t, &budget()).await;
            let got = tool_text(&t.turns()[2]);
            assert!(got.starts_with("tool error: path must be canonical: no empty, \".\" or \"..\" segments and no trailing \"/\"; at most 4096 bytes and no NUL byte"), "{got}");
        }
        // By VALUE, so a mutant substituting another number for the constant
        // is caught here too, not only at the router's own boundary table.
        assert_eq!(maknae_proto::MAX_MUTATION_PATH_BYTES, 4096);
    }
    #[test]
    fn a_reply_carrying_a_non_text_block_contributes_no_text_to_the_answer() {
        // `admitted_reply` refuses non-text before it reaches the loop; this
        // pins `text_of`'s behaviour if that ever loosens.
        let r = PromptReply {
            blocks: vec![
                ContentBlock::Image {
                    data: "AA==".into(),
                    mime_type: "image/png".into(),
                },
                text("ok"),
            ],
            tool_calls: vec![],
            usage: None,
        };
        assert!(matches!(step(&r, 3, &budget()), Next::Answer(s) if s == "ok"));
    }
    #[tokio::test]
    async fn a_zero_step_budget_stops_before_any_model_call() {
        // The loop-top guard is structurally unreachable for max_steps >= 1
        // (`step` stops first at steps_remaining == 0); it is what keeps a
        // zero budget safe if `agent_from_section`'s 1..=64 bound were ever
        // loosened. Covered so the guard is a tested property, not dead code.
        let mut p = scripted(vec![PromptReply {
            blocks: vec![text("never")],
            tool_calls: vec![],
            usage: None,
        }]);
        let mut t = Transcript::new("conv", "q");
        let out = drive_unmetered(
            &mut p,
            &mut t,
            &Budget {
                max_steps: 0,
                max_tool_calls_per_step: 2,
            },
        )
        .await;
        assert!(matches!(out.stopped, Some(StopReason::StepBudget)));
        assert_eq!(p.prompts, 0);
    }
    #[tokio::test]
    async fn an_unavailable_read_is_rendered_as_unavailable_not_refused() {
        let mut p = scripted(vec![
            PromptReply {
                blocks: vec![],
                tool_calls: vec![call("c1", "read_file", r#"{"path":"/a"}"#)],
                usage: None,
            },
            PromptReply {
                blocks: vec![text("ok")],
                tool_calls: vec![],
                usage: None,
            },
        ]);
        p.read_outcome = ReadOutcome::Unavailable;
        let mut t = Transcript::new("conv", "q");
        drive_unmetered(&mut p, &mut t, &budget()).await;
        assert!(tool_text(&t.turns()[2]).starts_with("read unavailable"));
    }
    #[tokio::test]
    async fn every_prompt_failure_stops_with_its_own_reason() {
        for (err, want) in [
            (PlaneError::FrameTooLarge, StopReason::FrameBound),
            (PlaneError::Refused, StopReason::PromptRefused),
            // Its OWN reason, never folded into `PromptRefused`: the CLI
            // prints a different line for it, because a pre-gate `BadRequest`
            // provably never reached the provider.
            (PlaneError::Malformed, StopReason::PromptMalformed),
            (
                PlaneError::Transport("t".into()),
                StopReason::Transport("t".into()),
            ),
        ] {
            let mut p = scripted(vec![]);
            p.replies.push_back(Err(err));
            let mut t = Transcript::new("conv", "q");
            let out = drive_unmetered(&mut p, &mut t, &budget()).await;
            assert_eq!(out.stopped, Some(want));
            assert_eq!(out.steps_used, 0);
        }
    }

    fn answer() -> PromptReply {
        PromptReply {
            blocks: vec![text("done")],
            tool_calls: vec![],
            usage: None,
        }
    }

    #[tokio::test]
    async fn the_loop_stops_before_sending_a_turn_past_the_budget() {
        let mut notices = vec![];
        let mut p = scripted(vec![answer()]);
        let mut m = Meter::new(ContextBudget::new(2_000, None).unwrap());
        let mut t = Transcript::new("c", &"q".repeat(100));
        let out = drive(&mut p, &mut t, &budget(), &mut m, &mut |n: &Notice| {
            notices.push(*n)
        })
        .await;
        assert_eq!((out.answer.as_deref(), p.prompts), (Some("done"), 1));

        let mut p = scripted(vec![answer()]);
        let mut m = Meter::new(ContextBudget::new(2_000, None).unwrap());
        let mut t = Transcript::new("c", &"q".repeat(5_000));
        let out = drive(&mut p, &mut t, &budget(), &mut m, &mut |n: &Notice| {
            notices.push(*n)
        })
        .await;
        assert_eq!(out.stopped, Some(StopReason::ContextBudget));
        assert_eq!((p.prompts, out.steps_used), (0, 0));
        assert!(notices.is_empty());
    }

    #[tokio::test]
    async fn a_turn_near_the_budget_is_sent_with_a_notice() {
        let mut notices = vec![];
        let mut p = scripted(vec![answer()]);
        let mut m = Meter::new(ContextBudget::new(2_000, None).unwrap());
        let mut t = Transcript::new("c", &"q".repeat(1_800));
        let out = drive(&mut p, &mut t, &budget(), &mut m, &mut |n: &Notice| {
            notices.push(*n)
        })
        .await;
        assert_eq!(out.answer.as_deref(), Some("done"));
        assert_eq!(
            notices,
            vec![Notice {
                percent: 99,
                tokens: 1_986,
                budget: 2_000,
                estimated: true
            }]
        );
    }

    #[tokio::test]
    async fn the_providers_usage_meters_the_next_turn() {
        let mut p = scripted(vec![
            PromptReply {
                blocks: vec![],
                tool_calls: vec![call("c1", "read_file", r#"{"path":"/w/a.txt"}"#)],
                usage: Some(maknae_proto::Usage {
                    prompt_tokens: 1_990,
                    completion_tokens: None,
                }),
            },
            answer(),
        ]);
        let mut m = Meter::new(ContextBudget::new(2_000, None).unwrap());
        let mut t = Transcript::new("c", "q");
        let out = drive(&mut p, &mut t, &budget(), &mut m, &mut |_: &Notice| {}).await;
        assert_eq!(out.stopped, Some(StopReason::ContextBudget));
        assert_eq!(p.prompts, 1);
    }
}
