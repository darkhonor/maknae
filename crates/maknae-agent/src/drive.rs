//! The loop. `step` is the pure decision — answer, execute, or stop — and
//! `drive` runs it against a [`Plane`] until an answer or a bound. Bounds are
//! ADVISORY by construction (ADR-0023 d7): a well-behaved loop stops early;
//! nothing here fails closed against a hostile loop, and nothing here claims
//! to. The kernel decides every verb this asks for.
use crate::plane::{Plane, PlaneError, ReadOutcome, WriteOutcome};
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
    Transport(String),
}

#[derive(Debug)]
pub enum Next {
    Answer(String),
    Execute(Vec<ProposedToolCall>),
    Stop(StopReason),
}

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
) -> Outcome {
    let mut steps_used = 0u32;
    loop {
        if steps_used >= budget.max_steps {
            return Outcome {
                answer: None,
                stopped: Some(StopReason::StepBudget),
                steps_used,
            };
        }
        let reply = match plane
            .prompt(transcript.conversation(), transcript.turns())
            .await
        {
            Ok(r) => r,
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
                        Ok(ToolRequest::Read { path, .. }) => match plane.read(&path).await {
                            ReadOutcome::Content(b) => ToolOutcome::ReadContent(b),
                            ReadOutcome::Refused => ToolOutcome::ReadRefused,
                            ReadOutcome::Unavailable => ToolOutcome::ReadUnavailable,
                        },
                        Ok(ToolRequest::Write { path, content, .. }) => {
                            match plane.write(&path, &content).await {
                                WriteOutcome::Applied => ToolOutcome::WriteApplied,
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
            matches!(step(&PromptReply { blocks: vec![text("done")], tool_calls: vec![] }, 3, &budget()), Next::Answer(s) if s == "done")
        );
    }
    #[test]
    fn tool_calls_are_executed_when_steps_remain_and_stop_when_none_do() {
        let r = PromptReply {
            blocks: vec![],
            tool_calls: vec![call("c1", "read_file", "{}")],
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
        };
        assert!(matches!(
            step(&r, 3, &budget()),
            Next::Stop(StopReason::TooManyToolCalls(3))
        ));
    }

    struct Scripted {
        replies: VecDeque<Result<PromptReply, PlaneError>>,
        reads: Vec<String>,
        writes: Vec<(String, Vec<u8>)>,
        prompts: usize,
        read_outcome: ReadOutcome,
        write_outcome: WriteOutcome,
    }
    impl Plane for Scripted {
        async fn prompt(&mut self, _c: &str, _t: &[Turn]) -> Result<PromptReply, PlaneError> {
            self.prompts += 1;
            self.replies.pop_front().expect("script exhausted")
        }
        async fn read(&mut self, p: &str) -> ReadOutcome {
            self.reads.push(p.into());
            self.read_outcome.clone()
        }
        async fn write(&mut self, p: &str, c: &[u8]) -> WriteOutcome {
            self.writes.push((p.into(), c.to_vec()));
            self.write_outcome.clone()
        }
    }
    fn scripted(replies: Vec<PromptReply>) -> Scripted {
        Scripted {
            replies: replies.into_iter().map(Ok).collect(),
            reads: vec![],
            writes: vec![],
            prompts: 0,
            read_outcome: ReadOutcome::Content(Zeroizing::new(b"file body".to_vec())),
            write_outcome: WriteOutcome::Applied,
        }
    }

    #[tokio::test]
    async fn read_then_write_then_answer_drives_to_completion_with_the_right_transcript() {
        // Absolute paths throughout: R10's `route()` refuses relative ones.
        let mut p = scripted(vec![
            PromptReply {
                blocks: vec![],
                tool_calls: vec![call("c1", "read_file", r#"{"path":"/w/a.txt"}"#)],
            },
            PromptReply {
                blocks: vec![],
                tool_calls: vec![call(
                    "c2",
                    "write_file",
                    r#"{"path":"/w/a.txt","content":"new"}"#,
                )],
            },
            PromptReply {
                blocks: vec![text("all done")],
                tool_calls: vec![],
            },
        ]);
        let mut t = Transcript::new("conv", "edit a.txt");
        let out = drive(&mut p, &mut t, &budget()).await;
        assert_eq!(out.answer.as_deref(), Some("all done"));
        assert!(out.stopped.is_none());
        assert_eq!(out.steps_used, 3);
        assert_eq!(p.reads, vec!["/w/a.txt"]);
        assert_eq!(p.writes, vec![("/w/a.txt".to_string(), b"new".to_vec())]);
        assert_eq!(t.turns().len(), 6, "user, asst, tool, asst, tool, asst");
        assert!(tool_text(&t.turns()[2]).starts_with("file body"));
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
            },
            PromptReply {
                blocks: vec![text("both read")],
                tool_calls: vec![],
            },
        ]);
        let mut t = Transcript::new("conv", "read both");
        let out = drive(&mut p, &mut t, &budget()).await;
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
            },
            PromptReply {
                blocks: vec![text("I could not read that")],
                tool_calls: vec![],
            },
        ]);
        p.read_outcome = ReadOutcome::Refused;
        let mut t = Transcript::new("conv", "q");
        let out = drive(&mut p, &mut t, &budget()).await;
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
                },
                PromptReply {
                    blocks: vec![text("ok")],
                    tool_calls: vec![],
                },
            ]);
            p.write_outcome = outcome;
            let mut t = Transcript::new("conv", "q");
            drive(&mut p, &mut t, &budget()).await;
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
        };
        let mut p = scripted(vec![
            looping.clone(),
            looping.clone(),
            looping.clone(),
            looping,
        ]);
        let mut t = Transcript::new("conv", "q");
        let out = drive(
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
        // Every RouteError arm, by name and by args (R16: each is a render
        // arm in `drive`, and the T1 floor is measured on this module alone).
        for (name, bad) in [
            ("read_file", "not json"),
            ("read_file", r#"{"path":"relative.txt"}"#),
            ("read_file", r#"{"path":""}"#),
            ("nope", r#"{"path":"/a"}"#),
        ] {
            let mut p = scripted(vec![
                PromptReply {
                    blocks: vec![],
                    tool_calls: vec![call("c1", name, bad)],
                },
                PromptReply {
                    blocks: vec![text("sorry")],
                    tool_calls: vec![],
                },
            ]);
            let mut t = Transcript::new("conv", "q");
            drive(&mut p, &mut t, &budget()).await;
            assert!(p.reads.is_empty() && p.writes.is_empty(), "{name} {bad}");
            assert!(
                tool_text(&t.turns()[2]).starts_with("tool error:"),
                "{name} {bad}"
            );
        }
    }
    #[test]
    fn a_reply_carrying_a_non_text_block_contributes_no_text_to_the_answer() {
        // `admitted_reply` refuses non-text before it reaches the loop; this
        // pins `text_of`'s behaviour if that ever loosens (R16).
        let r = PromptReply {
            blocks: vec![
                ContentBlock::Image {
                    data: "AA==".into(),
                    mime_type: "image/png".into(),
                },
                text("ok"),
            ],
            tool_calls: vec![],
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
        }]);
        let mut t = Transcript::new("conv", "q");
        let out = drive(
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
            },
            PromptReply {
                blocks: vec![text("ok")],
                tool_calls: vec![],
            },
        ]);
        p.read_outcome = ReadOutcome::Unavailable;
        let mut t = Transcript::new("conv", "q");
        drive(&mut p, &mut t, &budget()).await;
        assert!(tool_text(&t.turns()[2]).starts_with("read unavailable"));
    }
    #[tokio::test]
    async fn every_prompt_failure_stops_with_its_own_reason() {
        for (err, want) in [
            (PlaneError::FrameTooLarge, StopReason::FrameBound),
            (PlaneError::Refused, StopReason::PromptRefused),
            (
                PlaneError::Transport("t".into()),
                StopReason::Transport("t".into()),
            ),
        ] {
            let mut p = scripted(vec![]);
            p.replies.push_back(Err(err));
            let mut t = Transcript::new("conv", "q");
            let out = drive(&mut p, &mut t, &budget()).await;
            assert_eq!(out.stopped, Some(want));
            assert_eq!(out.steps_used, 0);
        }
    }
}
