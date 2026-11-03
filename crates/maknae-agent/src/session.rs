//! One conversation across prompts: the transcript, the per-file read basis,
//! the context meter and the conversation ID live here, so a host can give it
//! prompt after prompt. Each session is its own value; nothing is shared
//! between sessions except through the kernel.
use crate::budget::{ContextBudget, Meter};
use crate::drive::{drive_session, Budget, LoopEvent, Outcome, Seen, StopReason};
use crate::plane::Plane;
use crate::transcript::Transcript;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

/// Stops one session before its next plane call. A cooperative courtesy: the
/// stop that must hold without the loop's cooperation is enforced elsewhere.
#[derive(Clone)]
pub struct LoopHandle(Arc<AtomicBool>);

impl LoopHandle {
    pub fn stop(&self) {
        self.0.store(true, Ordering::Release);
    }
}

#[derive(Debug, PartialEq, Eq)]
pub struct SessionClosed;

pub struct Session {
    transcript: Transcript,
    seen: Seen,
    meter: Meter,
    budget: Budget,
    stop: Arc<AtomicBool>,
    answered: bool,
    pending: bool,
    home: Option<String>,
}

impl Session {
    pub fn new(
        conversation: impl Into<String>,
        first_prompt: &str,
        budget: Budget,
        context: ContextBudget,
        home: Option<String>,
    ) -> Self {
        Session {
            transcript: Transcript::new(conversation, first_prompt),
            seen: Seen::new(),
            meter: Meter::new(context),
            budget,
            stop: Arc::new(AtomicBool::new(false)),
            answered: false,
            pending: true,
            home,
        }
    }

    pub fn handle(&self) -> LoopHandle {
        LoopHandle(Arc::clone(&self.stop))
    }

    pub fn conversation(&self) -> &str {
        self.transcript.conversation()
    }

    pub fn budget(&self) -> Budget {
        self.budget
    }

    /// Refused unless the last run answered: a step-budget or too-many-calls
    /// stop leaves tool calls unanswered, and a user turn after them is not a
    /// valid exchange.
    pub fn prompt(&mut self, text: &str) -> Result<(), SessionClosed> {
        if !self.answered || self.pending {
            return Err(SessionClosed);
        }
        self.transcript.push_user(text);
        self.pending = true;
        Ok(())
    }

    pub async fn run<P: Plane + Send>(
        &mut self,
        plane: &mut P,
        emit: &mut (impl FnMut(LoopEvent) + Send),
    ) -> Outcome {
        if !self.pending {
            emit(LoopEvent::Stopped(StopReason::NothingPending));
            return Outcome {
                answer: None,
                stopped: Some(StopReason::NothingPending),
                steps_used: 0,
            };
        }
        self.pending = false;
        // Cleared before the await: a run dropped mid-call must leave the
        // session closed, not answered from the run before it.
        self.answered = false;
        let outcome = drive_session(
            plane,
            &mut self.transcript,
            &mut self.seen,
            &self.budget,
            &mut self.meter,
            &self.stop,
            emit,
            self.home.as_deref(),
        )
        .await;
        match (&outcome.answer, &outcome.stopped) {
            (Some(_), _) => emit(LoopEvent::Answered),
            (None, Some(r)) => emit(LoopEvent::Stopped(r.clone())),
            (None, None) => {}
        }
        self.answered = outcome.answer.is_some();
        outcome
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::plane::{PlaneError, ReadBasis, ReadOutcome, ReadPage, WriteOutcome};
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
            refused: None,
        }
    }
    fn tool(id: &str, name: &str, args: &str) -> PromptReply {
        PromptReply {
            reasoning: None,
            blocks: vec![],
            tool_calls: vec![call(id, name, args)],
            usage: None,
        }
    }
    fn answer(s: &str) -> PromptReply {
        PromptReply {
            reasoning: None,
            blocks: vec![text(s)],
            tool_calls: vec![],
            usage: None,
        }
    }
    fn budget() -> Budget {
        Budget {
            max_steps: 8,
            max_tool_calls_per_step: 2,
        }
    }
    fn unmetered() -> ContextBudget {
        ContextBudget::new(maknae_proto::MAX_CONTEXT_TOKENS, None).unwrap()
    }
    fn read_args(path: &str) -> String {
        format!(r#"{{"path":"{path}"}}"#)
    }
    fn write_args(path: &str) -> String {
        format!(r#"{{"path":"{path}","content":"new"}}"#)
    }

    #[derive(Default)]
    struct Fake {
        replies: VecDeque<PromptReply>,
        prompts: Vec<(String, usize)>,
        bases: Vec<ReadBasis>,
        paths: Vec<String>,
        version: [i64; 7],
        yields: bool,
        started: Option<tokio::sync::oneshot::Sender<()>>,
        release: Option<tokio::sync::oneshot::Receiver<()>>,
    }
    impl Plane for Fake {
        async fn prompt(&mut self, c: &str, t: &[Turn]) -> Result<PromptReply, PlaneError> {
            if self.yields {
                tokio::task::yield_now().await;
            }
            self.prompts.push((c.into(), t.len()));
            Ok(self.replies.pop_front().expect("script exhausted"))
        }
        async fn read(
            &mut self,
            _c: &str,
            p: &str,
            _page: maknae_proto::PageRequest,
        ) -> ReadOutcome {
            self.paths.push(p.into());
            if self.yields {
                tokio::task::yield_now().await;
            }
            ReadOutcome::Content(ReadPage {
                content: Zeroizing::new(b"body".to_vec()),
                level: "UNCLASSIFIED".into(),
                lines: Some((1, 1)),
                complete_line: true,
                next: None,
                eof: true,
                version: self.version,
                changed: false,
            })
        }
        async fn write(&mut self, _c: &str, p: &str, _b: &[u8], basis: ReadBasis) -> WriteOutcome {
            self.paths.push(p.into());
            if let Some(s) = self.started.take() {
                s.send(()).unwrap();
            }
            if let Some(r) = self.release.take() {
                r.await.unwrap();
            }
            if self.yields {
                tokio::task::yield_now().await;
            }
            self.bases.push(basis);
            WriteOutcome::Applied(None)
        }
    }
    fn fake(replies: Vec<PromptReply>) -> Fake {
        Fake {
            replies: replies.into(),
            ..Fake::default()
        }
    }

    fn tool_ids(s: &Session) -> Vec<String> {
        s.transcript
            .turns()
            .iter()
            .filter_map(|t| match t {
                Turn::Tool { call_id, .. } => Some(call_id.clone()),
                _ => None,
            })
            .collect()
    }

    async fn run_collect(s: &mut Session, p: &mut Fake) -> Vec<LoopEvent> {
        run_answer(s, p).await.0
    }

    async fn run_answer(s: &mut Session, p: &mut Fake) -> (Vec<LoopEvent>, Option<String>) {
        let mut events = vec![];
        let out = s.run(p, &mut |e| events.push(e)).await;
        (events, out.answer)
    }

    #[tokio::test]
    async fn an_answer_emits_one_answer_event_and_opens_the_session() {
        let mut s = Session::new("conv-1", "hello", budget(), unmetered(), None);
        let mut p = fake(vec![answer("hi")]);
        assert_eq!(
            run_answer(&mut s, &mut p).await,
            (vec![LoopEvent::Answered], Some("hi".to_string()))
        );
        assert_eq!(s.prompt("again"), Ok(()));
        assert_eq!(s.conversation(), "conv-1");
    }

    #[tokio::test]
    async fn a_prompt_after_a_stop_is_refused() {
        let mut s = Session::new("c", "go", budget(), unmetered(), None);
        let mut p = fake(vec![PromptReply {
            reasoning: None,
            blocks: vec![],
            tool_calls: vec![
                call("1", "read_file", &read_args("/a")),
                call("2", "read_file", &read_args("/b")),
                call("3", "read_file", &read_args("/c")),
            ],
            usage: None,
        }]);
        let events = run_collect(&mut s, &mut p).await;
        assert_eq!(
            events,
            vec![LoopEvent::Stopped(StopReason::TooManyToolCalls(3))]
        );
        let turns = s.transcript.turns().len();
        assert_eq!(s.prompt("x"), Err(SessionClosed));
        assert_eq!(s.transcript.turns().len(), turns);
    }

    #[tokio::test]
    async fn a_run_without_a_pending_prompt_sends_nothing() {
        let mut s = Session::new("c", "go", budget(), unmetered(), None);
        let mut p = fake(vec![answer("hi")]);
        run_collect(&mut s, &mut p).await;
        let events = run_collect(&mut s, &mut p).await;
        assert_eq!(events, vec![LoopEvent::Stopped(StopReason::NothingPending)]);
        assert_eq!(p.prompts.len(), 1);
        assert_eq!(s.prompt("a"), Ok(()));
        assert_eq!(
            s.prompt("b"),
            Err(SessionClosed),
            "one prompt is already pending"
        );
    }

    #[tokio::test]
    async fn a_second_prompt_carries_the_conversation_and_the_read_basis() {
        let mut s = Session::new("conv-x", "read /f", budget(), unmetered(), None);
        let mut p = fake(vec![
            tool("c1", "read_file", &read_args("/f")),
            answer("read"),
            tool("c2", "write_file", &write_args("/f")),
            answer("written"),
        ]);
        p.version = [5; 7];
        run_collect(&mut s, &mut p).await;
        s.prompt("now edit /f").unwrap();
        let (events, answer) = run_answer(&mut s, &mut p).await;
        assert_eq!(events, vec![LoopEvent::Answered]);
        assert_eq!(answer.as_deref(), Some("written"));
        assert_eq!(p.bases, vec![ReadBasis::Read([5; 7])]);
        assert!(p.prompts.iter().all(|(c, _)| c == "conv-x"));
        let lens: Vec<usize> = p.prompts.iter().map(|(_, n)| *n).collect();
        assert_eq!(lens, vec![1, 3, 5, 7]);
    }

    #[tokio::test]
    async fn budget_warnings_fire_once_per_conversation_not_per_prompt() {
        let mut s = Session::new(
            "c",
            &"q".repeat(1_700),
            budget(),
            ContextBudget::new(2_000, None).unwrap(),
            None,
        );
        let mut p = fake(vec![answer("one"), answer("two")]);
        let first = run_collect(&mut s, &mut p).await;
        assert!(
            matches!(&first[..], [LoopEvent::Notice(_), LoopEvent::Answered]),
            "{first:?}"
        );
        s.prompt("more").unwrap();
        let second = run_collect(&mut s, &mut p).await;
        assert_eq!(second, vec![LoopEvent::Answered]);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn two_sessions_run_concurrently_without_sharing_state() {
        let spawn = |id: &'static str, script: Vec<PromptReply>| {
            tokio::spawn(async move {
                let mut s = Session::new(id, "go", budget(), unmetered(), None);
                let mut p = fake(script);
                p.yields = true;
                let mut events = vec![];
                let out = s.run(&mut p, &mut |e| events.push(e)).await;
                (events, p, s, out.answer)
            })
        };
        let a = spawn(
            "conv-a",
            vec![tool("a1", "read_file", &read_args("/a")), answer("A")],
        );
        let b = spawn(
            "conv-b",
            vec![
                tool("b1", "write_file", &write_args("/b")),
                tool("b2", "read_file", &read_args("/b")),
                answer("B"),
            ],
        );
        let (ea, pa, sa, aa) = a.await.unwrap();
        let (eb, pb, sb, ab) = b.await.unwrap();
        assert_eq!(ea.last(), Some(&LoopEvent::Answered));
        assert_eq!(eb.last(), Some(&LoopEvent::Answered));
        assert_eq!((aa.as_deref(), ab.as_deref()), (Some("A"), Some("B")));
        assert!(pa.prompts.iter().all(|(c, _)| c == "conv-a"));
        assert!(pb.prompts.iter().all(|(c, _)| c == "conv-b"));
        assert!(tool_ids(&sa).iter().all(|id| id.starts_with('a')));
        assert!(tool_ids(&sb).iter().all(|id| id.starts_with('b')));
        assert_eq!(tool_ids(&sb), vec!["b1".to_string(), "b2".to_string()]);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_stop_waits_for_the_granted_write_then_ends_the_loop() {
        let (started_tx, started_rx) = tokio::sync::oneshot::channel();
        let (release_tx, release_rx) = tokio::sync::oneshot::channel();
        let mut sa = Session::new("conv-a", "go", budget(), unmetered(), None);
        let handle = sa.handle();
        let mut pa = fake(vec![
            tool("a1", "write_file", &write_args("/a")),
            answer("A"),
        ]);
        pa.started = Some(started_tx);
        pa.release = Some(release_rx);
        let a = tokio::spawn(async move {
            let mut events = vec![];
            sa.run(&mut pa, &mut |e| events.push(e)).await;
            (events, pa, sa)
        });
        let b = tokio::spawn(async move {
            let mut sb = Session::new("conv-b", "go", budget(), unmetered(), None);
            let mut pb = fake(vec![tool("b1", "read_file", &read_args("/b")), answer("B")]);
            pb.yields = true;
            let mut events = vec![];
            let out = sb.run(&mut pb, &mut |e| events.push(e)).await;
            (events, out.answer)
        });
        tokio::time::timeout(std::time::Duration::from_secs(10), started_rx)
            .await
            .expect("A's write never started")
            .unwrap();
        handle.stop();
        release_tx.send(()).unwrap();
        let (ea, pa, sa) = a.await.unwrap();
        assert_eq!(tool_ids(&sa), vec!["a1".to_string()]);
        assert_eq!(pa.bases.len(), 1, "the granted write ran to its outcome");
        assert_eq!(pa.prompts.len(), 1);
        assert_eq!(ea.last(), Some(&LoopEvent::Stopped(StopReason::Stopped)));
        let (eb, ab) = b.await.unwrap();
        assert_eq!(eb.last(), Some(&LoopEvent::Answered));
        assert_eq!(ab.as_deref(), Some("B"));
    }

    #[tokio::test]
    async fn a_run_cancelled_mid_write_leaves_the_session_closed() {
        let mut s = Session::new("c", "first", budget(), unmetered(), None);
        let mut p = fake(vec![
            answer("one"),
            tool("w1", "write_file", &write_args("/a")),
        ]);
        run_collect(&mut s, &mut p).await;
        s.prompt("second").unwrap();
        let (_started_tx, started_rx) = tokio::sync::oneshot::channel::<()>();
        let (_release_tx, release_rx) = tokio::sync::oneshot::channel();
        drop(started_rx);
        p.release = Some(release_rx);
        let cancelled = tokio::time::timeout(
            std::time::Duration::from_millis(50),
            s.run(&mut p, &mut |_| {}),
        )
        .await;
        assert!(
            cancelled.is_err(),
            "the run must still be waiting on its write"
        );
        assert_eq!(s.prompt("third"), Err(SessionClosed));
    }

    #[tokio::test]
    async fn an_answer_event_carries_no_reply_text() {
        let mut s = Session::new("c", "q", budget(), unmetered(), None);
        let mut p = fake(vec![answer("SENTINEL-ANSWER-TEXT")]);
        let mut events = vec![];
        let out = s.run(&mut p, &mut |e| events.push(e)).await;
        assert_eq!(out.answer.as_deref(), Some("SENTINEL-ANSWER-TEXT"));
        let shown = format!("{events:?}");
        assert!(!shown.contains("SENTINEL-ANSWER-TEXT"), "{shown}");
    }

    fn home_session(home: Option<&str>) -> Session {
        Session::new("c", "go", budget(), unmetered(), home.map(str::to_string))
    }

    #[tokio::test]
    async fn a_session_writes_through_its_home() {
        let mut s = home_session(Some("/home/u"));
        let mut p = fake(vec![
            tool("w1", "write_file", &write_args("~/f")),
            answer("ok"),
        ]);
        run_collect(&mut s, &mut p).await;
        assert_eq!(p.paths, vec!["/home/u/f".to_string()]);
    }

    #[tokio::test]
    async fn the_read_basis_spans_the_tilde_and_absolute_forms() {
        let mut s = home_session(Some("/home/u"));
        let mut p = fake(vec![
            tool("r1", "read_file", &read_args("~/f")),
            tool("w1", "write_file", &write_args("/home/u/f")),
            answer("ok"),
        ]);
        p.version = [9; 7];
        run_collect(&mut s, &mut p).await;
        assert_eq!(p.bases, vec![ReadBasis::Read([9; 7])]);
        assert_eq!(
            p.paths,
            vec!["/home/u/f".to_string(), "/home/u/f".to_string()]
        );
    }

    #[tokio::test]
    async fn a_session_without_a_home_refuses_tilde_and_keeps_absolute() {
        let mut s = home_session(None);
        let mut p = fake(vec![
            tool("w1", "write_file", &write_args("~/f")),
            tool("w2", "write_file", &write_args("/abs/f")),
            answer("ok"),
        ]);
        run_collect(&mut s, &mut p).await;
        assert_eq!(p.paths, vec!["/abs/f".to_string()]);
        let tilde_result = s
            .transcript
            .turns()
            .iter()
            .find_map(|t| match t {
                Turn::Tool { call_id, content } if call_id == "w1" => match &content[0] {
                    ContentBlock::Text { text } => Some(text.0.to_string()),
                    _ => None,
                },
                _ => None,
            })
            .unwrap();
        assert!(
            tilde_result.starts_with("tool error: home-relative paths are unavailable"),
            "{tilde_result}"
        );
    }

    #[test]
    fn run_is_send() {
        fn assert_send<T: Send>(_: T) {}
        let mut s = Session::new("c", "q", budget(), unmetered(), None);
        let mut p = fake(vec![]);
        assert_send(s.run(&mut p, &mut |_| {}));
    }

    #[test]
    fn the_budget_is_returned_as_given() {
        let s = Session::new("c", "q", budget(), unmetered(), None);
        let b = s.budget();
        assert_eq!((b.max_steps, b.max_tool_calls_per_step), (8, 2));
    }
}
