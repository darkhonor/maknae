//! Holds every mutation worker for the length of the test: own binary.
mod common;
use common::{Fixture, Records};
use maknae_proto::{
    ContentBlock, Payload, PromptReply, RespResult, SecretText, Turn, Verb, WriteMode,
};
use std::sync::Arc;
use std::time::Duration;

const GRANTS: &str = "roles:\n  user:\n    allow: [\"session.prompt\", \"session.new\", \"session.close\", \"session.list\", \"session.delete\"]\ndestinations:\n  user:\n    allow: [\"provider:openai\"]\n";
const MUTATION_WORKERS: usize = 16;

fn text(s: &str) -> ContentBlock {
    ContentBlock::Text {
        text: SecretText(maknae_io::Zeroizing::new(s.into())),
    }
}

struct Answer;
impl maknae_kernel::Egress for Answer {
    fn ready(&self) -> Result<(), maknae_kernel::EgressFailure> {
        Ok(())
    }
    fn deadline(&self) -> Duration {
        Duration::from_secs(5)
    }
    fn send(
        &self,
        _: &maknae_kernel::DurableEgressIntent,
        _: maknae_kernel::EgressRequest,
    ) -> Result<maknae_kernel::EgressReply, maknae_kernel::EgressFailure> {
        Ok(maknae_kernel::EgressReply {
            reply: PromptReply {
                blocks: vec![text("bound")],
                tool_calls: vec![],
                usage: None,
                reasoning: None,
            },
        })
    }
}

async fn next_response(client: &mut tokio::io::DuplexStream) -> maknae_proto::Response {
    let frame = tokio::time::timeout(Duration::from_secs(3), common::read_frame(client, 65536))
        .await
        .expect("a frame within 3s")
        .expect("a complete frame");
    maknae_proto::decode_response(&frame).unwrap()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn held_mutation_attempts_do_not_refuse_another_uids_conversation_work() {
    let mut fx = Fixture::with_rules("conv-pool", &["Read", "Write"], &[], GRANTS);
    fx.conversations = common::conversations();
    fx.take_turns = false;
    let target = fx.root.join("held-attempt-target");
    std::fs::write(&target, b"untouched").unwrap();
    let mut stalled = Vec::new();
    for _ in 0..MUTATION_WORKERS {
        let attempt = Records::new(0);
        let (mut client, task, body) = fx.start(
            Verb::FsWrite {
                path: target.to_str().unwrap().into(),
                content_length: 1,
                mode: WriteMode::Existing,
                conversation: None,
            },
            Some(maknae_io::open_path_for_delegation(&target).unwrap()),
            Arc::clone(&attempt),
        );
        common::write_frame(&mut client, &body).await.unwrap();
        match next_response(&mut client).await.result {
            RespResult::Ok(Payload::MutationAttempt(_)) => {}
            other => panic!(
                "expected a held grant, got {other:?}: {:?}",
                attempt
                    .snapshot()
                    .iter()
                    .map(|r| r.outcome.reason.clone())
                    .collect::<Vec<_>>()
            ),
        }
        stalled.push((client, task));
    }
    let overflow = Records::new(0);
    let (mut client, task, body) = fx.start(
        Verb::FsWrite {
            path: target.to_str().unwrap().into(),
            content_length: 1,
            mode: WriteMode::Existing,
            conversation: None,
        },
        Some(maknae_io::open_path_for_delegation(&target).unwrap()),
        Arc::clone(&overflow),
    );
    common::write_frame(&mut client, &body).await.unwrap();
    let refused = next_response(&mut client).await.result;
    assert!(
        !matches!(refused, RespResult::Ok(Payload::MutationAttempt(_))),
        "the mutation pool was not full: {refused:?}"
    );
    assert!(
        overflow.snapshot().iter().any(|r| r
            .outcome
            .reason
            .contains("mutation worker budget exhausted")),
        "the overflow write was not refused by the mutation budget"
    );
    stalled.push((client, task));
    let nobody = nix::unistd::User::from_name("nobody")
        .unwrap()
        .expect("a nobody account");
    assert_ne!(nobody.uid.as_raw(), fx.peer_uid);
    common::write_0640(
        &fx.paths().bindings,
        &format!(
            "schema_version: 1\nbindings:\n  user: [\"{}\", \"nobody\"]\n",
            common::euid_name()
        ),
    );
    fx.peer_uid = nobody.uid.as_raw();
    fx.peer_user = Some(nobody.name);

    let conv = fx.open_conversation().await;
    let records = Records::new(0);
    let resp = fx
        .roundtrip(
            Verb::SessionPrompt {
                conversation: conv.as_str().into(),
                turns: vec![Turn::User {
                    content: vec![text("a")],
                }],
                output_tokens: None,
                choice: Some(common::test_choice()),
            },
            Arc::clone(&records),
            Some("openai"),
            Arc::new(Answer),
        )
        .await
        .expect("a prompt frame");
    match resp.result {
        RespResult::Ok(Payload::PromptReply(r)) => assert_eq!(r.blocks.len(), 1),
        other => panic!(
            "the reply was withheld: {other:?}: {:?}",
            records
                .snapshot()
                .iter()
                .map(|r| r.outcome.reason.clone())
                .collect::<Vec<_>>()
        ),
    }
    let held = fx
        .conversations
        .get(&maknae_proto::ConversationId::parse(&conv).unwrap())
        .unwrap();
    assert_eq!(held.turns, 1);
    assert!(
        held.last_reply.is_some(),
        "the reply bound to the conversation"
    );
    for (client, task) in stalled {
        drop(client);
        task.abort();
    }
    assert_eq!(std::fs::read(&target).unwrap(), b"untouched");
}
