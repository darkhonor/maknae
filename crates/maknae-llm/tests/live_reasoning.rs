#![cfg(unix)]

use maknae_llm::{ChatMessage, ChatRequest, ReplyError};
use std::time::Duration;
use zeroize::Zeroizing;

struct Live {
    url: String,
    key: Zeroizing<String>,
    model: String,
}

fn live() -> Live {
    maknae_crypto::init().unwrap();
    let var = |k: &str| std::env::var(k).unwrap_or_else(|_| panic!("set {k}"));
    let key = std::fs::read_to_string(var("LIVE_LLM_KEY_FILE")).expect("read the key file");
    Live {
        url: format!("{}/v1/chat/completions", var("LIVE_LLM_BASE")),
        key: Zeroizing::new(key.trim().to_string()),
        model: var("LIVE_LLM_MODEL"),
    }
}

fn text(s: &str) -> maknae_proto::SecretText {
    maknae_proto::SecretText(Zeroizing::new(s.into()))
}

async fn call(
    l: &Live,
    messages: Vec<ChatMessage>,
    max_tokens: u64,
) -> Result<maknae_llm::Completion, maknae_llm::CallError> {
    let req = ChatRequest {
        model: &l.model,
        messages,
        tools: vec![],
        tool_choice: None,
        reasoning_effort: None,
        max_completion_tokens: None,
        max_tokens: Some(max_tokens),
        stream: false,
    };
    maknae_llm::chat_completion(
        &l.url,
        &l.key,
        &req,
        &[],
        Duration::from_secs(120),
        1024 * 1024,
    )
    .await
}

#[tokio::test]
#[ignore = "needs a live OpenAI-compatible reasoning server (operator-gated)"]
async fn a_live_reasoning_reply_is_delivered_with_its_reasoning() {
    let l = live();
    let c = call(
        &l,
        vec![ChatMessage::user(text(
            "What is 17*23? Answer with just the number.",
        ))],
        2000,
    )
    .await
    .expect("a usable reply");
    let answer = match &c.reply.blocks[0] {
        maknae_proto::ContentBlock::Text { text } => text.0.trim().to_string(),
        other => panic!("{other:?}"),
    };
    println!(
        "answer={answer:?} reasoning_bytes={:?}",
        c.reply.reasoning.as_ref().map(|r| r.0.len())
    );
    assert_eq!(answer, "391");
    assert!(c.reply.reasoning.is_some());
}

#[tokio::test]
#[ignore = "needs a live OpenAI-compatible reasoning server (operator-gated)"]
async fn a_live_reply_cut_while_reasoning_is_token_limit() {
    let l = live();
    let e = call(
        &l,
        vec![ChatMessage::user(text(
            "What is 17*23? Answer with just the number.",
        ))],
        10,
    )
    .await
    .expect_err("a refusal");
    println!("{e}");
    assert!(matches!(
        e,
        maknae_llm::CallError::Reply {
            error: ReplyError::TokenLimit,
            ..
        }
    ));
}

#[tokio::test]
#[ignore = "needs a live OpenAI-compatible reasoning server (operator-gated)"]
async fn a_live_server_accepts_resent_reasoning_content() {
    let l = live();
    let q = text("Name a colour. Reply with one word.");
    let first = call(&l, vec![ChatMessage::user(q.clone())], 2000)
        .await
        .expect("first turn");
    let answer = match &first.reply.blocks[0] {
        maknae_proto::ContentBlock::Text { text } => text.clone(),
        other => panic!("{other:?}"),
    };
    let follow = text("Now name another. Reply with one word.");
    let turn = |reasoning: Option<maknae_proto::SecretText>| {
        let mut a = ChatMessage::user(answer.clone());
        a.role = "assistant".into();
        a.reasoning_content = reasoning;
        vec![
            ChatMessage::user(q.clone()),
            a,
            ChatMessage::user(follow.clone()),
        ]
    };
    let accepted = |r: Result<maknae_llm::Completion, maknae_llm::CallError>| match r {
        Ok(c) => c.reply.usage.map(|u| u.prompt_tokens),
        Err(maknae_llm::CallError::Reply { error: e, .. }) => {
            println!("server accepted the request; the reply was refused: {e}");
            None
        }
        Err(e) => panic!("the server did not accept the request: {e}"),
    };
    let without = accepted(call(&l, turn(None), 2000).await);
    let with = accepted(call(&l, turn(first.reply.reasoning.clone()), 2000).await);
    println!(
        "prompt_tokens without={without:?} with={with:?} (the server's chat template decides whether reasoning reaches the model)"
    );
}
