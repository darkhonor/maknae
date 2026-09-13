//! The FIPS gate, in its own test BINARY.
//!
//! It cannot live beside `stub_server.rs`: installing a rustls crypto provider
//! is process-global and irreversible, so a suite that installs one can never
//! observe the un-installed case again. Cargo gives each integration test file
//! its own binary, which is exactly the isolation this needs — this file
//! installs NOTHING.
#![cfg(unix)]

use maknae_llm::{CallError, ChatMessage, ChatRequest};
use std::time::Duration;
use zeroize::Zeroizing;

/// With no crypto provider installed, a provider call REFUSES rather than
/// proceeding — and refuses before any network is touched, so the endpoint
/// here is deliberately one that would otherwise connect instantly.
///
/// Without this assertion the call would reach `reqwest::Client::builder()`,
/// which PANICS under `rustls-no-provider` when no provider is configured. A
/// panic in the deputy is a crash; a refusal is an auditable answer.
#[tokio::test]
async fn a_call_without_an_installed_fips_provider_is_refused_not_attempted() {
    let req = ChatRequest {
        model: "m",
        messages: vec![ChatMessage {
            role: "user".into(),
            content: "hi".into(),
        }],
        tools: vec![],
        tool_choice: None,
        stream: false,
    };
    let out = maknae_llm::chat_completion(
        "http://127.0.0.1:1/v1/chat/completions",
        &Zeroizing::new("sk-test".to_string()),
        &req,
        &[],
        Duration::from_secs(2),
        1024,
    )
    .await;
    match out {
        Err(CallError::Transport(m)) => assert!(
            m.contains("refusing to call a provider"),
            "expected the FIPS refusal, got: {m}"
        ),
        other => panic!(
            "a call with NO crypto provider installed must be refused by the \
             FIPS gate, not attempted; got {other:?}"
        ),
    }
}
