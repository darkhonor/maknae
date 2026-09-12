//! The hermetic OpenAI-compatible stub server #240's scope specifies:
//! "a plain reply, a tool-call reply, a malformed reply, and a 401".
//!
//! HTTP over loopback, no TLS — `ProviderConfig` already permits `http://` to
//! loopback for exactly this, and a TLS stub would test rustls rather than the
//! client. The FIPS posture is a DEPENDENCY PINNING property, asserted in the
//! manifest and by the deputy's provider install, not by a test fixture.
#![cfg(unix)]

use maknae_llm::{CallError, ChatMessage, ChatRequest, ReplyError};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use zeroize::Zeroizing;

/// The deputy installs the FIPS provider at startup; these tests must do the
/// same, because `rustls-no-provider` deliberately leaves the process to choose
/// and `chat_completion` refuses unless the installed one reports `.fips()`.
/// Idempotent across the suite's tests.
fn fips() {
    static ONCE: std::sync::Once = std::sync::Once::new();
    ONCE.call_once(|| {
        maknae_vault::install_default_crypto_provider();
    });
}

/// Serve exactly one request, answering with `status` and `body`. Returns the
/// request bytes the client sent, so a test can assert what went out.
async fn stub(
    status: &'static str,
    body: &'static str,
) -> (String, tokio::task::JoinHandle<String>) {
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = l.local_addr().unwrap();
    let h = tokio::spawn(async move {
        let (mut s, _) = l.accept().await.unwrap();
        let mut buf = vec![0u8; 8192];
        let n = s.read(&mut buf).await.unwrap();
        let seen = String::from_utf8_lossy(&buf[..n]).to_string();
        let resp = format!(
            "HTTP/1.1 {status}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
            body.len()
        );
        s.write_all(resp.as_bytes()).await.unwrap();
        s.flush().await.unwrap();
        seen
    });
    (format!("http://{addr}/v1/chat/completions"), h)
}

fn req<'a>(model: &'a str) -> ChatRequest<'a> {
    ChatRequest {
        model,
        messages: vec![ChatMessage {
            role: "user".into(),
            content: "hi".into(),
        }],
        tools: vec![],
        tool_choice: None,
        stream: false,
    }
}

fn key() -> Zeroizing<String> {
    Zeroizing::new("sk-test-not-a-real-key".to_string())
}

async fn call(url: &str, offered: &[String]) -> Result<maknae_proto::PromptReply, CallError> {
    fips();
    maknae_llm::chat_completion(
        url,
        &key(),
        &req("m"),
        offered,
        Duration::from_secs(5),
        64 * 1024,
    )
    .await
}

#[tokio::test]
async fn a_plain_reply_round_trips_and_the_key_rides_as_a_bearer_header() {
    let (url, h) = stub("200 OK", r#"{"choices":[{"message":{"content":"hello"}}]}"#).await;
    let reply = call(&url, &[]).await.unwrap();
    assert_eq!(reply.blocks.len(), 1);

    let sent = h.await.unwrap();
    assert!(sent.contains("POST /v1/chat/completions"));
    assert!(
        sent.contains("authorization: Bearer sk-test-not-a-real-key")
            || sent.contains("Authorization: Bearer sk-test-not-a-real-key"),
        "the key must ride as a bearer header; sent:\n{sent}"
    );
    // Non-streaming, explicitly.
    assert!(sent.contains("\"stream\":false"), "sent:\n{sent}");
}

#[tokio::test]
async fn a_tool_call_reply_arrives_as_a_proposal() {
    let (url, _h) = stub(
        "200 OK",
        r#"{"choices":[{"message":{"tool_calls":[{"id":"c1","function":{"name":"read_file","arguments":"{}"}}]}}]}"#,
    )
    .await;
    let reply = call(&url, &["read_file".to_string()]).await.unwrap();
    assert_eq!(reply.tool_calls.len(), 1);
    assert_eq!(reply.tool_calls[0].call_id, "c1");
}

#[tokio::test]
async fn a_malformed_reply_is_a_refusal_not_an_empty_success() {
    let (url, _h) = stub("200 OK", "this is not json").await;
    match call(&url, &[]).await {
        Err(CallError::Reply(ReplyError::Malformed(_))) => {}
        other => panic!("expected a malformed refusal, got {other:?}"),
    }
}

/// A 401 is a refusal carrying the CODE and not the body: a provider error body
/// is third-party content and must not be echoed into the trail or the terminal.
#[tokio::test]
async fn a_401_is_refused_and_its_body_is_not_echoed() {
    let (url, _h) = stub(
        "401 Unauthorized",
        r#"{"error":{"message":"SECRET-LOOKING-DIAGNOSTIC"}}"#,
    )
    .await;
    match call(&url, &[]).await {
        Err(e @ CallError::Status(401)) => assert!(
            !e.to_string().contains("SECRET-LOOKING-DIAGNOSTIC"),
            "the provider's error body reached the rendered error: {e}"
        ),
        other => panic!("expected a 401 status refusal, got {other:?}"),
    }
}

/// The body cap is enforced even when the provider's declared length is honest,
/// and the refusal happens rather than the buffer growing.
/// A stub with RAW control of the response head, so a test can lie about
/// `Content-Length` or omit it entirely.
async fn raw_stub(head: String, body: &'static str) -> String {
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = l.local_addr().unwrap();
    tokio::spawn(async move {
        let (mut s, _) = l.accept().await.unwrap();
        let mut buf = vec![0u8; 8192];
        let _ = s.read(&mut buf).await.unwrap();
        s.write_all(head.as_bytes()).await.unwrap();
        s.write_all(body.as_bytes()).await.unwrap();
        s.flush().await.unwrap();
    });
    format!("http://{addr}/v1/chat/completions")
}

/// The DECLARED length is refused on its own, before a byte of body is read.
/// This isolates the `Content-Length` check: the body actually sent is TINY, so
/// the streaming check downstream cannot be what refuses. Exactly the "provider
/// lies about its length" case the code comments claim to defend against.
#[tokio::test]
async fn a_lying_content_length_over_the_cap_is_refused_on_the_declaration() {
    fips();
    let url = raw_stub(
        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 99999\r\nConnection: close\r\n\r\n".to_string(),
        "{}",
    )
    .await;
    match maknae_llm::chat_completion(&url, &key(), &req("m"), &[], Duration::from_secs(5), 1024)
        .await
    {
        Err(CallError::Transport(m)) => assert!(
            m.contains("declared") && m.contains("cap"),
            "expected the DECLARED-length refusal, got: {m}"
        ),
        other => panic!("expected a declared-length refusal, got {other:?}"),
    }
}

/// With NO `Content-Length` at all, the accumulated-body check is the only
/// thing standing between the deputy and an unbounded read. This isolates it.
#[tokio::test]
async fn a_body_with_no_declared_length_is_bounded_as_it_arrives() {
    fips();
    let big: &'static str = Box::leak("a".repeat(8192).into_boxed_str());
    let url = raw_stub(
        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nConnection: close\r\n\r\n"
            .to_string(),
        big,
    )
    .await;
    // Cap of 16, so the FIRST chunk alone exceeds it whatever chunking the
    // transport chooses. With a large cap the first chunk can fit and the
    // refusal then depends on how many chunks arrive — non-deterministic, AND
    // it lets `body.len() + chunk.len()` survive mutation to `*`, since
    // `0 * n == 0` admits the first chunk unconditionally.
    match maknae_llm::chat_completion(&url, &key(), &req("m"), &[], Duration::from_secs(5), 16)
        .await
    {
        Err(CallError::Transport(m)) => assert!(
            m.contains("exceeded") && m.contains("cap"),
            "expected the ACCUMULATED-body refusal, got: {m}"
        ),
        other => panic!("expected an accumulated-body refusal, got {other:?}"),
    }
}

/// Every call refusal renders actionably, and none renders provider content:
/// `Status` carries the CODE alone, because a provider error body is
/// third-party content that must not reach the trail through a Display impl.
#[test]
fn every_call_refusal_renders_actionably() {
    let cases = [
        (
            CallError::Transport("connect refused".into()),
            "provider call failed",
        ),
        (CallError::Status(401), "401"),
        (CallError::Reply(ReplyError::NoChoices), "no choices"),
    ];
    for (e, needle) in cases {
        let r = e.to_string();
        assert!(!r.is_empty(), "{e:?} rendered empty");
        assert!(
            r.contains(needle),
            "{e:?} rendered as {r:?}, expected {needle:?}"
        );
    }
}

/// THE BOUNDARY. A body of EXACTLY the cap must be ACCEPTED by both checks —
/// the discriminator that `>` is not `>=` and not `==`. Every earlier cap test
/// sent a body far above the limit, where all three operators refuse alike.
#[tokio::test]
async fn a_body_of_exactly_the_cap_is_accepted() {
    fips();
    // A valid completion padded to an exact byte length.
    let prefix = r#"{"choices":[{"message":{"content":""#;
    let suffix = r#""}}]}"#;
    let cap = 256usize;
    let pad = cap - prefix.len() - suffix.len();
    let body: &'static str =
        Box::leak(format!("{prefix}{}{suffix}", "a".repeat(pad)).into_boxed_str());
    assert_eq!(body.len(), cap, "the fixture must be exactly the cap");
    let url = raw_stub(
        format!("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {cap}\r\nConnection: close\r\n\r\n"),
        body,
    )
    .await;
    let reply =
        maknae_llm::chat_completion(&url, &key(), &req("m"), &[], Duration::from_secs(5), cap)
            .await
            .expect("a body of exactly the cap must be accepted — the checks are `>`, not `>=`");
    assert_eq!(reply.blocks.len(), 1);
}

#[tokio::test]
async fn an_over_cap_body_is_refused() {
    let big: &'static str = Box::leak(
        format!(
            r#"{{"choices":[{{"message":{{"content":"{}"}}}}]}}"#,
            "a".repeat(4096)
        )
        .into_boxed_str(),
    );
    let (url, _h) = stub("200 OK", big).await;
    fips();
    match maknae_llm::chat_completion(
        &url,
        &key(),
        &req("m"),
        &[],
        Duration::from_secs(5),
        1024, // cap below the body
    )
    .await
    {
        Err(CallError::Transport(m)) => assert!(m.contains("cap"), "{m}"),
        other => panic!("expected an over-cap refusal, got {other:?}"),
    }
}

/// A dead endpoint is a transport refusal, never a hang and never a silent
/// empty reply.
#[tokio::test]
async fn an_unreachable_endpoint_is_a_transport_refusal() {
    // Port 1 on loopback: nothing listens, connect refuses immediately.
    fips();
    match maknae_llm::chat_completion(
        "http://127.0.0.1:1/v1/chat/completions",
        &key(),
        &req("m"),
        &[],
        Duration::from_secs(2),
        64 * 1024,
    )
    .await
    {
        Err(CallError::Transport(_)) => {}
        other => panic!("expected a transport refusal, got {other:?}"),
    }
}
