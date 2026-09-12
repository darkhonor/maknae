//! Fulfilling an admitted frame (#240b) — the only place content leaves.
//!
//! Takes an [`Admitted`](crate::handle::Admitted), which has no public
//! constructor: a provider call cannot be made on a frame whose bounds were
//! never checked. The property is in the type, not in a comment.

use crate::handle::Admitted;
use crate::keys::{KeyCache, KeySource};
use maknae_proto::EgressFrameReply;
use std::time::Duration;

/// Why fulfilment failed. Distinct from `handle::Refusal`, which is about
/// ADMISSION — this is about the call.
#[derive(Debug, PartialEq, Eq)]
pub enum FulfilError {
    /// The provider credential could not be obtained. Carries the reason, which
    /// names the PATH and never the value.
    Credential(String),
    /// The call did not produce a usable reply.
    Provider(String),
}

impl std::fmt::Display for FulfilError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            FulfilError::Credential(m) => write!(f, "provider credential unavailable: {m}"),
            FulfilError::Provider(m) => write!(f, "{m}"),
        }
    }
}

/// Bounds on one provider call. Named rather than magic numbers at the call
/// site, so the deputy's limits are one reviewable place.
#[derive(Clone, Copy, Debug)]
pub struct CallBounds {
    pub timeout: Duration,
    pub max_body_bytes: usize,
}

impl Default for CallBounds {
    fn default() -> Self {
        Self {
            timeout: Duration::from_secs(120),
            max_body_bytes: 1024 * 1024,
        }
    }
}

/// Read the credential (first use per destination) and make the call.
///
/// The key is fetched, used as a bearer header inside `maknae-llm`, and
/// dropped: it is `Zeroizing` throughout and is never returned, logged, or
/// rendered — including in either error variant here.
pub async fn fulfil<S: KeySource>(
    admitted: &Admitted<'_>,
    keys: &mut KeyCache<S>,
    offered: &[String],
    bounds: CallBounds,
) -> Result<EgressFrameReply, FulfilError> {
    let req = admitted.request();
    let key = keys
        .get(&req.key_vault_path)
        .map_err(FulfilError::Credential)?
        .clone();

    let messages = req
        .content
        .iter()
        .filter_map(|b| match b {
            maknae_proto::ContentBlock::Text { text } => Some(maknae_llm::ChatMessage {
                role: "user".to_string(),
                content: text.0.to_string(),
            }),
            // Cooky is text-only on the prompt leg; the kernel's own admission
            // refuses anything else long before it reaches here, so a non-text
            // block arriving is a kernel bug and is dropped rather than
            // silently reinterpreted.
            _ => None,
        })
        .collect::<Vec<_>>();

    let chat = maknae_llm::ChatRequest {
        model: &req.model,
        messages,
        tools: vec![],
        tool_choice: None,
        stream: false,
    };

    let reply = maknae_llm::chat_completion(
        &req.endpoint,
        &key,
        &chat,
        offered,
        bounds.timeout,
        bounds.max_body_bytes,
    )
    .await
    .map_err(|e| FulfilError::Provider(e.to_string()))?;

    Ok(EgressFrameReply { reply })
}

#[cfg(test)]
mod tests {
    use super::*;
    use zeroize::Zeroizing;

    struct Denied;
    impl KeySource for Denied {
        fn read(&self, p: &str) -> Result<Zeroizing<String>, String> {
            Err(format!("permission denied on {p}"))
        }
    }

    fn frame() -> maknae_proto::EgressFrameRequest {
        maknae_proto::EgressFrameRequest {
            destination: "provider:openai".into(),
            endpoint: "http://127.0.0.1:1/v1/chat/completions".into(),
            model: "m".into(),
            key_vault_path: "secret/data/maknae/providers/openai".into(),
            conversation: "conv1".into(),
            content: vec![maknae_proto::ContentBlock::Text {
                text: maknae_proto::SecretText(zeroize::Zeroizing::new("hi".into())),
            }],
        }
    }

    fn bounds() -> maknae_config::EgressBounds {
        maknae_config::EgressBounds {
            key_vault_path_prefix: "secret/data/maknae/providers".into(),
        }
    }

    /// No credential, no call. The refusal names the PATH and carries nothing
    /// of the secret — and no provider is contacted at all.
    #[tokio::test]
    async fn an_unavailable_credential_refuses_before_any_call() {
        let f = frame();
        let admitted = crate::handle::decide(&f, &bounds()).unwrap();
        let mut keys = KeyCache::new(Denied);
        let e = fulfil(&admitted, &mut keys, &[], CallBounds::default())
            .await
            .unwrap_err();
        match &e {
            FulfilError::Credential(m) => {
                assert!(m.contains("secret/data/maknae/providers/openai"));
            }
            other => panic!("expected a credential refusal, got {other:?}"),
        }
        assert!(e.to_string().contains("credential unavailable"));
    }

    struct Fixed(&'static str);
    impl KeySource for Fixed {
        fn read(&self, _p: &str) -> Result<Zeroizing<String>, String> {
            Ok(Zeroizing::new(self.0.to_string()))
        }
    }

    /// A loopback provider, answering once. Same shape as `maknae-llm`'s
    /// hermetic suite — `ProviderConfig` permits `http://` to loopback for
    /// exactly this.
    async fn provider(
        status: &'static str,
        body: &'static str,
    ) -> (String, tokio::task::JoinHandle<String>) {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
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

    fn fips() {
        static ONCE: std::sync::Once = std::sync::Once::new();
        ONCE.call_once(|| {
            maknae_vault::install_default_crypto_provider();
        });
    }

    fn frame_to(endpoint: String) -> maknae_proto::EgressFrameRequest {
        let mut f = frame();
        f.endpoint = endpoint;
        f
    }

    /// The whole deputy path, end to end against a loopback provider: admitted
    /// frame -> credential -> call -> reply. The prompt's TEXT must reach the
    /// provider, and the key must ride as a bearer header.
    #[tokio::test]
    async fn an_admitted_frame_reaches_the_provider_and_returns_its_reply() {
        fips();
        let (url, h) = provider("200 OK", r#"{"choices":[{"message":{"content":"pong"}}]}"#).await;
        let f = frame_to(url);
        let admitted = crate::handle::decide(&f, &bounds()).unwrap();
        let mut keys = KeyCache::new(Fixed("sk-test-not-real"));
        let reply = fulfil(&admitted, &mut keys, &[], CallBounds::default())
            .await
            .unwrap();
        assert_eq!(reply.reply.blocks.len(), 1);

        let sent = h.await.unwrap();
        assert!(sent.contains("\"model\":\"m\""), "sent:\n{sent}");
        assert!(
            sent.contains("hi"),
            "the prompt text must reach the provider; sent:\n{sent}"
        );
        assert!(
            sent.to_lowercase()
                .contains("authorization: bearer sk-test-not-real"),
            "the key must ride as a bearer header; sent:\n{sent}"
        );
    }

    /// A provider failure is a NAMED refusal the kernel reads, and the
    /// credential appears nowhere in it.
    #[tokio::test]
    async fn a_provider_failure_is_a_named_refusal_that_never_echoes_the_key() {
        fips();
        let (url, _h) = provider("401 Unauthorized", r#"{"error":"nope"}"#).await;
        let f = frame_to(url);
        let admitted = crate::handle::decide(&f, &bounds()).unwrap();
        let mut keys = KeyCache::new(Fixed("sk-SECRET-VALUE"));
        let e = fulfil(&admitted, &mut keys, &[], CallBounds::default())
            .await
            .unwrap_err();
        match &e {
            FulfilError::Provider(m) => assert!(m.contains("401"), "{m}"),
            other => panic!("expected a provider refusal, got {other:?}"),
        }
        // THE credential assertion #240's scope requires.
        assert!(
            !e.to_string().contains("sk-SECRET-VALUE"),
            "the credential reached a rendered error: {e}"
        );
    }
}
