//! The chat-completions call (#240b) — the I/O half of `wire`.
//!
//! Split from `wire.rs` for the reason this crate's siblings split
//! (`secret_io`/`secret_source`, `kv_io`/`kv`): the MAPPING is a decision worth
//! mutation-testing, and this is a network call that no unit test should stand
//! in for. It is exercised by a hermetic OpenAI-compatible stub server, which
//! is what #240's scope specifies.
//!
//! **TLS provider selection is the process's, never this crate's.** `reqwest`
//! is pinned with `rustls-no-provider` precisely so nothing here installs a
//! default; the deputy's `.fips()`-asserted provider is the one used. Building
//! a client that installed its own would be the failure the pin prevents.

use crate::{to_prompt_reply, ChatRequest, ReplyError};
use std::time::Duration;
use zeroize::Zeroizing;

/// Why a call did not produce a usable reply. Distinct from [`ReplyError`]:
/// that is about the CONTENT of an answer, this is about getting one.
#[derive(Debug)]
pub enum CallError {
    /// The request never completed — connect, TLS, timeout, truncated read.
    Transport(String),
    /// The provider answered with a non-2xx status. The body is NOT included:
    /// a provider error body is untrusted content and can carry anything.
    Status(u16),
    /// The answer arrived and is unusable.
    Reply(ReplyError),
}

impl std::fmt::Display for CallError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CallError::Transport(m) => write!(f, "provider call failed: {m}"),
            CallError::Status(c) => write!(f, "provider answered {c}"),
            CallError::Reply(e) => write!(f, "{e}"),
        }
    }
}

/// One non-streaming chat completion.
///
/// `api_key` is `Zeroizing` and is used only as a bearer header — it is never
/// logged, never rendered by `Debug`, and never returned in an error. The
/// `Status` variant deliberately carries the code and NOT the body, because a
/// provider error body is third-party content.
pub async fn chat_completion(
    endpoint: &str,
    api_key: &Zeroizing<String>,
    req: &ChatRequest<'_>,
    offered: &[String],
    timeout: Duration,
    max_body_bytes: usize,
) -> Result<maknae_proto::PromptReply, CallError> {
    // THE FIPS GATE, and it is not decorative. `rustls-no-provider` means
    // reqwest installs NO crypto provider of its own — building a client with
    // none configured panics, which is exactly the pin's purpose: the process
    // must have installed one deliberately. Asserting `.fips()` here turns
    // "the deputy probably installed the FIPS provider" into a refusal the
    // caller sees, at the only place that matters — immediately before a
    // credential rides a TLS connection.
    maknae_vault::assert_fips_provider()
        .map_err(|e| CallError::Transport(format!("refusing to call a provider: {e}")))?;

    let client = reqwest::Client::builder()
        .timeout(timeout)
        // No redirect following: a redirect is a new destination, and the
        // destination is what the PDP decided on. Following one silently would
        // move the egress to somewhere the verdict never covered.
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .map_err(|e| CallError::Transport(e.to_string()))?;

    let resp = client
        .post(endpoint)
        .bearer_auth(api_key.as_str())
        .json(req)
        .send()
        .await
        .map_err(|e| CallError::Transport(e.to_string()))?;

    let status = resp.status();
    if !status.is_success() {
        return Err(CallError::Status(status.as_u16()));
    }

    // BOUNDED before it is a String. `Content-Length` is the provider's claim,
    // so it is checked first as a cheap refusal, and the accumulated body is
    // checked again as it arrives — a provider that lies about its length, or
    // sends none, must not be able to grow this without limit.
    if let Some(len) = resp.content_length() {
        if len as usize > max_body_bytes {
            return Err(CallError::Transport(format!(
                "provider declared a {len}-byte body over the {max_body_bytes}-byte cap"
            )));
        }
    }
    let mut resp = resp;
    let mut body: Vec<u8> = Vec::new();
    while let Some(chunk) = resp
        .chunk()
        .await
        .map_err(|e| CallError::Transport(e.to_string()))?
    {
        body.extend_from_slice(&chunk);
        // Checked on the ACCUMULATED length, after extending — deliberately not
        // `body.len() + chunk.len() > cap` before it. That form carries an
        // addition whose mutation to `*` is unkillable: on the first chunk
        // `body.len()` is 0, so `0 * n == 0` admits unconditionally, and
        // whether a later chunk catches it depends on how the transport happens
        // to split the body. This form has no arithmetic to get wrong, and
        // overshoots by at most one chunk before refusing.
        if body.len() > max_body_bytes {
            return Err(CallError::Transport(format!(
                "provider body exceeded the {max_body_bytes}-byte cap"
            )));
        }
    }

    let parsed = serde_json::from_slice(&body)
        .map_err(|e| CallError::Reply(ReplyError::Malformed(e.to_string())))?;
    to_prompt_reply(parsed, offered).map_err(CallError::Reply)
}
