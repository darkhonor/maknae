//! The wire client: one verb per connection over the post-mint plane, bounded
//! at every stage. Connects to a live daemon, so it is T3; the decisions it
//! feeds are T1 in `maknae_agent::wire`.
use crate::outcome::SentOutcome;
use maknae_proto::{
    class_of, decode_response, encode_request_zeroizing, read_frame_of_class, write_frame,
    FrameCaps, Payload, Request, RespResult, ATTEMPT_REQUEST_MAX, CONTROL_REQUEST_MAX,
    PROTOCOL_VERSION,
};
use maknae_vault::{PlaneClient, PlaneConnector, TrustBundle};
use std::sync::Arc;

fn response_caps(transport: &maknae_config::TransportConfig) -> FrameCaps {
    FrameCaps::responses(transport.prompt_max_bytes)
}

async fn read_reply<S: tokio::io::AsyncRead + Unpin>(
    stream: &mut S,
    class: maknae_proto::FrameClass,
    caps: &FrameCaps,
) -> Result<zeroize::Zeroizing<Vec<u8>>, String> {
    read_frame_of_class(stream, class, caps)
        .await
        .map_err(|e| e.to_string())
}

// Beyond the egress deadline and the reply write: the connect-time session-fact gather
// (5 s), the admission audit (5 s), the request's gather (5 s), the PDP decision (5 s)
// and two audit appends (10 s) are 30 s; 10 s of slack.
const PROMPT_REPLY_MARGIN: std::time::Duration = std::time::Duration::from_secs(40);

// A small frame finishes writing right after the handshake, so both session-fact
// gathers and the admission audit run inside the reply wait.
const SESSION_CHECKS_MS: u64 =
    2 * maknae_config::GROUP_LOOKUP_TIMEOUT_MS + maknae_config::ADMISSION_AUDIT_TIMEOUT_MS;

fn reply_wait(
    verb: &maknae_proto::Verb,
    transport: &maknae_config::TransportConfig,
) -> std::time::Duration {
    let stages = match verb {
        maknae_proto::Verb::AdminContain { .. } | maknae_proto::Verb::AdminRelease { .. } => {
            maknae_config::CONTAINMENT_REPLY_STAGES
        }
        maknae_proto::Verb::AdminBaselineAccept { .. } => {
            maknae_config::BASELINE_ACCEPT_REPLY_STAGES
        }
        _ => return class_wait(class_of(verb), transport),
    };
    class_wait(class_of(verb), transport)
        + std::time::Duration::from_millis(
            stages * maknae_config::BLOCKING_STAGE_TIMEOUT_MS
                + maknae_config::ADMIN_REPLY_MARGIN_MS,
        )
}

fn class_wait(
    class: maknae_proto::FrameClass,
    transport: &maknae_config::TransportConfig,
) -> std::time::Duration {
    match class {
        maknae_proto::FrameClass::Prompt => {
            std::time::Duration::from_millis(
                maknae_config::EGRESS_DEADLINE_MS_MAX + maknae_config::TRANSPORT_TIMEOUT_MS_MAX,
            ) + PROMPT_REPLY_MARGIN
        }
        maknae_proto::FrameClass::Attempt => std::time::Duration::from_millis(
            transport.read_timeout_ms + maknae_config::HOME_RESOLVE_TIMEOUT_MS + SESSION_CHECKS_MS,
        ),
        maknae_proto::FrameClass::Control => {
            std::time::Duration::from_millis(transport.read_timeout_ms + SESSION_CHECKS_MS)
        }
    }
}

/// Instant at which the request frame finished writing.
#[must_use]
#[derive(Clone, Copy, Debug)]
pub struct WriteCompleted(std::time::Instant);

impl WriteCompleted {
    pub fn at(self) -> std::time::Instant {
        self.0
    }

    #[cfg(test)]
    pub fn for_test(at: std::time::Instant) -> Self {
        Self(at)
    }
}

fn request_write_bound(
    class: maknae_proto::FrameClass,
    transport: &maknae_config::TransportConfig,
) -> std::time::Duration {
    match class {
        maknae_proto::FrameClass::Control => {
            std::time::Duration::from_millis(transport.read_timeout_ms)
        }
        maknae_proto::FrameClass::Attempt | maknae_proto::FrameClass::Prompt => {
            maknae_config::content_write_bound(transport)
        }
    }
}

async fn send_request_frame<S: tokio::io::AsyncWrite + Unpin>(
    stream: &mut S,
    class: maknae_proto::FrameClass,
    body: &[u8],
    transport: &maknae_config::TransportConfig,
) -> Result<WriteCompleted, String> {
    let bound = request_write_bound(class, transport);
    match tokio::time::timeout(bound, write_frame(stream, class, body)).await {
        Err(_elapsed) => {
            return Err(match class {
                maknae_proto::FrameClass::Control => format!(
                    "request write to the daemon stalled for {}ms (daemon not reading?)",
                    bound.as_millis()
                ),
                maknae_proto::FrameClass::Attempt | maknae_proto::FrameClass::Prompt => format!(
                    "request write to the daemon stalled for {}ms (read_timeout_ms {}ms + group lookup {}ms + admission audit {}ms); daemon not reading?",
                    bound.as_millis(),
                    transport.read_timeout_ms,
                    maknae_config::GROUP_LOOKUP_TIMEOUT_MS,
                    maknae_config::ADMISSION_AUDIT_TIMEOUT_MS
                ),
            })
        }
        Ok(r) => r.map_err(|e| e.to_string())?,
    }
    Ok(WriteCompleted(tokio::time::Instant::now().into_std()))
}

async fn await_reply<S: tokio::io::AsyncRead + Unpin>(
    stream: &mut S,
    class: maknae_proto::FrameClass,
    wait: std::time::Duration,
    transport: &maknae_config::TransportConfig,
) -> Result<zeroize::Zeroizing<Vec<u8>>, String> {
    match tokio::time::timeout(wait, read_reply(stream, class, &response_caps(transport))).await {
        Err(_elapsed) => Err(match class {
            maknae_proto::FrameClass::Control => format!(
                "no response from daemon within {}ms; it may be slow admitting the connection or re-checking the session (the session-fact lookups at connect and at the request, or the admission audit)",
                wait.as_millis()
            ),
            maknae_proto::FrameClass::Attempt | maknae_proto::FrameClass::Prompt => format!(
                "no response from daemon within {}ms (stalled?)",
                wait.as_millis()
            ),
        }),
        Ok(r) => r,
    }
}

/// Send ONE verb over the post-mint plane and report what came back, printing no RESULT —
/// the caller decides what a terminal (or a model) is told. The arming line and the
/// attempt's stop line go to `diag`, which the caller prints or buffers.
pub async fn send_verb(
    request_verb: maknae_proto::Verb,
    content: Option<maknae_proto::Bytes>,
    check: crate::mutation::WriteCheck,
    transport: &maknae_config::TransportConfig,
    client: &PlaneClient,
    trust: &Arc<TrustBundle>,
    diag: &mut (dyn FnMut(String) + Send),
) -> Result<SentOutcome, String> {
    // Bound the client-side TLS handshake by the configured `handshake_timeout_ms`: a
    // process that accepts the Unix socket but never completes TLS must not hang the CLI
    // forever (it still fails non-zero).
    let connect = tokio::time::timeout(
        std::time::Duration::from_millis(transport.handshake_timeout_ms),
        PlaneConnector::connect(&transport.socket_path, client, trust),
    )
    .await;
    let mut stream = match connect {
        Err(_elapsed) => {
            return Err(format!(
                "TLS handshake to the daemon timed out after {}ms",
                transport.handshake_timeout_ms
            ))
        }
        Ok(r) => r.map_err(|e| e.to_string())?,
    };

    // ADR-0009: for a term that names an object, WE open it — as the subject, for
    // location only — and delegate the descriptor. The OS answers at our own re-open
    // after the grant, and the daemon decides on an object it never resolved a name to.
    //
    // Armed AFTER the handshake, deliberately: the handshake's own writes would
    // otherwise consume the descriptor.
    let prepared = crate::mutation::prepare_checked(request_verb.clone(), content, check);
    let mut armed = true;
    if let Some(prepared) = &prepared {
        if let Some(line) = crate::mutation::arming_diagnostic(prepared) {
            diag(line);
        }
        match (
            prepared.descriptor().map_err(|e| e.to_string())?,
            stream.armer(),
        ) {
            (Some(fd), Some(armer)) => {
                armer.arm(fd);
            }
            _ => armed = false,
        }
    }

    let request = Request {
        task: None,
        protocol_version: PROTOCOL_VERSION,
        verb: prepared
            .as_ref()
            .map(|p| p.request().clone())
            .unwrap_or(request_verb),
    };
    let class = class_of(&request.verb);
    let request_caps = FrameCaps {
        control: CONTROL_REQUEST_MAX,
        attempt: ATTEMPT_REQUEST_MAX,
        prompt: transport.prompt_max_bytes,
    };
    let body =
        encode_request_zeroizing(&request, request_caps.cap(class)).map_err(|e| e.to_string())?;
    let written = send_request_frame(&mut stream, class, &body, transport).await?;

    let resp_body = await_reply(
        &mut stream,
        class,
        reply_wait(&request.verb, transport),
        transport,
    )
    .await?;
    let response = decode_response(&resp_body).map_err(|e| e.to_string())?;

    match response.result {
        RespResult::Ok(Payload::MutationAttempt(grant)) => {
            let prepared =
                prepared.ok_or("protocol error: mutation grant for an ordinary request")?;
            if matches!(prepared.request(), maknae_proto::Verb::Read { .. }) {
                let read = crate::mutation::execute_read(
                    prepared,
                    grant,
                    &mut stream,
                    transport,
                    written,
                    diag,
                )
                .await?;
                return Ok(SentOutcome::ReadDone { read });
            }
            let end =
                crate::mutation::execute(prepared, grant, &mut stream, transport, written, diag)
                    .await?;
            Ok(SentOutcome::WriteDone {
                applied: end.applied,
                stale: end.stale,
                version: end.version,
            })
        }
        RespResult::Ok(payload) => Ok(SentOutcome::Payload(payload)),
        RespResult::Err(e) => Ok(SentOutcome::Refused {
            code: e.code,
            message: e.message,
            armed,
        }),
    }
}

/// Build an `FsWrite` for `content` the caller already holds in memory, bounded by the
/// prompt budget the CLI's `request_from_input` applies to stdin; the request carries only the length.
///
/// The mode is `Existing` — what `maknae write` sends too — because
/// [`crate::mutation::prepare_checked`] overrides it at open time (`CreateExclusive` on a
/// `NotFound`), so BOTH write lanes are reachable from this one constructor.
pub fn write_request(
    path: String,
    content: zeroize::Zeroizing<Vec<u8>>,
    conversation: Option<String>,
    content_max: usize,
) -> Result<(maknae_proto::Verb, maknae_proto::Bytes), String> {
    if content.len() > content_max {
        return Err("content exceeds the configured prompt budget".to_string());
    }
    let request = maknae_proto::Verb::FsWrite {
        conversation,
        path,
        content_length: content.len() as u64,
        mode: maknae_proto::WriteMode::Existing,
    };
    Ok((request, maknae_proto::Bytes::new(content)))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn a_prompt_reply_over_the_control_cap_is_read_with_the_prompt_cap() {
        let reply = maknae_proto::Response {
            protocol_version: PROTOCOL_VERSION,
            result: RespResult::Ok(Payload::PromptReply(maknae_proto::PromptReply {
                reasoning: None,
                blocks: vec![maknae_proto::ContentBlock::Text {
                    text: maknae_proto::SecretText(zeroize::Zeroizing::new("y".repeat(100 * 1024))),
                }],
                tool_calls: vec![],
                usage: None,
            })),
        };
        let body = maknae_proto::encode_response(&reply).unwrap();
        assert!(body.len() > maknae_proto::CONTROL_RESPONSE_MAX);
        let transport = maknae_config::TransportConfig {
            prompt_max_bytes: 1 << 20,
            ..Default::default()
        };
        async fn framed(class: maknae_proto::FrameClass, body: &[u8]) -> Vec<u8> {
            let mut buf = Vec::new();
            write_frame(&mut buf, class, body).await.unwrap();
            buf
        }
        let prompt = maknae_proto::FrameClass::Prompt;
        let bytes = framed(prompt, &body).await;
        let got = read_reply(&mut &bytes[..], prompt, &response_caps(&transport))
            .await
            .unwrap();
        assert_eq!(got.len(), body.len());
        let narrow = FrameCaps {
            prompt: maknae_proto::CONTROL_RESPONSE_MAX,
            ..response_caps(&transport)
        };
        assert!(read_reply(&mut &bytes[..], prompt, &narrow)
            .await
            .unwrap_err()
            .contains("oversize"));
        let control = framed(maknae_proto::FrameClass::Control, &body).await;
        let wide = FrameCaps {
            control: 1 << 20,
            ..response_caps(&transport)
        };
        assert_eq!(
            read_reply(&mut &control[..], prompt, &wide)
                .await
                .unwrap_err(),
            "frame class unexpected: Control, expected Prompt"
        );
    }

    #[test]
    fn write_request_carries_the_conversation_it_is_given() {
        let (v, _) = write_request(
            "/projects/a".into(),
            zeroize::Zeroizing::new(b"x".to_vec()),
            Some("conv-cli".into()),
            4096,
        )
        .unwrap();
        assert!(matches!(
            v,
            maknae_proto::Verb::FsWrite {
                conversation: Some(ref c),
                content_length: 1,
                ..
            } if c == "conv-cli"
        ));
    }

    #[test]
    fn write_request_refuses_content_over_the_frame_budget() {
        let e = write_request(
            "/projects/big".into(),
            zeroize::Zeroizing::new(vec![7u8; 64]),
            None,
            16,
        )
        .expect_err("over-budget content must not encode");
        assert!(
            e.contains("exceeds the configured prompt budget"),
            "unexpected message: {e}"
        );
    }

    fn small_prompt_reply() -> Vec<u8> {
        maknae_proto::encode_response(&maknae_proto::Response {
            protocol_version: PROTOCOL_VERSION,
            result: RespResult::Ok(Payload::PromptReply(maknae_proto::PromptReply {
                reasoning: None,
                blocks: vec![maknae_proto::ContentBlock::Text {
                    text: maknae_proto::SecretText(zeroize::Zeroizing::new("sentinel-413".into())),
                }],
                tool_calls: vec![],
                usage: None,
            })),
        })
        .unwrap()
    }

    async fn reply_after(
        delay: std::time::Duration,
        class: maknae_proto::FrameClass,
        read_timeout_ms: u64,
    ) -> Result<zeroize::Zeroizing<Vec<u8>>, String> {
        let transport = maknae_config::TransportConfig {
            read_timeout_ms,
            ..Default::default()
        };
        let body = small_prompt_reply();
        let (mut cli, mut daemon) = tokio::io::duplex(64 * 1024);
        let writer = tokio::spawn(async move {
            tokio::time::sleep(delay).await;
            let _ = write_frame(&mut daemon, class, &body).await;
            daemon
        });
        let got = await_reply(&mut cli, class, class_wait(class, &transport), &transport).await;
        writer.abort();
        got
    }

    fn kernel_worst_prompt_reply() -> std::time::Duration {
        std::time::Duration::from_millis(
            maknae_config::EGRESS_DEADLINE_MS_MAX + maknae_config::TRANSPORT_TIMEOUT_MS_MAX,
        )
    }

    #[tokio::test(start_paused = true)]
    async fn a_prompt_reply_slower_than_read_timeout_ms_is_received() {
        let got = reply_after(
            std::time::Duration::from_millis(8_270),
            maknae_proto::FrameClass::Prompt,
            5_000,
        )
        .await
        .expect("an 8.27 s model turn must not stop the agent (#413)");
        assert_eq!(&got[..], &small_prompt_reply()[..]);
    }

    #[tokio::test(start_paused = true)]
    async fn a_prompt_reply_just_inside_the_clis_prompt_wait_is_received() {
        let delay =
            kernel_worst_prompt_reply() + PROMPT_REPLY_MARGIN - std::time::Duration::from_millis(1);
        assert!(reply_after(delay, maknae_proto::FrameClass::Prompt, 5_000)
            .await
            .is_ok());
    }

    #[tokio::test(start_paused = true)]
    async fn a_prompt_that_never_answers_still_stops() {
        let delay =
            kernel_worst_prompt_reply() + PROMPT_REPLY_MARGIN + std::time::Duration::from_millis(1);
        let err = reply_after(delay, maknae_proto::FrameClass::Prompt, 5_000)
            .await
            .unwrap_err();
        assert_eq!(err, "no response from daemon within 700000ms (stalled?)");
    }

    const READ_TIMEOUT_MS: u64 = 5_000;
    const TICK: std::time::Duration = std::time::Duration::from_millis(1);

    const DUPLEX: usize = 16 * 1024;

    async fn write_with_reader_delay(
        class: maknae_proto::FrameClass,
        body_len: usize,
        delay: std::time::Duration,
    ) -> Result<WriteCompleted, String> {
        assert!(
            body_len > DUPLEX,
            "the frame must exceed the in-flight buffer"
        );
        let transport = maknae_config::TransportConfig {
            read_timeout_ms: READ_TIMEOUT_MS,
            ..Default::default()
        };
        let body = vec![0u8; body_len];
        let (mut cli, mut daemon) = tokio::io::duplex(DUPLEX);
        let reader = tokio::spawn(async move {
            tokio::time::sleep(delay).await;
            let mut sink = Vec::new();
            let _ = tokio::io::AsyncReadExt::read_to_end(&mut daemon, &mut sink).await;
        });
        let got = send_request_frame(&mut cli, class, &body, &transport).await;
        drop(cli);
        reader.abort();
        got
    }

    fn content_bound() -> std::time::Duration {
        maknae_config::content_write_bound(&maknae_config::TransportConfig {
            read_timeout_ms: READ_TIMEOUT_MS,
            ..Default::default()
        })
    }

    #[tokio::test(start_paused = true)]
    async fn a_large_prompt_write_outlasts_the_daemons_pre_read_work() {
        let _written = write_with_reader_delay(
            maknae_proto::FrameClass::Prompt,
            256 * 1024,
            content_bound() - TICK,
        )
        .await
        .expect("#421: a healthy daemon still in its pre-read work must not fail a prompt write");
    }

    #[tokio::test(start_paused = true)]
    async fn a_large_attempt_write_outlasts_the_daemons_pre_read_work() {
        let _written = write_with_reader_delay(
            maknae_proto::FrameClass::Attempt,
            maknae_proto::ATTEMPT_REQUEST_MAX,
            content_bound() - TICK,
        )
        .await
        .expect("#421: an attempt frame exceeds macOS's socket buffer and must not fail there");
    }

    #[tokio::test(start_paused = true)]
    async fn a_content_write_past_its_bound_names_the_bound_and_its_parts() {
        let bound = content_bound();
        let err =
            write_with_reader_delay(maknae_proto::FrameClass::Prompt, 256 * 1024, bound + TICK)
                .await
                .unwrap_err();
        assert_eq!(
            err,
            format!(
                "request write to the daemon stalled for {}ms (read_timeout_ms {}ms + group lookup {}ms + admission audit {}ms); daemon not reading?",
                bound.as_millis(),
                READ_TIMEOUT_MS,
                maknae_config::GROUP_LOOKUP_TIMEOUT_MS,
                maknae_config::ADMISSION_AUDIT_TIMEOUT_MS
            )
        );
    }

    #[tokio::test(start_paused = true)]
    async fn the_attempt_window_anchor_is_taken_after_the_write_completes() {
        let start = tokio::time::Instant::now();
        let delay = std::time::Duration::from_secs(7);
        let written = write_with_reader_delay(
            maknae_proto::FrameClass::Attempt,
            maknae_proto::ATTEMPT_REQUEST_MAX,
            delay,
        )
        .await
        .unwrap();
        assert!(
            written.at() >= (start + delay).into_std(),
            "the attempt window must not be charged for the daemon's pre-read work on a large frame"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn a_control_write_stall_names_the_read_timeout() {
        const SMALL_DUPLEX: usize = 64;
        let body = vec![0u8; 4 * SMALL_DUPLEX];
        assert!(
            body.len() > SMALL_DUPLEX,
            "the frame must exceed the in-flight buffer"
        );
        let transport = maknae_config::TransportConfig {
            read_timeout_ms: READ_TIMEOUT_MS,
            ..Default::default()
        };
        let (mut cli, _daemon) = tokio::io::duplex(SMALL_DUPLEX);
        let err = send_request_frame(
            &mut cli,
            maknae_proto::FrameClass::Control,
            &body,
            &transport,
        )
        .await
        .unwrap_err();
        assert_eq!(
            err,
            "request write to the daemon stalled for 5000ms (daemon not reading?)"
        );
    }

    #[test]
    fn control_writes_keep_the_read_timeout() {
        let t = maknae_config::TransportConfig {
            read_timeout_ms: READ_TIMEOUT_MS,
            ..Default::default()
        };
        assert_eq!(
            request_write_bound(maknae_proto::FrameClass::Control, &t),
            std::time::Duration::from_millis(READ_TIMEOUT_MS)
        );
        assert_eq!(
            request_write_bound(maknae_proto::FrameClass::Attempt, &t),
            maknae_config::content_write_bound(&t)
        );
        assert_eq!(
            request_write_bound(maknae_proto::FrameClass::Prompt, &t),
            maknae_config::content_write_bound(&t)
        );
    }

    #[tokio::test]
    async fn a_frame_larger_than_the_real_socket_buffers_waits_for_a_slow_reader() {
        use nix::sys::socket::{getsockopt, sockopt};
        let (mut cli, mut daemon) = tokio::net::UnixStream::pair().unwrap();
        let snd = getsockopt(&cli, sockopt::SndBuf).unwrap();
        let rcv = getsockopt(&daemon, sockopt::RcvBuf).unwrap();
        let body = vec![0u8; 2 * (snd + rcv) + 1];
        let transport = maknae_config::TransportConfig {
            read_timeout_ms: 100,
            ..Default::default()
        };
        let reader = tokio::spawn(async move {
            tokio::time::sleep(std::time::Duration::from_millis(300)).await;
            let mut sink = Vec::new();
            let _ = tokio::io::AsyncReadExt::read_to_end(&mut daemon, &mut sink).await;
        });
        let got = send_request_frame(
            &mut cli,
            maknae_proto::FrameClass::Prompt,
            &body,
            &transport,
        )
        .await;
        drop(cli);
        let _ = reader.await;
        let _written = got.expect(
            "#421: a 300 ms pre-read delay is within the bound, whatever the platform's buffers",
        );
    }

    fn stalled(wait_ms: u64) -> String {
        format!("no response from daemon within {wait_ms}ms (stalled?)")
    }

    fn control_stalled(wait_ms: u64) -> String {
        format!("no response from daemon within {wait_ms}ms; it may be slow admitting the connection or re-checking the session (the session-fact lookups at connect and at the request, or the admission audit)")
    }

    #[test]
    fn control_and_attempt_waits_include_the_request_gather() {
        let transport = maknae_config::TransportConfig {
            read_timeout_ms: READ_TIMEOUT_MS,
            ..Default::default()
        };
        let session =
            2 * maknae_config::GROUP_LOOKUP_TIMEOUT_MS + maknae_config::ADMISSION_AUDIT_TIMEOUT_MS;
        assert_eq!(session, 15_000);
        assert_eq!(
            class_wait(maknae_proto::FrameClass::Control, &transport),
            std::time::Duration::from_millis(READ_TIMEOUT_MS + session)
        );
        assert_eq!(
            class_wait(maknae_proto::FrameClass::Attempt, &transport),
            std::time::Duration::from_millis(
                READ_TIMEOUT_MS + maknae_config::HOME_RESOLVE_TIMEOUT_MS + session
            )
        );
        assert_eq!(PROMPT_REPLY_MARGIN, std::time::Duration::from_secs(40));
    }

    #[tokio::test(start_paused = true)]
    async fn control_replies_are_bounded_by_read_timeout_ms_and_the_session_checks() {
        let wait_ms = READ_TIMEOUT_MS + SESSION_CHECKS_MS;
        let wait = std::time::Duration::from_millis(wait_ms);
        let class = maknae_proto::FrameClass::Control;
        assert!(reply_after(wait - TICK, class, READ_TIMEOUT_MS)
            .await
            .is_ok());
        let err = reply_after(wait + TICK, class, READ_TIMEOUT_MS)
            .await
            .unwrap_err();
        assert_eq!(err, control_stalled(wait_ms));
    }

    #[test]
    fn admin_live_edits_wait_out_every_bounded_daemon_stage() {
        let transport = maknae_config::TransportConfig {
            read_timeout_ms: READ_TIMEOUT_MS,
            ..Default::default()
        };
        let stage = maknae_config::BLOCKING_STAGE_TIMEOUT_MS;
        let target = || maknae_proto::ContainTarget::Uid(4242);
        for (verb, stages) in [
            (
                maknae_proto::Verb::AdminContain {
                    target: target(),
                    reason: maknae_proto::contain_reason("r").unwrap().into(),
                },
                maknae_config::CONTAINMENT_REPLY_STAGES,
            ),
            (
                maknae_proto::Verb::AdminRelease { target: target() },
                maknae_config::CONTAINMENT_REPLY_STAGES,
            ),
            (
                maknae_proto::Verb::AdminBaselineAccept { hash: "h".into() },
                maknae_config::BASELINE_ACCEPT_REPLY_STAGES,
            ),
        ] {
            assert!(stages > 0);
            assert!(
                reply_wait(&verb, &transport)
                    >= std::time::Duration::from_millis(
                        READ_TIMEOUT_MS + SESSION_CHECKS_MS + stages * stage
                    ),
                "{verb:?}"
            );
        }
        assert_eq!(
            reply_wait(&maknae_proto::Verb::AdminStatus, &transport),
            std::time::Duration::from_millis(READ_TIMEOUT_MS + SESSION_CHECKS_MS)
        );
    }

    #[tokio::test(start_paused = true)]
    async fn attempt_replies_also_wait_out_the_kernels_home_resolution() {
        let wait_ms = READ_TIMEOUT_MS + maknae_config::HOME_RESOLVE_TIMEOUT_MS + SESSION_CHECKS_MS;
        let wait = std::time::Duration::from_millis(wait_ms);
        let class = maknae_proto::FrameClass::Attempt;
        assert!(reply_after(wait - TICK, class, READ_TIMEOUT_MS)
            .await
            .is_ok());
        let err = reply_after(wait + TICK, class, READ_TIMEOUT_MS)
            .await
            .unwrap_err();
        assert_eq!(err, stalled(wait_ms));
    }

    /// The future `send_verb` returns must be `Send`: `LoopPlane`'s `impl Plane`
    /// (`plane.rs`) returns it behind a trait bound that carries `+ Send`, and a
    /// guard held across an `.await` inside `send_verb` would otherwise only
    /// surface there. Compile-time only — never called, and that is the point:
    /// it checks the FUTURE, not a closure. It lives inside `mod tests` so a
    /// future re-tiering of this file cannot trip
    /// `coverage_check.py`'s column-0-after-the-test-module rule.
    #[allow(dead_code)]
    fn assert_send_verb_future_is_send(
        t: &maknae_config::TransportConfig,
        c: &PlaneClient,
        trust: &Arc<TrustBundle>,
    ) {
        fn s<T: Send>(_: T) {}
        s(send_verb(
            maknae_proto::Verb::Ping,
            None,
            crate::mutation::WriteCheck::Unchecked,
            t,
            c,
            trust,
            &mut |_| {},
        ));
    }
}
