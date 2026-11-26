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
    FrameCaps::responses(maknae_proto::prompt_response_cap(
        transport.prompt_max_bytes,
    ))
}

/// A task's or the board's answer is sized by the kernel's current text bound, which the
/// agent knows only as enrollment copied it.
fn reply_caps(verb: &maknae_proto::Verb, transport: &maknae_config::TransportConfig) -> FrameCaps {
    match verb {
        maknae_proto::Verb::TaskClaim { .. }
        | maknae_proto::Verb::TaskReport { .. }
        | maknae_proto::Verb::TaskSubmit { .. }
        | maknae_proto::Verb::TaskAdd { .. }
        | maknae_proto::Verb::TaskStatus { .. }
        | maknae_proto::Verb::TaskList { .. }
        | maknae_proto::Verb::TaskStop { .. }
        | maknae_proto::Verb::TaskDrop { .. }
        | maknae_proto::Verb::TaskCollect { .. }
        | maknae_proto::Verb::AgentList { .. }
        | maknae_proto::Verb::BoardPost { .. }
        | maknae_proto::Verb::BoardRead { .. }
        | maknae_proto::Verb::BoardList { .. } => FrameCaps::responses(
            maknae_proto::prompt_response_cap(maknae_config::PROMPT_MAX_CEILING),
        ),
        _ => response_caps(transport),
    }
}

/// A connected plane stream. `arm` delegates `fd` with the next write, and says whether it could.
pub trait Wire: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send {
    fn arm(&self, fd: std::os::fd::OwnedFd) -> bool;
}

impl Wire for maknae_vault::AuthenticatedStream {
    fn arm(&self, fd: std::os::fd::OwnedFd) -> bool {
        match self.armer() {
            Some(armer) => {
                armer.arm(fd);
                true
            }
            None => false,
        }
    }
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
    let counted = if maknae_proto::carries_board_unseen(verb) {
        maknae_config::BOARD_UNSEEN_REPLY_STAGES * maknae_config::BLOCKING_STAGE_TIMEOUT_MS
    } else {
        0
    };
    verb_wait(verb, transport) + std::time::Duration::from_millis(counted)
}

fn verb_wait(
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
        maknae_proto::Verb::AdminHeldList { .. } | maknae_proto::Verb::AdminHeldRelease { .. } => {
            maknae_config::HELD_REPLY_STAGES
        }
        maknae_proto::Verb::TaskSubmit { .. } | maknae_proto::Verb::TaskAdd { .. } => {
            return class_wait(maknae_proto::FrameClass::Control, transport)
                + std::time::Duration::from_millis(maknae_config::task_reach_reply_ms(
                    maknae_config::REACH_DEADLINE_MS_MAX,
                ))
        }
        maknae_proto::Verb::TaskClaim { .. }
        | maknae_proto::Verb::TaskReport { .. }
        | maknae_proto::Verb::TaskStatus { .. }
        | maknae_proto::Verb::TaskList { .. }
        | maknae_proto::Verb::TaskStop { .. }
        | maknae_proto::Verb::TaskDrop { .. }
        | maknae_proto::Verb::TaskCollect { .. } => {
            return class_wait(maknae_proto::FrameClass::Control, transport)
        }
        maknae_proto::Verb::AgentList { .. } => {
            return class_wait(maknae_proto::FrameClass::Control, transport)
                + std::time::Duration::from_millis(
                    maknae_config::AGENT_LIST_REPLY_STAGES
                        * maknae_config::BLOCKING_STAGE_TIMEOUT_MS,
                )
        }
        _ => return class_wait(class_of(verb), transport),
    };
    class_wait(class_of(verb), transport)
        + std::time::Duration::from_millis(
            stages * maknae_config::BLOCKING_STAGE_TIMEOUT_MS
                + maknae_config::ADMIN_REPLY_MARGIN_MS,
        )
}

fn request_caps(
    verb: &maknae_proto::Verb,
    transport: &maknae_config::TransportConfig,
) -> FrameCaps {
    let prompt = match maknae_proto::takes_task_request_cap(verb) {
        true => maknae_proto::task_request_cap(transport.prompt_max_bytes),
        false => maknae_proto::prompt_request_cap(transport.prompt_max_bytes),
    };
    FrameCaps {
        control: CONTROL_REQUEST_MAX,
        attempt: ATTEMPT_REQUEST_MAX,
        prompt,
    }
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
    caps: &FrameCaps,
) -> Result<zeroize::Zeroizing<Vec<u8>>, String> {
    match tokio::time::timeout(wait, read_reply(stream, class, caps)).await {
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
    send_via(
        PlaneConnector::connect(&transport.socket_path, client, trust),
        None,
        request_verb,
        content,
        check,
        transport,
        diag,
    )
    .await
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) struct SendFailure {
    pub(crate) after_write: bool,
    /// A complete reply frame arrived and did not decode.
    pub(crate) answered: bool,
    pub(crate) why: String,
}

/// [`send_verb`] over a stream `connect` opens, for this one verb, with `task` cited on the request.
pub(crate) async fn send_via<S: Wire>(
    connect: impl std::future::Future<Output = Result<S, maknae_vault::VaultError>>,
    task: Option<maknae_proto::TaskId>,
    request_verb: maknae_proto::Verb,
    content: Option<maknae_proto::Bytes>,
    check: crate::mutation::WriteCheck,
    transport: &maknae_config::TransportConfig,
    diag: &mut (dyn FnMut(String) + Send),
) -> Result<SentOutcome, String> {
    send_located(connect, task, request_verb, content, check, transport, diag)
        .await
        .map_err(|f| f.why)
}

/// What one verb came back as, with the stamps the reply carried.
#[derive(Debug)]
pub(crate) struct Sent {
    pub(crate) outcome: SentOutcome,
    pub(crate) catalog_digest: Option<maknae_proto::CatalogDigest>,
    pub(crate) board_unseen: Option<maknae_proto::BoardUnseen>,
}

/// [`send_via`], with the failure saying whether it came after the request was written.
pub(crate) async fn send_located<S: Wire>(
    connect: impl std::future::Future<Output = Result<S, maknae_vault::VaultError>>,
    task: Option<maknae_proto::TaskId>,
    request_verb: maknae_proto::Verb,
    content: Option<maknae_proto::Bytes>,
    check: crate::mutation::WriteCheck,
    transport: &maknae_config::TransportConfig,
    diag: &mut (dyn FnMut(String) + Send),
) -> Result<SentOutcome, SendFailure> {
    send_stamped(connect, task, request_verb, content, check, transport, diag)
        .await
        .map(|sent| sent.outcome)
}

/// [`send_located`], keeping the stamps of the reply.
pub(crate) async fn send_stamped<S: Wire>(
    connect: impl std::future::Future<Output = Result<S, maknae_vault::VaultError>>,
    task: Option<maknae_proto::TaskId>,
    request_verb: maknae_proto::Verb,
    content: Option<maknae_proto::Bytes>,
    check: crate::mutation::WriteCheck,
    transport: &maknae_config::TransportConfig,
    diag: &mut (dyn FnMut(String) + Send),
) -> Result<Sent, SendFailure> {
    let mutating = mutates(&request_verb);
    match exchange(connect, task, request_verb, content, check, transport, diag).await {
        Ok(sent) => Ok(sent),
        Err(failed) => settle_located(mutating, Err(failed)).map(|outcome| Sent {
            outcome,
            catalog_digest: None,
            board_unseen: None,
        }),
    }
}

#[cfg(test)]
fn settle(mutating: bool, sent: Result<SentOutcome, Failed>) -> Result<SentOutcome, String> {
    settle_located(mutating, sent).map_err(|f| f.why)
}

fn settle_located(
    mutating: bool,
    sent: Result<SentOutcome, Failed>,
) -> Result<SentOutcome, SendFailure> {
    let failure = |after_write, answered, why| SendFailure {
        after_write,
        answered,
        why,
    };
    match sent {
        Ok(sent) => Ok(sent),
        Err(Failed::Unsent(why)) => {
            before_grant(mutating, why).map_err(|why| failure(false, false, why))
        }
        Err(Failed::BeforeGrant(why)) => {
            before_grant(mutating, why).map_err(|why| failure(true, false, why))
        }
        Err(Failed::Malformed(why)) => {
            before_grant(mutating, why).map_err(|why| failure(true, true, why))
        }
        Err(Failed::After(why)) => Err(failure(true, false, why)),
    }
}

enum Failed {
    /// No request frame had been written: nothing the kernel could have acted on.
    Unsent(String),
    BeforeGrant(String),
    /// A complete reply frame that is not a response this client can read.
    Malformed(String),
    After(String),
}

fn mutates(verb: &maknae_proto::Verb) -> bool {
    matches!(
        verb,
        maknae_proto::Verb::FsWrite { .. }
            | maknae_proto::Verb::FsDelete { .. }
            | maknae_proto::Verb::FsMkdir { .. }
    )
}

/// A mutation that failed before its grant arrived had no effect (ADR-0034 decision 7).
fn before_grant(mutating: bool, why: String) -> Result<SentOutcome, String> {
    if mutating {
        Ok(SentOutcome::NotAttempted { why })
    } else {
        Err(why)
    }
}

async fn exchange<S: Wire>(
    connect: impl std::future::Future<Output = Result<S, maknae_vault::VaultError>>,
    task: Option<maknae_proto::TaskId>,
    request_verb: maknae_proto::Verb,
    content: Option<maknae_proto::Bytes>,
    check: crate::mutation::WriteCheck,
    transport: &maknae_config::TransportConfig,
    diag: &mut (dyn FnMut(String) + Send),
) -> Result<Sent, Failed> {
    let mutating = mutates(&request_verb);
    let before = Failed::BeforeGrant;
    let unstamped = |outcome| Sent {
        outcome,
        catalog_digest: None,
        board_unseen: None,
    };
    let unsent = Failed::Unsent;
    // Bound the client-side TLS handshake by the configured `handshake_timeout_ms`: a
    // process that accepts the Unix socket but never completes TLS must not hang the CLI
    // forever (it still fails non-zero).
    let connect = tokio::time::timeout(
        std::time::Duration::from_millis(transport.handshake_timeout_ms),
        connect,
    )
    .await;
    let mut stream = match connect {
        Err(_elapsed) => {
            return Err(unsent(format!(
                "TLS handshake to the daemon timed out after {}ms",
                transport.handshake_timeout_ms
            )))
        }
        Ok(r) => r.map_err(|e| unsent(e.to_string()))?,
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
        armed = match prepared.descriptor().map_err(|e| unsent(e.to_string()))? {
            Some(fd) => stream.arm(fd),
            None => false,
        };
    }

    let request = Request {
        task,
        protocol_version: PROTOCOL_VERSION,
        verb: prepared
            .as_ref()
            .map(|p| p.request().clone())
            .unwrap_or(request_verb),
    };
    let class = class_of(&request.verb);
    let body =
        encode_request_zeroizing(&request, request_caps(&request.verb, transport).cap(class))
            .map_err(|e| unsent(e.to_string()))?;
    let written = send_request_frame(&mut stream, class, &body, transport)
        .await
        .map_err(before)?;

    let resp_body = await_reply(
        &mut stream,
        class,
        reply_wait(&request.verb, transport),
        &reply_caps(&request.verb, transport),
    )
    .await
    .map_err(before)?;
    let response = decode_response(&resp_body).map_err(|e| Failed::Malformed(e.to_string()))?;

    let (catalog_digest, board_unseen) = (response.catalog_digest, response.board_unseen);
    let (prepared, grant) = match first_answer(mutating, prepared, response.result, armed)? {
        FirstAnswer::Done(outcome) => {
            return Ok(Sent {
                outcome,
                catalog_digest,
                board_unseen,
            })
        }
        FirstAnswer::Grant(prepared, grant) => (prepared, grant),
    };
    if matches!(prepared.request(), maknae_proto::Verb::FsList { .. }) {
        return Ok(unstamped(
            match crate::mutation::execute_list(
                prepared,
                grant,
                &mut stream,
                transport,
                written,
                diag,
            )
            .await
            .map_err(Failed::After)?
            {
                Ok(page) => SentOutcome::Payload(Payload::ListGrant(page)),
                Err(refused) => SentOutcome::Refused {
                    code: refused.code,
                    message: refused.message,
                    armed: true,
                },
            },
        ));
    }
    if matches!(prepared.request(), maknae_proto::Verb::Read { .. }) {
        let read =
            crate::mutation::execute_read(prepared, grant, &mut stream, transport, written, diag)
                .await
                .map_err(Failed::After)?;
        return Ok(unstamped(SentOutcome::ReadDone { read }));
    }
    let end = crate::mutation::execute(prepared, grant, &mut stream, transport, written, diag)
        .await
        .map_err(Failed::After)?;
    Ok(unstamped(SentOutcome::WriteDone {
        applied: end.applied,
        stale: end.stale,
        withheld: end.withheld,
        version: end.version,
    }))
}

enum FirstAnswer {
    Grant(
        crate::mutation::PreparedMutation,
        maknae_proto::MutationGrant,
    ),
    Done(SentOutcome),
}

fn first_answer(
    mutating: bool,
    prepared: Option<crate::mutation::PreparedMutation>,
    result: RespResult,
    armed: bool,
) -> Result<FirstAnswer, Failed> {
    match (result, prepared) {
        (RespResult::Ok(Payload::MutationAttempt(_)), Some(prepared))
            if matches!(prepared.request(), maknae_proto::Verb::FsStat { .. }) =>
        {
            Err(Failed::BeforeGrant(
                "protocol error: an attempt grant for fs.stat".into(),
            ))
        }
        (RespResult::Ok(Payload::MutationAttempt(grant)), Some(prepared)) => {
            Ok(FirstAnswer::Grant(prepared, grant))
        }
        (RespResult::Ok(Payload::MutationAttempt(_)), None) => Err(Failed::BeforeGrant(
            "protocol error: mutation grant for an ordinary request".into(),
        )),
        (RespResult::Ok(payload), _) if mutating => Err(Failed::BeforeGrant(format!(
            "protocol error: unexpected reply to a mutation: {payload:?}"
        ))),
        (RespResult::Ok(payload), _) => Ok(FirstAnswer::Done(SentOutcome::Payload(payload))),
        (RespResult::Err(e), _) => Ok(FirstAnswer::Done(SentOutcome::Refused {
            code: e.code,
            message: e.message,
            armed,
        })),
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
        let reply = maknae_proto::Response::new(
            PROTOCOL_VERSION,
            RespResult::Ok(Payload::PromptReply(maknae_proto::PromptReply {
                reasoning: None,
                blocks: vec![maknae_proto::ContentBlock::Text {
                    text: maknae_proto::SecretText::from(zeroize::Zeroizing::new(
                        "y".repeat(100 * 1024),
                    )),
                }],
                tool_calls: vec![],
                usage: None,
            })),
            None,
        );
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
    fn task_verbs_wait_the_call_timeout_and_read_at_the_ceiling() {
        let transport = maknae_config::TransportConfig {
            read_timeout_ms: 7_000,
            prompt_max_bytes: maknae_config::PROMPT_MAX_BYTES_FLOOR,
            ..Default::default()
        };
        let control = class_wait(maknae_proto::FrameClass::Control, &transport);
        let ceiling = FrameCaps::responses(maknae_proto::prompt_response_cap(
            maknae_config::PROMPT_MAX_CEILING,
        ));
        for verb in [
            maknae_proto::Verb::TaskClaim {
                seen_follow_ups: None,
            },
            maknae_proto::Verb::TaskClaim {
                seen_follow_ups: Some(3),
            },
            maknae_proto::Verb::TaskReport {
                text: maknae_proto::SecretText::from(zeroize::Zeroizing::new("r".into())),
                seen_follow_ups: None,
            },
        ] {
            assert_eq!(reply_wait(&verb, &transport), control, "{verb:?}");
            assert_eq!(reply_caps(&verb, &transport).prompt, ceiling.prompt);
        }
        let prompt = maknae_proto::Verb::SessionPrompt {
            conversation: "c".into(),
            turns: vec![],
            output_tokens: None,
            choice: None,
        };
        assert_eq!(
            reply_wait(&prompt, &transport),
            class_wait(maknae_proto::FrameClass::Prompt, &transport)
        );
        assert_eq!(
            reply_caps(&prompt, &transport).prompt,
            response_caps(&transport).prompt
        );
    }

    fn tasker_verbs() -> Vec<maknae_proto::Verb> {
        use maknae_proto::{Ask, Labels, SecretText, TaskId, TaskRef, TaskSubmission, Verb};
        let task = TaskRef::from_id(&TaskId([3; 16]));
        let text = || SecretText::from(zeroize::Zeroizing::new("t".into()));
        vec![
            Verb::TaskSubmit {
                task: TaskSubmission {
                    schema: maknae_proto::TASK_SCHEMA.into(),
                    version: maknae_proto::TASK_VERSION,
                    agent: "hobi".into(),
                    ask: Ask::Prompt { prompt: text() },
                    labels: Labels {},
                    bindings: vec![],
                },
                forge_tokens: maknae_proto::ForgeTokens::default(),
            },
            Verb::TaskAdd {
                task: task.clone(),
                text: text(),
                bindings: vec![],
                forge_tokens: maknae_proto::ForgeTokens::default(),
            },
            Verb::TaskStatus { task: task.clone() },
            Verb::TaskList {
                agent: "hobi".into(),
                after: None,
            },
            Verb::TaskStop { task: task.clone() },
            Verb::TaskDrop { task },
            Verb::TaskCollect {
                agent: "hobi".into(),
                after: None,
                task: None,
            },
            Verb::TaskClaim {
                seen_follow_ups: None,
            },
            Verb::TaskReport {
                text: text(),
                seen_follow_ups: None,
            },
            Verb::AgentList { after: None },
        ]
    }

    #[test]
    fn every_tasker_verb_waits_the_control_reply() {
        let transport = maknae_config::TransportConfig::default();
        let control = class_wait(maknae_proto::FrameClass::Control, &transport);
        let counted = std::time::Duration::from_millis(
            maknae_config::BOARD_UNSEEN_REPLY_STAGES * maknae_config::BLOCKING_STAGE_TIMEOUT_MS,
        );
        for verb in tasker_verbs() {
            if matches!(
                verb,
                maknae_proto::Verb::AgentList { .. }
                    | maknae_proto::Verb::TaskSubmit { .. }
                    | maknae_proto::Verb::TaskAdd { .. }
            ) {
                assert!(reply_wait(&verb, &transport) > control);
            } else if matches!(
                verb,
                maknae_proto::Verb::TaskStatus { .. }
                    | maknae_proto::Verb::TaskStop { .. }
                    | maknae_proto::Verb::TaskDrop { .. }
            ) {
                assert_eq!(reply_wait(&verb, &transport), control + counted, "{verb:?}");
            } else {
                assert_eq!(reply_wait(&verb, &transport), control, "{verb:?}");
            }
        }
    }

    #[test]
    fn a_counted_verb_waits_one_stage_longer() {
        let transport = maknae_config::TransportConfig {
            read_timeout_ms: READ_TIMEOUT_MS,
            ..Default::default()
        };
        let stage = std::time::Duration::from_millis(
            maknae_config::BOARD_UNSEEN_REPLY_STAGES * maknae_config::BLOCKING_STAGE_TIMEOUT_MS,
        );
        let task = maknae_proto::TaskRef::from_id(&maknae_proto::TaskId([3; 16]));
        let list = reply_wait(
            &maknae_proto::Verb::TaskList {
                agent: "hobi".into(),
                after: None,
            },
            &transport,
        );
        assert_eq!(
            reply_wait(&maknae_proto::Verb::TaskStatus { task }, &transport),
            list + stage
        );
        let session = maknae_proto::Verb::SessionNew {
            cwd: "/p".into(),
            sensitive: vec![],
        };
        assert_eq!(
            reply_wait(&session, &transport),
            class_wait(maknae_proto::FrameClass::Attempt, &transport) + stage
        );
    }

    #[test]
    fn the_reply_wait_for_submit_covers_the_reach_ceiling() {
        let transport = maknae_config::TransportConfig {
            read_timeout_ms: READ_TIMEOUT_MS,
            ..Default::default()
        };
        let control = class_wait(maknae_proto::FrameClass::Control, &transport);
        let reach = std::time::Duration::from_millis(maknae_config::task_reach_reply_ms(
            maknae_config::REACH_DEADLINE_MS_MAX,
        ));
        assert_eq!(reach, std::time::Duration::from_secs(460));
        let counted = std::time::Duration::from_millis(
            maknae_config::BOARD_UNSEEN_REPLY_STAGES * maknae_config::BLOCKING_STAGE_TIMEOUT_MS,
        );
        let mut reached = 0;
        for verb in tasker_verbs() {
            if matches!(
                verb,
                maknae_proto::Verb::TaskSubmit { .. } | maknae_proto::Verb::TaskAdd { .. }
            ) {
                assert_eq!(
                    reply_wait(&verb, &transport),
                    control + reach + counted,
                    "{verb:?}"
                );
                reached += 1;
            }
        }
        assert_eq!(reached, 2);
    }

    #[test]
    fn a_task_verb_is_encoded_under_the_task_request_cap() {
        let transport = maknae_config::TransportConfig {
            prompt_max_bytes: 4096,
            ..Default::default()
        };
        let mut tasked = 0;
        for verb in tasker_verbs() {
            let task = maknae_proto::takes_task_request_cap(&verb);
            let want = match task {
                true => maknae_proto::task_request_cap(4096),
                false => maknae_proto::prompt_request_cap(4096),
            };
            assert_eq!(request_caps(&verb, &transport).prompt, want, "{verb:?}");
            tasked += usize::from(task);
        }
        assert_eq!(tasked, 2);
    }

    #[test]
    fn the_board_verbs_are_read_at_the_ceiling_cap() {
        let transport = maknae_config::TransportConfig {
            prompt_max_bytes: 4096,
            ..Default::default()
        };
        let ceiling = maknae_proto::prompt_response_cap(maknae_config::PROMPT_MAX_CEILING);
        for verb in [
            maknae_proto::Verb::BoardPost {
                post: maknae_proto::PostDraft {
                    kind: maknae_proto::PostKind::Note,
                    to: maknae_proto::Addressee::Board,
                    in_reply_to: None,
                    body: maknae_proto::SecretText::from(zeroize::Zeroizing::new("b".into())),
                    attachments: vec![],
                },
            },
            maknae_proto::Verb::BoardRead { seen_through: None },
            maknae_proto::Verb::BoardList {
                before: None,
                new: false,
            },
        ] {
            assert_eq!(reply_caps(&verb, &transport).prompt, ceiling, "{verb:?}");
        }
    }

    #[test]
    fn every_tasker_verb_is_read_at_the_ceiling_cap() {
        let transport = maknae_config::TransportConfig {
            prompt_max_bytes: 4096,
            ..Default::default()
        };
        let ceiling = maknae_proto::prompt_response_cap(maknae_config::PROMPT_MAX_CEILING);
        for verb in tasker_verbs() {
            assert_eq!(reply_caps(&verb, &transport).prompt, ceiling, "{verb:?}");
        }
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
        maknae_proto::encode_response(&maknae_proto::Response::new(
            PROTOCOL_VERSION,
            RespResult::Ok(Payload::PromptReply(maknae_proto::PromptReply {
                reasoning: None,
                blocks: vec![maknae_proto::ContentBlock::Text {
                    text: maknae_proto::SecretText::from(zeroize::Zeroizing::new(
                        "sentinel-413".into(),
                    )),
                }],
                tool_calls: vec![],
                usage: None,
            })),
            None,
        ))
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
        let got = await_reply(
            &mut cli,
            class,
            class_wait(class, &transport),
            &response_caps(&transport),
        )
        .await;
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
    fn a_mutation_that_fails_before_its_grant_answers_unavailable() {
        use maknae_agent::plane::WriteOutcome;
        use maknae_agent::wire::{write_outcome, WireOutcome};
        let p = || "/sentinel-617".to_string();
        for verb in [
            maknae_proto::Verb::FsWrite {
                path: p(),
                content_length: 1,
                mode: maknae_proto::WriteMode::Existing,
                conversation: None,
            },
            maknae_proto::Verb::FsDelete {
                path: p(),
                recursive: false,
                conversation: None,
            },
            maknae_proto::Verb::FsMkdir {
                path: p(),
                parents: false,
                components: vec![],
                conversation: None,
            },
        ] {
            let sent = before_grant(
                mutates(&verb),
                "TLS handshake to the daemon timed out".into(),
            );
            assert_eq!(
                write_outcome(sent.map(WireOutcome::from)),
                WriteOutcome::Unavailable,
                "{verb:?}"
            );
        }
        let read = maknae_proto::Verb::Read {
            path: p(),
            conversation: None,
            page: None,
        };
        assert_eq!(
            before_grant(mutates(&read), "connection reset".into()).unwrap_err(),
            "connection reset"
        );
    }

    fn fs_write() -> maknae_proto::Verb {
        maknae_proto::Verb::FsWrite {
            path: "/sentinel-617".into(),
            content_length: 1,
            mode: maknae_proto::WriteMode::Existing,
            conversation: None,
        }
    }

    #[tokio::test]
    async fn a_write_that_cannot_reach_the_daemon_answers_unavailable() {
        use maknae_agent::plane::WriteOutcome;
        use maknae_agent::wire::{write_outcome, WireOutcome};
        let unreachable = async {
            Err::<maknae_vault::AuthenticatedStream, _>(maknae_vault::VaultError::Handshake(
                "connection refused".into(),
            ))
        };
        let sent = exchange(
            unreachable,
            None,
            fs_write(),
            Some(maknae_proto::Bytes::new(zeroize::Zeroizing::new(
                b"x".to_vec(),
            ))),
            crate::mutation::WriteCheck::Unread,
            &maknae_config::TransportConfig::default(),
            &mut |_| {},
        )
        .await
        .map(|sent| sent.outcome);
        let settled = settle(true, sent);
        assert!(
            matches!(&settled, Ok(SentOutcome::NotAttempted { why }) if why.contains("connection refused")),
            "{settled:?}"
        );
        assert_eq!(
            write_outcome(settled.map(WireOutcome::from)),
            WriteOutcome::Unavailable
        );
    }

    #[test]
    fn a_grant_time_fault_on_a_mutation_answers_unavailable() {
        let grant = || {
            RespResult::Ok(Payload::MutationAttempt(maknae_proto::MutationGrant {
                id: maknae_proto::MutationId {
                    session_id: 1,
                    intent_seq: 1,
                },
                scope: maknae_proto::MutationScope::Exact {
                    path: "/sentinel-617".into(),
                    effect: maknae_proto::ReportedEffect::ReplacedFile,
                },
                limits: maknae_proto::MutationLimits {
                    max_effects: 1,
                    max_depth: 1,
                    deadline_ms: 1,
                    max_bytes: 0,
                },
                label: maknae_proto::ObjectLabel {
                    level: "UNCLASSIFIED".into(),
                    categories: vec![],
                },
            }))
        };
        for (what, result) in [
            ("a grant for an unprepared request", grant()),
            (
                "a payload in place of the grant",
                RespResult::Ok(Payload::Pong),
            ),
        ] {
            let settled = settle(
                true,
                first_answer(true, None, result, true).map(|a| match a {
                    FirstAnswer::Done(sent) => sent,
                    FirstAnswer::Grant(..) => panic!("{what}: granted"),
                }),
            );
            assert!(
                matches!(settled, Ok(SentOutcome::NotAttempted { .. })),
                "{what}: {settled:?}"
            );
        }
        assert!(matches!(
            first_answer(false, None, RespResult::Ok(Payload::Pong), true),
            Ok(FirstAnswer::Done(SentOutcome::Payload(Payload::Pong)))
        ));
        let stat = || {
            crate::mutation::prepare_checked(
                maknae_proto::Verb::FsStat {
                    path: "/sentinel-161".into(),
                    conversation: None,
                },
                None,
                crate::mutation::WriteCheck::Unchecked,
            )
        };
        assert!(
            matches!(
                first_answer(false, stat(), grant(), false),
                Err(Failed::BeforeGrant(why)) if why.contains("fs.stat")
            ),
            "a grant never reaches an executor for fs.stat"
        );
        let listing = crate::mutation::prepare_checked(
            maknae_proto::Verb::FsList {
                path: "/sentinel-161".into(),
                after: None,
                conversation: None,
            },
            None,
            crate::mutation::WriteCheck::Unchecked,
        );
        assert!(
            matches!(
                first_answer(false, listing, grant(), false),
                Ok(FirstAnswer::Grant(p, _)) if matches!(p.request(), maknae_proto::Verb::FsList { .. })
            ),
            "a listing grant reaches the listing executor"
        );
        assert!(!mutates(&maknae_proto::Verb::FsList {
            path: "/sentinel-161".into(),
            after: None,
            conversation: None,
        }));
        let answer = Payload::Stat(maknae_proto::StatView {
            size: 1,
            mtime_secs: 1,
            kind: maknae_proto::StatKind::File,
        });
        assert!(matches!(
            first_answer(false, stat(), RespResult::Ok(answer.clone()), true),
            Ok(FirstAnswer::Done(SentOutcome::Payload(p))) if p == answer
        ));
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
    fn an_agent_list_waits_out_the_kernels_worst_case() {
        let transport = maknae_config::TransportConfig {
            read_timeout_ms: READ_TIMEOUT_MS,
            ..Default::default()
        };
        let stage = maknae_config::BLOCKING_STAGE_TIMEOUT_MS;
        let worst =
            READ_TIMEOUT_MS + SESSION_CHECKS_MS + maknae_config::AGENT_LIST_REPLY_STAGES * stage;
        assert!(
            reply_wait(&maknae_proto::Verb::AgentList { after: None }, &transport)
                >= std::time::Duration::from_millis(worst)
        );
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
            (
                maknae_proto::Verb::AdminHeldList {
                    filter: None,
                    after: None,
                },
                maknae_config::HELD_REPLY_STAGES,
            ),
            (
                maknae_proto::Verb::AdminHeldRelease {
                    target: maknae_proto::HeldTarget::User(target()),
                    after: None,
                },
                maknae_config::HELD_REPLY_STAGES,
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
