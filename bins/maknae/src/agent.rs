//! `maknae agent` — the HANDS of the runtime loop (#241). T3: I/O wiring over
//! the brain in `maknae-agent`. Runs as the subject, holds no key and no
//! policy, and asks the kernel for everything (ADR-0023 d2, d4).
use crate::cli::{send_verb, write_request, SentOutcome};
use maknae_agent::drive::{drive, Budget, StopReason};
use maknae_agent::plane::{Plane, PlaneError, ReadOutcome, WriteOutcome};
use maknae_agent::transcript::Transcript;
use maknae_config::Value;
use maknae_proto::{Payload, Turn, Verb};
use maknae_vault::PlaneClient;

pub const AGENT_SECTION: &str = "agent";
const AGENT_KEYS: [&str; 2] = ["max_steps", "max_tool_calls_per_step"];

pub struct AgentConfig {
    pub max_steps: u32,
    pub max_tool_calls_per_step: u32,
}

/// Advisory bounds (ADR-0023 d7), from the subject's own config — a file the
/// subject may edit, which is fine precisely because they are advisory.
/// String-errored like the rest of the CLI (R3); the closed vocabulary is
/// maknae-config's public `reject_unknown_keys` (#210).
pub fn agent_from_section(v: Option<&Value>) -> Result<AgentConfig, String> {
    let Some(section) = v else {
        return Ok(AgentConfig {
            max_steps: 8,
            max_tool_calls_per_step: 4,
        });
    };
    let Value::Map(entries) = section else {
        return Err(format!("{AGENT_SECTION}: section must be a map"));
    };
    maknae_config::reject_unknown_keys(AGENT_SECTION, entries, &AGENT_KEYS)
        .map_err(|e| e.to_string())?;
    Ok(AgentConfig {
        max_steps: bounded_u32(entries, "max_steps", 8, 64)?,
        max_tool_calls_per_step: bounded_u32(entries, "max_tool_calls_per_step", 4, 16)?,
    })
}

fn bounded_u32(
    entries: &[(String, Value)],
    key: &str,
    default: u32,
    max: u32,
) -> Result<u32, String> {
    match entries.iter().find(|(k, _)| k == key).map(|(_, v)| v) {
        None => Ok(default),
        Some(Value::Int(n)) if *n >= 1 && *n <= max as i64 => Ok(*n as u32),
        Some(_) => Err(format!(
            "{AGENT_SECTION}.{key}: must be an integer in 1..={max}"
        )),
    }
}

/// ≤32 chars, no whitespace — `conversation_id_is_acceptable`'s bound.
pub fn mint_conversation_id() -> String {
    let secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    format!("c{secs:x}p{:x}", std::process::id())
}

/// A CONTROL, and a pure function so it is testable: only an AUTHORIZATION
/// refusal of an ARMED request is `Refused` — the one outcome the model may
/// not appeal. Any other code (a `BadRequest` for `/a/../b` is a client-shape
/// fault, not a decision), any protocol surprise, and any transport error is
/// `Unavailable`. The wire carries no reason (ADR-0019); it does carry the
/// code.
///
/// Corrected 2026-09-22 (#241): an UNARMED refusal is `Unavailable`, not
/// `Refused`. When the subject's own `open_for_delegation` fails — a typo'd
/// path, ENOENT, EACCES — `send_verb` sends the request anyway, unarmed, so
/// the deny lands in the audit trail (ADR-0009 decision 2), and the kernel
/// refuses it for want of a descriptor. That arrives as the same generic
/// `Unauthorized` as a real deny, but it is not a PDP verdict on the object's
/// content: it is the subject's own OS-DAC or a path that does not exist.
/// Rendering it as "Not authorized" told the model a decision had been made,
/// and the compiled prompt forbids the model to diagnose or retry that.
pub fn read_outcome(sent: Result<SentOutcome, String>) -> ReadOutcome {
    match sent {
        // The buffer is MOVED, never copied: `b.0` is already a `Zeroizing`,
        // and `maknae_proto::Bytes::new` forbids copying content out of one
        // into a plain `Vec`. `ReadOutcome::Content` carries the same type, so
        // the secrecy survives the hop into the brain.
        Ok(SentOutcome::Payload(Payload::ReadContent(b))) => ReadOutcome::Content(b.0),
        Ok(SentOutcome::Refused { armed: false, .. }) => ReadOutcome::Unavailable,
        Ok(SentOutcome::Refused {
            code: maknae_proto::ProtoErrCode::Unauthorized,
            ..
        }) => ReadOutcome::Refused,
        _ => ReadOutcome::Unavailable,
    }
}

/// The write half of the same treatment, and pure for the same reason: ONLY a
/// clean `WriteDone { applied: true }` is `Applied`.
///
/// Everything else is `Unknown` — a non-applied completion, a refusal, a
/// payload for some other verb, and every transport error. ADR-0023 d4: a
/// `String` error cannot tell a pre-send connect failure from a post-send read
/// timeout, and guessing would manufacture certainty. `NotSent` is NOT decided
/// here: it is the one LOCAL refusal, judged from `write_request`'s `Err`
/// before `send_verb` is ever called. `armed` does not enter the write
/// decision: every non-`Applied` write is already `Unknown`.
pub fn write_outcome(sent: Result<SentOutcome, String>) -> WriteOutcome {
    match sent {
        Ok(SentOutcome::WriteDone { applied: true }) => WriteOutcome::Applied,
        _ => WriteOutcome::Unknown,
    }
}

/// The real Plane: one authenticated client, one connection per verb.
pub struct RealPlane<'a> {
    pub transport: &'a maknae_config::TransportConfig,
    pub client: &'a PlaneClient,
    pub ca: &'a maknae_vault::CaBundle,
}

impl Plane for RealPlane<'_> {
    async fn prompt(
        &mut self,
        conversation: &str,
        turns: &[Turn],
    ) -> Result<maknae_proto::PromptReply, PlaneError> {
        let verb = Verb::SessionPrompt {
            conversation: conversation.to_string(),
            turns: turns.to_vec(),
        };
        // Measured against the frame cap BEFORE sending (ADR-0023 d7). This
        // encodes once here and once inside send_verb; accepted for Cooky.
        if maknae_proto::encode_request_zeroizing(
            &maknae_proto::Request {
                protocol_version: maknae_proto::PROTOCOL_VERSION,
                verb: verb.clone(),
            },
            self.transport.frame_max_bytes,
        )
        .is_err()
        {
            return Err(PlaneError::FrameTooLarge);
        }
        match send_verb(verb, None, self.transport, self.client, self.ca).await {
            Ok(SentOutcome::Payload(Payload::PromptReply(r))) => Ok(r),
            Ok(SentOutcome::Refused { .. }) => Err(PlaneError::Refused),
            Ok(other) => Err(PlaneError::Transport(format!(
                "protocol error: unexpected reply to session.prompt: {other:?}"
            ))),
            Err(m) => Err(PlaneError::Transport(m)),
        }
    }
    async fn read(&mut self, path: &str) -> ReadOutcome {
        // R1: the object is passed so the read is ARMED exactly as `maknae read` is.
        read_outcome(
            send_verb(
                Verb::Read {
                    path: path.to_string(),
                },
                Some(path),
                self.transport,
                self.client,
                self.ca,
            )
            .await,
        )
    }
    async fn write(&mut self, path: &str, content: &[u8]) -> WriteOutcome {
        // R13: the frame-budget refusal is LOCAL and pre-send — nothing left
        // the process, nothing is on the trail, the file is untouched.
        let Ok(verb) = write_request(
            path.to_string(),
            zeroize::Zeroizing::new(content.to_vec()),
            self.transport.frame_max_bytes,
        ) else {
            return WriteOutcome::NotSent;
        };
        write_outcome(send_verb(verb, None, self.transport, self.client, self.ca).await)
    }
}

/// Mirrors `execute()`'s setup exactly (FIPS provider, config, mint, revoke).
pub async fn run(prompt: String) -> Result<u8, String> {
    maknae_vault::install_default_crypto_provider();
    let dir = crate::cli::resolve_config_dir();
    let document = maknae_config::load_config(&dir, &crate::cli::cli_config_specs())
        .map_err(|e| e.to_string())?;
    let transport =
        maknae_config::transport_from_section(document.section(maknae_config::TRANSPORT_SECTION))
            .map_err(|e| e.to_string())?;
    let agent = agent_from_section(document.section(AGENT_SECTION))?;
    let client = PlaneClient::from_document(&document, &dir, maknae_vault::Plane::Cli)
        .map_err(|e| e.to_string())?;
    let ca = maknae_vault::load_ca_pin(&dir).map_err(|e| e.to_string())?;
    client.mint().await.map_err(|e| e.to_string())?;
    let mut plane = RealPlane {
        transport: &transport,
        client: &client,
        ca: &ca,
    };
    let mut transcript = Transcript::new(mint_conversation_id(), &prompt);
    let budget = Budget {
        max_steps: agent.max_steps,
        max_tool_calls_per_step: agent.max_tool_calls_per_step,
    };
    let outcome = drive(&mut plane, &mut transcript, &budget).await;
    client.shutdown().await; // revoke on EVERY path, as execute() does
    if let Some(answer) = outcome.answer {
        println!("{answer}");
        return Ok(0);
    }
    let why = match outcome.stopped {
        Some(StopReason::StepBudget) => format!(
            "stopped: the step budget ({}) was spent without an answer",
            budget.max_steps
        ),
        Some(StopReason::TooManyToolCalls(n)) => format!(
            "stopped: the model asked for {n} tools in one step (cap {})",
            budget.max_tool_calls_per_step
        ),
        Some(StopReason::FrameBound) => {
            "stopped: the conversation has reached the platform's frame bound".into()
        }
        // NOT "refused the prompt" (corrected 2026-09-22, #241): the kernel
        // answers `LandedUndelivered`, `DeadlineExpired` and `OutcomeUnknown`
        // with the same generic `Unauthorized`, so the prompt may well have
        // reached the provider. Only the trail knows which.
        Some(StopReason::PromptRefused) => {
            "stopped: the kernel refused the exchange — whether the prompt reached the provider is in the audit trail".into()
        }
        Some(StopReason::Transport(m)) => format!("stopped: {m}"),
        None => "stopped".into(),
    };
    eprintln!("maknae agent: {why}");
    Ok(2)
}

#[cfg(test)]
mod tests {
    use super::*;
    fn yaml(s: &str) -> maknae_config::Value {
        maknae_config::load_str(s).unwrap()
    }
    #[test]
    fn agent_section_defaults_and_bounds() {
        let none = agent_from_section(None).unwrap();
        assert_eq!((none.max_steps, none.max_tool_calls_per_step), (8, 4));
        let c =
            agent_from_section(Some(&yaml("max_steps: 3\nmax_tool_calls_per_step: 1\n"))).unwrap();
        assert_eq!((c.max_steps, c.max_tool_calls_per_step), (3, 1));
        // The UPPER bound at its own boundary, both keys: every other row sits
        // strictly inside or far outside it, so without these an `<=` → `<`
        // mutant on either ceiling survives.
        let top = agent_from_section(Some(&yaml("max_steps: 64\nmax_tool_calls_per_step: 16\n")))
            .unwrap();
        assert_eq!((top.max_steps, top.max_tool_calls_per_step), (64, 16));
        assert!(
            agent_from_section(Some(&yaml("max_tool_calls_per_step: 17\n"))).is_err(),
            "one past the tool-call ceiling (16)"
        );
        assert!(
            agent_from_section(Some(&yaml("max_steps: 0\n"))).is_err(),
            "zero steps is not a loop"
        );
        assert!(
            agent_from_section(Some(&yaml("max_steps: 1000\n"))).is_err(),
            "bounded above (64)"
        );
        assert!(
            agent_from_section(Some(&yaml("max_stepz: 3\n"))).is_err(),
            "closed vocabulary (#210)"
        );
        assert!(
            agent_from_section(Some(&yaml("disabled"))).is_err(),
            "a non-map section fails closed"
        );
        // R15's actual case: a BARE `agent:` key reaches this function as
        // `Some(&Value::Null)` (loader assembles sections as (key, val) pairs
        // from the root map). Loud, not silently defaulted.
        assert!(
            agent_from_section(Some(&maknae_config::Value::Null)).is_err(),
            "a bare `agent:` key fails closed"
        );
    }
    #[test]
    fn a_conversation_id_is_minted_within_the_wire_bound() {
        assert!(maknae_proto::conversation_id_is_acceptable(
            &mint_conversation_id()
        ));
    }
    #[test]
    fn a_write_is_applied_only_for_a_clean_completion_and_unknown_for_everything_else() {
        // R29/ADR-0023 d4: the wire cannot distinguish uncertain from refused
        // on the write lane, so only a clean `applied: true` may claim
        // certainty. `NotSent` is absent by construction — it is decided from
        // `write_request`'s `Err`, before `send_verb` is called (R13).
        use maknae_proto::{Payload, ProtoErrCode};
        assert_eq!(
            write_outcome(Ok(SentOutcome::WriteDone { applied: true })),
            WriteOutcome::Applied
        );
        assert_eq!(
            write_outcome(Ok(SentOutcome::WriteDone { applied: false })),
            WriteOutcome::Unknown
        );
        assert_eq!(
            write_outcome(Ok(SentOutcome::Refused {
                code: ProtoErrCode::Unauthorized,
                message: "not authorized".into(),
                armed: true
            })),
            WriteOutcome::Unknown,
            "a refusal is not a certainty on the write lane"
        );
        assert_eq!(
            write_outcome(Ok(SentOutcome::Payload(Payload::Pong))),
            WriteOutcome::Unknown
        );
        assert_eq!(
            write_outcome(Err("no response from daemon within 5000ms".into())),
            WriteOutcome::Unknown
        );
    }
    #[test]
    fn a_read_is_refused_only_for_unauthorized_and_unavailable_for_every_other_outcome() {
        // R11 is a CONTROL, so it is tested: only the authorization code is a
        // refusal the model may not appeal; a BadRequest (`/a/../b`), a
        // protocol error, or a transport error is "unavailable".
        use maknae_proto::{Payload, ProtoErrCode};
        let content = maknae_proto::Bytes::new(zeroize::Zeroizing::new(b"x".to_vec()));
        assert_eq!(
            read_outcome(Ok(SentOutcome::Payload(Payload::ReadContent(content)))),
            ReadOutcome::Content(zeroize::Zeroizing::new(b"x".to_vec()))
        );
        assert_eq!(
            read_outcome(Ok(SentOutcome::Refused {
                code: ProtoErrCode::Unauthorized,
                message: "not authorized".into(),
                armed: true
            })),
            ReadOutcome::Refused
        );
        assert_eq!(
            read_outcome(Ok(SentOutcome::Refused {
                code: ProtoErrCode::BadRequest,
                message: "not absolute".into(),
                armed: true
            })),
            ReadOutcome::Unavailable
        );
        // #241: an UNARMED refusal is not a PDP verdict on the content. The
        // subject's own `open_for_delegation` failed (ENOENT, EACCES), the
        // request went out without a descriptor, and the kernel denied it for
        // want of one (ADR-0009 d2) — which arrives as the same generic
        // `Unauthorized`. Telling the model "Not authorized" for a typo'd path
        // asserts a decision nobody made, and the compiled prompt forbids the
        // model to diagnose or retry it.
        assert_eq!(
            read_outcome(Ok(SentOutcome::Refused {
                code: ProtoErrCode::Unauthorized,
                message: "no delegated descriptor".into(),
                armed: false
            })),
            ReadOutcome::Unavailable,
            "a read the subject could not arm was never decided"
        );
        assert_eq!(
            read_outcome(Ok(SentOutcome::Refused {
                code: ProtoErrCode::BadRequest,
                message: "not absolute".into(),
                armed: false
            })),
            ReadOutcome::Unavailable
        );
        assert_eq!(
            read_outcome(Ok(SentOutcome::WriteDone { applied: true })),
            ReadOutcome::Unavailable
        );
        assert_eq!(
            read_outcome(Err("handshake timed out".into())),
            ReadOutcome::Unavailable
        );
    }
}
