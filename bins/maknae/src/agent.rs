//! `maknae agent` — the HANDS of the runtime loop (#241). T3: I/O wiring over
//! the brain in `maknae-agent`. Runs as the subject, holds no key and no
//! policy, and asks the kernel for everything (ADR-0023 d2, d4).
use crate::cli::{send_verb, write_request, SentOutcome};
use maknae_agent::budget::{prompt_cap, ContextBudget, Meter, Notice};
use maknae_agent::drive::{drive, Budget, StopReason};
use maknae_agent::plane::{Plane, PlaneError, ReadBasis, ReadOutcome, ReadPage, WriteOutcome};
use maknae_agent::transcript::Transcript;
use maknae_config::{UserProviderEntry, UserProviders, Value};
use maknae_proto::{Payload, ProviderChoice, SealedKey, Turn, Verb};
use maknae_seal::{SealAad, SealContext, SealPublicKey};
use maknae_vault::{
    aad_parts, PlaneClient, UserToken, VaultApi, VaultError, WrapExpectation, WrappedSecret,
    USER_KEY_WRAP_TTL,
};
use std::future::Future;
use std::path::Path;

pub const AGENT_SECTION: &str = "agent";
const AGENT_KEYS: [&str; 2] = ["max_steps", "max_tool_calls_per_step"];

pub struct AgentConfig {
    pub max_steps: u32,
    pub max_tool_calls_per_step: u32,
}

/// Advisory bounds (ADR-0023 d7), from the subject's own config — a file the
/// subject may edit, which is fine precisely because they are advisory.
/// String-errored like the rest of the CLI; the closed vocabulary is
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

pub fn key_location<'a>(
    kv_mount: Option<&'a str>,
    user_prefix: Option<&'a str>,
) -> Result<(&'a str, &'a str), String> {
    let missing = |key: &str| {
        format!("vault.{key} is not set in your maknae.yaml: `sudo maknae enroll` writes it")
    };
    Ok((
        kv_mount.ok_or_else(|| missing("kv_mount"))?,
        user_prefix.ok_or_else(|| missing("user_prefix"))?,
    ))
}

pub fn choose_entry<'a>(
    providers: &'a UserProviders,
    label: Option<&str>,
    dir: &Path,
) -> Result<&'a UserProviderEntry, String> {
    if providers.is_empty() {
        return Err(format!(
            "no model access: no providers are defined in {}",
            dir.join(maknae_config::USER_PROVIDERS_FILE).display()
        ));
    }
    providers.select(label).map_err(|e| e.to_string())
}

pub const LOGIN_EXPIRED: &str = "your Vault login expired: run `maknae login`";

pub const PROMPT_REFUSED: &str = "the kernel refused the exchange — whether the prompt reached the provider is in the host's audit trail (ask your administrator); if it did not, check that your providers.yaml names a provider and model your administrator has authorized for your role and the key subpath and field of your own Vault secret, that your maknae.yaml vault block matches the host's, and that your login is current (maknae login)";

pub fn login_expired(expires_at: u64, now: u64) -> bool {
    now.saturating_add(maknae_vault::TOKEN_EXPIRY_MARGIN.as_secs()) >= expires_at
}

pub fn key_read_failure(label: &str, e: &VaultError) -> String {
    match e {
        VaultError::VaultStatus { status: 403, .. } => format!(
            "Vault refused to read the key for provider entry {label} (HTTP 403): the key is \
             outside your Vault policy, or your login was revoked: run `maknae login`"
        ),
        VaultError::VaultStatus { status: 404, .. } => {
            format!("no key is stored in Vault for provider entry {label}: store it, then retry")
        }
        other => format!("reading the key for provider entry {label} from Vault failed: {other}"),
    }
}

fn seal_key_from(pem: &str) -> Result<SealPublicKey, String> {
    SealPublicKey::from_pem(pem).map_err(|e| {
        format!(
            "the Egress Daemon public key published on this host is not usable ({e}): ask your \
             administrator to run `sudo maknae enroll`"
        )
    })
}

fn token_copy(token: &UserToken) -> Result<UserToken, String> {
    let mut copy = zeroize::Zeroizing::new(String::with_capacity(token.expose().len()));
    copy.push_str(token.expose());
    UserToken::new(copy).map_err(|e| e.to_string())
}

pub struct KeyContext<'a> {
    pub entry: &'a UserProviderEntry,
    pub kv_mount: &'a str,
    pub user_prefix: &'a str,
    pub username: &'a str,
    pub seal_key: &'a SealPublicKey,
    pub expires_at: u64,
}

pub async fn turn_choice<F, Fut>(
    key: &KeyContext<'_>,
    conversation: &str,
    now: u64,
    read: F,
) -> Result<ProviderChoice, String>
where
    F: FnOnce(String) -> Fut,
    Fut: Future<Output = Result<WrappedSecret, VaultError>>,
{
    let entry = key.entry;
    if login_expired(key.expires_at, now) {
        return Err(LOGIN_EXPIRED.to_string());
    }
    let unusable = || {
        format!(
            "provider entry {}: its key's Vault path is not acceptable (check vault.kv_mount, \
             vault.user_prefix and the entry's key subpath)",
            entry.label
        )
    };
    let secret_path =
        maknae_config::user_key_path(key.user_prefix, key.username, &entry.key_subpath)
            .map_err(|_| unusable())?;
    let expect = WrapExpectation::new(
        key.kv_mount,
        &secret_path,
        &entry.key_field,
        USER_KEY_WRAP_TTL,
    )
    .map_err(|_| unusable())?;
    let wrapped = read(secret_path)
        .await
        .map_err(|e| key_read_failure(&entry.label, &e))?;
    let sealing = |e: &dyn std::fmt::Display| {
        format!(
            "sealing the key for provider entry {} failed: {e}",
            entry.label
        )
    };
    let parts = aad_parts(&expect, conversation, &entry.provider, &entry.model);
    let aad = SealAad::new(&SealContext {
        conversation: parts.conversation,
        provider: parts.provider,
        model: parts.model,
        expected_path: parts.expected_path,
        key_field: parts.key_field,
    })
    .map_err(|e| sealing(&e))?;
    let blob = maknae_seal::seal(key.seal_key, &aad, wrapped.token.expose().as_bytes())
        .map_err(|e| sealing(&e))?;
    let sealed_key = SealedKey::new(blob.into_bytes()).map_err(|e| sealing(&e))?;
    Ok(ProviderChoice {
        provider: entry.provider.clone(),
        model: entry.model.clone(),
        key_subpath: entry.key_subpath.clone(),
        key_field: entry.key_field.clone(),
        sealed_key,
    })
}

/// `Some(parsed)` only when the subject's `transport` section sets the key;
/// a default must not cap the loop below its window.
pub fn explicit_prompt_cap(transport: Option<&Value>, parsed: usize) -> Option<usize> {
    match transport {
        Some(Value::Map(entries)) if entries.iter().any(|(k, _)| k == "prompt_max_bytes") => {
            Some(parsed)
        }
        _ => None,
    }
}

pub fn loop_prompt_cap(context_tokens: u64, explicit: Option<usize>) -> usize {
    let derived = prompt_cap(context_tokens);
    explicit.map_or(derived, |e| derived.min(e))
}

fn thousands(n: u64) -> String {
    let digits = n.to_string();
    let mut out = String::with_capacity(digits.len() + digits.len() / 3);
    for (i, c) in digits.chars().enumerate() {
        if i > 0 && (digits.len() - i).is_multiple_of(3) {
            out.push(',');
        }
        out.push(c);
    }
    out
}

pub fn warning_line(n: &Notice) -> String {
    format!(
        "warning: this conversation is at {}% of the declared context budget ({} of {} tokens){}",
        n.percent,
        thousands(n.tokens),
        thousands(n.budget),
        if n.estimated {
            " — estimated from bytes; the provider has not reported usage"
        } else {
            ""
        }
    )
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
/// not appeal. An armed `Unauthorized` is the kernel's refusal before any
/// grant; the wire carries no reason (ADR-0019), so it also covers evidence and
/// capacity refusals (#344, #370). An unarmed refusal, any other
/// code (a `BadRequest` for `/a/../b` is a client-shape fault), any protocol
/// surprise and any transport error is `Unavailable`. So is a grant that ends
/// without an acknowledged `Success` (OS refusal, limit, changed object, lost
/// ack): a fact about the attempt, not a verdict.
pub fn read_outcome(sent: Result<SentOutcome, String>) -> ReadOutcome {
    match sent {
        Ok(SentOutcome::ReadDone { read: Some(r) }) => ReadOutcome::Content(ReadPage {
            content: r.content,
            level: r.label.level,
            lines: r.page.lines,
            complete_line: r.page.complete_last,
            next: r.page.next,
            eof: r.page.eof,
            version: r.page.version.key(),
            changed: false,
        }),
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
///
/// **Amended 2026-09-28 (#388):** one non-applied completion is certain, not
/// guessed — `stale`, set only when the client's read-before-write check refused
/// the attempt before any write syscall and the no-effect completion was
/// acknowledged. It is `Stale`; every other non-applied completion stays
/// `Unknown`.
pub fn write_outcome(sent: Result<SentOutcome, String>) -> WriteOutcome {
    match sent {
        Ok(SentOutcome::WriteDone {
            applied: true,
            version,
            ..
        }) => WriteOutcome::Applied(version),
        Ok(SentOutcome::WriteDone {
            applied: false,
            stale: true,
            ..
        }) => WriteOutcome::Stale,
        _ => WriteOutcome::Unknown,
    }
}

/// The loop's knowledge of a file, as the client's write check (#388). The
/// loop never sends `Unchecked`: that is `maknae write`'s, for a human.
pub fn check_for(basis: ReadBasis) -> crate::mutation::WriteCheck {
    match basis {
        ReadBasis::Unread => crate::mutation::WriteCheck::Unread,
        ReadBasis::Read(k) => crate::mutation::WriteCheck::Read(k),
    }
}

/// The prompt leg's mapper, pure and tested for the same reason the read and
/// write mappers are: it is a CONTROL. A `BadRequest` on `session.prompt` is a
/// pre-gate fault on the request's own shape — `maknae agent "   "` is refused
/// for carrying no text to send, and provably never reached the provider: no
/// egress block was opened and no intent record was written. Reporting that
/// with [`PROMPT_REFUSED`] would send the subject to their providers.yaml and
/// their login for a fault they can fix from the message. What
/// the trail does hold is the pre-gate deny: the kernel appends
/// `emit_request_outcome` with a `deny` and the reason
/// `prompt fails operand pre-gate: …` before it writes the `BadRequest` back,
/// and it writes that error only under `may_respond(appended)`, so a subject
/// who saw it is proof the record landed. Both facts, and neither more: no
/// provider contact, and a recorded pre-gate deny. Every OTHER refusal code
/// stays `Refused`, because the
/// kernel answers `LandedUndelivered`, `DeadlineExpired` and `OutcomeUnknown`
/// with the same generic `Unauthorized` and the prompt may well have landed.
pub fn prompt_outcome(
    sent: Result<SentOutcome, String>,
) -> Result<maknae_proto::PromptReply, PlaneError> {
    match sent {
        Ok(SentOutcome::Payload(Payload::PromptReply(r))) => Ok(r),
        Ok(SentOutcome::Refused {
            code: maknae_proto::ProtoErrCode::BadRequest,
            ..
        }) => Err(PlaneError::Malformed),
        Ok(SentOutcome::Refused { .. }) => Err(PlaneError::Refused),
        Ok(other) => Err(PlaneError::Transport(format!(
            "protocol error: unexpected reply to session.prompt: {other:?}"
        ))),
        Err(m) => Err(PlaneError::Transport(m)),
    }
}

/// The real Plane: one authenticated client, one connection per verb.
pub struct RealPlane<'a> {
    pub transport: &'a maknae_config::TransportConfig,
    pub client: &'a PlaneClient,
    pub ca: &'a maknae_vault::CaBundle,
    pub output_tokens: Option<u64>,
    pub write_max: usize,
    pub api: &'a VaultApi,
    pub token: &'a UserToken,
    pub key: KeyContext<'a>,
}

impl Plane for RealPlane<'_> {
    async fn prompt(
        &mut self,
        conversation: &str,
        turns: &[Turn],
    ) -> Result<maknae_proto::PromptReply, PlaneError> {
        let now = crate::login::now_unix().map_err(PlaneError::Transport)?;
        let (api, token, kv_mount) = (self.api, self.token, self.key.kv_mount);
        let choice = turn_choice(&self.key, conversation, now, |path| async move {
            api.read_wrapped(token, kv_mount, &path, maknae_vault::USER_KEY_WRAP_TTL)
                .await
        })
        .await
        .map_err(PlaneError::Transport)?;
        let verb = Verb::SessionPrompt {
            conversation: conversation.to_string(),
            turns: turns.to_vec(),
            output_tokens: self.output_tokens,
            choice: Some(choice),
        };
        // Measured against the frame cap BEFORE sending (ADR-0023 d7). This
        // encodes once here and once inside send_verb; accepted for Cooky.
        if maknae_proto::encode_request_zeroizing(
            &maknae_proto::Request {
                protocol_version: maknae_proto::PROTOCOL_VERSION,
                verb: verb.clone(),
            },
            self.transport.prompt_max_bytes,
        )
        .is_err()
        {
            return Err(PlaneError::FrameTooLarge);
        }
        prompt_outcome(
            send_verb(
                verb,
                None,
                crate::mutation::WriteCheck::Unchecked,
                self.transport,
                self.client,
                self.ca,
            )
            .await,
        )
    }
    async fn read(
        &mut self,
        conversation: &str,
        path: &str,
        page: maknae_proto::PageRequest,
    ) -> ReadOutcome {
        read_outcome(
            send_verb(
                Verb::Read {
                    path: path.to_string(),
                    conversation: Some(conversation.to_string()),
                    page: Some(page),
                },
                None,
                crate::mutation::WriteCheck::Unchecked,
                self.transport,
                self.client,
                self.ca,
            )
            .await,
        )
    }
    async fn write(
        &mut self,
        conversation: &str,
        path: &str,
        content: &[u8],
        basis: ReadBasis,
    ) -> WriteOutcome {
        // The prompt-budget refusal is LOCAL and pre-send — nothing left
        // the process, nothing is on the trail, the file is untouched.
        let Ok((verb, content)) = write_request(
            path.to_string(),
            zeroize::Zeroizing::new(content.to_vec()),
            Some(conversation.to_string()),
            self.write_max,
        ) else {
            return WriteOutcome::NotSent;
        };
        write_outcome(
            send_verb(
                verb,
                Some(content),
                check_for(basis),
                self.transport,
                self.client,
                self.ca,
            )
            .await,
        )
    }
}

pub fn stop_line(r: Option<&StopReason>, budget: &Budget) -> String {
    match r {
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
        Some(StopReason::PromptRefused) => format!("stopped: {PROMPT_REFUSED}"),
        // Distinct from the line above, and the distinction is the point: a
        // `BadRequest` on the prompt leg is a pre-gate fault on the request's
        // own shape, decided before any exchange was attempted, so nothing
        // reached the provider.
        //
        // Corrected 2026-09-22 (codex round 1): this said "there is nothing in
        // the trail to go and read", and that is false. The kernel DOES append
        // a record for this case — `emit_request_outcome` with a `deny` and
        // the reason `prompt fails operand pre-gate: …` — before it writes the
        // `BadRequest` back. What is absent is the durable EGRESS INTENT,
        // because no exchange was attempted. So the line names both facts and
        // neither more: no provider contact, and a pre-gate deny that is on
        // the record. The earlier wording risked an operator concluding the
        // refusal went unaudited (#241 CR1 SF2 set the first half of this).
        //
        // The claim is not merely usually true: `run.rs`'s prompt pre-gate
        // writes the `BadRequest` only under `may_respond(appended)`, so a
        // subject that SAW this error is proof the record was appended. That
        // pre-gate is also the only `BadRequest` the prompt leg can produce.
        Some(StopReason::PromptMalformed) => {
            "stopped: the kernel refused the prompt as malformed before any provider contact (the trail records the pre-gate deny)"
                .into()
        }
        Some(StopReason::Transport(m)) => format!("stopped: {m}"),
        Some(StopReason::ContextBudget) => "stopped: the conversation has reached the declared context budget; compaction arrives with #171".into(),
        None => "stopped".into(),
    }
}

/// Mirrors `execute()`'s setup (FIPS provider, config, user token, mint).
pub async fn run(label: Option<String>, prompt: String) -> Result<u8, String> {
    maknae_vault::install_default_crypto_provider();
    let dir = crate::cli::resolve_config_dir();
    let document = maknae_config::load_config(&dir, &crate::cli::cli_config_specs())
        .map_err(|e| e.to_string())?;
    let transport =
        maknae_config::transport_from_section(document.section(maknae_config::TRANSPORT_SECTION))
            .map_err(|e| e.to_string())?;
    let agent = agent_from_section(document.section(AGENT_SECTION))?;
    let vault = maknae_vault::vault_config_from_document(&document).map_err(|e| e.to_string())?;
    let (kv_mount, user_prefix) =
        key_location(vault.kv_mount.as_deref(), vault.user_prefix.as_deref())?;
    let providers = maknae_config::load_user_providers(&dir).map_err(|e| e.to_string())?;
    let entry = choose_entry(&providers, label.as_deref(), &dir)?;
    let context = ContextBudget::new(entry.context_tokens, entry.output_tokens)
        .map_err(|e| format!("provider entry {}: {e}", entry.label))?;
    let username = crate::login::local_username()?;
    let seal_key = seal_key_from(&maknae_vault::read_seal_pub_pem().map_err(|e| e.to_string())?)?;
    let session = crate::login::user_session(&document, &dir)?;
    let explicit = explicit_prompt_cap(
        document.section(maknae_config::TRANSPORT_SECTION),
        transport.prompt_max_bytes,
    );
    let write_max = transport.prompt_max_bytes;
    let mut transport = transport;
    transport.prompt_max_bytes = loop_prompt_cap(context.context_tokens(), explicit);
    let client = PlaneClient::for_user(&document, &dir, token_copy(&session.token)?)
        .map_err(|e| e.to_string())?;
    let ca = maknae_vault::load_ca_pin(&dir).map_err(|e| e.to_string())?;
    client.mint().await.map_err(|e| e.to_string())?;
    let mut plane = RealPlane {
        transport: &transport,
        client: &client,
        ca: &ca,
        output_tokens: context.output_tokens(),
        write_max,
        api: &session.api,
        token: &session.token,
        key: KeyContext {
            entry,
            kv_mount,
            user_prefix,
            username: &username,
            seal_key: &seal_key,
            expires_at: session.expires_at,
        },
    };
    let mut transcript = Transcript::new(mint_conversation_id(), &prompt);
    let budget = Budget {
        max_steps: agent.max_steps,
        max_tool_calls_per_step: agent.max_tool_calls_per_step,
    };
    let outcome = drive(
        &mut plane,
        &mut transcript,
        &budget,
        &mut Meter::new(context),
        &mut |n| eprintln!("{}", warning_line(n)),
    )
    .await;
    client.shutdown().await;
    if let Some(answer) = outcome.answer {
        println!("{answer}");
        return Ok(0);
    }
    eprintln!(
        "maknae agent: {}",
        stop_line(outcome.stopped.as_ref(), &budget)
    );
    Ok(2)
}

#[cfg(test)]
mod tests {
    use super::*;
    fn yaml(s: &str) -> maknae_config::Value {
        maknae_config::load_str(s).unwrap()
    }
    #[test]
    fn only_a_set_prompt_max_bytes_is_explicit() {
        let set = yaml("prompt_max_bytes: 65536\n");
        assert_eq!(explicit_prompt_cap(Some(&set), 65_536), Some(65_536));
        let other = yaml("read_timeout_ms: 5000\n");
        assert_eq!(explicit_prompt_cap(Some(&other), 1_048_576), None);
        assert_eq!(explicit_prompt_cap(None, 1_048_576), None);
    }
    #[test]
    fn the_loops_cap_is_the_smaller_of_explicit_and_derived() {
        assert_eq!(loop_prompt_cap(128_000, None), 768_000);
        assert_eq!(loop_prompt_cap(128_000, Some(65_536)), 65_536);
        assert_eq!(loop_prompt_cap(1_537, Some(1_048_576)), 65_536);
    }
    const FULL_PATH: &str = "maknae-kv/data/maknae/users/alice/openai/personal";

    fn entry() -> maknae_config::UserProviderEntry {
        maknae_config::UserProviderEntry {
            label: "work".into(),
            provider: "openai".into(),
            model: "gpt-5.6-luna".into(),
            key_subpath: "openai/personal".into(),
            key_field: "api_key".into(),
            context_tokens: 128_000,
            output_tokens: Some(16_000),
            default: true,
        }
    }

    fn key<'a>(
        e: &'a maknae_config::UserProviderEntry,
        seal_key: &'a maknae_seal::SealPublicKey,
        kv_mount: &'a str,
    ) -> KeyContext<'a> {
        KeyContext {
            entry: e,
            kv_mount,
            user_prefix: "maknae/users",
            username: "alice",
            seal_key,
            expires_at: 10_000,
        }
    }

    fn wrapped(token: &str) -> maknae_vault::WrappedSecret {
        maknae_vault::WrappedSecret {
            token: maknae_vault::WrappingToken::new(zeroize::Zeroizing::new(token.into())).unwrap(),
            ttl: std::time::Duration::from_secs(60),
            creation_path: FULL_PATH.into(),
            creation_time: "2026-10-02T00:00:00Z".into(),
        }
    }

    fn aad(
        conversation: &str,
        provider: &str,
        model: &str,
        path: &str,
        field: &str,
    ) -> maknae_seal::SealAad {
        maknae_seal::SealAad::new(&maknae_seal::SealContext {
            conversation,
            provider,
            model,
            expected_path: path,
            key_field: field,
        })
        .unwrap()
    }

    #[test]
    fn both_vault_key_locations_are_required_and_each_is_named() {
        assert_eq!(
            key_location(Some("maknae-kv"), Some("maknae/users")),
            Ok(("maknae-kv", "maknae/users"))
        );
        let kv = "vault.kv_mount is not set in your maknae.yaml: `sudo maknae enroll` writes it";
        assert_eq!(key_location(None, Some("maknae/users")).unwrap_err(), kv);
        assert_eq!(key_location(None, None).unwrap_err(), kv);
        assert_eq!(
            key_location(Some("maknae-kv"), None).unwrap_err(),
            "vault.user_prefix is not set in your maknae.yaml: `sudo maknae enroll` writes it"
        );
    }

    #[test]
    fn the_entry_is_the_default_or_the_named_label_and_no_entries_means_no_model_access() {
        let dir = std::path::Path::new("/home/alice/.maknae");
        let none = maknae_config::user_providers_from_document(&yaml("providers: []\n")).unwrap();
        let no_access =
            "no model access: no providers are defined in /home/alice/.maknae/providers.yaml";
        assert_eq!(choose_entry(&none, None, dir).unwrap_err(), no_access);
        assert_eq!(
            choose_entry(&none, Some("work"), dir).unwrap_err(),
            no_access
        );
        let two = maknae_config::user_providers_from_document(&yaml(
            "providers:\n\
             \x20 - label: work\n    provider: openai\n    model: gpt-5.6-luna\n\
             \x20   key: { subpath: openai/personal, field: api_key }\n\
             \x20   context_tokens: 128000\n    default: true\n\
             \x20 - label: home\n    provider: openai\n    model: gpt-5.6\n\
             \x20   key: { subpath: openai/home, field: api_key }\n\
             \x20   context_tokens: 128000\n",
        ))
        .unwrap();
        assert_eq!(choose_entry(&two, None, dir).unwrap().label, "work");
        assert_eq!(choose_entry(&two, Some("home"), dir).unwrap().label, "home");
        let unknown = choose_entry(&two, Some("nope"), dir).unwrap_err();
        assert!(unknown.contains("nope"), "{unknown}");
    }

    #[tokio::test]
    async fn a_turn_reads_the_wrapped_key_then_seals_it_to_exactly_this_request() {
        let recipient = maknae_seal::SealPrivateKey::generate().unwrap();
        let e = entry();
        let k = key(&e, recipient.public_key(), "maknae-kv");
        let asked = std::sync::Mutex::new(Vec::new());
        let choice = turn_choice(&k, "c-153", 1_000, |path| {
            asked.lock().unwrap().push(path);
            async { Ok(wrapped("hvs.wrap-sentinel-153")) }
        })
        .await
        .unwrap();
        assert_eq!(
            *asked.lock().unwrap(),
            ["maknae/users/alice/openai/personal"]
        );
        assert_eq!(
            (
                choice.provider.as_str(),
                choice.model.as_str(),
                choice.key_subpath.as_str(),
                choice.key_field.as_str()
            ),
            ("openai", "gpt-5.6-luna", "openai/personal", "api_key")
        );
        let sealed = choice.sealed_key.as_bytes();
        let opened = maknae_seal::open(
            &recipient,
            &aad("c-153", "openai", "gpt-5.6-luna", FULL_PATH, "api_key"),
            sealed,
        )
        .unwrap();
        assert!(opened.as_slice() == b"hvs.wrap-sentinel-153");
        for (i, other) in [
            aad("c-154", "openai", "gpt-5.6-luna", FULL_PATH, "api_key"),
            aad("c-153", "anthropic", "gpt-5.6-luna", FULL_PATH, "api_key"),
            aad("c-153", "openai", "gpt-5.6", FULL_PATH, "api_key"),
            aad(
                "c-153",
                "openai",
                "gpt-5.6-luna",
                "maknae/users/alice/openai/personal",
                "api_key",
            ),
            aad(
                "c-153",
                "openai",
                "gpt-5.6-luna",
                "maknae-kv/data/maknae/users/bob/openai/personal",
                "api_key",
            ),
            aad("c-153", "openai", "gpt-5.6-luna", FULL_PATH, "org"),
        ]
        .iter()
        .enumerate()
        {
            assert!(
                matches!(
                    maknae_seal::open(&recipient, other, sealed),
                    Err(maknae_seal::SealError::Open)
                ),
                "AAD row {i} opened"
            );
        }
    }

    #[tokio::test]
    async fn an_expired_login_stops_the_turn_before_vault_is_asked() {
        let recipient = maknae_seal::SealPrivateKey::generate().unwrap();
        let e = entry();
        let k = key(&e, recipient.public_key(), "maknae-kv");
        let mut asked = 0;
        let got = turn_choice(&k, "c-153", 9_941, |_| {
            asked += 1;
            async { Ok(wrapped("hvs.wrap-sentinel-153")) }
        })
        .await;
        assert_eq!(got.unwrap_err(), LOGIN_EXPIRED);
        assert_eq!(asked, 0);
        assert_eq!(
            LOGIN_EXPIRED,
            "your Vault login expired: run `maknae login`"
        );
        assert_eq!(maknae_vault::TOKEN_EXPIRY_MARGIN.as_secs(), 60);
        assert!(!login_expired(10_000, 9_939));
        assert!(login_expired(10_000, 9_940));
        assert!(login_expired(10_000, 9_941));
        assert!(login_expired(10_000, 10_000));
        assert!(login_expired(10_000, 10_001));
    }

    #[tokio::test]
    async fn an_unformable_key_path_is_refused_before_vault_is_asked() {
        let recipient = maknae_seal::SealPrivateKey::generate().unwrap();
        let e = entry();
        let long_mount = "k".repeat(1_000);
        let k = key(&e, recipient.public_key(), &long_mount);
        let mut asked = 0;
        let got = turn_choice(&k, "c-153", 1_000, |_| {
            asked += 1;
            async { Ok(wrapped("hvs.wrap-sentinel-153")) }
        })
        .await;
        assert_eq!(
            got.unwrap_err(),
            "provider entry work: its key's Vault path is not acceptable (check vault.kv_mount, vault.user_prefix and the entry's key subpath)"
        );
        assert_eq!(asked, 0);
    }

    #[tokio::test]
    async fn a_failed_key_read_is_named_and_never_shows_the_path_field_or_token() {
        use maknae_vault::VaultError;
        let recipient = maknae_seal::SealPrivateKey::generate().unwrap();
        let e = entry();
        let k = key(&e, recipient.public_key(), "maknae-kv");
        let rows = [
            (
                VaultError::VaultStatus {
                    op: "wrapped KV read",
                    status: 403,
                    hint: "the token is expired or revoked (run `maknae login`), or the path is outside your grant",
                },
                "Vault refused to read the key for provider entry work (HTTP 403): the key is outside your Vault policy, or your login was revoked: run `maknae login`",
            ),
            (
                VaultError::VaultStatus {
                    op: "wrapped KV read",
                    status: 404,
                    hint: "no secret at this path",
                },
                "no key is stored in Vault for provider entry work: store it, then retry",
            ),
            (
                VaultError::VaultTransport {
                    op: "wrapped KV read",
                    detail: "connection refused".into(),
                },
                "reading the key for provider entry work from Vault failed: Vault wrapped KV read failed: connection refused",
            ),
            (
                VaultError::WrapMismatch(maknae_vault::WrapMismatch::CreationPath),
                "reading the key for provider entry work from Vault failed: wrapping token refused: the token wraps a different path than this request names",
            ),
        ];
        for (failure, want) in rows {
            let got = turn_choice(&k, "c-153", 1_000, |_| async move { Err(failure) })
                .await
                .unwrap_err();
            assert_eq!(got, want);
            for secret in [
                "openai/personal",
                "api_key",
                "alice",
                "maknae/users",
                "maknae-kv",
                "hvs.",
            ] {
                assert!(!got.contains(secret), "{secret} in {got}");
            }
        }
    }

    #[test]
    fn the_published_seal_key_must_parse_and_a_token_copy_is_the_same_token() {
        let k = maknae_seal::SealPrivateKey::generate().unwrap();
        assert!(seal_key_from(&k.public_key().to_pem()).unwrap() == *k.public_key());
        assert_eq!(
            seal_key_from("-----BEGIN PUBLIC KEY-----\nAAAA\n-----END PUBLIC KEY-----\n").unwrap_err(),
            "the Egress Daemon public key published on this host is not usable (the sealing public key is not a canonical P-384 SubjectPublicKeyInfo PEM): ask your administrator to run `sudo maknae enroll`"
        );
        let t =
            maknae_vault::UserToken::new(zeroize::Zeroizing::new("hvs.copy-153".into())).unwrap();
        assert!(token_copy(&t).unwrap().expose() == "hvs.copy-153");
    }

    #[test]
    fn an_unauthorized_prompt_prints_one_line_that_names_what_to_check_and_nothing_else() {
        assert_eq!(
            prompt_outcome(Ok(SentOutcome::Refused {
                code: maknae_proto::ProtoErrCode::Unauthorized,
                message: "not authorized".into(),
                armed: false,
            })),
            Err(PlaneError::Refused)
        );
        assert_eq!(
            PROMPT_REFUSED,
            "the kernel refused the exchange — whether the prompt reached the provider is in the host's audit trail (ask your administrator); if it did not, check that your providers.yaml names a provider and model your administrator has authorized for your role and the key subpath and field of your own Vault secret, that your maknae.yaml vault block matches the host's, and that your login is current (maknae login)"
        );
        let b = Budget {
            max_steps: 8,
            max_tool_calls_per_step: 4,
        };
        assert_eq!(
            stop_line(Some(&StopReason::PromptRefused), &b),
            format!("stopped: {PROMPT_REFUSED}")
        );
    }

    #[tokio::test]
    async fn the_sealed_key_opens_under_the_creation_path_the_egress_daemon_expects() {
        let secret_path =
            maknae_config::user_key_path("maknae/users", "alice", "openai/personal").unwrap();
        let expect = maknae_vault::WrapExpectation::new(
            "maknae-kv",
            &secret_path,
            "api_key",
            maknae_vault::USER_KEY_WRAP_TTL,
        )
        .unwrap();
        assert_eq!(
            maknae_vault::kv_data_path("maknae-kv", &secret_path)
                .unwrap()
                .as_str(),
            expect.creation_path()
        );
        assert_eq!(expect.creation_path(), FULL_PATH);
        let recipient = maknae_seal::SealPrivateKey::generate().unwrap();
        let e = entry();
        let k = key(&e, recipient.public_key(), "maknae-kv");
        let choice = turn_choice(&k, "c-153", 1_000, |_| async {
            Ok(wrapped("hvs.wrap-sentinel-153"))
        })
        .await
        .unwrap();
        let p = maknae_vault::aad_parts(&expect, "c-153", "openai", "gpt-5.6-luna");
        let egress = aad(
            p.conversation,
            p.provider,
            p.model,
            p.expected_path,
            p.key_field,
        );
        let opened = maknae_seal::open(&recipient, &egress, choice.sealed_key.as_bytes()).unwrap();
        assert!(opened.as_slice() == b"hvs.wrap-sentinel-153");
    }
    #[test]
    fn the_warning_and_stop_lines_are_exact() {
        assert_eq!(
            warning_line(&Notice {
                percent: 82,
                tokens: 104_960,
                budget: 128_000,
                estimated: false
            }),
            "warning: this conversation is at 82% of the declared context budget (104,960 of 128,000 tokens)"
        );
        assert_eq!(
            warning_line(&Notice {
                percent: 80,
                tokens: 800,
                budget: 1_000,
                estimated: true
            }),
            "warning: this conversation is at 80% of the declared context budget (800 of 1,000 tokens) — estimated from bytes; the provider has not reported usage"
        );
        assert_eq!(thousands(16_777_216), "16,777,216");
        assert_eq!(thousands(999), "999");
        let b = Budget {
            max_steps: 8,
            max_tool_calls_per_step: 4,
        };
        assert_eq!(
            stop_line(Some(&StopReason::ContextBudget), &b),
            "stopped: the conversation has reached the declared context budget; compaction arrives with #171"
        );
        assert_eq!(
            stop_line(Some(&StopReason::StepBudget), &b),
            "stopped: the step budget (8) was spent without an answer"
        );
        assert_eq!(
            stop_line(Some(&StopReason::TooManyToolCalls(5)), &b),
            "stopped: the model asked for 5 tools in one step (cap 4)"
        );
        assert_eq!(stop_line(None, &b), "stopped");
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
        // The actual case: a BARE `agent:` key reaches this function as
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
    fn the_loops_basis_becomes_the_clients_check() {
        use crate::mutation::WriteCheck;
        assert_eq!(check_for(ReadBasis::Unread), WriteCheck::Unread);
        assert_eq!(check_for(ReadBasis::Read([4; 7])), WriteCheck::Read([4; 7]));
    }
    #[test]
    fn the_loops_same_content_agrees_with_the_file_versions() {
        let base = maknae_io::FileVersion {
            dev: 1,
            ino: 2,
            size: 3,
            mtime: 4,
            mtime_nsec: 5,
            ctime: 6,
            ctime_nsec: 7,
        };
        let changed: [fn(&mut maknae_io::FileVersion); 7] = [
            |v| v.dev += 1,
            |v| v.ino += 1,
            |v| v.size += 1,
            |v| v.mtime += 1,
            |v| v.mtime_nsec += 1,
            |v| v.ctime += 1,
            |v| v.ctime_nsec += 1,
        ];
        for (i, change) in changed.iter().enumerate() {
            let mut v = base;
            change(&mut v);
            assert_eq!(
                maknae_agent::plane::same_content(&base.key(), &v.key()),
                base.same_content(&v),
                "field {i}"
            );
        }
    }
    #[test]
    fn a_write_is_applied_only_for_a_clean_completion_and_unknown_for_everything_else() {
        // ADR-0023 d4: the wire cannot distinguish uncertain from refused
        // on the write lane, so only a clean `applied: true` — and, since #388,
        // a client-decided `stale` refusal — may claim certainty. `NotSent` is
        // absent by construction: it is decided from `write_request`'s `Err`,
        // before `send_verb` is called.
        use maknae_proto::{Payload, ProtoErrCode};
        assert_eq!(
            write_outcome(Ok(SentOutcome::WriteDone {
                applied: true,
                stale: false,
                version: None
            })),
            WriteOutcome::Applied(None)
        );
        assert_eq!(
            write_outcome(Ok(SentOutcome::WriteDone {
                applied: true,
                stale: false,
                version: Some([2; 7])
            })),
            WriteOutcome::Applied(Some([2; 7]))
        );
        assert_eq!(
            write_outcome(Ok(SentOutcome::WriteDone {
                applied: false,
                stale: true,
                version: None
            })),
            WriteOutcome::Stale
        );
        assert_eq!(
            write_outcome(Ok(SentOutcome::WriteDone {
                applied: false,
                stale: false,
                version: None
            })),
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
    fn a_prompt_is_malformed_only_for_bad_request_and_refused_for_every_other_code() {
        // The control: `maknae agent "   "` is refused `BadRequest` for
        // carrying no text to send, and that refusal is decided BEFORE any
        // exchange — no egress block, no intent record, so nothing reached the
        // provider; what the trail holds is the pre-gate deny, not an egress
        // intent. Every other refusal code keeps `Refused`, because
        // `LandedUndelivered`, `DeadlineExpired` and
        // `OutcomeUnknown` all arrive as the same generic `Unauthorized` and
        // the prompt may well have landed.
        use maknae_proto::{Payload, PromptReply, ProtoErrCode};
        let refused = |code| {
            prompt_outcome(Ok(SentOutcome::Refused {
                code,
                message: "prompt carries no text to send".into(),
                armed: false,
            }))
        };
        assert_eq!(
            refused(ProtoErrCode::BadRequest),
            Err(PlaneError::Malformed)
        );
        for code in [
            ProtoErrCode::Unauthorized,
            ProtoErrCode::Internal,
            ProtoErrCode::TooLarge,
            ProtoErrCode::UnknownVerb,
            ProtoErrCode::NotImplemented,
        ] {
            assert_eq!(refused(code.clone()), Err(PlaneError::Refused), "{code:?}");
        }
        assert_eq!(
            prompt_outcome(Ok(SentOutcome::Payload(Payload::PromptReply(
                PromptReply {
                    blocks: vec![],
                    tool_calls: vec![],
                    usage: None,
                }
            )))),
            Ok(PromptReply {
                blocks: vec![],
                tool_calls: vec![],
                usage: None,
            })
        );
        assert!(matches!(
            prompt_outcome(Ok(SentOutcome::Payload(Payload::Pong))),
            Err(PlaneError::Transport(_))
        ));
        assert!(matches!(
            prompt_outcome(Err("handshake timed out".into())),
            Err(PlaneError::Transport(_))
        ));
    }
    #[test]
    fn a_read_is_refused_only_for_unauthorized_and_unavailable_for_every_other_outcome() {
        // This mapper is a CONTROL, so it is tested: only the authorization
        // code is a refusal the model may not appeal; a BadRequest
        // (`/a/../b`), a protocol error, or a transport error is
        // "unavailable".
        use maknae_proto::{Payload, ProtoErrCode};
        let read = crate::mutation::ReadResult {
            content: zeroize::Zeroizing::new(b"x".to_vec()),
            label: maknae_proto::ObjectLabel {
                level: "UNCLASSIFIED".into(),
                categories: vec![],
            },
            page: crate::mutation::PageMeta {
                start: 0,
                lines: Some((1, 1)),
                complete_last: true,
                next: None,
                eof: true,
                version: maknae_io::FileVersion::default(),
            },
        };
        assert_eq!(
            read_outcome(Ok(SentOutcome::ReadDone { read: Some(read) })),
            ReadOutcome::Content(ReadPage {
                content: zeroize::Zeroizing::new(b"x".to_vec()),
                level: "UNCLASSIFIED".into(),
                lines: Some((1, 1)),
                complete_line: true,
                next: None,
                eof: true,
                version: maknae_io::FileVersion::default().key(),
                changed: false,
            })
        );
        assert_eq!(
            read_outcome(Ok(SentOutcome::ReadDone { read: None })),
            ReadOutcome::Unavailable
        );
        assert_eq!(
            read_outcome(Ok(SentOutcome::Payload(Payload::Pong))),
            ReadOutcome::Unavailable
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
        // subject's own `open_path_for_delegation` failed (ENOENT), the
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
            read_outcome(Ok(SentOutcome::WriteDone {
                applied: true,
                stale: false,
                version: None
            })),
            ReadOutcome::Unavailable
        );
        assert_eq!(
            read_outcome(Err("handshake timed out".into())),
            ReadOutcome::Unavailable
        );
    }
}
