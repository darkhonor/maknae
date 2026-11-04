//! `maknae agent` — the HANDS of the runtime loop (#241). T3: I/O wiring over
//! the brain in `maknae-agent`. Runs as the subject, holds no key and no
//! policy, and asks the kernel for everything (ADR-0023 d2, d4).
use maknae_agent::budget::{prompt_cap, ContextBudget, Notice};
use maknae_agent::drive::{Budget, LoopEvent, Outcome, StopReason};
use maknae_agent::plane::Plane;
use maknae_agent::session::Session;
use maknae_config::{UserProviderEntry, UserProviders, Value};
use maknae_loop::keys::KeySupply;
use maknae_loop::plane::LoopPlane;
use maknae_proto::{ProviderChoice, SealedKey};
use maknae_seal::{SealAad, SealContext, SealPublicKey};
use maknae_vault::{
    aad_parts, PlaneClient, UserToken, VaultApi, VaultError, WrapExpectation, WrappedSecret,
    USER_KEY_WRAP_TTL,
};
use std::future::Future;
use std::io::Write;
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

pub const EGRESS_UNAVAILABLE: &str = "the model service is at capacity or restarting, and nothing was sent to the provider: try again in a moment";

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

/// The user host's key supply: each turn reads the subject's own wrapped key
/// under their login and seals it to exactly that request (ADR-0028).
pub struct UserLoginKeys {
    pub api: VaultApi,
    pub token: UserToken,
    pub entry: UserProviderEntry,
    pub kv_mount: String,
    pub user_prefix: String,
    pub username: String,
    pub seal_key: SealPublicKey,
    pub expires_at: u64,
}

impl KeySupply for UserLoginKeys {
    async fn choice(&mut self, conversation: &str, now: u64) -> Result<ProviderChoice, String> {
        let key = KeyContext {
            entry: &self.entry,
            kv_mount: &self.kv_mount,
            user_prefix: &self.user_prefix,
            username: &self.username,
            seal_key: &self.seal_key,
            expires_at: self.expires_at,
        };
        let (api, token, kv_mount) = (&self.api, &self.token, self.kv_mount.as_str());
        turn_choice(&key, conversation, now, |path| async move {
            api.read_wrapped(token, kv_mount, &path, maknae_vault::USER_KEY_WRAP_TTL)
                .await
        })
        .await
    }
}

pub fn reply_unusable_line(d: maknae_proto::ReplyDefect) -> &'static str {
    use maknae_proto::ReplyDefect as D;
    match d {
        D::Malformed => "the provider's reply was not a chat completion: check that this entry's endpoint and model are OpenAI-compatible",
        D::NoChoices => "the provider's reply carried no answer: retry, or choose another model",
        D::Empty => "the provider's reply was empty: retry, or choose another model",
        D::ReasoningOnly => "the model reasoned but gave no final answer: retry, or choose another model",
        D::TokenLimit => "the model reached its reply token limit before answering: raise output_tokens for this entry in your providers.yaml",
        D::UnknownTool => "the model asked for a tool Maknae does not offer: choose another model",
        D::OverBound => "the model's reply exceeded a platform limit: ask for the work in smaller pieces",
        D::ProviderAuth => "the provider refused this key, or its access to this entry's model: check the key stored in your Vault secret for this entry, and the model name",
        D::ProviderRateLimit => "the provider is rate-limiting this key: wait and retry, or check your quota with the provider",
        D::ProviderRejected => "the provider rejected the request: check this entry's model name, and ask your administrator for the provider's reason in the Egress Daemon's journal",
        D::ProviderError => "the provider failed to answer: retry later",
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
        Some(StopReason::ReplyUnusable(d)) => format!("stopped: {}", reply_unusable_line(*d)),
        Some(StopReason::EgressUnavailable) => format!("stopped: {EGRESS_UNAVAILABLE}"),
        Some(StopReason::Transport(m)) => format!("stopped: {m}"),
        Some(StopReason::ContextBudget) => "stopped: the conversation has reached the declared context budget; compaction arrives with #171".into(),
        Some(StopReason::Stopped) => "stopped: the loop was asked to stop".into(),
        Some(StopReason::NothingPending) => "stopped: there was no prompt to answer".into(),
        None => "stopped".into(),
    }
}

/// The lines a run prints while it is going: notices and the plane's
/// diagnostics, on stderr. The answer and the stop line are [`print_end`]'s.
pub fn print_event(e: &LoopEvent, err: &mut impl Write) -> std::io::Result<()> {
    match e {
        LoopEvent::Notice(n) => writeln!(err, "{}", warning_line(n)),
        LoopEvent::Diagnostic(d) => writeln!(err, "{d}"),
        _ => Ok(()),
    }
}

pub fn print_end(
    outcome: &Outcome,
    budget: &Budget,
    out: &mut impl Write,
    err: &mut impl Write,
) -> std::io::Result<u8> {
    if let Some(answer) = &outcome.answer {
        writeln!(out, "{answer}")?;
        return Ok(0);
    }
    writeln!(
        err,
        "maknae agent: {}",
        stop_line(outcome.stopped.as_ref(), budget)
    )?;
    Ok(2)
}

/// A failed print stops the session before its next plane call, so nothing new
/// is started on the subject's behalf after output is lost; a granted attempt finishes.
pub async fn drive_to<P: Plane + Send>(
    session: &mut Session,
    plane: &mut P,
    err: &mut (impl Write + Send),
) -> std::io::Result<Outcome> {
    let handle = session.handle();
    let mut failed: Option<std::io::Error> = None;
    let outcome = session
        .run(plane, &mut |e| {
            if failed.is_none() {
                if let Err(e) = print_event(&e, err) {
                    handle.stop();
                    failed = Some(e);
                }
            }
        })
        .await;
    match failed {
        Some(e) => Err(e),
        None => Ok(outcome),
    }
}

/// Mirrors `execute()`'s setup (FIPS provider, config, user token, mint).
const HOME_SNAPSHOT_TIMEOUT: std::time::Duration =
    std::time::Duration::from_millis(maknae_config::HOME_RESOLVE_TIMEOUT_MS);

/// A stalled passwd service or home mount leaves the session without `~`,
/// never without a session.
async fn snapshot_home<F>(timeout: std::time::Duration, resolve: F) -> Option<String>
where
    F: FnOnce() -> Option<std::path::PathBuf> + Send + 'static,
{
    match tokio::time::timeout(timeout, tokio::task::spawn_blocking(resolve)).await {
        Ok(Ok(Some(home))) => home.to_str().map(str::to_string),
        _ => None,
    }
}

pub async fn run(label: Option<String>, prompt: String) -> Result<u8, String> {
    maknae_crypto::init().map_err(|e| maknae_vault::crypto_refusal_message(&e))?;
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
    let id = maknae_loop::id::mint_conversation_id()?;
    // One snapshot per session: `~` cannot change meaning for this process (#596).
    let home = snapshot_home(HOME_SNAPSHOT_TIMEOUT, maknae_io::session_home).await;
    let client = PlaneClient::for_user(&document, &dir, token_copy(&session.token)?)
        .map_err(|e| e.to_string())?;
    let ca = maknae_vault::load_ca_pin(&dir).map_err(|e| e.to_string())?;
    client.mint().await.map_err(|e| e.to_string())?;
    let keys = UserLoginKeys {
        api: session.api,
        token: session.token,
        entry: entry.clone(),
        kv_mount: kv_mount.to_string(),
        user_prefix: user_prefix.to_string(),
        username,
        seal_key,
        expires_at: session.expires_at,
    };
    let mut plane = LoopPlane::new(
        transport,
        client,
        ca,
        context.output_tokens(),
        write_max,
        keys,
    );
    let budget = Budget {
        max_steps: agent.max_steps,
        max_tool_calls_per_step: agent.max_tool_calls_per_step,
    };
    let mut session = Session::new(id, &prompt, budget, context, home);
    let outcome = drive_to(&mut session, &mut plane, &mut std::io::stderr()).await;
    plane.into_client().shutdown().await;
    let outcome = outcome.map_err(|e| e.to_string())?;
    print_end(
        &outcome,
        &budget,
        &mut std::io::stdout(),
        &mut std::io::stderr(),
    )
    .map_err(|e| e.to_string())
}

#[cfg(test)]
mod tests {
    #[tokio::test]
    async fn a_stalled_home_lookup_snapshots_no_home() {
        let fast = std::time::Duration::from_millis(20);
        let stalled = super::snapshot_home(fast, || {
            std::thread::sleep(std::time::Duration::from_secs(2));
            Some("/home/late".into())
        });
        let started = std::time::Instant::now();
        assert_eq!(stalled.await, None);
        assert!(started.elapsed() < std::time::Duration::from_secs(1));
    }

    #[tokio::test]
    async fn a_prompt_home_lookup_is_snapshotted() {
        let patient = std::time::Duration::from_secs(10);
        assert_eq!(
            super::snapshot_home(patient, || Some("/home/b".into())).await,
            Some("/home/b".to_string())
        );
        assert_eq!(super::snapshot_home(patient, || None).await, None);
    }

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
    fn an_unavailable_egress_says_so_and_that_nothing_was_sent() {
        let b = Budget {
            max_steps: 8,
            max_tool_calls_per_step: 4,
        };
        assert_eq!(
            stop_line(Some(&StopReason::EgressUnavailable), &b),
            "stopped: the model service is at capacity or restarting, and nothing was sent to the provider: try again in a moment"
        );
    }

    #[test]
    fn an_unauthorized_prompt_prints_one_line_that_names_what_to_check_and_nothing_else() {
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
            stop_line(Some(&StopReason::Stopped), &b),
            "stopped: the loop was asked to stop"
        );
        assert_eq!(
            stop_line(Some(&StopReason::NothingPending), &b),
            "stopped: there was no prompt to answer"
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
    fn every_reply_defect_has_a_distinct_line_that_never_blames_authorization() {
        let b = Budget {
            max_steps: 8,
            max_tool_calls_per_step: 4,
        };
        let mut seen = std::collections::HashSet::new();
        for d in maknae_proto::ReplyDefect::ALL {
            let line = stop_line(Some(&StopReason::ReplyUnusable(d)), &b);
            assert!(line.starts_with("stopped: "), "{line}");
            assert!(!line.contains("authorized"), "{d:?}: {line}");
            assert!(!line.contains(PROMPT_REFUSED), "{d:?}");
            assert!(seen.insert(line), "{d:?} shares its line");
        }
        let line = |d| stop_line(Some(&StopReason::ReplyUnusable(d)), &b);
        assert!(line(maknae_proto::ReplyDefect::TokenLimit).contains("output_tokens"));
        assert!(line(maknae_proto::ReplyDefect::ProviderAuth).contains("Vault secret"));
    }
    mod printer {
        use super::*;
        use maknae_agent::drive::Outcome;
        use maknae_agent::plane::{PlaneError, ReadBasis, ReadOutcome, WriteOutcome};
        use maknae_agent::session::Session;
        use maknae_proto::Turn;
        use maknae_proto::{ContentBlock, PromptReply, ProposedToolCall, SecretText};
        use std::collections::VecDeque;

        const ARMING: &str = "maknae: cannot prepare filesystem operation: x";
        const ATTEMPT: &str = "mutation stopped: OsRefused; 0 effect(s) reported";

        fn reply(text: Option<&str>, calls: &[(&str, &str)]) -> PromptReply {
            PromptReply {
                reasoning: None,
                blocks: text
                    .map(|t| {
                        vec![ContentBlock::Text {
                            text: SecretText(zeroize::Zeroizing::new(t.into())),
                        }]
                    })
                    .unwrap_or_default(),
                tool_calls: calls
                    .iter()
                    .map(|(id, path)| ProposedToolCall {
                        name: "write_file".into(),
                        call_id: (*id).into(),
                        arguments: SecretText(zeroize::Zeroizing::new(format!(
                            r#"{{"path":"{path}","content":"x"}}"#
                        ))),
                        refused: None,
                    })
                    .collect(),
                usage: None,
            }
        }

        struct Fake {
            replies: VecDeque<PromptReply>,
            write_diags: VecDeque<&'static str>,
            queued: Vec<String>,
            prompts: usize,
            writes: usize,
        }
        impl Plane for Fake {
            async fn prompt(
                &mut self,
                _c: &str,
                _t: &[Turn],
            ) -> Result<maknae_proto::PromptReply, PlaneError> {
                self.prompts += 1;
                Ok(self.replies.pop_front().expect("script exhausted"))
            }
            async fn read(
                &mut self,
                _c: &str,
                _p: &str,
                _page: maknae_proto::PageRequest,
            ) -> ReadOutcome {
                ReadOutcome::Unavailable
            }
            async fn write(
                &mut self,
                _c: &str,
                _p: &str,
                _b: &[u8],
                _b2: ReadBasis,
            ) -> WriteOutcome {
                self.writes += 1;
                if let Some(d) = self.write_diags.pop_front() {
                    self.queued.push(d.into());
                }
                WriteOutcome::Applied(None)
            }
            fn take_diagnostics(&mut self) -> Vec<String> {
                std::mem::take(&mut self.queued)
            }
        }
        fn fake(replies: Vec<PromptReply>) -> Fake {
            Fake {
                replies: replies.into(),
                write_diags: VecDeque::new(),
                queued: vec![],
                prompts: 0,
                writes: 0,
            }
        }
        fn budget() -> Budget {
            Budget {
                max_steps: 8,
                max_tool_calls_per_step: 4,
            }
        }
        fn unmetered() -> ContextBudget {
            ContextBudget::new(maknae_proto::MAX_CONTEXT_TOKENS, None).unwrap()
        }

        async fn host(
            mut session: Session,
            plane: &mut Fake,
        ) -> (Vec<u8>, Vec<u8>, std::io::Result<u8>) {
            let (mut out, mut err) = (vec![], vec![]);
            let code = match drive_to(&mut session, plane, &mut err).await {
                Ok(outcome) => print_end(&outcome, &session.budget(), &mut out, &mut err),
                Err(e) => Err(e),
            };
            (out, err, code)
        }

        #[tokio::test]
        async fn the_agent_printer_is_byte_identical() {
            let (out, err, code) = host(
                Session::new("c", "q", budget(), unmetered(), None),
                &mut fake(vec![reply(Some("ok"), &[])]),
            )
            .await;
            assert_eq!((out, err, code.unwrap()), (b"ok\n".to_vec(), vec![], 0));

            let (out, err, code) = host(
                Session::new(
                    "c",
                    &"q".repeat(1_800),
                    budget(),
                    ContextBudget::new(2_000, None).unwrap(),
                    None,
                ),
                &mut fake(vec![reply(Some("ok"), &[])]),
            )
            .await;
            let notice = Notice {
                percent: 99,
                tokens: 1_986,
                budget: 2_000,
                estimated: true,
            };
            assert_eq!(out, b"ok\n");
            assert_eq!(
                String::from_utf8(err).unwrap(),
                format!("{}\n", warning_line(&notice))
            );
            assert_eq!(code.unwrap(), 0);

            let b = budget();
            let every = [
                StopReason::StepBudget,
                StopReason::TooManyToolCalls(5),
                StopReason::FrameBound,
                StopReason::PromptRefused,
                StopReason::PromptMalformed,
                StopReason::ReplyUnusable(maknae_proto::ReplyDefect::Empty),
                StopReason::EgressUnavailable,
                StopReason::Transport("t".into()),
                StopReason::ContextBudget,
                StopReason::Stopped,
                StopReason::NothingPending,
            ];
            for r in &every {
                match r {
                    StopReason::StepBudget
                    | StopReason::TooManyToolCalls(_)
                    | StopReason::FrameBound
                    | StopReason::PromptRefused
                    | StopReason::PromptMalformed
                    | StopReason::ReplyUnusable(_)
                    | StopReason::EgressUnavailable
                    | StopReason::Transport(_)
                    | StopReason::ContextBudget
                    | StopReason::Stopped
                    | StopReason::NothingPending => {}
                }
                let (mut out, mut err) = (vec![], vec![]);
                let outcome = Outcome {
                    answer: None,
                    stopped: Some(r.clone()),
                    steps_used: 0,
                };
                assert_eq!(print_end(&outcome, &b, &mut out, &mut err).unwrap(), 2);
                assert!(out.is_empty());
                assert_eq!(
                    String::from_utf8(err).unwrap(),
                    format!("maknae agent: {}\n", stop_line(Some(r), &b))
                );
            }
        }

        #[test]
        fn the_agent_printer_matches_literal_bytes() {
            let b = budget();
            for (r, want) in [
                (
                    StopReason::StepBudget,
                    "maknae agent: stopped: the step budget (8) was spent without an answer\n",
                ),
                (
                    StopReason::TooManyToolCalls(5),
                    "maknae agent: stopped: the model asked for 5 tools in one step (cap 4)\n",
                ),
            ] {
                let (mut out, mut err) = (vec![], vec![]);
                let outcome = Outcome {
                    answer: None,
                    stopped: Some(r),
                    steps_used: 0,
                };
                assert_eq!(print_end(&outcome, &b, &mut out, &mut err).unwrap(), 2);
                assert_eq!(String::from_utf8(err).unwrap(), want);
            }
        }

        #[tokio::test]
        async fn the_agent_printer_interleaves_diagnostics_in_todays_order() {
            let mut p = fake(vec![
                reply(None, &[("c1", "/w/a")]),
                reply(None, &[("c2", "/w/b")]),
                reply(None, &[("c3", "/w/c")]),
            ]);
            p.write_diags = VecDeque::from([ARMING, ATTEMPT]);
            let b = Budget {
                max_steps: 3,
                max_tool_calls_per_step: 4,
            };
            let (out, err, code) = host(
                Session::new(
                    "c",
                    &"q".repeat(1_700),
                    b,
                    ContextBudget::new(2_000, None).unwrap(),
                    None,
                ),
                &mut p,
            )
            .await;
            assert!(out.is_empty());
            assert_eq!(code.unwrap(), 2);
            let err = String::from_utf8(err).unwrap();
            let lines: Vec<&str> = err.lines().collect();
            assert_eq!(lines.len(), 4, "{err}");
            assert!(lines[0].starts_with("warning: "), "{err}");
            assert_eq!(lines[1], ARMING);
            assert_eq!(lines[2], ATTEMPT);
            assert_eq!(
                lines[3],
                format!(
                    "maknae agent: {}",
                    stop_line(Some(&StopReason::StepBudget), &b)
                )
            );
            assert!(err.ends_with('\n'));
        }

        struct Broken;
        impl std::io::Write for Broken {
            fn write(&mut self, _: &[u8]) -> std::io::Result<usize> {
                Err(std::io::Error::from(std::io::ErrorKind::BrokenPipe))
            }
            fn flush(&mut self) -> std::io::Result<()> {
                Ok(())
            }
        }

        #[tokio::test]
        async fn a_failed_notice_print_sends_no_prompt() {
            let mut p = fake(vec![reply(None, &[("c1", "/w/a"), ("c2", "/w/b")])]);
            let mut session = Session::new(
                "c",
                &"q".repeat(1_800),
                budget(),
                ContextBudget::new(2_000, None).unwrap(),
                None,
            );
            match drive_to(&mut session, &mut p, &mut Broken).await {
                Err(e) => assert_eq!(e.kind(), std::io::ErrorKind::BrokenPipe),
                Ok(_) => panic!("a failed print must surface as an error"),
            }
            assert_eq!((p.prompts, p.writes), (0, 0));
        }

        #[tokio::test]
        async fn a_stderr_write_error_stops_the_loop() {
            let mut p = fake(vec![
                reply(None, &[("c1", "/w/a")]),
                reply(None, &[("c2", "/w/b")]),
                reply(None, &[("c3", "/w/c")]),
                reply(Some("done"), &[]),
            ]);
            p.write_diags = VecDeque::from([ARMING, ARMING, ARMING]);
            let mut session = Session::new("c", "q", budget(), unmetered(), None);
            match drive_to(&mut session, &mut p, &mut Broken).await {
                Err(e) => assert_eq!(e.kind(), std::io::ErrorKind::BrokenPipe),
                Ok(_) => panic!("a failed print must surface as an error"),
            }
            assert_eq!(
                (p.prompts, p.writes),
                (1, 1),
                "nothing ran after the failed print"
            );
        }
    }
}
