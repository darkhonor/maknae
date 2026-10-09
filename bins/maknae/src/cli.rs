//! `maknae` CLI — the untrusted interaction plane (spec §3). Resolves its own
//! config dir, mints a short-lived plane leaf, connects to `maknaed` over the
//! Stage-2 mTLS/UDS transport, and issues one verb per invocation
//! (`ping`/`whoami`) — OR, one-time and elevated, provisions the deployment via
//! `enroll`/`enroll-helper` (`enroll/`, spec §4.1-§4.6, PR-J1 Task 8).
//!
//! **Closed dependency enumeration** (recorded here and in `Cargo.toml`; no gate
//! enforces it): `maknae-proto`, `maknae-vault`, `maknae-config`, `maknae-msgs`,
//! `maknae-io`, `maknae-agent`, `maknae-seal`, `clap`, `tokio`, `nix`, `zeroize`, `yaml-rust2`,
//! and `rpassword` (`bins/maknae/Cargo.toml`).
//! *(Corrected 2026-09-22, #241: `maknae-io` was missing from both this list and
//! the "wire path" sentence below, though it has been a direct dependency and on
//! the wire path since ADR-0009 arming landed.)* The `ping`/`whoami` wire path
//! below uses only `maknae-proto`, `maknae-vault`, `maknae-config`, `maknae-msgs`,
//! `clap` and `maknae-io` (delegation arming — `mutation.rs`); `maknae-agent` and `maknae-seal` are the agent loop's
//! (`agent.rs`) alone; `yaml-rust2`/`rpassword` are
//! `enroll/`-only, and `nix`/`zeroize` serve `enroll/` and `login`/`tty`. NO privileged crate
//! (`maknae-kernel`/`-subject-ctx-mint`/`-audit-append`/`-spif-compile`) — spec §3
//! P1 — even for `enroll`: it does its own privileged work via `nix` safe wrappers
//! and process re-exec (`sudo -u`), never by linking the daemon's privileged crates.

use clap::{Parser, Subcommand};
use maknae_config::{load_config, transport_from_section, SectionSpec, TRANSPORT_SECTION};
use maknae_proto::{
    class_of, read_frame_of_class, write_frame, FrameCaps, ATTEMPT_REQUEST_MAX, CONTROL_REQUEST_MAX,
};
use maknae_proto::{
    decode_response, encode_request_zeroizing, Payload, Request, RespResult, PROTOCOL_VERSION,
};
use maknae_vault::{load_ca_pin, PlaneClient, PlaneConnector, VAULT_SECTION};
use std::path::PathBuf;
use std::process::ExitCode;

/// The `MAKNAE_CONFIG_DIR` env var name (overrides the `$HOME/.maknae` default).
const CONFIG_DIR_ENV: &str = "MAKNAE_CONFIG_DIR";

/// Resolve the CLI's own config directory: `MAKNAE_CONFIG_DIR` if set, else
/// `$HOME/.maknae`. This is the CLI's OWN Stage-1 config dir (the user's
/// Vault token custody + CA pin for `Plane::Cli`) — distinct from the daemon's
/// `/etc/maknae` (spec §3).
pub fn resolve_config_dir() -> PathBuf {
    if let Ok(dir) = std::env::var(CONFIG_DIR_ENV) {
        return PathBuf::from(dir);
    }
    let home = std::env::var("HOME").unwrap_or_else(|_| ".".to_string());
    PathBuf::from(home).join(".maknae")
}

/// The section registry the CLI loads its config under: `vault` (required — the CLI
/// mints a plane leaf) + `transport` (optional — the daemon's socket path / frame cap;
/// absent → documented defaults) + `agent` (optional — the loop's own advisory bounds,
/// #241). `core` is auto-registered. Loading ONCE with this combined set is what lets a
/// realistic `vault`+`transport` config load without each section's own loader rejecting
/// the other as `UnknownSection` (the P1-B fix).
///
/// One list serves every verb, so `agent` is ACCEPTED — but not validated — for `ping` as
/// much as for `agent`: the combined registry is what the unknown-section check consults,
/// so the section's presence never fails any verb, while its BOUNDS are read only by
/// `agent_from_section`, whose one production caller is `maknae agent`'s own `run`. A
/// documented residual of the single-registry design, not a per-verb grammar: an `[agent]`
/// section with `max_steps: 1000` loads clean under `maknae ping` and is refused by
/// `maknae agent` (corrected 2026-09-22, #344 — this said "accepted (and validated)",
/// which `execute` never does).
pub(crate) fn cli_config_specs() -> [SectionSpec; 3] {
    [
        SectionSpec {
            name: VAULT_SECTION.to_string(),
            required: true,
        },
        SectionSpec {
            name: TRANSPORT_SECTION.to_string(),
            required: false,
        },
        SectionSpec {
            name: crate::agent::AGENT_SECTION.to_string(),
            required: false,
        },
    ]
}

/// `maknae` — filesystem and management verbs over the mTLS plane, plus elevated
/// enrollment.
#[derive(Parser, Debug)]
#[command(
    name = "maknae",
    about = "CLI for maknaed: filesystem operations, daemon queries, and enrollment"
)]
pub(crate) struct Cli {
    #[command(subcommand)]
    command: Command,
}

/// The top-level subcommand surface. `Ping`/`Whoami` route to the existing
/// wire-path `execute()` below (unchanged behavior); `Enroll`/`EnrollHelper`
/// route to `enroll/` (spec §4.1-§4.6, PR-J1 Task 8). `EnrollHelper` is hidden
/// from `--help` — it is `mod.rs`'s own re-exec target, never operator-invoked.
#[derive(Subcommand, Debug)]
enum Command {
    /// Check that the daemon is reachable.
    Ping,
    /// Report the verified peer plane identity (URI-SAN + uid).
    Whoami,
    /// Read a file under your home: the daemon decides (the policy in
    /// /etc/maknae/authz.yaml), and the CLI reads under your credentials; raw
    /// bytes to stdout. Paths are sent lexically absolute; `..` is refused by
    /// the daemon's canonical pre-gate.
    Read {
        /// File to read (absolute, or relative to the current directory).
        path: std::path::PathBuf,
        /// Read one page starting at this line (1-based) instead of the whole file.
        #[arg(long)]
        offset: Option<u64>,
        /// Read one page of at most this many lines (default 2000).
        #[arg(long)]
        limit: Option<u32>,
        /// Read one page starting this many bytes into its first line.
        #[arg(long)]
        column: Option<u64>,
    },
    /// Write raw stdin bytes to a file. Replaces existing content, or creates
    /// an absent file exclusively. Requires Write authority and OS permission.
    Write { path: PathBuf },
    /// Remove a file, symlink or empty directory. --recursive removes a tree.
    Delete {
        path: PathBuf,
        #[arg(short = 'r', long)]
        recursive: bool,
    },
    /// Create a directory. --parents creates missing parent directories.
    Mkdir {
        path: PathBuf,
        #[arg(short = 'p', long)]
        parents: bool,
    },
    /// Report daemon runtime posture: version, protocol version, listener,
    /// active authorization backend, and any pending baseline change by count and
    /// class. The shipped `authz.yaml` grants `admin.status` to the `admin` role.
    Status,
    /// Show the effective configuration as the daemon resolved it. Secret
    /// values render `<value set>`; some keys are withheld entirely because
    /// their mere presence is a disclosure. Ungranted by default.
    ConfigShow,
    /// Enumerate role bindings as the daemon resolves them right now.
    /// The shipped `authz.yaml` grants `admin.subject.list` to the `admin` role.
    SubjectList,
    /// Show the pending baseline change set: what changed in maknae.yaml or config.d,
    /// rendered as `maknae config-show` renders it, whether it applies live or by a
    /// restart, and the hash `baseline-accept` needs.
    BaselineShow,
    /// Accept the pending baseline change set named by HASH (from `maknae baseline-show`).
    BaselineAccept { hash: String },
    /// Print the accounts `audit.readers` grants read on the audit trail, validated, one
    /// per line. Run as root; the packages call it after every hold of /var/log/maknae.
    /// With --stopped it refuses unless maknaed is stopped (the runbook's file grant).
    AuditReaders {
        #[arg(long)]
        stopped: bool,
    },
    /// Run the agent loop on one prompt (ADR-0023).
    Agent {
        /// The providers.yaml entry to use instead of the default.
        #[arg(long)]
        provider: Option<String>,
        prompt: String,
    },
    /// Log in to Vault as your local account; stores only the token.
    Login,
    /// Revoke and erase your stored Vault token.
    Logout,
    /// One-time elevated provisioning: mint credentials, seal them to the
    /// platform HRoT, write daemon+CLI config (spec §4.1). Requires `sudo`.
    Enroll(Box<crate::enroll::EnrollArgs>),
    /// Authorize maknaed to seed a fresh kernel graph at its next start, keeping a
    /// readable current store aside. Requires `sudo`.
    Reseed,
    /// Root-only bindings maintenance.
    Policy {
        #[command(subcommand)]
        action: PolicyCommand,
    },
    /// Hidden operator-context helper `enroll` re-execs via `sudo -u` — not a
    /// user-facing verb.
    #[command(hide = true, name = "enroll-helper")]
    EnrollHelper(crate::enroll::HelperArgs),
}

#[derive(Subcommand, Debug)]
enum PolicyCommand {
    /// Install maknaed's bindings mirror as /etc/maknae/bindings.yaml. Requires `sudo`.
    Sync {
        /// Print what would change and install nothing.
        #[arg(long)]
        check: bool,
    },
}

/// The verbs the wire path can issue (mirrors `maknae_proto::Verb`).
/// `Clone` (no longer `Copy` — `Read` carries its path), no `clap` derive of
/// its own — `Command::*` above own the argument surface; this is purely the
/// internal wire-path type `execute`/`round_trip`/`print_payload_for_verb`
/// were already built around.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Verb {
    Ping,
    Whoami,
    Read {
        path: String,
        page: Option<maknae_proto::PageRequest>,
    },
    Write {
        path: String,
    },
    Delete {
        path: String,
        recursive: bool,
    },
    Mkdir {
        path: String,
        parents: bool,
    },
    AdminStatus,
    AdminConfigShow,
    AdminSubjectList,
    AdminBaselineShow,
    AdminBaselineAccept {
        hash: AcceptHash,
    },
}

/// The accept operand; Debug shows only the prefix the trail carries.
#[derive(Clone, PartialEq, Eq)]
struct AcceptHash(String);

impl AcceptHash {
    fn short(&self) -> &str {
        self.0.get(..12).unwrap_or("")
    }
}

impl From<String> for AcceptHash {
    fn from(hash: String) -> Self {
        Self(hash)
    }
}

impl std::fmt::Debug for AcceptHash {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "sha256:{}", self.short())
    }
}

impl From<Verb> for maknae_proto::Verb {
    fn from(v: Verb) -> Self {
        match v {
            Verb::Ping => maknae_proto::Verb::Ping,
            Verb::Whoami => maknae_proto::Verb::Whoami,
            Verb::Read { path, page } => maknae_proto::Verb::Read {
                path,
                conversation: None,
                page,
            },
            Verb::Write { path } => maknae_proto::Verb::FsWrite {
                path,
                content_length: 0,
                mode: maknae_proto::WriteMode::Existing,
                conversation: None,
            },
            Verb::Delete { path, recursive } => maknae_proto::Verb::FsDelete { path, recursive },
            Verb::Mkdir { path, parents } => maknae_proto::Verb::FsMkdir {
                path,
                parents,
                components: Vec::new(),
            },
            Verb::AdminStatus => maknae_proto::Verb::AdminStatus,
            Verb::AdminConfigShow => maknae_proto::Verb::AdminConfigShow,
            Verb::AdminSubjectList => maknae_proto::Verb::AdminSubjectList,
            Verb::AdminBaselineShow => maknae_proto::Verb::AdminBaselineShow,
            Verb::AdminBaselineAccept { hash } => {
                maknae_proto::Verb::AdminBaselineAccept { hash: hash.0 }
            }
        }
    }
}

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

// The group lookup, one PDP decision and the audit appends, beyond the egress deadline
// and the reply write.
const PROMPT_REPLY_MARGIN: std::time::Duration = std::time::Duration::from_secs(30);

fn reply_wait(
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
            transport.read_timeout_ms + maknae_config::HOME_RESOLVE_TIMEOUT_MS,
        ),
        maknae_proto::FrameClass::Control => {
            std::time::Duration::from_millis(transport.read_timeout_ms)
        }
    }
}

/// Instant at which the request frame finished writing.
#[must_use]
#[derive(Clone, Copy, Debug)]
pub(crate) struct WriteCompleted(std::time::Instant);

impl WriteCompleted {
    pub(crate) fn at(self) -> std::time::Instant {
        self.0
    }

    #[cfg(test)]
    pub(crate) fn for_test(at: std::time::Instant) -> Self {
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
    transport: &maknae_config::TransportConfig,
) -> Result<zeroize::Zeroizing<Vec<u8>>, String> {
    let wait = reply_wait(class, transport);
    match tokio::time::timeout(wait, read_reply(stream, class, &response_caps(transport))).await {
        Err(_elapsed) => Err(match class {
            maknae_proto::FrameClass::Control => format!(
                "no response from daemon within {}ms; it may be slow admitting the connection (group lookup or admission audit)",
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

fn request_from_input(
    verb: Verb,
    content_max: usize,
    input: &mut impl std::io::Read,
) -> Result<(maknae_proto::Verb, Option<maknae_proto::Bytes>), String> {
    let mut request: maknae_proto::Verb = verb.into();
    let maknae_proto::Verb::FsWrite { content_length, .. } = &mut request else {
        return Ok((request, None));
    };
    let cap = content_max.checked_add(1).ok_or("invalid prompt budget")?;
    let mut bytes = zeroize::Zeroizing::new(vec![0; cap]);
    let mut used = 0;
    loop {
        match input.read(&mut bytes[used..]) {
            Ok(0) => break,
            Ok(n) => {
                used += n;
                if used > content_max {
                    return Err("stdin content exceeds the configured prompt budget".into());
                }
            }
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(format!("reading stdin: {e}")),
        }
    }
    *content_length = used as u64;
    bytes.truncate(used);
    Ok((request, Some(maknae_proto::Bytes::new(bytes))))
}

fn absolute_path(path: PathBuf) -> Result<String, String> {
    std::path::absolute(path)
        .map_err(|e| format!("cannot absolutize path: {e}"))?
        .into_os_string()
        .into_string()
        .map_err(|_| "path is not valid UTF-8".into())
}

/// The full round trip: resolve config → mint a plane leaf → connect →
/// request/response → print → shut down. Returns `Ok(true)` on a successful
/// verb response, `Ok(false)` when the daemon returned a `ProtoError` (already
/// printed to stderr — the caller maps this to a non-zero exit), `Err` for any
/// earlier (config/mint/connect/frame) failure.
async fn execute(verb: Verb) -> Result<bool, String> {
    // Install the aws-lc-rs FIPS provider as the process default BEFORE any operation
    // that asserts FIPS (`PlaneClient::for_user` → `mint()` assert `.fips()`). The
    // daemon does the identical install-then-assert in `run_inner`; the CLI is a separate
    // process with its own empty default provider, so it must install too — without this,
    // `mint()` fails closed with "FIPS provider not active" and the CLI never connects.
    // (Live-smoke-caught: the CLI tests only cover arg-parsing/config-discovery, never the
    // live mint path, so no unit test exercised this.)
    maknae_vault::install_default_crypto_provider();

    let dir = resolve_config_dir();

    // Load the CLI's config ONCE, registering EVERY section it uses (vault + transport
    // + agent)
    // so a realistic combined config is accepted; a genuinely-unknown section still
    // fails closed with UnknownSection. The single document is then parsed by-section —
    // transport here, vault inside `PlaneClient::for_user` — never re-loaded under a
    // registry that would reject the other section (the P1-B fix).
    let document = load_config(&dir, &cli_config_specs()).map_err(|e| e.to_string())?;
    let transport =
        transport_from_section(document.section(TRANSPORT_SECTION)).map_err(|e| e.to_string())?;

    let session = crate::login::user_session(&document, &dir)?;
    let (request, content) = request_from_input(
        verb.clone(),
        transport.prompt_max_bytes,
        &mut std::io::stdin().lock(),
    )?;

    let client =
        PlaneClient::for_user(&document, &dir, session.token).map_err(|e| e.to_string())?;
    let ca = load_ca_pin(&dir).map_err(|e| e.to_string())?;
    client.mint().await.map_err(|e| e.to_string())?;
    let outcome = round_trip(verb, request, content, &transport, &client, &ca).await;
    client.shutdown().await;
    outcome
}

/// The post-mint round trip: connect → request → (bounded) response → print. Split out so
/// [`execute`] shuts the plane client down on every return path before propagating this
/// result. Returns `Ok(true)` on a served verb, `Ok(false)` on a daemon
/// `ProtoError` (already printed), `Err` on any transport/codec/timeout failure.
///
/// On this file's wire path, result printing lives here and in [`print_payload_for_verb`];
/// `maknae agent` prints its own (`agent::run`'s `println!` of the final answer). The
/// sendable core is [`send_verb`], which prints no result, so a caller that sends many
/// verbs is not also a printer. `send_verb` is not silent: it writes one arming
/// diagnostic to stderr (`cannot prepare filesystem operation`), and
/// `mutation::execute`, which it calls on the `MutationAttempt` path, prints too.
async fn round_trip(
    verb: Verb,
    request_verb: maknae_proto::Verb,
    content: Option<maknae_proto::Bytes>,
    transport: &maknae_config::TransportConfig,
    client: &PlaneClient,
    ca: &maknae_vault::CaBundle,
) -> Result<bool, String> {
    if let Verb::Read { path, page: None } = &verb {
        let mut stdout = std::io::stdout().lock();
        return crate::mutation::stream_pages(
            |p| {
                let v = maknae_proto::Verb::Read {
                    path: path.clone(),
                    conversation: None,
                    page: Some(p),
                };
                async move {
                    match send_verb(
                        v,
                        None,
                        crate::mutation::WriteCheck::Unchecked,
                        transport,
                        client,
                        ca,
                    )
                    .await?
                    {
                        SentOutcome::ReadDone { read } => Ok(read),
                        SentOutcome::Refused { code, message, .. } => {
                            eprintln!("maknae: daemon refused: {code:?}: {message}");
                            Ok(None)
                        }
                        _ => Err("protocol error: a read answered with something else".into()),
                    }
                }
            },
            &mut stdout,
        )
        .await;
    }
    match send_verb(
        request_verb,
        content,
        crate::mutation::WriteCheck::Unchecked,
        transport,
        client,
        ca,
    )
    .await?
    {
        SentOutcome::Payload(payload) => {
            // The daemon returned SOME successful payload — but it must be the payload
            // for the verb WE sent. A `Payload::Pong` for a `whoami` (or vice-versa) is
            // a protocol violation, not a result to print; propagate Err so the CLI
            // exits non-zero.
            print_payload_for_verb(verb, payload)?;
            Ok(true)
        }
        SentOutcome::WriteDone { applied, .. } => Ok(applied),
        SentOutcome::ReadDone { read: Some(r) } => {
            // Raw bytes, no trailing newline, no lossy conversion — a
            // non-UTF-8 file is legal content.
            use std::io::Write;
            std::io::stdout()
                .write_all(&r.content)
                .map_err(|e| format!("writing content to stdout: {e}"))?;
            match r.page.next {
                Some((line, column)) => eprintln!("next: line {line} column {column}"),
                None => eprintln!("eof"),
            }
            Ok(true)
        }
        SentOutcome::ReadDone { read: None } => Ok(false),
        SentOutcome::Refused { code, message, .. } => {
            eprintln!("maknae: daemon refused: {code:?}: {message}");
            Ok(false)
        }
    }
}

/// What one sent verb came back as, with no RESULT printed — the caller decides what a
/// terminal (or a model) is told. (`send_verb`'s arming diagnostic goes to stderr;
/// see [`send_verb`].)
///
/// `Refused` carries the code AND the message because [`round_trip`] prints both; dropping
/// the message would be a silent behaviour change no CLI test captures. `Debug` because a
/// caller that expected a different variant formats the whole outcome to say so.
#[derive(Debug)]
pub(crate) enum SentOutcome {
    /// A successful payload, NOT yet checked against the verb that asked for it —
    /// [`print_payload_for_verb`] is what rejects an answer to a different question.
    Payload(maknae_proto::Payload),
    /// A mutation reached a terminal state. `applied` is true ONLY for a client-reported
    /// `Ok(true)` — a CLAIM (ADR-0023 decision 4), never a kernel assertion.
    ///
    /// `stale` (#388): the client's own read-before-write check refused it before
    /// any write syscall, so it is certain nothing was written. `version` is the
    /// written file's, when known.
    WriteDone {
        applied: bool,
        stale: bool,
        version: Option<[i64; 7]>,
    },
    /// A read attempt ended; `read` is `Some` only after an acknowledged client-reported `Success`.
    ReadDone {
        read: Option<crate::mutation::ReadResult>,
    },
    /// The daemon refused, with the wire's own code and message (ADR-0019). `armed` is false, on a filesystem verb, iff the CLI delegated no descriptor, so no decision was made about the object.
    Refused {
        code: maknae_proto::ProtoErrCode,
        message: String,
        armed: bool,
    },
}

/// Send ONE verb over the post-mint plane and report what came back, printing no RESULT —
/// the caller decides what a terminal (or a model) is told. Not silent: the arming
/// diagnostic below goes to stderr, and `mutation::execute` prints on the attempt path.
pub(crate) async fn send_verb(
    request_verb: maknae_proto::Verb,
    content: Option<maknae_proto::Bytes>,
    check: crate::mutation::WriteCheck,
    transport: &maknae_config::TransportConfig,
    client: &PlaneClient,
    ca: &maknae_vault::CaBundle,
) -> Result<SentOutcome, String> {
    // Bound the client-side TLS handshake by the configured `handshake_timeout_ms`: a
    // process that accepts the Unix socket but never completes TLS must not hang the CLI
    // forever (it still fails non-zero).
    let connect = tokio::time::timeout(
        std::time::Duration::from_millis(transport.handshake_timeout_ms),
        PlaneConnector::connect(&transport.socket_path, client, ca),
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
        if let Some(error) = prepared.preparation_error() {
            eprintln!("maknae: cannot prepare filesystem operation: {error}");
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

    let resp_body = await_reply(&mut stream, class, transport).await?;
    let response = decode_response(&resp_body).map_err(|e| e.to_string())?;

    match response.result {
        RespResult::Ok(Payload::MutationAttempt(grant)) => {
            let prepared =
                prepared.ok_or("protocol error: mutation grant for an ordinary request")?;
            if matches!(prepared.request(), maknae_proto::Verb::Read { .. }) {
                let read =
                    crate::mutation::execute_read(prepared, grant, &mut stream, transport, written)
                        .await?;
                return Ok(SentOutcome::ReadDone { read });
            }
            let end =
                crate::mutation::execute(prepared, grant, &mut stream, transport, written).await?;
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
/// prompt budget [`request_from_input`] applies to stdin; the request carries only the length.
///
/// The mode is `Existing` — what `maknae write` sends too — because
/// [`crate::mutation::prepare_checked`] overrides it at open time (`CreateExclusive` on a
/// `NotFound`), so BOTH write lanes are reachable from this one constructor.
pub(crate) fn write_request(
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

fn kernel_graph_line(revision: Option<u64>, anchor: Option<&str>) -> Option<String> {
    match (revision, anchor) {
        (Some(r), Some(a)) => Some(format!("kernel graph: revision {r} ({a})")),
        _ => None,
    }
}

fn status_lines(s: &maknae_proto::StatusView) -> Vec<String> {
    // Labels live in the format strings, not as bare literals: the
    // authz-composition drift gate's vocabulary net rejects a bare
    // PDP-naming literal in production code (ADR-0008 decision 1).
    let mut lines = vec![
        format!("version               {}", s.version),
        format!("protocol_version      {}", s.protocol_version),
        format!("listener              {}", s.listener),
        format!("authz_backend         {}", s.authz_backend),
        format!("classification_policy {}", s.classification_policy),
    ];
    lines.extend(kernel_graph_line(
        s.kernel_graph_revision,
        s.kernel_graph_anchor.as_deref(),
    ));
    lines.extend(identity_problems_line(&s.identity_problem_counts));
    lines.extend(s.baseline_pending.iter().map(|l| terminal_safe(l)));
    lines
}

fn baseline_lines(v: &maknae_proto::BaselineView) -> Vec<String> {
    if v.state == "none" {
        return vec!["no baseline change is pending".into()];
    }
    let hash = terminal_safe(&v.hash);
    let apply = if v.apply.is_empty() { "-" } else { &v.apply };
    let mut lines = vec![
        format!("state      {}", terminal_safe(&v.state)),
        format!("source     {}", terminal_safe(&v.source)),
        format!("apply      {}", terminal_safe(apply)),
        format!("hash       {hash}"),
    ];
    lines.extend(v.changes.iter().map(|c| format!("  {}", terminal_safe(c))));
    match v.state.as_str() {
        "pending" => lines.push(format!("accept with: maknae baseline-accept {hash}")),
        "invalid" => lines.push("this change set does not validate and cannot be accepted".into()),
        _ => {}
    }
    lines
}

fn accepted_line(hash: &AcceptHash, v: &maknae_proto::BaselineView) -> Result<String, String> {
    let short = terminal_safe(hash.short());
    match (v.state.as_str(), v.apply.as_str()) {
        ("accepted", "live") => Ok(format!("accepted sha256:{short}; applied live")),
        ("accepted", "restart") => Ok(format!(
            "accepted sha256:{short}; maknaed is restarting to apply it"
        )),
        ("accepted", apply) => Err(format!(
            "protocol error: an accepted baseline with apply {:?}",
            terminal_safe(apply)
        )),
        (state, _) => Err(format!(
            "baseline accept refused: {}; run maknae baseline-show",
            terminal_safe(state)
        )),
    }
}

fn accept_hash(hash: String) -> Result<String, String> {
    if hash.len() == 64 && hash.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f')) {
        Ok(hash)
    } else {
        Err(
            "baseline-accept takes the 64-character lowercase hex hash `maknae baseline-show` prints"
                .into(),
        )
    }
}

fn identity_problems_line(counts: &[String]) -> Option<String> {
    let parts: Vec<String> = counts
        .iter()
        .filter_map(|entry| match entry.split_once('=') {
            Some((kind, n)) => match n.parse::<u64>() {
                Ok(0) => None,
                Ok(n) => Some(format!(
                    "{n} {}",
                    kind.replace(['-', '_'], " ").escape_default()
                )),
                Err(_) => Some(entry.escape_default().to_string()),
            },
            None => Some(entry.escape_default().to_string()),
        })
        .collect();
    (!parts.is_empty()).then(|| format!("identity problems: {}", parts.join(", ")))
}

/// Anything but printable ASCII is escaped: the daemon escapes its labels, and a
/// daemon that did not cannot reach the terminal with a control character.
pub(crate) fn terminal_safe(s: &str) -> String {
    s.chars()
        .map(|c| {
            if c == ' ' || c.is_ascii_graphic() {
                c.to_string()
            } else {
                c.escape_default().to_string()
            }
        })
        .collect()
}

/// One row per subject, with the role it is bound or listed under (empty for an
/// unbound subject). A daemon that predates #496 sends one entry per role and no
/// label or state; its members stand in for the label.
fn subject_table(entries: &[maknae_proto::RoleBindingView]) -> Vec<String> {
    if entries.is_empty() {
        return Vec::new();
    }
    let header = ["UID", "ROLE", "SUBJECT", "STATE"].map(String::from);
    let rows: Vec<[String; 4]> = entries
        .iter()
        .map(|e| {
            [
                e.uid.map_or_else(|| "-".to_string(), |u| u.to_string()),
                terminal_safe(&e.role),
                terminal_safe(&if e.label.is_empty() {
                    e.members.join(", ")
                } else {
                    e.label.clone()
                }),
                terminal_safe(&e.state),
            ]
        })
        .collect();
    let w = |i: usize| {
        rows.iter()
            .chain(std::iter::once(&header))
            .map(|r| r[i].chars().count())
            .max()
            .unwrap_or(0)
    };
    let (w0, w1, w2) = (w(0), w(1), w(2));
    std::iter::once(&header)
        .chain(rows.iter())
        .map(|r| {
            format!("{:<w0$}  {:<w1$}  {:<w2$}  {}", r[0], r[1], r[2], r[3])
                .trim_end()
                .to_string()
        })
        .collect()
}

/// Print the successful `payload` IFF its variant matches the requested `verb`
/// (`Ping`→`Pong`, `Whoami`→`Whoami(_)`). A mismatched variant means the daemon
/// answered a different question than we asked — a protocol error: return `Err`
/// (the caller exits non-zero).
fn print_payload_for_verb(verb: Verb, payload: Payload) -> Result<(), String> {
    match (verb, payload) {
        (Verb::Ping, Payload::Pong) => {
            println!("pong");
            Ok(())
        }
        (Verb::Whoami, Payload::Whoami(w)) => {
            println!("{} uid={}", w.peer_plane_uri_san, w.peer_uid);
            Ok(())
        }
        (Verb::AdminStatus, Payload::Status(s)) => {
            for line in status_lines(&s) {
                println!("{line}");
            }
            Ok(())
        }
        (Verb::AdminConfigShow, Payload::ConfigView(v)) => {
            for (section, fields) in &v {
                for (k, val) in fields {
                    println!("{section}.{k} = {val}");
                }
            }
            Ok(())
        }
        (Verb::AdminSubjectList, Payload::SubjectList(bindings)) => {
            for line in subject_table(&bindings) {
                println!("{line}");
            }
            Ok(())
        }
        (Verb::AdminBaselineShow, Payload::Baseline(v)) => {
            for line in baseline_lines(&v) {
                println!("{line}");
            }
            Ok(())
        }
        (Verb::AdminBaselineAccept { hash }, Payload::Baseline(v)) => {
            println!("{}", accepted_line(&hash, &v)?);
            Ok(())
        }
        // A payload for a DIFFERENT verb than we sent — a protocol error.
        //
        // Written as an explicit list of the wrong-payload cases rather than a
        // `(v, p)` wildcard, deliberately. The wildcard silently absorbed
        // `Payload::ConfigView` when it was added: the client compiled clean
        // with no arm for it, and nothing said an arm was missing. That is the
        // opposite of `dispatch_verb`, which has no wildcard precisely so a new
        // variant is a compile error until someone decides what it does. The
        // producing side forced the decision; the consuming side did not.
        (v, p @ Payload::Pong)
        | (v, p @ Payload::Whoami(_))
        | (v, p @ Payload::ConfigView(_))
        | (v, p @ Payload::Status(_))
        | (v, p @ Payload::MutationAttempt(_))
        | (v, p @ Payload::SubjectList(_))
        | (v, p @ Payload::PromptReply(_))
        | (v, p @ Payload::Baseline(_)) => Err(format!(
            "protocol error: daemon returned a {p:?} payload for a {v:?} request"
        )),
    }
}

/// The `maknae` entrypoint: parse args, dispatch to the wire path
/// (`ping`/`whoami`) or `enroll`/`enroll-helper`, map the outcome to an exit
/// code. Fail-closed — any error prints to stderr and exits non-zero.
pub async fn run_cli() -> ExitCode {
    let cli = Cli::parse();
    match cli.command {
        Command::Ping => wire_exit_code(execute(Verb::Ping).await),
        Command::Whoami => wire_exit_code(execute(Verb::Whoami).await),
        Command::Status => wire_exit_code(execute(Verb::AdminStatus).await),
        Command::ConfigShow => wire_exit_code(execute(Verb::AdminConfigShow).await),
        Command::SubjectList => wire_exit_code(execute(Verb::AdminSubjectList).await),
        Command::BaselineShow => wire_exit_code(execute(Verb::AdminBaselineShow).await),
        Command::BaselineAccept { hash } => wire_exit_code(match accept_hash(hash) {
            Ok(hash) => execute(Verb::AdminBaselineAccept { hash: hash.into() }).await,
            Err(e) => Err(e),
        }),
        Command::AuditReaders { stopped } => {
            crate::audit_readers::run(nix::unistd::geteuid().as_raw(), stopped)
        }
        Command::Write { path } => wire_exit_code(match absolute_path(path) {
            Ok(path) => execute(Verb::Write { path }).await,
            Err(e) => Err(e),
        }),
        Command::Delete { path, recursive } => wire_exit_code(match absolute_path(path) {
            Ok(path) => execute(Verb::Delete { path, recursive }).await,
            Err(e) => Err(e),
        }),
        Command::Mkdir { path, parents } => wire_exit_code(match absolute_path(path) {
            Ok(path) => execute(Verb::Mkdir { path, parents }).await,
            Err(e) => Err(e),
        }),
        Command::Read {
            path,
            offset,
            limit,
            column,
        } => {
            let page = single_page(offset, limit, column);
            // Lexically absolutize client-side (std::path::absolute keeps `..`
            // on Unix — the daemon's canonical pre-gate refuses those as
            // BadRequest, a stated consequence); `~` is the shell's business.
            match std::path::absolute(&path) {
                Ok(abs) => match abs.into_os_string().into_string() {
                    Ok(p) => wire_exit_code(execute(Verb::Read { path: p, page }).await),
                    Err(_) => {
                        eprintln!("maknae: path is not valid UTF-8 (recorded v1 limit)");
                        ExitCode::FAILURE
                    }
                },
                Err(e) => {
                    eprintln!("maknae: cannot absolutize path: {e}");
                    ExitCode::FAILURE
                }
            }
        }
        Command::Agent { provider, prompt } => match crate::agent::run(provider, prompt).await {
            Ok(code) => ExitCode::from(code),
            Err(e) => {
                eprintln!("maknae: {e}");
                ExitCode::from(1)
            }
        },
        Command::Login => crate::login::run_login().await,
        Command::Logout => crate::login::run_logout().await,
        Command::Enroll(args) => crate::enroll::run_enroll(*args).await,
        Command::Reseed => crate::reseed::run_reseed(),
        Command::Policy {
            action: PolicyCommand::Sync { check },
        } => crate::policy_sync::run(nix::unistd::geteuid().as_raw(), check),
        Command::EnrollHelper(args) => crate::enroll::run_enroll_helper(args).await,
    }
}

/// Map the wire path's `execute()` outcome to an exit code — split out of
/// `run_cli` so `Ping`/`Whoami` share one mapping (unchanged from before the
/// `Command`-enum restructure).
fn wire_exit_code(result: Result<bool, String>) -> ExitCode {
    match result {
        Ok(true) => ExitCode::SUCCESS,
        Ok(false) => ExitCode::FAILURE,
        Err(e) => {
            eprintln!("maknae: {e}");
            ExitCode::FAILURE
        }
    }
}

fn single_page(
    offset: Option<u64>,
    limit: Option<u32>,
    column: Option<u64>,
) -> Option<maknae_proto::PageRequest> {
    (offset.is_some() || limit.is_some() || column.is_some()).then(|| maknae_proto::PageRequest {
        offset_line: offset.unwrap_or(1),
        limit_lines: limit.unwrap_or(2000),
        column: column.unwrap_or(0),
    })
}

#[cfg(test)]
mod tests {
    #[tokio::test]
    async fn a_prompt_reply_over_the_control_cap_is_read_with_the_prompt_cap() {
        let reply = maknae_proto::Response {
            protocol_version: PROTOCOL_VERSION,
            result: RespResult::Ok(Payload::PromptReply(maknae_proto::PromptReply {
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
    fn mutation_commands_preserve_options() {
        assert!(matches!(
            super::Cli::try_parse_from(["maknae", "write", "a"])
                .unwrap()
                .command,
            super::Command::Write { .. }
        ));
        assert!(matches!(
            super::Cli::try_parse_from(["maknae", "delete", "-r", "a"])
                .unwrap()
                .command,
            super::Command::Delete {
                recursive: true,
                ..
            }
        ));
        assert!(matches!(
            super::Cli::try_parse_from(["maknae", "mkdir", "-p", "a/b"])
                .unwrap()
                .command,
            super::Command::Mkdir { parents: true, .. }
        ));
    }

    #[test]
    fn write_input_keeps_binary_bytes_and_refuses_over_budget() {
        use super::*;
        let verb = Verb::Write {
            path: "/projects/binary".into(),
        };
        let (request, content) =
            request_from_input(verb.clone(), 512, &mut &[0, 255, 7][..]).unwrap();
        assert!(matches!(
            request,
            maknae_proto::Verb::FsWrite {
                content_length: 3,
                ..
            }
        ));
        assert_eq!(content.unwrap().0.as_slice(), &[0, 255, 7]);
        assert!(request_from_input(verb.clone(), 2, &mut &[1, 2, 3][..]).is_err());
        let (_, empty) = request_from_input(verb, 8, &mut &[][..]).unwrap();
        assert!(empty.unwrap().0.is_empty());
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

    use super::*;
    use std::sync::Mutex;

    fn small_prompt_reply() -> Vec<u8> {
        maknae_proto::encode_response(&maknae_proto::Response {
            protocol_version: PROTOCOL_VERSION,
            result: RespResult::Ok(Payload::PromptReply(maknae_proto::PromptReply {
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
        let got = await_reply(&mut cli, class, &transport).await;
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
        assert_eq!(err, "no response from daemon within 690000ms (stalled?)");
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
        format!("no response from daemon within {wait_ms}ms; it may be slow admitting the connection (group lookup or admission audit)")
    }

    #[tokio::test(start_paused = true)]
    async fn control_replies_are_bounded_by_read_timeout_ms() {
        let read = std::time::Duration::from_millis(READ_TIMEOUT_MS);
        let class = maknae_proto::FrameClass::Control;
        assert!(reply_after(read - TICK, class, READ_TIMEOUT_MS)
            .await
            .is_ok());
        let err = reply_after(read + TICK, class, READ_TIMEOUT_MS)
            .await
            .unwrap_err();
        assert_eq!(err, control_stalled(READ_TIMEOUT_MS));
    }

    #[tokio::test(start_paused = true)]
    async fn attempt_replies_also_wait_out_the_kernels_home_resolution() {
        let wait_ms = READ_TIMEOUT_MS + maknae_config::HOME_RESOLVE_TIMEOUT_MS;
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

    // `cargo test` runs tests in this file on multiple threads by default, and
    // `MAKNAE_CONFIG_DIR` is process-wide — without this lock the two env-var
    // tests below can interleave (one sets it while the other asserts the
    // absent-var default), flaking CI. std-only, no new dependency.
    static ENV_LOCK: Mutex<()> = Mutex::new(());

    // ---- resolve_config_dir --------------------------------------------

    #[test]
    fn env_overrides_default() {
        let _guard = ENV_LOCK.lock().unwrap();
        std::env::set_var("MAKNAE_CONFIG_DIR", "/tmp/x");
        assert_eq!(resolve_config_dir(), std::path::PathBuf::from("/tmp/x"));
        std::env::remove_var("MAKNAE_CONFIG_DIR");
    }
    #[test]
    fn default_is_home_maknae() {
        let _guard = ENV_LOCK.lock().unwrap();
        std::env::remove_var("MAKNAE_CONFIG_DIR");
        let d = resolve_config_dir();
        assert!(d.ends_with(".maknae"));
    }

    // ---- clap arg parsing -----------------------------------------------

    #[test]
    fn parses_ping() {
        let cli = Cli::try_parse_from(["maknae", "ping"]).expect("parses");
        assert!(matches!(cli.command, Command::Ping));
    }

    #[test]
    fn parses_whoami() {
        let cli = Cli::try_parse_from(["maknae", "whoami"]).expect("parses");
        assert!(matches!(cli.command, Command::Whoami));
    }

    #[test]
    fn login_and_logout_parse_and_take_no_arguments() {
        let cli = Cli::try_parse_from(["maknae", "login"]).expect("parses");
        assert!(matches!(cli.command, Command::Login));
        let cli = Cli::try_parse_from(["maknae", "logout"]).expect("parses");
        assert!(matches!(cli.command, Command::Logout));
        for argv in [
            ["maknae", "login", "password=hunter2"].as_slice(),
            ["maknae", "login", "--password", "hunter2"].as_slice(),
            ["maknae", "login", "--password=hunter2"].as_slice(),
            ["maknae", "login", "alice"].as_slice(),
            ["maknae", "logout", "--token", "hvs.x"].as_slice(),
        ] {
            assert!(Cli::try_parse_from(argv).is_err(), "{argv:?}");
        }
    }

    #[test]
    fn agent_takes_an_optional_provider_label_before_the_prompt() {
        match Cli::try_parse_from(["maknae", "agent", "--provider", "home", "hello"])
            .unwrap()
            .command
        {
            Command::Agent { provider, prompt } => {
                assert_eq!(
                    (provider.as_deref(), prompt.as_str()),
                    (Some("home"), "hello")
                )
            }
            other => panic!("expected Command::Agent, got {other:?}"),
        }
        match Cli::try_parse_from(["maknae", "agent", "hello"])
            .unwrap()
            .command
        {
            Command::Agent { provider, prompt } => {
                assert_eq!((provider, prompt.as_str()), (None, "hello"))
            }
            other => panic!("expected Command::Agent, got {other:?}"),
        }
        assert!(Cli::try_parse_from(["maknae", "agent", "--provider"]).is_err());
        assert!(Cli::try_parse_from(["maknae", "agent", "--provider", "home"]).is_err());
    }

    #[test]
    fn rejects_unknown_verb() {
        assert!(Cli::try_parse_from(["maknae", "bogus"]).is_err());
    }

    #[test]
    fn rejects_no_verb() {
        assert!(Cli::try_parse_from(["maknae"]).is_err());
    }

    // ---- enroll / enroll-helper clap wiring (Step 3) -----------------------

    const ENROLL_REQUIRED: &[&str] = &[
        "maknae",
        "enroll",
        "--vault-ca",
        "/tmp/ca.crt",
        "--vault-addr",
        "https://v.example:8200",
        "--deployment-id",
        "dev-01",
    ];

    #[test]
    fn enroll_parses_with_required_args() {
        let cli = Cli::try_parse_from(ENROLL_REQUIRED).expect("parses");
        match cli.command {
            Command::Enroll(args) => {
                assert_eq!(args.vault_ca, Some(std::path::PathBuf::from("/tmp/ca.crt")));
                assert_eq!(args.ca_dir, None);
                assert_eq!(args.vault_addr, "https://v.example:8200");
                assert_eq!(args.deployment_id, "dev-01");
                assert_eq!(args.approle_mount, maknae_vault::DEFAULT_APPROLE_MOUNT);
                assert_eq!(args.pki_int_mount, maknae_vault::DEFAULT_PKI_INT_MOUNT);
                assert_eq!(args.userpass_mount, "maknae-userpass");
                assert_eq!(args.kv_mount, "maknae-kv");
                assert_eq!(args.user_prefix, "maknae/users");
                assert!(!args.rotate);
                assert!(!args.rotate_seal_key);
                assert!(!args.insecure_plaintext_secret);
                assert!(!args.verbose);
            }
            other => panic!("expected Command::Enroll, got {other:?}"),
        }
    }

    #[test]
    fn enroll_accepts_ca_dir_instead_of_vault_ca() {
        let cli = Cli::try_parse_from([
            "maknae",
            "enroll",
            "--ca-dir",
            "/tmp/cadir",
            "--vault-addr",
            "https://v.example:8200",
            "--deployment-id",
            "dev-01",
        ])
        .expect("parses");
        match cli.command {
            Command::Enroll(args) => {
                assert_eq!(args.ca_dir, Some(std::path::PathBuf::from("/tmp/cadir")));
                assert_eq!(args.vault_ca, None);
            }
            other => panic!("expected Command::Enroll, got {other:?}"),
        }
    }

    #[test]
    fn enroll_missing_ca_source_is_refused() {
        assert!(Cli::try_parse_from([
            "maknae",
            "enroll",
            "--vault-addr",
            "https://v.example:8200",
            "--deployment-id",
            "dev-01",
        ])
        .is_err());
    }

    #[test]
    fn enroll_both_ca_sources_is_refused() {
        assert!(Cli::try_parse_from([
            "maknae",
            "enroll",
            "--vault-ca",
            "/tmp/ca.crt",
            "--ca-dir",
            "/tmp/cadir",
            "--vault-addr",
            "https://v.example:8200",
            "--deployment-id",
            "dev-01",
        ])
        .is_err());
    }

    #[test]
    fn enroll_missing_vault_addr_is_refused() {
        assert!(Cli::try_parse_from([
            "maknae",
            "enroll",
            "--vault-ca",
            "/tmp/ca.crt",
            "--deployment-id",
            "dev-01",
        ])
        .is_err());
    }

    #[test]
    fn enroll_missing_deployment_id_is_refused() {
        assert!(Cli::try_parse_from([
            "maknae",
            "enroll",
            "--vault-ca",
            "/tmp/ca.crt",
            "--vault-addr",
            "https://v.example:8200",
        ])
        .is_err());
    }

    #[test]
    fn enroll_overrides_mounts_rotate_and_flags() {
        let mut argv: Vec<&str> = ENROLL_REQUIRED.to_vec();
        argv.extend([
            "--approle-mount",
            "alt-approle",
            "--pki-int-mount",
            "alt-pki-int",
            "--userpass-mount",
            "corp-userpass",
            "--kv-mount",
            "corp-kv",
            "--user-prefix",
            "corp/users",
            "--rotate",
            "--rotate-seal-key",
            "--insecure-plaintext-secret",
            "--verbose",
        ]);
        let cli = Cli::try_parse_from(argv).expect("parses");
        match cli.command {
            Command::Enroll(args) => {
                assert_eq!(args.approle_mount, "alt-approle");
                assert_eq!(args.pki_int_mount, "alt-pki-int");
                assert_eq!(args.userpass_mount, "corp-userpass");
                assert_eq!(args.kv_mount, "corp-kv");
                assert_eq!(args.user_prefix, "corp/users");
                assert!(args.rotate);
                assert!(args.rotate_seal_key);
                assert!(args.insecure_plaintext_secret);
                assert!(args.verbose);
            }
            other => panic!("expected Command::Enroll, got {other:?}"),
        }
    }

    #[test]
    fn the_removed_probe_verb_is_refused() {
        assert!(Cli::try_parse_from([
            "maknae",
            "enroll-helper",
            "probe",
            "--euid",
            "1000",
            "--egid",
            "1000",
        ])
        .is_err());
    }

    #[test]
    fn reseed_parses_and_takes_no_arguments() {
        let cli = Cli::try_parse_from(["maknae", "reseed"]).expect("parses");
        assert!(matches!(cli.command, Command::Reseed));
        assert!(Cli::try_parse_from(["maknae", "reseed", "--force"]).is_err());
    }

    #[test]
    fn the_status_kernel_graph_line_is_printed_only_when_reported() {
        assert_eq!(kernel_graph_line(None, None), None);
        assert_eq!(kernel_graph_line(Some(12), None), None);
        assert_eq!(kernel_graph_line(None, Some("verified")), None);
        assert_eq!(
            kernel_graph_line(Some(12), Some("verified")).as_deref(),
            Some("kernel graph: revision 12 (verified)")
        );
    }

    #[test]
    fn the_status_lists_each_identity_problem_after_the_kernel_graph_line() {
        let mut s = maknae_proto::StatusView {
            version: "v".into(),
            protocol_version: 1,
            listener: "l".into(),
            authz_backend: "b".into(),
            classification_policy: "US".into(),
            kernel_graph_revision: Some(3),
            kernel_graph_anchor: Some("verified".into()),
            identity_problem_counts: vec![],
            baseline_pending: vec![],
        };
        let base = status_lines(&s);
        assert_eq!(
            base.last().map(String::as_str),
            Some("kernel graph: revision 3 (verified)")
        );
        assert!(!base.iter().any(|l| l.starts_with("identity problem")));
        s.identity_problem_counts = vec!["unbound_conflict=0".into(), "released=0".into()];
        assert_eq!(status_lines(&s), base, "all-zero counts print nothing");
        s.identity_problem_counts = vec![
            "unresolved=1".into(),
            "unbound_conflict=0".into(),
            "carried_forward=1".into(),
            "unresolved_adversary=2".into(),
        ];
        let lines = status_lines(&s);
        assert_eq!(&lines[..base.len()], &base[..]);
        assert_eq!(
            &lines[base.len()..],
            ["identity problems: 1 unresolved, 1 carried forward, 2 unresolved adversary"]
        );
    }

    fn entry(
        role: &str,
        members: &[&str],
        uid: Option<u32>,
        label: &str,
        state: &str,
    ) -> maknae_proto::RoleBindingView {
        maknae_proto::RoleBindingView {
            role: role.into(),
            members: members.iter().map(|m| m.to_string()).collect(),
            uid,
            label: label.into(),
            state: state.into(),
        }
    }

    #[test]
    fn the_subject_list_is_a_table_one_row_per_subject() {
        assert_eq!(
            subject_table(&[
                entry("admin", &["uid:0"], Some(0), "root (uid 0)", "bound admin"),
                entry(
                    "adversary",
                    &["uid:666"],
                    Some(666),
                    "uid 666 (mallory)",
                    "contained (carried forward)"
                ),
                entry(
                    "",
                    &[],
                    Some(1002),
                    "uid 1002 (gus, gustav)",
                    "unbound (conflict: guest, user)"
                ),
                entry(
                    "user",
                    &[],
                    None,
                    "ghost (no account)",
                    "unresolved (no account)"
                ),
                entry(
                    "adversary",
                    &[],
                    None,
                    "trudy (no account)",
                    "unresolved adversary (no account, not contained)"
                ),
            ]),
            [
                "UID   ROLE       SUBJECT                 STATE",
                "0     admin      root (uid 0)            bound admin",
                "666   adversary  uid 666 (mallory)       contained (carried forward)",
                "1002             uid 1002 (gus, gustav)  unbound (conflict: guest, user)",
                "-     user       ghost (no account)      unresolved (no account)",
                "-     adversary  trudy (no account)      unresolved adversary (no account, not contained)",
            ]
        );
        assert!(subject_table(&[]).is_empty());
        assert_eq!(
            subject_table(&[entry("user", &["uid:1", "uid:2"], None, "", "")]),
            ["UID  ROLE  SUBJECT       STATE", "-    user  uid:1, uid:2"],
            "an older daemon's per-role entry"
        );
    }

    #[test]
    fn a_subject_label_reaches_the_terminal_escaped() {
        let kernel_escaped = entry(
            "user",
            &[],
            Some(7),
            "\\u{e9}\\u{7f}\\,x (uid 7)",
            "bound user",
        );
        assert_eq!(
            subject_table(&[kernel_escaped])[1],
            "7    user  \\u{e9}\\u{7f}\\,x (uid 7)  bound user",
            "an already-escaped label passes unchanged"
        );
        let raw = entry(
            "user\u{1b}[2J",
            &[],
            Some(7),
            "a\u{7}b,\u{202e}c\nd",
            "bound\tx",
        );
        let row = &subject_table(&[raw])[1];
        assert_eq!(
            row,
            "7    user\\u{1b}[2J  a\\u{7}b,\\u{202e}c\\nd  bound\\tx"
        );
        assert!(row.chars().all(|c| c == ' ' || c.is_ascii_graphic()));
    }

    #[test]
    fn a_malformed_count_entry_is_shown_escaped_not_dropped() {
        assert_eq!(
            identity_problems_line(&["bad\u{1b}[2J".into(), "x=y".into(), "u\u{7}=1".into()])
                .as_deref(),
            Some("identity problems: bad\\u{1b}[2J, x=y, 1 u\\u{7}")
        );
    }

    #[test]
    fn enroll_helper_provision_parses() {
        let cli = Cli::try_parse_from([
            "maknae",
            "enroll-helper",
            "provision",
            "--euid",
            "1000",
            "--egid",
            "1000",
        ])
        .expect("parses");
        assert!(matches!(cli.command, Command::EnrollHelper(_)));
    }

    #[test]
    fn enroll_helper_is_hidden_from_help() {
        let help = <Cli as clap::CommandFactory>::command()
            .render_help()
            .to_string();
        assert!(
            !help.contains("enroll-helper"),
            "enroll-helper leaked into --help:\n{help}"
        );
        // Sanity: the visible subcommands ARE present, so this isn't a
        // vacuously-passing empty-help check.
        assert!(help.contains("enroll"));
        assert!(help.contains("ping"));
    }

    #[test]
    fn verb_maps_to_proto_verb() {
        assert_eq!(
            maknae_proto::Verb::from(Verb::Ping),
            maknae_proto::Verb::Ping
        );
        assert_eq!(
            maknae_proto::Verb::from(Verb::Whoami),
            maknae_proto::Verb::Whoami
        );
    }

    // ---- verb/payload matching (P2) -------------------------------------------

    #[test]
    fn ping_accepts_pong_payload() {
        assert!(print_payload_for_verb(Verb::Ping, Payload::Pong).is_ok());
    }

    #[test]
    fn whoami_accepts_whoami_payload() {
        let w = maknae_proto::WhoamiView {
            peer_plane_uri_san: "urn:maknae:plane:cli".into(),
            peer_uid: 1000,
        };
        assert!(print_payload_for_verb(Verb::Whoami, Payload::Whoami(w)).is_ok());
    }

    #[test]
    fn whoami_rejects_pong_payload() {
        // The daemon answered a `ping` question for our `whoami` — a protocol error.
        assert!(print_payload_for_verb(Verb::Whoami, Payload::Pong).is_err());
    }

    #[test]
    fn ping_rejects_whoami_payload() {
        let w = maknae_proto::WhoamiView {
            peer_plane_uri_san: "urn:maknae:plane:cli".into(),
            peer_uid: 1000,
        };
        assert!(print_payload_for_verb(Verb::Ping, Payload::Whoami(w)).is_err());
    }

    // ---- CLI config-load coherence (P1-B) -------------------------------------

    #[cfg(unix)]
    struct CfgDir(std::path::PathBuf);
    #[cfg(unix)]
    impl Drop for CfgDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }
    #[cfg(unix)]
    fn cfg_dir(tag: &str, body: &str) -> CfgDir {
        use std::os::unix::fs::PermissionsExt;
        let p = std::env::temp_dir().join(format!("maknae-cli-cfg-{}-{tag}", std::process::id()));
        let _ = std::fs::remove_dir_all(&p);
        std::fs::create_dir_all(&p).unwrap();
        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o700)).unwrap();
        let f = p.join("maknae.yaml");
        std::fs::write(&f, body).unwrap();
        std::fs::set_permissions(&f, std::fs::Permissions::from_mode(0o600)).unwrap();
        CfgDir(p)
    }

    // A realistic combined vault + transport CLI config loads under the ONE registry
    // and both sections parse — the P1-B gap: the old CLI loaded `transport`-only, then
    // re-loaded `vault`-only inside `from_config_dir`, so each rejected the other's
    // section with UnknownSection.
    #[cfg(unix)]
    #[test]
    fn combined_vault_transport_cli_config_loads() {
        let d = cfg_dir(
            "combined",
            "core:\n  deployment_id: dev-01\n\
             vault:\n  addr: https://v.example:8200\n\
             transport:\n  socket_path: /run/maknae/maknaed.sock\n",
        );
        let doc = load_config(&d.0, &cli_config_specs()).expect("combined CLI config loads");
        assert!(doc.section("vault").is_some());
        let transport = transport_from_section(doc.section(TRANSPORT_SECTION))
            .expect("transport parses from the shared document");
        assert_eq!(
            transport.socket_path,
            std::path::PathBuf::from("/run/maknae/maknaed.sock")
        );
        let vc = maknae_vault::vault_config_from_document(&doc)
            .expect("vault parses from the shared document");
        assert_eq!(vc.addr, "https://v.example:8200");
    }

    #[cfg(unix)]
    #[test]
    fn the_cli_reads_vault_user_auth_beside_addr() {
        let d = cfg_dir(
            "vault-user-auth",
            "core:\n  deployment_id: dev-01\n\
             vault:\n  addr: https://v.example:8200\n  user_auth:\n    type: userpass\n    mount: corp-userpass\n",
        );
        let doc = load_config(&d.0, &cli_config_specs()).expect("loads");
        let vc = maknae_vault::vault_config_from_document(&doc).expect("parses");
        assert_eq!(vc.user_auth.resolve().unwrap().mount(), "corp-userpass");
    }

    // A genuinely-unknown section is still rejected under the CLI registry — fail-closed
    // on unknown preserved.
    #[cfg(unix)]
    #[test]
    fn bogus_section_still_rejected_by_cli_registry() {
        let d = cfg_dir(
            "bogus",
            "core:\n  deployment_id: dev-01\n\
             vault:\n  addr: https://v.example:8200\n\
             transport:\n  socket_path: /run/maknae/maknaed.sock\n\
             mystery:\n  a: 1\n",
        );
        assert!(matches!(
            load_config(&d.0, &cli_config_specs()),
            Err(maknae_config::ConfigError::UnknownSection { .. })
        ));
    }

    #[cfg(unix)]
    #[test]
    fn a_user_provider_section_is_refused_by_name() {
        let d = cfg_dir(
            "user-provider",
            "core:\n  deployment_id: dev-01\n\
             vault:\n  addr: https://v.example:8200\n\
             provider:\n  context_tokens: 128000\n",
        );
        match load_config(&d.0, &cli_config_specs()) {
            Err(maknae_config::ConfigError::UnknownSection { section, .. }) => {
                assert_eq!(section, "provider")
            }
            other => panic!(
                "a user provider block must be refused by name, got {:?}",
                other.map(|_| "a document")
            ),
        }
    }

    // ---- read verb surface (#77) ----

    #[test]
    fn any_one_paging_flag_selects_a_single_page() {
        assert_eq!(single_page(None, None, None), None);
        let one = |offset, limit, column| single_page(offset, limit, column).unwrap();
        assert_eq!(
            one(Some(5), None, None),
            maknae_proto::PageRequest {
                offset_line: 5,
                limit_lines: 2000,
                column: 0
            }
        );
        assert_eq!(one(None, Some(7), None).limit_lines, 7);
        assert_eq!(one(None, None, Some(9)).column, 9);
    }

    #[test]
    fn read_parses_with_a_path() {
        let cli = Cli::try_parse_from(["maknae", "read", "/home/op/notes.txt"]).unwrap();
        assert!(matches!(cli.command, Command::Read { .. }));
    }

    #[test]
    fn read_verb_converts_to_proto_with_its_path() {
        let v: maknae_proto::Verb = Verb::Read {
            path: "/a/b".into(),
            page: None,
        }
        .into();
        assert_eq!(
            v,
            maknae_proto::Verb::Read {
                path: "/a/b".into(),
                conversation: None,
                page: None,
            }
        );
    }

    fn bview(state: &str, apply: &str, hash: &str, changes: &[&str]) -> maknae_proto::BaselineView {
        maknae_proto::BaselineView {
            source: if state == "none" { "" } else { "root-file" }.into(),
            hash: hash.into(),
            state: state.into(),
            apply: apply.into(),
            changes: changes.iter().map(|c| c.to_string()).collect(),
        }
    }

    #[test]
    fn baseline_show_prints_the_set_and_the_command_that_accepts_it() {
        let h = "ab".repeat(32);
        let v = bview(
            "pending",
            "restart",
            &h,
            &["vault.addr: <value changed>", "principal.uid: 1000 -> 1001"],
        );
        assert_eq!(
            baseline_lines(&v),
            [
                "state      pending".to_string(),
                "source     root-file".into(),
                "apply      restart".into(),
                format!("hash       {h}"),
                "  vault.addr: <value changed>".into(),
                "  principal.uid: 1000 -> 1001".into(),
                format!("accept with: maknae baseline-accept {h}"),
            ]
        );
        assert_eq!(
            baseline_lines(&bview("none", "", "", &[])),
            ["no baseline change is pending"]
        );
        assert!(print_payload_for_verb(Verb::AdminBaselineShow, Payload::Baseline(v)).is_ok());
    }

    #[test]
    fn an_invalid_set_is_shown_without_an_accept_command() {
        let h = "cd".repeat(32);
        let lines = baseline_lines(&bview("invalid", "", &h, &["the file does not validate"]));
        assert_eq!(
            lines,
            [
                "state      invalid".to_string(),
                "source     root-file".into(),
                "apply      -".into(),
                format!("hash       {h}"),
                "  the file does not validate".into(),
                "this change set does not validate and cannot be accepted".into(),
            ]
        );
    }

    #[test]
    fn baseline_lines_escape_what_the_daemon_sends() {
        let v = bview("pending\u{7}", "live", "h\u{1b}", &["a\u{1b}[2Jb"]);
        let lines = baseline_lines(&v);
        assert!(
            lines
                .iter()
                .all(|l| !l.contains('\u{1b}') && !l.contains('\u{7}')),
            "{lines:?}"
        );
        assert!(lines.contains(&"  a\\u{1b}[2Jb".to_string()), "{lines:?}");
    }

    #[test]
    fn the_accept_verbs_debug_carries_only_the_hash_prefix() {
        let h = "0123456789ab".to_string() + &"cd".repeat(26);
        let shown = format!(
            "{:?}",
            Verb::AdminBaselineAccept {
                hash: h.clone().into()
            }
        );
        assert!(!shown.contains(&h[..13]), "{shown}");
        assert!(shown.contains("sha256:0123456789ab"), "{shown}");
    }

    #[test]
    fn baseline_accept_reports_how_the_accepted_set_applies() {
        let h = "ef".repeat(32);
        let accept = || Verb::AdminBaselineAccept {
            hash: h.clone().into(),
        };
        assert_eq!(
            accepted_line(
                &h.clone().into(),
                &bview("accepted", "live", "", &[maknae_config::SUPPRESSED_CHANGED])
            ),
            Ok(format!("accepted sha256:{}; applied live", &h[..12]))
        );
        assert_eq!(
            accepted_line(
                &h.clone().into(),
                &bview(
                    "accepted",
                    "restart",
                    "",
                    &["vault.addr: https://v:8200 -> https://w:8200"]
                )
            ),
            Ok(format!(
                "accepted sha256:{}; maknaed is restarting to apply it",
                &h[..12]
            ))
        );
        for state in ["stale", "none", "invalid", "pending"] {
            assert_eq!(
                print_payload_for_verb(accept(), Payload::Baseline(bview(state, "", "", &[]))),
                Err(format!(
                    "baseline accept refused: {state}; run maknae baseline-show"
                ))
            );
        }
        assert!(accepted_line(&h.clone().into(), &bview("accepted", "", "", &[])).is_err());
        assert!(print_payload_for_verb(
            accept(),
            Payload::Baseline(bview("accepted", "live", "", &[]))
        )
        .is_ok());
    }

    #[test]
    fn baseline_accept_takes_exactly_a_shown_hash() {
        let h = "0123456789abcdef".repeat(4);
        assert_eq!(accept_hash(h.clone()), Ok(h.clone()));
        for bad in [
            String::new(),
            h[..63].to_string(),
            format!("{h}0"),
            h.to_uppercase(),
            format!("{}g", &h[..63]),
            format!("sha256:{}", &h[..57]),
        ] {
            assert_eq!(
                accept_hash(bad.clone()),
                Err(
                    "baseline-accept takes the 64-character lowercase hex hash `maknae baseline-show` prints"
                        .into()
                ),
                "{bad}"
            );
        }
    }

    #[test]
    fn the_baseline_commands_parse_and_reach_the_wire_verbs() {
        let cli = Cli::try_parse_from(["maknae", "baseline-show"]).expect("parses");
        assert!(matches!(cli.command, Command::BaselineShow));
        let h = "ab".repeat(32);
        let cli = Cli::try_parse_from(["maknae", "baseline-accept", &h]).expect("parses");
        assert!(matches!(&cli.command, Command::BaselineAccept { hash } if *hash == h));
        assert!(Cli::try_parse_from(["maknae", "baseline-accept"]).is_err());
        assert_eq!(
            maknae_proto::Verb::from(Verb::AdminBaselineShow),
            maknae_proto::Verb::AdminBaselineShow
        );
        assert_eq!(
            maknae_proto::Verb::from(Verb::AdminBaselineAccept {
                hash: h.clone().into()
            }),
            maknae_proto::Verb::AdminBaselineAccept { hash: h }
        );
        let cli = Cli::try_parse_from(["maknae", "audit-readers"]).expect("parses");
        assert!(matches!(
            cli.command,
            Command::AuditReaders { stopped: false }
        ));
        let cli = Cli::try_parse_from(["maknae", "audit-readers", "--stopped"]).expect("parses");
        assert!(matches!(
            cli.command,
            Command::AuditReaders { stopped: true }
        ));
    }

    #[test]
    fn policy_sync_parses_with_and_without_check() {
        for (argv, want) in [
            (&["maknae", "policy", "sync"][..], false),
            (&["maknae", "policy", "sync", "--check"][..], true),
        ] {
            let cli = Cli::try_parse_from(argv).expect("parses");
            assert!(
                matches!(cli.command, Command::Policy { action: PolicyCommand::Sync { check } } if check == want),
                "{argv:?}"
            );
        }
    }

    #[test]
    fn the_status_ends_with_the_pending_baseline_lines() {
        let s = maknae_proto::StatusView {
            version: "v".into(),
            protocol_version: 1,
            listener: "l".into(),
            authz_backend: "b".into(),
            classification_policy: "US".into(),
            kernel_graph_revision: Some(3),
            kernel_graph_anchor: Some("verified".into()),
            identity_problem_counts: vec!["unresolved=1".into()],
            baseline_pending: vec!["baseline: 1 pending (live)".into()],
        };
        let lines = status_lines(&s);
        assert_eq!(
            lines.last().map(String::as_str),
            Some("baseline: 1 pending (live)")
        );
        assert_eq!(lines[lines.len() - 2], "identity problems: 1 unresolved");
    }

    #[test]
    fn a_baseline_payload_for_any_other_verb_is_a_protocol_error() {
        let p = || Payload::Baseline(bview("none", "", "", &[]));
        for verb in [
            Verb::Ping,
            Verb::Whoami,
            Verb::AdminStatus,
            Verb::AdminConfigShow,
            Verb::AdminSubjectList,
            Verb::Read {
                path: "/a".into(),
                page: None,
            },
        ] {
            assert!(print_payload_for_verb(verb, p()).is_err());
        }
        assert!(print_payload_for_verb(Verb::AdminBaselineShow, Payload::Pong).is_err());
        assert!(print_payload_for_verb(
            Verb::AdminBaselineAccept {
                hash: "ab".repeat(32).into()
            },
            Payload::Pong
        )
        .is_err());
    }

    #[test]
    fn a_read_accepts_no_plain_payload() {
        let mismatch = print_payload_for_verb(
            Verb::Read {
                path: "/a".into(),
                page: None,
            },
            Payload::Pong,
        );
        assert!(mismatch.is_err(), "a Pong for a read is a protocol error");
    }

    /// The future `send_verb` returns must be `Send`: the CLI's `impl Plane`
    /// (`agent.rs`) returns it behind a trait bound that carries `+ Send`, and a
    /// guard held across an `.await` inside `send_verb` would otherwise only
    /// surface there. Compile-time only — never called, and that is the point:
    /// it checks the FUTURE, not a closure. It lives inside `mod tests` so a
    /// future re-tiering of `cli.rs` cannot trip
    /// `coverage_check.py`'s column-0-after-the-test-module rule.
    #[allow(dead_code)]
    fn assert_send_verb_future_is_send(
        t: &maknae_config::TransportConfig,
        c: &PlaneClient,
        ca: &maknae_vault::CaBundle,
    ) {
        fn s<T: Send>(_: T) {}
        s(send_verb(
            maknae_proto::Verb::Ping,
            None,
            crate::mutation::WriteCheck::Unchecked,
            t,
            c,
            ca,
        ));
    }
}
