//! `maknae` CLI — the untrusted interaction plane (spec §3). Resolves its own
//! config dir, mints a short-lived plane leaf, connects to `maknaed` over the
//! Stage-2 mTLS/UDS transport, and issues one verb per invocation
//! (`ping`/`whoami`) — OR, one-time and elevated, provisions the deployment via
//! `enroll`/`enroll-helper` (`enroll/`, spec §4.1-§4.6, PR-J1 Task 8).
//!
//! **Closed dependency enumeration** (Task 9's isolation gate enforces this):
//! `maknae-proto`, `maknae-vault`, `maknae-config`, `maknae-msgs`, `clap`, `tokio`,
//! `nix`, `zeroize`, `yaml-rust2`, `rpassword`, and macOS-only `security-framework`
//! (`bins/maknae/Cargo.toml`). The `ping`/`whoami` wire path below uses only the
//! first five; `nix`/`zeroize`/`yaml-rust2`/`rpassword`/`security-framework` are
//! `enroll/`-only. NO privileged crate (`maknae-kernel`/`-subject-ctx-mint`/
//! `-audit-append`/`-spif-compile`) — spec §3 P1 — even for `enroll`: it does its
//! own privileged work via `nix` safe wrappers and process re-exec (`sudo -u`),
//! never by linking the daemon's privileged crates.

use clap::{Parser, Subcommand};
use maknae_config::{load_config, transport_from_section, SectionSpec, TRANSPORT_SECTION};
use maknae_proto::{
    decode_response, encode_request_zeroizing, Payload, Request, RespResult, PROTOCOL_VERSION,
};
use maknae_proto::{read_frame, write_frame};
use maknae_vault::{load_ca_pin, Plane, PlaneClient, PlaneConnector, VAULT_SECTION};
use std::path::PathBuf;
use std::process::ExitCode;

/// The `MAKNAE_CONFIG_DIR` env var name (overrides the `$HOME/.maknae` default).
const CONFIG_DIR_ENV: &str = "MAKNAE_CONFIG_DIR";

/// Resolve the CLI's own config directory: `MAKNAE_CONFIG_DIR` if set, else
/// `$HOME/.maknae`. This is the CLI's OWN Stage-1 config dir (AppRole
/// credentials + CA pin for `Plane::Cli`) — distinct from the daemon's
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
/// absent → documented defaults). `core` is auto-registered. Loading ONCE with this
/// combined set is what lets a realistic `vault`+`transport` config load without each
/// section's own loader rejecting the other as `UnknownSection` (the P1-B fix).
fn cli_config_specs() -> [SectionSpec; 2] {
    [
        SectionSpec {
            name: VAULT_SECTION.to_string(),
            required: true,
        },
        SectionSpec {
            name: TRANSPORT_SECTION.to_string(),
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
struct Cli {
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
    /// Read a file under the enrolled home through the daemon's reference
    /// monitor (the policy in /etc/maknae/authz.yaml decides; raw bytes to
    /// stdout). Paths are sent lexically absolute; `..` is refused by the
    /// daemon's canonical pre-gate.
    Read {
        /// File to read (absolute, or relative to the current directory).
        path: std::path::PathBuf,
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
    /// active authorization backend. Ungranted by default — the operator must
    /// grant `admin.status` to a role in `authz.yaml`'s `roles:` block.
    Status,
    /// Show the effective configuration as the daemon resolved it. Secret
    /// values render `<value set>`; some keys are withheld entirely because
    /// their mere presence is a disclosure. Ungranted by default.
    ConfigShow,
    /// Enumerate role bindings as the daemon resolves them right now.
    /// Ungranted by default.
    SubjectList,
    /// One-time elevated provisioning: mint credentials, seal them to the
    /// platform HRoT, write daemon+CLI config (spec §4.1). Requires `sudo`.
    Enroll(crate::enroll::EnrollArgs),
    /// Hidden operator-context helper `enroll` re-execs via `sudo -u` — not a
    /// user-facing verb.
    #[command(hide = true, name = "enroll-helper")]
    EnrollHelper(crate::enroll::HelperArgs),
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
    Read { path: String },
    Write { path: String },
    Delete { path: String, recursive: bool },
    Mkdir { path: String, parents: bool },
    AdminStatus,
    AdminConfigShow,
    AdminSubjectList,
}

impl From<Verb> for maknae_proto::Verb {
    fn from(v: Verb) -> Self {
        match v {
            Verb::Ping => maknae_proto::Verb::Ping,
            Verb::Whoami => maknae_proto::Verb::Whoami,
            Verb::Read { path } => maknae_proto::Verb::Read { path },
            Verb::Write { path } => maknae_proto::Verb::FsWrite {
                path,
                content: maknae_proto::Bytes::new(zeroize::Zeroizing::new(Vec::new())),
                mode: maknae_proto::WriteMode::Existing,
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
        }
    }
}

fn request_from_input(
    verb: Verb,
    frame_max: usize,
    input: &mut impl std::io::Read,
) -> Result<maknae_proto::Verb, String> {
    let mut request: maknae_proto::Verb = verb.into();
    if let maknae_proto::Verb::FsWrite { content, .. } = &mut request {
        let cap = frame_max.checked_add(1).ok_or("invalid frame budget")?;
        let mut bytes = zeroize::Zeroizing::new(vec![0; cap]);
        let mut used = 0;
        loop {
            match input.read(&mut bytes[used..]) {
                Ok(0) => break,
                Ok(n) => {
                    used += n;
                    if used > frame_max {
                        return Err("stdin content exceeds the configured frame budget".into());
                    }
                }
                Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
                Err(e) => return Err(format!("reading stdin: {e}")),
            }
        }
        bytes.truncate(used);
        *content = maknae_proto::Bytes::new(bytes);
        // Includes the actual CBOR envelope, not just the content length.
        encode_request_zeroizing(
            &Request {
                protocol_version: PROTOCOL_VERSION,
                verb: request.clone(),
            },
            frame_max,
        )
        .map_err(|e| e.to_string())?;
    }
    Ok(request)
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
    // that asserts FIPS (`PlaneClient::from_document` → `mint()` assert `.fips()`). The
    // daemon does the identical install-then-assert in `run_inner`; the CLI is a separate
    // process with its own empty default provider, so it must install too — without this,
    // `mint()` fails closed with "FIPS provider not active" and the CLI never connects.
    // (Live-smoke-caught: the CLI tests only cover arg-parsing/config-discovery, never the
    // live mint path, so no unit test exercised this.)
    maknae_vault::install_default_crypto_provider();

    let dir = resolve_config_dir();

    // Load the CLI's config ONCE, registering EVERY section it uses (vault + transport)
    // so a realistic combined config is accepted; a genuinely-unknown section still
    // fails closed with UnknownSection. The single document is then parsed by-section —
    // transport here, vault inside `PlaneClient::from_document` — never re-loaded under a
    // registry that would reject the other section (the P1-B fix).
    let document = load_config(&dir, &cli_config_specs()).map_err(|e| e.to_string())?;
    let transport =
        transport_from_section(document.section(TRANSPORT_SECTION)).map_err(|e| e.to_string())?;

    let request = request_from_input(
        verb.clone(),
        transport.frame_max_bytes,
        &mut std::io::stdin().lock(),
    )?;

    let client =
        PlaneClient::from_document(&document, &dir, Plane::Cli).map_err(|e| e.to_string())?;
    let ca = load_ca_pin(&dir).map_err(|e| e.to_string())?;
    client.mint().await.map_err(|e| e.to_string())?;

    // Once `mint()` succeeds the Vault token is LIVE until lease expiry — so EVERY
    // post-mint path (success, a daemon ProtoError, OR any transport/codec/timeout error)
    // must revoke it, or the token leaks. Capture the whole round-trip outcome, revoke the
    // token UNCONDITIONALLY, THEN propagate. (A pre-mint failure above skips revoke — there
    // is nothing minted to revoke.)
    let outcome = round_trip(verb, request, &transport, &client, &ca).await;
    client.shutdown().await;
    outcome
}

/// The post-mint round trip: connect → request → (bounded) response → print. Split out so
/// [`execute`] can revoke the minted token on EVERY return path (success or error) before
/// propagating this result. Returns `Ok(true)` on a served verb, `Ok(false)` on a daemon
/// `ProtoError` (already printed), `Err` on any transport/codec/timeout failure.
/// The object this verb delegates a descriptor for, if any.
///
/// Only terms that NAME an object have one (ADR-0009). `ping` and `whoami` name none,
/// so an unarmed connection writes plainly and the daemon's OS-DAC gate never asks
/// about them.
fn delegated_object(verb: &Verb) -> Option<&str> {
    match verb {
        Verb::Read { path } => Some(path.as_str()),
        // The three admin disclosures name NO object: the state they report is
        // the daemon's own, never a client-supplied path, so there is nothing
        // for a subject to delegate a descriptor for.
        Verb::Ping
        | Verb::Write { .. }
        | Verb::Delete { .. }
        | Verb::Mkdir { .. }
        | Verb::Whoami
        | Verb::AdminStatus
        | Verb::AdminConfigShow
        | Verb::AdminSubjectList => None,
    }
}

async fn round_trip(
    verb: Verb,
    request_verb: maknae_proto::Verb,
    transport: &maknae_config::TransportConfig,
    client: &PlaneClient,
    ca: &maknae_vault::CaBundle,
) -> Result<bool, String> {
    // Bound the client-side TLS handshake by the configured `handshake_timeout_ms`: a
    // process that accepts the Unix socket but never completes TLS must not hang the CLI
    // forever (it still fails non-zero, and `execute` still revokes the token on this
    // post-mint path — a handshake timeout is a post-mint failure like any other).
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

    // ADR-0009: for a term that names an object, WE open it — as the subject — and
    // delegate the descriptor. The kernel therefore runs the whole permission check
    // (DAC bits, ACLs, supplementary groups, SELinux) under our own credentials, and
    // the daemon decides on an object it never had to resolve a name to find.
    //
    // Armed AFTER the handshake, deliberately: the handshake's own writes would
    // otherwise consume the descriptor.
    //
    // If the open FAILS the request is still sent, unarmed. That is not a fallback —
    // the daemon denies for want of a descriptor (ADR-0009 decision 2) and the refusal
    // lands in the audit trail, which is the whole reason not to fail silently here.
    let prepared = crate::mutation::prepare(request_verb.clone());
    if let Some(prepared) = &prepared {
        if let Some(error) = prepared.preparation_error() {
            eprintln!("maknae: cannot prepare filesystem operation: {error}");
        }
        if let (Some(fd), Some(armer)) = (
            prepared.descriptor().map_err(|e| e.to_string())?,
            stream.armer(),
        ) {
            armer.arm(fd);
        }
    } else if let (Some(object), Some(armer)) = (delegated_object(&verb), stream.armer()) {
        match maknae_io::open_for_delegation(std::path::Path::new(object)) {
            Ok(fd) => {
                armer.arm(fd);
            }
            Err(e) => {
                eprintln!("maknae: cannot open {object}: {e}");
            }
        }
    }

    let request = Request {
        protocol_version: PROTOCOL_VERSION,
        verb: prepared
            .as_ref()
            .map(|p| p.request().clone())
            .unwrap_or(request_verb),
    };
    let body =
        encode_request_zeroizing(&request, transport.frame_max_bytes).map_err(|e| e.to_string())?;
    // Bound the request write like the handshake and read: a daemon that accepted but
    // stopped consuming must not hang the CLI on a full socket buffer (the frame can
    // exceed the UDS buffer). `read_timeout_ms` doubles as the write bound.
    let request_started = std::time::Instant::now();
    match tokio::time::timeout(
        std::time::Duration::from_millis(transport.read_timeout_ms),
        write_frame(&mut stream, &body),
    )
    .await
    {
        Err(_elapsed) => {
            return Err(format!(
                "request write to the daemon stalled for {}ms (daemon not reading?)",
                transport.read_timeout_ms
            ))
        }
        Ok(r) => r.map_err(|e| e.to_string())?,
    }

    // Bound the response wait by the configured `read_timeout_ms`: a daemon that accepts
    // the connection but never answers must not hang the CLI forever (it still fails
    // non-zero, and `execute` still revokes the token).
    let read = tokio::time::timeout(
        std::time::Duration::from_millis(transport.read_timeout_ms),
        read_frame(&mut stream, transport.frame_max_bytes),
    )
    .await;
    let resp_body = match read {
        Err(_elapsed) => {
            return Err(format!(
                "no response from daemon within {}ms (stalled?)",
                transport.read_timeout_ms
            ))
        }
        Ok(r) => r.map_err(|e| e.to_string())?,
    };
    let response = decode_response(&resp_body).map_err(|e| e.to_string())?;

    let ok = match response.result {
        RespResult::Ok(Payload::MutationAttempt(grant)) => {
            let prepared =
                prepared.ok_or("protocol error: mutation grant for an ordinary request")?;
            return crate::mutation::execute(
                prepared,
                grant,
                &mut stream,
                transport,
                request_started,
            )
            .await;
        }
        RespResult::Ok(Payload::MutationComplete) => {
            if !matches!(prepared.as_ref(), Some(p) if !p.is_namespace()) {
                return Err(
                    "protocol error: daemon completion for a namespace or ordinary request".into(),
                );
            }
            true
        }
        RespResult::Ok(payload) => {
            // The daemon returned SOME successful payload — but it must be the payload
            // for the verb WE sent. A `Payload::Pong` for a `whoami` (or vice-versa) is
            // a protocol violation, not a result to print; propagate Err so `execute`
            // revokes the token and the CLI exits non-zero.
            print_payload_for_verb(verb, payload)?;
            true
        }
        RespResult::Err(e) => {
            eprintln!("maknae: daemon refused: {:?}: {}", e.code, e.message);
            false
        }
    };
    Ok(ok)
}

/// Print the successful `payload` IFF its variant matches the requested `verb`
/// (`Ping`→`Pong`, `Whoami`→`Whoami(_)`). A mismatched variant means the daemon
/// answered a different question than we asked — a protocol error: return `Err`
/// (the caller already revokes the token on every error path and exits non-zero).
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
        (Verb::Read { .. }, Payload::ReadContent(content)) => {
            // Raw bytes, no trailing newline, no lossy conversion — a
            // non-UTF-8 file is legal content.
            use std::io::Write;
            std::io::stdout()
                .write_all(&content.0)
                .map_err(|e| format!("writing content to stdout: {e}"))?;
            Ok(())
        }
        (Verb::AdminStatus, Payload::Status(s)) => {
            // Labels live in the format strings, not as bare literals: the
            // authz-composition drift gate's vocabulary net rejects a bare
            // PDP-naming literal in production code (ADR-0008 decision 1).
            println!("version               {}", s.version);
            println!("protocol_version      {}", s.protocol_version);
            println!("listener              {}", s.listener);
            println!("authz_backend         {}", s.authz_backend);
            println!("classification_policy {}", s.classification_policy);
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
            for b in &bindings {
                println!("{}: {}", b.role, b.members.join(", "));
            }
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
        | (v, p @ Payload::ReadContent(_))
        | (v, p @ Payload::ConfigView(_))
        | (v, p @ Payload::Status(_))
        | (v, p @ Payload::MutationAttempt(_))
        | (v, p @ Payload::MutationComplete)
        | (v, p @ Payload::SubjectList(_)) => Err(format!(
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
        Command::Read { path } => {
            // Lexically absolutize client-side (std::path::absolute keeps `..`
            // on Unix — the daemon's canonical pre-gate refuses those as
            // BadRequest, a stated consequence); `~` is the shell's business.
            match std::path::absolute(&path) {
                Ok(abs) => match abs.into_os_string().into_string() {
                    Ok(p) => wire_exit_code(execute(Verb::Read { path: p }).await),
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
        Command::Enroll(args) => crate::enroll::run_enroll(args).await,
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

#[cfg(test)]
mod tests {
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
        let request = request_from_input(verb.clone(), 512, &mut &[0, 255, 7][..]).unwrap();
        let maknae_proto::Verb::FsWrite { content, .. } = request else {
            panic!("write expected")
        };
        assert_eq!(content.0.as_slice(), &[0, 255, 7]);
        assert!(request_from_input(verb.clone(), 2, &mut &[1, 2, 3][..]).is_err());
        assert!(
            request_from_input(verb, 8, &mut &[][..]).is_err(),
            "envelope alone exceeds budget"
        );
    }

    /// Only terms that NAME an object delegate one. `ping` and `whoami` name none, so
    /// the client must not manufacture a descriptor for them — an unarmed connection
    /// writes plainly, and the daemon's gate does not ask about OS DAC for a term with
    /// no object.
    #[test]
    fn only_object_naming_verbs_delegate_a_descriptor() {
        assert_eq!(
            super::delegated_object(&super::Verb::Read {
                path: "/home/op/notes".into()
            }),
            Some("/home/op/notes")
        );
        assert_eq!(super::delegated_object(&super::Verb::Ping), None);
        assert_eq!(super::delegated_object(&super::Verb::Whoami), None);
        // The three admin disclosures too. `delegated_object` gained these arms
        // and this test did not: flipping one to `Some(..)` would make the
        // untrusted client manufacture and delegate a descriptor for a term
        // that names no object, and left the whole suite green.
        for v in [
            super::Verb::AdminStatus,
            super::Verb::AdminConfigShow,
            super::Verb::AdminSubjectList,
        ] {
            assert_eq!(super::delegated_object(&v), None, "{v:?} names no object");
        }
    }

    use super::*;
    use std::sync::Mutex;

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
                assert!(!args.rotate);
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
            "--rotate",
            "--insecure-plaintext-secret",
            "--verbose",
        ]);
        let cli = Cli::try_parse_from(argv).expect("parses");
        match cli.command {
            Command::Enroll(args) => {
                assert_eq!(args.approle_mount, "alt-approle");
                assert_eq!(args.pki_int_mount, "alt-pki-int");
                assert!(args.rotate);
                assert!(args.insecure_plaintext_secret);
                assert!(args.verbose);
            }
            other => panic!("expected Command::Enroll, got {other:?}"),
        }
    }

    #[test]
    fn enroll_helper_probe_parses() {
        let cli = Cli::try_parse_from([
            "maknae",
            "enroll-helper",
            "probe",
            "--euid",
            "1000",
            "--egid",
            "1000",
        ])
        .expect("parses");
        match cli.command {
            Command::EnrollHelper(args) => match args.verb {
                crate::enroll::HelperVerb::Probe(id) => {
                    assert_eq!(id.euid, 1000);
                    assert_eq!(id.egid, 1000);
                }
                other => panic!("expected HelperVerb::Probe, got {other:?}"),
            },
            other => panic!("expected Command::EnrollHelper, got {other:?}"),
        }
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
    // ---- read verb surface (#77) ----

    #[test]
    fn read_parses_with_a_path() {
        let cli = Cli::try_parse_from(["maknae", "read", "/home/op/notes.txt"]).unwrap();
        assert!(matches!(cli.command, Command::Read { .. }));
    }

    #[test]
    fn read_verb_converts_to_proto_with_its_path() {
        let v: maknae_proto::Verb = Verb::Read {
            path: "/a/b".into(),
        }
        .into();
        assert_eq!(
            v,
            maknae_proto::Verb::Read {
                path: "/a/b".into()
            }
        );
    }

    #[test]
    fn read_payload_arm_accepts_content_and_refuses_mismatch() {
        use maknae_proto::Bytes;
        let ok = print_payload_for_verb(
            Verb::Read { path: "/a".into() },
            Payload::ReadContent(Bytes::new(maknae_io_zeroizing(vec![b'x']))),
        );
        assert!(ok.is_ok());
        let mismatch = print_payload_for_verb(Verb::Read { path: "/a".into() }, Payload::Pong);
        assert!(mismatch.is_err(), "a Pong for a read is a protocol error");
        let mismatch2 = print_payload_for_verb(
            Verb::Ping,
            Payload::ReadContent(Bytes::new(maknae_io_zeroizing(vec![b'x']))),
        );
        assert!(mismatch2.is_err(), "content for a ping is a protocol error");
    }

    fn maknae_io_zeroizing(v: Vec<u8>) -> zeroize::Zeroizing<Vec<u8>> {
        zeroize::Zeroizing::new(v)
    }
}
