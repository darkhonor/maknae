//! `maknae` CLI — the untrusted interaction plane (spec §3). Resolves its own
//! config dir, mints a short-lived plane leaf, connects to `maknaed` over the
//! Stage-2 mTLS/UDS transport, and issues one read-only verb per invocation.
//! STRICTLY non-privileged: this crate links ONLY `maknae-proto`, `maknae-vault`,
//! `maknae-config`, `clap`, `tokio` (Task 9's isolation gate enforces this).

use clap::{Parser, Subcommand};
use maknae_config::{load_config, transport_from_section, SectionSpec, TRANSPORT_SECTION};
use maknae_proto::{
    decode_response, encode_request, Payload, Request, RespResult, PROTOCOL_VERSION,
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

/// `maknae` — read-only verbs over the mTLS plane.
#[derive(Parser, Debug)]
#[command(name = "maknae", about = "Untrusted CLI plane for maknaed (read-only)")]
struct Cli {
    #[command(subcommand)]
    verb: Verb,
}

/// The read-only verbs this CLI can issue (mirrors `maknae_proto::Verb`, kept as
/// a distinct clap-derived type so the wire contract doesn't grow a `clap`
/// dependency).
#[derive(Subcommand, Debug, Clone, Copy, PartialEq, Eq)]
enum Verb {
    /// Check that the daemon is reachable.
    Ping,
    /// Report the verified peer plane identity (URI-SAN + uid).
    Whoami,
}

impl From<Verb> for maknae_proto::Verb {
    fn from(v: Verb) -> Self {
        match v {
            Verb::Ping => maknae_proto::Verb::Ping,
            Verb::Whoami => maknae_proto::Verb::Whoami,
        }
    }
}

/// The full round trip: resolve config → mint a plane leaf → connect →
/// request/response → print → shut down. Returns `Ok(true)` on a successful
/// verb response, `Ok(false)` when the daemon returned a `ProtoError` (already
/// printed to stderr — the caller maps this to a non-zero exit), `Err` for any
/// earlier (config/mint/connect/frame) failure.
async fn execute(verb: Verb) -> Result<bool, String> {
    let dir = resolve_config_dir();

    // Load the CLI's config ONCE, registering EVERY section it uses (vault + transport)
    // so a realistic combined config is accepted; a genuinely-unknown section still
    // fails closed with UnknownSection. The single document is then parsed by-section —
    // transport here, vault inside `PlaneClient::from_document` — never re-loaded under a
    // registry that would reject the other section (the P1-B fix).
    let document = load_config(&dir, &cli_config_specs()).map_err(|e| e.to_string())?;
    let transport =
        transport_from_section(document.section(TRANSPORT_SECTION)).map_err(|e| e.to_string())?;

    let client =
        PlaneClient::from_document(&document, &dir, Plane::Cli).map_err(|e| e.to_string())?;
    let ca = load_ca_pin(&dir).map_err(|e| e.to_string())?;
    client.mint().await.map_err(|e| e.to_string())?;

    // Once `mint()` succeeds the Vault token is LIVE until lease expiry — so EVERY
    // post-mint path (success, a daemon ProtoError, OR any transport/codec/timeout error)
    // must revoke it, or the token leaks. Capture the whole round-trip outcome, revoke the
    // token UNCONDITIONALLY, THEN propagate. (A pre-mint failure above skips revoke — there
    // is nothing minted to revoke.)
    let outcome = round_trip(verb, &transport, &client, &ca).await;
    client.shutdown().await;
    outcome
}

/// The post-mint round trip: connect → request → (bounded) response → print. Split out so
/// [`execute`] can revoke the minted token on EVERY return path (success or error) before
/// propagating this result. Returns `Ok(true)` on a served verb, `Ok(false)` on a daemon
/// `ProtoError` (already printed), `Err` on any transport/codec/timeout failure.
async fn round_trip(
    verb: Verb,
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

    let request = Request {
        protocol_version: PROTOCOL_VERSION,
        verb: verb.into(),
    };
    let body = encode_request(&request).map_err(|e| e.to_string())?;
    write_frame(&mut stream, &body)
        .await
        .map_err(|e| e.to_string())?;

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
        (v, p) => Err(format!(
            "protocol error: daemon returned a {p:?} payload for a {v:?} request"
        )),
    }
}

/// The `maknae` entrypoint: parse args, run the round trip, map the outcome to
/// an exit code. Fail-closed — any error prints to stderr and exits non-zero.
pub async fn run_cli() -> ExitCode {
    let cli = Cli::parse();
    match execute(cli.verb).await {
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
        assert_eq!(cli.verb, Verb::Ping);
    }

    #[test]
    fn parses_whoami() {
        let cli = Cli::try_parse_from(["maknae", "whoami"]).expect("parses");
        assert_eq!(cli.verb, Verb::Whoami);
    }

    #[test]
    fn rejects_unknown_verb() {
        assert!(Cli::try_parse_from(["maknae", "bogus"]).is_err());
    }

    #[test]
    fn rejects_no_verb() {
        assert!(Cli::try_parse_from(["maknae"]).is_err());
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
}
