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
use maknae_vault::{load_ca_pin, Plane, PlaneClient, PlaneConnector};
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

    // The CLI reads only the `transport` section (the daemon's socket path +
    // frame cap) from its own config dir — schema-agnostic, mirrors
    // maknae-kernel's boot.rs.
    let specs = [SectionSpec {
        name: TRANSPORT_SECTION.to_string(),
        required: false,
    }];
    let document = load_config(&dir, &specs).map_err(|e| e.to_string())?;
    let transport =
        transport_from_section(document.section(TRANSPORT_SECTION)).map_err(|e| e.to_string())?;

    let client = PlaneClient::from_config_dir(&dir, Plane::Cli).map_err(|e| e.to_string())?;
    let ca = load_ca_pin(&dir).map_err(|e| e.to_string())?;
    client.mint().await.map_err(|e| e.to_string())?;

    let mut stream = PlaneConnector::connect(&transport.socket_path, &client, &ca)
        .await
        .map_err(|e| e.to_string())?;

    let request = Request {
        protocol_version: PROTOCOL_VERSION,
        verb: verb.into(),
    };
    let body = encode_request(&request).map_err(|e| e.to_string())?;
    write_frame(&mut stream, &body)
        .await
        .map_err(|e| e.to_string())?;
    let resp_body = read_frame(&mut stream, transport.frame_max_bytes)
        .await
        .map_err(|e| e.to_string())?;
    let response = decode_response(&resp_body).map_err(|e| e.to_string())?;

    let ok = match response.result {
        RespResult::Ok(Payload::Pong) => {
            println!("pong");
            true
        }
        RespResult::Ok(Payload::Whoami(w)) => {
            println!("{} uid={}", w.peer_plane_uri_san, w.peer_uid);
            true
        }
        RespResult::Err(e) => {
            eprintln!("maknae: daemon refused: {:?}: {}", e.code, e.message);
            false
        }
    };

    // Best-effort revoke on the way out, whether the verb itself succeeded or
    // the daemon returned a ProtoError — only an earlier connection-level
    // failure (above) skips this (the process is exiting anyway).
    client.shutdown().await;
    Ok(ok)
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
}
