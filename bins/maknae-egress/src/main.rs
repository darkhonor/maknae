//! `maknae-egress` — the egress deputy (#240a).
//!
//! The only process with a route out, running as `_maknae-egress`. It holds
//! its seal key and a socket and nothing else: no Vault identity, no policy,
//! no provider registry, no identity map, no audit sink. It makes no identity
//! decision: the kernel decided who the subject is before the frame existed,
//! and the `key_vault_path` it is handed carries the requester's user segment
//! only so it can act on that user's behalf. It never originates a call of its
//! own.
//!
//! **Amended 2026-09-21 by #264:** the binary also links `maknae-llm`'s
//! compiled-in core prompt and baseline tool definitions, and composes them
//! into every outbound request (`call.rs`). That is not a walk-back of "no
//! policy" above: those artifacts are policy **APPROVED at design time** —
//! `include_str!`'d from reviewable text files, changed only by a reviewed
//! commit — not policy **EVALUATED at runtime**. The deputy still decides
//! nothing, holds no registry, and reads no configuration for them. The "no
//! policy" clause is about runtime state and decisions, and that is unchanged.
//! *(Recorded because misreading this exact clause as excluding the preamble
//! cost a design round on #264 and needed a maintainer ruling to unwind.)*
//!
//! Thin by design (T3, the `bins/maknaed` precedent): the decision is in
//! `handle`, the I/O in `serve`, the socket in `listen`.

mod listen;
mod opener;
mod serve;

use maknae_deputy::call;

use std::path::PathBuf;

const BOUNDS_PATH: &str = "/etc/maknae/egress-bounds.yaml";
/// The account the kernel runs as. The deputy speaks to nobody else.
const KERNEL_USER: &str = "_maknae";

fn fail(msg: impl std::fmt::Display) -> ! {
    eprintln!("maknae-egress: refusing to start: {msg}");
    std::process::exit(1)
}

fn main() {
    // FIRST of all, while single-threaded: nothing inherited from the
    // environment may choose where a connection goes or how it is verified.
    // "The unit's environment is clean" is not true — `DefaultEnvironment=`
    // and `systemctl set-environment` reach every service. The list, and the
    // names deliberately KEPT (`CREDENTIALS_DIRECTORY` and the `LISTEN_*` this
    // process exists to read), are `maknae_vault::{SCRUBBED_ENV,
    // NEVER_SCRUB_ENV}` — shared with `maknaed` and `maknae` since #318, held
    // disjoint by a test there.
    maknae_vault::scrub_with(|k| std::env::remove_var(k));

    let mut args = std::env::args().skip(1);
    let mut bind: Option<PathBuf> = None;
    let mut bounds_path = PathBuf::from(BOUNDS_PATH);
    while let Some(a) = args.next() {
        match a.as_str() {
            // The Linux dev/harness path AND the macOS launchd job's path
            // (#76); the shipped Linux unit socket-activates and passes no
            // bind path, a packaging test asserts that.
            "--bind" => bind = args.next().map(PathBuf::from),
            // Development only: the Vault CA and the macOS seal-key pointer
            // are read from `egress/` beside the bounds file, not from a fixed path.
            "--bounds" => bounds_path = args.next().map(PathBuf::from).unwrap_or(bounds_path),
            other => fail(format!("unknown argument '{other}'")),
        }
    }

    // FIRST, before any client exists: the process-default CryptoProvider.
    // `maknae-llm` and `maknae-vault` both assert `.fips()` at the moment a
    // credential rides TLS; without this install every call would refuse.
    // The same ordering as `maknae_kernel::run`.
    maknae_vault::install_default_crypto_provider();
    if let Err(e) = maknae_vault::assert_fips_provider() {
        fail(e);
    }

    // The error names the file (or the path that failed) itself.
    let bounds = match maknae_config::load_egress_bounds(&bounds_path) {
        Ok(b) => b,
        Err(e) => fail(e),
    };

    // Resolved ONCE, at startup, fail-closed. Never per request: a name lookup
    // on the serving path is the hazard the group-lookup circuit breaker
    // exists to prevent.
    let expected_uid = match nix::unistd::User::from_name(KERNEL_USER) {
        Ok(Some(u)) => u.uid.as_raw(),
        Ok(None) => fail(format!("no such account '{KERNEL_USER}'")),
        Err(e) => fail(format!("cannot resolve '{KERNEL_USER}': {e}")),
    };

    // One current-thread runtime for the process: the provider call and the
    // Vault read are futures, and the serving path is otherwise blocking.
    let rt = match tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
    {
        Ok(r) => r,
        Err(e) => fail(format!("cannot start a runtime: {e}")),
    };

    let egress_dir = bounds_path
        .parent()
        .map(|p| p.join("egress"))
        .unwrap_or_else(|| PathBuf::from("/etc/maknae/egress"));
    let credentials_dir = match maknae_vault::credentials_directory_env() {
        Ok(c) => c,
        Err(e) => fail(format!("egress seal key: {e}")),
    };
    let key = match maknae_vault::read_egress_seal_key(credentials_dir.as_deref(), &egress_dir) {
        Ok(der) => match maknae_seal::SealPrivateKey::from_pkcs8_der(der.expose()) {
            Ok(k) => k,
            Err(e) => fail(format!("egress seal key: {e}")),
        },
        Err(e) => fail(format!("egress seal key: {e}")),
    };
    let api = match maknae_vault::VaultApi::new(
        &bounds.vault_addr,
        &egress_dir.join(maknae_vault::EGRESS_VAULT_CA_FILE),
    ) {
        Ok(a) => a,
        Err(e) => fail(format!("vault client: {e}")),
    };
    let opener = opener::SealedOpener { key, api };

    let listener = match listen::from_init_system() {
        Ok(Some(l)) => l,
        Ok(None) => match bind {
            Some(p) => {
                let kernel_gid = match nix::unistd::Group::from_name(KERNEL_USER) {
                    Ok(Some(g)) => g.gid,
                    Ok(None) => fail(format!("no such group '{KERNEL_USER}'")),
                    Err(e) => fail(format!("cannot resolve group '{KERNEL_USER}': {e}")),
                };
                match listen::bind_gated(&rt, &p, kernel_gid) {
                    Ok(l) => l,
                    Err(e) => fail(e),
                }
            }
            None => fail("no socket from the init system and no --bind path"),
        },
        Err(e) => fail(e),
    };

    // Accept forever. A failed connection is refused and the loop continues:
    // one bad or hostile peer must not take the deputy down. This is wiring,
    // not logic — the decision is `handle::decide`, the per-connection I/O is
    // `serve::serve_one`, and both are tested.
    for conn in listener.incoming() {
        match conn {
            Ok(s) => {
                if let Err(e) = serve::serve_one(s, expected_uid, &bounds, |admitted| {
                    rt.block_on(call::fulfil(admitted, &opener, call::CallBounds::default()))
                        .map_err(serve::serve_error)
                }) {
                    eprintln!("maknae-egress: connection refused: {e:?}");
                }
            }
            Err(e) => eprintln!("maknae-egress: accept failed: {e}"),
        }
    }
}

#[cfg(test)]
mod tests {

    /// The deputy's unit carries EVERY `[Service]` line maknaed's unit
    /// carries, except a NAMED set that differs by design, and NEITHER carries
    /// the two directives maknaed's unit records as a measured SIGSYS
    /// crash-loop for aws-lc-fips — the module both binaries install at start.
    /// Derived from the daemon's file, not an allowlist: a directive added to
    /// maknaed.service is held to the deputy by default (review round 6; the
    /// first version of this test was an allowlist that already missed
    /// `AmbientCapabilities=`). Lines are trimmed, as systemd trims them.
    #[test]
    fn the_units_confinement_is_maknaeds_and_never_the_two_fips_incompatible_directives() {
        let deputy = include_str!("../../../packaging/common/maknae-egress.service");
        let daemon = include_str!("../../../packaging/common/maknaed.service");
        fn service_lines(unit: &str) -> Vec<&str> {
            let mut in_service = false;
            let mut out = Vec::new();
            for raw in unit.lines() {
                let l = raw.trim();
                if l.starts_with('[') {
                    in_service = l == "[Service]";
                    continue;
                }
                if in_service && !l.is_empty() && !l.starts_with('#') {
                    out.push(l);
                }
            }
            out
        }
        for unit in [deputy, daemon] {
            for l in service_lines(unit) {
                assert!(
                    !l.starts_with("MemoryDenyWriteExecute="),
                    "MemoryDenyWriteExecute= crash-loops aws-lc-fips (measured)"
                );
                assert!(
                    !l.starts_with("SystemCallFilter=~"),
                    "a subtractive SystemCallFilter crash-loops aws-lc-fips (measured)"
                );
            }
        }
        // Differ by design — each named, each with its reason in the units.
        const DEPUTY_DIFFERS: &[&str] = &[
            "ExecStart=",               // its own binary
            "ExecReload=",              // the daemon's SIGHUP policy reload
            "LoadCredentialEncrypted=", // its own sealed seal key
            "ProtectHome=",             // `yes` here, `read-only` for the daemon's read path
            "ReadWritePaths=",          // the daemon's audit sink; the deputy writes nothing
            "Restart=",
            "RestartSec=",
            "RuntimeDirectory=", // the deputy's is the socket unit's
            "RuntimeDirectoryMode=",
            "StandardError=",
            "StandardOutput=",
            "StateDirectory=", // the daemon's kernel graph store; the deputy keeps no state
            "StateDirectoryMode=",
            "SupplementaryGroups=", // the daemon's socket-group gate
            "SyslogIdentifier=",
            "TimeoutStopSec=", // the daemon's drain chain; the deputy has no handler
            "Type=",
            "User=",
        ];
        let deputy_lines = service_lines(deputy);
        let mut held = 0;
        for line in service_lines(daemon) {
            if DEPUTY_DIFFERS.iter().any(|p| line.starts_with(p)) {
                continue;
            }
            assert!(
                deputy_lines.contains(&line),
                "maknaed.service's `{line}` is missing from maknae-egress.service"
            );
            held += 1;
        }
        assert!(
            held >= 17,
            "only {held} hardening lines were held to the deputy"
        );
    }

    #[test]
    fn main_scrubs_first_and_loads_its_keys_before_adopting_the_listener() {
        let src = include_str!("main.rs");
        let at = |needle: &str| {
            src.find(needle)
                .unwrap_or_else(|| panic!("{needle} not in main.rs"))
        };
        let scrub = at(concat!(
            "maknae_vault::scrub_with(|k| ",
            "std::env::remove_var(k))"
        ));
        let fips = at(concat!(
            "maknae_vault::install_default_crypto_provider",
            "();"
        ));
        let seal = at(concat!(
            "maknae_vault::read_egress_seal_key",
            "(credentials_dir.as_deref(), &egress_dir)"
        ));
        let parse = at(concat!(
            "maknae_seal::SealPrivateKey::from_pkcs8_der",
            "(der.expose())"
        ));
        let client = at(concat!("maknae_vault::VaultApi::new", "("));
        let listener = at(concat!("listen::from_init_system", "()"));
        let mapped = at(concat!(".map_err(serve::", "serve_error)"));
        assert!(scrub < fips, "the scrub must precede the FIPS install");
        assert!(scrub < seal, "the scrub must precede reading the seal key");
        assert!(
            fips < seal,
            "the FIPS install must precede reading the seal key"
        );
        assert!(seal < parse, "the seal key is parsed from what was read");
        assert!(fips < client, "the FIPS install must precede any client");
        assert!(
            parse < listener,
            "the seal key must be parsed before the listener is adopted"
        );
        assert!(
            client < listener,
            "the Vault client must exist before the listener is adopted"
        );
        assert!(
            listener < mapped,
            "the accept loop maps fulfil failures through serve::serve_error"
        );
        assert!(
            !src.contains(concat!("App", "Role")) && !src.contains(concat!("probe", "_login")),
            "the Egress Daemon holds no Vault identity and logs in to nothing"
        );
    }

    /// The shipped unit socket-activates: its ExecStart carries no --bind.
    /// (main.rs and listen.rs both said "a packaging test asserts that"; until
    /// now none did.)
    #[test]
    fn the_shipped_unit_passes_no_bind_path() {
        let unit = include_str!("../../../packaging/common/maknae-egress.service");
        let exec = unit
            .lines()
            .find_map(|l| l.strip_prefix("ExecStart="))
            .expect("ExecStart=");
        assert!(!exec.contains("--bind"), "{exec}");
        assert!(!exec.contains("--bounds"), "{exec}");
    }

    #[test]
    fn the_macos_job_binds_the_socket_the_daemon_is_told_about() {
        let plist = include_str!("../../../packaging/macos/io.maknae.maknae-egress.plist");
        let args: Vec<&str> = plist
            .split("<key>ProgramArguments</key>")
            .nth(1)
            .and_then(|s| s.split("</array>").next())
            .expect("ProgramArguments")
            .lines()
            .filter_map(|l| l.trim().strip_prefix("<string>")?.strip_suffix("</string>"))
            .collect();
        assert_eq!(
            args,
            [
                "/usr/local/bin/maknae-egress",
                "--bind",
                maknae_config::MACOS_EGRESS_SOCKET_PATH
            ]
        );
        assert!(plist.contains("<key>UserName</key>\n  <string>_maknae-egress</string>"));
    }
}
