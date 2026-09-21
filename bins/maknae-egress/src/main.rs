//! `maknae-egress` — the egress deputy (#240a).
//!
//! The only process with a route out, running as `_maknae-egress` under its
//! own Vault policy. It holds a credential and a socket and nothing else: no
//! policy, no provider registry, no identity map, no audit sink. It never
//! learns WHO the subject is — the kernel decided that long before the frame
//! existed — and it never originates a call of its own.
//!
//! Thin by design (T3, the `bins/maknaed` precedent): the decision is in
//! `handle`, the I/O in `serve`, the socket in `listen`.

mod call;
mod handle;
mod keys;
mod keys_vault;
mod listen;
mod serve;

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
            // Development only. The shipped unit socket-activates and passes
            // no bind path; a packaging test asserts that.
            "--bind" => bind = args.next().map(PathBuf::from),
            // Development only, likewise — and it relocates the whole
            // credential set: the RoleID and the Vault CA are read from
            // `egress/` BESIDE the bounds file, not from a fixed path.
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

    // The third plane's credential (#240b): the RoleID and the Vault CA sit
    // beside the bounds file under `egress/`, the SecretID comes from
    // $CREDENTIALS_DIRECTORY (the unit's LoadCredentialEncrypted=). Resolved
    // ONCE, fail-closed, and the SecretID is `Zeroizing` from the read. The
    // AppRole mount defaults to the packaged Terraform's, resolved HERE rather
    // than in the config crate so there is one place for that default.
    let egress_dir = bounds_path
        .parent()
        .map(|p| p.join("egress"))
        .unwrap_or_else(|| PathBuf::from("/etc/maknae/egress"));
    let approle_mount = bounds
        .approle_mount
        .clone()
        .unwrap_or_else(|| maknae_vault::DEFAULT_APPROLE_MOUNT.to_string());
    let auth = match maknae_vault::load_egress_auth(
        &egress_dir,
        approle_mount,
        std::env::var("CREDENTIALS_DIRECTORY").ok().as_deref(),
    ) {
        Ok(a) => a,
        Err(e) => fail(format!("egress credential: {e}")),
    };
    let vault = match maknae_vault::EgressVault::new(
        &bounds.vault_addr,
        &egress_dir.join(maknae_vault::EGRESS_VAULT_CA_FILE),
        auth,
    ) {
        Ok(v) => v,
        Err(e) => fail(format!("vault client: {e}")),
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

    // Boot probe BEFORE the listener is adopted: one login and one revoke. A
    // wrong SecretID, or a Vault the deputy cannot reach, refuses START — not
    // the first live request (the same preference the kernel's bounds boot
    // gate records) — and refuses it before the listener is adopted, so the
    // connections already queued on the activation socket are not accepted
    // and dropped by a process that is about to exit.
    if let Err(e) = rt.block_on(vault.probe_login()) {
        fail(format!("vault login probe: {e}"));
    }

    let listener = match listen::from_init_system() {
        Ok(Some(l)) => l,
        Ok(None) => match bind {
            Some(p) => match listen::bind_path(&p) {
                Ok(l) => l,
                Err(e) => fail(e),
            },
            None => fail("no socket from the init system and no --bind path"),
        },
        Err(e) => fail(e),
    };

    // ONE cache for the PROCESS, outside the accept loop.
    //
    // Reviewed finding (#296): this was constructed inside the per-connection
    // closure, which gave "read on first use, cached per destination" a lifetime
    // of exactly one request — every prompt would have re-read Vault and then
    // dropped the entry. The unit test passed because IT held a cache across
    // calls; the deputy never did. A cache the production path rebuilds per
    // request is not a cache.
    //
    // CONCURRENCY MODEL, stated because a shared mutable cache needs one: the
    // accept loop is SEQUENTIAL — `incoming()` yields one connection at a time
    // and each is served to completion before the next is accepted — so access
    // is serialized by construction and needs no lock. If the deputy ever serves
    // connections concurrently, this becomes shared state and must gain one;
    // the `&mut` borrow here is what will force that decision rather than
    // letting it pass silently.
    let mut keys = keys::KeyCache::new(keys_vault::VaultKeys { vault });

    // Accept forever. A failed connection is refused and the loop continues:
    // one bad or hostile peer must not take the deputy down. This is wiring,
    // not logic — the decision is `handle::decide`, the per-connection I/O is
    // `serve::serve_one`, and both are tested.
    for conn in listener.incoming() {
        match conn {
            Ok(s) => {
                if let Err(e) = serve::serve_one(s, expected_uid, &bounds, |admitted| {
                    // The real fulfilment path: the key is read through the
                    // cache on first use per destination (#240b), then the
                    // provider call is made under the FIPS provider installed
                    // above.
                    rt.block_on(call::fulfil(
                        admitted,
                        &mut keys,
                        call::CallBounds::default(),
                        // #308: the KV mount, from the deputy's own bounds
                        // document — the only place it is declared, because the
                        // deputy is the only component in the tree that reads KV.
                        &bounds.kv_mount,
                    ))
                    .map_err(|e| serve::ServeError::Fulfil(e.to_string()))
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
            "LoadCredentialEncrypted=", // its own sealed SecretID
            "ProtectHome=",             // `yes` here, `read-only` for the daemon's read path
            "ReadWritePaths=",          // the daemon's audit sink; the deputy writes nothing
            "Restart=",
            "RestartSec=",
            "RuntimeDirectory=", // the deputy's is the socket unit's
            "RuntimeDirectoryMode=",
            "StandardError=",
            "StandardOutput=",
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

    /// `main` runs the scrub before anything else, and the boot probe before
    /// the listener is adopted — fail-closed ORDERINGS asserted in comments,
    /// pinned here by source order the way the kernel's boot gate pins its
    /// gate-before-mint (a behavioural test cannot reach a T3 main).
    #[test]
    fn main_scrubs_first_and_probes_before_adopting_the_listener() {
        let src = include_str!("main.rs");
        let at = |needle: &str| {
            src.find(needle)
                .unwrap_or_else(|| panic!("{needle} not in main.rs"))
        };
        // The WHOLE call site, remover included: `scrub_with(|_| {})` would
        // keep every other assertion here green while the deputy inherited
        // HTTPS_PROXY again.
        let scrub = at(concat!(
            "maknae_vault::scrub_with(|k| ",
            "std::env::remove_var(k))"
        ));
        let fips = at("install_default_crypto_provider()");
        let client = at("EgressVault::new(");
        let probe = at("vault.probe_login()");
        let listener = at("listen::from_init_system()");
        assert!(scrub < fips, "the scrub must precede the FIPS install");
        assert!(scrub < client, "the scrub must precede any client");
        assert!(fips < client, "the FIPS install must precede any client");
        assert!(probe < listener, "the probe must precede the listener");
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
}
