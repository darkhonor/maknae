//! The deputy's process environment, scrubbed before any client exists (#240b).
//!
//! Self-review round 3 corrected a false premise here: "the unit's environment
//! is clean" is not true — systemd's `DefaultEnvironment=` (system.conf) and
//! `systemctl set-environment` reach EVERY spawned service, and a proxied
//! enterprise estate sets `HTTPS_PROXY` that way as routine practice. Three
//! families, each verified against the locked dependency rather than recalled:
//! reqwest honours the proxy variables by default on both of the deputy's
//! legs (hyper-util's matcher, eight spellings); vaultrs fills `VAULT_*`
//! settings from the environment (seven names in its `client.rs`); and the
//! platform verifier's root store — `rustls-native-certs`, one dependency
//! further down the same reqwest build — is REPLACED, not extended, by
//! `SSL_CERT_FILE`/`SSL_CERT_DIR` on the provider leg, the one that uses the
//! platform verifier (self-review round 4: the first two families
//! decide where a connection goes, the third decides how it is verified, and
//! the third turns an inherited variable directly into the provider key in
//! an attacker's hands). So the deputy names what it will not inherit and
//! removes it first — the unit's `UnsetEnvironment=` carries the SAME list at
//! the init-system layer (a test holds the two equal), and this is the
//! in-process half that also covers a `--bind` development run.
//!
//! `CREDENTIALS_DIRECTORY` is deliberately NOT here: it is the one variable
//! the deputy exists to read.

/// Every variable removed before the first client is built. Pure data, so a
/// test can hold the list against the two families it must cover.
pub const SCRUBBED_ENV: &[&str] = &[
    // reqwest's ambient proxy set, both spellings it reads.
    "HTTP_PROXY",
    "HTTPS_PROXY",
    "ALL_PROXY",
    "NO_PROXY",
    "http_proxy",
    "https_proxy",
    "all_proxy",
    "no_proxy",
    // vaultrs 0.8.0's settings defaults — the seven names its client.rs reads.
    "VAULT_ADDR",
    "VAULT_TOKEN",
    "VAULT_SKIP_VERIFY",
    "VAULT_CACERT",
    "VAULT_CAPATH",
    "VAULT_CLIENT_CERT",
    "VAULT_CLIENT_KEY",
    // NOT read by vaultrs 0.8.0 (its `namespace` has a plain default); listed
    // so a future version that starts reading it cannot do so silently.
    "VAULT_NAMESPACE",
    // rustls-native-certs: either of these REPLACES the system trust store
    // for the platform verifier — the PROVIDER leg's verifier. (The Vault leg
    // is pinned to the deployment CA by maknae-vault's own client and never
    // consults the platform store.)
    "SSL_CERT_FILE",
    "SSL_CERT_DIR",
];

/// The scrub, over an injected remover. `main` passes `std::env::remove_var`
/// — first thing, while the process is still single-threaded. Injected so the
/// test proves every listed name is passed to it WITHOUT mutating the test
/// binary's real environment (sibling tests read it concurrently — the
/// setenv/getenv race, which is between a write and ANY read, not only of the
/// same name). There is deliberately no zero-argument wrapper: one would be a
/// production function no test could execute safely.
pub fn scrub_with(mut remove: impl FnMut(&str)) {
    for k in SCRUBBED_ENV {
        remove(k);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The list covers both families by NAME — a proxy variable in each
    /// spelling reqwest reads, and every vaultrs env default that changes where
    /// a connection goes or how it is verified — and never the one variable
    /// the deputy must keep.
    #[test]
    fn the_scrub_list_names_both_families_and_keeps_credentials_directory() {
        for must in [
            "HTTPS_PROXY",
            "https_proxy",
            "ALL_PROXY",
            "NO_PROXY",
            "VAULT_SKIP_VERIFY",
            "VAULT_ADDR",
            "VAULT_TOKEN",
            "VAULT_CLIENT_CERT",
            "VAULT_CLIENT_KEY",
            "SSL_CERT_FILE",
            "SSL_CERT_DIR",
        ] {
            assert!(SCRUBBED_ENV.contains(&must), "{must} must be scrubbed");
        }
        assert!(!SCRUBBED_ENV.contains(&"CREDENTIALS_DIRECTORY"));
    }

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

    /// The unit's `UnsetEnvironment=` is the SAME list — read from the shipped
    /// unit, so adding a name to one half and not the other goes red here.
    #[test]
    fn the_units_unset_environment_is_exactly_the_scrub_list() {
        let unit = include_str!("../../../packaging/common/maknae-egress.service");
        // Every UnsetEnvironment= line, not the first: a second one would
        // otherwise be silently unchecked.
        let mut in_unit: Vec<&str> = unit
            .lines()
            .filter_map(|l| l.strip_prefix("UnsetEnvironment="))
            .flat_map(str::split_whitespace)
            .collect();
        assert!(
            !in_unit.is_empty(),
            "the unit carries an UnsetEnvironment= line"
        );
        let mut here: Vec<&str> = SCRUBBED_ENV.to_vec();
        in_unit.sort_unstable();
        here.sort_unstable();
        assert_eq!(in_unit, here, "env.rs and maknae-egress.service disagree");
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
        let scrub = at("env::scrub_with(|k| std::env::remove_var(k))");
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

    /// The scrub passes every listed name, once, to the remover — proven over
    /// an injected remover rather than the process environment, which sibling
    /// tests in this binary read concurrently.
    #[test]
    fn scrub_removes_every_listed_variable_exactly_once() {
        let mut removed: Vec<String> = vec![];
        scrub_with(|k| removed.push(k.to_string()));
        assert_eq!(removed.len(), SCRUBBED_ENV.len());
        for k in SCRUBBED_ENV {
            assert_eq!(removed.iter().filter(|r| r == k).count(), 1, "{k}");
        }
    }
}
