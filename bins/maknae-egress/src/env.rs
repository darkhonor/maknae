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
//! `SSL_CERT_FILE`/`SSL_CERT_DIR` (self-review round 4: the first two families
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
    // for the platform verifier, on both legs.
    "SSL_CERT_FILE",
    "SSL_CERT_DIR",
];

/// Remove every [`SCRUBBED_ENV`] variable. Called first thing in `main`, while
/// the process is still single-threaded (the environment is process-global).
pub fn scrub_env() {
    for k in SCRUBBED_ENV {
        std::env::remove_var(k);
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

    /// The unit's `UnsetEnvironment=` is the SAME list — read from the shipped
    /// unit, so adding a name to one half and not the other goes red here.
    #[test]
    fn the_units_unset_environment_is_exactly_the_scrub_list() {
        let unit = include_str!("../../../packaging/common/maknae-egress.service");
        let line = unit
            .lines()
            .find_map(|l| l.strip_prefix("UnsetEnvironment="))
            .expect("the unit carries an UnsetEnvironment= line");
        let mut in_unit: Vec<&str> = line.split_whitespace().collect();
        let mut here: Vec<&str> = SCRUBBED_ENV.to_vec();
        in_unit.sort_unstable();
        here.sort_unstable();
        assert_eq!(in_unit, here, "env.rs and maknae-egress.service disagree");
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

    /// The scrub actually removes them from THIS process.
    #[test]
    fn scrub_env_removes_every_listed_variable() {
        std::env::set_var("HTTPS_PROXY", "http://proxy.test:3128");
        std::env::set_var("VAULT_SKIP_VERIFY", "");
        scrub_env();
        for k in SCRUBBED_ENV {
            assert!(std::env::var_os(k).is_none(), "{k} survived the scrub");
        }
    }
}
