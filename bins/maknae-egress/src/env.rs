//! The deputy's process environment, scrubbed before any client exists (#240b).
//!
//! Self-review round 3 corrected a false premise here: "the unit's environment
//! is clean" is not true — systemd's `DefaultEnvironment=` (system.conf) and
//! `systemctl set-environment` reach EVERY spawned service, and a proxied
//! enterprise estate sets `HTTPS_PROXY` that way as routine practice. reqwest
//! honours the proxy variables by default on both of the deputy's legs, and
//! vaultrs fills `VAULT_*` settings from the environment. Either would move a
//! connection to a destination the kernel's verdict never covered, or change
//! how it is verified. So the deputy names what it will not inherit, and
//! removes it first — the unit's `UnsetEnvironment=` does the same at the
//! init-system layer, and this is the in-process half that also covers a
//! `--bind` development run.
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
    // vaultrs's settings defaults.
    "VAULT_ADDR",
    "VAULT_TOKEN",
    "VAULT_SKIP_VERIFY",
    "VAULT_CACERT",
    "VAULT_CAPATH",
    "VAULT_CLIENT_CERT",
    "VAULT_CLIENT_KEY",
    "VAULT_NAMESPACE",
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
        ] {
            assert!(SCRUBBED_ENV.contains(&must), "{must} must be scrubbed");
        }
        assert!(!SCRUBBED_ENV.contains(&"CREDENTIALS_DIRECTORY"));
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
