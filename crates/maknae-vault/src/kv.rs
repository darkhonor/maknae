//! KV v2 secret reads (#240a).
//!
//! This crate owns **every** Vault interaction — AppRole login, the plane
//! client, the operator client, credential sourcing. A second Vault client in
//! a `bins/` crate would be the `maknae-io` failure one layer up: two sites
//! re-implementing security-critical code, one of them the process that holds
//! the provider credential. So the KV read lives here.
//!
//! Split pure/IO like the rest of the crate (`secret_io`/`secret_source`,
//! `syslog_io`/`syslog_fmt`): THIS file is the parsing decision and is
//! unit-tested; the network call lives in `kv_io.rs` and is exercised by an
//! operator-gated live test against a real Vault — this project has no Vault
//! stub and deliberately uses none.

use crate::VaultError;

/// The marker KV v2 inserts between the mount and the secret's path.
const KV2_DATA: &str = "/data/";

/// Split a configured `key_vault_path` into the `(mount, path)` pair
/// `vaultrs::kv2::read` wants.
///
/// The operator writes ONE string — `secret/data/maknae/providers/openai` —
/// because that is what Vault's own UI and CLI show and what a policy stanza
/// contains. The API takes the two halves separately and re-inserts `data`
/// itself, so this is a real translation and not a formality.
///
/// Fail-closed on every ambiguity: no `/data/` marker, an empty mount, an
/// empty secret path, a leading slash, or any `.`/`..` segment. A path that
/// cannot be split unambiguously is refused rather than guessed at — guessing
/// here would read the wrong secret, or read one outside the deputy's grant.
pub fn split_kv_path(key_vault_path: &str) -> Result<(&str, &str), VaultError> {
    let refuse = |why: &str| {
        Err(VaultError::InvalidKeyVaultPath(format!(
            "'{key_vault_path}': {why}"
        )))
    };
    if key_vault_path.starts_with('/') {
        return refuse("must not start with '/'");
    }
    // `find`, not `rfind`: the FIRST marker is the mount boundary. A secret
    // whose own path contains `data` must not be able to move the split.
    let Some(i) = key_vault_path.find(KV2_DATA) else {
        return refuse("is not a KV v2 path (no '/data/' segment)");
    };
    let mount = &key_vault_path[..i];
    let path = &key_vault_path[i + KV2_DATA.len()..];
    if mount.is_empty() {
        return refuse("has an empty mount");
    }
    if path.is_empty() {
        return refuse("has an empty secret path");
    }
    if path
        .split('/')
        .any(|seg| seg.is_empty() || seg == "." || seg == "..")
    {
        return refuse("has an empty, '.' or '..' segment");
    }
    Ok((mount, path))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_well_formed_kv2_path_splits_into_mount_and_path() {
        assert_eq!(
            split_kv_path("secret/data/maknae/providers/openai").unwrap(),
            ("secret", "maknae/providers/openai")
        );
        assert_eq!(split_kv_path("kv/data/x").unwrap(), ("kv", "x"));
    }

    /// The FIRST `/data/` is the mount boundary. A secret whose own path
    /// contains a `data` segment must not be able to move the split — that
    /// would read a different secret than the operator wrote and the boot gate
    /// validated.
    #[test]
    fn a_data_segment_inside_the_secret_path_does_not_move_the_split() {
        assert_eq!(
            split_kv_path("secret/data/maknae/data/openai").unwrap(),
            ("secret", "maknae/data/openai")
        );
    }

    /// Every ambiguity is a refusal, never a guess: guessing reads the wrong
    /// secret, or one outside the deputy's grant.
    #[test]
    fn every_ambiguous_path_is_refused() {
        for bad in [
            "secret/maknae/openai", // no /data/ marker at all
            "/secret/data/x",       // leading slash
            "/data/x",              // empty mount
            "secret/data/",         // empty secret path
            "secret/data/a//b",     // empty segment
            "secret/data/a/../b",   // traversal
            "secret/data/a/./b",    // current-dir segment
            "",
        ] {
            assert!(
                split_kv_path(bad).is_err(),
                "expected a refusal for {bad:?}"
            );
        }
    }
}
