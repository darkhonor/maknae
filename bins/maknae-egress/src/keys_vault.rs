//! The Vault-backed [`KeySource`](crate::keys::KeySource) — the I/O half.
//!
//! Split from `keys.rs` for the reason this tree splits `kv_io`/`kv` and
//! `secret_io`/`secret_source`: the CACHE is a decision worth mutation-testing
//! and this is a network read no unit test should stand in for. This project
//! has no Vault stub and deliberately uses none.

use crate::keys::KeySource;
use zeroize::Zeroizing;

// Not constructed until the Vault client is built (the AppRole login against
// the sealed SecretID, which cannot be verified until the third plane is
// provisioned). Kept and allowed rather than deleted: it is the production
// source, its shape is reviewed here, and deleting it would mean writing it
// again blind in the slice that finally wires it.
#[allow(dead_code)]
/// Reads through `maknae-vault`, which owns every Vault interaction.
pub struct VaultKeys<C> {
    pub client: C,
}

impl<C: maknae_vault::VaultClientTrait + Sync> KeySource for VaultKeys<C> {
    /// No `block_on` and no runtime handle. An earlier version held a
    /// `runtime::Handle` and blocked on it — which PANICS, because the deputy
    /// already calls `fulfil` inside that runtime and Tokio refuses a nested
    /// block. The credential error this design promises could never have been
    /// produced; the process would have aborted instead (#296).
    async fn read(
        &self,
        mount: &str,
        path: &str,
        field: &str,
    ) -> Result<Zeroizing<String>, String> {
        // #308: compose here, in the SOURCE, because addressing is the store's
        // business. `data/` is a KV v2 API artifact — it is synthesized rather
        // than written in configuration, which also means a configured path can
        // never name `metadata/`, the parallel tree a `list` would enumerate.
        maknae_vault::read_kv_field(&self.client, &format!("{mount}/data/{path}"), field)
            .await
            .map_err(|e| e.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keys::KeyCache;

    /// THE composition the panic lived in, exercised for real.
    ///
    /// Reviewed finding (#296): `VaultKeys::read` was synchronous and bridged
    /// with `Handle::block_on`, while the deputy calls `fulfil` inside that same
    /// runtime — Tokio aborts on a nested block, so the named credential error
    /// could never be produced. Every test used a synchronous FAKE source, so
    /// nothing touched the code that panicked.
    ///
    /// This drives the real `VaultKeys` through the real `KeyCache`, from inside
    /// a runtime, exactly as `main` does. A Vault at a dead address gives a
    /// transport failure — the point is that it RETURNS one rather than
    /// aborting the process.
    #[test]
    fn the_real_vault_source_returns_an_error_from_inside_a_runtime() {
        maknae_vault::install_default_crypto_provider();
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();

        // A client pointed at a port nothing listens on.
        let settings = vaultrs_settings();
        let client = match settings {
            Some(c) => c,
            // If a client cannot be constructed on this host at all, the
            // composition under test cannot be reached; say so rather than
            // reporting a pass.
            None => panic!("could not construct a Vault client for the composition test"),
        };

        // #308: `VaultKeys` no longer carries a field name. The field is a
        // PER-REQUEST value from the frame, because the registry knows it and the
        // deputy must not guess — the constant that used to live here was the
        // only field name in the tree, and it said `api_key` while a real
        // deployment stored `api-key`.
        let mut keys = KeyCache::new(VaultKeys { client });

        // INSIDE the runtime — the exact shape that used to abort.
        let out = rt.block_on(keys.get("maknae-kv", "llm-providers/openai", "api-key"));
        let e = out.expect_err("a dead Vault address must produce an error");
        assert!(!e.is_empty(), "the error must say something");
    }

    /// A `vaultrs` client aimed at a closed loopback port.
    fn vaultrs_settings() -> Option<vaultrs::client::VaultClient> {
        let settings = vaultrs::client::VaultClientSettingsBuilder::default()
            .address("http://127.0.0.1:1")
            .token("not-a-real-token")
            .build()
            .ok()?;
        vaultrs::client::VaultClient::new(settings).ok()
    }
}
