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
    pub field: String,
}

impl<C: maknae_vault::VaultClientTrait + Sync> KeySource for VaultKeys<C> {
    /// No `block_on` and no runtime handle. An earlier version held a
    /// `runtime::Handle` and blocked on it — which PANICS, because the deputy
    /// already calls `fulfil` inside that runtime and Tokio refuses a nested
    /// block. The credential error this design promises could never have been
    /// produced; the process would have aborted instead (#296).
    async fn read(&self, key_vault_path: &str) -> Result<Zeroizing<String>, String> {
        maknae_vault::read_kv_field(&self.client, key_vault_path, &self.field)
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

        let mut keys = KeyCache::new(VaultKeys {
            client,
            field: "api_key".to_string(),
        });

        // INSIDE the runtime — the exact shape that used to abort.
        let out = rt.block_on(keys.get("secret/data/maknae/providers/openai"));
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
