//! The Vault-backed [`KeySource`](crate::keys::KeySource) — the I/O half.
//!
//! Split from `keys.rs` for the reason this tree splits `kv_io`/`kv` and
//! `secret_io`/`secret_source`: the CACHE is a decision worth mutation-testing
//! and this is a network read no unit test should stand in for. This project
//! has no Vault stub and deliberately uses none.

use crate::keys::KeySource;
use zeroize::Zeroizing;

/// Reads through `maknae-vault`, which owns every Vault interaction.
pub struct VaultKeys<C> {
    pub client: C,
    pub field: String,
    pub runtime: tokio::runtime::Handle,
}

impl<C: maknae_vault::VaultClientTrait> KeySource for VaultKeys<C> {
    fn read(&self, key_vault_path: &str) -> Result<Zeroizing<String>, String> {
        self.runtime
            .block_on(maknae_vault::read_kv_field(
                &self.client,
                key_vault_path,
                &self.field,
            ))
            .map_err(|e| e.to_string())
    }
}
