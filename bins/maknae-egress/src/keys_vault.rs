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
