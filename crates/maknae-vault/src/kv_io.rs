//! The KV v2 network read (#240a) — the I/O half of `kv`.
//!
//! Separated from `kv.rs` for the reason the crate separates `secret_io` from
//! `secret_source`: the PARSE is a decision worth mutation-testing, and this
//! is a network call that no unit test should stand in for. This project has
//! no Vault stub and deliberately uses none — the network is exercised by
//! `#[ignore]`d live tests against a real Vault, and its ABSENCE is tested
//! fail-closed at boot.

use crate::{split_kv_path, VaultError};
use zeroize::Zeroizing;

/// Read one field of a KV v2 secret, as a zeroizing string.
///
/// The value is a provider API key: it is `Zeroizing` from the moment it
/// exists here, never logged, and never rendered by `Debug`. I/O — the pure
/// decision above is what carries the tests.
pub async fn read_kv_field(
    client: &impl vaultrs::client::Client,
    key_vault_path: &str,
    field: &str,
) -> Result<Zeroizing<String>, VaultError> {
    let (mount, path) = split_kv_path(key_vault_path)?;
    let data: std::collections::BTreeMap<String, String> = vaultrs::kv2::read(client, mount, path)
        .await
        .map_err(|e| VaultError::Auth(e.to_string()))?;
    data.get(field)
        .map(|v| Zeroizing::new(v.clone()))
        .ok_or_else(|| {
            // The field name is safe to name; the secret's contents never are.
            VaultError::MissingKvField {
                path: key_vault_path.to_string(),
                field: field.to_string(),
            }
        })
}
