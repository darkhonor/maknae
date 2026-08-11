//! Provider-fetch glue for the FIPS gate. Fail-closed: the binary `main` installs
//! the process-default `CryptoProvider` once (aws-lc-rs FIPS); this reads it —
//! detecting a pre-installed NON-FIPS default, or none at all — and delegates the
//! decision to `fips::fips_result`.
//!
//! **Load-bearing ordering:** callers MUST run `assert_fips_provider()` before
//! constructing any Vault client, because `vaultrs`'s reqwest reads the same
//! process-default provider and would otherwise fall back to `ring` (non-FIPS).
//!
//! T3 (a process-global default is not deterministically coverable) + mutation-
//! excluded (`mutants.toml`). The pure `fips::fips_result` carries the T1 logic.
use crate::{fips::fips_result, VaultError};

/// Install the aws-lc-rs FIPS provider as the process-default `CryptoProvider`, once.
/// Idempotent: a pre-existing default (or a second call) is a no-op. The daemon `main`
/// (via `maknae_kernel::run`) MUST call this before [`assert_fips_provider`] and before
/// constructing any Vault client, so `vaultrs`'s reqwest + rustls read the FIPS default
/// rather than falling back to `ring` (spec §6.1). The subsequent `assert_fips_provider`
/// remains the authoritative gate: this installer only makes a FIPS build's default
/// available; it never masks a non-FIPS build (whose `.fips()` is false → refuse).
pub fn install_default_crypto_provider() {
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
}

/// Assert the process is running the aws-lc-rs FIPS provider. Fail-closed:
/// no installed default (the binary `main` forgot to install one) → refuse.
pub fn assert_fips_provider() -> Result<(), VaultError> {
    let provider =
        rustls::crypto::CryptoProvider::get_default().ok_or(VaultError::FipsUnavailable)?;
    fips_result(provider.fips())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn asserts_fips_true_on_this_build() {
        // With rustls[fips] + aws-lc-rs[fips], installing the default is FIPS.
        rustls::crypto::aws_lc_rs::default_provider()
            .install_default()
            .ok();
        assert!(assert_fips_provider().is_ok());
    }
}
