//! Reads the process-default `CryptoProvider` and the FIPS module state, and
//! delegates each decision to `provider` and `fips`. T3: a process-global
//! default is not deterministically coverable.
use crate::provider::{crypto_provider, fips_result, kx_groups_result};
use crate::CryptoError;

/// Installs [`crate::crypto_provider`] as the process default; a no-op if one
/// is already installed. Call it before constructing any TLS client, then
/// [`assert_fips_provider`], which refuses a non-FIPS default.
pub fn install_default_crypto_provider() {
    let _ = crypto_provider().install_default();
}

/// Asserts the aws-lc FIPS module is active, independent of any TLS provider.
pub fn assert_fips_module() -> Result<(), CryptoError> {
    crate::fips::fips_result(aws_lc_rs::try_fips_mode().is_ok())
}

/// Asserts the process default is the aws-lc-rs FIPS provider carrying
/// [`crate::KX_GROUPS`]. Refuses when no default is installed.
pub fn assert_fips_provider() -> Result<(), CryptoError> {
    let provider =
        rustls::crypto::CryptoProvider::get_default().ok_or(CryptoError::FipsUnavailable)?;
    fips_result(provider.fips())?;
    let names: Vec<_> = provider.kx_groups.iter().map(|g| g.name()).collect();
    kx_groups_result(&names)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn asserts_fips_true_on_this_build() {
        install_default_crypto_provider();
        assert!(assert_fips_provider().is_ok());
    }

    #[test]
    fn the_fips_module_is_active_on_this_build() {
        assert!(assert_fips_module().is_ok());
    }
}
