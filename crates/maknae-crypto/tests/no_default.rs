//! With no process default installed, the start-up check refuses (#589).
use maknae_crypto::{assert_fips_provider, CryptoError};

#[test]
fn no_installed_default_is_drift() {
    assert_eq!(assert_fips_provider(), Err(CryptoError::PolicyDrift));
}
