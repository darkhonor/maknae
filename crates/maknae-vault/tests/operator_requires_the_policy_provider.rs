//! Its own binary, so no process default provider is installed.
use maknae_vault::{OperatorClient, VaultError};
use zeroize::Zeroizing;

#[test]
fn without_the_policy_provider_the_operator_client_is_refused() {
    let r = OperatorClient::new(
        "https://vault.invalid.example:8200",
        std::path::Path::new("/nonexistent/vault-ca.crt"),
        Zeroizing::new("t".into()),
    );
    assert!(matches!(r, Err(VaultError::PolicyDrift)), "{:?}", r.err());
}
