//! Gated live-smoke — runbook ch.1. Needs a REAL Vault + a just-seeded response-
//! wrapped SecretID, so it is `#[ignore]` and NEVER runs in CI. Run it manually WITH
//! the operator present (they seed the wrapped SecretID with their root cred):
//!
//!   MAKNAE_CONFIG_DIR=~/.maknae \
//!     cargo test -p maknae-vault --test live_smoke -- --ignored --nocapture
//!
//! Expected config-dir layout (see docs/runbook.md):
//!   <dir>/maknae.yaml            (0o600)  -> vault.addr + core.deployment_id
//!   <dir>/tls/vault-ca.crt                -> the Vault server's TLS CA
//!   <dir>/tls/maknae-root-ca.crt          -> Maknae plane root (pinned)
//!   <dir>/tls/maknae-int-ca.crt           -> Maknae plane intermediate
//!   <dir>/maknaed-approle-id              -> the trust-plane RoleID
//!   <dir>/maknaed-secret-id      (0o400)  -> the response-wrapped SecretID (wrapping token)
#![cfg(unix)]

#[tokio::test]
#[ignore = "needs live Vault + a just-seeded response-wrapped SecretID (operator-gated)"]
async fn mint_kernel_leaf_against_live_vault() {
    let dir = std::env::var("MAKNAE_CONFIG_DIR")
        .expect("set MAKNAE_CONFIG_DIR to the config dir (e.g. ~/.maknae)");
    // The daemon's `main` installs the FIPS provider; the smoke installs it too.
    rustls::crypto::aws_lc_rs::default_provider()
        .install_default()
        .ok();

    let client = maknae_vault::PlaneClient::from_config_dir(
        std::path::Path::new(&dir),
        maknae_vault::Plane::Kernel,
    )
    .expect("build PlaneClient from config dir");

    let id = client
        .mint()
        .await
        .expect("mint a plane leaf against live Vault");

    // mint() already self-checks the returned leaf's URI-SAN internally; assert the
    // externally-visible shape here too.
    assert!(
        id.leaf_pem().contains("BEGIN CERTIFICATE"),
        "minted a PEM leaf"
    );
    assert!(!id.chain_pem().is_empty(), "issuing chain returned");
    assert!(
        client.current_identity().is_some(),
        "identity stored as a snapshot"
    );

    client.shutdown().await;
    println!("LIVE SMOKE OK: minted maknae://<deployment_id>/plane/kernel (P-384), revoked on shutdown");
}
