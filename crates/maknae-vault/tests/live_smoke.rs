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
    println!(
        "LIVE SMOKE OK: minted maknae://<deployment_id>/plane/kernel (P-384), revoked on shutdown"
    );
}

/// Gated live-smoke for `rotate_leaf` (ADR-0018 Decision 3's rotation mutator).
/// Needs the SAME live Vault + seeded credentials as `mint_kernel_leaf_against_live_vault`
/// above; for a meaningful check within a short test run, point `MAKNAE_CONFIG_DIR` at a
/// config dir whose `maknae-kernel` PKI role was applied with a SHORT
/// `leaf_ttl_seconds` (e.g. `terraform apply -var leaf_ttl_seconds=120` against
/// `deploy/vault-pki`, on a disposable dev mount — see docs/runbook.md) so the leaf's
/// actual TTL is short enough to eyeball in the printed output. `rotate_leaf` itself
/// does not depend on the TTL value; a 72h-TTL config dir also exercises the call path,
/// it just won't demonstrate near-term re-rotation.
#[tokio::test]
#[ignore = "needs live Vault + a just-seeded response-wrapped SecretID (operator-gated); \
            use a short leaf_ttl_seconds PKI role to observe near-term rotation"]
async fn rotate_leaf_against_live_vault() {
    let dir = std::env::var("MAKNAE_CONFIG_DIR")
        .expect("set MAKNAE_CONFIG_DIR to the config dir (e.g. ~/.maknae)");
    rustls::crypto::aws_lc_rs::default_provider()
        .install_default()
        .ok();

    let client = maknae_vault::PlaneClient::from_config_dir(
        std::path::Path::new(&dir),
        maknae_vault::Plane::Kernel,
    )
    .expect("build PlaneClient from config dir");

    let first = client.mint().await.expect("mint the initial plane leaf");

    client
        .rotate_leaf()
        .await
        .expect("rotate_leaf re-signs on the CURRENT token (no re-auth)");

    let second = client
        .current_identity()
        .expect("identity still present after rotation");

    assert_ne!(
        first.leaf_pem(),
        second.leaf_pem(),
        "rotate_leaf must install a NEW leaf, not repeat the old one"
    );
    assert!(
        second.leaf_pem().contains("BEGIN CERTIFICATE"),
        "the rotated leaf is a PEM certificate"
    );

    client.shutdown().await;
    println!("LIVE SMOKE OK: rotate_leaf installed a fresh maknae-kernel leaf on the live token");
}
