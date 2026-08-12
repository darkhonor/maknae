//! Gated live-smoke for `OperatorClient` (Task 3, spec §4.1/§4.5) — the `maknae
//! enroll` Vault surface. Needs a REAL Vault reachable with an operator's OWN
//! (already-authenticated) token, so this is `#[ignore]` and NEVER runs in CI. Run it
//! manually WITH the operator present (they supply their own live Vault token — this
//! does NOT do the AppRole login `PlaneClient`/`live_smoke.rs` do):
//!
//!   MAKNAE_VAULT_ADDR=https://vault.example:8200 \
//!   MAKNAE_VAULT_CA=~/.maknae/tls/vault-ca.crt \
//!   MAKNAE_VAULT_TOKEN=$(vault print token) \
//!   MAKNAE_APPROLE_MOUNT=maknae-approle \
//!   MAKNAE_APPROLE_ROLE=maknae-kernel \
//!   MAKNAE_PKI_INT_MOUNT=maknae-pki-int \
//!     cargo test -p maknae-vault --test live_operator -- --ignored --nocapture
//!
//! `MAKNAE_APPROLE_MOUNT`/`MAKNAE_APPROLE_ROLE`/`MAKNAE_PKI_INT_MOUNT` default to the
//! Terraform module's own defaults (`maknae-approle` / `maknae-kernel` /
//! `maknae-pki-int`) if unset.
#![cfg(unix)]

use std::path::Path;
use zeroize::Zeroizing;

fn env_or(key: &str, default: &str) -> String {
    std::env::var(key).unwrap_or_else(|_| default.to_string())
}

/// Exercises the full `OperatorClient` surface `enroll` needs, in the order enroll
/// would use it: read the role's RoleID, mint a SecretID (capturing its accessor),
/// fetch the PKI CA chain, then destroy the just-minted SecretID by accessor (the
/// same rollback path enroll takes on a mid-flow failure) — leaving no live SecretID
/// behind.
#[tokio::test]
#[ignore = "needs live Vault + an operator's own token (operator-gated)"]
async fn operator_client_role_id_secret_id_ca_chain_roundtrip() {
    rustls::crypto::aws_lc_rs::default_provider()
        .install_default()
        .ok();

    let addr = std::env::var("MAKNAE_VAULT_ADDR")
        .expect("set MAKNAE_VAULT_ADDR (e.g. https://vault.example:8200)");
    let ca_path =
        std::env::var("MAKNAE_VAULT_CA").expect("set MAKNAE_VAULT_CA to the Vault TLS CA path");
    let token = Zeroizing::new(
        std::env::var("MAKNAE_VAULT_TOKEN")
            .expect("set MAKNAE_VAULT_TOKEN to your own live Vault token"),
    );
    let approle_mount = env_or("MAKNAE_APPROLE_MOUNT", "maknae-approle");
    let approle_role = env_or("MAKNAE_APPROLE_ROLE", "maknae-kernel");
    let pki_int_mount = env_or("MAKNAE_PKI_INT_MOUNT", "maknae-pki-int");

    let client = maknae_vault::OperatorClient::new(&addr, Path::new(&ca_path), token)
        .expect("build OperatorClient from the operator's own token");

    let role_id = client
        .read_role_id(&approle_mount, &approle_role)
        .await
        .expect("read the role's RoleID");
    assert!(!role_id.is_empty(), "RoleID is non-empty");

    let (secret_id, accessor) = client
        .mint_secret_id(&approle_mount, &approle_role)
        .await
        .expect("mint a new SecretID");
    assert!(!secret_id.is_empty(), "SecretID is non-empty");
    assert!(!accessor.is_empty(), "accessor is non-empty");

    let ca_chain = client
        .fetch_ca_chain(&pki_int_mount)
        .await
        .expect("fetch the PKI intermediate's CA chain");
    assert!(
        ca_chain.contains("BEGIN CERTIFICATE"),
        "CA chain is PEM-formatted"
    );

    client
        .destroy_accessor(&approle_mount, &approle_role, &accessor)
        .await
        .expect("destroy the just-minted SecretID by accessor (rollback path)");

    println!(
        "LIVE SMOKE OK: OperatorClient read RoleID, minted+destroyed a SecretID by \
         accessor, and fetched the PKI CA chain"
    );
}
