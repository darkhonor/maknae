//! `OperatorClient` — the token-authenticated Vault surface for `maknae enroll`
//! (PR-J1 Task 3, spec §4.1/§4.5). Distinct from `PlaneClient` (`client.rs`): that
//! client logs ITSELF in via AppRole (a standing raw SecretID). `OperatorClient`
//! instead wraps an ALREADY-AUTHENTICATED operator token — the operator authenticates
//! out-of-band (their own `vault login`) and hands the resulting token to `new()` —
//! and exposes exactly the four operations `enroll` needs against it: read a role's
//! RoleID (non-secret), mint a new SecretID (capturing its accessor so a failed
//! enrollment can be rolled back), destroy a SecretID by accessor, and fetch the
//! maknae PKI intermediate's CA chain (for pinning on the new deployment).
//!
//! Pure I/O adapter (T3, `coverage-tiers.toml`): every op below is a thin
//! pass-through to a verified `vaultrs` 0.7.4 call, EXCEPT `fetch_ca_chain`, which
//! hand-rolls a `rustify::Endpoint` — `vaultrs` 0.7.4 has no `issuer/default/json`
//! operation (verified against the vendored source: no such op in `src/pki.rs`, and
//! no `pub use rustify` in its `lib.rs`, so `rustify`/`rustify_derive` are added here
//! as direct deps — both already transitive via `vaultrs`, so `cargo deny` stays
//! green). The hand-rolled endpoint mirrors the pattern in vaultrs' own
//! `src/api/pki/requests.rs` (`#[derive(Endpoint)]` + `#[endpoint(path = ..., ...)]`).
use crate::VaultError;
use serde::Deserialize;
use vaultrs::client::{VaultClient, VaultClientSettingsBuilder};
use zeroize::Zeroizing;

/// A token-authenticated Vault client for the operator-driven `enroll` flow.
///
/// Deliberately does NOT `#[derive(Debug)]`: the wrapped `VaultClient` carries the
/// operator's live token in its settings/middleware, and an auto-derived `Debug`
/// impl would print it verbatim in any `{:?}` log line (`VaultClient` itself has no
/// `Debug` impl upstream either — this just keeps it that way rather than adding
/// one).
pub struct OperatorClient {
    inner: VaultClient,
}

impl OperatorClient {
    /// Build a token-authed client against `addr`, trusting `ca_path` as the Vault
    /// server's TLS CA. Mirrors `PlaneClient::from_document_with_secret`'s builder
    /// use (`client.rs`'s `VaultClientSettingsBuilder` block) minus the AppRole
    /// login step — the caller already holds a valid token (e.g. from their own
    /// `vault login`) and hands it straight in.
    pub fn new(
        addr: &str,
        ca_path: &std::path::Path,
        token: Zeroizing<String>,
    ) -> Result<Self, VaultError> {
        let settings = VaultClientSettingsBuilder::default()
            .address(addr)
            .ca_certs(vec![ca_path.to_string_lossy().to_string()])
            .token(token.as_str())
            .build()
            .map_err(|e| VaultError::Operator(format!("vault client settings: {e}")))?;
        let inner = VaultClient::new(settings)
            .map_err(|e| VaultError::Operator(format!("vault client: {e}")))?;
        Ok(Self { inner })
    }

    /// Read an AppRole's RoleID — a non-secret identifier, safe to write into the
    /// new deployment's config.
    pub async fn read_role_id(&self, mount: &str, role: &str) -> Result<String, VaultError> {
        let resp = vaultrs::auth::approle::role::read_id(&self.inner, mount, role)
            .await
            .map_err(|e| VaultError::Operator(e.to_string()))?;
        Ok(resp.role_id)
    }

    /// Mint a new SecretID for `role`, returning `(secret, accessor)`. The secret is
    /// held in `Zeroizing` and MUST NOT be cloned into a bare `String` or logged; the
    /// accessor is non-secret and is what `destroy_accessor` needs to roll the
    /// SecretID back if the rest of enrollment fails.
    pub async fn mint_secret_id(
        &self,
        mount: &str,
        role: &str,
    ) -> Result<(Zeroizing<String>, String), VaultError> {
        let resp = vaultrs::auth::approle::role::secret::generate(&self.inner, mount, role, None)
            .await
            .map_err(|e| VaultError::Operator(e.to_string()))?;
        Ok((Zeroizing::new(resp.secret_id), resp.secret_id_accessor))
    }

    /// Destroy a previously-minted SecretID by its accessor (rotate/failure
    /// rollback) — never needs the raw secret itself.
    pub async fn destroy_accessor(
        &self,
        mount: &str,
        role: &str,
        accessor: &str,
    ) -> Result<(), VaultError> {
        vaultrs::auth::approle::role::secret::delete_accessor(&self.inner, mount, role, accessor)
            .await
            .map_err(|e| VaultError::Operator(e.to_string()))?;
        Ok(())
    }

    /// Fetch the maknae PKI intermediate's default issuer CA chain (PEM), for
    /// pinning on the newly enrolled deployment. `vaultrs` has no op for this
    /// endpoint, so it is executed via the hand-rolled `ReadDefaultIssuerJsonRequest`
    /// below, through the same `vaultrs::api::exec_with_result` driver every
    /// built-in vaultrs call uses.
    pub async fn fetch_ca_chain(&self, pki_int_mount: &str) -> Result<String, VaultError> {
        let endpoint = ReadDefaultIssuerJsonRequest {
            mount: pki_int_mount.to_string(),
        };
        let resp = vaultrs::api::exec_with_result(&self.inner, endpoint)
            .await
            .map_err(|e| VaultError::Operator(e.to_string()))?;
        join_ca_chain(resp.ca_chain)
    }
}

/// `GET {mount}/issuer/default/json` — absent from `vaultrs` 0.7.4 (verified against
/// the vendored source). Modeled on vaultrs' own PKI endpoints
/// (`src/api/pki/requests.rs`'s `ReadCertificateRequest`): a GET with the mount
/// templated into the path and no body (the only field is `#[endpoint(skip)]`).
#[derive(rustify_derive::Endpoint, Debug)]
#[endpoint(
    path = "{self.mount}/issuer/default/json",
    response = "IssuerJsonResponse"
)]
struct ReadDefaultIssuerJsonRequest {
    #[endpoint(skip)]
    mount: String,
}

/// The fields of Vault's `issuer/default/json` response this crate needs. Extra
/// upstream fields (`issuer_id`, `issuer_name`, `key_id`, `revocation_time`, ...) are
/// ignored by default (no `deny_unknown_fields`).
#[derive(Deserialize, Debug)]
struct IssuerJsonResponse {
    ca_chain: Vec<String>,
}

/// Join Vault's `ca_chain` (one PEM cert per array element) into a single PEM
/// document, newline-separated. Fails closed on an empty chain — Vault should
/// always return at least the issuer's own certificate, so an empty response means
/// something is wrong upstream (e.g. wrong mount) rather than a legitimately empty
/// chain.
fn join_ca_chain(chain: Vec<String>) -> Result<String, VaultError> {
    if chain.is_empty() {
        return Err(VaultError::Operator(
            "issuer/default/json returned an empty ca_chain".to_string(),
        ));
    }
    Ok(chain
        .iter()
        .map(|pem| pem.trim())
        .collect::<Vec<_>>()
        .join("\n"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn join_ca_chain_rejects_empty() {
        assert!(matches!(
            join_ca_chain(vec![]),
            Err(VaultError::Operator(_))
        ));
    }

    #[test]
    fn join_ca_chain_joins_and_trims() {
        let chain = vec![
            "-----BEGIN CERTIFICATE-----\nAAA\n-----END CERTIFICATE-----\n".to_string(),
            "  -----BEGIN CERTIFICATE-----\nBBB\n-----END CERTIFICATE-----  ".to_string(),
        ];
        let joined = join_ca_chain(chain).unwrap();
        assert_eq!(
            joined,
            "-----BEGIN CERTIFICATE-----\nAAA\n-----END CERTIFICATE-----\n\
             -----BEGIN CERTIFICATE-----\nBBB\n-----END CERTIFICATE-----"
        );
    }

    #[test]
    fn join_ca_chain_single_cert() {
        let chain = vec!["-----BEGIN CERTIFICATE-----\nAAA\n-----END CERTIFICATE-----".to_string()];
        assert_eq!(
            join_ca_chain(chain).unwrap(),
            "-----BEGIN CERTIFICATE-----\nAAA\n-----END CERTIFICATE-----"
        );
    }
}
