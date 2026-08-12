//! The `Authenticator` abstraction. Stage 1 impl: `AppRoleAuth` — logs in directly with
//! a **standing raw SecretID** (ADR-0018: the RoleID + SecretID pair is a local,
//! `_maknae`-/operator-owned bootstrap credential, not a delivery across an untrusted
//! channel, so the old single-use response-wrapping step adds nothing here and is
//! retired — spec §4.4). `auth/<mount>/login` is called directly against `role_id` +
//! `secret_id`. A future `KubernetesAuth` slots in behind this trait without touching
//! the mint core.
use crate::VaultError;
use vaultrs::client::VaultClient;
use zeroize::Zeroizing;

/// Which auth method a client uses (forward-looking; Stage 1 is `AppRole`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthMethod {
    AppRole,
}

/// A renewable Vault token from a successful authentication.
pub struct VaultToken {
    pub client_token: String,
    pub renewable: bool,
    pub lease_duration: u64,
}

/// AppRole auth over a standing raw SecretID (ADR-0018).
pub struct AppRoleAuth {
    pub role_id: String,
    /// The on-disk artifact: a standing, plaintext SecretID (owner-only file
    /// permissions enforced by the reader — see `client::read_secret_credential`).
    pub secret_id: Zeroizing<String>,
    pub approle_mount: String,
}

impl AppRoleAuth {
    pub fn method(&self) -> AuthMethod {
        AuthMethod::AppRole
    }

    /// Direct AppRole login with the standing SecretID — no unwrap step.
    pub async fn authenticate(&self, client: &VaultClient) -> Result<VaultToken, VaultError> {
        let auth = vaultrs::auth::approle::login(
            client,
            &self.approle_mount,
            &self.role_id,
            self.secret_id.as_str(),
        )
        .await
        .map_err(|e| VaultError::Auth(e.to_string()))?;
        Ok(VaultToken {
            client_token: auth.client_token,
            renewable: auth.renewable,
            lease_duration: auth.lease_duration,
        })
    }
}
