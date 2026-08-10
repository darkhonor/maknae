//! The `Authenticator` abstraction. Stage 1 impl: `AppRoleAuth` — reads the
//! response-wrapped SecretID (a single-use wrapping token), **unwraps once** via
//! `sys/wrapping/unwrap` (fail-closed if already-used/expired — the interception-
//! detection control), then `auth/<mount>/login`. No plaintext SecretID touches disk.
//! A future `KubernetesAuth` slots in behind this trait without touching the mint core.
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

/// AppRole auth over a response-wrapped SecretID.
pub struct AppRoleAuth {
    pub role_id: String,
    /// The on-disk artifact: a single-use *wrapping token* (NOT a plaintext SecretID).
    pub wrapped_secret_id: String,
    pub approle_mount: String,
}

/// Shape of the unwrapped SecretID payload.
#[derive(serde::Deserialize)]
struct UnwrappedSecretId {
    secret_id: String,
}

impl AppRoleAuth {
    pub fn method(&self) -> AuthMethod {
        AuthMethod::AppRole
    }

    /// Unwrap the wrapping token once (fail-closed) → SecretID, then AppRole login.
    pub async fn authenticate(&self, client: &VaultClient) -> Result<VaultToken, VaultError> {
        let unwrapped: UnwrappedSecretId =
            vaultrs::sys::wrapping::unwrap(client, Some(&self.wrapped_secret_id))
                .await
                .map_err(|e| VaultError::WrapUnwrap(e.to_string()))?;
        let secret_id = Zeroizing::new(unwrapped.secret_id);
        let auth = vaultrs::auth::approle::login(
            client,
            &self.approle_mount,
            &self.role_id,
            secret_id.as_str(),
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
