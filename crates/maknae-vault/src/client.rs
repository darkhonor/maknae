//! `PlaneClient` — the Stage-1 orchestrator: config → AppRole auth (response-wrapped
//! SecretID) → P-384 CSR → `pki/sign` → memory-only leaf. The identity is Arc-backed
//! (cheap snapshot; key wiped on drop). Renewal runs on a shared handle so serving and
//! renewal can proceed concurrently.
use crate::auth::AppRoleAuth;
use crate::{
    assert_fips_provider, generate_plane_csr, load_ca_pin, load_vault_config,
    verify::verify_plane_uri_san, Plane, VaultError,
};
use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, RwLock};
use tokio::sync::Mutex;
use vaultrs::client::{Client, VaultClient, VaultClientSettingsBuilder};
use zeroize::Zeroizing;

// Stage-1 mount defaults (match the merged Terraform defaults; overridable later).
const APPROLE_MOUNT: &str = "maknae-approle";
const INT_PKI_MOUNT: &str = "maknae-pki-int";

struct IdentityInner {
    leaf_pem: String,
    #[allow(dead_code)] // consumed by the Stage-2 rustls config builder
    key_der: Zeroizing<Vec<u8>>,
    chain_pem: Vec<String>,
}

/// A minted plane identity — cheaply cloneable (Arc), private key wiped on drop.
#[derive(Clone)]
pub struct PlaneIdentity(Arc<IdentityInner>);

impl PlaneIdentity {
    /// The signed leaf certificate (PEM).
    pub fn leaf_pem(&self) -> &str {
        &self.0.leaf_pem
    }
    /// The issuing CA chain (PEM), as returned by `pki/sign`.
    pub fn chain_pem(&self) -> &[String] {
        &self.0.chain_pem
    }
}

/// The Stage-1 plane-cert client.
pub struct PlaneClient {
    plane: Plane,
    deployment_id: String,
    auth: AppRoleAuth,
    client: Arc<Mutex<VaultClient>>,
    identity: Arc<RwLock<Option<PlaneIdentity>>>,
    /// The last mint's token lease (seconds); drives the renewal interval so it tracks
    /// the actual token TTL rather than a hardcoded assumption. 0 until first mint.
    lease_secs: Arc<AtomicU64>,
}

fn read_trimmed(path: &Path) -> Result<String, VaultError> {
    std::fs::read_to_string(path)
        .map(|s| s.trim().to_string())
        .map_err(|source| VaultError::Io {
            path: path.to_path_buf(),
            source,
        })
}

/// Read a SENSITIVE credential file (the wrapped SecretID). Refuse a symlink or any
/// group/other access BEFORE reading — the wrapping token must never be world-readable
/// (maknae-config gates `maknae.yaml` + the dir, but not files we read directly).
fn read_secret_credential(path: &Path) -> Result<String, VaultError> {
    use std::os::unix::fs::PermissionsExt;
    let meta = std::fs::symlink_metadata(path).map_err(|source| VaultError::Io {
        path: path.to_path_buf(),
        source,
    })?;
    if meta.file_type().is_symlink() {
        return Err(VaultError::InsecureCredential {
            path: path.to_path_buf(),
            detail: "is a symlink".to_string(),
        });
    }
    let mode = meta.permissions().mode() & 0o777;
    if mode & 0o077 != 0 {
        return Err(VaultError::InsecureCredential {
            path: path.to_path_buf(),
            detail: format!("mode {mode:o} allows group/other access (require 0600 or stricter)"),
        });
    }
    std::fs::read_to_string(path)
        .map(|s| s.trim().to_string())
        .map_err(|source| VaultError::Io {
            path: path.to_path_buf(),
            source,
        })
}

/// Parse the first PEM cert block to DER (for the returned-leaf SAN self-check).
fn pem_to_der(pem: &str) -> Result<Vec<u8>, VaultError> {
    let (_, parsed) = x509_parser::pem::parse_x509_pem(pem.as_bytes())
        .map_err(|_| VaultError::Pem("signed leaf: malformed PEM"))?;
    if parsed.label != "CERTIFICATE" {
        return Err(VaultError::Pem("signed leaf: not a CERTIFICATE PEM"));
    }
    Ok(parsed.contents)
}

impl PlaneClient {
    /// Build from a config dir. **LOAD-BEARING ordering:** `assert_fips_provider()`
    /// runs first — before the Vault client is built — so reqwest reads the FIPS
    /// default (§6.1), never falling back to ring. Fail-closed throughout.
    pub fn from_config_dir(dir: &Path, plane: Plane) -> Result<Self, VaultError> {
        assert_fips_provider()?;
        let cfg = load_vault_config(dir)?;
        // Loading the CA-pin validates it now (Stage 2 consumes the bundle).
        let _ca = load_ca_pin(dir)?;
        let prefix = plane.config_prefix();
        // RoleID is non-secret (an identifier); the wrapped SecretID is sensitive and
        // must be owner-only (perm-checked, no symlink).
        let role_id = read_trimmed(&dir.join(format!("{prefix}-approle-id")))?;
        let wrapped_secret_id = read_secret_credential(&dir.join(format!("{prefix}-secret-id")))?;
        let vault_ca = dir.join("tls").join("vault-ca.crt");
        let settings = VaultClientSettingsBuilder::default()
            .address(cfg.addr)
            .ca_certs(vec![vault_ca.to_string_lossy().to_string()])
            .build()
            .map_err(|e| VaultError::Auth(format!("vault client settings: {e}")))?;
        let client = VaultClient::new(settings)
            .map_err(|e| VaultError::Auth(format!("vault client: {e}")))?;
        Ok(Self {
            plane,
            deployment_id: cfg.deployment_id,
            auth: AppRoleAuth {
                role_id,
                wrapped_secret_id,
                approle_mount: APPROLE_MOUNT.to_string(),
            },
            client: Arc::new(Mutex::new(client)),
            identity: Arc::new(RwLock::new(None)),
            lease_secs: Arc::new(AtomicU64::new(0)),
        })
    }

    /// The live mint: authenticate → CSR → `pki/sign` → hold memory-only. Stores a
    /// snapshot and returns a clone.
    pub async fn mint(&self) -> Result<PlaneIdentity, VaultError> {
        let mut client = self.client.lock().await;
        let token = self.auth.authenticate(&client).await?;
        client.set_token(&token.client_token);
        // Record the actual lease so spawn_renewal renews on the real TTL; surface a
        // non-renewable token (a role misconfig) rather than silently failing later.
        self.lease_secs
            .store(token.lease_duration, Ordering::Relaxed);
        if !token.renewable {
            eprintln!(
                "maknae-vault: WARNING — minted token is not renewable; background \
                 renewal will fail closed at its TTL (check the AppRole role config)"
            );
        }

        // Any failure AFTER the token is installed must revoke the just-issued token —
        // otherwise `client.mint().await?` drops the client (shutdown() never runs) and
        // leaks a usable privileged token until its TTL.
        let (key_der, leaf_pem, chain_pem) = match self.sign_leaf(&client).await {
            Ok(v) => v,
            Err(e) => {
                let _ = vaultrs::token::revoke_self(&*client).await; // best-effort
                return Err(e);
            }
        };

        let id = PlaneIdentity(Arc::new(IdentityInner {
            leaf_pem,
            key_der,
            chain_pem,
        }));
        *self.identity.write().expect("identity lock poisoned") = Some(id.clone());
        Ok(id)
    }

    /// CSR → `pki/sign` → returned-leaf SAN self-check. Split out so `mint` has a single
    /// post-auth cleanup point (revoke-on-failure).
    async fn sign_leaf(
        &self,
        client: &VaultClient,
    ) -> Result<(Zeroizing<Vec<u8>>, String, Vec<String>), VaultError> {
        let (key_der, csr_pem) = generate_plane_csr(self.plane, &self.deployment_id)?;
        let resp = vaultrs::pki::cert::ca::sign(
            client,
            INT_PKI_MOUNT,
            self.plane.pki_sign_role(),
            &csr_pem,
            "", // empty CN — the role sets require_cn=false / use_csr_common_name=false
            None,
        )
        .await
        .map_err(|e| VaultError::Sign(e.to_string()))?;
        // Defense-in-depth: the leaf Vault returned must carry exactly our plane SAN.
        let leaf_der = pem_to_der(&resp.certificate)?;
        verify_plane_uri_san(&leaf_der, self.plane, &self.deployment_id)
            .map_err(|e| VaultError::Sign(format!("returned leaf failed SAN self-check: {e:?}")))?;
        Ok((key_der, resp.certificate, resp.ca_chain.unwrap_or_default()))
    }

    /// Non-blocking snapshot of the current identity (for the Stage-2 transport).
    pub fn current_identity(&self) -> Option<PlaneIdentity> {
        self.identity
            .read()
            .expect("identity lock poisoned")
            .clone()
    }

    /// Spawn the background token-renewal loop on a SHARED handle (not `&mut self`, so
    /// serving and renewal proceed concurrently). **MUST be called after a successful
    /// `mint()`** — there is no token to renew before minting. If called before (lease
    /// still 0), the task fails closed immediately (`RenewalExpired`) rather than
    /// guessing an interval. The handle resolves to `RenewalExpired` when the token can
    /// no longer be renewed (token_max_ttl reached / revoked); at that point the shared
    /// identity is CLEARED so `current_identity()` returns `None` (fail closed) whether or
    /// not the caller observes the handle — re-authenticate to mint a fresh leaf.
    pub fn spawn_renewal(&self) -> tokio::task::JoinHandle<VaultError> {
        let client = Arc::clone(&self.client);
        let lease_secs = Arc::clone(&self.lease_secs);
        let identity = Arc::clone(&self.identity);
        // Once renewal can no longer continue, the leaf's usefulness is bounded by the
        // token's remaining TTL — so INVALIDATE the identity here rather than trusting the
        // caller to observe the join handle. current_identity() then returns None (fail
        // closed) even if nobody is watching the handle.
        let expire = move || {
            *identity.write().expect("identity lock poisoned") = None;
            VaultError::RenewalExpired
        };
        tokio::spawn(async move {
            loop {
                // Fail closed if spawned before mint() — no token to renew, and we must
                // never guess an interval that could outlast a short lease.
                let lease = lease_secs.load(Ordering::Relaxed);
                if lease == 0 {
                    return expire();
                }
                // Renew at ~2/3 of the token's ACTUAL lease — always STRICTLY below the
                // lease so even a sub-60s TTL renews before it expires.
                let wait = (lease * 2 / 3).max(1);
                tokio::time::sleep(std::time::Duration::from_secs(wait)).await;
                let c = client.lock().await;
                // Update the lease from THIS renewal's response — near token_max_ttl Vault
                // shortens the lease, so the next delay must track the current one.
                match vaultrs::token::renew_self(&*c, None).await {
                    Ok(auth) => lease_secs.store(auth.lease_duration, Ordering::Relaxed),
                    Err(_) => return expire(),
                }
            }
        })
    }

    /// Best-effort revoke on shutdown; failure is logged, never blocks exit.
    pub async fn shutdown(self) {
        let client = self.client.lock().await;
        if let Err(e) = vaultrs::token::revoke_self(&*client).await {
            eprintln!("maknae-vault: token revoke-self on shutdown failed (ignored): {e}");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    fn tmpfile(name: &str, mode: u32) -> std::path::PathBuf {
        let p = std::env::temp_dir().join(format!("mv-cred-{}-{}", std::process::id(), name));
        std::fs::write(&p, "wrapped-token-xyz").unwrap();
        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(mode)).unwrap();
        p
    }

    #[test]
    fn secret_credential_rejects_group_other_access() {
        let p = tmpfile("open", 0o644);
        assert!(matches!(
            read_secret_credential(&p),
            Err(VaultError::InsecureCredential { .. })
        ));
        let _ = std::fs::remove_file(&p);
    }

    #[test]
    fn secret_credential_accepts_owner_only() {
        let p = tmpfile("secure", 0o600);
        assert_eq!(read_secret_credential(&p).unwrap(), "wrapped-token-xyz");
        let _ = std::fs::remove_file(&p);
    }
}
