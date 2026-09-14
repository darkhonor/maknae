//! The egress deputy's Vault client (#240b) — the I/O half.
//!
//! The deputy is the third plane: its own AppRole, its own policy (a read on
//! the provider-key prefix and its own token lifecycle, nothing else), no PKI
//! role. It authenticates through the SAME `AppRoleAuth` the two mTLS planes
//! use; what is new here is the token LIFECYCLE and the KV read.
//!
//! **Login per read, revoke after — and revoke is NOT best-effort.** The
//! deputy reads a key once per destination for the life of the process
//! (`keys.rs`'s cache). A token acquired at boot would sit unrenewed past
//! `token_period` and fail the next uncached read with a 403; the daemon's
//! renewal supervisor is disproportionate for a process that makes a handful
//! of reads. So each read is login → read → `revoke-self`, and no token
//! stands between reads. How those three compose — a failed revoke is a
//! failed probe, and a read whose revoke failed withholds its secret — is the
//! DECISION in `egress_session.rs` (T1, over the `EgressOps` seam); this file
//! is the vaultrs implementation of the three operations. The boot probe is
//! login + revoke, so a wrong SecretID refuses START rather than the first
//! live request — the same preference the bounds boot gate records.
//!
//! T3 and mutation-excluded like `client.rs`: this project has no Vault stub
//! and deliberately uses none. The DECISIONS it consumes — which source the
//! SecretID comes from, and how a session's steps compose — are T1 in
//! `secret_source.rs` and `egress_session.rs`.

use crate::auth::AppRoleAuth;
use crate::config::validate_vault_addr;
use crate::egress_session::{probe, read_one, EgressOps};
use crate::secret_source::resolve_egress_secret_source;
use crate::{assert_fips_provider, VaultError};
use std::path::Path;
use vaultrs::client::{Client, VaultClient, VaultClientSettings, VaultClientSettingsBuilder};
use zeroize::Zeroizing;

/// The deputy's AppRole role name — `deploy/vault-pki/main.tf`'s
/// `vault_approle_auth_backend_role.maknae_egress`.
pub const EGRESS_APPROLE_ROLE: &str = "maknae-egress";
/// The RoleID file `maknae enroll` writes into the deputy's credential dir.
pub const EGRESS_ROLE_ID_FILE: &str = "maknae-egress-approle-id";
/// The deputy's own copy of the Vault TLS CA, beside the RoleID. An EXTRA
/// trust anchor beside the system store, not a pin: vaultrs merges `ca_certs`
/// into the platform verifier (`tls_certs_merge`), and pinning the Vault leg
/// to this CA alone is not expressible through it (#318 records the gap).
pub const EGRESS_VAULT_CA_FILE: &str = "vault-ca.crt";
/// The same hard per-request timeout as the two plane clients, for the same
/// reason: vaultrs defaults to an UNBOUNDED reqwest client, and a hung Vault
/// must surface as an error the deputy can name.
const VAULT_HTTP_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);

/// Read the deputy's AppRole halves: the RoleID from
/// `<egress_dir>/maknae-egress-approle-id`, the SecretID from
/// `$CREDENTIALS_DIRECTORY/maknae-egress-secret-id`. The source decision is
/// resolved FIRST so an absent credentials directory is refused before any
/// file is opened.
pub fn load_egress_auth(
    egress_dir: &Path,
    approle_mount: String,
    credentials_dir_env: Option<&str>,
) -> Result<AppRoleAuth, VaultError> {
    let secret_path = resolve_egress_secret_source(credentials_dir_env)?;
    let role_id = crate::client::read_trimmed(&egress_dir.join(EGRESS_ROLE_ID_FILE))?;
    let secret_id = crate::secret_io::read_egress_secret(&secret_path)?;
    Ok(AppRoleAuth {
        role_id,
        secret_id,
        approle_mount,
    })
}

/// The deputy's client: settings plus the standing AppRole credential. Holds
/// NO token between operations (see the module doc).
pub struct EgressVault {
    settings: VaultClientSettings,
    auth: AppRoleAuth,
}

impl EgressVault {
    /// `assert_fips_provider` runs FIRST so vaultrs's reqwest reads the FIPS
    /// default — the load-bearing ordering `client.rs` documents. The CA file
    /// is read once here so a missing or malformed CA is a boot refusal.
    pub fn new(addr: &str, vault_ca: &Path, auth: AppRoleAuth) -> Result<Self, VaultError> {
        assert_fips_provider()?;
        validate_vault_addr(addr)?;
        let settings = VaultClientSettingsBuilder::default()
            .address(addr)
            .ca_certs(vec![vault_ca.to_string_lossy().to_string()])
            // Stated rather than defaulted: vaultrs fills an unset `verify`
            // from VAULT_SKIP_VERIFY and turns verification OFF for any value
            // other than 0/f/false — the empty string included. The other
            // env-defaulted settings (token, identity, proxy) are handled by
            // the deputy scrubbing those variables before this runs
            // (`bins/maknae-egress/src/env.rs`); a unit's environment is NOT
            // clean by default — DefaultEnvironment= reaches every service.
            .verify(true)
            // Stated too, so this constructor is safe on its own and not only
            // under the deputy's scrub: no inherited token (login supplies
            // one), no inherited client identity.
            .token("")
            .identity(None)
            .timeout(Some(VAULT_HTTP_TIMEOUT))
            .build()
            .map_err(|e| VaultError::Auth(format!("egress vault client settings: {e}")))?;
        Self::client(&settings)?;
        Ok(Self { settings, auth })
    }

    /// A fresh client per login. `VaultClient::new` reads and parses the CA
    /// file again each time — the honest cost of holding no client between
    /// reads, paid once per destination for the life of the process. It also
    /// means a CA file replaced between reads is picked up by the next one,
    /// which is the behaviour a rotated Vault CA wants.
    fn client(settings: &VaultClientSettings) -> Result<VaultClient, VaultError> {
        let mut client = VaultClient::new(settings.clone())
            .map_err(|e| VaultError::Auth(format!("egress vault client: {e}")))?;
        // The client vaultrs built follows redirects and is not HTTPS-only;
        // the one that actually sends is `http.rs`'s (no redirects, HTTPS
        // only, no proxy) — see that module for the downgrade it prevents.
        crate::http::harden(
            &mut client,
            settings.address.as_str(),
            Path::new(&settings.ca_certs[0]),
            VAULT_HTTP_TIMEOUT,
        )?;
        Ok(client)
    }

    /// Login and revoke: proves the credential at boot without leaving a token,
    /// and reports success only when both halves completed (`egress_session`).
    pub async fn probe_login(&self) -> Result<(), VaultError> {
        probe(self).await
    }

    /// One field of one KV v2 secret, under a token that exists only for this
    /// call and is gone before the value is returned; a read whose revoke
    /// failed is a refusal (`egress_session::read_one`). `key_vault_path` is
    /// the full API path (`<mount>/data/<path>`): the deputy composes it,
    /// because addressing is the store's business.
    pub async fn read_kv_field(
        &self,
        key_vault_path: &str,
        field: &str,
    ) -> Result<Zeroizing<String>, VaultError> {
        read_one(self, key_vault_path, field).await
    }
}

/// The three Vault operations, over vaultrs. The session is the token-bearing
/// client; `revoke` consumes it, so nothing can use the token afterwards. The
/// trait is crate-private: outside this crate only the composed
/// `probe_login`/`read_kv_field` exist.
impl EgressOps for EgressVault {
    type Session = VaultClient;

    async fn login(&self) -> Result<VaultClient, VaultError> {
        let mut client = Self::client(&self.settings)?;
        let token = self.auth.authenticate(&client).await?;
        client.set_token(&token.client_token);
        Ok(client)
    }

    async fn read(
        &self,
        session: &VaultClient,
        key_vault_path: &str,
        field: &str,
    ) -> Result<Zeroizing<String>, VaultError> {
        crate::read_kv_field(session, key_vault_path, field).await
    }

    async fn revoke(&self, session: VaultClient) -> Result<(), VaultError> {
        vaultrs::token::revoke_self(&session)
            .await
            .map_err(|e| VaultError::Revoke(e.to_string()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::AppRoleAuth;
    use crate::secret_source::EGRESS_CREDENTIALS_DIRECTORY_CRED_NAME;
    use crate::VaultError;
    use zeroize::Zeroizing;

    fn tmp(name: &str) -> std::path::PathBuf {
        let p = std::env::temp_dir().join(format!("mv-egress-{}-{name}", std::process::id()));
        let _ = std::fs::remove_dir_all(&p);
        std::fs::create_dir_all(&p).unwrap();
        p
    }

    fn self_signed_pem() -> String {
        let params = rcgen::CertificateParams::new(vec!["ca.test".to_string()]).unwrap();
        let key = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P384_SHA384).unwrap();
        params.self_signed(&key).unwrap().pem()
    }

    fn auth() -> AppRoleAuth {
        AppRoleAuth {
            role_id: "r".into(),
            secret_id: Zeroizing::new("s".into()),
            approle_mount: "maknae-approle".into(),
        }
    }

    /// The RoleID file and the sealed SecretID are read verbatim (trimmed); a
    /// missing RoleID is a refusal naming the path, and an absent credentials
    /// directory is refused BEFORE any file is opened.
    #[test]
    fn load_egress_auth_reads_both_halves_and_refuses_a_missing_role_id() {
        let etc = tmp("auth");
        let creds = tmp("creds");
        std::fs::write(
            creds.join(EGRESS_CREDENTIALS_DIRECTORY_CRED_NAME),
            "sid-123\n",
        )
        .unwrap();
        let creds_env = creds.to_str().unwrap();
        // no $CREDENTIALS_DIRECTORY: refused by source, not by file
        assert!(matches!(
            load_egress_auth(&etc, "m".into(), None),
            Err(VaultError::CredentialSource(_))
        ));
        // missing RoleID
        // (`unwrap_err` would need `Debug` on `AppRoleAuth`, which deliberately
        // has none: it holds the SecretID.)
        match load_egress_auth(&etc, "maknae-approle".into(), Some(creds_env)) {
            Err(e) => assert!(matches!(e, VaultError::Io { .. }), "{e}"),
            Ok(_) => panic!("a missing RoleID must refuse"),
        }
        std::fs::write(etc.join(EGRESS_ROLE_ID_FILE), "rid-abc\n").unwrap();
        let a = load_egress_auth(&etc, "maknae-approle".into(), Some(creds_env)).unwrap();
        assert_eq!(a.role_id, "rid-abc");
        assert_eq!(a.secret_id.as_str(), "sid-123");
        assert_eq!(a.approle_mount, "maknae-approle");
    }

    /// A dead Vault address is an ERROR from inside a runtime — never a panic
    /// and never a success — from both the boot probe and the read.
    #[test]
    fn a_dead_vault_returns_errors_from_probe_and_read() {
        crate::install_default_crypto_provider();
        let d = tmp("dead");
        let ca = d.join(EGRESS_VAULT_CA_FILE);
        std::fs::write(&ca, self_signed_pem()).unwrap();
        let v = EgressVault::new("https://127.0.0.1:1", &ca, auth()).unwrap();
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        assert!(rt.block_on(v.probe_login()).is_err());
        assert!(rt
            .block_on(v.read_kv_field("maknae-kv/data/maknae/providers/openai", "api-key"))
            .is_err());
    }

    /// Construction refuses a plaintext scheme and a missing CA file NOW, at
    /// boot, not on the first request.
    #[test]
    fn construction_fails_closed_on_plaintext_addr_and_missing_ca() {
        crate::install_default_crypto_provider();
        let d = tmp("ctor");
        assert!(matches!(
            EgressVault::new("http://127.0.0.1:1", &d.join("x.crt"), auth()),
            Err(VaultError::InvalidAddr(_))
        ));
        assert!(EgressVault::new("https://127.0.0.1:1", &d.join("absent.crt"), auth()).is_err());
    }
}
