//! `PlaneClient` — the Stage-1 orchestrator: config → AppRole auth (response-wrapped
//! SecretID) → P-384 CSR → `pki/sign` → memory-only leaf. The identity is Arc-backed
//! (cheap snapshot; key wiped on drop). The credential supervisor (`spawn_supervisor`,
//! `supervisor_run.rs`) runs on a shared handle so serving, token renewal, and leaf
//! rotation all proceed concurrently (ADR-0018 Decision 3).
use crate::auth::AppRoleAuth;
use crate::{
    assert_fips_provider, generate_plane_csr, load_ca_pin, load_vault_config,
    verify::verify_plane_uri_san, Plane, VaultError,
};
use arc_swap::ArcSwapOption;
use rustls::sign::CertifiedKey;
use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, RwLock};
use tokio::sync::Mutex;
use vaultrs::client::{Client, VaultClient, VaultClientSettingsBuilder};
use x509_parser::certificate::X509Certificate;
use x509_parser::prelude::FromDer;
use zeroize::Zeroizing;

struct IdentityInner {
    leaf_pem: String,
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
    /// The private key in DER (crate-internal only — used to build the rustls
    /// `CertifiedKey` in `tls.rs`; never handed to a caller).
    pub(crate) fn key_der(&self) -> &[u8] {
        &self.0.key_der
    }
}

/// Detaches a listener's cert sink from its `PlaneClient` when the listener is dropped, so
/// the client can back a replacement listener afterward. Held by `PlaneListener`.
pub(crate) struct CertSinkGuard {
    cert_sink: Arc<RwLock<Option<Arc<ArcSwapOption<CertifiedKey>>>>>,
    slot: Arc<ArcSwapOption<CertifiedKey>>,
}

impl Drop for CertSinkGuard {
    fn drop(&mut self) {
        let mut guard = self.cert_sink.write().expect("cert_sink lock poisoned");
        // Only detach if the registered slot is still OURS (defensive; a second active bind
        // is rejected, so it always is). Clear the slot (stop serving) then deregister so a
        // fresh bind can succeed.
        if guard
            .as_ref()
            .map(|s| Arc::ptr_eq(s, &self.slot))
            .unwrap_or(false)
        {
            self.slot.store(None);
            *guard = None;
        }
    }
}

/// The Stage-1 plane-cert client.
pub struct PlaneClient {
    plane: Plane,
    deployment_id: String,
    auth: AppRoleAuth,
    /// Intermediate PKI mount for `pki/sign` (from config; Terraform `int_mount_path`).
    pki_int_mount: String,
    client: Arc<Mutex<VaultClient>>,
    identity: Arc<RwLock<Option<PlaneIdentity>>>,
    /// The last mint's token lease (seconds); drives the renewal interval so it tracks
    /// the actual token TTL rather than a hardcoded assumption. 0 until first mint.
    lease_secs: Arc<AtomicU64>,
    /// The server resolver's cert slot (set only when a PlaneListener is bound; None for
    /// the CLI). Stored/cleared IN THE SAME critical section as the identity write so the
    /// resolver never lags the identity.
    cert_sink: Arc<RwLock<Option<Arc<ArcSwapOption<CertifiedKey>>>>>,
    /// The current leaf's `NotBefore`, unix seconds (0 until first mint) — feeds the
    /// leaf-rotation loop's `leaf_age_secs` off the ACTUAL issued validity window
    /// (mirrors `lease_secs` for the token; avoids drifting from a hardcoded TTL
    /// constant if the Vault role's `leaf_ttl_seconds` changes).
    leaf_issued_at: Arc<AtomicU64>,
    /// The current leaf's TTL in seconds (`NotAfter - NotBefore`), 0 until first mint.
    leaf_ttl_secs: Arc<AtomicU64>,
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
    // Non-Unix has no owner-only permission model to check → refuse rather than read the
    // wrapped SecretID unchecked (fail closed; mirrors maknae-config). Not exercisable on
    // a unix CI runner, hence no mutation/coverage obligation on the non-unix arm.
    #[cfg(not(unix))]
    {
        let _ = &meta;
        Err(VaultError::PermissionsUnsupported)
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = meta.permissions().mode() & 0o777;
        if mode & 0o077 != 0 {
            return Err(VaultError::InsecureCredential {
                path: path.to_path_buf(),
                detail: format!(
                    "mode {mode:o} allows group/other access (require 0600 or stricter)"
                ),
            });
        }
        std::fs::read_to_string(path)
            .map(|s| s.trim().to_string())
            .map_err(|source| VaultError::Io {
                path: path.to_path_buf(),
                source,
            })
    }
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

/// Parse the leaf's actual issued validity window (unix seconds) — `(NotBefore,
/// NotAfter - NotBefore)`. Drives the rotation loop's `leaf_age_secs`/`leaf_ttl_secs`
/// off what Vault ACTUALLY issued rather than a hardcoded assumption (the Terraform
/// `leaf_ttl_seconds` var could change without a client rebuild).
fn leaf_validity_unix(pem: &str) -> Result<(u64, u64), VaultError> {
    let der = pem_to_der(pem)?;
    let (_, cert) = X509Certificate::from_der(&der)
        .map_err(|_| VaultError::Pem("signed leaf: malformed certificate (validity)"))?;
    let validity = cert.validity();
    let not_before = validity.not_before.timestamp();
    let not_after = validity.not_after.timestamp();
    if not_before < 0 || not_after <= not_before {
        return Err(VaultError::Pem("signed leaf: invalid validity window"));
    }
    Ok((not_before as u64, (not_after - not_before) as u64))
}

/// CSR → `pki/sign` → returned-leaf SAN self-check. A free fn (not `&self`) so it has
/// exactly ONE implementation shared by `PlaneClient::sign_leaf` (used by `mint`) and
/// `SupervisorCtx::rotate_leaf` (the leaf-rotation loop's mutator) — both need
/// identical CSR/sign/verify logic, just against a different already-authenticated
/// `VaultClient` handle.
async fn sign_leaf_for(
    plane: Plane,
    deployment_id: &str,
    pki_int_mount: &str,
    client: &VaultClient,
) -> Result<(Zeroizing<Vec<u8>>, String, Vec<String>), VaultError> {
    let (key_der, csr_pem) = generate_plane_csr(plane, deployment_id)?;
    let resp = vaultrs::pki::cert::ca::sign(
        client,
        pki_int_mount,
        plane.pki_sign_role(),
        &csr_pem,
        "", // empty CN — the role sets require_cn=false / use_csr_common_name=false
        None,
    )
    .await
    .map_err(|e| VaultError::Sign(e.to_string()))?;
    // Defense-in-depth: the leaf Vault returned must carry exactly our plane SAN.
    let leaf_der = pem_to_der(&resp.certificate)?;
    verify_plane_uri_san(&leaf_der, plane, deployment_id)
        .map_err(|e| VaultError::Sign(format!("returned leaf failed SAN self-check: {e:?}")))?;
    Ok((key_der, resp.certificate, resp.ca_chain.unwrap_or_default()))
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
                approle_mount: cfg.approle_mount,
            },
            pki_int_mount: cfg.pki_int_mount,
            client: Arc::new(Mutex::new(client)),
            identity: Arc::new(RwLock::new(None)),
            lease_secs: Arc::new(AtomicU64::new(0)),
            cert_sink: Arc::new(RwLock::new(None)),
            leaf_issued_at: Arc::new(AtomicU64::new(0)),
            leaf_ttl_secs: Arc::new(AtomicU64::new(0)),
        })
    }

    /// Attach the server resolver's cert slot AND seed it from the current identity, both
    /// under the identity READ lock. Renewal-expiry takes the identity WRITE lock, so
    /// holding the read lock here excludes it: the seed cannot race an expiry that would
    /// otherwise clear the slot and leave this call restoring a retired cert. After this,
    /// `mint()`/expiry keep the slot in lock-step with the identity.
    pub(crate) fn attach_cert_sink(
        &self,
        slot: Arc<ArcSwapOption<CertifiedKey>>,
    ) -> Result<CertSinkGuard, VaultError> {
        let id_guard = self.identity.read().expect("identity lock poisoned");
        let mut sink_guard = self.cert_sink.write().expect("cert_sink lock poisoned");
        // ONE client backs at most ONE ACTIVE listener. Reject a second concurrent bind
        // rather than orphaning the first listener's sink — an orphan would keep serving a
        // stale cert that mint/expiry/shutdown no longer update (codex r5). The returned
        // CertSinkGuard deregisters this slot when the listener drops, so a *replacement*
        // listener can bind afterward (codex r6). Held across the is_some check + set so two
        // concurrent binds can't both win.
        if sink_guard.is_some() {
            return Err(VaultError::SocketBind(
                "this PlaneClient already backs a listener (one client backs one listener)".into(),
            ));
        }
        // Build + seed the new slot BEFORE registering it, so a build failure returns Err
        // without ever registering a half-initialized sink.
        if let Some(id) = id_guard.as_ref() {
            let ck = crate::tls::certified_key_from_identity(id)?;
            slot.store(Some(ck));
        }
        *sink_guard = Some(Arc::clone(&slot));
        Ok(CertSinkGuard {
            cert_sink: Arc::clone(&self.cert_sink),
            slot,
        })
    }

    /// The live mint: authenticate → CSR → `pki/sign` → hold memory-only. Stores a
    /// snapshot and returns a clone.
    pub async fn mint(&self) -> Result<PlaneIdentity, VaultError> {
        let mut client = self.client.lock().await;
        let token = self.auth.authenticate(&client).await?;
        client.set_token(&token.client_token);
        // Record the actual lease so the supervisor loop (spawn_supervisor) renews on
        // the real TTL; surface a non-renewable token (a role misconfig) rather than
        // silently failing later.
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
        // Record the ACTUAL issued validity window so the leaf-rotation loop tracks
        // it rather than a hardcoded assumption (mirrors lease_secs.store above).
        let (leaf_issued_at, leaf_ttl_secs) = match leaf_validity_unix(&leaf_pem) {
            Ok(v) => v,
            Err(e) => {
                let _ = vaultrs::token::revoke_self(&*client).await; // best-effort
                return Err(e);
            }
        };
        self.leaf_issued_at.store(leaf_issued_at, Ordering::Relaxed);
        self.leaf_ttl_secs.store(leaf_ttl_secs, Ordering::Relaxed);

        let id = PlaneIdentity(Arc::new(IdentityInner {
            leaf_pem,
            key_der,
            chain_pem,
        }));
        // Commit under the identity WRITE lock, reading the sink + building the CertifiedKey
        // INSIDE it, so a racing attach_cert_sink (which registers/seeds under the identity
        // lock) is fully serialized — no window where mint installs a new identity while the
        // resolver keeps the old cert, and no window where attach seeds a retired cert. The
        // build is synchronous, so nothing is awaited while the std lock is held; the only
        // await (token revoke on build failure) happens AFTER the guard is dropped, and the
        // identity is NOT committed on that failure path (fail closed).
        let build_result: Result<(), VaultError> = {
            let mut guard = self.identity.write().expect("identity lock poisoned");
            let sink = self
                .cert_sink
                .read()
                .expect("cert_sink lock poisoned")
                .clone();
            match sink {
                Some(slot) => match crate::tls::certified_key_from_identity(&id) {
                    Ok(ck) => {
                        *guard = Some(id.clone());
                        slot.store(Some(ck));
                        Ok(())
                    }
                    Err(e) => Err(e), // do NOT commit identity; revoke below (outside the lock)
                },
                None => {
                    *guard = Some(id.clone());
                    Ok(())
                }
            }
        };
        if let Err(e) = build_result {
            let _ = vaultrs::token::revoke_self(&*client).await; // best-effort
            return Err(e);
        }
        Ok(id)
    }

    /// CSR → `pki/sign` → returned-leaf SAN self-check. Split out so `mint` has a single
    /// post-auth cleanup point (revoke-on-failure). Delegates to the free `sign_leaf_for`
    /// (shared with `SupervisorCtx::rotate_leaf`).
    async fn sign_leaf(
        &self,
        client: &VaultClient,
    ) -> Result<(Zeroizing<Vec<u8>>, String, Vec<String>), VaultError> {
        sign_leaf_for(self.plane, &self.deployment_id, &self.pki_int_mount, client).await
    }

    /// The deployment id (crate-internal — the verifier needs it to compute the expected
    /// peer URI-SAN).
    pub(crate) fn deployment_id(&self) -> &str {
        &self.deployment_id
    }
    /// This client's plane (crate-internal — used to assert `expected_peer == plane.peer()`).
    pub(crate) fn plane(&self) -> Plane {
        self.plane
    }

    /// Non-blocking snapshot of the current identity (for the Stage-2 transport).
    pub fn current_identity(&self) -> Option<PlaneIdentity> {
        self.identity
            .read()
            .expect("identity lock poisoned")
            .clone()
    }

    /// Build a cheap, `'static`-safe handle to this client's shareable pieces — used
    /// by `spawn_supervisor`'s background task, which must outlive the `&self` borrow
    /// it's called with (mirrors the old `spawn_renewal`'s per-field `Arc::clone`
    /// pattern, generalized so `rotate_leaf`'s lock-discipline-critical code has
    /// exactly ONE implementation, shared by `PlaneClient::rotate_leaf` and the
    /// supervisor loop in `supervisor_run.rs`).
    pub(crate) fn supervisor_ctx(&self) -> SupervisorCtx {
        SupervisorCtx {
            client: Arc::clone(&self.client),
            identity: Arc::clone(&self.identity),
            cert_sink: Arc::clone(&self.cert_sink),
            lease_secs: Arc::clone(&self.lease_secs),
            leaf_issued_at: Arc::clone(&self.leaf_issued_at),
            leaf_ttl_secs: Arc::clone(&self.leaf_ttl_secs),
            plane: self.plane,
            deployment_id: self.deployment_id.clone(),
            pki_int_mount: self.pki_int_mount.clone(),
        }
    }

    /// Re-mint the plane leaf on the CURRENT valid token (ADR-0018 Decision 3's
    /// rotation mutator) — thin delegating wrapper. See `SupervisorCtx::rotate_leaf`
    /// for the lock-discipline contract (shared with the supervisor loop so there is
    /// exactly one implementation of this security-critical path).
    pub async fn rotate_leaf(&self) -> Result<(), VaultError> {
        self.supervisor_ctx().rotate_leaf().await
    }

    /// Best-effort revoke on shutdown; failure is logged, never blocks exit.
    pub async fn shutdown(self) {
        // Retire the transport credential FIRST — clear the resolver slot (a live listener
        // stops presenting a leaf) and the identity — so shutdown actually retires the cert
        // regardless of whether the token revoke below succeeds. Same lock-step order as
        // `expire` (slot before identity, under the identity write guard).
        {
            let mut guard = self.identity.write().expect("identity lock poisoned");
            if let Some(slot) = self
                .cert_sink
                .read()
                .expect("cert_sink lock poisoned")
                .as_ref()
            {
                slot.store(None);
            }
            *guard = None;
        }
        let client = self.client.lock().await;
        if let Err(e) = vaultrs::token::revoke_self(&*client).await {
            eprintln!("maknae-vault: token revoke-self on shutdown failed (ignored): {e}");
        }
    }
}

/// A cheap, `'static`-safe handle to a `PlaneClient`'s shareable pieces (built by
/// `PlaneClient::supervisor_ctx`) — the credential supervisor's I/O surface
/// (`supervisor_run.rs`, T3). All fields are `Arc`-backed except two small owned
/// `String`s (cloned once at construction); every method here mirrors the lock
/// discipline reviewed in `PlaneClient::mint`/`expire`/`shutdown`.
pub(crate) struct SupervisorCtx {
    client: Arc<Mutex<VaultClient>>,
    identity: Arc<RwLock<Option<PlaneIdentity>>>,
    cert_sink: Arc<RwLock<Option<Arc<ArcSwapOption<CertifiedKey>>>>>,
    lease_secs: Arc<AtomicU64>,
    leaf_issued_at: Arc<AtomicU64>,
    leaf_ttl_secs: Arc<AtomicU64>,
    plane: Plane,
    deployment_id: String,
    pki_int_mount: String,
}

impl SupervisorCtx {
    /// The last-known token lease (seconds); 0 before the first mint.
    pub(crate) fn current_lease_secs(&self) -> u64 {
        self.lease_secs.load(Ordering::Relaxed)
    }

    /// `(leaf_age_secs, leaf_ttl_secs)` off the ACTUAL issued validity window —
    /// `rotate_now`'s two inputs.
    pub(crate) fn leaf_age_and_ttl_secs(&self) -> (u64, u64) {
        let issued = self.leaf_issued_at.load(Ordering::Relaxed);
        let ttl = self.leaf_ttl_secs.load(Ordering::Relaxed);
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        (now.saturating_sub(issued), ttl)
    }

    /// One token-renewal attempt against the CURRENT token (no re-auth — `mint()`
    /// must have run first). Updates `lease_secs` from THIS renewal's response on
    /// success (Vault may shorten the lease near `token_max_ttl`) and returns the
    /// fresh lease so the caller can compute the next cadence / retry budget.
    pub(crate) async fn renew_token_once(&self) -> Result<u64, VaultError> {
        let c = self.client.lock().await;
        let auth = vaultrs::token::renew_self(&*c, None)
            .await
            .map_err(|e| VaultError::Renew(e.to_string()))?;
        self.lease_secs.store(auth.lease_duration, Ordering::Relaxed);
        Ok(auth.lease_duration)
    }

    /// Fail-closed retirement: clear the resolver slot (if bound) THEN the identity,
    /// under a single identity WRITE lock so a racing mint (which also takes
    /// `identity.write()`) cannot interleave into a torn state. Mirrors
    /// `PlaneClient::shutdown` / the old `spawn_renewal`'s `expire` closure. Used when
    /// the renewal retry budget is exhausted (`RetryAction::FailClosed`) and when
    /// leaf-rotation fails sustainedly.
    pub(crate) fn expire_now(&self) -> VaultError {
        let mut guard = self.identity.write().expect("identity lock poisoned");
        if let Some(slot) = self.cert_sink.read().expect("cert_sink lock poisoned").as_ref() {
            slot.store(None);
        }
        *guard = None;
        VaultError::RenewalExpired
    }

    /// Re-mint the plane leaf on the CURRENT valid token — the leaf-rotation loop's
    /// mutator (ADR-0018 Decision 3).
    ///
    /// **Lock discipline mirrors `PlaneClient::mint` exactly (client.rs `mint`,
    /// commit block at :272-273 in the original layout):** the async `pki/sign` call
    /// (`sign_leaf_for`) runs to completion with NO identity lock held. THEN a
    /// synchronous block takes `identity.write()` and installs the new leaf —
    /// `*guard = Some(new_identity); slot.store(Some(new_ck));`, identity-then-slot,
    /// mint's own order — with **NOTHING awaited inside that block**. Holding the std
    /// `RwLock` write guard across the sign `.await` is forbidden here: it would let
    /// one in-flight rotation block every OTHER thread that needs the identity lock
    /// (including the TLS resolver's hot-path reads and a concurrent `mint`/`expire`)
    /// for the full round-trip to Vault, and — because this is `#![forbid(unsafe_code)]`
    /// with no `unsafe` escape hatch and no compiler lint that catches "sync guard
    /// held across an await point" — the only enforcement is this comment plus code
    /// review; the structure below (sign happens entirely BEFORE the `.write()` call
    /// is even taken) makes the mistake syntactically impossible to reintroduce by
    /// accident, since the guard variable doesn't exist yet during the `.await`.
    ///
    /// On failure the CURRENT identity/token are left untouched (fail-safe, not
    /// fail-closed): the token here is REUSED, not newly issued like `mint()`'s, so
    /// unlike `mint()` there is nothing to revoke. The supervisor loop
    /// (`supervisor_run.rs`) retries rotation within the same retry-window discipline
    /// as token renewal and falls back to `expire_now()` only on SUSTAINED failure.
    pub(crate) async fn rotate_leaf(&self) -> Result<(), VaultError> {
        let client = self.client.lock().await;
        let (key_der, leaf_pem, chain_pem) =
            sign_leaf_for(self.plane, &self.deployment_id, &self.pki_int_mount, &client).await?;
        let (issued_at, ttl_secs) = leaf_validity_unix(&leaf_pem)?;

        let id = PlaneIdentity(Arc::new(IdentityInner {
            leaf_pem,
            key_der,
            chain_pem,
        }));
        // Commit under the identity WRITE lock — synchronous only, NO `.await`
        // inside. identity-then-slot order (mint's own order).
        {
            let mut guard = self.identity.write().expect("identity lock poisoned");
            let sink = self
                .cert_sink
                .read()
                .expect("cert_sink lock poisoned")
                .clone();
            match sink {
                Some(slot) => match crate::tls::certified_key_from_identity(&id) {
                    Ok(ck) => {
                        *guard = Some(id);
                        slot.store(Some(ck));
                    }
                    // Do NOT commit identity on a build failure — the OLD leaf stays
                    // live; nothing to revoke (the token is reused, not newly issued).
                    Err(e) => return Err(e),
                },
                None => {
                    *guard = Some(id);
                }
            }
        }
        self.leaf_issued_at.store(issued_at, Ordering::Relaxed);
        self.leaf_ttl_secs.store(ttl_secs, Ordering::Relaxed);
        Ok(())
    }
}

// The credential-permission tests exercise the Unix-only mode check; gate the whole
// module to unix so the crate still compiles + tests on non-Unix targets.
#[cfg(all(test, unix))]
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
