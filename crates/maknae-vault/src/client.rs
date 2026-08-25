//! `PlaneClient` — the Stage-1 orchestrator: config → AppRole auth (standing raw
//! SecretID, ADR-0018) → P-384 CSR → `pki/sign` → memory-only leaf. The identity is Arc-backed
//! (cheap snapshot; key wiped on drop). The credential supervisor (`spawn_supervisor`,
//! `supervisor_run.rs`) runs on a shared handle so serving, token renewal, and leaf
//! rotation all proceed concurrently (ADR-0018 Decision 3).
use crate::auth::AppRoleAuth;
use crate::secret_io::{read_cli_secret, read_daemon_secret};
use crate::secret_source::{
    resolve_cli_secret_source, resolve_daemon_secret_source, CredentialSourceKind,
};
use crate::{
    assert_fips_provider, generate_plane_csr, load_ca_pin, vault_config_from_document,
    verify::verify_plane_uri_san, Plane, VaultError, VAULT_SECTION,
};
use arc_swap::ArcSwapOption;
use maknae_config::{load_config, Document, SectionSpec};
use rustls::sign::CertifiedKey;
use std::path::{Path, PathBuf};
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
    /// The posture record for THIS client's SecretID credential source (Task 7's
    /// audit reads this via `secret_source()`). Set by `from_document`'s dispatch;
    /// `from_document_with_secret` alone (no resolution info available) defaults it
    /// to `PlaintextPath` — the most conservative/weakest posture — as a safe
    /// placeholder that `from_document` always overwrites with the real resolved
    /// kind right after construction (same module — private-field access is
    /// module-scoped, not impl-scoped, in Rust).
    secret_source_kind: CredentialSourceKind,
}

fn read_trimmed(path: &Path) -> Result<String, VaultError> {
    let bytes = crate::read_storage(
        path,
        maknae_io::TargetRequired {
            owner: None,
            mode_mask: None,
            nlink_exactly_one: false,
            regular_file: true,
        },
    )?;
    std::str::from_utf8(&bytes)
        .map(|s| s.trim().to_string())
        .map_err(|e| VaultError::Io {
            path: path.to_path_buf(),
            source: std::io::Error::other(e.to_string()),
        })
}

/// Read a SENSITIVE credential file (the standing raw SecretID). Refuse a symlink or any
/// group/other access BEFORE reading — the SecretID must never be world-readable
/// (maknae-config gates `maknae.yaml` + the dir, but not files we read directly).
/// `pub(crate)`: `secret_io.rs`'s PLAINTEXT read branches route through this SAME
/// gate (the sealed branches — `$CREDENTIALS_DIRECTORY`, SEP — do not, since
/// systemd/SEP produce their own `0400` artifacts).
pub(crate) fn read_secret_credential(path: &Path) -> Result<String, VaultError> {
    // Non-Unix has no owner-only permission model to check → refuse rather than read the
    // wrapped SecretID unchecked (fail closed; mirrors maknae-config). Not exercisable on
    // a unix CI runner, hence no mutation/coverage obligation on the non-unix arm.
    #[cfg(not(unix))]
    {
        Err(VaultError::PermissionsUnsupported)
    }
    #[cfg(unix)]
    {
        let target = maknae_io::TargetRequired {
            owner: None,
            mode_mask: Some(0o077),
            nlink_exactly_one: false,
            regular_file: true,
        };
        let bytes = maknae_io::read_absolute(path, target, maknae_io::StrategyPref::Auto)
            .map_err(|error| match error {
                maknae_io::IoError::Symlink { .. } => VaultError::InsecureCredential {
                    path: path.to_path_buf(),
                    detail: "is a symlink".into(),
                },
                maknae_io::IoError::InsecurePermissions { mode, .. } => {
                    VaultError::InsecureCredential {
                        path: path.to_path_buf(),
                        detail: format!(
                            "mode {:o} allows group/other access (require 0600 or stricter)",
                            mode & 0o777
                        ),
                    }
                }
                other => VaultError::Io {
                    path: path.to_path_buf(),
                    source: std::io::Error::other(other.to_string()),
                },
            })?
            .value;
        std::str::from_utf8(&bytes)
            .map(|s| s.trim().to_string())
            .map_err(|e| VaultError::Io {
                path: path.to_path_buf(),
                source: std::io::Error::other(e.to_string()),
            })
    }
}

/// The daemon's SEP-sealed blob path, IF one is present — macOS only (there is no
/// systemd on darwin, so `$CREDENTIALS_DIRECTORY` never applies there; a SEP blob is
/// the darwin equivalent). Observing "is it present" here (rather than inside the
/// PURE `resolve_daemon_secret_source`) is what keeps that resolver pure/testable —
/// this is the one spot that touches the filesystem to decide what to hand it.
#[cfg(target_os = "macos")]
fn daemon_sep_blob_path(dir: &Path) -> Option<PathBuf> {
    let p = dir.join("maknaed-secret-id.sep");
    p.is_file().then_some(p)
}
#[cfg(not(target_os = "macos"))]
fn daemon_sep_blob_path(_dir: &Path) -> Option<PathBuf> {
    None
}

/// Whether this target has a user-scoped `systemd-creds` credential file for the
/// CLI — observed here (filesystem), handed to the PURE `resolve_cli_secret_source`
/// as a plain `bool`.
fn cli_dir_has_user_creds(cli_dir: &Path) -> bool {
    cli_dir.join("maknae-secret-id.cred").is_file()
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
    /// Build from a config dir, loading the config under a `vault`-only registry.
    /// Retained for back-compat (the gated live-smoke tests). A process that ALSO reads
    /// other sections (the daemon: `core`+`lake`+`vault`+`transport`+`audit`; the CLI:
    /// `core`+`vault`+`transport`) must instead load the config ONCE with every section
    /// registered and call [`PlaneClient::from_document`] on that shared document — a
    /// per-call `vault`-only reload here would reject those sections as `UnknownSection`
    /// (the P1-A/P1-B fix). File I/O only; the FIPS assertion is in `from_document`.
    pub fn from_config_dir(dir: &Path, plane: Plane) -> Result<Self, VaultError> {
        let doc = load_config(
            dir,
            &[SectionSpec {
                name: VAULT_SECTION.to_string(),
                required: true,
            }],
        )?;
        Self::from_document(&doc, dir, plane)
    }

    /// Build from an ALREADY-LOADED config [`Document`] plus the credential dir,
    /// resolving THIS PLANE's SecretID credential SOURCE (spec §5.1) and reading it,
    /// then delegating to [`Self::from_document_with_secret`]. **Keeps its exact
    /// pre-Task-4 signature** — every existing caller (the daemon's `run.rs`, the
    /// CLI's `cli.rs`) is unaffected.
    ///
    /// **Dispatches on `plane` — the two planes do NOT share a resolver (round-1
    /// C1 regression guard):**
    /// - `Plane::Kernel` → [`resolve_daemon_secret_source`]: `$CREDENTIALS_DIRECTORY`
    ///   (if set) → a SEP-sealed blob (macOS only) → `vault.insecure_plaintext_secret_path`
    ///   (from config) → fail closed. This is EXACTLY the daemon's pre-existing boot
    ///   path when `$CREDENTIALS_DIRECTORY` is set — that env var, when present,
    ///   ALWAYS wins here, never falling through to a CLI-shaped order.
    /// - `Plane::Cli` → [`resolve_cli_secret_source`]: a user-scoped `systemd-creds`
    ///   file (if present in `dir`) → the macOS Keychain → the residual plaintext
    ///   file in `dir`.
    ///
    /// `dir` still supplies the non-section credential files (AppRole id / the
    /// resolved SecretID source / CA pins / Vault CA), read from disk, not the
    /// document.
    pub fn from_document(doc: &Document, dir: &Path, plane: Plane) -> Result<Self, VaultError> {
        // Parsed here (in addition to inside from_document_with_secret) ONLY to
        // reach `insecure_plaintext_secret_path` before the secret_id is resolved —
        // vault_config_from_document is a pure in-memory parse of the
        // already-loaded `doc` (no I/O), so parsing it twice is cheap and safe, not
        // a double-read of anything sensitive.
        let cfg = vault_config_from_document(doc)?;
        let (secret_id, kind) = match plane {
            Plane::Kernel => {
                let src = resolve_daemon_secret_source(
                    std::env::var("CREDENTIALS_DIRECTORY").ok().as_deref(),
                    daemon_sep_blob_path(dir).as_deref(),
                    cfg.insecure_plaintext_secret_path.as_deref(),
                )?;
                let secret = read_daemon_secret(&src)?;
                (secret, CredentialSourceKind::from(&src))
            }
            Plane::Cli => {
                let src = resolve_cli_secret_source(
                    dir,
                    cli_dir_has_user_creds(dir),
                    cfg!(target_os = "macos"),
                )?;
                let secret = read_cli_secret(&src)?;
                (secret, CredentialSourceKind::from(&src))
            }
        };
        let mut client = Self::from_document_with_secret(doc, dir, plane, secret_id)?;
        client.secret_source_kind = kind;
        Ok(client)
    }

    /// Build from an ALREADY-LOADED config [`Document`], the credential dir, AND an
    /// already-read SecretID — the coherent-config entrypoint (P1-A/P1-B) plus the
    /// Task-4 credential-source seam: [`Self::from_document`] resolves + reads the
    /// SecretID per-plane (spec §5.1) and hands it here; this constructor no longer
    /// decides WHERE the SecretID comes from, only how to build the client once it
    /// has one. `dir` still supplies the non-secret credential files (AppRole id /
    /// CA pins / Vault CA), read from disk, not the document.
    ///
    /// **LOAD-BEARING ordering:** `assert_fips_provider()` runs first — before the Vault
    /// client is built — so reqwest reads the FIPS default (§6.1), never falling back to
    /// ring. Fail-closed throughout.
    ///
    /// The returned client's `secret_source()` defaults to `PlaintextPath` (the most
    /// conservative placeholder) since this constructor has no resolution info of its
    /// own; `from_document` — its sole production caller — overwrites it with the
    /// real resolved kind immediately after construction.
    pub fn from_document_with_secret(
        doc: &Document,
        dir: &Path,
        plane: Plane,
        secret_id: Zeroizing<String>,
    ) -> Result<Self, VaultError> {
        assert_fips_provider()?;
        let cfg = vault_config_from_document(doc)?;
        // Loading the CA-pin validates it now (Stage 2 consumes the bundle).
        let _ca = load_ca_pin(dir)?;
        let prefix = plane.config_prefix();
        // RoleID is non-secret (an identifier), still read from disk here.
        let role_id = read_trimmed(&dir.join(format!("{prefix}-approle-id")))?;
        let vault_ca = dir.join("tls").join("vault-ca.crt");
        // A HARD per-request HTTP timeout on every Vault operation this client ever
        // makes (login/mint/sign, renew_self, revoke_self). vaultrs defaults
        // `timeout` to None — an UNBOUNDED reqwest client — so a hung Vault connection
        // (network drop with no RST, a stalled LB) would otherwise wedge whatever
        // awaits it: the credential supervisor's renew/rotate (silently zombifying the
        // daemon — the supervisor never returns, so the run-loop's supervisor-exit
        // select never fires and the leaf just expires), boot-time `mint()`, and the
        // best-effort `revoke_self` on the shutdown path. 30s is far above any healthy
        // Vault round-trip and far below every credential validity window; a timeout
        // surfaces as an ordinary retryable error to the supervisor's
        // retry-within-window logic (ADR-0018).
        let settings = VaultClientSettingsBuilder::default()
            .address(cfg.addr)
            .ca_certs(vec![vault_ca.to_string_lossy().to_string()])
            .timeout(Some(std::time::Duration::from_secs(30)))
            .build()
            .map_err(|e| VaultError::Auth(format!("vault client settings: {e}")))?;
        let client = VaultClient::new(settings)
            .map_err(|e| VaultError::Auth(format!("vault client: {e}")))?;
        Ok(Self {
            plane,
            deployment_id: cfg.deployment_id,
            auth: AppRoleAuth {
                role_id,
                secret_id,
                approle_mount: cfg.approle_mount,
            },
            pki_int_mount: cfg.pki_int_mount,
            client: Arc::new(Mutex::new(client)),
            identity: Arc::new(RwLock::new(None)),
            lease_secs: Arc::new(AtomicU64::new(0)),
            cert_sink: Arc::new(RwLock::new(None)),
            leaf_issued_at: Arc::new(AtomicU64::new(0)),
            leaf_ttl_secs: Arc::new(AtomicU64::new(0)),
            secret_source_kind: CredentialSourceKind::PlaintextPath,
        })
    }

    /// This client's resolved SecretID credential-source posture (Task 7's audit
    /// seam, round-1 C2). Reflects whichever source [`Self::from_document`] actually
    /// used — `CredentialsDirectory`/`SepSealed` are the sealed postures,
    /// `PlaintextPath` the weakest (also the default for a client built directly via
    /// [`Self::from_document_with_secret`], which has no resolution info to report).
    pub fn secret_source(&self) -> CredentialSourceKind {
        self.secret_source_kind
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
        self.lease_secs
            .store(auth.lease_duration, Ordering::Relaxed);
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
        if let Some(slot) = self
            .cert_sink
            .read()
            .expect("cert_sink lock poisoned")
            .as_ref()
        {
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
        let (key_der, leaf_pem, chain_pem) = sign_leaf_for(
            self.plane,
            &self.deployment_id,
            &self.pki_int_mount,
            &client,
        )
        .await?;
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
        std::fs::write(&p, "secret-id-value-xyz").unwrap();
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
        assert_eq!(read_secret_credential(&p).unwrap(), "secret-id-value-xyz");
        let _ = std::fs::remove_file(&p);
    }

    // ---- from_document plane dispatch (Task 4) ---------------------------------
    //
    // `$CREDENTIALS_DIRECTORY` is process-wide; without this lock these tests can
    // interleave across cargo's multi-threaded test runner (env-lock pattern per
    // bins/maknae/src/cli.rs's ENV_LOCK / crates/maknae-msgs/src/lib.rs's ENV_LOCK).
    static ENV_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    struct DispatchFixture(std::path::PathBuf);
    impl DispatchFixture {
        fn self_signed_pem() -> String {
            let params = rcgen::CertificateParams::new(vec!["ca.test".to_string()]).unwrap();
            let key = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P384_SHA384).unwrap();
            params.self_signed(&key).unwrap().pem()
        }

        /// A complete config dir: `core`+`vault` document, CA-pin trio, and the
        /// AppRole ids for BOTH planes — everything `from_document` needs EXCEPT
        /// the SecretID files/dirs themselves, which each test wires up per
        /// scenario.
        fn new(tag: &str, extra_vault_yaml: &str) -> Self {
            // `assert_fips_provider()` (inside `from_document_with_secret`) reads the
            // PROCESS-GLOBAL rustls default provider; install it here (idempotent —
            // a no-op if some other test already did) rather than relying on test
            // execution order, matching every other provider-touching test in this
            // crate (fips_glue.rs, resolver.rs, transport_tests.rs, tls.rs,
            // plane_verify.rs all do this same call at their own point of use).
            rustls::crypto::aws_lc_rs::default_provider()
                .install_default()
                .ok();
            let p =
                std::env::temp_dir().join(format!("mv-dispatch-{}-{}", std::process::id(), tag));
            let _ = std::fs::remove_dir_all(&p);
            std::fs::create_dir_all(p.join("tls")).unwrap();
            std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o700)).unwrap();
            let yaml = format!(
                "core:\n  deployment_id: dev-01\nvault:\n  addr: https://v.example:8200\n{extra_vault_yaml}"
            );
            let cfg_path = p.join("maknae.yaml");
            std::fs::write(&cfg_path, yaml).unwrap();
            std::fs::set_permissions(&cfg_path, std::fs::Permissions::from_mode(0o600)).unwrap();
            for f in [
                "tls/maknae-root-ca.crt",
                "tls/maknae-int-ca.crt",
                "tls/vault-ca.crt",
            ] {
                std::fs::write(p.join(f), Self::self_signed_pem()).unwrap();
            }
            std::fs::write(p.join("maknaed-approle-id"), "maknaed-role-id\n").unwrap();
            std::fs::write(p.join("maknae-approle-id"), "maknae-role-id\n").unwrap();
            DispatchFixture(p)
        }

        fn doc(&self) -> Document {
            load_config(
                &self.0,
                &[SectionSpec {
                    name: VAULT_SECTION.to_string(),
                    required: true,
                }],
            )
            .expect("fixture config loads")
        }
    }
    impl Drop for DispatchFixture {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    /// The regression guard (round-1 C1, mandatory per plan review): `Plane::Kernel`
    /// with a POPULATED `$CREDENTIALS_DIRECTORY` resolves THERE — never the CLI
    /// order — even though `dir` has no `maknaed-secret-id` file of its own (so a
    /// bug that fell through to `dir`-relative resolution would fail closed with
    /// `Io`, not silently pass).
    #[test]
    fn kernel_dispatch_prefers_credentials_directory_never_cli_order() {
        let _g = ENV_LOCK.lock().unwrap();
        let fx = DispatchFixture::new("kernel-cd", "");
        let creds_dir =
            std::env::temp_dir().join(format!("mv-dispatch-creds-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&creds_dir);
        std::fs::create_dir_all(&creds_dir).unwrap();
        std::fs::write(creds_dir.join("maknaed-secret-id"), "kernel-secret-value").unwrap();

        std::env::set_var("CREDENTIALS_DIRECTORY", &creds_dir);
        let doc = fx.doc();
        let result = PlaneClient::from_document(&doc, &fx.0, Plane::Kernel);
        std::env::remove_var("CREDENTIALS_DIRECTORY");
        let _ = std::fs::remove_dir_all(&creds_dir);

        let client = result.expect("Kernel resolves via $CREDENTIALS_DIRECTORY");
        assert_eq!(
            client.secret_source(),
            CredentialSourceKind::CredentialsDirectory
        );
    }

    /// `$CREDENTIALS_DIRECTORY` UNSET → `Plane::Kernel` falls through to the next
    /// configured source (`vault.insecure_plaintext_secret_path`), proving the
    /// resolution order isn't hardcoded to always pick `CredentialsDirectory`.
    #[test]
    fn kernel_dispatch_falls_through_when_credentials_directory_unset() {
        let _g = ENV_LOCK.lock().unwrap();
        std::env::remove_var("CREDENTIALS_DIRECTORY");
        let plain = std::env::temp_dir().join(format!("mv-dispatch-plain-{}", std::process::id()));
        std::fs::write(&plain, "plaintext-secret-value").unwrap();
        std::fs::set_permissions(&plain, std::fs::Permissions::from_mode(0o600)).unwrap();

        let fx = DispatchFixture::new(
            "kernel-plain",
            &format!(
                "  insecure_plaintext_secret_path: {}\n",
                plain.to_string_lossy()
            ),
        );
        let doc = fx.doc();
        let client = PlaneClient::from_document(&doc, &fx.0, Plane::Kernel)
            .expect("Kernel falls through to the configured plaintext path");
        assert_eq!(client.secret_source(), CredentialSourceKind::PlaintextPath);
        let _ = std::fs::remove_file(&plain);
    }

    /// The other half of the regression guard: with `$CREDENTIALS_DIRECTORY`
    /// STILL populated (same env as the first test), `Plane::Cli` must NOT read
    /// it — proving the two planes do not share a resolver. Tolerant of platform
    /// (the CLI's own order differs by `cfg!(target_os = "macos")`): on a
    /// non-macOS build with no user-creds file it falls through to the residual
    /// plaintext file (`PlaintextPath`); on macOS it falls to the (stubbed)
    /// Keychain and fails closed. Either outcome proves non-use of the Kernel's
    /// `$CREDENTIALS_DIRECTORY` value — a regression that shared the resolver
    /// would instead return `Ok` with `CredentialSourceKind::CredentialsDirectory`
    /// and the KERNEL secret value, matching neither arm below.
    #[test]
    fn cli_dispatch_ignores_credentials_directory_uses_cli_order() {
        let _g = ENV_LOCK.lock().unwrap();
        let fx = DispatchFixture::new("cli-order", "");
        let creds_dir =
            std::env::temp_dir().join(format!("mv-dispatch-cli-creds-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&creds_dir);
        std::fs::create_dir_all(&creds_dir).unwrap();
        std::fs::write(creds_dir.join("maknaed-secret-id"), "kernel-secret-value").unwrap();
        // The CLI's residual-file fallback — present so a non-macOS build (where
        // Keychain is skipped) can resolve all the way to a successful client.
        std::fs::write(fx.0.join("maknae-secret-id"), "cli-secret-value").unwrap();
        std::fs::set_permissions(
            fx.0.join("maknae-secret-id"),
            std::fs::Permissions::from_mode(0o600),
        )
        .unwrap();

        std::env::set_var("CREDENTIALS_DIRECTORY", &creds_dir);
        let doc = fx.doc();
        let result = PlaneClient::from_document(&doc, &fx.0, Plane::Cli);
        std::env::remove_var("CREDENTIALS_DIRECTORY");
        let _ = std::fs::remove_dir_all(&creds_dir);

        match result {
            Ok(client) => assert_eq!(
                client.secret_source(),
                CredentialSourceKind::PlaintextPath,
                "non-macOS CLI order must land on the residual plaintext file, not the kernel's $CREDENTIALS_DIRECTORY"
            ),
            Err(VaultError::CredentialSource(_)) => {
                // macOS: fell to the stubbed Keychain — also proves it did not
                // read $CREDENTIALS_DIRECTORY (which would have succeeded).
            }
            Err(e) => panic!("unexpected error proving the CLI plane uses its own order: {e:?}"),
        }
    }
}
