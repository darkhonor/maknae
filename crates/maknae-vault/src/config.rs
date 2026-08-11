//! Vault client configuration, loaded via `maknae-config`. `maknae_config::Value`
//! is a bare enum (no accessors), so we pattern-match. `deployment_id` is
//! charset-guarded to match the PKI role's own guard (a glob/slash would corrupt
//! the plane URI-SAN or be rejected by Vault). All pure/fixture-testable (T1).
use crate::VaultError;
use maknae_config::{load_config, Document, SectionSpec, Value};
use std::path::Path;

/// The config section this client reads (the Terraform `vault` block: addr + mounts).
/// Exposed so each process registers it in the SAME `load_config` call as every OTHER
/// section it uses — the daemon (`core`+`lake`+`vault`+`transport`+`audit`) and the CLI
/// (`core`+`vault`+`transport`) — instead of re-loading under a per-call registry that
/// would reject the other sections with `UnknownSection` (the P1-A/P1-B fix).
pub const VAULT_SECTION: &str = "vault";

/// Default Vault mount paths — MUST match the deploy module's `approle_path` /
/// `int_mount_path` variable defaults (deploy/vault-pki/variables.tf). Overridable via
/// the `vault.approle_mount` / `vault.pki_int_mount` config keys so a deployment that
/// overrides those Terraform vars stays compatible with the client.
pub const DEFAULT_APPROLE_MOUNT: &str = "maknae-approle";
pub const DEFAULT_PKI_INT_MOUNT: &str = "maknae-pki-int";

/// The non-sensitive Vault settings.
pub struct VaultConfig {
    pub addr: String,
    pub deployment_id: String,
    /// AppRole auth mount (Terraform `approle_path`); defaults to `maknae-approle`.
    pub approle_mount: String,
    /// Intermediate PKI mount (Terraform `int_mount_path`); defaults to `maknae-pki-int`.
    pub pki_int_mount: String,
}

/// Pull a string value out of a `Value::Map` by key. `Value` exposes no accessor.
pub(crate) fn get_str<'a>(v: &'a Value, key: &str) -> Option<&'a str> {
    match v {
        Value::Map(entries) => {
            entries
                .iter()
                .find(|(k, _)| k == key)
                .and_then(|(_, val)| match val {
                    Value::Str(s) => Some(s.as_str()),
                    _ => None,
                })
        }
        _ => None,
    }
}

/// `deployment_id` charset guard — non-empty, `^[A-Za-z0-9._-]+$`.
pub fn validate_deployment_id(id: &str) -> Result<(), VaultError> {
    let ok = !id.is_empty()
        && id
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'));
    if ok {
        Ok(())
    } else {
        Err(VaultError::InvalidDeploymentId(id.to_string()))
    }
}

/// `vault.addr` must be a well-formed `https://` URL. A plaintext `http://` addr
/// would send the wrapping token / SecretID / Vault token in the clear (the CA cert
/// cannot protect a non-TLS connection), and a malformed URL would panic vaultrs's
/// builder — both rejected fail-closed here.
pub fn validate_vault_addr(addr: &str) -> Result<(), VaultError> {
    // `url` requires a non-empty host for the special `https` scheme — verified
    // empirically: "https://", "https://:8200", and "https://user@:9" all fail to parse
    // with "empty host". So once parse succeeds AND the scheme is https, a host is
    // guaranteed; a separate empty-host branch would be unreachable (and untestable).
    let url =
        url::Url::parse(addr).map_err(|e| VaultError::InvalidAddr(format!("{addr:?}: {e}")))?;
    if url.scheme() != "https" {
        return Err(VaultError::InvalidAddr(format!(
            "{addr:?}: scheme must be https (got {:?}) — plaintext would disclose credentials",
            url.scheme()
        )));
    }
    Ok(())
}

/// Load `vault.addr` + `deployment_id` (from `core` first, else `vault`) from the
/// config dir; validate both. Fail-closed on any absent/invalid field. Kept for
/// back-compat (the live-smoke tests + `PlaneClient::from_config_dir`); processes that
/// also read other sections load the config ONCE and call
/// [`vault_config_from_document`] on the shared document instead.
pub fn load_vault_config(dir: &Path) -> Result<VaultConfig, VaultError> {
    let doc = load_config(
        dir,
        &[SectionSpec {
            name: VAULT_SECTION.to_string(),
            required: true,
        }],
    )?;
    vault_config_from_document(&doc)
}

/// Parse + validate the Vault settings out of an ALREADY-LOADED [`Document`]. This is
/// the coherent-config seam (P1-A/P1-B): the daemon and CLI load their config once with
/// EVERY section they use registered, then hand the parsed document here — so a
/// realistic combined config (`core`+`vault`+`transport`+`audit`) is never re-loaded
/// under a `vault`-only registry that would reject `transport`/`audit` as
/// `UnknownSection`. A `vault` section absent from the document is `MissingKey("vault")`
/// (fail-closed) — the registry's required/optional flag is the caller's concern.
pub fn vault_config_from_document(doc: &Document) -> Result<VaultConfig, VaultError> {
    let vault = doc
        .section(VAULT_SECTION)
        .ok_or(VaultError::MissingKey("vault"))?;
    let addr = get_str(vault, "addr")
        .ok_or(VaultError::MissingKey("vault.addr"))?
        .to_string();
    validate_vault_addr(&addr)?;
    let deployment_id = doc
        .section("core")
        .and_then(|c| get_str(c, "deployment_id"))
        .or_else(|| get_str(vault, "deployment_id"))
        .ok_or(VaultError::MissingKey("deployment_id"))?
        .to_string();
    validate_deployment_id(&deployment_id)?;
    // Mount paths are OPTIONAL — absent keys fall back to the Terraform-default mounts.
    let approle_mount = get_str(vault, "approle_mount")
        .unwrap_or(DEFAULT_APPROLE_MOUNT)
        .to_string();
    let pki_int_mount = get_str(vault, "pki_int_mount")
        .unwrap_or(DEFAULT_PKI_INT_MOUNT)
        .to_string();
    Ok(VaultConfig {
        addr,
        deployment_id,
        approle_mount,
        pki_int_mount,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn get_str_map_str_hit_and_misses() {
        let m = Value::Map(vec![
            ("a".into(), Value::Str("x".into())),
            ("n".into(), Value::Int(1)),
        ]);
        assert_eq!(get_str(&m, "a"), Some("x"));
        assert_eq!(get_str(&m, "n"), None); // non-Str
        assert_eq!(get_str(&m, "z"), None); // absent
        assert_eq!(get_str(&Value::Int(1), "a"), None); // non-Map
    }

    #[test]
    fn validate_vault_addr_guard() {
        assert!(validate_vault_addr("https://v.example:8200").is_ok());
        // Plaintext http:// — would disclose the wrapping token / SecretID / Vault token.
        assert!(matches!(
            validate_vault_addr("http://v.example:8200"),
            Err(VaultError::InvalidAddr(_))
        ));
        // Any non-https scheme is refused.
        assert!(matches!(
            validate_vault_addr("ftp://v.example"),
            Err(VaultError::InvalidAddr(_))
        ));
        // Malformed URL fails closed (would otherwise panic vaultrs's builder).
        assert!(matches!(
            validate_vault_addr("not a url"),
            Err(VaultError::InvalidAddr(_))
        ));
        // Empty-host https fails at parse (url guarantees a host for the https scheme).
        assert!(matches!(
            validate_vault_addr("https://:8200"),
            Err(VaultError::InvalidAddr(_))
        ));
    }

    #[test]
    fn validate_deployment_id_guard() {
        assert!(validate_deployment_id("maknae-dev-01").is_ok());
        assert!(validate_deployment_id("*").is_err());
        assert!(validate_deployment_id("a/b").is_err());
        assert!(validate_deployment_id("a b").is_err());
        assert!(validate_deployment_id("").is_err());
    }

    // ---- load_vault_config fixture tests (tempdir) --------------------------

    use std::os::unix::fs::PermissionsExt;

    struct TempDir(std::path::PathBuf);
    impl TempDir {
        fn new(tag: &str) -> Self {
            let p = std::env::temp_dir().join(format!(
                "maknae-vault-cfg-{}-{}",
                std::process::id(),
                tag
            ));
            let _ = std::fs::remove_dir_all(&p);
            std::fs::create_dir_all(&p).unwrap();
            // maknae-config permission-gates the config dir (rejects group/other access).
            std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o700)).unwrap();
            TempDir(p)
        }
        fn write(&self, name: &str, body: &str) {
            let f = self.0.join(name);
            std::fs::write(&f, body).unwrap();
            // maknae-config rejects world/other-readable config files (must be 0o600).
            std::fs::set_permissions(&f, std::fs::Permissions::from_mode(0o600)).unwrap();
        }
    }
    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn loads_addr_and_deployment_id_from_core() {
        let d = TempDir::new("core");
        d.write(
            "maknae.yaml",
            "vault:\n  addr: https://v.example:8200\ncore:\n  deployment_id: dev-01\n",
        );
        let c = load_vault_config(&d.0).unwrap();
        assert_eq!(c.addr, "https://v.example:8200");
        assert_eq!(c.deployment_id, "dev-01");
        // Absent mount keys → Terraform-default mounts.
        assert_eq!(c.approle_mount, DEFAULT_APPROLE_MOUNT);
        assert_eq!(c.pki_int_mount, DEFAULT_PKI_INT_MOUNT);
    }

    #[test]
    fn mount_paths_honor_overrides() {
        let d = TempDir::new("mounts");
        d.write(
            "maknae.yaml",
            "vault:\n  addr: https://v.example:8200\n  approle_mount: alt-approle\n  \
             pki_int_mount: alt-pki-int\ncore:\n  deployment_id: dev-01\n",
        );
        let c = load_vault_config(&d.0).unwrap();
        assert_eq!(c.approle_mount, "alt-approle");
        assert_eq!(c.pki_int_mount, "alt-pki-int");
    }

    #[test]
    fn deployment_id_falls_back_to_vault_section() {
        let d = TempDir::new("fallback");
        d.write(
            "maknae.yaml",
            "vault:\n  addr: https://v.example:8200\n  deployment_id: dev-02\n",
        );
        assert_eq!(load_vault_config(&d.0).unwrap().deployment_id, "dev-02");
    }

    #[test]
    fn missing_addr_fails_closed() {
        let d = TempDir::new("noaddr");
        d.write("maknae.yaml", "vault:\n  deployment_id: dev-01\n");
        assert!(matches!(
            load_vault_config(&d.0),
            Err(VaultError::MissingKey("vault.addr"))
        ));
    }

    #[test]
    fn missing_deployment_id_fails_closed() {
        let d = TempDir::new("noid");
        d.write("maknae.yaml", "vault:\n  addr: https://v.example:8200\n");
        assert!(matches!(
            load_vault_config(&d.0),
            Err(VaultError::MissingKey("deployment_id"))
        ));
    }

    #[test]
    fn glob_deployment_id_rejected() {
        let d = TempDir::new("glob");
        d.write(
            "maknae.yaml",
            "vault:\n  addr: https://v.example:8200\n  deployment_id: \"*\"\n",
        );
        assert!(matches!(
            load_vault_config(&d.0),
            Err(VaultError::InvalidDeploymentId(_))
        ));
    }

    // ---- shared-document coherence (P1-A/P1-B) ------------------------------

    #[test]
    fn vault_parses_from_a_combined_document() {
        // The gap the old tests missed: a REALISTIC combined config (core + vault +
        // transport + audit) loaded ONCE with every section registered, then parsed
        // by-section. Under the old per-call `vault`-only registry this document could
        // not exist (transport/audit would be UnknownSection); the shared-document seam
        // is exactly what lets the daemon/CLI accept it.
        let d = TempDir::new("combined");
        d.write(
            "maknae.yaml",
            "core:\n  deployment_id: dev-01\n\
             vault:\n  addr: https://v.example:8200\n\
             transport:\n  socket_path: /run/maknae/maknaed.sock\n\
             audit:\n  path: /var/log/maknae/audit.jsonl\n",
        );
        let doc = load_config(
            &d.0,
            &[
                SectionSpec {
                    name: VAULT_SECTION.to_string(),
                    required: true,
                },
                SectionSpec {
                    name: "transport".to_string(),
                    required: false,
                },
                SectionSpec {
                    name: "audit".to_string(),
                    required: false,
                },
            ],
        )
        .expect("combined config loads with all sections registered");
        let c = vault_config_from_document(&doc).expect("vault parses from the shared document");
        assert_eq!(c.addr, "https://v.example:8200");
        assert_eq!(c.deployment_id, "dev-01");
    }

    #[test]
    fn absent_vault_section_in_document_is_missing_key() {
        // An OPTIONAL vault registration with no vault block present (the daemon's boot
        // registry marks vault optional): the document loads, but parsing fails closed
        // with MissingKey("vault") rather than silently proceeding without Vault.
        let d = TempDir::new("novault");
        d.write("maknae.yaml", "core:\n  deployment_id: dev-01\n");
        let doc = load_config(
            &d.0,
            &[SectionSpec {
                name: VAULT_SECTION.to_string(),
                required: false,
            }],
        )
        .expect("loads without the optional vault section");
        assert!(matches!(
            vault_config_from_document(&doc),
            Err(VaultError::MissingKey("vault"))
        ));
    }
}
