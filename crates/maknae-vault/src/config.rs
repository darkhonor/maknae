//! Vault client configuration, loaded via `maknae-config`. `maknae_config::Value`
//! is a bare enum (no accessors), so we pattern-match. `deployment_id` is
//! charset-guarded to match the PKI role's own guard (a glob/slash would corrupt
//! the plane URI-SAN or be rejected by Vault). All pure/fixture-testable (T1).
use crate::VaultError;
use maknae_config::{load_config, SectionSpec, Value};
use std::path::Path;

/// The non-sensitive Vault settings.
pub struct VaultConfig {
    pub addr: String,
    pub deployment_id: String,
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
    let url =
        url::Url::parse(addr).map_err(|e| VaultError::InvalidAddr(format!("{addr:?}: {e}")))?;
    if url.scheme() != "https" {
        return Err(VaultError::InvalidAddr(format!(
            "{addr:?}: scheme must be https (got {:?}) — plaintext would disclose credentials",
            url.scheme()
        )));
    }
    if url.host_str().map(|h| h.is_empty()).unwrap_or(true) {
        return Err(VaultError::InvalidAddr(format!("{addr:?}: no host")));
    }
    Ok(())
}

/// Load `vault.addr` + `deployment_id` (from `core` first, else `vault`) from the
/// config dir; validate both. Fail-closed on any absent/invalid field.
pub fn load_vault_config(dir: &Path) -> Result<VaultConfig, VaultError> {
    let doc = load_config(
        dir,
        &[SectionSpec {
            name: "vault".to_string(),
            required: true,
        }],
    )?;
    let vault = doc
        .section("vault")
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
    Ok(VaultConfig {
        addr,
        deployment_id,
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
}
