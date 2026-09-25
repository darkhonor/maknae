//! The Vault-backed [`KeySource`](maknae_deputy::keys::KeySource) — the I/O half.
//!
//! Split from `keys.rs` for the reason this tree splits `kv_io`/`kv` and
//! `secret_io`/`secret_source`: the CACHE is a decision worth mutation-testing
//! and this is a network read no unit test should stand in for. This project
//! has no Vault stub and deliberately uses none.

use maknae_deputy::keys::KeySource;
use zeroize::Zeroizing;

/// Reads through `maknae-vault`'s deputy client, which owns the login, the KV
/// read and the revoke (#240b: login per read, no standing token). Composes the
/// KV v2 API path HERE because addressing is the store's business: `data/` is
/// synthesized rather than written in configuration, which also means a
/// configured path can never name `metadata/`, the parallel tree a `list`
/// would enumerate.
pub struct VaultKeys {
    pub vault: maknae_vault::EgressVault,
}

impl KeySource for VaultKeys {
    /// No `block_on` and no runtime handle. An earlier version held a
    /// `runtime::Handle` and blocked on it — which PANICS, because the deputy
    /// already calls `fulfil` inside that runtime and Tokio refuses a nested
    /// block. The credential error this design promises could never have been
    /// produced; the process would have aborted instead (#296).
    async fn read(
        &self,
        mount: &str,
        path: &str,
        field: &str,
    ) -> Result<Zeroizing<String>, String> {
        self.vault
            .read_kv_field(&format!("{mount}/data/{path}"), field)
            .await
            .map_err(|e| e.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use maknae_deputy::keys::KeyCache;

    /// A throwaway self-signed CA, generated once with
    /// `openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-384 -nodes
    /// -subj /CN=ca.test -days 3650`. Its key was never kept: the test needs
    /// a parseable anchor, not a trust relationship.
    const TEST_CA_PEM: &str = "-----BEGIN CERTIFICATE-----
MIIBtTCCATygAwIBAgIUULDH6JmXYLo3iF5hxI4/L1j2+DYwCgYIKoZIzj0EAwIw
EjEQMA4GA1UEAwwHY2EudGVzdDAeFw0yNjA5MTQxMjE0NDhaFw0zNjA5MTExMjE0
NDhaMBIxEDAOBgNVBAMMB2NhLnRlc3QwdjAQBgcqhkjOPQIBBgUrgQQAIgNiAASZ
iOE81dyIcpd91xRH64m5BS55i8UtJCCmgFfbBtOSJ8AIl49LXXJ/n0oMJYMYTc4M
yYiZU829p8gs804BacFPR8iVw3Y1AXZMTP6aeY5OY+W0iNAfXb8kB2fYUBHaOhmj
UzBRMB0GA1UdDgQWBBRPCpNpo3yKdFLAJ9mDC4Q6Na1uwDAfBgNVHSMEGDAWgBRP
CpNpo3yKdFLAJ9mDC4Q6Na1uwDAPBgNVHRMBAf8EBTADAQH/MAoGCCqGSM49BAMC
A2cAMGQCMBIUOA0bc98jJmqncakndRWUnoFWQDYhkKiSKiDqvYS/uQFSz8CVlrDH
GsTOHSQ/TQIwTI0QPmUvWSWEtxmnn9qj+NCmu0XZXYB4fG/FqUk/ILFGmJu7DV5u
ampbv97Rcx9j
-----END CERTIFICATE-----
";

    /// THE composition the panic lived in, exercised for real.
    ///
    /// Reviewed finding (#296): `VaultKeys::read` was synchronous and bridged
    /// with `Handle::block_on`, while the deputy calls `fulfil` inside that same
    /// runtime — Tokio aborts on a nested block, so the named credential error
    /// could never be produced. Every test used a synchronous FAKE source, so
    /// nothing touched the code that panicked.
    ///
    /// This drives the real `VaultKeys` — on the real `EgressVault`, the one
    /// `main` constructs — through the real `KeyCache`, from inside a runtime,
    /// exactly as `main` does. A Vault at a dead address gives a transport
    /// failure — the point is that it RETURNS one rather than aborting.
    #[test]
    fn the_real_vault_source_returns_an_error_from_inside_a_runtime() {
        maknae_vault::install_default_crypto_provider();
        let d = tempfile::tempdir().unwrap();
        let ca = d.path().join(maknae_vault::EGRESS_VAULT_CA_FILE);
        std::fs::write(&ca, TEST_CA_PEM).unwrap();
        let vault = maknae_vault::EgressVault::new(
            "https://127.0.0.1:1",
            &ca,
            maknae_vault::AppRoleAuth {
                role_id: "r".into(),
                secret_id: Zeroizing::new("s".into()),
                approle_mount: maknae_vault::DEFAULT_APPROLE_MOUNT.into(),
            },
        )
        .expect("a parseable anchor and an https address construct");
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();

        let mut keys = KeyCache::new(VaultKeys { vault });

        // INSIDE the runtime — the exact shape that used to abort.
        let out = rt.block_on(keys.get("maknae-kv", "maknae/providers/openai", "api-key"));
        let e = out.expect_err("a dead Vault address must produce an error");
        assert!(!e.is_empty(), "the error must say something");
    }
}
