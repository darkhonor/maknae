//! The HTTP client every Vault client in this crate sends through (#240b).
//!
//! vaultrs 0.8.0 builds its own reqwest client from `VaultClientSettings` and
//! keeps reqwest's DEFAULTS where they matter most: redirects are followed
//! (ten of them), `https_only` is unset, and so is `no_proxy`. An HTTPS-to-HTTP
//! 307/308 from Vault or a reverse proxy in front of it — an HA node
//! advertising an `http://` `api_addr` is the ordinary case — would therefore
//! be followed, and a POST body resent: the AppRole login, SecretID included,
//! in plaintext. Found by codex review of #240b on the deputy's client; the
//! daemon's and enroll's clients had the same shape, so all three are built
//! here. `VaultClient.http` is a public field, and rustify rebuilds it from
//! any `reqwest::Client`, which is how the hardened one is installed.
//!
//! What this client states, rather than inherits: **no redirects** at all (a
//! redirect is a new destination), **HTTPS only** end to end, **no ambient
//! proxy**, the deployment's Vault CA as the ONLY trust anchor (a pin — the
//! system store is not consulted on this leg), the same hard timeout the three
//! constructors already applied, and no client identity.
//!
//! T3: constructs a network client. The two refusals it makes at construction
//! (a missing or malformed CA; a plaintext URL) are unit-tested; that a
//! redirect is not followed is stated by construction (`Policy::none()`),
//! since proving it needs a TLS server and reqwest exposes no getter.

use crate::VaultError;
use rustify::clients::reqwest::Client as HTTPClient;
use std::path::Path;
use std::time::Duration;
use vaultrs::client::VaultClient;

/// Build the hardened reqwest client. The CA file is read and parsed HERE, so
/// a missing or malformed anchor is a construction-time refusal that names the
/// path.
pub(crate) fn hardened_http_client(
    vault_ca: &Path,
    timeout: Duration,
) -> Result<reqwest::Client, VaultError> {
    let pem = crate::read_storage(vault_ca)?;
    let certs = reqwest::Certificate::from_pem_bundle(&pem).map_err(|e| VaultError::Io {
        path: vault_ca.to_path_buf(),
        source: std::io::Error::other(format!("Vault CA bundle did not parse: {e}")),
    })?;
    if certs.is_empty() {
        return Err(VaultError::Io {
            path: vault_ca.to_path_buf(),
            source: std::io::Error::other("no CERTIFICATE in the Vault CA bundle"),
        });
    }
    reqwest::Client::builder()
        .tls_backend_rustls()
        // PINNED: the deployment's Vault CA is the ONLY trust anchor for the
        // Vault leg. `maknae enroll` copies exactly that anchor for each plane,
        // so a certificate for the Vault hostname issued by any other CA —
        // public, corporate MITM, anything in the system store — is refused.
        // Round 7 of self-review: this was `tls_certs_merge` (system store plus
        // the CA) with a comment calling a pin "not expressible"; it is one
        // method call, and this is the deputy's most sensitive leg.
        .tls_certs_only(certs)
        .redirect(reqwest::redirect::Policy::none())
        .https_only(true)
        .no_proxy()
        .timeout(timeout)
        .build()
        .map_err(|e| VaultError::Auth(format!("hardened vault http client: {e}")))
}

/// Install the hardened client into a vaultrs `VaultClient` built from its
/// settings, keeping vaultrs's endpoint middleware (token, API version).
pub(crate) fn harden(
    client: &mut VaultClient,
    address: &str,
    vault_ca: &Path,
    timeout: Duration,
) -> Result<(), VaultError> {
    client.http = HTTPClient::new(address, hardened_http_client(vault_ca, timeout)?);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmp(name: &str) -> std::path::PathBuf {
        let p = std::env::temp_dir().join(format!("mv-http-{}-{name}", std::process::id()));
        let _ = std::fs::remove_dir_all(&p);
        std::fs::create_dir_all(&p).unwrap();
        p
    }

    fn self_signed_pem() -> String {
        let params = rcgen::CertificateParams::new(vec!["ca.test".to_string()]).unwrap();
        let key = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P384_SHA384).unwrap();
        params.self_signed(&key).unwrap().pem()
    }

    /// A missing or malformed CA is refused at construction, naming the path.
    #[test]
    fn a_missing_or_malformed_ca_is_refused_at_construction() {
        crate::install_default_crypto_provider();
        let d = tmp("ca");
        let absent = d.join("absent.crt");
        match hardened_http_client(&absent, std::time::Duration::from_secs(1)) {
            Err(e) => assert!(e.to_string().contains("absent.crt"), "{e}"),
            Ok(_) => panic!("an absent CA must refuse"),
        }
        let bad = d.join("bad.crt");
        std::fs::write(&bad, "not a pem").unwrap();
        assert!(hardened_http_client(&bad, std::time::Duration::from_secs(1)).is_err());
    }

    /// HTTPS only: a plaintext URL is refused by the CLIENT, before any
    /// connection — so a redirect chain that leaves HTTPS cannot be followed
    /// even in principle. (Redirects are also disabled outright; that half is
    /// asserted by construction — `Policy::none()` — since proving it needs a
    /// TLS server, and reqwest exposes no getter.)
    /// The four hardening calls, pinned at the source: this file is T3 and
    /// mutation-excluded, so nothing else holds `tls_certs_only` (once
    /// `tls_certs_merge`, the regression the comment above records),
    /// `redirect(none)`, `https_only(true)` and `no_proxy()` in place on the
    /// leg that carries the AppRole SecretID. Patterns composed at runtime so
    /// this test does not match itself.
    #[test]
    fn the_four_hardening_calls_are_present_and_the_merge_is_not() {
        let src = include_str!("http.rs");
        for call in [
            format!(".{}(certs)", "tls_certs_only"),
            format!(".{}(reqwest::redirect::Policy::none())", "redirect"),
            format!(".{}(true)", "https_only"),
            format!(".{}()", "no_proxy"),
        ] {
            assert!(src.contains(&call), "hardening call missing: {call}");
        }
        assert!(!src.contains(&format!(".{}(", "tls_certs_merge")));
    }

    #[test]
    fn a_plaintext_url_is_refused_by_the_client_itself() {
        crate::install_default_crypto_provider();
        let d = tmp("https");
        let ca = d.join("ca.crt");
        std::fs::write(&ca, self_signed_pem()).unwrap();
        let c = hardened_http_client(&ca, std::time::Duration::from_secs(1)).unwrap();
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let e = rt
            .block_on(c.get("http://127.0.0.1:1/v1/sys/health").send())
            .expect_err("http:// must be refused");
        // reqwest refuses an https_only violation as a BUILDER error before any
        // connection is attempted; a connect failure to the closed port would
        // be a different kind. The scheme text sits one level down the chain.
        assert!(
            e.is_builder() && !e.is_connect(),
            "not a scheme refusal: {e}"
        );
        let chain = {
            let mut src: Option<&dyn std::error::Error> = Some(&e);
            let mut out = String::new();
            while let Some(s) = src {
                out.push_str(&s.to_string().to_lowercase());
                src = s.source();
            }
            out
        };
        assert!(chain.contains("scheme"), "{chain}");
    }
}
