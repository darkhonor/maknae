//! CA-pin loader. The pinned trust **anchor is the ROOT** (`maknae-root-ca.crt`);
//! the intermediate is kept for chain-building (the peer presents it, and it also
//! rides the `pki/sign` response). Stage 2's rustls transport consumes these. The
//! root is config-pinned (a spoofed Vault cannot swap the trust anchor).
use crate::VaultError;
use std::path::Path;
use x509_parser::prelude::FromDer;

/// The pinned CA material (DER). Root is the trust anchor; intermediate builds chains.
pub struct CaBundle {
    pub root_der: Vec<u8>,
    pub int_der: Vec<u8>,
}

/// Parse the FIRST certificate from a PEM file into DER. Fail-closed on
/// missing/malformed/empty (via `x509-parser`; rustls-pemfile is unmaintained).
fn first_cert_der(path: &Path) -> Result<Vec<u8>, VaultError> {
    let bytes = crate::read_storage(
        path,
        maknae_io::TargetRequired {
            owner: None,
            mode_mask: None,
            nlink_exactly_one: false,
            regular_file: true,
        },
    )?;
    let (_, pem) = x509_parser::pem::parse_x509_pem(&bytes)
        .map_err(|_| VaultError::Pem("malformed certificate PEM"))?;
    if pem.label != "CERTIFICATE" {
        return Err(VaultError::Pem("not a CERTIFICATE PEM"));
    }
    // Validate the DER actually parses as an X.509 certificate NOW — a valid PEM
    // envelope around garbage/truncated bytes must fail at load, not later in the
    // transport (fail-closed, as the CA-pin loader advertises).
    x509_parser::certificate::X509Certificate::from_der(&pem.contents)
        .map_err(|_| VaultError::Pem("CA certificate DER is not a valid X.509 certificate"))?;
    Ok(pem.contents)
}

/// Load `<dir>/tls/maknae-root-ca.crt` + `<dir>/tls/maknae-int-ca.crt`.
pub fn load_ca_pin(dir: &Path) -> Result<CaBundle, VaultError> {
    let tls = dir.join("tls");
    Ok(CaBundle {
        root_der: first_cert_der(&tls.join("maknae-root-ca.crt"))?,
        int_der: first_cert_der(&tls.join("maknae-int-ca.crt"))?,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    struct TempDir(std::path::PathBuf);
    impl TempDir {
        fn new(tag: &str) -> Self {
            let p = std::env::temp_dir().join(format!(
                "maknae-vault-ca-{}-{}",
                std::process::id(),
                tag
            ));
            let _ = std::fs::remove_dir_all(&p);
            std::fs::create_dir_all(p.join("tls")).unwrap();
            TempDir(p)
        }
    }
    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    fn self_signed_pem() -> String {
        let params = rcgen::CertificateParams::new(vec!["ca.test".to_string()]).unwrap();
        let key = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P384_SHA384).unwrap();
        params.self_signed(&key).unwrap().pem()
    }

    #[test]
    fn loads_root_and_int() {
        let d = TempDir::new("ok");
        std::fs::write(d.0.join("tls/maknae-root-ca.crt"), self_signed_pem()).unwrap();
        std::fs::write(d.0.join("tls/maknae-int-ca.crt"), self_signed_pem()).unwrap();
        let b = load_ca_pin(&d.0).unwrap();
        assert!(!b.root_der.is_empty());
        assert!(!b.int_der.is_empty());
    }

    #[test]
    fn missing_root_fails_closed() {
        let d = TempDir::new("noroot");
        std::fs::write(d.0.join("tls/maknae-int-ca.crt"), self_signed_pem()).unwrap();
        assert!(matches!(load_ca_pin(&d.0), Err(VaultError::Io { .. })));
    }

    #[test]
    fn malformed_pem_fails_closed() {
        let d = TempDir::new("bad");
        std::fs::write(d.0.join("tls/maknae-root-ca.crt"), "not a pem").unwrap();
        std::fs::write(d.0.join("tls/maknae-int-ca.crt"), self_signed_pem()).unwrap();
        assert!(matches!(load_ca_pin(&d.0), Err(VaultError::Pem(_))));
    }

    #[test]
    fn valid_envelope_garbage_der_fails_at_load() {
        // A valid CERTIFICATE PEM envelope whose base64 decodes to non-cert bytes
        // must fail NOW (not later in the transport).
        let d = TempDir::new("garbageder");
        std::fs::write(
            d.0.join("tls/maknae-root-ca.crt"),
            "-----BEGIN CERTIFICATE-----\nAAAAAAAA\n-----END CERTIFICATE-----\n",
        )
        .unwrap();
        std::fs::write(d.0.join("tls/maknae-int-ca.crt"), self_signed_pem()).unwrap();
        assert!(matches!(load_ca_pin(&d.0), Err(VaultError::Pem(_))));
    }
}
