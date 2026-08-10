//! The URI-SAN plane-identity verifier — the register's single consciously-owned
//! code (ADR-0016 T1, 0 missed mutants). rustls/webpki validates the CHAIN; this
//! asserts the peer leaf carries EXACTLY the expected plane URI-SAN and nothing
//! else. SAN extraction via `x509-parser` (webpki is verification-only and does not
//! enumerate SANs — verified).
use crate::Plane;
use x509_parser::extensions::{GeneralName, ParsedExtension};
use x509_parser::prelude::*;

/// Why a peer leaf's plane identity was rejected.
#[derive(Debug, PartialEq, Eq)]
pub enum VerifyError {
    /// The leaf carried no URI SAN at all.
    NoUriSan,
    /// The leaf's URI SAN did not equal the expected plane SAN.
    WrongSan { found: Vec<String> },
    /// The leaf carried more than one URI SAN.
    ExtraSans,
    /// The DER could not be parsed.
    ParseError,
}

/// Assert the peer leaf carries EXACTLY `maknae://<deployment_id>/plane/<expect>`
/// and nothing else. Fail-closed on any deviation.
pub fn verify_plane_uri_san(
    peer_cert_der: &[u8],
    expect: Plane,
    deployment_id: &str,
) -> Result<(), VerifyError> {
    let (_, cert) = X509Certificate::from_der(peer_cert_der).map_err(|_| VerifyError::ParseError)?;
    let mut uris: Vec<String> = Vec::new();
    for ext in cert.extensions() {
        if let ParsedExtension::SubjectAlternativeName(san) = ext.parsed_extension() {
            for gn in &san.general_names {
                if let GeneralName::URI(u) = gn {
                    uris.push(u.to_string());
                }
            }
        }
    }
    if uris.is_empty() {
        return Err(VerifyError::NoUriSan);
    }
    if uris.len() > 1 {
        return Err(VerifyError::ExtraSans);
    }
    let want = expect.uri_san(deployment_id);
    if uris[0] != want {
        return Err(VerifyError::WrongSan { found: uris });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a self-signed leaf carrying exactly the given URI SANs (DER).
    fn leaf_with_uri_sans(uris: &[&str]) -> Vec<u8> {
        let mut params = rcgen::CertificateParams::new(vec![]).unwrap();
        params.distinguished_name = rcgen::DistinguishedName::new();
        params.subject_alt_names = uris
            .iter()
            .map(|u| rcgen::SanType::URI((*u).try_into().unwrap()))
            .collect();
        let key = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P384_SHA384).unwrap();
        params.self_signed(&key).unwrap().der().as_ref().to_vec()
    }

    #[test]
    fn accepts_exact_plane_san() {
        let der = leaf_with_uri_sans(&["maknae://dev-01/plane/kernel"]);
        assert!(verify_plane_uri_san(&der, Plane::Kernel, "dev-01").is_ok());
    }

    #[test]
    fn rejects_wrong_plane() {
        let der = leaf_with_uri_sans(&["maknae://dev-01/plane/cli"]);
        assert!(matches!(
            verify_plane_uri_san(&der, Plane::Kernel, "dev-01"),
            Err(VerifyError::WrongSan { .. })
        ));
    }

    #[test]
    fn rejects_wrong_deployment_id() {
        let der = leaf_with_uri_sans(&["maknae://other/plane/kernel"]);
        assert!(matches!(
            verify_plane_uri_san(&der, Plane::Kernel, "dev-01"),
            Err(VerifyError::WrongSan { .. })
        ));
    }

    #[test]
    fn rejects_absent_uri_san() {
        // A DNS SAN, no URI SAN.
        let mut params = rcgen::CertificateParams::new(vec![]).unwrap();
        params.subject_alt_names =
            vec![rcgen::SanType::DnsName("example.com".try_into().unwrap())];
        let key = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P384_SHA384).unwrap();
        let der = params.self_signed(&key).unwrap().der().as_ref().to_vec();
        assert_eq!(
            verify_plane_uri_san(&der, Plane::Kernel, "dev-01"),
            Err(VerifyError::NoUriSan)
        );
    }

    #[test]
    fn rejects_extra_sans() {
        let der = leaf_with_uri_sans(&[
            "maknae://dev-01/plane/kernel",
            "maknae://dev-01/plane/cli",
        ]);
        assert_eq!(
            verify_plane_uri_san(&der, Plane::Kernel, "dev-01"),
            Err(VerifyError::ExtraSans)
        );
    }

    #[test]
    fn rejects_unparseable() {
        assert_eq!(
            verify_plane_uri_san(b"not a cert", Plane::Kernel, "dev-01"),
            Err(VerifyError::ParseError)
        );
    }
}
