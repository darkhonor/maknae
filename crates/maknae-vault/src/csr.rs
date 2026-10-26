//! Pure CSR-shape predicates (T1, 0-missed): assert an empty subject, exactly one
//! URI SAN, and the configured `PlaneKey` by algorithm identifier (#573). `generate_plane_csr` (the rcgen keygen I/O) lives in
//! `csr_gen.rs` (T3) and self-checks its output with these predicates.
use crate::PlaneKey;
use x509_parser::certification_request::X509CertificationRequest;
use x509_parser::extensions::{GeneralName, ParsedExtension};
use x509_parser::prelude::FromDer;

const ID_ML_DSA_87: &str = "2.16.840.1.101.3.4.3.19";
const ID_EC_PUBLIC_KEY: &str = "1.2.840.10045.2.1";
const SECP384R1: &str = "1.3.132.0.34";
const SECP521R1: &str = "1.3.132.0.35";

fn parse_csr(pem: &str) -> Option<Vec<u8>> {
    let (_, pem) = x509_parser::pem::parse_x509_pem(pem.as_bytes()).ok()?;
    Some(pem.contents)
}

/// True iff the CSR's subject Distinguished Name is empty (no RDNs — no CN).
pub fn csr_has_empty_subject(pem: &str) -> bool {
    let Some(der) = parse_csr(pem) else {
        return false;
    };
    let Ok((_, csr)) = X509CertificationRequest::from_der(&der) else {
        return false;
    };
    csr.certification_request_info.subject.iter().count() == 0
}

/// True iff the CSR carries EXACTLY one SAN of ANY type, and that sole SAN is a URI
/// equal to `want`. A rogue DNS/IP/email SAN alongside the plane URI is rejected — the
/// same URI-SAN-ONLY shape the returned-leaf verifier enforces (defense in depth: do
/// NOT rely on the Vault role config to strip a second identity).
pub fn csr_single_uri_san(pem: &str, want: &str) -> bool {
    let Some(der) = parse_csr(pem) else {
        return false;
    };
    let Ok((_, csr)) = X509CertificationRequest::from_der(&der) else {
        return false;
    };
    let mut all_sans = 0usize;
    let mut uris: Vec<String> = Vec::new();
    if let Some(exts) = csr.requested_extensions() {
        for ext in exts {
            if let ParsedExtension::SubjectAlternativeName(san) = ext {
                for gn in &san.general_names {
                    all_sans += 1;
                    if let GeneralName::URI(u) = gn {
                        uris.push(u.to_string());
                    }
                }
            }
        }
    }
    all_sans == 1 && uris.len() == 1 && uris[0] == want
}

/// The SubjectPublicKeyInfo algorithm parameters, as far as the plane decision reads them.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum SpkiParams {
    Absent,
    NamedCurve(String),
    Other,
}

/// PURE decision: the parsed SPKI is exactly `key`'s algorithm, parameters and key length.
pub(crate) fn spki_is(alg: &str, params: &SpkiParams, key_len: usize, key: PlaneKey) -> bool {
    match key {
        PlaneKey::MlDsa87 => {
            alg == ID_ML_DSA_87 && *params == SpkiParams::Absent && key_len == 2592
        }
        PlaneKey::P384 => {
            alg == ID_EC_PUBLIC_KEY
                && *params == SpkiParams::NamedCurve(SECP384R1.to_string())
                && key_len == 97
        }
        PlaneKey::P521 => {
            alg == ID_EC_PUBLIC_KEY
                && *params == SpkiParams::NamedCurve(SECP521R1.to_string())
                && key_len == 133
        }
    }
}

/// True iff the CSR's public key is exactly `key`'s algorithm (see [`spki_is`]).
pub fn csr_key_is(pem: &str, key: PlaneKey) -> bool {
    let Some(der) = parse_csr(pem) else {
        return false;
    };
    let Ok((_, csr)) = X509CertificationRequest::from_der(&der) else {
        return false;
    };
    let spki = &csr.certification_request_info.subject_pki;
    let params = match &spki.algorithm.parameters {
        None => SpkiParams::Absent,
        Some(p) => match p.as_oid() {
            Ok(oid) => SpkiParams::NamedCurve(oid.to_id_string()),
            Err(_) => SpkiParams::Other,
        },
    };
    spki_is(
        &spki.algorithm.algorithm.to_id_string(),
        &params,
        spki.subject_public_key.data.len(),
        key,
    )
}

/// True iff the CSR matches the required plane-cert shape: empty subject, EXACTLY one
/// URI SAN == `want_uri_san`, and `key`'s algorithm. This is the fail-closed self-check that
/// `csr_gen::generate_plane_csr` applies to its own output. The AND-decision lives
/// here (T1, mutation-covered — the negative tests prove it REJECTS a bad shape) so
/// that `csr_gen.rs` is left with only external-error plumbing (T3).
pub fn csr_matches_plane_shape(pem: &str, want_uri_san: &str, key: PlaneKey) -> bool {
    csr_has_empty_subject(pem) && csr_single_uri_san(pem, want_uri_san) && csr_key_is(pem, key)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a CSR with a configurable CN, URI SANs, and key algorithm.
    fn make_csr(
        cn: Option<&str>,
        uris: &[&str],
        alg: &'static rcgen::SignatureAlgorithm,
    ) -> String {
        let mut params = rcgen::CertificateParams::new(vec![]).unwrap();
        let mut dn = rcgen::DistinguishedName::new();
        if let Some(cn) = cn {
            dn.push(rcgen::DnType::CommonName, cn);
        }
        params.distinguished_name = dn;
        params.subject_alt_names = uris
            .iter()
            .map(|u| rcgen::SanType::URI((*u).try_into().unwrap()))
            .collect();
        let key = rcgen::KeyPair::generate_for(alg).unwrap();
        params.serialize_request(&key).unwrap().pem().unwrap()
    }

    #[test]
    fn empty_subject_true_and_false() {
        let empty = make_csr(
            None,
            &["maknae://d/plane/kernel"],
            &rcgen::PKCS_ECDSA_P384_SHA384,
        );
        assert!(csr_has_empty_subject(&empty));
        let with_cn = make_csr(
            Some("someone"),
            &["maknae://d/plane/kernel"],
            &rcgen::PKCS_ECDSA_P384_SHA384,
        );
        assert!(!csr_has_empty_subject(&with_cn));
    }

    #[test]
    fn single_uri_san_variants() {
        let one = make_csr(
            None,
            &["maknae://d/plane/kernel"],
            &rcgen::PKCS_ECDSA_P384_SHA384,
        );
        assert!(csr_single_uri_san(&one, "maknae://d/plane/kernel"));
        assert!(!csr_single_uri_san(&one, "maknae://d/plane/cli")); // wrong value
        let none = make_csr(None, &[], &rcgen::PKCS_ECDSA_P384_SHA384);
        assert!(!csr_single_uri_san(&none, "maknae://d/plane/kernel")); // zero SANs
        let two = make_csr(
            None,
            &["maknae://d/plane/kernel", "maknae://d/plane/cli"],
            &rcgen::PKCS_ECDSA_P384_SHA384,
        );
        assert!(!csr_single_uri_san(&two, "maknae://d/plane/kernel")); // two SANs
    }

    /// Build a CSR with an empty subject and an arbitrary mix of SAN types (P-384).
    fn make_csr_sans(sans: Vec<rcgen::SanType>) -> String {
        let mut params = rcgen::CertificateParams::new(vec![]).unwrap();
        params.distinguished_name = rcgen::DistinguishedName::new();
        params.subject_alt_names = sans;
        let key = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P384_SHA384).unwrap();
        params.serialize_request(&key).unwrap().pem().unwrap()
    }

    #[test]
    fn rejects_plane_uri_plus_rogue_dns() {
        // The expected plane URI PLUS a rogue DNS SAN — must be rejected as URI-only,
        // exactly as the returned-leaf verifier does (codex r6 P2).
        let want = "maknae://d/plane/kernel";
        let mixed = make_csr_sans(vec![
            rcgen::SanType::URI(want.try_into().unwrap()),
            rcgen::SanType::DnsName("evil.example".try_into().unwrap()),
        ]);
        assert!(!csr_single_uri_san(&mixed, want)); // second (DNS) SAN → reject
        assert!(!csr_matches_plane_shape(&mixed, want, PlaneKey::P384));
    }

    fn csr_with_key(key: &rcgen::KeyPair) -> String {
        let mut params = rcgen::CertificateParams::new(vec![]).unwrap();
        params.distinguished_name = rcgen::DistinguishedName::new();
        params.subject_alt_names = vec![rcgen::SanType::URI(
            "maknae://d/plane/kernel".try_into().unwrap(),
        )];
        params.serialize_request(key).unwrap().pem().unwrap()
    }

    fn csr_for(alg: &'static rcgen::SignatureAlgorithm) -> String {
        csr_with_key(&rcgen::KeyPair::generate_for(alg).unwrap())
    }

    #[test]
    fn each_plane_key_accepts_only_its_own_algorithm() {
        let cases = [
            (PlaneKey::MlDsa87, csr_for(&rcgen::PKCS_ML_DSA_87)),
            (PlaneKey::P384, csr_for(&rcgen::PKCS_ECDSA_P384_SHA384)),
            (PlaneKey::P521, csr_for(&rcgen::PKCS_ECDSA_P521_SHA512)),
        ];
        for (want, pem) in &cases {
            for k in PlaneKey::ALL {
                assert_eq!(csr_key_is(pem, k), k == *want, "{want:?} CSR against {k:?}");
            }
        }
    }

    #[test]
    fn every_other_algorithm_is_refused() {
        let rsa =
            rcgen::KeyPair::generate_rsa_for(&rcgen::PKCS_RSA_SHA256, rcgen::RsaKeySize::_3072)
                .unwrap();
        let others = [
            csr_for(&rcgen::PKCS_ML_DSA_44),
            csr_for(&rcgen::PKCS_ML_DSA_65),
            csr_for(&rcgen::PKCS_ECDSA_P256_SHA256),
            csr_for(&rcgen::PKCS_ED25519),
            csr_with_key(&rsa),
        ];
        for pem in &others {
            for k in PlaneKey::ALL {
                assert!(!csr_key_is(pem, k), "{k:?} accepted {pem}");
            }
        }
    }

    fn curve(oid: &str) -> SpkiParams {
        SpkiParams::NamedCurve(oid.to_string())
    }

    #[test]
    fn spki_is_requires_every_conjunct() {
        assert!(spki_is(
            ID_ML_DSA_87,
            &SpkiParams::Absent,
            2592,
            PlaneKey::MlDsa87
        ));
        assert!(spki_is(
            ID_EC_PUBLIC_KEY,
            &curve(SECP384R1),
            97,
            PlaneKey::P384
        ));
        assert!(spki_is(
            ID_EC_PUBLIC_KEY,
            &curve(SECP521R1),
            133,
            PlaneKey::P521
        ));

        assert!(!spki_is(
            ID_EC_PUBLIC_KEY,
            &SpkiParams::Absent,
            2592,
            PlaneKey::MlDsa87
        ));
        assert!(!spki_is(
            ID_ML_DSA_87,
            &SpkiParams::Other,
            2592,
            PlaneKey::MlDsa87
        ));
        assert!(!spki_is(
            ID_ML_DSA_87,
            &curve(SECP384R1),
            2592,
            PlaneKey::MlDsa87
        ));
        assert!(!spki_is(
            ID_ML_DSA_87,
            &SpkiParams::Absent,
            97,
            PlaneKey::MlDsa87
        ));

        assert!(!spki_is(
            ID_ML_DSA_87,
            &curve(SECP384R1),
            97,
            PlaneKey::P384
        ));
        assert!(!spki_is(
            ID_EC_PUBLIC_KEY,
            &curve(SECP521R1),
            97,
            PlaneKey::P384
        ));
        assert!(!spki_is(
            ID_EC_PUBLIC_KEY,
            &SpkiParams::Absent,
            97,
            PlaneKey::P384
        ));
        assert!(!spki_is(
            ID_EC_PUBLIC_KEY,
            &SpkiParams::Other,
            97,
            PlaneKey::P384
        ));
        assert!(!spki_is(
            ID_EC_PUBLIC_KEY,
            &curve(SECP384R1),
            133,
            PlaneKey::P384
        ));

        assert!(!spki_is(
            ID_ML_DSA_87,
            &curve(SECP521R1),
            133,
            PlaneKey::P521
        ));
        assert!(!spki_is(
            ID_EC_PUBLIC_KEY,
            &curve(SECP384R1),
            133,
            PlaneKey::P521
        ));
        assert!(!spki_is(
            ID_EC_PUBLIC_KEY,
            &SpkiParams::Other,
            133,
            PlaneKey::P521
        ));
        assert!(!spki_is(
            ID_EC_PUBLIC_KEY,
            &curve(SECP521R1),
            97,
            PlaneKey::P521
        ));
    }

    #[test]
    fn malformed_pem_all_false() {
        assert!(!csr_has_empty_subject("garbage"));
        assert!(!csr_single_uri_san("garbage", "x"));
        assert!(!csr_key_is("garbage", PlaneKey::P384));
    }

    #[test]
    fn valid_pem_envelope_garbage_der_all_false() {
        // A well-formed PEM envelope whose DER is NOT a valid CSR: parse_csr succeeds
        // (base64 decodes), then X509CertificationRequest::from_der fails — every
        // predicate must return false (covers the from_der Err arm in each).
        let g =
            "-----BEGIN CERTIFICATE REQUEST-----\nAQIDBA==\n-----END CERTIFICATE REQUEST-----\n";
        assert!(!csr_has_empty_subject(g));
        assert!(!csr_single_uri_san(g, "maknae://d/plane/kernel"));
        assert!(!csr_key_is(g, PlaneKey::MlDsa87));
    }

    #[test]
    fn matches_plane_shape_accepts_and_rejects_each_failure() {
        let want = "maknae://d/plane/kernel";
        // Good shape: empty subject, one URI-SAN == want, P-384.
        let good = make_csr(None, &[want], &rcgen::PKCS_ECDSA_P384_SHA384);
        assert!(csr_matches_plane_shape(&good, want, PlaneKey::P384));
        assert!(!csr_matches_plane_shape(&good, want, PlaneKey::MlDsa87));
        // Each SINGLE failing dimension must flip it to false (this also kills the
        // `&&`->`||` mutants — with only one predicate false, `||` would still be true).
        let cn = make_csr(Some("x"), &[want], &rcgen::PKCS_ECDSA_P384_SHA384); // subject not empty
        assert!(!csr_matches_plane_shape(&cn, want, PlaneKey::P384));
        let wrong_san = make_csr(
            None,
            &["maknae://d/plane/cli"],
            &rcgen::PKCS_ECDSA_P384_SHA384,
        );
        assert!(!csr_matches_plane_shape(&wrong_san, want, PlaneKey::P384)); // SAN != want
        let p256 = make_csr(None, &[want], &rcgen::PKCS_ECDSA_P256_SHA256); // not P-384
        assert!(!csr_matches_plane_shape(&p256, want, PlaneKey::P384));
    }
}
