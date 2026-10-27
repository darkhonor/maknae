//! The plane identity's signature algorithms (#573): each one's rcgen algorithm, TLS
//! signature scheme and SubjectPublicKeyInfo identifiers.
use rustls::SignatureScheme;

const ID_ML_DSA_87: &str = "2.16.840.1.101.3.4.3.19";
const ID_EC_PUBLIC_KEY: &str = "1.2.840.10045.2.1";
const SECP384R1: &str = "1.3.132.0.34";
const SECP521R1: &str = "1.3.132.0.35";

/// The plane identity's key algorithm: what a plane generates, and what
/// `deploy/vault-pki`'s `plane_key_algorithm` must issue.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PlaneKey {
    MlDsa87,
    P384,
    P521,
}

/// The SubjectPublicKeyInfo algorithm parameters, as far as [`PlaneKey::matches_spki`] reads them.
#[derive(Debug, PartialEq, Eq)]
pub enum SpkiParams {
    Absent,
    NamedCurve(String),
    Other,
}

impl PlaneKey {
    pub const ALL: [PlaneKey; 3] = [PlaneKey::MlDsa87, PlaneKey::P384, PlaneKey::P521];

    pub fn as_str(self) -> &'static str {
        match self {
            PlaneKey::MlDsa87 => "ml-dsa-87",
            PlaneKey::P384 => "p384",
            PlaneKey::P521 => "p521",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        PlaneKey::ALL.into_iter().find(|k| k.as_str() == s)
    }

    pub fn rcgen_algorithm(self) -> &'static rcgen::SignatureAlgorithm {
        match self {
            PlaneKey::MlDsa87 => &rcgen::PKCS_ML_DSA_87,
            PlaneKey::P384 => &rcgen::PKCS_ECDSA_P384_SHA384,
            PlaneKey::P521 => &rcgen::PKCS_ECDSA_P521_SHA512,
        }
    }

    pub fn signature_scheme(self) -> SignatureScheme {
        match self {
            PlaneKey::MlDsa87 => SignatureScheme::ML_DSA_87,
            PlaneKey::P384 => SignatureScheme::ECDSA_NISTP384_SHA384,
            PlaneKey::P521 => SignatureScheme::ECDSA_NISTP521_SHA512,
        }
    }

    /// PURE decision: a parsed SPKI is exactly this algorithm, its parameters and key length.
    pub fn matches_spki(
        self,
        alg: &str,
        params: &SpkiParams,
        key_len: usize,
        unused_bits: u8,
    ) -> bool {
        unused_bits == 0
            && match self {
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
}

#[cfg(test)]
mod tests {
    use super::*;
    use rustls::pki_types::PrivateKeyDer;

    #[test]
    fn names_round_trip_and_nothing_else_parses() {
        assert_eq!(
            PlaneKey::ALL.map(PlaneKey::as_str),
            ["ml-dsa-87", "p384", "p521"]
        );
        for k in PlaneKey::ALL {
            assert_eq!(PlaneKey::parse(k.as_str()), Some(k));
        }
        for s in ["ML-DSA-87", "p256", "ml-dsa-65", ""] {
            assert_eq!(PlaneKey::parse(s), None, "{s}");
        }
    }

    #[test]
    fn each_algorithm_maps_to_its_own_scheme_and_spki() {
        let table = [
            (
                PlaneKey::MlDsa87,
                SignatureScheme::ML_DSA_87,
                ID_ML_DSA_87,
                SpkiParams::Absent,
            ),
            (
                PlaneKey::P384,
                SignatureScheme::ECDSA_NISTP384_SHA384,
                ID_EC_PUBLIC_KEY,
                curve(SECP384R1),
            ),
            (
                PlaneKey::P521,
                SignatureScheme::ECDSA_NISTP521_SHA512,
                ID_EC_PUBLIC_KEY,
                curve(SECP521R1),
            ),
        ];
        for (k, scheme, alg, params) in &table {
            assert_eq!(k.signature_scheme(), *scheme);
            let key = rcgen::KeyPair::generate_for(k.rcgen_algorithm()).unwrap();
            let len = key.public_key_raw().len();
            for other in PlaneKey::ALL {
                assert_eq!(
                    other.matches_spki(alg, params, len, 0),
                    other == *k,
                    "{k:?} key against {other:?}"
                );
            }
        }
    }

    #[test]
    fn each_algorithm_generates_a_key_the_provider_signs_with_only_its_scheme() {
        let schemes = PlaneKey::ALL.map(PlaneKey::signature_scheme);
        for k in PlaneKey::ALL {
            let key = rcgen::KeyPair::generate_for(k.rcgen_algorithm()).unwrap();
            let signing =
                crate::tls::load_private_key(PrivateKeyDer::Pkcs8(key.serialize_der().into()))
                    .unwrap();
            for scheme in schemes {
                let chosen = signing.choose_scheme(&[scheme]).map(|s| s.scheme());
                if scheme == k.signature_scheme() {
                    assert_eq!(chosen, Some(scheme), "{k:?}");
                } else {
                    assert_eq!(chosen, None, "{k:?} offered {scheme:?}");
                }
            }
        }
    }

    fn curve(oid: &str) -> SpkiParams {
        SpkiParams::NamedCurve(oid.to_string())
    }

    #[test]
    fn matches_spki_requires_every_conjunct() {
        let good = [
            (PlaneKey::MlDsa87, ID_ML_DSA_87, SpkiParams::Absent, 2592),
            (PlaneKey::P384, ID_EC_PUBLIC_KEY, curve(SECP384R1), 97),
            (PlaneKey::P521, ID_EC_PUBLIC_KEY, curve(SECP521R1), 133),
        ];
        for (k, alg, params, len) in &good {
            assert!(k.matches_spki(alg, params, *len, 0), "{k:?}");
            assert!(
                !k.matches_spki(alg, params, *len, 1),
                "{k:?} with unused bits"
            );
        }

        let bad = [
            (
                PlaneKey::MlDsa87,
                ID_EC_PUBLIC_KEY,
                SpkiParams::Absent,
                2592,
            ),
            (PlaneKey::MlDsa87, ID_ML_DSA_87, SpkiParams::Other, 2592),
            (PlaneKey::MlDsa87, ID_ML_DSA_87, curve(SECP384R1), 2592),
            (PlaneKey::MlDsa87, ID_ML_DSA_87, SpkiParams::Absent, 97),
            (PlaneKey::P384, ID_ML_DSA_87, curve(SECP384R1), 97),
            (PlaneKey::P384, ID_EC_PUBLIC_KEY, curve(SECP521R1), 97),
            (PlaneKey::P384, ID_EC_PUBLIC_KEY, SpkiParams::Absent, 97),
            (PlaneKey::P384, ID_EC_PUBLIC_KEY, SpkiParams::Other, 97),
            (PlaneKey::P384, ID_EC_PUBLIC_KEY, curve(SECP384R1), 133),
            (PlaneKey::P521, ID_ML_DSA_87, curve(SECP521R1), 133),
            (PlaneKey::P521, ID_EC_PUBLIC_KEY, curve(SECP384R1), 133),
            (PlaneKey::P521, ID_EC_PUBLIC_KEY, SpkiParams::Absent, 133),
            (PlaneKey::MlDsa87, ID_ML_DSA_87, curve(SECP521R1), 2592),
            (PlaneKey::P521, ID_EC_PUBLIC_KEY, SpkiParams::Other, 133),
            (PlaneKey::P521, ID_EC_PUBLIC_KEY, curve(SECP521R1), 97),
        ];
        for (k, alg, params, len) in &bad {
            assert!(
                !k.matches_spki(alg, params, *len, 0),
                "{k:?} {alg} {params:?} {len}"
            );
        }
    }
}
