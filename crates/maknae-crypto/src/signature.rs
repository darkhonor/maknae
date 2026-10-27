//! The signature key algorithms (#573): each one's rcgen algorithm, TLS
//! signature scheme and SubjectPublicKeyInfo identifiers.
use rustls::SignatureScheme;

const ID_ML_DSA_87: &str = "2.16.840.1.101.3.4.3.19";
const ID_EC_PUBLIC_KEY: &str = "1.2.840.10045.2.1";
const SECP384R1: &str = "1.3.132.0.34";
const SECP521R1: &str = "1.3.132.0.35";

/// A signature key algorithm: what a key is generated as, and what a CA must issue for it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum SignatureAlgorithm {
    /// ML-DSA-87 (FIPS 204).
    MlDsa87,
    /// ECDSA on P-384 with SHA-384.
    EcdsaP384Sha384,
    /// ECDSA on P-521 with SHA-512.
    EcdsaP521Sha512,
}

/// The SubjectPublicKeyInfo algorithm parameters, as far as [`SignatureAlgorithm::matches_spki`] reads them.
#[derive(Debug, PartialEq, Eq)]
pub enum SpkiParams {
    /// The parameters field is omitted.
    Absent,
    /// A named-curve OID, in dotted form.
    NamedCurve(String),
    /// Any other parameters encoding.
    Other,
}

impl SignatureAlgorithm {
    /// Every supported algorithm.
    pub const ALL: [SignatureAlgorithm; 3] = [
        SignatureAlgorithm::MlDsa87,
        SignatureAlgorithm::EcdsaP384Sha384,
        SignatureAlgorithm::EcdsaP521Sha512,
    ];

    /// The algorithm's configuration name.
    pub fn as_str(self) -> &'static str {
        match self {
            SignatureAlgorithm::MlDsa87 => "ml-dsa-87",
            SignatureAlgorithm::EcdsaP384Sha384 => "ecdsa-p384-sha384",
            SignatureAlgorithm::EcdsaP521Sha512 => "ecdsa-p521-sha512",
        }
    }

    /// The algorithm with this configuration name, if any.
    pub fn parse(s: &str) -> Option<Self> {
        SignatureAlgorithm::ALL
            .into_iter()
            .find(|k| k.as_str() == s)
    }

    pub(crate) fn rcgen_alg(self) -> &'static rcgen::SignatureAlgorithm {
        match self {
            SignatureAlgorithm::MlDsa87 => &rcgen::PKCS_ML_DSA_87,
            SignatureAlgorithm::EcdsaP384Sha384 => &rcgen::PKCS_ECDSA_P384_SHA384,
            SignatureAlgorithm::EcdsaP521Sha512 => &rcgen::PKCS_ECDSA_P521_SHA512,
        }
    }

    /// The rcgen algorithm used to generate keys of this kind.
    #[cfg(feature = "test-support")]
    pub fn rcgen_algorithm(self) -> &'static rcgen::SignatureAlgorithm {
        self.rcgen_alg()
    }

    /// The TLS signature scheme this algorithm signs with.
    pub fn signature_scheme(self) -> SignatureScheme {
        match self {
            SignatureAlgorithm::MlDsa87 => SignatureScheme::ML_DSA_87,
            SignatureAlgorithm::EcdsaP384Sha384 => SignatureScheme::ECDSA_NISTP384_SHA384,
            SignatureAlgorithm::EcdsaP521Sha512 => SignatureScheme::ECDSA_NISTP521_SHA512,
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
                SignatureAlgorithm::MlDsa87 => {
                    alg == ID_ML_DSA_87 && *params == SpkiParams::Absent && key_len == 2592
                }
                SignatureAlgorithm::EcdsaP384Sha384 => {
                    alg == ID_EC_PUBLIC_KEY
                        && *params == SpkiParams::NamedCurve(SECP384R1.to_string())
                        && key_len == 97
                }
                SignatureAlgorithm::EcdsaP521Sha512 => {
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
    fn names_are_explicit_and_the_short_names_are_refused() {
        assert_eq!(
            SignatureAlgorithm::ALL.map(SignatureAlgorithm::as_str),
            ["ml-dsa-87", "ecdsa-p384-sha384", "ecdsa-p521-sha512"]
        );
        for a in SignatureAlgorithm::ALL {
            assert_eq!(SignatureAlgorithm::parse(a.as_str()), Some(a));
        }
        for s in [
            "p384",
            "p521",
            "ML-DSA-87",
            "ecdsa-p256-sha256",
            "ml-dsa-65",
            "",
        ] {
            assert_eq!(SignatureAlgorithm::parse(s), None, "{s}");
        }
    }

    #[test]
    fn each_algorithm_maps_to_its_own_scheme_and_spki() {
        let table = [
            (
                SignatureAlgorithm::MlDsa87,
                SignatureScheme::ML_DSA_87,
                ID_ML_DSA_87,
                SpkiParams::Absent,
            ),
            (
                SignatureAlgorithm::EcdsaP384Sha384,
                SignatureScheme::ECDSA_NISTP384_SHA384,
                ID_EC_PUBLIC_KEY,
                curve(SECP384R1),
            ),
            (
                SignatureAlgorithm::EcdsaP521Sha512,
                SignatureScheme::ECDSA_NISTP521_SHA512,
                ID_EC_PUBLIC_KEY,
                curve(SECP521R1),
            ),
        ];
        for (k, scheme, alg, params) in &table {
            assert_eq!(k.signature_scheme(), *scheme);
            let key = rcgen::KeyPair::generate_for(k.rcgen_alg()).unwrap();
            let len = key.public_key_raw().len();
            for other in SignatureAlgorithm::ALL {
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
        let schemes = SignatureAlgorithm::ALL.map(SignatureAlgorithm::signature_scheme);
        for k in SignatureAlgorithm::ALL {
            let key = rcgen::KeyPair::generate_for(k.rcgen_alg()).unwrap();
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
            (
                SignatureAlgorithm::MlDsa87,
                ID_ML_DSA_87,
                SpkiParams::Absent,
                2592,
            ),
            (
                SignatureAlgorithm::EcdsaP384Sha384,
                ID_EC_PUBLIC_KEY,
                curve(SECP384R1),
                97,
            ),
            (
                SignatureAlgorithm::EcdsaP521Sha512,
                ID_EC_PUBLIC_KEY,
                curve(SECP521R1),
                133,
            ),
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
                SignatureAlgorithm::MlDsa87,
                ID_EC_PUBLIC_KEY,
                SpkiParams::Absent,
                2592,
            ),
            (
                SignatureAlgorithm::MlDsa87,
                ID_ML_DSA_87,
                SpkiParams::Other,
                2592,
            ),
            (
                SignatureAlgorithm::MlDsa87,
                ID_ML_DSA_87,
                curve(SECP384R1),
                2592,
            ),
            (
                SignatureAlgorithm::MlDsa87,
                ID_ML_DSA_87,
                SpkiParams::Absent,
                97,
            ),
            (
                SignatureAlgorithm::EcdsaP384Sha384,
                ID_ML_DSA_87,
                curve(SECP384R1),
                97,
            ),
            (
                SignatureAlgorithm::EcdsaP384Sha384,
                ID_EC_PUBLIC_KEY,
                curve(SECP521R1),
                97,
            ),
            (
                SignatureAlgorithm::EcdsaP384Sha384,
                ID_EC_PUBLIC_KEY,
                SpkiParams::Absent,
                97,
            ),
            (
                SignatureAlgorithm::EcdsaP384Sha384,
                ID_EC_PUBLIC_KEY,
                SpkiParams::Other,
                97,
            ),
            (
                SignatureAlgorithm::EcdsaP384Sha384,
                ID_EC_PUBLIC_KEY,
                curve(SECP384R1),
                133,
            ),
            (
                SignatureAlgorithm::EcdsaP521Sha512,
                ID_ML_DSA_87,
                curve(SECP521R1),
                133,
            ),
            (
                SignatureAlgorithm::EcdsaP521Sha512,
                ID_EC_PUBLIC_KEY,
                curve(SECP384R1),
                133,
            ),
            (
                SignatureAlgorithm::EcdsaP521Sha512,
                ID_EC_PUBLIC_KEY,
                SpkiParams::Absent,
                133,
            ),
            (
                SignatureAlgorithm::MlDsa87,
                ID_ML_DSA_87,
                curve(SECP521R1),
                2592,
            ),
            (
                SignatureAlgorithm::EcdsaP521Sha512,
                ID_EC_PUBLIC_KEY,
                SpkiParams::Other,
                133,
            ),
            (
                SignatureAlgorithm::EcdsaP521Sha512,
                ID_EC_PUBLIC_KEY,
                curve(SECP521R1),
                97,
            ),
        ];
        for (k, alg, params, len) in &bad {
            assert!(
                !k.matches_spki(alg, params, *len, 0),
                "{k:?} {alg} {params:?} {len}"
            );
        }
    }
}
