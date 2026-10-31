//! The plane identity's signature key algorithms: the subset of [`SignatureAlgorithm`] a plane
//! may hold, under their `vault.plane_key` names (#573, #589).
use crate::rustls::SignatureScheme;
use crate::signature::{self, SpkiParams};
use crate::SignatureAlgorithm;

/// A plane identity's signature key algorithm.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PlaneKey {
    /// ML-DSA-87 (FIPS 204).
    MlDsa87,
    /// ECDSA on P-384 with SHA-384.
    EcdsaP384Sha384,
    /// ECDSA on P-521 with SHA-512.
    EcdsaP521Sha512,
}

impl PlaneKey {
    /// Every plane key algorithm.
    pub const ALL: [PlaneKey; 3] = [
        PlaneKey::MlDsa87,
        PlaneKey::EcdsaP384Sha384,
        PlaneKey::EcdsaP521Sha512,
    ];

    /// The algorithm's `vault.plane_key` name.
    pub fn as_str(self) -> &'static str {
        SignatureAlgorithm::from(self).as_str()
    }

    /// The plane key with this `vault.plane_key` name, if any.
    pub fn parse(s: &str) -> Option<Self> {
        PlaneKey::ALL.into_iter().find(|k| k.as_str() == s)
    }

    /// The TLS signature scheme this key signs with.
    pub fn signature_scheme(self) -> SignatureScheme {
        SignatureScheme::from(SignatureAlgorithm::from(self).tls_scheme().iana())
    }

    /// True iff a parsed SubjectPublicKeyInfo is exactly this algorithm's key.
    pub fn matches_spki(
        self,
        alg: &str,
        params: &SpkiParams,
        key_len: usize,
        unused_bits: u8,
    ) -> bool {
        signature::matches_spki(self.into(), alg, params, key_len, unused_bits)
    }

    /// The rcgen algorithm that generates keys of this kind.
    #[cfg(feature = "test-support")]
    pub fn rcgen_algorithm(self) -> &'static crate::rcgen::SignatureAlgorithm {
        match self {
            PlaneKey::MlDsa87 => &crate::rcgen::PKCS_ML_DSA_87,
            PlaneKey::EcdsaP384Sha384 => &crate::rcgen::PKCS_ECDSA_P384_SHA384,
            PlaneKey::EcdsaP521Sha512 => &crate::rcgen::PKCS_ECDSA_P521_SHA512,
        }
    }
}

impl From<PlaneKey> for SignatureAlgorithm {
    fn from(k: PlaneKey) -> Self {
        match k {
            PlaneKey::MlDsa87 => SignatureAlgorithm::MlDsa87,
            PlaneKey::EcdsaP384Sha384 => SignatureAlgorithm::EcdsaP384Sha384,
            PlaneKey::EcdsaP521Sha512 => SignatureAlgorithm::EcdsaP521Sha512,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_tokens_round_trip_and_nothing_else_parses() {
        assert_eq!(
            PlaneKey::ALL.map(PlaneKey::as_str),
            ["ml-dsa-87", "ecdsa-p384-sha384", "ecdsa-p521-sha512"]
        );
        for k in PlaneKey::ALL {
            assert_eq!(PlaneKey::parse(k.as_str()), Some(k));
        }
        for s in [
            "ecdsa-p256-sha256",
            "ecdsa-p521-sha384",
            "ed25519",
            "rsa3072-sha384",
            "ML-DSA-87",
            "p384",
            "",
        ] {
            assert_eq!(PlaneKey::parse(s), None, "{s}");
        }
    }

    #[test]
    fn each_plane_key_is_its_own_algorithm() {
        assert_eq!(
            SignatureAlgorithm::from(PlaneKey::MlDsa87),
            SignatureAlgorithm::MlDsa87
        );
        assert_eq!(
            SignatureAlgorithm::from(PlaneKey::EcdsaP384Sha384),
            SignatureAlgorithm::EcdsaP384Sha384
        );
        assert_eq!(
            SignatureAlgorithm::from(PlaneKey::EcdsaP521Sha512),
            SignatureAlgorithm::EcdsaP521Sha512
        );
    }

    #[test]
    fn each_plane_key_signs_with_its_own_scheme() {
        assert_eq!(
            PlaneKey::MlDsa87.signature_scheme(),
            SignatureScheme::ML_DSA_87
        );
        assert_eq!(
            PlaneKey::EcdsaP384Sha384.signature_scheme(),
            SignatureScheme::ECDSA_NISTP384_SHA384
        );
        assert_eq!(
            PlaneKey::EcdsaP521Sha512.signature_scheme(),
            SignatureScheme::ECDSA_NISTP521_SHA512
        );
    }

    #[test]
    fn matches_spki_is_the_backends_decision() {
        let p384 = SpkiParams::NamedCurve("1.3.132.0.34".to_string());
        assert!(PlaneKey::EcdsaP384Sha384.matches_spki("1.2.840.10045.2.1", &p384, 97, 0));
        assert!(!PlaneKey::EcdsaP521Sha512.matches_spki("1.2.840.10045.2.1", &p384, 97, 0));
        assert!(PlaneKey::MlDsa87.matches_spki(
            "2.16.840.1.101.3.4.3.19",
            &SpkiParams::Absent,
            2592,
            0
        ));
        assert!(!PlaneKey::MlDsa87.matches_spki(
            "2.16.840.1.101.3.4.3.19",
            &SpkiParams::Absent,
            2592,
            1
        ));
    }

    #[cfg(feature = "test-support")]
    #[test]
    fn the_test_support_accessor_returns_each_keys_rcgen_algorithm() {
        assert_eq!(
            PlaneKey::MlDsa87.rcgen_algorithm(),
            &crate::rcgen::PKCS_ML_DSA_87
        );
        assert_eq!(
            PlaneKey::EcdsaP384Sha384.rcgen_algorithm(),
            &crate::rcgen::PKCS_ECDSA_P384_SHA384
        );
        assert_eq!(
            PlaneKey::EcdsaP521Sha512.rcgen_algorithm(),
            &crate::rcgen::PKCS_ECDSA_P521_SHA512
        );
    }
}
