use crate::signature::SignatureAlgorithm;
use crate::CryptoError;
use zeroize::Zeroizing;

/// A new keypair and its PKCS#10 request: an empty subject and exactly one URI SAN.
/// Returns `(key_der, csr_pem)`, the key as zeroizing PKCS#8.
pub fn generate_csr(
    key: SignatureAlgorithm,
    uri_san: &str,
) -> Result<(Zeroizing<Vec<u8>>, String), CryptoError> {
    let csr_err = |e: rcgen::Error| CryptoError::Csr(e.to_string());
    let mut params = rcgen::CertificateParams::new(vec![]).map_err(csr_err)?;
    params.distinguished_name = rcgen::DistinguishedName::new();
    params.subject_alt_names = vec![rcgen::SanType::URI(uri_san.try_into().map_err(csr_err)?)];
    let pair = rcgen::KeyPair::generate_for(key.rcgen_alg()).map_err(csr_err)?;
    let csr_pem = params
        .serialize_request(&pair)
        .map_err(csr_err)?
        .pem()
        .map_err(csr_err)?;
    Ok((Zeroizing::new(pair.serialize_der()), csr_pem))
}
