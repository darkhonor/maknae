//! FIPS-pinned rustls config builders (Layer 1, T3). Both builders assert the aws-lc-rs
//! FIPS provider first (fail-closed) and construct via `builder_with_provider(...)` so no
//! ambient `CryptoProvider` default is relied on. TLS 1.3 only. The private key never
//! leaves the crate — the `CertifiedKey` is built here from the `pub(crate)` key accessor.
use crate::plane_verify::{PlaneClientCertVerifier, PlaneServerCertVerifier};
use crate::resolver::PlaneCertResolver;
use crate::{assert_fips_provider, CaBundle, Plane, PlaneClient, PlaneIdentity, VaultError};
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::sign::CertifiedKey;
use rustls::{ClientConfig, ServerConfig};
use std::sync::Arc;

fn pem_chain_to_der(id: &PlaneIdentity) -> Result<Vec<CertificateDer<'static>>, VaultError> {
    // leaf first, then the (single) issuing intermediate — presented chain [leaf, int].
    let mut out = Vec::new();
    for pem in std::iter::once(id.leaf_pem()).chain(id.chain_pem().iter().map(|s| s.as_str())) {
        let (_, parsed) = x509_parser::pem::parse_x509_pem(pem.as_bytes())
            .map_err(|_| VaultError::Pem("tls: malformed PEM in identity chain"))?;
        out.push(CertificateDer::from(parsed.contents));
        if out.len() == 2 {
            break; // leaf + one intermediate
        }
    }
    Ok(out)
}

pub(crate) fn certified_key_from_identity(
    id: &PlaneIdentity,
) -> Result<Arc<CertifiedKey>, VaultError> {
    let chain = pem_chain_to_der(id)?;
    let key = rustls::crypto::aws_lc_rs::default_provider()
        .key_provider
        .load_private_key(PrivateKeyDer::Pkcs8(id.key_der().to_vec().into()))
        .map_err(|e| VaultError::Handshake(format!("load leaf key: {e}")))?;
    Ok(Arc::new(CertifiedKey::new(chain, key)))
}

pub(crate) fn certified_key_from(client: &PlaneClient) -> Result<Arc<CertifiedKey>, VaultError> {
    let id = client
        .current_identity()
        .ok_or_else(|| VaultError::Handshake("no minted identity".into()))?;
    certified_key_from_identity(&id)
}

/// Server config: dynamic resolver (fail-closed when empty) + client-auth via the custom
/// client-cert verifier expecting the peer plane.
pub(crate) fn server_config(
    client: &PlaneClient,
    ca: &CaBundle,
    resolver: Arc<PlaneCertResolver>,
) -> Result<Arc<ServerConfig>, VaultError> {
    assert_fips_provider()?;
    let expect = client.plane().peer();
    let verifier = PlaneClientCertVerifier::new(ca, expect, client.deployment_id())?;
    let cfg = ServerConfig::builder_with_provider(Arc::new(
        rustls::crypto::aws_lc_rs::default_provider(),
    ))
    .with_protocol_versions(&[&rustls::version::TLS13])
    .map_err(|e| VaultError::Handshake(format!("server tls13: {e}")))?
    .with_client_cert_verifier(verifier)
    .with_cert_resolver(resolver);
    Ok(Arc::new(cfg))
}

/// Client config: custom server-cert verifier + STATIC client cert (CLI is stateless).
pub(crate) fn client_config(
    client: &PlaneClient,
    ca: &CaBundle,
    expected_peer: Plane,
) -> Result<Arc<ClientConfig>, VaultError> {
    assert_fips_provider()?;
    debug_assert_eq!(expected_peer, client.plane().peer());
    let verifier = PlaneServerCertVerifier::new(ca, expected_peer, client.deployment_id())?;
    let id = client
        .current_identity()
        .ok_or_else(|| VaultError::Handshake("no minted identity".into()))?;
    let chain = pem_chain_to_der(&id)?;
    let key = PrivateKeyDer::Pkcs8(id.key_der().to_vec().into());
    let cfg = ClientConfig::builder_with_provider(Arc::new(
        rustls::crypto::aws_lc_rs::default_provider(),
    ))
    .with_protocol_versions(&[&rustls::version::TLS13])
    .map_err(|e| VaultError::Handshake(format!("client tls13: {e}")))?
    .dangerous()
    .with_custom_certificate_verifier(verifier)
    .with_client_auth_cert(chain, key)
    .map_err(|e| VaultError::Handshake(format!("client auth cert: {e}")))?;
    Ok(Arc::new(cfg))
}

#[cfg(test)]
mod tests {
    use super::*;
    const _: fn() = || {
        fn _sig(client: &PlaneClient, ca: &CaBundle) {
            let _s: Result<Arc<rustls::ServerConfig>, VaultError> = server_config(
                client,
                ca,
                Arc::new(crate::resolver::PlaneCertResolver::new_empty()),
            );
            let _c: Result<Arc<rustls::ClientConfig>, VaultError> =
                client_config(client, ca, Plane::Kernel);
            let _k: Result<Arc<rustls::sign::CertifiedKey>, VaultError> =
                certified_key_from(client);
        }
    };
}
