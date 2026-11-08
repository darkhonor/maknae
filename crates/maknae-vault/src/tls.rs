//! FIPS-pinned rustls config builders (Layer 1, T3). `server_config` and `client_config`
//! assert the aws-lc-rs FIPS provider first (fail-closed); every builder starts from
//! `maknae_crypto::tls`, so no ambient `CryptoProvider` default is relied on. TLS 1.3
//! only. The private key never leaves the crate — the `CertifiedKey` is built here from
//! the `pub(crate)` key accessor.
use crate::peer_auth::SanIdentity;
use crate::resolver::PlaneCertResolver;
use crate::{PeerAuth, PlaneClient, PlaneIdentity, SanRule, TrustBundle, VaultError};
use maknae_crypto::assert_fips_provider;
use maknae_crypto::rustls::client::danger::ServerCertVerifier;
use maknae_crypto::rustls::client::Resumption;
use maknae_crypto::rustls::pki_types::{CertificateDer, PrivateKeyDer};
use maknae_crypto::rustls::server::danger::ClientCertVerifier;
use maknae_crypto::rustls::server::NoServerSessionStorage;
use maknae_crypto::rustls::sign::CertifiedKey;
use maknae_crypto::rustls::{ClientConfig, ServerConfig};
use maknae_crypto::tls::{ClientVerifierHandle, ServerVerifierHandle};
use std::sync::Arc;

pub(crate) fn pem_chain_to_der(
    id: &PlaneIdentity,
) -> Result<Vec<CertificateDer<'static>>, VaultError> {
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

pub(crate) fn client_verifier(
    trust: &TrustBundle,
    rule: SanRule,
) -> Result<Arc<ClientVerifierHandle>, VaultError> {
    maknae_crypto::tls::client_cert_verifier_builder(trust.roots(), &maknae_crypto::policy()?.tls)?
        .with_peer_identity(Arc::new(SanIdentity(rule)))
        .build()
        .map_err(|e| VaultError::Handshake(format!("client verifier: {e}")))
}

pub(crate) fn server_verifier(
    trust: &TrustBundle,
    rule: SanRule,
) -> Result<Arc<ServerVerifierHandle>, VaultError> {
    maknae_crypto::tls::server_cert_verifier_builder(trust.roots(), &maknae_crypto::policy()?.tls)?
        .with_peer_identity(Arc::new(SanIdentity(rule)))
        .build()
        .map_err(|e| VaultError::Handshake(format!("server verifier: {e}")))
}

pub(crate) fn certified_key_from_identity(
    id: &PlaneIdentity,
) -> Result<Arc<CertifiedKey>, VaultError> {
    let chain = pem_chain_to_der(id)?;
    let key = maknae_crypto::tls::load_private_key(
        &maknae_crypto::policy()?.tls,
        PrivateKeyDer::Pkcs8(id.key_der().to_vec().into()),
    )
    .map_err(|e| VaultError::Handshake(format!("load leaf key: {e}")))?;
    Ok(Arc::new(CertifiedKey::new(chain, key)))
}

/// Server config: dynamic resolver (fail-closed when empty); client auth per `auth`.
pub(crate) fn server_config(
    trust: &TrustBundle,
    auth: &PeerAuth,
    resolver: Arc<PlaneCertResolver>,
) -> Result<Arc<ServerConfig>, VaultError> {
    assert_fips_provider()?;
    let config = match auth {
        PeerAuth::Certless => without_resumption(
            maknae_crypto::tls::server_builder(&maknae_crypto::policy()?.tls)
                .map_err(|e| VaultError::Handshake(format!("server tls13: {e}")))?
                .with_no_client_auth()
                .with_cert_resolver(resolver),
        ),
        PeerAuth::PlaneLeaf { accept } => {
            plane_server_config(client_verifier(trust, accept.clone())?, resolver)?
        }
    };
    Ok(Arc::new(config))
}

/// Client config. The CLI still configures its static leaf (removed by #116); the client
/// channel never requests it, so only the machine class sends it.
pub(crate) fn client_config(
    client: &PlaneClient,
    trust: &TrustBundle,
    accept: SanRule,
) -> Result<Arc<ClientConfig>, VaultError> {
    assert_fips_provider()?;
    let verifier = server_verifier(trust, accept)?;
    let id = client
        .current_identity()
        .ok_or_else(|| VaultError::Handshake("no minted identity".into()))?;
    let chain = pem_chain_to_der(&id)?;
    let key = PrivateKeyDer::Pkcs8(id.key_der().to_vec().into());
    Ok(Arc::new(plane_client_config(verifier, Some((chain, key)))?))
}

fn without_resumption(mut config: ServerConfig) -> ServerConfig {
    config.session_storage = Arc::new(NoServerSessionStorage {});
    config.send_tls13_tickets = 0;
    config
}

pub(crate) fn plane_server_config(
    verifier: Arc<dyn ClientCertVerifier>,
    resolver: Arc<PlaneCertResolver>,
) -> Result<ServerConfig, VaultError> {
    Ok(without_resumption(
        maknae_crypto::tls::server_builder(&maknae_crypto::policy()?.tls)
            .map_err(|e| VaultError::Handshake(format!("server tls13: {e}")))?
            .with_client_cert_verifier(verifier)
            .with_cert_resolver(resolver),
    ))
}

pub(crate) fn plane_client_config(
    verifier: Arc<dyn ServerCertVerifier>,
    client_auth: Option<(Vec<CertificateDer<'static>>, PrivateKeyDer<'static>)>,
) -> Result<ClientConfig, VaultError> {
    let builder = maknae_crypto::tls::client_builder(&maknae_crypto::policy()?.tls)
        .map_err(|e| VaultError::Handshake(format!("client tls13: {e}")))?
        .dangerous()
        .with_custom_certificate_verifier(verifier);
    let mut config = match client_auth {
        Some((chain, key)) => builder
            .with_client_auth_cert(chain, key)
            .map_err(|e| VaultError::Handshake(format!("client auth cert: {e}")))?,
        None => builder.with_no_client_auth(),
    };
    config.resumption = Resumption::disabled();
    Ok(config)
}

#[cfg(test)]
mod tests {
    use super::*;
    const _: fn() = || {
        fn _sig(client: &PlaneClient, trust: &TrustBundle, auth: &PeerAuth) {
            let _s: Result<Arc<maknae_crypto::rustls::ServerConfig>, VaultError> = server_config(
                trust,
                auth,
                Arc::new(crate::resolver::PlaneCertResolver::new_empty()),
            );
            let _c: Result<Arc<maknae_crypto::rustls::ClientConfig>, VaultError> =
                client_config(client, trust, SanRule::Exact(String::new()));
        }
    };
}
