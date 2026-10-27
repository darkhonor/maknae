//! rustls configuration builders on the crate's FIPS provider, TLS 1.3 only.
use crate::{crypto_provider, CryptoError};
use rustls::{ClientConfig, ConfigBuilder, ServerConfig, WantsVerifier};
use std::sync::Arc;

pub fn client_builder() -> Result<ConfigBuilder<ClientConfig, WantsVerifier>, CryptoError> {
    ClientConfig::builder_with_provider(Arc::new(crypto_provider()))
        .with_protocol_versions(&[&rustls::version::TLS13])
        .map_err(|e| CryptoError::Tls(e.to_string()))
}

pub fn server_builder() -> Result<ConfigBuilder<ServerConfig, WantsVerifier>, CryptoError> {
    ServerConfig::builder_with_provider(Arc::new(crypto_provider()))
        .with_protocol_versions(&[&rustls::version::TLS13])
        .map_err(|e| CryptoError::Tls(e.to_string()))
}

pub fn load_private_key(
    der: rustls::pki_types::PrivateKeyDer<'static>,
) -> Result<Arc<dyn rustls::sign::SigningKey>, CryptoError> {
    crypto_provider()
        .key_provider
        .load_private_key(der)
        .map_err(|e| CryptoError::Tls(e.to_string()))
}

pub fn client_cert_verifier_builder(
    roots: Arc<rustls::RootCertStore>,
) -> rustls::server::ClientCertVerifierBuilder {
    rustls::server::WebPkiClientVerifier::builder_with_provider(roots, Arc::new(crypto_provider()))
}

pub fn server_cert_verifier_builder(
    roots: Arc<rustls::RootCertStore>,
) -> rustls::client::ServerCertVerifierBuilder {
    rustls::client::WebPkiServerVerifier::builder_with_provider(roots, Arc::new(crypto_provider()))
}
