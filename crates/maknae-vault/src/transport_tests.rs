//! In-process mTLS negative suite (Stage 2, CI). Unit-module so it can reach pub(crate)
//! config/verifier constructors. Uses tokio duplex (no socket/peer-creds — those are unit
//! tested in socket.rs/peercred.rs). rcgen mints a test CA + kernel/cli leaves. This is
//! ADR-0005's mTLS negative suite: happy path + each negative fails closed.
use crate::{CaBundle, Plane};
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use std::sync::Arc;

fn provider() {
    rustls::crypto::aws_lc_rs::default_provider()
        .install_default()
        .ok();
}

struct Ca {
    der: Vec<u8>,
    kp: rcgen::KeyPair,
    cert: rcgen::Certificate,
}
fn mk_ca() -> Ca {
    let mut p = rcgen::CertificateParams::new(vec![]).unwrap();
    p.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
    let kp = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P384_SHA384).unwrap();
    let cert = p.self_signed(&kp).unwrap();
    Ca {
        der: cert.der().to_vec(),
        kp,
        cert,
    }
}

/// Returns (chain=[leaf, ca], leaf_key_der). `expired=true` → not_after in the past.
fn mk_leaf(ca: &Ca, uri: &str, expired: bool) -> (Vec<CertificateDer<'static>>, Vec<u8>) {
    let mut p = rcgen::CertificateParams::new(vec![]).unwrap();
    p.distinguished_name = rcgen::DistinguishedName::new();
    p.subject_alt_names = vec![rcgen::SanType::URI(uri.try_into().unwrap())];
    if expired {
        p.not_before = rcgen::date_time_ymd(1999, 1, 1);
        p.not_after = rcgen::date_time_ymd(2000, 1, 1);
    }
    let kp = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P384_SHA384).unwrap();
    let leaf = p.signed_by(&kp, &ca.cert, &ca.kp).unwrap();
    (
        vec![
            CertificateDer::from(leaf.der().to_vec()),
            CertificateDer::from(ca.der.clone()),
        ],
        kp.serialize_der(),
    )
}

/// A leaf carrying the plane URI PLUS a rogue DNS SAN (defense-in-depth negative).
fn mk_leaf_extra_san(ca: &Ca, uri: &str) -> (Vec<CertificateDer<'static>>, Vec<u8>) {
    let mut p = rcgen::CertificateParams::new(vec![]).unwrap();
    p.distinguished_name = rcgen::DistinguishedName::new();
    p.subject_alt_names = vec![
        rcgen::SanType::URI(uri.try_into().unwrap()),
        rcgen::SanType::DnsName("evil.example".try_into().unwrap()),
    ];
    let kp = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P384_SHA384).unwrap();
    let leaf = p.signed_by(&kp, &ca.cert, &ca.kp).unwrap();
    (
        vec![
            CertificateDer::from(leaf.der().to_vec()),
            CertificateDer::from(ca.der.clone()),
        ],
        kp.serialize_der(),
    )
}

fn server_cfg(
    chain: Vec<CertificateDer<'static>>,
    key: Vec<u8>,
    ca: &CaBundle,
    expect: Plane,
) -> Arc<rustls::ServerConfig> {
    let key = rustls::crypto::aws_lc_rs::default_provider()
        .key_provider
        .load_private_key(PrivateKeyDer::Pkcs8(key.into()))
        .unwrap();
    let resolver = Arc::new(crate::resolver::PlaneCertResolver::new_empty());
    resolver
        .slot()
        .store(Some(Arc::new(rustls::sign::CertifiedKey::new(chain, key))));
    let verifier = crate::plane_verify::PlaneClientCertVerifier::new(ca, expect, "d").unwrap();
    Arc::new(
        rustls::ServerConfig::builder_with_provider(Arc::new(
            rustls::crypto::aws_lc_rs::default_provider(),
        ))
        .with_protocol_versions(&[&rustls::version::TLS13])
        .unwrap()
        .with_client_cert_verifier(verifier)
        .with_cert_resolver(resolver),
    )
}

fn client_cfg(
    chain: Vec<CertificateDer<'static>>,
    key: Vec<u8>,
    ca: &CaBundle,
    expect: Plane,
    with_cert: bool,
) -> Arc<rustls::ClientConfig> {
    let verifier = crate::plane_verify::PlaneServerCertVerifier::new(ca, expect, "d").unwrap();
    let b = rustls::ClientConfig::builder_with_provider(Arc::new(
        rustls::crypto::aws_lc_rs::default_provider(),
    ))
    .with_protocol_versions(&[&rustls::version::TLS13])
    .unwrap()
    .dangerous()
    .with_custom_certificate_verifier(verifier);
    Arc::new(if with_cert {
        b.with_client_auth_cert(chain, PrivateKeyDer::Pkcs8(key.into()))
            .unwrap()
    } else {
        b.with_no_client_auth()
    })
}

async fn handshake(
    server: Arc<rustls::ServerConfig>,
    client: Arc<rustls::ClientConfig>,
) -> Result<(), String> {
    use tokio_rustls::{TlsAcceptor, TlsConnector};
    let (c, s) = tokio::io::duplex(16 * 1024);
    let acceptor = TlsAcceptor::from(server);
    let connector = TlsConnector::from(client);
    let name = rustls::pki_types::ServerName::try_from("maknae.invalid").unwrap();
    let srv = tokio::spawn(async move {
        acceptor
            .accept(s)
            .await
            .map(|_| ())
            .map_err(|e| e.to_string())
    });
    // Hold the client stream alive until the server has finished the handshake — dropping
    // it the instant connect() returns would close the pipe before the server reads the
    // client's final (Finished + cert) flight, yielding a spurious "broken pipe".
    match connector.connect(name, c).await {
        Ok(stream) => {
            let srv_res = srv.await.unwrap();
            drop(stream);
            srv_res
        }
        Err(e) => {
            let _ = srv.await;
            Err(e.to_string())
        }
    }
}

fn cab(ca: &Ca) -> CaBundle {
    CaBundle {
        root_der: ca.der.clone(),
        int_der: ca.der.clone(),
    }
}

#[tokio::test]
async fn happy_path_mutual_auth() {
    provider();
    let ca = mk_ca();
    let (kchain, kkey) = mk_leaf(&ca, "maknae://d/plane/kernel", false);
    let (cchain, ckey) = mk_leaf(&ca, "maknae://d/plane/cli", false);
    let s = server_cfg(kchain, kkey, &cab(&ca), Plane::Cli); // daemon=kernel expects cli
    let c = client_cfg(cchain, ckey, &cab(&ca), Plane::Kernel, true); // cli expects kernel
    handshake(s, c).await.expect("mutual auth succeeds");
}

#[tokio::test]
async fn rejects_wrong_plane_client() {
    provider();
    let ca = mk_ca();
    let (kchain, kkey) = mk_leaf(&ca, "maknae://d/plane/kernel", false);
    // CLI presents a KERNEL leaf (wrong plane) — server expects cli → reject.
    let (wrong, wkey) = mk_leaf(&ca, "maknae://d/plane/kernel", false);
    let s = server_cfg(kchain, kkey, &cab(&ca), Plane::Cli);
    let c = client_cfg(wrong, wkey, &cab(&ca), Plane::Kernel, true);
    assert!(handshake(s, c).await.is_err());
}

#[tokio::test]
async fn rejects_absent_client_cert() {
    provider();
    let ca = mk_ca();
    let (kchain, kkey) = mk_leaf(&ca, "maknae://d/plane/kernel", false);
    let (cchain, ckey) = mk_leaf(&ca, "maknae://d/plane/cli", false);
    let s = server_cfg(kchain, kkey, &cab(&ca), Plane::Cli);
    let c = client_cfg(cchain, ckey, &cab(&ca), Plane::Kernel, false); // no client cert
    assert!(handshake(s, c).await.is_err());
}

#[tokio::test]
async fn rejects_expired_server_leaf() {
    provider();
    let ca = mk_ca();
    let (kchain, kkey) = mk_leaf(&ca, "maknae://d/plane/kernel", true); // expired
    let (cchain, ckey) = mk_leaf(&ca, "maknae://d/plane/cli", false);
    let s = server_cfg(kchain, kkey, &cab(&ca), Plane::Cli);
    let c = client_cfg(cchain, ckey, &cab(&ca), Plane::Kernel, true);
    assert!(handshake(s, c).await.is_err());
}

#[tokio::test]
async fn rejects_foreign_ca() {
    provider();
    let ca = mk_ca();
    let foreign = mk_ca();
    let (kchain, kkey) = mk_leaf(&foreign, "maknae://d/plane/kernel", false); // foreign-signed
    let (cchain, ckey) = mk_leaf(&ca, "maknae://d/plane/cli", false);
    let s = server_cfg(kchain, kkey, &cab(&ca), Plane::Cli);
    let c = client_cfg(cchain, ckey, &cab(&ca), Plane::Kernel, true);
    assert!(handshake(s, c).await.is_err());
}

#[tokio::test]
async fn rejects_extra_san_client() {
    provider();
    let ca = mk_ca();
    let (kchain, kkey) = mk_leaf(&ca, "maknae://d/plane/kernel", false);
    // CLI leaf carries the correct plane URI PLUS a rogue DNS SAN → rejected (URI-SAN-only).
    let (cchain, ckey) = mk_leaf_extra_san(&ca, "maknae://d/plane/cli");
    let s = server_cfg(kchain, kkey, &cab(&ca), Plane::Cli);
    let c = client_cfg(cchain, ckey, &cab(&ca), Plane::Kernel, true);
    assert!(handshake(s, c).await.is_err());
}
