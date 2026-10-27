#![cfg(test)]

//! In-process mTLS negative suite (Stage 2, CI). Unit-module so it can reach pub(crate)
//! config/verifier constructors. Uses tokio duplex (no socket/peer-creds — those are unit
//! tested in socket.rs/peercred.rs). rcgen mints a test CA + kernel/cli leaves. This is
//! ADR-0005's mTLS negative suite: happy path + each negative fails closed.
use crate::{CaBundle, Plane};
use maknae_crypto::rcgen;
use maknae_crypto::rustls::pki_types::{CertificateDer, PrivateKeyDer};
use maknae_crypto::signature::PlaneKey;
use std::sync::Arc;

fn provider() {
    maknae_crypto::install_default_crypto_provider();
}

/// The CA keeps its `CertificateParams`, not its `Certificate`: rcgen 0.14 signs
/// against an `Issuer`, which is built from the issuing params + key.
/// (`Issuer::from_ca_cert_der` would recover one from DER, but it needs rcgen's
/// `x509-parser` feature, which this crate does not enable.)
struct Ca {
    der: Vec<u8>,
    kp: rcgen::KeyPair,
    params: rcgen::CertificateParams,
}
impl Ca {
    fn issuer(&self) -> rcgen::Issuer<'_, &rcgen::KeyPair> {
        rcgen::Issuer::from_params(&self.params, &self.kp)
    }
}
const P384: PlaneKey = PlaneKey::P384;
const MLDSA87: PlaneKey = PlaneKey::MlDsa87;

fn mk_ca() -> Ca {
    mk_ca_with(P384)
}
fn mk_ca_with(alg: PlaneKey) -> Ca {
    let mut p = rcgen::CertificateParams::new(vec![]).unwrap();
    p.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
    let kp = rcgen::KeyPair::generate_for(alg.rcgen_algorithm()).unwrap();
    let cert = p.self_signed(&kp).unwrap();
    Ca {
        der: cert.der().to_vec(),
        kp,
        params: p,
    }
}

/// Returns (chain=[leaf, ca], leaf_key_der). `expired=true` → not_after in the past.
fn mk_leaf(ca: &Ca, uri: &str, expired: bool) -> (Vec<CertificateDer<'static>>, Vec<u8>) {
    mk_leaf_with(ca, uri, expired, P384)
}
fn mk_leaf_with(
    ca: &Ca,
    uri: &str,
    expired: bool,
    alg: PlaneKey,
) -> (Vec<CertificateDer<'static>>, Vec<u8>) {
    let mut p = rcgen::CertificateParams::new(vec![]).unwrap();
    p.distinguished_name = rcgen::DistinguishedName::new();
    p.subject_alt_names = vec![rcgen::SanType::URI(uri.try_into().unwrap())];
    if expired {
        p.not_before = rcgen::date_time_ymd(1999, 1, 1);
        p.not_after = rcgen::date_time_ymd(2000, 1, 1);
    }
    let kp = rcgen::KeyPair::generate_for(alg.rcgen_algorithm()).unwrap();
    let leaf = p.signed_by(&kp, &ca.issuer()).unwrap();
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
    mk_leaf_extra_san_with(ca, uri, P384)
}
fn mk_leaf_extra_san_with(
    ca: &Ca,
    uri: &str,
    alg: PlaneKey,
) -> (Vec<CertificateDer<'static>>, Vec<u8>) {
    let mut p = rcgen::CertificateParams::new(vec![]).unwrap();
    p.distinguished_name = rcgen::DistinguishedName::new();
    p.subject_alt_names = vec![
        rcgen::SanType::URI(uri.try_into().unwrap()),
        rcgen::SanType::DnsName("evil.example".try_into().unwrap()),
    ];
    let kp = rcgen::KeyPair::generate_for(alg.rcgen_algorithm()).unwrap();
    let leaf = p.signed_by(&kp, &ca.issuer()).unwrap();
    (
        vec![
            CertificateDer::from(leaf.der().to_vec()),
            CertificateDer::from(ca.der.clone()),
        ],
        kp.serialize_der(),
    )
}

/// A real intermediate CA signed by `root` (for the root-only-anchor topology test).
fn mk_intermediate(root: &Ca) -> Ca {
    mk_intermediate_with(root, P384)
}
fn mk_intermediate_with(root: &Ca, alg: PlaneKey) -> Ca {
    let mut p = rcgen::CertificateParams::new(vec![]).unwrap();
    p.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
    let kp = rcgen::KeyPair::generate_for(alg.rcgen_algorithm()).unwrap();
    let cert = p.signed_by(&kp, &root.issuer()).unwrap();
    Ca {
        der: cert.der().to_vec(),
        kp,
        params: p,
    }
}

fn server_cfg(
    chain: Vec<CertificateDer<'static>>,
    key: Vec<u8>,
    ca: &CaBundle,
    expect: Plane,
) -> Arc<maknae_crypto::rustls::ServerConfig> {
    let key = maknae_crypto::tls::load_private_key(PrivateKeyDer::Pkcs8(key.into())).unwrap();
    let resolver = Arc::new(crate::resolver::PlaneCertResolver::new_empty());
    resolver.slot().store(Some(Arc::new(
        maknae_crypto::rustls::sign::CertifiedKey::new(chain, key),
    )));
    let verifier = crate::plane_verify::PlaneClientCertVerifier::new(ca, expect, "d").unwrap();
    Arc::new(crate::tls::plane_server_config(verifier, resolver).unwrap())
}

fn client_cfg(
    chain: Vec<CertificateDer<'static>>,
    key: Vec<u8>,
    ca: &CaBundle,
    expect: Plane,
    with_cert: bool,
) -> Arc<maknae_crypto::rustls::ClientConfig> {
    let verifier = crate::plane_verify::PlaneServerCertVerifier::new(ca, expect, "d").unwrap();
    let auth = with_cert.then(|| (chain, PrivateKeyDer::Pkcs8(key.into())));
    Arc::new(crate::tls::plane_client_config(verifier, auth).unwrap())
}

async fn handshake(
    server: Arc<maknae_crypto::rustls::ServerConfig>,
    client: Arc<maknae_crypto::rustls::ClientConfig>,
) -> Result<(), String> {
    use tokio_rustls::{TlsAcceptor, TlsConnector};
    let (c, s) = tokio::io::duplex(16 * 1024);
    let acceptor = TlsAcceptor::from(server);
    let connector = TlsConnector::from(client);
    let name = maknae_crypto::rustls::pki_types::ServerName::try_from("maknae.invalid").unwrap();
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

/// **THE SEAM.** Every other test in this file uses `tokio::io::duplex`, and the
/// descriptor adapters are unit-tested on a bare `socketpair` — so until this test
/// nothing exercised the assembled path: a real Unix socket, `FdSender` beneath the
/// TLS connector, `FdCollector` beneath the TLS acceptor, and rustls doing its
/// byte-stream work on top.
///
/// That gap is exactly where the failure this design exists to prevent would hide.
/// `SCM_RIGHTS` is ancillary data on the raw socket; rustls can neither see nor carry
/// it, and a plain `read(2)` DESTROYS it with no error whatsoever (measured: the frame
/// bytes arrive intact and the kernel closes the descriptor). Both halves passing in
/// isolation proves nothing about them meeting.
///
/// Arming happens AFTER the handshake, deliberately and necessarily: the handshake's
/// own writes would otherwise consume the descriptor before the request frame exists.
#[tokio::test]
async fn a_delegated_descriptor_survives_the_assembled_tls_path() {
    use std::os::fd::OwnedFd;
    use std::os::unix::fs::MetadataExt;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio_rustls::{TlsAcceptor, TlsConnector};

    provider();
    let ca = mk_ca();
    let (kchain, kkey) = mk_leaf(&ca, "maknae://d/plane/kernel", false);
    let (cchain, ckey) = mk_leaf(&ca, "maknae://d/plane/cli", false);
    let server = server_cfg(kchain, kkey, &cab(&ca), Plane::Cli);
    let client = client_cfg(cchain, ckey, &cab(&ca), Plane::Kernel, true);

    // A REAL socket pair — a duplex pipe cannot carry ancillary data at all, which is
    // why every other test here is blind to this property.
    let (client_raw, server_raw) = tokio::net::UnixStream::pair().expect("socketpair");
    let sender = maknae_plane::FdSender::new(client_raw);
    let armer = sender.armer();
    let collector = maknae_plane::FdCollector::new(server_raw, 8);
    let delegated = collector.delegated();

    let acceptor = TlsAcceptor::from(server);
    let connector = TlsConnector::from(client);
    let srv = tokio::spawn(async move {
        let mut tls = acceptor.accept(collector).await.expect("server handshake");
        let mut buf = [0u8; 5];
        tls.read_exact(&mut buf)
            .await
            .expect("server reads the frame");
        buf
    });

    let name = maknae_crypto::rustls::pki_types::ServerName::try_from("maknae.invalid").unwrap();
    let mut tls = connector
        .connect(name, sender)
        .await
        .expect("client handshake");

    let dir = tempfile::tempdir().expect("tempdir");
    let obj = dir.path().join("obj");
    std::fs::write(&obj, b"delegated").expect("write fixture");
    let f = std::fs::File::open(&obj).expect("an object to delegate");
    let want = f.metadata().expect("stat").ino();
    armer.arm(OwnedFd::from(f));
    tls.write_all(b"FRAME")
        .await
        .expect("client writes the frame");
    tls.flush().await.expect("flush");

    assert_eq!(
        &srv.await.expect("server task"),
        b"FRAME",
        "TLS carried the bytes"
    );
    let got = delegated
        .take()
        .expect("the descriptor must survive the assembled path, not only the bare socket");
    assert_eq!(
        std::fs::File::from(got).metadata().expect("stat").ino(),
        want,
        "and it names the same object the client opened"
    );
    drop(tls);
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
async fn root_only_anchor_with_presented_intermediate() {
    // The load-bearing pin property: RootCertStore holds the ROOT only; the intermediate
    // must ride the peer-presented chain, never be trusted as an anchor. Real 3-level
    // topology root→int→leaf (unlike the other tests where root==int).
    provider();
    let root = mk_ca();
    let int = mk_intermediate(&root);
    let cab = CaBundle {
        root_der: root.der.clone(),
        int_der: int.der.clone(),
    };
    // leaves signed by the INTERMEDIATE; mk_leaf presents chain [leaf, int].
    let (kchain, kkey) = mk_leaf(&int, "maknae://d/plane/kernel", false);
    let (cchain, ckey) = mk_leaf(&int, "maknae://d/plane/cli", false);
    // Happy: present [leaf, int] → path-builds to the pinned root.
    let s = server_cfg(kchain.clone(), kkey.clone(), &cab, Plane::Cli);
    let c = client_cfg(cchain.clone(), ckey.clone(), &cab, Plane::Kernel, true);
    handshake(s, c)
        .await
        .expect("root-anchored, intermediate-presented mutual auth");

    // Withhold the intermediate: present [leaf] ONLY → cannot path-build to the root → fail.
    let (mut kleaf, mut cleaf) = (kchain, cchain);
    kleaf.truncate(1);
    cleaf.truncate(1);
    let s2 = server_cfg(kleaf, kkey, &cab, Plane::Cli);
    let c2 = client_cfg(cleaf, ckey, &cab, Plane::Kernel, true);
    assert!(
        handshake(s2, c2).await.is_err(),
        "withheld intermediate must fail (root is the only anchor)"
    );
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

// ---- accept() rejection surfacing (Task 5): needs a REAL UnixStream socketpair, since the
// in-process `tokio::io::duplex` used above cannot carry `SO_PEERCRED` — peer-creds are the
// whole point of `AcceptRejection`. Unix-only, like `socket.rs`/`peercred.rs`/`stream.rs`.
#[cfg(unix)]
mod accept_reject {
    use super::*;
    use crate::stream::accept_on;
    use crate::{AcceptRejection, RejectReason};
    use std::os::unix::fs::PermissionsExt;
    use std::time::Duration;

    /// A private (0700) temp dir — `socket::bind_listener` refuses a group/other-writable
    /// parent (see `socket.rs`).
    fn tmp_sock_dir(tag: &str) -> std::path::PathBuf {
        let p = std::env::temp_dir().join(format!("mv-accept-reject-{}-{tag}", std::process::id()));
        let _ = std::fs::remove_dir_all(&p);
        std::fs::create_dir_all(&p).unwrap();
        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o700)).unwrap();
        p
    }

    /// Drive `accept_on` (the real socket-backed accept path `PlaneListener::accept`
    /// delegates to) against a client that presents a wrong-plane leaf. Expect a rejection
    /// that carries the captured `PeerCreds` (available since creds are captured BEFORE the
    /// handshake) tagged `WrongPlane` (our own SAN check) — `Handshake` is the documented
    /// fallback if the rustls error can't be classified more precisely.
    #[tokio::test]
    async fn accept_reject_wrong_plane_carries_peer_creds() {
        provider();
        let ca = mk_ca();
        let (kchain, kkey) = mk_leaf(&ca, "maknae://d/plane/kernel", false);
        // Server (daemon) presents kernel, expects the peer to prove plane == cli.
        let server_cfg = server_cfg(kchain, kkey, &cab(&ca), Plane::Cli);
        // Client presents a KERNEL leaf instead of the expected CLI leaf — wrong plane.
        let (wrong_chain, wrong_key) = mk_leaf(&ca, "maknae://d/plane/kernel", false);
        let client_cfg = client_cfg(wrong_chain, wrong_key, &cab(&ca), Plane::Kernel, true);

        let dir = tmp_sock_dir("wrong-plane");
        let sock = dir.join("s.sock");
        let listener = crate::socket::bind_listener(&sock, None).expect("bind real UDS");
        let acceptor = tokio_rustls::TlsAcceptor::from(server_cfg);

        let srv = tokio::spawn(async move {
            accept_on(
                &listener,
                &acceptor,
                Plane::Cli,
                "d",
                Duration::from_secs(5),
            )
            .await
        });

        let raw = crate::socket::connect(&sock).await.expect("client connect");
        let connector = tokio_rustls::TlsConnector::from(client_cfg);
        let name =
            maknae_crypto::rustls::pki_types::ServerName::try_from("maknae.invalid").unwrap();
        // The client's own connect() is expected to fail too (server sends a rejection
        // alert) — the assertion of record is on the SERVER's AcceptRejection below.
        let _ = connector.connect(name, raw).await;

        let result = srv.await.expect("server task did not panic");
        let _ = std::fs::remove_dir_all(&dir);
        match result {
            Err(AcceptRejection {
                peer_creds: Some(_),
                reason,
            }) => {
                assert!(
                    matches!(reason, RejectReason::WrongPlane | RejectReason::Handshake),
                    "expected WrongPlane (or Handshake fallback), got {reason:?}"
                );
            }
            Err(other) => panic!(
                "expected Err(AcceptRejection {{ peer_creds: Some(_), reason: WrongPlane | Handshake }}), got {other:?}"
            ),
            Ok(_) => panic!(
                "expected accept_on to REJECT a wrong-plane leaf, but it succeeded"
            ),
        }
    }
}

struct Pki {
    ca: Ca,
    kernel: (Vec<CertificateDer<'static>>, Vec<u8>),
    cli: (Vec<CertificateDer<'static>>, Vec<u8>),
}

fn pki() -> Pki {
    provider();
    let ca = mk_ca();
    let kernel = mk_leaf(&ca, "maknae://d/plane/kernel", false);
    let cli = mk_leaf(&ca, "maknae://d/plane/cli", false);
    Pki { ca, kernel, cli }
}

fn offering(
    groups: &[&'static dyn maknae_crypto::rustls::crypto::SupportedKxGroup],
) -> Arc<maknae_crypto::rustls::crypto::CryptoProvider> {
    Arc::new(maknae_crypto::rustls::crypto::CryptoProvider {
        kx_groups: groups.to_vec(),
        ..maknae_crypto::crypto_provider()
    })
}

fn peer_client(
    p: &Pki,
    groups: &[&'static dyn maknae_crypto::rustls::crypto::SupportedKxGroup],
) -> Arc<maknae_crypto::rustls::ClientConfig> {
    let verifier =
        crate::plane_verify::PlaneServerCertVerifier::new(&cab(&p.ca), Plane::Kernel, "d").unwrap();
    Arc::new(
        maknae_crypto::rustls::ClientConfig::builder_with_provider(offering(groups))
            .with_protocol_versions(&[&maknae_crypto::rustls::version::TLS13])
            .unwrap()
            .dangerous()
            .with_custom_certificate_verifier(verifier)
            .with_client_auth_cert(
                p.cli.0.clone(),
                PrivateKeyDer::Pkcs8(p.cli.1.clone().into()),
            )
            .unwrap(),
    )
}

fn peer_server(
    p: &Pki,
    groups: &[&'static dyn maknae_crypto::rustls::crypto::SupportedKxGroup],
) -> Arc<maknae_crypto::rustls::ServerConfig> {
    let verifier =
        crate::plane_verify::PlaneClientCertVerifier::new(&cab(&p.ca), Plane::Cli, "d").unwrap();
    Arc::new(
        maknae_crypto::rustls::ServerConfig::builder_with_provider(offering(groups))
            .with_protocol_versions(&[&maknae_crypto::rustls::version::TLS13])
            .unwrap()
            .with_client_cert_verifier(verifier)
            .with_single_cert(
                p.kernel.0.clone(),
                PrivateKeyDer::Pkcs8(p.kernel.1.clone().into()),
            )
            .unwrap(),
    )
}

type Outcome = Result<
    (
        maknae_crypto::rustls::NamedGroup,
        maknae_crypto::rustls::HandshakeKind,
    ),
    String,
>;

async fn negotiate(
    server: Arc<maknae_crypto::rustls::ServerConfig>,
    client: Arc<maknae_crypto::rustls::ClientConfig>,
) -> Outcome {
    use tokio_rustls::{TlsAcceptor, TlsConnector};
    let (c, s) = tokio::io::duplex(64 * 1024);
    let srv = tokio::spawn(async move {
        TlsAcceptor::from(server)
            .accept(s)
            .await
            .map(|_| ())
            .map_err(|e| e.to_string())
    });
    let name = maknae_crypto::rustls::pki_types::ServerName::try_from("maknae.invalid").unwrap();
    match TlsConnector::from(client).connect(name, c).await {
        Ok(stream) => {
            srv.await.unwrap()?;
            let conn = stream.get_ref().1;
            Ok((
                conn.negotiated_key_exchange_group().unwrap().name(),
                conn.handshake_kind().unwrap(),
            ))
        }
        Err(client_err) => Err(match srv.await.unwrap() {
            Err(server_err) => server_err,
            Ok(()) => client_err.to_string(),
        }),
    }
}

fn maknae_server(p: &Pki) -> Arc<maknae_crypto::rustls::ServerConfig> {
    server_cfg(
        p.kernel.0.clone(),
        p.kernel.1.clone(),
        &cab(&p.ca),
        Plane::Cli,
    )
}

fn maknae_client(p: &Pki) -> Arc<maknae_crypto::rustls::ClientConfig> {
    client_cfg(
        p.cli.0.clone(),
        p.cli.1.clone(),
        &cab(&p.ca),
        Plane::Kernel,
        true,
    )
}

fn group_names(
    groups: &[&dyn maknae_crypto::rustls::crypto::SupportedKxGroup],
) -> Vec<maknae_crypto::rustls::NamedGroup> {
    groups.iter().map(|g| g.name()).collect()
}

#[test]
fn both_plane_builders_carry_maknaes_key_exchange_groups() {
    let p = pki();
    let want = group_names(&maknae_crypto::KX_GROUPS);
    assert_eq!(
        group_names(&maknae_server(&p).crypto_provider().kx_groups),
        want
    );
    assert_eq!(
        group_names(&maknae_client(&p).crypto_provider().kx_groups),
        want
    );
}

#[tokio::test]
async fn a_peer_offering_each_supported_group_alone_completes_on_it_with_no_retry() {
    use maknae_crypto::rustls::crypto::aws_lc_rs::kx_group;
    let p = pki();
    for g in [
        kx_group::MLKEM1024,
        kx_group::X25519MLKEM768,
        kx_group::SECP256R1MLKEM768,
        kx_group::SECP384R1,
        kx_group::SECP256R1,
    ] {
        assert_eq!(
            negotiate(maknae_server(&p), peer_client(&p, &[g])).await,
            Ok((g.name(), maknae_crypto::rustls::HandshakeKind::Full)),
            "{:?}",
            g.name()
        );
    }
}

#[tokio::test]
async fn a_rhel_fips_shaped_client_gets_its_first_hybrid_with_no_retry() {
    use maknae_crypto::rustls::crypto::aws_lc_rs::kx_group;
    let p = pki();
    let client = peer_client(
        &p,
        &[
            kx_group::SECP256R1MLKEM768,
            kx_group::X25519MLKEM768,
            kx_group::SECP256R1,
        ],
    );
    assert_eq!(
        negotiate(maknae_server(&p), client).await,
        Ok((
            maknae_crypto::rustls::NamedGroup::secp256r1MLKEM768,
            maknae_crypto::rustls::HandshakeKind::Full
        ))
    );
}

#[tokio::test]
async fn the_server_takes_the_clients_order_not_its_own() {
    use maknae_crypto::rustls::crypto::aws_lc_rs::kx_group;
    let p = pki();
    let client = peer_client(&p, &[kx_group::SECP384R1, kx_group::MLKEM1024]);
    assert_eq!(
        negotiate(maknae_server(&p), client).await,
        Ok((
            maknae_crypto::rustls::NamedGroup::secp384r1,
            maknae_crypto::rustls::HandshakeKind::Full
        ))
    );
}

#[tokio::test]
async fn a_peer_offering_only_x25519_is_refused_for_no_common_group() {
    let p = pki();
    let client = peer_client(
        &p,
        &[maknae_crypto::rustls::crypto::aws_lc_rs::kx_group::X25519],
    );
    let err = negotiate(maknae_server(&p), client).await.unwrap_err();
    assert!(err.contains("NoKxGroupsInCommon"), "{err}");
}

#[tokio::test]
async fn maknaes_client_retries_once_onto_a_hybrid_only_server() {
    use maknae_crypto::rustls::crypto::aws_lc_rs::kx_group;
    let p = pki();
    assert_eq!(
        negotiate(
            peer_server(&p, &[kx_group::X25519MLKEM768]),
            maknae_client(&p)
        )
        .await,
        Ok((
            maknae_crypto::rustls::NamedGroup::X25519MLKEM768,
            maknae_crypto::rustls::HandshakeKind::FullWithHelloRetryRequest
        ))
    );
}

#[tokio::test]
async fn maknaes_client_and_server_agree_on_ml_kem_1024() {
    let p = pki();
    assert_eq!(
        negotiate(maknae_server(&p), maknae_client(&p)).await,
        Ok((
            maknae_crypto::rustls::NamedGroup::MLKEM1024,
            maknae_crypto::rustls::HandshakeKind::Full
        ))
    );
}

mod plane_key_algorithms {
    use super::*;
    use maknae_crypto::rustls::client::danger::{
        HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier,
    };
    use maknae_crypto::rustls::pki_types::{ServerName, UnixTime};
    use maknae_crypto::rustls::server::danger::{ClientCertVerified, ClientCertVerifier};
    use maknae_crypto::rustls::{DigitallySignedStruct, DistinguishedName, Error, SignatureScheme};
    use std::sync::Mutex;

    #[derive(Debug)]
    struct Recording<V> {
        inner: Arc<V>,
        seen: Arc<Mutex<Vec<SignatureScheme>>>,
    }

    impl ServerCertVerifier for Recording<crate::plane_verify::PlaneServerCertVerifier> {
        fn verify_server_cert(
            &self,
            e: &CertificateDer<'_>,
            i: &[CertificateDer<'_>],
            n: &ServerName<'_>,
            o: &[u8],
            t: UnixTime,
        ) -> Result<ServerCertVerified, Error> {
            self.inner.verify_server_cert(e, i, n, o, t)
        }
        fn verify_tls12_signature(
            &self,
            m: &[u8],
            c: &CertificateDer<'_>,
            d: &DigitallySignedStruct,
        ) -> Result<HandshakeSignatureValid, Error> {
            self.inner.verify_tls12_signature(m, c, d)
        }
        fn verify_tls13_signature(
            &self,
            m: &[u8],
            c: &CertificateDer<'_>,
            d: &DigitallySignedStruct,
        ) -> Result<HandshakeSignatureValid, Error> {
            self.seen.lock().unwrap().push(d.scheme);
            self.inner.verify_tls13_signature(m, c, d)
        }
        fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
            self.inner.supported_verify_schemes()
        }
    }

    impl ClientCertVerifier for Recording<crate::plane_verify::PlaneClientCertVerifier> {
        fn root_hint_subjects(&self) -> &[DistinguishedName] {
            self.inner.root_hint_subjects()
        }
        fn verify_client_cert(
            &self,
            e: &CertificateDer<'_>,
            i: &[CertificateDer<'_>],
            n: UnixTime,
        ) -> Result<ClientCertVerified, Error> {
            self.inner.verify_client_cert(e, i, n)
        }
        fn verify_tls12_signature(
            &self,
            m: &[u8],
            c: &CertificateDer<'_>,
            d: &DigitallySignedStruct,
        ) -> Result<HandshakeSignatureValid, Error> {
            self.inner.verify_tls12_signature(m, c, d)
        }
        fn verify_tls13_signature(
            &self,
            m: &[u8],
            c: &CertificateDer<'_>,
            d: &DigitallySignedStruct,
        ) -> Result<HandshakeSignatureValid, Error> {
            self.seen.lock().unwrap().push(d.scheme);
            self.inner.verify_tls13_signature(m, c, d)
        }
        fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
            self.inner.supported_verify_schemes()
        }
    }

    struct Seen {
        by_server: Arc<Mutex<Vec<SignatureScheme>>>,
        by_client: Arc<Mutex<Vec<SignatureScheme>>>,
    }

    async fn mutual_tls(
        cab: &CaBundle,
        kernel: (Vec<CertificateDer<'static>>, Vec<u8>),
        cli: (Vec<CertificateDer<'static>>, Vec<u8>),
    ) -> Result<Seen, String> {
        let seen = Seen {
            by_server: Arc::default(),
            by_client: Arc::default(),
        };
        let key =
            maknae_crypto::tls::load_private_key(PrivateKeyDer::Pkcs8(kernel.1.into())).unwrap();
        let resolver = Arc::new(crate::resolver::PlaneCertResolver::new_empty());
        resolver.slot().store(Some(Arc::new(
            maknae_crypto::rustls::sign::CertifiedKey::new(kernel.0, key),
        )));
        let client_verifier = Arc::new(Recording {
            inner: crate::plane_verify::PlaneClientCertVerifier::new(cab, Plane::Cli, "d").unwrap(),
            seen: Arc::clone(&seen.by_server),
        });
        let server_verifier = Arc::new(Recording {
            inner: crate::plane_verify::PlaneServerCertVerifier::new(cab, Plane::Kernel, "d")
                .unwrap(),
            seen: Arc::clone(&seen.by_client),
        });
        let server = Arc::new(crate::tls::plane_server_config(client_verifier, resolver).unwrap());
        let client = Arc::new(
            crate::tls::plane_client_config(
                server_verifier,
                Some((cli.0, PrivateKeyDer::Pkcs8(cli.1.into()))),
            )
            .unwrap(),
        );
        handshake(server, client).await.map(|()| seen)
    }

    #[tokio::test]
    async fn each_plane_key_completes_mutual_tls_and_both_sides_sign_with_it() {
        provider();
        for alg in PlaneKey::ALL {
            let ca = mk_ca_with(alg);
            let seen = mutual_tls(
                &cab(&ca),
                mk_leaf_with(&ca, "maknae://d/plane/kernel", false, alg),
                mk_leaf_with(&ca, "maknae://d/plane/cli", false, alg),
            )
            .await
            .unwrap_or_else(|e| panic!("{alg:?}: {e}"));
            let want = vec![alg.signature_scheme()];
            assert_eq!(
                *seen.by_client.lock().unwrap(),
                want,
                "kernel's CertificateVerify"
            );
            assert_eq!(
                *seen.by_server.lock().unwrap(),
                want,
                "cli's CertificateVerify"
            );
        }
    }

    #[tokio::test]
    async fn a_p384_root_over_an_ml_dsa_87_intermediate_and_leaves_completes() {
        provider();
        let root = mk_ca_with(P384);
        let int = mk_intermediate_with(&root, MLDSA87);
        let cab = CaBundle {
            root_der: root.der.clone(),
            int_der: int.der.clone(),
        };
        let seen = mutual_tls(
            &cab,
            mk_leaf_with(&int, "maknae://d/plane/kernel", false, MLDSA87),
            mk_leaf_with(&int, "maknae://d/plane/cli", false, MLDSA87),
        )
        .await
        .expect("mixed chain");
        assert_eq!(
            *seen.by_client.lock().unwrap(),
            vec![SignatureScheme::ML_DSA_87]
        );
        assert_eq!(
            *seen.by_server.lock().unwrap(),
            vec![SignatureScheme::ML_DSA_87]
        );
    }

    #[tokio::test]
    async fn the_negative_suite_fails_closed_for_every_plane_key() {
        provider();
        for alg in PlaneKey::ALL {
            let ca = mk_ca_with(alg);
            let foreign = mk_ca_with(alg);
            let kernel = || mk_leaf_with(&ca, "maknae://d/plane/kernel", false, alg);
            let cli = || mk_leaf_with(&ca, "maknae://d/plane/cli", false, alg);
            let cases = [
                (
                    "wrong plane",
                    kernel(),
                    mk_leaf_with(&ca, "maknae://d/plane/kernel", false, alg),
                ),
                (
                    "expired server leaf",
                    mk_leaf_with(&ca, "maknae://d/plane/kernel", true, alg),
                    cli(),
                ),
                (
                    "foreign CA",
                    mk_leaf_with(&foreign, "maknae://d/plane/kernel", false, alg),
                    cli(),
                ),
                (
                    "extra SAN",
                    kernel(),
                    mk_leaf_extra_san_with(&ca, "maknae://d/plane/cli", alg),
                ),
            ];
            for (what, k, c) in cases {
                assert!(
                    mutual_tls(&cab(&ca), k, c).await.is_err(),
                    "{alg:?}: {what} must fail"
                );
            }
            let (kchain, kkey) = kernel();
            let (cchain, ckey) = cli();
            let s = server_cfg(kchain, kkey, &cab(&ca), Plane::Cli);
            let c = client_cfg(cchain, ckey, &cab(&ca), Plane::Kernel, false);
            assert!(
                handshake(s, c).await.is_err(),
                "{alg:?}: absent client cert must fail"
            );
        }
    }
}
