#![cfg(test)]

//! In-process negative suite (Stage 2, CI) for both channel classes: mutual TLS for machine
//! peers, server-authenticated TLS for the certless client. Unit-module so it can reach pub(crate)
//! config/verifier constructors. Uses tokio duplex (no socket/peer-creds — those are unit
//! tested in socket.rs/peercred.rs). rcgen mints a test CA + kernel/cli leaves. This is
//! ADR-0005's negative suite: happy path + each negative fails closed.
use crate::{CaBundle, ChannelPeer, PeerAuth, Plane, SanRule, TrustBundle};
use maknae_crypto::plane_key::PlaneKey;
use maknae_crypto::rcgen;
use maknae_crypto::rustls::pki_types::{CertificateDer, PrivateKeyDer};
use std::sync::Arc;

fn provider() {
    maknae_crypto::init().unwrap();
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
const P384: PlaneKey = PlaneKey::EcdsaP384Sha384;
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

fn trust(ca: &CaBundle) -> Arc<TrustBundle> {
    TrustBundle::from_pins(&[ca]).unwrap()
}

fn client_verifier(ca: &CaBundle, expect: Plane) -> Arc<maknae_crypto::tls::ClientVerifierHandle> {
    crate::tls::client_verifier(&trust(ca), SanRule::for_plane(expect, "d")).unwrap()
}

fn server_verifier(ca: &CaBundle, expect: Plane) -> Arc<maknae_crypto::tls::ServerVerifierHandle> {
    crate::tls::server_verifier(&trust(ca), SanRule::for_plane(expect, "d")).unwrap()
}

fn plane_leaf(expect: Plane) -> PeerAuth {
    PeerAuth::PlaneLeaf {
        accept: SanRule::for_plane(expect, "d"),
    }
}

fn resolver_for(
    chain: Vec<CertificateDer<'static>>,
    key: Vec<u8>,
) -> Arc<crate::resolver::PlaneCertResolver> {
    let key = maknae_crypto::tls::load_private_key(
        &maknae_crypto::policy().unwrap().tls,
        PrivateKeyDer::Pkcs8(key.into()),
    )
    .unwrap();
    let resolver = Arc::new(crate::resolver::PlaneCertResolver::new_empty());
    resolver.slot().store(Some(Arc::new(
        maknae_crypto::rustls::sign::CertifiedKey::new(chain, key),
    )));
    resolver
}

fn server_cfg(
    chain: Vec<CertificateDer<'static>>,
    key: Vec<u8>,
    ca: &CaBundle,
    auth: &PeerAuth,
) -> Arc<maknae_crypto::rustls::ServerConfig> {
    crate::tls::server_config(&trust(ca), auth, resolver_for(chain, key)).unwrap()
}

fn client_cfg(
    chain: Vec<CertificateDer<'static>>,
    key: Vec<u8>,
    ca: &CaBundle,
    expect: Plane,
    with_cert: bool,
) -> Arc<maknae_crypto::rustls::ClientConfig> {
    let verifier = server_verifier(ca, expect);
    let auth = with_cert.then(|| (chain, PrivateKeyDer::Pkcs8(key.into())));
    Arc::new(crate::tls::plane_client_config(verifier, auth).unwrap())
}

const NO_CLIENT_CERT: &str = "peer sent no certificates";

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
    let (kchain, kkey) = mk_leaf(&ca, "spiffe://d/plane/kernel", false);
    let (cchain, ckey) = mk_leaf(&ca, "spiffe://d/plane/cli", false);
    let server = server_cfg(kchain, kkey, &cab(&ca), &PeerAuth::Certless);
    let client = client_cfg(cchain, ckey, &cab(&ca), Plane::Kernel, true);

    // A REAL socket pair — a duplex pipe cannot carry ancillary data at all, which is
    // why every other test here is blind to this property.
    let (client_raw, server_raw) = tokio::net::UnixStream::pair().expect("socketpair");
    let sender = maknae_plane::FdSender::new(client_raw);
    let armer = sender.armer();
    let collector = maknae_plane::FdCollector::new(server_raw, 8, None);
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
    let (kchain, kkey) = mk_leaf(&ca, "spiffe://d/plane/kernel", false);
    let (cchain, ckey) = mk_leaf(&ca, "spiffe://d/plane/cli", false);
    let s = server_cfg(kchain, kkey, &cab(&ca), &plane_leaf(Plane::Cli)); // daemon=kernel expects cli
    let c = client_cfg(cchain, ckey, &cab(&ca), Plane::Kernel, true); // cli expects kernel
    handshake(s, c).await.expect("mutual auth succeeds");
}

#[tokio::test]
async fn rejects_wrong_plane_client() {
    provider();
    let ca = mk_ca();
    let (kchain, kkey) = mk_leaf(&ca, "spiffe://d/plane/kernel", false);
    // CLI presents a KERNEL leaf (wrong plane) — server expects cli → reject.
    let (wrong, wkey) = mk_leaf(&ca, "spiffe://d/plane/kernel", false);
    let s = server_cfg(kchain, kkey, &cab(&ca), &plane_leaf(Plane::Cli));
    let c = client_cfg(wrong, wkey, &cab(&ca), Plane::Kernel, true);
    let e = handshake(s, c).await.unwrap_err();
    assert!(e.contains(crate::peer_auth::PLANE_URI_SAN_PREFIX), "{e}");
}

#[tokio::test]
async fn rejects_wrong_plane_server() {
    provider();
    let ca = mk_ca();
    let (wrong, wkey) = mk_leaf(&ca, "spiffe://d/plane/cli", false);
    let (cchain, ckey) = mk_leaf(&ca, "spiffe://d/plane/cli", false);
    let s = server_cfg(wrong, wkey, &cab(&ca), &plane_leaf(Plane::Cli));
    let c = client_cfg(cchain, ckey, &cab(&ca), Plane::Kernel, true);
    let e = handshake(s, c).await.unwrap_err();
    assert!(e.contains(crate::peer_auth::PLANE_URI_SAN_PREFIX), "{e}");
}

#[tokio::test]
async fn rejects_absent_client_cert() {
    provider();
    let ca = mk_ca();
    let (kchain, kkey) = mk_leaf(&ca, "spiffe://d/plane/kernel", false);
    let (cchain, ckey) = mk_leaf(&ca, "spiffe://d/plane/cli", false);
    let s = server_cfg(kchain, kkey, &cab(&ca), &plane_leaf(Plane::Cli));
    let c = client_cfg(cchain, ckey, &cab(&ca), Plane::Kernel, false); // no client cert
    assert_eq!(handshake(s, c).await, Err(NO_CLIENT_CERT.to_string()));
}

#[tokio::test]
async fn rejects_expired_server_leaf() {
    provider();
    let ca = mk_ca();
    let (kchain, kkey) = mk_leaf(&ca, "spiffe://d/plane/kernel", true); // expired
    let (cchain, ckey) = mk_leaf(&ca, "spiffe://d/plane/cli", false);
    for auth in [PeerAuth::Certless, plane_leaf(Plane::Cli)] {
        let s = server_cfg(kchain.clone(), kkey.clone(), &cab(&ca), &auth);
        let c = client_cfg(cchain.clone(), ckey.clone(), &cab(&ca), Plane::Kernel, true);
        assert!(handshake(s, c).await.is_err(), "{auth:?}");
    }
}

#[tokio::test]
async fn rejects_foreign_ca() {
    provider();
    let ca = mk_ca();
    let foreign = mk_ca();
    let (kchain, kkey) = mk_leaf(&foreign, "spiffe://d/plane/kernel", false); // foreign-signed
    let (cchain, ckey) = mk_leaf(&ca, "spiffe://d/plane/cli", false);
    for auth in [PeerAuth::Certless, plane_leaf(Plane::Cli)] {
        let s = server_cfg(kchain.clone(), kkey.clone(), &cab(&ca), &auth);
        let c = client_cfg(cchain.clone(), ckey.clone(), &cab(&ca), Plane::Kernel, true);
        assert!(handshake(s, c).await.is_err(), "{auth:?}");
    }
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
    let (kchain, kkey) = mk_leaf(&int, "spiffe://d/plane/kernel", false);
    let (cchain, ckey) = mk_leaf(&int, "spiffe://d/plane/cli", false);
    // Happy: present [leaf, int] → path-builds to the pinned root.
    let s = server_cfg(kchain.clone(), kkey.clone(), &cab, &plane_leaf(Plane::Cli));
    let c = client_cfg(cchain.clone(), ckey.clone(), &cab, Plane::Kernel, true);
    handshake(s, c)
        .await
        .expect("root-anchored, intermediate-presented mutual auth");

    // Withhold the intermediate: present [leaf] ONLY → cannot path-build to the root → fail.
    let (mut kleaf, mut cleaf) = (kchain, cchain);
    kleaf.truncate(1);
    cleaf.truncate(1);
    let s2 = server_cfg(kleaf, kkey, &cab, &plane_leaf(Plane::Cli));
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
    let (kchain, kkey) = mk_leaf(&ca, "spiffe://d/plane/kernel", false);
    // CLI leaf carries the correct plane URI PLUS a rogue DNS SAN → rejected (URI-SAN-only).
    let (cchain, ckey) = mk_leaf_extra_san(&ca, "spiffe://d/plane/cli");
    let s = server_cfg(kchain, kkey, &cab(&ca), &plane_leaf(Plane::Cli));
    let c = client_cfg(cchain, ckey, &cab(&ca), Plane::Kernel, true);
    let e = handshake(s, c).await.unwrap_err();
    assert!(e.contains(crate::peer_auth::PLANE_URI_SAN_PREFIX), "{e}");
}

fn agent_leaf_auth() -> PeerAuth {
    PeerAuth::PlaneLeaf {
        accept: SanRule::Agent {
            trust_domain: "d".to_string(),
        },
    }
}

#[tokio::test]
async fn agent_class_accepts_an_enrolled_agent_leaf() {
    provider();
    let ca = mk_ca();
    let (kchain, kkey) = mk_leaf(&ca, "spiffe://d/plane/kernel", false);
    let (achain, akey) = mk_leaf(&ca, "spiffe://d/plane/agent/hobi", false);
    let s = server_cfg(kchain, kkey, &cab(&ca), &agent_leaf_auth());
    let c = client_cfg(achain, akey, &cab(&ca), Plane::Kernel, true);
    handshake(s, c).await.expect("agent leaf admitted");
}

#[tokio::test]
async fn agent_class_refuses_a_plane_cli_leaf() {
    provider();
    let ca = mk_ca();
    let (kchain, kkey) = mk_leaf(&ca, "spiffe://d/plane/kernel", false);
    let (cchain, ckey) = mk_leaf(&ca, "spiffe://d/plane/cli", false);
    let s = server_cfg(kchain, kkey, &cab(&ca), &agent_leaf_auth());
    let c = client_cfg(cchain, ckey, &cab(&ca), Plane::Kernel, true);
    let e = handshake(s, c).await.unwrap_err();
    assert!(e.contains(crate::peer_auth::PLANE_URI_SAN_PREFIX), "{e}");
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
    /// handshake) tagged `WrongPlane` (our own SAN check).
    #[tokio::test]
    async fn accept_reject_wrong_plane_carries_peer_creds() {
        provider();
        let ca = mk_ca();
        let server = Server::new("wrong-plane", &ca);
        // Client presents a KERNEL leaf instead of the expected CLI leaf — wrong plane.
        let (wrong_chain, wrong_key) = mk_leaf(&ca, "spiffe://d/plane/kernel", false);
        let client_cfg = client_cfg(wrong_chain, wrong_key, &cab(&ca), Plane::Kernel, true);
        let trust = trust(&cab(&ca));
        let auth = plane_leaf(Plane::Cli);

        let client = async {
            let raw = crate::socket::connect(&server.sock)
                .await
                .expect("client connect");
            let name =
                maknae_crypto::rustls::pki_types::ServerName::try_from("maknae.invalid").unwrap();
            // The client's own connect() may fail too (server sends a rejection alert) —
            // the assertion of record is on the SERVER's AcceptRejection below.
            tokio_rustls::TlsConnector::from(client_cfg)
                .connect(name, raw)
                .await
        };
        let accepted = accept_on(
            &server.listener,
            &server.resolver,
            &trust,
            &auth,
            Duration::from_secs(5),
        );
        let (_client, result) = tokio::join!(client, accepted);
        match result {
            Err(AcceptRejection {
                peer_creds: Some(_),
                reason,
            }) => assert_eq!(reason, RejectReason::WrongPlane),
            Err(other) => panic!(
                "expected Err(AcceptRejection {{ peer_creds: Some(_), reason: WrongPlane }}), got {other:?}"
            ),
            Ok(_) => panic!("expected accept_on to REJECT a wrong-plane leaf, but it succeeded"),
        }
    }

    struct Server {
        listener: tokio::net::UnixListener,
        sock: std::path::PathBuf,
        dir: std::path::PathBuf,
        resolver: Arc<crate::resolver::PlaneCertResolver>,
    }

    impl Server {
        fn new(tag: &str, ca: &Ca) -> Self {
            let (kchain, kkey) = mk_leaf(ca, "spiffe://d/plane/kernel", false);
            let dir = tmp_sock_dir(tag);
            let sock = dir.join("s.sock");
            let listener = crate::socket::bind_listener(&sock, None).expect("bind real UDS");
            Server {
                listener,
                sock,
                dir,
                resolver: resolver_for(kchain, kkey),
            }
        }

        async fn attempt(
            &self,
            trust: &Arc<TrustBundle>,
            auth: &PeerAuth,
            client_cfg: Arc<maknae_crypto::rustls::ClientConfig>,
        ) -> Result<ChannelPeer, RejectReason> {
            let connector = tokio_rustls::TlsConnector::from(client_cfg);
            let name =
                maknae_crypto::rustls::pki_types::ServerName::try_from("maknae.invalid").unwrap();
            let client = async {
                let raw = crate::socket::connect(&self.sock)
                    .await
                    .expect("client connect");
                connector.connect(name, raw).await
            };
            let server = accept_on(
                &self.listener,
                &self.resolver,
                trust,
                auth,
                Duration::from_secs(5),
            );
            let (_client, server) = tokio::join!(client, server);
            server.map(|s| s.peer().clone()).map_err(|r| r.reason)
        }
    }

    impl Drop for Server {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.dir);
        }
    }

    #[tokio::test]
    async fn san_identity_admits_only_its_san() {
        provider();
        let ca = mk_ca();
        let server = Server::new("san-identity", &ca);
        let trust = trust(&cab(&ca));
        let auth = plane_leaf(Plane::Cli);
        let client_with = |(chain, key)| client_cfg(chain, key, &cab(&ca), Plane::Kernel, true);
        let cli = client_with(mk_leaf(&ca, "spiffe://d/plane/cli", false));
        let kernel = client_with(mk_leaf(&ca, "spiffe://d/plane/kernel", false));
        let extra = client_with(mk_leaf_extra_san(&ca, "spiffe://d/plane/cli"));

        let admitted = server.attempt(&trust, &auth, cli).await;
        let wrong = server.attempt(&trust, &auth, Arc::clone(&kernel)).await;
        let extra_san = server.attempt(&trust, &auth, Arc::clone(&extra)).await;

        assert_eq!(
            admitted,
            Ok(ChannelPeer::Certified("spiffe://d/plane/cli".to_string()))
        );
        assert_eq!(wrong, Err(RejectReason::WrongPlane));
        assert_eq!(extra_san, Err(RejectReason::WrongPlane));
        let (kchain, kkey) = mk_leaf(&ca, "spiffe://d/plane/kernel", false);
        let in_handshake = server_cfg(kchain, kkey, &cab(&ca), &auth);
        for refused in [kernel, extra] {
            let e = handshake(Arc::clone(&in_handshake), refused)
                .await
                .unwrap_err();
            assert!(
                e.contains(crate::peer_auth::PLANE_URI_SAN_PREFIX),
                "refused in the handshake by the identity check, got {e}"
            );
        }
    }

    #[tokio::test]
    async fn client_class_completes_with_no_client_cert() {
        provider();
        let ca = mk_ca();
        let server = Server::new("certless-none", &ca);
        let (cchain, ckey) = mk_leaf(&ca, "spiffe://d/plane/cli", false);
        let client = client_cfg(cchain, ckey, &cab(&ca), Plane::Kernel, false);
        assert_eq!(
            server
                .attempt(&trust(&cab(&ca)), &PeerAuth::Certless, client)
                .await,
            Ok(ChannelPeer::Certless)
        );
    }

    #[tokio::test]
    async fn machine_class_refuses_a_certless_client_in_the_handshake() {
        provider();
        let ca = mk_ca();
        let server = Server::new("plane-leaf-certless", &ca);
        let (cchain, ckey) = mk_leaf(&ca, "spiffe://d/plane/cli", false);
        let client = client_cfg(cchain, ckey, &cab(&ca), Plane::Kernel, false);
        assert_eq!(
            server
                .attempt(&trust(&cab(&ca)), &plane_leaf(Plane::Cli), client)
                .await,
            Err(RejectReason::Handshake)
        );
    }

    #[tokio::test]
    async fn client_class_reports_certless_even_when_the_client_offers_a_leaf() {
        provider();
        let ca = mk_ca();
        let server = Server::new("certless-offered", &ca);
        let (cchain, ckey) = mk_leaf(&ca, "spiffe://d/plane/cli", false);
        let client = client_cfg(cchain, ckey, &cab(&ca), Plane::Kernel, true);
        assert_eq!(
            server
                .attempt(&trust(&cab(&ca)), &PeerAuth::Certless, client)
                .await,
            Ok(ChannelPeer::Certless)
        );
    }

    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn the_listener_passes_credentials_to_accepted_sockets() {
        use nix::sys::socket::{getsockopt, sockopt::PassCred};
        provider();
        let server = Server::new("passcred", &mk_ca());
        let _client = crate::socket::connect(&server.sock)
            .await
            .expect("client connect");
        let (accepted, _) = server.listener.accept().await.expect("accept");
        assert!(getsockopt(&accepted, PassCred).expect("SO_PASSCRED"));
    }

    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn bytes_written_before_accept_carry_credentials() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        provider();
        let server = Server::new("before-accept", &mk_ca());
        let mut client = crate::socket::connect(&server.sock)
            .await
            .expect("client connect");
        client
            .write_all(b"EARLY")
            .await
            .expect("write before accept");
        let (accepted, _) = server.listener.accept().await.expect("accept");
        let creds = crate::peercred::capture(&accepted).expect("peer creds");
        let expected = maknae_plane::ExpectedSender {
            pid: i32::try_from(creds.pid.expect("pid")).expect("pid fits"),
            uid: creds.uid,
        };
        let mut collector = maknae_plane::FdCollector::new(accepted, 4, Some(expected));
        let verdict = collector.sender_verdict();
        let mut buf = [0u8; 5];
        collector
            .read_exact(&mut buf)
            .await
            .expect("the early bytes carry the sender's credentials");
        assert_eq!(&buf, b"EARLY");
        assert!(!verdict.mismatched());
    }

    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn the_bound_sender_completes_a_handshake_with_passcred_on() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        provider();
        let ca = mk_ca();
        let server = Server::new("bound-sender", &ca);
        let (cchain, ckey) = mk_leaf(&ca, "spiffe://d/plane/cli", false);
        let client_cfg = client_cfg(cchain, ckey, &cab(&ca), Plane::Kernel, false);
        let trust = trust(&cab(&ca));
        let client = async {
            let raw = crate::socket::connect(&server.sock)
                .await
                .expect("client connect");
            let name =
                maknae_crypto::rustls::pki_types::ServerName::try_from("maknae.invalid").unwrap();
            let mut tls = tokio_rustls::TlsConnector::from(client_cfg)
                .connect(name, raw)
                .await
                .expect("client handshake");
            tls.write_all(b"FRAME").await.expect("write the frame");
            tls.flush().await.expect("flush");
            tls
        };
        let accepted = accept_on(
            &server.listener,
            &server.resolver,
            &trust,
            &PeerAuth::Certless,
            Duration::from_secs(5),
        );
        let (_client, accepted) = tokio::join!(client, accepted);
        let mut stream = accepted.expect("the bound sender is admitted");
        let mut buf = [0u8; 5];
        stream.read_exact(&mut buf).await.expect("one frame");
        assert_eq!(&buf, b"FRAME");
        assert!(!stream.sender_verdict().mismatched());
    }

    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn a_mismatched_sender_is_refused_during_the_handshake() {
        provider();
        let ca = mk_ca();
        let server = Server::new("mismatched-sender", &ca);
        let (cchain, ckey) = mk_leaf(&ca, "spiffe://d/plane/cli", false);
        let client_cfg = client_cfg(cchain, ckey, &cab(&ca), Plane::Kernel, false);
        let trust = trust(&cab(&ca));
        let client = async {
            let raw = crate::socket::connect(&server.sock)
                .await
                .expect("client connect");
            let name =
                maknae_crypto::rustls::pki_types::ServerName::try_from("maknae.invalid").unwrap();
            tokio_rustls::TlsConnector::from(client_cfg)
                .connect(name, raw)
                .await
        };
        let accepted = async {
            let (raw, creds) = crate::stream::accept_raw_on(&server.listener)
                .await
                .expect("raw accept");
            let foreign = crate::PeerCreds {
                uid: creds.uid + 1,
                ..creds
            };
            crate::stream::finish_handshake_on(
                &server.resolver,
                &trust,
                &PeerAuth::Certless,
                raw,
                foreign,
                Duration::from_secs(5),
            )
            .await
        };
        let (_client, accepted) = tokio::join!(client, accepted);
        match accepted {
            Err(AcceptRejection { reason, .. }) => assert_eq!(reason, RejectReason::SenderMismatch),
            Ok(_) => panic!("a sender other than the connecting uid must be refused"),
        }
    }

    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn a_connection_without_a_peer_pid_is_refused() {
        provider();
        let ca = mk_ca();
        let server = Server::new("no-peer-pid", &ca);
        let _client = crate::socket::connect(&server.sock)
            .await
            .expect("client connect");
        let (raw, creds) = crate::stream::accept_raw_on(&server.listener)
            .await
            .expect("raw accept");
        let got = crate::stream::finish_handshake_on(
            &server.resolver,
            &trust(&cab(&ca)),
            &PeerAuth::Certless,
            raw,
            crate::PeerCreds { pid: None, ..creds },
            Duration::from_secs(5),
        )
        .await;
        match got {
            Err(AcceptRejection { reason, .. }) => {
                assert_eq!(reason, RejectReason::PeerCredCapture)
            }
            Ok(_) => panic!("a connection with no peer pid cannot be bound to a sender"),
        }
    }

    #[tokio::test]
    async fn swapping_the_trust_bundle_changes_which_peer_verifies() {
        provider();
        let ca_a = mk_ca();
        let ca_b = mk_ca();
        let server = Server::new("trust-swap", &ca_a);
        let trust = trust(&cab(&ca_a));
        let auth = plane_leaf(Plane::Cli);
        let client_of = |ca: &Ca| {
            let (chain, key) = mk_leaf(ca, "spiffe://d/plane/cli", false);
            client_cfg(chain, key, &cab(&ca_a), Plane::Kernel, true)
        };
        let from_a = client_of(&ca_a);
        let from_b = client_of(&ca_b);
        let cli = Ok(ChannelPeer::Certified("spiffe://d/plane/cli".to_string()));

        assert_eq!(
            server.attempt(&trust, &auth, Arc::clone(&from_a)).await,
            cli
        );
        trust.replace(&[&cab(&ca_b)]).unwrap();
        assert_eq!(
            server.attempt(&trust, &auth, from_a).await,
            Err(RejectReason::ChainOrCa)
        );
        assert_eq!(server.attempt(&trust, &auth, from_b).await, cli);
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
    let kernel = mk_leaf(&ca, "spiffe://d/plane/kernel", false);
    let cli = mk_leaf(&ca, "spiffe://d/plane/cli", false);
    Pki { ca, kernel, cli }
}

fn offering(
    groups: &[maknae_crypto::KxGroup],
) -> Arc<maknae_crypto::rustls::crypto::CryptoProvider> {
    let mut p = maknae_crypto::policy().unwrap().tls.clone();
    p.kx_groups = groups.to_vec();
    Arc::new(maknae_crypto::tls::crypto_provider(&p).unwrap())
}

#[expect(clippy::disallowed_methods)]
fn peer_client(
    p: &Pki,
    groups: &[maknae_crypto::KxGroup],
) -> Arc<maknae_crypto::rustls::ClientConfig> {
    let verifier = server_verifier(&cab(&p.ca), Plane::Kernel);
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

#[expect(clippy::disallowed_methods)]
fn peer_server(
    p: &Pki,
    groups: &[maknae_crypto::KxGroup],
) -> Arc<maknae_crypto::rustls::ServerConfig> {
    let verifier = client_verifier(&cab(&p.ca), Plane::Cli);
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
        &plane_leaf(Plane::Cli),
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

async fn second_session_kind(
    server: Arc<maknae_crypto::rustls::ServerConfig>,
    client: Arc<maknae_crypto::rustls::ClientConfig>,
) -> maknae_crypto::rustls::HandshakeKind {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let mut kind = None;
    for _ in 0..2 {
        let (c, s) = tokio::io::duplex(16 * 1024);
        let acceptor = tokio_rustls::TlsAcceptor::from(Arc::clone(&server));
        let srv = tokio::spawn(async move {
            let mut tls = acceptor.accept(s).await.unwrap();
            tls.write_all(b"x").await.unwrap();
            tls.flush().await.unwrap();
            tls
        });
        let name =
            maknae_crypto::rustls::pki_types::ServerName::try_from("maknae.invalid").unwrap();
        let mut tls = tokio_rustls::TlsConnector::from(Arc::clone(&client))
            .connect(name, c)
            .await
            .unwrap();
        let mut byte = [0u8; 1];
        tls.read_exact(&mut byte).await.unwrap();
        kind = tls.get_ref().1.handshake_kind();
        drop(srv.await.unwrap());
    }
    kind.unwrap()
}

#[tokio::test]
async fn neither_plane_side_resumes_a_session() {
    use maknae_crypto::rustls::client::Resumption;
    use maknae_crypto::rustls::server::ServerSessionMemoryCache;
    use maknae_crypto::rustls::HandshakeKind;
    let p = pki();
    let server = maknae_server(&p);
    let client = maknae_client(&p);
    let mut resuming_server = (*server).clone();
    resuming_server.send_tls13_tickets = 2;
    resuming_server.session_storage = ServerSessionMemoryCache::new(32);
    let resuming_server = Arc::new(resuming_server);
    let mut resuming_client = (*client).clone();
    resuming_client.resumption = Resumption::default();
    let resuming_client = Arc::new(resuming_client);

    assert_eq!(
        second_session_kind(Arc::clone(&resuming_server), Arc::clone(&resuming_client)).await,
        HandshakeKind::Resumed
    );
    assert_eq!(
        second_session_kind(server, Arc::clone(&resuming_client)).await,
        HandshakeKind::Full
    );
    let certless = server_cfg(
        p.kernel.0.clone(),
        p.kernel.1.clone(),
        &cab(&p.ca),
        &PeerAuth::Certless,
    );
    assert_eq!(
        second_session_kind(certless, resuming_client).await,
        HandshakeKind::Full
    );
    assert_eq!(
        second_session_kind(resuming_server, client).await,
        HandshakeKind::Full
    );
}

fn group_names(
    groups: &[&dyn maknae_crypto::rustls::crypto::SupportedKxGroup],
) -> Vec<maknae_crypto::rustls::NamedGroup> {
    groups.iter().map(|g| g.name()).collect()
}

#[test]
fn both_plane_builders_carry_maknaes_key_exchange_groups() {
    let p = pki();
    let want = maknae_crypto::policy()
        .unwrap()
        .tls
        .kx_groups
        .iter()
        .map(|g| maknae_crypto::rustls::NamedGroup::from(g.iana()))
        .collect::<Vec<_>>();
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
    let p = pki();
    for g in maknae_crypto::policy()
        .unwrap()
        .tls
        .kx_groups
        .iter()
        .copied()
    {
        let name = maknae_crypto::rustls::NamedGroup::from(g.iana());
        assert_eq!(
            negotiate(maknae_server(&p), peer_client(&p, &[g])).await,
            Ok((name, maknae_crypto::rustls::HandshakeKind::Full)),
            "{name:?}"
        );
    }
}

#[tokio::test]
async fn a_rhel_fips_shaped_client_gets_its_first_hybrid_with_no_retry() {
    use maknae_crypto::KxGroup;
    let p = pki();
    let client = peer_client(
        &p,
        &[
            KxGroup::Secp256r1MlKem768,
            KxGroup::X25519MlKem768,
            KxGroup::Secp256r1,
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
    use maknae_crypto::KxGroup;
    let p = pki();
    let client = peer_client(&p, &[KxGroup::Secp384r1, KxGroup::MlKem1024]);
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
    let client = peer_client(&p, &[maknae_crypto::KxGroup::X25519]);
    let err = negotiate(maknae_server(&p), client).await.unwrap_err();
    assert!(err.contains("NoKxGroupsInCommon"), "{err}");
}

#[tokio::test]
async fn maknaes_client_retries_once_onto_a_hybrid_only_server() {
    use maknae_crypto::KxGroup;
    let p = pki();
    assert_eq!(
        negotiate(
            peer_server(&p, &[KxGroup::X25519MlKem768]),
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

    impl ServerCertVerifier for Recording<maknae_crypto::tls::ServerVerifierHandle> {
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

    impl ClientCertVerifier for Recording<maknae_crypto::tls::ClientVerifierHandle> {
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
        let key = maknae_crypto::tls::load_private_key(
            &maknae_crypto::policy().unwrap().tls,
            PrivateKeyDer::Pkcs8(kernel.1.into()),
        )
        .unwrap();
        let resolver = Arc::new(crate::resolver::PlaneCertResolver::new_empty());
        resolver.slot().store(Some(Arc::new(
            maknae_crypto::rustls::sign::CertifiedKey::new(kernel.0, key),
        )));
        let client_verifier = Arc::new(Recording {
            inner: client_verifier(cab, Plane::Cli),
            seen: Arc::clone(&seen.by_server),
        });
        let server_verifier = Arc::new(Recording {
            inner: server_verifier(cab, Plane::Kernel),
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
                mk_leaf_with(&ca, "spiffe://d/plane/kernel", false, alg),
                mk_leaf_with(&ca, "spiffe://d/plane/cli", false, alg),
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
            mk_leaf_with(&int, "spiffe://d/plane/kernel", false, MLDSA87),
            mk_leaf_with(&int, "spiffe://d/plane/cli", false, MLDSA87),
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
            let kernel = || mk_leaf_with(&ca, "spiffe://d/plane/kernel", false, alg);
            let cli = || mk_leaf_with(&ca, "spiffe://d/plane/cli", false, alg);
            let cases = [
                (
                    "wrong plane",
                    kernel(),
                    mk_leaf_with(&ca, "spiffe://d/plane/kernel", false, alg),
                ),
                (
                    "expired server leaf",
                    mk_leaf_with(&ca, "spiffe://d/plane/kernel", true, alg),
                    cli(),
                ),
                (
                    "foreign CA",
                    mk_leaf_with(&foreign, "spiffe://d/plane/kernel", false, alg),
                    cli(),
                ),
                (
                    "extra SAN",
                    kernel(),
                    mk_leaf_extra_san_with(&ca, "spiffe://d/plane/cli", alg),
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
            let s = server_cfg(kchain, kkey, &cab(&ca), &plane_leaf(Plane::Cli));
            let c = client_cfg(cchain, ckey, &cab(&ca), Plane::Kernel, false);
            assert_eq!(
                handshake(s, c).await,
                Err(NO_CLIENT_CERT.to_string()),
                "{alg:?}: absent client cert must fail"
            );
        }
    }
}
