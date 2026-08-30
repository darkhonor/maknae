#![cfg(test)]

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

/// A real intermediate CA signed by `root` (for the root-only-anchor topology test).
fn mk_intermediate(root: &Ca) -> Ca {
    let mut p = rcgen::CertificateParams::new(vec![]).unwrap();
    p.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
    let kp = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P384_SHA384).unwrap();
    let cert = p.signed_by(&kp, &root.cert, &root.kp).unwrap();
    Ca {
        der: cert.der().to_vec(),
        kp,
        cert,
    }
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

    let name = rustls::pki_types::ServerName::try_from("maknae.invalid").unwrap();
    let mut tls = connector
        .connect(name, sender)
        .await
        .expect("client handshake");

    let f = std::fs::File::open("/etc/hostname").expect("an object to delegate");
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
        let name = rustls::pki_types::ServerName::try_from("maknae.invalid").unwrap();
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
