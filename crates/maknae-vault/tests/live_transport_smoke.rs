//! Gated live loopback — runbook ch.2. Stands up BOTH planes in one process against the
//! operator's real Vault (two config dirs, each with its own minted leaf), does a real
//! mTLS + peer-cred round-trip over a real UDS. #[ignore]; operator-present only.
//!
//!   MAKNAE_KERNEL_DIR=~/.maknae MAKNAE_CLI_DIR=~/.maknae-cli \
//!     cargo test -p maknae-vault --test live_transport_smoke -- --ignored --nocapture
#![cfg(unix)]
use tokio::io::{AsyncReadExt, AsyncWriteExt};

#[tokio::test]
#[ignore = "needs live Vault + two minted plane identities + a real UDS (operator-gated)"]
async fn plane_to_plane_roundtrip() {
    rustls::crypto::aws_lc_rs::default_provider()
        .install_default()
        .ok();
    let kdir = std::env::var("MAKNAE_KERNEL_DIR").expect("set MAKNAE_KERNEL_DIR");
    let cdir = std::env::var("MAKNAE_CLI_DIR").expect("set MAKNAE_CLI_DIR");
    let sock = std::env::temp_dir().join(format!("maknae-live-{}.sock", std::process::id()));

    let kclient = maknae_vault::PlaneClient::from_config_dir(
        std::path::Path::new(&kdir),
        maknae_vault::Plane::Kernel,
    )
    .unwrap();
    kclient.mint().await.expect("kernel mint");
    let kca = maknae_vault::load_ca_pin(std::path::Path::new(&kdir)).unwrap();
    let listener = maknae_vault::PlaneListener::bind(&sock, &kclient, &kca).unwrap();

    let cclient = maknae_vault::PlaneClient::from_config_dir(
        std::path::Path::new(&cdir),
        maknae_vault::Plane::Cli,
    )
    .unwrap();
    cclient.mint().await.expect("cli mint");
    let cca = maknae_vault::load_ca_pin(std::path::Path::new(&cdir)).unwrap();

    let srv = tokio::spawn(async move {
        let mut s = listener.accept().await.expect("accept");
        assert_eq!(s.peer_uri_san(), "maknae://vmhomelab/plane/cli");
        let mut buf = [0u8; 5];
        s.read_exact(&mut buf).await.unwrap();
        s.write_all(b"pong!").await.unwrap();
        s.flush().await.unwrap();
        buf
    });
    let mut c = maknae_vault::PlaneConnector::connect(&sock, &cclient, &cca)
        .await
        .expect("connect");
    assert_eq!(c.peer_uri_san(), "maknae://vmhomelab/plane/kernel");
    c.write_all(b"hello").await.unwrap();
    c.flush().await.unwrap();
    let mut resp = [0u8; 5];
    c.read_exact(&mut resp).await.unwrap();
    assert_eq!(&resp, b"pong!");
    assert_eq!(&srv.await.unwrap(), b"hello");
    kclient.shutdown().await;
    cclient.shutdown().await;
    let _ = std::fs::remove_file(&sock);
    println!("LIVE TRANSPORT OK: kernel<->cli mTLS + peer-creds round-trip over UDS");
}
