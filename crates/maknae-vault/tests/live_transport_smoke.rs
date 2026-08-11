//! Gated live loopback — runbook ch.2. Stands up BOTH planes in one process against the
//! operator's real Vault (two config dirs, each with its own minted leaf), does a real
//! mTLS + peer-cred round-trip over a real UDS. #[ignore]; operator-present only.
//!
//!   MAKNAE_KERNEL_DIR=~/.maknae MAKNAE_CLI_DIR=~/.maknae-cli \
//!     cargo test -p maknae-vault --test live_transport_smoke -- --ignored --nocapture
#![cfg(unix)]
use std::os::unix::fs::PermissionsExt;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

#[tokio::test]
#[ignore = "needs live Vault + two minted plane identities + a real UDS (operator-gated)"]
async fn plane_to_plane_roundtrip() {
    rustls::crypto::aws_lc_rs::default_provider()
        .install_default()
        .ok();
    let kdir = std::env::var("MAKNAE_KERNEL_DIR").expect("set MAKNAE_KERNEL_DIR");
    let cdir = std::env::var("MAKNAE_CLI_DIR").expect("set MAKNAE_CLI_DIR");
    // The socket's parent dir must be owner-only (PlaneListener::bind refuses a
    // group/other-writable dir like /tmp, mode 1777) — create a private 0700 subdir.
    let sockdir = std::env::temp_dir().join(format!("maknae-live-{}", std::process::id()));
    std::fs::create_dir_all(&sockdir).unwrap();
    std::fs::set_permissions(&sockdir, std::fs::Permissions::from_mode(0o700)).unwrap();
    let sock = sockdir.join("maknae.sock");

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
        // Deployment-agnostic: assert the plane suffix, not a hard-coded deployment_id.
        let san = s.peer_uri_san();
        assert!(
            san.starts_with("maknae://") && san.ends_with("/plane/cli"),
            "kernel must see the cli plane URI-SAN, got {san}"
        );
        let mut buf = [0u8; 5];
        s.read_exact(&mut buf).await.unwrap();
        s.write_all(b"pong!").await.unwrap();
        s.flush().await.unwrap();
        buf
    });
    let mut c = maknae_vault::PlaneConnector::connect(&sock, &cclient, &cca)
        .await
        .expect("connect");
    let csan = c.peer_uri_san();
    assert!(
        csan.starts_with("maknae://") && csan.ends_with("/plane/kernel"),
        "cli must see the kernel plane URI-SAN, got {csan}"
    );
    c.write_all(b"hello").await.unwrap();
    c.flush().await.unwrap();
    let mut resp = [0u8; 5];
    c.read_exact(&mut resp).await.unwrap();
    assert_eq!(&resp, b"pong!");
    assert_eq!(&srv.await.unwrap(), b"hello");
    kclient.shutdown().await;
    cclient.shutdown().await;
    let _ = std::fs::remove_dir_all(&sockdir);
    println!("LIVE TRANSPORT OK: kernel<->cli mTLS + peer-creds round-trip over UDS");
}
