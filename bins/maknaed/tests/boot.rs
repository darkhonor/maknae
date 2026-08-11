//! maknaed startup exit-code contract. A bad/absent config → exit 1 (fail-closed at the
//! config gate). A GOOD config now advances the full run-loop startup (FIPS install +
//! assert → boot → audit sink → plane-credential mint), so in CI — where there is no live
//! Vault — it also fails closed (exit 1), but PAST the FIPS + config gates: the daemon no
//! longer exits 0 on boot because a successful start begins serving forever. The
//! `good_config_passes_gates_then_fails_without_vault` test pins that distinction on stderr.
//!
//! Unix-only: the boot path enforces Unix permissions (non-Unix → PermissionsUnsupported),
//! so these assertions are meaningful only on Unix. On non-Unix this file is empty.
#![cfg(unix)]

use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::Command;

fn bin() -> &'static str {
    env!("CARGO_BIN_EXE_maknaed")
}

struct Dir(PathBuf);
impl Drop for Dir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}
fn new_dir(tag: &str) -> Dir {
    let p = std::env::temp_dir().join(format!("maknaed_it_{}_{tag}", std::process::id()));
    let _ = std::fs::remove_dir_all(&p);
    std::fs::create_dir_all(&p).unwrap();
    std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o750)).unwrap();
    Dir(p)
}
fn put(dir: &Path, name: &str, body: &str, mode: u32) {
    let p = dir.join(name);
    std::fs::write(&p, body).unwrap();
    std::fs::set_permissions(&p, std::fs::Permissions::from_mode(mode)).unwrap();
}

#[test]
fn good_config_passes_gates_then_fails_without_vault() {
    let d = new_dir("good");
    put(
        &d.0,
        "maknae.yaml",
        "core:\n  identity:\n    name: t\n",
        0o640,
    );
    let out = Command::new(bin()).arg(&d.0).output().unwrap();
    // No live Vault in CI → fail closed (the daemon refuses to serve without a plane cert).
    assert_eq!(
        out.status.code(),
        Some(1),
        "good config must fail closed without a live Vault (exit 1)"
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    // Proof the good config advanced PAST the FIPS gate (provider installed + FIPS) and PAST
    // config validation — i.e. it failed at the credential/serving phase, not at a gate.
    assert!(
        !stderr.contains("FIPS provider not active"),
        "the FIPS provider must install and pass on this build; stderr: {stderr}"
    );
    assert!(
        !stderr.to_lowercase().contains("unknown section")
            && !stderr.to_lowercase().contains("ceiling"),
        "a good config must clear config validation; stderr: {stderr}"
    );
}

#[test]
fn unknown_section_exits_one() {
    let d = new_dir("bad");
    put(&d.0, "maknae.yaml", "mystery:\n  a: 1\n", 0o640);
    let status = Command::new(bin()).arg(&d.0).status().unwrap();
    assert_eq!(
        status.code(),
        Some(1),
        "unknown section should refuse (exit 1)"
    );
}

#[test]
fn invalid_ceiling_exits_one() {
    let d = new_dir("badceil");
    // a present but unrecognized classification → InvalidCeiling → exit 1
    let body = "core:\n  handling:\n    ceiling:\n      classification: SEKRET\n      sci: false\n      releasable_to: []\n      cui_permitted: false\n      cui_categories_permitted: []\n      dissemination_permitted: [\"Distribution Statement A\"]\n    accreditation_ref: null\n";
    put(&d.0, "maknae.yaml", body, 0o640);
    let status = Command::new(bin()).arg(&d.0).status().unwrap();
    assert_eq!(
        status.code(),
        Some(1),
        "invalid ceiling should refuse (exit 1)"
    );
}

#[test]
fn world_readable_exits_one() {
    let d = new_dir("644");
    put(&d.0, "maknae.yaml", "core: {}\n", 0o644);
    let status = Command::new(bin()).arg(&d.0).status().unwrap();
    assert_eq!(
        status.code(),
        Some(1),
        "world-readable config should refuse (exit 1)"
    );
}

#[test]
fn absent_dir_exits_one() {
    let status = Command::new(bin())
        .arg("/nonexistent/maknae_it_absent")
        .status()
        .unwrap();
    assert_eq!(
        status.code(),
        Some(1),
        "absent config dir should refuse (exit 1)"
    );
}
