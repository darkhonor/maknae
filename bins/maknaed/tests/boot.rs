//! maknaed boot exit-code contract: a good config → exit 0; a bad/absent config → exit 1.
//! Unix-only: the boot path enforces Unix permissions (non-Unix → PermissionsUnsupported),
//! so these exit-0 assertions are meaningful only on Unix. On non-Unix this file is empty.
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
fn good_config_exits_zero() {
    let d = new_dir("good");
    put(
        &d.0,
        "maknae.yaml",
        "core:\n  identity:\n    name: t\n",
        0o640,
    );
    let status = Command::new(bin()).arg(&d.0).status().unwrap();
    assert_eq!(status.code(), Some(0), "good config should boot (exit 0)");
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
