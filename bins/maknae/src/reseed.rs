//! `sudo maknae reseed` (#488): authorize `maknaed` to seed a fresh kernel graph at
//! its next start. It writes one root-owned marker into the state directory and never
//! reads or decrypts the store.
//!
//! The marker goes through `maknae_io`'s anchored publish, never a path-based write:
//! the directory is writable by `_maknae`, so a path-based write as root would follow
//! a planted `reseed.authorized -> /etc/shadow`.

use maknae_config::state::{MARKER_FILE, MARKER_MAX_BYTES, STATE_DIR};
use maknae_io::{open_anchor, AnchorRequired, IoError, IoKind, Mode, StrategyPref, TargetRequired};
use std::path::Path;
use std::process::ExitCode;

const KERNEL_USER: &str = "_maknae";
const MARKER_MODE: u32 = 0o644;

#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Marker {
    Written,
    Pending,
}

fn preflight(euid: u32) -> Result<(), String> {
    if euid == 0 {
        Ok(())
    } else {
        Err("maknae reseed must run as root: run `sudo maknae reseed`".into())
    }
}

/// `dir_owner` and `marker_owner` are the `_maknae` uid and 0 in production; a test
/// passes its own euid for both.
pub(crate) fn write_reseed_marker(
    dir: &Path,
    dir_owner: u32,
    marker_owner: u32,
    now: u64,
) -> Result<Marker, String> {
    let anchor = open_anchor(
        dir,
        AnchorRequired {
            owner: Some(dir_owner),
            mode_mask: Some(0o077),
        },
        StrategyPref::Auto,
    )
    .map_err(|e| format!("cannot use the state directory {}: {e}", dir.display()))?;
    let marker = dir.join(MARKER_FILE);
    let pending = TargetRequired {
        owner: Some(marker_owner),
        mode_mask: Some(0o022),
        nlink_exactly_one: true,
        regular_file: true,
        max_bytes: Some(MARKER_MAX_BYTES),
    };
    match anchor.read(Path::new(MARKER_FILE), None, pending) {
        Ok(_) => return Ok(Marker::Pending),
        Err(IoError::Io {
            kind: IoKind::NotFound,
            ..
        }) => {}
        Err(e) => {
            return Err(format!(
                "an unexpected file is at {}: {e}; investigate before reseeding",
                marker.display()
            ))
        }
    }
    // The file is created with MARKER_MODE under the umask; clear the bits the caller's
    // umask would drop so the daemon's mode check sees exactly 0644.
    let prior = nix::sys::stat::umask(nix::sys::stat::Mode::from_bits_truncate(0o022));
    let published = anchor.publish(
        Path::new(MARKER_FILE),
        None,
        format!("reseed authorized at {now}\n").as_bytes(),
        Mode(MARKER_MODE),
    );
    nix::sys::stat::umask(prior);
    published.map_err(|e| format!("cannot write {}: {e}", marker.display()))?;
    Ok(Marker::Written)
}

pub(crate) fn kernel_uid() -> Result<u32, String> {
    nix::unistd::User::from_name(KERNEL_USER)
        .map_err(|e| format!("user {KERNEL_USER}: {e}"))?
        .map(|u| u.uid.as_raw())
        .ok_or_else(|| format!("no such user: {KERNEL_USER}; is maknae installed?"))
}

fn reseed(euid: u32, now: u64) -> Result<Marker, String> {
    preflight(euid)?;
    write_reseed_marker(Path::new(STATE_DIR), kernel_uid()?, 0, now)
}

pub(crate) fn run_reseed() -> ExitCode {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs());
    match reseed(nix::unistd::geteuid().as_raw(), now) {
        Ok(Marker::Written) => {
            println!(
                "reseed authorized; restart maknaed to seed a fresh kernel graph (a readable \
                 current store is kept as kernel.graph.rejected.<time>). Containment that was \
                 never synced to bindings.yaml is dropped."
            );
            ExitCode::SUCCESS
        }
        Ok(Marker::Pending) => {
            println!(
                "a reseed is already authorized ({}/{MARKER_FILE}); restart maknaed to seed a \
                 fresh kernel graph",
                STATE_DIR
            );
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("maknae: {e}");
            ExitCode::FAILURE
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::{MetadataExt, PermissionsExt};
    use std::path::PathBuf;

    const UMASK_CHILD_ENV: &str = "MAKNAE_TEST_RESEED_UMASK_CHILD";

    struct Scratch(PathBuf);
    impl Scratch {
        fn new(tag: &str) -> Self {
            let p = std::env::temp_dir()
                .join(format!("maknae_cli_reseed_{}_{tag}", std::process::id()));
            let _ = std::fs::remove_dir_all(&p);
            std::fs::create_dir_all(&p).unwrap();
            std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o700)).unwrap();
            Scratch(p)
        }
    }
    impl Drop for Scratch {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    fn euid() -> u32 {
        nix::unistd::geteuid().as_raw()
    }

    fn mode_of(p: &Path) -> u32 {
        std::fs::symlink_metadata(p).unwrap().permissions().mode() & 0o7777
    }

    #[test]
    fn reseed_marker_mode_is_explicit_under_umask_077() {
        if let Some(dir) = std::env::var_os(UMASK_CHILD_ENV) {
            nix::sys::stat::umask(nix::sys::stat::Mode::from_bits_truncate(0o077));
            let dir = Path::new(&dir);
            assert_eq!(
                write_reseed_marker(dir, euid(), euid(), 1),
                Ok(Marker::Written)
            );
            assert_eq!(mode_of(&dir.join(MARKER_FILE)), MARKER_MODE);
            return;
        }
        let scratch = Scratch::new("umask");
        let name = concat!(
            module_path!(),
            "::reseed_marker_mode_is_explicit_under_umask_077"
        );
        let name = name.split_once("::").map_or(name, |(_, rest)| rest);
        let out = std::process::Command::new(std::env::current_exe().unwrap())
            .args(["--exact", name, "--test-threads=1"])
            .env(UMASK_CHILD_ENV, &scratch.0)
            .output()
            .unwrap();
        assert!(
            out.status.success(),
            "child failed: {}",
            String::from_utf8_lossy(&out.stdout)
        );
        assert!(
            String::from_utf8_lossy(&out.stdout).contains("1 passed"),
            "the child ran no test: {}",
            String::from_utf8_lossy(&out.stdout)
        );
        let marker = scratch.0.join(MARKER_FILE);
        assert_eq!(mode_of(&marker), MARKER_MODE);
        assert_eq!(
            std::fs::read_to_string(&marker).unwrap(),
            "reseed authorized at 1\n"
        );
    }

    #[test]
    fn reseed_refuses_a_planted_symlink() {
        let scratch = Scratch::new("symlink");
        let elsewhere = Scratch::new("symlink_target");
        let target = elsewhere.0.join("precious");
        std::fs::write(&target, "precious\n").unwrap();
        std::fs::set_permissions(&target, std::fs::Permissions::from_mode(0o600)).unwrap();
        let marker = scratch.0.join(MARKER_FILE);
        std::os::unix::fs::symlink(&target, &marker).unwrap();

        let err = write_reseed_marker(&scratch.0, euid(), euid(), 1).unwrap_err();
        assert!(
            err.starts_with(&format!("an unexpected file is at {}: ", marker.display()))
                && err.ends_with("; investigate before reseeding"),
            "{err}"
        );
        assert_eq!(std::fs::read_to_string(&target).unwrap(), "precious\n");
        assert_eq!(mode_of(&target), 0o600);
        assert!(std::fs::symlink_metadata(&marker)
            .unwrap()
            .file_type()
            .is_symlink());
    }

    #[test]
    fn a_group_writable_marker_is_unexpected_and_left_alone() {
        let scratch = Scratch::new("loose_marker");
        let marker = scratch.0.join(MARKER_FILE);
        std::fs::write(&marker, "planted\n").unwrap();
        std::fs::set_permissions(&marker, std::fs::Permissions::from_mode(0o666)).unwrap();
        let err = write_reseed_marker(&scratch.0, euid(), euid(), 1).unwrap_err();
        assert!(err.contains("investigate before reseeding"), "{err}");
        assert_eq!(std::fs::read_to_string(&marker).unwrap(), "planted\n");
    }

    #[test]
    fn reseed_with_a_pending_valid_marker_is_a_no_op() {
        let scratch = Scratch::new("pending");
        assert_eq!(
            write_reseed_marker(&scratch.0, euid(), euid(), 1),
            Ok(Marker::Written)
        );
        let marker = scratch.0.join(MARKER_FILE);
        let ino = std::fs::metadata(&marker).unwrap().ino();
        assert_eq!(
            write_reseed_marker(&scratch.0, euid(), euid(), 2),
            Ok(Marker::Pending)
        );
        assert_eq!(
            std::fs::read_to_string(&marker).unwrap(),
            "reseed authorized at 1\n"
        );
        assert_eq!(std::fs::metadata(&marker).unwrap().ino(), ino);
    }

    #[test]
    fn a_non_root_caller_is_refused_before_anything_is_touched() {
        assert_eq!(preflight(0), Ok(()));
        let err = preflight(1000).unwrap_err();
        assert!(err.contains("sudo maknae reseed"), "{err}");
        if euid() != 0 {
            assert_eq!(reseed(euid(), 1), Err(err));
        }
    }

    #[test]
    fn the_state_directory_must_be_the_daemons_and_private() {
        let scratch = Scratch::new("dir_mode");
        std::fs::set_permissions(&scratch.0, std::fs::Permissions::from_mode(0o755)).unwrap();
        let err = write_reseed_marker(&scratch.0, euid(), euid(), 1).unwrap_err();
        assert!(
            err.starts_with(&format!(
                "cannot use the state directory {}: ",
                scratch.0.display()
            )),
            "{err}"
        );
        std::fs::set_permissions(&scratch.0, std::fs::Permissions::from_mode(0o700)).unwrap();
        let err = write_reseed_marker(&scratch.0, euid() + 1, euid(), 1).unwrap_err();
        assert!(err.starts_with("cannot use the state directory "), "{err}");
        assert!(!scratch.0.join(MARKER_FILE).exists());
    }
}
