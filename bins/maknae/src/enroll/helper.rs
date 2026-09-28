//! The hidden operator-context helper (`enroll-helper`, spec §4.1). `mod.rs`
//! re-execs this via `sudo -u $SUDO_USER` for every step that must run AS the
//! operator: the pre-mint capability probe (`probe`) and the post-mint CLI
//! provisioning (`provision`). Never invoked directly by an operator — hidden
//! from `--help` at the clap level (`cli.rs`).
//!
//! First act, always: self-verify the process actually landed in the
//! operator's identity (spec §4.1 — "the helper self-verifies its effective
//! uid/gid/supplementary groups against the operator before doing anything").
use super::{EnrollError, HelperArgs, HelperIdentityArgs, HelperVerb, ProvisionJob};
use crate::enroll::artifact_table::{self, ContentKind};
use crate::enroll::artifact_write::{self, SelfOwnerResolver};
use std::io::Read;
use std::path::{Path, PathBuf};
use zeroize::Zeroizing;

// macOS-only: the Keychain probe's service; gated so Linux clippy sees no dead_code.
#[cfg(target_os = "macos")]
const KEYCHAIN_PROBE_SERVICE: &str = "maknae-enroll-probe";
const PROBE_VALUE: &str = "maknae-enroll-probe-throwaway-value";

pub async fn dispatch(args: HelperArgs) -> Result<(), EnrollError> {
    match args.verb {
        HelperVerb::Probe(id) => {
            assert_operator_context(&id)?;
            probe(id.verbose)
        }
        HelperVerb::Provision(id) => {
            assert_operator_context(&id)?;
            let mut payload = String::new();
            std::io::stdin()
                .read_to_string(&mut payload)
                .map_err(|e| EnrollError::Io {
                    path: PathBuf::from("<stdin>"),
                    source: e.to_string(),
                })?;
            let job = ProvisionJob::from_yaml(&payload)?;
            provision(job, id.verbose)
        }
    }
}

/// The helper's mandatory first act (spec §4.1): prove it actually landed at
/// the operator's euid/egid, and that it does NOT still carry root's
/// supplementary groups — a helper that did would prove a capability the real
/// CLI never has.
fn assert_operator_context(id: &HelperIdentityArgs) -> Result<(), EnrollError> {
    let euid = nix::unistd::geteuid().as_raw();
    let egid = nix::unistd::getegid().as_raw();
    if euid != id.euid || egid != id.egid {
        return Err(EnrollError::HelperContextMismatch {
            expected_uid: id.euid,
            got_uid: euid,
            expected_gid: id.egid,
            got_gid: egid,
        });
    }
    if euid != 0 {
        let groups = supplementary_groups()?;
        if groups.contains(&0) {
            return Err(EnrollError::HelperStillPrivileged);
        }
    }
    Ok(())
}

// `nix` cfg-gates `getgroups` off Apple targets (round-1 C4) — shell out to
// `id -G` there instead. The platform delta is stated, not hidden.
#[cfg(target_os = "linux")]
fn supplementary_groups() -> Result<Vec<u32>, EnrollError> {
    nix::unistd::getgroups()
        .map(|gs| gs.into_iter().map(|g| g.as_raw()).collect())
        .map_err(|e| EnrollError::Command {
            program: "getgroups".to_string(),
            detail: e.to_string(),
        })
}

#[cfg(not(target_os = "linux"))]
fn supplementary_groups() -> Result<Vec<u32>, EnrollError> {
    let out = std::process::Command::new("id")
        .arg("-G")
        .output()
        .map_err(|e| EnrollError::Command {
            program: "id".to_string(),
            detail: e.to_string(),
        })?;
    if !out.status.success() {
        return Err(EnrollError::Command {
            program: "id".to_string(),
            detail: String::from_utf8_lossy(&out.stderr).to_string(),
        });
    }
    parse_id_dash_g(&String::from_utf8_lossy(&out.stdout))
}

// Non-Linux only: parses `id -G` output for the fallback `supplementary_groups`
// impl above (Linux uses `nix::unistd::getgroups` directly and never calls this).
// Gated with its sole consumer so the Linux `-D warnings` gate sees no dead_code.
#[cfg(not(target_os = "linux"))]
fn parse_id_dash_g(text: &str) -> Result<Vec<u32>, EnrollError> {
    text.split_whitespace()
        .map(|s| {
            s.parse::<u32>().map_err(|e| EnrollError::Command {
                program: "id".to_string(),
                detail: e.to_string(),
            })
        })
        .collect()
}

// ============================================================================
// probe — spec §4.1 step 1's post-drop capability probe: a real throwaway
// round trip of this target's CLI-seal mechanism, in the operator's own
// context, BEFORE any Vault mutation.
// ============================================================================

fn probe(verbose: bool) -> Result<(), EnrollError> {
    if cfg!(target_os = "macos") {
        probe_keychain(PROBE_VALUE, verbose)
    } else {
        probe_systemd_creds_user(PROBE_VALUE, verbose)
    }
}

fn probe_systemd_creds_user(value: &str, verbose: bool) -> Result<(), EnrollError> {
    use std::io::Write;
    use std::process::Stdio;

    if verbose {
        eprintln!("exec: systemd-creds encrypt --user --with-key=auto - -");
    }
    // `--user` (uid-scoped) seals CANNOT use `--with-key=tpm2`: the TPM host key
    // needs root-only /var/lib/systemd/credential.secret, so systemd-creds refuses
    // it in --uid= scoped mode (verified on Rocky 10 / systemd 257, issue #89). The
    // CLI plane is untrusted (ADR-0005: operator-uid compromise is fatal to it), so
    // host-bound `--with-key=auto` (disk-at-rest, useless off-host) is sufficient.
    // The DAEMON seal (root, in mod.rs) keeps full `--with-key=tpm2` TPM binding.
    let mut enc = std::process::Command::new("systemd-creds")
        .args([
            "encrypt",
            "--user",
            "--with-key=auto",
            "--name=maknae-enroll-probe",
            "-",
            "-",
        ])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| EnrollError::Command {
            program: "systemd-creds".to_string(),
            detail: e.to_string(),
        })?;
    enc.stdin
        .take()
        .expect("piped stdin")
        .write_all(value.as_bytes())
        .map_err(|e| EnrollError::Command {
            program: "systemd-creds".to_string(),
            detail: e.to_string(),
        })?;
    let enc_out = enc.wait_with_output().map_err(|e| EnrollError::Command {
        program: "systemd-creds".to_string(),
        detail: e.to_string(),
    })?;
    if !enc_out.status.success() {
        return Err(EnrollError::Command {
            program: "systemd-creds encrypt --user".to_string(),
            detail: String::from_utf8_lossy(&enc_out.stderr).to_string(),
        });
    }

    if verbose {
        eprintln!("exec: systemd-creds decrypt --user - -");
    }
    let mut dec = std::process::Command::new("systemd-creds")
        .args(["decrypt", "--user", "--name=maknae-enroll-probe", "-", "-"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| EnrollError::Command {
            program: "systemd-creds".to_string(),
            detail: e.to_string(),
        })?;
    dec.stdin
        .take()
        .expect("piped stdin")
        .write_all(&enc_out.stdout)
        .map_err(|e| EnrollError::Command {
            program: "systemd-creds".to_string(),
            detail: e.to_string(),
        })?;
    let dec_out = dec.wait_with_output().map_err(|e| EnrollError::Command {
        program: "systemd-creds".to_string(),
        detail: e.to_string(),
    })?;
    if !dec_out.status.success() {
        return Err(EnrollError::Command {
            program: "systemd-creds decrypt --user".to_string(),
            detail: String::from_utf8_lossy(&dec_out.stderr).to_string(),
        });
    }
    if dec_out.stdout != value.as_bytes() {
        return Err(EnrollError::Probe(
            "systemd-creds --user round trip returned a different value".to_string(),
        ));
    }
    Ok(())
}

#[cfg(target_os = "macos")]
fn probe_keychain(value: &str, verbose: bool) -> Result<(), EnrollError> {
    if verbose {
        eprintln!("keychain: set/get/delete generic password service={KEYCHAIN_PROBE_SERVICE}");
    }
    security_framework::passwords::set_generic_password(
        KEYCHAIN_PROBE_SERVICE,
        "probe",
        value.as_bytes(),
    )
    .map_err(|e| EnrollError::Probe(format!("keychain write: {e}")))?;
    let got = security_framework::passwords::get_generic_password(KEYCHAIN_PROBE_SERVICE, "probe")
        .map_err(|e| EnrollError::Probe(format!("keychain read: {e}")));
    let _ = security_framework::passwords::delete_generic_password(KEYCHAIN_PROBE_SERVICE, "probe");
    let got = got?;
    if got != value.as_bytes() {
        return Err(EnrollError::Probe(
            "keychain round trip returned a different value".to_string(),
        ));
    }
    Ok(())
}

#[cfg(not(target_os = "macos"))]
fn probe_keychain(_value: &str, _verbose: bool) -> Result<(), EnrollError> {
    Err(EnrollError::Probe(
        "Keychain probe requested on a non-macOS build target".to_string(),
    ))
}

// ============================================================================
// provision — spec §4.1 step 7: write the CLI artifact set + seal the real
// SecretID, entirely in the operator's own context (ownership correct by
// construction, no post-hoc chown).
// ============================================================================

fn provision(job: ProvisionJob, verbose: bool) -> Result<(), EnrollError> {
    let table = artifact_table::artifact_table(&job.cli_dir, job.macos, job.insecure_plaintext);
    let resolver = SelfOwnerResolver;

    let cli_yaml = super::build_cli_yaml(
        &job.deployment_id,
        &job.vault_addr,
        &job.approle_mount,
        &job.pki_int_mount,
        job.macos,
    );

    let mut contents = std::collections::BTreeMap::new();
    contents.insert(job.cli_dir.join("maknae.yaml"), cli_yaml.into_bytes());
    contents.insert(
        job.cli_dir.join("maknae-approle-id"),
        job.role_id.as_bytes().to_vec(),
    );
    contents.insert(
        job.cli_dir.join("tls/vault-ca.crt"),
        job.vault_ca_pem.as_bytes().to_vec(),
    );
    contents.insert(
        job.cli_dir.join("tls/maknae-root-ca.crt"),
        job.root_ca_pem.as_bytes().to_vec(),
    );
    contents.insert(
        job.cli_dir.join("tls/maknae-int-ca.crt"),
        job.int_ca_pem.as_bytes().to_vec(),
    );

    let cli_rows: Vec<_> = table
        .iter()
        .filter(|a| a.path.starts_with(&job.cli_dir) && a.content != ContentKind::SealedCliSecret)
        .cloned()
        .collect();
    artifact_write::write_artifacts(&cli_rows, &contents, &resolver)?;

    if job.macos {
        seal_cli_secret_keychain(&job.secret_id, verbose)?;
    } else {
        let sealed_path = job.cli_dir.join("maknae-secret-id.cred");
        seal_cli_secret_linux(&job.secret_id, &sealed_path, verbose)?;
        let row = table
            .iter()
            .find(|a| a.content == ContentKind::SealedCliSecret)
            .expect("non-macOS table always has a CLI sealed-secret row");
        artifact_write::apply_ownership_and_mode(row, &resolver)?;
    }
    Ok(())
}

fn seal_cli_secret_linux(
    secret: &Zeroizing<String>,
    out_path: &Path,
    verbose: bool,
) -> Result<(), EnrollError> {
    use std::io::Write;
    use std::process::Stdio;
    let out_str = out_path
        .to_str()
        .ok_or_else(|| EnrollError::Owner("non-UTF-8 seal output path".to_string()))?;
    if verbose {
        eprintln!(
            "exec: systemd-creds encrypt --user --with-key=auto --name=maknae-secret-id - {out_str}"
        );
    }
    // `--with-key=auto`, not `tpm2` — see the probe above (#89): the TPM host key is
    // unavailable to a uid-scoped user; host-bound encryption is sufficient for the
    // untrusted CLI plane.
    let mut child = std::process::Command::new("systemd-creds")
        .args([
            "encrypt",
            "--user",
            "--with-key=auto",
            "--name=maknae-secret-id",
            "-",
            out_str,
        ])
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| EnrollError::Command {
            program: "systemd-creds".to_string(),
            detail: e.to_string(),
        })?;
    child
        .stdin
        .take()
        .expect("piped stdin")
        .write_all(secret.as_bytes())
        .map_err(|e| EnrollError::Command {
            program: "systemd-creds".to_string(),
            detail: e.to_string(),
        })?;
    let out = child.wait_with_output().map_err(|e| EnrollError::Command {
        program: "systemd-creds".to_string(),
        detail: e.to_string(),
    })?;
    if !out.status.success() {
        return Err(EnrollError::Command {
            program: "systemd-creds encrypt --user".to_string(),
            detail: String::from_utf8_lossy(&out.stderr).to_string(),
        });
    }
    Ok(())
}

#[cfg(target_os = "macos")]
fn keychain_failure(op: &'static str, e: security_framework::base::Error) -> EnrollError {
    EnrollError::Keychain {
        op,
        detail: format!("status {}: {e}", e.code()),
    }
}

#[cfg(target_os = "macos")]
fn cli_item_cleared(
    deleted: Result<(), security_framework::base::Error>,
) -> Result<(), EnrollError> {
    match deleted {
        Ok(()) => Ok(()),
        Err(e) if e.code() == -25300 => Ok(()),
        Err(e) => Err(keychain_failure("delete", e)),
    }
}

// Refuses a duplicate (-25299): `set_generic_password` would update the data and keep the old ACL.
#[cfg(target_os = "macos")]
fn add_cli_item_in(
    keychain: &security_framework::os::macos::keychain::SecKeychain,
    secret: &Zeroizing<String>,
) -> Result<(), EnrollError> {
    let item = maknae_vault::CLI_KEYCHAIN_ITEM;
    keychain
        .add_generic_password(item.service, item.account, secret.as_bytes())
        .map_err(|e| keychain_failure("add", e))
}

#[cfg(target_os = "macos")]
fn verify_cli_item_in(
    keychain: &security_framework::os::macos::keychain::SecKeychain,
    secret: &Zeroizing<String>,
) -> Result<(), EnrollError> {
    use security_framework::os::macos::passwords::find_generic_password;
    let item = maknae_vault::CLI_KEYCHAIN_ITEM;
    let (password, _) = find_generic_password(
        Some(std::slice::from_ref(keychain)),
        item.service,
        item.account,
    )
    .map_err(|e| keychain_failure("verify", e))?;
    let read_back = Zeroizing::new(password.to_vec());
    if read_back.as_slice() != secret.as_bytes() {
        return Err(EnrollError::Keychain {
            op: "verify",
            detail: "the item read back is not the SecretID just added".to_string(),
        });
    }
    Ok(())
}

#[cfg(target_os = "macos")]
fn seal_cli_secret_keychain(secret: &Zeroizing<String>, verbose: bool) -> Result<(), EnrollError> {
    use security_framework::os::macos::keychain::SecKeychain;
    use security_framework::passwords::delete_generic_password;
    let item = maknae_vault::CLI_KEYCHAIN_ITEM;
    if verbose {
        eprintln!(
            "keychain: replace generic password service={}",
            item.service
        );
    }
    cli_item_cleared(delete_generic_password(item.service, item.account))?;
    let default = SecKeychain::default().map_err(|e| keychain_failure("add", e))?;
    add_cli_item_in(&default, secret)?;
    verify_cli_item_in(&default, secret)
}

#[cfg(not(target_os = "macos"))]
fn seal_cli_secret_keychain(
    _secret: &Zeroizing<String>,
    _verbose: bool,
) -> Result<(), EnrollError> {
    Err(EnrollError::Command {
        program: "keychain".to_string(),
        detail: "Keychain seal requested on a non-macOS build target".to_string(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(target_os = "macos")]
    static SCRATCH_KEYCHAIN: std::sync::Mutex<()> = std::sync::Mutex::new(());

    #[cfg(target_os = "macos")]
    struct ScratchKeychain {
        path: std::path::PathBuf,
        dir: std::path::PathBuf,
    }

    #[cfg(target_os = "macos")]
    impl Drop for ScratchKeychain {
        fn drop(&mut self) {
            let _ = std::process::Command::new("/usr/bin/security")
                .arg("delete-keychain")
                .arg(&self.path)
                .status();
            let _ = std::fs::remove_dir_all(&self.dir);
        }
    }

    #[cfg(target_os = "macos")]
    fn scratch_keychain(tag: &str) -> ScratchKeychain {
        let dir = std::env::temp_dir().join(format!("maknae-t76-{tag}-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let kc = ScratchKeychain {
            path: dir.join("t76-helper.keychain"),
            dir,
        };
        let p = kc.path.to_str().unwrap();
        for args in [
            ["create-keychain", "-p", "t76", p],
            ["unlock-keychain", "-p", "t76", p],
        ] {
            assert!(std::process::Command::new("/usr/bin/security")
                .args(args)
                .status()
                .unwrap()
                .success());
        }
        kc
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn the_cli_item_is_added_fresh_or_not_at_all() {
        use security_framework::os::macos::keychain::SecKeychain;
        let _serial = SCRATCH_KEYCHAIN.lock().unwrap_or_else(|e| e.into_inner());
        let scratch = scratch_keychain("add");
        let kc = SecKeychain::open(&scratch.path).unwrap();
        let first = Zeroizing::new("sentinel-add-first-t76".to_string());
        add_cli_item_in(&kc, &first).unwrap();
        verify_cli_item_in(&kc, &first).unwrap();
        let second = Zeroizing::new("sentinel-add-second-t76".to_string());
        match add_cli_item_in(&kc, &second) {
            Err(EnrollError::Keychain { op: "add", detail }) => {
                assert!(detail.contains("-25299"), "{detail}")
            }
            other => panic!("a duplicate add must refuse, got {other:?}"),
        }
        verify_cli_item_in(&kc, &first).unwrap();
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn a_cli_item_that_does_not_read_back_is_refused() {
        use security_framework::os::macos::keychain::SecKeychain;
        let _serial = SCRATCH_KEYCHAIN.lock().unwrap_or_else(|e| e.into_inner());
        let scratch = scratch_keychain("verify");
        let kc = SecKeychain::open(&scratch.path).unwrap();
        let added = Zeroizing::new("sentinel-verify-added-t76".to_string());
        let other = Zeroizing::new("sentinel-verify-other-t76".to_string());
        assert!(matches!(
            verify_cli_item_in(&kc, &added),
            Err(EnrollError::Keychain { op: "verify", .. })
        ));
        add_cli_item_in(&kc, &added).unwrap();
        match verify_cli_item_in(&kc, &other) {
            Err(EnrollError::Keychain {
                op: "verify",
                detail,
            }) => {
                assert!(!detail.contains("sentinel"), "{detail}")
            }
            got => panic!("a mismatched read-back must refuse, got {got:?}"),
        }
        verify_cli_item_in(&kc, &added).unwrap();
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn only_an_absent_cli_item_clears_quietly() {
        use security_framework::base::Error;
        assert!(cli_item_cleared(Ok(())).is_ok());
        assert!(cli_item_cleared(Err(Error::from_code(-25300))).is_ok());
        assert!(matches!(
            cli_item_cleared(Err(Error::from_code(-25308))),
            Err(EnrollError::Keychain { op: "delete", .. })
        ));
        assert!(matches!(
            cli_item_cleared(Err(Error::from_code(-25293))),
            Err(EnrollError::Keychain { op: "delete", .. })
        ));
    }

    #[test]
    #[cfg(not(target_os = "linux"))]
    fn parse_id_dash_g_parses_whitespace_separated_gids() {
        assert_eq!(
            parse_id_dash_g("20 12 61 79 80").unwrap(),
            vec![20, 12, 61, 79, 80]
        );
    }

    #[test]
    #[cfg(not(target_os = "linux"))]
    fn parse_id_dash_g_rejects_non_numeric() {
        assert!(parse_id_dash_g("20 abc").is_err());
    }

    #[test]
    #[cfg(not(target_os = "linux"))]
    fn parse_id_dash_g_empty_is_empty_vec() {
        assert_eq!(parse_id_dash_g("").unwrap(), Vec::<u32>::new());
    }

    #[test]
    #[cfg(not(target_os = "linux"))]
    fn parse_id_dash_g_single_gid() {
        assert_eq!(parse_id_dash_g("1000\n").unwrap(), vec![1000]);
    }

    #[test]
    fn assert_operator_context_detects_uid_mismatch() {
        let real_euid = nix::unistd::geteuid().as_raw();
        let id = HelperIdentityArgs {
            euid: real_euid.wrapping_add(1),
            egid: nix::unistd::getegid().as_raw(),
            verbose: false,
        };
        assert!(matches!(
            assert_operator_context(&id),
            Err(EnrollError::HelperContextMismatch { .. })
        ));
    }

    #[test]
    fn assert_operator_context_accepts_real_identity() {
        let id = HelperIdentityArgs {
            euid: nix::unistd::geteuid().as_raw(),
            egid: nix::unistd::getegid().as_raw(),
            verbose: false,
        };
        // On the CI/dev host running this test unprivileged, our own identity
        // trivially matches itself; the "still holds root's groups" branch
        // only triggers for euid != 0 processes carrying gid 0 supplementary
        // membership, which a normal test-runner uid does not.
        let result = assert_operator_context(&id);
        assert!(result.is_ok() || matches!(result, Err(EnrollError::HelperStillPrivileged)));
    }
}
