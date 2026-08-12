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

// macOS-only: referenced solely by the `#[cfg(target_os = "macos")]` Keychain
// probe/seal functions below. Gated so the Linux `-D warnings` clippy gate does
// not flag them as dead_code (CI runs on Linux, where these are never used).
#[cfg(target_os = "macos")]
const KEYCHAIN_PROBE_SERVICE: &str = "maknae-enroll-probe";
#[cfg(target_os = "macos")]
const KEYCHAIN_CLI_SERVICE: &str = "maknae-cli";
#[cfg(target_os = "macos")]
const KEYCHAIN_CLI_ACCOUNT: &str = "maknae-secret-id";
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
        eprintln!("exec: systemd-creds encrypt --user --with-key=tpm2 - -");
    }
    let mut enc = std::process::Command::new("systemd-creds")
        .args([
            "encrypt",
            "--user",
            "--with-key=tpm2",
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
            "exec: systemd-creds encrypt --user --with-key=tpm2 --name=maknae-secret-id - {out_str}"
        );
    }
    let mut child = std::process::Command::new("systemd-creds")
        .args([
            "encrypt",
            "--user",
            "--with-key=tpm2",
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
fn seal_cli_secret_keychain(secret: &Zeroizing<String>, verbose: bool) -> Result<(), EnrollError> {
    if verbose {
        eprintln!("keychain: set generic password service={KEYCHAIN_CLI_SERVICE}");
    }
    security_framework::passwords::set_generic_password(
        KEYCHAIN_CLI_SERVICE,
        KEYCHAIN_CLI_ACCOUNT,
        secret.as_bytes(),
    )
    .map_err(|e| EnrollError::Command {
        program: "keychain".to_string(),
        detail: e.to_string(),
    })
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
