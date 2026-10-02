//! The hidden operator-context helper (`enroll-helper`, spec §4.1). `mod.rs`
//! re-execs this via `sudo -u $SUDO_USER` for the one step that must run AS the
//! operator: writing the CLI configuration set (`provision`). Never invoked
//! directly by an operator — hidden from `--help` at the clap level (`cli.rs`).
//!
//! First act, always: self-verify the process actually landed in the
//! operator's identity (spec §4.1 — "the helper self-verifies its effective
//! uid/gid/supplementary groups against the operator before doing anything").
use super::{EnrollError, HelperArgs, HelperIdentityArgs, HelperVerb, ProvisionJob};
use crate::enroll::artifact_table;
use crate::enroll::artifact_write::{self, SelfOwnerResolver};
use std::io::Read;
use std::path::PathBuf;

pub async fn dispatch(args: HelperArgs) -> Result<(), EnrollError> {
    let HelperVerb::Provision(id) = args.verb;
    assert_operator_context(&id)?;
    let mut payload = String::new();
    std::io::stdin()
        .read_to_string(&mut payload)
        .map_err(|e| EnrollError::Io {
            path: PathBuf::from("<stdin>"),
            source: e.to_string(),
        })?;
    provision(ProvisionJob::from_yaml(&payload)?, id.verbose)
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

fn provision(job: ProvisionJob, verbose: bool) -> Result<(), EnrollError> {
    let table = artifact_table::artifact_table(&job.cli_dir, job.macos, job.insecure_plaintext);
    let cli_yaml = super::build_cli_yaml(
        &job.deployment_id,
        &job.vault_addr,
        &job.pki_int_mount,
        &job.userpass_mount,
        &job.kv_mount,
        &job.user_prefix,
        job.macos,
    );

    let mut contents = std::collections::BTreeMap::new();
    contents.insert(job.cli_dir.join("maknae.yaml"), cli_yaml.into_bytes());
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
        .filter(|a| a.path.starts_with(&job.cli_dir))
        .cloned()
        .collect();
    if verbose {
        eprintln!(
            "write: {} CLI artifacts under {}",
            cli_rows.len(),
            job.cli_dir.display()
        );
    }
    artifact_write::write_artifacts(&cli_rows, &contents, &SelfOwnerResolver)
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
        let result = assert_operator_context(&id);
        assert!(result.is_ok() || matches!(result, Err(EnrollError::HelperStillPrivileged)));
    }
}
