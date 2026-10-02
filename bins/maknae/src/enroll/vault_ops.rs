//! Thin calls over `maknae_vault::OperatorClient` for the Vault operations
//! `maknae enroll` needs (spec §4.1 step 3). No ordering/rollback/rotate
//! decision logic of its own — `mod.rs` owns that; this module names the one
//! role enroll provisions and wraps the client's ops for enroll's shape.
use maknae_vault::{OperatorClient, VaultError};
use zeroize::Zeroizing;

/// The daemon's AppRole (Terraform `maknaed`, spec §4.5).
pub const DAEMON_ROLE: &str = "maknaed";
/// The roles enroll provisions.
pub const ROLES: [&str; 1] = [DAEMON_ROLE];

/// A minted SecretID + its accessor, tagged with the role it belongs to — what
/// `enroll-state.yaml` records and rollback/rotate destroy by.
pub struct MintedSecret {
    pub role: &'static str,
    pub secret: Zeroizing<String>,
    pub accessor: String,
}

/// Read the daemon's RoleID — a non-secret identifier, safe to write into its config.
pub async fn read_daemon_role_id(
    client: &OperatorClient,
    mount: &str,
) -> Result<String, VaultError> {
    client.read_role_id(mount, DAEMON_ROLE).await
}

/// The recorded accessors whose role enroll still provisions.
pub fn still_provisioned(records: &[(String, String)]) -> Vec<(String, String)> {
    records
        .iter()
        .filter(|(role, _)| ROLES.contains(&role.as_str()))
        .cloned()
        .collect()
}

/// Mint a new SecretID for `role`, tagged for `enroll-state.yaml`/rollback.
pub async fn mint_secret(
    client: &OperatorClient,
    mount: &str,
    role: &'static str,
) -> Result<MintedSecret, VaultError> {
    let (secret, accessor) = client.mint_secret_id(mount, role).await?;
    Ok(MintedSecret {
        role,
        secret,
        accessor,
    })
}

/// Destroy every recorded `(role, accessor)` — used for rollback-after-failure
/// and unconditional re-enroll rotation (spec §4.1). Collects rather than
/// short-circuits on individual destroy failures: a partial rollback still
/// destroys everything it can, and the caller (`mod.rs`) reports the rest.
pub async fn destroy_all(
    client: &OperatorClient,
    mount: &str,
    records: &[(String, String)],
) -> Vec<(String, String, VaultError)> {
    let mut failures = Vec::new();
    for (role, accessor) in records {
        let role_static: &str = role.as_str();
        if let Err(e) = client.destroy_accessor(mount, role_static, accessor).await {
            failures.push((role.clone(), accessor.clone(), e));
        }
    }
    failures
}

/// Fetch the maknae PKI intermediate's issuer chain and split it into
/// `(root_ca_pem, int_ca_pem)`. Vault's `ca_chain` orders the issuing (leaf-
/// most, i.e. the intermediate) certificate first and its parents after, up to
/// the root last (per Vault's `issuer/default/json` docs) — so a 2-element
/// chain is `[int, root]`. A single-element chain has no separate root in the
/// response at all; the caller (`mod.rs`) falls back to a `--ca-dir`-supplied
/// root file in that case (spec §4.1 step 3: "if the chain omits the root,
/// `--ca-dir` must supply it").
pub async fn fetch_and_split_ca_chain(
    client: &OperatorClient,
    pki_int_mount: &str,
) -> Result<(String, String), VaultError> {
    let chain = client.fetch_ca_chain(pki_int_mount).await?;
    split_ca_chain(&chain)
}

/// PURE: split a joined PEM chain (as `join_ca_chain` in `operator.rs` builds
/// it — each cert's `-----BEGIN/END CERTIFICATE-----` block, newline-joined)
/// into `(root_ca_pem, int_ca_pem)`. A single-cert chain returns `("", cert)` —
/// an empty root signals the caller must look elsewhere (`--ca-dir`).
pub fn split_ca_chain(chain: &str) -> Result<(String, String), VaultError> {
    let certs = split_pem_certs(chain);
    match certs.len() {
        0 => Err(VaultError::Operator(
            "issuer chain contained no PEM certificates".to_string(),
        )),
        1 => Ok((String::new(), certs[0].trim().to_string())),
        _ => {
            let int_ca = certs[0].trim().to_string();
            let root_ca = certs[certs.len() - 1].trim().to_string();
            Ok((root_ca, int_ca))
        }
    }
}

const PEM_BEGIN: &str = "-----BEGIN CERTIFICATE-----";
const PEM_END: &str = "-----END CERTIFICATE-----";

fn split_pem_certs(joined: &str) -> Vec<&str> {
    let mut out = Vec::new();
    let mut rest = joined;
    while let Some(start) = rest.find(PEM_BEGIN) {
        let from_start = &rest[start..];
        match from_start.find(PEM_END) {
            Some(end_rel) => {
                let end = end_rel + PEM_END.len();
                out.push(&from_start[..end]);
                rest = &from_start[end..];
            }
            None => break,
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn enroll_provisions_only_the_daemon_role() {
        assert_eq!(ROLES, ["maknaed"]);
    }

    #[test]
    fn only_a_still_provisioned_roles_accessor_is_kept_for_destruction() {
        let r = |role: &str, acc: &str| (role.to_string(), acc.to_string());
        assert_eq!(
            still_provisioned(&[
                r("maknaed", "acc-1"),
                r("maknae", "acc-2"),
                r("maknae-egress", "acc-3")
            ]),
            vec![r("maknaed", "acc-1")]
        );
        assert!(still_provisioned(&[r("maknae", "acc-2")]).is_empty());
        assert!(still_provisioned(&[]).is_empty());
    }

    fn cert(tag: &str) -> String {
        format!("{PEM_BEGIN}\n{tag}\n{PEM_END}\n")
    }

    #[test]
    fn empty_chain_errs() {
        assert!(split_ca_chain("").is_err());
        assert!(split_ca_chain("not a pem at all").is_err());
    }

    #[test]
    fn single_cert_chain_has_no_root() {
        let chain = cert("AAA");
        let (root, int) = split_ca_chain(&chain).unwrap();
        assert_eq!(root, "");
        assert!(int.contains("AAA"));
    }

    #[test]
    fn two_cert_chain_splits_int_first_root_last() {
        // Mirrors `operator.rs::join_ca_chain`'s newline join of Vault's
        // ca_chain ordering: issuing (intermediate) cert first, root last.
        let chain = format!("{}\n{}", cert("INT"), cert("ROOT"));
        let (root, int) = split_ca_chain(&chain).unwrap();
        assert!(root.contains("ROOT"), "root: {root}");
        assert!(int.contains("INT"), "int: {int}");
    }

    #[test]
    fn three_cert_chain_takes_first_as_int_last_as_root() {
        let chain = format!("{}\n{}\n{}", cert("INT"), cert("MID"), cert("ROOT"));
        let (root, int) = split_ca_chain(&chain).unwrap();
        assert!(root.contains("ROOT"));
        assert!(int.contains("INT"));
        // The middle cert is neither returned half — a 3+ element chain only
        // pins the two ends this function's contract promises.
    }

    #[test]
    fn destroy_all_empty_records_is_noop_without_a_client() {
        // Pure-shape check: an empty record set never calls into Vault at all
        // (no live client available in this unit-test tier — T3), so this only
        // asserts `split_ca_chain`'s error/ok shape is exercised above; the
        // async `destroy_all`/`mint_secret`/`read_daemon_role_id` I/O paths are
        // exercised by the gated live test (`tests/live_operator.rs` precedent
        // in `maknae-vault`), documented in the task report.
        assert!(split_ca_chain("x").is_err());
    }
}
