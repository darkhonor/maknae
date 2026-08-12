//! `maknae enroll` — one-time elevated provisioning (spec §4.1-§4.6, PR-J1
//! Task 8). Orchestrates the daemon+CLI credential mint/seal/write flow in the
//! EXACT step order spec §4.1 lays out; the individual mechanisms live in the
//! sibling modules:
//!
//! - [`artifact_table`] — the pure §4.6 row manifest.
//! - [`artifact_write`] — applies rows to disk (chown/chmod/restorecon/YAML).
//! - [`vault_ops`] — thin calls over `maknae_vault::OperatorClient`.
//! - [`helper`] — the hidden operator-context re-exec target (`enroll-helper`).
//!
//! **Privilege descent (spec §4.1, no `unsafe`):** every step that must run AS
//! the operator (the pre-mint capability probe, the post-mint CLI provisioning)
//! is re-exec'd via `sudo -u $SUDO_USER` with `XDG_RUNTIME_DIR=/run/user/$SUDO_UID`
//! pinned ([`run_helper`]) — never an in-process uid drop (the workspace forbids
//! `unsafe`, and `nix` cfg-gates the direct drop APIs off Apple targets anyway).
//! Root performs every privileged mutation FIRST; its last act is spawning the
//! final operator-context child and reporting — monotonic descent by flow order.

pub mod artifact_table;
pub mod artifact_write;
mod helper;
pub mod vault_ops;

use clap::{ArgGroup, Args, Subcommand};
use maknae_msgs::{detect_locale, msg, Locale, MsgId};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use yaml_rust2::Yaml;
use zeroize::Zeroizing;

// ============================================================================
// Errors
// ============================================================================

#[derive(Debug)]
pub enum EnrollError {
    /// Preflight: not running as root (euid != 0).
    NotRoot,
    /// Preflight: root but `$SUDO_UID`/`$SUDO_USER` absent — bare root refused
    /// (spec §4.1: "require euid 0 and `$SUDO_UID`/`$SUDO_USER`").
    MissingSudoContext,
    /// Preflight: `$SUDO_UID` names no passwd entry.
    UnknownOperator(u32),
    /// Preflight: `$SUDO_USER` disagrees with the passwd name for `$SUDO_UID`.
    SudoUserMismatch {
        sudo_user: String,
        passwd_name: String,
    },
    /// A file read/write failed.
    Io { path: PathBuf, source: String },
    /// A passwd/group lookup or `chown` failed.
    Owner(String),
    /// A `maknae-vault` operation failed (Vault client build, RoleID read,
    /// SecretID mint/destroy, CA-chain fetch).
    Vault(maknae_vault::VaultError),
    /// An external command (`usermod`, `systemd-creds`, `sudo`, `restorecon`,
    /// `id`) failed to spawn or exited non-zero.
    Command { program: String, detail: String },
    /// The operator-context helper landed at the wrong euid/egid.
    HelperContextMismatch {
        expected_uid: u32,
        got_uid: u32,
        expected_gid: u32,
        got_gid: u32,
    },
    /// The helper still carries root's supplementary groups after the `sudo -u`
    /// switch — refuses itself (spec §4.1: "a helper still holding root's
    /// groups proves a capability the real CLI won't have").
    HelperStillPrivileged,
    /// The re-exec'd helper reported a verb-level failure.
    HelperFailed { verb: &'static str, detail: String },
    /// The post-drop capability probe (systemd-creds `--user`/Keychain round
    /// trip) failed.
    Probe(String),
    /// The coarse host-level HRoT presence check (spec §4.1 step 1:
    /// `systemd-creds has-tpm2` on Linux, SEP detection on macOS) failed —
    /// checked before the deeper operator-context probe so the diagnostic is
    /// clear rather than a confusing subprocess failure.
    HrotUnavailable { detail: String },
    /// No Vault token was supplied (`--token-file` absent/empty and the
    /// interactive prompt returned empty).
    MissingToken,
    /// `--vault-addr` could not be parsed into a host:port to reachability-probe.
    InvalidVaultAddr(String),
    /// The reachability probe (spec §4.1 step 1) could not reach Vault.
    VaultUnreachable { addr: String, detail: String },
    /// The fetched issuer chain was empty/malformed, or omitted the root with
    /// no `--ca-dir` root override available.
    InvalidCaChain(String),
    /// State (enroll-state.yaml / the helper's job payload) failed to parse.
    State(String),
    /// The macOS SEP daemon-credential seal (spec §6.2) is not implemented
    /// this increment — a documented, flagged stub (spec §11: "SEP key ACL for
    /// a launchd daemon — prototyped early in PR-J1"). Never faked.
    MacosSepUnimplemented,
    /// Rotate's PRE-MINT cleanup (spec §4.1) could not destroy every
    /// previously-recorded accessor — FATAL: enroll aborts before minting
    /// anything new or overwriting `enroll-state.yaml`, so the still-live old
    /// accessors stay recorded there (not orphaned) and the operator can
    /// retry. Round-1 review Important #1: a swallowed destroy failure here
    /// followed by an unconditional state-file overwrite is exactly the
    /// orphaned-accessor leak class the brief calls out.
    RotateDestroyFailed { mount: String, detail: String },
}

impl std::fmt::Display for EnrollError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            EnrollError::NotRoot => write!(f, "must run as root (via sudo)"),
            EnrollError::MissingSudoContext => write!(
                f,
                "refusing bare root: $SUDO_UID/$SUDO_USER absent — run via `sudo maknae enroll`"
            ),
            EnrollError::UnknownOperator(uid) => write!(f, "no passwd entry for uid {uid}"),
            EnrollError::SudoUserMismatch {
                sudo_user,
                passwd_name,
            } => write!(
                f,
                "$SUDO_USER={sudo_user:?} does not match the passwd name {passwd_name:?} for $SUDO_UID"
            ),
            EnrollError::Io { path, source } => write!(f, "{}: {source}", path.display()),
            EnrollError::Owner(msg) => write!(f, "{msg}"),
            EnrollError::Vault(e) => write!(f, "{e}"),
            EnrollError::Command { program, detail } => write!(f, "{program}: {detail}"),
            EnrollError::HelperContextMismatch {
                expected_uid,
                got_uid,
                expected_gid,
                got_gid,
            } => write!(
                f,
                "operator-context helper landed at uid={got_uid} gid={got_gid}, expected uid={expected_uid} gid={expected_gid}"
            ),
            EnrollError::HelperStillPrivileged => {
                write!(f, "operator-context helper still holds root's groups")
            }
            EnrollError::HelperFailed { verb, detail } => {
                write!(f, "enroll-helper {verb} failed: {detail}")
            }
            EnrollError::Probe(msg) => write!(f, "capability probe failed: {msg}"),
            EnrollError::HrotUnavailable { detail } => {
                write!(f, "no hardware root of trust available: {detail}")
            }
            EnrollError::MissingToken => write!(f, "no Vault token supplied"),
            EnrollError::InvalidVaultAddr(addr) => {
                write!(f, "cannot parse --vault-addr {addr:?} as host:port")
            }
            EnrollError::VaultUnreachable { addr, detail } => {
                write!(f, "cannot reach Vault at {addr}: {detail}")
            }
            EnrollError::InvalidCaChain(msg) => write!(f, "{msg}"),
            EnrollError::State(msg) => write!(f, "{msg}"),
            EnrollError::MacosSepUnimplemented => write!(
                f,
                "macOS SEP daemon-credential sealing is not implemented yet (spec §6.2, §11) — \
                 refusing rather than writing an unsealed credential"
            ),
            EnrollError::RotateDestroyFailed { mount, detail } => write!(
                f,
                "rotate: could not destroy every accessor from the previous enrollment on mount \
                 {mount:?} ({detail}); enroll-state.yaml was left unmodified — resolve the Vault \
                 error and re-run enroll"
            ),
        }
    }
}

impl std::error::Error for EnrollError {}

impl From<maknae_vault::VaultError> for EnrollError {
    fn from(e: maknae_vault::VaultError) -> Self {
        EnrollError::Vault(e)
    }
}

// ============================================================================
// Preflight (Step 2, pure + a small passwd seam)
// ============================================================================

/// The enrolling operator, resolved by [`preflight_check`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Operator {
    pub uid: u32,
    pub gid: u32,
    pub name: String,
    pub home: PathBuf,
}

/// A passwd lookup seam — real production code hits `nix::unistd::User`;
/// tests mock it. Returns `(name, home, primary_gid)`.
pub trait PasswdLookup {
    fn lookup(&self, uid: u32) -> Option<(String, PathBuf, u32)>;
}

/// The real passwd lookup, via `nix::unistd::User::from_uid` (spec §4.1's path
/// rule: `getpwuid($SUDO_UID)`, never `$HOME`).
pub struct RealPasswd;

impl PasswdLookup for RealPasswd {
    fn lookup(&self, uid: u32) -> Option<(String, PathBuf, u32)> {
        let user = nix::unistd::User::from_uid(nix::unistd::Uid::from_raw(uid))
            .ok()
            .flatten()?;
        Some((user.name, user.dir, user.gid.as_raw()))
    }
}

/// PURE decision: euid 0 required; `$SUDO_UID`/`$SUDO_USER` required (refuses
/// bare root); the uid must resolve in passwd, and the passwd name must match
/// `$SUDO_USER` (a forged/stale `$SUDO_USER` is refused rather than trusted
/// blindly). Real `nix`/env reads happen at the call site — this function only
/// decides, so it is exhaustively unit-testable without root or a real host.
pub fn preflight_check(
    euid: u32,
    sudo_uid: Option<u32>,
    sudo_user: Option<&str>,
    passwd: &dyn PasswdLookup,
) -> Result<Operator, EnrollError> {
    if euid != 0 {
        return Err(EnrollError::NotRoot);
    }
    let uid = sudo_uid.ok_or(EnrollError::MissingSudoContext)?;
    let user = sudo_user.ok_or(EnrollError::MissingSudoContext)?;
    let (name, home, gid) = passwd
        .lookup(uid)
        .ok_or(EnrollError::UnknownOperator(uid))?;
    if name != user {
        return Err(EnrollError::SudoUserMismatch {
            sudo_user: user.to_string(),
            passwd_name: name,
        });
    }
    Ok(Operator {
        uid,
        gid,
        name,
        home,
    })
}

// ============================================================================
// clap surface (Step 3)
// ============================================================================

/// `maknae enroll` — one-time elevated provisioning (spec §4.1).
#[derive(Args, Debug, Clone)]
#[command(group(ArgGroup::new("ca_source").required(true).multiple(false).args(["vault_ca", "ca_dir"])))]
pub struct EnrollArgs {
    /// The Vault TLS trust anchor (a single PEM file). Mutually exclusive
    /// with `--ca-dir`; exactly one is required — the trust anchor cannot be
    /// fetched over the connection it anchors.
    #[arg(long)]
    pub vault_ca: Option<PathBuf>,
    /// A directory carrying `vault-ca.crt` (the trust anchor) and, when the
    /// fetched issuer chain omits the root, `maknae-root-ca.crt`.
    #[arg(long)]
    pub ca_dir: Option<PathBuf>,
    /// The Vault server address, e.g. `https://vault.example:8200`.
    #[arg(long)]
    pub vault_addr: String,
    /// This deployment's identifier (charset-guarded by `maknae-vault`).
    #[arg(long)]
    pub deployment_id: String,
    /// The AppRole auth mount (defaults to the Terraform default; ALWAYS
    /// persisted into both written configs, spec §4.1).
    #[arg(long, default_value_t = maknae_vault::DEFAULT_APPROLE_MOUNT.to_string())]
    pub approle_mount: String,
    /// The intermediate PKI mount (defaults to the Terraform default; ALWAYS
    /// persisted).
    #[arg(long, default_value_t = maknae_vault::DEFAULT_PKI_INT_MOUNT.to_string())]
    pub pki_int_mount: String,
    /// Read the Vault token from this file instead of an interactive prompt.
    #[arg(long)]
    pub token_file: Option<PathBuf>,
    /// Override the CLI config directory (default: `<passwd-home>/.maknae`).
    #[arg(long)]
    pub cli_dir: Option<PathBuf>,
    /// Explicit alias for re-enroll's unconditional rotate semantics (spec
    /// §4.1: re-enroll always rotates — this flag only signals operator
    /// intent, it changes no behavior).
    #[arg(long)]
    pub rotate: bool,
    /// Opt into the degraded plaintext daemon-secret fallback (audited,
    /// never a silent default).
    #[arg(long)]
    pub insecure_plaintext_secret: bool,
    /// Print raw operation detail (Vault calls, shelled-out commands) instead
    /// of the default plain-language transcript (spec §4.2).
    #[arg(long)]
    pub verbose: bool,
}

/// Identity/verbosity args shared by every `enroll-helper` verb.
#[derive(Args, Debug, Clone)]
pub struct HelperIdentityArgs {
    /// The operator uid the helper must be running as (self-verification).
    #[arg(long)]
    pub euid: u32,
    /// The operator's primary gid the helper must be running as.
    #[arg(long)]
    pub egid: u32,
    #[arg(long)]
    pub verbose: bool,
}

/// The hidden `enroll-helper` subcommand's own verbs.
#[derive(Subcommand, Debug, Clone)]
pub enum HelperVerb {
    /// A throwaway round trip of this target's CLI-seal mechanism — proves
    /// the operator context can seal/unseal BEFORE any Vault mutation.
    Probe(HelperIdentityArgs),
    /// Write the CLI artifact set + seal the real SecretID (job payload read
    /// from stdin — never argv/env, spec §4.1 step 7).
    Provision(HelperIdentityArgs),
}

/// `maknae enroll-helper` — hidden, operator-context-only. `mod.rs` is the
/// only caller (via `sudo -u`); never invoked directly by an operator.
#[derive(Args, Debug, Clone)]
pub struct HelperArgs {
    #[command(subcommand)]
    pub verb: HelperVerb,
}

// ============================================================================
// The operator-context handoff payload ("job") — spec §4.1 step 7: the real
// SecretID travels ONLY over the helper's inherited stdin pipe, never argv/env.
// ============================================================================

pub(crate) struct ProvisionJob {
    pub cli_dir: PathBuf,
    pub macos: bool,
    pub insecure_plaintext: bool,
    pub deployment_id: String,
    pub vault_addr: String,
    pub approle_mount: String,
    pub pki_int_mount: String,
    pub role_id: String,
    pub secret_id: Zeroizing<String>,
    pub vault_ca_pem: String,
    pub root_ca_pem: String,
    pub int_ca_pem: String,
}

impl ProvisionJob {
    fn to_yaml(&self) -> String {
        artifact_write::emit_yaml(artifact_write::yaml_map(vec![
            (
                "cli_dir",
                Yaml::String(self.cli_dir.to_string_lossy().to_string()),
            ),
            ("macos", Yaml::Boolean(self.macos)),
            ("insecure_plaintext", Yaml::Boolean(self.insecure_plaintext)),
            ("deployment_id", Yaml::String(self.deployment_id.clone())),
            ("vault_addr", Yaml::String(self.vault_addr.clone())),
            ("approle_mount", Yaml::String(self.approle_mount.clone())),
            ("pki_int_mount", Yaml::String(self.pki_int_mount.clone())),
            ("role_id", Yaml::String(self.role_id.clone())),
            ("secret_id", Yaml::String(self.secret_id.to_string())),
            ("vault_ca_pem", Yaml::String(self.vault_ca_pem.clone())),
            ("root_ca_pem", Yaml::String(self.root_ca_pem.clone())),
            ("int_ca_pem", Yaml::String(self.int_ca_pem.clone())),
        ]))
    }

    pub(crate) fn from_yaml(text: &str) -> Result<Self, EnrollError> {
        let v = maknae_config::load_str(text)
            .map_err(|e| EnrollError::State(format!("provision job: {e:?}")))?;
        let map = match &v {
            maknae_config::Value::Map(entries) => entries,
            _ => return Err(EnrollError::State("provision job is not a map".into())),
        };
        let get_str = |key: &str| -> Result<String, EnrollError> {
            map.iter()
                .find(|(k, _)| k == key)
                .and_then(|(_, v)| match v {
                    maknae_config::Value::Str(s) => Some(s.clone()),
                    _ => None,
                })
                .ok_or_else(|| EnrollError::State(format!("provision job missing {key}")))
        };
        let get_bool = |key: &str| -> Result<bool, EnrollError> {
            map.iter()
                .find(|(k, _)| k == key)
                .and_then(|(_, v)| match v {
                    maknae_config::Value::Bool(b) => Some(*b),
                    _ => None,
                })
                .ok_or_else(|| EnrollError::State(format!("provision job missing {key}")))
        };
        Ok(ProvisionJob {
            cli_dir: PathBuf::from(get_str("cli_dir")?),
            macos: get_bool("macos")?,
            insecure_plaintext: get_bool("insecure_plaintext")?,
            deployment_id: get_str("deployment_id")?,
            vault_addr: get_str("vault_addr")?,
            approle_mount: get_str("approle_mount")?,
            pki_int_mount: get_str("pki_int_mount")?,
            role_id: get_str("role_id")?,
            secret_id: Zeroizing::new(get_str("secret_id")?),
            vault_ca_pem: get_str("vault_ca_pem")?,
            root_ca_pem: get_str("root_ca_pem")?,
            int_ca_pem: get_str("int_ca_pem")?,
        })
    }
}

// ============================================================================
// YAML content builders (daemon/CLI docs) — shared by mod.rs (daemon side)
// and helper.rs (CLI side, via `super::build_cli_yaml`).
// ============================================================================

#[allow(clippy::too_many_arguments)]
fn build_daemon_yaml(
    deployment_id: &str,
    vault_addr: &str,
    approle_mount: &str,
    pki_int_mount: &str,
    insecure_plaintext_path: Option<&Path>,
    jsonl_path: &str,
    macos: bool,
    socket_path: Option<&str>,
    principal: &Operator,
) -> String {
    let mut vault_pairs = vec![
        ("addr", Yaml::String(vault_addr.to_string())),
        ("approle_mount", Yaml::String(approle_mount.to_string())),
        ("pki_int_mount", Yaml::String(pki_int_mount.to_string())),
    ];
    if let Some(p) = insecure_plaintext_path {
        vault_pairs.push((
            "insecure_plaintext_secret_path",
            Yaml::String(p.to_string_lossy().to_string()),
        ));
    }
    let mut top = vec![
        (
            "core",
            artifact_write::yaml_map(vec![(
                "deployment_id",
                Yaml::String(deployment_id.to_string()),
            )]),
        ),
        ("vault", artifact_write::yaml_map(vault_pairs)),
        (
            "audit",
            artifact_write::yaml_map(vec![("jsonl_path", Yaml::String(jsonl_path.to_string()))]),
        ),
        (
            "principal",
            artifact_write::yaml_map(vec![
                ("name", Yaml::String(principal.name.clone())),
                ("uid", Yaml::Integer(i64::from(principal.uid))),
                (
                    "home",
                    Yaml::String(principal.home.to_string_lossy().to_string()),
                ),
            ]),
        ),
    ];
    if macos {
        if let Some(sp) = socket_path {
            top.push((
                "transport",
                artifact_write::yaml_map(vec![("socket_path", Yaml::String(sp.to_string()))]),
            ));
        }
    }
    artifact_write::emit_yaml(artifact_write::yaml_map(top))
}

fn build_cli_yaml(
    deployment_id: &str,
    vault_addr: &str,
    approle_mount: &str,
    pki_int_mount: &str,
) -> String {
    artifact_write::emit_yaml(artifact_write::yaml_map(vec![
        (
            "core",
            artifact_write::yaml_map(vec![(
                "deployment_id",
                Yaml::String(deployment_id.to_string()),
            )]),
        ),
        (
            "vault",
            artifact_write::yaml_map(vec![
                ("addr", Yaml::String(vault_addr.to_string())),
                ("approle_mount", Yaml::String(approle_mount.to_string())),
                ("pki_int_mount", Yaml::String(pki_int_mount.to_string())),
            ]),
        ),
    ]))
}

fn build_enroll_state_yaml(mount: &str, records: &[(String, String)]) -> String {
    let accessors: Vec<Yaml> = records
        .iter()
        .map(|(role, accessor)| {
            artifact_write::yaml_map(vec![
                ("role", Yaml::String(role.clone())),
                ("accessor", Yaml::String(accessor.clone())),
            ])
        })
        .collect();
    let enrolled_at = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    artifact_write::emit_yaml(artifact_write::yaml_map(vec![
        ("approle_mount", Yaml::String(mount.to_string())),
        ("accessors", Yaml::Array(accessors)),
        ("enrolled_at_unix", Yaml::Integer(enrolled_at as i64)),
    ]))
}

fn build_posture_yaml(source: &str, mechanism: &str) -> String {
    let sealed_at = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    artifact_write::emit_yaml(artifact_write::yaml_map(vec![
        ("source", Yaml::String(source.to_string())),
        ("seal_mechanism", Yaml::String(mechanism.to_string())),
        ("sealed_at_unix", Yaml::Integer(sealed_at as i64)),
    ]))
}

/// The `approle_mount` recorded in `enroll-state.yaml` — the mount the
/// recorded accessors were ACTUALLY minted under. Round-1 review Important
/// #2: a rotate must destroy the previous enrollment's accessors against
/// THIS recorded mount, never whatever `--approle-mount` the CURRENT
/// invocation passed — an operator who changes `--approle-mount` between
/// enrollments must not have the rotate cleanup misdirected at the new
/// (wrong) mount, where every destroy call would 403/fail against accessors
/// that were never minted there.
fn parse_state_mount(text: &str) -> Result<String, EnrollError> {
    let v = maknae_config::load_str(text)
        .map_err(|e| EnrollError::State(format!("enroll-state.yaml: {e:?}")))?;
    match &v {
        maknae_config::Value::Map(entries) => entries
            .iter()
            .find(|(k, _)| k == "approle_mount")
            .and_then(|(_, v)| match v {
                maknae_config::Value::Str(s) => Some(s.clone()),
                _ => None,
            })
            .ok_or_else(|| {
                EnrollError::State("enroll-state.yaml missing approle_mount".to_string())
            }),
        _ => Err(EnrollError::State(
            "enroll-state.yaml is not a map".to_string(),
        )),
    }
}

fn parse_state_accessors(text: &str) -> Result<Vec<(String, String)>, EnrollError> {
    let v = maknae_config::load_str(text)
        .map_err(|e| EnrollError::State(format!("enroll-state.yaml: {e:?}")))?;
    let accessors = match &v {
        maknae_config::Value::Map(entries) => entries
            .iter()
            .find(|(k, _)| k == "accessors")
            .map(|(_, v)| v),
        _ => None,
    }
    .ok_or_else(|| EnrollError::State("enroll-state.yaml missing accessors".into()))?;
    let items = match accessors {
        maknae_config::Value::Seq(items) => items,
        _ => return Err(EnrollError::State("accessors is not a sequence".into())),
    };
    let mut out = Vec::new();
    for item in items {
        let fields = match item {
            maknae_config::Value::Map(fields) => fields,
            _ => return Err(EnrollError::State("accessor entry is not a map".into())),
        };
        let role = fields.iter().find(|(k, _)| k == "role").and_then(|(_, v)| {
            if let maknae_config::Value::Str(s) = v {
                Some(s.clone())
            } else {
                None
            }
        });
        let accessor = fields
            .iter()
            .find(|(k, _)| k == "accessor")
            .and_then(|(_, v)| {
                if let maknae_config::Value::Str(s) = v {
                    Some(s.clone())
                } else {
                    None
                }
            });
        match (role, accessor) {
            (Some(r), Some(a)) => out.push((r, a)),
            _ => return Err(EnrollError::State("malformed accessor entry".into())),
        }
    }
    Ok(out)
}

// ============================================================================
// Reachability probe (spec §4.1 step 1) — std-only TCP connect, no TLS: a
// real "is something listening" signal without pulling rustls/reqwest into
// this crate's closed dependency enumeration.
// ============================================================================

/// PURE: parse `scheme://[user@]host:port[/...]` into `(host, port)`.
fn parse_host_port(addr: &str) -> Option<(String, u16)> {
    let rest = addr
        .strip_prefix("https://")
        .or_else(|| addr.strip_prefix("http://"))?;
    let hostport = rest.split(['/', '?', '#']).next()?;
    let hostport = hostport.rsplit('@').next()?;
    let (host, port) = hostport.rsplit_once(':')?;
    if host.is_empty() {
        return None;
    }
    let port: u16 = port.parse().ok()?;
    Some((host.to_string(), port))
}

fn check_vault_reachable(addr: &str) -> Result<(), EnrollError> {
    use std::net::ToSocketAddrs;
    let (host, port) =
        parse_host_port(addr).ok_or_else(|| EnrollError::InvalidVaultAddr(addr.to_string()))?;
    let resolved =
        (host.as_str(), port)
            .to_socket_addrs()
            .map_err(|e| EnrollError::VaultUnreachable {
                addr: addr.to_string(),
                detail: e.to_string(),
            })?;
    let target = resolved
        .into_iter()
        .next()
        .ok_or_else(|| EnrollError::VaultUnreachable {
            addr: addr.to_string(),
            detail: "no addresses resolved".to_string(),
        })?;
    std::net::TcpStream::connect_timeout(&target, std::time::Duration::from_secs(5)).map_err(
        |e| EnrollError::VaultUnreachable {
            addr: addr.to_string(),
            detail: e.to_string(),
        },
    )?;
    Ok(())
}

/// Informational only (verbose-gated) — the authoritative gate is the
/// operator-context capability probe (`run_helper(..., "probe", ...)`), which
/// actually exercises the seal mechanism rather than guessing its presence.
fn detect_hrot_capability(macos: bool, verbose: bool) -> bool {
    if macos {
        let apple_silicon = std::env::consts::ARCH == "aarch64";
        if verbose {
            eprintln!("SEP heuristic (Apple Silicon arch check): {apple_silicon}");
        }
        apple_silicon
    } else {
        let ok = std::process::Command::new("systemd-creds")
            .arg("has-tpm2")
            .status()
            .map(|s| s.success())
            .unwrap_or(false);
        if verbose {
            eprintln!("exec: systemd-creds has-tpm2 -> {ok}");
        }
        ok
    }
}

// ============================================================================
// Operator-context re-exec (spec §4.1's unified mechanism)
// ============================================================================

async fn run_helper(
    operator: &Operator,
    verb: &str,
    stdin_payload: Option<String>,
    verbose: bool,
) -> Result<(), EnrollError> {
    let exe = std::env::current_exe().map_err(|e| EnrollError::Io {
        path: PathBuf::from("<self>"),
        source: e.to_string(),
    })?;
    let mut cmd = tokio::process::Command::new("sudo");
    cmd.arg("-u").arg(&operator.name);
    cmd.arg("env")
        .arg(format!("XDG_RUNTIME_DIR=/run/user/{}", operator.uid));
    cmd.arg(&exe);
    cmd.arg("enroll-helper");
    cmd.arg(verb);
    cmd.arg("--euid").arg(operator.uid.to_string());
    cmd.arg("--egid").arg(operator.gid.to_string());
    if verbose {
        cmd.arg("--verbose");
    }
    cmd.stdin(if stdin_payload.is_some() {
        std::process::Stdio::piped()
    } else {
        std::process::Stdio::null()
    });
    cmd.stdout(std::process::Stdio::piped());
    cmd.stderr(std::process::Stdio::piped());

    if verbose {
        eprintln!(
            "exec: sudo -u {} env XDG_RUNTIME_DIR=/run/user/{} {} enroll-helper {verb}",
            operator.name,
            operator.uid,
            exe.display()
        );
    }

    let mut child = cmd.spawn().map_err(|e| EnrollError::Command {
        program: "sudo".to_string(),
        detail: e.to_string(),
    })?;

    if let Some(payload) = stdin_payload {
        use tokio::io::AsyncWriteExt;
        let mut stdin = child.stdin.take().expect("piped stdin requested above");
        stdin
            .write_all(payload.as_bytes())
            .await
            .map_err(|e| EnrollError::Command {
                program: "sudo".to_string(),
                detail: e.to_string(),
            })?;
        drop(stdin);
    }

    let output = child
        .wait_with_output()
        .await
        .map_err(|e| EnrollError::Command {
            program: "sudo".to_string(),
            detail: e.to_string(),
        })?;

    if verbose && !output.stdout.is_empty() {
        eprint!("{}", String::from_utf8_lossy(&output.stdout));
    }

    if !output.status.success() {
        return Err(EnrollError::Command {
            program: format!("enroll-helper {verb}"),
            detail: String::from_utf8_lossy(&output.stderr).to_string(),
        });
    }
    Ok(())
}

// ============================================================================
// Token intake (spec §4.1 step 2)
// ============================================================================

fn intake_token(args: &EnrollArgs, locale: Locale) -> Result<Zeroizing<String>, EnrollError> {
    if let Some(path) = &args.token_file {
        let raw = std::fs::read_to_string(path).map_err(|e| EnrollError::Io {
            path: path.clone(),
            source: e.to_string(),
        })?;
        let trimmed = raw.trim();
        if trimmed.is_empty() {
            return Err(EnrollError::MissingToken);
        }
        return Ok(Zeroizing::new(trimmed.to_string()));
    }
    let prompt = msg(locale, MsgId::EnrollTokenPrompt);
    let raw = rpassword::prompt_password(prompt).map_err(|e| EnrollError::Io {
        path: PathBuf::from("<tty>"),
        source: e.to_string(),
    })?;
    if raw.trim().is_empty() {
        return Err(EnrollError::MissingToken);
    }
    Ok(Zeroizing::new(raw))
}

// ============================================================================
// CA path resolution (spec §4.1 inputs + step 3's root-omission fallback)
// ============================================================================

fn resolve_vault_ca_path(args: &EnrollArgs) -> PathBuf {
    if let Some(p) = &args.vault_ca {
        return p.clone();
    }
    args.ca_dir
        .as_ref()
        .expect("clap group requires exactly one of --vault-ca/--ca-dir")
        .join("vault-ca.crt")
}

fn root_ca_override_path(args: &EnrollArgs) -> Option<PathBuf> {
    args.ca_dir.as_ref().map(|d| d.join("maknae-root-ca.crt"))
}

fn insecure_plaintext_path(args: &EnrollArgs) -> Option<PathBuf> {
    args.insecure_plaintext_secret
        .then(|| PathBuf::from("/etc/maknae/private/maknae-secret-id"))
}

// ============================================================================
// Group membership (spec §4.1 step 6) — hand-rolled (no dep on the privileged
// `maknae-kernel` crate's `groupres.rs`; this crate stays strictly
// non-privileged per spec §3 P1, even for `enroll`).
// ============================================================================

fn is_already_maknae_group_member(name: &str, uid: u32) -> Result<bool, EnrollError> {
    let grp = nix::unistd::Group::from_name("maknae")
        .map_err(|e| EnrollError::Owner(format!("group maknae: {e}")))?
        .ok_or_else(|| EnrollError::Owner("no `maknae` group".to_string()))?;
    if grp.mem.iter().any(|m| m == name) {
        return Ok(true);
    }
    if let Some(user) = nix::unistd::User::from_uid(nix::unistd::Uid::from_raw(uid))
        .map_err(|e| EnrollError::Owner(e.to_string()))?
    {
        if user.gid == grp.gid {
            return Ok(true);
        }
    }
    Ok(false)
}

async fn ensure_group_membership(operator: &Operator, verbose: bool) -> Result<bool, EnrollError> {
    if is_already_maknae_group_member(&operator.name, operator.uid)? {
        return Ok(false);
    }
    let (program, cmd_args): (&str, Vec<String>) = if cfg!(target_os = "macos") {
        (
            "dseditgroup",
            vec![
                "-o".into(),
                "edit".into(),
                "-a".into(),
                operator.name.clone(),
                "-t".into(),
                "user".into(),
                "maknae".into(),
            ],
        )
    } else {
        (
            "usermod",
            vec!["-aG".into(), "maknae".into(), operator.name.clone()],
        )
    };
    if verbose {
        eprintln!("exec: {program} {}", cmd_args.join(" "));
    }
    let status = tokio::process::Command::new(program)
        .args(&cmd_args)
        .status()
        .await
        .map_err(|e| EnrollError::Command {
            program: program.to_string(),
            detail: e.to_string(),
        })?;
    if !status.success() {
        return Err(EnrollError::Command {
            program: program.to_string(),
            detail: format!("exit status {status}"),
        });
    }
    Ok(true)
}

// ============================================================================
// Daemon credential sealing (spec §4.1 step 5)
// ============================================================================

async fn seal_daemon_secret_linux(
    secret: &Zeroizing<String>,
    out_path: &Path,
    verbose: bool,
) -> Result<(), EnrollError> {
    use tokio::io::AsyncWriteExt;
    let out_str = out_path
        .to_str()
        .ok_or_else(|| EnrollError::Owner("non-UTF-8 seal output path".to_string()))?;
    if verbose {
        eprintln!(
            "exec: systemd-creds encrypt --with-key=tpm2 --name=maknaed-secret-id - {out_str}"
        );
    }
    let mut child = tokio::process::Command::new("systemd-creds")
        .args([
            "encrypt",
            "--with-key=tpm2",
            "--name=maknaed-secret-id",
            "-",
            out_str,
        ])
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .map_err(|e| EnrollError::Command {
            program: "systemd-creds".to_string(),
            detail: e.to_string(),
        })?;
    {
        let mut stdin = child.stdin.take().expect("piped stdin");
        stdin
            .write_all(secret.as_bytes())
            .await
            .map_err(|e| EnrollError::Command {
                program: "systemd-creds".to_string(),
                detail: e.to_string(),
            })?;
    }
    let output = child
        .wait_with_output()
        .await
        .map_err(|e| EnrollError::Command {
            program: "systemd-creds".to_string(),
            detail: e.to_string(),
        })?;
    if !output.status.success() {
        return Err(EnrollError::Command {
            program: "systemd-creds encrypt".to_string(),
            detail: String::from_utf8_lossy(&output.stderr).to_string(),
        });
    }
    artifact_write::maybe_restorecon(out_path);
    Ok(())
}

fn seal_daemon_secret_macos(
    _secret: &Zeroizing<String>,
    _out_path: &Path,
) -> Result<(), EnrollError> {
    // TODO(spec §6.2/§11): SEP envelope encryption — a non-exportable EC key
    // with an access policy usable by `_maknae`, ECIES-encrypting the
    // SecretID. Flagged as a real, unresolved risk in the spec itself ("SEP
    // key ACL for a launchd daemon — prototyped early in PR-J1"); not
    // attempted this increment. Refuses rather than writing an unsealed
    // daemon credential — never faked. The CLI-side Keychain seal (§6.3,
    // `helper.rs::seal_cli_secret_keychain`) IS implemented for real: it has
    // none of the launchd-daemon ACL complexity (an ordinary per-user
    // Keychain item, not a system-daemon-readable one).
    Err(EnrollError::MacosSepUnimplemented)
}

// ============================================================================
// Rollback / rotate (spec §4.1: "any failure after step 3 destroys the
// just-minted accessors"; "re-enroll destroys the accessors in the existing
// enroll-state.yaml before overwriting — unconditional rotate semantics")
//
// Two distinct fatality contracts (round-1 review Important #1):
//   - `destroy_and_report` (POST-mint failure ROLLBACK): best-effort/
//     non-fatal, as before. It runs only once enroll is ALREADY failing for
//     some other reason (a later step errored) and the operator's token is
//     still live for a manual cleanup; a rollback-destroy failure is reported
//     but does not change the outcome — there's no "un-failing" the enroll.
//   - `destroy_previous_accessors_or_abort` (rotate's PRE-mint cleanup):
//     FATAL. It runs BEFORE anything new is minted or `enroll-state.yaml` is
//     overwritten, so a destroy failure here — if swallowed — would leave the
//     OLD accessors still live on Vault and recorded nowhere but stderr the
//     moment the state file is overwritten with the NEW ones. Aborting here
//     keeps the old accessors recorded in the still-intact state file.
// ============================================================================

async fn destroy_and_report(
    client: &maknae_vault::OperatorClient,
    mount: &str,
    records: &[(String, String)],
    locale: Locale,
) {
    if records.is_empty() {
        return;
    }
    let failures = vault_ops::destroy_all(client, mount, records).await;
    if failures.is_empty() {
        eprintln!("{}", msg(locale, MsgId::EnrollRollbackDestroyed));
    } else {
        eprintln!("{}", msg(locale, MsgId::EnrollRollbackDestroyed));
        for (role, accessor, e) in &failures {
            eprintln!("  ! failed to destroy accessor for role {role} ({accessor}): {e}");
        }
    }
}

/// Rotate's PRE-MINT cleanup (spec §4.1). Destroys `records` (the PREVIOUS
/// enrollment's accessors, recorded in `enroll-state.yaml`) against `mount`
/// — the caller MUST pass the mount recorded alongside those accessors
/// (`parse_state_mount`), never the current invocation's `--approle-mount`
/// (round-1 review Important #2). `records.is_empty()` short-circuits to
/// `Ok(())` without any Vault call — a fresh enroll (or a state file that
/// somehow recorded zero accessors) has nothing to destroy and nothing to
/// abort over.
///
/// Unlike [`destroy_and_report`], ANY destroy failure here is FATAL
/// (`Err(EnrollError::RotateDestroyFailed)`, round-1 review Important #1):
/// the caller (`enroll_inner`) propagates it with `?` BEFORE minting
/// anything new or overwriting `enroll-state.yaml`, so the old accessors
/// stay recorded in the untouched state file rather than being silently
/// orphaned.
async fn destroy_previous_accessors_or_abort(
    client: &maknae_vault::OperatorClient,
    mount: &str,
    records: &[(String, String)],
    locale: Locale,
) -> Result<(), EnrollError> {
    if records.is_empty() {
        return Ok(());
    }
    let failures = vault_ops::destroy_all(client, mount, records).await;
    if failures.is_empty() {
        eprintln!("{}", msg(locale, MsgId::EnrollRollbackDestroyed));
        return Ok(());
    }
    let detail = failures
        .iter()
        .map(|(role, accessor, e)| format!("role {role} ({accessor}): {e}"))
        .collect::<Vec<_>>()
        .join("; ");
    Err(EnrollError::RotateDestroyFailed {
        mount: mount.to_string(),
        detail,
    })
}

// ============================================================================
// Orchestration (spec §4.1 step order, exactly)
// ============================================================================

pub async fn run_enroll(args: EnrollArgs) -> ExitCode {
    // FIPS install FIRST, before any OperatorClient build (round-1 Q3).
    maknae_vault::install_default_crypto_provider();
    let locale = detect_locale();
    println!("{}", msg(locale, MsgId::EnrollStarted));
    match enroll_inner(&args, locale).await {
        Ok(summary) => {
            println!("{summary}");
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("{}: {e}", msg(locale, MsgId::EnrollFailed));
            ExitCode::FAILURE
        }
    }
}

fn env_u32(name: &str) -> Option<u32> {
    std::env::var(name).ok().and_then(|s| s.parse().ok())
}

async fn enroll_inner(args: &EnrollArgs, locale: Locale) -> Result<String, EnrollError> {
    // ---- Step 1: preflight ------------------------------------------------
    let euid = nix::unistd::geteuid().as_raw();
    let sudo_uid = env_u32("SUDO_UID");
    let sudo_user = std::env::var("SUDO_USER").ok();
    let operator = preflight_check(euid, sudo_uid, sudo_user.as_deref(), &RealPasswd)
        .inspect_err(|_| eprintln!("{}", msg(locale, MsgId::EnrollPreflightFailed)))?;

    let cli_dir = args
        .cli_dir
        .clone()
        .unwrap_or_else(|| operator.home.join(".maknae"));
    let macos = cfg!(target_os = "macos");

    check_vault_reachable(&args.vault_addr)?;

    // spec §4.1 step 1's two-tier HRoT gate: a coarse presence check first
    // (clearer diagnostic than letting a missing TPM/SEP surface only as a
    // confusing subprocess failure inside the probe below), THEN the real
    // operator-context probe — which stays authoritative (this coarse check
    // is advisory: it can't see the operator's own systemd-creds --user /
    // Keychain access, only the host-level TPM/SEP presence).
    if !detect_hrot_capability(macos, args.verbose) {
        eprintln!("{}", msg(locale, MsgId::EnrollPreflightFailed));
        return Err(EnrollError::HrotUnavailable {
            detail: if macos {
                "no Secure Enclave detected (Apple Silicon required)".to_string()
            } else {
                "systemd-creds has-tpm2 reports no usable TPM2".to_string()
            },
        });
    }

    println!("{}", msg(locale, MsgId::EnrollProbeStarted));
    match run_helper(&operator, "probe", None, args.verbose).await {
        Ok(()) => println!("{}", msg(locale, MsgId::EnrollProbeOk)),
        Err(e) => {
            eprintln!("{}", msg(locale, MsgId::EnrollProbeFailed));
            return Err(EnrollError::Probe(e.to_string()));
        }
    }

    // ---- Step 2: token intake ---------------------------------------------
    let token = intake_token(args, locale)?;

    // ---- Step 3: Vault operations ------------------------------------------
    let vault_ca_path = resolve_vault_ca_path(args);
    let vault_ca_bytes = std::fs::read(&vault_ca_path).map_err(|e| EnrollError::Io {
        path: vault_ca_path.clone(),
        source: e.to_string(),
    })?;
    let client = maknae_vault::OperatorClient::new(&args.vault_addr, &vault_ca_path, token)?;
    println!("{}", msg(locale, MsgId::EnrollVaultOpsStarted));

    // Unconditional rotate: a pre-existing enroll-state.yaml is destroyed
    // before anything new is minted, regardless of --rotate (spec §4.1).
    // The destroy targets the MOUNT RECORDED IN THAT FILE (`parse_state_mount`)
    // — never `args.approle_mount` — and a destroy failure is FATAL: `?`
    // propagates it before any new mint / before the state file is
    // overwritten (round-1 review Important #1 + #2).
    let state_path = PathBuf::from("/etc/maknae/private/enroll-state.yaml");
    if state_path.exists() {
        println!("{}", msg(locale, MsgId::EnrollRotating));
        let text = std::fs::read_to_string(&state_path).map_err(|e| EnrollError::Io {
            path: state_path.clone(),
            source: e.to_string(),
        })?;
        let existing_mount = parse_state_mount(&text)?;
        let existing_accessors = parse_state_accessors(&text)?;
        destroy_previous_accessors_or_abort(&client, &existing_mount, &existing_accessors, locale)
            .await?;
    }

    let (daemon_role_id, cli_role_id) =
        vault_ops::read_role_ids(&client, &args.approle_mount).await?;

    let daemon_secret =
        vault_ops::mint_secret(&client, &args.approle_mount, vault_ops::DAEMON_ROLE).await?;
    let mut minted: Vec<(String, String)> = vec![(
        daemon_secret.role.to_string(),
        daemon_secret.accessor.clone(),
    )];

    let cli_secret =
        match vault_ops::mint_secret(&client, &args.approle_mount, vault_ops::CLI_ROLE).await {
            Ok(s) => {
                minted.push((s.role.to_string(), s.accessor.clone()));
                s
            }
            Err(e) => {
                destroy_and_report(&client, &args.approle_mount, &minted, locale).await;
                return Err(e.into());
            }
        };

    let (mut root_ca_pem, int_ca_pem) =
        match vault_ops::fetch_and_split_ca_chain(&client, &args.pki_int_mount).await {
            Ok(pair) => pair,
            Err(e) => {
                destroy_and_report(&client, &args.approle_mount, &minted, locale).await;
                return Err(e.into());
            }
        };
    if root_ca_pem.is_empty() {
        match root_ca_override_path(args) {
            Some(root_path) => match std::fs::read_to_string(&root_path) {
                Ok(s) => root_ca_pem = s,
                Err(e) => {
                    destroy_and_report(&client, &args.approle_mount, &minted, locale).await;
                    return Err(EnrollError::Io {
                        path: root_path,
                        source: e.to_string(),
                    });
                }
            },
            None => {
                destroy_and_report(&client, &args.approle_mount, &minted, locale).await;
                return Err(EnrollError::InvalidCaChain(
                    "the issuer chain omitted the root CA and no --ca-dir root override was given"
                        .to_string(),
                ));
            }
        }
    }

    // ---- Steps 4-8: write, seal, group, provision, summarize --------------
    // Every failure from here rolls back the mint (spec §4.1).
    match finish_enrollment(
        args,
        locale,
        &operator,
        &cli_dir,
        macos,
        &daemon_role_id,
        &cli_role_id,
        &daemon_secret.secret,
        &cli_secret.secret,
        &vault_ca_bytes,
        &root_ca_pem,
        &int_ca_pem,
        &minted,
    )
    .await
    {
        Ok(summary) => Ok(summary),
        Err(e) => {
            destroy_and_report(&client, &args.approle_mount, &minted, locale).await;
            Err(e)
        }
    }
}

#[allow(clippy::too_many_arguments)]
async fn finish_enrollment(
    args: &EnrollArgs,
    locale: Locale,
    operator: &Operator,
    cli_dir: &Path,
    macos: bool,
    daemon_role_id: &str,
    cli_role_id: &str,
    daemon_secret: &Zeroizing<String>,
    cli_secret: &Zeroizing<String>,
    vault_ca_pem: &[u8],
    root_ca_pem: &str,
    int_ca_pem: &str,
    minted: &[(String, String)],
) -> Result<String, EnrollError> {
    // ---- Step 4: write the daemon's config artifacts -----------------------
    println!("{}", msg(locale, MsgId::EnrollWritingDaemonConfig));

    let table = artifact_table::artifact_table(cli_dir, macos, args.insecure_plaintext_secret);
    let resolver = artifact_write::RealOwnerResolver {
        operator_uid: operator.uid,
        operator_gid: operator.gid,
    };

    let jsonl_path = "/var/log/maknae/audit.jsonl";
    let socket_path = macos.then_some("/usr/local/var/run/maknae/maknaed.sock");

    let daemon_yaml = build_daemon_yaml(
        &args.deployment_id,
        &args.vault_addr,
        &args.approle_mount,
        &args.pki_int_mount,
        insecure_plaintext_path(args).as_deref(),
        jsonl_path,
        macos,
        socket_path,
        operator,
    );
    let enroll_state_yaml = build_enroll_state_yaml(&args.approle_mount, minted);
    let posture_yaml = build_posture_yaml(
        if macos {
            "sep_sealed"
        } else {
            "credentials_directory"
        },
        if macos { "sep" } else { "tpm2" },
    );

    let etc = Path::new("/etc/maknae");
    let mut contents: BTreeMap<PathBuf, Vec<u8>> = BTreeMap::new();
    contents.insert(etc.join("maknae.yaml"), daemon_yaml.into_bytes());
    contents.insert(
        etc.join("maknaed-approle-id"),
        daemon_role_id.as_bytes().to_vec(),
    );
    contents.insert(etc.join("tls/vault-ca.crt"), vault_ca_pem.to_vec());
    contents.insert(
        etc.join("tls/maknae-root-ca.crt"),
        root_ca_pem.as_bytes().to_vec(),
    );
    contents.insert(
        etc.join("tls/maknae-int-ca.crt"),
        int_ca_pem.as_bytes().to_vec(),
    );
    contents.insert(etc.join("private/posture.yaml"), posture_yaml.into_bytes());
    contents.insert(
        etc.join("private/enroll-state.yaml"),
        enroll_state_yaml.into_bytes(),
    );
    if args.insecure_plaintext_secret {
        contents.insert(
            etc.join("private/maknae-secret-id"),
            daemon_secret.as_bytes().to_vec(),
        );
    }

    // Only the rows `write_artifacts` can fill from `contents` — the sealed-
    // secret placeholder row is excluded (produced by the seal step below);
    // CLI rows are excluded (the operator-context helper's job, step 7).
    let daemon_rows: Vec<_> = table
        .iter()
        .filter(|a| {
            a.content != artifact_table::ContentKind::SealedDaemonSecret
                && a.content != artifact_table::ContentKind::SealedCliSecret
                && !a.path.starts_with(cli_dir)
        })
        .cloned()
        .collect();
    artifact_write::write_artifacts(&daemon_rows, &contents, &resolver)?;

    // ---- Step 5: seal the daemon credential --------------------------------
    println!("{}", msg(locale, MsgId::EnrollSealingDaemonCredential));
    let sealed_row = table
        .iter()
        .find(|a| a.content == artifact_table::ContentKind::SealedDaemonSecret)
        .expect("artifact_table always emits exactly one SealedDaemonSecret row");
    if macos {
        seal_daemon_secret_macos(daemon_secret, &sealed_row.path)?;
    } else {
        seal_daemon_secret_linux(daemon_secret, &sealed_row.path, args.verbose).await?;
    }
    artifact_write::apply_ownership_and_mode(sealed_row, &resolver)?;

    // ---- Step 6: group membership -------------------------------------------
    let added = ensure_group_membership(operator, args.verbose).await?;
    if added {
        println!(
            "{}",
            msg(locale, MsgId::EnrollGroupAdded).replace("{user}", &operator.name)
        );
    } else {
        println!(
            "{}",
            msg(locale, MsgId::EnrollAlreadyMember).replace("{user}", &operator.name)
        );
    }

    // ---- Step 7: CLI provisioning (operator context, via re-exec) ----------
    println!("{}", msg(locale, MsgId::EnrollProvisioningCli));
    let job = ProvisionJob {
        cli_dir: cli_dir.to_path_buf(),
        macos,
        insecure_plaintext: args.insecure_plaintext_secret,
        deployment_id: args.deployment_id.clone(),
        vault_addr: args.vault_addr.clone(),
        approle_mount: args.approle_mount.clone(),
        pki_int_mount: args.pki_int_mount.clone(),
        role_id: cli_role_id.to_string(),
        secret_id: cli_secret.clone(),
        vault_ca_pem: String::from_utf8_lossy(vault_ca_pem).to_string(),
        root_ca_pem: root_ca_pem.to_string(),
        int_ca_pem: int_ca_pem.to_string(),
    };
    run_helper(operator, "provision", Some(job.to_yaml()), args.verbose)
        .await
        .map_err(|e| EnrollError::HelperFailed {
            verb: "provision",
            detail: e.to_string(),
        })?;

    // ---- Step 8: posture summary -------------------------------------------
    let summary = msg(locale, MsgId::EnrollPostureSummary)
        .replace("{cli_dir}", &cli_dir.display().to_string());
    Ok(format!(
        "{summary}\n{}\n{}",
        msg(locale, MsgId::EnrollReloginNote),
        msg(locale, MsgId::EnrollEnableDaemonHint),
    ))
}

// ============================================================================
// enroll-helper entrypoint
// ============================================================================

pub async fn run_enroll_helper(args: HelperArgs) -> ExitCode {
    match helper::dispatch(args).await {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("maknae enroll-helper: {e}");
            ExitCode::FAILURE
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ---- preflight_check (Step 2 TDD) --------------------------------------

    struct MockPasswd(Vec<(u32, String, PathBuf, u32)>);
    impl PasswdLookup for MockPasswd {
        fn lookup(&self, uid: u32) -> Option<(String, PathBuf, u32)> {
            self.0
                .iter()
                .find(|(u, ..)| *u == uid)
                .map(|(_, n, h, g)| (n.clone(), h.clone(), *g))
        }
    }

    fn ops_passwd() -> MockPasswd {
        MockPasswd(vec![(
            1000,
            "ops".to_string(),
            PathBuf::from("/home/ops"),
            1000,
        )])
    }

    #[test]
    fn non_root_is_refused() {
        let p = ops_passwd();
        assert!(matches!(
            preflight_check(1000, Some(1000), Some("ops"), &p),
            Err(EnrollError::NotRoot)
        ));
    }

    #[test]
    fn root_without_sudo_uid_is_refused() {
        let p = ops_passwd();
        assert!(matches!(
            preflight_check(0, None, Some("ops"), &p),
            Err(EnrollError::MissingSudoContext)
        ));
    }

    #[test]
    fn root_without_sudo_user_is_refused() {
        let p = ops_passwd();
        assert!(matches!(
            preflight_check(0, Some(1000), None, &p),
            Err(EnrollError::MissingSudoContext)
        ));
    }

    #[test]
    fn root_without_either_sudo_var_is_refused() {
        let p = ops_passwd();
        assert!(matches!(
            preflight_check(0, None, None, &p),
            Err(EnrollError::MissingSudoContext)
        ));
    }

    #[test]
    fn valid_context_resolves_operator() {
        let p = ops_passwd();
        let op = preflight_check(0, Some(1000), Some("ops"), &p).unwrap();
        assert_eq!(op.uid, 1000);
        assert_eq!(op.gid, 1000);
        assert_eq!(op.name, "ops");
        assert_eq!(op.home, PathBuf::from("/home/ops"));
    }

    #[test]
    fn unknown_sudo_uid_is_refused() {
        let p = ops_passwd();
        assert!(matches!(
            preflight_check(0, Some(9999), Some("ghost"), &p),
            Err(EnrollError::UnknownOperator(9999))
        ));
    }

    #[test]
    fn sudo_user_mismatch_is_refused() {
        let p = ops_passwd();
        assert!(matches!(
            preflight_check(0, Some(1000), Some("someone-else"), &p),
            Err(EnrollError::SudoUserMismatch { .. })
        ));
    }

    // ---- parse_host_port (reachability probe, pure) ------------------------

    #[test]
    fn parse_host_port_https_with_port() {
        assert_eq!(
            parse_host_port("https://vault.example:8200"),
            Some(("vault.example".to_string(), 8200))
        );
    }

    #[test]
    fn parse_host_port_ignores_path_and_userinfo() {
        assert_eq!(
            parse_host_port("https://user@vault.example:8200/v1/sys/health"),
            Some(("vault.example".to_string(), 8200))
        );
    }

    #[test]
    fn parse_host_port_rejects_no_port() {
        assert_eq!(parse_host_port("https://vault.example"), None);
    }

    #[test]
    fn parse_host_port_rejects_non_http_scheme() {
        assert_eq!(parse_host_port("ftp://vault.example:21"), None);
    }

    #[test]
    fn parse_host_port_rejects_empty_host() {
        assert_eq!(parse_host_port("https://:8200"), None);
    }

    // ---- insecure_plaintext_path / CA path resolution (pure) ---------------

    #[test]
    fn insecure_plaintext_path_absent_by_default() {
        let mut args = default_args();
        args.insecure_plaintext_secret = false;
        assert_eq!(insecure_plaintext_path(&args), None);
    }

    #[test]
    fn insecure_plaintext_path_present_when_opted_in() {
        let mut args = default_args();
        args.insecure_plaintext_secret = true;
        assert_eq!(
            insecure_plaintext_path(&args),
            Some(PathBuf::from("/etc/maknae/private/maknae-secret-id"))
        );
    }

    #[test]
    fn resolve_vault_ca_path_prefers_vault_ca() {
        let mut args = default_args();
        args.vault_ca = Some(PathBuf::from("/tmp/ca.crt"));
        args.ca_dir = None;
        assert_eq!(resolve_vault_ca_path(&args), PathBuf::from("/tmp/ca.crt"));
    }

    #[test]
    fn resolve_vault_ca_path_derives_from_ca_dir() {
        let mut args = default_args();
        args.vault_ca = None;
        args.ca_dir = Some(PathBuf::from("/tmp/cadir"));
        assert_eq!(
            resolve_vault_ca_path(&args),
            PathBuf::from("/tmp/cadir/vault-ca.crt")
        );
    }

    #[test]
    fn root_ca_override_path_only_set_with_ca_dir() {
        let mut args = default_args();
        args.vault_ca = Some(PathBuf::from("/tmp/ca.crt"));
        args.ca_dir = None;
        assert_eq!(root_ca_override_path(&args), None);

        args.vault_ca = None;
        args.ca_dir = Some(PathBuf::from("/tmp/cadir"));
        assert_eq!(
            root_ca_override_path(&args),
            Some(PathBuf::from("/tmp/cadir/maknae-root-ca.crt"))
        );
    }

    fn default_args() -> EnrollArgs {
        EnrollArgs {
            vault_ca: Some(PathBuf::from("/tmp/ca.crt")),
            ca_dir: None,
            vault_addr: "https://v.example:8200".to_string(),
            deployment_id: "dev-01".to_string(),
            approle_mount: maknae_vault::DEFAULT_APPROLE_MOUNT.to_string(),
            pki_int_mount: maknae_vault::DEFAULT_PKI_INT_MOUNT.to_string(),
            token_file: None,
            cli_dir: None,
            rotate: false,
            insecure_plaintext_secret: false,
            verbose: false,
        }
    }

    // ---- YAML content builders ---------------------------------------------

    #[test]
    fn build_cli_yaml_round_trips_and_carries_both_mounts() {
        let text = build_cli_yaml("dev-01", "https://v.example:8200", "am", "pm");
        let v = maknae_config::load_str(&text).unwrap();
        // vault section present with both mounts ALWAYS persisted (spec §4.1) —
        // parsed through the real `vault_config_from_document`-adjacent shape
        // check via the same field accessors the CLI's own loader would use.
        let vault_section = section(&v, "vault").expect("vault section present");
        if let maknae_config::Value::Map(vfields) = vault_section {
            assert!(vfields.iter().any(|(k, _)| k == "approle_mount"));
            assert!(vfields.iter().any(|(k, _)| k == "pki_int_mount"));
        } else {
            panic!("vault section not a map");
        }
    }

    #[test]
    fn build_daemon_yaml_includes_transport_only_on_macos() {
        let op = Operator {
            uid: 1000,
            gid: 1000,
            name: "ops".to_string(),
            home: PathBuf::from("/home/ops"),
        };
        let linux = build_daemon_yaml(
            "dev-01",
            "https://v.example:8200",
            "am",
            "pm",
            None,
            "/var/log/maknae/audit.jsonl",
            false,
            None,
            &op,
        );
        assert!(!linux.contains("transport"));

        let macos = build_daemon_yaml(
            "dev-01",
            "https://v.example:8200",
            "am",
            "pm",
            None,
            "/var/log/maknae/audit.jsonl",
            true,
            Some("/usr/local/var/run/maknae/maknaed.sock"),
            &op,
        );
        assert!(macos.contains("transport"));
        assert!(macos.contains("socket_path"));
    }

    fn section<'a>(v: &'a maknae_config::Value, name: &str) -> Option<&'a maknae_config::Value> {
        match v {
            maknae_config::Value::Map(entries) => {
                entries.iter().find(|(k, _)| k == name).map(|(_, v)| v)
            }
            _ => None,
        }
    }

    #[test]
    fn build_daemon_yaml_carries_principal_and_audit() {
        let op = Operator {
            uid: 1000,
            gid: 1000,
            name: "ops".to_string(),
            home: PathBuf::from("/home/ops"),
        };
        let text = build_daemon_yaml(
            "dev-01",
            "https://v.example:8200",
            "am",
            "pm",
            None,
            "/var/log/maknae/audit.jsonl",
            false,
            None,
            &op,
        );
        let v = maknae_config::load_str(&text).unwrap();
        // Parses through the SAME section parsers the daemon boot path uses
        // (principal.rs/audit_cfg.rs), proving the emitted document is not
        // just well-formed YAML but a shape those loaders actually accept.
        let principal = maknae_config::principal_from_section(section(&v, "principal"))
            .unwrap()
            .expect("principal parses");
        assert_eq!(principal.name, "ops");
        assert_eq!(principal.uid, 1000);
        let audit =
            maknae_config::audit_from_section(section(&v, "audit"), Path::new("/nope")).unwrap();
        assert_eq!(
            audit.jsonl_path,
            PathBuf::from("/var/log/maknae/audit.jsonl")
        );
    }

    #[test]
    fn build_enroll_state_yaml_round_trips_accessors() {
        let text = build_enroll_state_yaml(
            "maknae-approle",
            &[
                ("maknaed".to_string(), "acc-1".to_string()),
                ("maknae".to_string(), "acc-2".to_string()),
            ],
        );
        let parsed = parse_state_accessors(&text).unwrap();
        assert_eq!(
            parsed,
            vec![
                ("maknaed".to_string(), "acc-1".to_string()),
                ("maknae".to_string(), "acc-2".to_string()),
            ]
        );
    }

    #[test]
    fn parse_state_accessors_rejects_missing_key() {
        assert!(parse_state_accessors("approle_mount: x\n").is_err());
    }

    #[test]
    fn parse_state_accessors_rejects_malformed_entry() {
        assert!(parse_state_accessors("accessors:\n  - role: maknaed\n").is_err());
    }

    // ---- round-1 review Important #2: rotate destroys against the RECORDED
    // mount, not whatever --approle-mount the current invocation passed ----

    #[test]
    fn parse_state_mount_round_trips() {
        let text = build_enroll_state_yaml("maknae-approle", &[]);
        assert_eq!(parse_state_mount(&text).unwrap(), "maknae-approle");
    }

    #[test]
    fn parse_state_mount_returns_the_stored_mount_even_when_current_args_differ() {
        // Pins the actual bug: enroll-state.yaml was minted under "old-approle";
        // the CURRENT invocation's --approle-mount is "new-approle" (an operator
        // who changed the flag between enrollments). The rotate destroy must
        // target "old-approle" — what parse_state_mount returns — never
        // whatever `args.approle_mount` happens to be right now.
        let text = build_enroll_state_yaml(
            "old-approle",
            &[("maknaed".to_string(), "acc-1".to_string())],
        );
        let recorded_mount = parse_state_mount(&text).unwrap();
        let current_args_mount = "new-approle";
        assert_eq!(recorded_mount, "old-approle");
        assert_ne!(recorded_mount, current_args_mount);
    }

    #[test]
    fn parse_state_mount_rejects_missing_key() {
        assert!(parse_state_mount("accessors: []\n").is_err());
    }

    #[test]
    fn parse_state_mount_rejects_non_map_document() {
        assert!(parse_state_mount("- just\n- a\n- list\n").is_err());
    }

    #[test]
    fn parse_state_mount_rejects_wrong_type() {
        assert!(parse_state_mount("approle_mount: 1\naccessors: []\n").is_err());
    }

    // ---- round-1 review Important #1: rotate's pre-mint destroy is FATAL --
    //
    // The full flow (a live Vault destroy_accessor call actually failing mid-
    // rotate, then asserting enroll returns Err AND enroll-state.yaml still
    // holds the OLD accessors on disk) needs a live Vault — `OperatorClient`
    // wraps a real `vaultrs::VaultClient` with no injectable transport, and
    // this crate has no mock-Vault harness (T3, per the task brief: the live
    // enroll flow is exercised manually, not in CI). What IS provable without
    // a network call: `VaultClient::new` (verified against vaultrs 0.7.4's
    // vendored source) reads+parses the CA file but makes NO request, so a
    // real `OperatorClient` can be built here to exercise
    // `destroy_previous_accessors_or_abort`'s structure for real. The
    // `records.is_empty()` short-circuit is the one branch reachable without
    // ever calling into Vault — proven below. The failure branch's fatality
    // (`Err(RotateDestroyFailed)`, propagated by `?` in `enroll_inner` BEFORE
    // any mint/state-file overwrite — see the `?` on the call in
    // `enroll_inner`, and `destroy_and_report`'s doc comment contrasting the
    // two fatality contracts) is a live-run assertion, documented in the
    // task report's manual live-run procedure.
    //
    // A fixed, valid, throwaway self-signed CA (P-384, generated once via
    // `openssl req -x509 -newkey ec ...`, no secret material) — embedding it
    // lets this test avoid a new `rcgen` dev-dependency for a single fixture.
    const FIXTURE_CA_PEM: &str = "-----BEGIN CERTIFICATE-----\n\
MIIBwzCCAUqgAwIBAgIUD2PQ7v3W12PH7C5ZDatOgant16QwCgYIKoZIzj0EAwIw\n\
GTEXMBUGA1UEAwwObWFrbmFlLXRlc3QtY2EwHhcNMjYwODEyMTkxMzAwWhcNMzYw\n\
ODA5MTkxMzAwWjAZMRcwFQYDVQQDDA5tYWtuYWUtdGVzdC1jYTB2MBAGByqGSM49\n\
AgEGBSuBBAAiA2IABElj0WbWS6Y4BjKnEMMxo1ZS58CLLfjlDjvrjucx9eQS9SAv\n\
JZ3bFLGPVXjSOhlD0TVTnxq6Gs1bA27177Kb7ZNbjekux1YyQPz3hWivvkcPwJXd\n\
jTEagk7s09/GEUUOxaNTMFEwHQYDVR0OBBYEFNacW0UIekDQ2gQjS+62oTzy0IMD\n\
MB8GA1UdIwQYMBaAFNacW0UIekDQ2gQjS+62oTzy0IMDMA8GA1UdEwEB/wQFMAMB\n\
Af8wCgYIKoZIzj0EAwIDZwAwZAIwC0JoylgM7l8gcIiSlyOkaj1mLQdddPXJgy5X\n\
lpE4Nfhw3jZWJyqzO7kL9ey3/dduAjAfjKftO7e9He2FqUUiExbwKFQ9VTZu30O7\n\
26pU6zb4+iAQy9t/45KRW6ugFuF0tfw=\n\
-----END CERTIFICATE-----\n";

    fn fixture_operator_client(tag: &str) -> maknae_vault::OperatorClient {
        let ca_path = std::env::temp_dir().join(format!(
            "maknae-enroll-rotate-fixture-ca-{}-{tag}.pem",
            std::process::id()
        ));
        std::fs::write(&ca_path, FIXTURE_CA_PEM).unwrap();
        // A well-formed https:// address that is never actually connected to —
        // `OperatorClient::new` only builds settings + reads/parses the CA
        // file; it makes no request (verified against vaultrs 0.7.4).
        let client = maknae_vault::OperatorClient::new(
            "https://vault.invalid.example:8200",
            &ca_path,
            Zeroizing::new("test-token".to_string()),
        )
        .expect("OperatorClient::new performs no network I/O — settings-only");
        let _ = std::fs::remove_file(&ca_path);
        client
    }

    #[tokio::test]
    async fn rotate_destroy_is_a_noop_when_nothing_was_recorded() {
        // A fresh enroll (no prior enroll-state.yaml) or a state file that
        // somehow recorded zero accessors: nothing to destroy, so this must
        // resolve WITHOUT calling into Vault at all (there is no live Vault
        // in this test) and WITHOUT treating "nothing to do" as a failure.
        let client = fixture_operator_client("empty");
        let result =
            destroy_previous_accessors_or_abort(&client, "maknae-approle", &[], Locale::EnUs).await;
        assert!(result.is_ok());
    }

    // ---- ProvisionJob round trip --------------------------------------------

    #[test]
    fn provision_job_round_trips_through_yaml() {
        let job = ProvisionJob {
            cli_dir: PathBuf::from("/home/ops/.maknae"),
            macos: false,
            insecure_plaintext: false,
            deployment_id: "dev-01".to_string(),
            vault_addr: "https://v.example:8200".to_string(),
            approle_mount: "maknae-approle".to_string(),
            pki_int_mount: "maknae-pki-int".to_string(),
            role_id: "role-id-value".to_string(),
            secret_id: Zeroizing::new("s.SECRETVALUE".to_string()),
            vault_ca_pem: "-----BEGIN CERTIFICATE-----\nA\n-----END CERTIFICATE-----\n".to_string(),
            root_ca_pem: "-----BEGIN CERTIFICATE-----\nB\n-----END CERTIFICATE-----\n".to_string(),
            int_ca_pem: "-----BEGIN CERTIFICATE-----\nC\n-----END CERTIFICATE-----\n".to_string(),
        };
        let text = job.to_yaml();
        let back = ProvisionJob::from_yaml(&text).unwrap();
        assert_eq!(back.cli_dir, job.cli_dir);
        assert_eq!(back.macos, job.macos);
        assert_eq!(back.role_id, job.role_id);
        assert_eq!(back.secret_id.as_str(), job.secret_id.as_str());
        assert_eq!(back.root_ca_pem, job.root_ca_pem);
    }

    #[test]
    fn provision_job_from_yaml_rejects_missing_field() {
        assert!(ProvisionJob::from_yaml("cli_dir: /x\n").is_err());
    }
}
