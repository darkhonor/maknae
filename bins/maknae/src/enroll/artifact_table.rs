//! The enroll-created filesystem artifact table (spec §4.6) — PURE, no I/O.
//!
//! `artifact_table` enumerates every path `maknae enroll` itself creates: the
//! daemon's `/etc/maknae/*` set and the CLI's `<cli_dir>/*` set. It does NOT
//! include packaging-created rows (`/var/log/maknae`, `/var/log/maknae/audit.jsonl`,
//! `/run/maknae`, `/usr/local/var/run/maknae`) — those ship with PR-J2's package
//! scriptlets (spec §9.2), never touched here — nor `authz.yaml` (also packaging's:
//! spec §7/§9 ships the default DAC policy; §4.1's step list never has enroll write
//! it). `config.d/` is likewise excluded: enroll never creates it ("if present").
//!
//! Each row is symbolic on purpose: [`Owner`] names a *class* of owner (resolved to
//! a real uid/gid by `artifact_write.rs` at write time, via passwd/group lookups or
//! the operator identity `mod.rs` already resolved) and [`ContentKind`] names a
//! *class* of content (the literal bytes come from live enroll state — Vault
//! responses, sealed blobs — supplied by the caller at write time). Keeping both
//! symbolic is what makes this function pure and its rows exactly assertable
//! without live Vault/passwd data.
use std::path::{Path, PathBuf};

/// A symbolic file/dir owner — resolved to a real uid/gid by `artifact_write.rs`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Owner {
    /// `root:_maknae` — the daemon traverses/reads via group membership; only
    /// root can modify (spec §4.6).
    RootMaknaeGroup,
    /// `root:root` — the sealed `.cred` blob; systemd (running as root) decrypts
    /// it at unit start, the daemon never reads it directly.
    RootRoot,
    /// `_maknae:_maknae` — the degraded plaintext SecretID (opt-out only): the
    /// `0o077` group/other-bit gate in `read_secret_credential` forbids a
    /// root-owned group-readable file here, so ownership is traded to `_maknae`.
    MaknaeMaknae,
    /// The enrolling operator (`$SUDO_UID`'s passwd entry) — every row under
    /// `<cli_dir>`.
    Operator,
}

/// What KIND of content a row holds. `artifact_table` only classifies the row;
/// the literal bytes are supplied by the caller (`mod.rs`/`helper.rs`) at write
/// time from live enroll state.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ContentKind {
    /// A directory; no file content.
    Dir,
    /// The daemon's `maknae.yaml` (`core`+`vault`+`audit`+`principal`).
    DaemonYaml,
    /// The daemon's `maknae.yaml` on macOS — carries an additional
    /// `transport.socket_path` key (the compiled Linux default cannot exist
    /// there, spec §4.6's `/usr/local/var/run/maknae` row note).
    DaemonYamlWithTransport,
    /// The CLI's `maknae.yaml` (`core`+`vault`).
    CliYaml,
    /// A RoleID text file (`maknaed-approle-id` / `maknae-approle-id`) — a
    /// non-secret identifier, safe to write verbatim.
    RoleId,
    /// The operator-supplied Vault TLS CA (`--vault-ca`/`--ca-dir`), copied
    /// verbatim.
    VaultCaCopy,
    /// The maknae root CA, split from the fetched issuer chain.
    RootCa,
    /// The maknae intermediate CA, split from the fetched issuer chain.
    IntCa,
    /// The sealed daemon SecretID — `systemd-creds`'s `.cred` ciphertext on
    /// Linux, the SEP-encrypted blob on macOS. Produced by the seal step (an
    /// external command / SEP call), not a literal byte copy — `artifact_write`
    /// applies ownership/mode to an already-written file for this row.
    SealedDaemonSecret,
    /// The sealed CLI SecretID — user-scoped `systemd-creds` `.cred` (Linux
    /// only; macOS uses the login Keychain instead, which is not a filesystem
    /// row at all).
    SealedCliSecret,
    /// The root-owned accessor bookkeeping file (`enroll-state.yaml`) —
    /// what `--rotate` and failure-cleanup destroy by.
    EnrollState,
    /// The root-owned posture marker (`posture.yaml`) the daemon cross-checks
    /// its boot-time credential source against (spec §5.2).
    Posture,
    /// The degraded plaintext SecretID (opt-in only, `--insecure-plaintext-secret`).
    PlaintextSecret,
}

/// One row of the enroll-created artifact table.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Artifact {
    pub path: PathBuf,
    pub owner: Owner,
    pub mode: u32,
    pub content: ContentKind,
}

fn row(path: PathBuf, owner: Owner, mode: u32, content: ContentKind) -> Artifact {
    Artifact {
        path,
        owner,
        mode,
        content,
    }
}

/// The enroll-created rows of the spec §4.6 ownership/mode table, for a single
/// enroll run. `cli_dir` is the already-resolved CLI config directory (passwd-
/// derived home ∥ `--cli-dir`, spec §4.1's path-resolution rule — this function
/// does not resolve it itself, keeping it pure). `macos` selects the platform
/// branch (SEP ciphertext vs. `systemd-creds` `.cred`; Keychain vs. `.cred` for
/// the CLI; the `transport` section written into the daemon's `maknae.yaml`).
/// `insecure_plaintext` adds the opt-out degraded-plaintext row.
pub fn artifact_table(cli_dir: &Path, macos: bool, insecure_plaintext: bool) -> Vec<Artifact> {
    let etc = Path::new("/etc/maknae");
    let mut rows = vec![
        row(
            etc.to_path_buf(),
            Owner::RootMaknaeGroup,
            0o750,
            ContentKind::Dir,
        ),
        row(
            etc.join("maknae.yaml"),
            Owner::RootMaknaeGroup,
            0o640,
            if macos {
                ContentKind::DaemonYamlWithTransport
            } else {
                ContentKind::DaemonYaml
            },
        ),
        row(
            etc.join("maknaed-approle-id"),
            Owner::RootMaknaeGroup,
            0o640,
            ContentKind::RoleId,
        ),
        row(
            etc.join("tls"),
            Owner::RootMaknaeGroup,
            0o750,
            ContentKind::Dir,
        ),
        row(
            etc.join("tls/vault-ca.crt"),
            Owner::RootMaknaeGroup,
            0o640,
            ContentKind::VaultCaCopy,
        ),
        row(
            etc.join("tls/maknae-root-ca.crt"),
            Owner::RootMaknaeGroup,
            0o640,
            ContentKind::RootCa,
        ),
        row(
            etc.join("tls/maknae-int-ca.crt"),
            Owner::RootMaknaeGroup,
            0o640,
            ContentKind::IntCa,
        ),
        row(
            etc.join("private"),
            Owner::RootMaknaeGroup,
            0o750,
            ContentKind::Dir,
        ),
    ];

    if macos {
        rows.push(row(
            etc.join("private/maknaed-secret-id.sep"),
            Owner::RootMaknaeGroup,
            0o640,
            ContentKind::SealedDaemonSecret,
        ));
    } else {
        rows.push(row(
            etc.join("private/maknaed-secret-id.cred"),
            Owner::RootRoot,
            0o400,
            ContentKind::SealedDaemonSecret,
        ));
    }

    rows.push(row(
        etc.join("private/posture.yaml"),
        Owner::RootMaknaeGroup,
        0o640,
        ContentKind::Posture,
    ));
    rows.push(row(
        etc.join("private/enroll-state.yaml"),
        Owner::RootRoot,
        0o600,
        ContentKind::EnrollState,
    ));

    if insecure_plaintext {
        rows.push(row(
            etc.join("private/maknae-secret-id"),
            Owner::MaknaeMaknae,
            0o400,
            ContentKind::PlaintextSecret,
        ));
    }

    // ---- CLI rows (operator-owned, at cli_dir) -------------------------
    rows.push(row(
        cli_dir.to_path_buf(),
        Owner::Operator,
        0o700,
        ContentKind::Dir,
    ));
    rows.push(row(
        cli_dir.join("tls"),
        Owner::Operator,
        0o700,
        ContentKind::Dir,
    ));
    rows.push(row(
        cli_dir.join("maknae.yaml"),
        Owner::Operator,
        0o600,
        ContentKind::CliYaml,
    ));
    rows.push(row(
        cli_dir.join("maknae-approle-id"),
        Owner::Operator,
        0o600,
        ContentKind::RoleId,
    ));
    rows.push(row(
        cli_dir.join("tls/vault-ca.crt"),
        Owner::Operator,
        0o600,
        ContentKind::VaultCaCopy,
    ));
    rows.push(row(
        cli_dir.join("tls/maknae-root-ca.crt"),
        Owner::Operator,
        0o600,
        ContentKind::RootCa,
    ));
    rows.push(row(
        cli_dir.join("tls/maknae-int-ca.crt"),
        Owner::Operator,
        0o600,
        ContentKind::IntCa,
    ));

    if !macos {
        // macOS: no filesystem row — the CLI SecretID lives in the login
        // Keychain (spec §6.3), looked up by service/account at read time.
        rows.push(row(
            cli_dir.join("maknae-secret-id.cred"),
            Owner::Operator,
            0o400,
            ContentKind::SealedCliSecret,
        ));
    }

    rows
}

#[cfg(test)]
mod tests {
    use super::*;

    // Oracle honesty (round-1 SF8): this list is typed out independently here,
    // not re-derived from `artifact_table` itself or any shared constant.
    fn expected_linux_paths(cli_dir: &Path) -> Vec<PathBuf> {
        vec![
            PathBuf::from("/etc/maknae"),
            PathBuf::from("/etc/maknae/maknae.yaml"),
            PathBuf::from("/etc/maknae/maknaed-approle-id"),
            PathBuf::from("/etc/maknae/tls"),
            PathBuf::from("/etc/maknae/tls/vault-ca.crt"),
            PathBuf::from("/etc/maknae/tls/maknae-root-ca.crt"),
            PathBuf::from("/etc/maknae/tls/maknae-int-ca.crt"),
            PathBuf::from("/etc/maknae/private"),
            PathBuf::from("/etc/maknae/private/maknaed-secret-id.cred"),
            PathBuf::from("/etc/maknae/private/posture.yaml"),
            PathBuf::from("/etc/maknae/private/enroll-state.yaml"),
            cli_dir.to_path_buf(),
            cli_dir.join("tls"),
            cli_dir.join("maknae.yaml"),
            cli_dir.join("maknae-approle-id"),
            cli_dir.join("tls/vault-ca.crt"),
            cli_dir.join("tls/maknae-root-ca.crt"),
            cli_dir.join("tls/maknae-int-ca.crt"),
            cli_dir.join("maknae-secret-id.cred"),
        ]
    }

    fn expected_macos_paths(cli_dir: &Path) -> Vec<PathBuf> {
        vec![
            PathBuf::from("/etc/maknae"),
            PathBuf::from("/etc/maknae/maknae.yaml"),
            PathBuf::from("/etc/maknae/maknaed-approle-id"),
            PathBuf::from("/etc/maknae/tls"),
            PathBuf::from("/etc/maknae/tls/vault-ca.crt"),
            PathBuf::from("/etc/maknae/tls/maknae-root-ca.crt"),
            PathBuf::from("/etc/maknae/tls/maknae-int-ca.crt"),
            PathBuf::from("/etc/maknae/private"),
            PathBuf::from("/etc/maknae/private/maknaed-secret-id.sep"),
            PathBuf::from("/etc/maknae/private/posture.yaml"),
            PathBuf::from("/etc/maknae/private/enroll-state.yaml"),
            cli_dir.to_path_buf(),
            cli_dir.join("tls"),
            cli_dir.join("maknae.yaml"),
            cli_dir.join("maknae-approle-id"),
            cli_dir.join("tls/vault-ca.crt"),
            cli_dir.join("tls/maknae-root-ca.crt"),
            cli_dir.join("tls/maknae-int-ca.crt"),
            // No `maknae-secret-id.cred` row on macOS — login Keychain instead.
        ]
    }

    fn paths_of(artifacts: &[Artifact]) -> Vec<PathBuf> {
        artifacts.iter().map(|a| a.path.clone()).collect()
    }

    #[test]
    fn linux_rows_match_independent_oracle_exactly() {
        let cli_dir = Path::new("/home/op/.maknae");
        let got = artifact_table(cli_dir, false, false);
        let mut got_paths = paths_of(&got);
        let mut want_paths = expected_linux_paths(cli_dir);
        got_paths.sort();
        want_paths.sort();
        assert_eq!(got_paths, want_paths);
        assert_eq!(got.len(), 19, "row count drifted");
    }

    #[test]
    fn macos_rows_match_independent_oracle_exactly() {
        let cli_dir = Path::new("/Users/op/.maknae");
        let got = artifact_table(cli_dir, true, false);
        let mut got_paths = paths_of(&got);
        let mut want_paths = expected_macos_paths(cli_dir);
        got_paths.sort();
        want_paths.sort();
        assert_eq!(got_paths, want_paths);
        assert_eq!(got.len(), 18, "row count drifted");
    }

    #[test]
    fn var_log_maknae_is_absent_linux() {
        // Negative assertion (round-1 SF8): /var/log/maknae is packaging's row,
        // never enroll's.
        let got = artifact_table(Path::new("/home/op/.maknae"), false, false);
        assert!(!got.iter().any(|a| a.path.starts_with("/var/log/maknae")));
    }

    #[test]
    fn var_log_maknae_is_absent_macos() {
        let got = artifact_table(Path::new("/Users/op/.maknae"), true, false);
        assert!(!got.iter().any(|a| a.path.starts_with("/var/log/maknae")));
    }

    #[test]
    fn run_maknae_and_socket_dirs_are_absent() {
        // Packaging rows (spec §9.2): /run/maknae, /usr/local/var/run/maknae.
        for macos in [false, true] {
            let got = artifact_table(Path::new("/home/op/.maknae"), macos, false);
            assert!(!got.iter().any(|a| a.path.starts_with("/run/maknae")));
            assert!(!got
                .iter()
                .any(|a| a.path.starts_with("/usr/local/var/run/maknae")));
        }
    }

    #[test]
    fn authz_yaml_is_absent() {
        // authz.yaml ships with the package default (spec §7/§9), never written
        // by enroll (absent from spec §4.1's step-4 write list).
        let got = artifact_table(Path::new("/home/op/.maknae"), false, false);
        assert!(!got.iter().any(|a| a.path.ends_with("authz.yaml")));
    }

    #[test]
    fn config_d_is_absent() {
        let got = artifact_table(Path::new("/home/op/.maknae"), false, false);
        assert!(!got.iter().any(|a| a.path.ends_with("config.d")));
    }

    #[test]
    fn insecure_plaintext_adds_exactly_one_row_with_correct_shape() {
        let without = artifact_table(Path::new("/home/op/.maknae"), false, false);
        let with = artifact_table(Path::new("/home/op/.maknae"), false, true);
        assert_eq!(with.len(), without.len() + 1);
        let added = with
            .iter()
            .find(|a| a.path == Path::new("/etc/maknae/private/maknae-secret-id"))
            .expect("plaintext row present");
        assert_eq!(added.owner, Owner::MaknaeMaknae);
        assert_eq!(added.mode, 0o400);
        assert_eq!(added.content, ContentKind::PlaintextSecret);
        assert!(!without
            .iter()
            .any(|a| a.path == Path::new("/etc/maknae/private/maknae-secret-id")));
    }

    #[test]
    fn insecure_plaintext_absent_by_default_on_macos_too() {
        let with = artifact_table(Path::new("/Users/op/.maknae"), true, true);
        assert!(with
            .iter()
            .any(|a| a.path == Path::new("/etc/maknae/private/maknae-secret-id")));
        let without = artifact_table(Path::new("/Users/op/.maknae"), true, false);
        assert!(!without
            .iter()
            .any(|a| a.path == Path::new("/etc/maknae/private/maknae-secret-id")));
    }

    #[test]
    fn daemon_secret_seal_row_shape_differs_by_platform() {
        let linux = artifact_table(Path::new("/home/op/.maknae"), false, false);
        let l = linux
            .iter()
            .find(|a| a.content == ContentKind::SealedDaemonSecret)
            .unwrap();
        assert_eq!(
            l.path,
            Path::new("/etc/maknae/private/maknaed-secret-id.cred")
        );
        assert_eq!(l.owner, Owner::RootRoot);
        assert_eq!(l.mode, 0o400);

        let macos = artifact_table(Path::new("/Users/op/.maknae"), true, false);
        let m = macos
            .iter()
            .find(|a| a.content == ContentKind::SealedDaemonSecret)
            .unwrap();
        assert_eq!(
            m.path,
            Path::new("/etc/maknae/private/maknaed-secret-id.sep")
        );
        assert_eq!(m.owner, Owner::RootMaknaeGroup);
        assert_eq!(m.mode, 0o640);
    }

    #[test]
    fn daemon_yaml_content_kind_differs_by_platform() {
        let linux = artifact_table(Path::new("/home/op/.maknae"), false, false);
        let l = linux
            .iter()
            .find(|a| a.path == Path::new("/etc/maknae/maknae.yaml"))
            .unwrap();
        assert_eq!(l.content, ContentKind::DaemonYaml);

        let macos = artifact_table(Path::new("/Users/op/.maknae"), true, false);
        let m = macos
            .iter()
            .find(|a| a.path == Path::new("/etc/maknae/maknae.yaml"))
            .unwrap();
        assert_eq!(m.content, ContentKind::DaemonYamlWithTransport);
    }

    #[test]
    fn cli_dir_root_and_tls_dir_modes_are_0700() {
        let cli_dir = Path::new("/home/op/.maknae");
        let got = artifact_table(cli_dir, false, false);
        let root = got.iter().find(|a| a.path == cli_dir).unwrap();
        assert_eq!(root.mode, 0o700);
        assert_eq!(root.owner, Owner::Operator);
        assert_eq!(root.content, ContentKind::Dir);
        let tls = got.iter().find(|a| a.path == cli_dir.join("tls")).unwrap();
        assert_eq!(tls.mode, 0o700);
    }

    #[test]
    fn cli_files_are_mode_0600_operator_owned() {
        let cli_dir = Path::new("/home/op/.maknae");
        let got = artifact_table(cli_dir, false, false);
        for p in [
            "maknae.yaml",
            "maknae-approle-id",
            "tls/vault-ca.crt",
            "tls/maknae-root-ca.crt",
            "tls/maknae-int-ca.crt",
        ] {
            let a = got.iter().find(|a| a.path == cli_dir.join(p)).unwrap();
            assert_eq!(a.mode, 0o600, "{p}");
            assert_eq!(a.owner, Owner::Operator, "{p}");
        }
    }

    #[test]
    fn cli_sealed_secret_is_mode_0400_operator_owned_on_linux() {
        let cli_dir = Path::new("/home/op/.maknae");
        let got = artifact_table(cli_dir, false, false);
        let a = got
            .iter()
            .find(|a| a.path == cli_dir.join("maknae-secret-id.cred"))
            .unwrap();
        assert_eq!(a.mode, 0o400);
        assert_eq!(a.owner, Owner::Operator);
    }

    #[test]
    fn etc_maknae_root_and_private_dir_modes() {
        let got = artifact_table(Path::new("/home/op/.maknae"), false, false);
        let etc = got
            .iter()
            .find(|a| a.path == Path::new("/etc/maknae"))
            .unwrap();
        assert_eq!(etc.mode, 0o750);
        assert_eq!(etc.owner, Owner::RootMaknaeGroup);
        let private = got
            .iter()
            .find(|a| a.path == Path::new("/etc/maknae/private"))
            .unwrap();
        assert_eq!(private.mode, 0o750);
        assert_eq!(private.owner, Owner::RootMaknaeGroup);
    }

    #[test]
    fn enroll_state_is_root_root_0600() {
        let got = artifact_table(Path::new("/home/op/.maknae"), false, false);
        let a = got
            .iter()
            .find(|a| a.content == ContentKind::EnrollState)
            .unwrap();
        assert_eq!(a.path, Path::new("/etc/maknae/private/enroll-state.yaml"));
        assert_eq!(a.owner, Owner::RootRoot);
        assert_eq!(a.mode, 0o600);
    }

    #[test]
    fn posture_marker_is_root_maknaegroup_0640() {
        let got = artifact_table(Path::new("/home/op/.maknae"), false, false);
        let a = got
            .iter()
            .find(|a| a.content == ContentKind::Posture)
            .unwrap();
        assert_eq!(a.path, Path::new("/etc/maknae/private/posture.yaml"));
        assert_eq!(a.owner, Owner::RootMaknaeGroup);
        assert_eq!(a.mode, 0o640);
    }

    #[test]
    fn no_duplicate_paths_in_any_configuration() {
        for macos in [false, true] {
            for plaintext in [false, true] {
                let got = artifact_table(Path::new("/home/op/.maknae"), macos, plaintext);
                let mut paths = paths_of(&got);
                let before = paths.len();
                paths.sort();
                paths.dedup();
                assert_eq!(paths.len(), before, "macos={macos} plaintext={plaintext}");
            }
        }
    }
}
