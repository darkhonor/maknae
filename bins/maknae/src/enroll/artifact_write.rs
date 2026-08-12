//! Applies an [`artifact_table`] row set to disk (spec §4.6): creates
//! directories, writes files, and enforces ownership/mode — `nix::unistd::chown`
//! (needs the `fs` feature) + `chmod` via `std::fs::set_permissions`, with a
//! `restorecon` shell-out on SELinux hosts. YAML is emitted via
//! `yaml_rust2::YamlEmitter` (not `serde_yaml` — it trips `deny.toml`, matching
//! `maknae-config`'s own parser pin).
//!
//! Ownership is symbolic in [`Artifact`] (`Owner`); resolving it to a real
//! uid/gid is behind the [`OwnerResolver`] trait so callers running as different
//! identities (root writing the daemon's `/etc/maknae` set vs. the operator-
//! context helper writing its own `<cli_dir>`) supply the right resolution
//! strategy without this module caring which caller it is.
use super::EnrollError;
use crate::enroll::artifact_table::{Artifact, ContentKind, Owner};
use nix::unistd::{Gid, Uid};
use std::collections::BTreeMap;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use yaml_rust2::yaml::Hash;
use yaml_rust2::{Yaml, YamlEmitter};

/// Resolves a symbolic [`Owner`] to a real `(uid, gid)` pair. `None` for
/// either half means "leave that half unchanged" (mirrors `nix::unistd::chown`'s
/// own `Option<Uid>`/`Option<Gid>` contract) — every resolver here always
/// returns both, but the trait stays honest about what `chown` actually allows.
pub trait OwnerResolver {
    fn resolve(&self, owner: Owner) -> Result<(Option<Uid>, Option<Gid>), EnrollError>;
}

/// The root-context resolver `mod.rs` uses for the daemon's `/etc/maknae` set:
/// `Operator` resolves to the already-known operator uid/gid (from preflight);
/// `RootRoot`/`RootMaknaeGroup`/`MaknaeMaknae` resolve via passwd/group lookups.
pub struct RealOwnerResolver {
    pub operator_uid: u32,
    pub operator_gid: u32,
}

impl OwnerResolver for RealOwnerResolver {
    fn resolve(&self, owner: Owner) -> Result<(Option<Uid>, Option<Gid>), EnrollError> {
        match owner {
            Owner::Operator => Ok((
                Some(Uid::from_raw(self.operator_uid)),
                Some(Gid::from_raw(self.operator_gid)),
            )),
            Owner::RootRoot => Ok((Some(Uid::from_raw(0)), Some(Gid::from_raw(0)))),
            Owner::RootMaknaeGroup => Ok((Some(Uid::from_raw(0)), Some(group_gid("_maknae")?))),
            Owner::MaknaeMaknae => {
                let (uid, gid) = user_uid_gid("_maknae")?;
                Ok((Some(uid), Some(gid)))
            }
        }
    }
}

/// The operator-context resolver `helper.rs` uses for `<cli_dir>`: every row
/// there is `Owner::Operator`, and the helper already runs AS the operator
/// (self-verified, spec §4.1), so ownership is correct by construction — no
/// `chown` needed at all, only `chmod`. Any other `Owner` variant reaching this
/// resolver is a programming error (the CLI table only ever emits `Operator`
/// rows) — fail closed rather than silently chowning to the wrong identity.
pub struct SelfOwnerResolver;

impl OwnerResolver for SelfOwnerResolver {
    fn resolve(&self, owner: Owner) -> Result<(Option<Uid>, Option<Gid>), EnrollError> {
        match owner {
            Owner::Operator => Ok((None, None)),
            other => Err(EnrollError::Owner(format!(
                "operator-context helper cannot resolve non-operator owner {other:?}"
            ))),
        }
    }
}

fn group_gid(name: &str) -> Result<Gid, EnrollError> {
    nix::unistd::Group::from_name(name)
        .map_err(|e| EnrollError::Owner(format!("group {name}: {e}")))?
        .map(|g| g.gid)
        .ok_or_else(|| EnrollError::Owner(format!("no such group: {name}")))
}

fn user_uid_gid(name: &str) -> Result<(Uid, Gid), EnrollError> {
    let u = nix::unistd::User::from_name(name)
        .map_err(|e| EnrollError::Owner(format!("user {name}: {e}")))?
        .ok_or_else(|| EnrollError::Owner(format!("no such user: {name}")))?;
    Ok((u.uid, u.gid))
}

fn io_err(path: &Path, e: std::io::Error) -> EnrollError {
    EnrollError::Io {
        path: path.to_path_buf(),
        source: e.to_string(),
    }
}

/// `restorecon` the given path IFF this host is SELinux-enforcing (probed by
/// `/sys/fs/selinux/enforce`'s presence, spec §4.1 step 5). Best-effort: a
/// missing `restorecon` binary or a non-zero exit does not fail enrollment —
/// the file is still correctly owned/moded, just possibly mislabeled until the
/// next full relabel, which is the same posture the shipped `%post`/postinst
/// scriptlets already accept for anything created after package install.
pub fn maybe_restorecon(path: &Path) {
    if Path::new("/sys/fs/selinux/enforce").exists() {
        let _ = std::process::Command::new("restorecon").arg(path).status();
    }
}

/// Apply `artifact.owner`/`artifact.mode` to an ALREADY-EXISTING path (a
/// directory just created, or a file a seal command just wrote) + `restorecon`
/// on SELinux hosts.
pub fn apply_ownership_and_mode(
    artifact: &Artifact,
    resolver: &dyn OwnerResolver,
) -> Result<(), EnrollError> {
    let (uid, gid) = resolver.resolve(artifact.owner)?;
    if uid.is_some() || gid.is_some() {
        nix::unistd::chown(&artifact.path, uid, gid)
            .map_err(|e| EnrollError::Owner(format!("chown {}: {e}", artifact.path.display())))?;
    }
    std::fs::set_permissions(
        &artifact.path,
        std::fs::Permissions::from_mode(artifact.mode),
    )
    .map_err(|e| io_err(&artifact.path, e))?;
    maybe_restorecon(&artifact.path);
    Ok(())
}

/// `mkdir -p` + apply ownership/mode.
pub fn ensure_dir(artifact: &Artifact, resolver: &dyn OwnerResolver) -> Result<(), EnrollError> {
    std::fs::create_dir_all(&artifact.path).map_err(|e| io_err(&artifact.path, e))?;
    apply_ownership_and_mode(artifact, resolver)
}

/// Write `bytes` to `artifact.path` (create/truncate) + apply ownership/mode.
pub fn write_file(
    artifact: &Artifact,
    bytes: &[u8],
    resolver: &dyn OwnerResolver,
) -> Result<(), EnrollError> {
    std::fs::write(&artifact.path, bytes).map_err(|e| io_err(&artifact.path, e))?;
    apply_ownership_and_mode(artifact, resolver)
}

/// Apply every row in `rows` (directories via [`ensure_dir`], files via
/// [`write_file`] with their content pulled from `contents` by path). Every
/// file-kind row MUST have a `contents` entry — an artifact-table row this
/// function is handed with no supplied bytes is a caller bug (a silently
/// unwritten config file is exactly the failure mode this refuses), so it
/// fails closed rather than skipping the row. Rows whose content is produced
/// by an external seal command (`SealedDaemonSecret`/`SealedCliSecret`) are
/// the caller's responsibility to exclude from `rows` — they are written by
/// that seal step, then ownership-applied via [`apply_ownership_and_mode`]
/// directly.
pub fn write_artifacts(
    rows: &[Artifact],
    contents: &BTreeMap<PathBuf, Vec<u8>>,
    resolver: &dyn OwnerResolver,
) -> Result<(), EnrollError> {
    for artifact in rows {
        match artifact.content {
            ContentKind::Dir => ensure_dir(artifact, resolver)?,
            _ => {
                let bytes = contents.get(&artifact.path).ok_or_else(|| {
                    EnrollError::State(format!(
                        "no content supplied for {}",
                        artifact.path.display()
                    ))
                })?;
                write_file(artifact, bytes, resolver)?;
            }
        }
    }
    Ok(())
}

// ---- YAML building (yaml_rust2::YamlEmitter, spec §7 "YAML, never JSON") ---

/// Build a `Yaml::Hash` from ordered key/value pairs (insertion order preserved
/// — `yaml_rust2`'s `Hash` is a `LinkedHashMap`, so the emitted document reads
/// in the order the caller wrote it, not alphabetized).
pub fn yaml_map(pairs: Vec<(&str, Yaml)>) -> Yaml {
    let mut h = Hash::new();
    for (k, v) in pairs {
        h.insert(Yaml::String(k.to_string()), v);
    }
    Yaml::Hash(h)
}

/// Emit a `Yaml` document to a `String` (trailing newline). `YamlEmitter::dump`
/// only fails on a `fmt::Write` error, which an in-memory `String` target never
/// produces — the `expect` is infallible in practice.
pub fn emit_yaml(doc: Yaml) -> String {
    let mut out = String::new();
    YamlEmitter::new(&mut out)
        .dump(&doc)
        .expect("in-memory String emit target cannot fail");
    out.push('\n');
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::enroll::artifact_table::{artifact_table, ContentKind};
    use std::os::unix::fs::MetadataExt;

    struct TempDir(PathBuf);
    impl TempDir {
        fn new(tag: &str) -> Self {
            let p = std::env::temp_dir()
                .join(format!("maknae-enroll-write-{}-{tag}", std::process::id()));
            let _ = std::fs::remove_dir_all(&p);
            std::fs::create_dir_all(&p).unwrap();
            TempDir(p)
        }
    }
    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    // A resolver that always leaves ownership untouched (`None, None`) — lets
    // these tests run unprivileged (no real chown to root/_maknae) while still
    // exercising mkdir/write/chmod/YAML-content shape for real.
    struct NoopOwnerResolver;
    impl OwnerResolver for NoopOwnerResolver {
        fn resolve(&self, _owner: Owner) -> Result<(Option<Uid>, Option<Gid>), EnrollError> {
            Ok((None, None))
        }
    }

    #[test]
    fn emit_yaml_round_trips_through_maknae_config_load_str() {
        let doc = yaml_map(vec![
            (
                "core",
                yaml_map(vec![("deployment_id", Yaml::String("dev-01".into()))]),
            ),
            (
                "vault",
                yaml_map(vec![("addr", Yaml::String("https://v:8200".into()))]),
            ),
        ]);
        let text = emit_yaml(doc);
        let parsed = maknae_config::load_str(&text).expect("round-trips through the loader");
        match parsed {
            maknae_config::Value::Map(entries) => {
                assert!(entries.iter().any(|(k, _)| k == "core"));
                assert!(entries.iter().any(|(k, _)| k == "vault"));
            }
            other => panic!("expected a map, got {other:?}"),
        }
    }

    #[test]
    fn emit_yaml_preserves_key_order() {
        let doc = yaml_map(vec![
            ("z", Yaml::Integer(1)),
            ("a", Yaml::Integer(2)),
            ("m", Yaml::Integer(3)),
        ]);
        let text = emit_yaml(doc);
        let z = text.find("z:").unwrap();
        let a = text.find("a:").unwrap();
        let m = text.find("m:").unwrap();
        assert!(
            z < a && a < m,
            "expected insertion order z,a,m; got {text:?}"
        );
    }

    #[test]
    fn ensure_dir_creates_and_chmods() {
        let td = TempDir::new("dir");
        let target = td.0.join("nested/dir");
        let artifact = Artifact {
            path: target.clone(),
            owner: Owner::Operator,
            mode: 0o700,
            content: ContentKind::Dir,
        };
        ensure_dir(&artifact, &NoopOwnerResolver).unwrap();
        let meta = std::fs::metadata(&target).unwrap();
        assert!(meta.is_dir());
        assert_eq!(meta.mode() & 0o777, 0o700);
    }

    #[test]
    fn write_file_writes_bytes_and_chmods() {
        let td = TempDir::new("file");
        let target = td.0.join("x.yaml");
        let artifact = Artifact {
            path: target.clone(),
            owner: Owner::Operator,
            mode: 0o600,
            content: ContentKind::CliYaml,
        };
        write_file(
            &artifact,
            b"core:\n  deployment_id: dev\n",
            &NoopOwnerResolver,
        )
        .unwrap();
        let got = std::fs::read_to_string(&target).unwrap();
        assert_eq!(got, "core:\n  deployment_id: dev\n");
        let meta = std::fs::metadata(&target).unwrap();
        assert_eq!(meta.mode() & 0o777, 0o600);
    }

    #[test]
    fn write_artifacts_fails_closed_on_missing_content() {
        let td = TempDir::new("missing");
        let rows = vec![Artifact {
            path: td.0.join("maknae.yaml"),
            owner: Owner::Operator,
            mode: 0o600,
            content: ContentKind::CliYaml,
        }];
        let contents = BTreeMap::new();
        assert!(matches!(
            write_artifacts(&rows, &contents, &NoopOwnerResolver),
            Err(EnrollError::State(_))
        ));
    }

    #[test]
    fn write_artifacts_applies_every_row_of_a_real_table() {
        let td = TempDir::new("full-cli");
        // Reuse the real CLI half of `artifact_table` (macos=false so it
        // includes the sealed-secret row, which we deliberately exclude below
        // — this integration test proves `write_artifacts` handles every OTHER
        // row of a real table end to end).
        let cli_dir = td.0.join("cli");
        let all = artifact_table(&cli_dir, false, false);
        let cli_rows: Vec<_> = all
            .into_iter()
            .filter(|a| a.path.starts_with(&cli_dir) && a.content != ContentKind::SealedCliSecret)
            .collect();
        let mut contents = BTreeMap::new();
        for row in &cli_rows {
            if row.content != ContentKind::Dir {
                contents.insert(row.path.clone(), b"placeholder\n".to_vec());
            }
        }
        write_artifacts(&cli_rows, &contents, &NoopOwnerResolver).expect("writes cleanly");
        assert!(cli_dir.is_dir());
        assert!(cli_dir.join("tls").is_dir());
        assert!(cli_dir.join("maknae.yaml").is_file());
        assert!(cli_dir.join("tls/vault-ca.crt").is_file());
        let meta = std::fs::metadata(&cli_dir).unwrap();
        assert_eq!(meta.mode() & 0o777, 0o700);
        let file_meta = std::fs::metadata(cli_dir.join("maknae.yaml")).unwrap();
        assert_eq!(file_meta.mode() & 0o777, 0o600);
    }

    #[test]
    fn self_owner_resolver_accepts_operator_and_rejects_others() {
        assert_eq!(
            SelfOwnerResolver.resolve(Owner::Operator).unwrap(),
            (None, None)
        );
        assert!(SelfOwnerResolver.resolve(Owner::RootRoot).is_err());
        assert!(SelfOwnerResolver.resolve(Owner::RootMaknaeGroup).is_err());
        assert!(SelfOwnerResolver.resolve(Owner::MaknaeMaknae).is_err());
    }

    #[test]
    fn real_owner_resolver_resolves_operator_without_lookup() {
        let r = RealOwnerResolver {
            operator_uid: 1000,
            operator_gid: 1000,
        };
        let (uid, gid) = r.resolve(Owner::Operator).unwrap();
        assert_eq!(uid, Some(Uid::from_raw(1000)));
        assert_eq!(gid, Some(Gid::from_raw(1000)));
    }

    #[test]
    fn real_owner_resolver_resolves_root_root_without_lookup() {
        let r = RealOwnerResolver {
            operator_uid: 1000,
            operator_gid: 1000,
        };
        let (uid, gid) = r.resolve(Owner::RootRoot).unwrap();
        assert_eq!(uid, Some(Uid::from_raw(0)));
        assert_eq!(gid, Some(Gid::from_raw(0)));
    }
}
