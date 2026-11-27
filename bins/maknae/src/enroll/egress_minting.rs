//! The Egress Daemon's minting identity (#168, ADR-0038). While
//! `egress/minting.yaml` exists, enroll writes the role id, keeps a SecretID in
//! custody and loads it through a unit drop-in; once it is gone, enroll
//! withdraws all three and destroys the SecretID.
#![cfg_attr(target_os = "macos", allow(dead_code))]
use super::agent::{dedup, io_error, is_not_found, AgentState};
use super::agent_access::Run;
use super::artifact_table::{self, Artifact, ContentKind};
use super::artifact_write::{self, OwnerResolver};
use super::secret_slot::{self, SecretSlot};
use super::EnrollError;
use maknae_config::MintingConfig;
use maknae_io::{AnchorRequired, FileOwner, MaknaeSecret, Mode, StrategyPref, TargetRequired};
use std::path::{Path, PathBuf};

pub(crate) const ROLE: &str = "maknae-egress";
pub(crate) const UNIT: &str = "maknae-egress.service";
const SMALL_FILE: u64 = 64 * 1024;

pub(crate) trait MintingOps {
    async fn read_role_id(&self, mount: &str) -> Result<String, EnrollError>;
    async fn mint(&self, mount: &str) -> Result<(MaknaeSecret, String), EnrollError>;
    async fn list_accessors(&self, mount: &str) -> Result<Vec<String>, EnrollError>;
    async fn destroy(&self, mount: &str, accessor: &str) -> Result<(), EnrollError>;
    /// `false` when Vault has no such mount or role.
    async fn role_exists(&self, mount: &str) -> Result<bool, EnrollError>;
    async fn seal(&self, secret: &MaknaeSecret, custody: &Path) -> Result<(), EnrollError>;
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Minting {
    Off,
    Enrolled { retired: usize },
    Withdrawn { destroyed: usize },
}

fn row(kind: ContentKind) -> Artifact {
    artifact_table::minting_rows()
        .into_iter()
        .find(|a| a.content == kind)
        .expect("minting_rows emits one row of each kind")
}

fn leaf(a: &Artifact) -> PathBuf {
    PathBuf::from(a.path.file_name().expect("a row path has a file name"))
}

fn parent(kind: ContentKind) -> PathBuf {
    row(kind)
        .path
        .parent()
        .expect("a row path has a parent")
        .to_path_buf()
}

pub(crate) fn minting_path() -> PathBuf {
    parent(ContentKind::MintRoleId).join(maknae_config::MINTING_FILE)
}

/// `None` when minting is off.
pub(crate) fn load(path: &Path) -> Result<Option<MintingConfig>, EnrollError> {
    maknae_config::load_minting(path)
        .map(|f| f.and_then(maknae_config::MintingFile::into_minting))
        .map_err(|e| EnrollError::MintingConfig {
            path: path.to_path_buf(),
            detail: e.to_string(),
        })
}

/// The Egress Daemon must not log in on maknaed's or an agent's mount.
pub(crate) fn check_mount(
    config: &MintingConfig,
    daemon_mount: &str,
    agent_mounts: &[String],
) -> Result<(), EnrollError> {
    let mount = &config.vault.approle_mount;
    let same = |other: &str| mount.trim_matches('/') == other.trim_matches('/');
    if same(daemon_mount) {
        return Err(EnrollError::InvalidVaultMount(format!(
            "minting.yaml vault.approle_mount {mount} is maknaed's own AppRole mount; the Egress Daemon logs in on its own mount"
        )));
    }
    if agent_mounts.iter().any(|m| same(m)) {
        return Err(EnrollError::InvalidVaultMount(format!(
            "minting.yaml vault.approle_mount {mount} is an agent's AppRole mount; the Egress Daemon logs in on its own mount"
        )));
    }
    super::agent::check_mount("minting.yaml vault.approle_mount", mount)
}

/// Where this host keeps the minting artifacts; `root` owns every one, and the
/// role id is readable by `egress_group`.
pub(crate) struct MintingFiles<'a> {
    pub egress: PathBuf,
    pub private: PathBuf,
    pub units: PathBuf,
    pub root: FileOwner,
    pub egress_group: u32,
    pub resolver: &'a dyn OwnerResolver,
}

impl MintingFiles<'_> {
    pub(crate) fn host(
        resolver: &artifact_write::RealOwnerResolver,
    ) -> Result<MintingFiles<'_>, EnrollError> {
        let egress_group = match resolver.resolve(artifact_table::Owner::RootMaknaeEgressGroup)? {
            (_, Some(gid)) => gid.as_raw(),
            (_, None) => return Err(EnrollError::Owner("no _maknae-egress group".to_string())),
        };
        Ok(MintingFiles {
            egress: parent(ContentKind::MintRoleId),
            private: parent(ContentKind::SealedEgressSecretId),
            units: parent(ContentKind::Dir),
            root: FileOwner { uid: 0, gid: 0 },
            egress_group,
            resolver,
        })
    }

    pub(crate) fn custody_path(&self) -> PathBuf {
        self.private
            .join(leaf(&row(ContentKind::SealedEgressSecretId)))
    }

    /// Held from the state read through retirement, so two enrolls never each
    /// retire the SecretID the other just installed.
    fn lock_slot(&self) -> Result<Option<maknae_io::AnchorLock>, EnrollError> {
        let Some(private) = self.anchor(&self.private, 0o027)? else {
            return Ok(None);
        };
        private.try_lock_exclusive().map(Some).map_err(|e| match e {
            maknae_io::IoError::Locked { .. } => EnrollError::State(
                "another maknae enroll is running; the Egress Daemon's SecretID is left as it was"
                    .to_string(),
            ),
            e => io_error(&self.private, e),
        })
    }

    fn state_path(&self) -> PathBuf {
        self.private.join(leaf(&row(ContentKind::EnrollState)))
    }

    fn drop_in_dir(&self) -> PathBuf {
        self.units.join(leaf(&row(ContentKind::Dir)))
    }

    fn anchor(&self, dir: &Path, mode_mask: u32) -> Result<Option<maknae_io::Anchor>, EnrollError> {
        let required = AnchorRequired {
            owner: Some(self.root.uid),
            mode_mask: Some(mode_mask),
        };
        match maknae_io::open_anchor(dir, required, StrategyPref::Auto) {
            Ok(a) => Ok(Some(a)),
            Err(e) if is_not_found(&e) => Ok(None),
            Err(e) => Err(io_error(dir, e)),
        }
    }

    fn existing(&self, dir: &Path, mode_mask: u32) -> Result<maknae_io::Anchor, EnrollError> {
        self.anchor(dir, mode_mask)?
            .ok_or_else(|| EnrollError::State(format!("{} does not exist", dir.display())))
    }

    /// `Ok(false)` when there was nothing to remove.
    fn remove_in(&self, dir: &Path, mode_mask: u32, file: &Path) -> Result<bool, EnrollError> {
        let Some(anchor) = self.anchor(dir, mode_mask)? else {
            return Ok(false);
        };
        match anchor.remove(file, None) {
            Ok(_) => Ok(true),
            Err(e) if is_not_found(&e) => Ok(false),
            Err(e) => Err(io_error(&dir.join(file), e)),
        }
    }

    fn read_state(&self) -> Result<AgentState, EnrollError> {
        let Some(anchor) = self.anchor(&self.private, 0o027)? else {
            return Ok(AgentState::default());
        };
        let target = TargetRequired {
            owner: Some(self.root.uid),
            mode_mask: Some(0o077),
            nlink_exactly_one: true,
            regular_file: true,
            max_bytes: Some(SMALL_FILE),
        };
        let path = self.state_path();
        match anchor.read(&leaf(&row(ContentKind::EnrollState)), None, target) {
            Ok(out) => std::str::from_utf8(&out.value)
                .map_err(|_| EnrollError::State(format!("{} is not UTF-8", path.display())))
                .and_then(AgentState::parse)
                .map_err(|e| EnrollError::State(format!("{}: {e}", path.display()))),
            Err(e) if is_not_found(&e) => Ok(AgentState::default()),
            Err(e) => Err(io_error(&path, e)),
        }
    }

    fn write_state(&self, state: &AgentState) -> Result<(), EnrollError> {
        let r = row(ContentKind::EnrollState);
        self.existing(&self.private, 0o027)?
            .publish_owned(
                &leaf(&r),
                None,
                state.to_yaml().as_bytes(),
                Mode(r.mode),
                self.root,
            )
            .map(drop)
            .map_err(|e| io_error(&self.state_path(), e))
    }

    fn remove_state(&self) -> Result<(), EnrollError> {
        self.remove_in(&self.private, 0o027, &leaf(&row(ContentKind::EnrollState)))
            .map(drop)
    }

    fn write_role_id(&self, role_id: &str) -> Result<(), EnrollError> {
        let r = row(ContentKind::MintRoleId);
        self.existing(&self.egress, 0o022)?
            .publish_owned(
                &leaf(&r),
                None,
                role_id.as_bytes(),
                Mode(r.mode),
                FileOwner {
                    uid: self.root.uid,
                    gid: self.egress_group,
                },
            )
            .map_err(|e| io_error(&self.egress.join(leaf(&r)), e))?;
        artifact_write::maybe_restorecon(&self.egress.join(leaf(&r)));
        Ok(())
    }

    fn remove_role_id(&self) -> Result<(), EnrollError> {
        self.remove_in(&self.egress, 0o022, &leaf(&row(ContentKind::MintRoleId)))
            .map(drop)
    }

    fn remove_custody(&self) -> Result<(), EnrollError> {
        self.remove_in(
            &self.private,
            0o027,
            &leaf(&row(ContentKind::SealedEgressSecretId)),
        )
        .map(drop)
    }

    fn write_drop_in(&self) -> Result<(), EnrollError> {
        let dir = row(ContentKind::Dir);
        let file = row(ContentKind::UnitDropIn);
        artifact_write::ensure_dir(
            &Artifact {
                path: self.drop_in_dir(),
                ..dir
            },
            self.resolver,
        )?;
        let path = self.drop_in_dir().join(leaf(&file));
        self.existing(&self.drop_in_dir(), 0o022)?
            .publish_owned(
                &leaf(&file),
                None,
                drop_in().as_bytes(),
                Mode(file.mode),
                self.root,
            )
            .map_err(|e| io_error(&path, e))?;
        artifact_write::maybe_restorecon(&path);
        Ok(())
    }

    /// Leaves the empty drop-in directory: `maknae-io` removes no directory.
    fn remove_drop_in(&self) -> Result<bool, EnrollError> {
        self.remove_in(
            &self.drop_in_dir(),
            0o022,
            &leaf(&row(ContentKind::UnitDropIn)),
        )
    }
}

pub(crate) fn drop_in() -> String {
    format!(
        "[Service]\nLoadCredentialEncrypted={}:{}\n",
        maknae_vault::EGRESS_SECRET_ID_CRED_NAME,
        row(ContentKind::SealedEgressSecretId).path.display()
    )
}

struct EgressSlot<'a, O> {
    ops: &'a O,
    files: &'a MintingFiles<'a>,
    mount: &'a str,
}

impl<O: MintingOps> SecretSlot for EgressSlot<'_, O> {
    type Sealed = ();

    async fn mint(&self) -> Result<(MaknaeSecret, String), EnrollError> {
        self.ops.mint(self.mount).await
    }

    fn write_state(&self, state: &AgentState) -> Result<(), EnrollError> {
        self.files.write_state(state)
    }

    async fn seal(&self, secret: &MaknaeSecret) -> Result<(), EnrollError> {
        self.ops
            .seal(secret, &self.files.custody_path())
            .await
            .map_err(|e| super::agent::scrub_secret(e, secret))
    }

    async fn destroy(&self, accessor: &str) -> Result<(), EnrollError> {
        self.ops.destroy(self.mount, accessor).await
    }

    fn orphaned(&self, accessor: String, cause: EnrollError, recorded: bool) -> EnrollError {
        EnrollError::EgressOrphanedAccessor {
            accessor,
            cause: cause.to_string(),
            recorded,
        }
    }
}

pub(crate) async fn enroll_minting<O: MintingOps>(
    ops: &O,
    files: &MintingFiles<'_>,
    run: &dyn Run,
    minting: Option<&MintingConfig>,
    daemon_mount: &str,
    agent_mounts: &[String],
) -> Result<Minting, EnrollError> {
    let _slot = files.lock_slot()?;
    let prior = files.read_state()?;
    match minting {
        Some(config) => {
            check_mount(config, daemon_mount, agent_mounts)?;
            enroll(ops, files, run, &config.vault.approle_mount, prior).await
        }
        None => withdraw(ops, files, run, prior).await,
    }
}

async fn enroll<O: MintingOps>(
    ops: &O,
    files: &MintingFiles<'_>,
    run: &dyn Run,
    mount: &str,
    prior: AgentState,
) -> Result<Minting, EnrollError> {
    if !prior.approle_mount.is_empty() && prior.approle_mount != mount {
        return Err(EnrollError::State(format!(
            "minting.yaml names AppRole mount {mount}, but {} records SecretIDs on {}; move minting.yaml aside and run maknae enroll to withdraw them, then restore it",
            files.state_path().display(),
            prior.approle_mount
        )));
    }
    let role_id = ops.read_role_id(mount).await?;
    files.write_role_id(&role_id)?;
    let base = AgentState {
        approle_mount: mount.to_string(),
        role: ROLE.to_string(),
        ..prior
    };
    let slot = EgressSlot { ops, files, mount };
    let (acc, ()) = secret_slot::mint_and_seal(&slot, &base).await?;
    let listed = ops.list_accessors(mount).await?;
    let retiring = secret_slot::retiring(&base, &listed, &acc);
    let live = AgentState {
        live: vec![acc],
        pending: Vec::new(),
        retiring: retiring.clone(),
        ..base
    };
    files.write_state(&live)?;
    files.write_drop_in()?;
    super::agent_unit::reload_and_try_restart(run, UNIT)?;
    let (_, failures) = secret_slot::retire(&slot, live).await?;
    if !failures.is_empty() {
        return Err(EnrollError::EgressRetireFailed {
            accessors: failures,
        });
    }
    Ok(Minting::Enrolled {
        retired: retiring.len(),
    })
}

async fn withdraw<O: MintingOps>(
    ops: &O,
    files: &MintingFiles<'_>,
    run: &dyn Run,
    prior: AgentState,
) -> Result<Minting, EnrollError> {
    let unloaded = files.remove_drop_in()?;
    if unloaded {
        super::agent_unit::reload_and_try_restart(run, UNIT)?;
    }
    files.remove_custody()?;
    files.remove_role_id()?;
    if prior.approle_mount.is_empty() {
        files.remove_state()?;
        return Ok(if unloaded {
            Minting::Withdrawn { destroyed: 0 }
        } else {
            Minting::Off
        });
    }
    let mount = prior.approle_mount.clone();
    let all = dedup(
        prior
            .live
            .iter()
            .chain(&prior.pending)
            .chain(&prior.retiring),
    );
    let retiring = AgentState {
        live: Vec::new(),
        pending: Vec::new(),
        retiring: all.clone(),
        ..prior
    };
    files.write_state(&retiring)?;
    let slot = EgressSlot {
        ops,
        files,
        mount: &mount,
    };
    let (_, failures) = secret_slot::retire(&slot, retiring).await?;
    // A deleted mount or role took its SecretIDs with it.
    if !failures.is_empty() && ops.role_exists(&mount).await? {
        return Err(EnrollError::EgressRetireFailed {
            accessors: failures,
        });
    }
    files.remove_state()?;
    Ok(Minting::Withdrawn {
        destroyed: all.len(),
    })
}

pub(crate) struct RealMintingOps<'a> {
    pub client: &'a maknae_vault::OperatorClient,
    pub verbose: bool,
}

impl MintingOps for RealMintingOps<'_> {
    async fn read_role_id(&self, mount: &str) -> Result<String, EnrollError> {
        Ok(self.client.read_role_id(mount, ROLE).await?)
    }

    async fn mint(&self, mount: &str) -> Result<(MaknaeSecret, String), EnrollError> {
        Ok(self.client.mint_secret_id(mount, ROLE).await?)
    }

    async fn list_accessors(&self, mount: &str) -> Result<Vec<String>, EnrollError> {
        Ok(self.client.list_secret_id_accessors(mount, ROLE).await?)
    }

    async fn destroy(&self, mount: &str, accessor: &str) -> Result<(), EnrollError> {
        Ok(self
            .client
            .destroy_accessor_if_present(mount, ROLE, accessor)
            .await?)
    }

    async fn role_exists(&self, mount: &str) -> Result<bool, EnrollError> {
        Ok(self.client.find_role_id(mount, ROLE).await?.is_some())
    }

    async fn seal(&self, secret: &MaknaeSecret, custody: &Path) -> Result<(), EnrollError> {
        super::seal_linux(
            secret.expose().as_bytes(),
            custody,
            maknae_vault::EGRESS_SECRET_ID_CRED_NAME,
            self.verbose,
        )
        .await?;
        artifact_write::apply_ownership_and_mode(
            &Artifact {
                path: custody.to_path_buf(),
                ..row(ContentKind::SealedEgressSecretId)
            },
            &artifact_write::RealOwnerResolver {
                operator_uid: 0,
                operator_gid: 0,
            },
        )
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::disallowed_methods)]
    use super::super::agent::tests::{scratch_anchor, strings, Scratch};
    use super::super::agent_access::Ran;
    use super::*;
    use maknae_io::program::Program;
    use std::cell::RefCell;
    use std::collections::HashSet;
    use std::os::unix::fs::{MetadataExt, PermissionsExt};
    use zeroize::Zeroizing;

    const SENTINEL: &str = "e9e55e11-0000-4000-8000-5ec7e7aa0000";
    const ROLE_ID: &str = "egress-role-uuid-1111";
    const MOUNT: &str = "maknae-egress-approle";
    const DAEMON_MOUNT: &str = "maknae-approle";

    #[derive(Default)]
    struct Fake {
        log: RefCell<Vec<String>>,
        listed: Vec<String>,
        fail: HashSet<String>,
        role_gone: bool,
    }

    impl Fake {
        fn log(&self) -> Vec<String> {
            self.log.borrow().clone()
        }

        fn push(&self, line: String) -> Result<(), EnrollError> {
            let failed = self.fail.contains(&line);
            self.log.borrow_mut().push(line.clone());
            if failed {
                Err(EnrollError::State(format!("{line} failed")))
            } else {
                Ok(())
            }
        }
    }

    impl MintingOps for Fake {
        async fn read_role_id(&self, mount: &str) -> Result<String, EnrollError> {
            self.push(format!("read_role_id {mount}"))?;
            Ok(ROLE_ID.into())
        }

        async fn mint(&self, mount: &str) -> Result<(MaknaeSecret, String), EnrollError> {
            self.push(format!("mint {mount}"))?;
            Ok((
                MaknaeSecret::new(Zeroizing::new(SENTINEL.into())).unwrap(),
                "acc-new".into(),
            ))
        }

        async fn list_accessors(&self, mount: &str) -> Result<Vec<String>, EnrollError> {
            self.push(format!("list {mount}"))?;
            Ok(self.listed.clone())
        }

        async fn destroy(&self, mount: &str, accessor: &str) -> Result<(), EnrollError> {
            self.push(format!("destroy {mount} {accessor}"))
        }

        async fn role_exists(&self, mount: &str) -> Result<bool, EnrollError> {
            self.push(format!("role_exists {mount}"))?;
            Ok(!self.role_gone)
        }

        async fn seal(&self, secret: &MaknaeSecret, custody: &Path) -> Result<(), EnrollError> {
            self.push("seal".into())?;
            std::fs::write(custody, secret.expose().as_bytes()).unwrap();
            std::fs::set_permissions(custody, std::fs::Permissions::from_mode(0o600)).unwrap();
            Ok(())
        }
    }

    impl Run for Fake {
        fn run(&self, program: Program, args: &[String]) -> Result<Ran, String> {
            let line = format!("{program} {}", args.join(" "));
            let ok = !self.fail.contains(&line);
            self.log.borrow_mut().push(line);
            Ok(Ran {
                ok,
                code: Some(if ok { 0 } else { 1 }),
                stdout: String::new(),
                stderr: String::new(),
            })
        }
    }

    struct Mine;
    impl OwnerResolver for Mine {
        fn resolve(
            &self,
            _owner: artifact_table::Owner,
        ) -> Result<(Option<nix::unistd::Uid>, Option<nix::unistd::Gid>), EnrollError> {
            Ok((None, None))
        }
    }

    struct Host {
        _dirs: [Scratch; 3],
        files: MintingFiles<'static>,
    }

    fn host(tag: &str) -> Host {
        let dir = |name: &str| {
            let (d, _) = scratch_anchor(&format!("minting-{tag}-{name}"));
            std::fs::set_permissions(&*d, std::fs::Permissions::from_mode(0o750)).unwrap();
            d
        };
        let (e, p, u) = (dir("egress"), dir("private"), dir("units"));
        let me = FileOwner {
            uid: nix::unistd::geteuid().as_raw(),
            gid: nix::unistd::getegid().as_raw(),
        };
        let files = MintingFiles {
            egress: e.to_path_buf(),
            private: p.to_path_buf(),
            units: u.to_path_buf(),
            root: me,
            egress_group: me.gid,
            resolver: &Mine,
        };
        Host {
            _dirs: [e, p, u],
            files,
        }
    }

    impl Host {
        fn role_id(&self) -> PathBuf {
            self.files.egress.join("role-id")
        }
        fn drop_in(&self) -> PathBuf {
            self.files
                .units
                .join("maknae-egress.service.d/50-minting.conf")
        }
        fn state(&self) -> PathBuf {
            self.files.private.join("maknae-egress-enroll-state.yaml")
        }
        fn read_state(&self) -> AgentState {
            AgentState::parse(&std::fs::read_to_string(self.state()).unwrap()).unwrap()
        }
        fn write_state(&self, live: &[&str]) {
            self.files
                .write_state(&AgentState {
                    approle_mount: MOUNT.into(),
                    role: ROLE.into(),
                    live: strings(live),
                    ..AgentState::default()
                })
                .unwrap();
        }
    }

    fn config() -> MintingConfig {
        MintingConfig {
            vault: maknae_config::MintVault {
                approle_mount: MOUNT.into(),
            },
            github_apps: Default::default(),
        }
    }

    async fn on(h: &Host, fake: &Fake, minting: bool) -> Result<Minting, EnrollError> {
        let c = config();
        enroll_minting(
            fake,
            &h.files,
            fake,
            minting.then_some(&c),
            DAEMON_MOUNT,
            &[],
        )
        .await
    }

    const RELOAD: &str = "/usr/bin/systemctl daemon-reload";
    const RESTART: &str = "/usr/bin/systemctl try-restart maknae-egress.service";

    #[tokio::test]
    async fn enroll_with_minting_writes_role_id_secret_id_and_dropin() {
        let h = host("writes");
        let fake = Fake::default();
        assert_eq!(
            on(&h, &fake, true).await.unwrap(),
            Minting::Enrolled { retired: 0 }
        );
        assert_eq!(std::fs::read_to_string(h.role_id()).unwrap(), ROLE_ID);
        let meta = std::fs::metadata(h.role_id()).unwrap();
        assert_eq!(meta.mode() & 0o7777, 0o640);
        assert_eq!(meta.gid(), h.files.egress_group);
        assert_eq!(
            std::fs::read_to_string(h.files.custody_path()).unwrap(),
            SENTINEL
        );
        assert_eq!(
            h.files.custody_path(),
            h.files.private.join("maknae-egress-secret-id.cred")
        );
        assert_eq!(
            std::fs::read_to_string(h.drop_in()).unwrap(),
            "[Service]\nLoadCredentialEncrypted=maknae-egress-secret-id:/etc/maknae/private/maknae-egress-secret-id.cred\n"
        );
        assert_eq!(
            std::fs::metadata(h.drop_in()).unwrap().mode() & 0o7777,
            0o644
        );
        assert_eq!(
            fake.log(),
            strings(&[
                &format!("read_role_id {MOUNT}"),
                &format!("mint {MOUNT}"),
                "seal",
                &format!("list {MOUNT}"),
                RELOAD,
                RESTART,
            ])
        );
        assert_eq!(
            h.read_state(),
            AgentState {
                approle_mount: MOUNT.into(),
                role: ROLE.into(),
                live: strings(&["acc-new"]),
                ..AgentState::default()
            }
        );
    }

    #[tokio::test]
    async fn enroll_without_minting_writes_none_and_removes_a_stale_dropin() {
        let h = host("none");
        let fake = Fake::default();
        assert_eq!(on(&h, &fake, false).await.unwrap(), Minting::Off);
        assert!(fake.log().is_empty());
        for p in [h.role_id(), h.drop_in(), h.files.custody_path(), h.state()] {
            assert!(!p.exists(), "{}", p.display());
        }

        let h = host("stale");
        on(&h, &Fake::default(), true).await.unwrap();
        let fake = Fake::default();
        assert_eq!(
            on(&h, &fake, false).await.unwrap(),
            Minting::Withdrawn { destroyed: 1 }
        );
        for p in [h.role_id(), h.drop_in(), h.files.custody_path(), h.state()] {
            assert!(!p.exists(), "{}", p.display());
        }
        assert_eq!(
            fake.log(),
            strings(&[RELOAD, RESTART, &format!("destroy {MOUNT} acc-new")])
        );

        let h = host("dropin-only");
        h.files.write_drop_in().unwrap();
        let fake = Fake::default();
        assert_eq!(
            on(&h, &fake, false).await.unwrap(),
            Minting::Withdrawn { destroyed: 0 }
        );
        assert!(!h.drop_in().exists());
        assert_eq!(fake.log(), strings(&[RELOAD, RESTART]));
    }

    #[tokio::test]
    async fn a_failed_destroy_on_withdrawal_stays_recorded() {
        let h = host("withdraw-fails");
        h.write_state(&["a1", "a2"]);
        let fake = Fake {
            fail: [format!("destroy {MOUNT} a1")].into(),
            ..Fake::default()
        };
        let e = on(&h, &fake, false).await.unwrap_err();
        assert!(
            matches!(&e, EnrollError::EgressRetireFailed { accessors } if accessors == &strings(&["a1"])),
            "{e:?}"
        );
        assert_eq!(h.read_state().retiring, strings(&["a1"]));
        assert!(e.to_string().contains("maknae-egress-enroll-state.yaml"));
        assert_eq!(fake.log().last().unwrap(), &format!("role_exists {MOUNT}"));
    }

    #[tokio::test]
    async fn withdrawal_completes_once_vault_no_longer_has_the_role_or_mount() {
        let h = host("withdraw-gone");
        h.write_state(&["a1", "a2"]);
        let fake = Fake {
            fail: [format!("destroy {MOUNT} a1"), format!("destroy {MOUNT} a2")].into(),
            role_gone: true,
            ..Fake::default()
        };
        assert_eq!(
            on(&h, &fake, false).await.unwrap(),
            Minting::Withdrawn { destroyed: 2 }
        );
        assert!(!h.state().exists());
        assert_eq!(
            fake.log(),
            strings(&[
                &format!("destroy {MOUNT} a1"),
                &format!("destroy {MOUNT} a2"),
                &format!("role_exists {MOUNT}"),
            ])
        );
        assert!(on(&h, &Fake::default(), false).await.is_ok());
    }

    #[tokio::test]
    async fn a_second_enroll_keeps_minting_yaml_untouched() {
        let h = host("untouched");
        let yaml = h.files.egress.join("minting.yaml");
        std::fs::write(&yaml, "vault:\n  approle_mount: maknae-egress-approle\n").unwrap();
        std::fs::set_permissions(&yaml, std::fs::Permissions::from_mode(0o640)).unwrap();
        let before = std::fs::metadata(&yaml).unwrap();
        let bytes = std::fs::read(&yaml).unwrap();
        for _ in 0..2 {
            on(&h, &Fake::default(), true).await.unwrap();
        }
        let after = std::fs::metadata(&yaml).unwrap();
        assert_eq!(std::fs::read(&yaml).unwrap(), bytes);
        assert_eq!(
            (after.ino(), after.mode(), after.mtime(), after.mtime_nsec()),
            (
                before.ino(),
                before.mode(),
                before.mtime(),
                before.mtime_nsec()
            )
        );
    }

    #[tokio::test]
    async fn rotate_replaces_the_egress_secret_id_new_first() {
        let h = host("rotate");
        h.write_state(&["old"]);
        let fake = Fake {
            listed: strings(&["old", "stray", "acc-new"]),
            ..Fake::default()
        };
        assert_eq!(
            on(&h, &fake, true).await.unwrap(),
            Minting::Enrolled { retired: 2 }
        );
        assert_eq!(
            fake.log(),
            strings(&[
                &format!("read_role_id {MOUNT}"),
                &format!("mint {MOUNT}"),
                "seal",
                &format!("list {MOUNT}"),
                RELOAD,
                RESTART,
                &format!("destroy {MOUNT} old"),
                &format!("destroy {MOUNT} stray"),
            ])
        );
        assert_eq!(
            std::fs::read_to_string(h.files.custody_path()).unwrap(),
            SENTINEL
        );
        assert_eq!(
            h.read_state(),
            AgentState {
                approle_mount: MOUNT.into(),
                role: ROLE.into(),
                live: strings(&["acc-new"]),
                ..AgentState::default()
            }
        );

        let h = host("rotate-seal-fails");
        h.write_state(&["old"]);
        let fake = Fake {
            fail: ["seal".to_string()].into(),
            ..Fake::default()
        };
        on(&h, &fake, true).await.unwrap_err();
        assert_eq!(
            fake.log(),
            strings(&[
                &format!("read_role_id {MOUNT}"),
                &format!("mint {MOUNT}"),
                "seal",
                &format!("destroy {MOUNT} acc-new"),
            ])
        );
        assert_eq!(h.read_state().live, strings(&["old"]));
        assert!(!h.drop_in().exists());
    }

    #[tokio::test]
    async fn maknaeds_own_mount_or_a_moved_mount_is_refused_before_any_call() {
        let h = host("mounts");
        let fake = Fake::default();
        let c = config();
        let e = enroll_minting(&fake, &h.files, &fake, Some(&c), MOUNT, &[])
            .await
            .unwrap_err();
        assert!(matches!(e, EnrollError::InvalidVaultMount(_)), "{e:?}");

        h.files
            .write_state(&AgentState {
                approle_mount: "elsewhere".into(),
                ..AgentState::default()
            })
            .unwrap();
        let e = on(&h, &fake, true).await.unwrap_err();
        assert!(e.to_string().contains("elsewhere"), "{e}");
        assert!(fake.log().is_empty());
        assert!(!h.role_id().exists());
    }

    #[tokio::test]
    async fn an_agent_s_approle_mount_is_refused_before_any_call() {
        let h = host("agent-mount");
        let fake = Fake::default();
        let c = config();
        for agents in [
            strings(&[MOUNT]),
            strings(&["maknae-agent-approle", &format!("/{MOUNT}/")]),
        ] {
            let e = check_mount(&c, DAEMON_MOUNT, &agents).unwrap_err();
            assert!(
                matches!(&e, EnrollError::InvalidVaultMount(m) if m.contains("an agent's AppRole mount")),
                "{e:?}"
            );
            let e = enroll_minting(&fake, &h.files, &fake, Some(&c), DAEMON_MOUNT, &agents)
                .await
                .unwrap_err();
            assert!(matches!(e, EnrollError::InvalidVaultMount(_)), "{e:?}");
        }
        assert!(check_mount(&c, DAEMON_MOUNT, &strings(&["maknae-agent-approle"])).is_ok());
        assert!(fake.log().is_empty());
        assert!(!h.role_id().exists());
    }

    #[tokio::test]
    async fn a_second_enroll_while_one_holds_the_slot_is_refused_before_any_call() {
        let h = host("locked");
        let fake = Fake::default();
        h.write_state(&["old"]);
        let held = maknae_io::open_anchor(
            &h.files.private,
            AnchorRequired {
                owner: None,
                mode_mask: None,
            },
            StrategyPref::Auto,
        )
        .unwrap();
        let _lock = held.try_lock_exclusive().unwrap();
        for minting in [true, false] {
            let e = on(&h, &fake, minting).await.unwrap_err();
            assert!(
                matches!(&e, EnrollError::State(m) if m.contains("another maknae enroll is running")),
                "{e:?}"
            );
        }
        assert!(fake.log().is_empty(), "{:?}", fake.log());
        assert_eq!(h.read_state().live, strings(&["old"]));
        assert!(!h.role_id().exists());
    }

    #[test]
    fn a_minting_yaml_that_cannot_be_used_names_its_path_and_requirement() {
        let (d, _) = scratch_anchor("minting-load");
        let path = d.join("minting.yaml");
        assert_eq!(load(&path).unwrap(), None);
        for (mode, text) in [
            (0o644, "vault:\n  approle_mount: m\n"),
            (0o640, "vault: [\n"),
        ] {
            std::fs::write(&path, text).unwrap();
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(mode)).unwrap();
            let e = load(&path).unwrap_err();
            let shown = e.to_string();
            assert!(
                shown.contains(&path.display().to_string())
                    && shown.contains("root:_maknae-egress")
                    && shown.contains("0640"),
                "{shown}"
            );
        }
    }

    #[test]
    fn the_minting_path_is_the_one_the_egress_daemon_reads() {
        assert_eq!(minting_path(), Path::new("/etc/maknae/egress/minting.yaml"));
        assert_eq!(ROLE, "maknae-egress");
    }
}
