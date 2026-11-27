//! An Agent Daemon's seal key pair (#168): the private half in `systemd-creds`
//! custody for its unit, the public half where the Egress Daemon reads it.
use super::agent::{io_error, is_not_found, ETC_DIR, PRIVATE_DIR};
use super::artifact_table::{self, Artifact, ContentKind};
use super::artifact_write::{self, OwnerResolver};
use super::{seal_key_action, EnrollError, GenerateStep, SealKeyAction, GENERATE_STEPS};
use maknae_io::{
    AnchorRequired, DescendantRequired, FileOwner, Mode, StrategyPref, TargetRequired,
};
use maknae_vault::agent_enroll::AgentId;
use std::path::{Path, PathBuf};

pub(crate) trait Custody {
    async fn store(&self, der: &[u8], path: &Path, cred_name: &str) -> Result<(), EnrollError>;
}

/// Where one host keeps both halves. `root` owns every artifact; the public half
/// is published as `publisher`.
pub(crate) struct SealPair<'a> {
    pub egress: PathBuf,
    pub private: PathBuf,
    pub root: u32,
    pub publisher: FileOwner,
    pub resolver: &'a dyn OwnerResolver,
}

fn row(agent: &AgentId, kind: ContentKind) -> Artifact {
    artifact_table::agent_seal_rows(agent)
        .into_iter()
        .find(|a| a.content == kind)
        .expect("agent_seal_rows emits one row of each kind")
}

fn leaf(a: &Artifact) -> PathBuf {
    PathBuf::from(a.path.file_name().expect("a row path has a file name"))
}

impl SealPair<'_> {
    pub(crate) fn custody_path(&self, agent: &AgentId) -> PathBuf {
        self.private
            .join(leaf(&row(agent, ContentKind::SealedAgentSealKey)))
    }

    fn agents_dir(&self, agent: &AgentId) -> PathBuf {
        self.egress.join(leaf(&row(agent, ContentKind::Dir)))
    }

    pub(crate) fn pub_path(&self, agent: &AgentId) -> PathBuf {
        self.agents_dir(agent)
            .join(leaf(&row(agent, ContentKind::AgentSealPub)))
    }

    fn rel_pub(&self, agent: &AgentId) -> PathBuf {
        leaf(&row(agent, ContentKind::Dir)).join(leaf(&row(agent, ContentKind::AgentSealPub)))
    }

    fn descendant(&self) -> DescendantRequired {
        DescendantRequired {
            owner: Some(self.root),
            mode_mask: Some(0o022),
        }
    }

    fn egress_anchor(&self) -> Result<Option<maknae_io::Anchor>, EnrollError> {
        let required = AnchorRequired {
            owner: Some(self.root),
            mode_mask: Some(0o022),
        };
        match maknae_io::open_anchor(&self.egress, required, StrategyPref::Auto) {
            Ok(a) => Ok(Some(a)),
            Err(e) if is_not_found(&e) => Ok(None),
            Err(e) => Err(io_error(&self.egress, e)),
        }
    }

    fn custody_present(&self, agent: &AgentId) -> bool {
        super::sealed_custody_present(&self.custody_path(agent), self.root)
    }

    fn pub_present(&self, agent: &AgentId) -> bool {
        let Ok(Some(anchor)) = self.egress_anchor() else {
            return false;
        };
        let target = TargetRequired {
            owner: Some(self.root),
            mode_mask: Some(0o027),
            nlink_exactly_one: true,
            regular_file: true,
            max_bytes: Some(maknae_seal::SEAL_PUB_PEM_LEN as u64),
        };
        anchor
            .read(&self.rel_pub(agent), Some(self.descendant()), target)
            .ok()
            .and_then(|out| String::from_utf8(out.value.to_vec()).ok())
            .is_some_and(|pem| maknae_seal::SealPublicKey::from_pem(&pem).is_ok())
    }

    fn retract_pub(&self, agent: &AgentId) -> Result<(), EnrollError> {
        let Some(anchor) = self.egress_anchor()? else {
            return Ok(());
        };
        match anchor.remove(&self.rel_pub(agent), Some(self.descendant())) {
            Ok(_) => Ok(()),
            Err(e) if is_not_found(&e) => Ok(()),
            Err(e) => Err(io_error(&self.pub_path(agent), e)),
        }
    }

    fn publish_pub(&self, agent: &AgentId, pem: &str) -> Result<(), EnrollError> {
        let anchor = self.egress_anchor()?.ok_or_else(|| {
            EnrollError::HostNotEnrolled(format!(
                "{} does not exist; run maknae enroll first",
                self.egress.display()
            ))
        })?;
        let dir = row(agent, ContentKind::Dir);
        artifact_write::ensure_dir(
            &Artifact {
                path: self.agents_dir(agent),
                ..dir
            },
            self.resolver,
        )?;
        let file = row(agent, ContentKind::AgentSealPub);
        anchor
            .publish_owned(
                &self.rel_pub(agent),
                Some(self.descendant()),
                pem.as_bytes(),
                Mode(file.mode),
                self.publisher,
            )
            .map_err(|e| io_error(&self.pub_path(agent), e))?;
        artifact_write::maybe_restorecon(&self.pub_path(agent));
        Ok(())
    }

    fn remove_custody(&self, agent: &AgentId) -> Result<(), EnrollError> {
        let required = AnchorRequired {
            owner: Some(self.root),
            mode_mask: Some(0o027),
        };
        let anchor = match maknae_io::open_anchor(&self.private, required, StrategyPref::Auto) {
            Ok(a) => a,
            Err(e) if is_not_found(&e) => return Ok(()),
            Err(e) => return Err(io_error(&self.private, e)),
        };
        let file = leaf(&row(agent, ContentKind::SealedAgentSealKey));
        match anchor.remove(&file, None) {
            Ok(_) => Ok(()),
            Err(e) if is_not_found(&e) => Ok(()),
            Err(e) => Err(io_error(&self.custody_path(agent), e)),
        }
    }
}

/// This host's pair: `/etc/maknae/egress` and `/etc/maknae/private`, owned by root,
/// the public half readable by the `_maknae-egress` group.
pub(crate) fn host_pair(
    resolver: &artifact_write::RealOwnerResolver,
) -> Result<SealPair<'_>, EnrollError> {
    let gid = match resolver.resolve(artifact_table::Owner::RootMaknaeEgressGroup)? {
        (_, Some(gid)) => gid.as_raw(),
        (_, None) => return Err(EnrollError::Owner("no _maknae-egress group".to_string())),
    };
    Ok(SealPair {
        egress: Path::new(ETC_DIR).join("egress"),
        private: PathBuf::from(PRIVATE_DIR),
        root: 0,
        publisher: FileOwner { uid: 0, gid },
        resolver,
    })
}

/// Removal resolves no owner and publishes nothing, so it needs no group.
pub(crate) fn removal_pair(etc: &Path, root: u32) -> SealPair<'static> {
    SealPair {
        egress: etc.join("egress"),
        private: etc.join("private"),
        root,
        publisher: FileOwner {
            uid: root,
            gid: root,
        },
        resolver: &artifact_write::SelfOwnerResolver,
    }
}

pub(crate) struct SystemdCustody {
    pub verbose: bool,
}

impl Custody for SystemdCustody {
    async fn store(&self, der: &[u8], path: &Path, cred_name: &str) -> Result<(), EnrollError> {
        super::seal_linux(der, path, cred_name, self.verbose).await?;
        artifact_write::apply_ownership_and_mode(
            &Artifact {
                path: path.to_path_buf(),
                owner: artifact_table::Owner::RootRoot,
                mode: 0o400,
                content: ContentKind::SealedAgentSealKey,
            },
            &artifact_write::RealOwnerResolver {
                operator_uid: 0,
                operator_gid: 0,
            },
        )
    }
}

/// Generates a pair when either half is missing or `rotate` is set; otherwise keeps both.
pub(crate) async fn place(
    pair: &SealPair<'_>,
    custody: &impl Custody,
    agent: &AgentId,
    rotate: bool,
) -> Result<SealKeyAction, EnrollError> {
    let action = seal_key_action(pair.custody_present(agent), pair.pub_present(agent), rotate);
    if action == SealKeyAction::Keep {
        return Ok(action);
    }
    let key = maknae_seal::SealPrivateKey::generate()?;
    let der = key.to_pkcs8_der()?;
    for step in GENERATE_STEPS {
        match step {
            GenerateStep::RetractPub => pair.retract_pub(agent)?,
            GenerateStep::StoreCustody => {
                custody
                    .store(
                        der.expose(),
                        &pair.custody_path(agent),
                        &super::agent_unit::seal_key_cred_name(agent),
                    )
                    .await?
            }
            GenerateStep::PublishPub => pair.publish_pub(agent, &key.public_key().to_pem())?,
        }
    }
    Ok(action)
}

pub(crate) fn remove(pair: &SealPair<'_>, agent: &AgentId) -> Result<(), EnrollError> {
    pair.retract_pub(agent)?;
    pair.remove_custody(agent)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::disallowed_methods)]
    use super::super::agent::tests::{scratch_anchor, Scratch};
    use super::*;
    use std::cell::RefCell;
    use std::os::unix::fs::{MetadataExt, PermissionsExt};

    struct Mine;
    impl OwnerResolver for Mine {
        fn resolve(
            &self,
            _owner: artifact_table::Owner,
        ) -> Result<(Option<nix::unistd::Uid>, Option<nix::unistd::Gid>), EnrollError> {
            Ok((None, None))
        }
    }

    #[derive(Default)]
    struct FileCustody {
        stored: RefCell<Vec<(PathBuf, String)>>,
    }

    impl Custody for FileCustody {
        async fn store(&self, der: &[u8], path: &Path, name: &str) -> Result<(), EnrollError> {
            std::fs::write(path, der).unwrap();
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)).unwrap();
            self.stored
                .borrow_mut()
                .push((path.to_path_buf(), name.to_string()));
            Ok(())
        }
    }

    struct Host {
        _dirs: [Scratch; 2],
        egress: PathBuf,
        private: PathBuf,
    }

    fn host(tag: &str) -> Host {
        static FIPS: std::sync::Once = std::sync::Once::new();
        FIPS.call_once(|| maknae_crypto::init().unwrap());
        let (e, _) = scratch_anchor(&format!("seal-{tag}-egress"));
        let (p, _) = scratch_anchor(&format!("seal-{tag}-private"));
        std::fs::set_permissions(&*e, std::fs::Permissions::from_mode(0o750)).unwrap();
        std::fs::set_permissions(&*p, std::fs::Permissions::from_mode(0o750)).unwrap();
        Host {
            egress: e.to_path_buf(),
            private: p.to_path_buf(),
            _dirs: [e, p],
        }
    }

    fn pair(h: &Host) -> SealPair<'static> {
        SealPair {
            egress: h.egress.clone(),
            private: h.private.clone(),
            root: nix::unistd::geteuid().as_raw(),
            publisher: FileOwner {
                uid: nix::unistd::geteuid().as_raw(),
                gid: nix::unistd::getegid().as_raw(),
            },
            resolver: &Mine,
        }
    }

    fn hobi() -> AgentId {
        AgentId::parse("hobi").unwrap()
    }

    fn halves(p: &SealPair<'_>) -> (Vec<u8>, String) {
        (
            std::fs::read(p.custody_path(&hobi())).unwrap(),
            std::fs::read_to_string(p.pub_path(&hobi())).unwrap(),
        )
    }

    fn matched(der: &[u8], pem: &str) -> bool {
        maknae_seal::SealPrivateKey::from_pkcs8_der(der)
            .unwrap()
            .public_key()
            .to_pem()
            == pem
    }

    #[tokio::test]
    async fn the_agent_seal_pair_is_generated_when_missing_and_kept_when_present() {
        let h = host("keep");
        let p = pair(&h);
        let custody = FileCustody::default();
        assert_eq!(
            place(&p, &custody, &hobi(), false).await.unwrap(),
            SealKeyAction::Generate
        );
        let (der, pem) = halves(&p);
        assert!(matched(&der, &pem));
        assert_eq!(
            *custody.stored.borrow(),
            [(p.custody_path(&hobi()), "agent-hobi-seal-key".to_string())]
        );
        assert_eq!(
            p.custody_path(&hobi()),
            h.private.join("agent-hobi-seal-key.cred")
        );

        assert_eq!(
            place(&p, &custody, &hobi(), false).await.unwrap(),
            SealKeyAction::Keep
        );
        assert_eq!(halves(&p), (der.clone(), pem.clone()));
        assert_eq!(custody.stored.borrow().len(), 1);

        for lost in [p.pub_path(&hobi()), p.custody_path(&hobi())] {
            std::fs::remove_file(&lost).unwrap();
            assert_eq!(
                place(&p, &custody, &hobi(), false).await.unwrap(),
                SealKeyAction::Generate,
                "{}",
                lost.display()
            );
            let (d, k) = halves(&p);
            assert!(matched(&d, &k));
            assert_ne!(k, pem);
        }
    }

    #[tokio::test]
    async fn rotate_seal_key_replaces_both_halves() {
        let h = host("rotate");
        let p = pair(&h);
        let custody = FileCustody::default();
        place(&p, &custody, &hobi(), false).await.unwrap();
        let (der, pem) = halves(&p);
        assert_eq!(
            place(&p, &custody, &hobi(), true).await.unwrap(),
            SealKeyAction::Generate
        );
        let (der2, pem2) = halves(&p);
        assert_ne!(der2, der);
        assert_ne!(pem2, pem);
        assert!(matched(&der2, &pem2));
    }

    #[tokio::test]
    async fn the_published_agent_key_has_the_owner_mode_and_path_recipient_key_requires() {
        let rows = artifact_table::agent_seal_rows(&hobi());
        let at = |kind| rows.iter().find(|a| a.content == kind).unwrap().clone();
        assert_eq!(
            at(ContentKind::AgentSealPub),
            Artifact {
                path: PathBuf::from("/etc/maknae/egress/agents/hobi.seal.pub"),
                owner: artifact_table::Owner::RootMaknaeEgressGroup,
                mode: 0o640,
                content: ContentKind::AgentSealPub,
            }
        );
        assert_eq!(
            at(ContentKind::Dir),
            Artifact {
                path: PathBuf::from("/etc/maknae/egress/agents"),
                owner: artifact_table::Owner::RootMaknaeEgressGroup,
                mode: 0o750,
                content: ContentKind::Dir,
            }
        );
        assert_eq!(
            at(ContentKind::SealedAgentSealKey),
            Artifact {
                path: PathBuf::from("/etc/maknae/private/agent-hobi-seal-key.cred"),
                owner: artifact_table::Owner::RootRoot,
                mode: 0o400,
                content: ContentKind::SealedAgentSealKey,
            }
        );
        assert_eq!(rows.len(), 3);

        let h = host("recipient");
        let p = pair(&h);
        place(&p, &FileCustody::default(), &hobi(), false)
            .await
            .unwrap();
        let file = std::fs::symlink_metadata(p.pub_path(&hobi())).unwrap();
        let dir = std::fs::symlink_metadata(h.egress.join("agents")).unwrap();
        assert_eq!(file.mode() & 0o7777, 0o640);
        assert_eq!(dir.mode() & 0o7777, 0o750);
        assert_eq!(file.nlink(), 1);
        assert!(file.file_type().is_file());
        assert_eq!(
            p.pub_path(&hobi()),
            h.egress.join("agents").join("hobi.seal.pub")
        );
        assert_eq!(file.len(), maknae_seal::SEAL_PUB_PEM_LEN as u64);
    }

    #[tokio::test]
    async fn remove_agent_removes_both_seal_artifacts() {
        let h = host("remove");
        let p = pair(&h);
        place(&p, &FileCustody::default(), &hobi(), false)
            .await
            .unwrap();
        let other = AgentId::parse("jin").unwrap();
        place(&p, &FileCustody::default(), &other, false)
            .await
            .unwrap();
        let etc = Path::new("/etc/maknae");
        assert_eq!(
            (removal_pair(etc, 0).egress, removal_pair(etc, 0).private),
            (etc.join("egress"), etc.join("private"))
        );
        let removal = SealPair {
            egress: h.egress.clone(),
            private: h.private.clone(),
            ..removal_pair(etc, p.root)
        };
        remove(&removal, &hobi()).unwrap();
        assert!(!p.pub_path(&hobi()).exists());
        assert!(!p.custody_path(&hobi()).exists());
        assert!(p.pub_path(&other).exists());
        assert!(p.custody_path(&other).exists());
        remove(&p, &hobi()).unwrap();
    }
}
