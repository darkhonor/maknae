//! The recipient agent's public seal key, read from a root-owned file beside
//! egress's own configuration and never from the frame.

use maknae_config::AgentId;
use maknae_io::{AnchorRequired, DescendantRequired, StrategyPref, TargetRequired};
use maknae_proto::MintRefusal;
use maknae_seal::{SealPublicKey, SEAL_PUB_PEM_LEN};
use std::path::{Path, PathBuf};

pub const AGENTS_DIR: &str = "agents";
pub const SEAL_PUB_SUFFIX: &str = ".seal.pub";

pub(crate) const ROOT_UID: u32 = 0;
const NO_GROUP_OTHER_WRITE: u32 = 0o022;
const NO_GROUP_WRITE_NO_OTHER: u32 = 0o027;

pub fn recipient_key(egress_dir: &Path, agent: &AgentId) -> Result<SealPublicKey, MintRefusal> {
    recipient_key_owned_by(egress_dir, agent, ROOT_UID)
}

pub(crate) fn recipient_key_owned_by(
    egress_dir: &Path,
    agent: &AgentId,
    owner: u32,
) -> Result<SealPublicKey, MintRefusal> {
    let anchor = maknae_io::open_anchor(egress_dir, dir_required(owner), StrategyPref::Auto)
        .map_err(|_| MintRefusal::Recipient)?;
    let read = anchor
        .read(
            &key_path(agent),
            Some(agents_dir_required(owner)),
            key_required(owner),
        )
        .map_err(|_| MintRefusal::Recipient)?;
    let text = std::str::from_utf8(&read.value).map_err(|_| MintRefusal::Recipient)?;
    SealPublicKey::from_pem(text).map_err(|_| MintRefusal::Recipient)
}

fn key_path(agent: &AgentId) -> PathBuf {
    Path::new(AGENTS_DIR).join(format!("{}{SEAL_PUB_SUFFIX}", agent.as_str()))
}

fn dir_required(owner: u32) -> AnchorRequired {
    AnchorRequired {
        owner: Some(owner),
        mode_mask: Some(NO_GROUP_OTHER_WRITE),
    }
}

fn agents_dir_required(owner: u32) -> DescendantRequired {
    DescendantRequired {
        owner: Some(owner),
        mode_mask: Some(NO_GROUP_OTHER_WRITE),
    }
}

fn key_required(owner: u32) -> TargetRequired {
    TargetRequired {
        owner: Some(owner),
        mode_mask: Some(NO_GROUP_WRITE_NO_OTHER),
        nlink_exactly_one: true,
        regular_file: true,
        max_bytes: Some(SEAL_PUB_PEM_LEN as u64),
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use maknae_seal::SealPrivateKey;
    use std::os::unix::fs::PermissionsExt;

    pub(crate) fn euid() -> u32 {
        use std::os::unix::fs::MetadataExt;
        let probe = tempfile::tempdir().unwrap();
        std::fs::metadata(probe.path()).unwrap().uid()
    }

    fn fips() {
        static ONCE: std::sync::Once = std::sync::Once::new();
        ONCE.call_once(|| maknae_crypto::init().unwrap());
    }

    pub(crate) fn coder() -> AgentId {
        AgentId::parse("coder").unwrap()
    }

    pub(crate) struct EgressDir {
        pub dir: tempfile::TempDir,
    }

    impl EgressDir {
        pub(crate) fn new() -> Self {
            let dir = tempfile::tempdir().unwrap();
            std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o750)).unwrap();
            let agents = dir.path().join(AGENTS_DIR);
            std::fs::create_dir(&agents).unwrap();
            std::fs::set_permissions(&agents, std::fs::Permissions::from_mode(0o750)).unwrap();
            Self { dir }
        }

        pub(crate) fn path(&self) -> &Path {
            self.dir.path()
        }

        pub(crate) fn key_file(&self, agent: &str) -> PathBuf {
            self.dir
                .path()
                .join(AGENTS_DIR)
                .join(format!("{agent}{SEAL_PUB_SUFFIX}"))
        }

        pub(crate) fn publish(&self, agent: &str, text: &[u8], mode: u32) -> PathBuf {
            let file = self.key_file(agent);
            std::fs::write(&file, text).unwrap();
            std::fs::set_permissions(&file, std::fs::Permissions::from_mode(mode)).unwrap();
            file
        }

        pub(crate) fn publish_key(&self, agent: &str) -> SealPrivateKey {
            fips();
            let key = SealPrivateKey::generate().unwrap();
            self.publish(agent, key.public_key().to_pem().as_bytes(), 0o640);
            key
        }
    }

    fn read(d: &EgressDir, owner: u32) -> Result<SealPublicKey, MintRefusal> {
        recipient_key_owned_by(d.path(), &coder(), owner)
    }

    #[test]
    fn the_key_is_read_from_agents_beside_egress_under_the_agents_id() {
        let d = EgressDir::new();
        let key = d.publish_key("coder");
        assert_eq!(&read(&d, euid()).unwrap(), key.public_key());
        assert_eq!(
            key_path(&coder()),
            Path::new("agents").join("coder.seal.pub")
        );
        let other = EgressDir::new();
        other.publish_key("coder2");
        assert_eq!(read(&other, euid()), Err(MintRefusal::Recipient));
    }

    #[test]
    fn mode_0640_is_the_widest_admitted() {
        for (mode, ok) in [
            (0o640, true),
            (0o600, true),
            (0o440, true),
            (0o644, false),
            (0o660, false),
            (0o641, false),
            (0o642, false),
        ] {
            let d = EgressDir::new();
            let key = d.publish_key("coder");
            std::fs::set_permissions(d.key_file("coder"), std::fs::Permissions::from_mode(mode))
                .unwrap();
            let got = read(&d, euid());
            assert_eq!(got.is_ok(), ok, "{mode:o}");
            if ok {
                assert_eq!(&got.unwrap(), key.public_key());
            } else {
                assert_eq!(got, Err(MintRefusal::Recipient), "{mode:o}");
            }
        }
    }

    #[test]
    fn every_custody_failure_is_recipient() {
        let absent = EgressDir::new();
        let foreign = EgressDir::new();
        foreign.publish_key("coder");
        let linked = EgressDir::new();
        linked.publish_key("coder");
        std::fs::hard_link(
            linked.key_file("coder"),
            linked.path().join(AGENTS_DIR).join("second"),
        )
        .unwrap();
        let symlinked = EgressDir::new();
        symlinked.publish_key("real");
        std::os::unix::fs::symlink(symlinked.key_file("real"), symlinked.key_file("coder"))
            .unwrap();
        let open_agents = EgressDir::new();
        open_agents.publish_key("coder");
        std::fs::set_permissions(
            open_agents.path().join(AGENTS_DIR),
            std::fs::Permissions::from_mode(0o770),
        )
        .unwrap();
        let open_egress = EgressDir::new();
        open_egress.publish_key("coder");
        std::fs::set_permissions(open_egress.path(), std::fs::Permissions::from_mode(0o770))
            .unwrap();
        let a_directory = EgressDir::new();
        std::fs::create_dir(a_directory.key_file("coder")).unwrap();
        let oversized = EgressDir::new();
        let k = SealPrivateKey::generate().unwrap();
        oversized.publish(
            "coder",
            format!("{}\n", k.public_key().to_pem()).as_bytes(),
            0o640,
        );
        let not_a_key = EgressDir::new();
        not_a_key.publish("coder", &[b'x'; SEAL_PUB_PEM_LEN], 0o640);
        let not_utf8 = EgressDir::new();
        not_utf8.publish("coder", &[0xff; SEAL_PUB_PEM_LEN], 0o640);
        let private = EgressDir::new();
        private.publish("coder", &k.to_pkcs8_der().unwrap()[..64], 0o640);
        for (label, d, owner) in [
            ("absent", &absent, euid()),
            ("not owned by the required owner", &foreign, euid() + 1),
            ("two links", &linked, euid()),
            ("symlink", &symlinked, euid()),
            ("group-writable agents dir", &open_agents, euid()),
            ("group-writable egress dir", &open_egress, euid()),
            ("a directory", &a_directory, euid()),
            ("over the PEM length", &oversized, euid()),
            ("not a public key", &not_a_key, euid()),
            ("not UTF-8", &not_utf8, euid()),
            ("private key bytes", &private, euid()),
        ] {
            assert_eq!(read(d, owner), Err(MintRefusal::Recipient), "{label}");
        }
    }

    #[test]
    fn the_agents_dir_must_be_owned_too() {
        assert_eq!(
            dir_required(7),
            AnchorRequired {
                owner: Some(7),
                mode_mask: Some(0o022)
            }
        );
        assert_eq!(
            agents_dir_required(7),
            DescendantRequired {
                owner: Some(7),
                mode_mask: Some(0o022)
            }
        );
        assert_eq!(
            key_required(7),
            TargetRequired {
                owner: Some(7),
                mode_mask: Some(0o027),
                nlink_exactly_one: true,
                regular_file: true,
                max_bytes: Some(215),
            }
        );
    }

    #[test]
    fn the_production_reader_requires_root() {
        let d = EgressDir::new();
        d.publish_key("coder");
        assert_eq!(
            recipient_key(d.path(), &coder()).is_ok(),
            euid() == ROOT_UID
        );
        assert_eq!(ROOT_UID, 0);
    }
}
