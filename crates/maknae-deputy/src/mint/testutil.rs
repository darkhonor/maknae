use super::recipient::{AGENTS_DIR, SEAL_PUB_SUFFIX};
use maknae_config::AgentId;
use maknae_seal::SealPrivateKey;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

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
