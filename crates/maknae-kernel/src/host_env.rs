//! The host environment the baseline validator reads (#490): the egress bounds file,
//! the account database, the audit trail and the sockets.

use std::path::{Path, PathBuf};

use maknae_config::{ReaderAccount, ReaderLookup};

pub(crate) struct HostEnv {
    pub(crate) config_dir: PathBuf,
}

impl ReaderLookup for HostEnv {
    fn account(&self, name: &str) -> Result<Option<ReaderAccount>, String> {
        maknae_vault::NssAccounts.account(name)
    }

    fn daemon_gid(&self) -> Result<Option<u32>, String> {
        maknae_vault::NssAccounts.daemon_gid()
    }

    fn service_uids(&self) -> Result<Vec<u32>, String> {
        maknae_vault::NssAccounts.service_uids()
    }
}

impl crate::baseline_check::Env for HostEnv {
    fn egress_bounds(&self) -> Result<maknae_config::EgressBounds, maknae_config::ConfigError> {
        maknae_config::load_egress_bounds(&self.config_dir.join(maknae_config::EGRESS_BOUNDS_FILE))
    }

    fn egress_account(&self) -> Result<Option<u32>, String> {
        crate::egress::resolve_account_uid(crate::egress::EGRESS_USER)
    }

    fn trail_prepared(&self, path: &Path) -> Result<(), String> {
        maknae_audit_append::AuditSink::open_prepared(&maknae_config::AuditConfig {
            jsonl_path: path.to_path_buf(),
            siem: None,
            au3_1: serde_json::Value::Null,
            readers: Vec::new(),
        })
        .map(drop)
        .map_err(|e| e.to_string())
    }

    fn listener_bindable(&self, path: &Path) -> Result<(), String> {
        maknae_vault::probe_bindable(path).map_err(|e| e.to_string())
    }

    fn deputy_reachable(&self, path: &Path) -> Result<(), String> {
        std::os::unix::net::UnixStream::connect(path)
            .map(drop)
            .map_err(|e| e.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::baseline_check::Env;

    #[test]
    fn the_host_answers_from_the_host() {
        let dir = tempfile::tempdir().unwrap();
        let env = HostEnv {
            config_dir: dir.path().to_path_buf(),
        };
        assert!(matches!(
            env.egress_bounds(),
            Err(maknae_config::ConfigError::NotFound { .. })
        ));
        assert_eq!(
            env.egress_account(),
            crate::egress::resolve_account_uid(crate::egress::EGRESS_USER)
        );
        assert_eq!(
            env.account("root").unwrap().map(|a| a.uid),
            Some(0),
            "readers resolve through NSS"
        );
        assert_eq!(env.daemon_gid(), maknae_vault::NssAccounts.daemon_gid());
        assert_eq!(env.service_uids(), maknae_vault::NssAccounts.service_uids());
        let trail = dir.path().join("audit.jsonl");
        assert!(env
            .trail_prepared(&trail)
            .unwrap_err()
            .contains("is missing"));
        std::fs::write(&trail, "").unwrap();
        assert!(
            env.trail_prepared(&trail).is_err(),
            "a plain file is not prepared"
        );
        let sock = dir.path().join("probe.sock");
        assert!(env.deputy_reachable(&sock).is_err());
        let _listener = std::os::unix::net::UnixListener::bind(&sock).unwrap();
        assert_eq!(env.deputy_reachable(&sock), Ok(()));
    }
}
