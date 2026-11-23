#![cfg(test)]

use maknae_config::{EgressBounds, MintingFile};
use maknae_proto::{CredentialRef, ReachRequest, ReachSide, RepoAsk, SealedKey};

pub(crate) const MINTING: &str = concat!(
    "vault:\n",
    "  approle_mount: approle-mint\n",
    "apis:\n",
    "  github.com:\n",
    "    provider: github\n",
    "    api: https://api.github.com\n",
    "  ghe.example:\n",
    "    provider: github\n",
    "    api: https://ghe.example\n",
    "  gitlab.example:\n",
    "    provider: gitlab\n",
    "    api: https://gitlab.example\n",
    "github_apps:\n",
    "  deploy:\n",
    "    app_id: 5834363\n",
    "    installation_id: 77\n",
    "    host: github.com\n",
    "    api: https://api.github.com\n",
    "    transit_mount: transit\n",
    "    transit_key: deploy-app\n",
    "  review:\n",
    "    app_id: 5834364\n",
    "    installation_id: 78\n",
    "    host: github.com\n",
    "    api: https://api.github.com\n",
    "    transit_mount: transit\n",
    "    transit_key: review-app\n",
    "  enterprise:\n",
    "    app_id: 9\n",
    "    installation_id: 79\n",
    "    host: ghe.example\n",
    "    api: https://ghe.example\n",
    "    transit_mount: transit\n",
    "    transit_key: ghe-app\n",
);

pub(crate) fn file(text: &str) -> MintingFile {
    maknae_config::minting_from_document(&maknae_config::load_str(text).unwrap()).unwrap()
}

pub(crate) fn ask(base: &str) -> RepoAsk {
    RepoAsk {
        base: base.into(),
        change: None,
        head: None,
    }
}

pub(crate) fn app_frame(server: &str, provider: &str, creds: &[(&str, &str)]) -> ReachRequest {
    ReachRequest::new(
        server.into(),
        provider.into(),
        20_000,
        ReachSide::Agent {
            agent: "coder".into(),
            credentials: creds
                .iter()
                .map(|(k, n)| CredentialRef {
                    kind: (*k).into(),
                    name: (*n).into(),
                })
                .collect(),
        },
        vec![ask("o/r")],
    )
    .unwrap()
}

pub(crate) fn tasker_frame(server: &str, provider: &str, deadline_ms: u64) -> ReachRequest {
    ReachRequest::new(
        server.into(),
        provider.into(),
        deadline_ms,
        ReachSide::Tasker {
            tasker: "alice".into(),
            expected_path: format!("maknae/users/alice/forges/{server}"),
            key_field: "token".into(),
            nonce: "0123456789abcdef0123456789abcdef".into(),
            sealed: SealedKey::new(vec![7; 200]).unwrap(),
        },
        vec![ask("o/r")],
    )
    .unwrap()
}

pub(crate) fn bounds() -> EgressBounds {
    EgressBounds {
        call_timeout_ms: maknae_config::DEFAULT_CALL_TIMEOUT_MS,
        kv_mount: "maknae-kv".into(),
        user_prefix: "maknae/users".into(),
        agent_prefix: None,
        vault_addr: "https://vault.example:8200".into(),
    }
}
