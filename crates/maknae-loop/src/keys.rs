//! Where each turn's provider key comes from. The host decides: a person's
//! session reads their own wrapped key under their login (ADR-0028); an agent
//! reads its own under its AppRole login. The loop never knows which.
use maknae_config::{AgentId, AgentProvider};
use maknae_proto::{ProviderChoice, SealedKey};
use maknae_seal::{SealAad, SealContext, SealPublicKey};
use maknae_vault::{
    aad_parts, PlaneClient, VaultError, WrapExpectation, WrappedSecret, USER_KEY_WRAP_TTL,
};
use std::future::Future;
use std::sync::Arc;

pub trait KeySupply: Send {
    fn choice(
        &mut self,
        conversation: &str,
        now: u64,
    ) -> impl Future<Output = Result<maknae_proto::ProviderChoice, String>> + Send;
}

/// One provider key, at the Vault path its owner's tree puts it.
pub struct KeyTarget<'a> {
    pub kv_mount: &'a str,
    pub secret_path: &'a str,
    pub provider: &'a str,
    pub model: &'a str,
    pub key_subpath: &'a str,
    pub key_field: &'a str,
}

#[derive(Debug)]
pub enum ChoiceFault {
    /// The path or field cannot name a Vault key; nothing was read.
    Unusable,
    Read(VaultError),
    Seal(String),
}

/// Reads the wrapped key at `target` and seals its wrapping token to exactly this
/// request, binding the path the egress will expect (ADR-0028).
pub async fn sealed_choice<F, Fut>(
    target: &KeyTarget<'_>,
    seal_key: &SealPublicKey,
    conversation: &str,
    read: F,
) -> Result<ProviderChoice, ChoiceFault>
where
    F: FnOnce(String) -> Fut,
    Fut: Future<Output = Result<WrappedSecret, VaultError>>,
{
    let expect = WrapExpectation::new(
        target.kv_mount,
        target.secret_path,
        target.key_field,
        USER_KEY_WRAP_TTL,
    )
    .map_err(|_| ChoiceFault::Unusable)?;
    let wrapped = read(target.secret_path.to_string())
        .await
        .map_err(ChoiceFault::Read)?;
    let sealing = |e: &dyn std::fmt::Display| ChoiceFault::Seal(e.to_string());
    let parts = aad_parts(&expect, conversation, target.provider, target.model);
    let aad = SealAad::new(&SealContext {
        conversation: parts.conversation,
        provider: parts.provider,
        model: parts.model,
        expected_path: parts.expected_path,
        key_field: parts.key_field,
    })
    .map_err(|e| sealing(&e))?;
    let blob = maknae_seal::seal(seal_key, &aad, wrapped.token.expose().as_bytes())
        .map_err(|e| sealing(&e))?;
    let sealed_key = SealedKey::new(blob.into_bytes()).map_err(|e| sealing(&e))?;
    Ok(ProviderChoice {
        provider: target.provider.to_string(),
        model: target.model.to_string(),
        key_subpath: target.key_subpath.to_string(),
        key_field: target.key_field.to_string(),
        sealed_key,
    })
}

/// The agent's own key, under `<agent_prefix>/<id>/`, the path the kernel builds
/// from the agent's authenticated id.
pub struct AgentKeyContext<'a> {
    pub provider: &'a AgentProvider,
    pub kv_mount: &'a str,
    pub agent_prefix: &'a str,
    pub agent: &'a AgentId,
    pub seal_key: &'a SealPublicKey,
}

pub async fn agent_choice<F, Fut>(
    key: &AgentKeyContext<'_>,
    conversation: &str,
    read: F,
) -> Result<ProviderChoice, String>
where
    F: FnOnce(String) -> Fut,
    Fut: Future<Output = Result<WrappedSecret, VaultError>>,
{
    let p = key.provider;
    let unusable = |why: &str| {
        format!(
            "the agent's provider key path is not acceptable ({why}): check agent_prefix, \
             kv_mount and the provider key subpath and field in agent.yaml"
        )
    };
    let secret_path = maknae_config::agent_key_path(key.agent_prefix, key.agent, &p.key_subpath)
        .map_err(|why| unusable(&why))?;
    let target = KeyTarget {
        kv_mount: key.kv_mount,
        secret_path: &secret_path,
        provider: &p.provider,
        model: &p.model,
        key_subpath: &p.key_subpath,
        key_field: &p.key_field,
    };
    sealed_choice(&target, key.seal_key, conversation, read)
        .await
        .map_err(|f| match f {
            ChoiceFault::Unusable => unusable("not a Vault key"),
            ChoiceFault::Read(VaultError::VaultStatus { status: 403, .. }) => {
                "Vault refused to read the agent's provider key (HTTP 403): the key is outside \
                 the agent's Vault policy, or its login was revoked"
                    .to_string()
            }
            ChoiceFault::Read(VaultError::VaultStatus { status: 404, .. }) => {
                format!("no provider key is stored in Vault at {secret_path}")
            }
            ChoiceFault::Read(e) => format!("reading the agent's provider key failed: {e}"),
            ChoiceFault::Seal(e) => format!("sealing the agent's provider key failed: {e}"),
        })
}

/// A response-wrapped KV read made as the reader's own Vault login.
pub trait WrappedRead: Send + Sync {
    fn read_wrapped(
        &self,
        kv_mount: &str,
        secret_path: &str,
    ) -> impl Future<Output = Result<WrappedSecret, VaultError>> + Send;
}

impl WrappedRead for PlaneClient {
    fn read_wrapped(
        &self,
        kv_mount: &str,
        secret_path: &str,
    ) -> impl Future<Output = Result<WrappedSecret, VaultError>> + Send {
        self.read_wrapped_as_self(kv_mount, secret_path, USER_KEY_WRAP_TTL)
    }
}

/// The agent host's key supply: each turn reads the agent's own wrapped key as
/// the agent's plane client and seals it to exactly that request.
pub struct AgentKeys<R: WrappedRead = PlaneClient> {
    reader: Arc<R>,
    provider: AgentProvider,
    kv_mount: String,
    agent_prefix: String,
    agent: AgentId,
    seal_key: SealPublicKey,
}

impl<R: WrappedRead> AgentKeys<R> {
    pub fn new(
        reader: Arc<R>,
        provider: AgentProvider,
        kv_mount: String,
        agent_prefix: String,
        agent: AgentId,
        seal_key: SealPublicKey,
    ) -> Self {
        AgentKeys {
            reader,
            provider,
            kv_mount,
            agent_prefix,
            agent,
            seal_key,
        }
    }

    pub fn reader(&self) -> &Arc<R> {
        &self.reader
    }

    pub fn agent(&self) -> &AgentId {
        &self.agent
    }
}

impl<R: WrappedRead> KeySupply for AgentKeys<R> {
    async fn choice(&mut self, conversation: &str, _now: u64) -> Result<ProviderChoice, String> {
        let key = AgentKeyContext {
            provider: &self.provider,
            kv_mount: &self.kv_mount,
            agent_prefix: &self.agent_prefix,
            agent: &self.agent,
            seal_key: &self.seal_key,
        };
        let (reader, kv_mount) = (&self.reader, self.kv_mount.as_str());
        agent_choice(&key, conversation, |path| async move {
            reader.read_wrapped(kv_mount, &path).await
        })
        .await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const KV: &str = "maknae-kv";
    const AGENTS: &str = "maknae/agents";

    fn provider(subpath: &str) -> AgentProvider {
        AgentProvider {
            provider: "openai".into(),
            model: "gpt-5.6-luna".into(),
            key_subpath: subpath.into(),
            key_field: "api_key".into(),
            context_tokens: 128_000,
            output_tokens: None,
        }
    }

    fn wrapped(token: &str, path: &str) -> WrappedSecret {
        WrappedSecret {
            token: maknae_vault::WrappingToken::new(zeroize::Zeroizing::new(token.into())).unwrap(),
            ttl: std::time::Duration::from_secs(60),
            creation_path: path.into(),
            creation_time: "2026-11-13T00:00:00Z".into(),
        }
    }

    #[tokio::test]
    async fn agent_keys_read_only_under_the_agent_tree() {
        maknae_crypto::init().unwrap();
        let recipient = maknae_seal::SealPrivateKey::generate().unwrap();
        let hobi = AgentId::parse("hobi").unwrap();
        let p = provider("openai/main");
        let key = AgentKeyContext {
            provider: &p,
            kv_mount: KV,
            agent_prefix: AGENTS,
            agent: &hobi,
            seal_key: recipient.public_key(),
        };
        let asked = std::sync::Mutex::new(Vec::new());
        let choice = agent_choice(&key, "c-629", |path| {
            asked.lock().unwrap().push(path);
            async { Ok(wrapped("hvs.wrap-sentinel-629", "unused")) }
        })
        .await
        .unwrap();
        let path = "maknae/agents/hobi/openai/main";
        assert_eq!(*asked.lock().unwrap(), [path]);
        assert_eq!(
            maknae_config::agent_key_path(AGENTS, &hobi, "openai/main").unwrap(),
            path
        );
        assert_eq!(
            (
                choice.provider.as_str(),
                choice.model.as_str(),
                choice.key_subpath.as_str(),
                choice.key_field.as_str()
            ),
            ("openai", "gpt-5.6-luna", "openai/main", "api_key")
        );
        let expect = WrapExpectation::new(KV, path, "api_key", USER_KEY_WRAP_TTL).unwrap();
        let parts = aad_parts(&expect, "c-629", "openai", "gpt-5.6-luna");
        let aad = SealAad::new(&SealContext {
            conversation: parts.conversation,
            provider: parts.provider,
            model: parts.model,
            expected_path: parts.expected_path,
            key_field: parts.key_field,
        })
        .unwrap();
        assert_eq!(
            parts.expected_path,
            "maknae-kv/data/maknae/agents/hobi/openai/main"
        );
        let opened = maknae_seal::open(&recipient, &aad, choice.sealed_key.as_bytes()).unwrap();
        assert_eq!(opened.as_slice(), b"hvs.wrap-sentinel-629");

        let user_tree = WrapExpectation::new(
            KV,
            "maknae/users/hobi/openai/main",
            "api_key",
            USER_KEY_WRAP_TTL,
        )
        .unwrap();
        let p = aad_parts(&user_tree, "c-629", "openai", "gpt-5.6-luna");
        let elsewhere = SealAad::new(&SealContext {
            conversation: p.conversation,
            provider: p.provider,
            model: p.model,
            expected_path: p.expected_path,
            key_field: p.key_field,
        })
        .unwrap();
        assert!(maknae_seal::open(&recipient, &elsewhere, choice.sealed_key.as_bytes()).is_err());
    }

    #[tokio::test]
    async fn an_agent_key_path_that_could_leave_the_tree_is_never_read() {
        maknae_crypto::init().unwrap();
        let recipient = maknae_seal::SealPrivateKey::generate().unwrap();
        let hobi = AgentId::parse("hobi").unwrap();
        for (prefix, subpath) in [
            (AGENTS, "../../users/alice/openai"),
            (AGENTS, "/openai"),
            ("", "openai/main"),
            ("maknae/../users", "openai/main"),
        ] {
            let p = provider(subpath);
            let key = AgentKeyContext {
                provider: &p,
                kv_mount: KV,
                agent_prefix: prefix,
                agent: &hobi,
                seal_key: recipient.public_key(),
            };
            let got = agent_choice(&key, "c-629", |path| async move {
                panic!("read {path} for prefix {prefix:?} and subpath {subpath:?}")
            })
            .await
            .unwrap_err();
            assert!(got.contains("not acceptable"), "{got}");
        }
    }

    #[tokio::test]
    async fn a_vault_refusal_names_the_agents_key_not_a_users_login() {
        maknae_crypto::init().unwrap();
        let recipient = maknae_seal::SealPrivateKey::generate().unwrap();
        let hobi = AgentId::parse("hobi").unwrap();
        let p = provider("openai/main");
        let key = AgentKeyContext {
            provider: &p,
            kv_mount: KV,
            agent_prefix: AGENTS,
            agent: &hobi,
            seal_key: recipient.public_key(),
        };
        let status = |status: u16, hint: &'static str| VaultError::VaultStatus {
            op: "wrapped read",
            status,
            hint,
        };
        let login = "the token is expired or revoked (run `maknae login`)";
        for (failure, says) in [
            (status(403, login), "HTTP 403"),
            (
                status(404, "no secret at this path"),
                "maknae/agents/hobi/openai/main",
            ),
            (status(500, ""), "reading the agent's provider key failed"),
        ] {
            let got = agent_choice(&key, "c-629", |_| async move { Err(failure) })
                .await
                .unwrap_err();
            assert!(got.contains(says), "{got}");
            assert!(!got.contains("maknae login"), "{got}");
        }
    }

    #[tokio::test]
    async fn an_agent_key_field_that_names_no_vault_key_is_never_read() {
        maknae_crypto::init().unwrap();
        let recipient = maknae_seal::SealPrivateKey::generate().unwrap();
        let hobi = AgentId::parse("hobi").unwrap();
        let mut p = provider("openai/main");
        p.key_field = String::new();
        let key = AgentKeyContext {
            provider: &p,
            kv_mount: KV,
            agent_prefix: AGENTS,
            agent: &hobi,
            seal_key: recipient.public_key(),
        };
        let got = agent_choice(&key, "c-629", |_| async { panic!("read") })
            .await
            .unwrap_err();
        assert!(got.contains("not a Vault key"), "{got}");
        assert!(got.contains("agent.yaml"), "{got}");
    }

    #[tokio::test]
    async fn an_agent_key_that_cannot_be_sealed_says_so() {
        maknae_crypto::init().unwrap();
        let recipient = maknae_seal::SealPrivateKey::generate().unwrap();
        let hobi = AgentId::parse("hobi").unwrap();
        let p = provider("openai/main");
        let key = AgentKeyContext {
            provider: &p,
            kv_mount: KV,
            agent_prefix: AGENTS,
            agent: &hobi,
            seal_key: recipient.public_key(),
        };
        let path = format!("{KV}/data/{AGENTS}/hobi/openai/main");
        let got = agent_choice(&key, "", |_| async move { Ok(wrapped("s.629", &path)) })
            .await
            .unwrap_err();
        assert!(
            got.starts_with("sealing the agent's provider key failed"),
            "{got}"
        );
    }

    struct FakeReader {
        asked: std::sync::Mutex<Vec<(String, String)>>,
        token: &'static str,
    }

    impl WrappedRead for FakeReader {
        async fn read_wrapped(
            &self,
            kv_mount: &str,
            secret_path: &str,
        ) -> Result<WrappedSecret, VaultError> {
            self.asked
                .lock()
                .unwrap()
                .push((kv_mount.into(), secret_path.into()));
            Ok(wrapped(self.token, secret_path))
        }
    }

    #[tokio::test]
    async fn agent_keys_read_through_their_client_and_seal_each_turn() {
        maknae_crypto::init().unwrap();
        let recipient = maknae_seal::SealPrivateKey::generate().unwrap();
        let reader = Arc::new(FakeReader {
            asked: std::sync::Mutex::new(Vec::new()),
            token: "hvs.wrap-sentinel-629-keys",
        });
        let mut keys = AgentKeys::new(
            Arc::clone(&reader),
            provider("openai/main"),
            KV.into(),
            AGENTS.into(),
            AgentId::parse("hobi").unwrap(),
            recipient.public_key().clone(),
        );
        let choice = keys.choice("c-629", 0).await.unwrap();
        let again = keys.choice("c-630", 0).await.unwrap();
        assert_eq!(
            *reader.asked.lock().unwrap(),
            vec![(KV.to_string(), "maknae/agents/hobi/openai/main".to_string()); 2]
        );
        let expect = WrapExpectation::new(
            KV,
            "maknae/agents/hobi/openai/main",
            "api_key",
            USER_KEY_WRAP_TTL,
        )
        .unwrap();
        for (conversation, c) in [("c-629", &choice), ("c-630", &again)] {
            let parts = aad_parts(&expect, conversation, "openai", "gpt-5.6-luna");
            let aad = SealAad::new(&SealContext {
                conversation: parts.conversation,
                provider: parts.provider,
                model: parts.model,
                expected_path: parts.expected_path,
                key_field: parts.key_field,
            })
            .unwrap();
            let opened = maknae_seal::open(&recipient, &aad, c.sealed_key.as_bytes()).unwrap();
            assert_eq!(opened.as_slice(), b"hvs.wrap-sentinel-629-keys");
        }
        assert_eq!(keys.agent().as_str(), "hobi");
    }
}
