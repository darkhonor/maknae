use crate::session::SessionChannel;
use maknae_config::{
    agent_key_path, key_field_is_acceptable, key_subpath_is_acceptable, kv_fragment_is_acceptable,
    user_key_path, AgentId, AuthorizedProvider, EgressBounds, ProviderSet,
};
use maknae_proto::{ProviderChoice, SealedKey};

pub struct ProviderAuthority {
    pub set: ProviderSet,
    pub user_prefix: String,
    pub agent_prefix: Option<String>,
}

/// Whose key a provider choice names: the session's authenticated subject, never the request.
#[derive(Clone, Copy, Debug)]
pub enum KeyOwner<'s> {
    User(Option<&'s str>),
    Agent(&'s AgentId),
}

impl<'s> KeyOwner<'s> {
    pub fn of(channel: &'s SessionChannel, peer_user: Option<&'s str>) -> Self {
        match channel {
            SessionChannel::Client => KeyOwner::User(peer_user),
            SessionChannel::Agent { agent, .. } => KeyOwner::Agent(agent),
        }
    }
}

pub fn provider_authority(
    set: &ProviderSet,
    bounds: Option<&EgressBounds>,
) -> Option<ProviderAuthority> {
    match bounds {
        Some(b) if !set.is_empty() => Some(ProviderAuthority {
            set: set.clone(),
            user_prefix: b.user_prefix.clone(),
            agent_prefix: b.agent_prefix.clone(),
        }),
        _ => None,
    }
}

pub struct AdmittedChoice<'a> {
    pub provider: &'a AuthorizedProvider,
    pub model: &'a str,
    pub key_vault_path: String,
    pub key_field: &'a str,
    pub sealed_key: &'a SealedKey,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ChoiceRefusal {
    NoChoice,
    NoProviders,
    UnknownProvider,
    ModelNotListed,
    UnsafeUsername,
    NoAgentPrefix,
    MalformedSubpath,
    MalformedField,
}

impl ChoiceRefusal {
    pub fn reason(&self) -> &'static str {
        match self {
            ChoiceRefusal::NoChoice => "session.prompt carries no provider choice",
            ChoiceRefusal::NoProviders => {
                "no model access: no providers are authorized on this host"
            }
            ChoiceRefusal::UnknownProvider => "provider not in the authorized set",
            ChoiceRefusal::ModelNotListed => "model not on the authorized provider's list",
            ChoiceRefusal::UnsafeUsername => {
                "local account has no name usable as a key path segment"
            }
            ChoiceRefusal::NoAgentPrefix => {
                "no model access: no agent key prefix is configured on this host"
            }
            ChoiceRefusal::MalformedSubpath => "key subpath malformed",
            ChoiceRefusal::MalformedField => "key field malformed",
        }
    }
}

pub fn admit_choice<'a>(
    set: &'a ProviderSet,
    choice: Option<&'a ProviderChoice>,
    owner: KeyOwner<'_>,
    user_prefix: &str,
    agent_prefix: Option<&str>,
) -> Result<AdmittedChoice<'a>, ChoiceRefusal> {
    let choice = choice.ok_or(ChoiceRefusal::NoChoice)?;
    if set.is_empty() {
        return Err(ChoiceRefusal::NoProviders);
    }
    let provider = set
        .get(&choice.provider)
        .ok_or(ChoiceRefusal::UnknownProvider)?;
    if !provider.models.contains(&choice.model) {
        return Err(ChoiceRefusal::ModelNotListed);
    }
    enum Tree<'o> {
        User(&'o str),
        Agent(&'o AgentId, &'o str),
    }
    let tree = match owner {
        KeyOwner::User(username) => Tree::User(
            username
                .filter(|u| {
                    maknae_vault::userpass_username_is_acceptable(u).is_ok()
                        && kv_fragment_is_acceptable(u).is_ok()
                })
                .ok_or(ChoiceRefusal::UnsafeUsername)?,
        ),
        KeyOwner::Agent(agent) => {
            Tree::Agent(agent, agent_prefix.ok_or(ChoiceRefusal::NoAgentPrefix)?)
        }
    };
    if key_subpath_is_acceptable(&choice.key_subpath).is_err() {
        return Err(ChoiceRefusal::MalformedSubpath);
    }
    if !key_field_is_acceptable(&choice.key_field) {
        return Err(ChoiceRefusal::MalformedField);
    }
    let key_vault_path = match tree {
        Tree::User(username) => user_key_path(user_prefix, username, &choice.key_subpath),
        Tree::Agent(agent, prefix) => agent_key_path(prefix, agent, &choice.key_subpath),
    }
    .map_err(|_| ChoiceRefusal::MalformedSubpath)?;
    Ok(AdmittedChoice {
        provider,
        model: &choice.model,
        key_vault_path,
        key_field: &choice.key_field,
        sealed_key: &choice.sealed_key,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use maknae_config::Value;

    const PREFIX: &str = "maknae/users";

    fn entry(name: &str, models: &[&str]) -> Value {
        Value::Map(vec![
            ("name".into(), Value::Str(name.into())),
            (
                "endpoint".into(),
                Value::Str("https://api.example.test/v1".into()),
            ),
            (
                "models".into(),
                Value::Seq(models.iter().map(|m| Value::Str((*m).into())).collect()),
            ),
        ])
    }

    fn set() -> ProviderSet {
        maknae_config::providers_from_section(Some(&Value::Seq(vec![
            entry("openai", &["gpt-5.6-luna", "gpt-5.6"]),
            entry("local", &["llama-4"]),
        ])))
        .unwrap()
    }

    fn choice(provider: &str, model: &str, subpath: &str, field: &str) -> ProviderChoice {
        ProviderChoice {
            provider: provider.into(),
            model: model.into(),
            key_subpath: subpath.into(),
            key_field: field.into(),
            sealed_key: SealedKey::new(vec![0x5a; maknae_proto::SEALED_KEY_MIN_BYTES]).unwrap(),
        }
    }

    fn good() -> ProviderChoice {
        choice("openai", "gpt-5.6", "openai/personal", "api_key")
    }

    fn refusal(c: &ProviderChoice, user: Option<&str>) -> Option<ChoiceRefusal> {
        admit_choice(&set(), Some(c), KeyOwner::User(user), PREFIX, None).err()
    }

    #[test]
    fn an_admitted_choice_carries_the_sets_entry_the_choices_model_and_field_and_the_peers_path() {
        let s = set();
        let c = good();
        let a = admit_choice(&s, Some(&c), KeyOwner::User(Some("alice")), PREFIX, None).unwrap();
        assert!(std::ptr::eq(a.provider, s.get("openai").unwrap()));
        assert_eq!(a.model, "gpt-5.6");
        assert_eq!(a.key_field, "api_key");
        assert_eq!(a.key_vault_path, "maknae/users/alice/openai/personal");
        assert!(std::ptr::eq(a.sealed_key, &c.sealed_key));
    }

    #[test]
    fn the_refusals_come_in_the_ruled_order() {
        let s = set();
        let empty = ProviderSet::empty();
        let worst = choice("anthropic", "gpt-9", "../x", "a b");
        assert_eq!(
            admit_choice(&empty, None, KeyOwner::User(None), PREFIX, None).err(),
            Some(ChoiceRefusal::NoChoice)
        );
        assert_eq!(
            admit_choice(&s, None, KeyOwner::User(Some("alice")), PREFIX, None).err(),
            Some(ChoiceRefusal::NoChoice)
        );
        assert_eq!(
            admit_choice(&empty, Some(&worst), KeyOwner::User(None), PREFIX, None).err(),
            Some(ChoiceRefusal::NoProviders)
        );
        assert_eq!(
            admit_choice(
                &empty,
                Some(&good()),
                KeyOwner::User(Some("alice")),
                PREFIX,
                None
            )
            .err(),
            Some(ChoiceRefusal::NoProviders)
        );
        assert_eq!(refusal(&worst, None), Some(ChoiceRefusal::UnknownProvider));
        assert_eq!(
            refusal(&choice("openai", "gpt-9", "../x", "a b"), None),
            Some(ChoiceRefusal::ModelNotListed)
        );
        assert_eq!(
            refusal(&choice("openai", "gpt-5.6", "../x", "a b"), None),
            Some(ChoiceRefusal::UnsafeUsername)
        );
        assert_eq!(
            refusal(&choice("openai", "gpt-5.6", "../x", "a b"), Some("alice")),
            Some(ChoiceRefusal::MalformedSubpath)
        );
        assert_eq!(
            refusal(
                &choice("openai", "gpt-5.6", "openai/personal", "a b"),
                Some("alice")
            ),
            Some(ChoiceRefusal::MalformedField)
        );
    }

    #[test]
    fn a_model_must_be_on_the_chosen_providers_own_list_exactly() {
        for bad in ["llama-4", "GPT-5.6", "gpt-5.6 ", ""] {
            assert_eq!(
                refusal(
                    &choice("openai", bad, "openai/personal", "api_key"),
                    Some("alice")
                ),
                Some(ChoiceRefusal::ModelNotListed),
                "{bad:?}"
            );
        }
        assert!(admit_choice(
            &set(),
            Some(&choice("local", "llama-4", "local/k", "api_key")),
            KeyOwner::User(Some("alice")),
            PREFIX,
            None
        )
        .is_ok());
    }

    #[test]
    fn the_username_must_be_one_safe_lower_case_segment() {
        let c = good();
        let at = "u".repeat(crate::MAX_SUBJECT_USER_BYTES);
        let over = "u".repeat(crate::MAX_SUBJECT_USER_BYTES + 1);
        for bad in [
            None,
            Some(""),
            Some("Alice"),
            Some("al/ice"),
            Some(".."),
            Some("a b"),
            Some("data"),
            Some(over.as_str()),
        ] {
            assert_eq!(
                refusal(&c, bad),
                Some(ChoiceRefusal::UnsafeUsername),
                "{bad:?}"
            );
        }
        for ok in ["alice", "svc_maknae", "a.b-c", at.as_str()] {
            assert!(
                admit_choice(&set(), Some(&c), KeyOwner::User(Some(ok)), PREFIX, None).is_ok(),
                "{ok}"
            );
        }
    }

    #[test]
    fn a_subpath_that_climbs_out_or_names_the_kv_artifact_is_refused() {
        let long = "a".repeat(maknae_config::MAX_KEY_SUBPATH_BYTES + 1);
        for bad in [
            "../bob/openai",
            "openai/../../bob",
            "/openai",
            "openai/",
            "openai//x",
            "data/openai",
            "openai/data",
            "",
            "a b",
            long.as_str(),
        ] {
            assert_eq!(
                refusal(&choice("openai", "gpt-5.6", bad, "api_key"), Some("alice")),
                Some(ChoiceRefusal::MalformedSubpath),
                "{bad:?}"
            );
        }
    }

    #[test]
    fn a_field_with_whitespace_or_over_its_bound_is_refused() {
        let over = "f".repeat(maknae_config::MAX_KEY_FIELD_BYTES + 1);
        for bad in ["api key", "", over.as_str()] {
            assert_eq!(
                refusal(
                    &choice("openai", "gpt-5.6", "openai/personal", bad),
                    Some("alice")
                ),
                Some(ChoiceRefusal::MalformedField),
                "{bad:?}"
            );
        }
        let at = "f".repeat(maknae_config::MAX_KEY_FIELD_BYTES);
        assert!(admit_choice(
            &set(),
            Some(&choice("openai", "gpt-5.6", "openai/personal", &at)),
            KeyOwner::User(Some("alice")),
            PREFIX,
            None
        )
        .is_ok());
    }

    #[test]
    fn a_path_that_cannot_be_composed_is_refused_as_a_malformed_subpath() {
        assert_eq!(
            admit_choice(
                &set(),
                Some(&good()),
                KeyOwner::User(Some("alice")),
                "",
                None
            )
            .err(),
            Some(ChoiceRefusal::MalformedSubpath)
        );
    }

    #[test]
    fn each_refusal_reason_is_fixed_text_naming_no_request_value() {
        assert_eq!(
            [
                ChoiceRefusal::NoChoice.reason(),
                ChoiceRefusal::NoProviders.reason(),
                ChoiceRefusal::UnknownProvider.reason(),
                ChoiceRefusal::ModelNotListed.reason(),
                ChoiceRefusal::UnsafeUsername.reason(),
                ChoiceRefusal::NoAgentPrefix.reason(),
                ChoiceRefusal::MalformedSubpath.reason(),
                ChoiceRefusal::MalformedField.reason(),
            ],
            [
                "session.prompt carries no provider choice",
                "no model access: no providers are authorized on this host",
                "provider not in the authorized set",
                "model not on the authorized provider's list",
                "local account has no name usable as a key path segment",
                "no model access: no agent key prefix is configured on this host",
                "key subpath malformed",
                "key field malformed",
            ]
        );
    }

    const AGENTS: &str = "maknae/agents";

    fn hobi() -> maknae_config::AgentId {
        maknae_config::AgentId::parse("hobi").unwrap()
    }

    fn agent_channel(id: &str) -> SessionChannel {
        SessionChannel::Agent {
            agent: maknae_config::AgentId::parse(id).unwrap(),
            leaf_expires: std::time::Instant::now() + std::time::Duration::from_secs(60),
        }
    }

    fn as_agent<'a>(
        s: &'a ProviderSet,
        c: &'a ProviderChoice,
        agent: &maknae_config::AgentId,
        agent_prefix: Option<&str>,
    ) -> Result<AdmittedChoice<'a>, ChoiceRefusal> {
        admit_choice(s, Some(c), KeyOwner::Agent(agent), PREFIX, agent_prefix)
    }

    #[test]
    fn an_agent_choice_resolves_under_the_agent_prefix_by_its_own_id() {
        let s = set();
        let c = choice("openai", "gpt-5.6", "openai/hobi", "api_key");
        let a = as_agent(&s, &c, &hobi(), Some(AGENTS)).unwrap();
        assert_eq!(a.key_vault_path, "maknae/agents/hobi/openai/hobi");
        let suga = maknae_config::AgentId::parse("suga").unwrap();
        assert_eq!(
            as_agent(&s, &c, &suga, Some(AGENTS))
                .unwrap()
                .key_vault_path,
            "maknae/agents/suga/openai/hobi"
        );
    }

    #[test]
    fn the_key_owner_is_the_sessions_channel_never_the_peers_account_name() {
        let ch = agent_channel("hobi");
        match KeyOwner::of(&ch, Some("alice")) {
            KeyOwner::Agent(a) => assert_eq!(a.as_str(), "hobi"),
            KeyOwner::User(u) => panic!("an agent session owned as user {u:?}"),
        }
        match KeyOwner::of(&SessionChannel::Client, Some("alice")) {
            KeyOwner::User(u) => assert_eq!(u, Some("alice")),
            KeyOwner::Agent(a) => panic!("a client session owned as agent {a:?}"),
        }
        let s = set();
        let c = good();
        let a = admit_choice(
            &s,
            Some(&c),
            KeyOwner::of(&ch, Some("alice")),
            PREFIX,
            Some(AGENTS),
        )
        .unwrap();
        assert_eq!(a.key_vault_path, "maknae/agents/hobi/openai/personal");
    }

    #[test]
    fn an_agent_choice_with_no_agent_prefix_is_refused() {
        let s = set();
        let c = good();
        assert_eq!(
            as_agent(&s, &c, &hobi(), None).err(),
            Some(ChoiceRefusal::NoAgentPrefix)
        );
        assert_eq!(
            as_agent(&s, &c, &hobi(), Some("")).err(),
            Some(ChoiceRefusal::MalformedSubpath)
        );
        assert_eq!(
            as_agent(
                &s,
                &choice("openai", "gpt-9", "openai/personal", "api_key"),
                &hobi(),
                None
            )
            .err(),
            Some(ChoiceRefusal::ModelNotListed)
        );
        assert_eq!(
            as_agent(
                &s,
                &choice("openai", "gpt-5.6", "../x", "a b"),
                &hobi(),
                None
            )
            .err(),
            Some(ChoiceRefusal::NoAgentPrefix)
        );
    }

    #[test]
    fn an_agent_subpath_cannot_climb_out_of_its_tree() {
        let s = set();
        for bad in [
            "../suga/openai",
            "openai/../../suga",
            "../../users/alice/openai",
            "/openai",
            "/maknae/users/alice/openai",
            "openai//x",
            "openai/",
            "",
            "data/openai",
        ] {
            assert_eq!(
                as_agent(
                    &s,
                    &choice("openai", "gpt-5.6", bad, "api_key"),
                    &hobi(),
                    Some(AGENTS)
                )
                .err(),
                Some(ChoiceRefusal::MalformedSubpath),
                "{bad:?}"
            );
        }
    }

    #[test]
    fn a_user_choice_never_resolves_under_the_agent_prefix() {
        let s = set();
        for sub in ["openai/personal", "hobi/openai"] {
            let c = choice("openai", "gpt-5.6", sub, "api_key");
            let a = admit_choice(
                &s,
                Some(&c),
                KeyOwner::User(Some("alice")),
                PREFIX,
                Some(AGENTS),
            )
            .unwrap();
            assert_eq!(a.key_vault_path, format!("maknae/users/alice/{sub}"));
            assert!(!maknae_config::path_is_within_prefix(
                &a.key_vault_path,
                AGENTS
            ));
        }
        let c = choice("openai", "gpt-5.6", "openai/hobi", "api_key");
        let a = as_agent(&s, &c, &hobi(), Some(AGENTS)).unwrap();
        assert!(!maknae_config::path_is_within_prefix(
            &a.key_vault_path,
            PREFIX
        ));
    }

    #[test]
    fn an_authority_exists_only_for_a_non_empty_set_with_bounds() {
        let b = EgressBounds {
            call_timeout_ms: maknae_config::DEFAULT_CALL_TIMEOUT_MS,
            kv_mount: "maknae-kv".into(),
            user_prefix: PREFIX.into(),
            agent_prefix: Some(AGENTS.into()),
            vault_addr: "https://vault.example:8200".into(),
        };
        assert!(provider_authority(&ProviderSet::empty(), Some(&b)).is_none());
        assert!(provider_authority(&set(), None).is_none());
        let a = provider_authority(&set(), Some(&b)).unwrap();
        assert_eq!(a.user_prefix, PREFIX);
        assert_eq!(a.agent_prefix.as_deref(), Some(AGENTS));
        assert_eq!(a.set.len(), 2);
        assert!(a.set.get("local").is_some());
    }
}
