use maknae_config::{
    key_field_is_acceptable, key_subpath_is_acceptable, kv_fragment_is_acceptable, user_key_path,
    AuthorizedProvider, EgressBounds, ProviderSet,
};
use maknae_proto::{ProviderChoice, SealedKey};

pub struct ProviderAuthority {
    pub set: ProviderSet,
    pub user_prefix: String,
}

pub fn provider_authority(
    set: &ProviderSet,
    bounds: Option<&EgressBounds>,
) -> Option<ProviderAuthority> {
    match bounds {
        Some(b) if !set.is_empty() => Some(ProviderAuthority {
            set: set.clone(),
            user_prefix: b.user_prefix.clone(),
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
            ChoiceRefusal::MalformedSubpath => "key subpath malformed",
            ChoiceRefusal::MalformedField => "key field malformed",
        }
    }
}

pub fn admit_choice<'a>(
    set: &'a ProviderSet,
    choice: Option<&'a ProviderChoice>,
    username: Option<&str>,
    user_prefix: &str,
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
    let username = username
        .filter(|u| {
            maknae_vault::userpass_username_is_acceptable(u).is_ok()
                && kv_fragment_is_acceptable(u).is_ok()
        })
        .ok_or(ChoiceRefusal::UnsafeUsername)?;
    if key_subpath_is_acceptable(&choice.key_subpath).is_err() {
        return Err(ChoiceRefusal::MalformedSubpath);
    }
    if !key_field_is_acceptable(&choice.key_field) {
        return Err(ChoiceRefusal::MalformedField);
    }
    let key_vault_path = user_key_path(user_prefix, username, &choice.key_subpath)
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
        admit_choice(&set(), Some(c), user, PREFIX).err()
    }

    #[test]
    fn an_admitted_choice_carries_the_sets_entry_the_choices_model_and_field_and_the_peers_path() {
        let s = set();
        let c = good();
        let a = admit_choice(&s, Some(&c), Some("alice"), PREFIX).unwrap();
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
            admit_choice(&empty, None, None, PREFIX).err(),
            Some(ChoiceRefusal::NoChoice)
        );
        assert_eq!(
            admit_choice(&s, None, Some("alice"), PREFIX).err(),
            Some(ChoiceRefusal::NoChoice)
        );
        assert_eq!(
            admit_choice(&empty, Some(&worst), None, PREFIX).err(),
            Some(ChoiceRefusal::NoProviders)
        );
        assert_eq!(
            admit_choice(&empty, Some(&good()), Some("alice"), PREFIX).err(),
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
            Some("alice"),
            PREFIX
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
                admit_choice(&set(), Some(&c), Some(ok), PREFIX).is_ok(),
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
            Some("alice"),
            PREFIX
        )
        .is_ok());
    }

    #[test]
    fn a_path_that_cannot_be_composed_is_refused_as_a_malformed_subpath() {
        assert_eq!(
            admit_choice(&set(), Some(&good()), Some("alice"), "").err(),
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
                ChoiceRefusal::MalformedSubpath.reason(),
                ChoiceRefusal::MalformedField.reason(),
            ],
            [
                "session.prompt carries no provider choice",
                "no model access: no providers are authorized on this host",
                "provider not in the authorized set",
                "model not on the authorized provider's list",
                "local account has no name usable as a key path segment",
                "key subpath malformed",
                "key field malformed",
            ]
        );
    }

    #[test]
    fn an_authority_exists_only_for_a_non_empty_set_with_bounds() {
        let b = EgressBounds {
            kv_mount: "maknae-kv".into(),
            user_prefix: PREFIX.into(),
            vault_addr: "https://vault.example:8200".into(),
        };
        assert!(provider_authority(&ProviderSet::empty(), Some(&b)).is_none());
        assert!(provider_authority(&set(), None).is_none());
        let a = provider_authority(&set(), Some(&b)).unwrap();
        assert_eq!(a.user_prefix, PREFIX);
        assert_eq!(a.set.len(), 2);
        assert!(a.set.get("local").is_some());
    }
}
