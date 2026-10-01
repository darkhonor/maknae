use crate::{
    key_field_is_acceptable, key_subpath_is_acceptable, model_is_acceptable,
    provider_name_is_acceptable, ConfigError, Value, MAX_KEY_FIELD_BYTES, MAX_MODEL_BYTES,
    MAX_PROVIDERS, MAX_PROVIDER_NAME_BYTES,
};

pub const USER_PROVIDERS_FILE: &str = "providers.yaml";

const ENTRY_LEVEL: &str = "providers.yaml/providers";
const KEY_LEVEL: &str = "providers.yaml/providers/key";
const ENTRY_KEYS: [&str; 7] = [
    "label",
    "provider",
    "model",
    "key",
    "context_tokens",
    "output_tokens",
    "default",
];
const KEY_KEYS: [&str; 2] = ["subpath", "field"];

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UserProviderEntry {
    pub label: String,
    pub provider: String,
    pub model: String,
    pub key_subpath: String,
    pub key_field: String,
    pub context_tokens: u64,
    pub output_tokens: Option<u64>,
    pub default: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UserProviders(Vec<UserProviderEntry>);

impl UserProviders {
    pub fn empty() -> Self {
        Self(Vec::new())
    }

    pub fn entries(&self) -> &[UserProviderEntry] {
        &self.0
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    pub fn select(&self, label: Option<&str>) -> Result<&UserProviderEntry, ConfigError> {
        if self.0.is_empty() {
            return Err(err("no model access: no providers are defined"));
        }
        match label {
            Some(l) if !provider_name_is_acceptable(l) => Err(err(format!(
                "the requested provider is not a valid label (1 to {MAX_PROVIDER_NAME_BYTES} bytes of ASCII letters, digits, '-', '_' and '.')"
            ))),
            Some(l) => self.0.iter().find(|e| e.label == l).ok_or_else(|| {
                err(format!(
                    "no entry is labelled '{l}' (labels: {})",
                    self.labels()
                ))
            }),
            None => Ok(self.0.iter().find(|e| e.default).unwrap_or(&self.0[0])),
        }
    }

    fn labels(&self) -> String {
        self.0
            .iter()
            .map(|e| e.label.as_str())
            .collect::<Vec<_>>()
            .join(", ")
    }
}

fn err(reason: impl Into<String>) -> ConfigError {
    ConfigError::UserProviders(reason.into())
}

fn get<'a>(m: &'a [(String, Value)], key: &str) -> Option<&'a Value> {
    m.iter().find(|(k, _)| k == key).map(|(_, v)| v)
}

fn required_str<'a>(m: &'a [(String, Value)], at: &str, key: &str) -> Result<&'a str, ConfigError> {
    match get(m, key) {
        None => Err(err(format!("{at}: missing '{key}'"))),
        Some(Value::Str(s)) => Ok(s),
        Some(_) => Err(err(format!("{at}.{key} must be a string"))),
    }
}

fn tokens(m: &[(String, Value)], at: &str, key: &str) -> Result<Option<u64>, ConfigError> {
    match get(m, key) {
        None => Ok(None),
        Some(Value::Int(n)) => u64::try_from(*n)
            .map(Some)
            .map_err(|_| err(format!("{at}.{key} must not be negative"))),
        Some(_) => Err(err(format!("{at}.{key} must be an integer"))),
    }
}

pub fn user_providers_from_document(v: &Value) -> Result<UserProviders, ConfigError> {
    let m = match v {
        Value::Null => return Ok(UserProviders::empty()),
        Value::Map(m) => m,
        _ => return Err(err("expected a mapping at the top level")),
    };
    crate::reject_unknown_keys(USER_PROVIDERS_FILE, m, &["providers"])?;
    let items = match get(m, "providers") {
        None => return Ok(UserProviders::empty()),
        Some(Value::Seq(items)) => items,
        Some(_) => return Err(err("'providers' must be a list of entries")),
    };
    if items.len() > MAX_PROVIDERS {
        return Err(err(format!(
            "providers may list at most {MAX_PROVIDERS} entries"
        )));
    }
    let mut entries: Vec<UserProviderEntry> = Vec::with_capacity(items.len());
    for (i, item) in items.iter().enumerate() {
        let entry = user_entry(i, item)?;
        if entries.iter().any(|e| e.label == entry.label) {
            return Err(err(format!(
                "providers[{i}].label '{}' is used more than once",
                entry.label
            )));
        }
        entries.push(entry);
    }
    let defaults: Vec<&str> = entries
        .iter()
        .filter(|e| e.default)
        .map(|e| e.label.as_str())
        .collect();
    if defaults.len() > 1 {
        return Err(err(format!(
            "more than one entry is marked default: true ({})",
            defaults.join(", ")
        )));
    }
    let undecided = entries.len() > 1 && defaults.is_empty();
    let providers = UserProviders(entries);
    if undecided {
        return Err(err(format!(
            "{} entries and none is marked default: true; mark exactly one (labels: {})",
            providers.0.len(),
            providers.labels()
        )));
    }
    Ok(providers)
}

fn user_entry(i: usize, item: &Value) -> Result<UserProviderEntry, ConfigError> {
    let at = format!("providers[{i}]");
    let Value::Map(m) = item else {
        return Err(err(format!("{at} must be a map")));
    };
    crate::reject_unknown_keys(ENTRY_LEVEL, m, &ENTRY_KEYS)?;
    let label = required_str(m, &at, "label")?;
    if !provider_name_is_acceptable(label) {
        return Err(err(format!(
            "{at}.label must be 1 to {MAX_PROVIDER_NAME_BYTES} bytes of ASCII letters, digits, '-', '_' and '.'"
        )));
    }
    let provider = required_str(m, &at, "provider")?;
    if !provider_name_is_acceptable(provider) {
        return Err(err(format!(
            "{at}.provider must name an authorized provider (1 to {MAX_PROVIDER_NAME_BYTES} bytes of ASCII letters, digits, '-', '_' and '.')"
        )));
    }
    let model = required_str(m, &at, "model")?;
    if !model_is_acceptable(model) {
        return Err(err(format!(
            "{at}.model must be 1 to {MAX_MODEL_BYTES} printable ASCII characters with no whitespace"
        )));
    }
    let (key_subpath, key_field) = key_of(m, &at)?;
    let context_tokens = tokens(m, &at, "context_tokens")?.ok_or_else(|| {
        err(format!(
            "{at}.context_tokens is required: declare the model's context window in tokens"
        ))
    })?;
    let output_tokens = tokens(m, &at, "output_tokens")?;
    let default = match get(m, "default") {
        None => false,
        Some(Value::Bool(b)) => *b,
        Some(_) => return Err(err(format!("{at}.default must be true or false"))),
    };
    Ok(UserProviderEntry {
        label: label.to_string(),
        provider: provider.to_string(),
        model: model.to_string(),
        key_subpath,
        key_field,
        context_tokens,
        output_tokens,
        default,
    })
}

fn key_of(m: &[(String, Value)], at: &str) -> Result<(String, String), ConfigError> {
    let k = match get(m, "key") {
        None => return Err(err(format!("{at}: missing 'key'"))),
        Some(Value::Map(k)) => k,
        Some(_) => {
            return Err(err(format!(
                "{at}.key must be a map of subpath and field; the API key itself is stored only in Vault, never in this file"
            )))
        }
    };
    crate::reject_unknown_keys(KEY_LEVEL, k, &KEY_KEYS)?;
    let key_at = format!("{at}.key");
    let subpath = required_str(k, &key_at, "subpath")?;
    key_subpath_is_acceptable(subpath).map_err(|why| err(format!("{key_at}.subpath {why}")))?;
    let field = required_str(k, &key_at, "field")?;
    if !key_field_is_acceptable(field) {
        return Err(err(format!(
            "{key_at}.field must be 1 to {MAX_KEY_FIELD_BYTES} bytes with no whitespace"
        )));
    }
    Ok((subpath.to_string(), field.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::load_str;

    const ENTRY: &str = "  - label: work-luna\n    provider: openai\n    model: gpt-5.6-luna\n    key:\n      subpath: openai/personal\n      field: api_key\n    context_tokens: 128000\n    output_tokens: 16000\n    default: true\n";

    fn entry(label: &str, default: bool) -> String {
        format!(
            "  - label: {label}\n    provider: openai\n    model: gpt-5.6\n    key:\n      subpath: openai/{label}\n      field: api_key\n    context_tokens: 128000\n    default: {default}\n"
        )
    }

    fn without(omit: &str) -> String {
        let lines = [
            ("label", "label: work-luna\n"),
            ("provider", "provider: openai\n"),
            ("model", "model: gpt-5.6-luna\n"),
            (
                "key",
                "key:\n      subpath: openai/personal\n      field: api_key\n",
            ),
            ("context_tokens", "context_tokens: 128000\n"),
        ];
        let mut out = String::from("providers:\n");
        let mut first = true;
        for (name, line) in lines {
            if name == omit {
                continue;
            }
            out.push_str(if first { "  - " } else { "    " });
            out.push_str(line);
            first = false;
        }
        out
    }

    fn parse(yaml: &str) -> Result<UserProviders, ConfigError> {
        user_providers_from_document(&load_str(yaml).expect("test yaml parses"))
    }

    fn refusal(yaml: &str) -> String {
        match parse(yaml) {
            Err(ConfigError::UserProviders(m)) => m,
            other => panic!("expected UserProviders, got {other:?}"),
        }
    }

    fn unknown_key(yaml: &str) -> (String, String) {
        match parse(yaml) {
            Err(ConfigError::UnknownKey { section, key }) => (section, key),
            other => panic!("expected UnknownKey, got {other:?}"),
        }
    }

    #[test]
    fn an_empty_file_or_an_empty_list_defines_no_providers() {
        assert!(user_providers_from_document(&Value::Null)
            .unwrap()
            .is_empty());
        assert!(parse("providers: []\n").unwrap().is_empty());
        assert!(parse("{}\n").unwrap().entries().is_empty());
        assert_eq!(UserProviders::empty(), parse("providers: []\n").unwrap());
        assert!(refusal("providers\n").contains("top level"));
        assert!(refusal("providers: openai\n").contains("'providers' must be a list"));
    }

    #[test]
    fn a_valid_entry_parses_every_field() {
        let p = parse(&format!("providers:\n{ENTRY}")).unwrap();
        assert!(!p.is_empty());
        assert_eq!(
            p.entries(),
            [UserProviderEntry {
                label: "work-luna".into(),
                provider: "openai".into(),
                model: "gpt-5.6-luna".into(),
                key_subpath: "openai/personal".into(),
                key_field: "api_key".into(),
                context_tokens: 128_000,
                output_tokens: Some(16_000),
                default: true,
            }]
        );
    }

    #[test]
    fn output_tokens_and_default_are_optional() {
        let y = "providers:\n  - label: a\n    provider: openai\n    model: m\n    key:\n      subpath: s\n      field: f\n    context_tokens: 4096\n";
        let p = parse(y).unwrap();
        assert_eq!(p.entries()[0].output_tokens, None);
        assert!(!p.entries()[0].default);
    }

    #[test]
    fn every_level_of_the_file_is_closed_and_a_pasted_key_is_never_echoed() {
        assert_eq!(
            unknown_key("provider:\n  context_tokens: 1\n"),
            ("providers.yaml".to_string(), "provider".to_string())
        );
        assert_eq!(
            unknown_key(&format!("providers:\n{ENTRY}    api_key: sk-live-1234\n")),
            (
                "providers.yaml/providers".to_string(),
                "api_key".to_string()
            )
        );
        assert_eq!(
            unknown_key(&format!("providers:\n{ENTRY}").replace(
                "      field: api_key\n",
                "      field: api_key\n      secret: sk-live-1234\n"
            )),
            (
                "providers.yaml/providers/key".to_string(),
                "secret".to_string()
            )
        );
        let pasted = format!("providers:\n{ENTRY}").replace(
            "    key:\n      subpath: openai/personal\n      field: api_key\n",
            "    key: sk-live-1234\n",
        );
        let m = refusal(&pasted);
        assert!(
            m.contains("providers[0].key") && m.contains("only in Vault"),
            "{m}"
        );
        assert!(!m.contains("sk-live"), "{m}");
    }

    #[test]
    fn each_field_keeps_its_shape_and_the_refusal_names_the_field() {
        let base = format!("providers:\n{ENTRY}");
        for (from, to, want) in [
            (
                "label: work-luna",
                "label: 'work luna'",
                "providers[0].label",
            ),
            (
                "provider: openai",
                "provider: 'open/ai'",
                "providers[0].provider",
            ),
            (
                "model: gpt-5.6-luna",
                "model: 'gpt 5'",
                "providers[0].model",
            ),
            (
                "subpath: openai/personal",
                "subpath: ../bob/x",
                "providers[0].key.subpath has a '.' or '..' segment",
            ),
            (
                "subpath: openai/personal",
                "subpath: data/x",
                "providers[0].key.subpath has a 'data' segment",
            ),
            (
                "field: api_key",
                "field: 'api key'",
                "providers[0].key.field",
            ),
            (
                "context_tokens: 128000",
                "context_tokens: -1",
                "providers[0].context_tokens must not be negative",
            ),
            (
                "context_tokens: 128000",
                "context_tokens: lots",
                "providers[0].context_tokens must be an integer",
            ),
            (
                "output_tokens: 16000",
                "output_tokens: -5",
                "providers[0].output_tokens must not be negative",
            ),
            (
                "default: true",
                "default: 1",
                "providers[0].default must be true or false",
            ),
        ] {
            let m = refusal(&base.replace(from, to));
            assert!(m.contains(want), "{to}: {m}");
            assert!(!m.contains("openai/personal") && !m.contains("bob"), "{m}");
        }
        for field in ["label", "provider", "model", "key"] {
            let m = refusal(&without(field));
            assert!(
                m.contains(&format!("providers[0]: missing '{field}'")),
                "{field}: {m}"
            );
        }
        assert!(
            refusal(&without("context_tokens")).contains("providers[0].context_tokens is required")
        );
        assert!(parse(&without("")).is_ok());
        let no_field = without("").replace("      field: api_key\n", "");
        assert!(refusal(&no_field).contains("providers[0].key: missing 'field'"));
        let no_subpath = without("").replace("      subpath: openai/personal\n", "");
        assert!(refusal(&no_subpath).contains("providers[0].key: missing 'subpath'"));
        assert!(refusal("providers:\n  - openai\n").contains("providers[0] must be a map"));
        assert!(refusal(&base.replace("label: work-luna", "label: 3"))
            .contains("providers[0].label must be a string"));
    }

    #[test]
    fn labels_are_unique_and_two_or_more_entries_have_exactly_one_default() {
        let m = refusal(&format!(
            "providers:\n{}{}",
            entry("a", false),
            entry("a", false)
        ));
        assert!(
            m.contains("providers[1].label 'a' is used more than once"),
            "{m}"
        );
        let m = refusal(&format!(
            "providers:\n{}{}",
            entry("a", true),
            entry("b", true)
        ));
        assert!(
            m.contains("more than one entry is marked default: true (a, b)"),
            "{m}"
        );
        let m = refusal(&format!(
            "providers:\n{}{}",
            entry("a", false),
            entry("b", false)
        ));
        assert!(
            m.contains(
                "2 entries and none is marked default: true; mark exactly one (labels: a, b)"
            ),
            "{m}"
        );
        assert!(parse(&format!(
            "providers:\n{}{}",
            entry("a", false),
            entry("b", true)
        ))
        .is_ok());
        assert!(parse(&format!("providers:\n{}", entry("solo", false))).is_ok());
    }

    #[test]
    fn the_list_is_bounded_at_max_providers() {
        let at: String = (0..MAX_PROVIDERS)
            .map(|i| entry(&format!("l{i}"), i == 0))
            .collect();
        assert_eq!(
            parse(&format!("providers:\n{at}")).unwrap().entries().len(),
            MAX_PROVIDERS
        );
        let over: String = (0..=MAX_PROVIDERS)
            .map(|i| entry(&format!("l{i}"), i == 0))
            .collect();
        assert!(
            refusal(&format!("providers:\n{over}")).contains(&format!("at most {MAX_PROVIDERS}"))
        );
    }

    #[test]
    fn selection_takes_the_named_entry_the_only_entry_or_the_one_default() {
        let none = UserProviders::empty();
        for label in [None, Some("a")] {
            match none.select(label) {
                Err(ConfigError::UserProviders(m)) => assert!(m.contains("no model access"), "{m}"),
                other => panic!("{label:?}: {other:?}"),
            }
        }
        let one = parse(&format!("providers:\n{}", entry("solo", false))).unwrap();
        assert_eq!(one.select(None).unwrap().label, "solo");
        let two = parse(&format!(
            "providers:\n{}{}",
            entry("a", false),
            entry("b", true)
        ))
        .unwrap();
        assert_eq!(two.select(None).unwrap().label, "b");
        assert_eq!(two.select(Some("a")).unwrap().label, "a");
        assert_eq!(two.select(Some("b")).unwrap().label, "b");
        match two.select(Some("c")) {
            Err(ConfigError::UserProviders(m)) => {
                assert!(
                    m.contains("no entry is labelled 'c'") && m.contains("(labels: a, b)"),
                    "{m}"
                )
            }
            other => panic!("{other:?}"),
        }
        match two.select(Some("bad label; rm -rf")) {
            Err(ConfigError::UserProviders(m)) => {
                assert!(
                    m.contains("not a valid label") && !m.contains("rm -rf"),
                    "{m}"
                )
            }
            other => panic!("{other:?}"),
        }
    }
}
