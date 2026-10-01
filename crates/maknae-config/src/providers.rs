use crate::{ConfigError, Value};

pub const PROVIDERS_SECTION: &str = "providers";

pub(crate) const PROVIDER_KEYS: [&str; 5] = [
    "name",
    "endpoint",
    "models",
    "reasoning_effort",
    "output_tokens_field",
];

pub const OUTPUT_TOKENS_FIELDS: [&str; 2] = ["max_completion_tokens", "max_tokens"];
pub const MAX_KEY_FIELD_BYTES: usize = 64;
pub const MAX_PROVIDER_NAME_BYTES: usize = 32;
pub const MAX_REASONING_EFFORT_BYTES: usize = 16;
pub const MAX_PROVIDERS: usize = 32;
pub const MAX_MODELS_PER_PROVIDER: usize = 32;
pub const MAX_MODEL_BYTES: usize = 128;
pub const MAX_KEY_SUBPATH_BYTES: usize = 256;

const PLAINTEXT_KEY_KEYS: [&str; 7] = [
    "key",
    "api_key",
    "apikey",
    "token",
    "secret",
    "secret_key",
    "bearer",
];

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AuthorizedProvider {
    pub name: String,
    pub endpoint: String,
    pub models: Vec<String>,
    pub reasoning_effort: Option<String>,
    pub output_tokens_field: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProviderSet(Vec<AuthorizedProvider>);

impl ProviderSet {
    pub fn empty() -> Self {
        Self(Vec::new())
    }

    pub fn get(&self, name: &str) -> Option<&AuthorizedProvider> {
        self.0.iter().find(|p| p.name == name)
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    pub fn len(&self) -> usize {
        self.0.len()
    }

    pub fn iter(&self) -> std::slice::Iter<'_, AuthorizedProvider> {
        self.0.iter()
    }
}

fn safe_token_byte(b: u8) -> bool {
    b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-')
}

pub fn provider_name_is_acceptable(s: &str) -> bool {
    !s.is_empty() && s.len() <= MAX_PROVIDER_NAME_BYTES && s.bytes().all(safe_token_byte)
}

pub fn model_is_acceptable(s: &str) -> bool {
    !s.is_empty() && s.len() <= MAX_MODEL_BYTES && s.bytes().all(|b| b.is_ascii_graphic())
}

pub fn key_field_is_acceptable(s: &str) -> bool {
    !s.is_empty() && s.len() <= MAX_KEY_FIELD_BYTES && s.bytes().all(|b| b.is_ascii_graphic())
}

pub fn key_subpath_is_acceptable(s: &str) -> Result<(), String> {
    if s.is_empty() {
        return Err("is empty".into());
    }
    if s.len() > MAX_KEY_SUBPATH_BYTES {
        return Err(format!("exceeds {MAX_KEY_SUBPATH_BYTES} bytes"));
    }
    let segs: Vec<&str> = s.split('/').collect();
    let last = segs.len() - 1;
    for (i, seg) in segs.iter().enumerate() {
        if seg.is_empty() {
            return Err(if i == 0 {
                "must not start with '/'".into()
            } else if i == last {
                "must not end with '/'".into()
            } else {
                "has an empty interior path segment".into()
            });
        }
        if !seg.bytes().all(safe_token_byte) {
            return Err("has a character outside [A-Za-z0-9._-]".into());
        }
        if *seg == "." || *seg == ".." {
            return Err("has a '.' or '..' segment".into());
        }
        if *seg == "data" {
            return Err("has a 'data' segment".into());
        }
    }
    Ok(())
}

pub fn user_key_path(user_prefix: &str, username: &str, subpath: &str) -> Result<String, String> {
    if user_prefix.len() > crate::MAX_USER_PREFIX_BYTES {
        return Err(format!(
            "the user prefix exceeds {} bytes",
            crate::MAX_USER_PREFIX_BYTES
        ));
    }
    crate::kv_fragment_is_acceptable(user_prefix)
        .map_err(|why| format!("the user prefix {why}"))?;
    if !crate::vault_path_is_safe(user_prefix) {
        return Err("the user prefix has a character outside [A-Za-z0-9._/-]".into());
    }
    if username.contains('/') {
        return Err("the username is not one path segment".into());
    }
    if username == "data" {
        return Err("the username 'data' is not a usable Vault path segment".into());
    }
    crate::kv_fragment_is_acceptable(username).map_err(|why| format!("the username {why}"))?;
    if !username.bytes().all(safe_token_byte) {
        return Err("the username has a character outside [A-Za-z0-9._-]".into());
    }
    key_subpath_is_acceptable(subpath).map_err(|why| format!("the key subpath {why}"))?;
    Ok(format!("{user_prefix}/{username}/{subpath}"))
}

pub fn reasoning_effort_is_acceptable(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= MAX_REASONING_EFFORT_BYTES
        && s.chars().all(|c| c.is_ascii_lowercase())
}

pub fn endpoint_is_acceptable(url: &str) -> bool {
    if url.chars().any(char::is_whitespace) {
        return false;
    }
    let (secure, rest) = if let Some(r) = url.strip_prefix("https://") {
        (true, r)
    } else if let Some(r) = url.strip_prefix("http://") {
        (false, r)
    } else {
        return false;
    };
    let authority = rest.split('/').next().unwrap_or("");
    if authority.contains('@') {
        return false;
    }
    let (loopback, port) = if let Some(v6) = authority.strip_prefix('[') {
        match v6.split_once(']') {
            Some((h, rest)) => {
                let Ok(addr) = h.parse::<std::net::Ipv6Addr>() else {
                    return false;
                };
                let port = match rest.strip_prefix(':') {
                    Some(p) => Some(p),
                    None if rest.is_empty() => None,
                    None => return false,
                };
                (addr.is_loopback(), port)
            }
            None => return false,
        }
    } else {
        let (h, port) = match authority.split_once(':') {
            Some((h, p)) => (h, Some(p)),
            None => (authority, None),
        };
        let ok = !h.is_empty()
            && h.chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '-')
            && !h.starts_with(['-', '.'])
            && !h.ends_with(['-', '.'])
            && !h.contains("..");
        if !ok {
            return false;
        }
        let loopback = if h.bytes().all(|b| b.is_ascii_digit() || b == b'.') {
            match h.parse::<std::net::Ipv4Addr>() {
                Ok(addr) => addr.is_loopback(),
                Err(_) => return false,
            }
        } else {
            h == "localhost"
        };
        (loopback, port)
    };
    if let Some(p) = port {
        let digits = !p.is_empty() && p.bytes().all(|b| b.is_ascii_digit());
        if !digits || p.starts_with('0') || p.parse::<u16>().is_err() {
            return false;
        }
    }
    secure || loopback
}

pub fn refuse_plaintext_keys(v: &Value) -> Result<(), ConfigError> {
    match v {
        Value::Map(m) => match m
            .iter()
            .find(|(k, _)| PLAINTEXT_KEY_KEYS.contains(&k.to_ascii_lowercase().as_str()))
        {
            Some((k, _)) => Err(ConfigError::ProviderPlaintextKey { field: k.clone() }),
            None => Ok(()),
        },
        Value::Seq(items) => items.iter().try_for_each(refuse_plaintext_keys),
        _ => Ok(()),
    }
}

fn err(reason: impl Into<String>) -> ConfigError {
    ConfigError::InvalidProvider(reason.into())
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

pub fn providers_from_section(v: Option<&Value>) -> Result<ProviderSet, ConfigError> {
    let Some(section) = v else {
        return Ok(ProviderSet::empty());
    };
    refuse_plaintext_keys(section)?;
    let Value::Seq(items) = section else {
        return Err(err("providers must be a sequence of provider entries"));
    };
    if items.len() > MAX_PROVIDERS {
        return Err(err(format!(
            "providers may list at most {MAX_PROVIDERS} entries"
        )));
    }
    let mut set: Vec<AuthorizedProvider> = Vec::with_capacity(items.len());
    for (i, item) in items.iter().enumerate() {
        let provider = provider_entry(i, item)?;
        if set.iter().any(|p| p.name == provider.name) {
            return Err(err(format!(
                "providers[{i}].name '{}' is listed more than once",
                provider.name
            )));
        }
        set.push(provider);
    }
    Ok(ProviderSet(set))
}

fn provider_entry(i: usize, item: &Value) -> Result<AuthorizedProvider, ConfigError> {
    let at = format!("providers[{i}]");
    let Value::Map(m) = item else {
        return Err(err(format!("{at} must be a map")));
    };
    crate::reject_unknown_keys(PROVIDERS_SECTION, m, &PROVIDER_KEYS)?;
    let name = required_str(m, &at, "name")?;
    if !provider_name_is_acceptable(name) {
        return Err(err(format!(
            "{at}.name must be 1 to {MAX_PROVIDER_NAME_BYTES} bytes of ASCII letters, digits, '-', '_' and '.' (it is written into every egress audit record)"
        )));
    }
    let endpoint = required_str(m, &at, "endpoint")?;
    if !endpoint_is_acceptable(endpoint) {
        return Err(err(format!(
            "{at}.endpoint must be an https:// URL (http:// is permitted to loopback only)"
        )));
    }
    let models = models_of(m, &at)?;
    let reasoning_effort = match get(m, "reasoning_effort") {
        None => None,
        Some(Value::Str(s)) if reasoning_effort_is_acceptable(s) => Some(s.clone()),
        Some(_) => {
            return Err(err(format!(
                "{at}.reasoning_effort must be 1 to {MAX_REASONING_EFFORT_BYTES} lowercase ASCII letters"
            )))
        }
    };
    let output_tokens_field = match get(m, "output_tokens_field") {
        None => None,
        Some(Value::Str(s)) if OUTPUT_TOKENS_FIELDS.contains(&s.as_str()) => Some(s.clone()),
        Some(_) => {
            return Err(err(format!(
                "{at}.output_tokens_field must be max_completion_tokens or max_tokens"
            )))
        }
    };
    Ok(AuthorizedProvider {
        name: name.to_string(),
        endpoint: endpoint.to_string(),
        models,
        reasoning_effort,
        output_tokens_field,
    })
}

fn models_of(m: &[(String, Value)], at: &str) -> Result<Vec<String>, ConfigError> {
    let shape = || {
        err(format!(
            "{at}.models must be a list of 1 to {MAX_MODELS_PER_PROVIDER} model identifiers"
        ))
    };
    let Some(Value::Seq(items)) = get(m, "models") else {
        return Err(shape());
    };
    if items.is_empty() || items.len() > MAX_MODELS_PER_PROVIDER {
        return Err(shape());
    }
    let mut models: Vec<String> = Vec::with_capacity(items.len());
    for item in items {
        let Value::Str(model) = item else {
            return Err(err(format!("{at}.models entries must be strings")));
        };
        if !model_is_acceptable(model) {
            return Err(err(format!(
                "{at}.models entries must be 1 to {MAX_MODEL_BYTES} printable ASCII characters with no whitespace"
            )));
        }
        if models.contains(model) {
            return Err(err(format!("{at}.models lists '{model}' more than once")));
        }
        models.push(model.clone());
    }
    Ok(models)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::load_str;

    const ONE: &str =
        "- name: openai\n  endpoint: https://api.openai.com/v1\n  models: [gpt-5.6-luna, gpt-5.6]\n";

    fn parse(yaml: &str) -> Result<ProviderSet, ConfigError> {
        let v = load_str(yaml).expect("test yaml parses");
        providers_from_section(Some(&v))
    }

    fn refusal(yaml: &str) -> String {
        match parse(yaml) {
            Err(ConfigError::InvalidProvider(m)) => m,
            other => panic!("expected InvalidProvider, got {other:?}"),
        }
    }

    #[test]
    fn an_absent_section_and_an_empty_list_are_both_the_empty_set() {
        let none = providers_from_section(None).unwrap();
        assert!(none.is_empty());
        assert_eq!(none.len(), 0);
        assert_eq!(none, ProviderSet::empty());
        assert!(parse("[]\n").unwrap().is_empty());
    }

    #[test]
    fn a_valid_entry_parses_every_field() {
        let set = parse(&format!(
            "{ONE}  reasoning_effort: none\n  output_tokens_field: max_completion_tokens\n"
        ))
        .unwrap();
        assert_eq!(set.len(), 1);
        assert!(!set.is_empty());
        assert_eq!(
            set.get("openai"),
            Some(&AuthorizedProvider {
                name: "openai".into(),
                endpoint: "https://api.openai.com/v1".into(),
                models: vec!["gpt-5.6-luna".into(), "gpt-5.6".into()],
                reasoning_effort: Some("none".into()),
                output_tokens_field: Some("max_completion_tokens".into()),
            })
        );
        assert_eq!(set.get("openai2"), None);
        let names: Vec<&str> = set.iter().map(|p| p.name.as_str()).collect();
        assert_eq!(names, ["openai"]);
    }

    #[test]
    fn several_entries_keep_their_order_and_each_name_is_listed_once() {
        let two = format!(
            "{ONE}- name: local\n  endpoint: http://127.0.0.1:8080/v1\n  models: [llama]\n"
        );
        let set = parse(&two).unwrap();
        let names: Vec<&str> = set.iter().map(|p| p.name.as_str()).collect();
        assert_eq!(names, ["openai", "local"]);
        assert_eq!(set.get("local").unwrap().models, ["llama"]);
        let m = refusal(&format!("{ONE}{ONE}"));
        assert!(
            m.contains("providers[1].name") && m.contains("more than once"),
            "{m}"
        );
    }

    #[test]
    fn the_set_is_bounded_at_max_providers() {
        let entry =
            |i: usize| format!("- name: p{i}\n  endpoint: https://api.example/v1\n  models: [m]\n");
        let at: String = (0..MAX_PROVIDERS).map(entry).collect();
        assert_eq!(parse(&at).unwrap().len(), MAX_PROVIDERS);
        let over: String = (0..=MAX_PROVIDERS).map(entry).collect();
        let m = refusal(&over);
        assert!(m.contains(&format!("at most {MAX_PROVIDERS}")), "{m}");
    }

    #[test]
    fn the_section_is_a_list_of_maps() {
        assert!(refusal("openai\n").contains("sequence"));
        assert!(refusal("name: openai\n").contains("sequence"));
        assert!(refusal("- openai\n").contains("providers[0] must be a map"));
    }

    #[test]
    fn models_are_a_bounded_deduplicated_list_of_printable_identifiers() {
        let with = |models: &str| {
            format!("- name: openai\n  endpoint: https://api.openai.com/v1\n  models: {models}\n")
        };
        for bad in ["[]", "gpt-5.6", "[1]", "['gpt 5']", "[gpt-5.6, gpt-5.6]"] {
            let m = refusal(&with(bad));
            assert!(m.contains("providers[0].models"), "{bad}: {m}");
        }
        assert!(refusal(&with("[gpt-5.6, gpt-5.6]")).contains("more than once"));
        assert!(
            refusal("- name: openai\n  endpoint: https://api.openai.com/v1\n")
                .contains("providers[0].models")
        );
        let at: Vec<String> = (0..MAX_MODELS_PER_PROVIDER)
            .map(|i| format!("m{i}"))
            .collect();
        let set = parse(&with(&format!("[{}]", at.join(", ")))).unwrap();
        assert_eq!(
            set.get("openai").unwrap().models.len(),
            MAX_MODELS_PER_PROVIDER
        );
        let over: Vec<String> = (0..=MAX_MODELS_PER_PROVIDER)
            .map(|i| format!("m{i}"))
            .collect();
        assert!(refusal(&with(&format!("[{}]", over.join(", ")))).contains("providers[0].models"));
    }

    #[test]
    fn a_model_is_printable_ascii_without_whitespace_up_to_its_bound() {
        assert!(model_is_acceptable("gpt-5.6-luna"));
        assert!(model_is_acceptable("org/model:tag@v1"));
        assert!(model_is_acceptable(&"m".repeat(MAX_MODEL_BYTES)));
        for bad in [
            "",
            "gpt 5",
            "gpt\t5",
            "modèle",
            &"m".repeat(MAX_MODEL_BYTES + 1),
        ] {
            assert!(!model_is_acceptable(bad), "{bad:?}");
        }
    }

    #[test]
    fn a_provider_name_is_one_bounded_token_of_a_safe_alphabet() {
        for ok in [
            "open-ai",
            "open_ai",
            "gpt.4",
            "A1",
            &"n".repeat(MAX_PROVIDER_NAME_BYTES),
        ] {
            assert!(provider_name_is_acceptable(ok), "{ok:?}");
        }
        for bad in [
            "",
            "open ai",
            "open/ai",
            "ope;nai",
            "provider:x",
            "ü",
            &"n".repeat(MAX_PROVIDER_NAME_BYTES + 1),
        ] {
            assert!(!provider_name_is_acceptable(bad), "{bad:?}");
        }
        assert!(
            refusal(&ONE.replace("name: openai", "name: 'open ai'")).contains("providers[0].name")
        );
        assert!(
            refusal("- endpoint: https://x.example/v1\n  models: [m]\n").contains("missing 'name'")
        );
        assert!(
            refusal("- name: 3\n  endpoint: https://x.example/v1\n  models: [m]\n")
                .contains("providers[0].name must be a string")
        );
    }

    #[test]
    fn endpoints_are_https_or_loopback_http_and_nothing_else() {
        for ok in [
            "https://api.openai.com/v1",
            "https://llm.internal:8443/v1",
            "http://127.0.0.1:8080/v1",
            "http://localhost/v1",
            "http://[::1]:9/v1",
            "https://api.openai.com:8443/v1",
            "https://10.0.0.5/v1",
            "http://[::1]/v1",
            "http://[0:0:0:0:0:0:0:1]:8080/v1",
            "https://api.openai.com:65535/v1",
            "http://127.0.0.2/v1",
        ] {
            assert!(endpoint_is_acceptable(ok), "{ok}");
        }
        for bad in [
            "http://api.openai.com/v1",
            "http://10.0.0.5/v1",
            "http://localhost.evil.com/v1",
            "api.openai.com",
            "ftp://x",
            "https://",
            "https:///v1",
            "https://api.openai.com/v 1",
            "http://localhost:pw@remote.example/v1",
            "http://127.0.0.1@remote.example/v1",
            "https://user:pw@api.openai.com/v1",
            "https://@api.openai.com/v1",
            "HTTPS://api.openai.com/v1",
            "http://[::1/v1",
            "https://?query",
            "https://[]",
            "https://[]:443/v1",
            "http://localhost:garbage/v1",
            "http://localhost:/v1",
            "http://localhost:0/v1",
            "http://localhost:123456/v1",
            "https://-bad.example/v1",
            "https://bad.example./v1",
            "https://api..example/v1",
            "https://exa mple/v1",
            "https://[::1]x/v1",
            "http://[::1]:/v1",
            "https://[zz::1]/v1",
            "https://[1]/v1",
            "http://[::2]/v1",
            "https://256.256.256.256/v1",
            "https://1.2.3/v1",
            "https://1.2.3.4.5/v1",
            "http://127.1/v1",
            "http://127.0.0.01/v1",
            "https://api.openai.com:65536/v1",
            "http://localhost:00000/v1",
            "http://localhost:08080/v1",
            "http://localhost:+80/v1",
        ] {
            assert!(!endpoint_is_acceptable(bad), "{bad}");
        }
        let m = refusal(&ONE.replace("https://api.openai.com/v1", "http://api.openai.com/v1"));
        assert!(m.contains("providers[0].endpoint"), "{m}");
        assert!(refusal("- name: p\n  models: [m]\n").contains("missing 'endpoint'"));
    }

    #[test]
    fn reasoning_effort_and_output_tokens_field_keep_their_shapes() {
        let p = parse(ONE).unwrap();
        assert_eq!(p.get("openai").unwrap().reasoning_effort, None);
        assert_eq!(p.get("openai").unwrap().output_tokens_field, None);
        assert!(reasoning_effort_is_acceptable(
            &"e".repeat(MAX_REASONING_EFFORT_BYTES)
        ));
        for bad in [
            "",
            "None",
            "low medium",
            "x-high",
            &"e".repeat(MAX_REASONING_EFFORT_BYTES + 1),
        ] {
            assert!(!reasoning_effort_is_acceptable(bad), "{bad:?}");
        }
        for bad in ["None", "7"] {
            let m = refusal(&format!("{ONE}  reasoning_effort: {bad}\n"));
            assert!(m.contains("providers[0].reasoning_effort"), "{bad}: {m}");
        }
        for v in OUTPUT_TOKENS_FIELDS {
            let set = parse(&format!("{ONE}  output_tokens_field: {v}\n")).unwrap();
            assert_eq!(
                set.get("openai").unwrap().output_tokens_field.as_deref(),
                Some(v)
            );
        }
        for bad in ["maxTokens", "max_output_tokens", "3"] {
            let m = refusal(&format!("{ONE}  output_tokens_field: {bad}\n"));
            assert!(m.contains("providers[0].output_tokens_field"), "{bad}: {m}");
        }
    }

    #[test]
    fn a_pasted_key_anywhere_in_the_list_is_refused_by_name_before_any_other_defect() {
        for spelling in [
            "key",
            "api_key",
            "apikey",
            "token",
            "secret",
            "secret_key",
            "bearer",
            "API_KEY",
            "Token",
        ] {
            let y = format!("{ONE}- name: 'bad name'\n  {spelling}: sk-live-1234\n  bogus: 1\n");
            match parse(&y) {
                Err(ConfigError::ProviderPlaintextKey { field }) => assert_eq!(field, spelling),
                other => panic!("{spelling}: expected ProviderPlaintextKey, got {other:?}"),
            }
        }
        match parse("api_key: sk-live-1234\n") {
            Err(ConfigError::ProviderPlaintextKey { field }) => assert_eq!(field, "api_key"),
            other => panic!("a map-shaped section with a pasted key: {other:?}"),
        }
    }

    #[test]
    fn refuse_plaintext_keys_looks_inside_a_list_and_ignores_scalars() {
        let v = load_str("- name: p\n- TOKEN: x\n").unwrap();
        assert!(matches!(
            refuse_plaintext_keys(&v),
            Err(ConfigError::ProviderPlaintextKey { field }) if field == "TOKEN"
        ));
        assert!(refuse_plaintext_keys(&load_str(ONE).unwrap()).is_ok());
        assert!(refuse_plaintext_keys(&Value::Str("sk-live".into())).is_ok());
        assert!(matches!(
            refuse_plaintext_keys(&load_str("api_key: x\n").unwrap()),
            Err(ConfigError::ProviderPlaintextKey { field }) if field == "api_key"
        ));
    }

    #[test]
    fn the_pre_switch_per_provider_keys_are_refused_by_name() {
        for key in ["key_vault_path", "key_field", "model", "region"] {
            match parse(&format!("{ONE}  {key}: x\n")) {
                Err(ConfigError::UnknownKey { section, key: got }) => {
                    assert_eq!(section, PROVIDERS_SECTION);
                    assert_eq!(got, key);
                }
                other => panic!("{key}: expected UnknownKey, got {other:?}"),
            }
        }
    }

    #[test]
    fn a_key_subpath_is_relative_segments_of_a_safe_alphabet() {
        let at = "s".repeat(MAX_KEY_SUBPATH_BYTES);
        for ok in ["openai", "openai/personal", "a.b/c_d/e-f", at.as_str()] {
            assert_eq!(key_subpath_is_acceptable(ok), Ok(()), "{ok:?}");
        }
        let over = "s".repeat(MAX_KEY_SUBPATH_BYTES + 1);
        for (bad, want) in [
            ("", "is empty"),
            (over.as_str(), "exceeds 256 bytes"),
            ("/openai", "must not start with '/'"),
            ("openai/", "must not end with '/'"),
            ("a//b", "has an empty interior path segment"),
            ("../bob/x", "has a '.' or '..' segment"),
            ("a/./b", "has a '.' or '..' segment"),
            ("data/x", "has a 'data' segment"),
            ("x/data", "has a 'data' segment"),
            ("a b", "has a character outside [A-Za-z0-9._-]"),
            ("a%2e", "has a character outside [A-Za-z0-9._-]"),
            ("ü", "has a character outside [A-Za-z0-9._-]"),
        ] {
            assert_eq!(
                key_subpath_is_acceptable(bad),
                Err(want.to_string()),
                "{bad:?}"
            );
        }
    }

    #[test]
    fn a_key_field_is_bounded_and_whitespace_free() {
        assert!(key_field_is_acceptable("api_key"));
        assert!(key_field_is_acceptable("api-key"));
        assert!(key_field_is_acceptable(&"f".repeat(MAX_KEY_FIELD_BYTES)));
        for bad in [
            "",
            "api key",
            "api\tkey",
            "\u{1b}[31m",
            "api\0key",
            "clé",
            &"f".repeat(MAX_KEY_FIELD_BYTES + 1),
        ] {
            assert!(!key_field_is_acceptable(bad), "{bad:?}");
        }
    }

    #[test]
    fn user_key_path_composes_prefix_username_and_subpath_or_says_which_part_is_wrong() {
        assert_eq!(
            user_key_path("maknae/users", "alice", "openai/personal"),
            Ok("maknae/users/alice/openai/personal".to_string())
        );
        for (prefix, user, sub, want) in [
            ("", "alice", "x", "the user prefix is empty"),
            (
                "/maknae",
                "alice",
                "x",
                "the user prefix must not start with '/'",
            ),
            (
                "maknae/data",
                "alice",
                "x",
                "the user prefix contains a 'data' segment",
            ),
            ("maknae/users", "", "x", "the username is empty"),
            (
                "maknae/users",
                "a/b",
                "x",
                "the username is not one path segment",
            ),
            (
                "maknae/users",
                "..",
                "x",
                "the username has a '.' or '..' segment",
            ),
            (
                "maknae/users",
                "data",
                "x",
                "the username 'data' is not a usable Vault path segment",
            ),
            ("maknae/users", "alice", "", "the key subpath is empty"),
            (
                "maknae/users",
                "alice",
                "../bob/x",
                "the key subpath has a '.' or '..' segment",
            ),
        ] {
            let e = user_key_path(prefix, user, sub).unwrap_err();
            assert!(e.starts_with(want), "{prefix:?} {user:?} {sub:?}: {e}");
        }
        for (prefix, user, want) in [
            (
                "maknae/users",
                "%2e%2e",
                "the username has a character outside [A-Za-z0-9._-]",
            ),
            (
                "maknae/users",
                "a#b",
                "the username has a character outside [A-Za-z0-9._-]",
            ),
            (
                "maknae/users",
                "a@b",
                "the username has a character outside [A-Za-z0-9._-]",
            ),
            (
                "maknae/a#b",
                "alice",
                "the user prefix has a character outside [A-Za-z0-9._/-]",
            ),
        ] {
            assert_eq!(
                user_key_path(prefix, user, "x"),
                Err(want.to_string()),
                "{prefix:?} {user:?}"
            );
        }
        let e = user_key_path("maknae/users", "data", "x").unwrap_err();
        assert!(!e.contains("#308"), "{e}");
        let at = "p".repeat(crate::MAX_USER_PREFIX_BYTES);
        assert!(user_key_path(&at, "alice", "x").is_ok());
        let over = "p".repeat(crate::MAX_USER_PREFIX_BYTES + 1);
        assert_eq!(
            user_key_path(&over, "alice", "x"),
            Err(format!(
                "the user prefix exceeds {} bytes",
                crate::MAX_USER_PREFIX_BYTES
            ))
        );
    }
}
