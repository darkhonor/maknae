//! The `provider` section (#243, Cooky; ADR-0023 decision 3) — the ONE model
//! provider this deployment's runtime loop may reach, registered as data.
//!
//! What is here: an endpoint, a model name, a display name, and the Vault
//! path where the API key lives. What is NOT here, and is refused when
//! present: the key itself, under any spelling. Credentials are delivered via
//! Vault, never plaintext (ADR-0005 decision 8; the `maknae-egress` process
//! reads the path under its own policy — #240). Absent section → `None`: a
//! deployment with no provider boots and its loop has nothing to prompt.
//! Present → strictly validated (exactly the four keys); present-but-invalid →
//! [`ConfigError::InvalidProvider`]; a plaintext-key key →
//! [`ConfigError::ProviderPlaintextKey`], named separately because it is the
//! misconfiguration an operator is most likely to make and the one whose
//! consequence is worst.
//!
//! **Where the block may live, and who may write it,** is the loader's
//! concern, not this parser's: `load_config_rooted` requires the SOURCE that
//! contributed this section — `maknae.yaml` or a `config.d/` member — to be
//! root-owned and not group/other-writable, so the subject the loop runs as
//! cannot register a destination (ADR-0023 decision 3: custody of the
//! registration, covering every input path).

use crate::{ConfigError, Value};

/// The registered section name.
pub const PROVIDER_SECTION: &str = "provider";

/// The four keys the section accepts, and no others.
const KEYS: [&str; 4] = ["name", "endpoint", "model", "key_vault_path"];

/// Spellings under which an operator might paste the key itself. Any of these
/// present — with any value — refuses the section by name.
const PLAINTEXT_KEY_KEYS: [&str; 7] = [
    "key",
    "api_key",
    "apikey",
    "token",
    "secret",
    "secret_key",
    "bearer",
];

/// One registered provider. `Clone` so boot can hand it to whoever asks.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProviderConfig {
    /// Operator-chosen label; appears in the trail's destination field.
    pub name: String,
    /// The OpenAI-compatible base URL. `https://` — or `http://` to loopback
    /// only, for the hermetic acceptance stub (#242).
    pub endpoint: String,
    /// The model identifier sent on every request.
    pub model: String,
    /// The Vault KV path holding the API key. Never disclosed (`omit`).
    pub key_vault_path: String,
}

fn err(reason: impl Into<String>) -> ConfigError {
    ConfigError::InvalidProvider(reason.into())
}

fn get<'a>(m: &'a [(String, Value)], key: &str) -> Option<&'a Value> {
    m.iter().find(|(k, _)| k == key).map(|(_, v)| v)
}

fn required_str<'a>(m: &'a [(String, Value)], key: &str) -> Result<&'a str, ConfigError> {
    match get(m, key) {
        None => Err(err(format!("provider: missing '{key}'"))),
        Some(Value::Str(s)) if !s.trim().is_empty() => Ok(s.trim()),
        Some(_) => Err(err(format!("provider.{key} must be a non-empty string"))),
    }
}

/// `https://…`, or `http://` to a loopback host only. Anything else — a bare
/// host, another scheme, whitespace, an `http://` to a routable address — is
/// refused: the loop's content leaves the trust plane over this URL.
fn endpoint_is_acceptable(url: &str) -> bool {
    if url.chars().any(char::is_whitespace) {
        return false;
    }
    if let Some(rest) = url.strip_prefix("https://") {
        return !rest.is_empty() && !rest.starts_with('/');
    }
    if let Some(rest) = url.strip_prefix("http://") {
        let host = if rest.starts_with('[') {
            rest.split(']')
                .next()
                .map(|h| format!("{h}]"))
                .unwrap_or_default()
        } else {
            rest.split(['/', ':']).next().unwrap_or("").to_string()
        };
        return host == "127.0.0.1" || host == "localhost" || host == "[::1]";
    }
    false
}

/// Read the `provider` section. Absent → `Ok(None)`; present → strictly
/// validated; a plaintext-key spelling → refused by name before anything else
/// is looked at.
pub fn provider_from_section(v: Option<&Value>) -> Result<Option<ProviderConfig>, ConfigError> {
    let section = match v {
        None => return Ok(None),
        Some(s) => s,
    };
    let m = match section {
        Value::Map(m) => m,
        _ => return Err(err("provider section must be a map")),
    };
    // The plaintext-key refusal comes FIRST: an operator who pasted a key next
    // to a typo in another field should hear about the key, not the typo.
    if let Some((k, _)) = m
        .iter()
        .find(|(k, _)| PLAINTEXT_KEY_KEYS.contains(&k.to_ascii_lowercase().as_str()))
    {
        return Err(ConfigError::ProviderPlaintextKey { field: k.clone() });
    }
    for (k, _) in m {
        if !KEYS.contains(&k.as_str()) {
            return Err(err(format!("provider: unknown key '{k}'")));
        }
    }
    let name = required_str(m, "name")?;
    if !name
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_' || c == '.')
    {
        return Err(err(
            "provider.name may contain only ASCII letters, digits, '-', '_' and '.'",
        ));
    }
    let endpoint = required_str(m, "endpoint")?;
    if !endpoint_is_acceptable(endpoint) {
        return Err(err(
            "provider.endpoint must be an https:// URL (http:// is permitted to loopback only)",
        ));
    }
    let model = required_str(m, "model")?;
    let key_vault_path = required_str(m, "key_vault_path")?;
    if key_vault_path.chars().any(char::is_whitespace) || key_vault_path.starts_with('/') {
        return Err(err(
            "provider.key_vault_path must be a relative Vault path without whitespace",
        ));
    }
    Ok(Some(ProviderConfig {
        name: name.to_string(),
        endpoint: endpoint.to_string(),
        model: model.to_string(),
        key_vault_path: key_vault_path.to_string(),
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::load_str;

    const OK: &str = "name: openai\nendpoint: https://api.openai.com/v1\nmodel: gpt-5\nkey_vault_path: maknae/provider/openai\n";

    fn parse(yaml: &str) -> Result<Option<ProviderConfig>, ConfigError> {
        let v = load_str(yaml).expect("test yaml parses");
        provider_from_section(Some(&v))
    }

    #[test]
    fn absent_is_none_and_a_valid_block_parses_every_field() {
        assert_eq!(provider_from_section(None).unwrap(), None);
        let p = parse(OK).unwrap().unwrap();
        assert_eq!(p.name, "openai");
        assert_eq!(p.endpoint, "https://api.openai.com/v1");
        assert_eq!(p.model, "gpt-5");
        assert_eq!(p.key_vault_path, "maknae/provider/openai");
    }

    #[test]
    fn values_are_trimmed_but_never_defaulted() {
        let p = parse(&OK.replace("model: gpt-5", "model: '  gpt-5  '"))
            .unwrap()
            .unwrap();
        assert_eq!(p.model, "gpt-5");
        for key in ["name", "endpoint", "model", "key_vault_path"] {
            let y: String = OK
                .lines()
                .filter(|l| !l.starts_with(&format!("{key}:")))
                .map(|l| format!("{l}\n"))
                .collect();
            match parse(&y) {
                Err(ConfigError::InvalidProvider(r)) => assert!(r.contains(key), "{key}: {r}"),
                other => panic!("missing {key} must refuse, got {other:?}"),
            }
        }
    }

    #[test]
    fn a_plaintext_key_under_any_spelling_is_refused_by_name_before_anything_else() {
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
            // Even with ANOTHER defect present (an unknown key), the plaintext
            // key is what the operator hears about.
            let y = format!("{OK}{spelling}: sk-live-1234\nbogus: 1\n");
            match parse(&y) {
                Err(ConfigError::ProviderPlaintextKey { field }) => assert_eq!(field, spelling),
                other => panic!("{spelling}: expected ProviderPlaintextKey, got {other:?}"),
            }
        }
    }

    #[test]
    fn the_key_set_is_exact() {
        match parse(&format!("{OK}region: us\n")) {
            Err(ConfigError::InvalidProvider(r)) => {
                assert!(r.contains("unknown key 'region'"), "{r}")
            }
            other => panic!("{other:?}"),
        }
        assert!(matches!(
            provider_from_section(Some(&Value::Str("openai".into()))),
            Err(ConfigError::InvalidProvider(_))
        ));
    }

    #[test]
    fn endpoints_are_https_or_loopback_http_and_nothing_else() {
        for ok in [
            "https://api.openai.com/v1",
            "https://llm.internal:8443/v1",
            "http://127.0.0.1:8080/v1",
            "http://localhost/v1",
            "http://[::1]:9/v1",
        ] {
            assert!(
                parse(&OK.replace("https://api.openai.com/v1", ok)).is_ok(),
                "{ok}"
            );
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
        ] {
            match parse(&OK.replace("https://api.openai.com/v1", bad)) {
                Err(ConfigError::InvalidProvider(r)) => {
                    assert!(r.contains("endpoint"), "{bad}: {r}")
                }
                other => panic!("{bad}: {other:?}"),
            }
        }
    }

    #[test]
    fn names_and_vault_paths_are_constrained() {
        for bad in ["open ai", "open/ai", "ope;nai", ""] {
            assert!(
                matches!(
                    parse(&OK.replace("name: openai", &format!("name: '{bad}'"))),
                    Err(ConfigError::InvalidProvider(_))
                ),
                "{bad:?}"
            );
        }
        for bad in ["/secret/x", "maknae/provider x", ""] {
            assert!(
                matches!(
                    parse(&OK.replace(
                        "key_vault_path: maknae/provider/openai",
                        &format!("key_vault_path: '{bad}'")
                    )),
                    Err(ConfigError::InvalidProvider(_))
                ),
                "{bad:?}"
            );
        }
    }
}
