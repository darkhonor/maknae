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
/// host, another scheme (case-sensitively: `HTTPS://` is not a scheme this
/// accepts), whitespace, **userinfo** (`user:pw@host` — a credential in a
/// disclosed field, and the trick that made `localhost:pw@remote` read as
/// loopback; codex review 2026-09-07), an `http://` to a routable address — is
/// refused: the loop's content leaves the trust plane over this URL.
fn endpoint_is_acceptable(url: &str) -> bool {
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
    // The AUTHORITY is everything up to the first '/'; it must not carry
    // userinfo, and it must name a host.
    let authority = rest.split('/').next().unwrap_or("");
    if authority.contains('@') {
        return false;
    }
    // host[:port]; a bracketed host must PARSE as an IPv6 address (`[1]` is
    // hex but is not an address -- codex review round 3), or a DNS-label/IPv4
    // host of [A-Za-z0-9.-] that neither starts nor ends with '-' or '.'; a
    // port, when present, is decimal digits with no leading zero that parse
    // to 1..=65535 (`65536` and `00000` are not ports). `https://?query`,
    // `https://[]` and `localhost:garbage` are not destinations (round 2).
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
            && !h.ends_with(['-', '.']);
        if !ok {
            return false;
        }
        (h == "127.0.0.1" || h == "localhost", port)
    };
    if let Some(p) = port {
        let digits = !p.is_empty() && p.bytes().all(|b| b.is_ascii_digit());
        if !digits || p.starts_with('0') || p.parse::<u16>().is_err() {
            return false;
        }
    }
    secure || loopback
}

/// Refuse a provider VALUE that carries a key under a plaintext-key spelling —
/// callable on every contribution to the section, not only the winner: a base
/// block a `config.d/` member shadows still had the key in it (codex review
/// 2026-09-07). A non-map value refuses nothing here; the parser handles it.
pub fn refuse_plaintext_keys(v: &Value) -> Result<(), ConfigError> {
    if let Value::Map(m) = v {
        if let Some((k, _)) = m
            .iter()
            .find(|(k, _)| PLAINTEXT_KEY_KEYS.contains(&k.to_ascii_lowercase().as_str()))
        {
            return Err(ConfigError::ProviderPlaintextKey { field: k.clone() });
        }
    }
    Ok(())
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
    refuse_plaintext_keys(section)?;
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
    fn refuse_plaintext_keys_sees_any_contribution_and_ignores_non_maps() {
        let v = load_str("name: p\nTOKEN: x\n").unwrap();
        assert!(matches!(
            refuse_plaintext_keys(&v),
            Err(ConfigError::ProviderPlaintextKey { field }) if field == "TOKEN"
        ));
        assert!(refuse_plaintext_keys(&load_str(OK).unwrap()).is_ok());
        assert!(refuse_plaintext_keys(&Value::Str("sk-live".into())).is_ok());
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
            "https://api.openai.com:8443/v1",
            "https://10.0.0.5/v1",
            // a bare bracketed loopback, no port; the loopback ADDRESS in its
            // long spelling; the top of the port range
            "http://[::1]/v1",
            "http://[0:0:0:0:0:0:0:1]:8080/v1",
            "https://api.openai.com:65535/v1",
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
            // userinfo: a credential in a disclosed field, and the trick that
            // reads `localhost:pw@remote` as loopback
            "http://localhost:pw@remote.example/v1",
            "http://127.0.0.1@remote.example/v1",
            "https://user:pw@api.openai.com/v1",
            "https://@api.openai.com/v1",
            // scheme is case-sensitive; an unclosed IPv6 bracket is not a host
            "HTTPS://api.openai.com/v1",
            "http://[::1/v1",
            // authority syntax (codex round 2): hostless, empty brackets, bad
            // port, bad host characters
            "https://?query",
            "https://[]",
            "https://[]:443/v1",
            "http://localhost:garbage/v1",
            "http://localhost:/v1",
            "http://localhost:0/v1",
            "http://localhost:123456/v1",
            "https://-bad.example/v1",
            "https://bad.example./v1",
            "https://exa mple/v1",
            "https://[::1]x/v1",
            "http://[::1]:/v1",
            // bracket contents that are not an IPv6 address, whichever scheme
            "https://[zz::1]/v1",
            "https://[1]/v1",
            "http://[::2]/v1",
            // ports: above the range, leading zeros, a sign
            "https://api.openai.com:65536/v1",
            "http://localhost:00000/v1",
            "http://localhost:08080/v1",
            "http://localhost:+80/v1",
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
        // Each permitted separator on its own, so no single `||` in the
        // allowlist can be turned into `&&` unnoticed.
        for ok in ["open-ai", "open_ai", "gpt.4", "A1"] {
            let p = parse(&OK.replace("name: openai", &format!("name: '{ok}'")))
                .unwrap()
                .unwrap();
            assert_eq!(p.name, ok);
        }
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
