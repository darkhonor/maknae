use crate::{ConfigError, Value};

pub const FORGES_SECTION: &str = "forges";

pub const FORGE_KEYS: [&str; 4] = ["name", "kind", "host", "provider"];

pub const MAX_FORGES: usize = 32;
pub const MAX_FORGE_NAME_BYTES: usize = 64;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ForgeKind {
    Git,
}

impl ForgeKind {
    pub fn as_str(self) -> &'static str {
        match self {
            ForgeKind::Git => "git",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ForgeProvider {
    Github,
    Gitlab,
}

impl ForgeProvider {
    pub fn as_str(self) -> &'static str {
        match self {
            ForgeProvider::Github => "github",
            ForgeProvider::Gitlab => "gitlab",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AuthorizedForge {
    pub name: String,
    pub kind: ForgeKind,
    pub host: String,
    pub provider: ForgeProvider,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ForgeSet(Vec<AuthorizedForge>);

impl ForgeSet {
    pub fn empty() -> Self {
        Self(Vec::new())
    }

    pub fn get(&self, name: &str) -> Option<&AuthorizedForge> {
        self.0.iter().find(|f| f.name == name)
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    pub fn len(&self) -> usize {
        self.0.len()
    }

    pub fn iter(&self) -> std::slice::Iter<'_, AuthorizedForge> {
        self.0.iter()
    }
}

fn err(reason: impl Into<String>) -> ConfigError {
    ConfigError::InvalidForge(reason.into())
}

fn name_is_acceptable(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= MAX_FORGE_NAME_BYTES
        && s.bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
}

fn required_str<'a>(m: &'a [(String, Value)], at: &str, key: &str) -> Result<&'a str, ConfigError> {
    match m.iter().find(|(k, _)| k == key).map(|(_, v)| v) {
        None => Err(err(format!("{at}: missing '{key}'"))),
        Some(Value::Str(s)) => Ok(s),
        Some(_) => Err(err(format!("{at}.{key} must be a string"))),
    }
}

pub fn forges_from_section(v: Option<&Value>) -> Result<ForgeSet, ConfigError> {
    let Some(section) = v else {
        return Ok(ForgeSet::empty());
    };
    let Value::Seq(items) = section else {
        return Err(err("forges must be a sequence of forge entries"));
    };
    if items.len() > MAX_FORGES {
        return Err(err(format!("forges may list at most {MAX_FORGES} entries")));
    }
    let mut set: Vec<AuthorizedForge> = Vec::with_capacity(items.len());
    for (i, item) in items.iter().enumerate() {
        let forge = forge_entry(i, item)?;
        if set.iter().any(|f| f.name == forge.name) {
            return Err(err(format!(
                "forges[{i}].name '{}' is listed more than once",
                forge.name
            )));
        }
        set.push(forge);
    }
    Ok(ForgeSet(set))
}

fn forge_entry(i: usize, item: &Value) -> Result<AuthorizedForge, ConfigError> {
    let at = format!("forges[{i}]");
    let Value::Map(m) = item else {
        return Err(err(format!("{at} must be a map")));
    };
    crate::reject_unknown_keys(FORGES_SECTION, m, &FORGE_KEYS)?;
    let name = required_str(m, &at, "name")?;
    if !name_is_acceptable(name) {
        return Err(err(format!(
            "{at}.name must be 1 to {MAX_FORGE_NAME_BYTES} bytes of lowercase ASCII letters, digits and '-'"
        )));
    }
    let kind = match required_str(m, &at, "kind")? {
        "git" => ForgeKind::Git,
        _ => return Err(err(format!("{at}.kind must be git"))),
    };
    let host = required_str(m, &at, "host")?;
    let host = host.to_ascii_lowercase();
    if !maknae_proto::server_is_acceptable(&host) {
        return Err(err(format!(
            "{at}.host must be a host name or IP address with an optional port in 1 to 65535, at most {} bytes, and no scheme, path or userinfo",
            maknae_proto::SERVER_MAX_BYTES
        )));
    }
    let provider = match required_str(m, &at, "provider")? {
        "github" => ForgeProvider::Github,
        "gitlab" => ForgeProvider::Gitlab,
        _ => return Err(err(format!("{at}.provider must be github or gitlab"))),
    };
    Ok(AuthorizedForge {
        name: name.to_string(),
        kind,
        host,
        provider,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::load_str;
    use crate::providers::endpoint_is_acceptable;

    fn host_port_is_acceptable(s: &str) -> bool {
        maknae_proto::host_port(s).is_some()
    }

    const FULL: &str = concat!(
        "- name: github\n",
        "  kind: git\n",
        "  host: github.com\n",
        "  provider: github\n",
        "- name: lab\n",
        "  kind: git\n",
        "  host: GitLab.Lab.Local:8443\n",
        "  provider: gitlab\n",
    );

    fn parse(yaml: &str) -> Result<ForgeSet, ConfigError> {
        let v = load_str(yaml).expect("test yaml parses");
        forges_from_section(Some(&v))
    }

    fn refusal(yaml: &str) -> String {
        match parse(yaml) {
            Err(ConfigError::InvalidForge(m)) => m,
            other => panic!("expected InvalidForge, got {other:?}"),
        }
    }

    fn entry(name: &str, kind: &str, host: &str, provider: &str) -> String {
        format!("- name: '{name}'\n  kind: '{kind}'\n  host: '{host}'\n  provider: '{provider}'\n")
    }

    #[test]
    fn an_absent_section_is_empty() {
        let none = forges_from_section(None).unwrap();
        assert!(none.is_empty());
        assert_eq!(none.len(), 0);
        assert_eq!(none, ForgeSet::empty());
        assert!(parse("[]\n").unwrap().is_empty());
    }

    #[test]
    fn a_full_section_parses() {
        let set = parse(FULL).unwrap();
        assert_eq!(set.len(), 2);
        assert!(!set.is_empty());
        assert_eq!(
            set.get("github"),
            Some(&AuthorizedForge {
                name: "github".into(),
                kind: ForgeKind::Git,
                host: "github.com".into(),
                provider: ForgeProvider::Github,
            })
        );
        assert_eq!(
            set.get("lab"),
            Some(&AuthorizedForge {
                name: "lab".into(),
                kind: ForgeKind::Git,
                host: "gitlab.lab.local:8443".into(),
                provider: ForgeProvider::Gitlab,
            })
        );
        assert_eq!(set.get("gitlab"), None);
        let names: Vec<&str> = set.iter().map(|f| f.name.as_str()).collect();
        assert_eq!(names, ["github", "lab"]);
        assert_eq!(ForgeKind::Git.as_str(), "git");
        assert_eq!(ForgeProvider::Github.as_str(), "github");
        assert_eq!(ForgeProvider::Gitlab.as_str(), "gitlab");
    }

    #[test]
    fn unknown_keys_are_refused() {
        let yaml = format!(
            "{}  url: https://github.com\n",
            entry("g", "git", "github.com", "github")
        );
        match parse(&yaml) {
            Err(ConfigError::UnknownKey { section, key }) => {
                assert_eq!((section.as_str(), key.as_str()), (FORGES_SECTION, "url"));
            }
            other => panic!("expected UnknownKey, got {other:?}"),
        }
    }

    #[test]
    fn the_section_is_a_list_of_maps_with_every_key() {
        assert!(refusal("github\n").contains("sequence"));
        assert!(refusal("name: github\n").contains("sequence"));
        assert!(refusal("- github\n").contains("forges[0] must be a map"));
        match forges_from_section(Some(&Value::Null)) {
            Err(ConfigError::InvalidForge(m)) => {
                assert_eq!(m, "forges must be a sequence of forge entries")
            }
            other => panic!("expected InvalidForge, got {other:?}"),
        }
        assert!(refusal("~\n").contains("sequence"));
        let fields = [
            ("name", "g"),
            ("kind", "git"),
            ("host", "github.com"),
            ("provider", "github"),
        ];
        for key in FORGE_KEYS {
            let body: Vec<String> = fields
                .iter()
                .filter(|(k, _)| *k != key)
                .map(|(k, v)| format!("{k}: {v}"))
                .collect();
            let m = refusal(&format!("- {}\n", body.join("\n  ")));
            assert!(
                m.contains(&format!("forges[0]: missing '{key}'")),
                "{key}: {m}"
            );
        }
        let m = refusal("- name: 3\n  kind: git\n  host: github.com\n  provider: github\n");
        assert!(m.contains("forges[0].name must be a string"), "{m}");
    }

    #[test]
    fn each_field_outside_its_grammar_is_refused() {
        let long = "n".repeat(MAX_FORGE_NAME_BYTES + 1);
        for bad in [
            "",
            "GitHub",
            "git_hub",
            "git.hub",
            "git hub",
            "gît",
            long.as_str(),
        ] {
            let m = refusal(&entry(bad, "git", "github.com", "github"));
            assert!(m.contains("forges[0].name"), "{bad:?}: {m}");
        }
        for bad in ["", "Git", "svn", "git ", "hg"] {
            let m = refusal(&entry("g", bad, "github.com", "github"));
            assert!(m.contains("forges[0].kind"), "{bad:?}: {m}");
        }
        for bad in ["", "GitHub", "gitea", "bitbucket", "github "] {
            let m = refusal(&entry("g", "git", "github.com", bad));
            assert!(m.contains("forges[0].provider"), "{bad:?}: {m}");
        }
        for bad in [
            "",
            "a..b",
            "-a",
            "a-",
            ".a",
            "a.",
            "a:0",
            "a:08",
            "a:65536",
            ":22",
            "https://github.com",
            "ssh://github.com",
            "github.com/org",
            "git@github.com",
            "github .com",
            "a:",
            "[::1",
            "[zz::1]",
            "256.256.256.256",
        ] {
            let m = refusal(&entry("g", "git", bad, "github"));
            assert!(m.contains("forges[0].host"), "{bad:?}: {m}");
        }
    }

    #[test]
    fn a_host_over_255_bytes_is_refused_so_every_forge_can_be_bound() {
        let at_cap = format!("{}.com", "A".repeat(251));
        assert_eq!(at_cap.len(), 255);
        let set = parse(&entry("g", "git", &at_cap, "github")).unwrap();
        assert_eq!(set.get("g").unwrap().host, at_cap.to_ascii_lowercase());
        let m = refusal(&entry("g", "git", &format!("{at_cap}x"), "github"));
        assert!(m.contains("forges[0].host"), "{m}");
    }

    #[test]
    fn the_name_takes_its_whole_alphabet_up_to_its_bound() {
        let at = "a-0".repeat(MAX_FORGE_NAME_BYTES / 3) + &"z".repeat(MAX_FORGE_NAME_BYTES % 3);
        assert_eq!(at.len(), MAX_FORGE_NAME_BYTES);
        for ok in ["a", "0", "-", "my-forge-9", at.as_str()] {
            let set = parse(&entry(ok, "git", "github.com", "github")).unwrap();
            assert_eq!(set.get(ok).map(|f| f.name.as_str()), Some(ok), "{ok:?}");
        }
    }

    #[test]
    fn ports_and_ipv6_are_accepted() {
        for (host, stored) in [
            ("ghe.example:8443", "ghe.example:8443"),
            ("[::1]:8443", "[::1]:8443"),
            ("[::1]", "[::1]"),
            ("[FE80::1]", "[fe80::1]"),
            ("GHE.Example:65535", "ghe.example:65535"),
            ("10.0.0.5:22", "10.0.0.5:22"),
            ("ghe.example:1", "ghe.example:1"),
        ] {
            let set = parse(&entry("g", "git", host, "github")).unwrap();
            assert_eq!(set.get("g").unwrap().host, stored, "{host}");
        }
    }

    #[test]
    fn duplicate_names_are_refused() {
        let yaml = format!(
            "{}{}",
            entry("g", "git", "github.com", "github"),
            entry("g", "git", "gitlab.example", "gitlab")
        );
        let m = refusal(&yaml);
        assert!(
            m.contains("forges[1].name") && m.contains("more than once"),
            "{m}"
        );
    }

    #[test]
    fn thirty_three_are_refused_and_thirty_two_accepted() {
        assert_eq!(MAX_FORGES, 32);
        let one = |i: usize| entry(&format!("f{i}"), "git", "github.com", "github");
        let at: String = (0..MAX_FORGES).map(one).collect();
        assert_eq!(parse(&at).unwrap().len(), MAX_FORGES);
        let over: String = (0..=MAX_FORGES).map(one).collect();
        let m = refusal(&over);
        assert!(m.contains(&format!("at most {MAX_FORGES}")), "{m}");
    }

    #[test]
    fn the_host_grammar_is_shared_with_providers() {
        for (h, accepted) in [
            ("github.com", true),
            ("ghe.example:8443", true),
            ("[::1]:8443", true),
            ("[::1]", true),
            ("10.0.0.5", true),
            ("A.B", true),
            ("x:65535", true),
            ("", false),
            ("a..b", false),
            ("-a", false),
            ("a.", false),
            ("a:0", false),
            ("a:08", false),
            ("a:65536", false),
            ("a:+80", false),
            ("a:", false),
            (":22", false),
            ("u@a", false),
            ("a b", false),
            ("[::1", false),
            ("[::1]x", false),
            ("[]", false),
            ("[1]", false),
            ("256.256.256.256", false),
            ("1.2.3", false),
            ("127.0.0.01", false),
        ] {
            assert_eq!(host_port_is_acceptable(h), accepted, "{h:?}");
            assert_eq!(
                endpoint_is_acceptable(&format!("https://{h}")),
                host_port_is_acceptable(h),
                "{h:?}"
            );
        }
    }
}
