//! The check that a GitHub installation-token grant is exactly the permission
//! set that was asked for.

use maknae_proto::{AccessLevel, GithubPermission, PermissionSet};
use serde::{Deserialize, Deserializer};
use std::collections::{BTreeMap, BTreeSet};
use zeroize::Zeroizing;

pub(super) fn level(l: AccessLevel) -> &'static str {
    match l {
        AccessLevel::Read => "read",
        AccessLevel::Write => "write",
    }
}

pub(super) fn grant_matches(set: &PermissionSet, grant: &Grant) -> bool {
    let want: BTreeMap<&str, &str> = set
        .permissions
        .iter()
        .map(|(p, l)| (p.as_str(), level(*l)))
        .collect();
    let mut got: BTreeMap<&str, &str> = grant
        .permissions
        .iter()
        .map(|(k, v)| (k.as_str(), v.as_str()))
        .collect();
    let metadata = GithubPermission::Metadata.as_str();
    if !want.contains_key(metadata) && got.get(metadata) == Some(&"read") {
        got.remove(metadata);
    }
    let Some(repositories) = &grant.repositories else {
        return false;
    };
    let want_repos: BTreeSet<String> = set
        .repositories
        .iter()
        .map(|r| r.to_ascii_lowercase())
        .collect();
    let got_repos: BTreeSet<String> = repositories
        .iter()
        .map(|r| r.name.to_ascii_lowercase())
        .collect();
    grant.repository_selection.as_deref() == Some("selected")
        && got == want
        && got_repos == want_repos
}

#[derive(Deserialize)]
pub(super) struct Grant {
    #[serde(deserialize_with = "de_secret")]
    pub(super) token: Zeroizing<String>,
    pub(super) expires_at: String,
    #[serde(deserialize_with = "unique_keys")]
    permissions: Vec<(String, String)>,
    repository_selection: Option<String>,
    repositories: Option<Vec<GrantedRepository>>,
}

#[derive(Deserialize)]
struct GrantedRepository {
    name: String,
}

struct SecretStrVisitor;

impl serde::de::Visitor<'_> for SecretStrVisitor {
    type Value = Zeroizing<String>;

    fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("a string")
    }

    fn visit_str<E: serde::de::Error>(self, v: &str) -> Result<Self::Value, E> {
        Ok(Zeroizing::new(v.to_owned()))
    }
}

fn de_secret<'de, D: Deserializer<'de>>(d: D) -> Result<Zeroizing<String>, D::Error> {
    d.deserialize_str(SecretStrVisitor)
}

fn unique_keys<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<(String, String)>, D::Error> {
    struct V;
    impl<'de> serde::de::Visitor<'de> for V {
        type Value = Vec<(String, String)>;
        fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.write_str("a map of permissions, each named once")
        }
        fn visit_map<A: serde::de::MapAccess<'de>>(
            self,
            mut m: A,
        ) -> Result<Self::Value, A::Error> {
            let mut out: Vec<(String, String)> = Vec::new();
            while let Some((k, v)) = m.next_entry::<String, String>()? {
                if out.iter().any(|(seen, _)| *seen == k) {
                    return Err(serde::de::Error::custom("duplicate permission"));
                }
                out.push((k, v));
            }
            Ok(out)
        }
    }
    d.deserialize_map(V)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_grant_of_the_wrong_shape_is_refused_naming_what_was_expected() {
        let token = serde_json::from_str::<Grant>(
            r#"{"token":5,"expires_at":"x","permissions":{},"repository_selection":null,"repositories":null}"#,
        )
        .err()
        .unwrap()
        .to_string();
        assert!(token.contains("expected a string"), "{token}");
        let perms = serde_json::from_str::<Grant>(
            r#"{"token":"t","expires_at":"x","permissions":[],"repository_selection":null,"repositories":null}"#,
        )
        .err()
        .unwrap()
        .to_string();
        assert!(
            perms.contains("expected a map of permissions, each named once"),
            "{perms}"
        );
    }
}
