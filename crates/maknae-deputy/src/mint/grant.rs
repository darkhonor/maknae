//! The check that a GitHub installation-token grant is exactly the permission
//! set that was asked for.

use maknae_io::secret::de_zeroizing_string;
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

pub const TOKEN_MAX_BYTES: usize = 255;

/// GitHub's installation-token alphabet; anything else is never sent as a bearer.
pub fn is_installation_token(token: &str) -> bool {
    (1..=TOKEN_MAX_BYTES).contains(&token.len())
        && token
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'_')
}

/// `YYYY-MM-DDTHH:MM:SSZ`, the one form GitHub writes `expires_at` in.
pub(super) fn is_github_timestamp(at: &str) -> bool {
    const FORM: &[u8; 20] = b"0000-00-00T00:00:00Z";
    at.len() == FORM.len()
        && at.bytes().zip(FORM).all(|(b, f)| match f {
            b'0' => b.is_ascii_digit(),
            _ => b == *f,
        })
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
    if got_repos.len() != repositories.len() {
        return false;
    }
    grant.repository_selection.as_deref() == Some("selected")
        && got == want
        && got_repos == want_repos
}

pub(super) fn grant_is_metadata_read(grant: &Grant) -> bool {
    let metadata = GithubPermission::Metadata.as_str();
    matches!(grant.permissions.as_slice(), [(p, l)] if p == metadata && l == "read")
}

/// The token alone, parsed before the rest of the grant so a grant that fails
/// to parse can still be revoked with it.
#[derive(Deserialize)]
pub(super) struct Bearer {
    #[serde(deserialize_with = "de_zeroizing_string")]
    pub(super) token: Zeroizing<String>,
}

#[derive(Deserialize)]
pub(super) struct Grant {
    #[serde(deserialize_with = "de_zeroizing_string")]
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
    fn an_installation_token_is_1_to_255_bytes_of_alphanumerics_and_underscore() {
        let longest = "a".repeat(TOKEN_MAX_BYTES);
        let over = "a".repeat(TOKEN_MAX_BYTES + 1);
        for ok in [
            "g",
            "ghs_16C7e42F292c6912E7710c838347Ae178B4a",
            "Z_9",
            &longest,
        ] {
            assert!(is_installation_token(ok), "{ok:?}");
        }
        for bad in [
            "",
            &over,
            "ghs-x",
            "ghs x",
            "ghs.x",
            "ghs/x",
            "ghs\nx",
            "ghs\r\nx: y",
            "gh\u{e9}s",
        ] {
            assert!(!is_installation_token(bad), "{bad:?}");
        }
        assert_eq!(TOKEN_MAX_BYTES, 255);
    }

    #[test]
    fn expires_at_is_exactly_github_s_utc_timestamp_form() {
        assert!(is_github_timestamp("2026-11-19T01:00:00Z"));
        assert!(is_github_timestamp("0000-00-00T00:00:00Z"));
        for bad in [
            "",
            "x",
            "2026-11-19T01:00:00",
            "2026-11-19T01:00:00ZZ",
            "2026-11-19T01:00:00.000Z",
            "2026-11-19T01:00:00+00:00",
            "2026-11-19 01:00:00Z",
            "2026-11-19t01:00:00Z",
            "2026-11-19T01:00:00z",
            "2026/11-19T01:00:00Z",
            "2026-11/19T01:00:00Z",
            "2026-11-19T01-00:00Z",
            "2026-11-19T01:00-00Z",
            "a026-11-19T01:00:00Z",
            "2026-1a-19T01:00:00Z",
            "2026-11-1aT01:00:00Z",
            "2026-11-19Ta1:00:00Z",
            "2026-11-19T01:a0:00Z",
            "2026-11-19T01:00:0aZ",
            "2026-11-19T01:00:00\u{0}",
            "\u{e9}026-11-19T01:00:00Z",
        ] {
            assert!(!is_github_timestamp(bad), "{bad:?}");
        }
        assert!(!is_github_timestamp(&"2".repeat(1 << 20)));
    }

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
