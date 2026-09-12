//! Egress operating bounds (#240a D4-B / D8) — `/etc/maknae/egress-bounds.yaml`.
//!
//! **Why this is its own file and not a section of `maknae.yaml`.** `maknaed`
//! reads the whole configuration; `maknae-egress` must not. The deputy holds
//! the provider credential and the only route out, so it is given its own
//! operating bounds and nothing else — no policy, no provider registry, no
//! identity map. The invariant is *egress reads no policy and no registry; it
//! may read its own operating bounds.*
//!
//! **Why the parser lives here rather than in the binary.** Both processes
//! read this file — `maknaed` validates every registered `key_vault_path`
//! against the prefix at BOOT (`maknae-kernel`'s `egress_bounds_boot_gate`),
//! `maknae-egress` validates the frame's path at USE (`handle::decide`) — and
//! two parsers over one file is the failure that created `maknae-io`. One
//! parser, two callers.
//!
//! The prefix is **not a secret**: `maknaed`'s Vault policy does not grant the
//! read, so nothing is protected by hiding it. It lives beside the `provider:`
//! sections it describes, in the file the operator is already editing.

use crate::{ConfigError, Value};

/// The file, relative to the configuration anchor directory.
pub const EGRESS_BOUNDS_FILE: &str = "egress-bounds.yaml";

/// Upper bound on the prefix. It reaches audit records and terminals.
pub const MAX_KEY_VAULT_PREFIX_BYTES: usize = 256;

/// What the deputy is allowed to do, and nothing more.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EgressBounds {
    /// The Vault KV path prefix the deputy's policy grants. Every provider's
    /// `key_vault_path` must sit under it.
    pub key_vault_path_prefix: String,
}

fn err(reason: impl Into<String>) -> ConfigError {
    ConfigError::InvalidProvider(reason.into())
}

/// Is `path` genuinely CONTAINED by `prefix`?
///
/// Not a bare `starts_with`. `secret/data/maknae/providers` must not admit
/// `secret/data/maknae/providers-evil/key`: a prefix that stops mid-segment
/// is the classic containment bug, and here it would let a malformed or
/// hostile registry entry name a Vault path outside the deputy's grant. The
/// match must land on a segment boundary.
pub fn path_is_within_prefix(path: &str, prefix: &str) -> bool {
    if prefix.is_empty() || path.is_empty() {
        return false;
    }
    let p = prefix.strip_suffix('/').unwrap_or(prefix);
    match path.strip_prefix(p) {
        Some(rest) => rest.starts_with('/') && rest.len() > 1,
        None => false,
    }
}

/// Parse the bounds document. Shape-only and fail-closed: an absent or empty
/// prefix is a refusal, never a permissive default, and `None` is never a
/// silent absence.
pub fn bounds_from_document(v: &Value) -> Result<EgressBounds, ConfigError> {
    let Value::Map(m) = v else {
        return Err(err(
            "egress-bounds.yaml: expected a mapping at the top level",
        ));
    };
    for (k, _) in m.iter() {
        if k != "key_vault_path_prefix" {
            return Err(err(format!(
                "egress-bounds.yaml: unknown key '{k}' (no registered spec)"
            )));
        }
    }
    let Some((_, Value::Str(prefix))) = m.iter().find(|(k, _)| k == "key_vault_path_prefix") else {
        return Err(err(
            "egress-bounds.yaml: 'key_vault_path_prefix' is required and must be a string",
        ));
    };
    if prefix.is_empty() {
        return Err(err("egress-bounds.yaml: 'key_vault_path_prefix' is empty"));
    }
    if prefix.len() > MAX_KEY_VAULT_PREFIX_BYTES {
        return Err(err(format!(
            "egress-bounds.yaml: 'key_vault_path_prefix' exceeds {MAX_KEY_VAULT_PREFIX_BYTES} bytes"
        )));
    }
    if prefix.starts_with('/') || prefix.chars().any(char::is_whitespace) {
        return Err(err(
            "egress-bounds.yaml: 'key_vault_path_prefix' must not start with '/' or contain whitespace",
        ));
    }
    Ok(EgressBounds {
        key_vault_path_prefix: prefix.clone(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn doc(prefix: &str) -> Value {
        Value::Map(vec![(
            "key_vault_path_prefix".into(),
            Value::Str(prefix.into()),
        )])
    }

    /// THE containment control. A bare `starts_with` admits a sibling path
    /// whose name merely begins with the prefix, which would let a registry
    /// entry name a Vault path outside the deputy's grant.
    #[test]
    fn a_sibling_path_that_merely_starts_with_the_prefix_is_not_contained() {
        let p = "secret/data/maknae/providers";
        assert!(path_is_within_prefix(
            "secret/data/maknae/providers/openai",
            p
        ));
        assert!(!path_is_within_prefix(
            "secret/data/maknae/providers-evil/key",
            p
        ));
        // the prefix itself is not a document
        assert!(!path_is_within_prefix(p, p));
        // a trailing slash on the prefix behaves identically
        assert!(path_is_within_prefix(
            "secret/data/maknae/providers/openai",
            "secret/data/maknae/providers/"
        ));
        assert!(!path_is_within_prefix("secret/data/other/openai", p));
        assert!(!path_is_within_prefix("", p));
        assert!(!path_is_within_prefix("x", ""));
    }

    #[test]
    fn a_well_formed_document_parses() {
        assert_eq!(
            bounds_from_document(&doc("secret/data/maknae/providers")).unwrap(),
            EgressBounds {
                key_vault_path_prefix: "secret/data/maknae/providers".into()
            }
        );
    }

    /// Fail closed on every malformed shape: absent, empty, wrong type,
    /// unknown key, over-long, absolute, or whitespace-bearing.
    #[test]
    fn every_malformed_document_is_refused() {
        assert!(bounds_from_document(&Value::Str("x".into())).is_err());
        assert!(bounds_from_document(&Value::Map(vec![])).is_err());
        assert!(bounds_from_document(&doc("")).is_err());
        assert!(bounds_from_document(&doc("/secret/data")).is_err());
        assert!(bounds_from_document(&doc("secret data")).is_err());
        assert!(bounds_from_document(&doc(&"a".repeat(MAX_KEY_VAULT_PREFIX_BYTES + 1))).is_err());
        assert!(bounds_from_document(&Value::Map(vec![(
            "key_vault_path_prefix".into(),
            Value::Int(3)
        )]))
        .is_err());
        // an unknown key is refused BY NAME rather than ignored
        assert!(bounds_from_document(&Value::Map(vec![
            ("key_vault_path_prefix".into(), Value::Str("a/b".into())),
            ("mystery".into(), Value::Bool(true)),
        ]))
        .is_err());
    }
}
