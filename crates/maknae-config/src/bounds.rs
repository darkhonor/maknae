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
///
/// The two fields together mirror the Vault grant's own shape,
/// `<mount>/data/<prefix>/*` — so this document is the host-side statement of
/// exactly what Terraform granted, in the file the granted process reads.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EgressBounds {
    /// The KV v2 mount the provider keys live in (Terraform `kv_mount_path`;
    /// `maknae-kv` in the shipped deployment).
    ///
    /// **Declared here and nowhere else (#308).** The deputy is the ONLY
    /// component in the tree that reads KV — `bins/maknae-egress`'s
    /// `keys_vault.rs` is the single caller of `read_kv_field` — so a
    /// `vault.kv_mount` in `maknae.yaml` would be read by nobody, and a
    /// cross-check between the two would reintroduce the two-places-for-one-
    /// value problem this change exists to remove.
    pub kv_mount: String,
    /// The path prefix, **RELATIVE to `kv_mount` and without the `data/`
    /// segment**, that the deputy's policy grants. Every provider's
    /// `key_vault_path` must sit under it.
    ///
    /// Relative because Terraform's `provider_key_prefix` is documented
    /// relative to `kv_mount_path` while the old configuration value was
    /// mount-absolute *plus* the `data/` API artifact: two coordinate systems
    /// for one value, required to "MATCH". That mismatch is what made #307's
    /// singular/plural defect invisible — the two host-side values agreed with
    /// each other and disagreed with the grant, and the boot gate compares only
    /// the two host-side values, never the grant.
    pub key_vault_path_prefix: String,
}

/// Is this a usable mount-relative Vault path fragment? `Err` names the reason,
/// so a refusal tells an operator which rule they hit.
///
/// Pure, and shared by the mount, the prefix, and `provider.key_vault_path`, so
/// all three agree by construction rather than by three hand-kept copies.
pub fn kv_fragment_is_acceptable(s: &str) -> Result<(), String> {
    if s.is_empty() {
        return Err("is empty".into());
    }
    if s.chars().any(char::is_whitespace) {
        return Err("contains whitespace".into());
    }
    // A leading/trailing-slash check here would be DEAD LOGIC: `/foo` splits to
    // `["", "foo"]` and `foo/` to `["foo", ""]`, so the empty-segment arm below
    // already rejects both — which is why `cargo mutants` could turn its `||`
    // into `&&` and no test could tell (measured 2026-09-13, #308). The position
    // of the empty segment carries the message instead, so each arm is reachable
    // and therefore killable.
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
        if *seg == "." || *seg == ".." {
            return Err("has a '.' or '..' segment".into());
        }
        // THE HALF-MIGRATED CONFIG GUARD. A value still carrying the mount and
        // the API artifact — `maknae-kv/data/llm-providers` — would compose to
        // `maknae-kv/data/maknae-kv/data/llm-providers` and fetch nothing. #307
        // proved this class fails at the credential read rather than at boot,
        // because nothing compares a host-side value to Vault's grant. Refusing
        // any `data` segment makes it a named boot refusal. The cost, stated: a
        // secret path legitimately containing a `data` segment cannot be
        // expressed here. That is rare; the migration error is not.
        if *seg == "data" {
            return Err(
                "contains a 'data' segment — the mount and the KV v2 'data/'                  segment are no longer written in configuration (#308); write                  the path as your Vault CLI shows it"
                    .into(),
            );
        }
    }
    Ok(())
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
        if k != "key_vault_path_prefix" && k != "kv_mount" {
            return Err(err(format!(
                "egress-bounds.yaml: unknown key '{k}' (no registered spec)"
            )));
        }
    }
    let required = |name: &str| -> Result<String, ConfigError> {
        let Some((_, Value::Str(v))) = m.iter().find(|(k, _)| k == name) else {
            return Err(err(format!(
                "egress-bounds.yaml: '{name}' is required and must be a string"
            )));
        };
        if v.len() > MAX_KEY_VAULT_PREFIX_BYTES {
            return Err(err(format!(
                "egress-bounds.yaml: '{name}' exceeds {MAX_KEY_VAULT_PREFIX_BYTES} bytes"
            )));
        }
        kv_fragment_is_acceptable(v)
            .map_err(|why| err(format!("egress-bounds.yaml: '{name}' {why}")))?;
        Ok(v.clone())
    };
    Ok(EgressBounds {
        kv_mount: required("kv_mount")?,
        key_vault_path_prefix: required("key_vault_path_prefix")?,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A document carrying BOTH fields (#308). `doc` below remains the
    /// single-field builder, so the tests that assert a missing `kv_mount` is
    /// refused keep working.
    fn doc2(mount: &str, prefix: &str) -> Value {
        Value::Map(vec![
            ("kv_mount".into(), Value::Str(mount.into())),
            ("key_vault_path_prefix".into(), Value::Str(prefix.into())),
        ])
    }

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
        let p = "llm-providers";
        assert!(path_is_within_prefix("llm-providers/openai", p));
        assert!(!path_is_within_prefix(
            "secret/data/maknae/providers-evil/key",
            p
        ));
        // the prefix itself is not a document
        assert!(!path_is_within_prefix(p, p));
        // a trailing slash on the prefix behaves identically
        assert!(path_is_within_prefix(
            "llm-providers/openai",
            "llm-providers/"
        ));
        assert!(!path_is_within_prefix("secret/data/other/openai", p));
        assert!(!path_is_within_prefix("", p));
        assert!(!path_is_within_prefix("x", ""));
    }

    /// An EMPTY prefix admits nothing. Measured gap (#295's class, found by
    /// `cargo mutants` on this PR's own code): `||` → `&&` on the emptiness
    /// guard survived, because every input the tests used was also refused
    /// downstream. This one is not: with `&&`, an empty prefix strips to ""
    /// and `"/x".strip_prefix("")` yields `"/x"`, which is segment-aligned and
    /// long enough — so an UNSET prefix would admit an absolute-looking path.
    /// An absent grant must never be a universal grant.
    #[test]
    fn an_empty_prefix_admits_nothing_including_an_absolute_looking_path() {
        assert!(!path_is_within_prefix("/x", ""));
        assert!(!path_is_within_prefix(
            "/secret/data/maknae/providers/openai",
            ""
        ));
        assert!(!path_is_within_prefix("", ""));
    }

    /// The prefix itself, with a trailing slash and nothing after it, is not a
    /// document. Measured gap: `rest.len() > 1` → `>=` survived, which would
    /// make `<prefix>/` count as contained — a path naming the directory
    /// rather than a secret inside it.
    #[test]
    fn the_prefix_with_a_trailing_slash_is_not_a_document_within_it() {
        let p = "llm-providers";
        assert!(!path_is_within_prefix("llm-providers/", p));
        // and one character after the slash IS a document
        assert!(path_is_within_prefix("llm-providers/a", p));
    }

    #[test]
    fn a_well_formed_document_parses() {
        assert_eq!(
            bounds_from_document(&doc2("maknae-kv", "llm-providers")).unwrap(),
            EgressBounds {
                kv_mount: "maknae-kv".into(),
                key_vault_path_prefix: "llm-providers".into()
            }
        );
    }

    /// #308: the mount is declared HERE, in the deputy's own file, because the
    /// deputy is the only component in the tree that reads KV — `keys_vault.rs`
    /// is the single caller. A `vault.kv_mount` in `maknae.yaml` would be read
    /// by nobody, and a cross-check between the two would be the
    /// two-places-for-one-value problem this change exists to remove. Together
    /// the two fields mirror the Vault grant's own shape,
    /// `<mount>/data/<prefix>/*`.
    #[test]
    fn the_mount_is_required_and_validated_like_the_prefix() {
        // absent
        assert!(bounds_from_document(&doc("llm-providers")).is_err());
        // Each empty-segment POSITION has its own message, so a mutation of one
        // arm is observable. Asserted rather than merely `is_err()`, which a
        // single shared message would have made indistinguishable.
        for (bad, want) in [
            ("/maknae-kv", "must not start with '/'"),
            ("maknae-kv/", "must not end with '/'"),
            ("maknae//kv", "empty interior path segment"),
        ] {
            let e = bounds_from_document(&doc2(bad, "llm-providers")).unwrap_err();
            assert!(
                e.to_string().contains(want),
                "kv_mount {bad:?} must be refused with {want:?}, got: {e}"
            );
        }
        // present but malformed, each for its own reason
        for bad in [
            "",             // empty
            "/maknae-kv",   // leading slash
            "maknae-kv/",   // trailing slash
            "maknae kv",    // whitespace
            "maknae//kv",   // empty interior segment
            "maknae-kv/..", // traversal
            "./maknae-kv",  // traversal
        ] {
            assert!(
                bounds_from_document(&doc2(bad, "llm-providers")).is_err(),
                "kv_mount {bad:?} must be refused"
            );
        }
        // a NESTED mount is legal in Vault (`-path=a/b`) and must be accepted
        assert!(bounds_from_document(&doc2("platform/maknae-kv", "llm-providers")).is_ok());
    }

    /// THE HALF-MIGRATED CONFIG, and the reason this refusal exists rather than
    /// a silent compose. #307 shipped documentation whose prefix and path agreed
    /// with each other and disagreed with Vault's grant: the boot gate compares
    /// the two host-side values and NEVER the grant, so it booted clean and took
    /// a 403 at the credential read. The same class after #308 is a value still
    /// carrying the mount and `data/` — `maknae-kv/data/llm-providers` — which
    /// would compose to `maknae-kv/data/maknae-kv/data/llm-providers`. Refusing
    /// any `data` SEGMENT makes it a named boot refusal instead. The cost is
    /// stated: a secret path legitimately containing a `data` segment cannot be
    /// expressed, which is rare, and the migration error is not.
    #[test]
    fn a_prefix_still_carrying_the_mount_or_data_segment_is_refused_by_name() {
        for bad in [
            "maknae-kv/data/llm-providers", // the old absolute value, pasted
            "data/llm-providers",           // the mount stripped, `data/` left
            "llm/data/providers",           // a `data` segment anywhere
        ] {
            let e = bounds_from_document(&doc2("maknae-kv", bad)).unwrap_err();
            assert!(
                e.to_string().contains("data"),
                "prefix {bad:?} must be refused naming 'data', got: {e}"
            );
        }
        // And the mount itself must not carry one either.
        assert!(bounds_from_document(&doc2("maknae-kv/data", "llm-providers")).is_err());
    }

    /// Fail closed on every malformed shape: absent, empty, wrong type,
    /// unknown key, over-long, absolute, or whitespace-bearing.
    #[test]
    fn every_malformed_document_is_refused() {
        // Each prefix case carries a VALID mount, so it is refused for its own
        // reason rather than for the missing mount (#308) — the
        // rejected-for-the-wrong-reason trap `expect_reject_because` exists for.
        const OK_MOUNT: &str = "maknae-kv";
        assert!(bounds_from_document(&Value::Str("x".into())).is_err());
        assert!(bounds_from_document(&Value::Map(vec![])).is_err());
        for bad_prefix in ["", "/secret", "secret data", "a//b", "a/../b"] {
            assert!(
                bounds_from_document(&doc2(OK_MOUNT, bad_prefix)).is_err(),
                "prefix {bad_prefix:?} must be refused"
            );
        }
        assert!(
            bounds_from_document(&doc2(OK_MOUNT, &"a".repeat(MAX_KEY_VAULT_PREFIX_BYTES + 1)))
                .is_err()
        );
        // AT the bound, accepted. Measured gap: `>` → `>=` survived because the
        // only length ever tested was MAX+1, where both operators refuse alike.
        assert!(
            bounds_from_document(&doc2(OK_MOUNT, &"a".repeat(MAX_KEY_VAULT_PREFIX_BYTES))).is_ok()
        );
        // and the same bound applies to the mount, for the same reason
        assert!(bounds_from_document(&doc2(
            &"m".repeat(MAX_KEY_VAULT_PREFIX_BYTES + 1),
            "llm-providers"
        ))
        .is_err());
        assert!(bounds_from_document(&doc2(
            &"m".repeat(MAX_KEY_VAULT_PREFIX_BYTES),
            "llm-providers"
        ))
        .is_ok());
        // a non-string value for either field
        assert!(bounds_from_document(&Value::Map(vec![
            ("kv_mount".into(), Value::Str(OK_MOUNT.into())),
            ("key_vault_path_prefix".into(), Value::Int(3)),
        ]))
        .is_err());
        assert!(bounds_from_document(&Value::Map(vec![
            ("kv_mount".into(), Value::Int(3)),
            ("key_vault_path_prefix".into(), Value::Str("a/b".into())),
        ]))
        .is_err());
        // a document carrying ONLY the prefix is refused — the mount is not
        // optional and has no default, so an old file fails closed rather than
        // composing against a guessed mount.
        assert!(bounds_from_document(&doc("llm-providers")).is_err());
        // an unknown key is refused BY NAME rather than ignored
        assert!(bounds_from_document(&Value::Map(vec![
            ("kv_mount".into(), Value::Str(OK_MOUNT.into())),
            ("key_vault_path_prefix".into(), Value::Str("a/b".into())),
            ("mystery".into(), Value::Bool(true)),
        ]))
        .is_err());
    }
}
