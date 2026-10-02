//! Egress operating bounds (#240a D4-B / D8) — `/etc/maknae/egress-bounds.yaml`.
//!
//! **Why this is its own file and not a section of `maknae.yaml`.** `maknaed`
//! reads the whole configuration; `maknae-egress` must not. The deputy holds
//! the provider credential and the only route out, so it is given its own
//! operating bounds and nothing else — no policy, no provider registry, no
//! identity map. The invariant is *egress reads no policy and no registry; it
//! may read its own operating bounds.*
//!
//! **Amended 2026-09-21 by #264 — READ THIS BEFORE REASONING FROM THE CLAUSE
//! ABOVE.** The deputy's binary also links `maknae-llm`'s compiled-in core
//! prompt and baseline tool definitions and composes them into every outbound
//! request. That does not weaken the invariant: those are policy **APPROVED at
//! design time** (`include_str!`'d from reviewable text files, changed only by
//! a reviewed commit), not policy **EVALUATED at runtime**, and the deputy
//! still reads no configuration for them and decides nothing about them. The
//! clause is about runtime state and decisions. *(Recorded here, and in
//! `bins/maknae-egress/src/main.rs`, because misreading it as excluding the
//! preamble cost a design round on #264 and needed a maintainer ruling to
//! unwind — and this file is where the invariant is attributed, so it is the
//! one the next agent opens.)*
//!
//! One parser for both processes: `maknaed` checks the prefix's SHAPE at boot and composes each
//! user's key path beneath it per request, and `maknae-egress` checks a frame's path against it at
//! USE (`handle::decide`).
//! `user_prefix` is not a secret: it is a location, not a credential.

use crate::{ConfigError, Value};

/// The file, relative to the configuration anchor directory.
pub const EGRESS_BOUNDS_FILE: &str = "egress-bounds.yaml";

/// Upper bound on the prefix. It reaches audit records and terminals.
pub const MAX_USER_PREFIX_BYTES: usize = 256;

/// What the deputy is allowed to do, and nothing more.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EgressBounds {
    /// The KV v2 mount the user keys live in.
    pub kv_mount: String,
    /// Relative to `kv_mount`, without `data/`; each user's keys live under `<user_prefix>/<username>/`.
    pub user_prefix: String,
    /// `vault.addr` — where the Egress Daemon unwraps wrapping tokens. Declared in THIS file
    /// because the deputy reads its own bounds and nothing else: the AppArmor
    /// profile and the SELinux type carve-out grant it exactly this document,
    /// and `maknae.yaml` is denied to it by design. The same address appears in
    /// `maknae.yaml`'s `vault` block for `maknaed`; the two are used
    /// independently and never compared, so this is not #308's
    /// two-coordinate-systems-required-to-match shape. The scheme is validated
    /// where the client is built (`maknae-vault`), not here — one validator.
    pub vault_addr: String,
}

/// Is this a usable mount-relative Vault path fragment? `Err` names the reason,
/// so a refusal tells an operator which rule they hit.
///
/// Pure, and shared by the mount, the user prefix, the username and the composed
/// key path, so they agree by construction rather than by hand-kept copies.
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
        // the API artifact — `maknae-kv/data/maknae/providers` — would compose to
        // `maknae-kv/data/maknae-kv/data/maknae/providers` and fetch nothing. #307
        // proved this class fails at the credential read rather than at boot,
        // because nothing compares a host-side value to Vault's grant. Refusing
        // any `data` segment makes it a named boot refusal. The cost, stated: a
        // secret path legitimately containing a `data` segment cannot be
        // expressed here. That is rare; the migration error is not.
        if *seg == "data" {
            return Err(concat!(
                "contains a 'data' segment — the mount and the KV v2 'data/' segment ",
                "are no longer written in configuration (#308); write the path as ",
                "your Vault CLI shows it"
            )
            .into());
        }
    }
    Ok(())
}

/// Is this a usable AUTH MOUNT path? The shape half of
/// [`kv_fragment_is_acceptable`] — non-empty, no whitespace, no empty or
/// `.`/`..` segment — with the auth-mount analogue of the KV `data` rule in
/// place of it: a leading `auth` segment is refused by name, because vaultrs
/// composes `/auth/<mount>/login` itself and `auth/maknae-approle` (the
/// spelling `vault write` needs, and the README shows) would become
/// `/auth/auth/…` and fail the boot probe as an opaque 404 rather than here.
///
/// A near-copy of `kv_fragment_is_acceptable` rather than a call to it,
/// deliberately: each arm's message names the field's own rule, and folding
/// the two would change which reason `data/` reports for a KV path.
pub fn mount_path_is_acceptable(s: &str) -> Result<(), String> {
    if s.is_empty() {
        return Err("is empty".into());
    }
    if s.chars().any(char::is_whitespace) {
        return Err("contains whitespace".into());
    }
    if s.len() > MAX_USER_PREFIX_BYTES {
        return Err(format!("exceeds {MAX_USER_PREFIX_BYTES} bytes"));
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
        if *seg == "." || *seg == ".." {
            return Err("has a '.' or '..' segment".into());
        }
    }
    // After the shape checks, so `auth/` reports its trailing slash rather
    // than this.
    if segs[0] == "auth" {
        return Err(
            "starts with 'auth' — the auth/ prefix is composed by the client; write the bare mount name as Terraform declares it"
                .into(),
        );
    }
    Ok(())
}

/// Non-empty, and every byte in the Vault URL path alphabet `[A-Za-z0-9._/-]`.
pub fn vault_path_is_safe(s: &str) -> bool {
    !s.is_empty()
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'/' | b'-'))
}

fn err(reason: impl Into<String>) -> ConfigError {
    ConfigError::InvalidEgressBounds(reason.into())
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
        return Err(err("expected a mapping at the top level"));
    };
    // #210: `egress-bounds.yaml` is operator-authored, root-owned and read by
    // BOTH daemons, so a typo here is the same defect as one in `maknae.yaml`
    // and now raises the same error. It kept its own spelling until round-1
    // review pointed out that "one sentence for a wrong key, wherever it
    // appears" was false while these two sites survived.
    crate::reject_unknown_keys(EGRESS_BOUNDS_FILE, m, &["user_prefix", "kv_mount", "vault"])?;
    let required = |name: &str| -> Result<String, ConfigError> {
        let Some((_, Value::Str(v))) = m.iter().find(|(k, _)| k == name) else {
            return Err(err(format!("'{name}' is required and must be a string")));
        };
        if v.len() > MAX_USER_PREFIX_BYTES {
            return Err(err(format!(
                "'{name}' exceeds {MAX_USER_PREFIX_BYTES} bytes"
            )));
        }
        kv_fragment_is_acceptable(v).map_err(|why| err(format!("'{name}' {why}")))?;
        if !vault_path_is_safe(v) {
            return Err(err(format!(
                "'{name}' has a character outside [A-Za-z0-9._/-]"
            )));
        }
        Ok(v.clone())
    };
    let kv_mount = required("kv_mount")?;
    let user_prefix = required("user_prefix")?;
    // #240b: the deputy's Vault connection. Required — a deployment that
    // registers a provider needs the deputy to log in, and an absent block is
    // a refusal here rather than a first-request failure. Every key inside it
    // is enumerated: a `token` or a `secret_id` written here would be a
    // credential in configuration, and nothing may accept one silently.
    let Some((_, vault)) = m.iter().find(|(k, _)| k == "vault") else {
        return Err(err("'vault' is required (addr)"));
    };
    let Value::Map(vm) = vault else {
        return Err(err("'vault' must be a mapping"));
    };
    crate::reject_unknown_keys(&format!("{EGRESS_BOUNDS_FILE}/vault"), vm, &["addr"])?;
    let Some((_, Value::Str(addr))) = vm.iter().find(|(k, _)| k == "addr") else {
        return Err(err("'vault.addr' is required and must be a string"));
    };
    if addr.is_empty() || addr.chars().any(char::is_whitespace) {
        return Err(err(
            "'vault.addr' must be a non-empty URL without whitespace",
        ));
    }
    if addr.len() > MAX_USER_PREFIX_BYTES {
        return Err(err(format!(
            "'vault.addr' exceeds {MAX_USER_PREFIX_BYTES} bytes"
        )));
    }
    Ok(EgressBounds {
        kv_mount,
        user_prefix,
        vault_addr: addr.clone(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn doc2(mount: &str, prefix: &str) -> Value {
        doc2_vault(mount, prefix, Some("https://vault.example:8200"))
    }

    fn doc2_vault(mount: &str, prefix: &str, addr: Option<&str>) -> Value {
        let mut m = vec![
            ("kv_mount".into(), Value::Str(mount.into())),
            ("user_prefix".into(), Value::Str(prefix.into())),
        ];
        if let Some(a) = addr {
            m.push((
                "vault".into(),
                Value::Map(vec![("addr".to_string(), Value::Str(a.into()))]),
            ));
        }
        Value::Map(m)
    }

    fn with_vault(vm: Vec<(String, Value)>) -> Value {
        Value::Map(vec![
            ("kv_mount".into(), Value::Str("maknae-kv".into())),
            ("user_prefix".into(), Value::Str("maknae/users".into())),
            ("vault".into(), Value::Map(vm)),
        ])
    }

    #[test]
    fn the_vault_block_is_required_and_carries_only_addr() {
        let b = bounds_from_document(&doc2_vault(
            "maknae-kv",
            "maknae/users",
            Some("https://v:8200"),
        ))
        .unwrap();
        assert_eq!(b.vault_addr, "https://v:8200");
        let e = bounds_from_document(&doc2_vault("maknae-kv", "maknae/users", None)).unwrap_err();
        assert!(e.to_string().contains("'vault'"), "{e}");
        for bad in ["", " ", "https://v :8200"] {
            let e = bounds_from_document(&doc2_vault("maknae-kv", "maknae/users", Some(bad)))
                .unwrap_err();
            assert!(e.to_string().contains("'vault.addr'"), "{bad:?}: {e}");
        }
        let long_addr = format!("https://{}", "h".repeat(MAX_USER_PREFIX_BYTES - 8));
        assert!(
            bounds_from_document(&doc2_vault("maknae-kv", "maknae/users", Some(&long_addr)))
                .is_ok()
        );
        assert!(bounds_from_document(&doc2_vault(
            "maknae-kv",
            "maknae/users",
            Some(&format!("{long_addr}h"))
        ))
        .is_err());
        assert!(bounds_from_document(&Value::Map(vec![
            ("kv_mount".into(), Value::Str("maknae-kv".into())),
            ("user_prefix".into(), Value::Str("maknae/users".into())),
            ("vault".into(), Value::Str("https://v:8200".into())),
        ]))
        .is_err());
        let e = bounds_from_document(&with_vault(vec![
            ("addr".into(), Value::Str("https://v:8200".into())),
            ("token".into(), Value::Str("x".into())),
        ]))
        .unwrap_err();
        assert!(e.to_string().contains("'token'"), "{e}");
        assert!(bounds_from_document(&with_vault(vec![("addr".into(), Value::Int(1))])).is_err());
    }

    #[test]
    fn the_pre_switch_spellings_are_refused_by_name() {
        match bounds_from_document(&Value::Map(vec![
            ("kv_mount".into(), Value::Str("maknae-kv".into())),
            (
                "key_vault_path_prefix".into(),
                Value::Str("maknae/providers".into()),
            ),
            (
                "vault".into(),
                Value::Map(vec![("addr".into(), Value::Str("https://v:8200".into()))]),
            ),
        ])) {
            Err(ConfigError::UnknownKey { section, key }) => {
                assert_eq!(section, EGRESS_BOUNDS_FILE);
                assert_eq!(key, "key_vault_path_prefix");
            }
            other => panic!("expected UnknownKey key_vault_path_prefix, got {other:?}"),
        }
        match bounds_from_document(&with_vault(vec![
            ("addr".into(), Value::Str("https://v:8200".into())),
            ("approle_mount".into(), Value::Str("maknae-approle".into())),
        ])) {
            Err(ConfigError::UnknownKey { section, key }) => {
                assert_eq!(section, "egress-bounds.yaml/vault");
                assert_eq!(key, "approle_mount");
            }
            other => panic!("expected UnknownKey approle_mount, got {other:?}"),
        }
    }

    #[test]
    fn an_auth_mount_is_checked_for_shape_and_never_for_a_data_segment() {
        for (bad, want) in [
            ("", "is empty"),
            ("/approle", "must not start with '/'"),
            ("approle/", "must not end with '/'"),
            ("app role", "contains whitespace"),
            ("a//b", "empty interior"),
            ("a/../b", "'.' or '..'"),
            ("auth/maknae-approle", "starts with 'auth'"),
        ] {
            let why = mount_path_is_acceptable(bad).unwrap_err();
            assert!(why.contains(want), "{bad:?}: {why}");
        }
        assert_eq!(mount_path_is_acceptable("team/approle"), Ok(()));
        assert_eq!(mount_path_is_acceptable("data"), Ok(()));
        let long = "a".repeat(MAX_USER_PREFIX_BYTES);
        assert_eq!(mount_path_is_acceptable(&long), Ok(()));
        assert!(mount_path_is_acceptable(&format!("{long}a")).is_err());
    }

    #[test]
    fn vault_path_is_safe_admits_only_the_vault_path_alphabet() {
        assert!(vault_path_is_safe("maknae-kv/maknae/users_1/a.b"));
        for bad in ["", "a#b", "a?b", "a%2eb", "a b", "a\\b", "ä", "a;b"] {
            assert!(!vault_path_is_safe(bad), "{bad:?}");
        }
    }

    #[test]
    fn a_mount_or_prefix_outside_the_vault_path_alphabet_is_refused_by_name() {
        for bad in ["maknae#kv", "maknae?kv", "maknae%2ekv"] {
            let e = bounds_from_document(&doc2(bad, "maknae/users")).unwrap_err();
            assert!(
                e.to_string()
                    .contains("'kv_mount' has a character outside [A-Za-z0-9._/-]"),
                "{bad:?}: {e}"
            );
            let e = bounds_from_document(&doc2("maknae-kv", &format!("maknae/{bad}"))).unwrap_err();
            assert!(
                e.to_string()
                    .contains("'user_prefix' has a character outside [A-Za-z0-9._/-]"),
                "{bad:?}: {e}"
            );
        }
        for (mount, prefix, key) in [
            ("maknae kv", "maknae/users", "'kv_mount'"),
            ("maknae-kv", "maknae/us ers", "'user_prefix'"),
        ] {
            let e = bounds_from_document(&doc2(mount, prefix)).unwrap_err();
            assert!(
                e.to_string().contains(key) && e.to_string().contains("whitespace"),
                "{mount:?} {prefix:?}: {e}"
            );
        }
    }

    fn doc(prefix: &str) -> Value {
        Value::Map(vec![("user_prefix".into(), Value::Str(prefix.into()))])
    }

    /// THE containment control. A bare `starts_with` admits a sibling path
    /// whose name merely begins with the prefix, which would let a registry
    /// entry name a Vault path outside the deputy's grant.
    #[test]
    fn a_sibling_path_that_merely_starts_with_the_prefix_is_not_contained() {
        let p = "maknae/providers";
        assert!(path_is_within_prefix("maknae/providers/openai", p));
        assert!(!path_is_within_prefix(
            "secret/data/maknae/providers-evil/key",
            p
        ));
        // the prefix itself is not a document
        assert!(!path_is_within_prefix(p, p));
        // a trailing slash on the prefix behaves identically
        assert!(path_is_within_prefix(
            "maknae/providers/openai",
            "maknae/providers/"
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
        let p = "maknae/providers";
        assert!(!path_is_within_prefix("maknae/providers/", p));
        // and one character after the slash IS a document
        assert!(path_is_within_prefix("maknae/providers/a", p));
    }

    #[test]
    fn a_well_formed_document_parses() {
        assert_eq!(
            bounds_from_document(&doc2("maknae-kv", "maknae/providers")).unwrap(),
            EgressBounds {
                kv_mount: "maknae-kv".into(),
                user_prefix: "maknae/providers".into(),
                vault_addr: "https://vault.example:8200".into(),
            }
        );
    }

    #[test]
    fn the_mount_is_required_and_validated_like_the_prefix() {
        // absent
        assert!(bounds_from_document(&doc("maknae/providers")).is_err());
        // Each empty-segment POSITION has its own message, so a mutation of one
        // arm is observable. Asserted rather than merely `is_err()`, which a
        // single shared message would have made indistinguishable.
        for (bad, want) in [
            ("/maknae-kv", "must not start with '/'"),
            ("maknae-kv/", "must not end with '/'"),
            ("maknae//kv", "empty interior path segment"),
        ] {
            let e = bounds_from_document(&doc2(bad, "maknae/providers")).unwrap_err();
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
                bounds_from_document(&doc2(bad, "maknae/providers")).is_err(),
                "kv_mount {bad:?} must be refused"
            );
        }
        // a NESTED mount is legal in Vault (`-path=a/b`) and must be accepted
        assert!(bounds_from_document(&doc2("platform/maknae-kv", "maknae/providers")).is_ok());
    }

    /// THE HALF-MIGRATED CONFIG, and the reason this refusal exists rather than
    /// a silent compose. #307 shipped documentation whose prefix and path agreed
    /// with each other and disagreed with Vault's grant: the boot gate compares
    /// the two host-side values and NEVER the grant, so it booted clean and took
    /// a 403 at the credential read. The same class after #308 is a value still
    /// carrying the mount and `data/` — `maknae-kv/data/maknae/providers` — which
    /// would compose to `maknae-kv/data/maknae-kv/data/maknae/providers`. Refusing
    /// any `data` SEGMENT makes it a named boot refusal instead. The cost is
    /// stated: a secret path legitimately containing a `data` segment cannot be
    /// expressed, which is rare, and the migration error is not.
    #[test]
    fn a_prefix_still_carrying_the_mount_or_data_segment_is_refused_by_name() {
        for bad in [
            "maknae-kv/data/maknae/providers", // the old absolute value, pasted
            "data/maknae/providers",           // the mount stripped, `data/` left
            "llm/data/providers",              // a `data` segment anywhere
        ] {
            let e = bounds_from_document(&doc2("maknae-kv", bad)).unwrap_err();
            assert!(
                e.to_string().contains("data"),
                "prefix {bad:?} must be refused naming 'data', got: {e}"
            );
        }
        // And the mount itself must not carry one either.
        assert!(bounds_from_document(&doc2("maknae-kv/data", "maknae/providers")).is_err());
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
            bounds_from_document(&doc2(OK_MOUNT, &"a".repeat(MAX_USER_PREFIX_BYTES + 1))).is_err()
        );
        // AT the bound, accepted. Measured gap: `>` → `>=` survived because the
        // only length ever tested was MAX+1, where both operators refuse alike.
        assert!(bounds_from_document(&doc2(OK_MOUNT, &"a".repeat(MAX_USER_PREFIX_BYTES))).is_ok());
        // and the same bound applies to the mount, for the same reason
        assert!(bounds_from_document(&doc2(
            &"m".repeat(MAX_USER_PREFIX_BYTES + 1),
            "maknae/providers"
        ))
        .is_err());
        assert!(bounds_from_document(&doc2(
            &"m".repeat(MAX_USER_PREFIX_BYTES),
            "maknae/providers"
        ))
        .is_ok());
        // a non-string value for either field
        assert!(bounds_from_document(&Value::Map(vec![
            ("kv_mount".into(), Value::Str(OK_MOUNT.into())),
            ("user_prefix".into(), Value::Int(3)),
        ]))
        .is_err());
        assert!(bounds_from_document(&Value::Map(vec![
            ("kv_mount".into(), Value::Int(3)),
            ("user_prefix".into(), Value::Str("a/b".into())),
        ]))
        .is_err());
        // a document carrying ONLY the prefix is refused — the mount is not
        // optional and has no default, so an old file fails closed rather than
        // composing against a guessed mount.
        assert!(bounds_from_document(&doc("maknae/providers")).is_err());
        // an unknown key is refused BY NAME rather than ignored — asserted as
        // the name, not merely as `is_err()`, which is what this comment has
        // always claimed and never checked (#210 round-1 review).
        match bounds_from_document(&Value::Map(vec![
            ("kv_mount".into(), Value::Str(OK_MOUNT.into())),
            ("user_prefix".into(), Value::Str("a/b".into())),
            ("mystery".into(), Value::Bool(true)),
        ])) {
            Err(ConfigError::UnknownKey { section, key }) => {
                assert_eq!(section, "egress-bounds.yaml");
                assert_eq!(key, "mystery");
            }
            other => panic!("expected UnknownKey, got {other:?}"),
        }
    }
}
