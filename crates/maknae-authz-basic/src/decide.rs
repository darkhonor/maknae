//! The pure decision core (#85, spec §4/§5): (loaded policy, request) →
//! four-valued verdict. No I/O, no NSS, no clocks — deterministic w.r.t. its
//! inputs, which is what makes the full role × class matrix hermetically
//! testable and the golden vectors below the crate's contract.
//!
//! Total by construction: no `unwrap`/`expect`/panicking indexing — every
//! absent-or-wrong-typed input required at its point of use is
//! failed-to-evaluate → `Indeterminate` (ADR-0004 §3 matcher invariant,
//! discharged here per `maknae-security/tests/golden.rs`'s deferral), never a
//! silent non-match.

use crate::binding::{Resolution, ResolvedBindings};
use crate::role::Role;
use maknae_security::{AttrValue, Attributes, Obligation, Request as SecRequest, Verdict};

/// Subject attribute keys (spec §6, pinned for #77): `uid` is the
/// authenticated datum (ADR-0018); `name` carries the reserved runtime token,
/// stamped by the daemon door, never client-settable.
pub(crate) const SUBJECT_UID: &str = "uid";
pub(crate) const SUBJECT_NAME: &str = "name";
/// Resource attribute key for `acp.fs.*` (spec §4.4).
pub(crate) const RESOURCE_PATH: &str = "path";

/// One loaded policy snapshot: the parsed grammar + validated bindings.
pub(crate) struct LoadedPolicy {
    pub(crate) policy: maknae_config::AuthzPolicy,
    pub(crate) roles: ResolvedBindings,
}

/// The closed action-class vocabulary (spec §5).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Class {
    Liveness,
    Admin,
    AcpSession,
    AcpFs,
    AcpTerminal,
}

/// Exact-segment class match (spec §5): `a == c` or `a.starts_with(c + ".")`,
/// byte-wise. `liveness_bypass.exec` is NOT in `liveness` — the over-matching
/// `starts_with(c)` implementation is the pinned negative.
pub(crate) fn class_of(action: &str) -> Option<Class> {
    fn in_class(a: &str, c: &str) -> bool {
        a == c || (a.len() > c.len() && a.as_bytes()[c.len()] == b'.' && a.starts_with(c))
    }
    // Longest-prefix classes first so `acp.session.x` never tests bare `acp`.
    if in_class(action, "acp.session") {
        Some(Class::AcpSession)
    } else if in_class(action, "acp.fs") {
        Some(Class::AcpFs)
    } else if in_class(action, "acp.terminal") {
        Some(Class::AcpTerminal)
    } else if in_class(action, "liveness") {
        Some(Class::Liveness)
    } else if in_class(action, "admin") {
        Some(Class::Admin)
    } else {
        None
    }
}

/// The one obligation every `Permit` carries (spec §4.5, pinned literally:
/// ADR-0004 §5's non-removable `audit`; empty params — same-id/different-
/// params is an unrankable conflict under `merge_obligations`).
pub(crate) fn audit_obligation() -> Obligation {
    Obligation {
        id: "audit".into(),
        params: Attributes::new(),
    }
}

fn permit_with_audit() -> Verdict {
    Verdict::Permit {
        obligations: vec![audit_obligation()],
    }
}

/// The lexical canonical-form pre-gate (spec §4.4): absolute; no `.`/`..`
/// components; no empty segment after the leading `/` (no `//`, no trailing
/// `/`; bare `/` passes vacuously). Returns the offending component on
/// violation.
fn canonical_violation(path: &str) -> Option<&'static str> {
    if !path.starts_with('/') {
        return Some("not absolute");
    }
    if path == "/" {
        return None;
    }
    for seg in path[1..].split('/') {
        match seg {
            "" => return Some("empty segment ('//' or trailing '/')"),
            "." => return Some("'.' component"),
            ".." => return Some("'..' component"),
            _ => {}
        }
    }
    None
}

/// (loaded policy, principal, request) → verdict. Spec §4 steps 2–6.
pub(crate) fn decide_loaded(
    lp: &LoadedPolicy,
    principal: &maknae_config::Principal,
    req: &SecRequest,
) -> Verdict {
    // Step 2 — subject resolution, matcher invariant first: a PRESENT but
    // wrong-typed `name` or `uid` is failed-to-evaluate, never a fall-through.
    let name = match req.subject.0.get(SUBJECT_NAME) {
        None => None,
        Some(AttrValue::Str(s)) => Some(s.as_str()),
        Some(_) => return Verdict::Indeterminate,
    };
    let uid: Option<u32> = match req.subject.0.get(SUBJECT_UID) {
        None => None,
        Some(AttrValue::Int(i)) => match u32::try_from(*i) {
            Ok(u) => Some(u),
            Err(_) => return Verdict::Indeterminate, // out-of-range carriage
        },
        Some(_) => return Verdict::Indeterminate,
    };
    if name.is_none() && uid.is_none() {
        // Neither identity datum present: the subject cannot be evaluated.
        return Verdict::Indeterminate;
    }
    let role = match lp.roles.role_for(name, uid, principal.uid) {
        Resolution::Role(r) => r,
        Resolution::NoRole => return Verdict::NotApplicable,
    };

    // Step 3 — role gates over the closed class vocabulary.
    let class = class_of(&req.action.0);
    match role {
        Role::Adversary => Verdict::Deny {
            reason: "subject contained: role=adversary".into(),
        },
        Role::Guest | Role::User => match class {
            Some(Class::Liveness) => permit_with_audit(),
            _ => Verdict::NotApplicable,
        },
        Role::Admin => match class {
            Some(Class::Admin) | Some(Class::Liveness) => permit_with_audit(),
            Some(Class::AcpFs) => decide_fs(lp, req),
            Some(Class::AcpSession) | Some(Class::AcpTerminal) | None => Verdict::NotApplicable,
        },
    }
}

/// Step 4 — the capability grammar, admin-only, `acp.fs.*`-only (spec §4.4).
fn decide_fs(lp: &LoadedPolicy, req: &SecRequest) -> Verdict {
    let path = match req.resource.0.get(RESOURCE_PATH) {
        Some(AttrValue::Str(s)) => s.as_str(),
        // Required at THIS point of use: absent or wrong-typed → Indeterminate.
        _ => return Verdict::Indeterminate,
    };
    if let Some(offense) = canonical_violation(path) {
        // A non-canonical path is a matcher bypass, refused BEFORE matching —
        // never passed through, never NotApplicable (spec §4.4).
        return Verdict::Deny {
            reason: format!("non-canonical resource path ({offense})"),
        };
    }
    match lp
        .policy
        .evaluate3(&maknae_config::Request::Read(std::path::Path::new(path)))
    {
        maknae_config::Match3::DenyMatch { source } => Verdict::Deny {
            // Audit-only provenance (spec §4.4): this reason reaches the
            // audit record; #77's wiring must never copy it onto the wire.
            reason: format!("denied by policy entry {source}"),
        },
        maknae_config::Match3::AllowMatch => permit_with_audit(),
        maknae_config::Match3::NoMatch => Verdict::NotApplicable,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::binding::{resolve, UidMap};
    use maknae_security::{Action, Context, Resource, Subject};
    use std::collections::BTreeMap;

    const OPERATOR_UID: u32 = 501;
    const OTHER_UID: u32 = 666;

    fn principal() -> maknae_config::Principal {
        maknae_config::Principal {
            name: "operator".into(),
            uid: OPERATOR_UID,
            home: "/home/operator".into(),
        }
    }

    fn shipped_policy() -> maknae_config::AuthzPolicy {
        maknae_config::parse_authz(
            "schema_version: 1\npermissions:\n  allow:\n    - \"Read(~/**)\"\n  deny:\n    - \"Read(~/.ssh/**)\"\n",
            Some(std::path::Path::new("/home/operator")),
        )
        .unwrap()
    }

    /// Fixture bindings over host-independent identities only (issue #138
    /// lesson): the reserved `agent` token plus uids supplied via the map.
    fn lp_with(bindings: Option<&[(&str, &[&str])]>, uid_map: &[(&str, u32)]) -> LoadedPolicy {
        let b: Option<BTreeMap<String, Vec<String>>> = bindings.map(|pairs| {
            pairs
                .iter()
                .map(|(k, v)| (k.to_string(), v.iter().map(|s| s.to_string()).collect()))
                .collect()
        });
        let lookup: UidMap = uid_map.iter().map(|(n, u)| (n.to_string(), *u)).collect();
        LoadedPolicy {
            policy: shipped_policy(),
            roles: resolve(&b, &lookup).unwrap(),
        }
    }

    fn request(
        name: Option<&str>,
        uid: Option<i64>,
        action: &str,
        path: Option<&str>,
    ) -> SecRequest {
        let mut s = Attributes::new();
        if let Some(n) = name {
            s.insert(SUBJECT_NAME, AttrValue::Str(n.into()));
        }
        if let Some(u) = uid {
            s.insert(SUBJECT_UID, AttrValue::Int(u));
        }
        let mut r = Attributes::new();
        if let Some(p) = path {
            r.insert(RESOURCE_PATH, AttrValue::Str(p.into()));
        }
        SecRequest {
            subject: Subject(s),
            resource: Resource(r),
            action: Action(action.into()),
            context: Context(Attributes::new()),
        }
    }

    const ALL_ACTIONS: &[&str] = &[
        "liveness.ping",
        "admin.whoami",
        "acp.session.prompt",
        "acp.fs.read",
        "acp.terminal.exec",
        "unknown.thing",
    ];

    // ---- the golden matrix (spec §5, authoritative) ----

    #[test]
    fn adversary_denies_everything_including_liveness() {
        let lp = lp_with(
            Some(&[("adversary", &["mallory"])]),
            &[("mallory", OTHER_UID)],
        );
        for action in ALL_ACTIONS {
            let v = decide_loaded(
                &lp,
                &principal(),
                &request(None, Some(OTHER_UID as i64), action, Some("/etc/hosts")),
            );
            assert!(
                matches!(v, Verdict::Deny { ref reason } if reason.contains("role=adversary")),
                "adversary must be denied {action}: {v:?}"
            );
        }
    }

    #[test]
    fn guest_and_user_permit_only_liveness() {
        for (role_key, ident, uid) in [("guest", "guestic", 700_u32), ("user", "usery", 701)] {
            let lp = lp_with(Some(&[(role_key, &[ident])]), &[(ident, uid)]);
            for action in ALL_ACTIONS {
                let v = decide_loaded(
                    &lp,
                    &principal(),
                    &request(None, Some(uid as i64), action, Some("/home/operator/x")),
                );
                if *action == "liveness.ping" {
                    assert!(
                        matches!(v, Verdict::Permit { .. }),
                        "{role_key} {action}: {v:?}"
                    );
                } else {
                    assert_eq!(v, Verdict::NotApplicable, "{role_key} {action}");
                }
            }
        }
    }

    #[test]
    fn user_not_applicable_where_admin_is_permitted_on_acp_fs() {
        // The C2 discriminator (spec §7): the untrusted runtime's default role
        // never inherits the capability grammar.
        let lp = lp_with(
            Some(&[("admin", &["alex"]), ("user", &["usery"])]),
            &[("alex", OPERATOR_UID), ("usery", 701)],
        );
        let action = "acp.fs.read";
        let path = Some("/home/operator/notes.txt");
        let admin_v = decide_loaded(
            &lp,
            &principal(),
            &request(None, Some(OPERATOR_UID as i64), action, path),
        );
        let user_v = decide_loaded(&lp, &principal(), &request(None, Some(701), action, path));
        assert!(matches!(admin_v, Verdict::Permit { .. }), "{admin_v:?}");
        assert_eq!(user_v, Verdict::NotApplicable);
    }

    #[test]
    fn admin_grammar_deny_overrides_and_carries_source() {
        let lp = lp_with(None, &[]);
        let v = decide_loaded(
            &lp,
            &principal(),
            &request(
                None,
                Some(OPERATOR_UID as i64),
                "acp.fs.read",
                Some("/home/operator/.ssh/id_rsa"),
            ),
        );
        assert!(
            matches!(v, Verdict::Deny { ref reason } if reason.contains("Read(~/.ssh/**)")),
            "{v:?}"
        );
    }

    #[test]
    fn admin_dotdot_evasion_is_denied_by_the_pregate_not_allowed_by_the_glob() {
        // The C1 discriminator (spec §4.4/§7), exercised as ADMIN — any other
        // role short-circuits at step 3 and would pass for the wrong reason.
        let lp = lp_with(None, &[]);
        let v = decide_loaded(
            &lp,
            &principal(),
            &request(
                None,
                Some(OPERATOR_UID as i64),
                "acp.fs.read",
                Some("/home/operator/docs/../.ssh/id_rsa"),
            ),
        );
        assert!(
            matches!(v, Verdict::Deny { ref reason } if reason.contains("..")),
            "the pre-gate, not the glob, must decide: {v:?}"
        );
    }

    #[test]
    fn admin_acp_fs_nomatch_is_not_applicable_and_bare_root_passes_pregate() {
        let lp = lp_with(None, &[]);
        for path in ["/etc/hosts", "/"] {
            let v = decide_loaded(
                &lp,
                &principal(),
                &request(None, Some(OPERATOR_UID as i64), "acp.fs.read", Some(path)),
            );
            assert_eq!(v, Verdict::NotApplicable, "{path}");
        }
    }

    #[test]
    fn admin_reserved_classes_are_not_applicable() {
        let lp = lp_with(None, &[]);
        for action in ["acp.session.prompt", "acp.terminal.exec", "unknown.thing"] {
            let v = decide_loaded(
                &lp,
                &principal(),
                &request(None, Some(OPERATOR_UID as i64), action, None),
            );
            assert_eq!(v, Verdict::NotApplicable, "{action}");
        }
    }

    // ---- matcher invariant golden vectors (spec §4.2, golden.rs deferral) ----

    #[test]
    fn missing_identity_is_indeterminate_distinct_from_unbound() {
        let lp = lp_with(None, &[]);
        // Missing BOTH identity attrs → failed-to-evaluate.
        let v = decide_loaded(
            &lp,
            &principal(),
            &request(None, None, "liveness.ping", None),
        );
        assert_eq!(v, Verdict::Indeterminate);
        // Present-but-unbound uid → NotApplicable (defaults: not the principal).
        let v = decide_loaded(
            &lp,
            &principal(),
            &request(None, Some(999), "liveness.ping", None),
        );
        assert_eq!(v, Verdict::NotApplicable);
    }

    #[test]
    fn wrong_typed_subject_name_is_indeterminate_never_uid_fallthrough() {
        // Spec §3b: a wrong-typed `name` must NOT fall through to uid — on a
        // single-user host that fall-through would resolve the agent to admin.
        let lp = lp_with(None, &[]);
        let mut s = Attributes::new();
        s.insert(SUBJECT_NAME, AttrValue::Int(1));
        s.insert(SUBJECT_UID, AttrValue::Int(OPERATOR_UID as i64));
        let req = SecRequest {
            subject: Subject(s),
            resource: Resource(Attributes::new()),
            action: Action("liveness.ping".into()),
            context: Context(Attributes::new()),
        };
        assert_eq!(
            decide_loaded(&lp, &principal(), &req),
            Verdict::Indeterminate
        );
    }

    #[test]
    fn wrong_typed_or_out_of_range_uid_is_indeterminate() {
        let lp = lp_with(None, &[]);
        let v = decide_loaded(
            &lp,
            &principal(),
            &request(None, Some(-1), "liveness.ping", None),
        );
        assert_eq!(
            v,
            Verdict::Indeterminate,
            "negative uid is out-of-range carriage"
        );
        let mut s = Attributes::new();
        s.insert(SUBJECT_UID, AttrValue::Str("501".into()));
        let req = SecRequest {
            subject: Subject(s),
            resource: Resource(Attributes::new()),
            action: Action("liveness.ping".into()),
            context: Context(Attributes::new()),
        };
        assert_eq!(
            decide_loaded(&lp, &principal(), &req),
            Verdict::Indeterminate
        );
    }

    #[test]
    fn admin_missing_or_wrong_typed_path_is_indeterminate_at_the_grammar() {
        let lp = lp_with(None, &[]);
        let v = decide_loaded(
            &lp,
            &principal(),
            &request(None, Some(OPERATOR_UID as i64), "acp.fs.read", None),
        );
        assert_eq!(v, Verdict::Indeterminate);
        // But for a role that never reaches the grammar, absent path is
        // NotApplicable at step 3 (spec R3 should-fix: the invariant fires at
        // the point of use, not globally).
        let lp2 = lp_with(Some(&[("guest", &["g"])]), &[("g", 700)]);
        let v2 = decide_loaded(
            &lp2,
            &principal(),
            &request(None, Some(700), "acp.fs.read", None),
        );
        assert_eq!(v2, Verdict::NotApplicable);
    }

    // ---- class-match rule pins (spec §5) ----

    #[test]
    fn liveness_bypass_prefix_is_not_liveness() {
        assert_eq!(class_of("liveness_bypass.exec"), None);
        assert_eq!(class_of("liveness.ping"), Some(Class::Liveness));
        assert_eq!(class_of("liveness"), Some(Class::Liveness));
        assert_eq!(class_of("admindeed"), None);
        assert_eq!(class_of("acp.session"), Some(Class::AcpSession));
        assert_eq!(class_of("acp.sessionX"), None);
        assert_eq!(class_of("acp.fs.read"), Some(Class::AcpFs));
        assert_eq!(class_of("acp.terminal.exec"), Some(Class::AcpTerminal));
        assert_eq!(class_of(""), None);
    }

    #[test]
    fn every_permit_carries_exactly_the_audit_obligation() {
        let lp = lp_with(None, &[]);
        for (action, path) in [
            ("liveness.ping", None),
            ("admin.whoami", None),
            ("acp.fs.read", Some("/home/operator/x")),
        ] {
            let v = decide_loaded(
                &lp,
                &principal(),
                &request(None, Some(OPERATOR_UID as i64), action, path),
            );
            match v {
                Verdict::Permit { obligations } => {
                    assert_eq!(obligations, vec![audit_obligation()], "{action}")
                }
                other => panic!("{action} expected Permit, got {other:?}"),
            }
        }
    }

    #[test]
    fn agent_under_operator_uid_is_user_never_admin() {
        // Single-user-host hole, closed (spec §3b) — end to end through decide.
        let lp = lp_with(None, &[]);
        let v = decide_loaded(
            &lp,
            &principal(),
            &request(
                Some(AGENT_SUBJECT),
                Some(OPERATOR_UID as i64),
                "acp.fs.read",
                Some("/home/operator/x"),
            ),
        );
        assert_eq!(
            v,
            Verdict::NotApplicable,
            "agent must not inherit admin's grammar"
        );
    }

    #[test]
    fn canonical_pregate_rejections_name_the_offense() {
        assert_eq!(canonical_violation("relative/x"), Some("not absolute"));
        assert!(canonical_violation("/a//b").unwrap().contains("empty"));
        assert!(canonical_violation("/a/b/").unwrap().contains("empty"));
        assert!(canonical_violation("/a/./b").unwrap().contains("'.'"));
        assert!(canonical_violation("/a/../b").unwrap().contains("'..'"));
        assert_eq!(canonical_violation("/"), None);
        assert_eq!(canonical_violation("/a/b"), None);
    }
}
