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
/// Resource attribute key for `fs.*` (spec §4.4).
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
    Session,
    Fs,
    Terminal,
    Mcp,
    Kernel,
}

/// Exact-segment class match (spec §5): `a == c` or `a.starts_with(c + ".")`,
/// byte-wise. `liveness_bypass.exec` is NOT in `liveness` — the over-matching
/// `starts_with(c)` implementation is the pinned negative.
pub(crate) fn class_of(action: &str) -> Option<Class> {
    fn in_class(a: &str, c: &str) -> bool {
        a == c || (a.len() > c.len() && a.as_bytes()[c.len()] == b'.' && a.starts_with(c))
    }
    // Flat namespace after the `acp.` rename: no class name is a prefix of
    // another, so ordering is no longer load-bearing. Kept explicit for reading.
    if in_class(action, "liveness") {
        Some(Class::Liveness)
    } else if in_class(action, "admin") {
        Some(Class::Admin)
    } else if in_class(action, "session") {
        Some(Class::Session)
    } else if in_class(action, "fs") {
        Some(Class::Fs)
    } else if in_class(action, "terminal") {
        Some(Class::Terminal)
    } else if in_class(action, "mcp") {
        Some(Class::Mcp)
    } else if in_class(action, "kernel") {
        Some(Class::Kernel)
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

/// What OS discretionary access control says about a request naming an object.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum OsDacGate {
    /// The OS permits this subject this object. The policy decision proceeds.
    Satisfied,
    /// Refuse, with an audit-only reason distinguishing WHY from a policy denial.
    Deny(&'static str),
    /// OS DAC is not the applicable control on this lane. The operand contributes
    /// nothing on this ground and the rest of the policy carries the decision.
    NotApplicable,
    /// Present but wrong-typed — failed-to-evaluate, never a fall-through to absent.
    Indeterminate,
}

/// The OS-DAC gate over a request that names an object (ADR-0009 decision 8).
///
/// **Code-defined and unconfigurable.** No `authz.yaml` key enables, disables, or
/// overrides it — the same class as `Role::Adversary`'s deny-all. Operator ruling:
/// *"DAC permissions aren't something I should have to write a policy configuration
/// for. Those are managed by the OS."*
///
/// The LANE is read first and it is load-bearing: it is the only thing separating
/// *absent means unknown, so deny* (local — the OS could have been asked) from
/// *absent means not applicable, so abstain* (remote — there is no uid, process, or
/// descriptor on this host to ask about). Collapse the two and either every remote
/// read denies the day the gateway lands, or every local read fails open.
pub(crate) fn os_dac_gate(req: &SecRequest) -> OsDacGate {
    let lane = match req.context.0.get(maknae_security::CONTEXT_DAC_LANE) {
        Some(AttrValue::Str(s)) => s.as_str(),
        // Absent, or present-but-wrong-typed. Either way the two meanings of a
        // missing answer cannot be told apart, so neither may be assumed.
        _ => return OsDacGate::Deny("dac lane absent"),
    };
    if lane == maknae_security::Lane::Remote.as_str() {
        return OsDacGate::NotApplicable;
    }
    if lane != maknae_security::Lane::Local.as_str() {
        return OsDacGate::Deny("dac lane unrecognised");
    }
    match req.resource.0.get(maknae_security::RESOURCE_OS_ACCESSIBLE) {
        Some(AttrValue::Bool(true)) => OsDacGate::Satisfied,
        Some(AttrValue::Bool(false)) => OsDacGate::Deny("os dac refuses this subject this object"),
        Some(_) => OsDacGate::Indeterminate,
        // ADR-0008 decision 4: no operand may fail open. On this lane the OS could
        // have been asked, so silence is unknown — and unknown is never a permit.
        None => OsDacGate::Deny("os accessibility unknown"),
    }
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
            Some(Class::Liveness) => permit_with_audit(),
            // Keyed to the ONE built admin term. A class-granular permit here
            // would grant admin.contain / admin.credential.broker /
            // admin.policy.reload off an arm that keys nothing — the outcome
            // #67's spec D3 names as the thing that must not land. Individual
            // decidability for the rest is D3's implementation obligation.
            Some(Class::Admin) if req.action.0 == "admin.whoami" => permit_with_audit(),
            Some(Class::Admin) => Verdict::NotApplicable,
            // Keyed like the admin arm above, and for the same reason. Without
            // it, safety rests on a remote `if let Verb::Read` in another crate:
            // `decide_fs` builds `Request::Read(path)` for ANY `fs.*` action, so
            // an unbuilt fs term reaching it with a path would match `Read(~/**)`.
            // Keying here makes the property provable in the file that decides,
            // and makes unbuilt fs terms abstain (NotApplicable) rather than
            // report Indeterminate — which is a PDP-malfunction signal, not a
            // "this term has no behaviour yet" signal.
            // OS DAC first, and ONLY for terms that name an object: `liveness.ping`
            // and `admin.whoami` name none, so discretionary access to an object is
            // not a question they raise. `-basic` IS the DAC layer (ADR-0020 §5), and
            // a DAC decision that ignores the OS's own discretionary controls is not
            // a complete DAC decision (ADR-0009).
            Some(Class::Fs) if req.action.0 == "fs.read" => match os_dac_gate(req) {
                // Satisfied: the OS permits it, so the policy decides.
                // NotApplicable: OS DAC is not this lane's control, so likewise.
                OsDacGate::Satisfied | OsDacGate::NotApplicable => decide_fs(lp, req),
                OsDacGate::Deny(why) => Verdict::Deny {
                    reason: format!("os dac: {why}"),
                },
                OsDacGate::Indeterminate => Verdict::Indeterminate,
            },
            Some(Class::Fs) => Verdict::NotApplicable,
            Some(Class::Session)
            | Some(Class::Terminal)
            | Some(Class::Mcp)
            | Some(Class::Kernel)
            | None => Verdict::NotApplicable,
        },
    }
}

/// Step 4 — the capability grammar, admin-only, `fs.*`-only (spec §4.4).
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
    use crate::binding::{resolve, UidMap, AGENT_SUBJECT};
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
        // These vectors exercise the GRAMMAR, the globs and the role gates -- not OS
        // DAC -- so give them a satisfied gate and each keeps testing the one thing it
        // names. Unconditional, not path-keyed: the missing-path vector asserts an
        // Indeterminate from the GRAMMAR, and it can only reach the grammar if the
        // gate ahead of it is satisfied. `read_req` drives the gate itself.
        r.insert(
            maknae_security::RESOURCE_OS_ACCESSIBLE,
            AttrValue::Bool(true),
        );
        let mut c = Attributes::new();
        c.insert(
            maknae_security::CONTEXT_DAC_LANE,
            AttrValue::Str(maknae_security::Lane::Local.as_str().into()),
        );
        SecRequest {
            subject: Subject(s),
            resource: Resource(r),
            action: Action(action.into()),
            context: Context(c),
        }
    }

    /// Build a read request with an explicit lane and OS-DAC answer.
    fn read_req(lane: Option<&str>, accessible: Option<AttrValue>) -> SecRequest {
        let mut r = request(None, Some(501), "fs.read", Some("/home/operator/x"));
        // request() stamps a satisfied gate for the grammar vectors; these tests own
        // the gate's inputs outright, so start from a clean slate.
        r.resource.0 = {
            let mut fresh = Attributes::new();
            fresh.insert(RESOURCE_PATH, AttrValue::Str("/home/operator/x".into()));
            fresh
        };
        let mut c = Attributes::new();
        if let Some(l) = lane {
            c.insert(maknae_security::CONTEXT_DAC_LANE, AttrValue::Str(l.into()));
        }
        if let Some(a) = accessible {
            r.resource
                .0
                .insert(maknae_security::RESOURCE_OS_ACCESSIBLE, a);
        }
        r.context = Context(c);
        r
    }

    #[test]
    fn local_with_os_access_satisfies_the_gate() {
        assert!(matches!(
            os_dac_gate(&read_req(Some("local"), Some(AttrValue::Bool(true)))),
            OsDacGate::Satisfied
        ));
    }

    /// The defect #186 was filed for: the OS refuses this subject this object, and
    /// the daemon must refuse too or it is a path around the OS.
    #[test]
    fn local_without_os_access_denies() {
        assert!(matches!(
            os_dac_gate(&read_req(Some("local"), Some(AttrValue::Bool(false)))),
            OsDacGate::Deny(_)
        ));
    }

    /// ADR-0008 decision 4 applied: an operand that permits an object whose OS
    /// accessibility it never evaluated is deciding on input it did not evaluate.
    /// On the LOCAL lane the OS could have been asked, so silence is UNKNOWN.
    #[test]
    fn local_with_no_answer_denies_because_unknown_is_never_permit() {
        assert!(matches!(
            os_dac_gate(&read_req(Some("local"), None)),
            OsDacGate::Deny(_)
        ));
    }

    /// NOT the same as unknown, and the distinction is the whole point of the lane:
    /// a remote subject has no uid, process, or descriptor on this host (ADR-0006
    /// D5/D7), so there is nothing to ask. The operand abstains and the rest of the
    /// policy carries the decision. Collapse this into Deny and the remote lane can
    /// never read anything the day the gateway lands.
    #[test]
    fn remote_is_not_applicable_because_there_is_no_uid_to_ask_about() {
        assert!(matches!(
            os_dac_gate(&read_req(Some("remote"), None)),
            OsDacGate::NotApplicable
        ));
    }

    /// The lane is the ONLY thing separating "absent means Deny" from "absent means
    /// abstain", so an absent or unrecognised lane cannot be treated as either.
    #[test]
    fn an_absent_or_unrecognised_lane_denies() {
        assert!(matches!(
            os_dac_gate(&read_req(None, None)),
            OsDacGate::Deny(_)
        ));
        assert!(matches!(
            os_dac_gate(&read_req(Some("locaI"), Some(AttrValue::Bool(true)))),
            OsDacGate::Deny(_)
        ));
    }

    /// The crate's matcher invariant, applied here too: a PRESENT but wrong-typed
    /// value is failed-to-evaluate, never a fall-through to "absent".
    #[test]
    fn a_wrong_typed_answer_is_indeterminate_never_a_fall_through() {
        assert!(matches!(
            os_dac_gate(&read_req(
                Some("local"),
                Some(AttrValue::Str("true".into()))
            )),
            OsDacGate::Indeterminate
        ));
        assert!(matches!(
            os_dac_gate(&read_req(Some("local"), Some(AttrValue::Int(1)))),
            OsDacGate::Indeterminate
        ));
    }

    const ALL_ACTIONS: &[&str] = &[
        "liveness.ping",
        "admin.whoami",
        "session.prompt",
        "fs.read",
        "terminal.create",
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
    fn user_not_applicable_where_admin_is_permitted_on_fs() {
        // The C2 discriminator (spec §7): the untrusted runtime's default role
        // never inherits the capability grammar.
        let lp = lp_with(
            Some(&[("admin", &["alex"]), ("user", &["usery"])]),
            &[("alex", OPERATOR_UID), ("usery", 701)],
        );
        let action = "fs.read";
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
                "fs.read",
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
                "fs.read",
                Some("/home/operator/docs/../.ssh/id_rsa"),
            ),
        );
        assert!(
            matches!(v, Verdict::Deny { ref reason } if reason.contains("..")),
            "the pre-gate, not the glob, must decide: {v:?}"
        );
    }

    #[test]
    fn admin_fs_nomatch_is_not_applicable_and_bare_root_passes_pregate() {
        let lp = lp_with(None, &[]);
        for path in ["/etc/hosts", "/"] {
            let v = decide_loaded(
                &lp,
                &principal(),
                &request(None, Some(OPERATOR_UID as i64), "fs.read", Some(path)),
            );
            assert_eq!(v, Verdict::NotApplicable, "{path}");
        }
    }

    #[test]
    fn admin_reserved_classes_are_not_applicable() {
        let lp = lp_with(None, &[]);
        for action in ["session.prompt", "terminal.create", "unknown.thing"] {
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
            &request(None, Some(OPERATOR_UID as i64), "fs.read", None),
        );
        assert_eq!(v, Verdict::Indeterminate);
        // But for a role that never reaches the grammar, absent path is
        // NotApplicable at step 3 (spec R3 should-fix: the invariant fires at
        // the point of use, not globally).
        let lp2 = lp_with(Some(&[("guest", &["g"])]), &[("g", 700)]);
        let v2 = decide_loaded(
            &lp2,
            &principal(),
            &request(None, Some(700), "fs.read", None),
        );
        assert_eq!(v2, Verdict::NotApplicable);
    }

    // ---- class-match rule pins (spec §5) ----

    /// The admin class is NOT a blanket grant. A class-granular permit here
    /// would grant every future admin term — containment, credential
    /// brokering, policy reload — off an arm that keys nothing.
    #[test]
    fn admin_class_permits_only_whoami() {
        let lp = lp_with(None, &[]); // shipped default: enrolled uid → admin
        let req = |a: &str| request(None, Some(OPERATOR_UID as i64), a, None);
        assert!(
            matches!(
                decide_loaded(&lp, &principal(), &req("admin.whoami")),
                Verdict::Permit { .. }
            ),
            "the one built admin term must still permit"
        );
        for action in [
            "admin.status",
            "admin.contain",
            "admin.release",
            "admin.credential.broker",
            "admin.policy.reload",
            "admin.subject.bind",
        ] {
            assert_eq!(
                decide_loaded(&lp, &principal(), &req(action)),
                Verdict::NotApplicable,
                "{action} must NOT permit off the admin class arm"
            );
        }
    }

    /// Each new class RESOLVES (so this cannot pass merely because `class_of`
    /// returns None, as it would have before the rename) and ABSTAINS. Adding
    /// a permissive arm for any of them turns this red.
    /// GOLDEN MATRIX (#162 step 0) — 4 roles x 8 (action, path) columns, written
    /// BEFORE the action-grant surface exists and never edited after.
    ///
    /// Its whole value is that it predates the change: every cell here must be
    /// byte-identical once `roles:` lands, because this fixture is `lp_with`,
    /// which hard-wires `shipped_policy()` — and that has no `roles:` key, so
    /// the grant map stays empty and the three grant-sensitive terms keep
    /// answering `NotApplicable`. The grant path is asserted separately, against
    /// its own fixture. **If you find yourself editing a cell below, stop.**
    ///
    /// Full `Verdict` equality, never `matches!`: the variant alone collapses
    /// adversary-deny, policy-deny and OS-DAC deny into one cell, and a pin that
    /// cannot tell them apart cannot detect the regression it exists for.
    #[test]
    fn golden_matrix_pins_every_role_against_every_class() {
        let lp = lp_with(
            Some(&[
                ("admin", &["alex"][..]),
                ("user", &["ursula"][..]),
                ("guest", &["gwen"][..]),
                ("adversary", &["adam"][..]),
            ]),
            // Distinct names AND distinct uids: `resolve` refuses a repeated name,
            // and `by_uid` is uid-keyed, so a shared uid would silently overwrite.
            &[
                ("alex", 1001),
                ("ursula", 1002),
                ("gwen", 1003),
                ("adam", 1004),
            ],
        );

        let permit = || Verdict::Permit {
            obligations: vec![audit_obligation()],
        };
        let contained = || Verdict::Deny {
            reason: "subject contained: role=adversary".into(),
        };
        let policy_deny = || Verdict::Deny {
            reason: "denied by policy entry Read(~/.ssh/**)".into(),
        };
        let na = || Verdict::NotApplicable;

        // (action, path) x (admin 1001, user 1002, guest 1003, adversary 1004)
        let matrix: &[(&str, Option<&str>, Verdict, Verdict, Verdict, Verdict)] = &[
            (
                "liveness.ping",
                None,
                permit(),
                permit(),
                permit(),
                contained(),
            ),
            ("admin.whoami", None, permit(), na(), na(), contained()),
            ("admin.status", None, na(), na(), na(), contained()),
            ("admin.config.show", None, na(), na(), na(), contained()),
            ("admin.subject.list", None, na(), na(), na(), contained()),
            (
                "fs.read",
                Some("/home/operator/x"),
                permit(),
                na(),
                na(),
                contained(),
            ),
            (
                "fs.read",
                Some("/home/operator/.ssh/k"),
                policy_deny(),
                na(),
                na(),
                contained(),
            ),
            ("unknown.thing", None, na(), na(), na(), contained()),
        ];

        for (action, path, adm, usr, gst, adv) in matrix {
            for (uid, role, expected) in [
                (1001i64, "admin", adm),
                (1002, "user", usr),
                (1003, "guest", gst),
                (1004, "adversary", adv),
            ] {
                let req = request(None, Some(uid), action, *path);
                assert_eq!(
                    &decide_loaded(&lp, &principal(), &req),
                    expected,
                    "role={role} action={action} path={path:?}"
                );
            }
        }
    }

    #[test]
    fn every_new_class_resolves_and_abstains() {
        let lp = lp_with(None, &[]);
        for (action, expect) in [
            ("session.prompt", Class::Session),
            ("terminal.create", Class::Terminal),
            ("mcp.tool.call", Class::Mcp),
            ("fs.write", Class::Fs),
            ("fs.delete", Class::Fs),
            ("kernel.contain", Class::Kernel),
        ] {
            assert_eq!(class_of(action), Some(expect), "{action} must resolve");
            assert_eq!(
                decide_loaded(
                    &lp,
                    &principal(),
                    &request(
                        None,
                        Some(OPERATOR_UID as i64),
                        action,
                        Some("/home/operator/x")
                    ),
                ),
                Verdict::NotApplicable,
                "{action} must abstain"
            );
        }
    }

    /// The old prefix is GONE, not aliased — a stale caller resolves to no
    /// class and is denied, rather than silently hitting the fs grammar.
    #[test]
    fn the_acp_prefix_no_longer_resolves() {
        for stale in ["acp.fs.read", "acp.session.prompt", "acp.terminal.exec"] {
            assert_eq!(class_of(stale), None, "{stale} must not resolve");
        }
    }

    #[test]
    fn liveness_bypass_prefix_is_not_liveness() {
        assert_eq!(class_of("liveness_bypass.exec"), None);
        assert_eq!(class_of("liveness.ping"), Some(Class::Liveness));
        assert_eq!(class_of("liveness"), Some(Class::Liveness));
        assert_eq!(class_of("admindeed"), None);
        assert_eq!(class_of("session"), Some(Class::Session));
        assert_eq!(class_of("sessionX"), None);
        assert_eq!(class_of("fs.read"), Some(Class::Fs));
        assert_eq!(class_of("terminal.create"), Some(Class::Terminal));
        assert_eq!(class_of(""), None);
    }

    #[test]
    fn every_permit_carries_exactly_the_audit_obligation() {
        let lp = lp_with(None, &[]);
        for (action, path) in [
            ("liveness.ping", None),
            ("admin.whoami", None),
            ("fs.read", Some("/home/operator/x")),
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
                "fs.read",
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
