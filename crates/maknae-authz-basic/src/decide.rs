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

use crate::binding::{Resolution, Roles};
use crate::role::Role;
use maknae_security::{AttrValue, Attributes, Obligation, Request as SecRequest, Verdict};

/// Subject attribute key (spec §6, pinned for #77): `uid`, the authenticated
/// datum (ADR-0018), and since #276 the ONLY one. A sibling `name` key
/// carried a reserved runtime token; ADR-0024 decision 3 struck it, so there
/// is no second identity datum and no fall-back between them.
pub(crate) const SUBJECT_UID: &str = "uid";
/// Resource attribute key for `fs.*` (spec §4.4).
pub(crate) const RESOURCE_PATH: &str = "path";
/// Resource attribute carrying the resolved egress destination of a
/// `session.prompt` (#172): `provider:<name>` from the admitted provider choice.
/// Set by the kernel, never the client; the arm refuses it absent.
pub(crate) const RESOURCE_DESTINATION: &str = "destination";
pub(crate) const RESOURCE_MODEL: &str = "model";

/// One loaded policy snapshot: the parsed grammar + validated bindings.
pub(crate) struct LoadedPolicy {
    pub(crate) policy: maknae_config::AuthzPolicy,
    pub(crate) roles: Roles,
    pub(crate) action_grants: ActionGrants,
    pub(crate) destinations: DestinationGrants,
    pub(crate) subjects: SubjectGrants,
    pub(crate) agents: AgentUids,
    pub(crate) taskers: AgentTaskers,
}

#[derive(Clone, Debug, PartialEq, Eq, Default)]
pub(crate) struct AgentUids(pub(crate) std::collections::BTreeMap<u32, String>);

impl AgentUids {
    pub(crate) fn get(&self, uid: u32) -> Option<&str> {
        self.0.get(&uid).map(String::as_str)
    }
}

/// Actions an enrolled agent holds only when its own `policy.yaml` grants them (R-S).
const AGENT_DEFAULT_DENIED: [&str; 1] = ["session.new"];

/// Each enrolled agent's `taskers:` resolved to uids; `None` where its policy lists none.
#[derive(Clone, Debug, PartialEq, Eq, Default)]
pub(crate) struct AgentTaskers(
    pub(crate) std::collections::BTreeMap<String, Option<std::collections::BTreeSet<u32>>>,
);

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum SubjectOrigin {
    Authz,
    Agent(String),
}

/// `subjects:` entries by resolved uid; a name that resolves to no account has none.
#[derive(Clone, Debug, PartialEq, Eq, Default)]
pub(crate) struct SubjectGrants(pub(crate) std::collections::BTreeMap<u32, SubjectEntry>);

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct SubjectEntry {
    pub(crate) name: String,
    pub(crate) permissions: Option<maknae_config::SubjectPermissions>,
    pub(crate) actions: Option<SubjectActionSet>,
    pub(crate) models: Option<Vec<maknae_config::ModelRef>>,
    pub(crate) origin: SubjectOrigin,
}

impl SubjectEntry {
    fn section(&self) -> String {
        match &self.origin {
            SubjectOrigin::Authz => format!("subjects.{}", self.name),
            SubjectOrigin::Agent(id) => format!("agents.{id}.policy"),
        }
    }

    fn cited_path(&self, effect: Effect, source: String) -> Cited {
        match &self.origin {
            SubjectOrigin::Authz => Cited::SubjectPath {
                subject: self.name.clone(),
                effect,
                source,
            },
            SubjectOrigin::Agent(id) => Cited::AgentPath {
                agent: id.clone(),
                effect,
                source,
            },
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Default)]
pub(crate) struct SubjectActionSet {
    pub(crate) allow: std::collections::BTreeMap<&'static str, String>,
    pub(crate) deny: std::collections::BTreeMap<&'static str, String>,
}

impl SubjectGrants {
    pub(crate) fn get(&self, uid: u32) -> Option<&SubjectEntry> {
        self.0.get(&uid)
    }
}

/// The policy entry a verdict was decided by, in the terms the rule index keys on.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) enum Cited {
    Path {
        effect: Effect,
        source: String,
    },
    Grant {
        role: &'static str,
        term: String,
        effect: Effect,
    },
    Destination {
        role: &'static str,
        destination: String,
    },
    SubjectPath {
        subject: String,
        effect: Effect,
        source: String,
    },
    AgentPath {
        agent: String,
        effect: Effect,
        source: String,
    },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) enum Effect {
    Allow,
    Deny,
}

#[derive(Clone, Debug, PartialEq)]
pub(crate) struct Decided {
    pub(crate) verdict: Verdict,
    pub(crate) role: Option<&'static str>,
    pub(crate) cited: Option<Cited>,
}

/// Validated `destinations:` allowlists (#172), role key → `provider:<name>`
/// entries. Built only by `validate_destinations`.
#[derive(Clone, Debug, PartialEq, Eq, Default)]
pub(crate) struct DestinationGrants(pub(crate) std::collections::BTreeMap<String, Vec<String>>);

impl DestinationGrants {
    /// Absent role or empty list is `false`: the allowlist never defaults open
    /// (#172 spec §2.2).
    pub(crate) fn allows(&self, role_key: &str, destination: &str) -> bool {
        self.0
            .get(role_key)
            .is_some_and(|l| l.iter().any(|e| e == destination))
    }
}

/// The terms `roles:` may grant or deny; a term absent here is refused at load. Only
/// `session.prompt` and `session.task` may be granted to `user`; `admin.baseline.accept` changes state.
// One line: the drift gate's extractor reads only the matched line.
#[rustfmt::skip]
pub(crate) const GRANTABLE_ACTIONS: [&str; 9] = ["admin.status", "admin.config.show", "admin.subject.list", "admin.baseline.show", "admin.baseline.accept", "admin.contain", "admin.release", "session.prompt", "session.task"];

/// The terms a `subjects:` action list or a family wildcard can name.
#[rustfmt::skip]
pub(crate) const ACTION_VOCABULARY: [&str; 14] = ["admin.status", "admin.config.show", "admin.subject.list", "admin.baseline.show", "admin.baseline.accept", "admin.contain", "admin.release", "session.prompt", "session.task", "fs.read", "fs.write", "fs.delete", "fs.mkdir", "session.new"];

/// An action entry as compiled against [`ACTION_VOCABULARY`]: `(term, entry as written)`.
pub(crate) fn expand(
    p: &maknae_config::ActionPattern,
) -> Result<Vec<(&'static str, String)>, crate::AuthzBasicError> {
    use crate::AuthzBasicError::{UngrantableAction, UnknownAction};
    let source = p.source();
    let (maknae_config::ActionPattern::Exact(name) | maknae_config::ActionPattern::Family(name)) =
        p;
    let class = match class_of(name) {
        Some(Class::Kernel | Class::Liveness) => return Err(UngrantableAction(source)),
        Some(c) => c,
        None => return Err(UnknownAction(source)),
    };
    let terms: Vec<_> = ACTION_VOCABULARY
        .into_iter()
        .filter(|t| match p {
            maknae_config::ActionPattern::Exact(e) => t == e,
            maknae_config::ActionPattern::Family(_) => class_of(t) == Some(class),
        })
        .map(|t| (t, source.clone()))
        .collect();
    match p {
        maknae_config::ActionPattern::Exact(_) if terms.is_empty() => Err(UnknownAction(source)),
        _ => Ok(terms),
    }
}

/// Byte-wise `&str` equality usable in a `const` context.
///
/// `PartialEq::eq` for `&str` is not a `const fn` (E0015), so the compile-time
/// pin below cannot use `==` or `[&str]::contains`. Hoisted to module scope
/// rather than nested inside the const block so it can be TESTED: the pin
/// asserts `!str_eq(term, "admin.whoami")`, which a `str_eq` that always
/// returned `false` would satisfy vacuously while still compiling.
const fn str_eq(a: &str, b: &str) -> bool {
    let (a, b) = (a.as_bytes(), b.as_bytes());
    if a.len() != b.len() {
        return false;
    }
    let mut i = 0;
    while i < a.len() {
        if a[i] != b[i] {
            return false;
        }
        i += 1;
    }
    true
}

/// `admin.whoami` must NEVER join [`GRANTABLE_ACTIONS`]. It has its own arm and
/// is permitted unconditionally for admins; routing it through grants would
/// make an operator's empty `roles:` block revoke it -- a silent downgrade of
/// working behaviour, from a file that says nothing about `whoami`.
///
/// Enforced at COMPILE time, so the mistake cannot reach a test run.
///
/// Written as a DESTRUCTURING rather than a `while` loop, deliberately. A loop
/// carries a bound, and `cargo mutants` weakens bounds: `<` to `==` or `>` both
/// make the pin check fewer terms -- or none -- while still compiling, and both
/// were reported MISSED, because compile-time code is unreachable from a test
/// run and no assertion can observe it. There is no bound here to weaken. The
/// array's LENGTH is in its type, so this destructuring is exhaustive by
/// construction: adding a fourth term makes it fail to compile (E0527) and
/// demands the fourth assertion, which is the failure mode an unrolled check
/// would otherwise have had.
const _: () = {
    let [a, b, c, d, e, f, g, h, i] = GRANTABLE_ACTIONS;
    const WHY: &str = "admin.whoami is unconditional for admins and must not be grantable";
    assert!(!str_eq(a, "admin.whoami"), "{}", WHY);
    assert!(!str_eq(b, "admin.whoami"), "{}", WHY);
    assert!(!str_eq(c, "admin.whoami"), "{}", WHY);
    assert!(!str_eq(d, "admin.whoami"), "{}", WHY);
    assert!(!str_eq(e, "admin.whoami"), "{}", WHY);
    assert!(!str_eq(f, "admin.whoami"), "{}", WHY);
    assert!(!str_eq(g, "admin.whoami"), "{}", WHY);
    assert!(!str_eq(h, "admin.whoami"), "{}", WHY);
    assert!(!str_eq(i, "admin.whoami"), "{}", WHY);
};

/// One expanded grant: the term and the entry it was written as.
pub(crate) type Grant = (&'static str, String);

/// Validated per-role action grants: role key → (allow, deny), each expanded.
#[derive(Clone, Debug, PartialEq, Eq, Default)]
pub(crate) struct ActionGrants(
    pub(crate) std::collections::BTreeMap<String, (Vec<Grant>, Vec<Grant>)>,
);

impl ActionGrants {
    /// Construct from already-validated parts. Private to the crate, and the
    /// only constructor besides `Default`, so every term inside has been
    /// through `validate_grants`.
    pub(crate) fn from_validated(
        m: std::collections::BTreeMap<String, (Vec<Grant>, Vec<Grant>)>,
    ) -> Self {
        ActionGrants(m)
    }

    /// Three-valued lookup for one role's grants on one action.
    ///
    /// **Takes the role key.** A one-argument form would be the flattening the
    /// spec forbids, hidden one layer down: a Phase-2 `Role::User` arm would
    /// call it and silently receive admin's grants.
    ///
    /// Deny beats allow within the role, matching `AuthzPolicy::evaluate3`'s
    /// stance -- and the composition layer above is deny-overrides regardless,
    /// so a grant here can never waive a mandatory deny.
    pub(crate) fn evaluate3_action(&self, role_key: &str, action: &str) -> maknae_config::Match3 {
        let Some((allow, deny)) = self.0.get(role_key) else {
            return maknae_config::Match3::NoMatch;
        };
        if let Some((_, source)) = deny.iter().find(|(t, _)| *t == action) {
            return maknae_config::Match3::DenyMatch {
                source: source.clone(),
            };
        }
        if let Some((_, source)) = allow.iter().find(|(t, _)| *t == action) {
            return maknae_config::Match3::AllowMatch {
                source: source.clone(),
            };
        }
        maknae_config::Match3::NoMatch
    }
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
    if path.contains('\0') {
        return Some("NUL byte");
    }
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

/// The one spelling of the absence note, shared by every arm that abstains
/// on a role's reach (#172): three tests depend on the class arm and the
/// prompt arm agreeing byte for byte, so the agreement is one function.
fn no_rule_note(role_key: &str, action: &str) -> String {
    format!("role {role_key}: no rule for {action}")
}

/// The `session.prompt` arm (#172, #608): the role's grant, the kernel-resolved
/// destination in the role's allowlist, and, when the subject lists `models`, the
/// admitted model in that list. A missing destination is a Deny, not a policy gap.
fn decide_prompt(
    lp: &LoadedPolicy,
    req: &SecRequest,
    role_key: &'static str,
    subject: Option<&SubjectEntry>,
) -> (Verdict, Option<Cited>) {
    match lp
        .action_grants
        .evaluate3_action(role_key, "session.prompt")
    {
        maknae_config::Match3::DenyMatch { source } => {
            return (
                Verdict::Deny {
                    reason: format!("denied by role grant {source}"),
                },
                Some(Cited::Grant {
                    role: role_key,
                    term: source,
                    effect: Effect::Deny,
                }),
            )
        }
        maknae_config::Match3::NoMatch => {
            return (
                Verdict::NotApplicable {
                    note: Some(no_rule_note(role_key, "session.prompt")),
                },
                None,
            )
        }
        maknae_config::Match3::AllowMatch { .. } => {}
    }
    let destination = match req.resource.0.get(RESOURCE_DESTINATION) {
        Some(AttrValue::Str(d)) => d.as_str(),
        Some(_) => return (Verdict::Indeterminate, None),
        None => {
            return (
                Verdict::Deny {
                    reason: "no destination on session.prompt".into(),
                },
                None,
            )
        }
    };
    if !lp.destinations.allows(role_key, destination) {
        return (
            Verdict::Deny {
                reason: format!("destination not allowlisted for role {role_key}: {destination}"),
            },
            None,
        );
    }
    if let Some((entry, listed)) = subject.and_then(|s| Some((s, s.models.as_ref()?))) {
        let model = match req.resource.0.get(RESOURCE_MODEL) {
            Some(AttrValue::Str(m)) => m.as_str(),
            _ => return (Verdict::Indeterminate, None),
        };
        if !listed.iter().any(|m| m.as_resource() == model) {
            return (
                Verdict::Deny {
                    reason: format!(
                        "subject {}: model {model} is not in {}.models allow",
                        entry.name,
                        entry.section()
                    ),
                },
                None,
            );
        }
    }
    (
        permit_with_audit(),
        Some(Cited::Destination {
            role: role_key,
            destination: destination.to_string(),
        }),
    )
}

/// The `taskers:` default (R-TD): without a list only people may task the agent.
pub(crate) fn taskers_admit(
    list: Option<&std::collections::BTreeSet<u32>>,
    uid: u32,
    requester_is_agent: bool,
) -> bool {
    match list {
        None => !requester_is_agent,
        Some(l) => l.contains(&uid),
    }
}

/// The `session.task` arm (#609): the role's grant, an enrolled target, and the
/// target's `taskers:` admitting the requester, all from this snapshot.
fn decide_task(
    lp: &LoadedPolicy,
    req: &SecRequest,
    role_key: &'static str,
    uid: u32,
) -> (Verdict, Option<Cited>) {
    let deny = |reason: String| (Verdict::Deny { reason }, None);
    let source = match lp.action_grants.evaluate3_action(role_key, "session.task") {
        maknae_config::Match3::DenyMatch { source } => {
            return (
                Verdict::Deny {
                    reason: format!("denied by role grant {source}"),
                },
                Some(Cited::Grant {
                    role: role_key,
                    term: source,
                    effect: Effect::Deny,
                }),
            )
        }
        maknae_config::Match3::NoMatch => {
            return (
                Verdict::NotApplicable {
                    note: Some(no_rule_note(role_key, "session.task")),
                },
                None,
            )
        }
        maknae_config::Match3::AllowMatch { source } => source,
    };
    let target = match req.resource.0.get(maknae_security::RESOURCE_AGENT) {
        Some(AttrValue::Str(t)) => t.as_str(),
        Some(_) => return (Verdict::Indeterminate, None),
        None => return deny("no agent on session.task".into()),
    };
    if !lp.agents.0.values().any(|id| id == target) {
        return deny(format!("session.task: agent {target} is not enrolled"));
    }
    let Some(list) = lp.taskers.0.get(target) else {
        return (Verdict::Indeterminate, None);
    };
    if !taskers_admit(list.as_ref(), uid, lp.agents.get(uid).is_some()) {
        return deny(format!("agent {target}: uid {uid} is not a tasker"));
    }
    (
        permit_with_audit(),
        Some(Cited::Grant {
            role: role_key,
            term: source,
            effect: Effect::Allow,
        }),
    )
}

/// (loaded policy, principal, request) → verdict. Spec §4 steps 2–6.
///
/// A thin `.0` over [`decide_loaded_with_role`]. **Test-only since #275:**
/// production now decides through the role-reporting path, and this wrapper
/// exists so the 54 in-file assertions keep asserting on a bare `Verdict`
/// rather than being rewritten to `.0` — the verdict they check is byte-for-byte
/// the one production enforces.
#[allow(dead_code)]
pub(crate) fn decide_loaded(
    lp: &LoadedPolicy,
    principal: &maknae_config::Principal,
    req: &SecRequest,
) -> Verdict {
    decide_loaded_with_role(lp, principal, req).0
}

/// The verdict AND the role it was decided on, from the SAME `LoadedPolicy`
/// (#275). One policy read, one resolution, both facts — so the audit record
/// can never attest a role the decision was not made on.
///
/// `None` means no role was resolved: either the subject data could not be
/// evaluated at all (the four pre-resolution returns below) or the bindings
/// resolve the subject to nothing. A role that WAS resolved is reported even
/// when the verdict is later `Indeterminate` — the resolution happened, and the
/// trail should say which role was being evaluated.
pub(crate) fn decide_loaded_with_role(
    lp: &LoadedPolicy,
    principal: &maknae_config::Principal,
    req: &SecRequest,
) -> (Verdict, Option<&'static str>) {
    let d = decide_loaded_cited(lp, principal, req);
    (d.verdict, d.role)
}

/// [`decide_loaded_with_role`] plus the policy entry that decided, where one did.
pub(crate) fn decide_loaded_cited(
    lp: &LoadedPolicy,
    principal: &maknae_config::Principal,
    req: &SecRequest,
) -> Decided {
    let undecided = |verdict| Decided {
        verdict,
        role: None,
        cited: None,
    };
    // Step 2 — subject resolution, matcher invariant first: a PRESENT but
    // wrong-typed `uid` is failed-to-evaluate, never a fall-through. Since
    // #276 struck the reserved subject name, `uid` is the ONLY identity datum
    // and this is the only gate.
    let uid: Option<u32> = match req.subject.0.get(SUBJECT_UID) {
        None => None,
        Some(AttrValue::Int(i)) => match u32::try_from(*i) {
            Ok(u) => Some(u),
            Err(_) => return undecided(Verdict::Indeterminate), // out-of-range carriage
        },
        Some(_) => return undecided(Verdict::Indeterminate),
    };
    // No uid: the subject cannot be evaluated. Since #276 struck the reserved
    // subject-name token there is no second identity datum to fall back to, so
    // this is the ONLY identity gate -- and it must stay a return, never a
    // fall-through.
    let Some(uid) = uid else {
        return undecided(Verdict::Indeterminate);
    };
    if class_of(&req.action.0) == Some(Class::Kernel) {
        return undecided(kernel_decided(req));
    }
    if let Some(reason) = channel_refusal(&lp.agents, uid, req) {
        return undecided(Verdict::Deny { reason });
    }
    let role = match lp.roles.role_for(uid, principal.uid) {
        Resolution::Role(r) => r,
        // Case-1 testimony (#181): the FACT, audit-only. The absence still
        // composes as an absence -- an extension may yet grant.
        Resolution::NoRole => {
            return undecided(Verdict::NotApplicable {
                note: Some("subject resolves to no role".into()),
            })
        }
    };

    // Step 3 — role gates over the closed class vocabulary. The match is BOUND
    // so the role can ride out beside the verdict; every arm stays a tail
    // expression exactly as before.
    let class = class_of(&req.action.0);
    let (verdict, cited) = match role {
        Role::Adversary => (
            Verdict::Deny {
                reason: "subject contained: role=adversary".into(),
            },
            None,
        ),
        Role::Admin | Role::User | Role::Guest
            if let Some(decided) = agent_arm(&lp.agents, lp.subjects.get(uid), uid, role, req) =>
        {
            (decided, None)
        }
        Role::Admin | Role::User | Role::Guest
            if let Some(limited) = action_limit(lp.subjects.get(uid), &req.action.0) =>
        {
            (limited, None)
        }
        Role::User | Role::Guest
            if req.action.0 == "admin.whoami" && lp.agents.get(uid).is_some() =>
        {
            (permit_with_audit(), None)
        }
        // #158, operator ruling 2026-09-07: admin governs Maknae management,
        // not filesystem privilege. Users and admins share the universal path
        // policy. Key the implemented terms exactly; adding a path to an unbuilt
        // fs verb must never grant it access.
        Role::Admin | Role::User
            if matches!(
                req.action.0.as_str(),
                "fs.read" | "fs.write" | "fs.delete" | "fs.mkdir"
            ) =>
        {
            match attempt_scope(req) {
                Ok(scope) => decide_fs(lp, req, role.key(), scope, lp.subjects.get(uid)),
                Err(verdict) => (verdict, None),
            }
        }
        // #172: the content-plane egress term, decided for admin AND user by
        // each role's OWN grant plus its OWN destination allowlist. The
        // position is load-bearing: the `Guest | User` class arm and the
        // `Admin` class arm below both match this action, so this arm must
        // precede both or it is dead for that role; it sits after the fs arms
        // only for reading order (their guards key on other action strings).
        Role::Admin | Role::User if req.action.0 == "session.prompt" => {
            decide_prompt(lp, req, role.key(), lp.subjects.get(uid))
        }
        Role::Admin | Role::User if req.action.0 == "session.task" => {
            decide_task(lp, req, role.key(), uid)
        }
        Role::Guest | Role::User => match class {
            Some(Class::Liveness) => (permit_with_audit(), None),
            // Case-2 testimony: ROLE-REACH OUTRANKS BUILD-STATE (#181 D4).
            // A non-admin's trail reads its own operational fact -- its reach
            // -- never the roadmap, which is admin-visible only; the wire is
            // the same generic Unauthorized either way.
            _ => (
                Verdict::NotApplicable {
                    note: Some(no_rule_note(role.key(), &req.action.0)),
                },
                None,
            ),
        },
        Role::Admin => match class {
            Some(Class::Liveness) => (permit_with_audit(), None),
            Some(Class::Admin) if req.action.0 == "admin.whoami" => (permit_with_audit(), None),
            // The three disclosure terms are decided per-ACTION by the operator's
            // `roles:` grants (#162), never by the class. The guard keys on the
            // CONSTANT, not on membership in the grant map: keying on the map
            // would make a term the operator explicitly DENIED fall through to
            // the NotApplicable arm below, and an explicit deny would silently
            // become an absence. Nothing falls through -- all three answers are
            // produced inside this arm.
            //
            // `"admin"` is a literal because the arm sits inside `Role::Admin`,
            // so the role is statically known here. A Phase-2 `Role::User` arm
            // must pass its own key; it cannot inherit admin's grants by
            // omitting the argument.
            Some(Class::Admin) if GRANTABLE_ACTIONS.contains(&req.action.0.as_str()) => {
                match lp.action_grants.evaluate3_action("admin", &req.action.0) {
                    maknae_config::Match3::AllowMatch { source } => (
                        permit_with_audit(),
                        Some(Cited::Grant {
                            role: "admin",
                            term: source,
                            effect: Effect::Allow,
                        }),
                    ),
                    // Names the term, matching what `decide_fs` does for a path
                    // entry: an audit record that says WHICH entry decided.
                    maknae_config::Match3::DenyMatch { source } => (
                        Verdict::Deny {
                            reason: format!("denied by role grant {source}"),
                        },
                        Some(Cited::Grant {
                            role: "admin",
                            term: source,
                            effect: Effect::Deny,
                        }),
                    ),
                    // No grant is an ABSENCE, not a refusal: deny-by-default
                    // happens once, at `finalize`, with "no grant" kept
                    // distinguishable from an explicit deny.
                    // Case-2 testimony: a grant COULD exist and none is
                    // written -- a policy question, named by term.
                    maknae_config::Match3::NoMatch => (
                        Verdict::NotApplicable {
                            note: Some(no_rule_note("admin", &req.action.0)),
                        },
                        None,
                    ),
                }
            }
            // Case-3 testimony: an enumerated admin term outside the grantable
            // set is unbuilt -- a roadmap question, and the admin trail may say
            // so (the wire still may not).
            Some(Class::Admin) | Some(Class::Fs) => (
                Verdict::NotApplicable {
                    note: Some(format!(
                        "term enumerated, not implemented: {}",
                        req.action.0
                    )),
                },
                None,
            ),
            // Case-3 testimony for whole unbuilt classes. `None` (a term the
            // class map cannot place) shares the arm and the note; for that
            // sub-case the "enumerated" wording is inexact -- and the sub-case
            // is production-unreachable (`class_of` is total over the closed
            // set every decoded Verb maps into). The unknown-vocabulary Deny
            // (ADR-0008 D5) is a COMPOSITION-layer control with no carrier
            // until a second operand exists (spec D5: pinned, deferred, owner
            // named); it, not this note, owns the unreachable case.
            Some(Class::Session)
            | Some(Class::Terminal)
            | Some(Class::Mcp)
            | Some(Class::Kernel)
            | None => (
                Verdict::NotApplicable {
                    note: Some(format!(
                        "term enumerated, not implemented: {}",
                        req.action.0
                    )),
                },
                None,
            ),
        },
    };
    Decided {
        verdict,
        role: Some(role.key()),
        cited,
    }
}

fn channel_refusal(agents: &AgentUids, uid: u32, req: &SecRequest) -> Option<String> {
    let enrolled = agents.get(uid);
    let off_channel = || enrolled.map(|id| format!("agent {id}: not on the agent channel"));
    match req.subject.0.get(maknae_security::SUBJECT_CHANNEL) {
        None => off_channel(),
        Some(AttrValue::Str(c)) if c == maknae_security::CHANNEL_CLIENT => off_channel(),
        Some(AttrValue::Str(c)) if c == maknae_security::CHANNEL_AGENT => {
            let named = match req.subject.0.get(maknae_security::SUBJECT_AGENT) {
                Some(AttrValue::Str(a)) => Some(a.as_str()),
                _ => None,
            };
            match (enrolled, named) {
                (Some(id), Some(n)) if id == n => None,
                (_, n) => Some(format!(
                    "agent channel: uid {uid} is not enrolled agent {}",
                    n.unwrap_or("(none)")
                )),
            }
        }
        Some(_) => Some(format!("channel: uid {uid} arrived on no known channel")),
    }
}

fn agent_arm(
    agents: &AgentUids,
    entry: Option<&SubjectEntry>,
    uid: u32,
    role: Role,
    req: &SecRequest,
) -> Option<Verdict> {
    let id = agents.get(uid)?;
    let action = req.action.0.as_str();
    let deny = |reason: String| Some(Verdict::Deny { reason });
    match role {
        Role::Admin => return deny(format!("agent {id}: an agent never holds admin")),
        Role::Adversary => return deny("subject contained: role=adversary".into()),
        Role::User | Role::Guest => {}
    }
    match class_of(action) {
        Some(Class::Admin) if action == "admin.whoami" => return None,
        Some(Class::Admin) => {
            return deny(format!(
                "agent {id}: {action} is never permitted to an agent"
            ))
        }
        Some(
            Class::Liveness
            | Class::Session
            | Class::Fs
            | Class::Terminal
            | Class::Mcp
            | Class::Kernel,
        )
        | None => {}
    }
    let granted = entry
        .filter(|e| matches!(e.origin, SubjectOrigin::Agent(_)))
        .and_then(|e| e.actions.as_ref())
        .is_some_and(|set| set.allow.contains_key(action) && !set.deny.contains_key(action));
    if AGENT_DEFAULT_DENIED.contains(&action) && !granted {
        return deny(format!(
            "agent {id}: {action} needs a grant in its policy.yaml"
        ));
    }
    None
}

fn action_limit(entry: Option<&SubjectEntry>, action: &str) -> Option<Verdict> {
    let entry = entry?;
    let set = entry.actions.as_ref()?;
    match class_of(action) {
        Some(Class::Liveness | Class::Kernel) | None => return None,
        Some(Class::Admin) if action == "admin.whoami" => return None,
        Some(Class::Admin | Class::Session | Class::Fs | Class::Terminal | Class::Mcp) => {}
    }
    let (name, section) = (&entry.name, entry.section());
    if let Some(source) = set.deny.get(action) {
        return Some(Verdict::Deny {
            reason: format!("subject {name}: {action} denied by {section}.actions entry {source}"),
        });
    }
    if set.allow.contains_key(action) {
        None
    } else {
        Some(Verdict::Deny {
            reason: format!("subject {name}: {action} is not in {section}.actions allow"),
        })
    }
}

fn kernel_decided(req: &SecRequest) -> Verdict {
    let kernel = matches!(
        req.subject.0.get(maknae_security::SUBJECT_INITIATOR),
        Some(AttrValue::Str(s)) if s == maknae_security::INITIATOR_KERNEL
    );
    match (req.action.0.as_str(), kernel) {
        ("kernel.contain", true) => permit_with_audit(),
        (a, false) => Verdict::NotApplicable {
            note: Some(format!(
                "kernel action requested by a subject that is not the kernel: {a}"
            )),
        },
        (a, true) => Verdict::NotApplicable {
            note: Some(format!("term enumerated, not implemented: {a}")),
        },
    }
}

/// Universal filesystem capability grammar (#158). `role_key` supplies audit
/// testimony only; it does not select a different path permission set.
enum FsScope {
    Read,
    Write,
    WriteSubtree,
}

fn attempt_scope(req: &SecRequest) -> Result<FsScope, Verdict> {
    use maknae_security::{
        FsOperation, CONTEXT_DAC_LANE, CONTEXT_FS_OPERATION, RESOURCE_OS_ACCESSIBLE,
    };
    let refuse = |reason: &str| Verdict::Deny {
        reason: reason.into(),
    };
    if req.context.0.str(CONTEXT_DAC_LANE) != Some("local") {
        return Err(refuse("filesystem attempt requires a local subject"));
    }
    let operation = req
        .context
        .0
        .str(CONTEXT_FS_OPERATION)
        .and_then(FsOperation::parse)
        .ok_or_else(|| refuse("filesystem attempt preparation absent or invalid"))?;
    let scope = match (req.action.0.as_str(), operation) {
        ("fs.read", FsOperation::Read) => FsScope::Read,
        ("fs.write", FsOperation::WriteExisting | FsOperation::WriteCreate)
        | ("fs.delete", FsOperation::DeleteEntry)
        | ("fs.mkdir", FsOperation::Mkdir) => FsScope::Write,
        ("fs.delete", FsOperation::DeleteTree) => FsScope::WriteSubtree,
        _ => {
            return Err(refuse(
                "filesystem attempt preparation does not match action",
            ))
        }
    };
    if req.resource.0.get(RESOURCE_OS_ACCESSIBLE).is_some() {
        return Err(refuse("filesystem attempt cannot carry an OS preapproval"));
    }
    Ok(scope)
}

fn decide_fs(
    lp: &LoadedPolicy,
    req: &SecRequest,
    role_key: &str,
    scope: FsScope,
    entry: Option<&SubjectEntry>,
) -> (Verdict, Option<Cited>) {
    let path = match req.resource.0.get(RESOURCE_PATH) {
        Some(AttrValue::Str(s)) => s.as_str(),
        // Required at THIS point of use: absent or wrong-typed → Indeterminate.
        _ => return (Verdict::Indeterminate, None),
    };
    if let Some(offense) = canonical_violation(path) {
        // A non-canonical path is a matcher bypass, refused BEFORE matching —
        // never passed through, never NotApplicable (spec §4.4).
        return (
            Verdict::Deny {
                reason: format!("non-canonical resource path ({offense})"),
            },
            None,
        );
    }
    let path = std::path::Path::new(path);
    let home = match req.subject.0.get(maknae_security::SUBJECT_HOME) {
        None => None,
        Some(AttrValue::Str(h)) => Some(std::path::Path::new(h.as_str())),
        Some(_) => return (Verdict::Indeterminate, None),
    };
    let subject = entry.and_then(|e| e.permissions.as_ref().map(|p| (e, p)));
    let set = subject.map(|(_, p)| p);
    let matched = match scope {
        FsScope::Read => {
            lp.policy
                .evaluate3_floored(set, &maknae_config::Request::Read(path), home)
        }
        FsScope::Write => {
            lp.policy
                .evaluate3_floored(set, &maknae_config::Request::Write(path), home)
        }
        FsScope::WriteSubtree => lp.policy.evaluate_write_subtree_floored(set, path, home),
    };
    let Ok(matched) = matched else {
        return (Verdict::Indeterminate, None);
    };
    match (matched, subject) {
        (maknae_config::Match3::DenyMatch { source }, Some((e, _)))
            if !lp.policy.deny_sources().contains(&source) =>
        {
            (
                Verdict::Deny {
                    reason: format!("denied by {}.permissions entry {source}", e.section()),
                },
                Some(e.cited_path(Effect::Deny, source)),
            )
        }
        (maknae_config::Match3::DenyMatch { source }, _) => (
            Verdict::Deny {
                // Audit-only provenance (spec §4.4): this reason reaches the
                // audit record; #77's wiring must never copy it onto the wire.
                reason: format!("denied by policy entry {source}"),
            },
            Some(Cited::Path {
                effect: Effect::Deny,
                source,
            }),
        ),
        (maknae_config::Match3::AllowMatch { source }, Some((e, _))) => (
            permit_with_audit(),
            Some(e.cited_path(Effect::Allow, source)),
        ),
        (maknae_config::Match3::AllowMatch { source }, None) => (
            permit_with_audit(),
            Some(Cited::Path {
                effect: Effect::Allow,
                source,
            }),
        ),
        // Case-5 testimony (#181): role and term ONLY -- never the path (the
        // D9 hazard). "No capability entry" is accurate where "no rule" would
        // be false: a rule for fs.read exists; no ENTRY matched this request.
        (maknae_config::Match3::NoMatch, _) => (
            Verdict::NotApplicable {
                note: Some(format!(
                    "role {role_key}: no capability entry for {}",
                    req.action.0
                )),
            },
            None,
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::binding::UidMap;
    use crate::tests::oracle::resolve;
    use maknae_security::{Action, Context, Resource, Subject};
    use std::collections::BTreeMap;

    const OPERATOR_UID: u32 = 501;
    const OTHER_UID: u32 = 666;
    const REQUESTER_HOME: &str = "/home/operator";

    fn principal() -> maknae_config::Principal {
        maknae_config::Principal {
            name: "operator".into(),
            uid: OPERATOR_UID,
        }
    }

    fn shipped_policy() -> maknae_config::AuthzPolicy {
        maknae_config::parse_authz("schema_version: 1\npermissions:\n  allow:\n    - \"Read(~/**)\"\n  deny:\n    - \"Read(~/.ssh/**)\"\n")
        .unwrap()
    }

    /// Fixture bindings over host-independent identities only (issue #138
    /// lesson): uids supplied via the map. The reserved `agent` token used to
    /// be the other half of that; #276 struck it, so the map is all of it.
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
            roles: Roles::File(resolve(&b, &lookup).unwrap()),
            // Grants are a SEPARATE fixture (`lp_with_grants`). All 16 call
            // sites of `lp_with` -- the golden matrix among them -- must keep
            // seeing an empty grant map, or the pin stops pinning.
            action_grants: ActionGrants::default(),
            destinations: DestinationGrants::default(),
            subjects: SubjectGrants::default(),
            agents: Default::default(),
            taskers: Default::default(),
        }
    }

    fn request(uid: Option<i64>, action: &str, path: Option<&str>) -> SecRequest {
        let mut s = Attributes::new();
        if let Some(u) = uid {
            s.insert(SUBJECT_UID, AttrValue::Int(u));
        }
        s.insert(
            maknae_security::SUBJECT_HOME,
            AttrValue::Str(REQUESTER_HOME.into()),
        );
        let mut r = Attributes::new();
        if let Some(p) = path {
            r.insert(RESOURCE_PATH, AttrValue::Str(p.into()));
        }
        let mut c = Attributes::new();
        c.insert(
            maknae_security::CONTEXT_DAC_LANE,
            AttrValue::Str(maknae_security::Lane::Local.as_str().into()),
        );
        // Grammar vectors decide a prepared local read.
        if action == "fs.read" {
            c.insert(
                maknae_security::CONTEXT_FS_OPERATION,
                AttrValue::Str("read".into()),
            );
        }
        SecRequest {
            subject: Subject(s),
            resource: Resource(r),
            action: Action(action.into()),
            context: Context(c),
        }
    }

    /// The production role and capability decision, with kernel preparation facts.
    #[test]
    fn filesystem_mutation_attempts_share_user_and_admin_policy() {
        for role in ["admin", "user"] {
            let mut lp = lp_with(
                Some(&[(role, &["operator"])]),
                &[("operator", OPERATOR_UID)],
            );
            lp.policy = maknae_config::parse_authz("schema_version: 1\npermissions:\n  allow: [\"Read(~/**)\", \"Write(~/projects/**)\"]\n  deny: [\"Write(~/projects/private/**)\"]\n").unwrap();
            for (action, operation) in [
                ("fs.write", "write-existing"),
                ("fs.write", "write-create"),
                ("fs.delete", "delete-entry"),
                ("fs.delete", "delete-tree"),
                ("fs.mkdir", "mkdir"),
            ] {
                let mut req = read_req(Some("local"), None);
                req.action.0 = action.into();
                req.context
                    .0
                    .insert("fs_operation", AttrValue::Str(operation.into()));
                req.resource.0.insert(
                    RESOURCE_PATH,
                    AttrValue::Str("/home/operator/projects/sentinel-158".into()),
                );
                assert!(
                    matches!(
                        decide_loaded(&lp, &principal(), &req),
                        Verdict::Permit { .. }
                    ),
                    "{role} {operation} must reach its universal Write grant"
                );
                req.resource.0.insert(
                    RESOURCE_PATH,
                    AttrValue::Str("/home/operator/projects/private/sentinel-158".into()),
                );
                let refused = decide_loaded(&lp, &principal(), &req);
                assert!(
                    matches!(refused, Verdict::Deny { ref reason } if reason.contains("Write(~/projects/private/**)")),
                    "wrong refusal: {refused:?}"
                );
                req.resource.0.insert(
                    RESOURCE_PATH,
                    AttrValue::Str("/home/operator/read-only-sentinel-158".into()),
                );
                assert!(
                    matches!(
                        decide_loaded(&lp, &principal(), &req),
                        Verdict::NotApplicable { .. }
                    ),
                    "Read authority must not imply Write"
                );
            }
        }
    }

    #[test]
    fn mutation_preparation_cannot_substitute_for_other_os_evidence() {
        let mut lp = lp_with(None, &[]);
        lp.policy = maknae_config::parse_authz(
            "schema_version: 1\npermissions:\n  allow: [\"Read(~/**)\", \"Write(~/**)\"]\n",
        )
        .unwrap();
        for (action, operation, lane, accessible) in [
            (
                "fs.write",
                "write-existing",
                "local",
                Some(AttrValue::Bool(true)),
            ),
            (
                "fs.write",
                "write-existing",
                "local",
                Some(AttrValue::Bool(false)),
            ),
            (
                "fs.write",
                "write-create",
                "local",
                Some(AttrValue::Bool(true)),
            ),
            ("fs.mkdir", "mkdir", "local", Some(AttrValue::Bool(false))),
            (
                "fs.delete",
                "delete-entry",
                "local",
                Some(AttrValue::Int(1)),
            ),
            (
                "fs.write",
                "write-existing",
                "remote",
                Some(AttrValue::Bool(true)),
            ),
            ("fs.write", "write-create", "remote", None),
            ("fs.delete", "write-create", "local", None),
            ("fs.write", "mkdir", "local", None),
            ("fs.mkdir", "unknown", "local", None),
            ("fs.read", "write-create", "local", None),
        ] {
            let mut req = read_req(Some(lane), accessible);
            req.action.0 = action.into();
            req.context
                .0
                .insert("fs_operation", AttrValue::Str(operation.into()));
            assert!(
                matches!(decide_loaded(&lp, &principal(), &req), Verdict::Deny { .. }),
                "{action} {operation} {lane}"
            );
        }
        let mut req = read_req(Some("local"), Some(AttrValue::Bool(true)));
        req.action.0 = "fs.write".into();
        assert!(
            matches!(decide_loaded(&lp, &principal(), &req), Verdict::Deny { .. }),
            "bare positive OS access is not a prepared write"
        );
        req.context
            .0
            .insert("fs_operation", AttrValue::Str("write-existing".into()));
        req.resource
            .0
            .insert(maknae_security::RESOURCE_OS_ACCESSIBLE, AttrValue::Int(1));
        assert_eq!(
            decide_loaded(&lp, &principal(), &req),
            Verdict::Deny {
                reason: "filesystem attempt cannot carry an OS preapproval".into()
            }
        );
        let mut plain = read_req(Some("local"), None);
        plain.action.0 = "fs.write".into();
        plain
            .context
            .0
            .insert("fs_operation", AttrValue::Str("write-existing".into()));
        assert!(matches!(
            decide_loaded(&lp, &principal(), &plain),
            Verdict::Permit { .. }
        ));
    }

    #[test]
    fn mutation_capability_checks_reject_noncanonical_paths_before_matching() {
        let mut lp = lp_with(None, &[]);
        lp.policy = maknae_config::parse_authz(
            "schema_version: 1\npermissions:\n  allow: [\"Write(/**)\"]\n",
        )
        .unwrap();
        for path in [
            "relative",
            "/home//operator/x",
            "/home/operator/../x",
            "/home/operator/x/",
            "/home/operator/\0x",
        ] {
            let mut req = read_req(Some("local"), None);
            req.action.0 = "fs.write".into();
            req.context
                .0
                .insert("fs_operation", AttrValue::Str("write-existing".into()));
            req.resource
                .0
                .insert(RESOURCE_PATH, AttrValue::Str(path.into()));
            assert!(
                matches!(decide_loaded(&lp, &principal(), &req), Verdict::Deny { ref reason } if reason.starts_with("non-canonical resource path")),
                "{path:?}"
            );
        }
    }

    #[test]
    fn the_requesters_home_decides_tilde_not_the_enrolled_principals() {
        let lp = lp_with(None, &[]);
        let mut req = request(
            Some(i64::from(OPERATOR_UID)),
            "fs.read",
            Some("/home/b/notes.txt"),
        );
        req.subject.0.insert(
            maknae_security::SUBJECT_HOME,
            AttrValue::Str("/home/b".into()),
        );
        assert!(matches!(
            decide_loaded(&lp, &principal(), &req),
            Verdict::Permit { .. }
        ));
        req.subject.0.insert(
            maknae_security::SUBJECT_HOME,
            AttrValue::Str("/home/c".into()),
        );
        assert!(matches!(
            decide_loaded(&lp, &principal(), &req),
            Verdict::NotApplicable { .. }
        ));
    }

    #[test]
    fn a_filesystem_request_with_no_home_is_indeterminate_under_a_tilde_policy() {
        let lp = lp_with(None, &[]);
        let mut req = request(
            Some(i64::from(OPERATOR_UID)),
            "fs.read",
            Some("/home/b/notes.txt"),
        );
        req.subject.0 = {
            let mut s = Attributes::new();
            s.insert(SUBJECT_UID, AttrValue::Int(i64::from(OPERATOR_UID)));
            s
        };
        assert_eq!(
            decide_loaded(&lp, &principal(), &req),
            Verdict::Indeterminate
        );
    }

    #[test]
    fn a_root_home_is_unbound_under_a_tilde_policy() {
        let lp = lp_with(None, &[]);
        let mut req = request(Some(i64::from(OPERATOR_UID)), "fs.read", Some("/x"));
        req.subject
            .0
            .insert(maknae_security::SUBJECT_HOME, AttrValue::Str("/".into()));
        assert_eq!(
            decide_loaded(&lp, &principal(), &req),
            Verdict::Indeterminate
        );
    }

    #[test]
    fn a_homeless_request_is_decided_normally_under_an_absolute_only_policy() {
        let mut lp = lp_with(None, &[]);
        lp.policy = maknae_config::parse_authz(
            "schema_version: 1\npermissions:\n  allow:\n    - \"Read(/srv/**)\"\n  deny: []\n",
        )
        .unwrap();
        let mut req = request(Some(i64::from(OPERATOR_UID)), "fs.read", Some("/srv/x"));
        req.subject.0 = {
            let mut s = Attributes::new();
            s.insert(SUBJECT_UID, AttrValue::Int(i64::from(OPERATOR_UID)));
            s
        };
        assert!(matches!(
            decide_loaded(&lp, &principal(), &req),
            Verdict::Permit { .. }
        ));
    }

    #[test]
    fn a_wrong_typed_home_is_indeterminate() {
        let lp = lp_with(None, &[]);
        let mut req = request(
            Some(i64::from(OPERATOR_UID)),
            "fs.read",
            Some("/home/b/notes.txt"),
        );
        req.subject
            .0
            .insert(maknae_security::SUBJECT_HOME, AttrValue::Int(7));
        assert_eq!(
            decide_loaded(&lp, &principal(), &req),
            Verdict::Indeterminate
        );
    }

    #[test]
    fn a_wrong_typed_home_is_indeterminate_even_where_no_pattern_needs_one() {
        let mut lp = lp_with(None, &[]);
        lp.policy = maknae_config::parse_authz(
            "schema_version: 1\npermissions:\n  allow:\n    - \"Read(/srv/**)\"\n  deny: []\n",
        )
        .unwrap();
        let mut req = request(
            Some(i64::from(OPERATOR_UID)),
            "fs.read",
            Some("/srv/notes.txt"),
        );
        assert!(matches!(
            decide_loaded(&lp, &principal(), &req),
            Verdict::Permit { .. }
        ));
        req.subject
            .0
            .insert(maknae_security::SUBJECT_HOME, AttrValue::Int(7));
        assert_eq!(
            decide_loaded(&lp, &principal(), &req),
            Verdict::Indeterminate
        );
    }

    /// A read request with an explicit lane and optional OS attribute; no preparation.
    fn read_req(lane: Option<&str>, accessible: Option<AttrValue>) -> SecRequest {
        let mut r = request(Some(501), "fs.read", Some("/home/operator/x"));
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
    fn a_read_is_decided_only_as_a_local_prepared_attempt_without_os_preapproval() {
        let lp = lp_with(None, &[]);
        let decide = |lane: Option<&str>, op: Option<&str>, accessible: Option<AttrValue>| {
            let mut req = read_req(lane, accessible);
            if let Some(op) = op {
                req.context.0.insert(
                    maknae_security::CONTEXT_FS_OPERATION,
                    AttrValue::Str(op.into()),
                );
            }
            decide_loaded(&lp, &principal(), &req)
        };
        assert!(matches!(
            decide(Some("local"), Some("read"), None),
            Verdict::Permit { .. }
        ));
        for (lane, op, accessible, reason) in [
            (
                Some("remote"),
                Some("read"),
                None,
                "filesystem attempt requires a local subject",
            ),
            (
                None,
                Some("read"),
                None,
                "filesystem attempt requires a local subject",
            ),
            (
                Some("local"),
                None,
                None,
                "filesystem attempt preparation absent or invalid",
            ),
            (
                Some("local"),
                Some("write-existing"),
                None,
                "filesystem attempt preparation does not match action",
            ),
            (
                Some("local"),
                Some("read"),
                Some(AttrValue::Bool(true)),
                "filesystem attempt cannot carry an OS preapproval",
            ),
            (
                Some("local"),
                Some("read"),
                Some(AttrValue::Bool(false)),
                "filesystem attempt cannot carry an OS preapproval",
            ),
        ] {
            assert_eq!(
                decide(lane, op, accessible),
                Verdict::Deny {
                    reason: reason.into()
                },
                "{lane:?} {op:?}"
            );
        }
        let mut write = read_req(Some("local"), None);
        write.action.0 = "fs.write".into();
        write.context.0.insert(
            maknae_security::CONTEXT_FS_OPERATION,
            AttrValue::Str("read".into()),
        );
        assert!(matches!(
            decide_loaded(&lp, &principal(), &write),
            Verdict::Deny { .. }
        ));
    }

    /// A SUPERSET of the golden matrix's columns, not the same list. The loops
    /// over this (adversary-denies-everything, guest-and-user-permit-only-
    /// liveness) must exercise the grantable terms too, so a future
    /// permissive arm for them turns those tests red as well as the matrix.
    const ALL_ACTIONS: &[&str] = &[
        "liveness.ping",
        "admin.whoami",
        "admin.status",
        "admin.config.show",
        "admin.subject.list",
        "admin.baseline.show",
        "admin.baseline.accept",
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
                &request(Some(OTHER_UID as i64), action, Some("/etc/hosts")),
            );
            assert!(
                matches!(v, Verdict::Deny { ref reason } if reason.contains("role=adversary")),
                "adversary must be denied {action}: {v:?}"
            );
        }
    }

    #[test]
    fn guest_stays_liveness_only_and_user_can_read() {
        for (role_key, ident, uid) in [("guest", "guestic", 700_u32), ("user", "usery", 701)] {
            let lp = lp_with(Some(&[(role_key, &[ident])]), &[(ident, uid)]);
            for action in ALL_ACTIONS {
                let v = decide_loaded(
                    &lp,
                    &principal(),
                    &request(Some(uid as i64), action, Some("/home/operator/x")),
                );
                if *action == "liveness.ping" || (role_key == "user" && *action == "fs.read") {
                    assert!(
                        matches!(v, Verdict::Permit { .. }),
                        "{role_key} {action}: {v:?}"
                    );
                } else {
                    // Exact case-2 note per cell (#181 D4): role-reach outranks
                    // build-state for non-admin roles, whatever the term.
                    assert_eq!(
                        v,
                        Verdict::NotApplicable {
                            note: Some(format!("role {role_key}: no rule for {action}"))
                        },
                        "{role_key} {action}"
                    );
                }
            }
        }
    }

    #[test]
    fn user_and_admin_share_filesystem_permissions_and_refuse_os_preapproval() {
        let lp = lp_with(
            Some(&[("admin", &["alex"]), ("user", &["usery"])]),
            &[("alex", OPERATOR_UID), ("usery", 701)],
        );
        for uid in [OPERATOR_UID, 701] {
            let mut req = request(
                Some(uid as i64),
                "fs.read",
                Some("/home/operator/notes.txt"),
            );
            assert_eq!(decide_loaded(&lp, &principal(), &req), permit_with_audit());
            req.resource.0.insert(
                RESOURCE_PATH,
                AttrValue::Str("/home/operator/.ssh/key".into()),
            );
            assert_eq!(
                decide_loaded(&lp, &principal(), &req),
                Verdict::Deny {
                    reason: "denied by policy entry Read(~/.ssh/**)".into(),
                }
            );
            req.resource.0.insert(
                RESOURCE_PATH,
                AttrValue::Str("/home/operator/notes.txt".into()),
            );
            req.resource.0.insert(
                maknae_security::RESOURCE_OS_ACCESSIBLE,
                AttrValue::Bool(false),
            );
            assert_eq!(
                decide_loaded(&lp, &principal(), &req),
                Verdict::Deny {
                    reason: "filesystem attempt cannot carry an OS preapproval".into(),
                }
            );
        }
    }

    #[test]
    fn admin_grammar_deny_overrides_and_carries_source() {
        let lp = lp_with(None, &[]);
        let v = decide_loaded(
            &lp,
            &principal(),
            &request(
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
                &request(Some(OPERATOR_UID as i64), "fs.read", Some(path)),
            );
            // Case-5 note: role and term only — the PATH stays out (D9).
            assert_eq!(
                v,
                Verdict::NotApplicable {
                    note: Some("role admin: no capability entry for fs.read".into())
                },
                "{path}"
            );
        }
    }

    #[test]
    fn admin_reserved_classes_are_not_applicable() {
        let lp = lp_with(None, &[]);
        // `session.prompt` left this list with #172: it has an arm now, and its
        // absence note is pinned by the prompt tests (`role admin: no rule…`).
        for action in ["terminal.create", "unknown.thing"] {
            let v = decide_loaded(
                &lp,
                &principal(),
                &request(Some(OPERATOR_UID as i64), action, None),
            );
            // Case-3 note, including `unknown.thing` (class None): build-state
            // is the true fact either way; the D5 unknown-vocabulary Deny is a
            // composition-layer control with no carrier yet.
            assert_eq!(
                v,
                Verdict::NotApplicable {
                    note: Some(format!("term enumerated, not implemented: {action}"))
                },
                "{action}"
            );
        }
    }

    // ---- matcher invariant golden vectors (spec §4.2, golden.rs deferral) ----

    #[test]
    fn missing_identity_is_indeterminate_distinct_from_unbound() {
        let lp = lp_with(None, &[]);
        // No uid → failed-to-evaluate. (Was "missing BOTH identity attrs";
        // #276 struck the reserved subject name, so uid is the only one.)
        let v = decide_loaded(&lp, &principal(), &request(None, "liveness.ping", None));
        assert_eq!(v, Verdict::Indeterminate);
        // Present-but-unbound uid → NotApplicable (defaults: not the principal).
        let v = decide_loaded(
            &lp,
            &principal(),
            &request(Some(999), "liveness.ping", None),
        );
        assert_eq!(
            v,
            Verdict::NotApplicable {
                note: Some("subject resolves to no role".into())
            }
        );
    }

    #[test]
    fn wrong_typed_or_out_of_range_uid_is_indeterminate() {
        let lp = lp_with(None, &[]);
        let v = decide_loaded(&lp, &principal(), &request(Some(-1), "liveness.ping", None));
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
            &request(Some(OPERATOR_UID as i64), "fs.read", None),
        );
        assert_eq!(v, Verdict::Indeterminate);
        // But for a role that never reaches the grammar, absent path is
        // NotApplicable at step 3 (spec R3 should-fix: the invariant fires at
        // the point of use, not globally).
        let lp2 = lp_with(Some(&[("guest", &["g"])]), &[("g", 700)]);
        let v2 = decide_loaded(&lp2, &principal(), &request(Some(700), "fs.read", None));
        assert_eq!(
            v2,
            Verdict::NotApplicable {
                note: Some("role guest: no rule for fs.read".into())
            }
        );
    }

    // ---- class-match rule pins (spec §5) ----

    /// The admin class is NOT a blanket grant. A class-granular permit here
    /// would grant every future admin term — containment, policy reload — off an
    /// arm that keys nothing.
    #[test]
    fn admin_class_permits_only_whoami() {
        let lp = lp_with(None, &[]); // shipped default: enrolled uid → admin
        let req = |a: &str| request(Some(OPERATOR_UID as i64), a, None);
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
            "admin.policy.reload",
            "admin.subject.bind",
        ] {
            // The note tells the two absences apart (#181 D4): a GRANTABLE
            // sibling with no grant is a policy question (case 2); an
            // ungrantable admin term is a roadmap question (case 3). Exact
            // equality on both — the distinction IS the new behaviour.
            let expected = if GRANTABLE_ACTIONS.contains(&action) {
                format!("role admin: no rule for {action}")
            } else {
                format!("term enumerated, not implemented: {action}")
            };
            assert_eq!(
                decide_loaded(&lp, &principal(), &req(action)),
                Verdict::NotApplicable {
                    note: Some(expected)
                },
                "{action} must NOT permit off the admin class arm"
            );
        }
    }

    /// `str_eq` is what makes the compile-time pin mean something. The pin
    /// reads `!str_eq(term, "admin.whoami")`, so a `str_eq` that always
    /// returned `false` would satisfy it vacuously and still compile -- the
    /// assertion would be green while asserting nothing. These cases are the
    /// ones that distinguish a real comparison from a constant `false`.
    #[test]
    fn str_eq_actually_compares() {
        assert!(str_eq("admin.whoami", "admin.whoami"), "equal strings");
        assert!(str_eq("", ""), "both empty");
        assert!(
            !str_eq("admin.whoami", "admin.status"),
            "same length, differ"
        );
        assert!(
            !str_eq("admin.status", "admin.status2"),
            "prefix, differing length"
        );
        assert!(!str_eq("", "a"), "empty vs non-empty");
        // The exact comparison the pin performs, both ways round.
        for t in GRANTABLE_ACTIONS {
            assert!(!str_eq(t, "admin.whoami"));
        }
        assert!(str_eq(GRANTABLE_ACTIONS[0], "admin.status"));
    }

    fn expanded(p: &str) -> Result<Vec<(&'static str, String)>, crate::AuthzBasicError> {
        expand(&maknae_config::ActionPattern::parse(p).unwrap())
    }

    #[test]
    fn a_family_wildcard_expands_to_its_members() {
        let terms = |p: &str| -> Vec<&'static str> {
            let got = expanded(p).unwrap();
            assert!(got.iter().all(|(_, s)| s == p), "{p}: {got:?}");
            got.into_iter().map(|(t, _)| t).collect()
        };
        assert_eq!(
            terms("fs.*"),
            ["fs.read", "fs.write", "fs.delete", "fs.mkdir"]
        );
        assert_eq!(
            terms("admin.*"),
            [
                "admin.status",
                "admin.config.show",
                "admin.subject.list",
                "admin.baseline.show",
                "admin.baseline.accept",
                "admin.contain",
                "admin.release"
            ]
        );
        assert_eq!(
            terms("session.*"),
            ["session.prompt", "session.task", "session.new"]
        );
        assert!(terms("terminal.*").is_empty());
        assert!(terms("mcp.*").is_empty());
        assert_eq!(terms("fs.write"), ["fs.write"]);
        assert_eq!(terms("admin.status"), ["admin.status"]);
    }

    #[test]
    fn kernel_and_liveness_are_never_patterns() {
        for p in ["kernel.*", "liveness.*", "kernel.contain", "liveness.ping"] {
            assert_eq!(
                expanded(p),
                Err(crate::AuthzBasicError::UngrantableAction(p.into())),
                "{p}"
            );
        }
        for p in ["nope.*", "fs.exec", "admin.whoami", "admin.policy.reload"] {
            assert_eq!(
                expanded(p),
                Err(crate::AuthzBasicError::UnknownAction(p.into())),
                "{p}"
            );
        }
    }

    #[test]
    fn the_vocabulary_is_the_grantable_terms_the_four_fs_terms_and_session_new() {
        assert_eq!(ACTION_VOCABULARY[..9], GRANTABLE_ACTIONS);
        assert_eq!(
            ACTION_VOCABULARY[9..],
            [
                "fs.read",
                "fs.write",
                "fs.delete",
                "fs.mkdir",
                "session.new"
            ]
        );
    }

    #[test]
    fn the_fs_terms_of_the_vocabulary_are_the_fs_arm_guard() {
        let lp = lp_with(Some(&[("admin", &["alex"])]), &[("alex", 1001)]);
        let unbuilt = |t: &str| Verdict::NotApplicable {
            note: Some(format!("term enumerated, not implemented: {t}")),
        };
        let fs_terms: Vec<&str> = crate::ACTION_TERMS
            .iter()
            .copied()
            .filter(|t| class_of(t) == Some(Class::Fs))
            .collect();
        assert_eq!(fs_terms.len(), 10);
        for t in fs_terms {
            let mut req = request(Some(1001), t, Some("/home/operator/x"));
            req.context.0.insert(
                maknae_security::CONTEXT_FS_OPERATION,
                AttrValue::Str("mkdir".into()),
            );
            let keyed = decide_loaded(&lp, &principal(), &req) != unbuilt(t);
            assert_eq!(keyed, ACTION_VOCABULARY.contains(&t), "{t}");
        }
    }

    /// The arm's guard is a SECOND lock, and this is what proves it locks.
    ///
    /// `validate_grants` already refuses a term outside `GRANTABLE_ACTIONS` at
    /// load, so in production the map can only hold grantable terms -- which
    /// makes the guard look redundant, and a mutation that weakens it to `true`
    /// behaviourally identical. It is not redundant: it is the reason the arm
    /// does not have to TRUST the map's contents. Here the map is built past
    /// the validator, holding a term the arm must never honour.
    #[test]
    fn the_arm_does_not_trust_a_grant_map_holding_an_ungrantable_term() {
        let forged = ActionGrants::from_validated(std::collections::BTreeMap::from([(
            "admin".to_string(),
            (
                vec![("admin.policy.reload", "admin.policy.reload".into())],
                Vec::new(),
            ),
        )]));
        let mut lp = lp_with_grants("", GRANT_UIDS);
        lp.action_grants = forged;
        assert_eq!(
            decide_loaded(
                &lp,
                &principal(),
                &request(Some(1001), "admin.policy.reload", None)
            ),
            Verdict::NotApplicable {
                note: Some("term enumerated, not implemented: admin.policy.reload".into())
            },
            "a term outside GRANTABLE_ACTIONS must not be honoured even if it \
             somehow reaches the grant map"
        );
    }

    /// The same property the compile-time pin holds, held again at runtime so
    /// it is carried by a KILLABLE test. The const block is unreachable from a
    /// test run by construction, so on its own it is a control nothing can
    /// prove fires except by breaking the build on purpose.
    /// Every grantable term must be in `Class::Admin` -- the arm's OTHER
    /// precondition, and until this test the unenforced one.
    ///
    /// `validate_grants` admits a term on membership in `GRANTABLE_ACTIONS`
    /// alone, but the arm also requires `class_of(action) == Some(Class::Admin)`
    /// to be reached at all. Add `session.list` to the constant and everything
    /// passes -- the const pin (it only excludes `admin.whoami`), validation,
    /// the drift gate with a manifest row, boot -- and the request routes to
    /// `Some(Class::Session) => NotApplicable`. The grant parses, passes, and
    /// does nothing: exactly the "accepted but inert" outcome the spec claims
    /// is impossible by construction. It was impossible by one check, not two.
    #[test]
    fn every_grantable_term_has_an_arm_that_consults_grants() {
        // Structural: a grantable term that no arm consults would abstain.
        // Granted in full to admin, with the prompt term's second condition
        // (the destination attribute) satisfied for that term only.
        let mut lp = lp_with_grants(
            "roles:\n  admin:\n    allow: [\"admin.status\", \"admin.config.show\", \"admin.subject.list\", \"admin.baseline.show\", \"admin.baseline.accept\", \"admin.contain\", \"admin.release\", \"session.prompt\", \"session.task\"]\ndestinations:\n  admin:\n    allow: [\"provider:openai\"]\n",
            GRANT_UIDS,
        );
        lp.agents.0.insert(HOBI_UID, "hobi".into());
        lp.taskers.0.insert("hobi".into(), None);
        for t in GRANTABLE_ACTIONS {
            let req = match t {
                "session.prompt" => prompt_req(1001, Some("provider:openai")),
                "session.task" => task_req(1001, Some(AttrValue::Str("hobi".into()))),
                _ => request(Some(1001), t, None),
            };
            assert_eq!(
                decide_loaded(&lp, &principal(), &req),
                permit_with_audit(),
                "`{t}` is grantable but no arm consulted its grant"
            );
        }
    }

    fn prompt_req(uid: u32, destination: Option<&str>) -> SecRequest {
        let mut r = request(Some(uid as i64), "session.prompt", None);
        if let Some(d) = destination {
            r.resource
                .0
                .insert(RESOURCE_DESTINATION, AttrValue::Str(d.into()));
        }
        r
    }
    fn lp_prompt(roles: &str, dests: &str) -> LoadedPolicy {
        lp_with_grants(&format!("{roles}{dests}"), GRANT_UIDS)
    }
    const USER_PROMPT: &str = "roles:\n  user:\n    allow: [\"session.prompt\"]\n";
    const USER_OPENAI: &str = "destinations:\n  user:\n    allow: [\"provider:openai\"]\n";

    #[test]
    fn prompt_permits_only_with_the_grant_and_an_allowlisted_destination() {
        let lp = lp_prompt(USER_PROMPT, USER_OPENAI);
        assert_eq!(
            decide_loaded(
                &lp,
                &principal(),
                &prompt_req(1002, Some("provider:openai"))
            ),
            permit_with_audit()
        );
    }

    #[test]
    fn prompt_with_the_grant_but_an_unlisted_destination_is_a_deny_naming_it() {
        let lp = lp_prompt(USER_PROMPT, USER_OPENAI);
        assert_eq!(
            decide_loaded(&lp, &principal(), &prompt_req(1002, Some("provider:other"))),
            Verdict::Deny {
                reason: "destination not allowlisted for role user: provider:other".into()
            }
        );
    }

    #[test]
    fn prompt_with_no_destinations_block_or_an_empty_one_is_a_deny() {
        // Spec §6: "observed failing if absence defaults open" (observed at
        // implementation time by making `allows` default open; the deny below
        // went red on the "" case and green on revert).
        for dests in ["", "destinations:\n  user:\n    allow: []\n"] {
            let lp = lp_prompt(USER_PROMPT, dests);
            assert_eq!(
                decide_loaded(
                    &lp,
                    &principal(),
                    &prompt_req(1002, Some("provider:openai"))
                ),
                Verdict::Deny {
                    reason: "destination not allowlisted for role user: provider:openai".into()
                },
                "{dests:?}"
            );
        }
    }

    #[test]
    fn prompt_with_no_destination_is_a_deny_and_a_non_string_destination_is_indeterminate() {
        let lp = lp_prompt(USER_PROMPT, USER_OPENAI);
        assert_eq!(
            decide_loaded(&lp, &principal(), &prompt_req(1002, None)),
            Verdict::Deny {
                reason: "no destination on session.prompt".into()
            }
        );
        let mut r = prompt_req(1002, None);
        r.resource.0.insert(RESOURCE_DESTINATION, AttrValue::Int(1));
        assert_eq!(decide_loaded(&lp, &principal(), &r), Verdict::Indeterminate);
    }

    #[test]
    fn prompt_without_the_action_grant_is_an_absence_even_with_a_destination() {
        let lp = lp_prompt("", USER_OPENAI);
        assert_eq!(
            decide_loaded(
                &lp,
                &principal(),
                &prompt_req(1002, Some("provider:openai"))
            ),
            Verdict::NotApplicable {
                note: Some("role user: no rule for session.prompt".into())
            }
        );
        // The admin absence note (this term left `admin_reserved_classes_are_not_applicable`).
        assert_eq!(
            decide_loaded(
                &lp_prompt("", ""),
                &principal(),
                &prompt_req(1001, Some("provider:openai"))
            ),
            Verdict::NotApplicable {
                note: Some("role admin: no rule for session.prompt".into())
            }
        );
    }

    #[test]
    fn prompt_deny_grant_beats_allow_and_names_the_source() {
        let lp = lp_prompt(
            "roles:\n  user:\n    allow: [\"session.prompt\"]\n    deny: [\"session.prompt\"]\n",
            USER_OPENAI,
        );
        assert_eq!(
            decide_loaded(
                &lp,
                &principal(),
                &prompt_req(1002, Some("provider:openai"))
            ),
            Verdict::Deny {
                reason: "denied by role grant session.prompt".into()
            }
        );
    }

    #[test]
    fn prompt_grants_are_per_role_admin_and_user_do_not_share() {
        let lp = lp_prompt(
            "roles:\n  admin:\n    allow: [\"session.prompt\"]\n",
            "destinations:\n  admin:\n    allow: [\"provider:openai\"]\n",
        );
        assert_eq!(
            decide_loaded(
                &lp,
                &principal(),
                &prompt_req(1001, Some("provider:openai"))
            ),
            permit_with_audit()
        );
        assert_eq!(
            decide_loaded(
                &lp,
                &principal(),
                &prompt_req(1002, Some("provider:openai"))
            ),
            Verdict::NotApplicable {
                note: Some("role user: no rule for session.prompt".into())
            }
        );
    }

    #[test]
    fn prompt_is_contained_for_adversary_and_absent_for_guest() {
        let lp = lp_prompt(USER_PROMPT, USER_OPENAI);
        assert_eq!(
            decide_loaded(
                &lp,
                &principal(),
                &prompt_req(1004, Some("provider:openai"))
            ),
            Verdict::Deny {
                reason: "subject contained: role=adversary".into()
            }
        );
        assert_eq!(
            decide_loaded(
                &lp,
                &principal(),
                &prompt_req(1003, Some("provider:openai"))
            ),
            Verdict::NotApplicable {
                note: Some("role guest: no rule for session.prompt".into())
            }
        );
    }

    #[test]
    fn the_other_session_terms_did_not_flip() {
        let lp = lp_prompt(USER_PROMPT, USER_OPENAI);
        for term in ["session.cancel", "session.update"] {
            assert_eq!(
                decide_loaded(&lp, &principal(), &request(Some(1001), term, None)),
                Verdict::NotApplicable {
                    note: Some(format!("term enumerated, not implemented: {term}"))
                }
            );
            assert!(matches!(
                decide_loaded(&lp, &principal(), &request(Some(1002), term, None)),
                Verdict::NotApplicable { .. }
            ));
        }
    }

    #[test]
    fn admin_whoami_is_not_in_the_grantable_set() {
        assert!(
            !GRANTABLE_ACTIONS.contains(&"admin.whoami"),
            "admin.whoami is unconditional for admins; granting it would let an \
             empty roles: block revoke working behaviour"
        );
    }

    // ---- action-scoped grants: the decide arm (#162 step 4) ----

    /// A SEPARATE fixture, so none of `lp_with`'s 16 call sites -- the golden
    /// matrix among them -- ever sees a non-empty grant map. Grants are built
    /// by the REAL validator over REAL parsed YAML: a hand-built `ActionGrants`
    /// would prove the arm and hide the parse-and-validate path feeding it.
    fn lp_with_grants(roles_block: &str, uid_map: &[(&str, u32)]) -> LoadedPolicy {
        let body = format!(
            "schema_version: 1\npermissions:\n  allow:\n    - \"Read(~/**)\"\n  deny:\n    - \"Read(~/.ssh/**)\"\n{roles_block}"
        );
        let policy = maknae_config::parse_authz(&body).unwrap();
        let lookup: UidMap = uid_map.iter().map(|(n, u)| (n.to_string(), *u)).collect();
        let bindings = [
            ("admin", "alex"),
            ("user", "ursula"),
            ("guest", "gwen"),
            ("adversary", "adam"),
        ]
        .into_iter()
        .map(|(r, n)| (r.to_string(), vec![n.to_string()]))
        .collect();
        // Bound BEFORE the literal: `policy` is moved into it. This is also the
        // killer for the `Ok(DestinationGrants::default())` mutant on
        // `validate_destinations`: every permit test builds its allowlist here.
        let destinations = crate::validate_destinations(&policy.destinations).unwrap();
        LoadedPolicy {
            roles: Roles::File(resolve(&Some(bindings), &lookup).unwrap()),
            action_grants: crate::validate_grants(&policy.action_grants).unwrap(),
            destinations,
            subjects: SubjectGrants::default(),
            agents: Default::default(),
            taskers: Default::default(),
            policy,
        }
    }

    const GRANT_UIDS: &[(&str, u32)] = &[
        ("alex", 1001),
        ("ursula", 1002),
        ("gwen", 1003),
        ("adam", 1004),
    ];

    fn kernel_request(uid: u32, action: &str, initiator: Option<&str>) -> SecRequest {
        let mut r = request(Some(i64::from(uid)), action, None);
        if let Some(i) = initiator {
            r.subject
                .0
                .insert(maknae_security::SUBJECT_INITIATOR, AttrValue::Str(i.into()));
        }
        r
    }

    #[test]
    fn kernel_contain_is_permitted_only_for_the_kernel_subject() {
        let lp = lp_with_grants("", GRANT_UIDS);
        assert!(matches!(
            decide_loaded(
                &lp,
                &principal(),
                &kernel_request(70, "kernel.contain", Some("kernel"))
            ),
            Verdict::Permit { .. }
        ));
        for (action, initiator, note) in [
            (
                "kernel.contain",
                None,
                "kernel action requested by a subject that is not the kernel: kernel.contain",
            ),
            (
                "kernel.contain",
                Some("operator"),
                "kernel action requested by a subject that is not the kernel: kernel.contain",
            ),
            (
                "kernel.session.terminate",
                Some("kernel"),
                "term enumerated, not implemented: kernel.session.terminate",
            ),
        ] {
            assert_eq!(
                decide_loaded(&lp, &principal(), &kernel_request(70, action, initiator)),
                Verdict::NotApplicable {
                    note: Some(note.into())
                },
                "{action} {initiator:?}"
            );
        }
    }

    #[test]
    fn the_initiator_attribute_grants_nothing_outside_the_kernel_class() {
        let lp = lp_with_grants("", GRANT_UIDS);
        assert_eq!(
            decide_loaded(
                &lp,
                &principal(),
                &kernel_request(1004, "admin.status", Some("kernel"))
            ),
            Verdict::Deny {
                reason: "subject contained: role=adversary".into()
            }
        );
        for uid in [70, 1001, 1002, 1004] {
            for action in [
                "admin.status",
                "admin.contain",
                "admin.release",
                "liveness.ping",
                "admin.whoami",
                "session.prompt",
                "fs.read",
            ] {
                assert_eq!(
                    decide_loaded(
                        &lp,
                        &principal(),
                        &kernel_request(uid, action, Some("kernel"))
                    ),
                    decide_loaded(&lp, &principal(), &kernel_request(uid, action, None)),
                    "{uid} {action}"
                );
            }
        }
    }

    /// A granted term permits, and ONLY that term. The other two grantable
    /// terms stay `NotApplicable` -- the arm keys on the action, so one grant
    /// is one grant, not a class-granular opening of `admin.*`.
    #[test]
    fn granted_admin_term_permits_and_ungranted_siblings_do_not() {
        let lp = lp_with_grants(
            "roles:\n  admin:\n    allow: [\"admin.status\"]\n",
            GRANT_UIDS,
        );
        let req = |a: &str| request(Some(1001), a, None);
        assert_eq!(
            decide_loaded(&lp, &principal(), &req("admin.status")),
            Verdict::Permit {
                obligations: vec![audit_obligation()]
            }
        );
        for other in ["admin.config.show", "admin.subject.list"] {
            assert_eq!(
                decide_loaded(&lp, &principal(), &req(other)),
                Verdict::NotApplicable {
                    note: Some(format!("role admin: no rule for {other}"))
                },
                "granting one term must not grant `{other}`"
            );
        }
        // And the term that was never grantable is untouched by any of this.
        assert_eq!(
            decide_loaded(&lp, &principal(), &req("admin.whoami")),
            Verdict::Permit {
                obligations: vec![audit_obligation()]
            },
            "admin.whoami keeps its own arm; it is not routed through grants"
        );
    }

    /// An explicit deny beats an explicit allow within the role, and the
    /// verdict NAMES the term that denied it -- so the audit record says which
    /// entry decided, not merely that something did.
    #[test]
    fn denied_admin_term_denies_naming_the_source_even_when_also_allowed() {
        let lp = lp_with_grants(
            "roles:\n  admin:\n    allow: [\"admin.status\", \"admin.config.show\"]\n    deny: [\"admin.status\"]\n",
            GRANT_UIDS,
        );
        assert_eq!(
            decide_loaded(
                &lp,
                &principal(),
                &request(Some(1001), "admin.status", None)
            ),
            Verdict::Deny {
                reason: "denied by role grant admin.status".into()
            }
        );
        // The co-listed allow is unaffected -- deny is per-term, not per-role.
        assert_eq!(
            decide_loaded(
                &lp,
                &principal(),
                &request(Some(1001), "admin.config.show", None)
            ),
            Verdict::Permit {
                obligations: vec![audit_obligation()]
            }
        );
    }

    /// `evaluate3_action` keys on the ROLE, tested DIRECTLY.
    ///
    /// This has to be a unit test on the function. The end-to-end version
    /// (`admin_grants_do_not_leak_to_other_roles`, below) cannot reach it:
    /// `Role::Guest | Role::User` returns `NotApplicable` for every non-liveness
    /// class before the `Role::Admin` block that holds the only call site. So
    /// `evaluate3_action` could ignore `role_key` entirely -- taking the first
    /// value in the map -- and the whole suite stayed green. Measured, not
    /// supposed: that mutation was applied and 58/58 still passed.
    ///
    /// This is what the two-argument form buys, and until now nothing bought it.
    /// A Phase-2 `Role::User` arm calling a one-argument version would silently
    /// receive admin's grants, one layer below where any end-to-end test looks.
    #[test]
    fn evaluate3_action_answers_per_role_not_per_map() {
        let grants = ActionGrants::from_validated(std::collections::BTreeMap::from([(
            "admin".to_string(),
            (
                vec![("admin.status", "admin.status".into())],
                vec![("admin.config.show", "admin.config.show".into())],
            ),
        )]));
        assert_eq!(
            grants.evaluate3_action("admin", "admin.status"),
            maknae_config::Match3::AllowMatch {
                source: "admin.status".into()
            }
        );
        assert_eq!(
            grants.evaluate3_action("admin", "admin.config.show"),
            maknae_config::Match3::DenyMatch {
                source: "admin.config.show".into()
            }
        );
        // The whole point: a DIFFERENT role gets nothing from admin's entry --
        // not the allow, and not the deny either.
        for role in ["user", "guest", "adversary", "", "Admin"] {
            assert_eq!(
                grants.evaluate3_action(role, "admin.status"),
                maknae_config::Match3::NoMatch,
                "role `{role}` must not read admin's allow list"
            );
            assert_eq!(
                grants.evaluate3_action(role, "admin.config.show"),
                maknae_config::Match3::NoMatch,
                "role `{role}` must not read admin's deny list either"
            );
        }
    }

    #[test]
    fn the_baseline_terms_permit_only_a_granted_admin() {
        let lp = lp_with_grants(
            "roles:\n  admin:\n    allow: [\"admin.status\", \"admin.config.show\", \"admin.subject.list\", \"admin.baseline.show\", \"admin.baseline.accept\", \"admin.contain\", \"admin.release\", \"session.prompt\"]\n",
            GRANT_UIDS,
        );
        for term in ["admin.baseline.show", "admin.baseline.accept"] {
            let at = |uid: i64| decide_loaded(&lp, &principal(), &request(Some(uid), term, None));
            assert_eq!(at(1001), permit_with_audit(), "admin {term}");
            for (uid, role) in [(1002, "user"), (1003, "guest")] {
                assert_eq!(
                    at(uid),
                    Verdict::NotApplicable {
                        note: Some(format!("role {role}: no rule for {term}"))
                    },
                    "{role} {term}"
                );
            }
            assert_eq!(
                at(1099),
                Verdict::NotApplicable {
                    note: Some("subject resolves to no role".into())
                },
                "unbound {term}"
            );
            assert_eq!(
                at(1004),
                Verdict::Deny {
                    reason: "subject contained: role=adversary".into()
                },
                "contained {term}"
            );
        }
    }

    /// The end-to-end companion. It pins that the Guest/User arms abstain and
    /// that containment precedes the class match -- NOT that `evaluate3_action`
    /// keys on the role, which it never reaches. See the test above for that.
    #[test]
    fn admin_grants_do_not_leak_to_other_roles() {
        let lp = lp_with_grants(
            "roles:\n  admin:\n    allow: [\"admin.status\"]\n",
            GRANT_UIDS,
        );
        for (uid, role) in [(1002u32, "user"), (1003, "guest")] {
            assert_eq!(
                decide_loaded(
                    &lp,
                    &principal(),
                    &request(Some(uid as i64), "admin.status", None)
                ),
                Verdict::NotApplicable {
                    note: Some(format!("role {role}: no rule for admin.status"))
                },
                "role `{role}` must not inherit admin's grant"
            );
        }
        // Containment is upstream of the class match and stays unconditional.
        assert_eq!(
            decide_loaded(
                &lp,
                &principal(),
                &request(Some(1004), "admin.status", None)
            ),
            Verdict::Deny {
                reason: "subject contained: role=adversary".into()
            },
            "a grant can never reach a contained subject"
        );
    }

    #[test]
    fn contain_and_release_are_granted_separately_and_never_by_membership() {
        let only_release = lp_with_grants(
            "roles:\n  admin:\n    allow: [\"admin.release\"]\n",
            GRANT_UIDS,
        );
        let only_contain = lp_with_grants(
            "roles:\n  admin:\n    allow: [\"admin.contain\"]\n",
            GRANT_UIDS,
        );
        let neither = lp_with_grants("", GRANT_UIDS);
        let permits = |lp: &LoadedPolicy, a: &str| {
            matches!(
                decide_loaded(lp, &principal(), &request(Some(1001), a, None)),
                Verdict::Permit { .. }
            )
        };
        assert!(
            permits(&only_release, "admin.release") && !permits(&only_release, "admin.contain")
        );
        assert!(
            permits(&only_contain, "admin.contain") && !permits(&only_contain, "admin.release")
        );
        assert!(!permits(&neither, "admin.contain") && !permits(&neither, "admin.release"));
        let denied = lp_with_grants(
            "roles:\n  admin:\n    allow: [\"admin.release\"]\n    deny: [\"admin.release\"]\n",
            GRANT_UIDS,
        );
        assert!(matches!(
            decide_loaded(
                &denied,
                &principal(),
                &request(Some(1001), "admin.release", None)
            ),
            Verdict::Deny { .. }
        ));
    }

    #[test]
    fn a_contained_subject_granted_both_terms_is_still_denied_everything() {
        let lp = lp_with_grants(
            "roles:\n  admin:\n    allow: [\"admin.release\", \"admin.contain\", \"admin.status\"]\n",
            GRANT_UIDS,
        );
        for a in [
            "liveness.ping",
            "admin.whoami",
            "admin.status",
            "admin.release",
            "admin.contain",
        ] {
            assert_eq!(
                decide_loaded(&lp, &principal(), &request(Some(1004), a, None)),
                Verdict::Deny {
                    reason: "subject contained: role=adversary".into()
                },
                "{a}"
            );
        }
    }

    /// An empty `roles:` block behaves exactly as an absent one. This is the
    /// assertion that makes the plain-map-not-Option decision in maknae-config
    /// testable rather than merely asserted.
    #[test]
    fn empty_roles_block_leaves_the_grantable_terms_not_applicable() {
        // `decide_prompt`'s NoMatch note is byte-identical to the class arm's on
        // purpose (`no_rule_note`), which is why this loop covers all four.
        for block in ["", "roles: {}\n", "roles:\n  admin: {}\n"] {
            let lp = lp_with_grants(block, GRANT_UIDS);
            for t in GRANTABLE_ACTIONS {
                assert_eq!(
                    decide_loaded(&lp, &principal(), &request(Some(1001), t, None)),
                    Verdict::NotApplicable {
                        note: Some(format!("role admin: no rule for {t}"))
                    },
                    "block {block:?}, term {t}"
                );
            }
        }
    }

    /// GOLDEN MATRIX: roles against management and filesystem requests.
    /// Corrected 2026-09-07, #158: the prior "never edit any verdict" rule
    /// preserved #85's initial user-liveness-only scope beyond its purpose.
    /// Operator-approved ordinary development changes exactly the two user
    /// fs.read cells: a matching allow permits and an explicit path deny denies.
    /// Management, guest, containment, and unknown-action cells are unchanged.
    /// Full verdict equality distinguishes each refusal's actual reason.
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
        // The note argument is #181's only edit to this table (see the dated
        // correction above): the CELL verdicts are untouched.
        let na = |n: &str| Verdict::NotApplicable {
            note: Some(n.into()),
        };

        // (action, path) x (admin 1001, user 1002, guest 1003, adversary 1004)
        // The literal tuple type, NOT a `type Row` alias. clippy::type_complexity
        // fires here and is allowed rather than satisfied: this table's docstring
        // and the plan both say no line of it is ever edited, and an alias
        // extracted for lint comfort makes that claim false the first time
        // someone checks the diff. The shape IS the contract.
        #[allow(clippy::type_complexity)]
        let matrix: &[(&str, Option<&str>, Verdict, Verdict, Verdict, Verdict)] = &[
            (
                "liveness.ping",
                None,
                permit(),
                permit(),
                permit(),
                contained(),
            ),
            (
                "admin.whoami",
                None,
                permit(),
                na("role user: no rule for admin.whoami"),
                na("role guest: no rule for admin.whoami"),
                contained(),
            ),
            (
                "admin.status",
                None,
                na("role admin: no rule for admin.status"),
                na("role user: no rule for admin.status"),
                na("role guest: no rule for admin.status"),
                contained(),
            ),
            (
                "admin.config.show",
                None,
                na("role admin: no rule for admin.config.show"),
                na("role user: no rule for admin.config.show"),
                na("role guest: no rule for admin.config.show"),
                contained(),
            ),
            (
                "admin.subject.list",
                None,
                na("role admin: no rule for admin.subject.list"),
                na("role user: no rule for admin.subject.list"),
                na("role guest: no rule for admin.subject.list"),
                contained(),
            ),
            (
                "admin.baseline.show",
                None,
                na("role admin: no rule for admin.baseline.show"),
                na("role user: no rule for admin.baseline.show"),
                na("role guest: no rule for admin.baseline.show"),
                contained(),
            ),
            (
                "admin.baseline.accept",
                None,
                na("role admin: no rule for admin.baseline.accept"),
                na("role user: no rule for admin.baseline.accept"),
                na("role guest: no rule for admin.baseline.accept"),
                contained(),
            ),
            (
                "fs.read",
                Some("/home/operator/x"),
                permit(),
                permit(),
                na("role guest: no rule for fs.read"),
                contained(),
            ),
            (
                "fs.read",
                Some("/home/operator/.ssh/k"),
                policy_deny(),
                policy_deny(),
                na("role guest: no rule for fs.read"),
                contained(),
            ),
            (
                "unknown.thing",
                None,
                na("term enumerated, not implemented: unknown.thing"),
                na("role user: no rule for unknown.thing"),
                na("role guest: no rule for unknown.thing"),
                contained(),
            ),
        ];

        for (action, path, adm, usr, gst, adv) in matrix {
            for (uid, role, expected) in [
                (1001i64, "admin", adm),
                (1002, "user", usr),
                (1003, "guest", gst),
                (1004, "adversary", adv),
            ] {
                let req = request(Some(uid), action, *path);
                assert_eq!(
                    &decide_loaded(&lp, &principal(), &req),
                    expected,
                    "role={role} action={action} path={path:?}"
                );
            }
        }

        let mut lp = lp_with(
            Some(&[("user", &["ursula", SENTINEL][..])]),
            &[("ursula", 1002), (SENTINEL, SENTINEL_UID)],
        );
        let entry = maknae_config::parse_authz(&format!(
            "schema_version: 1\n{}",
            sentinel_entry(
                "    permissions:\n      allow: [\"Read(~/notes/**)\"]\n    actions:\n      allow: [\"fs.read\"]\n"
            )
        ))
        .unwrap();
        let lookups: crate::Lookups = [(SENTINEL.to_string(), Some(SENTINEL_UID))].into();
        lp.subjects = crate::validate_subjects(&entry, &lookups).unwrap();
        let limited = |a: &str| Verdict::Deny {
            reason: format!("subject {SENTINEL}: {a} is not in subjects.{SENTINEL}.actions allow"),
        };
        let subject_row: &[(&str, Option<&str>, Verdict)] = &[
            ("liveness.ping", None, permit()),
            (
                "admin.whoami",
                None,
                na("role user: no rule for admin.whoami"),
            ),
            ("admin.status", None, limited("admin.status")),
            ("admin.config.show", None, limited("admin.config.show")),
            ("admin.subject.list", None, limited("admin.subject.list")),
            ("admin.baseline.show", None, limited("admin.baseline.show")),
            (
                "admin.baseline.accept",
                None,
                limited("admin.baseline.accept"),
            ),
            (
                "fs.read",
                Some("/home/operator/x"),
                na("role user: no capability entry for fs.read"),
            ),
            ("fs.read", Some("/home/operator/.ssh/k"), policy_deny()),
            (
                "unknown.thing",
                None,
                na("role user: no rule for unknown.thing"),
            ),
        ];
        assert_eq!(subject_row.len(), matrix.len());
        for (action, path, expected) in subject_row {
            assert_eq!(
                &decide_loaded(
                    &lp,
                    &principal(),
                    &request(Some(i64::from(SENTINEL_UID)), action, *path)
                ),
                expected,
                "subject action={action} path={path:?}"
            );
        }
    }

    /// Each new class RESOLVES (so this cannot pass merely because `class_of`
    /// returns None, as it would have before the rename) and ABSTAINS. Adding
    /// a permissive arm for any of them turns this red.
    #[test]
    fn every_new_class_resolves_and_abstains() {
        let lp = lp_with(None, &[]);
        for (action, expect, note) in [
            (
                "terminal.create",
                Class::Terminal,
                "term enumerated, not implemented",
            ),
            (
                "mcp.tool.call",
                Class::Mcp,
                "term enumerated, not implemented",
            ),
            ("fs.move", Class::Fs, "term enumerated, not implemented"),
            ("fs.link", Class::Fs, "term enumerated, not implemented"),
            (
                "kernel.contain",
                Class::Kernel,
                "kernel action requested by a subject that is not the kernel",
            ),
        ] {
            assert_eq!(class_of(action), Some(expect), "{action} must resolve");
            assert_eq!(
                decide_loaded(
                    &lp,
                    &principal(),
                    &request(Some(OPERATOR_UID as i64), action, Some("/home/operator/x")),
                ),
                Verdict::NotApplicable {
                    note: Some(format!("{note}: {action}"))
                },
                "{action} must abstain"
            );
        }
        // `session.prompt` still resolves; its abstention is pinned by
        // `prompt_without_the_action_grant_is_an_absence_even_with_a_destination`
        // with a different note, because the arm exists now (#172).
        assert_eq!(class_of("session.prompt"), Some(Class::Session));
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
                &request(Some(OPERATOR_UID as i64), action, path),
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
    fn canonical_pregate_rejections_name_the_offense() {
        assert_eq!(canonical_violation("relative/x"), Some("not absolute"));
        assert!(canonical_violation("/a//b").unwrap().contains("empty"));
        assert!(canonical_violation("/a/b/").unwrap().contains("empty"));
        assert!(canonical_violation("/a/./b").unwrap().contains("'.'"));
        assert!(canonical_violation("/a/../b").unwrap().contains("'..'"));
        assert_eq!(canonical_violation("/"), None);
        assert_eq!(canonical_violation("/a/b"), None);
    }

    #[test]
    fn decide_loaded_cited_names_the_entry_for_every_cited_arm() {
        let lp = lp_with_grants(
            "roles:\n  admin:\n    allow: [\"admin.status\", \"session.prompt\"]\n    deny: [\"admin.config.show\"]\n  user:\n    allow: [\"session.prompt\"]\n    deny: [\"session.prompt\"]\ndestinations:\n  admin:\n    allow: [\"provider:openai\"]\n",
            GRANT_UIDS,
        );
        let path = |uid: u32, p: &str| request(Some(i64::from(uid)), "fs.read", Some(p));
        let act = |uid: u32, a: &str| request(Some(i64::from(uid)), a, None);
        let cases: Vec<(SecRequest, Option<&'static str>, Option<Cited>)> = vec![
            (
                path(1001, "/home/operator/.ssh/id_ed25519"),
                Some("admin"),
                Some(Cited::Path {
                    effect: Effect::Deny,
                    source: "Read(~/.ssh/**)".into(),
                }),
            ),
            (
                path(1002, "/home/operator/notes"),
                Some("user"),
                Some(Cited::Path {
                    effect: Effect::Allow,
                    source: "Read(~/**)".into(),
                }),
            ),
            (
                act(1001, "admin.config.show"),
                Some("admin"),
                Some(Cited::Grant {
                    role: "admin",
                    term: "admin.config.show".into(),
                    effect: Effect::Deny,
                }),
            ),
            (
                act(1001, "admin.status"),
                Some("admin"),
                Some(Cited::Grant {
                    role: "admin",
                    term: "admin.status".into(),
                    effect: Effect::Allow,
                }),
            ),
            (
                prompt_req(1001, Some("provider:openai")),
                Some("admin"),
                Some(Cited::Destination {
                    role: "admin",
                    destination: "provider:openai".into(),
                }),
            ),
            (
                prompt_req(1002, Some("provider:openai")),
                Some("user"),
                Some(Cited::Grant {
                    role: "user",
                    term: "session.prompt".into(),
                    effect: Effect::Deny,
                }),
            ),
            (
                prompt_req(1001, Some("provider:other")),
                Some("admin"),
                None,
            ),
            (act(1001, "liveness.ping"), Some("admin"), None),
            (act(1001, "admin.subject.list"), Some("admin"), None),
            (path(1001, "/etc/passwd"), Some("admin"), None),
            (act(1004, "liveness.ping"), Some("adversary"), None),
            (act(9999, "liveness.ping"), None, None),
        ];
        for (req, role, cited) in cases {
            let d = decide_loaded_cited(&lp, &principal(), &req);
            assert_eq!((d.role, &d.cited), (role, &cited), "{}", req.action.0);
            assert_eq!(
                decide_loaded_with_role(&lp, &principal(), &req),
                (d.verdict.clone(), d.role)
            );
            if cited.is_some() {
                assert!(!matches!(d.verdict, Verdict::NotApplicable { .. }));
            }
        }
    }

    const SENTINEL: &str = "subject-608-sentinel";
    const SENTINEL_UID: u32 = 1608;
    const SUBJECT_SITE: &str = "schema_version: 1\npermissions:\n  allow: [\"Read(~/**)\", \"Write(~/**)\"]\n  deny: [\"Read(~/.ssh/**)\"]\nroles:\n  admin:\n    allow: [\"admin.status\", \"session.prompt\"]\n  user:\n    allow: [\"session.prompt\"]\ndestinations:\n  admin:\n    allow: [\"provider:openai\"]\n  user:\n    allow: [\"provider:openai\"]\n";

    fn subject_lookups() -> crate::Lookups {
        [("operator", OPERATOR_UID), (SENTINEL, SENTINEL_UID)]
            .into_iter()
            .map(|(n, u)| (n.to_string(), Some(u)))
            .collect()
    }

    fn lp_subject(role: &str, subjects_block: &str) -> LoadedPolicy {
        let policy =
            maknae_config::parse_authz(&format!("{SUBJECT_SITE}{subjects_block}")).unwrap();
        let mut bindings: BTreeMap<String, Vec<String>> = BTreeMap::new();
        bindings.insert("admin".into(), vec!["operator".into()]);
        bindings
            .entry(role.into())
            .or_default()
            .push(SENTINEL.into());
        let lookups = subject_lookups();
        let uid_map: UidMap = crate::found(&lookups);
        LoadedPolicy {
            roles: Roles::File(resolve(&Some(bindings), &uid_map).unwrap()),
            action_grants: crate::validate_grants(&policy.action_grants).unwrap(),
            destinations: crate::validate_destinations(&policy.destinations).unwrap(),
            subjects: crate::validate_subjects(&policy, &lookups).unwrap(),
            agents: Default::default(),
            taskers: Default::default(),
            policy,
        }
    }

    fn sentinel_entry(body: &str) -> String {
        format!("subjects:\n  {SENTINEL}:\n{body}")
    }

    fn fs_op(uid: u32, action: &str, rel: &str) -> SecRequest {
        let mut r = request(
            Some(i64::from(uid)),
            action,
            Some(&format!("{REQUESTER_HOME}/{rel}")),
        );
        let op = match action {
            "fs.read" => "read",
            "fs.write" => "write-existing",
            "fs.delete" => "delete-entry",
            _ => "mkdir",
        };
        r.context.0.insert(
            maknae_security::CONTEXT_FS_OPERATION,
            AttrValue::Str(op.into()),
        );
        r
    }

    fn any_action(uid: u32, action: &str) -> SecRequest {
        match action {
            "session.prompt" => prompt_req(uid, Some("provider:openai")),
            a if a.starts_with("fs.") => fs_op(uid, a, "x"),
            a => request(Some(i64::from(uid)), a, None),
        }
    }

    fn assert_limited(d: &Decided, action: &str) {
        assert!(
            matches!(&d.verdict, Verdict::Deny { reason } if reason.contains(SENTINEL) && reason.contains(action) && reason.contains("subjects")),
            "{action}: {d:?}"
        );
        assert_eq!(d.cited, None, "{action}");
    }

    fn site(effect: Effect, source: &str) -> Option<Cited> {
        Some(Cited::Path {
            effect,
            source: source.into(),
        })
    }

    fn by_subject(effect: Effect, source: &str) -> Option<Cited> {
        Some(Cited::SubjectPath {
            subject: SENTINEL.into(),
            effect,
            source: source.into(),
        })
    }

    #[test]
    fn a_subject_allow_replaces_the_site_allow() {
        let lp = lp_subject(
            "user",
            &sentinel_entry("    permissions:\n      allow: [\"Read(~/notes/**)\"]\n"),
        );
        let notes = decide_loaded_cited(
            &lp,
            &principal(),
            &fs_op(SENTINEL_UID, "fs.read", "notes/a"),
        );
        assert_eq!(
            (notes.verdict, notes.cited),
            (
                permit_with_audit(),
                by_subject(Effect::Allow, "Read(~/notes/**)")
            )
        );
        let other = decide_loaded_cited(&lp, &principal(), &fs_op(SENTINEL_UID, "fs.read", "b"));
        assert!(
            matches!(
                maknae_security::finalize(other.verdict),
                maknae_security::Decision::Deny { .. }
            ),
            "the site allow Read(~/**) must not reach a subject with its own set"
        );
        assert_eq!(other.cited, None);
    }

    #[test]
    fn the_site_deny_floor_holds_under_a_subject_set() {
        let lp = lp_subject(
            "user",
            &sentinel_entry(
                "    permissions:\n      allow: [\"Read(~/**)\"]\n      deny: [\"Read(~/private/**)\"]\n",
            ),
        );
        let ask = |rel: &str| {
            let d = decide_loaded_cited(&lp, &principal(), &fs_op(SENTINEL_UID, "fs.read", rel));
            (d.verdict, d.cited)
        };
        assert_eq!(
            ask(".ssh/id_ed25519"),
            (
                Verdict::Deny {
                    reason: "denied by policy entry Read(~/.ssh/**)".into()
                },
                site(Effect::Deny, "Read(~/.ssh/**)")
            )
        );
        assert_eq!(
            ask("private/k"),
            (
                Verdict::Deny {
                    reason: format!(
                        "denied by subjects.{SENTINEL}.permissions entry Read(~/private/**)"
                    )
                },
                by_subject(Effect::Deny, "Read(~/private/**)")
            )
        );
        assert_eq!(
            ask("notes"),
            (permit_with_audit(), by_subject(Effect::Allow, "Read(~/**)"))
        );
    }

    #[test]
    fn a_delete_tree_is_decided_by_the_subject_set() {
        let delete_tree = |rel: &str| {
            let mut r = fs_op(SENTINEL_UID, "fs.delete", rel);
            r.context.0.insert(
                maknae_security::CONTEXT_FS_OPERATION,
                AttrValue::Str("delete-tree".into()),
            );
            r
        };
        let narrow = lp_subject(
            "user",
            &sentinel_entry("    permissions:\n      allow: [\"Read(~/notes/**)\"]\n"),
        );
        let refused = decide_loaded_cited(&narrow, &principal(), &delete_tree("x"));
        assert!(
            matches!(
                maknae_security::finalize(refused.verdict.clone()),
                maknae_security::Decision::Deny { .. }
            ),
            "the site Write(~/**) must not reach a subject with its own set: {refused:?}"
        );
        assert_eq!(refused.cited, None);
        let covering = lp_subject(
            "user",
            &sentinel_entry("    permissions:\n      allow: [\"Write(~/scratch/**)\"]\n"),
        );
        let permitted = decide_loaded_cited(&covering, &principal(), &delete_tree("scratch/x"));
        assert_eq!(
            (permitted.verdict, permitted.cited),
            (
                permit_with_audit(),
                by_subject(Effect::Allow, "Write(~/scratch/**)")
            )
        );
    }

    #[test]
    fn an_empty_subject_permission_set_grants_no_file_access() {
        let lp = lp_subject("admin", &sentinel_entry("    permissions: {}\n"));
        for action in ["fs.read", "fs.write", "fs.delete", "fs.mkdir"] {
            let d = decide_loaded_cited(&lp, &principal(), &fs_op(SENTINEL_UID, action, "x"));
            assert_eq!(
                (d.verdict, d.cited),
                (
                    Verdict::NotApplicable {
                        note: Some(format!("role admin: no capability entry for {action}"))
                    },
                    None
                ),
                "{action}"
            );
        }
        let ssh = decide_loaded_cited(&lp, &principal(), &fs_op(SENTINEL_UID, "fs.read", ".ssh/k"));
        assert_eq!(ssh.cited, site(Effect::Deny, "Read(~/.ssh/**)"));
    }

    #[test]
    fn a_subject_without_an_entry_is_decided_as_today() {
        let with = lp_subject(
            "user",
            "subjects:\n  operator:\n    permissions:\n      allow: []\n    actions:\n      allow: []\n",
        );
        let without = lp_subject("user", "");
        assert_eq!(without.subjects, SubjectGrants::default());
        assert!(with.subjects.get(OPERATOR_UID).is_some());
        for action in [
            "fs.read",
            "fs.write",
            "fs.delete",
            "fs.mkdir",
            "session.prompt",
            "admin.status",
            "liveness.ping",
        ] {
            let req = any_action(SENTINEL_UID, action);
            assert_eq!(
                decide_loaded_cited(&with, &principal(), &req),
                decide_loaded_cited(&without, &principal(), &req),
                "{action}"
            );
        }
    }

    #[test]
    fn the_entry_is_keyed_on_the_requester_not_the_principal() {
        let lp = lp_subject(
            "admin",
            &sentinel_entry(
                "    permissions:\n      allow: [\"Read(~/notes/**)\"]\n    actions:\n      allow: [\"fs.read\"]\n",
            ),
        );
        let sentinel_read =
            decide_loaded_cited(&lp, &principal(), &fs_op(SENTINEL_UID, "fs.read", "b"));
        assert!(matches!(
            sentinel_read.verdict,
            Verdict::NotApplicable { .. }
        ));
        assert_limited(
            &decide_loaded_cited(&lp, &principal(), &any_action(SENTINEL_UID, "admin.status")),
            "admin.status",
        );
        let principal_read =
            decide_loaded_cited(&lp, &principal(), &fs_op(OPERATOR_UID, "fs.read", "b"));
        assert_eq!(
            (principal_read.verdict, principal_read.cited),
            (permit_with_audit(), site(Effect::Allow, "Read(~/**)"))
        );
        assert!(matches!(
            decide_loaded(&lp, &principal(), &any_action(OPERATOR_UID, "admin.status")),
            Verdict::Permit { .. }
        ));
    }

    #[test]
    fn a_subject_action_limit_refuses_unlisted_actions() {
        let lp = lp_subject(
            "user",
            &sentinel_entry("    actions:\n      allow: [\"fs.read\"]\n"),
        );
        for action in ["fs.write", "fs.delete", "fs.mkdir", "session.prompt"] {
            assert_limited(
                &decide_loaded_cited(&lp, &principal(), &any_action(SENTINEL_UID, action)),
                action,
            );
        }
        let read = decide_loaded_cited(&lp, &principal(), &fs_op(SENTINEL_UID, "fs.read", "x"));
        assert_eq!(
            (read.verdict, read.cited),
            (permit_with_audit(), site(Effect::Allow, "Read(~/**)"))
        );
        let ssh = decide_loaded_cited(&lp, &principal(), &fs_op(SENTINEL_UID, "fs.read", ".ssh/k"));
        assert_eq!(ssh.cited, site(Effect::Deny, "Read(~/.ssh/**)"));
    }

    fn model_req(uid: u32, model: Option<AttrValue>) -> SecRequest {
        let mut r = prompt_req(uid, Some("provider:openai"));
        if let Some(m) = model {
            r.resource.0.insert("model", m);
        }
        r
    }

    #[test]
    fn a_subject_model_limit_refuses_an_unlisted_model() {
        let lp = lp_subject(
            "user",
            &sentinel_entry("    models:\n      allow: [\"openai/a\"]\n"),
        );
        let b = decide_loaded_cited(
            &lp,
            &principal(),
            &model_req(SENTINEL_UID, Some(AttrValue::Str("openai/b".into()))),
        );
        assert!(
            matches!(&b.verdict, Verdict::Deny { reason } if reason.contains(SENTINEL) && reason.contains("openai/b") && reason.contains("subjects")),
            "{b:?}"
        );
        assert_eq!(b.cited, None);
        let a = decide_loaded_cited(
            &lp,
            &principal(),
            &model_req(SENTINEL_UID, Some(AttrValue::Str("openai/a".into()))),
        );
        assert!(matches!(a.verdict, Verdict::Permit { .. }), "{a:?}");
        for bad in [None, Some(AttrValue::Int(1))] {
            let d = decide_loaded_cited(&lp, &principal(), &model_req(SENTINEL_UID, bad));
            assert_eq!(d.verdict, Verdict::Indeterminate);
        }
    }

    #[test]
    fn an_extra_model_entry_does_not_block_a_listed_model_and_an_entry_free_subject_is_not_asked_for_a_model(
    ) {
        let lp = lp_subject(
            "user",
            &sentinel_entry("    models:\n      allow: [\"openai/gone\", \"openai/a\"]\n"),
        );
        let a = decide_loaded_cited(
            &lp,
            &principal(),
            &model_req(SENTINEL_UID, Some(AttrValue::Str("openai/a".into()))),
        );
        assert!(matches!(a.verdict, Verdict::Permit { .. }), "{a:?}");
        let lp = lp_subject(
            "user",
            &sentinel_entry("    actions:\n      allow: [\"session.prompt\"]\n"),
        );
        let d = decide_loaded_cited(&lp, &principal(), &model_req(SENTINEL_UID, None));
        assert!(matches!(d.verdict, Verdict::Permit { .. }), "{d:?}");
    }

    #[test]
    fn a_family_wildcard_admits_the_whole_family() {
        let lp = lp_subject(
            "user",
            &sentinel_entry("    actions:\n      allow: [\"fs.*\"]\n"),
        );
        for action in ["fs.read", "fs.write", "fs.delete", "fs.mkdir"] {
            assert_eq!(
                decide_loaded(&lp, &principal(), &fs_op(SENTINEL_UID, action, "x")),
                permit_with_audit(),
                "{action}"
            );
        }
        assert_limited(
            &decide_loaded_cited(
                &lp,
                &principal(),
                &any_action(SENTINEL_UID, "session.prompt"),
            ),
            "session.prompt",
        );
    }

    #[test]
    fn a_specific_deny_beats_a_family_allow() {
        let lp = lp_subject(
            "user",
            &sentinel_entry("    actions:\n      allow: [\"fs.*\"]\n      deny: [\"fs.delete\"]\n"),
        );
        assert_limited(
            &decide_loaded_cited(&lp, &principal(), &fs_op(SENTINEL_UID, "fs.delete", "x")),
            "fs.delete",
        );
        for action in ["fs.read", "fs.write", "fs.mkdir"] {
            assert_eq!(
                decide_loaded(&lp, &principal(), &fs_op(SENTINEL_UID, action, "x")),
                permit_with_audit(),
                "{action}"
            );
        }
    }

    #[test]
    fn a_family_deny_beats_a_specific_allow() {
        let lp = lp_subject(
            "user",
            &sentinel_entry("    actions:\n      allow: [\"fs.read\"]\n      deny: [\"fs.*\"]\n"),
        );
        let d = decide_loaded_cited(&lp, &principal(), &fs_op(SENTINEL_UID, "fs.read", "x"));
        assert_limited(&d, "fs.read");
        assert!(
            matches!(&d.verdict, Verdict::Deny { reason } if reason.contains("fs.*")),
            "the deny names the entry as written: {d:?}"
        );
    }

    #[test]
    fn an_empty_action_list_refuses_every_limited_action_but_not_liveness() {
        for role in ["admin", "user"] {
            let lp = lp_subject(role, &sentinel_entry("    actions:\n      allow: []\n"));
            for action in [
                "fs.read",
                "fs.write",
                "session.prompt",
                "admin.status",
                "terminal.create",
                "mcp.tool.call",
            ] {
                assert_limited(
                    &decide_loaded_cited(&lp, &principal(), &any_action(SENTINEL_UID, action)),
                    action,
                );
            }
            assert_eq!(
                decide_loaded(
                    &lp,
                    &principal(),
                    &any_action(SENTINEL_UID, "liveness.ping")
                ),
                permit_with_audit(),
                "{role}"
            );
            let unknown = decide_loaded(
                &lp,
                &principal(),
                &any_action(SENTINEL_UID, "unknown.thing"),
            );
            assert!(
                matches!(unknown, Verdict::NotApplicable { .. }),
                "{role}: {unknown:?}"
            );
        }
    }

    #[test]
    fn a_subject_entry_cannot_widen_a_structural_role() {
        let wide = "    permissions:\n      allow: [\"Read(~/**)\", \"Write(~/**)\"]\n    actions:\n      allow: [\"fs.*\", \"session.*\", \"admin.*\"]\n";
        let guest = lp_subject("guest", &sentinel_entry(wide));
        let bare_guest = lp_subject("guest", "");
        for action in ["fs.read", "fs.write", "session.prompt", "admin.status"] {
            let got = decide_loaded_cited(&guest, &principal(), &any_action(SENTINEL_UID, action));
            assert_eq!(
                got,
                decide_loaded_cited(&bare_guest, &principal(), &any_action(SENTINEL_UID, action)),
                "{action}"
            );
            assert!(
                matches!(got.verdict, Verdict::NotApplicable { .. }),
                "{action}"
            );
        }
        let adversary = lp_subject(
            "adversary",
            &sentinel_entry("    actions:\n      allow: [\"fs.read\"]\n"),
        );
        for action in ["fs.write", "fs.read", "session.prompt", "liveness.ping"] {
            assert_eq!(
                decide_loaded_cited(&adversary, &principal(), &any_action(SENTINEL_UID, action)),
                Decided {
                    verdict: Verdict::Deny {
                        reason: "subject contained: role=adversary".into()
                    },
                    role: Some("adversary"),
                    cited: None,
                },
                "{action}"
            );
        }
    }

    #[test]
    fn an_actions_limit_never_revokes_whoami() {
        let today = decide_loaded_cited(
            &lp_subject("admin", ""),
            &principal(),
            &any_action(SENTINEL_UID, "admin.whoami"),
        );
        assert_eq!(today.verdict, permit_with_audit());
        for list in ["[\"admin.*\"]", "[]"] {
            let lp = lp_subject(
                "admin",
                &sentinel_entry(&format!("    actions:\n      allow: {list}\n")),
            );
            assert_eq!(
                decide_loaded_cited(&lp, &principal(), &any_action(SENTINEL_UID, "admin.whoami")),
                today,
                "{list}"
            );
        }
        let named = maknae_config::parse_authz(&format!(
            "{SUBJECT_SITE}{}",
            sentinel_entry("    actions:\n      allow: [\"admin.whoami\"]\n")
        ))
        .unwrap();
        assert_eq!(
            crate::validate_subjects(&named, &subject_lookups()),
            Err(crate::AuthzBasicError::UnknownAction("admin.whoami".into()))
        );
    }

    const HOBI_UID: u32 = 2001;
    const HUMAN_UID: u32 = 1002;
    const AGENT_SITE: &str = "schema_version: 1\npermissions:\n  allow: [\"Read(~/**)\"]\n  deny: [\"Read(~/.ssh/**)\"]\nroles:\n  admin:\n    allow: [\"admin.*\", \"session.prompt\"]\n  user:\n    allow: [\"session.prompt\"]\ndestinations:\n  admin:\n    allow: [\"provider:openai\"]\n  user:\n    allow: [\"provider:openai\"]\n";

    fn lp_agent_over(role: &str, agent_policy: Option<&str>, enrolled: bool) -> LoadedPolicy {
        let policy = maknae_config::parse_authz(AGENT_SITE).unwrap();
        let lookups: crate::Lookups = [
            ("operator", OPERATOR_UID),
            ("hobi-svc", HOBI_UID),
            ("ursula", HUMAN_UID),
        ]
        .into_iter()
        .map(|(n, u)| (n.to_string(), Some(u)))
        .collect();
        let mut bindings: BTreeMap<String, Vec<String>> = BTreeMap::new();
        bindings.insert("admin".into(), vec!["operator".into()]);
        bindings
            .entry("user".into())
            .or_default()
            .push("ursula".into());
        if !role.is_empty() {
            bindings
                .entry(role.into())
                .or_default()
                .push("hobi-svc".into());
        }
        let mut subjects = crate::validate_subjects(&policy, &lookups).unwrap();
        let mut agents = AgentUids::default();
        if enrolled {
            let id = maknae_config::AgentId::parse("hobi").unwrap();
            let outcome = crate::AgentOutcome {
                load: maknae_config::AgentsLoad {
                    enrollments: Vec::new(),
                    policies: agent_policy
                        .map(|b| maknae_config::parse_agent_policy(&id, b).unwrap())
                        .into_iter()
                        .collect(),
                    skipped: Vec::new(),
                },
                enrolled: [(
                    id,
                    (HOBI_UID, "hobi-svc".into(), maknae_config::AgentRole::User),
                )]
                .into(),
                problems: Vec::new(),
                taskers: Default::default(),
            };
            crate::agent_subjects(&outcome, &mut subjects).unwrap();
            agents.0.insert(HOBI_UID, "hobi".into());
        }
        LoadedPolicy {
            roles: Roles::File(resolve(&Some(bindings), &crate::found(&lookups)).unwrap()),
            action_grants: crate::validate_grants(&policy.action_grants).unwrap(),
            destinations: crate::validate_destinations(&policy.destinations).unwrap(),
            subjects,
            agents,
            taskers: Default::default(),
            policy,
        }
    }

    fn lp_agent(role: &str, agent_policy: Option<&str>) -> LoadedPolicy {
        lp_agent_over(role, agent_policy, true)
    }

    fn on_channel(mut r: SecRequest, channel: Option<&str>, agent: Option<&str>) -> SecRequest {
        if let Some(c) = channel {
            r.subject
                .0
                .insert(maknae_security::SUBJECT_CHANNEL, AttrValue::Str(c.into()));
        }
        if let Some(a) = agent {
            r.subject
                .0
                .insert(maknae_security::SUBJECT_AGENT, AttrValue::Str(a.into()));
        }
        r
    }

    fn as_hobi(action: &str) -> SecRequest {
        on_channel(
            any_action(HOBI_UID, action),
            Some(maknae_security::CHANNEL_AGENT),
            Some("hobi"),
        )
    }

    fn deny(reason: &str) -> Verdict {
        Verdict::Deny {
            reason: reason.into(),
        }
    }

    fn admin_terms() -> impl Iterator<Item = &'static str> {
        GRANTABLE_ACTIONS
            .into_iter()
            .filter(|t| class_of(t) == Some(Class::Admin))
    }

    #[test]
    fn an_agent_with_admin_wildcard_in_its_policy_is_denied() {
        let lp = lp_agent(
            "user",
            Some("schema_version: 1\nactions:\n  allow: [\"admin.*\"]\n"),
        );
        let d = decide_loaded_cited(&lp, &principal(), &as_hobi("admin.status"));
        assert_eq!(
            d.verdict,
            deny("agent hobi: admin.status is never permitted to an agent")
        );
        assert_eq!(d.role, Some("user"));
    }

    #[test]
    fn an_agent_bound_to_admin_with_a_role_grant_is_still_denied() {
        let lp = lp_agent("admin", None);
        for term in admin_terms() {
            let d = decide_loaded_cited(&lp, &principal(), &as_hobi(term));
            assert!(
                matches!(&d.verdict, Verdict::Deny { reason } if reason.contains("hobi")),
                "{term}: {d:?}"
            );
            let human = decide_loaded_cited(&lp, &principal(), &any_action(OPERATOR_UID, term));
            assert_eq!(human.verdict, permit_with_audit(), "{term}");
        }
    }

    #[test]
    fn a_user_agent_may_ask_whoami() {
        let d = decide_loaded_cited(
            &lp_agent("user", None),
            &principal(),
            &as_hobi("admin.whoami"),
        );
        assert_eq!(d.verdict, permit_with_audit());
        assert_eq!(d.role, Some("user"));
        let guest = lp_agent("guest", None);
        assert_eq!(
            decide_loaded_cited(&guest, &principal(), &as_hobi("admin.whoami")).verdict,
            permit_with_audit()
        );
        let human =
            decide_loaded_cited(&guest, &principal(), &any_action(HUMAN_UID, "admin.whoami"));
        assert!(
            matches!(human.verdict, Verdict::NotApplicable { .. }),
            "{human:?}"
        );
    }

    #[test]
    fn a_whoami_permit_follows_the_action_limit() {
        let lp = lp_agent(
            "user",
            Some("schema_version: 1\nactions:\n  allow: []\n  deny: [\"admin.*\"]\n"),
        );
        assert_eq!(
            decide_loaded_cited(&lp, &principal(), &as_hobi("admin.whoami")).verdict,
            permit_with_audit()
        );
        assert_eq!(
            decide_loaded_cited(&lp, &principal(), &as_hobi("session.prompt")).verdict,
            deny("subject hobi-svc: session.prompt is not in agents.hobi.policy.actions allow")
        );
    }

    #[test]
    fn an_enrolled_agent_resolving_to_admin_is_denied_everything() {
        let lp = lp_agent("admin", None);
        for action in ["admin.whoami", "liveness.ping", "session.prompt", "fs.read"] {
            let d = decide_loaded_cited(&lp, &principal(), &as_hobi(action));
            assert_eq!(
                d.verdict,
                deny("agent hobi: an agent never holds admin"),
                "{action}"
            );
            assert_eq!(d.role, Some("admin"), "{action}");
        }
    }

    #[test]
    fn the_pdp_refuses_an_agent_channel_request_whose_agent_names_another_uid() {
        let lp = lp_agent("user", None);
        let agent = Some(maknae_security::CHANNEL_AGENT);
        for (uid, named, reason) in [
            (
                HOBI_UID,
                Some("suga"),
                "agent channel: uid 2001 is not enrolled agent suga",
            ),
            (
                HOBI_UID,
                None,
                "agent channel: uid 2001 is not enrolled agent (none)",
            ),
            (
                HUMAN_UID,
                Some("hobi"),
                "agent channel: uid 1002 is not enrolled agent hobi",
            ),
        ] {
            let d = decide_loaded_cited(
                &lp,
                &principal(),
                &on_channel(any_action(uid, "liveness.ping"), agent, named),
            );
            assert_eq!(
                d,
                Decided {
                    verdict: deny(reason),
                    role: None,
                    cited: None
                },
                "{uid} {named:?}"
            );
        }
        let mut wrong_type = any_action(HOBI_UID, "liveness.ping");
        wrong_type.subject.0.insert(
            maknae_security::SUBJECT_CHANNEL,
            AttrValue::Str("agent".into()),
        );
        wrong_type
            .subject
            .0
            .insert(maknae_security::SUBJECT_AGENT, AttrValue::Int(2001));
        assert_eq!(
            decide_loaded_cited(&lp, &principal(), &wrong_type).verdict,
            deny("agent channel: uid 2001 is not enrolled agent (none)")
        );
    }

    #[test]
    fn an_agent_uid_on_the_client_channel_is_denied() {
        for role in ["user", "guest", "admin", "adversary"] {
            let lp = lp_agent(role, None);
            for channel in [Some(maknae_security::CHANNEL_CLIENT), None] {
                for action in ["liveness.ping", "admin.whoami"] {
                    let d = decide_loaded_cited(
                        &lp,
                        &principal(),
                        &on_channel(any_action(HOBI_UID, action), channel, Some("hobi")),
                    );
                    assert_eq!(
                        d,
                        Decided {
                            verdict: deny("agent hobi: not on the agent channel"),
                            role: None,
                            cited: None
                        },
                        "{role} {channel:?} {action}"
                    );
                }
            }
        }
    }

    #[test]
    fn a_human_on_the_agent_channel_is_denied() {
        let lp = lp_agent("user", None);
        for uid in [HUMAN_UID, OPERATOR_UID, OTHER_UID] {
            let d = decide_loaded_cited(
                &lp,
                &principal(),
                &on_channel(
                    any_action(uid, "liveness.ping"),
                    Some(maknae_security::CHANNEL_AGENT),
                    None,
                ),
            );
            assert_eq!(
                d.verdict,
                deny(&format!(
                    "agent channel: uid {uid} is not enrolled agent (none)"
                )),
                "{uid}"
            );
            assert_eq!(d.role, None, "{uid}");
        }
    }

    #[test]
    fn an_unrecognised_channel_is_denied() {
        let lp = lp_agent("user", None);
        for uid in [HUMAN_UID, HOBI_UID] {
            let mut r = any_action(uid, "liveness.ping");
            r.subject.0.insert(
                maknae_security::SUBJECT_CHANNEL,
                AttrValue::Str("remote".into()),
            );
            assert_eq!(
                decide_loaded_cited(&lp, &principal(), &r).verdict,
                deny(&format!("channel: uid {uid} arrived on no known channel")),
                "{uid}"
            );
            r.subject
                .0
                .insert(maknae_security::SUBJECT_CHANNEL, AttrValue::Int(1));
            assert_eq!(
                decide_loaded_cited(&lp, &principal(), &r).verdict,
                deny(&format!("channel: uid {uid} arrived on no known channel")),
                "{uid}"
            );
        }
    }

    #[test]
    fn a_contained_agent_is_reported_contained() {
        let lp = lp_agent("adversary", None);
        assert_eq!(
            agent_arm(
                &lp.agents,
                lp.subjects.get(HOBI_UID),
                HOBI_UID,
                Role::Adversary,
                &as_hobi("admin.whoami")
            ),
            Some(deny("subject contained: role=adversary"))
        );
        for action in ["liveness.ping", "admin.whoami", "admin.status"] {
            assert_eq!(
                decide_loaded_cited(&lp, &principal(), &as_hobi(action)),
                Decided {
                    verdict: deny("subject contained: role=adversary"),
                    role: Some("adversary"),
                    cited: None
                },
                "{action}"
            );
        }
    }

    #[test]
    fn the_arm_leaves_session_and_fs_to_their_own_arms() {
        let lp = lp_agent(
            "user",
            Some("schema_version: 1\npermissions:\n  allow: [\"Read(~/**)\"]\nactions:\n  allow: [\"fs.read\", \"session.prompt\"]\n"),
        );
        let read = decide_loaded_cited(&lp, &principal(), &as_hobi("fs.read"));
        assert_eq!(read.verdict, permit_with_audit());
        assert_eq!(
            read.cited,
            Some(Cited::AgentPath {
                agent: "hobi".into(),
                effect: Effect::Allow,
                source: "Read(~/**)".into()
            })
        );
        let prompt = decide_loaded_cited(&lp, &principal(), &as_hobi("session.prompt"));
        assert_eq!(prompt.verdict, permit_with_audit());
        assert_eq!(
            prompt.cited,
            Some(Cited::Destination {
                role: "user",
                destination: "provider:openai".into()
            })
        );
        assert_eq!(
            decide_loaded_cited(&lp, &principal(), &as_hobi("fs.write")).verdict,
            deny("subject hobi-svc: fs.write is not in agents.hobi.policy.actions allow")
        );
        assert_eq!(
            decide_loaded_cited(&lp, &principal(), &as_hobi("liveness.ping")).verdict,
            permit_with_audit()
        );
    }

    #[test]
    fn requests_without_a_channel_attribute_are_unchanged_for_non_agents() {
        let with = lp_agent("user", None);
        let without = lp_agent_over("", None, false);
        for uid in [HUMAN_UID, OPERATOR_UID, OTHER_UID] {
            for action in [
                "liveness.ping",
                "admin.whoami",
                "admin.status",
                "session.prompt",
                "session.new",
                "fs.read",
            ] {
                let bare = any_action(uid, action);
                let today = decide_loaded_cited(&without, &principal(), &bare);
                assert_eq!(
                    decide_loaded_cited(&with, &principal(), &bare),
                    today,
                    "{uid} {action}"
                );
                let client = on_channel(bare, Some(maknae_security::CHANNEL_CLIENT), None);
                assert_eq!(
                    decide_loaded_cited(&with, &principal(), &client),
                    today,
                    "{uid} {action} client"
                );
            }
        }
        assert!(matches!(
            decide_loaded_cited(&with, &principal(), &any_action(HUMAN_UID, "session.new")).verdict,
            Verdict::NotApplicable { .. }
        ));
    }

    const SESSION_NEW_DEFAULT: &str = "agent hobi: session.new needs a grant in its policy.yaml";

    #[test]
    fn an_agent_asking_session_new_without_a_grant_is_denied() {
        for policy in [
            None,
            Some("schema_version: 1\n"),
            Some("schema_version: 1\nactions:\n  allow: [\"session.prompt\"]\n"),
            Some("schema_version: 1\nactions:\n  allow: []\n"),
        ] {
            for role in ["user", "guest"] {
                let lp = lp_agent(role, policy);
                let d = decide_loaded_cited(&lp, &principal(), &as_hobi("session.new"));
                assert_eq!(d.verdict, deny(SESSION_NEW_DEFAULT), "{role} {policy:?}");
                assert_eq!(d.role, Some(role), "{policy:?}");
            }
        }
        assert_eq!(AGENT_DEFAULT_DENIED, ["session.new"]);
    }

    #[test]
    fn a_policy_grant_lifts_the_session_new_default() {
        for allow in [
            "[\"session.new\"]",
            "[\"session.*\"]",
            "[\"session.prompt\", \"session.new\"]",
        ] {
            let policy = format!("schema_version: 1\nactions:\n  allow: {allow}\n");
            for role in ["user", "guest"] {
                let lp = lp_agent(role, Some(&policy));
                let req = as_hobi("session.new");
                assert_eq!(
                    agent_arm(
                        &lp.agents,
                        lp.subjects.get(HOBI_UID),
                        HOBI_UID,
                        Role::User,
                        &req
                    ),
                    None,
                    "{allow}"
                );
                let d = decide_loaded_cited(&lp, &principal(), &req);
                assert_eq!(
                    d.verdict,
                    Verdict::NotApplicable {
                        note: Some(format!("role {role}: no rule for session.new"))
                    },
                    "{role} {allow}"
                );
            }
        }
    }

    #[test]
    fn a_policy_deny_keeps_the_session_new_default() {
        for actions in [
            "  allow: [\"session.*\"]\n  deny: [\"session.new\"]\n",
            "  allow: [\"session.new\"]\n  deny: [\"session.*\"]\n",
            "  allow: [\"session.new\"]\n  deny: [\"session.new\"]\n",
        ] {
            let policy = format!("schema_version: 1\nactions:\n{actions}");
            let lp = lp_agent("user", Some(&policy));
            assert_eq!(
                decide_loaded_cited(&lp, &principal(), &as_hobi("session.new")).verdict,
                deny(SESSION_NEW_DEFAULT),
                "{actions}"
            );
        }
    }

    #[test]
    fn only_the_agents_own_policy_lifts_the_session_new_default() {
        let lp = lp_agent("user", None);
        let mut allow = BTreeMap::new();
        allow.insert("session.new", "session.new".to_string());
        let authz_entry = SubjectEntry {
            name: "hobi-svc".into(),
            permissions: None,
            actions: Some(SubjectActionSet {
                allow,
                deny: BTreeMap::new(),
            }),
            models: None,
            origin: SubjectOrigin::Authz,
        };
        let req = as_hobi("session.new");
        assert_eq!(
            agent_arm(&lp.agents, Some(&authz_entry), HOBI_UID, Role::User, &req),
            Some(deny(SESSION_NEW_DEFAULT))
        );
        let agent_entry = SubjectEntry {
            origin: SubjectOrigin::Agent("hobi".into()),
            ..authz_entry
        };
        assert_eq!(
            agent_arm(&lp.agents, Some(&agent_entry), HOBI_UID, Role::User, &req),
            None
        );
    }

    #[test]
    fn session_new_is_subject_limitable_and_never_role_grantable() {
        let site = format!(
            "{SUBJECT_SITE}{}",
            sentinel_entry("    actions:\n      allow: [\"session.new\"]\n")
        );
        let policy = maknae_config::parse_authz(&site).unwrap();
        let subjects = crate::validate_subjects(&policy, &subject_lookups()).unwrap();
        assert!(subjects
            .get(SENTINEL_UID)
            .unwrap()
            .actions
            .as_ref()
            .unwrap()
            .allow
            .contains_key("session.new"));
        for role in ["user", "admin"] {
            let body = format!("schema_version: 1\npermissions:\n  allow: []\n  deny: []\nroles:\n  {role}:\n    allow: [\"session.new\"]\n");
            let policy = maknae_config::parse_authz(&body).unwrap();
            assert_eq!(
                crate::validate_grants(&policy.action_grants),
                Err(crate::AuthzBasicError::UnknownActionTerm(
                    "session.new".into()
                )),
                "{role}"
            );
        }
        assert!(!GRANTABLE_ACTIONS.contains(&"session.new"));
    }

    #[test]
    fn the_agent_arm_abstains_for_a_uid_that_is_not_an_enrolled_agent() {
        let lp = lp_agent("user", None);
        for role in [Role::Admin, Role::User, Role::Guest, Role::Adversary] {
            for action in ["admin.status", "session.new", "liveness.ping"] {
                let req = any_action(HUMAN_UID, action);
                assert_eq!(
                    agent_arm(
                        &lp.agents,
                        lp.subjects.get(HUMAN_UID),
                        HUMAN_UID,
                        role,
                        &req
                    ),
                    None,
                    "{role:?} {action}"
                );
            }
        }
    }

    const JIN_UID: u32 = 2002;
    const GWEN_UID: u32 = 1003;
    const TASK_ROLES: &str =
        "roles:\n  admin:\n    allow: [\"session.task\"]\n  user:\n    allow: [\"session.task\"]\n";

    fn lp_task(site: &str, hobi_taskers: Option<&[u32]>) -> LoadedPolicy {
        let policy = maknae_config::parse_authz(&format!(
            "schema_version: 1\npermissions:\n  allow: [\"Read(~/**)\"]\n{site}"
        ))
        .unwrap();
        let lookups: crate::Lookups = [
            ("operator", OPERATOR_UID),
            ("ursula", HUMAN_UID),
            ("gwen", GWEN_UID),
            ("hobi-svc", HOBI_UID),
            ("jin-svc", JIN_UID),
        ]
        .into_iter()
        .map(|(n, u)| (n.to_string(), Some(u)))
        .collect();
        let bindings: BTreeMap<String, Vec<String>> = [
            ("admin", vec!["operator"]),
            ("user", vec!["ursula", "hobi-svc", "jin-svc"]),
            ("guest", vec!["gwen"]),
        ]
        .into_iter()
        .map(|(r, n)| (r.to_string(), n.into_iter().map(String::from).collect()))
        .collect();
        let mut subjects = crate::validate_subjects(&policy, &lookups).unwrap();
        let enrolled = [("hobi", HOBI_UID, "hobi-svc"), ("jin", JIN_UID, "jin-svc")];
        let outcome = crate::AgentOutcome {
            load: maknae_config::AgentsLoad::default(),
            enrolled: enrolled
                .iter()
                .map(|(id, uid, account)| {
                    (
                        maknae_config::AgentId::parse(id).unwrap(),
                        (*uid, account.to_string(), maknae_config::AgentRole::User),
                    )
                })
                .collect(),
            problems: Vec::new(),
            taskers: Default::default(),
        };
        crate::agent_subjects(&outcome, &mut subjects).unwrap();
        let mut agents = AgentUids::default();
        let mut taskers = AgentTaskers::default();
        for (id, uid, _) in enrolled {
            agents.0.insert(uid, id.into());
            taskers.0.insert(id.into(), None);
        }
        taskers.0.insert(
            "hobi".into(),
            hobi_taskers.map(|l| l.iter().copied().collect()),
        );
        LoadedPolicy {
            roles: Roles::File(resolve(&Some(bindings), &crate::found(&lookups)).unwrap()),
            action_grants: crate::validate_grants(&policy.action_grants).unwrap(),
            destinations: crate::validate_destinations(&policy.destinations).unwrap(),
            subjects,
            agents,
            taskers,
            policy,
        }
    }

    fn task_req(uid: u32, target: Option<AttrValue>) -> SecRequest {
        let mut r = request(Some(i64::from(uid)), "session.task", None);
        if let Some(t) = target {
            r.resource.0.insert(maknae_security::RESOURCE_AGENT, t);
        }
        r
    }

    fn task_of(uid: u32, target: &str) -> SecRequest {
        let r = task_req(uid, Some(AttrValue::Str(target.into())));
        if uid == JIN_UID {
            on_channel(r, Some(maknae_security::CHANNEL_AGENT), Some("jin"))
        } else {
            r
        }
    }

    fn task_verdict(lp: &LoadedPolicy, uid: u32, target: &str) -> Verdict {
        decide_loaded_cited(lp, &principal(), &task_of(uid, target)).verdict
    }

    fn not_a_tasker(uid: u32) -> Verdict {
        deny(&format!("agent hobi: uid {uid} is not a tasker"))
    }

    #[test]
    fn a_user_with_the_grant_may_task_an_enrolled_agent() {
        let lp = lp_task(TASK_ROLES, None);
        for (uid, role) in [(HUMAN_UID, "user"), (OPERATOR_UID, "admin")] {
            let d = decide_loaded_cited(&lp, &principal(), &task_of(uid, "hobi"));
            assert_eq!(d.verdict, permit_with_audit(), "{role}");
            assert_eq!(d.role, Some(role));
            assert_eq!(
                d.cited,
                Some(Cited::Grant {
                    role: if role == "admin" { "admin" } else { "user" },
                    term: "session.task".into(),
                    effect: Effect::Allow,
                })
            );
        }
    }

    #[test]
    fn tasking_an_agent_that_is_not_enrolled_is_denied() {
        let lp = lp_task(TASK_ROLES, None);
        for target in ["ghost", "hobi-svc", ""] {
            assert_eq!(
                task_verdict(&lp, HUMAN_UID, target),
                deny(&format!("session.task: agent {target} is not enrolled")),
                "{target}"
            );
        }
        let d = decide_loaded_cited(&lp, &principal(), &task_req(HUMAN_UID, None));
        assert_eq!(d.verdict, deny("no agent on session.task"));
        let d = decide_loaded_cited(
            &lp,
            &principal(),
            &task_req(HUMAN_UID, Some(AttrValue::Int(i64::from(HOBI_UID)))),
        );
        assert_eq!(d.verdict, Verdict::Indeterminate);
    }

    #[test]
    fn tasking_without_the_grant_is_not_applicable() {
        let lp = lp_task("", None);
        for (uid, role) in [(HUMAN_UID, "user"), (OPERATOR_UID, "admin")] {
            let d = decide_loaded_cited(&lp, &principal(), &task_of(uid, "hobi"));
            assert_eq!(
                d.verdict,
                Verdict::NotApplicable {
                    note: Some(format!("role {role}: no rule for session.task"))
                }
            );
            assert_eq!(d.cited, None);
        }
        let lp = lp_task(
            "roles:\n  user:\n    allow: [\"session.*\"]\n    deny: [\"session.task\"]\n",
            None,
        );
        let d = decide_loaded_cited(&lp, &principal(), &task_of(HUMAN_UID, "hobi"));
        assert_eq!(d.verdict, deny("denied by role grant session.task"));
        assert_eq!(
            d.cited,
            Some(Cited::Grant {
                role: "user",
                term: "session.task".into(),
                effect: Effect::Deny,
            })
        );
        let lp = lp_task("roles:\n  admin:\n    allow: [\"session.task\"]\n", None);
        assert_eq!(
            task_verdict(&lp, HUMAN_UID, "hobi"),
            Verdict::NotApplicable {
                note: Some("role user: no rule for session.task".into())
            }
        );
    }

    #[test]
    fn a_guest_may_not_task() {
        let lp = lp_task(TASK_ROLES, None);
        let d = decide_loaded_cited(&lp, &principal(), &task_of(GWEN_UID, "hobi"));
        assert_eq!(
            d.verdict,
            Verdict::NotApplicable {
                note: Some("role guest: no rule for session.task".into())
            }
        );
        assert_eq!(d.role, Some("guest"));
    }

    #[test]
    fn a_subject_actions_limit_can_withhold_session_task() {
        let lp = lp_task(
            &format!(
                "{TASK_ROLES}subjects:\n  ursula:\n    actions:\n      allow: [\"session.prompt\"]\n"
            ),
            None,
        );
        assert_eq!(
            task_verdict(&lp, HUMAN_UID, "hobi"),
            deny("subject ursula: session.task is not in subjects.ursula.actions allow")
        );
        assert_eq!(task_verdict(&lp, OPERATOR_UID, "hobi"), permit_with_audit());
        let lp = lp_task(
            &format!(
                "{TASK_ROLES}subjects:\n  ursula:\n    actions:\n      allow: [\"session.*\"]\n      deny: [\"session.task\"]\n"
            ),
            None,
        );
        assert_eq!(
            task_verdict(&lp, HUMAN_UID, "hobi"),
            deny(
                "subject ursula: session.task denied by subjects.ursula.actions entry session.task"
            )
        );
    }

    #[test]
    fn a_listed_tasker_is_permitted() {
        let lp = lp_task(TASK_ROLES, Some(&[HUMAN_UID]));
        assert_eq!(task_verdict(&lp, HUMAN_UID, "hobi"), permit_with_audit());
    }

    #[test]
    fn an_unlisted_user_is_refused() {
        let lp = lp_task(TASK_ROLES, Some(&[1500]));
        assert_eq!(
            task_verdict(&lp, HUMAN_UID, "hobi"),
            not_a_tasker(HUMAN_UID)
        );
        assert_eq!(
            task_verdict(&lp, OPERATOR_UID, "hobi"),
            not_a_tasker(OPERATOR_UID)
        );
    }

    #[test]
    fn an_unlisted_agent_is_refused() {
        let lp = lp_task(TASK_ROLES, Some(&[HUMAN_UID]));
        assert_eq!(task_verdict(&lp, JIN_UID, "hobi"), not_a_tasker(JIN_UID));
    }

    #[test]
    fn an_absent_taskers_list_permits_a_user() {
        let lp = lp_task(TASK_ROLES, None);
        assert_eq!(task_verdict(&lp, HUMAN_UID, "hobi"), permit_with_audit());
        assert_eq!(task_verdict(&lp, OPERATOR_UID, "hobi"), permit_with_audit());
    }

    #[test]
    fn an_absent_taskers_list_refuses_an_agent() {
        let lp = lp_task(TASK_ROLES, None);
        assert_eq!(task_verdict(&lp, JIN_UID, "hobi"), not_a_tasker(JIN_UID));
        assert_eq!(
            task_verdict(&lp, HUMAN_UID, "jin"),
            permit_with_audit(),
            "jin's own list is absent too"
        );
    }

    #[test]
    fn a_listed_agent_is_permitted() {
        let lp = lp_task(TASK_ROLES, Some(&[JIN_UID]));
        let d = decide_loaded_cited(&lp, &principal(), &task_of(JIN_UID, "hobi"));
        assert_eq!(d.verdict, permit_with_audit());
        assert_eq!(d.role, Some("user"));
        assert_eq!(
            task_verdict(&lp, HUMAN_UID, "hobi"),
            not_a_tasker(HUMAN_UID)
        );
    }

    #[test]
    fn an_empty_taskers_list_refuses_everyone() {
        let lp = lp_task(TASK_ROLES, Some(&[]));
        for uid in [HUMAN_UID, OPERATOR_UID, JIN_UID] {
            assert_eq!(task_verdict(&lp, uid, "hobi"), not_a_tasker(uid), "{uid}");
        }
    }

    #[test]
    fn taskers_admit_holds_the_default() {
        let listed: std::collections::BTreeSet<u32> = [5, 7].into();
        for agent in [false, true] {
            assert!(taskers_admit(Some(&listed), 5, agent));
            assert!(!taskers_admit(Some(&listed), 6, agent));
            assert!(!taskers_admit(Some(&Default::default()), 5, agent));
        }
        assert!(taskers_admit(None, 5, false));
        assert!(!taskers_admit(None, 5, true));
    }

    #[test]
    fn a_target_with_no_taskers_entry_is_indeterminate() {
        let mut lp = lp_task(TASK_ROLES, None);
        lp.taskers.0.remove("hobi");
        assert_eq!(task_verdict(&lp, HUMAN_UID, "hobi"), Verdict::Indeterminate);
    }
}
