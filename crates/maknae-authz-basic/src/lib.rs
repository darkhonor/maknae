//! maknae-authz-basic — the RBAC PDP backend behind the `maknae-security`
//! seam (#85). Four code-defined roles (`admin`/`user`/`guest`/`adversary`)
//! decide four-valued verdicts from `authz.yaml` (+ the additive `bindings:`
//! key), per request, deny-by-default, fail-closed. Spec:
//! `2026-08-26-maknae-authz-basic-design.md` (out-of-repo design spec; specs never live in this repository).
//!
//! Composition: `maknaed` constructs [`BasicAuthorizer`] at boot (#77,
//! `maknae-kernel::boot_gate`) and decides every request through the seam —
//! bindings are LIVE, re-read per request. The seam stays policy-agnostic
//! (ADR-0004).
#![forbid(unsafe_code)]

mod binding;
mod decide;

/// The grantable term set, re-exported for CROSS-CRATE tripwires (#181 S4).
///
/// The constant itself stays `pub(crate)` in `decide.rs` deliberately: the
/// `verb-vocabulary-drift` gate's awk anchor matches that exact spelling
/// (`pub(crate) const GRANTABLE_ACTIONS`), four negative-control fixture
/// literals hard-code it, and `mod decide` is private — so a re-exporting fn
/// is the only shape that adds reachability without moving the anchor the
/// gate and its controls stand on.
pub fn grantable_actions() -> &'static [&'static str] {
    &decide::GRANTABLE_ACTIONS
}

mod role;

use binding::UidMap;
use decide::LoadedPolicy;
use std::path::{Path, PathBuf};

/// Subject attribute key for the authenticated uid (pinned for #77; ADR-0018:
/// the per-request authorization principal is the uid, from peer-cred).
pub const SUBJECT_UID_KEY: &str = decide::SUBJECT_UID;
/// Resource attribute key carrying the (already-resolved) filesystem path for
/// `fs.*` actions (spec §4.4).
pub const RESOURCE_PATH_KEY: &str = decide::RESOURCE_PATH;

/// Why [`BasicAuthorizer::new`] refused (all fail-closed; §3a). The daemon's
/// boot gate (#77) surfaces this as a boot refusal.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AuthzBasicError {
    /// The policy file failed the hardened load (ownership/mode/symlink/
    /// grammar) — the message is `AuthzError`'s rendering.
    Load(String),
    /// The `bindings:` block is semantically invalid (unknown role, dual
    /// membership, duplicate, unresolvable username).
    Bindings(String),
    /// A `roles:` key names something that is not a role in the closed
    /// vocabulary (#162). Carries the offending key.
    UnknownRole(String),
    /// A `roles:`/`destinations:` key names a STRUCTURAL role (`guest`,
    /// `adversary`) that takes no grants. Distinct from `UnknownRole` on
    /// purpose: "takes none" and "does not exist" are different operator
    /// problems, and collapsing them would tell an operator their correct
    /// spelling was a typo. *(Corrected 2026-09-09, #172: `user` left this
    /// set; it holds the content-plane term.)*
    RoleNotSupportedYet(String),
    /// A `roles:` allow/deny list names a term outside `GRANTABLE_ACTIONS`
    /// (#162). Carries the offending term.
    UnknownActionTerm(String),
    /// A `roles:` list names a grantable term that THIS role may not hold
    /// (#172: `user` may hold `session.prompt` only; the admin disclosure
    /// terms are admin-only, ADR-0010 decision 4 as superseded 2026-09-08).
    TermNotGrantableForRole { role: String, term: String },
}

impl std::fmt::Display for AuthzBasicError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AuthzBasicError::Load(m) => write!(f, "authz policy load refused: {m}"),
            AuthzBasicError::Bindings(m) => write!(f, "authz bindings invalid: {m}"),
            AuthzBasicError::UnknownRole(k) => {
                write!(f, "authz roles: unknown role `{k}`")
            }
            AuthzBasicError::RoleNotSupportedYet(k) => write!(
                f,
                "authz roles: role `{k}` takes no grants (guest and adversary are structural)"
            ),
            AuthzBasicError::UnknownActionTerm(t) => write!(
                f,
                "authz roles: `{t}` is not a grantable action term (grantable: {})",
                decide::GRANTABLE_ACTIONS.join(", ")
            ),
            AuthzBasicError::TermNotGrantableForRole { role, term } => write!(
                f,
                "authz roles: `{term}` is not grantable to role `{role}` (admin: {}; user: session.prompt)",
                decide::GRANTABLE_ACTIONS.join(", ")
            ),
        }
    }
}

impl std::error::Error for AuthzBasicError {}

/// The RBAC PDP backend. Holds the policy PATH (never a snapshot: `decide`
/// re-reads the file per request — the Zero Trust ruling) plus the enrolled
/// principal and the construction-time username→uid map (zero per-request
/// NSS; a brand-new username edited into the file after construction is
/// `Indeterminate` until restart — spec §3).
#[derive(Debug)]
pub struct BasicAuthorizer {
    policy_path: PathBuf,
    principal: maknae_config::Principal,
    uid_map: UidMap,
}

impl BasicAuthorizer {
    /// Read + parse + validate the policy once, eagerly (a bad file refuses
    /// construction — the daemon's boot gate), resolving every bound username
    /// to a uid via getpwnam exactly once. Production load path only: the
    /// file must be root-owned, `mode & 0o027 == 0`, symlink-refused.
    pub fn new(
        policy_path: PathBuf,
        principal: maknae_config::Principal,
    ) -> Result<Self, AuthzBasicError> {
        let policy = maknae_config::load_authz(&policy_path, Some(&principal.home))
            .map_err(|e| AuthzBasicError::Load(e.to_string()))?;
        Self::finish_new(policy_path, principal, policy)
    }

    /// The post-load half of [`BasicAuthorizer::new`]: uid resolution + eager
    /// semantic validation + construction. Split out so it is hermetically
    /// testable with a [`maknae_config::parse_authz`]-produced policy (the
    /// load half's root-owned requirement is unconstructible off-root; the
    /// pieces are the same production code either way).
    fn finish_new(
        policy_path: PathBuf,
        principal: maknae_config::Principal,
        policy: maknae_config::AuthzPolicy,
    ) -> Result<Self, AuthzBasicError> {
        let uid_map = resolve_uid_map(&policy)?;
        // Eager semantic validation: the same checks every per-request load
        // repeats (the advesary-typo rule fails construction, not just
        // requests).
        binding::resolve(&policy.bindings, &uid_map)
            .map_err(|e| AuthzBasicError::Bindings(e.to_string()))?;
        // Grants validate eagerly for the same reason bindings do: an operator
        // who mistypes a term learns it at boot, in the journal, with the token
        // named -- not by wondering why a grant they wrote does nothing.
        validate_grants(&policy.action_grants)?;
        validate_destinations(&policy.destinations)?;
        Ok(Self {
            policy_path,
            principal,
            uid_map,
        })
    }

    /// The whole per-request sequence with the file-loader injected: loader →
    /// parsed policy → validated bindings (construction-time uid map) → pure
    /// core; any failure → `Indeterminate`. One sequence, two callers:
    /// production `decide()` injects `load_authz` (root-owned hardened path);
    /// the hermetic e2e injects the `hermetic-test-seam` loader, which runs
    /// the SAME maknae-io checks with a fixture-satisfiable owner requirement
    /// (the PR #139 pattern — the requirement is parameterized, the checks
    /// are real, nothing is stubbed).
    /// **Test-only since #275** — production decides through
    /// [`Self::decide_with_loader_reporting_role`]. Kept so the five existing
    /// assertions bind a bare `Verdict`; it is that function's `.0`, so they
    /// check exactly what production enforces.
    #[allow(dead_code)]
    fn decide_with_loader(
        &self,
        req: &maknae_security::Request,
        loader: impl Fn(&Path) -> Result<maknae_config::AuthzPolicy, maknae_config::AuthzError>,
    ) -> maknae_security::Verdict {
        self.decide_with_loader_reporting_role(req, loader).0
    }

    /// The verdict AND the role, from ONE policy read (#275). `decide_with_loader`
    /// is its `.0`, so the two can never disagree and no existing caller changed.
    fn decide_with_loader_reporting_role(
        &self,
        req: &maknae_security::Request,
        loader: impl Fn(&Path) -> Result<maknae_config::AuthzPolicy, maknae_config::AuthzError>,
    ) -> (maknae_security::Verdict, Option<&'static str>) {
        let Ok(policy) = loader(&self.policy_path) else {
            return (maknae_security::Verdict::Indeterminate, None);
        };
        match assemble(policy, &self.uid_map) {
            Ok(lp) => decide::decide_loaded_with_role(&lp, &self.principal, req),
            Err(()) => (maknae_security::Verdict::Indeterminate, None),
        }
    }
}

/// policy → LoadedPolicy under a uid map; any invalidity → Err (the caller
/// maps it to `Indeterminate`).
fn assemble(policy: maknae_config::AuthzPolicy, uid_map: &UidMap) -> Result<LoadedPolicy, ()> {
    let roles = binding::resolve(&policy.bindings, uid_map).map_err(|_| ())?;
    // Anonymous on this lane by design: `finish_new` names the offending term
    // for the operator at boot; a per-request refusal tells a caller only
    // `Indeterminate`. Both refuse -- only the diagnostic differs.
    let action_grants = validate_grants(&policy.action_grants).map_err(|_| ())?;
    let destinations = validate_destinations(&policy.destinations).map_err(|_| ())?;
    Ok(LoadedPolicy {
        policy,
        roles,
        action_grants,
        destinations,
    })
}

/// `destinations:` keys must be roles that can hold a prompt grant (#172):
/// `admin` and `user`. Structural roles refuse like `roles:` does; an unknown
/// key refuses by name. Runs at boot (finish_new) and on every per-request load.
fn validate_destinations(
    raw: &std::collections::BTreeMap<String, maknae_config::RawDestinations>,
) -> Result<decide::DestinationGrants, AuthzBasicError> {
    let mut out = std::collections::BTreeMap::new();
    for (key, d) in raw {
        match role::Role::from_key(key) {
            None => return Err(AuthzBasicError::UnknownRole(key.clone())),
            Some(role::Role::Admin | role::Role::User) => {}
            Some(_) => return Err(AuthzBasicError::RoleNotSupportedYet(key.clone())),
        }
        out.insert(key.clone(), d.allow.clone());
    }
    Ok(decide::DestinationGrants(out))
}

/// Validate the raw `roles:` grants against the closed vocabularies (#162).
///
/// Three checks, because `Role::from_key` answers only the first: the key is
/// a role; the role may hold grants at all (`admin` and, since #172, `user`;
/// `guest`/`adversary` are structural); and the term is one that role may
/// hold (`user`: `session.prompt` only — the admin disclosure terms stay
/// admin-only, ADR-0010 decision 4 as superseded 2026-09-08). Gates **both**
/// `allow` and `deny`, so a typo'd deny cannot be silently accepted as an
/// unenforced denial. *(Corrected 2026-09-09: this said Phase 1 grants
/// `admin` alone.)* `role.rs` is untouched: a grant surface over the existing
/// vocabulary, not an addition to it.
fn validate_grants(
    raw: &std::collections::BTreeMap<String, maknae_config::RawActionGrants>,
) -> Result<decide::ActionGrants, AuthzBasicError> {
    let mut out = std::collections::BTreeMap::new();
    for (key, grants) in raw {
        let role = match role::Role::from_key(key) {
            None => return Err(AuthzBasicError::UnknownRole(key.clone())),
            Some(r @ (role::Role::Admin | role::Role::User)) => r,
            Some(_) => return Err(AuthzBasicError::RoleNotSupportedYet(key.clone())),
        };
        let check = |terms: &Vec<String>| -> Result<Vec<decide::ActionTerm>, AuthzBasicError> {
            terms
                .iter()
                .map(|t| {
                    if !decide::GRANTABLE_ACTIONS.contains(&t.as_str()) {
                        return Err(AuthzBasicError::UnknownActionTerm(t.clone()));
                    }
                    if role == role::Role::User && t != "session.prompt" {
                        return Err(AuthzBasicError::TermNotGrantableForRole {
                            role: key.clone(),
                            term: t.clone(),
                        });
                    }
                    Ok(decide::ActionTerm::validated(t.clone()))
                })
                .collect()
        };
        out.insert(key.clone(), (check(&grants.allow)?, check(&grants.deny)?));
    }
    Ok(decide::ActionGrants::from_validated(out))
}

/// getpwnam every bound username once. No name is excluded since #276.
/// Unresolvable → construction refused. `cfg(unix)` is the only lane — the
/// workspace's non-unix story is fail-closed refusal upstream in
/// `maknae-config` (`load_authz` refuses off-unix before we are reached).
fn resolve_uid_map(policy: &maknae_config::AuthzPolicy) -> Result<UidMap, AuthzBasicError> {
    let mut map = UidMap::new();
    let Some(bindings) = &policy.bindings else {
        return Ok(map);
    };
    for members in bindings.values() {
        for name in members {
            if map.contains_key(name) {
                continue;
            }
            let uid = lookup_uid(name).ok_or_else(|| {
                AuthzBasicError::Bindings(format!(
                    "identity '{name}' has no resolvable uid on this host"
                ))
            })?;
            map.insert(name.clone(), uid);
        }
    }
    Ok(map)
}

/// One function with an INLINE `#[cfg(unix)]`/`#[cfg(not(unix))]` split
/// (the `security_load` idiom): a standalone `#[cfg(not(unix))] fn` would be
/// its own mutation target whose body never compiles on a unix runner — a
/// permanently-missed mutant for dead code.
fn lookup_uid(name: &str) -> Option<u32> {
    #[cfg(not(unix))]
    {
        // Unreachable in practice: `load_authz` refuses off-unix before any
        // lookup. Fail closed regardless.
        let _ = name;
        None
    }
    #[cfg(unix)]
    {
        match nix::unistd::User::from_name(name) {
            Ok(Some(user)) => Some(user.uid.as_raw()),
            _ => None,
        }
    }
}

impl BasicAuthorizer {
    /// Bindings as the PDP would resolve them RIGHT NOW, via the same loader
    /// `decide` uses. Any failure -- unreadable file, bad grammar, invalid
    /// bindings -- yields `None`, which the kernel reports as unavailable.
    /// Never a partial or defaulted list: "these are the bindings" is a claim,
    /// and a wrong one about authorization state is worse than no answer.
    fn subjects_with_loader(
        &self,
        loader: impl Fn(&Path) -> Result<maknae_config::AuthzPolicy, maknae_config::AuthzError>,
    ) -> Option<Vec<maknae_security::SubjectBinding>> {
        let policy = loader(&self.policy_path).ok()?;
        let resolved = binding::resolve(&policy.bindings, &self.uid_map).ok()?;
        resolved.as_subject_bindings()
    }
}

impl maknae_security::Authorizer for BasicAuthorizer {
    /// Per-request: re-read the policy file (Zero Trust — a binding edit
    /// bites on the next request), then run the pure core. ANY load/parse/
    /// validation failure → `Indeterminate` (finalize turns it into deny).
    fn decide(&self, req: &maknae_security::Request) -> maknae_security::Verdict {
        self.decide_reporting_role(req).0
    }

    /// One decision path: `decide` is this function's `.0`, so the verdict the
    /// kernel enforces and the role it stamps come from the SAME policy read
    /// (#275).
    fn decide_reporting_role(
        &self,
        req: &maknae_security::Request,
    ) -> (maknae_security::Verdict, Option<&'static str>) {
        let home = self.principal.home.clone();
        self.decide_with_loader_reporting_role(req, move |p| {
            maknae_config::load_authz(p, Some(&home))
        })
    }

    fn subjects(&self) -> Option<Vec<maknae_security::SubjectBinding>> {
        let home = self.principal.home.clone();
        self.subjects_with_loader(move |p| maknae_config::load_authz(p, Some(&home)))
    }

    fn backend_name(&self) -> String {
        "maknae-authz-basic".to_string()
    }
}

/// The NON-REMOVABLE baseline operand of the authorization composition
/// (ADR-0008 decision 1; #154).
///
/// **Sealed.** Only this crate can implement it, and it implements it for
/// exactly two types: [`BasicAuthorizer`] (production) and, under the
/// `hermetic-test-seam` feature only, `HermeticAuthorizer` — which wraps a real
/// `BasicAuthorizer` with the loader requirement parameterized, so the kernel's
/// unprivileged integration suites can construct a composition without a
/// root-owned policy file. `ci/gates/feature-resolution-pin.sh` pins production
/// resolution featureless, so in a shipped binary the ONLY `Baseline` is
/// `-basic`.
///
/// Why a sealed trait rather than the ADR's literal `baseline: BasicAuthorizer`
/// field: the field form cannot be constructed off-root, which would have left
/// every kernel composition test unwritable. The property the ADR names — the
/// absent state is not expressible — holds identically: `Composition` requires
/// a `B: Baseline`, and nothing outside this crate can satisfy that bound.
pub trait Baseline: maknae_security::Authorizer + sealed::Sealed + Send + Sync + 'static {}

mod sealed {
    pub trait Sealed {}
}

impl sealed::Sealed for BasicAuthorizer {}
impl Baseline for BasicAuthorizer {}

#[cfg(all(unix, feature = "hermetic-test-seam"))]
impl sealed::Sealed for HermeticAuthorizer {}
#[cfg(all(unix, feature = "hermetic-test-seam"))]
impl Baseline for HermeticAuthorizer {}

/// Test-only, requirement-parameterized door over the SAME production decide
/// sequence (#77; the PR #139 pattern applied at the decide layer): the
/// loader's `TargetRequired` is the caller's, everything else — eager
/// `finish_new` validation, per-request re-read through `decide_with_loader`,
/// the pure core — is the production code path. `BasicAuthorizer`'s own shape
/// is untouched in every build (no cfg'd fields: the coverage lane compiles
/// `--all-features` and must not alter production structs). Kernel e2e tests
/// pass this as `handle()`'s generic authorizer so the wiring under test is
/// identical to production with the loader differing by exactly the declared
/// requirement. Production resolution is pinned featureless by
/// `ci/gates/feature-resolution-pin.sh`.
#[cfg(all(unix, feature = "hermetic-test-seam"))]
#[derive(Debug)]
pub struct HermeticAuthorizer {
    inner: BasicAuthorizer,
    req: maknae_config::TargetRequired,
}

#[cfg(all(unix, feature = "hermetic-test-seam"))]
impl HermeticAuthorizer {
    /// Eager-validating constructor: same load→`finish_new` sequence as
    /// [`BasicAuthorizer::new`], with the door's requirement parameterized.
    pub fn new(
        policy_path: PathBuf,
        principal: maknae_config::Principal,
        req: maknae_config::TargetRequired,
    ) -> Result<Self, AuthzBasicError> {
        let inner = BasicAuthorizer::new_hermetic(policy_path, principal, req.clone())?;
        Ok(Self { inner, req })
    }
}

#[cfg(all(unix, feature = "hermetic-test-seam"))]
impl BasicAuthorizer {
    /// The construction half of the hermetic door: a REAL `BasicAuthorizer`
    /// (production `finish_new` sequence) whose load requirement is the
    /// caller's — so consumers whose success paths are unconstructible
    /// off-root (the kernel boot gate) can exercise them with nothing
    /// stubbed. Feature-gated; the feature-resolution-pin gate keeps it out
    /// of production resolution. NOTE: the instance's own trait `decide()`
    /// still uses the PRODUCTION loader (root-owned door) — only
    /// [`HermeticAuthorizer`] parameterizes decide-time.
    pub fn new_hermetic(
        policy_path: PathBuf,
        principal: maknae_config::Principal,
        req: maknae_config::TargetRequired,
    ) -> Result<Self, AuthzBasicError> {
        let policy =
            maknae_config::load_authz_with_requirement(&policy_path, req, Some(&principal.home))
                .map_err(|e| AuthzBasicError::Load(e.to_string()))?;
        BasicAuthorizer::finish_new(policy_path, principal, policy)
    }
}

#[cfg(all(unix, feature = "hermetic-test-seam"))]
impl maknae_security::Authorizer for HermeticAuthorizer {
    fn decide(&self, r: &maknae_security::Request) -> maknae_security::Verdict {
        self.decide_reporting_role(r).0
    }

    /// Delegates through the HERMETIC loader, exactly as `decide` does.
    /// Delegating to `inner.decide_reporting_role` instead would silently use
    /// the production root-owned loader and report `Indeterminate`/`None` in
    /// every test (#275).
    fn decide_reporting_role(
        &self,
        r: &maknae_security::Request,
    ) -> (maknae_security::Verdict, Option<&'static str>) {
        let req = self.req.clone();
        let home = self.inner.principal.home.clone();
        self.inner.decide_with_loader_reporting_role(r, move |p| {
            maknae_config::load_authz_with_requirement(p, req.clone(), Some(&home))
        })
    }

    /// DELEGATED, not defaulted. The hermetic wrapper exists to exercise the
    /// real backend through a fixture-satisfiable loader; reporting `unknown`
    /// here would make every e2e test assert against a stub value and prove
    /// nothing about what production answers.
    fn subjects(&self) -> Option<Vec<maknae_security::SubjectBinding>> {
        let req = self.req.clone();
        let home = self.inner.principal.home.clone();
        self.inner.subjects_with_loader(move |p| {
            maknae_config::load_authz_with_requirement(p, req.clone(), Some(&home))
        })
    }

    fn backend_name(&self) -> String {
        self.inner.backend_name()
    }
}

/// P2 artifact-witness marker: this is a PRIVILEGED trust-plane crate,
/// forbidden from the untrusted client binary (the P1 gate keys on
/// `PRIVILEGED_CRATES`; this marker is the P2 witness that a shipped
/// artifact actually links it).
#[used]
pub static PRIVILEGED_MARKER: &[u8] = b"PRIVILEGED_MAKNAE_AUTHZ_BASIC";

// Integration proofs live in-crate (they need pub(crate) reach into the pure
// core). Spec §6: (a) shipped-content defaults proof; (b) the bindings-fixture
// matrix proof rides decide.rs's golden vectors; (c) containment e2e below.
#[cfg(test)]
mod tests {

    /// The re-export is pinned IN THIS CRATE: the kernel's cross-crate
    /// tripwire cannot kill a `-basic` mutant (per-package mutation runs only
    /// this crate's tests), and the gate's run reported exactly that — three
    /// `grantable_actions -> Vec::leak(...)` mutants MISSED. Exact equality
    /// against the literal, both directions of drift covered. (Lives inside
    /// the crate's single `#[cfg(test)]` module: coverage_check.py hard-fails
    /// a second column-0 marker, which the first placement added — caught by
    /// diff-CR running the LIVE coverage lane, `coverage-tiers.sh --root .`.)
    #[test]
    fn the_reexport_returns_the_real_constant_exactly() {
        assert_eq!(
            super::grantable_actions(),
            [
                "admin.status",
                "admin.config.show",
                "admin.subject.list",
                "session.prompt"
            ]
        );
    }
    use super::*;
    use maknae_security::{
        Action, AttrValue, Attributes, Authorizer, Context, Resource, Subject, Verdict,
    };

    fn principal() -> maknae_config::Principal {
        maknae_config::Principal {
            name: "operator".into(),
            uid: 501,
            home: "/home/operator".into(),
        }
    }

    fn liveness_req(uid: Option<i64>) -> maknae_security::Request {
        let mut s = Attributes::new();
        if let Some(u) = uid {
            s.insert(SUBJECT_UID_KEY, AttrValue::Int(u));
        }
        maknae_security::Request {
            subject: Subject(s),
            resource: Resource(Attributes::new()),
            action: Action("liveness.ping".into()),
            context: Context(Attributes::new()),
        }
    }

    /// Proof (a): the REAL shipped authz.yaml (byte-identical, via
    /// include_str!) parses, has no bindings key, and the defaults branch
    /// decides: enrolled uid → admin rows; agent name → user rows.
    #[test]
    fn shipped_content_defaults_proof() {
        const SHIPPED: &str = include_str!("../../../packaging/common/authz.yaml");
        let policy =
            maknae_config::parse_authz(SHIPPED, Some(std::path::Path::new("/home/operator")))
                .expect("shipped authz.yaml parses");
        assert!(
            policy.bindings.is_none(),
            "shipped file has no bindings key"
        );
        let lp = decide::LoadedPolicy {
            policy,
            roles: binding::resolve(&None, &UidMap::new()).unwrap(),
            action_grants: decide::ActionGrants::default(),
            destinations: decide::DestinationGrants::default(),
        };
        // Enrolled uid → admin: admin verb permitted; deny-list still denies.
        let admin_whoami = decide::decide_loaded(&lp, &principal(), &{
            let mut r = liveness_req(Some(501));
            r.action = Action("admin.whoami".into());
            r
        });
        assert!(matches!(admin_whoami, Verdict::Permit { .. }));
        let mut fs_req = liveness_req(Some(501));
        fs_req.action = Action("fs.read".into());
        fs_req.resource.0.insert(
            RESOURCE_PATH_KEY,
            AttrValue::Str("/home/operator/.ssh/id_rsa".into()),
        );
        assert!(matches!(
            decide::decide_loaded(&lp, &principal(), &fs_req),
            Verdict::Deny { .. }
        ));
        // An UNBOUND uid gets no role under the shipped defaults -- the half
        // that used to be asserted through the reserved `agent` name (#276).
        assert_eq!(
            decide::decide_loaded(&lp, &principal(), &liveness_req(Some(4242))),
            Verdict::NotApplicable {
                note: Some("subject resolves to no role".into())
            }
        );
    }

    /// Proof (c): containment-without-restart — the Zero Trust property,
    /// end-to-end through the real (seam-parameterized) load path: same
    /// authorizer instance, file edited between requests, next decide() flips
    /// to Deny with no restart.
    #[test]
    fn containment_without_restart_bites_on_the_next_request() {
        use std::os::unix::fs::PermissionsExt;
        let dir = std::env::temp_dir().join(format!("mab_contain_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700)).unwrap();
        let p = dir.join("authz.yaml");
        let write = |bindings_role: &str| {
            std::fs::write(
                &p,
                format!(
                    // `root` rather than the struck reserved token (#276): this
                    // proof's subject is CONTAINMENT -- that a binding edit bites
                    // on the next request -- not the identity it is written over.
                    "schema_version: 1\npermissions:\n  allow: []\n  deny: []\nbindings:\n  {bindings_role}: [\"root\"]\n"
                ),
            )
            .unwrap();
            std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o640)).unwrap();
        };
        write("user");
        let auth = BasicAuthorizer {
            policy_path: p.clone(),
            principal: principal(),
            uid_map: [("root".to_string(), 0u32)].into_iter().collect(),
        };
        let seam_loader = |path: &Path| {
            maknae_config::load_authz_with_requirement(
                path,
                maknae_io::TargetRequired {
                    owner: None,
                    mode_mask: Some(0o022),
                    nlink_exactly_one: false,
                    regular_file: true,
                    max_bytes: None,
                },
                Some(std::path::Path::new("/home/operator")),
            )
        };
        let before = auth.decide_with_loader(&liveness_req(Some(0)), seam_loader);
        assert!(matches!(before, Verdict::Permit { .. }), "{before:?}");

        // Containment: root (here: the test) rewrites the binding. No
        // restart, no new authorizer — the very next request must deny.
        write("adversary");
        let after = auth.decide_with_loader(&liveness_req(Some(0)), seam_loader);
        assert!(
            matches!(after, Verdict::Deny { ref reason } if reason.contains("role=adversary")),
            "{after:?}"
        );

        // And a garbage file mid-flight → Indeterminate (fail-closed).
        std::fs::write(&p, "not: [valid").unwrap();
        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o640)).unwrap();
        // `Some(0)`, NOT `None`: a subject with no uid yields Indeterminate on
        // its own, so `liveness_req(None)` here would pass whether or not the
        // GARBAGE POLICY was refused -- proven by substituting a valid policy
        // and watching it still pass (codex). The identity must be good so the
        // only thing under test is the policy.
        let garbage = auth.decide_with_loader(&liveness_req(Some(0)), seam_loader);
        assert_eq!(garbage, Verdict::Indeterminate);
        // A brand-new username edited in after construction: Indeterminate
        // until restart (spec §3 resolution model).
        std::fs::write(
            &p,
            "schema_version: 1\npermissions:\n  allow: []\n  deny: []\nbindings:\n  user: [\"nobody-new\"]\n",
        )
        .unwrap();
        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o640)).unwrap();
        // Same reason: a resolvable identity, so the refusal under test is the
        // unresolvable BINDING and nothing else.
        let new_name = auth.decide_with_loader(&liveness_req(Some(0)), seam_loader);
        assert_eq!(new_name, Verdict::Indeterminate);
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// finish_new (the post-load half of `new`) hermetically: eager
    /// validation + uid resolution over a host-independent identity
    /// (`root` — uid 0 exists everywhere).
    ///
    /// #276: this used to bind `user: ["agent"]` and assert the reserved token
    /// was never looked up. With the token struck, `agent` is an ordinary name:
    /// the binding would break DIFFERENTLY on the two mutation lanes -- a
    /// `getpwnam` panic on a host without such an account, an assertion failure
    /// on a host with one. Bound to `root` alone, which resolves everywhere.
    #[test]
    fn finish_new_resolves_root_validates_eagerly_and_refuses_bad_bindings() {
        let ok_policy = maknae_config::parse_authz(
            "schema_version: 1\npermissions:\n  allow: []\n  deny: []\nbindings:\n  admin: [\"root\"]\n",
            None,
        )
        .unwrap();
        let auth =
            BasicAuthorizer::finish_new("/nonexistent".into(), principal(), ok_policy).unwrap();
        assert_eq!(auth.uid_map.get("root"), Some(&0), "root resolves to uid 0");
        assert_eq!(
            auth.uid_map.len(),
            1,
            "every bound name resolves, no exception"
        );

        // The advesary-typo rule fails CONSTRUCTION, not just requests.
        let typo = maknae_config::parse_authz(
            "schema_version: 1\npermissions:\n  allow: []\n  deny: []\nbindings:\n  advesary: [\"root\"]\n",
            None,
        )
        .unwrap();
        let got = BasicAuthorizer::finish_new("/nonexistent".into(), principal(), typo);
        assert!(matches!(got, Err(AuthzBasicError::Bindings(ref m)) if m.contains("advesary")));

        // An unresolvable username refuses construction.
        let ghost = maknae_config::parse_authz(
            "schema_version: 1\npermissions:\n  allow: []\n  deny: []\nbindings:\n  user: [\"no-such-user-maknae-85\"]\n",
            None,
        )
        .unwrap();
        let got = BasicAuthorizer::finish_new("/nonexistent".into(), principal(), ghost);
        assert!(
            matches!(got, Err(AuthzBasicError::Bindings(ref m)) if m.contains("no-such-user-maknae-85"))
        );
    }

    // ---- `roles:` action grants: refusal at boot (#162) ----

    const GRANT_PREAMBLE: &str = "schema_version: 1\npermissions:\n  allow: []\n  deny: []\n";

    fn parse_with_roles(roles_block: &str) -> maknae_config::AuthzPolicy {
        maknae_config::parse_authz(&format!("{GRANT_PREAMBLE}{roles_block}"), None)
            .expect("grammar is valid; the SEMANTIC refusal is what is under test")
    }

    /// A `roles:` key outside the role vocabulary refuses CONSTRUCTION, and the
    /// error names the offending key. Not a warning, not a skipped entry: a
    /// grant an operator wrote and the daemon silently ignored is the failure
    /// mode this whole surface exists to avoid.
    #[test]
    fn roles_unknown_role_refuses_construction_naming_the_key() {
        let p = parse_with_roles("roles:\n  admn:\n    allow: [\"admin.status\"]\n");
        let got = BasicAuthorizer::finish_new("/nonexistent".into(), principal(), p);
        assert!(
            matches!(got, Err(AuthzBasicError::UnknownRole(ref k)) if k == "admn"),
            "expected UnknownRole(\"admn\"), got {got:?}"
        );
    }

    /// A REAL but STRUCTURAL role gets its own variant. `Role::from_key`
    /// returns `Some` for these, so this is a second check -- and it must not
    /// collapse into `UnknownRole`, which would tell an operator their correct
    /// spelling was a typo. (`user` left this loop with #172.)
    #[test]
    fn roles_real_but_ungrantable_role_refuses_with_its_own_variant() {
        for key in ["guest", "adversary"] {
            let p = parse_with_roles(&format!(
                "roles:\n  {key}:\n    allow: [\"admin.status\"]\n"
            ));
            let got = BasicAuthorizer::finish_new("/nonexistent".into(), principal(), p);
            assert!(
                matches!(got, Err(AuthzBasicError::RoleNotSupportedYet(ref k)) if k == key),
                "role `{key}`: expected RoleNotSupportedYet, got {got:?}"
            );
        }
    }

    #[test]
    fn user_may_hold_only_the_content_plane_term_and_the_error_names_role_and_term() {
        let p = parse_with_roles("roles:\n  user:\n    allow: [\"admin.status\"]\n");
        let got = BasicAuthorizer::finish_new("/nonexistent".into(), principal(), p);
        assert!(
            matches!(got, Err(AuthzBasicError::TermNotGrantableForRole { ref role, ref term }) if role == "user" && term == "admin.status"),
            "{got:?}"
        );
        let p = parse_with_roles("roles:\n  user:\n    allow: [\"session.prompt\"]\n");
        assert!(BasicAuthorizer::finish_new("/nonexistent".into(), principal(), p).is_ok());
    }

    #[test]
    fn destinations_for_a_structural_or_unknown_role_refuse_at_boot_naming_the_role() {
        for (role, want_unknown) in [("guest", false), ("adversary", false), ("ghost", true)] {
            let p = parse_with_roles(&format!(
                "destinations:\n  {role}:\n    allow: [\"provider:x\"]\n"
            ));
            let got = BasicAuthorizer::finish_new("/nonexistent".into(), principal(), p);
            match got {
                Err(AuthzBasicError::UnknownRole(ref k)) if want_unknown => assert_eq!(k, role),
                Err(AuthzBasicError::RoleNotSupportedYet(ref k)) if !want_unknown => {
                    assert_eq!(k, role)
                }
                other => panic!("{role}: {other:?}"),
            }
        }
        let p = parse_with_roles(
            "destinations:\n  user:\n    allow: [\"provider:x\"]\n  admin:\n    allow: []\n",
        );
        assert!(BasicAuthorizer::finish_new("/nonexistent".into(), principal(), p).is_ok());
    }

    /// A term outside `GRANTABLE_ACTIONS` refuses, whether it is a real verb
    /// this phase withholds (`admin.contain`) or nonexistent (`admin.stauts`).
    /// Both are `UnknownActionTerm`: the grantable list is the vocabulary here,
    /// and "exists elsewhere in the system" earns no standing.
    #[test]
    fn roles_ungrantable_term_refuses_construction_naming_the_term() {
        for term in [
            "admin.contain",
            "admin.policy.reload",
            "admin.stauts",
            "fs.read",
        ] {
            let p = parse_with_roles(&format!("roles:\n  admin:\n    allow: [\"{term}\"]\n"));
            let got = BasicAuthorizer::finish_new("/nonexistent".into(), principal(), p);
            assert!(
                matches!(got, Err(AuthzBasicError::UnknownActionTerm(ref t)) if t == term),
                "term `{term}`: expected UnknownActionTerm, got {got:?}"
            );
        }
    }

    /// Validation gates the DENY list too. A typo'd deny that parsed silently
    /// would read to an operator as a denial in force while denying nothing --
    /// the worst outcome on a policy surface, and invisible without this test.
    #[test]
    fn roles_ungrantable_term_in_deny_list_also_refuses() {
        let p = parse_with_roles("roles:\n  admin:\n    deny: [\"admin.contain\"]\n");
        let got = BasicAuthorizer::finish_new("/nonexistent".into(), principal(), p);
        assert!(
            matches!(got, Err(AuthzBasicError::UnknownActionTerm(ref t)) if t == "admin.contain"),
            "deny lists are gated identically to allow lists, got {got:?}"
        );
    }

    #[test]
    fn subjects_reports_file_bindings_and_none_on_failure() {
        let auth = BasicAuthorizer {
            policy_path: "/nonexistent".into(),
            principal: principal(),
            uid_map: [("root".to_string(), 0u32)].into_iter().collect(),
        };
        let got = auth
            .subjects_with_loader(|_| {
                maknae_config::parse_authz(
                    &format!("{GRANT_PREAMBLE}bindings:\n  admin: [\"root\"]\n"),
                    None,
                )
            })
            .expect("a readable policy yields Some");
        assert_eq!(got.len(), 1);
        assert_eq!(got[0].role, "admin");
        assert_eq!(got[0].members, vec!["uid:0".to_string()]);

        // An unreadable policy yields None -- NOT an empty list.
        let none = auth.subjects_with_loader(|_| Err(maknae_config::AuthzError::Yaml("x".into())));
        assert!(none.is_none(), "unreadable must be None, got {none:?}");

        // So does an INVALID one: a binding that does not resolve is not
        // "no bindings", and answering as though it were would tell an
        // operator their policy binds nobody when it binds something broken.
        let invalid = auth.subjects_with_loader(|_| {
            maknae_config::parse_authz(
                &format!("{GRANT_PREAMBLE}bindings:\n  admn: [\"root\"]\n"),
                None,
            )
        });
        assert!(invalid.is_none(), "invalid bindings must be None");
    }

    /// `BasicAuthorizer::subjects` FAILS CLOSED on an unreadable path.
    ///
    /// That is all this asserts, and the name says so. An earlier version was
    /// called `..._use_the_production_loaders` and its comment claimed to prove
    /// the wrapper reaches `load_authz` "rather than some laxer reader" -- it
    /// cannot: EVERY loader returns `None` for a nonexistent path, so the
    /// assertion is satisfied by a hardened reader, a lax one, and a `None`
    /// stub alike. `.cargo/mutants.toml` records that same fact as the reason
    /// the wrapper is mutation-excluded; the test and the exclusion note were
    /// asserting opposite things in one branch.
    #[test]
    fn basic_authorizer_subjects_fails_closed_on_an_unreadable_path() {
        use maknae_security::Authorizer;
        let auth = BasicAuthorizer {
            policy_path: "/nonexistent".into(),
            principal: principal(),
            uid_map: UidMap::new(),
        };
        assert!(auth.subjects().is_none(), "unreadable must fail closed");
    }

    /// TWO members under one role, asserted BY EQUALITY on the sorted vector.
    ///
    /// Replaces `subjects_reports_the_agent_binding` (#276). That test was the
    /// only one in the crate putting two members under a single role, so it was
    /// also the only exercise of `as_subject_bindings`'s `or_default().push()`
    /// accumulation and its `members.sort()`. Retiring it with the reserved
    /// token would have left `sort()` a newly-unkillable mutant in a `[t1]`
    /// zero-missed file -- the accumulation is the real subject, and it
    /// survives the token.
    #[test]
    fn subjects_reports_every_member_of_a_role_sorted() {
        let auth = BasicAuthorizer {
            policy_path: "/nonexistent".into(),
            principal: principal(),
            // uids 2 and 10, deliberately: `BTreeMap` iterates them NUMERICALLY
            // (2, 10) while `members.sort()` orders the rendered strings
            // LEXICALLY ("uid:10", "uid:2"). uids 0 and 99 -- the first choice
            // here -- agree in both orders, so the assertion passed with
            // `sort()` deleted (codex proved it). The two orders must disagree
            // or this proves nothing.
            uid_map: [("two".to_string(), 2u32), ("ten".to_string(), 10u32)]
                .into_iter()
                .collect(),
        };
        let got = auth
            .subjects_with_loader(|_| {
                maknae_config::parse_authz(
                    &format!("{GRANT_PREAMBLE}bindings:\n  admin: [\"ten\", \"two\"]\n"),
                    None,
                )
            })
            .expect("readable policy with an explicit block");
        let admin = got.iter().find(|b| b.role == "admin").expect("admin");
        assert_eq!(
            admin.members,
            vec!["uid:10".to_string(), "uid:2".to_string()],
            "both members, LEXICALLY sorted -- not BTreeMap's numeric order"
        );
    }

    /// NO `bindings:` key -> `None`, never `Some(vec![])`.
    ///
    /// The shipped `packaging/common/authz.yaml` has no `bindings:` key, so
    /// the DEFAULT deployment took this path and answered "these are the
    /// bindings, and there are none" -- while the default-role fallback was
    /// live and the enrolled uid was resolving to admin. That is the exact
    /// claim the `Option` on this seam exists to refuse.
    #[test]
    fn subjects_refuses_to_report_an_empty_set_when_no_block_exists() {
        let auth = BasicAuthorizer {
            policy_path: "/nonexistent".into(),
            principal: principal(),
            uid_map: UidMap::new(),
        };
        let no_key = auth.subjects_with_loader(|_| {
            maknae_config::parse_authz(GRANT_PREAMBLE, None) // no `bindings:` at all
        });
        assert!(
            no_key.is_none(),
            "no bindings key means CANNOT ENUMERATE, not `nobody is bound`: {no_key:?}"
        );

        // An EXPLICIT empty block is a different state and IS reportable --
        // the operator wrote "nobody", so saying so is honest.
        let explicit_empty = auth
            .subjects_with_loader(|_| {
                maknae_config::parse_authz(
                    &format!("{GRANT_PREAMBLE}bindings:\n  admin: []\n"),
                    None,
                )
            })
            .expect("an explicit block is reportable");
        assert!(explicit_empty.is_empty(), "{explicit_empty:?}");
    }

    #[test]
    fn backend_name_identifies_this_backend() {
        let auth = BasicAuthorizer {
            policy_path: "/nonexistent".into(),
            principal: principal(),
            uid_map: UidMap::new(),
        };
        assert_eq!(
            maknae_security::Authorizer::backend_name(&auth),
            "maknae-authz-basic"
        );
    }

    /// A valid `roles:` block CONSTRUCTS. The refusal tests above all pass
    /// against a validator that refuses everything, so this is the assertion
    /// that keeps them honest.
    #[test]
    fn roles_valid_grant_block_constructs() {
        let p = parse_with_roles(
            "roles:\n  admin:\n    allow: [\"admin.status\", \"admin.config.show\"]\n    deny: [\"admin.subject.list\"]\n",
        );
        BasicAuthorizer::finish_new("/nonexistent".into(), principal(), p)
            .expect("every role key and term is in vocabulary");
    }

    /// The per-request path refuses too, and refuses ANONYMOUSLY.
    ///
    /// "Same discriminant at both entry points" is not achievable and is not
    /// the goal: `assemble` returns `Result<_, ()>`, so there is no discriminant
    /// to assert. The contract is asymmetric on purpose -- boot NAMES the bad
    /// term in the journal where an operator is reading, while a per-request
    /// refusal stays `Indeterminate`, telling a caller nothing about why. What
    /// must hold at both ends is that neither one proceeds.
    ///
    /// This is the case where the file is edited to something invalid AFTER
    /// construction, which is reachable precisely because `decide` re-reads
    /// per request (the Zero Trust ruling) rather than holding a snapshot.
    #[test]
    fn roles_invalid_grants_edited_in_after_boot_are_indeterminate_per_request() {
        let auth = BasicAuthorizer {
            policy_path: "/nonexistent".into(),
            principal: principal(),
            uid_map: UidMap::new(),
        };
        // The injected loader IS the per-request re-read; only the source of
        // the bytes is hermetic. Nothing about the validation is stubbed.
        let v = auth.decide_with_loader(&liveness_req(Some(501)), |_| {
            maknae_config::parse_authz(
                &format!("{GRANT_PREAMBLE}roles:\n  admin:\n    allow: [\"admin.contain\"]\n"),
                None,
            )
        });
        assert_eq!(
            v,
            Verdict::Indeterminate,
            "an invalid grant block must fail the request closed, not fall through to the arms"
        );
    }

    /// Every error variant renders its offending token. An operator reading a
    /// boot refusal in the journal gets the token, not just a category.
    #[test]
    fn roles_error_display_names_the_offending_token() {
        assert!(AuthzBasicError::UnknownRole("admn".into())
            .to_string()
            .contains("admn"));
        // `starts_with`, not `contains`: the static tail names guest and
        // adversary, so a `contains` would pass without the interpolation.
        assert!(AuthzBasicError::RoleNotSupportedYet("adversary".into())
            .to_string()
            .starts_with("authz roles: role `adversary` takes no grants"));
        assert!(AuthzBasicError::TermNotGrantableForRole {
            role: "user".into(),
            term: "admin.status".into()
        }
        .to_string()
        .starts_with("authz roles: `admin.status` is not grantable to role `user`"));
        let d = AuthzBasicError::UnknownActionTerm("admin.contain".into()).to_string();
        assert!(d.contains("admin.contain"), "{d}");
        // ...and lists what IS grantable, so the fix is in the message.
        assert!(d.contains("admin.status"), "{d}");
    }

    #[test]
    fn finish_new_without_bindings_needs_no_lookups_and_defaults_apply() {
        let policy = maknae_config::parse_authz(
            "schema_version: 1\npermissions:\n  allow: []\n  deny: []\n",
            None,
        )
        .unwrap();
        let auth = BasicAuthorizer::finish_new("/nonexistent".into(), principal(), policy).unwrap();
        assert!(
            auth.uid_map.is_empty(),
            "no bindings → no NSS resolution at all"
        );
    }

    #[test]
    fn error_displays_name_their_cause() {
        assert!(AuthzBasicError::Load("boom".into())
            .to_string()
            .contains("load refused"));
        assert!(AuthzBasicError::Bindings("b".into())
            .to_string()
            .contains("bindings invalid"));
        use crate::binding::BindingError;
        for (e, needle) in [
            (BindingError::UnknownRole("r".into()), "unknown role"),
            (
                BindingError::DualMembership("n".into()),
                "more than one role",
            ),
            (BindingError::Duplicate("n".into()), "twice"),
            (BindingError::Unresolvable("n".into()), "no resolved uid"),
        ] {
            assert!(e.to_string().contains(needle), "{e:?}");
        }
    }

    /// The production `Authorizer::decide` path on an euid-owned fixture:
    /// the hardened door refuses (off root) → Indeterminate — proving decide()
    /// really rides load_authz and fails closed, not open.
    #[test]
    fn production_decide_fails_closed_on_an_unownable_fixture() {
        use std::os::unix::fs::PermissionsExt;
        if nix::unistd::geteuid().is_root() {
            return; // the refusal under test is unconstructible as root
        }
        let dir = std::env::temp_dir().join(format!("mab_prod_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700)).unwrap();
        let p = dir.join("authz.yaml");
        std::fs::write(
            &p,
            "schema_version: 1\npermissions:\n  allow: []\n  deny: []\n",
        )
        .unwrap();
        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o640)).unwrap();
        let auth = BasicAuthorizer {
            policy_path: p,
            principal: principal(),
            uid_map: UidMap::new(),
        };
        let v = auth.decide(&liveness_req(Some(501)));
        let _ = std::fs::remove_dir_all(&dir);
        assert_eq!(v, Verdict::Indeterminate);
    }

    #[test]
    fn new_refuses_a_non_root_owned_policy_file_off_root() {
        // The production door is load_authz (root-owned requirement): an
        // euid-owned fixture must refuse construction — proving `new` really
        // sits behind the hardened path (the eager-validation successes are
        // proven via the seam in tests/proofs.rs).
        use std::os::unix::fs::PermissionsExt;
        let dir = std::env::temp_dir().join(format!("mab_new_{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700)).unwrap();
        let p = dir.join("authz.yaml");
        std::fs::write(
            &p,
            "schema_version: 1\npermissions:\n  allow: []\n  deny: []\n",
        )
        .unwrap();
        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o640)).unwrap();
        let principal = maknae_config::Principal {
            name: "operator".into(),
            uid: 501,
            home: "/home/operator".into(),
        };
        let got = BasicAuthorizer::new(p, principal);
        let _ = std::fs::remove_dir_all(&dir);
        if nix::unistd::geteuid().is_root() {
            assert!(got.is_ok(), "as root the fixture IS root-owned: {got:?}");
        } else {
            assert!(
                matches!(got, Err(AuthzBasicError::Load(ref m)) if m.contains("root")),
                "unprivileged construction must refuse the euid-owned fixture: {got:?}"
            );
        }
    }
    /// In-crate killers for the feature-gated wrapper (`cargo mutants -p` runs
    /// only in-package tests, so these — not the kernel e2e — are what kill the
    /// wrapper's mutants when the mutation lane enables the feature).
    #[cfg(all(unix, feature = "hermetic-test-seam"))]
    mod hermetic {
        use super::super::*;
        use maknae_security::{
            Action, AttrValue, Attributes, Authorizer, Context, Resource, Subject, Verdict,
        };
        use std::os::unix::fs::PermissionsExt;

        fn fixture_req() -> maknae_config::TargetRequired {
            maknae_config::TargetRequired {
                owner: None,
                mode_mask: Some(0o022),
                nlink_exactly_one: false,
                regular_file: true,
                max_bytes: None,
            }
        }

        fn principal() -> maknae_config::Principal {
            maknae_config::Principal {
                name: "operator".into(),
                uid: 501,
                home: "/home/operator".into(),
            }
        }

        fn write_policy(p: &std::path::Path, bindings_role: &str) {
            std::fs::write(
                p,
                format!(
                    "schema_version: 1\npermissions:\n  allow: []\n  deny: []\nbindings:\n  {bindings_role}: [\"root\"]\n"
                ),
            )
            .unwrap();
            std::fs::set_permissions(p, std::fs::Permissions::from_mode(0o640)).unwrap();
        }

        fn whoami_req(uid: i64) -> maknae_security::Request {
            let mut s = Attributes::new();
            s.insert("uid", AttrValue::Int(uid));
            maknae_security::Request {
                subject: Subject(s),
                resource: Resource(Attributes::new()),
                action: Action("admin.whoami".into()),
                context: Context(Attributes::new()),
            }
        }

        fn fixture_dir(tag: &str) -> std::path::PathBuf {
            let d = std::env::temp_dir().join(format!("mab_herm_{tag}_{}", std::process::id()));
            let _ = std::fs::remove_dir_all(&d);
            std::fs::create_dir_all(&d).unwrap();
            std::fs::set_permissions(&d, std::fs::Permissions::from_mode(0o700)).unwrap();
            d
        }

        /// Constructor refuses an unresolvable binding, naming the identity —
        /// proving `new` really runs the eager `finish_new` validation.
        #[test]
        fn constructor_refuses_unresolvable_binding() {
            let d = fixture_dir("bindfail");
            let p = d.join("authz.yaml");
            std::fs::write(
                &p,
                "schema_version: 1\npermissions:\n  allow: []\n  deny: []\nbindings:\n  user: [\"no-such-user-maknae-77\"]\n",
            )
            .unwrap();
            std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o640)).unwrap();
            let got = HermeticAuthorizer::new(p, principal(), fixture_req());
            let _ = std::fs::remove_dir_all(&d);
            assert!(
                matches!(got, Err(AuthzBasicError::Bindings(ref m)) if m.contains("no-such-user-maknae-77")),
                "{got:?}"
            );
        }

        /// #275: the decision reports the role it was MADE ON, from the same
        /// policy read. All four shipped roles, through the real decide path.
        #[test]
        fn the_decision_reports_the_role_it_was_made_on_for_every_shipped_role() {
            for role in ["admin", "user", "guest", "adversary"] {
                let d = fixture_dir(&format!("role_{role}"));
                let p = d.join("authz.yaml");
                write_policy(&p, role);
                let auth = HermeticAuthorizer::new(p, principal(), fixture_req()).unwrap();
                let (_v, got) = auth.decide_reporting_role(&whoami_req(0));
                let _ = std::fs::remove_dir_all(&d);
                assert_eq!(got, Some(role), "role reported for binding {role}");
            }
        }

        /// A subject bound to nothing reports NO role — never a default. The
        /// verdict is the annotated absence, and the role is honestly absent.
        #[test]
        fn a_subject_resolving_to_no_role_reports_none_not_a_default() {
            let d = fixture_dir("norole");
            let p = d.join("authz.yaml");
            write_policy(&p, "admin");
            let auth = HermeticAuthorizer::new(p, principal(), fixture_req()).unwrap();
            // uid 4242 is bound by nothing; `root` (uid 0) is the only binding.
            let (v, got) = auth.decide_reporting_role(&whoami_req(4242));
            let _ = std::fs::remove_dir_all(&d);
            assert_eq!(got, None, "an unbound uid must never be given a role");
            assert!(
                matches!(v, Verdict::NotApplicable { .. }),
                "expected the annotated absence, got {v:?}"
            );
        }

        /// The wrapper must delegate through the HERMETIC loader. Delegating to
        /// the inner authorizer's own override would use the production
        /// root-owned loader and report Indeterminate/None here — this test is
        /// what catches that.
        #[test]
        fn the_wrapper_reports_a_role_which_proves_it_used_the_hermetic_loader() {
            let d = fixture_dir("hermloader");
            let p = d.join("authz.yaml");
            write_policy(&p, "admin");
            let auth = HermeticAuthorizer::new(p, principal(), fixture_req()).unwrap();
            let (v, got) = auth.decide_reporting_role(&whoami_req(0));
            let _ = std::fs::remove_dir_all(&d);
            assert_eq!(got, Some("admin"));
            assert!(matches!(v, Verdict::Permit { .. }), "{v:?}");
        }

        /// `decide` IS `decide_reporting_role().0` — a guard against a future
        /// re-implementation splitting the two paths apart again.
        #[test]
        fn decide_agrees_with_the_role_reporting_path() {
            let d = fixture_dir("agree");
            let p = d.join("authz.yaml");
            write_policy(&p, "admin");
            let auth = HermeticAuthorizer::new(p, principal(), fixture_req()).unwrap();
            for uid in [0, 501, 4242] {
                assert_eq!(
                    auth.decide(&whoami_req(uid)),
                    auth.decide_reporting_role(&whoami_req(uid)).0,
                    "uid {uid}"
                );
            }
            let _ = std::fs::remove_dir_all(&d);
        }

        /// Trait-path permit → containment flip: the wrapper's `decide` rides the
        /// real per-request re-read (the Zero Trust property) end to end.
        #[test]
        fn trait_path_permits_then_flips_to_deny_on_file_edit() {
            let d = fixture_dir("flip");
            let p = d.join("authz.yaml");
            write_policy(&p, "admin");
            let auth = HermeticAuthorizer::new(p.clone(), principal(), fixture_req()).unwrap();
            let before = auth.decide(&whoami_req(0));
            assert!(matches!(before, Verdict::Permit { .. }), "{before:?}");

            write_policy(&p, "adversary");
            let after = auth.decide(&whoami_req(0));
            let _ = std::fs::remove_dir_all(&d);
            assert!(
                matches!(after, Verdict::Deny { ref reason } if reason.contains("role=adversary")),
                "{after:?}"
            );
        }

        /// The wrapper's `subjects` and `backend_name` DELEGATE to the inner
        /// backend rather than taking the trait defaults. A default here would
        /// make every kernel e2e assert against `None`/`unknown` and prove
        /// nothing about what production answers -- and it reads LIVE, so a
        /// binding edited after construction shows up on the next call.
        #[test]
        fn wrapper_subjects_delegate_and_read_live() {
            let d = fixture_dir("subjects");
            let p = d.join("authz.yaml");
            write_policy(&p, "admin");
            let auth = HermeticAuthorizer::new(p.clone(), principal(), fixture_req()).unwrap();

            assert_eq!(auth.backend_name(), "maknae-authz-basic");
            let before = auth.subjects().expect("readable policy");
            assert_eq!(before.len(), 1);
            assert_eq!(before[0].role, "admin");
            assert_eq!(before[0].members, vec!["uid:0".to_string()]);

            // LIVE: the same edit that flips a verdict flips the listing.
            write_policy(&p, "adversary");
            let after = auth.subjects().expect("still readable");
            let _ = std::fs::remove_dir_all(&d);
            assert_eq!(
                after[0].role, "adversary",
                "subjects must re-read, not report a construction-time snapshot"
            );
        }

        /// Every Permit through the wrapper carries exactly the audit obligation —
        /// the PEP-side discharge contract depends on it.
        #[test]
        fn wrapper_permit_carries_exactly_audit_obligation() {
            let d = fixture_dir("oblig");
            let p = d.join("authz.yaml");
            write_policy(&p, "admin");
            let auth = HermeticAuthorizer::new(p, principal(), fixture_req()).unwrap();
            let v = auth.decide(&whoami_req(0));
            let _ = std::fs::remove_dir_all(&d);
            match v {
                Verdict::Permit { obligations } => {
                    assert_eq!(obligations.len(), 1);
                    assert_eq!(obligations[0].id, "audit");
                    assert!(obligations[0].params.is_empty());
                }
                other => panic!("expected Permit, got {other:?}"),
            }
        }

        /// The wrapper honors ITS requirement: a fixture violating the declared
        /// mode requirement is refused at construction (the checks are real).
        #[test]
        fn constructor_honors_the_declared_requirement() {
            let d = fixture_dir("mode");
            let p = d.join("authz.yaml");
            write_policy(&p, "admin");
            std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o666)).unwrap();
            let got = HermeticAuthorizer::new(p, principal(), fixture_req());
            let _ = std::fs::remove_dir_all(&d);
            assert!(matches!(got, Err(AuthzBasicError::Load(_))), "{got:?}");
        }
    }
}
