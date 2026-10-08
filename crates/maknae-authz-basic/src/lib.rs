//! maknae-authz-basic — the RBAC PDP backend behind the `maknae-security`
//! seam (#85). Four code-defined roles (`admin`/`user`/`guest`/`adversary`)
//! decide four-valued verdicts from `authz.yaml` and `bindings.yaml`, per request, deny-by-default, fail-closed. Spec:
//! `2026-08-26-maknae-authz-basic-design.md` (out-of-repo design spec; specs never live in this repository).
//!
//! Composition: `maknaed` compiles the policy into a [`snapshot::Snapshot`] at
//! boot (#77, `maknae-kernel::boot_gate`) and decides every request from the
//! snapshot installed at the time; a reload installs a new one. The seam stays
//! policy-agnostic (ADR-0004).
#![forbid(unsafe_code)]

mod binding;
mod decide;

/// The grantable term set, re-exported for CROSS-CRATE tripwires (#181).
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
pub mod snapshot;
mod vocabulary;
pub use vocabulary::{class_name, compiled_set, ACTION_TERMS, CLASSES, KERNEL_TERMS};

use binding::UidMap;
use decide::LoadedPolicy;
use snapshot::Snapshot;
use std::path::{Path, PathBuf};
use std::sync::{Arc, PoisonError, RwLock};

/// Subject attribute key for the authenticated uid (pinned for #77; ADR-0018:
/// the per-request authorization principal is the uid, from peer-cred).
pub const SUBJECT_UID_KEY: &str = decide::SUBJECT_UID;
/// Resource attribute key carrying the (already-resolved) filesystem path for
/// `fs.*` actions (spec §4.4).
pub const RESOURCE_PATH_KEY: &str = decide::RESOURCE_PATH;

/// Why loading or compiling the policy refused (all fail-closed; §3a). The
/// daemon's boot gate (#77) surfaces this as a boot refusal, a reload as a
/// refused reload.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AuthzBasicError {
    /// The policy file failed the hardened load (ownership/mode/symlink/
    /// grammar) — the message is `AuthzError`'s rendering.
    Load(String),
    /// `bindings.yaml` is semantically invalid (unknown role, dual
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
    /// The snapshot compiler refused the policy against the persisted identity
    /// layer or the vocabulary.
    Compile(snapshot::CompileError),
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
            AuthzBasicError::Compile(e) => write!(f, "authz {e}"),
        }
    }
}

impl std::error::Error for AuthzBasicError {}

/// The RBAC PDP backend: the enrolled principal and the compiled policy
/// snapshot every decision reads. `paths` and `digest` are what a reload loads
/// and compiles with; nothing reads the files per request.
#[derive(Debug)]
pub struct BasicAuthorizer {
    principal: maknae_config::Principal,
    paths: PolicyPaths,
    digest: fn(&[u8]) -> [u8; 32],
    snapshot: RwLock<Arc<Snapshot>>,
    #[cfg(any(test, all(unix, feature = "hermetic-test-seam")))]
    evaluation_gate: Option<Arc<EvaluationGate>>,
}

/// Parks each evaluation after it has decided on its snapshot and before it
/// cites: `arrived`, then `release`.
#[cfg(any(test, all(unix, feature = "hermetic-test-seam")))]
#[derive(Debug)]
pub struct EvaluationGate {
    pub arrived: std::sync::Barrier,
    pub release: std::sync::Barrier,
}

impl BasicAuthorizer {
    pub fn from_snapshot(
        principal: maknae_config::Principal,
        paths: PolicyPaths,
        digest: fn(&[u8]) -> [u8; 32],
        snapshot: Arc<Snapshot>,
    ) -> Self {
        Self {
            principal,
            paths,
            digest,
            snapshot: RwLock::new(snapshot),
            #[cfg(any(test, all(unix, feature = "hermetic-test-seam")))]
            evaluation_gate: None,
        }
    }

    /// The installed snapshot. The read guard is released before this returns,
    /// so an evaluation never holds the lock.
    pub fn snapshot(&self) -> Arc<Snapshot> {
        self.snapshot
            .read()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }

    /// The hot swap: the next decision reads `snapshot`; a decision already
    /// holding the previous one finishes on it.
    pub fn install(&self, snapshot: Arc<Snapshot>) {
        *self
            .snapshot
            .write()
            .unwrap_or_else(PoisonError::into_inner) = snapshot;
    }

    fn decide_on(
        &self,
        snap: &Snapshot,
        req: &maknae_security::Request,
    ) -> maknae_security::Decided {
        let d = decide::decide_loaded_cited(snap.loaded(), &self.principal, req);
        #[cfg(any(test, all(unix, feature = "hermetic-test-seam")))]
        if let Some(gate) = &self.evaluation_gate {
            gate.arrived.wait();
            gate.release.wait();
        }
        maknae_security::Decided {
            verdict: d.verdict,
            role: d.role,
            rule: d.cited.as_ref().and_then(|c| snap.cite(c)),
        }
    }

    /// The file-based evaluator the snapshot path must agree with.
    #[cfg(test)]
    fn decide_oracle(
        &self,
        source: &PolicySource,
        req: &maknae_security::Request,
    ) -> (maknae_security::Verdict, Option<&'static str>) {
        match assemble(source.policy().clone(), source.legacy(), source.uid_map()) {
            Ok(lp) => decide::decide_loaded_with_role(&lp, &self.principal, req),
            Err(()) => (maknae_security::Verdict::Indeterminate, None),
        }
    }
}

/// Where the two policy files live: `authz.yaml` (grants, denies, roles) and
/// `bindings.yaml` (identity).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PolicyPaths {
    pub authz: PathBuf,
    pub bindings: PathBuf,
}

impl PolicyPaths {
    pub fn in_dir(dir: &Path) -> Self {
        Self {
            authz: dir.join("authz.yaml"),
            bindings: dir.join(maknae_config::BINDINGS_FILE),
        }
    }
}

fn utf8(p: &Path) -> Result<String, AuthzBasicError> {
    p.to_str()
        .map(str::to_string)
        .ok_or_else(|| AuthzBasicError::Load(format!("policy path {} is not UTF-8", p.display())))
}

type LegacyBindings = Option<std::collections::BTreeMap<String, Vec<String>>>;

/// A loaded, validated `authz.yaml` and `bindings.yaml` with the bound usernames
/// resolved to uids: the policy input the snapshot compiler takes.
#[derive(Debug, Clone)]
pub struct PolicySource {
    policy: maknae_config::AuthzPolicy,
    bindings: maknae_config::Bindings,
    legacy: LegacyBindings,
    uid_map: UidMap,
    resolved: binding::ResolvedBindings,
    principal: maknae_config::Principal,
    paths: PolicyPaths,
    policy_source: String,
    identity_source: String,
}

impl PolicySource {
    /// The production loaders (root-owned, `mode & 0o027 == 0`, symlink-refused) for
    /// both files, then one getpwnam per bound username and eager validation.
    pub fn load(
        paths: PolicyPaths,
        principal: maknae_config::Principal,
    ) -> Result<Self, AuthzBasicError> {
        let policy = maknae_config::load_authz(&paths.authz)
            .map_err(|e| AuthzBasicError::Load(e.to_string()))?;
        let bindings = maknae_config::load_bindings(&paths.bindings)
            .map_err(|e| AuthzBasicError::Load(e.to_string()))?;
        let uid_map = resolve_uid_map(&bindings)?;
        Self::from_parts(policy, bindings, uid_map, principal, paths)
    }

    #[cfg(all(unix, feature = "hermetic-test-seam"))]
    pub fn load_with_requirement(
        paths: PolicyPaths,
        principal: maknae_config::Principal,
        req: maknae_config::TargetRequired,
    ) -> Result<Self, AuthzBasicError> {
        let policy = maknae_config::load_authz_with_requirement(&paths.authz, req.clone())
            .map_err(|e| AuthzBasicError::Load(e.to_string()))?;
        let bindings = maknae_config::load_bindings_with_requirement(&paths.bindings, req)
            .map_err(|e| AuthzBasicError::Load(e.to_string()))?;
        let uid_map = resolve_uid_map(&bindings)?;
        Self::from_parts(policy, bindings, uid_map, principal, paths)
    }

    pub fn from_parts(
        policy: maknae_config::AuthzPolicy,
        bindings: maknae_config::Bindings,
        uid_map: std::collections::BTreeMap<String, u32>,
        principal: maknae_config::Principal,
        paths: PolicyPaths,
    ) -> Result<Self, AuthzBasicError> {
        let policy_source = utf8(&paths.authz)?;
        let identity_source = utf8(&paths.bindings)?;
        let (legacy, uid_map) = legacy_bindings(&bindings, uid_map)?;
        let resolved = binding::resolve(&legacy, &uid_map)
            .map_err(|e| AuthzBasicError::Bindings(e.to_string()))?;
        validate_grants(&policy.action_grants)?;
        validate_destinations(&policy.destinations)?;
        Ok(Self {
            policy,
            bindings,
            legacy,
            uid_map,
            resolved,
            principal,
            paths,
            policy_source,
            identity_source,
        })
    }

    pub fn policy(&self) -> &maknae_config::AuthzPolicy {
        &self.policy
    }

    pub fn bindings(&self) -> &maknae_config::Bindings {
        &self.bindings
    }

    pub fn principal(&self) -> &maknae_config::Principal {
        &self.principal
    }

    pub fn paths(&self) -> &PolicyPaths {
        &self.paths
    }

    pub(crate) fn policy_source(&self) -> &str {
        &self.policy_source
    }

    pub(crate) fn legacy(&self) -> &LegacyBindings {
        &self.legacy
    }

    pub(crate) fn uid_map(&self) -> &UidMap {
        &self.uid_map
    }

    /// The identity layer `bindings.yaml` declares; `source` is its path and
    /// `bindings_sha256` is `None` iff the file has no `bindings:` key. Subjects are in
    /// uid order, the order `identity::extract` produces, so an unchanged file compares
    /// equal to its persisted layer.
    pub fn identity_layer(
        &self,
        label: &str,
        bindings_sha256: Option<[u8; 32]>,
    ) -> maknae_graph::identity::IdentityLayer {
        maknae_graph::identity::IdentityLayer {
            source: self.identity_source.clone(),
            label: label.into(),
            bindings_sha256,
            subjects: self
                .resolved
                .subjects()
                .map(|(uid, role, name)| maknae_graph::identity::SubjectEntry {
                    uid,
                    name: name.into(),
                    role: role.key().into(),
                })
                .collect(),
        }
    }

    /// `authz.yaml`'s top-level sections, plus `"bindings"` from `bindings.yaml` when it
    /// has the key, each canonical JSON through the caller's digest, by key.
    pub fn section_digests(
        &self,
        digest: fn(&[u8]) -> [u8; 32],
    ) -> std::collections::BTreeMap<String, [u8; 32]> {
        let mut out: std::collections::BTreeMap<String, [u8; 32]> = self
            .policy
            .sections()
            .map(|(k, v)| (k.to_string(), digest(v.as_bytes())))
            .collect();
        if let Some(b) = self.bindings.section_canonical() {
            out.insert("bindings".into(), digest(b.as_bytes()));
        }
        out
    }
}

/// The file's entries as the name-keyed resolver reads them: a `uid:` entry becomes
/// the name `uid:N` mapped to N. `uid:` entries are accepted under `adversary` only.
fn legacy_bindings(
    bindings: &maknae_config::Bindings,
    mut uid_map: UidMap,
) -> Result<(LegacyBindings, UidMap), AuthzBasicError> {
    let Some(roles) = &bindings.roles else {
        return Ok((None, uid_map));
    };
    let mut out = std::collections::BTreeMap::new();
    for (role, entries) in roles {
        let mut names = Vec::new();
        for e in entries {
            if let maknae_config::BindingEntry::Uid(u) = e {
                if role != "adversary" {
                    return Err(AuthzBasicError::Bindings(format!(
                        "role '{role}' lists a uid entry; `uid:` entries are accepted under adversary only"
                    )));
                }
                uid_map.insert(e.render(), *u);
            }
            names.push(e.render());
        }
        out.insert(role.clone(), names);
    }
    Ok((Some(out), uid_map))
}

/// policy → LoadedPolicy under a uid map; any invalidity → Err. Anonymous by
/// design: `PolicySource::from_parts` has already named the offending token.
fn assemble(
    policy: maknae_config::AuthzPolicy,
    legacy: &LegacyBindings,
    uid_map: &UidMap,
) -> Result<LoadedPolicy, ()> {
    let roles = binding::Roles::File(binding::resolve(legacy, uid_map).map_err(|_| ())?);
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
/// key refuses by name. Runs on every load.
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

/// getpwnam every bound username once per load; a `uid:` entry needs no lookup.
/// Unresolvable → the load refuses. `cfg(unix)` is the only lane — the
/// workspace's non-unix story is fail-closed refusal upstream in
/// `maknae-config` (`load_authz` refuses off-unix before we are reached).
fn resolve_uid_map(bindings: &maknae_config::Bindings) -> Result<UidMap, AuthzBasicError> {
    let mut map = UidMap::new();
    let Some(roles) = &bindings.roles else {
        return Ok(map);
    };
    for entries in roles.values() {
        for entry in entries {
            let maknae_config::BindingEntry::Name(name) = entry else {
                continue;
            };
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

impl maknae_security::Authorizer for BasicAuthorizer {
    fn decide(&self, req: &maknae_security::Request) -> maknae_security::Verdict {
        self.decide_cited(req).verdict
    }

    fn decide_reporting_role(
        &self,
        req: &maknae_security::Request,
    ) -> (maknae_security::Verdict, Option<&'static str>) {
        self.decide_cited(req).into()
    }

    /// One decision from one snapshot: the verdict, the role and the cited
    /// rule all come from the `Arc` cloned out here.
    fn decide_cited(&self, req: &maknae_security::Request) -> maknae_security::Decided {
        self.decide_on(&self.snapshot(), req)
    }

    fn decide_cited_all(&self, reqs: &[maknae_security::Request]) -> Vec<maknae_security::Decided> {
        let snap = self.snapshot();
        reqs.iter().map(|r| self.decide_on(&snap, r)).collect()
    }

    fn subjects(&self) -> Option<Vec<maknae_security::SubjectBinding>> {
        self.snapshot().subjects()
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
pub trait Baseline: maknae_security::Authorizer + sealed::Sealed + Send + Sync + 'static {
    fn snapshot(&self) -> Arc<Snapshot>;
    fn install(&self, snapshot: Arc<Snapshot>);
    fn principal(&self) -> &maknae_config::Principal;
    /// Load and validate the policy file through this baseline's own loader.
    /// Blocking I/O, including getpwnam: call it off the async workers.
    fn load_source(&self) -> Result<PolicySource, AuthzBasicError>;
    /// The section digest this baseline's snapshots are compiled with.
    fn digest(&self) -> fn(&[u8]) -> [u8; 32];

    /// The installed snapshot's [`Snapshot::policy_sha256`].
    fn policy_sha256(&self) -> String {
        self.snapshot().policy_sha256(self.digest())
    }
}

mod sealed {
    pub trait Sealed {}
}

impl sealed::Sealed for BasicAuthorizer {}
impl Baseline for BasicAuthorizer {
    fn snapshot(&self) -> Arc<Snapshot> {
        BasicAuthorizer::snapshot(self)
    }

    fn install(&self, snapshot: Arc<Snapshot>) {
        BasicAuthorizer::install(self, snapshot)
    }

    fn principal(&self) -> &maknae_config::Principal {
        &self.principal
    }

    fn load_source(&self) -> Result<PolicySource, AuthzBasicError> {
        PolicySource::load(self.paths.clone(), self.principal.clone())
    }

    fn digest(&self) -> fn(&[u8]) -> [u8; 32] {
        self.digest
    }
}

#[cfg(all(unix, feature = "hermetic-test-seam"))]
impl sealed::Sealed for HermeticAuthorizer {}
#[cfg(all(unix, feature = "hermetic-test-seam"))]
impl Baseline for HermeticAuthorizer {
    fn snapshot(&self) -> Arc<Snapshot> {
        self.inner.snapshot()
    }

    fn install(&self, snapshot: Arc<Snapshot>) {
        self.inner.install(snapshot)
    }

    fn principal(&self) -> &maknae_config::Principal {
        &self.inner.principal
    }

    fn load_source(&self) -> Result<PolicySource, AuthzBasicError> {
        PolicySource::load_with_requirement(
            self.inner.paths.clone(),
            self.inner.principal.clone(),
            self.req.clone(),
        )
    }

    fn digest(&self) -> fn(&[u8]) -> [u8; 32] {
        self.inner.digest
    }
}

/// Test-only, requirement-parameterized door over the production load and
/// compile sequence (#77; the PR #139 pattern): the loader's `TargetRequired`
/// is the caller's, everything else — eager validation, the snapshot compiler,
/// the decision core — is the production code. `BasicAuthorizer`'s own shape is
/// untouched by the feature. Production resolution is pinned featureless by
/// `ci/gates/feature-resolution-pin.sh`.
#[cfg(all(unix, feature = "hermetic-test-seam"))]
#[derive(Debug)]
pub struct HermeticAuthorizer {
    inner: BasicAuthorizer,
    req: maknae_config::TargetRequired,
    label: String,
}

#[cfg(all(unix, feature = "hermetic-test-seam"))]
impl HermeticAuthorizer {
    /// Compiles the first snapshot over an identity graph built in memory at
    /// revision 1, labelled with the US system's lowest level.
    pub fn new(
        paths: PolicyPaths,
        principal: maknae_config::Principal,
        req: maknae_config::TargetRequired,
        digest: fn(&[u8]) -> [u8; 32],
    ) -> Result<Self, AuthzBasicError> {
        let label =
            maknae_security::ClassificationPolicy::unmarked(&maknae_config::BasicPolicy).name;
        let source =
            PolicySource::load_with_requirement(paths.clone(), principal.clone(), req.clone())?;
        let snapshot = snapshot_over(&source, &label, digest, None)?;
        Ok(Self {
            inner: BasicAuthorizer::from_snapshot(principal, paths, digest, snapshot),
            req,
            label,
        })
    }

    /// Compiles the first snapshot against `persisted`, which must carry the
    /// identity layer the file declares.
    pub fn new_over_graph(
        paths: PolicyPaths,
        principal: maknae_config::Principal,
        req: maknae_config::TargetRequired,
        digest: fn(&[u8]) -> [u8; 32],
        persisted: Arc<maknae_graph::graph::Graph>,
    ) -> Result<Self, AuthzBasicError> {
        let label = maknae_graph::identity::extract(&persisted)
            .map_err(|e| AuthzBasicError::Compile(snapshot::CompileError::Identity(e.to_string())))?
            .layer
            .label;
        let source =
            PolicySource::load_with_requirement(paths.clone(), principal.clone(), req.clone())?;
        let snapshot = snapshot::compile(
            persisted,
            &source,
            &compiled_set(&label),
            &source.section_digests(digest),
        )
        .map_err(AuthzBasicError::Compile)?;
        Ok(Self {
            inner: BasicAuthorizer::from_snapshot(principal, paths, digest, Arc::new(snapshot)),
            req,
            label,
        })
    }

    /// Load, re-resolve and compile the file against the installed snapshot's
    /// identity graph, advanced one revision when the file's layer differs.
    pub fn compile_from_file(&self) -> Result<Arc<Snapshot>, AuthzBasicError> {
        let source = Baseline::load_source(self)?;
        let current = self.inner.snapshot();
        snapshot_over(
            &source,
            &self.label,
            self.inner.digest,
            Some(current.persisted()),
        )
    }

    /// [`Self::compile_from_file`] then install; an `Err` leaves the old snapshot.
    pub fn reload_from_file(&self) -> Result<(), AuthzBasicError> {
        let next = self.compile_from_file()?;
        self.inner.install(next);
        Ok(())
    }

    pub fn digest(&self) -> fn(&[u8]) -> [u8; 32] {
        self.inner.digest
    }

    /// Every later evaluation parks on `gate`.
    pub fn park_evaluations(&mut self, gate: Arc<EvaluationGate>) {
        self.inner.evaluation_gate = Some(gate);
    }
}

/// Every seam method DELEGATES: a default here would make every kernel e2e
/// assert against a stub and prove nothing about what production answers.
#[cfg(all(unix, feature = "hermetic-test-seam"))]
impl maknae_security::Authorizer for HermeticAuthorizer {
    fn decide(&self, r: &maknae_security::Request) -> maknae_security::Verdict {
        self.inner.decide(r)
    }

    fn decide_reporting_role(
        &self,
        r: &maknae_security::Request,
    ) -> (maknae_security::Verdict, Option<&'static str>) {
        self.inner.decide_reporting_role(r)
    }

    fn decide_cited(&self, r: &maknae_security::Request) -> maknae_security::Decided {
        self.inner.decide_cited(r)
    }

    fn decide_cited_all(&self, reqs: &[maknae_security::Request]) -> Vec<maknae_security::Decided> {
        self.inner.decide_cited_all(reqs)
    }

    fn subjects(&self) -> Option<Vec<maknae_security::SubjectBinding>> {
        self.inner.subjects()
    }

    fn backend_name(&self) -> String {
        self.inner.backend_name()
    }
}

/// Builds the identity graph `source` declares — fresh at revision 1, or `base`
/// carried forward (unchanged, or at its revision + 1 when the layer differs) —
/// and compiles the snapshot over it.
#[cfg(any(test, all(unix, feature = "hermetic-test-seam")))]
fn snapshot_over(
    source: &PolicySource,
    label: &str,
    digest: fn(&[u8]) -> [u8; 32],
    base: Option<&Arc<maknae_graph::graph::Graph>>,
) -> Result<Arc<Snapshot>, AuthzBasicError> {
    use maknae_graph::record::ProvenanceKind;
    let refused = |m: String| AuthzBasicError::Compile(snapshot::CompileError::Identity(m));
    let digests = source.section_digests(digest);
    let layer = source.identity_layer(label, digests.get("bindings").copied());
    let persisted_set = maknae_graph::kernel::persisted_compiled_set(label);
    let vocabulary = digest(
        &persisted_set
            .canonical_bytes()
            .map_err(|e| refused(e.to_string()))?,
    );
    let build = |revision: u64, initiator: ProvenanceKind| {
        maknae_graph::identity::build(&layer, &persisted_set, vocabulary, revision, initiator)
            .map(Arc::new)
            .map_err(|e| refused(e.to_string()))
    };
    let persisted = match base {
        None => build(1, ProvenanceKind::Seed)?,
        Some(g) => {
            let stored = maknae_graph::identity::extract(g).map_err(|e| refused(e.to_string()))?;
            if stored.layer == layer {
                g.clone()
            } else {
                build(g.revision() + 1, ProvenanceKind::RootFile)?
            }
        }
    };
    snapshot::compile(persisted, source, &compiled_set(label), &digests)
        .map(Arc::new)
        .map_err(AuthzBasicError::Compile)
}

/// A deterministic 32-byte fold of `bytes` (four FNV-1a-64 lanes). NOT
/// cryptographic: it stands in for SHA-256 where no store is involved, and a
/// digest value never enters a verdict.
#[cfg(any(test, all(unix, feature = "hermetic-test-seam")))]
pub fn test_digest(bytes: &[u8]) -> [u8; 32] {
    let mut out = [0u8; 32];
    for (lane, chunk) in out.chunks_mut(8).enumerate() {
        let mut h: u64 = 0xcbf2_9ce4_8422_2325 ^ lane as u64;
        for b in bytes {
            h ^= u64::from(*b);
            h = h.wrapping_mul(0x0000_0100_0000_01b3);
        }
        chunk.copy_from_slice(&h.to_le_bytes());
    }
    out
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

    const LABEL: &str = "UNCLASSIFIED";
    const DIR: &str = "/etc/maknae";
    const PATH: &str = "/etc/maknae/authz.yaml";
    const EMPTY: &str = "schema_version: 1\npermissions:\n  allow: []\n  deny: []\n";
    const ADMIN_ROOT: &str = "schema_version: 1\nbindings:\n  admin: [\"root\"]\n";
    const ADVERSARY_ROOT: &str = "schema_version: 1\nbindings:\n  adversary: [\"root\"]\n";
    const CONTAINED: &str = "subject contained: role=adversary";

    fn principal() -> maknae_config::Principal {
        maknae_config::Principal {
            name: "operator".into(),
            uid: 501,
        }
    }

    fn parse(body: &str) -> maknae_config::AuthzPolicy {
        maknae_config::parse_authz(body).expect("grammar is valid")
    }

    /// The production post-load half: one getpwnam per bound name, then eager
    /// validation.
    fn finish(policy: maknae_config::AuthzPolicy) -> Result<PolicySource, AuthzBasicError> {
        finish_with(policy, maknae_config::Bindings::missing())
    }

    fn finish_with(
        policy: maknae_config::AuthzPolicy,
        bindings: maknae_config::Bindings,
    ) -> Result<PolicySource, AuthzBasicError> {
        let uid_map = resolve_uid_map(&bindings)?;
        PolicySource::from_parts(policy, bindings, uid_map, principal(), paths())
    }

    fn bound(body: &str) -> maknae_config::Bindings {
        maknae_config::parse_bindings(body).expect("bindings grammar is valid")
    }

    fn paths() -> PolicyPaths {
        PolicyPaths::in_dir(Path::new(DIR))
    }

    fn source_with(authz: &str, bindings: Option<&str>, uids: &[(&str, u32)]) -> PolicySource {
        PolicySource::from_parts(
            parse(authz),
            bindings.map_or_else(maknae_config::Bindings::missing, bound),
            uids.iter().map(|(n, u)| (n.to_string(), *u)).collect(),
            principal(),
            paths(),
        )
        .unwrap()
    }

    fn compiled(src: &PolicySource) -> Arc<Snapshot> {
        snapshot_over(src, LABEL, test_digest, None).unwrap()
    }

    fn authorizer_over(
        authz: &str,
        bindings: Option<&str>,
        uids: &[(&str, u32)],
    ) -> BasicAuthorizer {
        BasicAuthorizer::from_snapshot(
            principal(),
            paths(),
            test_digest,
            compiled(&source_with(authz, bindings, uids)),
        )
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

    fn whoami(uid: i64) -> maknae_security::Request {
        let mut r = liveness_req(Some(uid));
        r.action = Action("admin.whoami".into());
        r
    }

    fn audit_permit() -> Verdict {
        Verdict::Permit {
            obligations: vec![maknae_security::Obligation {
                id: "audit".into(),
                params: Attributes::new(),
            }],
        }
    }

    fn contained() -> Verdict {
        Verdict::Deny {
            reason: CONTAINED.into(),
        }
    }

    fn ssh_read(uid: i64) -> maknae_security::Request {
        let mut r = liveness_req(Some(uid));
        r.action = Action("fs.read".into());
        r.subject.0.insert(
            maknae_security::SUBJECT_HOME,
            AttrValue::Str("/home/operator".into()),
        );
        r.resource.0.insert(
            RESOURCE_PATH_KEY,
            AttrValue::Str("/home/operator/.ssh/id_rsa".into()),
        );
        r.context.0.insert(
            maknae_security::CONTEXT_DAC_LANE,
            AttrValue::Str("local".into()),
        );
        r.context.0.insert(
            maknae_security::CONTEXT_FS_OPERATION,
            AttrValue::Str("read".into()),
        );
        r
    }

    const SHIPPED: &str = include_str!("../../../packaging/common/authz.yaml");

    /// Proof (a): the REAL shipped authz.yaml (byte-identical, via
    /// include_str!) parses, and with bindings absent the defaults branch
    /// decides: enrolled uid → admin rows; agent name → user rows.
    #[test]
    fn shipped_content_defaults_proof() {
        let policy = maknae_config::parse_authz(SHIPPED).expect("shipped authz.yaml parses");
        let lp = decide::LoadedPolicy {
            policy,
            roles: binding::Roles::File(binding::resolve(&None, &UidMap::new()).unwrap()),
            action_grants: decide::ActionGrants::default(),
            destinations: decide::DestinationGrants::default(),
        };
        let admin_whoami = decide::decide_loaded(&lp, &principal(), &whoami(501));
        assert!(matches!(admin_whoami, Verdict::Permit { .. }));
        assert!(matches!(
            decide::decide_loaded(&lp, &principal(), &ssh_read(501)),
            Verdict::Deny { ref reason } if reason.contains("Read(~/.ssh/**)")
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

    /// The decision names its rule, from the snapshot it was made on.
    #[test]
    fn decide_cited_names_the_rule_from_the_same_snapshot() {
        let auth = BasicAuthorizer::from_snapshot(
            principal(),
            paths(),
            test_digest,
            compiled(&source_with(SHIPPED, None, &[])),
        );
        let d = auth.decide_cited(&ssh_read(501));
        assert!(
            matches!(d.verdict, Verdict::Deny { ref reason } if reason.contains("Read(~/.ssh/**)"))
        );
        assert_eq!(d.role, Some("admin"));
        let rule = d.rule.expect("a path deny cites its rule");
        assert_eq!(rule.section, format!("{PATH}#permissions"));
        let node = auth
            .snapshot()
            .graph()
            .node(maknae_graph::record::NodeId(rule.node))
            .unwrap()
            .clone();
        assert_eq!(node.key, "rule:permissions:deny:0");
        assert_eq!(rule.key, node.key);
        assert_eq!(
            (
                auth.decide(&ssh_read(501)),
                auth.decide_reporting_role(&ssh_read(501))
            ),
            (d.verdict.clone(), (d.verdict, d.role))
        );
        let uncited = auth.decide_cited(&whoami(501));
        assert_eq!((uncited.verdict, uncited.rule), (audit_permit(), None));
    }

    /// The `cfg(test)` file-based evaluator agrees with the snapshot path.
    #[test]
    fn the_oracle_and_the_snapshot_agree() {
        let src = source_with(
            SHIPPED,
            Some(
                "schema_version: 1\nbindings:\n  user: [\"ursula\"]\n  adversary: [\"mallory\"]\n",
            ),
            &[("ursula", 1001), ("mallory", 666)],
        );
        let auth =
            BasicAuthorizer::from_snapshot(principal(), paths(), test_digest, compiled(&src));
        for req in [
            whoami(501),
            whoami(1001),
            whoami(666),
            whoami(4242),
            ssh_read(501),
            ssh_read(1001),
        ] {
            assert_eq!(
                auth.decide_oracle(&src, &req),
                auth.decide_reporting_role(&req)
            );
        }
        let broken = PolicySource {
            uid_map: UidMap::new(),
            ..src.clone()
        };
        assert_eq!(
            auth.decide_oracle(&broken, &whoami(1001)),
            (Verdict::Indeterminate, None)
        );
    }

    #[test]
    fn subjects_reports_none_without_a_bindings_section_and_an_empty_set_with_one() {
        let none = authorizer_over("schema_version: 1\n", None, &[]);
        assert_eq!(
            none.subjects(),
            None,
            "no bindings key means CANNOT ENUMERATE, not `nobody is bound`"
        );
        let empty = authorizer_over(
            "schema_version: 1\n",
            Some("schema_version: 1\nbindings:\n  admin: []\n"),
            &[],
        );
        assert_eq!(empty.subjects(), Some(vec![]));
        let one = authorizer_over(EMPTY, Some(ADMIN_ROOT), &[("root", 0)]);
        assert_eq!(
            one.subjects(),
            Some(vec![maknae_security::SubjectBinding {
                role: "admin".into(),
                members: vec!["uid:0".into()],
            }])
        );
    }

    #[test]
    fn subjects_on_the_shipped_tilde_policy_needs_no_home() {
        let auth = authorizer_over(SHIPPED, Some(ADMIN_ROOT), &[("root", 0)]);
        assert!(auth.subjects().is_some());
    }

    /// TWO members under one role, asserted BY EQUALITY on the sorted vector.
    /// uids 2 and 10, deliberately: `BTreeMap` iterates them NUMERICALLY
    /// while `members.sort()` orders the rendered strings LEXICALLY.
    #[test]
    fn subjects_reports_every_member_of_a_role_sorted() {
        let auth = authorizer_over(
            "schema_version: 1\n",
            Some("schema_version: 1\nbindings:\n  admin: [\"ten\", \"two\"]\n"),
            &[("two", 2), ("ten", 10)],
        );
        let got = auth.subjects().expect("an explicit block");
        let admin = got.iter().find(|b| b.role == "admin").expect("admin");
        assert_eq!(
            admin.members,
            vec!["uid:10".to_string(), "uid:2".to_string()],
            "both members, LEXICALLY sorted -- not BTreeMap's numeric order"
        );
    }

    #[test]
    fn backend_name_identifies_this_backend() {
        assert_eq!(
            authorizer_over("schema_version: 1\n", None, &[]).backend_name(),
            "maknae-authz-basic"
        );
    }

    #[test]
    fn the_baseline_trait_reports_this_authorizers_parts() {
        let auth = authorizer_over(EMPTY, Some(ADMIN_ROOT), &[("root", 0)]);
        assert_eq!(Baseline::principal(&auth), &principal());
        assert_eq!(Baseline::digest(&auth)(b"maknae"), test_digest(b"maknae"));
        let held = Baseline::snapshot(&auth);
        assert!(Arc::ptr_eq(&held, &auth.snapshot()));
        let folded = |body: &str| {
            let lines: String = source_with(EMPTY, Some(body), &[("root", 0)])
                .section_digests(test_digest)
                .iter()
                .map(|(k, d)| format!("{k}={}\n", maknae_graph::identity::hex(d)))
                .collect();
            maknae_graph::identity::hex(&test_digest(lines.as_bytes()))
        };
        assert_eq!(Baseline::policy_sha256(&auth), folded(ADMIN_ROOT));
        let next = compiled(&source_with(EMPTY, Some(ADVERSARY_ROOT), &[("root", 0)]));
        Baseline::install(&auth, next.clone());
        assert!(Arc::ptr_eq(&auth.snapshot(), &next));
        assert_eq!(auth.decide(&whoami(0)), contained());
        assert_eq!(Baseline::policy_sha256(&auth), folded(ADVERSARY_ROOT));
        assert_ne!(folded(ADVERSARY_ROOT), folded(ADMIN_ROOT));
    }

    /// The production `load_source` sits behind the root-owned door.
    #[test]
    fn production_load_source_sits_behind_the_root_owned_door() {
        use std::os::unix::fs::PermissionsExt;
        let dir = std::env::temp_dir().join(format!("mab_load_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700)).unwrap();
        for (name, body) in [("authz.yaml", EMPTY), ("bindings.yaml", ADMIN_ROOT)] {
            let p = dir.join(name);
            std::fs::write(&p, body).unwrap();
            std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o640)).unwrap();
        }
        let auth = BasicAuthorizer::from_snapshot(
            principal(),
            PolicyPaths::in_dir(&dir),
            test_digest,
            compiled(&source_with("schema_version: 1\n", None, &[])),
        );
        let got = Baseline::load_source(&auth);
        let _ = std::fs::remove_dir_all(&dir);
        if nix::unistd::geteuid().is_root() {
            let src = got.expect("as root the fixture IS root-owned");
            assert_eq!(src.uid_map().get("root"), Some(&0));
        } else {
            assert!(
                matches!(got, Err(AuthzBasicError::Load(ref m)) if m.contains("root")),
                "unprivileged load must refuse the euid-owned fixture: {got:?}"
            );
        }
    }

    #[test]
    fn concurrent_decisions_see_whole_snapshots() {
        let admin = compiled(&source_with(EMPTY, Some(ADMIN_ROOT), &[("root", 0)]));
        let adversary = compiled(&source_with(EMPTY, Some(ADVERSARY_ROOT), &[("root", 0)]));
        let auth = Arc::new(BasicAuthorizer::from_snapshot(
            principal(),
            paths(),
            test_digest,
            admin.clone(),
        ));
        let start = Arc::new(std::sync::Barrier::new(5));
        let deciders: Vec<_> = (0..4)
            .map(|_| {
                let auth = auth.clone();
                let start = start.clone();
                std::thread::spawn(move || {
                    start.wait();
                    (0..2_000)
                        .map(|_| auth.decide(&whoami(0)))
                        .collect::<Vec<_>>()
                })
            })
            .collect();
        start.wait();
        let mut installs = 0u32;
        while installs < 500 || !deciders.iter().all(|d| d.is_finished()) {
            auth.install(if installs.is_multiple_of(2) {
                adversary.clone()
            } else {
                admin.clone()
            });
            installs += 1;
        }
        if !installs.is_multiple_of(2) {
            auth.install(admin.clone());
        }
        let mut seen = (0, 0);
        for d in deciders {
            for v in d.join().unwrap() {
                if v == audit_permit() {
                    seen.0 += 1;
                } else {
                    assert_eq!(v, contained());
                    seen.1 += 1;
                }
            }
        }
        assert_eq!(seen.0 + seen.1, 8_000);
        assert!(Arc::ptr_eq(&auth.snapshot(), &admin));
    }

    #[test]
    fn a_poisoned_lock_is_recovered_not_propagated() {
        let auth = authorizer_over(EMPTY, Some(ADMIN_ROOT), &[("root", 0)]);
        std::thread::scope(|s| {
            let _ = s
                .spawn(|| {
                    let _guard = auth.snapshot.write().unwrap();
                    panic!("poison the snapshot lock");
                })
                .join();
        });
        assert!(auth.snapshot.is_poisoned());
        assert_eq!(auth.decide(&whoami(0)), audit_permit());
        auth.install(compiled(&source_with(
            EMPTY,
            Some(ADVERSARY_ROOT),
            &[("root", 0)],
        )));
        assert_eq!(auth.decide(&whoami(0)), contained());
    }

    #[test]
    fn install_is_visible_to_the_next_decide_only() {
        let auth = authorizer_over(EMPTY, Some(ADMIN_ROOT), &[("root", 0)]);
        let held = auth.snapshot();
        auth.install(compiled(&source_with(
            EMPTY,
            Some(ADVERSARY_ROOT),
            &[("root", 0)],
        )));
        let d = decide::decide_loaded_cited(held.loaded(), &principal(), &whoami(0));
        assert_eq!(
            d.verdict,
            audit_permit(),
            "the held snapshot keeps its answer"
        );
        assert_eq!(auth.decide(&whoami(0)), contained());
    }

    fn arrives(gate: &Arc<EvaluationGate>) -> bool {
        let (tx, rx) = std::sync::mpsc::channel();
        let gate = gate.clone();
        std::thread::spawn(move || {
            gate.arrived.wait();
            let _ = tx.send(());
        });
        rx.recv_timeout(std::time::Duration::from_secs(5)).is_ok()
    }

    /// A decision parked after cloning its snapshot out must not block an
    /// install, and it cites from the snapshot it decided on.
    #[test]
    fn decide_never_holds_the_lock_while_evaluating() {
        let mut auth = BasicAuthorizer::from_snapshot(
            principal(),
            paths(),
            test_digest,
            compiled(&source_with(SHIPPED, None, &[])),
        );
        let before = auth.decide_cited(&ssh_read(501));
        assert_eq!(
            before.rule.as_ref().expect("a path deny cites").key,
            "rule:permissions:deny:0"
        );
        let next = compiled(&source_with(
            &SHIPPED.replacen("  deny:\n", "  deny:\n    - \"Read(~/.cache/**)\"\n", 1),
            None,
            &[],
        ));
        let after = BasicAuthorizer::from_snapshot(principal(), paths(), test_digest, next.clone())
            .decide_cited(&ssh_read(501));
        assert_eq!(after.verdict, before.verdict);
        let (old, new) = (before.rule.clone().unwrap(), after.rule.unwrap());
        assert_ne!(old.key, new.key);
        assert_ne!(old.node, new.node);
        let gate = Arc::new(EvaluationGate {
            arrived: std::sync::Barrier::new(2),
            release: std::sync::Barrier::new(2),
        });
        auth.evaluation_gate = Some(gate.clone());
        let auth = Arc::new(auth);
        let parked = {
            let auth = auth.clone();
            std::thread::spawn(move || auth.decide_cited(&ssh_read(501)))
        };
        assert!(arrives(&gate), "the decision never reached evaluation");
        let (tx, rx) = std::sync::mpsc::channel();
        {
            let auth = auth.clone();
            std::thread::spawn(move || {
                auth.install(next);
                let _ = tx.send(());
            });
        }
        let installed = rx.recv_timeout(std::time::Duration::from_secs(5));
        assert!(
            installed.is_ok(),
            "install blocked behind an evaluating decision"
        );
        gate.release.wait();
        assert_eq!(
            parked.join().unwrap(),
            before,
            "the parked decision cites from the snapshot it decided on"
        );
    }

    /// An install that lands between two of a batch's evaluations does not
    /// reach the rest of the batch.
    #[test]
    fn decide_cited_all_reads_one_snapshot_for_the_whole_batch() {
        let mut auth = authorizer_over(EMPTY, Some(ADMIN_ROOT), &[("root", 0)]);
        let gate = Arc::new(EvaluationGate {
            arrived: std::sync::Barrier::new(2),
            release: std::sync::Barrier::new(2),
        });
        auth.evaluation_gate = Some(gate.clone());
        let auth = Arc::new(auth);
        let next = compiled(&source_with(EMPTY, Some(ADVERSARY_ROOT), &[("root", 0)]));
        let installed = next.clone();
        let batch = {
            let auth = auth.clone();
            std::thread::spawn(move || auth.decide_cited_all(&[whoami(0), whoami(0)]))
        };
        assert!(arrives(&gate), "the batch never reached evaluation");
        auth.install(next);
        gate.release.wait();
        assert!(arrives(&gate), "the batch stopped after one evaluation");
        gate.release.wait();
        let verdicts: Vec<_> = batch
            .join()
            .unwrap()
            .into_iter()
            .map(|d| d.verdict)
            .collect();
        assert_eq!(verdicts, vec![audit_permit(), audit_permit()]);
        assert!(Arc::ptr_eq(&auth.snapshot(), &installed));
        let probe = std::thread::spawn(move || auth.decide(&whoami(0)));
        assert!(arrives(&gate), "the probe never reached evaluation");
        gate.release.wait();
        assert_eq!(probe.join().unwrap(), contained());
    }

    #[test]
    fn test_digest_is_a_pinned_four_lane_fold() {
        assert_eq!(
            test_digest(b""),
            [
                0x25, 0x23, 0x22, 0x84, 0xe4, 0x9c, 0xf2, 0xcb, 0x24, 0x23, 0x22, 0x84, 0xe4, 0x9c,
                0xf2, 0xcb, 0x27, 0x23, 0x22, 0x84, 0xe4, 0x9c, 0xf2, 0xcb, 0x26, 0x23, 0x22, 0x84,
                0xe4, 0x9c, 0xf2, 0xcb
            ]
        );
        assert_eq!(
            &test_digest(b"a")[..8],
            &0xaf63_dc4c_8601_ec8c_u64.to_le_bytes()
        );
        assert_ne!(test_digest(b"ab"), test_digest(b"ba"));
    }

    #[test]
    fn snapshot_over_carries_an_unchanged_layer_and_advances_a_changed_one() {
        let first = compiled(&source_with(EMPTY, Some(ADMIN_ROOT), &[("root", 0)]));
        assert_eq!(first.revision(), 1);
        let same = snapshot_over(
            &source_with(EMPTY, Some(ADMIN_ROOT), &[("root", 0)]),
            LABEL,
            test_digest,
            Some(first.persisted()),
        )
        .unwrap();
        assert!(Arc::ptr_eq(same.persisted(), first.persisted()));
        let moved = snapshot_over(
            &source_with(EMPTY, Some(ADVERSARY_ROOT), &[("root", 0)]),
            LABEL,
            test_digest,
            Some(first.persisted()),
        )
        .unwrap();
        assert_eq!(moved.revision(), 2);
        assert!(moved
            .persisted()
            .nodes()
            .iter()
            .any(|n| n.provenance.kind == maknae_graph::record::ProvenanceKind::RootFile));
        let g = first.persisted();
        let b = g.nodes().iter().cloned().map(|mut n| {
            if n.key == maknae_graph::kernel::VOCABULARY_SOURCE_KEY {
                n.attrs.insert(
                    maknae_graph::kernel::ATTR_SHA256.into(),
                    maknae_graph::record::AttrValue::Str("zz".into()),
                );
            }
            n
        });
        let b = b.fold(
            maknae_graph::graph::GraphBuilder::new(maknae_graph::record::GraphSpace::Kernel, 1),
            maknae_graph::graph::GraphBuilder::node,
        );
        let bad = Arc::new(
            g.edges()
                .iter()
                .cloned()
                .fold(b, maknae_graph::graph::GraphBuilder::edge)
                .build(
                    &maknae_graph::kernel::SCHEMA,
                    &maknae_graph::kernel::persisted_compiled_set(LABEL),
                )
                .unwrap(),
        );
        let unreadable = snapshot_over(
            &source_with(EMPTY, Some(ADMIN_ROOT), &[("root", 0)]),
            LABEL,
            test_digest,
            Some(&bad),
        );
        assert!(
            matches!(
                unreadable,
                Err(AuthzBasicError::Compile(snapshot::CompileError::Identity(
                    _
                )))
            ),
            "{unreadable:?}"
        );
    }

    /// The post-load half (one getpwnam per name, eager validation) over a
    /// host-independent identity (`root` — uid 0 exists everywhere).
    #[test]
    fn finish_resolves_root_validates_eagerly_and_refuses_bad_bindings() {
        let src = finish_with(parse(EMPTY), bound(ADMIN_ROOT)).unwrap();
        assert_eq!(
            src.uid_map().get("root"),
            Some(&0),
            "root resolves to uid 0"
        );
        assert_eq!(
            src.uid_map().len(),
            1,
            "every bound name resolves, no exception"
        );
        let typo = finish_with(
            parse(EMPTY),
            bound("schema_version: 1\nbindings:\n  advesary: [\"root\"]\n"),
        );
        assert!(matches!(typo, Err(AuthzBasicError::Bindings(ref m)) if m.contains("advesary")));
        let ghost = finish_with(
            parse(EMPTY),
            bound("schema_version: 1\nbindings:\n  user: [\"no-such-user-maknae-85\"]\n"),
        );
        assert!(
            matches!(ghost, Err(AuthzBasicError::Bindings(ref m)) if m.contains("no-such-user-maknae-85"))
        );
    }

    // ---- `roles:` action grants: refusal at load (#162) ----

    const GRANT_PREAMBLE: &str = "schema_version: 1\npermissions:\n  allow: []\n  deny: []\n";

    fn parse_with_roles(roles_block: &str) -> maknae_config::AuthzPolicy {
        maknae_config::parse_authz(&format!("{GRANT_PREAMBLE}{roles_block}"))
            .expect("grammar is valid; the SEMANTIC refusal is what is under test")
    }

    /// A `roles:` key outside the role vocabulary refuses the load, and the
    /// error names the offending key.
    #[test]
    fn roles_unknown_role_refuses_construction_naming_the_key() {
        let got = finish(parse_with_roles(
            "roles:\n  admn:\n    allow: [\"admin.status\"]\n",
        ));
        assert!(
            matches!(got, Err(AuthzBasicError::UnknownRole(ref k)) if k == "admn"),
            "expected UnknownRole(\"admn\"), got {got:?}"
        );
    }

    /// A REAL but STRUCTURAL role gets its own variant, not `UnknownRole`.
    #[test]
    fn roles_real_but_ungrantable_role_refuses_with_its_own_variant() {
        for key in ["guest", "adversary"] {
            let got = finish(parse_with_roles(&format!(
                "roles:\n  {key}:\n    allow: [\"admin.status\"]\n"
            )));
            assert!(
                matches!(got, Err(AuthzBasicError::RoleNotSupportedYet(ref k)) if k == key),
                "role `{key}`: expected RoleNotSupportedYet, got {got:?}"
            );
        }
    }

    #[test]
    fn user_may_hold_only_the_content_plane_term_and_the_error_names_role_and_term() {
        let got = finish(parse_with_roles(
            "roles:\n  user:\n    allow: [\"admin.status\"]\n",
        ));
        assert!(
            matches!(got, Err(AuthzBasicError::TermNotGrantableForRole { ref role, ref term }) if role == "user" && term == "admin.status"),
            "{got:?}"
        );
        assert!(finish(parse_with_roles(
            "roles:\n  user:\n    allow: [\"session.prompt\"]\n"
        ))
        .is_ok());
    }

    #[test]
    fn destinations_for_a_structural_or_unknown_role_refuse_at_boot_naming_the_role() {
        for (role, want_unknown) in [("guest", false), ("adversary", false), ("ghost", true)] {
            let got = finish(parse_with_roles(&format!(
                "destinations:\n  {role}:\n    allow: [\"provider:x\"]\n"
            )));
            match got {
                Err(AuthzBasicError::UnknownRole(ref k)) if want_unknown => assert_eq!(k, role),
                Err(AuthzBasicError::RoleNotSupportedYet(ref k)) if !want_unknown => {
                    assert_eq!(k, role)
                }
                other => panic!("{role}: {other:?}"),
            }
        }
        assert!(finish(parse_with_roles(
            "destinations:\n  user:\n    allow: [\"provider:x\"]\n  admin:\n    allow: []\n",
        ))
        .is_ok());
    }

    /// A term outside `GRANTABLE_ACTIONS` refuses, whether it is a real verb
    /// this phase withholds (`admin.contain`) or nonexistent (`admin.stauts`).
    #[test]
    fn roles_ungrantable_term_refuses_construction_naming_the_term() {
        for term in [
            "admin.contain",
            "admin.policy.reload",
            "admin.stauts",
            "fs.read",
        ] {
            let got = finish(parse_with_roles(&format!(
                "roles:\n  admin:\n    allow: [\"{term}\"]\n"
            )));
            assert!(
                matches!(got, Err(AuthzBasicError::UnknownActionTerm(ref t)) if t == term),
                "term `{term}`: expected UnknownActionTerm, got {got:?}"
            );
        }
    }

    /// Validation gates the DENY list too: a typo'd deny would read as a
    /// denial in force while denying nothing.
    #[test]
    fn roles_ungrantable_term_in_deny_list_also_refuses() {
        let got = finish(parse_with_roles(
            "roles:\n  admin:\n    deny: [\"admin.contain\"]\n",
        ));
        assert!(
            matches!(got, Err(AuthzBasicError::UnknownActionTerm(ref t)) if t == "admin.contain"),
            "deny lists are gated identically to allow lists, got {got:?}"
        );
    }

    /// A valid `roles:` block loads. The refusal tests above all pass against
    /// a validator that refuses everything, so this keeps them honest.
    #[test]
    fn roles_valid_grant_block_constructs() {
        finish(parse_with_roles(
            "roles:\n  admin:\n    allow: [\"admin.status\", \"admin.config.show\"]\n    deny: [\"admin.subject.list\"]\n",
        ))
        .expect("every role key and term is in vocabulary");
    }

    /// Every error variant renders its offending token.
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
        assert_eq!(
            AuthzBasicError::Compile(snapshot::CompileError::Policy("p".into())).to_string(),
            "authz snapshot policy refused: p"
        );
    }

    #[test]
    fn finish_without_bindings_needs_no_lookups_and_defaults_apply() {
        let src = finish(parse(
            "schema_version: 1\npermissions:\n  allow: []\n  deny: []\n",
        ))
        .unwrap();
        assert!(
            src.uid_map().is_empty(),
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

    fn stand_in_digest(b: &[u8]) -> [u8; 32] {
        let mut d = [0u8; 32];
        for (i, x) in b.iter().enumerate() {
            d[i % 32] ^= x.wrapping_add(i as u8);
        }
        d[0] = b.len() as u8;
        d
    }

    #[test]
    fn the_bindings_digest_is_the_section_of_bindings_yaml_under_the_same_key() {
        let s = source_with(
            SHIPPED,
            Some("schema_version: 1\nbindings:\n  admin: [\"alex\"]\n"),
            &[("alex", 1000)],
        );
        let d = s.section_digests(stand_in_digest);
        assert_eq!(d["bindings"], stand_in_digest(br#"{"admin":["alex"]}"#));
        assert_eq!(
            d["permissions"],
            stand_in_digest(
                s.policy()
                    .section_canonical("permissions")
                    .unwrap()
                    .as_bytes()
            )
        );
        let keys: Vec<&str> = d.keys().map(String::as_str).collect();
        assert_eq!(keys, ["bindings", "permissions", "schema_version"]);
        let empty = source_with(SHIPPED, Some("schema_version: 1\nbindings: {}\n"), &[])
            .section_digests(stand_in_digest);
        assert_eq!(empty["bindings"], stand_in_digest(b"{}"));
        let none = source_with(SHIPPED, None, &[]).section_digests(stand_in_digest);
        assert!(!none.contains_key("bindings"));
        let no_key = source_with(SHIPPED, Some("schema_version: 1\n"), &[]);
        assert!(!no_key
            .section_digests(stand_in_digest)
            .contains_key("bindings"));
    }

    #[test]
    fn policy_paths_in_dir_names_both_files() {
        assert_eq!(
            PolicyPaths::in_dir(Path::new("/x")),
            PolicyPaths {
                authz: "/x/authz.yaml".into(),
                bindings: "/x/bindings.yaml".into(),
            }
        );
    }

    #[test]
    fn the_identity_layer_comes_from_bindings_yaml() {
        let s = source_with(
            SHIPPED,
            Some("schema_version: 1\nbindings:\n  admin: [alex]\n  adversary: [mallory, {uid: 4242}]\n"),
            &[("alex", 1000), ("mallory", 666)],
        );
        let layer = s.identity_layer(LABEL, Some([7; 32]));
        assert_eq!(layer.source, "/etc/maknae/bindings.yaml");
        let got: Vec<(u32, &str, &str)> = layer
            .subjects
            .iter()
            .map(|e| (e.uid, e.name.as_str(), e.role.as_str()))
            .collect();
        assert_eq!(
            got,
            [
                (666, "mallory", "adversary"),
                (1000, "alex", "admin"),
                (4242, "uid:4242", "adversary")
            ]
        );
        assert_eq!(s.paths(), &paths());
        assert!(s.bindings().roles.is_some());
        assert_eq!(s.policy_source(), PATH);
    }

    #[test]
    fn absent_and_empty_bindings_differ_across_both_spellings_of_absent() {
        let missing = compiled(&source_with(SHIPPED, None, &[]));
        let no_key = compiled(&source_with(SHIPPED, Some("schema_version: 1\n"), &[]));
        let empty = compiled(&source_with(
            SHIPPED,
            Some("schema_version: 1\nbindings: {}\n"),
            &[],
        ));
        let principal_req = liveness_req(Some(501));
        for absent in [&missing, &no_key] {
            assert_eq!(absent.subjects(), None);
            let a = BasicAuthorizer::from_snapshot(
                principal(),
                paths(),
                test_digest,
                Arc::clone(absent),
            );
            assert_eq!(a.decide_reporting_role(&principal_req).1, Some("admin"));
        }
        assert_eq!(empty.subjects(), Some(vec![]));
        let e = BasicAuthorizer::from_snapshot(principal(), paths(), test_digest, empty);
        assert_eq!(e.decide_reporting_role(&principal_req).1, None);
    }

    #[test]
    fn a_uid_entry_outside_adversary_refuses_the_file() {
        let got = PolicySource::from_parts(
            parse(SHIPPED),
            bound("schema_version: 1\nbindings:\n  user: [{uid: 7}]\n"),
            UidMap::new(),
            principal(),
            paths(),
        );
        assert!(
            matches!(got, Err(AuthzBasicError::Bindings(ref m)) if m.contains("adversary")),
            "{got:?}"
        );
    }

    #[test]
    fn policy_source_keeps_its_parts_and_declares_its_identity_layer() {
        let policy = parse("schema_version: 1\n");
        let bindings = bound(
            "schema_version: 1\nbindings:\n  user: [\"ursula\"]\n  admin: [\"alex\"]\n  adversary: [\"mallory\"]\n",
        );
        let uid_map: UidMap = [("alex", 1000), ("ursula", 7), ("mallory", 666)]
            .iter()
            .map(|(n, u)| (n.to_string(), *u))
            .collect();
        let src = PolicySource::from_parts(
            policy.clone(),
            bindings.clone(),
            uid_map.clone(),
            principal(),
            paths(),
        )
        .unwrap();
        assert_eq!(src.policy(), &policy);
        assert_eq!(src.bindings(), &bindings);
        assert_eq!(src.principal(), &principal());
        assert_eq!(src.paths(), &paths());
        assert_eq!(src.uid_map(), &uid_map);
        let layer = src.identity_layer("UNCLASSIFIED", Some([4; 32]));
        let entry = |uid: u32, name: &str, role: &str| maknae_graph::identity::SubjectEntry {
            uid,
            name: name.into(),
            role: role.into(),
        };
        assert_eq!(
            layer,
            maknae_graph::identity::IdentityLayer {
                source: "/etc/maknae/bindings.yaml".into(),
                label: "UNCLASSIFIED".into(),
                bindings_sha256: Some([4; 32]),
                subjects: vec![
                    entry(7, "ursula", "user"),
                    entry(666, "mallory", "adversary"),
                    entry(1000, "alex", "admin"),
                ],
            }
        );
    }

    #[test]
    fn policy_source_refuses_a_non_utf8_policy_path() {
        use std::os::unix::ffi::OsStrExt;
        let bad = PathBuf::from(std::ffi::OsStr::from_bytes(b"/etc/maknae/auth\xffz.yaml"));
        for paths in [
            PolicyPaths {
                authz: bad.clone(),
                ..paths()
            },
            PolicyPaths {
                bindings: bad.clone(),
                ..paths()
            },
        ] {
            let got = PolicySource::from_parts(
                parse("schema_version: 1\n"),
                maknae_config::Bindings::missing(),
                UidMap::new(),
                principal(),
                paths,
            );
            assert!(
                matches!(got, Err(AuthzBasicError::Load(ref m)) if m.contains("is not UTF-8")),
                "{got:?}"
            );
        }
    }

    #[test]
    fn policy_source_validates_like_construction() {
        let parts = |body: &str, uids: &[(&str, u32)]| {
            PolicySource::from_parts(
                maknae_config::parse_authz(body).unwrap(),
                maknae_config::Bindings::missing(),
                uids.iter().map(|(n, u)| (n.to_string(), *u)).collect(),
                principal(),
                paths(),
            )
        };
        let ghost = PolicySource::from_parts(
            parse("schema_version: 1\n"),
            bound("schema_version: 1\nbindings:\n  user: [\"ghost\"]\n"),
            UidMap::new(),
            principal(),
            paths(),
        );
        assert!(matches!(
            ghost,
            Err(AuthzBasicError::Bindings(ref m)) if m.contains("ghost")
        ));
        assert_eq!(
            parts(
                "schema_version: 1\nroles:\n  admin:\n    allow: [\"admin.contain\"]\n",
                &[]
            )
            .unwrap_err(),
            AuthzBasicError::UnknownActionTerm("admin.contain".into())
        );
        assert_eq!(
            parts(
                "schema_version: 1\ndestinations:\n  guest:\n    allow: [\"provider:x\"]\n",
                &[]
            )
            .unwrap_err(),
            AuthzBasicError::RoleNotSupportedYet("guest".into())
        );
    }

    #[test]
    fn policy_source_load_sits_behind_the_production_door() {
        use std::os::unix::fs::PermissionsExt;
        let dir = std::env::temp_dir().join(format!("mab_src_{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700)).unwrap();
        for name in ["authz.yaml", "bindings.yaml"] {
            let p = dir.join(name);
            std::fs::write(&p, "schema_version: 1\n").unwrap();
            std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o640)).unwrap();
        }
        let got = PolicySource::load(PolicyPaths::in_dir(&dir), principal());
        let _ = std::fs::remove_dir_all(&dir);
        if nix::unistd::geteuid().is_root() {
            assert!(got.is_ok(), "{got:?}");
        } else {
            assert!(
                matches!(got, Err(AuthzBasicError::Load(ref m)) if m.contains("root")),
                "{got:?}"
            );
        }
    }

    /// In-crate killers for the feature-gated wrapper (`cargo mutants -p` runs
    /// only in-package tests, so these — not the kernel e2e — are what kill the
    /// wrapper's mutants when the mutation lane enables the feature).
    #[cfg(all(unix, feature = "hermetic-test-seam"))]
    mod hermetic {
        use super::super::*;
        use super::{arrives, audit_permit, contained, principal, whoami, CONTAINED, EMPTY};
        use maknae_security::{Authorizer, Verdict};
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

        fn write(p: &std::path::Path, body: &str) {
            std::fs::write(p, body).unwrap();
            std::fs::set_permissions(p, std::fs::Permissions::from_mode(0o640)).unwrap();
        }

        struct Fixture(std::path::PathBuf);

        impl Drop for Fixture {
            fn drop(&mut self) {
                let _ = std::fs::remove_dir_all(&self.0);
            }
        }

        impl Fixture {
            fn new(tag: &str) -> Self {
                let d = std::env::temp_dir().join(format!("mab_herm_{tag}_{}", std::process::id()));
                let _ = std::fs::remove_dir_all(&d);
                std::fs::create_dir_all(&d).unwrap();
                std::fs::set_permissions(&d, std::fs::Permissions::from_mode(0o700)).unwrap();
                Fixture(d)
            }

            fn policy(&self) -> std::path::PathBuf {
                self.paths().authz
            }

            fn bindings(&self) -> std::path::PathBuf {
                self.paths().bindings
            }

            fn paths(&self) -> PolicyPaths {
                PolicyPaths::in_dir(&self.0)
            }

            fn bind(&self, role: &str) {
                write(
                    &self.bindings(),
                    &format!("schema_version: 1\nbindings:\n  {role}: [\"root\"]\n"),
                );
            }

            fn authorizer(&self, role: &str) -> HermeticAuthorizer {
                write(&self.policy(), EMPTY);
                self.bind(role);
                HermeticAuthorizer::new(self.paths(), principal(), fixture_req(), test_digest)
                    .unwrap()
            }
        }

        #[test]
        fn policy_source_loads_through_the_hermetic_door_resolving_uids() {
            let fx = Fixture::new("source");
            write(&fx.policy(), EMPTY);
            fx.bind("admin");
            let got = PolicySource::load_with_requirement(fx.paths(), principal(), fixture_req());
            write(
                &fx.bindings(),
                "schema_version: 1\nbindings:\n  user: [\"no-such-user-maknae-489\"]\n",
            );
            let unresolvable =
                PolicySource::load_with_requirement(fx.paths(), principal(), fixture_req());
            let missing_authz = PolicySource::load_with_requirement(
                PolicyPaths {
                    authz: fx.0.join("absent.yaml"),
                    ..fx.paths()
                },
                principal(),
                fixture_req(),
            );
            std::fs::remove_file(fx.bindings()).unwrap();
            let missing_bindings =
                PolicySource::load_with_requirement(fx.paths(), principal(), fixture_req());
            let src = got.unwrap();
            assert_eq!(src.uid_map().get("root"), Some(&0));
            assert_eq!(src.paths(), &fx.paths());
            assert!(
                matches!(unresolvable, Err(AuthzBasicError::Bindings(ref m)) if m.contains("no-such-user-maknae-489"))
            );
            assert!(matches!(missing_authz, Err(AuthzBasicError::Load(_))));
            let absent = missing_bindings.expect("a missing bindings.yaml is bindings absent");
            assert!(absent.bindings().is_missing());
        }

        #[test]
        fn constructor_refuses_unresolvable_binding() {
            let fx = Fixture::new("bindfail");
            write(&fx.policy(), EMPTY);
            write(
                &fx.bindings(),
                "schema_version: 1\nbindings:\n  user: [\"no-such-user-maknae-77\"]\n",
            );
            let got = HermeticAuthorizer::new(fx.paths(), principal(), fixture_req(), test_digest);
            assert!(
                matches!(got, Err(AuthzBasicError::Bindings(ref m)) if m.contains("no-such-user-maknae-77")),
                "{got:?}"
            );
        }

        /// #275: the decision reports the role it was MADE ON. All four shipped
        /// roles, through the real decide path.
        #[test]
        fn the_decision_reports_the_role_it_was_made_on_for_every_shipped_role() {
            for role in ["admin", "user", "guest", "adversary"] {
                let fx = Fixture::new(&format!("role_{role}"));
                let auth = fx.authorizer(role);
                let (_v, got) = auth.decide_reporting_role(&whoami(0));
                assert_eq!(got, Some(role), "role reported for binding {role}");
            }
        }

        #[test]
        fn a_subject_resolving_to_no_role_reports_none_not_a_default() {
            let fx = Fixture::new("norole");
            let auth = fx.authorizer("admin");
            let (v, got) = auth.decide_reporting_role(&whoami(4242));
            assert_eq!(got, None, "an unbound uid must never be given a role");
            assert!(
                matches!(v, Verdict::NotApplicable { .. }),
                "expected the annotated absence, got {v:?}"
            );
        }

        /// The wrapper DELEGATES every seam method; a trait default would
        /// answer `None`/`unknown` and prove nothing.
        #[test]
        fn the_wrapper_delegates_every_seam_method() {
            let fx = Fixture::new("delegate");
            write(
                &fx.policy(),
                include_str!("../../../packaging/common/authz.yaml"),
            );
            fx.bind("admin");
            let auth = HermeticAuthorizer::new(fx.paths(), principal(), fixture_req(), test_digest)
                .unwrap();
            let (v, got) = auth.decide_reporting_role(&whoami(0));
            assert_eq!((v, got), (audit_permit(), Some("admin")));
            assert_eq!(auth.decide(&whoami(0)), audit_permit());
            let d = auth.decide_cited(&super::ssh_read(0));
            assert_eq!(d.role, Some("admin"));
            assert!(d
                .rule
                .clone()
                .expect("cited")
                .section
                .ends_with("#permissions"));
            let batch = [whoami(0), super::ssh_read(0)];
            assert_eq!(
                auth.decide_cited_all(&batch),
                vec![auth.inner.decide_cited(&batch[0]), d]
            );
            assert_eq!(auth.backend_name(), "maknae-authz-basic");
            assert_eq!(
                auth.subjects().expect("an explicit block")[0].members,
                vec!["uid:0".to_string()]
            );
        }

        #[test]
        fn decide_agrees_with_the_role_reporting_path() {
            let fx = Fixture::new("agree");
            let auth = fx.authorizer("admin");
            for uid in [0, 501, 4242] {
                assert_eq!(
                    auth.decide(&whoami(uid)),
                    auth.decide_reporting_role(&whoami(uid)).0,
                    "uid {uid}"
                );
            }
        }

        /// A file edit changes nothing until a reload; a refused reload keeps
        /// the old snapshot.
        #[test]
        fn containment_bites_on_the_next_request_after_a_reload() {
            let fx = Fixture::new("contain");
            let auth = fx.authorizer("user");
            let ping = super::liveness_req(Some(0));
            assert_eq!(auth.decide(&ping), audit_permit());

            fx.bind("adversary");
            assert_eq!(
                auth.decide(&ping),
                audit_permit(),
                "the per-request re-read is removed; a reload is the only transition"
            );
            auth.reload_from_file().unwrap();
            assert_eq!(auth.decide(&whoami(0)), contained());

            write(&fx.policy(), "not: [valid");
            assert!(matches!(
                auth.reload_from_file(),
                Err(AuthzBasicError::Load(_))
            ));
            assert_eq!(auth.decide(&whoami(0)), contained());

            write(&fx.policy(), EMPTY);
            write(
                &fx.bindings(),
                "schema_version: 1\nbindings:\n  user: [\"nobody-new-maknae-489\"]\n",
            );
            assert!(
                matches!(auth.reload_from_file(), Err(AuthzBasicError::Bindings(ref m)) if m.contains("nobody-new-maknae-489"))
            );
            assert_eq!(auth.decide(&whoami(0)), contained());
        }

        #[test]
        fn invalid_grants_edited_in_after_boot_refuse_the_reload() {
            let fx = Fixture::new("grants");
            let auth = fx.authorizer("admin");
            let before = auth.snapshot();
            write(
                &fx.policy(),
                &format!("{EMPTY}roles:\n  admin:\n    allow: [\"admin.contain\"]\n"),
            );
            assert_eq!(
                auth.reload_from_file(),
                Err(AuthzBasicError::UnknownActionTerm("admin.contain".into()))
            );
            assert!(Arc::ptr_eq(&before, &auth.snapshot()));
        }

        #[test]
        fn trait_path_flips_only_at_reload() {
            let fx = Fixture::new("flip");
            let auth = fx.authorizer("admin");
            assert_eq!(auth.decide(&whoami(0)), audit_permit());
            fx.bind("adversary");
            assert_eq!(auth.decide(&whoami(0)), audit_permit());
            auth.reload_from_file().unwrap();
            assert_eq!(
                auth.decide(&whoami(0)),
                Verdict::Deny {
                    reason: CONTAINED.into()
                }
            );
        }

        #[test]
        fn wrapper_subjects_delegate_and_follow_the_snapshot() {
            let fx = Fixture::new("subjects");
            let auth = fx.authorizer("admin");
            assert_eq!(auth.subjects().unwrap()[0].role, "admin");
            fx.bind("adversary");
            assert_eq!(auth.subjects().unwrap()[0].role, "admin");
            auth.reload_from_file().unwrap();
            assert_eq!(auth.subjects().unwrap()[0].role, "adversary");
        }

        #[test]
        fn decide_never_touches_the_file() {
            let fx = Fixture::new("gone");
            let auth = fx.authorizer("admin");
            std::fs::remove_file(fx.policy()).unwrap();
            assert_eq!(auth.decide(&whoami(0)), audit_permit());
            assert!(matches!(
                auth.reload_from_file(),
                Err(AuthzBasicError::Load(_))
            ));
        }

        /// A reload that changes the identity layer advances the in-memory
        /// identity graph one revision; an unchanged one keeps it.
        #[test]
        fn compile_from_file_advances_the_revision_only_when_the_layer_changes() {
            let fx = Fixture::new("revision");
            let auth = fx.authorizer("admin");
            assert_eq!(auth.snapshot().revision(), 1);
            let same = auth.compile_from_file().unwrap();
            assert!(Arc::ptr_eq(same.persisted(), auth.snapshot().persisted()));
            fx.bind("adversary");
            let next = auth.compile_from_file().unwrap();
            assert_eq!(next.revision(), 2);
            assert_eq!(auth.snapshot().revision(), 1, "compile does not install");
            assert_eq!(Baseline::digest(&auth)(b"x"), test_digest(b"x"));
            assert_eq!(auth.digest()(b"y"), test_digest(b"y"));
        }

        #[test]
        fn the_hermetic_baseline_delegates_to_its_inner_authorizer() {
            let fx = Fixture::new("baseline");
            let auth = fx.authorizer("admin");
            assert_eq!(Baseline::principal(&auth), &principal());
            assert!(Arc::ptr_eq(
                &Baseline::snapshot(&auth),
                &auth.inner.snapshot()
            ));
            let src = Baseline::load_source(&auth).expect("the hermetic loader");
            assert_eq!(src.uid_map().get("root"), Some(&0));
            fx.bind("adversary");
            let next = auth.compile_from_file().unwrap();
            Baseline::install(&auth, next.clone());
            assert!(Arc::ptr_eq(&auth.inner.snapshot(), &next));
            assert_eq!(auth.decide(&whoami(0)), contained());
        }

        #[test]
        fn park_evaluations_parks_every_later_evaluation() {
            let fx = Fixture::new("park");
            let mut auth = fx.authorizer("admin");
            let gate = Arc::new(EvaluationGate {
                arrived: std::sync::Barrier::new(2),
                release: std::sync::Barrier::new(2),
            });
            auth.park_evaluations(gate.clone());
            let auth = Arc::new(auth);
            let parked = {
                let auth = auth.clone();
                std::thread::spawn(move || auth.decide(&whoami(0)))
            };
            assert!(arrives(&gate), "the evaluation did not park");
            gate.release.wait();
            assert_eq!(parked.join().unwrap(), audit_permit());
        }

        #[test]
        fn the_hermetic_batch_reads_one_snapshot() {
            let fx = Fixture::new("batch");
            let mut auth = fx.authorizer("admin");
            let gate = Arc::new(EvaluationGate {
                arrived: std::sync::Barrier::new(2),
                release: std::sync::Barrier::new(2),
            });
            auth.park_evaluations(gate.clone());
            fx.bind("adversary");
            let next = auth.compile_from_file().unwrap();
            let auth = Arc::new(auth);
            let batch = {
                let auth = auth.clone();
                std::thread::spawn(move || auth.decide_cited_all(&[whoami(0), whoami(0)]))
            };
            assert!(arrives(&gate), "the batch never reached evaluation");
            Baseline::install(&*auth, next.clone());
            gate.release.wait();
            assert!(arrives(&gate), "the batch stopped after one evaluation");
            gate.release.wait();
            let verdicts: Vec<_> = batch
                .join()
                .unwrap()
                .into_iter()
                .map(|d| d.verdict)
                .collect();
            assert_eq!(verdicts, vec![audit_permit(), audit_permit()]);
            assert!(Arc::ptr_eq(&auth.inner.snapshot(), &next));
            let probe = std::thread::spawn(move || auth.decide(&whoami(0)));
            assert!(arrives(&gate), "the probe never reached evaluation");
            gate.release.wait();
            assert_eq!(probe.join().unwrap(), contained());
        }

        #[test]
        fn new_over_graph_compiles_against_the_given_identity_graph() {
            let fx = Fixture::new("overgraph");
            let first = fx.authorizer("admin");
            let persisted = first.snapshot().persisted().clone();
            let over = HermeticAuthorizer::new_over_graph(
                fx.paths(),
                principal(),
                fixture_req(),
                test_digest,
                persisted.clone(),
            )
            .unwrap();
            assert!(Arc::ptr_eq(over.snapshot().persisted(), &persisted));
            assert_eq!(over.decide(&whoami(0)), audit_permit());
            fx.bind("adversary");
            let refused = HermeticAuthorizer::new_over_graph(
                fx.paths(),
                principal(),
                fixture_req(),
                test_digest,
                persisted,
            );
            assert!(
                matches!(
                    refused,
                    Err(AuthzBasicError::Compile(snapshot::CompileError::Identity(
                        _
                    )))
                ),
                "{refused:?}"
            );
            let empty = Arc::new(
                maknae_graph::graph::GraphBuilder::new(maknae_graph::record::GraphSpace::Kernel, 1)
                    .build(
                        &maknae_graph::kernel::SCHEMA,
                        &maknae_graph::schema::CompiledSet::default(),
                    )
                    .unwrap(),
            );
            let no_source = HermeticAuthorizer::new_over_graph(
                fx.paths(),
                principal(),
                fixture_req(),
                test_digest,
                empty,
            );
            assert!(
                matches!(no_source, Err(AuthzBasicError::Compile(_))),
                "{no_source:?}"
            );
        }

        #[test]
        fn wrapper_permit_carries_exactly_audit_obligation() {
            let fx = Fixture::new("oblig");
            let auth = fx.authorizer("admin");
            match auth.decide(&whoami(0)) {
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
            let fx = Fixture::new("mode");
            for loose in [fx.policy(), fx.bindings()] {
                write(&fx.policy(), EMPTY);
                fx.bind("admin");
                std::fs::set_permissions(&loose, std::fs::Permissions::from_mode(0o666)).unwrap();
                let got =
                    HermeticAuthorizer::new(fx.paths(), principal(), fixture_req(), test_digest);
                assert!(
                    matches!(got, Err(AuthzBasicError::Load(_))),
                    "{loose:?}: {got:?}"
                );
            }
        }
    }

    /// File-resolved vs graph-resolved roles over one shared evaluator, compared as
    /// full `(Verdict, role)`; the evaluator itself is pinned by decide.rs's golden vectors.
    mod equivalence {
        use super::*;
        use maknae_security::FsOperation;

        const BASE_UIDS: &[(&str, u32)] = &[
            ("alex", 1000),
            ("ursula", 1001),
            ("gus", 1002),
            ("mallory", 666),
        ];
        const EXPLICIT: &str = "schema_version: 1\nbindings: { admin: [alex], user: [ursula], guest: [gus], adversary: [mallory] }\n";
        const GRANTS: &str = "roles: { admin: { allow: [admin.status, admin.subject.list, session.prompt], deny: [admin.config.show] }, user: { allow: [session.prompt] } }\ndestinations: { user: { allow: [\"provider:openai\"] }, admin: { allow: [\"provider:anthropic\"] } }\n";

        fn policies() -> Vec<(&'static str, PolicySource)> {
            let uids: &[(&str, u32)] = BASE_UIDS;
            vec![
                ("absent", source_with(SHIPPED, None, &[])),
                (
                    "empty",
                    source_with(SHIPPED, Some("schema_version: 1\nbindings: {}\n"), &[]),
                ),
                ("explicit", source_with(SHIPPED, Some(EXPLICIT), uids)),
                (
                    "explicit+grants",
                    source_with(&format!("{SHIPPED}{GRANTS}"), Some(EXPLICIT), uids),
                ),
            ]
        }

        fn uids() -> Vec<Option<AttrValue>> {
            let mut v: Vec<Option<AttrValue>> = [1000, 1001, 1002, 666, 501, 4242]
                .into_iter()
                .map(|u| Some(AttrValue::Int(u)))
                .collect();
            v.push(None);
            v.push(Some(AttrValue::Str("1000".into())));
            v.push(Some(AttrValue::Int(-1)));
            v
        }

        fn paths() -> Vec<Option<AttrValue>> {
            let mut v: Vec<Option<AttrValue>> = [
                "/home/alex/.ssh/id_rsa",
                "/home/alex/.ssh",
                "/home/alex/.sshkeys",
                "/home/alex/projects/a/b.rs",
                "/home/alex/projects",
                "/home/alex/projectsX/y",
                "/home/alex/.aws/credentials",
                "/home/alex/.docker/config.json",
                "/home/alex/.docker/other",
                "/home/alex/notes.txt",
                "/home/alex",
                "/home/other/notes.txt",
                "/etc/passwd",
                "/opt/x",
                "/",
                "~/.ssh/id_rsa",
                "/home/alex/projects/../.ssh/id_rsa",
                "/home/alex//x",
                "/home/alex/x/",
                "",
            ]
            .into_iter()
            .map(|p| Some(AttrValue::Str(p.into())))
            .collect();
            v.push(None);
            v.push(Some(AttrValue::Int(7)));
            v
        }

        fn homes() -> Vec<Option<AttrValue>> {
            vec![
                Some(AttrValue::Str("/home/alex".into())),
                None,
                Some(AttrValue::Str("/".into())),
                Some(AttrValue::Str("relative".into())),
                Some(AttrValue::Int(7)),
            ]
        }

        fn operations() -> Vec<Option<&'static str>> {
            let mut v: Vec<Option<&'static str>> = [
                FsOperation::WriteExisting,
                FsOperation::WriteCreate,
                FsOperation::DeleteEntry,
                FsOperation::DeleteTree,
                FsOperation::Mkdir,
                FsOperation::Read,
            ]
            .into_iter()
            .map(|o| Some(o.as_str()))
            .collect();
            v.push(None);
            v
        }

        const FS_TERMS: [&str; 4] = ["fs.read", "fs.write", "fs.delete", "fs.mkdir"];

        fn request(
            action: &str,
            uid: &Option<AttrValue>,
            home: &Option<AttrValue>,
            resource: Option<(&'static str, &AttrValue)>,
            lane: bool,
            operation: Option<&str>,
        ) -> maknae_security::Request {
            let mut s = Attributes::new();
            if let Some(u) = uid {
                s.insert(SUBJECT_UID_KEY, u.clone());
            }
            if let Some(h) = home {
                s.insert(maknae_security::SUBJECT_HOME, h.clone());
            }
            let mut r = Attributes::new();
            if let Some((k, v)) = resource {
                r.insert(k, v.clone());
            }
            let mut c = Attributes::new();
            if lane {
                c.insert(
                    maknae_security::CONTEXT_DAC_LANE,
                    AttrValue::Str("local".into()),
                );
            }
            if let Some(o) = operation {
                c.insert(
                    maknae_security::CONTEXT_FS_OPERATION,
                    AttrValue::Str(o.into()),
                );
            }
            maknae_security::Request {
                subject: Subject(s),
                resource: Resource(r),
                action: Action(action.into()),
                context: Context(c),
            }
        }

        #[derive(Default)]
        struct Arms {
            allow: bool,
            deny: bool,
            none: bool,
        }

        #[test]
        fn every_shipped_cell_agrees_between_the_file_oracle_and_the_snapshot() {
            let terms: Vec<&str> = ACTION_TERMS
                .iter()
                .chain(KERNEL_TERMS.iter())
                .copied()
                .collect();
            assert_eq!(terms.len(), 59);
            let (uids, paths, homes, ops) = (uids(), paths(), homes(), operations());
            assert_eq!(
                (uids.len(), paths.len(), homes.len(), ops.len()),
                (9, 22, 5, 7)
            );
            let destinations = [
                Some(AttrValue::Str("provider:openai".into())),
                Some(AttrValue::Str("provider:anthropic".into())),
                Some(AttrValue::Str("provider:other".into())),
                None,
            ];

            fn distinct<T: std::fmt::Debug>(v: &[T]) -> usize {
                v.iter()
                    .map(|x| format!("{x:?}"))
                    .collect::<std::collections::BTreeSet<_>>()
                    .len()
            }
            assert_eq!(
                (
                    distinct(&terms),
                    distinct(&uids),
                    distinct(&paths),
                    distinct(&homes),
                    distinct(&ops),
                    distinct(&destinations),
                ),
                (59, 9, 22, 5, 7, 4)
            );
            let mut cells = 0usize;
            let mut mismatches: Vec<String> = Vec::new();
            let mut roles_seen = std::collections::BTreeSet::new();
            let mut arms: std::collections::BTreeMap<&'static str, Arms> = Default::default();
            let mut grant_arms = (false, false, false);
            for (variant, src) in policies() {
                let auth = BasicAuthorizer::from_snapshot(
                    principal(),
                    src.paths().clone(),
                    test_digest,
                    compiled(&src),
                );
                let mut check = |req: maknae_security::Request, cell: &dyn Fn() -> String| {
                    cells += 1;
                    let oracle = auth.decide_oracle(&src, &req);
                    let snap = auth.decide_reporting_role(&req);
                    roles_seen.insert(oracle.1);
                    match (&oracle.0, req.action.0.as_str()) {
                        (Verdict::Permit { .. }, "session.prompt") if oracle.1 == Some("user") => {
                            grant_arms.0 = true
                        }
                        (Verdict::Permit { .. }, "session.prompt") => grant_arms.2 = true,
                        (Verdict::Deny { reason }, _)
                            if reason.starts_with("denied by role grant ") =>
                        {
                            grant_arms.1 = true
                        }
                        _ => {}
                    }
                    if FS_TERMS.contains(&req.action.0.as_str()) {
                        if let Some(role) = oracle.1 {
                            let a = arms.entry(role).or_default();
                            match &oracle.0 {
                                Verdict::Permit { .. } => a.allow = true,
                                Verdict::Deny { reason }
                                    if reason.starts_with("denied by policy entry ") =>
                                {
                                    a.deny = true
                                }
                                Verdict::NotApplicable { note: Some(n) }
                                    if n.contains("no capability entry") =>
                                {
                                    a.none = true
                                }
                                _ => {}
                            }
                        }
                    }
                    if oracle != snap {
                        mismatches.push(format!(
                            "{variant} {}: oracle {oracle:?} != snapshot {snap:?}",
                            cell()
                        ));
                    }
                };
                for uid in &uids {
                    for term in &terms {
                        if FS_TERMS.contains(term) {
                            let lanes: &[bool] = if *term == "fs.read" {
                                &[true, false]
                            } else {
                                &[true]
                            };
                            for &lane in lanes {
                                for op in &ops {
                                    for path in &paths {
                                        for home in &homes {
                                            let req = request(
                                                term,
                                                uid,
                                                home,
                                                path.as_ref().map(|p| (RESOURCE_PATH_KEY, p)),
                                                lane,
                                                *op,
                                            );
                                            check(req, &|| {
                                                format!(
                                                    "{term} uid={uid:?} lane={lane} op={op:?} path={path:?} home={home:?}"
                                                )
                                            });
                                        }
                                    }
                                }
                            }
                        } else if *term == "session.prompt" {
                            for d in &destinations {
                                let req = request(
                                    term,
                                    uid,
                                    &None,
                                    d.as_ref().map(|d| (decide::RESOURCE_DESTINATION, d)),
                                    false,
                                    None,
                                );
                                check(req, &|| format!("{term} uid={uid:?} destination={d:?}"));
                            }
                        } else {
                            let req = request(term, uid, &None, None, false, None);
                            check(req, &|| format!("{term} uid={uid:?}"));
                        }
                    }
                }
            }

            assert!(
                mismatches.is_empty(),
                "{} of {cells} cells disagree; first: {:#?}",
                mismatches.len(),
                &mismatches[..mismatches.len().min(10)]
            );
            let fs_cells = 4 * 7 * 22 * 5 + 7 * 22 * 5;
            let other_cells = 54 + 4;
            assert_eq!(cells, 4 * 9 * (fs_cells + other_cells));
            assert_eq!(
                roles_seen,
                [
                    None,
                    Some("admin"),
                    Some("user"),
                    Some("guest"),
                    Some("adversary")
                ]
                .into_iter()
                .collect()
            );
            assert_eq!(
                grant_arms,
                (true, true, true),
                "the grants variant must decide by grant"
            );
            for role in ["admin", "user"] {
                let a = &arms[role];
                assert!(
                    a.allow && a.deny && a.none,
                    "role {role} must reach every match arm"
                );
            }
        }

        #[test]
        fn subjects_agree_between_the_file_oracle_and_the_snapshot() {
            let mut seen = Vec::new();
            for (variant, src) in policies() {
                let oracle = assemble(src.policy().clone(), src.legacy(), src.uid_map())
                    .unwrap()
                    .roles
                    .as_subject_bindings();
                let snap = compiled(&src).subjects();
                assert_eq!(oracle, snap, "{variant}");
                seen.push(oracle.map(|v| v.len()));
            }
            assert_eq!(seen, [None, Some(0), Some(4), Some(4)]);
        }
    }
}
