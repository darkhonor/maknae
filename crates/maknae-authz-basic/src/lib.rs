//! maknae-authz-basic — the RBAC PDP backend behind the `maknae-security`
//! seam (#85). Four code-defined roles (`admin`/`user`/`guest`/`adversary`)
//! decide four-valued verdicts from `authz.yaml` and `bindings.yaml`, per
//! request, deny-by-default, fail-closed. Spec:
//! `2026-08-26-maknae-authz-basic-design.md` (out-of-repo design spec; specs
//! never live in this repository).
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
pub use binding::{shown, IdentityProblem, ListedSubject, SubjectState};
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
    /// `bindings.yaml` is refused as a whole (unknown role, an entry twice in
    /// one list, a `uid:` entry outside `adversary`, a failed account lookup).
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
    principal: RwLock<Arc<maknae_config::Principal>>,
    paths: PolicyPaths,
    digest: fn(&[u8]) -> [u8; 32],
    snapshot: RwLock<Arc<Snapshot>>,
    live_turn: LiveTurnLock,
    #[cfg(any(test, all(unix, feature = "hermetic-test-seam")))]
    evaluation_gate: Option<Arc<EvaluationGate>>,
}

/// A baseline's live turn: every composed decision shares it, and a live install
/// takes it alone. Only a baseline owns one, so a [`LiveTurn`] is always a baseline's.
#[derive(Debug)]
pub struct LiveTurnLock(RwLock<()>);

/// The live turn, held exclusively; every live install requires one.
pub struct LiveTurn<'a> {
    _held: std::sync::RwLockWriteGuard<'a, ()>,
    of: &'a LiveTurnLock,
}

impl LiveTurnLock {
    fn new() -> Self {
        Self(RwLock::new(()))
    }

    /// A lock owned by no baseline, for unit tests of the other live holders.
    #[cfg(all(unix, feature = "hermetic-test-seam"))]
    pub fn hermetic() -> Self {
        Self::new()
    }

    /// Held for the length of one decision.
    pub fn share(&self) -> std::sync::RwLockReadGuard<'_, ()> {
        self.0.read().unwrap_or_else(PoisonError::into_inner)
    }

    /// `None` while any decision or another install holds the turn.
    pub fn try_take(&self) -> Option<LiveTurn<'_>> {
        let held = match self.0.try_write() {
            Ok(held) => held,
            Err(std::sync::TryLockError::Poisoned(p)) => p.into_inner(),
            Err(std::sync::TryLockError::WouldBlock) => return None,
        };
        Some(LiveTurn {
            _held: held,
            of: self,
        })
    }

    pub fn holds(&self, turn: &LiveTurn<'_>) -> bool {
        std::ptr::eq(self, turn.of)
    }
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
            principal: RwLock::new(Arc::new(principal)),
            paths,
            digest,
            snapshot: RwLock::new(snapshot),
            live_turn: LiveTurnLock::new(),
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

    /// The installed principal; the read guard is released before this returns.
    fn current_principal(&self) -> Arc<maknae_config::Principal> {
        self.principal
            .read()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }

    /// The next decision reads `principal`; a decision holding the previous one
    /// finishes on it.
    fn install_principal(&self, principal: maknae_config::Principal) {
        *self
            .principal
            .write()
            .unwrap_or_else(PoisonError::into_inner) = Arc::new(principal);
    }

    fn decide_on(
        &self,
        snap: &Snapshot,
        principal: &maknae_config::Principal,
        req: &maknae_security::Request,
    ) -> maknae_security::Decided {
        let d = decide::decide_loaded_cited(snap.loaded(), principal, req);
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
        match tests::oracle::assemble(source) {
            Ok(lp) => decide::decide_loaded_with_role(&lp, &self.current_principal(), req),
            Err(_) => (maknae_security::Verdict::Indeterminate, None),
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

/// A loaded, validated `authz.yaml` and `bindings.yaml` with the bound usernames
/// resolved to uids: the policy input the snapshot compiler takes.
#[derive(Debug, Clone)]
pub struct PolicySource {
    policy: maknae_config::AuthzPolicy,
    bindings: maknae_config::Bindings,
    #[cfg(test)]
    uid_map: UidMap,
    resolved: binding::Resolved,
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
        let resolved = binding::resolve_subjects(&bindings, &uid_map)
            .map_err(|e| AuthzBasicError::Bindings(e.to_string()))?;
        validate_grants(&policy.action_grants)?;
        validate_destinations(&policy.destinations)?;
        Ok(Self {
            policy,
            bindings,
            #[cfg(test)]
            uid_map,
            resolved,
            principal,
            paths,
            policy_source,
            identity_source,
        })
    }

    /// Blocking: one getpwnam per bound username.
    pub fn with_bindings(
        &self,
        bindings: maknae_config::Bindings,
    ) -> Result<Self, AuthzBasicError> {
        let uid_map = resolve_uid_map(&bindings)?;
        self.with_bindings_resolved(bindings, uid_map)
    }

    fn with_bindings_resolved(
        &self,
        bindings: maknae_config::Bindings,
        uid_map: UidMap,
    ) -> Result<Self, AuthzBasicError> {
        Self::from_parts(
            self.policy.clone(),
            bindings,
            uid_map,
            self.principal.clone(),
            self.paths.clone(),
        )
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

    #[cfg(test)]
    pub(crate) fn uid_map(&self) -> &UidMap {
        &self.uid_map
    }

    /// The subjects this load could not bind as written; each is decided alone.
    pub fn identity_problems(&self) -> &[IdentityProblem] {
        &self.resolved.problems
    }

    /// The `adversary:` names this load could not resolve, in problem order.
    pub fn unresolved_adversaries(&self) -> Vec<String> {
        self.resolved
            .problems
            .iter()
            .filter_map(|p| match p {
                IdentityProblem::UnresolvedAdversary { name } => Some(name.clone()),
                _ => None,
            })
            .collect()
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
                .subjects
                .iter()
                .map(|(uid, role, name)| maknae_graph::identity::SubjectEntry {
                    uid: *uid,
                    name: name.clone(),
                    role: role.key().into(),
                })
                .collect(),
            aliases: std::collections::BTreeMap::new(),
        }
        .with_claims(self.resolved.adversary_names.clone())
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

/// What one account lookup said. `Absent` is decided per subject; `Failed`
/// refuses the whole load.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Lookup {
    Found(u32),
    Absent,
    Failed(i32),
}

/// getpwnam(3)'s "not found" spellings are `Ok(None)`, `ENOENT`, `ESRCH`, `EBADF`
/// and `EPERM`; every other errno, `ERANGE` and errno 0 included, is a failed lookup.
#[cfg(unix)]
pub(crate) fn classify_lookup(r: Result<Option<u32>, nix::errno::Errno>) -> Lookup {
    use nix::errno::Errno;
    match r {
        Ok(Some(uid)) => Lookup::Found(uid),
        Ok(None) | Err(Errno::ENOENT | Errno::ESRCH | Errno::EBADF | Errno::EPERM) => {
            Lookup::Absent
        }
        Err(e) => Lookup::Failed(e as i32),
    }
}

/// One lookup per distinct bound username; a `uid:` entry needs none.
fn resolve_uid_map_with(
    bindings: &maknae_config::Bindings,
    lookup: impl Fn(&str) -> Lookup,
) -> Result<UidMap, AuthzBasicError> {
    let mut map = UidMap::new();
    let mut asked = std::collections::BTreeSet::new();
    for entries in bindings.roles.iter().flat_map(|r| r.values()) {
        for e in entries {
            let maknae_config::BindingEntry::Name(name) = e else {
                continue;
            };
            if !asked.insert(name.as_str()) {
                continue;
            }
            match lookup(name) {
                Lookup::Found(uid) => {
                    map.insert(name.clone(), uid);
                }
                Lookup::Absent => {}
                Lookup::Failed(errno) => {
                    return Err(AuthzBasicError::Bindings(format!(
                        "looking up '{name}' failed (errno {errno}); nothing was changed"
                    )))
                }
            }
        }
    }
    Ok(map)
}

fn resolve_uid_map(bindings: &maknae_config::Bindings) -> Result<UidMap, AuthzBasicError> {
    resolve_uid_map_with(bindings, lookup_uid)
}

/// One function with an INLINE `#[cfg(unix)]`/`#[cfg(not(unix))]` split
/// (the `security_load` idiom): a standalone `#[cfg(not(unix))] fn` would be
/// its own mutation target whose body never compiles on a unix runner.
fn lookup_uid(name: &str) -> Lookup {
    #[cfg(not(unix))]
    {
        let _ = name;
        Lookup::Failed(0)
    }
    #[cfg(unix)]
    {
        // nix reads errno on a non-zero return; macOS getpwnam_r returns ERANGE
        // without setting it, so a stale not-found errno must not survive to here.
        nix::errno::Errno::clear();
        classify_lookup(nix::unistd::User::from_name(name).map(|u| u.map(|u| u.uid.as_raw())))
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
        self.decide_on(&self.snapshot(), &self.current_principal(), req)
    }

    fn decide_cited_all(&self, reqs: &[maknae_security::Request]) -> Vec<maknae_security::Decided> {
        let (snap, principal) = (self.snapshot(), self.current_principal());
        reqs.iter()
            .map(|r| self.decide_on(&snap, &principal, r))
            .collect()
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
    fn principal(&self) -> maknae_config::Principal;
    fn live_turn(&self) -> &LiveTurnLock;
    /// The next decision resolves the enrolled principal to `principal`; refused
    /// unless `turn` is this baseline's own.
    fn install_principal(
        &self,
        turn: &LiveTurn<'_>,
        principal: maknae_config::Principal,
    ) -> Result<(), String>;
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

    fn principal(&self) -> maknae_config::Principal {
        (*self.current_principal()).clone()
    }

    fn live_turn(&self) -> &LiveTurnLock {
        &self.live_turn
    }

    fn install_principal(
        &self,
        turn: &LiveTurn<'_>,
        principal: maknae_config::Principal,
    ) -> Result<(), String> {
        if !self.live_turn.holds(turn) {
            return Err("the principal is installed only in this baseline's live turn".into());
        }
        BasicAuthorizer::install_principal(self, principal);
        Ok(())
    }

    fn load_source(&self) -> Result<PolicySource, AuthzBasicError> {
        PolicySource::load(self.paths.clone(), Baseline::principal(self))
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

    fn principal(&self) -> maknae_config::Principal {
        Baseline::principal(&self.inner)
    }

    fn live_turn(&self) -> &LiveTurnLock {
        Baseline::live_turn(&self.inner)
    }

    fn install_principal(
        &self,
        turn: &LiveTurn<'_>,
        principal: maknae_config::Principal,
    ) -> Result<(), String> {
        Baseline::install_principal(&self.inner, turn, principal)
    }

    fn load_source(&self) -> Result<PolicySource, AuthzBasicError> {
        PolicySource::load_with_requirement(
            self.inner.paths.clone(),
            Baseline::principal(&self.inner),
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
    let file = source.identity_layer(label, digests.get("bindings").copied());
    let stored = base
        .map(|g| maknae_graph::identity::extract(g).map_err(|e| refused(e.to_string())))
        .transpose()?;
    let layer = match &stored {
        None => file,
        Some(stored) => {
            if let Some(m) = maknae_graph::identity::drops_explicit_bindings(
                &stored.layer,
                &file,
                source.bindings().is_missing(),
            ) {
                return Err(refused(m.into()));
            }
            maknae_graph::identity::carry_forward(
                &file,
                &source.unresolved_adversaries(),
                &stored.layer,
            )
            .0
        }
    };
    let persisted_set = maknae_graph::kernel::persisted_compiled_set(label);
    let vocabulary = digest(
        &persisted_set
            .canonical_bytes()
            .map_err(|e| refused(e.to_string()))?,
    );
    let build = |revision: u64, initiator: ProvenanceKind| {
        maknae_graph::identity::build(
            &layer,
            stored.as_ref().and_then(|s| s.baseline.as_ref()),
            &persisted_set,
            vocabulary,
            revision,
            initiator,
        )
        .map(Arc::new)
        .map_err(|e| refused(e.to_string()))
    };
    let persisted = match (base, &stored) {
        (Some(g), Some(stored)) if stored.layer == layer => g.clone(),
        (Some(g), _) => build(g.revision() + 1, ProvenanceKind::RootFile)?,
        (None, _) => build(1, ProvenanceKind::Seed)?,
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
                "admin.baseline.show",
                "admin.baseline.accept",
                "session.prompt"
            ]
        );
    }
    use super::*;
    use maknae_security::{
        Action, AttrValue, Attributes, Authorizer, Context, Resource, Subject, Verdict,
    };

    /// The resolution `maknaed` used before #496 — whole-policy refusals — kept
    /// as the equivalence oracle. Production never reaches it.
    pub(crate) mod oracle {
        use crate::binding::{Resolution, UidMap};
        use crate::role::Role;
        use crate::AuthzBasicError;
        use std::collections::btree_map::Entry;
        use std::collections::BTreeMap;

        pub(crate) type LegacyBindings = Option<BTreeMap<String, Vec<String>>>;

        /// The file's entries as the name-keyed resolver reads them: a `uid:` entry becomes
        /// the name `uid:N` mapped to N. `uid:` entries are accepted under `adversary` only.
        pub(crate) fn legacy_bindings(
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

        /// Validated, uid-keyed bindings for one loaded policy snapshot.
        #[derive(Clone, Debug, PartialEq, Eq)]
        pub(crate) struct ResolvedBindings {
            by_uid: BTreeMap<u32, (Role, String)>,
            /// The `bindings:` key was PRESENT in the file → defaults suppressed
            /// entirely (spec §3 precedence; what makes `admin: []` mean "no admin").
            explicit: bool,
        }

        /// Why a `bindings:` block is invalid (spec §3a). Every variant names the
        /// offending token so the boot refusal / audit record is actionable.
        #[derive(Clone, Debug, PartialEq, Eq)]
        pub(crate) enum BindingError {
            UnknownRole(String),
            DualMembership(String),
            Duplicate(String),
            Unresolvable(String),
            DuplicateUid { uid: u32, names: (String, String) },
        }

        impl std::fmt::Display for BindingError {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                match self {
                    BindingError::UnknownRole(k) => write!(f, "bindings names unknown role '{k}'"),
                    BindingError::DualMembership(n) => {
                        write!(f, "identity '{n}' appears in more than one role")
                    }
                    BindingError::Duplicate(n) => {
                        write!(f, "identity '{n}' listed twice in one role")
                    }
                    BindingError::Unresolvable(n) => {
                        write!(f, "identity '{n}' has no resolved uid")
                    }
                    BindingError::DuplicateUid { uid, names: (a, b) } => write!(
                f,
                "identities '{a}' and '{b}' resolve to the same uid {uid}; bind one of them"
            ),
                }
            }
        }

        /// Validate a parsed `bindings` value against the closed role vocabulary and
        /// the construction-time `UidMap`.
        pub(crate) fn resolve(
            bindings: &Option<BTreeMap<String, Vec<String>>>,
            lookup: &UidMap,
        ) -> Result<ResolvedBindings, BindingError> {
            let Some(map) = bindings else {
                return Ok(ResolvedBindings {
                    by_uid: BTreeMap::new(),
                    explicit: false,
                });
            };
            let mut by_uid: BTreeMap<u32, (Role, String)> = BTreeMap::new();
            let mut seen: BTreeMap<&str, ()> = BTreeMap::new();
            for (key, members) in map {
                let role =
                    Role::from_key(key).ok_or_else(|| BindingError::UnknownRole(key.clone()))?;
                for name in members {
                    if seen.insert(name.as_str(), ()).is_some() {
                        // Same name earlier — in this role (Duplicate) or another
                        // (DualMembership). Distinguish for the error message only;
                        // both refuse.
                        let dup_in_this_role = members
                            .iter()
                            .filter(|m| m.as_str() == name.as_str())
                            .count()
                            > 1;
                        return Err(if dup_in_this_role {
                            BindingError::Duplicate(name.clone())
                        } else {
                            BindingError::DualMembership(name.clone())
                        });
                    }
                    let uid = lookup
                        .get(name)
                        .copied()
                        .ok_or_else(|| BindingError::Unresolvable(name.clone()))?;
                    match by_uid.entry(uid) {
                        Entry::Vacant(v) => {
                            v.insert((role, name.clone()));
                        }
                        Entry::Occupied(o) if o.get().0 == role => {}
                        Entry::Occupied(o) => {
                            return Err(BindingError::DuplicateUid {
                                uid,
                                names: (o.get().1.clone(), name.clone()),
                            })
                        }
                    }
                }
            }
            Ok(ResolvedBindings {
                by_uid,
                explicit: true,
            })
        }

        impl ResolvedBindings {
            /// The explicit block by role, members as `uid:N`; `None` without a `bindings:` key.
            pub(crate) fn as_subject_bindings(
                &self,
            ) -> Option<Vec<maknae_security::SubjectBinding>> {
                if !self.explicit {
                    return None;
                }
                let mut out: std::collections::BTreeMap<String, Vec<String>> = Default::default();
                for (uid, (role, _)) in self.by_uid.iter() {
                    out.entry(role.key().to_string())
                        .or_default()
                        .push(format!("uid:{uid}"));
                }
                Some(
                    out.into_iter()
                        .map(|(role, mut members)| {
                            members.sort();
                            maknae_security::SubjectBinding { role, members }
                        })
                        .collect(),
                )
            }

            /// Subject → role on the uid; defaults apply only without a `bindings:` key.
            pub(crate) fn role_for(&self, uid: u32, principal_uid: u32) -> Resolution {
                if self.explicit {
                    match self.by_uid.get(&uid) {
                        Some((r, _)) => Resolution::Role(*r),
                        None => Resolution::NoRole,
                    }
                } else if uid == principal_uid {
                    Resolution::Role(Role::Admin)
                } else {
                    Resolution::NoRole
                }
            }
        }

        impl ResolvedBindings {
            /// Every bound uid in uid order, with its role and the name it was bound under.
            pub(crate) fn subjects(&self) -> impl Iterator<Item = (u32, Role, &str)> {
                self.by_uid
                    .iter()
                    .map(|(uid, (role, name))| (*uid, *role, name.as_str()))
            }
        }

        #[derive(Debug, PartialEq, Eq)]
        pub(crate) enum Refused {
            Bindings(BindingError),
            Other(String),
        }

        pub(crate) fn assemble(
            src: &crate::PolicySource,
        ) -> Result<crate::decide::LoadedPolicy, Refused> {
            let other = |e: AuthzBasicError| Refused::Other(e.to_string());
            let (legacy, uid_map) =
                legacy_bindings(src.bindings(), src.uid_map().clone()).map_err(other)?;
            Ok(crate::decide::LoadedPolicy {
                policy: src.policy().clone(),
                roles: crate::binding::Roles::File(
                    resolve(&legacy, &uid_map).map_err(Refused::Bindings)?,
                ),
                action_grants: crate::validate_grants(&src.policy().action_grants)
                    .map_err(other)?,
                destinations: crate::validate_destinations(&src.policy().destinations)
                    .map_err(other)?,
            })
        }

        mod pinned {
            use super::*;

            fn b(pairs: &[(&str, &[&str])]) -> Option<BTreeMap<String, Vec<String>>> {
                Some(
                    pairs
                        .iter()
                        .map(|(k, v)| (k.to_string(), v.iter().map(|s| s.to_string()).collect()))
                        .collect(),
                )
            }

            fn uids(pairs: &[(&str, u32)]) -> UidMap {
                pairs.iter().map(|(n, u)| (n.to_string(), *u)).collect()
            }

            const PRINCIPAL_UID: u32 = 501;

            #[test]
            fn unknown_role_key_is_refused_never_defaulted() {
                let got = resolve(&b(&[("advesary", &["alex"])]), &uids(&[("alex", 501)]));
                assert_eq!(got, Err(BindingError::UnknownRole("advesary".into())));
            }

            #[test]
            fn a_name_in_two_role_sets_is_dual_membership() {
                let got = resolve(
                    &b(&[("admin", &["alex"]), ("user", &["alex"])]),
                    &uids(&[("alex", 501)]),
                );
                assert_eq!(got, Err(BindingError::DualMembership("alex".into())));
            }

            #[test]
            fn a_name_twice_in_one_list_is_duplicate() {
                let got = resolve(&b(&[("user", &["alex", "alex"])]), &uids(&[("alex", 501)]));
                assert_eq!(got, Err(BindingError::Duplicate("alex".into())));
            }

            #[test]
            fn a_name_missing_from_the_uid_map_is_unresolvable() {
                let got = resolve(&b(&[("user", &["nobody-new"])]), &UidMap::new());
                assert_eq!(got, Err(BindingError::Unresolvable("nobody-new".into())));
            }

            /// #276: `agent` is an ordinary username now. It resolves through NSS like
            /// any other bound name and fails closed when no such account exists --
            /// which is the behaviour change an operator could actually notice, so it
            /// gets a test. Replaces `agent_token_is_never_looked_up`, whose subject
            /// (a name that bypasses the uid map) no longer exists.
            #[test]
            fn agent_is_an_ordinary_name_and_fails_closed_when_unresolvable() {
                let got = resolve(&b(&[("adversary", &["agent"])]), &UidMap::new());
                assert_eq!(got, Err(BindingError::Unresolvable("agent".into())));
                // And when it DOES resolve, it binds like any other name.
                let r =
                    resolve(&b(&[("adversary", &["agent"])]), &uids(&[("agent", 4242)])).unwrap();
                assert_eq!(
                    r.role_for(4242, PRINCIPAL_UID),
                    Resolution::Role(Role::Adversary)
                );
            }

            #[test]
            fn present_but_empty_bindings_suppress_defaults_entirely() {
                // The no-discretionary-admin posture (spec §3): with an explicit
                // empty map, even the enrolled principal has NO role.
                let r = resolve(&Some(BTreeMap::new()), &UidMap::new()).unwrap();
                assert_eq!(r.role_for(PRINCIPAL_UID, PRINCIPAL_UID), Resolution::NoRole);
            }

            #[test]
            fn absent_bindings_apply_defaults() {
                let r = resolve(&None, &UidMap::new()).unwrap();
                assert_eq!(
                    r.role_for(PRINCIPAL_UID, PRINCIPAL_UID),
                    Resolution::Role(Role::Admin)
                );
                assert_eq!(r.role_for(999, PRINCIPAL_UID), Resolution::NoRole);
            }

            #[test]
            fn explicit_bindings_bind_by_resolved_uid() {
                let r = resolve(
                    &b(&[("admin", &["alex"]), ("adversary", &["mallory"])]),
                    &uids(&[("alex", 501), ("mallory", 666)]),
                )
                .unwrap();
                assert_eq!(r.role_for(501, 501), Resolution::Role(Role::Admin));
                assert_eq!(r.role_for(666, 501), Resolution::Role(Role::Adversary));
                assert_eq!(r.role_for(1000, 501), Resolution::NoRole);
            }

            // `missing_uid_with_no_reserved_name_is_no_role` retired with its subject
            // (#276): `role_for` now takes `u32`, so "no uid" is not expressible here.
            // The property moved UP to `decide_loaded_with_role`'s guard, which returns
            // Indeterminate before reaching this function -- see
            // `decide::tests::missing_identity_is_indeterminate_distinct_from_unbound`.

            #[test]
            fn one_uid_under_two_roles_refuses_naming_both_names() {
                let got = resolve(
                    &b(&[("admin", &["root"]), ("adversary", &["toor"])]),
                    &uids(&[("root", 0), ("toor", 0)]),
                );
                let want = BindingError::DuplicateUid {
                    uid: 0,
                    names: ("root".into(), "toor".into()),
                };
                assert_eq!(got, Err(want.clone()));
                assert_eq!(
                    want.to_string(),
                    "identities 'root' and 'toor' resolve to the same uid 0; bind one of them"
                );
            }

            #[test]
            fn one_uid_twice_under_one_role_keeps_the_first_name() {
                let r = resolve(
                    &b(&[("admin", &["root", "toor"])]),
                    &uids(&[("root", 0), ("toor", 0)]),
                )
                .unwrap();
                let got: Vec<(u32, Role, &str)> = r.subjects().collect();
                assert_eq!(got, vec![(0, Role::Admin, "root")]);
                assert_eq!(r.role_for(0, PRINCIPAL_UID), Resolution::Role(Role::Admin));
            }

            #[test]
            fn subjects_lists_every_binding_in_uid_order() {
                let r = resolve(
                    &b(&[("user", &["ursula"]), ("admin", &["alex"])]),
                    &uids(&[("alex", 1000), ("ursula", 7)]),
                )
                .unwrap();
                let got: Vec<(u32, Role, &str)> = r.subjects().collect();
                assert_eq!(
                    got,
                    vec![(7, Role::User, "ursula"), (1000, Role::Admin, "alex")]
                );
            }
        }
    }

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

    #[test]
    fn a_replacement_section_is_resolved_and_hashed_as_the_enforced_section() {
        let src = source_with(EMPTY, Some(ADMIN_ROOT), &[("root", 0), ("mallory", 4242)]);
        let live = maknae_config::parse_bindings(
            "schema_version: 1\nbindings:\n  admin: [\"root\"]\n  adversary: [\"mallory\"]\n",
        )
        .unwrap();
        let next = src
            .with_bindings_resolved(
                live.clone(),
                [("root".into(), 0), ("mallory".into(), 4242)].into(),
            )
            .unwrap();
        assert_eq!(next.bindings(), &live);
        let layer = next.identity_layer("UNCLASSIFIED", None);
        assert!(layer
            .subjects
            .iter()
            .any(|s| s.uid == 4242 && s.role == "adversary"));
        let d = |b: &[u8]| {
            let mut o = [0u8; 32];
            o[0] = b.len() as u8;
            o
        };
        assert_eq!(
            next.section_digests(d)["bindings"],
            d(live.section_canonical().unwrap().as_bytes())
        );
        assert_eq!(next.policy(), src.policy(), "authz.yaml is not re-read");
        let refused =
            maknae_config::parse_bindings("schema_version: 1\nbindings:\n  root: [\"x\"]\n")
                .unwrap();
        assert!(src
            .with_bindings_resolved(refused, Default::default())
            .is_err());
    }

    #[test]
    fn with_bindings_resolves_uid_entries_without_a_lookup() {
        let src = source_with(EMPTY, Some(ADMIN_ROOT), &[("root", 0)]);
        let live = maknae_config::parse_bindings(
            "schema_version: 1\nbindings:\n  adversary:\n    - uid: 4242\n",
        )
        .unwrap();
        let next = src.with_bindings(live).unwrap();
        assert!(next
            .identity_layer("UNCLASSIFIED", Some([0; 32]))
            .subjects
            .iter()
            .any(|s| s.uid == 4242));
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

    /// The shipped file with its `roles:` block cut, for tests that write their own.
    pub(crate) fn shipped_without_roles() -> &'static str {
        let cut = SHIPPED
            .find("\nroles:")
            .expect("the shipped file has a roles block");
        &SHIPPED[..=cut]
    }

    /// Proof (a): the REAL shipped authz.yaml (byte-identical, via
    /// include_str!) parses, and with bindings absent the defaults branch
    /// decides: enrolled uid → admin rows; agent name → user rows.
    #[test]
    fn shipped_content_defaults_proof() {
        let policy = maknae_config::parse_authz(SHIPPED).expect("shipped authz.yaml parses");
        let action_grants = validate_grants(&policy.action_grants).expect("shipped grants");
        let lp = decide::LoadedPolicy {
            policy,
            roles: binding::Roles::File(tests::oracle::resolve(&None, &UidMap::new()).unwrap()),
            action_grants,
            destinations: decide::DestinationGrants::default(),
        };
        let ask = |uid: i64, action: &str| {
            let mut r = liveness_req(Some(uid));
            r.action = Action(action.into());
            decide::decide_loaded(&lp, &principal(), &r)
        };
        for term in SHIPPED_ADMIN_TERMS {
            assert_eq!(ask(501, term), audit_permit(), "{term} for the principal");
            assert_eq!(
                ask(4242, term),
                Verdict::NotApplicable {
                    note: Some("subject resolves to no role".into())
                },
                "{term} for an unbound uid"
            );
        }
        assert_eq!(
            ask(501, "admin.config.show"),
            Verdict::NotApplicable {
                note: Some("role admin: no rule for admin.config.show".into())
            }
        );
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

    const SHIPPED_ADMIN_TERMS: [&str; 4] = [
        "admin.status",
        "admin.subject.list",
        "admin.baseline.show",
        "admin.baseline.accept",
    ];

    #[test]
    fn the_shipped_file_grants_admin_exactly_the_four_terms() {
        let policy = maknae_config::parse_authz(SHIPPED).expect("shipped authz.yaml parses");
        let roles: Vec<&String> = policy.action_grants.keys().collect();
        assert_eq!(roles, ["admin"]);
        let admin = &policy.action_grants["admin"];
        assert_eq!(admin.allow, SHIPPED_ADMIN_TERMS);
        assert!(admin.deny.is_empty());
        assert!(policy.destinations.is_empty());
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
        let auth = BasicAuthorizer::from_snapshot(
            principal(),
            src.paths().clone(),
            test_digest,
            compiled(&src),
        );
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

    fn no_role() -> Verdict {
        Verdict::NotApplicable {
            note: Some("subject resolves to no role".into()),
        }
    }

    #[test]
    fn an_installed_principal_is_admin_on_the_next_decision_when_bindings_are_absent() {
        let auth = authorizer_over(EMPTY, None, &[]);
        assert_eq!(auth.decide(&whoami(501)), audit_permit());
        let held = Baseline::principal(&auth);
        let next = maknae_config::Principal {
            name: "b".into(),
            uid: 777,
        };
        let turn = auth.live_turn().try_take().unwrap();
        Baseline::install_principal(&auth, &turn, next.clone()).unwrap();
        drop(turn);
        assert_eq!(auth.decide(&whoami(501)), no_role());
        assert_eq!(auth.decide(&whoami(777)), audit_permit());
        assert_eq!(Baseline::principal(&auth), next);
        assert_eq!(held, principal());
        let all = auth.decide_cited_all(&[whoami(501), whoami(777)]);
        assert_eq!(all[0].verdict, no_role());
        assert_eq!(all[1].verdict, audit_permit());
    }

    #[test]
    fn the_live_turn_is_taken_alone_and_installs_only_into_its_own_baseline() {
        let auth = authorizer_over(EMPTY, None, &[]);
        let other = authorizer_over(EMPTY, None, &[]);
        let next = maknae_config::Principal {
            name: "b".into(),
            uid: 777,
        };
        let decision = auth.live_turn().share();
        assert!(auth.live_turn().try_take().is_none());
        drop(decision);
        let foreign = other.live_turn().try_take().unwrap();
        assert!(!auth.live_turn().holds(&foreign));
        let err = Baseline::install_principal(&auth, &foreign, next.clone()).unwrap_err();
        assert!(err.contains("live turn"), "{err}");
        assert_eq!(Baseline::principal(&auth), principal());
        drop(foreign);
        let turn = auth.live_turn().try_take().unwrap();
        assert!(auth.live_turn().holds(&turn));
        assert!(auth.live_turn().try_take().is_none());
        Baseline::install_principal(&auth, &turn, next.clone()).unwrap();
        assert_eq!(Baseline::principal(&auth), next);
    }

    #[test]
    fn a_poisoned_live_turn_is_still_taken() {
        let auth = Arc::new(authorizer_over(EMPTY, None, &[]));
        let poisoner = Arc::clone(&auth);
        let _ = std::thread::spawn(move || {
            let _turn = poisoner.live_turn().try_take().unwrap();
            panic!("poison the turn");
        })
        .join();
        drop(auth.live_turn().share());
        assert!(auth.live_turn().try_take().is_some());
    }

    #[test]
    fn a_poisoned_principal_holder_still_decides_and_installs() {
        let auth = Arc::new(authorizer_over(EMPTY, None, &[]));
        let poisoner = Arc::clone(&auth);
        let _ = std::thread::spawn(move || {
            let _guard = poisoner.principal.write().unwrap();
            panic!("poison the holder");
        })
        .join();
        assert!(auth.principal.is_poisoned());
        assert_eq!(auth.decide(&whoami(501)), audit_permit());
        let turn = auth.live_turn().try_take().unwrap();
        Baseline::install_principal(
            &*auth,
            &turn,
            maknae_config::Principal {
                name: "b".into(),
                uid: 777,
            },
        )
        .unwrap();
        drop(turn);
        assert_eq!(auth.decide(&whoami(777)), audit_permit());
        assert_eq!(auth.decide(&whoami(501)), no_role());
    }

    #[test]
    fn the_baseline_trait_reports_this_authorizers_parts() {
        let auth = authorizer_over(EMPTY, Some(ADMIN_ROOT), &[("root", 0)]);
        assert_eq!(Baseline::principal(&auth), principal());
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
    fn every_subject_the_load_named_is_one_entry_with_its_state() {
        let file = Some(
            "schema_version: 1\nbindings:\n  admin: [alex]\n  user: [ursula, ghost, gus, eve]\n  guest: [gustav]\n  adversary: [mallory, nobody, eve, {uid: 4242}]\n",
        );
        let uids = vec![
            ("alex", 1000),
            ("ursula", 1001),
            ("gus", 1002),
            ("gustav", 1002),
            ("eve", 1003),
        ];
        let resolving = [uids.clone(), vec![("mallory", 666)]].concat();
        let first = compiled(&source_with(SHIPPED, file, &resolving));
        let next = snapshot_over(
            &source_with(SHIPPED, file, &uids),
            LABEL,
            test_digest,
            Some(first.persisted()),
        )
        .unwrap();
        let e = |uid: Option<u32>, names: &[&str], state| ListedSubject {
            uid,
            names: names.iter().map(|n| n.to_string()).collect(),
            state,
        };
        assert_eq!(
            next.subject_entries().unwrap(),
            [
                e(Some(666), &["mallory"], SubjectState::CarriedForward),
                e(Some(1000), &["alex"], SubjectState::Bound("admin")),
                e(Some(1001), &["ursula"], SubjectState::Bound("user")),
                e(
                    Some(1002),
                    &["gustav", "gus"],
                    SubjectState::Unbound(vec!["guest", "user"])
                ),
                e(Some(1003), &["eve"], SubjectState::Contained),
                e(Some(4242), &[], SubjectState::Contained),
                e(None, &["ghost"], SubjectState::Unresolved("user")),
                e(None, &["nobody"], SubjectState::Unresolved("adversary")),
            ]
        );
        assert_eq!(
            compiled(&source_with(SHIPPED, None, &resolving)).subject_entries(),
            None,
            "absent bindings enumerate nothing"
        );
        assert_eq!(
            compiled(&source_with(
                SHIPPED,
                Some("schema_version: 1\nbindings: {}\n"),
                &resolving
            ))
            .subject_entries(),
            Some(vec![])
        );
    }

    #[test]
    fn a_contained_name_that_stops_resolving_stays_contained_across_a_recompile() {
        let file = Some("schema_version: 1\nbindings:\n  admin: [alex]\n  adversary: [mallory]\n");
        let first = compiled(&source_with(
            SHIPPED,
            file,
            &[("alex", 1000), ("mallory", 666)],
        ));
        assert!(first.identity_problems().is_empty());
        let gone = source_with(SHIPPED, file, &[("alex", 1000)]);
        assert_eq!(gone.unresolved_adversaries(), ["mallory"]);
        let next = snapshot_over(&gone, LABEL, test_digest, Some(first.persisted())).unwrap();
        assert!(
            Arc::ptr_eq(next.persisted(), first.persisted()),
            "the carried layer compares equal"
        );
        let a =
            BasicAuthorizer::from_snapshot(principal(), paths(), test_digest, Arc::clone(&next));
        assert_eq!(
            a.decide_reporting_role(&liveness_req(Some(666))),
            (
                Verdict::Deny {
                    reason: CONTAINED.into()
                },
                Some("adversary")
            )
        );
        assert_eq!(
            next.identity_problems().as_ref(),
            [IdentityProblem::CarriedForward {
                uid: 666,
                name: "mallory".into(),
                overrides: vec![]
            }]
        );
        let again = snapshot_over(&gone, LABEL, test_digest, Some(next.persisted())).unwrap();
        assert!(
            Arc::ptr_eq(again.persisted(), first.persisted()),
            "idempotent"
        );
        let released = source_with(
            SHIPPED,
            Some("schema_version: 1\nbindings:\n  admin: [alex]\n"),
            &[("alex", 1000)],
        );
        let after = snapshot_over(&released, LABEL, test_digest, Some(next.persisted())).unwrap();
        let b = BasicAuthorizer::from_snapshot(principal(), paths(), test_digest, after);
        assert_eq!(
            b.decide_reporting_role(&liveness_req(Some(666))).1,
            None,
            "removing the name releases it"
        );
    }

    #[test]
    fn a_never_contained_unresolved_adversary_is_not_carried() {
        let first = compiled(&source_with(
            SHIPPED,
            Some("schema_version: 1\nbindings:\n  user: [mallory]\n"),
            &[("mallory", 666)],
        ));
        let file = "schema_version: 1\nbindings:\n  adversary: [mallory]\n";
        let next = snapshot_over(
            &source_with(SHIPPED, Some(file), &[]),
            LABEL,
            test_digest,
            Some(first.persisted()),
        )
        .unwrap();
        assert_eq!(
            next.identity_problems().as_ref(),
            [IdentityProblem::UnresolvedAdversary {
                name: "mallory".into()
            }]
        );
        let a = BasicAuthorizer::from_snapshot(principal(), paths(), test_digest, next);
        assert_eq!(a.decide_reporting_role(&liveness_req(Some(666))).1, None);
    }

    #[test]
    fn a_reused_uid_stays_contained_and_the_problem_names_the_overridden_binding() {
        let file = "schema_version: 1\nbindings:\n  user: [bob]\n  adversary: [mallory]\n";
        let first = compiled(&source_with(
            SHIPPED,
            Some("schema_version: 1\nbindings:\n  adversary: [mallory]\n"),
            &[("mallory", 666)],
        ));
        let reused = source_with(SHIPPED, Some(file), &[("bob", 666)]);
        let next = snapshot_over(&reused, LABEL, test_digest, Some(first.persisted())).unwrap();
        assert_eq!(
            next.identity_problems().as_ref(),
            [IdentityProblem::CarriedForward {
                uid: 666,
                name: "mallory".into(),
                overrides: vec![("bob".into(), "user")]
            }]
        );
        assert_eq!(
            next.identity_problems()[0].to_string(),
            "'mallory' under adversary no longer resolves; uid 666 stays contained (carried forward); this overrides bob (user)"
        );
        let a =
            BasicAuthorizer::from_snapshot(principal(), paths(), test_digest, Arc::clone(&next));
        assert_eq!(
            a.decide_reporting_role(&liveness_req(Some(666))),
            (
                Verdict::Deny {
                    reason: CONTAINED.into()
                },
                Some("adversary")
            ),
            "bob's uid is contained"
        );
    }

    #[test]
    fn a_carried_uid_that_the_file_also_binds_twice_is_one_carried_subject() {
        let first = compiled(&source_with(
            SHIPPED,
            Some("schema_version: 1\nbindings:\n  adversary: [mallory]\n"),
            &[("mallory", 666)],
        ));
        let file = "schema_version: 1\nbindings:\n  admin: [bob]\n  user: [bobby]\n  adversary: [mallory]\n";
        let reused = source_with(SHIPPED, Some(file), &[("bob", 666), ("bobby", 666)]);
        let next = snapshot_over(&reused, LABEL, test_digest, Some(first.persisted())).unwrap();
        assert_eq!(
            next.identity_problems().as_ref(),
            [IdentityProblem::CarriedForward {
                uid: 666,
                name: "mallory".into(),
                overrides: vec![("bob".into(), "admin"), ("bobby".into(), "user")]
            }]
        );
        assert_eq!(
            next.identity_problems()[0].to_string(),
            "'mallory' under adversary no longer resolves; uid 666 stays contained (carried forward); this overrides bob (admin), bobby (user)"
        );
        assert_eq!(
            next.subject_entries().unwrap(),
            [crate::ListedSubject {
                uid: Some(666),
                names: vec!["mallory".into(), "bob".into(), "bobby".into()],
                state: crate::SubjectState::CarriedForward,
            }]
        );
        let a = BasicAuthorizer::from_snapshot(principal(), paths(), test_digest, next);
        assert_eq!(
            a.decide_reporting_role(&liveness_req(Some(666))).1,
            Some("adversary")
        );
    }

    #[test]
    fn an_unresolved_adversary_keeps_its_claim_while_a_uid_entry_contains_the_uid() {
        let first = compiled(&source_with(
            SHIPPED,
            Some("schema_version: 1\nbindings:\n  adversary: [mallory]\n"),
            &[("mallory", 666)],
        ));
        let file = "schema_version: 1\nbindings:\n  adversary: [mallory, {uid: 666}]\n";
        let next = snapshot_over(
            &source_with(SHIPPED, Some(file), &[]),
            LABEL,
            test_digest,
            Some(first.persisted()),
        )
        .unwrap();
        assert_eq!(
            next.identity_problems().as_ref(),
            [IdentityProblem::CarriedForward {
                uid: 666,
                name: "mallory".into(),
                overrides: vec![]
            }]
        );
        let dropped = source_with(
            SHIPPED,
            Some("schema_version: 1\nbindings:\n  adversary: [mallory]\n"),
            &[],
        );
        let after = snapshot_over(&dropped, LABEL, test_digest, Some(next.persisted())).unwrap();
        let a = BasicAuthorizer::from_snapshot(principal(), paths(), test_digest, after);
        assert_eq!(
            a.decide_reporting_role(&liveness_req(Some(666))).1,
            Some("adversary"),
            "dropping the uid entry leaves the name's claim"
        );
    }

    #[test]
    fn an_alias_that_stops_resolving_keeps_its_uid_contained_after_the_other_alias_moves() {
        let file = Some(
            "schema_version: 1\nbindings:\n  admin: [operator]\n  adversary: [alice, alicia]\n",
        );
        let first = compiled(&source_with(
            SHIPPED,
            file,
            &[("alice", 1001), ("alicia", 1001), ("operator", 1001)],
        ));
        let moved = source_with(SHIPPED, file, &[("alice", 1002), ("operator", 1001)]);
        assert_eq!(moved.unresolved_adversaries(), ["alicia"]);
        let next = snapshot_over(&moved, LABEL, test_digest, Some(first.persisted())).unwrap();
        let a =
            BasicAuthorizer::from_snapshot(principal(), paths(), test_digest, Arc::clone(&next));
        for uid in [1001, 1002] {
            assert_eq!(
                a.decide_reporting_role(&liveness_req(Some(uid))),
                (
                    Verdict::Deny {
                        reason: CONTAINED.into()
                    },
                    Some("adversary")
                ),
                "uid {uid}"
            );
        }
        assert_eq!(
            next.identity_problems().as_ref(),
            [IdentityProblem::CarriedForward {
                uid: 1001,
                name: "alicia".into(),
                overrides: vec![("operator".into(), "admin")]
            }]
        );
        assert_eq!(
            next.subject_entries().unwrap(),
            [
                crate::ListedSubject {
                    uid: Some(1001),
                    names: vec!["alicia".into(), "operator".into()],
                    state: crate::SubjectState::CarriedForward,
                },
                crate::ListedSubject {
                    uid: Some(1002),
                    names: vec!["alice".into()],
                    state: crate::SubjectState::Contained,
                },
            ]
        );
        let again = snapshot_over(&moved, LABEL, test_digest, Some(next.persisted())).unwrap();
        assert!(
            Arc::ptr_eq(again.persisted(), next.persisted()),
            "idempotent"
        );
    }

    #[test]
    fn a_uid_two_aliases_claim_is_released_only_when_neither_claims_it() {
        let both = Some("schema_version: 1\nbindings:\n  adversary: [alice, alicia]\n");
        let first = compiled(&source_with(
            SHIPPED,
            both,
            &[("alice", 1001), ("alicia", 1001)],
        ));
        assert_eq!(
            first.subject_entries().unwrap(),
            [crate::ListedSubject {
                uid: Some(1001),
                names: vec!["alice".into(), "alicia".into()],
                state: crate::SubjectState::Contained,
            }]
        );
        let held = source_with(SHIPPED, both, &[("alice", 1001)]);
        let next = snapshot_over(&held, LABEL, test_digest, Some(first.persisted())).unwrap();
        assert_eq!(
            next.identity_problems().as_ref(),
            [IdentityProblem::CarriedForward {
                uid: 1001,
                name: "alicia".into(),
                overrides: vec![]
            }]
        );
        let alice_gone = source_with(
            SHIPPED,
            Some("schema_version: 1\nbindings:\n  adversary: [alicia]\n"),
            &[],
        );
        let still = snapshot_over(&alice_gone, LABEL, test_digest, Some(next.persisted())).unwrap();
        let a = BasicAuthorizer::from_snapshot(principal(), paths(), test_digest, still);
        assert_eq!(
            a.decide_reporting_role(&liveness_req(Some(1001))).1,
            Some("adversary"),
            "alicia still claims 1001"
        );
        let elsewhere = source_with(SHIPPED, both, &[("alice", 1002), ("alicia", 1003)]);
        let after = snapshot_over(&elsewhere, LABEL, test_digest, Some(next.persisted())).unwrap();
        let b = BasicAuthorizer::from_snapshot(principal(), paths(), test_digest, after);
        assert_eq!(
            b.decide_reporting_role(&liveness_req(Some(1001))).1,
            None,
            "no listed name claims 1001"
        );
    }

    #[test]
    fn a_missing_file_over_explicit_bindings_refuses_the_hermetic_reload() {
        let explicit = compiled(&source_with(
            SHIPPED,
            Some("schema_version: 1\nbindings: {}\n"),
            &[],
        ));
        let gone = source_with(SHIPPED, None, &[]);
        match snapshot_over(&gone, LABEL, test_digest, Some(explicit.persisted())) {
            Err(AuthzBasicError::Compile(snapshot::CompileError::Identity(m))) => {
                assert_eq!(m, maknae_graph::identity::BINDINGS_MISSING)
            }
            other => panic!("expected the missing-file refusal, got {other:?}"),
        }
        let absent = source_with(SHIPPED, Some("schema_version: 1\n"), &[]);
        assert!(
            snapshot_over(&absent, LABEL, test_digest, Some(explicit.persisted())).is_ok(),
            "root's keyless edit is allowed"
        );
        let bare = compiled(&source_with(SHIPPED, Some("schema_version: 1\n"), &[]));
        assert!(
            snapshot_over(&gone, LABEL, test_digest, Some(bare.persisted())).is_ok(),
            "nothing explicit to drop"
        );
    }

    #[test]
    fn a_layer_from_authz_yaml_refuses_until_the_block_is_pasted() {
        let set = maknae_graph::kernel::persisted_compiled_set(LABEL);
        let old = Arc::new(
            maknae_graph::identity::build(
                &maknae_graph::identity::IdentityLayer {
                    aliases: Default::default(),
                    source: PATH.into(),
                    label: LABEL.into(),
                    bindings_sha256: Some([7; 32]),
                    subjects: vec![maknae_graph::identity::SubjectEntry {
                        uid: 666,
                        name: "mallory".into(),
                        role: "adversary".into(),
                    }],
                },
                None,
                &set,
                test_digest(&set.canonical_bytes().unwrap()),
                1,
                maknae_graph::record::ProvenanceKind::Seed,
            )
            .unwrap(),
        );
        let shipped = source_with(SHIPPED, Some("schema_version: 1\n"), &[]);
        assert_eq!(shipped.policy_source(), PATH);
        match snapshot_over(&shipped, LABEL, test_digest, Some(&old)) {
            Err(AuthzBasicError::Compile(snapshot::CompileError::Identity(m))) => {
                assert_eq!(m, maknae_graph::identity::BINDINGS_NOT_MOVED)
            }
            other => panic!("expected the not-moved refusal, got {other:?}"),
        }
        let pasted = source_with(
            SHIPPED,
            Some("schema_version: 1\nbindings:\n  adversary: [mallory]\n"),
            &[("mallory", 666)],
        );
        let next = snapshot_over(&pasted, LABEL, test_digest, Some(&old)).unwrap();
        assert_eq!(next.revision(), 2);
        let a = BasicAuthorizer::from_snapshot(principal(), paths(), test_digest, next);
        assert_eq!(
            a.decide_reporting_role(&liveness_req(Some(666))).1,
            Some("adversary")
        );
    }

    #[test]
    fn a_rebuild_over_a_graph_carrying_a_baseline_keeps_it() {
        let set = maknae_graph::kernel::persisted_compiled_set(LABEL);
        let baseline = maknae_graph::baseline::BaselineLayer {
            sections: [("core".to_string(), r#"{"deployment_id":"d"}"#.to_string())]
                .into_iter()
                .collect(),
            system: "US".into(),
            ceiling: "UNCLASSIFIED".into(),
            sha256: [3; 32],
            moved_from: Some("/var/log/maknae/old.jsonl".into()),
        };
        let old = Arc::new(
            maknae_graph::identity::build(
                &maknae_graph::identity::IdentityLayer {
                    aliases: Default::default(),
                    source: PATH.into(),
                    label: LABEL.into(),
                    bindings_sha256: Some([7; 32]),
                    subjects: vec![],
                },
                Some(&baseline),
                &set,
                test_digest(&set.canonical_bytes().unwrap()),
                1,
                maknae_graph::record::ProvenanceKind::Seed,
            )
            .unwrap(),
        );
        let edited = source_with(SHIPPED, Some("schema_version: 1\nbindings: {}\n"), &[]);
        let next = snapshot_over(&edited, LABEL, test_digest, Some(&old)).unwrap();
        assert_eq!(next.revision(), 2);
        let kept = maknae_graph::identity::extract(next.persisted()).unwrap();
        assert_eq!(kept.baseline, Some(baseline));
    }

    #[test]
    fn unresolved_adversaries_are_the_adversary_names_that_did_not_resolve() {
        let src = source_with(
            SHIPPED,
            Some("schema_version: 1\nbindings:\n  user: [ghost]\n  adversary: [eve, mallory, trudy]\n"),
            &[("mallory", 666)],
        );
        assert_eq!(src.unresolved_adversaries(), ["eve", "trudy"]);
        assert!(source_with(SHIPPED, None, &[])
            .unresolved_adversaries()
            .is_empty());
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
    fn finish_resolves_root_validates_eagerly_and_reports_an_unresolvable_name() {
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
        )
        .expect("an unresolvable name leaves only that subject unbound");
        assert_eq!(
            ghost.identity_problems(),
            [IdentityProblem::Unresolved {
                role: "user",
                name: "no-such-user-maknae-85".into()
            }]
        );
        assert_eq!(
            tests::oracle::assemble(&ghost).err(),
            Some(tests::oracle::Refused::Bindings(
                tests::oracle::BindingError::Unresolvable("no-such-user-maknae-85".into())
            )),
            "before #496 the whole file refused"
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

    #[test]
    fn the_baseline_terms_are_not_grantable_to_user() {
        for term in ["admin.baseline.show", "admin.baseline.accept"] {
            let got = finish(parse_with_roles(&format!(
                "roles:\n  user:\n    allow: [\"{term}\"]\n"
            )));
            assert!(
                matches!(got, Err(AuthzBasicError::TermNotGrantableForRole { ref role, term: ref t }) if role == "user" && t == term),
                "{term}: {got:?}"
            );
        }
        assert!(finish(parse_with_roles(
            "roles:\n  admin:\n    allow: [\"admin.baseline.show\", \"admin.baseline.accept\"]\n"
        ))
        .is_ok());
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
            (BindingError::Duplicate("n".into()), "twice"),
            (
                BindingError::UidOutsideAdversary("r".into()),
                "adversary only",
            ),
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
        assert_eq!(keys, ["bindings", "permissions", "roles", "schema_version"]);
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
    fn a_missing_account_is_per_subject_and_a_failed_lookup_refuses() {
        use nix::errno::Errno;
        assert_eq!(classify_lookup(Ok(Some(7))), Lookup::Found(7));
        for absent in [
            Ok(None),
            Err(Errno::ENOENT),
            Err(Errno::ESRCH),
            Err(Errno::EBADF),
            Err(Errno::EPERM),
        ] {
            assert_eq!(classify_lookup(absent), Lookup::Absent, "{absent:?}");
        }
        for failed in [
            Errno::UnknownErrno,
            Errno::ERANGE,
            Errno::EIO,
            Errno::EMFILE,
            Errno::ENFILE,
            Errno::ENOMEM,
            Errno::EINTR,
        ] {
            assert_eq!(
                classify_lookup(Err(failed)),
                Lookup::Failed(failed as i32),
                "{failed:?}"
            );
        }
    }

    #[test]
    fn a_failed_lookup_refuses_and_a_missing_account_does_not() {
        let b = maknae_config::parse_bindings(
            "schema_version: 1\nbindings:\n  admin: [alex]\n  user: [ghost, alex]\n  adversary: [mallory, {uid: 9}]\n",
        )
        .unwrap();
        let calls = std::cell::RefCell::new(Vec::new());
        let map = resolve_uid_map_with(&b, |n| {
            calls.borrow_mut().push(n.to_string());
            match n {
                "alex" => Lookup::Found(1000),
                "mallory" => Lookup::Found(666),
                _ => Lookup::Absent,
            }
        })
        .unwrap();
        assert_eq!(
            map,
            [("alex".to_string(), 1000), ("mallory".to_string(), 666)]
                .into_iter()
                .collect()
        );
        assert_eq!(
            *calls.borrow(),
            ["alex", "mallory", "ghost"],
            "each name once; uid entries are never looked up"
        );
        let e = resolve_uid_map_with(&b, |n| {
            if n == "mallory" {
                Lookup::Failed(5)
            } else {
                Lookup::Absent
            }
        })
        .unwrap_err();
        assert_eq!(
            e,
            AuthzBasicError::Bindings(
                "looking up 'mallory' failed (errno 5); nothing was changed".into()
            )
        );
        assert_eq!(
            resolve_uid_map_with(&maknae_config::Bindings::missing(), |_| {
                Lookup::Failed(5)
            }),
            Ok(UidMap::new())
        );
    }

    #[test]
    fn the_host_lookup_resolves_root_and_reports_a_missing_name_as_absent() {
        assert_eq!(lookup_uid("root"), Lookup::Found(0));
        assert_eq!(lookup_uid("no-such-user-maknae-496"), Lookup::Absent);
    }

    /// Measured on macOS 26 (aarch64): a missing name is `Ok(None)`. `getpwnam_r` with a
    /// buffer too small for the record returns ERANGE and leaves errno as it was.
    #[test]
    #[ignore = "measurement: run with --ignored on each platform and record the output"]
    fn measure_the_lookup_of_a_name_with_no_account() {
        let raw = nix::unistd::User::from_name("no-such-user-maknae-496")
            .map(|u| u.map(|u| u.uid.as_raw()));
        println!(
            "from_name -> {raw:?}; classified {:?}",
            classify_lookup(raw)
        );
    }

    #[test]
    fn an_unresolvable_name_leaves_only_that_subject_unbound() {
        let s = source_with(
            SHIPPED,
            Some("schema_version: 1\nbindings:\n  admin: [alex]\n  user: [ghost]\n"),
            &[("alex", 1000)],
        );
        assert_eq!(
            s.identity_problems(),
            [IdentityProblem::Unresolved {
                role: "user",
                name: "ghost".into()
            }]
        );
        let snap = compiled(&s);
        assert_eq!(snap.identity_problems().as_ref(), s.identity_problems());
        let a = BasicAuthorizer::from_snapshot(principal(), paths(), test_digest, snap);
        assert_eq!(
            a.decide_reporting_role(&liveness_req(Some(1000))).1,
            Some("admin")
        );
        assert_eq!(
            a.decide_oracle(&s, &liveness_req(Some(1000))),
            (Verdict::Indeterminate, None),
            "before #496 the whole file refused"
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
                aliases: Default::default(),
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
        )
        .unwrap();
        assert_eq!(ghost.identity_problems()[0].names(), ["ghost"]);
        assert!(matches!(
            PolicySource::from_parts(
                parse("schema_version: 1\n"),
                bound("schema_version: 1\nbindings:\n  gest: [\"ghost\"]\n"),
                UidMap::new(),
                principal(),
                paths(),
            ),
            Err(AuthzBasicError::Bindings(ref m)) if m.contains("'gest'")
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
        use super::{
            arrives, audit_permit, contained, no_role, principal, whoami, CONTAINED, EMPTY,
        };
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
            assert_eq!(
                unresolvable.unwrap().identity_problems(),
                [IdentityProblem::Unresolved {
                    role: "user",
                    name: "no-such-user-maknae-489".into()
                }]
            );
            assert!(matches!(missing_authz, Err(AuthzBasicError::Load(_))));
            let absent = missing_bindings.expect("a missing bindings.yaml is bindings absent");
            assert!(absent.bindings().is_missing());
        }

        #[test]
        fn constructor_loads_and_reports_an_unresolvable_binding() {
            let fx = Fixture::new("bindfail");
            write(&fx.policy(), EMPTY);
            write(
                &fx.bindings(),
                "schema_version: 1\nbindings:\n  user: [\"no-such-user-maknae-77\"]\n",
            );
            let got = HermeticAuthorizer::new(fx.paths(), principal(), fixture_req(), test_digest)
                .unwrap();
            assert_eq!(
                got.snapshot().identity_problems()[0].names(),
                ["no-such-user-maknae-77"]
            );
            assert_eq!(got.decide_reporting_role(&whoami(501)).1, None);
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
                "schema_version: 1\nbindings:\n  adversary: [\"root\"]\n  user: [\"nobody-new-maknae-489\"]\n",
            );
            auth.reload_from_file().unwrap();
            assert_eq!(
                auth.snapshot().identity_problems()[0].names(),
                ["nobody-new-maknae-489"]
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
        fn an_installed_principal_is_admin_on_the_next_hermetic_decision_when_bindings_are_absent()
        {
            let fx = Fixture::new("principal");
            write(&fx.policy(), EMPTY);
            write(&fx.bindings(), "schema_version: 1\n");
            let auth = HermeticAuthorizer::new(fx.paths(), principal(), fixture_req(), test_digest)
                .unwrap();
            assert_eq!(auth.decide(&whoami(501)), audit_permit());
            let next = maknae_config::Principal {
                name: "b".into(),
                uid: 777,
            };
            let turn = auth.live_turn().try_take().unwrap();
            Baseline::install_principal(&auth, &turn, next.clone()).unwrap();
            drop(turn);
            assert_eq!(auth.decide(&whoami(501)), no_role());
            assert_eq!(auth.decide(&whoami(777)), audit_permit());
            assert_eq!(Baseline::principal(&auth), next);
            assert_eq!(
                Baseline::load_source(&auth).unwrap().principal(),
                &next,
                "a reload loads with the installed principal"
            );
            auth.reload_from_file().unwrap();
            assert_eq!(auth.decide(&whoami(777)), audit_permit());
            assert_eq!(auth.decide(&whoami(501)), no_role());
        }

        #[test]
        fn the_hermetic_baseline_delegates_to_its_inner_authorizer() {
            let fx = Fixture::new("baseline");
            let auth = fx.authorizer("admin");
            assert_eq!(Baseline::principal(&auth), principal());
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

        fn explicit_with(admin: &str, user: &str, guest: &str, adversary: &str) -> String {
            format!("schema_version: 1\nbindings: {{ admin: [{admin}], user: [{user}], guest: [{guest}], adversary: [{adversary}] }}\n")
        }

        /// `(variant, subject source, oracle source)`: each per-subject case is
        /// compared with the oracle over the file it is equivalent to.
        fn policies() -> Vec<(&'static str, PolicySource, PolicySource)> {
            let uids: &[(&str, u32)] = BASE_UIDS;
            let alias_uids: &[(&str, u32)] = &[BASE_UIDS, &[("gustav", 1002)]].concat();
            let same = |v: &'static str, src: PolicySource| (v, src.clone(), src);
            vec![
                same("absent", source_with(SHIPPED, None, &[])),
                same(
                    "absent-key",
                    source_with(SHIPPED, Some("schema_version: 1\n"), &[]),
                ),
                same(
                    "empty",
                    source_with(SHIPPED, Some("schema_version: 1\nbindings: {}\n"), &[]),
                ),
                same("explicit", source_with(SHIPPED, Some(EXPLICIT), uids)),
                same(
                    "explicit+grants",
                    source_with(
                        &format!("{}{GRANTS}", super::shipped_without_roles()),
                        Some(EXPLICIT),
                        uids,
                    ),
                ),
                same(
                    "explicit-no-match",
                    source_with(
                        SHIPPED,
                        Some("schema_version: 1\nbindings: { admin: [alex] }\n"),
                        uids,
                    ),
                ),
                same(
                    "adversary-by-uid",
                    source_with(
                        SHIPPED,
                        Some(&explicit_with("alex", "ursula", "gus", "{uid: 666}")),
                        uids,
                    ),
                ),
                (
                    "unresolved-name",
                    source_with(
                        SHIPPED,
                        Some(&explicit_with("alex", "ursula, ghost", "gus", "mallory")),
                        uids,
                    ),
                    source_with(SHIPPED, Some(EXPLICIT), uids),
                ),
                (
                    "overlap",
                    source_with(
                        SHIPPED,
                        Some(&explicit_with("alex, mallory", "ursula", "gus", "mallory")),
                        uids,
                    ),
                    source_with(SHIPPED, Some(EXPLICIT), uids),
                ),
                (
                    "conflict",
                    source_with(
                        SHIPPED,
                        Some(&explicit_with("alex", "ursula, gus", "gus", "mallory")),
                        uids,
                    ),
                    source_with(
                        SHIPPED,
                        Some(&explicit_with("alex", "ursula", "", "mallory")),
                        uids,
                    ),
                ),
                (
                    "alias",
                    source_with(
                        SHIPPED,
                        Some(&explicit_with("alex", "ursula, gustav", "gus", "mallory")),
                        alias_uids,
                    ),
                    source_with(
                        SHIPPED,
                        Some(&explicit_with("alex", "ursula", "", "mallory")),
                        alias_uids,
                    ),
                ),
            ]
        }

        #[test]
        fn the_policy_variants_are_pairwise_distinct() {
            let all = policies();
            let names: std::collections::BTreeSet<_> = all.iter().map(|p| p.0).collect();
            let sources: std::collections::BTreeSet<_> =
                all.iter().map(|p| format!("{:?}", p.1)).collect();
            assert_eq!((names.len(), sources.len()), (all.len(), all.len()));
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
            assert_eq!(terms.len(), 61);
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
                (61, 9, 22, 5, 7, 4)
            );
            let mut cells = 0usize;
            let mut mismatches: Vec<String> = Vec::new();
            let mut roles_seen = std::collections::BTreeSet::new();
            let mut arms: std::collections::BTreeMap<&'static str, Arms> = Default::default();
            let mut grant_arms = (false, false, false);
            for (variant, src, oracle_src) in policies() {
                let auth = BasicAuthorizer::from_snapshot(
                    principal(),
                    src.paths().clone(),
                    test_digest,
                    compiled(&src),
                );
                let mut check = |req: maknae_security::Request, cell: &dyn Fn() -> String| {
                    cells += 1;
                    let oracle = auth.decide_oracle(&oracle_src, &req);
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
            let other_cells = 56 + 4;
            assert_eq!(cells, 11 * 9 * (fs_cells + other_cells));
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
            for (variant, src, oracle_src) in policies() {
                let oracle = tests::oracle::assemble(&oracle_src)
                    .unwrap()
                    .roles
                    .as_subject_bindings();
                let snap = compiled(&src).subjects();
                assert_eq!(oracle, snap, "{variant}");
                seen.push(oracle.map(|v| v.len()));
            }
            assert_eq!(
                seen,
                [
                    None,
                    None,
                    Some(0),
                    Some(4),
                    Some(4),
                    Some(1),
                    Some(4),
                    Some(4),
                    Some(4),
                    Some(3),
                    Some(3)
                ]
            );
        }

        #[test]
        fn each_per_subject_case_is_a_verdict_change_from_the_whole_policy_refusal() {
            use tests::oracle::{BindingError, Refused};
            let uids: &[(&str, u32)] = &[BASE_UIDS, &[("gustav", 1002)]].concat();
            let names = |n: &[&str]| n.iter().map(|s| s.to_string()).collect::<Vec<_>>();
            for (variant, body, subject_uid, new_subject, refused, problem) in [
                (
                    "unresolved-name",
                    "admin: [alex]\n  user: [ursula, ghost]\n  adversary: [mallory]",
                    1001_i64,
                    Some("user"),
                    BindingError::Unresolvable("ghost".into()),
                    IdentityProblem::Unresolved {
                        role: "user",
                        name: "ghost".into(),
                    },
                ),
                (
                    "overlap",
                    "admin: [alex, mallory]\n  adversary: [mallory]",
                    666,
                    Some("adversary"),
                    BindingError::DualMembership("mallory".into()),
                    IdentityProblem::Contained {
                        uid: 666,
                        names: names(&["mallory"]),
                        roles: vec!["admin", "adversary"],
                    },
                ),
                (
                    "conflict",
                    "admin: [alex]\n  guest: [gus]\n  user: [gus]",
                    1002,
                    None,
                    BindingError::DualMembership("gus".into()),
                    IdentityProblem::Unbound {
                        uid: 1002,
                        names: names(&["gus"]),
                        roles: vec!["guest", "user"],
                    },
                ),
                (
                    "alias",
                    "admin: [alex]\n  guest: [gus]\n  user: [gustav]",
                    1002,
                    None,
                    BindingError::DuplicateUid {
                        uid: 1002,
                        names: ("gus".into(), "gustav".into()),
                    },
                    IdentityProblem::Unbound {
                        uid: 1002,
                        names: names(&["gus", "gustav"]),
                        roles: vec!["guest", "user"],
                    },
                ),
            ] {
                let src = source_with(
                    SHIPPED,
                    Some(&format!("schema_version: 1\nbindings:\n  {body}\n")),
                    uids,
                );
                let auth = BasicAuthorizer::from_snapshot(
                    principal(),
                    src.paths().clone(),
                    test_digest,
                    compiled(&src),
                );
                assert_eq!(
                    tests::oracle::assemble(&src).err(),
                    Some(Refused::Bindings(refused)),
                    "{variant}: before #496 the whole file refused"
                );
                assert_eq!(
                    auth.decide_oracle(&src, &whoami(1000)),
                    (Verdict::Indeterminate, None),
                    "{variant}"
                );
                assert_eq!(
                    auth.decide_reporting_role(&whoami(1000)).1,
                    Some("admin"),
                    "{variant}: the rest loads"
                );
                assert_eq!(
                    auth.decide_reporting_role(&whoami(subject_uid)).1,
                    new_subject,
                    "{variant}"
                );
                assert_eq!(src.identity_problems(), [problem], "{variant}");
            }
        }
    }
}
