//! maknae-authz-basic — the RBAC PDP backend behind the `maknae-security`
//! seam (#85). Four code-defined roles (`admin`/`user`/`guest`/`adversary`)
//! decide four-valued verdicts from `authz.yaml` (+ the additive `bindings:`
//! key), per request, deny-by-default, fail-closed. Spec:
//! `~/claude-memory/maknae/specs/2026-08-26-maknae-authz-basic-design.md`.
//!
//! Composition: `maknaed` constructs [`BasicAuthorizer`] and hands it to the
//! seam (#77 wires the boot gate and the per-request call site; bindings are
//! inert until then). The seam stays policy-agnostic (ADR-0004).
#![forbid(unsafe_code)]

mod binding;
mod decide;
mod role;

use binding::UidMap;
use decide::LoadedPolicy;
use std::path::{Path, PathBuf};

/// Subject attribute key for the authenticated uid (pinned for #77; ADR-0018:
/// the per-request authorization principal is the uid, from peer-cred).
pub const SUBJECT_UID_KEY: &str = decide::SUBJECT_UID;
/// Subject attribute key for the reserved runtime-subject token `agent` —
/// stamped by the daemon door on runtime-originated requests, never
/// client-settable (spec §3b/§6).
pub const SUBJECT_NAME_KEY: &str = decide::SUBJECT_NAME;
/// Resource attribute key carrying the (already-resolved) filesystem path for
/// `acp.fs.*` actions (spec §4.4).
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
}

impl std::fmt::Display for AuthzBasicError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AuthzBasicError::Load(m) => write!(f, "authz policy load refused: {m}"),
            AuthzBasicError::Bindings(m) => write!(f, "authz bindings invalid: {m}"),
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
    fn decide_with_loader(
        &self,
        req: &maknae_security::Request,
        loader: impl Fn(&Path) -> Result<maknae_config::AuthzPolicy, maknae_config::AuthzError>,
    ) -> maknae_security::Verdict {
        let Ok(policy) = loader(&self.policy_path) else {
            return maknae_security::Verdict::Indeterminate;
        };
        match assemble(policy, &self.uid_map) {
            Ok(lp) => decide::decide_loaded(&lp, &self.principal, req),
            Err(()) => maknae_security::Verdict::Indeterminate,
        }
    }
}

/// policy → LoadedPolicy under a uid map; any invalidity → Err (the caller
/// maps it to `Indeterminate`).
fn assemble(policy: maknae_config::AuthzPolicy, uid_map: &UidMap) -> Result<LoadedPolicy, ()> {
    let roles = binding::resolve(&policy.bindings, uid_map).map_err(|_| ())?;
    Ok(LoadedPolicy { policy, roles })
}

/// getpwnam every bound username once (the reserved `agent` token excluded).
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
            if name == binding::AGENT_SUBJECT || map.contains_key(name) {
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
    /// Per-request: re-read the policy file (Zero Trust — a binding edit
    /// bites on the next request), then run the pure core. ANY load/parse/
    /// validation failure → `Indeterminate` (finalize turns it into deny).
    fn decide(&self, req: &maknae_security::Request) -> maknae_security::Verdict {
        let home = self.principal.home.clone();
        self.decide_with_loader(req, move |p| maknae_config::load_authz(p, Some(&home)))
    }
}

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
        let policy = maknae_config::load_authz_with_requirement(
            &policy_path,
            req.clone(),
            Some(&principal.home),
        )
        .map_err(|e| AuthzBasicError::Load(e.to_string()))?;
        let inner = BasicAuthorizer::finish_new(policy_path, principal, policy)?;
        Ok(Self { inner, req })
    }
}

#[cfg(all(unix, feature = "hermetic-test-seam"))]
impl maknae_security::Authorizer for HermeticAuthorizer {
    fn decide(&self, r: &maknae_security::Request) -> maknae_security::Verdict {
        let req = self.req.clone();
        let home = self.inner.principal.home.clone();
        self.inner.decide_with_loader(r, move |p| {
            maknae_config::load_authz_with_requirement(p, req.clone(), Some(&home))
        })
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

    fn liveness_req(name: Option<&str>, uid: Option<i64>) -> maknae_security::Request {
        let mut s = Attributes::new();
        if let Some(n) = name {
            s.insert(SUBJECT_NAME_KEY, AttrValue::Str(n.into()));
        }
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
        };
        // Enrolled uid → admin: admin verb permitted; deny-list still denies.
        let admin_whoami = decide::decide_loaded(&lp, &principal(), &{
            let mut r = liveness_req(None, Some(501));
            r.action = Action("admin.whoami".into());
            r
        });
        assert!(matches!(admin_whoami, Verdict::Permit { .. }));
        let mut fs_req = liveness_req(None, Some(501));
        fs_req.action = Action("acp.fs.read".into());
        fs_req.resource.0.insert(
            RESOURCE_PATH_KEY,
            AttrValue::Str("/home/operator/.ssh/id_rsa".into()),
        );
        assert!(matches!(
            decide::decide_loaded(&lp, &principal(), &fs_req),
            Verdict::Deny { .. }
        ));
        // Agent name → user: liveness yes, admin verb no.
        assert!(matches!(
            decide::decide_loaded(&lp, &principal(), &liveness_req(Some("agent"), None)),
            Verdict::Permit { .. }
        ));
        let mut agent_admin = liveness_req(Some("agent"), None);
        agent_admin.action = Action("admin.whoami".into());
        assert_eq!(
            decide::decide_loaded(&lp, &principal(), &agent_admin),
            Verdict::NotApplicable
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
                    "schema_version: 1\npermissions:\n  allow: []\n  deny: []\nbindings:\n  {bindings_role}: [\"agent\"]\n"
                ),
            )
            .unwrap();
            std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o640)).unwrap();
        };
        write("user");
        let auth = BasicAuthorizer {
            policy_path: p.clone(),
            principal: principal(),
            uid_map: UidMap::new(),
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
        let before = auth.decide_with_loader(&liveness_req(Some("agent"), None), seam_loader);
        assert!(matches!(before, Verdict::Permit { .. }), "{before:?}");

        // Containment: root (here: the test) rewrites the binding. No
        // restart, no new authorizer — the very next request must deny.
        write("adversary");
        let after = auth.decide_with_loader(&liveness_req(Some("agent"), None), seam_loader);
        assert!(
            matches!(after, Verdict::Deny { ref reason } if reason.contains("role=adversary")),
            "{after:?}"
        );

        // And a garbage file mid-flight → Indeterminate (fail-closed).
        std::fs::write(&p, "not: [valid").unwrap();
        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o640)).unwrap();
        let garbage = auth.decide_with_loader(&liveness_req(Some("agent"), None), seam_loader);
        assert_eq!(garbage, Verdict::Indeterminate);
        // A brand-new username edited in after construction: Indeterminate
        // until restart (spec §3 resolution model).
        std::fs::write(
            &p,
            "schema_version: 1\npermissions:\n  allow: []\n  deny: []\nbindings:\n  user: [\"nobody-new\"]\n",
        )
        .unwrap();
        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o640)).unwrap();
        let new_name = auth.decide_with_loader(&liveness_req(Some("agent"), None), seam_loader);
        assert_eq!(new_name, Verdict::Indeterminate);
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// finish_new (the post-load half of `new`) hermetically: eager
    /// validation + uid resolution over host-independent identities
    /// (`root` — uid 0 exists everywhere; the reserved `agent` token).
    #[test]
    fn finish_new_resolves_root_validates_eagerly_and_refuses_bad_bindings() {
        let ok_policy = maknae_config::parse_authz(
            "schema_version: 1\npermissions:\n  allow: []\n  deny: []\nbindings:\n  admin: [\"root\"]\n  user: [\"agent\"]\n",
            None,
        )
        .unwrap();
        let auth =
            BasicAuthorizer::finish_new("/nonexistent".into(), principal(), ok_policy).unwrap();
        assert_eq!(auth.uid_map.get("root"), Some(&0), "root resolves to uid 0");
        assert!(
            !auth.uid_map.contains_key("agent"),
            "reserved token never looked up"
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
        let v = auth.decide(&liveness_req(None, Some(501)));
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
}

/// In-crate killers for the feature-gated wrapper (`cargo mutants -p` runs
/// only in-package tests, so these — not the kernel e2e — are what kill the
/// wrapper's mutants when the mutation lane enables the feature).
#[cfg(all(test, unix, feature = "hermetic-test-seam"))]
mod hermetic_tests {
    use super::*;
    use maknae_security::{Action, AttrValue, Attributes, Authorizer, Context, Resource, Subject, Verdict};
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
