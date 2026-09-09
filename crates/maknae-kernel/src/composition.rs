//! The authorization composition root (ADR-0008 decision 1; #154, #148).
//!
//! T1 — this is where "a vendor cannot relax our baselines" stops being a hope
//! and becomes an invariant. Two non-removable floors are NAMED FIELDS, never
//! elements of an operand vector:
//!
//! - `baseline` — the discretionary (RBAC) floor, [`Baseline`]-bounded. The
//!   trait is SEALED in `maknae-authz-basic`, so nothing outside that crate can
//!   satisfy the bound, and a `Composition` cannot be constructed without one.
//!   The absent state is not expressible. (ADR-0008 wrote the field as the
//!   concrete `BasicAuthorizer`; the sealed trait carries the same property
//!   and is additionally constructible off-root — see the trait's doc.)
//! - `ceiling` — the mandatory (MAC) floor: the booted ceiling in the booted
//!   classification SYSTEM (ADR-0022). ADR-0020 §3: mandatory operands are
//!   ALWAYS composed, never silently absent.
//!
//! **No `extensions` vector yet.** ADR-0008's struct shows one; the property
//! it names — baseline as a named field — holds with or without it, and an
//! always-empty vector plus a constructor nothing calls is a tested thing that
//! decides nothing. It arrives with the first extension, together with the
//! composed-vocabulary check (ADR-0008 decision 5 / amendment item 5), which
//! that extension owns.
//!
//! **Order is load-bearing.** The baseline is folded FIRST: `combine` rule 4
//! keeps the first annotated absence, so baseline testimony outranks (#181).
//!
//! **`combine` is not modified** (ADR-0008 decision 3). This type folds
//! through the same free functions [`ConjunctionAuthorizer`] uses, so the
//! panic boundary, the sanitize-once name rule and the exactly-one
//! enumeration rule are defined in one place, the seam.
//!
//! [`ConjunctionAuthorizer`]: maknae_security::ConjunctionAuthorizer

use crate::ceiling_authz::CeilingAuthorizer;
use maknae_authz_basic::Baseline;
use maknae_security::{
    compose_backend_name, compose_decide_reporting_role, compose_subjects, Authorizer, Request,
    SubjectBinding, Verdict,
};

/// The daemon's PDP: baseline ∧ ceiling, deny-overrides.
pub struct Composition<B: Baseline> {
    /// The non-removable discretionary floor. A named field, not a vector
    /// element: there is no way to build this type without one.
    baseline: B,
    /// The non-removable mandatory floor: the booted classification ceiling,
    /// evaluated on every request.
    ceiling: CeilingAuthorizer,
}

impl<B: Baseline> Composition<B> {
    pub fn new(baseline: B, ceiling: CeilingAuthorizer) -> Self {
        Self { baseline, ceiling }
    }

    /// Baseline FIRST — see the module doc.
    fn operands(&self) -> [&dyn Authorizer; 2] {
        [&self.baseline, &self.ceiling]
    }
}

/// Build the daemon's PDP from the BOOTED configuration and the gate's baseline.
///
/// Extracted from `run.rs` (T3, mutation-excluded) into this T1 file because
/// this is the one line on which the whole of #148 rests: the CONFIGURED
/// ceiling, in the CONFIGURED system, must be what the operand evaluates.
/// Critical-review round 4 of the prototype replaced `boot.ceiling().clone()`
/// with the baseline in `run.rs` and every gate stayed green and all kernel
/// tests passed — nothing observed the difference. Here it is a mutation
/// target, and the test below proves a `CONFIDENTIAL` boot yields an operand
/// that refuses SECRET-marked content, and an `AUS` boot ranks by PSPF.
pub fn build_pdp<B: Baseline>(boot: &crate::boot::BootConfig, baseline: B) -> Composition<B> {
    Composition::new(
        baseline,
        CeilingAuthorizer::new(boot.ceiling().clone(), boot.policy()),
    )
}

impl<B: Baseline> Authorizer for Composition<B> {
    fn decide(&self, req: &Request) -> Verdict {
        self.decide_reporting_role(req).0
    }

    /// The one decision path (#275). Folds through the seam's
    /// `compose_decide_reporting_role`, so `combine` and the panic boundary stay
    /// defined in one place and a future extensions operand is picked up by
    /// `operands()` automatically. `decide` is this function's `.0`, so every
    /// existing composition test still covers what production runs.
    fn decide_reporting_role(&self, req: &Request) -> (Verdict, Option<&'static str>) {
        compose_decide_reporting_role(&self.operands(), req)
    }

    fn subjects(&self) -> Option<Vec<SubjectBinding>> {
        compose_subjects(&self.operands())
    }

    fn backend_name(&self) -> String {
        compose_backend_name(&self.operands())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use maknae_authz_basic::HermeticAuthorizer;
    use maknae_config::{BasicPolicy, Ceiling, ClassificationPolicy, Principal};
    use maknae_security::{Action, AttrValue, Attributes, Context, Resource, Subject};
    use std::path::PathBuf;

    /// A real `-basic` through the hermetic door: same load → `finish_new` →
    /// per-request decide sequence as production, with only the loader's
    /// ownership requirement relaxed so an unprivileged test can construct it.
    struct DirGuard(PathBuf);

    impl Drop for DirGuard {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    /// Returns the guard SEPARATELY from the authorizer so the authorizer can
    /// be moved into a `Composition` while the guard still owns the cleanup.
    /// Mirrors `tests/enforce_loop.rs`'s `Fixture`: a CANONICAL 0700 home
    /// (#216 -- `$TMPDIR` is under the `/var` symlink on macOS), the enrolled
    /// principal IS the test euid, and bindings name `root` so the enrolled-
    /// principal default role resolution is what grants (boot_gate.rs).
    fn fixture(tag: &str, policy: &str) -> (DirGuard, HermeticAuthorizer) {
        use std::os::unix::fs::PermissionsExt;
        let dir =
            std::env::temp_dir().join(format!("maknae_composition_{tag}_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700)).unwrap();
        let dir = dir.canonicalize().expect("canonicalize the fixture home");
        let policy_path = dir.join("authz.yaml");
        std::fs::write(&policy_path, policy).unwrap();
        std::fs::set_permissions(&policy_path, std::fs::Permissions::from_mode(0o640)).unwrap();
        let principal = Principal {
            name: "operator".into(),
            uid: nix::unistd::geteuid().as_raw(),
            home: dir.clone(),
        };
        let req = maknae_config::TargetRequired {
            owner: None,
            mode_mask: Some(0o022),
            nlink_exactly_one: false,
            regular_file: true,
            max_bytes: None,
        };
        let basic =
            HermeticAuthorizer::new(policy_path, principal, req).expect("fixture constructs");
        (DirGuard(dir), basic)
    }

    /// A policy that grants `admin.status` to the admin role.
    fn status_policy() -> String {
        "schema_version: 1\npermissions:\n  allow: []\n  deny: []\nbindings:\n  admin: [\"root\"]\nroles:\n  admin:\n    allow: [\"admin.status\"]\n".to_string()
    }

    const US: &BasicPolicy = &BasicPolicy;

    fn secret() -> Ceiling {
        let mut c = Ceiling::baseline_for(US);
        c.classification = US.level_of("SECRET").unwrap();
        c
    }

    fn ceiling(c: Ceiling) -> CeilingAuthorizer {
        CeilingAuthorizer::new(c, US)
    }

    fn request(action: &str) -> Request {
        let mut subject = Attributes::new();
        // uid 0: the fixture binds `root` to admin, exactly as enforce_loop's
        // status test drives as peer_uid 0. A CLAIMED attribute here -- this is
        // a unit test of the fold, not of the daemon door that stamps uids.
        subject.insert("uid", AttrValue::Int(0));
        let mut context = Attributes::new();
        context.insert(
            maknae_security::CONTEXT_DAC_LANE,
            AttrValue::Str(maknae_security::Lane::Local.as_str().to_string()),
        );
        Request {
            subject: Subject(subject),
            resource: Resource(Attributes::new()),
            action: Action(action.into()),
            context: Context(context),
        }
    }

    #[test]
    fn the_composed_name_lists_baseline_then_ceiling() {
        let (_g, basic) = fixture("name", &status_policy());
        let c = Composition::new(basic, ceiling(Ceiling::baseline_for(US)));
        assert_eq!(c.backend_name(), "maknae-authz-basic+maknae-ceiling");
        // And through the kernel's choke point, sanitized once.
        assert_eq!(
            maknae_security::guarded_backend_name(&c),
            "maknae-authz-basic+maknae-ceiling"
        );
    }

    #[test]
    fn a_control_plane_grant_survives_an_above_baseline_ceiling() {
        // Diagnosability: admin.status still answers under SECRET.
        let (_g, basic) = fixture("status-secret", &status_policy());
        let c = Composition::new(basic, ceiling(secret()));
        let v = c.decide(&request("admin.status"));
        assert!(
            matches!(v, Verdict::Permit { .. }),
            "the ceiling must abstain on control plane; got {v:?}"
        );
    }

    /// A read the baseline PERMITS: a real `Read(~/**)` grant for the enrolled
    /// principal, a path under its home, and the OS's answer stamped `true`
    /// (exactly what `build_authz_request` stamps after `verify_delegated`).
    fn permitted_read(home: &std::path::Path) -> Request {
        permitted_read_marked(home, None)
    }

    /// The same read, with a classification MARKING stamped the way a future
    /// labeler would (trust-plane side, never client-supplied).
    fn permitted_read_marked(home: &std::path::Path, marking: Option<&str>) -> Request {
        let mut subject = Attributes::new();
        subject.insert(
            "uid",
            AttrValue::Int(i64::from(nix::unistd::geteuid().as_raw())),
        );
        let mut resource = Attributes::new();
        resource.insert(
            "path",
            AttrValue::Str(home.join("notes.txt").display().to_string()),
        );
        resource.insert(
            maknae_security::RESOURCE_OS_ACCESSIBLE,
            AttrValue::Bool(true),
        );
        if let Some(m) = marking {
            resource.insert(
                maknae_security::RESOURCE_CLASSIFICATION,
                AttrValue::Str(m.into()),
            );
        }
        let mut context = Attributes::new();
        context.insert(
            maknae_security::CONTEXT_DAC_LANE,
            AttrValue::Str(maknae_security::Lane::Local.as_str().to_string()),
        );
        Request {
            subject: Subject(subject),
            resource: Resource(resource),
            action: Action("fs.read".into()),
            context: Context(context),
        }
    }

    const READ_POLICY: &str =
        "schema_version: 1\npermissions:\n  allow:\n    - \"Read(~/**)\"\n  deny: []\n";

    #[test]
    fn a_mandatory_deny_is_not_waivable_by_a_baseline_permit() {
        // ADR-0020 decision 4, asserted rather than assumed: the baseline
        // GRANTS this read (proved alone first), the content is marked ABOVE
        // the declared ceiling, and the ceiling's Deny wins the fold. No role,
        // no grant, lifts a mandatory refusal.
        let (g, basic) = fixture("mac-wins", READ_POLICY);
        let req = permitted_read_marked(&g.0, Some("TOP SECRET"));
        assert!(
            matches!(basic.decide(&req), Verdict::Permit { .. }),
            "premise: the baseline alone must PERMIT this read, got {:?}",
            basic.decide(&req)
        );
        let c = Composition::new(basic, ceiling(secret()));
        match c.decide(&req) {
            Verdict::Deny { reason } => assert_eq!(
                reason,
                "ceiling: content marked TOP SECRET exceeds the declared ceiling SECRET"
            ),
            other => panic!("expected the ceiling's Deny over a baseline Permit, got {other:?}"),
        }
    }

    #[test]
    fn unmarked_content_flows_under_a_secret_ceiling_exactly_as_the_baseline_decides() {
        // The operator's ruling, at the composition: unmarked is the system's lowest level,
        // so a SECRET deployment serves it -- the composed verdict is the
        // baseline's, note and all.
        let (g, basic) = fixture("secret-identity", READ_POLICY);
        let req = permitted_read(&g.0);
        let alone = basic.decide(&req);
        assert!(matches!(alone, Verdict::Permit { .. }));
        let c = Composition::new(basic, ceiling(secret()));
        assert_eq!(c.decide(&req), alone);
    }

    #[test]
    fn a_ceiling_deny_reaches_the_top_past_an_abstaining_baseline() {
        // The other fold shape: -basic has no rule for `session.prompt`
        // (NotApplicable, with testimony), the content is marked above the
        // ceiling, and the ceiling denies. Rule 1 takes the Deny.
        let (_g, basic) = fixture("abstain-deny", &status_policy());
        let c = Composition::new(basic, ceiling(secret()));
        let mut r = request("session.prompt");
        r.resource.0.insert(
            maknae_security::RESOURCE_CLASSIFICATION,
            AttrValue::Str("TOP SECRET".into()),
        );
        match c.decide(&r) {
            Verdict::Deny { reason } => assert!(reason.starts_with("ceiling: "), "{reason}"),
            other => panic!("expected the ceiling's Deny, got {other:?}"),
        }
    }

    #[test]
    fn at_baseline_the_ceiling_changes_nothing_the_baseline_decided() {
        // The identity property: with the ceiling abstaining, the composed
        // verdict IS the baseline's verdict, note and all.
        let (_g, basic) = fixture("identity", &status_policy());
        let alone = basic.decide(&request("fs.read"));
        let c = Composition::new(basic, ceiling(Ceiling::baseline_for(US)));
        assert_eq!(c.decide(&request("fs.read")), alone);
    }

    /// THE wiring test. A minimal config directory whose `core.handling`
    /// declares SECRET is booted for real through `crate::boot::boot`, and the
    /// PDP built from it must refuse an unlabeled content read -- while the
    /// same build over a baseline config must be the identity. Round 4 of
    /// review showed that without this, `Ceiling::baseline()` in place of the
    /// booted ceiling was invisible to every gate and test.
    #[test]
    fn build_pdp_evaluates_the_ceiling_that_was_actually_booted() {
        fn booted(tag: &str, core: &str) -> crate::boot::BootConfig {
            let dir =
                std::env::temp_dir().join(format!("maknae_build_pdp_{tag}_{}", std::process::id()));
            use std::os::unix::fs::PermissionsExt;
            let _ = std::fs::remove_dir_all(&dir);
            std::fs::create_dir_all(&dir).unwrap();
            // The hardened loader refuses a config directory that is group- or
            // world-accessible (InsecurePermissions on 0755); mirror run.rs's
            // boot fixtures: 0700 directory, 0640 file.
            std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700)).unwrap();
            std::fs::write(dir.join("maknae.yaml"), core).unwrap();
            std::fs::set_permissions(
                dir.join("maknae.yaml"),
                std::fs::Permissions::from_mode(0o640),
            )
            .unwrap();
            let b = crate::boot::boot(&dir).expect("minimal config boots");
            let _ = std::fs::remove_dir_all(&dir);
            b
        }
        const CONFIDENTIAL_CORE: &str = "core:\n  handling:\n    ceiling:\n      classification: CONFIDENTIAL\n      sci: false\n      releasable_to: []\n      cui_permitted: false\n      cui_categories_permitted: []\n      dissemination_permitted: [\"Distribution Statement A\"]\n    accreditation_ref: null\n";
        const BASELINE_CORE: &str = "core: {}\n";

        // A CONFIDENTIAL boot: SECRET-marked content is refused naming the
        // BOOTED ceiling; unmarked content flows exactly as the baseline says.
        let (g, basic) = fixture("build-pdp-confidential", READ_POLICY);
        let marked = permitted_read_marked(&g.0, Some("SECRET"));
        let unmarked = permitted_read(&g.0);
        assert!(
            matches!(basic.decide(&marked), Verdict::Permit { .. }),
            "premise"
        );
        let alone_unmarked = basic.decide(&unmarked);
        let pdp = build_pdp(&booted("confidential", CONFIDENTIAL_CORE), basic);
        match pdp.decide(&marked) {
            Verdict::Deny { reason } => assert_eq!(
                reason, "ceiling: content marked SECRET exceeds the declared ceiling CONFIDENTIAL",
                "the BOOTED ceiling must be the one refused on"
            ),
            other => panic!("a CONFIDENTIAL boot must refuse SECRET-marked content, got {other:?}"),
        }
        assert_eq!(pdp.decide(&unmarked), alone_unmarked, "unmarked flows");

        // A baseline boot: even CONFIDENTIAL-marked content is spillage.
        let (g2, basic2) = fixture("build-pdp-baseline", READ_POLICY);
        let marked2 = permitted_read_marked(&g2.0, Some("CONFIDENTIAL"));
        let pdp2 = build_pdp(&booted("baseline", BASELINE_CORE), basic2);
        assert!(
            matches!(pdp2.decide(&marked2), Verdict::Deny { .. }),
            "spillage onto UNCLASSIFIED"
        );

        // An AUS boot (ADR-0022): the operand ranks by PSPF. OFFICIAL: Sensitive
        // flows under PROTECTED; SECRET is spillage; a US-only level is refused
        // BY NAME, never mapped.
        const AUS_PROTECTED_CORE: &str = "core:\n  handling:\n    ceiling:\n      classification: PROTECTED\n      sci: false\n      releasable_to: []\n      cui_permitted: false\n      cui_categories_permitted: []\n      dissemination_permitted: [\"Distribution Statement A\"]\n    accreditation_ref: null\n    policy: AUS\n";
        let (g3, basic3) = fixture("build-pdp-aus", READ_POLICY);
        let pdp3 = build_pdp(&booted("aus", AUS_PROTECTED_CORE), basic3);
        assert_eq!(pdp3.backend_name(), "maknae-authz-basic+maknae-ceiling");
        assert!(
            matches!(
                pdp3.decide(&permitted_read_marked(
                    &g3.0,
                    Some("official: sensitive//AGAO")
                )),
                Verdict::Permit { .. }
            ),
            "OFFICIAL: Sensitive flows under PROTECTED"
        );
        match pdp3.decide(&permitted_read_marked(&g3.0, Some("SECRET"))) {
            Verdict::Deny { reason } => assert_eq!(
                reason,
                "ceiling: content marked SECRET exceeds the declared ceiling PROTECTED"
            ),
            other => panic!("expected the PSPF refusal, got {other:?}"),
        }
        match pdp3.decide(&permitted_read_marked(&g3.0, Some("CONFIDENTIAL"))) {
            Verdict::Deny { reason } => {
                assert_eq!(
                    reason,
                    "ceiling: marking is a level of the US system, not AUS"
                )
            }
            other => panic!("expected the cross-system refusal, got {other:?}"),
        }
    }

    #[test]
    fn subjects_are_the_baselines_because_only_it_enumerates() {
        let (_g, basic) = fixture("subjects", &status_policy());
        let alone = basic.subjects();
        assert!(alone.is_some(), "the hermetic baseline enumerates");
        let c = Composition::new(basic, ceiling(secret()));
        assert_eq!(c.subjects(), alone);
    }
}
