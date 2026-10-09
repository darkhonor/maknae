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

use std::sync::Arc;
use std::time::{Duration, Instant};

use crate::ceiling_authz::CeilingAuthorizer;
use maknae_authz_basic::Baseline;
use maknae_security::{
    compose_backend_name, compose_decide_cited, compose_decide_cited_all, compose_subjects,
    Authorizer, Decided, Request, SubjectBinding, Verdict,
};

/// The daemon's PDP: baseline ∧ ceiling, deny-overrides.
pub struct Composition<B: Baseline> {
    /// The non-removable discretionary floor. A named field, not a vector
    /// element: there is no way to build this type without one.
    baseline: B,
    /// The non-removable mandatory floor: the installed classification ceiling,
    /// evaluated on every request.
    ceiling: CeilingAuthorizer,
    /// The view and providers the request path serves; installed only in the live turn.
    live: Arc<crate::live::LiveConfig>,
}

impl<B: Baseline> Composition<B> {
    pub fn new(baseline: B, ceiling: CeilingAuthorizer) -> Self {
        Self {
            baseline,
            ceiling,
            live: Arc::new(crate::live::LiveConfig::new(Default::default(), None)),
        }
    }

    /// The booted view and providers, set before the composition is shared.
    pub fn with_live(mut self, live: crate::live::LiveConfig) -> Self {
        self.live = Arc::new(live);
        self
    }

    /// What the request path serves: the one `LiveConfig` [`crate::live::install`] installs into.
    pub fn live(&self) -> &Arc<crate::live::LiveConfig> {
        &self.live
    }

    /// The baseline operand, for the reload's snapshot swap.
    pub fn baseline(&self) -> &B {
        &self.baseline
    }

    pub fn ceiling(&self) -> &CeilingAuthorizer {
        &self.ceiling
    }

    #[cfg(feature = "hermetic-test-seam")]
    pub fn install_live(&self, values: crate::live::LiveValues) -> Result<(), String> {
        self.install_live_within(
            values,
            Instant::now() + crate::blocking_guard::BLOCKING_OPERATION_TIMEOUT,
        )
    }

    /// Polls for the turn rather than queueing on it, and never takes it at or after
    /// `deadline`, so an install that timed out has changed nothing and cannot land later.
    pub(crate) fn install_live_within(
        &self,
        values: crate::live::LiveValues,
        deadline: Instant,
    ) -> Result<(), String> {
        let turn = loop {
            if Instant::now() >= deadline {
                return Err(
                    "in-flight decisions held the live turn past the install deadline; nothing was installed"
                        .into(),
                );
            }
            match self.baseline.live_turn().try_take() {
                Some(turn) => break turn,
                None => std::thread::sleep(Duration::from_millis(1)),
            }
        };
        self.install_in(&turn, values)
    }

    fn install_in(
        &self,
        turn: &maknae_authz_basic::LiveTurn<'_>,
        values: crate::live::LiveValues,
    ) -> Result<(), String> {
        if !self.baseline.live_turn().holds(turn) {
            return Err("the live values are installed only in this composition's own turn".into());
        }
        self.ceiling.admits(&values.ceiling)?;
        self.baseline.install_principal(turn, values.principal)?;
        self.ceiling.install(turn, values.ceiling)?;
        self.live.install(turn, values.view, values.providers);
        Ok(())
    }

    /// Holds the turn as a decision in flight does.
    #[cfg(test)]
    pub(crate) fn hold_live_turn(&self) -> std::sync::RwLockReadGuard<'_, ()> {
        self.baseline.live_turn().share()
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

    fn decide_reporting_role(&self, req: &Request) -> (Verdict, Option<&'static str>) {
        self.decide_cited(req).into()
    }

    /// The one decision path (#275). Folds through the seam's
    /// `compose_decide_cited`, so `combine` and the panic boundary stay defined
    /// in one place and a future extensions operand is picked up by
    /// `operands()` automatically. `decide` and `decide_reporting_role` are its
    /// projections, so every existing composition test covers what production
    /// runs.
    fn decide_cited(&self, req: &Request) -> Decided {
        let _turn = self.baseline.live_turn().share();
        compose_decide_cited(&self.operands(), req)
    }

    fn decide_cited_all(&self, reqs: &[Request]) -> Vec<Decided> {
        let _turn = self.baseline.live_turn().share();
        compose_decide_cited_all(&self.operands(), reqs)
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
    use crate::test_fixtures::{fixture, permitted_read_marked, secret, READ_POLICY};
    use maknae_config::{BasicPolicy, Ceiling, ClassificationPolicy, Principal};
    use maknae_security::{Action, AttrValue, Attributes, Context, Resource, Subject};

    /// A policy that grants `admin.status` to the admin role.
    fn status_policy() -> String {
        "schema_version: 1\npermissions:\n  allow: []\n  deny: []\nroles:\n  admin:\n    allow: [\"admin.status\"]\n".to_string()
    }

    const ADMIN_ROOT: &str = "schema_version: 1\nbindings:\n  admin: [\"root\"]\n";

    const US: &BasicPolicy = &BasicPolicy;

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
        let (_g, basic) = fixture("name", &status_policy(), Some(ADMIN_ROOT));
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
        let (_g, basic) = fixture("status-secret", &status_policy(), Some(ADMIN_ROOT));
        let c = Composition::new(basic, ceiling(secret()));
        let v = c.decide(&request("admin.status"));
        assert!(
            matches!(v, Verdict::Permit { .. }),
            "the ceiling must abstain on control plane; got {v:?}"
        );
    }

    /// A read the baseline PERMITS: a real `Read(~/**)` grant, a path under the
    /// requester's home, prepared as a local read attempt.
    fn permitted_read(home: &std::path::Path) -> Request {
        permitted_read_marked(home, None)
    }

    #[test]
    fn a_mandatory_deny_is_not_waivable_by_a_baseline_permit() {
        // ADR-0020 decision 4, asserted rather than assumed: the baseline
        // GRANTS this read (proved alone first), the content is marked ABOVE
        // the declared ceiling, and the ceiling's Deny wins the fold. No role,
        // no grant, lifts a mandatory refusal.
        let (g, basic) = fixture("mac-wins", READ_POLICY, None);
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
    fn the_composition_cites_the_baselines_rule_only_when_its_verdict_stands() {
        use maknae_authz_basic::Baseline;
        let (g, basic) = fixture("cite", READ_POLICY, None);
        let held = basic.snapshot();
        let c = Composition::new(basic, ceiling(secret()));
        assert!(std::sync::Arc::ptr_eq(&c.baseline().snapshot(), &held));
        let flows = c.decide_cited(&permitted_read(&g.0));
        assert!(matches!(flows.verdict, Verdict::Permit { .. }), "{flows:?}");
        let rule = flows.rule.clone().expect("the baseline's allow rule");
        assert!(rule.section.ends_with("authz.yaml#permissions"), "{rule:?}");
        assert_eq!(
            c.decide_reporting_role(&permitted_read(&g.0)),
            (flows.verdict.clone(), flows.role)
        );
        assert_eq!(c.decide(&permitted_read(&g.0)), flows.verdict);
        let refused = c.decide_cited(&permitted_read_marked(&g.0, Some("TOP SECRET")));
        assert!(matches!(refused.verdict, Verdict::Deny { .. }));
        assert_eq!(
            refused.rule, None,
            "a ceiling Deny never cites the baseline's allow"
        );
        let batch = [
            permitted_read(&g.0),
            permitted_read_marked(&g.0, Some("TOP SECRET")),
        ];
        assert_eq!(c.decide_cited_all(&batch), vec![flows, refused]);
    }

    /// An install that lands between two of a batch's baseline evaluations
    /// does not reach the rest of the batch, through the production fold.
    #[test]
    fn the_composed_batch_decides_from_one_snapshot() {
        use maknae_authz_basic::{Baseline, EvaluationGate};
        let (g, mut basic) = fixture("batch", READ_POLICY, None);
        let gate = std::sync::Arc::new(EvaluationGate {
            arrived: std::sync::Barrier::new(2),
            release: std::sync::Barrier::new(2),
        });
        basic.park_evaluations(gate.clone());
        std::fs::write(
            g.0.join("authz.yaml"),
            READ_POLICY.replace("deny: []", "deny:\n    - \"Read(~/**)\""),
        )
        .unwrap();
        let next = basic.compile_from_file().unwrap();
        let c = std::sync::Arc::new(Composition::new(basic, ceiling(secret())));
        let arrives = || {
            let (tx, rx) = std::sync::mpsc::channel();
            let gate = gate.clone();
            std::thread::spawn(move || {
                gate.arrived.wait();
                let _ = tx.send(());
            });
            rx.recv_timeout(std::time::Duration::from_secs(5)).is_ok()
        };
        let batch = {
            let (c, home) = (c.clone(), g.0.clone());
            std::thread::spawn(move || {
                c.decide_cited_all(&[permitted_read(&home), permitted_read(&home)])
            })
        };
        assert!(arrives(), "the batch never reached evaluation");
        c.baseline().install(next.clone());
        gate.release.wait();
        assert!(arrives(), "the batch stopped after one evaluation");
        gate.release.wait();
        let all = batch.join().unwrap();
        assert_eq!(all.len(), 2);
        for d in all {
            assert!(matches!(d.verdict, Verdict::Permit { .. }), "{d:?}");
        }
        assert!(std::sync::Arc::ptr_eq(&c.baseline().snapshot(), &next));
        let probe = {
            let (c, home) = (c.clone(), g.0.clone());
            std::thread::spawn(move || c.decide(&permitted_read(&home)))
        };
        assert!(arrives(), "the probe never reached evaluation");
        gate.release.wait();
        let probed = probe.join().unwrap();
        assert!(matches!(probed, Verdict::Deny { .. }), "{probed:?}");
    }

    #[test]
    fn unmarked_content_flows_under_a_secret_ceiling_exactly_as_the_baseline_decides() {
        // The operator's ruling, at the composition: unmarked is the system's lowest level,
        // so a SECRET deployment serves it -- the composed verdict is the
        // baseline's, note and all.
        let (g, basic) = fixture("secret-identity", READ_POLICY, None);
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
        let (_g, basic) = fixture("abstain-deny", &status_policy(), Some(ADMIN_ROOT));
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
        let (_g, basic) = fixture("identity", &status_policy(), Some(ADMIN_ROOT));
        let alone = basic.decide(&request("fs.read"));
        let c = Composition::new(basic, ceiling(Ceiling::baseline_for(US)));
        assert_eq!(c.decide(&request("fs.read")), alone);
    }

    /// THE wiring test. A minimal config directory whose `core.handling`
    /// declares SECRET is booted for real through `crate::boot::assemble`, and the
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
            let b = crate::boot::read_files_as_owner(&dir)
                .and_then(crate::boot::assemble)
                .expect("minimal config boots");
            let _ = std::fs::remove_dir_all(&dir);
            b
        }
        const CONFIDENTIAL_CORE: &str = "core:\n  handling:\n    ceiling:\n      classification: CONFIDENTIAL\n      sci: false\n      releasable_to: []\n      cui_permitted: false\n      cui_categories_permitted: []\n      dissemination_permitted: [\"Distribution Statement A\"]\n    accreditation_ref: null\n";
        const BASELINE_CORE: &str = "core: {}\n";

        // A CONFIDENTIAL boot: SECRET-marked content is refused naming the
        // BOOTED ceiling; unmarked content flows exactly as the baseline says.
        let (g, basic) = fixture("build-pdp-confidential", READ_POLICY, None);
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
        let (g2, basic2) = fixture("build-pdp-baseline", READ_POLICY, None);
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
        let (g3, basic3) = fixture("build-pdp-aus", READ_POLICY, None);
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

    pub(crate) fn install<B: Baseline>(
        c: &Composition<B>,
        ceiling: Ceiling,
        principal: Principal,
    ) -> Result<(), String> {
        c.install_live_within(
            crate::live::LiveValues {
                ceiling,
                principal,
                view: Default::default(),
                providers: None,
            },
            Instant::now() + crate::blocking_guard::BLOCKING_OPERATION_TIMEOUT,
        )
    }

    fn enrolled(uid: u32) -> Principal {
        Principal {
            name: "operator".into(),
            uid,
        }
    }

    fn other_uid() -> u32 {
        nix::unistd::geteuid().as_raw().wrapping_add(1)
    }

    #[test]
    fn an_installed_live_baseline_governs_the_next_decision_through_both_operands() {
        let (g, basic) = fixture("live-install", READ_POLICY, None);
        let c = Composition::new(basic, ceiling(Ceiling::baseline_for(US)));
        let marked = permitted_read_marked(&g.0, Some("SECRET"));
        assert!(matches!(c.decide(&marked), Verdict::Deny { .. }));
        let euid = nix::unistd::geteuid().as_raw();
        install(&c, secret(), enrolled(euid)).unwrap();
        assert!(matches!(c.decide(&marked), Verdict::Permit { .. }));
        assert_eq!(c.ceiling().ceiling().classification.name, "SECRET");
        install(&c, secret(), enrolled(other_uid())).unwrap();
        assert!(!matches!(c.decide(&marked), Verdict::Permit { .. }));
        assert_eq!(c.baseline().principal(), enrolled(other_uid()));
        install(&c, Ceiling::baseline_for(US), enrolled(euid)).unwrap();
        assert!(matches!(c.decide(&marked), Verdict::Deny { .. }));
        assert!(matches!(
            c.decide(&permitted_read(&g.0)),
            Verdict::Permit { .. }
        ));
    }

    #[test]
    fn a_refused_ceiling_installs_neither_operand() {
        use maknae_classification_aus::AusPspf;
        let (_g, basic) = fixture("live-refused", READ_POLICY, None);
        let euid = nix::unistd::geteuid().as_raw();
        let c = Composition::new(basic, ceiling(Ceiling::baseline_for(US)));
        let mut aus = Ceiling::baseline_for(&AusPspf);
        aus.classification = AusPspf.level_of("PROTECTED").unwrap();
        let err = install(&c, aus, enrolled(other_uid())).unwrap_err();
        assert_eq!(err, "PROTECTED is not a level of the US system");
        assert_eq!(c.baseline().principal(), enrolled(euid));
        assert_eq!(c.ceiling().ceiling().classification, US.unmarked());
    }

    /// The old baseline grants the principal and refuses SECRET content; the new one
    /// admits SECRET content and grants someone else. Only a decision that mixed the
    /// old principal with the new ceiling would permit.
    #[test]
    fn a_decision_in_flight_during_an_install_sees_one_baseline_wholly() {
        use maknae_authz_basic::EvaluationGate;
        use std::sync::mpsc::channel;
        use std::time::Duration;
        let (g, mut basic) = fixture("live-race", READ_POLICY, None);
        let gate = std::sync::Arc::new(EvaluationGate {
            arrived: std::sync::Barrier::new(2),
            release: std::sync::Barrier::new(2),
        });
        basic.park_evaluations(gate.clone());
        let c = std::sync::Arc::new(Composition::new(basic, ceiling(Ceiling::baseline_for(US))));
        let marked = permitted_read_marked(&g.0, Some("SECRET"));
        let (decided_tx, decided) = channel();
        {
            let (c, marked) = (c.clone(), marked.clone());
            std::thread::spawn(move || {
                let _ = decided_tx.send(c.decide(&marked));
            });
        }
        let barrier = |which: fn(&EvaluationGate) -> &std::sync::Barrier| {
            let (tx, rx) = channel();
            let gate = gate.clone();
            std::thread::spawn(move || {
                which(&gate).wait();
                let _ = tx.send(());
            });
            rx.recv_timeout(Duration::from_secs(5)).is_ok()
        };
        assert!(
            barrier(|g| &g.arrived),
            "the decision never reached evaluation"
        );
        let (installed_tx, installed) = channel();
        {
            let c = c.clone();
            std::thread::spawn(move || {
                let _ = installed_tx.send(install(&c, secret(), enrolled(other_uid())));
            });
        }
        assert!(
            installed.recv_timeout(Duration::from_millis(200)).is_err(),
            "the install landed while a decision was in flight"
        );
        assert!(barrier(|g| &g.release), "the decision was never released");
        let verdict = decided
            .recv_timeout(Duration::from_secs(5))
            .expect("the decision finishes");
        assert!(
            matches!(verdict, Verdict::Deny { ref reason } if reason.starts_with("ceiling: ")),
            "{verdict:?}"
        );
        installed
            .recv_timeout(Duration::from_secs(5))
            .expect("the install finishes")
            .unwrap();
        assert_eq!(c.ceiling().ceiling().classification.name, "SECRET");
        assert_eq!(c.baseline().principal(), enrolled(other_uid()));
    }

    #[test]
    fn an_install_refused_on_any_value_installs_none() {
        let (_g, basic) = fixture("live-whole", READ_POLICY, None);
        let c = Composition::new(basic, ceiling(Ceiling::baseline_for(US)));
        let before = (
            c.ceiling().ceiling(),
            c.baseline().principal(),
            c.live().generation(),
        );
        let foreign = maknae_authz_basic::LiveTurnLock::hermetic();
        let turn = foreign.try_take().unwrap();
        let values = crate::live::LiveValues {
            ceiling: secret(),
            principal: enrolled(other_uid()),
            view: std::collections::BTreeMap::from([("core".into(), Default::default())]),
            providers: None,
        };
        assert!(c.install_in(&turn, values).is_err());
        assert!(
            *c.ceiling().ceiling() == *before.0,
            "the ceiling was installed"
        );
        assert_eq!(c.baseline().principal(), before.1);
        assert_eq!(c.live().generation(), before.2);
    }

    #[test]
    fn a_ceiling_the_system_does_not_rank_installs_no_principal() {
        let (_g, basic) = fixture("live-unranked", READ_POLICY, None);
        let c = Composition::new(basic, ceiling(Ceiling::baseline_for(US)));
        let before = (c.baseline().principal(), c.live().generation());
        let mut unranked = Ceiling::baseline_for(US);
        unranked.classification = maknae_classification_aus::AusPspf
            .level_of("PROTECTED")
            .unwrap();
        let values = crate::live::LiveValues {
            ceiling: unranked,
            principal: enrolled(other_uid()),
            view: std::collections::BTreeMap::from([("core".into(), Default::default())]),
            providers: None,
        };
        let turn = c.baseline().live_turn().try_take().unwrap();
        assert!(c.install_in(&turn, values).is_err());
        assert_eq!(
            c.baseline().principal(),
            before.0,
            "the principal was installed"
        );
        assert_eq!(c.live().generation(), before.1);
        assert_eq!(*c.ceiling().ceiling(), Ceiling::baseline_for(US));
    }

    #[test]
    fn an_install_that_cannot_take_the_turn_in_time_changes_nothing() {
        use std::sync::mpsc::channel;
        let (_g, basic) = fixture("live-bound", READ_POLICY, None);
        let c = std::sync::Arc::new(Composition::new(basic, ceiling(Ceiling::baseline_for(US))));
        let live = std::sync::Arc::clone(c.live());
        let before = c.baseline().principal();
        let (held_tx, held) = channel();
        let (release_tx, release) = channel::<()>();
        let holder = {
            let c = c.clone();
            std::thread::spawn(move || {
                let _decision = c.baseline().live_turn().share();
                let _ = held_tx.send(());
                let _ = release.recv_timeout(Duration::from_secs(5));
            })
        };
        held.recv_timeout(Duration::from_secs(5))
            .expect("the turn is held");
        let values = crate::live::LiveValues {
            ceiling: secret(),
            principal: enrolled(other_uid()),
            view: std::collections::BTreeMap::from([("core".into(), Default::default())]),
            providers: None,
        };
        let releaser = std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(300));
            let _ = release_tx.send(());
        });
        let err = c
            .install_live_within(values, Instant::now() + Duration::from_millis(50))
            .unwrap_err();
        assert!(err.contains("nothing was installed"), "{err}");
        releaser.join().unwrap();
        holder.join().unwrap();
        assert_eq!(c.baseline().principal(), before);
        assert_eq!(c.ceiling().ceiling().classification, US.unmarked());
        assert_eq!(live.generation(), 0);
        assert!(live.view().is_empty());
    }

    #[test]
    fn an_install_that_starts_after_its_deadline_changes_nothing() {
        let (_g, basic) = fixture("live-late", READ_POLICY, None);
        let c = Composition::new(basic, ceiling(Ceiling::baseline_for(US)));
        let before = c.baseline().principal();
        let values = crate::live::LiveValues {
            ceiling: secret(),
            principal: enrolled(other_uid()),
            view: std::collections::BTreeMap::from([("core".into(), Default::default())]),
            providers: None,
        };
        let err = c.install_live_within(values, Instant::now()).unwrap_err();
        assert!(err.contains("nothing was installed"), "{err}");
        assert_eq!(c.baseline().principal(), before);
        assert_eq!(c.ceiling().ceiling().classification, US.unmarked());
        assert_eq!(c.live().generation(), 0);
    }

    #[test]
    fn subjects_are_the_baselines_because_only_it_enumerates() {
        let (_g, basic) = fixture("subjects", &status_policy(), Some(ADMIN_ROOT));
        let alone = basic.subjects();
        assert!(alone.is_some(), "the hermetic baseline enumerates");
        let c = Composition::new(basic, ceiling(secret()));
        assert_eq!(c.subjects(), alone);
    }
}
