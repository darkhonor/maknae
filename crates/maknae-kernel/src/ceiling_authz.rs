//! The per-request classification-ceiling operand (#148; ADR-0020 §3, ADR-0008
//! decisions 2 and 4; ADR-0022). T1 — a wrong arm here passes content marked
//! ABOVE the declared ceiling, or refuses at baseline what today flows.
//!
//! **Why per request.** A boot-time check is a posture assertion evaluated
//! once; zero trust re-makes the decision on every request (operator ruling
//! 2026-09-06: *"A boot time only detection is not zero trust"*).
//!
//! **What a ceiling IS (operator ruling 2026-09-06).** Content at or below the
//! declared level flows; content marked ABOVE it is spillage and is refused.
//! The ORDER is the selected classification system's (ADR-0022): the operand
//! holds the [`ClassificationPolicy`] boot selected from `core.handling.policy`
//! and asks IT to rank the marking's first token and to compare -- this file
//! orders nothing itself. Everything beyond the level -- compartments,
//! releasability, need-to-know -- remains the external DCS library's, which
//! JOINS this operand as a further floor.
//!
//! **Unmarked content is the system's lowest level.** Under the US system,
//! data that carries no marking is UNCLASSIFIED and, as a rule, publicly
//! releasable (AUS: UNOFFICIAL); vendor and lake content is governed by its
//! license, not by a classification. So an absent label is not "unknown, so
//! deny" -- it is `policy.unmarked()`, at or below every ceiling.
//! Consequences the three deployment tiers rely on: a HomeLab (no `handling`
//! block) serves everything; a small business that declares CUI still serves
//! everything unmarked; an enterprise that declares SECRET serves everything
//! unmarked AND refuses a document marked TOP SECRET. No tier needs a labeler
//! to function; a labeler (#229) only makes HIGHER markings expressible.
//! `handling.accreditation_ref` has no bearing on this operand -- an ATO is a
//! US-government artifact that two of the three tiers will never have -- and
//! neither does `ingest_posture()`, whose consumer is the future memory-system
//! ingest path, not this operand.
//!
//! **Caveats are opaque; a foreign or malformed marking is refused.** The
//! policy ranks the FIRST token (`SECRET//NOFORN` → SECRET; everything after
//! `//` is the scalpel's). A first token the selected system does not carry
//! is refused, never coerced (ADR-0008 decision 4) -- and when another
//! COMPILED-IN system carries it, the refusal NAMES that system (ADR-0022
//! decision 5: recognized and refused; equivalence is `rust-dcs`'s). Unmarked
//! and malformed are different states. Because deny-overrides makes this
//! unwaivable, the writer (#229; `dcs-label` where DCS is installed) must
//! stamp a marking of the enclave's own system.
//!
//! **It never `Permit`s.** ADR-0008 decision 2 *allows* a mandatory operand to
//! permit on a complete evaluation of its own predicate; this operand's
//! predicate is a CONSTRAINT, not an entitlement — being at or below the
//! ceiling says the content may exist on this system, not that this subject may
//! have it. Had it permitted, a request the baseline abstains on would fold to
//! `Permit` under rule 3: fail-open on exactly the requests `-basic` declined.
//! Satisfied → `NotApplicable` (identity); violated → `Deny`.
//!
//! **Control plane abstains.** `liveness.*`, `admin.*` and `kernel.*` carry no
//! content — operator ruling 2026-09-06: even an IP address is not classified
//! per several SCGs. Every other class is content-bearing and is evaluated; a
//! namespace this file has never heard of is content, not control plane (fail
//! closed). The partition is pinned over the whole vocabulary in `handler.rs`.
//!
//! **`Deny`, never `Indeterminate`.** Both are unmaskable (`combine` rules 1
//! and 2), but `finalize` renders `Indeterminate` as the fixed string
//! `indeterminate (fail-closed)`, which loses the operand's identity — and
//! ADR-0008 makes "which operand refused, and why" an audit obligation.
//! Reasons carry closed-vocabulary tokens only -- level NAMES and system
//! NAMES from the registry; a raw marking is request content and is never
//! echoed.
//!
//! **The ceiling and the system are frozen at boot; the baseline is not.**
//! `-basic` re-reads its policy on every request; the ceiling is the static
//! TCB's own declaration (ADR-0002: no hot-swap) and is cloned once from
//! `BootConfig`, with the `'static` policy the registry selected. "Per-request
//! enforcement" means the DECISION is re-made per request.
//!
//! **Abstentions carry no note, deliberately.** `combine` rule 4 keeps the
//! FIRST annotated absence; the baseline is passed first, but where `-basic`
//! abstains bare a note here would replace the historical
//! `no applicable authorizer (fail-closed)` reason. This operand changes no
//! existing audit string.

use maknae_config::Ceiling;
use maknae_security::{
    AttrValue, Authorizer, ClassificationPolicy, Request, Verdict, RESOURCE_CLASSIFICATION,
};

/// The action classes that are CONTROL PLANE: no content crosses the boundary,
/// so the ceiling makes no demand and the operand abstains. Everything else is
/// content-bearing. No gate extracts this constant (unlike `GRANTABLE_ACTIONS`);
/// the whole-vocabulary partition test in `handler.rs` is its control.
pub const CONTROL_PLANE_CLASSES: [&str; 3] = ["liveness", "admin", "kernel"];

/// The name this operand reports through `admin.status`.
pub const CEILING_BACKEND_NAME: &str = "maknae-ceiling";

/// Exact-segment class match — `a == c` or `a.starts_with(c + ".")`, byte-wise.
/// Mirrors `decide.rs::class_of`: `liveness_bypass.exec` is NOT in `liveness`,
/// and an over-matching `starts_with(c)` is the pinned negative.
fn in_class(action: &str, class: &str) -> bool {
    action == class
        || (action.len() > class.len()
            && action.as_bytes()[class.len()] == b'.'
            && action.starts_with(class))
}

/// Does this action move no content? (See the module doc.)
pub fn is_control_plane(action: &str) -> bool {
    CONTROL_PLANE_CLASSES
        .iter()
        .any(|class| in_class(action, class))
}

/// What the operand found under [`RESOURCE_CLASSIFICATION`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Label<'a> {
    /// No marking on the request: the system's lowest level, at or below
    /// every ceiling (operator ruling 2026-09-06).
    Absent,
    /// A marking string, ranked by its FIRST token through the selected
    /// system; caveats after `//` are opaque here.
    Marking(&'a str),
    /// Present but not a string — a writer bug, refused rather than coerced.
    NotAString,
}

/// Read the label off the request's resource attributes.
pub fn label_of(req: &Request) -> Label<'_> {
    match req.resource.0.get(RESOURCE_CLASSIFICATION) {
        None => Label::Absent,
        Some(AttrValue::Str(s)) => Label::Marking(s.as_str()),
        Some(_) => Label::NotAString,
    }
}

/// The pure decision — the truth table this file exists to hold.
///
/// | action | label | verdict |
/// |---|---|---|
/// | control plane | any | `NotApplicable` |
/// | content | absent | `NotApplicable` — unmarked is `policy.unmarked()`, at or below every ceiling |
/// | content | first token ranks ≤ ceiling | `NotApplicable` — constraint satisfied |
/// | content | first token ranks > ceiling | `Deny` — spillage, naming both LEVELS |
/// | content | first token is another compiled-in system's level | `Deny` — naming that SYSTEM |
/// | content | first token no system carries, or not a string | `Deny` — malformed, not unmarked |
/// | content | the ceiling itself is not this system's level | `Deny` — fail closed (boot never produces it) |
///
/// Only `ceiling.classification` is consulted: `sci`, `releasable_to`,
/// `cui_*`, `dissemination_permitted` and `accreditation_ref` are the scalpel's
/// or nobody's, never this operand's.
pub fn decide_ceiling(
    policy: &dyn ClassificationPolicy,
    ceiling: &Ceiling,
    action: &str,
    label: Label<'_>,
) -> Verdict {
    if is_control_plane(action) {
        return Verdict::NotApplicable { note: None };
    }
    let level = match label {
        Label::NotAString => {
            return Verdict::Deny {
                reason: "ceiling: classification attribute is not a string".into(),
            }
        }
        // Unmarked IS a level: the system's lowest.
        Label::Absent => policy.unmarked(),
        Label::Marking(raw) => match policy.level_of(raw) {
            Some(level) => level,
            None => {
                // Recognized-and-refused (ADR-0022 decision 5): name the
                // compiled-in system(s) that DO carry this first token, if any.
                let others: Vec<&str> = crate::classification::recognizing(raw)
                    .into_iter()
                    .filter(|n| *n != policy.name())
                    .collect();
                return Verdict::Deny {
                    reason: if others.is_empty() {
                        "ceiling: unrecognized classification marking".to_string()
                    } else {
                        format!(
                            "ceiling: marking is a level of the {} system, not {}",
                            others.join("/"),
                            policy.name()
                        )
                    },
                };
            }
        },
    };
    match policy.dominates(&ceiling.classification, &level) {
        Some(true) => Verdict::NotApplicable { note: None },
        Some(false) => Verdict::Deny {
            reason: format!(
                "ceiling: content marked {} exceeds the declared ceiling {}",
                level.name, ceiling.classification.name
            ),
        },
        // The ceiling was not ranked by this system. Boot cannot produce this
        // (it validates the ceiling THROUGH the selected system), so it is a
        // construction error -- and it fails closed, not open.
        None => Verdict::Deny {
            reason: format!(
                "ceiling: the declared ceiling is not a level of the {} system",
                policy.name()
            ),
        },
    }
}

/// The operand: the booted ceiling, in the booted system, evaluated on every
/// request.
pub struct CeilingAuthorizer {
    ceiling: Ceiling,
    policy: &'static dyn ClassificationPolicy,
}

impl CeilingAuthorizer {
    pub fn new(ceiling: Ceiling, policy: &'static dyn ClassificationPolicy) -> Self {
        Self { ceiling, policy }
    }
}

impl Authorizer for CeilingAuthorizer {
    fn decide(&self, req: &Request) -> Verdict {
        decide_ceiling(self.policy, &self.ceiling, &req.action.0, label_of(req))
    }

    fn backend_name(&self) -> String {
        CEILING_BACKEND_NAME.to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use maknae_classification_aus::AusPspf;
    use maknae_config::{BasicPolicy, Level};
    use maknae_security::{Action, Attributes, Context, Resource, Subject};

    const US: &BasicPolicy = &BasicPolicy;
    const AUS: &AusPspf = &AusPspf;

    fn ladder(p: &dyn ClassificationPolicy, names: &[&str]) -> Vec<Level> {
        names.iter().map(|n| p.level_of(n).unwrap()).collect()
    }

    fn at(p: &dyn ClassificationPolicy, level: &Level) -> Ceiling {
        let mut c = Ceiling::baseline_for(p);
        c.classification = level.clone();
        c
    }

    fn us_at(name: &str) -> Ceiling {
        at(US, &US.level_of(name).unwrap())
    }

    /// Deviates from the baseline in every NON-level field, including an ATO
    /// reference: none of it may matter to this operand.
    fn tuned_unclassified() -> Ceiling {
        Ceiling {
            classification: US.unmarked(),
            sci: true,
            releasable_to: vec!["REL FVEY".into()],
            cui_permitted: true,
            cui_categories_permitted: vec!["SP-PRVCY".into()],
            dissemination_permitted: vec!["Distribution Statement C".into()],
            accreditation_ref: Some("ATO-2026-0042".into()),
        }
    }

    fn req(action: &str, label: Option<AttrValue>) -> Request {
        let mut resource = Attributes::new();
        if let Some(v) = label {
            resource.insert(RESOURCE_CLASSIFICATION, v);
        }
        Request {
            subject: Subject(Attributes::new()),
            resource: Resource(resource),
            action: Action(action.into()),
            context: Context(Attributes::new()),
        }
    }

    fn deny_reason(v: Verdict) -> String {
        match v {
            Verdict::Deny { reason } => reason,
            other => panic!("expected Deny, got {other:?}"),
        }
    }

    #[test]
    fn control_plane_classes_abstain_under_every_ceiling_and_every_label() {
        for action in [
            "liveness.ping",
            "admin.status",
            "admin.config.show",
            "kernel.contain",
        ] {
            for top in ladder(US, &maknae_config::US_LEVELS) {
                for label in [
                    Label::Absent,
                    Label::Marking("TOP SECRET"),
                    Label::Marking("PROTECTED"),
                    Label::NotAString,
                ] {
                    assert_eq!(
                        decide_ceiling(US, &at(US, &top), action, label),
                        Verdict::NotApplicable { note: None },
                        "{action} must abstain at {}: {label:?}",
                        top.name
                    );
                }
            }
        }
    }

    #[test]
    fn class_match_is_exact_segment_not_prefix() {
        assert!(is_control_plane("admin"));
        assert!(is_control_plane("admin.status"));
        assert!(is_control_plane("kernel.session.terminate"));
        assert!(!is_control_plane("liveness_bypass.exec"));
        assert!(!is_control_plane("adminx"));
        assert!(!is_control_plane("admix"), "same length, different text");
        assert!(
            !is_control_plane("admi"),
            "a prefix of a class is not the class"
        );
        assert!(!is_control_plane("fs.read"));
        assert!(!is_control_plane("session.prompt"));
        assert!(!is_control_plane("mcp.tool.call"));
        assert!(!is_control_plane("terminal.input"));
        assert!(!is_control_plane("future.verb"));
        assert!(!is_control_plane(""));
    }

    #[test]
    fn unmarked_content_is_the_lowest_level_and_flows_under_every_ceiling_in_both_systems() {
        // THE ruling: unmarked is the default level, at or below every ceiling.
        // No tier needs a labeler to function -- in either shipped system.
        for (p, names) in [
            (
                US as &dyn ClassificationPolicy,
                &maknae_config::US_LEVELS[..],
            ),
            (
                AUS as &dyn ClassificationPolicy,
                &maknae_classification_aus::LEVELS[..],
            ),
        ] {
            for top in ladder(p, names) {
                assert_eq!(
                    decide_ceiling(p, &at(p, &top), "fs.read", Label::Absent),
                    Verdict::NotApplicable { note: None },
                    "unmarked content must flow at {} ({})",
                    top.name,
                    p.name()
                );
            }
        }
    }

    #[test]
    fn the_full_matrix_is_at_or_below_flows_above_refuses_in_both_systems() {
        // Every (content level, ceiling level) pair of each ladder, both halves
        // of the order -- computed from the ladders, not typed.
        for (p, names) in [
            (
                US as &dyn ClassificationPolicy,
                &maknae_config::US_LEVELS[..],
            ),
            (
                AUS as &dyn ClassificationPolicy,
                &maknae_classification_aus::LEVELS[..],
            ),
        ] {
            let l = ladder(p, names);
            for top in &l {
                for level in &l {
                    let v = decide_ceiling(p, &at(p, top), "fs.read", Label::Marking(&level.name));
                    if level.rank <= top.rank {
                        assert_eq!(
                            v,
                            Verdict::NotApplicable { note: None },
                            "{} at {} ({})",
                            level.name,
                            top.name,
                            p.name()
                        );
                    } else {
                        assert_eq!(
                            deny_reason(v),
                            format!(
                                "ceiling: content marked {} exceeds the declared ceiling {}",
                                level.name, top.name
                            ),
                            "{} above {} ({})",
                            level.name,
                            top.name,
                            p.name()
                        );
                    }
                }
            }
        }
    }

    #[test]
    fn never_permits_on_any_cell_in_either_system() {
        // The rule-3 fail-open guard: not one cell of either matrix, nor the
        // unmarked row, nor a refusal, may be a Permit.
        for (p, names) in [
            (
                US as &dyn ClassificationPolicy,
                &maknae_config::US_LEVELS[..],
            ),
            (
                AUS as &dyn ClassificationPolicy,
                &maknae_classification_aus::LEVELS[..],
            ),
        ] {
            for top in ladder(p, names) {
                for label in [
                    Label::Absent,
                    Label::Marking("UNCLASSIFIED"),
                    Label::Marking("TOP SECRET"),
                    Label::Marking("PROTECTED"),
                    Label::Marking("BOGUS"),
                    Label::NotAString,
                ] {
                    assert!(
                        !matches!(
                            decide_ceiling(p, &at(p, &top), "fs.read", label),
                            Verdict::Permit { .. }
                        ),
                        "{label:?} at {} ({})",
                        top.name,
                        p.name()
                    );
                }
            }
        }
    }

    #[test]
    fn only_the_level_matters_never_sci_cui_releasability_or_an_ato_reference() {
        // Operator ruling: an ATO is a US-government artifact two of the three
        // deployment tiers will never have; it has no bearing. Nor does any
        // other non-level field: a heavily tuned UNCLASSIFIED ceiling behaves
        // exactly like the bare baseline.
        let tuned = tuned_unclassified();
        assert_eq!(
            decide_ceiling(US, &tuned, "fs.read", Label::Absent),
            decide_ceiling(US, &Ceiling::baseline_for(US), "fs.read", Label::Absent)
        );
        assert_eq!(
            decide_ceiling(US, &tuned, "fs.read", Label::Marking("UNCLASSIFIED")),
            Verdict::NotApplicable { note: None }
        );
        assert_eq!(
            deny_reason(decide_ceiling(
                US,
                &tuned,
                "fs.read",
                Label::Marking("CONFIDENTIAL")
            )),
            "ceiling: content marked CONFIDENTIAL exceeds the declared ceiling UNCLASSIFIED"
        );
    }

    #[test]
    fn the_comparison_is_case_normalized_and_caveats_are_opaque() {
        for marking in [
            "secret",
            "Secret",
            "SECRET",
            "sEcReT",
            "SECRET//NOFORN",
            "secret//REL TO USA, FVEY",
        ] {
            assert_eq!(
                decide_ceiling(US, &us_at("SECRET"), "fs.read", Label::Marking(marking)),
                Verdict::NotApplicable { note: None },
                "{marking}"
            );
            assert_eq!(
                deny_reason(decide_ceiling(
                    US,
                    &us_at("CONFIDENTIAL"),
                    "fs.read",
                    Label::Marking(marking)
                )),
                "ceiling: content marked SECRET exceeds the declared ceiling CONFIDENTIAL",
                "{marking} above CONFIDENTIAL"
            );
        }
        // CUI is UNCLASSIFIED for the level; the caveat is the egress switch's (#147).
        assert_eq!(
            decide_ceiling(
                US,
                &us_at("UNCLASSIFIED"),
                "fs.read",
                Label::Marking("CUI//SP-PRVCY")
            ),
            Verdict::NotApplicable { note: None }
        );
    }

    #[test]
    fn a_foreign_systems_marking_is_recognized_and_refused_by_name() {
        // ADR-0022 decision 5: PROTECTED is a level of AUS and nothing of US.
        // The refusal names the system; it never maps (PROTECTED ≈ CONFIDENTIAL
        // is treaty data and lives in rust-dcs).
        for top in ladder(US, &maknae_config::US_LEVELS) {
            assert_eq!(
                deny_reason(decide_ceiling(
                    US,
                    &at(US, &top),
                    "fs.read",
                    Label::Marking("PROTECTED//AGAO")
                )),
                "ceiling: marking is a level of the AUS system, not US",
                "at {}",
                top.name
            );
        }
        // And the other way: CONFIDENTIAL is US-only.
        let aus_top = AUS.level_of("TOP SECRET").unwrap();
        assert_eq!(
            deny_reason(decide_ceiling(
                AUS,
                &at(AUS, &aus_top),
                "fs.read",
                Label::Marking("confidential")
            )),
            "ceiling: marking is a level of the US system, not AUS"
        );
        // A spelling BOTH carry ranks in the selected system, not the other.
        assert_eq!(
            decide_ceiling(AUS, &at(AUS, &aus_top), "fs.read", Label::Marking("SECRET")),
            Verdict::NotApplicable { note: None }
        );
    }

    #[test]
    fn a_malformed_marking_is_refused_not_treated_as_unmarked() {
        // Unmarked and malformed are different states. The raw value is
        // request content and never reaches the trail.
        for raw in ["SEKRET", "TOP_SECRET", "", "//NOFORN", "FOUO"] {
            for top in ladder(US, &maknae_config::US_LEVELS) {
                let r = deny_reason(decide_ceiling(
                    US,
                    &at(US, &top),
                    "fs.read",
                    Label::Marking(raw),
                ));
                assert_eq!(
                    r, "ceiling: unrecognized classification marking",
                    "{raw:?} at {}",
                    top.name
                );
            }
        }
        let r = deny_reason(decide_ceiling(
            US,
            &us_at("TOP SECRET"),
            "fs.read",
            Label::NotAString,
        ));
        assert_eq!(r, "ceiling: classification attribute is not a string");
    }

    #[test]
    fn a_ceiling_from_another_system_fails_closed() {
        // Boot cannot construct this (it validates the ceiling THROUGH the
        // selected system); the operand still refuses rather than compares.
        let aus_ceiling = at(AUS, &AUS.level_of("TOP SECRET").unwrap());
        for label in [Label::Absent, Label::Marking("UNCLASSIFIED")] {
            assert_eq!(
                deny_reason(decide_ceiling(US, &aus_ceiling, "fs.read", label)),
                "ceiling: the declared ceiling is not a level of the US system",
                "{label:?}"
            );
        }
        // Control plane still abstains even then: it carries no content.
        assert_eq!(
            decide_ceiling(US, &aus_ceiling, "admin.status", Label::Absent),
            Verdict::NotApplicable { note: None }
        );
    }

    #[test]
    fn label_of_reads_the_seam_key_and_distinguishes_all_three_states() {
        assert_eq!(label_of(&req("fs.read", None)), Label::Absent);
        assert_eq!(
            label_of(&req("fs.read", Some(AttrValue::Str("Secret".into())))),
            Label::Marking("Secret")
        );
        assert_eq!(
            label_of(&req("fs.read", Some(AttrValue::Bool(true)))),
            Label::NotAString
        );
        assert_eq!(
            label_of(&req("fs.read", Some(AttrValue::Int(4)))),
            Label::NotAString
        );
    }

    #[test]
    fn the_operand_decides_through_the_trait_and_names_itself() {
        let op = CeilingAuthorizer::new(us_at("SECRET"), US);
        assert_eq!(op.backend_name(), "maknae-ceiling");
        assert_eq!(
            op.decide(&req("fs.read", None)),
            Verdict::NotApplicable { note: None }
        );
        assert!(matches!(
            op.decide(&req("fs.read", Some(AttrValue::Str("top secret".into())))),
            Verdict::Deny { .. }
        ));
        assert_eq!(
            op.decide(&req(
                "admin.status",
                Some(AttrValue::Str("TOP SECRET".into()))
            )),
            Verdict::NotApplicable { note: None }
        );
        assert_eq!(op.subjects(), None);
        // The AUS operand ranks by ITS ladder.
        let aus = CeilingAuthorizer::new(at(AUS, &AUS.level_of("PROTECTED").unwrap()), AUS);
        assert_eq!(
            aus.decide(&req(
                "fs.read",
                Some(AttrValue::Str("official: sensitive".into()))
            )),
            Verdict::NotApplicable { note: None }
        );
        assert!(matches!(
            aus.decide(&req("fs.read", Some(AttrValue::Str("SECRET".into())))),
            Verdict::Deny { .. }
        ));
    }

    /// #172: the egress verb is CONTENT-plane, so the ceiling operand decides
    /// it like any other content term — a prompt marked above the declared
    /// level is refused, unmarked text flows (nothing stamps markings yet, #229;
    /// the attribute is set directly here).
    #[test]
    fn a_prompt_marked_above_the_ceiling_is_refused_and_unmarked_text_flows() {
        let op = CeilingAuthorizer::new(us_at("UNCLASSIFIED"), US);
        assert!(matches!(
            op.decide(&req(
                "session.prompt",
                Some(AttrValue::Str("SECRET".into()))
            )),
            Verdict::Deny { .. }
        ));
        assert!(matches!(
            op.decide(&req("session.prompt", None)),
            Verdict::NotApplicable { .. }
        ));
        assert!(!is_control_plane("session.prompt"));
    }
}
