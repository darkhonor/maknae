//! N-ary composition of authorizers (spec §13, §14).
//!
//! [`combine`] folds operand verdicts with **deny-overrides + indeterminate-
//! blocks + NotApplicable-identity** — deliberately stronger than XACML
//! deny-overrides, which would let `Permit ∧ Indeterminate → Permit` (a
//! fail-open we reject). [`ConjunctionAuthorizer`] is the reusable combinator
//! the kernel holds when more than one backend is installed.
//!
//! *(Corrected 2026-08-31 per #108 and [ADR-0008]: this line previously read
//! "`DCS_MAC ∧ OS_MAC ∧ DAC`", describing the fold as a conjunction of named
//! policy types — which contradicted the paragraph directly above it and
//! predates ADR-0008. Composition does not know what KIND of policy an operand
//! implements. Each operand decides by its own model and returns a `Verdict`;
//! `combine` folds those verdicts by the rule above. A mandatory operand may
//! `Permit` on a complete evaluation of its own predicate, which a conjunction
//! of policy types cannot express.)*

use crate::authorizer::{Authorizer, SubjectBinding};
use crate::obligation::{merge_obligations, Obligation};
use crate::request::Request;
use crate::verdict::Verdict;

/// Fold operand verdicts (order-independent):
/// 1. any `Deny` → `Deny`;
/// 2. else any `Indeterminate` → `Deny` (never masked by a peer `Permit`);
/// 3. else any `Permit` → `Permit` with the union of all Permit obligations
///    (a `(id, params)` conflict → `Deny`);
/// 4. else (all `NotApplicable`, or empty) → `NotApplicable`.
pub fn combine(verdicts: Vec<Verdict>) -> Verdict {
    // 1. any Deny
    for v in &verdicts {
        if let Verdict::Deny { reason } = v {
            return Verdict::Deny {
                reason: reason.clone(),
            };
        }
    }
    // 2. any Indeterminate (never masked by a peer Permit)
    if verdicts.iter().any(|v| matches!(v, Verdict::Indeterminate)) {
        return Verdict::Deny {
            reason: "indeterminate operand blocks (fail-closed)".into(),
        };
    }
    // 3. any Permit → union obligations
    let mut any_permit = false;
    let mut acc: Vec<Obligation> = Vec::new();
    for v in verdicts {
        if let Verdict::Permit { obligations } = v {
            any_permit = true;
            match merge_obligations(std::mem::take(&mut acc), obligations) {
                Ok(m) => acc = m,
                Err(_) => {
                    return Verdict::Deny {
                        reason: "conflicting obligations (fail-closed)".into(),
                    }
                }
            }
        }
    }
    if any_permit {
        return Verdict::Permit { obligations: acc };
    }
    // 4. all NotApplicable (or empty)
    Verdict::NotApplicable
}

/// Invoke a backend behind a **panic boundary** (spec §6, §15.4). A buggy or
/// hostile `Authorizer` that panics is converted to `Indeterminate` — which
/// `combine`/`finalize` turn into `Deny` — instead of letting the panic escape
/// and crash the PDP or bypass composition. Any PDP host (the kernel) that
/// invokes a single backend directly should route through this too.
///
/// `AssertUnwindSafe` is sound here: `decide` takes `&self`/`&Request` and
/// returns an owned `Verdict`; a panic mid-decide leaves no shared state we
/// observe — we discard the operand and deny.
///
/// (Relies on unwinding panics; under `panic = "abort"` a panicking backend
/// aborts the process, which is still fail-closed — no wrong `Permit` is served.)
pub fn guarded_decide(a: &dyn Authorizer, req: &Request) -> Verdict {
    std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| a.decide(req)))
        .unwrap_or(Verdict::Indeterminate)
}

/// The same panic boundary for the two DISCLOSURE seam methods.
///
/// `guarded_decide`'s doc already says any PDP host invoking a backend
/// directly should route through it — and when `subjects`/`backend_name` were
/// added, the composed authorizer called both operands RAW, three lines below
/// its own guarded `decide`. A hostile or buggy third-party operand panicking
/// in either one unwinds through the kernel's `handle()` AFTER its audit
/// record has already said `permit / authorized`.
///
/// Both fail CLOSED, and the two failures are different: a name that cannot be
/// obtained is `unknown` (the seam default, honest), and an enumeration that
/// cannot be performed is `None` — "cannot enumerate", never an empty list,
/// which is the claim this whole surface refuses to make wrongly.
pub fn guarded_backend_name(a: &dyn Authorizer) -> String {
    let raw = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| a.backend_name()))
        .unwrap_or_else(|_| "unknown".to_string());
    sanitize_backend_name(&raw)
}

/// The longest name this surface will carry, whole.
///
/// Sized for a COMPOSED name, not a single operand: the kernel calls
/// `guarded_backend_name` on the `ConjunctionAuthorizer` itself, so the cap
/// applies to the joined string, and a per-operand-sized cap would truncate a
/// legitimate three-backend name. 128 comfortably holds the realistic
/// compositions and is still a trivial bound against a hostile operand.
const BACKEND_NAME_MAX: usize = 128;

/// An operand-supplied IDENTIFIER, reduced to what an identifier needs.
///
/// This value is serialized into `StatusView.authz_backend`, returned to the
/// client, and printed by the CLI. Left unbounded and unfiltered it is a
/// terminal-injection vector (ANSI escapes, embedded newlines forging a second
/// line of output) and a way for a third-party backend to push a permitted
/// `admin.status` response past `frame_max_bytes` — turning it into a
/// `refused-oversize` the operator has no way to explain. Truncation is on a
/// CHARACTER boundary: slicing a `String` by bytes panics mid-codepoint, which
/// would defeat the panic boundary this same function exists to provide.
fn sanitize_backend_name(raw: &str) -> String {
    let kept: String = raw
        .chars()
        .filter(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.' | '+'))
        .collect();
    // Truncation is MARKED. An unmarked cut would render a composed
    // `a+b+c` as `a+b+` and read as a complete two-backend deployment —
    // a wrong answer to the one question this field exists to answer, which is
    // worse than a visibly incomplete one. `~` is outside the kept charset, so
    // it cannot be forged by an operand naming itself.
    let cleaned = if kept.chars().count() > BACKEND_NAME_MAX {
        let mut t: String = kept.chars().take(BACKEND_NAME_MAX).collect();
        t.push('~');
        t
    } else {
        kept
    };
    if cleaned.is_empty() {
        // Sanitized away is indistinguishable from "did not answer", and the
        // honest report for both is the same one a panic gets.
        "unknown".to_string()
    } else {
        cleaned
    }
}

/// See [`guarded_backend_name`]. A panicking operand yields `None` —
/// "cannot enumerate" — never `Some(vec![])`.
pub fn guarded_subjects(a: &dyn Authorizer) -> Option<Vec<SubjectBinding>> {
    std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| a.subjects())).unwrap_or(None)
}

/// Holds N backends; `decide` composes their verdicts via [`combine`], each
/// behind [`guarded_decide`]. Spec §13/§14 (N-ary operand fold). The kernel
/// constructs this in a DCS build; a non-DCS build can use a single backend
/// directly (still via `guarded_decide`).
pub struct ConjunctionAuthorizer {
    operands: Vec<Box<dyn Authorizer>>,
}

impl ConjunctionAuthorizer {
    pub fn new(operands: Vec<Box<dyn Authorizer>>) -> Self {
        Self { operands }
    }
}

impl Authorizer for ConjunctionAuthorizer {
    fn decide(&self, req: &Request) -> Verdict {
        combine(
            self.operands
                .iter()
                .map(|a| guarded_decide(a.as_ref(), req))
                .collect(),
        )
    }

    /// Names every operand, in composition order.
    ///
    /// Taking the `unknown` default here would have made `admin.status`'s
    /// disclosure useless in the exact deployment it was justified for: the
    /// stated reason to disclose this field is that under the composed build
    /// the deciding backend is NOT `-basic`, and an operator needs to know
    /// which one produced a verdict.
    fn backend_name(&self) -> String {
        self.operands
            .iter()
            .map(|a| guarded_backend_name(a.as_ref()))
            .collect::<Vec<_>>()
            .join("+")
    }

    /// Enumerable ONLY when exactly one operand can enumerate.
    ///
    /// Two operands that both answer are two different claims about who holds
    /// what, and this layer has no basis to pick one or to merge them — a
    /// union would assert a binding set no single PDP actually resolves. Under
    /// deny-overrides an operand may also deny what another permits, so the
    /// merged list would not describe the composed decision either. `None`
    /// means "cannot enumerate", which the kernel reports as unavailable;
    /// answering wrongly about authorization state is worse than not
    /// answering.
    /// A PANIC is distinguished from a decline. `guarded_subjects` folds both
    /// to `None`, which would let a hostile operand panic on demand to remove
    /// itself from the count — turning "two answers, refuse" into "one answer,
    /// disclose it" and promoting the survivor's list to sole authority over a
    /// composed decision it does not describe. An operand that failed is not an
    /// operand that declined, so any panic refuses the whole enumeration.
    fn subjects(&self) -> Option<Vec<SubjectBinding>> {
        let mut answers = Vec::new();
        for a in &self.operands {
            match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| a.subjects())) {
                Err(_) => return None,
                Ok(Some(list)) => answers.push(list),
                Ok(None) => {}
            }
        }
        match answers.len() {
            1 => answers.pop(),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Both new seam methods sit behind the panic boundary, mirroring
    /// `guarded_decide_converts_panic_to_indeterminate`. A hostile operand
    /// panicking in either one would otherwise unwind through the kernel's
    /// `handle()` after its audit record already said permit/authorized.
    #[test]
    fn guarded_seam_methods_convert_panic_to_the_fail_closed_answer() {
        struct Hostile;
        impl Authorizer for Hostile {
            fn decide(&self, _: &Request) -> Verdict {
                Verdict::NotApplicable
            }
            fn backend_name(&self) -> String {
                panic!("hostile backend")
            }
            fn subjects(&self) -> Option<Vec<SubjectBinding>> {
                panic!("hostile backend")
            }
        }
        assert_eq!(crate::guarded_backend_name(&Hostile), "unknown");
        assert_eq!(
            crate::guarded_subjects(&Hostile),
            None,
            "a panicking operand must yield `cannot enumerate`, never an empty list"
        );
        // And through the composed authorizer, which is where the raw calls were.
        let c = ConjunctionAuthorizer::new(vec![Box::new(Hostile)]);
        assert_eq!(c.backend_name(), "unknown");
        assert_eq!(c.subjects(), None);
    }

    /// The composed authorizer NAMES its operands rather than taking the
    /// `unknown` default. Taking the default would have made `admin.status`'s
    /// disclosure useless in the one deployment it was justified for.
    #[test]
    fn composed_backend_name_lists_every_operand() {
        struct Named(&'static str);
        impl Authorizer for Named {
            fn decide(&self, _: &Request) -> Verdict {
                Verdict::NotApplicable
            }
            fn backend_name(&self) -> String {
                self.0.to_string()
            }
        }
        let c = ConjunctionAuthorizer::new(vec![
            Box::new(Named("maknae-authz-basic")),
            Box::new(Named("maknae-authz-dcs")),
        ]);
        assert_eq!(c.backend_name(), "maknae-authz-basic+maknae-authz-dcs");
    }

    /// The name is OPERAND-SUPPLIED and reaches the wire, so it is bounded and
    /// sanitized at the guard — the single choke point the kernel calls.
    ///
    /// `StatusView.authz_backend` is serialized to the client and printed by
    /// the CLI. An unbounded `String` from a third-party backend is a terminal
    /// injection vector (control bytes, ANSI escapes, embedded newlines that
    /// forge a second line of output) and a way to push the response over
    /// `frame_max_bytes`, turning a permitted `admin.status` into a
    /// `refused-oversize` the operator cannot explain. Nothing about a backend
    /// IDENTIFIER needs those bytes.
    #[test]
    fn a_backend_name_reaching_the_wire_is_bounded_and_sanitized() {
        struct Nasty(String);
        impl Authorizer for Nasty {
            fn decide(&self, _: &Request) -> Verdict {
                Verdict::NotApplicable
            }
            fn backend_name(&self) -> String {
                self.0.clone()
            }
        }
        let esc = crate::guarded_backend_name(&Nasty("dcs\u{1b}[2Kforged\nline".into()));
        assert!(
            !esc.contains('\u{1b}') && !esc.contains('\n'),
            "control bytes must not reach an operator terminal, got {esc:?}"
        );
        let long = crate::guarded_backend_name(&Nasty("x".repeat(10_000)));
        assert!(
            long.len() <= 129,
            "an operand-supplied identifier must be bounded, got {} bytes",
            long.len()
        );
        assert!(
            long.ends_with('~'),
            "a truncated name must SAY it was truncated: unmarked, a composed \
             `a+b+c` cut to `a+b+` reads as a complete two-backend deployment"
        );
        // A realistic COMPOSED name survives whole — the cap is sized for the
        // joined string because that is what the kernel passes through here.
        let c = ConjunctionAuthorizer::new(vec![
            Box::new(Nasty("maknae-authz-basic".into())),
            Box::new(Nasty("maknae-authz-dcs".into())),
        ]);
        assert_eq!(
            crate::guarded_backend_name(&c),
            "maknae-authz-basic+maknae-authz-dcs"
        );
        // An identifier that is legitimate passes through UNCHANGED — a
        // sanitizer that mangles the real names would make the field useless.
        assert_eq!(
            crate::guarded_backend_name(&Nasty("maknae-authz-dcs_1.2".into())),
            "maknae-authz-dcs_1.2"
        );
        // Emptied by sanitizing is the same state as "did not answer".
        assert_eq!(
            crate::guarded_backend_name(&Nasty("\u{1b}\u{1b}".into())),
            "unknown"
        );
    }

    /// A PANICKING operand must not be able to promote another operand's list
    /// to sole authority.
    ///
    /// `guarded_subjects` maps a panic to the same `None` as "this backend
    /// cannot enumerate", and the "exactly one operand answers" rule then
    /// counts only the answers it can see. So two enumerating operands -- which
    /// must refuse, being two different claims about who holds what -- become
    /// ONE answering operand the moment the other panics, and the survivor's
    /// list is disclosed as though it described the composed decision. A
    /// hostile operand chooses that outcome by panicking on demand.
    ///
    /// Distinguishing the two states is the whole fix: a panic is an operand
    /// that FAILED, not one that declines, and the composition refuses.
    #[test]
    fn a_panicking_operand_cannot_promote_another_list_to_sole_authority() {
        struct Hostile;
        impl Authorizer for Hostile {
            fn decide(&self, _: &Request) -> Verdict {
                Verdict::NotApplicable
            }
            fn subjects(&self) -> Option<Vec<SubjectBinding>> {
                panic!("hostile backend")
            }
        }
        struct Enumerates;
        impl Authorizer for Enumerates {
            fn decide(&self, _: &Request) -> Verdict {
                Verdict::NotApplicable
            }
            fn subjects(&self) -> Option<Vec<SubjectBinding>> {
                Some(vec![SubjectBinding {
                    role: "admin".into(),
                    members: vec!["uid:0".into()],
                }])
            }
        }
        let c = ConjunctionAuthorizer::new(vec![Box::new(Hostile), Box::new(Enumerates)]);
        assert_eq!(
            c.subjects(),
            None,
            "an operand that PANICKED is a failed operand, not one that declines: \
             its silence must not make another operand's list authoritative"
        );
        // Order must not decide it either.
        let c = ConjunctionAuthorizer::new(vec![Box::new(Enumerates), Box::new(Hostile)]);
        assert_eq!(c.subjects(), None);
    }

    /// Enumerable ONLY when exactly one operand can enumerate. Two answering
    /// operands are two different claims about who holds what, and this layer
    /// has no basis to pick one or merge them.
    #[test]
    fn composed_subjects_answers_only_when_exactly_one_operand_can() {
        struct Enum(Option<&'static str>);
        impl Authorizer for Enum {
            fn decide(&self, _: &Request) -> Verdict {
                Verdict::NotApplicable
            }
            fn subjects(&self) -> Option<Vec<SubjectBinding>> {
                self.0.map(|r| {
                    vec![SubjectBinding {
                        role: r.to_string(),
                        members: vec!["uid:0".into()],
                    }]
                })
            }
        }
        // Exactly one answers -> that answer.
        let one =
            ConjunctionAuthorizer::new(vec![Box::new(Enum(Some("admin"))), Box::new(Enum(None))]);
        assert_eq!(
            one.subjects().map(|v| v[0].role.clone()),
            Some("admin".into())
        );

        // Two answer -> None. NOT a merge and NOT first-wins: either would
        // assert a binding set no single PDP actually resolves.
        let two = ConjunctionAuthorizer::new(vec![
            Box::new(Enum(Some("admin"))),
            Box::new(Enum(Some("operator"))),
        ]);
        assert!(two.subjects().is_none(), "ambiguous must be None");

        // None answer -> None.
        let zero = ConjunctionAuthorizer::new(vec![Box::new(Enum(None)), Box::new(Enum(None))]);
        assert!(zero.subjects().is_none());
    }
    use crate::obligation::Obligation;
    use crate::request::{Action, Context, Request, Resource, Subject};
    use crate::value::{AttrValue, Attributes};

    fn ob(id: &str) -> Obligation {
        Obligation {
            id: id.into(),
            params: Attributes::new(),
        }
    }
    fn permit(obs: Vec<Obligation>) -> Verdict {
        Verdict::Permit { obligations: obs }
    }

    // ---- combine() ----

    #[test]
    fn deny_beats_permit_alone() {
        // isolates step 1 (no Indeterminate present)
        assert!(matches!(
            combine(vec![permit(vec![]), Verdict::Deny { reason: "n".into() }]),
            Verdict::Deny { .. }
        ));
    }

    #[test]
    fn indeterminate_blocks_permit() {
        // the round-1 fail-open critical: must NOT be masked
        assert!(matches!(
            combine(vec![permit(vec![]), Verdict::Indeterminate]),
            Verdict::Deny { .. }
        ));
    }

    #[test]
    fn permit_unions_obligations() {
        match combine(vec![permit(vec![ob("audit")]), permit(vec![ob("orcon")])]) {
            Verdict::Permit { obligations } => assert_eq!(obligations.len(), 2),
            _ => panic!("obligations lost"),
        }
    }

    #[test]
    fn permit_obligation_conflict_denies() {
        let mut p10 = Attributes::new();
        p10.insert("per_min", AttrValue::Int(10));
        let mut p60 = Attributes::new();
        p60.insert("per_min", AttrValue::Int(60));
        let a = Verdict::Permit {
            obligations: vec![Obligation {
                id: "rate-limit".into(),
                params: p10,
            }],
        };
        let b = Verdict::Permit {
            obligations: vec![Obligation {
                id: "rate-limit".into(),
                params: p60,
            }],
        };
        assert!(matches!(combine(vec![a, b]), Verdict::Deny { .. }));
    }

    #[test]
    fn notapplicable_is_identity() {
        match combine(vec![permit(vec![ob("audit")]), Verdict::NotApplicable]) {
            Verdict::Permit { obligations } => assert_eq!(obligations.len(), 1),
            _ => panic!("identity broken"),
        }
    }

    #[test]
    fn all_notapplicable_stays_notapplicable() {
        assert!(matches!(
            combine(vec![Verdict::NotApplicable, Verdict::NotApplicable]),
            Verdict::NotApplicable
        ));
    }

    #[test]
    fn empty_is_notapplicable() {
        assert!(matches!(combine(vec![]), Verdict::NotApplicable));
    }

    #[test]
    fn lone_permit_permits() {
        assert!(matches!(
            combine(vec![permit(vec![])]),
            Verdict::Permit { .. }
        ));
    }

    // ---- ConjunctionAuthorizer ----

    struct Fixed(Verdict);
    impl Authorizer for Fixed {
        fn decide(&self, _r: &Request) -> Verdict {
            self.0.clone()
        }
    }
    fn req() -> Request {
        Request {
            subject: Subject(Attributes::new()),
            resource: Resource(Attributes::new()),
            action: Action("x".into()),
            context: Context(Attributes::new()),
        }
    }

    #[test]
    fn conjunction_denies_when_one_operand_denies() {
        let c = ConjunctionAuthorizer::new(vec![
            Box::new(Fixed(Verdict::Permit {
                obligations: vec![],
            })),
            Box::new(Fixed(Verdict::Deny {
                reason: "mac".into(),
            })),
        ]);
        match c.decide(&req()) {
            Verdict::Deny { reason } => assert_eq!(reason, "mac"), // operand reason propagates
            _ => panic!("must deny"),
        }
    }

    #[test]
    fn conjunction_reduces_over_notapplicable() {
        let c = ConjunctionAuthorizer::new(vec![
            Box::new(Fixed(Verdict::NotApplicable)),
            Box::new(Fixed(Verdict::Permit {
                obligations: vec![],
            })),
        ]);
        assert!(matches!(c.decide(&req()), Verdict::Permit { .. }));
    }

    // ---- panic boundary (spec §6, §15.4) ----

    struct Panics;
    impl Authorizer for Panics {
        fn decide(&self, _r: &Request) -> Verdict {
            panic!("hostile/buggy backend");
        }
    }

    #[test]
    fn guarded_decide_converts_panic_to_indeterminate() {
        // asserts Indeterminate specifically (not NotApplicable) so a mutant
        // swapping the fallback is caught.
        assert!(matches!(
            guarded_decide(&Panics, &req()),
            Verdict::Indeterminate
        ));
    }

    #[test]
    fn conjunction_denies_on_backend_panic_not_crash() {
        // a panicking operand alongside a Permit must Deny, never fail-open,
        // never escape the panic.
        let c = ConjunctionAuthorizer::new(vec![
            Box::new(Fixed(Verdict::Permit {
                obligations: vec![],
            })),
            Box::new(Panics),
        ]);
        assert!(matches!(c.decide(&req()), Verdict::Deny { .. }));
    }
}
