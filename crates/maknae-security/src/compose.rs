//! N-ary composition of authorizers (spec §13, §14).
//!
//! [`combine`] folds operand verdicts with **deny-overrides + indeterminate-
//! blocks + NotApplicable-identity** — deliberately stronger than XACML
//! deny-overrides, which would let `Permit ∧ Indeterminate → Permit` (a
//! fail-open we reject). [`ConjunctionAuthorizer`] is the reusable combinator
//! the kernel holds in a DCS build (`DCS_MAC ∧ OS_MAC ∧ DAC`).

use crate::authorizer::Authorizer;
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

/// Holds N backends; `decide` composes their verdicts via [`combine`]. Spec
/// §13/§14 (N-ary MAC ∧ DAC). The kernel constructs this in a DCS build; a
/// non-DCS build can use a single backend directly.
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
        combine(self.operands.iter().map(|a| a.decide(req)).collect())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
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
}
