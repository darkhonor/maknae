//! Language-neutral golden vectors for the composition + finalize surface
//! (spec §15.4). The failed-`when` polarity rows and the missing-attribute≠false
//! matcher invariant belong to the future `maknae-authz-basic` backend (they need
//! a real matcher) and are asserted there, not here.

use maknae_security::*;

fn permit() -> Verdict {
    Verdict::Permit {
        obligations: vec![],
    }
}

#[test]
fn v_indeterminate_never_masked_then_denied() {
    // §15.4: any operand Indeterminate (even with a peer Permit) → Deny
    assert!(matches!(
        finalize(combine(vec![permit(), Verdict::Indeterminate])),
        Decision::Deny { .. }
    ));
}

#[test]
fn v_all_notapplicable_finalizes_deny() {
    // §15.4: NotApplicable reaching the top → Deny
    assert!(matches!(
        finalize(combine(vec![Verdict::NotApplicable])),
        Decision::Deny { .. }
    ));
}

#[test]
fn v_deny_overrides_permit() {
    assert!(matches!(
        finalize(combine(vec![
            permit(),
            Verdict::Deny { reason: "m".into() }
        ])),
        Decision::Deny { .. }
    ));
}

#[test]
fn v_obligations_survive_composition() {
    // §13: Permit{a} ∧ Permit{b} → Permit{a,b}
    let a = Verdict::Permit {
        obligations: vec![Obligation {
            id: "audit".into(),
            params: Attributes::new(),
        }],
    };
    let b = Verdict::Permit {
        obligations: vec![Obligation {
            id: "orcon".into(),
            params: Attributes::new(),
        }],
    };
    match finalize(combine(vec![a, b])) {
        Decision::Permit { obligations } => assert_eq!(obligations.len(), 2),
        _ => panic!("obligations lost in composition"),
    }
}

#[test]
fn v_obligation_conflict_denies() {
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
    assert!(matches!(
        finalize(combine(vec![a, b])),
        Decision::Deny { .. }
    ));
}

#[test]
fn v_lone_permit_permits() {
    assert!(matches!(
        finalize(combine(vec![permit()])),
        Decision::Permit { .. }
    ));
}

#[test]
fn v_deny_reasons_are_populated() {
    // pins reason substrings so a reason-only mutation is caught (mutation-gate hardening)
    match finalize(combine(vec![Verdict::Indeterminate])) {
        Decision::Deny { reason } => assert!(reason.contains("indeterminate")),
        _ => panic!("indeterminate must deny"),
    }
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
    match finalize(combine(vec![a, b])) {
        Decision::Deny { reason } => assert!(reason.contains("onflict")), // "conflict"
        _ => panic!("obligation conflict must deny"),
    }
}
