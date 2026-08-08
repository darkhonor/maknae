//! ORCON emission + validity decision vectors (#48).
mod common;
use common::*;
use maknae_dcs_core::{
    decide, validate_label, Action, ControlMarking, Controls, Decision, DenyReason,
    LabelInvalidity, Obligation, RedisseminationScope,
};
use std::collections::BTreeSet;

fn orcon_secret(ctrls: &[ControlMarking]) -> maknae_dcs_core::ResourceLabel {
    let mut r = mk_owned_classified("USA", "SECRET");
    r.controls = Controls::from_set(ctrls.iter().copied().collect());
    r
}

#[test]
fn orcon_emits_originator_controlled() {
    let spif = us_classified_spif();
    let go = |ctrls: &[ControlMarking], a: Action| {
        decide(
            &sub_classified("USA"),
            &orcon_secret(ctrls),
            a,
            &purpose(""),
            &spif,
        )
    };
    let oc_none: BTreeSet<Obligation> = [Obligation::OriginatorControlled { scope: None }]
        .into_iter()
        .collect();
    let oc_usgov: BTreeSet<Obligation> = [Obligation::OriginatorControlled {
        scope: Some(RedisseminationScope::UsGov),
    }]
    .into_iter()
    .collect();
    assert_eq!(
        go(&[ControlMarking::Orcon], Action::Export),
        Decision::PermitWithObligations {
            obligations: oc_none
        }
    );
    assert_eq!(
        go(&[ControlMarking::OrconUsGov], Action::Read),
        Decision::PermitWithObligations {
            obligations: oc_usgov
        }
    );
}

#[test]
fn orcon_relido_and_unclassified_rejected_both_arms() {
    let spif = us_classified_spif();
    for ctrls in [
        &[ControlMarking::Orcon, ControlMarking::Relido][..],
        &[ControlMarking::OrconUsGov, ControlMarking::Relido][..],
    ] {
        let r = orcon_secret(ctrls);
        assert!(matches!(
            validate_label(&r, &spif),
            Err(LabelInvalidity::Label)
        ));
        assert_eq!(
            decide(
                &sub_classified("USA"),
                &r,
                Action::Read,
                &purpose(""),
                &spif
            ),
            Decision::Deny(DenyReason::InvalidLabel)
        );
    }
    for oc in [ControlMarking::Orcon, ControlMarking::OrconUsGov] {
        let mut r = orcon_secret(&[oc]);
        r.classification.name = "UNCLASSIFIED".into();
        assert!(matches!(
            validate_label(&r, &spif),
            Err(LabelInvalidity::Label)
        ));
        assert_eq!(
            decide(
                &sub_classified("USA"),
                &r,
                Action::Read,
                &purpose(""),
                &spif
            ),
            Decision::Deny(DenyReason::InvalidLabel)
        );
    }
}
