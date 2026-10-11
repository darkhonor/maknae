use maknae_graph::identity::IdentityLayer;
use maknae_proto::{ContainTarget, ContainmentOutcome, OperandError, Verb};
use std::collections::{BTreeMap, BTreeSet};

/// Why a live edit did not commit.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum LiveRefusal {
    Busy,
    Stopping,
    NoExplicitBindings,
    LastReleaser,
    SelfContainWithoutRelease,
    AlreadyContained,
    NotContained,
    LookupUnavailable,
    Failed(String),
}

/// Which containment request a record or check is for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Kind {
    Contain,
    Release,
    KernelContain,
}

/// The safety check a live edit runs in the turn.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum LiveCheck {
    None,
    Contain { target: u32, requester: u32 },
    KernelContain { target: u32 },
}

/// A live edit, or a release whose claimants are resolved in the turn.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum LiveOp {
    Edit(maknae_config::LiveEdit),
    Release { uid: u32, named: Option<String> },
}

/// What the live record says beyond the edit; trail-only.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct LiveNote<'a> {
    pub requester: Option<(u32, u64)>,
    pub reason: Option<&'a str>,
}

impl LiveNote<'_> {
    /// A note that adds nothing to the record.
    #[cfg(test)]
    pub(crate) fn none() -> Self {
        Self {
            requester: None,
            reason: None,
        }
    }
}

/// The reply code for a refusal; an internal failure has none.
pub(crate) fn outcome(r: &LiveRefusal) -> Option<ContainmentOutcome> {
    Some(match r {
        LiveRefusal::Busy => ContainmentOutcome::Busy,
        LiveRefusal::Stopping => ContainmentOutcome::Stopping,
        LiveRefusal::NoExplicitBindings => ContainmentOutcome::NoExplicitBindings,
        LiveRefusal::LastReleaser => ContainmentOutcome::LastReleaser,
        LiveRefusal::SelfContainWithoutRelease => ContainmentOutcome::SelfContainWithoutRelease,
        LiveRefusal::AlreadyContained => ContainmentOutcome::AlreadyContained,
        LiveRefusal::NotContained => ContainmentOutcome::NotContained,
        LiveRefusal::LookupUnavailable => ContainmentOutcome::LookupUnavailable,
        LiveRefusal::Failed(_) => return None,
    })
}

/// The record's (result, posture) for an outcome.
pub(crate) fn record_class(o: ContainmentOutcome) -> (&'static str, &'static str) {
    use ContainmentOutcome as O;
    match o {
        O::LastReleaser
        | O::SelfContainWithoutRelease
        | O::NoExplicitBindings
        | O::UnknownAccount => ("deny", "refused"),
        O::Busy | O::Stopping | O::LookupUnavailable => ("deny", "unavailable"),
        O::AlreadyContained | O::NotContained => ("permit", "unchanged"),
        O::Contained | O::Released => ("permit", "authorized"),
    }
}

/// The corrective record's reason for a refused or unchanged request.
pub(crate) fn corrective(
    verb: Kind,
    o: ContainmentOutcome,
    uid: Option<u32>,
    detail: &str,
    reason: Option<&str>,
) -> String {
    use ContainmentOutcome as O;
    let word = match verb {
        Kind::Contain => "contain",
        Kind::Release => "release",
        Kind::KernelContain => "kernel containment",
    };
    let subject = uid.map_or_else(|| "the subject".to_string(), |u| format!("uid {u}"));
    let text = match o {
        O::LastReleaser => {
            format!("containing {subject} would leave no uncontained subject holding admin.release")
        }
        O::SelfContainWithoutRelease => {
            format!("{subject} does not hold admin.release and cannot contain itself")
        }
        O::AlreadyContained => format!("{subject} is already contained"),
        O::NotContained => format!("{subject} is not contained"),
        O::NoExplicitBindings => {
            "bindings.yaml has no bindings: key; a live identity edit needs explicit bindings"
                .to_string()
        }
        O::Busy
        | O::Stopping
        | O::LookupUnavailable
        | O::UnknownAccount
        | O::Contained
        | O::Released => {
            if detail.is_empty() {
                o.text().to_string()
            } else {
                detail.to_string()
            }
        }
    };
    let mut out = match record_class(o) {
        ("deny", _) => format!("{word} refused: {}: {text}", o.code()),
        (_, posture) => format!("{word} {posture}: {text}"),
    };
    if let Some(r) = reason {
        out.push_str(&format!("; reason {}", quoted(r)));
    }
    out
}

/// Whether the stored layer binds `uid` as an adversary, carried forward included.
pub(crate) fn is_contained(layer: &IdentityLayer, uid: u32) -> bool {
    layer
        .subjects
        .iter()
        .any(|s| s.uid == uid && s.role == maknae_graph::kernel::ADVERSARY)
}

/// Every adversary name claiming `uid`, plus the name the request gave.
pub(crate) fn release_names(
    uid: u32,
    named: Option<&str>,
    claims: &BTreeMap<String, u32>,
) -> BTreeSet<String> {
    claims
        .iter()
        .filter(|(_, u)| **u == uid)
        .map(|(n, _)| n.clone())
        .chain(named.map(str::to_owned))
        .collect()
}

/// The first name bound in `live` that `answered` does not know, other than one `edit` binds itself.
pub(crate) fn unanswered(
    live: &maknae_config::Section,
    edit: &maknae_config::LiveEdit,
    answered: impl Fn(&str) -> bool,
) -> Option<String> {
    use maknae_config::{BindingEntry, LiveEdit};
    let own = match edit {
        LiveEdit::Contain(BindingEntry::Name(n)) | LiveEdit::Bind { name: n, .. } => Some(n),
        _ => None,
    };
    live.entries().into_iter().find_map(|e| match e {
        BindingEntry::Name(n) if Some(n) != own && !answered(n) => Some(n.clone()),
        _ => None,
    })
}

/// Whether `edit` is the one a containment check guards: its target, bound by uid.
pub(crate) fn binds_target_by_uid(check: LiveCheck, edit: &maknae_config::LiveEdit) -> bool {
    use maknae_config::{BindingEntry, LiveEdit};
    match check {
        LiveCheck::None => true,
        LiveCheck::Contain { target, .. } | LiveCheck::KernelContain { target } => {
            *edit == LiveEdit::Contain(BindingEntry::Uid(target))
        }
    }
}

/// Whether a decision permits, by the request path's own fold and discharge.
pub(crate) fn permits(d: &maknae_security::Decided) -> bool {
    match maknae_security::finalize(maknae_security::combine(vec![d.verdict.clone()])) {
        maknae_security::Decision::Permit { obligations } => {
            crate::handler::discharge_plan(&obligations).is_ok()
        }
        maknae_security::Decision::Deny { .. } => false,
    }
}

/// The probes' answers: whether the requester holds admin.release, and each candidate subject's.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Probed {
    pub self_holds: Option<bool>,
    pub releasers: Option<Vec<bool>>,
}

/// Why the probes gave no answer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum ProbeError {
    Busy,
    Failed(String),
}

/// The uids to probe for admin.release; a candidate that lists no subjects gives no answer.
pub(crate) fn releaser_uids(
    entries: Option<Vec<maknae_authz_basic::ListedSubject>>,
) -> Result<Vec<u32>, ProbeError> {
    entries
        .map(|e| e.iter().filter_map(|s| s.uid).collect())
        .ok_or_else(|| ProbeError::Failed("the candidate lists no subjects to probe".into()))
}

/// The operator contain's checks: self-contain first, then the last releaser.
pub(crate) fn check_contain(
    target: u32,
    requester: Option<u32>,
    probed: Result<Probed, ProbeError>,
) -> Result<(), LiveRefusal> {
    let p = match probed {
        Ok(p) => p,
        Err(ProbeError::Busy) => return Err(LiveRefusal::Busy),
        Err(ProbeError::Failed(why)) => return Err(LiveRefusal::Failed(why)),
    };
    if requester == Some(target) {
        match p.self_holds {
            Some(true) => {}
            Some(false) => return Err(LiveRefusal::SelfContainWithoutRelease),
            None => {
                return Err(LiveRefusal::Failed(
                    "the self-contain probe gave no answer".into(),
                ))
            }
        }
    }
    match p.releasers {
        Some(v) if v.iter().any(|&holds| holds) => Ok(()),
        Some(_) => Err(LiveRefusal::LastReleaser),
        None => Err(LiveRefusal::Failed(
            "the releaser probe gave no answer".into(),
        )),
    }
}

/// The check a request of `kind` runs in the turn.
pub(crate) fn check_for(kind: Kind, target: u32, requester: u32) -> LiveCheck {
    match kind {
        Kind::Release => LiveCheck::None,
        Kind::Contain => LiveCheck::Contain { target, requester },
        Kind::KernelContain => LiveCheck::KernelContain { target },
    }
}

/// A release by uid; its claimant names are resolved under the turn.
pub(crate) fn release_op(uid: u32, named: Option<String>) -> LiveOp {
    LiveOp::Release { uid, named }
}

/// Applies the shared operand rule to a containment verb's operands, in place.
pub(crate) fn normalise_operands(verb: &mut Verb) -> Result<(), (&'static str, OperandError)> {
    match verb {
        Verb::AdminContain { target, reason } => {
            *target = maknae_proto::contain_target(target).map_err(|e| ("contain", e))?;
            *reason = maknae_proto::contain_reason(reason.as_str())
                .map_err(|e| ("contain", e))?
                .into();
        }
        Verb::AdminRelease { target } => {
            *target = maknae_proto::contain_target(target).map_err(|e| ("release", e))?;
        }
        _ => {}
    }
    Ok(())
}

/// `r` in double quotes with only `\` and `"` escaped; for operand-rule-validated text.
pub(crate) fn quoted(r: &str) -> String {
    format!("\"{}\"", r.replace('\\', "\\\\").replace('"', "\\\""))
}

/// The verb whose action is `admin.release`; its operand never reaches the PDP.
pub(crate) fn release_probe() -> Verb {
    Verb::AdminRelease {
        target: ContainTarget::Uid(0),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use maknae_graph::identity::{IdentityLayer, SubjectEntry};
    use maknae_proto::ContainmentOutcome;
    use std::collections::BTreeMap;

    fn probed(
        self_holds: Option<bool>,
        releasers: Option<Vec<bool>>,
    ) -> Result<Probed, ProbeError> {
        Ok(Probed {
            self_holds,
            releasers,
        })
    }

    fn layer_with(s: &[(u32, &str, &str)]) -> IdentityLayer {
        IdentityLayer {
            subjects: s
                .iter()
                .map(|&(uid, name, role)| SubjectEntry {
                    uid,
                    name: name.into(),
                    role: role.into(),
                })
                .collect(),
            ..Default::default()
        }
    }

    #[test]
    fn self_contain_needs_release_and_is_checked_before_the_releasers() {
        assert_eq!(
            check_contain(501, Some(501), probed(Some(false), None)),
            Err(LiveRefusal::SelfContainWithoutRelease)
        );
        assert_eq!(
            check_contain(501, Some(501), probed(Some(false), Some(vec![true]))),
            Err(LiveRefusal::SelfContainWithoutRelease)
        );
        assert_eq!(
            check_contain(501, Some(501), probed(Some(true), Some(vec![true]))),
            Ok(())
        );
        assert!(
            matches!(
                check_contain(501, Some(501), probed(None, Some(vec![true]))),
                Err(LiveRefusal::Failed(_))
            ),
            "a self-contain with no self answer fails closed"
        );
    }

    #[test]
    fn a_contain_of_another_needs_no_self_answer() {
        assert_eq!(
            check_contain(1003, Some(501), probed(None, Some(vec![false, true]))),
            Ok(())
        );
        assert_eq!(
            check_contain(1003, None, probed(None, Some(vec![true]))),
            Ok(())
        );
    }

    #[test]
    fn no_permitted_releaser_in_the_candidate_refuses_and_a_missing_answer_fails_closed() {
        for v in [vec![], vec![false], vec![false, false]] {
            assert_eq!(
                check_contain(1003, Some(501), probed(None, Some(v.clone()))),
                Err(LiveRefusal::LastReleaser),
                "{v:?}"
            );
        }
        assert!(matches!(
            check_contain(1003, None, probed(None, None)),
            Err(LiveRefusal::Failed(_))
        ));
        assert_eq!(
            check_contain(1, None, Err(ProbeError::Busy)),
            Err(LiveRefusal::Busy)
        );
        assert!(matches!(
            check_contain(1, None, Err(ProbeError::Failed("timed out".into()))),
            Err(LiveRefusal::Failed(_))
        ));
    }

    #[test]
    fn a_candidate_without_subjects_fails_the_probe_rather_than_finding_no_releaser() {
        use maknae_authz_basic::{ListedSubject, SubjectState};
        assert!(matches!(releaser_uids(None), Err(ProbeError::Failed(_))));
        let listed = |uid| ListedSubject {
            uid,
            names: Vec::new(),
            state: SubjectState::Bound("admin"),
        };
        assert_eq!(
            releaser_uids(Some(vec![listed(Some(3)), listed(None), listed(Some(5))])),
            Ok(vec![3, 5])
        );
        assert_eq!(releaser_uids(Some(Vec::new())), Ok(Vec::new()));
    }

    #[test]
    fn a_failed_probe_keeps_its_cause() {
        assert_eq!(
            check_contain(1, None, Err(ProbeError::Failed("timed out".into()))),
            Err(LiveRefusal::Failed("timed out".into()))
        );
    }

    #[test]
    fn a_release_runs_no_check_and_only_the_operator_contain_checks_the_releasers() {
        assert_eq!(check_for(Kind::Release, 7, 501), LiveCheck::None);
        assert_eq!(
            check_for(Kind::Contain, 7, 501),
            LiveCheck::Contain {
                target: 7,
                requester: 501
            }
        );
        assert_eq!(
            check_for(Kind::KernelContain, 7, 501),
            LiveCheck::KernelContain { target: 7 }
        );
    }

    #[test]
    fn a_release_defers_its_claimants_to_the_turn() {
        assert_eq!(
            release_op(7, Some("mal".into())),
            LiveOp::Release {
                uid: 7,
                named: Some("mal".into())
            }
        );
        assert_eq!(
            release_op(7, None),
            LiveOp::Release {
                uid: 7,
                named: None
            }
        );
        assert_ne!(
            release_op(7, None),
            LiveOp::Edit(maknae_config::LiveEdit::ReleaseUid {
                uid: 7,
                names: Default::default()
            }),
            "a release never carries a claimant set computed before the turn"
        );
    }

    #[test]
    fn operands_are_normalised_in_place_by_the_shared_rule() {
        let mut v = maknae_proto::Verb::AdminContain {
            target: maknae_proto::ContainTarget::Name("\u{1112}\u{1161}\u{11ab}".into()),
            reason: "e\u{301}".into(),
        };
        assert_eq!(normalise_operands(&mut v), Ok(()));
        assert_eq!(
            v,
            maknae_proto::Verb::AdminContain {
                target: maknae_proto::ContainTarget::Name("\u{d55c}".into()),
                reason: "\u{e9}".into()
            }
        );
        let mut bad = maknae_proto::Verb::AdminRelease {
            target: maknae_proto::ContainTarget::Name("a\u{202e}".into()),
        };
        assert_eq!(
            normalise_operands(&mut bad),
            Err((
                "release",
                maknae_proto::OperandError::Format(maknae_proto::Operand::Name, 0x202e)
            ))
        );
        let mut ping = maknae_proto::Verb::Ping;
        assert_eq!(normalise_operands(&mut ping), Ok(()));
    }

    #[test]
    fn a_contain_operand_refusal_names_the_contain_verb_and_the_operand() {
        use maknae_proto::{ContainTarget, Operand, OperandError, Verb};
        let mut bad_target = Verb::AdminContain {
            target: ContainTarget::Name(" mal".into()),
            reason: "r".into(),
        };
        assert_eq!(
            normalise_operands(&mut bad_target),
            Err(("contain", OperandError::EdgeWhitespace))
        );
        let mut bad_reason = Verb::AdminContain {
            target: ContainTarget::Uid(7),
            reason: "a\u{7}".into(),
        };
        assert_eq!(
            normalise_operands(&mut bad_reason),
            Err(("contain", OperandError::Control(Operand::Reason, 7)))
        );
        let mut release = Verb::AdminRelease {
            target: ContainTarget::Name("\u{1112}\u{1161}\u{11ab}".into()),
        };
        assert_eq!(normalise_operands(&mut release), Ok(()));
        assert_eq!(
            release,
            Verb::AdminRelease {
                target: ContainTarget::Name("\u{d55c}".into())
            }
        );
    }

    #[test]
    fn permits_is_the_request_paths_own_test() {
        let ob = |id: &str| maknae_security::Obligation {
            id: id.into(),
            params: Default::default(),
        };
        let permit = maknae_security::Decided {
            verdict: maknae_security::Verdict::Permit {
                obligations: vec![ob("audit")],
            },
            role: None,
            rule: None,
        };
        assert!(permits(&permit));
        for v in [
            maknae_security::Verdict::Deny { reason: "x".into() },
            maknae_security::Verdict::NotApplicable { note: None },
            maknae_security::Verdict::Indeterminate,
        ] {
            assert!(!permits(&maknae_security::Decided {
                verdict: v,
                role: None,
                rule: None
            }));
        }
        let unhonorable = maknae_security::Decided {
            verdict: maknae_security::Verdict::Permit {
                obligations: vec![ob("notify")],
            },
            role: None,
            rule: None,
        };
        assert!(!permits(&unhonorable));
    }

    #[test]
    fn contained_is_read_from_the_stored_layer_including_carried_forward() {
        let layer = layer_with(&[
            (1003, "mallory", "adversary"),
            (1001, "alice", "admin"),
            (666, "uid:666", "adversary"),
        ]);
        assert!(is_contained(&layer, 1003) && is_contained(&layer, 666));
        assert!(!is_contained(&layer, 1001) && !is_contained(&layer, 7));
    }

    #[test]
    fn release_names_are_every_claim_on_the_uid_plus_the_named_one() {
        let claims: BTreeMap<String, u32> = [
            ("mallory".into(), 1003),
            ("mal".into(), 1003),
            ("eve".into(), 4242),
        ]
        .into();
        assert_eq!(
            release_names(1003, None, &claims),
            ["mal".to_string(), "mallory".into()].into()
        );
        assert_eq!(
            release_names(1003, Some("mally"), &claims),
            ["mal".to_string(), "mallory".into(), "mally".into()].into()
        );
        assert!(release_names(7, None, &claims).is_empty());
    }

    #[test]
    fn every_refusal_maps_to_its_code_and_record_class() {
        use ContainmentOutcome::*;
        assert_eq!(outcome(&LiveRefusal::Busy), Some(Busy));
        assert_eq!(outcome(&LiveRefusal::Failed("x".into())), None);
        assert_eq!(record_class(LastReleaser), ("deny", "refused"));
        assert_eq!(record_class(SelfContainWithoutRelease), ("deny", "refused"));
        assert_eq!(record_class(NoExplicitBindings), ("deny", "refused"));
        assert_eq!(record_class(UnknownAccount), ("deny", "refused"));
        assert_eq!(record_class(Busy), ("deny", "unavailable"));
        assert_eq!(record_class(Stopping), ("deny", "unavailable"));
        assert_eq!(record_class(LookupUnavailable), ("deny", "unavailable"));
        assert_eq!(record_class(AlreadyContained), ("permit", "unchanged"));
        assert_eq!(record_class(NotContained), ("permit", "unchanged"));
        assert_eq!(record_class(Contained), ("permit", "authorized"));
        assert_eq!(record_class(Released), ("permit", "authorized"));
    }

    #[test]
    fn every_live_refusal_but_a_failure_has_its_own_code() {
        use ContainmentOutcome as O;
        for (r, o) in [
            (LiveRefusal::Busy, O::Busy),
            (LiveRefusal::Stopping, O::Stopping),
            (LiveRefusal::NoExplicitBindings, O::NoExplicitBindings),
            (LiveRefusal::LastReleaser, O::LastReleaser),
            (
                LiveRefusal::SelfContainWithoutRelease,
                O::SelfContainWithoutRelease,
            ),
            (LiveRefusal::AlreadyContained, O::AlreadyContained),
            (LiveRefusal::NotContained, O::NotContained),
            (LiveRefusal::LookupUnavailable, O::LookupUnavailable),
        ] {
            assert_eq!(outcome(&r), Some(o), "{r:?}");
        }
    }

    fn section(yaml: &str) -> maknae_config::Section {
        maknae_config::Section::of(&maknae_config::parse_bindings(yaml).unwrap())
    }

    #[test]
    fn a_name_the_applied_load_never_answered_is_found_unless_the_edit_binds_it() {
        use maknae_config::{BindingEntry, BoundRole, LiveEdit};
        let live = section(
            "schema_version: 1\nbindings:\n  admin: [\"root\"]\n  adversary:\n    - \"mal\"\n    - uid: 7\n",
        );
        let release = LiveEdit::ReleaseUid {
            uid: 7,
            names: Default::default(),
        };
        assert_eq!(unanswered(&live, &release, |_| true), None);
        assert_eq!(
            unanswered(&live, &release, |n| n == "root"),
            Some("mal".into())
        );
        assert_eq!(
            unanswered(&live, &release, |n| n == "mal"),
            Some("root".into())
        );
        for own in [
            LiveEdit::Contain(BindingEntry::Name("mal".into())),
            LiveEdit::Bind {
                name: "mal".into(),
                role: BoundRole::Guest,
            },
        ] {
            assert_eq!(unanswered(&live, &own, |n| n == "root"), None, "{own:?}");
            assert_eq!(
                unanswered(&live, &own, |n| n == "mal"),
                Some("root".into()),
                "{own:?}"
            );
        }
        assert_eq!(
            unanswered(&live, &LiveEdit::Contain(BindingEntry::Uid(7)), |n| n
                == "root"),
            Some("mal".into())
        );
    }

    #[test]
    fn a_containment_check_guards_only_its_target_bound_by_uid() {
        use maknae_config::{BindingEntry, LiveEdit};
        let by_uid = LiveEdit::Contain(BindingEntry::Uid(7));
        let by_name = LiveEdit::Contain(BindingEntry::Name("mal".into()));
        for check in [
            LiveCheck::Contain {
                target: 7,
                requester: 0,
            },
            LiveCheck::KernelContain { target: 7 },
        ] {
            assert!(binds_target_by_uid(check, &by_uid), "{check:?}");
            assert!(!binds_target_by_uid(check, &by_name), "{check:?}");
            assert!(
                !binds_target_by_uid(check, &LiveEdit::Contain(BindingEntry::Uid(8))),
                "{check:?}"
            );
            assert!(
                !binds_target_by_uid(
                    check,
                    &LiveEdit::ReleaseUid {
                        uid: 7,
                        names: Default::default()
                    }
                ),
                "{check:?}"
            );
        }
        assert!(binds_target_by_uid(LiveCheck::None, &by_name));
    }

    #[test]
    fn corrective_reasons_name_the_code_and_escape_the_reason() {
        assert_eq!(corrective(Kind::Contain, ContainmentOutcome::LastReleaser, Some(1003), "", Some("a \"b\"")),
            "contain refused: last-releaser: containing uid 1003 would leave no uncontained subject holding admin.release; reason \"a \\\"b\\\"\"");
        assert_eq!(
            corrective(
                Kind::Contain,
                ContainmentOutcome::AlreadyContained,
                Some(1003),
                "",
                Some("r")
            ),
            "contain unchanged: uid 1003 is already contained; reason \"r\""
        );
        assert_eq!(
            corrective(
                Kind::Release,
                ContainmentOutcome::NotContained,
                Some(7),
                "",
                None
            ),
            "release unchanged: uid 7 is not contained"
        );
        assert_eq!(
            corrective(
                Kind::Contain,
                ContainmentOutcome::LookupUnavailable,
                None,
                "did not complete within 5000ms",
                Some("r")
            ),
            "contain refused: lookup-unavailable: did not complete within 5000ms; reason \"r\""
        );
    }

    #[test]
    fn corrective_texts_are_fixed_per_code_and_only_operational_causes_take_the_detail() {
        use ContainmentOutcome as O;
        assert_eq!(
            corrective(Kind::Contain, O::SelfContainWithoutRelease, Some(501), "ignored", None),
            "contain refused: self-contain-without-release: uid 501 does not hold admin.release and cannot contain itself"
        );
        assert_eq!(
            corrective(Kind::KernelContain, O::NoExplicitBindings, Some(7), "ignored", Some("r")),
            "kernel containment refused: no-explicit-bindings: bindings.yaml has no bindings: key; a live identity edit needs explicit bindings; reason \"r\""
        );
        assert_eq!(
            corrective(Kind::Contain, O::LastReleaser, Some(7), "ignored", None),
            "contain refused: last-releaser: containing uid 7 would leave no uncontained subject holding admin.release"
        );
        assert_eq!(
            corrective(
                Kind::KernelContain,
                O::AlreadyContained,
                Some(7),
                "ignored",
                None
            ),
            "kernel containment unchanged: uid 7 is already contained"
        );
        assert_eq!(
            corrective(Kind::Release, O::NotContained, Some(7), "ignored", None),
            "release unchanged: uid 7 is not contained"
        );
        for o in [
            O::Busy,
            O::Stopping,
            O::LookupUnavailable,
            O::UnknownAccount,
        ] {
            assert_eq!(
                corrective(Kind::Release, o, None, "the cause", None),
                format!("release refused: {}: the cause", o.code())
            );
            assert_eq!(
                corrective(Kind::Release, o, None, "", None),
                format!("release refused: {}: {}", o.code(), o.text())
            );
        }
        assert_eq!(
            corrective(
                Kind::Contain,
                O::UnknownAccount,
                None,
                "no account named mal\\,x",
                Some("r")
            ),
            "contain refused: unknown-account: no account named mal\\,x; reason \"r\""
        );
    }

    #[test]
    fn a_corrective_without_a_uid_names_the_subject() {
        assert_eq!(
            corrective(
                Kind::Contain,
                ContainmentOutcome::LastReleaser,
                None,
                "",
                None
            ),
            "contain refused: last-releaser: containing the subject would leave no uncontained subject holding admin.release"
        );
    }

    #[test]
    fn quoted_escapes_only_backslash_and_quote() {
        assert_eq!(quoted("plain"), "\"plain\"");
        assert_eq!(quoted("a\\\"b"), "\"a\\\\\\\"b\"");
        assert_eq!(quoted("\\\""), "\"\\\\\\\"\"");
        assert_eq!(
            quoted("\u{d1a0}\u{d070} \u{e9}"),
            "\"\u{d1a0}\u{d070} \u{e9}\""
        );
    }

    #[test]
    fn the_release_probe_asks_for_admin_release_with_no_target() {
        let v = release_probe();
        assert_eq!(
            v,
            maknae_proto::Verb::AdminRelease {
                target: maknae_proto::ContainTarget::Uid(0)
            }
        );
        assert_eq!(crate::handler::verb_to_action(&v), "admin.release");
    }

    #[test]
    fn an_empty_note_carries_nothing() {
        let n = LiveNote::none();
        assert_eq!((n.requester, n.reason), (None, None));
    }
}
