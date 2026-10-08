//! What `maknaed` records and publishes for the per-subject identity problems of a
//! policy load (#496): one `graph.identity` record per problem, counts by kind for
//! `admin.status`, and the subject detail for `admin.subject.list`.

use maknae_authz_basic::snapshot::Snapshot;
use maknae_authz_basic::{shown, IdentityProblem, ListedSubject, SubjectState};
use maknae_proto::RoleBindingView;
use maknae_security::SubjectBinding;
use std::collections::BTreeMap;
use std::sync::{Arc, PoisonError, RwLock};

pub const GRAPH_IDENTITY_ACTION: &str = "graph.identity";

const ADVERSARY: &str = "adversary";

/// `(result, reason, posture)` of one problem's audit record.
pub fn record_fields(p: &IdentityProblem) -> (&'static str, String, &'static str) {
    match p {
        IdentityProblem::Released { .. } => ("permit", p.to_string(), "authorized"),
        IdentityProblem::UnresolvedAdversary { .. } => ("deny", p.to_string(), "unavailable"),
        _ => ("deny", p.to_string(), "unauthorized"),
    }
}

/// The store writes each release ahead of the persist that makes it, so no release
/// is recorded here.
fn recordable(p: &&IdentityProblem) -> bool {
    !matches!(p, IdentityProblem::Released { .. })
}

/// `<kind>=<count>` per kind present, in kind order.
pub fn counts(problems: &[IdentityProblem]) -> Vec<String> {
    let mut by_kind: BTreeMap<&'static str, usize> = BTreeMap::new();
    for p in problems {
        *by_kind.entry(p.kind()).or_default() += 1;
    }
    by_kind
        .into_iter()
        .map(|(kind, n)| format!("{kind}={n}"))
        .collect()
}

/// The problems a reload records: those of the applied load that the load before it
/// did not have, so each is recorded once; none for a refused reload.
pub fn recorded_after(
    r: &Result<crate::reload::Applied, crate::reload::Refusal>,
    previous: &[IdentityProblem],
    current: &[IdentityProblem],
) -> Vec<IdentityProblem> {
    match r {
        Ok(_) => current
            .iter()
            .filter(recordable)
            .filter(|p| !previous.contains(p))
            .cloned()
            .collect(),
        Err(_) => Vec::new(),
    }
}

/// Publishes `published`, then hands each recordable problem of `to_record` to
/// `emit` in order, with one journal line each, stopping at the first failed append.
pub async fn publish_and_record<F, Fut, E>(
    status: &IdentityStatus,
    published: Published,
    to_record: &[IdentityProblem],
    mut emit: F,
) -> Result<(), E>
where
    F: FnMut(&'static str, String, &'static str) -> Fut,
    Fut: std::future::Future<Output = Result<(), E>>,
{
    let _ = status.publish(published);
    for p in to_record.iter().filter(recordable) {
        let (result, reason, posture) = record_fields(p);
        eprintln!("maknaed: identity: {reason}");
        emit(result, reason, posture).await?;
    }
    Ok(())
}

/// What one applied load leaves for `admin.status` and `admin.subject.list`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Published {
    problems: Arc<[IdentityProblem]>,
    subjects: Arc<[ListedSubject]>,
}

impl Published {
    /// The snapshot's problems followed by `released`, and the snapshot's subjects.
    pub fn of(snapshot: &Snapshot, released: impl IntoIterator<Item = IdentityProblem>) -> Self {
        Self {
            problems: snapshot
                .identity_problems()
                .iter()
                .cloned()
                .chain(released)
                .collect(),
            subjects: snapshot.subject_entries().unwrap_or_default().into(),
        }
    }
}

/// Replaced whole at boot and at each applied reload.
#[derive(Debug, Clone, Default)]
pub struct IdentityStatus(Arc<RwLock<Published>>);

impl IdentityStatus {
    /// Returns the problems it replaced.
    pub fn publish(&self, published: Published) -> Arc<[IdentityProblem]> {
        std::mem::replace(
            &mut *self.0.write().unwrap_or_else(PoisonError::into_inner),
            published,
        )
        .problems
    }

    fn get(&self) -> Published {
        self.0
            .read()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }

    pub fn current(&self) -> Arc<[IdentityProblem]> {
        self.get().problems
    }

    pub fn counts(&self) -> Vec<String> {
        counts(&self.get().problems)
    }

    pub fn subjects(&self) -> Arc<[ListedSubject]> {
        self.get().subjects
    }
}

/// Escaped; the uid and names are the load's, never a live account lookup.
pub fn label(s: &ListedSubject) -> String {
    let names = s
        .names
        .iter()
        .map(|n| shown(n))
        .collect::<Vec<_>>()
        .join(", ");
    match (&s.state, s.uid) {
        (SubjectState::Unresolved(_), _) | (_, None) => format!("{names} (no account)"),
        (SubjectState::CarriedForward | SubjectState::Unbound(_), Some(u)) => {
            format!("uid {u} ({names})")
        }
        (_, Some(u)) if names.is_empty() => format!("uid {u}"),
        (_, Some(u)) => format!("{names} (uid {u})"),
    }
}

pub fn state(s: &ListedSubject) -> String {
    match &s.state {
        SubjectState::Bound(role) => format!("bound {role}"),
        SubjectState::Contained => "contained".into(),
        SubjectState::CarriedForward => "contained (carried forward)".into(),
        SubjectState::Unbound(roles) => format!("unbound (conflict: {})", roles.join(", ")),
        SubjectState::Unresolved(ADVERSARY) => {
            "unresolved adversary (no account, not contained)".into()
        }
        SubjectState::Unresolved(_) => "unresolved (no account)".into(),
    }
}

/// The role a subject is bound under, or for an unresolved name the role it is
/// listed under; `None` for an unbound subject.
fn role_of(s: &ListedSubject) -> Option<&'static str> {
    match &s.state {
        SubjectState::Bound(role) | SubjectState::Unresolved(role) => Some(role),
        SubjectState::Contained | SubjectState::CarriedForward => Some(ADVERSARY),
        SubjectState::Unbound(_) => None,
    }
}

fn binds(s: &ListedSubject) -> bool {
    matches!(
        s.state,
        SubjectState::Bound(_) | SubjectState::Contained | SubjectState::CarriedForward
    )
}

fn view(s: &ListedSubject, role: String, members: Vec<String>) -> RoleBindingView {
    RoleBindingView {
        role,
        members,
        uid: s.uid,
        label: label(s),
        state: state(s),
    }
}

/// One entry per subject: each member of the PDP's `bindings`, described by the
/// published load where that load agrees on its role, then every listed subject
/// that holds no binding.
pub fn subject_views(
    bindings: Vec<SubjectBinding>,
    listed: &[ListedSubject],
) -> Vec<RoleBindingView> {
    let mut out = Vec::new();
    for b in bindings {
        for m in b.members {
            let known = listed.iter().find(|s| {
                binds(s)
                    && s.uid.is_some_and(|u| m == format!("uid:{u}"))
                    && role_of(s) == Some(b.role.as_str())
            });
            out.push(match known {
                Some(s) => view(s, b.role.clone(), vec![m]),
                None => {
                    let uid = m.strip_prefix("uid:").and_then(|u| u.parse().ok());
                    RoleBindingView {
                        uid,
                        label: uid.map_or_else(|| shown(&m), |u| format!("uid {u}")),
                        state: if b.role == ADVERSARY {
                            "contained".into()
                        } else {
                            format!("bound {}", shown(&b.role))
                        },
                        role: b.role.clone(),
                        members: vec![m],
                    }
                }
            });
        }
    }
    for s in listed.iter().filter(|s| !binds(s)) {
        out.push(view(
            s,
            role_of(s).unwrap_or_default().to_string(),
            Vec::new(),
        ));
    }
    out.sort_by(|a, b| (a.uid.is_none(), a.uid, &a.label).cmp(&(b.uid.is_none(), b.uid, &b.label)));
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn all() -> Vec<IdentityProblem> {
        vec![
            IdentityProblem::Unresolved {
                role: "user",
                name: "ghost".into(),
            },
            IdentityProblem::UnresolvedAdversary {
                name: "ghost2".into(),
            },
            IdentityProblem::Contained {
                uid: 0,
                names: vec!["root".into(), "toor".into()],
                roles: vec!["admin", "adversary"],
            },
            IdentityProblem::Unbound {
                uid: 1002,
                names: vec!["gus".into()],
                roles: vec!["guest", "user"],
            },
            IdentityProblem::CarriedForward {
                uid: 666,
                name: "mallory".into(),
                overrides: vec![("bob".into(), "user")],
            },
            IdentityProblem::Released {
                uid: 667,
                name: "trudy".into(),
                cause: "its name is no longer listed under adversary".into(),
            },
        ]
    }

    fn listed(uid: Option<u32>, names: &[&str], state: SubjectState) -> ListedSubject {
        ListedSubject {
            uid,
            names: names.iter().map(|n| n.to_string()).collect(),
            state,
        }
    }

    #[test]
    fn every_problem_is_a_deny_except_a_release_and_an_unapplied_containment_is_unavailable() {
        let postures: Vec<(&str, &str)> = all()
            .iter()
            .map(|p| {
                let (r, _, posture) = record_fields(p);
                (r, posture)
            })
            .collect();
        assert_eq!(
            postures,
            [
                ("deny", "unauthorized"),
                ("deny", "unavailable"),
                ("deny", "unauthorized"),
                ("deny", "unauthorized"),
                ("deny", "unauthorized"),
                ("permit", "authorized")
            ]
        );
        for p in all() {
            assert_eq!(record_fields(&p).1, p.to_string());
        }
        assert_eq!(GRAPH_IDENTITY_ACTION, "graph.identity");
    }

    #[test]
    fn counts_are_per_kind_and_carry_no_name_or_uid() {
        let mut problems = all();
        problems.push(IdentityProblem::Unresolved {
            role: "admin",
            name: "ghost3".into(),
        });
        assert_eq!(
            counts(&problems),
            [
                "carried_forward=1",
                "contained=1",
                "released=1",
                "unbound_conflict=1",
                "unresolved=2",
                "unresolved_adversary=1"
            ]
        );
        assert!(counts(&[]).is_empty());
    }

    #[test]
    fn a_reload_records_only_the_problems_its_load_added_and_a_refused_one_none() {
        let p = all();
        let ok = Ok(crate::reload::Applied {
            revision: 3,
            persisted: false,
            durability_error: None,
            checkpoint_error: None,
        });
        assert_eq!(recorded_after(&ok, &[], &p), p[..5], "never a release");
        assert_eq!(
            recorded_after(&ok, &p[1..3], &p),
            [&p[0], &p[3], &p[4]].map(Clone::clone)
        );
        assert!(
            recorded_after(&ok, &p, &p).is_empty(),
            "an unchanged load records nothing"
        );
        assert!(recorded_after(&Err(crate::reload::Refusal::Load("x".into())), &[], &p).is_empty());
    }

    #[test]
    fn the_pseudo_action_is_registered() {
        assert!(crate::run::GRAPH_PSEUDO_ACTIONS.contains(&GRAPH_IDENTITY_ACTION));
    }

    fn published(problems: Vec<IdentityProblem>) -> Published {
        Published {
            problems: problems.into(),
            subjects: Arc::from(vec![listed(Some(1), &["a"], SubjectState::Bound("user"))]),
        }
    }

    #[tokio::test]
    async fn publish_and_record_publishes_first_then_records_in_order_and_stops_at_a_failure() {
        let s = IdentityStatus::default();
        let seen = std::sync::Mutex::new(Vec::new());
        let ok: Result<(), String> =
            publish_and_record(&s, published(all()), &all(), |result, reason, posture| {
                seen.lock().unwrap().push((result, reason, posture));
                async { Ok(()) }
            })
            .await;
        assert_eq!(ok, Ok(()));
        let got = seen.lock().unwrap().clone();
        assert_eq!(
            got.iter().map(|r| r.1.clone()).collect::<Vec<_>>(),
            all()[..5]
                .iter()
                .map(ToString::to_string)
                .collect::<Vec<_>>(),
            "every problem once, in order, and never a release"
        );
        assert_eq!(got[1].2, "unavailable");
        let calls = std::sync::atomic::AtomicUsize::new(0);
        let failed = publish_and_record(&s, published(all()), &all(), |_, _, _| {
            calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            async { Err("disk") }
        })
        .await;
        assert_eq!(failed, Err("disk"));
        assert_eq!(
            calls.load(std::sync::atomic::Ordering::SeqCst),
            1,
            "stops at the first failure"
        );
        assert_eq!(s.current().len(), 6, "published before recording");
        assert_eq!(s.subjects().len(), 1);
    }

    #[test]
    fn the_status_is_replaced_whole() {
        let s = IdentityStatus::default();
        assert!(s.current().is_empty() && s.counts().is_empty() && s.subjects().is_empty());
        s.publish(published(all()));
        assert_eq!(s.counts().len(), 6);
        assert_eq!(s.subjects().len(), 1);
        let shared = s.clone();
        assert_eq!(
            s.publish(Published::default()).len(),
            6,
            "returns what it replaced"
        );
        assert!(
            shared.current().is_empty() && shared.subjects().is_empty(),
            "clones share one set"
        );
    }

    #[test]
    fn each_state_has_its_label_and_state_text() {
        let cases = [
            (
                listed(Some(1001), &["alice"], SubjectState::Bound("user")),
                "alice (uid 1001)",
                "bound user",
            ),
            (
                listed(Some(1234), &[], SubjectState::Contained),
                "uid 1234",
                "contained",
            ),
            (
                listed(Some(1003), &["eve"], SubjectState::Contained),
                "eve (uid 1003)",
                "contained",
            ),
            (
                listed(Some(666), &["mallory"], SubjectState::CarriedForward),
                "uid 666 (mallory)",
                "contained (carried forward)",
            ),
            (
                listed(None, &["ghost"], SubjectState::Unresolved("user")),
                "ghost (no account)",
                "unresolved (no account)",
            ),
            (
                listed(None, &["trudy"], SubjectState::Unresolved("adversary")),
                "trudy (no account)",
                "unresolved adversary (no account, not contained)",
            ),
            (
                listed(
                    Some(1002),
                    &["gus", "gustav"],
                    SubjectState::Unbound(vec!["guest", "user"]),
                ),
                "uid 1002 (gus, gustav)",
                "unbound (conflict: guest, user)",
            ),
        ];
        for (s, l, st) in cases {
            assert_eq!((label(&s), state(&s)), (l.to_string(), st.to_string()));
        }
    }

    #[test]
    fn a_label_escapes_control_characters_and_commas_in_a_persisted_name() {
        let s = listed(Some(7), &["é\u{7f},x\u{1b}[2J"], SubjectState::Contained);
        assert_eq!(label(&s), "\\u{e9}\\u{7f}\\,x\\u{1b}[2J (uid 7)");
        let u = listed(None, &["a\nb"], SubjectState::Unresolved("adversary"));
        assert_eq!(label(&u), "a\\nb (no account)");
        assert!(label(&s).chars().all(|c| c.is_ascii_graphic() || c == ' '));
    }

    fn binding(role: &str, members: &[&str]) -> SubjectBinding {
        SubjectBinding {
            role: role.into(),
            members: members.iter().map(|m| m.to_string()).collect(),
        }
    }

    type Row<'a> = (&'a str, Vec<String>, Option<u32>, &'a str, &'a str);

    #[test]
    fn the_list_is_one_entry_per_subject_bound_or_not() {
        let table = [
            listed(Some(666), &["mallory"], SubjectState::CarriedForward),
            listed(Some(1000), &["alex"], SubjectState::Bound("admin")),
            listed(
                Some(1002),
                &["gus", "gustav"],
                SubjectState::Unbound(vec!["guest", "user"]),
            ),
            listed(Some(4242), &[], SubjectState::Contained),
            listed(None, &["ghost"], SubjectState::Unresolved("user")),
            listed(None, &["trudy"], SubjectState::Unresolved("adversary")),
        ];
        let got = subject_views(
            vec![
                binding("admin", &["uid:1000"]),
                binding("adversary", &["uid:4242", "uid:666"]),
            ],
            &table,
        );
        let rows: Vec<Row> = got
            .iter()
            .map(|v| {
                (
                    v.role.as_str(),
                    v.members.clone(),
                    v.uid,
                    v.label.as_str(),
                    v.state.as_str(),
                )
            })
            .collect();
        assert_eq!(
            rows,
            [
                (
                    "adversary",
                    vec!["uid:666".to_string()],
                    Some(666),
                    "uid 666 (mallory)",
                    "contained (carried forward)"
                ),
                (
                    "admin",
                    vec!["uid:1000".to_string()],
                    Some(1000),
                    "alex (uid 1000)",
                    "bound admin"
                ),
                (
                    "",
                    vec![],
                    Some(1002),
                    "uid 1002 (gus, gustav)",
                    "unbound (conflict: guest, user)"
                ),
                (
                    "adversary",
                    vec!["uid:4242".to_string()],
                    Some(4242),
                    "uid 4242",
                    "contained"
                ),
                (
                    "user",
                    vec![],
                    None,
                    "ghost (no account)",
                    "unresolved (no account)"
                ),
                (
                    "adversary",
                    vec![],
                    None,
                    "trudy (no account)",
                    "unresolved adversary (no account, not contained)"
                ),
            ]
        );
    }

    #[test]
    fn a_member_the_load_does_not_describe_is_listed_from_the_binding_alone() {
        let table = [listed(Some(1000), &["alex"], SubjectState::Bound("user"))];
        let got = subject_views(
            vec![
                binding("admin", &["uid:1000", "op\u{7}"]),
                binding("adversary", &["uid:5"]),
            ],
            &table,
        );
        let rows: Vec<(Option<u32>, &str, &str)> = got
            .iter()
            .map(|v| (v.uid, v.label.as_str(), v.state.as_str()))
            .collect();
        assert_eq!(
            rows,
            [
                (Some(5), "uid 5", "contained"),
                (Some(1000), "uid 1000", "bound admin"),
                (None, "op\\u{7}", "bound admin"),
            ],
            "a role the load disagrees on is not described by it"
        );
        assert!(subject_views(vec![], &[]).is_empty());
    }
}
