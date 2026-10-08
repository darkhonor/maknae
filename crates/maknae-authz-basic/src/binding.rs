//! Subject → role binding resolution (#85, #496; spec §3/§3a/§3b).
//!
//! Identity semantics (ADR-0018: the per-request authorization principal is
//! the **uid**): `bindings.yaml` entries are usernames resolved to uids once per
//! policy load (the `UidMap`), or `uid:` entries under `adversary`; **matching
//! is uid vs uid, with no exception.** `agent` is an ordinary username
//! ([ADR-0024](../../../design/adr/ADR-0024-tenancy-model-and-agent-identity.md)
//! decision 3, #276).
//!
//! A file-level defect (unknown role key, one entry twice in one list, a `uid:`
//! entry outside `adversary`) refuses the whole file. Resolution outcomes are
//! per subject and reported as [`IdentityProblem`]s: a name with no account
//! holds no role, a uid under `adversary` and another role is contained, and a
//! uid under two other roles holds none.

use crate::role::Role;
use maknae_graph::graph::Graph;
use maknae_graph::identity::{bindings_section_key, subject_key};
use maknae_graph::kernel::{ADVERSARY, ATTR_NAME, ATTR_UID, BINDS, CONTAINED, SECTION, SUBJECT};
use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

/// username → uid, built once per policy load (start or reload) via getpwnam.
pub(crate) type UidMap = BTreeMap<String, u32>;

/// Why `bindings.yaml` is refused as a whole. Every variant names the offending
/// token so the refusal is actionable.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum BindingError {
    UnknownRole(String),
    Duplicate(String),
    UidOutsideAdversary(String),
}

impl std::fmt::Display for BindingError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            BindingError::UnknownRole(k) => write!(f, "bindings names unknown role '{k}'"),
            BindingError::Duplicate(n) => write!(f, "identity '{n}' listed twice in one role"),
            BindingError::UidOutsideAdversary(k) => write!(
                f,
                "role '{k}' lists a uid entry; `uid:` entries are accepted under adversary only"
            ),
        }
    }
}

/// A subject `bindings.yaml` names that could not be bound as written. Each is
/// decided for that subject alone; the rest of the policy loads.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum IdentityProblem {
    Unresolved {
        role: &'static str,
        name: String,
    },
    UnresolvedAdversary {
        name: String,
    },
    Contained {
        uid: u32,
        names: Vec<String>,
        roles: Vec<&'static str>,
    },
    Unbound {
        uid: u32,
        names: Vec<String>,
        roles: Vec<&'static str>,
    },
    CarriedForward {
        uid: u32,
        name: String,
        overrides: Vec<(String, &'static str)>,
    },
    Released {
        uid: u32,
        name: String,
        cause: String,
    },
}

/// A name as a problem's text prints it: `escape_default`, then `,` as `\,`. A name
/// persisted before #496 was never validated.
pub fn shown(name: &str) -> String {
    name.escape_default().to_string().replace(',', "\\,")
}

fn joined(names: &[String]) -> String {
    names
        .iter()
        .map(|n| shown(n))
        .collect::<Vec<_>>()
        .join(", ")
}

impl From<&maknae_graph::identity::Released> for IdentityProblem {
    fn from(r: &maknae_graph::identity::Released) -> Self {
        Self::Released {
            uid: r.uid,
            name: r.name.clone(),
            cause: r.cause.to_string(),
        }
    }
}

impl IdentityProblem {
    pub fn kind(&self) -> &'static str {
        match self {
            Self::Unresolved { .. } => "unresolved",
            Self::UnresolvedAdversary { .. } => "unresolved_adversary",
            Self::Contained { .. } => "contained",
            Self::Unbound { .. } => "unbound_conflict",
            Self::CarriedForward { .. } => "carried_forward",
            Self::Released { .. } => "released",
        }
    }

    pub fn uid(&self) -> Option<u32> {
        match self {
            Self::Unresolved { .. } | Self::UnresolvedAdversary { .. } => None,
            Self::Contained { uid, .. }
            | Self::Unbound { uid, .. }
            | Self::CarriedForward { uid, .. }
            | Self::Released { uid, .. } => Some(*uid),
        }
    }

    pub fn names(&self) -> Vec<String> {
        match self {
            Self::Unresolved { name, .. } | Self::UnresolvedAdversary { name } => {
                vec![name.clone()]
            }
            Self::Contained { names, .. } | Self::Unbound { names, .. } => names.clone(),
            Self::CarriedForward {
                name, overrides, ..
            } => std::iter::once(name.clone())
                .chain(overrides.iter().map(|(n, _)| n.clone()))
                .collect(),
            Self::Released { name, .. } => vec![name.clone()],
        }
    }

    pub fn roles(&self) -> Vec<&'static str> {
        match self {
            Self::Unresolved { role, .. } => vec![*role],
            Self::UnresolvedAdversary { .. } => vec![ADVERSARY],
            Self::Contained { roles, .. } | Self::Unbound { roles, .. } => roles.clone(),
            Self::CarriedForward { overrides, .. } => std::iter::once(ADVERSARY)
                .chain(overrides.iter().map(|(_, r)| *r))
                .collect(),
            Self::Released { .. } => vec![ADVERSARY],
        }
    }
}

impl std::fmt::Display for IdentityProblem {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Unresolved { role, name } => write!(
                f,
                "'{}' under {role} has no account on this host; it holds no role",
                shown(name)
            ),
            Self::UnresolvedAdversary { name } => write!(
                f,
                "'{}' under adversary has no account on this host; nothing is contained for it (write \"- uid: <n>\" to contain an id that has no account)",
                shown(name)
            ),
            Self::Contained { uid, names, roles } => write!(
                f,
                "uid {uid} ({}) is under {}; containment wins and it is contained",
                joined(names),
                roles.join(", ")
            ),
            Self::Unbound { uid, names, roles } => write!(
                f,
                "uid {uid} ({}) is under {}; it holds no role",
                joined(names),
                roles.join(", ")
            ),
            Self::CarriedForward {
                uid,
                name,
                overrides,
            } => {
                write!(
                    f,
                    "'{}' under adversary no longer resolves; uid {uid} stays contained (carried forward)",
                    shown(name)
                )?;
                if !overrides.is_empty() {
                    let o: Vec<String> = overrides
                        .iter()
                        .map(|(n, r)| format!("{} ({r})", shown(n)))
                        .collect();
                    write!(f, "; this overrides {}", o.join(", "))?;
                }
                Ok(())
            }
            Self::Released { uid, name, cause } => write!(
                f,
                "uid {uid} ('{}') is no longer contained: {cause}",
                shown(name)
            ),
        }
    }
}

/// The subjects one load binds, in uid order, and the problems it reported.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Resolved {
    pub(crate) subjects: Vec<(u32, Role, String)>,
    pub(crate) problems: Vec<IdentityProblem>,
}

/// Resolve `bindings.yaml` against the load's `UidMap`, one subject at a time.
pub(crate) fn resolve_subjects(
    bindings: &maknae_config::Bindings,
    lookup: &UidMap,
) -> Result<Resolved, BindingError> {
    use maknae_config::BindingEntry;
    let mut out = Resolved {
        subjects: Vec::new(),
        problems: Vec::new(),
    };
    let Some(map) = &bindings.roles else {
        return Ok(out);
    };
    let mut by_uid: BTreeMap<u32, Vec<(Role, String)>> = BTreeMap::new();
    for (key, entries) in map {
        let role = Role::from_key(key).ok_or_else(|| BindingError::UnknownRole(key.clone()))?;
        let mut seen = BTreeSet::new();
        for e in entries {
            let name = e.render();
            if !seen.insert(name.clone()) {
                return Err(BindingError::Duplicate(name));
            }
            let uid = match e {
                BindingEntry::Uid(_) if role != Role::Adversary => {
                    return Err(BindingError::UidOutsideAdversary(key.clone()))
                }
                BindingEntry::Uid(u) => Some(*u),
                BindingEntry::Name(n) => lookup.get(n).copied(),
            };
            match uid {
                Some(u) => by_uid.entry(u).or_default().push((role, name)),
                None if role == Role::Adversary => out
                    .problems
                    .push(IdentityProblem::UnresolvedAdversary { name }),
                None => out.problems.push(IdentityProblem::Unresolved {
                    role: role.key(),
                    name,
                }),
            }
        }
    }
    for (uid, held) in by_uid {
        let mut roles: Vec<&'static str> = held.iter().map(|(r, _)| r.key()).collect();
        roles.sort_unstable();
        roles.dedup();
        let mut names: Vec<String> = Vec::new();
        for (_, n) in &held {
            if !names.contains(n) {
                names.push(n.clone());
            }
        }
        if let Some((_, first)) = held.iter().find(|(r, _)| *r == Role::Adversary) {
            out.subjects.push((uid, Role::Adversary, first.clone()));
            if roles.len() > 1 {
                out.problems
                    .push(IdentityProblem::Contained { uid, names, roles });
            }
        } else if roles.len() == 1 {
            out.subjects.push((uid, held[0].0, held[0].1.clone()));
        } else {
            out.problems
                .push(IdentityProblem::Unbound { uid, names, roles });
        }
    }
    Ok(out)
}

/// The outcome of subject resolution.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Resolution {
    Role(Role),
    NoRole,
}

/// Subject resolution by graph hops over a compiled snapshot's identity layer.
#[derive(Clone, Debug)]
pub(crate) struct GraphBindings {
    graph: Arc<Graph>,
    explicit: bool,
}

impl GraphBindings {
    pub(crate) fn new(graph: Arc<Graph>, source: &str) -> Self {
        let explicit = graph
            .lookup(SECTION, &bindings_section_key(source))
            .is_some();
        Self { graph, explicit }
    }

    /// `contained` is consulted before `binds`, so containment outranks any binding.
    pub(crate) fn role_for(&self, uid: u32, principal_uid: u32) -> Resolution {
        if !self.explicit {
            return if uid == principal_uid {
                Resolution::Role(Role::Admin)
            } else {
                Resolution::NoRole
            };
        }
        let Some(subject) = self.graph.lookup(SUBJECT, &subject_key(uid)) else {
            return Resolution::NoRole;
        };
        if self.graph.out_edges(subject.id, CONTAINED).next().is_some() {
            return Resolution::Role(Role::Adversary);
        }
        self.graph
            .out_edges(subject.id, BINDS)
            .next()
            .and_then(|e| self.graph.node(e.to))
            .and_then(|r| Role::from_key(&r.key))
            .map_or(Resolution::NoRole, Resolution::Role)
    }

    pub(crate) fn as_subject_bindings(&self) -> Option<Vec<maknae_security::SubjectBinding>> {
        if !self.explicit {
            return None;
        }
        let mut out: BTreeMap<String, Vec<String>> = BTreeMap::new();
        for s in self.graph.nodes().iter().filter(|n| n.kind == SUBJECT) {
            let role = if self.graph.out_edges(s.id, CONTAINED).next().is_some() {
                Some(ADVERSARY.to_string())
            } else {
                self.graph
                    .out_edges(s.id, BINDS)
                    .next()
                    .and_then(|e| self.graph.node(e.to))
                    .and_then(|r| Role::from_key(&r.key))
                    .map(|r| r.key().to_string())
            };
            if let Some(role) = role {
                out.entry(role).or_default().push(s.key.clone());
            }
        }
        Some(
            out.into_iter()
                .map(|(role, mut members)| {
                    members.sort();
                    maknae_security::SubjectBinding { role, members }
                })
                .collect(),
        )
    }

    /// Every subject the load named, bound or not; `None` when bindings are absent.
    pub(crate) fn entries(&self, problems: &[IdentityProblem]) -> Option<Vec<ListedSubject>> {
        if !self.explicit {
            return None;
        }
        let mut out = Vec::new();
        for s in self.graph.nodes().iter().filter(|n| n.kind == SUBJECT) {
            let Some(maknae_graph::record::AttrValue::U64(uid)) = s.attrs.get(ATTR_UID) else {
                continue;
            };
            let Ok(uid) = u32::try_from(*uid) else {
                continue;
            };
            let name = match s.attrs.get(ATTR_NAME) {
                Some(maknae_graph::record::AttrValue::Str(n)) if *n != subject_key(uid) => {
                    vec![n.clone()]
                }
                _ => Vec::new(),
            };
            let carried = problems.iter().find_map(|p| match p {
                IdentityProblem::CarriedForward { uid: u, name, .. } if *u == uid => {
                    Some(name.clone())
                }
                _ => None,
            });
            let entry = if let Some(n) = carried {
                ListedSubject {
                    uid: Some(uid),
                    names: vec![n],
                    state: SubjectState::CarriedForward,
                }
            } else if self.graph.out_edges(s.id, CONTAINED).next().is_some() {
                ListedSubject {
                    uid: Some(uid),
                    names: name,
                    state: SubjectState::Contained,
                }
            } else {
                let Some(role) = self
                    .graph
                    .out_edges(s.id, BINDS)
                    .next()
                    .and_then(|e| self.graph.node(e.to))
                    .and_then(|r| Role::from_key(&r.key))
                else {
                    continue;
                };
                ListedSubject {
                    uid: Some(uid),
                    names: name,
                    state: SubjectState::Bound(role.key()),
                }
            };
            out.push(entry);
        }
        for p in problems {
            out.push(match p {
                IdentityProblem::Unresolved { role, name } => ListedSubject {
                    uid: None,
                    names: vec![name.clone()],
                    state: SubjectState::Unresolved(role),
                },
                IdentityProblem::UnresolvedAdversary { name } => ListedSubject {
                    uid: None,
                    names: vec![name.clone()],
                    state: SubjectState::Unresolved(ADVERSARY),
                },
                IdentityProblem::Unbound { uid, names, roles } => ListedSubject {
                    uid: Some(*uid),
                    names: names.clone(),
                    state: SubjectState::Unbound(roles.clone()),
                },
                IdentityProblem::Contained { .. }
                | IdentityProblem::CarriedForward { .. }
                | IdentityProblem::Released { .. } => continue,
            });
        }
        out.sort_by(|a, b| {
            (a.uid.is_none(), a.uid, &a.names).cmp(&(b.uid.is_none(), b.uid, &b.names))
        });
        Some(out)
    }
}

/// One subject `bindings.yaml` named, as the load that produced a snapshot left it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ListedSubject {
    pub uid: Option<u32>,
    /// The file's names for it; empty for a `uid:` entry.
    pub names: Vec<String>,
    pub state: SubjectState,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SubjectState {
    Bound(&'static str),
    Contained,
    CarriedForward,
    /// The roles its names are listed under; it holds none of them.
    Unbound(Vec<&'static str>),
    /// The role its name is listed under; the name has no account.
    Unresolved(&'static str),
}

/// Where a loaded policy resolves subjects: the file's bindings, or a compiled snapshot's graph.
#[derive(Clone, Debug)]
pub(crate) enum Roles {
    #[cfg(test)]
    File(crate::tests::oracle::ResolvedBindings),
    Graph(GraphBindings),
}

impl Roles {
    pub(crate) fn role_for(&self, uid: u32, principal_uid: u32) -> Resolution {
        match self {
            #[cfg(test)]
            Roles::File(r) => r.role_for(uid, principal_uid),
            Roles::Graph(g) => g.role_for(uid, principal_uid),
        }
    }

    pub(crate) fn as_subject_bindings(&self) -> Option<Vec<maknae_security::SubjectBinding>> {
        match self {
            #[cfg(test)]
            Roles::File(r) => r.as_subject_bindings(),
            Roles::Graph(g) => g.as_subject_bindings(),
        }
    }

    pub(crate) fn entries(&self, problems: &[IdentityProblem]) -> Option<Vec<ListedSubject>> {
        match self {
            #[cfg(test)]
            Roles::File(_) => None,
            Roles::Graph(g) => g.entries(problems),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tests::oracle::resolve;

    use maknae_config::parse_bindings;

    fn b(pairs: &[(&str, &[&str])]) -> Option<BTreeMap<String, Vec<String>>> {
        Some(
            pairs
                .iter()
                .map(|(k, v)| (k.to_string(), v.iter().map(|s| s.to_string()).collect()))
                .collect(),
        )
    }

    fn uids(pairs: &[(&str, u32)]) -> UidMap {
        pairs.iter().map(|(n, u)| (n.to_string(), *u)).collect()
    }

    const PRINCIPAL_UID: u32 = 501;

    fn file(body: &str) -> maknae_config::Bindings {
        parse_bindings(&format!("schema_version: 1\nbindings:\n{body}")).unwrap()
    }

    fn subjects(r: &Resolved) -> Vec<(u32, &'static str, &str)> {
        r.subjects
            .iter()
            .map(|(u, role, n)| (*u, role.key(), n.as_str()))
            .collect()
    }

    #[test]
    fn an_unresolvable_name_drops_only_that_name() {
        let r = resolve_subjects(
            &file("  admin: [alex]\n  user: [ursula, ghost]\n"),
            &uids(&[("alex", 1000), ("ursula", 1001)]),
        )
        .unwrap();
        assert_eq!(
            subjects(&r),
            [(1000, "admin", "alex"), (1001, "user", "ursula")]
        );
        assert_eq!(
            r.problems,
            [IdentityProblem::Unresolved {
                role: "user",
                name: "ghost".into()
            }]
        );
    }

    #[test]
    fn an_unresolvable_adversary_name_is_its_own_problem() {
        let r = resolve_subjects(
            &file("  adversary: [mallory, ghost]\n"),
            &uids(&[("mallory", 666)]),
        )
        .unwrap();
        assert_eq!(subjects(&r), [(666, "adversary", "mallory")]);
        assert_eq!(
            r.problems,
            [IdentityProblem::UnresolvedAdversary {
                name: "ghost".into()
            }]
        );
    }

    #[test]
    fn an_overlap_by_name_alias_or_uid_is_contained() {
        let map = uids(&[("mallory", 666), ("root", 0), ("toor", 0), ("alex", 1000)]);
        for (body, uid, name, names, roles) in [
            (
                "  admin: [mallory]\n  adversary: [mallory]\n",
                666,
                "mallory",
                vec!["mallory"],
                vec!["admin", "adversary"],
            ),
            (
                "  admin: [root]\n  adversary: [toor]\n",
                0,
                "toor",
                vec!["root", "toor"],
                vec!["admin", "adversary"],
            ),
            (
                "  user: [alex]\n  adversary: [{uid: 1000}]\n",
                1000,
                "uid:1000",
                vec!["uid:1000", "alex"],
                vec!["adversary", "user"],
            ),
            (
                "  admin: [root]\n  user: [toor]\n  adversary: [{uid: 0}]\n",
                0,
                "uid:0",
                vec!["root", "uid:0", "toor"],
                vec!["admin", "adversary", "user"],
            ),
        ] {
            let r = resolve_subjects(&file(body), &map).unwrap();
            assert_eq!(subjects(&r), [(uid, "adversary", name)], "{body}");
            assert_eq!(
                r.problems,
                [IdentityProblem::Contained {
                    uid,
                    names: names.into_iter().map(String::from).collect(),
                    roles
                }],
                "{body}"
            );
        }
    }

    #[test]
    fn one_uid_in_two_roles_without_adversary_is_unbound() {
        let map = uids(&[("gus", 1002), ("root", 0), ("toor", 0), ("alex", 1000)]);
        for (body, uid, names, roles) in [
            (
                "  admin: [alex]\n  guest: [gus]\n  user: [gus]\n",
                1002,
                vec!["gus"],
                vec!["guest", "user"],
            ),
            (
                "  admin: [root, alex]\n  user: [toor]\n",
                0,
                vec!["root", "toor"],
                vec!["admin", "user"],
            ),
        ] {
            let r = resolve_subjects(&file(body), &map).unwrap();
            assert!(r.subjects.iter().all(|(u, ..)| *u != uid), "{body}");
            assert!(
                r.subjects.iter().any(|(u, ..)| *u == 1000),
                "the rest loads"
            );
            assert!(
                r.problems.contains(&IdentityProblem::Unbound {
                    uid,
                    names: names.into_iter().map(String::from).collect(),
                    roles
                }),
                "{body}: {:?}",
                r.problems
            );
        }
    }

    #[test]
    fn two_names_for_one_uid_in_one_role_deduplicate_to_the_first() {
        let r = resolve_subjects(
            &file("  admin: [root, toor]\n"),
            &uids(&[("root", 0), ("toor", 0)]),
        )
        .unwrap();
        assert_eq!(subjects(&r), [(0, "admin", "root")]);
        assert!(r.problems.is_empty());
        let a = resolve_subjects(
            &file("  adversary: [mallory, {uid: 666}]\n"),
            &uids(&[("mallory", 666)]),
        )
        .unwrap();
        assert_eq!(subjects(&a), [(666, "adversary", "mallory")]);
        assert!(
            a.problems.is_empty(),
            "a name and a uid for one adversary is not an overlap: {:?}",
            a.problems
        );
    }

    #[test]
    fn file_level_defects_refuse_the_whole_file() {
        let map = uids(&[("a", 1)]);
        assert_eq!(
            resolve_subjects(&file("  advesary: [a]\n"), &map),
            Err(BindingError::UnknownRole("advesary".into()))
        );
        assert_eq!(
            resolve_subjects(&file("  user: [a, a]\n"), &map),
            Err(BindingError::Duplicate("a".into()))
        );
        assert_eq!(
            resolve_subjects(&file("  adversary: [{uid: 5}, {uid: 5}]\n"), &map),
            Err(BindingError::Duplicate("uid:5".into()))
        );
        assert_eq!(
            resolve_subjects(&file("  guest: [{uid: 5}]\n"), &map),
            Err(BindingError::UidOutsideAdversary("guest".into()))
        );
        for (e, text) in [
            (
                BindingError::UnknownRole("x".into()),
                "bindings names unknown role 'x'",
            ),
            (
                BindingError::Duplicate("y".into()),
                "identity 'y' listed twice in one role",
            ),
            (
                BindingError::UidOutsideAdversary("z".into()),
                "role 'z' lists a uid entry; `uid:` entries are accepted under adversary only",
            ),
        ] {
            assert_eq!(e.to_string(), text);
        }
    }

    #[test]
    fn absent_and_empty_resolve_to_nothing() {
        let nothing = Resolved {
            subjects: vec![],
            problems: vec![],
        };
        for b in [
            maknae_config::Bindings::missing(),
            maknae_config::Bindings::absent(),
            parse_bindings("schema_version: 1\nbindings: {}\n").unwrap(),
        ] {
            assert_eq!(resolve_subjects(&b, &UidMap::new()), Ok(nothing.clone()));
        }
    }

    #[test]
    fn problems_come_in_a_fixed_order() {
        let body =
            "  admin: [ghost1, root]\n  adversary: [ghost2, toor]\n  guest: [gus]\n  user: [gus]\n";
        let map = uids(&[("root", 0), ("toor", 0), ("gus", 1002)]);
        let kinds: Vec<&str> = resolve_subjects(&file(body), &map)
            .unwrap()
            .problems
            .iter()
            .map(IdentityProblem::kind)
            .collect();
        assert_eq!(
            kinds,
            [
                "unresolved",
                "unresolved_adversary",
                "contained",
                "unbound_conflict"
            ]
        );
    }

    #[test]
    fn every_problem_reports_its_kind_uid_names_roles_and_text() {
        let cases = [
            (
                IdentityProblem::Unresolved {
                    role: "user",
                    name: "ghost".into(),
                },
                "unresolved",
                None,
                vec!["ghost"],
                vec!["user"],
                "'ghost' under user has no account on this host; it holds no role",
            ),
            (
                IdentityProblem::UnresolvedAdversary {
                    name: "ghost".into(),
                },
                "unresolved_adversary",
                None,
                vec!["ghost"],
                vec!["adversary"],
                "'ghost' under adversary has no account on this host; nothing is contained for it (write \"- uid: <n>\" to contain an id that has no account)",
            ),
            (
                IdentityProblem::Contained {
                    uid: 0,
                    names: vec!["root".into(), "toor".into()],
                    roles: vec!["admin", "adversary"],
                },
                "contained",
                Some(0),
                vec!["root", "toor"],
                vec!["admin", "adversary"],
                "uid 0 (root, toor) is under admin, adversary; containment wins and it is contained",
            ),
            (
                IdentityProblem::Unbound {
                    uid: 1002,
                    names: vec!["gus".into()],
                    roles: vec!["guest", "user"],
                },
                "unbound_conflict",
                Some(1002),
                vec!["gus"],
                vec!["guest", "user"],
                "uid 1002 (gus) is under guest, user; it holds no role",
            ),
            (
                IdentityProblem::CarriedForward {
                    uid: 666,
                    name: "mallory".into(),
                    overrides: vec![],
                },
                "carried_forward",
                Some(666),
                vec!["mallory"],
                vec!["adversary"],
                "'mallory' under adversary no longer resolves; uid 666 stays contained (carried forward)",
            ),
            (
                IdentityProblem::CarriedForward {
                    uid: 666,
                    name: "mallory".into(),
                    overrides: vec![("bob".into(), "user"), ("carol".into(), "admin")],
                },
                "carried_forward",
                Some(666),
                vec!["mallory", "bob", "carol"],
                vec!["adversary", "user", "admin"],
                "'mallory' under adversary no longer resolves; uid 666 stays contained (carried forward); this overrides bob (user), carol (admin)",
            ),
            (
                IdentityProblem::Released {
                    uid: 666,
                    name: "mallory".into(),
                    cause: "its name is no longer listed under adversary".into(),
                },
                "released",
                Some(666),
                vec!["mallory"],
                vec!["adversary"],
                "uid 666 ('mallory') is no longer contained: its name is no longer listed under adversary",
            ),
        ];
        for (p, kind, uid, names, roles, text) in cases {
            assert_eq!(p.kind(), kind);
            assert_eq!(p.uid(), uid);
            assert_eq!(p.names(), names);
            assert_eq!(p.roles(), roles);
            assert_eq!(p.to_string(), text);
        }
    }

    #[test]
    fn a_release_becomes_a_released_problem_naming_its_cause() {
        let r = maknae_graph::identity::Released {
            uid: 666,
            name: "mallory".into(),
            cause: maknae_graph::identity::ReleaseCause::NameNowResolvesTo(777),
        };
        assert_eq!(
            IdentityProblem::from(&r),
            IdentityProblem::Released {
                uid: 666,
                name: "mallory".into(),
                cause: "its name now resolves to uid 777".into(),
            }
        );
    }

    #[test]
    fn every_printed_name_is_escaped_and_its_commas_marked() {
        assert_eq!(shown("é\u{7f},x"), "\\u{e9}\\u{7f}\\,x");
        assert_eq!(shown("mallory"), "mallory");
        let odd = "a,b\n".to_string();
        let texts = [
            IdentityProblem::Unresolved {
                role: "user",
                name: odd.clone(),
            },
            IdentityProblem::UnresolvedAdversary { name: odd.clone() },
            IdentityProblem::Contained {
                uid: 1,
                names: vec![odd.clone()],
                roles: vec!["adversary"],
            },
            IdentityProblem::Unbound {
                uid: 1,
                names: vec![odd.clone()],
                roles: vec!["user"],
            },
            IdentityProblem::CarriedForward {
                uid: 1,
                name: odd.clone(),
                overrides: vec![],
            },
            IdentityProblem::CarriedForward {
                uid: 1,
                name: "m".into(),
                overrides: vec![(odd.clone(), "user")],
            },
            IdentityProblem::Released {
                uid: 1,
                name: odd.clone(),
                cause: "c".into(),
            },
        ]
        .map(|p| p.to_string());
        for t in texts {
            assert!(t.contains("a\\,b\\n") && !t.contains('\n'), "{t}");
        }
    }

    #[test]
    fn a_contained_subject_never_carries_a_binds_edge() {
        let r = resolve_subjects(
            &file("  admin: [root]\n  adversary: [toor]\n"),
            &uids(&[("root", 0), ("toor", 0)]),
        )
        .unwrap();
        let layer = maknae_graph::identity::IdentityLayer {
            source: SOURCE.into(),
            label: "UNCLASSIFIED".into(),
            bindings_sha256: Some([3; 32]),
            subjects: r
                .subjects
                .iter()
                .map(|(uid, role, name)| SubjectEntry {
                    uid: *uid,
                    name: name.clone(),
                    role: role.key().into(),
                })
                .collect(),
        };
        let g = graph(&layer);
        let s = g.lookup(SUBJECT, "uid:0").unwrap().id;
        assert_eq!(g.out_edges(s, CONTAINED).count(), 1);
        assert_eq!(g.out_edges(s, BINDS).count(), 0);
        let gb = GraphBindings::new(g, SOURCE);
        assert_eq!(gb.role_for(0, 0), Resolution::Role(Role::Adversary));
    }

    use maknae_graph::graph::GraphBuilder;
    use maknae_graph::identity::{build, IdentityLayer, SubjectEntry};
    use maknae_graph::kernel::{persisted_compiled_set, ROLE, SCHEMA};
    use maknae_graph::record::{EdgeId, EdgeRecord, GraphSpace, Provenance, ProvenanceKind};
    use maknae_graph::schema::{CompiledNode, CompiledSet};

    const SOURCE: &str = "/etc/maknae/authz.yaml";

    fn layer(explicit: bool, subjects: &[(u32, &str, &str)]) -> IdentityLayer {
        IdentityLayer {
            source: SOURCE.into(),
            label: "UNCLASSIFIED".into(),
            bindings_sha256: explicit.then_some([3; 32]),
            subjects: subjects
                .iter()
                .map(|(uid, name, role)| SubjectEntry {
                    uid: *uid,
                    name: (*name).into(),
                    role: (*role).into(),
                })
                .collect(),
        }
    }

    fn graph_with(l: &IdentityLayer, compiled: &CompiledSet) -> Arc<Graph> {
        Arc::new(build(l, compiled, [1; 32], 5, ProvenanceKind::Seed).unwrap())
    }

    fn graph(l: &IdentityLayer) -> Arc<Graph> {
        graph_with(l, &persisted_compiled_set("UNCLASSIFIED"))
    }

    #[test]
    fn absent_and_empty_bindings_differ() {
        let absent = GraphBindings::new(graph(&layer(false, &[])), SOURCE);
        assert_eq!(
            absent.role_for(PRINCIPAL_UID, PRINCIPAL_UID),
            Resolution::Role(Role::Admin)
        );
        assert_eq!(absent.role_for(999, PRINCIPAL_UID), Resolution::NoRole);
        assert_eq!(absent.as_subject_bindings(), None);

        let empty = GraphBindings::new(graph(&layer(true, &[])), SOURCE);
        assert_eq!(
            empty.role_for(PRINCIPAL_UID, PRINCIPAL_UID),
            Resolution::NoRole
        );
        assert_eq!(empty.as_subject_bindings(), Some(vec![]));
    }

    #[test]
    fn the_bindings_section_is_looked_up_under_the_named_source() {
        let g = GraphBindings::new(graph(&layer(true, &[])), "/other/authz.yaml");
        assert_eq!(
            g.role_for(PRINCIPAL_UID, PRINCIPAL_UID),
            Resolution::Role(Role::Admin)
        );
    }

    #[test]
    fn explicit_bindings_resolve_by_graph_hops() {
        let l = layer(
            true,
            &[
                (1000, "alex", "admin"),
                (1001, "ursula", "user"),
                (1002, "gus", "guest"),
                (666, "mallory", "adversary"),
                (1003, "alice", "admin"),
            ],
        );
        let g = GraphBindings::new(graph(&l), SOURCE);
        assert_eq!(g.role_for(1000, 1000), Resolution::Role(Role::Admin));
        assert_eq!(g.role_for(1001, 1000), Resolution::Role(Role::User));
        assert_eq!(g.role_for(1002, 1000), Resolution::Role(Role::Guest));
        assert_eq!(g.role_for(666, 1000), Resolution::Role(Role::Adversary));
        assert_eq!(g.role_for(4242, 4242), Resolution::NoRole);

        let file = resolve(
            &b(&[
                ("admin", &["alex", "alice"]),
                ("user", &["ursula"]),
                ("guest", &["gus"]),
                ("adversary", &["mallory"]),
            ]),
            &uids(&[
                ("alex", 1000),
                ("alice", 1003),
                ("ursula", 1001),
                ("gus", 1002),
                ("mallory", 666),
            ]),
        )
        .unwrap();
        let want = file.as_subject_bindings();
        assert_eq!(g.as_subject_bindings(), want);
        assert_eq!(Roles::Graph(g.clone()).as_subject_bindings(), want);
        assert_eq!(Roles::File(file.clone()).as_subject_bindings(), want);
        for uid in [1000, 1001, 1002, 666, 4242] {
            assert_eq!(
                Roles::Graph(g.clone()).role_for(uid, 1000),
                file.role_for(uid, 1000)
            );
            assert_eq!(
                Roles::File(file.clone()).role_for(uid, 1000),
                file.role_for(uid, 1000)
            );
        }
    }

    fn with_extra_edge(
        g: &Graph,
        from: &str,
        kind: maknae_graph::record::EdgeKind,
        to: (maknae_graph::record::NodeKind, &str),
        compiled: &CompiledSet,
    ) -> Arc<Graph> {
        let from = g.lookup(SUBJECT, from).unwrap().id;
        let to = g.lookup(to.0, to.1).unwrap().id;
        let next = g.edges().iter().map(|e| e.id.0).max().unwrap_or(0) + 1;
        let b = g.nodes().iter().cloned().fold(
            GraphBuilder::new(GraphSpace::Kernel, g.revision()),
            |b, n| b.node(n),
        );
        let b = g.edges().iter().cloned().fold(b, |b, e| b.edge(e));
        let b = b.edge(EdgeRecord {
            id: EdgeId(next),
            space: GraphSpace::Kernel,
            from,
            to,
            kind,
            label: "UNCLASSIFIED".into(),
            provenance: Provenance {
                kind: ProvenanceKind::Seed,
                transition: 5,
            },
            revision: 5,
            attrs: Default::default(),
        });
        Arc::new(b.build(&SCHEMA, compiled).unwrap())
    }

    #[test]
    fn contained_outranks_binds() {
        let g = graph(&layer(true, &[(7, "mallory", "adversary")]));
        let both = with_extra_edge(
            &g,
            "uid:7",
            BINDS,
            (ROLE, "user"),
            &persisted_compiled_set("UNCLASSIFIED"),
        );
        let s = both.lookup(SUBJECT, "uid:7").unwrap().id;
        assert_eq!(both.out_edges(s, BINDS).count(), 1);
        assert_eq!(both.out_edges(s, CONTAINED).count(), 1);
        let gb = GraphBindings::new(both, SOURCE);
        assert_eq!(gb.role_for(7, 1000), Resolution::Role(Role::Adversary));
        assert_eq!(
            gb.as_subject_bindings(),
            Some(vec![maknae_security::SubjectBinding {
                role: ADVERSARY.into(),
                members: vec!["uid:7".into()],
            }])
        );
    }

    #[test]
    fn a_binds_to_a_role_the_binary_lacks_is_no_role() {
        let mut nodes: Vec<CompiledNode> = persisted_compiled_set("UNCLASSIFIED")
            .iter()
            .cloned()
            .collect();
        nodes.push(CompiledNode {
            kind: ROLE,
            key: "superadmin".into(),
            label: "UNCLASSIFIED".into(),
            attrs: Default::default(),
        });
        let wide = CompiledSet::new(nodes);
        let g = graph_with(&layer(true, &[(9, "sam", "superadmin")]), &wide);
        let gb = GraphBindings::new(g, SOURCE);
        assert_eq!(gb.role_for(9, 9), Resolution::NoRole);
        assert_eq!(gb.as_subject_bindings(), Some(vec![]));
    }

    #[test]
    fn a_subject_with_no_edges_is_no_role_and_unlisted() {
        let g = graph(&layer(true, &[(9, "sam", "user")]));
        let s = g.lookup(SUBJECT, "uid:9").unwrap().id;
        let b = g.nodes().iter().cloned().fold(
            GraphBuilder::new(GraphSpace::Kernel, g.revision()),
            |b, n| b.node(n),
        );
        let b = g
            .edges()
            .iter()
            .filter(|e| !(e.from == s && e.kind == BINDS))
            .cloned()
            .fold(b, |b, e| b.edge(e));
        let bare = Arc::new(
            b.build(&SCHEMA, &persisted_compiled_set("UNCLASSIFIED"))
                .unwrap(),
        );
        let gb = GraphBindings::new(bare, SOURCE);
        assert_eq!(gb.role_for(9, 9), Resolution::NoRole);
        assert_eq!(gb.as_subject_bindings(), Some(vec![]));
    }
}
