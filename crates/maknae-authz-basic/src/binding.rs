//! Subject → role binding resolution (#85, spec §3/§3a/§3b).
//!
//! Identity semantics (ADR-0018: the per-request authorization principal is
//! the **uid**): `bindings:` entries are operator-facing usernames, resolved
//! to uids ONCE at [`crate::BasicAuthorizer`] construction (the `UidMap`);
//! **matching is uid vs uid, with no exception.**
//!
//! A reserved `agent` token used to sit beside the uid map, meaning the runtime
//! subject and never looked up. [ADR-0024](../../../design/adr/ADR-0024-tenancy-model-and-agent-identity.md)
//! decision 3 struck it: Maknae is multi-tenant, and one reserved runtime token
//! cannot express two agent personas. An agent holds no identity of its own —
//! it acts within a delegation from the human who invoked it — so ADR-0018's
//! uid principal now applies uniformly. `agent` is an ordinary username: if a
//! deployer creates such an account and binds it, it resolves through NSS like
//! any other, which is their call to make and not this crate's (#276).
//!
//! Fail-closed everywhere: unknown role key, dual membership, a duplicate
//! name, or a name absent from the `UidMap` (the map is resolved at each load,
//! so only a name with no uid on the host is absent) all make the policy
//! invalid.

use crate::role::Role;
use maknae_graph::graph::Graph;
use maknae_graph::identity::{bindings_section_key, subject_key};
use maknae_graph::kernel::{ADVERSARY, BINDS, CONTAINED, SECTION, SUBJECT};
use std::collections::btree_map::Entry;
use std::collections::BTreeMap;
use std::sync::Arc;

/// username → uid, built once at construction via getpwnam.
pub(crate) type UidMap = BTreeMap<String, u32>;

/// Validated, uid-keyed bindings for one loaded policy snapshot.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct ResolvedBindings {
    by_uid: BTreeMap<u32, (Role, String)>,
    /// The `bindings:` key was PRESENT in the file → defaults suppressed
    /// entirely (spec §3 precedence; what makes `admin: []` mean "no admin").
    explicit: bool,
}

/// Why a `bindings:` block is invalid (spec §3a). Every variant names the
/// offending token so the boot refusal / audit record is actionable.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum BindingError {
    UnknownRole(String),
    DualMembership(String),
    Duplicate(String),
    Unresolvable(String),
    DuplicateUid { uid: u32, names: (String, String) },
}

impl std::fmt::Display for BindingError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            BindingError::UnknownRole(k) => write!(f, "bindings names unknown role '{k}'"),
            BindingError::DualMembership(n) => {
                write!(f, "identity '{n}' appears in more than one role")
            }
            BindingError::Duplicate(n) => write!(f, "identity '{n}' listed twice in one role"),
            BindingError::Unresolvable(n) => {
                write!(
                    f,
                    "identity '{n}' has no resolved uid (restart to add principals)"
                )
            }
            BindingError::DuplicateUid { uid, names: (a, b) } => write!(
                f,
                "identities '{a}' and '{b}' resolve to the same uid {uid}; bind one of them"
            ),
        }
    }
}

/// The outcome of subject resolution.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Resolution {
    Role(Role),
    NoRole,
}

/// Validate a parsed `bindings` value against the closed role vocabulary and
/// the construction-time `UidMap`.
pub(crate) fn resolve(
    bindings: &Option<BTreeMap<String, Vec<String>>>,
    lookup: &UidMap,
) -> Result<ResolvedBindings, BindingError> {
    let Some(map) = bindings else {
        return Ok(ResolvedBindings {
            by_uid: BTreeMap::new(),
            explicit: false,
        });
    };
    let mut by_uid: BTreeMap<u32, (Role, String)> = BTreeMap::new();
    let mut seen: BTreeMap<&str, ()> = BTreeMap::new();
    for (key, members) in map {
        let role = Role::from_key(key).ok_or_else(|| BindingError::UnknownRole(key.clone()))?;
        for name in members {
            if seen.insert(name.as_str(), ()).is_some() {
                // Same name earlier — in this role (Duplicate) or another
                // (DualMembership). Distinguish for the error message only;
                // both refuse.
                let dup_in_this_role = members
                    .iter()
                    .filter(|m| m.as_str() == name.as_str())
                    .count()
                    > 1;
                return Err(if dup_in_this_role {
                    BindingError::Duplicate(name.clone())
                } else {
                    BindingError::DualMembership(name.clone())
                });
            }
            let uid = lookup
                .get(name)
                .copied()
                .ok_or_else(|| BindingError::Unresolvable(name.clone()))?;
            match by_uid.entry(uid) {
                Entry::Vacant(v) => {
                    v.insert((role, name.clone()));
                }
                Entry::Occupied(o) if o.get().0 == role => {}
                Entry::Occupied(o) => {
                    return Err(BindingError::DuplicateUid {
                        uid,
                        names: (o.get().1.clone(), name.clone()),
                    })
                }
            }
        }
    }
    Ok(ResolvedBindings {
        by_uid,
        explicit: true,
    })
}

impl ResolvedBindings {
    /// Render as seam-level bindings for `admin.subject.list`.
    ///
    /// Reports what the POLICY FILE binds -- the explicit `bindings:` block --
    /// and nothing else. The default-role fallback (an enrolled uid resolving
    /// to admin when no bindings key is present) is a decision rule, not a
    /// binding, and listing it as one would tell an operator a binding exists
    /// that they could then look for in the file and not find.
    /// MEMBERS ARE REPORTED BY UID -- every binding has one since #276.
    ///
    /// Worth naming, because the sibling rationale on `Role::key` argues the
    /// opposite direction for roles ("the token an operator would grep for in
    /// `authz.yaml`"). `root` reports as `uid:0`, which appears in no policy
    /// file. The uid IS the authenticated datum (ADR-0018) and the thing
    /// `role_for` keys on, so it is the honest answer to "who is bound"; a
    /// name is an input resolved once at construction that may since have been
    pub(crate) fn as_subject_bindings(&self) -> Option<Vec<maknae_security::SubjectBinding>> {
        // NO `bindings:` KEY -> `None`, not an empty list.
        //
        // The shipped `packaging/common/authz.yaml` has no `bindings:` key, so
        // the default deployment took this path and rendered `Some(vec![])` --
        // "these are the bindings, and there are none" -- while the DEFAULT
        // ROLE FALLBACK was live and the enrolled uid was resolving to admin.
        // Materially different states (`bindings: {}` and
        // no-key-with-fallback-active) would otherwise read identically as
        // "nobody is bound", which is exactly the claim the `Option` on this
        // seam exists to refuse. Only an EXPLICIT block can report a set.
        if !self.explicit {
            return None;
        }
        let mut out: std::collections::BTreeMap<String, Vec<String>> = Default::default();
        for (uid, (role, _)) in self.by_uid.iter() {
            out.entry(role.key().to_string())
                .or_default()
                .push(format!("uid:{uid}"));
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

    /// Subject → role, on the uid alone.
    ///
    /// A reserved-subject-name arm used to run FIRST, never through uid
    /// (spec §3b's fixed order). [ADR-0024](../../../design/adr/ADR-0024-tenancy-model-and-agent-identity.md)
    /// decision 3 struck the reserved token, so there is no longer an ordering
    /// to state: there is one lookup (#276).
    ///
    /// `uid` is `u32`, not `Option<u32>`: the caller
    /// ([`crate::decide::decide_loaded_with_role`]) returns `Indeterminate`
    /// before reaching here when the subject carries no uid. An arm for the
    /// absent case would be production-unreachable, and in a `[t1]`
    /// zero-missed-mutant file an unreachable arm's mutants are unkillable.
    ///
    /// Defaults apply only when the file had no `bindings:` key.
    pub(crate) fn role_for(&self, uid: u32, principal_uid: u32) -> Resolution {
        if self.explicit {
            match self.by_uid.get(&uid) {
                Some((r, _)) => Resolution::Role(*r),
                None => Resolution::NoRole,
            }
        } else if uid == principal_uid {
            Resolution::Role(Role::Admin)
        } else {
            Resolution::NoRole
        }
    }
}

impl ResolvedBindings {
    /// Every bound uid in uid order, with its role and the name it was bound under.
    pub(crate) fn subjects(&self) -> impl Iterator<Item = (u32, Role, &str)> {
        self.by_uid
            .iter()
            .map(|(uid, (role, name))| (*uid, *role, name.as_str()))
    }
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
}

/// Where a loaded policy resolves subjects: the file's bindings, or a compiled snapshot's graph.
#[derive(Clone, Debug)]
pub(crate) enum Roles {
    File(ResolvedBindings),
    Graph(GraphBindings),
}

impl Roles {
    pub(crate) fn role_for(&self, uid: u32, principal_uid: u32) -> Resolution {
        match self {
            Roles::File(r) => r.role_for(uid, principal_uid),
            Roles::Graph(g) => g.role_for(uid, principal_uid),
        }
    }

    pub(crate) fn as_subject_bindings(&self) -> Option<Vec<maknae_security::SubjectBinding>> {
        match self {
            Roles::File(r) => r.as_subject_bindings(),
            Roles::Graph(g) => g.as_subject_bindings(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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

    #[test]
    fn unknown_role_key_is_refused_never_defaulted() {
        let got = resolve(&b(&[("advesary", &["alex"])]), &uids(&[("alex", 501)]));
        assert_eq!(got, Err(BindingError::UnknownRole("advesary".into())));
    }

    #[test]
    fn a_name_in_two_role_sets_is_dual_membership() {
        let got = resolve(
            &b(&[("admin", &["alex"]), ("user", &["alex"])]),
            &uids(&[("alex", 501)]),
        );
        assert_eq!(got, Err(BindingError::DualMembership("alex".into())));
    }

    #[test]
    fn a_name_twice_in_one_list_is_duplicate() {
        let got = resolve(&b(&[("user", &["alex", "alex"])]), &uids(&[("alex", 501)]));
        assert_eq!(got, Err(BindingError::Duplicate("alex".into())));
    }

    #[test]
    fn a_name_missing_from_the_uid_map_is_unresolvable() {
        let got = resolve(&b(&[("user", &["nobody-new"])]), &UidMap::new());
        assert_eq!(got, Err(BindingError::Unresolvable("nobody-new".into())));
    }

    /// #276: `agent` is an ordinary username now. It resolves through NSS like
    /// any other bound name and fails closed when no such account exists --
    /// which is the behaviour change an operator could actually notice, so it
    /// gets a test. Replaces `agent_token_is_never_looked_up`, whose subject
    /// (a name that bypasses the uid map) no longer exists.
    #[test]
    fn agent_is_an_ordinary_name_and_fails_closed_when_unresolvable() {
        let got = resolve(&b(&[("adversary", &["agent"])]), &UidMap::new());
        assert_eq!(got, Err(BindingError::Unresolvable("agent".into())));
        // And when it DOES resolve, it binds like any other name.
        let r = resolve(&b(&[("adversary", &["agent"])]), &uids(&[("agent", 4242)])).unwrap();
        assert_eq!(
            r.role_for(4242, PRINCIPAL_UID),
            Resolution::Role(Role::Adversary)
        );
    }

    #[test]
    fn present_but_empty_bindings_suppress_defaults_entirely() {
        // The no-discretionary-admin posture (spec §3): with an explicit
        // empty map, even the enrolled principal has NO role.
        let r = resolve(&Some(BTreeMap::new()), &UidMap::new()).unwrap();
        assert_eq!(r.role_for(PRINCIPAL_UID, PRINCIPAL_UID), Resolution::NoRole);
    }

    #[test]
    fn absent_bindings_apply_defaults() {
        let r = resolve(&None, &UidMap::new()).unwrap();
        assert_eq!(
            r.role_for(PRINCIPAL_UID, PRINCIPAL_UID),
            Resolution::Role(Role::Admin)
        );
        assert_eq!(r.role_for(999, PRINCIPAL_UID), Resolution::NoRole);
    }

    #[test]
    fn explicit_bindings_bind_by_resolved_uid() {
        let r = resolve(
            &b(&[("admin", &["alex"]), ("adversary", &["mallory"])]),
            &uids(&[("alex", 501), ("mallory", 666)]),
        )
        .unwrap();
        assert_eq!(r.role_for(501, 501), Resolution::Role(Role::Admin));
        assert_eq!(r.role_for(666, 501), Resolution::Role(Role::Adversary));
        assert_eq!(r.role_for(1000, 501), Resolution::NoRole);
    }

    // `missing_uid_with_no_reserved_name_is_no_role` retired with its subject
    // (#276): `role_for` now takes `u32`, so "no uid" is not expressible here.
    // The property moved UP to `decide_loaded_with_role`'s guard, which returns
    // Indeterminate before reaching this function -- see
    // `decide::tests::missing_identity_is_indeterminate_distinct_from_unbound`.

    #[test]
    fn one_uid_under_two_roles_refuses_naming_both_names() {
        let got = resolve(
            &b(&[("admin", &["root"]), ("adversary", &["toor"])]),
            &uids(&[("root", 0), ("toor", 0)]),
        );
        let want = BindingError::DuplicateUid {
            uid: 0,
            names: ("root".into(), "toor".into()),
        };
        assert_eq!(got, Err(want.clone()));
        assert_eq!(
            want.to_string(),
            "identities 'root' and 'toor' resolve to the same uid 0; bind one of them"
        );
    }

    #[test]
    fn one_uid_twice_under_one_role_keeps_the_first_name() {
        let r = resolve(
            &b(&[("admin", &["root", "toor"])]),
            &uids(&[("root", 0), ("toor", 0)]),
        )
        .unwrap();
        let got: Vec<(u32, Role, &str)> = r.subjects().collect();
        assert_eq!(got, vec![(0, Role::Admin, "root")]);
        assert_eq!(r.role_for(0, PRINCIPAL_UID), Resolution::Role(Role::Admin));
    }

    #[test]
    fn subjects_lists_every_binding_in_uid_order() {
        let r = resolve(
            &b(&[("user", &["ursula"]), ("admin", &["alex"])]),
            &uids(&[("alex", 1000), ("ursula", 7)]),
        )
        .unwrap();
        let got: Vec<(u32, Role, &str)> = r.subjects().collect();
        assert_eq!(
            got,
            vec![(7, Role::User, "ursula"), (1000, Role::Admin, "alex")]
        );
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
