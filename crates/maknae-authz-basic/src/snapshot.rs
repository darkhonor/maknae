//! The compiled snapshot: the persisted identity graph plus `authz.yaml` plus the
//! binary's vocabulary, compiled into one immutable in-memory graph with a rule index.

use crate::binding::{GraphBindings, Roles};
use crate::decide::{Cited, Effect, LoadedPolicy};
use crate::{IdentityProblem, PolicySource};
use maknae_graph::graph::{Graph, GraphBuilder};
use maknae_graph::identity::{extract, hex};
use maknae_graph::kernel::{
    ATTR_SHA256, CLASS, CONFIG_SOURCE, DECLARED_BY, DENIES, MATCHES, MEMBER_OF, PART_OF, PERMITS,
    ROLE, RULE, SCHEMA, SECTION, TERM,
};
use maknae_graph::record::{
    AttrValue, Attrs, EdgeId, EdgeKind, EdgeRecord, GraphSpace, NodeId, NodeKind, NodeRecord,
    Provenance, ProvenanceKind,
};
use maknae_graph::schema::CompiledSet;
use maknae_security::RuleCitation;
use std::collections::BTreeMap;
use std::fmt;
use std::sync::Arc;

const ATTR_CLASS: &str = "class";
const ATTR_ENTRY: &str = "entry";
const ATTR_EFFECT: &str = "effect";
const ATTR_TERM: &str = "term";
const ATTR_DESTINATION: &str = "destination";

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CompileError {
    Identity(String),
    Graph(String),
    Policy(String),
}

impl fmt::Display for CompileError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Identity(m) => write!(f, "snapshot identity refused: {m}"),
            Self::Graph(m) => write!(f, "snapshot graph refused: {m}"),
            Self::Policy(m) => write!(f, "snapshot policy refused: {m}"),
        }
    }
}

impl std::error::Error for CompileError {}

pub struct Snapshot {
    graph: Arc<Graph>,
    persisted: Arc<Graph>,
    loaded: LoadedPolicy,
    index: BTreeMap<Cited, RuleCitation>,
    sections: BTreeMap<String, [u8; 32]>,
    problems: Arc<[IdentityProblem]>,
}

impl fmt::Debug for Snapshot {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Snapshot")
            .field("revision", &self.revision())
            .field("nodes", &self.graph.nodes().len())
            .field("rules", &self.index.len())
            .finish()
    }
}

impl Snapshot {
    pub fn graph(&self) -> &Arc<Graph> {
        &self.graph
    }

    pub fn persisted(&self) -> &Arc<Graph> {
        &self.persisted
    }

    pub fn revision(&self) -> u64 {
        self.persisted.revision()
    }

    pub fn subjects(&self) -> Option<Vec<maknae_security::SubjectBinding>> {
        self.loaded.roles.as_subject_bindings()
    }

    /// Every subject the load named, with what that load made of it; `None` when
    /// bindings are absent.
    pub fn subject_entries(&self) -> Option<Vec<crate::ListedSubject>> {
        self.loaded.roles.entries(&self.problems)
    }

    /// The subjects the load this snapshot was compiled from could not bind as written.
    pub fn identity_problems(&self) -> &Arc<[IdentityProblem]> {
        &self.problems
    }

    pub(crate) fn loaded(&self) -> &LoadedPolicy {
        &self.loaded
    }

    pub(crate) fn cite(&self, c: &Cited) -> Option<RuleCitation> {
        self.index.get(c).cloned()
    }

    /// The policy digest, in hex: `digest` over one `<section>=<hex digest>\n`
    /// line per section this snapshot was compiled from, in section order.
    pub fn policy_sha256(&self, digest: fn(&[u8]) -> [u8; 32]) -> String {
        let lines: String = self
            .sections
            .iter()
            .map(|(name, d)| format!("{name}={}\n", hex(d)))
            .collect();
        hex(&digest(lines.as_bytes()))
    }
}

struct Compiler {
    nodes: Vec<NodeRecord>,
    edges: Vec<EdgeRecord>,
    node: u64,
    edge: u64,
    label: String,
    revision: u64,
    source_id: NodeId,
    source: String,
    ids: BTreeMap<(NodeKind, String), NodeId>,
    index: BTreeMap<Cited, RuleCitation>,
}

impl Compiler {
    fn seeded(&self) -> Provenance {
        Provenance {
            kind: ProvenanceKind::Seed,
            transition: self.revision,
        }
    }

    fn add_node(&mut self, kind: NodeKind, key: String, attrs: Attrs) -> NodeId {
        self.node += 1;
        let id = NodeId(self.node);
        self.nodes.push(NodeRecord {
            id,
            space: GraphSpace::Kernel,
            kind,
            key,
            label: self.label.clone(),
            provenance: self.seeded(),
            revision: self.revision,
            attrs,
        });
        id
    }

    fn add_edge(&mut self, from: NodeId, kind: EdgeKind, to: NodeId) {
        self.edge += 1;
        self.edges.push(EdgeRecord {
            id: EdgeId(self.edge),
            space: GraphSpace::Kernel,
            from,
            to,
            kind,
            label: self.label.clone(),
            provenance: self.seeded(),
            revision: self.revision,
            attrs: Attrs::new(),
        });
    }

    fn id_of(&self, kind: NodeKind, key: &str) -> Result<NodeId, CompileError> {
        self.ids
            .get(&(kind, key.to_string()))
            .copied()
            .ok_or_else(|| {
                CompileError::Policy(format!("`{key}` is not in the compiled vocabulary"))
            })
    }

    fn section(
        &mut self,
        name: &str,
        digests: &BTreeMap<String, [u8; 32]>,
        parent: &str,
    ) -> Result<(NodeId, String), CompileError> {
        let d = digests
            .get(parent)
            .ok_or_else(|| CompileError::Policy(format!("no digest for section `{parent}`")))?;
        let key = format!("{}#{name}", self.source);
        let mut attrs = Attrs::new();
        attrs.insert(ATTR_SHA256.into(), AttrValue::Str(hex(d)));
        let id = self.add_node(SECTION, key.clone(), attrs);
        self.add_edge(id, PART_OF, self.source_id);
        Ok((id, key))
    }

    fn rule(
        &mut self,
        key: String,
        attrs: Attrs,
        section: &(NodeId, String),
        cited: Cited,
    ) -> NodeId {
        let id = self.add_node(RULE, key.clone(), attrs);
        self.add_edge(id, DECLARED_BY, section.0);
        self.index.entry(cited).or_insert(RuleCitation {
            node: id.0,
            key,
            section: section.1.clone(),
        });
        id
    }
}

fn effect_attrs(effect: Effect) -> (EdgeKind, &'static str) {
    match effect {
        Effect::Allow => (PERMITS, "allow"),
        Effect::Deny => (DENIES, "deny"),
    }
}

fn permissions_declared(
    canonical: Option<&str>,
    deny: &[String],
    allow: &[String],
) -> Result<bool, CompileError> {
    if canonical.is_some() {
        return Ok(true);
    }
    if deny.is_empty() && allow.is_empty() {
        return Ok(false);
    }
    Err(CompileError::Policy(format!(
        "{} deny and {} allow permissions entries without a permissions section",
        deny.len(),
        allow.len()
    )))
}

fn static_role(key: &str) -> Result<&'static str, CompileError> {
    crate::role::Role::from_key(key)
        .map(|r| r.key())
        .ok_or_else(|| CompileError::Policy(format!("`{key}` is not a role")))
}

pub fn compile(
    persisted: Arc<Graph>,
    source: &PolicySource,
    vocabulary: &CompiledSet,
    section_sha256: &BTreeMap<String, [u8; 32]>,
) -> Result<Snapshot, CompileError> {
    let stored = extract(&persisted).map_err(|e| CompileError::Identity(e.to_string()))?;
    let (declared, carried) = maknae_graph::identity::carry_forward(
        &source.identity_layer(&stored.layer.label, section_sha256.get("bindings").copied()),
        &source.unresolved_adversaries(),
        &stored.layer,
    );
    if stored.layer != declared {
        return Err(CompileError::Identity(format!(
            "the persisted identity layer differs from the one {} declares",
            declared.source
        )));
    }
    let action_grants = crate::validate_grants(&source.policy().action_grants)
        .map_err(|e| CompileError::Policy(e.to_string()))?;
    let destinations = crate::validate_destinations(&source.policy().destinations)
        .map_err(|e| CompileError::Policy(e.to_string()))?;

    let revision = persisted.revision();
    let mut ids = BTreeMap::new();
    for n in persisted.nodes() {
        ids.insert((n.kind, n.key.clone()), n.id);
    }
    if !ids.contains_key(&(CONFIG_SOURCE, declared.source.clone())) {
        return Err(CompileError::Identity("no bindings source node".into()));
    }
    let mut c = Compiler {
        nodes: persisted.nodes().to_vec(),
        edges: persisted.edges().to_vec(),
        node: persisted.nodes().iter().map(|n| n.id.0).max().unwrap_or(0),
        edge: persisted.edges().iter().map(|e| e.id.0).max().unwrap_or(0),
        label: stored.layer.label.clone(),
        revision,
        source_id: NodeId(0),
        source: source.policy_source().to_string(),
        ids,
        index: BTreeMap::new(),
    };
    c.source_id = c.add_node(CONFIG_SOURCE, c.source.clone(), Attrs::new());

    for cn in vocabulary.iter() {
        if c.ids.contains_key(&(cn.kind, cn.key.clone())) {
            continue;
        }
        c.node += 1;
        let id = NodeId(c.node);
        c.nodes.push(NodeRecord {
            id,
            space: GraphSpace::Kernel,
            kind: cn.kind,
            key: cn.key.clone(),
            label: cn.label.clone(),
            provenance: Provenance {
                kind: ProvenanceKind::Compiled,
                transition: 0,
            },
            revision: 0,
            attrs: cn.attrs.clone(),
        });
        c.ids.insert((cn.kind, cn.key.clone()), id);
    }
    for t in vocabulary.iter().filter(|n| n.kind == TERM) {
        let class = match t.attrs.get(ATTR_CLASS) {
            Some(AttrValue::Str(s)) => s.as_str(),
            _ => "",
        };
        let from = c.id_of(TERM, &t.key)?;
        let to = c.id_of(CLASS, class).map_err(|_| {
            CompileError::Graph(format!("term `{}` names no compiled class", t.key))
        })?;
        c.add_edge(from, MEMBER_OF, to);
    }

    let admin = c.id_of(ROLE, "admin")?;
    let user = c.id_of(ROLE, "user")?;
    let policy = source.policy();
    if permissions_declared(
        policy.section_canonical("permissions"),
        policy.deny_sources(),
        policy.allow_sources(),
    )? {
        let sec = c.section("permissions", section_sha256, "permissions")?;
        for (effect, entries) in [
            (Effect::Deny, policy.deny_sources()),
            (Effect::Allow, policy.allow_sources()),
        ] {
            let (edge, word) = effect_attrs(effect);
            for (i, entry) in entries.iter().enumerate() {
                let mut attrs = Attrs::new();
                attrs.insert(ATTR_ENTRY.into(), AttrValue::Str(entry.clone()));
                attrs.insert(ATTR_EFFECT.into(), AttrValue::Str(word.into()));
                let id = c.rule(
                    format!("rule:permissions:{word}:{i}"),
                    attrs,
                    &sec,
                    Cited::Path {
                        effect,
                        source: entry.clone(),
                    },
                );
                c.add_edge(admin, edge, id);
                c.add_edge(user, edge, id);
            }
        }
    }
    for (role, (allow, deny)) in &action_grants.0 {
        let role_key = static_role(role)?;
        let role_id = c.id_of(ROLE, role_key)?;
        let sec = c.section(&format!("roles.{role}"), section_sha256, "roles")?;
        for (effect, terms) in [(Effect::Deny, deny), (Effect::Allow, allow)] {
            let (edge, word) = effect_attrs(effect);
            for (i, term) in terms.iter().enumerate() {
                let term_id = c.id_of(TERM, term.as_str())?;
                let mut attrs = Attrs::new();
                attrs.insert(ATTR_TERM.into(), AttrValue::Str(term.as_str().into()));
                attrs.insert(ATTR_EFFECT.into(), AttrValue::Str(word.into()));
                let id = c.rule(
                    format!("rule:roles.{role}:{word}:{i}"),
                    attrs,
                    &sec,
                    Cited::Grant {
                        role: role_key,
                        term: term.as_str().into(),
                        effect,
                    },
                );
                c.add_edge(id, MATCHES, term_id);
                c.add_edge(role_id, edge, id);
            }
        }
    }
    for (role, allowed) in &destinations.0 {
        let role_key = static_role(role)?;
        let role_id = c.id_of(ROLE, role_key)?;
        let sec = c.section(
            &format!("destinations.{role}"),
            section_sha256,
            "destinations",
        )?;
        for (i, d) in allowed.iter().enumerate() {
            let mut attrs = Attrs::new();
            attrs.insert(ATTR_DESTINATION.into(), AttrValue::Str(d.clone()));
            let id = c.rule(
                format!("rule:destinations.{role}:allow:{i}"),
                attrs,
                &sec,
                Cited::Destination {
                    role: role_key,
                    destination: d.clone(),
                },
            );
            c.add_edge(role_id, PERMITS, id);
        }
    }

    let builder = c.nodes.into_iter().fold(
        GraphBuilder::new(GraphSpace::Kernel, revision),
        GraphBuilder::node,
    );
    let builder = c.edges.into_iter().fold(builder, GraphBuilder::edge);
    let graph = Arc::new(
        builder
            .build(&SCHEMA, vocabulary)
            .map_err(|e| CompileError::Graph(e.to_string()))?,
    );
    let loaded = LoadedPolicy {
        policy: source.policy().clone(),
        roles: Roles::Graph(GraphBindings::new(graph.clone(), &declared.source)),
        action_grants,
        destinations,
    };
    Ok(Snapshot {
        graph,
        persisted,
        loaded,
        index: c.index,
        sections: section_sha256.clone(),
        problems: carried_problems(source.identity_problems(), &carried, source.bindings()).into(),
    })
}

/// The load's problems with each carried-forward adversary name said so; an unbound
/// conflict on a carried uid is folded into that uid's carried record, so each uid is
/// reported once.
fn carried_problems(
    problems: &[IdentityProblem],
    carried: &[maknae_graph::identity::Carried],
    bindings: &maknae_config::Bindings,
) -> Vec<IdentityProblem> {
    let listed_under = |name: &str| -> Vec<(String, &'static str)> {
        bindings
            .roles
            .iter()
            .flatten()
            .filter(|(_, entries)| entries.iter().any(|e| e.render() == name))
            .filter_map(|(role, _)| crate::role::Role::from_key(role))
            .map(|r| (name.to_string(), r.key()))
            .collect()
    };
    let folded = |uid: u32| {
        problems.iter().find_map(|p| match p {
            IdentityProblem::Unbound { uid: u, names, .. } if *u == uid => Some(
                names
                    .iter()
                    .flat_map(|n| listed_under(n))
                    .collect::<Vec<_>>(),
            ),
            _ => None,
        })
    };
    problems
        .iter()
        .filter(|p| {
            !matches!(p, IdentityProblem::Unbound { uid, .. }
                if carried.iter().any(|c| c.uid == *uid))
        })
        .map(|p| match p {
            IdentityProblem::UnresolvedAdversary { name } => {
                match carried.iter().find(|c| c.name == *name) {
                    Some(c) => {
                        let first = carried.iter().find(|f| f.uid == c.uid).map(|f| &f.name);
                        let fold = (first == Some(&c.name)).then(|| folded(c.uid)).flatten();
                        IdentityProblem::CarriedForward {
                            uid: c.uid,
                            name: c.name.clone(),
                            overrides: c
                                .overrides
                                .iter()
                                .filter_map(|e| {
                                    crate::role::Role::from_key(&e.role)
                                        .map(|r| (e.name.clone(), r.key()))
                                })
                                .chain(fold.into_iter().flatten())
                                .collect(),
                        }
                    }
                    None => p.clone(),
                }
            }
            _ => p.clone(),
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{compiled_set, test_digest};
    use maknae_graph::format::encode;
    use maknae_graph::identity::build;
    use maknae_graph::kernel::{persisted_compiled_set, SUBJECT};
    use maknae_graph::schema::CompiledNode;

    const SHIPPED: &str = include_str!("../../../packaging/common/authz.yaml");
    const BINDINGS: &str = "schema_version: 1\nbindings:\n  admin: [\"alex\"]\n  user: [\"ursula\"]\n  guest: [\"gus\"]\n  adversary: [\"mallory\"]\n";
    const WITH_GRANTS_AND_DESTS: &str = "schema_version: 1\nroles:\n  admin:\n    allow: [\"admin.status\"]\n    deny: [\"admin.config.show\"]\n  user:\n    allow: [\"session.prompt\"]\ndestinations:\n  user:\n    allow: [\"provider:openai\"]\n";
    const PATH: &str = "/etc/maknae/authz.yaml";
    const DIR: &str = "/etc/maknae";
    const LABEL: &str = "UNCLASSIFIED";

    fn uids(pairs: &[(&str, u32)]) -> BTreeMap<String, u32> {
        pairs.iter().map(|(n, u)| (n.to_string(), *u)).collect()
    }

    fn principal() -> maknae_config::Principal {
        maknae_config::Principal {
            name: "operator".into(),
            uid: 501,
        }
    }

    fn parse(body: &str) -> maknae_config::AuthzPolicy {
        maknae_config::parse_authz(body).unwrap()
    }

    fn source(authz: &str) -> PolicySource {
        source_with(authz, None)
    }

    fn source_with(authz: &str, bindings: Option<&str>) -> PolicySource {
        PolicySource::from_parts(
            parse(authz),
            bindings.map_or_else(maknae_config::Bindings::missing, |b| {
                maknae_config::parse_bindings(b).unwrap()
            }),
            uids(&[
                ("alex", 1000),
                ("ursula", 1001),
                ("gus", 1002),
                ("mallory", 666),
                ("root", 0),
            ]),
            principal(),
            crate::PolicyPaths::in_dir(std::path::Path::new(DIR)),
        )
        .unwrap()
    }

    fn digests(s: &PolicySource) -> BTreeMap<String, [u8; 32]> {
        s.section_digests(test_digest)
    }

    fn persisted_layer(l: &maknae_graph::identity::IdentityLayer) -> Arc<Graph> {
        Arc::new(
            build(
                l,
                None,
                None,
                &persisted_compiled_set(LABEL),
                [1; 32],
                5,
                ProvenanceKind::Seed,
            )
            .unwrap(),
        )
    }

    fn persisted(s: &PolicySource) -> Arc<Graph> {
        persisted_layer(&s.identity_layer(LABEL, digests(s).get("bindings").copied()))
    }

    fn snap(s: &PolicySource) -> Snapshot {
        compile(persisted(s), s, &compiled_set(LABEL), &digests(s)).unwrap()
    }

    fn shipped_with_bindings() -> PolicySource {
        source_with(SHIPPED, Some(BINDINGS))
    }

    fn str_attr<'a>(n: &'a NodeRecord, k: &str) -> Option<&'a str> {
        match n.attrs.get(k) {
            Some(AttrValue::Str(s)) => Some(s),
            _ => None,
        }
    }

    #[test]
    fn the_policy_digest_folds_every_section_digest_in_section_order() {
        let s = shipped_with_bindings();
        let lines: String = digests(&s)
            .iter()
            .map(|(k, d)| format!("{k}={}\n", hex(d)))
            .collect();
        assert!(lines.starts_with("bindings="), "{lines}");
        assert!(lines.contains("\npermissions="), "{lines}");
        assert_eq!(
            snap(&s).policy_sha256(test_digest),
            hex(&test_digest(lines.as_bytes()))
        );
        let edited = source_with(&SHIPPED.replacen("Read(", "Write(", 1), Some(BINDINGS));
        assert_ne!(
            snap(&edited).policy_sha256(test_digest),
            snap(&s).policy_sha256(test_digest)
        );
    }

    #[test]
    fn the_in_memory_graph_carries_identity_terms_classes_rules_and_sections() {
        let s = shipped_with_bindings();
        let snap = snap(&s);
        let g = snap.graph();
        assert_eq!(g.nodes().iter().filter(|n| n.kind == TERM).count(), 61);
        assert_eq!(g.nodes().iter().filter(|n| n.kind == CLASS).count(), 7);
        let rules: Vec<_> = g.nodes().iter().filter(|n| n.kind == RULE).collect();
        assert_eq!(rules.len(), 24);
        let admin = g.lookup(ROLE, "admin").unwrap();
        assert_eq!(g.out_edges(admin.id, DENIES).count(), 18);
        assert_eq!(g.out_edges(admin.id, PERMITS).count(), 6);
        let grants = g
            .lookup(SECTION, "/etc/maknae/authz.yaml#roles.admin")
            .unwrap();
        assert_eq!(g.in_edges(grants.id, DECLARED_BY).count(), 4);
        let user = g.lookup(ROLE, "user").unwrap();
        assert_eq!(g.out_edges(user.id, DENIES).count(), 18);
        assert_eq!(g.out_edges(user.id, PERMITS).count(), 2);
        let sec = g
            .lookup(SECTION, "/etc/maknae/authz.yaml#permissions")
            .unwrap();
        assert_eq!(g.in_edges(sec.id, DECLARED_BY).count(), 20);
        assert_eq!(g.out_edges(sec.id, PART_OF).count(), 1);
        let src = g.lookup(CONFIG_SOURCE, PATH).unwrap();
        assert_eq!(
            g.out_edges(sec.id, PART_OF).next().map(|e| e.to),
            Some(src.id)
        );
        assert_eq!(
            str_attr(sec, ATTR_SHA256),
            Some(
                hex(&test_digest(
                    s.policy()
                        .section_canonical("permissions")
                        .unwrap()
                        .as_bytes()
                ))
                .as_str()
            )
        );
        assert_eq!(snap.persisted().revision(), 5);
        assert_eq!(snap.revision(), 5);
        assert_eq!(g.revision(), 5);
        for n in snap.persisted().nodes() {
            assert_eq!(g.node(n.id), Some(n));
        }
        assert_eq!(
            g.edges().len() - snap.persisted().edges().len(),
            61 + 1 + 20 * 3 + 1 + 4 * 3
        );

        let deny0 = g.lookup(RULE, "rule:permissions:deny:0").unwrap();
        assert_eq!(str_attr(deny0, ATTR_ENTRY), Some("Read(~/.ssh/**)"));
        assert_eq!(str_attr(deny0, ATTR_EFFECT), Some("deny"));
        let allow1 = g.lookup(RULE, "rule:permissions:allow:1").unwrap();
        assert_eq!(str_attr(allow1, ATTR_ENTRY), Some("Write(~/projects/**)"));
        assert_eq!(str_attr(allow1, ATTR_EFFECT), Some("allow"));
        assert!(g.out_edges(admin.id, PERMITS).any(|e| e.to == allow1.id));
        assert!(g.out_edges(user.id, DENIES).any(|e| e.to == deny0.id));

        let max_persisted = snap
            .persisted()
            .nodes()
            .iter()
            .map(|n| n.id.0)
            .max()
            .unwrap();
        for n in g.nodes().iter().filter(|n| n.id.0 > max_persisted) {
            assert_eq!(n.label, LABEL);
            if n.kind == TERM || n.kind == CLASS {
                assert_eq!(n.provenance.kind, ProvenanceKind::Compiled);
                assert_eq!((n.provenance.transition, n.revision), (0, 0));
            } else {
                assert_eq!(n.provenance.kind, ProvenanceKind::Seed);
                assert_eq!((n.provenance.transition, n.revision), (5, 5));
            }
        }
        let max_edge = snap
            .persisted()
            .edges()
            .iter()
            .map(|e| e.id.0)
            .max()
            .unwrap();
        for e in g.edges().iter().filter(|e| e.id.0 > max_edge) {
            assert_eq!(e.label, LABEL);
            assert_eq!(e.provenance.kind, ProvenanceKind::Seed);
            assert_eq!((e.provenance.transition, e.revision), (5, 5));
        }

        let read = g.lookup(TERM, "fs.read").unwrap();
        let fs = g.lookup(CLASS, "fs").unwrap();
        let classes: Vec<NodeId> = g.out_edges(read.id, MEMBER_OF).map(|e| e.to).collect();
        assert_eq!(classes, vec![fs.id]);
        assert_eq!(g.in_edges(fs.id, MEMBER_OF).count(), 10);
        assert_eq!(
            g.lookup(SUBJECT, "uid:666").map(|n| n.id),
            snap.persisted().lookup(SUBJECT, "uid:666").map(|n| n.id)
        );
    }

    #[test]
    fn rule_citations_still_name_authz_yaml_sections() {
        let s = shipped_with_bindings();
        let snap = snap(&s);
        let deny = snap
            .cite(&Cited::Path {
                effect: Effect::Deny,
                source: "Read(~/.ssh/**)".into(),
            })
            .unwrap();
        assert_eq!(deny.section, "/etc/maknae/authz.yaml#permissions");
        let g = snap.graph();
        let authz = g
            .lookup(CONFIG_SOURCE, "/etc/maknae/authz.yaml")
            .expect("in-memory policy source");
        let bindings = g
            .lookup(CONFIG_SOURCE, "/etc/maknae/bindings.yaml")
            .expect("persisted identity source");
        assert_ne!(authz.id, bindings.id);
        assert!(g
            .lookup(SECTION, "/etc/maknae/bindings.yaml#bindings")
            .is_some());
        assert!(snap
            .persisted()
            .lookup(CONFIG_SOURCE, "/etc/maknae/authz.yaml")
            .is_none());
    }

    #[test]
    fn a_cited_deny_resolves_to_its_rule_node_and_section() {
        let snap = snap(&shipped_with_bindings());
        let c = snap
            .cite(&Cited::Path {
                effect: Effect::Deny,
                source: "Read(~/.ssh/**)".into(),
            })
            .unwrap();
        let node = snap.graph().node(NodeId(c.node)).unwrap();
        assert_eq!(node.kind, RULE);
        assert_eq!(str_attr(node, ATTR_ENTRY), Some("Read(~/.ssh/**)"));
        assert_eq!(c.section, "/etc/maknae/authz.yaml#permissions");
        assert_eq!(
            snap.cite(&Cited::Path {
                effect: Effect::Deny,
                source: "Read(/nowhere)".into(),
            }),
            None
        );
        let a = snap
            .cite(&Cited::Path {
                effect: Effect::Allow,
                source: "Read(~/**)".into(),
            })
            .unwrap();
        assert_eq!(
            snap.graph().node(NodeId(a.node)).map(|n| n.key.as_str()),
            Some("rule:permissions:allow:0")
        );
        assert_eq!(
            snap.cite(&Cited::Path {
                effect: Effect::Deny,
                source: "Read(~/**)".into(),
            }),
            None
        );
    }

    #[test]
    fn a_repeated_entry_cites_its_first_rule() {
        let s = source("schema_version: 1\npermissions:\n  deny: [\"Read(/a)\", \"Read(/a)\"]\n");
        let snap = snap(&s);
        let c = snap
            .cite(&Cited::Path {
                effect: Effect::Deny,
                source: "Read(/a)".into(),
            })
            .unwrap();
        assert_eq!(
            snap.graph().node(NodeId(c.node)).map(|n| n.key.as_str()),
            Some("rule:permissions:deny:0")
        );
        assert!(snap
            .graph()
            .lookup(RULE, "rule:permissions:deny:1")
            .is_some());
    }

    #[test]
    fn grants_and_destinations_are_rule_nodes_matching_terms() {
        let s = source(WITH_GRANTS_AND_DESTS);
        let snap = snap(&s);
        let g = snap.graph();
        let c = snap
            .cite(&Cited::Grant {
                role: "admin",
                term: "admin.config.show".into(),
                effect: Effect::Deny,
            })
            .unwrap();
        let rule = g.node(NodeId(c.node)).unwrap();
        assert_eq!(rule.key, "rule:roles.admin:deny:0");
        assert_eq!(str_attr(rule, ATTR_TERM), Some("admin.config.show"));
        assert_eq!(str_attr(rule, ATTR_EFFECT), Some("deny"));
        let term = g
            .out_edges(rule.id, MATCHES)
            .next()
            .map(|e| g.node(e.to).unwrap().key.clone());
        assert_eq!(term.as_deref(), Some("admin.config.show"));
        assert_eq!(c.section, "/etc/maknae/authz.yaml#roles.admin");
        let admin = g.lookup(ROLE, "admin").unwrap();
        assert!(g.out_edges(admin.id, DENIES).any(|e| e.to == rule.id));

        let a = snap
            .cite(&Cited::Grant {
                role: "admin",
                term: "admin.status".into(),
                effect: Effect::Allow,
            })
            .unwrap();
        assert!(g.out_edges(admin.id, PERMITS).any(|e| e.to.0 == a.node));
        assert_eq!(
            g.node(NodeId(a.node)).map(|n| n.key.as_str()),
            Some("rule:roles.admin:allow:0")
        );
        let u = snap
            .cite(&Cited::Grant {
                role: "user",
                term: "session.prompt".into(),
                effect: Effect::Allow,
            })
            .unwrap();
        assert_eq!(u.section, "/etc/maknae/authz.yaml#roles.user");
        let user = g.lookup(ROLE, "user").unwrap();
        assert!(g.out_edges(user.id, PERMITS).any(|e| e.to.0 == u.node));
        assert_eq!(
            snap.cite(&Cited::Grant {
                role: "user",
                term: "session.prompt".into(),
                effect: Effect::Deny,
            }),
            None
        );

        let d = snap
            .cite(&Cited::Destination {
                role: "user",
                destination: "provider:openai".into(),
            })
            .unwrap();
        assert_eq!(d.section, "/etc/maknae/authz.yaml#destinations.user");
        let dn = g.node(NodeId(d.node)).unwrap();
        assert_eq!(dn.key, "rule:destinations.user:allow:0");
        assert_eq!(str_attr(dn, ATTR_DESTINATION), Some("provider:openai"));
        assert!(g.out_edges(user.id, PERMITS).any(|e| e.to == dn.id));
        assert_eq!(g.in_edges(dn.id, PERMITS).count(), 1);
        assert_eq!(
            snap.cite(&Cited::Destination {
                role: "admin",
                destination: "provider:openai".into(),
            }),
            None
        );

        let roles_digest = hex(&test_digest(
            s.policy().section_canonical("roles").unwrap().as_bytes(),
        ));
        for key in ["roles.admin", "roles.user"] {
            let sec = g.lookup(SECTION, &format!("{PATH}#{key}")).unwrap();
            assert_eq!(str_attr(sec, ATTR_SHA256), Some(roles_digest.as_str()));
            assert_eq!(g.out_edges(sec.id, PART_OF).count(), 1);
        }
        let dsec = g
            .lookup(SECTION, &format!("{PATH}#destinations.user"))
            .unwrap();
        assert_eq!(
            str_attr(dsec, ATTR_SHA256),
            Some(
                hex(&test_digest(
                    s.policy()
                        .section_canonical("destinations")
                        .unwrap()
                        .as_bytes()
                ))
                .as_str()
            )
        );
        assert!(g.lookup(SECTION, &format!("{PATH}#permissions")).is_none());
        assert!(g.lookup(SECTION, &format!("{PATH}#roles")).is_none());
        assert!(g
            .lookup(SECTION, &format!("{PATH}#schema_version"))
            .is_none());
        assert_eq!(g.nodes().iter().filter(|n| n.kind == RULE).count(), 4);
    }

    fn rebuilt(
        g: &Graph,
        compiled: &CompiledSet,
        map: impl Fn(NodeRecord) -> NodeRecord,
    ) -> Arc<Graph> {
        let b = g.nodes().iter().cloned().map(map).fold(
            GraphBuilder::new(GraphSpace::Kernel, g.revision()),
            GraphBuilder::node,
        );
        let b = g.edges().iter().cloned().fold(b, GraphBuilder::edge);
        Arc::new(b.build(&SCHEMA, compiled).unwrap())
    }

    #[test]
    fn compile_refuses_a_persisted_layer_that_differs_from_the_file() {
        let s = shipped_with_bindings();
        let d = digests(&s);
        let vocab = compiled_set(LABEL);
        let good = s.identity_layer(LABEL, d.get("bindings").copied());
        let mut other_source = good.clone();
        other_source.source = "/other/bindings.yaml".into();
        let mut other_subjects = good.clone();
        other_subjects
            .subjects
            .iter_mut()
            .find(|e| e.uid == 1000)
            .unwrap()
            .role = "user".into();
        let mut other_hash = good.clone();
        other_hash.bindings_sha256 = Some([2; 32]);
        for l in [other_source, other_subjects, other_hash] {
            assert!(matches!(
                compile(persisted_layer(&l), &s, &vocab, &d),
                Err(CompileError::Identity(_))
            ));
        }
        assert!(compile(persisted_layer(&good), &s, &vocab, &d).is_ok());
    }

    #[test]
    fn compile_refuses_a_persisted_graph_that_does_not_extract() {
        let s = shipped_with_bindings();
        let g = persisted(&s);
        let bad = rebuilt(&g, &persisted_compiled_set(LABEL), |mut n| {
            if n.key == maknae_graph::kernel::VOCABULARY_SOURCE_KEY {
                n.attrs
                    .insert(ATTR_SHA256.into(), AttrValue::Str("zz".into()));
            }
            n
        });
        assert!(matches!(
            compile(bad, &s, &compiled_set(LABEL), &digests(&s)),
            Err(CompileError::Identity(_))
        ));
    }

    #[test]
    fn compile_refuses_a_missing_section_digest() {
        let shipped = shipped_with_bindings();
        let grants = source(WITH_GRANTS_AND_DESTS);
        for (g, key) in [
            (&shipped, "permissions"),
            (&grants, "roles"),
            (&grants, "destinations"),
        ] {
            let mut d = digests(g);
            d.remove(key);
            assert_eq!(
                compile(persisted(g), g, &compiled_set(LABEL), &d).unwrap_err(),
                CompileError::Policy(format!("no digest for section `{key}`"))
            );
        }
    }

    fn narrowed(drop: &str, retarget: Option<&str>) -> CompiledSet {
        CompiledSet::new(
            compiled_set(LABEL)
                .iter()
                .filter(|n| n.key != drop)
                .cloned()
                .map(|mut n: CompiledNode| {
                    if let (Some(class), true) = (retarget, n.key == "fs.read") {
                        n.attrs
                            .insert(ATTR_CLASS.into(), AttrValue::Str(class.into()));
                    }
                    n
                })
                .collect(),
        )
    }

    #[test]
    fn a_granted_term_outside_the_vocabulary_refuses() {
        let s = source(WITH_GRANTS_AND_DESTS);
        assert_eq!(
            compile(
                persisted(&s),
                &s,
                &narrowed("admin.status", None),
                &digests(&s)
            )
            .unwrap_err(),
            CompileError::Policy("`admin.status` is not in the compiled vocabulary".into())
        );
    }

    #[test]
    fn a_term_naming_no_compiled_class_refuses() {
        let s = source(WITH_GRANTS_AND_DESTS);
        assert_eq!(
            compile(persisted(&s), &s, &narrowed("", Some("nope")), &digests(&s)).unwrap_err(),
            CompileError::Graph("term `fs.read` names no compiled class".into())
        );
        let mut nodes: Vec<CompiledNode> = compiled_set(LABEL).iter().cloned().collect();
        for n in nodes.iter_mut().filter(|n| n.key == "fs.read") {
            n.attrs.clear();
        }
        assert!(matches!(
            compile(persisted(&s), &s, &CompiledSet::new(nodes), &digests(&s)),
            Err(CompileError::Graph(_))
        ));
    }

    #[test]
    fn a_vocabulary_labelled_differently_from_the_store_refuses() {
        let s = source(WITH_GRANTS_AND_DESTS);
        assert!(matches!(
            compile(persisted(&s), &s, &compiled_set("SECRET"), &digests(&s)),
            Err(CompileError::Graph(_))
        ));
    }

    fn alias_source(body: &str) -> PolicySource {
        PolicySource::from_parts(
            parse("schema_version: 1\n"),
            maknae_config::parse_bindings(&format!("schema_version: 1\nbindings:\n{body}"))
                .unwrap(),
            uids(&[("root", 0), ("toor", 0), ("alex", 1000)]),
            principal(),
            crate::PolicyPaths::in_dir(std::path::Path::new(DIR)),
        )
        .unwrap()
    }

    fn alias_snap(s: &PolicySource) -> Snapshot {
        let d = digests(s);
        compile(
            persisted_layer(&s.identity_layer(LABEL, d.get("bindings").copied())),
            s,
            &compiled_set(LABEL),
            &d,
        )
        .unwrap()
    }

    fn edges_of(snap: &Snapshot, uid: u32) -> Option<(usize, usize)> {
        let g = snap.graph();
        let s = g.lookup(SUBJECT, &format!("uid:{uid}"))?.id;
        Some((
            g.out_edges(s, maknae_graph::kernel::CONTAINED).count(),
            g.out_edges(s, maknae_graph::kernel::BINDS).count(),
        ))
    }

    #[test]
    fn an_alias_uid_under_two_roles_is_unbound_and_reported() {
        let s = alias_source("  admin: [\"root\", \"alex\"]\n  user: [\"toor\"]\n");
        assert_eq!(
            crate::tests::oracle::assemble(&s).err(),
            Some(crate::tests::oracle::Refused::Bindings(
                crate::tests::oracle::BindingError::DuplicateUid {
                    uid: 0,
                    names: ("root".into(), "toor".into())
                }
            )),
            "before #496 this file refused as a whole"
        );
        let snap = alias_snap(&s);
        assert_eq!(edges_of(&snap, 0), None, "uid 0 has no Subject node");
        assert_eq!(edges_of(&snap, 1000), Some((0, 1)), "the rest loads");
        assert_eq!(
            snap.loaded.roles.role_for(0, 501),
            crate::binding::Resolution::NoRole
        );
        assert_eq!(
            snap.identity_problems().as_ref(),
            [IdentityProblem::Unbound {
                uid: 0,
                names: vec!["root".into(), "toor".into()],
                roles: vec!["admin", "user"],
            }]
        );
    }

    #[test]
    fn an_alias_uid_under_a_role_and_adversary_is_contained() {
        let s = alias_source("  admin: [\"root\"]\n  adversary: [\"toor\"]\n");
        assert_eq!(
            crate::tests::oracle::assemble(&s).err(),
            Some(crate::tests::oracle::Refused::Bindings(
                crate::tests::oracle::BindingError::DuplicateUid {
                    uid: 0,
                    names: ("root".into(), "toor".into())
                }
            )),
            "before #496 this file refused as a whole"
        );
        let snap = alias_snap(&s);
        assert_eq!(edges_of(&snap, 0), Some((1, 0)));
        assert_eq!(
            snap.loaded.roles.role_for(0, 501),
            crate::binding::Resolution::Role(crate::role::Role::Adversary)
        );
        assert_eq!(
            snap.identity_problems().as_ref(),
            [IdentityProblem::Contained {
                uid: 0,
                names: vec!["root".into(), "toor".into()],
                roles: vec!["admin", "adversary"],
            }]
        );
    }

    #[test]
    fn an_alias_uid_twice_under_one_role_keeps_the_first_name() {
        let same_role = alias_source("  admin: [\"root\", \"toor\"]\n");
        let layer = same_role.identity_layer(LABEL, Some([1; 32]));
        assert_eq!(layer.subjects.len(), 1);
        assert_eq!(
            (
                layer.subjects[0].uid,
                layer.subjects[0].role.as_str(),
                layer.subjects[0].name.as_str()
            ),
            (0, "admin", "root")
        );
        let snap = alias_snap(&same_role);
        let file = crate::tests::oracle::assemble(&same_role).unwrap();
        assert_eq!(
            snap.loaded.roles.role_for(0, 501),
            file.roles.role_for(0, 501)
        );
        assert_eq!(
            snap.loaded.roles.role_for(0, 501),
            crate::binding::Resolution::Role(crate::role::Role::Admin)
        );
        assert!(snap.identity_problems().is_empty());
    }

    #[test]
    fn the_snapshot_resolves_subjects_through_its_graph() {
        let s = shipped_with_bindings();
        let snap = snap(&s);
        assert!(matches!(snap.loaded.roles, Roles::Graph(_)));
        let file = crate::tests::oracle::assemble(&s).unwrap();
        assert_eq!(snap.subjects(), file.roles.as_subject_bindings());
        assert!(snap.subjects().is_some());
        let none = source(SHIPPED);
        assert_eq!(super::tests::snap(&none).subjects(), None);
        assert_eq!(snap.loaded.policy, *s.policy());
        assert_eq!(snap.loaded.action_grants, file.action_grants);
        assert_eq!(snap.loaded.destinations, file.destinations);
    }

    #[test]
    fn compile_is_deterministic() {
        let s = source_with(WITH_GRANTS_AND_DESTS, Some(BINDINGS));
        let a = snap(&s);
        let b = snap(&s);
        assert_eq!(encode(a.graph()), encode(b.graph()));
        assert_eq!(a.index, b.index);
    }

    #[test]
    fn displays_and_debug_name_their_content() {
        assert_eq!(
            CompileError::Identity("x".into()).to_string(),
            "snapshot identity refused: x"
        );
        assert_eq!(
            CompileError::Graph("x".into()).to_string(),
            "snapshot graph refused: x"
        );
        assert_eq!(
            CompileError::Policy("x".into()).to_string(),
            "snapshot policy refused: x"
        );
        let shown = format!("{:?}", snap(&shipped_with_bindings()));
        assert!(
            shown.starts_with("Snapshot { revision: 5, nodes: "),
            "{shown}"
        );
        assert!(shown.ends_with(", rules: 24 }"), "{shown}");
    }

    #[test]
    fn permissions_entries_without_their_section_refuse() {
        let one = || vec!["Read(/x)".to_string()];
        let refused = |deny: Vec<String>, allow: Vec<String>, msg: &str| {
            assert_eq!(
                permissions_declared(None, &deny, &allow),
                Err(CompileError::Policy(msg.into()))
            );
        };
        refused(
            one(),
            vec![],
            "1 deny and 0 allow permissions entries without a permissions section",
        );
        refused(
            vec![],
            one(),
            "0 deny and 1 allow permissions entries without a permissions section",
        );
        refused(
            one(),
            vec![one()[0].clone(), one()[0].clone()],
            "1 deny and 2 allow permissions entries without a permissions section",
        );
        assert_eq!(permissions_declared(None, &[], &[]), Ok(false));
        assert_eq!(permissions_declared(Some("{}"), &[], &[]), Ok(true));
        assert_eq!(permissions_declared(Some("{}"), &one(), &one()), Ok(true));
    }

    fn sec_request(
        uid: u32,
        action: &str,
        path: Option<&str>,
        dest: Option<&str>,
    ) -> maknae_security::Request {
        use maknae_security::{Action, Attributes, Context, Resource, Subject};
        let mut s = Attributes::new();
        s.insert(
            crate::SUBJECT_UID_KEY,
            maknae_security::AttrValue::Int(i64::from(uid)),
        );
        s.insert(
            maknae_security::SUBJECT_HOME,
            maknae_security::AttrValue::Str("/home/operator".into()),
        );
        let mut r = Attributes::new();
        if let Some(p) = path {
            r.insert(
                crate::RESOURCE_PATH_KEY,
                maknae_security::AttrValue::Str(p.into()),
            );
        }
        if let Some(d) = dest {
            r.insert("destination", maknae_security::AttrValue::Str(d.into()));
        }
        let mut c = Attributes::new();
        c.insert(
            maknae_security::CONTEXT_DAC_LANE,
            maknae_security::AttrValue::Str(maknae_security::Lane::Local.as_str().into()),
        );
        c.insert(
            maknae_security::CONTEXT_FS_OPERATION,
            maknae_security::AttrValue::Str("read".into()),
        );
        maknae_security::Request {
            subject: Subject(s),
            resource: Resource(r),
            action: Action(action.into()),
            context: Context(c),
        }
    }

    #[test]
    fn every_citation_the_decision_core_emits_resolves_in_the_index() {
        let s = source_with(&format!(
            "{}roles:\n  admin:\n    allow: [\"admin.status\", \"session.prompt\"]\n    deny: [\"admin.config.show\"]\n  user:\n    allow: [\"session.prompt\"]\n    deny: [\"session.prompt\"]\ndestinations:\n  admin:\n    allow: [\"provider:openai\"]\n",
            crate::tests::shipped_without_roles()
        ), Some(BINDINGS));
        let snap = snap(&s);
        let oracle = crate::tests::oracle::assemble(&s).unwrap();
        let cases = [
            sec_request(
                1000,
                "fs.read",
                Some("/home/operator/.ssh/id_ed25519"),
                None,
            ),
            sec_request(1001, "fs.read", Some("/home/operator/notes"), None),
            sec_request(1000, "admin.config.show", None, None),
            sec_request(1000, "admin.status", None, None),
            sec_request(1000, "session.prompt", None, Some("provider:openai")),
            sec_request(1001, "session.prompt", None, Some("provider:openai")),
        ];
        for req in cases {
            let d = crate::decide::decide_loaded_cited(&snap.loaded, &principal(), &req);
            assert_eq!(
                crate::decide::decide_loaded_with_role(&oracle, &principal(), &req),
                (d.verdict.clone(), d.role),
                "{}",
                req.action.0
            );
            let cited = d
                .cited
                .unwrap_or_else(|| panic!("{} cites nothing", req.action.0));
            let hit = snap
                .cite(&cited)
                .unwrap_or_else(|| panic!("{cited:?} is not in the index"));
            let rule = snap.graph().node(NodeId(hit.node)).unwrap();
            assert_eq!(rule.kind, RULE);
            let denied = matches!(d.verdict, maknae_security::Verdict::Deny { .. });
            match cited {
                Cited::Destination { .. } => {
                    assert!(matches!(d.verdict, maknae_security::Verdict::Permit { .. }));
                    assert_eq!(str_attr(rule, ATTR_EFFECT), None);
                }
                _ => assert_eq!(
                    str_attr(rule, ATTR_EFFECT),
                    Some(if denied { "deny" } else { "allow" }),
                    "{cited:?}"
                ),
            }
        }
    }
}
