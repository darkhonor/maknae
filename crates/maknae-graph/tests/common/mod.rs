#![allow(dead_code)]

use maknae_graph::graph::GraphBuilder;
use maknae_graph::kernel::*;
use maknae_graph::record::*;
use maknae_graph::schema::{CompiledNode, CompiledSet};

pub fn prov(kind: ProvenanceKind) -> Provenance {
    Provenance {
        kind,
        transition: 0,
    }
}

pub fn node(id: u64, kind: NodeKind, key: &str, p: ProvenanceKind) -> NodeRecord {
    NodeRecord {
        id: NodeId(id),
        space: GraphSpace::Kernel,
        kind,
        key: key.into(),
        label: "UNCLASSIFIED".into(),
        provenance: prov(p),
        revision: 1,
        attrs: Attrs::new(),
    }
}

/// A compiled-kind node exactly as `compiled()` describes it: revision 0, transition 0.
pub fn compiled_node(id: u64, kind: NodeKind, key: &str) -> NodeRecord {
    NodeRecord {
        revision: 0,
        ..node(id, kind, key, ProvenanceKind::Compiled)
    }
}

pub fn edge(id: u64, from: u64, kind: EdgeKind, to: u64) -> EdgeRecord {
    EdgeRecord {
        id: EdgeId(id),
        space: GraphSpace::Kernel,
        from: NodeId(from),
        to: NodeId(to),
        kind,
        label: "UNCLASSIFIED".into(),
        provenance: prov(ProvenanceKind::Seed),
        revision: 1,
        attrs: Attrs::new(),
    }
}

pub fn compiled() -> CompiledSet {
    let c = |kind, key: &str| CompiledNode {
        kind,
        key: key.into(),
        label: "UNCLASSIFIED".into(),
        attrs: Attrs::new(),
    };
    CompiledSet::new(vec![
        c(ROLE, "admin"),
        c(ROLE, "user"),
        c(ROLE, "guest"),
        c(ROLE, ADVERSARY),
        c(TERM, "admin.status"),
        c(CLASS, "Admin"),
    ])
}

/// Node ids: roles 1-4, term 5, class 6, source 10, section 11,
/// subject 20 (uid 1000), subject 21 (uid 1001), rule 30, containment 40.
pub fn builder() -> GraphBuilder {
    let mut section = node(
        11,
        SECTION,
        "authz.yaml#permissions.admin",
        ProvenanceKind::Seed,
    );
    section
        .attrs
        .insert("hash".into(), AttrValue::Str("ab12".into()));
    let mut subject = node(20, SUBJECT, "1000", ProvenanceKind::Seed);
    subject
        .attrs
        .insert("username".into(), AttrValue::Str("alex".into()));
    let mut rule = node(30, RULE, "admin.allow.0", ProvenanceKind::Seed);
    rule.attrs
        .insert("effect".into(), AttrValue::Str("allow".into()));
    let mut containment = node(40, CONTAINMENT, "1001", ProvenanceKind::Operator);
    containment
        .attrs
        .insert("since".into(), AttrValue::U64(1_791_300_000));
    GraphBuilder::new(GraphSpace::Kernel, 7)
        .node(compiled_node(1, ROLE, "admin"))
        .node(compiled_node(2, ROLE, "user"))
        .node(compiled_node(3, ROLE, "guest"))
        .node(compiled_node(4, ROLE, ADVERSARY))
        .node(compiled_node(5, TERM, "admin.status"))
        .node(compiled_node(6, CLASS, "Admin"))
        .node(node(
            10,
            CONFIG_SOURCE,
            "/etc/maknae/authz.yaml",
            ProvenanceKind::Seed,
        ))
        .node(section)
        .node(subject)
        .node(node(21, SUBJECT, "1001", ProvenanceKind::Seed))
        .node(rule)
        .node(containment)
        .edge(edge(100, 20, BINDS, 1))
        .edge(edge(101, 1, PERMITS, 30))
        .edge(edge(102, 30, MATCHES, 5))
        .edge(edge(103, 5, MEMBER_OF, 6))
        .edge(edge(104, 30, DECLARED_BY, 11))
        .edge(edge(105, 11, PART_OF, 10))
        .edge(edge(106, 21, CONTAINED, 40))
        .edge(edge(107, 21, BINDS, 2))
}
