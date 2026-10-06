mod common;

use common::*;
use maknae_graph::graph::{GraphBuilder, GraphError};
use maknae_graph::kernel::*;
use maknae_graph::record::*;
use maknae_graph::schema::{CompiledNode, CompiledSet};

fn build(b: GraphBuilder) -> Result<maknae_graph::graph::Graph, GraphError> {
    b.build(&SCHEMA, &compiled())
}

#[test]
fn fixture_builds_and_answers_queries() {
    let g = build(builder()).unwrap();
    assert_eq!(g.space(), GraphSpace::Kernel);
    assert_eq!(g.revision(), 7);
    assert_eq!(g.schema_version(), SCHEMA_VERSION);
    assert_eq!(g.nodes().len(), 12);
    assert_eq!(g.edges().len(), 8);
    assert_eq!(g.node(NodeId(20)).unwrap().key, "1000");
    assert!(g.node(NodeId(999)).is_none());
    assert_eq!(g.lookup(SUBJECT, "1001").unwrap().id, NodeId(21));
    assert!(g.lookup(SUBJECT, "4242").is_none());
    assert!(g.lookup(ROLE, "1001").is_none());

    let roles: Vec<u64> = g.out_edges(NodeId(21), BINDS).map(|e| e.to.0).collect();
    assert_eq!(roles, vec![2]);
    let contained: Vec<u64> = g.out_edges(NodeId(21), CONTAINED).map(|e| e.to.0).collect();
    assert_eq!(contained, vec![40]);
    assert_eq!(g.out_edges(NodeId(20), CONTAINED).count(), 0);
    assert_eq!(g.out_edges(NodeId(999), BINDS).count(), 0);

    let bound_admin: Vec<u64> = g.in_edges(NodeId(1), BINDS).map(|e| e.from.0).collect();
    assert_eq!(bound_admin, vec![20]);
    let holders: Vec<u64> = g
        .in_edges(NodeId(40), CONTAINED)
        .map(|e| e.from.0)
        .collect();
    assert_eq!(holders, vec![21]);
    assert_eq!(g.in_edges(NodeId(1), PERMITS).count(), 0);
    assert_eq!(g.in_edges(NodeId(999), BINDS).count(), 0);
}

#[test]
fn out_and_in_edges_select_only_the_asked_kind_among_several() {
    let b = builder()
        .node(node(31, RULE, "admin.deny.0", ProvenanceKind::Seed))
        .edge(edge(108, 1, DENIES, 31))
        .edge(edge(109, 31, DECLARED_BY, 11));
    let g = build(b).unwrap();
    let permits: Vec<u64> = g.out_edges(NodeId(1), PERMITS).map(|e| e.to.0).collect();
    let denies: Vec<u64> = g.out_edges(NodeId(1), DENIES).map(|e| e.to.0).collect();
    assert_eq!(permits, vec![30]);
    assert_eq!(denies, vec![31]);
    let declared: Vec<u64> = g
        .in_edges(NodeId(11), DECLARED_BY)
        .map(|e| e.from.0)
        .collect();
    assert_eq!(declared, vec![30, 31]);
    assert_eq!(g.in_edges(NodeId(11), PART_OF).count(), 0);
}

#[test]
fn build_is_order_independent() {
    let forward = build(builder()).unwrap();
    let mut nodes = forward.nodes().to_vec();
    let mut edges = forward.edges().to_vec();
    nodes.reverse();
    edges.reverse();
    let mut b = GraphBuilder::new(GraphSpace::Kernel, 7);
    for n in nodes {
        b = b.node(n);
    }
    for e in edges {
        b = b.edge(e);
    }
    assert_eq!(build(b).unwrap(), forward);
}

#[test]
fn binds_to_adversary_is_forbidden_target() {
    let err = build(builder().edge(edge(200, 20, BINDS, 4))).unwrap_err();
    assert_eq!(err, GraphError::ForbiddenTarget(EdgeId(200)));
}

#[test]
fn record_space_must_match_graph_space() {
    let mut n = node(50, SUBJECT, "2000", ProvenanceKind::Seed);
    n.space = GraphSpace::User(SubjectId(2000));
    assert_eq!(
        build(builder().node(n)).unwrap_err(),
        GraphError::SpaceMismatch
    );
    let mut e = edge(201, 20, BINDS, 2);
    e.space = GraphSpace::Shared;
    assert_eq!(
        build(builder().edge(e)).unwrap_err(),
        GraphError::SpaceMismatch
    );
}

#[test]
fn every_graph_error_is_reachable() {
    let cases: Vec<(GraphBuilder, GraphError)> = vec![
        (
            builder().node(node(60, NodeKind(99), "x", ProvenanceKind::Seed)),
            GraphError::UnknownNodeKind(NodeKind(99)),
        ),
        (
            builder().edge(edge(202, 20, EdgeKind(99), 1)),
            GraphError::UnknownEdgeKind(EdgeKind(99)),
        ),
        (
            builder().node(node(20, SUBJECT, "3000", ProvenanceKind::Seed)),
            GraphError::DuplicateNodeId(NodeId(20)),
        ),
        (
            builder().edge(edge(100, 20, BINDS, 2)),
            GraphError::DuplicateEdgeId(EdgeId(100)),
        ),
        (
            builder().node(node(61, SUBJECT, "1000", ProvenanceKind::Seed)),
            GraphError::DuplicateKey {
                kind: SUBJECT,
                key: "1000".into(),
            },
        ),
        (
            builder().node(node(62, SUBJECT, "", ProvenanceKind::Seed)),
            GraphError::EmptyKey(NodeId(62)),
        ),
        (
            builder().edge(edge(203, 20, BINDS, 77)),
            GraphError::DanglingEdge(EdgeId(203)),
        ),
        (
            builder().edge(edge(204, 77, BINDS, 1)),
            GraphError::DanglingEdge(EdgeId(204)),
        ),
        (
            builder().edge(edge(205, 1, BINDS, 20)),
            GraphError::ForbiddenTriple {
                from: ROLE,
                edge: BINDS,
                to: SUBJECT,
            },
        ),
        (
            builder().node(node(63, SUBJECT, "4000", ProvenanceKind::Compiled)),
            GraphError::CompiledProvenance(NodeId(63)),
        ),
    ];
    for (b, want) in cases {
        assert_eq!(build(b).unwrap_err(), want);
    }
    let mut unlabeled = node(64, SUBJECT, "5000", ProvenanceKind::Seed);
    unlabeled.label.clear();
    assert_eq!(
        build(builder().node(unlabeled)).unwrap_err(),
        GraphError::EmptyLabel
    );
    let mut unlabeled_edge = edge(206, 20, BINDS, 2);
    unlabeled_edge.label.clear();
    assert_eq!(
        build(builder().edge(unlabeled_edge)).unwrap_err(),
        GraphError::EmptyLabel
    );
}

#[test]
fn compiled_nodes_must_match_the_binary_exactly() {
    let mut seeded_role = node(1, ROLE, "admin", ProvenanceKind::Seed);
    seeded_role.provenance = prov(ProvenanceKind::Seed);
    let b = rebuild_with(1, seeded_role);
    assert_eq!(
        build(b).unwrap_err(),
        GraphError::CompiledProvenance(NodeId(1))
    );

    let term_mismatch = GraphError::CompiledMismatch {
        kind: TERM,
        key: "admin.status".into(),
    };
    let mut drifted = compiled_node(5, TERM, "admin.status");
    drifted.attrs.insert("x".into(), AttrValue::U64(1));
    assert_eq!(build(rebuild_with(5, drifted)).unwrap_err(), term_mismatch);
    let mut relabeled = compiled_node(5, TERM, "admin.status");
    relabeled.label = "SECRET".into();
    assert_eq!(
        build(rebuild_with(5, relabeled)).unwrap_err(),
        term_mismatch
    );
    let mut revised = compiled_node(5, TERM, "admin.status");
    revised.revision = 1;
    assert_eq!(build(rebuild_with(5, revised)).unwrap_err(), term_mismatch);
    let mut transitioned = compiled_node(5, TERM, "admin.status");
    transitioned.provenance.transition = 9;
    assert_eq!(
        build(rebuild_with(5, transitioned)).unwrap_err(),
        term_mismatch
    );
    assert!(build(rebuild_with(5, compiled_node(5, TERM, "admin.status"))).is_ok());

    let extra = builder().node(node(70, TERM, "fs.read", ProvenanceKind::Compiled));
    assert_eq!(
        build(extra).unwrap_err(),
        GraphError::CompiledMismatch {
            kind: TERM,
            key: "fs.read".into()
        }
    );

    let mut with_more = compiled().iter().cloned().collect::<Vec<_>>();
    with_more.push(CompiledNode {
        kind: CLASS,
        key: "Fs".into(),
        label: "UNCLASSIFIED".into(),
        attrs: Attrs::new(),
    });
    assert_eq!(
        builder()
            .build(&SCHEMA, &CompiledSet::new(with_more))
            .unwrap_err(),
        GraphError::CompiledMissing {
            kind: CLASS,
            key: "Fs".into()
        }
    );

    let mut wrong_kind = compiled().iter().cloned().collect::<Vec<_>>();
    wrong_kind.push(CompiledNode {
        kind: SUBJECT,
        key: "1000".into(),
        label: "UNCLASSIFIED".into(),
        attrs: Attrs::new(),
    });
    assert_eq!(
        builder()
            .build(&SCHEMA, &CompiledSet::new(wrong_kind))
            .unwrap_err(),
        GraphError::CompiledMismatch {
            kind: SUBJECT,
            key: "1000".into()
        }
    );
}

fn rebuild_with(replace: u64, n: NodeRecord) -> GraphBuilder {
    let g = build(builder()).unwrap();
    let mut b = GraphBuilder::new(GraphSpace::Kernel, 7);
    for old in g.nodes() {
        b = b.node(if old.id.0 == replace {
            n.clone()
        } else {
            old.clone()
        });
    }
    for e in g.edges() {
        b = b.edge(e.clone());
    }
    b
}

#[test]
fn graph_error_messages_name_the_cause() {
    let cases = [
        (
            GraphError::UnknownNodeKind(NodeKind(9)),
            "unknown node kind 9",
        ),
        (
            GraphError::UnknownEdgeKind(EdgeKind(9)),
            "unknown edge kind 9",
        ),
        (
            GraphError::DuplicateNodeId(NodeId(3)),
            "duplicate node id 3",
        ),
        (
            GraphError::DuplicateEdgeId(EdgeId(4)),
            "duplicate edge id 4",
        ),
        (
            GraphError::DuplicateKey {
                kind: NodeKind(3),
                key: "k".into(),
            },
            "duplicate key \"k\" for node kind 3",
        ),
        (GraphError::EmptyKey(NodeId(5)), "node 5 has an empty key"),
        (GraphError::EmptyLabel, "record has an empty label"),
        (
            GraphError::SpaceMismatch,
            "record space differs from the graph space",
        ),
        (
            GraphError::DanglingEdge(EdgeId(6)),
            "edge 6 names a node that does not exist",
        ),
        (
            GraphError::ForbiddenTriple {
                from: NodeKind(1),
                edge: EdgeKind(2),
                to: NodeKind(3),
            },
            "edge kind 2 is not permitted from node kind 1 to node kind 3",
        ),
        (
            GraphError::ForbiddenTarget(EdgeId(7)),
            "edge 7 targets a node no edge of its kind may reach",
        ),
        (
            GraphError::CompiledProvenance(NodeId(8)),
            "node 8 has a provenance its kind does not allow",
        ),
        (
            GraphError::CompiledMismatch {
                kind: NodeKind(6),
                key: "t".into(),
            },
            "compiled node \"t\" of kind 6 disagrees with the binary",
        ),
        (
            GraphError::CompiledMissing {
                kind: NodeKind(7),
                key: "c".into(),
            },
            "compiled node \"c\" of kind 7 is missing",
        ),
        (
            GraphError::ExpansionLimit,
            "graph string references expand past the decode limit",
        ),
    ];
    for (err, text) in cases {
        assert_eq!(err.to_string(), text);
    }
    let long = "é".repeat(100);
    let shown = "é".repeat(64);
    for err in [
        GraphError::DuplicateKey {
            kind: NodeKind(1),
            key: long.clone(),
        },
        GraphError::CompiledMismatch {
            kind: NodeKind(1),
            key: long.clone(),
        },
        GraphError::CompiledMissing {
            kind: NodeKind(1),
            key: long.clone(),
        },
    ] {
        let text = err.to_string();
        assert!(text.contains(&format!("{shown:?}")), "{text}");
        assert!(!text.contains(&"é".repeat(65)), "{text}");
    }
}

#[test]
fn schema_version_comes_from_the_schema_built_against() {
    let v7 = maknae_graph::schema::Schema {
        version: 7,
        node_kinds: SCHEMA.node_kinds,
        edge_kinds: SCHEMA.edge_kinds,
        triples: SCHEMA.triples,
        compiled_kinds: SCHEMA.compiled_kinds,
        forbidden_targets: SCHEMA.forbidden_targets,
    };
    assert_eq!(
        builder().build(&v7, &compiled()).unwrap().schema_version(),
        7
    );
}
