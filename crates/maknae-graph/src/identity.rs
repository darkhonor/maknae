use crate::graph::{Graph, GraphBuilder, GraphError};
use crate::kernel::{
    ADVERSARY, ATTR_NAME, ATTR_SHA256, ATTR_UID, BINDS, CONFIG_SOURCE, CONTAINED, CONTAINMENT,
    DECLARED_BY, PART_OF, ROLE, SCHEMA, SECTION, SUBJECT, VOCABULARY_SOURCE_KEY,
};
use crate::record::{
    AttrValue, Attrs, EdgeId, EdgeKind, EdgeRecord, GraphSpace, NodeId, NodeKind, NodeRecord,
    Provenance, ProvenanceKind,
};
use crate::schema::CompiledSet;
use std::collections::BTreeMap;
use std::fmt;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SubjectEntry {
    pub uid: u32,
    pub name: String,
    pub role: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct IdentityLayer {
    pub source: String,
    pub label: String,
    pub bindings_sha256: Option<[u8; 32]>,
    pub subjects: Vec<SubjectEntry>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Extracted {
    pub layer: IdentityLayer,
    pub vocabulary_sha256: Option<[u8; 32]>,
    pub unbound: Vec<u32>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IdentityError {
    Graph(GraphError),
    BadAttr { node: u64, attr: &'static str },
    UnknownRole(String),
}

impl fmt::Display for IdentityError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Graph(e) => write!(f, "identity layer: {e}"),
            Self::BadAttr { node, attr } => write!(
                f,
                "identity layer: node {node} lacks a valid `{attr}` attribute"
            ),
            Self::UnknownRole(r) => write!(f, "identity layer: role `{r}` is not compiled in"),
        }
    }
}

impl std::error::Error for IdentityError {}

pub fn hex(d: &[u8; 32]) -> String {
    d.iter().map(|b| format!("{b:02x}")).collect()
}

pub fn unhex(s: &str) -> Option<[u8; 32]> {
    if s.len() != 64 || !s.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f')) {
        return None;
    }
    let mut out = [0u8; 32];
    for (o, [hi, lo]) in out.iter_mut().zip(s.as_bytes().as_chunks::<2>().0) {
        *o = (nibble(*hi) << 4) | nibble(*lo);
    }
    Some(out)
}

fn nibble(b: u8) -> u8 {
    match b {
        b'a'..=b'f' => b - b'a' + 10,
        _ => b - b'0',
    }
}

pub fn subject_key(uid: u32) -> String {
    format!("uid:{uid}")
}

pub fn bindings_section_key(source: &str) -> String {
    format!("{source}#bindings")
}

fn containment_key(source: &str) -> String {
    format!("{source}#bindings.{ADVERSARY}")
}

struct Alloc {
    node: u64,
    edge: u64,
    revision: u64,
    prov: Provenance,
    label: String,
}

impl Alloc {
    fn node(&mut self, kind: NodeKind, key: String, attrs: Attrs) -> NodeRecord {
        self.node += 1;
        NodeRecord {
            id: NodeId(self.node),
            space: GraphSpace::Kernel,
            kind,
            key,
            label: self.label.clone(),
            provenance: self.prov,
            revision: self.revision,
            attrs,
        }
    }

    fn edge(&mut self, from: NodeId, kind: EdgeKind, to: NodeId) -> EdgeRecord {
        self.edge += 1;
        EdgeRecord {
            id: EdgeId(self.edge),
            space: GraphSpace::Kernel,
            from,
            to,
            kind,
            label: self.label.clone(),
            provenance: self.prov,
            revision: self.revision,
            attrs: Attrs::new(),
        }
    }
}

pub fn build(
    layer: &IdentityLayer,
    compiled: &CompiledSet,
    vocabulary_sha256: [u8; 32],
    revision: u64,
    initiator: ProvenanceKind,
) -> Result<Graph, IdentityError> {
    let mut a = Alloc {
        node: 0,
        edge: 0,
        revision,
        prov: Provenance {
            kind: initiator,
            transition: revision,
        },
        label: layer.label.clone(),
    };
    let mut b = GraphBuilder::new(GraphSpace::Kernel, revision);

    let source = a.node(CONFIG_SOURCE, layer.source.clone(), Attrs::new());
    let source_id = source.id;
    b = b.node(source);

    let mut vocab_attrs = Attrs::new();
    vocab_attrs.insert(ATTR_SHA256.into(), AttrValue::Str(hex(&vocabulary_sha256)));
    b = b.node(a.node(CONFIG_SOURCE, VOCABULARY_SOURCE_KEY.into(), vocab_attrs));

    let mut role_ids: BTreeMap<&str, NodeId> = BTreeMap::new();
    for c in compiled.iter() {
        let n = NodeRecord {
            label: c.label.clone(),
            provenance: Provenance {
                kind: ProvenanceKind::Compiled,
                transition: 0,
            },
            revision: 0,
            ..a.node(c.kind, c.key.clone(), c.attrs.clone())
        };
        if c.kind == ROLE {
            role_ids.insert(&c.key, n.id);
        }
        b = b.node(n);
    }

    let mut section_id = None;
    if let Some(d) = layer.bindings_sha256 {
        let mut attrs = Attrs::new();
        attrs.insert(ATTR_SHA256.into(), AttrValue::Str(hex(&d)));
        let s = a.node(SECTION, bindings_section_key(&layer.source), attrs);
        let id = s.id;
        b = b.node(s).edge(a.edge(id, PART_OF, source_id));
        section_id = Some(id);
    }

    let mut containment_id = None;
    let mut subjects: Vec<&SubjectEntry> = layer.subjects.iter().collect();
    subjects.sort_by_key(|s| s.uid);
    for s in subjects {
        let role_id = *role_ids
            .get(s.role.as_str())
            .ok_or_else(|| IdentityError::UnknownRole(s.role.clone()))?;
        let mut attrs = Attrs::new();
        attrs.insert(ATTR_NAME.into(), AttrValue::Str(s.name.clone()));
        attrs.insert(ATTR_UID.into(), AttrValue::U64(u64::from(s.uid)));
        let n = a.node(SUBJECT, subject_key(s.uid), attrs);
        let sid = n.id;
        b = b.node(n);
        if s.role == ADVERSARY {
            let cid = match containment_id {
                Some(id) => id,
                None => {
                    let c = a.node(CONTAINMENT, containment_key(&layer.source), Attrs::new());
                    let id = c.id;
                    b = b.node(c);
                    if let Some(sec) = section_id {
                        b = b.edge(a.edge(id, DECLARED_BY, sec));
                    }
                    containment_id = Some(id);
                    id
                }
            };
            b = b.edge(a.edge(sid, CONTAINED, cid));
        } else {
            b = b.edge(a.edge(sid, BINDS, role_id));
        }
        if let Some(sec) = section_id {
            b = b.edge(a.edge(sid, DECLARED_BY, sec));
        }
    }
    b.build(&SCHEMA, compiled).map_err(IdentityError::Graph)
}

fn str_attr<'a>(n: &'a NodeRecord, attr: &'static str) -> Result<&'a str, IdentityError> {
    match n.attrs.get(attr) {
        Some(AttrValue::Str(s)) => Ok(s),
        _ => Err(IdentityError::BadAttr { node: n.id.0, attr }),
    }
}

fn digest_attr(n: &NodeRecord) -> Result<[u8; 32], IdentityError> {
    unhex(str_attr(n, ATTR_SHA256)?).ok_or(IdentityError::BadAttr {
        node: n.id.0,
        attr: ATTR_SHA256,
    })
}

pub fn extract(g: &Graph) -> Result<Extracted, IdentityError> {
    let mut layer = IdentityLayer::default();
    let mut vocabulary_sha256 = None;
    let mut unbound = Vec::new();
    for n in g.nodes().iter().filter(|n| n.kind == CONFIG_SOURCE) {
        if n.key == VOCABULARY_SOURCE_KEY {
            vocabulary_sha256 = Some(digest_attr(n)?);
        } else {
            layer.source = n.key.clone();
            layer.label = n.label.clone();
        }
    }
    if let Some(sec) = g.lookup(SECTION, &bindings_section_key(&layer.source)) {
        layer.bindings_sha256 = Some(digest_attr(sec)?);
    }
    for n in g.nodes().iter().filter(|n| n.kind == SUBJECT) {
        let uid = match n.attrs.get(ATTR_UID) {
            Some(AttrValue::U64(u)) => u32::try_from(*u).ok(),
            _ => None,
        }
        .ok_or(IdentityError::BadAttr {
            node: n.id.0,
            attr: ATTR_UID,
        })?;
        let name = str_attr(n, ATTR_NAME)?.to_string();
        let role = if g.out_edges(n.id, CONTAINED).next().is_some() {
            Some(ADVERSARY.to_string())
        } else {
            g.out_edges(n.id, BINDS)
                .next()
                .and_then(|e| g.node(e.to))
                .map(|r| r.key.clone())
        };
        match role {
            Some(role) => layer.subjects.push(SubjectEntry { uid, name, role }),
            None => unbound.push(uid),
        }
    }
    layer.subjects.sort_by_key(|s| s.uid);
    unbound.sort_unstable();
    Ok(Extracted {
        layer,
        vocabulary_sha256,
        unbound,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::graph::GraphBuilder;
    use crate::kernel::{ADVERSARY, BINDS, CONTAINED, CONTAINMENT, DECLARED_BY, ROLE, SECTION};
    use crate::record::{AttrValue, EdgeId, EdgeRecord, GraphSpace, NodeId, ProvenanceKind};
    use crate::schema::CompiledSet;

    fn layer(bindings: Option<&str>, subjects: &[(u32, &str, &str)]) -> IdentityLayer {
        IdentityLayer {
            source: "/etc/maknae/authz.yaml".into(),
            label: "UNCLASSIFIED".into(),
            bindings_sha256: bindings.map(|s| {
                let mut d = [0u8; 32];
                d[..s.len()].copy_from_slice(s.as_bytes());
                d
            }),
            subjects: subjects
                .iter()
                .map(|(u, n, r)| SubjectEntry {
                    uid: *u,
                    name: (*n).into(),
                    role: (*r).into(),
                })
                .collect(),
        }
    }

    fn roles() -> CompiledSet {
        crate::kernel::persisted_compiled_set("UNCLASSIFIED")
    }

    const VOCAB: [u8; 32] = [9; 32];

    fn rebuild(
        g: &Graph,
        keep: impl Fn(&EdgeRecord) -> bool,
        extra: Vec<EdgeRecord>,
        map_node: impl Fn(NodeRecord) -> NodeRecord,
    ) -> Result<Graph, GraphError> {
        let b = GraphBuilder::new(GraphSpace::Kernel, g.revision());
        let b = g
            .nodes()
            .iter()
            .cloned()
            .map(map_node)
            .fold(b, |b, n| b.node(n));
        let b = g
            .edges()
            .iter()
            .filter(|e| keep(e))
            .cloned()
            .chain(extra)
            .fold(b, |b, e| b.edge(e));
        b.build(&crate::kernel::SCHEMA, &roles())
    }

    #[test]
    fn build_then_extract_round_trips_every_layer_shape() {
        for l in [
            layer(None, &[]),
            layer(Some("e"), &[]),
            layer(
                Some("x"),
                &[
                    (1000, "alex", "admin"),
                    (1001, "ursula", "user"),
                    (1002, "gus", "guest"),
                    (666, "mallory", "adversary"),
                ],
            ),
        ] {
            let g = build(&l, &roles(), VOCAB, 7, ProvenanceKind::Seed).unwrap();
            let e = extract(&g).unwrap();
            let mut want = l.clone();
            want.subjects.sort_by_key(|s| s.uid);
            assert_eq!(e.layer, want);
            assert_eq!(e.vocabulary_sha256, Some(VOCAB));
            assert!(e.unbound.is_empty());
            assert_eq!(g.revision(), 7);
        }
    }

    #[test]
    fn records_carry_the_initiator_revision_and_label() {
        let g = build(
            &layer(Some("x"), &[(1000, "alex", "admin")]),
            &roles(),
            VOCAB,
            7,
            ProvenanceKind::RootFile,
        )
        .unwrap();
        for n in g.nodes() {
            assert_eq!(n.label, "UNCLASSIFIED");
            if n.kind == ROLE {
                assert_eq!(n.provenance.kind, ProvenanceKind::Compiled);
                assert_eq!((n.revision, n.provenance.transition), (0, 0));
            } else {
                assert_eq!(n.provenance.kind, ProvenanceKind::RootFile);
                assert_eq!((n.revision, n.provenance.transition), (7, 7));
            }
        }
        assert_eq!(g.edges().len(), 3);
        for e in g.edges() {
            assert_eq!(e.label, "UNCLASSIFIED");
            assert_eq!(e.provenance.kind, ProvenanceKind::RootFile);
            assert_eq!((e.revision, e.provenance.transition), (7, 7));
        }
        let s = g.lookup(crate::kernel::SUBJECT, "uid:1000").unwrap();
        assert_eq!(s.attrs.get(ATTR_NAME), Some(&AttrValue::Str("alex".into())));
        assert_eq!(s.attrs.get(ATTR_UID), Some(&AttrValue::U64(1000)));
        let v = g
            .lookup(crate::kernel::CONFIG_SOURCE, VOCABULARY_SOURCE_KEY)
            .unwrap();
        assert_eq!(v.attrs.get(ATTR_SHA256), Some(&AttrValue::Str(hex(&VOCAB))));
        let sec = g
            .lookup(SECTION, &bindings_section_key("/etc/maknae/authz.yaml"))
            .unwrap();
        assert_eq!(g.out_edges(sec.id, crate::kernel::PART_OF).count(), 1);
        assert_eq!(g.out_edges(s.id, DECLARED_BY).count(), 1);
        assert_eq!(subject_key(1000), "uid:1000");
    }

    #[test]
    fn adversary_is_a_contained_edge_never_a_binds_edge() {
        let g = build(
            &layer(Some("x"), &[(666, "mallory", "adversary")]),
            &roles(),
            VOCAB,
            1,
            ProvenanceKind::Seed,
        )
        .unwrap();
        let s = g.lookup(crate::kernel::SUBJECT, "uid:666").unwrap();
        assert_eq!(g.out_edges(s.id, BINDS).count(), 0);
        assert_eq!(g.out_edges(s.id, CONTAINED).count(), 1);
        let c = g
            .lookup(CONTAINMENT, "/etc/maknae/authz.yaml#bindings.adversary")
            .unwrap();
        assert_eq!(g.out_edges(c.id, DECLARED_BY).count(), 1);
    }

    #[test]
    fn two_adversaries_share_one_containment_node() {
        let g = build(
            &layer(
                Some("x"),
                &[(666, "mallory", "adversary"), (667, "eve", "adversary")],
            ),
            &roles(),
            VOCAB,
            1,
            ProvenanceKind::Seed,
        )
        .unwrap();
        assert_eq!(
            g.nodes().iter().filter(|n| n.kind == CONTAINMENT).count(),
            1
        );
        let c = g
            .lookup(CONTAINMENT, "/etc/maknae/authz.yaml#bindings.adversary")
            .unwrap();
        assert_eq!(g.in_edges(c.id, CONTAINED).count(), 2);
    }

    #[test]
    fn contained_outranks_binds_on_extract() {
        let g = build(
            &layer(Some("x"), &[(666, "mallory", "adversary")]),
            &roles(),
            VOCAB,
            1,
            ProvenanceKind::Seed,
        )
        .unwrap();
        let s = g.lookup(crate::kernel::SUBJECT, "uid:666").unwrap().id;
        let admin = g.lookup(ROLE, "admin").unwrap().id;
        let mut extra = g.edges()[0].clone();
        extra.id = EdgeId(1000);
        extra.from = s;
        extra.to = admin;
        extra.kind = BINDS;
        let both = rebuild(&g, |_| true, vec![extra], |n| n).unwrap();
        assert_eq!(both.out_edges(s, BINDS).count(), 1);
        let e = extract(&both).unwrap();
        assert_eq!(e.layer.subjects[0].role, ADVERSARY);
    }

    #[test]
    fn absent_bindings_has_no_section_node_and_empty_bindings_has_one() {
        let none = build(&layer(None, &[]), &roles(), VOCAB, 1, ProvenanceKind::Seed).unwrap();
        assert!(none
            .lookup(SECTION, "/etc/maknae/authz.yaml#bindings")
            .is_none());
        let empty = build(
            &layer(Some("e"), &[]),
            &roles(),
            VOCAB,
            1,
            ProvenanceKind::Seed,
        )
        .unwrap();
        assert!(empty
            .lookup(SECTION, "/etc/maknae/authz.yaml#bindings")
            .is_some());
        assert_eq!(extract(&none).unwrap().layer.bindings_sha256, None);
        assert!(extract(&empty).unwrap().layer.bindings_sha256.is_some());
    }

    #[test]
    fn subjects_without_a_bindings_section_declare_nothing() {
        let g = build(
            &layer(
                None,
                &[(1000, "alex", "admin"), (666, "mallory", "adversary")],
            ),
            &roles(),
            VOCAB,
            1,
            ProvenanceKind::Seed,
        )
        .unwrap();
        assert_eq!(
            g.edges().iter().filter(|e| e.kind == DECLARED_BY).count(),
            0
        );
        assert_eq!(extract(&g).unwrap().layer.subjects.len(), 2);
    }

    #[test]
    fn a_role_outside_the_compiled_set_refuses_and_a_vanished_role_is_reported_on_extract() {
        let bad = build(
            &layer(Some("x"), &[(1, "a", "superadmin")]),
            &roles(),
            VOCAB,
            1,
            ProvenanceKind::Seed,
        );
        assert_eq!(bad, Err(IdentityError::UnknownRole("superadmin".into())));
        let adversary = build(
            &layer(Some("x"), &[(1, "a", "adversary")]),
            &CompiledSet::default(),
            VOCAB,
            1,
            ProvenanceKind::Seed,
        );
        assert_eq!(
            adversary,
            Err(IdentityError::UnknownRole("adversary".into()))
        );
        let mut l = layer(Some("x"), &[(1000, "alex", "admin")]);
        let g = build(&l, &roles(), VOCAB, 1, ProvenanceKind::Seed).unwrap();
        let g2 = rebuild(&g, |e| e.kind != BINDS, vec![], |n| n).unwrap();
        let e = extract(&g2).unwrap();
        assert_eq!(e.unbound, vec![1000]);
        l.subjects.clear();
        assert_eq!(e.layer, l);
    }

    #[test]
    fn extract_reports_unbound_uids_sorted() {
        let g = build(
            &layer(
                Some("x"),
                &[
                    (1002, "c", "user"),
                    (1000, "a", "admin"),
                    (1001, "b", "guest"),
                ],
            ),
            &roles(),
            VOCAB,
            1,
            ProvenanceKind::Seed,
        )
        .unwrap();
        let g2 = rebuild(&g, |e| e.kind != BINDS, vec![], |n| n).unwrap();
        assert_eq!(extract(&g2).unwrap().unbound, vec![1000, 1001, 1002]);
    }

    #[test]
    fn extract_on_the_s2_empty_graph_is_the_empty_layer_with_no_digest() {
        let g = GraphBuilder::new(GraphSpace::Kernel, 1)
            .build(&crate::kernel::SCHEMA, &CompiledSet::default())
            .unwrap();
        let e = extract(&g).unwrap();
        assert_eq!(
            e,
            Extracted {
                layer: IdentityLayer::default(),
                vocabulary_sha256: None,
                unbound: vec![]
            }
        );
    }

    fn with_attr(g: &Graph, id: NodeId, attr: &str, v: Option<AttrValue>) -> Graph {
        rebuild(
            g,
            |_| true,
            vec![],
            |mut n| {
                if n.id == id {
                    match &v {
                        Some(v) => {
                            n.attrs.insert(attr.into(), v.clone());
                        }
                        None => {
                            n.attrs.remove(attr);
                        }
                    }
                }
                n
            },
        )
        .unwrap()
    }

    #[test]
    fn extract_refuses_a_malformed_attribute_naming_the_node() {
        let g = build(
            &layer(Some("x"), &[(1000, "alex", "admin")]),
            &roles(),
            VOCAB,
            1,
            ProvenanceKind::Seed,
        )
        .unwrap();
        let subject = g.lookup(crate::kernel::SUBJECT, "uid:1000").unwrap().id;
        let vocab = g
            .lookup(crate::kernel::CONFIG_SOURCE, VOCABULARY_SOURCE_KEY)
            .unwrap()
            .id;
        let section = g
            .lookup(SECTION, "/etc/maknae/authz.yaml#bindings")
            .unwrap()
            .id;
        let cases = [
            (vocab, ATTR_SHA256, None),
            (vocab, ATTR_SHA256, Some(AttrValue::Str("AB".repeat(32)))),
            (vocab, ATTR_SHA256, Some(AttrValue::U64(1))),
            (section, ATTR_SHA256, None),
            (section, ATTR_SHA256, Some(AttrValue::Str("zz".into()))),
            (subject, ATTR_UID, None),
            (subject, ATTR_UID, Some(AttrValue::Str("1000".into()))),
            (
                subject,
                ATTR_UID,
                Some(AttrValue::U64(u64::from(u32::MAX) + 1)),
            ),
            (subject, ATTR_NAME, None),
            (subject, ATTR_NAME, Some(AttrValue::U64(1))),
        ];
        for (id, attr, v) in cases {
            let bad = with_attr(&g, id, attr, v.clone());
            assert_eq!(
                extract(&bad),
                Err(IdentityError::BadAttr { node: id.0, attr }),
                "{attr} = {v:?}"
            );
        }
        let max = with_attr(
            &g,
            subject,
            ATTR_UID,
            Some(AttrValue::U64(u64::from(u32::MAX))),
        );
        assert_eq!(extract(&max).unwrap().layer.subjects[0].uid, u32::MAX);
    }

    #[test]
    fn hex_round_trips_and_refuses_uppercase_and_short() {
        let d = [0xab; 32];
        assert_eq!(hex(&d), "ab".repeat(32));
        assert_eq!(unhex(&hex(&d)), Some(d));
        assert_eq!(unhex(&"AB".repeat(32)), None);
        assert_eq!(unhex("ab"), None);
        let mut all = [0u8; 32];
        for (i, b) in all.iter_mut().enumerate() {
            *b = (i as u8).wrapping_mul(37);
        }
        assert_eq!(unhex(&hex(&all)), Some(all));
        assert_eq!(hex(&[0x0f; 32]), "0f".repeat(32));
        assert_eq!(
            unhex(&"0123456789abcdef".repeat(4)).unwrap()[..8],
            [0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef]
        );
        assert_eq!(unhex(&format!("{}g", "a".repeat(63))), None);
        assert_eq!(unhex(&format!("{}/", "a".repeat(63))), None);
        assert_eq!(unhex(&format!("{}:", "a".repeat(63))), None);
        assert_eq!(unhex(&format!("{}`", "a".repeat(63))), None);
        assert_eq!(unhex(&"a".repeat(65)), None);
        assert_eq!(unhex(&"a".repeat(63)), None);
    }

    #[test]
    fn build_is_deterministic_across_subject_order() {
        let a = layer(Some("x"), &[(1, "a", "admin"), (2, "b", "user")]);
        let mut b = a.clone();
        b.subjects.reverse();
        let ga =
            crate::format::encode(&build(&a, &roles(), VOCAB, 1, ProvenanceKind::Seed).unwrap());
        let gb =
            crate::format::encode(&build(&b, &roles(), VOCAB, 1, ProvenanceKind::Seed).unwrap());
        assert_eq!(ga, gb);
    }

    #[test]
    fn build_refuses_an_empty_source_or_label_rather_than_emitting_an_empty_key() {
        assert!(matches!(
            build(
                &IdentityLayer::default(),
                &roles(),
                [1; 32],
                1,
                ProvenanceKind::Seed
            ),
            Err(IdentityError::Graph(GraphError::EmptyKey(_)))
        ));
        let no_label = IdentityLayer {
            source: "p".into(),
            label: String::new(),
            bindings_sha256: None,
            subjects: vec![],
        };
        assert!(matches!(
            build(&no_label, &roles(), [1; 32], 1, ProvenanceKind::Seed),
            Err(IdentityError::Graph(GraphError::EmptyLabel))
        ));
    }

    #[test]
    fn identity_errors_name_their_cause() {
        let cases = [
            (
                IdentityError::Graph(GraphError::EmptyLabel),
                "identity layer: record has an empty label",
            ),
            (
                IdentityError::BadAttr {
                    node: 4,
                    attr: "uid",
                },
                "identity layer: node 4 lacks a valid `uid` attribute",
            ),
            (
                IdentityError::UnknownRole("x".into()),
                "identity layer: role `x` is not compiled in",
            ),
        ];
        for (e, want) in cases {
            assert_eq!(e.to_string(), want);
        }
        let _: &dyn std::error::Error = &IdentityError::UnknownRole("x".into());
    }
}
