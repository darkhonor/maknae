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
    Ambiguous { node: u64, what: &'static str },
    LabelMismatch(String),
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
            Self::Ambiguous { node, what } => {
                write!(f, "identity layer: node {node} is ambiguous: {what}")
            }
            Self::LabelMismatch(key) => write!(
                f,
                "identity layer: compiled node `{key}` is labelled differently from the layer"
            ),
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
        *o = (nibble(*hi) << 4) + nibble(*lo);
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
    let g = b.build(&SCHEMA, compiled).map_err(IdentityError::Graph)?;
    if let Some(c) = compiled.iter().find(|c| c.label != layer.label) {
        return Err(IdentityError::LabelMismatch(c.key.clone()));
    }
    Ok(g)
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
    let mut has_source = false;
    for n in g.nodes().iter().filter(|n| n.kind == CONFIG_SOURCE) {
        if n.key == VOCABULARY_SOURCE_KEY {
            vocabulary_sha256 = Some(digest_attr(n)?);
        } else if has_source {
            return Err(IdentityError::Ambiguous {
                node: n.id.0,
                what: "more than one policy source",
            });
        } else {
            has_source = true;
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
        .filter(|&u| n.key == subject_key(u))
        .ok_or(IdentityError::BadAttr {
            node: n.id.0,
            attr: ATTR_UID,
        })?;
        if !has_source {
            return Err(IdentityError::Ambiguous {
                node: n.id.0,
                what: "subject without a policy source",
            });
        }
        if g.out_edges(n.id, BINDS).nth(1).is_some() {
            return Err(IdentityError::Ambiguous {
                node: n.id.0,
                what: "more than one binds edge",
            });
        }
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

pub const BINDINGS_MISSING: &str = "bindings.yaml is missing but the store holds explicit bindings; to return to principal-as-admin write bindings.yaml without a `bindings:` key";
const BINDINGS_YAML: &str = "bindings.yaml";
pub const BINDINGS_NOT_MOVED: &str = "the store holds explicit bindings from authz.yaml; paste the bindings: block into /etc/maknae/bindings.yaml";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Carried {
    pub uid: u32,
    pub name: String,
    pub overrides: Vec<SubjectEntry>,
}

/// `file` plus every persisted contained subject whose name is in `unresolved_adversaries`,
/// contained under its persisted uid unless the file already lists that uid under
/// adversary; any other file entry for that uid is replaced and returned in `overrides`.
/// Idempotent.
pub fn carry_forward(
    file: &IdentityLayer,
    unresolved_adversaries: &[String],
    persisted: &IdentityLayer,
) -> (IdentityLayer, Vec<Carried>) {
    let mut out = file.clone();
    let mut carried = Vec::new();
    for s in persisted
        .subjects
        .iter()
        .filter(|s| s.role == ADVERSARY && unresolved_adversaries.contains(&s.name))
    {
        if out
            .subjects
            .iter()
            .any(|e| e.uid == s.uid && e.role == ADVERSARY)
        {
            continue;
        }
        let (overrides, keep): (Vec<SubjectEntry>, Vec<SubjectEntry>) =
            out.subjects.drain(..).partition(|e| e.uid == s.uid);
        out.subjects = keep;
        out.subjects.push(s.clone());
        carried.push(Carried {
            uid: s.uid,
            name: s.name.clone(),
            overrides,
        });
    }
    out.subjects.sort_by_key(|e| e.uid);
    (out, carried)
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReleaseCause {
    NotListed,
    NameNowResolvesTo(u32),
    BoundAs(String),
    BindingsEmpty,
    BindingsAbsent,
}

impl fmt::Display for ReleaseCause {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotListed => f.write_str("its name is no longer listed under adversary"),
            Self::NameNowResolvesTo(uid) => write!(f, "its name now resolves to uid {uid}"),
            Self::BoundAs(role) => write!(f, "it is now listed under {role}"),
            Self::BindingsEmpty => f.write_str("bindings.yaml now binds nobody"),
            Self::BindingsAbsent => f.write_str(
                "bindings.yaml has no bindings: key, so the enrolled principal is admin and nobody else holds a role",
            ),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Released {
    pub uid: u32,
    pub name: String,
    pub cause: ReleaseCause,
}

/// Every subject contained in `persisted` and not contained in `next`, in uid order.
/// `file_lists_nobody`: the file's `bindings:` key lists no entry at all.
pub fn released(
    persisted: &IdentityLayer,
    next: &IdentityLayer,
    file_lists_nobody: bool,
) -> Vec<Released> {
    let contained = |uid: u32| {
        next.subjects
            .iter()
            .any(|e| e.uid == uid && e.role == ADVERSARY)
    };
    let mut out: Vec<Released> = persisted
        .subjects
        .iter()
        .filter(|s| s.role == ADVERSARY && !contained(s.uid))
        .map(|s| {
            let cause = if next.bindings_sha256.is_none() {
                ReleaseCause::BindingsAbsent
            } else if file_lists_nobody {
                ReleaseCause::BindingsEmpty
            } else if let Some(moved) = next
                .subjects
                .iter()
                .find(|e| e.name == s.name && e.role == ADVERSARY)
            {
                ReleaseCause::NameNowResolvesTo(moved.uid)
            } else if let Some(bound) = next.subjects.iter().find(|e| e.uid == s.uid) {
                ReleaseCause::BoundAs(bound.role.clone())
            } else {
                ReleaseCause::NotListed
            };
            Released {
                uid: s.uid,
                name: s.name.clone(),
                cause,
            }
        })
        .collect();
    out.sort_by_key(|r| r.uid);
    out
}

/// Whether moving from `persisted` to `next` ends explicit bindings, which makes the
/// enrolled principal admin.
pub fn promotes_principal(persisted: &IdentityLayer, next: &IdentityLayer) -> bool {
    persisted.bindings_sha256.is_some() && next.bindings_sha256.is_none()
}

/// The refusal, if `file` would drop explicit bindings that root has not written into
/// `bindings.yaml`: explicit bindings persisted from any other file, or a vanished file.
pub fn drops_explicit_bindings(
    persisted: &IdentityLayer,
    file: &IdentityLayer,
    file_missing: bool,
) -> Option<&'static str> {
    persisted.bindings_sha256?;
    let from_bindings_yaml = std::path::Path::new(&persisted.source).file_name()
        == Some(std::ffi::OsStr::new(BINDINGS_YAML));
    if !from_bindings_yaml && file.bindings_sha256.is_none() {
        return Some(BINDINGS_NOT_MOVED);
    }
    if file_missing {
        return Some(BINDINGS_MISSING);
    }
    None
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
            assert!(g.nodes().iter().all(|n| n.label == l.label));
            assert!(g.edges().iter().all(|e| e.label == l.label));
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
    fn extract_on_an_empty_graph_is_the_empty_layer_with_no_digest() {
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
            (subject, ATTR_UID, Some(AttrValue::U64(1001))),
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
        let max = build(
            &layer(Some("x"), &[(u32::MAX, "max", "admin")]),
            &roles(),
            VOCAB,
            1,
            ProvenanceKind::Seed,
        )
        .unwrap();
        assert_eq!(extract(&max).unwrap().layer.subjects[0].uid, u32::MAX);
    }

    fn regraph(
        g: &Graph,
        keep_node: impl Fn(&NodeRecord) -> bool,
        extra_nodes: Vec<NodeRecord>,
        extra_edges: Vec<EdgeRecord>,
    ) -> Graph {
        let nodes: Vec<NodeRecord> = g
            .nodes()
            .iter()
            .filter(|n| keep_node(n))
            .cloned()
            .chain(extra_nodes)
            .collect();
        let kept = |id: NodeId| nodes.iter().any(|n| n.id == id);
        let edges: Vec<EdgeRecord> = g
            .edges()
            .iter()
            .filter(|e| kept(e.from) && kept(e.to))
            .cloned()
            .chain(extra_edges)
            .collect();
        let b = GraphBuilder::new(GraphSpace::Kernel, g.revision());
        let b = nodes.into_iter().fold(b, |b, n| b.node(n));
        edges
            .into_iter()
            .fold(b, |b, e| b.edge(e))
            .build(&crate::kernel::SCHEMA, &roles())
            .unwrap()
    }

    fn one_admin() -> Graph {
        build(
            &layer(Some("x"), &[(1000, "alex", "admin")]),
            &roles(),
            VOCAB,
            1,
            ProvenanceKind::Seed,
        )
        .unwrap()
    }

    #[test]
    fn extract_refuses_a_second_policy_source() {
        let g = one_admin();
        let mut second = g
            .lookup(crate::kernel::CONFIG_SOURCE, "/etc/maknae/authz.yaml")
            .unwrap()
            .clone();
        second.id = NodeId(100);
        second.key = "/etc/maknae/other.yaml".into();
        let two = regraph(&g, |_| true, vec![second], vec![]);
        assert_eq!(
            extract(&two),
            Err(IdentityError::Ambiguous {
                node: 100,
                what: "more than one policy source"
            })
        );
    }

    #[test]
    fn extract_refuses_a_subject_with_two_binds_edges() {
        let g = one_admin();
        let s = g.lookup(crate::kernel::SUBJECT, "uid:1000").unwrap().id;
        let mut extra = g.edges()[0].clone();
        extra.id = EdgeId(100);
        extra.from = s;
        extra.to = g.lookup(ROLE, "user").unwrap().id;
        extra.kind = BINDS;
        let two = regraph(&g, |_| true, vec![], vec![extra]);
        assert_eq!(two.out_edges(s, BINDS).count(), 2);
        assert_eq!(
            extract(&two),
            Err(IdentityError::Ambiguous {
                node: s.0,
                what: "more than one binds edge"
            })
        );
    }

    #[test]
    fn extract_refuses_subjects_without_a_policy_source() {
        let g = one_admin();
        let s = g.lookup(crate::kernel::SUBJECT, "uid:1000").unwrap().id;
        let orphan = regraph(
            &g,
            |n| !(n.kind == crate::kernel::CONFIG_SOURCE && n.key != VOCABULARY_SOURCE_KEY),
            vec![],
            vec![],
        );
        assert_eq!(
            extract(&orphan),
            Err(IdentityError::Ambiguous {
                node: s.0,
                what: "subject without a policy source"
            })
        );
    }

    #[test]
    fn build_refuses_a_compiled_set_labelled_for_another_level() {
        let l = layer(Some("x"), &[(1000, "alex", "admin")]);
        assert_eq!(
            build(
                &l,
                &crate::kernel::persisted_compiled_set("SECRET"),
                VOCAB,
                1,
                ProvenanceKind::Seed
            ),
            Err(IdentityError::LabelMismatch("admin".into()))
        );
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

    fn entry(uid: u32, name: &str, role: &str) -> SubjectEntry {
        SubjectEntry {
            uid,
            name: name.into(),
            role: role.into(),
        }
    }

    fn at(source: &str, bindings: Option<&str>, subjects: &[(u32, &str, &str)]) -> IdentityLayer {
        IdentityLayer {
            source: source.into(),
            ..layer(bindings, subjects)
        }
    }

    #[test]
    fn a_contained_name_that_stops_resolving_stays_contained() {
        let persisted = layer(
            Some("x"),
            &[(1000, "alex", "admin"), (666, "mallory", "adversary")],
        );
        let file = layer(Some("y"), &[(1000, "alex", "admin")]);
        let (carried, which) = carry_forward(&file, &["mallory".into()], &persisted);
        assert_eq!(
            which,
            [Carried {
                uid: 666,
                name: "mallory".into(),
                overrides: vec![]
            }]
        );
        assert_eq!(
            carried.subjects,
            [
                entry(666, "mallory", "adversary"),
                entry(1000, "alex", "admin")
            ]
        );
        assert_eq!(
            carried.bindings_sha256, file.bindings_sha256,
            "only subjects are carried"
        );
        assert_eq!(
            carry_forward(&carried, &["mallory".into()], &persisted).0,
            carried,
            "idempotent"
        );
        assert!(released(&persisted, &carried, false).is_empty());
    }

    #[test]
    fn removing_the_name_releases_it_and_says_so() {
        let persisted = layer(
            Some("x"),
            &[(666, "mallory", "adversary"), (1000, "alex", "admin")],
        );
        let file = layer(Some("y"), &[(1000, "alex", "admin")]);
        assert_eq!(
            carry_forward(&file, &[], &persisted),
            (file.clone(), vec![])
        );
        assert_eq!(
            released(&persisted, &file, false),
            [Released {
                uid: 666,
                name: "mallory".into(),
                cause: ReleaseCause::NotListed
            }]
        );
    }

    #[test]
    fn a_typo_in_the_name_releases_and_is_recorded() {
        let persisted = layer(Some("x"), &[(666, "mallory", "adversary")]);
        let file = layer(Some("y"), &[]);
        let (next, carried) = carry_forward(&file, &["Mallory".into()], &persisted);
        assert!(carried.is_empty(), "a different name carries nothing");
        assert_eq!(
            released(&persisted, &next, false),
            [Released {
                uid: 666,
                name: "mallory".into(),
                cause: ReleaseCause::NotListed
            }],
            "the file lists a name, so it does not bind nobody"
        );
        let other = layer(Some("y"), &[(1, "a", "user")]);
        let (next, _) = carry_forward(&other, &["Mallory".into()], &persisted);
        assert_eq!(
            released(&persisted, &next, false),
            [Released {
                uid: 666,
                name: "mallory".into(),
                cause: ReleaseCause::NotListed
            }]
        );
    }

    #[test]
    fn every_release_cause_is_named() {
        let persisted = layer(Some("x"), &[(666, "mallory", "adversary")]);
        let cases = [
            (
                layer(
                    Some("y"),
                    &[(777, "mallory", "adversary"), (1, "a", "user")],
                ),
                ReleaseCause::NameNowResolvesTo(777),
            ),
            (
                layer(Some("y"), &[(666, "mallory", "user")]),
                ReleaseCause::BoundAs("user".into()),
            ),
            (layer(Some("y"), &[]), ReleaseCause::NotListed),
            (layer(None, &[]), ReleaseCause::BindingsAbsent),
            (
                layer(None, &[(1, "a", "user")]),
                ReleaseCause::BindingsAbsent,
            ),
            (
                layer(Some("y"), &[(1, "a", "user")]),
                ReleaseCause::NotListed,
            ),
            (
                layer(Some("y"), &[(1, "mallory", "user")]),
                ReleaseCause::NotListed,
            ),
        ];
        assert_eq!(
            released(&persisted, &layer(Some("y"), &[]), true),
            [Released {
                uid: 666,
                name: "mallory".into(),
                cause: ReleaseCause::BindingsEmpty
            }]
        );
        assert_eq!(
            released(&persisted, &layer(None, &[]), true)[0].cause,
            ReleaseCause::BindingsAbsent
        );
        for (next, cause) in cases {
            assert_eq!(
                released(&persisted, &next, false),
                [Released {
                    uid: 666,
                    name: "mallory".into(),
                    cause: cause.clone()
                }],
                "{cause:?}"
            );
        }
        let texts: Vec<String> = [
            ReleaseCause::NotListed,
            ReleaseCause::NameNowResolvesTo(777),
            ReleaseCause::BoundAs("user".into()),
            ReleaseCause::BindingsEmpty,
            ReleaseCause::BindingsAbsent,
        ]
        .iter()
        .map(ToString::to_string)
        .collect();
        assert_eq!(
            texts,
            [
                "its name is no longer listed under adversary",
                "its name now resolves to uid 777",
                "it is now listed under user",
                "bindings.yaml now binds nobody",
                "bindings.yaml has no bindings: key, so the enrolled principal is admin and nobody else holds a role",
            ]
        );
    }

    #[test]
    fn only_contained_subjects_are_released_one_record_each_in_uid_order() {
        let persisted = layer(
            Some("x"),
            &[
                (700, "trudy", "adversary"),
                (1000, "alex", "admin"),
                (666, "mallory", "adversary"),
                (1001, "ursula", "user"),
            ],
        );
        let next = layer(Some("y"), &[(1000, "alex", "user")]);
        let r = released(&persisted, &next, false);
        assert_eq!(
            r.iter()
                .map(|r| (r.uid, r.name.as_str()))
                .collect::<Vec<_>>(),
            [(666, "mallory"), (700, "trudy")]
        );
        assert!(
            released(&persisted, &persisted, false).is_empty(),
            "unchanged"
        );
        let still = layer(
            Some("y"),
            &[(700, "trudy", "adversary"), (666, "renamed", "adversary")],
        );
        assert!(
            released(&persisted, &still, false).is_empty(),
            "a uid still contained is not released whatever its name"
        );
    }

    #[test]
    fn carry_forward_over_a_reused_uid_stays_contained_and_names_what_it_overrides() {
        let persisted = layer(Some("x"), &[(666, "mallory", "adversary")]);
        let file = layer(Some("y"), &[(666, "bob", "user"), (1000, "alex", "admin")]);
        let (next, carried) = carry_forward(&file, &["mallory".into()], &persisted);
        assert_eq!(
            next.subjects,
            [
                entry(666, "mallory", "adversary"),
                entry(1000, "alex", "admin")
            ],
            "fail closed"
        );
        assert_eq!(
            carried,
            [Carried {
                uid: 666,
                name: "mallory".into(),
                overrides: vec![entry(666, "bob", "user")]
            }]
        );
        assert_eq!(
            carry_forward(&next, &["mallory".into()], &persisted).0,
            next,
            "idempotent over an override"
        );
        let bound = layer(Some("x"), &[(666, "mallory", "user")]);
        assert!(
            carry_forward(&file, &["mallory".into()], &bound)
                .1
                .is_empty(),
            "bound, never contained"
        );
        let unlisted = layer(Some("x"), &[(666, "mallory", "adversary")]);
        assert_eq!(
            carry_forward(&file, &["eve".into()], &unlisted),
            (file.clone(), vec![]),
            "only the names that no longer resolve"
        );
    }

    #[test]
    fn the_guard_refuses_the_upgrade_without_the_block_and_a_vanished_file() {
        let a = "/etc/maknae/authz.yaml";
        let b = "/etc/maknae/bindings.yaml";
        let old_explicit = at(a, Some("x"), &[(666, "mallory", "adversary")]);
        let old_empty = at(a, Some("e"), &[]);
        let old_absent = at(a, None, &[]);
        let new_absent = at(b, None, &[]);
        let new_explicit = at(b, Some("x"), &[(666, "mallory", "adversary")]);
        let guard = |p: &IdentityLayer, f: &IdentityLayer, missing: bool| {
            drops_explicit_bindings(p, f, missing)
        };
        assert_eq!(
            guard(&old_explicit, &new_absent, false),
            Some(BINDINGS_NOT_MOVED)
        );
        assert_eq!(
            guard(&old_explicit, &new_absent, true),
            Some(BINDINGS_NOT_MOVED)
        );
        assert_eq!(
            guard(&old_empty, &new_absent, false),
            Some(BINDINGS_NOT_MOVED),
            "an explicit `bindings: {{}}` is explicit"
        );
        assert_eq!(
            guard(&old_absent, &new_absent, false),
            None,
            "the shipped default upgrades in one transition"
        );
        assert_eq!(
            guard(&old_absent, &new_absent, true),
            None,
            "nothing explicit to drop"
        );
        assert_eq!(
            guard(&old_explicit, &new_explicit, false),
            None,
            "the block was pasted"
        );
        let steady = at(b, Some("x"), &[]);
        assert_eq!(guard(&steady, &new_absent, true), Some(BINDINGS_MISSING));
        assert_eq!(
            guard(&steady, &new_absent, false),
            None,
            "root's keyless edit is allowed, and recorded as releases"
        );
        assert_eq!(guard(&steady, &steady, false), None, "an unchanged reboot");
        assert_eq!(guard(&new_absent, &new_absent, true), None);
        assert_eq!(
            guard(&IdentityLayer::default(), &new_absent, true),
            None,
            "a store from before the identity layer"
        );
        for other in [
            "/private/etc/maknae/authz.yaml",
            "/etc//maknae/authz.yaml",
            "/opt/x/authz.yaml",
            "/etc/maknae/policy.yaml",
            "/etc/maknae/bindings.yaml.bak",
            "/etc/maknae/",
        ] {
            assert_eq!(
                guard(&at(other, Some("x"), &[]), &new_absent, false),
                Some(BINDINGS_NOT_MOVED),
                "{other}"
            );
            assert_eq!(
                guard(&at(other, Some("x"), &[]), &new_explicit, false),
                None,
                "{other}, pasted"
            );
        }
        for respelled in [
            "/private/etc/maknae/bindings.yaml",
            "/etc/maknae/./bindings.yaml",
        ] {
            let p = at(respelled, Some("x"), &[]);
            assert_eq!(guard(&p, &new_absent, false), None, "{respelled}");
            assert_eq!(
                guard(&p, &new_absent, true),
                Some(BINDINGS_MISSING),
                "{respelled}"
            );
        }
        assert!(
            BINDINGS_NOT_MOVED.contains("/etc/maknae/bindings.yaml")
                && BINDINGS_MISSING.contains("without a `bindings:` key")
        );
    }

    #[test]
    fn an_adversary_entry_on_the_carried_uid_is_kept_and_overrides_nothing() {
        let persisted = layer(Some("x"), &[(666, "mallory", "adversary")]);
        let file = layer(
            Some("y"),
            &[(666, "uid:666", "adversary"), (1000, "alex", "admin")],
        );
        let (next, carried) = carry_forward(&file, &["mallory".into()], &persisted);
        assert_eq!(next, file, "the file already contains the uid");
        assert!(carried.is_empty());
        assert!(released(&persisted, &next, false).is_empty());
    }

    #[test]
    fn only_explicit_to_keyless_promotes_the_principal() {
        let explicit = layer(Some("x"), &[(666, "mallory", "adversary")]);
        let empty = layer(Some("y"), &[]);
        let keyless = layer(None, &[]);
        assert!(promotes_principal(&explicit, &keyless));
        assert!(promotes_principal(&empty, &keyless));
        assert!(!promotes_principal(&explicit, &empty));
        assert!(!promotes_principal(&keyless, &keyless));
        assert!(!promotes_principal(&keyless, &explicit));
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
            (
                IdentityError::Ambiguous {
                    node: 3,
                    what: "more than one binds edge",
                },
                "identity layer: node 3 is ambiguous: more than one binds edge",
            ),
            (
                IdentityError::LabelMismatch("admin".into()),
                "identity layer: compiled node `admin` is labelled differently from the layer",
            ),
        ];
        for (e, want) in cases {
            assert_eq!(e.to_string(), want);
        }
        let _: &dyn std::error::Error = &IdentityError::UnknownRole("x".into());
    }
}
