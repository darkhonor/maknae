use crate::record::{
    EdgeId, EdgeKind, EdgeRecord, GraphSpace, NodeId, NodeKind, NodeRecord, ProvenanceKind,
};
use crate::schema::{CompiledSet, Schema};
use std::fmt;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GraphError {
    UnknownNodeKind(NodeKind),
    UnknownEdgeKind(EdgeKind),
    DuplicateNodeId(NodeId),
    DuplicateEdgeId(EdgeId),
    DuplicateKey {
        kind: NodeKind,
        key: String,
    },
    EmptyKey(NodeId),
    EmptyLabel,
    SpaceMismatch,
    DanglingEdge(EdgeId),
    ForbiddenTriple {
        from: NodeKind,
        edge: EdgeKind,
        to: NodeKind,
    },
    ForbiddenTarget(EdgeId),
    CompiledProvenance(NodeId),
    CompiledEdgeProvenance(EdgeId),
    CompiledMismatch {
        kind: NodeKind,
        key: String,
    },
    CompiledMissing {
        kind: NodeKind,
        key: String,
    },
    ExpansionLimit,
}

impl fmt::Display for GraphError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnknownNodeKind(k) => write!(f, "unknown node kind {}", k.0),
            Self::UnknownEdgeKind(k) => write!(f, "unknown edge kind {}", k.0),
            Self::DuplicateNodeId(id) => write!(f, "duplicate node id {}", id.0),
            Self::DuplicateEdgeId(id) => write!(f, "duplicate edge id {}", id.0),
            Self::DuplicateKey { kind, key } => {
                write!(f, "duplicate key {:?} for node kind {}", shown(key), kind.0)
            }
            Self::EmptyKey(id) => write!(f, "node {} has an empty key", id.0),
            Self::EmptyLabel => f.write_str("record has an empty label"),
            Self::SpaceMismatch => f.write_str("record space differs from the graph space"),
            Self::DanglingEdge(id) => write!(f, "edge {} names a node that does not exist", id.0),
            Self::ForbiddenTriple { from, edge, to } => write!(
                f,
                "edge kind {} is not permitted from node kind {} to node kind {}",
                edge.0, from.0, to.0
            ),
            Self::ForbiddenTarget(id) => write!(
                f,
                "edge {} targets a node no edge of its kind may reach",
                id.0
            ),
            Self::CompiledProvenance(id) => {
                write!(f, "node {} has a provenance its kind does not allow", id.0)
            }
            Self::CompiledEdgeProvenance(id) => {
                write!(f, "edge {} has a provenance edges do not allow", id.0)
            }
            Self::CompiledMismatch { kind, key } => {
                write!(
                    f,
                    "compiled node {:?} of kind {} disagrees with the binary",
                    shown(key),
                    kind.0
                )
            }
            Self::CompiledMissing { kind, key } => {
                write!(
                    f,
                    "compiled node {:?} of kind {} is missing",
                    shown(key),
                    kind.0
                )
            }
            Self::ExpansionLimit => {
                f.write_str("graph string references expand past the decode limit")
            }
        }
    }
}

impl std::error::Error for GraphError {}

fn shown(s: &str) -> &str {
    match s.char_indices().nth(64) {
        Some((i, _)) => &s[..i],
        None => s,
    }
}

#[derive(Debug, Clone)]
pub struct GraphBuilder {
    space: GraphSpace,
    revision: u64,
    nodes: Vec<NodeRecord>,
    edges: Vec<EdgeRecord>,
}

impl GraphBuilder {
    pub fn new(space: GraphSpace, revision: u64) -> Self {
        Self {
            space,
            revision,
            nodes: Vec::new(),
            edges: Vec::new(),
        }
    }

    pub fn node(mut self, n: NodeRecord) -> Self {
        self.nodes.push(n);
        self
    }

    pub fn edge(mut self, e: EdgeRecord) -> Self {
        self.edges.push(e);
        self
    }

    pub fn build(self, schema: &Schema, compiled: &CompiledSet) -> Result<Graph, GraphError> {
        self.build_encoded(schema, compiled).map(|(g, _)| g)
    }

    pub(crate) fn build_encoded(
        self,
        schema: &Schema,
        compiled: &CompiledSet,
    ) -> Result<(Graph, Vec<u8>), GraphError> {
        let GraphBuilder {
            space,
            revision,
            mut nodes,
            mut edges,
        } = self;

        nodes.sort_by_key(|n| n.id);
        if let Some(w) = nodes.windows(2).find(|w| w[0].id == w[1].id) {
            return Err(GraphError::DuplicateNodeId(w[0].id));
        }
        for n in &nodes {
            check_node(n, space, schema, compiled)?;
        }

        let mut keys: Vec<(NodeKind, String, u32)> = nodes
            .iter()
            .enumerate()
            .map(|(i, n)| (n.kind, n.key.clone(), index_u32(i)))
            .collect();
        keys.sort();
        if let Some(w) = keys
            .windows(2)
            .find(|w| w[0].0 == w[1].0 && w[0].1 == w[1].1)
        {
            return Err(GraphError::DuplicateKey {
                kind: w[0].0,
                key: w[0].1.clone(),
            });
        }
        for c in compiled.iter() {
            if !schema.is_compiled(c.kind) {
                return Err(GraphError::CompiledMismatch {
                    kind: c.kind,
                    key: c.key.clone(),
                });
            }
            let found = keys
                .binary_search_by(|(k, key, _)| (*k, key.as_str()).cmp(&(c.kind, c.key.as_str())))
                .is_ok();
            if !found {
                return Err(GraphError::CompiledMissing {
                    kind: c.kind,
                    key: c.key.clone(),
                });
            }
        }

        edges.sort_by_key(|e| e.id);
        if let Some(w) = edges.windows(2).find(|w| w[0].id == w[1].id) {
            return Err(GraphError::DuplicateEdgeId(w[0].id));
        }
        let position = |id: NodeId| nodes.binary_search_by_key(&id, |n| n.id).ok();
        for e in &edges {
            if schema.edge_kind_name(e.kind).is_none() {
                return Err(GraphError::UnknownEdgeKind(e.kind));
            }
            if e.space != space {
                return Err(GraphError::SpaceMismatch);
            }
            if e.label.is_empty() {
                return Err(GraphError::EmptyLabel);
            }
            if e.provenance.kind == ProvenanceKind::Compiled {
                return Err(GraphError::CompiledEdgeProvenance(e.id));
            }
            let (Some(f), Some(t)) = (position(e.from), position(e.to)) else {
                return Err(GraphError::DanglingEdge(e.id));
            };
            let (from, to) = (&nodes[f], &nodes[t]);
            if !schema.allows(from.kind, e.kind, to.kind) {
                return Err(GraphError::ForbiddenTriple {
                    from: from.kind,
                    edge: e.kind,
                    to: to.kind,
                });
            }
            if schema.forbids_target(e.kind, to.kind, &to.key) {
                return Err(GraphError::ForbiddenTarget(e.id));
            }
        }

        edges.sort_by_key(|e| (position(e.from), e.kind, e.to, e.id));
        let out_offsets = offsets(nodes.len(), edges.iter().map(|e| position(e.from)));
        let mut in_edges: Vec<u32> = (0..edges.len()).map(index_u32).collect();
        in_edges.sort_by_key(|&i| {
            let e = &edges[i as usize];
            (position(e.to), e.kind, e.from, e.id)
        });
        let in_offsets = offsets(
            nodes.len(),
            in_edges.iter().map(|&i| position(edges[i as usize].to)),
        );

        let graph = Graph {
            space,
            revision,
            schema_version: schema.version,
            nodes,
            edges,
            out_offsets,
            in_offsets,
            in_edges,
            keys,
        };
        let encoded = crate::format::encode(&graph);
        if !crate::format::within_expansion_limit(graph.reference_bytes(), encoded.len()) {
            return Err(GraphError::ExpansionLimit);
        }
        Ok((graph, encoded))
    }
}

fn check_node(
    n: &NodeRecord,
    space: GraphSpace,
    schema: &Schema,
    compiled: &CompiledSet,
) -> Result<(), GraphError> {
    if schema.node_kind_name(n.kind).is_none() {
        return Err(GraphError::UnknownNodeKind(n.kind));
    }
    if n.space != space {
        return Err(GraphError::SpaceMismatch);
    }
    if n.key.is_empty() {
        return Err(GraphError::EmptyKey(n.id));
    }
    if n.label.is_empty() {
        return Err(GraphError::EmptyLabel);
    }
    let compiled_provenance = n.provenance.kind == ProvenanceKind::Compiled;
    if schema.is_compiled(n.kind) {
        if !compiled_provenance {
            return Err(GraphError::CompiledProvenance(n.id));
        }
        match compiled.get(n.kind, &n.key) {
            Some(c)
                if c.attrs == n.attrs
                    && c.label == n.label
                    && n.revision == 0
                    && n.provenance.transition == 0 => {}
            _ => {
                return Err(GraphError::CompiledMismatch {
                    kind: n.kind,
                    key: n.key.clone(),
                })
            }
        }
    } else if compiled_provenance {
        return Err(GraphError::CompiledProvenance(n.id));
    }
    Ok(())
}

fn offsets(nodes: usize, owners: impl Iterator<Item = Option<usize>>) -> Vec<u32> {
    let mut out = vec![0u32; nodes + 1];
    for owner in owners.flatten() {
        out[owner + 1] += 1;
    }
    for i in 0..nodes {
        out[i + 1] += out[i];
    }
    out
}

pub(crate) fn index_u32(i: usize) -> u32 {
    u32::try_from(i).expect("graph record counts fit in u32")
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Graph {
    space: GraphSpace,
    revision: u64,
    schema_version: u16,
    nodes: Vec<NodeRecord>,
    edges: Vec<EdgeRecord>,
    out_offsets: Vec<u32>,
    in_offsets: Vec<u32>,
    in_edges: Vec<u32>,
    keys: Vec<(NodeKind, String, u32)>,
}

impl Graph {
    pub fn space(&self) -> GraphSpace {
        self.space
    }

    pub fn revision(&self) -> u64 {
        self.revision
    }

    pub fn schema_version(&self) -> u16 {
        self.schema_version
    }

    pub fn nodes(&self) -> &[NodeRecord] {
        &self.nodes
    }

    pub fn edges(&self) -> &[EdgeRecord] {
        &self.edges
    }

    pub fn node(&self, id: NodeId) -> Option<&NodeRecord> {
        self.position(id).map(|i| &self.nodes[i])
    }

    pub fn lookup(&self, kind: NodeKind, key: &str) -> Option<&NodeRecord> {
        self.keys
            .binary_search_by(|(k, s, _)| (*k, s.as_str()).cmp(&(kind, key)))
            .ok()
            .map(|i| &self.nodes[self.keys[i].2 as usize])
    }

    pub fn out_edges(&self, id: NodeId, kind: EdgeKind) -> impl Iterator<Item = &EdgeRecord> {
        let row: &[EdgeRecord] = match self.position(id) {
            Some(i) => &self.edges[self.out_offsets[i] as usize..self.out_offsets[i + 1] as usize],
            None => &[],
        };
        let start = row.partition_point(|e| e.kind < kind);
        let end = row.partition_point(|e| e.kind <= kind);
        row[start..end].iter()
    }

    pub fn in_edges(&self, id: NodeId, kind: EdgeKind) -> impl Iterator<Item = &EdgeRecord> {
        let row: &[u32] = match self.position(id) {
            Some(i) => &self.in_edges[self.in_offsets[i] as usize..self.in_offsets[i + 1] as usize],
            None => &[],
        };
        let start = row.partition_point(|&j| self.edges[j as usize].kind < kind);
        let end = row.partition_point(|&j| self.edges[j as usize].kind <= kind);
        row[start..end]
            .iter()
            .map(move |&j| &self.edges[j as usize])
    }

    pub(crate) fn out_offsets(&self) -> &[u32] {
        &self.out_offsets
    }

    pub(crate) fn in_offsets(&self) -> &[u32] {
        &self.in_offsets
    }

    pub(crate) fn in_edge_indices(&self) -> &[u32] {
        &self.in_edges
    }

    pub(crate) fn key_index(&self) -> &[(NodeKind, String, u32)] {
        &self.keys
    }

    fn reference_bytes(&self) -> usize {
        let attrs = |a: &crate::record::Attrs| {
            a.iter()
                .map(|(k, v)| {
                    k.len()
                        + if let crate::record::AttrValue::Str(s) = v {
                            s.len()
                        } else {
                            0
                        }
                })
                .sum::<usize>()
        };
        self.nodes
            .iter()
            .map(|n| n.key.len() + n.label.len() + attrs(&n.attrs))
            .sum::<usize>()
            + self
                .edges
                .iter()
                .map(|e| e.label.len() + attrs(&e.attrs))
                .sum::<usize>()
    }

    fn position(&self, id: NodeId) -> Option<usize> {
        self.nodes.binary_search_by_key(&id, |n| n.id).ok()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::record::{AttrValue, Attrs, Provenance};

    static ONE: Schema = Schema {
        version: 1,
        node_kinds: &[(NodeKind(1), "N")],
        edge_kinds: &[(EdgeKind(1), "e")],
        triples: &[(NodeKind(1), EdgeKind(1), NodeKind(1))],
        compiled_kinds: &[],
        forbidden_targets: &[],
    };

    #[test]
    fn reference_bytes_counts_every_cloned_string_once() {
        let p = Provenance {
            kind: ProvenanceKind::Seed,
            transition: 0,
        };
        let mut a1 = Attrs::new();
        a1.insert("k".repeat(7), AttrValue::Str("v".repeat(11)));
        let mut a2 = Attrs::new();
        a2.insert("q".into(), AttrValue::U64(9));
        let mut ea = Attrs::new();
        ea.insert("e".repeat(17), AttrValue::Str("w".repeat(19)));
        let n = |id, key: &str, label: &str, attrs: Attrs| NodeRecord {
            id: NodeId(id),
            space: GraphSpace::Kernel,
            kind: NodeKind(1),
            key: key.into(),
            label: label.into(),
            provenance: p,
            revision: 1,
            attrs,
        };
        let g = GraphBuilder::new(GraphSpace::Kernel, 1)
            .node(n(1, "abc", "abcde", a1))
            .node(n(2, "ab", "lmnopqrstuvwxyzab", a2))
            .edge(EdgeRecord {
                id: EdgeId(1),
                space: GraphSpace::Kernel,
                from: NodeId(1),
                to: NodeId(2),
                kind: EdgeKind(1),
                label: "l".repeat(13),
                provenance: p,
                revision: 1,
                attrs: ea,
            })
            .build(&ONE, &CompiledSet::default())
            .unwrap();
        assert_eq!(
            g.reference_bytes(),
            (3 + 5 + 7 + 11) + (2 + 17 + 1) + (13 + 17 + 19)
        );
    }
}
