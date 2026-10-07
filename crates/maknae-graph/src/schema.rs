use crate::graph::{index_u32, GraphError};
use crate::record::{AttrValue, Attrs, EdgeKind, NodeKind};

#[derive(Debug)]
pub struct Schema {
    pub version: u16,
    pub node_kinds: &'static [(NodeKind, &'static str)],
    pub edge_kinds: &'static [(EdgeKind, &'static str)],
    pub triples: &'static [(NodeKind, EdgeKind, NodeKind)],
    pub compiled_kinds: &'static [NodeKind],
    pub forbidden_targets: &'static [(EdgeKind, NodeKind, &'static str)],
}

impl Schema {
    pub fn node_kind_name(&self, kind: NodeKind) -> Option<&'static str> {
        self.node_kinds
            .iter()
            .find(|(k, _)| *k == kind)
            .map(|(_, n)| *n)
    }

    pub fn edge_kind_name(&self, kind: EdgeKind) -> Option<&'static str> {
        self.edge_kinds
            .iter()
            .find(|(k, _)| *k == kind)
            .map(|(_, n)| *n)
    }

    pub fn allows(&self, from: NodeKind, edge: EdgeKind, to: NodeKind) -> bool {
        self.triples.contains(&(from, edge, to))
    }

    pub fn is_compiled(&self, kind: NodeKind) -> bool {
        self.compiled_kinds.contains(&kind)
    }

    pub fn forbids_target(&self, edge: EdgeKind, to: NodeKind, key: &str) -> bool {
        self.forbidden_targets
            .iter()
            .any(|&(e, n, k)| e == edge && n == to && k == key)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CompiledNode {
    pub kind: NodeKind,
    pub key: String,
    pub label: String,
    pub attrs: Attrs,
}

#[derive(Debug, Clone, Default)]
pub struct CompiledSet {
    nodes: Vec<CompiledNode>,
}

impl CompiledSet {
    pub fn new(nodes: Vec<CompiledNode>) -> Self {
        Self { nodes }
    }

    pub fn get(&self, kind: NodeKind, key: &str) -> Option<&CompiledNode> {
        self.nodes.iter().find(|c| c.kind == kind && c.key == key)
    }

    pub fn iter(&self) -> impl Iterator<Item = &CompiledNode> {
        self.nodes.iter()
    }

    pub fn is_empty(&self) -> bool {
        self.nodes.is_empty()
    }

    pub fn canonical_bytes(&self) -> Result<Vec<u8>, GraphError> {
        fn put(out: &mut Vec<u8>, s: &str) {
            out.extend_from_slice(&index_u32(s.len()).to_le_bytes());
            out.extend_from_slice(s.as_bytes());
        }
        let mut sorted: Vec<&CompiledNode> = self.nodes.iter().collect();
        sorted.sort_by(|a, b| (a.kind, a.key.as_str()).cmp(&(b.kind, b.key.as_str())));
        if let Some(w) = sorted
            .windows(2)
            .find(|w| (w[0].kind, &w[0].key) == (w[1].kind, &w[1].key))
        {
            return Err(GraphError::DuplicateKey {
                kind: w[0].kind,
                key: w[0].key.clone(),
            });
        }
        let mut out = Vec::new();
        out.extend_from_slice(&index_u32(sorted.len()).to_le_bytes());
        for c in sorted {
            out.extend_from_slice(&c.kind.0.to_le_bytes());
            put(&mut out, &c.key);
            put(&mut out, &c.label);
            out.extend_from_slice(&index_u32(c.attrs.len()).to_le_bytes());
            for (k, v) in &c.attrs {
                put(&mut out, k);
                match v {
                    AttrValue::Str(s) => {
                        out.push(1);
                        put(&mut out, s);
                    }
                    AttrValue::U64(n) => {
                        out.push(2);
                        out.extend_from_slice(&n.to_le_bytes());
                    }
                }
            }
        }
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    static TEST: Schema = Schema {
        version: 7,
        node_kinds: &[(NodeKind(1), "A"), (NodeKind(2), "B")],
        edge_kinds: &[(EdgeKind(1), "to_b"), (EdgeKind(2), "to_a")],
        triples: &[(NodeKind(1), EdgeKind(1), NodeKind(2))],
        compiled_kinds: &[NodeKind(2)],
        forbidden_targets: &[(EdgeKind(1), NodeKind(2), "x")],
    };

    #[test]
    fn kind_names_resolve_and_unknowns_do_not() {
        assert_eq!(TEST.node_kind_name(NodeKind(1)), Some("A"));
        assert_eq!(TEST.node_kind_name(NodeKind(2)), Some("B"));
        assert_eq!(TEST.node_kind_name(NodeKind(3)), None);
        assert_eq!(TEST.edge_kind_name(EdgeKind(1)), Some("to_b"));
        assert_eq!(TEST.edge_kind_name(EdgeKind(2)), Some("to_a"));
        assert_eq!(TEST.edge_kind_name(EdgeKind(3)), None);
    }

    #[test]
    fn allows_only_listed_triples_in_listed_direction() {
        assert!(TEST.allows(NodeKind(1), EdgeKind(1), NodeKind(2)));
        assert!(!TEST.allows(NodeKind(2), EdgeKind(1), NodeKind(1)));
        assert!(!TEST.allows(NodeKind(1), EdgeKind(2), NodeKind(2)));
    }

    #[test]
    fn compiled_kinds_and_forbidden_targets() {
        assert!(TEST.is_compiled(NodeKind(2)));
        assert!(!TEST.is_compiled(NodeKind(1)));
        assert!(TEST.forbids_target(EdgeKind(1), NodeKind(2), "x"));
        assert!(!TEST.forbids_target(EdgeKind(1), NodeKind(2), "y"));
        assert!(!TEST.forbids_target(EdgeKind(2), NodeKind(2), "x"));
        assert!(!TEST.forbids_target(EdgeKind(1), NodeKind(1), "x"));
    }

    #[test]
    fn canonical_bytes_are_order_independent_and_content_sensitive() {
        let a = CompiledNode {
            kind: NodeKind(2),
            key: "k".into(),
            label: "L".into(),
            attrs: Attrs::new(),
        };
        let mut b = a.clone();
        b.key = "j".into();
        let ab = CompiledSet::new(vec![a.clone(), b.clone()])
            .canonical_bytes()
            .unwrap();
        let ba = CompiledSet::new(vec![b.clone(), a.clone()])
            .canonical_bytes()
            .unwrap();
        assert_eq!(ab, ba);
        let mut c = a.clone();
        c.label = "M".into();
        assert_ne!(
            CompiledSet::new(vec![c, b.clone()])
                .canonical_bytes()
                .unwrap(),
            ab
        );
        let mut d = a.clone();
        d.attrs.insert("x".into(), AttrValue::U64(1));
        let du = CompiledSet::new(vec![d.clone(), b.clone()])
            .canonical_bytes()
            .unwrap();
        assert_ne!(du, ab);
        d.attrs.insert("x".into(), AttrValue::Str("1".into()));
        assert_ne!(
            CompiledSet::new(vec![d, b.clone()])
                .canonical_bytes()
                .unwrap(),
            du
        );
        let mut k = a.clone();
        k.kind = NodeKind(3);
        assert_ne!(CompiledSet::new(vec![k, b]).canonical_bytes().unwrap(), ab);
        assert!(CompiledSet::default().is_empty());
        assert!(!CompiledSet::new(vec![a]).is_empty());
        assert_eq!(
            CompiledSet::default().canonical_bytes().unwrap(),
            0u32.to_le_bytes()
        );
    }

    #[test]
    fn canonical_bytes_refuse_a_duplicate_kind_and_key() {
        let a = CompiledNode {
            kind: NodeKind(2),
            key: "k".into(),
            label: "L".into(),
            attrs: Attrs::new(),
        };
        let mut b = a.clone();
        b.label = "M".into();
        let mut other_kind = a.clone();
        other_kind.kind = NodeKind(3);
        assert!(CompiledSet::new(vec![a.clone(), other_kind])
            .canonical_bytes()
            .is_ok());
        for set in [vec![a.clone(), b.clone()], vec![b, a]] {
            assert_eq!(
                CompiledSet::new(set).canonical_bytes(),
                Err(GraphError::DuplicateKey {
                    kind: NodeKind(2),
                    key: "k".into()
                })
            );
        }
    }

    #[test]
    fn canonical_bytes_are_pinned() {
        let mut attrs = Attrs::new();
        attrs.insert("n".into(), AttrValue::U64(5));
        attrs.insert("s".into(), AttrValue::Str("v".into()));
        let set = CompiledSet::new(vec![CompiledNode {
            kind: NodeKind(4),
            key: "k".into(),
            label: "L".into(),
            attrs,
        }]);
        let mut want = Vec::new();
        want.extend_from_slice(&1u32.to_le_bytes());
        want.extend_from_slice(&4u16.to_le_bytes());
        want.extend_from_slice(&1u32.to_le_bytes());
        want.push(b'k');
        want.extend_from_slice(&1u32.to_le_bytes());
        want.push(b'L');
        want.extend_from_slice(&2u32.to_le_bytes());
        want.extend_from_slice(&1u32.to_le_bytes());
        want.push(b'n');
        want.push(2);
        want.extend_from_slice(&5u64.to_le_bytes());
        want.extend_from_slice(&1u32.to_le_bytes());
        want.push(b's');
        want.push(1);
        want.extend_from_slice(&1u32.to_le_bytes());
        want.push(b'v');
        assert_eq!(set.canonical_bytes().unwrap(), want);
    }

    #[test]
    fn compiled_set_finds_by_kind_and_key() {
        let set = CompiledSet::new(vec![CompiledNode {
            kind: NodeKind(2),
            key: "k".into(),
            label: "L".into(),
            attrs: Attrs::new(),
        }]);
        assert_eq!(set.get(NodeKind(2), "k").map(|c| c.key.as_str()), Some("k"));
        assert!(set.get(NodeKind(2), "other").is_none());
        assert!(set.get(NodeKind(1), "k").is_none());
        assert_eq!(set.iter().count(), 1);
    }
}
