use crate::record::{Attrs, EdgeKind, NodeKind};

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
