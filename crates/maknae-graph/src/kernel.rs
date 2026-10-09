use crate::record::{Attrs, EdgeKind, NodeKind};
use crate::schema::{CompiledNode, CompiledSet, Schema};

pub const SCHEMA_VERSION: u16 = 1;

pub const CONFIG_SOURCE: NodeKind = NodeKind(1);
pub const SECTION: NodeKind = NodeKind(2);
pub const SUBJECT: NodeKind = NodeKind(3);
pub const ROLE: NodeKind = NodeKind(4);
pub const RULE: NodeKind = NodeKind(5);
pub const TERM: NodeKind = NodeKind(6);
pub const CLASS: NodeKind = NodeKind(7);
pub const CLASSIFICATION_SYSTEM: NodeKind = NodeKind(8);
pub const LEVEL: NodeKind = NodeKind(9);
pub const CONTAINMENT: NodeKind = NodeKind(10);
pub const PENDING_CHANGE: NodeKind = NodeKind(11);
pub const SYNC_BASE: NodeKind = NodeKind(12);
pub const INSTANCE: NodeKind = NodeKind(13);

pub const BINDS: EdgeKind = EdgeKind(1);
pub const CONTAINED: EdgeKind = EdgeKind(2);
pub const PERMITS: EdgeKind = EdgeKind(3);
pub const DENIES: EdgeKind = EdgeKind(4);
pub const MATCHES: EdgeKind = EdgeKind(5);
pub const MEMBER_OF: EdgeKind = EdgeKind(6);
pub const DOMINATES: EdgeKind = EdgeKind(7);
pub const DECLARES: EdgeKind = EdgeKind(8);
pub const DECLARED_BY: EdgeKind = EdgeKind(9);
pub const PART_OF: EdgeKind = EdgeKind(10);
pub const PENDING_FOR: EdgeKind = EdgeKind(11);
pub const LEVEL_OF: EdgeKind = EdgeKind(12);

pub const ADVERSARY: &str = "adversary";

pub const ROLES: [&str; 4] = ["admin", "user", "guest", ADVERSARY];
pub const VOCABULARY_SOURCE_KEY: &str = "binary:vocabulary";
pub const ATTR_SHA256: &str = "sha256";
pub const ATTR_NAME: &str = "name";
pub const ATTR_UID: &str = "uid";
pub const ATTR_ALIASES: &str = "aliases";
pub const ATTR_VALUE: &str = "value";

pub fn persisted_compiled_set(label: &str) -> CompiledSet {
    CompiledSet::new(
        ROLES
            .iter()
            .map(|r| CompiledNode {
                kind: ROLE,
                key: (*r).into(),
                label: label.into(),
                attrs: Attrs::new(),
            })
            .collect(),
    )
}

pub static SCHEMA: Schema = Schema {
    version: SCHEMA_VERSION,
    node_kinds: &[
        (CONFIG_SOURCE, "ConfigSource"),
        (SECTION, "Section"),
        (SUBJECT, "Subject"),
        (ROLE, "Role"),
        (RULE, "Rule"),
        (TERM, "Term"),
        (CLASS, "Class"),
        (CLASSIFICATION_SYSTEM, "ClassificationSystem"),
        (LEVEL, "Level"),
        (CONTAINMENT, "Containment"),
        (PENDING_CHANGE, "PendingChange"),
        (SYNC_BASE, "SyncBase"),
        (INSTANCE, "Instance"),
    ],
    edge_kinds: &[
        (BINDS, "binds"),
        (CONTAINED, "contained"),
        (PERMITS, "permits"),
        (DENIES, "denies"),
        (MATCHES, "matches"),
        (MEMBER_OF, "member_of"),
        (DOMINATES, "dominates"),
        (DECLARES, "declares"),
        (DECLARED_BY, "declared_by"),
        (PART_OF, "part_of"),
        (PENDING_FOR, "pending_for"),
        (LEVEL_OF, "level_of"),
    ],
    triples: &[
        (SUBJECT, BINDS, ROLE),
        (SUBJECT, CONTAINED, CONTAINMENT),
        (ROLE, PERMITS, RULE),
        (ROLE, DENIES, RULE),
        (RULE, MATCHES, TERM),
        (TERM, MEMBER_OF, CLASS),
        (LEVEL, DOMINATES, LEVEL),
        (LEVEL, LEVEL_OF, CLASSIFICATION_SYSTEM),
        (INSTANCE, DECLARES, CLASSIFICATION_SYSTEM),
        (SECTION, PART_OF, CONFIG_SOURCE),
        (PENDING_CHANGE, PENDING_FOR, SECTION),
        (SUBJECT, DECLARED_BY, SECTION),
        (RULE, DECLARED_BY, SECTION),
        (CLASSIFICATION_SYSTEM, DECLARED_BY, SECTION),
        (LEVEL, DECLARED_BY, SECTION),
        (INSTANCE, DECLARED_BY, SECTION),
        (CONTAINMENT, DECLARED_BY, SECTION),
    ],
    compiled_kinds: &[ROLE, TERM, CLASS],
    forbidden_targets: &[(BINDS, ROLE, ADVERSARY)],
};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn persisted_compiled_set_is_the_four_roles_labelled() {
        let set = persisted_compiled_set("UNCLASSIFIED");
        let keys: Vec<&str> = set.iter().map(|c| c.key.as_str()).collect();
        assert_eq!(keys, ROLES);
        for c in set.iter() {
            assert_eq!(c.kind, ROLE);
            assert_eq!(c.label, "UNCLASSIFIED");
            assert!(c.attrs.is_empty());
        }
        assert!(ROLES.contains(&ADVERSARY));
    }

    #[test]
    fn every_triple_names_known_kinds() {
        for &(from, edge, to) in SCHEMA.triples {
            assert!(SCHEMA.node_kind_name(from).is_some(), "{from:?}");
            assert!(SCHEMA.edge_kind_name(edge).is_some(), "{edge:?}");
            assert!(SCHEMA.node_kind_name(to).is_some(), "{to:?}");
        }
    }

    #[test]
    fn kind_codes_are_unique() {
        let mut nodes: Vec<u16> = SCHEMA.node_kinds.iter().map(|(k, _)| k.0).collect();
        nodes.sort_unstable();
        nodes.dedup();
        assert_eq!(nodes.len(), SCHEMA.node_kinds.len());
        let mut edges: Vec<u16> = SCHEMA.edge_kinds.iter().map(|(k, _)| k.0).collect();
        edges.sort_unstable();
        edges.dedup();
        assert_eq!(edges.len(), SCHEMA.edge_kinds.len());
    }

    #[test]
    fn containment_is_an_edge_never_a_binding_to_adversary() {
        assert!(SCHEMA.allows(SUBJECT, CONTAINED, CONTAINMENT));
        assert!(SCHEMA.allows(SUBJECT, BINDS, ROLE));
        assert!(SCHEMA.forbids_target(BINDS, ROLE, ADVERSARY));
        assert!(!SCHEMA.forbids_target(BINDS, ROLE, "admin"));
        assert!(!SCHEMA.allows(ROLE, BINDS, SUBJECT));
    }

    #[test]
    fn schema_tables_are_pinned() {
        assert_eq!(
            SCHEMA.node_kinds,
            &[
                (NodeKind(1), "ConfigSource"),
                (NodeKind(2), "Section"),
                (NodeKind(3), "Subject"),
                (NodeKind(4), "Role"),
                (NodeKind(5), "Rule"),
                (NodeKind(6), "Term"),
                (NodeKind(7), "Class"),
                (NodeKind(8), "ClassificationSystem"),
                (NodeKind(9), "Level"),
                (NodeKind(10), "Containment"),
                (NodeKind(11), "PendingChange"),
                (NodeKind(12), "SyncBase"),
                (NodeKind(13), "Instance"),
            ]
        );
        assert_eq!(
            SCHEMA.edge_kinds,
            &[
                (EdgeKind(1), "binds"),
                (EdgeKind(2), "contained"),
                (EdgeKind(3), "permits"),
                (EdgeKind(4), "denies"),
                (EdgeKind(5), "matches"),
                (EdgeKind(6), "member_of"),
                (EdgeKind(7), "dominates"),
                (EdgeKind(8), "declares"),
                (EdgeKind(9), "declared_by"),
                (EdgeKind(10), "part_of"),
                (EdgeKind(11), "pending_for"),
                (EdgeKind(12), "level_of"),
            ]
        );
        assert_eq!(
            SCHEMA.triples,
            &[
                (SUBJECT, BINDS, ROLE),
                (SUBJECT, CONTAINED, CONTAINMENT),
                (ROLE, PERMITS, RULE),
                (ROLE, DENIES, RULE),
                (RULE, MATCHES, TERM),
                (TERM, MEMBER_OF, CLASS),
                (LEVEL, DOMINATES, LEVEL),
                (LEVEL, LEVEL_OF, CLASSIFICATION_SYSTEM),
                (INSTANCE, DECLARES, CLASSIFICATION_SYSTEM),
                (SECTION, PART_OF, CONFIG_SOURCE),
                (PENDING_CHANGE, PENDING_FOR, SECTION),
                (SUBJECT, DECLARED_BY, SECTION),
                (RULE, DECLARED_BY, SECTION),
                (CLASSIFICATION_SYSTEM, DECLARED_BY, SECTION),
                (LEVEL, DECLARED_BY, SECTION),
                (INSTANCE, DECLARED_BY, SECTION),
                (CONTAINMENT, DECLARED_BY, SECTION),
            ]
        );
        assert_eq!(SCHEMA.compiled_kinds, &[ROLE, TERM, CLASS]);
        assert_eq!(SCHEMA.forbidden_targets, &[(BINDS, ROLE, ADVERSARY)]);
    }

    #[test]
    fn role_term_class_are_compiled_and_nothing_else_is() {
        for &(kind, _) in SCHEMA.node_kinds {
            let expected = [ROLE, TERM, CLASS].contains(&kind);
            assert_eq!(SCHEMA.is_compiled(kind), expected, "{kind:?}");
        }
        assert_eq!(SCHEMA.version, 1);
    }
}
