use crate::envelope::sha256;
use maknae_graph::graph::GraphError;
use maknae_graph::schema::CompiledSet;

pub fn digest(set: &CompiledSet) -> Result<[u8; 32], GraphError> {
    Ok(sha256(&set.canonical_bytes()?))
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Assessment {
    Current,
    Upgrade { from: Option<[u8; 32]> },
    Forged(&'static str),
}

/// Judges a store's compiled set: its own nodes must hash to the digest it records, and
/// that digest either is the binary's (`Current`) or names an older vocabulary (`Upgrade`).
pub fn assess(
    stored_digest: Option<[u8; 32]>,
    stored: &CompiledSet,
    binary_digest: [u8; 32],
) -> Assessment {
    let Ok(nodes) = digest(stored) else {
        return Assessment::Forged("the stored compiled nodes are not canonical");
    };
    match stored_digest {
        None if stored.is_empty() => Assessment::Upgrade { from: None },
        None => Assessment::Forged("compiled nodes are stored without a vocabulary digest"),
        Some(claimed) if nodes != claimed && claimed == binary_digest => {
            Assessment::Forged("compiled nodes differ from the digest they claim")
        }
        Some(claimed) if nodes != claimed => {
            Assessment::Forged("the stored digest does not cover the stored compiled nodes")
        }
        Some(claimed) if claimed == binary_digest => Assessment::Current,
        Some(claimed) => Assessment::Upgrade {
            from: Some(claimed),
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use maknae_graph::kernel::persisted_compiled_set;
    use maknae_graph::record::{Attrs, NodeKind};
    use maknae_graph::schema::{CompiledNode, CompiledSet};

    fn roles() -> CompiledSet {
        persisted_compiled_set("UNCLASSIFIED")
    }

    fn wider() -> CompiledSet {
        let mut v: Vec<CompiledNode> = roles().iter().cloned().collect();
        v.push(CompiledNode {
            kind: NodeKind(4),
            key: "superadmin".into(),
            label: "UNCLASSIFIED".into(),
            attrs: Attrs::new(),
        });
        CompiledSet::new(v)
    }

    fn d(set: &CompiledSet) -> [u8; 32] {
        digest(set).unwrap()
    }

    #[test]
    fn digest_is_sha256_of_canonical_bytes_and_differs_across_labels() {
        let r = roles();
        assert_eq!(
            d(&r),
            crate::envelope::sha256(&r.canonical_bytes().unwrap())
        );
        assert_ne!(d(&r), d(&persisted_compiled_set("UNOFFICIAL")));
        assert_eq!(
            d(&CompiledSet::default()),
            crate::envelope::sha256(&0u32.to_le_bytes())
        );
    }

    #[test]
    fn digest_refuses_a_set_with_a_duplicate_node() {
        let mut v: Vec<CompiledNode> = roles().iter().cloned().collect();
        v.push(v[0].clone());
        assert!(digest(&CompiledSet::new(v)).is_err());
    }

    #[test]
    fn same_digest_same_nodes_is_current() {
        assert_eq!(
            assess(Some(d(&roles())), &roles(), d(&roles())),
            Assessment::Current
        );
    }

    #[test]
    fn same_digest_different_nodes_is_forgery() {
        assert_eq!(
            assess(Some(d(&roles())), &wider(), d(&roles())),
            Assessment::Forged("compiled nodes differ from the digest they claim")
        );
    }

    #[test]
    fn a_self_consistent_different_digest_is_an_upgrade() {
        let old = d(&wider());
        assert_eq!(
            assess(Some(old), &wider(), d(&roles())),
            Assessment::Upgrade { from: Some(old) }
        );
        assert_eq!(
            assess(None, &CompiledSet::default(), d(&roles())),
            Assessment::Upgrade { from: None }
        );
    }

    #[test]
    fn a_digest_that_does_not_cover_the_stored_nodes_is_forgery() {
        assert_eq!(
            assess(Some([7; 32]), &roles(), d(&roles())),
            Assessment::Forged("the stored digest does not cover the stored compiled nodes")
        );
        assert_eq!(
            assess(
                Some(d(&wider())),
                &roles(),
                d(&persisted_compiled_set("UNOFFICIAL"))
            ),
            Assessment::Forged("the stored digest does not cover the stored compiled nodes")
        );
        assert_eq!(
            assess(None, &roles(), d(&roles())),
            Assessment::Forged("compiled nodes are stored without a vocabulary digest")
        );
    }

    #[test]
    fn stored_nodes_that_do_not_canonicalize_are_forgery() {
        let mut v: Vec<CompiledNode> = roles().iter().cloned().collect();
        v.push(v[0].clone());
        let dup = CompiledSet::new(v);
        for claimed in [None, Some(d(&roles())), Some([7; 32])] {
            assert_eq!(
                assess(claimed, &dup, d(&roles())),
                Assessment::Forged("the stored compiled nodes are not canonical")
            );
        }
    }
}
