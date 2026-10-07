//! The binary's compiled vocabulary under the booted system's lowest level: the
//! full set the snapshot compiler takes, the role subset the store persists, and
//! that subset's digest.

use maknae_graph::graph::GraphError;
use maknae_graph::schema::CompiledSet;

#[derive(Debug, Clone)]
pub struct Vocabulary {
    pub full: CompiledSet,
    pub persisted: CompiledSet,
    pub digest: [u8; 32],
}

pub fn kernel_vocabulary(label: &str) -> Result<Vocabulary, GraphError> {
    let persisted = maknae_graph::kernel::persisted_compiled_set(label);
    let digest = maknae_state::vocabulary::digest(&persisted)?;
    Ok(Vocabulary {
        full: maknae_authz_basic::compiled_set(label),
        persisted,
        digest,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_persisted_set_is_the_role_subset_of_the_full_set_under_one_label() {
        let v = kernel_vocabulary("UNCLASSIFIED").unwrap();
        assert!(!v.persisted.is_empty());
        assert!(v.full.iter().count() > v.persisted.iter().count());
        for n in v.persisted.iter() {
            assert_eq!(n.label, "UNCLASSIFIED");
            assert!(v.full.iter().any(|f| f == n), "{n:?} is in the full set");
        }
        assert!(v.full.iter().all(|n| n.label == "UNCLASSIFIED"));
    }

    #[test]
    fn the_digest_covers_the_persisted_set_and_follows_the_label() {
        let us = kernel_vocabulary("UNCLASSIFIED").unwrap();
        assert_eq!(
            us.digest,
            maknae_state::vocabulary::digest(&us.persisted).unwrap()
        );
        let aus = kernel_vocabulary("UNOFFICIAL").unwrap();
        assert_ne!(us.digest, aus.digest);
        assert!(aus
            .persisted
            .iter()
            .eq(maknae_graph::kernel::persisted_compiled_set("UNOFFICIAL").iter()));
        assert!(aus
            .full
            .iter()
            .eq(maknae_authz_basic::compiled_set("UNOFFICIAL").iter()));
    }
}
