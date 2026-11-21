//! The subject's tool catalog as the loop holds it: a hint fetched when the kernel's
//! stamp changes, never an input to a decision.
use maknae_graph::catalog;
use maknae_graph::graph::Graph;
use maknae_proto::{CatalogDigest, ToolCatalogReply};
use std::sync::Arc;

#[derive(Debug, PartialEq, Eq)]
pub enum CatalogRejected {
    DigestMismatch,
    Undecodable,
}

#[derive(Default)]
pub struct CatalogHolder {
    held: Option<(CatalogDigest, Arc<Graph>)>,
    last_attempted: Option<CatalogDigest>,
}

impl CatalogHolder {
    pub fn current(&self) -> Option<Arc<Graph>> {
        self.held.as_ref().map(|(_, g)| Arc::clone(g))
    }

    pub fn should_fetch(&mut self, seen: Option<CatalogDigest>) -> bool {
        let Some(seen) = seen else { return false };
        let held = self.held.as_ref().map(|(d, _)| *d);
        if held == Some(seen) || self.last_attempted == Some(seen) {
            return false;
        }
        self.last_attempted = Some(seen);
        true
    }

    pub fn accept(
        &mut self,
        view: ToolCatalogReply,
        digest: fn(&[u8]) -> [u8; 32],
    ) -> Result<(), CatalogRejected> {
        self.held = None;
        if CatalogDigest(digest(&view.graph.0)) != view.digest {
            return Err(CatalogRejected::DigestMismatch);
        }
        let graph = catalog::decode(&view.graph.0).map_err(|_| CatalogRejected::Undecodable)?;
        self.held = Some((view.digest, Arc::new(graph)));
        Ok(())
    }

    pub fn refused(&mut self) {
        self.held = None;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use maknae_graph::catalog::{CatalogEntry, CatalogInput, CatalogOutput};

    fn view(name: &str) -> ToolCatalogReply {
        let bytes = catalog::encode(&CatalogInput {
            entries: vec![CatalogEntry {
                name: name.into(),
                description: None,
                executes_workspace: false,
                output: CatalogOutput::Redacted,
                binds: vec![],
                programs: vec![("git".into(), vec!["status".into()])],
            }],
            forges: vec![],
        })
        .unwrap();
        ToolCatalogReply {
            digest: CatalogDigest(maknae_crypto::sha256(&bytes)),
            graph: maknae_proto::Bytes::new(zeroize::Zeroizing::new(bytes)),
        }
    }

    #[test]
    fn a_new_digest_fetches_once_and_an_equal_one_never() {
        let mut h = CatalogHolder::default();
        let v = view("git");
        let d = v.digest;
        assert!(!h.should_fetch(None));
        assert!(h.should_fetch(Some(d)));
        assert!(!h.should_fetch(Some(d)));
        h.accept(v, maknae_crypto::sha256).unwrap();
        assert!(h.current().is_some());
        assert!(!h.should_fetch(Some(d)));
        let other = view("cargo").digest;
        assert!(h.should_fetch(Some(other)));
    }

    #[test]
    fn a_refused_fetch_does_not_refetch_until_the_digest_changes() {
        let mut h = CatalogHolder::default();
        let d = view("git").digest;
        let fetches = (0..5)
            .filter(|_| {
                let fetch = h.should_fetch(Some(d));
                if fetch {
                    h.refused();
                }
                fetch
            })
            .count();
        assert_eq!(fetches, 1);
        assert!(h.current().is_none());
        assert!(h.should_fetch(Some(view("cargo").digest)));
    }

    #[test]
    fn a_digest_mismatch_or_bad_bytes_leaves_no_catalog_and_no_retry_loop() {
        let mut h = CatalogHolder::default();
        let good = view("git");
        h.accept(good, maknae_crypto::sha256).unwrap();
        let mut wrong = view("cargo");
        wrong.digest = CatalogDigest([0; 32]);
        assert_eq!(
            h.accept(wrong, maknae_crypto::sha256),
            Err(CatalogRejected::DigestMismatch)
        );
        assert!(h.current().is_none());

        let junk = vec![1u8, 2, 3];
        let bad = ToolCatalogReply {
            digest: CatalogDigest(maknae_crypto::sha256(&junk)),
            graph: maknae_proto::Bytes::new(zeroize::Zeroizing::new(junk)),
        };
        let d = bad.digest;
        assert!(h.should_fetch(Some(d)));
        assert_eq!(
            h.accept(bad, maknae_crypto::sha256),
            Err(CatalogRejected::Undecodable)
        );
        assert!(h.current().is_none());
        assert!(!h.should_fetch(Some(d)));
    }

    #[test]
    fn no_catalog_module_reads_etc_maknae() {
        let src = include_str!("catalog.rs");
        let code = src.split("#[cfg(test)]").next().unwrap();
        for needle in ["/etc/maknae", "tools.yaml", "maknae.yaml", "std::fs"] {
            assert!(!code.contains(needle), "{needle}");
        }
        let cli = include_str!("../../../bins/maknae/src/tools.rs");
        let code = cli.split("#[cfg(test)]").next().unwrap();
        for needle in ["/etc/maknae", "tools.yaml", "maknae.yaml", "std::fs"] {
            assert!(!code.contains(needle), "{needle}");
        }
    }
}
