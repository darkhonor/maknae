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

/// Why a `tool.catalog` fetch produced no catalog. `NoReply` is retried on the next
/// claim; `Refused`, which includes a protocol fault, waits for a new digest.
#[derive(Debug, PartialEq, Eq)]
pub enum CatalogFetchError {
    NoReply(String),
    Refused(String),
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

    pub fn accept(&mut self, view: ToolCatalogReply) -> Result<(), CatalogRejected> {
        self.held = None;
        let graph = verify(&view)?;
        self.held = Some((view.digest, Arc::new(graph)));
        self.last_attempted = None;
        Ok(())
    }

    pub fn refused(&mut self) {
        self.held = None;
    }

    pub fn fetch_failed(&mut self) {
        self.held = None;
        self.last_attempted = None;
    }
}

/// The reply's graph, once its bytes match their digest and decode.
pub fn verify(reply: &ToolCatalogReply) -> Result<Graph, CatalogRejected> {
    if CatalogDigest(maknae_crypto::sha256(&reply.graph.0)) != reply.digest {
        return Err(CatalogRejected::DigestMismatch);
    }
    catalog::decode(&reply.graph.0).map_err(|_| CatalogRejected::Undecodable)
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
        h.accept(v).unwrap();
        assert!(h.current().is_some());
        assert!(!h.should_fetch(Some(d)));
        let other = view("cargo").digest;
        assert!(h.should_fetch(Some(other)));
    }

    #[test]
    fn a_fetch_that_failed_drops_the_catalog_and_fetches_the_same_digest_again() {
        let mut h = CatalogHolder::default();
        let a = view("git");
        assert!(h.should_fetch(Some(a.digest)));
        h.accept(a).unwrap();
        let d = view("cargo").digest;
        assert!(h.should_fetch(Some(d)));
        h.fetch_failed();
        assert!(h.current().is_none());
        assert!(h.should_fetch(Some(d)));
    }

    #[test]
    fn a_catalog_accepted_under_another_stamp_leaves_the_stamp_fetchable() {
        let mut h = CatalogHolder::default();
        let a = view("git").digest;
        assert!(h.should_fetch(Some(a)));
        h.accept(view("cargo")).unwrap();
        assert!(h.should_fetch(Some(a)));
    }

    #[test]
    fn the_held_digest_is_not_fetched_after_another_was_attempted() {
        let mut h = CatalogHolder::default();
        let a = view("git");
        let d = a.digest;
        assert!(h.should_fetch(Some(d)));
        h.accept(a).unwrap();
        assert!(h.should_fetch(Some(view("cargo").digest)));
        assert!(!h.should_fetch(Some(d)));
    }

    #[test]
    fn a_refused_fetch_does_not_refetch_until_the_digest_changes() {
        let mut h = CatalogHolder::default();
        let held = view("git");
        h.accept(held).unwrap();
        let d = view("cargo").digest;
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
        assert!(h.should_fetch(Some(view("hobi").digest)));
    }

    #[test]
    fn a_digest_mismatch_or_bad_bytes_leaves_no_catalog_and_no_retry_loop() {
        let mut h = CatalogHolder::default();
        let good = view("git");
        h.accept(good).unwrap();
        let mut wrong = view("cargo");
        wrong.digest = CatalogDigest([0; 32]);
        assert_eq!(h.accept(wrong), Err(CatalogRejected::DigestMismatch));
        assert!(h.current().is_none());

        let junk = vec![1u8, 2, 3];
        let bad = ToolCatalogReply {
            digest: CatalogDigest(maknae_crypto::sha256(&junk)),
            graph: maknae_proto::Bytes::new(zeroize::Zeroizing::new(junk)),
        };
        let d = bad.digest;
        assert!(h.should_fetch(Some(d)));
        assert_eq!(h.accept(bad), Err(CatalogRejected::Undecodable));
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
    }
}
