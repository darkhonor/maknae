//! Provider credentials, read on first use and cached per destination (#240b).
//!
//! Scope says the key is "read at boot or on first use and never logged".
//! **At boot is single-provider thinking** and fails the moment there are two,
//! so it is first use, per destination — the invariant #240a's design records.
//!
//! The cache holds `Zeroizing<String>`, so a dropped entry wipes. Nothing here
//! implements `Debug`: a derived one on a map of secrets is exactly how a key
//! reaches a log line.

use std::collections::BTreeMap;
use zeroize::Zeroizing;

/// Where a provider key comes from. A trait so the serving path can be tested
/// without a live Vault — this project has no Vault stub and deliberately uses
/// none, so the seam is here rather than a fake server.
/// ASYNC, deliberately. A synchronous seam forces any real implementation to
/// bridge with `block_on`, and the deputy already calls `fulfil` inside a
/// runtime — Tokio panics when a thread driving a runtime blocks on it again.
/// A synchronous `read` therefore could not produce the named fail-closed
/// credential error this design promises; it would abort the process instead.
/// Reviewed finding (#296): the shape has to be async, not the bridge.
pub trait KeySource {
    /// #308: `mount`, a mount-relative `path`, and the `field` inside the
    /// secret — **the source composes the address for its own store.** The
    /// kernel sends a mount-relative path and the field name; the mount comes
    /// from the deputy's own `egress-bounds.yaml`. Passing the three parts
    /// rather than one pre-composed string is what lets a non-Vault source
    /// (#306 question 21) interpret them its own way instead of parsing a
    /// Vault-shaped path back apart.
    fn read(
        &self,
        mount: &str,
        path: &str,
        field: &str,
    ) -> impl std::future::Future<Output = Result<Zeroizing<String>, String>> + Send;
}

/// The source in use until a Vault client is constructed.
///
/// Deliberately a `KeySource` and not a special case upstream: the deputy runs
/// its REAL path — admit, ask for the credential, refuse — so the refusal comes
/// from the layer that owns credentials and names itself accordingly. A closure
/// short-circuiting `fulfil` would have left the whole fulfilment path unbuilt
/// and unexercised, which is what `dead_code` caught.
pub struct NoCredentialSource;

impl KeySource for NoCredentialSource {
    async fn read(
        &self,
        mount: &str,
        path: &str,
        field: &str,
    ) -> Result<Zeroizing<String>, String> {
        Err(format!(
            "no Vault client is configured; cannot read field '{field}' of '{mount}/data/{path}'"
        ))
    }
}

/// First-use, per-destination cache.
pub struct KeyCache<S> {
    source: S,
    /// Keyed on **(mount, path, field)** since #308, not on the path alone: two
    /// providers may name the same secret and read different fields from it, and
    /// a path-only key would serve the first field to the second provider. The
    /// same reasoning as keying per destination rather than per process.
    entries: BTreeMap<(String, String, String), Zeroizing<String>>,
}

impl<S: KeySource> KeyCache<S> {
    pub fn new(source: S) -> Self {
        Self {
            source,
            entries: BTreeMap::new(),
        }
    }

    /// The key for one destination, read on first use.
    ///
    /// Keyed on the VAULT PATH, not the provider name: two providers sharing a
    /// path share a key, and the path is what the deputy's grant is expressed
    /// over. The error carries the path — never the value.
    /// The source, for tests that need to observe how often it was asked.
    /// `cfg(test)` rather than `#[allow(dead_code)]`: it exists only to let a
    /// test count reads, and production has no business reaching past the cache
    /// to the thing behind it.
    #[cfg(test)]
    pub fn source(&self) -> &S {
        &self.source
    }

    pub async fn get(
        &mut self,
        mount: &str,
        path: &str,
        field: &str,
    ) -> Result<&Zeroizing<String>, String> {
        let k = (mount.to_string(), path.to_string(), field.to_string());
        if !self.entries.contains_key(&k) {
            let v = self.source.read(mount, path, field).await?;
            self.entries.insert(k.clone(), v);
        }
        Ok(&self.entries[&k])
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    struct Counting {
        reads: Mutex<Vec<String>>,
    }
    impl KeySource for Counting {
        async fn read(&self, m: &str, p: &str, f: &str) -> Result<Zeroizing<String>, String> {
            // Records all THREE, so the test below can prove what the cache key
            // actually is rather than what its comment says (#308).
            self.reads.lock().unwrap().push(format!("{m}|{p}|{f}"));
            Ok(Zeroizing::new(format!("key-for-{p}#{f}")))
        }
    }

    /// First use reads; every use after that does not. Scope says "read at boot
    /// or on first use" — this is the first-use half, and the count is what
    /// proves the cache exists rather than a comment claiming it.
    ///
    /// **And the key is the TRIPLE (#308.)** A path-only key would serve the
    /// first field's value to a provider asking for a different field of the
    /// same secret — silently, and with the wrong credential. Each of the three
    /// components is varied independently below, so the discriminator for each
    /// is a distinct assertion rather than a comment.
    #[tokio::test]
    async fn a_key_is_read_once_per_mount_path_and_field_and_reused() {
        let mut c = KeyCache::new(Counting {
            reads: Mutex::new(Vec::new()),
        });
        let m = "maknae-kv";
        // Same triple twice: one read.
        assert_eq!(
            &**c.get(m, "one", "api-key").await.unwrap(),
            "key-for-one#api-key"
        );
        assert_eq!(
            &**c.get(m, "one", "api-key").await.unwrap(),
            "key-for-one#api-key"
        );
        assert_eq!(c.source.reads.lock().unwrap().len(), 1, "cached on re-ask");
        // A different PATH is a different entry.
        assert_eq!(
            &**c.get(m, "two", "api-key").await.unwrap(),
            "key-for-two#api-key"
        );
        // A different FIELD of the SAME path is a different entry — the case a
        // path-only key got wrong.
        assert_eq!(
            &**c.get(m, "one", "other-key").await.unwrap(),
            "key-for-one#other-key"
        );
        // A different MOUNT is a different entry.
        assert_eq!(
            &**c.get("other-kv", "one", "api-key").await.unwrap(),
            "key-for-one#api-key"
        );
        assert_eq!(
            *c.source.reads.lock().unwrap(),
            vec![
                "maknae-kv|one|api-key",
                "maknae-kv|two|api-key",
                "maknae-kv|one|other-key",
                "other-kv|one|api-key",
            ],
            "one read per (mount, path, field), in first-use order"
        );
    }

    struct Failing;
    impl KeySource for Failing {
        async fn read(&self, _m: &str, p: &str, _f: &str) -> Result<Zeroizing<String>, String> {
            Err(format!("permission denied on {p}"))
        }
    }

    /// A failed read is a refusal that names the PATH and nothing else, and is
    /// not cached — a transient Vault failure must not poison the destination.
    #[tokio::test]
    async fn a_failed_read_names_the_path_and_is_not_cached() {
        let mut c = KeyCache::new(Failing);
        let e = c.get("maknae-kv", "one", "api-key").await.unwrap_err();
        assert!(e.contains("one"));
        assert!(
            c.get("maknae-kv", "a/data/one", "api-key").await.is_err(),
            "a failure must not be cached"
        );
    }

    /// The source the deputy runs on until a Vault client exists. It refuses,
    /// names the PATH it was asked for, and is never cached as a success —
    /// this is the deputy's real behaviour right now, not a placeholder.
    #[tokio::test]
    async fn the_no_credential_source_refuses_and_names_the_path() {
        let mut c = KeyCache::new(NoCredentialSource);
        let e = c
            .get("maknae-kv", "llm-providers/openai", "api-key")
            .await
            .unwrap_err();
        assert!(e.contains("no Vault client is configured"), "{e}");
        assert!(e.contains("llm-providers/openai"), "{e}");
        // Still refuses on a second ask — a refusal is not cached as a value.
        assert!(c
            .get("maknae-kv", "llm-providers/openai", "api-key")
            .await
            .is_err());
    }
}
