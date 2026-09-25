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
    /// Keyed on (mount, path, field), never the provider name: two providers
    /// naming the same secret and field share a key, and the path is what the
    /// deputy's grant is expressed over. The error carries the path — never
    /// the value.
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

    /// Fails the FIRST read of every triple and succeeds after — so a second
    /// ask of the SAME triple distinguishes "not cached" (it retries and
    /// succeeds) from "cached" (it would still be the error).
    struct FailsOnce {
        seen: Mutex<Vec<String>>,
    }
    impl KeySource for FailsOnce {
        async fn read(&self, m: &str, p: &str, f: &str) -> Result<Zeroizing<String>, String> {
            let k = format!("{m}|{p}|{f}");
            let mut seen = self.seen.lock().unwrap();
            if seen.contains(&k) {
                Ok(Zeroizing::new(format!("key-for-{p}")))
            } else {
                seen.push(k);
                Err(format!("permission denied on {p}"))
            }
        }
    }

    /// A failed read is a refusal that names the PATH and nothing else, and is
    /// not cached — a transient Vault failure must not poison the destination.
    /// Proven by re-asking the SAME triple: the second ask reaches the source
    /// again and succeeds. (An earlier version asked a different path against
    /// a source that always failed, which proved nothing about caching.)
    #[tokio::test]
    async fn a_failed_read_names_the_path_and_is_not_cached() {
        let mut c = KeyCache::new(FailsOnce {
            seen: Mutex::new(vec![]),
        });
        let e = c.get("maknae-kv", "one", "api-key").await.unwrap_err();
        assert!(e.contains("one"));
        assert!(
            !e.contains("key-for"),
            "the error names the path, never a value"
        );
        assert_eq!(
            &**c.get("maknae-kv", "one", "api-key").await.unwrap(),
            "key-for-one",
            "the failure was not cached: the same triple was asked of the source again"
        );
        assert_eq!(c.source.seen.lock().unwrap().len(), 1);
    }
}
