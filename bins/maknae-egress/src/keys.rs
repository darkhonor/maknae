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
pub trait KeySource {
    fn read(&self, key_vault_path: &str) -> Result<Zeroizing<String>, String>;
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
    fn read(&self, key_vault_path: &str) -> Result<Zeroizing<String>, String> {
        Err(format!(
            "no Vault client is configured; cannot read '{key_vault_path}'"
        ))
    }
}

/// First-use, per-destination cache.
pub struct KeyCache<S> {
    source: S,
    entries: BTreeMap<String, Zeroizing<String>>,
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
    pub fn get(&mut self, key_vault_path: &str) -> Result<&Zeroizing<String>, String> {
        if !self.entries.contains_key(key_vault_path) {
            let v = self.source.read(key_vault_path)?;
            self.entries.insert(key_vault_path.to_string(), v);
        }
        Ok(&self.entries[key_vault_path])
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;

    struct Counting {
        reads: RefCell<Vec<String>>,
    }
    impl KeySource for Counting {
        fn read(&self, p: &str) -> Result<Zeroizing<String>, String> {
            self.reads.borrow_mut().push(p.to_string());
            Ok(Zeroizing::new(format!("key-for-{p}")))
        }
    }

    /// First use reads; every use after that does not. Scope says "read at boot
    /// or on first use" — this is the first-use half, and the count is what
    /// proves the cache exists rather than a comment claiming it.
    #[test]
    fn a_key_is_read_once_per_destination_and_reused() {
        let mut c = KeyCache::new(Counting {
            reads: RefCell::new(Vec::new()),
        });
        assert_eq!(&**c.get("a/data/one").unwrap(), "key-for-a/data/one");
        assert_eq!(&**c.get("a/data/one").unwrap(), "key-for-a/data/one");
        assert_eq!(&**c.get("a/data/two").unwrap(), "key-for-a/data/two");
        assert_eq!(c.source.reads.borrow().len(), 2, "one read per DESTINATION");
    }

    struct Failing;
    impl KeySource for Failing {
        fn read(&self, p: &str) -> Result<Zeroizing<String>, String> {
            Err(format!("permission denied on {p}"))
        }
    }

    /// A failed read is a refusal that names the PATH and nothing else, and is
    /// not cached — a transient Vault failure must not poison the destination.
    #[test]
    fn a_failed_read_names_the_path_and_is_not_cached() {
        let mut c = KeyCache::new(Failing);
        let e = c.get("a/data/one").unwrap_err();
        assert!(e.contains("a/data/one"));
        assert!(c.get("a/data/one").is_err(), "a failure must not be cached");
    }

    /// The source the deputy runs on until a Vault client exists. It refuses,
    /// names the PATH it was asked for, and is never cached as a success —
    /// this is the deputy's real behaviour right now, not a placeholder.
    #[test]
    fn the_no_credential_source_refuses_and_names_the_path() {
        let mut c = KeyCache::new(NoCredentialSource);
        let e = c.get("secret/data/maknae/providers/openai").unwrap_err();
        assert!(e.contains("no Vault client is configured"), "{e}");
        assert!(e.contains("secret/data/maknae/providers/openai"), "{e}");
        // Still refuses on a second ask — a refusal is not cached as a value.
        assert!(c.get("secret/data/maknae/providers/openai").is_err());
    }
}
