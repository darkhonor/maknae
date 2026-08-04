//! Offline CUI Registry snapshot (spec §6): a dated, provenance-stamped,
//! line-oriented controlled vocabulary the engine carries so it NEVER fetches
//! at decide-time (air-gapped target). A maintenance tool refreshes the `.tsv`.
//!
//! ENUM-VS-DATA LINE: algebra-bearing controls are the closed `ControlMarking`
//! enum (the lattice reasons over them); the ~125 Registry-DELEGATED CUI
//! categories + LDC strings live HERE as data (§ 2002.4(k) / § 2002.16(b)(4)).
//!
//! Stage 1 lands the loader + `is_known_*` API + the loader's fail-closed
//! (empty/malformed/provenance-less → `Err`). `validate_label` ENFORCEMENT
//! against the snapshot (which needs the CUI-regime discriminator) is Stage 4.
use std::collections::{BTreeMap, BTreeSet};

/// Provenance stamped on every snapshot (mirrors `coverage-tiers.toml`'s
/// `ratchet_provenance`): where it came from, when, the registry's own
/// "current as of" date, and a content hash.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RegistryProvenance {
    pub source_url: String,
    pub extraction_date: String,
    pub current_as_of: String,
    pub content_hash: String,
}

/// A CUI category as published in the Registry: its organizational index and
/// URL slug (the marking definition lives at that slug's detail page).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CuiCategory {
    pub index: String,
    pub slug: String,
}

/// A loaded, dated CUI Registry snapshot. Constructed only via
/// [`CuiRegistry::from_snapshot_tsv`], which fails closed on degenerate input.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CuiRegistry {
    provenance: RegistryProvenance,
    categories: BTreeMap<String, CuiCategory>,
    ldcs: BTreeSet<String>,
}

/// Why a snapshot failed to load. Every variant is fail-CLOSED (reject), never
/// a silent empty registry that would later fail OPEN.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RegistryError {
    /// A required provenance key was absent from the header.
    MissingProvenance(String),
    /// A data/header row did not match the grammar (1-based line number).
    MalformedRow(usize),
    /// No categories AND no LDCs parsed — an empty registry is rejected (an
    /// empty one would make every `is_known_*` return false = over-reject, and
    /// a naive `Default` that returned true would fail OPEN; reject instead).
    EmptyRegistry,
}

impl CuiRegistry {
    pub fn provenance(&self) -> &RegistryProvenance {
        &self.provenance
    }

    /// Is `name` a Registry-published CUI category? Unknown → `false` (fail
    /// closed). Kills the fail-open mutant under the T1 0-missed gate.
    pub fn is_known_category(&self, name: &str) -> bool {
        self.categories.contains_key(name)
    }

    /// The category's index + slug, if published.
    pub fn category(&self, name: &str) -> Option<&CuiCategory> {
        self.categories.get(name)
    }

    /// Is `marking` a Registry-published Limited Dissemination Control? Unknown
    /// → `false` (fail closed).
    pub fn is_known_ldc(&self, marking: &str) -> bool {
        self.ldcs.contains(marking)
    }

    /// Parse the line-oriented snapshot. Grammar (tab-separated; blank lines
    /// ignored):
    ///
    /// ```text
    /// # source_url=...
    /// # extraction_date=...
    /// # current_as_of=...
    /// # content_hash=...
    /// LDC\t<NAME>
    /// CATEGORY\t<NAME>\t<INDEX>\t<SLUG>
    /// ```
    ///
    /// Fails closed: a malformed row, a missing required provenance key, or an
    /// empty resulting registry → `Err` (never a silent partial/empty load).
    pub fn from_snapshot_tsv(text: &str) -> Result<CuiRegistry, RegistryError> {
        let mut prov: BTreeMap<String, String> = BTreeMap::new();
        let mut categories: BTreeMap<String, CuiCategory> = BTreeMap::new();
        let mut ldcs: BTreeSet<String> = BTreeSet::new();

        for (i, raw) in text.lines().enumerate() {
            let line = raw.trim_end();
            if line.trim().is_empty() {
                continue;
            }
            if let Some(kv) = line.strip_prefix("# ") {
                let (k, v) = kv.split_once('=').ok_or(RegistryError::MalformedRow(i + 1))?;
                prov.insert(k.trim().to_string(), v.trim().to_string());
                continue;
            }
            let fields: Vec<&str> = line.split('\t').collect();
            match fields.as_slice() {
                // `line` is trim_end'd, so a 2-field LDC row's name is the last
                // field and is never empty (a trailing empty field is trimmed to
                // a 1-field row → the `_` arm) — no empty-name guard needed here.
                ["LDC", name] => {
                    ldcs.insert((*name).to_string());
                }
                // CATEGORY's name is NOT the last field, so an empty name IS
                // reachable (`CATEGORY\t\t<index>\t<slug>`) — guard it.
                ["CATEGORY", name, index, slug] if !name.is_empty() => {
                    categories.insert(
                        (*name).to_string(),
                        CuiCategory {
                            index: (*index).to_string(),
                            slug: (*slug).to_string(),
                        },
                    );
                }
                _ => return Err(RegistryError::MalformedRow(i + 1)),
            }
        }

        let get = |k: &str| {
            prov.get(k)
                .cloned()
                .ok_or_else(|| RegistryError::MissingProvenance(k.to_string()))
        };
        let provenance = RegistryProvenance {
            source_url: get("source_url")?,
            extraction_date: get("extraction_date")?,
            current_as_of: get("current_as_of")?,
            content_hash: get("content_hash")?,
        };
        if categories.is_empty() && ldcs.is_empty() {
            return Err(RegistryError::EmptyRegistry);
        }
        Ok(CuiRegistry {
            provenance,
            categories,
            ldcs,
        })
    }

    /// The dated seed snapshot embedded in the binary (air-gapped: the engine
    /// carries its own registry). Refreshed out-of-band by the extraction tool.
    ///
    /// # Panics
    /// Panics only if the compiled-in seed `.tsv` fails to parse — a build-time
    /// invariant covered by `seed_loads_and_knows_legal_privilege_and_ldcs`, so
    /// it cannot fire at runtime unless a future edit to the embedded asset
    /// breaks its grammar (which that test catches in CI).
    pub fn seed() -> CuiRegistry {
        Self::from_snapshot_tsv(include_str!(
            "../references/cui-registry/cui-registry-2026-08-04.tsv"
        ))
        .expect("embedded seed snapshot must parse")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn seed_loads_and_knows_legal_privilege_and_ldcs() {
        let reg = CuiRegistry::seed();
        assert_eq!(reg.provenance().extraction_date, "2026-08-04");
        // authoritative Registry facts (operator-supplied 2026-08-04)
        assert!(reg.is_known_category("Legal Privilege"));
        assert_eq!(reg.category("Legal Privilege").map(|c| c.slug.as_str()), Some("legal-privilege"));
        assert!(reg.is_known_ldc("NOFORN"));
        assert!(reg.is_known_ldc("DISPLAY ONLY"));
        // fail-closed unknown (kills the is_known_* fail-open mutant)
        assert!(!reg.is_known_category("Bogus"));
        assert!(!reg.is_known_ldc("BOGUS"));
    }

    #[test]
    fn loader_fails_closed_on_degenerate_input() {
        let prov = "# source_url=u\n# extraction_date=d\n# current_as_of=c\n# content_hash=h\n";
        // provenance-only → EmptyRegistry (never a silent empty load)
        assert_eq!(
            CuiRegistry::from_snapshot_tsv(prov),
            Err(RegistryError::EmptyRegistry)
        );
        // a registry with ONLY LDCs, or ONLY categories, DOES load — this pins
        // the empty-check as `categories.is_empty() && ldcs.is_empty()` (an `||`
        // mutant would wrongly reject a non-empty-one-side registry)
        assert!(CuiRegistry::from_snapshot_tsv(&format!("{prov}LDC\tNOFORN\n")).is_ok());
        assert!(CuiRegistry::from_snapshot_tsv(&format!(
            "{prov}CATEGORY\tLegal Privilege\tLegal\tlegal-privilege\n"
        ))
        .is_ok());
        // missing a provenance key
        let no_hash = "# source_url=u\n# extraction_date=d\n# current_as_of=c\nLDC\tNOFORN\n";
        assert_eq!(
            CuiRegistry::from_snapshot_tsv(no_hash),
            Err(RegistryError::MissingProvenance("content_hash".into()))
        );
        // malformed PROVENANCE row (no '=') → MalformedRow at its 1-based line
        // (pins the `i + 1` line number: a `*` mutant would report line 1)
        assert_eq!(
            CuiRegistry::from_snapshot_tsv("# source_url=u\n# noequals\n"),
            Err(RegistryError::MalformedRow(2))
        );
        // empty-name CATEGORY row → MalformedRow (exercises the name guard)
        assert_eq!(
            CuiRegistry::from_snapshot_tsv(&format!("{prov}CATEGORY\t\tLegal\tslug\n")),
            Err(RegistryError::MalformedRow(5))
        );
        // malformed data row (wrong field count) → MalformedRow at line 5
        // (pins the data-row `i + 1`)
        assert_eq!(
            CuiRegistry::from_snapshot_tsv(&format!("{prov}LDC\n")),
            Err(RegistryError::MalformedRow(5))
        );
        // fully empty input → missing provenance
        assert!(matches!(
            CuiRegistry::from_snapshot_tsv(""),
            Err(RegistryError::MissingProvenance(_))
        ));
    }
}
