//! The compiled, versioned world-view registries (#26): the accessors over the
//! `data/*.json` sources that `build.rs` compiles into the binary (source-only;
//! the air-gapped engine never fetches at decide-time). Three sources:
//!
//! - ISO 3166-1 alpha-3 nations (`is_iso3166`) — the national world view;
//! - coalition tetragraphs (`expand_coalition`) — in-memory expand-or-deny;
//! - the full DoD CUI Registry (`is_cui_category`) — recognition by
//!   `category_marking` (the rest of each category is inert provenance).
//!
//! Every table is emitted SORTED, so each accessor is a `binary_search`, and a
//! malformed source FAILS THE BUILD (fail-closed — a bad registry never ships).

// The versioned `data/*.json` registries, compiled into the binary by build.rs.
// Generates `pub static ISO3166 / COALITIONS / CUI_CATEGORIES` (all sorted).
include!(concat!(env!("OUT_DIR"), "/registries.rs"));

/// Is `token` a code in the ISO 3166-1 alpha-3 world view? This is the
/// *recognition* check (#26): a structurally-valid trigraph that is not a real
/// country is `InvalidElement`. Unknown → `false` (fail closed). `ISO3166` is
/// emitted sorted, so this is a binary search.
pub fn is_iso3166(token: &str) -> bool {
    ISO3166.binary_search(&token).is_ok()
}

/// The member nation trigraphs of a coalition tetragraph, or `None` if the
/// tetragraph is not registered (#26 expand-or-deny: an unregistered coalition
/// grants nothing → the caller denies). Membership is a GLOBAL, versioned data
/// fact (not policy-context-dependent). `COALITIONS` is emitted sorted by
/// tetragraph, so this is a binary search; every member was cross-validated
/// against `ISO3166` at build time.
pub fn expand_coalition(token: &str) -> Option<&'static [&'static str]> {
    COALITIONS
        .binary_search_by(|(k, _)| (*k).cmp(token))
        .ok()
        .map(|i| COALITIONS[i].1)
}

/// Is `marking` a published DoD CUI Registry `category_marking`? Recognition
/// only (#26 consumes just the marking; the banner/authorities/description each
/// category carries are inert provenance). Unknown → `false` (fail closed).
/// `CUI_CATEGORIES` is emitted sorted + deduped, so this is a binary search.
pub fn is_cui_category(marking: &str) -> bool {
    CUI_CATEGORIES.binary_search(&marking).is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cui_registry_recognizes_a_known_category() {
        assert!(is_cui_category("ISVI")); // Information Systems Vulnerability Information
        assert!(!is_cui_category("NOTACUI"));
    }
}
