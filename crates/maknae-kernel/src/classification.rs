//! The compiled-in classification systems, keyed by name (ADR-0022 decision 4).
//!
//! `core.handling.policy` names a SYSTEM this build carries — deployment data:
//! which classification system the enclave operates under. It never selects
//! or replaces an implementation: the set below is fixed at build (ADR-0002,
//! static TCB), the kernel's own US system first, and a name this build does
//! not carry refuses boot (`ConfigError::UnknownClassificationPolicy`).
//! `rust-dcs`, when compiled in, registers its SPIF-backed systems through the
//! same table; nothing here changes.

use maknae_classification_aus::AusPspf;
use maknae_config::BasicPolicy;
use maknae_security::{first_token, ClassificationPolicy};

/// Every system this build carries, kernel-shipped US first. Order is not
/// precedence: selection is by NAME, and names are unique (pinned below).
/// A fixed-arity array on purpose: adding a system is a BUILD change (a
/// dependency and an entry here), never a runtime registration -- that is
/// ADR-0002's static TCB, and it is how `rust-dcs` joins too.
static SYSTEMS: [&dyn ClassificationPolicy; 2] = [&BasicPolicy, &AusPspf];

/// The system `name` selects, matched case-insensitively on the trimmed
/// name, or `None` when this build carries no such system.
pub fn select(name: &str) -> Option<&'static dyn ClassificationPolicy> {
    let wanted = name.trim();
    SYSTEMS
        .iter()
        .copied()
        .find(|p| p.name().eq_ignore_ascii_case(wanted))
}

/// The names this build carries, in registry order — for the refusal
/// message and `admin.status`, never for selection.
pub fn names() -> Vec<&'static str> {
    SYSTEMS.iter().map(|p| p.name()).collect()
}

/// Which compiled-in systems recognize `marking`'s first token. A marking the
/// SELECTED system rejects but another carries is a cross-system marking:
/// recognized, and refused with that name (ADR-0022 decision 5) — never
/// mapped. Shared spellings (`SECRET` is a level of both US and AUS) return
/// every system that carries them.
pub fn recognizing(marking: &str) -> Vec<&'static str> {
    let token = first_token(marking);
    SYSTEMS
        .iter()
        .filter(|p| p.level_of(token).is_some())
        .map(|p| p.name())
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_kernel_ships_us_first_and_names_are_unique() {
        let n = names();
        assert_eq!(n, vec!["US", "AUS"]);
        let mut sorted = n.clone();
        sorted.sort_unstable();
        sorted.dedup();
        assert_eq!(
            sorted.len(),
            n.len(),
            "a duplicate name would make selection ambiguous"
        );
    }

    #[test]
    fn selection_is_by_name_case_insensitive_and_trimmed() {
        for (raw, want) in [
            ("US", "US"),
            ("us", "US"),
            (" Us ", "US"),
            ("AUS", "AUS"),
            ("aus", "AUS"),
        ] {
            assert_eq!(select(raw).map(|p| p.name()), Some(want), "{raw:?}");
        }
        for unknown in ["ROK", "UK", "", "U S", "USA", "AUSS"] {
            assert!(
                select(unknown).is_none(),
                "{unknown:?} must not select a system"
            );
        }
    }

    #[test]
    fn the_selected_system_is_the_one_that_ranks() {
        // The same marking, two systems, two answers: PROTECTED is a level of
        // AUS and nothing of US -- the kernel maps nothing between them.
        assert_eq!(select("US").unwrap().level_of("PROTECTED"), None);
        assert_eq!(
            select("AUS").unwrap().level_of("PROTECTED").unwrap().rank,
            3
        );
        assert_eq!(select("US").unwrap().unmarked().name, "UNCLASSIFIED");
        assert_eq!(select("AUS").unwrap().unmarked().name, "UNOFFICIAL");
    }

    #[test]
    fn a_marking_is_recognized_by_every_system_that_carries_its_first_token() {
        assert_eq!(recognizing("PROTECTED//AGAO"), vec!["AUS"]);
        assert_eq!(recognizing("CUI//SP-PRVCY"), vec!["US"]);
        assert_eq!(recognizing("secret//NOFORN"), vec!["US", "AUS"]);
        assert!(recognizing("BOGUS").is_empty());
        assert!(recognizing("").is_empty());
    }
}
