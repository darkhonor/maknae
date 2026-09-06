//! `maknae-classification-aus` — the Australian Government's Protective
//! Security Policy Framework (PSPF) as a [`ClassificationPolicy`] (ADR-0022
//! decision 3): the seam's first non-kernel implementation, in-repo, still on
//! `maknae-authz-basic` and RBAC, aware of a different system's markings.
//!
//! **Authority.** PSPF Release 2025, Australian Attorney-General's Department,
//! as recorded in `darkhonor/rust-dcs`'s `design/references/dcs-schema-migration.md`
//! §13.1 ("Australia — Protective Security Policy Framework"). Post-2018
//! reform: CONFIDENTIAL and RESTRICTED were REMOVED, leaving the ladder
//!
//! ```text
//!   UNOFFICIAL < OFFICIAL < OFFICIAL: Sensitive < PROTECTED < SECRET < TOP SECRET
//! ```
//!
//! `OFFICIAL: Sensitive` is the CUI-equivalent — the non-public marker.
//! `AUSTEO` (Australian Eyes Only) and `AGAO` (Australian Government Access
//! Only) are national caveats: they appear after the `//` and are OPAQUE here.
//!
//! **What this crate does not do, by the ADR's line:** map PSPF levels onto
//! US ones (`PROTECTED ≈ CONFIDENTIAL` is treaty data and lives in rust-dcs's
//! §13.1 table, not here), interpret caveats, or hold a lattice. Other foreign
//! systems (ROK, …) are separate crates, each when its authority is in hand.
#![forbid(unsafe_code)]

use maknae_security::{first_token, ClassificationPolicy, Level};

/// The system's name, as `core.handling.policy` selects it.
pub const NAME: &str = "AUS";

/// The PSPF ladder, lowest first. Canonical spellings; matching is
/// case-insensitive (the same rule the US system applies), separators are
/// not normalized (`OFFICIAL:Sensitive` without the space is NOT recognized —
/// the PSPF's own spelling carries the space).
pub const LEVELS: [&str; 6] = [
    "UNOFFICIAL",
    "OFFICIAL",
    "OFFICIAL: SENSITIVE",
    "PROTECTED",
    "SECRET",
    "TOP SECRET",
];

/// The PSPF system.
///
/// A unit value IS the constructor. No `new()` (clippy would then demand a
/// `Default`), and no `Default`: a `Default` on a type returned by a mutated
/// function makes its mutants equivalent-and-unkillable.
#[derive(Debug, Clone, Copy)]
pub struct AusPspf;

impl AusPspf {
    /// Is `l` exactly one of this system's levels (tag, rank AND name agree)?
    fn is_level(&self, l: &Level) -> bool {
        l.policy == NAME
            && LEVELS
                .get(l.rank)
                .is_some_and(|n| n.eq_ignore_ascii_case(&l.name))
    }

    fn level(&self, rank: usize) -> Level {
        Level {
            policy: NAME.into(),
            name: LEVELS[rank].into(),
            rank,
        }
    }
}

impl ClassificationPolicy for AusPspf {
    fn name(&self) -> &str {
        NAME
    }

    fn level_of(&self, marking: &str) -> Option<Level> {
        let token = first_token(marking);
        LEVELS
            .iter()
            .position(|l| l.eq_ignore_ascii_case(token))
            .map(|rank| self.level(rank))
    }

    fn unmarked(&self) -> Level {
        self.level(0)
    }

    fn dominates(&self, ceiling: &Level, content: &Level) -> Option<bool> {
        // BOTH must be levels of THIS system -- name AND rank, not just the
        // policy tag: `Level`'s fields are public, and a forged
        // `{policy: NAME, rank: 99}` would otherwise dominate everything.
        if !self.is_level(ceiling) || !self.is_level(content) {
            return None;
        }
        Some(content.rank <= ceiling.rank)
    }

    /// `OFFICIAL: Sensitive` is the PSPF's non-public marker (rust-dcs §13.1:
    /// "CUI / SBU" equivalent). Read from the FIRST token only: the marker is
    /// a level in this system, not a caveat.
    fn non_public(&self, marking: &str) -> bool {
        first_token(marking).eq_ignore_ascii_case("OFFICIAL: SENSITIVE")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn p() -> AusPspf {
        AusPspf
    }

    #[test]
    fn the_ladder_is_the_post_2018_pspf_and_carries_its_name() {
        assert_eq!(p().name(), "AUS");
        assert_eq!(LEVELS.len(), 6);
        // The 2018 reform: no CONFIDENTIAL, no RESTRICTED.
        assert!(p().level_of("CONFIDENTIAL").is_none());
        assert!(p().level_of("RESTRICTED").is_none());
        for (rank, name) in LEVELS.iter().enumerate() {
            let l = p().level_of(name).unwrap();
            assert_eq!(
                (l.policy.as_str(), l.name.as_str(), l.rank),
                ("AUS", *name, rank)
            );
        }
    }

    #[test]
    fn unmarked_is_unofficial_the_lowest_rung() {
        let u = p().unmarked();
        assert_eq!((u.name.as_str(), u.rank), ("UNOFFICIAL", 0));
        for name in LEVELS {
            assert_eq!(
                p().dominates(&p().level_of(name).unwrap(), &u),
                Some(true),
                "{name}"
            );
        }
    }

    /// Every (ceiling, content) pair over the six-rung ladder: at-or-below
    /// flows, above refuses. Kills the `<=` mutants on the whole matrix.
    #[test]
    fn the_full_six_by_six_dominance_matrix() {
        for (ci, c) in LEVELS.iter().enumerate() {
            for (xi, x) in LEVELS.iter().enumerate() {
                let want = xi <= ci;
                assert_eq!(
                    p().dominates(&p().level_of(c).unwrap(), &p().level_of(x).unwrap()),
                    Some(want),
                    "content {x} under ceiling {c}"
                );
            }
        }
    }

    #[test]
    fn markings_are_read_by_first_token_case_insensitively_with_caveats_opaque() {
        for (raw, want) in [
            ("PROTECTED//AUSTEO", "PROTECTED"),
            ("protected", "PROTECTED"),
            ("Official: Sensitive//AGAO", "OFFICIAL: SENSITIVE"),
            ("TOP SECRET//AUSTEO//REL TO AUS, USA", "TOP SECRET"),
            ("  unofficial  ", "UNOFFICIAL"),
        ] {
            assert_eq!(p().level_of(raw).unwrap().name, want, "{raw}");
        }
        // Separators are not normalized; another system's level is not ours.
        for bad in [
            "OFFICIAL:Sensitive",
            "TOP_SECRET",
            "UNCLASSIFIED",
            "SEKRET",
            "",
            "//AUSTEO",
        ] {
            assert!(p().level_of(bad).is_none(), "{bad:?}");
        }
    }

    #[test]
    fn cross_system_levels_are_none_never_ordered() {
        let us = Level {
            policy: "US".into(),
            name: "SECRET".into(),
            rank: 2,
        };
        let aus = p().level_of("SECRET").unwrap();
        assert_eq!(p().dominates(&aus, &us), None);
        assert_eq!(p().dominates(&us, &aus), None);
        assert_eq!(
            p().dominates(&us, &us),
            None,
            "two US levels are not this system's to order"
        );
    }

    #[test]
    fn official_sensitive_is_the_non_public_marker_and_nothing_else_is() {
        assert!(p().non_public("OFFICIAL: Sensitive"));
        assert!(p().non_public("official: sensitive//AGAO"));
        for not in [
            "OFFICIAL",
            "UNOFFICIAL",
            "PROTECTED",
            "SECRET//AUSTEO",
            "OFFICIAL:Sensitive",
            "",
        ] {
            assert!(!p().non_public(not), "{not:?}");
        }
    }

    #[test]
    fn the_policy_is_usable_as_a_trait_object() {
        let b: Box<dyn ClassificationPolicy> = Box::new(p());
        assert_eq!(b.name(), "AUS");
        assert_eq!(b.level_of("PROTECTED").unwrap().rank, 3);
    }
    /// `Level`'s fields are public. A level that carries this system's TAG but
    /// a rank/name this ladder does not have -- or a foreign tag with a rank
    /// this ladder does have -- is NOT a level of this system: `dominates` is
    /// `None`, never a verdict. (Kills the `&&`->`||` mutant in `is_level`.)
    #[test]
    fn a_forged_level_is_not_ordered() {
        let real = p().level_of("PROTECTED").unwrap();
        let forged_rank = Level {
            policy: NAME.into(),
            name: real.name.clone(),
            rank: 99,
        };
        let forged_name = Level {
            policy: NAME.into(),
            name: "BOGUS".into(),
            rank: real.rank,
        };
        let foreign_tag = Level {
            policy: "US".into(),
            name: real.name.clone(),
            rank: real.rank,
        };
        for bad in [&forged_rank, &forged_name, &foreign_tag] {
            assert_eq!(p().dominates(&real, bad), None, "{bad:?} as content");
            assert_eq!(p().dominates(bad, &real), None, "{bad:?} as ceiling");
        }
        assert_eq!(p().dominates(&real, &real), Some(true));
    }
}
