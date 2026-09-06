//! The US classification system as a [`ClassificationPolicy`] (ADR-0022
//! decision 2) — the kernel's reference implementation, and the config's
//! default vocabulary. Nothing foreign lives here, ever: other systems are
//! their own crates (`maknae-classification-aus`), and the lattice is
//! `rust-dcs`'s.
//!
//! The ladder is the lake's `_ceiling.py` `CLASSIFICATION_ORDER`; matching is
//! case-insensitive (operator ruling 2026-09-06, a stated divergence from that
//! file); separator forms are not normalized (`TOP_SECRET` is not a level).
//! `CUI` is accepted as a FIRST token and reads as `UNCLASSIFIED` + non-public:
//! CUI is unclassified by definition, and a CUI-marked document refused as
//! "malformed" would be the operand refusing the one marking a small business
//! actually uses.

use maknae_security::{first_token, ClassificationPolicy, Level};

/// The system's name, as `core.handling.policy` selects it (and the default).
pub const NAME: &str = "US";

/// The US ladder, lowest first (EO 13526 order).
pub const LEVELS: [&str; 4] = ["UNCLASSIFIED", "CONFIDENTIAL", "SECRET", "TOP SECRET"];

/// The US system. A unit value is the constructor; no `Default` (a `Default`
/// on a type a mutated function returns makes its mutants unkillable).
#[derive(Debug, Clone, Copy)]
pub struct BasicPolicy;

impl BasicPolicy {
    fn level(&self, rank: usize) -> Level {
        Level {
            policy: NAME.into(),
            name: LEVELS[rank].into(),
            rank,
        }
    }
}

impl ClassificationPolicy for BasicPolicy {
    fn name(&self) -> &str {
        NAME
    }

    fn level_of(&self, marking: &str) -> Option<Level> {
        let token = first_token(marking);
        if token.eq_ignore_ascii_case("CUI") {
            return Some(self.level(0));
        }
        LEVELS
            .iter()
            .position(|l| l.eq_ignore_ascii_case(token))
            .map(|rank| self.level(rank))
    }

    fn unmarked(&self) -> Level {
        self.level(0)
    }

    fn dominates(&self, ceiling: &Level, content: &Level) -> Option<bool> {
        if ceiling.policy != NAME || content.policy != NAME {
            return None;
        }
        Some(content.rank <= ceiling.rank)
    }

    /// The US non-public markers: `CUI` as the level token, `FOUO`/`SBU`/`CUI`
    /// as a caveat segment, or a distribution statement other than A anywhere
    /// in the marking. Non-public is read over the WHOLE marking — it is a
    /// flag about handling, not a level, so the first-token rule does not
    /// apply to it.
    fn non_public(&self, marking: &str) -> bool {
        if first_token(marking).eq_ignore_ascii_case("CUI") {
            return true;
        }
        let upper = marking.to_ascii_uppercase();
        if upper
            .split("//")
            .skip(1)
            .any(|seg| matches!(seg.trim(), "FOUO" | "SBU" | "CUI"))
        {
            return true;
        }
        upper
            .split("DISTRIBUTION STATEMENT ")
            .skip(1)
            .any(|rest| matches!(rest.chars().next(), Some('B'..='F')))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn p() -> BasicPolicy {
        BasicPolicy
    }

    #[test]
    fn the_ladder_is_eo_13526_order_and_carries_its_name() {
        assert_eq!(p().name(), "US");
        for (rank, name) in LEVELS.iter().enumerate() {
            let l = p().level_of(name).unwrap();
            assert_eq!(
                (l.policy.as_str(), l.name.as_str(), l.rank),
                ("US", *name, rank)
            );
        }
        assert_eq!(p().unmarked().name, "UNCLASSIFIED");
        assert_eq!(p().unmarked().rank, 0);
    }

    /// Every (ceiling, content) pair: at-or-below flows, above refuses.
    #[test]
    fn the_full_four_by_four_dominance_matrix() {
        for (ci, c) in LEVELS.iter().enumerate() {
            for (xi, x) in LEVELS.iter().enumerate() {
                assert_eq!(
                    p().dominates(&p().level_of(c).unwrap(), &p().level_of(x).unwrap()),
                    Some(xi <= ci),
                    "content {x} under ceiling {c}"
                );
            }
        }
    }

    #[test]
    fn markings_are_read_by_first_token_case_insensitively_with_caveats_opaque() {
        for (raw, want) in [
            ("SECRET//NOFORN", "SECRET"),
            ("secret", "SECRET"),
            ("Top Secret//SI//REL TO USA, FVEY", "TOP SECRET"),
            ("UNCLASSIFIED//FOUO", "UNCLASSIFIED"),
            ("CUI//SP-PRVCY", "UNCLASSIFIED"),
            ("cui", "UNCLASSIFIED"),
            ("  confidential  ", "CONFIDENTIAL"),
        ] {
            assert_eq!(p().level_of(raw).unwrap().name, want, "{raw}");
        }
        for bad in [
            "TOP_SECRET",
            "SEKRET",
            "PROTECTED",
            "OFFICIAL",
            "",
            "//NOFORN",
            " SECRET//",
        ] {
            let r = p().level_of(bad);
            assert!(r.is_none() || bad == " SECRET//", "{bad:?} -> {r:?}");
        }
        assert!(
            p().level_of("TOP_SECRET").is_none(),
            "separators are not normalized"
        );
    }

    #[test]
    fn cross_system_levels_are_none_never_ordered() {
        let aus = Level {
            policy: "AUS".into(),
            name: "PROTECTED".into(),
            rank: 3,
        };
        let us = p().level_of("SECRET").unwrap();
        assert_eq!(p().dominates(&us, &aus), None);
        assert_eq!(p().dominates(&aus, &us), None);
        assert_eq!(p().dominates(&aus, &aus), None);
    }

    #[test]
    fn the_non_public_markers_and_the_public_ones() {
        for np in [
            "CUI",
            "cui//SP-PRVCY",
            "UNCLASSIFIED//FOUO",
            "UNCLASSIFIED//SBU",
            "SECRET//NOFORN//CUI",
            "UNCLASSIFIED - Distribution Statement C applies",
            "distribution statement f",
        ] {
            assert!(p().non_public(np), "{np:?} must be non-public");
        }
        for pub_ in [
            "UNCLASSIFIED",
            "unclassified",
            "SECRET//NOFORN",
            "TOP SECRET//SI",
            "Distribution Statement A",
            "",
            "FOUO",
        ] {
            assert!(
                !p().non_public(pub_),
                "{pub_:?} must be public (FOUO is a caveat, not a first token)"
            );
        }
    }

    #[test]
    fn the_policy_is_usable_as_a_trait_object() {
        let b: Box<dyn ClassificationPolicy> = Box::new(p());
        assert_eq!(b.name(), "US");
        assert_eq!(b.level_of("SECRET").unwrap().rank, 2);
    }
}
