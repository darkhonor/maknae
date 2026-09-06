//! The classification-system seam (ADR-0022): how markings RANK within one
//! declared system. Level and sensitivity only — never the lattice.
//!
//! Sits beside [`crate::Authorizer`] for the same reason that trait exists
//! (ADR-0004): where a real substitution axis exists, a stable contract with
//! swappable implementations behind it. The kernel ships the US system
//! (`maknae_config::BasicPolicy`); `maknae-classification-aus` ships PSPF;
//! `rust-dcs` brings SPIF-backed systems and the lattice — all through this
//! one contract, which speaks general security, not DCS vocabulary (rust-dcs's
//! own optionality rule: *"or the optionality is fake"*).
//!
//! **What a policy may answer:** which level a marking's first token names in
//! THIS system; the system's default for unmarked content; whether one level
//! is at or below another within THIS system; whether a marking is non-public.
//! **What it may never answer:** anything after the first `//` (caveats,
//! releasability, compartments), an ordering across systems, or a lattice. A
//! cross-system pair is `None`, and the kernel refuses on `None`.

/// One classification level, in ONE system. `rank` is the level's position in
/// that system's ladder (lowest first) and is meaningful only against a `Level`
/// of the same `policy` — which [`ClassificationPolicy::dominates`] enforces.
///
/// The shape is `rust-dcs`'s `Classification { policy, name }` plus the rank,
/// deliberately, so the seam speaks the same language when DCS arrives.
///
/// No `Default`: a defaulted level would be a level in no system.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Level {
    /// The system this level belongs to (`"US"`, `"AUS"`, a SPIF's policy id).
    pub policy: String,
    /// The canonical (upper-case) name of the level in that system.
    pub name: String,
    /// Position in the system's ladder, lowest first.
    pub rank: usize,
}

/// One classification SYSTEM. Total: every method answers for every input;
/// `None` is an answer ("not this system's"), never a panic.
///
/// **MUST NOT perform I/O, and MUST NOT block** — the kernel calls these
/// inline on a request path. A policy's data is fixed at construction.
pub trait ClassificationPolicy: Send + Sync {
    /// The system's name: what `core.handling.policy` names to select it.
    fn name(&self) -> &str;

    /// The level a marking carries in THIS system, or `None` if the marking's
    /// first token is not one of this system's levels — a malformed marking,
    /// or another system's. Implementations read the FIRST token of a banner
    /// and treat everything after the first `//` as opaque.
    fn level_of(&self, marking: &str) -> Option<Level>;

    /// The level unmarked content carries in this system (US: `UNCLASSIFIED`;
    /// AUS PSPF: `UNOFFICIAL`). Operator ruling 2026-09-06: unmarked content
    /// is the default level, at or below every ceiling, and flows.
    fn unmarked(&self) -> Level;

    /// Is `content` at or below `ceiling`? `None` when the two are not both
    /// this system's levels — the kernel refuses on `None`; equivalence across
    /// systems is `rust-dcs`'s, never this seam's.
    fn dominates(&self, ceiling: &Level, content: &Level) -> Option<bool>;

    /// Does this marking carry a non-public marker in this system (US: `CUI`
    /// as the first token, `FOUO`/`SBU`/`CUI` as a caveat segment, or a
    /// distribution statement other than A anywhere; AUS: `OFFICIAL:
    /// Sensitive`)? One switch, governed by `cui_permitted` on a ceiling
    /// (ADR-0022 decision 6). A flag, not a level. *(Corrected 2026-09-06,
    /// critical-review round 1: the earlier text listed bare `FOUO` as a US
    /// marker; a bare legacy `FOUO`/`SBU` first token is NOT a level and is
    /// refused as unrankable. Operator ruling 2026-09-06: REFUSE -- `FOUO`
    /// as a first token was never legal; `CUI` is the authorized first-token
    /// state, which is why only it is aliased.)*
    fn non_public(&self, marking: &str) -> bool;
}

/// The first token of a marking: everything before the first `//`, trimmed.
/// Shared by implementations so "first token" means one thing across systems.
pub fn first_token(marking: &str) -> &str {
    marking.split("//").next().unwrap_or("").trim()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn first_token_stops_at_the_first_double_slash_and_trims() {
        assert_eq!(first_token("SECRET//NOFORN"), "SECRET");
        assert_eq!(
            first_token("  TOP SECRET//SI//REL TO USA, FVEY "),
            "TOP SECRET"
        );
        assert_eq!(
            first_token("OFFICIAL: Sensitive//AUSTEO"),
            "OFFICIAL: Sensitive"
        );
        assert_eq!(first_token("UNCLASSIFIED"), "UNCLASSIFIED");
        assert_eq!(first_token(""), "");
        assert_eq!(
            first_token("//NOFORN"),
            "",
            "a marking that is only caveats has no level"
        );
    }

    /// The trait is object-safe and total by construction: a minimal
    /// implementation compiles as `Box<dyn ClassificationPolicy>` and every
    /// method answers.
    #[test]
    fn the_seam_is_object_safe() {
        struct One;
        impl ClassificationPolicy for One {
            fn name(&self) -> &str {
                "ONE"
            }
            fn level_of(&self, marking: &str) -> Option<Level> {
                (first_token(marking) == "L").then(|| self.unmarked())
            }
            fn unmarked(&self) -> Level {
                Level {
                    policy: "ONE".into(),
                    name: "L".into(),
                    rank: 0,
                }
            }
            fn dominates(&self, c: &Level, x: &Level) -> Option<bool> {
                (c.policy == "ONE" && x.policy == "ONE").then_some(x.rank <= c.rank)
            }
            fn non_public(&self, _: &str) -> bool {
                false
            }
        }
        let p: Box<dyn ClassificationPolicy> = Box::new(One);
        assert_eq!(p.name(), "ONE");
        assert_eq!(p.level_of("L//X"), Some(p.unmarked()));
        assert_eq!(p.level_of("Z"), None);
        assert_eq!(p.dominates(&p.unmarked(), &p.unmarked()), Some(true));
        assert!(
            !p.non_public("L//X"),
            "every method answers through the object"
        );
    }
}
