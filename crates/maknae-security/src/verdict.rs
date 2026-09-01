//! The four-valued internal verdict, the binary public decision, and the
//! fail-closed finalize (spec §3, §13).
//!
//! `Verdict` is XACML in *shape* only — the combining semantics (spec §13,
//! [`crate::combine`]) are deliberately stronger (indeterminate blocks). The
//! public `decide()` boundary collapses any non-`Permit` to `Deny` via
//! [`finalize`].

use crate::obligation::Obligation;

/// The internal four-valued verdict. `Default` is the fail-closed identity
/// `NotApplicable` (which `finalize` maps to `Deny`) — a defaulted verdict is
/// never a fail-open. Making `Default` production (not test-only) also lets
/// `cargo-mutants` generate viable `-> Default::default()` mutants for
/// `combine`/`decide`, so the fail-closed core is actually mutation-exercised.
/// (`Default` is hand-written below — `#[default]` is unit-variants-only and
/// `NotApplicable` now carries its note — but the rationale above is unchanged
/// and the impl exists for exactly those reasons.)
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Verdict {
    Permit {
        obligations: Vec<Obligation>,
    },
    Deny {
        reason: String,
    },
    /// An absence — this operand has no rule for the request. The optional
    /// `note` is TESTIMONY the operand may volunteer about WHY it abstained
    /// (audit-only; #181, ADR-0008 amendment): it is never an input to
    /// composition — `combine` classifies an annotated absence identically to
    /// a bare one — and it never reaches the wire, which stays the static
    /// `Unauthorized`. `None` composes and renders exactly as the historical
    /// bare variant did. Notes carry role/term tokens only, never paths.
    NotApplicable {
        note: Option<String>,
    },
    Indeterminate,
}

impl Default for Verdict {
    fn default() -> Self {
        Verdict::NotApplicable { note: None }
    }
}

/// The binary public decision. `Default` is `Deny` (fail-closed); its variants
/// carry fields, so it cannot be a `#[default]`-derive and is written by hand.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Decision {
    Permit { obligations: Vec<Obligation> },
    Deny { reason: String },
}

impl Default for Decision {
    fn default() -> Self {
        Decision::Deny {
            reason: "default (fail-closed)".into(),
        }
    }
}

/// Kernel→PEP boundary: anything that is not a definite `Permit` collapses to
/// `Deny` (fail-closed). Spec §13.
pub fn finalize(v: Verdict) -> Decision {
    match v {
        Verdict::Permit { obligations } => Decision::Permit { obligations },
        Verdict::Deny { reason } => Decision::Deny { reason },
        // An annotated absence renders its testimony as the reason (#181);
        // the bare fallback is the HISTORICAL string, byte-identical — any
        // operand that abstains without speaking produces exactly what every
        // absence produced before notes existed.
        Verdict::NotApplicable { note } => Decision::Deny {
            reason: note.unwrap_or_else(|| "no applicable authorizer (fail-closed)".to_string()),
        },
        Verdict::Indeterminate => Decision::Deny {
            reason: "indeterminate (fail-closed)".into(),
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_are_fail_closed() {
        assert_eq!(Verdict::default(), Verdict::NotApplicable { note: None });
        assert!(matches!(Decision::default(), Decision::Deny { .. }));
    }

    #[test]
    fn finalize_permit_passes_through() {
        match finalize(Verdict::Permit {
            obligations: vec![],
        }) {
            Decision::Permit { obligations } => assert!(obligations.is_empty()),
            _ => panic!("permit lost"),
        }
    }

    #[test]
    fn finalize_notapplicable_denies() {
        // Strengthened from `matches!` (Deny-ness only) to the exact bytes:
        // nothing else in the workspace pins the fallback string, so a
        // fallback-string mutant survived the old shape.
        assert_eq!(
            finalize(Verdict::NotApplicable { note: None }),
            Decision::Deny {
                reason: "no applicable authorizer (fail-closed)".into()
            }
        );
    }

    /// An ANNOTATED absence renders its testimony as the deny reason (#181).
    /// The note is audit-only: it changes what the trail says, never what
    /// composes and never what the wire carries.
    #[test]
    fn finalize_annotated_absence_renders_the_note() {
        assert_eq!(
            finalize(Verdict::NotApplicable {
                note: Some("x".into())
            }),
            Decision::Deny { reason: "x".into() }
        );
    }

    #[test]
    fn finalize_indeterminate_denies() {
        assert!(matches!(
            finalize(Verdict::Indeterminate),
            Decision::Deny { .. }
        ));
    }

    #[test]
    fn finalize_deny_preserves_reason() {
        match finalize(Verdict::Deny {
            reason: "because".into(),
        }) {
            Decision::Deny { reason } => assert_eq!(reason, "because"),
            _ => panic!("deny lost"),
        }
    }
}
