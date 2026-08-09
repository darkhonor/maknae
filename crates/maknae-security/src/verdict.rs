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
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub enum Verdict {
    Permit {
        obligations: Vec<Obligation>,
    },
    Deny {
        reason: String,
    },
    #[default]
    NotApplicable,
    Indeterminate,
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
        Verdict::NotApplicable => Decision::Deny {
            reason: "no applicable authorizer (fail-closed)".into(),
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
        assert_eq!(Verdict::default(), Verdict::NotApplicable);
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
        assert!(matches!(
            finalize(Verdict::NotApplicable),
            Decision::Deny { .. }
        ));
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
