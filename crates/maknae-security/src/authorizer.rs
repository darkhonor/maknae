//! The seam itself: the object-safe `Authorizer` trait (spec §13).
//!
//! Object-safe by construction (no generic methods, no `Self`-returning
//! methods). The kernel today threads a concrete `Arc<P: Authorizer>` through
//! its generic call path (#77); object safety keeps `Box<dyn Authorizer>`
//! available for the composed multi-backend (DCS) build.

use crate::request::Request;
use crate::verdict::Verdict;

/// One role and the member identities bound to it, as a backend reports them.
///
/// Strings, deliberately: the seam stays policy-agnostic (ADR-0004), and how a
/// backend spells an identity is its own business. The kernel renders; it does
/// not interpret.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SubjectBinding {
    pub role: String,
    pub members: Vec<String>,
}

/// A policy decision point. Total: always returns a `Verdict`, never panics.
pub trait Authorizer {
    fn decide(&self, req: &Request) -> Verdict;

    /// The bindings this PDP would resolve **right now**, for
    /// `admin.subject.list`.
    ///
    /// Live, not a snapshot, and that is the whole reason this is on the seam
    /// rather than computed at boot like the config view. Bindings are re-read
    /// per request by design — a containment edit bites on the next request —
    /// so a boot snapshot would report bindings the PDP is no longer using.
    /// Disclosing stale authorization state is worse than disclosing none.
    ///
    /// `None` means this backend cannot enumerate, which the kernel reports as
    /// unavailable — never as "no bindings", which is a different and
    /// dangerous claim. Defaulted so a backend need not implement it.
    fn subjects(&self) -> Option<Vec<SubjectBinding>> {
        None
    }

    /// A short identifier for this backend, for `admin.status`.
    ///
    /// `String`, not `&'static str`, so a COMPOSED authorizer can name the
    /// operands it actually consulted. The whole justification for disclosing
    /// this field is that an operator debugging a verdict needs to know WHICH
    /// PDP produced it — and under the composed multi-backend build that is
    /// several, whose names are not known until construction.
    ///
    /// Defaulted rather than required: a backend that does not name itself
    /// reports `unknown`, which is honest.
    fn backend_name(&self) -> String {
        "unknown".to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::request::{Action, Context, Request, Resource, Subject};
    use crate::value::Attributes;

    /// The DEFAULTS themselves. A backend that implements only `decide` must
    /// get `None` and `unknown` -- and the values matter, not just the fact
    /// that a default exists.
    ///
    /// `None` specifically, never `Some(vec![])`: the kernel renders an empty
    /// list as "these are the bindings, and there are none", which is a claim
    /// about authorization state. A backend that cannot enumerate has not made
    /// that claim. Mutating the default to `Some(vec![])` turns "I cannot tell
    /// you" into "nobody is bound", which is exactly the wrong direction to
    /// fail, so the distinction is asserted rather than assumed.
    #[test]
    fn seam_defaults_are_cannot_enumerate_and_unknown() {
        struct OnlyDecides;
        impl Authorizer for OnlyDecides {
            fn decide(&self, _: &Request) -> Verdict {
                Verdict::NotApplicable
            }
        }
        assert_eq!(
            OnlyDecides.subjects(),
            None,
            "the default must be `cannot enumerate`, NOT an empty list"
        );
        assert_eq!(OnlyDecides.backend_name(), "unknown");
        assert!(
            !OnlyDecides.backend_name().is_empty(),
            "an empty name is not an honest answer"
        );
    }

    struct Always(Verdict);
    impl Authorizer for Always {
        fn decide(&self, _r: &Request) -> Verdict {
            self.0.clone()
        }
    }

    fn req() -> Request {
        Request {
            subject: Subject(Attributes::new()),
            resource: Resource(Attributes::new()),
            action: Action("x".into()),
            context: Context(Attributes::new()),
        }
    }

    #[test]
    fn trait_is_object_safe() {
        // The `Box<dyn Authorizer>` coercion compiling *is* the object-safety proof.
        let b: Box<dyn Authorizer> = Box::new(Always(Verdict::NotApplicable));
        assert_eq!(b.decide(&req()), Verdict::NotApplicable);
    }
}
