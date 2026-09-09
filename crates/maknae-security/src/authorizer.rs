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

    /// The verdict AND the role it was decided on, from the SAME evaluation.
    ///
    /// **Defaulted on purpose.** An operand that does not key on roles — the
    /// mandatory classification ceiling, every test double, any future additive
    /// operand — inherits this unchanged and reports no role, which is honest.
    /// Only the RBAC baseline and the composition override it.
    ///
    /// **Why it exists (#275).** The audit record must carry the role the
    /// decision was MADE ON. The in-repo RBAC operand re-reads its policy file
    /// on every decision, so resolving the role in a second call would both
    /// read twice and open a window in which the file changes between the
    /// decision and the stamp — the record would then attest a role the
    /// decision was not made on. Returning both facts together closes that by
    /// construction.
    ///
    /// **A wrapper that delegates [`Authorizer::decide`] MUST also delegate
    /// this**, or it silently reports no role for a decision that had one.
    ///
    /// `&'static str` because the role vocabulary is fixed and compiled in; the
    /// seam stays policy-agnostic by reporting an opaque token it never
    /// interprets, exactly as [`SubjectBinding`] does.
    fn decide_reporting_role(&self, req: &Request) -> (Verdict, Option<&'static str>) {
        (self.decide(req), None)
    }

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
    ///
    /// **MUST NOT perform I/O, and MUST NOT block.** The kernel calls this
    /// inline on an async worker, unlike [`Authorizer::subjects`], which it
    /// offloads to the blocking pool under a timeout and circuit breaker.
    ///
    /// The asymmetry is deliberate and is a property of the two contracts, not
    /// of the call sites. `subjects` is REQUIRED to be live — bindings are
    /// re-read per request so a containment edit bites on the next one — so
    /// reading a policy file is what implementing it correctly means. A
    /// backend's own NAME is an identifier it already knows; resolving one
    /// from a version file, a `dlopen`'d handle, or an IPC probe would pin a
    /// tokio worker with no timeout and no breaker, which is the failure the
    /// `subjects` offload exists to prevent. Compute the name at construction.
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
                Verdict::NotApplicable { note: None }
            }
        }
        assert_eq!(
            OnlyDecides.subjects(),
            None,
            "the default must be `cannot enumerate`, NOT an empty list"
        );
        assert_eq!(
            OnlyDecides.backend_name(),
            "unknown",
            "a backend that does not name itself says so; an empty string is not \
             an honest answer"
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
    fn an_authorizer_that_does_not_key_on_roles_reports_no_role_by_default() {
        // #275: the default must report the SAME verdict `decide` does, and no
        // role — never an invented one. Every operand that does not key on
        // roles (the classification ceiling, every test double, any future
        // additive operand) inherits exactly this.
        let a = Always(Verdict::Permit {
            obligations: Vec::new(),
        });
        let (v, role) = a.decide_reporting_role(&req());
        assert_eq!(
            v,
            Verdict::Permit {
                obligations: Vec::new()
            }
        );
        assert_eq!(role, None, "the default must never invent a role");
    }

    #[test]
    fn reporting_the_role_keeps_the_trait_object_safe() {
        // The coercion compiling IS the proof; a generic or `Self`-returning
        // method would break `Box<dyn Authorizer>` and the composed build.
        let b: Box<dyn Authorizer> = Box::new(Always(Verdict::Indeterminate));
        let (v, role) = b.decide_reporting_role(&req());
        assert_eq!(v, Verdict::Indeterminate);
        assert_eq!(role, None);
    }

    #[test]
    fn trait_is_object_safe() {
        // The `Box<dyn Authorizer>` coercion compiling *is* the object-safety proof.
        let b: Box<dyn Authorizer> = Box::new(Always(Verdict::NotApplicable { note: None }));
        assert_eq!(b.decide(&req()), Verdict::NotApplicable { note: None });
    }
}
