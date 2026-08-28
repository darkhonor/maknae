//! The seam itself: the object-safe `Authorizer` trait (spec §13).
//!
//! Object-safe by construction (no generic methods, no `Self`-returning
//! methods). The kernel today threads a concrete `Arc<P: Authorizer>` through
//! its generic call path (#77); object safety keeps `Box<dyn Authorizer>`
//! available for the composed multi-backend (DCS) build.

use crate::request::Request;
use crate::verdict::Verdict;

/// A policy decision point. Total: always returns a `Verdict`, never panics.
pub trait Authorizer {
    fn decide(&self, req: &Request) -> Verdict;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::request::{Action, Context, Request, Resource, Subject};
    use crate::value::Attributes;

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
