//! The authorization request: subject / resource / action / context (spec §3, §4).
//!
//! Named `Action` per spec §12. §4 lists action as an attribute bag, but the
//! load-bearing part is the name (the grammar's `action(specifier)`); §4 is
//! revisable, so action is modelled as a newtype name here — any action
//! attributes ride in `context`.

use crate::value::Attributes;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Subject(pub Attributes);

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Resource(pub Attributes);

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Action(pub String);

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Context(pub Attributes);

/// The context attribute naming which boundary a request arrived on.
///
/// Defined HERE, in the seam both sides depend on, rather than as a literal in the
/// kernel and a `const` in each backend. A key whose spelling can drift between the
/// writer and the reader is a decision that silently stops being made — and this
/// particular key is what separates "unknown, so deny" from "not applicable, so
/// abstain" (ADR-0009 decision 8).
pub const CONTEXT_DAC_LANE: &str = "dac_lane";

/// Which boundary a request arrived on.
///
/// **Derived from the accepting listener and from nothing else.** Never from a request
/// field, a header, or a session claim — anything that lets a local request present as
/// remote escapes OS DAC entirely, which ADR-0009 calls the single most important
/// control in its design. It is an argument to request construction precisely so there
/// is no code path by which client-supplied content could reach it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Lane {
    /// The on-host client plane: the subject is a `SO_PEERCRED` uid on this machine,
    /// so OS DAC is meaningful and can be asked (ADR-0006 decision 4).
    Local,
    /// Through the gateway: the subject is an OIDC principal with no uid, no process,
    /// and no descriptors on this host (ADR-0006 decisions 5 and 7). OS DAC is
    /// structurally inapplicable — which is NOT the same as unknown.
    Remote,
}

impl Lane {
    /// The stamped value. Closed vocabulary: a backend that does not recognise the
    /// string must fail closed rather than treat it as absent.
    pub fn as_str(self) -> &'static str {
        match self {
            Lane::Local => "local",
            Lane::Remote => "remote",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Request {
    pub subject: Subject,
    pub resource: Resource,
    pub action: Action,
    pub context: Context,
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The lane vocabulary is a CLOSED set whose two members mean opposite things to
    /// a backend: on `local` an absent `os_accessible` is unknown and denies; on
    /// `remote` it is structurally not applicable and the operand abstains (ADR-0009
    /// decision 8). Swap these two strings and every remote request starts being
    /// judged as though the OS could have been asked — so the spelling is asserted,
    /// not assumed.
    #[test]
    fn the_lane_vocabulary_is_pinned_in_both_directions() {
        assert_eq!(Lane::Local.as_str(), "local");
        assert_eq!(Lane::Remote.as_str(), "remote");
        assert_ne!(Lane::Local.as_str(), Lane::Remote.as_str());
        assert_eq!(CONTEXT_DAC_LANE, "dac_lane");
    }

    use crate::value::{AttrValue, Attributes};

    #[test]
    fn request_holds_four_bags_and_action() {
        let mut s = Attributes::new();
        s.insert("id", AttrValue::Str("alex".into()));
        let req = Request {
            subject: Subject(s),
            resource: Resource(Attributes::new()),
            action: Action("egress".into()),
            context: Context(Attributes::new()),
        };
        assert_eq!(req.action.0, "egress");
        assert_eq!(req.subject.0.str("id"), Some("alex"));
    }
}
