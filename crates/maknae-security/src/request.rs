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

/// The resource attribute carrying the OPERATING SYSTEM'S ANSWER on whether this
/// subject may access this object.
///
/// **The answer, never the raw bits.** Owner, mode and gid are deliberately NOT put on
/// the request for a backend to recompute: ACLs, supplementary groups, SELinux and
/// AppArmor make a hand-rolled mode calculation non-equivalent to what the kernel
/// decides, so the kernel is asked and its verdict is stamped (ADR-0009 decision 1).
/// Absent on the local lane means UNKNOWN and denies; absent on the remote lane means
/// structurally inapplicable — which is why the lane must be read first.
pub const RESOURCE_OS_ACCESSIBLE: &str = "os_accessible";

/// The resource attribute carrying the CONTENT'S CLASSIFICATION MARKING, as a
/// string. Its FIRST token (everything before the first `//`) is ranked by the
/// classification system the enclave selected (`ClassificationPolicy::level_of`
/// is the one normalizer: case-insensitive, separators not normalized); what
/// follows `//` -- caveats, compartments, releasability -- is opaque to the
/// kernel's ceiling operand and belongs to the external DCS library.
///
/// Defined HERE, beside [`RESOURCE_OS_ACCESSIBLE`] and [`CONTEXT_DAC_LANE`], for
/// the same reason those are: a key whose spelling can drift between the writer
/// and the reader is a decision that silently stops being made.
///
/// **Absent means the system's lowest level** (operator ruling 2026-09-06,
/// #148; US `UNCLASSIFIED`, AUS `UNOFFICIAL`): unmarked content is the default
/// level, at or below every ceiling, and flows. Absent is a legitimate,
/// evaluated state, never a silent pass-through -- and never a refusal.
///
/// **The value's CONTRACT, for the writer this key waits for:** a marking of
/// the ENCLAVE'S OWN system whose first token is one of that system's level
/// names (`SECRET//NOFORN` ranks as SECRET; `CUI//SP-PRVCY` as UNCLASSIFIED).
/// A first token the selected system does not carry is refused, unwaivably,
/// under deny-overrides -- naming the compiled-in system that does carry it
/// when one does (ADR-0022 decision 5; the kernel maps nothing between
/// systems). Stamping the marking is the WRITER's job (`rust-dcs`'s
/// `dcs-label` where DCS is installed; #229 otherwise). Nothing populates the
/// key yet.
///
/// **Provenance rule for that writer:** stamped by the trust plane from the
/// OBJECT's own label (a SPIF marking, a filesystem attribute the kernel read),
/// **never from a request attribute a client can supply.** The risk is a
/// client-supplied DOWNGRADE: a marking at or below the ceiling is an abstention,
/// so a client that could write `UNCLASSIFIED` over `TOP SECRET` would remove a
/// mandatory refusal -- the inform-but-not-authorize inversion AGENTS.md
/// principle 2 forbids.
pub const RESOURCE_CLASSIFICATION: &str = "classification";

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
