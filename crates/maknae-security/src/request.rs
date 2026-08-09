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
