//! Typed attribute values and the opaque attribute bag (spec §4).
//!
//! The seam defines the *container*, never the *vocabulary*: keys are general
//! strings, values a small typed enum. Backends supply meaning. Absent-vs-
//! wrong-type both return `None` from the typed accessors; distinguishing a
//! *missing* attribute from a *false* match is the backend matcher's job
//! (spec §15.1 matcher invariant), not this layer's.

use std::collections::{BTreeMap, BTreeSet};

/// A typed attribute value. `BTreeSet` (not `HashSet`) keeps ordering
/// deterministic for reproducible golden vectors and mutation runs.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AttrValue {
    Str(String),
    Int(i64),
    Bool(bool),
    Set(BTreeSet<String>),
}

/// An opaque bag of typed attributes. Deterministic ordering via `BTreeMap`.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Attributes(BTreeMap<String, AttrValue>);

impl Attributes {
    pub fn new() -> Self {
        Self(BTreeMap::new())
    }

    pub fn insert(&mut self, k: impl Into<String>, v: AttrValue) {
        self.0.insert(k.into(), v);
    }

    pub fn get(&self, k: &str) -> Option<&AttrValue> {
        self.0.get(k)
    }

    /// The string value at `k`, or `None` if absent or not a `Str`.
    pub fn str(&self, k: &str) -> Option<&str> {
        match self.0.get(k) {
            Some(AttrValue::Str(s)) => Some(s.as_str()),
            _ => None,
        }
    }

    /// The set value at `k`, or `None` if absent or not a `Set`.
    pub fn set_of(&self, k: &str) -> Option<&BTreeSet<String>> {
        match self.0.get(k) {
            Some(AttrValue::Set(s)) => Some(s),
            _ => None,
        }
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn typed_accessors_return_none_on_type_mismatch() {
        let mut a = Attributes::new();
        a.insert("host", AttrValue::Str("api.weather.gov".into()));
        assert_eq!(a.str("host"), Some("api.weather.gov"));
        assert_eq!(a.str("missing"), None); // absent
        a.insert("port", AttrValue::Int(443));
        assert_eq!(a.str("port"), None); // present but wrong type
    }

    #[test]
    fn get_set_and_emptiness() {
        let mut a = Attributes::new();
        assert!(a.is_empty());
        let mut s = BTreeSet::new();
        s.insert("USA".to_string());
        a.insert("rel", AttrValue::Set(s));
        assert!(!a.is_empty());
        assert!(matches!(a.get("rel"), Some(AttrValue::Set(_))));
        assert!(a.get("nope").is_none());
        assert_eq!(a.set_of("rel").map(|s| s.len()), Some(1));
        assert_eq!(a.set_of("missing"), None); // absent
        let mut b = Attributes::new();
        b.insert("flag", AttrValue::Bool(true));
        assert_eq!(b.set_of("flag"), None); // wrong type
    }
}
