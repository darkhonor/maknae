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
    List(Vec<String>),
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

    /// The list value at `k`, or `None` if absent or not a `List`.
    pub fn list(&self, k: &str) -> Option<&[String]> {
        match self.0.get(k) {
            Some(AttrValue::List(l)) => Some(l.as_slice()),
            _ => None,
        }
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    pub fn iter(&self) -> impl Iterator<Item = (&str, &AttrValue)> {
        self.0.iter().map(|(k, v)| (k.as_str(), v))
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

    #[test]
    fn iter_yields_every_pair_in_key_order() {
        let mut a = Attributes::new();
        a.insert("b", AttrValue::Int(2));
        a.insert("a", AttrValue::Str("x".into()));
        let pairs: Vec<(&str, &AttrValue)> = a.iter().collect();
        assert_eq!(
            pairs,
            [
                ("a", &AttrValue::Str("x".into())),
                ("b", &AttrValue::Int(2))
            ]
        );
        assert_eq!(Attributes::new().iter().count(), 0);
    }

    #[test]
    fn list_preserves_order() {
        let mut a = Attributes::new();
        let v = vec!["b".to_string(), "a".to_string(), "b".to_string()];
        a.insert("tool.argv", AttrValue::List(v.clone()));
        assert_eq!(a.list("tool.argv"), Some(v.as_slice()));
    }

    #[test]
    fn list_accessor_is_none_for_other_variants() {
        let mut a = Attributes::new();
        a.insert("s", AttrValue::Str("x".into()));
        a.insert("set", AttrValue::Set(BTreeSet::new()));
        assert_eq!(a.list("s"), None);
        assert_eq!(a.list("set"), None);
        assert_eq!(a.list("missing"), None);
        a.insert("l", AttrValue::List(vec![]));
        assert_eq!(a.str("l"), None);
        assert_eq!(a.set_of("l"), None);
        assert_eq!(a.list("l"), Some(&[][..]));
    }

    #[test]
    fn list_equality_is_order_sensitive() {
        let ab = AttrValue::List(vec!["a".into(), "b".into()]);
        let ba = AttrValue::List(vec!["b".into(), "a".into()]);
        assert_ne!(ab, ba);
        assert_eq!(ab, ab.clone());
    }
}
