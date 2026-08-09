//! The owned configuration value tree (spec §3).
//!
//! `maknae-config` exposes its *own* `Value`, converting from `yaml_rust2::Yaml`
//! internally — so only this crate depends on `yaml-rust2` and the parser is
//! swappable without leaking into downstream signatures.

/// An owned, insertion-ordered YAML value. `Map` keys are strings by
/// construction (§4); `PartialEq` only (not `Eq`) because of `f64`.
#[derive(Clone, Debug, PartialEq)]
pub enum Value {
    Null,
    Bool(bool),
    Int(i64),
    Float(f64),
    Str(String),
    Seq(Vec<Value>),
    Map(Vec<(String, Value)>),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn map_is_insertion_ordered() {
        let m = Value::Map(vec![
            ("b".into(), Value::Int(2)),
            ("a".into(), Value::Int(1)),
        ]);
        if let Value::Map(e) = m {
            assert_eq!(e[0].0, "b");
            assert_eq!(e[1].0, "a");
        } else {
            panic!("not a map");
        }
    }
}
