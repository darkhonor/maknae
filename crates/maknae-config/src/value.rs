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

/// JSON with keys sorted bytewise and no insignificant whitespace.
pub fn canonical_json(v: &Value) -> String {
    let mut out = String::new();
    write_canonical(v, &mut out);
    out
}

fn write_canonical(v: &Value, out: &mut String) {
    match v {
        Value::Null => out.push_str("null"),
        Value::Bool(b) => out.push_str(if *b { "true" } else { "false" }),
        Value::Int(n) => out.push_str(&n.to_string()),
        Value::Float(f) => {
            let text = f.to_string();
            let int_shaped = !text.contains(['.', 'e', 'E']);
            out.push_str(&text);
            if int_shaped {
                out.push_str(".0");
            }
        }
        Value::Str(s) => write_json_string(s, out),
        Value::Seq(items) => {
            out.push('[');
            for (i, item) in items.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                write_canonical(item, out);
            }
            out.push(']');
        }
        Value::Map(entries) => {
            let mut sorted: Vec<&(String, Value)> = entries.iter().collect();
            sorted.sort_by(|a, b| a.0.as_bytes().cmp(b.0.as_bytes()));
            out.push('{');
            for (i, (k, v)) in sorted.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                write_json_string(k, out);
                out.push(':');
                write_canonical(v, out);
            }
            out.push('}');
        }
    }
}

fn write_json_string(s: &str, out: &mut String) {
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out.push('"');
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

    #[test]
    fn canonical_json_sorts_keys_escapes_strings_and_has_no_whitespace() {
        let v = Value::Map(vec![
            (
                "b".into(),
                Value::Seq(vec![Value::Int(1), Value::Null, Value::Bool(true)]),
            ),
            ("a".into(), Value::Str("q\"\\\n\u{1}é".into())),
            (
                "c".into(),
                Value::Map(vec![
                    ("z".into(), Value::Int(-7)),
                    ("y".into(), Value::Float(1.5)),
                ]),
            ),
        ]);
        assert_eq!(
            canonical_json(&v),
            r#"{"a":"q\"\\\n\u0001é","b":[1,null,true],"c":{"y":1.5,"z":-7}}"#
        );
        assert_eq!(canonical_json(&Value::Map(vec![])), "{}");
        assert_eq!(canonical_json(&Value::Seq(vec![])), "[]");
    }

    #[test]
    fn canonical_json_escapes_every_control_character_and_nothing_else() {
        let v = Value::Str("\r\t\u{1f} ~\u{7f}".into());
        assert_eq!(canonical_json(&v), "\"\\r\\t\\u001f ~\u{7f}\"");
        assert_eq!(
            canonical_json(&Value::Seq(vec![Value::Bool(false), Value::Float(-0.25)])),
            "[false,-0.25]"
        );
    }

    #[test]
    fn a_float_never_canonicalizes_like_an_int() {
        assert_eq!(canonical_json(&Value::Int(1)), "1");
        assert_eq!(canonical_json(&Value::Float(1.0)), "1.0");
        assert_eq!(canonical_json(&Value::Float(1.5)), "1.5");
        let big = canonical_json(&Value::Float(1e300));
        assert_eq!(big, format!("1{}.0", "0".repeat(300)));
        assert_eq!(big, canonical_json(&Value::Float(1e300)));
    }

    #[test]
    fn the_parser_never_yields_a_non_finite_float() {
        for doc in ["a: .nan\n", "a: .inf\n", "a: -.inf\n", "a: 1e999\n"] {
            assert!(
                !matches!(crate::load_str(doc), Ok(Value::Map(ref m)) if matches!(m[0].1, Value::Float(_))),
                "{doc}"
            );
        }
    }
}
