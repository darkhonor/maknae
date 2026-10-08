//! The persisted baseline's form: each `maknae.yaml`/`config.d` section's winning
//! value as canonical JSON, and the strict decode back to a [`Document`] (#490).

use crate::{canonical_json, ConfigError, Document, Source, Value};

use std::collections::BTreeMap;

/// Section name to canonical JSON. `Debug` prints the section names only.
#[derive(Clone, Default, PartialEq, Eq)]
pub struct BaselineSections(BTreeMap<String, String>);

impl BaselineSections {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn into_inner(self) -> BTreeMap<String, String> {
        self.0
    }
}

impl std::fmt::Debug for BaselineSections {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_set().entries(self.0.keys()).finish()
    }
}

impl std::ops::Deref for BaselineSections {
    type Target = BTreeMap<String, String>;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl std::ops::DerefMut for BaselineSections {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

impl From<BTreeMap<String, String>> for BaselineSections {
    fn from(m: BTreeMap<String, String>) -> Self {
        Self(m)
    }
}

impl<const N: usize> From<[(String, String); N]> for BaselineSections {
    fn from(pairs: [(String, String); N]) -> Self {
        Self(pairs.into())
    }
}

impl FromIterator<(String, String)> for BaselineSections {
    fn from_iter<I: IntoIterator<Item = (String, String)>>(iter: I) -> Self {
        Self(iter.into_iter().collect())
    }
}

impl<'a> IntoIterator for &'a BaselineSections {
    type Item = (&'a String, &'a String);
    type IntoIter = std::collections::btree_map::Iter<'a, String, String>;
    fn into_iter(self) -> Self::IntoIter {
        self.0.iter()
    }
}

/// The winning value of every section, as canonical JSON.
pub fn document_sections(doc: &Document) -> BaselineSections {
    doc.winners()
        .map(|(name, value)| (name.to_string(), canonical_json(value)))
        .collect()
}

/// Strict: JSON produced by `canonical_json`, and nothing else, decodes.
pub fn value_from_canonical_json(s: &str) -> Result<Value, ConfigError> {
    decode(s).map_err(ConfigError::BaselineValue)
}

fn decode(s: &str) -> Result<Value, String> {
    let parsed: serde_json::Value =
        serde_json::from_str(s).map_err(|e| format!("not JSON: {e}"))?;
    let value = convert(&parsed)?;
    if canonical_json(&value) != s {
        return Err("not in canonical form".to_string());
    }
    Ok(value)
}

fn convert(j: &serde_json::Value) -> Result<Value, String> {
    Ok(match j {
        serde_json::Value::Null => Value::Null,
        serde_json::Value::Bool(b) => Value::Bool(*b),
        serde_json::Value::Number(n) => {
            if let Some(i) = n.as_i64() {
                Value::Int(i)
            } else if let (true, Some(f)) = (n.is_f64(), n.as_f64()) {
                Value::Float(f)
            } else {
                return Err("a number is out of range".to_string());
            }
        }
        serde_json::Value::String(s) => Value::Str(s.clone()),
        serde_json::Value::Array(items) => {
            Value::Seq(items.iter().map(convert).collect::<Result<_, _>>()?)
        }
        serde_json::Value::Object(entries) => Value::Map(
            entries
                .iter()
                .map(|(k, v)| Ok((k.clone(), convert(v)?)))
                .collect::<Result<_, String>>()?,
        ),
    })
}

impl Document {
    /// A document whose every section is a `Base` winner and which has no shadowed sections.
    pub fn from_baseline(sections: &BaselineSections) -> Result<Document, ConfigError> {
        let mut out = Vec::with_capacity(sections.len());
        for (name, json) in sections {
            let value = decode(json)
                .map_err(|m| ConfigError::BaselineValue(format!("baseline section {name}: {m}")))?;
            out.push((name.clone(), value, Source::Base));
        }
        Ok(Document::new(out, Vec::new(), Vec::new()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{canonical_json, Value};

    fn every_shape() -> Value {
        Value::Map(vec![
            ("z".into(), Value::Null),
            ("b".into(), Value::Bool(true)),
            ("c".into(), Value::Bool(false)),
            ("i".into(), Value::Int(-7)),
            ("big".into(), Value::Int(i64::MAX)),
            ("small".into(), Value::Int(i64::MIN)),
            ("f".into(), Value::Float(1.0)),
            ("g".into(), Value::Float(1e300)),
            ("h".into(), Value::Float(-0.5)),
            ("s".into(), Value::Str("q\"\\\n\u{1}é".into())),
            (
                "seq".into(),
                Value::Seq(vec![
                    Value::Int(1),
                    Value::Str("x".into()),
                    Value::Seq(vec![]),
                ]),
            ),
            (
                "m".into(),
                Value::Map(vec![
                    ("b".into(), Value::Int(2)),
                    ("a".into(), Value::Map(vec![])),
                ]),
            ),
        ])
    }

    #[test]
    fn canonical_json_round_trips_every_value_shape() {
        let v = every_shape();
        let once = canonical_json(&v);
        let back = value_from_canonical_json(&once).unwrap();
        assert_eq!(canonical_json(&back), once);
    }

    #[test]
    fn the_decoded_value_is_the_encoded_value() {
        let back = value_from_canonical_json(&canonical_json(&every_shape())).unwrap();
        let Value::Map(entries) = back else {
            panic!("not a map: {back:?}")
        };
        let get = |k: &str| entries.iter().find(|(n, _)| n == k).unwrap().1.clone();
        assert_eq!(get("z"), Value::Null);
        assert_eq!(get("b"), Value::Bool(true));
        assert_eq!(get("c"), Value::Bool(false));
        assert_eq!(get("big"), Value::Int(i64::MAX));
        assert_eq!(get("small"), Value::Int(i64::MIN));
        assert_eq!(get("g"), Value::Float(1e300));
        assert_eq!(get("h"), Value::Float(-0.5));
        assert_eq!(get("s"), Value::Str("q\"\\\n\u{1}é".into()));
        assert_eq!(
            get("seq"),
            Value::Seq(vec![
                Value::Int(1),
                Value::Str("x".into()),
                Value::Seq(vec![])
            ])
        );
    }

    #[test]
    fn a_float_with_a_long_decimal_expansion_round_trips_exactly() {
        for f in [
            1.0715660391465826e-76,
            -1.81996730402717e-182,
            5e-324,
            f64::MAX,
        ] {
            let once = canonical_json(&Value::Float(f));
            assert_eq!(
                value_from_canonical_json(&once).unwrap(),
                Value::Float(f),
                "{once}"
            );
        }
    }

    #[test]
    fn an_int_stays_an_int_and_a_float_stays_a_float() {
        assert_eq!(value_from_canonical_json("3").unwrap(), Value::Int(3));
        assert_eq!(value_from_canonical_json("3.0").unwrap(), Value::Float(3.0));
    }

    #[test]
    fn non_canonical_or_non_json_input_is_refused() {
        for bad in [
            "NaN",
            "inf",
            "{\"b\":1,\"a\":2}",
            "{ \"a\":1}",
            "[1, 2]",
            "18446744073709551615",
            "",
            "{\"a\":1}x",
            "{\"a\":1,\"a\":2}",
            "1e2",
            "3.00",
        ] {
            assert!(
                matches!(
                    value_from_canonical_json(bad),
                    Err(ConfigError::BaselineValue(_))
                ),
                "{bad}"
            );
        }
    }

    #[test]
    fn an_out_of_range_integer_is_refused_by_name_inside_a_container() {
        let e = value_from_canonical_json("[18446744073709551615]").unwrap_err();
        assert_eq!(
            e,
            ConfigError::BaselineValue("a number is out of range".into())
        );
    }

    #[test]
    fn from_baseline_round_trips_document_sections() {
        let mut s = BaselineSections::new();
        s.insert("core".into(), "{\"deployment_id\":\"d\"}".into());
        s.insert(
            "audit".into(),
            "{\"jsonl_path\":\"/var/log/maknae/audit.jsonl\"}".into(),
        );
        let doc = Document::from_baseline(&s).unwrap();
        assert_eq!(document_sections(&doc), s);
        assert_eq!(doc.shadowed_sections("audit").count(), 0);
        assert_eq!(doc.source_of("core"), Some(&crate::Source::Base));
        assert_eq!(doc.source_of("audit"), Some(&crate::Source::Base));
        assert!(doc.overrides().is_empty());
    }

    #[test]
    fn document_sections_takes_only_the_winners() {
        let doc = Document::new(
            vec![(
                "audit".into(),
                Value::Map(vec![("jsonl_path".into(), Value::Str("/w".into()))]),
                Source::ConfigD("a.yaml".into()),
            )],
            Vec::new(),
            vec![(
                "audit".into(),
                Value::Map(vec![("jsonl_path".into(), Value::Str("/s".into()))]),
                Source::Base,
            )],
        );
        let mut want = BaselineSections::new();
        want.insert("audit".into(), "{\"jsonl_path\":\"/w\"}".into());
        assert_eq!(document_sections(&doc), want);
    }

    #[test]
    fn debug_names_the_sections_and_never_prints_a_value() {
        let mut s = BaselineSections::new();
        s.insert(
            "core".into(),
            r#"{"handling":{"ceiling":{"classification":"SECRET"}}}"#.into(),
        );
        s.insert("audit".into(), r#"{"au3_1":{"enclave":"SCIF-B7"}}"#.into());
        let base = Document::from_baseline(&s).unwrap();
        let shadowing = Document::new(
            vec![(
                "audit".into(),
                Value::Map(vec![("au3_1".into(), Value::Str("SCIF-B7".into()))]),
                Source::ConfigD("a.yaml".into()),
            )],
            Vec::new(),
            vec![(
                "audit".into(),
                Value::Map(vec![("au3_1".into(), Value::Str("SCIF-B7".into()))]),
                Source::Base,
            )],
        );
        for shown in [
            format!("{s:?}"),
            format!("{base:?}"),
            format!("{shadowing:?}"),
        ] {
            assert!(shown.contains("audit"), "{shown}");
            for value in ["SECRET", "SCIF-B7", "enclave", "au3_1"] {
                assert!(!shown.contains(value), "{shown}");
            }
        }
        assert!(format!("{s:?}").contains("core"));
        assert_eq!(s.clone().into_inner(), *s);
    }

    #[test]
    fn from_baseline_refuses_a_value_that_is_not_canonical() {
        let mut s = BaselineSections::new();
        s.insert("core".into(), "{\"b\":1,\"a\":2}".into());
        assert!(
            matches!(Document::from_baseline(&s), Err(ConfigError::BaselineValue(ref m)) if m.contains("core"))
        );
    }

    #[test]
    fn the_deepest_section_the_loader_accepts_decodes_back() {
        let nested = |n: usize| format!("s: {}1{}", "{a: ".repeat(n), "}".repeat(n));
        let deepest = (1..512)
            .take_while(|n| crate::load_str(&nested(*n)).is_ok())
            .last()
            .unwrap();
        assert!(deepest > 100, "{deepest}");
        let Value::Map(top) = crate::load_str(&nested(deepest)).unwrap() else {
            panic!("not a map")
        };
        let doc = Document::new(
            top.into_iter().map(|(n, v)| (n, v, Source::Base)).collect(),
            Vec::new(),
            Vec::new(),
        );
        let sections = document_sections(&doc);
        assert_eq!(
            document_sections(&Document::from_baseline(&sections).unwrap()),
            sections
        );
    }
}
