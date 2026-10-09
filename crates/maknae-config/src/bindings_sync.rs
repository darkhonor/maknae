use crate::bindings::{entry, section_roles, BindingEntry, Bindings, BindingsError};
use crate::value::{canonical_json, Value};
use std::collections::{BTreeMap, BTreeSet};

const MISSING: &str = "missing";
const ABSENT: &str = "null";

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Section {
    Missing,
    Absent,
    Present(BTreeMap<String, Vec<BindingEntry>>),
}

fn entry_value(e: &BindingEntry) -> Value {
    match e {
        BindingEntry::Name(n) => Value::Str(n.clone()),
        BindingEntry::Uid(u) => Value::Map(vec![("uid".into(), Value::Int(i64::from(*u)))]),
    }
}

impl Section {
    pub fn of(b: &Bindings) -> Self {
        match (&b.roles, b.is_missing()) {
            (_, true) => Self::Missing,
            (None, false) => Self::Absent,
            (Some(m), false) => Self::Present(m.clone()),
        }
    }

    pub fn canonical(&self) -> String {
        match self {
            Self::Missing => MISSING.into(),
            Self::Absent => ABSENT.into(),
            Self::Present(m) => canonical_json(&Value::Map(
                m.iter()
                    .map(|(k, v)| (k.clone(), Value::Seq(v.iter().map(entry_value).collect())))
                    .collect(),
            )),
        }
    }

    pub fn from_canonical(s: &str) -> Result<Self, BindingsError> {
        match s {
            MISSING => return Ok(Self::Missing),
            ABSENT => return Ok(Self::Absent),
            _ => {}
        }
        let v =
            crate::value_from_canonical_json(s).map_err(|e| BindingsError::Yaml(e.to_string()))?;
        let section = Self::Present(section_roles(&v)?);
        crate::check_roles(&Bindings::from_section(&section))
            .map_err(|e| BindingsError::Yaml(e.to_string()))?;
        Ok(section)
    }

    pub fn roles_of(&self, e: &BindingEntry) -> BTreeSet<&str> {
        match self {
            Self::Present(m) => m
                .iter()
                .filter(|(_, v)| v.contains(e))
                .map(|(k, _)| k.as_str())
                .collect(),
            _ => BTreeSet::new(),
        }
    }

    pub fn entries(&self) -> Vec<&BindingEntry> {
        let mut out: Vec<&BindingEntry> = Vec::new();
        if let Self::Present(m) = self {
            for e in m.values().flatten() {
                if !out.contains(&e) {
                    out.push(e);
                }
            }
        }
        out
    }
}

pub fn conflicts_canonical(c: &BTreeSet<BindingEntry>) -> String {
    canonical_json(&Value::Seq(c.iter().map(entry_value).collect()))
}

pub fn conflicts_from_canonical(s: &str) -> Result<BTreeSet<BindingEntry>, BindingsError> {
    let Value::Seq(items) =
        crate::value_from_canonical_json(s).map_err(|e| BindingsError::Yaml(e.to_string()))?
    else {
        return Err(BindingsError::Yaml("a conflict list is a sequence".into()));
    };
    let set: BTreeSet<BindingEntry> = items.iter().map(entry).collect::<Result<_, _>>()?;
    if conflicts_canonical(&set) != s {
        return Err(BindingsError::Yaml(
            "a conflict list is sorted and unique".into(),
        ));
    }
    Ok(set)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{parse_bindings, Bindings};

    const FIXTURES: [&str; 6] = [
        "schema_version: 1\n",
        "schema_version: 1\nbindings: {}\n",
        "schema_version: 1\nbindings:\n  guest: []\n",
        "schema_version: 1\nbindings:\n  user: [\"bob\", \"carol\"]\n  admin: [\"alice\"]\n",
        "schema_version: 1\nbindings:\n  adversary:\n    - \"mallory\"\n    - uid: 4242\n    - uid: 0\n",
        "schema_version: 1\nbindings:\n  admin: [\"a\\\"b\\\\c\", \"\\u00e9\"]\n  adversary: [\"a\\\"b\\\\c\"]\n",
    ];

    #[test]
    fn a_section_prints_the_text_the_parser_hashes() {
        for f in FIXTURES {
            let b = parse_bindings(f).unwrap();
            let s = Section::of(&b);
            assert_eq!(
                s.canonical(),
                b.section_canonical().unwrap_or("null"),
                "{f}"
            );
            assert_eq!(Section::from_canonical(&s.canonical()).unwrap(), s, "{f}");
            assert_eq!(Bindings::from_section(&s), b, "{f}");
        }
        assert_eq!(Section::of(&Bindings::missing()).canonical(), "missing");
        assert_eq!(
            Section::from_canonical("missing").unwrap(),
            Section::Missing
        );
        assert_eq!(Section::from_canonical("null").unwrap(), Section::Absent);
        assert_eq!(
            Bindings::from_section(&Section::Missing),
            Bindings::missing()
        );
        assert_eq!(Bindings::from_section(&Section::Absent), Bindings::absent());
    }

    #[test]
    fn from_canonical_takes_canonical_text_only() {
        for bad in [
            "",
            "{ }",
            r#"{"user":["b"],"admin":["a"]}"#,
            r#"{"admin":"a"}"#,
            "[]",
            "\"null\"",
            r#"{"admin":[{"uid":7}]}"#,
            r#"{"root":["a"]}"#,
            r#"{"admin":["a","a"]}"#,
        ] {
            assert!(Section::from_canonical(bad).is_err(), "{bad:?}");
        }
    }

    #[test]
    fn roles_of_an_entry_is_every_list_holding_it() {
        let s = Section::of(&parse_bindings(
            "schema_version: 1\nbindings:\n  user: [\"eve\"]\n  adversary: [\"eve\", {uid: 7}]\n",
        ).unwrap());
        let eve = BindingEntry::Name("eve".into());
        assert_eq!(
            s.roles_of(&eve).into_iter().collect::<Vec<_>>(),
            ["adversary", "user"]
        );
        assert!(Section::Absent.roles_of(&eve).is_empty());
        assert_eq!(s.entries(), [&eve, &BindingEntry::Uid(7)]);
    }

    #[test]
    fn the_conflict_list_round_trips_in_entry_order() {
        let c: BTreeSet<_> = [
            BindingEntry::Uid(7),
            BindingEntry::Name("b".into()),
            BindingEntry::Name("a".into()),
        ]
        .into();
        assert_eq!(conflicts_canonical(&c), r#"["a","b",{"uid":7}]"#);
        assert_eq!(
            conflicts_from_canonical(&conflicts_canonical(&c)).unwrap(),
            c
        );
        assert_eq!(conflicts_canonical(&BTreeSet::new()), "[]");
        for bad in [
            "",
            r#"["b","a"]"#,
            r#"["a","a"]"#,
            r#"[1]"#,
            r#"[""]"#,
            r#"["a:b"]"#,
        ] {
            assert!(conflicts_from_canonical(bad).is_err(), "{bad:?}");
        }
    }
}
