//! The assembled configuration document and its provenance types (spec §5/§6).
//! Schema-agnostic: sections are opaque `Value`s; each subsystem parses its own.

use crate::Value;
use std::collections::BTreeMap;
use std::path::PathBuf;

/// A section the caller registers (extensions only — `core` is reserved and
/// injected by the loader, spec §5).
#[derive(Clone, Debug)]
pub struct SectionSpec {
    pub name: String,
    pub required: bool,
}

/// Which source supplied a winning section.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Source {
    Base,
    ConfigD(PathBuf),
}

/// A recorded override: a `config.d/` section shadowed a base section (spec §4).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Override {
    pub section: String,
    pub winner: Source,
    pub shadowed: Source,
}

/// The assembled document: named sections + the audit trail of overrides.
#[derive(Debug)]
pub struct Document {
    sections: Vec<(String, Value, Source)>,
    overrides: Vec<Override>,
}

impl Document {
    /// Loader-only constructor.
    pub(crate) fn new(sections: Vec<(String, Value, Source)>, overrides: Vec<Override>) -> Self {
        Document {
            sections,
            overrides,
        }
    }

    /// The section's `Value`, or `None` for a registered-optional-absent (or
    /// unregistered) name. The subsystem parses the `Value` itself.
    pub fn section(&self, name: &str) -> Option<&Value> {
        self.sections
            .iter()
            .find(|(n, _, _)| n == name)
            .map(|(_, v, _)| v)
    }

    /// The audit trail of which source won each overridden section.
    pub fn overrides(&self) -> &[Override] {
        &self.overrides
    }

    /// The effective configuration as `admin.config.show` may disclose it
    /// (#162 Phase 2, operator ruling 2026-08-31): every section, every key, at
    /// every depth -- and a VALUE only where this crate has declared the field
    /// disclosable. Everything else renders [`MASK`].
    ///
    /// **Deny by default, and that is the entire design.** The obvious
    /// alternative -- a denylist of names that look secret (`*token*`,
    /// `*password*`) -- defaults every future field to DISCLOSED and depends on
    /// whoever adds one remembering to classify it. A rule that depends on
    /// someone remembering is not a control. Here a field added five minutes
    /// ago is masked until a human puts it on [`DISCLOSABLE`], which is a code
    /// change, reviewed, in this file.
    ///
    /// Keys are flattened to dotted paths within a section, so nesting cannot
    /// hide a field from the classifier by depth.
    pub fn disclosable_view(&self) -> BTreeMap<String, BTreeMap<String, String>> {
        let mut out = BTreeMap::new();
        for (name, value, _) in &self.sections {
            let mut flat = BTreeMap::new();
            flatten(name, "", value, &mut flat);
            out.insert(name.clone(), flat);
        }
        out
    }
}

/// Rendered in place of a value this crate has not declared disclosable. Says
/// THAT the setting is configured, never what it is -- presence is what an
/// operator debugging an unset credential needs; the value never is.
pub const MASK: &str = "<value set>";

/// Rendered for a key that is present but has no value. Deliberately distinct
/// from [`MASK`]: "not set" and "set to something I will not show you" are
/// different answers to the operator's actual question, and collapsing them
/// makes the disclosure useless for the case it exists to serve.
pub const NOT_SET: &str = "<not set>";

/// Fields whose VALUES `admin.config.show` may disclose in the clear, as
/// `<section>.<dotted path>`.
///
/// Everything absent from this list is masked. Adding an entry is a deliberate
/// disclosure decision: it publishes that value to any subject holding a grant
/// for `admin.config.show`. The bar is that the value is deployment SHAPE an
/// operator cannot debug without, and is not itself a credential, a secret
/// location, or a fact that materially helps an attacker choose a target.
const DISCLOSABLE: &[&str] = &[
    // Deployment identity. Already baked into every plane leaf's URI SAN, so
    // any peer completing a handshake has it; withholding it here would hide
    // it from the operator and from nobody else.
    "core.deployment_id",
];

fn flatten(section: &str, prefix: &str, v: &Value, out: &mut BTreeMap<String, String>) {
    match v {
        Value::Map(entries) => {
            for (k, sub) in entries {
                let next = if prefix.is_empty() {
                    k.clone()
                } else {
                    format!("{prefix}.{k}")
                };
                flatten(section, &next, sub, out);
            }
        }
        _ => {
            if prefix.is_empty() {
                // A section whose whole body is a scalar: name it by section.
                out.insert(section.to_string(), render(section, section, v));
                return;
            }
            out.insert(prefix.to_string(), render(section, prefix, v));
        }
    }
}

fn render(section: &str, path: &str, v: &Value) -> String {
    // Absence is reported before disclosure is even considered: a key with no
    // value has nothing to leak, and the operator needs to see it is unset.
    if matches!(v, Value::Null) {
        return NOT_SET.to_string();
    }
    let full = format!("{section}.{path}");
    if !DISCLOSABLE.contains(&full.as_str()) {
        return MASK.to_string();
    }
    match v {
        Value::Bool(b) => b.to_string(),
        Value::Int(n) => n.to_string(),
        Value::Float(f) => f.to_string(),
        Value::Str(s) => s.clone(),
        // A declared field holding a collection is NOT rendered element-wise:
        // the declaration was made about a scalar, and silently widening it to
        // a list would disclose values nobody classified.
        Value::Seq(_) | Value::Map(_) | Value::Null => MASK.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Value;

    #[test]
    fn section_lookup_and_overrides() {
        let doc = Document::new(
            vec![
                ("core".into(), Value::Int(1), Source::Base),
                (
                    "authz".into(),
                    Value::Int(2),
                    Source::ConfigD("cfg.yaml".into()),
                ),
            ],
            vec![Override {
                section: "authz".into(),
                winner: Source::ConfigD("cfg.yaml".into()),
                shadowed: Source::Base,
            }],
        );
        assert_eq!(doc.section("core"), Some(&Value::Int(1)));
        assert_eq!(doc.section("authz"), Some(&Value::Int(2)));
        assert_eq!(doc.section("missing"), None);
        assert_eq!(doc.overrides().len(), 1);
        assert_eq!(doc.overrides()[0].section, "authz");
    }
}

#[cfg(test)]
mod disclosure_tests {
    use super::*;
    use crate::Value;

    fn doc(sections: Vec<(&str, Value)>) -> Document {
        Document::new(
            sections
                .into_iter()
                .map(|(n, v)| (n.to_string(), v, Source::Base))
                .collect(),
            Vec::new(),
        )
    }

    fn map(pairs: Vec<(&str, Value)>) -> Value {
        Value::Map(pairs.into_iter().map(|(k, v)| (k.to_string(), v)).collect())
    }

    /// The SHAPE is disclosed in full: every section, every key, at every depth.
    /// That is what makes the term worth having -- an operator debugging a
    /// deployment needs to see which settings exist and which are set.
    #[test]
    fn every_key_at_every_depth_appears_in_the_view() {
        let d = doc(vec![
            (
                "core",
                map(vec![("deployment_id", Value::Str("site-7".into()))]),
            ),
            (
                "vault",
                map(vec![
                    ("addr", Value::Str("https://v:8200".into())),
                    ("nested", map(vec![("deep", Value::Int(1))])),
                ]),
            ),
        ]);
        let v = d.disclosable_view();
        assert!(v.contains_key("core"), "{v:?}");
        assert!(v.contains_key("vault"), "{v:?}");
        let vault = v.get("vault").expect("vault section");
        assert!(vault.contains_key("addr"), "{vault:?}");
        assert!(
            vault.contains_key("nested.deep"),
            "nesting must be walked: {vault:?}"
        );
    }

    /// A field NOT on the disclosable list shows a presence marker, never its
    /// value. `<value set>` says THAT it is configured, which is what an
    /// operator debugging an unset credential needs; the value never is.
    #[test]
    fn an_undeclared_field_is_masked_to_a_presence_marker() {
        let d = doc(vec![(
            "vault",
            map(vec![(
                "root_token",
                Value::Str("hvs.CAESIJ-real-secret".into()),
            )]),
        )]);
        let v = d.disclosable_view();
        let got = v["vault"]["root_token"].clone();
        assert_eq!(got, MASK, "an undeclared field must not disclose its value");
        assert!(
            !format!("{v:?}").contains("hvs.CAESIJ"),
            "the secret must not appear ANYWHERE in the view: {v:?}"
        );
    }

    /// DENY BY DEFAULT is the whole design, and this is the test that holds it.
    ///
    /// A brand-new config field -- one nobody has classified, because it was
    /// added five minutes ago -- is masked. The alternative, a denylist of
    /// known-sensitive names, defaults every future field to DISCLOSED and
    /// depends on whoever adds it remembering to classify it. A rule that
    /// depends on someone remembering is not a control.
    #[test]
    fn a_field_nobody_has_classified_yet_is_masked() {
        let d = doc(vec![(
            "some_future_section",
            map(vec![
                ("a_field_invented_today", Value::Str("sensitive?".into())),
                ("innocuous_looking_count", Value::Int(42)),
            ]),
        )]);
        let v = d.disclosable_view();
        assert_eq!(v["some_future_section"]["a_field_invented_today"], MASK);
        assert_eq!(
            v["some_future_section"]["innocuous_looking_count"], MASK,
            "even an int in an unknown section is masked -- the classifier is the \
             PATH, not the type, and 'it looks harmless' is not a control"
        );
    }

    /// A field ON the list shows its real value. Without this the masking
    /// would be indistinguishable from masking everything, and the term would
    /// disclose nothing useful.
    #[test]
    fn a_declared_field_discloses_its_value() {
        let d = doc(vec![(
            "core",
            map(vec![("deployment_id", Value::Str("site-7".into()))]),
        )]);
        assert_eq!(d.disclosable_view()["core"]["deployment_id"], "site-7");
    }

    /// An ABSENT field is distinguishable from a masked one. "not set" and
    /// "set to something I will not show you" are different answers to the
    /// operator's actual question, and collapsing them makes the term useless
    /// for the case it exists to serve.
    #[test]
    fn absent_is_distinguishable_from_masked() {
        let d = doc(vec![("vault", map(vec![("addr", Value::Null)]))]);
        let v = d.disclosable_view();
        assert_eq!(v["vault"]["addr"], NOT_SET);
        assert_ne!(v["vault"]["addr"], MASK);
    }
}
