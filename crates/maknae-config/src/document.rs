//! The assembled configuration document and its provenance types (spec §5/§6).
//! Schema-agnostic: sections are opaque `Value`s; each subsystem parses its own.

use crate::Value;
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
        Document { sections, overrides }
    }

    /// The section's `Value`, or `None` for a registered-optional-absent (or
    /// unregistered) name. The subsystem parses the `Value` itself.
    pub fn section(&self, name: &str) -> Option<&Value> {
        self.sections.iter().find(|(n, _, _)| n == name).map(|(_, v, _)| v)
    }

    /// The audit trail of which source won each overridden section.
    pub fn overrides(&self) -> &[Override] {
        &self.overrides
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
                ("authz".into(), Value::Int(2), Source::ConfigD("cfg.yaml".into())),
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
