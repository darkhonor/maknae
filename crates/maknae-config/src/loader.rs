//! `load_config` — directory → `Document` (spec §2–§6). Spec validation and the
//! registry are platform-independent; the secure read/scan is `cfg(unix)`.

// Imports land incrementally per task so each task passes `clippy -D warnings`
// (unused-import is an error under CI's `-D warnings`): Task 3 needs only
// `SectionSpec`; Task 5 adds `Source`; Task 6 adds `Document`/`Override` +
// `load_str`/`Value`.
use crate::document::SectionSpec;
use crate::ConfigError;

pub(crate) const CORE_SECTION: &str = "core";

/// Validate the caller's specs before any file is read (spec §5): reject a
/// reserved name and duplicate names. Fail-closed on caller misuse.
// `allow(dead_code)`: sole non-test caller is `load_config` (Task 7); removed there.
#[allow(dead_code)]
pub(crate) fn validate_specs(specs: &[SectionSpec]) -> Result<(), ConfigError> {
    for (i, s) in specs.iter().enumerate() {
        if s.name == CORE_SECTION {
            return Err(ConfigError::ReservedSection { section: s.name.clone() });
        }
        if specs[..i].iter().any(|p| p.name == s.name) {
            return Err(ConfigError::DuplicateSpec { section: s.name.clone() });
        }
    }
    Ok(())
}

/// Name lookups over the validated extension specs plus the reserved `core`.
// `allow(dead_code)`: sole non-test caller is `assemble` (Task 6); removed there.
#[allow(dead_code)]
pub(crate) struct Registry<'a> {
    pub(crate) specs: &'a [SectionSpec],
}

#[allow(dead_code)]
impl<'a> Registry<'a> {
    pub(crate) fn is_reserved(&self, name: &str) -> bool {
        name == CORE_SECTION
    }
    pub(crate) fn is_known(&self, name: &str) -> bool {
        name == CORE_SECTION || self.specs.iter().any(|s| s.name == name)
    }
    pub(crate) fn required_extensions(&self) -> impl Iterator<Item = &str> {
        self.specs.iter().filter(|s| s.required).map(|s| s.name.as_str())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn spec(name: &str, required: bool) -> SectionSpec {
        SectionSpec { name: name.into(), required }
    }

    #[test]
    fn validate_rejects_reserved_name() {
        let specs = [spec("core", false)];
        assert!(matches!(
            validate_specs(&specs),
            Err(ConfigError::ReservedSection { section }) if section == "core"
        ));
    }

    #[test]
    fn validate_rejects_duplicate_specs() {
        let specs = [spec("authz", true), spec("authz", false)];
        assert!(matches!(
            validate_specs(&specs),
            Err(ConfigError::DuplicateSpec { section }) if section == "authz"
        ));
    }

    #[test]
    fn validate_accepts_distinct_extensions() {
        let specs = [spec("authz", true), spec("llm", false)];
        assert!(validate_specs(&specs).is_ok());
    }

    #[test]
    fn registry_knows_core_and_specs_only() {
        let specs = [spec("authz", true)];
        let reg = Registry { specs: &specs };
        assert!(reg.is_known("core") && reg.is_reserved("core"));
        assert!(reg.is_known("authz") && !reg.is_reserved("authz"));
        assert!(!reg.is_known("nope"));
        assert_eq!(reg.required_extensions().collect::<Vec<_>>(), vec!["authz"]);
    }
}
