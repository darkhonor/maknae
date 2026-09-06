//! Cycle ②c — the `core` section's classification **ceiling** (the ingest bludgeon).
//! Reuses the lake's `handling` vocabulary verbatim (`lake.yaml` / `lake.schema.json`)
//! so the lake and the optional `-dcs` scalpel read the same declaration. Fail-closed:
//! absent → the selected system's baseline; present → strictly validated;
//! present-but-invalid → `ConfigError::InvalidCeiling`.
//!
//! *Corrected 2026-09-06 (#148, ADR-0022): the ceiling's `classification` is a
//! [`Level`] in a declared classification SYSTEM, validated through the seam's
//! [`ClassificationPolicy`] — the kernel's US system by default, another
//! system when `core.handling.policy` names one this build carries. The
//! marking vocabulary is matched case-insensitively, a stated divergence from
//! `_ceiling.py`'s case-sensitive `CLASSIFICATION_ORDER`; separator forms are
//! still rejected. This module no longer holds a level enum, and it never
//! ORDERS levels itself: a policy ranks within its own system, and only there.*

use crate::{ConfigError, Value};
use maknae_security::{first_token, ClassificationPolicy, Level};

/// The classification ceiling — mirrors the lake's `handling` block field-for-field.
/// `classification` is a [`Level`] in the system `core.handling.policy` selected.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Ceiling {
    pub classification: Level,
    pub sci: bool,
    pub releasable_to: Vec<String>,
    pub cui_permitted: bool,
    pub cui_categories_permitted: Vec<String>,
    pub dissemination_permitted: Vec<String>,
    pub accreditation_ref: Option<String>,
}

/// The coarse ingest gate (the "bludgeon") — one derived bit, no lattice math.
///
/// Its consumer is the memory-system INGEST path, not the per-request ceiling
/// operand (ADR-0022): an ATO reference or a CUI category makes a declaration
/// `Gated` here without affecting what the operand serves.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum IngestPosture {
    Public,
    Gated,
}

impl Ceiling {
    /// The compiled Public default a bare Maknae runs at, in `policy`'s system:
    /// its unmarked level, and the wide-open handling fields.
    pub fn baseline_for(policy: &dyn ClassificationPolicy) -> Ceiling {
        Ceiling {
            classification: policy.unmarked(),
            sci: false,
            releasable_to: Vec::new(),
            cui_permitted: false,
            cui_categories_permitted: Vec::new(),
            dissemination_permitted: vec!["Distribution Statement A".to_string()],
            accreditation_ref: None,
        }
    }

    /// `Public` iff the ceiling equals `policy`'s baseline; any above-baseline
    /// signal → `Gated`.
    pub fn ingest_posture(&self, policy: &dyn ClassificationPolicy) -> IngestPosture {
        if *self == Ceiling::baseline_for(policy) {
            IngestPosture::Public
        } else {
            IngestPosture::Gated
        }
    }
}

fn err(reason: impl Into<String>) -> ConfigError {
    ConfigError::InvalidCeiling {
        reason: reason.into(),
    }
}

fn as_map(v: &Value) -> Option<&[(String, Value)]> {
    match v {
        Value::Map(m) => Some(m),
        _ => None,
    }
}

fn get<'a>(m: &'a [(String, Value)], key: &str) -> Option<&'a Value> {
    m.iter().find(|(k, _)| k == key).map(|(_, v)| v)
}

fn field<'a>(m: &'a [(String, Value)], key: &str) -> Result<&'a Value, ConfigError> {
    get(m, key).ok_or_else(|| err(format!("handling.ceiling: missing '{key}'")))
}

fn as_bool(v: &Value) -> Option<bool> {
    match v {
        Value::Bool(b) => Some(*b),
        _ => None,
    }
}

fn as_str(v: &Value) -> Option<&str> {
    match v {
        Value::Str(s) => Some(s.as_str()),
        _ => None,
    }
}

/// A sequence of strings, or `None` if not a sequence or any element isn't a string.
fn as_str_vec(v: &Value) -> Option<Vec<String>> {
    match v {
        Value::Seq(items) => items.iter().map(|x| as_str(x).map(String::from)).collect(),
        _ => None,
    }
}

/// The name of the classification system this deployment operates under:
/// `core.handling.policy`, defaulting to the US system when absent. Read
/// BEFORE the ceiling, because the ceiling is validated through the system it
/// names (the kernel resolves the name against its compiled registry; an
/// unknown name is `ConfigError::UnknownClassificationPolicy` there).
pub fn policy_name_from_core(core: Option<&Value>) -> Result<String, ConfigError> {
    let Some(core_map) = core.and_then(as_map) else {
        return Ok(crate::policy::NAME.to_string());
    };
    let Some(handling) = get(core_map, "handling").and_then(as_map) else {
        return Ok(crate::policy::NAME.to_string());
    };
    match get(handling, "policy") {
        None => Ok(crate::policy::NAME.to_string()),
        Some(Value::Str(s)) if !s.trim().is_empty() => Ok(s.trim().to_ascii_uppercase()),
        Some(_) => Err(err(
            "handling.policy must be a non-empty string naming a classification system",
        )),
    }
}

/// Read the `core` section's classification ceiling (spec ②c §4) in `policy`'s
/// system. Absent/non-map/no `handling` → that system's baseline. A present
/// `handling` is validated strictly per `lake.schema.json`; any violation →
/// `InvalidCeiling`.
pub fn ceiling_from_core(
    core: Option<&Value>,
    policy: &dyn ClassificationPolicy,
) -> Result<Ceiling, ConfigError> {
    let core_map = match core.and_then(as_map) {
        Some(m) => m,
        None => return Ok(Ceiling::baseline_for(policy)), // None / non-map core → baseline
    };
    match get(core_map, "handling") {
        None => Ok(Ceiling::baseline_for(policy)), // no handling block → baseline
        Some(handling) => parse_handling(handling, policy),
    }
}

fn parse_handling(
    handling: &Value,
    policy: &dyn ClassificationPolicy,
) -> Result<Ceiling, ConfigError> {
    let hmap = as_map(handling).ok_or_else(|| err("handling is not a map"))?;
    // additionalProperties: false -- `policy` (ADR-0022) joins the two lake keys.
    for (k, _) in hmap {
        if k != "ceiling" && k != "accreditation_ref" && k != "policy" {
            return Err(err(format!("handling: unknown key '{k}'")));
        }
    }
    // required: [ceiling, accreditation_ref]; `policy` is optional (read separately).
    let accreditation_ref = match get(hmap, "accreditation_ref") {
        None => return Err(err("handling: missing 'accreditation_ref'")),
        Some(Value::Null) => None,
        Some(Value::Str(s)) => Some(s.clone()),
        Some(_) => return Err(err("handling.accreditation_ref must be a string or null")),
    };
    let ceiling = get(hmap, "ceiling").ok_or_else(|| err("handling: missing 'ceiling'"))?;
    parse_ceiling(ceiling, accreditation_ref, policy)
}

fn parse_ceiling(
    ceiling: &Value,
    accreditation_ref: Option<String>,
    policy: &dyn ClassificationPolicy,
) -> Result<Ceiling, ConfigError> {
    const KEYS: [&str; 6] = [
        "classification",
        "sci",
        "releasable_to",
        "cui_permitted",
        "cui_categories_permitted",
        "dissemination_permitted",
    ];
    let m = as_map(ceiling).ok_or_else(|| err("handling.ceiling is not a map"))?;
    // additionalProperties: false
    for (k, _) in m {
        if !KEYS.contains(&k.as_str()) {
            return Err(err(format!("handling.ceiling: unknown key '{k}'")));
        }
    }
    // required + typed (field() errors on a missing required key)
    let classification = {
        let raw = as_str(field(m, "classification")?)
            .ok_or_else(|| err("classification must be a string"))?;
        // A CEILING is a bare level NAME in the declared system -- not a
        // marking: no caveats after `//`, and no alias (`CUI` is a marking's
        // spelling of UNCLASSIFIED, not a level a system declares).
        let level = policy
            .level_of(raw)
            .filter(|l| first_token(raw) == raw.trim() && l.name.eq_ignore_ascii_case(raw.trim()))
            .ok_or_else(|| {
                err(format!(
                    "classification: '{raw}' is not a level of the {} system",
                    policy.name()
                ))
            })?;
        level
    };
    let sci = as_bool(field(m, "sci")?).ok_or_else(|| err("sci must be a boolean"))?;
    let cui_permitted = as_bool(field(m, "cui_permitted")?)
        .ok_or_else(|| err("cui_permitted must be a boolean"))?;
    let releasable_to = as_str_vec(field(m, "releasable_to")?)
        .ok_or_else(|| err("releasable_to must be an array of strings"))?;
    let cui_categories_permitted = as_str_vec(field(m, "cui_categories_permitted")?)
        .ok_or_else(|| err("cui_categories_permitted must be an array of strings"))?;
    let dissemination_permitted = as_str_vec(field(m, "dissemination_permitted")?)
        .ok_or_else(|| err("dissemination_permitted must be an array of strings"))?;
    Ok(Ceiling {
        classification,
        sci,
        releasable_to,
        cui_permitted,
        cui_categories_permitted,
        dissemination_permitted,
        accreditation_ref,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::policy::BasicPolicy;
    use crate::{load_str, ConfigError, Value};

    const US: BasicPolicy = BasicPolicy;

    fn base() -> Ceiling {
        Ceiling::baseline_for(&US)
    }

    fn us(name: &str) -> Level {
        US.level_of(name).unwrap()
    }

    // Parse a YAML snippet representing the `core` section's VALUE (a map).
    fn core(yaml: &str) -> Value {
        load_str(yaml).expect("test yaml parses")
    }

    // A full, conformant, baseline `handling` block (all six + accreditation_ref).
    // `\n`-escaped (not a `"\`-continuation literal) so no YAML line sits at column 0
    // inside the test module — the coverage gate splits production/test at column 0.
    const BASE: &str = "handling:\n  ceiling:\n    classification: UNCLASSIFIED\n    sci: false\n    releasable_to: []\n    cui_permitted: false\n    cui_categories_permitted: []\n    dissemination_permitted: [\"Distribution Statement A\"]\n  accreditation_ref: null\n";

    #[test]
    fn baseline_is_the_public_default_in_the_selected_system() {
        let b = base();
        // Pin the concrete baseline field values (kills mutants that alter baseline_for()).
        assert_eq!(b.classification, US.unmarked());
        assert_eq!(b.classification.name, "UNCLASSIFIED");
        assert!(!b.sci);
        assert!(b.releasable_to.is_empty());
        assert!(!b.cui_permitted);
        assert!(b.cui_categories_permitted.is_empty());
        assert_eq!(
            b.dissemination_permitted,
            vec!["Distribution Statement A".to_string()]
        );
        assert_eq!(b.accreditation_ref, None);
        assert_eq!(b.ingest_posture(&US), IngestPosture::Public);
    }

    #[test]
    fn each_above_baseline_signal_is_gated() {
        // Every deviation from baseline, in isolation, projects to Gated -- the
        // INGEST bit; the per-request operand reads the level only (ADR-0022).
        let mut c = base();
        c.classification = us("SECRET");
        assert_eq!(
            c.ingest_posture(&US),
            IngestPosture::Gated,
            "classification"
        );
        let mut c = base();
        c.sci = true;
        assert_eq!(c.ingest_posture(&US), IngestPosture::Gated, "sci");
        let mut c = base();
        c.cui_permitted = true;
        assert_eq!(c.ingest_posture(&US), IngestPosture::Gated, "cui_permitted");
        let mut c = base();
        c.releasable_to = vec!["REL FVEY".into()];
        assert_eq!(c.ingest_posture(&US), IngestPosture::Gated, "releasable_to");
        let mut c = base();
        c.cui_categories_permitted = vec!["SP-PRVCY".into()];
        assert_eq!(
            c.ingest_posture(&US),
            IngestPosture::Gated,
            "cui_categories_permitted"
        );
        let mut c = base();
        c.dissemination_permitted = vec!["Distribution Statement C".into()];
        assert_eq!(
            c.ingest_posture(&US),
            IngestPosture::Gated,
            "dissemination_permitted"
        );
        let mut c = base();
        c.accreditation_ref = Some("ATO-123".into());
        assert_eq!(
            c.ingest_posture(&US),
            IngestPosture::Gated,
            "accreditation_ref"
        );
    }

    #[test]
    fn absent_core_is_baseline_public() {
        assert_eq!(ceiling_from_core(None, &US).unwrap(), base());
        assert_eq!(
            ceiling_from_core(None, &US).unwrap().ingest_posture(&US),
            IngestPosture::Public
        );
    }

    #[test]
    fn core_without_handling_is_baseline() {
        let v = core("identity:\n  name: maknae-1\n");
        assert_eq!(ceiling_from_core(Some(&v), &US).unwrap(), base());
    }

    #[test]
    fn non_map_core_is_baseline() {
        let v = Value::Str("nonsense".into());
        assert_eq!(ceiling_from_core(Some(&v), &US).unwrap(), base());
    }

    #[test]
    fn full_baseline_block_parses_to_baseline_public() {
        let v = core(BASE);
        assert_eq!(ceiling_from_core(Some(&v), &US).unwrap(), base());
        assert_eq!(
            ceiling_from_core(Some(&v), &US)
                .unwrap()
                .ingest_posture(&US),
            IngestPosture::Public
        );
    }

    #[test]
    fn above_baseline_signals_parse_to_gated() {
        let cases = [
            BASE.replace("classification: UNCLASSIFIED", "classification: SECRET"),
            BASE.replace("sci: false", "sci: true"),
            BASE.replace("cui_permitted: false", "cui_permitted: true"),
            BASE.replace("releasable_to: []", "releasable_to: [\"REL FVEY\"]"),
            BASE.replace(
                "cui_categories_permitted: []",
                "cui_categories_permitted: [\"SP-PRVCY\"]",
            ),
            BASE.replace(
                "dissemination_permitted: [\"Distribution Statement A\"]",
                "dissemination_permitted: [\"Distribution Statement C\"]",
            ),
            // An EMPTY dissemination set is still an explicit deviation from the exact
            // baseline → Gated: the coarse bit is "is this the wide-open default?".
            BASE.replace(
                "dissemination_permitted: [\"Distribution Statement A\"]",
                "dissemination_permitted: []",
            ),
            BASE.replace("accreditation_ref: null", "accreditation_ref: \"ATO-123\""),
        ];
        for y in cases {
            let v = core(&y);
            let c = ceiling_from_core(Some(&v), &US).expect("valid ceiling");
            assert_eq!(c.ingest_posture(&US), IngestPosture::Gated, "yaml:\n{y}");
        }
    }

    #[test]
    fn each_recognized_level_parses_through_the_policy_case_insensitively() {
        for (raw, want) in [
            ("CONFIDENTIAL", "CONFIDENTIAL"),
            ("SECRET", "SECRET"),
            ("TOP SECRET", "TOP SECRET"),
            ("Unclassified", "UNCLASSIFIED"), // the live bug this closed: used to refuse boot
            ("secret", "SECRET"),
        ] {
            let v = core(&BASE.replace(
                "classification: UNCLASSIFIED",
                &format!("classification: {raw}"),
            ));
            assert_eq!(
                ceiling_from_core(Some(&v), &US).unwrap().classification,
                us(want),
                "level {raw}"
            );
        }
    }

    #[test]
    fn a_ceiling_is_a_bare_level_name_not_a_marking() {
        // Caveats, the CUI alias, separator forms and unknown names all refuse:
        // a DECLARATION names a level; a marking is what content carries.
        for raw in [
            "SECRET//NOFORN",
            "CUI",
            "TOP_SECRET",
            "SEKRET",
            "PROTECTED",
            "",
        ] {
            let v = core(&BASE.replace(
                "classification: UNCLASSIFIED",
                &format!("classification: \"{raw}\""),
            ));
            let e = ceiling_from_core(Some(&v), &US).unwrap_err();
            assert!(
                matches!(&e, ConfigError::InvalidCeiling { reason } if reason.contains("is not a level of the US system")),
                "{raw:?} -> {e}"
            );
        }
    }

    #[test]
    fn the_policy_name_is_read_before_the_ceiling_and_defaults_to_us() {
        assert_eq!(policy_name_from_core(None).unwrap(), "US");
        assert_eq!(
            policy_name_from_core(Some(&core("identity:\n  name: x\n"))).unwrap(),
            "US"
        );
        assert_eq!(policy_name_from_core(Some(&core(BASE))).unwrap(), "US");
        let v = core(&BASE.replace(
            "  accreditation_ref: null\n",
            "  accreditation_ref: null\n  policy: aus\n",
        ));
        assert_eq!(
            policy_name_from_core(Some(&v)).unwrap(),
            "AUS",
            "upper-cased name"
        );
        for bad in ["  policy: 7\n", "  policy: \"\"\n", "  policy: [AUS]\n"] {
            let v = core(&BASE.replace(
                "  accreditation_ref: null\n",
                &format!("  accreditation_ref: null\n{bad}"),
            ));
            assert!(
                matches!(
                    policy_name_from_core(Some(&v)),
                    Err(ConfigError::InvalidCeiling { .. })
                ),
                "{bad:?}"
            );
        }
    }

    #[test]
    fn a_ceiling_in_another_system_is_validated_through_that_system() {
        // The seam is the contract: hand the parser a policy that knows a
        // different ladder and the same YAML validates against IT. (The real
        // AUS system is its own crate; this stub proves the parser is
        // policy-agnostic.)
        struct Two;
        impl ClassificationPolicy for Two {
            fn name(&self) -> &str {
                "TWO"
            }
            fn level_of(&self, m: &str) -> Option<Level> {
                ["LOW", "HIGH"]
                    .iter()
                    .position(|l| l.eq_ignore_ascii_case(first_token(m)))
                    .map(|rank| Level {
                        policy: "TWO".into(),
                        name: ["LOW", "HIGH"][rank].into(),
                        rank,
                    })
            }
            fn unmarked(&self) -> Level {
                self.level_of("LOW").unwrap()
            }
            fn dominates(&self, c: &Level, x: &Level) -> Option<bool> {
                (c.policy == "TWO" && x.policy == "TWO").then_some(x.rank <= c.rank)
            }
            fn non_public(&self, _: &str) -> bool {
                false
            }
        }
        let v = core(&BASE.replace("classification: UNCLASSIFIED", "classification: high"));
        let c = ceiling_from_core(Some(&v), &Two).unwrap();
        assert_eq!(
            (
                c.classification.policy.as_str(),
                c.classification.name.as_str()
            ),
            ("TWO", "HIGH")
        );
        // The US name is not a level of TWO.
        let v = core(BASE);
        assert!(ceiling_from_core(Some(&v), &Two).is_err());
        assert_eq!(
            ceiling_from_core(None, &Two).unwrap().classification.name,
            "LOW"
        );
    }

    #[test]
    fn invalids_are_invalid_ceiling() {
        let bad = [
            // handling missing accreditation_ref
            BASE.replace("  accreditation_ref: null\n", ""),
            // a bare `handling:` (present key, null value) is a malformed block
            "handling:\n".to_string(),
            // handling missing ceiling
            "handling:\n  accreditation_ref: null\n".to_string(),
            // additionalProperties: unknown key at the HANDLING level
            BASE.replace(
                "  accreditation_ref: null\n",
                "  accreditation_ref: null\n  bogus: 1\n",
            ),
            // additionalProperties: unknown key in ceiling
            BASE.replace(
                "    cui_permitted: false\n",
                "    cui_permitted: false\n    cui_permited: true\n",
            ),
            // classification wrong type
            BASE.replace("classification: UNCLASSIFIED", "classification: 42"),
            // sci wrong type
            BASE.replace("sci: false", "sci: \"yes\""),
            // cui_permitted wrong type
            BASE.replace("cui_permitted: false", "cui_permitted: \"yes\""),
            // releasable_to scalar not seq
            BASE.replace("releasable_to: []", "releasable_to: REL FVEY"),
            // cui_categories_permitted scalar not seq
            BASE.replace(
                "cui_categories_permitted: []",
                "cui_categories_permitted: SP-PRVCY",
            ),
            // dissemination_permitted scalar not seq
            BASE.replace(
                "dissemination_permitted: [\"Distribution Statement A\"]",
                "dissemination_permitted: A",
            ),
            // accreditation_ref wrong type
            BASE.replace("accreditation_ref: null", "accreditation_ref: 7"),
        ];
        for y in bad {
            let v = core(&y);
            match ceiling_from_core(Some(&v), &US) {
                Err(ConfigError::InvalidCeiling { .. }) => {}
                other => panic!("expected InvalidCeiling for yaml:\n{y}\ngot {other:?}"),
            }
        }
    }

    #[test]
    fn each_missing_ceiling_field_is_invalid() {
        for key in [
            "classification",
            "sci",
            "releasable_to",
            "cui_permitted",
            "cui_categories_permitted",
            "dissemination_permitted",
        ] {
            let y: String = BASE
                .lines()
                .filter(|l| !l.trim_start().starts_with(&format!("{key}:")))
                .map(|l| format!("{l}\n"))
                .collect();
            let v = core(&y);
            match ceiling_from_core(Some(&v), &US) {
                Err(ConfigError::InvalidCeiling { reason }) => {
                    assert!(reason.contains(key), "missing {key}: {reason}")
                }
                other => panic!("expected InvalidCeiling without {key}, got {other:?}"),
            }
        }
    }
}
