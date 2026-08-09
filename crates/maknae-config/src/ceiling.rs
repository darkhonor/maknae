//! Cycle ②c — the `core` section's classification **ceiling** (the ingest bludgeon).
//! Reuses the lake's `handling` vocabulary verbatim (`lake.yaml` / `lake.schema.json`)
//! and `lib/lake/_ceiling.py`'s `CLASSIFICATION_ORDER`, so the lake and the future
//! `-dcs` scalpel read the same declaration. Fail-closed: absent → Public baseline;
//! present → strictly validated; present-but-invalid → `ConfigError::InvalidCeiling`.

/// A recognized DoD classification level (`_ceiling.py` `CLASSIFICATION_ORDER`).
/// ②c stores the level; it does NOT order them (dominance is the `-dcs` scalpel).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Classification {
    Unclassified,
    Confidential,
    Secret,
    TopSecret,
}

/// The classification ceiling — mirrors the lake's `handling` block field-for-field.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Ceiling {
    pub classification: Classification,
    pub sci: bool,
    pub releasable_to: Vec<String>,
    pub cui_permitted: bool,
    pub cui_categories_permitted: Vec<String>,
    pub dissemination_permitted: Vec<String>,
    pub accreditation_ref: Option<String>,
}

/// The coarse ingest gate (the "bludgeon") — one derived bit, no lattice math.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum IngestPosture {
    Public,
    Gated,
}

impl Ceiling {
    /// The compiled Public default: the wide-open baseline a bare Maknae runs at.
    pub fn baseline() -> Ceiling {
        Ceiling {
            classification: Classification::Unclassified,
            sci: false,
            releasable_to: Vec::new(),
            cui_permitted: false,
            cui_categories_permitted: Vec::new(),
            dissemination_permitted: vec!["Distribution Statement A".to_string()],
            accreditation_ref: None,
        }
    }

    /// `Public` iff the ceiling equals the baseline; any above-baseline signal → `Gated`.
    pub fn ingest_posture(&self) -> IngestPosture {
        if *self == Ceiling::baseline() {
            IngestPosture::Public
        } else {
            IngestPosture::Gated
        }
    }
}

use crate::{ConfigError, Value};

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
    get(m, key).ok_or_else(|| err(format!("core.handling.ceiling: missing '{key}'")))
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

impl Classification {
    /// Case-sensitive exact match on the canonical spellings (`_ceiling.py`).
    fn from_canonical(s: &str) -> Option<Classification> {
        match s {
            "UNCLASSIFIED" => Some(Classification::Unclassified),
            "CONFIDENTIAL" => Some(Classification::Confidential),
            "SECRET" => Some(Classification::Secret),
            "TOP SECRET" => Some(Classification::TopSecret),
            _ => None,
        }
    }
}

/// Read the `core` section's classification ceiling (spec ②c §4). Absent/non-map/no
/// `handling` → baseline (Public). A present `handling` is validated strictly per
/// `lake.schema.json`; any violation → `InvalidCeiling`.
pub fn ceiling_from_core(core: Option<&Value>) -> Result<Ceiling, ConfigError> {
    let core_map = match core.and_then(as_map) {
        Some(m) => m,
        None => return Ok(Ceiling::baseline()), // None / non-map core → baseline
    };
    match get(core_map, "handling") {
        None => Ok(Ceiling::baseline()), // no handling block → baseline
        Some(handling) => parse_handling(handling),
    }
}

fn parse_handling(handling: &Value) -> Result<Ceiling, ConfigError> {
    let hmap = as_map(handling).ok_or_else(|| err("core.handling is not a map"))?;
    // additionalProperties: false
    for (k, _) in hmap {
        if k != "ceiling" && k != "accreditation_ref" {
            return Err(err(format!("core.handling: unknown key '{k}'")));
        }
    }
    // required: [ceiling, accreditation_ref]
    let accreditation_ref = match get(hmap, "accreditation_ref") {
        None => return Err(err("core.handling: missing 'accreditation_ref'")),
        Some(Value::Null) => None,
        Some(Value::Str(s)) => Some(s.clone()),
        Some(_) => {
            return Err(err(
                "core.handling.accreditation_ref must be a string or null",
            ))
        }
    };
    let ceiling = get(hmap, "ceiling").ok_or_else(|| err("core.handling: missing 'ceiling'"))?;
    parse_ceiling(ceiling, accreditation_ref)
}

fn parse_ceiling(
    ceiling: &Value,
    accreditation_ref: Option<String>,
) -> Result<Ceiling, ConfigError> {
    const KEYS: [&str; 6] = [
        "classification",
        "sci",
        "releasable_to",
        "cui_permitted",
        "cui_categories_permitted",
        "dissemination_permitted",
    ];
    let m = as_map(ceiling).ok_or_else(|| err("core.handling.ceiling is not a map"))?;
    // additionalProperties: false
    for (k, _) in m {
        if !KEYS.contains(&k.as_str()) {
            return Err(err(format!("core.handling.ceiling: unknown key '{k}'")));
        }
    }
    // required + typed (field() errors on a missing required key)
    let classification = {
        let raw = as_str(field(m, "classification")?)
            .ok_or_else(|| err("classification must be a string"))?;
        Classification::from_canonical(raw)
            .ok_or_else(|| err(format!("classification: unrecognized level '{raw}'")))?
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

    #[test]
    fn baseline_is_the_public_default() {
        let b = Ceiling::baseline();
        // Pin the concrete baseline field values (kills mutants that alter baseline()).
        assert_eq!(b.classification, Classification::Unclassified);
        assert!(!b.sci);
        assert!(b.releasable_to.is_empty());
        assert!(!b.cui_permitted);
        assert!(b.cui_categories_permitted.is_empty());
        assert_eq!(
            b.dissemination_permitted,
            vec!["Distribution Statement A".to_string()]
        );
        assert_eq!(b.accreditation_ref, None);
        assert_eq!(b.ingest_posture(), IngestPosture::Public);
    }

    #[test]
    fn each_above_baseline_signal_is_gated() {
        // Every deviation from baseline, in isolation, projects to Gated.
        let mut c = Ceiling::baseline();
        c.classification = Classification::Secret;
        assert_eq!(c.ingest_posture(), IngestPosture::Gated, "classification");
        let mut c = Ceiling::baseline();
        c.sci = true;
        assert_eq!(c.ingest_posture(), IngestPosture::Gated, "sci");
        let mut c = Ceiling::baseline();
        c.cui_permitted = true;
        assert_eq!(c.ingest_posture(), IngestPosture::Gated, "cui_permitted");
        let mut c = Ceiling::baseline();
        c.releasable_to = vec!["REL FVEY".into()];
        assert_eq!(c.ingest_posture(), IngestPosture::Gated, "releasable_to");
        let mut c = Ceiling::baseline();
        c.cui_categories_permitted = vec!["SP-PRVCY".into()];
        assert_eq!(
            c.ingest_posture(),
            IngestPosture::Gated,
            "cui_categories_permitted"
        );
        let mut c = Ceiling::baseline();
        c.dissemination_permitted = vec!["Distribution Statement C".into()];
        assert_eq!(
            c.ingest_posture(),
            IngestPosture::Gated,
            "dissemination_permitted"
        );
        let mut c = Ceiling::baseline();
        c.accreditation_ref = Some("ATO-123".into());
        assert_eq!(
            c.ingest_posture(),
            IngestPosture::Gated,
            "accreditation_ref"
        );
    }

    use crate::{load_str, ConfigError, Value};

    // Parse a YAML snippet representing the `core` section's VALUE (a map).
    fn core(yaml: &str) -> Value {
        load_str(yaml).expect("test yaml parses")
    }

    // A full, conformant, baseline `handling` block (all six + accreditation_ref).
    // `\n`-escaped (not a `"\`-continuation literal) so no YAML line sits at column 0
    // inside the test module — the coverage gate splits production/test at column 0.
    const BASE: &str = "handling:\n  ceiling:\n    classification: UNCLASSIFIED\n    sci: false\n    releasable_to: []\n    cui_permitted: false\n    cui_categories_permitted: []\n    dissemination_permitted: [\"Distribution Statement A\"]\n  accreditation_ref: null\n";

    #[test]
    fn absent_core_is_baseline_public() {
        assert_eq!(ceiling_from_core(None).unwrap(), Ceiling::baseline());
        assert_eq!(
            ceiling_from_core(None).unwrap().ingest_posture(),
            IngestPosture::Public
        );
    }

    #[test]
    fn core_without_handling_is_baseline() {
        let v = core("identity:\n  name: maknae-1\n");
        assert_eq!(ceiling_from_core(Some(&v)).unwrap(), Ceiling::baseline());
    }

    #[test]
    fn non_map_core_is_baseline() {
        let v = Value::Str("nonsense".into());
        assert_eq!(ceiling_from_core(Some(&v)).unwrap(), Ceiling::baseline());
    }

    #[test]
    fn full_baseline_block_parses_to_baseline_public() {
        let v = core(BASE);
        assert_eq!(ceiling_from_core(Some(&v)).unwrap(), Ceiling::baseline());
        assert_eq!(
            ceiling_from_core(Some(&v)).unwrap().ingest_posture(),
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
            // baseline → Gated. The coarse bit is "is this the wide-open Public default?"
            // — any explicit, well-formed deviation (even a more-restrictive-looking one)
            // is a declaration to be read by the -dcs scalpel, so it reads as Gated here.
            // Not a fail-open: absent/malformed still → Public/error.
            BASE.replace(
                "dissemination_permitted: [\"Distribution Statement A\"]",
                "dissemination_permitted: []",
            ),
            BASE.replace("accreditation_ref: null", "accreditation_ref: \"ATO-123\""),
        ];
        for y in cases {
            let v = core(&y);
            let c = ceiling_from_core(Some(&v)).expect("valid ceiling");
            assert_eq!(c.ingest_posture(), IngestPosture::Gated, "yaml:\n{y}");
        }
    }

    #[test]
    fn each_recognized_classification_parses() {
        // Exercises every from_canonical arm (UNCLASSIFIED via BASE elsewhere; the
        // other three here — incl. "TOP SECRET" with its space).
        for (raw, want) in [
            ("CONFIDENTIAL", Classification::Confidential),
            ("SECRET", Classification::Secret),
            ("TOP SECRET", Classification::TopSecret),
        ] {
            let v = core(&BASE.replace(
                "classification: UNCLASSIFIED",
                &format!("classification: {raw}"),
            ));
            assert_eq!(
                ceiling_from_core(Some(&v)).unwrap().classification,
                want,
                "level {raw}"
            );
        }
    }

    #[test]
    fn each_missing_ceiling_field_is_invalid() {
        // Exhaustively demonstrate "no partial blocks" (spec §4): removing ANY one of
        // the six required ceiling fields → InvalidCeiling (not a silent baseline fill).
        for line in [
            "    classification: UNCLASSIFIED\n",
            "    sci: false\n",
            "    releasable_to: []\n",
            "    cui_permitted: false\n",
            "    cui_categories_permitted: []\n",
            "    dissemination_permitted: [\"Distribution Statement A\"]\n",
        ] {
            let v = core(&BASE.replace(line, ""));
            assert!(
                matches!(
                    ceiling_from_core(Some(&v)),
                    Err(ConfigError::InvalidCeiling { .. })
                ),
                "removing {line:?} should be InvalidCeiling"
            );
        }
    }

    #[test]
    fn invalids_are_invalid_ceiling() {
        let bad = [
            // (missing required ceiling fields are covered exhaustively by
            //  each_missing_ceiling_field_is_invalid)
            // handling missing accreditation_ref
            BASE.replace("  accreditation_ref: null\n", ""),
            // handling missing ceiling (accreditation_ref present, no ceiling)
            "handling:\n  accreditation_ref: null\n".to_string(),
            // additionalProperties: unknown key at the HANDLING level
            "handling:\n  bogus: 1\n  ceiling:\n    classification: UNCLASSIFIED\n    sci: false\n    releasable_to: []\n    cui_permitted: false\n    cui_categories_permitted: []\n    dissemination_permitted: [\"Distribution Statement A\"]\n  accreditation_ref: null\n".to_string(),
            // additionalProperties: unknown key in ceiling
            BASE.replace(
                "    cui_permitted: false\n",
                "    cui_permitted: false\n    cui_permited: true\n",
            ),
            // classification wrong type
            BASE.replace("classification: UNCLASSIFIED", "classification: 42"),
            // classification unrecognized (typo fail-open guard)
            BASE.replace("classification: UNCLASSIFIED", "classification: SEKRET"),
            // classification wrong case (case-sensitive per _ceiling.py)
            BASE.replace("classification: UNCLASSIFIED", "classification: secret"),
            // sci wrong type
            BASE.replace("sci: false", "sci: \"yes\""),
            // cui_permitted wrong type
            BASE.replace("cui_permitted: false", "cui_permitted: \"yes\""),
            // releasable_to scalar not seq
            BASE.replace("releasable_to: []", "releasable_to: REL FVEY"),
            // cui_categories_permitted scalar not seq
            BASE.replace("cui_categories_permitted: []", "cui_categories_permitted: SP-PRVCY"),
            // dissemination_permitted wrong type (scalar not seq)
            BASE.replace(
                "dissemination_permitted: [\"Distribution Statement A\"]",
                "dissemination_permitted: 5",
            ),
            // accreditation_ref wrong type
            BASE.replace("accreditation_ref: null", "accreditation_ref: 7"),
            // ceiling a scalar not a map
            "handling:\n  ceiling: hello\n  accreditation_ref: null\n".to_string(),
            // handling a scalar not a map
            "handling: hello\n".to_string(),
        ];
        for y in bad {
            let v = core(&y);
            assert!(
                matches!(
                    ceiling_from_core(Some(&v)),
                    Err(ConfigError::InvalidCeiling { .. })
                ),
                "expected InvalidCeiling for yaml:\n{y}"
            );
        }
    }
}
