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
        assert_eq!(b.dissemination_permitted, vec!["Distribution Statement A".to_string()]);
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
        assert_eq!(c.ingest_posture(), IngestPosture::Gated, "cui_categories_permitted");
        let mut c = Ceiling::baseline();
        c.dissemination_permitted = vec!["Distribution Statement C".into()];
        assert_eq!(c.ingest_posture(), IngestPosture::Gated, "dissemination_permitted");
        let mut c = Ceiling::baseline();
        c.accreditation_ref = Some("ATO-123".into());
        assert_eq!(c.ingest_posture(), IngestPosture::Gated, "accreditation_ref");
    }
}
