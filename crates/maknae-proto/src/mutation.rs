//! Correlated subject-side mutation reports. All outcomes are client claims,
//! never attestations of operating-system effects.
use serde::{Deserialize, Serialize};

pub const MAX_MUTATION_EFFECTS: u32 = 4096;
pub const MAX_MUTATION_DEPTH: u16 = 128;
pub const MAX_MUTATION_BATCH: usize = 32;
pub const MAX_MUTATION_PATH_BYTES: usize = 4096;

/// Correlation within a live authenticated connection, never a bearer capability.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct MutationId {
    pub session_id: u64,
    pub intent_seq: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum WriteMode {
    Existing,
    CreateExclusive,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct MutationLimits {
    pub max_effects: u32,
    pub max_depth: u16,
    /// Absolute attempt window from issuance; supplied by transport configuration.
    pub deadline_ms: u64,
    /// Content bytes a ReadFile grant permits; 0 on every other grant.
    pub max_bytes: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum MutationScope {
    Exact {
        path: String,
        effect: ReportedEffect,
    },
    RecursiveDelete {
        root: String,
    },
    /// Consecutive prepared, authorized mkdir-p prefixes, including existing
    /// prefixes. The first prospective path is depth one from the existing ancestor.
    Directories {
        paths: Vec<String>,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MutationGrant {
    pub id: MutationId,
    pub scope: MutationScope,
    pub limits: MutationLimits,
    pub label: ObjectLabel,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ReportedEffect {
    CreatedFile,
    ReplacedFile,
    CreatedDirectory,
    DeletedEntry,
    ReadFile,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ReportedFinish {
    Success,
    OsRefused,
    Partial,
    LimitReached,
    PathChanged,
    UnsupportedName,
    DurabilityUnknown,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EffectEntry {
    /// Canonical absolute path, identical to the prepared namespace spelling.
    pub path: String,
    pub effect: ReportedEffect,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub length: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub range: Option<ByteRange>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub lines: Option<LineSpan>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct ByteRange {
    pub start: u64,
    pub end: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct LineSpan {
    pub first: u64,
    pub last: u64,
    pub complete_last: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum MutationReport {
    Batch {
        id: MutationId,
        first_index: u32,
        effects: Vec<EffectEntry>,
    },
    Finished {
        id: MutationId,
        next_index: u32,
        outcome: ReportedFinish,
        stopped_at: Option<String>,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct MutationAck {
    pub id: MutationId,
    pub next_index: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ObjectLabel {
    pub level: String,
    pub categories: Vec<CategoryEntry>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CategoryEntry {
    pub category: String,
    pub provenance: Provenance,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Provenance {
    Declared,
    Region,
    Detected {
        detector: String,
        tier: DetectionTier,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum DetectionTier {
    Validated,
    Contextual,
    PatternOnly,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_read_effect_carries_its_range_and_lines_and_other_effects_omit_them() {
        let id = MutationId {
            session_id: 1,
            intent_seq: 2,
        };
        let read = EffectEntry {
            path: "/h/f".into(),
            effect: ReportedEffect::ReadFile,
            length: Some(3),
            range: Some(ByteRange { start: 10, end: 13 }),
            lines: Some(LineSpan {
                first: 2,
                last: 2,
                complete_last: false,
            }),
        };
        let report = MutationReport::Batch {
            id,
            first_index: 0,
            effects: vec![read],
        };
        let bytes = crate::encode_mutation_report(&report).unwrap();
        assert_eq!(crate::decode_mutation_report(&bytes).unwrap(), report);
        let dir = EffectEntry {
            path: "/h/d".into(),
            effect: ReportedEffect::CreatedDirectory,
            length: None,
            range: None,
            lines: None,
        };
        let bytes = crate::encode_mutation_report(&MutationReport::Batch {
            id,
            first_index: 0,
            effects: vec![dir],
        })
        .unwrap();
        assert!(!bytes.windows(5).any(|w| w == b"range"));
        assert!(!bytes.windows(5).any(|w| w == b"lines"));
    }

    fn roundtrip<T>(value: T)
    where
        T: Serialize + serde::de::DeserializeOwned + PartialEq + std::fmt::Debug,
    {
        let mut encoded = Vec::new();
        ciborium::into_writer(&value, &mut encoded).unwrap();
        let decoded: T = ciborium::from_reader(encoded.as_slice()).unwrap();
        assert_eq!(decoded, value);
    }

    #[test]
    fn mutation_exchange_preserves_scope_correlation_and_report_origin() {
        let id = MutationId {
            session_id: 91,
            intent_seq: 37,
        };
        for (scope, max_bytes) in [
            (
                MutationScope::Exact {
                    path: "/sentinel/create".into(),
                    effect: ReportedEffect::CreatedFile,
                },
                0,
            ),
            (
                MutationScope::Exact {
                    path: "/sentinel/read".into(),
                    effect: ReportedEffect::ReadFile,
                },
                65024,
            ),
            (
                MutationScope::RecursiveDelete {
                    root: "/sentinel/delete".into(),
                },
                0,
            ),
            (
                MutationScope::Directories {
                    paths: vec!["/sentinel/a".into(), "/sentinel/a/b".into()],
                },
                0,
            ),
        ] {
            roundtrip(MutationGrant {
                id,
                scope,
                limits: MutationLimits {
                    max_effects: 4096,
                    max_depth: 128,
                    deadline_ms: 5000,
                    max_bytes,
                },
                label: crate::ObjectLabel {
                    level: "UNCLASSIFIED".into(),
                    categories: vec![],
                },
            });
        }
        for effect in [
            ReportedEffect::CreatedFile,
            ReportedEffect::ReplacedFile,
            ReportedEffect::CreatedDirectory,
            ReportedEffect::DeletedEntry,
            ReportedEffect::ReadFile,
        ] {
            roundtrip(MutationReport::Batch {
                id,
                first_index: 17,
                effects: vec![EffectEntry {
                    path: "/sentinel/effect".into(),
                    effect,
                    length: None,
                    range: None,
                    lines: None,
                }],
            });
        }
        roundtrip(MutationReport::Batch {
            id,
            first_index: 0,
            effects: vec![EffectEntry {
                path: "/sentinel/read".into(),
                effect: ReportedEffect::ReadFile,
                length: Some(u64::MAX),
                range: None,
                lines: None,
            }],
        });
        for outcome in [
            ReportedFinish::Success,
            ReportedFinish::OsRefused,
            ReportedFinish::Partial,
            ReportedFinish::LimitReached,
            ReportedFinish::PathChanged,
            ReportedFinish::UnsupportedName,
            ReportedFinish::DurabilityUnknown,
        ] {
            roundtrip(MutationReport::Finished {
                id,
                next_index: 18,
                outcome,
                stopped_at: Some("/sentinel/stopped".into()),
            });
        }
        roundtrip(MutationAck { id, next_index: 18 });
        roundtrip(WriteMode::Existing);
        roundtrip(WriteMode::CreateExclusive);
    }

    #[test]
    fn a_read_effect_carries_its_length_and_no_other_effect_encodes_one() {
        let encoded = |length| {
            let mut bytes = Vec::new();
            let entry = EffectEntry {
                path: "/sentinel/read".into(),
                effect: ReportedEffect::ReadFile,
                length,
                range: None,
                lines: None,
            };
            ciborium::into_writer(&entry, &mut bytes).unwrap();
            let value: ciborium::Value = ciborium::from_reader(bytes.as_slice()).unwrap();
            value
                .into_map()
                .unwrap()
                .into_iter()
                .map(|(k, v)| (k.into_text().unwrap(), v))
                .collect::<Vec<_>>()
        };
        assert!(!encoded(None).iter().any(|(k, _)| k == "length"));
        assert!(encoded(Some(7))
            .iter()
            .any(|(k, v)| k == "length" && *v == ciborium::Value::Integer(7.into())));
    }
}
