use std::fmt;

pub const CHECKPOINT_ACTION: &str = "graph.checkpoint";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Checkpoint {
    pub revision: u64,
    pub digest: [u8; 32],
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StoreFacts {
    pub revision: u64,
    pub digest: [u8; 32],
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AnchorState {
    Verified,
    Advanced,
    Unavailable,
}

impl AnchorState {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Verified => "verified",
            Self::Advanced => "advanced",
            Self::Unavailable => "rollback-anchor-unavailable",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Refusal {
    RolledBack { store: u64, checkpoint: u64 },
    Substituted { revision: u64 },
    Missing { checkpoint: u64 },
}

impl fmt::Display for Refusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::RolledBack { store, checkpoint } => write!(
                f,
                "graph store revision {store} is older than the audited checkpoint {checkpoint}: rolled back"
            ),
            Self::Substituted { revision } => write!(
                f,
                "graph store at revision {revision} differs from the audited checkpoint: substituted"
            ),
            Self::Missing { checkpoint } => write!(
                f,
                "graph store is missing but the audit trail holds checkpoint {checkpoint}"
            ),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BootAction {
    SeedFirstBoot,
    SeedAuthorized { revision: u64 },
    Load(AnchorState),
    Refuse(Refusal),
}

pub fn assess(
    store: Option<StoreFacts>,
    checkpoint: Option<Checkpoint>,
    reseed_authorized: bool,
) -> BootAction {
    if reseed_authorized {
        let floor = store
            .map_or(0, |s| s.revision)
            .max(checkpoint.map_or(0, |c| c.revision));
        return BootAction::SeedAuthorized {
            revision: floor + 1,
        };
    }
    match (store, checkpoint) {
        (None, None) => BootAction::SeedFirstBoot,
        (None, Some(c)) => BootAction::Refuse(Refusal::Missing {
            checkpoint: c.revision,
        }),
        (Some(_), None) => BootAction::Load(AnchorState::Unavailable),
        (Some(s), Some(c)) if s.revision < c.revision => BootAction::Refuse(Refusal::RolledBack {
            store: s.revision,
            checkpoint: c.revision,
        }),
        (Some(s), Some(c)) if s.revision == c.revision && s.digest != c.digest => {
            BootAction::Refuse(Refusal::Substituted {
                revision: s.revision,
            })
        }
        (Some(s), Some(c)) if s.revision == c.revision => BootAction::Load(AnchorState::Verified),
        (Some(_), Some(_)) => BootAction::Load(AnchorState::Advanced),
    }
}

pub fn parse_checkpoint(line: &[u8]) -> Option<Checkpoint> {
    let v: serde_json::Value = serde_json::from_slice(line).ok()?;
    if v.get("action")?.as_str()? != CHECKPOINT_ACTION {
        return None;
    }
    let graph = v.get("graph")?;
    let revision = graph.get("revision")?.as_u64()?;
    let hex = graph.get("ciphertext_sha256")?.as_str()?;
    if hex.len() != 64
        || !hex
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return None;
    }
    let mut digest = [0u8; 32];
    for (i, out) in digest.iter_mut().enumerate() {
        *out = u8::from_str_radix(&hex[2 * i..2 * i + 2], 16).ok()?;
    }
    Some(Checkpoint { revision, digest })
}

#[cfg(test)]
mod tests {
    use super::*;

    const D1: [u8; 32] = [1; 32];
    const D2: [u8; 32] = [2; 32];
    fn s(revision: u64, digest: [u8; 32]) -> Option<StoreFacts> {
        Some(StoreFacts { revision, digest })
    }
    fn c(revision: u64, digest: [u8; 32]) -> Option<Checkpoint> {
        Some(Checkpoint { revision, digest })
    }

    #[test]
    fn decision_table() {
        assert_eq!(assess(None, None, false), BootAction::SeedFirstBoot);
        assert_eq!(
            assess(None, c(4, D1), false),
            BootAction::Refuse(Refusal::Missing { checkpoint: 4 })
        );
        assert_eq!(
            assess(s(4, D1), None, false),
            BootAction::Load(AnchorState::Unavailable)
        );
        assert_eq!(
            assess(s(3, D1), c(4, D1), false),
            BootAction::Refuse(Refusal::RolledBack {
                store: 3,
                checkpoint: 4
            })
        );
        assert_eq!(
            assess(s(4, D2), c(4, D1), false),
            BootAction::Refuse(Refusal::Substituted { revision: 4 })
        );
        assert_eq!(
            assess(s(4, D1), c(4, D1), false),
            BootAction::Load(AnchorState::Verified)
        );
        assert_eq!(
            assess(s(5, D2), c(4, D1), false),
            BootAction::Load(AnchorState::Advanced)
        );
    }

    #[test]
    fn a_reseed_outranks_every_store_state_and_seeds_past_the_checkpoint() {
        assert_eq!(
            assess(None, None, true),
            BootAction::SeedAuthorized { revision: 1 }
        );
        assert_eq!(
            assess(None, c(4, D1), true),
            BootAction::SeedAuthorized { revision: 5 }
        );
        assert_eq!(
            assess(s(3, D1), c(4, D1), true),
            BootAction::SeedAuthorized { revision: 5 }
        );
        assert_eq!(
            assess(s(9, D1), c(4, D1), true),
            BootAction::SeedAuthorized { revision: 10 }
        );
        assert_eq!(
            assess(s(9, D1), None, true),
            BootAction::SeedAuthorized { revision: 10 }
        );
    }

    #[test]
    fn anchor_and_refusal_text() {
        assert_eq!(AnchorState::Verified.as_str(), "verified");
        assert_eq!(AnchorState::Advanced.as_str(), "advanced");
        assert_eq!(
            AnchorState::Unavailable.as_str(),
            "rollback-anchor-unavailable"
        );
        assert_eq!(
            Refusal::RolledBack {
                store: 3,
                checkpoint: 4
            }
            .to_string(),
            "graph store revision 3 is older than the audited checkpoint 4: rolled back"
        );
        assert_eq!(
            Refusal::Substituted { revision: 4 }.to_string(),
            "graph store at revision 4 differs from the audited checkpoint: substituted"
        );
        assert_eq!(
            Refusal::Missing { checkpoint: 4 }.to_string(),
            "graph store is missing but the audit trail holds checkpoint 4"
        );
    }

    fn line(action: &str, graph: &str) -> Vec<u8> {
        format!(r#"{{"action":"{action}","graph":{graph},"seq":1}}"#).into_bytes()
    }

    #[test]
    fn checkpoint_parsing() {
        let hex = "01".repeat(32);
        let ok = line(
            CHECKPOINT_ACTION,
            &format!(r#"{{"revision":7,"ciphertext_sha256":"{hex}"}}"#),
        );
        assert_eq!(
            parse_checkpoint(&ok),
            Some(Checkpoint {
                revision: 7,
                digest: D1
            })
        );
        assert_eq!(
            parse_checkpoint(&line(
                "graph.seed",
                &format!(r#"{{"revision":7,"ciphertext_sha256":"{hex}"}}"#)
            )),
            None
        );
        assert_eq!(
            parse_checkpoint(&line(CHECKPOINT_ACTION, r#"{"revision":7}"#)),
            None
        );
        assert_eq!(
            parse_checkpoint(&line(
                CHECKPOINT_ACTION,
                &format!(r#"{{"ciphertext_sha256":"{hex}"}}"#)
            )),
            None
        );
        assert_eq!(
            parse_checkpoint(&line(
                CHECKPOINT_ACTION,
                &format!(r#"{{"revision":-1,"ciphertext_sha256":"{hex}"}}"#)
            )),
            None
        );
        assert_eq!(
            parse_checkpoint(&line(
                CHECKPOINT_ACTION,
                r#"{"revision":7,"ciphertext_sha256":"zz"}"#
            )),
            None
        );
        let upper = "AB".repeat(32);
        assert_eq!(
            parse_checkpoint(&line(
                CHECKPOINT_ACTION,
                &format!(r#"{{"revision":7,"ciphertext_sha256":"{upper}"}}"#)
            )),
            None
        );
        assert_eq!(parse_checkpoint(b"not json"), None);
        assert_eq!(parse_checkpoint(br#"{"action":"graph.checkpoint"}"#), None);
    }
}
