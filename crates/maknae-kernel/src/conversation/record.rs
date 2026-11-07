use super::chain::ChainHead;
use super::store::StoreError;
use maknae_proto::ConversationId;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Provenance {
    pub high_water: String,
    pub sources: Vec<String>,
}

impl Provenance {
    pub fn new(lowest_level: &str) -> Self {
        Self {
            high_water: lowest_level.to_owned(),
            sources: Vec::new(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ConversationRecord {
    pub id: ConversationId,
    pub owner: u32,
    pub cwd: String,
    pub opened_at: u64,
    pub last_active: u64,
    pub full: bool,
    pub chain: ChainHead,
    pub turns: u64,
    pub bytes: u64,
    pub last_reply: Option<[u8; 32]>,
    pub fence: u64,
    pub provenance: Provenance,
}

pub(crate) fn encode(rec: &ConversationRecord) -> Result<Vec<u8>, StoreError> {
    let mut out = Vec::new();
    ciborium::into_writer(rec, &mut out).map_err(|e| StoreError::Io(e.to_string()))?;
    Ok(out)
}

pub(crate) fn decode(
    plain: &[u8],
    expected: &ConversationId,
) -> Result<ConversationRecord, StoreError> {
    let rec: ConversationRecord = ciborium::from_reader(plain).map_err(|_| StoreError::Corrupt)?;
    if rec.id != *expected {
        return Err(StoreError::IdMismatch);
    }
    Ok(rec)
}
