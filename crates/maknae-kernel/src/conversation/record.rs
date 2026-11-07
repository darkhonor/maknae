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

pub fn mint_id() -> Result<ConversationId, StoreError> {
    let mut bytes = [0u8; 16];
    maknae_crypto::random::fill(&mut bytes)
        .map_err(|_| StoreError::Io("no conversation id from the system random source".into()))?;
    let hex: String = bytes.iter().map(|b| format!("{b:02x}")).collect();
    ConversationId::parse(&hex).ok_or(StoreError::Corrupt)
}

pub fn opened(
    id: ConversationId,
    owner: u32,
    cwd: String,
    now: u64,
    lowest_level: &str,
) -> ConversationRecord {
    ConversationRecord {
        chain: ChainHead::genesis(&id),
        id,
        owner,
        cwd,
        opened_at: now,
        last_active: now,
        full: false,
        turns: 0,
        bytes: 0,
        last_reply: None,
        fence: 0,
        provenance: Provenance::new(lowest_level),
    }
}

pub fn view(rec: &ConversationRecord) -> maknae_proto::ConversationView {
    maknae_proto::ConversationView {
        conversation: rec.id.clone(),
        cwd: rec.cwd.clone(),
        opened_at: rec.opened_at,
        last_active: rec.last_active,
        turns: rec.turns,
        bytes: rec.bytes,
        chain_head: rec.chain.to_hex(),
    }
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_minted_id_is_acceptable_and_fresh() {
        let a = mint_id().unwrap();
        assert!(maknae_proto::conversation_id_is_acceptable(a.as_str()));
        assert_ne!(a, mint_id().unwrap());
    }

    #[test]
    fn an_opened_record_starts_at_genesis_with_nothing_held() {
        let id = ConversationId::parse(&"a".repeat(32)).unwrap();
        let rec = opened(id.clone(), 1170, "/home/s/p".into(), 42, "UNCLASSIFIED");
        assert_eq!(
            rec,
            ConversationRecord {
                chain: ChainHead::genesis(&id),
                id,
                owner: 1170,
                cwd: "/home/s/p".into(),
                opened_at: 42,
                last_active: 42,
                full: false,
                turns: 0,
                bytes: 0,
                last_reply: None,
                fence: 0,
                provenance: Provenance::new("UNCLASSIFIED"),
            }
        );
    }

    #[test]
    fn the_view_carries_the_records_fields() {
        let id = ConversationId::parse(&"b".repeat(32)).unwrap();
        let mut rec = opened(id.clone(), 7, "/c".into(), 1, "UNCLASSIFIED");
        rec.last_active = 9;
        rec.turns = 3;
        rec.bytes = 77;
        assert_eq!(
            view(&rec),
            maknae_proto::ConversationView {
                conversation: id.clone(),
                cwd: "/c".into(),
                opened_at: 1,
                last_active: 9,
                turns: 3,
                bytes: 77,
                chain_head: ChainHead::genesis(&id).to_hex(),
            }
        );
    }
}
