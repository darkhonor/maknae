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
    #[serde(default)]
    pub sensitive: Vec<String>,
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
        sensitive: Vec::new(),
    }
}

/// The personal `sensitive.yaml` entries `session.new` carries, refused whole if one
/// is too long for a path or fails the host list's parser.
pub fn personal_sensitive(entries: &[String]) -> Result<(), String> {
    let limit = maknae_proto::MAX_MUTATION_PATH_BYTES;
    if let Some(at) = entries.iter().position(|e| e.len() > limit) {
        return Err(format!(
            "personal sensitive entry {at} is longer than {limit} bytes"
        ));
    }
    maknae_config::SensitiveList::from_entries(entries)
        .map(drop)
        .map_err(|e| format!("personal {e}"))
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
    fn a_malformed_personal_entry_is_refused_with_the_entry_named() {
        assert_eq!(personal_sensitive(&[]), Ok(()));
        assert_eq!(
            personal_sensitive(&["~/sentinel-617/**".into(), "/srv/sentinel-617".into()]),
            Ok(())
        );
        let why = personal_sensitive(&["/ok".into(), "~bob/x".into()]).unwrap_err();
        assert!(why.starts_with("personal sensitive.yaml: "), "{why}");
        assert!(why.contains("'~bob/x'"), "{why}");
    }

    #[test]
    fn a_personal_entry_is_bounded_by_the_path_limit() {
        let limit = maknae_proto::MAX_MUTATION_PATH_BYTES;
        let exact = format!("/{}", "a".repeat(limit - 1));
        assert_eq!(personal_sensitive(std::slice::from_ref(&exact)), Ok(()));
        let over = format!("{exact}a");
        assert_eq!(
            personal_sensitive(&["/ok".into(), over]),
            Err(format!(
                "personal sensitive entry 1 is longer than {limit} bytes"
            ))
        );
    }

    #[test]
    fn a_record_written_before_the_personal_list_decodes_with_none() {
        let id = ConversationId::parse(&"c".repeat(32)).unwrap();
        let rec = opened(id.clone(), 9, "/w".into(), 1, "UNCLASSIFIED");
        let mut value: ciborium::Value =
            ciborium::from_reader(encode(&rec).unwrap().as_slice()).unwrap();
        let ciborium::Value::Map(fields) = &mut value else {
            panic!("a record encodes as a map");
        };
        fields.retain(|(k, _)| k.as_text() != Some("sensitive"));
        let mut legacy = Vec::new();
        ciborium::into_writer(&value, &mut legacy).unwrap();
        assert_eq!(decode(&legacy, &id).unwrap(), rec);
    }

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
                sensitive: Vec::new(),
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

    fn sample() -> ConversationRecord {
        let id = ConversationId::parse(&"c".repeat(32)).unwrap();
        let mut rec = opened(id, 5, "/w".into(), 3, "UNCLASSIFIED");
        rec.last_reply = Some([9u8; 32]);
        rec.fence = 4;
        rec.provenance.sources.push("src".into());
        rec
    }

    #[test]
    fn an_encoded_record_decodes_to_itself() {
        let rec = sample();
        assert_eq!(decode(&encode(&rec).unwrap(), &rec.id).unwrap(), rec);
    }

    #[test]
    fn a_record_naming_another_conversation_is_an_id_mismatch() {
        let rec = sample();
        let other = ConversationId::parse(&"d".repeat(32)).unwrap();
        assert_eq!(
            decode(&encode(&rec).unwrap(), &other),
            Err(StoreError::IdMismatch)
        );
    }

    #[test]
    fn bytes_that_are_not_cbor_are_corrupt() {
        let id = sample().id;
        assert_eq!(decode(&[0xff, 0xff, 0xff], &id), Err(StoreError::Corrupt));
        assert_eq!(decode(&[], &id), Err(StoreError::Corrupt));
    }

    #[test]
    fn a_truncated_record_is_corrupt() {
        let rec = sample();
        let bytes = encode(&rec).unwrap();
        assert_eq!(
            decode(&bytes[..bytes.len() / 2], &rec.id),
            Err(StoreError::Corrupt)
        );
    }

    #[test]
    fn a_record_with_an_unknown_field_is_corrupt() {
        let rec = sample();
        let mut value: ciborium::Value = ciborium::from_reader(&encode(&rec).unwrap()[..]).unwrap();
        value.as_map_mut().unwrap().push((
            ciborium::Value::Text("extra".into()),
            ciborium::Value::Bool(true),
        ));
        let mut bytes = Vec::new();
        ciborium::into_writer(&value, &mut bytes).unwrap();
        assert_eq!(decode(&bytes, &rec.id), Err(StoreError::Corrupt));
    }
}
