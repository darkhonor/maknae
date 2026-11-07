use super::record::ConversationRecord;
use super::store::StoreError;

pub const CONVERSATION_MAX_BYTES: u64 = 256 << 20;
pub const OWNER_MAX_ACTIVE: usize = 32;
pub const CONVERSATION_IDLE_MAX: u64 = 24 * 60 * 60;
pub const LIST_PAGE_MAX: usize = 12;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BoundRefusal {
    ConversationFull,
    OwnerFull,
}

impl BoundRefusal {
    pub fn message(self) -> &'static str {
        match self {
            Self::ConversationFull => "conversation is full",
            Self::OwnerFull => "too many active conversations",
        }
    }

    pub fn wire_code(self) -> maknae_proto::ProtoErrCode {
        maknae_proto::ProtoErrCode::TooLarge
    }

    pub fn from_store(e: &StoreError) -> Option<Self> {
        match e {
            StoreError::OwnerFull => Some(Self::OwnerFull),
            StoreError::NotFound
            | StoreError::StaleFence
            | StoreError::Exists
            | StoreError::IdMismatch
            | StoreError::Corrupt
            | StoreError::Io(_) => None,
        }
    }
}

pub fn check_turn(rec: &ConversationRecord, add: u64) -> Result<(), BoundRefusal> {
    if rec.full || rec.bytes.saturating_add(add) > CONVERSATION_MAX_BYTES {
        return Err(BoundRefusal::ConversationFull);
    }
    Ok(())
}

pub fn idle_cutoff(now_epoch: u64) -> u64 {
    now_epoch.saturating_sub(CONVERSATION_IDLE_MAX)
}

pub fn page_limit() -> usize {
    LIST_PAGE_MAX
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::conversation::chain::ChainHead;
    use crate::conversation::record::Provenance;
    use maknae_proto::{
        encode_response, ConversationId, ConversationPage, ConversationView, Payload, RespResult,
        Response, CONTROL_RESPONSE_MAX, MAX_MUTATION_PATH_BYTES, PROTOCOL_VERSION,
    };

    fn rec(bytes: u64, full: bool) -> ConversationRecord {
        let id = ConversationId::parse(&"7".repeat(32)).unwrap();
        ConversationRecord {
            chain: ChainHead::genesis(&id),
            id,
            owner: 1170,
            cwd: "/home/sentinel-170".into(),
            opened_at: 1,
            last_active: 1,
            full,
            turns: 0,
            bytes,
            last_reply: None,
            fence: 0,
            provenance: Provenance::new("UNCLASSIFIED"),
        }
    }

    #[test]
    fn the_bounds_are_the_ruled_values() {
        assert_eq!(CONVERSATION_MAX_BYTES, 268_435_456);
        assert_eq!(OWNER_MAX_ACTIVE, 32);
        assert_eq!(CONVERSATION_IDLE_MAX, 86_400);
        assert_eq!(page_limit(), 12);
    }

    #[test]
    fn check_turn_refuses_at_and_over_the_cap() {
        assert_eq!(check_turn(&rec(0, false), 0), Ok(()));
        assert_eq!(check_turn(&rec(0, false), CONVERSATION_MAX_BYTES), Ok(()));
        assert_eq!(
            check_turn(&rec(CONVERSATION_MAX_BYTES - 10, false), 10),
            Ok(())
        );
        assert_eq!(
            check_turn(&rec(CONVERSATION_MAX_BYTES - 10, false), 11),
            Err(BoundRefusal::ConversationFull)
        );
        assert_eq!(
            check_turn(&rec(0, false), CONVERSATION_MAX_BYTES + 1),
            Err(BoundRefusal::ConversationFull)
        );
        assert_eq!(
            check_turn(&rec(u64::MAX, false), 1),
            Err(BoundRefusal::ConversationFull)
        );
    }

    #[test]
    fn a_full_conversation_refuses_every_turn_even_an_empty_one() {
        assert_eq!(
            check_turn(&rec(0, true), 0),
            Err(BoundRefusal::ConversationFull)
        );
    }

    #[test]
    fn idle_cutoff_is_24h_before_now() {
        assert_eq!(idle_cutoff(1_000_000), 1_000_000 - 86_400);
        assert_eq!(idle_cutoff(86_400), 0);
        assert_eq!(idle_cutoff(5), 0);
    }

    #[test]
    fn each_refusal_has_its_own_fixed_message() {
        assert_eq!(
            BoundRefusal::ConversationFull.message(),
            "conversation is full"
        );
        assert_eq!(
            BoundRefusal::OwnerFull.message(),
            "too many active conversations"
        );
    }

    #[test]
    fn every_bound_refusal_answers_too_large() {
        for r in [BoundRefusal::ConversationFull, BoundRefusal::OwnerFull] {
            assert_eq!(r.wire_code(), maknae_proto::ProtoErrCode::TooLarge);
        }
    }

    #[test]
    fn only_the_owner_count_refusal_maps_from_the_store() {
        assert_eq!(
            BoundRefusal::from_store(&StoreError::OwnerFull),
            Some(BoundRefusal::OwnerFull)
        );
        for e in [
            StoreError::NotFound,
            StoreError::StaleFence,
            StoreError::Exists,
            StoreError::IdMismatch,
            StoreError::Corrupt,
            StoreError::Io("x".into()),
        ] {
            assert_eq!(BoundRefusal::from_store(&e), None, "{e:?}");
        }
    }

    #[test]
    fn a_full_page_of_longest_cwds_fits_a_control_response() {
        let id = ConversationId::parse(&"f".repeat(32)).unwrap();
        let view = ConversationView {
            conversation: id.clone(),
            cwd: "a".repeat(MAX_MUTATION_PATH_BYTES),
            opened_at: u64::MAX,
            last_active: u64::MAX,
            turns: u64::MAX,
            bytes: u64::MAX,
            chain_head: "f".repeat(64),
        };
        let bytes = encode_response(&Response {
            protocol_version: PROTOCOL_VERSION,
            result: RespResult::Ok(Payload::ConversationList(ConversationPage {
                entries: vec![view; page_limit()],
                next: Some(id),
            })),
        })
        .unwrap();
        assert!(bytes.len() <= CONTROL_RESPONSE_MAX, "{}", bytes.len());
    }
}
