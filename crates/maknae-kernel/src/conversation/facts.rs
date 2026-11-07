use super::chain::{self, Extends};
use super::record::ConversationRecord;
use super::store::{ConversationStore, StoreError};
use maknae_proto::{ConversationId, Turn};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FactState {
    Active,
    Unknown,
    Error,
}

impl FactState {
    pub fn as_attr(self) -> &'static str {
        match self {
            Self::Active => maknae_authz_basic::CONVERSATION_ACTIVE,
            Self::Unknown => maknae_authz_basic::CONVERSATION_UNKNOWN,
            Self::Error => maknae_authz_basic::CONVERSATION_ERROR,
        }
    }
}

pub fn extends_attr(e: Extends) -> &'static str {
    match e {
        Extends::Retry => maknae_authz_basic::EXTENDS_RETRY,
        Extends::Advance { .. } => maknae_authz_basic::EXTENDS_ADVANCE,
        Extends::Rewrite => maknae_authz_basic::EXTENDS_REWRITE,
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ConversationFacts {
    pub state: FactState,
    pub owner: Option<u32>,
    pub extends: Option<Extends>,
}

/// The facts the PDP decides a conversation-citing request on, read from the
/// kernel's own store. `None` when the request cites nothing. A conversation the
/// store does not hold is `Unknown` and names `requester` as its owner (the
/// caller's peer-credential uid, never a client-supplied value). Any store or
/// chain failure other than `NotFound` is `Error`, never `Unknown`.
pub fn gather(
    store: &dyn ConversationStore,
    requester: u32,
    cited: Option<&str>,
    turns: Option<&[Turn]>,
) -> Option<(ConversationFacts, Option<ConversationRecord>)> {
    let cited = cited?;
    let unknown = ConversationFacts {
        state: FactState::Unknown,
        owner: Some(requester),
        extends: None,
    };
    let Some(id) = ConversationId::parse(cited) else {
        return Some((unknown, None));
    };
    let rec = match store.get(&id) {
        Ok(rec) => rec,
        Err(StoreError::NotFound) => return Some((unknown, None)),
        Err(_) => return Some((ERROR, None)),
    };
    let extends = turns
        .map(|turns| chain::extends(&rec.chain, rec.turns, &id, rec.last_reply.as_ref(), turns))
        .transpose();
    Some(settle(rec, extends))
}

const ERROR: ConversationFacts = ConversationFacts {
    state: FactState::Error,
    owner: None,
    extends: None,
};

fn settle(
    rec: ConversationRecord,
    extends: Result<Option<Extends>, chain::ChainError>,
) -> (ConversationFacts, Option<ConversationRecord>) {
    match extends {
        Ok(extends) => (
            ConversationFacts {
                state: FactState::Active,
                owner: Some(rec.owner),
                extends,
            },
            Some(rec),
        ),
        Err(_) => (ERROR, None),
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeleteEffect {
    RemoveActive,
    RecordArchived,
    Refuse,
}

pub fn delete_effect(state: FactState) -> DeleteEffect {
    match state {
        FactState::Active => DeleteEffect::RemoveActive,
        FactState::Unknown => DeleteEffect::RecordArchived,
        FactState::Error => DeleteEffect::Refuse,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::conversation::chain::ChainHead;
    use crate::conversation::mem_store::MemStore;
    use crate::conversation::record::Provenance;
    use crate::conversation::store::{Page, Scan};
    use maknae_io::Zeroizing;
    use maknae_proto::{ContentBlock, SecretText};

    const REQUESTER: u32 = 1170;
    const OWNER: u32 = 4242;

    fn id(c: char) -> ConversationId {
        ConversationId::parse(&c.to_string().repeat(32)).unwrap()
    }

    fn rec(id: ConversationId, owner: u32) -> ConversationRecord {
        ConversationRecord {
            chain: ChainHead::genesis(&id),
            id,
            owner,
            cwd: "/home/sentinel-170/project".into(),
            opened_at: 10,
            last_active: 10,
            full: false,
            turns: 0,
            bytes: 0,
            last_reply: None,
            fence: 0,
            provenance: Provenance::new("UNCLASSIFIED"),
        }
    }

    fn user(s: &str) -> Turn {
        Turn::User {
            content: vec![ContentBlock::Text {
                text: SecretText(Zeroizing::new(s.into())),
            }],
        }
    }

    fn holding(r: ConversationRecord) -> MemStore {
        let store = MemStore::default();
        store.create(r, 32).unwrap();
        store
    }

    struct Failing(StoreError);

    impl ConversationStore for Failing {
        fn create(&self, _: ConversationRecord, _: usize) -> Result<Scan<()>, StoreError> {
            Err(self.0.clone())
        }
        fn get(&self, _: &ConversationId) -> Result<ConversationRecord, StoreError> {
            Err(self.0.clone())
        }
        fn update(
            &self,
            _: &ConversationId,
            _: u64,
            _: &mut dyn FnMut(&mut ConversationRecord),
        ) -> Result<ConversationRecord, StoreError> {
            Err(self.0.clone())
        }
        fn remove(&self, _: &ConversationId, _: u64) -> Result<ConversationRecord, StoreError> {
            Err(self.0.clone())
        }
        fn list_by_owner(
            &self,
            _: u32,
            _: Option<&ConversationId>,
            _: usize,
        ) -> Result<Scan<Page>, StoreError> {
            Err(self.0.clone())
        }
        fn idle_for_owner(
            &self,
            _: u32,
            _: u64,
        ) -> Result<Scan<Vec<ConversationRecord>>, StoreError> {
            Err(self.0.clone())
        }
    }

    fn unknown() -> ConversationFacts {
        ConversationFacts {
            state: FactState::Unknown,
            owner: Some(REQUESTER),
            extends: None,
        }
    }

    fn error() -> ConversationFacts {
        ConversationFacts {
            state: FactState::Error,
            owner: None,
            extends: None,
        }
    }

    #[test]
    fn nothing_cited_gathers_nothing() {
        let store = holding(rec(id('a'), OWNER));
        assert_eq!(gather(&store, REQUESTER, None, None), None);
        assert_eq!(gather(&store, REQUESTER, None, Some(&[])), None);
    }

    #[test]
    fn gather_maps_not_found_to_unknown_and_other_errors_to_error() {
        let cited = id('b');
        assert_eq!(
            gather(
                &Failing(StoreError::NotFound),
                REQUESTER,
                Some(cited.as_str()),
                None
            ),
            Some((unknown(), None))
        );
        for e in [
            StoreError::StaleFence,
            StoreError::Exists,
            StoreError::OwnerFull,
            StoreError::IdMismatch,
            StoreError::Corrupt,
            StoreError::Io("sentinel-170-io".into()),
        ] {
            assert_eq!(
                gather(&Failing(e.clone()), REQUESTER, Some(cited.as_str()), None),
                Some((error(), None)),
                "{e:?}"
            );
        }
        let empty = MemStore::default();
        assert_eq!(
            gather(&empty, REQUESTER, Some(cited.as_str()), Some(&[user("x")])),
            Some((unknown(), None))
        );
    }

    #[test]
    fn a_swapped_or_damaged_record_is_error_never_unknown() {
        let store = holding(rec(id('c'), OWNER));
        store.put_raw(&id('d'), store.raw(&id('c')).unwrap());
        store.put_raw(&id('e'), b"sentinel-170-not-cbor".to_vec());
        for cited in [id('d'), id('e')] {
            assert_eq!(
                gather(&store, REQUESTER, Some(cited.as_str()), None),
                Some((error(), None)),
                "{cited:?}"
            );
        }
    }

    #[test]
    fn gather_of_an_unparseable_id_is_unknown() {
        let store = holding(rec(id('a'), OWNER));
        for cited in ["c", "", &"A".repeat(32), &"a".repeat(31), &"a".repeat(33)] {
            assert_eq!(
                gather(&store, REQUESTER, Some(cited), None),
                Some((unknown(), None)),
                "{cited:?}"
            );
        }
    }

    #[test]
    fn facts_name_the_records_owner() {
        let r = rec(id('f'), OWNER);
        let store = holding(r.clone());
        assert_eq!(
            gather(&store, REQUESTER, Some(id('f').as_str()), None),
            Some((
                ConversationFacts {
                    state: FactState::Active,
                    owner: Some(OWNER),
                    extends: None,
                },
                Some(r)
            ))
        );
    }

    #[test]
    fn gather_computes_extends_only_when_turns_are_given() {
        let r = rec(id('1'), OWNER);
        let store = holding(r.clone());
        let at = |turns: &[Turn]| {
            gather(&store, OWNER, Some(id('1').as_str()), Some(turns)).and_then(|(f, _)| f.extends)
        };
        assert_eq!(at(&[]), Some(Extends::Retry));
        assert_eq!(
            at(&[user("a"), user("b")]),
            Some(Extends::Advance { new: 2 })
        );
        let mut held = r;
        held.turns = 1;
        let store = holding(ConversationRecord {
            id: id('2'),
            chain: ChainHead::genesis(&id('2')),
            ..held
        });
        assert_eq!(
            gather(&store, OWNER, Some(id('2').as_str()), Some(&[user("a")]))
                .and_then(|(f, _)| f.extends),
            Some(Extends::Rewrite)
        );
    }

    #[test]
    fn a_chain_error_settles_to_error_never_unknown() {
        let r = rec(id('9'), OWNER);
        assert_eq!(
            settle(r.clone(), Err(chain::ChainError::Encode)),
            (error(), None)
        );
        assert_eq!(
            settle(r.clone(), Ok(Some(Extends::Retry))),
            (
                ConversationFacts {
                    state: FactState::Active,
                    owner: Some(OWNER),
                    extends: Some(Extends::Retry),
                },
                Some(r)
            )
        );
    }

    #[test]
    fn delete_effect_per_state() {
        assert_eq!(delete_effect(FactState::Active), DeleteEffect::RemoveActive);
        assert_eq!(
            delete_effect(FactState::Unknown),
            DeleteEffect::RecordArchived
        );
        assert_eq!(delete_effect(FactState::Error), DeleteEffect::Refuse);
    }

    #[test]
    fn the_attribute_values_are_the_pdps_vocabulary() {
        assert_eq!(FactState::Active.as_attr(), "active");
        assert_eq!(FactState::Unknown.as_attr(), "unknown");
        assert_eq!(FactState::Error.as_attr(), "error");
        assert_eq!(extends_attr(Extends::Retry), "retry");
        assert_eq!(extends_attr(Extends::Advance { new: 3 }), "advance");
        assert_eq!(extends_attr(Extends::Rewrite), "rewrite");
    }
}
