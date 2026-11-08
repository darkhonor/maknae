use super::bounds::{check_turn, BoundRefusal};
use super::chain::{self, ChainHead, Extends};
use super::record::ConversationRecord;
use super::store::{ConversationStore, StoreError};
use maknae_proto::{ConversationId, PromptReply, Turn};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TurnRefusal {
    Bound(BoundRefusal),
    Rewrite,
    Unencodable,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RequestStep {
    chain: ChainHead,
    turns: u64,
    add: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ReplyStep {
    digest: [u8; 32],
    add: u64,
}

/// `None` is a retry: the request holds nothing the record does not.
pub fn request_step(
    rec: &ConversationRecord,
    extends: Extends,
    request: &[Turn],
) -> Result<Option<RequestStep>, TurnRefusal> {
    let new = match extends {
        Extends::Retry => {
            check_turn(rec, 0).map_err(TurnRefusal::Bound)?;
            return Ok(None);
        }
        Extends::Advance { new } => new,
        Extends::Rewrite => return Err(TurnRefusal::Rewrite),
    };
    let fresh = usize::try_from(rec.turns)
        .ok()
        .and_then(|held| request.get(held..))
        .filter(|fresh| fresh.len() == new && new > 0)
        .ok_or(TurnRefusal::Rewrite)?;
    let counted = match rec.last_reply {
        Some(_) => &fresh[1..],
        None => fresh,
    };
    let add = chain::turn_bytes(counted).map_err(|_| TurnRefusal::Unencodable)?;
    check_turn(rec, add).map_err(TurnRefusal::Bound)?;
    let chain = chain::advance(&rec.chain, fresh).map_err(|_| TurnRefusal::Unencodable)?;
    Ok(Some(RequestStep {
        chain,
        turns: request.len() as u64,
        add,
    }))
}

pub fn apply_request(rec: &mut ConversationRecord, step: Option<&RequestStep>, now: u64) {
    rec.last_active = now;
    if let Some(step) = step {
        rec.chain = step.chain;
        rec.turns = step.turns;
        rec.bytes = rec.bytes.saturating_add(step.add);
        rec.last_reply = None;
    }
}

pub fn reply_step(rec: &ConversationRecord, reply: &PromptReply) -> Result<ReplyStep, TurnRefusal> {
    let add = chain::reply_bytes(reply).map_err(|_| TurnRefusal::Unencodable)?;
    check_turn(rec, add).map_err(TurnRefusal::Bound)?;
    let digest = chain::reply_digest(reply).map_err(|_| TurnRefusal::Unencodable)?;
    Ok(ReplyStep { digest, add })
}

pub fn apply_reply(rec: &mut ConversationRecord, step: &ReplyStep, now: u64) {
    rec.last_active = now;
    rec.last_reply = Some(step.digest);
    rec.bytes = rec.bytes.saturating_add(step.add);
}

pub fn mark_full(rec: &mut ConversationRecord) {
    rec.full = true;
}

pub const MARK_FULL_ATTEMPTS: usize = 3;

pub fn mark_full_at_any_fence(
    store: &dyn ConversationStore,
    id: &ConversationId,
) -> Result<(), StoreError> {
    for _ in 0..MARK_FULL_ATTEMPTS {
        let rec = store.get(id)?;
        match store.update(id, rec.fence, &mut mark_full) {
            Err(StoreError::StaleFence) => {}
            other => return other.map(|_| ()),
        }
    }
    Err(StoreError::StaleFence)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::conversation::bounds::CONVERSATION_MAX_BYTES;
    use crate::conversation::mem_store::MemStore;
    use crate::conversation::record::opened;
    use maknae_io::Zeroizing;
    use maknae_proto::{ContentBlock, SecretText};
    use std::sync::atomic::{AtomicUsize, Ordering};

    fn text(s: &str) -> ContentBlock {
        ContentBlock::Text {
            text: SecretText(Zeroizing::new(s.into())),
        }
    }
    fn user(s: &str) -> Turn {
        Turn::User {
            content: vec![text(s)],
        }
    }
    fn reply(s: &str) -> PromptReply {
        PromptReply {
            blocks: vec![text(s)],
            tool_calls: vec![],
            usage: None,
            reasoning: None,
        }
    }
    fn assistant(s: &str) -> Turn {
        Turn::Assistant {
            content: vec![text(s)],
            tool_calls: vec![],
            reasoning: None,
        }
    }
    fn fresh() -> ConversationRecord {
        opened(
            ConversationId::parse(&"c".repeat(32)).unwrap(),
            1170,
            "/h".into(),
            5,
            "UNCLASSIFIED",
        )
    }

    #[test]
    fn a_retry_is_no_step_and_touches_only_last_active() {
        let mut rec = fresh();
        rec.turns = 1;
        rec.bytes = 9;
        rec.last_reply = Some([4; 32]);
        assert_eq!(request_step(&rec, Extends::Retry, &[user("a")]), Ok(None));
        let before = rec.clone();
        apply_request(&mut rec, None, 77);
        assert_eq!(
            rec,
            ConversationRecord {
                last_active: 77,
                ..before
            }
        );
    }

    #[test]
    fn a_full_conversation_refuses_a_retry_and_an_advance() {
        let mut rec = fresh();
        mark_full(&mut rec);
        assert!(rec.full);
        let full = Err(TurnRefusal::Bound(BoundRefusal::ConversationFull));
        assert_eq!(request_step(&rec, Extends::Retry, &[]), full);
        assert_eq!(
            request_step(&rec, Extends::Advance { new: 1 }, &[user("a")]),
            full
        );
    }

    #[test]
    fn an_advance_chains_the_new_turns_and_counts_them() {
        let rec = fresh();
        let req = [user("a"), user("b")];
        let step = request_step(&rec, Extends::Advance { new: 2 }, &req)
            .unwrap()
            .unwrap();
        let mut next = rec.clone();
        next.last_reply = Some([1; 32]);
        apply_request(&mut next, Some(&step), 9);
        assert_eq!(next.chain, chain::advance(&rec.chain, &req).unwrap());
        assert_eq!(next.turns, 2);
        assert_eq!(next.bytes, chain::turn_bytes(&req).unwrap());
        assert_eq!(next.last_reply, None);
        assert_eq!(next.last_active, 9);
    }

    #[test]
    fn the_bound_assistant_turn_is_chained_but_not_counted() {
        let mut rec = fresh();
        let first = [user("a")];
        rec.chain = chain::advance(&rec.chain, &first).unwrap();
        rec.turns = 1;
        rec.bytes = 100;
        rec.last_reply = Some([2; 32]);
        let req = [user("a"), assistant("r"), user("b")];
        let step = request_step(&rec, Extends::Advance { new: 2 }, &req)
            .unwrap()
            .unwrap();
        let mut next = rec.clone();
        apply_request(&mut next, Some(&step), 1);
        assert_eq!(next.chain, chain::advance(&rec.chain, &req[1..]).unwrap());
        assert_eq!(next.turns, 3);
        assert_eq!(next.bytes, 100 + chain::turn_bytes(&req[2..]).unwrap());
    }

    #[test]
    fn a_rewrite_or_a_count_that_disagrees_with_the_record_is_refused() {
        let mut rec = fresh();
        assert_eq!(
            request_step(&rec, Extends::Rewrite, &[user("a")]),
            Err(TurnRefusal::Rewrite)
        );
        assert_eq!(
            request_step(&rec, Extends::Advance { new: 2 }, &[user("a")]),
            Err(TurnRefusal::Rewrite)
        );
        assert_eq!(
            request_step(&rec, Extends::Advance { new: 0 }, &[]),
            Err(TurnRefusal::Rewrite)
        );
        rec.turns = 3;
        assert_eq!(
            request_step(&rec, Extends::Advance { new: 1 }, &[user("a")]),
            Err(TurnRefusal::Rewrite)
        );
    }

    #[test]
    fn an_advance_over_the_cap_is_refused() {
        let mut rec = fresh();
        let req = [user("a")];
        rec.bytes = CONVERSATION_MAX_BYTES - chain::turn_bytes(&req).unwrap();
        assert!(request_step(&rec, Extends::Advance { new: 1 }, &req).is_ok());
        rec.bytes += 1;
        assert_eq!(
            request_step(&rec, Extends::Advance { new: 1 }, &req),
            Err(TurnRefusal::Bound(BoundRefusal::ConversationFull))
        );
    }

    #[test]
    fn a_reply_binds_its_digest_and_counts_its_bytes() {
        let mut rec = fresh();
        rec.bytes = 10;
        let r = reply("ok");
        let step = reply_step(&rec, &r).unwrap();
        apply_reply(&mut rec, &step, 33);
        assert_eq!(rec.last_reply, Some(chain::reply_digest(&r).unwrap()));
        assert_eq!(rec.bytes, 10 + chain::reply_bytes(&r).unwrap());
        assert_eq!(rec.last_active, 33);
    }

    #[test]
    fn a_reply_over_the_cap_is_refused() {
        let mut rec = fresh();
        let r = reply("ok");
        rec.bytes = CONVERSATION_MAX_BYTES - chain::reply_bytes(&r).unwrap();
        assert!(reply_step(&rec, &r).is_ok());
        rec.bytes += 1;
        assert_eq!(
            reply_step(&rec, &r),
            Err(TurnRefusal::Bound(BoundRefusal::ConversationFull))
        );
    }

    struct Moving {
        inner: MemStore,
        moves: AtomicUsize,
    }
    impl ConversationStore for Moving {
        fn create(
            &self,
            r: ConversationRecord,
            m: usize,
        ) -> Result<crate::conversation::store::Scan<()>, StoreError> {
            self.inner.create(r, m)
        }
        fn get(&self, id: &ConversationId) -> Result<ConversationRecord, StoreError> {
            self.inner.get(id)
        }
        fn update(
            &self,
            id: &ConversationId,
            fence: u64,
            f: &mut dyn FnMut(&mut ConversationRecord),
        ) -> Result<ConversationRecord, StoreError> {
            if self.moves.load(Ordering::SeqCst) > 0 {
                self.moves.fetch_sub(1, Ordering::SeqCst);
                let cur = self.inner.get(id)?;
                self.inner
                    .update(id, cur.fence, &mut |r| r.last_active += 1)?;
            }
            self.inner.update(id, fence, f)
        }
        fn remove(
            &self,
            id: &ConversationId,
            fence: u64,
        ) -> Result<ConversationRecord, StoreError> {
            self.inner.remove(id, fence)
        }
        fn list_by_owner(
            &self,
            o: u32,
            a: Option<&ConversationId>,
            l: usize,
        ) -> Result<crate::conversation::store::Scan<crate::conversation::store::Page>, StoreError>
        {
            self.inner.list_by_owner(o, a, l)
        }
        fn idle_for_owner(
            &self,
            o: u32,
            t: u64,
        ) -> Result<crate::conversation::store::Scan<Vec<ConversationRecord>>, StoreError> {
            self.inner.idle_for_owner(o, t)
        }
    }

    fn moving(moves: usize) -> (Moving, ConversationId) {
        let store = Moving {
            inner: MemStore::default(),
            moves: AtomicUsize::new(0),
        };
        let rec = fresh();
        let id = rec.id.clone();
        store.create(rec, 1).unwrap();
        store.moves.store(moves, Ordering::SeqCst);
        (store, id)
    }

    #[test]
    fn marking_full_survives_a_moved_fence_within_its_attempts() {
        let (store, id) = moving(2);
        assert_eq!(mark_full_at_any_fence(&store, &id), Ok(()));
        assert!(store.get(&id).unwrap().full);
    }

    #[test]
    fn marking_full_gives_up_after_its_attempts_and_says_so() {
        let (store, id) = moving(3);
        assert_eq!(
            mark_full_at_any_fence(&store, &id),
            Err(StoreError::StaleFence)
        );
        assert!(!store.get(&id).unwrap().full);
        assert_eq!(
            mark_full_at_any_fence(&store, &ConversationId::parse(&"d".repeat(32)).unwrap()),
            Err(StoreError::NotFound)
        );
    }
}
