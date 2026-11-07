//! #170: a store effect that overruns its bound. Its own binary: the stalled
//! worker holds the test euid's store slot past every other test's timeout.
mod common;
use common::{Fixture, Records};
use maknae_kernel::{ConversationRecord, ConversationStore, ConversationStoreError as StoreError};
use maknae_proto::{ConversationId, Payload, ProtoErrCode, RespResult, Verb};
use std::sync::Arc;
use std::time::Duration;

const GRANTS: &str = "roles:\n  user:\n    allow: [\"session.prompt\", \"session.new\", \"session.close\", \"session.list\", \"session.delete\"]\n";

struct SlowRemove(Arc<dyn ConversationStore>);
impl ConversationStore for SlowRemove {
    fn create(
        &self,
        rec: ConversationRecord,
        max: usize,
    ) -> Result<maknae_kernel::Scan<()>, StoreError> {
        self.0.create(rec, max)
    }
    fn get(&self, id: &ConversationId) -> Result<ConversationRecord, StoreError> {
        self.0.get(id)
    }
    fn update(
        &self,
        id: &ConversationId,
        fence: u64,
        f: &mut dyn FnMut(&mut ConversationRecord),
    ) -> Result<ConversationRecord, StoreError> {
        self.0.update(id, fence, f)
    }
    fn remove(&self, id: &ConversationId, fence: u64) -> Result<ConversationRecord, StoreError> {
        std::thread::sleep(Duration::from_millis(2_500));
        self.0.remove(id, fence)
    }
    fn list_by_owner(
        &self,
        owner: u32,
        after: Option<&ConversationId>,
        limit: usize,
    ) -> Result<maknae_kernel::Scan<maknae_kernel::Page>, StoreError> {
        self.0.list_by_owner(owner, after, limit)
    }
    fn idle_for_owner(
        &self,
        owner: u32,
        older_than: u64,
    ) -> Result<maknae_kernel::Scan<Vec<ConversationRecord>>, StoreError> {
        self.0.idle_for_owner(owner, older_than)
    }
}

#[tokio::test]
async fn an_effect_that_overruns_its_bound_is_recorded_as_unknown() {
    let mut fx = Fixture::with_rules("conv-overrun", &["Read"], &[], GRANTS);
    let conv = fx.open_conversation().await;
    let id = ConversationId::parse(&conv).unwrap();
    let plain = Arc::clone(&fx.conversations);
    fx.conversations = Arc::new(SlowRemove(Arc::clone(&plain)));
    let records = Records::new(0);
    let (client, task, body) = fx.start(
        Verb::SessionClose {
            conversation: id.clone(),
        },
        None,
        Arc::clone(&records),
    );
    let resp = Fixture::exchange(client, task, &body).await.unwrap();
    assert!(
        matches!(&resp.result, RespResult::Err(e) if e.code == ProtoErrCode::Unauthorized),
        "{resp:?}"
    );
    assert!(!matches!(
        resp.result,
        RespResult::Ok(Payload::ConversationClosed(_))
    ));
    let recs: Vec<_> = records
        .snapshot()
        .into_iter()
        .filter(|r| r.action == "session.close")
        .collect();
    assert_eq!(recs.len(), 2, "{recs:?}");
    assert_eq!(
        recs[1].outcome.reason,
        "outcome unknown: store work did not finish within its bound"
    );
    assert_eq!(recs[1].outcome.posture, "unavailable");
    tokio::time::sleep(Duration::from_millis(1_000)).await;
    assert_eq!(
        plain.get(&id),
        Err(StoreError::NotFound),
        "the overrun removal landed after all, which is why the trail says unknown"
    );
}
