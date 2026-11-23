//! The board verbs (#695): the switch gate, the per-post decision and the page walk.
use std::collections::BTreeSet;
use std::sync::Arc;
use std::time::Duration;

use maknae_audit_append::{AuditRecord, BoardAudit};
use maknae_config::AgentId;
use maknae_proto::{
    Addressee, BoardDefect, BoardPage, PostDraft, PostId, ProtoCodecError, BOARD_READ_PAGE_POSTS,
};
use maknae_security::{AttrValue, Attributes, Authorizer, Decision, Verdict};

use crate::blocking_guard::{admit_blocking, Offload};
use crate::board::{BoardDue, BoardDueFor, BoardRefusal, BoardStore};
use crate::board_store::{BoardKey, HeldFor, LabelValue, Stored};
use crate::task::CitedTask;

pub trait BoardSwitches: Send + Sync {
    fn site(&self) -> bool;
    fn agent(&self, agent: &AgentId) -> bool;
}

/// The production switches until #698: the board is served nowhere.
pub struct SwitchesOff;

impl BoardSwitches for SwitchesOff {
    fn site(&self) -> bool {
        false
    }

    fn agent(&self, _: &AgentId) -> bool {
        false
    }
}

#[cfg(any(test, feature = "hermetic-test-seam"))]
#[derive(Clone, Debug, Default)]
pub struct FixedSwitches {
    pub site: bool,
    pub agents: BTreeSet<AgentId>,
}

#[cfg(any(test, feature = "hermetic-test-seam"))]
impl BoardSwitches for FixedSwitches {
    fn site(&self) -> bool {
        self.site
    }

    fn agent(&self, agent: &AgentId) -> bool {
        self.agents.contains(agent)
    }
}

/// Why the gate refused a board request before any decision.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Off {
    ClientChannel,
    NoTasker,
    Site,
    Agent,
    Tasker,
    NoTask,
}

impl std::fmt::Display for Off {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Off::ClientChannel => "board: not served on the client channel",
            Off::NoTasker => "board off: the chain has no tasker",
            Off::Site => "board off: site",
            Off::Agent => "board off: agent",
            Off::Tasker => "board off: tasker",
            Off::NoTask => "board: the request cites no task",
        })
    }
}

/// `Ok(None)` for an agent citing no task: the decision refuses it.
pub(crate) fn gate(
    channel_agent: Option<&AgentId>,
    cited: Option<&CitedTask>,
    switches: &dyn BoardSwitches,
    board: &BoardStore,
) -> Result<Option<BoardKey>, Off> {
    let agent = channel_agent.ok_or(Off::ClientChannel)?;
    let Some(cited) = cited else {
        return Ok(None);
    };
    let key = BoardKey::of(&cited.root).ok_or(Off::NoTasker)?;
    if !switches.site() {
        return Err(Off::Site);
    }
    if !switches.agent(agent) {
        return Err(Off::Agent);
    }
    if !board.settings(key).enabled {
        return Err(Off::Tasker);
    }
    Ok(Some(key))
}

/// The read request `base` asked again of one post: its board and its labels.
pub(crate) fn post_request(
    base: &maknae_security::Request,
    key: BoardKey,
    stored: &Stored,
) -> maknae_security::Request {
    let mut resource = Attributes::new();
    resource.insert(
        maknae_security::RESOURCE_BOARD,
        AttrValue::Str(key.partition()),
    );
    for (name, value) in &stored.labels.0 {
        let value = match value {
            LabelValue::Str(s) => AttrValue::Str(s.clone()),
            LabelValue::Set(s) => AttrValue::Set(s.clone()),
        };
        resource.insert(
            format!("{}{name}", maknae_security::POST_LABEL_PREFIX),
            value,
        );
    }
    maknae_security::Request {
        subject: base.subject.clone(),
        resource: maknae_security::Resource(resource),
        action: maknae_security::Action("board.read".into()),
        context: base.context.clone(),
    }
}

pub(crate) const UNDECIDED: &str = "board: the decision did not complete";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum PostVerdict {
    Permit,
    Deny,
    Undecided,
}

fn post_verdict(verdict: Verdict) -> PostVerdict {
    if maknae_security::undecided(&verdict) {
        return PostVerdict::Undecided;
    }
    match maknae_security::finalize(maknae_security::combine(vec![verdict])) {
        Decision::Permit { obligations } => match crate::handler::discharge_plan(&obligations) {
            Ok(()) => PostVerdict::Permit,
            Err(_) => PostVerdict::Undecided,
        },
        Decision::Deny { .. } => PostVerdict::Deny,
    }
}

/// One guarded batch, under the decision breaker and timeout, on one view of the policy.
/// `base`, the verb's own request, is decided again at the head of the batch; unless it is
/// permitted, every post is undecided. An empty batch decides nothing and permits nothing.
pub(crate) async fn decide_posts<P: Authorizer + Send + Sync + 'static>(
    authorizer: &Arc<P>,
    live: &Arc<crate::live::LiveConfig>,
    admitted_generation: u64,
    timeout: Duration,
    base: &maknae_security::Request,
    requests: Vec<maknae_security::Request>,
) -> Vec<PostVerdict> {
    let n = requests.len();
    if n == 0 {
        return Vec::new();
    }
    decide_batch(
        authorizer,
        live,
        admitted_generation,
        timeout,
        base,
        requests,
    )
    .await
    .unwrap_or_else(|| vec![PostVerdict::Undecided; n])
}

/// Whether `base` is still permitted, decided as a batch of no posts.
pub(crate) async fn base_holds<P: Authorizer + Send + Sync + 'static>(
    authorizer: &Arc<P>,
    live: &Arc<crate::live::LiveConfig>,
    admitted_generation: u64,
    timeout: Duration,
    base: &maknae_security::Request,
) -> bool {
    decide_batch(
        authorizer,
        live,
        admitted_generation,
        timeout,
        base,
        Vec::new(),
    )
    .await
    .is_some()
}

/// The posts' verdicts, or `None` when `base` is not permitted again or the batch did not
/// complete.
async fn decide_batch<P: Authorizer + Send + Sync + 'static>(
    authorizer: &Arc<P>,
    live: &Arc<crate::live::LiveConfig>,
    admitted_generation: u64,
    timeout: Duration,
    base: &maknae_security::Request,
    requests: Vec<maknae_security::Request>,
) -> Option<Vec<PostVerdict>> {
    let n = requests.len();
    let mut batch = Vec::with_capacity(n + 1);
    batch.push(base.clone());
    batch.extend(requests);
    let (a, live) = (Arc::clone(authorizer), Arc::clone(live));
    let breaker = crate::run::authz_decide_breaker();
    let decided: Result<_, Offload> =
        admit_blocking(&breaker, timeout, "board post decision", move || {
            let all = maknae_security::guarded_decide_cited_all(&*a, &batch);
            (all, live.generation())
        })
        .await;
    match decided {
        Ok((all, generation)) if generation == admitted_generation && all.len() == n + 1 => {
            let mut all = all.into_iter().map(|d| post_verdict(d.verdict));
            match all.next() {
                Some(PostVerdict::Permit) => Some(all.collect()),
                Some(PostVerdict::Deny | PostVerdict::Undecided) | None => None,
            }
        }
        Ok(_) | Err(Offload::Open | Offload::AtCapacity | Offload::Join | Offload::TimedOut) => {
            None
        }
    }
}

pub(crate) struct Walk {
    pub page: BoardPage,
    pub first_seq: Option<u64>,
    pub last_seq: Option<u64>,
    pub returned: u32,
    pub withheld: u32,
    pub skip_to: Option<u64>,
    /// The sequences of the posts on the page.
    pub sent: Vec<u64>,
}

/// One read's page, built post by post in board order.
pub(crate) struct Walker {
    budget: usize,
    used: usize,
    kept: Vec<Arc<Stored>>,
    withheld: u32,
    skip_to: Option<u64>,
    permitted: bool,
    more: bool,
    /// The permitted post the page had no room for: what `more` stands on.
    lookahead: Option<Arc<Stored>>,
    stalled: bool,
}

/// A post's encoded size, counted without a buffer.
pub(crate) fn post_size(stored: &Stored) -> usize {
    let mut size = crate::task_store::Counted(0);
    match ciborium::into_writer(&stored.post, &mut size) {
        Ok(()) => size.0,
        Err(_) => usize::MAX,
    }
}

impl Walker {
    pub(crate) fn new(budget: usize) -> Self {
        Walker {
            budget,
            used: 0,
            kept: Vec::new(),
            withheld: 0,
            skip_to: None,
            permitted: false,
            more: false,
            lookahead: None,
            stalled: false,
        }
    }

    /// `false` once the walk has ended: a post undecided, or a permitted post left out.
    pub(crate) fn take(&mut self, chunk: &[Arc<Stored>], verdicts: &[PostVerdict]) -> bool {
        for (i, stored) in chunk.iter().enumerate() {
            match verdicts.get(i).copied().unwrap_or(PostVerdict::Undecided) {
                PostVerdict::Undecided => {
                    self.stalled = true;
                    return false;
                }
                PostVerdict::Deny => {
                    self.withheld = self.withheld.saturating_add(1);
                    if !self.permitted {
                        self.skip_to = Some(stored.seq);
                    }
                }
                PostVerdict::Permit => {
                    let size = post_size(stored);
                    let fits = self.kept.len() < BOARD_READ_PAGE_POSTS
                        && self.used.saturating_add(size) <= self.budget;
                    if !self.kept.is_empty() && !fits {
                        self.more = true;
                        self.lookahead = Some(Arc::clone(stored));
                        return false;
                    }
                    self.permitted = true;
                    self.used = self.used.saturating_add(size);
                    self.kept.push(Arc::clone(stored));
                }
            }
        }
        true
    }

    pub(crate) fn stalled(&self) -> bool {
        self.stalled
    }

    /// The sequences the final check must find live: the kept posts and the lookahead.
    pub(crate) fn checked_seqs(&self) -> Vec<u64> {
        self.kept
            .iter()
            .chain(&self.lookahead)
            .map(|s| s.seq)
            .collect()
    }

    /// Drops each kept post `live` does not hold. When that frees room, or the lookahead is
    /// no longer live, the walk is not what it would be without those posts: returns the
    /// sequence to resume walking after, with the lookahead taken again if it is live.
    pub(crate) fn revalidate(&mut self, live: &BTreeSet<u64>) -> Option<u64> {
        let before = self.kept.len();
        self.kept.retain(|s| live.contains(&s.seq));
        let dropped = self.kept.len() != before;
        if dropped {
            self.used = self
                .kept
                .iter()
                .map(|s| post_size(s))
                .fold(0, usize::saturating_add);
        }
        if self.stalled {
            return None;
        }
        let lookahead = self.lookahead.take()?;
        if !dropped && live.contains(&lookahead.seq) {
            self.lookahead = Some(lookahead);
            return None;
        }
        self.more = false;
        let at = lookahead.seq;
        if live.contains(&at) && !self.take(&[lookahead], &[PostVerdict::Permit]) {
            return None;
        }
        Some(at)
    }

    pub(crate) fn reply_targets(&self) -> Vec<PostId> {
        let kept: BTreeSet<PostId> = self.kept.iter().map(|s| s.post.id).collect();
        let targets: BTreeSet<PostId> = self
            .kept
            .iter()
            .filter_map(|s| s.post.draft.in_reply_to)
            .filter(|t| !kept.contains(t))
            .collect();
        targets.into_iter().collect()
    }

    pub(crate) fn finish(self, visible_targets: &BTreeSet<PostId>) -> Walk {
        let kept: BTreeSet<PostId> = self.kept.iter().map(|s| s.post.id).collect();
        let posts = self
            .kept
            .iter()
            .map(|s| {
                let mut post = s.post.clone();
                if post
                    .draft
                    .in_reply_to
                    .is_some_and(|t| !kept.contains(&t) && !visible_targets.contains(&t))
                {
                    post.draft.in_reply_to = None;
                }
                post
            })
            .collect();
        Walk {
            page: BoardPage {
                posts,
                more: self.more || self.stalled,
            },
            first_seq: self.kept.first().map(|s| s.seq),
            last_seq: self.kept.last().map(|s| s.seq),
            returned: u32::try_from(self.kept.len()).unwrap_or(u32::MAX),
            withheld: self.withheld,
            skip_to: self.skip_to,
            sent: self.kept.iter().map(|s| s.seq).collect(),
        }
    }
}

/// SHA-256 of the post's canonical content, 64 lowercase hex.
pub(crate) fn post_digest(draft: &PostDraft) -> Result<String, ProtoCodecError> {
    let content = maknae_proto::post_content_bytes(draft)?;
    Ok(maknae_crypto::sha256(&content)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect())
}

pub(crate) fn defect_of(r: &BoardRefusal) -> BoardDefect {
    match r {
        BoardRefusal::Full => BoardDefect::Full,
        BoardRefusal::AuthorAtCap => BoardDefect::AuthorAtCap,
        BoardRefusal::NoSuchPost => BoardDefect::NoSuchPost,
        BoardRefusal::Store(_) | BoardRefusal::Random | BoardRefusal::StillContained => {
            BoardDefect::TryAgain
        }
        BoardRefusal::Unavailable(_) => BoardDefect::OutcomeUnknown,
    }
}

pub(crate) fn posture(r: &BoardRefusal) -> &'static str {
    match r {
        BoardRefusal::Unavailable(_) => "unavailable",
        BoardRefusal::Full
        | BoardRefusal::AuthorAtCap
        | BoardRefusal::NoSuchPost
        | BoardRefusal::Store(_)
        | BoardRefusal::Random
        | BoardRefusal::StillContained => "unauthorized",
    }
}

/// The board store's work off the async worker, bounded by `deadline`.
pub(crate) async fn offload<T, F>(
    uid: u32,
    deadline: tokio::time::Instant,
    f: F,
) -> Result<T, BoardRefusal>
where
    T: Send + 'static,
    F: FnOnce() -> Result<T, BoardRefusal> + Send + 'static,
{
    let left = deadline.saturating_duration_since(tokio::time::Instant::now());
    match crate::mutation::blocking(uid, left, f).await {
        Ok(done) => done,
        Err(crate::mutation::Blocked::NotStarted) => Err(BoardRefusal::Store(
            "not done: the board store was busy".into(),
        )),
        Err(crate::mutation::Blocked::Unknown) => Err(BoardRefusal::Unavailable(format!(
            "{}the board store did not answer in time",
            crate::task::OUTCOME_UNKNOWN
        ))),
    }
}

pub(crate) fn on_board(mut rec: AuditRecord, key: Option<BoardKey>) -> AuditRecord {
    rec.object = key.map(|k| format!("board:{}", k.partition()));
    rec
}

fn addressed(to: &Addressee) -> String {
    match to {
        Addressee::Board => "board".into(),
        Addressee::Tasker => "tasker".into(),
        Addressee::Agents(ids) => format!("agents:{}", ids.join(",")),
    }
}

fn bytes(n: usize) -> Option<u32> {
    Some(u32::try_from(n).unwrap_or(u32::MAX))
}

/// What a post's records say of it: its shape, sizes and digest, never its content.
pub(crate) fn post_audit(draft: &PostDraft, digest: &str) -> BoardAudit {
    BoardAudit {
        kind: Some(draft.kind.as_str().into()),
        to: Some(addressed(&draft.to)),
        in_reply_to: draft.in_reply_to.map(|id| id.to_string()),
        attachments: bytes(draft.attachments.len()),
        body_bytes: bytes(draft.body.0.len()),
        attachment_bytes: bytes(
            draft
                .attachments
                .iter()
                .map(|a| a.content.0.len())
                .fold(0, usize::saturating_add),
        ),
        digest: Some(digest.into()),
        ..BoardAudit::default()
    }
}

pub(crate) fn posted_audit(mut audit: BoardAudit, stored: &Stored) -> BoardAudit {
    audit.post_id = Some(stored.post.id.to_string());
    audit.seq = Some(stored.seq);
    audit
}

pub(crate) fn read_audit(walk: &Walk, cursor: u64) -> BoardAudit {
    BoardAudit {
        first_seq: walk.first_seq,
        last_seq: walk.last_seq,
        returned: Some(walk.returned),
        withheld: Some(walk.withheld),
        cursor: Some(cursor),
        ..BoardAudit::default()
    }
}

/// A due item's `board_op` and reason.
pub(crate) fn due_said(why: BoardDueFor) -> (&'static str, &'static str) {
    match why {
        BoardDueFor::Expire => ("expire", "expired"),
        BoardDueFor::Hold(HeldFor::Author) => ("hold", "post held: contained (author)"),
        BoardDueFor::Hold(HeldFor::Person) => ("hold", "post held: contained (person)"),
        BoardDueFor::DropCursor => ("expire", "cursor removed: agent gone"),
    }
}

/// A due post's id and sequence; nothing for a cursor.
pub(crate) fn due_audit(due: &BoardDue) -> Option<BoardAudit> {
    due.post.map(|id| BoardAudit {
        post_id: Some(id.to_string()),
        seq: due.seq,
        ..BoardAudit::default()
    })
}

pub(crate) fn cursor_audit(cursor: u64) -> BoardAudit {
    BoardAudit {
        cursor: Some(cursor),
        ..BoardAudit::default()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::board::BoardStore;
    use crate::board_store::{LabelValue, PostLabels, Settings, Stored};
    use crate::task::{CitedTask, TaskObjectForTest};
    use crate::task_store::RootTasker;
    use maknae_proto::{
        Addressee, Attachment, Author, Labels, Media, Post, PostDraft, PostId, PostKind,
        SecretText, BOARD_READ_PAGE_POSTS,
    };
    use maknae_security::{AttrValue, Attributes, RESOURCE_BOARD};
    use std::collections::BTreeSet;
    use std::sync::Arc;

    const BOB: BoardKey = BoardKey(1000);

    #[test]
    fn the_production_switches_are_off() {
        let hobi = AgentId::parse("sentinel-695-hobi").unwrap();
        assert!(!SwitchesOff.site());
        assert!(!SwitchesOff.agent(&hobi));
    }

    fn hobi() -> AgentId {
        AgentId::parse("sentinel-695-hobi").unwrap()
    }

    fn cited(root: RootTasker) -> CitedTask {
        CitedTask {
            signed: Arc::new(maknae_proto::SignedTask {
                task: maknae_proto::TaskObject::for_test("sentinel-695-hobi", BOB.0),
                signature: maknae_proto::TaskSignature {
                    alg: "test".into(),
                    leaf: maknae_proto::Bytes::new(vec![1].into()),
                    chain: Vec::new(),
                    sig: maknae_proto::Bytes::new(vec![2].into()),
                },
            }),
            root,
            start: 1,
        }
    }

    fn switches(site: bool, agent: bool) -> FixedSwitches {
        FixedSwitches {
            site,
            agents: if agent {
                [hobi()].into_iter().collect()
            } else {
                BTreeSet::new()
            },
        }
    }

    fn enabled(on: bool) -> BoardStore {
        let board = BoardStore::new();
        board
            .set_settings(
                BOB,
                Settings {
                    enabled: on,
                    ..Settings::default()
                },
            )
            .unwrap();
        board
    }

    #[test]
    fn the_gate_refuses_in_order() {
        let person = cited(RootTasker::Person { uid: BOB.0 });
        let rooted = cited(RootTasker::Agent {
            agent: "sentinel-695-jin".into(),
        });
        let agent = hobi();
        type Row<'a> = (
            &'a str,
            Option<&'a AgentId>,
            Option<&'a CitedTask>,
            FixedSwitches,
            bool,
            Result<Option<BoardKey>, Off>,
        );
        let table: Vec<Row<'_>> = vec![
            (
                "client",
                None,
                Some(&person),
                switches(true, true),
                true,
                Err(Off::ClientChannel),
            ),
            (
                "client citing nothing",
                None,
                None,
                switches(false, false),
                false,
                Err(Off::ClientChannel),
            ),
            (
                "agent-rooted",
                Some(&agent),
                Some(&rooted),
                switches(false, false),
                false,
                Err(Off::NoTasker),
            ),
            (
                "site",
                Some(&agent),
                Some(&person),
                switches(false, true),
                true,
                Err(Off::Site),
            ),
            (
                "agent",
                Some(&agent),
                Some(&person),
                switches(true, false),
                true,
                Err(Off::Agent),
            ),
            (
                "tasker",
                Some(&agent),
                Some(&person),
                switches(true, true),
                false,
                Err(Off::Tasker),
            ),
            (
                "all off",
                Some(&agent),
                Some(&person),
                switches(false, false),
                false,
                Err(Off::Site),
            ),
            (
                "agent and tasker off",
                Some(&agent),
                Some(&person),
                switches(true, false),
                false,
                Err(Off::Agent),
            ),
            (
                "on",
                Some(&agent),
                Some(&person),
                switches(true, true),
                true,
                Ok(Some(BOB)),
            ),
            (
                "cites nothing",
                Some(&agent),
                None,
                switches(false, false),
                false,
                Ok(None),
            ),
        ];
        for (at, channel, task, sw, on, want) in table {
            assert_eq!(gate(channel, task, &sw, &enabled(on)), want, "{at}");
        }
        assert_eq!(
            [
                Off::ClientChannel,
                Off::NoTasker,
                Off::Site,
                Off::Agent,
                Off::Tasker,
                Off::NoTask
            ]
            .map(|o| o.to_string()),
            [
                "board: not served on the client channel",
                "board off: the chain has no tasker",
                "board off: site",
                "board off: agent",
                "board off: tasker",
                "board: the request cites no task"
            ]
        );
    }

    fn secret(s: &str) -> SecretText {
        SecretText(maknae_io::Zeroizing::new(s.into()))
    }

    fn draft(body: &str, in_reply_to: Option<PostId>) -> PostDraft {
        PostDraft {
            kind: PostKind::Note,
            to: Addressee::Board,
            in_reply_to,
            body: secret(body),
            attachments: vec![],
        }
    }

    fn stored(seq: u64, in_reply_to: Option<u64>, labels: PostLabels) -> Arc<Stored> {
        Arc::new(Stored {
            post: Post {
                id: id(seq),
                author: Author::Agent("sentinel-695-hobi".into()),
                task: None,
                at_secs: 0,
                labels: Labels {},
                draft: draft("sentinel-695-body", in_reply_to.map(id)),
            },
            seq,
            author_uid: None,
            labels,
            held: BTreeSet::new(),
        })
    }

    fn id(seq: u64) -> PostId {
        let mut b = [0u8; 16];
        b[8..].copy_from_slice(&seq.to_be_bytes());
        PostId(b)
    }

    fn plain(seqs: std::ops::RangeInclusive<u64>) -> Vec<Arc<Stored>> {
        seqs.map(|s| stored(s, None, PostLabels::default()))
            .collect()
    }

    fn seqs(walk: &Walk) -> Vec<PostId> {
        walk.page.posts.iter().map(|p| p.id).collect()
    }

    const BIG: usize = 1 << 30;
    use PostVerdict::{Deny as D, Permit as P, Undecided as U};

    #[test]
    fn a_post_request_carries_the_board_and_the_posts_labels() {
        let mut subject = Attributes::new();
        subject.insert(
            maknae_security::SUBJECT_AGENT,
            AttrValue::Str("sentinel-695-jin".into()),
        );
        let mut resource = Attributes::new();
        resource.insert("path", AttrValue::Str("/sentinel-695".into()));
        let mut context = Attributes::new();
        context.insert(
            maknae_security::CONTEXT_DAC_LANE,
            AttrValue::Str("local".into()),
        );
        let base = maknae_security::Request {
            subject: maknae_security::Subject(subject),
            resource: maknae_security::Resource(resource),
            action: maknae_security::Action("board.post".into()),
            context: maknae_security::Context(context),
        };
        let set: BTreeSet<String> = ["a".to_string(), "b".to_string()].into();
        let labels = PostLabels(
            [
                (
                    "sentinel-695.level".to_string(),
                    LabelValue::Str("x".into()),
                ),
                ("sentinel-695.rel".to_string(), LabelValue::Set(set.clone())),
            ]
            .into(),
        );
        let req = post_request(&base, BOB, &stored(7, None, labels));
        assert_eq!(req.action.0, "board.read");
        assert_eq!(req.subject, base.subject);
        assert_eq!(req.context, base.context);
        let mut want = Attributes::new();
        want.insert(RESOURCE_BOARD, AttrValue::Str("users/1000".into()));
        want.insert("post.sentinel-695.level", AttrValue::Str("x".into()));
        want.insert("post.sentinel-695.rel", AttrValue::Set(set));
        assert_eq!(req.resource.0, want);
    }

    #[test]
    fn a_walk_skips_a_withheld_post_without_ending() {
        let mut w = Walker::new(BIG);
        assert!(w.take(&plain(1..=3), &[P, D, P]));
        assert!(!w.stalled());
        let walk = w.finish(&BTreeSet::new());
        assert_eq!(seqs(&walk), [id(1), id(3)]);
        assert_eq!((walk.withheld, walk.returned), (1, 2));
        assert_eq!((walk.first_seq, walk.last_seq), (Some(1), Some(3)));
        assert_eq!(walk.skip_to, None);
        assert_eq!(walk.sent, [1, 3], "only what is returned is sent");
        assert!(!walk.page.more);
    }

    #[test]
    fn an_undecided_post_stops_the_walk_and_is_not_withheld() {
        let mut w = Walker::new(BIG);
        assert!(!w.take(&plain(1..=3), &[P, U, P]));
        assert!(w.stalled());
        let walk = w.finish(&BTreeSet::new());
        assert_eq!(seqs(&walk), [id(1)]);
        assert_eq!(walk.withheld, 0);
        assert_eq!(walk.sent, [1], "a stalled walk sends only what it kept");
        assert_eq!(walk.skip_to, None);
        assert!(walk.page.more, "a stalled walk says more");
    }

    #[test]
    fn a_leading_run_ends_at_an_undecided_post() {
        let mut w = Walker::new(BIG);
        assert!(!w.take(&plain(1..=4), &[D, D, U, D]));
        assert!(w.stalled());
        let walk = w.finish(&BTreeSet::new());
        assert!(walk.page.posts.is_empty());
        assert_eq!(walk.skip_to, Some(2));
        assert_eq!(walk.withheld, 2);
        assert!(walk.sent.is_empty(), "a denied post is never sent");
    }

    #[test]
    fn a_leading_withheld_run_sets_skip_to_and_a_later_one_does_not() {
        let mut w = Walker::new(BIG);
        let posts = plain(1..=5);
        assert!(w.take(&posts[..2], &[D, D]));
        assert!(w.take(&posts[2..], &[P, D, D]));
        let walk = w.finish(&BTreeSet::new());
        assert_eq!(seqs(&walk), [id(3)]);
        assert_eq!(walk.skip_to, Some(2));
        assert_eq!(walk.withheld, 4);
        assert_eq!(walk.sent, [3]);
        let mut none = Walker::new(BIG);
        assert!(none.take(&[], &[]));
        let walk = none.finish(&BTreeSet::new());
        assert_eq!((walk.skip_to, walk.sent), (None, vec![]));
    }

    #[test]
    fn more_is_set_only_by_a_permitted_post_left_out() {
        let page = BOARD_READ_PAGE_POSTS as u64;
        let mut full = Walker::new(BIG);
        let posts = plain(1..=page + 2);
        let mut verdicts = vec![P; BOARD_READ_PAGE_POSTS];
        verdicts.extend([D, D]);
        assert!(full.take(&posts, &verdicts));
        let walk = full.finish(&BTreeSet::new());
        assert_eq!(walk.page.posts.len(), BOARD_READ_PAGE_POSTS);
        assert!(
            !walk.page.more,
            "withheld posts after a full page set no more"
        );
        assert_eq!(walk.withheld, 2);

        let mut over = Walker::new(BIG);
        assert!(!over.take(&plain(1..=page + 1), &[P; BOARD_READ_PAGE_POSTS + 1]));
        assert!(!over.stalled());
        let walk = over.finish(&BTreeSet::new());
        assert_eq!(walk.page.posts.len(), BOARD_READ_PAGE_POSTS);
        assert!(walk.page.more);
        assert_eq!(
            walk.sent,
            (1..=page).collect::<Vec<_>>(),
            "the post left out is not sent"
        );

        let one = post_size(&stored(1, None, PostLabels::default()));
        let mut budget = Walker::new(one + one / 2);
        assert!(!budget.take(&plain(1..=2), &[P, P]));
        let walk = budget.finish(&BTreeSet::new());
        assert_eq!(seqs(&walk), [id(1)]);
        assert!(walk.page.more);
        assert_eq!(walk.sent, [1]);
    }

    #[test]
    fn withheld_counts_only_posts_walked() {
        let page = BOARD_READ_PAGE_POSTS as u64;
        let mut w = Walker::new(BIG);
        let mut verdicts = vec![P; BOARD_READ_PAGE_POSTS + 1];
        verdicts.push(D);
        assert!(!w.take(&plain(1..=page + 2), &verdicts));
        let walk = w.finish(&BTreeSet::new());
        assert_eq!(walk.withheld, 0);
        let mut stalled = Walker::new(BIG);
        assert!(!stalled.take(&plain(1..=3), &[D, U, D]));
        assert_eq!(stalled.finish(&BTreeSet::new()).withheld, 1);
    }

    #[test]
    fn the_first_permitted_post_is_always_kept() {
        let mut w = Walker::new(0);
        assert!(!w.take(&plain(1..=2), &[P, P]));
        let walk = w.finish(&BTreeSet::new());
        assert_eq!(seqs(&walk), [id(1)]);
        assert!(walk.page.more);
    }

    #[test]
    fn a_reply_keeps_its_target_only_when_the_target_is_visible() {
        let posts = vec![
            stored(1, None, PostLabels::default()),
            stored(10, Some(1), PostLabels::default()),
            stored(11, Some(98), PostLabels::default()),
            stored(12, Some(99), PostLabels::default()),
        ];
        let mut w = Walker::new(BIG);
        assert!(w.take(&posts, &[P, P, P, P]));
        let targets: BTreeSet<PostId> = w.reply_targets().into_iter().collect();
        assert_eq!(targets, [id(98), id(99)].into());
        let walk = w.finish(&[id(98)].into());
        let replies: Vec<Option<PostId>> = walk
            .page
            .posts
            .iter()
            .map(|p| p.draft.in_reply_to)
            .collect();
        assert_eq!(replies, [None, Some(id(1)), Some(id(98)), None]);
    }

    #[test]
    fn a_post_verdict_is_permit_deny_or_undecided() {
        let permit = |id: &str| Verdict::Permit {
            obligations: vec![maknae_security::Obligation {
                id: id.into(),
                params: Attributes::new(),
            }],
        };
        let deny = |reason: &str| Verdict::Deny {
            reason: reason.into(),
        };
        for (verdict, want) in [
            (permit("audit"), P),
            (permit("sentinel-695-unhonourable"), U),
            (deny("sentinel-695-withheld"), D),
            (Verdict::NotApplicable { note: None }, D),
            (Verdict::Indeterminate, U),
            (deny(maknae_security::INDETERMINATE_BLOCKS), U),
            (conflicted(), U),
        ] {
            assert_eq!(post_verdict(verdict.clone()), want, "{verdict:?}");
        }
    }

    /// Two operands' permits whose obligations conflict, as `combine` folds them.
    fn conflicted() -> Verdict {
        let with = |v: &str| {
            let mut params = Attributes::new();
            params.insert("sentinel-695-param", AttrValue::Str(v.into()));
            Verdict::Permit {
                obligations: vec![maknae_security::Obligation {
                    id: "sentinel-695-ob".into(),
                    params,
                }],
            }
        };
        maknae_security::combine(vec![with("a"), with("b")])
    }

    #[test]
    fn a_leading_post_whose_obligations_conflict_stalls_the_walk_and_skips_nothing() {
        let verdicts: Vec<_> = [
            conflicted(),
            Verdict::Permit {
                obligations: vec![],
            },
        ]
        .into_iter()
        .map(post_verdict)
        .collect();
        let mut w = Walker::new(BIG);
        assert!(!w.take(&plain(1..=2), &verdicts));
        assert!(w.stalled());
        let walk = w.finish(&BTreeSet::new());
        assert_eq!(walk.skip_to, None);
        assert!(walk.page.posts.is_empty());
    }

    /// Answers `base` for a request without the post label and permits every other one.
    struct Scripted {
        base: Verdict,
        calls: std::sync::atomic::AtomicUsize,
    }

    impl Authorizer for Scripted {
        fn decide_cited_all(
            &self,
            reqs: &[maknae_security::Request],
        ) -> Vec<maknae_security::Decided> {
            maknae_security::decide_each_cited(self, reqs)
        }

        fn decide(&self, req: &maknae_security::Request) -> Verdict {
            self.calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            match req.resource.0.get("post.sentinel-695.level") {
                Some(_) => Verdict::Permit {
                    obligations: Vec::new(),
                },
                None => self.base.clone(),
            }
        }
    }

    #[tokio::test]
    async fn a_batch_is_undecided_unless_the_verbs_own_request_is_permitted_again() {
        let base = maknae_security::Request {
            subject: maknae_security::Subject(Attributes::new()),
            resource: maknae_security::Resource(Attributes::new()),
            action: maknae_security::Action("board.read".into()),
            context: maknae_security::Context(Attributes::new()),
        };
        let labels = PostLabels(
            [(
                "sentinel-695.level".to_string(),
                LabelValue::Str("x".into()),
            )]
            .into(),
        );
        let posts: Vec<_> = (1..=2)
            .map(|seq| post_request(&base, BOB, &stored(seq, None, labels.clone())))
            .collect();
        let live = Arc::new(crate::live::LiveConfig::new(Default::default(), None));
        let generation = live.generation();
        let unhonourable = Verdict::Permit {
            obligations: vec![maknae_security::Obligation {
                id: "sentinel-695-unhonourable".into(),
                params: Attributes::new(),
            }],
        };
        for (verdict, want) in [
            (
                Verdict::Permit {
                    obligations: Vec::new(),
                },
                vec![P, P],
            ),
            (
                Verdict::Deny {
                    reason: "sentinel-695-contained".into(),
                },
                vec![U, U],
            ),
            (Verdict::NotApplicable { note: None }, vec![U, U]),
            (unhonourable, vec![U, U]),
        ] {
            let pdp = Arc::new(Scripted {
                base: verdict.clone(),
                calls: Default::default(),
            });
            let got = decide_posts(
                &pdp,
                &live,
                generation,
                Duration::from_secs(5),
                &base,
                posts.clone(),
            )
            .await;
            assert_eq!(got, want, "{verdict:?}");
        }
        let pdp = Arc::new(Scripted {
            base: Verdict::Permit {
                obligations: Vec::new(),
            },
            calls: Default::default(),
        });
        let none = decide_posts(
            &pdp,
            &live,
            generation,
            Duration::from_secs(5),
            &base,
            Vec::new(),
        )
        .await;
        assert!(none.is_empty(), "an empty batch permits nothing");
        assert_eq!(pdp.calls.load(std::sync::atomic::Ordering::SeqCst), 0);
    }

    #[test]
    fn a_store_refusal_names_its_defect() {
        for (r, defect, said) in [
            (BoardRefusal::Full, BoardDefect::Full, "unauthorized"),
            (
                BoardRefusal::AuthorAtCap,
                BoardDefect::AuthorAtCap,
                "unauthorized",
            ),
            (
                BoardRefusal::NoSuchPost,
                BoardDefect::NoSuchPost,
                "unauthorized",
            ),
            (
                BoardRefusal::Store("x".into()),
                BoardDefect::TryAgain,
                "unauthorized",
            ),
            (BoardRefusal::Random, BoardDefect::TryAgain, "unauthorized"),
            (
                BoardRefusal::StillContained,
                BoardDefect::TryAgain,
                "unauthorized",
            ),
            (
                BoardRefusal::Unavailable("outcome unknown: x".into()),
                BoardDefect::OutcomeUnknown,
                "unavailable",
            ),
        ] {
            assert_eq!((defect_of(&r), posture(&r)), (defect, said), "{r}");
        }
    }

    #[test]
    fn the_digest_is_sha256_of_the_canonical_content() {
        let mut d = draft("sentinel-695-body", None);
        d.attachments.push(Attachment {
            label: "a".into(),
            media: Media::TextPlain,
            content: secret("sentinel-695-att"),
        });
        let digest = post_digest(&d).unwrap();
        let bytes = maknae_proto::post_content_bytes(&d).unwrap();
        let want: String = maknae_crypto::sha256(&bytes)
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect();
        assert_eq!(digest, want);
        assert_eq!(digest.len(), 64);
        assert!(digest
            .bytes()
            .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase()));
        let mut other = d.clone();
        other.kind = PostKind::Question;
        other.to = Addressee::Tasker;
        assert_eq!(post_digest(&other).unwrap(), digest, "content only");
        other.body = secret("sentinel-695-other");
        assert_ne!(post_digest(&other).unwrap(), digest);
    }
}
