//! The board verbs (#695): the switch gate, the per-post decision and the page walk.
use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;
use std::time::Duration;

use maknae_audit_append::{AuditRecord, BoardAudit};
use maknae_config::AgentId;
use maknae_proto::{
    Addressee, BoardDefect, BoardEntry, BoardHold, BoardListing, BoardPage, PostDraft, PostId,
    ProtoCodecError, BOARD_READ_PAGE_POSTS,
};
use maknae_security::{AttrValue, Attributes, Authorizer, Decision, Verdict};

use crate::blocking_guard::{admit_blocking, Offload};
use crate::board::{BoardDue, BoardDueFor, BoardRefusal, BoardStore, Window};
use crate::board_store::{BoardKey, HeldFor, LabelValue, Report, Settings, Stored};
use crate::boot::BootConfig;
use crate::enrollment::{EnrollmentView, Load};
use crate::task::CitedTask;

pub trait BoardSwitches: Send + Sync {
    fn site(&self) -> bool;
    fn agent(&self, agent: &AgentId) -> bool;
}

/// The site switch from `maknae.yaml`, and each agent's from the installed snapshot.
pub struct ConfiguredSwitches {
    site: bool,
    view: Arc<dyn EnrollmentView>,
}

impl ConfiguredSwitches {
    pub fn from_boot(boot: &BootConfig, view: Arc<dyn EnrollmentView>) -> Self {
        ConfiguredSwitches {
            site: boot.board().enabled,
            view,
        }
    }
}

impl BoardSwitches for ConfiguredSwitches {
    fn site(&self) -> bool {
        self.site
    }

    fn agent(&self, agent: &AgentId) -> bool {
        self.view.board(agent)
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
    AgentChannel,
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
            Off::AgentChannel => "board: not served on the agent channel",
            Off::NoTasker => "board off: the chain has no tasker",
            Off::Site => "board off: site",
            Off::Agent => "board off: agent",
            Off::Tasker => "board off: tasker",
            Off::NoTask => "board: the request cites no task",
        })
    }
}

/// `Ok(None)` for an agent citing no task: the decision refuses it. Otherwise the board
/// and the policy load the switches were read from, in the same hold.
pub(crate) fn gate(
    channel_agent: Option<&AgentId>,
    cited: Option<&CitedTask>,
    switches: &dyn BoardSwitches,
    board: &BoardStore,
    view: &dyn EnrollmentView,
) -> Result<Option<(BoardKey, Load)>, Off> {
    let agent = channel_agent.ok_or(Off::ClientChannel)?;
    let Some(cited) = cited else {
        return Ok(None);
    };
    let key = BoardKey::of(&cited.root).ok_or(Off::NoTasker)?;
    if !switches.site() {
        return Err(Off::Site);
    }
    let ((agent_on, load), tasker_on) =
        board.enabled_with(key, || (switches.agent(agent), view.load()));
    if !agent_on {
        return Err(Off::Agent);
    }
    if !tasker_on {
        return Err(Off::Tasker);
    }
    Ok(Some((key, load)))
}

pub(crate) const POLICY_CHANGED: &str = "board: the policy changed during the request";

pub(crate) const ONLY_A_PERSON: &str = "board: only a person manages a board";

/// The board a `board.manage` acts on: the caller's own, and only a person's.
pub(crate) fn manage_key(channel_agent: Option<&AgentId>, uid: u32) -> Option<BoardKey> {
    match channel_agent {
        None => Some(BoardKey(uid)),
        Some(_) => None,
    }
}

pub(crate) fn wire_settings(s: Settings) -> maknae_proto::BoardSettings {
    maknae_proto::BoardSettings {
        enabled: s.enabled,
        report: match s.report {
            Report::Off => maknae_proto::BoardReport::Off,
            Report::Summary => maknae_proto::BoardReport::Summary,
            Report::Every => maknae_proto::BoardReport::Every,
        },
    }
}

pub(crate) fn stored_settings(s: maknae_proto::BoardSettings) -> Settings {
    Settings {
        enabled: s.enabled,
        report: match s.report {
            maknae_proto::BoardReport::Off => Report::Off,
            maknae_proto::BoardReport::Summary => Report::Summary,
            maknae_proto::BoardReport::Every => Report::Every,
        },
    }
}

/// `enabled=<bool> report=<off|summary|every>`.
pub(crate) fn settings_text(s: Settings) -> String {
    let report = match s.report {
        Report::Off => "off",
        Report::Summary => "summary",
        Report::Every => "every",
    };
    format!("enabled={} report={report}", s.enabled)
}

pub(crate) fn removed_audit(ids: &[PostId]) -> BoardAudit {
    BoardAudit {
        removed: Some(ids.iter().map(PostId::to_string).collect()),
        ..BoardAudit::default()
    }
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

/// A batch's verdicts, and whether it confirmed the verb's own request.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Decided {
    pub confirmed: bool,
    pub verdicts: Vec<PostVerdict>,
}

/// One guarded batch, under the decision breaker and timeout, on one view of the policy.
/// `base`, the verb's own request, is decided again at the head of the batch; unless it is
/// permitted, every post is undecided. An empty batch decides nothing, permits nothing and
/// confirms nothing.
pub(crate) async fn decide_posts<P: Authorizer + Send + Sync + 'static>(
    authorizer: &Arc<P>,
    live: &Arc<crate::live::LiveConfig>,
    admitted_generation: u64,
    timeout: Duration,
    base: &maknae_security::Request,
    requests: Vec<maknae_security::Request>,
) -> Decided {
    let n = requests.len();
    if n == 0 {
        return Decided {
            confirmed: false,
            verdicts: Vec::new(),
        };
    }
    match decide_batch(
        authorizer,
        live,
        admitted_generation,
        timeout,
        base,
        requests,
    )
    .await
    {
        Some(verdicts) => Decided {
            confirmed: true,
            verdicts,
        },
        None => Decided {
            confirmed: false,
            verdicts: vec![PostVerdict::Undecided; n],
        },
    }
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

/// The posts' verdicts, or `None` when `base` is not permitted again, the batch did not
/// complete, or the live values were replaced while it ran. `guarded_decide_cited_all`
/// answers one verdict per request.
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
        Ok((all, generation)) if generation == admitted_generation => {
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
    /// The sequences of the posts on the page.
    pub sent: Vec<u64>,
}

/// One read's page, built post by post in board order, from every post decided so far.
/// A post found no longer live is made absent and the page is built again without it.
pub(crate) struct Walker {
    budget: usize,
    decided: Vec<(Arc<Stored>, PostVerdict)>,
    absent: BTreeSet<u64>,
    at: Walked,
}

/// The walk over `decided`, as far as it went.
#[derive(Default)]
struct Walked {
    used: usize,
    kept: Vec<Arc<Stored>>,
    withheld: u32,
    /// The permitted post the page had no room for: what `more` stands on.
    lookahead: Option<Arc<Stored>>,
    /// The undecided post the walk stopped at.
    stop: Option<Arc<Stored>>,
}

/// A post's encoded size, counted without a buffer.
pub(crate) fn post_size(stored: &Stored) -> usize {
    encoded_len(&stored.post)
}

impl Walker {
    pub(crate) fn new(budget: usize) -> Self {
        Walker {
            budget,
            decided: Vec::new(),
            absent: BTreeSet::new(),
            at: Walked::default(),
        }
    }

    /// `false` once the walk has ended: a post undecided, or a permitted post left out.
    pub(crate) fn take(&mut self, chunk: &[Arc<Stored>], verdicts: &[PostVerdict]) -> bool {
        let from = self.decided.len();
        self.decided.extend(chunk.iter().enumerate().map(|(i, s)| {
            let verdict = verdicts.get(i).copied().unwrap_or(PostVerdict::Undecided);
            (Arc::clone(s), verdict)
        }));
        self.walk_from(from)
    }

    fn ended(&self) -> bool {
        self.at.stop.is_some() || self.at.lookahead.is_some()
    }

    /// Walks `decided[from..]` until the walk ends; `false` once it has.
    fn walk_from(&mut self, from: usize) -> bool {
        for i in from..self.decided.len() {
            if self.ended() {
                break;
            }
            let (stored, verdict) = (Arc::clone(&self.decided[i].0), self.decided[i].1);
            self.step(stored, verdict);
        }
        !self.ended()
    }

    fn step(&mut self, stored: Arc<Stored>, verdict: PostVerdict) {
        let at = &mut self.at;
        match verdict {
            PostVerdict::Undecided => at.stop = Some(stored),
            PostVerdict::Deny => at.withheld = at.withheld.saturating_add(1),
            PostVerdict::Permit => {
                let size = post_size(&stored);
                let fits = at.kept.len() < BOARD_READ_PAGE_POSTS
                    && at.used.saturating_add(size) <= self.budget;
                if !at.kept.is_empty() && !fits {
                    at.lookahead = Some(stored);
                    return;
                }
                at.used = at.used.saturating_add(size);
                at.kept.push(stored);
            }
        }
    }

    pub(crate) fn stalled(&self) -> bool {
        self.at.stop.is_some()
    }

    pub(crate) fn wants_more(&self) -> bool {
        !self.ended()
    }

    pub(crate) fn is_absent(&self, seq: u64) -> bool {
        self.absent.contains(&seq)
    }

    /// Every post whose presence shaped the page so far: each kept post, the lookahead and
    /// the undecided stop. The leading denied run is not one: a post denied to the reader
    /// is passed whether or not it is still live.
    pub(crate) fn influences(&self) -> Vec<u64> {
        let at = &self.at;
        at.kept
            .iter()
            .chain(&at.lookahead)
            .chain(&at.stop)
            .map(|s| s.seq)
            .collect()
    }

    /// Makes absent each kept post, lookahead or stop that `live` does not hold, and walks
    /// again without them; a dead stop also drops the undecided verdicts after it, to be
    /// decided again. `true` when anything changed.
    pub(crate) fn drop_dead(&mut self, live: &BTreeSet<u64>) -> bool {
        let at = &self.at;
        let dead: Vec<u64> = at
            .kept
            .iter()
            .chain(&at.lookahead)
            .chain(&at.stop)
            .map(|s| s.seq)
            .filter(|seq| !live.contains(seq))
            .collect();
        if dead.is_empty() {
            return false;
        }
        let stop_dead = at.stop.as_ref().is_some_and(|s| !live.contains(&s.seq));
        self.absent.extend(dead);
        let absent = &self.absent;
        self.decided.retain(|(s, _)| !absent.contains(&s.seq));
        if stop_dead {
            if let Some(i) = self
                .decided
                .iter()
                .position(|(_, v)| *v == PostVerdict::Undecided)
            {
                self.decided.truncate(i);
            }
        }
        self.at = Walked::default();
        self.walk_from(0);
        true
    }

    /// The highest sequence the final check must find no new live post below: the last
    /// post decided when the walk ended, or `upper` when it ran to the end of the range.
    pub(crate) fn hi(&self, upper: u64) -> u64 {
        if self.ended() {
            self.decided.last().map_or(upper, |(s, _)| s.seq)
        } else {
            upper
        }
    }

    /// The lowest of `in_range` the walk has neither decided nor made absent: a post that
    /// came alive since the walk passed its place.
    pub(crate) fn missing(&self, in_range: &BTreeSet<u64>) -> Option<u64> {
        let decided: BTreeSet<u64> = self.decided.iter().map(|(s, _)| s.seq).collect();
        in_range
            .iter()
            .copied()
            .find(|seq| !decided.contains(seq) && !self.absent.contains(seq))
    }

    /// Forgets every verdict from `seq` on and walks again what is left, so the posts from
    /// `seq` are fetched and decided again in order.
    pub(crate) fn rewalk_from(&mut self, seq: u64) {
        self.decided.retain(|(s, _)| s.seq < seq);
        self.at = Walked::default();
        self.walk_from(0);
    }

    /// The sequence to fetch candidates after: the last post decided and still walked.
    pub(crate) fn resume_after(&self) -> Option<u64> {
        self.decided.last().map(|(s, _)| s.seq)
    }

    pub(crate) fn reply_targets(&self) -> Vec<PostId> {
        let kept: BTreeSet<PostId> = self.at.kept.iter().map(|s| s.post.id).collect();
        let targets: BTreeSet<PostId> = self
            .at
            .kept
            .iter()
            .filter_map(|s| s.post.draft.in_reply_to)
            .filter(|t| !kept.contains(t))
            .collect();
        targets.into_iter().collect()
    }

    pub(crate) fn finish(self, visible_targets: &BTreeSet<PostId>) -> Walk {
        let at = self.at;
        let more = at.lookahead.is_some() || at.stop.is_some();
        let kept: BTreeSet<PostId> = at.kept.iter().map(|s| s.post.id).collect();
        let posts = at
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
            page: BoardPage { posts, more },
            first_seq: at.kept.first().map(|s| s.seq),
            last_seq: at.kept.last().map(|s| s.seq),
            returned: u32::try_from(at.kept.len()).unwrap_or(u32::MAX),
            withheld: at.withheld,
            sent: at.kept.iter().map(|s| s.seq).collect(),
        }
    }
}

/// How a verb's posts are decided: its own request, on one view of the policy.
pub(crate) struct Deciding<'a, P> {
    pub authorizer: &'a Arc<P>,
    pub live: &'a Arc<crate::live::LiveConfig>,
    pub generation: u64,
    pub timeout: Duration,
    pub request: &'a maknae_security::Request,
}

impl<P> Clone for Deciding<'_, P> {
    fn clone(&self) -> Self {
        *self
    }
}

impl<P> Copy for Deciding<'_, P> {}

/// A read's finished walk, built from one liveness check that found every influence live,
/// and whether the read's own request was confirmed permitted during the read.
pub(crate) struct Read {
    pub walk: Walk,
    pub base_confirmed: bool,
    pub stalled: bool,
}

/// The most passes one read makes. A page's influences are its posts, the lookahead and the
/// stop; each can be found dead once and as many posts found alive below them, plus the
/// final pass. A read changed under it for longer is stalled.
pub const READ_ROUNDS: usize = 2 * (BOARD_READ_PAGE_POSTS + 2) + 1;

/// One read's walk over the posts in `(cursor, upper]`, decided in batches. Each pass walks
/// to a fixpoint, confirms the read's own request if no batch did, then checks every post
/// that shaped the reply in one memory-only `still_live`; a dead one is walked as absent and
/// the pass repeats. That check is the last observation: the walk is finished right after
/// it, with no await between. An absent post is never decided again; after `READ_ROUNDS`
/// passes the read is stalled and sends nothing.
pub(crate) async fn read_page<P: Authorizer + Send + Sync + 'static>(
    store: &BoardStore,
    key: BoardKey,
    view: &dyn crate::enrollment::EnrollmentView,
    d: &Deciding<'_, P>,
    (cursor, upper): (u64, u64),
    budget: usize,
) -> Read {
    let Deciding {
        authorizer,
        live,
        generation,
        timeout,
        request,
    } = *d;
    let mut walker = Walker::new(budget);
    let mut after = cursor;
    let mut base_confirmed = false;
    for _ in 0..READ_ROUNDS {
        while walker.wants_more() {
            let raw: Vec<_> = store
                .candidates(key, after, BOARD_READ_PAGE_POSTS)
                .into_iter()
                .take_while(|s| s.seq <= upper)
                .collect();
            let Some(last) = raw.last() else {
                break;
            };
            after = last.seq;
            let chunk: Vec<_> = raw
                .into_iter()
                .filter(|s| !walker.is_absent(s.seq))
                .collect();
            if chunk.is_empty() {
                continue;
            }
            let asked = chunk
                .iter()
                .map(|s| post_request(request, key, s))
                .collect();
            let decided = decide_posts(authorizer, live, generation, timeout, request, asked).await;
            base_confirmed |= decided.confirmed;
            walker.take(&chunk, &decided.verdicts);
        }
        let mut targets = Vec::new();
        if !walker.stalled() {
            let asked: Vec<_> = walker
                .reply_targets()
                .into_iter()
                .filter_map(|id| store.get(key, id))
                .collect();
            let requests = asked
                .iter()
                .map(|t| post_request(request, key, t))
                .collect();
            let decided =
                decide_posts(authorizer, live, generation, timeout, request, requests).await;
            base_confirmed |= decided.confirmed;
            targets = asked
                .into_iter()
                .zip(decided.verdicts)
                .filter(|(_, v)| *v == PostVerdict::Permit)
                .map(|(t, _)| t)
                .collect();
        }
        if !base_confirmed {
            base_confirmed = base_holds(authorizer, live, generation, timeout, request).await;
            if !base_confirmed {
                return Read {
                    walk: walker.finish(&BTreeSet::new()),
                    base_confirmed,
                    stalled: true,
                };
            }
        }
        let mut influences = walker.influences();
        influences.extend(targets.iter().map(|t| t.seq));
        let seen = store.observe(key, &influences, (cursor, walker.hi(upper)), view);
        let dropped = walker.drop_dead(&seen.live);
        let missing = walker.missing(&seen.in_range);
        if let Some(seq) = missing {
            walker.rewalk_from(seq);
        }
        if !dropped && missing.is_none() {
            let visible = targets
                .iter()
                .filter(|t| seen.live.contains(&t.seq))
                .map(|t| t.post.id)
                .collect();
            let stalled = walker.stalled();
            return Read {
                walk: walker.finish(&visible),
                base_confirmed,
                stalled,
            };
        }
        after = walker.resume_after().unwrap_or(cursor);
    }
    Read {
        walk: Walker::new(budget).finish(&BTreeSet::new()),
        base_confirmed,
        stalled: true,
    }
}

pub(crate) const LISTED: &str = "done";
pub(crate) const LISTED_OLDER: &str = "done; older posts remain";

/// One listing page; `links` maps an entry's sequence to its kept reply target's.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Paged {
    pub listing: BoardListing,
    pub withheld: u32,
    pub links: BTreeMap<u64, u64>,
}

/// The newest released post alone is over the page budget.
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct Oversize;

fn encoded_len<T: serde::Serialize>(value: &T) -> usize {
    let mut size = crate::task_store::Counted(0);
    match ciborium::into_writer(value, &mut size) {
        Ok(()) => size.0,
        Err(_) => usize::MAX,
    }
}

pub(crate) fn entry_size(e: &BoardEntry) -> usize {
    encoded_len(e)
}

/// `verdicts` are `w.posts`' and then `w.targets'`.
pub(crate) fn paged(w: Window, verdicts: &[PostVerdict], budget: usize) -> Result<Paged, Oversize> {
    let verdict = |i: usize| verdicts.get(i).copied().unwrap_or(PostVerdict::Undecided);
    let permitted: BTreeMap<PostId, u64> = w
        .posts
        .iter()
        .map(|l| &l.stored)
        .chain(&w.targets)
        .enumerate()
        .filter(|(i, _)| verdict(*i) == PostVerdict::Permit)
        .map(|(_, s)| (s.post.id, s.seq))
        .collect();
    let mut p = Paged {
        listing: BoardListing {
            entries: Vec::new(),
            older: None,
        },
        withheld: 0,
        links: BTreeMap::new(),
    };
    let (mut used, mut cut) = (0usize, false);
    for (i, l) in w.posts.iter().enumerate() {
        if verdict(i) != PostVerdict::Permit {
            p.withheld = p.withheld.saturating_add(1);
            continue;
        }
        if cut {
            continue;
        }
        let mut post = l.stored.post.clone();
        let link = post.draft.in_reply_to.and_then(|t| permitted.get(&t));
        if link.is_none() {
            post.draft.in_reply_to = None;
        }
        let held = l
            .held
            .iter()
            .map(|h| match h {
                HeldFor::Author => BoardHold::Author,
                HeldFor::Person => BoardHold::Person,
            })
            .collect();
        let entry = BoardEntry {
            seq: l.stored.seq,
            post,
            held,
        };
        let size = entry_size(&entry);
        if used.saturating_add(size) > budget {
            cut = true;
            continue;
        }
        used = used.saturating_add(size);
        if let Some(t) = link {
            p.links.insert(entry.seq, *t);
        }
        p.listing.entries.push(entry);
    }
    p.listing.older = match p.listing.entries.last() {
        Some(lowest) => (cut || w.more).then_some(lowest.seq),
        None if cut => return Err(Oversize),
        None => w.posts.last().filter(|_| w.more).map(|l| l.stored.seq),
    };
    p.listing.entries.reverse();
    Ok(p)
}

/// Drops each entry `live` does not hold, and each kept link to a target it does not hold.
pub(crate) fn settle(mut p: Paged, live: &BTreeSet<u64>) -> Paged {
    p.listing.entries.retain(|e| live.contains(&e.seq));
    for e in &mut p.listing.entries {
        if p.links.get(&e.seq).is_some_and(|t| !live.contains(t)) {
            e.post.draft.in_reply_to = None;
        }
    }
    p
}

pub(crate) fn list_audit(p: &Paged) -> BoardAudit {
    let entries = &p.listing.entries;
    BoardAudit {
        first_seq: entries.first().map(|e| e.seq),
        last_seq: entries.last().map(|e| e.seq),
        returned: Some(u32::try_from(entries.len()).unwrap_or(u32::MAX)),
        withheld: Some(p.withheld),
        ..BoardAudit::default()
    }
}

/// One page of `key`'s board below `before`, its window and reply targets decided in one
/// batch. `None` when the batch did not confirm the request's own decision, or the newest
/// released post alone is over `budget`.
pub(crate) async fn list_page<P: Authorizer + Send + Sync + 'static>(
    store: &BoardStore,
    key: BoardKey,
    view: &dyn EnrollmentView,
    d: &Deciding<'_, P>,
    before: Option<u64>,
    budget: usize,
) -> Option<Paged> {
    let w = store.listing(key, before, BOARD_READ_PAGE_POSTS, view);
    let asked: Vec<_> = w
        .posts
        .iter()
        .map(|l| &l.stored)
        .chain(&w.targets)
        .map(|s| post_request(d.request, key, s))
        .collect();
    let verdicts = if asked.is_empty() {
        if !base_holds(d.authorizer, d.live, d.generation, d.timeout, d.request).await {
            return None;
        }
        Vec::new()
    } else {
        let decided = decide_posts(
            d.authorizer,
            d.live,
            d.generation,
            d.timeout,
            d.request,
            asked,
        )
        .await;
        if !decided.confirmed {
            return None;
        }
        decided.verdicts
    };
    paged(w, &verdicts, budget).ok()
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
        body_bytes: bytes(draft.body.expose().len()),
        attachment_bytes: bytes(
            draft
                .attachments
                .iter()
                .map(|a| a.content.expose().len())
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

    #[test]
    fn board_manage_keys_the_callers_own_board_and_only_a_persons() {
        assert_eq!(manage_key(None, 1000), Some(BoardKey(1000)));
        assert_eq!(manage_key(None, 0), Some(BoardKey(0)));
        let hobi = AgentId::parse("hobi").unwrap();
        assert_eq!(manage_key(Some(&hobi), 1000), None);
        assert_eq!(manage_key(Some(&hobi), 2001), None);
        assert_eq!(ONLY_A_PERSON, "board: only a person manages a board");
    }

    #[test]
    fn the_settings_text_names_enabled_and_report_only() {
        assert_eq!(
            settings_text(Settings::default()),
            "enabled=false report=off"
        );
    }

    #[test]
    fn the_settings_convert_both_ways_and_read_as_pinned() {
        use maknae_proto::{BoardReport as W, BoardSettings};
        let mut seen = BTreeSet::new();
        for (enabled, stored, wire, said) in [
            (false, Report::Off, W::Off, "enabled=false report=off"),
            (
                true,
                Report::Summary,
                W::Summary,
                "enabled=true report=summary",
            ),
            (false, Report::Every, W::Every, "enabled=false report=every"),
            (true, Report::Off, W::Off, "enabled=true report=off"),
        ] {
            let kernel = Settings {
                enabled,
                report: stored,
            };
            let on_wire = BoardSettings {
                enabled,
                report: wire,
            };
            assert_eq!(wire_settings(kernel), on_wire);
            assert_eq!(stored_settings(on_wire), kernel);
            assert_eq!(settings_text(kernel), said);
            seen.insert(said);
        }
        assert_eq!(seen.len(), 4);
    }

    #[test]
    fn a_clear_names_its_removed_posts_in_lowercase_hex() {
        let ids = [PostId([0xab; 16]), PostId([0x01; 16])];
        assert_eq!(
            removed_audit(&ids),
            BoardAudit {
                removed: Some(vec!["ab".repeat(16), "01".repeat(16)]),
                ..BoardAudit::default()
            }
        );
        assert_eq!(
            removed_audit(&[]),
            BoardAudit {
                removed: Some(Vec::new()),
                ..BoardAudit::default()
            }
        );
    }

    const BOB: BoardKey = BoardKey(1000);

    fn boot_with(board: Option<bool>) -> crate::BootConfig {
        use maknae_config::Value;
        let mut sections = vec![(
            "deployment".to_string(),
            Value::Map(vec![("mode".into(), Value::Str("container".into()))]),
        )];
        if let Some(on) = board {
            sections.push((
                "board".to_string(),
                Value::Map(vec![("enabled".into(), Value::Bool(on))]),
            ));
        }
        crate::boot::assemble(maknae_config::Document::from_sections_for_test(sections))
            .expect("assembles")
    }

    #[test]
    fn the_configured_switches_read_the_site_from_boot_and_the_agent_from_the_view() {
        use crate::enrollment::{Boarding, FixedEnrollment};
        let jin = AgentId::parse("sentinel-698-jin").unwrap();
        let unknown = AgentId::parse("sentinel-698-nobody").unwrap();
        let enrolled = FixedEnrollment([(hobi(), 12_101), (jin.clone(), 12_103)].into());
        let views: [(&str, Arc<dyn crate::EnrollmentView>, bool); 2] = [
            (
                "agent on",
                Arc::new(Boarding(enrolled.clone(), [hobi()].into())),
                true,
            ),
            (
                "agent off",
                Arc::new(Boarding(enrolled.clone(), BTreeSet::new())),
                false,
            ),
        ];
        for (board, site) in [(None, false), (Some(false), false), (Some(true), true)] {
            for (name, view, agent) in &views {
                let s = ConfiguredSwitches::from_boot(&boot_with(board), Arc::clone(view));
                assert_eq!(s.site(), site, "{board:?} {name}");
                assert_eq!(s.agent(&hobi()), *agent, "{board:?} {name}");
                assert!(!s.agent(&jin), "{board:?} {name}");
                assert!(!s.agent(&unknown), "{board:?} {name}");
            }
        }
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
            addendum: None,
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

    /// The agent's switch, read first; reading it starts an install that turns it off and
    /// a write that turns the tasker on, and gives both 300 ms before it answers.
    struct FlipWhileRead {
        agent_on: Arc<std::sync::atomic::AtomicBool>,
        board: Arc<BoardStore>,
        flipper: std::sync::Mutex<Option<std::thread::JoinHandle<()>>>,
    }

    impl BoardSwitches for FlipWhileRead {
        fn site(&self) -> bool {
            true
        }

        fn agent(&self, _: &AgentId) -> bool {
            use std::sync::atomic::Ordering::SeqCst;
            let on = self.agent_on.load(SeqCst);
            let (agent_on, board) = (Arc::clone(&self.agent_on), Arc::clone(&self.board));
            let (done, wait) = std::sync::mpsc::channel();
            *self.flipper.lock().unwrap() = Some(std::thread::spawn(move || {
                board.install_and_mark(
                    || agent_on.store(false, SeqCst),
                    &crate::enrollment::FixedEnrollment(Default::default()),
                );
                board
                    .set_settings(
                        BOB,
                        Settings {
                            enabled: true,
                            ..Settings::default()
                        },
                    )
                    .unwrap();
                let _ = done.send(());
            }));
            let _ = wait.recv_timeout(std::time::Duration::from_millis(300));
            on
        }
    }

    /// A view whose installed load is `current`. Reading the agent's switch starts an
    /// install that replaces the load; reading the load first waits up to 300 ms for that
    /// install to land, which it can only do while the board's memory lock is free.
    struct SwapWhileRead {
        current: Arc<std::sync::Mutex<Arc<dyn std::any::Any + Send + Sync>>>,
        board: Arc<BoardStore>,
        landed: std::sync::Mutex<Option<std::sync::mpsc::Receiver<()>>>,
        swapper: std::sync::Mutex<Option<std::thread::JoinHandle<()>>>,
    }

    impl BoardSwitches for SwapWhileRead {
        fn site(&self) -> bool {
            true
        }

        fn agent(&self, _: &AgentId) -> bool {
            let (current, board) = (Arc::clone(&self.current), Arc::clone(&self.board));
            let (done, landed) = std::sync::mpsc::channel();
            *self.landed.lock().unwrap() = Some(landed);
            *self.swapper.lock().unwrap() = Some(std::thread::spawn(move || {
                board.install_and_mark(
                    || *current.lock().unwrap() = Arc::new(2_u8),
                    &crate::enrollment::FixedEnrollment(Default::default()),
                );
                let _ = done.send(());
            }));
            true
        }
    }

    impl EnrollmentView for SwapWhileRead {
        fn agent_uid(&self, _: &AgentId) -> Option<u32> {
            None
        }
        fn agents(&self) -> Vec<(AgentId, u32)> {
            Vec::new()
        }
        fn is_enrolled(&self, _: u32) -> bool {
            false
        }
        fn contained(&self, _: u32) -> bool {
            false
        }
        fn unresolved(&self, _: u32) -> bool {
            false
        }
        fn board(&self, _: &AgentId) -> bool {
            true
        }
        fn load(&self) -> Load {
            if let Some(landed) = self.landed.lock().unwrap().take() {
                let _ = landed.recv_timeout(std::time::Duration::from_millis(300));
            }
            Load::installed(Arc::clone(&self.current.lock().unwrap()))
        }
    }

    #[test]
    fn the_gate_reads_the_policy_load_with_the_switches_and_sees_a_later_install() {
        let first: Arc<dyn std::any::Any + Send + Sync> = Arc::new(1_u8);
        let swap = SwapWhileRead {
            current: Arc::new(std::sync::Mutex::new(Arc::clone(&first))),
            board: Arc::new(enabled(true)),
            landed: std::sync::Mutex::new(None),
            swapper: std::sync::Mutex::new(None),
        };
        let person = cited(RootTasker::Person { uid: BOB.0 });
        let got = gate(Some(&hobi()), Some(&person), &swap, &swap.board, &swap);
        swap.swapper
            .lock()
            .unwrap()
            .take()
            .expect("reading the switch started the install")
            .join()
            .unwrap();
        let (key, load) = got.expect("on").expect("a board");
        assert_eq!(key, BOB);
        assert_eq!(
            load,
            Load::installed(first),
            "the load the switch was read on"
        );
        assert!(!swap.board.still_installed(&load, 0, &swap));
        assert!(swap.board.still_installed(&swap.load(), 0, &swap));
        assert!(!swap.board.still_installed(&swap.load(), 1, &swap));
        assert_ne!(load, swap.load());
    }

    #[test]
    fn the_gate_reads_the_agent_and_the_tasker_at_one_instant() {
        let switches = FlipWhileRead {
            agent_on: Arc::new(true.into()),
            board: Arc::new(enabled(false)),
            flipper: std::sync::Mutex::new(None),
        };
        let person = cited(RootTasker::Person { uid: BOB.0 });
        let got = gate(
            Some(&hobi()),
            Some(&person),
            &switches,
            &switches.board,
            &crate::enrollment::FixedEnrollment(Default::default()),
        );
        switches
            .flipper
            .lock()
            .unwrap()
            .take()
            .expect("reading the switch started the flip")
            .join()
            .unwrap();
        assert_eq!(
            got,
            Err(Off::Tasker),
            "agent on and tasker off, read together"
        );
        assert!(
            switches.board.settings(BOB).enabled,
            "the write landed after"
        );
        assert_eq!(
            gate(
                Some(&hobi()),
                Some(&person),
                &switches,
                &switches.board,
                &crate::enrollment::FixedEnrollment(Default::default()),
            ),
            Err(Off::Agent)
        );
        switches
            .flipper
            .lock()
            .unwrap()
            .take()
            .unwrap()
            .join()
            .unwrap();
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
            let got = gate(
                channel,
                task,
                &sw,
                &enabled(on),
                &crate::enrollment::FixedEnrollment(Default::default()),
            );
            assert_eq!(got.map(|g| g.map(|(key, _)| key)), want, "{at}");
        }
        assert_eq!(
            [
                Off::ClientChannel,
                Off::AgentChannel,
                Off::NoTasker,
                Off::Site,
                Off::Agent,
                Off::Tasker,
                Off::NoTask
            ]
            .map(|o| o.to_string()),
            [
                "board: not served on the client channel",
                "board: not served on the agent channel",
                "board off: the chain has no tasker",
                "board off: site",
                "board off: agent",
                "board off: tasker",
                "board: the request cites no task"
            ]
        );
    }

    fn secret(s: &str) -> SecretText {
        SecretText::from(maknae_io::Zeroizing::new(s.into()))
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
        assert!(walk.page.more, "a stalled walk says more");
    }

    #[test]
    fn a_leading_run_ends_at_an_undecided_post() {
        let mut w = Walker::new(BIG);
        assert!(!w.take(&plain(1..=4), &[D, D, U, D]));
        assert!(w.stalled());
        let walk = w.finish(&BTreeSet::new());
        assert!(walk.page.posts.is_empty());
        assert_eq!(walk.withheld, 2);
        assert!(walk.sent.is_empty(), "a denied post is never sent");
    }

    #[test]
    fn a_withheld_post_costs_no_room_on_the_page() {
        let mut w = Walker::new(BIG);
        let posts = plain(1..=5);
        assert!(w.take(&posts[..2], &[D, D]));
        assert!(w.take(&posts[2..], &[P, D, D]));
        let walk = w.finish(&BTreeSet::new());
        assert_eq!(seqs(&walk), [id(3)]);
        assert_eq!(walk.withheld, 4);
        assert_eq!(walk.sent, [3]);
        let mut none = Walker::new(BIG);
        assert!(none.take(&[], &[]));
        let walk = none.finish(&BTreeSet::new());
        assert!(walk.sent.is_empty());
    }

    #[test]
    fn a_posts_size_is_its_encoded_length() {
        let post = stored(1, None, PostLabels::default());
        let mut encoded = Vec::new();
        ciborium::into_writer(&post.post, &mut encoded).unwrap();
        assert!(encoded.len() > 1);
        assert_eq!(post_size(&post), encoded.len());
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

    fn listed(seq: u64, in_reply_to: Option<u64>, held: &[HeldFor]) -> crate::board::Listed {
        crate::board::Listed {
            stored: stored(seq, in_reply_to, PostLabels::default()),
            held: held.iter().copied().collect(),
        }
    }

    fn window(seqs: std::ops::RangeInclusive<u64>, more: bool) -> Window {
        Window {
            posts: seqs.rev().map(|s| listed(s, None, &[])).collect(),
            more,
            targets: Vec::new(),
        }
    }

    fn on_page(p: &Paged) -> Vec<u64> {
        p.listing.entries.iter().map(|e| e.seq).collect()
    }

    fn links(p: &Paged) -> Vec<(u64, Option<PostId>)> {
        p.listing
            .entries
            .iter()
            .map(|e| (e.seq, e.post.draft.in_reply_to))
            .collect()
    }

    fn page(w: Window, verdicts: &[PostVerdict], budget: usize) -> Paged {
        paged(w, verdicts, budget).unwrap_or_else(|_| panic!("oversize"))
    }

    #[test]
    fn paged_omits_denied_and_undecided_posts_and_counts_them() {
        let got = page(window(1..=5, false), &[P, D, P, U, P], BIG);
        assert_eq!(on_page(&got), [1, 3, 5]);
        assert_eq!(got.withheld, 2);
        let mut released = window(1..=5, false);
        released.posts.retain(|l| l.stored.seq % 2 == 1);
        let alone = page(released, &[P, P, P], BIG);
        assert_eq!(got.listing, alone.listing);
        assert_eq!(got.links, alone.links);
        assert_eq!(alone.withheld, 0);
        let short = page(window(1..=3, false), &[P], BIG);
        assert_eq!(on_page(&short), [3]);
        assert_eq!(short.withheld, 2);
    }

    #[test]
    fn paged_cuts_at_the_budget_and_older_is_the_pages_lowest() {
        let whole = page(window(1..=5, false), &[P; 5], BIG);
        assert_eq!(on_page(&whole), [1, 2, 3, 4, 5]);
        assert_eq!(whole.listing.older, None);
        let size = entry_size(&whole.listing.entries[0]);
        assert!(whole.listing.entries.iter().all(|e| entry_size(e) == size));
        let three = page(window(1..=5, false), &[P; 5], 3 * size);
        assert_eq!(on_page(&three), [3, 4, 5]);
        assert_eq!(three.listing.older, Some(3));
        let short = page(window(1..=5, false), &[P; 5], 3 * size - 1);
        assert_eq!(on_page(&short), [4, 5]);
        assert_eq!(short.listing.older, Some(4));
        let all = page(window(1..=5, false), &[P; 5], 5 * size);
        assert_eq!(all.listing.older, None);
        let more = page(window(1..=5, true), &[P; 5], 5 * size);
        assert_eq!(more.listing.older, Some(1));
        assert_eq!(
            paged(window(1..=5, false), &[P; 5], size - 1),
            Err(Oversize)
        );
        let denied_first = page(window(1..=5, false), &[D, P, P, P, P], size);
        assert_eq!(on_page(&denied_first), [4]);
        assert_eq!(denied_first.listing.older, Some(4));
    }

    #[test]
    fn paged_with_more_and_a_withheld_tail_names_the_pages_lowest_not_the_tail() {
        let mut verdicts = vec![P; 7];
        verdicts.extend([D; 3]);
        let got = page(window(1..=10, true), &verdicts, BIG);
        assert_eq!(on_page(&got), (4..=10).collect::<Vec<_>>());
        assert_eq!(got.listing.older, Some(4));
        assert_eq!(got.withheld, 3);
    }

    #[test]
    fn paged_with_a_withheld_tail_and_nothing_below_has_no_older() {
        let mut verdicts = vec![P; 7];
        verdicts.extend([D; 3]);
        let got = page(window(1..=10, false), &verdicts, BIG);
        assert_eq!(on_page(&got), (4..=10).collect::<Vec<_>>());
        assert_eq!(got.listing.older, None);
        assert_eq!(got.withheld, 3);
    }

    #[test]
    fn paged_empty_because_none_released_names_the_windows_lowest_only_when_more() {
        let more = page(window(3..=10, true), &[D, U, D, D, D, D, D, D], BIG);
        assert!(more.listing.entries.is_empty());
        assert_eq!(more.listing.older, Some(3));
        assert_eq!(more.withheld, 8);
        let last = page(window(3..=10, false), &[D; 8], BIG);
        assert!(last.listing.entries.is_empty());
        assert_eq!(last.listing.older, None);
        let none = page(Window::default(), &[], BIG);
        assert_eq!(
            none,
            Paged {
                listing: BoardListing {
                    entries: Vec::new(),
                    older: None
                },
                withheld: 0,
                links: BTreeMap::new(),
            }
        );
    }

    #[test]
    fn paged_keeps_a_reply_link_only_to_a_permitted_target() {
        let w = || Window {
            posts: vec![
                listed(9, Some(1), &[]),
                listed(8, Some(2), &[]),
                listed(7, Some(90), &[]),
                listed(6, Some(91), &[]),
                listed(5, Some(92), &[]),
                listed(4, Some(93), &[]),
                listed(2, None, &[]),
                listed(1, None, &[]),
            ],
            more: false,
            targets: vec![
                stored(90, None, PostLabels::default()),
                stored(91, None, PostLabels::default()),
                stored(92, None, PostLabels::default()),
            ],
        };
        let verdicts = [P, P, P, P, P, P, D, P, P, D, U];
        let got = page(w(), &verdicts, BIG);
        assert_eq!(
            links(&got),
            [
                (1, None),
                (4, None),
                (5, None),
                (6, None),
                (7, Some(id(90))),
                (8, None),
                (9, Some(id(1))),
            ]
        );
        assert_eq!(got.links, [(7, 90), (9, 1)].into());
        let upper: usize = got.listing.entries[1..].iter().map(entry_size).sum();
        let cut = page(w(), &verdicts, upper);
        assert_eq!(on_page(&cut), [4, 5, 6, 7, 8, 9]);
        assert_eq!(links(&cut)[5], (9, Some(id(1))));
        assert_eq!(cut.links, [(7, 90), (9, 1)].into());
        assert_eq!(cut.listing.older, Some(4));
    }

    #[test]
    fn settle_drops_stale_entries_and_links_and_keeps_older() {
        let w = Window {
            posts: vec![
                listed(5, Some(1), &[]),
                listed(4, Some(2), &[]),
                listed(3, None, &[]),
                listed(2, None, &[]),
                listed(1, None, &[]),
            ],
            more: true,
            targets: Vec::new(),
        };
        let got = page(w, &[P, P, D, P, P], BIG);
        assert_eq!(got.links, [(4, 2), (5, 1)].into());
        assert_eq!(got.listing.older, Some(1));
        let settled = settle(got.clone(), &[2, 4, 5].into());
        assert_eq!(links(&settled), [(2, None), (4, Some(id(2))), (5, None)]);
        assert_eq!(settled.listing.older, Some(1));
        assert_eq!(settled.withheld, 1);
        assert_eq!(settled.links, got.links);
        let unchanged = settle(got.clone(), &[1, 2, 3, 4, 5].into());
        assert_eq!(unchanged, got);
        let gone = settle(got.clone(), &BTreeSet::new());
        assert!(gone.listing.entries.is_empty());
        assert_eq!(gone.listing.older, Some(1));
        assert_eq!(gone.withheld, 1);
    }

    #[test]
    fn paged_lists_ascending_with_holds_in_order() {
        let w = Window {
            posts: vec![
                listed(4, None, &[HeldFor::Person]),
                listed(3, None, &[HeldFor::Person, HeldFor::Author]),
                listed(2, None, &[HeldFor::Author]),
                listed(1, None, &[]),
            ],
            more: false,
            targets: Vec::new(),
        };
        let got = page(w, &[P; 4], BIG);
        let holds: Vec<(u64, Vec<BoardHold>)> = got
            .listing
            .entries
            .iter()
            .map(|e| (e.seq, e.held.clone()))
            .collect();
        assert_eq!(
            holds,
            [
                (1, vec![]),
                (2, vec![BoardHold::Author]),
                (3, vec![BoardHold::Author, BoardHold::Person]),
                (4, vec![BoardHold::Person]),
            ]
        );
        assert_eq!(
            got.listing.entries[3].post,
            stored(4, None, PostLabels::default()).post
        );
        let bytes = maknae_proto::encode_response(&maknae_proto::Response::new(
            maknae_proto::PROTOCOL_VERSION,
            maknae_proto::RespResult::Ok(maknae_proto::Payload::BoardListing(got.listing.clone())),
            None,
        ));
        let back = maknae_proto::decode_response(&bytes.unwrap()).unwrap();
        assert!(matches!(
            back.result,
            maknae_proto::RespResult::Ok(maknae_proto::Payload::BoardListing(l)) if l == got.listing
        ));
    }

    #[test]
    fn the_listing_audit_holds_counts_and_sequences_only() {
        let got = page(window(1..=6, true), &[P, D, P, P, D, D], BIG);
        assert_eq!(
            list_audit(&got),
            BoardAudit {
                first_seq: Some(3),
                last_seq: Some(6),
                returned: Some(3),
                withheld: Some(3),
                ..BoardAudit::default()
            }
        );
        let empty = page(window(1..=2, false), &[D, D], BIG);
        assert_eq!(
            list_audit(&empty),
            BoardAudit {
                first_seq: None,
                last_seq: None,
                returned: Some(0),
                withheld: Some(2),
                ..BoardAudit::default()
            }
        );
        assert_eq!([LISTED, LISTED_OLDER], ["done", "done; older posts remain"]);
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
    fn a_leading_post_whose_obligations_conflict_stalls_the_walk() {
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
            assert_eq!(got.verdicts, want, "{verdict:?}");
            assert_eq!(got.confirmed, want == [P, P], "{verdict:?}");
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
        assert!(none.verdicts.is_empty(), "an empty batch permits nothing");
        assert!(!none.confirmed, "and confirms nothing");
        assert_eq!(pdp.calls.load(std::sync::atomic::Ordering::SeqCst), 0);
    }

    /// Decides through `inner`, then installs new live values before the batch returns, as a
    /// reload landing while a batch is in flight.
    struct InstallsDuring<A> {
        inner: Arc<A>,
        live: Arc<crate::live::LiveConfig>,
    }

    impl<A: Authorizer> Authorizer for InstallsDuring<A> {
        fn decide(&self, req: &maknae_security::Request) -> Verdict {
            self.inner.decide(req)
        }

        fn decide_cited_all(
            &self,
            reqs: &[maknae_security::Request],
        ) -> Vec<maknae_security::Decided> {
            let all = self.inner.decide_cited_all(reqs);
            let lock = maknae_authz_basic::LiveTurnLock::hermetic();
            let turn = lock.try_take().expect("a hermetic turn is free");
            self.live.install(&turn, Default::default(), None);
            all
        }
    }

    #[tokio::test]
    async fn a_batch_decided_across_a_live_install_yields_no_verdicts() {
        let (home, basic) = crate::test_fixtures::fixture(
            "board-generation",
            crate::test_fixtures::READ_POLICY,
            None,
        );
        let us = &maknae_config::BasicPolicy;
        let pdp = Arc::new(crate::Composition::new(
            basic,
            crate::CeilingAuthorizer::new(maknae_config::Ceiling::baseline_for(us), us),
        ));
        let req = crate::test_fixtures::permitted_read_marked(&home.0, None);
        let live = Arc::new(crate::live::LiveConfig::new(Default::default(), None));
        let generation = live.generation();
        let timeout = Duration::from_secs(5);
        let held = decide_posts(&pdp, &live, generation, timeout, &req, vec![req.clone()]).await;
        assert_eq!(
            held,
            Decided {
                confirmed: true,
                verdicts: vec![P]
            },
            "the real composition permits both"
        );
        let installing = Arc::new(InstallsDuring {
            inner: pdp,
            live: Arc::clone(&live),
        });
        let moved = decide_posts(
            &installing,
            &live,
            generation,
            timeout,
            &req,
            vec![req.clone()],
        )
        .await;
        assert_eq!(live.generation(), generation + 1);
        assert_eq!(
            moved,
            Decided {
                confirmed: false,
                verdicts: vec![U]
            },
            "a batch decided on a view since replaced yields nothing"
        );
    }

    fn kept(walk: Walk) -> Vec<u64> {
        walk.sent
    }

    #[test]
    fn a_walk_wants_more_until_its_page_fills_or_it_stops() {
        let page = BOARD_READ_PAGE_POSTS as u64;
        let mut w = Walker::new(BIG);
        assert!(w.wants_more());
        assert!(w.take(&plain(1..=page), &[P; BOARD_READ_PAGE_POSTS]));
        assert!(
            w.wants_more(),
            "a full page has not yet found its lookahead"
        );
        assert!(!w.take(&plain(page + 1..=page + 1), &[P]));
        assert!(!w.wants_more(), "the lookahead ends the walk");
        let mut stopped = Walker::new(BIG);
        assert!(!stopped.take(&plain(1..=2), &[P, U]));
        assert!(!stopped.wants_more(), "an undecided post ends the walk");
    }

    #[test]
    fn a_dead_kept_post_is_made_absent_and_the_walk_closes_over_it() {
        let mut w = Walker::new(BIG);
        w.take(&plain(1..=3), &[P, P, P]);
        let live: BTreeSet<u64> = [1, 3].into_iter().collect();
        assert!(w.drop_dead(&live));
        assert!(w.is_absent(2));
        assert!(!w.is_absent(1) && !w.is_absent(3) && !w.is_absent(4));
        assert!(!w.drop_dead(&live), "nothing left to drop");
        assert_eq!(kept(w.finish(&BTreeSet::new())), [1, 3]);
    }

    #[test]
    fn a_dead_stop_drops_the_undecided_verdicts_after_it_and_keeps_the_rest() {
        let mut w = Walker::new(BIG);
        w.take(&plain(1..=4), &[P, U, U, P]);
        assert!(w.stalled());
        let live: BTreeSet<u64> = [1, 3, 4].into_iter().collect();
        assert!(w.drop_dead(&live));
        assert_eq!(
            w.resume_after(),
            Some(1),
            "the undecided post 3 is decided again"
        );
        assert!(w.wants_more());
    }

    #[test]
    fn hi_is_the_last_post_decided_once_the_walk_ends_and_upper_before() {
        let mut w = Walker::new(BIG);
        w.take(&plain(5..=7), &[P, P, P]);
        assert_eq!(w.hi(100), 100, "still walking: the whole range");
        let mut ended = Walker::new(BIG);
        ended.take(&plain(5..=7), &[P, U, P]);
        assert_eq!(ended.hi(100), 7);
    }

    #[test]
    fn missing_is_the_lowest_live_post_neither_decided_nor_absent() {
        let mut w = Walker::new(BIG);
        w.take(&plain(2..=4), &[P, P, P]);
        let live: BTreeSet<u64> = [2, 4].into_iter().collect();
        w.drop_dead(&live);
        let range = |seqs: &[u64]| seqs.iter().copied().collect::<BTreeSet<u64>>();
        assert_eq!(w.missing(&range(&[2, 3, 4])), None, "decided or absent");
        assert_eq!(w.missing(&range(&[2, 3, 4, 6, 9])), Some(6));
        assert_eq!(w.missing(&range(&[])), None);
    }

    #[test]
    fn rewalk_from_forgets_that_post_and_every_later_one() {
        let mut w = Walker::new(BIG);
        w.take(&plain(1..=5), &[P, P, P, P, P]);
        w.rewalk_from(3);
        assert_eq!(w.resume_after(), Some(2));
        assert_eq!(kept(w.finish(&BTreeSet::new())), [1, 2]);
    }

    #[test]
    fn a_read_makes_at_most_sixty_nine_passes() {
        assert_eq!(READ_ROUNDS, 69);
    }

    #[test]
    fn a_post_audit_names_the_post_it_replies_to() {
        let mut d = draft("sentinel-695-body", Some(id(9)));
        d.kind = PostKind::Answer;
        let audit = post_audit(&d, "d1");
        assert_eq!(audit.in_reply_to, Some(id(9).to_string()));
        assert_eq!(audit.kind.as_deref(), Some("answer"));
        assert_eq!(post_audit(&draft("b", None), "d1").in_reply_to, None);
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
        other.to = Addressee::Agents(vec!["hobi".into()]);
        assert_eq!(post_digest(&other).unwrap(), digest, "content only");
        other.body = secret("sentinel-695-other");
        assert_ne!(post_digest(&other).unwrap(), digest);
    }
}
