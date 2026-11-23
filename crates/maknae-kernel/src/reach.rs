//! Intake's reach (#168, ADR-0037 decision 7): for each binding, what the tasker and the agent
//! were each observed able to do at submission, asked of the Egress Daemon one frame at a time.
//!
//! T1: this decides what a task is sealed able to reach, and refuses the task when either side
//! cannot be observed.

use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::Duration;

use maknae_audit_append::{AuditEmit, AuditRecord};
use maknae_config::{AgentId, CredentialKind, ForgeProvider, ForgeSet};
use maknae_forge::{AgentSide, CredentialForge};
use maknae_proto::{
    AgentReach, Binding, BindingReach, CredentialRef, EmptyReason, ForgeTokens, GitReach,
    Observations, ReachRefusal, ReachReply, ReachRequest, ReachSide, RepoAsk, SealedForgeToken,
    SideReach, SignedAddendum, TaskAddendum, TaskObject, TaskerBasis, REACH_CREDENTIALS_MAX,
};

use crate::egress_socket::{ReachEgress, ReachOutcome, Unanswered};
use crate::task::TaskRefusal;

const KINDS: [CredentialKind; 6] = [
    CredentialKind::GithubAppInstallation,
    CredentialKind::GithubMachineUser,
    CredentialKind::GitlabProjectToken,
    CredentialKind::GitlabBotToken,
    CredentialKind::VaultChildToken,
    CredentialKind::VaultDynamicSecret,
];

const _: fn(CredentialKind) = |k| match k {
    CredentialKind::GithubAppInstallation
    | CredentialKind::GithubMachineUser
    | CredentialKind::GitlabProjectToken
    | CredentialKind::GitlabBotToken
    | CredentialKind::VaultChildToken
    | CredentialKind::VaultDynamicSecret => {}
};

/// What intake needs of one forge, decided by `maknae-forge` at boot and kept as plain data.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ForgeTraits {
    pub observes_reach: bool,
    pub agent_side: BTreeMap<CredentialKind, AgentSide>,
}

impl ForgeTraits {
    pub fn of(provider: ForgeProvider) -> Self {
        let forge = maknae_forge::forge(provider);
        Self {
            observes_reach: maknae_forge::observes_reach(provider),
            agent_side: KINDS
                .iter()
                .filter_map(|k| k.forge().map(|fk| (*k, forge.agent_side(fk))))
                .collect(),
        }
    }

    fn side(&self, kind: &str) -> AgentSide {
        CredentialKind::parse(kind)
            .and_then(|k| self.agent_side.get(&k).copied())
            .unwrap_or(AgentSide::NotThisForge)
    }
}

/// The `forges:` set's reach traits, its user key prefix and the reach deadline; restart-only.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReachSettings {
    forges: Vec<(String, ForgeProvider, ForgeTraits)>,
    user_prefix: Option<String>,
    deadline_ms: u64,
}

impl Default for ReachSettings {
    fn default() -> Self {
        Self::of(
            &ForgeSet::empty(),
            None,
            maknae_config::EgressConfig::default().reach_deadline_ms,
        )
    }
}

impl ReachSettings {
    pub fn of(forges: &ForgeSet, user_prefix: Option<String>, deadline_ms: u64) -> Self {
        Self {
            forges: forges
                .iter()
                .filter(|f| f.kind == maknae_config::ForgeKind::Git)
                .map(|f| (f.host.clone(), f.provider, ForgeTraits::of(f.provider)))
                .collect(),
            user_prefix,
            deadline_ms,
        }
    }

    pub fn deadline_ms(&self) -> u64 {
        self.deadline_ms
    }

    pub fn observes_reach(&self) -> bool {
        self.forges.iter().any(|(_, _, t)| t.observes_reach)
    }

    fn forge(&self, server: &str) -> Option<(ForgeProvider, &ForgeTraits)> {
        self.forges
            .iter()
            .find(|(host, ..)| host == server)
            .map(|(_, p, t)| (*p, t))
    }
}

/// The kernel's own cap on reach exchanges in flight (SF8); a wait for it spends the reach budget.
pub fn kernel_reach_permits() -> &'static tokio::sync::Semaphore {
    static PERMITS: std::sync::OnceLock<tokio::sync::Semaphore> = std::sync::OnceLock::new();
    PERMITS.get_or_init(|| tokio::sync::Semaphore::new(maknae_config::REACH_CONCURRENCY_MAX))
}

/// A task's bindings and their reach, index-aligned: the task's own, then its addendum's.
/// `reach` is empty when the task's own bindings were sealed without it.
pub(crate) struct TaskBound<'a> {
    pub bindings: Vec<&'a Binding>,
    pub reach: Vec<&'a BindingReach>,
}

impl<'a> TaskBound<'a> {
    pub fn of(task: &'a TaskObject, addendum: Option<&'a SignedAddendum>) -> Self {
        let added = addendum.map(|a| &a.addendum);
        let bindings = task
            .bindings
            .iter()
            .chain(added.into_iter().flat_map(TaskAddendum::bindings))
            .collect();
        let reach = match task.reach.len() == task.bindings.len() {
            true => task
                .reach
                .iter()
                .chain(added.into_iter().flat_map(TaskAddendum::reach))
                .collect(),
            false => Vec::new(),
        };
        Self { bindings, reach }
    }
}

/// What intake asks reach with.
pub(crate) struct ReachCtx<'a> {
    pub egress: &'a Arc<dyn ReachEgress>,
    pub settings: &'a ReachSettings,
    pub permits: &'a tokio::sync::Semaphore,
    pub credentials: &'a (dyn Fn(u32) -> Vec<CredentialRef> + Send + Sync),
}

/// Who the tasker side is.
pub(crate) enum Asker<'a> {
    Person { username: Option<&'a str> },
    Parent(TaskBound<'a>),
    Agent { agent: &'a AgentId, uid: u32 },
}

/// Where each frame's intent and outcome records go.
pub(crate) struct FrameTrail<'a, E> {
    pub emit: &'a E,
    pub record: &'a (dyn Fn(&str, &str, &str) -> AuditRecord + Send + Sync),
}

/// The agent whose side is observed.
pub(crate) struct Target<'a> {
    pub agent: &'a AgentId,
    pub uid: u32,
}

fn unreached(why: impl Into<String>) -> TaskRefusal {
    TaskRefusal::Unreached(why.into())
}

pub(crate) fn refusal_class(r: ReachRefusal) -> &'static str {
    match r {
        ReachRefusal::Request => "request",
        ReachRefusal::Seal => "seal",
        ReachRefusal::Login => "login",
        ReachRefusal::NotFound => "not_found",
        ReachRefusal::Unauthorized => "unauthorized",
        ReachRefusal::Forbidden => "forbidden",
        ReachRefusal::Moved => "moved",
        ReachRefusal::Upstream => "upstream",
        ReachRefusal::Unanswered => "unanswered",
        ReachRefusal::Shape => "shape",
        ReachRefusal::Suspended => "suspended",
        ReachRefusal::AmbiguousCredential => "ambiguous_credential",
        ReachRefusal::Signer => "signer",
    }
}

/// An agent's forge credentials on one forge, as C3 classifies them.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Credentials {
    Observe(Vec<CredentialRef>),
    AtHandOut,
    NoForgeCredential,
}

pub(crate) fn classify(
    creds: &[CredentialRef],
    traits: &ForgeTraits,
) -> Result<Credentials, TaskRefusal> {
    let side = |c: &&CredentialRef| traits.side(&c.kind);
    let observed: Vec<CredentialRef> = creds
        .iter()
        .filter(|c| side(c) == AgentSide::Observe)
        .cloned()
        .collect();
    if observed.len() > REACH_CREDENTIALS_MAX {
        return Err(unreached(format!(
            "reach refused: {}: more than {REACH_CREDENTIALS_MAX} observable credentials",
            refusal_class(ReachRefusal::AmbiguousCredential)
        )));
    }
    if !observed.is_empty() {
        return Ok(Credentials::Observe(observed));
    }
    if creds.iter().any(|c| side(&c) == AgentSide::AtHandOut) {
        return Ok(Credentials::AtHandOut);
    }
    Ok(Credentials::NoForgeCredential)
}

/// One binding's reach as it is assembled.
#[derive(Clone, Copy)]
struct Slot {
    tasker: SideReach,
    agent: AgentReach,
    checked: bool,
    head_gone: bool,
    uncovered: bool,
    submitter_unseen: bool,
}

impl Slot {
    fn why(&self) -> Option<EmptyReason> {
        if !self.checked {
            Some(EmptyReason::NoReachCheck)
        } else if self.agent == AgentReach::NoForgeCredential {
            Some(EmptyReason::NoForgeCredential)
        } else if self.uncovered {
            Some(EmptyReason::AgentNotCovered)
        } else if self.submitter_unseen {
            Some(EmptyReason::NoForgeCredential)
        } else if self.head_gone {
            Some(EmptyReason::HeadGone)
        } else {
            None
        }
    }
}

enum Answer {
    Observed(Observations),
    NoForgeCredential,
}

struct Run<'c, 'a, E> {
    ctx: &'c ReachCtx<'a>,
    trail: &'c FrameTrail<'a, E>,
    end: tokio::time::Instant,
    permit: Option<tokio::sync::SemaphorePermit<'a>>,
}

impl<'a, E: AuditEmit> Run<'_, 'a, E> {
    fn left(&self) -> Duration {
        self.end
            .saturating_duration_since(tokio::time::Instant::now())
    }

    async fn say(&self, result: &str, reason: &str, posture: &str) -> Result<(), TaskRefusal> {
        let rec = (self.trail.record)(result, reason, posture);
        self.trail
            .emit
            .emit_within(&rec, crate::blocking_guard::AUDIT_APPEND_TIMEOUT)
            .await
            .map_err(|e| TaskRefusal::Audit(e.to_string()))
    }

    async fn frame(
        &mut self,
        side: ReachSide,
        server: &str,
        provider: ForgeProvider,
        asks: Vec<RepoAsk>,
    ) -> Result<Answer, TaskRefusal> {
        let named = match &side {
            ReachSide::Tasker { .. } => format!("tasker {server}"),
            ReachSide::Agent { agent, .. } => format!("agent {agent} {server}"),
        };
        if self.permit.is_none() {
            let permits = self.ctx.permits;
            match tokio::time::timeout(self.left(), permits.acquire()).await {
                Ok(Ok(p)) => self.permit = Some(p),
                Ok(Err(_)) | Err(_) => return Err(unreached(Unanswered::AtCapacity.trail())),
            }
        }
        let left = self.left().as_millis() as u64;
        if left == 0 {
            return Err(unreached("the reach deadline passed"));
        }
        let wanted = asks.len();
        let req = ReachRequest::new(
            server.to_owned(),
            provider.as_str().to_owned(),
            left,
            side,
            asks,
        )
        .map_err(|e| unreached(format!("reach refused: request ({named}): {e}")))?;
        let tasker = matches!(req.side(), ReachSide::Tasker { .. });
        self.say(
            "permit",
            &format!("reach intent recorded ({named})"),
            "authorized",
        )
        .await?;
        let egress = Arc::clone(self.ctx.egress);
        let out = tokio::task::spawn_blocking(move || egress.reach(req))
            .await
            .unwrap_or_else(|e| {
                ReachOutcome::Unanswered(Unanswered::Unknown(format!(
                    "the exchange did not finish: {e}"
                )))
            });
        let (said, answer) = match out {
            ReachOutcome::Reply(ReachReply::Observed(obs)) if obs.as_slice().len() == wanted => {
                ("reach observed".to_owned(), Ok(Answer::Observed(obs)))
            }
            ReachOutcome::Reply(ReachReply::Observed(_)) => {
                let said = "reach refused: shape: the reply does not match its asks".to_owned();
                (said.clone(), Err((said, "unauthorized")))
            }
            ReachOutcome::Reply(ReachReply::NoForgeCredential) if !tasker => (
                "reach observed: no forge credential".to_owned(),
                Ok(Answer::NoForgeCredential),
            ),
            ReachOutcome::Reply(ReachReply::NoForgeCredential) => {
                let said = "reach refused: login: no forge credential".to_owned();
                (said.clone(), Err((said, "unauthorized")))
            }
            ReachOutcome::Reply(ReachReply::Refused(class)) => {
                let said = format!("reach refused: {}", refusal_class(class));
                (said.clone(), Err((said, "unauthorized")))
            }
            ReachOutcome::Unanswered(u) => {
                let said = u.trail();
                (said.clone(), Err((said, "unavailable")))
            }
        };
        let reason = format!("{said} ({named})");
        match answer {
            Ok(a) => {
                self.say("permit", &reason, "authorized").await?;
                Ok(a)
            }
            Err((_, posture)) => {
                self.say("deny", &reason, posture).await?;
                Err(unreached(reason))
            }
        }
    }
}

fn servers(bindings: &[Binding]) -> Vec<&str> {
    let mut seen: Vec<&str> = Vec::new();
    for Binding::Git(g) in bindings {
        if !seen.contains(&g.server.as_str()) {
            seen.push(&g.server);
        }
    }
    seen
}

fn on<'b>(bindings: &'b [Binding], server: &'b str) -> impl Iterator<Item = usize> + 'b {
    bindings
        .iter()
        .enumerate()
        .filter(move |(_, Binding::Git(g))| g.server == server)
        .map(|(i, _)| i)
}

fn admit_tokens(
    asker: &Asker<'_>,
    tokens: &ForgeTokens,
    bindings: &[Binding],
) -> Result<(), TaskRefusal> {
    if tokens.is_empty() {
        return Ok(());
    }
    if !matches!(asker, Asker::Person { .. }) {
        return Err(unreached("an agent's submission carries no forge token"));
    }
    let bound = servers(bindings);
    match tokens
        .as_slice()
        .iter()
        .find(|t| !bound.contains(&t.server()))
    {
        Some(t) => Err(unreached(format!(
            "a forge token for {}, which no binding names",
            t.server()
        ))),
        None => Ok(()),
    }
}

fn side_of(o: &maknae_proto::RepoObservation) -> Result<SideReach, TaskRefusal> {
    SideReach::new(o.base(), o.head()).map_err(|e| unreached(format!("reach refused: shape: {e}")))
}

/// Observes reach for `bindings`, filling each change's `head` from the tasker side, and
/// returns their reach index-aligned. `tokens` are consumed here and dropped once sent.
pub(crate) async fn observe<E: AuditEmit>(
    ctx: &ReachCtx<'_>,
    trail: &FrameTrail<'_, E>,
    asker: Asker<'_>,
    tokens: ForgeTokens,
    target: Target<'_>,
    bindings: &mut [Binding],
) -> Result<Vec<BindingReach>, TaskRefusal> {
    admit_tokens(&asker, &tokens, bindings)?;
    if bindings.is_empty() {
        return Ok(Vec::new());
    }
    let end = tokio::time::Instant::now() + Duration::from_millis(ctx.settings.deadline_ms);
    let mut run = Run {
        ctx,
        trail,
        end,
        permit: None,
    };
    let mut slots = vec![
        Slot {
            tasker: SideReach::EMPTY,
            agent: AgentReach::NoForgeCredential,
            checked: false,
            head_gone: false,
            uncovered: false,
            submitter_unseen: false,
        };
        bindings.len()
    ];
    let mut forges: Vec<(String, ForgeProvider, ForgeTraits)> = Vec::new();
    for server in servers(bindings) {
        let (provider, traits) = ctx
            .settings
            .forge(server)
            .ok_or_else(|| unreached(format!("server {server} is not the host of a git forge")))?;
        forges.push((server.to_owned(), provider, traits.clone()));
    }
    let basis = match &asker {
        Asker::Person { .. } => TaskerBasis::Token,
        Asker::Parent(_) => TaskerBasis::Parent,
        Asker::Agent { .. } => TaskerBasis::Submitter,
    };
    match &asker {
        Asker::Person { username } => {
            let mut held: Vec<SealedForgeToken> = tokens.into_vec();
            for (server, provider, traits) in &forges {
                if !traits.observes_reach {
                    continue;
                }
                let at = held.iter().position(|t| t.server() == server);
                let token = at
                    .map(|i| held.swap_remove(i))
                    .ok_or_else(|| unreached(format!("no forge login for {server}")))?;
                let side = tasker_side(ctx, *username, server, token)?;
                let idx: Vec<usize> = on(bindings, server).collect();
                let asks = idx
                    .iter()
                    .map(|&i| {
                        let Binding::Git(g) = &bindings[i];
                        RepoAsk {
                            base: g.base.clone(),
                            change: g.change,
                            head: None,
                        }
                    })
                    .collect();
                let Answer::Observed(obs) = run.frame(side, server, *provider, asks).await? else {
                    return Err(unreached("reach refused: login: no forge credential"));
                };
                for (&i, o) in idx.iter().zip(obs.as_slice()) {
                    let Binding::Git(g) = &mut bindings[i];
                    if g.change.is_none() && (o.head_path().is_some() || o.head_gone()) {
                        return Err(unreached(
                            "reach refused: shape: a head for a binding without a change",
                        ));
                    }
                    g.head = o.head_path().map(str::to_owned);
                    slots[i].tasker = side_of(o)?;
                    slots[i].head_gone = o.head_gone();
                }
            }
            drop(held);
            heads_fit(bindings)?;
        }
        Asker::Parent(bound) => {
            if bound.reach.is_empty() {
                return Err(unreached("parent task has no reach"));
            }
            for (i, b) in bindings.iter().enumerate() {
                let at = bound
                    .bindings
                    .iter()
                    .position(|p| *p == b)
                    .ok_or_else(|| unreached("a binding is not the parent task's"))?;
                let reach = bound
                    .reach
                    .get(at)
                    .ok_or_else(|| unreached("parent task has no reach"))?;
                slots[i].tasker = maknae_proto::effective_reach(reach);
            }
        }
        Asker::Agent { agent, uid } => {
            let creds = (ctx.credentials)(*uid);
            for (server, provider, traits) in &forges {
                if !traits.observes_reach {
                    continue;
                }
                let idx: Vec<usize> = on(bindings, server).collect();
                match classify(&creds, traits)? {
                    Credentials::Observe(credentials) => {
                        let side = ReachSide::Agent {
                            agent: agent.as_str().to_owned(),
                            credentials,
                        };
                        match run
                            .frame(side, server, *provider, asks_of(bindings, &idx, false))
                            .await?
                        {
                            Answer::Observed(obs) => {
                                for (&i, o) in idx.iter().zip(obs.as_slice()) {
                                    slots[i].tasker =
                                        SideReach::new(o.base(), maknae_proto::ForgeOps::EMPTY)
                                            .map_err(|e| {
                                                unreached(format!("reach refused: shape: {e}"))
                                            })?;
                                    slots[i].uncovered |= !o.covered();
                                }
                            }
                            Answer::NoForgeCredential => {
                                for &i in &idx {
                                    slots[i].submitter_unseen = true;
                                }
                            }
                        }
                    }
                    Credentials::AtHandOut | Credentials::NoForgeCredential => {
                        for &i in &idx {
                            slots[i].submitter_unseen = true;
                        }
                    }
                }
            }
        }
    }
    let creds = (ctx.credentials)(target.uid);
    for (server, provider, traits) in &forges {
        let idx: Vec<usize> = on(bindings, server).collect();
        if !traits.observes_reach {
            continue;
        }
        for &i in &idx {
            slots[i].checked = true;
        }
        match classify(&creds, traits)? {
            Credentials::Observe(credentials) => {
                let side = ReachSide::Agent {
                    agent: target.agent.as_str().to_owned(),
                    credentials,
                };
                let with_heads = !matches!(asker, Asker::Agent { .. });
                match run
                    .frame(side, server, *provider, asks_of(bindings, &idx, with_heads))
                    .await?
                {
                    Answer::Observed(obs) => {
                        for (&i, o) in idx.iter().zip(obs.as_slice()) {
                            let Binding::Git(g) = &bindings[i];
                            if g.head.is_none() && !o.head().is_empty() {
                                return Err(unreached(
                                    "reach refused: shape: head ops for a binding without a head",
                                ));
                            }
                            slots[i].agent = AgentReach::Observed(side_of(o)?);
                            slots[i].uncovered |= !o.covered();
                        }
                    }
                    Answer::NoForgeCredential => {}
                }
            }
            Credentials::AtHandOut => {
                for &i in &idx {
                    slots[i].agent = AgentReach::AtHandOut;
                }
            }
            Credentials::NoForgeCredential => {}
        }
    }
    if run.permit.is_some() && run.left().is_zero() {
        return Err(unreached("the reach deadline passed"));
    }
    drop(run);
    Ok(slots
        .iter()
        .map(|s| {
            BindingReach::Git(GitReach {
                tasker: s.tasker,
                basis,
                agent: s.agent,
                why: s.why(),
            })
        })
        .collect())
}

fn asks_of(bindings: &[Binding], idx: &[usize], with_heads: bool) -> Vec<RepoAsk> {
    idx.iter()
        .map(|&i| {
            let Binding::Git(g) = &bindings[i];
            RepoAsk {
                base: g.base.clone(),
                change: g.change,
                head: g.head.clone().filter(|_| with_heads),
            }
        })
        .collect()
}

fn tasker_side(
    ctx: &ReachCtx<'_>,
    username: Option<&str>,
    server: &str,
    token: SealedForgeToken,
) -> Result<ReachSide, TaskRefusal> {
    let username = username.ok_or_else(|| unreached("the tasker has no username"))?;
    let prefix = ctx
        .settings
        .user_prefix
        .as_deref()
        .ok_or_else(|| unreached("no user key prefix is configured"))?;
    let sub = maknae_vault::forge_token_subpath(server)
        .ok_or_else(|| unreached(format!("server {server} has no forge token path")))?;
    let expected_path = maknae_config::user_key_path(prefix, username, sub.as_str())
        .map_err(|e| unreached(format!("no forge token path: {e}")))?;
    let (_, nonce, sealed) = token.into_parts();
    Ok(ReachSide::Tasker {
        tasker: username.to_owned(),
        expected_path,
        key_field: maknae_vault::FORGE_TOKEN_FIELD.to_owned(),
        nonce,
        sealed,
    })
}

fn heads_fit(bindings: &[Binding]) -> Result<(), TaskRefusal> {
    let len = maknae_proto::bindings_encoded_len(bindings);
    if len <= maknae_proto::TASK_BINDINGS_MAX_BYTES {
        return Ok(());
    }
    let named: Vec<String> = bindings
        .iter()
        .filter_map(|Binding::Git(g)| {
            g.head.as_ref().map(|h| {
                format!(
                    "{} {}{} head {h}",
                    g.server,
                    g.base,
                    g.change.map(|c| format!(" change {c}")).unwrap_or_default()
                )
            })
        })
        .collect();
    Err(TaskRefusal::Unbound(format!(
        "the heads of {} take the sealed bindings to {len} bytes, more than {}",
        named.join(", "),
        maknae_proto::TASK_BINDINGS_MAX_BYTES
    )))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cred(kind: &str, name: &str) -> CredentialRef {
        CredentialRef {
            kind: kind.into(),
            name: name.into(),
        }
    }

    #[test]
    fn each_forges_traits_are_what_maknae_forge_decides() {
        let github = ForgeTraits::of(ForgeProvider::Github);
        assert!(github.observes_reach);
        assert_eq!(
            github
                .agent_side
                .get(&CredentialKind::GithubAppInstallation),
            Some(&AgentSide::Observe)
        );
        assert_eq!(
            github.agent_side.get(&CredentialKind::GithubMachineUser),
            Some(&AgentSide::AtHandOut)
        );
        assert_eq!(
            github.agent_side.get(&CredentialKind::GitlabBotToken),
            Some(&AgentSide::NotThisForge)
        );
        assert_eq!(
            github.agent_side.get(&CredentialKind::VaultChildToken),
            None
        );
        let gitlab = ForgeTraits::of(ForgeProvider::Gitlab);
        assert!(!gitlab.observes_reach);
        assert_eq!(
            gitlab.agent_side.get(&CredentialKind::GitlabProjectToken),
            Some(&AgentSide::AtHandOut)
        );
        assert_eq!(gitlab.side("not-a-kind"), AgentSide::NotThisForge);
    }

    #[test]
    fn an_agents_credentials_classify_observe_first_then_at_hand_out_then_none() {
        let github = ForgeTraits::of(ForgeProvider::Github);
        let app = cred("github-app-installation", "app-a");
        let pat = cred("github-machine-user", "pat");
        let lab = cred("gitlab-bot-token", "bot");
        assert_eq!(
            classify(&[pat.clone(), app.clone(), lab.clone()], &github),
            Ok(Credentials::Observe(vec![app]))
        );
        assert_eq!(
            classify(&[lab.clone(), pat], &github),
            Ok(Credentials::AtHandOut)
        );
        assert_eq!(
            classify(&[lab, cred("vault-child-token", "v")], &github),
            Ok(Credentials::NoForgeCredential)
        );
        assert_eq!(classify(&[], &github), Ok(Credentials::NoForgeCredential));
    }

    #[test]
    fn more_than_eight_observable_credentials_are_ambiguous() {
        let github = ForgeTraits::of(ForgeProvider::Github);
        let apps = |n: usize| -> Vec<CredentialRef> {
            (0..n)
                .map(|i| cred("github-app-installation", &format!("app-{i}")))
                .collect()
        };
        assert_eq!(
            classify(&apps(REACH_CREDENTIALS_MAX), &github),
            Ok(Credentials::Observe(apps(REACH_CREDENTIALS_MAX)))
        );
        let Err(TaskRefusal::Unreached(why)) = classify(&apps(REACH_CREDENTIALS_MAX + 1), &github)
        else {
            panic!("nine apps are ambiguous");
        };
        assert!(
            why.starts_with("reach refused: ambiguous_credential"),
            "{why}"
        );
    }

    #[test]
    fn reach_settings_find_a_git_forge_by_its_exact_host() {
        let yaml = "- { name: a, kind: git, host: \"git.sentinel-168c.example\", provider: github }\n- { name: b, kind: git, host: \"lab.sentinel-168c.example:8443\", provider: gitlab }\n";
        let forges =
            maknae_config::forges_from_section(Some(&maknae_config::load_str(yaml).unwrap()))
                .unwrap();
        let s = ReachSettings::of(&forges, None, 1_000);
        assert_eq!(
            s.forge("git.sentinel-168c.example").map(|(p, _)| p),
            Some(ForgeProvider::Github)
        );
        assert_eq!(
            s.forge("lab.sentinel-168c.example:8443")
                .map(|(p, t)| (p, t.observes_reach)),
            Some((ForgeProvider::Gitlab, false))
        );
        assert!(s.forge("lab.sentinel-168c.example").is_none());
        assert_eq!(s.deadline_ms(), 1_000);
    }

    #[test]
    fn every_refusal_class_has_its_wire_spelling() {
        for class in [
            ReachRefusal::Request,
            ReachRefusal::Seal,
            ReachRefusal::Login,
            ReachRefusal::NotFound,
            ReachRefusal::Unauthorized,
            ReachRefusal::Forbidden,
            ReachRefusal::Moved,
            ReachRefusal::Upstream,
            ReachRefusal::Unanswered,
            ReachRefusal::Shape,
            ReachRefusal::Suspended,
            ReachRefusal::AmbiguousCredential,
            ReachRefusal::Signer,
        ] {
            let mut wire = Vec::new();
            ciborium::into_writer(&class, &mut wire).unwrap();
            let spelled: String = ciborium::from_reader(&wire[..]).unwrap();
            assert_eq!(refusal_class(class), spelled);
        }
    }

    mod observing {
        use super::*;
        use crate::egress_socket::{ReachEgress, ReachOutcome, Unanswered};
        use maknae_audit_append::{AuditEmit, AuditError, AuditRecord};
        use maknae_proto::{
            ForgeOp, ForgeOps, GitBinding, RepoObservation, SealedKey, TaskerBasis,
        };
        use std::sync::atomic::{AtomicUsize, Ordering};
        use std::sync::Mutex;

        const GH: &str = "git.sentinel-168r.example";
        const LAB: &str = "lab.sentinel-168r.example";
        const SUBMITTER: u32 = 1;
        const TARGET: u32 = 2;

        type Reply = Box<dyn Fn(&ReachRequest) -> ReachOutcome + Send + Sync>;

        struct Fake {
            reply: Reply,
            asked: Mutex<Vec<String>>,
        }

        impl ReachEgress for Fake {
            fn has_socket(&self) -> bool {
                true
            }

            fn reach(&self, req: ReachRequest) -> ReachOutcome {
                let who = match req.side() {
                    ReachSide::Tasker { .. } => "tasker".to_owned(),
                    ReachSide::Agent { agent, .. } => agent.clone(),
                };
                self.asked.lock().unwrap().push(who);
                (self.reply)(&req)
            }
        }

        struct Emit {
            ok_for: usize,
            n: AtomicUsize,
        }

        impl AuditEmit for Emit {
            fn emit(
                &self,
                _: &AuditRecord,
            ) -> impl std::future::Future<Output = Result<(), AuditError>> + Send {
                let ok = self.n.fetch_add(1, Ordering::SeqCst) < self.ok_for;
                async move {
                    match ok {
                        true => Ok(()),
                        false => Err(AuditError::WritePrimary("full".into())),
                    }
                }
            }
        }

        fn record() -> AuditRecord {
            serde_json::from_value(serde_json::json!({
                "ts":"test", "event":"request", "where":{"host":"test","component":"kernel","socket":"test"},
                "source":{"uid":0},"subject":{},"action":"session.task",
                "outcome":{"result":"deny","reason":"pending","posture":"unauthorized"},
                "session_id":1,"seq":1,"au3_1":{},"integrity":{}
            }))
            .unwrap()
        }

        fn settings(user_prefix: Option<&str>, deadline_ms: u64) -> ReachSettings {
            let yaml = format!(
                "- {{ name: a, kind: git, host: \"{GH}\", provider: github }}\n- {{ name: b, kind: git, host: \"{LAB}\", provider: gitlab }}\n"
            );
            let forges =
                maknae_config::forges_from_section(Some(&maknae_config::load_str(&yaml).unwrap()))
                    .unwrap();
            ReachSettings::of(&forges, user_prefix.map(str::to_owned), deadline_ms)
        }

        fn ops(list: &[ForgeOp]) -> ForgeOps {
            list.iter().fold(ForgeOps::EMPTY, |o, op| o.with(*op))
        }

        fn seen(head: Option<&str>, head_ops: &[ForgeOp], gone: bool) -> RepoObservation {
            RepoObservation::new(
                ops(&[ForgeOp::Read]),
                head.map(str::to_owned),
                ops(head_ops),
                gone,
                true,
            )
            .unwrap()
        }

        fn observed(list: Vec<RepoObservation>) -> ReachOutcome {
            ReachOutcome::Reply(ReachReply::Observed(Observations::new(list).unwrap()))
        }

        fn each(f: fn() -> RepoObservation) -> Reply {
            Box::new(move |req| observed(req.asks().iter().map(|_| f()).collect()))
        }

        fn git(server: &str, base: &str, change: Option<u64>) -> Binding {
            Binding::Git(GitBinding {
                server: server.into(),
                base: base.into(),
                head: None,
                change,
            })
        }

        fn app(name: &str) -> CredentialRef {
            CredentialRef {
                kind: "github-app-installation".into(),
                name: name.into(),
            }
        }

        fn token(server: &str) -> ForgeTokens {
            let sealed = SealedKey::new(vec![7; 200]).unwrap();
            ForgeTokens::new(vec![SealedForgeToken::new(
                server.into(),
                "0123456789abcdef0123456789abcdef".into(),
                sealed,
            )
            .unwrap()])
            .unwrap()
        }

        struct World {
            settings: ReachSettings,
            reply: Reply,
            submitter: Vec<CredentialRef>,
            target: Vec<CredentialRef>,
            ok_for: usize,
        }

        impl World {
            fn new(reply: Reply) -> Self {
                Self {
                    settings: settings(Some("maknae/users"), 20_000),
                    reply,
                    submitter: Vec::new(),
                    target: vec![app("deploy")],
                    ok_for: usize::MAX,
                }
            }
        }

        struct Seen {
            out: Result<Vec<BindingReach>, TaskRefusal>,
            asked: Vec<String>,
            said: Vec<(String, String, String)>,
            emitted: usize,
        }

        async fn run(
            w: World,
            asker: Asker<'_>,
            tokens: ForgeTokens,
            bindings: &mut [Binding],
        ) -> Seen {
            let fake = Arc::new(Fake {
                reply: w.reply,
                asked: Mutex::default(),
            });
            let egress: Arc<dyn ReachEgress> = fake.clone();
            let permits = tokio::sync::Semaphore::new(1);
            let (submitter, target) = (w.submitter, w.target);
            let credentials = move |uid| match uid {
                SUBMITTER => submitter.clone(),
                _ => target.clone(),
            };
            let ctx = ReachCtx {
                egress: &egress,
                settings: &w.settings,
                permits: &permits,
                credentials: &credentials,
            };
            let said = Mutex::new(Vec::new());
            let rec = |result: &str, reason: &str, posture: &str| {
                said.lock().unwrap().push((
                    result.to_owned(),
                    reason.to_owned(),
                    posture.to_owned(),
                ));
                record()
            };
            let emit = Emit {
                ok_for: w.ok_for,
                n: AtomicUsize::new(0),
            };
            let trail = FrameTrail {
                emit: &emit,
                record: &rec,
            };
            let coder = AgentId::parse("coder").unwrap();
            let target = Target {
                agent: &coder,
                uid: TARGET,
            };
            let out = observe(&ctx, &trail, asker, tokens, target, bindings).await;
            let asked = fake.asked.lock().unwrap().clone();
            Seen {
                out,
                asked,
                said: said.into_inner().unwrap(),
                emitted: emit.n.load(Ordering::SeqCst),
            }
        }

        fn person() -> Asker<'static> {
            Asker::Person {
                username: Some("alice"),
            }
        }

        fn unreached_why(s: &Seen) -> &str {
            match &s.out {
                Err(TaskRefusal::Unreached(why)) => why,
                other => panic!("expected an unreached refusal, got {other:?}"),
            }
        }

        fn agent_reach(s: &Seen) -> Vec<(AgentReach, Option<EmptyReason>)> {
            s.out
                .as_ref()
                .unwrap()
                .iter()
                .map(|BindingReach::Git(g)| (g.agent, g.why))
                .collect()
        }

        #[test]
        fn a_tasker_side_needs_a_username_a_prefix_and_a_token_path() {
            let egress: Arc<dyn ReachEgress> = Arc::new(Fake {
                reply: each(|| seen(None, &[], false)),
                asked: Mutex::default(),
            });
            let permits = tokio::sync::Semaphore::new(1);
            let none = |_| Vec::new();
            let with = settings(Some("maknae/users"), 1_000);
            let without = settings(None, 1_000);
            let side = |s: &ReachSettings, user: Option<&str>, server: &str| {
                let ctx = ReachCtx {
                    egress: &egress,
                    settings: s,
                    permits: &permits,
                    credentials: &none,
                };
                let t = token(GH).into_vec().pop().unwrap();
                match tasker_side(&ctx, user, server, t) {
                    Ok(ReachSide::Tasker {
                        tasker,
                        expected_path,
                        key_field,
                        ..
                    }) => Ok((tasker, expected_path, key_field)),
                    Ok(ReachSide::Agent { .. }) => panic!("a tasker side"),
                    Err(TaskRefusal::Unreached(why)) => Err(why),
                    Err(other) => panic!("{other:?}"),
                }
            };
            let (tasker, path, field) = side(&with, Some("alice"), GH).unwrap();
            assert_eq!(tasker, "alice");
            assert!(path.starts_with("maknae/users/alice/"), "{path}");
            assert_eq!(field, maknae_vault::FORGE_TOKEN_FIELD);
            assert_eq!(
                side(&with, None, GH).unwrap_err(),
                "the tasker has no username"
            );
            assert_eq!(
                side(&without, Some("alice"), GH).unwrap_err(),
                "no user key prefix is configured"
            );
            assert_eq!(
                side(&with, Some("alice"), "[::1]:443").unwrap_err(),
                "server [::1]:443 has no forge token path"
            );
            assert!(side(&with, Some("data"), GH)
                .unwrap_err()
                .starts_with("no forge token path: "));
        }

        #[tokio::test]
        async fn a_person_without_a_username_is_refused_before_any_frame() {
            let mut b = [git(GH, "o/r", None)];
            let s = run(
                World::new(each(|| seen(None, &[], false))),
                Asker::Person { username: None },
                token(GH),
                &mut b,
            )
            .await;
            assert_eq!(unreached_why(&s), "the tasker has no username");
            assert!(s.asked.is_empty());
            assert_eq!(s.emitted, 0);
        }

        #[tokio::test]
        async fn a_server_that_is_no_git_forge_is_refused_before_any_frame() {
            let mut b = [git("elsewhere.example", "o/r", None)];
            let s = run(
                World::new(each(|| seen(None, &[], false))),
                person(),
                ForgeTokens::default(),
                &mut b,
            )
            .await;
            assert_eq!(
                unreached_why(&s),
                "server elsewhere.example is not the host of a git forge"
            );
            assert!(s.asked.is_empty());
        }

        #[tokio::test]
        async fn a_frame_the_proto_refuses_is_refused_unsent() {
            let mut b = [git(GH, "o/r", None), git(GH, "o/r", None)];
            let s = run(
                World::new(each(|| seen(None, &[], false))),
                person(),
                token(GH),
                &mut b,
            )
            .await;
            assert!(
                unreached_why(&s).starts_with(&format!("reach refused: request (tasker {GH}): ")),
                "{}",
                unreached_why(&s)
            );
            assert!(s.asked.is_empty());
            assert!(s.said.is_empty());
        }

        async fn tasker_answered(reply: Reply) -> Seen {
            let mut b = [git(GH, "o/r", None)];
            run(World::new(reply), person(), token(GH), &mut b).await
        }

        fn denied(s: &Seen, reason: &str, posture: &str) {
            assert_eq!(unreached_why(s), reason);
            assert_eq!(s.asked, ["tasker"], "the agent side is never asked");
            assert_eq!(
                s.said,
                [
                    (
                        "permit".to_owned(),
                        format!("reach intent recorded (tasker {GH})"),
                        "authorized".to_owned()
                    ),
                    ("deny".to_owned(), reason.to_owned(), posture.to_owned()),
                ]
            );
        }

        #[tokio::test]
        async fn a_tasker_with_no_forge_credential_is_refused_login() {
            let s = tasker_answered(Box::new(|_| {
                ReachOutcome::Reply(ReachReply::NoForgeCredential)
            }))
            .await;
            denied(
                &s,
                &format!("reach refused: login: no forge credential (tasker {GH})"),
                "unauthorized",
            );
        }

        #[tokio::test]
        async fn a_reply_that_does_not_match_its_asks_is_refused_shape() {
            let s = tasker_answered(Box::new(|_| {
                observed(vec![seen(None, &[], false), seen(None, &[], false)])
            }))
            .await;
            denied(
                &s,
                &format!("reach refused: shape: the reply does not match its asks (tasker {GH})"),
                "unauthorized",
            );
        }

        #[tokio::test]
        async fn an_unanswered_frame_is_refused_unavailable() {
            let s = tasker_answered(Box::new(|_| {
                ReachOutcome::Unanswered(Unanswered::NotSent("no deputy".into()))
            }))
            .await;
            denied(
                &s,
                &format!("reach not sent: no deputy (tasker {GH})"),
                "unavailable",
            );
        }

        #[tokio::test]
        async fn an_exchange_that_does_not_finish_is_refused_unavailable() {
            let s = tasker_answered(Box::new(|_| panic!("the exchange broke"))).await;
            let why = unreached_why(&s);
            assert!(
                why.starts_with("reach outcome unknown: the exchange did not finish: "),
                "{why}"
            );
            assert_eq!(s.said.last().unwrap().0, "deny");
            assert_eq!(s.said.last().unwrap().2, "unavailable");
        }

        #[tokio::test]
        async fn an_outcome_record_that_cannot_be_written_refuses_the_task() {
            for reply in [
                each(|| seen(None, &[], false)),
                Box::new(|_: &ReachRequest| {
                    ReachOutcome::Reply(ReachReply::Refused(ReachRefusal::Forbidden))
                }) as Reply,
            ] {
                let mut w = World::new(reply);
                w.ok_for = 1;
                let mut b = [git(GH, "o/r", None)];
                let s = run(w, person(), token(GH), &mut b).await;
                assert!(matches!(s.out, Err(TaskRefusal::Audit(_))), "{:?}", s.out);
                assert_eq!(s.asked, ["tasker"]);
                assert_eq!(s.emitted, 2);
            }
        }

        #[tokio::test]
        async fn a_tasker_head_for_a_binding_without_a_change_is_refused_shape() {
            let s =
                tasker_answered(each(|| seen(Some("fork/r"), &[ForgeOp::PushHead], false))).await;
            assert_eq!(
                unreached_why(&s),
                "reach refused: shape: a head for a binding without a change"
            );
            assert_eq!(s.asked, ["tasker"]);
        }

        #[tokio::test]
        async fn a_gone_head_empties_the_bindings_reach_as_head_gone() {
            let mut b = [git(GH, "o/r", Some(7))];
            let reply: Reply = Box::new(|req| match req.side() {
                ReachSide::Tasker { .. } => observed(vec![seen(None, &[], true)]),
                ReachSide::Agent { .. } => observed(vec![seen(None, &[], false)]),
            });
            let s = run(World::new(reply), person(), token(GH), &mut b).await;
            let Binding::Git(g) = &b[0];
            assert_eq!(g.head, None);
            assert_eq!(s.asked, ["tasker", "coder"]);
            assert_eq!(
                agent_reach(&s),
                [(
                    AgentReach::Observed(
                        SideReach::new(ops(&[ForgeOp::Read]), ForgeOps::EMPTY).unwrap()
                    ),
                    Some(EmptyReason::HeadGone)
                )]
            );
        }

        #[tokio::test]
        async fn a_parent_must_hold_each_binding_and_its_reach() {
            let mine = git(GH, "o/r", None);
            let other = git(GH, "o/other", None);
            let r = BindingReach::Git(GitReach {
                tasker: SideReach::EMPTY,
                basis: TaskerBasis::Token,
                agent: AgentReach::NoForgeCredential,
                why: Some(EmptyReason::NoForgeCredential),
            });
            let mut b = [git(GH, "o/elsewhere", None)];
            let s = run(
                World::new(each(|| seen(None, &[], false))),
                Asker::Parent(TaskBound {
                    bindings: vec![&mine],
                    reach: vec![&r],
                }),
                ForgeTokens::default(),
                &mut b,
            )
            .await;
            assert_eq!(unreached_why(&s), "a binding is not the parent task's");
            assert!(s.asked.is_empty());
            let mut b = [other.clone()];
            let s = run(
                World::new(each(|| seen(None, &[], false))),
                Asker::Parent(TaskBound {
                    bindings: vec![&mine, &other],
                    reach: vec![&r],
                }),
                ForgeTokens::default(),
                &mut b,
            )
            .await;
            assert_eq!(unreached_why(&s), "parent task has no reach");
            assert!(s.asked.is_empty());
        }

        fn agent_asker(agent: &AgentId) -> Asker<'_> {
            Asker::Agent {
                agent,
                uid: SUBMITTER,
            }
        }

        #[tokio::test]
        async fn too_many_observable_credentials_on_either_agent_refuse_the_task() {
            let lead = AgentId::parse("lead").unwrap();
            let nine: Vec<CredentialRef> = (0..=REACH_CREDENTIALS_MAX)
                .map(|i| app(&format!("app-{i}")))
                .collect();
            let mut w = World::new(each(|| seen(None, &[], false)));
            w.submitter = nine.clone();
            let mut b = [git(GH, "o/r", None)];
            let s = run(w, agent_asker(&lead), ForgeTokens::default(), &mut b).await;
            assert!(unreached_why(&s).starts_with("reach refused: ambiguous_credential"));
            assert!(s.asked.is_empty());
            let mut w = World::new(each(|| seen(None, &[], false)));
            w.target = nine;
            let s = run(w, agent_asker(&lead), ForgeTokens::default(), &mut b).await;
            assert!(unreached_why(&s).starts_with("reach refused: ambiguous_credential"));
            assert!(s.asked.is_empty());
        }

        #[tokio::test]
        async fn a_submitting_agents_refused_frame_refuses_the_task() {
            let lead = AgentId::parse("lead").unwrap();
            let mut w = World::new(Box::new(|_| {
                ReachOutcome::Reply(ReachReply::Refused(ReachRefusal::Suspended))
            }));
            w.submitter = vec![app("lead-app")];
            let mut b = [git(GH, "o/r", None)];
            let s = run(w, agent_asker(&lead), ForgeTokens::default(), &mut b).await;
            assert_eq!(
                unreached_why(&s),
                format!("reach refused: suspended (agent lead {GH})")
            );
            assert_eq!(s.asked, ["lead"], "the target is never asked");
        }

        #[tokio::test]
        async fn an_unseen_submitter_empties_an_observed_targets_reach() {
            let lead = AgentId::parse("lead").unwrap();
            let mut b = [git(GH, "o/r", None)];
            let s = run(
                World::new(each(|| seen(None, &[], false))),
                agent_asker(&lead),
                ForgeTokens::default(),
                &mut b,
            )
            .await;
            assert_eq!(s.asked, ["coder"]);
            assert_eq!(
                agent_reach(&s),
                [(
                    AgentReach::Observed(
                        SideReach::new(ops(&[ForgeOp::Read]), ForgeOps::EMPTY).unwrap()
                    ),
                    Some(EmptyReason::NoForgeCredential)
                )]
            );
        }

        #[tokio::test]
        async fn a_submitter_whose_credential_does_not_cover_a_binding_empties_it() {
            let lead = AgentId::parse("lead").unwrap();
            for (lead_covers, why) in [(false, Some(EmptyReason::AgentNotCovered)), (true, None)] {
                let mut w = World::new(Box::new(move |req: &ReachRequest| {
                    let covered = match req.side() {
                        ReachSide::Agent { agent, .. } if agent == "lead" => lead_covers,
                        _ => true,
                    };
                    let one = || {
                        RepoObservation::new(
                            ops(&[ForgeOp::Read]),
                            None,
                            ForgeOps::EMPTY,
                            false,
                            covered,
                        )
                        .unwrap()
                    };
                    observed(req.asks().iter().map(|_| one()).collect())
                }));
                w.submitter = vec![app("lead-app")];
                let mut b = [git(GH, "o/r", None)];
                let s = run(w, agent_asker(&lead), ForgeTokens::default(), &mut b).await;
                assert_eq!(s.asked, ["lead", "coder"]);
                assert_eq!(
                    agent_reach(&s),
                    [(
                        AgentReach::Observed(
                            SideReach::new(ops(&[ForgeOp::Read]), ForgeOps::EMPTY).unwrap()
                        ),
                        why
                    )],
                    "{lead_covers}"
                );
            }
        }

        #[tokio::test]
        async fn target_head_ops_for_a_binding_without_a_head_are_refused_shape() {
            let lead = AgentId::parse("lead").unwrap();
            let mut b = [git(GH, "o/r", Some(3))];
            let s = run(
                World::new(each(|| seen(Some("fork/r"), &[ForgeOp::PushHead], false))),
                agent_asker(&lead),
                ForgeTokens::default(),
                &mut b,
            )
            .await;
            assert_eq!(
                unreached_why(&s),
                "reach refused: shape: head ops for a binding without a head"
            );
            assert_eq!(s.asked, ["coder"]);
        }

        #[tokio::test]
        async fn a_target_with_no_forge_credential_is_sealed_as_such() {
            let lead = AgentId::parse("lead").unwrap();
            let answered: Reply = Box::new(|_| ReachOutcome::Reply(ReachReply::NoForgeCredential));
            let mut b = [git(GH, "o/r", None)];
            let s = run(
                World::new(answered),
                agent_asker(&lead),
                ForgeTokens::default(),
                &mut b,
            )
            .await;
            assert_eq!(s.asked, ["coder"]);
            assert_eq!(
                agent_reach(&s),
                [(
                    AgentReach::NoForgeCredential,
                    Some(EmptyReason::NoForgeCredential)
                )]
            );
            let mut w = World::new(each(|| seen(None, &[], false)));
            w.target = Vec::new();
            let s = run(w, agent_asker(&lead), ForgeTokens::default(), &mut b).await;
            assert!(s.asked.is_empty());
            assert_eq!(
                agent_reach(&s),
                [(
                    AgentReach::NoForgeCredential,
                    Some(EmptyReason::NoForgeCredential)
                )]
            );
        }

        #[tokio::test]
        async fn a_last_frame_that_outlives_the_deadline_refuses_the_task() {
            let lead = AgentId::parse("lead").unwrap();
            let mut w = World::new(Box::new(|req| {
                std::thread::sleep(Duration::from_millis(req.deadline_ms() + 100));
                observed(req.asks().iter().map(|_| seen(None, &[], false)).collect())
            }));
            w.settings = settings(Some("maknae/users"), 50);
            let mut b = [git(GH, "o/r", None)];
            let s = run(w, agent_asker(&lead), ForgeTokens::default(), &mut b).await;
            assert_eq!(unreached_why(&s), "the reach deadline passed");
            assert_eq!(s.asked, ["coder"]);
            assert_eq!(s.said.last().unwrap().0, "permit");
        }
    }
}
