//! Connection-admission and per-request session decisions (spec §5, #115). Pure; T1/0-missed.

use maknae_config::AgentId;
use maknae_proto::TaskId;
use maknae_vault::ChannelPeer;

use crate::enrollment::EnrollmentView;
use crate::groupres::AuthzError;
use crate::handler::Admission;
use crate::session::Facts;
use crate::session_facts::{AccountFact, AccountState, NotCheckedWhy};
use crate::task::{TaskRefusal, TaskStore};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DenyCause {
    NotMember,
    Account(AccountState),
    SenderMismatch,
    Infrastructure(FactSource),
    AgentAccount,
    NotEnrolled,
    HumanAccount,
    TaskOnClientChannel,
    Task { refusal: TaskRefusal, cited: TaskId },
    TaskNotWorking { cited: TaskId },
}

/// The fact source that could not answer, named in an infrastructure denial.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FactSource {
    Group,
    Account,
    SessionMap,
    Audit,
    SessionFacts,
}

impl FactSource {
    pub fn name(self) -> &'static str {
        match self {
            FactSource::Group => "group",
            FactSource::Account => "account",
            FactSource::SessionMap => "session-map",
            FactSource::Audit => "audit",
            FactSource::SessionFacts => "session-facts",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Revalidation {
    Continue,
    Deny(DenyCause),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Ending {
    Disconnect,
    Idle,
    Lifetime,
    LeafExpired,
    Denied(DenyCause),
}

/// The connection-time standing of `uid` on a channel of class `class`, against the
/// installed enrollment.
pub fn admit(
    class: Admission,
    peer: &ChannelPeer,
    uid: u32,
    view: &dyn EnrollmentView,
) -> Result<(), DenyCause> {
    match class {
        Admission::EnrolledAgent => match peer {
            ChannelPeer::Agent { agent, .. } if view.agent_uid(agent) == Some(uid) => Ok(()),
            ChannelPeer::Agent { .. } | ChannelPeer::Certless | ChannelPeer::Certified(_) => {
                Err(DenyCause::NotEnrolled)
            }
        },
        Admission::MaknaeGroupMember if view.is_enrolled(uid) => Err(DenyCause::AgentAccount),
        Admission::MaknaeGroupMember => Ok(()),
    }
}

/// The task a request cites, resolved for this channel: only the agent's own `Working`
/// task; another agent's is refused as such, and anything else as not working.
pub fn task_for(
    admission: Admission,
    cited: Option<&TaskId>,
    agent: Option<&AgentId>,
    uid: u32,
    store: &TaskStore,
) -> Result<Option<crate::task::CitedTask>, DenyCause> {
    let Some(id) = cited else {
        return Ok(None);
    };
    match (admission, agent) {
        (Admission::MaknaeGroupMember, _) => Err(DenyCause::TaskOnClientChannel),
        (Admission::EnrolledAgent, None) => Err(DenyCause::NotEnrolled),
        (Admission::EnrolledAgent, Some(agent)) => {
            store
                .working(id, agent, uid)
                .map(Some)
                .map_err(|refusal| match refusal {
                    TaskRefusal::OtherAgent => DenyCause::Task {
                        refusal,
                        cited: *id,
                    },
                    TaskRefusal::Unknown
                    | TaskRefusal::NotWorking
                    | TaskRefusal::Schema(_)
                    | TaskRefusal::Denied(_)
                    | TaskRefusal::AtCapacity { .. }
                    | TaskRefusal::ParentNotHeld
                    | TaskRefusal::AgentGone
                    | TaskRefusal::Random
                    | TaskRefusal::Audit(_)
                    | TaskRefusal::Unsigned
                    | TaskRefusal::Store(_)
                    | TaskRefusal::CursorAhead
                    | TaskRefusal::Finished
                    | TaskRefusal::TooLong
                    | TaskRefusal::TaskerLive { .. }
                    | TaskRefusal::TaskerHeld
                    | TaskRefusal::FollowUps
                    | TaskRefusal::FollowUpsUnseen
                    | TaskRefusal::Unavailable(_) => DenyCause::TaskNotWorking { cited: *id },
                })
        }
    }
}

/// Whether the session may serve this request, on facts gathered for it alone
/// (ADR-0006 decision 4): the uid map, then membership and account state.
pub fn revalidate(
    admission: Admission,
    bound_uid: u32,
    request_uid: u32,
    f: &Facts,
) -> Revalidation {
    if bound_uid != request_uid {
        return Revalidation::Deny(DenyCause::Infrastructure(FactSource::SessionMap));
    }
    if !f.answered {
        return Revalidation::Deny(DenyCause::Infrastructure(FactSource::SessionFacts));
    }
    let refused = match (admission, &f.membership) {
        (
            Admission::MaknaeGroupMember | Admission::EnrolledAgent,
            Err(AuthzError::Resolve(_) | AuthzError::Unanswered { .. }),
        ) => Some(DenyCause::Infrastructure(FactSource::Group)),
        (Admission::MaknaeGroupMember, Err(AuthzError::NoUser)) => Some(DenyCause::NotMember),
        (Admission::MaknaeGroupMember, Ok(m)) => (!m.in_group).then_some(DenyCause::NotMember),
        (Admission::EnrolledAgent, Err(AuthzError::NoUser)) => Some(DenyCause::NotEnrolled),
        (Admission::EnrolledAgent, Ok(m)) => m.in_group.then_some(DenyCause::HumanAccount),
    };
    if let Some(cause) = refused {
        return Revalidation::Deny(cause);
    }
    match &f.account {
        AccountFact::Checked(AccountState::Active) | AccountFact::NotChecked(_) => {
            Revalidation::Continue
        }
        AccountFact::Checked(AccountState::Unknown(_)) => {
            Revalidation::Deny(DenyCause::Infrastructure(FactSource::Account))
        }
        AccountFact::Checked(
            state @ (AccountState::Locked | AccountState::Expired | AccountState::Disabled),
        ) => Revalidation::Deny(DenyCause::Account(state.clone())),
    }
}

pub fn cause_reason(c: &DenyCause) -> std::borrow::Cow<'static, str> {
    let fixed = match c {
        DenyCause::NotMember => "not-member",
        DenyCause::Account(AccountState::Locked) => "account-locked",
        DenyCause::Account(AccountState::Expired) => "account-expired",
        DenyCause::Account(AccountState::Disabled) => "account-disabled",
        DenyCause::Account(AccountState::Active) => "account-active",
        DenyCause::Account(AccountState::Unknown(_)) => "account-unknown",
        DenyCause::SenderMismatch => "sender-mismatch",
        DenyCause::Infrastructure(FactSource::Group) => "infrastructure:group",
        DenyCause::Infrastructure(FactSource::Account) => "infrastructure:account",
        DenyCause::Infrastructure(FactSource::SessionMap) => "infrastructure:session-map",
        DenyCause::Infrastructure(FactSource::Audit) => "infrastructure:audit",
        DenyCause::Infrastructure(FactSource::SessionFacts) => "infrastructure:session-facts",
        DenyCause::AgentAccount => "agent-account",
        DenyCause::NotEnrolled => "not-enrolled",
        DenyCause::HumanAccount => "human-account",
        DenyCause::TaskOnClientChannel => "task-on-client-channel",
        DenyCause::Task { refusal, cited } => {
            return format!("{}:{cited}", task_reason(refusal)).into();
        }
        DenyCause::TaskNotWorking { cited } => {
            return format!("task-not-working:{cited}").into();
        }
    };
    fixed.into()
}

fn task_reason(r: &TaskRefusal) -> &'static str {
    match r {
        TaskRefusal::Unknown => "task-unknown",
        TaskRefusal::OtherAgent => "task-other-agent",
        TaskRefusal::Schema(_) => "task-schema",
        TaskRefusal::Denied(_) => "task-denied",
        TaskRefusal::AtCapacity { .. } => "task-at-capacity",
        TaskRefusal::ParentNotHeld => "task-parent-not-held",
        TaskRefusal::AgentGone => "task-agent-gone",
        TaskRefusal::Random => "task-random",
        TaskRefusal::Audit(_) => "task-audit",
        TaskRefusal::Unsigned => "task-unsigned",
        TaskRefusal::Store(_) => "task-store",
        TaskRefusal::CursorAhead => "cursor_ahead",
        TaskRefusal::Finished => "task-finished",
        TaskRefusal::TooLong => "task-too-long",
        TaskRefusal::TaskerLive { .. } => "task-tasker-live",
        TaskRefusal::TaskerHeld => "task-tasker-held",
        TaskRefusal::FollowUps => "task-follow-ups",
        TaskRefusal::FollowUpsUnseen => "task-follow-ups-unseen",
        TaskRefusal::NotWorking => "task-not-working",
        TaskRefusal::Unavailable(_) => "task-unavailable",
    }
}

pub fn cause_posture(c: &DenyCause) -> &'static str {
    match c {
        DenyCause::Infrastructure(_) => "unavailable",
        DenyCause::NotMember
        | DenyCause::Account(_)
        | DenyCause::SenderMismatch
        | DenyCause::AgentAccount
        | DenyCause::NotEnrolled
        | DenyCause::HumanAccount
        | DenyCause::TaskOnClientChannel
        | DenyCause::Task { .. }
        | DenyCause::TaskNotWorking { .. } => "unauthorized",
    }
}

pub fn account_label(a: &AccountFact) -> &'static str {
    match a {
        AccountFact::Checked(AccountState::Active) => "active",
        AccountFact::Checked(AccountState::Locked) => "locked",
        AccountFact::Checked(AccountState::Expired) => "expired",
        AccountFact::Checked(AccountState::Disabled) => "disabled",
        AccountFact::Checked(AccountState::Unknown(_)) => "unknown",
        AccountFact::NotChecked(NotCheckedWhy::DirectoryAccount) => "not-checked:directory",
        AccountFact::NotChecked(NotCheckedWhy::Platform) => "not-checked:platform",
        AccountFact::NotChecked(NotCheckedWhy::Configured) => "not-checked:configured",
    }
}

pub fn admission_reason(a: &AccountFact) -> String {
    format!("admitted (account: {})", account_label(a))
}

pub fn ending_reason(e: &Ending) -> std::borrow::Cow<'static, str> {
    match e {
        Ending::Disconnect => "disconnect".into(),
        Ending::Idle => "idle".into(),
        Ending::Lifetime => "lifetime".into(),
        Ending::LeafExpired => "leaf-expired".into(),
        Ending::Denied(c) => cause_reason(c),
    }
}

pub fn ending_result(e: &Ending) -> &'static str {
    match e {
        Ending::Disconnect => "permit",
        Ending::Idle | Ending::Lifetime | Ending::LeafExpired | Ending::Denied(_) => "deny",
    }
}

pub fn ending_posture(e: &Ending) -> &'static str {
    match e {
        Ending::Disconnect | Ending::Idle | Ending::Lifetime | Ending::LeafExpired => "stopped",
        Ending::Denied(c) => cause_posture(c),
    }
}

pub fn admission_facts(
    admission: Admission,
    looked_up: &Result<crate::groupres::Membership, AuthzError>,
) -> (bool, Option<String>, Option<std::path::PathBuf>) {
    match looked_up {
        Ok(m) => {
            let admitted = match admission {
                Admission::MaknaeGroupMember => m.in_group,
                Admission::EnrolledAgent => !m.in_group,
            };
            (
                m.in_group,
                Some(m.user.clone()),
                admitted.then(|| m.dir.clone()),
            )
        }
        Err(AuthzError::Unanswered { user, .. }) => (false, Some(user.clone()), None),
        Err(AuthzError::Resolve(_) | AuthzError::NoUser) => (false, None, None),
    }
}

pub(crate) const HOME_RESOLVE_TIMEOUT: std::time::Duration =
    std::time::Duration::from_millis(maknae_config::HOME_RESOLVE_TIMEOUT_MS);
const MAX_HOME_RESOLVERS: usize = 16;
const HOME_UNAVAILABLE: &str = "requester home unavailable";
const HOME_HEALTH_LOG_INTERVAL: std::time::Duration = std::time::Duration::from_secs(60);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HomeUnavailable {
    Unresolvable,
    TimedOut,
    RequesterAtCapacity,
    AtCapacity,
}

impl HomeUnavailable {
    pub fn cause(self) -> &'static str {
        match self {
            HomeUnavailable::Unresolvable => "unresolvable",
            HomeUnavailable::TimedOut => "timed out",
            HomeUnavailable::RequesterAtCapacity => "at capacity for this requester",
            HomeUnavailable::AtCapacity => "at capacity",
        }
    }

    pub fn reason(self) -> String {
        format!("{HOME_UNAVAILABLE}: {}", self.cause())
    }
}

#[derive(Default)]
struct HealthLog {
    logged: Option<HomeUnavailable>,
    at: Option<std::time::Instant>,
}

#[derive(Default)]
struct HomeHealth(std::sync::Mutex<HealthLog>);

impl HomeHealth {
    fn observe(
        &self,
        outcome: &Result<std::path::PathBuf, HomeUnavailable>,
        now: std::time::Instant,
    ) -> Option<String> {
        let state = match outcome {
            Ok(_) => None,
            Err(HomeUnavailable::Unresolvable | HomeUnavailable::RequesterAtCapacity) => {
                return None
            }
            Err(cause) => Some(*cause),
        };
        let mut log = self
            .0
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if log.logged == state
            || log
                .at
                .is_some_and(|at| now.duration_since(at) < HOME_HEALTH_LOG_INTERVAL)
        {
            return None;
        }
        log.logged = state;
        log.at = Some(now);
        Some(match state {
            Some(cause) => format!(
                "maknaed: requester home resolution {} — filesystem verbs refuse with `{}` until it recovers",
                cause.cause(),
                cause.reason()
            ),
            None => "maknaed: requester home resolution recovered".to_string(),
        })
    }
}

pub(crate) struct HomeResolver {
    capacity: std::sync::Arc<tokio::sync::Semaphore>,
    gate: crate::uid_gate::UidGate,
    health: HomeHealth,
    #[cfg(test)]
    entered: std::sync::Mutex<Vec<u32>>,
}

impl HomeResolver {
    pub(crate) fn new(slots: usize) -> Self {
        HomeResolver {
            capacity: std::sync::Arc::new(tokio::sync::Semaphore::new(slots)),
            gate: crate::uid_gate::UidGate::default(),
            health: HomeHealth::default(),
            #[cfg(test)]
            entered: std::sync::Mutex::default(),
        }
    }

    pub(crate) async fn resolve<F>(
        &self,
        uid: u32,
        dir: Option<std::path::PathBuf>,
        timeout: std::time::Duration,
        resolve: F,
    ) -> Result<std::path::PathBuf, HomeUnavailable>
    where
        F: FnOnce(&std::path::Path) -> Option<std::path::PathBuf> + Send + 'static,
    {
        #[cfg(test)]
        self.entered.lock().unwrap().push(uid);
        let outcome = self.attempt(uid, dir, timeout, resolve).await;
        if let Some(line) = self.health.observe(&outcome, std::time::Instant::now()) {
            eprintln!("{line}");
        }
        outcome
    }

    #[cfg(test)]
    pub(crate) fn entered(&self, uid: u32) -> usize {
        self.entered
            .lock()
            .unwrap()
            .iter()
            .filter(|&&u| u == uid)
            .count()
    }

    #[cfg(test)]
    pub(crate) fn claim(&self, uid: u32) -> Option<crate::uid_gate::UidClaim> {
        self.gate.try_claim(uid)
    }

    async fn attempt<F>(
        &self,
        uid: u32,
        dir: Option<std::path::PathBuf>,
        timeout: std::time::Duration,
        resolve: F,
    ) -> Result<std::path::PathBuf, HomeUnavailable>
    where
        F: FnOnce(&std::path::Path) -> Option<std::path::PathBuf> + Send + 'static,
    {
        let dir = dir.ok_or(HomeUnavailable::Unresolvable)?;
        let slot = self
            .gate
            .try_admit(uid, &self.capacity)
            .map_err(|busy| match busy {
                crate::uid_gate::Busy::Requester => HomeUnavailable::RequesterAtCapacity,
                crate::uid_gate::Busy::Global => HomeUnavailable::AtCapacity,
            })?;
        let worker = tokio::task::spawn_blocking(move || {
            let _slot = slot;
            resolve(&dir)
        });
        match tokio::time::timeout(timeout, worker).await {
            Ok(Ok(Some(home))) => Ok(home),
            Ok(_) => Err(HomeUnavailable::Unresolvable),
            Err(_) => Err(HomeUnavailable::TimedOut),
        }
    }
}

static HOME_RESOLVER: std::sync::OnceLock<HomeResolver> = std::sync::OnceLock::new();

pub(crate) fn home_resolver() -> &'static HomeResolver {
    HOME_RESOLVER.get_or_init(|| HomeResolver::new(MAX_HOME_RESOLVERS))
}

pub(crate) async fn admitted_home(
    uid: u32,
    dir: Option<std::path::PathBuf>,
) -> Result<std::path::PathBuf, HomeUnavailable> {
    home_resolver()
        .resolve(
            uid,
            dir,
            HOME_RESOLVE_TIMEOUT,
            crate::groupres::canonical_home,
        )
        .await
}

#[cfg(test)]
mod tests {
    use super::*;
    use maknae_proto::SignedTask;
    use std::sync::Arc;

    fn membership(in_group: bool, user: &str) -> crate::groupres::Membership {
        crate::groupres::Membership {
            in_group,
            user: user.into(),
            dir: format!("/home/{user}").into(),
        }
    }

    #[test]
    fn a_member_carries_its_user_and_raw_home_through() {
        assert_eq!(
            admission_facts(
                Admission::MaknaeGroupMember,
                &Ok(membership(true, "b-435-sentinel"))
            ),
            (
                true,
                Some("b-435-sentinel".to_string()),
                Some(std::path::PathBuf::from("/home/b-435-sentinel"))
            )
        );
    }

    #[test]
    fn a_non_member_keeps_its_user_but_never_its_home() {
        assert_eq!(
            admission_facts(
                Admission::MaknaeGroupMember,
                &Ok(membership(false, "c-435-sentinel"))
            ),
            (false, Some("c-435-sentinel".to_string()), None)
        );
    }

    #[test]
    fn a_failed_lookup_admits_no_one_and_carries_no_home() {
        for failed in [AuthzError::Resolve("nss".into()), AuthzError::NoUser] {
            assert_eq!(
                admission_facts(Admission::MaknaeGroupMember, &Err(failed)),
                (false, None, None)
            );
        }
        let unanswered = AuthzError::Unanswered {
            user: "d-115-sentinel".into(),
            why: "EIO".into(),
        };
        assert_eq!(
            admission_facts(Admission::MaknaeGroupMember, &Err(unanswered)),
            (false, Some("d-115-sentinel".to_string()), None)
        );
    }

    const FAST: std::time::Duration = std::time::Duration::from_millis(20);
    const PATIENCE: std::time::Duration = std::time::Duration::from_secs(10);

    fn never_runs() -> (
        std::sync::Arc<std::sync::atomic::AtomicBool>,
        impl FnOnce(&std::path::Path) -> Option<std::path::PathBuf> + Send + 'static,
    ) {
        let ran = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let flag = std::sync::Arc::clone(&ran);
        (ran, move |d: &std::path::Path| {
            flag.store(true, std::sync::atomic::Ordering::SeqCst);
            Some(d.into())
        })
    }

    fn held_until(
        release: std::sync::mpsc::Receiver<()>,
    ) -> impl FnOnce(&std::path::Path) -> Option<std::path::PathBuf> + Send + 'static {
        move |d: &std::path::Path| {
            let _ = release.recv();
            Some(d.into())
        }
    }

    async fn settles(what: &str, done: impl Fn() -> bool) {
        tokio::time::timeout(PATIENCE, async {
            while !done() {
                tokio::time::sleep(std::time::Duration::from_millis(1)).await;
            }
        })
        .await
        .unwrap_or_else(|_| panic!("{what}"));
    }

    #[test]
    fn home_resolution_waits_for_the_bound_the_cli_allows_for() {
        assert_eq!(
            HOME_RESOLVE_TIMEOUT,
            std::time::Duration::from_millis(maknae_config::HOME_RESOLVE_TIMEOUT_MS)
        );
    }

    #[test]
    fn each_cause_has_one_stable_reason() {
        assert_eq!(
            HomeUnavailable::Unresolvable.reason(),
            "requester home unavailable: unresolvable"
        );
        assert_eq!(
            HomeUnavailable::TimedOut.reason(),
            "requester home unavailable: timed out"
        );
        assert_eq!(
            HomeUnavailable::RequesterAtCapacity.reason(),
            "requester home unavailable: at capacity for this requester"
        );
        assert_eq!(
            HomeUnavailable::AtCapacity.reason(),
            "requester home unavailable: at capacity"
        );
    }

    #[tokio::test]
    async fn a_resolving_home_is_returned() {
        let got = HomeResolver::new(1)
            .resolve(1, Some("/home/b".into()), PATIENCE, |d| {
                Some(d.join("canon"))
            })
            .await;
        assert_eq!(got, Ok(std::path::PathBuf::from("/home/b/canon")));
    }

    #[tokio::test]
    async fn no_raw_home_is_unresolvable_and_resolves_nothing() {
        let (ran, f) = never_runs();
        let got = HomeResolver::new(1).resolve(1, None, PATIENCE, f).await;
        assert_eq!(got, Err(HomeUnavailable::Unresolvable));
        assert!(!ran.load(std::sync::atomic::Ordering::SeqCst));
    }

    #[tokio::test]
    async fn a_home_that_does_not_resolve_is_unresolvable() {
        let got = HomeResolver::new(1)
            .resolve(1, Some("/home/b".into()), PATIENCE, |_| None)
            .await;
        assert_eq!(got, Err(HomeUnavailable::Unresolvable));
    }

    #[tokio::test]
    async fn a_panicking_resolver_is_unresolvable() {
        let got = HomeResolver::new(1)
            .resolve(1, Some("/home/b".into()), PATIENCE, |_| panic!("x"))
            .await;
        assert_eq!(got, Err(HomeUnavailable::Unresolvable));
    }

    #[tokio::test]
    async fn a_stalled_home_times_out_while_its_worker_still_blocks() {
        let r = HomeResolver::new(1);
        let (release, held) = std::sync::mpsc::channel::<()>();
        let got = tokio::time::timeout(
            PATIENCE,
            r.resolve(1, Some("/home/b".into()), FAST, held_until(held)),
        )
        .await
        .expect("the caller is not held by the stalled worker");
        assert_eq!(got, Err(HomeUnavailable::TimedOut));
        release.send(()).expect("the worker was still blocked");
    }

    #[tokio::test]
    async fn a_stuck_uid_blocks_only_itself() {
        let r = HomeResolver::new(4);
        let (release, held) = std::sync::mpsc::channel::<()>();
        let first = r
            .resolve(1, Some("/home/a".into()), FAST, held_until(held))
            .await;
        assert_eq!(first, Err(HomeUnavailable::TimedOut));
        assert_eq!(r.capacity.available_permits(), 3);

        let (ran, f) = never_runs();
        let again = r.resolve(1, Some("/home/a".into()), PATIENCE, f).await;
        assert_eq!(again, Err(HomeUnavailable::RequesterAtCapacity));
        assert!(
            !ran.load(std::sync::atomic::Ordering::SeqCst),
            "no worker is spawned for a uid already in flight"
        );
        assert_eq!(
            r.capacity.available_permits(),
            3,
            "the refused attempt took no global slot"
        );

        let other = r
            .resolve(2, Some("/home/b".into()), PATIENCE, |d| Some(d.into()))
            .await;
        assert_eq!(other, Ok(std::path::PathBuf::from("/home/b")));

        release.send(()).unwrap();
        settles(
            "the stuck uid's slot and claim return when its worker ends",
            || r.capacity.available_permits() == 4 && r.gate.try_claim(1).is_some(),
        )
        .await;
    }

    #[tokio::test]
    async fn the_global_capacity_still_bounds_the_total() {
        let r = HomeResolver::new(2);
        let (release_a, held_a) = std::sync::mpsc::channel::<()>();
        let (release_b, held_b) = std::sync::mpsc::channel::<()>();
        assert_eq!(
            r.resolve(1, Some("/home/a".into()), FAST, held_until(held_a))
                .await,
            Err(HomeUnavailable::TimedOut)
        );
        assert_eq!(
            r.resolve(2, Some("/home/b".into()), FAST, held_until(held_b))
                .await,
            Err(HomeUnavailable::TimedOut)
        );
        let (ran, f) = never_runs();
        assert_eq!(
            r.resolve(3, Some("/home/c".into()), PATIENCE, f).await,
            Err(HomeUnavailable::AtCapacity)
        );
        assert!(!ran.load(std::sync::atomic::Ordering::SeqCst));
        assert!(
            r.gate.try_claim(3).is_some(),
            "a global refusal leaves the uid unclaimed"
        );
        release_a.send(()).unwrap();
        release_b.send(()).unwrap();
        let slot = tokio::time::timeout(PATIENCE, r.capacity.acquire_many(2))
            .await
            .expect("both slots return when their workers end");
        drop(slot);
    }

    #[test]
    fn stall_and_capacity_log_on_transition_at_most_once_per_interval() {
        let h = HomeHealth::default();
        let t0 = std::time::Instant::now();
        let at = |d: std::time::Duration| t0 + d;
        let secs = std::time::Duration::from_secs;
        let tick = std::time::Duration::from_millis(1);
        let ok: Result<std::path::PathBuf, HomeUnavailable> = Ok("/home/b".into());
        let err = |e| Err::<std::path::PathBuf, _>(e);
        let i = HOME_HEALTH_LOG_INTERVAL;

        assert_eq!(h.observe(&ok, t0), None, "healthy from the start");
        let stalled = h
            .observe(&err(HomeUnavailable::TimedOut), t0)
            .expect("logged");
        assert!(
            stalled.contains("requester home unavailable: timed out"),
            "{stalled}"
        );
        assert_eq!(
            h.observe(&err(HomeUnavailable::TimedOut), at(secs(1))),
            None
        );
        assert_eq!(h.observe(&ok, at(secs(1))), None, "a flap is held back");
        assert_eq!(
            h.observe(&err(HomeUnavailable::AtCapacity), at(secs(1))),
            None
        );
        assert_eq!(h.observe(&ok, at(i - tick)), None);
        let back = h
            .observe(&ok, at(i))
            .expect("logged once the interval passes");
        assert!(back.contains("recovered"), "{back}");
        assert_eq!(h.observe(&ok, at(i + i)), None, "no change, no line");

        for quiet in [
            HomeUnavailable::Unresolvable,
            HomeUnavailable::RequesterAtCapacity,
        ] {
            assert_eq!(h.observe(&err(quiet), at(i + i)), None, "{quiet:?}");
        }
        let full = h
            .observe(&err(HomeUnavailable::AtCapacity), at(i + i))
            .expect("neither quiet cause changed the state or the clock");
        assert!(
            full.contains("requester home unavailable: at capacity"),
            "{full}"
        );
        assert_eq!(
            h.observe(&err(HomeUnavailable::AtCapacity), at(i * 4)),
            None
        );
        assert_eq!(
            h.observe(&err(HomeUnavailable::RequesterAtCapacity), at(i * 4)),
            None,
            "one uid's own concurrency is not a daemon-wide state"
        );
        assert!(h.observe(&ok, at(i * 4)).is_some());
    }

    struct TempDir(std::path::PathBuf);
    impl TempDir {
        fn new(tag: &str) -> Self {
            let d = std::env::temp_dir().join(format!("authz_{tag}_{}", std::process::id()));
            let _ = std::fs::remove_dir_all(&d);
            std::fs::create_dir_all(&d).unwrap();
            TempDir(d)
        }
    }
    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    #[tokio::test]
    async fn the_production_step_resolves_a_plain_directory_to_its_kernel_form() {
        let d = TempDir::new("plain");
        let got = admitted_home(4_350_001, Some(d.0.clone())).await;
        assert_eq!(got, Ok(std::fs::canonicalize(&d.0).unwrap()));
    }

    #[tokio::test]
    async fn the_production_step_resolves_a_symlink_to_its_target() {
        let d = TempDir::new("link");
        let target = d.0.join("target");
        std::fs::create_dir(&target).unwrap();
        let link = d.0.join("link");
        std::os::unix::fs::symlink(&target, &link).unwrap();
        let got = admitted_home(4_350_002, Some(link)).await;
        assert_eq!(got, Ok(std::fs::canonicalize(&target).unwrap()));
    }

    #[tokio::test]
    async fn the_production_step_refuses_a_missing_directory() {
        let d = TempDir::new("missing");
        let got = admitted_home(4_350_003, Some(d.0.join("absent"))).await;
        assert_eq!(got, Err(HomeUnavailable::Unresolvable));
    }

    fn member(in_group: bool) -> Facts {
        Facts {
            membership: Ok(membership(in_group, "s-115-sentinel")),
            account: AccountFact::Checked(AccountState::Active),
            answered: true,
        }
    }

    fn deny(c: DenyCause) -> Revalidation {
        Revalidation::Deny(c)
    }

    #[test]
    fn an_active_member_continues() {
        assert_eq!(
            revalidate(Admission::MaknaeGroupMember, 7, 7, &member(true)),
            Revalidation::Continue
        );
    }

    #[test]
    fn a_uid_that_is_not_the_bound_uid_is_a_session_map_failure() {
        let mut f = member(false);
        f.membership = Err(AuthzError::Resolve("nss".into()));
        assert_eq!(
            revalidate(Admission::MaknaeGroupMember, 7, 8, &f),
            deny(DenyCause::Infrastructure(FactSource::SessionMap))
        );
    }

    #[test]
    fn a_gather_that_did_not_answer_names_the_session_facts_not_a_source() {
        let mut f = member(true);
        f.answered = false;
        assert_eq!(
            revalidate(Admission::MaknaeGroupMember, 7, 7, &f),
            deny(DenyCause::Infrastructure(FactSource::SessionFacts))
        );
        assert_eq!(
            revalidate(Admission::MaknaeGroupMember, 7, 8, &f),
            deny(DenyCause::Infrastructure(FactSource::SessionMap))
        );
    }

    #[test]
    fn each_source_has_its_name() {
        for (source, name) in [
            (FactSource::Group, "group"),
            (FactSource::Account, "account"),
            (FactSource::SessionMap, "session-map"),
            (FactSource::Audit, "audit"),
            (FactSource::SessionFacts, "session-facts"),
        ] {
            assert_eq!(source.name(), name);
        }
    }

    #[test]
    fn an_unanswered_membership_is_infrastructure() {
        let mut f = member(true);
        f.membership = Err(AuthzError::Resolve("nss".into()));
        f.account = AccountFact::Checked(AccountState::Locked);
        assert_eq!(
            revalidate(Admission::MaknaeGroupMember, 7, 7, &f),
            deny(DenyCause::Infrastructure(FactSource::Group))
        );
    }

    #[test]
    fn a_failed_group_source_is_infrastructure_not_de_enrollment() {
        let mut f = member(true);
        f.membership = Err(AuthzError::Unanswered {
            user: "s-115-sentinel".into(),
            why: "EIO".into(),
        });
        f.account = AccountFact::Checked(AccountState::Locked);
        assert_eq!(
            revalidate(Admission::MaknaeGroupMember, 7, 7, &f),
            deny(DenyCause::Infrastructure(FactSource::Group))
        );
    }

    #[test]
    fn a_deleted_account_is_not_a_member() {
        let mut f = member(true);
        f.membership = Err(AuthzError::NoUser);
        f.account = AccountFact::Checked(AccountState::Locked);
        assert_eq!(
            revalidate(Admission::MaknaeGroupMember, 7, 7, &f),
            deny(DenyCause::NotMember)
        );
    }

    #[test]
    fn a_non_member_is_not_a_member() {
        let mut f = member(false);
        f.account = AccountFact::Checked(AccountState::Locked);
        assert_eq!(
            revalidate(Admission::MaknaeGroupMember, 7, 7, &f),
            deny(DenyCause::NotMember)
        );
    }

    #[test]
    fn an_unknown_account_is_infrastructure() {
        let mut f = member(true);
        f.account = AccountFact::Checked(AccountState::Unknown("userdb".into()));
        assert_eq!(
            revalidate(Admission::MaknaeGroupMember, 7, 7, &f),
            deny(DenyCause::Infrastructure(FactSource::Account))
        );
    }

    #[test]
    fn a_locked_expired_or_disabled_account_is_refused_by_its_state() {
        for state in [
            AccountState::Locked,
            AccountState::Expired,
            AccountState::Disabled,
        ] {
            let mut f = member(true);
            f.account = AccountFact::Checked(state.clone());
            assert_eq!(
                revalidate(Admission::MaknaeGroupMember, 7, 7, &f),
                deny(DenyCause::Account(state))
            );
        }
    }

    #[test]
    fn a_not_checked_account_continues() {
        for why in [
            NotCheckedWhy::DirectoryAccount,
            NotCheckedWhy::Platform,
            NotCheckedWhy::Configured,
        ] {
            let mut f = member(true);
            f.account = AccountFact::NotChecked(why);
            assert_eq!(
                revalidate(Admission::MaknaeGroupMember, 7, 7, &f),
                Revalidation::Continue
            );
        }
    }

    #[test]
    fn each_cause_has_its_audit_reason_and_posture() {
        for (cause, reason, posture) in [
            (DenyCause::NotMember, "not-member", "unauthorized"),
            (
                DenyCause::Account(AccountState::Locked),
                "account-locked",
                "unauthorized",
            ),
            (
                DenyCause::Account(AccountState::Expired),
                "account-expired",
                "unauthorized",
            ),
            (
                DenyCause::Account(AccountState::Disabled),
                "account-disabled",
                "unauthorized",
            ),
            (
                DenyCause::Account(AccountState::Active),
                "account-active",
                "unauthorized",
            ),
            (
                DenyCause::Account(AccountState::Unknown("x".into())),
                "account-unknown",
                "unauthorized",
            ),
            (DenyCause::SenderMismatch, "sender-mismatch", "unauthorized"),
            (
                DenyCause::Infrastructure(FactSource::Group),
                "infrastructure:group",
                "unavailable",
            ),
            (
                DenyCause::Infrastructure(FactSource::Account),
                "infrastructure:account",
                "unavailable",
            ),
            (
                DenyCause::Infrastructure(FactSource::SessionMap),
                "infrastructure:session-map",
                "unavailable",
            ),
            (
                DenyCause::Infrastructure(FactSource::Audit),
                "infrastructure:audit",
                "unavailable",
            ),
            (
                DenyCause::Infrastructure(FactSource::SessionFacts),
                "infrastructure:session-facts",
                "unavailable",
            ),
        ] {
            assert_eq!(
                (&*cause_reason(&cause), cause_posture(&cause)),
                (reason, posture),
                "{cause:?}"
            );
        }
    }

    const HOBI: u32 = 2001;
    const JIN: u32 = 2002;

    fn agent(id: &str) -> AgentId {
        AgentId::parse(id).unwrap()
    }

    fn enrolled(pairs: &[(&str, u32)]) -> crate::enrollment::FixedEnrollment {
        crate::enrollment::FixedEnrollment(pairs.iter().map(|(a, u)| (agent(a), *u)).collect())
    }

    fn leaf(id: &str, not_after: std::time::SystemTime) -> ChannelPeer {
        ChannelPeer::Agent {
            san: maknae_vault::agent_uri_san("d", &agent(id)),
            agent: agent(id),
            not_after,
        }
    }

    fn hobi_leaf() -> ChannelPeer {
        leaf(
            "hobi",
            std::time::SystemTime::now() + std::time::Duration::from_secs(3600),
        )
    }

    #[test]
    fn an_enrolled_agent_is_admitted() {
        assert_eq!(
            admit(
                Admission::EnrolledAgent,
                &hobi_leaf(),
                HOBI,
                &enrolled(&[("hobi", HOBI)])
            ),
            Ok(())
        );
    }

    #[test]
    fn a_wrong_uid_is_refused_at_connect() {
        let view = enrolled(&[("hobi", HOBI), ("jin", JIN)]);
        assert_eq!(
            admit(Admission::EnrolledAgent, &hobi_leaf(), JIN, &view),
            Err(DenyCause::NotEnrolled)
        );
    }

    #[test]
    fn a_de_enrolled_agent_is_refused_at_connect() {
        let view = enrolled(&[("jin", JIN)]);
        assert_eq!(
            admit(Admission::EnrolledAgent, &hobi_leaf(), HOBI, &view),
            Err(DenyCause::NotEnrolled)
        );
        for peer in [
            ChannelPeer::Certless,
            ChannelPeer::Certified("spiffe://d/plane/cli".into()),
        ] {
            assert_eq!(
                admit(
                    Admission::EnrolledAgent,
                    &peer,
                    HOBI,
                    &enrolled(&[("hobi", HOBI)])
                ),
                Err(DenyCause::NotEnrolled),
                "{peer:?}"
            );
        }
    }

    #[test]
    fn an_agent_uid_is_refused_on_the_client_socket() {
        assert_eq!(
            admit(
                Admission::MaknaeGroupMember,
                &ChannelPeer::Certless,
                HOBI,
                &enrolled(&[("hobi", HOBI)])
            ),
            Err(DenyCause::AgentAccount)
        );
    }

    #[test]
    fn the_uid_of_an_ignored_enrollment_is_an_ordinary_account_on_the_client_socket() {
        assert_eq!(
            admit(
                Admission::MaknaeGroupMember,
                &ChannelPeer::Certless,
                HOBI,
                &enrolled(&[("jin", JIN)])
            ),
            Ok(())
        );
    }

    fn outside_maknae() -> Facts {
        Facts {
            membership: Ok(membership(false, "hobi-svc")),
            account: AccountFact::Checked(AccountState::Active),
            answered: true,
        }
    }

    #[test]
    fn an_agent_outside_maknae_continues_on_its_account_state() {
        let a = Admission::EnrolledAgent;
        assert_eq!(
            revalidate(a, HOBI, HOBI, &outside_maknae()),
            Revalidation::Continue
        );
        let mut locked = outside_maknae();
        locked.account = AccountFact::Checked(AccountState::Locked);
        assert_eq!(
            revalidate(a, HOBI, HOBI, &locked),
            deny(DenyCause::Account(AccountState::Locked))
        );
        assert_eq!(
            revalidate(a, HOBI, JIN, &outside_maknae()),
            deny(DenyCause::Infrastructure(FactSource::SessionMap))
        );
    }

    #[test]
    fn an_agent_session_whose_account_joins_maknae_is_refused_at_the_next_request() {
        let mut joined = outside_maknae();
        joined.membership = Ok(membership(true, "hobi-svc"));
        assert_eq!(
            revalidate(Admission::EnrolledAgent, HOBI, HOBI, &joined),
            deny(DenyCause::HumanAccount)
        );
    }

    #[test]
    fn an_unanswered_group_source_is_infrastructure_for_an_agent() {
        for failed in [
            AuthzError::Resolve("nss".into()),
            AuthzError::Unanswered {
                user: "hobi-svc".into(),
                why: "EIO".into(),
            },
        ] {
            let mut f = outside_maknae();
            f.membership = Err(failed);
            assert_eq!(
                revalidate(Admission::EnrolledAgent, HOBI, HOBI, &f),
                deny(DenyCause::Infrastructure(FactSource::Group))
            );
        }
    }

    #[test]
    fn a_gone_agent_account_is_not_enrolled() {
        let mut f = outside_maknae();
        f.membership = Err(AuthzError::NoUser);
        assert_eq!(
            revalidate(Admission::EnrolledAgent, HOBI, HOBI, &f),
            deny(DenyCause::NotEnrolled)
        );
    }

    #[test]
    fn an_agents_home_is_its_own_directory_outside_maknae() {
        assert_eq!(
            admission_facts(Admission::EnrolledAgent, &Ok(membership(false, "hobi-svc"))),
            (
                false,
                Some("hobi-svc".to_string()),
                Some(std::path::PathBuf::from("/home/hobi-svc"))
            )
        );
        assert_eq!(
            admission_facts(Admission::EnrolledAgent, &Ok(membership(true, "hobi-svc"))),
            (true, Some("hobi-svc".to_string()), None)
        );
    }

    fn task_of(id: &str, tasker_uid: u32) -> SignedTask {
        use crate::task::TaskObjectForTest;
        SignedTask {
            task: maknae_proto::TaskObject::for_test(id, tasker_uid),
            signature: maknae_proto::TaskSignature {
                alg: "test".into(),
                leaf: maknae_proto::Bytes::new(vec![1].into()),
                chain: Vec::new(),
                sig: maknae_proto::Bytes::new(vec![2].into()),
            },
        }
    }

    #[test]
    fn a_request_citing_an_unknown_task_is_refused() {
        let store = TaskStore::new();
        let unknown = task_of("hobi", 1000).task.task_id;
        assert_eq!(
            task_for(
                Admission::EnrolledAgent,
                Some(&unknown),
                Some(&agent("hobi")),
                HOBI,
                &store
            ),
            Err(DenyCause::TaskNotWorking { cited: unknown })
        );
    }

    #[test]
    fn a_request_citing_its_own_task_that_is_not_working_is_refused() {
        let store = TaskStore::new();
        let queued = store.insert_for_test(task_of("hobi", 1000), HOBI);
        let cite = |id: &TaskId| {
            task_for(
                Admission::EnrolledAgent,
                Some(id),
                Some(&agent("hobi")),
                HOBI,
                &store,
            )
        };
        let id = queued.task.task_id;
        assert_eq!(cite(&id), Err(DenyCause::TaskNotWorking { cited: id }));
        store.start_for_test(&id);
        assert!(cite(&id).unwrap().is_some());
        store
            .publish_report(&id, maknae_proto::SecretText(String::new().into()), None)
            .unwrap();
        assert_eq!(cite(&id), Err(DenyCause::TaskNotWorking { cited: id }));
    }

    #[test]
    fn citing_a_non_working_task_is_refused() {
        use maknae_proto::{SecretText, TaskClose, TaskState, Tasker};
        let store = TaskStore::new();
        let me = Tasker::Uid(1000);
        let cite = |id: &TaskId| {
            task_for(
                Admission::EnrolledAgent,
                Some(id),
                Some(&agent("hobi")),
                HOBI,
                &store,
            )
        };
        let held = || {
            let id = store
                .insert_for_test(task_of("hobi", 1000), HOBI)
                .task
                .task_id;
            assert_eq!(cite(&id), Err(DenyCause::TaskNotWorking { cited: id }));
            store.start_for_test(&id);
            let cited = cite(&id).unwrap().expect("a working task is citable");
            assert_eq!(cited.signed.task.task_id, id);
            assert_eq!(cited.root.partition(), "users/1000");
            id
        };
        let empty = || SecretText(String::new().into());
        let queued = store
            .insert_for_test(task_of("hobi", 1000), HOBI)
            .task
            .task_id;
        let reported = held();
        store.publish_report(&reported, empty(), None).unwrap();
        let stopped = held();
        store.stop(&stopped, &me).unwrap();
        let closed = held();
        store
            .publish_report(&closed, empty(), Some(TaskClose::AgentGone))
            .unwrap();
        for (id, state) in [
            (queued, TaskState::Queued),
            (reported, TaskState::Reported),
            (stopped, TaskState::Closed),
            (closed, TaskState::Closed),
        ] {
            assert_eq!(store.state_for(&id, &me), Some(state));
            assert_eq!(
                cite(&id),
                Err(DenyCause::TaskNotWorking { cited: id }),
                "{state:?}"
            );
        }
        assert!(cite(&held()).is_ok());
    }

    #[test]
    fn a_sub_task_is_cited_with_the_root_persons_partition() {
        let store = TaskStore::new();
        let parent = store.insert_for_test(task_of("jin", 1000), JIN);
        let mut sub = task_of("hobi", 0);
        sub.task.tasker = maknae_proto::Tasker::Agent {
            agent: "jin".into(),
            uid: JIN,
        };
        sub.task.parent = Some(parent.task.task_id);
        let sub = store.insert_for_test(sub, HOBI).task.task_id;
        store.start_for_test(&sub);
        let cited = task_for(
            Admission::EnrolledAgent,
            Some(&sub),
            Some(&agent("hobi")),
            HOBI,
            &store,
        )
        .unwrap()
        .unwrap();
        assert_eq!(cited.root.partition(), "users/1000");
        assert_eq!(crate::handler::TaskStamp::of(&cited).root, "users/1000");
        assert_eq!(crate::handler::TaskStamp::of(&cited).tasker, "agent:jin");
    }

    #[test]
    fn a_request_citing_another_agents_task_is_refused() {
        let store = TaskStore::new();
        let jins = store.insert_for_test(task_of("jin", 1000), JIN);
        let hobis = store.insert_for_test(task_of("hobi", 1000), HOBI);
        store.start_for_test(&jins.task.task_id);
        store.start_for_test(&hobis.task.task_id);
        assert_eq!(
            task_for(
                Admission::EnrolledAgent,
                Some(&jins.task.task_id),
                Some(&agent("hobi")),
                HOBI,
                &store
            ),
            Err(DenyCause::Task {
                refusal: TaskRefusal::OtherAgent,
                cited: jins.task.task_id
            })
        );
        assert_eq!(
            task_for(
                Admission::EnrolledAgent,
                Some(&hobis.task.task_id),
                Some(&agent("hobi")),
                JIN,
                &store
            ),
            Err(DenyCause::Task {
                refusal: TaskRefusal::OtherAgent,
                cited: hobis.task.task_id
            })
        );
        let own = task_for(
            Admission::EnrolledAgent,
            Some(&hobis.task.task_id),
            Some(&agent("hobi")),
            HOBI,
            &store,
        )
        .unwrap()
        .expect("its own task resolves");
        assert!(Arc::ptr_eq(&own.signed, &hobis));
    }

    #[test]
    fn a_task_id_on_the_client_channel_is_refused() {
        let store = TaskStore::new();
        let held = store.insert_for_test(task_of("hobi", 1000), HOBI);
        assert_eq!(
            task_for(
                Admission::MaknaeGroupMember,
                Some(&held.task.task_id),
                None,
                HOBI,
                &store
            ),
            Err(DenyCause::TaskOnClientChannel)
        );
        assert_eq!(
            task_for(Admission::MaknaeGroupMember, None, None, HOBI, &store),
            Ok(None)
        );
    }

    #[test]
    fn an_agent_request_without_a_task_is_decided_on_its_own_policy() {
        let store = TaskStore::new();
        store.insert_for_test(task_of("hobi", 1000), HOBI);
        assert_eq!(
            task_for(
                Admission::EnrolledAgent,
                None,
                Some(&agent("hobi")),
                HOBI,
                &store
            ),
            Ok(None)
        );
    }

    #[test]
    fn the_session_ends_at_the_leaf_or_the_visit_clock_whichever_is_first() {
        use crate::session::{SessionChannel, SessionRecord};
        use std::time::{Duration, Instant, SystemTime};
        let now = Instant::now();
        let at = |opened_ago: u64, lifetime: u64, leaf_in: Option<i64>| {
            let mut s = SessionRecord::for_test(HOBI, None);
            s.opened_at = now - Duration::from_secs(opened_ago);
            s.lifetime = Duration::from_secs(lifetime);
            if let Some(d) = leaf_in {
                let leaf_expires = if d >= 0 {
                    now + Duration::from_secs(d.unsigned_abs())
                } else {
                    now - Duration::from_secs(d.unsigned_abs())
                };
                s.channel = SessionChannel::Agent {
                    agent: agent("hobi"),
                    leaf_expires,
                };
            }
            s.expiry()
        };
        assert_eq!(at(10, 60, None), None);
        assert_eq!(at(10, 5, None), Some(Ending::Lifetime));
        assert_eq!(at(10, 60, Some(60)), None);
        assert_eq!(at(10, 60, Some(-1)), Some(Ending::LeafExpired));
        assert_eq!(at(10, 5, Some(60)), Some(Ending::Lifetime));
        assert_eq!(at(100, 5, Some(-1)), Some(Ending::Lifetime));
        assert_eq!(at(100, 99, Some(-5)), Some(Ending::LeafExpired));
        assert_eq!(at(100, 50, Some(-50)), Some(Ending::Lifetime));

        let fresh = SessionChannel::of(
            Admission::EnrolledAgent,
            &leaf("hobi", SystemTime::now() + Duration::from_secs(600)),
        )
        .unwrap();
        match fresh {
            SessionChannel::Agent {
                agent: a,
                leaf_expires,
            } => {
                assert_eq!(a, agent("hobi"));
                let left = leaf_expires.saturating_duration_since(Instant::now());
                assert!(left > Duration::from_secs(590) && left <= Duration::from_secs(600));
            }
            SessionChannel::Client => panic!("an agent leaf opens an agent channel"),
        }
        assert_eq!(
            SessionChannel::of(
                Admission::EnrolledAgent,
                &leaf("hobi", SystemTime::now() - Duration::from_secs(1))
            ),
            Err(Ending::LeafExpired),
            "a leaf already expired at admission is refused"
        );
        assert_eq!(
            SessionChannel::of(Admission::MaknaeGroupMember, &ChannelPeer::Certless),
            Ok(SessionChannel::Client)
        );
        assert_eq!(
            SessionChannel::of(Admission::EnrolledAgent, &ChannelPeer::Certless),
            Err(Ending::Denied(DenyCause::NotEnrolled))
        );
        assert_eq!(
            SessionChannel::of(Admission::MaknaeGroupMember, &hobi_leaf()),
            Err(Ending::Denied(DenyCause::NotEnrolled)),
            "an agent leaf never opens a client channel"
        );
    }

    #[test]
    fn every_task_refusal_has_its_cited_reason() {
        let cited = TaskId([0x0e; 16]);
        for (refusal, reason) in [
            (TaskRefusal::Unknown, "task-unknown"),
            (TaskRefusal::OtherAgent, "task-other-agent"),
            (TaskRefusal::Schema("s".into()), "task-schema"),
            (TaskRefusal::Denied("d".into()), "task-denied"),
            (
                TaskRefusal::AtCapacity { agent: "a".into() },
                "task-at-capacity",
            ),
            (TaskRefusal::ParentNotHeld, "task-parent-not-held"),
            (TaskRefusal::AgentGone, "task-agent-gone"),
            (TaskRefusal::Random, "task-random"),
            (TaskRefusal::Audit("a".into()), "task-audit"),
            (TaskRefusal::Unsigned, "task-unsigned"),
            (TaskRefusal::Store("s".into()), "task-store"),
            (TaskRefusal::CursorAhead, "cursor_ahead"),
            (TaskRefusal::Finished, "task-finished"),
            (TaskRefusal::TooLong, "task-too-long"),
            (
                TaskRefusal::TaskerLive { agent: "a".into() },
                "task-tasker-live",
            ),
            (TaskRefusal::TaskerHeld, "task-tasker-held"),
            (TaskRefusal::FollowUps, "task-follow-ups"),
            (TaskRefusal::FollowUpsUnseen, "task-follow-ups-unseen"),
            (TaskRefusal::NotWorking, "task-not-working"),
            (TaskRefusal::Unavailable("u".into()), "task-unavailable"),
        ] {
            assert_eq!(
                cause_reason(&DenyCause::Task { refusal, cited }),
                format!("{reason}:{cited}")
            );
        }
    }

    #[test]
    fn each_agent_and_task_cause_has_its_audit_reason_and_posture() {
        let cited = TaskId([0x0f; 16]);
        let hex = "0f".repeat(16);
        for (cause, reason) in [
            (DenyCause::AgentAccount, "agent-account".to_string()),
            (DenyCause::NotEnrolled, "not-enrolled".to_string()),
            (DenyCause::HumanAccount, "human-account".to_string()),
            (
                DenyCause::TaskOnClientChannel,
                "task-on-client-channel".to_string(),
            ),
            (
                DenyCause::Task {
                    refusal: TaskRefusal::Unknown,
                    cited,
                },
                format!("task-unknown:{hex}"),
            ),
            (
                DenyCause::Task {
                    refusal: TaskRefusal::OtherAgent,
                    cited,
                },
                format!("task-other-agent:{hex}"),
            ),
            (
                DenyCause::TaskNotWorking { cited },
                format!("task-not-working:{hex}"),
            ),
        ] {
            assert_eq!(
                (cause_reason(&cause).into_owned(), cause_posture(&cause)),
                (reason, "unauthorized"),
                "{cause:?}"
            );
        }
        assert_eq!(
            (
                &*ending_reason(&Ending::LeafExpired),
                ending_result(&Ending::LeafExpired),
                ending_posture(&Ending::LeafExpired)
            ),
            ("leaf-expired", "deny", "stopped")
        );
    }

    #[test]
    fn the_admission_reason_says_what_was_and_was_not_checked() {
        for (account, label) in [
            (AccountFact::Checked(AccountState::Active), "active"),
            (AccountFact::Checked(AccountState::Locked), "locked"),
            (AccountFact::Checked(AccountState::Expired), "expired"),
            (AccountFact::Checked(AccountState::Disabled), "disabled"),
            (
                AccountFact::Checked(AccountState::Unknown("x".into())),
                "unknown",
            ),
            (
                AccountFact::NotChecked(NotCheckedWhy::DirectoryAccount),
                "not-checked:directory",
            ),
            (
                AccountFact::NotChecked(NotCheckedWhy::Platform),
                "not-checked:platform",
            ),
            (
                AccountFact::NotChecked(NotCheckedWhy::Configured),
                "not-checked:configured",
            ),
        ] {
            assert_eq!(account_label(&account), label);
            assert_eq!(
                admission_reason(&account),
                format!("admitted (account: {label})")
            );
        }
    }

    #[test]
    fn each_ending_has_its_termination_reason_result_and_posture() {
        for (ending, reason, result, posture) in [
            (Ending::Disconnect, "disconnect", "permit", "stopped"),
            (Ending::Idle, "idle", "deny", "stopped"),
            (Ending::Lifetime, "lifetime", "deny", "stopped"),
            (
                Ending::Denied(DenyCause::NotMember),
                "not-member",
                "deny",
                "unauthorized",
            ),
            (
                Ending::Denied(DenyCause::Infrastructure(FactSource::Group)),
                "infrastructure:group",
                "deny",
                "unavailable",
            ),
        ] {
            assert_eq!(
                (
                    &*ending_reason(&ending),
                    ending_result(&ending),
                    ending_posture(&ending)
                ),
                (reason, result, posture),
                "{ending:?}"
            );
        }
    }
}
