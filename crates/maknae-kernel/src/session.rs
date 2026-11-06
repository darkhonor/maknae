//! The daemon-side session record and the bounded gather of the facts it is
//! re-decided on (ADR-0006 decision 4, #115).
use std::path::PathBuf;
use std::sync::{Arc, OnceLock};
use std::time::{Duration, Instant};

use maknae_audit_append::Seq;
use maknae_vault::{PeerProcess, SenderVerdict};

use crate::authz::Ending;
use crate::blocking_guard::{BlockingBreaker, BreakerAdmission, BreakerTransition};
use crate::deployment::Platform;
use crate::groupres::{AuthzError, Membership};
use crate::handler::Admission;
use crate::session_facts::{AccountFact, AccountState, LoginFact};

pub trait SessionFacts: Send + Sync {
    fn membership(&self, admission: Admission, uid: u32) -> Result<Membership, AuthzError>;
    fn login(
        &self,
        process: &PeerProcess,
        pid: Option<u32>,
        uid: u32,
        user: Option<&str>,
    ) -> LoginFact;
    fn account(&self, uid: u32) -> AccountFact;
}

/// The facts one decision is made on; `membership` is `Err(Resolve)` when the lookup
/// failed or did not answer in time.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Facts {
    pub membership: Result<Membership, AuthzError>,
    pub login: LoginFact,
    pub account: AccountFact,
}

impl Facts {
    fn unanswered(why: &str) -> Self {
        Facts {
            membership: Err(AuthzError::Resolve(why.to_string())),
            login: LoginFact::Unavailable(why.to_string()),
            account: AccountFact::Checked(AccountState::Unknown(why.to_string())),
        }
    }
}

pub struct FactsGate {
    pub facts: Arc<dyn SessionFacts>,
    pub breaker: Arc<tokio::sync::Mutex<BlockingBreaker>>,
    pub bound: Duration,
}

impl FactsGate {
    #[cfg(any(test, feature = "hermetic-test-seam"))]
    pub fn for_test(facts: Arc<dyn SessionFacts>, bound: Duration) -> Arc<Self> {
        Arc::new(FactsGate {
            facts,
            breaker: Arc::new(tokio::sync::Mutex::new(BlockingBreaker::default())),
            bound,
        })
    }

    #[cfg(any(test, feature = "hermetic-test-seam"))]
    pub fn allow() -> Arc<Self> {
        Self::for_test(Arc::new(AllowFacts), Duration::from_secs(5))
    }
}

/// A member with a live login whose account state this platform does not read.
#[cfg(any(test, feature = "hermetic-test-seam"))]
pub struct AllowFacts;

#[cfg(any(test, feature = "hermetic-test-seam"))]
impl SessionFacts for AllowFacts {
    fn membership(&self, _admission: Admission, uid: u32) -> Result<Membership, AuthzError> {
        Ok(Membership {
            in_group: true,
            user: format!("allow-{uid}"),
            dir: PathBuf::from("/nonexistent"),
        })
    }

    fn login(
        &self,
        _process: &PeerProcess,
        _pid: Option<u32>,
        _uid: u32,
        _user: Option<&str>,
    ) -> LoginFact {
        LoginFact::Live
    }

    fn account(&self, _uid: u32) -> AccountFact {
        AccountFact::NotChecked(crate::session_facts::NotCheckedWhy::Platform)
    }
}

/// Every lookup the decision needs, as one blocking unit under the gate's breaker
/// and bound. `user` is the session's when it has one; otherwise `login` gets
/// the name `membership` resolved.
pub(crate) async fn gather(
    gate: &FactsGate,
    admission: Admission,
    uid: u32,
    process: Arc<PeerProcess>,
    pid: Option<u32>,
    user: Option<String>,
) -> Facts {
    let now = Instant::now();
    let admitted = gate.breaker.lock().await.begin_attempt_at(now);
    match admitted {
        BreakerAdmission::RefuseOpen => {
            if gate.breaker.lock().await.should_log_refusal_at(now) {
                eprintln!(
                    "maknaed: session fact lookup circuit breaker open for uid={uid} — failing closed without spawning more lookups"
                );
            }
            Facts::unanswered("session fact lookup circuit breaker open")
        }
        BreakerAdmission::RefuseAtCapacity => {
            Facts::unanswered("session fact lookup blocking worker budget exhausted")
        }
        BreakerAdmission::Admit => {
            let facts = Arc::clone(&gate.facts);
            let looked_up = tokio::time::timeout(
                gate.bound,
                tokio::task::spawn_blocking(move || {
                    let membership = facts.membership(admission, uid);
                    let name = user.or_else(|| membership.as_ref().ok().map(|m| m.user.clone()));
                    let login = facts.login(&process, pid, uid, name.as_deref());
                    let account = facts.account(uid);
                    Facts {
                        membership,
                        login,
                        account,
                    }
                }),
            )
            .await;
            match looked_up {
                Ok(joined) => {
                    gate.breaker.lock().await.record_success();
                    joined.unwrap_or_else(|_| Facts::unanswered("session fact lookup failed"))
                }
                Err(_elapsed) => {
                    if gate.breaker.lock().await.record_timeout_at(Instant::now())
                        == BreakerTransition::Tripped
                    {
                        eprintln!(
                            "maknaed: session fact lookup circuit breaker tripped after repeated {}ms blocking timeouts — failing closed without spawning more lookups",
                            gate.bound.as_millis()
                        );
                    } else {
                        eprintln!(
                            "maknaed: session fact lookup for uid={uid} stalled past {}ms — failing closed (deny)",
                            gate.bound.as_millis()
                        );
                    }
                    Facts::unanswered("session fact lookup timed out")
                }
            }
        }
    }
}

/// One admitted client connection, held only daemon-side and dropped with it.
pub struct SessionRecord {
    pub uid: u32,
    pub user: Option<String>,
    pub dir: Option<PathBuf>,
    pub session_id: u64,
    pub lane: maknae_security::Lane,
    pub admission: Admission,
    pub process: Arc<PeerProcess>,
    pub pid: Option<u32>,
    pub sender: SenderVerdict,
    pub account: AccountFact,
    pub seq: Seq,
    pub opened_at: Instant,
    pub lifetime: Duration,
    pub platform: Platform,
    pub(crate) ending: OnceLock<Ending>,
}

impl SessionRecord {
    /// Records why the session ended; the first ending other than `Disconnect` stands.
    pub fn end(&self, e: Ending) {
        match e {
            Ending::Disconnect => {}
            Ending::Idle | Ending::Lifetime | Ending::Denied(_) => {
                let _ = self.ending.set(e);
            }
        }
    }

    pub fn ending(&self) -> Ending {
        self.ending.get().cloned().unwrap_or(Ending::Disconnect)
    }

    pub fn expired(&self) -> bool {
        self.opened_at.elapsed() > self.lifetime
    }

    #[cfg(any(test, feature = "hermetic-test-seam"))]
    pub fn for_test(uid: u32, user: Option<String>, dir: Option<PathBuf>) -> Self {
        SessionRecord {
            uid,
            user,
            dir,
            session_id: 1,
            lane: maknae_security::Lane::Local,
            admission: Admission::MaknaeGroupMember,
            process: Arc::new(PeerProcess::Unavailable),
            pid: None,
            sender: SenderVerdict::default(),
            account: AccountFact::NotChecked(crate::session_facts::NotCheckedWhy::Platform),
            seq: Seq::new(),
            opened_at: Instant::now(),
            lifetime: Duration::MAX,
            platform: Platform::of_build(),
            ending: OnceLock::new(),
        }
    }

    #[cfg(any(test, feature = "hermetic-test-seam"))]
    pub fn with_session_id(mut self, session_id: u64) -> Self {
        self.session_id = session_id;
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::authz::DenyCause;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Mutex;

    struct Probe {
        calls: AtomicUsize,
        delay: Duration,
        member: Result<Membership, AuthzError>,
        seen_user: Mutex<Option<Option<String>>>,
    }

    impl Probe {
        fn new(delay: Duration, member: Result<Membership, AuthzError>) -> Arc<Self> {
            Arc::new(Probe {
                calls: AtomicUsize::new(0),
                delay,
                member,
                seen_user: Mutex::new(None),
            })
        }
    }

    impl SessionFacts for Probe {
        fn membership(&self, _admission: Admission, _uid: u32) -> Result<Membership, AuthzError> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            std::thread::sleep(self.delay);
            self.member.clone()
        }

        fn login(
            &self,
            _process: &PeerProcess,
            _pid: Option<u32>,
            _uid: u32,
            user: Option<&str>,
        ) -> LoginFact {
            *self.seen_user.lock().unwrap() = Some(user.map(str::to_string));
            LoginFact::NotActive
        }

        fn account(&self, _uid: u32) -> AccountFact {
            AccountFact::Checked(AccountState::Expired)
        }
    }

    fn resolved(user: &str) -> Result<Membership, AuthzError> {
        Ok(Membership {
            in_group: true,
            user: user.into(),
            dir: "/home/x".into(),
        })
    }

    fn gate(probe: &Arc<Probe>, bound: Duration) -> Arc<FactsGate> {
        FactsGate::for_test(Arc::clone(probe) as Arc<dyn SessionFacts>, bound)
    }

    async fn ask(gate: &FactsGate, user: Option<&str>) -> Facts {
        gather(
            gate,
            Admission::MaknaeGroupMember,
            4242,
            Arc::new(PeerProcess::Gone),
            Some(1),
            user.map(str::to_string),
        )
        .await
    }

    #[tokio::test]
    async fn the_three_answers_are_gathered_together() {
        let probe = Probe::new(Duration::ZERO, resolved("ann"));
        let got = ask(&gate(&probe, Duration::from_secs(5)), None).await;
        assert_eq!(
            got,
            Facts {
                membership: resolved("ann"),
                login: LoginFact::NotActive,
                account: AccountFact::Checked(AccountState::Expired),
            }
        );
    }

    #[tokio::test]
    async fn the_login_is_asked_for_the_sessions_user_before_the_resolved_one() {
        let probe = Probe::new(Duration::ZERO, resolved("resolved"));
        let g = gate(&probe, Duration::from_secs(5));
        ask(&g, Some("bound")).await;
        assert_eq!(
            *probe.seen_user.lock().unwrap(),
            Some(Some("bound".to_string()))
        );
        ask(&g, None).await;
        assert_eq!(
            *probe.seen_user.lock().unwrap(),
            Some(Some("resolved".to_string()))
        );
    }

    #[tokio::test]
    async fn a_failed_membership_is_unanswered_and_names_no_user() {
        let probe = Probe::new(Duration::ZERO, Err(AuthzError::Resolve("nss".into())));
        let got = ask(&gate(&probe, Duration::from_secs(5)), None).await;
        assert_eq!(got.membership, Err(AuthzError::Resolve("nss".into())));
        assert_eq!(*probe.seen_user.lock().unwrap(), Some(None));
    }

    #[tokio::test]
    async fn a_stalled_fact_source_trips_the_breaker() {
        let probe = Probe::new(Duration::from_millis(200), resolved("slow"));
        let g = gate(&probe, Duration::from_millis(20));
        for _ in 0..crate::blocking_guard::BLOCKING_BREAKER_TRIP_AFTER {
            let got = ask(&g, None).await;
            assert_eq!(got, Facts::unanswered("session fact lookup timed out"));
            assert_eq!(
                crate::authz::revalidate(4242, 4242, &got),
                crate::authz::Revalidation::Deny(DenyCause::Infrastructure("group"))
            );
        }
        let spawned = probe.calls.load(Ordering::SeqCst);
        for _ in 0..2 {
            assert_eq!(
                ask(&g, None).await,
                Facts::unanswered("session fact lookup circuit breaker open")
            );
        }
        assert_eq!(
            probe.calls.load(Ordering::SeqCst),
            spawned,
            "an open breaker refuses before spawning"
        );
    }

    #[tokio::test]
    async fn a_full_worker_budget_refuses_before_spawning() {
        let probe = Probe::new(Duration::ZERO, resolved("x"));
        let g = gate(&probe, Duration::from_secs(5));
        {
            let mut b = g.breaker.lock().await;
            while b.begin_attempt_at(Instant::now()) == BreakerAdmission::Admit {}
        }
        assert_eq!(
            ask(&g, None).await,
            Facts::unanswered("session fact lookup blocking worker budget exhausted")
        );
        assert_eq!(probe.calls.load(Ordering::SeqCst), 0);
    }

    struct Panics;
    impl SessionFacts for Panics {
        fn membership(&self, _admission: Admission, _uid: u32) -> Result<Membership, AuthzError> {
            panic!("lookup panicked")
        }
        fn login(
            &self,
            _process: &PeerProcess,
            _pid: Option<u32>,
            _uid: u32,
            _user: Option<&str>,
        ) -> LoginFact {
            LoginFact::Live
        }
        fn account(&self, _uid: u32) -> AccountFact {
            AccountFact::Checked(AccountState::Active)
        }
    }

    #[tokio::test]
    async fn a_panicking_lookup_is_unanswered_and_does_not_count_against_the_breaker() {
        let g = FactsGate::for_test(Arc::new(Panics), Duration::from_secs(5));
        for _ in 0..=crate::blocking_guard::BLOCKING_BREAKER_TRIP_AFTER {
            assert_eq!(
                ask(&g, None).await,
                Facts::unanswered("session fact lookup failed")
            );
        }
    }

    #[test]
    fn the_first_ending_other_than_a_disconnect_stands() {
        let s = SessionRecord::for_test(1, None, None);
        assert_eq!(s.ending(), Ending::Disconnect);
        s.end(Ending::Disconnect);
        assert_eq!(s.ending(), Ending::Disconnect);
        s.end(Ending::Denied(DenyCause::NotMember));
        s.end(Ending::Idle);
        s.end(Ending::Disconnect);
        assert_eq!(s.ending(), Ending::Denied(DenyCause::NotMember));
    }

    #[test]
    fn a_session_expires_only_after_its_lifetime() {
        let mut s = SessionRecord::for_test(1, None, None).with_session_id(9);
        assert_eq!(s.session_id, 9);
        assert!(!s.expired());
        s.lifetime = Duration::ZERO;
        std::thread::sleep(Duration::from_millis(2));
        assert!(s.expired());
        s.lifetime = Duration::from_secs(3600);
        assert!(!s.expired());
    }

    #[test]
    fn the_allowing_facts_answer_a_live_member_whose_account_is_not_read() {
        let f = AllowFacts;
        let m = f.membership(Admission::MaknaeGroupMember, 7).unwrap();
        assert!(m.in_group);
        assert_eq!(m.user, "allow-7");
        assert_eq!(f.login(&PeerProcess::Gone, None, 7, None), LoginFact::Live);
        assert_eq!(
            f.account(7),
            AccountFact::NotChecked(crate::session_facts::NotCheckedWhy::Platform)
        );
    }
}
