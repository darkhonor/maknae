//! The daemon-side session record and the bounded gather of the facts it is
//! re-decided on (ADR-0006 decision 4, #115).
#[cfg(any(test, feature = "hermetic-test-seam"))]
use std::path::PathBuf;
use std::sync::{Arc, OnceLock};
use std::time::{Duration, Instant};

use maknae_audit_append::Seq;
use maknae_vault::SenderVerdict;

use crate::authz::Ending;
use crate::blocking_guard::{BlockingBreaker, BreakerAdmission, BreakerTransition};
use crate::deployment::Platform;
use crate::groupres::{AuthzError, Membership};
use crate::handler::Admission;
use crate::session_facts::{AccountFact, AccountState};

pub trait SessionFacts: Send + Sync {
    fn membership(&self, admission: Admission, uid: u32) -> Result<Membership, AuthzError>;
    fn account(&self, uid: u32) -> AccountFact;
}

/// The facts one decision is made on; `answered` is false when the gather as a
/// whole was refused, failed or timed out, so no one source is to blame.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Facts {
    pub membership: Result<Membership, AuthzError>,
    pub account: AccountFact,
    pub answered: bool,
}

impl Facts {
    fn unanswered(why: &str) -> Self {
        Facts {
            membership: Err(AuthzError::Resolve(why.to_string())),
            account: AccountFact::Checked(AccountState::Unknown(why.to_string())),
            answered: false,
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

    /// A member named `user` (or `allow-<uid>`) whose home is `dir` (or none that resolves).
    #[cfg(any(test, feature = "hermetic-test-seam"))]
    pub fn allow_as(user: Option<String>, dir: Option<PathBuf>) -> Arc<Self> {
        Self::for_test(Arc::new(AllowFacts { user, dir }), Duration::from_secs(5))
    }
}

/// A member whose account state this platform does not read.
#[cfg(any(test, feature = "hermetic-test-seam"))]
pub struct AllowFacts {
    pub user: Option<String>,
    pub dir: Option<PathBuf>,
}

#[cfg(any(test, feature = "hermetic-test-seam"))]
impl SessionFacts for AllowFacts {
    fn membership(&self, _admission: Admission, uid: u32) -> Result<Membership, AuthzError> {
        Ok(Membership {
            in_group: true,
            user: self.user.clone().unwrap_or_else(|| format!("allow-{uid}")),
            dir: self.dir.clone().unwrap_or_default(),
        })
    }

    fn account(&self, _uid: u32) -> AccountFact {
        AccountFact::NotChecked(crate::session_facts::NotCheckedWhy::Platform)
    }
}

/// Every lookup the decision needs, as one blocking unit under the gate's breaker
/// and bound.
pub(crate) async fn gather(gate: &FactsGate, admission: Admission, uid: u32) -> Facts {
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
                    let account = facts.account(uid);
                    Facts {
                        membership,
                        account,
                        answered: true,
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

/// The channel a session was admitted on; an agent's session ends with its leaf.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SessionChannel {
    Client,
    Agent {
        agent: maknae_config::AgentId,
        leaf_expires: Instant,
    },
}

impl SessionChannel {
    /// The channel a connection admitted under `admission` opens; a leaf already past its
    /// `not_after` opens none.
    pub fn of(
        admission: Admission,
        peer: &maknae_vault::ChannelPeer,
    ) -> Result<SessionChannel, Ending> {
        use maknae_vault::ChannelPeer;
        match (admission, peer) {
            (Admission::MaknaeGroupMember, ChannelPeer::Certless | ChannelPeer::Certified(_)) => {
                Ok(SessionChannel::Client)
            }
            (Admission::MaknaeGroupMember, ChannelPeer::Agent { .. }) => {
                Err(Ending::Denied(crate::authz::DenyCause::NotEnrolled))
            }
            (
                Admission::EnrolledAgent,
                ChannelPeer::Agent {
                    agent, not_after, ..
                },
            ) => not_after
                .duration_since(std::time::SystemTime::now())
                .ok()
                .filter(|left| !left.is_zero())
                .and_then(|left| Instant::now().checked_add(left))
                .map(|leaf_expires| SessionChannel::Agent {
                    agent: agent.clone(),
                    leaf_expires,
                })
                .ok_or(Ending::LeafExpired),
            (Admission::EnrolledAgent, ChannelPeer::Certless | ChannelPeer::Certified(_)) => {
                Err(Ending::Denied(crate::authz::DenyCause::NotEnrolled))
            }
        }
    }
}

/// One admitted client connection, held only daemon-side and dropped with it.
/// `user` is the name admitted at connect; every request decides on its own gather.
pub struct SessionRecord {
    pub uid: u32,
    pub user: Option<String>,
    pub session_id: u64,
    pub lane: maknae_security::Lane,
    pub admission: Admission,
    pub channel: SessionChannel,
    pub sender: SenderVerdict,
    pub account: AccountFact,
    pub seq: Seq,
    pub opened_at: Instant,
    pub lifetime: Duration,
    pub platform: Platform,
    pub(crate) ending: OnceLock<Ending>,
    /// The `task_id` and `tasker` of the task the session's request cited, once resolved.
    pub(crate) task: OnceLock<(String, String)>,
}

impl SessionRecord {
    /// Records why the session ended; the first ending other than `Disconnect` stands.
    pub fn end(&self, e: Ending) {
        match e {
            Ending::Disconnect => {}
            Ending::Idle | Ending::Lifetime | Ending::LeafExpired | Ending::Denied(_) => {
                let _ = self.ending.set(e);
            }
        }
    }

    pub fn ending(&self) -> Ending {
        self.ending.get().cloned().unwrap_or(Ending::Disconnect)
    }

    /// Why the session may serve no more: the visit clock or the leaf, whichever ran out first.
    pub fn expiry(&self) -> Option<Ending> {
        let now = Instant::now();
        let visit = self
            .opened_at
            .checked_add(self.lifetime)
            .filter(|end| now > *end)
            .map(|end| (end, Ending::Lifetime));
        let leaf = match &self.channel {
            SessionChannel::Client => None,
            SessionChannel::Agent { leaf_expires, .. } => {
                (now > *leaf_expires).then_some((*leaf_expires, Ending::LeafExpired))
            }
        };
        match (visit, leaf) {
            (Some((v, visit)), Some((l, leaf))) => Some(if l < v { leaf } else { visit }),
            (one, other) => one.or(other).map(|(_, ending)| ending),
        }
    }

    pub(crate) fn cite(&self, task: &crate::handler::TaskStamp) {
        let _ = self.task.set((task.id.to_string(), task.tasker.clone()));
    }

    /// Stamps the session's agent and, once resolved, its cited task on `rec`.
    pub(crate) fn stamp(&self, rec: &mut maknae_audit_append::AuditRecord) {
        if let Some(agent) = self.agent() {
            rec.subject.agent = Some(agent.as_str().to_string());
        }
        if let Some((id, tasker)) = self.task.get() {
            rec.subject.task_id = Some(id.clone());
            rec.subject.tasker = Some(tasker.clone());
        }
    }

    pub fn agent(&self) -> Option<&maknae_config::AgentId> {
        match &self.channel {
            SessionChannel::Client => None,
            SessionChannel::Agent { agent, .. } => Some(agent),
        }
    }

    #[cfg(any(test, feature = "hermetic-test-seam"))]
    pub fn for_test(uid: u32, user: Option<String>) -> Self {
        SessionRecord {
            uid,
            user,
            session_id: 1,
            lane: maknae_security::Lane::Local,
            admission: Admission::MaknaeGroupMember,
            channel: SessionChannel::Client,
            sender: SenderVerdict::default(),
            account: AccountFact::NotChecked(crate::session_facts::NotCheckedWhy::Platform),
            seq: Seq::new(),
            opened_at: Instant::now(),
            lifetime: Duration::MAX,
            platform: Platform::of_build(),
            ending: OnceLock::new(),
            task: OnceLock::new(),
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

    struct Probe {
        calls: AtomicUsize,
        delay: Duration,
        member: Result<Membership, AuthzError>,
    }

    impl Probe {
        fn new(delay: Duration, member: Result<Membership, AuthzError>) -> Arc<Self> {
            Arc::new(Probe {
                calls: AtomicUsize::new(0),
                delay,
                member,
            })
        }
    }

    impl SessionFacts for Probe {
        fn membership(&self, _admission: Admission, _uid: u32) -> Result<Membership, AuthzError> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            std::thread::sleep(self.delay);
            self.member.clone()
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

    async fn ask(gate: &FactsGate) -> Facts {
        gather(gate, Admission::MaknaeGroupMember, 4242).await
    }

    #[tokio::test]
    async fn the_answers_are_gathered_together() {
        let probe = Probe::new(Duration::ZERO, resolved("ann"));
        let got = ask(&gate(&probe, Duration::from_secs(5))).await;
        assert_eq!(
            got,
            Facts {
                membership: resolved("ann"),
                account: AccountFact::Checked(AccountState::Expired),
                answered: true,
            }
        );
    }

    #[tokio::test]
    async fn a_failed_membership_is_carried_as_it_failed() {
        let probe = Probe::new(Duration::ZERO, Err(AuthzError::Resolve("nss".into())));
        let got = ask(&gate(&probe, Duration::from_secs(5))).await;
        assert_eq!(got.membership, Err(AuthzError::Resolve("nss".into())));
    }

    #[tokio::test]
    async fn a_stalled_fact_source_trips_the_breaker() {
        let probe = Probe::new(Duration::from_millis(200), resolved("slow"));
        let g = gate(&probe, Duration::from_millis(20));
        for _ in 0..crate::blocking_guard::BLOCKING_BREAKER_TRIP_AFTER {
            let got = ask(&g).await;
            assert_eq!(got, Facts::unanswered("session fact lookup timed out"));
            assert_eq!(
                crate::authz::revalidate(Admission::MaknaeGroupMember, 4242, 4242, &got),
                crate::authz::Revalidation::Deny(DenyCause::Infrastructure(
                    crate::authz::FactSource::SessionFacts
                ))
            );
        }
        let spawned = probe.calls.load(Ordering::SeqCst);
        for _ in 0..2 {
            assert_eq!(
                ask(&g).await,
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
            ask(&g).await,
            Facts::unanswered("session fact lookup blocking worker budget exhausted")
        );
        assert_eq!(probe.calls.load(Ordering::SeqCst), 0);
    }

    struct Panics;
    impl SessionFacts for Panics {
        fn membership(&self, _admission: Admission, _uid: u32) -> Result<Membership, AuthzError> {
            panic!("lookup panicked")
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
                ask(&g).await,
                Facts::unanswered("session fact lookup failed")
            );
        }
    }

    #[test]
    fn the_first_ending_other_than_a_disconnect_stands() {
        let s = SessionRecord::for_test(1, None);
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
        let mut s = SessionRecord::for_test(1, None).with_session_id(9);
        assert_eq!(s.session_id, 9);
        assert_eq!(s.expiry(), None);
        s.lifetime = Duration::ZERO;
        std::thread::sleep(Duration::from_millis(2));
        assert_eq!(s.expiry(), Some(Ending::Lifetime));
        s.lifetime = Duration::from_secs(3600);
        assert_eq!(s.expiry(), None);
    }

    #[test]
    fn the_allowing_facts_answer_a_member_whose_account_is_not_read() {
        let named = AllowFacts {
            user: Some("ann".into()),
            dir: Some("/home/ann".into()),
        };
        let m = named.membership(Admission::MaknaeGroupMember, 7).unwrap();
        assert_eq!(
            (m.in_group, m.user.as_str(), m.dir),
            (true, "ann", PathBuf::from("/home/ann"))
        );
        let f = AllowFacts {
            user: None,
            dir: None,
        };
        let m = f.membership(Admission::MaknaeGroupMember, 7).unwrap();
        assert!(m.in_group);
        assert_eq!(m.user, "allow-7");
        assert_eq!(m.dir, PathBuf::new());
        assert_eq!(
            f.account(7),
            AccountFact::NotChecked(crate::session_facts::NotCheckedWhy::Platform)
        );
    }
}
