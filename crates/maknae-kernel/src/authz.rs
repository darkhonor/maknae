//! Connection-admission decision (spec §5). Pure; T1/0-missed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConnDecision {
    Permit,
    Deny { reason: String },
}

pub fn authorize_connection(cert_verified: bool, uid_in_group: bool) -> ConnDecision {
    match (cert_verified, uid_in_group) {
        (true, true) => ConnDecision::Permit,
        (false, _) => ConnDecision::Deny {
            reason: "plane cert not verified".into(),
        },
        (true, false) => ConnDecision::Deny {
            reason: "peer uid not in `maknae` group".into(),
        },
    }
}

pub fn admission_facts(
    looked_up: Option<crate::groupres::Membership>,
) -> (bool, Option<String>, Option<std::path::PathBuf>) {
    match looked_up {
        Some(m) => (m.in_group, Some(m.user), m.in_group.then_some(m.dir)),
        None => (false, None, None),
    }
}

pub(crate) const HOME_RESOLVE_TIMEOUT: std::time::Duration =
    crate::blocking_guard::BLOCKING_OPERATION_TIMEOUT;
const MAX_HOME_RESOLVERS: usize = 16;
const HOME_UNAVAILABLE: &str = "requester home unavailable";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HomeUnavailable {
    Unresolvable,
    TimedOut,
    AtCapacity,
}

impl HomeUnavailable {
    pub fn cause(self) -> &'static str {
        match self {
            HomeUnavailable::Unresolvable => "unresolvable",
            HomeUnavailable::TimedOut => "timed out",
            HomeUnavailable::AtCapacity => "at capacity",
        }
    }

    pub fn reason(self) -> String {
        format!("{HOME_UNAVAILABLE}: {}", self.cause())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Miss {
    Unresolvable,
    TimedOut,
    Busy(crate::uid_gate::Busy),
}

impl Miss {
    fn cause(self) -> HomeUnavailable {
        match self {
            Miss::Unresolvable => HomeUnavailable::Unresolvable,
            Miss::TimedOut => HomeUnavailable::TimedOut,
            Miss::Busy(_) => HomeUnavailable::AtCapacity,
        }
    }
}

#[derive(Default)]
struct HomeHealth(std::sync::Mutex<Option<HomeUnavailable>>);

impl HomeHealth {
    fn observe(&self, outcome: &Result<std::path::PathBuf, Miss>) -> Option<String> {
        let now = match outcome {
            Ok(_) => None,
            Err(Miss::Unresolvable | Miss::Busy(crate::uid_gate::Busy::Requester)) => return None,
            Err(miss) => Some(miss.cause()),
        };
        let before = std::mem::replace(
            &mut *self
                .0
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner),
            now,
        );
        if before == now {
            return None;
        }
        Some(match now {
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
    timeout: std::time::Duration,
    capacity: std::sync::Arc<tokio::sync::Semaphore>,
    gate: crate::uid_gate::UidGate,
    health: HomeHealth,
}

impl HomeResolver {
    pub(crate) fn new(timeout: std::time::Duration, slots: usize) -> Self {
        HomeResolver {
            timeout,
            capacity: std::sync::Arc::new(tokio::sync::Semaphore::new(slots)),
            gate: crate::uid_gate::UidGate::default(),
            health: HomeHealth::default(),
        }
    }

    pub(crate) async fn resolve<F>(
        &self,
        uid: u32,
        dir: Option<std::path::PathBuf>,
        resolve: F,
    ) -> Result<std::path::PathBuf, HomeUnavailable>
    where
        F: FnOnce(&std::path::Path) -> Option<std::path::PathBuf> + Send + 'static,
    {
        let outcome = self.attempt(uid, dir, resolve).await;
        if let Some(line) = self.health.observe(&outcome) {
            eprintln!("{line}");
        }
        outcome.map_err(Miss::cause)
    }

    async fn attempt<F>(
        &self,
        uid: u32,
        dir: Option<std::path::PathBuf>,
        resolve: F,
    ) -> Result<std::path::PathBuf, Miss>
    where
        F: FnOnce(&std::path::Path) -> Option<std::path::PathBuf> + Send + 'static,
    {
        let dir = dir.ok_or(Miss::Unresolvable)?;
        let slot = self
            .gate
            .try_admit(uid, &self.capacity)
            .map_err(Miss::Busy)?;
        let worker = tokio::task::spawn_blocking(move || {
            let _slot = slot;
            resolve(&dir)
        });
        match tokio::time::timeout(self.timeout, worker).await {
            Ok(Ok(Some(home))) => Ok(home),
            Ok(_) => Err(Miss::Unresolvable),
            Err(_) => Err(Miss::TimedOut),
        }
    }
}

static HOME_RESOLVER: std::sync::OnceLock<HomeResolver> = std::sync::OnceLock::new();

pub(crate) async fn admitted_home(
    uid: u32,
    dir: Option<std::path::PathBuf>,
) -> Result<std::path::PathBuf, HomeUnavailable> {
    HOME_RESOLVER
        .get_or_init(|| HomeResolver::new(HOME_RESOLVE_TIMEOUT, MAX_HOME_RESOLVERS))
        .resolve(uid, dir, crate::groupres::canonical_home)
        .await
}

#[cfg(test)]
mod tests {
    use super::*;

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
            admission_facts(Some(membership(true, "b-435-sentinel"))),
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
            admission_facts(Some(membership(false, "c-435-sentinel"))),
            (false, Some("c-435-sentinel".to_string()), None)
        );
    }

    #[test]
    fn a_failed_lookup_admits_no_one_and_carries_no_home() {
        assert_eq!(admission_facts(None), (false, None, None));
    }

    const FAST: std::time::Duration = std::time::Duration::from_millis(20);
    const PATIENCE: std::time::Duration = std::time::Duration::from_secs(10);

    fn resolver(slots: usize) -> HomeResolver {
        HomeResolver::new(FAST, slots)
    }

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
            HomeUnavailable::AtCapacity.reason(),
            "requester home unavailable: at capacity"
        );
    }

    #[tokio::test]
    async fn a_resolving_home_is_returned() {
        let got = resolver(1)
            .resolve(1, Some("/home/b".into()), |d| Some(d.join("canon")))
            .await;
        assert_eq!(got, Ok(std::path::PathBuf::from("/home/b/canon")));
    }

    #[tokio::test]
    async fn no_raw_home_is_unresolvable_and_resolves_nothing() {
        let (ran, f) = never_runs();
        let got = resolver(1).resolve(1, None, f).await;
        assert_eq!(got, Err(HomeUnavailable::Unresolvable));
        assert!(!ran.load(std::sync::atomic::Ordering::SeqCst));
    }

    #[tokio::test]
    async fn a_home_that_does_not_resolve_is_unresolvable() {
        let got = resolver(1)
            .resolve(1, Some("/home/b".into()), |_| None)
            .await;
        assert_eq!(got, Err(HomeUnavailable::Unresolvable));
    }

    #[tokio::test]
    async fn a_panicking_resolver_is_unresolvable() {
        let got = resolver(1)
            .resolve(1, Some("/home/b".into()), |_| panic!("x"))
            .await;
        assert_eq!(got, Err(HomeUnavailable::Unresolvable));
    }

    #[tokio::test]
    async fn a_stalled_home_times_out_while_its_worker_still_blocks() {
        let r = resolver(1);
        let (release, held) = std::sync::mpsc::channel::<()>();
        let got = tokio::time::timeout(
            PATIENCE,
            r.resolve(1, Some("/home/b".into()), held_until(held)),
        )
        .await
        .expect("the caller is not held by the stalled worker");
        assert_eq!(got, Err(HomeUnavailable::TimedOut));
        release.send(()).expect("the worker was still blocked");
    }

    #[tokio::test]
    async fn a_stuck_uid_blocks_only_itself() {
        let r = resolver(4);
        let (release, held) = std::sync::mpsc::channel::<()>();
        let first = r.resolve(1, Some("/home/a".into()), held_until(held)).await;
        assert_eq!(first, Err(HomeUnavailable::TimedOut));
        assert_eq!(r.capacity.available_permits(), 3);

        let (ran, f) = never_runs();
        let again = r.resolve(1, Some("/home/a".into()), f).await;
        assert_eq!(again, Err(HomeUnavailable::AtCapacity));
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
            .resolve(2, Some("/home/b".into()), |d| Some(d.into()))
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
        let r = resolver(2);
        let (release_a, held_a) = std::sync::mpsc::channel::<()>();
        let (release_b, held_b) = std::sync::mpsc::channel::<()>();
        assert_eq!(
            r.resolve(1, Some("/home/a".into()), held_until(held_a))
                .await,
            Err(HomeUnavailable::TimedOut)
        );
        assert_eq!(
            r.resolve(2, Some("/home/b".into()), held_until(held_b))
                .await,
            Err(HomeUnavailable::TimedOut)
        );
        let (ran, f) = never_runs();
        assert_eq!(
            r.resolve(3, Some("/home/c".into()), f).await,
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
    fn stall_and_capacity_log_on_transition_only() {
        use crate::uid_gate::Busy;
        let h = HomeHealth::default();
        let ok: Result<std::path::PathBuf, Miss> = Ok("/home/b".into());
        let err = |e| Err::<std::path::PathBuf, _>(e);
        assert_eq!(h.observe(&ok), None);
        let stalled = h.observe(&err(Miss::TimedOut)).expect("logged");
        assert!(
            stalled.contains("requester home unavailable: timed out"),
            "{stalled}"
        );
        assert_eq!(h.observe(&err(Miss::TimedOut)), None);
        let full = h.observe(&err(Miss::Busy(Busy::Global))).expect("logged");
        assert!(full.contains("at capacity"), "{full}");
        assert_eq!(h.observe(&err(Miss::Unresolvable)), None);
        assert_eq!(h.observe(&err(Miss::Busy(Busy::Global))), None);
        let back = h.observe(&ok).expect("logged");
        assert!(back.contains("recovered"), "{back}");
        assert_eq!(h.observe(&ok), None);
        assert_eq!(h.observe(&err(Miss::Unresolvable)), None);
        assert_eq!(
            h.observe(&err(Miss::Busy(Busy::Requester))),
            None,
            "one uid's own concurrency is not a daemon-wide state"
        );
        assert_eq!(h.observe(&ok), None, "and it changed no state");
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

    #[test]
    fn permit_only_when_both() {
        assert!(matches!(
            authorize_connection(true, true),
            ConnDecision::Permit
        ));
    }
    #[test]
    fn deny_when_not_in_group() {
        assert_eq!(
            authorize_connection(true, false),
            ConnDecision::Deny {
                reason: "peer uid not in `maknae` group".into()
            }
        );
    }
    #[test]
    fn deny_when_cert_unverified() {
        assert_eq!(
            authorize_connection(false, true),
            ConnDecision::Deny {
                reason: "plane cert not verified".into()
            }
        );
    }
    #[test]
    fn deny_when_neither() {
        assert_eq!(
            authorize_connection(false, false),
            ConnDecision::Deny {
                reason: "plane cert not verified".into()
            }
        );
    }
}
