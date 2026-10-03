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

static HOME_RESOLVE_CAPACITY: std::sync::OnceLock<std::sync::Arc<tokio::sync::Semaphore>> =
    std::sync::OnceLock::new();
const MAX_HOME_RESOLVERS: usize = 16;

pub(crate) fn home_resolve_capacity() -> std::sync::Arc<tokio::sync::Semaphore> {
    std::sync::Arc::clone(
        HOME_RESOLVE_CAPACITY
            .get_or_init(|| std::sync::Arc::new(tokio::sync::Semaphore::new(MAX_HOME_RESOLVERS))),
    )
}

pub(crate) async fn bounded_home<F>(
    dir: Option<std::path::PathBuf>,
    resolve: F,
    timeout: std::time::Duration,
    capacity: std::sync::Arc<tokio::sync::Semaphore>,
) -> Option<std::path::PathBuf>
where
    F: FnOnce(&std::path::Path) -> Option<std::path::PathBuf> + Send + 'static,
{
    let dir = dir?;
    let Ok(permit) = capacity.try_acquire_owned() else {
        eprintln!("maknaed: requester home resolution at capacity — admitting with no home");
        return None;
    };
    let worker = tokio::task::spawn_blocking(move || {
        let _permit = permit;
        resolve(&dir)
    });
    match tokio::time::timeout(timeout, worker).await {
        Ok(Ok(home)) => home,
        Ok(Err(_)) => None,
        Err(_) => {
            eprintln!(
                "maknaed: requester home resolution stalled past {timeout:?} — admitting with no home"
            );
            None
        }
    }
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

    fn slots(n: usize) -> std::sync::Arc<tokio::sync::Semaphore> {
        std::sync::Arc::new(tokio::sync::Semaphore::new(n))
    }

    #[tokio::test]
    async fn a_resolving_home_is_returned() {
        let got = bounded_home(
            Some("/home/b".into()),
            |d| Some(d.join("canon")),
            FAST,
            slots(1),
        )
        .await;
        assert_eq!(got, Some("/home/b/canon".into()));
    }

    #[tokio::test]
    async fn no_raw_home_resolves_nothing() {
        let ran = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let flag = std::sync::Arc::clone(&ran);
        let got = bounded_home(
            None,
            move |d| {
                flag.store(true, std::sync::atomic::Ordering::SeqCst);
                Some(d.into())
            },
            FAST,
            slots(1),
        )
        .await;
        assert_eq!(got, None);
        assert!(!ran.load(std::sync::atomic::Ordering::SeqCst));
    }

    #[tokio::test]
    async fn a_stalled_home_is_none_after_the_timeout() {
        let started = std::time::Instant::now();
        let got = bounded_home(
            Some("/home/b".into()),
            |d| {
                std::thread::sleep(FAST * 10);
                Some(d.into())
            },
            FAST,
            slots(1),
        )
        .await;
        assert_eq!(got, None);
        assert!(
            started.elapsed() < FAST * 10,
            "the caller waited for the stall"
        );
    }

    #[tokio::test]
    async fn a_panicking_resolver_is_none() {
        let got = bounded_home(Some("/home/b".into()), |_| panic!("x"), FAST, slots(1)).await;
        assert_eq!(got, None);
    }

    #[tokio::test]
    async fn a_stuck_worker_keeps_its_slot_until_it_finishes() {
        let cap = slots(1);
        let (release, held) = std::sync::mpsc::channel::<()>();
        let first = bounded_home(
            Some("/home/b".into()),
            move |d| {
                let _ = held.recv();
                Some(d.into())
            },
            FAST,
            std::sync::Arc::clone(&cap),
        )
        .await;
        assert_eq!(first, None);
        let ran = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let flag = std::sync::Arc::clone(&ran);
        let second = bounded_home(
            Some("/home/c".into()),
            move |d| {
                flag.store(true, std::sync::atomic::Ordering::SeqCst);
                Some(d.into())
            },
            FAST,
            std::sync::Arc::clone(&cap),
        )
        .await;
        assert_eq!(second, None);
        assert!(
            !ran.load(std::sync::atomic::Ordering::SeqCst),
            "no worker is spawned while the stuck one holds the slot"
        );
        release.send(()).unwrap();
        let _ = cap
            .acquire()
            .await
            .expect("the slot returns when the worker ends");
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
