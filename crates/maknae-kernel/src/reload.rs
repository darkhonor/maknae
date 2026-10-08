//! The policy reload's ordering: intent, load and compile, persist, install,
//! outcome. The store publish's rename is the point of no return: once it lands the
//! candidate is installed whatever the directory sync or the checkpoint append does.

use maknae_graph::identity::IdentityLayer;
use std::fmt;
use std::future::Future;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Plan {
    Unchanged,
    Persist { revision: u64 },
}

/// Persist iff the file's identity layer differs from the persisted one; the next
/// revision is `store_revision + 1`.
pub fn plan(persisted: &IdentityLayer, next: &IdentityLayer, store_revision: u64) -> Plan {
    if sorted(persisted) == sorted(next) {
        Plan::Unchanged
    } else {
        Plan::Persist {
            revision: store_revision.saturating_add(1),
        }
    }
}

/// The [`plan`] and the identity graph it calls for: `current` itself when
/// unchanged, else what `build` makes at the plan's revision.
pub fn plan_candidate<G: Clone, E>(
    persisted: &IdentityLayer,
    next: &IdentityLayer,
    store_revision: u64,
    current: &G,
    build: impl FnOnce(u64) -> Result<G, E>,
) -> Result<(Plan, G), E> {
    let plan = plan(persisted, next, store_revision);
    let graph = match plan {
        Plan::Unchanged => current.clone(),
        Plan::Persist { revision } => build(revision)?,
    };
    Ok((plan, graph))
}

/// The layer a reload persists, with every persisted containment whose name no longer
/// resolves carried forward, and the containments it ends; refused if it would drop
/// explicit bindings root has not written into `bindings.yaml`.
pub fn next_layer(
    file: &IdentityLayer,
    unresolved_adversaries: &[String],
    persisted: &IdentityLayer,
    file_missing: bool,
    file_lists_nobody: bool,
) -> Result<(IdentityLayer, Vec<maknae_graph::identity::Released>), Refusal> {
    if let Some(m) = maknae_graph::identity::drops_explicit_bindings(persisted, file, file_missing)
    {
        return Err(Refusal::Load(m.into()));
    }
    let next = maknae_graph::identity::carry_forward(file, unresolved_adversaries, persisted).0;
    let released = maknae_graph::identity::released(persisted, &next, file_lists_nobody);
    Ok((next, released))
}

/// One reload's turn: refused once shutdown has begun, otherwise run from the
/// shared store revision, which advances only on `Ok`.
pub async fn turn<F, Fut>(
    stopping: bool,
    revision: &AtomicU64,
    reload: F,
) -> Result<Applied, Refusal>
where
    F: FnOnce(u64) -> Fut,
    Fut: Future<Output = Result<Applied, Refusal>>,
{
    if stopping {
        return Err(Refusal::Shutdown);
    }
    let r = reload(revision.load(Ordering::Acquire)).await;
    if let Ok(applied) = &r {
        revision.store(applied.revision, Ordering::Release);
    }
    r
}

#[derive(Debug, PartialEq, Eq)]
pub enum Stop<T> {
    Repeated,
    /// Holds the turn: abort the reload task before releasing it.
    Abort(T),
    LeaveRunning,
}

/// Only the first stop waits, and for at most `limit`, on the reload turn.
pub async fn stop<T>(
    already_stopping: bool,
    turn: impl Future<Output = T>,
    limit: Duration,
) -> Stop<T> {
    if already_stopping {
        return Stop::Repeated;
    }
    match tokio::time::timeout(limit, turn).await {
        Ok(held) => Stop::Abort(held),
        Err(_) => Stop::LeaveRunning,
    }
}

fn sorted(layer: &IdentityLayer) -> IdentityLayer {
    let mut l = layer.clone();
    l.subjects.sort_by_key(|s| s.uid);
    l
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Refusal {
    Audit(String),
    Load(String),
    Compile(String),
    Persist(String),
    Shutdown,
}

impl fmt::Display for Refusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Audit(m) => write!(f, "audit append failed: {m}"),
            Self::Load(m) => write!(f, "policy load: {m}"),
            Self::Compile(m) => write!(f, "compile: {m}"),
            Self::Persist(m) => write!(f, "persist: {m}"),
            Self::Shutdown => f.write_str("shutdown"),
        }
    }
}

/// A publish that took place; either failure after it is reported, never refused.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Committed {
    pub revision: u64,
    pub durability_error: Option<String>,
    pub checkpoint_error: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Applied {
    pub revision: u64,
    pub persisted: bool,
    pub durability_error: Option<String>,
    pub checkpoint_error: Option<String>,
}

/// The outcome record's `(result, reason, posture)`.
pub fn outcome(r: &Result<Applied, Refusal>) -> (&'static str, String, &'static str) {
    match r {
        Ok(a) => {
            let identity = if a.persisted {
                "persisted"
            } else {
                "unchanged"
            };
            let mut reason = format!(
                "reload applied: revision {}; identity {identity}",
                a.revision
            );
            if let Some(e) = &a.durability_error {
                reason.push_str(&format!("; store not durable: {e}"));
            }
            if let Some(e) = &a.checkpoint_error {
                reason.push_str(&format!("; checkpoint append failed: {e}"));
            }
            ("permit", reason, "authorized")
        }
        Err(refusal) => ("deny", format!("reload refused: {refusal}"), "unavailable"),
    }
}

pub trait Load {
    type Candidate;
    /// Load, validate and compile; a `Persist` plan's candidate carries the
    /// identity graph at that plan's revision.
    fn load(
        &self,
        store_revision: u64,
    ) -> impl Future<Output = Result<(Plan, Self::Candidate), Refusal>> + Send;
}

pub trait Store {
    type Candidate;
    fn commit(
        &self,
        candidate: &Self::Candidate,
    ) -> impl Future<Output = Result<Committed, Refusal>> + Send;
}

pub trait Swap {
    type Candidate;
    fn install(&self, candidate: Self::Candidate);
}

pub trait Audit {
    fn intent(&self, store_revision: u64) -> impl Future<Output = Result<(), Refusal>> + Send;
    fn outcome(&self, r: &Result<Applied, Refusal>) -> impl Future<Output = ()> + Send;
}

/// A failed intent append ends the reload with nothing loaded and no outcome
/// record; every later refusal is recorded as the outcome. `stopped` abandons the
/// load, never a commit already started.
pub async fn run_reload<C, L, S, W, A>(
    store_revision: u64,
    load: &L,
    store: &S,
    swap: &W,
    audit: &A,
    stopped: impl Future<Output = ()>,
) -> Result<Applied, Refusal>
where
    L: Load<Candidate = C>,
    S: Store<Candidate = C>,
    W: Swap<Candidate = C>,
    A: Audit,
{
    audit.intent(store_revision).await?;
    let applied = apply(store_revision, load, store, swap, stopped).await;
    audit.outcome(&applied).await;
    applied
}

async fn apply<C, L, S, W>(
    store_revision: u64,
    load: &L,
    store: &S,
    swap: &W,
    stopped: impl Future<Output = ()>,
) -> Result<Applied, Refusal>
where
    L: Load<Candidate = C>,
    S: Store<Candidate = C>,
    W: Swap<Candidate = C>,
{
    let (plan, candidate) = tokio::select! {
        biased;
        () = stopped => return Err(Refusal::Shutdown),
        loaded = load.load(store_revision) => loaded?,
    };
    let applied = match plan {
        Plan::Unchanged => Applied {
            revision: store_revision,
            persisted: false,
            durability_error: None,
            checkpoint_error: None,
        },
        Plan::Persist { .. } => {
            let c = store.commit(&candidate).await?;
            Applied {
                revision: c.revision,
                persisted: true,
                durability_error: c.durability_error,
                checkpoint_error: c.checkpoint_error,
            }
        }
    };
    swap.install(candidate);
    Ok(applied)
}

#[cfg(test)]
mod tests {
    use super::*;
    use maknae_graph::identity::SubjectEntry;
    use std::sync::Mutex;

    fn layer(subjects: &[(u32, &str)]) -> IdentityLayer {
        IdentityLayer {
            aliases: Default::default(),
            source: "/etc/maknae/authz.yaml".into(),
            label: "UNCLASSIFIED".into(),
            bindings_sha256: Some([7; 32]),
            subjects: subjects
                .iter()
                .map(|(uid, role)| SubjectEntry {
                    uid: *uid,
                    name: format!("u{uid}"),
                    role: (*role).into(),
                })
                .collect(),
        }
    }

    #[test]
    fn the_next_layer_guards_carries_and_reports_releases() {
        use maknae_graph::identity::{
            ReleaseCause, Released, SubjectEntry, BINDINGS_MISSING, BINDINGS_NOT_MOVED,
        };
        let mallory = SubjectEntry {
            uid: 666,
            name: "mallory".into(),
            role: "adversary".into(),
        };
        let persisted = IdentityLayer {
            aliases: Default::default(),
            source: "/etc/maknae/bindings.yaml".into(),
            label: "U".into(),
            bindings_sha256: Some([1; 32]),
            subjects: vec![mallory.clone()],
        };
        let file = IdentityLayer {
            subjects: vec![],
            bindings_sha256: Some([2; 32]),
            ..persisted.clone()
        };
        assert_eq!(
            next_layer(&file, &[], &persisted, true, false),
            Err(Refusal::Load(BINDINGS_MISSING.into()))
        );
        let moved = IdentityLayer {
            source: "/etc/maknae/authz.yaml".into(),
            ..persisted.clone()
        };
        let keyless = IdentityLayer {
            bindings_sha256: None,
            ..file.clone()
        };
        assert_eq!(
            next_layer(&keyless, &[], &moved, false, false),
            Err(Refusal::Load(BINDINGS_NOT_MOVED.into()))
        );
        let (carried, released) =
            next_layer(&file, &["mallory".into()], &persisted, false, false).unwrap();
        assert_eq!(
            (carried.subjects, released.len()),
            (persisted.subjects.clone(), 0)
        );
        let (plain, released) = next_layer(&file, &[], &persisted, false, true).unwrap();
        assert_eq!(plain, file);
        assert_eq!(
            released,
            [Released {
                uid: 666,
                name: "mallory".into(),
                cause: ReleaseCause::BindingsEmpty
            }]
        );
        let (_, released) = next_layer(&keyless, &[], &persisted, false, false).unwrap();
        assert_eq!(released[0].cause, ReleaseCause::BindingsAbsent);
        let (_, released) = next_layer(&file, &[], &persisted, false, false).unwrap();
        assert_eq!(
            released[0].cause,
            ReleaseCause::NotListed,
            "a file whose names did not resolve still lists them"
        );
        let (same, released) = next_layer(&persisted, &[], &persisted, false, false).unwrap();
        assert_eq!((same, released), (persisted.clone(), vec![]));
    }

    #[test]
    fn the_same_layer_in_any_subject_order_is_unchanged() {
        let a = layer(&[(0, "admin"), (7, "user")]);
        let b = layer(&[(7, "user"), (0, "admin")]);
        assert_eq!(plan(&a, &b, 4), Plan::Unchanged);
    }

    #[test]
    fn different_subjects_persist_at_the_next_store_revision() {
        let a = layer(&[(0, "admin")]);
        let b = layer(&[(0, "adversary")]);
        assert_eq!(plan(&a, &b, 4), Plan::Persist { revision: 5 });
    }

    #[test]
    fn a_different_bindings_hash_persists() {
        let a = layer(&[(0, "admin")]);
        let mut b = a.clone();
        b.bindings_sha256 = None;
        assert_eq!(plan(&a, &b, 9), Plan::Persist { revision: 10 });
    }

    #[test]
    fn a_different_source_persists() {
        let a = layer(&[]);
        let mut b = a.clone();
        b.source = "/opt/maknae/authz.yaml".into();
        assert_eq!(plan(&a, &b, 1), Plan::Persist { revision: 2 });
    }

    #[test]
    fn an_exhausted_revision_plans_a_revision_the_store_refuses() {
        let a = layer(&[]);
        let b = layer(&[(0, "admin")]);
        assert_eq!(plan(&a, &b, u64::MAX), Plan::Persist { revision: u64::MAX });
    }

    #[test]
    fn an_unchanged_plan_reuses_the_current_graph_and_builds_nothing() {
        let a = layer(&[(0, "admin")]);
        let r: Result<_, ()> = plan_candidate(&a, &a.clone(), 4, &"current", |_| {
            panic!("an unchanged layer builds nothing")
        });
        assert_eq!(r, Ok((Plan::Unchanged, "current")));
    }

    #[test]
    fn a_changed_layer_builds_at_the_planned_revision_or_refuses() {
        let a = layer(&[(0, "admin")]);
        let b = layer(&[(0, "adversary")]);
        let built: Result<_, ()> = plan_candidate(&a, &b, 4, &0, |revision| Ok(revision * 10));
        assert_eq!(built, Ok((Plan::Persist { revision: 5 }, 50)));
        assert_eq!(
            plan_candidate(&a, &b, 4, &0, |_| Err::<u64, _>("build refused")),
            Err("build refused")
        );
    }

    fn applied(revision: u64) -> Result<Applied, Refusal> {
        Ok(Applied {
            revision,
            persisted: true,
            durability_error: None,
            checkpoint_error: None,
        })
    }

    fn committed(revision: u64, durability: Option<&str>, checkpoint: Option<&str>) -> Committed {
        Committed {
            revision,
            durability_error: durability.map(str::to_string),
            checkpoint_error: checkpoint.map(str::to_string),
        }
    }

    #[tokio::test]
    async fn a_turn_after_shutdown_began_is_refused_without_running() {
        let revision = AtomicU64::new(3);
        let r = turn(true, &revision, |_| async { panic!("must not run") }).await;
        assert_eq!(r, Err(Refusal::Shutdown));
        assert_eq!(revision.load(Ordering::Acquire), 3);
    }

    #[tokio::test]
    async fn a_turn_runs_from_the_shared_revision_and_advances_it_only_on_ok() {
        let revision = AtomicU64::new(3);
        let r = turn(false, &revision, |from| async move { applied(from + 4) }).await;
        assert_eq!(r, applied(7));
        assert_eq!(revision.load(Ordering::Acquire), 7);
        let refused = turn(false, &revision, |_| async {
            Err(Refusal::Persist("stale".into()))
        })
        .await;
        assert_eq!(refused, Err(Refusal::Persist("stale".into())));
        assert_eq!(revision.load(Ordering::Acquire), 7);
    }

    #[tokio::test]
    async fn only_the_first_stop_waits_and_it_aborts_once_it_holds_the_turn() {
        let limit = Duration::from_secs(5);
        assert_eq!(
            stop(
                true,
                async { panic!("a repeated stop waits on nothing") },
                limit
            )
            .await,
            Stop::<()>::Repeated
        );
        assert_eq!(
            stop(false, async { "turn" }, limit).await,
            Stop::Abort("turn")
        );
    }

    #[tokio::test(start_paused = true)]
    async fn a_turn_not_released_within_the_limit_is_left_running() {
        assert_eq!(
            stop(false, std::future::pending::<()>(), Duration::from_secs(5)).await,
            Stop::LeaveRunning
        );
    }

    #[test]
    fn outcome_strings_are_pinned() {
        let ok_with = |persisted, durability: Option<&str>, checkpoint: Option<&str>| {
            Ok(Applied {
                revision: 6,
                persisted,
                durability_error: durability.map(str::to_string),
                checkpoint_error: checkpoint.map(str::to_string),
            })
        };
        let ok = |persisted, checkpoint: Option<&str>| ok_with(persisted, None, checkpoint);
        assert_eq!(
            outcome(&ok(true, None)),
            (
                "permit",
                "reload applied: revision 6; identity persisted".to_string(),
                "authorized"
            )
        );
        assert_eq!(
            outcome(&ok(false, None)),
            (
                "permit",
                "reload applied: revision 6; identity unchanged".to_string(),
                "authorized"
            )
        );
        assert_eq!(
            outcome(&ok(true, Some("disk full"))),
            (
                "permit",
                "reload applied: revision 6; identity persisted; checkpoint append failed: disk full"
                    .to_string(),
                "authorized"
            )
        );
        assert_eq!(
            outcome(&ok_with(true, Some("dir sync failed"), None)),
            (
                "permit",
                "reload applied: revision 6; identity persisted; store not durable: dir sync failed"
                    .to_string(),
                "authorized"
            )
        );
        assert_eq!(
            outcome(&ok_with(true, Some("dir sync failed"), Some("disk full"))),
            (
                "permit",
                "reload applied: revision 6; identity persisted; store not durable: dir sync failed; checkpoint append failed: disk full"
                    .to_string(),
                "authorized"
            )
        );
        for (refusal, reason) in [
            (
                Refusal::Audit("x".into()),
                "reload refused: audit append failed: x",
            ),
            (Refusal::Load("x".into()), "reload refused: policy load: x"),
            (Refusal::Compile("x".into()), "reload refused: compile: x"),
            (Refusal::Persist("x".into()), "reload refused: persist: x"),
            (Refusal::Shutdown, "reload refused: shutdown"),
        ] {
            assert_eq!(
                outcome(&Err(refusal)),
                ("deny", reason.to_string(), "unavailable")
            );
        }
    }

    #[derive(Default)]
    struct Fake {
        calls: Mutex<Vec<String>>,
        fail_intent: bool,
        load_hangs: bool,
        load: Option<Result<Plan, Refusal>>,
        commit: Option<Result<Committed, Refusal>>,
        installed: Mutex<Vec<u64>>,
        outcomes: Mutex<Vec<Result<Applied, Refusal>>>,
    }

    impl Fake {
        fn log(&self, s: String) {
            self.calls.lock().unwrap().push(s);
        }

        fn calls(&self) -> Vec<String> {
            self.calls.lock().unwrap().clone()
        }
    }

    impl Load for Fake {
        type Candidate = u64;
        fn load(
            &self,
            store_revision: u64,
        ) -> impl Future<Output = Result<(Plan, u64), Refusal>> + Send {
            self.log(format!("load {store_revision}"));
            let r = self.load.clone().unwrap_or(Ok(Plan::Persist {
                revision: store_revision + 1,
            }));
            let hangs = self.load_hangs;
            async move {
                if hangs {
                    std::future::pending::<()>().await;
                }
                r.map(|p| match p {
                    Plan::Persist { revision } => (p, revision),
                    Plan::Unchanged => (p, store_revision),
                })
            }
        }
    }

    impl Store for Fake {
        type Candidate = u64;
        fn commit(&self, c: &u64) -> impl Future<Output = Result<Committed, Refusal>> + Send {
            self.log(format!("commit {c}"));
            let r = self.commit.clone().unwrap_or(Ok(committed(*c, None, None)));
            async move { r }
        }
    }

    impl Swap for Fake {
        type Candidate = u64;
        fn install(&self, c: u64) {
            self.log(format!("install {c}"));
            self.installed.lock().unwrap().push(c);
        }
    }

    impl Audit for Fake {
        fn intent(&self, store_revision: u64) -> impl Future<Output = Result<(), Refusal>> + Send {
            self.log(format!("intent {store_revision}"));
            let r = if self.fail_intent {
                Err(Refusal::Audit("sink closed".into()))
            } else {
                Ok(())
            };
            async move { r }
        }

        fn outcome(&self, r: &Result<Applied, Refusal>) -> impl Future<Output = ()> + Send {
            self.log("outcome".into());
            self.outcomes.lock().unwrap().push(r.clone());
            async {}
        }
    }

    async fn run(f: &Fake, store_revision: u64) -> Result<Applied, Refusal> {
        run_reload(store_revision, f, f, f, f, std::future::pending()).await
    }

    #[tokio::test]
    async fn a_load_still_running_at_shutdown_is_abandoned_and_recorded() {
        let f = Fake {
            load_hangs: true,
            ..Fake::default()
        };
        let r = tokio::time::timeout(
            std::time::Duration::from_secs(5),
            run_reload(3, &f, &f, &f, &f, async {}),
        )
        .await
        .expect("shutdown abandons the load");
        assert_eq!(r, Err(Refusal::Shutdown));
        assert_eq!(f.calls(), ["intent 3", "load 3", "outcome"]);
        assert!(f.installed.lock().unwrap().is_empty());
        assert_eq!(*f.outcomes.lock().unwrap(), [Err(Refusal::Shutdown)]);
    }

    #[tokio::test]
    async fn run_reload_order_is_intent_load_commit_install_outcome() {
        let f = Fake::default();
        let r = run(&f, 3).await;
        assert_eq!(
            f.calls(),
            ["intent 3", "load 3", "commit 4", "install 4", "outcome"]
        );
        let applied = Applied {
            revision: 4,
            persisted: true,
            durability_error: None,
            checkpoint_error: None,
        };
        assert_eq!(r, Ok(applied.clone()));
        assert_eq!(*f.outcomes.lock().unwrap(), [Ok(applied)]);
    }

    #[tokio::test]
    async fn a_failed_intent_loads_nothing() {
        let f = Fake {
            fail_intent: true,
            ..Fake::default()
        };
        assert_eq!(run(&f, 3).await, Err(Refusal::Audit("sink closed".into())));
        assert_eq!(f.calls(), ["intent 3"]);
    }

    #[tokio::test]
    async fn a_failed_load_commits_nothing_installs_nothing_and_records_refused() {
        let f = Fake {
            load: Some(Err(Refusal::Load("bad yaml".into()))),
            ..Fake::default()
        };
        let r = run(&f, 3).await;
        assert_eq!(r, Err(Refusal::Load("bad yaml".into())));
        assert_eq!(f.calls(), ["intent 3", "load 3", "outcome"]);
        assert_eq!(*f.outcomes.lock().unwrap(), [r]);
    }

    #[tokio::test]
    async fn a_failed_commit_installs_nothing() {
        let f = Fake {
            commit: Some(Err(Refusal::Persist("stale".into()))),
            ..Fake::default()
        };
        let r = run(&f, 3).await;
        assert_eq!(r, Err(Refusal::Persist("stale".into())));
        assert_eq!(f.calls(), ["intent 3", "load 3", "commit 4", "outcome"]);
        assert!(f.installed.lock().unwrap().is_empty());
        assert_eq!(*f.outcomes.lock().unwrap(), [r]);
    }

    #[tokio::test]
    async fn a_failed_checkpoint_after_publish_still_installs_and_reports_it() {
        let f = Fake {
            commit: Some(Ok(committed(4, None, Some("disk full")))),
            ..Fake::default()
        };
        let r = run(&f, 3).await;
        assert_eq!(
            r,
            Ok(Applied {
                revision: 4,
                persisted: true,
                durability_error: None,
                checkpoint_error: Some("disk full".into()),
            })
        );
        assert_eq!(*f.installed.lock().unwrap(), [4]);
        assert_eq!(f.calls().last().map(String::as_str), Some("outcome"));
    }

    #[tokio::test]
    async fn a_publish_that_is_not_durable_still_installs_and_reports_it() {
        let f = Fake {
            commit: Some(Ok(committed(4, Some("dir sync failed"), None))),
            ..Fake::default()
        };
        let r = run(&f, 3).await;
        let applied = Applied {
            revision: 4,
            persisted: true,
            durability_error: Some("dir sync failed".into()),
            checkpoint_error: None,
        };
        assert_eq!(r, Ok(applied.clone()));
        assert_eq!(*f.installed.lock().unwrap(), [4]);
        assert_eq!(*f.outcomes.lock().unwrap(), [Ok(applied)]);
        let revision = AtomicU64::new(3);
        turn(false, &revision, |_| async { r.clone() })
            .await
            .unwrap();
        assert_eq!(revision.load(Ordering::Acquire), 4);
    }

    #[tokio::test]
    async fn unchanged_plan_skips_commit_and_installs_the_recompiled_snapshot() {
        let f = Fake {
            load: Some(Ok(Plan::Unchanged)),
            ..Fake::default()
        };
        let r = run(&f, 3).await;
        assert_eq!(f.calls(), ["intent 3", "load 3", "install 3", "outcome"]);
        assert_eq!(
            r,
            Ok(Applied {
                revision: 3,
                persisted: false,
                durability_error: None,
                checkpoint_error: None,
            })
        );
    }

    #[tokio::test]
    async fn the_applied_revision_is_the_commits_not_the_candidates() {
        let f = Fake {
            commit: Some(Ok(committed(8, None, Some("checkpoint refused")))),
            ..Fake::default()
        };
        let first = run(&f, 3).await.unwrap();
        assert_eq!(f.installed.lock().unwrap().last(), Some(&4));
        assert_eq!(first.revision, 8);
    }
}
