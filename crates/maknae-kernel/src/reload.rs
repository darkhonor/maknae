//! The policy reload's ordering: intent, load and compile, persist, install,
//! outcome. The store publish is the point of no return: once it succeeds the
//! candidate is installed whatever the checkpoint append does.

use maknae_graph::identity::IdentityLayer;
use std::fmt;
use std::future::Future;

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

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Applied {
    pub revision: u64,
    pub persisted: bool,
    pub checkpoint_error: Option<String>,
}

/// The outcome record's `(result, reason, posture)`.
pub fn outcome(r: &Result<Applied, Refusal>) -> (&'static str, String, &'static str) {
    match r {
        Ok(Applied {
            revision,
            checkpoint_error: Some(e),
            ..
        }) => (
            "permit",
            format!(
                "reload applied: revision {revision}; identity persisted; checkpoint append failed: {e}"
            ),
            "authorized",
        ),
        Ok(Applied {
            revision,
            persisted,
            checkpoint_error: None,
        }) => {
            let identity = if *persisted { "persisted" } else { "unchanged" };
            (
                "permit",
                format!("reload applied: revision {revision}; identity {identity}"),
                "authorized",
            )
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
    /// Publish; `Ok((revision, checkpoint_error))`.
    fn commit(
        &self,
        candidate: &Self::Candidate,
    ) -> impl Future<Output = Result<(u64, Option<String>), Refusal>> + Send;
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
            checkpoint_error: None,
        },
        Plan::Persist { .. } => {
            let (revision, checkpoint_error) = store.commit(&candidate).await?;
            Applied {
                revision,
                persisted: true,
                checkpoint_error,
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
    fn outcome_strings_are_pinned() {
        let ok = |persisted, checkpoint_error: Option<&str>| {
            Ok(Applied {
                revision: 6,
                persisted,
                checkpoint_error: checkpoint_error.map(str::to_string),
            })
        };
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
        commit: Option<Result<(u64, Option<String>), Refusal>>,
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
        fn commit(
            &self,
            c: &u64,
        ) -> impl Future<Output = Result<(u64, Option<String>), Refusal>> + Send {
            self.log(format!("commit {c}"));
            let r = self.commit.clone().unwrap_or(Ok((*c, None)));
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
            commit: Some(Ok((4, Some("disk full".into())))),
            ..Fake::default()
        };
        let r = run(&f, 3).await;
        assert_eq!(
            r,
            Ok(Applied {
                revision: 4,
                persisted: true,
                checkpoint_error: Some("disk full".into()),
            })
        );
        assert_eq!(*f.installed.lock().unwrap(), [4]);
        assert_eq!(f.calls().last().map(String::as_str), Some("outcome"));
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
                checkpoint_error: None,
            })
        );
    }

    #[tokio::test]
    async fn the_applied_revision_is_the_commits_not_the_candidates() {
        let f = Fake {
            commit: Some(Ok((8, Some("checkpoint refused".into())))),
            ..Fake::default()
        };
        let first = run(&f, 3).await.unwrap();
        assert_eq!(f.installed.lock().unwrap().last(), Some(&4));
        assert_eq!(first.revision, 8);
    }
}
