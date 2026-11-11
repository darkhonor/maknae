//! Which agents the installed snapshot enrolls, and under which uid (#609).
use std::sync::Arc;

use maknae_authz_basic::Baseline;
use maknae_config::AgentId;

use crate::Composition;

pub trait EnrollmentView: Send + Sync {
    fn agent_uid(&self, id: &AgentId) -> Option<u32>;
    fn is_enrolled(&self, uid: u32) -> bool;
    /// Whether the person or agent `uid` is contained.
    fn contained(&self, uid: u32) -> bool;
    /// Whether `uid`'s lack of a role may only be a name the load could not resolve.
    fn unresolved(&self, uid: u32) -> bool;
    /// The load these answers are read from.
    fn load(&self) -> Load {
        Load::fixed()
    }
}

/// One installed policy load, held so that a later reading can be compared with it. A
/// view that never changes has none, and every reading of it is the same.
#[derive(Clone)]
pub struct Load(Option<Arc<dyn std::any::Any + Send + Sync>>);

impl Load {
    /// The load of a view that never changes.
    pub fn fixed() -> Load {
        Load(None)
    }

    /// A load identified by `of`, which it keeps alive.
    pub fn installed(of: Arc<dyn std::any::Any + Send + Sync>) -> Load {
        Load(Some(of))
    }

    pub fn same(&self, other: &Load) -> bool {
        match (&self.0, &other.0) {
            (None, None) => true,
            (Some(a), Some(b)) => std::ptr::addr_eq(Arc::as_ptr(a), Arc::as_ptr(b)),
            (Some(_), None) | (None, Some(_)) => false,
        }
    }
}

impl PartialEq for Load {
    fn eq(&self, other: &Load) -> bool {
        self.same(other)
    }
}

impl Eq for Load {}

impl std::fmt::Debug for Load {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self.0 {
            None => "Load(fixed)",
            Some(_) => "Load(installed)",
        })
    }
}

pub struct SnapshotEnrollment<B: Baseline>(pub Arc<Composition<B>>);

impl<B: Baseline> Clone for SnapshotEnrollment<B> {
    fn clone(&self) -> Self {
        Self(Arc::clone(&self.0))
    }
}

impl<B: Baseline> EnrollmentView for SnapshotEnrollment<B> {
    fn agent_uid(&self, id: &AgentId) -> Option<u32> {
        self.0.baseline().snapshot().agent_uid(id.as_str())
    }

    fn is_enrolled(&self, uid: u32) -> bool {
        self.0.baseline().snapshot().agent_of(uid).is_some()
    }

    fn contained(&self, uid: u32) -> bool {
        let baseline = self.0.baseline();
        baseline.snapshot().contained(uid, baseline.principal().uid)
    }

    fn unresolved(&self, uid: u32) -> bool {
        let baseline = self.0.baseline();
        baseline
            .snapshot()
            .unresolved(uid, baseline.principal().uid)
    }

    fn load(&self) -> Load {
        Load::installed(self.0.baseline().snapshot())
    }
}

#[cfg(any(test, feature = "hermetic-test-seam"))]
#[derive(Clone)]
pub struct FixedEnrollment(pub std::collections::BTreeMap<AgentId, u32>);

#[cfg(any(test, feature = "hermetic-test-seam"))]
impl EnrollmentView for FixedEnrollment {
    fn agent_uid(&self, id: &AgentId) -> Option<u32> {
        self.0.get(id).copied()
    }

    fn is_enrolled(&self, uid: u32) -> bool {
        self.0.values().any(|u| *u == uid)
    }

    fn contained(&self, _uid: u32) -> bool {
        false
    }

    fn unresolved(&self, _uid: u32) -> bool {
        false
    }
}

/// `view`, in which the uids named have no role only because a name did not resolve.
#[cfg(any(test, feature = "hermetic-test-seam"))]
pub struct Unresolving<V>(pub V, pub std::collections::BTreeSet<u32>);

#[cfg(any(test, feature = "hermetic-test-seam"))]
impl<V: EnrollmentView> EnrollmentView for Unresolving<V> {
    fn agent_uid(&self, id: &AgentId) -> Option<u32> {
        self.0.agent_uid(id)
    }

    fn is_enrolled(&self, uid: u32) -> bool {
        self.0.is_enrolled(uid)
    }

    fn contained(&self, uid: u32) -> bool {
        self.0.contained(uid)
    }

    fn unresolved(&self, uid: u32) -> bool {
        self.1.contains(&uid)
    }
}

/// `view`, with `contained` contained.
#[cfg(any(test, feature = "hermetic-test-seam"))]
pub struct Containing<V>(pub V, pub std::collections::BTreeSet<u32>);

#[cfg(any(test, feature = "hermetic-test-seam"))]
impl<V: EnrollmentView> EnrollmentView for Containing<V> {
    fn agent_uid(&self, id: &AgentId) -> Option<u32> {
        self.0.agent_uid(id)
    }

    fn is_enrolled(&self, uid: u32) -> bool {
        self.0.is_enrolled(uid)
    }

    fn contained(&self, uid: u32) -> bool {
        self.1.contains(&uid)
    }

    fn unresolved(&self, uid: u32) -> bool {
        self.0.unresolved(uid)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn id(s: &str) -> AgentId {
        AgentId::parse(s).unwrap()
    }

    #[test]
    fn the_fixed_view_answers_by_id_and_by_uid() {
        let view = FixedEnrollment([(id("hobi"), 2001)].into());
        assert_eq!(view.agent_uid(&id("hobi")), Some(2001));
        assert_eq!(view.agent_uid(&id("jin")), None);
        assert!(view.is_enrolled(2001));
        assert!(!view.is_enrolled(2002));
        assert!(!view.contained(2001));
    }

    #[test]
    fn the_containing_view_adds_only_who_is_contained() {
        let view = Containing(FixedEnrollment([(id("hobi"), 2001)].into()), [1000].into());
        assert_eq!(view.agent_uid(&id("hobi")), Some(2001));
        assert!(view.is_enrolled(2001) && !view.is_enrolled(1000));
        assert!(view.contained(1000) && !view.contained(2001));
        assert!(!view.unresolved(1000));
        let view = Unresolving(view, [1000].into());
        assert_eq!(view.agent_uid(&id("hobi")), Some(2001));
        assert!(view.is_enrolled(2001) && view.contained(1000));
        assert!(view.unresolved(1000) && !view.unresolved(2001));
    }

    #[test]
    fn the_snapshot_view_reads_the_installed_snapshot() {
        let (_g, basic) = crate::test_fixtures::fixture(
            "enrollment-view",
            crate::test_fixtures::READ_POLICY,
            None,
        );
        let pdp = Arc::new(Composition::new(
            basic,
            crate::CeilingAuthorizer::new(
                maknae_config::Ceiling::baseline_for(&maknae_config::BasicPolicy),
                &maknae_config::BasicPolicy,
            ),
        ));
        let view = SnapshotEnrollment(pdp);
        assert_eq!(view.agent_uid(&id("hobi")), None);
        assert!(!view.is_enrolled(nix::unistd::geteuid().as_raw()));
        assert!(!view.contained(nix::unistd::geteuid().as_raw()));
        assert!(!view.unresolved(nix::unistd::geteuid().as_raw()));
        let (first, again) = (view.load(), view.load());
        assert!(first.same(&again), "one installed snapshot");
        view.0.baseline().reload_from_file().unwrap();
        assert_ne!(first, view.load(), "another was installed");
        let fixed = FixedEnrollment(Default::default());
        assert!(!first.same(&fixed.load()) && !fixed.load().same(&first));
        assert_eq!(fixed.load(), fixed.load());
        assert_eq!(
            (format!("{first:?}"), format!("{:?}", fixed.load())),
            ("Load(installed)".to_string(), "Load(fixed)".to_string())
        );
    }

    #[test]
    fn the_snapshot_view_names_an_enrolled_agent_by_id_and_by_uid() {
        let (g, basic) = crate::test_fixtures::fixture(
            "enrollment-view-hobi",
            crate::test_fixtures::READ_POLICY,
            None,
        );
        basic.set_hosts(crate::test_fixtures::HOBI_HOSTS);
        crate::test_fixtures::write_agent(&g.0, "hobi", "hobi-svc", 2001, "user");
        basic.reload_from_file().unwrap();
        let view = SnapshotEnrollment(Arc::new(Composition::new(
            basic,
            crate::CeilingAuthorizer::new(
                maknae_config::Ceiling::baseline_for(&maknae_config::BasicPolicy),
                &maknae_config::BasicPolicy,
            ),
        )));
        assert_eq!(view.agent_uid(&id("hobi")), Some(2001));
        assert!(view.is_enrolled(2001));
        assert!(!view.is_enrolled(2002));
    }
}
