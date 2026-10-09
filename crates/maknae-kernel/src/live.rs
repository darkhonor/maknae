//! What an accepted baseline swaps in for the next request (#490): the redacted
//! config view and the providers authority. The principal is the baseline
//! operand's own holder, installed in the same live turn; the ceiling is not live.

use std::sync::{Arc, PoisonError, RwLock};

use crate::baseline_check::Validated;
use crate::provider_choice::ProviderAuthority;
use crate::run::ConfigView;

type Served = (Arc<ConfigView>, Arc<Option<ProviderAuthority>>, u64);

pub struct LiveConfig {
    served: RwLock<Arc<Served>>,
}

/// One accepted live baseline, installed whole in the composition's live turn.
pub struct LiveValues {
    pub principal: maknae_config::Principal,
    pub view: ConfigView,
    pub providers: Option<ProviderAuthority>,
}

impl LiveValues {
    pub fn of(v: &Validated) -> Self {
        Self {
            principal: v.principal.clone(),
            view: config_view_of(v),
            providers: providers_of(v),
        }
    }
}

impl LiveConfig {
    pub fn new(view: ConfigView, providers: Option<ProviderAuthority>) -> Self {
        Self {
            served: RwLock::new(Arc::new((Arc::new(view), Arc::new(providers), 0))),
        }
    }

    pub fn of(v: &Validated) -> Self {
        Self::new(config_view_of(v), providers_of(v))
    }

    fn served(&self) -> Arc<Served> {
        self.served
            .read()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }

    pub fn view(&self) -> Arc<ConfigView> {
        Arc::clone(&self.served().0)
    }

    pub fn providers(&self) -> Arc<Option<ProviderAuthority>> {
        Arc::clone(&self.served().1)
    }

    /// The view and providers a request is admitted on, and the install generation they belong to.
    pub fn admission(&self) -> (Arc<ConfigView>, Arc<Option<ProviderAuthority>>, u64) {
        let served = self.served();
        (Arc::clone(&served.0), Arc::clone(&served.1), served.2)
    }

    pub fn generation(&self) -> u64 {
        self.served().2
    }

    pub(crate) fn install(
        &self,
        _turn: &maknae_authz_basic::LiveTurn<'_>,
        view: ConfigView,
        providers: Option<ProviderAuthority>,
    ) {
        let mut slot = self.served.write().unwrap_or_else(PoisonError::into_inner);
        let generation = slot.2.wrapping_add(1);
        *slot = Arc::new((Arc::new(view), Arc::new(providers), generation));
    }
}

/// The redacted view `admin.config.show` serves for a validated baseline.
pub fn config_view_of(v: &Validated) -> ConfigView {
    let vc = maknae_vault::vault_config_from_document(v.boot.document()).ok();
    maknae_config::effective_view(
        v.boot.document(),
        &maknae_config::ResolvedSettings {
            transport: &v.transport,
            audit: &v.audit,
            vault_approle_mount: vc.as_ref().map(|c| c.approle_mount.clone()),
            vault_pki_int_mount: vc.as_ref().map(|c| c.pki_int_mount.clone()),
            vault_user_auth_type: vc.as_ref().map(|c| c.user_auth.r#type.clone()),
            vault_user_auth_mount: vc.as_ref().map(|c| c.user_auth.mount.clone()),
            egress: &v.egress,
        },
    )
}

pub fn providers_of(v: &Validated) -> Option<ProviderAuthority> {
    crate::provider_choice::provider_authority(v.boot.providers(), v.egress_bounds.as_ref())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn install<B: maknae_authz_basic::Baseline>(
        pdp: &crate::Composition<B>,
        v: &Validated,
        deadline: std::time::Instant,
    ) -> Result<(), String> {
        pdp.install_live_within(LiveValues::of(v), deadline)
    }

    fn soon() -> std::time::Instant {
        std::time::Instant::now() + std::time::Duration::from_secs(5)
    }

    fn install_view(live: &LiveConfig, view: ConfigView, providers: Option<ProviderAuthority>) {
        let lock = maknae_authz_basic::LiveTurnLock::hermetic();
        let turn = lock.try_take().unwrap();
        live.install(&turn, view, providers)
    }
    use crate::baseline_check::{validate, Invalid, Mode};
    use crate::test_fixtures::{
        doc, fixture, minimal, permitted_read_marked, FakeEnv, PROVIDERS, READ_POLICY,
    };
    use maknae_authz_basic::Baseline;
    use maknae_config::{BasicPolicy, Ceiling, ClassificationPolicy, ProviderSet};
    use maknae_security::{Authorizer, Verdict};
    use std::collections::BTreeMap;
    use std::path::Path;

    const US: &BasicPolicy = &BasicPolicy;

    fn view(key: &str, value: &str) -> ConfigView {
        BTreeMap::from([(
            "core".to_string(),
            BTreeMap::from([(key.to_string(), value.to_string())]),
        )])
    }

    fn authority(prefix: &str) -> Option<ProviderAuthority> {
        Some(ProviderAuthority {
            set: ProviderSet::empty(),
            user_prefix: prefix.into(),
        })
    }

    fn prefix(p: &Option<ProviderAuthority>) -> Option<&str> {
        p.as_ref().map(|a| a.user_prefix.as_str())
    }

    fn with(pairs: &[(&'static str, &'static str)]) -> Vec<(&'static str, &'static str)> {
        let mut out = minimal();
        for (k, v) in pairs {
            out.retain(|(name, _)| name != k);
            out.push((k, v));
        }
        out
    }

    fn validated(pairs: &[(&str, &str)], env: &FakeEnv) -> Result<Validated, Invalid> {
        validate(doc(pairs), Mode::Boot, Path::new("/etc/maknae"), env)
    }

    const SECRET_CORE: &str = r#"{"deployment_id":"d","handling":{"accreditation_ref":null,"ceiling":{"classification":"SECRET","cui_categories_permitted":[],"cui_permitted":false,"dissemination_permitted":["Distribution Statement A"],"releasable_to":[],"sci":false}}}"#;

    #[test]
    fn install_replaces_both_and_a_held_copy_is_unchanged() {
        let live = LiveConfig::new(view("a", "1"), authority("old"));
        let (held_view, held_providers) = (live.view(), live.providers());
        install_view(&live, view("a", "2"), None);
        assert_eq!(*held_view, view("a", "1"));
        assert_eq!(prefix(&held_providers), Some("old"));
        assert_eq!(*live.view(), view("a", "2"));
        assert!(live.providers().is_none());
        install_view(&live, view("b", "3"), authority("new"));
        assert_eq!(*live.view(), view("b", "3"));
        assert_eq!(prefix(&live.providers()), Some("new"));
    }

    #[test]
    fn an_admission_holds_the_view_and_providers_of_its_generation() {
        let live = LiveConfig::new(view("a", "1"), authority("old"));
        let (view_then, providers_then, generation) = live.admission();
        install_view(&live, view("a", "2"), None);
        assert_eq!(generation, 0);
        assert_eq!(*view_then, view("a", "1"));
        assert_eq!(prefix(&providers_then), Some("old"));
        assert_eq!(live.generation(), 1);
    }

    #[test]
    fn a_poisoned_lock_still_answers() {
        let live = Arc::new(LiveConfig::new(view("a", "1"), authority("old")));
        let poisoner = Arc::clone(&live);
        let _ = std::thread::spawn(move || {
            let _guard = poisoner.served.write().unwrap();
            panic!("poison the holder");
        })
        .join();
        assert!(live.served.is_poisoned());
        assert_eq!(*live.view(), view("a", "1"));
        install_view(&live, view("a", "2"), None);
        assert_eq!(*live.view(), view("a", "2"));
        assert!(live.providers().is_none());
    }

    #[test]
    fn the_view_and_the_providers_are_the_validated_baselines() {
        let plain = validated(&minimal(), &FakeEnv::default()).unwrap();
        let live = LiveConfig::of(&plain);
        assert_eq!(*live.view(), config_view_of(&plain));
        assert_eq!(live.view()["principal"]["uid"], "1000");
        assert!(live.providers().is_none());
        let env = FakeEnv::with_bounds();
        let with_providers = validated(&with(&[("providers", PROVIDERS)]), &env).unwrap();
        let live = LiveConfig::of(&with_providers);
        assert_eq!(prefix(&live.providers()), Some("users"));
        assert_eq!(
            live.providers().as_ref().as_ref().unwrap().set.len(),
            1,
            "the validated providers"
        );
    }

    #[test]
    fn install_serves_the_accepted_principal_view_and_providers_and_never_a_ceiling() {
        let (g, basic) = fixture("live-accepted", READ_POLICY, None);
        let pdp = crate::Composition::new(
            basic,
            crate::CeilingAuthorizer::new(Ceiling::baseline_for(US), US),
        );
        let first = validated(&minimal(), &FakeEnv::default()).unwrap();
        let pdp = pdp.with_live(LiveConfig::of(&first));
        let live = pdp.live();
        let env = FakeEnv::with_bounds();
        let mut next = validated(
            &with(&[("core", SECRET_CORE), ("providers", PROVIDERS)]),
            &env,
        )
        .unwrap();
        next.principal.uid = nix::unistd::geteuid().as_raw();
        assert_eq!(live.generation(), 0);
        install(&pdp, &next, soon()).unwrap();
        assert_eq!(live.generation(), 1);
        assert_eq!(pdp.ceiling().ceiling().classification, US.unmarked());
        assert_eq!(pdp.baseline().principal(), next.principal);
        assert_eq!(*live.view(), config_view_of(&next));
        assert_eq!(prefix(&live.providers()), Some("users"));
        let marked = permitted_read_marked(&g.0, Some("SECRET"));
        assert!(
            matches!(pdp.decide(&marked), Verdict::Deny { ref reason } if reason.starts_with("ceiling: ")),
            "the booted ceiling still refuses SECRET content"
        );
    }

    #[test]
    fn a_removed_principal_section_is_refused_before_any_holder_changes() {
        let mut no_principal = minimal();
        no_principal.retain(|(k, _)| *k != "principal");
        assert!(matches!(
            validated(&no_principal, &FakeEnv::default()),
            Err(Invalid::Principal(_))
        ));
    }
}
