//! What an accepted baseline swaps in for the next request (#490): the redacted
//! config view and the providers authority. The ceiling level and the principal
//! are the composition's own holders ([`crate::Composition::install_live`]).

use std::sync::{Arc, PoisonError, RwLock};

use crate::baseline_check::Validated;
use crate::provider_choice::ProviderAuthority;
use crate::run::ConfigView;

type Served = (Arc<ConfigView>, Arc<Option<ProviderAuthority>>);

pub struct LiveConfig {
    served: RwLock<Arc<Served>>,
}

impl LiveConfig {
    pub fn new(view: ConfigView, providers: Option<ProviderAuthority>) -> Self {
        Self {
            served: RwLock::new(Arc::new((Arc::new(view), Arc::new(providers)))),
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

    /// Both values are replaced together; a request holding the previous ones
    /// finishes on them.
    pub fn install(&self, view: ConfigView, providers: Option<ProviderAuthority>) {
        *self.served.write().unwrap_or_else(PoisonError::into_inner) =
            Arc::new((Arc::new(view), Arc::new(providers)));
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

/// Installs a validated live baseline: the ceiling level and the principal first
/// (refused whole when the booted system does not rank the ceiling), then the view
/// and the providers. The validator requires a principal, so a baseline without
/// one never reaches here; an absent ceiling is the system's lowest level.
pub fn install<B: maknae_authz_basic::Baseline>(
    pdp: &crate::Composition<B>,
    live: &LiveConfig,
    v: &Validated,
) -> Result<(), String> {
    pdp.install_live(v.boot.ceiling().clone(), v.principal.clone())?;
    live.install(config_view_of(v), providers_of(v));
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::baseline_check::tests::{doc, minimal, FakeEnv, PROVIDERS};
    use crate::baseline_check::{validate, Invalid, Mode};
    use crate::composition::tests::{fixture, permitted_read_marked, READ_POLICY};
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
    const AUS_CORE: &str = r#"{"deployment_id":"d","handling":{"accreditation_ref":null,"ceiling":{"classification":"PROTECTED","cui_categories_permitted":[],"cui_permitted":false,"dissemination_permitted":["Distribution Statement A"],"releasable_to":[],"sci":false},"policy":"aus"}}"#;

    #[test]
    fn install_replaces_both_and_a_held_copy_is_unchanged() {
        let live = LiveConfig::new(view("a", "1"), authority("old"));
        let (held_view, held_providers) = (live.view(), live.providers());
        live.install(view("a", "2"), None);
        assert_eq!(*held_view, view("a", "1"));
        assert_eq!(prefix(&held_providers), Some("old"));
        assert_eq!(*live.view(), view("a", "2"));
        assert!(live.providers().is_none());
        live.install(view("b", "3"), authority("new"));
        assert_eq!(*live.view(), view("b", "3"));
        assert_eq!(prefix(&live.providers()), Some("new"));
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
        live.install(view("a", "2"), None);
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
    fn install_serves_the_accepted_ceiling_principal_view_and_providers() {
        let (g, basic) = fixture("live-accepted", READ_POLICY, None);
        let pdp = crate::Composition::new(
            basic,
            crate::CeilingAuthorizer::new(Ceiling::baseline_for(US), US),
        );
        let first = validated(&minimal(), &FakeEnv::default()).unwrap();
        let live = LiveConfig::of(&first);
        let env = FakeEnv::with_bounds();
        let next = validated(
            &with(&[("core", SECRET_CORE), ("providers", PROVIDERS)]),
            &env,
        )
        .unwrap();
        install(&pdp, &live, &next).unwrap();
        assert_eq!(pdp.ceiling().ceiling().classification.name, "SECRET");
        assert_eq!(pdp.baseline().principal(), next.principal);
        assert_eq!(*live.view(), config_view_of(&next));
        assert_eq!(prefix(&live.providers()), Some("users"));
        let marked = permitted_read_marked(&g.0, Some("SECRET"));
        assert!(
            !matches!(pdp.decide(&marked), Verdict::Permit { .. }),
            "uid 1000 is the principal now, not the test's euid"
        );
    }

    #[test]
    fn a_ceiling_removed_from_the_file_serves_the_systems_lowest_level() {
        let (g, basic) = fixture("live-no-ceiling", READ_POLICY, None);
        let pdp = crate::Composition::new(
            basic,
            crate::CeilingAuthorizer::new(crate::composition::tests::secret(), US),
        );
        let mut accepted = validated(&with(&[("core", SECRET_CORE)]), &FakeEnv::default()).unwrap();
        accepted.principal.uid = nix::unistd::geteuid().as_raw();
        let live = LiveConfig::of(&accepted);
        install(&pdp, &live, &accepted).unwrap();
        let marked = permitted_read_marked(&g.0, Some("CONFIDENTIAL"));
        assert!(matches!(pdp.decide(&marked), Verdict::Permit { .. }));
        let mut removed = validated(&minimal(), &FakeEnv::default()).unwrap();
        removed.principal.uid = accepted.principal.uid;
        assert_eq!(removed.boot.ceiling(), &Ceiling::baseline_for(US));
        install(&pdp, &live, &removed).unwrap();
        assert_eq!(pdp.ceiling().ceiling().classification, US.unmarked());
        assert!(matches!(pdp.decide(&marked), Verdict::Deny { .. }));
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

    #[test]
    fn a_ceiling_the_booted_system_does_not_rank_changes_no_holder() {
        let (_g, basic) = fixture("live-foreign", READ_POLICY, None);
        let pdp = crate::Composition::new(
            basic,
            crate::CeilingAuthorizer::new(Ceiling::baseline_for(US), US),
        );
        let before = pdp.baseline().principal();
        let first = validated(&minimal(), &FakeEnv::default()).unwrap();
        let live = LiveConfig::of(&first);
        let aus = validated(&with(&[("core", AUS_CORE)]), &FakeEnv::default()).unwrap();
        assert_eq!(
            install(&pdp, &live, &aus).unwrap_err(),
            "PROTECTED is not a level of the US system"
        );
        assert_eq!(pdp.baseline().principal(), before);
        assert_eq!(pdp.ceiling().ceiling().classification, US.unmarked());
        assert_eq!(*live.view(), config_view_of(&first));
    }
}
