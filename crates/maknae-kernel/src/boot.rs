//! Cycle: config-boot — the kernel's boot sequence over Maknae's own config.
//! Loads the config directory, selects the classification system
//! `core.handling.policy` names (ADR-0022), reads the `core` ceiling THROUGH
//! that system into the runtime ingest posture, and fails closed on any error.
//! Maknae reads only its own config; nothing external is read at boot.

use maknae_config::{
    ceiling_from_core, load_config_root_owned, policy_name_from_core, providers_from_section,
    refuse_plaintext_keys, Ceiling, ClassificationPolicy, ConfigError, Document, IngestPosture,
    ProviderSet, SectionSpec, Value, AUDIT_SECTION, EGRESS_SECTION, PRINCIPAL_SECTION,
    PROVIDERS_SECTION, TRANSPORT_SECTION,
};
use maknae_vault::VAULT_SECTION;
use std::path::Path;

/// The reserved, inert extension section for Maknae's own long-term-memory
/// subsystem (forthcoming). Registered so a present `lake` block loads and is
/// carried, but nothing reads it yet.
const LAKE_SECTION: &str = "lake";

/// The assembled boot configuration: the loaded document, the classification
/// system the deployment declared, and the ceiling resolved through it.
pub struct BootConfig {
    document: Document,
    ceiling: Ceiling,
    policy: &'static dyn ClassificationPolicy,
    providers: ProviderSet,
}

impl std::fmt::Debug for BootConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BootConfig")
            .field("document", &self.document)
            .field("ceiling", &self.ceiling)
            .field("policy", &self.policy.name())
            .field("providers", &self.providers)
            .finish()
    }
}

impl BootConfig {
    /// Access a loaded section's value (schema-agnostic; the subsystem parses it).
    pub fn section(&self, name: &str) -> Option<&Value> {
        self.document.section(name)
    }

    /// The resolved classification ceiling (`core.handling.ceiling`, or the
    /// selected system's baseline).
    pub fn ceiling(&self) -> &Ceiling {
        &self.ceiling
    }

    /// The classification system this enclave operates under -- the one
    /// `core.handling.policy` selected from the build's registry (ADR-0022).
    pub fn policy(&self) -> &'static dyn ClassificationPolicy {
        self.policy
    }

    /// The selected system's name, for `admin.status` and the boot evidence.
    pub fn classification_policy_name(&self) -> &str {
        self.policy.name()
    }

    pub fn providers(&self) -> &ProviderSet {
        &self.providers
    }

    pub fn shadowed_sections<'a>(&'a self, name: &'a str) -> impl Iterator<Item = &'a Value> + 'a {
        self.document.shadowed_sections(name)
    }

    /// The full loaded document — handed to `PlaneClient::from_document` so the daemon
    /// loads its config ONCE (this boot, registering every section it uses) instead of
    /// the plane client re-loading under a `vault`-only registry that would reject
    /// boot's `lake`/`transport`/`audit` sections as `UnknownSection` (P1-A).
    pub fn document(&self) -> &Document {
        &self.document
    }

    /// The coarse ingest posture derived from the ceiling, relative to the
    /// selected system's baseline.
    pub fn ingest_posture(&self) -> IngestPosture {
        self.ceiling.ingest_posture(self.policy)
    }
}

/// Boot the kernel over Maknae's config directory: [`read_files`], then [`assemble`].
pub fn boot(config_dir: &Path) -> Result<BootConfig, ConfigError> {
    read_files(config_dir).and_then(assemble)
}

/// Load the config ONCE with every section the daemon uses registered, every
/// source and the directories that select among them held to root ownership
/// (#490). `vault` and `principal` are optional here; their absence fails closed
/// where they are consumed.
pub fn read_files(config_dir: &Path) -> Result<Document, ConfigError> {
    load_config_root_owned(config_dir, &boot_specs())
}

/// The hermetic door: [`read_files`] with every source owned by the test's euid.
#[cfg(any(test, feature = "hermetic-test-seam"))]
pub fn read_files_as_owner(config_dir: &Path) -> Result<Document, ConfigError> {
    maknae_config::load_config_root_owned_with_requirement(
        config_dir,
        &boot_specs(),
        maknae_io::TargetRequired {
            owner: Some(nix::unistd::geteuid().as_raw()),
            mode_mask: Some(0o022),
            nlink_exactly_one: false,
            regular_file: true,
            max_bytes: None,
        },
    )
}

/// The sections the daemon registers, as literal blocks: the disclosure drift
/// gate reads each registration's `name:` operand from this file, so the list
/// is never built by a loop (and this comment never spells the block's opener).
fn boot_specs() -> [SectionSpec; 7] {
    [
        SectionSpec {
            name: LAKE_SECTION.to_string(),
            required: false,
        },
        SectionSpec {
            name: VAULT_SECTION.to_string(),
            required: false,
        },
        SectionSpec {
            name: TRANSPORT_SECTION.to_string(),
            required: false,
        },
        SectionSpec {
            name: AUDIT_SECTION.to_string(),
            required: false,
        },
        SectionSpec {
            name: PRINCIPAL_SECTION.to_string(),
            required: false,
        },
        SectionSpec {
            name: PROVIDERS_SECTION.to_string(),
            required: false,
        },
        SectionSpec {
            name: EGRESS_SECTION.to_string(),
            required: false,
        },
    ]
}

/// [`boot`] through the hermetic door.
#[cfg(feature = "hermetic-test-seam")]
pub fn boot_as_owner(config_dir: &Path) -> Result<BootConfig, ConfigError> {
    read_files_as_owner(config_dir).and_then(assemble)
}

/// Everything after the load: the classification system, the ceiling through
/// it, the provider.
pub(crate) fn assemble(document: Document) -> Result<BootConfig, ConfigError> {
    // The SYSTEM first, then the ceiling THROUGH it (ADR-0022): a name this
    // build does not carry refuses boot before any level is read, and a
    // level the selected system does not rank refuses it in the reader.
    let core = document.section("core");
    // #210: core's own vocabulary, closed HERE because this is where core is
    // consumed — `loader.rs` reserves the section but is deliberately
    // schema-agnostic, and `ceiling_from_core` owns the ceiling, not core.
    //
    // This is the one level whose typo the ceiling subtree cannot catch:
    // `handling` and `handling.ceiling` each close their own keys, but a
    // mistyped `handling` means neither ever runs, the block is invisible, and
    // the instance boots at BASELINE with the operator believing otherwise.
    // Measured as exactly that before this line existed.
    if let Some(maknae_config::Value::Map(entries)) = core {
        maknae_config::reject_unknown_keys(
            "core",
            entries,
            // DERIVED, not invented: `handling` is what `ceiling_from_core`
            // reads; `deployment_id` is read by `maknae-vault`'s
            // `vault_config_from_document`; `identity` and the version field are
            // carried verbatim for their consumers, as `docs/configuration.md`
            // §4 documents — admitted here because the section legitimately
            // holds them, not because anything in this crate reads them.
            &["deployment_id", "schema_version", "identity", "handling"],
        )?;
    }
    let name = policy_name_from_core(core)?;
    let policy = crate::classification::select(&name)
        .ok_or(ConfigError::UnknownClassificationPolicy { name })?;
    let ceiling = ceiling_from_core(core, policy)?;
    for shadowed in document.shadowed_sections(PROVIDERS_SECTION) {
        refuse_plaintext_keys(shadowed)?;
    }
    let providers = providers_from_section(document.section(PROVIDERS_SECTION))?;
    Ok(BootConfig {
        document,
        ceiling,
        policy,
        providers,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn owned(config_dir: &Path) -> Result<BootConfig, ConfigError> {
        boot_as_owner(config_dir)
    }

    #[cfg(unix)]
    fn boot_with_requirement(
        config_dir: &Path,
        requirement: maknae_io::TargetRequired,
    ) -> Result<BootConfig, ConfigError> {
        maknae_config::load_config_root_owned_with_requirement(
            config_dir,
            &boot_specs(),
            requirement,
        )
        .and_then(assemble)
    }

    // Platform-agnostic: a nonexistent dir fails on every platform (unix → Io from
    // canonicalize; non-unix → PermissionsUnsupported). Keeps `use super::*` live off-unix.
    #[test]
    fn nonexistent_dir_errors() {
        assert!(boot(std::path::Path::new("/nonexistent/maknae_boot_xyz")).is_err());
    }

    #[cfg(unix)]
    use std::os::unix::fs::PermissionsExt;
    #[cfg(unix)]
    use std::path::PathBuf;

    #[cfg(unix)]
    struct Dir(PathBuf);
    #[cfg(unix)]
    impl Drop for Dir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }
    #[cfg(unix)]
    fn new_dir(tag: &str) -> Dir {
        let p = std::env::temp_dir().join(format!("maknae_boot_{}_{tag}", std::process::id()));
        let _ = std::fs::remove_dir_all(&p);
        std::fs::create_dir_all(&p).unwrap();
        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o750)).unwrap();
        Dir(p)
    }
    #[cfg(unix)]
    fn put(dir: &std::path::Path, name: &str, body: &str, mode: u32) {
        let p = dir.join(name);
        std::fs::write(&p, body).unwrap();
        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(mode)).unwrap();
    }

    // A full, conformant, above-baseline (SECRET) core ceiling block.
    #[cfg(unix)]
    const SECRET_CORE: &str = "core:\n  handling:\n    ceiling:\n      classification: SECRET\n      sci: false\n      releasable_to: []\n      cui_permitted: false\n      cui_categories_permitted: []\n      dissemination_permitted: [\"Distribution Statement A\"]\n    accreditation_ref: null\n";

    /// #210: a key `core` does not carry must refuse the boot rather than be
    /// silently ignored. `handling` mistyped means the whole ceiling block is
    /// invisible and the instance boots at BASELINE — the one route to a
    /// silently-weakened ceiling that the `handling`/`ceiling` blocks' own
    /// closed vocabularies cannot catch, because they never run.
    #[cfg(unix)]
    #[test]
    fn an_unknown_core_key_refuses_the_boot() {
        let d = new_dir("core-unknown");
        put(
            &d.0,
            "maknae.yaml",
            "core:\n  handlng:\n    accreditation_ref: null\n",
            0o640,
        );
        match owned(&d.0) {
            Err(ConfigError::UnknownKey { section, key }) => {
                assert_eq!(section, "core");
                assert_eq!(key, "handlng");
            }
            other => panic!("expected Err(UnknownKey), got {other:?}"),
        }
    }

    /// #210 round-3 review: `core`'s allow-list had a refusal test but no
    /// acceptance companion, and `schema_version` — which `docs/configuration.md`
    /// §4 and its minimal example both use — was exercised by NO test, so a typo
    /// in that one entry would have refused the documented minimal config with
    /// nothing going red. All four accepted keys, loaded together.
    #[cfg(unix)]
    #[test]
    fn every_core_key_the_boot_accepts_is_accepted() {
        let d = new_dir("core-accept");
        put(
            &d.0,
            "maknae.yaml",
            "core:\n  schema_version: 1\n  deployment_id: dev-01\n  \
             identity:\n    name: t\n  handling:\n    accreditation_ref: null\n    \
             ceiling:\n      classification: UNCLASSIFIED\n      sci: false\n      \
             releasable_to: []\n      cui_permitted: false\n      \
             cui_categories_permitted: []\n      \
             dissemination_permitted: [\"Distribution Statement A\"]\n",
            0o640,
        );
        match owned(&d.0) {
            Err(ConfigError::UnknownKey { section, key }) => {
                panic!("a key core accepts was refused: '{key}' in '{section}'")
            }
            other => {
                other.expect("every accepted core key loads");
            }
        }
    }

    #[cfg(unix)]
    #[test]
    fn baseline_core_boots_public() {
        let d = new_dir("baseline");
        put(
            &d.0,
            "maknae.yaml",
            "core:\n  identity:\n    name: test\n",
            0o640,
        );
        let cfg = owned(&d.0).expect("boots");
        assert_eq!(
            cfg.ceiling(),
            &maknae_config::Ceiling::baseline_for(&maknae_config::BasicPolicy)
        );
        assert_eq!(cfg.ingest_posture(), maknae_config::IngestPosture::Public);
        assert_eq!(cfg.classification_policy_name(), "US", "the default system");
        assert_eq!(cfg.policy().unmarked().name, "UNCLASSIFIED");
        assert!(cfg.section("core").is_some());
        assert!(format!("{cfg:?}").contains("policy: \"US\""));
    }

    #[cfg(unix)]
    #[test]
    fn empty_base_boots_public() {
        let d = new_dir("empty");
        put(&d.0, "maknae.yaml", "", 0o640);
        let cfg = owned(&d.0).expect("boots");
        assert_eq!(cfg.ingest_posture(), maknae_config::IngestPosture::Public);
    }

    #[cfg(unix)]
    #[test]
    fn above_baseline_core_boots_gated() {
        let d = new_dir("secret");
        put(&d.0, "maknae.yaml", SECRET_CORE, 0o640);
        let cfg = owned(&d.0).expect("boots");
        assert_eq!(cfg.ingest_posture(), maknae_config::IngestPosture::Gated);
        let level = &cfg.ceiling().classification;
        assert_eq!(
            (level.policy.as_str(), level.name.as_str(), level.rank),
            ("US", "SECRET", 2)
        );
    }

    /// The live bug #148's sibling closed: a case-variant spelling of a level
    /// used to refuse boot outright.
    #[cfg(unix)]
    #[test]
    fn a_case_variant_level_boots() {
        let d = new_dir("caseok");
        let y = SECRET_CORE.replace("classification: SECRET", "classification: Unclassified");
        put(&d.0, "maknae.yaml", &y, 0o640);
        let cfg = owned(&d.0).expect("boots");
        assert_eq!(cfg.ceiling().classification.name, "UNCLASSIFIED");
        assert_eq!(cfg.ingest_posture(), maknae_config::IngestPosture::Public);
    }

    /// ADR-0022: an AUS enclave declares its system and its ceiling is read
    /// through the PSPF ladder -- PROTECTED is a level there and nowhere in US.
    #[cfg(unix)]
    #[test]
    fn an_aus_enclave_boots_on_protected() {
        let d = new_dir("aus");
        let y = SECRET_CORE
            .replace("classification: SECRET", "classification: PROTECTED")
            .replace(
                "    accreditation_ref: null\n",
                "    accreditation_ref: null\n    policy: aus\n",
            );
        put(&d.0, "maknae.yaml", &y, 0o640);
        let cfg = owned(&d.0).expect("boots");
        assert_eq!(cfg.classification_policy_name(), "AUS");
        let level = &cfg.ceiling().classification;
        assert_eq!(
            (level.policy.as_str(), level.name.as_str(), level.rank),
            ("AUS", "PROTECTED", 3)
        );
        assert_eq!(cfg.policy().unmarked().name, "UNOFFICIAL");
        assert_eq!(cfg.ingest_posture(), maknae_config::IngestPosture::Gated);
    }

    /// The one PSPF rung with a colon: quoted in YAML it ranks 2 (unquoted, the
    /// loader refuses the file -- docs §4.1 says so).
    #[cfg(unix)]
    #[test]
    fn the_official_sensitive_rung_boots_when_quoted() {
        let d = new_dir("aus-os");
        let y = SECRET_CORE
            .replace(
                "classification: SECRET",
                "classification: \"Official: Sensitive\"",
            )
            .replace(
                "    accreditation_ref: null\n",
                "    accreditation_ref: null\n    policy: AUS\n",
            );
        put(&d.0, "maknae.yaml", &y, 0o640);
        let cfg = owned(&d.0).expect("boots");
        let level = &cfg.ceiling().classification;
        assert_eq!(
            (level.name.as_str(), level.rank),
            ("OFFICIAL: SENSITIVE", 2)
        );
        // Unquoted: refused by the loader, not the ceiling reader.
        let y = y.replace("\"Official: Sensitive\"", "Official: Sensitive");
        put(&d.0, "maknae.yaml", &y, 0o640);
        assert!(
            matches!(owned(&d.0), Err(maknae_config::ConfigError::Parse { .. })),
            "{:?}",
            owned(&d.0)
        );
    }

    /// The same PROTECTED ceiling under the default (US) system refuses boot:
    /// the kernel maps nothing between systems.
    #[cfg(unix)]
    #[test]
    fn a_us_enclave_refuses_protected() {
        let d = new_dir("usprot");
        let y = SECRET_CORE.replace("classification: SECRET", "classification: PROTECTED");
        put(&d.0, "maknae.yaml", &y, 0o640);
        match owned(&d.0) {
            Err(maknae_config::ConfigError::InvalidCeiling { reason }) => {
                assert!(reason.contains("not a level of the US system"), "{reason}")
            }
            other => panic!("expected InvalidCeiling, got {other:?}"),
        }
    }

    /// A system this build does not carry refuses boot by NAME, before any
    /// level is read -- config names a system, never adds one.
    #[cfg(unix)]
    #[test]
    fn an_unknown_classification_system_refuses_boot() {
        let d = new_dir("rok");
        let y = SECRET_CORE.replace(
            "    accreditation_ref: null\n",
            "    accreditation_ref: null\n    policy: ROK\n",
        );
        put(&d.0, "maknae.yaml", &y, 0o640);
        match owned(&d.0) {
            Err(maknae_config::ConfigError::UnknownClassificationPolicy { name }) => {
                assert_eq!(name, "ROK")
            }
            other => panic!("expected UnknownClassificationPolicy, got {other:?}"),
        }
        // And a mistyped `policy` value is the ceiling reader's refusal.
        let y = SECRET_CORE.replace(
            "    accreditation_ref: null\n",
            "    accreditation_ref: null\n    policy: 7\n",
        );
        put(&d.0, "maknae.yaml", &y, 0o640);
        assert!(matches!(
            owned(&d.0),
            Err(maknae_config::ConfigError::InvalidCeiling { .. })
        ));
    }

    #[cfg(unix)]
    #[test]
    fn lake_section_is_carried() {
        let d = new_dir("lake");
        put(
            &d.0,
            "maknae.yaml",
            "core:\n  identity:\n    name: t\nlake:\n  in_scope_domains: [a]\n",
            0o640,
        );
        let cfg = owned(&d.0).expect("boots");
        assert!(cfg.section("lake").is_some());
    }

    // A config WITH a `principal` block loads under the boot registry (not rejected
    // as UnknownSection) — PR-J1 Task 5.
    #[cfg(unix)]
    #[test]
    fn principal_section_is_carried() {
        let d = new_dir("principal");
        put(
            &d.0,
            "maknae.yaml",
            "core:\n  identity:\n    name: t\n\
             principal:\n  name: alice\n  uid: 1000\n",
            0o640,
        );
        let cfg = owned(&d.0).expect("boots with a principal block");
        assert!(cfg.section("principal").is_some());
        let p = maknae_config::principal_from_section(cfg.section("principal"))
            .expect("principal parses from the booted document")
            .expect("principal section present");
        assert_eq!(p.name, "alice");
        assert_eq!(p.uid, 1000);
    }

    // A pre-Jackrabbit config WITHOUT a `principal` block still LOADS — the
    // optional-registration / upgrade property (spec §5.5), scoped to the loader.
    // (Discharged 2026-08-28, #77: the boot gate now REQUIRES the principal —
    // see boot_gate.rs. The loader half here legitimately still loads a
    // principal-less document; the refusal is the kernel gate's, downstream.)
    #[cfg(unix)]
    #[test]
    fn config_without_principal_section_still_boots() {
        let d = new_dir("no_principal");
        put(
            &d.0,
            "maknae.yaml",
            "core:\n  identity:\n    name: t\n",
            0o640,
        );
        let cfg = owned(&d.0).expect("pre-Jackrabbit config without principal still boots");
        assert!(cfg.section("principal").is_none());
        assert_eq!(
            maknae_config::principal_from_section(cfg.section("principal")),
            Ok(None)
        );
    }

    #[cfg(unix)]
    #[test]
    fn unknown_section_refused() {
        let d = new_dir("unknown");
        put(&d.0, "maknae.yaml", "mystery:\n  a: 1\n", 0o640);
        assert!(matches!(
            owned(&d.0),
            Err(maknae_config::ConfigError::UnknownSection { .. })
        ));
    }

    // A realistic combined config (core + vault + transport + audit) must boot AND
    // carry every section — the P1-A gap: the old boot registry omitted `vault`, so a
    // real /etc/maknae config was rejected with UnknownSection before the daemon could
    // start. The vault block must parse out of the SAME booted document that
    // `PlaneClient::from_document` consumes.
    #[cfg(unix)]
    #[test]
    fn combined_core_vault_transport_audit_boots() {
        let d = new_dir("combined");
        put(
            &d.0,
            "maknae.yaml",
            "core:\n  deployment_id: dev-01\n  identity:\n    name: t\n\
             vault:\n  addr: https://v.example:8200\n\
             transport:\n  socket_path: /run/maknae/maknaed.sock\n\
             audit:\n  jsonl_path: /var/log/maknae/audit.jsonl\n",
            0o640,
        );
        let cfg = owned(&d.0).expect("combined config boots");
        assert!(cfg.section("vault").is_some());
        assert!(cfg.section("transport").is_some());
        assert!(cfg.section("audit").is_some());
        // The booted document backs the plane client: prove the vault section parses
        // out of it (the coherence the daemon relies on to reach mint()).
        let vc = maknae_vault::vault_config_from_document(cfg.document())
            .expect("vault parses from the booted document");
        assert_eq!(vc.addr, "https://v.example:8200");
        assert_eq!(vc.deployment_id, "dev-01");
    }

    #[cfg(unix)]
    #[test]
    fn a_bad_root_vault_user_auth_refuses_the_vault_config_maknaed_starts_from() {
        let d = new_dir("bad_user_auth");
        put(
            &d.0,
            "maknae.yaml",
            "core:\n  deployment_id: dev-01\n  identity:\n    name: t\n\
             vault:\n  addr: https://v.example:8200\n  user_auth:\n    type: ldap\n",
            0o640,
        );
        let cfg = owned(&d.0).expect("the document loads; the vault parse is what refuses");
        assert!(matches!(
            maknae_vault::vault_config_from_document(cfg.document()),
            Err(maknae_vault::VaultError::UnknownUserAuth(t)) if t == "ldap"
        ));
    }

    // A genuinely-unknown section still fails closed EVEN alongside the now-accepted
    // combined sections — the fail-closed-on-unknown security property is preserved.
    #[cfg(unix)]
    #[test]
    fn combined_config_with_a_bogus_section_still_refused() {
        let d = new_dir("combined_bogus");
        put(
            &d.0,
            "maknae.yaml",
            "core:\n  deployment_id: dev-01\n\
             vault:\n  addr: https://v.example:8200\n\
             transport:\n  socket_path: /run/maknae/maknaed.sock\n\
             mystery:\n  a: 1\n",
            0o640,
        );
        assert!(matches!(
            owned(&d.0),
            Err(maknae_config::ConfigError::UnknownSection { .. })
        ));
    }

    #[cfg(unix)]
    #[test]
    fn invalid_ceiling_refused() {
        let d = new_dir("badceil");
        let bad = SECRET_CORE.replace("classification: SECRET", "classification: SEKRET");
        put(&d.0, "maknae.yaml", &bad, 0o640);
        assert!(matches!(
            owned(&d.0),
            Err(maknae_config::ConfigError::InvalidCeiling { .. })
        ));
    }

    #[cfg(unix)]
    #[test]
    fn missing_base_is_not_found() {
        let d = new_dir("nobase"); // no maknae.yaml
        assert!(matches!(
            owned(&d.0),
            Err(maknae_config::ConfigError::NotFound { .. })
        ));
    }

    #[cfg(unix)]
    #[test]
    fn world_readable_file_refused() {
        let d = new_dir("644");
        put(&d.0, "maknae.yaml", "core: {}\n", 0o644);
        assert!(matches!(
            owned(&d.0),
            Err(maknae_config::ConfigError::InsecurePermissions { .. })
        ));
    }

    #[cfg(unix)]
    #[test]
    fn symlinked_config_d_entry_refused() {
        let d = new_dir("sl");
        put(&d.0, "maknae.yaml", "core: {}\n", 0o640);
        let cd = d.0.join("config.d");
        std::fs::create_dir(&cd).unwrap();
        std::fs::set_permissions(&cd, std::fs::Permissions::from_mode(0o750)).unwrap();
        put(&d.0, "outside.yaml", "core: {}\n", 0o640);
        std::os::unix::fs::symlink(d.0.join("outside.yaml"), cd.join("evil.yaml")).unwrap();
        assert!(matches!(
            owned(&d.0),
            Err(maknae_config::ConfigError::Symlink { .. })
        ));
    }
    #[cfg(unix)]
    fn me() -> maknae_io::TargetRequired {
        maknae_io::TargetRequired {
            owner: Some(nix::unistd::geteuid().as_raw()),
            mode_mask: Some(0o022),
            nlink_exactly_one: false,
            regular_file: true,
            max_bytes: None,
        }
    }
    #[cfg(unix)]
    const PROVIDERS_BLOCK: &str = "providers:\n  - name: openai\n    endpoint: https://api.openai.com/v1\n    models: [gpt-5.6-luna, gpt-5.6]\n";

    #[cfg(unix)]
    #[test]
    fn an_authorized_set_is_carried_and_an_absent_one_is_empty() {
        let d = new_dir("providers");
        put(
            &d.0,
            "maknae.yaml",
            "core:\n  identity:\n    name: t\n",
            0o640,
        );
        assert!(owned(&d.0).unwrap().providers().is_empty());
        put(
            &d.0,
            "maknae.yaml",
            &format!("core:\n  identity:\n    name: t\n{PROVIDERS_BLOCK}"),
            0o640,
        );
        let cfg = owned(&d.0).unwrap();
        let p = cfg.providers().get("openai").expect("authorized");
        assert_eq!(
            (p.endpoint.as_str(), p.models.clone()),
            (
                "https://api.openai.com/v1",
                vec!["gpt-5.6-luna".to_string(), "gpt-5.6".to_string()]
            )
        );
        assert_eq!(cfg.providers().len(), 1);
        assert!(format!("{cfg:?}").contains("openai"));
    }

    #[cfg(unix)]
    #[test]
    fn the_retired_root_provider_block_is_refused_by_name() {
        let d = new_dir("provider-retired");
        put(
            &d.0,
            "maknae.yaml",
            "core: {}\nprovider:\n  name: openai\n  endpoint: https://api.openai.com/v1\n",
            0o640,
        );
        match owned(&d.0) {
            Err(maknae_config::ConfigError::UnknownSection { section, .. }) => {
                assert_eq!(section, "provider")
            }
            other => panic!("expected UnknownSection naming provider, got {other:?}"),
        }
    }

    #[cfg(unix)]
    #[test]
    fn a_pasted_key_in_an_entry_refuses_boot_by_its_field_name() {
        let d = new_dir("providers-key");
        put(
            &d.0,
            "maknae.yaml",
            &format!("core: {{}}\n{PROVIDERS_BLOCK}    api_key: sk-live\n"),
            0o640,
        );
        match owned(&d.0) {
            Err(maknae_config::ConfigError::ProviderPlaintextKey { field }) => {
                assert_eq!(field, "api_key")
            }
            other => panic!("expected ProviderPlaintextKey, got {other:?}"),
        }
    }

    #[cfg(unix)]
    #[test]
    fn a_set_authorized_through_config_d_is_verified_at_its_own_file() {
        let d = new_dir("providers-cd");
        put(&d.0, "maknae.yaml", "core: {}\n", 0o640);
        let cd = d.0.join("config.d");
        std::fs::create_dir(&cd).unwrap();
        std::fs::set_permissions(&cd, std::fs::Permissions::from_mode(0o750)).unwrap();
        put(&cd, "10-providers.yaml", PROVIDERS_BLOCK, 0o640);
        assert!(!owned(&d.0).unwrap().providers().is_empty());
        put(&cd, "10-providers.yaml", PROVIDERS_BLOCK, 0o660);
        match owned(&d.0) {
            Err(maknae_config::ConfigError::SourceNotRootOwned { path }) => {
                assert!(path.ends_with("config.d/10-providers.yaml"), "{path}");
            }
            other => panic!("expected SourceNotRootOwned naming the member, got {other:?}"),
        }
        let wrong = maknae_io::TargetRequired {
            owner: Some(nix::unistd::geteuid().as_raw().wrapping_add(1)),
            ..me()
        };
        put(&cd, "10-providers.yaml", PROVIDERS_BLOCK, 0o640);
        match boot_with_requirement(&d.0, wrong) {
            Err(maknae_config::ConfigError::SourceNotRootOwned { path }) => {
                assert!(
                    path.ends_with("providers-cd"),
                    "the root directory is named: {path}"
                );
            }
            other => panic!("expected SourceNotRootOwned, got {other:?}"),
        }
    }

    #[cfg(unix)]
    #[test]
    fn a_shadowed_providers_entry_with_a_pasted_key_still_refuses_boot() {
        let d = new_dir("providers-shadow");
        put(
            &d.0,
            "maknae.yaml",
            "core: {}\nproviders:\n  - name: openai\n    api_key: sk-live\n",
            0o640,
        );
        let cd = d.0.join("config.d");
        std::fs::create_dir(&cd).unwrap();
        std::fs::set_permissions(&cd, std::fs::Permissions::from_mode(0o750)).unwrap();
        put(&cd, "10-providers.yaml", PROVIDERS_BLOCK, 0o640);
        match owned(&d.0) {
            Err(maknae_config::ConfigError::ProviderPlaintextKey { field }) => {
                assert_eq!(field, "api_key")
            }
            other => panic!("expected ProviderPlaintextKey from the shadowed entry, got {other:?}"),
        }
    }

    #[cfg(unix)]
    #[test]
    fn a_shadowed_providers_block_written_as_a_map_with_a_pasted_key_still_refuses_boot() {
        let d = new_dir("providers-shadow-map");
        put(
            &d.0,
            "maknae.yaml",
            "core: {}\nproviders:\n  token: sk-live\n",
            0o640,
        );
        let cd = d.0.join("config.d");
        std::fs::create_dir(&cd).unwrap();
        std::fs::set_permissions(&cd, std::fs::Permissions::from_mode(0o750)).unwrap();
        put(&cd, "10-providers.yaml", PROVIDERS_BLOCK, 0o640);
        match owned(&d.0) {
            Err(maknae_config::ConfigError::ProviderPlaintextKey { field }) => {
                assert_eq!(field, "token")
            }
            other => panic!("expected ProviderPlaintextKey from the shadowed map, got {other:?}"),
        }
    }

    #[cfg(unix)]
    #[test]
    fn production_boot_refuses_a_providers_block_the_subject_owns() {
        if nix::unistd::geteuid().is_root() {
            return;
        }
        let d = new_dir("providers-prod");
        put(
            &d.0,
            "maknae.yaml",
            &format!("core: {{}}\n{PROVIDERS_BLOCK}"),
            0o640,
        );
        assert!(matches!(
            boot(&d.0),
            Err(maknae_config::ConfigError::SourceNotRootOwned { .. })
        ));
    }

    #[cfg(unix)]
    #[test]
    fn production_boot_holds_every_source_to_root() {
        let d = new_dir("every-source-prod");
        put(&d.0, "maknae.yaml", "core: {}\n", 0o640);
        let cd = d.0.join("config.d");
        std::fs::create_dir(&cd).unwrap();
        std::fs::set_permissions(&cd, std::fs::Permissions::from_mode(0o750)).unwrap();
        put(&cd, "10-lake.yaml", "lake: {}\n", 0o640);
        if nix::unistd::geteuid().is_root() {
            let cfg = boot(&d.0).expect("a root-owned config boots through the production door");
            assert!(cfg.section("lake").is_some());
            put(&cd, "10-lake.yaml", "lake: {}\n", 0o660);
            match read_files(&d.0) {
                Err(maknae_config::ConfigError::SourceNotRootOwned { path }) => {
                    assert!(path.ends_with("config.d/10-lake.yaml"), "{path}")
                }
                other => panic!("expected SourceNotRootOwned naming the member, got {other:?}"),
            }
        } else {
            assert!(matches!(
                read_files(&d.0),
                Err(maknae_config::ConfigError::SourceNotRootOwned { .. })
            ));
            assert!(
                owned(&d.0).is_ok(),
                "the same files load through the hermetic door"
            );
        }
    }

    #[cfg(unix)]
    #[test]
    fn read_files_refuses_a_group_writable_member() {
        let d = new_dir("group-writable");
        put(&d.0, "maknae.yaml", "core: {}\n", 0o660);
        assert!(
            matches!(
                read_files_as_owner(&d.0),
                Err(maknae_config::ConfigError::InsecurePermissions { .. }
                    | maknae_config::ConfigError::SourceNotRootOwned { .. })
            ),
            "{:?}",
            read_files_as_owner(&d.0)
        );
    }

    #[cfg(unix)]
    #[test]
    fn a_shadowed_root_vault_block_naming_the_user_key_layout_reaches_the_root_vault_gate() {
        let d = new_dir("vault-shadow");
        put(
            &d.0,
            "maknae.yaml",
            "core: {}\nvault:\n  addr: https://vault.example:8200\n  kv_mount: maknae-kv\n",
            0o640,
        );
        let cd = d.0.join("config.d");
        std::fs::create_dir(&cd).unwrap();
        std::fs::set_permissions(&cd, std::fs::Permissions::from_mode(0o750)).unwrap();
        put(
            &cd,
            "10-vault.yaml",
            "vault:\n  addr: https://vault.example:8200\n",
            0o640,
        );
        let boot = owned(&d.0).unwrap();
        assert_eq!(
            crate::boot_gate::root_vault_boot_gate(boot.section(VAULT_SECTION)),
            Ok(())
        );
        assert_eq!(
            boot.shadowed_sections(VAULT_SECTION)
                .map(|v| crate::boot_gate::root_vault_boot_gate(Some(v)))
                .collect::<Vec<_>>(),
            [Err(crate::boot_gate::RootVaultKeyRefused("kv_mount"))]
        );
    }
}
