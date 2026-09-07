//! Cycle: config-boot — the kernel's boot sequence over Maknae's own config.
//! Loads the config directory, selects the classification system
//! `core.handling.policy` names (ADR-0022), reads the `core` ceiling THROUGH
//! that system into the runtime ingest posture, and fails closed on any error.
//! Maknae reads only its own config; nothing external is read at boot.

use maknae_config::{
    ceiling_from_core, load_config_rooted, policy_name_from_core, provider_from_section, Ceiling,
    ClassificationPolicy, ConfigError, Document, IngestPosture, ProviderConfig, SectionSpec, Value,
    AUDIT_SECTION, PRINCIPAL_SECTION, PROVIDER_SECTION, TRANSPORT_SECTION,
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
    provider: Option<ProviderConfig>,
}

/// The sections whose contributing source must be root-controlled (#243;
/// ADR-0023 decision 3). One today; a name, not a mechanism.
const ROOT_REQUIRED_SECTIONS: [&str; 1] = [PROVIDER_SECTION];

impl std::fmt::Debug for BootConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BootConfig")
            .field("document", &self.document)
            .field("ceiling", &self.ceiling)
            .field("policy", &self.policy.name())
            .field("provider", &self.provider)
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

    /// The one registered model provider (#243), or `None` — a deployment with
    /// no provider boots, and its loop has nothing to prompt.
    pub fn provider(&self) -> Option<&ProviderConfig> {
        self.provider.as_ref()
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

/// Boot the kernel over Maknae's config directory: load the config ONCE with every
/// section the daemon uses registered (`core` is auto-registered; `lake`+`vault`+
/// `transport`+`audit`+`principal` as optional extensions), select the classification
/// system and read the `core` ceiling through it,
/// and return the assembled `BootConfig`. The `vault` block is registered here —
/// rather than re-loaded later under a `vault`-only registry — so the SAME document
/// boots the kernel AND backs `PlaneClient::from_document`; a realistic combined
/// config loads coherently while a genuinely-unknown section still fails closed
/// with `UnknownSection` (P1-A). Fail-closed: any `ConfigError` short-circuits.
pub fn boot(config_dir: &Path) -> Result<BootConfig, ConfigError> {
    // `vault` and `principal` are registered optional (not required) so the existing
    // minimal-config boot tests — and any pre-Jackrabbit deployment written before
    // `maknae enroll` started emitting a `principal` block — still load. The daemon's
    // actual dependence on a vault block fails closed later at `from_document`/`mint`
    // (MissingKey); the authorization layer's dependence on a principal (`~` resolution,
    // Task 6) fails closed there, not here.
    let specs = boot_specs();
    let document = load_config_rooted(config_dir, &specs, &ROOT_REQUIRED_SECTIONS)?;
    assemble_boot(document)
}

/// The hermetic door: the same assembly over a document loaded with the
/// caller's root requirement, so unprivileged tests can prove the provider
/// wiring end to end. Test-only; production is [`boot`].
#[cfg(test)]
fn boot_with_requirement(
    config_dir: &Path,
    requirement: maknae_io::TargetRequired,
) -> Result<BootConfig, ConfigError> {
    let specs = boot_specs();
    let document = maknae_config::load_config_rooted_with_requirement(
        config_dir,
        &specs,
        &ROOT_REQUIRED_SECTIONS,
        requirement,
    )?;
    assemble_boot(document)
}

/// The sections the daemon registers, as literal blocks: the disclosure drift
/// gate reads each registration's `name:` operand from this file, so the list
/// is never built by a loop (and this comment never spells the block's opener).
fn boot_specs() -> [SectionSpec; 6] {
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
            name: PROVIDER_SECTION.to_string(),
            required: false,
        },
    ]
}

/// Everything after the load: the classification system, the ceiling through
/// it, the provider.
fn assemble_boot(document: Document) -> Result<BootConfig, ConfigError> {
    // The SYSTEM first, then the ceiling THROUGH it (ADR-0022): a name this
    // build does not carry refuses boot before any level is read, and a
    // level the selected system does not rank refuses it in the reader.
    let core = document.section("core");
    let name = policy_name_from_core(core)?;
    let policy = crate::classification::select(&name)
        .ok_or(ConfigError::UnknownClassificationPolicy { name })?;
    let ceiling = ceiling_from_core(core, policy)?;
    let provider = provider_from_section(document.section(PROVIDER_SECTION))?;
    Ok(BootConfig {
        document,
        ceiling,
        policy,
        provider,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

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
        let cfg = boot(&d.0).expect("boots");
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
        let cfg = boot(&d.0).expect("boots");
        assert_eq!(cfg.ingest_posture(), maknae_config::IngestPosture::Public);
    }

    #[cfg(unix)]
    #[test]
    fn above_baseline_core_boots_gated() {
        let d = new_dir("secret");
        put(&d.0, "maknae.yaml", SECRET_CORE, 0o640);
        let cfg = boot(&d.0).expect("boots");
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
        let cfg = boot(&d.0).expect("boots");
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
        let cfg = boot(&d.0).expect("boots");
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
        let cfg = boot(&d.0).expect("boots");
        let level = &cfg.ceiling().classification;
        assert_eq!(
            (level.name.as_str(), level.rank),
            ("OFFICIAL: SENSITIVE", 2)
        );
        // Unquoted: refused by the loader, not the ceiling reader.
        let y = y.replace("\"Official: Sensitive\"", "Official: Sensitive");
        put(&d.0, "maknae.yaml", &y, 0o640);
        assert!(
            matches!(boot(&d.0), Err(maknae_config::ConfigError::Parse { .. })),
            "{:?}",
            boot(&d.0)
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
        match boot(&d.0) {
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
        match boot(&d.0) {
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
            boot(&d.0),
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
        let cfg = boot(&d.0).expect("boots");
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
             principal:\n  name: aackerman\n  uid: 1000\n  home: /Users/aackerman\n",
            0o640,
        );
        let cfg = boot(&d.0).expect("boots with a principal block");
        assert!(cfg.section("principal").is_some());
        let p = maknae_config::principal_from_section(cfg.section("principal"))
            .expect("principal parses from the booted document")
            .expect("principal section present");
        assert_eq!(p.name, "aackerman");
        assert_eq!(p.uid, 1000);
        assert_eq!(p.home, std::path::PathBuf::from("/Users/aackerman"));
    }

    // A pre-Jackrabbit config WITHOUT a `principal` block still LOADS — the
    // optional-registration / upgrade property (spec §5.5), scoped to the loader.
    // (Discharged 2026-08-28, #77: the boot gate now REQUIRES the principal —
    // see boot_gate.rs. The loader half here legitimately still loads a
    // principal-less document; the refusal is the kernel gate's, downstream.
    // Historical note: the daemon wouldn't *start* without a principal once authz used `~`
    // — Task 6 covers that; this only pins that the loader doesn't reject it.)
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
        let cfg = boot(&d.0).expect("pre-Jackrabbit config without principal still boots");
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
            boot(&d.0),
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
             audit:\n  path: /var/log/maknae/audit.jsonl\n",
            0o640,
        );
        let cfg = boot(&d.0).expect("combined config boots");
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
            boot(&d.0),
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
            boot(&d.0),
            Err(maknae_config::ConfigError::InvalidCeiling { .. })
        ));
    }

    #[cfg(unix)]
    #[test]
    fn missing_base_is_not_found() {
        let d = new_dir("nobase"); // no maknae.yaml
        assert!(matches!(
            boot(&d.0),
            Err(maknae_config::ConfigError::NotFound { .. })
        ));
    }

    #[cfg(unix)]
    #[test]
    fn world_readable_file_refused() {
        let d = new_dir("644");
        put(&d.0, "maknae.yaml", "core: {}\n", 0o644);
        assert!(matches!(
            boot(&d.0),
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
            boot(&d.0),
            Err(maknae_config::ConfigError::Symlink { .. })
        ));
    }
    // ---- #243: the provider registration, through the hermetic root door.
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
    const PROVIDER_BLOCK: &str = "provider:\n  name: openai\n  endpoint: https://api.openai.com/v1\n  model: gpt-5\n  key_vault_path: maknae/provider/openai\n";

    #[cfg(unix)]
    #[test]
    fn a_registered_provider_is_carried_and_an_absent_one_is_none() {
        let d = new_dir("provider");
        put(
            &d.0,
            "maknae.yaml",
            "core:\n  identity:\n    name: t\n",
            0o640,
        );
        assert_eq!(boot_with_requirement(&d.0, me()).unwrap().provider(), None);
        put(
            &d.0,
            "maknae.yaml",
            &format!("core:\n  identity:\n    name: t\n{PROVIDER_BLOCK}"),
            0o640,
        );
        let cfg = boot_with_requirement(&d.0, me()).unwrap();
        let p = cfg.provider().expect("registered");
        assert_eq!(
            (
                p.name.as_str(),
                p.endpoint.as_str(),
                p.model.as_str(),
                p.key_vault_path.as_str()
            ),
            (
                "openai",
                "https://api.openai.com/v1",
                "gpt-5",
                "maknae/provider/openai"
            )
        );
        assert!(format!("{cfg:?}").contains("openai"));
    }

    #[cfg(unix)]
    #[test]
    fn a_pasted_key_refuses_boot_by_its_field_name() {
        let d = new_dir("provider-key");
        put(
            &d.0,
            "maknae.yaml",
            &format!("core: {{}}\n{PROVIDER_BLOCK}  api_key: sk-live\n"),
            0o640,
        );
        match boot_with_requirement(&d.0, me()) {
            Err(maknae_config::ConfigError::ProviderPlaintextKey { field }) => {
                assert_eq!(field, "api_key")
            }
            other => panic!("expected ProviderPlaintextKey, got {other:?}"),
        }
    }

    #[cfg(unix)]
    #[test]
    fn a_provider_registered_through_config_d_is_verified_at_its_own_file() {
        let d = new_dir("provider-cd");
        put(&d.0, "maknae.yaml", "core: {}\n", 0o640);
        let cd = d.0.join("config.d");
        std::fs::create_dir(&cd).unwrap();
        std::fs::set_permissions(&cd, std::fs::Permissions::from_mode(0o750)).unwrap();
        put(&cd, "10-provider.yaml", PROVIDER_BLOCK, 0o640);
        assert!(boot_with_requirement(&d.0, me())
            .unwrap()
            .provider()
            .is_some());
        let wrong = maknae_io::TargetRequired {
            owner: Some(nix::unistd::geteuid().as_raw().wrapping_add(1)),
            ..me()
        };
        match boot_with_requirement(&d.0, wrong) {
            Err(maknae_config::ConfigError::SectionNotRootOwned { section, path }) => {
                assert_eq!(section, "provider");
                assert!(path.ends_with("config.d/10-provider.yaml"), "{path}");
            }
            other => panic!("expected SectionNotRootOwned, got {other:?}"),
        }
    }

    /// The PRODUCTION `boot()` refuses a provider block the test user owns —
    /// the custody property, proven on every unprivileged lane.
    #[cfg(unix)]
    #[test]
    fn production_boot_refuses_a_provider_block_the_subject_owns() {
        if nix::unistd::geteuid().is_root() {
            return;
        }
        let d = new_dir("provider-prod");
        put(
            &d.0,
            "maknae.yaml",
            &format!("core: {{}}\n{PROVIDER_BLOCK}"),
            0o640,
        );
        assert!(matches!(
            boot(&d.0),
            Err(maknae_config::ConfigError::SectionNotRootOwned { .. })
        ));
    }
}
