//! Cycle: config-boot — the kernel's boot sequence over Maknae's own config.
//! Loads the config directory, reads the `core` classification ceiling into the
//! runtime ingest posture, and fails closed on any error. Maknae reads only its
//! own config; nothing external is read at boot.

use maknae_config::{
    ceiling_from_core, load_config, Ceiling, ConfigError, Document, IngestPosture, SectionSpec,
    Value, AUDIT_SECTION, TRANSPORT_SECTION,
};
use maknae_vault::VAULT_SECTION;
use std::path::Path;

/// The reserved, inert extension section for Maknae's own long-term-memory
/// subsystem (forthcoming). Registered so a present `lake` block loads and is
/// carried, but nothing reads it yet.
const LAKE_SECTION: &str = "lake";

/// The assembled boot configuration: the loaded document + the resolved ceiling.
#[derive(Debug)]
pub struct BootConfig {
    document: Document,
    ceiling: Ceiling,
}

impl BootConfig {
    /// Access a loaded section's value (schema-agnostic; the subsystem parses it).
    pub fn section(&self, name: &str) -> Option<&Value> {
        self.document.section(name)
    }

    /// The resolved classification ceiling (`core.handling.ceiling`, or the baseline).
    pub fn ceiling(&self) -> &Ceiling {
        &self.ceiling
    }

    /// The full loaded document — handed to `PlaneClient::from_document` so the daemon
    /// loads its config ONCE (this boot, registering every section it uses) instead of
    /// the plane client re-loading under a `vault`-only registry that would reject
    /// boot's `lake`/`transport`/`audit` sections as `UnknownSection` (P1-A).
    pub fn document(&self) -> &Document {
        &self.document
    }

    /// The coarse ingest posture derived from the ceiling.
    pub fn ingest_posture(&self) -> IngestPosture {
        self.ceiling.ingest_posture()
    }
}

/// Boot the kernel over Maknae's config directory: load the config ONCE with every
/// section the daemon uses registered (`core` is auto-registered; `lake`+`vault`+
/// `transport`+`audit` as optional extensions), read the `core` ceiling, and return the
/// assembled `BootConfig`. The `vault` block is registered here — rather than re-loaded
/// later under a `vault`-only registry — so the SAME document boots the kernel AND backs
/// `PlaneClient::from_document`; a realistic combined config loads coherently while a
/// genuinely-unknown section still fails closed with `UnknownSection` (P1-A).
/// Fail-closed: any `ConfigError` short-circuits.
pub fn boot(config_dir: &Path) -> Result<BootConfig, ConfigError> {
    // `vault` is registered optional (not required) so the existing minimal-config boot
    // tests — and any core-only deployment — still load; the daemon's actual dependence
    // on a vault block fails closed later at `from_document`/`mint` (MissingKey).
    let specs = [
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
    ];
    let document = load_config(config_dir, &specs)?;
    let ceiling = ceiling_from_core(document.section("core"))?;
    Ok(BootConfig { document, ceiling })
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
        assert_eq!(cfg.ceiling(), &maknae_config::Ceiling::baseline());
        assert_eq!(cfg.ingest_posture(), maknae_config::IngestPosture::Public);
        assert!(cfg.section("core").is_some());
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
        assert_eq!(
            cfg.ceiling().classification,
            maknae_config::Classification::Secret
        );
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
    fn missing_base_is_io() {
        let d = new_dir("nobase"); // no maknae.yaml
        assert!(matches!(boot(&d.0), Err(maknae_config::ConfigError::Io(_))));
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
}
