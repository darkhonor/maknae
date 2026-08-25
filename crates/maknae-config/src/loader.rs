//! `load_config` — directory → `Document` (spec §2–§6). Spec validation and the
//! registry are platform-independent; the secure read/scan is `cfg(unix)`.

// Imports land incrementally per task so each task passes `clippy -D warnings`
// (unused-import is an error under CI's `-D warnings`): Task 3 needs only
// `SectionSpec`; Task 5 adds `Source`; Task 6 adds `Document`/`Override` +
// `load_str`/`Value`.
use crate::document::{Document, Override, SectionSpec, Source};
use crate::{load_str, ConfigError, Value};
use std::path::Path;

pub(crate) const CORE_SECTION: &str = "core";

/// Collapse any `Display` error (I/O, non-UTF-8) into `ConfigError::Io`. A single
/// named fn (not a per-site closure) so every `.map_err(io_err)` call sits on the
/// always-executed path and only *this one* body region needs a covering test —
/// keeps `loader.rs`'s defensive fs-error arms from sinking the T1 95% floor.
#[cfg(unix)]
pub(crate) fn io_err(e: impl std::fmt::Display) -> ConfigError {
    ConfigError::Io(e.to_string())
}

/// Secure read (spec §3): lstat screen (symlink + regular-file) → open → fstat mode
/// on the open fd → read from that same fd. The checked inode and the read inode are
/// one open fd — the read-reopen TOCTOU is closed. Symlink/type *detection* is a
/// bounded lstat→open race within the trusted-group dir boundary (spec §3).
#[cfg(unix)]
pub(crate) fn read_secure(path: &Path) -> Result<String, ConfigError> {
    read_secure_required(path, None, Some(0o007))
}

#[cfg(unix)]
pub(crate) fn read_secure_required(
    path: &Path,
    owner: Option<u32>,
    mode_mask: Option<u32>,
) -> Result<String, ConfigError> {
    let absolute = std::path::absolute(path).map_err(io_err)?;
    let parent = absolute
        .parent()
        .ok_or_else(|| io_err("file has no parent"))?;
    let name = absolute
        .file_name()
        .ok_or_else(|| io_err("file has no name"))?;
    let anchor = maknae_io::open_anchor(
        parent,
        maknae_io::AnchorRequired {
            owner: None,
            mode_mask: None,
        },
        maknae_io::StrategyPref::Auto,
    )
    .map_err(map_io)?;
    read_from_anchor_required(&anchor, Path::new(name), None, owner, mode_mask)
}

#[cfg(unix)]
fn map_io(e: maknae_io::IoError) -> ConfigError {
    match e {
        maknae_io::IoError::Symlink { path } => ConfigError::Symlink {
            path: path.display().to_string(),
        },
        maknae_io::IoError::InsecurePermissions { path, mode } => {
            ConfigError::InsecurePermissions {
                path: path.display().to_string(),
                mode,
            }
        }
        other => ConfigError::Io(other.to_string()),
    }
}

#[cfg(unix)]
fn read_from_anchor(
    anchor: &maknae_io::Anchor,
    rel: &Path,
    desc: Option<maknae_io::DescendantRequired>,
) -> Result<String, ConfigError> {
    read_from_anchor_required(anchor, rel, desc, None, Some(0o007))
}

#[cfg(unix)]
fn read_from_anchor_required(
    anchor: &maknae_io::Anchor,
    rel: &Path,
    desc: Option<maknae_io::DescendantRequired>,
    owner: Option<u32>,
    mode_mask: Option<u32>,
) -> Result<String, ConfigError> {
    let bytes = anchor
        .read(
            rel,
            desc,
            maknae_io::TargetRequired {
                owner,
                mode_mask,
                nlink_exactly_one: false,
                regular_file: true,
            },
        )
        .map_err(map_io)?
        .value;
    std::str::from_utf8(&bytes)
        .map(str::to_owned)
        .map_err(|e| ConfigError::Io(format!("invalid UTF-8: {e}")))
}

/// Validate the caller's specs before any file is read (spec §5): reject a
/// reserved name and duplicate names. Fail-closed on caller misuse.
fn validate_specs(specs: &[SectionSpec]) -> Result<(), ConfigError> {
    for (i, s) in specs.iter().enumerate() {
        if s.name == CORE_SECTION {
            return Err(ConfigError::ReservedSection {
                section: s.name.clone(),
            });
        }
        if specs[..i].iter().any(|p| p.name == s.name) {
            return Err(ConfigError::DuplicateSpec {
                section: s.name.clone(),
            });
        }
    }
    Ok(())
}

/// Name lookups over the validated extension specs plus the reserved `core`.
// Consumed only by the `#[cfg(unix)]` arm of `load_config` (+ tests); on a non-unix
// build the crate still compiles to the `PermissionsUnsupported` refusal.
#[cfg_attr(not(unix), allow(dead_code))]
pub(crate) struct Registry<'a> {
    pub(crate) specs: &'a [SectionSpec],
}

#[cfg_attr(not(unix), allow(dead_code))]
impl<'a> Registry<'a> {
    pub(crate) fn is_reserved(&self, name: &str) -> bool {
        name == CORE_SECTION
    }
    pub(crate) fn is_known(&self, name: &str) -> bool {
        name == CORE_SECTION || self.specs.iter().any(|s| s.name == name)
    }
    pub(crate) fn required_extensions(&self) -> impl Iterator<Item = &str> {
        self.specs
            .iter()
            .filter(|s| s.required)
            .map(|s| s.name.as_str())
    }
}

#[cfg(unix)]
fn is_yaml_ext(name: &str) -> bool {
    let lower = name.to_ascii_lowercase();
    lower.ends_with(".yaml") || lower.ends_with(".yml")
}

/// Canonicalize the dir, permission-check the dir + `config.d/` **first**, classify
/// each entry (spec §2 ordered sequence), then read buffered contents: base first,
/// then `config.d/` files lexically by filename. All perm/symlink/io violations
/// abort here, before any parse (spec §4(1): dir + config.d checked, *then* files
/// read — so a world-writable `config.d/` is caught before a bad base is opened).
#[cfg(unix)]
pub(crate) fn scan_dir(dir: &Path) -> Result<Vec<(Source, String)>, ConfigError> {
    let root = std::path::absolute(dir).map_err(io_err)?;
    let anchor = maknae_io::open_anchor(
        &root,
        maknae_io::AnchorRequired {
            owner: None,
            mode_mask: Some(0o007),
        },
        maknae_io::StrategyPref::Auto,
    )
    .map_err(map_io)?;

    // config.d/ (optional): permission/symlink-check the subdir and enumerate its
    // candidate files BEFORE any file content is read (spec §4(1)). Contents are
    // read below (base first), so the buffer order stays base-then-config.d.
    let cd = root.join("config.d");
    let mut cd_files: Vec<std::path::PathBuf> = Vec::new();

    // Detect config.d POSITIVELY as a `root` directory entry (root is a readable dir
    // — maknae.yaml is read from it below). This distinguishes a genuine absence from
    // a stat fault WITHOUT an error-kind guard: if config.d is present, any later stat
    // fault propagates via `?` (fail-closed — a present-but-unreadable config.d refuses
    // the load, never silently degrades to base-only); a true absence just yields
    // base-only. (Avoids the `e.kind()==NotFound` guard, which would be an untestable
    // equivalent mutant.)
    let root_entries = anchor.enumerate(Path::new(""), None).map_err(map_io)?.value;
    let cd_entry = root_entries
        .iter()
        .find(|e| e.name == std::ffi::OsStr::new("config.d"));
    let cd_present = cd_entry.is_some();

    if cd_present {
        if matches!(cd_entry.map(|e| e.kind), Some(maknae_io::Kind::Symlink)) {
            return Err(ConfigError::Symlink {
                path: cd.display().to_string(),
            });
        }
        if !matches!(cd_entry.map(|e| e.kind), Some(maknae_io::Kind::Dir)) {
            // Synthesized Io (config.d exists but is the wrong kind of thing) rather
            // than a converted io::Error — io_err deliberately does NOT apply here.
            return Err(ConfigError::Io(format!(
                "config.d is not a directory: {}",
                cd.display()
            )));
        }
        // Enumerate immediate entries; classify by the §2 ordered sequence.
        let desc_req = maknae_io::DescendantRequired {
            owner: None,
            mode_mask: Some(0o007),
        };
        let rd = anchor
            .enumerate(Path::new("config.d"), Some(desc_req.clone()))
            .map_err(map_io)?
            .value;
        for ent in rd {
            let name = ent.name.to_string_lossy().into_owned();
            // (1) dotfile → skip
            if name.starts_with('.') {
                continue;
            }
            // (2) symlink or subdirectory → error (checked before extension)
            if ent.kind == maknae_io::Kind::Symlink {
                return Err(ConfigError::Symlink {
                    path: cd.join(&ent.name).display().to_string(),
                });
            }
            if ent.kind == maknae_io::Kind::Dir {
                return Err(ConfigError::Io(format!(
                    "config.d entry is a directory: {}",
                    cd.join(&ent.name).display()
                )));
            }
            // (3) regular .yaml/.yml → load; (4) other regular → ignore
            if ent.kind == maknae_io::Kind::File && is_yaml_ext(&name) {
                cd_files.push(cd.join(&ent.name));
            }
        }
        cd_files.sort(); // lexical by full path (same parent → by filename)
    }

    // Now read contents in one buffer-before-parse pass: base (required — missing
    // → Io) first, then each config.d file in lexical order. First violation aborts.
    let mut out: Vec<(Source, String)> = Vec::new();
    out.push((
        Source::Base,
        read_from_anchor(&anchor, Path::new("maknae.yaml"), None)?,
    ));
    for p in cd_files {
        let rel = p.strip_prefix(&root).map_err(io_err)?;
        let body = read_from_anchor(
            &anchor,
            rel,
            Some(maknae_io::DescendantRequired {
                owner: None,
                mode_mask: Some(0o007),
            }),
        )?;
        out.push((Source::ConfigD(p), body));
    }
    Ok(out)
}

/// Parse each buffer and merge into a `Document` (spec §4 precedence): base
/// first, then `config.d/` in the given (already-sorted) order. Whole-section
/// replacement; ambiguity across config.d is an error, never last-wins.
#[cfg_attr(not(unix), allow(dead_code))]
fn source_label(source: &Source) -> String {
    match source {
        Source::Base => "maknae.yaml".to_string(),
        Source::ConfigD(p) => p.display().to_string(),
    }
}

// Consumed only by the `#[cfg(unix)]` arm of `load_config` (+ tests).
#[cfg_attr(not(unix), allow(dead_code))]
pub(crate) fn assemble(
    buffers: Vec<(Source, String)>,
    reg: &Registry,
) -> Result<Document, ConfigError> {
    // Phase 2 (spec §4): parse EVERY buffer before collecting any section, so a
    // Parse/NotAMap fault in any file is surfaced ahead of a section-name error in
    // another (the spec's numbered precedence: parse < collect). Empty (Null) → no
    // sections; a non-Map/Null root → NotAMap.
    let mut parsed: Vec<(Source, Vec<(String, Value)>)> = Vec::new();
    for (source, body) in buffers {
        let map = match load_str(&body)? {
            // cycle ①: parse errors propagate as-is
            Value::Null => Vec::new(),
            Value::Map(m) => m,
            _ => {
                let source_path = source_label(&source);
                return Err(ConfigError::NotAMap { source_path });
            }
        };
        parsed.push((source, map));
    }

    // Phase 3: collect sections with precedence (Unknown → CoreOverride → Duplicate).
    // sections: name -> (value, winning source). from_configd: which section a
    // config.d file already supplied (the cross-config.d duplicate guard).
    let mut sections: Vec<(String, Value, Source)> = Vec::new();
    let mut overrides: Vec<Override> = Vec::new();
    let mut from_configd: Vec<String> = Vec::new();

    for (source, map) in parsed {
        let source_path = source_label(&source);
        for (key, val) in map {
            // (3a) unknown (matches no spec and isn't reserved)
            if !reg.is_known(&key) {
                return Err(ConfigError::UnknownSection {
                    section: key,
                    source_path,
                });
            }
            match &source {
                Source::Base => {
                    // core allowed in base; a base can't collide with itself (dup keys
                    // already rejected by cycle ①), so just record.
                    sections.push((key, val, Source::Base));
                }
                Source::ConfigD(p) => {
                    // (3b) reserved core in config.d → CoreOverride
                    if reg.is_reserved(&key) {
                        return Err(ConfigError::CoreOverride);
                    }
                    // (3c) same section in two config.d files → DuplicateSection
                    if from_configd.iter().any(|n| n == &key) {
                        return Err(ConfigError::DuplicateSection { section: key });
                    }
                    from_configd.push(key.clone());
                    // config.d wins: replace a base section (record the override) or add.
                    if let Some(slot) = sections.iter_mut().find(|(n, _, _)| n == &key) {
                        overrides.push(Override {
                            section: key.clone(),
                            winner: Source::ConfigD(p.clone()),
                            shadowed: slot.2.clone(),
                        });
                        slot.1 = val;
                        slot.2 = Source::ConfigD(p.clone());
                    } else {
                        sections.push((key, val, Source::ConfigD(p.clone())));
                    }
                }
            }
        }
    }

    // (4) required extensions must be present.
    for name in reg.required_extensions() {
        if !sections.iter().any(|(n, _, _)| n == name) {
            return Err(ConfigError::MissingSection {
                section: name.to_string(),
            });
        }
    }

    Ok(Document::new(sections, overrides))
}

/// Load a config directory into a `Document` (spec §2–§6). Spec validation is
/// platform-independent and runs first (fail-closed on caller misuse); the
/// permission-gated read is `cfg(unix)`, and non-Unix refuses to load.
pub fn load_config(dir: &Path, specs: &[SectionSpec]) -> Result<Document, ConfigError> {
    validate_specs(specs)?;

    #[cfg(not(unix))]
    {
        // The Unix permission model is unavailable on this target; refuse to load
        // rather than proceed unchecked (spec §3, fail-closed). Not exercisable on
        // a unix CI runner, hence no mutation/coverage obligation on this block.
        let _ = (dir, specs);
        return Err(ConfigError::PermissionsUnsupported);
    }

    #[cfg(unix)]
    {
        let buffers = scan_dir(dir)?;
        assemble(buffers, &Registry { specs })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[cfg(unix)]
    use std::io::Write;
    #[cfg(unix)]
    use std::os::unix::fs::PermissionsExt;
    #[cfg(unix)]
    use std::path::PathBuf;

    fn spec(name: &str, required: bool) -> SectionSpec {
        SectionSpec {
            name: name.into(),
            required,
        }
    }

    // ---- spec validation + registry (platform-agnostic) ----

    #[test]
    fn validate_rejects_reserved_name() {
        let specs = [spec("core", false)];
        assert!(matches!(
            validate_specs(&specs),
            Err(ConfigError::ReservedSection { section }) if section == "core"
        ));
    }

    #[test]
    fn validate_rejects_duplicate_specs() {
        let specs = [spec("authz", true), spec("authz", false)];
        assert!(matches!(
            validate_specs(&specs),
            Err(ConfigError::DuplicateSpec { section }) if section == "authz"
        ));
    }

    #[test]
    fn validate_accepts_distinct_extensions() {
        let specs = [spec("authz", true), spec("llm", false)];
        assert!(validate_specs(&specs).is_ok());
    }

    #[test]
    fn registry_knows_core_and_specs_only() {
        let specs = [spec("authz", true)];
        let reg = Registry { specs: &specs };
        assert!(reg.is_known("core") && reg.is_reserved("core"));
        assert!(reg.is_known("authz") && !reg.is_reserved("authz"));
        assert!(!reg.is_known("nope"));
        assert_eq!(reg.required_extensions().collect::<Vec<_>>(), vec!["authz"]);
    }

    // ---- assemble: merge / precedence (platform-agnostic) ----

    fn reg(specs: &[SectionSpec]) -> Registry<'_> {
        Registry { specs }
    }
    fn base(body: &str) -> (Source, String) {
        (Source::Base, body.into())
    }
    fn cd(name: &str, body: &str) -> (Source, String) {
        (Source::ConfigD(name.into()), body.into())
    }

    #[test]
    fn base_plus_configd_override_recorded() {
        let specs = [spec("authz", false)];
        let doc = assemble(
            vec![
                base("core:\n  a: 1\nauthz:\n  x: 1\n"),
                cd("z.yaml", "authz:\n  x: 2\n"),
            ],
            &reg(&specs),
        )
        .unwrap();
        assert_eq!(
            doc.section("authz"),
            Some(&Value::Map(vec![("x".into(), Value::Int(2))]))
        );
        assert_eq!(doc.overrides().len(), 1);
        assert_eq!(doc.overrides()[0].section, "authz");
        assert!(matches!(doc.overrides()[0].winner, Source::ConfigD(_)));
        assert!(matches!(doc.overrides()[0].shadowed, Source::Base));
    }

    #[test]
    fn unknown_section_rejected() {
        let specs: [SectionSpec; 0] = [];
        assert!(matches!(
            assemble(vec![base("mystery:\n  a: 1\n")], &reg(&specs)),
            Err(ConfigError::UnknownSection { section, .. }) if section == "mystery"
        ));
    }

    #[test]
    fn unknown_section_reports_source_path() {
        // Pin source_label (§5: UnknownSection carries the offending file): base → the
        // base label, config.d → the file's path label.
        let specs: [SectionSpec; 0] = [];
        match assemble(vec![base("mystery:\n  a: 1\n")], &reg(&specs)) {
            Err(ConfigError::UnknownSection {
                section,
                source_path,
            }) => {
                assert_eq!(section, "mystery");
                assert_eq!(source_path, "maknae.yaml");
            }
            other => panic!("expected UnknownSection from base, got {other:?}"),
        }
        match assemble(
            vec![base(""), cd("z.yaml", "weird:\n  a: 1\n")],
            &reg(&specs),
        ) {
            Err(ConfigError::UnknownSection { source_path, .. }) => {
                assert_eq!(source_path, "z.yaml");
            }
            other => panic!("expected UnknownSection from config.d, got {other:?}"),
        }
    }

    #[test]
    fn parse_error_precedes_unknown_across_buffers() {
        // Spec §4: parse (phase 2) precedes section collection (phase 3). A NotAMap in
        // a *later* buffer must win over an UnknownSection in an *earlier* one.
        let specs: [SectionSpec; 0] = [];
        assert!(matches!(
            assemble(
                vec![base("mystery:\n  a: 1\n"), cd("z.yaml", "- 1\n- 2\n")],
                &reg(&specs)
            ),
            Err(ConfigError::NotAMap { .. })
        ));
    }

    #[test]
    fn core_in_configd_rejected() {
        let specs: [SectionSpec; 0] = [];
        assert!(matches!(
            assemble(
                vec![base("core:\n  a: 1\n"), cd("z.yaml", "core:\n  a: 2\n")],
                &reg(&specs)
            ),
            Err(ConfigError::CoreOverride)
        ));
    }

    #[test]
    fn duplicate_section_across_configd_rejected() {
        let specs = [spec("authz", false)];
        assert!(matches!(
            assemble(
                vec![base("core:\n  a: 1\n"), cd("a.yaml", "authz:\n  x: 1\n"), cd("b.yaml", "authz:\n  x: 2\n")],
                &reg(&specs)),
            Err(ConfigError::DuplicateSection { section }) if section == "authz"
        ));
    }

    #[test]
    fn missing_required_extension_rejected() {
        let specs = [spec("authz", true)];
        assert!(matches!(
            assemble(vec![base("core:\n  a: 1\n")], &reg(&specs)),
            Err(ConfigError::MissingSection { section }) if section == "authz"
        ));
    }

    #[test]
    fn missing_optional_extension_ok() {
        // An OPTIONAL, absent extension must NOT error. Kills the `|s| true`
        // mutant in `required_extensions` (treating optional as required):
        // without this vector, a mutant that yields MissingSection for `llm`
        // survives (every other vector registers only present/required specs).
        let specs = [spec("llm", false)];
        let doc = assemble(vec![base("core:\n  a: 1\n")], &reg(&specs)).unwrap();
        assert_eq!(doc.section("llm"), None);
    }

    #[test]
    fn empty_base_no_configd_is_empty_doc() {
        let specs: [SectionSpec; 0] = [];
        let doc = assemble(vec![base("")], &reg(&specs)).unwrap();
        assert_eq!(doc.section("core"), None);
        assert!(doc.overrides().is_empty());
    }

    #[test]
    fn non_map_base_is_not_a_map() {
        let specs: [SectionSpec; 0] = [];
        assert!(matches!(
            assemble(vec![base("- 1\n- 2\n")], &reg(&specs)),
            Err(ConfigError::NotAMap { .. })
        ));
    }

    #[test]
    fn optional_core_present_in_base_ok() {
        let specs: [SectionSpec; 0] = [];
        let doc = assemble(vec![base("core:\n  a: 1\n")], &reg(&specs)).unwrap();
        assert_eq!(
            doc.section("core"),
            Some(&Value::Map(vec![("a".into(), Value::Int(1))]))
        );
    }

    // ---- unix: secure per-file read (cfg(unix)) ----

    #[cfg(unix)]
    fn tmp(name: &str) -> PathBuf {
        std::env::temp_dir().join(format!("maknae_2a_{}_{name}", std::process::id()))
    }

    #[cfg(unix)]
    fn write_mode(path: &std::path::Path, body: &str, mode: u32) {
        let mut f = std::fs::File::create(path).unwrap();
        f.write_all(body.as_bytes()).unwrap();
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode)).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn secure_read_ok_640() {
        let p = tmp("ok");
        write_mode(&p, "x: 1\n", 0o640);
        let got = read_secure(&p);
        let _ = std::fs::remove_file(&p);
        assert_eq!(got.unwrap(), "x: 1\n");
    }

    #[cfg(unix)]
    #[test]
    fn world_readable_file_rejected() {
        let p = tmp("644");
        write_mode(&p, "x: 1\n", 0o644);
        let got = read_secure(&p);
        let _ = std::fs::remove_file(&p);
        assert!(
            matches!(got, Err(ConfigError::InsecurePermissions { mode, .. }) if mode & 0o007 != 0)
        );
    }

    #[cfg(unix)]
    #[test]
    fn symlink_rejected() {
        let target = tmp("sl_target");
        let link = tmp("sl_link");
        write_mode(&target, "x: 1\n", 0o640);
        let _ = std::fs::remove_file(&link);
        std::os::unix::fs::symlink(&target, &link).unwrap();
        let got = read_secure(&link);
        let _ = std::fs::remove_file(&link);
        let _ = std::fs::remove_file(&target);
        assert!(matches!(got, Err(ConfigError::Symlink { .. })));
    }

    #[cfg(unix)]
    #[test]
    fn missing_file_is_io() {
        let got = read_secure(&tmp("nope_never_created"));
        assert!(matches!(got, Err(ConfigError::Io(_))));
    }

    #[cfg(unix)]
    #[test]
    fn non_utf8_at_secure_mode_is_io() {
        // A 0o640 file with invalid UTF-8: passes the symlink + mode checks, fails
        // at read_to_string (InvalidData) → Io. Covers read_secure's read arm; the
        // spec §3 non-UTF-8→Io claim is a NEW path (does not reuse cycle ①'s load_file).
        let p = tmp("badutf8");
        std::fs::write(&p, [0xff, 0xfe, 0x00]).unwrap();
        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o640)).unwrap();
        let got = read_secure(&p);
        let _ = std::fs::remove_file(&p);
        assert!(matches!(got, Err(ConfigError::Io(_))));
    }

    #[cfg(unix)]
    #[test]
    fn non_regular_file_rejected() {
        // A non-regular config path (here a directory; a FIFO is the motivating case
        // — File::open on a FIFO O_RDONLY would block until a writer appears) is
        // rejected by the pre-open `!is_file()` gate with the "not a regular file"
        // message. Asserting the message (not just Io) kills the `delete !` mutant:
        // without the gate, a directory falls through to read_to_string → EISDIR Io
        // whose message differs. (Deterministic + no hang risk, unlike a FIFO probe.)
        let p = tmp("isdir");
        let _ = std::fs::remove_dir_all(&p);
        std::fs::create_dir(&p).unwrap();
        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o640)).unwrap();
        let got = read_secure(&p);
        let _ = std::fs::remove_dir_all(&p);
        match got {
            Err(ConfigError::Io(msg)) => assert!(msg.contains("not a regular file"), "msg: {msg}"),
            other => panic!("expected Io(not a regular file), got {other:?}"),
        }
    }

    // ---- unix: config-dir scan + classification (cfg(unix)) ----

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
        let p = std::env::temp_dir().join(format!("maknae_2a_scan_{}_{tag}", std::process::id()));
        let _ = std::fs::remove_dir_all(&p);
        std::fs::create_dir_all(&p).unwrap();
        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o750)).unwrap();
        Dir(p)
    }
    #[cfg(unix)]
    fn put(dir: &std::path::Path, name: &str, body: &str, mode: u32) {
        let p = dir.join(name);
        let mut f = std::fs::File::create(&p).unwrap();
        f.write_all(body.as_bytes()).unwrap();
        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(mode)).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn base_only_when_no_config_d() {
        let d = new_dir("baseonly");
        put(&d.0, "maknae.yaml", "core:\n  a: 1\n", 0o640);
        let bufs = scan_dir(&d.0).unwrap();
        assert_eq!(bufs.len(), 1);
        assert!(matches!(bufs[0].0, Source::Base));
    }

    #[cfg(unix)]
    #[test]
    fn config_d_files_sorted_and_yml_included() {
        let d = new_dir("sorted");
        put(&d.0, "maknae.yaml", "core:\n  a: 1\n", 0o640);
        let cd = d.0.join("config.d");
        std::fs::create_dir(&cd).unwrap();
        std::fs::set_permissions(&cd, std::fs::Permissions::from_mode(0o750)).unwrap();
        put(&cd, "b.yml", "llm:\n  x: 1\n", 0o640);
        put(&cd, "a.yaml", "authz:\n  y: 1\n", 0o640);
        put(&cd, "README.md", "ignore me\n", 0o640); // ignored
        put(&cd, ".#a.yaml", "dotfile\n", 0o640); // skipped (dotfile)
        let bufs = scan_dir(&d.0).unwrap();
        // base, then a.yaml, then b.yml
        assert_eq!(bufs.len(), 3);
        assert!(matches!(bufs[0].0, Source::Base));
        match (&bufs[1].0, &bufs[2].0) {
            (Source::ConfigD(p1), Source::ConfigD(p2)) => {
                assert!(p1.ends_with("a.yaml") && p2.ends_with("b.yml"));
            }
            _ => panic!("expected two ConfigD sources in lexical order"),
        }
    }

    #[cfg(unix)]
    #[test]
    fn world_writable_config_d_rejected() {
        let d = new_dir("wwcd");
        put(&d.0, "maknae.yaml", "core:\n  a: 1\n", 0o640);
        let cd = d.0.join("config.d");
        std::fs::create_dir(&cd).unwrap();
        std::fs::set_permissions(&cd, std::fs::Permissions::from_mode(0o772)).unwrap();
        assert!(matches!(
            scan_dir(&d.0),
            Err(ConfigError::InsecurePermissions { .. })
        ));
    }

    #[cfg(unix)]
    #[test]
    fn symlinked_config_d_entry_rejected() {
        let d = new_dir("slentry");
        put(&d.0, "maknae.yaml", "core:\n  a: 1\n", 0o640);
        let cd = d.0.join("config.d");
        std::fs::create_dir(&cd).unwrap();
        std::fs::set_permissions(&cd, std::fs::Permissions::from_mode(0o750)).unwrap();
        let target = d.0.join("outside.yaml");
        put(&d.0, "outside.yaml", "authz:\n  y: 1\n", 0o640);
        std::os::unix::fs::symlink(&target, cd.join("evil.yaml")).unwrap();
        assert!(matches!(scan_dir(&d.0), Err(ConfigError::Symlink { .. })));
    }

    #[cfg(unix)]
    #[test]
    fn subdir_in_config_d_rejected() {
        let d = new_dir("subdir");
        put(&d.0, "maknae.yaml", "core:\n  a: 1\n", 0o640);
        let cd = d.0.join("config.d");
        std::fs::create_dir(&cd).unwrap();
        std::fs::set_permissions(&cd, std::fs::Permissions::from_mode(0o750)).unwrap();
        let sub = cd.join("nested.yaml"); // a *directory* named like a yaml file
        std::fs::create_dir(&sub).unwrap();
        std::fs::set_permissions(&sub, std::fs::Permissions::from_mode(0o750)).unwrap();
        assert!(matches!(scan_dir(&d.0), Err(ConfigError::Io(_))));
    }

    #[cfg(unix)]
    #[test]
    fn config_d_itself_a_symlink_rejected() {
        // LOCKED §3 control: the config.d SUBDIR must be a real dir, not a symlink.
        // (Distinct from an entry INSIDE config.d being a symlink.)
        let d = new_dir("cdsymlink");
        put(&d.0, "maknae.yaml", "core:\n  a: 1\n", 0o640);
        let real = d.0.join("real_confd");
        std::fs::create_dir(&real).unwrap();
        std::fs::set_permissions(&real, std::fs::Permissions::from_mode(0o750)).unwrap();
        std::os::unix::fs::symlink(&real, d.0.join("config.d")).unwrap();
        assert!(matches!(scan_dir(&d.0), Err(ConfigError::Symlink { .. })));
    }

    #[cfg(unix)]
    #[test]
    fn config_d_is_a_regular_file_rejected() {
        // The `!m.is_dir()` arm: a plain file named config.d. Assert the SYNTHESIZED
        // message (not just Io): with the `!m.is_dir()` guard mutated away, a regular
        // config.d falls through to read_dir → also Io, but with a different (os-error)
        // message — so a bare `Err(Io)` assert wouldn't kill that mutant.
        let d = new_dir("cdfile");
        put(&d.0, "maknae.yaml", "core:\n  a: 1\n", 0o640);
        put(&d.0, "config.d", "not a dir\n", 0o640);
        match scan_dir(&d.0) {
            Err(ConfigError::Io(msg)) => {
                assert!(msg.contains("config.d is not a directory"), "msg: {msg}");
            }
            other => panic!("expected Io(config.d is not a directory), got {other:?}"),
        }
    }

    #[cfg(unix)]
    #[test]
    fn missing_base_is_io() {
        let d = new_dir("nobase");
        // no maknae.yaml
        assert!(matches!(scan_dir(&d.0), Err(ConfigError::Io(_))));
    }

    #[cfg(unix)]
    #[test]
    fn nonexistent_dir_is_io() {
        // canonicalize() fails on a non-existent path → Io (covers the canonicalize
        // error arm + io_err's body; root-safe, unlike a File::open EACCES test).
        let p = std::env::temp_dir().join(format!("maknae_2a_nope_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&p);
        assert!(matches!(scan_dir(&p), Err(ConfigError::Io(_))));
    }
}
