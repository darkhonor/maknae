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

/// The requirement a `maknae.yaml` / `config.d` member carries: a regular file with NO
/// other-class access (`mode & 0o007 == 0`). Ownership is left to OS DAC — the config
/// tree is the operator's own, and the root-controlled artifacts state their owner
/// requirement in [`ROOT_ARTIFACT`] instead.
///
/// A named const, not a positional pair, per issue #132: `read_secure_required(path,
/// None, Some(0o007))` passed a requirement the `std-fs-drift` inventory could not see,
/// because a positional `None` carries no field name to match on. The requirement is
/// now one reviewed line that the gate inventories.
#[cfg(unix)]
pub(crate) const CONFIG_ARTIFACT: maknae_io::TargetRequired = maknae_io::TargetRequired {
    owner: None,
    mode_mask: Some(0o007),
    nlink_exactly_one: false,
    regular_file: true,
    max_bytes: None,
};

/// The requirement a root-controlled host artifact carries ([`crate::load_root_file`]):
/// root-owned, regular, and not writable by group or other. Owner is named here rather
/// than passed positionally for the same reason as [`CONFIG_ARTIFACT`].
#[cfg(unix)]
pub(crate) const ROOT_ARTIFACT: maknae_io::TargetRequired = maknae_io::TargetRequired {
    owner: Some(0),
    mode_mask: Some(0o022),
    nlink_exactly_one: false,
    regular_file: true,
    max_bytes: None,
};

/// Secure read (spec §3): lstat screen (symlink + regular-file) → open → fstat mode
/// on the open fd → read from that same fd. The checked inode and the read inode are
/// one open fd — the read-reopen TOCTOU is closed. Symlink/type *detection* is a
/// bounded lstat→open race within the trusted-group dir boundary (spec §3).
#[cfg(unix)]
pub(crate) fn read_secure(path: &Path) -> Result<String, ConfigError> {
    read_secure_required(path, CONFIG_ARTIFACT)
}

#[cfg(unix)]
/// Single-path read. Absolutization, parent pinning and the anchor-relative open all
/// live in [`maknae_io::read_absolute`] (issue #137); this function is the crate's
/// error mapping and UTF-8 decode, nothing more. The hand-rolled copy that stood here
/// is exactly the duplication `maknae-io` exists to remove.
pub(crate) fn read_secure_required(
    path: &Path,
    target: maknae_io::TargetRequired,
) -> Result<String, ConfigError> {
    let bytes = maknae_io::read_absolute(path, target, maknae_io::StrategyPref::Auto)
        .map_err(map_io)?
        .value;
    decode_utf8(&bytes)
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
        maknae_io::IoError::Io {
            kind: maknae_io::IoKind::NotFound,
            path,
        } => ConfigError::NotFound {
            path: path.display().to_string(),
        },
        other => ConfigError::Io(other.to_string()),
    }
}

/// The reusable-anchor read: `scan_dir` opens the config directory ONCE and reads every
/// member relative to that one pinned fd, so it cannot go through
/// [`maknae_io::read_absolute`] (which pins a fresh parent per call). The single-path
/// callers do, and the `_required` variant that used to bridge the two is gone with them.
#[cfg(unix)]
fn read_from_anchor(
    anchor: &maknae_io::Anchor,
    rel: &Path,
    desc: Option<maknae_io::DescendantRequired>,
) -> Result<RawSource, ConfigError> {
    Ok(anchor
        .read(rel, desc, CONFIG_ARTIFACT)
        .map_err(map_io)?
        .value)
}

#[cfg(unix)]
fn decode_utf8(bytes: &[u8]) -> Result<String, ConfigError> {
    std::str::from_utf8(bytes)
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
    scan_dir_anchored(dir).map(|(_, buffers)| buffers)
}

/// [`scan_dir`], returning the anchor the scan was read through as well, so a
/// caller that must re-judge the directory later ([`load_config_root_owned`]) asks
/// the SAME open fd -- the standing `maknae-io` rule that the checked inode is
/// the used inode. A second `open_anchor_resolved` on the path would follow a
/// top-level symlink again, and one repointed between the two opens would hand
/// verification a different tree than the scan read (codex review round 3,
/// 2026-09-07).
#[cfg(unix)]
pub(crate) fn scan_dir_anchored(
    dir: &Path,
) -> Result<(maknae_io::Anchor, Vec<(Source, String)>), ConfigError> {
    let (anchor, raw) = scan_dir_raw(dir)?;
    Ok((anchor, decode_all(raw)?))
}

#[cfg(unix)]
type RawSource = maknae_io::Zeroizing<Vec<u8>>;

#[cfg(unix)]
fn decode_all(raw: Vec<(Source, RawSource)>) -> Result<Vec<(Source, String)>, ConfigError> {
    raw.into_iter()
        .map(|(source, bytes)| Ok((source, decode_utf8(&bytes)?)))
        .collect()
}

/// The scan's bytes, undecoded, so a source can be judged before anything is made of them.
#[cfg(unix)]
fn scan_dir_raw(dir: &Path) -> Result<(maknae_io::Anchor, Vec<(Source, RawSource)>), ConfigError> {
    let root = std::path::absolute(dir).map_err(io_err)?;
    let anchor = maknae_io::open_anchor_resolved(
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
    let mut out: Vec<(Source, RawSource)> = Vec::new();
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
    Ok((anchor, out))
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
    let mut shadowed: Vec<(String, Value, Source)> = Vec::new();
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
                        shadowed.push((
                            key.clone(),
                            std::mem::replace(&mut slot.1, val),
                            slot.2.clone(),
                        ));
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

    Ok(Document::new(sections, overrides, shadowed))
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

/// [`load_config`], plus: every scanned source -- each winner AND each shadowed
/// `config.d/` member -- and the directories that select among them (the config
/// root and `config.d/`) must be root-owned and not group/other-writable
/// ([`ROOT_ARTIFACT`]), each source re-read through the scan's anchor and compared
/// byte-for-byte with what was loaded (#490). Non-Unix refuses to load.
pub fn load_config_root_owned(dir: &Path, specs: &[SectionSpec]) -> Result<Document, ConfigError> {
    #[cfg(not(unix))]
    {
        let _ = (dir, specs);
        return Err(ConfigError::PermissionsUnsupported);
    }
    #[cfg(unix)]
    {
        load_config_rooted_with(dir, specs, ROOT_ARTIFACT)
    }
}

/// The hermetic door for [`load_config_root_owned`]: the owner requirement is the
/// caller's. Feature-gated, non-default; production goes through
/// [`load_config_root_owned`] only.
#[cfg(all(unix, feature = "hermetic-test-seam"))]
pub fn load_config_root_owned_with_requirement(
    dir: &Path,
    specs: &[SectionSpec],
    requirement: maknae_io::TargetRequired,
) -> Result<Document, ConfigError> {
    load_config_rooted_with(dir, specs, requirement)
}

#[cfg(unix)]
fn load_config_rooted_with(
    dir: &Path,
    specs: &[SectionSpec],
    requirement: maknae_io::TargetRequired,
) -> Result<Document, ConfigError> {
    validate_specs(specs)?;
    // The anchor the scan read through is the one every later check asks.
    let (anchor, raw) = scan_dir_raw(dir)?;
    let root = std::path::absolute(dir).map_err(io_err)?;
    verify_selection_dirs(&anchor, &root, &requirement).map_err(|failed| {
        ConfigError::SourceNotRootOwned {
            path: failed.display().to_string(),
        }
    })?;
    for (source, body) in &raw {
        verify_root_source(&anchor, &root, source, body, &requirement).map_err(|()| {
            ConfigError::SourceNotRootOwned {
                path: source_label(source),
            }
        })?;
    }
    assemble(decode_all(raw)?, &Registry { specs })
}

/// The directories that decide which candidate is scanned: the config root, and
/// `config.d/` when it exists, must both satisfy `requirement`'s owner and not be
/// group/other-writable. Checked ONCE per load, independent of which source
/// won -- a subject-writable `config.d/`
/// lets the subject hide a root-authored override and hand the win to the base
/// file (codex review round 2, 2026-09-07). `anchor` is the directory the scan read
/// through, re-judged on its held fd (`Anchor::require`), not reopened by path.
/// `Err` carries the directory the check itself refused -- `root`, or
/// `root/config.d` when ITS owner or mode was the finding -- so the refusal
/// names the thing to fix (codex review round 3). A fault that is not an
/// owner/mode finding on `config.d` (an `EACCES` opening it because the root's
/// own search bit went away underneath the held fd) names the root, not a
/// directory that was never judged (round 4).
#[cfg(unix)]
pub(crate) fn verify_selection_dirs(
    anchor: &maknae_io::Anchor,
    root: &Path,
    requirement: &maknae_io::TargetRequired,
) -> Result<(), std::path::PathBuf> {
    anchor
        .require(&maknae_io::AnchorRequired {
            owner: requirement.owner,
            mode_mask: Some(0o022),
        })
        .map_err(|_| root.to_path_buf())?;
    let entries = anchor
        .enumerate(Path::new(""), None)
        .map_err(|_| root.to_path_buf())?
        .value;
    if entries
        .iter()
        .any(|e| e.name == std::ffi::OsStr::new("config.d"))
    {
        // Enumerating under the descendant requirement is the check: a
        // `config.d/` the requirement owner does not hold, or that group/other
        // can write, is refused before anything in it is looked at.
        anchor
            .enumerate(
                Path::new("config.d"),
                Some(maknae_io::DescendantRequired {
                    owner: requirement.owner,
                    mode_mask: Some(0o022),
                }),
            )
            .map_err(|e| match e {
                maknae_io::IoError::InsecurePermissions { path, .. }
                | maknae_io::IoError::NotOwned { path, .. } => path,
                _ => root.to_path_buf(),
            })?;
    }
    Ok(())
}

/// The re-verification behind [`load_config_root_owned`], on one source: the config
/// root directory must satisfy `requirement`'s owner and not be group/other-
/// writable; a `config.d/` source additionally requires `config.d/` itself to;
/// the file is re-read under `requirement`; and the bytes must equal `expected`.
/// Any failure is `Err(())` — the caller names the section and the path. Kept
/// as its own function so the byte-equality half can be tested with bytes that
/// DIFFER, which no single load can produce deterministically. `anchor` is the
/// directory the scan read through; the source is re-read through it, never
/// through a second open of `root`.
#[cfg(unix)]
pub(crate) fn verify_root_source(
    anchor: &maknae_io::Anchor,
    root: &Path,
    source: &Source,
    expected: &[u8],
    requirement: &maknae_io::TargetRequired,
) -> Result<(), ()> {
    let rel: std::path::PathBuf = match source {
        Source::Base => Path::new("maknae.yaml").to_path_buf(),
        Source::ConfigD(p) => p.strip_prefix(root).map_err(|_| ())?.to_path_buf(),
    };
    // The DIRECTORY decides which candidate is scanned: it is held to the same
    // owner as the file, and must not be writable by group or other.
    anchor
        .require(&maknae_io::AnchorRequired {
            owner: requirement.owner,
            mode_mask: Some(0o022),
        })
        .map_err(|_| ())?;
    let desc = match source {
        Source::Base => None,
        Source::ConfigD(_) => Some(maknae_io::DescendantRequired {
            owner: requirement.owner,
            mode_mask: Some(0o022),
        }),
    };
    let reread = anchor
        .read(&rel, desc, requirement.clone())
        .map_err(|_| ())?
        .value;
    if reread.as_slice() != expected {
        // Changed between the two reads: the checked bytes are not the used
        // bytes, and the fail-closed answer is the same as a failed check.
        return Err(());
    }
    Ok(())
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

    /// The OWNER-requirement success arm of `read_secure_required`, hermetically
    /// (issue #138). `load_root_file` names `ROOT_ARTIFACT` — `owner: Some(0)` — which
    /// an unprivileged test can never satisfy, so this arm used to be reached by
    /// loading the host's real root-owned `/etc/hosts`. That made a security control
    /// depend on host state: a runner whose `/etc/hosts` shipped a different owner or
    /// mode failed the suite for a reason that says nothing about the loader, and one
    /// that shipped a *more* permissive mode passed it without exercising the check.
    ///
    /// The requirement is caller-supplied, so the same production path takes a fixture
    /// this test owns: require the CURRENT euid, which the just-created file genuinely
    /// has. It is a real owner comparison against a real inode — no injected uid, no
    /// stand-in — and it is the only positive owner case on this path.
    #[cfg(unix)]
    #[test]
    fn owner_requirement_matching_the_real_owner_is_accepted() {
        use std::os::unix::fs::MetadataExt;
        let p = tmp("owned_by_me");
        write_mode(&p, "x: 1\n", 0o640);
        let me = std::fs::metadata(&p).unwrap().uid();
        let got = read_secure_required(
            &p,
            maknae_io::TargetRequired {
                owner: Some(me),
                mode_mask: Some(0o022),
                nlink_exactly_one: false,
                regular_file: true,
                max_bytes: None,
            },
        );
        let _ = std::fs::remove_file(&p);
        assert_eq!(got.unwrap(), "x: 1\n");
    }

    /// And the refusal arm of the same comparison, on the same shape: an owner the
    /// fixture cannot have. Together these two kill the owner check's constant-return
    /// mutants — a refusal test alone leaves "always refuse" alive.
    #[cfg(unix)]
    #[test]
    fn owner_requirement_naming_another_uid_is_refused() {
        use std::os::unix::fs::MetadataExt;
        let p = tmp("owned_by_someone_else");
        write_mode(&p, "x: 1\n", 0o640);
        let other = std::fs::metadata(&p).unwrap().uid() + 1;
        let got = read_secure_required(
            &p,
            maknae_io::TargetRequired {
                owner: Some(other),
                mode_mask: Some(0o022),
                nlink_exactly_one: false,
                regular_file: true,
                max_bytes: None,
            },
        );
        let _ = std::fs::remove_file(&p);
        // The message names BOTH uids — the one required and the one found — so the
        // assertion cannot pass on an unrelated I/O failure that merely errored.
        assert!(
            matches!(&got, Err(ConfigError::Io(m))
                if m.contains(&format!("require {other}")) && m.contains(&format!("owned by {}", other - 1))),
            "got {got:?}"
        );
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
    fn missing_file_is_not_found() {
        let got = read_secure(&tmp("nope_never_created"));
        // Structured NotFound (PR #139 review): absence is a distinct variant,
        // never a rendered-string convention.
        assert!(matches!(got, Err(ConfigError::NotFound { .. })));
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
    fn symlinked_top_level_config_directory_is_resolved_once() {
        let d = new_dir("top-symlink-target");
        put(&d.0, "maknae.yaml", "core:\n  a: 1\n", 0o640);
        let link = d.0.with_extension("link");
        let _ = std::fs::remove_file(&link);
        std::os::unix::fs::symlink(&d.0, &link).unwrap();
        let got = scan_dir(&link).unwrap();
        let _ = std::fs::remove_file(&link);
        assert_eq!(got.len(), 1);
        assert_eq!(got[0].1, "core:\n  a: 1\n");
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
    fn missing_base_is_not_found() {
        let d = new_dir("nobase");
        // no maknae.yaml
        assert!(matches!(scan_dir(&d.0), Err(ConfigError::NotFound { .. })));
    }

    #[cfg(unix)]
    #[test]
    fn nonexistent_dir_is_not_found() {
        // canonicalize() fails on a non-existent path → Io (covers the canonicalize
        // error arm + io_err's body; root-safe, unlike a File::open EACCES test).
        let p = std::env::temp_dir().join(format!("maknae_2a_nope_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&p);
        assert!(matches!(scan_dir(&p), Err(ConfigError::NotFound { .. })));
    }
    // ---- #243: a root-required section's SOURCE is re-verified under the
    // caller's requirement, whichever file contributed it.
    #[cfg(unix)]
    fn my_uid() -> u32 {
        use std::os::unix::fs::MetadataExt;
        std::fs::metadata(
            std::env::temp_dir().join(format!("maknae_cfg_uid_{}", std::process::id())),
        )
        .or_else(|_| {
            let p = std::env::temp_dir().join(format!("maknae_cfg_uid_{}", std::process::id()));
            std::fs::write(&p, b"").unwrap();
            std::fs::metadata(&p)
        })
        .unwrap()
        .uid()
    }
    /// The anchor a scan of `p` reads through: what the verify functions take.
    #[cfg(unix)]
    fn anchor_of(p: &std::path::Path) -> maknae_io::Anchor {
        scan_dir_anchored(p).unwrap().0
    }
    #[cfg(unix)]
    fn me() -> maknae_io::TargetRequired {
        maknae_io::TargetRequired {
            owner: Some(my_uid()),
            mode_mask: Some(0o022),
            nlink_exactly_one: false,
            regular_file: true,
            max_bytes: None,
        }
    }
    #[cfg(unix)]
    fn not_me() -> maknae_io::TargetRequired {
        maknae_io::TargetRequired {
            owner: Some(my_uid().wrapping_add(1)),
            ..me()
        }
    }
    #[cfg(unix)]
    const PROVIDER: &str =
        "provider:\n  name: p\n  endpoint: https://x/v1\n  model: m\n  key_vault_path: k\n";

    /// The byte-equality half, with bytes that DIFFER: the file satisfies the
    /// requirement, the content is not what was loaded, and that is a refusal.
    /// Removing the comparison turns this red.
    #[cfg(unix)]
    #[test]
    fn a_source_whose_bytes_differ_from_what_was_loaded_is_refused() {
        let d = new_dir("rooted-bytes");
        put(
            &d.0,
            "maknae.yaml",
            &format!("core:\n  a: 1\n{PROVIDER}"),
            0o640,
        );
        let root = std::path::absolute(&d.0).unwrap();
        let anchor = anchor_of(&root);
        let on_disk = std::fs::read(root.join("maknae.yaml")).unwrap();
        assert_eq!(
            verify_root_source(&anchor, &root, &Source::Base, &on_disk, &me()),
            Ok(())
        );
        let mut other = on_disk.clone();
        other.push(b'#');
        assert_eq!(
            verify_root_source(&anchor, &root, &Source::Base, &other, &me()),
            Err(())
        );
        assert_eq!(
            verify_root_source(&anchor, &root, &Source::Base, b"", &me()),
            Err(())
        );
    }

    /// The verification asks the directory the SCAN read, not the path again.
    /// A config path that is a symlink is followed once, at scan; repointing it
    /// afterwards at a tree that would fail the directory requirement changes
    /// nothing, and repointing a failing tree's link at a passing one does not
    /// rescue it. Reopening by path inside either verify function turns this red.
    #[cfg(unix)]
    #[test]
    fn verification_judges_the_scanned_directory_not_a_reopened_path() {
        let good = new_dir("rooted-swap-good");
        put(
            &good.0,
            "maknae.yaml",
            &format!("core:\n  a: 1\n{PROVIDER}"),
            0o640,
        );
        let bad = new_dir("rooted-swap-bad");
        put(
            &bad.0,
            "maknae.yaml",
            &format!("core:\n  a: 1\n{PROVIDER}"),
            0o640,
        );
        // Group-writable: passes the scan's other-class mask, fails the
        // root-required 0o022 mask.
        std::fs::set_permissions(&bad.0, std::fs::Permissions::from_mode(0o770)).unwrap();
        let holder = new_dir("rooted-swap-holder");
        let link = holder.0.join("config");
        let repoint = |to: &std::path::Path| {
            let _ = std::fs::remove_file(&link);
            std::os::unix::fs::symlink(to, &link).unwrap();
        };
        repoint(&good.0);
        let (scanned_good, bufs) = scan_dir_anchored(&link).unwrap();
        repoint(&bad.0);
        let (scanned_bad, _) = scan_dir_anchored(&link).unwrap();
        repoint(&good.0);
        let root = std::path::absolute(&link).unwrap();
        let loaded = bufs[0].1.as_bytes();
        assert_eq!(verify_selection_dirs(&scanned_good, &root, &me()), Ok(()));
        assert_eq!(
            verify_root_source(&scanned_good, &root, &Source::Base, loaded, &me()),
            Ok(())
        );
        repoint(&bad.0);
        assert_eq!(verify_selection_dirs(&scanned_good, &root, &me()), Ok(()));
        assert_eq!(
            verify_root_source(&scanned_good, &root, &Source::Base, loaded, &me()),
            Ok(())
        );
        repoint(&good.0);
        assert_eq!(
            verify_selection_dirs(&scanned_bad, &root, &me()),
            Err(root.clone())
        );
        assert_eq!(
            verify_root_source(&scanned_bad, &root, &Source::Base, loaded, &me()),
            Err(())
        );
    }

    #[cfg(unix)]
    #[test]
    fn a_base_section_a_config_d_member_shadows_is_retained_for_inspection() {
        let d = new_dir("shadowed");
        put(
            &d.0,
            "maknae.yaml",
            "core:\n  a: 1\nprovider:\n  api_key: sk-live\n",
            0o640,
        );
        let cd = d.0.join("config.d");
        std::fs::create_dir(&cd).unwrap();
        std::fs::set_permissions(&cd, std::fs::Permissions::from_mode(0o750)).unwrap();
        put(&cd, "10-provider.yaml", PROVIDER, 0o640);
        let doc = load_config(&d.0, &[spec("provider", false)]).unwrap();
        assert!(matches!(
            doc.source_of("provider"),
            Some(Source::ConfigD(_))
        ));
        let shadowed: Vec<_> = doc.shadowed_sections("provider").collect();
        assert_eq!(shadowed.len(), 1, "the base block is kept, not discarded");
        assert!(format!("{:?}", shadowed[0]).contains("api_key"));
        assert_eq!(doc.shadowed_sections("core").count(), 0);
    }

    /// The directories that select a source are held: a group-writable root or
    /// `config.d/` refuses even when every file passes.
    #[cfg(unix)]
    #[test]
    fn a_selection_directory_the_requirement_owner_does_not_hold_refuses() {
        let d = new_dir("rooted-dir");
        std::fs::set_permissions(&d.0, std::fs::Permissions::from_mode(0o770)).unwrap();
        put(&d.0, "maknae.yaml", "core:\n  a: 1\n", 0o640);
        let specs = [spec("provider", false)];
        assert!(
            load_config(&d.0, &specs).is_ok(),
            "the plain loader accepts 0o770"
        );
        assert!(matches!(
            every(&d.0, &specs, me()),
            Err(ConfigError::SourceNotRootOwned { .. })
        ));
        let d = new_dir("rooted-base-winner");
        put(
            &d.0,
            "maknae.yaml",
            &format!("core:\n  a: 1\n{PROVIDER}"),
            0o640,
        );
        let cd = config_d(&d.0, 0o770);
        match every(&d.0, &specs, me()) {
            Err(ConfigError::SourceNotRootOwned { path }) => {
                assert!(path.ends_with("rooted-base-winner/config.d"), "{path}")
            }
            other => panic!("expected the selection-directory refusal, got {other:?}"),
        }
        std::fs::set_permissions(&cd, std::fs::Permissions::from_mode(0o750)).unwrap();
        assert!(every(&d.0, &specs, me()).is_ok());
    }

    /// The FILE check isolated from the directory checks.
    #[cfg(unix)]
    #[test]
    fn the_file_requirement_is_checked_after_the_directories_pass() {
        let d = new_dir("rooted-file-isolated");
        put(
            &d.0,
            "maknae.yaml",
            &format!("core:\n  a: 1\n{PROVIDER}"),
            0o660,
        );
        let specs = [spec("provider", false)];
        assert_eq!(
            verify_selection_dirs(&anchor_of(&d.0), &std::path::absolute(&d.0).unwrap(), &me()),
            Ok(())
        );
        match every(&d.0, &specs, me()) {
            Err(ConfigError::SourceNotRootOwned { path }) => assert_eq!(path, "maknae.yaml"),
            other => panic!("expected the FILE refusal, got {other:?}"),
        }
    }

    /// The OWNER half of the file check, isolated; needs root to chown.
    #[cfg(unix)]
    #[test]
    fn the_file_owner_is_checked_after_the_directories_pass_root_only() {
        use std::os::unix::fs::MetadataExt;
        if my_uid() != 0 {
            return;
        }
        let d = new_dir("rooted-file-owner");
        put(
            &d.0,
            "maknae.yaml",
            &format!("core:\n  a: 1\n{PROVIDER}"),
            0o640,
        );
        let other = 65534u32;
        std::os::unix::fs::chown(d.0.join("maknae.yaml"), Some(other), None).unwrap();
        assert_eq!(
            std::fs::metadata(d.0.join("maknae.yaml")).unwrap().uid(),
            other
        );
        let specs = [spec("provider", false)];
        assert_eq!(
            verify_selection_dirs(&anchor_of(&d.0), &std::path::absolute(&d.0).unwrap(), &me()),
            Ok(())
        );
        match every(&d.0, &specs, me()) {
            Err(ConfigError::SourceNotRootOwned { path }) => assert_eq!(path, "maknae.yaml"),
            other => panic!("expected the FILE OWNER refusal, got {other:?}"),
        }
    }

    #[cfg(unix)]
    fn every(
        d: &std::path::Path,
        specs: &[SectionSpec],
        requirement: maknae_io::TargetRequired,
    ) -> Result<Document, ConfigError> {
        load_config_rooted_with(d, specs, requirement)
    }

    #[cfg(unix)]
    fn config_d(d: &std::path::Path, mode: u32) -> PathBuf {
        let cd = d.join("config.d");
        std::fs::create_dir(&cd).unwrap();
        std::fs::set_permissions(&cd, std::fs::Permissions::from_mode(mode)).unwrap();
        cd
    }

    #[cfg(unix)]
    #[test]
    fn every_source_is_held_to_the_root_requirement_including_a_shadowed_member() {
        let d = new_dir("every-source");
        put(&d.0, "maknae.yaml", "transport: {}\n", 0o660);
        let cd = config_d(&d.0, 0o750);
        put(&cd, "10-a.yaml", "transport: {}\n", 0o640);
        let specs = [spec("transport", false)];
        let doc = load_config(&d.0, &specs).unwrap();
        assert!(
            matches!(doc.source_of("transport"), Some(Source::ConfigD(_))),
            "premise: the base file contributes nothing that wins"
        );
        match every(&d.0, &specs, me()) {
            Err(ConfigError::SourceNotRootOwned { path }) => assert_eq!(path, "maknae.yaml"),
            other => panic!("expected the shadowed base file refused, got {other:?}"),
        }
        std::fs::set_permissions(
            d.0.join("maknae.yaml"),
            std::fs::Permissions::from_mode(0o640),
        )
        .unwrap();
        assert!(every(&d.0, &specs, me()).is_ok());
        std::fs::set_permissions(cd.join("10-a.yaml"), std::fs::Permissions::from_mode(0o660))
            .unwrap();
        match every(&d.0, &specs, me()) {
            Err(ConfigError::SourceNotRootOwned { path }) => {
                assert!(path.ends_with("config.d/10-a.yaml"), "{path}")
            }
            other => panic!("expected the config.d member refused, got {other:?}"),
        }
    }

    #[cfg(unix)]
    #[test]
    fn a_section_with_no_root_requirement_today_is_held_to_it_now() {
        let d = new_dir("every-no-providers");
        put(&d.0, "maknae.yaml", "core:\n  deployment_id: d\n", 0o640);
        assert!(every(&d.0, &[], me()).is_ok());
        assert!(load_config(&d.0, &[]).is_ok());
        match every(&d.0, &[], not_me()) {
            Err(ConfigError::SourceNotRootOwned { path }) => {
                assert!(path.ends_with("every-no-providers"), "{path}")
            }
            other => panic!("expected the config root refused, got {other:?}"),
        }
    }

    #[cfg(unix)]
    #[test]
    fn a_shadowed_source_owned_by_another_uid_refuses() {
        if my_uid() != 0 {
            eprintln!("skipped: needs root to hand a fixture to another uid");
            return;
        }
        let d = new_dir("every-other-owner");
        put(&d.0, "maknae.yaml", "transport: {}\n", 0o640);
        let cd = config_d(&d.0, 0o750);
        put(&cd, "10-a.yaml", "transport: {}\n", 0o640);
        let specs = [spec("transport", false)];
        assert!(every(&d.0, &specs, me()).is_ok());
        std::os::unix::fs::chown(d.0.join("maknae.yaml"), Some(65534), Some(65534)).unwrap();
        match every(&d.0, &specs, me()) {
            Err(ConfigError::SourceNotRootOwned { path }) => assert_eq!(path, "maknae.yaml"),
            other => panic!("expected the file owner refusal, got {other:?}"),
        }
    }

    #[cfg(unix)]
    #[test]
    fn a_group_writable_config_d_directory_refuses() {
        let d = new_dir("every-group-writable-dir");
        put(&d.0, "maknae.yaml", "core:\n  deployment_id: d\n", 0o640);
        let cd = config_d(&d.0, 0o770);
        assert!(
            load_config(&d.0, &[]).is_ok(),
            "the plain loader accepts 0o770"
        );
        match every(&d.0, &[], me()) {
            Err(ConfigError::SourceNotRootOwned { path }) => {
                assert!(
                    path.ends_with("every-group-writable-dir/config.d"),
                    "{path}"
                )
            }
            other => panic!("expected config.d refused, got {other:?}"),
        }
        std::fs::set_permissions(&cd, std::fs::Permissions::from_mode(0o750)).unwrap();
        assert!(every(&d.0, &[], me()).is_ok());
    }

    #[cfg(unix)]
    #[test]
    fn the_root_owned_production_door_requires_root() {
        let d = new_dir("every-prod");
        put(&d.0, "maknae.yaml", "core:\n  deployment_id: d\n", 0o640);
        let got = load_config_root_owned(&d.0, &[]);
        if my_uid() == 0 {
            assert!(got.is_ok(), "{got:?}");
        } else {
            assert!(
                matches!(got, Err(ConfigError::SourceNotRootOwned { .. })),
                "{got:?}"
            );
        }
        assert!(matches!(
            load_config_root_owned(&d.0, &[spec("core", false)]),
            Err(ConfigError::ReservedSection { .. })
        ));
        assert!(matches!(
            load_config_root_owned(&d.0.join("absent"), &[]),
            Err(ConfigError::NotFound { .. })
        ));
        put(&d.0, "maknae.yaml", "unregistered: {}\n", 0o640);
        let got = load_config_root_owned(&d.0, &[]);
        if my_uid() == 0 {
            assert!(
                matches!(got, Err(ConfigError::UnknownSection { .. })),
                "{got:?}"
            );
        } else {
            assert!(
                matches!(got, Err(ConfigError::SourceNotRootOwned { .. })),
                "{got:?}"
            );
        }
    }

    #[cfg(unix)]
    #[test]
    fn a_source_is_judged_before_its_bytes_are_parsed() {
        let d = new_dir("every-before-parse");
        put(&d.0, "maknae.yaml", "core:\n  deployment_id: d\n", 0o640);
        let cd = config_d(&d.0, 0o750);
        put(&cd, "10-a.yaml", "secret-marker: [unclosed\n", 0o660);
        assert!(matches!(
            load_config(&d.0, &[]),
            Err(ConfigError::Parse { .. })
        ));
        let got = every(&d.0, &[], me());
        match &got {
            Err(ConfigError::SourceNotRootOwned { path }) => {
                assert!(path.ends_with("config.d/10-a.yaml"), "{path}")
            }
            other => panic!("expected the ownership refusal, got {other:?}"),
        }
        assert!(!format!("{got:?}").contains("secret-marker"));
        std::fs::set_permissions(cd.join("10-a.yaml"), std::fs::Permissions::from_mode(0o640))
            .unwrap();
        assert!(matches!(
            every(&d.0, &[], me()),
            Err(ConfigError::Parse { .. })
        ));
        put(&cd, "10-a.yaml", "unregistered: {}\n", 0o640);
        assert!(matches!(
            every(&d.0, &[], me()),
            Err(ConfigError::UnknownSection { .. })
        ));
    }

    #[cfg(unix)]
    #[test]
    fn a_source_is_judged_before_its_bytes_are_decoded() {
        let d = new_dir("every-before-decode");
        put(&d.0, "maknae.yaml", "core:\n  deployment_id: d\n", 0o640);
        let cd = config_d(&d.0, 0o750);
        let member = cd.join("10-a.yaml");
        std::fs::write(&member, [0xff, 0xfe, 0x00]).unwrap();
        std::fs::set_permissions(&member, std::fs::Permissions::from_mode(0o660)).unwrap();
        let invalid_utf8 = |r: Result<Document, ConfigError>| matches!(r, Err(ConfigError::Io(ref m)) if m.contains("invalid UTF-8"));
        assert!(invalid_utf8(load_config(&d.0, &[])));
        match every(&d.0, &[], me()) {
            Err(ConfigError::SourceNotRootOwned { path }) => {
                assert!(path.ends_with("config.d/10-a.yaml"), "{path}")
            }
            other => panic!("expected the ownership refusal, got {other:?}"),
        }
        std::fs::set_permissions(&member, std::fs::Permissions::from_mode(0o640)).unwrap();
        assert!(invalid_utf8(every(&d.0, &[], me())));
    }

    #[cfg(unix)]
    #[test]
    fn a_config_d_member_owned_by_another_uid_refuses_before_its_bytes_are_parsed() {
        if my_uid() != 0 {
            eprintln!("skipped: needs root to hand a fixture to another uid");
            return;
        }
        let d = new_dir("every-member-owner");
        put(&d.0, "maknae.yaml", "core:\n  deployment_id: d\n", 0o640);
        let cd = config_d(&d.0, 0o750);
        put(&cd, "10-a.yaml", "transport: {}\n", 0o640);
        let specs = [spec("transport", false)];
        assert!(every(&d.0, &specs, me()).is_ok());
        crate::tests::test_owner::hand_to_nobody_when_root(&[&cd.join("10-a.yaml")]);
        for body in ["transport: {}\n", "secret-marker: [unclosed\n"] {
            std::fs::write(cd.join("10-a.yaml"), body).unwrap();
            let got = every(&d.0, &specs, me());
            match &got {
                Err(ConfigError::SourceNotRootOwned { path }) => {
                    assert!(path.ends_with("config.d/10-a.yaml"), "{path}")
                }
                other => panic!("expected the member owner refusal, got {other:?}"),
            }
            assert!(!format!("{got:?}").contains("secret-marker"));
        }
    }

    #[cfg(all(unix, feature = "hermetic-test-seam"))]
    #[test]
    fn the_root_owned_seam_applies_the_callers_requirement() {
        let d = new_dir("every-seam");
        put(&d.0, "maknae.yaml", "core:\n  deployment_id: d\n", 0o660);
        assert!(matches!(
            load_config_root_owned_with_requirement(&d.0, &[], me()),
            Err(ConfigError::SourceNotRootOwned { ref path }) if path == "maknae.yaml"
        ));
        put(&d.0, "maknae.yaml", "core:\n  deployment_id: d\n", 0o640);
        assert!(load_config_root_owned_with_requirement(&d.0, &[], me()).is_ok());
        assert!(matches!(
            load_config_root_owned_with_requirement(&d.0, &[], not_me()),
            Err(ConfigError::SourceNotRootOwned { .. })
        ));
    }
}
