use maknae_authz_basic::{shown, AuthzBasicError, PolicySource};
use maknae_config::{
    BindingEntry, Bindings, BoundRole, LiveEdit, MergeEvent, ResolvedBy, Section, SyncKind,
};
use maknae_graph::graph::Graph;
use maknae_graph::sync::SyncBase;
use maknae_state::store::{LiveInitiator, StateDir};
use std::collections::BTreeSet;
use std::path::Path;
use std::sync::{Arc, RwLock};

#[derive(Debug)]
pub struct MergedSource {
    /// Its bindings are the merged live section.
    pub source: PolicySource,
    pub sync: SyncBase,
    pub kind: SyncKind,
    /// `graph.sync` reasons, written ahead.
    pub events: Vec<String>,
    pub refuse_missing: bool,
    pub counts: SyncCounts,
    pub lost: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct SyncCounts {
    pub unsynced: usize,
    pub conflicts: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MergeError {
    /// The stored sync base does not parse: exit 5 at boot, `Compile` at reload.
    Stored(String),
    /// The merged section fails the role rules or an account lookup fails: exit 3 at boot,
    /// `Load` at reload.
    Policy(String),
}

const CREATED: &str = "sync base created from bindings.yaml (the store had none)";

/// Blocking when the merged section differs from the file's (getpwnam).
pub fn merge_source(
    file: PolicySource,
    stored: Option<&SyncBase>,
) -> Result<MergedSource, MergeError> {
    merge_source_with(file, stored, |src, b| src.with_bindings(b))
}

pub fn merge_source_with(
    file: PolicySource,
    stored: Option<&SyncBase>,
    resolve: impl FnOnce(&PolicySource, Bindings) -> Result<PolicySource, AuthzBasicError>,
) -> Result<MergedSource, MergeError> {
    let file_section = Section::of(file.bindings());
    let parsed = stored
        .map(stored_sections)
        .transpose()
        .map_err(MergeError::Stored)?;
    let merged = maknae_config::merge(
        parsed
            .as_ref()
            .map(|(base, live, conflicts)| maknae_config::Stored {
                base,
                live,
                conflicts,
            }),
        &file_section,
    );
    let mut events = Vec::new();
    let mut lost = None;
    for e in &merged.events {
        match e {
            MergeEvent::Lost { .. } => lost = Some(event_reason(e)),
            _ => events.push(event_reason(e)),
        }
    }
    match merged.kind {
        SyncKind::Created => events.insert(0, CREATED.into()),
        SyncKind::Adopted => {
            let n = parsed
                .as_ref()
                .map_or(0, |(b, l, _)| maknae_config::unsynced(b, l));
            events.insert(
                0,
                format!("adopted: bindings.yaml holds the live section ({n} unsynced entries)"),
            );
        }
        SyncKind::Unchanged | SyncKind::RootFile | SyncKind::Lost => {}
    }
    let refuse_missing = file.bindings().is_missing() && stored.is_none();
    let source = if merged.live == file_section {
        file
    } else {
        resolve(&file, Bindings::from_section(&merged.live))
            .map_err(|e| MergeError::Policy(e.to_string()))?
    };
    Ok(MergedSource {
        source,
        sync: SyncBase {
            base: merged.base.canonical(),
            live: merged.live.canonical(),
            conflicts: maknae_config::conflicts_canonical(&merged.conflicts),
        },
        kind: merged.kind,
        events,
        refuse_missing,
        counts: SyncCounts {
            unsynced: maknae_config::unsynced(&merged.base, &merged.live),
            conflicts: merged.conflicts.len(),
        },
        lost,
    })
}

fn unparsed(e: impl std::fmt::Display) -> String {
    format!("the store's sync base does not parse: {e}")
}

pub fn stored_sections(s: &SyncBase) -> Result<(Section, Section, BTreeSet<BindingEntry>), String> {
    Ok((
        Section::from_canonical(&s.base).map_err(unparsed)?,
        Section::from_canonical(&s.live).map_err(unparsed)?,
        maknae_config::conflicts_from_canonical(&s.conflicts).map_err(unparsed)?,
    ))
}

fn entry(e: &BindingEntry) -> String {
    match e {
        BindingEntry::Name(n) => shown(n),
        BindingEntry::Uid(_) => e.render(),
    }
}

pub fn event_reason(e: &MergeEvent) -> String {
    match e {
        MergeEvent::Conflict { entry: x, contained } => format!(
            "conflict: {} changed in bindings.yaml and by an unsynced live transition; failed closed: {}",
            entry(x),
            if *contained { "contained" } else { "unbound" }
        ),
        MergeEvent::Resolved { entry: x, by } => format!(
            "conflict resolved: {}: {}",
            entry(x),
            match by {
                ResolvedBy::RootEdit => "bindings.yaml changed it again",
                ResolvedBy::Sync => "bindings.yaml holds the fail-closed value",
            }
        ),
        MergeEvent::Lost { missing } => format!(
            "lost: bindings.yaml {}; the enforced bindings stand; restore them with sudo maknae policy sync, or run sudo maknae reseed to return to principal-as-admin",
            if *missing { "is missing" } else { "has no bindings: key" }
        ),
    }
}

pub fn live_reason(edit: &LiveEdit, who: LiveInitiator) -> String {
    let what = match edit {
        LiveEdit::Contain(e) => format!("contain {}", entry(e)),
        LiveEdit::Release(e) => format!("release {}", entry(e)),
        LiveEdit::Bind { name, role } => {
            let role = match role {
                BoundRole::Admin => "admin",
                BoundRole::User => "user",
                BoundRole::Guest => "guest",
            };
            format!("bind {role} {}", shown(name))
        }
        LiveEdit::Unbind(name) => format!("unbind {}", shown(name)),
    };
    let who = match who {
        LiveInitiator::Operator => "operator",
        LiveInitiator::Kernel => "kernel",
    };
    format!("live ({who}): {what}")
}

pub fn counts(s: &SyncBase) -> Result<SyncCounts, String> {
    let (base, live, conflicts) = stored_sections(s)?;
    Ok(SyncCounts {
        unsynced: maknae_config::unsynced(&base, &live),
        conflicts: conflicts.len(),
    })
}

pub fn render(graph: &Graph, config_dir: &Path) -> Result<String, String> {
    let sync = maknae_graph::identity::extract(graph)
        .map_err(|e| e.to_string())?
        .sync
        .ok_or("the graph holds no sync base")?;
    let (base, live, conflicts) = stored_sections(&sync)?;
    let header = maknae_config::MirrorHeader {
        revision: graph.revision(),
        config_dir: config_dir
            .to_str()
            .ok_or("the configuration directory is not UTF-8")?
            .to_string(),
        base: maknae_config::base_token(&base, maknae_state::envelope::sha256),
        conflicts,
    };
    let text = maknae_config::render_mirror(&header, &live);
    maknae_config::parse_mirror(&text)
        .map_err(|e| format!("the render does not parse back: {e}"))?;
    Ok(text)
}

/// Ok: `sha256:<12 hex>` of the published bytes.
pub fn publish_mirror(dir: &StateDir, graph: &Graph, config_dir: &Path) -> Result<String, String> {
    let text = render(graph, config_dir)?;
    dir.publish_mirror(text.as_bytes())
        .map_err(|e| format!("publish: {e}"))?;
    let hex: String = maknae_state::envelope::sha256(text.as_bytes())[..6]
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    Ok(format!("sha256:{hex}"))
}

/// On a failure the old mirror is removed and the status marked stale.
pub fn publish_or_remove(
    dir: &StateDir,
    status: &SyncStatus,
    graph: &Graph,
    config_dir: &Path,
) -> Result<String, String> {
    match publish_mirror(dir, graph, config_dir) {
        Ok(hash) => {
            status.set_stale(false);
            Ok(hash)
        }
        Err(cause) => {
            let removal = match dir.remove_mirror() {
                Ok(()) => "the stale mirror was removed".to_string(),
                Err(e) => format!("the stale mirror could not be removed: {e}"),
            };
            status.set_stale(true);
            Err(format!(
                "mirror render failed: {cause}; the transition at revision {} stands; {removal}",
                graph.revision()
            ))
        }
    }
}

/// Counts, the lost flag (written only by `became_lost`), and the stale flag.
#[derive(Debug, Clone, Default)]
pub struct SyncStatus(Arc<RwLock<(SyncCounts, bool, bool)>>);

impl SyncStatus {
    fn write(&self) -> std::sync::RwLockWriteGuard<'_, (SyncCounts, bool, bool)> {
        self.0.write().unwrap_or_else(|p| p.into_inner())
    }

    pub fn set_counts(&self, c: SyncCounts) {
        self.write().0 = c;
    }

    pub fn set_stale(&self, stale: bool) {
        self.write().2 = stale;
    }

    /// True when the flag went from false to true.
    pub fn became_lost(&self, lost: bool) -> bool {
        let was = std::mem::replace(&mut self.write().1, lost);
        lost && !was
    }

    pub fn lines(&self) -> Vec<String> {
        let (c, lost, stale) = *self.0.read().unwrap_or_else(|p| p.into_inner());
        let mut out = vec![
            format!("unsynced={}", c.unsynced),
            format!("conflict={}", c.conflicts),
        ];
        if lost {
            out.push("file=lost".into());
        }
        if stale {
            out.push("mirror=stale".into());
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use maknae_authz_basic::PolicyPaths;
    use maknae_graph::identity::{build, extract, IdentityLayer, SubjectEntry};
    use maknae_graph::kernel::persisted_compiled_set;
    use maknae_graph::record::ProvenanceKind;
    use std::os::unix::fs::{MetadataExt, PermissionsExt};

    const ROOT_BINDINGS: &str = "schema_version: 1\nbindings:\n  admin: [\"root\"]\n";

    fn uids() -> std::collections::BTreeMap<String, u32> {
        [("root".to_string(), 0), ("eve".to_string(), 1001)]
            .into_iter()
            .collect()
    }

    fn hermetic(src: &PolicySource, b: Bindings) -> Result<PolicySource, AuthzBasicError> {
        PolicySource::from_parts(
            src.policy().clone(),
            b,
            uids(),
            src.principal().clone(),
            src.paths().clone(),
        )
    }

    fn source_or_missing(body: Option<&str>) -> PolicySource {
        let bindings = body.map_or_else(Bindings::missing, |b| {
            maknae_config::parse_bindings(b).unwrap()
        });
        PolicySource::from_parts(
            maknae_config::parse_authz("schema_version: 1\n").unwrap(),
            bindings,
            uids(),
            maknae_config::Principal {
                name: "op".into(),
                uid: 1000,
            },
            PolicyPaths::in_dir(Path::new("/etc/maknae")),
        )
        .unwrap()
    }

    fn source(body: &str) -> PolicySource {
        source_or_missing(Some(body))
    }

    fn stored(base: &str, live: &str, conflicts: &str) -> SyncBase {
        SyncBase {
            base: base.into(),
            live: live.into(),
            conflicts: conflicts.into(),
        }
    }

    fn kept_live() -> SyncBase {
        stored(
            r#"{"admin":["root"]}"#,
            r#"{"admin":["root"],"adversary":[{"uid":4242}]}"#,
            "[]",
        )
    }

    fn has(m: &MergedSource, uid: u32, role: &str) -> bool {
        m.source
            .identity_layer("UNCLASSIFIED", None)
            .subjects
            .iter()
            .any(|s| s.uid == uid && s.role == role)
    }

    fn layer(explicit: bool) -> IdentityLayer {
        IdentityLayer {
            source: "/etc/maknae/bindings.yaml".into(),
            label: "UNCLASSIFIED".into(),
            bindings_sha256: explicit.then_some([1; 32]),
            subjects: vec![SubjectEntry {
                uid: 0,
                name: "root".into(),
                role: "admin".into(),
            }],
            aliases: Default::default(),
        }
    }

    fn built(l: &IdentityLayer, s: Option<&SyncBase>, revision: u64) -> Graph {
        build(
            l,
            None,
            s,
            &persisted_compiled_set("UNCLASSIFIED"),
            [9; 32],
            revision,
            ProvenanceKind::RootFile,
        )
        .unwrap()
    }

    fn graph_with(s: &SyncBase, revision: u64) -> Graph {
        built(&layer(true), Some(s), revision)
    }

    fn ghost() -> Graph {
        graph_with(
            &stored(
                r#"{"admin":["root"]}"#,
                r#"{"admin":["root"],"user":["ghost"]}"#,
                r#"["ghost"]"#,
            ),
            9,
        )
    }

    struct Fixture {
        tmp: tempfile::TempDir,
        uid: u32,
    }

    impl Fixture {
        fn new() -> Self {
            let tmp = tempfile::tempdir().unwrap();
            std::fs::set_permissions(tmp.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
            let uid = std::fs::metadata(tmp.path()).unwrap().uid();
            Self { tmp, uid }
        }

        fn dir(&self) -> StateDir {
            StateDir::open_with_marker_owner(self.tmp.path(), self.uid, self.uid).unwrap()
        }

        fn mirror(&self) -> std::path::PathBuf {
            self.tmp.path().join(maknae_config::MIRROR_FILE)
        }
    }

    fn short_hash(bytes: &[u8]) -> String {
        let hex: String = maknae_state::envelope::sha256(bytes)
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect();
        format!("sha256:{}", &hex[..12])
    }

    #[test]
    fn with_no_stored_base_the_file_is_base_and_live_and_the_creation_is_recorded() {
        let m = merge_source(source(ROOT_BINDINGS), None).unwrap();
        assert_eq!(m.kind, SyncKind::Created);
        assert_eq!(
            (
                m.sync.base.as_str(),
                m.sync.live.as_str(),
                m.sync.conflicts.as_str()
            ),
            (r#"{"admin":["root"]}"#, r#"{"admin":["root"]}"#, "[]")
        );
        assert_eq!(
            m.events,
            ["sync base created from bindings.yaml (the store had none)"]
        );
        assert_eq!(m.counts, SyncCounts::default());
        assert_eq!(m.lost, None);
        assert!(!m.refuse_missing);
        assert!(has(&m, 0, "admin"));
    }

    #[test]
    fn an_unchanged_merge_keeps_the_file_without_resolving_it_again() {
        let s = stored(r#"{"admin":["root"]}"#, r#"{"admin":["root"]}"#, "[]");
        let m = merge_source_with(source(ROOT_BINDINGS), Some(&s), |_, _| {
            panic!("an unchanged section is not resolved again")
        })
        .unwrap();
        assert_eq!((m.kind, m.sync.clone()), (SyncKind::Unchanged, s));
        assert!(m.events.is_empty());
        assert!(has(&m, 0, "admin"));
    }

    #[test]
    fn a_kept_live_edit_is_resolved_and_counted() {
        let m = merge_source(source(ROOT_BINDINGS), Some(&kept_live())).unwrap();
        assert_eq!(m.kind, SyncKind::Unchanged);
        assert!(has(&m, 4242, "adversary"));
        assert_eq!(
            m.counts,
            SyncCounts {
                unsynced: 1,
                conflicts: 0
            }
        );
        assert!(m.events.is_empty());
        assert_eq!(m.sync, kept_live());
    }

    #[test]
    fn a_file_that_matches_live_is_adopted_and_says_how_many_entries_it_carried() {
        let file =
            "schema_version: 1\nbindings:\n  admin: [\"root\"]\n  adversary: [{uid: 4242}]\n";
        let m = merge_source(source(file), Some(&kept_live())).unwrap();
        assert_eq!(m.kind, SyncKind::Adopted);
        assert_eq!(
            m.events,
            ["adopted: bindings.yaml holds the live section (1 unsynced entries)"]
        );
        assert_eq!(m.sync.base, m.sync.live);
        assert_eq!(m.counts, SyncCounts::default());
    }

    #[test]
    fn a_conflict_fails_closed_is_written_ahead_and_counted() {
        let s = stored(
            r#"{"admin":["root"],"user":["eve"]}"#,
            r#"{"admin":["root"],"adversary":["eve"]}"#,
            "[]",
        );
        let file = "schema_version: 1\nbindings:\n  admin: [\"root\"]\n  guest: [\"eve\"]\n";
        let m = merge_source_with(source(file), Some(&s), hermetic).unwrap();
        assert_eq!(m.kind, SyncKind::RootFile);
        assert!(has(&m, 1001, "adversary"));
        assert!(!has(&m, 1001, "guest"));
        assert_eq!(
            m.events,
            ["conflict: eve changed in bindings.yaml and by an unsynced live transition; failed closed: contained"]
        );
        assert_eq!(m.sync.conflicts, r#"["eve"]"#);
        assert_eq!(
            m.counts,
            SyncCounts {
                unsynced: 1,
                conflicts: 1
            }
        );
        assert_eq!(m.lost, None);
    }

    #[test]
    fn the_enforced_sections_digests_do_not_depend_on_which_path_built_the_source() {
        let file = "schema_version: 1\n# root's note\nbindings:\n  adversary:\n    - uid: 4242\n    - 'eve'\n  user: []\n  admin: [\"root\"]\n";
        let kept = merge_source_with(source(file), None, |_, _| {
            panic!("a created base keeps the file")
        })
        .unwrap();
        let live = Section::of(kept.source.bindings()).canonical();
        let rebuilt = merge_source_with(
            source_or_missing(None),
            Some(&stored(&live, &live, "[]")),
            hermetic,
        )
        .unwrap();
        assert_eq!(rebuilt.kind, SyncKind::Lost);
        let digests = |m: &MergedSource| m.source.section_digests(maknae_state::envelope::sha256);
        assert!(digests(&kept).contains_key("bindings"));
        assert_eq!(digests(&kept), digests(&rebuilt));
        let layer = |m: &MergedSource| {
            m.source
                .identity_layer("UNCLASSIFIED", digests(m).get("bindings").copied())
        };
        assert_eq!(layer(&kept), layer(&rebuilt));
    }

    #[test]
    fn a_lost_file_keeps_live_resolves_from_it_and_says_so() {
        for (body, missing) in [(None, true), (Some("schema_version: 1\n"), false)] {
            let m = merge_source(source_or_missing(body), Some(&kept_live())).unwrap();
            assert_eq!(m.kind, SyncKind::Lost);
            assert_eq!(m.sync, kept_live(), "base, live and conflicts unchanged");
            assert!(has(&m, 4242, "adversary"));
            assert!(has(&m, 0, "admin"));
            assert!(m.events.is_empty(), "a loss is not written ahead");
            let what = if missing {
                "is missing"
            } else {
                "has no bindings: key"
            };
            assert_eq!(m.lost.as_deref(), Some(format!("lost: bindings.yaml {what}; the enforced bindings stand; restore them with sudo maknae policy sync, or run sudo maknae reseed to return to principal-as-admin").as_str()));
            assert_eq!(
                m.counts,
                SyncCounts {
                    unsynced: 1,
                    conflicts: 0
                }
            );
            assert!(!m.refuse_missing);
        }
        assert!(
            merge_source(source_or_missing(None), None)
                .unwrap()
                .refuse_missing,
            "no sync base: a missing file is still refused"
        );
        let absent = stored("null", "null", "[]");
        assert!(
            !merge_source(source_or_missing(None), Some(&absent))
                .unwrap()
                .refuse_missing
        );
        assert!(
            !merge_source(source_or_missing(Some("schema_version: 1\n")), None)
                .unwrap()
                .refuse_missing
        );
    }

    #[test]
    fn a_corrupt_stored_value_and_a_policy_failure_are_different_errors() {
        let bad = stored("{", "{", "[]");
        assert!(matches!(
            merge_source(source(ROOT_BINDINGS), Some(&bad)),
            Err(MergeError::Stored(_))
        ));
        let live = stored(
            r#"{"admin":["root"]}"#,
            r#"{"admin":["root"],"user":["eve"]}"#,
            "[]",
        );
        let r = merge_source_with(source(ROOT_BINDINGS), Some(&live), |_, _| {
            Err(AuthzBasicError::Bindings(
                "looking up 'eve' failed (errno 5); nothing was changed".into(),
            ))
        });
        assert_eq!(
            r.unwrap_err(),
            MergeError::Policy(
                "authz bindings invalid: looking up 'eve' failed (errno 5); nothing was changed"
                    .into()
            )
        );
    }

    #[test]
    fn the_merged_live_section_is_what_is_resolved() {
        let mut seen = None;
        merge_source_with(source(ROOT_BINDINGS), Some(&kept_live()), |src, b| {
            seen = Some(Section::of(&b).canonical());
            src.with_bindings(b)
        })
        .unwrap();
        assert_eq!(seen.as_deref(), Some(kept_live().live.as_str()));
    }

    #[test]
    fn each_stored_value_is_parsed_and_a_bad_one_is_named() {
        let ok = stored(
            r#"{"admin":["root"]}"#,
            r#"{"admin":["root"],"adversary":[{"uid":4242}]}"#,
            r#"[{"uid":4242}]"#,
        );
        let (base, live, conflicts) = stored_sections(&ok).unwrap();
        assert_eq!(
            (base.canonical(), live.canonical()),
            (ok.base.clone(), ok.live.clone())
        );
        assert_eq!(conflicts, [BindingEntry::Uid(4242)].into());
        for bad in [
            stored("{", &ok.live, &ok.conflicts),
            stored(&ok.base, "{", &ok.conflicts),
            stored(&ok.base, &ok.live, "[\"b\",\"a\"]"),
        ] {
            let e = stored_sections(&bad).unwrap_err();
            assert!(
                e.starts_with("the store's sync base does not parse: "),
                "{e}"
            );
            assert_eq!(counts(&bad), Err(e));
        }
        assert_eq!(
            counts(&ok),
            Ok(SyncCounts {
                unsynced: 1,
                conflicts: 1
            })
        );
    }

    #[test]
    fn every_event_has_its_reason_and_entries_are_escaped() {
        use maknae_config::{BindingEntry::*, MergeEvent::*, ResolvedBy::*};
        assert_eq!(event_reason(&Conflict { entry: Name("a,b\u{1b}".into()), contained: true }),
            "conflict: a\\,b\\u{1b} changed in bindings.yaml and by an unsynced live transition; failed closed: contained");
        assert_eq!(event_reason(&Conflict { entry: Uid(7), contained: false }),
            "conflict: uid:7 changed in bindings.yaml and by an unsynced live transition; failed closed: unbound");
        assert_eq!(
            event_reason(&Resolved {
                entry: Uid(7),
                by: RootEdit
            }),
            "conflict resolved: uid:7: bindings.yaml changed it again"
        );
        assert_eq!(
            event_reason(&Resolved {
                entry: Name("x\n".into()),
                by: ResolvedBy::Sync
            }),
            "conflict resolved: x\\n: bindings.yaml holds the fail-closed value"
        );
        assert_eq!(event_reason(&Lost { missing: true }), "lost: bindings.yaml is missing; the enforced bindings stand; restore them with sudo maknae policy sync, or run sudo maknae reseed to return to principal-as-admin");
        assert_eq!(event_reason(&Lost { missing: false }), "lost: bindings.yaml has no bindings: key; the enforced bindings stand; restore them with sudo maknae policy sync, or run sudo maknae reseed to return to principal-as-admin");
        assert_eq!(
            live_reason(&LiveEdit::Contain(Uid(7)), LiveInitiator::Kernel),
            "live (kernel): contain uid:7"
        );
        assert_eq!(
            live_reason(
                &LiveEdit::Bind {
                    name: "eve".into(),
                    role: BoundRole::User
                },
                LiveInitiator::Operator
            ),
            "live (operator): bind user eve"
        );
        for (role, word) in [(BoundRole::Admin, "admin"), (BoundRole::Guest, "guest")] {
            assert_eq!(
                live_reason(
                    &LiveEdit::Bind {
                        name: "a,b".into(),
                        role
                    },
                    LiveInitiator::Kernel
                ),
                format!("live (kernel): bind {word} a\\,b")
            );
        }
        assert_eq!(
            live_reason(
                &LiveEdit::Release(Name("e\u{7f}".into())),
                LiveInitiator::Operator
            ),
            "live (operator): release e\\u{7f}"
        );
        assert_eq!(
            live_reason(&LiveEdit::Unbind("eve,x".into()), LiveInitiator::Kernel),
            "live (kernel): unbind eve\\,x"
        );
    }

    #[test]
    fn the_rendered_mirror_parses_back_to_the_graphs_live_section() {
        let base = r#"{"admin":["root"]}"#;
        let text = render(&ghost(), Path::new("/etc/maknae")).unwrap();
        let m = maknae_config::parse_mirror(&text).unwrap();
        let want = maknae_config::base_token(
            &Section::from_canonical(base).unwrap(),
            maknae_state::envelope::sha256,
        );
        assert_eq!(
            (
                m.header.revision,
                m.header.base.clone(),
                m.header.config_dir.as_str()
            ),
            (9, want, "/etc/maknae")
        );
        assert_eq!(
            m.section.canonical(),
            r#"{"admin":["root"],"user":["ghost"]}"#
        );
        assert_eq!(
            m.header.conflicts,
            [BindingEntry::Name("ghost".into())].into()
        );
    }

    #[test]
    fn a_render_refuses_a_graph_without_a_sync_base_or_a_non_utf8_directory() {
        assert_eq!(
            render(&built(&layer(true), None, 9), Path::new("/etc/maknae")),
            Err("the graph holds no sync base".into())
        );
        use std::os::unix::ffi::OsStrExt;
        assert_eq!(
            render(
                &ghost(),
                Path::new(std::ffi::OsStr::from_bytes(b"/etc/\xff"))
            ),
            Err("the configuration directory is not UTF-8".into())
        );
    }

    #[test]
    fn the_graphs_null_and_missing_tokens_are_the_sections_canonical_text() {
        for section in [Section::Absent, Section::Missing] {
            let token = section.canonical();
            let s = stored(&token, &token, "[]");
            let g = built(&layer(false), Some(&s), 4);
            assert_eq!(extract(&g).unwrap().sync, Some(s));
            let text = render(&g, Path::new("/etc/maknae")).unwrap();
            assert_eq!(
                maknae_config::parse_mirror(&text).unwrap().section,
                Section::Absent
            );
        }
        let drifted = stored("absent", "absent", "[]");
        assert!(build(
            &layer(false),
            None,
            Some(&drifted),
            &persisted_compiled_set("UNCLASSIFIED"),
            [9; 32],
            4,
            ProvenanceKind::RootFile,
        )
        .and_then(|g| extract(&g))
        .is_err());
    }

    #[test]
    fn a_published_mirror_is_the_render_and_its_short_hash_is_returned() {
        let fx = Fixture::new();
        let g = ghost();
        let hash = publish_mirror(&fx.dir(), &g, Path::new("/etc/maknae")).unwrap();
        let bytes = std::fs::read(fx.mirror()).unwrap();
        assert_eq!(
            bytes,
            render(&g, Path::new("/etc/maknae")).unwrap().into_bytes()
        );
        assert_eq!(hash, short_hash(&bytes));
        assert_eq!(hash.len(), "sha256:".len() + 12);
    }

    #[test]
    fn a_successful_publish_clears_the_stale_flag() {
        let fx = Fixture::new();
        let status = SyncStatus::default();
        status.set_stale(true);
        let hash =
            publish_or_remove(&fx.dir(), &status, &ghost(), Path::new("/etc/maknae")).unwrap();
        assert_eq!(hash, short_hash(&std::fs::read(fx.mirror()).unwrap()));
        assert_eq!(status.lines(), ["unsynced=0", "conflict=0"]);
    }

    #[test]
    fn a_failed_publish_removes_the_old_mirror_and_marks_it_stale() {
        let fx = Fixture::new();
        let (dir, status) = (fx.dir(), SyncStatus::default());
        dir.publish_mirror(b"old").unwrap();
        dir.fail_next_mirror_publish();
        let e = publish_or_remove(&dir, &status, &ghost(), Path::new("/etc/maknae")).unwrap_err();
        assert!(e.starts_with("mirror render failed: publish: "), "{e}");
        assert!(
            e.ends_with("; the transition at revision 9 stands; the stale mirror was removed"),
            "{e}"
        );
        assert!(!fx.mirror().exists());
        assert_eq!(status.lines(), ["unsynced=0", "conflict=0", "mirror=stale"]);

        let status = SyncStatus::default();
        let e = publish_or_remove(
            &dir,
            &status,
            &built(&layer(true), None, 3),
            Path::new("/etc/maknae"),
        )
        .unwrap_err();
        assert_eq!(e, "mirror render failed: the graph holds no sync base; the transition at revision 3 stands; the stale mirror was removed");
        assert_eq!(status.lines(), ["unsynced=0", "conflict=0", "mirror=stale"]);
    }

    #[test]
    fn a_failed_removal_is_named_in_the_outcome() {
        let fx = Fixture::new();
        std::fs::create_dir(fx.mirror()).unwrap();
        std::fs::write(fx.mirror().join("x"), b"").unwrap();
        let status = SyncStatus::default();
        let e = publish_or_remove(
            &fx.dir(),
            &status,
            &built(&layer(true), None, 3),
            Path::new("/etc/maknae"),
        )
        .unwrap_err();
        assert!(
            e.starts_with("mirror render failed: the graph holds no sync base; the transition at revision 3 stands; the stale mirror could not be removed: "),
            "{e}"
        );
        assert_eq!(status.lines(), ["unsynced=0", "conflict=0", "mirror=stale"]);
    }

    #[test]
    fn status_lines_are_counts_and_a_stale_flag_only() {
        let s = SyncStatus::default();
        assert_eq!(s.lines(), ["unsynced=0", "conflict=0"]);
        s.set_counts(SyncCounts {
            unsynced: 2,
            conflicts: 1,
        });
        assert_eq!(s.lines(), ["unsynced=2", "conflict=1"]);
        s.set_stale(true);
        assert_eq!(s.lines(), ["unsynced=2", "conflict=1", "mirror=stale"]);
        assert!(!s.became_lost(false), "false -> false");
        assert_eq!(s.lines(), ["unsynced=2", "conflict=1", "mirror=stale"]);
        assert!(s.became_lost(true), "false -> true");
        assert!(!s.became_lost(true), "already lost");
        s.set_counts(SyncCounts {
            unsynced: 3,
            conflicts: 4,
        });
        assert_eq!(
            s.lines(),
            ["unsynced=3", "conflict=4", "file=lost", "mirror=stale"],
            "set_counts never clears the lost flag"
        );
        s.set_stale(false);
        assert_eq!(s.lines(), ["unsynced=3", "conflict=4", "file=lost"]);
        assert!(!s.became_lost(false));
        assert_eq!(s.lines(), ["unsynced=3", "conflict=4"]);
        assert!(s.became_lost(true), "lost again after a restore");
        let shared = s.clone();
        shared.set_stale(true);
        assert_eq!(
            s.lines(),
            ["unsynced=3", "conflict=4", "file=lost", "mirror=stale"]
        );
    }
}
