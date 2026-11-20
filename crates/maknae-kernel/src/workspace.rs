//! The workspace-mount decision (#674, ADR-0036 decision 5): the kernel's structural
//! refusals, then the mount decided through the composition, and the mask set a Permit
//! carries.

use std::collections::BTreeSet;
use std::path::Path;
use std::sync::Arc;

use maknae_config::{fold_path, Fold, Reach, SensitiveList};
use maknae_security::{
    AttrValue, Decided, Decision, FsOperation, Lane, Obligation, Request, RuleCitation, Verdict,
};

use crate::conversation::facts::ConversationFacts;
use crate::handler::{lane_context, lexical_pregate, stamp_conversation, stamp_subject, Stamp};

const SYSTEM_PATHS: [&str; 12] = [
    "/run",
    "/tmp",
    "/var/tmp",
    "/var/run",
    "/var/folders",
    "/proc",
    "/sys",
    "/dev",
    "/etc",
    "/usr",
    "/var/lib/maknae",
    "/var/log/maknae",
];

const MASK: &str = "workspace.mask";
const PATTERNS: &str = "patterns";

#[cfg_attr(
    not(test),
    expect(dead_code, reason = "called by the tool-invocation verb, #479")
)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum MountMode {
    ReadOnly,
    ReadWrite,
}

/// The role and rule a decision was made on, for the audit record.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(crate) struct Citation {
    pub(crate) role: Option<&'static str>,
    pub(crate) rule: Option<RuleCitation>,
}

/// `audit` reaches the trail only; `wire` is what the client is answered.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum MountDecision {
    Refused {
        audit: String,
        wire: String,
        cited: Citation,
    },
    Permitted {
        masks: Vec<String>,
        cited: Citation,
    },
}

/// Decides a batch and returns the host `sensitive.yaml` list of the snapshot it decided on.
pub(crate) trait DecidesPinned {
    fn decide_all_pinned(&self, reqs: &[Request]) -> (Vec<Decided>, Arc<SensitiveList>);
}

const NOT_AUTHORIZED: &str = "not authorized";
const UNEVALUATED: &str = "workspace: the decision could not be evaluated";

fn structural_refusal(reason: impl Into<String>) -> MountDecision {
    let reason = reason.into();
    MountDecision::Refused {
        wire: reason.clone(),
        audit: reason,
        cited: Citation::default(),
    }
}

fn denied(reason: impl Into<String>, cited: Citation) -> MountDecision {
    MountDecision::Refused {
        audit: reason.into(),
        wire: NOT_AUTHORIZED.into(),
        cited,
    }
}

/// `home` is the subject's canonical home (`maknae_io::canonical_home` or `session_home`).
#[cfg_attr(
    not(test),
    expect(dead_code, reason = "called by the tool-invocation verb, #479")
)]
#[allow(clippy::too_many_arguments)]
pub(crate) fn decide_mount<P: DecidesPinned>(
    authorizer: &P,
    lane: Lane,
    uid: u32,
    home: Option<&Path>,
    conversation: Option<&ConversationFacts>,
    personal: Option<&AttrValue>,
    stamp: &Stamp<'_>,
    root: &str,
    mode: MountMode,
) -> MountDecision {
    folded(
        authorizer,
        maknae_config::native_fold(),
        lane,
        uid,
        home,
        conversation,
        personal,
        stamp,
        root,
        mode,
    )
}

impl MountDecision {
    #[cfg(test)]
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn with_fold<P: DecidesPinned>(
        authorizer: &P,
        fold: Fold,
        lane: Lane,
        uid: u32,
        home: Option<&Path>,
        conversation: Option<&ConversationFacts>,
        personal: Option<&AttrValue>,
        stamp: &Stamp<'_>,
        root: &str,
        mode: MountMode,
    ) -> Self {
        folded(
            authorizer,
            fold,
            lane,
            uid,
            home,
            conversation,
            personal,
            stamp,
            root,
            mode,
        )
    }
}

#[allow(clippy::too_many_arguments)]
fn folded<P: DecidesPinned>(
    authorizer: &P,
    fold: Fold,
    lane: Lane,
    uid: u32,
    home: Option<&Path>,
    conversation: Option<&ConversationFacts>,
    personal: Option<&AttrValue>,
    stamp: &Stamp<'_>,
    root: &str,
    mode: MountMode,
) -> MountDecision {
    if let Err(why) = lexical_pregate(root) {
        return structural_refusal(format!("workspace: {why}"));
    }
    let Some(home) = usable_home(home, fold) else {
        return structural_refusal("workspace: no home to evaluate");
    };
    if let Err(why) = structural(root, home, fold) {
        return structural_refusal(why);
    }
    let personal = match stamp {
        Stamp::Client => personal,
        Stamp::Agent { .. } => None,
    };
    let actions: &[&str] = match mode {
        MountMode::ReadOnly => &["fs.read"],
        MountMode::ReadWrite => &["fs.read", "fs.write"],
    };
    let requests: Vec<Request> = actions
        .iter()
        .map(|action| mount_request(uid, home, conversation, personal, stamp, lane, root, action))
        .collect();
    let pinned = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        authorizer.decide_all_pinned(&requests)
    }));
    let (all, host) = match pinned {
        Ok((all, host)) if all.len() == requests.len() => (all, host),
        _ => return denied(UNEVALUATED, Citation::default()),
    };
    let mut masks = BTreeSet::new();
    let mut cited = Citation::default();
    for decided in all {
        cited = Citation {
            role: decided.role,
            rule: decided.rule,
        };
        let obligations = match decided.verdict {
            Verdict::Indeterminate => return denied(UNEVALUATED, cited),
            v => match maknae_security::finalize(maknae_security::combine(vec![v])) {
                Decision::Permit { obligations } => obligations,
                Decision::Deny { reason } => return denied(reason, cited),
            },
        };
        for ob in &obligations {
            match mask_patterns(ob) {
                Some(patterns) => masks.extend(patterns.iter().cloned()),
                None => return denied("workspace: an obligation the mount cannot honor", cited),
            }
        }
    }
    let dir = Path::new(root);
    let Ok(listed) = host.subtree_entries(dir, Some(home), fold) else {
        return denied(
            "workspace: the host sensitive list could not be evaluated",
            cited,
        );
    };
    masks.extend(listed);
    let Some(own) = personal_entries(personal, dir, home, fold) else {
        return denied(
            "workspace: the personal sensitive list could not be evaluated",
            cited,
        );
    };
    masks.extend(own);
    MountDecision::Permitted {
        masks: masks.into_iter().collect(),
        cited,
    }
}

fn usable_home(home: Option<&Path>, fold: Fold) -> Option<&Path> {
    let text = home?.to_str()?;
    lexical_pregate(text).ok()?;
    let folded = fold_path(text, fold, Reach::Subtree);
    (!folded.mapped().iter().any(|h| h == "/")).then_some(Path::new(text))
}

fn structural(root: &str, home: &Path, fold: Fold) -> Result<(), &'static str> {
    let root = fold_path(root, fold, Reach::Subtree);
    let home = fold_path(&home.to_string_lossy(), fold, Reach::Subtree);
    let any = |listed: &[String], related: &dyn Fn(&str, &str) -> bool| {
        root.mapped()
            .iter()
            .any(|r| listed.iter().any(|l| related(r, l)))
    };
    if any(home.mapped(), &|r, h| within(h, r)) {
        return Err("workspace: the home or a folder above it");
    }
    let system = SYSTEM_PATHS.iter().any(|p| {
        any(fold_path(p, fold, Reach::Subtree).mapped(), &|r, s| {
            within(r, s) || within(s, r)
        })
    });
    if system {
        return Err("workspace: a system directory or a folder above one");
    }
    Ok(())
}

/// Whether `path` is `dir` or lies beneath it, by whole components.
fn within(path: &str, dir: &str) -> bool {
    path == dir
        || dir == "/"
        || path
            .strip_prefix(dir)
            .is_some_and(|rest| rest.starts_with('/'))
}

/// The patterns an obligation adds to the mask set; `None` for one a mount cannot honor.
fn mask_patterns(ob: &Obligation) -> Option<&[String]> {
    match ob.id.as_str() {
        "audit" if ob.params.is_empty() => Some(&[]),
        MASK => {
            let patterns = ob.params.list(PATTERNS)?;
            let mut only = maknae_security::Attributes::new();
            only.insert(PATTERNS, AttrValue::List(patterns.to_vec()));
            (ob.params == only).then_some(patterns)
        }
        _ => None,
    }
}

fn personal_entries(
    personal: Option<&AttrValue>,
    dir: &Path,
    home: &Path,
    fold: Fold,
) -> Option<Vec<String>> {
    let entries: Vec<String> = match personal {
        None => return Some(Vec::new()),
        Some(AttrValue::Set(entries)) => entries.iter().cloned().collect(),
        Some(_) => return None,
    };
    SensitiveList::from_entries(&entries)
        .ok()?
        .subtree_entries(dir, Some(home), fold)
        .ok()
}

#[allow(clippy::too_many_arguments)]
fn mount_request(
    uid: u32,
    home: &Path,
    conversation: Option<&ConversationFacts>,
    personal: Option<&AttrValue>,
    stamp: &Stamp<'_>,
    lane: Lane,
    root: &str,
    action: &str,
) -> Request {
    let mut resource = maknae_security::Attributes::new();
    stamp_conversation(&mut resource, conversation);
    resource.insert(
        maknae_authz_basic::RESOURCE_PATH_KEY,
        AttrValue::Str(root.to_owned()),
    );
    let mut context = lane_context(lane);
    context.insert(
        maknae_security::CONTEXT_FS_OPERATION,
        AttrValue::Str(FsOperation::Mount.as_str().into()),
    );
    if let Some(personal) = personal {
        context.insert(
            maknae_security::CONTEXT_SENSITIVE_PERSONAL,
            personal.clone(),
        );
    }
    Request {
        subject: stamp_subject(uid, Some(home), stamp),
        resource: maknae_security::Resource(resource),
        action: maknae_security::Action(action.to_owned()),
        context: maknae_security::Context(context),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::composition::Composition;
    use crate::handler::TaskStamp;
    use crate::test_fixtures::{fixture, shipped_composition, write_sensitive, DirGuard};
    use maknae_authz_basic::{Baseline, HermeticAuthorizer};
    use maknae_security::{Authorizer, Obligation, Request, Verdict};

    const SYSTEM: &str = "workspace: a system directory or a folder above one";
    const HOME: &str = "workspace: the home or a folder above it";
    const NO_HOME: &str = "workspace: no home to evaluate";
    const ALICE: &str = "/home/alice";

    fn composition(policy: &str, sensitive: &str) -> (DirGuard, Composition<HermeticAuthorizer>) {
        use std::sync::atomic::{AtomicUsize, Ordering};
        static NEXT: AtomicUsize = AtomicUsize::new(0);
        let tag = format!("workspace-{}", NEXT.fetch_add(1, Ordering::Relaxed));
        let (g, basic) = fixture(&tag, policy, None);
        write_sensitive(&g.0, sensitive);
        basic.install(basic.compile_from_file().unwrap());
        (g, Composition::with_us_baseline_ceiling(basic))
    }

    fn broad() -> (DirGuard, Composition<HermeticAuthorizer>) {
        composition(
            "schema_version: 1\npermissions:\n  allow: [\"Read(/**)\", \"Write(/**)\"]\n  deny: []\n",
            "schema_version: 1\nsensitive: []\n",
        )
    }

    fn operator() -> u32 {
        nix::unistd::geteuid().as_raw()
    }

    fn mount<P: DecidesPinned>(
        a: &P,
        fold: Fold,
        home: Option<&str>,
        root: &str,
        mode: MountMode,
    ) -> MountDecision {
        uncited_mount(
            a,
            fold,
            operator(),
            home.map(Path::new),
            None,
            None,
            &Stamp::Client,
            root,
            mode,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn uncited_mount<P: DecidesPinned>(
        a: &P,
        fold: Fold,
        uid: u32,
        home: Option<&Path>,
        conversation: Option<&ConversationFacts>,
        personal: Option<&AttrValue>,
        stamp: &Stamp<'_>,
        root: &str,
        mode: MountMode,
    ) -> MountDecision {
        uncited(MountDecision::with_fold(
            a,
            fold,
            Lane::Local,
            uid,
            home,
            conversation,
            personal,
            stamp,
            root,
            mode,
        ))
    }

    fn refused(reason: &str) -> MountDecision {
        MountDecision::Refused {
            audit: reason.into(),
            wire: reason.into(),
            cited: Citation::default(),
        }
    }

    fn denied(reason: &str) -> MountDecision {
        MountDecision::Refused {
            audit: reason.into(),
            wire: NOT_AUTHORIZED.into(),
            cited: Citation::default(),
        }
    }

    fn permitted(masks: &[&str]) -> MountDecision {
        MountDecision::Permitted {
            masks: masks.iter().map(|m| (*m).to_owned()).collect(),
            cited: Citation::default(),
        }
    }

    fn uncited(d: MountDecision) -> MountDecision {
        match d {
            MountDecision::Refused { audit, wire, .. } => MountDecision::Refused {
                audit,
                wire,
                cited: Citation::default(),
            },
            MountDecision::Permitted { masks, .. } => MountDecision::Permitted {
                masks,
                cited: Citation::default(),
            },
        }
    }

    fn task() -> TaskStamp {
        TaskStamp {
            id: maknae_proto::TaskId([0x67; 16]),
            tasker: "uid:1000".into(),
            root: "users/1000".into(),
            start: 0,
        }
    }

    const SYSTEM_PATHS: [&str; 12] = [
        "/run",
        "/tmp",
        "/var/tmp",
        "/var/run",
        "/var/folders",
        "/proc",
        "/sys",
        "/dev",
        "/etc",
        "/usr",
        "/var/lib/maknae",
        "/var/log/maknae",
    ];

    #[test]
    fn refuses_structural_roots() {
        let (_g, c) = broad();
        for fold in [Fold::None, Fold::Case] {
            for sys in SYSTEM_PATHS {
                for root in [sys.to_owned(), format!("{sys}/sentinel-674")] {
                    for mode in [MountMode::ReadOnly, MountMode::ReadWrite] {
                        assert_eq!(
                            mount(&c, fold, Some(ALICE), &root, mode),
                            refused(SYSTEM),
                            "{root}"
                        );
                    }
                }
            }
            for root in ["/var", "/var/lib"] {
                assert_eq!(
                    mount(&c, fold, Some(ALICE), root, MountMode::ReadOnly),
                    refused(SYSTEM),
                    "{root}"
                );
            }
            assert!(matches!(
                mount(&c, fold, Some(ALICE), "/", MountMode::ReadOnly),
                MountDecision::Refused { .. }
            ));
        }
    }

    #[test]
    fn refuses_aliases_under_the_mac_fold() {
        let (_g, c) = broad();
        let home = Some("/Users/alex");
        for root in [
            "/private/tmp",
            "/private",
            "/System/Volumes/Data/private/tmp",
            "/ETC",
            "/Private/Var/Folders/xy",
        ] {
            assert_eq!(
                mount(&c, Fold::Case, home, root, MountMode::ReadOnly),
                refused(SYSTEM),
                "{root}"
            );
        }
        assert!(matches!(
            mount(
                &c,
                Fold::Case,
                home,
                "/System/Volumes/Data",
                MountMode::ReadOnly
            ),
            MountDecision::Refused { .. }
        ));
        assert_eq!(
            mount(
                &c,
                Fold::Case,
                home,
                "/srv/sentinel-674",
                MountMode::ReadOnly
            ),
            permitted(&[])
        );
    }

    #[test]
    fn refuses_home_and_above() {
        let (_g, c) = broad();
        for fold in [Fold::None, Fold::Case] {
            for root in [ALICE, "/home", "/"] {
                assert_eq!(
                    mount(&c, fold, Some(ALICE), root, MountMode::ReadOnly),
                    refused(HOME),
                    "{root}"
                );
            }
        }
    }

    #[test]
    fn home_children_pass_the_structural_step() {
        let (_g, c) = shipped_composition();
        assert_eq!(
            mount(
                &c,
                Fold::None,
                Some(ALICE),
                "/home/alice/projects/x",
                MountMode::ReadWrite
            ),
            permitted(&[])
        );
        let hobi = maknae_config::AgentId::parse("hobi").unwrap();
        let task = task();
        let agent = Stamp::Agent {
            agent: &hobi,
            task: Some(&task),
        };
        assert_eq!(
            uncited_mount(
                &c,
                Fold::None,
                2001,
                Some(Path::new("/home/hobi-svc")),
                None,
                None,
                &agent,
                "/home/hobi-svc/tasks/users/1000",
                MountMode::ReadWrite,
            ),
            permitted(&[])
        );
    }

    #[test]
    fn an_agent_mounts_its_partition_under_the_production_home() {
        let (_g, c) = shipped_composition();
        let hobi = maknae_config::AgentId::parse("hobi").unwrap();
        let task = task();
        let agent = Stamp::Agent {
            agent: &hobi,
            task: Some(&task),
        };
        for fold in [Fold::None, Fold::Case] {
            for mode in [MountMode::ReadOnly, MountMode::ReadWrite] {
                assert_eq!(
                    uncited_mount(
                        &c,
                        fold,
                        2001,
                        Some(Path::new("/var/lib/maknae-agents/hobi")),
                        None,
                        None,
                        &agent,
                        "/var/lib/maknae-agents/hobi/tasks/users/1000",
                        mode,
                    ),
                    permitted(&[]),
                    "{fold:?} {mode:?}"
                );
            }
        }
    }

    #[test]
    fn structural_rule_compares_components() {
        let (_g, c) = broad();
        for fold in [Fold::None, Fold::Case] {
            for root in [
                "/usr2",
                "/tmpx",
                "/var/lib/maknae-agents",
                "/home/alice2",
                "/home/al",
                "/home/alice/x",
            ] {
                assert_eq!(
                    mount(&c, fold, Some(ALICE), root, MountMode::ReadOnly),
                    permitted(&[]),
                    "{root}"
                );
            }
        }
    }

    #[test]
    fn home_rule_folds_aliases() {
        let (_g, c) = broad();
        let home = Some("/Users/alex");
        for root in [
            "/Users/ALEX",
            "/users",
            "/System/Volumes/Data/Users",
            "/System/Volumes/Data/Users/alex",
        ] {
            assert_eq!(
                mount(&c, Fold::Case, home, root, MountMode::ReadOnly),
                refused(HOME),
                "{root}"
            );
        }
        assert_eq!(
            mount(
                &c,
                Fold::Case,
                home,
                "/Users/ALEX/projects",
                MountMode::ReadOnly
            ),
            permitted(&[])
        );
        assert_eq!(
            mount(&c, Fold::None, home, "/Users/ALEX", MountMode::ReadOnly),
            permitted(&[])
        );
    }

    #[test]
    fn lexical_pregate_runs_first() {
        let (_g, c) = broad();
        for (root, why) in [
            ("/srv/../etc", "dot segment"),
            ("srv/x", "not absolute"),
            ("/srv/x/", "trailing slash"),
        ] {
            assert_eq!(
                mount(&c, Fold::None, None, root, MountMode::ReadOnly),
                refused(&format!("workspace: {why}")),
                "{root}"
            );
        }
    }

    #[test]
    fn no_home_refuses() {
        let (_g, c) = broad();
        for home in [None, Some("home/alice"), Some("/home/alice/"), Some("/")] {
            assert_eq!(
                mount(&c, Fold::None, home, "/srv/x", MountMode::ReadOnly),
                refused(NO_HOME),
                "{home:?}"
            );
        }
        assert_eq!(
            mount(
                &c,
                Fold::Case,
                Some("/System/Volumes/Data"),
                "/srv/x",
                MountMode::ReadOnly
            ),
            refused(NO_HOME)
        );
    }

    const MASKED: &str = "schema_version: 1\npermissions:\n  allow: [\"Read(~/**)\", \"Write(~/projects/**)\"]\n  deny: [\"Read(/**/.env)\", \"Read(~/projects/x/.secrets/**)\", \"Read(/srv/**)\", \"Write(/**/Cargo.lock)\"]\n";
    const HOST: &str = "schema_version: 1\nsensitive:\n  - \"~/projects/x/.secrets/**\"\n  - \"~/projects/x/keys/*.pem\"\n  - \"/etc/shadow\"\n  - \"~/.ssh/**\"\n";

    #[test]
    fn ro_permit_carries_masks() {
        let (_g, c) = composition(MASKED, HOST);
        assert_eq!(
            mount(
                &c,
                Fold::None,
                Some(ALICE),
                "/home/alice/projects/x",
                MountMode::ReadOnly
            ),
            permitted(&[
                "/**/.env",
                "/home/alice/projects/x/.secrets/**",
                "/home/alice/projects/x/keys/*.pem",
            ])
        );
        assert_eq!(
            mount(
                &c,
                Fold::None,
                Some(ALICE),
                "/home/alice/projects/x/.secrets",
                MountMode::ReadOnly
            ),
            denied("denied by policy entry Read(~/projects/x/.secrets/**)")
        );
    }

    #[test]
    fn rw_needs_both_and_unions_masks() {
        let (_g, c) = composition(MASKED, HOST);
        assert!(matches!(
            mount(
                &c,
                Fold::None,
                Some(ALICE),
                "/home/alice/docs",
                MountMode::ReadOnly
            ),
            MountDecision::Permitted { .. }
        ));
        assert!(matches!(
            mount(
                &c,
                Fold::None,
                Some(ALICE),
                "/home/alice/docs",
                MountMode::ReadWrite
            ),
            MountDecision::Refused { .. }
        ));
        assert_eq!(
            mount(
                &c,
                Fold::None,
                Some(ALICE),
                "/home/alice/projects/x",
                MountMode::ReadWrite
            ),
            permitted(&[
                "/**/.env",
                "/**/Cargo.lock",
                "/home/alice/projects/x/.secrets/**",
                "/home/alice/projects/x/keys/*.pem",
            ])
        );
    }

    #[test]
    fn personal_masks_for_an_operator_not_an_agent() {
        let (_g, c) = shipped_composition();
        let personal = AttrValue::Set(
            ["~/tasks/users/1000/sentinel-674/**".to_owned()]
                .into_iter()
                .collect(),
        );
        let decide = |uid: u32, home: &str, stamp: &Stamp<'_>| {
            uncited_mount(
                &c,
                Fold::None,
                uid,
                Some(Path::new(home)),
                None,
                Some(&personal),
                stamp,
                &format!("{home}/tasks/users/1000"),
                MountMode::ReadOnly,
            )
        };
        assert_eq!(
            decide(operator(), ALICE, &Stamp::Client),
            permitted(&["/home/alice/tasks/users/1000/sentinel-674/**"])
        );
        let hobi = maknae_config::AgentId::parse("hobi").unwrap();
        let task = task();
        let agent = Stamp::Agent {
            agent: &hobi,
            task: Some(&task),
        };
        assert_eq!(decide(2001, "/home/hobi-svc", &agent), permitted(&[]));
    }

    #[test]
    fn an_agent_mount_outside_its_partition_refuses() {
        let (_g, c) = shipped_composition();
        let hobi = maknae_config::AgentId::parse("hobi").unwrap();
        let task = task();
        for (cited, root, reason) in [
            (
                Some(&task),
                "/home/hobi-svc/tasks/users/1001",
                "partition: the mount lies outside the task's partition",
            ),
            (
                None,
                "/home/hobi-svc/tasks/users/1000",
                "partition: the request cites no task",
            ),
        ] {
            let agent = Stamp::Agent {
                agent: &hobi,
                task: cited,
            };
            assert_eq!(
                uncited_mount(
                    &c,
                    Fold::None,
                    2001,
                    Some(Path::new("/home/hobi-svc")),
                    None,
                    None,
                    &agent,
                    root,
                    MountMode::ReadOnly,
                ),
                denied(reason),
                "{root}"
            );
        }
    }

    fn cited_by<P: Authorizer>(a: &P, root: &str, action: &str) -> Citation {
        let request = mount_request(
            operator(),
            Path::new(ALICE),
            None,
            None,
            &Stamp::Client,
            Lane::Local,
            root,
            action,
        );
        let d = maknae_security::guarded_decide_cited(a, &request);
        Citation {
            role: d.role,
            rule: d.rule,
        }
    }

    #[test]
    fn a_decision_cites_the_refusing_rule_or_the_last_permit() {
        let (_g, c) = composition(MASKED, HOST);
        let decide = |root: &str, mode| {
            MountDecision::with_fold(
                &c,
                Fold::None,
                Lane::Local,
                operator(),
                Some(Path::new(ALICE)),
                None,
                None,
                &Stamp::Client,
                root,
                mode,
            )
        };
        let secrets = "/home/alice/projects/x/.secrets";
        let MountDecision::Refused { audit, wire, cited } = decide(secrets, MountMode::ReadOnly)
        else {
            panic!("a denied root refuses");
        };
        assert_eq!(
            audit,
            "denied by policy entry Read(~/projects/x/.secrets/**)"
        );
        assert_eq!(wire, NOT_AUTHORIZED);
        assert!(cited.rule.is_some());
        assert_eq!(cited, cited_by(&c, secrets, "fs.read"));

        let project = "/home/alice/projects/x";
        let read = cited_by(&c, project, "fs.read");
        let write = cited_by(&c, project, "fs.write");
        assert!(write.rule.is_some());
        assert_ne!(read, write);
        let MountDecision::Permitted { cited, .. } = decide(project, MountMode::ReadWrite) else {
            panic!("the project mounts read-write");
        };
        assert_eq!(cited, write);
    }

    #[test]
    fn a_structural_refusal_cites_nothing() {
        let (_g, c) = broad();
        assert_eq!(
            MountDecision::with_fold(
                &c,
                Fold::None,
                Lane::Local,
                operator(),
                Some(Path::new(ALICE)),
                None,
                None,
                &Stamp::Client,
                "/etc",
                MountMode::ReadOnly,
            ),
            refused(SYSTEM)
        );
    }

    #[test]
    fn a_remote_lane_refuses() {
        let (_g, c) = broad();
        assert_eq!(
            uncited(MountDecision::with_fold(
                &c,
                Fold::None,
                Lane::Remote,
                operator(),
                Some(Path::new(ALICE)),
                None,
                None,
                &Stamp::Client,
                "/srv/x",
                MountMode::ReadOnly,
            )),
            denied("filesystem attempt requires a local subject")
        );
    }

    #[test]
    fn decide_mount_folds_natively() {
        let (_g, c) = broad();
        let home = Some(Path::new(ALICE));
        let root = "/ETC";
        let at = |fold| {
            MountDecision::with_fold(
                &c,
                fold,
                Lane::Local,
                operator(),
                home,
                None,
                None,
                &Stamp::Client,
                root,
                MountMode::ReadOnly,
            )
        };
        assert_ne!(at(Fold::None), at(Fold::Case));
        assert_eq!(
            decide_mount(
                &c,
                Lane::Local,
                operator(),
                home,
                None,
                None,
                &Stamp::Client,
                root,
                MountMode::ReadOnly,
            ),
            at(maknae_config::native_fold())
        );
    }

    #[test]
    fn the_audit_log_is_a_system_path() {
        let (_g, c) = broad();
        for fold in [Fold::None, Fold::Case] {
            for root in [
                "/var/log/maknae",
                "/var/log/maknae/sentinel-674",
                "/var/log",
            ] {
                assert_eq!(
                    mount(&c, fold, Some(ALICE), root, MountMode::ReadOnly),
                    refused(SYSTEM),
                    "{root}"
                );
            }
            assert_eq!(
                mount(&c, fold, Some(ALICE), "/var/log/other", MountMode::ReadOnly),
                permitted(&[])
            );
        }
    }

    #[test]
    fn a_sensitive_root_refuses() {
        let (_g, c) = composition(MASKED, HOST);
        assert_eq!(
            mount(
                &c,
                Fold::None,
                Some(ALICE),
                "/home/alice/.ssh",
                MountMode::ReadOnly
            ),
            denied("sensitive: host ~/.ssh/**")
        );
    }

    struct Stub {
        verdict: Verdict,
        host: Arc<SensitiveList>,
    }

    impl Stub {
        fn permit(obligations: Vec<Obligation>) -> Self {
            Stub {
                verdict: Verdict::Permit { obligations },
                host: Arc::new(SensitiveList::empty()),
            }
        }
    }

    impl Authorizer for Stub {
        fn decide_cited_all(&self, reqs: &[Request]) -> Vec<Decided> {
            maknae_security::decide_each_cited(self, reqs)
        }
        fn decide(&self, _: &Request) -> Verdict {
            self.verdict.clone()
        }
    }

    impl DecidesPinned for Stub {
        fn decide_all_pinned(&self, reqs: &[Request]) -> (Vec<Decided>, Arc<SensitiveList>) {
            (
                maknae_security::decide_each_cited(self, reqs),
                Arc::clone(&self.host),
            )
        }
    }

    fn obligation(id: &str, params: &[(&str, AttrValue)]) -> Obligation {
        let mut attrs = maknae_security::Attributes::new();
        for (k, v) in params {
            attrs.insert(*k, v.clone());
        }
        Obligation {
            id: id.into(),
            params: attrs,
        }
    }

    fn patterns(p: &[&str]) -> (&'static str, AttrValue) {
        (
            "patterns",
            AttrValue::List(p.iter().map(|s| (*s).to_owned()).collect()),
        )
    }

    const UNHONORABLE: &str = "workspace: an obligation the mount cannot honor";

    #[test]
    fn foreign_obligation_refuses() {
        let cases = [
            obligation("sentinel-674-foreign", &[]),
            obligation("audit", &[("x", AttrValue::Str("y".into()))]),
            obligation(
                "workspace.mask",
                &[("patterns", AttrValue::Str("/x".into()))],
            ),
            obligation("workspace.mask", &[]),
            obligation(
                "workspace.mask",
                &[patterns(&["/x"]), ("extra", AttrValue::Str("y".into()))],
            ),
        ];
        for ob in cases {
            let stub = Stub::permit(vec![ob.clone()]);
            assert_eq!(
                mount(
                    &stub,
                    Fold::None,
                    Some(ALICE),
                    "/srv/x",
                    MountMode::ReadOnly
                ),
                denied(UNHONORABLE),
                "{ob:?}"
            );
        }
        let stub = Stub::permit(vec![
            obligation("audit", &[]),
            obligation(
                "workspace.mask",
                &[patterns(&["/srv/x/b", "/srv/x/a", "/srv/x/b"])],
            ),
        ]);
        assert_eq!(
            mount(
                &stub,
                Fold::None,
                Some(ALICE),
                "/srv/x",
                MountMode::ReadWrite
            ),
            permitted(&["/srv/x/a", "/srv/x/b"])
        );
    }

    #[test]
    fn a_verdict_that_is_not_a_permit_refuses() {
        for (verdict, reason) in [
            (
                Verdict::Indeterminate,
                "workspace: the decision could not be evaluated",
            ),
            (
                Verdict::Deny {
                    reason: "sentinel-674-deny".into(),
                },
                "sentinel-674-deny",
            ),
            (
                Verdict::NotApplicable { note: None },
                "no applicable authorizer (fail-closed)",
            ),
        ] {
            let stub = Stub {
                verdict,
                host: Arc::new(SensitiveList::empty()),
            };
            assert_eq!(
                mount(
                    &stub,
                    Fold::None,
                    Some(ALICE),
                    "/srv/x",
                    MountMode::ReadOnly
                ),
                denied(reason)
            );
        }
    }

    #[test]
    fn a_malformed_personal_list_refuses() {
        let stub = Stub::permit(vec![obligation("audit", &[])]);
        for personal in [
            AttrValue::Str("~/x".into()),
            AttrValue::Set(["relative/x".to_owned()].into_iter().collect()),
        ] {
            assert_eq!(
                uncited_mount(
                    &stub,
                    Fold::None,
                    operator(),
                    Some(Path::new(ALICE)),
                    None,
                    Some(&personal),
                    &Stamp::Client,
                    "/srv/x",
                    MountMode::ReadOnly,
                ),
                denied("workspace: the personal sensitive list could not be evaluated"),
                "{personal:?}"
            );
        }
    }

    #[test]
    fn the_host_list_is_captured_from_the_authorizer() {
        let stub = Stub {
            verdict: Verdict::Permit {
                obligations: vec![obligation("audit", &[])],
            },
            host: Arc::new(
                SensitiveList::from_entries(&[
                    "/srv/x/sentinel-674/**".to_owned(),
                    "/srv/y/**".to_owned(),
                ])
                .unwrap(),
            ),
        };
        assert_eq!(
            mount(
                &stub,
                Fold::None,
                Some(ALICE),
                "/srv/x",
                MountMode::ReadOnly
            ),
            permitted(&["/srv/x/sentinel-674/**"])
        );
    }

    struct Torn {
        decided_on: Arc<SensitiveList>,
    }

    impl Authorizer for Torn {
        fn decide_cited_all(&self, reqs: &[Request]) -> Vec<Decided> {
            maknae_security::decide_each_cited(self, reqs)
        }
        fn decide(&self, _: &Request) -> Verdict {
            Verdict::Permit {
                obligations: vec![obligation("audit", &[])],
            }
        }
    }

    impl DecidesPinned for Torn {
        fn decide_all_pinned(&self, reqs: &[Request]) -> (Vec<Decided>, Arc<SensitiveList>) {
            (
                maknae_security::decide_each_cited(self, reqs),
                Arc::clone(&self.decided_on),
            )
        }
    }

    impl crate::SensitiveNow for Torn {
        fn sensitive_now(&self) -> Arc<SensitiveList> {
            Arc::new(SensitiveList::empty())
        }
    }

    #[test]
    fn the_masks_come_from_the_snapshot_the_decision_ran_on() {
        let torn = Torn {
            decided_on: Arc::new(
                SensitiveList::from_entries(&["/srv/x/sentinel-674-pinned/**".to_owned()]).unwrap(),
            ),
        };
        assert_eq!(
            mount(
                &torn,
                Fold::None,
                Some(ALICE),
                "/srv/x",
                MountMode::ReadOnly
            ),
            permitted(&["/srv/x/sentinel-674-pinned/**"])
        );
    }

    enum Broken {
        Short,
        Long,
        Panics,
    }

    impl DecidesPinned for Broken {
        fn decide_all_pinned(&self, reqs: &[Request]) -> (Vec<Decided>, Arc<SensitiveList>) {
            let permit = Decided {
                verdict: Verdict::Permit {
                    obligations: vec![],
                },
                role: Some("sentinel-674-role"),
                rule: None,
            };
            let n = match self {
                Broken::Short => reqs.len() - 1,
                Broken::Long => reqs.len() + 1,
                Broken::Panics => panic!("sentinel-674-panic"),
            };
            (vec![permit; n], Arc::new(SensitiveList::empty()))
        }
    }

    #[test]
    fn a_batch_answer_that_panics_or_miscounts_refuses() {
        for broken in [Broken::Short, Broken::Long, Broken::Panics] {
            assert_eq!(
                MountDecision::with_fold(
                    &broken,
                    Fold::None,
                    Lane::Local,
                    operator(),
                    Some(Path::new(ALICE)),
                    None,
                    None,
                    &Stamp::Client,
                    "/srv/x",
                    MountMode::ReadOnly,
                ),
                MountDecision::Refused {
                    audit: UNEVALUATED.into(),
                    wire: NOT_AUTHORIZED.into(),
                    cited: Citation::default(),
                }
            );
        }
    }

    #[test]
    fn the_requests_carry_the_mount() {
        let personal = AttrValue::Set(["~/p".to_owned()].into_iter().collect());
        let hobi = maknae_config::AgentId::parse("hobi").unwrap();
        let task = task();
        let agent = Stamp::Agent {
            agent: &hobi,
            task: Some(&task),
        };
        let home = Path::new(ALICE);
        let facts = ConversationFacts {
            state: crate::conversation::facts::FactState::Active,
            owner_uid: Some(7),
            extends: None,
        };
        let client = mount_request(
            7,
            home,
            Some(&facts),
            Some(&personal),
            &Stamp::Client,
            Lane::Remote,
            "/srv/x",
            "fs.write",
        );
        assert_eq!(client.action.0, "fs.write");
        assert_eq!(client.resource.0.str("path"), Some("/srv/x"));
        assert_eq!(
            client.context.0.str(maknae_security::CONTEXT_FS_OPERATION),
            Some("mount")
        );
        assert_eq!(
            client.context.0.str(maknae_security::CONTEXT_DAC_LANE),
            Some(Lane::Remote.as_str())
        );
        assert_eq!(
            client
                .context
                .0
                .get(maknae_security::CONTEXT_SENSITIVE_PERSONAL),
            Some(&personal)
        );
        assert_eq!(
            client.subject.0.str(maknae_security::SUBJECT_HOME),
            Some(ALICE)
        );
        assert_eq!(
            client
                .resource
                .0
                .str(maknae_authz_basic::RESOURCE_CONVERSATION_STATE_KEY),
            Some(maknae_authz_basic::CONVERSATION_ACTIVE)
        );
        assert_eq!(
            client
                .resource
                .0
                .get(maknae_authz_basic::RESOURCE_CONVERSATION_OWNER_KEY),
            Some(&AttrValue::Int(7))
        );
        let tasked = mount_request(
            7,
            home,
            None,
            None,
            &agent,
            Lane::Local,
            "/srv/x",
            "fs.read",
        );
        assert_eq!(
            tasked.context.0.str(maknae_security::CONTEXT_DAC_LANE),
            Some(Lane::Local.as_str())
        );
        assert_eq!(
            tasked.subject.0.str(maknae_security::SUBJECT_ROOT_TASKER),
            Some("users/1000")
        );
    }

    #[test]
    fn discharge_plan_still_refuses_workspace_mask() {
        let (_g, c) = composition(MASKED, HOST);
        let request = mount_request(
            operator(),
            Path::new(ALICE),
            None,
            None,
            &Stamp::Client,
            Lane::Local,
            "/home/alice/projects/x",
            "fs.read",
        );
        let Verdict::Permit { obligations } = c.decide(&request) else {
            panic!("the mount is permitted");
        };
        assert!(obligations.iter().any(|o| o.id == "workspace.mask"));
        assert!(crate::handler::discharge_plan(&obligations).is_err());
    }
}
