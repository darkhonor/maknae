//! The per-subject tool catalog (#674, ADR-0039 decision 7): the `tools.yaml` entries a
//! subject's grants reach, as `maknae_graph::catalog` bytes. A hint; no decision reads it.

use crate::binding::Resolution;
use crate::decide::{role_stage, LoadedPolicy, SubjectEntry};
use crate::role::Role;
use maknae_config::{
    ArgPattern, CommandForm, Constraint, ForgeSet, OutputToModel, Pattern, Shape, ShapeClass,
    ShapePattern, Slot, SlotAt, Stage, ToolEntry, ToolTarget, ToolsCatalog,
};
use maknae_graph::catalog::{
    CatalogEntry, CatalogForge, CatalogInput, CatalogOutput, CatalogShape, CatalogSlot,
};
use maknae_proto::{CatalogDigest, CredentialRef, TOOL_CATALOG_MAX_BYTES};
use std::collections::BTreeSet;
use std::sync::Arc;

const GIT_BINDING: &str = "git";

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SubjectCatalog {
    pub bytes: Arc<Vec<u8>>,
    pub digest: CatalogDigest,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CatalogError {
    TooLarge,
    Build,
    /// The subject holds no role or is contained on the snapshot the build used.
    NotAdmitted,
}

/// What `uid` sees: each entry's own ceiling patterns that a stage of its effective
/// lists admits, and every forge. `TooLarge` once the graph keys and pattern text would
/// pass `budget` bytes, before any is built.
pub(crate) fn input(
    lp: &LoadedPolicy,
    uid: u32,
    principal_uid: u32,
    forges: &ForgeSet,
    budget: usize,
) -> Result<CatalogInput, CatalogError> {
    let role = match lp.roles.role_for(uid, principal_uid) {
        Resolution::Role(Role::Adversary) | Resolution::NoRole => {
            return Ok(CatalogInput::default())
        }
        Resolution::Role(role @ (Role::Admin | Role::User | Role::Guest)) => role,
    };
    let lists = effective_lists(lp, uid, Some(role.key()));
    let stages: Vec<&Stage<'_>> = lists.right.iter().chain([&lists.floored]).collect();
    let agent = lp.agents.get(uid).is_some();
    let mut spent = 0usize;
    let mut entries = Vec::new();
    for entry in lp
        .tools
        .entries()
        .filter(|e| !agent || reach_checked(e, &lp.tools))
        .filter_map(|e| granted(e, &stages))
    {
        spent = spent.saturating_add(graph_text(&entry));
        if spent > budget {
            return Err(CatalogError::TooLarge);
        }
        entries.push(entry);
    }
    let forges = forges
        .iter()
        .map(|f| CatalogForge {
            name: f.name.clone(),
            kind: f.kind.as_str().into(),
            host: f.host.clone(),
            provider: f.provider.as_str().into(),
        })
        .collect();
    Ok(CatalogInput { entries, forges })
}

/// The forge credentials of agent `uid`'s granted, enabled entries that bind `git`, as each
/// class's kind and its App, or the class name for a kind that names no App.
pub(crate) fn forge_credentials(
    lp: &LoadedPolicy,
    uid: u32,
    principal_uid: u32,
) -> Vec<CredentialRef> {
    if lp.agents.get(uid).is_none()
        || matches!(
            lp.roles.role_for(uid, principal_uid),
            Resolution::Role(Role::Adversary) | Resolution::NoRole
        )
    {
        return Vec::new();
    }
    let lists = effective_lists(lp, uid, None);
    let stages: Vec<&Stage<'_>> = lists.right.iter().chain([&lists.floored]).collect();
    let refs: BTreeSet<(&str, &str)> = lp
        .tools
        .entries()
        .filter(|e| e.binds.contains(GIT_BINDING))
        .filter(|e| granted(e, &stages).is_some())
        .filter_map(|e| lp.tools.class(e.credential.as_deref()?))
        .map(|c| (c.kind.as_str(), c.app.as_deref().unwrap_or(&c.name)))
        .collect();
    refs.into_iter()
        .map(|(kind, name)| CredentialRef {
            kind: kind.into(),
            name: name.into(),
        })
        .collect()
}

fn effective_lists<'a>(
    lp: &'a LoadedPolicy,
    uid: u32,
    role: Option<&'static str>,
) -> maknae_config::EffectiveLists<'a> {
    let subject = lp.subjects.get(uid);
    lp.policy.effective_lists(
        subject.and_then(SubjectEntry::agent_right).map(|(_, r)| r),
        subject.and_then(|s| s.permissions.as_ref()),
        role.and_then(|r| role_stage(subject, r)),
    )
}

/// A lower bound on the bytes `entry` puts in the graph: each program, pattern and shape
/// key repeats the entry and program names, and each pattern and shape carries its text again.
fn graph_text(entry: &CatalogEntry) -> usize {
    let patterns = entry.programs.iter().map(|(program, patterns)| {
        let key = entry.name.len() + 1 + program.len();
        patterns
            .iter()
            .fold(key, |n, text| n.saturating_add(key + 1 + 2 * text.len()))
    });
    let open = entry
        .open
        .iter()
        .map(|program| entry.name.len() + 1 + program.len());
    let shapes = entry.shapes.iter().flat_map(|(program, shapes)| {
        let key = entry.name.len() + 1 + program.len() + 1;
        shapes.iter().map(move |shape| {
            let slots = shape.slots.iter().fold(0usize, |n, slot| {
                let members = slot.members.iter().map(String::len).sum::<usize>();
                n.saturating_add(slot.name.len() + slot.at.len() + slot.description.len() + members)
            });
            key.saturating_add(shape.name.len() * 2 + shape.description.len() + slots)
        })
    });
    patterns
        .chain(open)
        .chain(shapes)
        .fold(0, usize::saturating_add)
}

pub(crate) fn build(
    lp: &LoadedPolicy,
    uid: u32,
    principal_uid: u32,
    forges: &ForgeSet,
    digest: fn(&[u8]) -> [u8; 32],
) -> Result<SubjectCatalog, CatalogError> {
    let input = input(lp, uid, principal_uid, forges, TOOL_CATALOG_MAX_BYTES)?;
    let bytes = maknae_graph::catalog::encode(&input).map_err(|_| CatalogError::Build)?;
    let bytes = within(bytes, TOOL_CATALOG_MAX_BYTES)?;
    Ok(SubjectCatalog {
        digest: CatalogDigest(digest(&bytes)),
        bytes: Arc::new(bytes),
    })
}

fn within(bytes: Vec<u8>, max: usize) -> Result<Vec<u8>, CatalogError> {
    if bytes.len() > max {
        Err(CatalogError::TooLarge)
    } else {
        Ok(bytes)
    }
}

fn reach_checked(entry: &ToolEntry, tools: &ToolsCatalog) -> bool {
    match entry.credential.as_deref() {
        None => true,
        Some(class) => tools.class(class).is_some_and(|c| c.kind.has_reach_check()),
    }
}

fn granted(entry: &ToolEntry, stages: &[&Stage<'_>]) -> Option<CatalogEntry> {
    let mut programs: Vec<(String, Vec<String>)> = Vec::new();
    let mut open = Vec::new();
    let mut shapes: Vec<(String, Vec<CatalogShape>)> = Vec::new();
    for (program, command) in &entry.commands {
        match &command.form {
            CommandForm::Positional(ceilings) => {
                let kept: Vec<String> = ceilings
                    .iter()
                    .filter(|ceiling| {
                        stages
                            .iter()
                            .any(|s| admits(s, &entry.name, program, ceiling))
                    })
                    .map(ArgPattern::canonical)
                    .collect();
                if !kept.is_empty() {
                    programs.push((program.clone(), kept));
                }
            }
            CommandForm::Grammar { shapes: all, .. } => {
                let kept: Vec<CatalogShape> = all
                    .iter()
                    .filter(|(name, _)| {
                        stages
                            .iter()
                            .any(|s| admits_shape(s, &entry.name, program, name))
                    })
                    .map(|(name, shape)| catalog_shape(name, shape))
                    .collect();
                if !kept.is_empty() {
                    shapes.push((program.clone(), kept));
                }
            }
            CommandForm::Open => {
                if stages.iter().any(|s| admits_open(s, &entry.name, program)) {
                    open.push(program.clone());
                }
            }
        }
    }
    (!(programs.is_empty() && open.is_empty() && shapes.is_empty())).then(|| CatalogEntry {
        name: entry.name.clone(),
        description: entry.description.clone(),
        executes_workspace: entry.executes_workspace,
        output: match entry.output_to_model {
            OutputToModel::Redacted => CatalogOutput::Redacted,
            OutputToModel::StatusOnly => CatalogOutput::StatusOnly,
        },
        binds: entry.binds.iter().cloned().collect(),
        programs,
        open,
        shapes,
    })
}

fn catalog_shape(name: &str, shape: &Shape) -> CatalogShape {
    CatalogShape {
        name: name.to_owned(),
        description: shape.description.clone(),
        access: match shape.class {
            ShapeClass::Read => "read",
            ShapeClass::Write => "write",
        }
        .into(),
        slots: shape
            .slots
            .iter()
            .map(|(slot, def)| catalog_slot(slot, def))
            .collect(),
    }
}

fn catalog_slot(name: &str, slot: &Slot) -> CatalogSlot {
    CatalogSlot {
        name: name.to_owned(),
        at: match slot.at {
            SlotAt::Token => "token",
            SlotAt::Option => "option",
            SlotAt::Stdin => "stdin",
            SlotAt::File => "file",
        }
        .into(),
        members: match &slot.constraint {
            Some(Constraint::Enum(members)) => members.iter().cloned().collect(),
            Some(Constraint::Pattern(_)) | None => Vec::new(),
        },
        description: slot.description.clone(),
    }
}

fn admits_shape(stage: &Stage<'_>, entry: &str, program: &str, shape: &str) -> bool {
    let ceiling = ShapePattern::Exact(shape.to_owned());
    stage
        .allow
        .iter()
        .flat_map(|l| l.iter())
        .filter_map(|p| tool_shape(p, entry, program))
        .any(|a| a.overlaps(&ceiling))
        && !stage
            .deny
            .iter()
            .flat_map(|l| l.iter())
            .filter_map(|p| tool_shape(p, entry, program))
            .any(|d| d.covers(&ceiling))
}

fn admits_open(stage: &Stage<'_>, entry: &str, program: &str) -> bool {
    stage
        .allow
        .iter()
        .flat_map(|l| l.iter())
        .filter_map(|p| tool_args(p, entry, program))
        .any(|granted| admits(stage, entry, program, granted))
}

fn admits(stage: &Stage<'_>, entry: &str, program: &str, ceiling: &ArgPattern) -> bool {
    stage
        .allow
        .iter()
        .flat_map(|l| l.iter())
        .filter_map(|p| tool_args(p, entry, program))
        .any(|a| a.overlaps(ceiling))
        && !stage
            .deny
            .iter()
            .flat_map(|l| l.iter())
            .filter_map(|p| tool_args(p, entry, program))
            .any(|d| d.covers(ceiling))
}

fn tool_args<'p>(p: &'p Pattern, entry: &str, program: &str) -> Option<&'p ArgPattern> {
    match p {
        Pattern::Tool(t) if t.entry == entry && t.program == program => match &t.target {
            ToolTarget::Args(args) => Some(args),
            ToolTarget::Shape(_) => None,
        },
        Pattern::Tool(_) | Pattern::Read(_) | Pattern::Write(_) => None,
    }
}

fn tool_shape<'p>(p: &'p Pattern, entry: &str, program: &str) -> Option<&'p ShapePattern> {
    match p {
        Pattern::Tool(t) if t.entry == entry && t.program == program => match &t.target {
            ToolTarget::Shape(shape) => Some(shape),
            ToolTarget::Args(_) => None,
        },
        Pattern::Tool(_) | Pattern::Read(_) | Pattern::Write(_) => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::snapshot::Snapshot;
    use crate::tests::agents::{hobi, load, try_source, HOBI};
    use crate::tests::compiled;
    use crate::{test_digest, Baseline, BasicAuthorizer};
    use maknae_config::{AgentsLoad, ToolsCatalog};
    use maknae_graph::catalog as cat;
    use maknae_graph::graph::Graph;

    const HOMELAB: &str = include_str!("../../../packaging/common/tools-homelab.yaml");
    const PRINCIPAL: u32 = 501;
    const ALICE: u32 = 1001;
    const BOB: u32 = 1002;
    const MALLORY: u32 = 666;
    const UIDS: [(&str, u32); 3] = [("alice", ALICE), ("bob", BOB), ("mallory", MALLORY)];
    const BINDINGS: &str =
        "schema_version: 1\nbindings:\n  user: [\"alice\", \"bob\"]\n  adversary: [\"mallory\"]\n";
    const FORGE_HOST: &str = "sentinel-674-forge.example";
    const IMAGE: &str = "registry.example/x@sha256:0000000000000000000000000000000000000000000000000000000000000000";

    fn forges() -> ForgeSet {
        let v = maknae_config::load_str(&format!(
            "- {{ name: sentinel-674-forge, kind: git, host: {FORGE_HOST}, provider: github }}\n"
        ))
        .unwrap();
        maknae_config::forges_from_section(Some(&v)).unwrap()
    }

    fn snap_with(authz: &str, tools: &str, agents: AgentsLoad) -> std::sync::Arc<Snapshot> {
        let src = try_source(authz, Some(BINDINGS), &UIDS, agents)
            .unwrap()
            .with_tools(
                ToolsCatalog::parse_with(tools, &maknae_config::shipped_grammars()).unwrap(),
            );
        compiled(&src)
    }

    fn snap(authz: &str, tools: &str) -> std::sync::Arc<Snapshot> {
        snap_with(authz, tools, AgentsLoad::default())
    }

    fn site(allow: &[&str], deny: &[&str]) -> String {
        let list = |l: &[&str]| {
            l.iter()
                .map(|p| format!("\"{p}\""))
                .collect::<Vec<_>>()
                .join(", ")
        };
        format!(
            "schema_version: 1\npermissions:\n  allow: [{}]\n  deny: [{}]\n",
            list(allow),
            list(deny)
        )
    }

    fn catalog(snap: &Snapshot, uid: u32) -> Arc<SubjectCatalog> {
        snap.catalog_for(uid, PRINCIPAL, &forges(), test_digest)
            .unwrap()
    }

    fn graph(snap: &Snapshot, uid: u32) -> Graph {
        cat::decode(&catalog(snap, uid).bytes).unwrap()
    }

    fn sorted(mut v: Vec<&str>) -> Vec<&str> {
        v.sort_unstable();
        v
    }

    fn agent_policy(allow: &[&str]) -> String {
        format!(
            "schema_version: 1\npermissions:\n  allow: [{}]\n",
            allow
                .iter()
                .map(|p| format!("\"{p}\""))
                .collect::<Vec<_>>()
                .join(", ")
        )
    }

    fn tool_entry(name: &str, credential: Option<&str>, program: &str) -> String {
        let credential = credential.map_or(String::new(), |c| format!("    credential: {c}\n"));
        format!("  {name}:\n    executes_workspace: false\n    image: {{ ref: \"{IMAGE}\" }}\n    output_to_model: redacted\n{credential}    commands:\n      {program}: {{ subcommands: [\"run *\"] }}\n")
    }

    const APP_CLASS: &str = "  sentinel-674-app-class:\n    kind: github-app-installation\n    source: minted-per-task\n    narrowing: provider\n    minting: trust-plane\n    app: sentinel-674-app-a\n";
    const PAT_CLASS: &str = "  sentinel-674-pat-class:\n    kind: github-machine-user\n";

    #[test]
    fn grammar_and_open_commands_add_no_positional_patterns() {
        let mut grammars = maknae_config::GrammarSet::empty();
        grammars.grammars.insert(
            "gh".into(),
            maknae_config::Grammar::parse("gh", "schema_version: 1\nprogram: gh\ntested: { version: \"1\", date: d }\nshapes:\n  pr.view:\n    description: View.\n    class: read\n    argv: [pr, view]\n").unwrap(),
        );
        let tools = format!("schema_version: 1\ntools:\n  sentinel-674-mixed:\n    executes_workspace: false\n    image: {{ ref: \"{IMAGE}\" }}\n    output_to_model: redacted\n    commands:\n      sh: {{ open: true }}\n      gh: {{ grammar: gh, shapes: [pr.view] }}\n      cargo: {{ subcommands: [\"build *\"] }}\n");
        let catalog = ToolsCatalog::parse_with(&tools, &grammars).unwrap();
        assert!(catalog.disabled().is_empty(), "{:?}", catalog.disabled());
        let authz = site(
            &[
                "Tool(sentinel-674-mixed sh -c *)",
                "Tool(sentinel-674-mixed gh pr *)",
                "Tool(sentinel-674-mixed cargo build *)",
            ],
            &[],
        );
        let src = try_source(&authz, Some(BINDINGS), &UIDS, AgentsLoad::default())
            .unwrap()
            .with_tools(catalog);
        let alice = graph(&compiled(&src), ALICE);
        assert_eq!(cat::entries(&alice), ["sentinel-674-mixed"]);
        assert_eq!(
            cat::patterns(&alice, "sentinel-674-mixed", "cargo"),
            ["build *"]
        );
        assert!(cat::patterns(&alice, "sentinel-674-mixed", "sh").is_empty());
        assert!(cat::patterns(&alice, "sentinel-674-mixed", "gh").is_empty());
    }

    #[test]
    fn a_replacing_list_replaces_the_site_list() {
        let authz = format!(
            "{}subjects:\n  alice:\n    permissions:\n      allow: [\"Tool(rust-fetch cargo fetch --locked*)\"]\n",
            site(&["Tool(rust-build cargo build *)"], &[])
        );
        let s = snap(&authz, HOMELAB);
        let alice = graph(&s, ALICE);
        assert_eq!(cat::entries(&alice), ["rust-fetch"]);
        assert_eq!(
            cat::patterns(&alice, "rust-fetch", "cargo"),
            ["fetch --locked*"]
        );
        assert!(cat::patterns(&alice, "rust-build", "cargo").is_empty());
    }

    #[test]
    fn catalog_includes_role_granted_patterns() {
        let roles = "roles:\n  user:\n    permissions:\n      allow: [\"Tool(rust-fetch cargo fetch --locked*)\"]\n      deny: [\"Tool(rust-build cargo build *)\"]\n";
        let authz = format!(
            "{}{roles}",
            site(
                &[
                    "Tool(rust-build cargo build *)",
                    "Tool(rust-build cargo test *)"
                ],
                &[]
            )
        );
        let s = snap_with(&authz, HOMELAB, load(vec![hobi()], &[]));
        let bob = graph(&s, BOB);
        assert_eq!(sorted(cat::entries(&bob)), ["rust-build", "rust-fetch"]);
        assert_eq!(cat::patterns(&bob, "rust-build", "cargo"), ["test *"]);
        assert_eq!(
            cat::patterns(&bob, "rust-fetch", "cargo"),
            ["fetch --locked*"]
        );
        let replaced = format!(
            "{}subjects:\n  alice:\n    permissions:\n      allow: [\"Tool(rust-build cargo build *)\"]\n{roles}",
            site(&["Tool(rust-build cargo test *)"], &[])
        );
        let alice = graph(&snap(&replaced, HOMELAB), ALICE);
        assert_eq!(cat::entries(&alice), ["rust-fetch"]);
        let policy = agent_policy(&["Tool(rust-build cargo build *)"]);
        let agent = snap_with(&authz, HOMELAB, load(vec![hobi()], &[("hobi", &policy)]));
        let hobi = graph(&agent, HOBI);
        assert_eq!(cat::entries(&hobi), ["rust-build"]);
        assert_eq!(cat::patterns(&hobi, "rust-build", "cargo"), ["build *"]);
    }

    #[test]
    fn bob_and_alice_differ() {
        let authz = format!(
            "{}subjects:\n  alice:\n    permissions:\n      allow: [\"Tool(rust-fetch cargo fetch --locked*)\"]\n",
            site(&["Tool(rust-build cargo build *)"], &[])
        );
        let s = snap(&authz, HOMELAB);
        let bob = graph(&s, BOB);
        assert_eq!(cat::entries(&bob), ["rust-build"]);
        assert_eq!(cat::patterns(&bob, "rust-build", "cargo"), ["build *"]);
        assert_ne!(catalog(&s, ALICE).digest, catalog(&s, BOB).digest);
    }

    #[test]
    fn an_agent_follows_the_pdps_list_selection() {
        let authz = site(&["Tool(rust-build cargo build *)"], &[]);
        let none = snap_with(&authz, HOMELAB, load(vec![hobi()], &[]));
        assert!(none.agent_of(HOBI).is_some());
        assert!(
            cat::entries(&graph(&none, HOBI)).is_empty(),
            "permissions: Some([]) replaces the site list"
        );
        let policy = agent_policy(&["Tool(rust-fetch cargo fetch --locked*)"]);
        let granted = snap_with(&authz, HOMELAB, load(vec![hobi()], &[("hobi", &policy)]));
        assert_eq!(cat::entries(&graph(&granted, HOBI)), ["rust-fetch"]);
    }

    #[test]
    fn a_right_stage_grant_is_seen_and_its_denies_apply() {
        let authz = site(&[], &["Tool(rust-build cargo test *)"]);
        let s = snap_with(&authz, HOMELAB, load(vec![hobi()], &[]));
        let mut lp = crate::tests::granting_tool_invoke(s.loaded());
        let entry = lp.subjects.0.get_mut(&HOBI).unwrap();
        let mut right = entry.right.clone().unwrap();
        for args in ["build *", "test *"] {
            right
                .allow
                .push(maknae_config::Pattern::Tool(maknae_config::ToolPattern {
                    entry: "rust-build".into(),
                    program: "cargo".into(),
                    target: maknae_config::ToolTarget::Args(
                        maknae_config::ArgPattern::parse(args).unwrap(),
                    ),
                }));
        }
        entry.right = Some(right);
        let got = input(&lp, HOBI, PRINCIPAL, &forges(), usize::MAX).unwrap();
        assert_eq!(got.entries.len(), 1);
        assert_eq!(got.entries[0].name, "rust-build");
        assert_eq!(
            got.entries[0].programs,
            [("cargo".to_string(), vec!["build *".to_string()])]
        );
    }

    #[test]
    fn a_grant_reaches_only_its_own_entry_and_program() {
        let tools = format!(
            "schema_version: 1\ntools:\n{}{}",
            tool_entry("sentinel-674-granted", None, "gh"),
            tool_entry("sentinel-674-same-program", None, "gh"),
        );
        let s = snap(&site(&["Tool(sentinel-674-granted gh run *)"], &[]), &tools);
        assert_eq!(cat::entries(&graph(&s, ALICE)), ["sentinel-674-granted"]);
    }

    #[test]
    fn an_agent_never_sees_a_kind_without_a_reach_check() {
        let tools = format!(
            "schema_version: 1\ncredential_classes:\n{APP_CLASS}{PAT_CLASS}tools:\n{}{}",
            tool_entry(
                "sentinel-674-app-entry",
                Some("sentinel-674-app-class"),
                "gh"
            ),
            tool_entry(
                "sentinel-674-pat-entry",
                Some("sentinel-674-pat-class"),
                "gh"
            ),
        );
        let grants = [
            "Tool(sentinel-674-app-entry gh run *)",
            "Tool(sentinel-674-pat-entry gh run *)",
        ];
        let policy = agent_policy(&grants);
        let s = snap_with(
            &site(&grants, &[]),
            &tools,
            load(vec![hobi()], &[("hobi", &policy)]),
        );
        assert_eq!(cat::entries(&graph(&s, HOBI)), ["sentinel-674-app-entry"]);
        assert_eq!(
            cat::entries(&graph(&s, ALICE)),
            ["sentinel-674-app-entry", "sentinel-674-pat-entry"],
            "a user is not limited to reach-checked kinds"
        );
    }

    fn git_entry(name: &str, credential: &str, enabled: bool) -> String {
        tool_entry(name, Some(credential), "gh").replacen(
            "    executes_workspace",
            &format!("    enabled: {enabled}\n    binds: {{ git: {{ resolver: git }} }}\n    executes_workspace"),
            1,
        )
    }

    #[test]
    fn the_agents_forge_credentials_are_those_of_its_granted_git_entries() {
        const APP_B_CLASS: &str = "  sentinel-674-app-b-class:\n    kind: github-app-installation\n    source: minted-per-task\n    narrowing: provider\n    minting: trust-plane\n    app: sentinel-674-app-b\n";
        let tools = format!(
            "schema_version: 1\ncredential_classes:\n{APP_CLASS}{APP_B_CLASS}{PAT_CLASS}tools:\n{}{}{}{}{}{}",
            git_entry("sentinel-674-app", "sentinel-674-app-class", true),
            git_entry("sentinel-674-app-again", "sentinel-674-app-class", true),
            git_entry("sentinel-674-pat", "sentinel-674-pat-class", true),
            git_entry("sentinel-674-off", "sentinel-674-app-b-class", false),
            git_entry("sentinel-674-ungranted", "sentinel-674-app-b-class", true),
            tool_entry("sentinel-674-unbound", Some("sentinel-674-app-b-class"), "gh"),
        );
        let grants = [
            "Tool(sentinel-674-app gh run *)",
            "Tool(sentinel-674-app-again gh run *)",
            "Tool(sentinel-674-pat gh run *)",
            "Tool(sentinel-674-off gh run *)",
            "Tool(sentinel-674-unbound gh run *)",
        ];
        let policy = agent_policy(&grants);
        let s = snap_with(
            &site(&grants, &[]),
            &tools,
            load(vec![hobi()], &[("hobi", &policy)]),
        );
        let cref = |kind: &str, name: &str| maknae_proto::CredentialRef {
            kind: kind.into(),
            name: name.into(),
        };
        let want = vec![
            cref("github-app-installation", "sentinel-674-app-a"),
            cref("github-machine-user", "sentinel-674-pat-class"),
        ];
        assert_eq!(s.forge_credentials(HOBI, PRINCIPAL), want);
        assert!(
            s.forge_credentials(ALICE, PRINCIPAL).is_empty(),
            "not an agent"
        );
        assert_eq!(
            Baseline::forge_credentials(&authorizer(s.clone()), HOBI, PRINCIPAL),
            want
        );
    }

    #[test]
    fn an_agent_drops_a_missing_class_and_keeps_credential_none() {
        let tools = ToolsCatalog::parse_with(HOMELAB, &maknae_config::shipped_grammars()).unwrap();
        let none = tools.entry("rust-build").unwrap();
        assert_eq!(none.credential, None);
        assert!(reach_checked(none, &tools));
        let mut missing = none.clone();
        missing.credential = Some("sentinel-674-missing-class".into());
        assert!(!reach_checked(&missing, &tools));
        assert!(reach_checked(tools.entry("github-read").unwrap(), &tools));

        let policy = agent_policy(&["Tool(rust-build cargo build *)"]);
        let s = snap_with(
            &site(&[], &[]),
            HOMELAB,
            load(vec![hobi()], &[("hobi", &policy)]),
        );
        assert_eq!(cat::entries(&graph(&s, HOBI)), ["rust-build"]);
    }

    #[test]
    fn contained_and_adversary_get_empty() {
        let s = snap(&site(&["Tool(rust-build cargo build *)"], &[]), HOMELAB);
        assert!(s.contained(MALLORY, PRINCIPAL));
        assert_eq!(
            input(s.loaded(), MALLORY, PRINCIPAL, &forges(), usize::MAX),
            Ok(CatalogInput::default())
        );
        assert_eq!(
            *catalog(&s, MALLORY).bytes,
            cat::encode(&CatalogInput::default()).unwrap()
        );
        assert_eq!(cat::entries(&graph(&s, BOB)), ["rust-build"]);
    }

    #[test]
    fn only_an_unbound_uid_holds_no_role() {
        let s = snap(&site(&[], &[]), HOMELAB);
        assert!(s.no_role(4242, PRINCIPAL));
        for bound in [ALICE, BOB, MALLORY] {
            assert!(!s.no_role(bound, PRINCIPAL), "{bound}");
        }
    }

    #[test]
    fn ceiling_shapes_not_grant_text() {
        let s = snap(&site(&["Tool(github-post gh:pr.review.*)"], &[]), HOMELAB);
        let g = graph(&s, ALICE);
        assert_eq!(cat::entries(&g), ["github-post"]);
        assert_eq!(
            shape_names(&g, "github-post", "gh"),
            [
                "pr.review.approve",
                "pr.review.comment",
                "pr.review.request-changes"
            ]
        );
    }

    #[test]
    fn a_covering_deny_removes_and_a_noncovering_deny_keeps() {
        let authz = format!(
            "{}subjects:\n  alice:\n    permissions:\n      allow: [\"Tool(rust-build cargo build *)\", \"Tool(rust-build cargo test *)\", \"Tool(rust-build cargo check *)\"]\n      deny: [\"Tool(rust-build cargo check *)\", \"Tool(rust-build cargo test --sentinel-674)\"]\n",
            site(
                &["Tool(rust-build cargo build *)", "Tool(rust-build cargo test *)"],
                &["Tool(rust-build cargo build *)", "Tool(rust-build cargo test --sentinel-674)"],
            )
        );
        let s = snap(&authz, HOMELAB);
        assert_eq!(
            cat::patterns(&graph(&s, BOB), "rust-build", "cargo"),
            ["test *"]
        );
        assert_eq!(
            cat::patterns(&graph(&s, ALICE), "rust-build", "cargo"),
            ["test *"]
        );
        let all_denied = snap(
            &site(
                &["Tool(rust-build cargo build *)"],
                &["Tool(rust-build cargo build *)"],
            ),
            HOMELAB,
        );
        assert!(cat::entries(&graph(&all_denied, BOB)).is_empty());
    }

    #[test]
    fn git_forges_appear_in_every_permitted_catalog() {
        let unbound = snap(&site(&["Tool(rust-build cargo build *)"], &[]), HOMELAB);
        let g = graph(&unbound, ALICE);
        assert_eq!(cat::forges(&g, "git"), [(FORGE_HOST, "github")]);
        assert!(cat::entries_for_binding(&g, "git").is_empty());
        let nothing = snap(&site(&[], &[]), HOMELAB);
        let g = graph(&nothing, ALICE);
        assert!(cat::entries(&g).is_empty());
        assert_eq!(cat::forges(&g, "git"), [(FORGE_HOST, "github")]);
        let bound = snap(&site(&["Tool(github-read gh:pr.view)"], &[]), HOMELAB);
        let g = graph(&bound, ALICE);
        assert_eq!(cat::forges(&g, "git"), [(FORGE_HOST, "github")]);
        assert_eq!(cat::entries_for_binding(&g, "git"), ["github-read"]);
        for uid in [MALLORY, 4242] {
            assert_eq!(
                input(unbound.loaded(), uid, PRINCIPAL, &forges(), usize::MAX),
                Ok(CatalogInput::default()),
                "{uid}"
            );
        }
    }

    const SENTINEL_TOOLS: &str = "schema_version: 1\ncredential_classes:\n  sentinel-674-cred-class:\n    kind: github-app-installation\n    source: minted-per-task\n    narrowing: provider\n    minting: trust-plane\n    app: sentinel-674-app\ntools:\n  sentinel-674-entry:\n    description: Read a pull request.\n    image: { ref: \"registry.example/sentinel-674-img@sha256:5e175e175e175e175e175e175e175e175e175e175e175e175e175e175e175e17\" }\n    isolation: container\n    executes_workspace: true\n    network: { via: maknae-proxy, sites: [sentinel-674-site.example] }\n    workspace: rw\n    volumes:\n      sentinel-674-vol: { access: ro, scope: tasker }\n    credential: sentinel-674-cred-class\n    output_to_model: redacted\n    binds: { git: { resolver: git } }\n    commands:\n      gh:\n        subcommands: [\"pr view *\"]\n        deny_args: [\"--sentinel-674-deny-xq\"]\n";

    #[test]
    fn no_fence_in_bytes_unique_sentinels() {
        let grant = ["Tool(sentinel-674-entry gh pr view *)"];
        let policy = agent_policy(&grant);
        let s = snap_with(
            &site(&grant, &[]),
            SENTINEL_TOOLS,
            load(vec![hobi()], &[("hobi", &policy)]),
        );
        let has = |bytes: &[u8], needle: &str| {
            bytes.windows(needle.len()).any(|w| w == needle.as_bytes())
        };
        for uid in [ALICE, HOBI] {
            let c = catalog(&s, uid);
            assert!(has(&c.bytes, "sentinel-674-entry"), "uid {uid}");
            assert!(has(&c.bytes, FORGE_HOST), "uid {uid}");
            for fenced in [
                "sentinel-674-cred-class",
                "sentinel-674-app",
                "sentinel-674-img",
                "5e175e17",
                "sentinel-674-site",
                "--sentinel-674-deny-xq",
                "sentinel-674-vol",
            ] {
                assert!(!has(&c.bytes, fenced), "uid {uid}: {fenced} in the catalog");
            }
        }
    }

    const HOMELAB_GRANTS: [&str; 15] = [
        "Tool(github-read gh:pr.view)",
        "Tool(github-read gh:pr.diff)",
        "Tool(github-read gh:pr.checks)",
        "Tool(github-read git fetch *)",
        "Tool(github-read git checkout *)",
        "Tool(github-post gh:pr.review.*)",
        "Tool(github-post gh:pr.comment)",
        "Tool(github-issues-read gh:issue.*)",
        "Tool(rust-fetch cargo fetch --locked*)",
        "Tool(rust-build cargo build *)",
        "Tool(rust-build cargo check *)",
        "Tool(rust-build cargo clippy *)",
        "Tool(rust-build cargo test *)",
        "Tool(rust-build cargo fmt --check*)",
        "Tool(rust-scratch cargo run *)",
    ];

    #[test]
    fn homelab_catalog_structure() {
        let s = snap(&site(&HOMELAB_GRANTS, &[]), HOMELAB);
        let g = graph(&s, ALICE);
        assert_eq!(
            cat::entries(&g),
            [
                "github-issues-read",
                "github-post",
                "github-read",
                "rust-build",
                "rust-fetch",
                "rust-scratch"
            ]
        );
        assert_eq!(
            shape_names(&g, "github-post", "gh"),
            [
                "pr.comment",
                "pr.review.approve",
                "pr.review.comment",
                "pr.review.request-changes"
            ]
        );
        assert!(cat::patterns(&g, "github-post", "gh").is_empty());
        assert_eq!(
            shape_names(&g, "github-read", "gh"),
            ["pr.checks", "pr.diff", "pr.view"]
        );
        assert_eq!(
            shape_names(&g, "github-issues-read", "gh"),
            ["issue.list", "issue.status", "issue.view"]
        );
        assert!(cat::open_program(&g, "rust-scratch", "cargo"));
        assert!(!cat::open_program(&g, "rust-scratch", "rustc"));
        assert_eq!(
            sorted(cat::patterns(&g, "github-read", "git")),
            ["checkout *", "fetch *"]
        );
        assert_eq!(
            sorted(cat::patterns(&g, "rust-build", "cargo")),
            ["build *", "check *", "clippy *", "fmt --check*", "test *"]
        );
        assert_eq!(
            cat::patterns(&g, "rust-fetch", "cargo"),
            ["fetch --locked*"]
        );
        assert_eq!(
            sorted(cat::entries_for_binding(&g, "git")),
            ["github-issues-read", "github-post", "github-read"]
        );
        assert_eq!(cat::forges(&g, "git"), [(FORGE_HOST, "github")]);
        let read = g.lookup(cat::ENTRY, "github-read").unwrap();
        assert_eq!(
            read.attrs.get(cat::ATTR_DESCRIPTION),
            Some(&maknae_graph::record::AttrValue::Str(
                "Read pull requests and fetch or check out their branches.".into()
            ))
        );
        assert_eq!(
            read.attrs.get(cat::ATTR_EXECUTES_WORKSPACE),
            Some(&maknae_graph::record::AttrValue::U64(1))
        );
        assert_eq!(
            g.lookup(cat::ENTRY, "github-post")
                .unwrap()
                .attrs
                .get(cat::ATTR_EXECUTES_WORKSPACE),
            Some(&maknae_graph::record::AttrValue::U64(0))
        );
        assert_eq!(
            read.attrs.get(cat::ATTR_OUTPUT),
            Some(&maknae_graph::record::AttrValue::Str("redacted".into()))
        );
    }

    #[test]
    fn an_output_status_only_entry_says_so() {
        let tools = HOMELAB.replacen(
            "output_to_model: redacted",
            "output_to_model: status_only",
            1,
        );
        let s = snap(&site(&["Tool(github-read gh:pr.view)"], &[]), &tools);
        assert_eq!(
            graph(&s, ALICE)
                .lookup(cat::ENTRY, "github-read")
                .unwrap()
                .attrs
                .get(cat::ATTR_OUTPUT),
            Some(&maknae_graph::record::AttrValue::Str("status_only".into()))
        );
    }

    #[test]
    fn a_catalog_whose_keys_pass_the_bound_is_refused_before_it_is_encoded() {
        let program = "p".repeat(1000);
        let subcommands: Vec<String> = (0..80).map(|i| format!("\"s{i}\"")).collect();
        let tools = format!(
            "schema_version: 1\ntools:\n  wide:\n    executes_workspace: false\n    image: {{ ref: \"{IMAGE}\" }}\n    output_to_model: redacted\n    commands:\n      {program}: {{ subcommands: [{}] }}\n",
            subcommands.join(", ")
        );
        let s = snap(&site(&[&format!("Tool(wide {program} s*)")], &[]), &tools);
        let max = TOOL_CATALOG_MAX_BYTES;
        assert_eq!(
            input(s.loaded(), BOB, PRINCIPAL, &forges(), max),
            Err(CatalogError::TooLarge)
        );
        let under = input(s.loaded(), BOB, PRINCIPAL, &forges(), usize::MAX).unwrap();
        assert_eq!(under.entries[0].programs[0].1.len(), 80);
        let need = graph_text(&under.entries[0]);
        assert!(input(s.loaded(), BOB, PRINCIPAL, &forges(), need).is_ok());
        assert_eq!(
            input(s.loaded(), BOB, PRINCIPAL, &forges(), need - 1),
            Err(CatalogError::TooLarge)
        );
        assert_eq!(
            s.catalog_for(BOB, PRINCIPAL, &forges(), test_digest)
                .map(|c| c.digest),
            Err(CatalogError::TooLarge)
        );
    }

    #[test]
    fn graph_text_counts_each_key_and_each_pattern_text() {
        let entry = CatalogEntry {
            name: "e".into(),
            description: Some("not counted".into()),
            executes_workspace: false,
            output: CatalogOutput::Redacted,
            binds: vec![],
            programs: vec![
                ("p".into(), vec!["ab".into(), "c".into()]),
                ("qq".into(), vec![]),
            ],
            open: vec![],
            shapes: vec![],
        };
        assert_eq!(graph_text(&entry), 3 + (3 + 1 + 4) + (3 + 1 + 2) + 4);
    }

    #[test]
    fn a_no_role_subject_gets_empty() {
        let s = snap(&site(&["Tool(rust-build cargo build *)"], &[]), HOMELAB);
        assert!(s.no_role(4242, PRINCIPAL));
        assert_eq!(
            input(s.loaded(), 4242, PRINCIPAL, &forges(), usize::MAX),
            Ok(CatalogInput::default())
        );
    }

    fn authorizer(s: std::sync::Arc<Snapshot>) -> BasicAuthorizer {
        BasicAuthorizer::from_snapshot(
            maknae_config::Principal {
                name: "operator".into(),
                uid: PRINCIPAL,
            },
            crate::PolicyPaths::in_dir(std::path::Path::new("/etc/maknae")),
            test_digest,
            s,
        )
    }

    const GH_GRAMMAR: &str = "schema_version: 1\nprogram: gh\ntested: { version: \"1\", date: d }\nshapes:\n  issue.list:\n    description: List issues.\n    class: read\n    forge: { base: [read] }\n    argv: [issue, list, \"--state={state}\"]\n    slots:\n      state: { at: option, enum: [open, closed, all], description: Which issues. }\n  issue.view:\n    description: View an issue.\n    class: read\n    forge: { base: [read] }\n    argv: [issue, view, \"{number}\"]\n    slots:\n      number: { at: token, pattern: \"^sentinel-674-rx[0-9]+$\", description: The number. }\n  issue.delete:\n    description: Delete an issue.\n    class: write\n    forge: { base: [issue-write] }\n    argv: [issue, delete, sentinel-674-argv-lit]\n  pr.view:\n    description: View a PR.\n    class: read\n    forge: { base: [read] }\n    argv: [pr, view]\n  pr.create:\n    description: Open a PR.\n    class: write\n    forge: { base: [issue-write] }\n    argv: [pr, create]\n";
    const GH_SHAPES: &str = "[issue.list, issue.view, issue.delete, pr.view, pr.create]";

    fn gh_entry(name: &str) -> String {
        format!("  {name}:\n    executes_workspace: false\n    image: {{ ref: \"{IMAGE}\" }}\n    output_to_model: redacted\n    credential: sentinel-674-app-class\n    binds: {{ git: {{ resolver: git }} }}\n    commands:\n      gh: {{ grammar: gh, shapes: {GH_SHAPES} }}\n")
    }

    fn grammar_catalog(entries: &str) -> ToolsCatalog {
        let mut grammars = maknae_config::GrammarSet::empty();
        grammars.grammars.insert(
            "gh".into(),
            maknae_config::Grammar::parse("gh", GH_GRAMMAR).unwrap(),
        );
        let tools = format!("schema_version: 1\ncredential_classes:\n{APP_CLASS}tools:\n{entries}");
        let catalog = ToolsCatalog::parse_with(&tools, &grammars).unwrap();
        assert!(catalog.disabled().is_empty(), "{:?}", catalog.disabled());
        catalog
    }

    fn grammar_snap(authz: &str, entries: &str, agents: AgentsLoad) -> std::sync::Arc<Snapshot> {
        let src = try_source(authz, Some(BINDINGS), &UIDS, agents)
            .unwrap()
            .with_tools(grammar_catalog(entries));
        compiled(&src)
    }

    fn shape_names(g: &Graph, entry: &str, program: &str) -> Vec<String> {
        let mut names: Vec<String> = cat::shapes(g, entry, program)
            .into_iter()
            .map(|s| s.name)
            .collect();
        names.sort();
        names
    }

    fn user_role(allow: &[&str], deny: &[&str]) -> String {
        let list = |l: &[&str]| {
            l.iter()
                .map(|p| format!("\"{p}\""))
                .collect::<Vec<_>>()
                .join(", ")
        };
        format!(
            "{}roles:\n  user:\n    permissions:\n      allow: [{}]\n      deny: [{}]\n",
            site(&[], &[]),
            list(allow),
            list(deny)
        )
    }

    #[test]
    fn only_admitted_shapes_are_granted() {
        let authz = user_role(
            &["Tool(gh-tool gh:issue.*)"],
            &["Tool(gh-tool gh:issue.delete)"],
        );
        let s = grammar_snap(&authz, &gh_entry("gh-tool"), AgentsLoad::default());
        let g = graph(&s, BOB);
        assert_eq!(cat::entries(&g), ["gh-tool"]);
        assert_eq!(
            shape_names(&g, "gh-tool", "gh"),
            ["issue.list", "issue.view"]
        );
        assert!(cat::patterns(&g, "gh-tool", "gh").is_empty());
        let list = cat::shapes(&g, "gh-tool", "gh")
            .into_iter()
            .find(|s| s.name == "issue.list")
            .unwrap();
        assert_eq!(list.access, "read");
        assert_eq!(list.description, "List issues.");
        assert_eq!(list.slots.len(), 1);
        assert_eq!(list.slots[0].name, "state");
        assert_eq!(list.slots[0].at, "option");
        assert_eq!(list.slots[0].members, ["all", "closed", "open"]);
    }

    #[test]
    fn ungranted_shapes_have_no_node() {
        let authz = user_role(&["Tool(gh-tool gh:issue.view)"], &[]);
        let s = grammar_snap(&authz, &gh_entry("gh-tool"), AgentsLoad::default());
        let g = graph(&s, BOB);
        let nodes: Vec<&str> = g
            .nodes()
            .iter()
            .filter(|n| n.kind == cat::SHAPE)
            .map(|n| n.key.as_str())
            .collect();
        assert_eq!(nodes, ["gh-tool/gh/issue.view"]);
        let bytes = catalog(&s, BOB).bytes.clone();
        for ungranted in [
            "issue.list",
            "issue.delete",
            "pr.view",
            "pr.create",
            "Open a PR",
        ] {
            assert!(
                !bytes
                    .windows(ungranted.len())
                    .any(|w| w == ungranted.as_bytes()),
                "{ungranted}"
            );
        }
        let none = grammar_snap(&site(&[], &[]), &gh_entry("gh-tool"), AgentsLoad::default());
        assert!(cat::entries(&graph(&none, BOB)).is_empty());
        let args_only = user_role(&["Tool(gh-tool gh issue *)"], &[]);
        let s = grammar_snap(&args_only, &gh_entry("gh-tool"), AgentsLoad::default());
        assert!(cat::entries(&graph(&s, BOB)).is_empty());
    }

    #[test]
    fn a_wildcard_grant_reaches_every_shape_and_a_prefix_deny_removes_its_family() {
        let authz = user_role(&["Tool(gh-tool gh:*)"], &["Tool(gh-tool gh:pr.*)"]);
        let s = grammar_snap(&authz, &gh_entry("gh-tool"), AgentsLoad::default());
        assert_eq!(
            shape_names(&graph(&s, BOB), "gh-tool", "gh"),
            ["issue.delete", "issue.list", "issue.view"]
        );
    }

    const OPEN_ENTRY: &str = "  sentinel-674-open:\n    executes_workspace: false\n    image: { ref: \"registry.example/x@sha256:0000000000000000000000000000000000000000000000000000000000000000\" }\n    output_to_model: redacted\n    commands:\n      sh: { open: true }\n";

    #[test]
    fn open_program_appears_when_granted() {
        let tools = format!("schema_version: 1\ntools:\n{OPEN_ENTRY}");
        let granted = snap(&site(&["Tool(sentinel-674-open sh -c *)"], &[]), &tools);
        let g = graph(&granted, ALICE);
        assert_eq!(cat::entries(&g), ["sentinel-674-open"]);
        assert!(cat::open_program(&g, "sentinel-674-open", "sh"));
        assert!(cat::patterns(&g, "sentinel-674-open", "sh").is_empty());

        let ungranted = snap(&site(&[], &[]), &tools);
        assert!(cat::entries(&graph(&ungranted, ALICE)).is_empty());

        let narrow_deny = snap(
            &site(
                &["Tool(sentinel-674-open sh -c *)"],
                &["Tool(sentinel-674-open sh -c ls)"],
            ),
            &tools,
        );
        assert!(cat::open_program(
            &graph(&narrow_deny, ALICE),
            "sentinel-674-open",
            "sh"
        ));

        let covering_deny = snap(
            &site(
                &["Tool(sentinel-674-open sh -c *)"],
                &["Tool(sentinel-674-open sh -c *)"],
            ),
            &tools,
        );
        assert!(cat::entries(&graph(&covering_deny, ALICE)).is_empty());
    }

    #[test]
    fn forge_credentials_counts_a_shape_grant() {
        let grants = ["Tool(gh-tool gh:pr.*)"];
        let policy = agent_policy(&grants);
        let s = grammar_snap(
            &site(&grants, &[]),
            &gh_entry("gh-tool"),
            load(vec![hobi()], &[("hobi", &policy)]),
        );
        assert_eq!(
            s.forge_credentials(HOBI, PRINCIPAL),
            vec![maknae_proto::CredentialRef {
                kind: "github-app-installation".into(),
                name: "sentinel-674-app-a".into(),
            }]
        );
        assert_eq!(
            shape_names(&graph(&s, HOBI), "gh-tool", "gh"),
            ["pr.create", "pr.view"]
        );
        let none = agent_policy(&["Tool(gh-tool gh:issue.*)"]);
        let other = grammar_snap(
            &site(&grants, &[]),
            &gh_entry("gh-tool"),
            load(vec![hobi()], &[("hobi", &none)]),
        );
        assert_eq!(other.forge_credentials(HOBI, PRINCIPAL).len(), 1);
        let nothing = grammar_snap(
            &site(&[], &[]),
            &gh_entry("gh-tool"),
            load(vec![hobi()], &[("hobi", &agent_policy(&[]))]),
        );
        assert!(nothing.forge_credentials(HOBI, PRINCIPAL).is_empty());
    }

    #[test]
    fn catalog_never_carries_pattern_argv_or_digest() {
        let authz = user_role(&["Tool(gh-tool gh:*)"], &[]);
        let catalog_in = grammar_catalog(&gh_entry("gh-tool"));
        let CommandForm::Grammar {
            grammar_canonical, ..
        } = &catalog_in.entry("gh-tool").unwrap().commands["gh"].form
        else {
            panic!("grammar form")
        };
        let canonical = grammar_canonical.to_string();
        let s = grammar_snap(&authz, &gh_entry("gh-tool"), AgentsLoad::default());
        let bytes = catalog(&s, BOB).bytes.clone();
        let has = |needle: &str| bytes.windows(needle.len()).any(|w| w == needle.as_bytes());
        assert!(has("issue.view") && has("The number.") && has("closed"));
        for fenced in [
            "sentinel-674-rx",
            "[0-9]",
            "sentinel-674-argv-lit",
            "sha256",
            "sentinel-674-app",
            "--state=",
            canonical.as_str(),
        ] {
            assert!(!has(fenced), "{fenced} in the catalog");
        }
        let g = cat::decode(&bytes).unwrap();
        for n in g.nodes().iter().filter(|n| n.kind == cat::SHAPE) {
            for key in n.attrs.keys() {
                for fence in ["pattern", "argv", "digest", "sha", "canonical", "image"] {
                    assert!(!key.contains(fence), "{key}");
                }
            }
        }
    }

    #[test]
    fn a_thirty_shape_catalog_fits_the_cap_and_an_oversize_one_is_refused() {
        let mut grammar = String::from(
            "schema_version: 1\nprogram: gh\ntested: { version: \"1\", date: d }\nshapes:\n",
        );
        let mut names = Vec::new();
        for i in 0..30 {
            names.push(format!("fam{}.op{i}", i % 6));
            grammar.push_str(&format!("  fam{}.op{i}:\n    description: Shape number {i} does one bounded thing against the repository this task is about.\n    class: read\n    argv: [thing, \"{{a}}\", \"--mode={{b}}\"]\n    slots:\n      a: {{ at: token, pattern: \"^[a-z]+$\", description: The first argument of shape {i}. }}\n      b: {{ at: option, enum: [one, two, three, four], description: The mode of shape {i}. }}\n", i % 6));
        }
        let mut grammars = maknae_config::GrammarSet::empty();
        grammars.grammars.insert(
            "gh".into(),
            maknae_config::Grammar::parse("gh", &grammar).unwrap(),
        );
        let tools = format!(
            "schema_version: 1\ntools:\n  big:\n    executes_workspace: false\n    image: {{ ref: \"{IMAGE}\" }}\n    output_to_model: redacted\n    commands:\n      gh: {{ grammar: gh, shapes: [{}] }}\n",
            names.join(", ")
        );
        let catalog_in = ToolsCatalog::parse_with(&tools, &grammars).unwrap();
        assert!(
            catalog_in.disabled().is_empty(),
            "{:?}",
            catalog_in.disabled()
        );
        let src = try_source(
            &site(&["Tool(big gh:*)"], &[]),
            Some(BINDINGS),
            &UIDS,
            AgentsLoad::default(),
        )
        .unwrap()
        .with_tools(catalog_in);
        let s = compiled(&src);
        let c = catalog(&s, ALICE);
        assert!(c.bytes.len() < TOOL_CATALOG_MAX_BYTES, "{}", c.bytes.len());
        assert_eq!(
            cat::shapes(&cat::decode(&c.bytes).unwrap(), "big", "gh").len(),
            30
        );
        assert_eq!(
            input(s.loaded(), ALICE, PRINCIPAL, &forges(), 1000),
            Err(CatalogError::TooLarge),
            "shape text counts against the pre-build budget"
        );
    }

    #[test]
    fn only_an_admitted_subject_has_an_admitted_catalog() {
        let s = snap(&site(&["Tool(rust-build cargo build *)"], &[]), HOMELAB);
        let auth = authorizer(s.clone());
        let bob = Baseline::admitted_catalog(&auth, BOB, PRINCIPAL, &forges()).unwrap();
        assert_eq!(bob.digest, catalog(&s, BOB).digest);
        assert!(s.no_role(4242, PRINCIPAL));
        for uid in [MALLORY, 4242] {
            assert_eq!(
                Baseline::admitted_catalog(&auth, uid, PRINCIPAL, &forges()),
                Err(CatalogError::NotAdmitted)
            );
        }
    }

    #[test]
    fn the_digest_is_content_only() {
        let authz = site(&["Tool(rust-build cargo build *)"], &[]);
        let first = snap(&authz, HOMELAB);
        let auth = authorizer(first.clone());
        let before = Baseline::catalog_for(&auth, ALICE, PRINCIPAL, &forges()).unwrap();
        assert_eq!(
            before.digest,
            maknae_proto::CatalogDigest(test_digest(&before.bytes))
        );

        let unrelated = snap(
            &format!("{authz}destinations:\n  user:\n    allow: [\"provider:openai\"]\n"),
            HOMELAB,
        );
        assert_ne!(
            unrelated.policy_sha256(test_digest),
            first.policy_sha256(test_digest)
        );
        auth.install(unrelated);
        let after = Baseline::catalog_for(&auth, ALICE, PRINCIPAL, &forges()).unwrap();
        assert_eq!(after.digest, before.digest);
        assert_eq!(after.bytes, before.bytes);

        auth.install(snap(
            &authz,
            &HOMELAB.replace(
                "Build, check, lint and test a workspace with no network.",
                "sentinel-674 changed",
            ),
        ));
        let changed = Baseline::catalog_for(&auth, ALICE, PRINCIPAL, &forges()).unwrap();
        assert_ne!(changed.digest, before.digest);
    }

    #[test]
    fn the_cache_is_per_snapshot() {
        use std::sync::atomic::Ordering::Relaxed;
        let authz = site(&["Tool(rust-build cargo build *)"], &[]);
        let s = snap(&authz, HOMELAB);
        assert_eq!(s.catalog_builds.load(Relaxed), 0);
        let one = catalog(&s, ALICE);
        let two = catalog(&s, ALICE);
        assert!(Arc::ptr_eq(&one, &two));
        assert_eq!(s.catalog_builds.load(Relaxed), 1);
        catalog(&s, BOB);
        assert_eq!(s.catalog_builds.load(Relaxed), 2);
        let next = snap(&authz, HOMELAB);
        assert_eq!(next.catalog_builds.load(Relaxed), 0);
        let three = catalog(&next, ALICE);
        assert!(!Arc::ptr_eq(&one, &three));
        assert_eq!(three, one);
        assert_eq!(next.catalog_builds.load(Relaxed), 1);
    }

    #[test]
    fn an_oversize_catalog_is_too_large() {
        let mut tools = String::from("schema_version: 1\ntools:\n");
        let mut grants = Vec::new();
        for i in 0..80 {
            let description: String = (0..80).map(|j| format!("sentinel-674-{i}-{j} ")).collect();
            tools.push_str(&format!("  sentinel-674-e{i}:\n    description: {description}\n    executes_workspace: false\n    image: {{ ref: \"{IMAGE}\" }}\n    output_to_model: redacted\n    commands:\n      run: {{ subcommands: [\"go *\"] }}\n"));
            grants.push(format!("Tool(sentinel-674-e{i} run go *)"));
        }
        let grants: Vec<&str> = grants.iter().map(String::as_str).collect();
        let s = snap(&site(&grants, &[]), &tools);
        let got = s.catalog_for(ALICE, PRINCIPAL, &forges(), test_digest);
        assert_eq!(got, Err(CatalogError::TooLarge));
        assert_eq!(
            s.catalog_for(ALICE, PRINCIPAL, &forges(), test_digest),
            Err(CatalogError::TooLarge)
        );
        assert_eq!(
            s.catalog_builds.load(std::sync::atomic::Ordering::Relaxed),
            1
        );
    }

    #[test]
    fn shipped_gh_catalog_fits_the_cap() {
        let grammars = maknae_config::shipped_grammars();
        let every: Vec<String> = grammars.grammars["gh"]
            .shapes
            .keys()
            .map(|n| n.to_string())
            .collect();
        assert_eq!(every.len(), 27);
        let tools = format!(
            "schema_version: 1\ntools:\n  all-gh:\n    executes_workspace: false\n    image: {{ ref: \"{IMAGE}\" }}\n    output_to_model: redacted\n    binds: {{ git: {{ resolver: git }} }}\n    commands:\n      gh: {{ grammar: gh, shapes: [{}] }}\n",
            every.join(", ")
        );
        let catalog_in = ToolsCatalog::parse_with(&tools, &grammars).unwrap();
        assert!(
            catalog_in.disabled().is_empty(),
            "{:?}",
            catalog_in.disabled()
        );
        let src = try_source(
            &site(&["Tool(all-gh gh:*)"], &[]),
            Some(BINDINGS),
            &UIDS,
            AgentsLoad::default(),
        )
        .unwrap()
        .with_tools(catalog_in);
        let s = compiled(&src);
        let c = catalog(&s, ALICE);
        assert!(c.bytes.len() < TOOL_CATALOG_MAX_BYTES, "{}", c.bytes.len());
        assert_eq!(
            cat::shapes(&cat::decode(&c.bytes).unwrap(), "all-gh", "gh").len(),
            27
        );
    }

    #[test]
    fn the_size_bound_is_inclusive() {
        let max = maknae_proto::TOOL_CATALOG_MAX_BYTES;
        assert_eq!(within(vec![0; max], max).map(|b| b.len()), Ok(max));
        assert_eq!(within(vec![0; max + 1], max), Err(CatalogError::TooLarge));
    }
}
