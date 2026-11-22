//! The per-subject tool catalog (#674, ADR-0039 decision 7): the `tools.yaml` entries a
//! subject's grants reach, as `maknae_graph::catalog` bytes. A hint; no decision reads it.

use crate::binding::Resolution;
use crate::decide::{LoadedPolicy, SubjectEntry};
use crate::role::Role;
use maknae_config::{ArgPattern, ForgeSet, OutputToModel, Pattern, Stage, ToolEntry, ToolsCatalog};
use maknae_graph::catalog::{CatalogEntry, CatalogForge, CatalogInput, CatalogOutput};
use maknae_proto::{CatalogDigest, TOOL_CATALOG_MAX_BYTES};
use std::sync::Arc;

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
    if matches!(
        lp.roles.role_for(uid, principal_uid),
        Resolution::Role(Role::Adversary) | Resolution::NoRole
    ) {
        return Ok(CatalogInput::default());
    }
    let subject = lp.subjects.get(uid);
    let lists = lp.policy.effective_lists(
        subject.and_then(SubjectEntry::agent_right).map(|(_, r)| r),
        subject.and_then(|s| s.permissions.as_ref()),
    );
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

/// A lower bound on the bytes `entry` puts in the graph: each program and pattern key
/// repeats the entry and program names, and each pattern carries its text again.
fn graph_text(entry: &CatalogEntry) -> usize {
    entry
        .programs
        .iter()
        .map(|(program, patterns)| {
            let key = entry.name.len() + 1 + program.len();
            patterns
                .iter()
                .fold(key, |n, text| n.saturating_add(key + 1 + 2 * text.len()))
        })
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
    let programs: Vec<(String, Vec<String>)> = entry
        .commands
        .iter()
        .filter_map(|(program, command)| {
            let kept: Vec<String> = command
                .subcommands
                .iter()
                .filter(|ceiling| {
                    stages
                        .iter()
                        .any(|s| admits(s, &entry.name, program, ceiling))
                })
                .map(ArgPattern::canonical)
                .collect();
            (!kept.is_empty()).then(|| (program.clone(), kept))
        })
        .collect();
    (!programs.is_empty()).then(|| CatalogEntry {
        name: entry.name.clone(),
        description: entry.description.clone(),
        executes_workspace: entry.executes_workspace,
        output: match entry.output_to_model {
            OutputToModel::Redacted => CatalogOutput::Redacted,
            OutputToModel::StatusOnly => CatalogOutput::StatusOnly,
        },
        binds: entry.binds.iter().cloned().collect(),
        programs,
    })
}

fn admits(stage: &Stage<'_>, entry: &str, program: &str, ceiling: &ArgPattern) -> bool {
    stage
        .allow
        .iter()
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
        Pattern::Tool(t) if t.entry == entry && t.program == program => Some(&t.args),
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
            .with_tools(ToolsCatalog::parse(tools).unwrap());
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
                    args: maknae_config::ArgPattern::parse(args).unwrap(),
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

    #[test]
    fn an_agent_drops_a_missing_class_and_keeps_credential_none() {
        let tools = ToolsCatalog::parse(HOMELAB).unwrap();
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
        let s = snap(&site(&["Tool(github-post gh pr review *)"], &[]), HOMELAB);
        let g = graph(&s, ALICE);
        assert_eq!(cat::entries(&g), ["github-post"]);
        assert_eq!(
            sorted(cat::patterns(&g, "github-post", "gh")),
            [
                "pr review {git.change} -R {git.base} --approve --body-file -",
                "pr review {git.change} -R {git.base} --comment --body-file -",
                "pr review {git.change} -R {git.base} --request-changes --body-file -",
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
        let bound = snap(&site(&["Tool(github-read gh pr view *)"], &[]), HOMELAB);
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

    const HOMELAB_GRANTS: [&str; 13] = [
        "Tool(github-read gh pr view *)",
        "Tool(github-read gh pr diff *)",
        "Tool(github-read gh pr checks *)",
        "Tool(github-read git fetch *)",
        "Tool(github-read git checkout *)",
        "Tool(github-post gh pr review *)",
        "Tool(github-post gh pr comment *)",
        "Tool(rust-fetch cargo fetch --locked*)",
        "Tool(rust-build cargo build *)",
        "Tool(rust-build cargo check *)",
        "Tool(rust-build cargo clippy *)",
        "Tool(rust-build cargo test *)",
        "Tool(rust-build cargo fmt --check*)",
    ];

    #[test]
    fn homelab_catalog_structure() {
        let s = snap(&site(&HOMELAB_GRANTS, &[]), HOMELAB);
        let g = graph(&s, ALICE);
        assert_eq!(
            cat::entries(&g),
            ["github-post", "github-read", "rust-build", "rust-fetch"]
        );
        assert_eq!(
            sorted(cat::patterns(&g, "github-post", "gh")),
            [
                "pr comment {git.change} -R {git.base} --body-file -",
                "pr review {git.change} -R {git.base} --approve --body-file -",
                "pr review {git.change} -R {git.base} --comment --body-file -",
                "pr review {git.change} -R {git.base} --request-changes --body-file -",
            ]
        );
        assert_eq!(
            sorted(cat::patterns(&g, "github-read", "gh")),
            ["pr checks *", "pr diff *", "pr view *"]
        );
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
            ["github-post", "github-read"]
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
        let s = snap(&site(&["Tool(github-read gh pr view *)"], &[]), &tools);
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
    fn the_size_bound_is_inclusive() {
        let max = maknae_proto::TOOL_CATALOG_MAX_BYTES;
        assert_eq!(within(vec![0; max], max).map(|b| b.len()), Ok(max));
        assert_eq!(within(vec![0; max + 1], max), Err(CatalogError::TooLarge));
    }
}
