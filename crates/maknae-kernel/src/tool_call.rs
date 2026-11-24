//! The tool-call decision (#674 PR 3a, spec §5.6): one pinned snapshot renders the call,
//! decides `tool.invoke`, mounts the workspace and assembles `tool.launch`.

use std::collections::{BTreeMap, BTreeSet};

use maknae_config::{
    check_open_argv, Bound, CallRefusal, CommandForm, ForgeKind, Rendered, Shape, ShapeClass,
    ToolEntry, ToolWorkspaceAccess, ToolsCatalog,
};
use maknae_proto::{effective_reach, Binding, BindingReach, GitBinding, SideReach};
use maknae_security::{
    combine, decode_git_bound, encode_git_bound, finalize, Action, AttrValue, Attributes, Context,
    Decision, GitBoundValues, Obligation, Request, Resource, Verdict, RESOURCE_BINDING_KINDS,
    RESOURCE_REACH_GIT_BASE, RESOURCE_REACH_GIT_HEAD, RESOURCE_TOOL_ARGV, RESOURCE_TOOL_BINDING,
    RESOURCE_TOOL_CLASS, RESOURCE_TOOL_ENTRY, RESOURCE_TOOL_FILES_SHA256, RESOURCE_TOOL_FORGE_BASE,
    RESOURCE_TOOL_FORGE_HEAD, RESOURCE_TOOL_LABELS, RESOURCE_TOOL_MODE, RESOURCE_TOOL_PROGRAM,
    RESOURCE_TOOL_SHAPE, RESOURCE_TOOL_STDIN_SHA256, TOOL_MODE_OPEN, TOOL_MODE_SHAPE,
};

use crate::handler::{
    discharge_for_tool_call, discharge_plan, lane_context, stamp_conversation, stamp_subject,
    stamp_task_bindings, UnhonorableObligation,
};
use crate::reach::TaskBound;
use crate::task::CitedTask;
use crate::tool_launch::{launch_obligation, ops, sha256_hex, LaunchCall, LaunchRefusal, PerCall};
use crate::workspace::{
    Citation, DecidesPinned, MountDecision, MountMode, PinnedPolicy, SubjectFacts, MASK, PATTERNS,
};

const ACTION_TOOL_INVOKE: &str = "tool.invoke";

#[cfg_attr(
    not(test),
    expect(dead_code, reason = "called by the tool-invocation verb, #479")
)]
pub(crate) struct ToolCallRequest {
    pub(crate) entry: String,
    pub(crate) program: String,
    pub(crate) binding: Option<usize>,
    pub(crate) call: CallInput,
}

#[cfg_attr(
    not(test),
    expect(dead_code, reason = "called by the tool-invocation verb, #479")
)]
pub(crate) enum CallInput {
    Shape {
        shape: String,
        slots: BTreeMap<String, String>,
    },
    Open {
        argv: Vec<String>,
    },
}

/// `audit` reaches the trail only; `wire` is what the client is answered.
#[cfg_attr(
    not(test),
    expect(dead_code, reason = "called by the tool-invocation verb, #479")
)]
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum ToolCallDecision {
    Refused {
        audit: String,
        wire: String,
        cited: Citation,
    },
    Permitted {
        obligations: Vec<Obligation>,
    },
}

const NOT_AUTHORIZED: &str = "not authorized";
const UNEVALUATED: &str = "tool: the decision could not be evaluated";

fn malformed(why: &str) -> ToolCallDecision {
    let reason = format!("tool: malformed request: {why}");
    ToolCallDecision::Refused {
        wire: reason.clone(),
        audit: reason,
        cited: Citation::default(),
    }
}

fn denied(reason: impl Into<String>, cited: Citation) -> ToolCallDecision {
    ToolCallDecision::Refused {
        audit: reason.into(),
        wire: NOT_AUTHORIZED.into(),
        cited,
    }
}

fn call_refusal(refusal: &CallRefusal) -> ToolCallDecision {
    malformed(&match refusal {
        CallRefusal::MissingSlot(slot) => format!("slot {slot}: missing"),
        CallRefusal::UnexpectedSlot => "a slot the shape does not declare".to_string(),
        CallRefusal::Invariant { slot, rule } => format!("slot {slot}: {rule}"),
        CallRefusal::Constraint { slot } => format!("slot {slot}: constraint"),
        CallRefusal::UnresolvedBound(key) => format!("bound {key}: unresolved"),
        CallRefusal::BadBound(key) => format!("bound {key}: refused"),
        CallRefusal::OpenToken { index, rule } => format!("argv token {index}: {rule}"),
        CallRefusal::OpenTooMany => "argv: too many tokens".to_string(),
    })
}

fn assemble_launch(
    entry: &ToolEntry,
    program: &str,
    call: &LaunchCall,
    per_call: &PerCall,
    cited: &Citation,
) -> Result<Obligation, ToolCallDecision> {
    launch_obligation(entry, program, call, per_call).map_err(|refusal| {
        let why = match refusal {
            LaunchRefusal::NoProgram => "the program is not in the entry",
            LaunchRefusal::FormMismatch => "the command's form does not take the call",
            LaunchRefusal::UnknownShape => "the shape is not in the command",
            LaunchRefusal::NoImage => "the entry has no image",
        };
        denied(
            format!("tool: the call cannot be launched: {why}"),
            cited.clone(),
        )
    })
}

struct Selected<'a> {
    index: i64,
    git: &'a GitBinding,
    reach: Option<&'a BindingReach>,
}

fn select<'a>(
    bound: &TaskBound<'a>,
    index: Option<usize>,
) -> Result<Option<Selected<'a>>, ToolCallDecision> {
    let count = bound.bindings.len();
    let index = match (index, count) {
        (Some(i), _) if i < count => i,
        (Some(i), _) => return Err(malformed(&format!("binding {i}: out of range"))),
        (None, 0) => return Ok(None),
        (None, 1) => 0,
        (None, _) => {
            return Err(malformed(&format!(
                "the task has {count} bindings; the call must select one"
            )))
        }
    };
    let Binding::Git(git) = bound.bindings[index];
    Ok(Some(Selected {
        index: i64::try_from(index).map_err(|_| malformed("binding index"))?,
        git,
        reach: bound.reach.get(index).copied(),
    }))
}

fn stamp_reach(resource: &mut Attributes, reach: Option<&BindingReach>) {
    let side = reach.map_or(SideReach::EMPTY, effective_reach);
    resource.insert(RESOURCE_REACH_GIT_BASE, ops(side.base()));
    resource.insert(RESOURCE_REACH_GIT_HEAD, ops(side.head()));
}

/// Stamps the selected binding alone and returns the bound values the PDP decodes from it.
fn stamp_selected(
    resource: &mut Attributes,
    selected: Option<&Selected<'_>>,
) -> Result<Bound, ToolCallDecision> {
    let mut kinds = BTreeSet::new();
    let mut bound = Bound::empty();
    if let Some(s) = selected {
        kinds.insert(ForgeKind::Git.as_str().to_owned());
        let values = GitBoundValues {
            server: s.git.server.clone(),
            base: s.git.base.clone(),
            head: s.git.head.clone(),
            change: s.git.change,
        };
        for (key, list) in encode_git_bound(std::slice::from_ref(&values)) {
            resource.insert(key, list);
        }
        resource.insert(RESOURCE_TOOL_BINDING, AttrValue::Int(s.index));
        stamp_reach(resource, s.reach);
        let decoded = decode_git_bound(resource).map_err(|_| malformed("binding values"))?;
        for (key, value) in decoded.iter().flatten() {
            bound.insert(key, value);
        }
    }
    resource.insert(RESOURCE_BINDING_KINDS, AttrValue::Set(kinds));
    Ok(bound)
}

fn stamp_shape(resource: &mut Attributes, name: &str, shape: &Shape, rendered: &Rendered) {
    resource.insert(RESOURCE_TOOL_MODE, AttrValue::Str(TOOL_MODE_SHAPE.into()));
    resource.insert(RESOURCE_TOOL_SHAPE, AttrValue::Str(name.into()));
    let class = match shape.class {
        ShapeClass::Read => "read",
        ShapeClass::Write => "write",
    };
    resource.insert(RESOURCE_TOOL_CLASS, AttrValue::Str(class.into()));
    resource.insert(RESOURCE_TOOL_ARGV, AttrValue::List(rendered.argv.clone()));
    if let Some(stdin) = &rendered.stdin {
        resource.insert(
            RESOURCE_TOOL_STDIN_SHA256,
            AttrValue::Str(sha256_hex(stdin)),
        );
    }
    if !rendered.files.is_empty() {
        resource.insert(
            RESOURCE_TOOL_FILES_SHA256,
            AttrValue::List(
                rendered
                    .files
                    .iter()
                    .map(|f| sha256_hex(&f.content))
                    .collect(),
            ),
        );
    }
    resource.insert(RESOURCE_TOOL_FORGE_BASE, ops(shape.forge.base));
    resource.insert(RESOURCE_TOOL_FORGE_HEAD, ops(shape.forge.head));
}

/// Open calls carry every binding, and reach only when the task has exactly one.
fn stamp_open(
    resource: &mut Attributes,
    argv: &[String],
    cited: Option<&CitedTask>,
    bound: &TaskBound<'_>,
) {
    resource.insert(RESOURCE_TOOL_MODE, AttrValue::Str(TOOL_MODE_OPEN.into()));
    resource.insert(RESOURCE_TOOL_ARGV, AttrValue::List(argv.to_vec()));
    resource.insert(RESOURCE_BINDING_KINDS, AttrValue::Set(BTreeSet::new()));
    if let Some(cited) = cited {
        stamp_task_bindings(resource, cited);
    }
    if let [_] = bound.bindings.as_slice() {
        stamp_reach(resource, bound.reach.first().copied());
    }
}

/// Renders or checks the call against the pinned catalog and stamps its resource facts.
fn resolve<'t>(
    tools: &'t ToolsCatalog,
    cited: Option<&CitedTask>,
    req: &ToolCallRequest,
    resource: &mut Attributes,
) -> Result<(&'t ToolEntry, LaunchCall), ToolCallDecision> {
    let (name, program) = (&req.entry, &req.program);
    let entry = tools.entry(name).ok_or_else(|| {
        denied(
            format!("tool: unknown or disabled entry {name}"),
            Citation::default(),
        )
    })?;
    let command = entry.commands.get(program).ok_or_else(|| {
        denied(
            format!("tool: program {program} not in entry {name}"),
            Citation::default(),
        )
    })?;
    let bound = match cited {
        Some(cited) => cited.bound(),
        None => TaskBound {
            bindings: Vec::new(),
            reach: Vec::new(),
        },
    };
    let wrong = |call: &str| {
        denied(
            format!("tool: {name}/{program} does not take {call}"),
            Citation::default(),
        )
    };
    let call = match (&command.form, &req.call) {
        (CommandForm::Grammar { shapes, .. }, CallInput::Shape { shape, slots }) => {
            let template = shapes.get(shape).ok_or_else(|| {
                denied(
                    format!("tool: shape {shape} is not enabled for {name}/{program}"),
                    Citation::default(),
                )
            })?;
            let selected = select(&bound, req.binding)?;
            let values = stamp_selected(resource, selected.as_ref())?;
            let rendered = template
                .render(slots, &values)
                .map_err(|r| call_refusal(&r))?;
            stamp_shape(resource, shape, template, &rendered);
            LaunchCall::Shape {
                shape: shape.clone(),
                rendered,
            }
        }
        (CommandForm::Open, CallInput::Open { argv }) => {
            if req.binding.is_some() {
                return Err(malformed("an open call selects no binding"));
            }
            check_open_argv(argv).map_err(|r| call_refusal(&r))?;
            stamp_open(resource, argv, cited, &bound);
            LaunchCall::Open { argv: argv.clone() }
        }
        (CommandForm::Grammar { .. } | CommandForm::Positional(_), CallInput::Open { .. }) => {
            return Err(wrong("an open call"))
        }
        (CommandForm::Open | CommandForm::Positional(_), CallInput::Shape { .. }) => {
            return Err(wrong("a shape call"))
        }
    };
    Ok((entry, call))
}

fn decide_pinned(
    pinned: &dyn PinnedPolicy,
    subject: &SubjectFacts<'_>,
    cited: Option<&CitedTask>,
    req: &ToolCallRequest,
    workspace_root: &str,
) -> Result<Vec<Obligation>, ToolCallDecision> {
    let mut resource = Attributes::new();
    stamp_conversation(&mut resource, subject.conversation);
    resource.insert(RESOURCE_TOOL_ENTRY, AttrValue::Str(req.entry.clone()));
    resource.insert(RESOURCE_TOOL_PROGRAM, AttrValue::Str(req.program.clone()));
    resource.insert(RESOURCE_TOOL_LABELS, AttrValue::Set(BTreeSet::new()));
    let (entry, call) = resolve(pinned.tools(), cited, req, &mut resource)?;
    let request = Request {
        subject: stamp_subject(subject.uid, subject.home, subject.stamp),
        resource: Resource(resource),
        action: Action(ACTION_TOOL_INVOKE.into()),
        context: Context(lane_context(subject.lane)),
    };
    let decided = pinned.decide(&request);
    let cited_rule = Citation {
        role: decided.role,
        rule: decided.rule,
    };
    let permit = match decided.verdict {
        Verdict::Indeterminate => return Err(denied(UNEVALUATED, cited_rule)),
        v => match finalize(combine(vec![v])) {
            Decision::Permit { obligations } => obligations,
            Decision::Deny { reason } => return Err(denied(reason, cited_rule)),
        },
    };
    discharge_plan(&permit).map_err(|UnhonorableObligation(id)| {
        denied(
            format!("tool: an obligation the call cannot honor: {id}"),
            cited_rule.clone(),
        )
    })?;
    let mode = match entry.workspace {
        ToolWorkspaceAccess::Rw => Some(MountMode::ReadWrite),
        ToolWorkspaceAccess::Ro => Some(MountMode::ReadOnly),
        ToolWorkspaceAccess::None => None,
    };
    let mask = match mode.map(|mode| pinned.mount(subject, workspace_root, mode)) {
        None => None,
        Some(MountDecision::Refused { audit, wire, cited }) => {
            return Err(ToolCallDecision::Refused { audit, wire, cited })
        }
        Some(MountDecision::Permitted { masks, .. }) => {
            let mut params = Attributes::new();
            params.insert(PATTERNS, AttrValue::List(masks));
            Some(Obligation {
                id: MASK.into(),
                params,
            })
        }
    };
    let per_call = PerCall {
        workspace_root: workspace_root.to_owned(),
        task: cited.map(|c| c.signed.task.task_id.to_string()),
        subject_uid: subject.uid,
    };
    let launch = assemble_launch(entry, &req.program, &call, &per_call, &cited_rule)?;
    let all: Vec<Obligation> = permit.into_iter().chain(mask).chain([launch]).collect();
    let discharged = discharge_for_tool_call(&all).map_err(|UnhonorableObligation(id)| {
        denied(
            format!("tool: an obligation the call cannot honor: {id}"),
            cited_rule,
        )
    })?;
    Ok(discharged.forward)
}

/// Lookup, rendering, the `tool.invoke` decision, the mount and `tool.launch`, all on one
/// pinned snapshot; a slot or argv refusal never reaches the PDP.
#[cfg_attr(
    not(test),
    expect(dead_code, reason = "called by the tool-invocation verb, #479")
)]
pub(crate) fn decide_tool_call<P: DecidesPinned>(
    authorizer: &P,
    subject: &SubjectFacts<'_>,
    cited: Option<&CitedTask>,
    req: ToolCallRequest,
    workspace_root: &str,
) -> ToolCallDecision {
    authorizer.with_pinned(|pinned| {
        match decide_pinned(pinned, subject, cited, &req, workspace_root) {
            Ok(obligations) => ToolCallDecision::Permitted { obligations },
            Err(refused) => refused,
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::composition::Composition;
    use crate::handler::Stamp;
    use crate::test_fixtures::{
        cited_task, fixture, link_grammar, write_0640, write_grammar, write_sensitive,
        write_tools_dropin, DirGuard, VENDOR_DIR,
    };
    use crate::workspace::{MountDecision, MountMode, PinnedPolicy};
    use maknae_authz_basic::snapshot::Snapshot;
    use maknae_authz_basic::HermeticAuthorizer;
    use maknae_proto::{
        AgentReach, Binding, BindingReach, ForgeOp, GitBinding, GitReach, SideReach, TaskerBasis,
    };
    use maknae_security::{AttrValue, Decided, Lane, Request, Verdict};
    use std::path::Path;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::{Arc, Mutex};

    const HOME: &str = "/home/alice";
    const ROOT: &str = "/srv/work/x";
    const IMAGE: &str = "registry.example/x@sha256:0000000000000000000000000000000000000000000000000000000000000000";

    const GRAMMAR: &str = r#"schema_version: 1
program: gh
tested: { version: "2.105.0", date: 2026-11-24 }
shapes:
  issue.list:
    description: List issues.
    class: read
    forge: { base: [read] }
    argv: [issue, list, -R, "{git.base}", "--state={state}"]
    slots:
      state: { at: option, enum: [open, closed, all], description: Which issues. }
  pr.comment:
    description: Comment on the pull request.
    class: write
    forge: { base: [review] }
    argv: [pr, comment, "{git.change}", -R, "{git.base}", --body-file, "-"]
    slots:
      body: { at: stdin, description: The comment. }
  issue.note:
    description: Comment on an issue from a file.
    class: write
    forge: { base: [issue-write], head: [read] }
    argv: [issue, comment, "{number}", -R, "{git.base}", --body-file, "{body}"]
    slots:
      number: { at: token, pattern: "[1-9][0-9]{0,9}", description: The issue. }
      body: { at: file, description: The comment. }
"#;

    fn tools() -> String {
        let entry = |name: &str, extra: &str, command: &str| {
            format!("  {name}:\n    executes_workspace: false\n    image: {{ ref: \"{IMAGE}\" }}\n    output_to_model: redacted\n{extra}    commands:\n      {command}\n")
        };
        [
            "schema_version: 1\ntools:\n".to_string(),
            entry(
                "gh",
                "    workspace: ro\n    binds: { git: { resolver: git } }\n",
                "gh: { grammar: gh, shapes: [issue.list, pr.comment, issue.note] }",
            ),
            entry("build", "    workspace: rw\n", "cargo: { open: true }"),
            entry("lint", "", "cargo: { open: true }"),
            entry("pos", "", "cargo: { subcommands: [\"build *\"] }"),
        ]
        .concat()
    }

    fn policy(deny: &[&str]) -> String {
        let deny: Vec<String> = deny.iter().map(|d| format!("\"{d}\"")).collect();
        format!(
            "schema_version: 1\npermissions:\n  allow: [\"Read(/**)\", \"Write(/**)\", \"Tool(gh gh:*)\", \"Tool(build cargo build *)\", \"Tool(lint cargo build *)\", \"Tool(pos cargo build *)\"]\n  deny: [{}]\n",
            deny.join(", ")
        )
    }

    fn catalog() -> maknae_config::ToolsCatalog {
        let mut grammars = maknae_config::GrammarSet::empty();
        grammars.grammars.insert(
            "gh".into(),
            maknae_config::Grammar::parse("gh", GRAMMAR).unwrap(),
        );
        maknae_config::ToolsCatalog::parse_with(&tools(), &grammars).unwrap()
    }

    const NO_SENSITIVE: &str = "schema_version: 1\nsensitive: []\n";

    fn pdp(deny: &[&str], sensitive: &str) -> (DirGuard, Composition<HermeticAuthorizer>) {
        use maknae_authz_basic::Baseline;
        use std::os::unix::fs::PermissionsExt;
        static NEXT: AtomicUsize = AtomicUsize::new(0);
        let tag = format!("tool-call-{}", NEXT.fetch_add(1, Ordering::Relaxed));
        let (g, basic) = fixture(&tag, &policy(deny), None);
        write_sensitive(&g.0, sensitive);
        let vendor = g.0.join(VENDOR_DIR);
        std::fs::create_dir(&vendor).unwrap();
        std::fs::set_permissions(&vendor, std::fs::Permissions::from_mode(0o755)).unwrap();
        write_0640(&vendor.join("gh.yaml"), GRAMMAR);
        std::fs::set_permissions(
            vendor.join("gh.yaml"),
            std::fs::Permissions::from_mode(0o644),
        )
        .unwrap();
        link_grammar(&g.0, &vendor, "gh.yaml");
        write_tools_dropin(&g.0, "site.yaml", &tools());
        basic.install(basic.compile_granting_tool_invoke(&["admin"]).unwrap());
        (g, Composition::with_us_baseline_ceiling(basic))
    }

    fn operator() -> u32 {
        nix::unistd::geteuid().as_raw()
    }

    fn decide<P: DecidesPinned>(
        a: &P,
        cited: Option<&CitedTask>,
        req: ToolCallRequest,
        root: &str,
    ) -> ToolCallDecision {
        let subject = SubjectFacts {
            lane: Lane::Local,
            uid: operator(),
            home: Some(Path::new(HOME)),
            conversation: None,
            personal: None,
            stamp: &Stamp::Client,
        };
        decide_tool_call(a, &subject, cited, req, root)
    }

    fn shape(name: &str, slots: &[(&str, &str)], binding: Option<usize>) -> ToolCallRequest {
        ToolCallRequest {
            entry: "gh".into(),
            program: "gh".into(),
            binding,
            call: CallInput::Shape {
                shape: name.into(),
                slots: slots
                    .iter()
                    .map(|(k, v)| (k.to_string(), v.to_string()))
                    .collect(),
            },
        }
    }

    fn open(entry: &str, argv: &[&str]) -> ToolCallRequest {
        ToolCallRequest {
            entry: entry.into(),
            program: "cargo".into(),
            binding: None,
            call: CallInput::Open {
                argv: argv.iter().map(|a| a.to_string()).collect(),
            },
        }
    }

    fn git(base: &str, change: Option<u64>) -> Binding {
        Binding::Git(GitBinding {
            server: "github.com".into(),
            base: base.into(),
            head: None,
            change,
        })
    }

    fn observed(base: &[ForgeOp], head: &[ForgeOp]) -> BindingReach {
        let side = SideReach::new(
            base.iter().copied().collect(),
            head.iter().copied().collect(),
        )
        .unwrap();
        BindingReach::Git(GitReach {
            tasker: side,
            basis: TaskerBasis::Token,
            agent: AgentReach::Observed(side),
            why: None,
        })
    }

    fn with_reach(mut cited: CitedTask, reach: Vec<BindingReach>) -> CitedTask {
        let mut signed = (*cited.signed).clone();
        signed.task.reach = reach;
        cited.signed = Arc::new(signed);
        cited
    }

    fn obligations(d: ToolCallDecision) -> Vec<Obligation> {
        match d {
            ToolCallDecision::Permitted { obligations } => obligations,
            ToolCallDecision::Refused { audit, .. } => panic!("refused: {audit}"),
        }
    }

    fn ids(obs: &[Obligation]) -> Vec<&str> {
        obs.iter().map(|o| o.id.as_str()).collect()
    }

    fn launch(obs: &[Obligation]) -> &maknae_security::Attributes {
        &obs.iter().find(|o| o.id == "tool.launch").unwrap().params
    }

    fn list(items: &[&str]) -> AttrValue {
        AttrValue::List(items.iter().map(|s| s.to_string()).collect())
    }

    fn set(items: &[&str]) -> AttrValue {
        AttrValue::Set(items.iter().map(|s| s.to_string()).collect())
    }

    fn mask(patterns: &[&str]) -> Obligation {
        let mut params = maknae_security::Attributes::new();
        params.insert("patterns", list(patterns));
        Obligation {
            id: "workspace.mask".into(),
            params,
        }
    }

    fn malformed(why: &str) -> ToolCallDecision {
        let reason = format!("tool: malformed request: {why}");
        ToolCallDecision::Refused {
            audit: reason.clone(),
            wire: reason,
            cited: Citation::default(),
        }
    }

    fn uncited(d: ToolCallDecision) -> ToolCallDecision {
        match d {
            ToolCallDecision::Refused { audit, wire, .. } => ToolCallDecision::Refused {
                audit,
                wire,
                cited: Citation::default(),
            },
            permitted @ ToolCallDecision::Permitted { .. } => permitted,
        }
    }

    fn denied(audit: &str) -> ToolCallDecision {
        ToolCallDecision::Refused {
            audit: audit.into(),
            wire: "not authorized".into(),
            cited: Citation::default(),
        }
    }

    /// Records what reaches the PDP and the mount, and installs `reload` at the first lookup.
    struct Spy<'a> {
        inner: &'a Composition<HermeticAuthorizer>,
        requests: Mutex<Vec<Request>>,
        mounts: AtomicUsize,
        reload: Mutex<Option<Arc<Snapshot>>>,
    }

    impl<'a> Spy<'a> {
        fn on(inner: &'a Composition<HermeticAuthorizer>) -> Self {
            Spy {
                inner,
                requests: Mutex::default(),
                mounts: AtomicUsize::new(0),
                reload: Mutex::default(),
            }
        }

        fn decided(&self) -> Vec<Request> {
            self.requests.lock().unwrap().clone()
        }
    }

    struct SpyView<'a> {
        spy: &'a Spy<'a>,
        view: &'a dyn PinnedPolicy,
    }

    impl DecidesPinned for Spy<'_> {
        fn decide_all_pinned(
            &self,
            reqs: &[Request],
        ) -> (Vec<Decided>, Arc<maknae_config::SensitiveList>) {
            self.inner.decide_all_pinned(reqs)
        }

        fn with_pinned<R>(&self, f: impl FnOnce(&dyn PinnedPolicy) -> R) -> R {
            self.inner
                .with_pinned(|view| f(&SpyView { spy: self, view }))
        }
    }

    impl PinnedPolicy for SpyView<'_> {
        fn tools(&self) -> &maknae_config::ToolsCatalog {
            use maknae_authz_basic::Baseline;
            if let Some(next) = self.spy.reload.lock().unwrap().take() {
                self.spy.inner.baseline().install(next);
            }
            self.view.tools()
        }

        fn decide(&self, req: &Request) -> Decided {
            self.spy.requests.lock().unwrap().push(req.clone());
            self.view.decide(req)
        }

        fn mount(&self, subject: &SubjectFacts<'_>, root: &str, mode: MountMode) -> MountDecision {
            self.spy.mounts.fetch_add(1, Ordering::SeqCst);
            self.view.mount(subject, root, mode)
        }
    }

    struct Fixed {
        verdict: Verdict,
        tools: maknae_config::ToolsCatalog,
    }

    impl DecidesPinned for Fixed {
        fn decide_all_pinned(
            &self,
            reqs: &[Request],
        ) -> (Vec<Decided>, Arc<maknae_config::SensitiveList>) {
            let decided = Decided {
                verdict: self.verdict.clone(),
                role: Some("sentinel-674-role"),
                rule: None,
            };
            (
                vec![decided; reqs.len()],
                Arc::new(maknae_config::SensitiveList::empty()),
            )
        }

        fn with_pinned<R>(&self, f: impl FnOnce(&dyn PinnedPolicy) -> R) -> R {
            f(&crate::workspace::Unpinned(self, &self.tools))
        }
    }

    fn fixed(verdict: Verdict) -> Fixed {
        Fixed {
            verdict,
            tools: catalog(),
        }
    }

    fn audit_only() -> Obligation {
        Obligation {
            id: "audit".into(),
            params: maknae_security::Attributes::new(),
        }
    }

    #[test]
    fn permitted_shape_call_returns_launch_and_mask() {
        let (_g, c) = pdp(&["Read(/**/.env)"], NO_SENSITIVE);
        let task = cited_task(vec![git("o/r", Some(7))]);
        let obs = obligations(decide(
            &c,
            Some(&task),
            shape("issue.list", &[("state", "open")], None),
            ROOT,
        ));
        assert_eq!(ids(&obs), ["workspace.mask", "tool.launch"]);
        assert_eq!(obs[0], mask(&["/**/.env"]));
        let l = launch(&obs);
        assert_eq!(
            l.get("argv"),
            Some(&list(&["issue", "list", "-R", "o/r", "--state=open"]))
        );
        assert_eq!(l.str("mode"), Some("shape"));
        assert_eq!(l.str("shape"), Some("issue.list"));
        assert_eq!(l.str("entry"), Some("gh"));
        assert_eq!(l.str("workspace.root"), Some(ROOT));
        assert_eq!(l.str("workspace.mode"), Some("ro"));
        assert_eq!(
            l.str("task"),
            Some(task.signed.task.task_id.to_string().as_str())
        );
        assert_eq!(
            l.get("subject.uid"),
            Some(&AttrValue::Int(i64::from(operator())))
        );
    }

    #[test]
    fn permitted_open_call_returns_launch() {
        let (_g, c) = pdp(&[], NO_SENSITIVE);
        let obs = obligations(decide(
            &c,
            None,
            open("build", &["build", "--release"]),
            ROOT,
        ));
        assert_eq!(ids(&obs), ["workspace.mask", "tool.launch"]);
        assert_eq!(obs[0], mask(&[]));
        let l = launch(&obs);
        assert_eq!(l.get("argv"), Some(&list(&["build", "--release"])));
        assert_eq!(l.str("mode"), Some("open"));
        assert_eq!(l.str("workspace.mode"), Some("rw"));
        assert_eq!(l.get("task"), None);
    }

    #[test]
    fn slot_refusal_never_reaches_the_pdp() {
        let (_g, c) = pdp(&[], NO_SENSITIVE);
        let task = cited_task(vec![git("o/r", Some(7))]);
        let cases = [
            (
                shape("issue.list", &[("state", "sentinel-674-value")], None),
                "slot state: constraint",
            ),
            (shape("issue.list", &[], None), "slot state: missing"),
            (
                shape(
                    "issue.list",
                    &[("state", "open"), ("sentinel-674-slot", "x")],
                    None,
                ),
                "a slot the shape does not declare",
            ),
            (
                shape("issue.note", &[("number", "-1"), ("body", "b")], None),
                "slot number: leading_dash",
            ),
            (
                open("build", &["build", "sentinel-674\0value"]),
                "argv token 1: nul",
            ),
            (open("build", &["x"; 65]), "argv: too many tokens"),
        ];
        for (req, why) in cases {
            let spy = Spy::on(&c);
            let got = decide(&spy, Some(&task), req, ROOT);
            assert_eq!(got, malformed(why));
            assert!(spy.decided().is_empty(), "{why}");
            assert_eq!(spy.mounts.load(Ordering::SeqCst), 0, "{why}");
        }
    }

    #[test]
    fn unresolved_bound_without_cited_task_is_refused() {
        let (_g, c) = pdp(&[], NO_SENSITIVE);
        let spy = Spy::on(&c);
        assert_eq!(
            decide(
                &spy,
                None,
                shape("issue.list", &[("state", "open")], None),
                ROOT
            ),
            malformed("bound git.base: unresolved")
        );
        let task = cited_task(vec![git("o/r", None)]);
        assert_eq!(
            decide(
                &spy,
                Some(&task),
                shape("pr.comment", &[("body", "b")], None),
                ROOT
            ),
            malformed("bound git.change: unresolved")
        );
        assert!(spy.decided().is_empty());
    }

    #[test]
    fn bound_values_come_from_the_cited_task_and_addendum() {
        let (_g, c) = pdp(&[], NO_SENSITIVE);
        let mut task = cited_task(vec![git("o/r", Some(7))]);
        let added = maknae_proto::TaskAddendum::new(
            task.signed.task.task_id,
            1,
            vec![git("o/added", Some(9))],
            vec![observed(&[ForgeOp::Read], &[])],
        )
        .unwrap();
        task.addendum = Some(Arc::new(maknae_proto::SignedAddendum {
            addendum: added,
            signature: task.signed.signature.clone(),
        }));
        for (index, change, base) in [(0, "7", "o/r"), (1, "9", "o/added")] {
            let obs = obligations(decide(
                &c,
                Some(&task),
                shape("pr.comment", &[("body", "b")], Some(index)),
                ROOT,
            ));
            assert_eq!(
                launch(&obs).get("argv"),
                Some(&list(&[
                    "pr",
                    "comment",
                    change,
                    "-R",
                    base,
                    "--body-file",
                    "-"
                ]))
            );
        }
    }

    #[test]
    fn refused_mount_refuses_the_call() {
        let (_g, c) = pdp(&["Read(/srv/secret/**)"], NO_SENSITIVE);
        assert_eq!(
            uncited(decide(&c, None, open("build", &["build"]), "/srv/secret/x")),
            denied("denied by policy entry Read(/srv/secret/**)")
        );
    }

    #[test]
    fn entry_without_workspace_skips_the_mount() {
        let (_g, c) = pdp(&[], NO_SENSITIVE);
        let spy = Spy::on(&c);
        let obs = obligations(decide(&spy, None, open("lint", &["build"]), HOME));
        assert_eq!(ids(&obs), ["tool.launch"]);
        assert_eq!(launch(&obs).str("workspace.mode"), Some("none"));
        assert_eq!(spy.mounts.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn host_sensitive_entry_under_the_root_is_masked() {
        let (_g, c) = pdp(
            &[],
            "schema_version: 1\nsensitive:\n  - \"/srv/work/x/sentinel-674/**\"\n  - \"/srv/other/**\"\n",
        );
        let obs = obligations(decide(&c, None, open("build", &["build"]), ROOT));
        assert_eq!(obs[0], mask(&["/srv/work/x/sentinel-674/**"]));
    }

    #[test]
    fn rw_mount_with_different_read_and_write_denies_is_permitted_with_one_mask() {
        let (_g, c) = pdp(&["Read(/**/.env)", "Write(/**/Cargo.lock)"], NO_SENSITIVE);
        let obs = obligations(decide(&c, None, open("build", &["build"]), ROOT));
        assert_eq!(ids(&obs), ["workspace.mask", "tool.launch"]);
        assert_eq!(obs[0], mask(&["/**/.env", "/**/Cargo.lock"]));
    }

    #[test]
    fn structural_root_refuses_the_call() {
        let (_g, c) = pdp(&[], NO_SENSITIVE);
        let home = "workspace: the home or a folder above it";
        assert_eq!(
            decide(&c, None, open("build", &["build"]), HOME),
            ToolCallDecision::Refused {
                audit: home.into(),
                wire: home.into(),
                cited: Citation::default(),
            }
        );
    }

    #[test]
    fn rendering_and_decision_share_one_snapshot() {
        let (g, c) = pdp(&[], NO_SENSITIVE);
        std::fs::remove_file(g.0.join(maknae_config::GRAMMARS_DIR).join("gh.yaml")).unwrap();
        write_grammar(
            &g.0,
            "gh.yaml",
            &GRAMMAR.replace(
                "[issue, list, -R, \"{git.base}\"",
                "[issue, list, --repo, \"{git.base}\"",
            ),
        );
        let next = c
            .baseline()
            .compile_granting_tool_invoke(&["admin"])
            .unwrap();
        let task = cited_task(vec![git("o/r", None)]);
        let call = || shape("issue.list", &[("state", "all")], None);
        let spy = Spy::on(&c);
        *spy.reload.lock().unwrap() = Some(next);
        let pinned = obligations(decide(&spy, Some(&task), call(), ROOT));
        assert!(spy.reload.lock().unwrap().is_none());
        assert_eq!(
            launch(&pinned).get("argv"),
            Some(&list(&["issue", "list", "-R", "o/r", "--state=all"]))
        );
        let after = obligations(decide(&c, Some(&task), call(), ROOT));
        assert_eq!(
            launch(&after).get("argv"),
            Some(&list(&["issue", "list", "--repo", "o/r", "--state=all"]))
        );
    }

    #[test]
    fn single_binding_renders_without_an_index() {
        let (_g, c) = pdp(&[], NO_SENSITIVE);
        let task = cited_task(vec![git("o/only", None)]);
        for binding in [None, Some(0)] {
            let obs = obligations(decide(
                &c,
                Some(&task),
                shape("issue.list", &[("state", "open")], binding),
                ROOT,
            ));
            assert_eq!(
                launch(&obs).get("argv"),
                Some(&list(&["issue", "list", "-R", "o/only", "--state=open"]))
            );
        }
    }

    #[test]
    fn two_bindings_without_an_index_are_refused() {
        let (_g, c) = pdp(&[], NO_SENSITIVE);
        let spy = Spy::on(&c);
        let two = cited_task(vec![git("o/a", None), git("o/b", None)]);
        let one = cited_task(vec![git("o/a", None)]);
        let cases = [
            (
                Some(&two),
                None,
                "the task has 2 bindings; the call must select one",
            ),
            (Some(&two), Some(2), "binding 2: out of range"),
            (Some(&one), Some(1), "binding 1: out of range"),
            (None, Some(0), "binding 0: out of range"),
        ];
        for (task, index, why) in cases {
            assert_eq!(
                decide(
                    &spy,
                    task,
                    shape("issue.list", &[("state", "open")], index),
                    ROOT
                ),
                malformed(why)
            );
        }
        assert!(spy.decided().is_empty());
    }

    #[test]
    fn index_selects_the_binding() {
        let (_g, c) = pdp(&[], NO_SENSITIVE);
        let task = cited_task(vec![git("o/a", None), git("o/b", None)]);
        for (index, base) in [(0, "o/a"), (1, "o/b")] {
            let obs = obligations(decide(
                &c,
                Some(&task),
                shape("issue.list", &[("state", "open")], Some(index)),
                ROOT,
            ));
            assert_eq!(
                launch(&obs).get("argv"),
                Some(&list(&["issue", "list", "-R", base, "--state=open"]))
            );
        }
    }

    #[test]
    fn shape_call_stamps_only_the_selected_binding_and_its_reach() {
        let (_g, c) = pdp(&[], NO_SENSITIVE);
        let task = with_reach(
            cited_task(vec![git("o/a", Some(3)), git("o/b", Some(4))]),
            vec![
                observed(&[ForgeOp::Merge], &[ForgeOp::PushHead]),
                observed(&[ForgeOp::Read, ForgeOp::Review], &[ForgeOp::Read]),
            ],
        );
        let spy = Spy::on(&c);
        obligations(decide(
            &spy,
            Some(&task),
            shape("issue.list", &[("state", "open")], Some(1)),
            ROOT,
        ));
        let [req] = spy.decided().try_into().unwrap();
        let r = &req.resource.0;
        assert_eq!(req.action.0, "tool.invoke");
        assert_eq!(r.get("binding.kinds"), Some(&set(&["git"])));
        assert_eq!(r.get("bound.git.server"), Some(&list(&["github.com"])));
        assert_eq!(r.get("bound.git.base"), Some(&list(&["o/b"])));
        assert_eq!(r.get("bound.git.head"), Some(&list(&[""])));
        assert_eq!(r.get("bound.git.change"), Some(&list(&["4"])));
        assert_eq!(r.get("tool.binding"), Some(&AttrValue::Int(1)));
        assert_eq!(r.get("reach.git.base"), Some(&set(&["read", "review"])));
        assert_eq!(r.get("reach.git.head"), Some(&set(&["read"])));
        assert_eq!(r.str("tool.entry"), Some("gh"));
        assert_eq!(r.str("tool.program"), Some("gh"));
        assert_eq!(r.str("tool.mode"), Some("shape"));
        assert_eq!(r.str("tool.shape"), Some("issue.list"));
        assert_eq!(r.str("tool.class"), Some("read"));
        assert_eq!(
            r.get("tool.argv"),
            Some(&list(&["issue", "list", "-R", "o/b", "--state=open"]))
        );
        assert_eq!(r.get("tool.forge.base"), Some(&set(&["read"])));
        assert_eq!(r.get("tool.forge.head"), Some(&set(&[])));
        assert_eq!(r.get("tool.labels"), Some(&set(&[])));
        assert_eq!(r.get("tool.stdin.sha256"), None);
        assert_eq!(r.get("tool.files.sha256"), None);
        assert_eq!(
            req.subject.0.get("uid"),
            Some(&AttrValue::Int(i64::from(operator())))
        );
        assert_eq!(
            req.context.0.str(maknae_security::CONTEXT_DAC_LANE),
            Some("local")
        );
    }

    fn hex(bytes: &[u8]) -> String {
        crate::run::lower_hex(&maknae_crypto::sha256(bytes))
    }

    #[test]
    fn shape_call_stamps_content_hashes_and_class() {
        let (_g, c) = pdp(&[], NO_SENSITIVE);
        let task = cited_task(vec![git("o/a", Some(3))]);
        let spy = Spy::on(&c);
        obligations(decide(
            &spy,
            Some(&task),
            shape("pr.comment", &[("body", "sentinel-674 body")], None),
            ROOT,
        ));
        obligations(decide(
            &spy,
            Some(&task),
            shape("issue.note", &[("number", "12"), ("body", "note")], None),
            ROOT,
        ));
        let [comment, note] = spy.decided().try_into().unwrap();
        let comment = &comment.resource.0;
        assert_eq!(comment.str("tool.class"), Some("write"));
        assert_eq!(
            comment.str("tool.stdin.sha256"),
            Some(hex(b"sentinel-674 body").as_str())
        );
        assert_eq!(comment.get("tool.files.sha256"), None);
        assert_eq!(comment.get("tool.forge.base"), Some(&set(&["review"])));
        assert_eq!(comment.get("tool.binding"), Some(&AttrValue::Int(0)));
        assert_eq!(comment.get("reach.git.base"), Some(&set(&[])));
        assert_eq!(comment.get("reach.git.head"), Some(&set(&[])));
        let note = &note.resource.0;
        assert_eq!(note.get("tool.stdin.sha256"), None);
        assert_eq!(note.get("tool.files.sha256"), Some(&list(&[&hex(b"note")])));
        assert_eq!(note.get("tool.forge.base"), Some(&set(&["issue-write"])));
        assert_eq!(note.get("tool.forge.head"), Some(&set(&["read"])));
    }

    #[test]
    fn open_call_stamps_every_binding_and_reach_only_for_one() {
        let (_g, c) = pdp(&[], NO_SENSITIVE);
        let one = with_reach(
            cited_task(vec![git("o/a", Some(3))]),
            vec![observed(&[ForgeOp::Read], &[])],
        );
        let two = cited_task(vec![git("o/a", Some(3)), git("o/b", None)]);
        let spy = Spy::on(&c);
        for task in [None, Some(&one), Some(&two)] {
            obligations(decide(&spy, task, open("lint", &["build", "-q"]), ROOT));
        }
        let [none, one, two] = spy.decided().try_into().unwrap();
        for req in [&none, &one, &two] {
            let r = &req.resource.0;
            assert_eq!(r.str("tool.mode"), Some("open"));
            assert_eq!(r.str("tool.entry"), Some("lint"));
            assert_eq!(r.str("tool.program"), Some("cargo"));
            assert_eq!(r.get("tool.argv"), Some(&list(&["build", "-q"])));
            assert_eq!(r.get("tool.labels"), Some(&set(&[])));
            for absent in [
                "tool.shape",
                "tool.class",
                "tool.binding",
                "tool.forge.base",
                "tool.forge.head",
                "tool.stdin.sha256",
                "tool.files.sha256",
            ] {
                assert_eq!(r.get(absent), None, "{absent}");
            }
        }
        let none = &none.resource.0;
        assert_eq!(none.get("binding.kinds"), Some(&set(&[])));
        assert_eq!(none.get("bound.git.base"), None);
        assert_eq!(none.get("reach.git.base"), None);
        let one = &one.resource.0;
        assert_eq!(one.get("binding.kinds"), Some(&set(&["git"])));
        assert_eq!(one.get("bound.git.base"), Some(&list(&["o/a"])));
        assert_eq!(one.get("reach.git.base"), Some(&set(&["read"])));
        assert_eq!(one.get("reach.git.head"), Some(&set(&[])));
        let two = &two.resource.0;
        assert_eq!(two.get("bound.git.base"), Some(&list(&["o/a", "o/b"])));
        assert_eq!(two.get("reach.git.base"), None);
        assert_eq!(two.get("reach.git.head"), None);
    }

    #[test]
    fn an_open_call_selects_no_binding() {
        let (_g, c) = pdp(&[], NO_SENSITIVE);
        let spy = Spy::on(&c);
        let mut req = open("lint", &["build"]);
        req.binding = Some(0);
        let task = cited_task(vec![git("o/a", None)]);
        assert_eq!(
            decide(&spy, Some(&task), req, ROOT),
            malformed("an open call selects no binding")
        );
        assert!(spy.decided().is_empty());
    }

    #[test]
    fn a_call_the_snapshot_cannot_resolve_is_refused_before_the_pdp() {
        let (_g, c) = pdp(&[], NO_SENSITIVE);
        let spy = Spy::on(&c);
        let mut no_program = open("lint", &["build"]);
        no_program.program = "sentinel-674-program".into();
        let cases = [
            (
                open("sentinel-674-entry", &["build"]),
                "tool: unknown or disabled entry sentinel-674-entry",
            ),
            (
                no_program,
                "tool: program sentinel-674-program not in entry lint",
            ),
            (
                shape("sentinel-674-shape", &[], None),
                "tool: shape sentinel-674-shape is not enabled for gh/gh",
            ),
            (
                ToolCallRequest {
                    program: "gh".into(),
                    ..open("gh", &["issue"])
                },
                "tool: gh/gh does not take an open call",
            ),
            (
                ToolCallRequest {
                    entry: "lint".into(),
                    program: "cargo".into(),
                    ..shape("issue.list", &[], None)
                },
                "tool: lint/cargo does not take a shape call",
            ),
            (
                ToolCallRequest {
                    entry: "pos".into(),
                    program: "cargo".into(),
                    ..shape("issue.list", &[], None)
                },
                "tool: pos/cargo does not take a shape call",
            ),
            (
                open("pos", &["build"]),
                "tool: pos/cargo does not take an open call",
            ),
        ];
        for (req, why) in cases {
            assert_eq!(decide(&spy, None, req, ROOT), denied(why));
        }
        assert!(spy.decided().is_empty());
        assert_eq!(spy.mounts.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn a_denied_invoke_refuses_before_the_mount() {
        let (_g, c) = pdp(&[], NO_SENSITIVE);
        let spy = Spy::on(&c);
        let got = uncited(decide(&spy, None, open("build", &["test"]), ROOT));
        assert!(
            matches!(&got, ToolCallDecision::Refused { wire, .. } if wire == "not authorized"),
            "{got:?}"
        );
        assert_eq!(spy.decided().len(), 1);
        assert_eq!(spy.mounts.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn the_permit_carries_only_audit() {
        let launchable = || open("lint", &["build"]);
        assert!(matches!(
            decide(
                &fixed(Verdict::Permit {
                    obligations: vec![audit_only()]
                }),
                None,
                launchable(),
                ROOT
            ),
            ToolCallDecision::Permitted { .. }
        ));
        for foreign in [
            mask(&["/x"]),
            Obligation {
                id: "tool.launch".into(),
                params: maknae_security::Attributes::new(),
            },
        ] {
            let id = foreign.id.clone();
            assert_eq!(
                decide(
                    &fixed(Verdict::Permit {
                        obligations: vec![audit_only(), foreign]
                    }),
                    None,
                    launchable(),
                    ROOT
                ),
                ToolCallDecision::Refused {
                    audit: format!("tool: an obligation the call cannot honor: {id}"),
                    wire: "not authorized".into(),
                    cited: Citation {
                        role: Some("sentinel-674-role"),
                        rule: None
                    },
                }
            );
        }
        assert_eq!(
            decide(&fixed(Verdict::Indeterminate), None, launchable(), ROOT),
            ToolCallDecision::Refused {
                audit: "tool: the decision could not be evaluated".into(),
                wire: "not authorized".into(),
                cited: Citation {
                    role: Some("sentinel-674-role"),
                    rule: None
                },
            }
        );
    }

    #[test]
    fn launch_refusal_refuses_the_call() {
        let catalog = catalog();
        let mut imageless = catalog.entry("lint").unwrap().clone();
        imageless.image = None;
        let per_call = PerCall {
            workspace_root: ROOT.into(),
            task: None,
            subject_uid: operator(),
        };
        let cited = Citation {
            role: Some("sentinel-674-role"),
            rule: None,
        };
        let argv = LaunchCall::Open {
            argv: vec!["build".into()],
        };
        let refused = |why: &str| ToolCallDecision::Refused {
            audit: format!("tool: the call cannot be launched: {why}"),
            wire: "not authorized".into(),
            cited: cited.clone(),
        };
        assert_eq!(
            assemble_launch(&imageless, "cargo", &argv, &per_call, &cited),
            Err(refused("the entry has no image"))
        );
        let gh = catalog.entry("gh").unwrap();
        assert_eq!(
            assemble_launch(gh, "gh", &argv, &per_call, &cited),
            Err(refused("the command's form does not take the call"))
        );
        assert_eq!(
            assemble_launch(gh, "cargo", &argv, &per_call, &cited),
            Err(refused("the program is not in the entry"))
        );
        let unknown = LaunchCall::Shape {
            shape: "sentinel-674-shape".into(),
            rendered: maknae_config::Rendered {
                argv: Vec::new(),
                stdin: None,
                files: Vec::new(),
            },
        };
        assert_eq!(
            assemble_launch(gh, "gh", &unknown, &per_call, &cited),
            Err(refused("the shape is not in the command"))
        );
        assert!(assemble_launch(
            catalog.entry("lint").unwrap(),
            "cargo",
            &argv,
            &per_call,
            &cited
        )
        .is_ok());
    }
}
