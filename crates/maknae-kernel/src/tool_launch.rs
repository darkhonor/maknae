//! The `tool.launch` obligation (#674 PR 3a, spec §5.7): the recipe a front end launches a permitted tool call from.

use crate::run::lower_hex;
use maknae_config::{
    canonical_json, ArgvToken, CommandForm, OutputToModel, Rendered, Shape, ToolCommand, ToolEntry,
    ToolIsolation, ToolNetwork, ToolVolumeAccess, ToolVolumeScope, ToolWorkspaceAccess, Value,
};
use maknae_proto::{ForgeOp, ForgeOps, WireAttr, WireObligation};
use maknae_security::{AttrValue, Attributes, Obligation};

#[cfg_attr(
    not(test),
    expect(dead_code, reason = "called by the tool-invocation verb, #479")
)]
pub(crate) enum LaunchCall {
    Shape { shape: String, rendered: Rendered },
    Open { argv: Vec<String> },
}

#[cfg_attr(
    not(test),
    expect(dead_code, reason = "called by the tool-invocation verb, #479")
)]
pub(crate) struct PerCall {
    pub(crate) workspace_root: String,
    pub(crate) task: Option<String>,
    pub(crate) subject_uid: u32,
}

enum Form<'a> {
    Shape {
        name: &'a str,
        shape: &'a Shape,
        grammar_canonical: &'a str,
        rendered: &'a Rendered,
    },
    Open {
        argv: &'a [String],
    },
}

#[cfg_attr(
    not(test),
    expect(dead_code, reason = "called by the tool-invocation verb, #479")
)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum LaunchRefusal {
    NoProgram,
    FormMismatch,
    UnknownShape,
    NoImage,
}

fn resolve<'a>(
    entry: &'a ToolEntry,
    program: &str,
    call: &'a LaunchCall,
) -> Result<(&'a ToolCommand, Form<'a>), LaunchRefusal> {
    let command = entry
        .commands
        .get(program)
        .ok_or(LaunchRefusal::NoProgram)?;
    let form = match (&command.form, call) {
        (
            CommandForm::Grammar {
                grammar_canonical,
                shapes,
                ..
            },
            LaunchCall::Shape { shape, rendered },
        ) => Form::Shape {
            name: shape,
            shape: shapes.get(shape).ok_or(LaunchRefusal::UnknownShape)?,
            grammar_canonical,
            rendered,
        },
        (CommandForm::Open, LaunchCall::Open { argv }) => Form::Open { argv },
        (CommandForm::Positional(_), LaunchCall::Shape { .. } | LaunchCall::Open { .. })
        | (CommandForm::Grammar { .. }, LaunchCall::Open { .. })
        | (CommandForm::Open, LaunchCall::Shape { .. }) => return Err(LaunchRefusal::FormMismatch),
    };
    Ok((command, form))
}

fn text(v: impl Into<String>) -> AttrValue {
    AttrValue::Str(v.into())
}

fn list<'a>(items: impl Iterator<Item = &'a str>) -> AttrValue {
    AttrValue::List(items.map(str::to_string).collect())
}

fn ops(ops: ForgeOps) -> AttrValue {
    AttrValue::Set(
        ForgeOp::ALL
            .iter()
            .filter(|op| ops.contains(**op))
            .map(|op| op.as_str().to_string())
            .collect(),
    )
}

fn sha256_hex(bytes: &[u8]) -> String {
    lower_hex(&maknae_crypto::sha256(bytes))
}

fn fixed(
    entry: &ToolEntry,
    program: &str,
    command: &ToolCommand,
    form: &Form,
) -> Result<Attributes, LaunchRefusal> {
    let mut p = Attributes::new();
    p.insert("entry", text(&entry.name));
    p.insert("program", text(program));
    match form {
        Form::Shape { name, .. } => {
            p.insert("mode", text("shape"));
            p.insert("shape", text(*name));
        }
        Form::Open { .. } => p.insert("mode", text("open")),
    }
    p.insert(
        "image.ref",
        text(
            &entry
                .image
                .as_ref()
                .ok_or(LaunchRefusal::NoImage)?
                .reference,
        ),
    );
    p.insert(
        "isolation",
        text(match entry.isolation {
            ToolIsolation::Container => "container",
            ToolIsolation::Vm => "vm",
        }),
    );
    let (via, sites) = match &entry.network {
        ToolNetwork::None => ("none", Default::default()),
        ToolNetwork::Proxy { sites } => ("maknae-proxy", sites.iter().cloned().collect()),
    };
    p.insert("network.via", text(via));
    p.insert("network.sites", AttrValue::Set(sites));
    if let Some(class) = &entry.credential {
        p.insert("credential", text(class));
    }
    p.insert(
        "workspace.mode",
        text(match entry.workspace {
            ToolWorkspaceAccess::Rw => "rw",
            ToolWorkspaceAccess::Ro => "ro",
            ToolWorkspaceAccess::None => "none",
        }),
    );
    let resources = entry.resources.as_ref();
    let optional = [
        ("resources.cpus", resources.and_then(|r| r.cpus.as_ref())),
        (
            "resources.memory",
            resources.and_then(|r| r.memory.as_ref()),
        ),
        ("lifetime.max", entry.lifetime_max.as_ref()),
        ("timeout", command.timeout.as_ref()),
        ("output", command.output.as_ref()),
    ];
    for (key, value) in optional {
        if let Some(value) = value {
            p.insert(key, text(value));
        }
    }
    p.insert(
        "output_to_model",
        text(match entry.output_to_model {
            OutputToModel::Redacted => "redacted",
            OutputToModel::StatusOnly => "status_only",
        }),
    );
    let volumes = &entry.volumes;
    p.insert("volumes.name", list(volumes.keys().map(String::as_str)));
    p.insert(
        "volumes.access",
        list(volumes.values().map(|v| match v.access {
            ToolVolumeAccess::Ro => "ro",
            ToolVolumeAccess::Rw => "rw",
        })),
    );
    p.insert(
        "volumes.scope",
        list(volumes.values().map(|v| match v.scope {
            None => "",
            Some(ToolVolumeScope::Task) => "task",
            Some(ToolVolumeScope::Tasker) => "tasker",
        })),
    );
    Ok(p)
}

fn json_value(v: &AttrValue) -> Value {
    let strings = |items: &mut dyn Iterator<Item = &String>| {
        Value::Seq(items.map(|s| Value::Str(s.clone())).collect())
    };
    match v {
        AttrValue::Str(s) => Value::Str(s.clone()),
        AttrValue::Int(n) => Value::Int(*n),
        AttrValue::Bool(b) => Value::Bool(*b),
        AttrValue::Set(items) => strings(&mut items.iter()),
        AttrValue::List(items) => strings(&mut items.iter()),
    }
}

fn template_value(token: &ArgvToken) -> Value {
    let pair = |k: &str, v: String| (k.to_string(), Value::Str(v));
    Value::Map(match token {
        ArgvToken::Literal(text) => vec![pair("literal", text.clone())],
        ArgvToken::Bound { kind, field } => vec![pair("bound", format!("{kind}.{field}"))],
        ArgvToken::Slot(slot) => vec![pair("slot", slot.clone())],
        ArgvToken::OptionSlot { prefix, slot } => {
            vec![pair("option", prefix.clone()), pair("slot", slot.clone())]
        }
    })
}

fn digest(fixed: &Attributes, form: &Form) -> String {
    let mut doc: Vec<(String, Value)> = fixed
        .iter()
        .map(|(k, v)| (k.to_string(), json_value(v)))
        .collect();
    match form {
        Form::Shape { shape, .. } => doc.push((
            "argv.template".to_string(),
            Value::Seq(shape.argv.iter().map(template_value).collect()),
        )),
        Form::Open { .. } => {}
    }
    sha256_hex(canonical_json(&Value::Map(doc)).as_bytes())
}

#[cfg_attr(
    not(test),
    expect(dead_code, reason = "called by the tool-invocation verb, #479")
)]
pub(crate) fn launch_obligation(
    entry: &ToolEntry,
    program: &str,
    call: &LaunchCall,
    per_call: &PerCall,
) -> Result<Obligation, LaunchRefusal> {
    let (command, form) = resolve(entry, program, call)?;
    let mut p = fixed(entry, program, command, &form)?;
    p.insert("shape.sha256", text(digest(&p, &form)));
    match form {
        Form::Shape {
            shape,
            grammar_canonical,
            rendered,
            ..
        } => {
            p.insert(
                "grammar.sha256",
                text(sha256_hex(grammar_canonical.as_bytes())),
            );
            p.insert("argv", AttrValue::List(rendered.argv.clone()));
            if let Some(stdin) = &rendered.stdin {
                p.insert("stdin.sha256", text(sha256_hex(stdin)));
            }
            if !rendered.files.is_empty() {
                p.insert(
                    "files.path",
                    list(rendered.files.iter().map(|f| f.path.as_str())),
                );
                p.insert(
                    "files.sha256",
                    AttrValue::List(
                        rendered
                            .files
                            .iter()
                            .map(|f| sha256_hex(&f.content))
                            .collect(),
                    ),
                );
            }
            p.insert("forge.base", ops(shape.forge.base));
            p.insert("forge.head", ops(shape.forge.head));
        }
        Form::Open { argv } => {
            p.insert("argv", AttrValue::List(argv.to_vec()));
            p.insert("forge.base", ops(ForgeOps::EMPTY));
            p.insert("forge.head", ops(ForgeOps::EMPTY));
        }
    }
    p.insert("workspace.root", text(&per_call.workspace_root));
    if let Some(task) = &per_call.task {
        p.insert("task", text(task));
    }
    p.insert(
        "subject.uid",
        AttrValue::Int(i64::from(per_call.subject_uid)),
    );
    Ok(Obligation {
        id: "tool.launch".to_string(),
        params: p,
    })
}

#[cfg_attr(
    not(test),
    expect(dead_code, reason = "called by the tool-invocation verb, #479")
)]
pub(crate) fn shape_sha256(
    entry: &ToolEntry,
    program: &str,
    call: &LaunchCall,
) -> Result<String, LaunchRefusal> {
    let (command, form) = resolve(entry, program, call)?;
    Ok(digest(&fixed(entry, program, command, &form)?, &form))
}

#[cfg_attr(
    not(test),
    expect(dead_code, reason = "called by the tool-invocation verb, #479")
)]
pub(crate) fn wire_obligation(ob: &Obligation) -> WireObligation {
    WireObligation {
        id: ob.id.clone(),
        params: ob
            .params
            .iter()
            .map(|(k, v)| (k.to_string(), wire_attr(v)))
            .collect(),
    }
}

fn wire_attr(v: &AttrValue) -> WireAttr {
    match v {
        AttrValue::Str(s) => WireAttr::Str(s.clone()),
        AttrValue::Int(n) => WireAttr::Int(*n),
        AttrValue::Bool(b) => WireAttr::Bool(*b),
        AttrValue::Set(items) => WireAttr::Set(items.iter().cloned().collect()),
        AttrValue::List(items) => WireAttr::List(items.clone()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use maknae_config::{Bound, Grammar, GrammarSet, ToolsCatalog};
    use maknae_security::Attributes;
    use std::collections::{BTreeMap, BTreeSet};

    const GRAMMAR: &str = r#"schema_version: 1
program: gh
tested: { version: "2.105.0", date: 2026-11-24 }
shapes:
  pr.comment:
    description: Comment.
    class: write
    forge: { base: [read, review], head: [push-head] }
    argv: [pr, comment, "{git.change}", -R, "{git.base}", --body-file, "-"]
    slots:
      body: { at: stdin, description: b }
  issue.create:
    description: Create.
    class: write
    forge: { base: [issue-write] }
    argv: [issue, create, "--title={title}", --notes, "{notes}", --body-file, "{body}"]
    slots:
      title: { at: option, description: t }
      notes: { at: file, description: n }
      body: { at: file, description: b }
"#;

    const IMAGE: &str =
        "registry.example/gh@sha256:0000000000000000000000000000000000000000000000000000000000000000";
    const OTHER_IMAGE: &str =
        "registry.example/gh@sha256:1111111111111111111111111111111111111111111111111111111111111111";

    fn tools(image: &str) -> String {
        format!(
            r#"schema_version: 1
credential_classes:
  post:
    kind: github-machine-user
tools:
  gh-post:
    image: {{ ref: "{image}" }}
    isolation: vm
    executes_workspace: false
    network: {{ via: maknae-proxy, sites: [github.com, api.github.com] }}
    workspace: ro
    credential: post
    output_to_model: redacted
    resources: {{ cpus: 2, memory: 1Gi }}
    lifetime: {{ max: 10m }}
    volumes: {{ tmp: {{ access: ro }}, cache: {{ access: rw, scope: task }} }}
    binds: {{ git: {{ resolver: git }} }}
    commands:
      gh: {{ grammar: gh, shapes: [pr.comment, issue.create], timeout: 2m, output: 1MiB }}
      git: {{ subcommands: ["fetch *"] }}
  scratch:
    image: {{ ref: "{image}" }}
    executes_workspace: true
    output_to_model: status_only
    commands:
      cargo: {{ open: true }}
"#
        )
    }

    fn grammars(text: &str) -> GrammarSet {
        let mut set = GrammarSet::empty();
        set.grammars
            .insert("gh".to_string(), Grammar::parse("gh", text).unwrap());
        set
    }

    fn catalog_with(image: &str, grammar: &str) -> ToolsCatalog {
        let c = ToolsCatalog::parse_with(&tools(image), &grammars(grammar)).unwrap();
        assert!(c.disabled().is_empty(), "{:?}", c.disabled());
        c
    }

    fn catalog() -> ToolsCatalog {
        catalog_with(IMAGE, GRAMMAR)
    }

    fn bound(change: &str) -> Bound {
        let mut b = Bound::empty();
        b.insert("git.base", "octo/repo");
        b.insert("git.change", change);
        b
    }

    fn slots(pairs: &[(&str, &str)]) -> BTreeMap<String, String> {
        pairs
            .iter()
            .map(|(k, v)| ((*k).to_string(), (*v).to_string()))
            .collect()
    }

    fn shape_call(
        c: &ToolsCatalog,
        shape: &str,
        values: &[(&str, &str)],
        change: &str,
    ) -> LaunchCall {
        let maknae_config::CommandForm::Grammar { shapes, .. } =
            &c.entry("gh-post").unwrap().commands["gh"].form
        else {
            panic!("gh is a grammar command");
        };
        LaunchCall::Shape {
            shape: shape.to_string(),
            rendered: shapes[shape]
                .render(&slots(values), &bound(change))
                .unwrap(),
        }
    }

    fn comment(c: &ToolsCatalog, body: &str, change: &str) -> LaunchCall {
        shape_call(c, "pr.comment", &[("body", body)], change)
    }

    fn per_call(root: &str, task: Option<&str>, uid: u32) -> PerCall {
        PerCall {
            workspace_root: root.to_string(),
            task: task.map(str::to_string),
            subject_uid: uid,
        }
    }

    fn hex(bytes: &[u8]) -> String {
        maknae_crypto::sha256(bytes)
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect()
    }

    fn s(v: &[&str]) -> AttrValue {
        AttrValue::List(v.iter().map(|t| (*t).to_string()).collect())
    }

    fn set(v: &[&str]) -> AttrValue {
        AttrValue::Set(v.iter().map(|t| (*t).to_string()).collect())
    }

    fn str_(v: &str) -> AttrValue {
        AttrValue::Str(v.to_string())
    }

    fn keys(p: &Attributes) -> BTreeSet<&str> {
        p.iter().map(|(k, _)| k).collect()
    }

    #[test]
    fn launch_obligation_carries_every_spec_field() {
        let c = catalog();
        let entry = c.entry("gh-post").unwrap();
        let call = comment(&c, "LGTM", "42");
        let ob = launch_obligation(
            entry,
            "gh",
            &call,
            &per_call("/home/alice/projects/x", Some("t-7"), 1000),
        )
        .unwrap();
        assert_eq!(ob.id, "tool.launch");
        let p = &ob.params;
        let want: [(&str, AttrValue); 27] = [
            (
                "argv",
                s(&["pr", "comment", "42", "-R", "octo/repo", "--body-file", "-"]),
            ),
            ("credential", str_("post")),
            ("entry", str_("gh-post")),
            ("forge.base", set(&["read", "review"])),
            ("forge.head", set(&["push-head"])),
            (
                "grammar.sha256",
                str_(&hex(c_grammar_canonical(&c).as_bytes())),
            ),
            ("image.ref", str_(IMAGE)),
            ("isolation", str_("vm")),
            ("lifetime.max", str_("10m")),
            ("mode", str_("shape")),
            ("network.sites", set(&["api.github.com", "github.com"])),
            ("network.via", str_("maknae-proxy")),
            ("output", str_("1MiB")),
            ("output_to_model", str_("redacted")),
            ("program", str_("gh")),
            ("resources.cpus", str_("2")),
            ("resources.memory", str_("1Gi")),
            ("shape", str_("pr.comment")),
            (
                "shape.sha256",
                str_(&shape_sha256(entry, "gh", &call).unwrap()),
            ),
            ("stdin.sha256", str_(&hex(b"LGTM"))),
            ("subject.uid", AttrValue::Int(1000)),
            ("task", str_("t-7")),
            ("timeout", str_("2m")),
            ("volumes.access", s(&["rw", "ro"])),
            ("volumes.name", s(&["cache", "tmp"])),
            ("volumes.scope", s(&["task", ""])),
            ("workspace.mode", str_("ro")),
        ];
        let mut expected = Attributes::new();
        for (k, v) in want.clone() {
            expected.insert(k, v);
        }
        expected.insert("workspace.root", str_("/home/alice/projects/x"));
        assert_eq!(p, &expected);
        assert_eq!(p.str("shape.sha256").unwrap().len(), 64);
        assert!(p
            .str("shape.sha256")
            .unwrap()
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)));

        let scratch = c.entry("scratch").unwrap();
        let open = LaunchCall::Open {
            argv: vec!["build".into(), "--release".into()],
        };
        let ob = launch_obligation(scratch, "cargo", &open, &per_call("/w", None, 1001)).unwrap();
        assert_eq!(ob.id, "tool.launch");
        let p = &ob.params;
        let mut expected = Attributes::new();
        for (k, v) in [
            ("argv", s(&["build", "--release"])),
            ("entry", str_("scratch")),
            ("forge.base", set(&[])),
            ("forge.head", set(&[])),
            ("image.ref", str_(IMAGE)),
            ("isolation", str_("container")),
            ("mode", str_("open")),
            ("network.sites", set(&[])),
            ("network.via", str_("none")),
            ("output_to_model", str_("status_only")),
            ("program", str_("cargo")),
            (
                "shape.sha256",
                str_(&shape_sha256(scratch, "cargo", &open).unwrap()),
            ),
            ("subject.uid", AttrValue::Int(1001)),
            ("volumes.access", s(&[])),
            ("volumes.name", s(&[])),
            ("volumes.scope", s(&[])),
            ("workspace.mode", str_("none")),
            ("workspace.root", str_("/w")),
        ] {
            expected.insert(k, v);
        }
        assert_eq!(p, &expected, "{:?}", keys(p));
    }

    fn c_grammar_canonical(c: &ToolsCatalog) -> String {
        let maknae_config::CommandForm::Grammar {
            grammar_canonical, ..
        } = &c.entry("gh-post").unwrap().commands["gh"].form
        else {
            panic!("gh is a grammar command");
        };
        grammar_canonical.to_string()
    }

    #[test]
    fn a_call_the_entry_cannot_launch_has_no_obligation() {
        let c = catalog();
        let post = c.entry("gh-post").unwrap();
        let scratch = c.entry("scratch").unwrap();
        let shaped = comment(&c, "b", "1");
        let open = LaunchCall::Open { argv: vec![] };
        let pc = per_call("/w", None, 1);
        let unknown_shape = LaunchCall::Shape {
            shape: "pr.view".into(),
            rendered: match &shaped {
                LaunchCall::Shape { rendered, .. } => rendered.clone(),
                LaunchCall::Open { .. } => unreachable!(),
            },
        };
        let mut imageless = scratch.clone();
        imageless.image = None;
        for (entry, program, call, why) in [
            (post, "gh", &open, LaunchRefusal::FormMismatch),
            (post, "gh", &unknown_shape, LaunchRefusal::UnknownShape),
            (post, "git", &shaped, LaunchRefusal::FormMismatch),
            (post, "git", &open, LaunchRefusal::FormMismatch),
            (post, "absent", &shaped, LaunchRefusal::NoProgram),
            (scratch, "cargo", &shaped, LaunchRefusal::FormMismatch),
            (&imageless, "cargo", &open, LaunchRefusal::NoImage),
        ] {
            assert_eq!(
                launch_obligation(entry, program, call, &pc).map(|o| o.id),
                Err(why),
                "{program}"
            );
            assert_eq!(shape_sha256(entry, program, call), Err(why), "{program}");
        }
    }

    #[test]
    fn shape_digest_is_stable_across_per_call_values() {
        let c = catalog();
        let entry = c.entry("gh-post").unwrap();
        let a = comment(&c, "first body", "1");
        let b = comment(&c, "a different body", "999");
        let digest = shape_sha256(entry, "gh", &a).unwrap();
        assert_eq!(shape_sha256(entry, "gh", &b).unwrap(), digest);
        let one = launch_obligation(entry, "gh", &a, &per_call("/w/a", Some("t-1"), 1000)).unwrap();
        let two = launch_obligation(entry, "gh", &b, &per_call("/w/b", None, 2000)).unwrap();
        assert_eq!(one.params.str("shape.sha256"), Some(digest.as_str()));
        assert_eq!(two.params.str("shape.sha256"), Some(digest.as_str()));
        assert_ne!(one.params, two.params);

        let scratch = c.entry("scratch").unwrap();
        let x = LaunchCall::Open {
            argv: vec!["build".into()],
        };
        let y = LaunchCall::Open {
            argv: vec!["test".into(), "--all".into()],
        };
        assert_eq!(
            shape_sha256(scratch, "cargo", &x),
            shape_sha256(scratch, "cargo", &y)
        );
    }

    #[test]
    fn shape_digest_changes_with_image_template_or_shape() {
        let c = catalog();
        let entry = c.entry("gh-post").unwrap();
        let call = comment(&c, "b", "1");
        let base = shape_sha256(entry, "gh", &call).unwrap();

        let moved = catalog_with(OTHER_IMAGE, GRAMMAR);
        let other = comment(&moved, "b", "1");
        assert_ne!(
            shape_sha256(moved.entry("gh-post").unwrap(), "gh", &other).unwrap(),
            base
        );

        let edited = GRAMMAR.replace("--body-file, \"-\"]", "--body-file, \"-\", --edit-last]");
        let retemplated = catalog_with(IMAGE, &edited);
        let call2 = comment(&retemplated, "b", "1");
        assert_ne!(
            shape_sha256(retemplated.entry("gh-post").unwrap(), "gh", &call2).unwrap(),
            base
        );

        let created = shape_call(
            &c,
            "issue.create",
            &[("title", "t"), ("body", "b"), ("notes", "n")],
            "1",
        );
        let created_digest = shape_sha256(entry, "gh", &created).unwrap();
        assert_ne!(created_digest, base);

        let scratch = c.entry("scratch").unwrap();
        let open = LaunchCall::Open { argv: vec![] };
        let open_digest = shape_sha256(scratch, "cargo", &open).unwrap();
        let mut renamed = scratch.clone();
        renamed.name = "scratch-2".into();
        assert_ne!(shape_sha256(&renamed, "cargo", &open).unwrap(), open_digest);
        let mut reprogrammed = scratch.clone();
        let cmd = reprogrammed.commands.remove("cargo").unwrap();
        reprogrammed.commands.insert("rustc".into(), cmd);
        assert_ne!(
            shape_sha256(&reprogrammed, "rustc", &open).unwrap(),
            open_digest
        );

        let mut each = Vec::new();
        let mut variant = |f: &dyn Fn(&mut ToolEntry)| {
            let mut e = entry.clone();
            f(&mut e);
            each.push(shape_sha256(&e, "gh", &call).unwrap());
        };
        variant(&|e| e.isolation = maknae_config::ToolIsolation::Container);
        variant(&|e| e.network = maknae_config::ToolNetwork::None);
        variant(&|e| {
            e.network = maknae_config::ToolNetwork::Proxy {
                sites: vec!["github.com".into()],
            }
        });
        variant(&|e| e.credential = None);
        variant(&|e| e.workspace = maknae_config::ToolWorkspaceAccess::Rw);
        variant(&|e| e.workspace = maknae_config::ToolWorkspaceAccess::None);
        variant(&|e| e.output_to_model = maknae_config::OutputToModel::StatusOnly);
        variant(&|e| e.resources = None);
        variant(&|e| e.lifetime_max = None);
        variant(&|e| e.volumes.clear());
        variant(&|e| {
            e.volumes.get_mut("tmp").unwrap().access = maknae_config::ToolVolumeAccess::Rw
        });
        variant(&|e| {
            e.volumes.get_mut("tmp").unwrap().scope = Some(maknae_config::ToolVolumeScope::Tasker)
        });
        variant(&|e| e.commands.get_mut("gh").unwrap().timeout = None);
        variant(&|e| e.commands.get_mut("gh").unwrap().output = None);
        let distinct: BTreeSet<&String> = each.iter().collect();
        assert_eq!(distinct.len(), each.len(), "{each:?}");
        assert!(!distinct.contains(&base));
    }

    #[test]
    fn stdin_and_file_hashes_match_content() {
        let c = catalog();
        let entry = c.entry("gh-post").unwrap();
        let call = shape_call(
            &c,
            "issue.create",
            &[
                ("title", "-t"),
                ("body", "the body"),
                ("notes", "some notes"),
            ],
            "1",
        );
        let ob = launch_obligation(entry, "gh", &call, &per_call("/w", None, 1)).unwrap();
        let p = &ob.params;
        assert_eq!(p.get("stdin.sha256"), None);
        assert_eq!(
            p.get("files.path"),
            Some(&s(&["/run/maknae/slots/body", "/run/maknae/slots/notes"]))
        );
        assert_eq!(
            p.get("files.sha256"),
            Some(&s(&[&hex(b"the body"), &hex(b"some notes")]))
        );
        assert_eq!(
            p.get("argv"),
            Some(&s(&[
                "issue",
                "create",
                "--title=-t",
                "--notes",
                "/run/maknae/slots/notes",
                "--body-file",
                "/run/maknae/slots/body",
            ]))
        );
        assert_eq!(p.get("forge.base"), Some(&set(&["issue-write"])));
        assert_eq!(p.get("forge.head"), Some(&set(&[])));

        let ob = launch_obligation(
            entry,
            "gh",
            &comment(&c, "héllo\n", "1"),
            &per_call("/w", None, 1),
        )
        .unwrap();
        assert_eq!(
            ob.params.str("stdin.sha256"),
            Some(hex("héllo\n".as_bytes()).as_str())
        );
        assert_eq!(ob.params.get("files.path"), None);
        assert_eq!(ob.params.get("files.sha256"), None);
    }

    #[test]
    fn the_hash_spelling_is_lowercase_hex_of_sha256() {
        let c = catalog();
        let entry = c.entry("gh-post").unwrap();
        let ob = launch_obligation(
            entry,
            "gh",
            &comment(&c, "abc", "1"),
            &per_call("/w", None, 1),
        )
        .unwrap();
        assert_eq!(
            ob.params.str("stdin.sha256"),
            Some("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad")
        );
    }

    #[test]
    fn wire_obligation_carries_every_param() {
        let mut params = Attributes::new();
        params.insert("a", AttrValue::Str("x".into()));
        params.insert("b", AttrValue::Int(-3));
        params.insert("c", AttrValue::Bool(true));
        params.insert("d", set(&["z", "y"]));
        params.insert("e", s(&["z", "y"]));
        let wire = wire_obligation(&Obligation {
            id: "tool.launch".into(),
            params,
        });
        assert_eq!(wire.id, "tool.launch");
        assert_eq!(
            wire.params,
            BTreeMap::from([
                ("a".to_string(), WireAttr::Str("x".into())),
                ("b".to_string(), WireAttr::Int(-3)),
                ("c".to_string(), WireAttr::Bool(true)),
                ("d".to_string(), WireAttr::Set(vec!["y".into(), "z".into()])),
                (
                    "e".to_string(),
                    WireAttr::List(vec!["z".into(), "y".into()])
                ),
            ])
        );
        assert_eq!(wire_attr(&AttrValue::Bool(false)), WireAttr::Bool(false));
    }

    #[test]
    fn json_value_keeps_each_attr_kind() {
        assert_eq!(json_value(&AttrValue::Int(-3)), Value::Int(-3));
        assert_eq!(json_value(&AttrValue::Bool(true)), Value::Bool(true));
        assert_eq!(json_value(&str_("x")), Value::Str("x".into()));
        let seq = Value::Seq(vec![Value::Str("a".into()), Value::Str("b".into())]);
        assert_eq!(json_value(&set(&["b", "a"])), seq);
        assert_eq!(json_value(&s(&["a", "b"])), seq);
    }
}
