use crate::cli::terminal_safe;
use crate::tools_admin::dirs::{
    dropin_path, lock, open, read_text, required, AnchoredDir, DirError, Dirs, DropinDir,
    WriteError,
};
use crate::tools_admin::inventory::{
    activations, catalog, collision_error, collisions, configured, defined, grammar_set, refusal,
    Def, Link,
};
use crate::tools_admin::{
    entry_ok, program_ok, report, template, Committed, Owners, Paths, Reload,
};
use maknae_config::{Grammar, GRAMMARS_DIR};
use maknae_io::MemberState;
use std::collections::BTreeSet;
use std::io::Write;
use std::path::Path;

const GRANT_HEADER: &str = "Grant these in authz.yaml (roles.<role>.permissions.allow) or an agent's policy.yaml (permissions.allow):";

pub(crate) struct Enable {
    pub program: String,
    pub image: String,
    pub shapes: Option<Vec<String>>,
    pub entry: Option<String>,
    pub reload: bool,
}

fn undone(result: Result<(), DirError>, path: &Path) -> Option<String> {
    match result {
        Ok(()) => None,
        Err(DirError::DoneNotDurable(e)) => Some(format!(
            "removed {}, but the removal is not yet durable: {e}",
            path.display()
        )),
        Err(DirError::NotDone(e)) => Some(format!("cannot remove {}: {e}", path.display())),
    }
}

struct Undo<'a> {
    d: &'a Dirs,
    p: &'a Paths,
    link: &'a Link,
    dir: &'a dyn DropinDir,
    links: &'a dyn DropinDir,
}

impl Undo<'_> {
    fn rollback(&self, created: &[String], linked: bool, cause: String) -> String {
        let mut problems = vec![cause];
        for file in created.iter().rev() {
            problems.extend(undone(self.dir.remove(file), &dropin_path(self.p, file)));
        }
        if linked {
            match self
                .d
                .grammars
                .enabled_member_state(&self.link.name, &self.p.vendor_grammars)
            {
                Ok(MemberState::VendorLink) => {
                    problems.extend(undone(self.links.remove(&self.link.name), &self.link.path));
                }
                Ok(
                    MemberState::Absent
                    | MemberState::LocalFile
                    | MemberState::ForeignLink(_)
                    | MemberState::Other,
                ) => {}
                Err(e) => {
                    problems.push(format!("cannot inspect {}: {e}", self.link.path.display()))
                }
            }
        }
        terminal_safe(&problems.join("; "))
    }
}

pub(crate) fn enable(
    p: &Paths,
    o: &Owners,
    req: &Enable,
    r: &dyn Reload,
    out: &mut dyn Write,
) -> Result<(), String> {
    program_ok(&req.program)?;
    if let Some(entry) = &req.entry {
        entry_ok(entry)?;
    }
    let d = Dirs::open(p, o)?;
    let dir = AnchoredDir {
        anchor: &d.tools,
        owner: o.file,
    };
    let links = AnchoredDir {
        anchor: &d.grammars,
        owner: o.file,
    };
    enable_with(p, o, &d, req, r, out, &dir, &links)
}

#[allow(clippy::too_many_arguments)]
pub(super) fn enable_with(
    p: &Paths,
    o: &Owners,
    d: &Dirs,
    req: &Enable,
    r: &dyn Reload,
    out: &mut dyn Write,
    dir: &dyn DropinDir,
    links: &dyn DropinDir,
) -> Result<(), String> {
    let _lock = lock(&d.tools)?;
    let program = req.program.as_str();
    let name = format!("{program}.yaml");
    let vendor_target = required(o.file.uid, 0o022);
    let vendor = p.vendor_grammars.join(&name);
    let grammar_text = read_text(
        &open(&p.vendor_grammars, o.dir, 0o022)?,
        Path::new(&name),
        vendor_target.clone(),
        &vendor,
    )?
    .ok_or_else(|| terminal_safe(&format!("no vendor grammar {}", vendor.display())))?;
    let template_path = p.vendor_templates.join(&name);
    let template_text = read_text(
        &open(&p.vendor_templates, o.dir, 0o022)?,
        Path::new(&name),
        vendor_target,
        &template_path,
    )?
    .ok_or_else(|| terminal_safe(&format!("no template {}", template_path.display())))?;
    let grammar = Grammar::parse(program, &grammar_text).map_err(|e| {
        terminal_safe(&format!(
            "the vendor grammar {} is not valid: {e}",
            vendor.display()
        ))
    })?;
    let dropins = template::render(
        program,
        &template_text,
        &grammar,
        &req.image,
        req.entry.as_deref(),
        req.shapes.as_deref(),
    )
    .map_err(|e| terminal_safe(&e))?;

    let path = p.config.join(GRAMMARS_DIR).join(&name);
    let before = d
        .grammars
        .enabled_member_state(&name, &p.vendor_grammars)
        .map_err(|e| terminal_safe(&format!("cannot inspect {}: {e}", path.display())))?;
    let link = Link {
        name,
        path,
        vendor,
        before,
    };
    let found = configured(p, o, d)?;
    let hits = collisions(&dropins, &found);
    if !hits.is_empty() {
        return Err(collision_error(&hits, &dropins, &link));
    }
    match &link.before {
        MemberState::Absent | MemberState::VendorLink => {}
        MemberState::LocalFile | MemberState::ForeignLink(_) | MemberState::Other => {
            return Err(terminal_safe(&refusal(&link.path, &link.before)))
        }
    }

    let grammars = grammar_set(p, o, d)?;
    let mut linked_set = grammars.clone();
    linked_set.grammars.insert(program.to_string(), grammar);
    let added: Vec<(String, &str)> = dropins
        .iter()
        .map(|dropin| (format!("{}.yaml", dropin.entry), dropin.text.as_str()))
        .collect();
    let asked: BTreeSet<(Def, String)> = dropins.iter().flat_map(|d| defined(&d.text)).collect();
    activations(
        &catalog(&found, &[], &grammars)?,
        &catalog(&found, &added, &linked_set)?,
        &asked,
        &found,
        "enable",
        "nothing was written",
    )?;

    let undo = Undo {
        d,
        p,
        link: &link,
        dir,
        links,
    };
    let mut done = Vec::new();
    let mut lines = Vec::new();
    let mut created = Vec::new();
    for dropin in &dropins {
        let file = format!("{}.yaml", dropin.entry);
        let path = dropin_path(p, &file);
        let cause = match dir.publish_new(&file, dropin.text.as_bytes()) {
            Ok(true) => None,
            Ok(false) => Some(format!(
                "{} already exists; enable never replaces a drop-in",
                path.display()
            )),
            Err(WriteError::NotDone(e)) => Some(format!("cannot write {}: {e}", path.display())),
            Err(WriteError::DoneNotDurable(e)) => {
                created.push(file.clone());
                Some(format!("wrote {}, but not durably: {e}", path.display()))
            }
        };
        if let Some(cause) = cause {
            return Err(undo.rollback(&created, false, cause));
        }
        created.push(file);
        let wrote = format!("wrote {}", path.display());
        lines.push(wrote.clone());
        done.push(wrote);
        lines.push(GRANT_HEADER.to_string());
        lines.extend(dropin.grants.iter().map(|grant| format!("  {grant}")));
        lines.extend(dropin.apps.iter().map(|(class, app)| {
            format!("credential class {class} expects the App {app} in the Egress Daemon's configuration")
        }));
    }
    let linked = match links.link(&link.name, &p.vendor_grammars) {
        Ok(linked) => linked,
        Err(WriteError::NotDone(e)) => {
            let cause = format!("cannot link {}: {e}", link.path.display());
            return Err(undo.rollback(&created, false, cause));
        }
        Err(WriteError::DoneNotDurable(e)) => {
            let cause = format!("linked {}, but not durably: {e}", link.path.display());
            return Err(undo.rollback(&created, true, cause));
        }
    };
    if linked {
        let line = format!(
            "linked {} to {}",
            link.path.display(),
            link.vendor.display()
        );
        lines.push(line.clone());
        done.push(line);
    }
    let committed = Committed {
        done,
        lines,
        notes: Vec::new(),
    };
    report(committed, req.reload, r, out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::enroll::Platform;
    use crate::policy_sync::RELOAD;

    use crate::tools_admin::requested;
    use crate::tools_admin::test_support::{
        enable_failing, enable_failing_third, enable_run, err, plan, req, set, write, yamls, Fail,
        FakeReload, Fx, Plan, GITHUB_READ_ONLY, GRAMMAR, HOMELAB, NAMES, OTHER, SITE, TEMPLATE,
    };
    use maknae_config::ToolsCatalog;
    use std::os::unix::fs::PermissionsExt;

    #[test]
    fn enable_writes_the_link_and_four_dropins() {
        let fx = Fx::new();
        write(&fx.tools().join(".hidden.yaml"), SITE, 0o640);
        write(&fx.tools().join("notes.txt"), SITE, 0o640);
        let r = FakeReload::ok();
        let (result, out) = fx.enable(&req(None, None), &r);
        result.unwrap();
        assert_eq!(fx.link(), fx.exact());
        let mut want = yamls(&NAMES);
        want.insert(0, ".hidden.yaml".to_string());
        want.push("notes.txt".to_string());
        assert_eq!(fx.dropins(), want);
        for name in NAMES {
            let path = fx.tools().join(format!("{name}.yaml"));
            let meta = std::fs::metadata(&path).unwrap();
            assert_eq!(meta.permissions().mode() & 0o7777, 0o640, "{name}");
            let text = std::fs::read_to_string(&path).unwrap();
            let catalog = ToolsCatalog::parse_with(&text, &set()).unwrap();
            assert!(catalog.disabled().is_empty(), "{name}");
            assert!(catalog.entry(name).is_some(), "{name}");
            assert!(out.contains(&format!("wrote {}", path.display())), "{out}");
        }
        assert!(out.contains("  Tool(github-post gh:pr.comment)\n"), "{out}");
        assert!(
            out.contains("credential class github-post expects the App maknae-github-post in the Egress Daemon's configuration"),
            "{out}"
        );
        assert!(
            out.contains("Grant these in authz.yaml (roles.<role>.permissions.allow) or an agent's policy.yaml (permissions.allow):"),
            "{out}"
        );
        assert!(
            out.contains(&format!(
                "linked {} to {}",
                fx.grammars().join("gh.yaml").display(),
                fx.vendor_grammars().join("gh.yaml").display()
            )),
            "{out}"
        );
        assert!(out.contains(requested(Platform::HOST)), "{out}");
        assert!(!out.contains(RELOAD), "{out}");
        assert_eq!(r.calls.get(), 1);
    }

    #[test]
    fn enable_with_entry_and_shapes_writes_one_narrowed_dropin() {
        let fx = Fx::new();
        let (result, out) = fx.enable(
            &req(Some("github-post"), Some(&["pr.comment"])),
            &FakeReload::ok(),
        );
        result.unwrap();
        assert_eq!(fx.dropins(), ["github-post.yaml"]);
        let text = std::fs::read_to_string(fx.tools().join("github-post.yaml")).unwrap();
        let catalog = ToolsCatalog::parse_with(&text, &set()).unwrap();
        let maknae_config::CommandForm::Grammar { shapes, .. } =
            &catalog.entry("github-post").unwrap().commands["gh"].form
        else {
            panic!("not a grammar command");
        };
        assert_eq!(shapes.keys().collect::<Vec<_>>(), ["pr.comment"]);
        assert!(out.contains("Tool(github-post gh:pr.comment)"), "{out}");
        assert!(!out.contains("pr.review"), "{out}");
    }

    #[test]
    fn enable_is_idempotent_on_the_link_but_refuses_an_existing_dropin() {
        let fx = Fx::new();
        fx.enabled();
        let read_all = || -> Vec<Vec<u8>> {
            NAMES
                .iter()
                .map(|n| std::fs::read(fx.tools().join(format!("{n}.yaml"))).unwrap())
                .collect()
        };
        let before = read_all();
        let r = FakeReload::ok();
        let e = err(fx.enable(&req(Some("github-post"), None), &r).0);
        assert!(e.contains("`github-post`"), "{e}");
        assert!(e.contains("tools.d/github-post.yaml"), "{e}");
        assert!(e.contains("sudo maknae tools disable github-post"), "{e}");
        assert_eq!(fx.link(), fx.exact());
        assert_eq!(fx.dropins(), yamls(&NAMES));
        assert_eq!(before, read_all());
        assert_eq!(r.calls.get(), 0);

        std::fs::remove_file(fx.tools().join("github-post.yaml")).unwrap();
        let (result, out) = fx.enable(&req(Some("github-post"), None), &r);
        result.unwrap();
        assert_eq!(fx.link(), fx.exact());
        assert!(!out.contains("linked"), "{out}");
        assert_eq!(fx.dropins(), yamls(&NAMES));
    }

    #[test]
    fn enable_refuses_a_file_already_at_the_dropin_name() {
        let fx = Fx::new();
        write(&fx.tools().join("github-post.yaml"), OTHER, 0o640);
        let r = FakeReload::ok();
        let e = err(fx.enable(&req(None, None), &r).0);
        assert!(
            e.contains(&fx.tools().join("github-post.yaml").display().to_string()),
            "{e}"
        );
        assert_eq!(fx.link(), None);
        assert_eq!(fx.dropins(), ["github-post.yaml"]);
        assert_eq!(
            std::fs::read_to_string(fx.tools().join("github-post.yaml")).unwrap(),
            OTHER
        );
        assert_eq!(r.calls.get(), 0);
    }

    #[test]
    fn a_publish_that_lands_without_durability_is_rolled_back() {
        let fx = Fx::new();
        let (e, reloads) = enable_failing(&fx, Fail::DoneNotDurable, Fail::Never, &|| {});
        assert!(e.contains("github-issues-read.yaml"), "{e}");
        assert!(e.contains("not durably"), "{e}");
        assert!(fx.dropins().is_empty(), "{:?}", fx.dropins());
        assert_eq!(fx.link(), None);
        assert_eq!(reloads, 0);
    }

    #[test]
    fn a_rollback_removal_without_durability_counts_as_removed() {
        let fx = Fx::new();
        let (e, _) = enable_failing(&fx, Fail::NotDone, Fail::DoneNotDurable, &|| {});
        assert!(e.contains("disk full"), "{e}");
        assert!(e.contains("removal is not yet durable"), "{e}");
        assert!(!e.contains("cannot remove"), "{e}");
        assert!(fx.dropins().is_empty(), "{:?}", fx.dropins());
        assert_eq!(fx.link(), None);
    }

    #[test]
    fn a_rollback_removal_that_fails_is_reported() {
        let fx = Fx::new();
        let (e, _) = enable_failing(&fx, Fail::NotDone, Fail::NotDone, &|| {});
        for name in ["github-read", "github-post"] {
            let path = fx.tools().join(format!("{name}.yaml"));
            assert!(
                e.contains(&format!("cannot remove {}", path.display())),
                "{e}"
            );
        }
        assert_eq!(fx.dropins(), yamls(&["github-read", "github-post"]));
        assert_eq!(fx.link(), None);
    }

    #[test]
    fn enable_refuses_a_name_tools_yaml_defines_even_if_the_loader_disables_it() {
        let fx = Fx::new();
        write(&fx.config().join("tools.yaml"), GITHUB_READ_ONLY, 0o640);
        let r = FakeReload::ok();
        let e = err(fx.enable(&req(None, None), &r).0);
        assert!(
            e.contains("`github-read`") && e.contains("tools.yaml"),
            "{e}"
        );
        assert_eq!(fx.link(), None);
        assert!(fx.dropins().is_empty());
        assert_eq!(r.calls.get(), 0);
    }

    #[test]
    fn enable_rolls_back_on_a_write_failure() {
        let fx = Fx::new();
        let (e, reloads) = enable_failing_third(&fx, &|| {});
        assert!(e.contains("github-issues-read.yaml"), "{e}");
        assert!(e.contains("disk full"), "{e}");
        assert!(fx.dropins().is_empty(), "{:?}", fx.dropins());
        assert_eq!(fx.link(), None);
        assert_eq!(reloads, 0);
    }

    #[test]
    fn rollback_keeps_a_link_that_was_there() {
        let fx = Fx::new();
        fx.link_exactly();
        let (e, _) = enable_failing_third(&fx, &|| {});
        assert!(e.contains("github-issues-read.yaml"), "{e}");
        assert!(fx.dropins().is_empty(), "{:?}", fx.dropins());
        assert_eq!(fx.link(), fx.exact());
    }

    #[test]
    fn rollback_leaves_a_grammar_that_is_no_longer_the_link() {
        let fx = Fx::new();
        let grammar = fx.grammars().join("gh.yaml");
        let swap = || {
            std::fs::remove_file(&grammar).unwrap();
            write(&grammar, GRAMMAR, 0o640);
        };
        let plan = Plan {
            links: Fail::DoneNotDurable,
            after_link: &swap,
            ..plan()
        };
        let (result, _, log) = enable_run(&fx, &req(None, None), &FakeReload::ok(), plan);
        assert!(err(result).contains("not durably"));
        assert!(fx.dropins().is_empty(), "{:?}", fx.dropins());
        assert_eq!(std::fs::read_to_string(&grammar).unwrap(), GRAMMAR);
        assert!(!log.contains(&"remove gh.yaml".to_string()), "{log:?}");
    }

    #[test]
    fn enable_and_disable_refuse_while_locked() {
        let fx = Fx::new();
        fx.enabled();
        std::fs::remove_file(fx.tools().join("github-post.yaml")).unwrap();
        let _held = fx.locked();
        let r = FakeReload::ok();
        let e = err(fx.enable(&req(Some("github-post"), None), &r).0);
        assert!(e.contains("another maknae tools command is running"), "{e}");
        let e = err(fx.disable("github-read", &r).0);
        assert!(e.contains("another maknae tools command is running"), "{e}");
        assert_eq!(
            fx.dropins(),
            yamls(&["github-issues-read", "github-issues-write", "github-read"])
        );
        assert_eq!(fx.link(), fx.exact());
        assert_eq!(r.calls.get(), 0);
    }

    #[test]
    fn enable_refuses_a_name_tools_yaml_defines() {
        let fx = Fx::new();
        write(&fx.config().join("tools.yaml"), HOMELAB, 0o640);
        let r = FakeReload::ok();
        let e = err(fx.enable(&req(None, None), &r).0);
        for name in NAMES {
            assert!(e.contains(&format!("`{name}`")), "{e}");
        }
        assert!(e.contains("tools.yaml"), "{e}");
        assert!(
            e.contains(&format!(
                "to keep tools.yaml's entries, link the grammar instead: sudo ln -s {}/gh.yaml {}/grammars/gh.yaml",
                fx.vendor_grammars().display(),
                fx.config().display()
            )),
            "{e}"
        );
        assert_eq!(fx.link(), None);
        assert!(fx.dropins().is_empty());
        assert_eq!(r.calls.get(), 0);

        fx.link_exactly();
        let e = err(fx.enable(&req(None, None), &r).0);
        assert!(
            e.contains("the grammar is already linked; tools.yaml's entries use it"),
            "{e}"
        );
        assert!(!e.contains("ln -s"), "{e}");
        assert!(fx.dropins().is_empty());

        std::fs::remove_file(fx.grammars().join("gh.yaml")).unwrap();
        write(&fx.grammars().join("gh.yaml"), GRAMMAR, 0o640);
        let e = err(fx.enable(&req(None, None), &r).0);
        assert!(
            e.contains("`github-read`") && e.contains("local file"),
            "{e}"
        );
        assert!(!e.contains("ln -s"), "{e}");
        assert!(fx.dropins().is_empty());
        assert_eq!(r.calls.get(), 0);
    }

    #[test]
    fn enable_refuses_a_name_another_dropin_defines() {
        let fx = Fx::new();
        write(&fx.tools().join("site.yaml"), SITE, 0o640);
        let r = FakeReload::ok();
        let e = err(fx.enable(&req(None, None), &r).0);
        assert!(
            e.contains("`github-post` already defined in tools.d/site.yaml; rename or remove `github-post` in tools.d/site.yaml; the entries that do not collide can be enabled one at a time with --entry: `github-read`, `github-issues-read`, `github-issues-write`; nothing was written"),
            "{e}"
        );
        assert!(!e.contains("disable"), "{e}");
        assert!(!e.contains("ln -s"), "{e}");
        assert_eq!(fx.link(), None);
        assert_eq!(fx.dropins(), ["site.yaml"]);
        assert_eq!(r.calls.get(), 0);

        let tool_only = SITE.replace("site-post:", "github-read:");
        let tool_only = tool_only.replace("  github-post:\n    kind", "  site-class:\n    kind");
        write(&fx.tools().join("site.yaml"), &tool_only, 0o640);
        let e = err(fx.enable(&req(None, None), &r).0);
        assert!(
            e.contains("rename or remove `github-read` in tools.d/site.yaml"),
            "{e}"
        );
        assert!(!e.contains("`github-post` already"), "{e}");
        assert!(
            e.contains("with --entry: `github-post`, `github-issues-read`, `github-issues-write`;"),
            "{e}"
        );
        assert!(!e.contains("disable"), "{e}");
    }

    #[test]
    fn a_failed_publish_never_removes_a_file_another_writer_made() {
        let fx = Fx::new();
        let theirs = fx.tools().join("github-issues-read.yaml");
        let (e, reloads) = enable_failing_third(&fx, &|| write(&theirs, OTHER, 0o640));
        assert!(e.contains("cannot write"), "{e}");
        assert!(!e.contains("wrote"), "{e}");
        assert_eq!(fx.dropins(), ["github-issues-read.yaml"]);
        assert_eq!(std::fs::read_to_string(&theirs).unwrap(), OTHER);
        assert_eq!(fx.link(), None);
        assert_eq!(reloads, 0);
    }

    #[test]
    fn a_failed_publish_never_rolls_back_a_file_that_was_there() {
        let fx = Fx::new();
        write(&fx.tools().join("github-issues-read.yaml"), OTHER, 0o640);
        let (e, _) = enable_failing_third(&fx, &|| {});
        assert!(e.contains("disk full"), "{e}");
        assert_eq!(fx.dropins(), ["github-issues-read.yaml"]);
        assert_eq!(
            std::fs::read_to_string(fx.tools().join("github-issues-read.yaml")).unwrap(),
            OTHER
        );
    }

    #[test]
    fn enable_writes_every_dropin_before_the_link() {
        let fx = Fx::new();
        let r = FakeReload::ok();
        let at_third = || {
            assert_eq!(fx.link(), None);
            assert_eq!(fx.dropins().len(), 2, "{:?}", fx.dropins());
        };
        let plan = Plan {
            before_failing: &at_third,
            ..plan()
        };
        let (result, out, log) = enable_run(&fx, &req(None, None), &r, plan);
        result.unwrap();
        let mut want: Vec<String> = [
            "github-read",
            "github-post",
            "github-issues-read",
            "github-issues-write",
        ]
        .iter()
        .map(|n| format!("publish {n}.yaml"))
        .collect();
        want.push("link gh.yaml".to_string());
        assert_eq!(log, want);
        assert_eq!(fx.link(), fx.exact());
        let linked = out.find("linked").unwrap();
        assert!(out.rfind("wrote").unwrap() < linked, "{out}");
    }

    #[test]
    fn a_link_that_fails_rolls_back_the_dropins_and_keeps_what_it_did_not_make() {
        let fx = Fx::new();
        let r = FakeReload::ok();
        let plan = Plan {
            links: Fail::NotDone,
            ..plan()
        };
        let (result, out, _) = enable_run(&fx, &req(None, None), &r, plan);
        let e = err(result);
        assert!(
            e.starts_with(&format!(
                "cannot link {}: disk full",
                fx.grammars().join("gh.yaml").display()
            )),
            "{e}"
        );
        assert!(fx.dropins().is_empty(), "{:?}", fx.dropins());
        assert_eq!(fx.link(), None);
        assert!(out.is_empty(), "{out}");
        assert_eq!(r.calls.get(), 0);

        fx.link_exactly();
        let (result, _, log) = enable_run(&fx, &req(None, None), &r, plan);
        err(result);
        assert!(fx.dropins().is_empty(), "{:?}", fx.dropins());
        assert_eq!(fx.link(), fx.exact());
        assert!(!log.contains(&"remove gh.yaml".to_string()), "{log:?}");
    }

    #[test]
    fn a_link_that_lands_without_durability_is_rolled_back() {
        let fx = Fx::new();
        let r = FakeReload::ok();
        let plan = Plan {
            links: Fail::DoneNotDurable,
            ..plan()
        };
        let (result, _, _) = enable_run(&fx, &req(None, None), &r, plan);
        let e = err(result);
        assert!(
            e.starts_with(&format!(
                "linked {}, but not durably: sync failed",
                fx.grammars().join("gh.yaml").display()
            )),
            "{e}"
        );
        assert!(fx.dropins().is_empty(), "{:?}", fx.dropins());
        assert_eq!(fx.link(), None);
        assert_eq!(r.calls.get(), 0);
    }

    #[test]
    fn rollback_never_removes_a_link_another_writer_made() {
        let fx = Fx::new();
        let (e, _) = enable_failing_third(&fx, &|| fx.link_exactly());
        assert!(e.contains("disk full"), "{e}");
        assert!(fx.dropins().is_empty(), "{:?}", fx.dropins());
        assert_eq!(fx.link(), fx.exact());
    }

    #[test]
    fn enable_refuses_to_wake_a_site_tool_that_waits_for_the_grammar() {
        let fx = Fx::new();
        write(&fx.tools().join("site.yaml"), SITE, 0o640);
        let r = FakeReload::ok();
        let e = err(fx.enable(&req(Some("github-read"), None), &r).0);
        assert_eq!(
            e,
            "enable would also enable the tool `site-post` defined in tools.d/site.yaml; nothing was written"
        );
        assert_eq!(fx.dropins(), ["site.yaml"]);
        assert_eq!(fx.link(), None);
        assert_eq!(r.calls.get(), 0);

        fx.link_exactly();
        fx.enable(&req(Some("github-read"), None), &r).0.unwrap();
        assert_eq!(fx.dropins(), yamls(&["github-read", "site"]));
    }

    #[test]
    fn enable_offers_disable_only_for_a_file_enable_could_have_written() {
        let fx = Fx::new();
        let r = FakeReload::ok();
        let one = SITE.replace("site-post:", "Site Tools:");
        write(&fx.tools().join("Site Tools.yaml"), &one, 0o640);
        let e = err(fx.enable(&req(None, None), &r).0);
        assert!(
            e.contains("rename or remove `github-post` in tools.d/Site Tools.yaml"),
            "{e}"
        );
        assert!(!e.contains("disable"), "{e}");
        std::fs::remove_file(fx.tools().join("Site Tools.yaml")).unwrap();

        let solo = SITE.replace("site-post:", "solo:");
        write(&fx.tools().join("solo.yaml"), &solo, 0o640);
        let e = err(fx.enable(&req(Some("github-post"), None), &r).0);
        assert!(
            e.contains("rename or remove `github-post` in tools.d/solo.yaml"),
            "{e}"
        );
        assert!(!e.contains("disable"), "{e}");
        assert!(!e.contains("--entry"), "{e}");
        std::fs::remove_file(fx.tools().join("solo.yaml")).unwrap();

        let extra = SITE.replace("site-post:", "github-read:");
        write(&fx.tools().join("github-read.yaml"), &extra, 0o640);
        let e = err(fx.enable(&req(None, None), &r).0);
        assert!(
            e.contains("rename or remove `github-post`, `github-read` in tools.d/github-read.yaml"),
            "{e}"
        );
        assert!(!e.contains("disable"), "{e}");

        let own = extra
            .replace("  github-post:\n    kind", "  github-read:\n    kind")
            .replace("credential: github-post", "credential: github-read");
        write(&fx.tools().join("github-read.yaml"), &own, 0o640);
        let e = err(fx.enable(&req(None, None), &r).0);
        assert!(
            e.contains("to replace tools.d/github-read.yaml, disable it first: sudo maknae tools disable github-read"),
            "{e}"
        );
        assert_eq!(fx.dropins(), ["github-read.yaml"]);
        assert_eq!(r.calls.get(), 0);
    }

    #[test]
    fn enable_refuses_a_local_grammar_file() {
        let fx = Fx::new();
        let grammar = fx.grammars().join("gh.yaml");
        write(&grammar, GRAMMAR, 0o640);
        let e = err(fx.enable(&req(None, None), &FakeReload::ok()).0);
        assert!(e.contains("grammars/gh.yaml"), "{e}");
        assert!(e.contains("local file"), "{e}");
        assert_eq!(std::fs::read_to_string(&grammar).unwrap(), GRAMMAR);
        assert!(fx.dropins().is_empty());
    }

    #[test]
    fn enable_refuses_a_foreign_link() {
        let fx = Fx::new();
        let grammar = fx.grammars().join("gh.yaml");
        std::os::unix::fs::symlink("/elsewhere/gh.yaml", &grammar).unwrap();
        let e = err(fx.enable(&req(None, None), &FakeReload::ok()).0);
        assert!(e.contains("grammars/gh.yaml"), "{e}");
        assert!(e.contains("/elsewhere/gh.yaml"), "{e}");
        assert_eq!(
            std::fs::read_link(&grammar).unwrap(),
            Path::new("/elsewhere/gh.yaml")
        );
        assert!(fx.dropins().is_empty());

        std::fs::remove_file(&grammar).unwrap();
        std::fs::create_dir(&grammar).unwrap();
        let e = err(fx.enable(&req(None, None), &FakeReload::ok()).0);
        assert!(e.contains("grammars/gh.yaml"), "{e}");
        assert!(e.contains("not a file or link"), "{e}");
        assert!(fx.dropins().is_empty());
    }

    #[test]
    fn enable_writes_nothing_for_a_bad_image() {
        let fx = Fx::new();
        let mut bad = req(None, None);
        bad.image = "ghcr.io/x/y:latest".to_string();
        let r = FakeReload::ok();
        let e = err(fx.enable(&bad, &r).0);
        assert!(e.contains("ghcr.io/x/y:latest"), "{e}");
        assert_eq!(fx.link(), None);
        assert!(fx.dropins().is_empty());
        assert_eq!(r.calls.get(), 0);
    }

    #[test]
    fn enable_refuses_an_unknown_program() {
        let fx = Fx::new();
        let mut glab = req(None, None);
        glab.program = "glab".to_string();
        let e = err(fx.enable(&glab, &FakeReload::ok()).0);
        assert!(
            e.contains(&fx.vendor_grammars().join("glab.yaml").display().to_string()),
            "{e}"
        );

        write(&fx.vendor_grammars().join("glab.yaml"), GRAMMAR, 0o644);
        let e = err(fx.enable(&glab, &FakeReload::ok()).0);
        assert!(
            e.contains(
                &fx.vendor_templates()
                    .join("glab.yaml")
                    .display()
                    .to_string()
            ),
            "{e}"
        );

        write(&fx.vendor_templates().join("glab.yaml"), TEMPLATE, 0o644);
        write(&fx.vendor_grammars().join("glab.yaml"), "a: [", 0o644);
        let e = err(fx.enable(&glab, &FakeReload::ok()).0);
        assert!(
            e.contains(&fx.vendor_grammars().join("glab.yaml").display().to_string()),
            "{e}"
        );
        assert!(fx.dropins().is_empty());
        assert!(!fx.grammars().join("glab.yaml").exists());
    }
}
