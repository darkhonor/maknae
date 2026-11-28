use crate::cli::terminal_safe;
use crate::tools_admin::dirs::{
    dropin_path, lock, read_text, required, AnchoredDir, DirError, Dirs, DropinDir,
};
use crate::tools_admin::inventory::{activations, catalog, configured, grammar_set, Found};
use crate::tools_admin::{entry_ok, report, Committed, Owners, Paths, Reload};
use maknae_config::{grammar_uses, tool_program_name_ok, GRAMMARS_DIR};
use maknae_io::MemberState;
use std::collections::BTreeSet;
use std::io::Write;
use std::path::Path;

pub(crate) fn disable(
    p: &Paths,
    o: &Owners,
    entry: &str,
    reload: bool,
    r: &dyn Reload,
    out: &mut dyn Write,
) -> Result<(), String> {
    entry_ok(entry)?;
    let d = Dirs::open(p, o)?;
    let dir = AnchoredDir {
        anchor: &d.tools,
        owner: o.file,
    };
    let links = AnchoredDir {
        anchor: &d.grammars,
        owner: o.file,
    };
    disable_with(p, o, &d, entry, reload, r, out, &dir, &links)
}

#[allow(clippy::too_many_arguments)]
pub(super) fn disable_with(
    p: &Paths,
    o: &Owners,
    d: &Dirs,
    entry: &str,
    reload: bool,
    r: &dyn Reload,
    out: &mut dyn Write,
    dir: &dyn DropinDir,
    links: &dyn DropinDir,
) -> Result<(), String> {
    let _lock = lock(&d.tools)?;
    let file = format!("{entry}.yaml");
    let path = dropin_path(p, &file);
    let missing = || terminal_safe(&format!("no drop-in {}", path.display()));
    let identity = |name: &str| {
        dir.identity(name)
            .map_err(|e| terminal_safe(&format!("cannot inspect {}: {e}", path.display())))
    };
    let seen = identity(&file)?.ok_or_else(missing)?;
    let text = read_text(
        &d.tools,
        Path::new(&file),
        required(o.file.uid, 0o027),
        &path,
    )?
    .ok_or_else(missing)?;
    let found = configured(p, o, d)?;
    let others: Vec<Found> = found
        .iter()
        .filter(|f| f.stem.as_deref() != Some(entry))
        .cloned()
        .collect();
    let grammars = grammar_set(p, o, d)?;
    activations(
        &catalog(&found, &[], &grammars)?,
        &catalog(&others, &[], &grammars)?,
        &BTreeSet::new(),
        &others,
        "disable",
        "nothing was removed",
    )?;
    let mut unlink = Vec::new();
    for program in grammar_uses(&text) {
        if !tool_program_name_ok(&program)
            || others
                .iter()
                .any(|f| grammar_uses(&f.text).contains(&program))
        {
            continue;
        }
        let name = format!("{program}.yaml");
        let link = p.config.join(GRAMMARS_DIR).join(&name);
        let state = d
            .grammars
            .enabled_member_state(&name, &p.vendor_grammars)
            .map_err(|e| terminal_safe(&format!("cannot inspect {}: {e}", link.display())))?;
        match state {
            MemberState::VendorLink => unlink.push((name, link)),
            MemberState::Absent
            | MemberState::LocalFile
            | MemberState::ForeignLink(_)
            | MemberState::Other => {}
        }
    }

    let same = identity(&file)? == Some(seen)
        && read_text(
            &d.tools,
            Path::new(&file),
            required(o.file.uid, 0o027),
            &path,
        )?
        .as_deref()
            == Some(text.as_str());
    if !same {
        return Err(terminal_safe(&format!(
            "{} changed while disable ran; nothing was removed",
            path.display()
        )));
    }
    let mut notes = Vec::new();
    let durable = match dir.remove(&file) {
        Ok(()) => true,
        Err(DirError::DoneNotDurable(e)) => {
            notes.push(format!("the removal is not yet durable: {e}"));
            false
        }
        Err(DirError::NotDone(e)) => {
            return Err(terminal_safe(&format!(
                "cannot remove {}: {e}",
                path.display()
            )))
        }
    };
    let mut done = vec![format!("removed {}", path.display())];
    for (name, link) in unlink {
        let rm = format!("sudo rm {}", link.display());
        if !durable {
            notes.push(format!(
                "kept {} until the removal of {} is durable; then remove it: {rm}",
                link.display(),
                path.display()
            ));
            continue;
        }
        match links.remove(&name) {
            Ok(()) => done.push(format!("removed {}", link.display())),
            Err(DirError::DoneNotDurable(e)) => {
                done.push(format!("removed {}", link.display()));
                notes.push(format!("the removal is not yet durable: {e}"));
            }
            Err(DirError::NotDone(e)) => notes.push(format!(
                "cannot remove {}: {e}; the link remains and disable cannot be run again for it: {rm}",
                link.display()
            )),
        }
    }
    let committed = Committed {
        lines: done.clone(),
        done,
        notes,
    };
    report(committed, reload, r, out)
}

#[cfg(test)]
mod tests {
    use crate::enroll::Platform;
    use crate::tools_admin::requested;
    use crate::tools_admin::test_support::{
        disable_failing, disable_run, err, plan, req, rewrite_in_place, write, yamls, Fail,
        FakeReload, Fx, Plan, GRAMMAR, HOMELAB, NAMES, OTHER, SITE,
    };

    #[test]
    fn disable_goes_on_when_the_removal_is_not_durable() {
        let fx = Fx::new();
        fx.enabled_one("github-post");
        let r = FakeReload::ok();
        let (result, out) = disable_failing(&fx, "github-post", Fail::DoneNotDurable, &r);
        let e = err(result);
        let link = fx.grammars().join("gh.yaml");
        let dropin = fx.tools().join("github-post.yaml");
        assert_eq!(
            e,
            format!(
                "removed {}; {}; the removal is not yet durable: sync failed; kept {} until the removal of {} is durable; then remove it: sudo rm {}",
                dropin.display(),
                requested(Platform::HOST),
                link.display(),
                dropin.display(),
                link.display()
            )
        );
        assert_eq!(fx.link(), fx.exact());
        assert!(fx.dropins().is_empty());
        assert_eq!(r.calls.get(), 1);
        assert_eq!(
            out,
            format!(
                "removed {}\n{}\n",
                dropin.display(),
                requested(Platform::HOST)
            )
        );

        std::fs::remove_file(&link).unwrap();
        fx.enabled_one("github-post");
        let r = FakeReload::failing();
        let e = err(disable_failing(&fx, "github-post", Fail::DoneNotDurable, &r).0);
        assert!(e.contains("maknaed was not reloaded"), "{e}");
        assert!(e.contains("the removal is not yet durable"), "{e}");
    }

    #[test]
    fn disable_stops_when_the_removal_fails() {
        let fx = Fx::new();
        fx.enabled_one("github-post");
        let r = FakeReload::ok();
        let (result, out) = disable_failing(&fx, "github-post", Fail::NotDone, &r);
        let e = err(result);
        assert!(e.contains("cannot remove"), "{e}");
        assert!(e.contains("disk full"), "{e}");
        assert_eq!(fx.dropins(), ["github-post.yaml"]);
        assert_eq!(fx.link(), fx.exact());
        assert_eq!(r.calls.get(), 0);
        assert!(out.is_empty(), "{out}");
    }

    #[test]
    fn disable_removes_a_dangling_exact_link() {
        let fx = Fx::new();
        fx.enabled_one("github-post");
        std::fs::remove_file(fx.vendor_grammars().join("gh.yaml")).unwrap();
        let (result, out) = fx.disable("github-post", &FakeReload::ok());
        result.unwrap();
        assert_eq!(fx.link(), None);
        assert!(
            out.contains(&format!(
                "removed {}",
                fx.grammars().join("gh.yaml").display()
            )),
            "{out}"
        );
    }

    #[test]
    fn disable_refuses_a_dropin_replaced_while_it_ran() {
        use std::os::unix::fs::MetadataExt;
        let fx = Fx::new();
        let dropin = fx.tools().join("github-post.yaml");
        let ino = || std::fs::metadata(&dropin).unwrap().ino();
        let replace = || {
            std::fs::remove_file(&dropin).unwrap();
            write(&dropin, OTHER, 0o640);
        };
        let in_place = || {
            let before = ino();
            rewrite_in_place(&dropin, OTHER);
            assert_eq!(ino(), before);
        };
        let swaps: [&dyn Fn(); 2] = [&replace, &in_place];
        for swap in swaps {
            let _ = std::fs::remove_file(&dropin);
            fx.enabled_one("github-post");
            let r = FakeReload::ok();
            let plan = Plan {
                before_recheck: swap,
                ..plan()
            };
            let (result, out) = disable_run(&fx, "github-post", &r, plan);
            assert_eq!(
                err(result),
                format!(
                    "{} changed while disable ran; nothing was removed",
                    dropin.display()
                )
            );
            assert_eq!(std::fs::read_to_string(&dropin).unwrap(), OTHER);
            assert_eq!(fx.link(), fx.exact());
            assert!(out.is_empty(), "{out}");
            assert_eq!(r.calls.get(), 0);
        }
    }

    #[test]
    fn disable_removes_a_dropin_rewritten_with_the_same_bytes() {
        let fx = Fx::new();
        fx.enabled_one("github-post");
        let dropin = fx.tools().join("github-post.yaml");
        let text = std::fs::read_to_string(&dropin).unwrap();
        let same = || rewrite_in_place(&dropin, &text);
        let r = FakeReload::ok();
        let plan = Plan {
            before_recheck: &same,
            ..plan()
        };
        disable_run(&fx, "github-post", &r, plan).0.unwrap();
        assert!(fx.dropins().is_empty());
        assert_eq!(fx.link(), None);
        assert_eq!(r.calls.get(), 1);
    }

    #[test]
    fn disable_refuses_to_wake_a_duplicate() {
        let fx = Fx::new();
        fx.enabled_one("github-read");
        let text = std::fs::read_to_string(fx.tools().join("github-read.yaml")).unwrap();
        write(&fx.tools().join("copy.yaml"), &text, 0o640);
        let r = FakeReload::ok();
        for (entry, other) in [("copy", "github-read"), ("github-read", "copy")] {
            let e = err(fx.disable(entry, &r).0);
            assert_eq!(
                e,
                format!("disable would also enable the credential class `github-read` defined in tools.d/{other}.yaml; disable would also enable the tool `github-read` defined in tools.d/{other}.yaml; nothing was removed")
            );
        }
        assert_eq!(fx.dropins(), yamls(&["copy", "github-read"]));
        assert_eq!(fx.link(), fx.exact());
        assert_eq!(r.calls.get(), 0);

        let classes = text.split("tools:").next().unwrap();
        write(&fx.tools().join("copy.yaml"), classes, 0o640);
        let e = err(fx.disable("copy", &r).0);
        assert!(
            e.contains("the credential class `github-read` defined in tools.d/github-read.yaml"),
            "{e}"
        );
        assert!(e.contains("the tool `github-read`"), "{e}");
        assert_eq!(fx.dropins(), yamls(&["copy", "github-read"]));
    }

    #[test]
    fn disable_is_never_blocked_by_the_vendor_directory() {
        let fx = Fx::new();
        fx.enabled_one("github-post");
        std::fs::remove_dir_all(fx.vendor_grammars()).unwrap();
        let r = FakeReload::ok();
        let (result, out) = fx.disable("github-post", &r);
        result.unwrap();
        assert!(fx.dropins().is_empty());
        assert_eq!(fx.link(), None);
        assert!(
            out.contains(&format!(
                "removed {}",
                fx.tools().join("github-post.yaml").display()
            )),
            "{out}"
        );
        assert_eq!(r.calls.get(), 1);

        let e = err(fx.enable(&req(Some("github-post"), None), &r).0);
        assert!(
            e.starts_with(&format!("cannot use {}: ", fx.vendor_grammars().display())),
            "{e}"
        );
        assert!(fx.dropins().is_empty());
        assert_eq!(fx.link(), None);
        assert_eq!(r.calls.get(), 1);
    }

    #[test]
    fn disable_keeps_the_link_while_a_dropin_uses_it() {
        let fx = Fx::new();
        fx.enabled();
        let r = FakeReload::ok();
        let (result, out) = fx.disable("github-post", &r);
        result.unwrap();
        assert_eq!(fx.link(), fx.exact());
        assert_eq!(
            fx.dropins(),
            yamls(&["github-issues-read", "github-issues-write", "github-read"])
        );
        assert!(
            out.contains(&format!(
                "removed {}",
                fx.tools().join("github-post.yaml").display()
            )),
            "{out}"
        );
        assert!(!out.contains("grammars"), "{out}");
        assert!(out.contains(requested(Platform::HOST)), "{out}");
        assert_eq!(r.calls.get(), 1);
    }

    #[test]
    fn disable_removes_the_link_with_its_last_user() {
        let fx = Fx::new();
        fx.enabled();
        let r = FakeReload::ok();
        for name in NAMES {
            assert_eq!(fx.link(), fx.exact());
            fx.disable(name, &r).0.unwrap();
        }
        assert_eq!(fx.link(), None);
        assert!(fx.dropins().is_empty());
        assert_eq!(r.calls.get(), 4);
    }

    #[test]
    fn disable_keeps_the_link_tools_yaml_uses() {
        let fx = Fx::new();
        fx.enabled_one("github-post");
        write(
            &fx.config().join("tools.yaml"),
            &HOMELAB.replace("github-", "site-"),
            0o640,
        );
        fx.disable("github-post", &FakeReload::ok()).0.unwrap();
        assert_eq!(fx.link(), fx.exact());
        assert!(fx.dropins().is_empty());
    }

    #[test]
    fn disable_keeps_a_local_grammar_file() {
        let fx = Fx::new();
        let grammar = fx.grammars().join("gh.yaml");
        write(&grammar, GRAMMAR, 0o640);
        write(&fx.tools().join("site.yaml"), SITE, 0o640);
        let (result, out) = fx.disable("site", &FakeReload::ok());
        result.unwrap();
        assert_eq!(std::fs::read_to_string(&grammar).unwrap(), GRAMMAR);
        assert!(fx.dropins().is_empty());
        assert!(!out.contains("grammars"), "{out}");
    }

    #[test]
    fn disable_ignores_a_grammar_name_that_is_not_a_program() {
        let fx = Fx::new();
        write(
            &fx.tools().join("site.yaml"),
            &SITE.replace("grammar: gh", "grammar: ../gh"),
            0o640,
        );
        let (result, out) = fx.disable("site", &FakeReload::ok());
        result.unwrap();
        assert!(fx.dropins().is_empty());
        assert!(!out.contains("grammars"), "{out}");
    }

    #[test]
    fn disable_refuses_a_missing_dropin() {
        let fx = Fx::new();
        fx.enabled();
        let r = FakeReload::ok();
        let e = err(fx.disable("nope", &r).0);
        assert!(
            e.contains(&format!(
                "no drop-in {}",
                fx.tools().join("nope.yaml").display()
            )),
            "{e}"
        );
        assert_eq!(fx.dropins(), yamls(&NAMES));
        assert_eq!(fx.link(), fx.exact());
        assert_eq!(r.calls.get(), 0);
    }
}
