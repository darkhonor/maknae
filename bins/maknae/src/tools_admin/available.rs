use crate::cli::terminal_safe;
use crate::tools_admin::dirs::{open, stems, Dirs};
use crate::tools_admin::inventory::configured;
use crate::tools_admin::{say, Owners, Paths};
use maknae_config::{grammar_uses, GRAMMARS_DIR};
use maknae_io::MemberState;
use std::io::Write;

pub(crate) fn available(p: &Paths, o: &Owners, out: &mut dyn Write) -> Result<(), String> {
    let d = Dirs::open(p, o)?;
    let vendor = stems(&open(&p.vendor_grammars, o.dir, 0o022)?, &p.vendor_grammars)?;
    let templates = stems(
        &open(&p.vendor_templates, o.dir, 0o022)?,
        &p.vendor_templates,
    )?;
    let grammars = p.config.join(GRAMMARS_DIR);
    let local = stems(&d.grammars, &grammars)?;
    let found = configured(p, o, &d)?;
    for program in vendor.union(&local) {
        let name = format!("{program}.yaml");
        let state = d
            .grammars
            .enabled_member_state(&name, &p.vendor_grammars)
            .map_err(|e| {
                terminal_safe(&format!(
                    "cannot inspect {}: {e}",
                    grammars.join(&name).display()
                ))
            })?;
        let state = match state {
            MemberState::VendorLink => "enabled (linked)".to_string(),
            MemberState::LocalFile => {
                if vendor.contains(program) {
                    "overridden (local file)".to_string()
                } else {
                    "local only".to_string()
                }
            }
            MemberState::Absent => "not enabled".to_string(),
            MemberState::ForeignLink(target) => format!("refused: link to {}", target.display()),
            MemberState::Other => "refused: not a file or link".to_string(),
        };
        let template = if templates.contains(program) {
            "yes"
        } else {
            "no"
        };
        let users: Vec<&str> = found
            .iter()
            .filter(|f| grammar_uses(&f.text).contains(program))
            .map(|f| f.file.as_str())
            .collect();
        let users = if users.is_empty() {
            "none".to_string()
        } else {
            users.join(", ")
        };
        say(
            out,
            &format!("{program}  {state}  template: {template}  used by: {users}"),
        )?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {

    use crate::tools_admin::test_support::{
        err, req, write, FakeReload, Fx, GRAMMAR, HOMELAB, SITE, TEMPLATE,
    };

    #[test]
    fn available_reports_each_state() {
        let fx = Fx::new();
        fx.enabled_one("github-post");
        fx.enabled_one("github-read");
        for program in ["glab", "jj", "kk"] {
            write(
                &fx.vendor_grammars().join(format!("{program}.yaml")),
                GRAMMAR,
                0o644,
            );
        }
        write(&fx.vendor_grammars().join(".hidden.yaml"), GRAMMAR, 0o644);
        write(&fx.vendor_grammars().join("README"), "", 0o644);
        write(&fx.grammars().join("zz.yaml"), GRAMMAR, 0o640);
        write(&fx.grammars().join("kk.yaml"), GRAMMAR, 0o640);
        std::fs::create_dir(fx.grammars().join("dd.yaml")).unwrap();
        std::os::unix::fs::symlink("/elsewhere/jj.yaml", fx.grammars().join("jj.yaml")).unwrap();
        std::os::unix::fs::symlink(
            fx.tools().join("github-read.yaml"),
            fx.tools().join("link.yaml"),
        )
        .unwrap();
        write(
            &fx.config().join("tools.yaml"),
            &HOMELAB.replace("grammar: gh", "grammar: glab"),
            0o640,
        );
        let out = fx.available();
        let lines: Vec<&str> = out.lines().collect();
        assert_eq!(
            lines,
            [
                "dd  refused: not a file or link  template: no  used by: none",
                "gh  enabled (linked)  template: yes  used by: tools.d/github-post.yaml, tools.d/github-read.yaml",
                "glab  not enabled  template: no  used by: tools.yaml",
                "jj  refused: link to /elsewhere/jj.yaml  template: no  used by: none",
                "kk  overridden (local file)  template: no  used by: none",
                "zz  local only  template: no  used by: none",
            ]
        );
    }

    #[test]
    fn output_escapes_file_text() {
        let fx = Fx::new();
        fx.enabled_one("github-post");
        write(&fx.tools().join("evil\x1b[31m.yaml"), SITE, 0o640);
        let out = fx.available();
        assert!(!out.contains('\x1b'), "{out:?}");
        assert!(out.contains("tools.d/evil\\u{1b}[31m.yaml"), "{out}");

        std::fs::remove_file(fx.tools().join("github-post.yaml")).unwrap();
        let e = err(fx
            .enable(&req(Some("github-post"), None), &FakeReload::ok())
            .0);
        assert!(!e.contains('\x1b'), "{e:?}");
        assert!(e.contains("tools.d/evil\\u{1b}[31m.yaml"), "{e}");

        std::fs::remove_file(fx.tools().join("evil\x1b[31m.yaml")).unwrap();
        write(
            &fx.vendor_templates().join("gh.yaml"),
            &TEMPLATE.replace(
                "app: maknae-github-post",
                "app: \"maknae-github-post\\e[31m\"",
            ),
            0o644,
        );
        let (result, out) = fx.enable(&req(Some("github-post"), None), &FakeReload::ok());
        result.unwrap();
        assert!(!out.contains('\x1b'), "{out:?}");
        assert!(out.contains("maknae-github-post\\u{1b}[31m"), "{out}");
    }
}
