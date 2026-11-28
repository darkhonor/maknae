use crate::cli::terminal_safe;
use crate::tools_admin::dirs::{listing, read_text, required, yaml_stem, Dirs};
use crate::tools_admin::{template, Owners, Paths};
use maknae_config::{
    defined_names, tool_program_name_ok, Grammar, GrammarSet, ToolsCatalog, GRAMMARS_DIR,
    TOOLS_DROPIN_DIR, TOOLS_FILE,
};
use maknae_io::{AnchorRequired, EnabledMember, Kind, MemberState, StrategyPref};
use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

#[derive(Clone)]
pub(super) struct Found {
    pub(super) file: String,
    pub(super) stem: Option<String>,
    pub(super) text: String,
}

pub(super) fn configured(p: &Paths, o: &Owners, d: &Dirs) -> Result<Vec<Found>, String> {
    let target = required(o.file.uid, 0o027);
    let mut found = Vec::new();
    let main = p.config.join(TOOLS_FILE);
    if let Some(text) = read_text(&d.config, Path::new(TOOLS_FILE), target.clone(), &main)? {
        found.push(Found {
            file: TOOLS_FILE.to_string(),
            stem: None,
            text,
        });
    }
    let dir = p.config.join(TOOLS_DROPIN_DIR);
    for entry in listing(&d.tools, &dir)? {
        let name = entry.name.to_string_lossy();
        let Some(stem) = yaml_stem(&name) else {
            continue;
        };
        if entry.kind != Kind::File {
            continue;
        }
        let shown = dir.join(&entry.name);
        if let Some(text) = read_text(&d.tools, Path::new(&entry.name), target.clone(), &shown)? {
            found.push(Found {
                file: format!("{TOOLS_DROPIN_DIR}/{name}"),
                stem: Some(stem.to_string()),
                text,
            });
        }
    }
    Ok(found)
}

fn describe(state: &MemberState) -> String {
    match state {
        MemberState::Absent => "absent".to_string(),
        MemberState::VendorLink => "the vendor link".to_string(),
        MemberState::LocalFile => "a local file".to_string(),
        MemberState::ForeignLink(target) => format!("a link to {}", target.display()),
        MemberState::Other => "not a file or link".to_string(),
    }
}

pub(super) fn refusal(link: &Path, state: &MemberState) -> String {
    format!(
        "{} is {}; enable never replaces it",
        link.display(),
        describe(state)
    )
}

pub(super) fn collisions<'a>(
    dropins: &[template::Dropin],
    found: &'a [Found],
) -> Vec<(&'a Found, Vec<String>)> {
    let mut classes = BTreeSet::new();
    let mut tools = BTreeSet::new();
    for dropin in dropins {
        let (c, t) = defined_names(&dropin.text);
        classes.extend(c);
        tools.extend(t);
    }
    found
        .iter()
        .filter_map(|f| {
            let (c, t) = defined_names(&f.text);
            let names: BTreeSet<String> = c
                .into_iter()
                .filter(|n| classes.contains(n))
                .chain(t.into_iter().filter(|n| tools.contains(n)))
                .collect();
            (!names.is_empty()).then(|| (f, names.into_iter().collect()))
        })
        .collect()
}

pub(super) struct Link {
    pub(super) name: String,
    pub(super) path: PathBuf,
    pub(super) vendor: PathBuf,
    pub(super) before: MemberState,
}

fn quoted(names: &[impl AsRef<str>]) -> String {
    names
        .iter()
        .map(|n| format!("`{}`", n.as_ref()))
        .collect::<Vec<_>>()
        .join(", ")
}

pub(super) fn collision_error(
    hits: &[(&Found, Vec<String>)],
    dropins: &[template::Dropin],
    link: &Link,
) -> String {
    let mut lines = Vec::new();
    for (found, names) in hits {
        let names = quoted(names);
        lines.push(format!("{names} already defined in {}", found.file));
        lines.push(match &found.stem {
            Some(stem) => {
                let (classes, tools) = defined_names(&found.text);
                let own = dropins.iter().find(|d| d.entry == *stem).is_some_and(|d| {
                    let (own, _) = defined_names(&d.text);
                    classes.iter().all(|c| own.contains(c))
                });
                if tools == [stem.as_str()] && own {
                    format!(
                        "to replace {}, disable it first: sudo maknae tools disable {stem}",
                        found.file
                    )
                } else {
                    format!("rename or remove {names} in {}", found.file)
                }
            }
            None => match &link.before {
                MemberState::Absent => format!(
                    "to keep tools.yaml's entries, link the grammar instead: sudo ln -s {} {}",
                    link.vendor.display(),
                    link.path.display()
                ),
                MemberState::VendorLink => {
                    "the grammar is already linked; tools.yaml's entries use it".to_string()
                }
                MemberState::LocalFile | MemberState::ForeignLink(_) | MemberState::Other => {
                    refusal(&link.path, &link.before)
                }
            },
        });
    }
    let taken: BTreeSet<&String> = hits.iter().flat_map(|(_, names)| names).collect();
    let free: Vec<&str> = dropins
        .iter()
        .filter(|d| {
            let (classes, tools) = defined_names(&d.text);
            !classes.iter().chain(&tools).any(|n| taken.contains(n))
        })
        .map(|d| d.entry.as_str())
        .collect();
    if !free.is_empty() {
        lines.push(format!(
            "the entries that do not collide can be enabled one at a time with --entry: {}",
            quoted(&free)
        ));
    }
    lines.push("nothing was written".to_string());
    terminal_safe(&lines.join("; "))
}

pub(super) fn grammar_set(p: &Paths, o: &Owners, d: &Dirs) -> Result<GrammarSet, String> {
    let vendor = maknae_io::open_anchor_resolved(
        &p.vendor_grammars,
        AnchorRequired {
            owner: Some(o.file.uid),
            mode_mask: Some(0o022),
        },
        StrategyPref::Auto,
    );
    let member = required(o.file.uid, 0o027);
    let mut set = GrammarSet::empty();
    for entry in listing(&d.grammars, &p.config.join(GRAMMARS_DIR))? {
        let name = entry.name.to_string_lossy();
        let Some(stem) = yaml_stem(&name) else {
            continue;
        };
        if !tool_program_name_ok(stem) || stem.ends_with(".yaml") {
            continue;
        }
        let read = match &vendor {
            Ok(vendor) => d
                .grammars
                .read_enabled_member(&name, vendor, &p.vendor_grammars, member.clone())
                .map(|m| match m {
                    EnabledMember::Local(bytes) | EnabledMember::Vendor(bytes) => bytes,
                }),
            Err(_) => d
                .grammars
                .read(Path::new(&entry.name), None, member.clone())
                .map(|o| o.value),
        };
        let Ok(bytes) = read else {
            continue;
        };
        let Some(grammar) = std::str::from_utf8(&bytes)
            .ok()
            .and_then(|text| Grammar::parse(stem, text).ok())
        else {
            continue;
        };
        set.grammars.insert(stem.to_string(), grammar);
    }
    Ok(set)
}

pub(super) fn catalog(
    found: &[Found],
    added: &[(String, &str)],
    grammars: &GrammarSet,
) -> Result<ToolsCatalog, String> {
    let main = found
        .iter()
        .find(|f| f.stem.is_none())
        .map(|f| f.text.as_str());
    let named: Vec<(String, &str)> = found
        .iter()
        .filter_map(|f| Some((format!("{}.yaml", f.stem.as_ref()?), f.text.as_str())))
        .chain(added.iter().map(|(name, text)| (name.clone(), *text)))
        .collect();
    let pairs: Vec<(&str, &str)> = named.iter().map(|(n, t)| (n.as_str(), *t)).collect();
    ToolsCatalog::from_texts(main, &pairs, grammars)
        .map_err(|e| terminal_safe(&format!("cannot check what this change enables: {e}")))
}

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub(super) enum Def {
    Class,
    Tool,
}

impl Def {
    fn label(self) -> &'static str {
        match self {
            Def::Class => "credential class",
            Def::Tool => "tool",
        }
    }

    fn in_text(self, text: &str) -> Vec<String> {
        let (classes, tools) = defined_names(text);
        match self {
            Def::Class => classes,
            Def::Tool => tools,
        }
    }
}

pub(super) fn defined(text: &str) -> BTreeSet<(Def, String)> {
    [Def::Class, Def::Tool]
        .into_iter()
        .flat_map(|def| def.in_text(text).into_iter().map(move |n| (def, n)))
        .collect()
}

pub(super) fn enabled(c: &ToolsCatalog) -> BTreeSet<(Def, String)> {
    c.entries()
        .map(|e| (Def::Tool, e.name.clone()))
        .chain(c.class_names().map(|n| (Def::Class, n.to_string())))
        .collect()
}

pub(super) fn activations(
    before: &ToolsCatalog,
    after: &ToolsCatalog,
    requested: &BTreeSet<(Def, String)>,
    found: &[Found],
    sub: &str,
    nothing: &str,
) -> Result<(), String> {
    let was = enabled(before);
    let woken: Vec<String> = enabled(after)
        .into_iter()
        .filter(|n| !was.contains(n) && !requested.contains(n))
        .map(|(def, name)| {
            let files: Vec<&str> = found
                .iter()
                .filter(|f| def.in_text(&f.text).contains(&name))
                .map(|f| f.file.as_str())
                .collect();
            format!(
                "{sub} would also enable the {} `{name}` defined in {}",
                def.label(),
                files.join(", ")
            )
        })
        .collect();
    if woken.is_empty() {
        Ok(())
    } else {
        Err(terminal_safe(&format!("{}; {nothing}", woken.join("; "))))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::tools_admin::test_support::{me, write, Fx, GRAMMAR};
    use std::os::unix::fs::PermissionsExt;

    #[test]
    fn grammar_set_reads_local_grammars_when_the_vendor_directory_is_unusable() {
        let fx = Fx::new();
        fx.link_exactly();
        write(
            &fx.grammars().join("kk.yaml"),
            &GRAMMAR.replace("program: gh", "program: kk"),
            0o640,
        );
        write(
            &fx.grammars().join("loose.yaml"),
            &GRAMMAR.replace("program: gh", "program: loose"),
            0o644,
        );
        let elsewhere = fx.0.join("ln.yaml");
        write(
            &elsewhere,
            &GRAMMAR.replace("program: gh", "program: ln"),
            0o640,
        );
        std::os::unix::fs::symlink(&elsewhere, fx.grammars().join("ln.yaml")).unwrap();
        std::fs::create_dir(fx.grammars().join("dd.yaml")).unwrap();
        let (o, p) = (me(), fx.paths());
        let keys = || {
            let set = grammar_set(&p, &o, &Dirs::open(&p, &o).unwrap()).unwrap();
            set.grammars.keys().cloned().collect::<Vec<_>>()
        };
        std::fs::set_permissions(fx.vendor_grammars(), std::fs::Permissions::from_mode(0o777))
            .unwrap();
        assert_eq!(keys(), ["kk"]);
        std::fs::remove_dir_all(fx.vendor_grammars()).unwrap();
        assert_eq!(keys(), ["kk"]);
    }

    #[test]
    fn grammar_set_holds_what_the_loader_would_enable() {
        let fx = Fx::new();
        fx.link_exactly();
        write(
            &fx.grammars().join("kk.yaml"),
            &GRAMMAR.replace("program: gh", "program: kk"),
            0o640,
        );
        write(
            &fx.grammars().join("bad name.yaml"),
            &GRAMMAR.replace("program: gh", "program: bad name"),
            0o640,
        );
        write(
            &fx.grammars().join("x.yaml.yaml"),
            &GRAMMAR.replace("program: gh", "program: x.yaml"),
            0o640,
        );
        write(&fx.grammars().join("broken.yaml"), "a: [", 0o640);
        write(
            &fx.grammars().join("loose.yaml"),
            &GRAMMAR.replace("program: gh", "program: loose"),
            0o644,
        );
        write(&fx.grammars().join("bytes.yaml"), "", 0o640);
        std::fs::write(fx.grammars().join("bytes.yaml"), [0xff, 0xfe]).unwrap();
        write(&fx.grammars().join(".hidden.yaml"), GRAMMAR, 0o640);
        write(&fx.grammars().join("notes"), GRAMMAR, 0o640);
        std::os::unix::fs::symlink("/elsewhere/jj.yaml", fx.grammars().join("jj.yaml")).unwrap();
        let (o, p) = (me(), fx.paths());
        let set = grammar_set(&p, &o, &Dirs::open(&p, &o).unwrap()).unwrap();
        assert_eq!(set.grammars.keys().collect::<Vec<_>>(), ["gh", "kk"]);
        assert_eq!(set.grammars["gh"], Grammar::parse("gh", GRAMMAR).unwrap());
    }
}
