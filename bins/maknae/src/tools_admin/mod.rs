mod template;

use crate::cli::{terminal_safe, ToolsCommand};
use crate::enroll::{Host, Platform, Ran, Run};
use crate::policy_sync::{kernel_gid, CONFIG_DIR, RELOAD};
use maknae_config::{
    defined_names, grammar_uses, tool_entry_name_ok, tool_program_name_ok, Grammar, GrammarSet,
    ToolsCatalog, GRAMMARS_DIR, TOOLS_DROPIN_DIR, TOOLS_FILE, VENDOR_GRAMMAR_DIR, VENDOR_TOOLS_DIR,
};
use maknae_io::program::Program;
use maknae_io::{
    open_anchor, Anchor, AnchorLock, AnchorRequired, EnabledMember, Entry, EntryId, FileOwner,
    IoError, IoKind, Kind, MemberState, Mode, StrategyPref, TargetRequired,
};
use std::collections::BTreeSet;
use std::io::Write;
use std::path::{Path, PathBuf};

const LOCKED: &str = "another maknae tools command is running";

const GRANT_HEADER: &str = "Grant these in authz.yaml (roles.<role>.permissions.allow) or an agent's policy.yaml (permissions.allow):";

pub(crate) struct Paths {
    pub config: PathBuf,
    pub vendor_grammars: PathBuf,
    pub vendor_templates: PathBuf,
}

pub(crate) struct Owners {
    pub dir: u32,
    pub file: FileOwner,
}

pub(crate) trait Reload {
    fn reload(&self) -> Result<(), String>;
}

pub(crate) enum DirError {
    NotDone(String),
    DoneNotDurable(String),
}

pub(crate) enum WriteError {
    NotDone(String),
    DoneNotDurable(String),
}

pub(crate) trait DropinDir {
    fn publish_new(&self, name: &str, bytes: &[u8]) -> Result<bool, WriteError>;
    fn link(&self, name: &str, vendor: &Path) -> Result<bool, WriteError>;
    fn identity(&self, name: &str) -> Result<Option<EntryId>, String>;
    fn remove(&self, name: &str) -> Result<(), DirError>;
}

pub(crate) struct Enable {
    pub program: String,
    pub image: String,
    pub shapes: Option<Vec<String>>,
    pub entry: Option<String>,
    pub reload: bool,
}

struct AnchoredDir<'a> {
    anchor: &'a Anchor,
    owner: FileOwner,
}

fn write_error(e: IoError) -> WriteError {
    match &e {
        IoError::PublishedNotDurable { .. } => WriteError::DoneNotDurable(e.to_string()),
        _ => WriteError::NotDone(e.to_string()),
    }
}

fn dir_error(e: IoError) -> DirError {
    match &e {
        IoError::RemovedNotDurable { .. } => DirError::DoneNotDurable(e.to_string()),
        _ => DirError::NotDone(e.to_string()),
    }
}

impl DropinDir for AnchoredDir<'_> {
    fn publish_new(&self, name: &str, bytes: &[u8]) -> Result<bool, WriteError> {
        self.anchor
            .publish_owned_new(Path::new(name), None, bytes, Mode(0o640), self.owner)
            .map(|o| o.value)
            .map_err(write_error)
    }

    fn link(&self, name: &str, vendor: &Path) -> Result<bool, WriteError> {
        self.anchor
            .link_member(name, vendor)
            .map(|o| o.value)
            .map_err(write_error)
    }

    fn identity(&self, name: &str) -> Result<Option<EntryId>, String> {
        self.anchor
            .entry_identity(name.as_ref())
            .map_err(|e| e.to_string())
    }

    fn remove(&self, name: &str) -> Result<(), DirError> {
        self.anchor
            .remove_durable(Path::new(name), None)
            .map(|_| ())
            .map_err(dir_error)
    }
}

struct Dirs {
    config: Anchor,
    grammars: Anchor,
    tools: Anchor,
}

impl Dirs {
    fn open(p: &Paths, o: &Owners) -> Result<Self, String> {
        Ok(Dirs {
            config: open(&p.config, o.dir, 0o027)?,
            grammars: open(&p.config.join(GRAMMARS_DIR), o.dir, 0o027)?,
            tools: open(&p.config.join(TOOLS_DROPIN_DIR), o.dir, 0o027)?,
        })
    }
}

#[derive(Clone)]
struct Found {
    file: String,
    stem: Option<String>,
    text: String,
}

fn say(out: &mut dyn Write, line: &str) -> Result<(), String> {
    writeln!(out, "{}", terminal_safe(line))
        .map_err(|e| format!("cannot write to standard output: {e}"))
}

fn open(path: &Path, owner: u32, mask: u32) -> Result<Anchor, String> {
    let required = AnchorRequired {
        owner: Some(owner),
        mode_mask: Some(mask),
    };
    open_anchor(path, required, StrategyPref::Auto)
        .map_err(|e| terminal_safe(&format!("cannot use {}: {e}", path.display())))
}

fn required(owner: u32, mask: u32) -> TargetRequired {
    TargetRequired {
        owner: Some(owner),
        mode_mask: Some(mask),
        nlink_exactly_one: false,
        regular_file: true,
        max_bytes: None,
    }
}

fn read_text(
    anchor: &Anchor,
    rel: &Path,
    target: TargetRequired,
    shown: &Path,
) -> Result<Option<String>, String> {
    let bytes = match anchor.read(rel, None, target) {
        Ok(o) => o.value,
        Err(IoError::Io {
            kind: IoKind::NotFound,
            ..
        }) => return Ok(None),
        Err(e) => {
            return Err(terminal_safe(&format!(
                "cannot read {}: {e}",
                shown.display()
            )))
        }
    };
    std::str::from_utf8(&bytes)
        .map(|text| Some(text.to_string()))
        .map_err(|_| terminal_safe(&format!("{} is not UTF-8", shown.display())))
}

fn yaml_stem(name: &str) -> Option<&str> {
    if name.starts_with('.') {
        None
    } else {
        name.strip_suffix(".yaml")
    }
}

fn listing(anchor: &Anchor, path: &Path) -> Result<Vec<Entry>, String> {
    let mut entries = anchor
        .enumerate(Path::new(""), None)
        .map_err(|e| terminal_safe(&format!("cannot list {}: {e}", path.display())))?
        .value;
    entries.sort_by(|a, b| a.name.cmp(&b.name));
    Ok(entries)
}

fn stems(anchor: &Anchor, path: &Path) -> Result<BTreeSet<String>, String> {
    Ok(listing(anchor, path)?
        .iter()
        .filter_map(|e| yaml_stem(&e.name.to_string_lossy()).map(str::to_string))
        .collect())
}

fn configured(p: &Paths, o: &Owners, d: &Dirs) -> Result<Vec<Found>, String> {
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

fn program_ok(program: &str) -> Result<(), String> {
    if tool_program_name_ok(program) {
        Ok(())
    } else {
        Err(format!(
            "`{}` is not a tool program name",
            terminal_safe(program)
        ))
    }
}

fn entry_ok(entry: &str) -> Result<(), String> {
    if tool_entry_name_ok(entry) {
        Ok(())
    } else {
        Err(format!(
            "`{}` is not a tool entry name",
            terminal_safe(entry)
        ))
    }
}

fn lock(tools: &Anchor) -> Result<AnchorLock, String> {
    tools.try_lock_exclusive().map_err(|e| match e {
        IoError::Locked { .. } => LOCKED.to_string(),
        e => terminal_safe(&format!("cannot lock the drop-in directory: {e}")),
    })
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

fn refusal(link: &Path, state: &MemberState) -> String {
    format!(
        "{} is {}; enable never replaces it",
        link.display(),
        describe(state)
    )
}

fn collisions<'a>(
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

struct Link {
    name: String,
    path: PathBuf,
    vendor: PathBuf,
    before: MemberState,
}

fn quoted(names: &[impl AsRef<str>]) -> String {
    names
        .iter()
        .map(|n| format!("`{}`", n.as_ref()))
        .collect::<Vec<_>>()
        .join(", ")
}

fn collision_error(
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

fn requested(platform: Platform) -> &'static str {
    match platform {
        Platform::Linux => "requested a reload of maknaed; if it refuses the new files it keeps the previous policy, and `sudo journalctl -u maknaed` says `maknaed: reload refused: <cause>`",
        Platform::Macos => "requested a reload of maknaed; if it refuses the new files it keeps the previous policy, and /usr/local/var/log/maknae/maknaed.err says `maknaed: reload refused: <cause>`",
    }
}

struct Committed {
    done: Vec<String>,
    lines: Vec<String>,
    notes: Vec<String>,
}

fn report(c: Committed, reload: bool, r: &dyn Reload, out: &mut dyn Write) -> Result<(), String> {
    let mut printed = c.lines.iter().try_for_each(|line| say(out, line));
    let state = if reload {
        r.reload().map(|()| requested(Platform::HOST))
    } else {
        Ok(RELOAD)
    };
    if let (Ok(()), Ok(line)) = (&printed, &state) {
        printed = say(out, line);
    }
    if printed.is_ok() && state.is_ok() && c.notes.is_empty() {
        return Ok(());
    }
    let mut parts = c.done;
    parts.push(match state {
        Ok(line) => line.to_string(),
        Err(cause) => format!("maknaed was not reloaded: {cause}; {RELOAD}"),
    });
    parts.extend(printed.err());
    parts.extend(c.notes);
    Err(terminal_safe(&parts.join("; ")))
}

fn grammar_set(p: &Paths, o: &Owners, d: &Dirs) -> Result<GrammarSet, String> {
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

fn catalog(
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
enum Def {
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

fn defined(text: &str) -> BTreeSet<(Def, String)> {
    [Def::Class, Def::Tool]
        .into_iter()
        .flat_map(|def| def.in_text(text).into_iter().map(move |n| (def, n)))
        .collect()
}

fn enabled(c: &ToolsCatalog) -> BTreeSet<(Def, String)> {
    c.entries()
        .map(|e| (Def::Tool, e.name.clone()))
        .chain(c.class_names().map(|n| (Def::Class, n.to_string())))
        .collect()
}

fn activations(
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

fn dropin_path(p: &Paths, file: &str) -> PathBuf {
    p.config.join(TOOLS_DROPIN_DIR).join(file)
}

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
fn enable_with(
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
fn disable_with(
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

fn preflight(euid: u32, sub: &str) -> Result<(), String> {
    if euid == 0 {
        Ok(())
    } else {
        Err(format!(
            "maknae tools {sub} must run as root: run `sudo maknae tools {sub}`"
        ))
    }
}

fn reload_call(platform: Platform) -> (Program, Vec<String>) {
    let (program, args): (Program, &[&str]) = match platform {
        Platform::Linux => (Program::Systemctl, &["reload", "maknaed"]),
        Platform::Macos => (
            Program::Launchctl,
            &["kill", "SIGHUP", "system/io.maknae.maknaed"],
        ),
    };
    (program, args.iter().map(|a| (*a).to_string()).collect())
}

struct HostReload<'a>(&'a dyn Run);

impl Reload for HostReload<'_> {
    fn reload(&self) -> Result<(), String> {
        let (program, args) = reload_call(Platform::HOST);
        let ran: Ran = self.0.run(program, &args)?;
        let stderr = ran.stderr.trim();
        match (ran.ok, ran.code) {
            (true, _) => Ok(()),
            (false, _) if !stderr.is_empty() => Err(stderr.to_string()),
            (false, Some(code)) => Err(format!("the reload exited with status {code}")),
            (false, None) => Err("the reload was ended by a signal".to_string()),
        }
    }
}

fn production_paths() -> Paths {
    Paths {
        config: PathBuf::from(CONFIG_DIR),
        vendor_grammars: PathBuf::from(VENDOR_GRAMMAR_DIR),
        vendor_templates: PathBuf::from(VENDOR_TOOLS_DIR),
    }
}

fn production_owners(kernel_gid: u32) -> Owners {
    Owners {
        dir: 0,
        file: FileOwner {
            uid: 0,
            gid: kernel_gid,
        },
    }
}

fn sub_name(cmd: &ToolsCommand) -> &'static str {
    match cmd {
        ToolsCommand::Available => "available",
        ToolsCommand::Enable { .. } => "enable",
        ToolsCommand::Disable { .. } => "disable",
    }
}

fn dispatch(
    cmd: ToolsCommand,
    p: &Paths,
    o: &Owners,
    r: &dyn Reload,
    out: &mut dyn Write,
) -> Result<(), String> {
    match cmd {
        ToolsCommand::Available => available(p, o, out),
        ToolsCommand::Enable {
            program,
            image,
            shapes,
            entry,
            no_reload,
        } => {
            let req = Enable {
                program,
                image,
                shapes,
                entry,
                reload: !no_reload,
            };
            enable(p, o, &req, r, out)
        }
        ToolsCommand::Disable { entry, no_reload } => disable(p, o, &entry, !no_reload, r, out),
    }
}

fn production(euid: u32, cmd: ToolsCommand, out: &mut dyn Write) -> Result<(), String> {
    preflight(euid, sub_name(&cmd))?;
    let o = production_owners(kernel_gid()?);
    dispatch(cmd, &production_paths(), &o, &HostReload(&Host), out)
}

fn finish_run(result: Result<(), String>, err: &mut dyn Write) -> u8 {
    match result {
        Ok(()) => 0,
        Err(e) => {
            let _ = writeln!(err, "maknae: {}", terminal_safe(&e));
            1
        }
    }
}

pub(crate) fn run_with(
    euid: u32,
    cmd: ToolsCommand,
    out: &mut dyn Write,
    err: &mut dyn Write,
) -> u8 {
    finish_run(production(euid, cmd, out), err)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::policy_sync::RELOAD;
    use maknae_config::{GrammarSet, ToolsCatalog};
    use std::cell::{Cell, RefCell};
    use std::os::unix::fs::PermissionsExt;
    use std::sync::atomic::{AtomicUsize, Ordering};

    const TEMPLATE: &str = include_str!("../../../../packaging/common/tools.d/gh.yaml");
    const GRAMMAR: &str = include_str!("../../../../packaging/common/grammars/gh.yaml");
    const HOMELAB: &str = include_str!("../../../../packaging/common/tools-homelab.yaml");
    const SITE: &str = include_str!("../testdata/dropin_site_github_post.yaml");
    const OTHER: &str = include_str!("../testdata/dropin_other_name.yaml");
    const GITHUB_READ_ONLY: &str = include_str!("../testdata/tools_github_read_only.yaml");

    const NAMES: [&str; 4] = [
        "github-issues-read",
        "github-issues-write",
        "github-post",
        "github-read",
    ];

    struct FakeReload {
        calls: Cell<u32>,
        fail: bool,
    }

    impl FakeReload {
        fn ok() -> Self {
            FakeReload {
                calls: Cell::new(0),
                fail: false,
            }
        }

        fn failing() -> Self {
            FakeReload {
                calls: Cell::new(0),
                fail: true,
            }
        }
    }

    impl Reload for FakeReload {
        fn reload(&self) -> Result<(), String> {
            self.calls.set(self.calls.get() + 1);
            if self.fail {
                Err("unit maknaed not loaded".to_string())
            } else {
                Ok(())
            }
        }
    }

    static NEXT: AtomicUsize = AtomicUsize::new(0);

    struct Fx(PathBuf);

    fn me() -> Owners {
        Owners {
            dir: nix::unistd::geteuid().as_raw(),
            file: FileOwner {
                uid: nix::unistd::geteuid().as_raw(),
                gid: nix::unistd::getegid().as_raw(),
            },
        }
    }

    fn img() -> String {
        format!("ghcr.io/example/tools@sha256:{}", "a".repeat(64))
    }

    fn req(entry: Option<&str>, shapes: Option<&[&str]>) -> Enable {
        Enable {
            program: "gh".to_string(),
            image: img(),
            shapes: shapes.map(|s| s.iter().map(|x| x.to_string()).collect()),
            entry: entry.map(str::to_string),
            reload: true,
        }
    }

    fn write(path: &Path, body: &str, mode: u32) {
        std::fs::write(path, body).unwrap();
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode)).unwrap();
    }

    fn mkdir(path: &Path, mode: u32) {
        std::fs::create_dir(path).unwrap();
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode)).unwrap();
    }

    fn set() -> GrammarSet {
        let mut set = GrammarSet::empty();
        set.grammars
            .insert("gh".to_string(), Grammar::parse("gh", GRAMMAR).unwrap());
        set
    }

    impl Fx {
        fn new() -> Self {
            let root = std::env::temp_dir().join(format!(
                "maknae_tools_admin_{}_{}",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::Relaxed)
            ));
            let _ = std::fs::remove_dir_all(&root);
            std::fs::create_dir_all(&root).unwrap();
            let fx = Fx(root);
            mkdir(&fx.config(), 0o750);
            mkdir(&fx.grammars(), 0o750);
            mkdir(&fx.tools(), 0o750);
            mkdir(&fx.0.join("vendor"), 0o755);
            mkdir(&fx.vendor_grammars(), 0o755);
            mkdir(&fx.vendor_templates(), 0o755);
            write(&fx.vendor_grammars().join("gh.yaml"), GRAMMAR, 0o644);
            write(&fx.vendor_templates().join("gh.yaml"), TEMPLATE, 0o644);
            fx
        }

        fn config(&self) -> PathBuf {
            self.0.join("config")
        }

        fn grammars(&self) -> PathBuf {
            self.config().join("grammars")
        }

        fn tools(&self) -> PathBuf {
            self.config().join("tools.d")
        }

        fn vendor_grammars(&self) -> PathBuf {
            self.0.join("vendor").join("grammars")
        }

        fn vendor_templates(&self) -> PathBuf {
            self.0.join("vendor").join("tools.d")
        }

        fn paths(&self) -> Paths {
            Paths {
                config: self.config(),
                vendor_grammars: self.vendor_grammars(),
                vendor_templates: self.vendor_templates(),
            }
        }

        fn enable(&self, req: &Enable, r: &FakeReload) -> (Result<(), String>, String) {
            let mut out = Vec::new();
            let result = enable(&self.paths(), &me(), req, r, &mut out);
            (result, String::from_utf8(out).unwrap())
        }

        fn disable(&self, entry: &str, r: &FakeReload) -> (Result<(), String>, String) {
            let mut out = Vec::new();
            let result = disable(&self.paths(), &me(), entry, true, r, &mut out);
            (result, String::from_utf8(out).unwrap())
        }

        fn available(&self) -> String {
            let mut out = Vec::new();
            available(&self.paths(), &me(), &mut out).unwrap();
            String::from_utf8(out).unwrap()
        }

        fn enabled(&self) {
            self.enable(&req(None, None), &FakeReload::ok()).0.unwrap();
        }

        fn enabled_one(&self, entry: &str) {
            self.enable(&req(Some(entry), None), &FakeReload::ok())
                .0
                .unwrap();
        }

        fn dropins(&self) -> Vec<String> {
            let mut names: Vec<String> = std::fs::read_dir(self.tools())
                .unwrap()
                .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
                .collect();
            names.sort();
            names
        }

        fn link(&self) -> Option<PathBuf> {
            std::fs::read_link(self.grammars().join("gh.yaml")).ok()
        }

        fn exact(&self) -> Option<PathBuf> {
            Some(self.vendor_grammars().join("gh.yaml"))
        }

        fn link_exactly(&self) {
            std::os::unix::fs::symlink(
                self.vendor_grammars().join("gh.yaml"),
                self.grammars().join("gh.yaml"),
            )
            .unwrap();
        }

        fn locked(&self) -> maknae_io::AnchorLock {
            open_anchor(
                &self.tools(),
                AnchorRequired {
                    owner: None,
                    mode_mask: None,
                },
                StrategyPref::Auto,
            )
            .unwrap()
            .try_lock_exclusive()
            .unwrap()
        }
    }

    impl Drop for Fx {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    fn err(result: Result<(), String>) -> String {
        match result {
            Ok(()) => panic!("expected an error"),
            Err(e) => e,
        }
    }

    fn yamls(names: &[&str]) -> Vec<String> {
        let mut v: Vec<String> = names.iter().map(|n| format!("{n}.yaml")).collect();
        v.sort();
        v
    }

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

    #[derive(Clone, Copy)]
    enum Fail {
        Never,
        NotDone,
        DoneNotDurable,
    }

    struct Failing<'a> {
        inner: &'a dyn DropinDir,
        calls: Cell<u32>,
        identities: Cell<u32>,
        plan: Plan<'a>,
        removes: Fail,
        log: &'a RefCell<Vec<String>>,
    }

    #[derive(Clone, Copy)]
    struct Plan<'p> {
        third_publish: Fail,
        removes: Fail,
        links: Fail,
        link_removes: Fail,
        before_failing: &'p dyn Fn(),
        after_link: &'p dyn Fn(),
        before_recheck: &'p dyn Fn(),
    }

    fn plan() -> Plan<'static> {
        Plan {
            third_publish: Fail::Never,
            removes: Fail::Never,
            links: Fail::Never,
            link_removes: Fail::Never,
            before_failing: &|| {},
            after_link: &|| {},
            before_recheck: &|| {},
        }
    }

    fn fail(how: Fail, done: impl FnOnce() -> Result<(), DirError>) -> Result<(), DirError> {
        match how {
            Fail::Never => done(),
            Fail::NotDone => Err(DirError::NotDone("disk full".to_string())),
            Fail::DoneNotDurable => {
                done()?;
                Err(DirError::DoneNotDurable("sync failed".to_string()))
            }
        }
    }

    fn fail_write(
        how: Fail,
        done: impl FnOnce() -> Result<bool, WriteError>,
        between: &dyn Fn(),
    ) -> Result<bool, WriteError> {
        match how {
            Fail::Never => done(),
            Fail::NotDone => Err(WriteError::NotDone("disk full".to_string())),
            Fail::DoneNotDurable => {
                done()?;
                between();
                Err(WriteError::DoneNotDurable("sync failed".to_string()))
            }
        }
    }

    impl DropinDir for Failing<'_> {
        fn publish_new(&self, name: &str, bytes: &[u8]) -> Result<bool, WriteError> {
            self.log.borrow_mut().push(format!("publish {name}"));
            self.calls.set(self.calls.get() + 1);
            if self.calls.get() != 3 {
                return self.inner.publish_new(name, bytes);
            }
            (self.plan.before_failing)();
            fail_write(
                self.plan.third_publish,
                || self.inner.publish_new(name, bytes),
                &|| {},
            )
        }

        fn link(&self, name: &str, vendor: &Path) -> Result<bool, WriteError> {
            self.log.borrow_mut().push(format!("link {name}"));
            fail_write(
                self.plan.links,
                || self.inner.link(name, vendor),
                self.plan.after_link,
            )
        }

        fn identity(&self, name: &str) -> Result<Option<EntryId>, String> {
            self.identities.set(self.identities.get() + 1);
            if self.identities.get() == 2 {
                (self.plan.before_recheck)();
            }
            self.inner.identity(name)
        }

        fn remove(&self, name: &str) -> Result<(), DirError> {
            self.log.borrow_mut().push(format!("remove {name}"));
            fail(self.removes, || self.inner.remove(name))
        }
    }

    fn with_run<T>(
        fx: &Fx,
        plan: Plan,
        f: impl FnOnce(&Paths, &Owners, &Dirs, &Failing, &Failing) -> T,
    ) -> (T, Vec<String>) {
        let o = me();
        let p = fx.paths();
        let dirs = Dirs::open(&p, &o).unwrap();
        let tools = AnchoredDir {
            anchor: &dirs.tools,
            owner: o.file,
        };
        let grammars = AnchoredDir {
            anchor: &dirs.grammars,
            owner: o.file,
        };
        let log = RefCell::new(Vec::new());
        let wrap = |inner, removes| Failing {
            inner,
            calls: Cell::new(0),
            identities: Cell::new(0),
            plan,
            removes,
            log: &log,
        };
        let got = f(
            &p,
            &o,
            &dirs,
            &wrap(&tools, plan.removes),
            &wrap(&grammars, plan.link_removes),
        );
        (got, log.into_inner())
    }

    fn enable_run(
        fx: &Fx,
        request: &Enable,
        r: &FakeReload,
        plan: Plan,
    ) -> (Result<(), String>, String, Vec<String>) {
        let ((result, out), log) = with_run(fx, plan, |p, o, dirs, tools, links| {
            let mut out = Vec::new();
            let result = enable_with(p, o, dirs, request, r, &mut out, tools, links);
            (result, String::from_utf8(out).unwrap())
        });
        (result, out, log)
    }

    fn enable_failing(
        fx: &Fx,
        third_publish: Fail,
        removes: Fail,
        before_failing: &dyn Fn(),
    ) -> (String, u32) {
        let r = FakeReload::ok();
        let plan = Plan {
            third_publish,
            removes,
            before_failing,
            ..plan()
        };
        let (result, out, _) = enable_run(fx, &req(None, None), &r, plan);
        assert!(out.is_empty(), "{out}");
        (err(result), r.calls.get())
    }

    fn enable_failing_third(fx: &Fx, before_failing: &dyn Fn()) -> (String, u32) {
        enable_failing(fx, Fail::NotDone, Fail::Never, before_failing)
    }

    fn disable_run(
        fx: &Fx,
        entry: &str,
        r: &FakeReload,
        plan: Plan,
    ) -> (Result<(), String>, String) {
        with_run(fx, plan, |p, o, dirs, tools, links| {
            let mut out = Vec::new();
            let result = disable_with(p, o, dirs, entry, true, r, &mut out, tools, links);
            (result, String::from_utf8(out).unwrap())
        })
        .0
    }

    fn disable_failing(
        fx: &Fx,
        entry: &str,
        removes: Fail,
        r: &FakeReload,
    ) -> (Result<(), String>, String) {
        disable_run(fx, entry, r, Plan { removes, ..plan() })
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
    fn io_errors_map_to_what_may_be_on_disk() {
        let path = PathBuf::from("/x");
        let kind = IoKind::Other { raw: 5 };
        let published = || IoError::PublishedNotDurable {
            path: path.clone(),
            kind: kind.clone(),
        };
        let removed = || IoError::RemovedNotDurable {
            path: path.clone(),
            kind: kind.clone(),
        };
        let other = || IoError::Io {
            kind: IoKind::NotFound,
            path: path.clone(),
        };
        assert!(matches!(
            write_error(published()),
            WriteError::DoneNotDurable(_)
        ));
        for e in [removed(), other()] {
            assert!(matches!(write_error(e), WriteError::NotDone(_)));
        }
        assert!(matches!(dir_error(removed()), DirError::DoneNotDurable(_)));
        for e in [published(), other()] {
            assert!(matches!(dir_error(e), DirError::NotDone(_)));
        }
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
    fn operands_are_checked() {
        let fx = Fx::new();
        let r = FakeReload::ok();
        let mut bad = req(None, None);
        bad.program = "../x".to_string();
        let e = err(fx.enable(&bad, &r).0);
        assert!(e.contains("`../x`"), "{e}");
        let e = err(fx.enable(&req(Some("a/b"), None), &r).0);
        assert!(e.contains("`a/b`"), "{e}");
        let e = err(fx.disable("sub/x", &r).0);
        assert!(e.contains("`sub/x`"), "{e}");
        assert!(fx.dropins().is_empty());
        assert_eq!(fx.link(), None);
        assert_eq!(r.calls.get(), 0);
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

    struct Broken;

    impl Write for Broken {
        fn write(&mut self, _: &[u8]) -> std::io::Result<usize> {
            Err(std::io::ErrorKind::BrokenPipe.into())
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    #[test]
    fn enable_reloads_and_reports_when_stdout_fails() {
        let fx = Fx::new();
        let r = FakeReload::ok();
        let e = err(enable(
            &fx.paths(),
            &me(),
            &req(Some("github-post"), None),
            &r,
            &mut Broken,
        ));
        let wrote = fx.tools().join("github-post.yaml");
        assert_eq!(
            e,
            format!(
                "wrote {}; linked {} to {}; {}; cannot write to standard output: {}",
                wrote.display(),
                fx.grammars().join("gh.yaml").display(),
                fx.vendor_grammars().join("gh.yaml").display(),
                requested(Platform::HOST),
                std::io::Error::from(std::io::ErrorKind::BrokenPipe)
            )
        );
        assert_eq!(r.calls.get(), 1);
        assert_eq!(fx.dropins(), ["github-post.yaml"]);
        assert_eq!(fx.link(), fx.exact());

        let mut no = req(Some("github-read"), None);
        no.reload = false;
        let e = err(enable(&fx.paths(), &me(), &no, &r, &mut Broken));
        assert!(
            e.starts_with(&format!(
                "wrote {}; {RELOAD}; cannot write to standard output",
                fx.tools().join("github-read.yaml").display()
            )),
            "{e}"
        );
        assert_eq!(r.calls.get(), 1);
    }

    #[test]
    fn disable_reloads_and_reports_when_stdout_fails() {
        let fx = Fx::new();
        fx.enabled_one("github-post");
        let r = FakeReload::ok();
        let e = err(disable(
            &fx.paths(),
            &me(),
            "github-post",
            true,
            &r,
            &mut Broken,
        ));
        assert!(
            e.starts_with(&format!(
                "removed {}; removed {}; {}; cannot write to standard output",
                fx.tools().join("github-post.yaml").display(),
                fx.grammars().join("gh.yaml").display(),
                requested(Platform::HOST)
            )),
            "{e}"
        );
        assert_eq!(r.calls.get(), 1);
        assert!(fx.dropins().is_empty());
        assert_eq!(fx.link(), None);
    }

    #[test]
    fn disable_reloads_and_reports_a_link_it_cannot_remove() {
        let fx = Fx::new();
        fx.enabled_one("github-post");
        let r = FakeReload::ok();
        let stuck = Plan {
            link_removes: Fail::NotDone,
            ..plan()
        };
        let (result, out) = disable_run(&fx, "github-post", &r, stuck);
        let link = fx.grammars().join("gh.yaml");
        let dropin = fx.tools().join("github-post.yaml");
        assert_eq!(
            err(result),
            format!(
                "removed {}; {}; cannot remove {}: disk full; the link remains and disable cannot be run again for it: sudo rm {}",
                dropin.display(),
                requested(Platform::HOST),
                link.display(),
                link.display()
            )
        );
        assert_eq!(r.calls.get(), 1);
        assert!(fx.dropins().is_empty());
        assert_eq!(fx.link(), fx.exact());
        assert_eq!(
            out,
            format!(
                "removed {}\n{}\n",
                dropin.display(),
                requested(Platform::HOST)
            )
        );

        fx.enabled_one("github-post");
        let unsynced = Plan {
            link_removes: Fail::DoneNotDurable,
            ..plan()
        };
        let e = err(disable_run(&fx, "github-post", &r, unsynced).0);
        assert_eq!(
            e,
            format!(
                "removed {}; removed {}; {}; the removal is not yet durable: sync failed",
                dropin.display(),
                link.display(),
                requested(Platform::HOST)
            )
        );
        assert_eq!(fx.link(), None);
    }

    fn rewrite_in_place(path: &Path, body: &str) {
        use std::io::Write as _;
        let mut f = std::fs::OpenOptions::new()
            .write(true)
            .truncate(true)
            .open(path)
            .unwrap();
        f.write_all(body.as_bytes()).unwrap();
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
    fn requested_names_where_a_refused_reload_is_reported() {
        assert_eq!(
            requested(Platform::Linux),
            "requested a reload of maknaed; if it refuses the new files it keeps the previous policy, and `sudo journalctl -u maknaed` says `maknaed: reload refused: <cause>`"
        );
        assert_eq!(
            requested(Platform::Macos),
            "requested a reload of maknaed; if it refuses the new files it keeps the previous policy, and /usr/local/var/log/maknae/maknaed.err says `maknaed: reload refused: <cause>`"
        );
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

    #[test]
    fn enable_with_no_reload_prints_the_command() {
        let fx = Fx::new();
        let r = FakeReload::ok();
        let mut no = req(None, None);
        no.reload = false;
        let (result, out) = fx.enable(&no, &r);
        result.unwrap();
        assert_eq!(r.calls.get(), 0);
        assert!(out.contains(RELOAD), "{out}");
        assert!(!out.contains("requested a reload"), "{out}");

        let mut out = Vec::new();
        disable(&fx.paths(), &me(), "github-post", false, &r, &mut out).unwrap();
        assert_eq!(r.calls.get(), 0);
        assert!(String::from_utf8(out).unwrap().contains(RELOAD));
    }

    #[test]
    fn a_failed_reload_reports_files_in_place() {
        let fx = Fx::new();
        let r = FakeReload::failing();
        let e = err(fx.enable(&req(Some("github-post"), None), &r).0);
        assert!(e.contains("maknaed was not reloaded"), "{e}");
        assert!(e.contains("unit maknaed not loaded"), "{e}");
        assert!(e.contains(RELOAD), "{e}");
        let wrote = fx.tools().join("github-post.yaml");
        assert!(e.contains(&format!("wrote {}", wrote.display())), "{e}");
        assert!(wrote.exists());
        assert_eq!(fx.link(), fx.exact());
        assert_eq!(r.calls.get(), 1);

        let e = err(fx.disable("github-post", &r).0);
        assert!(e.contains("maknaed was not reloaded"), "{e}");
        assert!(e.contains(&format!("removed {}", wrote.display())), "{e}");
        assert!(!wrote.exists());
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

    struct Spawn {
        ran: std::cell::RefCell<Vec<(Program, Vec<String>)>>,
        reply: Result<Ran, String>,
    }

    impl Run for Spawn {
        fn run(&self, program: Program, args: &[String]) -> Result<Ran, String> {
            self.ran.borrow_mut().push((program, args.to_vec()));
            self.reply.clone()
        }
    }

    fn spawn(reply: Result<Ran, String>) -> Spawn {
        Spawn {
            ran: Default::default(),
            reply,
        }
    }

    fn ran(ok: bool, stderr: &str) -> Ran {
        Ran {
            ok,
            code: Some(if ok { 0 } else { 1 }),
            stdout: String::new(),
            stderr: stderr.into(),
        }
    }

    fn run_as(euid: u32, cmd: ToolsCommand) -> (u8, String) {
        let (mut out, mut err) = (Vec::new(), Vec::new());
        let code = run_with(euid, cmd, &mut out, &mut err);
        (code, String::from_utf8(err).unwrap())
    }

    #[test]
    fn run_refuses_unless_root() {
        let disable = || ToolsCommand::Disable {
            entry: "x".into(),
            no_reload: true,
        };
        let enable = || ToolsCommand::Enable {
            program: "gh".into(),
            image: "i".into(),
            shapes: None,
            entry: None,
            no_reload: true,
        };
        for (cmd, sub) in [
            (ToolsCommand::Available, "available"),
            (enable(), "enable"),
            (disable(), "disable"),
        ] {
            let (code, err) = run_as(1000, cmd);
            assert_eq!(code, 1);
            assert_eq!(
                err,
                format!(
                    "maknae: maknae tools {sub} must run as root: run `sudo maknae tools {sub}`\n"
                )
            );
        }
    }

    #[test]
    fn run_reports_a_refusal_as_exit_one() {
        let (code, err) = run_as(
            0,
            ToolsCommand::Enable {
                program: "Bad Name".into(),
                image: "i".into(),
                shapes: None,
                entry: None,
                no_reload: true,
            },
        );
        assert_eq!(code, 1);
        assert!(err.starts_with("maknae: "), "{err}");
    }

    #[test]
    fn finish_maps_success_and_failure() {
        let mut err = Vec::new();
        assert_eq!(finish_run(Ok(()), &mut err), 0);
        assert!(err.is_empty());
        assert_eq!(finish_run(Err("bad\x1b[31m".into()), &mut err), 1);
        let text = String::from_utf8(err).unwrap();
        assert!(text.starts_with("maknae: bad"), "{text}");
        assert!(!text.contains('\x1b'), "{text:?}");
    }

    #[test]
    fn reload_call_names_each_platform_command() {
        assert_eq!(
            reload_call(Platform::Linux),
            (Program::Systemctl, vec!["reload".into(), "maknaed".into()])
        );
        assert_eq!(
            reload_call(Platform::Macos),
            (
                Program::Launchctl,
                vec![
                    "kill".into(),
                    "SIGHUP".into(),
                    "system/io.maknae.maknaed".into()
                ]
            )
        );
    }

    #[test]
    fn host_reload_runs_the_host_call_and_reports_stderr() {
        let ok = spawn(Ok(ran(true, "")));
        assert_eq!(HostReload(&ok).reload(), Ok(()));
        let (program, args) = reload_call(Platform::HOST);
        assert_eq!(*ok.ran.borrow(), vec![(program, args)]);

        let failed = spawn(Ok(ran(false, "Unit maknaed.service not loaded.")));
        assert_eq!(
            HostReload(&failed).reload(),
            Err("Unit maknaed.service not loaded.".to_string())
        );

        for stderr in ["", " \n"] {
            let silent = spawn(Ok(ran(false, stderr)));
            assert_eq!(
                HostReload(&silent).reload(),
                Err("the reload exited with status 1".to_string())
            );
        }
        let signalled = spawn(Ok(Ran {
            code: None,
            ..ran(false, "")
        }));
        assert_eq!(
            HostReload(&signalled).reload(),
            Err("the reload was ended by a signal".to_string())
        );

        let missing = spawn(Err("/usr/bin/systemctl not found".into()));
        assert_eq!(
            HostReload(&missing).reload(),
            Err("/usr/bin/systemctl not found".to_string())
        );
    }

    #[test]
    fn production_paths_and_owners_are_the_installed_ones() {
        let p = production_paths();
        assert_eq!(p.config, Path::new("/etc/maknae"));
        assert_eq!(p.vendor_grammars, Path::new(VENDOR_GRAMMAR_DIR));
        assert_eq!(p.vendor_templates, Path::new(VENDOR_TOOLS_DIR));
        let o = production_owners(77);
        assert_eq!(o.dir, 0);
        assert_eq!(o.file.uid, 0);
        assert_eq!(o.file.gid, 77);
    }

    fn enable_cmd(no_reload: bool) -> ToolsCommand {
        ToolsCommand::Enable {
            program: "gh".into(),
            image: img(),
            shapes: None,
            entry: None,
            no_reload,
        }
    }

    #[test]
    fn dispatch_reloads_unless_no_reload() {
        for (no_reload, calls) in [(true, 0), (false, 1)] {
            let fx = Fx::new();
            let r = FakeReload::ok();
            let mut out = Vec::new();
            dispatch(enable_cmd(no_reload), &fx.paths(), &me(), &r, &mut out).unwrap();
            assert_eq!(r.calls.get(), calls, "enable no_reload={no_reload}");

            let r = FakeReload::ok();
            let cmd = ToolsCommand::Disable {
                entry: "github-post".into(),
                no_reload,
            };
            dispatch(cmd, &fx.paths(), &me(), &r, &mut out).unwrap();
            assert_eq!(r.calls.get(), calls, "disable no_reload={no_reload}");
        }
    }

    #[test]
    fn dispatch_available_lists_the_grammars() {
        let fx = Fx::new();
        let mut out = Vec::new();
        dispatch(
            ToolsCommand::Available,
            &fx.paths(),
            &me(),
            &FakeReload::ok(),
            &mut out,
        )
        .unwrap();
        assert_eq!(String::from_utf8(out).unwrap(), fx.available());
    }
}
