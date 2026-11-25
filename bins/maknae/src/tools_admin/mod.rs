mod template;

use crate::cli::terminal_safe;
use crate::policy_sync::RELOAD;
use maknae_config::{
    defined_names, grammar_uses, tool_entry_name_ok, tool_program_name_ok, Grammar, GRAMMARS_DIR,
    TOOLS_DROPIN_DIR, TOOLS_FILE,
};
use maknae_io::{
    open_anchor, Anchor, AnchorLock, AnchorRequired, Entry, FileOwner, IoError, IoKind, Kind,
    MemberState, Mode, StrategyPref, TargetRequired,
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

pub(crate) trait DropinDir {
    fn publish_new(&self, name: &str, bytes: &[u8]) -> Result<bool, DirError>;
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

fn dir_error(e: IoError) -> DirError {
    match &e {
        IoError::PublishedNotDurable { .. } | IoError::RemovedNotDurable { .. } => {
            DirError::DoneNotDurable(e.to_string())
        }
        other => DirError::NotDone(other.to_string()),
    }
}

fn removal(anchor: &Anchor, name: &str) -> Result<(), DirError> {
    anchor
        .remove_durable(Path::new(name), None)
        .map(|_| ())
        .map_err(dir_error)
}

impl DropinDir for AnchoredDir<'_> {
    fn publish_new(&self, name: &str, bytes: &[u8]) -> Result<bool, DirError> {
        self.anchor
            .publish_owned_new(Path::new(name), None, bytes, Mode(0o640), self.owner)
            .map(|o| o.value)
            .map_err(dir_error)
    }

    fn remove(&self, name: &str) -> Result<(), DirError> {
        removal(self.anchor, name)
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

fn collision_error(hits: &[(&Found, Vec<String>)], link: &Link) -> String {
    let mut lines = Vec::new();
    for (found, names) in hits {
        let names: Vec<String> = names.iter().map(|n| format!("`{n}`")).collect();
        lines.push(format!(
            "{} already defined in {}",
            names.join(", "),
            found.file
        ));
        lines.push(match &found.stem {
            Some(stem) => format!(
                "to replace {}, disable it first: sudo maknae tools disable {stem}",
                found.file
            ),
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

fn rollback(
    d: &Dirs,
    p: &Paths,
    link: &Link,
    dir: &dyn DropinDir,
    written: &[String],
    cause: String,
) -> String {
    let mut problems = vec![cause];
    for file in written.iter().rev() {
        problems.extend(undone(dir.remove(file), &dropin_path(p, file)));
    }
    if link.before == MemberState::Absent {
        match d
            .grammars
            .enabled_member_state(&link.name, &p.vendor_grammars)
        {
            Ok(MemberState::VendorLink) => {
                problems.extend(undone(removal(&d.grammars, &link.name), &link.path));
            }
            Ok(
                MemberState::Absent
                | MemberState::LocalFile
                | MemberState::ForeignLink(_)
                | MemberState::Other,
            ) => {}
            Err(e) => problems.push(format!("cannot inspect {}: {e}", link.path.display())),
        }
    }
    terminal_safe(&problems.join("; "))
}

fn finish(
    done: &[String],
    reload: bool,
    r: &dyn Reload,
    out: &mut dyn Write,
) -> Result<(), String> {
    if !reload {
        return say(out, RELOAD);
    }
    r.reload().map_err(|cause| {
        terminal_safe(&format!(
            "{}; maknaed was not reloaded: {cause}; {RELOAD}",
            done.join("; ")
        ))
    })?;
    say(out, "reloaded maknaed")
}

fn dropin_path(p: &Paths, file: &str) -> PathBuf {
    p.config.join(TOOLS_DROPIN_DIR).join(file)
}

#[allow(dead_code)]
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

#[allow(dead_code)]
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
    enable_with(p, o, &d, req, r, out, &dir)
}

fn enable_with(
    p: &Paths,
    o: &Owners,
    d: &Dirs,
    req: &Enable,
    r: &dyn Reload,
    out: &mut dyn Write,
    dir: &dyn DropinDir,
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
        return Err(collision_error(&hits, &link));
    }
    match &link.before {
        MemberState::Absent | MemberState::VendorLink => {}
        MemberState::LocalFile | MemberState::ForeignLink(_) | MemberState::Other => {
            return Err(terminal_safe(&refusal(&link.path, &link.before)))
        }
    }

    let mut done = Vec::new();
    let created = d
        .grammars
        .link_member(&link.name, &p.vendor_grammars)
        .map_err(|e| {
            let cause = format!("cannot link {}: {e}", link.path.display());
            rollback(d, p, &link, dir, &[], cause)
        })?
        .value;
    if created {
        done.push(format!(
            "linked {} to {}",
            link.path.display(),
            link.vendor.display()
        ));
    }
    let mut written = Vec::new();
    for dropin in &dropins {
        let file = format!("{}.yaml", dropin.entry);
        let path = dropin_path(p, &file);
        let failure = match dir.publish_new(&file, dropin.text.as_bytes()) {
            Ok(true) => None,
            Ok(false) => Some(format!(
                "{} already exists; enable never replaces a drop-in",
                path.display()
            )),
            Err(DirError::NotDone(e)) => Some(format!("cannot write {}: {e}", path.display())),
            Err(DirError::DoneNotDurable(e)) => {
                written.push(file.clone());
                Some(format!("wrote {}, but not durably: {e}", path.display()))
            }
        };
        if let Some(cause) = failure {
            return Err(rollback(d, p, &link, dir, &written, cause));
        }
        written.push(file);
    }

    if created {
        say(out, &done[0])?;
    }
    for dropin in &dropins {
        let wrote = format!(
            "wrote {}",
            dropin_path(p, &format!("{}.yaml", dropin.entry)).display()
        );
        say(out, &wrote)?;
        done.push(wrote);
        say(out, GRANT_HEADER)?;
        for grant in &dropin.grants {
            say(out, &format!("  {grant}"))?;
        }
        for (class, app) in &dropin.apps {
            say(
                out,
                &format!("credential class {class} expects the App {app} in the Egress Daemon's configuration"),
            )?;
        }
    }
    finish(&done, req.reload, r, out)
}

#[allow(dead_code)]
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
    disable_with(p, o, &d, entry, reload, r, out, &dir)
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
) -> Result<(), String> {
    let _lock = lock(&d.tools)?;
    let file = format!("{entry}.yaml");
    let path = dropin_path(p, &file);
    let text = read_text(
        &d.tools,
        Path::new(&file),
        required(o.file.uid, 0o027),
        &path,
    )?
    .ok_or_else(|| terminal_safe(&format!("no drop-in {}", path.display())))?;
    let others: Vec<Found> = configured(p, o, d)?
        .into_iter()
        .filter(|f| f.stem.as_deref() != Some(entry))
        .collect();
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

    let mut pending = Vec::new();
    match dir.remove(&file) {
        Ok(()) => {}
        Err(DirError::DoneNotDurable(e)) => pending.push(e),
        Err(DirError::NotDone(e)) => {
            return Err(terminal_safe(&format!(
                "cannot remove {}: {e}",
                path.display()
            )))
        }
    }
    let mut done = vec![format!("removed {}", path.display())];
    for (name, link) in unlink {
        match removal(&d.grammars, &name) {
            Ok(()) => {}
            Err(DirError::DoneNotDurable(e)) => pending.push(e),
            Err(DirError::NotDone(e)) => {
                return Err(terminal_safe(&format!(
                    "{}; cannot remove {}: {e}",
                    done.join("; "),
                    link.display()
                )))
            }
        }
        done.push(format!("removed {}", link.display()));
    }
    for line in &done {
        say(out, line)?;
    }
    let reloaded = finish(&done, reload, r, out);
    if pending.is_empty() {
        return reloaded;
    }
    let mut problems: Vec<String> = reloaded.err().into_iter().collect();
    problems.push(format!(
        "the removal is not yet durable: {}",
        pending.join("; ")
    ));
    Err(terminal_safe(&problems.join("; ")))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::policy_sync::RELOAD;
    use maknae_config::{GrammarSet, ToolsCatalog};
    use std::cell::Cell;
    use std::os::unix::fs::PermissionsExt;
    use std::sync::atomic::{AtomicUsize, Ordering};

    const TEMPLATE: &str = include_str!("../../../../packaging/common/tools.d/gh.yaml");
    const GRAMMAR: &str = include_str!("../../../../packaging/common/grammars/gh.yaml");
    const HOMELAB: &str = include_str!("../../../../packaging/common/tools-homelab.yaml");
    const SITE: &str = include_str!("../testdata/dropin_site_github_post.yaml");
    const OTHER: &str = include_str!("../testdata/dropin_other_name.yaml");

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
        assert!(out.contains("reloaded maknaed"), "{out}");
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
        third_publish: Fail,
        removes: Fail,
        before_failing: &'a dyn Fn(),
    }

    fn fail<T>(how: Fail, done: impl FnOnce() -> Result<T, DirError>) -> Result<T, DirError> {
        match how {
            Fail::Never => done(),
            Fail::NotDone => Err(DirError::NotDone("disk full".to_string())),
            Fail::DoneNotDurable => {
                done()?;
                Err(DirError::DoneNotDurable("sync failed".to_string()))
            }
        }
    }

    impl DropinDir for Failing<'_> {
        fn publish_new(&self, name: &str, bytes: &[u8]) -> Result<bool, DirError> {
            self.calls.set(self.calls.get() + 1);
            if self.calls.get() != 3 {
                return self.inner.publish_new(name, bytes);
            }
            (self.before_failing)();
            fail(self.third_publish, || self.inner.publish_new(name, bytes))
        }

        fn remove(&self, name: &str) -> Result<(), DirError> {
            fail(self.removes, || self.inner.remove(name))
        }
    }

    fn enable_failing(
        fx: &Fx,
        third_publish: Fail,
        removes: Fail,
        before_failing: &dyn Fn(),
    ) -> (String, u32) {
        let o = me();
        let p = fx.paths();
        let dirs = Dirs::open(&p, &o).unwrap();
        let inner = AnchoredDir {
            anchor: &dirs.tools,
            owner: o.file,
        };
        let failing = Failing {
            inner: &inner,
            calls: Cell::new(0),
            third_publish,
            removes,
            before_failing,
        };
        let r = FakeReload::ok();
        let mut out = Vec::new();
        let e = err(enable_with(
            &p,
            &o,
            &dirs,
            &req(None, None),
            &r,
            &mut out,
            &failing,
        ));
        assert!(out.is_empty(), "{}", String::from_utf8_lossy(&out));
        (e, r.calls.get())
    }

    fn enable_failing_third(fx: &Fx, before_failing: &dyn Fn()) -> (String, u32) {
        enable_failing(fx, Fail::NotDone, Fail::Never, before_failing)
    }

    fn disable_failing(
        fx: &Fx,
        entry: &str,
        removes: Fail,
        r: &FakeReload,
    ) -> (Result<(), String>, String) {
        let o = me();
        let p = fx.paths();
        let dirs = Dirs::open(&p, &o).unwrap();
        let inner = AnchoredDir {
            anchor: &dirs.tools,
            owner: o.file,
        };
        let failing = Failing {
            inner: &inner,
            calls: Cell::new(0),
            third_publish: Fail::Never,
            removes,
            before_failing: &|| {},
        };
        let mut out = Vec::new();
        let result = disable_with(&p, &o, &dirs, entry, true, r, &mut out, &failing);
        (result, String::from_utf8(out).unwrap())
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
        assert!(
            e.contains("the removal is not yet durable: sync failed"),
            "{e}"
        );
        assert_eq!(fx.link(), None);
        assert!(fx.dropins().is_empty());
        assert_eq!(r.calls.get(), 1);
        assert!(
            out.contains(&format!(
                "removed {}",
                fx.grammars().join("gh.yaml").display()
            )),
            "{out}"
        );

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
    fn only_the_not_durable_errors_count_as_done() {
        let path = PathBuf::from("/x");
        let kind = IoKind::Other { raw: 5 };
        for e in [
            IoError::PublishedNotDurable {
                path: path.clone(),
                kind: kind.clone(),
            },
            IoError::RemovedNotDurable {
                path: path.clone(),
                kind: kind.clone(),
            },
        ] {
            assert!(matches!(dir_error(e), DirError::DoneNotDurable(_)));
        }
        let not_done = dir_error(IoError::Io {
            kind: IoKind::NotFound,
            path,
        });
        assert!(matches!(not_done, DirError::NotDone(_)));
    }

    #[test]
    fn enable_refuses_a_name_tools_yaml_defines_even_if_the_loader_disables_it() {
        let fx = Fx::new();
        write(
            &fx.config().join("tools.yaml"),
            "schema_version: 1\ntools:\n  github-read:\n    enabled: true\n",
            0o640,
        );
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
        let (e, _) = enable_failing_third(&fx, &swap);
        assert!(e.contains("disk full"), "{e}");
        assert!(fx.dropins().is_empty(), "{:?}", fx.dropins());
        assert_eq!(std::fs::read_to_string(&grammar).unwrap(), GRAMMAR);
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
        assert!(e.contains("`github-post`"), "{e}");
        assert!(e.contains("tools.d/site.yaml"), "{e}");
        assert!(e.contains("sudo maknae tools disable site"), "{e}");
        assert!(!e.contains("`github-read`"), "{e}");
        assert!(!e.contains("ln -s"), "{e}");
        assert_eq!(fx.link(), None);
        assert_eq!(fx.dropins(), ["site.yaml"]);
        assert_eq!(r.calls.get(), 0);

        let tool_only = SITE.replace("site-post:", "github-read:");
        let tool_only = tool_only.replace("  github-post:\n    kind", "  site-class:\n    kind");
        write(&fx.tools().join("site.yaml"), &tool_only, 0o640);
        let e = err(fx.enable(&req(None, None), &r).0);
        assert!(e.contains("`github-read`"), "{e}");
        assert!(!e.contains("`github-post`"), "{e}");
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
        assert!(!out.contains("reloaded maknaed"), "{out}");

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
        assert!(out.contains("reloaded maknaed"), "{out}");
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
}
