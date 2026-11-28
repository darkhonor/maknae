#![cfg(test)]

use crate::cli::ToolsCommand;
use crate::enroll::{Ran, Run};
use crate::tools_admin::available::available;
use crate::tools_admin::dirs::{AnchoredDir, DirError, Dirs, DropinDir, WriteError};
use crate::tools_admin::disable::{disable, disable_with};
use crate::tools_admin::enable::{enable, enable_with, Enable};
use crate::tools_admin::{run_with, Owners, Paths, Reload};
use maknae_config::{Grammar, GrammarSet};
use maknae_io::program::Program;
use maknae_io::{open_anchor, AnchorRequired, EntryId, FileOwner, StrategyPref};
use std::cell::{Cell, RefCell};
use std::io::Write;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};

pub(super) const TEMPLATE: &str = include_str!("../../../../packaging/common/tools.d/gh.yaml");

pub(super) const GRAMMAR: &str = include_str!("../../../../packaging/common/grammars/gh.yaml");

pub(super) const HOMELAB: &str = include_str!("../../../../packaging/common/tools-homelab.yaml");

pub(super) const SITE: &str = include_str!("../testdata/dropin_site_github_post.yaml");

pub(super) const OTHER: &str = include_str!("../testdata/dropin_other_name.yaml");

pub(super) const GITHUB_READ_ONLY: &str = include_str!("../testdata/tools_github_read_only.yaml");

pub(super) const NAMES: [&str; 4] = [
    "github-issues-read",
    "github-issues-write",
    "github-post",
    "github-read",
];

pub(super) struct FakeReload {
    pub(super) calls: Cell<u32>,
    fail: bool,
}

impl FakeReload {
    pub(super) fn ok() -> Self {
        FakeReload {
            calls: Cell::new(0),
            fail: false,
        }
    }

    pub(super) fn failing() -> Self {
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

pub(super) struct Fx(pub(super) PathBuf);

pub(super) fn me() -> Owners {
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

pub(super) fn req(entry: Option<&str>, shapes: Option<&[&str]>) -> Enable {
    Enable {
        program: "gh".to_string(),
        image: img(),
        shapes: shapes.map(|s| s.iter().map(|x| x.to_string()).collect()),
        entry: entry.map(str::to_string),
        reload: true,
    }
}

pub(super) fn write(path: &Path, body: &str, mode: u32) {
    std::fs::write(path, body).unwrap();
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode)).unwrap();
}

fn mkdir(path: &Path, mode: u32) {
    std::fs::create_dir(path).unwrap();
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode)).unwrap();
}

pub(super) fn set() -> GrammarSet {
    let mut set = GrammarSet::empty();
    set.grammars
        .insert("gh".to_string(), Grammar::parse("gh", GRAMMAR).unwrap());
    set
}

impl Fx {
    pub(super) fn new() -> Self {
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

    pub(super) fn config(&self) -> PathBuf {
        self.0.join("config")
    }

    pub(super) fn grammars(&self) -> PathBuf {
        self.config().join("grammars")
    }

    pub(super) fn tools(&self) -> PathBuf {
        self.config().join("tools.d")
    }

    pub(super) fn vendor_grammars(&self) -> PathBuf {
        self.0.join("vendor").join("grammars")
    }

    pub(super) fn vendor_templates(&self) -> PathBuf {
        self.0.join("vendor").join("tools.d")
    }

    pub(super) fn paths(&self) -> Paths {
        Paths {
            config: self.config(),
            vendor_grammars: self.vendor_grammars(),
            vendor_templates: self.vendor_templates(),
        }
    }

    pub(super) fn enable(&self, req: &Enable, r: &FakeReload) -> (Result<(), String>, String) {
        let mut out = Vec::new();
        let result = enable(&self.paths(), &me(), req, r, &mut out);
        (result, String::from_utf8(out).unwrap())
    }

    pub(super) fn disable(&self, entry: &str, r: &FakeReload) -> (Result<(), String>, String) {
        let mut out = Vec::new();
        let result = disable(&self.paths(), &me(), entry, true, r, &mut out);
        (result, String::from_utf8(out).unwrap())
    }

    pub(super) fn available(&self) -> String {
        let mut out = Vec::new();
        available(&self.paths(), &me(), &mut out).unwrap();
        String::from_utf8(out).unwrap()
    }

    pub(super) fn enabled(&self) {
        self.enable(&req(None, None), &FakeReload::ok()).0.unwrap();
    }

    pub(super) fn enabled_one(&self, entry: &str) {
        self.enable(&req(Some(entry), None), &FakeReload::ok())
            .0
            .unwrap();
    }

    pub(super) fn dropins(&self) -> Vec<String> {
        let mut names: Vec<String> = std::fs::read_dir(self.tools())
            .unwrap()
            .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
            .collect();
        names.sort();
        names
    }

    pub(super) fn link(&self) -> Option<PathBuf> {
        std::fs::read_link(self.grammars().join("gh.yaml")).ok()
    }

    pub(super) fn exact(&self) -> Option<PathBuf> {
        Some(self.vendor_grammars().join("gh.yaml"))
    }

    pub(super) fn link_exactly(&self) {
        std::os::unix::fs::symlink(
            self.vendor_grammars().join("gh.yaml"),
            self.grammars().join("gh.yaml"),
        )
        .unwrap();
    }

    pub(super) fn locked(&self) -> maknae_io::AnchorLock {
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

pub(super) fn err(result: Result<(), String>) -> String {
    match result {
        Ok(()) => panic!("expected an error"),
        Err(e) => e,
    }
}

pub(super) fn yamls(names: &[&str]) -> Vec<String> {
    let mut v: Vec<String> = names.iter().map(|n| format!("{n}.yaml")).collect();
    v.sort();
    v
}

#[derive(Clone, Copy)]
pub(super) enum Fail {
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
pub(super) struct Plan<'p> {
    pub(super) third_publish: Fail,
    pub(super) removes: Fail,
    pub(super) links: Fail,
    pub(super) link_removes: Fail,
    pub(super) before_failing: &'p dyn Fn(),
    pub(super) after_link: &'p dyn Fn(),
    pub(super) before_recheck: &'p dyn Fn(),
}

pub(super) fn plan() -> Plan<'static> {
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

pub(super) fn enable_run(
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

pub(super) fn enable_failing(
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

pub(super) fn enable_failing_third(fx: &Fx, before_failing: &dyn Fn()) -> (String, u32) {
    enable_failing(fx, Fail::NotDone, Fail::Never, before_failing)
}

pub(super) fn disable_run(
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

pub(super) fn disable_failing(
    fx: &Fx,
    entry: &str,
    removes: Fail,
    r: &FakeReload,
) -> (Result<(), String>, String) {
    disable_run(fx, entry, r, Plan { removes, ..plan() })
}

pub(super) struct Broken;

impl Write for Broken {
    fn write(&mut self, _: &[u8]) -> std::io::Result<usize> {
        Err(std::io::ErrorKind::BrokenPipe.into())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

pub(super) fn rewrite_in_place(path: &Path, body: &str) {
    use std::io::Write as _;
    let mut f = std::fs::OpenOptions::new()
        .write(true)
        .truncate(true)
        .open(path)
        .unwrap();
    f.write_all(body.as_bytes()).unwrap();
}

pub(super) struct Spawn {
    pub(super) ran: std::cell::RefCell<Vec<(Program, Vec<String>)>>,
    reply: Result<Ran, String>,
}

impl Run for Spawn {
    fn run(&self, program: Program, args: &[String]) -> Result<Ran, String> {
        self.ran.borrow_mut().push((program, args.to_vec()));
        self.reply.clone()
    }
}

pub(super) fn spawn(reply: Result<Ran, String>) -> Spawn {
    Spawn {
        ran: Default::default(),
        reply,
    }
}

pub(super) fn ran(ok: bool, stderr: &str) -> Ran {
    Ran {
        ok,
        code: Some(if ok { 0 } else { 1 }),
        stdout: String::new(),
        stderr: stderr.into(),
    }
}

pub(super) fn run_as(euid: u32, cmd: ToolsCommand) -> (u8, String) {
    let (mut out, mut err) = (Vec::new(), Vec::new());
    let code = run_with(euid, cmd, &mut out, &mut err);
    (code, String::from_utf8(err).unwrap())
}

pub(super) fn enable_cmd(no_reload: bool) -> ToolsCommand {
    ToolsCommand::Enable {
        program: "gh".into(),
        image: img(),
        shapes: None,
        entry: None,
        no_reload,
    }
}
