//! Test-only fixtures shared by the kernel's module test suites.
#![cfg(test)]

use crate::baseline_check::Env;
use maknae_authz_basic::HermeticAuthorizer;
use maknae_config::{
    BaselineSections, BasicPolicy, Ceiling, ClassificationPolicy, Document, Principal,
    ReaderAccount, ReaderLookup,
};
use maknae_security::{Action, AttrValue, Attributes, Context, Request, Resource, Subject};
use std::path::{Path, PathBuf};
use std::sync::Mutex;

const US: &BasicPolicy = &BasicPolicy;

pub(crate) struct FakeEnv {
    pub(crate) bounds: Option<maknae_config::EgressBounds>,
    pub(crate) egress_uid: Result<Option<u32>, String>,
    pub(crate) prepared: Result<(), String>,
    pub(crate) bindable: Result<(), String>,
    pub(crate) reachable: Result<(), String>,
    pub(crate) accounts: Vec<ReaderAccount>,
    pub(crate) probed: Mutex<Vec<String>>,
    pub(crate) present: Vec<PathBuf>,
    pub(crate) unreadable: Vec<PathBuf>,
    pub(crate) vars: Vec<(String, String)>,
}

impl Default for FakeEnv {
    fn default() -> Self {
        FakeEnv {
            bounds: None,
            egress_uid: Ok(Some(981)),
            prepared: Ok(()),
            bindable: Ok(()),
            reachable: Ok(()),
            accounts: Vec::new(),
            probed: Mutex::new(Vec::new()),
            present: vec![crate::deployment::SYSTEMD_RUNNING.into()],
            unreadable: Vec::new(),
            vars: Vec::new(),
        }
    }
}

impl FakeEnv {
    pub(crate) fn with_bounds() -> Self {
        FakeEnv {
            bounds: Some(maknae_config::EgressBounds {
                call_timeout_ms: maknae_config::DEFAULT_CALL_TIMEOUT_MS,
                kv_mount: "kv".into(),
                user_prefix: "users".into(),
                agent_prefix: None,
                vault_addr: "https://v:8200".into(),
            }),
            ..FakeEnv::default()
        }
    }
    pub(crate) fn probed(&self) -> Vec<String> {
        self.probed.lock().unwrap().clone()
    }
}

impl ReaderLookup for FakeEnv {
    fn account(&self, name: &str) -> Result<Option<ReaderAccount>, String> {
        Ok(self.accounts.iter().find(|a| a.name == name).cloned())
    }
    fn daemon_gid(&self) -> Result<Option<u32>, String> {
        Ok(Some(970))
    }
    fn service_uids(&self) -> Result<Vec<u32>, String> {
        Ok(vec![970, 981])
    }
}

impl Env for FakeEnv {
    fn egress_bounds(&self) -> Result<maknae_config::EgressBounds, maknae_config::ConfigError> {
        self.bounds
            .clone()
            .ok_or_else(|| maknae_config::ConfigError::NotFound {
                path: maknae_config::EGRESS_BOUNDS_FILE.into(),
            })
    }
    fn egress_account(&self) -> Result<Option<u32>, String> {
        self.egress_uid.clone()
    }
    fn trail_prepared(&self, path: &Path) -> Result<(), String> {
        self.probed
            .lock()
            .unwrap()
            .push(format!("prepared {}", path.display()));
        self.prepared.clone()
    }
    fn listener_bindable(&self, path: &Path) -> Result<(), String> {
        self.probed
            .lock()
            .unwrap()
            .push(format!("bind {}", path.display()));
        self.bindable.clone()
    }
    fn deputy_reachable(&self, path: &Path) -> Result<(), String> {
        self.probed
            .lock()
            .unwrap()
            .push(format!("connect {}", path.display()));
        self.reachable.clone()
    }
    fn presence(&self, path: &Path) -> Result<bool, String> {
        if self.unreadable.iter().any(|p| p == path) {
            return Err("Permission denied (os error 13)".into());
        }
        Ok(self.present.iter().any(|p| p == path))
    }
    fn env_var(&self, key: &str) -> Option<String> {
        self.vars
            .iter()
            .find(|(k, _)| k == key)
            .map(|(_, v)| v.clone())
    }
}

pub(crate) fn doc(pairs: &[(&str, &str)]) -> Document {
    let s: BaselineSections = pairs
        .iter()
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect();
    Document::from_baseline(&s).unwrap()
}
const AUDIT: &str = r#"{"jsonl_path":"/var/log/maknae/audit.jsonl"}"#;
const PRINCIPAL: &str = r#"{"name":"op","uid":1000}"#;
pub(crate) const PROVIDERS: &str =
    r#"[{"endpoint":"https://api.example.test/v1","models":["m"],"name":"openai"}]"#;
const VAULT: &str = r#"{"addr":"https://v:8200"}"#;
/// The `deployment` section this build's own host mode passes with.
pub(crate) const DEPLOYMENT: &str = if cfg!(target_os = "macos") {
    r#"{"mode":"macos-host"}"#
} else {
    r#"{"mode":"linux-host"}"#
};
pub(crate) fn write_sensitive(dir: &Path, body: &str) {
    use std::os::unix::fs::PermissionsExt;
    let p = dir.join(maknae_config::SENSITIVE_FILE);
    std::fs::write(&p, body).unwrap();
    std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o640)).unwrap();
}

pub(crate) fn write_tools(dir: &Path, body: &str) {
    use std::os::unix::fs::PermissionsExt;
    let p = dir.join(maknae_config::TOOLS_FILE);
    std::fs::write(&p, body).unwrap();
    std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o640)).unwrap();
}

/// The vendor grammar directory inside a [`fixture`]'s config dir.
pub(crate) const VENDOR_DIR: &str = "vendor";

fn policy_subdir(dir: &Path, name: &str, mode: u32) -> PathBuf {
    use std::os::unix::fs::PermissionsExt;
    let sub = dir.join(name);
    if !sub.exists() {
        std::fs::create_dir(&sub).unwrap();
        std::fs::set_permissions(&sub, std::fs::Permissions::from_mode(mode)).unwrap();
    }
    sub
}

/// `<dir>/grammars/<name>`, a site's own grammar file.
pub(crate) fn write_grammar(dir: &Path, name: &str, text: &str) {
    write_0640(
        &policy_subdir(dir, maknae_config::GRAMMARS_DIR, 0o750).join(name),
        text,
    );
}

/// Enables `<vendor_dir>/<name>` with a link in `<config_dir>/grammars/`.
pub(crate) fn link_grammar(config_dir: &Path, vendor_dir: &Path, name: &str) {
    std::os::unix::fs::symlink(
        vendor_dir.join(name),
        policy_subdir(config_dir, maknae_config::GRAMMARS_DIR, 0o750).join(name),
    )
    .unwrap();
}

pub(crate) fn write_shipped_gh_grammar(dir: &Path) {
    write_grammar(
        dir,
        "gh.yaml",
        include_str!("../../../packaging/common/grammars/gh.yaml"),
    );
}

pub(crate) fn write_tools_dropin(dir: &Path, name: &str, text: &str) {
    write_0640(
        &policy_subdir(dir, maknae_config::TOOLS_DROPIN_DIR, 0o750).join(name),
        text,
    );
}

pub(crate) fn write_empty_sensitive(dir: &Path) {
    write_sensitive(dir, "schema_version: 1\nsensitive: []\n");
}

pub(crate) const DEPLOYMENT_YAML: &str = if cfg!(target_os = "macos") {
    "deployment:\n  mode: macos-host\n"
} else {
    "deployment:\n  mode: linux-host\n"
};
pub(crate) fn minimal() -> Vec<(&'static str, &'static str)> {
    vec![
        ("core", r#"{"deployment_id":"d"}"#),
        ("audit", AUDIT),
        ("principal", PRINCIPAL),
        ("vault", VAULT),
        ("deployment", DEPLOYMENT),
    ]
}

/// A real `-basic` through the hermetic door: the production load, compile
/// and decide sequence, with only the loader's ownership requirement
/// relaxed so an unprivileged test can construct it.
pub(crate) struct DirGuard(pub(crate) PathBuf);

impl Drop for DirGuard {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// Returns the guard SEPARATELY from the authorizer so the authorizer can
/// be moved into a `Composition` while the guard still owns the cleanup.
/// Mirrors `tests/enforce_loop.rs`'s `Fixture`: a CANONICAL 0700 home
/// (#216 -- `$TMPDIR` is under the `/var` symlink on macOS), the enrolled
/// principal IS the test euid, and bindings name `root` so the enrolled-
/// principal default role resolution is what grants (boot_gate.rs).
pub(crate) fn fixture(
    tag: &str,
    policy: &str,
    bindings: Option<&str>,
) -> (DirGuard, HermeticAuthorizer) {
    use std::os::unix::fs::PermissionsExt;
    let dir = std::env::temp_dir().join(format!("maknae_composition_{tag}_{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700)).unwrap();
    let dir = dir.canonicalize().expect("canonicalize the fixture home");
    let paths =
        maknae_authz_basic::PolicyPaths::in_dir(&dir).with_grammar_vendor(dir.join(VENDOR_DIR));
    for (path, body) in [(&paths.authz, Some(policy)), (&paths.bindings, bindings)] {
        let Some(body) = body else { continue };
        std::fs::write(path, body).unwrap();
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o640)).unwrap();
    }
    write_empty_sensitive(&dir);
    let principal = Principal {
        name: "operator".into(),
        uid: nix::unistd::geteuid().as_raw(),
    };
    let req = maknae_config::TargetRequired {
        owner: None,
        mode_mask: Some(0o022),
        nlink_exactly_one: false,
        regular_file: true,
        max_bytes: None,
    };
    let basic = HermeticAuthorizer::new(paths, principal, req, maknae_crypto::sha256)
        .expect("fixture constructs");
    (DirGuard(dir), basic)
}

pub(crate) fn secret() -> Ceiling {
    let mut c = Ceiling::baseline_for(US);
    c.classification = US.level_of("SECRET").unwrap();
    c
}

/// The same read, with a classification MARKING stamped the way a future
/// labeler would (trust-plane side, never client-supplied).
pub(crate) fn permitted_read_marked(home: &std::path::Path, marking: Option<&str>) -> Request {
    let mut subject = Attributes::new();
    subject.insert(
        "uid",
        AttrValue::Int(i64::from(nix::unistd::geteuid().as_raw())),
    );
    subject.insert(
        maknae_security::SUBJECT_HOME,
        AttrValue::Str(home.display().to_string()),
    );
    subject.insert(
        maknae_security::SUBJECT_CHANNEL,
        AttrValue::Str(maknae_security::CHANNEL_CLIENT.into()),
    );
    let mut resource = Attributes::new();
    resource.insert(
        "path",
        AttrValue::Str(home.join("notes.txt").display().to_string()),
    );
    if let Some(m) = marking {
        resource.insert(
            maknae_security::RESOURCE_CLASSIFICATION,
            AttrValue::Str(m.into()),
        );
    }
    let mut context = Attributes::new();
    context.insert(
        maknae_security::CONTEXT_DAC_LANE,
        AttrValue::Str(maknae_security::Lane::Local.as_str().to_string()),
    );
    context.insert(
        maknae_security::CONTEXT_FS_OPERATION,
        AttrValue::Str("read".into()),
    );
    Request {
        subject: Subject(subject),
        resource: Resource(resource),
        action: Action("fs.read".into()),
        context: Context(context),
    }
}

pub(crate) const READ_POLICY: &str =
    "schema_version: 1\npermissions:\n  allow:\n    - \"Read(~/**)\"\n  deny: []\n";

fn agent_dir(config: &Path, id: &str) -> PathBuf {
    use std::os::unix::fs::PermissionsExt;
    let agents = config.join(maknae_config::AGENTS_DIR);
    let dir = agents.join(id);
    std::fs::create_dir_all(&dir).unwrap();
    for d in [&agents, &dir] {
        std::fs::set_permissions(d, std::fs::Permissions::from_mode(0o750)).unwrap();
    }
    dir
}

pub(crate) fn write_0640(path: &Path, body: &str) {
    use std::os::unix::fs::PermissionsExt;
    std::fs::write(path, body).unwrap();
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o640)).unwrap();
}

/// `<config>/agents/<id>/enrollment.yaml`, as `maknae enroll agent` writes it.
pub(crate) fn write_agent(config: &Path, id: &str, account: &str, uid: u32, role: &str) {
    write_0640(
        &agent_dir(config, id).join(maknae_config::ENROLLMENT_FILE),
        &format!("agent_id: {id}\naccount: {account}\nuid: {uid}\nrole: {role}\n"),
    );
}

pub(crate) fn write_agent_policy(config: &Path, id: &str, yaml: &str) {
    write_0640(
        &agent_dir(config, id).join(maknae_config::POLICY_FILE),
        yaml,
    );
}

/// Host lookups that know one account, `hobi-svc` at uid 2001, no daemons and no groups.
pub(crate) const HOBI_HOSTS: maknae_authz_basic::HostLookups = maknae_authz_basic::HostLookups {
    account: hobi_account,
    daemons: no_daemons,
    group: no_group,
};

fn hobi_account(uid: u32) -> Result<Option<maknae_io::HostAccount>, String> {
    Ok((uid == 2001).then(|| maknae_io::HostAccount {
        uid,
        name: "hobi-svc".into(),
        primary_gid: uid,
        shell: "/usr/sbin/nologin".into(),
        dir: "/var/empty".into(),
        named_groups: Vec::new(),
    }))
}

pub(crate) const BTS_HOSTS: maknae_authz_basic::HostLookups = maknae_authz_basic::HostLookups {
    account: bts_account,
    daemons: no_daemons,
    group: no_group,
};

fn bts_account(uid: u32) -> Result<Option<maknae_io::HostAccount>, String> {
    let name = match uid {
        2001 => "hobi-svc",
        2002 => "jin-svc",
        2003 => "suga-svc",
        2004 => "jimin-svc",
        _ => return Ok(None),
    };
    Ok(Some(maknae_io::HostAccount {
        uid,
        name: name.into(),
        primary_gid: uid,
        shell: "/usr/sbin/nologin".into(),
        dir: "/var/empty".into(),
        named_groups: Vec::new(),
    }))
}

pub(crate) const HOBI_AND_JIN_HOSTS: maknae_authz_basic::HostLookups =
    maknae_authz_basic::HostLookups {
        account: hobi_and_jin_account,
        daemons: no_daemons,
        group: no_group,
    };

fn hobi_and_jin_account(uid: u32) -> Result<Option<maknae_io::HostAccount>, String> {
    if uid != 2002 {
        return hobi_account(uid);
    }
    Ok(Some(maknae_io::HostAccount {
        uid,
        name: "jin-svc".into(),
        primary_gid: uid,
        shell: "/usr/sbin/nologin".into(),
        dir: "/var/empty".into(),
        named_groups: Vec::new(),
    }))
}

fn no_daemons() -> Result<maknae_io::DaemonFacts, String> {
    Ok(maknae_io::DaemonFacts {
        uids: Vec::new(),
        gids: Vec::new(),
    })
}

fn no_group(_: &str) -> Result<Option<u32>, String> {
    Ok(None)
}

/// The de-enrollment act.
pub(crate) fn remove_enrollment(config: &Path, id: &str) {
    std::fs::remove_file(
        config
            .join(maknae_config::AGENTS_DIR)
            .join(id)
            .join(maknae_config::ENROLLMENT_FILE),
    )
    .unwrap();
}

const HOBI_POLICY: &str =
    "schema_version: 1\npermissions:\n  allow: [\"Read(~/**)\", \"Write(~/**)\"]\n";

pub(crate) const AGENTS: &[(&str, u32, Option<&str>)] = &[
    ("hobi", 2001, Some(HOBI_POLICY)),
    ("jin", 2002, None),
    ("suga", 2003, Some(maknae_config::STARTER_POLICY)),
    (
        "jimin",
        2004,
        Some("schema_version: 1\npermissions:\n  allow: [\"Read(~/notes/**)\"]\n"),
    ),
];

pub(crate) fn shipped_composition() -> (
    DirGuard,
    crate::composition::Composition<HermeticAuthorizer>,
) {
    shipped_composition_with("", None)
}

pub(crate) fn shipped_composition_with(
    authz_tail: &str,
    bindings: Option<&str>,
) -> (
    DirGuard,
    crate::composition::Composition<HermeticAuthorizer>,
) {
    use maknae_authz_basic::Baseline;
    use std::sync::atomic::{AtomicUsize, Ordering};
    static NEXT: AtomicUsize = AtomicUsize::new(0);
    let tag = format!("shipped-{}", NEXT.fetch_add(1, Ordering::Relaxed));
    let (g, basic) = fixture(
        &tag,
        &format!(
            "{}{authz_tail}",
            include_str!("../../../packaging/common/authz.yaml")
        ),
        bindings,
    );
    write_sensitive(
        &g.0,
        include_str!("../../../packaging/common/sensitive.yaml"),
    );
    basic.set_hosts(BTS_HOSTS);
    for (id, uid, policy) in AGENTS {
        write_agent(&g.0, id, &format!("{id}-svc"), *uid, "user");
        if let Some(policy) = policy {
            write_agent_policy(&g.0, id, policy);
        }
    }
    basic.install(basic.compile_from_file().unwrap());
    (
        g,
        crate::composition::Composition::with_us_baseline_ceiling(basic),
    )
}

pub(crate) fn build_tool_request(
    stamp: &crate::handler::Stamp<'_>,
    peer_uid: u32,
    home: Option<&std::path::Path>,
    lane: maknae_security::Lane,
    conversation: Option<&crate::conversation::facts::ConversationFacts>,
    call: &maknae_config::ToolCall,
    cited: Option<&crate::task::CitedTask>,
) -> maknae_security::Request {
    let mode = match call.shape {
        Some(_) => maknae_security::TOOL_MODE_SHAPE,
        None => maknae_security::TOOL_MODE_POSITIONAL,
    };
    build_tool_request_in_mode(mode, stamp, peer_uid, home, lane, conversation, call, cited)
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn build_tool_request_in_mode(
    mode: &str,
    stamp: &crate::handler::Stamp<'_>,
    peer_uid: u32,
    home: Option<&std::path::Path>,
    lane: maknae_security::Lane,
    conversation: Option<&crate::conversation::facts::ConversationFacts>,
    call: &maknae_config::ToolCall,
    cited: Option<&crate::task::CitedTask>,
) -> maknae_security::Request {
    use maknae_security::{Action, AttrValue, Attributes, Context, Resource};
    let mut resource = Attributes::new();
    crate::handler::stamp_conversation(&mut resource, conversation);
    resource.insert(
        maknae_security::RESOURCE_TOOL_ENTRY,
        AttrValue::Str(call.entry.clone()),
    );
    resource.insert(
        maknae_security::RESOURCE_TOOL_PROGRAM,
        AttrValue::Str(call.program.clone()),
    );
    resource.insert(
        maknae_security::RESOURCE_TOOL_ARGV,
        AttrValue::List(call.argv.clone()),
    );
    resource.insert(
        maknae_security::RESOURCE_BINDING_KINDS,
        AttrValue::Set(Default::default()),
    );
    resource.insert(
        maknae_security::RESOURCE_TOOL_MODE,
        AttrValue::Str(mode.into()),
    );
    if let Some(shape) = &call.shape {
        resource.insert(
            maknae_security::RESOURCE_TOOL_SHAPE,
            AttrValue::Str(shape.clone()),
        );
    }
    if let Some(cited) = cited {
        crate::handler::stamp_task_bindings(&mut resource, cited);
    }
    maknae_security::Request {
        subject: crate::handler::stamp_subject(peer_uid, home, stamp),
        resource: Resource(resource),
        action: Action("tool.invoke".into()),
        context: Context(crate::handler::lane_context(lane)),
    }
}

/// hobi's `Working` task, tasked by uid 1000 with `bindings`, as the store resolves it.
pub(crate) fn cited_task(bindings: Vec<maknae_proto::Binding>) -> crate::task::CitedTask {
    cited_task_of("hobi", 2001, bindings)
}

/// `agent`'s `Working` task, tasked by uid 1000 with `bindings`.
pub(crate) fn cited_task_of(
    agent: &str,
    agent_uid: u32,
    bindings: Vec<maknae_proto::Binding>,
) -> crate::task::CitedTask {
    use crate::task::TaskObjectForTest;
    let mut task = maknae_proto::TaskObject::for_test(agent, 1000);
    task.bindings = bindings;
    let signed = maknae_proto::SignedTask {
        task,
        signature: maknae_proto::TaskSignature {
            alg: "test".into(),
            leaf: maknae_proto::Bytes::new(vec![1].into()),
            chain: Vec::new(),
            sig: maknae_proto::Bytes::new(vec![2].into()),
        },
    };
    let store = crate::task::TaskStore::new();
    let id = store.insert_for_test(signed, agent_uid).task.task_id;
    store.start_for_test(&id);
    store
        .working(
            &id,
            &maknae_config::AgentId::parse(agent).unwrap(),
            agent_uid,
        )
        .unwrap()
}

pub(crate) const LAUNCH_SITE_POLICY: &str = concat!(
    "schema_version: 1\n",
    "permissions:\n",
    "  allow: [\"Read(/srv/**)\", \"Write(/srv/**)\", \"Tool(github-post gh:pr.review.comment)\", \"Tool(github-read gh:pr.*)\", \"Tool(github-issues-read gh:issue.*)\", \"Tool(github-issues-write gh:issue.edit.title)\", \"Tool(rust-scratch cargo build *)\", \"Tool(rust-build cargo build *)\", \"Tool(open-credential cargo *)\"]\n",
    "  deny: [\"Read(/**/.env)\"]\n",
    "roles:\n",
    "  admin:\n",
    "    allow: [\"session.new\"]\n",
    "    permissions:\n",
    "      allow: [\"Tool(github-post gh:pr.comment)\", \"Tool(rust-scratch cargo test *)\"]\n",
    "      deny: [\"Tool(github-post gh:pr.review.comment)\", \"Tool(rust-scratch cargo build --offline*)\"]\n",
    "  user:\n",
    "    allow: [\"session.new\"]\n",
    "    permissions:\n",
    "      allow: [\"Tool(github-post gh:pr.comment)\"]\n",
);

pub(crate) const LAUNCH_HOBI_POLICY: &str = concat!(
    "schema_version: 1\n",
    "permissions:\n",
    "  allow: [\"Read(~/**)\", \"Write(~/**)\", \"Tool(github-post gh:pr.comment)\", \"Tool(github-issues-write gh:issue.edit.title)\", \"Tool(rust-scratch cargo *)\"]\n",
);

pub(crate) const LAUNCH_JIN_POLICY: &str = concat!(
    "schema_version: 1\n",
    "permissions:\n",
    "  allow: [\"Read(~/**)\", \"Write(~/**)\"]\n",
);

pub(crate) const OPEN_CREDENTIAL_DROPIN: &str = concat!(
    "schema_version: 1\n",
    "tools:\n",
    "  open-credential:\n",
    "    executes_workspace: true\n",
    "    image: { ref: \"ghcr.io/example/maknae-rust-build@sha256:0000000000000000000000000000000000000000000000000000000000000000\" }\n",
    "    output_to_model: redacted\n",
    "    credential: github-read\n",
    "    commands:\n",
    "      cargo: { open: true }\n",
);

/// The shipped `gh` grammar and HomeLab `tools.yaml` under [`LAUNCH_SITE_POLICY`], agents hobi
/// and jin, and the role `tool.invoke` test-injected for admin and user (grantable with #479).
pub(crate) fn homelab_launch_composition(
    tag: &str,
) -> (
    DirGuard,
    crate::composition::Composition<HermeticAuthorizer>,
) {
    use maknae_authz_basic::Baseline;
    let (g, basic) = fixture(tag, LAUNCH_SITE_POLICY, None);
    write_sensitive(
        &g.0,
        include_str!("../../../packaging/common/sensitive.yaml"),
    );
    write_tools(
        &g.0,
        include_str!("../../../packaging/common/tools-homelab.yaml"),
    );
    write_shipped_gh_grammar(&g.0);
    write_tools_dropin(&g.0, "open-credential.yaml", OPEN_CREDENTIAL_DROPIN);
    basic.set_hosts(BTS_HOSTS);
    for (id, uid, policy) in [
        ("hobi", 2001, LAUNCH_HOBI_POLICY),
        ("jin", 2002, LAUNCH_JIN_POLICY),
    ] {
        write_agent(&g.0, id, &format!("{id}-svc"), uid, "user");
        write_agent_policy(&g.0, id, policy);
    }
    basic.install(
        basic
            .compile_granting_tool_invoke(&["admin", "user"])
            .unwrap(),
    );
    (
        g,
        crate::composition::Composition::with_us_baseline_ceiling(basic),
    )
}
