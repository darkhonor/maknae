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
        }
    }
}

impl FakeEnv {
    pub(crate) fn with_bounds() -> Self {
        FakeEnv {
            bounds: Some(maknae_config::EgressBounds {
                kv_mount: "kv".into(),
                user_prefix: "users".into(),
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
pub(crate) fn minimal() -> Vec<(&'static str, &'static str)> {
    vec![
        ("core", r#"{"deployment_id":"d"}"#),
        ("audit", AUDIT),
        ("principal", PRINCIPAL),
        ("vault", VAULT),
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
    let paths = maknae_authz_basic::PolicyPaths::in_dir(&dir);
    for (path, body) in [(&paths.authz, Some(policy)), (&paths.bindings, bindings)] {
        let Some(body) = body else { continue };
        std::fs::write(path, body).unwrap();
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o640)).unwrap();
    }
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
    let basic = HermeticAuthorizer::new(paths, principal, req, maknae_state::envelope::sha256)
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
