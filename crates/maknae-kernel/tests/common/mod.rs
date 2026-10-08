//! Shared fixtures for the kernel integration suites. Each tests/*.rs is its
//! own crate and uses a subset of these — hence the allow (`-D warnings`
//! clippy would otherwise red on unused-in-one-crate items).
#![allow(dead_code)]

use std::future::Future;
use std::os::fd::OwnedFd;
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use maknae_proto::{Response, Verb};

use maknae_audit_append::{AuditEmit, AuditError, AuditRecord};
use maknae_security::{Authorizer, Obligation, Request, Verdict};

/// The labeled ALWAYS-PERMIT fixture for transport-behavior tests (read
/// timeout, frame cap, admission gating, audit-then-respond): their claims
/// are not PDP verdicts — the real-PDP proofs live in enforce_loop.rs with
/// HermeticAuthorizer. Carries the standard audit obligation so the permit
/// path exercises the discharge gate.
pub struct AlwaysPermit;

impl Authorizer for AlwaysPermit {
    fn decide_cited_all(&self, reqs: &[maknae_security::Request]) -> Vec<maknae_security::Decided> {
        maknae_security::decide_each_cited(self, reqs)
    }

    fn decide(&self, _r: &Request) -> Verdict {
        Verdict::Permit {
            obligations: vec![Obligation {
                id: "audit".into(),
                params: maknae_security::Attributes::new(),
            }],
        }
    }
}

/// A hostile/wedged backend: sleeps synchronously (a REAL blocking sleep —
/// the decide runs on the blocking pool, where virtual time cannot reach it)
/// then permits. Drives the two-sided decide-timeout proofs.
pub struct SleepAuthorizer(pub Duration);

impl Authorizer for SleepAuthorizer {
    fn decide_cited_all(&self, reqs: &[maknae_security::Request]) -> Vec<maknae_security::Decided> {
        maknae_security::decide_each_cited(self, reqs)
    }

    fn decide(&self, _r: &Request) -> Verdict {
        std::thread::sleep(self.0);
        AlwaysPermit.decide(_r)
    }
}

/// A backend returning an obligation the PEP has no handler for, on a cited rule.
pub struct HostileObligation;

impl Authorizer for HostileObligation {
    fn decide_cited_all(&self, reqs: &[maknae_security::Request]) -> Vec<maknae_security::Decided> {
        maknae_security::decide_each_cited(self, reqs)
    }

    fn decide(&self, _r: &Request) -> Verdict {
        Verdict::Permit {
            obligations: vec![Obligation {
                id: "exfil".into(),
                params: maknae_security::Attributes::new(),
            }],
        }
    }

    fn decide_cited(&self, r: &Request) -> maknae_security::Decided {
        maknae_security::Decided {
            verdict: self.decide(r),
            role: None,
            rule: Some(maknae_security::RuleCitation {
                node: 1,
                key: "rule:permissions:allow:0".into(),
                section: "hostile#permissions".into(),
            }),
        }
    }
}

/// Permits with the audit obligation on a cited rule, and cannot enumerate.
pub struct CitingPermit;

impl Authorizer for CitingPermit {
    fn decide_cited_all(&self, reqs: &[maknae_security::Request]) -> Vec<maknae_security::Decided> {
        maknae_security::decide_each_cited(self, reqs)
    }

    fn decide(&self, r: &Request) -> Verdict {
        AlwaysPermit.decide(r)
    }

    fn decide_cited(&self, r: &Request) -> maknae_security::Decided {
        maknae_security::Decided {
            verdict: self.decide(r),
            role: Some("admin"),
            rule: Some(maknae_security::RuleCitation {
                node: 7,
                key: "rule:roles.admin:allow:0".into(),
                section: "citing#roles.admin".into(),
            }),
        }
    }
}

/// Fails ONLY the Nth emit() call (1-based); records every offer
/// synchronously. n=2 fails the REQUEST record while the admission record
/// (call 1) succeeds — the deny/permit-record withhold scenarios need exactly
/// that, which neither RecEmit (fails all) nor FailFirstEmit (fails call 1 →
/// admission gate trips first) can reach.
pub struct FailNthEmit {
    recs: Mutex<Vec<AuditRecord>>,
    calls: Mutex<u32>,
    n: u32,
}

impl FailNthEmit {
    pub fn new(n: u32) -> Arc<Self> {
        Arc::new(FailNthEmit {
            recs: Mutex::new(Vec::new()),
            calls: Mutex::new(0),
            n,
        })
    }
    pub fn records(&self) -> Vec<AuditRecord> {
        self.recs.lock().unwrap().clone()
    }
}

impl AuditEmit for FailNthEmit {
    fn emit(&self, rec: &AuditRecord) -> impl Future<Output = Result<(), AuditError>> + Send {
        self.recs.lock().unwrap().push(rec.clone());
        let mut calls = self.calls.lock().unwrap();
        *calls += 1;
        let fail = *calls == self.n;
        drop(calls);
        async move {
            if fail {
                Err(AuditError::WritePrimary("forced (nth call)".into()))
            } else {
                Ok(())
            }
        }
    }
}

/// The standard test principal: uid 501 matches the suites' peer_uid so the
/// bindings-absent defaults resolve `admin` where a real PDP is in play.
pub fn fixture_principal() -> maknae_config::Principal {
    maknae_config::Principal {
        name: "operator".into(),
        uid: 501,
    }
}

pub fn fixture_home() -> PathBuf {
    PathBuf::from("/home/operator")
}

/// Standard extra args for `handle()` in transport-behavior tests.
pub fn permissive_authz() -> (Arc<AlwaysPermit>, Duration) {
    (Arc::new(AlwaysPermit), Duration::from_secs(5))
}

/// A backend whose `backend_name()` PANICS. Permits, so the request reaches
/// dispatch — the kernel calls `backend_name` INLINE on the async worker, and
/// unlike `subjects` it has no `spawn_blocking` backstop, so an unguarded
/// panic there unwinds through `handle()` after the audit record already said
/// permit/authorized.
pub struct PanickingName;

impl Authorizer for PanickingName {
    fn decide_cited_all(&self, reqs: &[maknae_security::Request]) -> Vec<maknae_security::Decided> {
        maknae_security::decide_each_cited(self, reqs)
    }

    fn decide(&self, _r: &maknae_security::Request) -> Verdict {
        Verdict::Permit {
            obligations: vec![maknae_security::Obligation {
                id: "audit".into(),
                params: maknae_security::Attributes::new(),
            }],
        }
    }
    fn backend_name(&self) -> String {
        panic!("hostile backend name")
    }
}

// ---- the composed-PDP harness (moved from mutation_loop.rs for #172; one
// harness, so the mutation and prompt suites cannot drift apart) ----

/// An `AuditEmit` that records every append and fails exactly the Nth one
/// (`fail == 0` never fails). The failure is injected AFTER the push, so the
/// failed record is still visible in `snapshot()`.
pub struct Records {
    records: Mutex<Vec<maknae_audit_append::AuditRecord>>,
    fail: usize,
}
impl Records {
    pub fn new(fail: usize) -> Arc<Self> {
        Arc::new(Self {
            records: Mutex::new(Vec::new()),
            fail,
        })
    }
    pub fn snapshot(&self) -> Vec<maknae_audit_append::AuditRecord> {
        self.records.lock().unwrap().clone()
    }
}
impl AuditEmit for Records {
    fn emit(
        &self,
        record: &maknae_audit_append::AuditRecord,
    ) -> impl std::future::Future<Output = Result<(), AuditError>> + Send {
        let mut records = self.records.lock().unwrap();
        records.push(record.clone());
        let fail = records.len() == self.fail;
        async move {
            if fail {
                Err(AuditError::WritePrimary(
                    "injected append/sync failure".into(),
                ))
            } else {
                Ok(())
            }
        }
    }
}

/// The kernel admits one filesystem preparation per uid at a time (#435), and
/// every fixture is the test euid, so filesystem requests take turns.
static FS_TURN: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

pub async fn fs_turn(verb: &Verb) -> Option<tokio::sync::MutexGuard<'static, ()>> {
    if maknae_kernel::is_filesystem_verb(verb) {
        Some(FS_TURN.lock().await)
    } else {
        None
    }
}

/// A temp root with a real `authz.yaml` and `bindings.yaml` (binding the test
/// euid's username to `user`, so the fixture's peer uid is the `user` role) and
/// a real composed PDP over them.
pub struct Fixture {
    pub root: PathBuf,
    pub principal: maknae_config::Principal,
    pub peer_uid: u32,
    pub peer_user: Option<String>,
    pub requester_home: Option<PathBuf>,
}

/// The test euid's username. It must pass `userpass_username_is_acceptable`
/// (one safe lower-case segment), as the provider tests also require.
pub fn euid_name() -> String {
    nix::unistd::User::from_uid(nix::unistd::geteuid())
        .expect("NSS")
        .expect("the test euid has a passwd entry")
        .name
}

pub fn write_0640(path: &std::path::Path, body: &str) {
    std::fs::write(path, body).unwrap();
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o640)).unwrap();
}

pub struct DirGuard(pub PathBuf);

impl std::ops::Deref for DirGuard {
    type Target = std::path::Path;
    fn deref(&self) -> &std::path::Path {
        &self.0
    }
}

impl Drop for DirGuard {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

pub fn second_home(tag: &str) -> DirGuard {
    let dir = std::env::temp_dir().join(format!("home_{tag}_{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700)).unwrap();
    DirGuard(dir.canonicalize().expect("canonicalize the second home"))
}

impl Fixture {
    pub fn new(tag: &str, allow: &str) -> Self {
        Self::with_policy(tag, allow, "")
    }
    /// `new`, then `policy_tail` appended to the policy body (a `roles:` /
    /// `destinations:` block for #172).
    /// Same as [`Fixture::with_policy`] but binds the test euid's username to
    /// the NAMED role, so a test can drive the real decision path for each of
    /// the four shipped roles (#275). The harness's peer uid is the test euid.
    pub fn with_policy_bound_to(tag: &str, allow: &str, role: &str, policy_tail: &str) -> Self {
        let f = Self::with_policy(tag, allow, policy_tail);
        let name = euid_name();
        let bindings = std::fs::read_to_string(f.paths().bindings).unwrap();
        let rebound = bindings.replace(
            &format!("bindings:\n  user: [\"{name}\"]"),
            &format!("bindings:\n  {role}: [\"{name}\"]"),
        );
        assert!(
            role == "user" || rebound != bindings,
            "the binding must actually change for {role}"
        );
        write_0640(&f.paths().bindings, &rebound);
        f
    }

    pub fn paths(&self) -> maknae_authz_basic::PolicyPaths {
        maknae_authz_basic::PolicyPaths::in_dir(&self.root)
    }

    pub fn with_policy(tag: &str, allow: &str, policy_tail: &str) -> Self {
        Self::with_rules(tag, &[allow], &[], policy_tail)
    }
    /// `allows` are capability names granted over `~/**` (the shape every
    /// existing caller used); `denies` are FULL rule strings as the shipped
    /// policy writes them (`packaging/common/authz.yaml`), e.g. `Read(~/.ssh/**)`.
    /// The asymmetry is deliberate: it keeps `with_policy`'s generated YAML
    /// byte-identical to what it produced before, for every existing caller.
    pub fn with_rules(tag: &str, allows: &[&str], denies: &[&str], policy_tail: &str) -> Self {
        let root = std::env::temp_dir().join(format!("mutation_{tag}_{}", std::process::id()));
        std::fs::create_dir_all(&root).unwrap();
        std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700)).unwrap();
        let root = root.canonicalize().unwrap();
        let principal = maknae_config::Principal {
            name: "operator".into(),
            uid: nix::unistd::geteuid().as_raw(),
        };
        let allow_lines: String = allows
            .iter()
            .map(|a| format!("    - \"{a}(~/**)\"\n"))
            .collect();
        let deny_block = if denies.is_empty() {
            "  deny: []\n".to_string()
        } else {
            format!(
                "  deny:\n{}",
                denies
                    .iter()
                    .map(|d| format!("    - \"{d}\"\n"))
                    .collect::<String>()
            )
        };
        let name = euid_name();
        let paths = maknae_authz_basic::PolicyPaths::in_dir(&root);
        write_0640(
            &paths.authz,
            &format!(
                "schema_version: 1\npermissions:\n  allow:\n{allow_lines}{deny_block}{policy_tail}"
            ),
        );
        write_0640(
            &paths.bindings,
            &format!("schema_version: 1\nbindings:\n  user: [\"{name}\"]\n"),
        );
        Self {
            peer_uid: nix::unistd::geteuid().as_raw(),
            peer_user: Some(name),
            requester_home: Some(root.clone()),
            root,
            principal,
        }
    }
    pub fn with_requester_home(mut self, home: Option<PathBuf>) -> Self {
        self.requester_home = home;
        self
    }
    pub fn authorizer(
        &self,
    ) -> Arc<maknae_kernel::Composition<maknae_authz_basic::HermeticAuthorizer>> {
        let basic = maknae_authz_basic::HermeticAuthorizer::new(
            self.paths(),
            self.principal.clone(),
            maknae_config::TargetRequired {
                owner: None,
                mode_mask: Some(0o022),
                nlink_exactly_one: false,
                regular_file: true,
                max_bytes: None,
            },
            maknae_state::envelope::sha256,
        )
        .unwrap();
        let us = &maknae_config::BasicPolicy;
        Arc::new(maknae_kernel::Composition::new(
            basic,
            maknae_kernel::CeilingAuthorizer::new(maknae_config::Ceiling::baseline_for(us), us),
        ))
    }
    pub fn start(
        &self,
        verb: Verb,
        fd: Option<OwnedFd>,
        records: Arc<impl AuditEmit + Send + Sync + 'static>,
    ) -> (
        tokio::io::DuplexStream,
        tokio::task::JoinHandle<()>,
        Vec<u8>,
    ) {
        self.start_with_config(
            verb,
            fd,
            records,
            maknae_config::transport_from_section(None).unwrap(),
        )
    }
    pub fn start_with_config(
        &self,
        verb: Verb,
        fd: Option<OwnedFd>,
        records: Arc<impl AuditEmit + Send + Sync + 'static>,
        config: maknae_config::TransportConfig,
    ) -> (
        tokio::io::DuplexStream,
        tokio::task::JoinHandle<()>,
        Vec<u8>,
    ) {
        self.start_egress(
            verb,
            fd,
            records,
            config,
            None,
            maknae_kernel::unavailable_egress(),
        )
    }
    /// The full starter (#172): a registered provider name and an egress
    /// backend. `fd` is INCLUDED: the mutation suite delegates a real no-access
    /// descriptor through here.
    pub fn start_egress(
        &self,
        verb: Verb,
        fd: Option<OwnedFd>,
        records: Arc<impl AuditEmit + Send + Sync + 'static>,
        config: maknae_config::TransportConfig,
        provider: Option<&str>,
        egress: Arc<dyn maknae_kernel::Egress>,
    ) -> (
        tokio::io::DuplexStream,
        tokio::task::JoinHandle<()>,
        Vec<u8>,
    ) {
        self.start_with_authorizer(
            self.authorizer(),
            verb,
            fd,
            records,
            config,
            provider,
            egress,
        )
    }
    #[allow(clippy::too_many_arguments)]
    pub fn start_with_authorizer<P>(
        &self,
        authz: Arc<P>,
        verb: Verb,
        fd: Option<OwnedFd>,
        records: Arc<impl AuditEmit + Send + Sync + 'static>,
        config: maknae_config::TransportConfig,
        provider: Option<&str>,
        egress: Arc<dyn maknae_kernel::Egress>,
    ) -> (
        tokio::io::DuplexStream,
        tokio::task::JoinHandle<()>,
        Vec<u8>,
    )
    where
        P: maknae_security::Authorizer + Send + Sync + 'static,
    {
        self.start_with_authorizer_and_caps(
            authz,
            verb,
            fd,
            records,
            config,
            provider,
            egress,
            maknae_kernel::AttemptCaps::default(),
        )
    }
    pub fn start_with_attempt_caps(
        &self,
        verb: Verb,
        fd: Option<OwnedFd>,
        records: Arc<impl AuditEmit + Send + Sync + 'static>,
        attempt_caps: maknae_kernel::AttemptCaps,
    ) -> (
        tokio::io::DuplexStream,
        tokio::task::JoinHandle<()>,
        Vec<u8>,
    ) {
        self.start_with_authorizer_and_caps(
            self.authorizer(),
            verb,
            fd,
            records,
            maknae_config::transport_from_section(None).unwrap(),
            None,
            maknae_kernel::unavailable_egress(),
            attempt_caps,
        )
    }
    /// The starter with the PDP supplied by the caller (a wrapper around the
    /// real composition, for tests that must OBSERVE whether it was consulted).
    #[allow(clippy::too_many_arguments)]
    pub fn start_with_authorizer_and_caps<P>(
        &self,
        authz: Arc<P>,
        verb: Verb,
        fd: Option<OwnedFd>,
        records: Arc<impl AuditEmit + Send + Sync + 'static>,
        config: maknae_config::TransportConfig,
        provider: Option<&str>,
        egress: Arc<dyn maknae_kernel::Egress>,
        attempt_caps: maknae_kernel::AttemptCaps,
    ) -> (
        tokio::io::DuplexStream,
        tokio::task::JoinHandle<()>,
        Vec<u8>,
    )
    where
        P: maknae_security::Authorizer + Send + Sync + 'static,
    {
        let (client, server) = tokio::io::duplex(65536);
        let fds = maknae_io::DelegatedFds::new(4);
        if let Some(fd) = fd {
            fds.push(fd);
        }
        let turn = verb.clone();
        let served = maknae_kernel::handle_with_attempt_caps(
            server,
            "maknae://d/plane/cli".into(),
            self.peer_uid,
            true,
            self.peer_user.clone(),
            self.requester_home.clone(),
            records,
            718,
            config,
            serde_json::json!({"mutation": "untrusted extension"}),
            authz,
            Arc::new(Default::default()),
            Arc::new("basic+ceiling".into()),
            Arc::new("US".into()),
            std::sync::Arc::new(None),
            Arc::new(authority(provider)),
            egress,
            Duration::from_secs(2),
            maknae_security::Lane::Local,
            fds,
            attempt_caps,
        );
        let task = tokio::spawn(async move {
            let _turn = fs_turn(&turn).await;
            served.await
        });
        let body = maknae_proto::encode_request(&maknae_proto::Request {
            protocol_version: maknae_proto::PROTOCOL_VERSION,
            verb,
        })
        .unwrap();
        // The client write happens in the driver, leaving this reusable for reports.
        (client, task, body)
    }
    /// One request, one frame back (`None` when the daemon closed frameless:
    /// the audit-failure discipline), under the default transport.
    pub async fn roundtrip(
        &self,
        verb: Verb,
        records: Arc<Records>,
        provider: Option<&str>,
        egress: Arc<dyn maknae_kernel::Egress>,
    ) -> Option<Response> {
        self.roundtrip_with_config(
            verb,
            records,
            provider,
            egress,
            maknae_config::transport_from_section(None).unwrap(),
        )
        .await
    }
    pub async fn roundtrip_with_config(
        &self,
        verb: Verb,
        records: Arc<Records>,
        provider: Option<&str>,
        egress: Arc<dyn maknae_kernel::Egress>,
        config: maknae_config::TransportConfig,
    ) -> Option<Response> {
        let (client, task, body) = self.start_egress(verb, None, records, config, provider, egress);
        Self::exchange(client, task, &body).await
    }
    /// `roundtrip` over a caller-supplied PDP.
    pub async fn roundtrip_with_authorizer<P>(
        &self,
        authz: Arc<P>,
        verb: Verb,
        records: Arc<Records>,
        provider: Option<&str>,
        egress: Arc<dyn maknae_kernel::Egress>,
    ) -> Option<Response>
    where
        P: maknae_security::Authorizer + Send + Sync + 'static,
    {
        let (client, task, body) = self.start_with_authorizer(
            authz,
            verb,
            None,
            records,
            maknae_config::transport_from_section(None).unwrap(),
            provider,
            egress,
        );
        Self::exchange(client, task, &body).await
    }
    /// `roundtrip` with the request bytes supplied RAW (a malformed frame the
    /// encoder would never produce).
    pub async fn roundtrip_raw(
        &self,
        raw_body: &[u8],
        records: Arc<Records>,
        provider: Option<&str>,
        egress: Arc<dyn maknae_kernel::Egress>,
    ) -> Option<Response> {
        let (client, task, _body) = self.start_egress(
            Verb::Ping,
            None,
            records,
            maknae_config::transport_from_section(None).unwrap(),
            provider,
            egress,
        );
        Self::exchange(client, task, raw_body).await
    }
    /// Write one frame, then read EVERYTHING the daemon sends until it closes.
    /// `None` means a CLEAN close with zero bytes; a timeout (the handler hung),
    /// a truncated frame, or an undecodable frame each PANIC, so a test that
    /// asserts `is_none()` proves frameless closure and not merely "no
    /// complete frame arrived".
    pub async fn exchange(
        mut client: tokio::io::DuplexStream,
        task: tokio::task::JoinHandle<()>,
        body: &[u8],
    ) -> Option<Response> {
        use tokio::io::AsyncReadExt;
        write_frame(&mut client, body).await.unwrap();
        let mut received = Vec::new();
        tokio::time::timeout(Duration::from_secs(3), client.read_to_end(&mut received))
            .await
            .expect("the daemon must close the connection within 3s")
            .expect("reading until close must not error");
        tokio::time::timeout(Duration::from_secs(3), task)
            .await
            .expect("the handler must finish within 3s")
            .unwrap();
        if received.is_empty() {
            return None;
        }
        let mut cursor = &received[..];
        let frame = read_frame(&mut cursor, 65536)
            .await
            .expect("bytes on the wire must be one complete frame, never a partial one");
        assert!(cursor.is_empty(), "exactly one frame, nothing after it");
        Some(maknae_proto::decode_response(&frame).expect("the frame must decode"))
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.root);
    }
}

pub const TEST_MODEL: &str = "test-model";
pub const TEST_USER_PREFIX: &str = "maknae/users";

pub fn authority(provider: Option<&str>) -> Option<maknae_kernel::ProviderAuthority> {
    use maknae_config::Value;
    let name = provider?;
    let set = maknae_config::providers_from_section(Some(&Value::Seq(vec![Value::Map(vec![
        ("name".into(), Value::Str(name.into())),
        (
            "endpoint".into(),
            Value::Str("http://127.0.0.1:1/v1".into()),
        ),
        (
            "models".into(),
            Value::Seq(vec![Value::Str(TEST_MODEL.into())]),
        ),
    ])])))
    .unwrap();
    Some(maknae_kernel::ProviderAuthority {
        set,
        user_prefix: TEST_USER_PREFIX.into(),
    })
}

pub fn choice(provider: &str, model: &str, subpath: &str) -> maknae_proto::ProviderChoice {
    maknae_proto::ProviderChoice {
        provider: provider.into(),
        model: model.into(),
        key_subpath: subpath.into(),
        key_field: "api_key".into(),
        sealed_key: maknae_proto::SealedKey::new(vec![0x5a; maknae_proto::SEALED_KEY_MIN_BYTES])
            .unwrap(),
    }
}

pub fn test_choice() -> maknae_proto::ProviderChoice {
    choice("openai", TEST_MODEL, "openai/personal")
}

/// The subject's half of a read attempt, as `bins/maknae`'s `mutation::execute_read` performs it.
pub struct ReadRun {
    pub first: Option<Vec<u8>>,
    pub content: Option<maknae_io::Zeroizing<Vec<u8>>>,
    pub finish: Option<maknae_proto::ReportedFinish>,
    pub page: Option<maknae_io::Page>,
    pub label: Option<maknae_proto::ObjectLabel>,
}
async fn report_acked(
    client: &mut tokio::io::DuplexStream,
    report: maknae_proto::MutationReport,
) -> Option<maknae_proto::MutationAck> {
    write_frame(
        client,
        &maknae_proto::encode_mutation_report(&report).unwrap(),
    )
    .await
    .unwrap();
    tokio::time::timeout(Duration::from_secs(2), read_frame(client, 65536))
        .await
        .ok()
        .and_then(Result::ok)
        .and_then(|b| maknae_proto::decode_mutation_ack(&b).ok())
}
pub async fn read_as_subject(
    client: &mut tokio::io::DuplexStream,
    held: Option<&OwnedFd>,
) -> ReadRun {
    read_with(client, held, None).await
}
pub async fn read_page_as_subject(
    client: &mut tokio::io::DuplexStream,
    held: Option<&OwnedFd>,
    window: maknae_io::PageWindow,
) -> ReadRun {
    read_with(client, held, Some(window)).await
}
async fn read_with(
    client: &mut tokio::io::DuplexStream,
    held: Option<&OwnedFd>,
    window: Option<maknae_io::PageWindow>,
) -> ReadRun {
    use maknae_proto::{
        ByteRange, EffectEntry, LineSpan, MutationReport, MutationScope, Payload, ReportedEffect,
        ReportedFinish, RespResult,
    };
    let first = tokio::time::timeout(Duration::from_secs(2), read_frame(client, 1 << 20))
        .await
        .ok()
        .and_then(Result::ok);
    let grant = first
        .as_deref()
        .and_then(|b| maknae_proto::decode_response(b).ok())
        .and_then(|r| match r.result {
            RespResult::Ok(Payload::MutationAttempt(g)) => Some(g),
            _ => None,
        });
    let (Some(grant), Some(held)) = (grant, held) else {
        return ReadRun {
            first,
            content: None,
            finish: None,
            page: None,
            label: None,
        };
    };
    let label = Some(grant.label.clone());
    let MutationScope::Exact {
        path,
        effect: ReportedEffect::ReadFile,
    } = &grant.scope
    else {
        panic!("a read must be granted Exact ReadFile: {:?}", grant.scope)
    };
    let fd = std::os::fd::AsFd::as_fd(held);
    let target = std::path::Path::new(path);
    let deadline = std::time::Instant::now() + Duration::from_millis(grant.limits.deadline_ms);
    let read = match window {
        None => maknae_io::read_held_page(
            fd,
            target,
            maknae_io::PageWindow {
                offset_line: 1,
                limit_lines: u32::MAX,
                column: 0,
            },
            grant.limits.max_bytes,
            deadline,
        )
        .map(|mut p| {
            let bytes = std::mem::take(&mut p.content);
            (bytes, Some(p))
        }),
        Some(w) => maknae_io::read_held_page(fd, target, w, grant.limits.max_bytes, deadline).map(
            |mut p| {
                let bytes = std::mem::take(&mut p.content);
                (bytes, Some(p))
            },
        ),
    };
    match read {
        Ok((bytes, page)) => {
            let len = bytes.len() as u64;
            let start = page.as_ref().map_or(0, |p| p.start);
            let batch = MutationReport::Batch {
                id: grant.id,
                first_index: 0,
                effects: vec![EffectEntry {
                    path: path.clone(),
                    effect: ReportedEffect::ReadFile,
                    length: Some(len),
                    range: Some(ByteRange {
                        start,
                        end: start + len,
                    }),
                    lines: page.as_ref().and_then(|p| {
                        p.lines.map(|(first, last)| LineSpan {
                            first,
                            last,
                            complete_last: p.complete_last,
                        })
                    }),
                }],
            };
            let acked = report_acked(client, batch).await.map(|a| a.next_index) == Some(1)
                && report_acked(
                    client,
                    MutationReport::Finished {
                        id: grant.id,
                        next_index: 1,
                        outcome: ReportedFinish::Success,
                        stopped_at: None,
                    },
                )
                .await
                .is_some();
            ReadRun {
                first,
                content: acked.then_some(bytes),
                finish: Some(ReportedFinish::Success),
                page,
                label,
            }
        }
        Err(e) => {
            let outcome = match e.source {
                maknae_io::IoError::TargetTooLarge { .. } => ReportedFinish::LimitReached,
                maknae_io::IoError::MutationPathChanged { .. }
                | maknae_io::IoError::SizeChanged { .. } => ReportedFinish::PathChanged,
                _ => ReportedFinish::OsRefused,
            };
            report_acked(
                client,
                MutationReport::Finished {
                    id: grant.id,
                    next_index: 0,
                    outcome,
                    stopped_at: Some(path.clone()),
                },
            )
            .await;
            ReadRun {
                first,
                content: None,
                finish: Some(outcome),
                page: None,
                label,
            }
        }
    }
}

pub async fn write_frame<W: tokio::io::AsyncWrite + Unpin>(
    w: &mut W,
    body: &[u8],
) -> Result<(), maknae_proto::ProtoFrameError> {
    let class = match maknae_proto::decode_request(body) {
        Ok(r) => maknae_proto::class_of(&r.verb),
        Err(_) => maknae_proto::FrameClass::Attempt,
    };
    maknae_proto::write_frame(w, class, body).await
}

pub async fn read_frame<R: tokio::io::AsyncRead + Unpin>(
    r: &mut R,
    max: usize,
) -> Result<Vec<u8>, maknae_proto::ProtoFrameError> {
    let caps = maknae_proto::FrameCaps {
        control: max,
        attempt: max,
        prompt: max,
    };
    let (_, mut body) = maknae_proto::read_frame_zeroizing(r, &caps).await?;
    Ok(std::mem::take(&mut *body))
}
