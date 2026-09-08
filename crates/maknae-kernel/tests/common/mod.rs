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
    fn decide(&self, _r: &Request) -> Verdict {
        std::thread::sleep(self.0);
        AlwaysPermit.decide(_r)
    }
}

/// A backend returning an obligation the PEP has no handler for.
pub struct HostileObligation;

impl Authorizer for HostileObligation {
    fn decide(&self, _r: &Request) -> Verdict {
        Verdict::Permit {
            obligations: vec![Obligation {
                id: "exfil".into(),
                params: maknae_security::Attributes::new(),
            }],
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
        home: "/home/operator".into(),
    }
}

/// Standard extra args for `handle()` in transport-behavior tests.
pub fn permissive_authz() -> (Arc<AlwaysPermit>, Arc<maknae_config::Principal>, Duration) {
    (
        Arc::new(AlwaysPermit),
        Arc::new(fixture_principal()),
        Duration::from_secs(5),
    )
}

/// A backend whose `backend_name()` PANICS. Permits, so the request reaches
/// dispatch — the kernel calls `backend_name` INLINE on the async worker, and
/// unlike `subjects` it has no `spawn_blocking` backstop, so an unguarded
/// panic there unwinds through `handle()` after the audit record already said
/// permit/authorized.
pub struct PanickingName;

impl Authorizer for PanickingName {
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

/// A temp root with a real `authz.yaml` (binding `user: ["root"]`, so the
/// fixture's peer uid 0 is the `user` role) and a real composed PDP over it.
pub struct Fixture {
    pub root: PathBuf,
    pub principal: maknae_config::Principal,
}
impl Fixture {
    pub fn new(tag: &str, allow: &str) -> Self {
        Self::with_policy(tag, allow, "")
    }
    /// `new`, then `policy_tail` appended to the policy body (a `roles:` /
    /// `destinations:` block for #172).
    pub fn with_policy(tag: &str, allow: &str, policy_tail: &str) -> Self {
        let root = std::env::temp_dir().join(format!("mutation_{tag}_{}", std::process::id()));
        std::fs::create_dir_all(&root).unwrap();
        std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700)).unwrap();
        let root = root.canonicalize().unwrap();
        let principal = maknae_config::Principal {
            name: "operator".into(),
            uid: nix::unistd::geteuid().as_raw(),
            home: root.clone(),
        };
        let policy = format!("schema_version: 1\npermissions:\n  allow:\n    - \"{allow}(~/**)\"\n  deny: []\nbindings:\n  user: [\"root\"]\n{policy_tail}");
        std::fs::write(root.join("authz.yaml"), policy).unwrap();
        std::fs::set_permissions(
            root.join("authz.yaml"),
            std::fs::Permissions::from_mode(0o640),
        )
        .unwrap();
        Self { root, principal }
    }
    pub fn authorizer(
        &self,
    ) -> Arc<maknae_kernel::Composition<maknae_authz_basic::HermeticAuthorizer>> {
        let basic = maknae_authz_basic::HermeticAuthorizer::new(
            self.root.join("authz.yaml"),
            self.principal.clone(),
            maknae_config::TargetRequired {
                owner: None,
                mode_mask: Some(0o022),
                nlink_exactly_one: false,
                regular_file: true,
                max_bytes: None,
            },
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
            maknae_kernel::production_egress(),
        )
    }
    /// The full starter (#172): a registered provider name and an egress
    /// backend. `fd` is INCLUDED: the mutation suite delegates a real writable
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
        let (client, server) = tokio::io::duplex(65536);
        let fds = maknae_io::DelegatedFds::new(4);
        if let Some(fd) = fd {
            fds.push(fd);
        }
        let principal = Arc::new(self.principal.clone());
        let authz = self.authorizer();
        let task = tokio::spawn(maknae_kernel::handle(
            server,
            "maknae://d/plane/cli".into(),
            0,
            true,
            records,
            718,
            config,
            serde_json::json!({"mutation": "untrusted extension"}),
            authz,
            principal,
            Arc::new(Default::default()),
            Arc::new("basic+ceiling".into()),
            Arc::new("US".into()),
            Arc::new(provider.map(str::to_string)),
            egress,
            Duration::from_secs(2),
            maknae_security::Lane::Local,
            fds,
        ));
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
        let (mut client, task, body) =
            self.start_egress(verb, None, records, config, provider, egress);
        maknae_proto::write_frame(&mut client, &body).await.unwrap();
        let response = tokio::time::timeout(
            Duration::from_secs(3),
            maknae_proto::read_frame(&mut client, 65536),
        )
        .await
        .ok()?
        .ok()
        .and_then(|body| maknae_proto::decode_response(&body).ok());
        task.await.unwrap();
        response
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.root);
    }
}
