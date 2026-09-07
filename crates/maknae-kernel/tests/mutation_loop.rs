//! Real composed PDP and real writable descriptors across the mutation audit gate.
use maknae_audit_append::{AuditEmit, AuditError, AuditRecord};
use maknae_proto::{Bytes, Payload, RespResult, Verb, WriteMode};
use std::{
    os::{fd::OwnedFd, unix::fs::PermissionsExt},
    path::PathBuf,
    sync::{Arc, Mutex},
    time::Duration,
};

struct Records {
    records: Mutex<Vec<AuditRecord>>,
    fail: usize,
}
impl Records {
    fn new(fail: usize) -> Arc<Self> {
        Arc::new(Self {
            records: Mutex::new(Vec::new()),
            fail,
        })
    }
    fn snapshot(&self) -> Vec<AuditRecord> {
        self.records.lock().unwrap().clone()
    }
}
impl AuditEmit for Records {
    fn emit(
        &self,
        record: &AuditRecord,
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
struct Fixture {
    root: PathBuf,
    principal: maknae_config::Principal,
}
impl Fixture {
    fn new(tag: &str, allow: &str) -> Self {
        let root = std::env::temp_dir().join(format!("mutation_{tag}_{}", std::process::id()));
        std::fs::create_dir_all(&root).unwrap();
        std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700)).unwrap();
        let root = root.canonicalize().unwrap();
        let principal = maknae_config::Principal {
            name: "operator".into(),
            uid: nix::unistd::geteuid().as_raw(),
            home: root.clone(),
        };
        let policy = format!("schema_version: 1\npermissions:\n  allow:\n    - \"{allow}(~/**)\"\n  deny: []\nbindings:\n  user: [\"root\"]\n");
        std::fs::write(root.join("authz.yaml"), policy).unwrap();
        std::fs::set_permissions(
            root.join("authz.yaml"),
            std::fs::Permissions::from_mode(0o640),
        )
        .unwrap();
        Self { root, principal }
    }
    fn authorizer(
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
    fn start(
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
    fn start_with_config(
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
            Duration::from_secs(2),
            maknae_security::Lane::Local,
            fds,
        ));
        let body = maknae_proto::encode_request(&maknae_proto::Request {
            protocol_version: maknae_proto::PROTOCOL_VERSION,
            verb,
        })
        .unwrap();
        // The client write happens in drive, leaving this helper reusable for reports.
        (client, task, body)
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.root);
    }
}
async fn drive(
    fx: &Fixture,
    bytes: &[u8],
    records: Arc<Records>,
    delegate: bool,
) -> Option<maknae_proto::Response> {
    let target = fx.root.join("unique-existing-write-sentinel");
    let fd = delegate.then(|| {
        std::fs::OpenOptions::new()
            .write(true)
            .open(&target)
            .unwrap()
            .into()
    });
    let (mut client, task, body) = fx.start(
        Verb::FsWrite {
            path: target.to_str().unwrap().into(),
            content: Bytes::new(bytes.to_vec().into()),
            mode: WriteMode::Existing,
        },
        fd,
        records,
    );
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
#[tokio::test]
async fn durable_intent_precedes_existing_empty_truncation_and_completion() {
    let fx = Fixture::new("existing_success", "Write");
    let target = fx.root.join("unique-existing-write-sentinel");
    std::fs::write(&target, b"original-long-sentinel").unwrap();
    let records = Records::new(0);
    let response = drive(&fx, b"", records.clone(), true).await.unwrap();
    assert!(
        matches!(response.result, RespResult::Ok(Payload::MutationComplete)),
        "{:?}",
        records.snapshot()
    );
    assert_eq!(std::fs::read(target).unwrap(), b"");
    let records = records.snapshot();
    assert_eq!(records[1].object_requested, None);
    assert_eq!(records[2].object_requested, None);
    assert_eq!(
        records[1].mutation.as_ref().unwrap().phase,
        maknae_audit_append::MutationPhase::Intent
    );
    assert_eq!(
        records[2].mutation.as_ref().unwrap().phase,
        maknae_audit_append::MutationPhase::Completion
    );
    assert_eq!(
        records[2].mutation.as_ref().unwrap().origin,
        maknae_audit_append::MutationOrigin::KernelObserved
    );
}
#[tokio::test]
async fn failed_intent_preserves_existing_bytes_and_length() {
    let fx = Fixture::new("intent_fail", "Write");
    let target = fx.root.join("unique-existing-write-sentinel");
    std::fs::write(&target, b"original-long-sentinel").unwrap();
    assert!(drive(&fx, b"", Records::new(2), true).await.is_none());
    assert_eq!(std::fs::read(target).unwrap(), b"original-long-sentinel");
}
#[tokio::test]
async fn failed_completion_does_not_claim_rollback() {
    let fx = Fixture::new("completion_fail", "Write");
    let target = fx.root.join("unique-existing-write-sentinel");
    std::fs::write(&target, b"old").unwrap();
    assert!(drive(&fx, b"new-sentinel", Records::new(3), true)
        .await
        .is_none());
    assert_eq!(std::fs::read(target).unwrap(), b"new-sentinel");
}
#[tokio::test]
async fn read_allow_and_missing_evidence_cannot_write() {
    for (tag, allow, delegate) in [("read_only", "Read", true), ("no_fd", "Write", false)] {
        let fx = Fixture::new(tag, allow);
        let target = fx.root.join("unique-existing-write-sentinel");
        std::fs::write(&target, b"untouched").unwrap();
        let response = drive(&fx, b"bad", Records::new(0), delegate).await.unwrap();
        assert!(matches!(response.result, RespResult::Err(_)));
        assert_eq!(std::fs::read(target).unwrap(), b"untouched");
    }
}

#[tokio::test]
async fn missing_write_descriptor_preserves_preparation_failure_in_audit() {
    let fx = Fixture::new("missing_descriptor_audit", "Write");
    let target = fx.root.join("unique-existing-write-sentinel");
    std::fs::write(&target, b"missing-descriptor-must-preserve-me").unwrap();
    let records = Records::new(0);
    let response = drive(&fx, b"forbidden-replacement", records.clone(), false)
        .await
        .unwrap();
    assert!(matches!(response.result, RespResult::Err(_)));
    assert_eq!(
        std::fs::read(&target).unwrap(),
        b"missing-descriptor-must-preserve-me"
    );
    let records = records.snapshot();
    assert_eq!(
        records.len(),
        2,
        "no mutation intent follows invalid evidence"
    );
    let refusal = &records[1];
    assert_eq!(refusal.object.as_deref(), target.to_str());
    assert_eq!(refusal.outcome.result, "deny");
    assert!(
        refusal.outcome.reason.contains("descriptor missing"),
        "audit must distinguish absent evidence from worker/policy failure: {refusal:?}"
    );
    assert!(refusal.mutation.is_none());
}

#[tokio::test]
async fn permitted_alias_write_audits_requested_and_verified_objects() {
    let fx = Fixture::new("permitted_alias_audit", "Write");
    let target = fx.root.join("unique-verified-alias-write-sentinel");
    let alias = fx.root.join("unique-requested-write-alias");
    std::fs::write(&target, b"original-alias-target").unwrap();
    std::os::unix::fs::symlink(&target, &alias).unwrap();
    let fd = std::fs::OpenOptions::new()
        .write(true)
        .open(&alias)
        .unwrap()
        .into();
    let records = Records::new(0);
    let (mut client, task, body) = fx.start(
        Verb::FsWrite {
            path: alias.to_str().unwrap().into(),
            content: Bytes::new(b"verified-alias-effect".to_vec().into()),
            mode: WriteMode::Existing,
        },
        Some(fd),
        records.clone(),
    );
    maknae_proto::write_frame(&mut client, &body).await.unwrap();
    assert!(matches!(
        next_response(&mut client).await.unwrap().result,
        RespResult::Ok(Payload::MutationComplete)
    ));
    task.await.unwrap();
    assert_eq!(std::fs::read(&target).unwrap(), b"verified-alias-effect");
    let records = records.snapshot();
    assert_eq!(records.len(), 3);
    for record in &records[1..] {
        assert_eq!(record.object.as_deref(), target.to_str());
        assert_eq!(record.object_requested.as_deref(), alias.to_str());
    }
    assert_eq!(
        records[1].mutation.as_ref().unwrap().authorized_paths,
        vec![target.to_str().unwrap()]
    );
    assert_eq!(
        records[2].mutation.as_ref().unwrap().status,
        maknae_audit_append::MutationStatus::Applied
    );
}

struct GateRecords {
    records: Mutex<Vec<AuditRecord>>,
    gate_at: usize,
    entered: tokio::sync::Notify,
    release: tokio::sync::Notify,
}
impl GateRecords {
    fn new(gate_at: usize) -> Arc<Self> {
        Arc::new(Self {
            records: Mutex::new(Vec::new()),
            gate_at,
            entered: tokio::sync::Notify::new(),
            release: tokio::sync::Notify::new(),
        })
    }
}
impl AuditEmit for GateRecords {
    fn emit(
        &self,
        record: &AuditRecord,
    ) -> impl std::future::Future<Output = Result<(), AuditError>> + Send {
        let wait = {
            let mut records = self.records.lock().unwrap();
            records.push(record.clone());
            records.len() == self.gate_at
        };
        async move {
            if wait {
                self.entered.notify_one();
                self.release.notified().await;
            }
            Ok(())
        }
    }
}
async fn next_response(client: &mut tokio::io::DuplexStream) -> Option<maknae_proto::Response> {
    tokio::time::timeout(
        Duration::from_secs(2),
        maknae_proto::read_frame(client, 65536),
    )
    .await
    .ok()?
    .ok()
    .and_then(|b| maknae_proto::decode_response(&b).ok())
}
async fn namespace_start(
    fx: &Fixture,
    records: Arc<impl AuditEmit + Send + Sync + 'static>,
    verb: Verb,
) -> (tokio::io::DuplexStream, tokio::task::JoinHandle<()>) {
    let fd = std::fs::File::open(&fx.root).unwrap().into();
    let (mut client, task, body) = fx.start(verb, Some(fd), records);
    maknae_proto::write_frame(&mut client, &body).await.unwrap();
    (client, task)
}
fn create_verb(fx: &Fixture) -> Verb {
    Verb::FsWrite {
        path: fx
            .root
            .join("unique-created-client-sentinel")
            .to_str()
            .unwrap()
            .into(),
        content: Bytes::new(b"content".to_vec().into()),
        mode: WriteMode::CreateExclusive,
    }
}
async fn send_report(client: &mut tokio::io::DuplexStream, report: &maknae_proto::MutationReport) {
    maknae_proto::write_frame(
        client,
        &maknae_proto::encode_mutation_report(report).unwrap(),
    )
    .await
    .unwrap();
}
async fn ack(client: &mut tokio::io::DuplexStream) -> Option<maknae_proto::MutationAck> {
    tokio::time::timeout(
        Duration::from_secs(2),
        maknae_proto::read_frame(client, 65536),
    )
    .await
    .ok()?
    .ok()
    .and_then(|b| maknae_proto::decode_mutation_ack(&b).ok())
}
#[tokio::test]
async fn namespace_grant_requires_durable_intent_and_never_creates_as_daemon() {
    let fx = Fixture::new("grant_order", "Write");
    let records = GateRecords::new(2);
    let (mut client, task) = namespace_start(&fx, records.clone(), create_verb(&fx)).await;
    records.entered.notified().await;
    assert!(tokio::time::timeout(
        Duration::from_millis(20),
        maknae_proto::read_frame(&mut client, 65536)
    )
    .await
    .is_err());
    assert!(!fx.root.join("unique-created-client-sentinel").exists());
    records.release.notify_one();
    assert!(matches!(
        next_response(&mut client).await.unwrap().result,
        RespResult::Ok(Payload::MutationAttempt(_))
    ));
    assert!(!fx.root.join("unique-created-client-sentinel").exists());
    drop(client);
    task.await.unwrap();
}
#[tokio::test]
async fn false_namespace_success_is_only_client_reported_and_ack_waits_for_audit() {
    use maknae_proto::{EffectEntry, MutationReport, ReportedEffect, ReportedFinish};
    let fx = Fixture::new("false_client_success", "Write");
    let records = GateRecords::new(3);
    let (mut client, task) = namespace_start(&fx, records.clone(), create_verb(&fx)).await;
    let RespResult::Ok(Payload::MutationAttempt(grant)) =
        next_response(&mut client).await.unwrap().result
    else {
        panic!("expected grant")
    };
    let target = fx.root.join("unique-created-client-sentinel");
    send_report(
        &mut client,
        &MutationReport::Batch {
            id: grant.id,
            first_index: 0,
            effects: vec![EffectEntry {
                path: target.to_str().unwrap().into(),
                effect: ReportedEffect::CreatedFile,
            }],
        },
    )
    .await;
    records.entered.notified().await;
    assert!(tokio::time::timeout(
        Duration::from_millis(20),
        maknae_proto::read_frame(&mut client, 65536)
    )
    .await
    .is_err());
    records.release.notify_one();
    assert_eq!(ack(&mut client).await.unwrap().next_index, 1);
    send_report(
        &mut client,
        &MutationReport::Finished {
            id: grant.id,
            next_index: 1,
            outcome: ReportedFinish::Success,
            stopped_at: None,
        },
    )
    .await;
    assert_eq!(ack(&mut client).await.unwrap().next_index, 1);
    task.await.unwrap();
    assert!(
        !target.exists(),
        "false reports must never cause daemon namespace effects"
    );
    let records = records.records.lock().unwrap();
    for rec in &records[2..] {
        assert_eq!(
            rec.mutation.as_ref().unwrap().origin,
            maknae_audit_append::MutationOrigin::ClientReported
        );
    }
    assert_eq!(
        records.last().unwrap().mutation.as_ref().unwrap().status,
        maknae_audit_append::MutationStatus::ReportedSuccess
    );
}
#[tokio::test]
async fn mismatched_report_and_failed_report_audit_send_no_ack() {
    for (tag, fail, wrong) in [("wrong_id", 0, true), ("report_audit_failure", 3, false)] {
        let fx = Fixture::new(tag, "Write");
        let records = Records::new(fail);
        let (mut client, task) = namespace_start(&fx, records.clone(), create_verb(&fx)).await;
        let RespResult::Ok(Payload::MutationAttempt(grant)) =
            next_response(&mut client).await.unwrap().result
        else {
            panic!("expected grant")
        };
        let mut id = grant.id;
        if wrong {
            id.session_id += 1;
        }
        send_report(
            &mut client,
            &maknae_proto::MutationReport::Finished {
                id,
                next_index: 0,
                outcome: maknae_proto::ReportedFinish::OsRefused,
                stopped_at: Some(
                    fx.root
                        .join("unique-created-client-sentinel")
                        .to_str()
                        .unwrap()
                        .into(),
                ),
            },
        )
        .await;
        assert!(ack(&mut client).await.is_none());
        task.await.unwrap();
        assert!(!fx.root.join("unique-created-client-sentinel").exists());
        if wrong {
            assert_eq!(
                records
                    .snapshot()
                    .last()
                    .unwrap()
                    .mutation
                    .as_ref()
                    .unwrap()
                    .status,
                maknae_audit_append::MutationStatus::Incomplete
            );
        }
    }
}
#[tokio::test]
async fn cancelled_socket_waiter_does_not_cancel_existing_effect_completion_owner() {
    let fx = Fixture::new("cancel_waiter", "Write");
    let target = fx.root.join("unique-existing-write-sentinel");
    std::fs::write(&target, b"original").unwrap();
    let records = GateRecords::new(2);
    let fd = std::fs::OpenOptions::new()
        .write(true)
        .open(&target)
        .unwrap()
        .into();
    let (mut client, task, body) = fx.start(
        Verb::FsWrite {
            path: target.to_str().unwrap().into(),
            content: Bytes::new(b"surviving-worker-effect".to_vec().into()),
            mode: WriteMode::Existing,
        },
        Some(fd),
        records.clone(),
    );
    maknae_proto::write_frame(&mut client, &body).await.unwrap();
    records.entered.notified().await;
    assert_eq!(
        std::fs::read(&target).unwrap(),
        b"original",
        "effect must wait for durable intent"
    );
    task.abort();
    let _ = task.await;
    drop(client);
    records.release.notify_one();
    tokio::time::timeout(Duration::from_secs(2), async {
        loop {
            if records.records.lock().unwrap().len() == 3 {
                break;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    assert_eq!(std::fs::read(target).unwrap(), b"surviving-worker-effect");
    assert_eq!(
        records.records.lock().unwrap()[2]
            .mutation
            .as_ref()
            .unwrap()
            .status,
        maknae_audit_append::MutationStatus::Applied
    );
}
#[tokio::test]
async fn mkdir_every_prefix_is_decided_and_alias_deny_uses_verified_path() {
    let fx = Fixture::new("mkdir_prefix_deny", "Write");
    let policy="schema_version: 1\npermissions:\n  allow:\n    - \"Write(~/**)\"\n  deny:\n    - \"Write(~/blocked)\"\nbindings:\n  user: [\"root\"]\n";
    std::fs::write(fx.root.join("authz.yaml"), policy).unwrap();
    let records = Records::new(0);
    let (mut client, task) = namespace_start(
        &fx,
        records.clone(),
        Verb::FsMkdir {
            path: fx.root.join("blocked/child").to_str().unwrap().into(),
            parents: true,
            components: vec!["blocked".into(), "child".into()],
        },
    )
    .await;
    assert!(matches!(
        next_response(&mut client).await.unwrap().result,
        RespResult::Err(_)
    ));
    task.await.unwrap();
    assert!(!fx.root.join("blocked").exists());
    assert!(
        records.snapshot()[1].outcome.reason.contains("den"),
        "{:?}",
        records.snapshot()
    );
    let target = fx.root.join("blocked");
    std::fs::write(&target, b"denied-sentinel").unwrap();
    let alias = fx.root.join("allowed-alias");
    std::os::unix::fs::symlink(&target, &alias).unwrap();
    let fd = std::fs::OpenOptions::new()
        .write(true)
        .open(&alias)
        .unwrap()
        .into();
    let records = Records::new(0);
    let (mut client, task, body) = fx.start(
        Verb::FsWrite {
            path: alias.to_str().unwrap().into(),
            content: Bytes::new(b"bad".to_vec().into()),
            mode: WriteMode::Existing,
        },
        Some(fd),
        records.clone(),
    );
    maknae_proto::write_frame(&mut client, &body).await.unwrap();
    assert!(matches!(
        next_response(&mut client).await.unwrap().result,
        RespResult::Err(_)
    ));
    task.await.unwrap();
    assert_eq!(std::fs::read(&target).unwrap(), b"denied-sentinel");
    assert_eq!(records.snapshot()[1].object.as_deref(), target.to_str());
    assert_eq!(
        records.snapshot()[1].object_requested.as_deref(),
        alias.to_str()
    );
}

#[tokio::test]
async fn user_and_admin_share_write_policy_and_bad_mkdir_suffix_cannot_grant() {
    for role in ["user", "admin"] {
        let fx = Fixture::new(&format!("same_policy_{role}"), "Write");
        let policy = std::fs::read_to_string(fx.root.join("authz.yaml"))
            .unwrap()
            .replace("  user:", &format!("  {role}:"));
        std::fs::write(fx.root.join("authz.yaml"), policy).unwrap();
        let target = fx.root.join("unique-existing-write-sentinel");
        std::fs::write(&target, b"before").unwrap();
        assert!(matches!(
            drive(&fx, b"same-rule", Records::new(0), true)
                .await
                .unwrap()
                .result,
            RespResult::Ok(Payload::MutationComplete)
        ));
        assert_eq!(std::fs::read(target).unwrap(), b"same-rule");
        for (asked, components) in [
            ("allowed", vec!["other".into()]),
            ("allowed", vec!["..".into()]),
            ("allowed", Vec::new()),
        ] {
            let (mut client, task) = namespace_start(
                &fx,
                Records::new(0),
                Verb::FsMkdir {
                    path: fx.root.join(asked).to_str().unwrap().into(),
                    parents: true,
                    components,
                },
            )
            .await;
            assert!(matches!(
                next_response(&mut client).await.unwrap().result,
                RespResult::Err(_)
            ));
            task.await.unwrap();
        }
    }
}

#[tokio::test]
async fn mkdir_depth_limit_grants_128_prefixes_and_refuses_129_before_intent() {
    for (depth, allowed) in [(128, true), (129, false)] {
        let fx = Fixture::new(&format!("mkdir_depth_{depth}"), "Write");
        // Short components keep both the request and the grant inside frame/path
        // limits, isolating the number of namespace effects that can be granted.
        let mut components = vec!["d".to_string(); depth];
        components[0] = "unique-depth-sentinel".into();
        let target = fx.root.join(components.join("/"));
        let records = Records::new(0);
        let (mut client, task) = namespace_start(
            &fx,
            records.clone(),
            Verb::FsMkdir {
                path: target.to_str().unwrap().into(),
                parents: true,
                components,
            },
        )
        .await;
        let response = next_response(&mut client).await;
        if !allowed {
            let records = records.snapshot();
            assert!(
                records.iter().all(|record| record.mutation.is_none()),
                "over-depth requests must be refused before any mutation intent: {records:?}"
            );
        }
        let response = response.expect("valid requests and explicit preparation refusals respond");
        if allowed {
            let RespResult::Ok(Payload::MutationAttempt(grant)) = response.result else {
                panic!(
                    "128 missing prefixes must be authorizable: {:?}",
                    records.snapshot()
                );
            };
            let maknae_proto::MutationScope::Directories { paths } = grant.scope else {
                panic!("mkdir parents requires explicit prefix scope");
            };
            assert_eq!(paths.len(), 128);
            assert_eq!(
                paths.first().unwrap(),
                fx.root.join("unique-depth-sentinel").to_str().unwrap()
            );
            assert_eq!(paths.last().unwrap(), target.to_str().unwrap());
            assert_eq!(
                records.snapshot()[1]
                    .mutation
                    .as_ref()
                    .unwrap()
                    .authorized_paths,
                paths
            );
        } else {
            assert!(
                matches!(response.result, RespResult::Err(_)),
                "129 prefixes must not receive a grant"
            );
        }
        drop(client);
        task.await.unwrap();
        assert!(!fx.root.join("unique-depth-sentinel").exists());
        if !allowed {
            let records = records.snapshot();
            assert_eq!(
                records.len(),
                2,
                "over-depth requests must not commit intent"
            );
            assert!(records[1].mutation.is_none());
            assert_eq!(records[1].outcome.result, "deny");
        }
    }
}

#[tokio::test]
async fn noop_mkdir_success_is_client_reported_with_zero_effects() {
    let fx = Fixture::new("noop_mkdir", "Write");
    let records = Records::new(0);
    std::fs::create_dir(fx.root.join("existing")).unwrap();
    let (mut client, task) = namespace_start(
        &fx,
        records.clone(),
        Verb::FsMkdir {
            path: fx.root.join("existing").to_str().unwrap().into(),
            parents: true,
            components: vec!["existing".into()],
        },
    )
    .await;
    let RespResult::Ok(Payload::MutationAttempt(grant)) =
        next_response(&mut client).await.unwrap().result
    else {
        panic!("expected grant")
    };
    send_report(
        &mut client,
        &maknae_proto::MutationReport::Finished {
            id: grant.id,
            next_index: 0,
            outcome: maknae_proto::ReportedFinish::Success,
            stopped_at: None,
        },
    )
    .await;
    assert_eq!(ack(&mut client).await.unwrap().next_index, 0);
    task.await.unwrap();
    let records = records.snapshot();
    assert_eq!(
        records[1].mutation.as_ref().unwrap().operation,
        Some(maknae_audit_append::MutationOperation::Mkdir)
    );
    assert_eq!(
        records[1].mutation.as_ref().unwrap().authorized_paths,
        vec![fx.root.join("existing").to_str().unwrap()]
    );
    assert_eq!(
        records[2].mutation.as_ref().unwrap().status,
        maknae_audit_append::MutationStatus::ReportedSuccess
    );
}
#[tokio::test]
async fn namespace_progress_does_not_extend_configured_absolute_deadline() {
    let fx = Fixture::new("absolute_deadline", "Write");
    let records = Records::new(0);
    let mut config = maknae_config::transport_from_section(None).unwrap();
    config.read_timeout_ms = 500;
    let fd = std::fs::File::open(&fx.root).unwrap().into();
    let verb = Verb::FsDelete {
        path: fx.root.join("tree").to_str().unwrap().into(),
        recursive: true,
    };
    let (mut client, task, body) = fx.start_with_config(verb, Some(fd), records.clone(), config);
    maknae_proto::write_frame(&mut client, &body).await.unwrap();
    let RespResult::Ok(Payload::MutationAttempt(grant)) =
        next_response(&mut client).await.unwrap().result
    else {
        panic!("expected grant")
    };
    assert_eq!(grant.limits.deadline_ms, 500);
    tokio::time::sleep(Duration::from_millis(200)).await;
    send_report(
        &mut client,
        &maknae_proto::MutationReport::Batch {
            id: grant.id,
            first_index: 0,
            effects: vec![maknae_proto::EffectEntry {
                path: fx.root.join("tree/child").to_str().unwrap().into(),
                effect: maknae_proto::ReportedEffect::DeletedEntry,
            }],
        },
    )
    .await;
    assert_eq!(ack(&mut client).await.unwrap().next_index, 1);
    tokio::time::sleep(Duration::from_millis(350)).await;
    assert!(
        matches!(
            tokio::time::timeout(
                Duration::from_millis(50),
                maknae_proto::read_frame(&mut client, 65536)
            )
            .await,
            Ok(Err(_))
        ),
        "the absolute deadline must close before another per-report window expires"
    );
    task.await.unwrap();
    assert_eq!(
        records
            .snapshot()
            .last()
            .unwrap()
            .mutation
            .as_ref()
            .unwrap()
            .status,
        maknae_audit_append::MutationStatus::Incomplete
    );
}

#[tokio::test]
async fn renamed_existing_object_after_intent_reports_no_effect_without_rollback_claim() {
    let fx = Fixture::new("late_rename", "Write");
    let target = fx.root.join("unique-existing-write-sentinel");
    std::fs::write(&target, b"unmodified-after-rename").unwrap();
    let records = GateRecords::new(2);
    let fd = std::fs::OpenOptions::new()
        .write(true)
        .open(&target)
        .unwrap()
        .into();
    let (mut client, task, body) = fx.start(
        Verb::FsWrite {
            path: target.to_str().unwrap().into(),
            content: Bytes::new(Vec::new().into()),
            mode: WriteMode::Existing,
        },
        Some(fd),
        records.clone(),
    );
    maknae_proto::write_frame(&mut client, &body).await.unwrap();
    records.entered.notified().await;
    let renamed = fx.root.join("renamed-sentinel");
    std::fs::rename(&target, &renamed).unwrap();
    records.release.notify_one();
    assert!(matches!(
        next_response(&mut client).await.unwrap().result,
        RespResult::Err(_)
    ));
    task.await.unwrap();
    assert_eq!(std::fs::read(renamed).unwrap(), b"unmodified-after-rename");
    assert_eq!(
        records.records.lock().unwrap()[2]
            .mutation
            .as_ref()
            .unwrap()
            .status,
        maknae_audit_append::MutationStatus::NoEffect
    );
}
#[tokio::test]
async fn every_client_finish_category_keeps_its_typed_origin_and_stopped_path() {
    use maknae_audit_append::MutationStatus as S;
    use maknae_proto::ReportedFinish as F;
    for (index, outcome, expected) in [
        (0, F::Partial, S::ReportedPartial),
        (1, F::LimitReached, S::ReportedLimitReached),
        (2, F::PathChanged, S::ReportedPathChanged),
        (3, F::UnsupportedName, S::ReportedUnsupportedName),
        (4, F::DurabilityUnknown, S::ReportedDurabilityUnknown),
    ] {
        let fx = Fixture::new(&format!("finish_category_{index}"), "Write");
        let records = Records::new(0);
        let target = fx.root.join("entry");
        let (mut client, task) = namespace_start(
            &fx,
            records.clone(),
            Verb::FsDelete {
                path: target.to_str().unwrap().into(),
                recursive: false,
            },
        )
        .await;
        let RespResult::Ok(Payload::MutationAttempt(grant)) =
            next_response(&mut client).await.unwrap().result
        else {
            panic!("expected grant")
        };
        send_report(
            &mut client,
            &maknae_proto::MutationReport::Finished {
                id: grant.id,
                next_index: 0,
                outcome,
                stopped_at: Some(target.to_str().unwrap().into()),
            },
        )
        .await;
        assert!(ack(&mut client).await.is_some());
        task.await.unwrap();
        let records = records.snapshot();
        let meta = records[2].mutation.as_ref().unwrap();
        assert_eq!(meta.status, expected);
        assert_eq!(meta.stopped_at.as_deref(), target.to_str());
        assert_eq!(
            meta.origin,
            maknae_audit_append::MutationOrigin::ClientReported
        );
        assert_eq!(
            records[1].mutation.as_ref().unwrap().operation,
            Some(maknae_audit_append::MutationOperation::DeleteEntry)
        );
    }
}
#[tokio::test]
async fn oversized_grant_is_withheld_even_when_the_prepare_frame_fits() {
    let fx = Fixture::new("oversize_grant", "Write");
    let records = Records::new(0);
    let components = vec!["x".to_string(); 64];
    let asked = fx.root.join(components.join("/"));
    let verb = Verb::FsMkdir {
        path: asked.to_str().unwrap().into(),
        parents: true,
        components,
    };
    let mut config = maknae_config::transport_from_section(None).unwrap();
    config.frame_max_bytes = 1024;
    let (mut client, task, body) = fx.start_with_config(
        verb,
        Some(std::fs::File::open(&fx.root).unwrap().into()),
        records.clone(),
        config,
    );
    assert!(body.len() < 1024);
    maknae_proto::write_frame(&mut client, &body).await.unwrap();
    assert!(next_response(&mut client).await.is_none());
    task.await.unwrap();
    let records = records.snapshot();
    assert_eq!(
        records[1].mutation.as_ref().unwrap().phase,
        maknae_audit_append::MutationPhase::Intent
    );
    assert_eq!(
        records[1].mutation.as_ref().unwrap().authorized_paths.len(),
        64
    );
    assert!(!fx.root.join("x").exists());
}

#[tokio::test]
async fn exact_grant_frame_budget_allows_reported_effect_but_one_byte_less_does_not() {
    let fx = Fixture::new("exact_grant_frame", "Write");
    let target = fx.root.join("unique-created-client-sentinel");
    // Measure an actual composed-policy grant. The next connection uses the
    // same request, correlation and timeout, so only its frame budget changes.
    let (mut client, task) = namespace_start(&fx, Records::new(0), create_verb(&fx)).await;
    let grant_bytes = maknae_proto::read_frame(&mut client, 65536).await.unwrap();
    assert!(matches!(
        maknae_proto::decode_response(&grant_bytes).unwrap().result,
        RespResult::Ok(Payload::MutationAttempt(_))
    ));
    drop(client);
    task.await.unwrap();
    for (shortfall, allowed) in [(1, false), (0, true)] {
        let records = Records::new(0);
        let mut config = maknae_config::transport_from_section(None).unwrap();
        config.frame_max_bytes = grant_bytes.len() - shortfall;
        let (mut client, task, body) = fx.start_with_config(
            create_verb(&fx),
            Some(std::fs::File::open(&fx.root).unwrap().into()),
            records.clone(),
            config,
        );
        assert!(body.len() < grant_bytes.len() - 1);
        maknae_proto::write_frame(&mut client, &body).await.unwrap();
        if allowed {
            let RespResult::Ok(Payload::MutationAttempt(grant)) = next_response(&mut client)
                .await
                .expect("a grant exactly at the cap fits")
                .result
            else {
                panic!("expected composed-policy grant at exact frame budget");
            };
            assert!(!target.exists(), "the grant has no daemon namespace effect");
            std::fs::write(&target, b"exact-frame-client-effect").unwrap();
            send_report(
                &mut client,
                &maknae_proto::MutationReport::Batch {
                    id: grant.id,
                    first_index: 0,
                    effects: vec![maknae_proto::EffectEntry {
                        path: target.to_str().unwrap().into(),
                        effect: maknae_proto::ReportedEffect::CreatedFile,
                    }],
                },
            )
            .await;
            assert_eq!(ack(&mut client).await.unwrap().next_index, 1);
            send_report(
                &mut client,
                &maknae_proto::MutationReport::Finished {
                    id: grant.id,
                    next_index: 1,
                    outcome: maknae_proto::ReportedFinish::Success,
                    stopped_at: None,
                },
            )
            .await;
            assert_eq!(ack(&mut client).await.unwrap().next_index, 1);
            task.await.unwrap();
            assert_eq!(
                std::fs::read(&target).unwrap(),
                b"exact-frame-client-effect"
            );
            let records = records.snapshot();
            let completion = records.last().unwrap().mutation.as_ref().unwrap();
            assert_eq!(
                completion.status,
                maknae_audit_append::MutationStatus::ReportedSuccess
            );
            assert_eq!(
                completion.origin,
                maknae_audit_append::MutationOrigin::ClientReported
            );
        } else {
            assert!(next_response(&mut client).await.is_none());
            task.await.unwrap();
            assert!(!target.exists());
            let records = records.snapshot();
            assert_eq!(records.len(), 2, "withheld grant must not accept effects");
            assert_eq!(
                records[1].mutation.as_ref().unwrap().phase,
                maknae_audit_append::MutationPhase::Intent
            );
        }
    }
}

#[test]
fn largest_ack_fits_below_every_grant_encoding_lower_bound() {
    use maknae_proto::{MutationAck, MutationGrant, MutationId, MutationLimits, MutationScope};
    // CBOR integers grow monotonically up to their type's maximum. Include
    // u32::MAX even though a live exchange caps next_index at 4096.
    let largest_ack = maknae_proto::encode_mutation_ack(&MutationAck {
        id: MutationId {
            session_id: u64::MAX,
            intent_seq: u64::MAX,
        },
        next_index: u32::MAX,
    })
    .unwrap();
    // Empty strings/collections and zero integers are lower bounds even for
    // shapes that live authorization would refuse. Every real scope is larger.
    for scope in [
        MutationScope::Exact {
            path: String::new(),
            effect: maknae_proto::ReportedEffect::CreatedFile,
        },
        MutationScope::RecursiveDelete {
            root: String::new(),
        },
        MutationScope::Directories { paths: Vec::new() },
    ] {
        let smallest_grant = maknae_proto::encode_response(&maknae_proto::Response {
            protocol_version: 0,
            result: RespResult::Ok(Payload::MutationAttempt(MutationGrant {
                id: MutationId {
                    session_id: 0,
                    intent_seq: 0,
                },
                scope,
                limits: MutationLimits {
                    max_effects: 0,
                    max_depth: 0,
                    deadline_ms: 0,
                },
            })),
        })
        .unwrap();
        assert!(
            largest_ack.len() < smallest_grant.len(),
            "a frame cap that admitted a grant must fit every ack (ack {}, grant {})",
            largest_ack.len(),
            smallest_grant.len()
        );
    }
}

struct FailWrites<S> {
    inner: S,
    fail: Arc<std::sync::atomic::AtomicBool>,
}
impl<S: tokio::io::AsyncRead + Unpin> tokio::io::AsyncRead for FailWrites<S> {
    fn poll_read(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}
impl<S: tokio::io::AsyncWrite + Unpin> tokio::io::AsyncWrite for FailWrites<S> {
    fn poll_write(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        if self.fail.load(std::sync::atomic::Ordering::SeqCst) {
            std::task::Poll::Ready(Err(std::io::Error::new(
                std::io::ErrorKind::BrokenPipe,
                "injected response write refusal",
            )))
        } else {
            std::pin::Pin::new(&mut self.inner).poll_write(cx, buf)
        }
    }
    fn poll_flush(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.inner).poll_flush(cx)
    }
    fn poll_shutdown(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}
#[tokio::test]
async fn failed_grant_or_ack_write_stops_before_accepting_more_client_reports() {
    for (tag, fail_grant) in [("grant_write_failed", true), ("ack_write_failed", false)] {
        let fx = Fixture::new(tag, "Write");
        let records = Records::new(0);
        let fail = Arc::new(std::sync::atomic::AtomicBool::new(fail_grant));
        let (mut client, server) = tokio::io::duplex(65536);
        let fds = maknae_io::DelegatedFds::new(4);
        fds.push(std::fs::File::open(&fx.root).unwrap().into());
        let task = tokio::spawn(maknae_kernel::handle(
            FailWrites {
                inner: server,
                fail: fail.clone(),
            },
            "maknae://d/plane/cli".into(),
            0,
            true,
            records.clone(),
            718,
            maknae_config::transport_from_section(None).unwrap(),
            serde_json::json!({}),
            fx.authorizer(),
            Arc::new(fx.principal.clone()),
            Arc::new(Default::default()),
            Arc::new("basic+ceiling".into()),
            Arc::new("US".into()),
            Duration::from_secs(2),
            maknae_security::Lane::Local,
            fds,
        ));
        let request = maknae_proto::encode_request(&maknae_proto::Request {
            protocol_version: maknae_proto::PROTOCOL_VERSION,
            verb: create_verb(&fx),
        })
        .unwrap();
        let id = maknae_proto::MutationId {
            session_id: 718,
            intent_seq: 2,
        };
        let first = maknae_proto::MutationReport::Batch {
            id,
            first_index: 0,
            effects: vec![maknae_proto::EffectEntry {
                path: fx
                    .root
                    .join("unique-created-client-sentinel")
                    .to_str()
                    .unwrap()
                    .into(),
                effect: maknae_proto::ReportedEffect::CreatedFile,
            }],
        };
        let finish = maknae_proto::MutationReport::Finished {
            id,
            next_index: 1,
            outcome: maknae_proto::ReportedFinish::Success,
            stopped_at: None,
        };
        // Queue reports before the server is polled when the grant itself fails.
        // This proves a failed outbound frame cannot be ignored while accepting input.
        maknae_proto::write_frame(&mut client, &request)
            .await
            .unwrap();
        if !fail_grant {
            assert!(matches!(
                next_response(&mut client).await.unwrap().result,
                RespResult::Ok(Payload::MutationAttempt(_))
            ));
            fail.store(true, std::sync::atomic::Ordering::SeqCst);
        }
        send_report(&mut client, &first).await;
        send_report(&mut client, &finish).await;
        task.await.unwrap();
        assert!(ack(&mut client).await.is_none());
        assert_eq!(
            records.snapshot().len(),
            if fail_grant { 2 } else { 3 },
            "a failed outbound grant/ack must stop the exchange"
        );
        assert!(!fx.root.join("unique-created-client-sentinel").exists());
    }
}

#[tokio::test]
async fn single_mkdir_grants_exact_created_directory_and_success_requires_one_effect() {
    use maknae_proto::{
        EffectEntry, MutationReport, MutationScope, ReportedEffect, ReportedFinish,
    };
    for report_effect in [false, true] {
        let fx = Fixture::new(
            if report_effect {
                "single_mkdir_effect"
            } else {
                "single_mkdir_no_effect"
            },
            "Write",
        );
        let records = Records::new(0);
        let target = fx.root.join("single-created-directory-sentinel");
        let (mut client, task) = namespace_start(
            &fx,
            records.clone(),
            Verb::FsMkdir {
                path: target.to_str().unwrap().into(),
                parents: false,
                components: vec!["single-created-directory-sentinel".into()],
            },
        )
        .await;
        let RespResult::Ok(Payload::MutationAttempt(grant)) =
            next_response(&mut client).await.unwrap().result
        else {
            panic!("expected a real composed-policy grant");
        };
        assert_eq!(
            grant.scope,
            MutationScope::Exact {
                path: target.to_str().unwrap().into(),
                effect: ReportedEffect::CreatedDirectory
            },
            "single mkdir must use the exact scope consumed by the CLI"
        );
        assert!(
            !target.exists(),
            "grant issuance itself must not create the directory"
        );
        if report_effect {
            std::fs::create_dir(&target).unwrap();
            send_report(
                &mut client,
                &MutationReport::Batch {
                    id: grant.id,
                    first_index: 0,
                    effects: vec![EffectEntry {
                        path: target.to_str().unwrap().into(),
                        effect: ReportedEffect::CreatedDirectory,
                    }],
                },
            )
            .await;
            assert_eq!(ack(&mut client).await.unwrap().next_index, 1);
        }
        send_report(
            &mut client,
            &MutationReport::Finished {
                id: grant.id,
                next_index: u32::from(report_effect),
                outcome: ReportedFinish::Success,
                stopped_at: None,
            },
        )
        .await;
        if report_effect {
            assert_eq!(ack(&mut client).await.unwrap().next_index, 1);
        } else {
            assert!(
                ack(&mut client).await.is_none(),
                "zero-effect Success is invalid for single mkdir"
            );
        }
        task.await.unwrap();
        let records = records.snapshot();
        assert_eq!(
            records.last().unwrap().mutation.as_ref().unwrap().status,
            if report_effect {
                maknae_audit_append::MutationStatus::ReportedSuccess
            } else {
                maknae_audit_append::MutationStatus::Incomplete
            }
        );
        assert_eq!(target.exists(), report_effect);
    }
}
