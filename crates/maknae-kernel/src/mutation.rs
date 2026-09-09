//! Mutation preparation and the durable-intent gate. Namespace facts remain
//! client reported. Only an existing writable object executes in the daemon.
use crate::{
    handler::{build_authz_request, delegated_plan, discharge_plan, lexical_pregate},
    MutationExchange,
};
use maknae_audit_append::{
    AuditEmit, AuditRecord, MutationAudit, MutationEffectKind, MutationEffectRecord,
    MutationOperation, MutationOrigin, MutationPhase, MutationStatus, Seq,
};
use maknae_config::{Principal, TransportConfig};
use maknae_io::{MutationDirectory, MutationRequired, WritableObject};
use maknae_proto::{
    Bytes, MutationGrant, MutationId, MutationLimits, MutationReport, MutationScope, Payload,
    ProtoErrCode, ProtoError, ReportedEffect, ReportedFinish, RespResult, Response, Verb,
    WriteMode, PROTOCOL_VERSION,
};
use maknae_security::{AttrValue, Authorizer, Decision, FsOperation, Lane};
use std::{
    os::fd::OwnedFd,
    path::Path,
    sync::{Arc, OnceLock},
    time::Duration,
};
use tokio::{
    io::{AsyncRead, AsyncWrite},
    sync::{OwnedSemaphorePermit, Semaphore},
};

/// No orphan reclamation: the permit follows the actual blocking worker and its
/// completion owner, even when the socket's waiter has gone away.
static CAPACITY: OnceLock<Arc<Semaphore>> = OnceLock::new();
const MAX_WORKERS: usize = 16;
fn capacity() -> Arc<Semaphore> {
    Arc::clone(CAPACITY.get_or_init(|| Arc::new(Semaphore::new(MAX_WORKERS))))
}

enum Operation {
    Existing {
        object: WritableObject,
        bytes: Bytes,
    },
    Namespace {
        _directory: MutationDirectory,
        scope: MutationScope,
    },
}
struct PreparedMutation {
    operation: Operation,
    paths: Vec<String>,
    kind: FsOperation,
}
struct DurableIntent {
    record: AuditRecord,
}

fn path(verb: &Verb) -> Option<&str> {
    match verb {
        Verb::FsWrite { path, .. } | Verb::FsDelete { path, .. } | Verb::FsMkdir { path, .. } => {
            Some(path)
        }
        _ => None,
    }
}
fn normal(component: &str) -> bool {
    !component.is_empty()
        && component != "."
        && component != ".."
        && !component.contains('/')
        && !component.contains('\0')
}
fn checked(path: &str) -> Result<(), String> {
    if path.len() > maknae_proto::MAX_MUTATION_PATH_BYTES || path.contains('\0') {
        return Err("mutation path limit or NUL".into());
    }
    lexical_pregate(path).map_err(str::to_owned)
}
fn prepare(
    verb: Verb,
    fd: Option<OwnedFd>,
    principal: &Principal,
    lane: Lane,
) -> Result<PreparedMutation, String> {
    let asked = path(&verb).ok_or("not a mutation")?;
    checked(asked)?;
    if lane != Lane::Local {
        return Err("mutation requires local subject execution".into());
    }
    let fd = fd.ok_or("mutation descriptor missing")?;
    if let Verb::FsWrite {
        content,
        mode: WriteMode::Existing,
        ..
    } = verb
    {
        let object = maknae_io::verify_writable_object(
            fd,
            delegated_plan(&principal.home, principal.uid, None),
        )
        .map_err(|e| format!("writable evidence refused: {e}"))?;
        let path = object
            .path()
            .to_str()
            .ok_or("non-UTF-8 object path")?
            .to_owned();
        checked(&path)?;
        return Ok(PreparedMutation {
            operation: Operation::Existing {
                object,
                bytes: content,
            },
            paths: vec![path],
            kind: FsOperation::WriteExisting,
        });
    }
    let directory = maknae_io::verify_mutation_directory(
        fd,
        MutationRequired {
            confined_beneath: principal.home.clone(),
            root_required: delegated_plan(&principal.home, principal.uid, None).root_required,
        },
    )
    .map_err(|e| format!("namespace location evidence refused: {e}"))?;
    let mut current = directory.path().to_path_buf();
    let components = match &verb {
        Verb::FsMkdir {
            components,
            parents,
            ..
        } => {
            if components.is_empty()
                || components.len() > usize::from(maknae_proto::MAX_MUTATION_DEPTH)
                || (!parents && components.len() != 1)
            {
                return Err("invalid mkdir suffix length".into());
            }
            if components.iter().any(|c| !normal(c)) {
                return Err("invalid mkdir component".into());
            }
            let requested: Vec<_> = asked.split('/').skip(1).collect();
            if !requested.ends_with(&components.iter().map(String::as_str).collect::<Vec<_>>()) {
                return Err("mkdir suffix does not match requested path".into());
            }
            components.clone()
        }
        _ => vec![Path::new(asked)
            .file_name()
            .and_then(|p| p.to_str())
            .filter(|p| normal(p))
            .ok_or("missing normal leaf")?
            .to_owned()],
    };
    let mut paths = Vec::with_capacity(components.len());
    for component in components {
        current.push(component);
        let p = current
            .to_str()
            .ok_or("non-UTF-8 namespace path")?
            .to_owned();
        checked(&p)?;
        paths.push(p);
    }
    let root = paths.last().ok_or("missing mutation path")?.clone();
    let (kind, scope) = match verb {
        Verb::FsWrite {
            mode: WriteMode::CreateExclusive,
            ..
        } => (
            FsOperation::WriteCreate,
            MutationScope::Exact {
                path: root,
                effect: ReportedEffect::CreatedFile,
            },
        ),
        Verb::FsDelete { recursive, .. } => {
            if Path::new(&root) == principal.home {
                return Err("cannot delete confinement root".into());
            }
            if recursive {
                (
                    FsOperation::DeleteTree,
                    MutationScope::RecursiveDelete { root },
                )
            } else {
                (
                    FsOperation::DeleteEntry,
                    MutationScope::Exact {
                        path: root,
                        effect: ReportedEffect::DeletedEntry,
                    },
                )
            }
        }
        Verb::FsMkdir { parents, .. } => (
            FsOperation::Mkdir,
            if parents {
                MutationScope::Directories {
                    paths: paths.clone(),
                }
            } else {
                MutationScope::Exact {
                    path: root,
                    effect: ReportedEffect::CreatedDirectory,
                }
            },
        ),
        _ => return Err("invalid mutation operation".into()),
    };
    Ok(PreparedMutation {
        operation: Operation::Namespace {
            _directory: directory,
            scope,
        },
        paths,
        kind,
    })
}

/// Decide every path in the mutation. Returns the role the decision was made
/// on in BOTH arms (#275): a denied `fs.write` is the security-interesting
/// record, so stamping `role=none` on it while a role was in fact resolved
/// would defeat the point. When several paths are decided, the reported role is
/// the one from the last decision evaluated — on a deny, that is the path that
/// caused the refusal.
type AuthorizeErr = (String, String, Option<&'static str>);

fn authorize<P: Authorizer>(
    prepared: &PreparedMutation,
    verb: &Verb,
    uid: u32,
    authorizer: &P,
) -> Result<Option<&'static str>, AuthorizeErr> {
    let mut decided_role: Option<&'static str> = None;
    for path in &prepared.paths {
        let mut request = build_authz_request(verb, uid, Lane::Local, None, None);
        request
            .resource
            .0
            .insert("path", AttrValue::Str(path.clone()));
        request.context.0.insert(
            maknae_security::CONTEXT_FS_OPERATION,
            AttrValue::Str(prepared.kind.as_str().into()),
        );
        if matches!(prepared.operation, Operation::Existing { .. }) {
            request.resource.0.insert(
                maknae_security::RESOURCE_OS_ACCESSIBLE,
                AttrValue::Bool(true),
            );
        }
        // `combine(vec![..])` preserved: it is what produces the
        // "indeterminate operand blocks (fail-closed)" trail string.
        let (v, role) = maknae_security::guarded_decide_reporting_role(authorizer, &request);
        decided_role = role;
        match maknae_security::finalize(maknae_security::combine(vec![v])) {
            Decision::Permit { obligations } => discharge_plan(&obligations).map_err(|_| {
                (
                    "unhonorable mutation obligation".to_string(),
                    path.clone(),
                    decided_role,
                )
            })?,
            Decision::Deny { reason } => return Err((reason, path.clone(), decided_role)),
        }
    }
    Ok(decided_role)
}
fn mutation_meta(
    seq: u64,
    phase: MutationPhase,
    origin: MutationOrigin,
    status: MutationStatus,
) -> MutationAudit {
    MutationAudit {
        operation: None,
        authorized_paths: Vec::new(),
        intent_seq: seq,
        phase,
        origin,
        status,
        content_length: None,
        first_index: None,
        effects: Vec::new(),
        stopped_at: None,
    }
}
async fn commit_intent<E: AuditEmit>(
    emit: &E,
    mut record: AuditRecord,
    content_length: Option<u64>,
    kind: FsOperation,
    paths: Vec<String>,
) -> Result<DurableIntent, ()> {
    record.outcome.result = "permit".into();
    record.outcome.reason = "authorized; intent alone does not establish execution".into();
    record.outcome.posture = "authorized".into();
    let mut meta = mutation_meta(
        record.seq,
        MutationPhase::Intent,
        MutationOrigin::KernelObserved,
        MutationStatus::IntentOnly,
    );
    meta.content_length = content_length;
    meta.operation = Some(match kind {
        FsOperation::WriteExisting => MutationOperation::WriteExisting,
        FsOperation::WriteCreate => MutationOperation::WriteCreate,
        FsOperation::DeleteEntry => MutationOperation::DeleteEntry,
        FsOperation::DeleteTree => MutationOperation::DeleteTree,
        FsOperation::Mkdir => MutationOperation::Mkdir,
    });
    meta.authorized_paths = paths;
    record.mutation = Some(meta);
    emit.emit(&record).await.map_err(|_| ())?;
    Ok(DurableIntent { record })
}
fn completion(intent: &DurableIntent, seq: u64, status: MutationStatus) -> AuditRecord {
    let mut record = intent.record.clone();
    record.seq = seq;
    record.ts = crate::run::rfc3339_now();
    record.mutation = Some(mutation_meta(
        intent.record.seq,
        MutationPhase::Completion,
        MutationOrigin::KernelObserved,
        status,
    ));
    record.outcome.reason =
        "kernel-observed mutation outcome; authorization is separate from effect".into();
    record
}
async fn send<S: AsyncWrite + Unpin>(stream: &mut S, cfg: &TransportConfig, response: Response) {
    if let Ok(bytes) = maknae_proto::encode_response(&response) {
        if bytes.len() <= cfg.frame_max_bytes {
            let _ = tokio::time::timeout(
                Duration::from_millis(cfg.read_timeout_ms),
                maknae_proto::write_frame(stream, &bytes),
            )
            .await;
        }
    }
}
async fn refuse<S: AsyncWrite + Unpin, E: AuditEmit>(
    stream: &mut S,
    cfg: &TransportConfig,
    emit: &E,
    mut record: AuditRecord,
    reason: String,
) {
    record.outcome.result = "deny".into();
    record.outcome.reason = reason;
    record.outcome.posture = "unauthorized".into();
    if emit.emit(&record).await.is_ok() {
        send(
            stream,
            cfg,
            Response {
                protocol_version: PROTOCOL_VERSION,
                result: RespResult::Err(ProtoError {
                    code: ProtoErrCode::Unauthorized,
                    message: "not authorized".into(),
                }),
            },
        )
        .await;
    }
}

/// Called once after request decode. True means this connection is consumed.
#[allow(clippy::too_many_arguments)]
pub(crate) async fn handle<S, E, P>(
    stream: &mut S,
    verb: &Verb,
    uid: u32,
    lane: Lane,
    delegated: &maknae_io::DelegatedFds,
    authorizer: Arc<P>,
    emit: Arc<E>,
    principal: Arc<Principal>,
    cfg: &TransportConfig,
    seq: &Seq,
    mut record: AuditRecord,
    authz_timeout: Duration,
) -> bool
where
    S: AsyncRead + AsyncWrite + Unpin + Send,
    E: AuditEmit + Send + Sync + 'static,
    P: Authorizer + Send + Sync + 'static,
{
    let Some(asked) = path(verb) else {
        return false;
    };
    record.object = Some(asked.into());
    let permit = match capacity().try_acquire_owned() {
        Ok(p) => p,
        Err(_) => {
            refuse(
                stream,
                cfg,
                &*emit,
                record,
                "mutation worker budget exhausted".into(),
            )
            .await;
            return true;
        }
    };
    let fd = delegated.take();
    let original = verb.clone();
    let prepared = tokio::time::timeout(
        authz_timeout,
        tokio::task::spawn_blocking(move || {
            let prepared = prepare(original.clone(), fd, &principal, lane)?;
            let decision = authorize(&prepared, &original, uid, &*authorizer);
            Ok::<_, String>((prepared, permit, decision))
        }),
    )
    .await;
    let (prepared, permit, decision) = match prepared {
        Ok(Ok(Ok(p))) => p,
        Ok(Ok(Err(reason))) => {
            refuse(stream, cfg, &*emit, record, reason).await;
            return true;
        }
        _ => {
            refuse(
                stream,
                cfg,
                &*emit,
                record,
                "mutation preparation or policy timed out/failed".into(),
            )
            .await;
            return true;
        }
    };
    let decided = prepared
        .paths
        .last()
        .expect("prepared nonempty paths")
        .clone();
    if asked != decided {
        record.object_requested = Some(asked.into());
    }
    record.object = Some(decided);
    // #275: stamp the role BEFORE the deny branch, so the REFUSED mutation --
    // the security-interesting record -- attests the role it was refused under.
    // Both arms carry it; the permit arm alone would leave every denied
    // fs.write/fs.delete/fs.mkdir saying role=none while a role WAS resolved.
    record.subject.role = match &decision {
        Ok(role) => role.map(str::to_string),
        Err((_, _, role)) => role.map(str::to_string),
    };
    if let Err((reason, denied_path, _role)) = decision {
        record.object_requested = (asked != denied_path).then(|| asked.into());
        record.object = Some(denied_path);
        refuse(stream, cfg, &*emit, record, reason).await;
        return true;
    }
    match prepared.operation {
        Operation::Existing { object, bytes } => {
            let completion_seq = seq.next();
            // The detached owner retains the permit, result and completion obligation.
            // Dropping the socket waiter cannot orphan the effect's audit owner.
            let worker = tokio::spawn(async move {
                let intent = commit_intent(
                    &*emit,
                    record,
                    Some(bytes.0.len() as u64),
                    prepared.kind,
                    prepared.paths,
                )
                .await?;
                existing_worker(object, bytes, intent, completion_seq, permit, emit).await
            });
            if let Ok(Ok(Ok(applied))) =
                tokio::time::timeout(Duration::from_millis(cfg.read_timeout_ms), worker).await
            {
                if applied {
                    send(
                        stream,
                        cfg,
                        Response {
                            protocol_version: PROTOCOL_VERSION,
                            result: RespResult::Ok(Payload::MutationComplete),
                        },
                    )
                    .await;
                } else {
                    send(
                        stream,
                        cfg,
                        Response {
                            protocol_version: PROTOCOL_VERSION,
                            result: RespResult::Err(ProtoError {
                                code: ProtoErrCode::Unauthorized,
                                message: "not authorized".into(),
                            }),
                        },
                    )
                    .await;
                }
            }
        }
        Operation::Namespace { _directory, scope } => {
            let length = if let Verb::FsWrite { content, .. } = verb {
                Some(content.0.len() as u64)
            } else {
                None
            };
            if let Ok(Ok(intent)) = tokio::time::timeout(
                Duration::from_millis(cfg.read_timeout_ms),
                commit_intent(&*emit, record, length, prepared.kind, prepared.paths),
            )
            .await
            {
                namespace(stream, cfg, &*emit, intent, scope, seq).await;
            }
            drop(_directory);
            drop(permit);
        }
    }
    true
}
async fn existing_worker<E: AuditEmit + Send + Sync + 'static>(
    object: WritableObject,
    bytes: Bytes,
    intent: DurableIntent,
    completion_seq: u64,
    permit: OwnedSemaphorePermit,
    emit: Arc<E>,
) -> Result<bool, ()> {
    let result =
        tokio::task::spawn_blocking(move || maknae_io::replace_existing(object, &bytes.0)).await;
    let (status, succeeded) = match result {
        Ok(effect) => observed_result(effect),
        Err(_) => (MutationStatus::Incomplete, false),
    };
    let record = completion(&intent, completion_seq, status);
    let result = emit.emit(&record).await.map_err(|_| ());
    drop(permit);
    result?;
    Ok(succeeded)
}

/// Effect state cannot manufacture operation success: a failed operation may
/// already have applied its effect and must still receive no success response.
fn observed_result(result: Result<(), maknae_io::MutationFailure>) -> (MutationStatus, bool) {
    match result {
        Ok(()) => (MutationStatus::Applied, true),
        Err(failure) => (
            match failure.state {
                maknae_io::EffectState::NoEffect => MutationStatus::NoEffect,
                maknae_io::EffectState::Applied => MutationStatus::Applied,
                maknae_io::EffectState::Partial => MutationStatus::Partial,
                maknae_io::EffectState::DurabilityUnknown => MutationStatus::DurabilityUnknown,
            },
            false,
        ),
    }
}

async fn namespace<S: AsyncRead + AsyncWrite + Unpin, E: AuditEmit>(
    stream: &mut S,
    cfg: &TransportConfig,
    emit: &E,
    intent: DurableIntent,
    scope: MutationScope,
    seq: &Seq,
) {
    let id = MutationId {
        session_id: intent.record.session_id,
        intent_seq: intent.record.seq,
    };
    let limits = MutationLimits {
        max_effects: maknae_proto::MAX_MUTATION_EFFECTS,
        max_depth: maknae_proto::MAX_MUTATION_DEPTH,
        deadline_ms: cfg.read_timeout_ms,
    };
    let Ok(mut exchange) = MutationExchange::begin(id, scope.clone(), limits) else {
        return;
    };
    let grant = MutationGrant { id, scope, limits };
    let deadline = tokio::time::Instant::now() + Duration::from_millis(limits.deadline_ms);
    let Ok(bytes) = maknae_proto::encode_response(&Response {
        protocol_version: PROTOCOL_VERSION,
        result: RespResult::Ok(Payload::MutationAttempt(grant)),
    }) else {
        return;
    };
    if bytes.len() > cfg.frame_max_bytes
        || !matches!(
            tokio::time::timeout_at(deadline, maknae_proto::write_frame(stream, &bytes)).await,
            Ok(Ok(()))
        )
    {
        return;
    }
    loop {
        let result = tokio::time::timeout_at(
            deadline,
            maknae_proto::read_frame(stream, cfg.frame_max_bytes),
        )
        .await;
        let report = match result {
            Ok(Ok(bytes)) => maknae_proto::decode_mutation_report(&bytes).ok(),
            _ => None,
        };
        let Some(report) = report else {
            incomplete(
                cfg,
                emit,
                &intent,
                seq,
                "mutation report missing or malformed; effects unknown",
            )
            .await;
            return;
        };
        let Ok(pending) = exchange.validate_report(&report) else {
            incomplete(
                cfg,
                emit,
                &intent,
                seq,
                "mutation report rejected; effects unknown",
            )
            .await;
            return;
        };
        let mut record = completion(&intent, seq.next(), MutationStatus::ReportedProgress);
        let meta = record.mutation.as_mut().expect("completion metadata");
        meta.origin = MutationOrigin::ClientReported;
        let terminal = match &report {
            MutationReport::Batch {
                first_index,
                effects,
                ..
            } => {
                meta.phase = MutationPhase::Progress;
                meta.first_index = Some(*first_index);
                meta.effects = effects
                    .iter()
                    .map(|e| MutationEffectRecord {
                        path: e.path.clone(),
                        effect: match e.effect {
                            ReportedEffect::CreatedFile => MutationEffectKind::CreatedFile,
                            ReportedEffect::ReplacedFile => MutationEffectKind::ReplacedFile,
                            ReportedEffect::CreatedDirectory => {
                                MutationEffectKind::CreatedDirectory
                            }
                            ReportedEffect::DeletedEntry => MutationEffectKind::DeletedEntry,
                        },
                    })
                    .collect();
                false
            }
            MutationReport::Finished {
                next_index,
                outcome,
                stopped_at,
                ..
            } => {
                meta.first_index = Some(*next_index);
                meta.stopped_at = stopped_at.clone();
                meta.status = match outcome {
                    ReportedFinish::Success => MutationStatus::ReportedSuccess,
                    ReportedFinish::OsRefused => MutationStatus::ReportedOsRefused,
                    ReportedFinish::Partial => MutationStatus::ReportedPartial,
                    ReportedFinish::LimitReached => MutationStatus::ReportedLimitReached,
                    ReportedFinish::PathChanged => MutationStatus::ReportedPathChanged,
                    ReportedFinish::UnsupportedName => MutationStatus::ReportedUnsupportedName,
                    ReportedFinish::DurabilityUnknown => MutationStatus::ReportedDurabilityUnknown,
                };
                true
            }
        };
        record.outcome.reason =
            "authenticated client report; effects not independently observed".into();
        if !matches!(
            tokio::time::timeout_at(deadline, emit.emit(&record)).await,
            Ok(Ok(()))
        ) {
            return;
        }
        let Ok(ack) = exchange.acknowledge(pending) else {
            return;
        };
        let Ok(bytes) = maknae_proto::encode_mutation_ack(&ack) else {
            return;
        };
        // The grant already fit this immutable frame budget. Even an ack with
        // maximal integer fields is smaller than every grant encoding; the
        // encoding-bound invariant is checked in mutation_loop.rs.
        if !matches!(
            tokio::time::timeout_at(deadline, maknae_proto::write_frame(stream, &bytes)).await,
            Ok(Ok(()))
        ) {
            return;
        }
        if terminal {
            return;
        }
    }
}
async fn incomplete<E: AuditEmit>(
    cfg: &TransportConfig,
    emit: &E,
    intent: &DurableIntent,
    seq: &Seq,
    reason: &str,
) {
    let mut record = completion(intent, seq.next(), MutationStatus::Incomplete);
    record.outcome.reason = reason.into();
    let _ = tokio::time::timeout(
        Duration::from_millis(cfg.read_timeout_ms),
        emit.emit(&record),
    )
    .await;
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    struct Fixture {
        root: std::path::PathBuf,
        principal: Principal,
    }
    impl Fixture {
        fn new() -> Self {
            static COUNT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
            let root = std::env::temp_dir().join(format!(
                "mutation_prepare_{}_{}",
                std::process::id(),
                COUNT.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
            ));
            std::fs::create_dir(&root).unwrap();
            std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700)).unwrap();
            let root = root.canonicalize().unwrap();
            let principal = Principal {
                name: "operator".into(),
                uid: nix::unistd::geteuid().as_raw(),
                home: root.clone(),
            };
            Self { root, principal }
        }
        fn fd(&self) -> OwnedFd {
            std::fs::File::open(&self.root).unwrap().into()
        }
        fn mkdir(&self, parents: bool, components: Vec<String>) -> Verb {
            Verb::FsMkdir {
                path: self.root.join("one/two").to_str().unwrap().into(),
                parents,
                components,
            }
        }
    }
    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.root);
        }
    }
    fn fixture_pdp(fx: &Fixture) -> crate::Composition<maknae_authz_basic::HermeticAuthorizer> {
        let path = fx.root.join("authz.yaml");
        std::fs::write(&path, "schema_version: 1\npermissions:\n  allow:\n    - \"Write(~/**)\"\n  deny: []\nbindings:\n  user: [\"root\"]\n").unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o640)).unwrap();
        let baseline = maknae_authz_basic::HermeticAuthorizer::new(
            path,
            fx.principal.clone(),
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
        crate::Composition::new(
            baseline,
            crate::CeilingAuthorizer::new(maknae_config::Ceiling::baseline_for(us), us),
        )
    }
    fn record() -> AuditRecord {
        serde_json::from_value(serde_json::json!({
            "ts":"test", "event":"request", "where":{"host":"test","component":"kernel","socket":"test"},
            "source":{"uid":0},"subject":{},"action":"fs.write",
            "outcome":{"result":"deny","reason":"pending","posture":"unauthorized"},
            "session_id":99,"seq":1,"au3_1":{},"integrity":{}
        })).unwrap()
    }
    #[derive(Default)]
    struct Recorder(std::sync::Mutex<Vec<AuditRecord>>);
    impl AuditEmit for Recorder {
        fn emit(
            &self,
            record: &AuditRecord,
        ) -> impl std::future::Future<Output = Result<(), maknae_audit_append::AuditError>> + Send
        {
            self.0.lock().unwrap().push(record.clone());
            async { Ok(()) }
        }
    }
    struct Delayed<P> {
        pdp: P,
        gate: Arc<(std::sync::Mutex<bool>, std::sync::Condvar)>,
    }
    impl<P: Authorizer> Authorizer for Delayed<P> {
        fn decide(&self, request: &maknae_security::Request) -> maknae_security::Verdict {
            let (lock, wake) = &*self.gate;
            let mut released = lock.lock().unwrap();
            while !*released {
                released = wake.wait(released).unwrap();
            }
            self.pdp.decide(request)
        }
    }
    #[tokio::test]
    async fn admission_capacity_stays_with_timed_out_real_policy_worker() {
        let fx = Fixture::new();
        let emit = Arc::new(Recorder::default());
        let cfg = maknae_config::transport_from_section(None).unwrap();
        let seq = Seq::new();
        let principal = Arc::new(fx.principal.clone());
        let authorizer = Arc::new(fixture_pdp(&fx));
        let (_client, mut server) = tokio::io::duplex(65536);
        let fds = maknae_io::DelegatedFds::new(4);
        assert!(
            !handle(
                &mut server,
                &Verb::Ping,
                0,
                Lane::Local,
                &fds,
                authorizer.clone(),
                emit.clone(),
                principal.clone(),
                &cfg,
                &seq,
                record(),
                Duration::from_secs(1)
            )
            .await
        );
        assert!(emit.0.lock().unwrap().is_empty());
        let target = fx.root.join("capacity-sentinel");
        std::fs::write(&target, b"untouched").unwrap();
        let verb = Verb::FsWrite {
            path: target.to_str().unwrap().into(),
            content: Bytes::new(Vec::new().into()),
            mode: WriteMode::Existing,
        };
        let full = tokio::time::timeout(
            Duration::from_secs(1),
            capacity().acquire_many_owned(MAX_WORKERS as u32),
        )
        .await
        .expect("idle admission budget is available")
        .unwrap();
        assert!(
            handle(
                &mut server,
                &verb,
                0,
                Lane::Local,
                &fds,
                authorizer,
                emit.clone(),
                principal.clone(),
                &cfg,
                &seq,
                record(),
                Duration::from_secs(1)
            )
            .await
        );
        assert!(emit
            .0
            .lock()
            .unwrap()
            .last()
            .unwrap()
            .outcome
            .reason
            .contains("budget"));
        drop(full);
        fds.push(
            std::fs::OpenOptions::new()
                .write(true)
                .open(&target)
                .unwrap()
                .into(),
        );
        let gate = Arc::new((std::sync::Mutex::new(false), std::sync::Condvar::new()));
        let delayed = Arc::new(Delayed {
            pdp: fixture_pdp(&fx),
            gate: gate.clone(),
        });
        handle(
            &mut server,
            &verb,
            0,
            Lane::Local,
            &fds,
            delayed,
            emit.clone(),
            principal,
            &cfg,
            &seq,
            record(),
            Duration::from_millis(20),
        )
        .await;
        assert!(emit
            .0
            .lock()
            .unwrap()
            .last()
            .unwrap()
            .outcome
            .reason
            .contains("timed out"));
        assert_eq!(
            capacity().available_permits(),
            MAX_WORKERS - 1,
            "timeout cannot reclaim a live worker's permit"
        );
        assert_eq!(std::fs::read(&target).unwrap(), b"untouched");
        let (released, wake) = &*gate;
        *released.lock().unwrap() = true;
        wake.notify_one();
        tokio::time::timeout(Duration::from_secs(2), async {
            while capacity().available_permits() != MAX_WORKERS {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        assert_eq!(
            std::fs::read(target).unwrap(),
            b"untouched",
            "a late permit cannot resurrect a timed-out request"
        );
    }
    #[test]
    fn observed_failure_state_never_becomes_success_or_rollback() {
        assert_eq!(observed_result(Ok(())), (MutationStatus::Applied, true));
        for (state, expected) in [
            (maknae_io::EffectState::NoEffect, MutationStatus::NoEffect),
            (maknae_io::EffectState::Applied, MutationStatus::Applied),
            (maknae_io::EffectState::Partial, MutationStatus::Partial),
            (
                maknae_io::EffectState::DurabilityUnknown,
                MutationStatus::DurabilityUnknown,
            ),
        ] {
            let at = std::path::PathBuf::from("/real-operation-result");
            let error = maknae_io::MutationFailure {
                state,
                source: maknae_io::IoError::MutationPathChanged { path: at.clone() },
                at,
            };
            assert_eq!(observed_result(Err(error)), (expected, false));
        }
    }
    #[test]
    fn canonical_paths_and_normal_components_reject_ambiguous_names_and_boundaries() {
        for p in ["", "relative", "/../x", "/./x", "/x//y", "/x/", "/x\0y"] {
            assert!(checked(p).is_err(), "{p:?}");
        }
        let exact = format!("/{}", "x".repeat(maknae_proto::MAX_MUTATION_PATH_BYTES - 1));
        assert!(checked(&exact).is_ok());
        assert!(checked(&(exact + "x")).is_err());
        for leaf in ["", ".", "..", "a/b", "a\0b"] {
            assert!(!normal(leaf), "{leaf:?}");
        }
        assert!(normal("uniçode"));
        assert!(normal("ordinary"));
    }
    #[test]
    fn preparation_requires_local_real_descriptor_and_valid_mkdir_suffix() {
        let fx = Fixture::new();
        assert!(prepare(Verb::Ping, None, &fx.principal, Lane::Local).is_err());
        assert!(prepare(
            fx.mkdir(true, vec!["one".into(), "two".into()]),
            Some(fx.fd()),
            &fx.principal,
            Lane::Remote
        )
        .is_err());
        assert!(prepare(
            fx.mkdir(true, vec!["one".into(), "two".into()]),
            None,
            &fx.principal,
            Lane::Local
        )
        .is_err());
        for (parents, components) in [
            (false, vec!["one".into(), "two".into()]),
            (true, vec!["x".into(); 129]),
            (true, vec!["".into()]),
            (true, vec![".".into()]),
            (true, vec!["bad/name".into()]),
            (true, vec!["bad\0name".into()]),
        ] {
            assert!(prepare(
                fx.mkdir(parents, components),
                Some(fx.fd()),
                &fx.principal,
                Lane::Local
            )
            .is_err());
        }
        assert!(prepare(
            Verb::FsDelete {
                path: "/".into(),
                recursive: false
            },
            Some(fx.fd()),
            &fx.principal,
            Lane::Local
        )
        .is_err());
        assert!(prepare(
            Verb::FsDelete {
                path: "/../x".into(),
                recursive: false
            },
            Some(fx.fd()),
            &fx.principal,
            Lane::Local
        )
        .is_err());
        let target = fx.root.join("real-file");
        std::fs::write(&target, b"sentinel").unwrap();
        assert!(prepare(
            fx.mkdir(true, vec!["two".into()]),
            Some(std::fs::File::open(&target).unwrap().into()),
            &fx.principal,
            Lane::Local
        )
        .is_err());
        let write = Verb::FsWrite {
            path: target.to_str().unwrap().into(),
            content: Bytes::new(Vec::new().into()),
            mode: WriteMode::Existing,
        };
        assert!(prepare(
            write,
            Some(std::fs::File::open(&target).unwrap().into()),
            &fx.principal,
            Lane::Local
        )
        .is_err());
        assert_eq!(std::fs::read(target).unwrap(), b"sentinel");
    }
}
