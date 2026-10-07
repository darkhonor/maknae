//! Mutation preparation and the durable-intent gate. Every effect is a subject-side
//! attempt; its progress and completion are client reported.
use crate::{
    handler::{build_authz_request, delegated_plan, discharge_plan, lexical_pregate},
    uid_gate::{Busy, UidGate},
    MutationExchange,
};
use maknae_audit_append::{
    AuditEmit, AuditRecord, MutationAudit, MutationEffectKind, MutationEffectRecord,
    MutationOperation, MutationOrigin, MutationPhase, MutationStatus, Seq,
};
use maknae_config::TransportConfig;
use maknae_io::{MutationDirectory, MutationRequired};
use maknae_proto::{
    MutationGrant, MutationId, MutationLimits, MutationReport, MutationScope, Payload,
    ProtoErrCode, ProtoError, ReportedEffect, ReportedFinish, RespResult, Response, Verb,
    WriteMode, PROTOCOL_VERSION,
};
use maknae_security::{AttrValue, Authorizer, Decision, FsOperation, Lane};
use std::os::fd::AsFd;
use std::{
    os::fd::OwnedFd,
    path::{Path, PathBuf},
    sync::{Arc, OnceLock},
    time::Duration,
};
use tokio::{
    io::{AsyncRead, AsyncWrite},
    sync::Semaphore,
};

/// No orphan reclamation: the permit follows the actual blocking worker, and the uid
/// claim lives only as long as that worker.
static CAPACITY: OnceLock<Arc<Semaphore>> = OnceLock::new();
static MUTATING: OnceLock<UidGate> = OnceLock::new();
const MAX_WORKERS: usize = 16;
fn capacity() -> Arc<Semaphore> {
    Arc::clone(CAPACITY.get_or_init(|| Arc::new(Semaphore::new(MAX_WORKERS))))
}
fn mutating() -> &'static UidGate {
    MUTATING.get_or_init(UidGate::default)
}

enum Evidence {
    Object { _fd: OwnedFd },
    Directory { _directory: MutationDirectory },
}
struct PreparedMutation {
    _evidence: Evidence,
    scope: MutationScope,
    paths: Vec<String>,
    kind: FsOperation,
}
struct DurableIntent {
    record: AuditRecord,
}

fn path(verb: &Verb) -> Option<&str> {
    match verb {
        Verb::FsWrite { path, .. }
        | Verb::FsDelete { path, .. }
        | Verb::FsMkdir { path, .. }
        | Verb::Read { path, .. } => Some(path),
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
    home: &Path,
    uid: u32,
    lane: Lane,
) -> Result<PreparedMutation, String> {
    let asked = path(&verb).ok_or("not a mutation")?;
    checked(asked)?;
    if lane != Lane::Local {
        return Err("mutation requires local subject execution".into());
    }
    if home == Path::new("/") {
        return Err(crate::authz::HomeUnavailable::Unresolvable.reason());
    }
    let read = matches!(verb, Verb::Read { .. });
    let fd = fd.ok_or(if read {
        "read descriptor missing"
    } else {
        "mutation descriptor missing"
    })?;
    let object = match &verb {
        Verb::Read { .. } => Some((
            "read evidence refused",
            FsOperation::Read,
            ReportedEffect::ReadFile,
        )),
        Verb::FsWrite {
            mode: WriteMode::Existing,
            ..
        } => Some((
            "replacement evidence refused",
            FsOperation::WriteExisting,
            ReportedEffect::ReplacedFile,
        )),
        _ => None,
    };
    if let Some((refused, kind, effect)) = object {
        let verified = maknae_io::verify_delegated(fd.as_fd(), delegated_plan(home, uid))
            .map_err(|e| format!("{refused}: {e}"))?;
        maknae_io::refuse_access_bearing(fd.as_fd(), &verified.path)
            .map_err(|e| format!("{refused}: {e}"))?;
        let path = verified
            .path
            .to_str()
            .ok_or("non-UTF-8 object path")?
            .to_owned();
        checked(&path)?;
        return Ok(PreparedMutation {
            _evidence: Evidence::Object { _fd: fd },
            scope: MutationScope::Exact {
                path: path.clone(),
                effect,
            },
            paths: vec![path],
            kind,
        });
    }
    let directory = maknae_io::verify_mutation_directory(
        fd,
        MutationRequired {
            confined_beneath: home.to_path_buf(),
            root_required: delegated_plan(home, uid).root_required,
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
            if Path::new(&root) == home {
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
        _evidence: Evidence::Directory {
            _directory: directory,
        },
        scope,
        paths,
        kind,
    })
}

/// Decide every path in the mutation. Returns the role the decision was made
/// on, and the rule it cites, in BOTH arms (#275): a denied `fs.write` is the
/// security-interesting record, so stamping `role=none` on it while a role was in
/// fact resolved would defeat the point. When several paths are decided, both
/// come from the last decision evaluated — on a deny, the path that caused the
/// refusal.
type DecidedBy = (Option<&'static str>, Option<maknae_security::RuleCitation>);
type AuthorizeErr = (String, String, DecidedBy);

fn authorize<P: Authorizer>(
    prepared: &PreparedMutation,
    verb: &Verb,
    uid: u32,
    home: Option<&Path>,
    authorizer: &P,
    policy_name: &str,
) -> Result<(DecidedBy, maknae_proto::ObjectLabel), AuthorizeErr> {
    let mut decided: DecidedBy = (None, None);
    let mut last = None;
    for path in &prepared.paths {
        let mut request = build_authz_request(verb, uid, home, Lane::Local, None);
        request
            .resource
            .0
            .insert("path", AttrValue::Str(path.clone()));
        request.context.0.insert(
            maknae_security::CONTEXT_FS_OPERATION,
            AttrValue::Str(prepared.kind.as_str().into()),
        );
        // `combine(vec![..])` preserved: it is what produces the
        // "indeterminate operand blocks (fail-closed)" trail string.
        let d = maknae_security::guarded_decide_cited(authorizer, &request);
        decided = (d.role, d.rule);
        match maknae_security::finalize(maknae_security::combine(vec![d.verdict])) {
            Decision::Permit { obligations } => discharge_plan(&obligations).map_err(|_| {
                (
                    "unhonorable mutation obligation".to_string(),
                    path.clone(),
                    decided.clone(),
                )
            })?,
            Decision::Deny { reason } => return Err((reason, path.clone(), decided)),
        }
        last = Some((request, path));
    }
    let (request, path) = last.expect("prepared nonempty paths");
    let label = object_label(policy_name, &request).ok_or_else(|| {
        (
            "object label unresolved".to_string(),
            path.clone(),
            decided.clone(),
        )
    })?;
    Ok((decided, label))
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
        label: None,
        requested_page: None,
    }
}
pub(crate) fn object_label(
    policy_name: &str,
    req: &maknae_security::Request,
) -> Option<maknae_proto::ObjectLabel> {
    let policy = crate::classification::select(policy_name)?;
    let level =
        crate::ceiling_authz::resolve_level(policy, crate::ceiling_authz::label_of(req)).ok()?;
    Some(maknae_proto::ObjectLabel {
        level: level.name,
        categories: Vec::new(),
    })
}
fn label_audit(label: &maknae_proto::ObjectLabel) -> maknae_audit_append::LabelAudit {
    maknae_audit_append::LabelAudit {
        level: label.level.clone(),
        categories: Vec::new(),
    }
}
async fn commit_intent<E: AuditEmit>(
    emit: &E,
    mut record: AuditRecord,
    content_length: Option<u64>,
    kind: FsOperation,
    paths: Vec<String>,
    label: &maknae_proto::ObjectLabel,
    requested: Option<maknae_proto::PageRequest>,
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
        FsOperation::Read => MutationOperation::Read,
    });
    meta.authorized_paths = paths;
    meta.label = Some(label_audit(label));
    meta.requested_page = requested.map(|p| maknae_audit_append::PageAudit {
        offset_line: p.offset_line,
        limit_lines: p.limit_lines,
        column: p.column,
    });
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
        if bytes.len() <= maknae_proto::ATTEMPT_RESPONSE_MAX {
            let _ = tokio::time::timeout(
                Duration::from_millis(cfg.read_timeout_ms),
                maknae_proto::write_frame(stream, maknae_proto::FrameClass::Attempt, &bytes),
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

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AttemptCaps {
    pub request: usize,
    pub response: usize,
}

impl Default for AttemptCaps {
    fn default() -> Self {
        AttemptCaps {
            request: maknae_proto::ATTEMPT_REQUEST_MAX,
            response: maknae_proto::ATTEMPT_RESPONSE_MAX,
        }
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
    home: Result<PathBuf, crate::authz::HomeUnavailable>,
    cfg: &TransportConfig,
    seq: &Seq,
    mut record: AuditRecord,
    authz_timeout: Duration,
    caps: AttemptCaps,
    policy_name: &str,
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
    let home = match home {
        Ok(home) => home,
        Err(cause) => {
            refuse(stream, cfg, &*emit, record, cause.reason()).await;
            return true;
        }
    };
    let (claim, permit) = match mutating().try_admit(uid, &capacity()) {
        Ok(slot) => slot.split(),
        Err(busy) => {
            let reason = match busy {
                Busy::Requester => "mutation worker budget exhausted for this requester",
                Busy::Global => "mutation worker budget exhausted",
            };
            refuse(stream, cfg, &*emit, record, reason.into()).await;
            return true;
        }
    };
    let fd = delegated.take();
    let original = verb.clone();
    let policy_name = policy_name.to_string();
    let prepared = tokio::time::timeout(
        authz_timeout,
        tokio::task::spawn_blocking(move || {
            let _claim = claim;
            let prepared = prepare(original.clone(), fd, &home, uid, lane)?;
            let decision = authorize(
                &prepared,
                &original,
                uid,
                Some(&home),
                &*authorizer,
                &policy_name,
            );
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
    let (role, rule) = match &decision {
        Ok((by, _)) => by,
        Err((_, _, by)) => by,
    };
    record.subject.role = role.map(str::to_string);
    record.rule = rule.as_ref().map(|c| maknae_audit_append::RuleAudit {
        node: c.node,
        section: c.section.clone(),
    });
    let label = match decision {
        Ok((_, label)) => label,
        Err((reason, denied_path, _)) => {
            record.object_requested = (asked != denied_path).then(|| asked.into());
            record.object = Some(denied_path);
            refuse(stream, cfg, &*emit, record, reason).await;
            return true;
        }
    };
    let requested = match verb {
        Verb::Read { page, .. } => *page,
        _ => None,
    };
    let read_page = match verb {
        Verb::Read { page, .. } => Some(page.unwrap_or(maknae_proto::WHOLE_FILE)),
        _ => None,
    };
    let length = if let Verb::FsWrite { content_length, .. } = verb {
        Some(*content_length)
    } else {
        None
    };
    if let Ok(Ok(intent)) = tokio::time::timeout(
        Duration::from_millis(cfg.read_timeout_ms),
        commit_intent(
            &*emit,
            record,
            length,
            prepared.kind,
            prepared.paths,
            &label,
            requested,
        ),
    )
    .await
    {
        attempt(
            stream,
            cfg,
            caps,
            &*emit,
            intent,
            prepared.scope,
            label,
            read_page,
            seq,
        )
        .await;
    }
    drop(prepared._evidence);
    drop(permit);
    true
}

#[allow(clippy::too_many_arguments)]
async fn attempt<S: AsyncRead + AsyncWrite + Unpin, E: AuditEmit>(
    stream: &mut S,
    cfg: &TransportConfig,
    caps: AttemptCaps,
    emit: &E,
    intent: DurableIntent,
    scope: MutationScope,
    label: maknae_proto::ObjectLabel,
    read_page: Option<maknae_proto::PageRequest>,
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
        max_bytes: if matches!(
            scope,
            MutationScope::Exact {
                effect: ReportedEffect::ReadFile,
                ..
            }
        ) {
            crate::handler::READ_PAGE_MAX_BYTES
        } else {
            0
        },
    };
    let deadline = tokio::time::Instant::now() + Duration::from_millis(limits.deadline_ms);
    let exchange = match read_page {
        Some(page) => MutationExchange::begin_paged(id, scope.clone(), limits, page),
        None => MutationExchange::begin(id, scope.clone(), limits),
    }
    .ok();
    let bytes = maknae_proto::encode_response(&Response {
        protocol_version: PROTOCOL_VERSION,
        result: RespResult::Ok(Payload::MutationAttempt(MutationGrant {
            id,
            scope,
            limits,
            label,
        })),
    })
    .ok()
    .filter(|bytes| bytes.len() <= caps.response);
    let delivered = match (exchange, bytes) {
        (Some(exchange), Some(bytes)) => matches!(
            tokio::time::timeout_at(
                deadline,
                maknae_proto::write_frame(stream, maknae_proto::FrameClass::Attempt, &bytes)
            )
            .await,
            Ok(Ok(()))
        )
        .then_some(exchange),
        _ => None,
    };
    let Some(mut exchange) = delivered else {
        incomplete(
            cfg,
            emit,
            &intent,
            seq,
            "attempt grant not delivered; no effect authorized",
        )
        .await;
        return;
    };
    loop {
        let result = tokio::time::timeout_at(
            deadline,
            maknae_proto::read_frame_of_class(
                stream,
                maknae_proto::FrameClass::Attempt,
                &maknae_proto::FrameCaps {
                    control: 0,
                    attempt: caps.request,
                    prompt: 0,
                },
            ),
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
                            ReportedEffect::ReadFile => MutationEffectKind::ReadFile,
                        },
                        length: e.length,
                        range: e.range.map(|r| maknae_audit_append::ByteRangeAudit {
                            start: r.start,
                            end: r.end,
                        }),
                        lines: e.lines.map(|l| maknae_audit_append::LineSpanAudit {
                            first: l.first,
                            last: l.last,
                            complete_last: l.complete_last,
                        }),
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
            incomplete(
                cfg,
                emit,
                &intent,
                seq,
                "mutation report not recorded; effects unknown",
            )
            .await;
            return;
        }
        let Ok(ack) = exchange.acknowledge(pending) else {
            incomplete(cfg, emit, &intent, seq, ACK_UNDELIVERED).await;
            return;
        };
        let Ok(bytes) = maknae_proto::encode_mutation_ack(&ack) else {
            incomplete(cfg, emit, &intent, seq, ACK_UNDELIVERED).await;
            return;
        };
        // The grant already fit this immutable frame budget. Even an ack with
        // maximal integer fields is smaller than every grant encoding; the
        // encoding-bound invariant is checked in mutation_loop.rs.
        if !matches!(
            tokio::time::timeout_at(
                deadline,
                maknae_proto::write_frame(stream, maknae_proto::FrameClass::Attempt, &bytes)
            )
            .await,
            Ok(Ok(()))
        ) {
            incomplete(cfg, emit, &intent, seq, ACK_UNDELIVERED).await;
            return;
        }
        if terminal {
            return;
        }
    }
}
const ACK_UNDELIVERED: &str = "mutation acknowledgment not delivered; effects unknown";

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

    #[test]
    fn the_object_label_is_the_ceiling_operands_resolution_with_no_categories() {
        let verb = Verb::Read {
            path: "/h/f".into(),
            conversation: None,
            page: None,
        };
        let plain = build_authz_request(&verb, 1000, None, Lane::Local, None);
        let us = object_label("US", &plain).unwrap();
        assert_eq!(
            (us.level.as_str(), us.categories.len()),
            ("UNCLASSIFIED", 0)
        );
        let mut marked = build_authz_request(&verb, 1000, None, Lane::Local, None);
        marked.resource.0.insert(
            maknae_security::RESOURCE_CLASSIFICATION,
            AttrValue::Str("SECRET//NOFORN".into()),
        );
        assert_eq!(object_label("US", &marked).unwrap().level, "SECRET");
        let mut foreign = build_authz_request(&verb, 1000, None, Lane::Local, None);
        foreign.resource.0.insert(
            maknae_security::RESOURCE_CLASSIFICATION,
            AttrValue::Str("NOT A LEVEL".into()),
        );
        assert!(object_label("US", &foreign).is_none());
        assert!(object_label("NO-SUCH-SYSTEM", &plain).is_none());
    }

    struct Fixture {
        root: std::path::PathBuf,
        principal: maknae_config::Principal,
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
            let principal = maknae_config::Principal {
                name: "operator".into(),
                uid: nix::unistd::geteuid().as_raw(),
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
    #[test]
    fn a_read_is_prepared_on_a_location_descriptor_as_an_exact_read() {
        let fx = Fixture::new();
        let target = fx.root.join("read-prepare-sentinel");
        std::fs::write(&target, b"sentinel").unwrap();
        let read = || Verb::Read {
            path: target.to_str().unwrap().into(),
            conversation: None,
            page: None,
        };
        let held = || Some(maknae_io::open_path_for_delegation(&target).unwrap());
        let prepared = prepare(read(), held(), &fx.root, fx.principal.uid, Lane::Local).unwrap();
        assert_eq!(prepared.kind, FsOperation::Read);
        assert_eq!(prepared.paths, vec![target.to_str().unwrap().to_string()]);
        assert_eq!(
            prepared.scope,
            MutationScope::Exact {
                path: target.to_str().unwrap().into(),
                effect: ReportedEffect::ReadFile
            }
        );
        assert_eq!(
            prepare(read(), None, &fx.root, fx.principal.uid, Lane::Local)
                .err()
                .as_deref(),
            Some("read descriptor missing")
        );
        assert_eq!(
            prepare(
                read(),
                held(),
                Path::new("/"),
                fx.principal.uid,
                Lane::Local
            )
            .err()
            .as_deref(),
            Some("requester home unavailable: unresolvable")
        );
        assert!(prepare(read(), held(), &fx.root, fx.principal.uid, Lane::Remote).is_err());
        assert!(prepare(
            read(),
            Some(fx.fd()),
            &fx.root,
            fx.principal.uid,
            Lane::Local
        )
        .err()
        .unwrap()
        .starts_with("read evidence refused"));
        #[cfg(target_os = "linux")]
        assert!(prepare(
            read(),
            Some(std::fs::File::open(&target).unwrap().into()),
            &fx.root,
            fx.principal.uid,
            Lane::Local
        )
        .err()
        .unwrap()
        .contains("confers access beyond location"));
        std::fs::hard_link(&target, fx.root.join("second-read-link")).unwrap();
        assert!(prepare(read(), held(), &fx.root, fx.principal.uid, Lane::Local).is_err());
        assert_eq!(std::fs::read(target).unwrap(), b"sentinel");
    }
    fn fixture_pdp(fx: &Fixture) -> crate::Composition<maknae_authz_basic::HermeticAuthorizer> {
        let path = fx.root.join("authz.yaml");
        let name = nix::unistd::User::from_uid(nix::unistd::geteuid())
            .expect("NSS")
            .expect("the test euid has a passwd entry")
            .name;
        std::fs::write(&path, format!("schema_version: 1\npermissions:\n  allow:\n    - \"Write(~/**)\"\n  deny: []\nbindings:\n  user: [\"{name}\"]\n")).unwrap();
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
            maknae_state::envelope::sha256,
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
            self.decide_reporting_role(request).0
        }

        /// Delegates rather than taking the trait default (#275): a wrapper
        /// that forwards only `decide` reports no role for a decision that had
        /// one. The delay behaviour is unchanged -- it gates BOTH entry points
        /// because `decide` is now this function's `.0`.
        fn decide_reporting_role(
            &self,
            request: &maknae_security::Request,
        ) -> (maknae_security::Verdict, Option<&'static str>) {
            let (lock, wake) = &*self.gate;
            let mut released = lock.lock().unwrap();
            while !*released {
                released = wake.wait(released).unwrap();
            }
            self.pdp.decide_reporting_role(request)
        }
    }
    struct Release(Arc<(std::sync::Mutex<bool>, std::sync::Condvar)>);
    impl Drop for Release {
        fn drop(&mut self) {
            let (released, wake) = &*self.0;
            *released
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner) = true;
            wake.notify_all();
        }
    }
    static EUID_TURN: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());
    fn last_reason(emit: &Recorder) -> String {
        emit.0
            .lock()
            .unwrap()
            .last()
            .expect("a record")
            .outcome
            .reason
            .clone()
    }
    #[tokio::test]
    async fn the_same_uid_starts_another_action_while_its_first_is_in_the_exchange() {
        let _turn = EUID_TURN.lock().await;
        let fx = Fixture::new();
        let cfg = maknae_config::transport_from_section(None).unwrap();
        let seq = Seq::new();
        let target = fx.root.join("exchange-sentinel");
        std::fs::write(&target, b"untouched").unwrap();
        let verb = Verb::FsWrite {
            path: target.to_str().unwrap().into(),
            content_length: 0,
            mode: WriteMode::Existing,
            conversation: None,
        };
        let fds = maknae_io::DelegatedFds::new(1);
        fds.push(maknae_io::open_path_for_delegation(&target).unwrap());
        let (mut client, mut server) = tokio::io::duplex(65536);
        let first = handle(
            &mut server,
            &verb,
            fx.principal.uid,
            Lane::Local,
            &fds,
            Arc::new(fixture_pdp(&fx)),
            Arc::new(Recorder::default()),
            Ok(fx.root.clone()),
            &cfg,
            &seq,
            record(),
            Duration::from_secs(10),
            AttemptCaps::default(),
            "US",
        );
        let second_emit = Arc::new(Recorder::default());
        let second = async {
            let grant = tokio::time::timeout(
                Duration::from_secs(10),
                maknae_proto::read_frame_of_class(
                    &mut client,
                    maknae_proto::FrameClass::Attempt,
                    &maknae_proto::FrameCaps {
                        control: 0,
                        attempt: maknae_proto::ATTEMPT_RESPONSE_MAX,
                        prompt: 0,
                    },
                ),
            )
            .await
            .expect("the grant arrives in time")
            .expect("a grant frame");
            assert!(matches!(
                maknae_proto::decode_response(&grant).unwrap().result,
                RespResult::Ok(Payload::MutationAttempt(_))
            ));
            let (_idle, mut other) = tokio::io::duplex(65536);
            assert!(
                handle(
                    &mut other,
                    &verb,
                    fx.principal.uid,
                    Lane::Local,
                    &maknae_io::DelegatedFds::new(1),
                    Arc::new(fixture_pdp(&fx)),
                    second_emit.clone(),
                    Ok(fx.root.clone()),
                    &cfg,
                    &seq,
                    record(),
                    Duration::from_secs(10),
                    AttemptCaps::default(),
                    "US",
                )
                .await
            );
            drop(client);
        };
        let (consumed, ()) = tokio::time::timeout(Duration::from_secs(20), async {
            tokio::join!(first, second)
        })
        .await
        .expect("both actions end once the client goes away");
        assert!(consumed);
        assert_eq!(
            last_reason(&second_emit),
            "mutation descriptor missing",
            "the second action reached its own worker"
        );
    }
    #[tokio::test]
    async fn an_unusable_home_is_refused_with_its_cause_before_any_slot() {
        use crate::authz::HomeUnavailable;
        let fx = Fixture::new();
        let cfg = maknae_config::transport_from_section(None).unwrap();
        let seq = Seq::new();
        let target = fx.root.join("unusable-home-sentinel");
        std::fs::write(&target, b"untouched").unwrap();
        let verb = Verb::FsWrite {
            path: target.to_str().unwrap().into(),
            content_length: 0,
            mode: WriteMode::Existing,
            conversation: None,
        };
        for (uid, cause) in (4_350_100..).zip([
            HomeUnavailable::Unresolvable,
            HomeUnavailable::TimedOut,
            HomeUnavailable::RequesterAtCapacity,
            HomeUnavailable::AtCapacity,
        ]) {
            let held = mutating().try_claim(uid).expect("an unclaimed uid");
            let fds = maknae_io::DelegatedFds::new(1);
            fds.push(maknae_io::open_path_for_delegation(&target).unwrap());
            let emit = Arc::new(Recorder::default());
            let (_client, mut server) = tokio::io::duplex(65536);
            assert!(
                handle(
                    &mut server,
                    &verb,
                    uid,
                    Lane::Local,
                    &fds,
                    Arc::new(fixture_pdp(&fx)),
                    emit.clone(),
                    Err(cause),
                    &cfg,
                    &seq,
                    record(),
                    Duration::from_secs(10),
                    AttemptCaps::default(),
                    "US",
                )
                .await
            );
            assert_eq!(last_reason(&emit), cause.reason(), "{cause:?}");
            assert!(fds.take().is_some(), "no worker took the descriptor");
            drop(held);
        }
    }
    #[tokio::test]
    async fn admission_capacity_stays_with_timed_out_real_policy_worker() {
        let _turn = EUID_TURN.lock().await;
        let fx = Fixture::new();
        let emit = Arc::new(Recorder::default());
        let cfg = maknae_config::transport_from_section(None).unwrap();
        let seq = Seq::new();
        let authorizer = Arc::new(fixture_pdp(&fx));
        let authorizer_for_second = Arc::new(fixture_pdp(&fx));
        let (_client, mut server) = tokio::io::duplex(65536);
        let fds = maknae_io::DelegatedFds::new(4);
        assert!(
            !handle(
                &mut server,
                &Verb::Ping,
                fx.principal.uid,
                Lane::Local,
                &fds,
                authorizer.clone(),
                emit.clone(),
                Ok(fx.root.clone()),
                &cfg,
                &seq,
                record(),
                Duration::from_secs(1),
                AttemptCaps::default(),
                "US",
            )
            .await
        );
        assert!(emit.0.lock().unwrap().is_empty());
        let target = fx.root.join("capacity-sentinel");
        std::fs::write(&target, b"untouched").unwrap();
        let verb = Verb::FsWrite {
            path: target.to_str().unwrap().into(),
            content_length: 0,
            mode: WriteMode::Existing,
            conversation: None,
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
                fx.principal.uid,
                Lane::Local,
                &fds,
                authorizer,
                emit.clone(),
                Ok(fx.root.clone()),
                &cfg,
                &seq,
                record(),
                Duration::from_secs(1),
                AttemptCaps::default(),
                "US",
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
        fds.push(maknae_io::open_path_for_delegation(&target).unwrap());
        let gate = Arc::new((std::sync::Mutex::new(false), std::sync::Condvar::new()));
        let release = Release(gate.clone());
        let delayed = Arc::new(Delayed {
            pdp: fixture_pdp(&fx),
            gate: gate.clone(),
        });
        handle(
            &mut server,
            &verb,
            fx.principal.uid,
            Lane::Local,
            &fds,
            delayed,
            emit.clone(),
            Ok(fx.root.clone()),
            &cfg,
            &seq,
            record(),
            Duration::from_millis(20),
            AttemptCaps::default(),
            "US",
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
        let rejected = Arc::new(Recorder::default());
        assert!(
            handle(
                &mut server,
                &verb,
                fx.principal.uid,
                Lane::Local,
                &fds,
                authorizer_for_second.clone(),
                rejected.clone(),
                Ok(fx.root.clone()),
                &cfg,
                &seq,
                record(),
                Duration::from_secs(1),
                AttemptCaps::default(),
                "US",
            )
            .await
        );
        assert_eq!(
            rejected.0.lock().unwrap().last().unwrap().outcome.reason,
            "mutation worker budget exhausted for this requester"
        );
        assert_eq!(
            capacity().available_permits(),
            MAX_WORKERS - 1,
            "a uid already in flight takes no global slot"
        );
        let other = Arc::new(Recorder::default());
        assert!(
            handle(
                &mut server,
                &verb,
                fx.principal.uid.wrapping_add(4_350_000),
                Lane::Local,
                &fds,
                authorizer_for_second,
                other.clone(),
                Ok(PathBuf::from("/")),
                &cfg,
                &seq,
                record(),
                Duration::from_secs(1),
                AttemptCaps::default(),
                "US",
            )
            .await
        );
        assert_eq!(
            other.0.lock().unwrap().last().unwrap().outcome.reason,
            "requester home unavailable: unresolvable",
            "another uid still reaches its own worker"
        );
        drop(release);
        tokio::time::timeout(Duration::from_secs(2), async {
            while capacity().available_permits() != MAX_WORKERS
                || mutating().try_claim(fx.principal.uid).is_none()
            {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("the slot and the uid claim return when the worker ends");
        assert_eq!(
            std::fs::read(target).unwrap(),
            b"untouched",
            "a late permit cannot resurrect a timed-out request"
        );
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
        assert!(prepare(Verb::Ping, None, &fx.root, fx.principal.uid, Lane::Local).is_err());
        assert!(prepare(
            fx.mkdir(true, vec!["one".into(), "two".into()]),
            Some(fx.fd()),
            &fx.root,
            fx.principal.uid,
            Lane::Remote
        )
        .is_err());
        assert!(prepare(
            fx.mkdir(true, vec!["one".into(), "two".into()]),
            None,
            &fx.root,
            fx.principal.uid,
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
                &fx.root,
                fx.principal.uid,
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
            &fx.root,
            fx.principal.uid,
            Lane::Local
        )
        .is_err());
        assert!(prepare(
            Verb::FsDelete {
                path: "/../x".into(),
                recursive: false
            },
            Some(fx.fd()),
            &fx.root,
            fx.principal.uid,
            Lane::Local
        )
        .is_err());
        let target = fx.root.join("real-file");
        std::fs::write(&target, b"sentinel").unwrap();
        assert!(prepare(
            fx.mkdir(true, vec!["two".into()]),
            Some(std::fs::File::open(&target).unwrap().into()),
            &fx.root,
            fx.principal.uid,
            Lane::Local
        )
        .is_err());
        let write = || Verb::FsWrite {
            path: target.to_str().unwrap().into(),
            content_length: 0,
            mode: WriteMode::Existing,
            conversation: None,
        };
        let held = || Some(maknae_io::open_path_for_delegation(&target).unwrap());
        let prepared = prepare(write(), held(), &fx.root, fx.principal.uid, Lane::Local).unwrap();
        assert_eq!(prepared.kind, FsOperation::WriteExisting);
        assert_eq!(prepared.paths, vec![target.to_str().unwrap().to_string()]);
        assert_eq!(
            prepared.scope,
            MutationScope::Exact {
                path: target.to_str().unwrap().into(),
                effect: ReportedEffect::ReplacedFile
            }
        );
        assert!(prepare(
            write(),
            Some(fx.fd()),
            &fx.root,
            fx.principal.uid,
            Lane::Local
        )
        .is_err());
        std::fs::hard_link(&target, fx.root.join("second-link")).unwrap();
        assert!(prepare(write(), held(), &fx.root, fx.principal.uid, Lane::Local).is_err());
        assert_eq!(std::fs::read(target).unwrap(), b"sentinel");
    }
}
