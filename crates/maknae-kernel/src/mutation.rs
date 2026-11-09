//! Mutation preparation and the durable-intent gate. Every effect is a subject-side
//! attempt; its progress and completion are client reported.
use crate::conversation::{
    facts::{gather, ConversationFacts},
    record::ConversationRecord,
    store::ConversationStore,
};
use crate::sensitive_authz::{sensitive_match, sensitive_subtree_match, SensitiveMatch};
use crate::{
    blocking_guard::AUDIT_APPEND_TIMEOUT,
    handler::{build_authz_request, delegated_plan, discharge_plan, lexical_pregate, Stamp},
    uid_gate::{Busy, UidGate},
    MutationExchange,
};
use maknae_audit_append::{
    AuditEmit, AuditRecord, MutationAudit, MutationEffectKind, MutationEffectRecord,
    MutationOperation, MutationOrigin, MutationPhase, MutationStatus, Seq,
};
use maknae_config::{SensitiveList, TransportConfig};
use maknae_io::MutationDirectory;
use maknae_proto::{
    MutationGrant, MutationId, MutationLimits, MutationReport, MutationScope, Payload,
    ProtoErrCode, ProtoError, ReportedEffect, ReportedFinish, RespResult, Response, Verb,
    WriteMode, PROTOCOL_VERSION,
};
use maknae_security::{AttrValue, Authorizer, Decision, FsOperation, Lane};
use std::os::fd::{AsFd, BorrowedFd};
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

fn busy_reason(busy: Busy) -> &'static str {
    match busy {
        Busy::Requester => "mutation worker budget exhausted for this requester",
        Busy::Global => "mutation worker budget exhausted",
    }
}

pub(crate) const STORE_SLOTS_PER_UID: usize = 1;
const STORE_WORKERS: usize = 16;
static STORE_CAPACITY: OnceLock<Arc<Semaphore>> = OnceLock::new();
fn store_capacity() -> Arc<Semaphore> {
    Arc::clone(STORE_CAPACITY.get_or_init(|| Arc::new(Semaphore::new(STORE_WORKERS))))
}
static STORE_SLOTS: OnceLock<std::sync::Mutex<std::collections::HashMap<u32, Arc<Semaphore>>>> =
    OnceLock::new();

fn store_slots(uid: u32) -> Arc<Semaphore> {
    let mut slots = STORE_SLOTS
        .get_or_init(Default::default)
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    slots.retain(|_, s| Arc::strong_count(s) > 1);
    Arc::clone(
        slots
            .entry(uid)
            .or_insert_with(|| Arc::new(Semaphore::new(STORE_SLOTS_PER_UID))),
    )
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Blocked {
    NotStarted,
    Unknown,
}

impl std::fmt::Display for Blocked {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::NotStarted => "store work did not start within its bound",
            Self::Unknown => "store work did not finish within its bound",
        })
    }
}

/// Runs on the requester's own slot, then a store worker; never on the mutation pool.
pub(crate) async fn blocking<T, F>(uid: u32, timeout: Duration, f: F) -> Result<T, Blocked>
where
    T: Send + 'static,
    F: FnOnce() -> T + Send + 'static,
{
    let deadline = tokio::time::Instant::now() + timeout;
    let admitted = tokio::time::timeout_at(deadline, async {
        let own = store_slots(uid).acquire_owned().await.ok()?;
        let shared = store_capacity().acquire_owned().await.ok()?;
        Some((own, shared))
    })
    .await;
    let Ok(Some(held)) = admitted else {
        return Err(Blocked::NotStarted);
    };
    let work = tokio::task::spawn_blocking(move || {
        let _held = held;
        f()
    });
    match tokio::time::timeout_at(deadline, work).await {
        Ok(Ok(v)) => Ok(v),
        _ => Err(Blocked::Unknown),
    }
}

pub(crate) fn verify_cwd(fd: BorrowedFd<'_>) -> Result<String, String> {
    let path = maknae_io::verify_unconfined_directory(fd)
        .map_err(|e| format!("cwd evidence refused: {e}"))?;
    let path = path.to_str().ok_or("non-UTF-8 cwd")?.to_owned();
    checked(&path)?;
    Ok(path)
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
fn cited(verb: &Verb) -> Option<&str> {
    match verb {
        Verb::FsWrite { conversation, .. } | Verb::Read { conversation, .. } => {
            conversation.as_deref()
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
pub(crate) fn checked(path: &str) -> Result<(), String> {
    if path.len() > maknae_proto::MAX_MUTATION_PATH_BYTES || path.contains('\0') {
        return Err("mutation path limit or NUL".into());
    }
    lexical_pregate(path).map_err(str::to_owned)
}
fn prepare(
    verb: Verb,
    fd: Option<OwnedFd>,
    home: &Path,
    lane: Lane,
) -> Result<PreparedMutation, String> {
    let asked = path(&verb).ok_or("not a mutation")?;
    checked(asked)?;
    if lane != Lane::Local {
        return Err("mutation requires local subject execution".into());
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
        let verified = maknae_io::verify_delegated(fd.as_fd(), delegated_plan())
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
    let directory = maknae_io::verify_mutation_directory(fd)
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
            if home.starts_with(&root) {
                return Err("cannot delete the requester's home".into());
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

type DecidedBy = (Option<&'static str>, Option<maknae_security::RuleCitation>);
type AuthorizeErr = (String, String, DecidedBy);

const WRITE_NEEDS_READ: &str = "fs.write needs fs.read: ";

/// The `fs.read` twin of a write's request (ADR-0034 decision 7): a write is permitted
/// only when a read of the same path would be.
pub(crate) fn read_of(write: &maknae_security::Request) -> maknae_security::Request {
    let mut read = write.clone();
    read.action = maknae_security::Action("fs.read".into());
    read.context.0.insert(
        maknae_security::CONTEXT_FS_OPERATION,
        AttrValue::Str(FsOperation::Read.as_str().into()),
    );
    read
}

/// Decides every path from one snapshot, and for an `fs.write` the `fs.read` twin
/// of each path too. Returns the role of the last path decided, in both arms (on a
/// deny, the path that refused, #275), and that path's rule, except on a deny
/// written in place of a permit that was never acted on. A permit cites the
/// write's rule; a deny cites the request that refused.
#[allow(clippy::too_many_arguments)]
fn authorize<P: Authorizer>(
    prepared: &PreparedMutation,
    verb: &Verb,
    uid: u32,
    home: Option<&Path>,
    authorizer: &P,
    policy_name: &str,
    facts: Option<&ConversationFacts>,
    personal: Option<&AttrValue>,
    stamp: &Stamp<'_>,
) -> Result<(DecidedBy, maknae_proto::ObjectLabel), AuthorizeErr> {
    let with_read = matches!(verb, Verb::FsWrite { .. });
    let mut requests = Vec::new();
    for path in &prepared.paths {
        let mut request = build_authz_request(verb, uid, home, Lane::Local, None, facts, stamp);
        request
            .resource
            .0
            .insert("path", AttrValue::Str(path.clone()));
        request.context.0.insert(
            maknae_security::CONTEXT_FS_OPERATION,
            AttrValue::Str(prepared.kind.as_str().into()),
        );
        if let Some(personal) = personal {
            request.context.0.insert(
                maknae_security::CONTEXT_SENSITIVE_PERSONAL,
                personal.clone(),
            );
        }
        let read = with_read.then(|| read_of(&request));
        requests.push(request);
        requests.extend(read);
    }
    let stride = if with_read { 2 } else { 1 };
    let verdicts = maknae_security::guarded_decide_cited_all(authorizer, &requests);
    let mut decided: DecidedBy = (None, None);
    for (i, d) in verdicts.into_iter().enumerate() {
        let path = &prepared.paths[i / stride];
        let read = i % stride == 1;
        if !read {
            decided = (d.role, d.rule.clone());
        }
        // `combine(vec![..])` preserved: it is what produces the
        // "indeterminate operand blocks (fail-closed)" trail string.
        match maknae_security::finalize(maknae_security::combine(vec![d.verdict])) {
            Decision::Permit { obligations } => discharge_plan(&obligations).map_err(|_| {
                (
                    "unhonorable mutation obligation".to_string(),
                    path.clone(),
                    (decided.0, None),
                )
            })?,
            Decision::Deny { reason } if read => {
                return Err((
                    format!("{WRITE_NEEDS_READ}{reason}"),
                    path.clone(),
                    (d.role, d.rule),
                ))
            }
            Decision::Deny { reason } => return Err((reason, path.clone(), decided)),
        }
    }
    let path = prepared.paths.last().expect("prepared nonempty paths");
    let request = requests.last().expect("one request per path");
    let label = object_label(policy_name, request).ok_or_else(|| {
        (
            "object label unresolved".to_string(),
            path.clone(),
            (decided.0, None),
        )
    })?;
    Ok((decided, label))
}

fn owned_personal(record: Option<&ConversationRecord>, uid: u32) -> Option<AttrValue> {
    record
        .filter(|rec| rec.owner == uid)
        .map(|rec| AttrValue::Set(rec.sensitive.iter().cloned().collect()))
}

/// The answer for an asked path on either list, decided before any descriptor, so it
/// depends only on the path.
struct Protection {
    list: &'static str,
    reason: String,
    entry: String,
}

/// The conversation's personal list for the `Protected` answer; `None` when it does not
/// parse, which leaves the refusal to the operand.
fn personal_list(personal: Option<&AttrValue>) -> Option<SensitiveList> {
    match personal {
        None => Some(SensitiveList::empty()),
        Some(AttrValue::Set(entries)) => {
            SensitiveList::from_entries(&entries.iter().cloned().collect::<Vec<_>>()).ok()
        }
        Some(_) => None,
    }
}

fn protection(
    verb: &Verb,
    asked: &str,
    home: &Path,
    host: &SensitiveList,
    personal: &SensitiveList,
) -> Option<Protection> {
    let decide = match verb {
        Verb::FsDelete {
            recursive: true, ..
        } => sensitive_subtree_match,
        _ => sensitive_match,
    };
    let (list, tag, entry) = match decide(
        Path::new(asked),
        Some(home),
        host,
        personal,
        maknae_config::native_fold(),
    ) {
        SensitiveMatch::Host(entry) => (maknae_proto::HOST_SENSITIVE_LIST, "host", entry),
        SensitiveMatch::Personal(entry) => {
            (maknae_proto::PERSONAL_SENSITIVE_LIST, "personal", entry)
        }
        SensitiveMatch::None | SensitiveMatch::Unbound => return None,
    };
    Some(Protection {
        list,
        reason: format!("sensitive: {tag} {entry}"),
        entry,
    })
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
    emit.emit_within(&record, AUDIT_APPEND_TIMEOUT)
        .await
        .map_err(|_| ())?;
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
    record: AuditRecord,
    reason: String,
) {
    let answer = ProtoError {
        code: ProtoErrCode::Unauthorized,
        message: "not authorized".into(),
    };
    refuse_with(stream, cfg, emit, record, reason, answer).await;
}
async fn refuse_with<S: AsyncWrite + Unpin, E: AuditEmit>(
    stream: &mut S,
    cfg: &TransportConfig,
    emit: &E,
    mut record: AuditRecord,
    reason: String,
    answer: ProtoError,
) {
    record.outcome.result = "deny".into();
    record.outcome.reason = reason;
    record.outcome.posture = "unauthorized".into();
    if emit
        .emit_within(&record, AUDIT_APPEND_TIMEOUT)
        .await
        .is_ok()
    {
        send(
            stream,
            cfg,
            Response {
                protocol_version: PROTOCOL_VERSION,
                result: RespResult::Err(answer),
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
    conversations: Arc<dyn ConversationStore>,
    stamp: &Stamp<'_>,
    sensitive: Arc<SensitiveList>,
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
            refuse(stream, cfg, &*emit, record, busy_reason(busy).into()).await;
            return true;
        }
    };
    let fd = delegated.take();
    let original = verb.clone();
    let policy_name = policy_name.to_string();
    let stamped = match stamp {
        Stamp::Client => None,
        Stamp::Agent { agent, task } => Some(((*agent).clone(), task.cloned())),
    };
    let prepared = tokio::time::timeout(
        authz_timeout,
        tokio::task::spawn_blocking(move || {
            let _claim = claim;
            let asked = path(&original).ok_or("not a mutation")?;
            checked(asked)?;
            let gathered = gather(&*conversations, uid, cited(&original), None);
            let personal = owned_personal(gathered.as_ref().and_then(|(_, rec)| rec.as_ref()), uid);
            if let Some(p) = personal_list(personal.as_ref())
                .and_then(|listed| protection(&original, asked, &home, &sensitive, &listed))
            {
                return Ok(Err(p));
            }
            let prepared = prepare(original.clone(), fd, &home, lane)?;
            let stamp = match &stamped {
                None => Stamp::Client,
                Some((agent, task)) => Stamp::Agent {
                    agent,
                    task: task.as_ref(),
                },
            };
            let decision = authorize(
                &prepared,
                &original,
                uid,
                Some(&home),
                &*authorizer,
                &policy_name,
                gathered.as_ref().map(|(facts, _)| facts),
                personal.as_ref(),
                &stamp,
            );
            let mut touch_failure = None;
            if let (Ok(_), Some((_, Some(rec)))) = (&decision, &gathered) {
                let now = crate::run::unix_now();
                if let Err(e) =
                    conversations.update(&rec.id, rec.fence, &mut |r| r.last_active = now)
                {
                    touch_failure = Some(e.to_string());
                }
            }
            Ok::<_, String>(Ok((prepared, permit, decision, touch_failure)))
        }),
    )
    .await;
    let (prepared, permit, decision, touch_failure) = match prepared {
        Ok(Ok(Ok(Ok(p)))) => p,
        Ok(Ok(Ok(Err(p)))) => {
            let answer = ProtoError {
                code: ProtoErrCode::Protected,
                message: maknae_proto::protected_message(p.list, &p.entry),
            };
            refuse_with(stream, cfg, &*emit, record, p.reason, answer).await;
            return true;
        }
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
    record.rule = rule.as_ref().map(crate::run::rule_audit);
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
        if let Some(why) = touch_failure {
            let mut note = intent.record.clone();
            note.seq = seq.next();
            note.mutation = None;
            note.outcome.reason = format!("conversation activity not recorded: {why}");
            note.outcome.posture = "unavailable".into();
            if let Err(e) = emit.emit_within(&note, AUDIT_APPEND_TIMEOUT).await {
                eprintln!("maknaed: AUDIT WRITE FAILED on conversation record: {e}");
            }
        }
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
    fn a_released_store_slot_is_pruned() {
        let (released, held) = (4_170_201, 4_170_202);
        drop(store_slots(released));
        let _held = store_slots(held);
        let slots = STORE_SLOTS
            .get()
            .unwrap()
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        assert!(!slots.contains_key(&released));
        assert!(slots.contains_key(&held));
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_stalled_requester_pins_only_its_own_store_slot() {
        let _turn = EUID_TURN.lock().await;
        use std::sync::atomic::{AtomicUsize, Ordering::SeqCst};
        let (stalled, other) = (4_170_101, 4_170_102);
        let (release, held) = std::sync::mpsc::channel::<()>();
        let held = Arc::new(std::sync::Mutex::new(held));
        let entered = Arc::new(AtomicUsize::new(0));
        let attempts: Vec<_> = (0..4)
            .map(|_| {
                let (held, entered) = (Arc::clone(&held), Arc::clone(&entered));
                tokio::spawn(blocking(stalled, Duration::from_millis(300), move || {
                    entered.fetch_add(1, SeqCst);
                    let _ = held.lock().unwrap().recv();
                }))
            })
            .collect();
        let mut results = Vec::new();
        for a in attempts {
            results.push(a.await.unwrap());
        }
        results.sort_by_key(|r| *r == Err(Blocked::Unknown));
        assert_eq!(
            results,
            vec![
                Err(Blocked::NotStarted),
                Err(Blocked::NotStarted),
                Err(Blocked::NotStarted),
                Err(Blocked::Unknown)
            ]
        );
        assert_eq!(entered.load(SeqCst), STORE_SLOTS_PER_UID);
        assert_eq!(blocking(other, Duration::from_secs(5), || 7).await, Ok(7));
        assert!(mutating().try_claim(other).is_some());
        assert!(
            tokio::time::timeout(Duration::from_secs(5), capacity().acquire_owned())
                .await
                .is_ok(),
            "a shared worker is still free for another requester's mutation"
        );
        assert_eq!(
            blocking(stalled, Duration::from_millis(100), || 1).await,
            Err(Blocked::NotStarted)
        );
        release.send(()).unwrap();
        assert_eq!(blocking(stalled, Duration::from_secs(2), || 1).await, Ok(1));
    }

    #[test]
    fn blocked_work_names_whether_it_ever_started() {
        assert_eq!(
            Blocked::NotStarted.to_string(),
            "store work did not start within its bound"
        );
        assert_eq!(
            Blocked::Unknown.to_string(),
            "store work did not finish within its bound"
        );
    }

    #[test]
    fn the_object_label_is_the_ceiling_operands_resolution_with_no_categories() {
        let verb = Verb::Read {
            path: "/h/f".into(),
            conversation: None,
            page: None,
        };
        let plain = build_authz_request(&verb, 1000, None, Lane::Local, None, None, &Stamp::Client);
        let us = object_label("US", &plain).unwrap();
        assert_eq!(
            (us.level.as_str(), us.categories.len()),
            ("UNCLASSIFIED", 0)
        );
        let mut marked =
            build_authz_request(&verb, 1000, None, Lane::Local, None, None, &Stamp::Client);
        marked.resource.0.insert(
            maknae_security::RESOURCE_CLASSIFICATION,
            AttrValue::Str("SECRET//NOFORN".into()),
        );
        assert_eq!(object_label("US", &marked).unwrap().level, "SECRET");
        let mut foreign =
            build_authz_request(&verb, 1000, None, Lane::Local, None, None, &Stamp::Client);
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
        let prepared = prepare(read(), held(), &fx.root, Lane::Local).unwrap();
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
            prepare(read(), None, &fx.root, Lane::Local)
                .err()
                .as_deref(),
            Some("read descriptor missing")
        );
        assert!(prepare(read(), held(), &fx.root, Lane::Remote).is_err());
        assert!(prepare(read(), Some(fx.fd()), &fx.root, Lane::Local)
            .err()
            .unwrap()
            .starts_with("read evidence refused"));
        #[cfg(target_os = "linux")]
        assert!(prepare(
            read(),
            Some(std::fs::File::open(&target).unwrap().into()),
            &fx.root,
            Lane::Local
        )
        .err()
        .unwrap()
        .contains("confers access beyond location"));
        std::fs::hard_link(&target, fx.root.join("second-read-link")).unwrap();
        assert!(prepare(read(), held(), &fx.root, Lane::Local).is_err());
        assert_eq!(std::fs::read(target).unwrap(), b"sentinel");
    }
    fn fixture_pdp(fx: &Fixture) -> crate::Composition<maknae_authz_basic::HermeticAuthorizer> {
        let paths = maknae_authz_basic::PolicyPaths::in_dir(&fx.root);
        let name = nix::unistd::User::from_uid(nix::unistd::geteuid())
            .expect("NSS")
            .expect("the test euid has a passwd entry")
            .name;
        let files = [
            (
                &paths.authz,
                "schema_version: 1\npermissions:\n  allow:\n    - \"Read(~/**)\"\n    - \"Write(~/**)\"\n  deny: []\n"
                    .to_string(),
            ),
            (
                &paths.bindings,
                format!("schema_version: 1\nbindings:\n  user: [\"{name}\"]\n"),
            ),
        ];
        for (path, body) in files {
            std::fs::write(path, body).unwrap();
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o640)).unwrap();
        }
        crate::test_fixtures::write_empty_sensitive(&fx.root);
        let baseline = maknae_authz_basic::HermeticAuthorizer::new(
            paths,
            fx.principal.clone(),
            maknae_config::TargetRequired {
                owner: None,
                mode_mask: Some(0o022),
                nlink_exactly_one: false,
                regular_file: true,
                max_bytes: None,
            },
            maknae_crypto::sha256,
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
    struct Stall;
    impl AuditEmit for Stall {
        fn emit(
            &self,
            _: &AuditRecord,
        ) -> impl std::future::Future<Output = Result<(), maknae_audit_append::AuditError>> + Send
        {
            std::future::pending()
        }
    }
    #[tokio::test(start_paused = true)]
    async fn a_stalled_intent_record_gives_up_and_no_intent_is_durable() {
        let label = maknae_proto::ObjectLabel {
            level: "UNCLASSIFIED".into(),
            categories: Vec::new(),
        };
        let got = tokio::time::timeout(
            Duration::from_secs(60),
            commit_intent(
                &Stall,
                record(),
                None,
                FsOperation::Mkdir,
                Vec::new(),
                &label,
                None,
            ),
        )
        .await;
        assert!(
            matches!(got, Ok(Err(()))),
            "the intent append must give up within its bound"
        );
    }
    #[tokio::test(start_paused = true)]
    async fn a_stalled_refusal_record_gives_up_and_answers_nothing() {
        let mut stream: Vec<u8> = Vec::new();
        let got = tokio::time::timeout(
            Duration::from_secs(60),
            refuse(
                &mut stream,
                &TransportConfig::default(),
                &Stall,
                record(),
                "denied".into(),
            ),
        )
        .await;
        assert!(
            got.is_ok(),
            "the refusal append must give up within its bound"
        );
        assert!(
            stream.is_empty(),
            "a refusal without its record answers nothing"
        );
    }
    struct Delayed<P> {
        pdp: P,
        gate: Arc<(std::sync::Mutex<bool>, std::sync::Condvar)>,
    }
    impl<P: Authorizer> Authorizer for Delayed<P> {
        fn decide(&self, request: &maknae_security::Request) -> maknae_security::Verdict {
            self.decide_cited(request).verdict
        }

        fn decide_reporting_role(
            &self,
            request: &maknae_security::Request,
        ) -> (maknae_security::Verdict, Option<&'static str>) {
            self.decide_cited(request).into()
        }

        fn decide_cited(&self, request: &maknae_security::Request) -> maknae_security::Decided {
            let (lock, wake) = &*self.gate;
            let mut released = lock.lock().unwrap();
            while !*released {
                released = wake.wait(released).unwrap();
            }
            drop(released);
            self.pdp.decide_cited(request)
        }

        fn decide_cited_all(
            &self,
            requests: &[maknae_security::Request],
        ) -> Vec<maknae_security::Decided> {
            let (lock, wake) = &*self.gate;
            let mut released = lock.lock().unwrap();
            while !*released {
                released = wake.wait(released).unwrap();
            }
            drop(released);
            self.pdp.decide_cited_all(requests)
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
            Arc::new(crate::conversation::mem_store::MemStore::default()),
            &Stamp::Client,
            Arc::new(SensitiveList::empty()),
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
                    Arc::new(crate::conversation::mem_store::MemStore::default()),
                    &Stamp::Client,
                    Arc::new(SensitiveList::empty()),
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
                    Arc::new(crate::conversation::mem_store::MemStore::default()),
                    &Stamp::Client,
                    Arc::new(SensitiveList::empty()),
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
                Arc::new(crate::conversation::mem_store::MemStore::default()),
                &Stamp::Client,
                Arc::new(SensitiveList::empty()),
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
                Arc::new(crate::conversation::mem_store::MemStore::default()),
                &Stamp::Client,
                Arc::new(SensitiveList::empty()),
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
            Arc::new(crate::conversation::mem_store::MemStore::default()),
            &Stamp::Client,
            Arc::new(SensitiveList::empty()),
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
                Arc::new(crate::conversation::mem_store::MemStore::default()),
                &Stamp::Client,
                Arc::new(SensitiveList::empty()),
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
                Ok(fx.root.clone()),
                &cfg,
                &seq,
                record(),
                Duration::from_secs(1),
                AttemptCaps::default(),
                "US",
                Arc::new(crate::conversation::mem_store::MemStore::default()),
                &Stamp::Client,
                Arc::new(SensitiveList::empty()),
            )
            .await
        );
        assert_eq!(
            other.0.lock().unwrap().last().unwrap().outcome.reason,
            "mutation descriptor missing",
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
        assert!(prepare(Verb::Ping, None, &fx.root, Lane::Local).is_err());
        assert!(prepare(
            fx.mkdir(true, vec!["one".into(), "two".into()]),
            Some(fx.fd()),
            &fx.root,
            Lane::Remote
        )
        .is_err());
        assert!(prepare(
            fx.mkdir(true, vec!["one".into(), "two".into()]),
            None,
            &fx.root,
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
            Lane::Local
        )
        .is_err());
        let target = fx.root.join("real-file");
        std::fs::write(&target, b"sentinel").unwrap();
        assert!(prepare(
            fx.mkdir(true, vec!["two".into()]),
            Some(std::fs::File::open(&target).unwrap().into()),
            &fx.root,
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
        let prepared = prepare(write(), held(), &fx.root, Lane::Local).unwrap();
        assert_eq!(prepared.kind, FsOperation::WriteExisting);
        assert_eq!(prepared.paths, vec![target.to_str().unwrap().to_string()]);
        assert_eq!(
            prepared.scope,
            MutationScope::Exact {
                path: target.to_str().unwrap().into(),
                effect: ReportedEffect::ReplacedFile
            }
        );
        assert!(prepare(write(), Some(fx.fd()), &fx.root, Lane::Local).is_err());
        std::fs::hard_link(&target, fx.root.join("second-link")).unwrap();
        assert!(prepare(write(), held(), &fx.root, Lane::Local).is_err());
        assert_eq!(std::fs::read(target).unwrap(), b"sentinel");
    }
    struct ReloadsAfterEachDecision {
        pdp: crate::Composition<maknae_authz_basic::HermeticAuthorizer>,
        policy: std::path::PathBuf,
        next: String,
    }
    impl ReloadsAfterEachDecision {
        fn reload(&self) {
            std::fs::write(&self.policy, &self.next).unwrap();
            self.pdp.baseline().reload_from_file().unwrap();
        }
    }
    impl Authorizer for ReloadsAfterEachDecision {
        fn decide(&self, request: &maknae_security::Request) -> maknae_security::Verdict {
            self.decide_cited(request).verdict
        }
        fn decide_cited(&self, request: &maknae_security::Request) -> maknae_security::Decided {
            let d = self.pdp.decide_cited(request);
            self.reload();
            d
        }
        fn decide_cited_all(
            &self,
            requests: &[maknae_security::Request],
        ) -> Vec<maknae_security::Decided> {
            let all = self.pdp.decide_cited_all(requests);
            self.reload();
            all
        }
    }
    #[tokio::test]
    async fn a_reload_between_paths_cannot_split_a_mutation_across_snapshots() {
        let _turn = EUID_TURN.lock().await;
        let fx = Fixture::new();
        let pdp = fixture_pdp(&fx);
        let policy = fx.root.join("authz.yaml");
        let next = std::fs::read_to_string(&policy)
            .unwrap()
            .replace("deny: []", "deny:\n    - \"Write(~/one/two)\"");
        let pdp = ReloadsAfterEachDecision { pdp, policy, next };
        let verb = fx.mkdir(true, vec!["one".into(), "two".into()]);
        let prepared = prepare(verb.clone(), Some(fx.fd()), &fx.root, Lane::Local).unwrap();
        assert_eq!(prepared.paths.len(), 2);
        let (by, _) = authorize(
            &prepared,
            &verb,
            fx.principal.uid,
            Some(&fx.root),
            &pdp,
            "US",
            None,
            None,
            &Stamp::Client,
        )
        .expect("both paths decided on the snapshot in force when the mutation began");
        let rule = by.1.expect("the permit cites its allow rule");
        assert!(rule.section.ends_with("#permissions"), "{rule:?}");
        let (reason, path, _) = authorize(
            &prepared,
            &verb,
            fx.principal.uid,
            Some(&fx.root),
            &pdp,
            "US",
            None,
            None,
            &Stamp::Client,
        )
        .unwrap_err();
        assert!(reason.contains("Write(~/one/two)"), "{reason}");
        assert_eq!(path, prepared.paths[1]);
    }
    #[tokio::test]
    async fn a_write_is_permitted_only_when_a_read_of_the_same_path_is() {
        let _turn = EUID_TURN.lock().await;
        let fx = Fixture::new();
        let pdp = fixture_pdp(&fx);
        let policy = fx.root.join("authz.yaml");
        let existing = fx.root.join("write-needs-read-existing");
        std::fs::write(&existing, b"x").unwrap();
        let created = fx.root.join("write-needs-read-created");
        let write = |p: &Path, mode| Verb::FsWrite {
            path: p.to_str().unwrap().into(),
            content_length: 1,
            mode,
            conversation: None,
        };
        let cases = [
            (
                write(&existing, maknae_proto::WriteMode::Existing),
                maknae_io::open_path_for_delegation(&existing).unwrap(),
            ),
            (
                write(&created, maknae_proto::WriteMode::CreateExclusive),
                fx.fd(),
            ),
        ];
        let decide = |verb: &Verb, fd: &OwnedFd| {
            let prepared = prepare(
                verb.clone(),
                Some(fd.try_clone().unwrap()),
                &fx.root,
                Lane::Local,
            )
            .unwrap();
            authorize(
                &prepared,
                verb,
                fx.principal.uid,
                Some(&fx.root),
                &pdp,
                "US",
                None,
                None,
                &Stamp::Client,
            )
        };
        let reload = |allow: &str, deny: &str| {
            std::fs::write(
                &policy,
                format!("schema_version: 1\npermissions:\n  allow:\n{allow}  deny:{deny}\n"),
            )
            .unwrap();
            pdp.baseline().reload_from_file().unwrap();
        };
        reload("    - \"Write(~/**)\"\n", " []");
        for (verb, fd) in &cases {
            let (reason, path, _) = decide(verb, fd).unwrap_err();
            assert!(reason.starts_with(WRITE_NEEDS_READ), "{reason}");
            assert!(reason.contains("fs.read"), "{reason}");
            assert_eq!(Some(path.as_str()), super::path(verb));
        }
        reload("    - \"Read(~/**)\"\n    - \"Write(~/**)\"\n", " []");
        for (verb, fd) in &cases {
            let (by, _) = decide(verb, fd).expect("Read and Write both permit");
            let rule = by.1.expect("the permit cites a rule");
            assert_eq!(rule.key, "rule:permissions:allow:1", "the Write allow");
        }
        reload(
            "    - \"Read(~/**)\"\n    - \"Write(~/**)\"\n",
            "\n    - \"Read(~/write-needs-read-*)\"",
        );
        for (verb, fd) in &cases {
            let (reason, _, by) = decide(verb, fd).unwrap_err();
            assert!(reason.starts_with(WRITE_NEEDS_READ), "{reason}");
            assert!(reason.contains("Read(~/write-needs-read-*)"), "{reason}");
            let rule = by.1.expect("the deny cites the read's rule");
            assert_eq!(rule.key, "rule:permissions:deny:0", "the Read deny");
        }
        assert!(!created.exists());
    }
    #[test]
    fn a_personal_list_that_does_not_parse_answers_no_protection() {
        let set = |e: &[&str]| AttrValue::Set(e.iter().map(|s| s.to_string()).collect());
        assert_eq!(personal_list(None), Some(SensitiveList::empty()));
        assert_eq!(personal_list(Some(&set(&["~bob/x"]))), None);
        assert_eq!(personal_list(Some(&AttrValue::Str("/k".into()))), None);
        let listed = personal_list(Some(&set(&["/srv/k"]))).unwrap();
        let p = protection(
            &Verb::Read {
                path: "/srv/k".into(),
                conversation: None,
                page: None,
            },
            "/srv/k",
            Path::new("/home/u"),
            &SensitiveList::empty(),
            &listed,
        )
        .unwrap();
        assert_eq!(
            (p.list, p.reason.as_str(), p.entry.as_str()),
            (
                maknae_proto::PERSONAL_SENSITIVE_LIST,
                "sensitive: personal /srv/k",
                "/srv/k"
            )
        );
    }

    #[test]
    fn only_the_requesters_own_conversation_contributes_its_personal_list() {
        let id = maknae_proto::ConversationId::parse(&"6".repeat(32)).unwrap();
        let mut rec = crate::conversation::record::opened(id, 1001, "/w".into(), 1, "UNCLASSIFIED");
        rec.sensitive = vec!["~/sentinel-617-a".into(), "/srv/sentinel-617".into()];
        assert_eq!(
            owned_personal(Some(&rec), 1001),
            Some(AttrValue::Set(
                ["/srv/sentinel-617".to_string(), "~/sentinel-617-a".into()].into()
            ))
        );
        assert_eq!(owned_personal(Some(&rec), 1002), None);
        assert_eq!(owned_personal(None, 1001), None);
    }
    #[tokio::test]
    async fn the_personal_list_is_decided_on_every_path_of_the_request() {
        let _turn = EUID_TURN.lock().await;
        let fx = Fixture::new();
        let pdp = fixture_pdp(&fx);
        let verb = fx.mkdir(true, vec!["one".into(), "two".into()]);
        let prepared = prepare(verb.clone(), Some(fx.fd()), &fx.root, Lane::Local).unwrap();
        let first = prepared.paths[0].clone();
        let decide = |personal: Option<&AttrValue>| {
            authorize(
                &prepared,
                &verb,
                fx.principal.uid,
                Some(&fx.root),
                &pdp,
                "US",
                None,
                personal,
                &Stamp::Client,
            )
        };
        assert!(decide(None).is_ok());
        assert!(decide(Some(&AttrValue::Set(Default::default()))).is_ok());
        let personal = AttrValue::Set([first.clone()].into());
        let (reason, path, _) = decide(Some(&personal)).unwrap_err();
        assert_eq!(reason, format!("sensitive: personal {first}"));
        assert_eq!(path, first);
    }
    #[tokio::test]
    async fn a_deny_in_place_of_an_unacted_permit_cites_no_rule() {
        let _turn = EUID_TURN.lock().await;
        let fx = Fixture::new();
        let pdp = fixture_pdp(&fx);
        let verb = fx.mkdir(false, vec!["two".into()]);
        let prepared = prepare(verb.clone(), Some(fx.fd()), &fx.root, Lane::Local).unwrap();
        let (by, _) = authorize(
            &prepared,
            &verb,
            fx.principal.uid,
            Some(&fx.root),
            &pdp,
            "US",
            None,
            None,
            &Stamp::Client,
        )
        .unwrap();
        assert!(by.1.is_some(), "the permit itself cites a rule");
        let (reason, _, by) = authorize(
            &prepared,
            &verb,
            fx.principal.uid,
            Some(&fx.root),
            &pdp,
            "NO-SUCH-SYSTEM",
            None,
            None,
            &Stamp::Client,
        )
        .unwrap_err();
        assert_eq!(reason, "object label unresolved");
        assert_eq!(by, (Some("user"), None));
    }
}
