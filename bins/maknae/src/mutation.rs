//! Cooperative subject-side namespace attempts. A report describes client claims,
//! never a daemon observation or an authorization decision. A blocking syscall may
//! outlive a timeout; its worker can finish that step but cannot start another.
use maknae_config::TransportConfig;
use maknae_io::{
    AnchorRequired, DirectoryCursor, EffectState, IoError, IoKind, MutationDirectory,
    MutationFailure, MutationRequired,
};
use maknae_proto::{
    self as proto, EffectEntry, MutationGrant, MutationReport, MutationScope, ReportedEffect,
    ReportedFinish, WriteMode,
};
use std::collections::HashSet;
use std::io;
use std::os::fd::OwnedFd;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};
use tokio::io::{AsyncRead, AsyncWrite};

pub struct PreparedMutation {
    request: proto::Verb,
    fd: Option<OwnedFd>,
    error: Option<String>,
    components: Vec<String>,
}
impl PreparedMutation {
    pub fn request(&self) -> &proto::Verb {
        &self.request
    }
    pub fn descriptor(&self) -> io::Result<Option<OwnedFd>> {
        self.fd.as_ref().map(OwnedFd::try_clone).transpose()
    }
    pub fn preparation_error(&self) -> Option<&str> {
        self.error.as_deref()
    }
    pub fn is_namespace(&self) -> bool {
        !matches!(
            self.request,
            proto::Verb::FsWrite {
                mode: WriteMode::Existing,
                ..
            }
        )
    }
}

fn normal(name: &str) -> bool {
    !name.is_empty()
        && name != "."
        && name != ".."
        && !name.contains(['/', '\0'])
        && name.len() <= proto::MAX_MUTATION_PATH_BYTES
}
fn split(path: &str) -> io::Result<(PathBuf, String)> {
    let leaf = path.rsplit('/').next().unwrap_or("");
    if path.len() > proto::MAX_MUTATION_PATH_BYTES || path.contains('\0') || !normal(leaf) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "invalid mutation path",
        ));
    }
    let parent = Path::new(path)
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    Ok((parent.into(), leaf.into()))
}

/// Opening evidence never creates, truncates, removes or publishes anything.
/// An open failure retains the request so the daemon can audit its refusal.
pub fn prepare(mut request: proto::Verb) -> Option<PreparedMutation> {
    let mut components = Vec::new();
    let opened = match &mut request {
        proto::Verb::FsWrite { path, mode, .. } => {
            *mode = WriteMode::Existing;
            match split(path) {
                Err(e) => Err(e),
                Ok((parent, leaf)) => {
                    components.push(leaf);
                    match maknae_io::open_writable_for_delegation(Path::new(path)) {
                        Ok(fd) => Ok(fd),
                        Err(e) if e.kind() == io::ErrorKind::NotFound => {
                            *mode = WriteMode::CreateExclusive;
                            maknae_io::open_directory_for_delegation(&parent)
                        }
                        Err(e) => Err(e),
                    }
                }
            }
        }
        proto::Verb::FsDelete { path, .. } => split(path).and_then(|(parent, leaf)| {
            components.push(leaf);
            maknae_io::open_directory_for_delegation(&parent)
        }),
        proto::Verb::FsMkdir {
            path,
            parents,
            components: wire_components,
        } => {
            let result = split(path).and_then(|(mut parent, leaf)| {
                components.push(leaf);
                loop {
                    match maknae_io::open_directory_for_delegation(&parent) {
                        Ok(fd) => break Ok(fd),
                        Err(e) if *parents && e.kind() == io::ErrorKind::NotFound => {
                            if components.len() >= usize::from(proto::MAX_MUTATION_DEPTH) {
                                break Err(io::Error::new(
                                    io::ErrorKind::InvalidInput,
                                    "mkdir depth limit",
                                ));
                            }
                            let Some(text) = parent.to_str() else {
                                break Err(io::Error::new(
                                    io::ErrorKind::InvalidInput,
                                    "unsupported path name",
                                ));
                            };
                            let (next, name) = split(text)?;
                            components.push(name);
                            parent = next;
                        }
                        Err(e) => break Err(e),
                    }
                }
            });
            components.reverse();
            *wire_components = components.clone();
            result
        }
        _ => return None,
    };
    let (fd, error) = match opened {
        Ok(fd) => (Some(fd), None),
        Err(e) => (None, Some(e.to_string())),
    };
    Some(PreparedMutation {
        request,
        fd,
        error,
        components,
    })
}

fn grant_parent(prepared: &PreparedMutation, grant: &MutationGrant) -> Result<PathBuf, String> {
    if prepared.fd.is_none() {
        return Err("namespace grant without prepared directory evidence".into());
    }
    let first = match (&prepared.request, &grant.scope) {
        (
            proto::Verb::FsWrite {
                mode: WriteMode::CreateExclusive,
                ..
            },
            MutationScope::Exact {
                path,
                effect: ReportedEffect::CreatedFile,
            },
        )
        | (
            proto::Verb::FsDelete {
                recursive: false, ..
            },
            MutationScope::Exact {
                path,
                effect: ReportedEffect::DeletedEntry,
            },
        )
        | (
            proto::Verb::FsMkdir { parents: false, .. },
            MutationScope::Exact {
                path,
                effect: ReportedEffect::CreatedDirectory,
            },
        ) => path,
        (
            proto::Verb::FsDelete {
                recursive: true, ..
            },
            MutationScope::RecursiveDelete { root },
        ) => root,
        (proto::Verb::FsMkdir { parents: true, .. }, MutationScope::Directories { paths })
            if !paths.is_empty() && paths.len() == prepared.components.len() =>
        {
            &paths[0]
        }
        _ => return Err("mutation grant does not match prepared operation".into()),
    };
    let (parent, leaf) = split(first).map_err(|e| e.to_string())?;
    if !Path::new(first).is_absolute() || prepared.components.first() != Some(&leaf) {
        return Err("mutation grant does not match prepared leaf".into());
    }
    // Reject noncanonical lexical spelling, while allowing a requested parent alias:
    // the held descriptor below is compared with the daemon's canonical parent.
    let mut current = parent.clone();
    for (index, component) in prepared.components.iter().enumerate() {
        if !normal(component) {
            return Err("invalid prepared component".into());
        }
        current.push(component);
        let expected = match &grant.scope {
            MutationScope::Directories { paths } => &paths[index],
            _ => first,
        };
        if current.to_str() != Some(expected)
            || current.components().any(|c| {
                matches!(
                    c,
                    std::path::Component::ParentDir | std::path::Component::CurDir
                )
            })
        {
            return Err("mutation grant component mismatch".into());
        }
    }
    Ok(parent)
}

struct WalkFrame {
    directory: MutationDirectory,
    cursor: DirectoryCursor,
    leaf: String,
    depth: usize,
}
enum Work {
    Create {
        parent: MutationDirectory,
        leaf: String,
        bytes: proto::Bytes,
    },
    Delete {
        parent: MutationDirectory,
        leaf: String,
        recursive: bool,
        stack: Vec<WalkFrame>,
        pending: Option<String>,
    },
    Mkdir {
        parent: MutationDirectory,
        components: std::collections::VecDeque<String>,
        parents: bool,
    },
    Done,
}
struct Worker {
    work: Work,
    grant: MutationGrant,
    deadline: Instant,
    frame_cap: usize,
    next_index: u32,
    seen: HashSet<String>,
}
struct Step {
    effect: Option<EffectEntry>,
    finish: Option<(ReportedFinish, Option<String>)>,
}
impl Step {
    fn stop(outcome: ReportedFinish, path: Option<String>) -> Self {
        Self {
            effect: None,
            finish: Some((outcome, path)),
        }
    }
}
fn io_finish(error: &IoError) -> ReportedFinish {
    match error {
        IoError::NonUtf8Component { .. } => ReportedFinish::UnsupportedName,
        IoError::MutationPathChanged { .. } => ReportedFinish::PathChanged,
        IoError::DeadlineElapsed { .. } => ReportedFinish::LimitReached,
        _ => ReportedFinish::OsRefused,
    }
}
fn error_step(e: MutationFailure, effect: ReportedEffect, path: String) -> Step {
    let changed = e.state != EffectState::NoEffect;
    let outcome = match e.state {
        EffectState::DurabilityUnknown => ReportedFinish::DurabilityUnknown,
        EffectState::Partial | EffectState::Applied => ReportedFinish::Partial,
        EffectState::NoEffect => io_finish(&e.source),
    };
    Step {
        effect: changed.then(|| EffectEntry {
            path: path.clone(),
            effect,
        }),
        finish: Some((outcome, Some(path))),
    }
}
fn batch(id: proto::MutationId, index: u32, entry: EffectEntry) -> MutationReport {
    MutationReport::Batch {
        id,
        first_index: index,
        effects: vec![entry],
    }
}
fn finished(
    id: proto::MutationId,
    index: u32,
    outcome: ReportedFinish,
    stopped_at: Option<String>,
) -> MutationReport {
    MutationReport::Finished {
        id,
        next_index: index,
        outcome,
        stopped_at,
    }
}
fn fits(report: &MutationReport, cap: usize) -> bool {
    proto::encode_mutation_report(report).is_ok_and(|bytes| bytes.len() <= cap)
}
impl Worker {
    /// Reserve both effect and every terminal form before entering the syscall.
    fn reserve(&self, path: &Path, effect: ReportedEffect, depth: usize) -> Result<String, Step> {
        let Some(path) = path.to_str() else {
            return Err(Step::stop(ReportedFinish::UnsupportedName, None));
        };
        if path.len() > proto::MAX_MUTATION_PATH_BYTES
            || depth > usize::from(self.grant.limits.max_depth)
            || self.next_index >= self.grant.limits.max_effects
            || Instant::now() >= self.deadline
        {
            return Err(Step::stop(ReportedFinish::LimitReached, None));
        }
        if self.seen.contains(path) {
            return Err(Step::stop(ReportedFinish::PathChanged, Some(path.into())));
        }
        let entry = EffectEntry {
            path: path.into(),
            effect,
        };
        if !fits(
            &batch(self.grant.id, self.next_index, entry),
            self.frame_cap,
        ) {
            return Err(Step::stop(ReportedFinish::LimitReached, None));
        }
        for outcome in [
            ReportedFinish::Success,
            ReportedFinish::OsRefused,
            ReportedFinish::Partial,
            ReportedFinish::LimitReached,
            ReportedFinish::PathChanged,
            ReportedFinish::UnsupportedName,
            ReportedFinish::DurabilityUnknown,
        ] {
            for index in [self.next_index, self.next_index + 1] {
                if !fits(
                    &finished(self.grant.id, index, outcome, Some(path.into())),
                    self.frame_cap,
                ) {
                    return Err(Step::stop(ReportedFinish::LimitReached, None));
                }
            }
        }
        Ok(path.into())
    }
    fn step(&mut self) -> Step {
        let work = std::mem::replace(&mut self.work, Work::Done);
        match work {
            Work::Done => Step::stop(ReportedFinish::Success, None),
            Work::Create {
                parent,
                leaf,
                bytes,
            } => {
                let path = match self.reserve(
                    &parent.path().join(&leaf),
                    ReportedEffect::CreatedFile,
                    1,
                ) {
                    Ok(p) => p,
                    Err(s) => return s,
                };
                match parent.create_exclusive(&leaf, &bytes.0) {
                    Ok(_) => Step {
                        effect: Some(EffectEntry {
                            path,
                            effect: ReportedEffect::CreatedFile,
                        }),
                        finish: Some((ReportedFinish::Success, None)),
                    },
                    Err(e) => error_step(e, ReportedEffect::CreatedFile, path),
                }
            }
            Work::Mkdir {
                mut parent,
                mut components,
                parents,
            } => loop {
                let Some(leaf) = components.pop_front() else {
                    return Step::stop(ReportedFinish::Success, None);
                };
                let depth = match &self.grant.scope {
                    MutationScope::Directories { paths } => paths.len() - components.len(),
                    _ => 1,
                };
                let path = match self.reserve(
                    &parent.path().join(&leaf),
                    ReportedEffect::CreatedDirectory,
                    depth,
                ) {
                    Ok(p) => p,
                    Err(s) => return s,
                };
                match parent.mkdir_one(&leaf) {
                    Ok(_) => {
                        let effect = Some(EffectEntry {
                            path: path.clone(),
                            effect: ReportedEffect::CreatedDirectory,
                        });
                        if components.is_empty() {
                            return Step {
                                effect,
                                finish: Some((ReportedFinish::Success, None)),
                            };
                        }
                        match parent.open_child_directory(&leaf) {
                            Ok(child) => {
                                self.work = Work::Mkdir {
                                    parent: child,
                                    components,
                                    parents,
                                };
                                return Step {
                                    effect,
                                    finish: None,
                                };
                            }
                            Err(e) => {
                                return Step {
                                    effect,
                                    finish: Some((io_finish(&e), Some(path))),
                                }
                            }
                        }
                    }
                    Err(MutationFailure {
                        state: EffectState::NoEffect,
                        source:
                            IoError::Io {
                                kind: IoKind::AlreadyExists,
                                ..
                            },
                        ..
                    }) if parents => match parent.open_child_directory(&leaf) {
                        Ok(child) => parent = child,
                        Err(e) => return Step::stop(io_finish(&e), Some(path)),
                    },
                    Err(e) => return error_step(e, ReportedEffect::CreatedDirectory, path),
                }
            },
            Work::Delete {
                parent,
                leaf,
                recursive,
                mut stack,
                mut pending,
            } => {
                loop {
                    if Instant::now() >= self.deadline {
                        return Step::stop(ReportedFinish::LimitReached, None);
                    }
                    // Try removal first: empty directories need no read/search access
                    // on the directory itself, including modes 0300 and 0000.
                    let (target_parent, target_leaf, depth, closing) = if stack.is_empty() {
                        (&parent, leaf.clone(), 0, false)
                    } else if let Some(name) = pending.take() {
                        (&stack.last().unwrap().directory, name, stack.len(), false)
                    } else {
                        let last = stack.last_mut().unwrap();
                        match last.cursor.next_entry() {
                            Ok(Some(entry)) => {
                                pending = match entry.name.into_string() {
                                    Ok(name) => Some(name),
                                    Err(_) => {
                                        return Step::stop(ReportedFinish::UnsupportedName, None)
                                    }
                                };
                                continue;
                            }
                            Ok(None) => {
                                let name = last.leaf.clone();
                                let closing_depth = last.depth;
                                let dir = if stack.len() == 1 {
                                    &parent
                                } else {
                                    &stack[stack.len() - 2].directory
                                };
                                (dir, name, closing_depth, true)
                            }
                            Err(e) => return Step::stop(io_finish(&e), None),
                        }
                    };
                    let path = match self.reserve(
                        &target_parent.path().join(&target_leaf),
                        ReportedEffect::DeletedEntry,
                        depth,
                    ) {
                        Ok(p) => p,
                        Err(s) => return s,
                    };
                    match target_parent.remove_entry(&target_leaf) {
                        Ok(_) => {
                            if closing {
                                stack.pop();
                            }
                            let done = stack.is_empty();
                            if !done {
                                self.work = Work::Delete {
                                    parent,
                                    leaf,
                                    recursive,
                                    stack,
                                    pending,
                                };
                            }
                            return Step {
                                effect: Some(EffectEntry {
                                    path,
                                    effect: ReportedEffect::DeletedEntry,
                                }),
                                finish: done.then_some((ReportedFinish::Success, None)),
                            };
                        }
                        Err(MutationFailure {
                            state: EffectState::NoEffect,
                            source:
                                IoError::Io {
                                    kind: IoKind::DirectoryNotEmpty,
                                    ..
                                },
                            ..
                        }) if recursive && !closing => {
                            if depth >= usize::from(self.grant.limits.max_depth) {
                                return Step::stop(ReportedFinish::LimitReached, Some(path));
                            }
                            let child = match target_parent.open_child_directory(&target_leaf) {
                                Ok(c) => c,
                                Err(e) => return Step::stop(io_finish(&e), Some(path)),
                            };
                            let cursor = match child.cursor() {
                                Ok(c) => c,
                                Err(e) => return Step::stop(io_finish(&e), Some(path)),
                            };
                            stack.push(WalkFrame {
                                directory: child,
                                cursor,
                                leaf: target_leaf,
                                depth,
                            });
                        }
                        Err(e) => return error_step(e, ReportedEffect::DeletedEntry, path),
                    }
                }
            }
        }
    }
}

async fn report<S: AsyncRead + AsyncWrite + Unpin>(
    stream: &mut S,
    cfg: &TransportConfig,
    deadline: Instant,
    message: MutationReport,
    id: proto::MutationId,
    index: u32,
) -> Result<(), String> {
    let body = proto::encode_mutation_report(&message).map_err(|e| e.to_string())?;
    if body.len() > cfg.frame_max_bytes {
        return Err("mutation report exceeds frame limit; no automatic retry".into());
    }
    let exchange = async {
        proto::write_frame(stream, &body)
            .await
            .map_err(|e| e.to_string())?;
        let bytes = proto::read_frame(stream, cfg.frame_max_bytes)
            .await
            .map_err(|e| e.to_string())?;
        let ack = proto::decode_mutation_ack(&bytes).map_err(|e| e.to_string())?;
        if ack.id != id || ack.next_index != index {
            return Err("mutation acknowledgment correlation mismatch".into());
        }
        Ok(())
    };
    tokio::time::timeout_at(tokio::time::Instant::from_std(deadline), exchange).await.map_err(|_| "mutation acknowledgment timed out; effects may already have occurred; no automatic retry".to_string())?
}

pub async fn execute<S: AsyncRead + AsyncWrite + Unpin + Send>(
    prepared: PreparedMutation,
    grant: MutationGrant,
    stream: &mut S,
    cfg: &TransportConfig,
    request_started: Instant,
) -> Result<bool, String> {
    let parent_path = grant_parent(&prepared, &grant)?;
    if grant.limits.max_effects == 0
        || grant.limits.max_effects > proto::MAX_MUTATION_EFFECTS
        || grant.limits.max_depth == 0
        || grant.limits.max_depth > proto::MAX_MUTATION_DEPTH
        || grant.limits.deadline_ms == 0
    {
        return Err("invalid mutation grant limits".into());
    }
    // Charge grant delivery and earlier request work to the same attempt window.
    // Acknowledgments never refresh this deadline.
    let deadline = request_started
        .checked_add(Duration::from_millis(
            grant.limits.deadline_ms.min(cfg.read_timeout_ms),
        ))
        .ok_or_else(|| "mutation deadline exceeds monotonic clock range".to_string())?;
    if Instant::now() >= deadline {
        return Err(
            "mutation attempt expired before grant receipt; no namespace effect started".into(),
        );
    }
    let id = grant.id;
    let cap = cfg.frame_max_bytes;
    if !fits(&finished(id, 0, ReportedFinish::LimitReached, None), cap) {
        return Err("frame limit cannot hold mutation completion; no effect attempted".into());
    }
    let initialize = tokio::task::spawn_blocking(move || -> Result<Worker, String> {
        let parent = maknae_io::verify_mutation_directory(
            prepared.fd.unwrap(),
            MutationRequired {
                confined_beneath: parent_path.clone(),
                root_required: AnchorRequired::OS_DAC,
            },
        )
        .map_err(|e| e.to_string())?
        .with_deadline(deadline);
        if parent.path() != parent_path {
            return Err("held mutation directory differs from grant parent".into());
        }
        let leaf = prepared.components[0].clone();
        let work = match prepared.request {
            proto::Verb::FsWrite {
                mode: WriteMode::CreateExclusive,
                content,
                ..
            } => Work::Create {
                parent,
                leaf,
                bytes: content,
            },
            proto::Verb::FsDelete { recursive, .. } => Work::Delete {
                parent,
                leaf,
                recursive,
                stack: Vec::new(),
                pending: None,
            },
            proto::Verb::FsMkdir { parents, .. } => Work::Mkdir {
                parent,
                components: prepared.components.into(),
                parents,
            },
            _ => return Err("unexpected mutation operation".into()),
        };
        Ok(Worker {
            work,
            grant,
            deadline,
            frame_cap: cap,
            next_index: 0,
            seen: HashSet::new(),
        })
    });
    let mut worker = tokio::time::timeout_at(tokio::time::Instant::from_std(deadline), initialize)
        .await
        .map_err(|_| {
            "mutation directory verification timed out; no namespace effect started".to_string()
        })?
        .map_err(|e| e.to_string())??;
    loop {
        // The worker performs at most one effect. Dropping this waiter never
        // releases a worker to start a second effect without the durable ack.
        let task = tokio::task::spawn_blocking(move || {
            let step = worker.step();
            (worker, step)
        });
        let (mut next, step) = tokio::time::timeout_at(tokio::time::Instant::from_std(deadline), task).await.map_err(|_| "mutation worker exceeded attempt window; a syscall may still complete; no automatic retry".to_string())?.map_err(|e| e.to_string())?;
        if let Some(entry) = step.effect {
            let message = batch(id, next.next_index, entry.clone());
            next.next_index += 1;
            next.seen.insert(entry.path);
            report(stream, cfg, deadline, message, id, next.next_index).await?;
        }
        if let Some((outcome, at)) = step.finish {
            let outcome = if outcome == ReportedFinish::OsRefused && next.next_index > 0 {
                ReportedFinish::Partial
            } else {
                outcome
            };
            report(
                stream,
                cfg,
                deadline,
                finished(id, next.next_index, outcome, at),
                id,
                next.next_index,
            )
            .await?;
            if outcome != ReportedFinish::Success {
                eprintln!(
                    "mutation stopped: {outcome:?}; {} effect(s) reported",
                    next.next_index
                );
            }
            return Ok(outcome == ReportedFinish::Success);
        }
        worker = next;
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicUsize, Ordering};
    struct Fixture(PathBuf);
    impl Fixture {
        fn new() -> Self {
            static NEXT: AtomicUsize = AtomicUsize::new(0);
            let p = std::env::temp_dir().join(format!(
                "maknae-mutation-{}-{}",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::Relaxed)
            ));
            std::fs::create_dir(&p).unwrap();
            Self(p.canonicalize().unwrap())
        }
        fn path(&self, leaf: &str) -> String {
            self.0.join(leaf).to_str().unwrap().into()
        }
    }
    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }
    fn write(path: String) -> proto::Verb {
        proto::Verb::FsWrite {
            path,
            content: proto::Bytes::new(zeroize::Zeroizing::new(b"new bytes".to_vec())),
            mode: proto::WriteMode::Existing,
        }
    }
    #[test]
    fn preparation_preserves_existing_sentinel_and_missing_entries() {
        let d = Fixture::new();
        let p = d.path("prepare-original-sentinel");
        std::fs::write(&p, b"original preserved bytes").unwrap();
        assert!(prepare(write(p.clone())).is_some());
        assert_eq!(std::fs::read(p).unwrap(), b"original preserved bytes");
        assert!(prepare(write(d.path("prepare-absent-sentinel"))).is_some());
        assert!(!d.0.join("prepare-absent-sentinel").exists());
        assert!(prepare(proto::Verb::FsMkdir {
            path: d.path("prepare-parent/child"),
            parents: true,
            components: vec![]
        })
        .is_some());
        assert!(!d.0.join("prepare-parent").exists());
    }
    fn grant(scope: MutationScope) -> MutationGrant {
        MutationGrant {
            id: proto::MutationId {
                session_id: 991,
                intent_seq: 158,
            },
            scope,
            limits: proto::MutationLimits {
                max_effects: proto::MAX_MUTATION_EFFECTS,
                max_depth: proto::MAX_MUTATION_DEPTH,
                deadline_ms: 5000,
            },
        }
    }
    fn mkdir(path: String, parents: bool) -> proto::Verb {
        proto::Verb::FsMkdir {
            path,
            parents,
            components: vec![],
        }
    }
    fn delete(path: String, recursive: bool) -> proto::Verb {
        proto::Verb::FsDelete { path, recursive }
    }
    async fn acknowledged(
        prepared: PreparedMutation,
        grant: MutationGrant,
        cfg: TransportConfig,
    ) -> (Result<bool, String>, Vec<MutationReport>) {
        acknowledged_from(prepared, grant, cfg, Instant::now()).await
    }
    async fn acknowledged_from(
        prepared: PreparedMutation,
        grant: MutationGrant,
        cfg: TransportConfig,
        request_started: Instant,
    ) -> (Result<bool, String>, Vec<MutationReport>) {
        let (mut client, mut server) = tokio::io::duplex(65536);
        let cap = cfg.frame_max_bytes;
        let receiver = tokio::spawn(async move {
            let mut reports = vec![];
            while let Ok(bytes) = proto::read_frame(&mut server, cap).await {
                let report = proto::decode_mutation_report(&bytes).unwrap();
                let (id, next_index, terminal) = match &report {
                    MutationReport::Batch {
                        id,
                        first_index,
                        effects,
                    } => (*id, first_index + effects.len() as u32, false),
                    MutationReport::Finished { id, next_index, .. } => (*id, *next_index, true),
                };
                reports.push(report);
                proto::write_frame(
                    &mut server,
                    &proto::encode_mutation_ack(&proto::MutationAck { id, next_index }).unwrap(),
                )
                .await
                .unwrap();
                if terminal {
                    break;
                }
            }
            reports
        });
        let result = execute(prepared, grant, &mut client, &cfg, request_started).await;
        drop(client);
        (result, receiver.await.unwrap())
    }
    #[test]
    fn preparation_keeps_evidence_and_never_reinterprets_other_open_errors() {
        let d = Fixture::new();
        std::fs::write(d.path("original"), b"unchanged").unwrap();
        let p = prepare(write(d.path("original"))).unwrap();
        assert!(matches!(
            p.request(),
            proto::Verb::FsWrite {
                mode: WriteMode::Existing,
                ..
            }
        ));
        assert!(!p.is_namespace());
        assert!(p.descriptor().unwrap().is_some());
        assert_eq!(p.preparation_error(), None);
        let absent = prepare(write(d.path("absent"))).unwrap();
        assert!(matches!(
            absent.request(),
            proto::Verb::FsWrite {
                mode: WriteMode::CreateExclusive,
                ..
            }
        ));
        let directory = prepare(write(d.0.to_str().unwrap().into())).unwrap();
        assert!(matches!(
            directory.request(),
            proto::Verb::FsWrite {
                mode: WriteMode::Existing,
                ..
            }
        ));
        assert!(directory.preparation_error().is_some());
        assert!(directory.descriptor().unwrap().is_none());
        let malformed = prepare(mkdir(d.path(".."), true)).unwrap();
        assert!(malformed.preparation_error().is_some());
        assert!(prepare(proto::Verb::Ping).is_none());
    }
    #[tokio::test]
    async fn exclusive_collision_preserves_intervening_sentinel() {
        let d = Fixture::new();
        let path = d.path("exclusive-collision-sentinel");
        let prepared = prepare(write(path.clone())).unwrap();
        std::fs::write(&path, b"intervening owner bytes").unwrap();
        let (result, reports) = acknowledged(
            prepared,
            grant(MutationScope::Exact {
                path: path.clone(),
                effect: ReportedEffect::CreatedFile,
            }),
            TransportConfig::default(),
        )
        .await;
        assert_eq!(result, Ok(false));
        assert_eq!(std::fs::read(path).unwrap(), b"intervening owner bytes");
        assert!(matches!(
            &reports[..],
            [MutationReport::Finished {
                next_index: 0,
                outcome: ReportedFinish::OsRefused,
                ..
            }]
        ));
    }
    #[tokio::test]
    async fn create_reports_effect_then_distinct_completion_and_preserves_bytes() {
        let d = Fixture::new();
        let path = d.path("created-content-sentinel");
        let (result, reports) = acknowledged(
            prepare(write(path.clone())).unwrap(),
            grant(MutationScope::Exact {
                path: path.clone(),
                effect: ReportedEffect::CreatedFile,
            }),
            TransportConfig::default(),
        )
        .await;
        assert_eq!(result, Ok(true));
        assert_eq!(std::fs::read(path).unwrap(), b"new bytes");
        assert!(
            matches!(&reports[..], [MutationReport::Batch { first_index: 0, effects, .. }, MutationReport::Finished { next_index: 1, outcome: ReportedFinish::Success, .. }] if effects.len() == 1)
        );
    }
    #[tokio::test]
    async fn mkdir_parents_refuses_planted_symlink_and_accepts_real_existing_dir() {
        let d = Fixture::new();
        let outside = Fixture::new();
        let paths = vec![d.path("new-parent"), d.path("new-parent/child-sentinel")];
        let prepared = prepare(mkdir(paths[1].clone(), true)).unwrap();
        std::os::unix::fs::symlink(&outside.0, &paths[0]).unwrap();
        let (result, _) = acknowledged(
            prepared,
            grant(MutationScope::Directories { paths }),
            TransportConfig::default(),
        )
        .await;
        assert_eq!(result, Ok(false));
        assert!(!outside.0.join("child-sentinel").exists());
        std::fs::create_dir(d.path("real-existing")).unwrap();
        let (result, reports) = acknowledged(
            prepare(mkdir(d.path("real-existing"), true)).unwrap(),
            grant(MutationScope::Directories {
                paths: vec![d.path("real-existing")],
            }),
            TransportConfig::default(),
        )
        .await;
        assert_eq!(result, Ok(true));
        assert!(matches!(
            &reports[..],
            [MutationReport::Finished {
                next_index: 0,
                outcome: ReportedFinish::Success,
                ..
            }]
        ));
    }
    #[tokio::test]
    async fn recursive_delete_never_follows_symlink_and_root_is_last() {
        let d = Fixture::new();
        let outside = Fixture::new();
        let root = d.path("recursive-root");
        std::fs::create_dir(&root).unwrap();
        std::fs::create_dir(d.path("recursive-root/sub")).unwrap();
        std::fs::write(d.path("recursive-root/sub/inside"), b"inside").unwrap();
        std::fs::write(outside.path("outside-preserved-sentinel"), b"safe outside").unwrap();
        std::os::unix::fs::symlink(&outside.0, d.path("recursive-root/link")).unwrap();
        let (result, reports) = acknowledged(
            prepare(delete(root.clone(), true)).unwrap(),
            grant(MutationScope::RecursiveDelete { root: root.clone() }),
            TransportConfig::default(),
        )
        .await;
        assert_eq!(result, Ok(true));
        assert!(!Path::new(&root).exists());
        assert_eq!(
            std::fs::read(outside.path("outside-preserved-sentinel")).unwrap(),
            b"safe outside"
        );
        let effects: Vec<_> = reports
            .iter()
            .filter_map(|r| match r {
                MutationReport::Batch { effects, .. } => Some(&effects[0].path),
                _ => None,
            })
            .collect();
        assert_eq!(effects.len(), 4);
        assert_eq!(effects.last(), Some(&&root));
    }
    #[tokio::test]
    async fn nonrecursive_nonempty_refusal_preserves_unique_sentinel() {
        let d = Fixture::new();
        let root = d.path("nonrecursive");
        std::fs::create_dir(&root).unwrap();
        std::fs::write(d.path("nonrecursive/keep-sentinel"), b"keep").unwrap();
        let (result, reports) = acknowledged(
            prepare(delete(root.clone(), false)).unwrap(),
            grant(MutationScope::Exact {
                path: root,
                effect: ReportedEffect::DeletedEntry,
            }),
            TransportConfig::default(),
        )
        .await;
        assert_eq!(result, Ok(false));
        assert_eq!(
            std::fs::read(d.path("nonrecursive/keep-sentinel")).unwrap(),
            b"keep"
        );
        assert!(matches!(
            &reports[..],
            [MutationReport::Finished { next_index: 0, .. }]
        ));
    }
    #[tokio::test]
    async fn tiny_frame_and_wrong_grant_have_no_effect() {
        let d = Fixture::new();
        let path = d.path("no-effect-sentinel");
        let cfg = TransportConfig {
            frame_max_bytes: 1,
            ..TransportConfig::default()
        };
        let (result, _) = acknowledged(
            prepare(write(path.clone())).unwrap(),
            grant(MutationScope::Exact {
                path: path.clone(),
                effect: ReportedEffect::CreatedFile,
            }),
            cfg,
        )
        .await;
        assert!(result.is_err());
        assert!(!Path::new(&path).exists());
        let outside = Fixture::new();
        let (result, _) = acknowledged(
            prepare(write(path.clone())).unwrap(),
            grant(MutationScope::Exact {
                path: outside.path("no-effect-sentinel"),
                effect: ReportedEffect::CreatedFile,
            }),
            TransportConfig::default(),
        )
        .await;
        assert!(result.is_err());
        assert!(!Path::new(&path).exists());
        assert!(!outside.0.join("no-effect-sentinel").exists());
    }
    #[tokio::test]
    async fn missing_ack_prevents_next_batch_and_never_retries() {
        let d = Fixture::new();
        let paths = vec![
            d.path("ack-parent"),
            d.path("ack-parent/not-created-sentinel"),
        ];
        let prepared = prepare(mkdir(paths[1].clone(), true)).unwrap();
        let (mut client, mut server) = tokio::io::duplex(65536);
        let task = tokio::spawn(async move {
            execute(
                prepared,
                grant(MutationScope::Directories { paths }),
                &mut client,
                &TransportConfig::default(),
                Instant::now(),
            )
            .await
        });
        let bytes = proto::read_frame(&mut server, 65536).await.unwrap();
        assert!(matches!(
            proto::decode_mutation_report(&bytes).unwrap(),
            MutationReport::Batch { first_index: 0, .. }
        ));
        assert!(d.0.join("ack-parent").is_dir());
        assert!(!d.0.join("ack-parent/not-created-sentinel").exists());
        drop(server);
        assert!(task.await.unwrap().is_err());
        assert!(!d.0.join("ack-parent/not-created-sentinel").exists());
    }
    #[tokio::test]
    async fn reserved_frame_budget_and_effect_limit_stop_before_next_effect() {
        let d = Fixture::new();
        let path = d.path("long-report-sentinel");
        let g = grant(MutationScope::Exact {
            path: path.clone(),
            effect: ReportedEffect::CreatedFile,
        });
        let base_size =
            proto::encode_mutation_report(&finished(g.id, 0, ReportedFinish::LimitReached, None))
                .unwrap()
                .len();
        let cfg = TransportConfig {
            frame_max_bytes: base_size,
            ..TransportConfig::default()
        };
        let (result, reports) = acknowledged(prepare(write(path.clone())).unwrap(), g, cfg).await;
        assert_eq!(result, Ok(false));
        assert!(!Path::new(&path).exists());
        assert!(matches!(
            &reports[..],
            [MutationReport::Finished {
                next_index: 0,
                outcome: ReportedFinish::LimitReached,
                ..
            }]
        ));
        let paths = vec![
            d.path("limit-parent"),
            d.path("limit-parent/untouched-sentinel"),
        ];
        let mut g = grant(MutationScope::Directories {
            paths: paths.clone(),
        });
        g.limits.max_effects = 1;
        let (result, reports) = acknowledged(
            prepare(mkdir(paths[1].clone(), true)).unwrap(),
            g,
            TransportConfig::default(),
        )
        .await;
        assert_eq!(result, Ok(false));
        assert!(Path::new(&paths[0]).is_dir());
        assert!(!Path::new(&paths[1]).exists());
        assert!(matches!(
            &reports[..],
            [
                MutationReport::Batch { first_index: 0, .. },
                MutationReport::Finished {
                    next_index: 1,
                    outcome: ReportedFinish::LimitReached,
                    ..
                }
            ]
        ));
    }
    #[tokio::test]
    async fn wrong_ack_index_stops_without_creating_next_directory() {
        let d = Fixture::new();
        let paths = vec![
            d.path("wrong-ack-parent"),
            d.path("wrong-ack-parent/untouched-sentinel"),
        ];
        let prepared = prepare(mkdir(paths[1].clone(), true)).unwrap();
        let g = grant(MutationScope::Directories { paths });
        let id = g.id;
        let (mut client, mut server) = tokio::io::duplex(65536);
        let task = tokio::spawn(async move {
            execute(
                prepared,
                g,
                &mut client,
                &TransportConfig::default(),
                Instant::now(),
            )
            .await
        });
        proto::read_frame(&mut server, 65536).await.unwrap();
        proto::write_frame(
            &mut server,
            &proto::encode_mutation_ack(&proto::MutationAck { id, next_index: 2 }).unwrap(),
        )
        .await
        .unwrap();
        assert!(task.await.unwrap().is_err());
        assert!(d.0.join("wrong-ack-parent").is_dir());
        assert!(!d.0.join("wrong-ack-parent/untouched-sentinel").exists());
    }
    #[tokio::test]
    async fn recursive_removes_unreadable_empty_directory_without_enumeration() {
        use std::os::unix::fs::PermissionsExt;
        let d = Fixture::new();
        for mode in [0o300, 0o000] {
            let path = d.path(&format!("empty-mode-{mode}"));
            std::fs::create_dir(&path).unwrap();
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(mode)).unwrap();
            let (result, _) = acknowledged(
                prepare(delete(path.clone(), true)).unwrap(),
                grant(MutationScope::RecursiveDelete { root: path.clone() }),
                TransportConfig::default(),
            )
            .await;
            assert_eq!(result, Ok(true));
            assert!(!Path::new(&path).exists());
        }
    }
    #[tokio::test]
    async fn refusal_after_acknowledged_creation_reports_partial() {
        let d = Fixture::new();
        let paths = vec![
            d.path("partial-parent"),
            d.path("partial-parent/collision-sentinel"),
        ];
        let prepared = prepare(mkdir(paths[1].clone(), true)).unwrap();
        let g = grant(MutationScope::Directories {
            paths: paths.clone(),
        });
        let (mut client, mut server) = tokio::io::duplex(65536);
        let task = tokio::spawn(async move {
            execute(
                prepared,
                g,
                &mut client,
                &TransportConfig::default(),
                Instant::now(),
            )
            .await
        });
        let bytes = proto::read_frame(&mut server, 65536).await.unwrap();
        let MutationReport::Batch {
            id, first_index: 0, ..
        } = proto::decode_mutation_report(&bytes).unwrap()
        else {
            panic!("expected first creation report");
        };
        std::fs::write(&paths[1], b"intervening preserved").unwrap();
        let ack = proto::encode_mutation_ack(&proto::MutationAck { id, next_index: 1 }).unwrap();
        proto::write_frame(&mut server, &ack).await.unwrap();
        let bytes = proto::read_frame(&mut server, 65536).await.unwrap();
        let terminal = proto::decode_mutation_report(&bytes).unwrap();
        proto::write_frame(&mut server, &ack).await.unwrap();
        assert_eq!(task.await.unwrap(), Ok(false));
        assert_eq!(std::fs::read(&paths[1]).unwrap(), b"intervening preserved");
        assert!(matches!(
            terminal,
            MutationReport::Finished {
                next_index: 1,
                outcome: ReportedFinish::Partial,
                ..
            }
        ));
    }
    #[tokio::test]
    async fn unacknowledged_batch_expires_without_starting_another_effect() {
        let d = Fixture::new();
        let paths = vec![
            d.path("deadline-parent"),
            d.path("deadline-parent/untouched-sentinel"),
        ];
        let prepared = prepare(mkdir(paths[1].clone(), true)).unwrap();
        let g = grant(MutationScope::Directories { paths });
        let (mut client, mut server) = tokio::io::duplex(65536);
        let cfg = TransportConfig {
            read_timeout_ms: 100,
            ..TransportConfig::default()
        };
        let task =
            tokio::spawn(
                async move { execute(prepared, g, &mut client, &cfg, Instant::now()).await },
            );
        proto::read_frame(&mut server, 65536).await.unwrap();
        assert!(task.await.unwrap().unwrap_err().contains("timed out"));
        assert!(d.0.join("deadline-parent").is_dir());
        assert!(!d.0.join("deadline-parent/untouched-sentinel").exists());
    }
    #[tokio::test]
    async fn existing_write_and_wrong_action_never_accept_namespace_grant() {
        let d = Fixture::new();
        let path = d.path("existing-lane-sentinel");
        std::fs::write(&path, b"retained bytes").unwrap();
        let (result, _) = acknowledged(
            prepare(write(path.clone())).unwrap(),
            grant(MutationScope::Exact {
                path: path.clone(),
                effect: ReportedEffect::CreatedFile,
            }),
            TransportConfig::default(),
        )
        .await;
        assert!(result.is_err());
        assert_eq!(std::fs::read(path).unwrap(), b"retained bytes");
        let path = d.path("wrong-action-sentinel");
        let (result, _) = acknowledged(
            prepare(mkdir(path.clone(), false)).unwrap(),
            grant(MutationScope::Exact {
                path: path.clone(),
                effect: ReportedEffect::CreatedFile,
            }),
            TransportConfig::default(),
        )
        .await;
        assert!(result.is_err());
        assert!(!Path::new(&path).exists());
    }
    #[test]
    fn malformed_preparation_and_mkdir_depth_are_refused_without_entries() {
        let d = Fixture::new();
        for suffix in ["", ".", "..", "bad\0name"] {
            let prepared = prepare(write(format!("{}/{suffix}", d.0.display()))).unwrap();
            assert!(prepared.preparation_error().is_some());
            assert!(prepared.descriptor().unwrap().is_none());
        }
        std::fs::write(d.path("parent-file"), b"safe").unwrap();
        let prepared = prepare(mkdir(d.path("parent-file/child"), true)).unwrap();
        assert!(prepared.preparation_error().is_some());
        let deep = format!("{}/{}leaf", d.0.display(), "absent/".repeat(128));
        let prepared = prepare(mkdir(deep, true)).unwrap();
        assert!(prepared.preparation_error().unwrap().contains("depth"));
        assert!(!d.0.join("absent").exists());
        assert_eq!(std::fs::read(d.path("parent-file")).unwrap(), b"safe");
    }
    #[tokio::test]
    async fn mkdir_exact_and_nested_success_count_only_created_directories() {
        let d = Fixture::new();
        let path = d.path("exact-created-sentinel");
        let (result, reports) = acknowledged(
            prepare(mkdir(path.clone(), false)).unwrap(),
            grant(MutationScope::Exact {
                path: path.clone(),
                effect: ReportedEffect::CreatedDirectory,
            }),
            TransportConfig::default(),
        )
        .await;
        assert_eq!(result, Ok(true));
        assert!(Path::new(&path).is_dir());
        assert!(
            matches!(&reports[..], [MutationReport::Batch { effects, .. }, MutationReport::Finished { next_index: 1, .. }] if effects[0].effect == ReportedEffect::CreatedDirectory)
        );
        let (result, reports) = acknowledged(
            prepare(mkdir(path.clone(), false)).unwrap(),
            grant(MutationScope::Exact {
                path,
                effect: ReportedEffect::CreatedDirectory,
            }),
            TransportConfig::default(),
        )
        .await;
        assert_eq!(result, Ok(false));
        assert!(matches!(
            &reports[..],
            [MutationReport::Finished {
                next_index: 0,
                outcome: ReportedFinish::OsRefused,
                ..
            }]
        ));
        let paths = vec![d.path("nested"), d.path("nested/child")];
        let (result, reports) = acknowledged(
            prepare(mkdir(paths[1].clone(), true)).unwrap(),
            grant(MutationScope::Directories {
                paths: paths.clone(),
            }),
            TransportConfig::default(),
        )
        .await;
        assert_eq!(result, Ok(true));
        assert!(Path::new(&paths[1]).is_dir());
        assert!(matches!(
            &reports[..],
            [
                MutationReport::Batch { first_index: 0, .. },
                MutationReport::Batch { first_index: 1, .. },
                MutationReport::Finished { next_index: 2, .. }
            ]
        ));
    }
    #[tokio::test]
    async fn malformed_scope_and_limits_cannot_create_the_prepared_leaf() {
        let d = Fixture::new();
        let path = d.path("grant-sentinel");
        let base = grant(MutationScope::Exact {
            path: path.clone(),
            effect: ReportedEffect::CreatedFile,
        });
        let mut grants = vec![];
        for (effects, depth, time) in [
            (0, 128, 5000),
            (4097, 128, 5000),
            (4096, 0, 5000),
            (4096, 129, 5000),
            (4096, 128, 0),
        ] {
            let mut g = base.clone();
            g.limits = proto::MutationLimits {
                max_effects: effects,
                max_depth: depth,
                deadline_ms: time,
            };
            grants.push(g);
        }
        for path in [
            d.path("different-leaf"),
            "relative/grant-sentinel".into(),
            d.path(".."),
            d.path("malformed/../grant-sentinel"),
        ] {
            grants.push(grant(MutationScope::Exact {
                path,
                effect: ReportedEffect::CreatedFile,
            }));
        }
        for g in grants {
            let (result, reports) = acknowledged(
                prepare(write(path.clone())).unwrap(),
                g,
                TransportConfig::default(),
            )
            .await;
            assert!(result.is_err());
            assert!(reports.is_empty());
            assert!(!Path::new(&path).exists());
        }
        std::fs::create_dir(d.path("nested-parent")).unwrap();
        let (result, _) = acknowledged(
            prepare(write(d.path("nested-parent/grant-sentinel"))).unwrap(),
            base,
            TransportConfig::default(),
        )
        .await;
        assert!(result.unwrap_err().contains("differs from grant parent"));
        assert!(!d.0.join("nested-parent/grant-sentinel").exists());
        let paths = vec![d.path("new-prefix"), d.path("wrong-prefix/last")];
        let (result, _) = acknowledged(
            prepare(mkdir(d.path("new-prefix/last"), true)).unwrap(),
            grant(MutationScope::Directories { paths }),
            TransportConfig::default(),
        )
        .await;
        assert!(result.is_err());
        assert!(!d.0.join("new-prefix").exists());
    }
    #[tokio::test]
    async fn recursive_depth_and_unreadable_tree_stop_without_losing_entries() {
        use std::os::unix::fs::PermissionsExt;
        let d = Fixture::new();
        std::fs::create_dir_all(d.path("depth/a/b")).unwrap();
        std::fs::write(d.path("depth/a/b/sentinel"), b"safe").unwrap();
        let mut g = grant(MutationScope::RecursiveDelete {
            root: d.path("depth"),
        });
        g.limits.max_depth = 1;
        let (result, reports) = acknowledged(
            prepare(delete(d.path("depth"), true)).unwrap(),
            g,
            TransportConfig::default(),
        )
        .await;
        assert_eq!(result, Ok(false));
        assert_eq!(
            std::fs::read(d.path("depth/a/b/sentinel")).unwrap(),
            b"safe"
        );
        assert!(matches!(
            &reports[..],
            [MutationReport::Finished {
                next_index: 0,
                outcome: ReportedFinish::LimitReached,
                ..
            }]
        ));
        std::fs::set_permissions(d.path("depth"), std::fs::Permissions::from_mode(0o300)).unwrap();
        let (result, reports) = acknowledged(
            prepare(delete(d.path("depth"), true)).unwrap(),
            grant(MutationScope::RecursiveDelete {
                root: d.path("depth"),
            }),
            TransportConfig::default(),
        )
        .await;
        std::fs::set_permissions(d.path("depth"), std::fs::Permissions::from_mode(0o700)).unwrap();
        assert_eq!(result, Ok(false));
        assert!(matches!(
            &reports[..],
            [MutationReport::Finished {
                next_index: 0,
                outcome: ReportedFinish::OsRefused,
                ..
            }]
        ));
        assert_eq!(
            std::fs::read(d.path("depth/a/b/sentinel")).unwrap(),
            b"safe"
        );
    }
    #[test]
    fn observed_failure_state_preserves_creation_claim_and_closed_reason() {
        for (state, outcome, changed) in [
            (EffectState::NoEffect, ReportedFinish::OsRefused, false),
            (EffectState::Applied, ReportedFinish::Partial, true),
            (EffectState::Partial, ReportedFinish::Partial, true),
            (
                EffectState::DurabilityUnknown,
                ReportedFinish::DurabilityUnknown,
                true,
            ),
        ] {
            let path = "/creation-state-sentinel".to_string();
            let step = error_step(
                MutationFailure {
                    state,
                    at: path.clone().into(),
                    source: IoError::Io {
                        path: path.clone().into(),
                        kind: IoKind::PermissionDenied,
                    },
                },
                ReportedEffect::CreatedFile,
                path.clone(),
            );
            assert_eq!(step.finish, Some((outcome, Some(path.clone()))));
            assert_eq!(
                step.effect,
                changed.then_some(EffectEntry {
                    path,
                    effect: ReportedEffect::CreatedFile
                })
            );
        }
        assert_eq!(
            io_finish(&IoError::NonUtf8Component {
                path: "/name".into()
            }),
            ReportedFinish::UnsupportedName
        );
        assert_eq!(
            io_finish(&IoError::MutationPathChanged {
                path: "/moved".into()
            }),
            ReportedFinish::PathChanged
        );
    }
    #[test]
    fn path_component_and_encoding_boundaries_are_exact() {
        for name in ["", ".", "..", "a/b", "a\0b"] {
            assert!(!normal(name), "{name:?}");
        }
        for name in ["plain", ".hidden", "two words", "é"] {
            assert!(normal(name), "{name:?}");
        }
        assert!(normal(&"a".repeat(4096)));
        assert!(!normal(&"a".repeat(4097)));
        assert!(split(&"a".repeat(4096)).is_ok());
        assert!(split(&"a".repeat(4097)).is_err());
        // The whole path has its own budget even when the final leaf is short.
        assert!(split(&format!("/{}leaf", "a/".repeat(2048))).is_err());
        assert!(split("/nul\0parent/leaf").is_err());
        assert_eq!(
            split("relative-leaf").unwrap(),
            (PathBuf::from("."), "relative-leaf".into())
        );
        assert_eq!(
            split("/parent/leaf").unwrap(),
            (PathBuf::from("/parent"), "leaf".into())
        );
        assert!(split("/parent/leaf/").is_err());
    }
    #[tokio::test]
    async fn malformed_ack_wrong_session_and_outbound_frame_cap_are_errors() {
        let g = grant(MutationScope::RecursiveDelete {
            root: "/report-only".into(),
        });
        let message = finished(g.id, 0, ReportedFinish::OsRefused, None);
        let bad_ack = proto::MutationAck {
            id: proto::MutationId {
                session_id: g.id.session_id + 1,
                intent_seq: g.id.intent_seq,
            },
            next_index: 0,
        };
        for bytes in [vec![0xff], proto::encode_mutation_ack(&bad_ack).unwrap()] {
            let (mut client, mut server) = tokio::io::duplex(65536);
            let peer = tokio::spawn(async move {
                proto::read_frame(&mut server, 65536).await.unwrap();
                proto::write_frame(&mut server, &bytes).await.unwrap();
            });
            assert!(report(
                &mut client,
                &TransportConfig::default(),
                Instant::now() + Duration::from_secs(1),
                message.clone(),
                g.id,
                0
            )
            .await
            .is_err());
            peer.await.unwrap();
        }
        let (mut client, server) = tokio::io::duplex(65536);
        let cfg = TransportConfig {
            frame_max_bytes: 1,
            ..TransportConfig::default()
        };
        assert!(report(
            &mut client,
            &cfg,
            Instant::now() + Duration::from_secs(1),
            message.clone(),
            g.id,
            0
        )
        .await
        .unwrap_err()
        .contains("frame limit"));
        drop(server);
        assert!(report(
            &mut client,
            &TransportConfig::default(),
            Instant::now() + Duration::from_secs(1),
            message,
            g.id,
            0
        )
        .await
        .is_err());
    }
    #[test]
    fn grant_validation_rejects_relative_scope_and_wrong_prefix_count() {
        let d = Fixture::new();
        let prepared = prepare(write(d.path("leaf"))).unwrap();
        assert!(grant_parent(
            &prepared,
            &grant(MutationScope::Exact {
                path: "relative/leaf".into(),
                effect: ReportedEffect::CreatedFile
            })
        )
        .is_err());
        let prepared = prepare(mkdir(d.path("new/child"), true)).unwrap();
        for paths in [
            vec![],
            vec![d.path("new")],
            vec![
                d.path("new"),
                d.path("new/child"),
                d.path("new/child/unrequested"),
            ],
        ] {
            assert!(grant_parent(&prepared, &grant(MutationScope::Directories { paths })).is_err());
        }
        let g = grant(MutationScope::Directories {
            paths: vec![d.path("new"), d.path("new/child")],
        });
        assert_eq!(grant_parent(&prepared, &g).unwrap(), d.0);
    }
    fn budget_worker() -> Worker {
        Worker {
            work: Work::Done,
            grant: grant(MutationScope::RecursiveDelete {
                root: "/budget".into(),
            }),
            deadline: Instant::now() + Duration::from_secs(5),
            frame_cap: 65536,
            next_index: 0,
            seen: HashSet::new(),
        }
    }
    #[test]
    fn effect_reservation_enforces_exact_path_depth_count_and_time_boundaries() {
        let mut w = budget_worker();
        let at_limit = format!("/{}", "x".repeat(4095));
        let beyond_limit = format!("/{}", "x".repeat(4096));
        assert_eq!(
            w.reserve(Path::new(&at_limit), ReportedEffect::DeletedEntry, 0)
                .ok(),
            Some(at_limit)
        );
        assert!(w
            .reserve(Path::new(&beyond_limit), ReportedEffect::DeletedEntry, 0)
            .is_err());
        assert!(w
            .reserve(
                Path::new("/budget/child"),
                ReportedEffect::DeletedEntry,
                128
            )
            .is_ok());
        assert!(w
            .reserve(
                Path::new("/budget/child"),
                ReportedEffect::DeletedEntry,
                129
            )
            .is_err());
        w.next_index = 4095;
        assert!(w
            .reserve(Path::new("/budget/child"), ReportedEffect::DeletedEntry, 1)
            .is_ok());
        w.next_index = 4096;
        assert!(w
            .reserve(Path::new("/budget/child"), ReportedEffect::DeletedEntry, 1)
            .is_err());
        w.next_index = 0;
        w.seen.insert("/budget/duplicate".into());
        let error = w
            .reserve(
                Path::new("/budget/duplicate"),
                ReportedEffect::DeletedEntry,
                1,
            )
            .err()
            .unwrap();
        assert_eq!(
            error.finish,
            Some((
                ReportedFinish::PathChanged,
                Some("/budget/duplicate".into())
            ))
        );
        w.deadline = Instant::now() - Duration::from_millis(1);
        assert!(w
            .reserve(Path::new("/budget/child"), ReportedEffect::DeletedEntry, 1)
            .is_err());
    }
    #[test]
    fn effect_reservation_accounts_for_terminal_counter_growth() {
        let mut w = budget_worker();
        w.next_index = 23;
        let path = "/budget/terminal-growth";
        let prior = proto::encode_mutation_report(&finished(
            w.grant.id,
            23,
            ReportedFinish::DurabilityUnknown,
            Some(path.into()),
        ))
        .unwrap()
        .len();
        let next = proto::encode_mutation_report(&finished(
            w.grant.id,
            24,
            ReportedFinish::DurabilityUnknown,
            Some(path.into()),
        ))
        .unwrap()
        .len();
        let effect = proto::encode_mutation_report(&batch(
            w.grant.id,
            23,
            EffectEntry {
                path: path.into(),
                effect: ReportedEffect::DeletedEntry,
            },
        ))
        .unwrap()
        .len();
        assert_eq!(next, prior + 1);
        assert!(effect <= prior, "effect={effect} prior={prior}");
        w.frame_cap = prior;
        assert!(w
            .reserve(Path::new(path), ReportedEffect::DeletedEntry, 1)
            .is_err());
        w.frame_cap = next;
        assert!(w
            .reserve(Path::new(path), ReportedEffect::DeletedEntry, 1)
            .is_ok());
    }
    #[tokio::test]
    async fn mkdir_depth_limit_allows_boundary_then_stops_before_next_prefix() {
        let d = Fixture::new();
        let paths = vec![d.path("depth-prefix"), d.path("depth-prefix/child")];
        let mut g = grant(MutationScope::Directories {
            paths: paths.clone(),
        });
        g.limits.max_depth = 1;
        let (result, reports) = acknowledged(
            prepare(mkdir(paths[1].clone(), true)).unwrap(),
            g,
            TransportConfig::default(),
        )
        .await;
        assert_eq!(result, Ok(false));
        assert!(Path::new(&paths[0]).is_dir());
        assert!(!Path::new(&paths[1]).exists());
        assert!(matches!(
            &reports[..],
            [
                MutationReport::Batch { first_index: 0, .. },
                MutationReport::Finished {
                    next_index: 1,
                    outcome: ReportedFinish::LimitReached,
                    ..
                }
            ]
        ));
        let paths = vec![d.path("boundary"), d.path("boundary/child")];
        let mut g = grant(MutationScope::Directories {
            paths: paths.clone(),
        });
        g.limits.max_depth = 2;
        let (result, _) = acknowledged(
            prepare(mkdir(paths[1].clone(), true)).unwrap(),
            g,
            TransportConfig::default(),
        )
        .await;
        assert_eq!(result, Ok(true));
        assert!(Path::new(&paths[1]).is_dir());
    }
    #[tokio::test]
    async fn delayed_grant_cannot_restart_expired_request_window() {
        let d = Fixture::new();
        let path = d.path("delayed-grant-untouched-sentinel");
        let prepared = prepare(write(path.clone())).unwrap();
        let cfg = TransportConfig {
            read_timeout_ms: 1000,
            ..TransportConfig::default()
        };
        let started = Instant::now() - Duration::from_secs(2);
        let (result, reports) = acknowledged_from(
            prepared,
            grant(MutationScope::Exact {
                path: path.clone(),
                effect: ReportedEffect::CreatedFile,
            }),
            cfg,
            started,
        )
        .await;
        assert!(
            !Path::new(&path).exists(),
            "expired request must not create the prepared sentinel"
        );
        assert!(result.is_err() || result == Ok(false));
        assert!(reports
            .iter()
            .all(|report| !matches!(report, MutationReport::Batch { .. })));
    }
    #[tokio::test]
    async fn acknowledgment_does_not_extend_original_request_window() {
        let d = Fixture::new();
        let paths = vec![
            d.path("elapsed-parent"),
            d.path("elapsed-parent/untouched-sentinel"),
        ];
        let prepared = prepare(mkdir(paths[1].clone(), true)).unwrap();
        let g = grant(MutationScope::Directories { paths });
        let cfg = TransportConfig {
            read_timeout_ms: 1000,
            ..TransportConfig::default()
        };
        let started = Instant::now() - Duration::from_millis(400);
        let (mut client, mut server) = tokio::io::duplex(65536);
        let task =
            tokio::spawn(async move { execute(prepared, g, &mut client, &cfg, started).await });
        let bytes = proto::read_frame(&mut server, 65536).await.unwrap();
        let MutationReport::Batch {
            id, first_index: 0, ..
        } = proto::decode_mutation_report(&bytes).unwrap()
        else {
            panic!("expected first directory effect");
        };
        tokio::time::sleep(Duration::from_millis(700)).await;
        let ack = proto::encode_mutation_ack(&proto::MutationAck { id, next_index: 1 }).unwrap();
        let _ = proto::write_frame(&mut server, &ack).await;
        assert!(task.await.unwrap().is_err());
        assert!(d.0.join("elapsed-parent").is_dir());
        assert!(!d.0.join("elapsed-parent/untouched-sentinel").exists());
    }
    #[test]
    fn io_deadline_refusal_is_reported_as_limit_with_no_invented_effect() {
        let path = "/deadline-state-sentinel".to_string();
        let step = error_step(
            MutationFailure {
                state: EffectState::NoEffect,
                at: path.clone().into(),
                source: IoError::DeadlineElapsed {
                    path: path.clone().into(),
                },
            },
            ReportedEffect::CreatedFile,
            path.clone(),
        );
        assert_eq!(
            step.finish,
            Some((ReportedFinish::LimitReached, Some(path)))
        );
        assert_eq!(step.effect, None);
    }
}
