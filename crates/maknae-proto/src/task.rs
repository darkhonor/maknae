//! The task object (#609): a fixed, versioned CBOR record of one task given to an agent.
use crate::{BindingReach, Bytes, ReachSummary, SecretText};
use serde::{de, Deserialize, Deserializer, Serialize, Serializer};

pub const TASK_SCHEMA: &str = "maknae.task";
pub const TASK_VERSION: u16 = 1;

/// Kernel-assigned; 16 CBOR bytes on the wire, 32 lowercase hex digits in audit text.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
pub struct TaskId(pub [u8; 16]);

impl Serialize for TaskId {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_bytes(&self.0)
    }
}

impl<'de> Deserialize<'de> for TaskId {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        struct V;
        impl<'de> de::Visitor<'de> for V {
            type Value = TaskId;
            fn expecting(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
                f.write_str("a 16-byte byte string")
            }
            fn visit_byte_buf<E: de::Error>(self, v: Vec<u8>) -> Result<TaskId, E> {
                <[u8; 16]>::try_from(v.as_slice())
                    .map(TaskId)
                    .map_err(|_| E::invalid_length(v.len(), &self))
            }
        }
        d.deserialize_byte_buf(V)
    }
}

impl std::fmt::Display for TaskId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.0.iter().try_for_each(|b| write!(f, "{b:02x}"))
    }
}

impl std::str::FromStr for TaskId {
    type Err = TaskSchemaError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        fn nibble(c: u8) -> Option<u8> {
            match c {
                b'0'..=b'9' => Some(c - b'0'),
                b'a'..=b'f' => Some(c - b'a' + 10),
                _ => None,
            }
        }
        let text: &[u8; 32] = s
            .as_bytes()
            .try_into()
            .map_err(|_| TaskSchemaError::TaskIdText)?;
        let (pairs, _) = text.as_chunks::<2>();
        let mut id = [0u8; 16];
        for (out, [hi, lo]) in id.iter_mut().zip(pairs) {
            let (Some(hi), Some(lo)) = (nibble(*hi), nibble(*lo)) else {
                return Err(TaskSchemaError::TaskIdText);
            };
            *out = hi << 4 | lo;
        }
        Ok(TaskId(id))
    }
}

/// Who gave the task. `Remote` has no uid, so its request carries none.
#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub enum Tasker {
    Uid(u32),
    Agent { agent: String, uid: u32 },
    Remote(String),
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub enum Ask {
    Prompt { prompt: SecretText },
}

impl std::fmt::Debug for Ask {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Ask::Prompt { prompt } => write!(f, "Prompt(<{} bytes>)", prompt.0.len()),
        }
    }
}

/// Reserved for classification and releasability. v1 decodes only an empty map:
/// a label carried but never evaluated would read as enforced.
#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Labels {}

pub const TASK_BINDINGS_MAX: usize = 8;
/// The most a task's sealed `Vec<Binding>` may encode to, its heads included.
pub const TASK_BINDINGS_MAX_BYTES: usize = 1280;
/// Sealing adds `head` to each request, 6 bytes as `null`; a request set at this bound seals
/// with one head of [`REPOSITORY_PATH_MAX_BYTES`] at exactly [`TASK_BINDINGS_MAX_BYTES`].
pub const TASK_BINDING_REQUESTS_MAX_BYTES: usize = 976;
/// The most a task's sealed `Vec<BindingReach>` may encode to.
pub const TASK_REACH_MAX_BYTES: usize = 1024;
pub const REPOSITORY_PATH_MAX_BYTES: usize = 255;

pub fn repository_path_is_acceptable(path: &str) -> bool {
    path.len() <= REPOSITORY_PATH_MAX_BYTES
        && !path.ends_with(".git")
        && path.split('/').nth(1).is_some()
        && path.split('/').all(|seg| {
            !matches!(seg, "" | "." | "..")
                && !seg.starts_with('-')
                && seg
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'))
        })
}

fn binding_refusal(
    server: &str,
    base: &str,
    head: Option<&str>,
    change: Option<u64>,
) -> Result<(), String> {
    if !crate::server_is_acceptable(server) {
        return Err(format!(
            "binding `server` is not a lowercase host[:port] of at most {} bytes",
            crate::SERVER_MAX_BYTES
        ));
    }
    if !repository_path_is_acceptable(base) {
        return Err("binding `base` is not a repository path".into());
    }
    if head.is_some_and(|h| !repository_path_is_acceptable(h)) {
        return Err("binding `head` is not a repository path".into());
    }
    if change == Some(0) {
        return Err("binding `change` is not a positive number".into());
    }
    Ok(())
}

#[derive(Clone, PartialEq, Eq, Hash, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields, try_from = "GitRefWire")]
pub struct GitRef {
    pub server: String,
    pub base: String,
    pub change: Option<u64>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct GitRefWire {
    server: String,
    base: String,
    change: Option<u64>,
}

impl TryFrom<GitRefWire> for GitRef {
    type Error = String;
    fn try_from(w: GitRefWire) -> Result<Self, String> {
        binding_refusal(&w.server, &w.base, None, w.change)?;
        Ok(GitRef {
            server: w.server,
            base: w.base,
            change: w.change,
        })
    }
}

/// A sealed binding. `head` is the repository a change's head lives in, when known.
#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields, try_from = "GitBindingWire")]
pub struct GitBinding {
    pub server: String,
    pub base: String,
    pub head: Option<String>,
    pub change: Option<u64>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct GitBindingWire {
    server: String,
    base: String,
    head: Option<String>,
    change: Option<u64>,
}

impl TryFrom<GitBindingWire> for GitBinding {
    type Error = String;
    fn try_from(w: GitBindingWire) -> Result<Self, String> {
        binding_refusal(&w.server, &w.base, w.head.as_deref(), w.change)?;
        Ok(GitBinding {
            server: w.server,
            base: w.base,
            head: w.head,
            change: w.change,
        })
    }
}

#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub enum BindingRequest {
    Git(GitRef),
}

#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub enum Binding {
    Git(GitBinding),
}

struct EncodedLen(usize);

impl std::io::Write for EncodedLen {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.0 = self.0.saturating_add(buf.len());
        Ok(buf.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

/// The CBOR length of `bindings` as a list, counted without buffering it.
pub fn bindings_encoded_len<T: Serialize>(bindings: &[T]) -> usize {
    let mut len = EncodedLen(0);
    match ciborium::into_writer(bindings, &mut len) {
        Ok(()) => len.0,
        Err(_) => usize::MAX,
    }
}

fn at_most<'de, D, T>(d: D, noun: &'static str) -> Result<Vec<T>, D::Error>
where
    D: Deserializer<'de>,
    T: Deserialize<'de>,
{
    struct AtMost<T>(&'static str, std::marker::PhantomData<T>);
    impl<'de, T: Deserialize<'de>> de::Visitor<'de> for AtMost<T> {
        type Value = Vec<T>;
        fn expecting(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
            write!(f, "a list of at most {TASK_BINDINGS_MAX} {}", self.0)
        }
        fn visit_seq<A: de::SeqAccess<'de>>(self, mut seq: A) -> Result<Vec<T>, A::Error> {
            let mut list = Vec::new();
            while let Some(item) = seq.next_element()? {
                if list.len() == TASK_BINDINGS_MAX {
                    return Err(de::Error::custom(format!(
                        "more than {TASK_BINDINGS_MAX} {}",
                        self.0
                    )));
                }
                list.push(item);
            }
            Ok(list)
        }
    }
    d.deserialize_seq(AtMost(noun, std::marker::PhantomData))
}

fn bounded<'de, D, T>(d: D, max_bytes: usize) -> Result<Vec<T>, D::Error>
where
    D: Deserializer<'de>,
    T: Deserialize<'de> + Serialize + PartialEq,
{
    let list = at_most(d, "bindings")?;
    if list.iter().enumerate().any(|(i, b)| list[..i].contains(b)) {
        return Err(de::Error::custom("a duplicate binding"));
    }
    let len = bindings_encoded_len(&list);
    if len > max_bytes {
        return Err(de::Error::custom(format!(
            "bindings of {len} bytes encode to more than {max_bytes}"
        )));
    }
    Ok(list)
}

pub(crate) fn bounded_requests<'de, D: Deserializer<'de>>(
    d: D,
) -> Result<Vec<BindingRequest>, D::Error> {
    bounded(d, TASK_BINDING_REQUESTS_MAX_BYTES)
}

fn bounded_bindings<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<Binding>, D::Error> {
    bounded(d, TASK_BINDINGS_MAX_BYTES)
}

fn reach_within<'de, D: Deserializer<'de>>(
    d: D,
    max_bytes: usize,
) -> Result<Vec<BindingReach>, D::Error> {
    let list = at_most(d, "reach entries")?;
    let len = bindings_encoded_len(&list);
    if len > max_bytes {
        return Err(de::Error::custom(format!(
            "reach of {len} bytes encodes to more than {max_bytes}"
        )));
    }
    Ok(list)
}

fn bounded_reach<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<BindingReach>, D::Error> {
    reach_within(d, TASK_REACH_MAX_BYTES)
}

fn bounded_summaries<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<ReachSummary>, D::Error> {
    at_most(d, "reach entries")
}

/// `reach`, when present, is index-aligned with `bindings`, and a binding with no head has no head ops.
fn reach_refusal<R>(
    bindings: &[Binding],
    reach: &[R],
    head_ops: impl Fn(&R) -> bool,
) -> Result<(), String> {
    if reach.is_empty() {
        return Ok(());
    }
    if bindings.is_empty() {
        return Err("reach without bindings".into());
    }
    if reach.len() != bindings.len() {
        return Err(format!(
            "{} reach entries for {} bindings",
            reach.len(),
            bindings.len()
        ));
    }
    for (Binding::Git(binding), entry) in bindings.iter().zip(reach) {
        if binding.head.is_none() && head_ops(entry) {
            return Err("head reach without a head".into());
        }
    }
    Ok(())
}

/// What a tasker sends. The id, the tasker and the parent are the kernel's.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TaskSubmission {
    pub schema: String,
    pub version: u16,
    pub agent: String,
    pub ask: Ask,
    pub labels: Labels,
    #[serde(
        default,
        skip_serializing_if = "Vec::is_empty",
        deserialize_with = "bounded_requests"
    )]
    pub bindings: Vec<BindingRequest>,
}

impl std::fmt::Debug for TaskSubmission {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TaskSubmission")
            .field("schema", &self.schema)
            .field("version", &self.version)
            .field("agent", &self.agent)
            .field("ask", &self.ask)
            .field("labels", &self.labels)
            .field("bindings", &self.bindings)
            .finish()
    }
}

/// `parent` is the task the submitting request cited, derived by the kernel;
/// `None` is a person's task or an agent's own initiative. `reach` is empty on a task sealed
/// before reach existed.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, try_from = "TaskObjectWire")]
pub struct TaskObject {
    pub schema: String,
    pub version: u16,
    pub task_id: TaskId,
    pub tasker: Tasker,
    pub parent: Option<TaskId>,
    pub agent: String,
    pub ask: Ask,
    pub labels: Labels,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub bindings: Vec<Binding>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub reach: Vec<BindingReach>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct TaskObjectWire {
    schema: String,
    version: u16,
    task_id: TaskId,
    tasker: Tasker,
    parent: Option<TaskId>,
    agent: String,
    ask: Ask,
    labels: Labels,
    #[serde(default, deserialize_with = "bounded_bindings")]
    bindings: Vec<Binding>,
    #[serde(default, deserialize_with = "bounded_reach")]
    reach: Vec<BindingReach>,
}

impl TryFrom<TaskObjectWire> for TaskObject {
    type Error = String;
    fn try_from(w: TaskObjectWire) -> Result<Self, String> {
        reach_refusal(&w.bindings, &w.reach, BindingReach::has_head_ops)?;
        Ok(TaskObject {
            schema: w.schema,
            version: w.version,
            task_id: w.task_id,
            tasker: w.tasker,
            parent: w.parent,
            agent: w.agent,
            ask: w.ask,
            labels: w.labels,
            bindings: w.bindings,
            reach: w.reach,
        })
    }
}

impl std::fmt::Debug for TaskObject {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TaskObject")
            .field("schema", &self.schema)
            .field("version", &self.version)
            .field("task_id", &self.task_id)
            .field("tasker", &self.tasker)
            .field("parent", &self.parent)
            .field("agent", &self.agent)
            .field("ask", &self.ask)
            .field("labels", &self.labels)
            .field("bindings", &self.bindings)
            .field("reach", &self.reach)
            .finish()
    }
}

pub const TASK_SIGNING_CONTEXT: &[u8] = b"maknae.task.v1\0";
pub const TASK_ENVELOPE_MARGIN: usize = 4096;
/// The most a signature's `alg`, `leaf`, `chain` and `sig` may hold together. A delivery
/// frame for a signed task needs `prompt_max_bytes + TASK_ENVELOPE_MARGIN +
/// TASK_SIGNATURE_MAX_BYTES`.
pub const TASK_SIGNATURE_MAX_BYTES: usize = 32 * 1024;
pub const TASK_CHAIN_MAX: usize = 2;

/// The prompt-class request frame cap: a full prompt and its envelope.
pub fn prompt_request_cap(prompt_max_bytes: usize) -> usize {
    prompt_max_bytes.saturating_add(TASK_ENVELOPE_MARGIN)
}

/// The most a TaskSubmit or TaskAdd `forge_tokens` field may add to a request, its key included.
pub const FORGE_TOKENS_MAX_BYTES: usize = 11_734;

/// The request frame cap for TaskSubmit and TaskAdd: a prompt request and the most tokens.
pub fn task_request_cap(prompt_max_bytes: usize) -> usize {
    prompt_request_cap(prompt_max_bytes).saturating_add(FORGE_TOKENS_MAX_BYTES)
}

/// The prompt-class response frame cap: a full prompt delivered as a signed task.
pub fn prompt_response_cap(prompt_max_bytes: usize) -> usize {
    prompt_request_cap(prompt_max_bytes).saturating_add(TASK_SIGNATURE_MAX_BYTES)
}

/// `alg` is the `vault.plane_key` name; `chain` holds the intermediates after `leaf`.
#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields, try_from = "TaskSignatureWire")]
pub struct TaskSignature {
    pub alg: String,
    pub leaf: Bytes,
    pub chain: Vec<Bytes>,
    pub sig: Bytes,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct TaskSignatureWire {
    alg: String,
    leaf: Bytes,
    chain: Vec<Bytes>,
    sig: Bytes,
}

impl TryFrom<TaskSignatureWire> for TaskSignature {
    type Error = String;
    fn try_from(w: TaskSignatureWire) -> Result<Self, String> {
        if w.chain.len() > TASK_CHAIN_MAX {
            return Err(format!(
                "task signature chain of {} exceeds {TASK_CHAIN_MAX}",
                w.chain.len()
            ));
        }
        let held = [w.alg.len(), w.leaf.0.len(), w.sig.0.len()]
            .into_iter()
            .chain(w.chain.iter().map(|c| c.0.len()))
            .fold(0usize, usize::saturating_add);
        if held > TASK_SIGNATURE_MAX_BYTES {
            return Err(format!(
                "task signature of {held} bytes exceeds {TASK_SIGNATURE_MAX_BYTES}"
            ));
        }
        Ok(TaskSignature {
            alg: w.alg,
            leaf: w.leaf,
            chain: w.chain,
            sig: w.sig,
        })
    }
}

#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignedTask {
    pub task: TaskObject,
    pub signature: TaskSignature,
}

/// The context, then the object's CBOR, in one zeroizing buffer of `max_bytes` that never grows.
pub fn task_signing_bytes(
    task: &TaskObject,
    max_bytes: usize,
) -> Result<zeroize::Zeroizing<Vec<u8>>, crate::ProtoCodecError> {
    signing_bytes(TASK_SIGNING_CONTEXT, task, max_bytes)
}

fn signing_bytes<T: Serialize>(
    context: &[u8],
    value: &T,
    max_bytes: usize,
) -> Result<zeroize::Zeroizing<Vec<u8>>, crate::ProtoCodecError> {
    use std::io::Write;
    let mut buf = zeroize::Zeroizing::new(vec![0; max_bytes]);
    let mut writer = std::io::Cursor::new(buf.as_mut_slice());
    writer
        .write_all(context)
        .map_err(|e| crate::ProtoCodecError::Encode(e.to_string()))?;
    ciborium::into_writer(value, &mut writer)
        .map_err(|e| crate::ProtoCodecError::Encode(e.to_string()))?;
    let len = writer.position() as usize;
    buf.truncate(len);
    Ok(buf)
}

pub const TASK_ADDENDUM_SCHEMA: &str = "maknae.task.addendum";
pub const TASK_ADDENDUM_VERSION: u16 = 1;
pub const TASK_ADDENDUM_SIGNING_CONTEXT: &[u8] = b"maknae.task.addendum.v1\0";
/// The most an addendum's signing bytes, its context included, may hold.
pub const TASK_ADDENDUM_MARGIN: usize = 4096;

/// The bindings a task's tasker added while it was working, cumulative: each addendum
/// holds every binding added so far, after the task's own. `seq` is the task's follow-up
/// count when it was sealed, so an agent that has seen that many follow-ups has seen it.
#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields, try_from = "TaskAddendumWire")]
pub struct TaskAddendum {
    schema: String,
    version: u16,
    task_id: TaskId,
    seq: u32,
    bindings: Vec<Binding>,
    reach: Vec<BindingReach>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct TaskAddendumWire {
    schema: String,
    version: u16,
    task_id: TaskId,
    seq: u32,
    #[serde(deserialize_with = "bounded_bindings")]
    bindings: Vec<Binding>,
    #[serde(deserialize_with = "bounded_reach")]
    reach: Vec<BindingReach>,
}

impl TryFrom<TaskAddendumWire> for TaskAddendum {
    type Error = String;
    fn try_from(w: TaskAddendumWire) -> Result<Self, String> {
        if w.schema != TASK_ADDENDUM_SCHEMA {
            return Err(format!(
                "addendum schema {:?} is not {TASK_ADDENDUM_SCHEMA}",
                w.schema
            ));
        }
        if w.version != TASK_ADDENDUM_VERSION {
            return Err(format!(
                "addendum version {} is not {TASK_ADDENDUM_VERSION}",
                w.version
            ));
        }
        TaskAddendum::new(w.task_id, w.seq, w.bindings, w.reach)
    }
}

impl TaskAddendum {
    /// Refuses a `seq` of 0, an empty list, and reach not aligned with the bindings.
    pub fn new(
        task_id: TaskId,
        seq: u32,
        bindings: Vec<Binding>,
        reach: Vec<BindingReach>,
    ) -> Result<Self, String> {
        if seq == 0 {
            return Err("an addendum's seq starts at 1".into());
        }
        if bindings.is_empty() || reach.len() != bindings.len() {
            return Err(format!(
                "an addendum of {} bindings and {} reach entries",
                bindings.len(),
                reach.len()
            ));
        }
        reach_refusal(&bindings, &reach, BindingReach::has_head_ops)?;
        Ok(TaskAddendum {
            schema: TASK_ADDENDUM_SCHEMA.into(),
            version: TASK_ADDENDUM_VERSION,
            task_id,
            seq,
            bindings,
            reach,
        })
    }

    pub fn task_id(&self) -> &TaskId {
        &self.task_id
    }

    pub fn seq(&self) -> u32 {
        self.seq
    }

    pub fn bindings(&self) -> &[Binding] {
        &self.bindings
    }

    pub fn reach(&self) -> &[BindingReach] {
        &self.reach
    }
}

#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignedAddendum {
    pub addendum: TaskAddendum,
    pub signature: TaskSignature,
}

/// The addendum context, then the addendum's CBOR, within [`TASK_ADDENDUM_MARGIN`].
pub fn addendum_signing_bytes(
    addendum: &TaskAddendum,
) -> Result<zeroize::Zeroizing<Vec<u8>>, crate::ProtoCodecError> {
    signing_bytes(
        TASK_ADDENDUM_SIGNING_CONTEXT,
        addendum,
        TASK_ADDENDUM_MARGIN,
    )
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum TaskSchemaError {
    Schema(String),
    Version(u16),
    TaskIdText,
    TaskCursorText,
}

impl std::fmt::Display for TaskSchemaError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TaskSchemaError::Schema(s) => write!(f, "task schema {s:?} is not {TASK_SCHEMA}"),
            TaskSchemaError::Version(v) => write!(f, "task version {v} is not {TASK_VERSION}"),
            TaskSchemaError::TaskIdText => f.write_str("a task id is 32 lowercase hex digits"),
            TaskSchemaError::TaskCursorText => {
                f.write_str("a task cursor is a decimal sequence number")
            }
        }
    }
}

impl std::error::Error for TaskSchemaError {}

#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Debug, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct TaskRef(String);

impl TaskRef {
    pub fn from_id(id: &TaskId) -> Self {
        Self(id.to_string())
    }

    pub fn parse(s: &str) -> Result<Self, TaskSchemaError> {
        s.parse::<TaskId>().map(|id| Self::from_id(&id))
    }

    pub fn to_id(&self) -> TaskId {
        self.0
            .parse()
            .expect("a TaskRef holds only 32 lowercase hex digits")
    }
}

impl TryFrom<String> for TaskRef {
    type Error = TaskSchemaError;
    fn try_from(s: String) -> Result<Self, TaskSchemaError> {
        Self::parse(&s)
    }
}

impl From<TaskRef> for String {
    fn from(r: TaskRef) -> String {
        r.0
    }
}

/// A canonical decimal `u64`, so one sequence number has one spelling.
#[derive(Clone, PartialEq, Eq, Hash, Debug, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct TaskCursor(String);

impl TaskCursor {
    pub fn from_seq(seq: u64) -> Self {
        Self(seq.to_string())
    }

    pub fn parse(s: &str) -> Result<Self, TaskSchemaError> {
        match s.parse::<u64>() {
            Ok(seq) if seq.to_string() == s => Ok(Self(s.to_owned())),
            _ => Err(TaskSchemaError::TaskCursorText),
        }
    }

    pub fn seq(&self) -> u64 {
        self.0
            .parse()
            .expect("a TaskCursor holds only a canonical decimal u64")
    }
}

impl TryFrom<String> for TaskCursor {
    type Error = TaskSchemaError;
    fn try_from(s: String) -> Result<Self, TaskSchemaError> {
        Self::parse(&s)
    }
}

impl From<TaskCursor> for String {
    fn from(c: TaskCursor) -> String {
        c.0
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub enum TaskState {
    Queued,
    Working,
    Reported,
    Closed,
    /// Set aside, as it stood, because its tasker or its agent was contained.
    Held,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub enum TaskClose {
    Stopped,
    Dropped,
    AgentGone,
    AgentLost,
    /// Its tasker lost the authority to task the agent before it was handed out.
    Withdrawn,
    /// The task it was given under stopped working.
    ParentEnded,
}

/// `reach` holds one summary per binding, or none for a task sealed before reach existed.
#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
#[serde(try_from = "TaskViewWire")]
pub struct TaskView {
    pub task: TaskRef,
    pub agent: String,
    pub state: TaskState,
    pub close: Option<TaskClose>,
    pub submitted_secs: i64,
    pub elapsed_secs: u64,
    pub actions: u32,
    pub last_action_secs: Option<i64>,
    pub cursor: TaskCursor,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub bindings: Vec<Binding>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub reach: Vec<ReachSummary>,
}

#[derive(Deserialize)]
struct TaskViewWire {
    task: TaskRef,
    agent: String,
    state: TaskState,
    close: Option<TaskClose>,
    submitted_secs: i64,
    elapsed_secs: u64,
    actions: u32,
    last_action_secs: Option<i64>,
    cursor: TaskCursor,
    #[serde(default, deserialize_with = "bounded_bindings")]
    bindings: Vec<Binding>,
    #[serde(default, deserialize_with = "bounded_summaries")]
    reach: Vec<ReachSummary>,
}

impl TryFrom<TaskViewWire> for TaskView {
    type Error = String;
    fn try_from(w: TaskViewWire) -> Result<Self, String> {
        reach_refusal(&w.bindings, &w.reach, |s| !s.head().is_empty())?;
        Ok(TaskView {
            task: w.task,
            agent: w.agent,
            state: w.state,
            close: w.close,
            submitted_secs: w.submitted_secs,
            elapsed_secs: w.elapsed_secs,
            actions: w.actions,
            last_action_secs: w.last_action_secs,
            cursor: w.cursor,
            bindings: w.bindings,
            reach: w.reach,
        })
    }
}

/// `next` is the submission sequence to resume after.
#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct TaskPage {
    pub entries: Vec<TaskView>,
    pub next: Option<TaskCursor>,
}

pub const TASK_PAGE_MAX: usize = 32;
pub const HELD_PAGE_MAX: usize = 32;

#[derive(Clone, Copy, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub enum HeldCause {
    Tasker,
    Root,
    Agent,
}

#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub enum HeldFilter {
    User(crate::ContainTarget),
    Agent(String),
}

#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub enum HeldTarget {
    Task(TaskRef),
    User(crate::ContainTarget),
    Agent(String),
}

/// `held_secs` is the epoch second the hold was written.
#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct HeldView {
    pub view: TaskView,
    pub tasker: String,
    pub held_from: TaskState,
    pub held_for: Option<HeldCause>,
    pub held_secs: Option<i64>,
}

/// `next` is the store sequence to resume after.
#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct HeldPage {
    pub entries: Vec<HeldView>,
    pub next: Option<TaskCursor>,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub enum ReleaseResult {
    Released,
    TaskerContained,
    RootContained,
    AgentContained,
    TaskerUnresolved,
    RootUnresolved,
    ParentHeld,
    NotHeld,
    Unknown,
    Unauthorized,
    NotDone,
    OutcomeUnknown,
}

/// `state` is the task's state after the attempt, `None` when it is unknown;
/// `parent` is set only for `ParentHeld`.
#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct ReleaseOutcome {
    pub task: TaskRef,
    pub result: ReleaseResult,
    pub state: Option<TaskState>,
    pub parent: Option<TaskRef>,
}

#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct ReleasePage {
    pub outcomes: Vec<ReleaseOutcome>,
    pub next: Option<TaskCursor>,
}

pub fn epoch_to_rfc3339(secs: u64, millis: u32) -> String {
    let days = (secs / 86_400) as i64;
    let rem = secs % 86_400;
    let (hh, mm, ss) = (rem / 3_600, (rem % 3_600) / 60, rem % 60);
    let z = days + 719_468;
    let era = z / 146_097;
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365;
    let year = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = if month <= 2 { year + 1 } else { year };
    format!("{year:04}-{month:02}-{day:02}T{hh:02}:{mm:02}:{ss:02}.{millis:03}Z")
}

pub const AGENT_PAGE_MAX: usize = 256;
pub const BANNER_TEXT_MAX: usize = 256;

#[derive(Clone, Copy, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub enum AgentStanding {
    Enrolled,
    Contained,
    Withdrawn,
    Removed,
    Undecided,
}

#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct AgentEntry {
    pub agent: String,
    pub standing: AgentStanding,
    pub waiting: u32,
}

/// `next` is the last returned entry's id; `undecided` counts the page's unnamed undecided agents.
#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct AgentPage {
    pub entries: Vec<AgentEntry>,
    pub next: Option<String>,
    pub undecided: u32,
    pub banner: Option<BannerSpec>,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub enum BannerColor {
    Black,
    Red,
    Green,
    Yellow,
    Blue,
    Magenta,
    Cyan,
    White,
    Rgb(u8, u8, u8),
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Contrast {
    BlackText,
    WhiteText,
}

impl BannerColor {
    fn rgb(self) -> (u8, u8, u8) {
        match self {
            Self::Black => (0, 0, 0),
            Self::Red => (205, 0, 0),
            Self::Green => (0, 205, 0),
            Self::Yellow => (205, 205, 0),
            Self::Blue => (0, 0, 238),
            Self::Magenta => (205, 0, 205),
            Self::Cyan => (0, 205, 205),
            Self::White => (229, 229, 229),
            Self::Rgb(r, g, b) => (r, g, b),
        }
    }

    fn luminance(self) -> f64 {
        fn lin(c: u8) -> f64 {
            let c = f64::from(c) / 255.0;
            if c <= 0.04045 {
                c / 12.92
            } else {
                ((c + 0.055) / 1.055).powf(2.4)
            }
        }
        let (r, g, b) = self.rgb();
        0.2126 * lin(r) + 0.7152 * lin(g) + 0.0722 * lin(b)
    }

    /// The text colour with the higher WCAG contrast ratio against this background.
    pub fn contrast(self) -> Contrast {
        let lum = self.luminance();
        let black_ratio = (lum + 0.05) / 0.05;
        let white_ratio = 1.05 / (lum + 0.05);
        if white_ratio > black_ratio {
            Contrast::WhiteText
        } else {
            Contrast::BlackText
        }
    }
}

#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct BannerSpec {
    pub text: String,
    pub color: Option<BannerColor>,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum BannerError {
    Empty,
    TooLong,
    ForbiddenChar,
}

impl std::fmt::Display for BannerError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Empty => f.write_str("banner text is empty"),
            Self::TooLong => write!(f, "banner text is over {BANNER_TEXT_MAX} bytes"),
            Self::ForbiddenChar => {
                f.write_str("banner text holds a control, line or format character")
            }
        }
    }
}

impl std::error::Error for BannerError {}

pub fn check_banner(spec: &BannerSpec) -> Result<(), BannerError> {
    if spec.text.is_empty() {
        return Err(BannerError::Empty);
    }
    if spec.text.len() > BANNER_TEXT_MAX {
        return Err(BannerError::TooLong);
    }
    if spec.text.chars().any(is_display_unsafe) {
        return Err(BannerError::ForbiddenChar);
    }
    Ok(())
}

pub fn is_display_unsafe(c: char) -> bool {
    c.is_control() || c == '\u{2028}' || c == '\u{2029}' || is_format_char(c)
}

/// Unicode general category Cf (format), as of Unicode 15.1.
pub fn is_format_char(c: char) -> bool {
    matches!(
        u32::from(c),
        0x00AD
            | 0x0600..=0x0605
            | 0x061C
            | 0x06DD
            | 0x070F
            | 0x0890..=0x0891
            | 0x08E2
            | 0x180E
            | 0x200B..=0x200F
            | 0x202A..=0x202E
            | 0x2060..=0x2064
            | 0x2066..=0x206F
            | 0xFEFF
            | 0xFFF9..=0xFFFB
            | 0x110BD
            | 0x110CD
            | 0x13430..=0x1343F
            | 0x1BCA0..=0x1BCA3
            | 0x1D173..=0x1D17A
            | 0xE0001
            | 0xE0020..=0xE007F
    )
}

/// `cursor` is the report-arrival sequence, assigned when the report or the close lands.
#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct TaskReportView {
    pub task: TaskRef,
    pub agent: String,
    pub close: Option<TaskClose>,
    pub text: SecretText,
    pub at_secs: i64,
    pub cursor: TaskCursor,
}

#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct TaskReportPage {
    pub entries: Vec<TaskReportView>,
    pub next: Option<TaskCursor>,
}

/// `signed` is the CBOR of a [`SignedTask`]; `partition` is relative to the agent's home.
/// `fresh` when the task was started and no request has cited it since, so nothing kept
/// from before the start may be resumed.
#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct TaskDelivery {
    pub signed: Bytes,
    pub partition: String,
    pub fresh: bool,
}

/// `addendum` is the CBOR of the task's [`SignedAddendum`] when the agent has not seen it;
/// it is taken before `items`.
#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct TaskFollowUps {
    pub task: TaskRef,
    pub from: u32,
    pub items: Vec<SecretText>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub addendum: Option<Bytes>,
}

const _: fn(&TaskReportView) -> &crate::wire::SecretText = |c| &c.text;
const _: fn(&TaskDelivery) -> &crate::bytes::Bytes = |c| &c.signed;
const _: fn(&TaskFollowUps) -> &Vec<crate::wire::SecretText> = |c| &c.items;
const _: fn(&TaskFollowUps) -> &Option<crate::bytes::Bytes> = |c| &c.addendum;

/// The one formatter for the audit field and the `tasker` subject attribute.
pub fn tasker_text(t: &Tasker) -> String {
    match t {
        Tasker::Uid(uid) => format!("uid:{uid}"),
        Tasker::Agent { agent, .. } => format!("agent:{agent}"),
        Tasker::Remote(id) => format!("remote:{id}"),
    }
}

/// Labels need no check here: v1's `Labels` holds none, and decode refuses any key.
pub fn validate_submission(sub: &TaskSubmission) -> Result<(), TaskSchemaError> {
    let Labels {} = sub.labels;
    if sub.schema != TASK_SCHEMA {
        return Err(TaskSchemaError::Schema(sub.schema.clone()));
    }
    if sub.version != TASK_VERSION {
        return Err(TaskSchemaError::Version(sub.version));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{AgentReach, EmptyReason, ForgeOp, ForgeOps, GitReach, SideReach, TaskerBasis};

    const SENTINEL: &str = "task-609-prompt-sentinel";

    fn prompt(text: &str) -> Ask {
        Ask::Prompt {
            prompt: SecretText(zeroize::Zeroizing::new(text.into())),
        }
    }

    fn submission() -> TaskSubmission {
        TaskSubmission {
            schema: TASK_SCHEMA.into(),
            version: TASK_VERSION,
            agent: "hobi".into(),
            ask: prompt(SENTINEL),
            labels: Labels {},
            bindings: vec![],
        }
    }

    fn id(seed: u8) -> TaskId {
        let mut b = [0u8; 16];
        for (i, x) in b.iter_mut().enumerate() {
            *x = seed.wrapping_add(i as u8);
        }
        TaskId(b)
    }

    fn object(tasker: Tasker, parent: Option<TaskId>) -> TaskObject {
        TaskObject {
            schema: TASK_SCHEMA.into(),
            version: TASK_VERSION,
            task_id: id(0),
            tasker,
            parent,
            agent: "hobi".into(),
            ask: prompt("hi"),
            labels: Labels {},
            bindings: vec![],
            reach: vec![],
        }
    }

    fn enc<T: Serialize>(v: &T) -> Vec<u8> {
        let mut buf = Vec::new();
        ciborium::into_writer(v, &mut buf).unwrap();
        buf
    }

    fn dec<T: serde::de::DeserializeOwned>(b: &[u8]) -> Result<T, String> {
        ciborium::from_reader(b).map_err(|e| e.to_string())
    }

    fn hex(s: &str) -> Vec<u8> {
        let s: String = s.split_whitespace().collect();
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    fn submission_value(extra: Option<(&str, ciborium::Value)>) -> ciborium::Value {
        use ciborium::Value;
        let mut m = vec![
            (
                Value::Text("schema".into()),
                Value::Text(TASK_SCHEMA.into()),
            ),
            (Value::Text("version".into()), Value::Integer(1.into())),
            (Value::Text("agent".into()), Value::Text("hobi".into())),
            (
                Value::Text("ask".into()),
                Value::Map(vec![(
                    Value::Text("Prompt".into()),
                    Value::Map(vec![(
                        Value::Text("prompt".into()),
                        Value::Text(SENTINEL.into()),
                    )]),
                )]),
            ),
            (Value::Text("labels".into()), Value::Map(vec![])),
        ];
        if let Some((k, v)) = extra {
            m.push((Value::Text(k.into()), v));
        }
        Value::Map(m)
    }

    #[test]
    fn a_submission_round_trips_with_no_id_and_no_tasker() {
        let sub = submission();
        let bytes = enc(&sub);
        assert_eq!(dec::<TaskSubmission>(&bytes).unwrap(), sub);
        let value: ciborium::Value = dec(&bytes).unwrap();
        let keys: Vec<String> = value
            .as_map()
            .unwrap()
            .iter()
            .map(|(k, _)| k.as_text().unwrap().to_string())
            .collect();
        assert_eq!(keys, ["schema", "version", "agent", "ask", "labels"]);
        assert_eq!(bytes, enc(&submission_value(None)));
        assert_eq!(validate_submission(&sub), Ok(()));
    }

    #[test]
    fn the_object_has_the_v1_shape() {
        let golden = hex("a8
             66 736368656d61 6b 6d616b6e61652e7461736b
             67 76657273696f6e 01
             67 7461736b5f6964 50 000102030405060708090a0b0c0d0e0f
             66 7461736b6572 a1 63 556964 19 03e8
             66 706172656e74 f6
             65 6167656e74 64 686f6269
             63 61736b a1 66 50726f6d7074 a1 66 70726f6d7074 62 6869
             66 6c6162656c73 a0");
        let obj = object(Tasker::Uid(1000), None);
        assert_eq!(enc(&obj), golden);
        assert_eq!(dec::<TaskObject>(&golden).unwrap(), obj);
    }

    #[test]
    fn the_signing_bytes_have_the_v1_golden_shape() {
        let golden = hex("6d616b6e61652e7461736b2e763100
             a8
             66 736368656d61 6b 6d616b6e61652e7461736b
             67 76657273696f6e 01
             67 7461736b5f6964 50 000102030405060708090a0b0c0d0e0f
             66 7461736b6572 a1 63 556964 19 03e8
             66 706172656e74 f6
             65 6167656e74 64 686f6269
             63 61736b a1 66 50726f6d7074 a1 66 70726f6d7074 62 6869
             66 6c6162656c73 a0");
        let obj = object(Tasker::Uid(1000), None);
        let bytes = task_signing_bytes(&obj, TASK_ENVELOPE_MARGIN).unwrap();
        assert_eq!(bytes.as_slice(), golden.as_slice());
        assert_eq!(&bytes[..TASK_SIGNING_CONTEXT.len()], TASK_SIGNING_CONTEXT);
        assert_eq!(bytes.capacity(), TASK_ENVELOPE_MARGIN, "allocated once");
    }

    #[test]
    fn signing_bytes_over_the_bound_are_refused() {
        let obj = object(Tasker::Uid(1000), None);
        let exact = task_signing_bytes(&obj, TASK_ENVELOPE_MARGIN)
            .unwrap()
            .len();
        assert_eq!(task_signing_bytes(&obj, exact).unwrap().len(), exact);
        for short in [exact - 1, TASK_SIGNING_CONTEXT.len() - 1, 0] {
            assert!(
                matches!(
                    task_signing_bytes(&obj, short),
                    Err(crate::ProtoCodecError::Encode(_))
                ),
                "{short}"
            );
        }
    }

    fn signature(alg: &str, leaf: &[u8], chain: &[&[u8]], sig: &[u8]) -> TaskSignature {
        let b = |v: &[u8]| Bytes::new(v.to_vec().into());
        TaskSignature {
            alg: alg.into(),
            leaf: b(leaf),
            chain: chain.iter().map(|c| b(c)).collect(),
            sig: b(sig),
        }
    }

    #[test]
    fn the_signature_fields_are_cbor_byte_strings() {
        let golden = hex("a4
             63 616c67 61 61
             64 6c656166 41 01
             65 636861696e 81 41 02
             63 736967 41 03");
        let sig = signature("a", &[1], &[&[2]], &[3]);
        assert_eq!(enc(&sig), golden);
        assert_eq!(dec::<TaskSignature>(&golden).unwrap(), sig);
    }

    #[test]
    fn a_signature_over_its_bounds_is_refused() {
        let alg = "ml-dsa-87";
        let half = (TASK_SIGNATURE_MAX_BYTES - alg.len()) / 2;
        let rest = TASK_SIGNATURE_MAX_BYTES - alg.len() - half;
        let at_bound = signature(alg, &vec![1; half], &[], &vec![2; rest]);
        assert_eq!(dec::<TaskSignature>(&enc(&at_bound)).unwrap(), at_bound);
        let over = signature(alg, &vec![1; half], &[], &vec![2; rest + 1]);
        let err = dec::<TaskSignature>(&enc(&over)).unwrap_err();
        assert!(err.contains("task signature"), "{err}");
        let one: &[u8] = &[3];
        let chain = vec![one; TASK_CHAIN_MAX];
        let longest = signature(alg, &[1], &chain, &[2]);
        assert_eq!(dec::<TaskSignature>(&enc(&longest)).unwrap(), longest);
        let chain = vec![one; TASK_CHAIN_MAX + 1];
        let err = dec::<TaskSignature>(&enc(&signature(alg, &[1], &chain, &[2]))).unwrap_err();
        assert!(err.contains("task signature"), "{err}");
        let signed = enc(&SignedTask {
            task: object(Tasker::Uid(1000), None),
            signature: signature(alg, &[1], &chain, &[2]),
        });
        assert!(dec::<SignedTask>(&signed).is_err());
    }

    #[test]
    fn an_ml_dsa_87_signature_beside_a_two_certificate_chain_fits_the_bound() {
        let cert = vec![7u8; 7 * 1024];
        let chain: Vec<&[u8]> = vec![&cert; TASK_CHAIN_MAX];
        let real = signature("ml-dsa-87", &cert, &chain, &[9; 4627]);
        assert_eq!(dec::<TaskSignature>(&enc(&real)).unwrap(), real);
    }

    #[test]
    fn a_signed_task_is_the_object_beside_its_signature() {
        let signed = SignedTask {
            task: object(Tasker::Uid(1000), None),
            signature: signature("ml-dsa-87", &[1], &[&[2]], &[3]),
        };
        let value: ciborium::Value = dec(&enc(&signed)).unwrap();
        let keys: Vec<&str> = value
            .as_map()
            .unwrap()
            .iter()
            .map(|(k, _)| k.as_text().unwrap())
            .collect();
        assert_eq!(keys, ["task", "signature"]);
        assert_eq!(dec::<SignedTask>(&enc(&signed)).unwrap(), signed);
    }

    #[test]
    fn an_unknown_key_is_refused() {
        let extra = enc(&submission_value(Some((
            "deadline",
            ciborium::Value::Integer(5.into()),
        ))));
        let err = dec::<TaskSubmission>(&extra).unwrap_err();
        assert!(err.contains("deadline"), "{err}");
        let mut obj = ciborium::Value::serialized(&object(Tasker::Uid(7), None)).unwrap();
        if let ciborium::Value::Map(m) = &mut obj {
            m.push((
                ciborium::Value::Text("priority".into()),
                ciborium::Value::Integer(1.into()),
            ));
        }
        let err = dec::<TaskObject>(&enc(&obj)).unwrap_err();
        assert!(err.contains("priority"), "{err}");
        let tasker = enc(&ciborium::Value::Map(vec![(
            ciborium::Value::Text("Agent".into()),
            ciborium::Value::Map(vec![
                (
                    ciborium::Value::Text("agent".into()),
                    ciborium::Value::Text("jin".into()),
                ),
                (
                    ciborium::Value::Text("uid".into()),
                    ciborium::Value::Integer(2.into()),
                ),
                (
                    ciborium::Value::Text("host".into()),
                    ciborium::Value::Text("x".into()),
                ),
            ]),
        )]));
        assert!(dec::<Tasker>(&tasker).unwrap_err().contains("host"));
        assert!(dec::<Tasker>(&enc(&Tasker::Agent {
            agent: "jin".into(),
            uid: 2
        }))
        .is_ok());
        let ask = enc(&ciborium::Value::Map(vec![(
            ciborium::Value::Text("Prompt".into()),
            ciborium::Value::Map(vec![
                (
                    ciborium::Value::Text("prompt".into()),
                    ciborium::Value::Text("p".into()),
                ),
                (
                    ciborium::Value::Text("tools".into()),
                    ciborium::Value::Text("x".into()),
                ),
            ]),
        )]));
        assert!(dec::<Ask>(&ask).unwrap_err().contains("tools"));
    }

    #[test]
    fn a_label_is_refused_in_v1() {
        let mut v = submission_value(None);
        if let ciborium::Value::Map(m) = &mut v {
            m[4].1 = ciborium::Value::Map(vec![(
                ciborium::Value::Text("classification".into()),
                ciborium::Value::Text("SECRET".into()),
            )]);
        }
        let err = dec::<TaskSubmission>(&enc(&v)).unwrap_err();
        assert!(err.contains("classification"), "{err}");
        assert!(dec::<TaskSubmission>(&enc(&submission_value(None))).is_ok());
    }

    #[test]
    fn schema_errors_name_what_was_refused() {
        assert_eq!(
            TaskSchemaError::Schema("x".into()).to_string(),
            "task schema \"x\" is not maknae.task"
        );
        assert_eq!(
            TaskSchemaError::Version(2).to_string(),
            "task version 2 is not 1"
        );
        assert_eq!(
            TaskSchemaError::TaskIdText.to_string(),
            "a task id is 32 lowercase hex digits"
        );
    }

    #[test]
    fn a_wrong_version_is_refused() {
        let mut sub = submission();
        sub.version = 2;
        assert_eq!(validate_submission(&sub), Err(TaskSchemaError::Version(2)));
        let mut sub = submission();
        sub.schema = "maknae.tasks".into();
        assert_eq!(
            validate_submission(&sub),
            Err(TaskSchemaError::Schema("maknae.tasks".into()))
        );
        assert_eq!(validate_submission(&submission()), Ok(()));
    }

    #[test]
    fn a_remote_tasker_round_trips() {
        let obj = object(Tasker::Remote("site-b/ops".into()), None);
        assert_eq!(dec::<TaskObject>(&enc(&obj)).unwrap(), obj);
        assert_eq!(tasker_text(&obj.tasker), "remote:site-b/ops");
        assert_eq!(tasker_text(&Tasker::Uid(1002)), "uid:1002");
    }

    #[test]
    fn an_agent_tasker_and_its_parent_round_trip() {
        let obj = object(
            Tasker::Agent {
                agent: "jin".into(),
                uid: 2002,
            },
            Some(id(0x40)),
        );
        let back = dec::<TaskObject>(&enc(&obj)).unwrap();
        assert_eq!(back, obj);
        assert_eq!(back.parent, Some(id(0x40)));
        assert_eq!(tasker_text(&back.tasker), "agent:jin");
    }

    #[test]
    fn debug_never_prints_the_prompt() {
        let mut obj = object(Tasker::Uid(1), None);
        obj.ask = prompt(SENTINEL);
        let shown = format!("{obj:?}");
        assert!(!shown.contains(SENTINEL), "{shown}");
        assert!(
            shown.contains(&format!("{} bytes", SENTINEL.len())),
            "{shown}"
        );
        let shown = format!("{:?}", submission());
        assert!(!shown.contains(SENTINEL), "{shown}");
        assert!(
            shown.contains(&format!("{} bytes", SENTINEL.len())),
            "{shown}"
        );
        let shown = format!("{:#?}", prompt(SENTINEL));
        assert!(!shown.contains(SENTINEL), "{shown}");
    }

    fn secret(s: &str) -> SecretText {
        SecretText(zeroize::Zeroizing::new(s.into()))
    }

    fn task_ref() -> TaskRef {
        TaskRef::from_id(&id(0xa0))
    }

    fn task_view() -> TaskView {
        TaskView {
            task: task_ref(),
            agent: "hobi".into(),
            state: TaskState::Working,
            close: None,
            submitted_secs: 1_700_000_000,
            elapsed_secs: 42,
            actions: 3,
            last_action_secs: Some(1_700_000_040),
            cursor: TaskCursor::from_seq(4),
            bindings: vec![],
            reach: vec![],
        }
    }

    fn report_view(text: &str) -> TaskReportView {
        TaskReportView {
            task: task_ref(),
            agent: "hobi".into(),
            close: Some(TaskClose::AgentLost),
            text: secret(text),
            at_secs: 1_700_000_100,
            cursor: TaskCursor::from_seq(7),
        }
    }

    fn task_verbs(text: &str) -> Vec<crate::Verb> {
        use crate::Verb;
        vec![
            Verb::TaskAdd {
                task: task_ref(),
                text: secret(text),
                bindings: vec![],
                forge_tokens: crate::ForgeTokens::default(),
            },
            Verb::TaskAdd {
                task: task_ref(),
                text: secret(text),
                bindings: vec![git_ref(FORGE, "o/r", Some(7))],
                forge_tokens: crate::ForgeTokens::new(crate::testutil::widest_forge_tokens(2))
                    .unwrap(),
            },
            Verb::TaskStatus { task: task_ref() },
            Verb::TaskList {
                agent: "hobi".into(),
                after: Some(TaskCursor::from_seq(9)),
            },
            Verb::TaskList {
                agent: "hobi".into(),
                after: None,
            },
            Verb::TaskStop { task: task_ref() },
            Verb::TaskDrop { task: task_ref() },
            Verb::TaskCollect {
                agent: "hobi".into(),
                after: Some(TaskCursor::from_seq(0)),
                task: None,
            },
            Verb::TaskCollect {
                agent: "hobi".into(),
                after: None,
                task: Some(task_ref()),
            },
            Verb::TaskClaim {
                seen_follow_ups: Some(2),
            },
            Verb::TaskClaim {
                seen_follow_ups: None,
            },
            Verb::TaskReport {
                text: secret(text),
                seen_follow_ups: Some(3),
            },
            Verb::AgentList {
                after: Some("hobi".into()),
            },
            Verb::AgentList { after: None },
        ]
    }

    #[test]
    fn only_a_submit_or_an_add_takes_the_task_request_cap() {
        let submit = crate::Verb::TaskSubmit {
            task: submission(),
            forge_tokens: crate::ForgeTokens::default(),
        };
        assert!(crate::takes_task_request_cap(&submit));
        for verb in task_verbs("x") {
            let add = format!("{verb:?}").starts_with("TaskAdd ");
            assert_eq!(crate::takes_task_request_cap(&verb), add, "{verb:?}");
        }
    }

    fn task_payloads(text: &str) -> Vec<crate::Payload> {
        use crate::Payload;
        let mut closed = task_view();
        closed.state = TaskState::Closed;
        closed.close = Some(TaskClose::Stopped);
        closed.last_action_secs = None;
        vec![
            Payload::TaskAccepted(task_view()),
            Payload::TaskState(closed),
            Payload::TaskAcknowledged(task_view()),
            Payload::TaskList(TaskPage {
                entries: vec![task_view()],
                next: Some(TaskCursor::from_seq(1)),
            }),
            Payload::TaskReports(TaskReportPage {
                entries: vec![report_view(text)],
                next: None,
            }),
            Payload::TaskDelivered(TaskDelivery {
                signed: Bytes::new(text.as_bytes().to_vec().into()),
                partition: "tasks/users/alex".into(),
                fresh: true,
            }),
            Payload::TaskFollowUps(TaskFollowUps {
                task: TaskRef::from_id(&TaskId([7; 16])),
                from: 1,
                items: vec![secret(text), secret("second")],
                addendum: Some(Bytes::new(text.as_bytes().to_vec().into())),
            }),
            Payload::TaskIdle,
            Payload::Agents(AgentPage {
                entries: vec![AgentEntry {
                    agent: "hobi".into(),
                    standing: AgentStanding::Contained,
                    waiting: 2,
                }],
                next: Some("hobi".into()),
                undecided: 1,
                banner: Some(BannerSpec {
                    text: "lab".into(),
                    color: Some(BannerColor::Rgb(1, 2, 3)),
                }),
            }),
        ]
    }

    fn delivery_envelope(bindings: Vec<Binding>, reach: Vec<BindingReach>) -> usize {
        const CATALOG_DIGEST_ENCODED_MAX: usize = 49;
        let prompt_max = 1 << 20;
        let agent = "a".repeat(32);
        let alg = "ml-dsa-87";
        let each = (TASK_SIGNATURE_MAX_BYTES - alg.len()) / (2 + TASK_CHAIN_MAX);
        let part = vec![0xa5; each];
        let chain: Vec<&[u8]> = vec![&part; TASK_CHAIN_MAX];
        let rest = TASK_SIGNATURE_MAX_BYTES - alg.len() - each * (1 + TASK_CHAIN_MAX);
        let signed = SignedTask {
            task: TaskObject {
                schema: TASK_SCHEMA.into(),
                version: TASK_VERSION,
                task_id: id(0xf0),
                tasker: Tasker::Agent {
                    agent: agent.clone(),
                    uid: u32::MAX,
                },
                parent: Some(id(0x0f)),
                agent: agent.clone(),
                ask: prompt(&"p".repeat(prompt_max)),
                labels: Labels {},
                bindings,
                reach,
            },
            signature: signature(alg, &part, &chain, &vec![0x5a; rest]),
        };
        assert_eq!(dec::<SignedTask>(&enc(&signed)).unwrap(), signed);
        let response = |catalog_digest| crate::Response {
            protocol_version: crate::PROTOCOL_VERSION,
            result: crate::RespResult::Ok(crate::Payload::TaskDelivered(TaskDelivery {
                signed: Bytes::new(enc(&signed).into()),
                partition: format!("tasks/agents/{agent}"),
                fresh: true,
            })),
            catalog_digest,
        };
        let bare = crate::encode_response(&response(None)).unwrap().len();
        let stamped = crate::encode_response(&response(Some(crate::CatalogDigest([0xff; 32]))))
            .unwrap()
            .len();
        assert_eq!(stamped - bare, CATALOG_DIGEST_ENCODED_MAX);
        assert!(stamped <= prompt_response_cap(prompt_max), "{stamped}");
        stamped - prompt_max - TASK_SIGNATURE_MAX_BYTES
    }

    #[test]
    fn a_max_size_task_delivery_fits_with_a_stamp() {
        let envelope = delivery_envelope(vec![], vec![]);
        assert!(envelope <= TASK_ENVELOPE_MARGIN, "{envelope}");
    }

    #[test]
    fn the_worst_case_bindings_heads_and_reach_fit_the_envelope() {
        let bindings = sealed_at(TASK_BINDINGS_MAX, TASK_BINDINGS_MAX_BYTES);
        assert!(bindings
            .iter()
            .all(|Binding::Git(b)| b.head.as_deref().is_some_and(|h| h.len() == HEAD_LEN)));
        let reach = most_reach();
        let reach_len = bindings_encoded_len(&reach);
        let bare = delivery_envelope(vec![], vec![]);
        let bound = delivery_envelope(bindings.clone(), vec![]);
        let reached = delivery_envelope(bindings, reach);
        assert_eq!(bound - bare, 1 + "bindings".len() + TASK_BINDINGS_MAX_BYTES);
        assert_eq!(reached - bound, 1 + "reach".len() + reach_len);
        assert!(reached <= TASK_ENVELOPE_MARGIN, "{reached}");
        assert!(
            bound + 1 + "reach".len() + TASK_REACH_MAX_BYTES <= TASK_ENVELOPE_MARGIN,
            "{bound} + {TASK_REACH_MAX_BYTES}"
        );
    }

    fn request_len(verb: crate::Verb) -> usize {
        let req = crate::Request {
            protocol_version: crate::PROTOCOL_VERSION,
            verb,
            task: Some(id(0xf0)),
        };
        let bytes = crate::encode_request(&req).unwrap();
        assert_eq!(crate::decode_request(&bytes).unwrap(), req);
        bytes.len()
    }

    #[test]
    fn a_max_size_submission_with_max_bindings_and_eight_tokens_fits_the_request_cap() {
        let prompt_max = 1 << 20;
        let mut task = submission();
        task.agent = "a".repeat(32);
        task.ask = prompt(&"p".repeat(prompt_max));
        task.bindings = requests_at(TASK_BINDINGS_MAX, TASK_BINDING_REQUESTS_MAX_BYTES);
        let tokens = crate::ForgeTokens::new(crate::testutil::widest_forge_tokens(
            crate::FORGE_TOKENS_MAX,
        ))
        .unwrap();
        let submit = |forge_tokens| crate::Verb::TaskSubmit {
            task: task.clone(),
            forge_tokens,
        };
        let bare = request_len(submit(crate::ForgeTokens::default()));
        let tokened = request_len(submit(tokens.clone()));
        assert!(bare <= prompt_request_cap(prompt_max), "{bare}");
        assert_eq!(tokened - bare, FORGE_TOKENS_MAX_BYTES);
        assert!(tokened <= task_request_cap(prompt_max), "{tokened}");

        let add = request_len(crate::Verb::TaskAdd {
            task: task_ref(),
            text: secret(&"p".repeat(prompt_max)),
            bindings: task.bindings.clone(),
            forge_tokens: tokens,
        });
        assert!(add <= task_request_cap(prompt_max), "{add}");
    }

    #[test]
    fn the_prompt_caps_add_the_envelope_the_tokens_and_then_the_signature() {
        assert_eq!(FORGE_TOKENS_MAX_BYTES, 11_734);
        assert_eq!(prompt_request_cap(65_536), 65_536 + 4096);
        assert_eq!(task_request_cap(65_536), 65_536 + 4096 + 11_734);
        assert_eq!(prompt_response_cap(65_536), 65_536 + 4096 + 32 * 1024);
        assert_eq!(prompt_request_cap(usize::MAX), usize::MAX);
        assert_eq!(task_request_cap(usize::MAX - 4096), usize::MAX);
        assert_eq!(prompt_response_cap(usize::MAX - 1), usize::MAX);
    }

    #[test]
    fn every_task_verb_round_trips_through_cbor() {
        for verb in task_verbs("round-trip") {
            let req = crate::Request {
                protocol_version: crate::PROTOCOL_VERSION,
                verb,
                task: None,
            };
            let back = crate::decode_request(&crate::encode_request(&req).unwrap()).unwrap();
            assert_eq!(back, req);
        }
        for payload in task_payloads("round-trip") {
            let resp = crate::Response {
                protocol_version: crate::PROTOCOL_VERSION,
                result: crate::RespResult::Ok(payload),
                catalog_digest: None,
            };
            let back = crate::decode_response(&crate::encode_response(&resp).unwrap()).unwrap();
            assert_eq!(back, resp);
        }
        let wire: ciborium::Value = dec(&enc(&task_ref())).unwrap();
        assert_eq!(wire.as_text(), Some("a0a1a2a3a4a5a6a7a8a9aaabacadaeaf"));
        let wire: ciborium::Value = dec(&enc(&TaskCursor::from_seq(12))).unwrap();
        assert_eq!(wire.as_text(), Some("12"));
    }

    #[test]
    fn a_collect_sent_without_a_task_decodes_as_naming_none() {
        #[derive(Serialize)]
        enum Before {
            TaskCollect {
                agent: String,
                after: Option<TaskCursor>,
            },
        }
        let sent = enc(&Before::TaskCollect {
            agent: "hobi".into(),
            after: Some(TaskCursor::from_seq(3)),
        });
        assert_eq!(
            dec::<crate::Verb>(&sent).unwrap(),
            crate::Verb::TaskCollect {
                agent: "hobi".into(),
                after: Some(TaskCursor::from_seq(3)),
                task: None,
            }
        );
        let unnamed = enc(&crate::Verb::TaskCollect {
            agent: "hobi".into(),
            after: None,
            task: None,
        });
        assert_eq!(
            unnamed,
            enc(&Before::TaskCollect {
                agent: "hobi".into(),
                after: None,
            })
        );
        let close: TaskClose = dec(&enc(&TaskClose::ParentEnded)).unwrap();
        assert_eq!(close, TaskClose::ParentEnded);
    }

    #[test]
    fn task_classes_are_pinned() {
        use crate::{class_of, FrameClass, Verb};
        for verb in task_verbs("c") {
            let want = match &verb {
                Verb::TaskAdd { .. }
                | Verb::TaskReport { .. }
                | Verb::TaskClaim { .. }
                | Verb::TaskCollect { .. } => FrameClass::Prompt,
                Verb::TaskStatus { .. }
                | Verb::TaskList { .. }
                | Verb::TaskStop { .. }
                | Verb::TaskDrop { .. }
                | Verb::AgentList { .. } => FrameClass::Control,
                other => panic!("not a task verb: {other:?}"),
            };
            assert_eq!(class_of(&verb), want, "{verb:?}");
        }
    }

    #[test]
    fn task_ref_refuses_anything_but_32_lowercase_hex_at_decode() {
        let good = "0123456789abcdef0a1b2c3d4e5f6978";
        let r: TaskRef = dec(&enc(&good.to_string())).unwrap();
        assert_eq!(r, TaskRef::parse(good).unwrap());
        assert_eq!(r.to_id(), good.parse::<TaskId>().unwrap());
        assert_eq!(TaskRef::from_id(&r.to_id()), r);
        for bad in [
            &good[..31],
            &format!("{good}0")[..],
            "0123456789ABCDEF0A1B2C3D4E5F6978",
            "0123456789abcdeg0a1b2c3d4e5f6978",
            "",
        ] {
            assert!(dec::<TaskRef>(&enc(&bad.to_string())).is_err(), "{bad}");
            assert!(TaskRef::parse(bad).is_err(), "{bad}");
        }
        assert!(dec::<TaskRef>(&enc(&id(1))).is_err());
        let mut bad_verb =
            ciborium::Value::serialized(&crate::Verb::TaskStop { task: task_ref() }).unwrap();
        if let ciborium::Value::Map(m) = &mut bad_verb {
            m[0].1 = ciborium::Value::Map(vec![(
                ciborium::Value::Text("task".into()),
                ciborium::Value::Text("A0A1A2A3A4A5A6A7A8A9AAABACADAEAF".into()),
            )]);
        }
        assert!(dec::<crate::Verb>(&enc(&bad_verb)).is_err());
    }

    #[test]
    fn task_cursor_refuses_non_decimal_at_decode() {
        for (text, seq) in [("0", 0u64), ("7", 7), ("18446744073709551615", u64::MAX)] {
            let c: TaskCursor = dec(&enc(&text.to_string())).unwrap();
            assert_eq!(c.seq(), seq);
            assert_eq!(c, TaskCursor::from_seq(seq));
            assert_eq!(TaskCursor::parse(text), Ok(c));
        }
        for bad in [
            "",
            "-1",
            "+1",
            "1a",
            "0x10",
            " 1",
            "01",
            "18446744073709551616",
            "１",
        ] {
            assert!(dec::<TaskCursor>(&enc(&bad.to_string())).is_err(), "{bad}");
            assert_eq!(
                TaskCursor::parse(bad),
                Err(TaskSchemaError::TaskCursorText),
                "{bad}"
            );
        }
        assert!(dec::<TaskCursor>(&enc(&7u64)).is_err());
        assert_eq!(
            TaskSchemaError::TaskCursorText.to_string(),
            "a task cursor is a decimal sequence number"
        );
    }

    #[test]
    fn secret_fields_never_print() {
        let sentinel = "task-628-secret-sentinel";
        let fragments: Vec<&str> = (0..sentinel.len() - 5)
            .map(|i| &sentinel[i..i + 6])
            .collect();
        let shown: Vec<String> = task_verbs(sentinel)
            .iter()
            .map(|v| format!("{v:?}"))
            .chain(task_payloads(sentinel).iter().map(|p| format!("{p:#?}")))
            .chain([
                format!("{:?}", report_view(sentinel)),
                format!(
                    "{:?}",
                    TaskFollowUps {
                        task: TaskRef::from_id(&TaskId([7; 16])),
                        from: 0,
                        items: vec![secret(sentinel)],
                        addendum: Some(Bytes::new(sentinel.as_bytes().to_vec().into())),
                    }
                ),
            ])
            .collect();
        for s in &shown {
            for frag in &fragments {
                assert!(!s.contains(frag), "{frag} leaked into {s}");
            }
        }
        assert!(shown
            .iter()
            .any(|s| s.contains(&format!("{} bytes", sentinel.len()))));
    }

    #[test]
    fn task_id_is_16_bytes_on_the_wire_and_32_hex_in_text() {
        let t = id(0xf0);
        let bytes = enc(&t);
        assert_eq!(bytes[0], 0x50);
        assert_eq!(&bytes[1..], &t.0);
        assert_eq!(dec::<TaskId>(&bytes).unwrap(), t);
        let text = t.to_string();
        assert_eq!(text, "f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff");
        assert_eq!(text.parse::<TaskId>(), Ok(t));
        for short in [&[0x4f_u8][..], &[0x51][..]] {
            let mut b = short.to_vec();
            b.extend(std::iter::repeat_n(0u8, usize::from(short[0] & 0x1f)));
            assert!(dec::<TaskId>(&b).is_err(), "{b:02x?}");
        }
        assert!(dec::<TaskId>(&enc(&[0u8; 16].to_vec())).is_err());
        let err = dec::<TaskId>(&enc(&Bytes::new(vec![0u8; 15].into()))).unwrap_err();
        assert!(err.contains("expected a 16-byte byte string"), "{err}");
        assert_eq!(
            "0123456789abcdef0a1b2c3d4e5f6978".parse::<TaskId>(),
            Ok(TaskId([
                0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0x0a, 0x1b, 0x2c, 0x3d, 0x4e, 0x5f,
                0x69, 0x78
            ]))
        );
        for bad in [
            "",
            "f0f1f2f3f4f5f6f7f8f9fafbfcfdfef",
            "f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff0",
            "F0F1F2F3F4F5F6F7F8F9FAFBFCFDFEFF",
            "g0f1f2f3f4f5f6f7f8f9fafbfcfdfeff",
            "+0f1f2f3f4f5f6f7f8f9fafbfcfdfeff",
            "f0f1f2f3f4f5f6f7f8f9fafbfcfdfeé",
        ] {
            assert_eq!(
                bad.parse::<TaskId>(),
                Err(TaskSchemaError::TaskIdText),
                "{bad}"
            );
        }
    }

    fn held_view(held_for: Option<HeldCause>, optional: bool) -> HeldView {
        HeldView {
            view: TaskView {
                task: TaskRef::from_id(&TaskId([7; 16])),
                agent: "jin".into(),
                state: TaskState::Held,
                close: optional.then_some(TaskClose::AgentGone),
                submitted_secs: 11,
                elapsed_secs: 12,
                actions: 3,
                last_action_secs: optional.then_some(14),
                cursor: TaskCursor::from_seq(9),
                bindings: vec![],
                reach: vec![],
            },
            tasker: "uid 1234".into(),
            held_from: TaskState::Working,
            held_for,
            held_secs: optional.then_some(15),
        }
    }

    #[test]
    fn agent_and_held_pages_round_trip() {
        let requests = [
            crate::Verb::AgentList {
                after: Some("hobi".into()),
            },
            crate::Verb::AdminHeldList {
                filter: None,
                after: None,
            },
            crate::Verb::AdminHeldList {
                filter: Some(HeldFilter::User(crate::ContainTarget::Name(
                    "daemon".into(),
                ))),
                after: Some(TaskCursor::from_seq(3)),
            },
            crate::Verb::AdminHeldList {
                filter: Some(HeldFilter::Agent("jin".into())),
                after: None,
            },
            crate::Verb::AdminHeldRelease {
                target: HeldTarget::Task(TaskRef::from_id(&TaskId([1; 16]))),
                after: None,
            },
            crate::Verb::AdminHeldRelease {
                target: HeldTarget::User(crate::ContainTarget::Uid(4242)),
                after: Some(TaskCursor::from_seq(5)),
            },
            crate::Verb::AdminHeldRelease {
                target: HeldTarget::Agent("hobi".into()),
                after: None,
            },
        ];
        for verb in requests {
            let req = crate::Request {
                protocol_version: crate::PROTOCOL_VERSION,
                verb,
                task: None,
            };
            let bytes = crate::encode_request(&req).unwrap();
            let back = crate::decode_request(&bytes).unwrap();
            assert_eq!(back, req);
            assert_eq!(crate::encode_request(&back).unwrap(), bytes);
        }
        let agents = crate::Payload::Agents(AgentPage {
            entries: vec![AgentEntry {
                agent: "hobi".into(),
                standing: AgentStanding::Contained,
                waiting: 2,
            }],
            next: Some("hobi".into()),
            undecided: 1,
            banner: Some(BannerSpec {
                text: "lab".into(),
                color: Some(BannerColor::Rgb(1, 2, 3)),
            }),
        });
        let held = crate::Payload::HeldTasks(HeldPage {
            entries: [
                Some(HeldCause::Tasker),
                Some(HeldCause::Root),
                Some(HeldCause::Agent),
                None,
            ]
            .into_iter()
            .enumerate()
            .map(|(i, cause)| held_view(cause, i % 2 == 0))
            .collect(),
            next: Some(TaskCursor::from_seq(9)),
        });
        let empty_held = crate::Payload::HeldTasks(HeldPage {
            entries: vec![],
            next: None,
        });
        let results = [
            ReleaseResult::Released,
            ReleaseResult::TaskerContained,
            ReleaseResult::RootContained,
            ReleaseResult::AgentContained,
            ReleaseResult::TaskerUnresolved,
            ReleaseResult::RootUnresolved,
            ReleaseResult::ParentHeld,
            ReleaseResult::NotHeld,
            ReleaseResult::Unknown,
            ReleaseResult::Unauthorized,
            ReleaseResult::NotDone,
            ReleaseResult::OutcomeUnknown,
        ];
        let released = crate::Payload::HeldReleased(ReleasePage {
            outcomes: results
                .into_iter()
                .map(|result| ReleaseOutcome {
                    task: TaskRef::from_id(&TaskId([2; 16])),
                    result,
                    state: (!matches!(
                        result,
                        ReleaseResult::Unknown | ReleaseResult::OutcomeUnknown
                    ))
                    .then_some(TaskState::Queued),
                    parent: (result == ReleaseResult::ParentHeld)
                        .then(|| TaskRef::from_id(&TaskId([3; 16]))),
                })
                .collect(),
            next: None,
        });
        for payload in [agents, held, empty_held, released] {
            let resp = crate::Response {
                protocol_version: crate::PROTOCOL_VERSION,
                result: crate::RespResult::Ok(payload),
                catalog_digest: None,
            };
            let bytes = crate::encode_response(&resp).unwrap();
            let back = crate::decode_response(&bytes).unwrap();
            assert_eq!(back, resp);
            assert_eq!(crate::encode_response(&back).unwrap(), bytes);
        }
    }

    #[test]
    fn agent_list_is_a_control_frame() {
        let verb = crate::Verb::AgentList { after: None };
        assert_eq!(crate::class_of(&verb), crate::FrameClass::Control);
    }

    #[test]
    fn a_maximal_agent_page_fits_a_control_frame() {
        let page = AgentPage {
            entries: (0..AGENT_PAGE_MAX)
                .map(|_| AgentEntry {
                    agent: "a".repeat(32),
                    standing: AgentStanding::Undecided,
                    waiting: u32::MAX,
                })
                .collect(),
            next: Some("a".repeat(32)),
            undecided: u32::MAX,
            banner: Some(BannerSpec {
                text: "é".repeat(BANNER_TEXT_MAX / 2),
                color: Some(BannerColor::Rgb(255, 255, 255)),
            }),
        };
        let resp = crate::Response {
            protocol_version: crate::PROTOCOL_VERSION,
            result: crate::RespResult::Ok(crate::Payload::Agents(page)),
            catalog_digest: None,
        };
        let bytes = crate::encode_response(&resp).unwrap();
        assert!(
            bytes.len() <= crate::CONTROL_RESPONSE_MAX,
            "{}",
            bytes.len()
        );
    }

    fn assert_fits_a_control_frame(payload: crate::Payload) {
        let resp = crate::Response {
            protocol_version: crate::PROTOCOL_VERSION,
            result: crate::RespResult::Ok(payload),
            catalog_digest: None,
        };
        let bytes = crate::encode_response(&resp).unwrap();
        assert!(
            bytes.len() <= crate::CONTROL_RESPONSE_MAX,
            "{}",
            bytes.len()
        );
        assert_eq!(crate::decode_response(&bytes).unwrap(), resp);
    }

    fn maximal_ref() -> TaskRef {
        TaskRef::from_id(&TaskId([0xff; 16]))
    }

    fn maximal_view(state: TaskState) -> TaskView {
        TaskView {
            task: maximal_ref(),
            agent: "a".repeat(32),
            state,
            close: Some(TaskClose::AgentGone),
            submitted_secs: i64::MAX,
            elapsed_secs: u64::MAX,
            actions: u32::MAX,
            last_action_secs: Some(i64::MAX),
            cursor: TaskCursor::from_seq(u64::MAX),
            bindings: sealed_at(TASK_BINDINGS_MAX, TASK_BINDINGS_MAX_BYTES),
            reach: most_reach().iter().map(ReachSummary::of).collect(),
        }
    }

    #[test]
    fn a_maximal_held_page_with_heads_and_reach_fits_a_control_frame() {
        let entry = HeldView {
            view: maximal_view(TaskState::Held),
            tasker: "é".repeat(128),
            held_from: TaskState::Reported,
            held_for: Some(HeldCause::Tasker),
            held_secs: Some(i64::MAX),
        };
        assert_eq!(entry.tasker.len(), 256);
        assert_fits_a_control_frame(crate::Payload::HeldTasks(HeldPage {
            entries: vec![entry; HELD_PAGE_MAX],
            next: Some(TaskCursor::from_seq(u64::MAX)),
        }));
    }

    #[test]
    fn a_maximal_task_page_with_heads_and_reach_fits_a_control_frame() {
        assert_fits_a_control_frame(crate::Payload::TaskList(TaskPage {
            entries: vec![maximal_view(TaskState::Working); TASK_PAGE_MAX],
            next: Some(TaskCursor::from_seq(u64::MAX)),
        }));
    }

    #[test]
    fn a_maximal_release_page_fits_a_control_frame() {
        let outcome = ReleaseOutcome {
            task: maximal_ref(),
            result: ReleaseResult::OutcomeUnknown,
            state: Some(TaskState::Reported),
            parent: Some(maximal_ref()),
        };
        assert_fits_a_control_frame(crate::Payload::HeldReleased(ReleasePage {
            outcomes: vec![outcome; HELD_PAGE_MAX],
            next: Some(TaskCursor::from_seq(u64::MAX)),
        }));
    }

    #[test]
    fn red_takes_white_text_and_yellow_takes_black() {
        assert_eq!(BannerColor::Red.contrast(), Contrast::WhiteText);
        assert_eq!(BannerColor::Yellow.contrast(), Contrast::BlackText);
        assert_eq!(BannerColor::Black.contrast(), Contrast::WhiteText);
        assert_eq!(BannerColor::White.contrast(), Contrast::BlackText);
        assert_eq!(BannerColor::Blue.contrast(), Contrast::WhiteText);
        assert_eq!(BannerColor::Green.contrast(), Contrast::BlackText);
        assert_eq!(BannerColor::Cyan.contrast(), Contrast::BlackText);
        assert_eq!(
            BannerColor::Rgb(255, 255, 255).contrast(),
            Contrast::BlackText
        );
        assert_eq!(BannerColor::Rgb(0, 0, 0).contrast(), Contrast::WhiteText);
    }

    #[test]
    fn each_banner_rule_refuses() {
        let spec = |text: &str| BannerSpec {
            text: text.into(),
            color: None,
        };
        assert_eq!(check_banner(&spec("ok")), Ok(()));
        assert_eq!(check_banner(&spec(&"a".repeat(256))), Ok(()));
        assert_eq!(check_banner(&spec("")), Err(BannerError::Empty));
        assert_eq!(
            check_banner(&spec(&"a".repeat(257))),
            Err(BannerError::TooLong)
        );
        for bad in ["a\u{7}b", "a\u{2028}b", "a\u{2029}b", "a\u{202e}b"] {
            assert_eq!(
                check_banner(&spec(bad)),
                Err(BannerError::ForbiddenChar),
                "{bad:?}"
            );
        }
    }

    #[test]
    fn every_banner_error_says_what_it_refused() {
        assert_eq!(BannerError::Empty.to_string(), "banner text is empty");
        assert_eq!(
            BannerError::TooLong.to_string(),
            "banner text is over 256 bytes"
        );
        assert_eq!(
            BannerError::ForbiddenChar.to_string(),
            "banner text holds a control, line or format character"
        );
    }

    #[test]
    fn luminance_follows_the_wcag_formula() {
        let near = |c: BannerColor, want: f64| {
            let got = c.luminance();
            assert!((got - want).abs() < 1e-6, "{c:?}: {got} != {want}");
        };
        near(BannerColor::Rgb(10, 10, 10), 0.003_035_3);
        near(BannerColor::Rgb(128, 128, 128), 0.215_860_5);
        near(BannerColor::Rgb(0, 0, 0), 0.0);
        near(BannerColor::Rgb(255, 255, 255), 1.0);
    }

    #[test]
    fn the_contrast_choice_flips_between_grey_117_and_118() {
        assert_eq!(
            BannerColor::Rgb(117, 117, 117).contrast(),
            Contrast::WhiteText
        );
        assert_eq!(
            BannerColor::Rgb(118, 118, 118).contrast(),
            Contrast::BlackText
        );
    }

    #[test]
    fn format_chars_are_the_unicode_cf_set() {
        let ranges: [(u32, u32); 21] = [
            (0x00AD, 0x00AD),
            (0x0600, 0x0605),
            (0x061C, 0x061C),
            (0x06DD, 0x06DD),
            (0x070F, 0x070F),
            (0x0890, 0x0891),
            (0x08E2, 0x08E2),
            (0x180E, 0x180E),
            (0x200B, 0x200F),
            (0x202A, 0x202E),
            (0x2060, 0x2064),
            (0x2066, 0x206F),
            (0xFEFF, 0xFEFF),
            (0xFFF9, 0xFFFB),
            (0x110BD, 0x110BD),
            (0x110CD, 0x110CD),
            (0x13430, 0x1343F),
            (0x1BCA0, 0x1BCA3),
            (0x1D173, 0x1D17A),
            (0xE0001, 0xE0001),
            (0xE0020, 0xE007F),
        ];
        let at = |u: u32| char::from_u32(u).is_some_and(is_format_char);
        for (lo, hi) in ranges {
            assert!(at(lo) && at(hi), "{lo:x}..={hi:x}");
            assert!(!at(lo - 1) || ranges.iter().any(|&(a, b)| (a..=b).contains(&(lo - 1))));
            assert!(!at(hi + 1) || ranges.iter().any(|&(a, b)| (a..=b).contains(&(hi + 1))));
        }
        assert!(!is_format_char('a'));
        assert!(!is_format_char('\u{2028}'));
    }

    #[test]
    fn display_unsafe_covers_controls_line_separators_and_format_characters() {
        for c in [
            '\u{7}', '\n', '\u{2028}', '\u{2029}', '\u{202e}', '\u{200b}',
        ] {
            assert!(is_display_unsafe(c), "{c:?}");
        }
        assert!(!is_display_unsafe('a') && !is_display_unsafe('é'));
    }

    #[test]
    fn epochs_format_as_rfc3339_utc_with_milliseconds() {
        for (secs, millis, want) in [
            (0, 0, "1970-01-01T00:00:00.000Z"),
            (1_700_000_000, 250, "2023-11-14T22:13:20.250Z"),
            (1_709_164_800, 7, "2024-02-29T00:00:00.007Z"),
            (1_709_251_199, 999, "2024-02-29T23:59:59.999Z"),
            (1_709_251_200, 0, "2024-03-01T00:00:00.000Z"),
            (1_735_689_599, 0, "2024-12-31T23:59:59.000Z"),
            (951_782_400, 0, "2000-02-29T00:00:00.000Z"),
            (951_868_800, 0, "2000-03-01T00:00:00.000Z"),
            (4_107_456_000, 0, "2100-02-28T00:00:00.000Z"),
            (4_107_542_400, 0, "2100-03-01T00:00:00.000Z"),
            (13_574_563_200, 0, "2400-02-29T00:00:00.000Z"),
        ] {
            assert_eq!(epoch_to_rfc3339(secs, millis), want, "{secs}");
        }
    }

    const V1_OBJECT: &str = "a8
         66 736368656d61 6b 6d616b6e61652e7461736b
         67 76657273696f6e 01
         67 7461736b5f6964 50 000102030405060708090a0b0c0d0e0f
         66 7461736b6572 a1 63 556964 19 03e8
         66 706172656e74 f6
         65 6167656e74 64 686f6269
         63 61736b a1 66 50726f6d7074 a1 66 70726f6d7074 62 6869
         66 6c6162656c73 a0";

    const V1_SUBMISSION: &str = "a5
         66 736368656d61 6b 6d616b6e61652e7461736b
         67 76657273696f6e 01
         65 6167656e74 64 686f6269
         63 61736b a1 66 50726f6d7074 a1 66 70726f6d7074 62 6869
         66 6c6162656c73 a0";

    const FORGE: &str = "forge.example";

    fn git_ref(server: &str, base: &str, change: Option<u64>) -> BindingRequest {
        BindingRequest::Git(GitRef {
            server: server.into(),
            base: base.into(),
            change,
        })
    }

    fn git_binding(server: &str, base: &str, head: Option<&str>, change: Option<u64>) -> Binding {
        Binding::Git(GitBinding {
            server: server.into(),
            base: base.into(),
            head: head.map(Into::into),
            change,
        })
    }

    fn path(i: usize, len: usize) -> String {
        let owner = format!("o{i}/");
        format!("{owner}{}", "r".repeat(len - owner.len()))
    }

    /// `count` distinct bindings whose list encodes to exactly `target` bytes.
    fn sized<T: Serialize>(
        count: usize,
        target: usize,
        make: impl Fn(usize, usize) -> T,
    ) -> Vec<T> {
        let mut lens = vec![24; count];
        let build = |lens: &[usize]| -> Vec<T> {
            lens.iter().enumerate().map(|(i, &l)| make(i, l)).collect()
        };
        let mut short = target - bindings_encoded_len(&build(&lens));
        for len in &mut lens {
            let add = short.min(REPOSITORY_PATH_MAX_BYTES - *len);
            *len += add;
            short -= add;
        }
        let list = build(&lens);
        assert_eq!(bindings_encoded_len(&list), target);
        list
    }

    fn requests_at(count: usize, target: usize) -> Vec<BindingRequest> {
        sized(count, target, |i, len| {
            git_ref(FORGE, &path(i, len), Some(u64::MAX))
        })
    }

    const HEAD_LEN: usize = 40;

    fn sealed_at(count: usize, target: usize) -> Vec<Binding> {
        sized(count, target, |i, len| {
            git_binding(
                FORGE,
                &path(i, len),
                Some(&path(i, HEAD_LEN)),
                Some(u64::MAX),
            )
        })
    }

    fn submit_with(bindings: Vec<BindingRequest>) -> Result<TaskSubmission, String> {
        let mut sub = submission();
        sub.bindings = bindings;
        dec(&enc(&sub))
    }

    fn object_with(bindings: Vec<Binding>) -> Result<TaskObject, String> {
        let mut obj = object(Tasker::Uid(1000), None);
        obj.bindings = bindings;
        dec(&enc(&obj))
    }

    fn view_with(bindings: Vec<Binding>) -> Result<TaskView, String> {
        let mut view = task_view();
        view.bindings = bindings;
        dec(&enc(&view))
    }

    fn keys(bytes: &[u8]) -> Vec<String> {
        let value: ciborium::Value = dec(bytes).unwrap();
        value
            .as_map()
            .unwrap()
            .iter()
            .map(|(k, _)| k.as_text().unwrap().to_string())
            .collect()
    }

    #[test]
    fn a_task_signed_before_bindings_reencodes_to_its_signed_bytes() {
        let signed = hex(V1_OBJECT);
        let object: TaskObject = dec(&signed).unwrap();
        assert!(object.bindings.is_empty());
        assert!(object.reach.is_empty());
        assert!(!keys(&signed).contains(&"reach".to_string()));
        assert_eq!(enc(&object), signed);
        let bytes = task_signing_bytes(&object, TASK_ENVELOPE_MARGIN).unwrap();
        let (context, body) = bytes.split_at(TASK_SIGNING_CONTEXT.len());
        assert_eq!(context, TASK_SIGNING_CONTEXT);
        assert_eq!(body, signed.as_slice());
        let sent = hex(V1_SUBMISSION);
        let sub: TaskSubmission = dec(&sent).unwrap();
        assert!(sub.bindings.is_empty());
        assert_eq!(enc(&sub), sent);
        let view = task_view();
        assert!(!keys(&enc(&view)).contains(&"bindings".to_string()));
        assert!(!keys(&enc(&view)).contains(&"reach".to_string()));
    }

    #[test]
    fn bindings_round_trip_after_labels_and_are_omitted_when_empty() {
        let golden = hex("a1 63 476974
             a4 66 736572766572 64 682e696f
                64 62617365 63 6f2f72
                64 68656164 f6
                66 6368616e6765 f6");
        let sealed = git_binding("h.io", "o/r", None, None);
        assert_eq!(enc(&sealed), golden);
        assert_eq!(dec::<Binding>(&golden).unwrap(), sealed);
        let request = hex("a1 63 476974
             a3 66 736572766572 64 682e696f
                64 62617365 63 6f2f72
                66 6368616e6765 f6");
        assert_eq!(enc(&git_ref("h.io", "o/r", None)), request);
        assert_eq!(
            dec::<BindingRequest>(&request).unwrap(),
            git_ref("h.io", "o/r", None)
        );

        let mut sub = submission();
        sub.bindings = vec![
            git_ref(FORGE, "o/r", Some(7)),
            git_ref("forge.example:8443", "group/sub/repo", None),
        ];
        let bytes = enc(&sub);
        assert_eq!(
            keys(&bytes),
            ["schema", "version", "agent", "ask", "labels", "bindings"]
        );
        assert_eq!(dec::<TaskSubmission>(&bytes).unwrap(), sub);

        let mut obj = object(Tasker::Uid(1000), None);
        obj.bindings = vec![
            git_binding(FORGE, "o/r", Some("fork/r"), Some(7)),
            git_binding(FORGE, "o/r", None, None),
        ];
        let bytes = enc(&obj);
        assert_eq!(keys(&bytes).last().map(String::as_str), Some("bindings"));
        assert_eq!(keys(&bytes)[keys(&bytes).len() - 2], "labels");
        assert_eq!(dec::<TaskObject>(&bytes).unwrap(), obj);

        let mut view = task_view();
        view.bindings = obj.bindings.clone();
        let bytes = enc(&view);
        assert_eq!(keys(&bytes).last().map(String::as_str), Some("bindings"));
        assert_eq!(dec::<TaskView>(&bytes).unwrap(), view);

        let bare = object(Tasker::Uid(1000), None);
        assert!(!keys(&enc(&bare)).contains(&"bindings".to_string()));
        assert!(!keys(&enc(&submission())).contains(&"bindings".to_string()));
    }

    #[test]
    fn a_malformed_binding_never_decodes() {
        use ciborium::Value;
        let good = "owner/repo";
        let long_server = format!("{}.com", "a".repeat(252));
        let long_path = path(0, 256);
        let server = |s: &str| GitBinding {
            server: s.into(),
            base: good.into(),
            head: None,
            change: None,
        };
        let base = |b: &str| GitBinding {
            base: b.into(),
            ..server(FORGE)
        };
        let head = |h: &str| GitBinding {
            head: Some(h.into()),
            ..server(FORGE)
        };
        let cases = [
            ("server", server("Forge.example")),
            ("server", server("forge.example/x")),
            ("server", server("https://forge.example")),
            ("server", server("")),
            ("server", server(&long_server)),
            ("base", base("owner")),
            ("base", base("owner//repo")),
            ("base", base("owner/")),
            ("base", base("./repo")),
            ("base", base("owner/.")),
            ("base", base("../repo")),
            ("base", base("owner/..")),
            ("base", base("-owner/repo")),
            ("base", base("owner/-repo")),
            ("base", base("owner/repo.git")),
            ("base", base("owner/re#po")),
            ("base", base("owner/re%po")),
            ("base", base("owner/re po")),
            ("base", base("owner/ré")),
            ("base", base("a/")),
            ("base", base(&long_path)),
            (
                "change",
                GitBinding {
                    change: Some(0),
                    ..server(FORGE)
                },
            ),
            ("head", head("fork")),
            ("head", head("fork/repo.git")),
            ("head", head(&path(1, 256))),
        ];
        let fields = ["server", "base", "head", "change"];
        let names_only = |err: &str, field: &str| {
            assert!(err.contains(&format!("`{field}`")), "{field}: {err}");
            for other in fields.iter().filter(|f| **f != field) {
                assert!(!err.contains(&format!("`{other}`")), "{field}: {err}");
            }
        };
        for (field, bad) in cases {
            if bad.head.is_none() {
                let req = git_ref(&bad.server, &bad.base, bad.change);
                let err = dec::<BindingRequest>(&enc(&req)).unwrap_err();
                names_only(&err, field);
                assert!(submit_with(vec![req]).is_err(), "{field}");
            }
            let sealed = Binding::Git(bad);
            let err = dec::<Binding>(&enc(&sealed)).unwrap_err();
            names_only(&err, field);
            assert!(object_with(vec![sealed.clone()]).is_err(), "{field}");
            assert!(view_with(vec![sealed]).is_err(), "{field}");
        }
        let at_cap = path(0, REPOSITORY_PATH_MAX_BYTES);
        for base in [
            "a/b",
            "o.x/r_y-z",
            "Owner/Repo.git2",
            "o/.r",
            at_cap.as_str(),
        ] {
            assert!(repository_path_is_acceptable(base), "{base}");
            assert!(
                dec::<BindingRequest>(&enc(&git_ref(FORGE, base, Some(1)))).is_ok(),
                "{base}"
            );
            let sealed = git_binding(FORGE, base, Some(base), Some(1));
            assert!(dec::<Binding>(&enc(&sealed)).is_ok(), "{base}");
        }

        let text = |s: &str| Value::Text(s.into());
        let git = |name: &str, extra: Option<(&str, Value)>| {
            let mut m = vec![
                (text("server"), text(FORGE)),
                (text("base"), text(good)),
                (text("change"), Value::Null),
            ];
            m.extend(extra.map(|(k, v)| (text(k), v)));
            enc(&Value::Map(vec![(text(name), Value::Map(m))]))
        };
        assert!(dec::<BindingRequest>(&git("Git", None)).is_ok());
        for (named, bytes) in [
            ("Svn", git("Svn", None)),
            ("token", git("Git", Some(("token", text("x"))))),
        ] {
            let err = dec::<BindingRequest>(&bytes).unwrap_err();
            assert!(err.contains(named), "{named}: {err}");
            let err = dec::<Binding>(&bytes).unwrap_err();
            assert!(err.contains(named), "{named}: {err}");
        }
    }

    #[test]
    fn a_submission_cannot_carry_a_head() {
        use ciborium::Value;
        let text = |s: &str| Value::Text(s.into());
        let with_head = enc(&Value::Map(vec![(
            text("Git"),
            Value::Map(vec![
                (text("server"), text(FORGE)),
                (text("base"), text("owner/repo")),
                (text("head"), text("fork/repo")),
                (text("change"), Value::Integer(3.into())),
            ]),
        )]));
        let err = dec::<BindingRequest>(&with_head).unwrap_err();
        assert!(err.contains("head"), "{err}");
        assert_eq!(
            dec::<Binding>(&with_head).unwrap(),
            git_binding(FORGE, "owner/repo", Some("fork/repo"), Some(3))
        );
        let mut sub = submission_value(None);
        if let Value::Map(m) = &mut sub {
            m.push((
                text("bindings"),
                Value::Array(vec![dec::<Value>(&with_head).unwrap()]),
            ));
        }
        let err = dec::<TaskSubmission>(&enc(&sub)).unwrap_err();
        assert!(err.contains("head"), "{err}");
    }

    fn add_with(bindings: Vec<BindingRequest>) -> Result<Vec<BindingRequest>, String> {
        let req = crate::Request {
            protocol_version: crate::PROTOCOL_VERSION,
            verb: crate::Verb::TaskAdd {
                task: task_ref(),
                text: secret("more"),
                bindings,
                forge_tokens: crate::ForgeTokens::default(),
            },
            task: None,
        };
        let bytes = crate::encode_request(&req).unwrap();
        match crate::decode_request(&bytes) {
            Ok(crate::Request {
                verb: crate::Verb::TaskAdd { bindings, .. },
                ..
            }) => Ok(bindings),
            Ok(other) => Err(format!("{other:?}")),
            Err(crate::ProtoCodecError::Decode(e)) => Err(e),
            Err(e) => Err(e.to_string()),
        }
    }

    #[test]
    fn a_duplicate_binding_is_refused() {
        let a = git_ref(FORGE, "o/r", Some(1));
        let b = git_ref(FORGE, "o/r", Some(2));
        assert!(submit_with(vec![a.clone(), b.clone()]).is_ok());
        for twice in [vec![a.clone(), a.clone()], vec![a.clone(), b, a.clone()]] {
            let err = submit_with(twice).unwrap_err();
            assert!(err.contains("duplicate binding"), "{err}");
        }
        let s = git_binding(FORGE, "o/r", None, Some(1));
        let t = git_binding(FORGE, "o/r", Some("f/r"), Some(1));
        assert!(object_with(vec![s.clone(), t.clone()]).is_ok());
        assert!(view_with(vec![s.clone(), t]).is_ok());
        let err = object_with(vec![s.clone(), s.clone()]).unwrap_err();
        assert!(err.contains("duplicate binding"), "{err}");
        let err = view_with(vec![s.clone(), s]).unwrap_err();
        assert!(err.contains("duplicate binding"), "{err}");
        assert!(add_with(vec![a.clone(), git_ref(FORGE, "o/r", Some(2))]).is_ok());
        let err = add_with(vec![a.clone(), a]).unwrap_err();
        assert!(err.contains("duplicate binding"), "{err}");
    }

    #[test]
    fn a_ninth_binding_is_refused() {
        let change = |i: usize| Some(i as u64 + 1);
        let reqs: Vec<_> = (0..=TASK_BINDINGS_MAX)
            .map(|i| git_ref(FORGE, "o/r", change(i)))
            .collect();
        assert_eq!(
            submit_with(reqs[..TASK_BINDINGS_MAX].to_vec())
                .unwrap()
                .bindings
                .len(),
            TASK_BINDINGS_MAX
        );
        assert_eq!(
            add_with(reqs[..TASK_BINDINGS_MAX].to_vec()).unwrap().len(),
            TASK_BINDINGS_MAX
        );
        let err = add_with(reqs.clone()).unwrap_err();
        assert!(err.contains("more than 8 bindings"), "{err}");
        let err = submit_with(reqs).unwrap_err();
        assert!(err.contains("more than 8 bindings"), "{err}");
        let sealed: Vec<_> = (0..=TASK_BINDINGS_MAX)
            .map(|i| git_binding(FORGE, "o/r", None, change(i)))
            .collect();
        assert!(object_with(sealed[..TASK_BINDINGS_MAX].to_vec()).is_ok());
        assert!(view_with(sealed[..TASK_BINDINGS_MAX].to_vec()).is_ok());
        let err = object_with(sealed.clone()).unwrap_err();
        assert!(err.contains("more than 8 bindings"), "{err}");
        let err = view_with(sealed).unwrap_err();
        assert!(err.contains("more than 8 bindings"), "{err}");
        type Primitive = serde::de::value::U32Deserializer<serde::de::value::Error>;
        let err = bounded_requests(Primitive::new(8)).unwrap_err().to_string();
        assert!(err.contains("a list of at most 8 bindings"), "{err}");
        let err = bounded_bindings(Primitive::new(8)).unwrap_err().to_string();
        assert!(err.contains("a list of at most 8 bindings"), "{err}");
    }

    #[test]
    fn bindings_one_byte_over_the_bound_are_refused_and_at_it_accepted() {
        let refused = |err: String| assert!(err.contains("encode to more than"), "{err}");
        for count in [4, TASK_BINDINGS_MAX] {
            let at = requests_at(count, TASK_BINDING_REQUESTS_MAX_BYTES);
            assert_eq!(submit_with(at.clone()).unwrap().bindings, at);
            refused(
                submit_with(requests_at(count, TASK_BINDING_REQUESTS_MAX_BYTES + 1)).unwrap_err(),
            );
            let at = sealed_at(count, TASK_BINDINGS_MAX_BYTES);
            assert_eq!(object_with(at.clone()).unwrap().bindings, at);
            assert_eq!(view_with(at.clone()).unwrap().bindings, at);
            let over = sealed_at(count, TASK_BINDINGS_MAX_BYTES + 1);
            refused(object_with(over.clone()).unwrap_err());
            refused(view_with(over).unwrap_err());
        }
    }

    #[test]
    fn a_request_set_at_its_bound_seals_within_the_sealed_bound() {
        assert_eq!(enc(&()).len(), 1, "a null is one byte");
        assert_eq!(enc(&"head").len() + 1, 6);
        for count in 4..=TASK_BINDINGS_MAX {
            let requests = requests_at(count, TASK_BINDING_REQUESTS_MAX_BYTES);
            let sealed: Vec<Binding> = requests
                .iter()
                .map(|BindingRequest::Git(r)| {
                    Binding::Git(GitBinding {
                        server: r.server.clone(),
                        base: r.base.clone(),
                        head: None,
                        change: r.change,
                    })
                })
                .collect();
            let len = bindings_encoded_len(&sealed);
            assert_eq!(len, TASK_BINDING_REQUESTS_MAX_BYTES + 6 * count);
            assert!(len <= TASK_BINDINGS_MAX_BYTES, "{count}: {len}");
            assert_eq!(object_with(sealed.clone()).unwrap().bindings, sealed);
            let mut headed = sealed;
            let Binding::Git(first) = &mut headed[0];
            first.head = Some(path(99, REPOSITORY_PATH_MAX_BYTES));
            let headed_len = bindings_encoded_len(&headed);
            assert_eq!(headed_len, len + REPOSITORY_PATH_MAX_BYTES + 1);
            assert!(
                headed_len <= TASK_BINDINGS_MAX_BYTES,
                "{count}: {headed_len}"
            );
            assert_eq!(object_with(headed.clone()).unwrap().bindings, headed);
        }
        assert_eq!(
            TASK_BINDING_REQUESTS_MAX_BYTES + 6 * TASK_BINDINGS_MAX + REPOSITORY_PATH_MAX_BYTES + 1,
            TASK_BINDINGS_MAX_BYTES
        );
    }

    #[test]
    fn the_encoded_length_is_the_lists_cbor_length() {
        let list = vec![
            git_binding(FORGE, "o/r", Some("f/r"), Some(1)),
            git_binding("h.io", "a/b/c", None, None),
        ];
        assert_eq!(bindings_encoded_len(&list), enc(&list).len());
        assert_eq!(bindings_encoded_len::<Binding>(&[]), 1);
    }

    fn ops(list: &[ForgeOp]) -> ForgeOps {
        list.iter().copied().collect()
    }

    fn side(base: &[ForgeOp], head: &[ForgeOp]) -> SideReach {
        SideReach::new(ops(base), ops(head)).unwrap()
    }

    fn git_reach(tasker: SideReach, agent: AgentReach, why: Option<EmptyReason>) -> BindingReach {
        BindingReach::Git(GitReach {
            tasker,
            basis: TaskerBasis::Token,
            agent,
            why,
        })
    }

    fn widest_side() -> SideReach {
        use ForgeOp::*;
        side(&[Read, Review, IssueWrite, Merge], &ForgeOp::ALL)
    }

    fn widest_entry(
        basis: TaskerBasis,
        agent: AgentReach,
        why: Option<EmptyReason>,
    ) -> BindingReach {
        BindingReach::Git(GitReach {
            tasker: widest_side(),
            basis,
            agent,
            why,
        })
    }

    fn most_reach() -> Vec<BindingReach> {
        let entry = widest_entry(
            TaskerBasis::Submitter,
            AgentReach::Observed(widest_side()),
            Some(EmptyReason::NoForgeCredential),
        );
        vec![entry; TASK_BINDINGS_MAX]
    }

    fn reached(bindings: Vec<Binding>, reach: Vec<BindingReach>) -> Result<TaskObject, String> {
        let mut obj = object(Tasker::Uid(1000), None);
        obj.bindings = bindings;
        obj.reach = reach;
        dec(&enc(&obj))
    }

    fn summarized(bindings: Vec<Binding>, reach: Vec<ReachSummary>) -> Result<TaskView, String> {
        let mut view = task_view();
        view.bindings = bindings;
        view.reach = reach;
        dec(&enc(&view))
    }

    fn summary(ops: u16, why: Option<u8>) -> ciborium::Value {
        use ciborium::Value;
        Value::Array(vec![
            Value::Integer(ops.into()),
            why.map_or(Value::Null, |w| Value::Integer(w.into())),
        ])
    }

    fn view_with_summaries(bindings: Vec<Binding>, summaries: Vec<ciborium::Value>) -> Vec<u8> {
        let mut view = task_view();
        view.bindings = bindings;
        let mut value: ciborium::Value = dec(&enc(&view)).unwrap();
        if let ciborium::Value::Map(m) = &mut value {
            m.push(("reach".into(), ciborium::Value::Array(summaries)));
        }
        enc(&value)
    }

    fn set_in(value: &mut ciborium::Value, path: &[&str], to: ciborium::Value) {
        let Some((last, rest)) = path.split_last() else {
            *value = to;
            return;
        };
        let mut at = value;
        for key in rest {
            at = match at {
                ciborium::Value::Map(m) => m
                    .iter_mut()
                    .find(|(k, _)| k.as_text() == Some(key))
                    .map(|(_, v)| v)
                    .unwrap(),
                ciborium::Value::Array(a) => &mut a[key.parse::<usize>().unwrap()],
                _ => panic!("{key}"),
            };
        }
        let ciborium::Value::Map(m) = at else {
            panic!("{last}")
        };
        m.iter_mut()
            .find(|(k, _)| k.as_text() == Some(last))
            .unwrap()
            .1 = to;
    }

    fn reached_with(
        obj: &TaskObject,
        path: &[&str],
        to: ciborium::Value,
    ) -> Result<TaskObject, String> {
        let mut value: ciborium::Value = dec(&enc(obj)).unwrap();
        set_in(&mut value, path, to);
        dec(&enc(&value))
    }

    fn headed(head: Option<&str>) -> Binding {
        git_binding(FORGE, "o/r", head, Some(7))
    }

    const PR_A_BOUND_OBJECT: &str = concat!(
        "a966736368656d616b6d616b6e61652e7461736b6776657273696f6e01677461",
        "736b5f696450000102030405060708090a0b0c0d0e0f667461736b6572a16355",
        "69641903e866706172656e74f6656167656e7464686f62696361736ba1665072",
        "6f6d7074a16670726f6d7074626869666c6162656c73a06862696e64696e6773",
        "82a163476974a4667365727665726d666f7267652e6578616d706c6564626173",
        "65636f2f726468656164f6666368616e676507a163476974a466736572766572",
        "72666f7267652e6578616d706c653a3834343364626173656e67726f75702f73",
        "75622f7265706f6468656164f6666368616e6765f6",
    );

    #[test]
    fn a_pr_a_bound_task_still_verifies() {
        let signed = hex(PR_A_BOUND_OBJECT);
        let object: TaskObject = dec(&signed).unwrap();
        assert_eq!(
            object.bindings,
            [
                git_binding(FORGE, "o/r", None, Some(7)),
                git_binding("forge.example:8443", "group/sub/repo", None, None),
            ]
        );
        assert!(object.reach.is_empty());
        assert_eq!(enc(&object), signed);
        let bytes = task_signing_bytes(&object, TASK_ENVELOPE_MARGIN).unwrap();
        let (context, body) = bytes.split_at(TASK_SIGNING_CONTEXT.len());
        assert_eq!(context, TASK_SIGNING_CONTEXT);
        assert_eq!(body, signed.as_slice());
    }

    #[test]
    fn reach_round_trips_after_bindings_and_is_omitted_when_empty() {
        use ForgeOp::*;
        let entry = git_reach(
            side(&[Read], &[PushHead]),
            AgentReach::AtHandOut,
            Some(EmptyReason::AgentNotCovered),
        );
        let golden = hex("a1 63 476974
             a4 66 7461736b6572 a2 64 62617365 01 64 68656164 08
                65 6261736973 65 546f6b656e
                65 6167656e74 69 417448616e644f7574
                63 776879 6f 4167656e744e6f74436f7665726564");
        assert_eq!(enc(&entry), golden);
        assert_eq!(dec::<BindingReach>(&golden).unwrap(), entry);

        let observed = git_reach(
            side(&[Read, Review, Merge], &[PushHead]),
            AgentReach::Observed(side(&[Read, Merge], &[PushHead, Read])),
            None,
        );
        let obj = reached(
            vec![
                headed(Some("f/r")),
                git_binding(FORGE, "o/s", Some("g/s"), None),
            ],
            vec![observed, entry],
        )
        .unwrap();
        let bytes = enc(&obj);
        let k = keys(&bytes);
        assert_eq!(&k[k.len() - 2..], ["bindings", "reach"]);
        assert_eq!(obj.reach, [observed, entry]);

        let view = summarized(
            obj.bindings.clone(),
            obj.reach.iter().map(ReachSummary::of).collect(),
        )
        .unwrap();
        let bytes = enc(&view);
        let k = keys(&bytes);
        assert_eq!(&k[k.len() - 2..], ["bindings", "reach"]);
        let reach = hex("82 82 19 0111 f6 82 00 01");
        let value: ciborium::Value = dec(&bytes).unwrap();
        let (_, got) = value.as_map().unwrap().last().unwrap();
        assert_eq!(enc(got), reach);
    }

    #[test]
    fn a_reach_without_bindings_never_decodes() {
        let entry = git_reach(SideReach::EMPTY, AgentReach::NoForgeCredential, None);
        let err = reached(vec![], vec![entry]).unwrap_err();
        assert!(err.contains("reach without bindings"), "{err}");
        let err = summarized(vec![], vec![ReachSummary::of(&entry)]).unwrap_err();
        assert!(err.contains("reach without bindings"), "{err}");
        assert!(reached(vec![headed(None)], vec![entry]).is_ok());
        assert!(reached(vec![headed(None)], vec![]).is_ok());
        assert!(summarized(vec![headed(None)], vec![]).is_ok());
    }

    #[test]
    fn a_reach_of_another_length_never_decodes() {
        let entry = git_reach(SideReach::EMPTY, AgentReach::NoForgeCredential, None);
        let two = vec![headed(None), git_binding(FORGE, "o/s", None, None)];
        for n in [1, 3] {
            let err = reached(two.clone(), vec![entry; n]).unwrap_err();
            assert!(
                err.contains(&format!("{n} reach entries for 2 bindings")),
                "{err}"
            );
            let err = summarized(two.clone(), vec![ReachSummary::of(&entry); n]).unwrap_err();
            assert!(
                err.contains(&format!("{n} reach entries for 2 bindings")),
                "{err}"
            );
        }
        assert!(reached(two.clone(), vec![entry; 2]).is_ok());
        assert!(summarized(two, vec![ReachSummary::of(&entry); 2]).is_ok());
        let nine = vec![entry; TASK_BINDINGS_MAX + 1];
        let err = reached(sealed_at(TASK_BINDINGS_MAX, TASK_BINDINGS_MAX_BYTES), nine).unwrap_err();
        assert!(err.contains("more than 8 reach entries"), "{err}");
        let nine = vec![summary(0, None); TASK_BINDINGS_MAX + 1];
        let err = dec::<TaskView>(&view_with_summaries(
            sealed_at(TASK_BINDINGS_MAX, TASK_BINDINGS_MAX_BYTES),
            nine,
        ))
        .unwrap_err();
        assert!(err.contains("more than 8 reach entries"), "{err}");
    }

    #[test]
    fn unknown_reach_bits_never_decode() {
        use ciborium::Value;
        let obj = reached(
            vec![headed(Some("f/r"))],
            vec![git_reach(
                SideReach::EMPTY,
                AgentReach::Observed(SideReach::EMPTY),
                None,
            )],
        )
        .unwrap();
        let tasker = &["reach", "0", "Git", "tasker"][..];
        let agent = &["reach", "0", "Git", "agent", "Observed"][..];
        for bits in [1u8 << 5, 1 << 6, 1 << 7, 0xff] {
            for (at, field) in [
                (tasker, "base"),
                (tasker, "head"),
                (agent, "base"),
                (agent, "head"),
            ] {
                let path: Vec<&str> = at.iter().copied().chain([field]).collect();
                let err = reached_with(&obj, &path, Value::Integer(bits.into())).unwrap_err();
                assert!(
                    err.contains("name no operation"),
                    "{bits:#x} {field}: {err}"
                );
            }
        }
        let max = reached_with(
            &obj,
            &["reach", "0", "Git", "tasker", "head"],
            Value::Integer(0x1f.into()),
        );
        assert!(max.is_ok(), "{max:?}");

        let one = || vec![headed(Some("f/r"))];
        assert!(
            dec::<TaskView>(&view_with_summaries(one(), vec![summary(0x3f7, Some(3))])).is_ok()
        );
        for ops in [1u16 << 10, 1 << 11, 1 << 15, 0x3f7 | 1 << 10] {
            let err =
                dec::<TaskView>(&view_with_summaries(one(), vec![summary(ops, None)])).unwrap_err();
            assert!(err.contains("name no operation"), "{ops:#x}: {err}");
        }
        for tag in [4u8, 5, 0xff] {
            let err = dec::<TaskView>(&view_with_summaries(one(), vec![summary(0, Some(tag))]))
                .unwrap_err();
            assert!(err.contains("no empty reason"), "{tag}: {err}");
        }
    }

    #[test]
    fn push_head_in_a_base_set_never_decodes() {
        use ciborium::Value;
        let push = ForgeOps::EMPTY.with(ForgeOp::PushHead);
        let err = SideReach::new(push, ForgeOps::EMPTY).unwrap_err();
        assert!(err.contains("`PushHead` in a base set"), "{err}");
        assert!(SideReach::new(ForgeOps::EMPTY, push).is_ok());
        let obj = reached(
            vec![headed(Some("f/r"))],
            vec![git_reach(
                SideReach::EMPTY,
                AgentReach::Observed(SideReach::EMPTY),
                None,
            )],
        )
        .unwrap();
        for path in [
            &["reach", "0", "Git", "tasker", "base"][..],
            &["reach", "0", "Git", "agent", "Observed", "base"][..],
        ] {
            let err = reached_with(&obj, path, Value::Integer(push.bits().into())).unwrap_err();
            assert!(err.contains("`PushHead` in a base set"), "{path:?}: {err}");
        }
        let one = || vec![headed(Some("f/r"))];
        let err = dec::<TaskView>(&view_with_summaries(one(), vec![summary(8, None)])).unwrap_err();
        assert!(err.contains("`PushHead` in a base set"), "{err}");
        assert!(dec::<TaskView>(&view_with_summaries(one(), vec![summary(8 << 5, None)])).is_ok());
    }

    #[test]
    fn head_ops_without_a_head_never_decode() {
        use ForgeOp::*;
        let on_head = side(&[Read], &[PushHead]);
        let cases = [
            git_reach(on_head, AgentReach::AtHandOut, None),
            git_reach(side(&[Read], &[]), AgentReach::Observed(on_head), None),
        ];
        for entry in cases {
            let err = reached(vec![headed(None)], vec![entry]).unwrap_err();
            assert!(err.contains("head reach without a head"), "{err}");
            assert!(reached(vec![headed(Some("f/r"))], vec![entry]).is_ok());
        }
        let base_only = git_reach(
            side(&[Read], &[]),
            AgentReach::Observed(side(&[Read], &[])),
            None,
        );
        assert!(reached(vec![headed(None)], vec![base_only]).is_ok());

        let entry = git_reach(on_head, AgentReach::Observed(on_head), None);
        let err = summarized(vec![headed(None)], vec![ReachSummary::of(&entry)]).unwrap_err();
        assert!(err.contains("head reach without a head"), "{err}");
        assert!(summarized(vec![headed(Some("f/r"))], vec![ReachSummary::of(&entry)]).is_ok());
    }

    const MOST_REACH_BYTES: usize = 761;

    fn within<'de, D: Deserializer<'de>, const MAX: usize>(
        d: D,
    ) -> Result<Vec<BindingReach>, D::Error> {
        reach_within(d, MAX)
    }

    #[derive(Debug, Deserialize)]
    struct Within<const MAX: usize>(
        #[serde(deserialize_with = "within::<_, MAX>")] Vec<BindingReach>,
    );

    #[test]
    fn the_most_reach_encodes_within_its_bound() {
        let most = most_reach();
        let entry = enc(&most[0]).len();
        let bases = [
            TaskerBasis::Token,
            TaskerBasis::Parent,
            TaskerBasis::Submitter,
        ];
        let agents = [
            AgentReach::Observed(widest_side()),
            AgentReach::AtHandOut,
            AgentReach::NoForgeCredential,
        ];
        let whys = [
            None,
            Some(EmptyReason::HeadGone),
            Some(EmptyReason::AgentNotCovered),
            Some(EmptyReason::NoForgeCredential),
            Some(EmptyReason::NoReachCheck),
        ];
        for basis in bases {
            for agent in agents {
                for why in whys {
                    let len = enc(&widest_entry(basis, agent, why)).len();
                    assert!(len <= entry, "{basis:?} {agent:?} {why:?}: {len}");
                }
            }
        }
        let len = bindings_encoded_len(&most);
        assert_eq!(len, 1 + TASK_BINDINGS_MAX * entry);
        assert!(len <= TASK_REACH_MAX_BYTES, "{len}");
        let obj = reached(
            sealed_at(TASK_BINDINGS_MAX, TASK_BINDINGS_MAX_BYTES),
            most.clone(),
        )
        .unwrap();
        assert_eq!(obj.reach, most);

        assert_eq!(len, MOST_REACH_BYTES);
        let bytes = enc(&most);
        assert_eq!(dec::<Within<MOST_REACH_BYTES>>(&bytes).unwrap().0, most);
        let err = dec::<Within<{ MOST_REACH_BYTES - 1 }>>(&bytes).unwrap_err();
        assert!(err.contains("encodes to more than"), "{err}");
    }

    fn max_addendum() -> SignedAddendum {
        let alg = "ml-dsa-87";
        let each = (TASK_SIGNATURE_MAX_BYTES - alg.len()) / (2 + TASK_CHAIN_MAX);
        let part = vec![0xa5; each];
        let chain: Vec<&[u8]> = vec![&part; TASK_CHAIN_MAX];
        let rest = TASK_SIGNATURE_MAX_BYTES - alg.len() - each * (1 + TASK_CHAIN_MAX);
        SignedAddendum {
            addendum: TaskAddendum::new(
                id(0xf0),
                u32::MAX,
                sealed_at(TASK_BINDINGS_MAX, TASK_BINDINGS_MAX_BYTES),
                most_reach(),
            )
            .unwrap(),
            signature: signature(alg, &part, &chain, &vec![0x5a; rest]),
        }
    }

    #[test]
    fn addendum_and_task_signing_contexts_are_disjoint() {
        let (task, added) = (TASK_SIGNING_CONTEXT, TASK_ADDENDUM_SIGNING_CONTEXT);
        assert!(!task.starts_with(added) && !added.starts_with(task));
        assert_eq!(added, b"maknae.task.addendum.v1\0");
        let addendum = max_addendum().addendum;
        let bytes = addendum_signing_bytes(&addendum).unwrap();
        assert_eq!(&bytes[..added.len()], added);
        assert_eq!(
            dec::<TaskAddendum>(&bytes[added.len()..]).unwrap(),
            addendum
        );
        let object =
            task_signing_bytes(&object(Tasker::Uid(1000), None), TASK_ENVELOPE_MARGIN).unwrap();
        assert!(dec::<TaskAddendum>(&object[task.len()..]).is_err());
        assert!(dec::<TaskObject>(&bytes[added.len()..]).is_err());
    }

    #[test]
    fn the_largest_addendum_signs_within_its_margin() {
        let addendum = max_addendum().addendum;
        let len = addendum_signing_bytes(&addendum).unwrap().len();
        let reach_len = bindings_encoded_len(addendum.reach());
        assert!(len <= TASK_ADDENDUM_MARGIN, "{len}");
        assert!(
            len >= TASK_BINDINGS_MAX_BYTES + reach_len,
            "{len} holds the bindings and the reach"
        );
    }

    #[test]
    fn an_addendum_that_is_empty_unaligned_or_unnumbered_never_decodes() {
        use ciborium::Value;
        let good = max_addendum().addendum;
        let with = |key: &str, value: Value| {
            let mut map: Value = dec(&enc(&good)).unwrap();
            for (k, v) in map.as_map_mut().unwrap() {
                if k.as_text() == Some(key) {
                    *v = value.clone();
                }
            }
            dec::<TaskAddendum>(&enc(&map))
        };
        assert_eq!(dec::<TaskAddendum>(&enc(&good)).unwrap(), good);
        let one_reach: Value = dec(&enc(&good.reach()[..1].to_vec())).unwrap();
        for (key, value, says) in [
            ("seq", Value::Integer(0.into()), "seq starts at 1"),
            (
                "bindings",
                Value::Array(vec![]),
                "an addendum of 0 bindings",
            ),
            ("reach", one_reach, "8 bindings and 1 reach"),
            ("reach", Value::Array(vec![]), "8 bindings and 0 reach"),
            (
                "schema",
                Value::Text("maknae.task".into()),
                "addendum schema",
            ),
            ("version", Value::Integer(2.into()), "addendum version 2"),
        ] {
            let err = with(key, value).unwrap_err();
            assert!(err.contains(says), "{key}: {err}");
        }
        assert!(
            TaskAddendum::new(id(1), 0, good.bindings().to_vec(), good.reach().to_vec()).is_err()
        );
    }

    #[test]
    fn an_addendum_with_the_most_follow_ups_fits_the_response_cap() {
        const KERNEL_FOLLOW_UPS_MAX: usize = 32;
        let signed = max_addendum();
        for prompt_max in [1, 4096, 1 << 20] {
            let each = prompt_max / KERNEL_FOLLOW_UPS_MAX;
            let mut items: Vec<SecretText> = (0..KERNEL_FOLLOW_UPS_MAX)
                .map(|_| secret(&"f".repeat(each)))
                .collect();
            items[0] = secret(&"f".repeat(prompt_max - each * (items.len() - 1)));
            let response = crate::Response {
                protocol_version: crate::PROTOCOL_VERSION,
                result: crate::RespResult::Ok(crate::Payload::TaskFollowUps(TaskFollowUps {
                    task: TaskRef::from_id(&id(0xf0)),
                    from: u32::MAX,
                    items,
                    addendum: Some(Bytes::new(enc(&signed).into())),
                })),
                catalog_digest: Some(crate::CatalogDigest([0xff; 32])),
            };
            let len = crate::encode_response(&response).unwrap().len();
            assert!(
                len <= prompt_response_cap(prompt_max),
                "{prompt_max}: {len}"
            );
        }
    }

    #[test]
    fn an_addendum_returns_what_it_was_built_with() {
        let bindings = sealed_at(TASK_BINDINGS_MAX, TASK_BINDINGS_MAX_BYTES);
        let reach = most_reach();
        let built = TaskAddendum::new(id(3), 7, bindings.clone(), reach.clone()).unwrap();
        assert_eq!(*built.task_id(), id(3));
        assert_eq!(built.seq(), 7);
        assert_eq!(built.bindings(), &bindings[..]);
        assert_eq!(built.reach(), &reach[..]);
    }
}
