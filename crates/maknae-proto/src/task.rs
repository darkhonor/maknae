//! The task object (#609): a fixed, versioned CBOR record of one task given to an agent.
use crate::{Bytes, SecretText};
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

/// What a tasker sends. The id, the tasker and the parent are the kernel's.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TaskSubmission {
    pub schema: String,
    pub version: u16,
    pub agent: String,
    pub ask: Ask,
    pub labels: Labels,
}

impl std::fmt::Debug for TaskSubmission {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TaskSubmission")
            .field("schema", &self.schema)
            .field("version", &self.version)
            .field("agent", &self.agent)
            .field("ask", &self.ask)
            .field("labels", &self.labels)
            .finish()
    }
}

/// `parent` is the task the submitting request cited, derived by the kernel;
/// `None` is a person's task or an agent's own initiative.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TaskObject {
    pub schema: String,
    pub version: u16,
    pub task_id: TaskId,
    pub tasker: Tasker,
    pub parent: Option<TaskId>,
    pub agent: String,
    pub ask: Ask,
    pub labels: Labels,
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
    use std::io::Write;
    let mut buf = zeroize::Zeroizing::new(vec![0; max_bytes]);
    let mut writer = std::io::Cursor::new(buf.as_mut_slice());
    writer
        .write_all(TASK_SIGNING_CONTEXT)
        .map_err(|e| crate::ProtoCodecError::Encode(e.to_string()))?;
    ciborium::into_writer(task, &mut writer)
        .map_err(|e| crate::ProtoCodecError::Encode(e.to_string()))?;
    let len = writer.position() as usize;
    buf.truncate(len);
    Ok(buf)
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
}

#[derive(Clone, Copy, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub enum TaskClose {
    Stopped,
    Dropped,
    AgentGone,
    AgentLost,
}

#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct TaskView {
    pub task: TaskRef,
    pub agent: String,
    pub state: TaskState,
    pub close: Option<TaskClose>,
    pub submitted_secs: i64,
    pub elapsed_secs: u64,
    pub actions: u32,
    pub last_action_secs: Option<i64>,
}

/// `next` is the submission sequence to resume after.
#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct TaskPage {
    pub entries: Vec<TaskView>,
    pub next: Option<TaskCursor>,
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
#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct TaskDelivery {
    pub signed: Bytes,
    pub partition: String,
}

#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct TaskFollowUps {
    pub from: u32,
    pub items: Vec<SecretText>,
}

const _: fn(&TaskReportView) -> &crate::wire::SecretText = |c| &c.text;
const _: fn(&TaskDelivery) -> &crate::bytes::Bytes = |c| &c.signed;
const _: fn(&TaskFollowUps) -> &Vec<crate::wire::SecretText> = |c| &c.items;

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
            },
            Verb::TaskClaim {
                seen_follow_ups: Some(2),
            },
            Verb::TaskClaim {
                seen_follow_ups: None,
            },
            Verb::TaskReport { text: secret(text) },
        ]
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
            }),
            Payload::TaskFollowUps(TaskFollowUps {
                from: 1,
                items: vec![secret(text), secret("second")],
            }),
            Payload::TaskIdle,
        ]
    }

    #[test]
    fn the_prompt_caps_add_the_envelope_and_then_the_signature() {
        assert_eq!(prompt_request_cap(65_536), 65_536 + 4096);
        assert_eq!(prompt_response_cap(65_536), 65_536 + 4096 + 32 * 1024);
        assert_eq!(prompt_request_cap(usize::MAX), usize::MAX);
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
                | Verb::TaskDrop { .. } => FrameClass::Control,
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
                        from: 0,
                        items: vec![secret(sentinel)],
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
}
