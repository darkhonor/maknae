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
}

impl std::fmt::Display for TaskSchemaError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TaskSchemaError::Schema(s) => write!(f, "task schema {s:?} is not {TASK_SCHEMA}"),
            TaskSchemaError::Version(v) => write!(f, "task version {v} is not {TASK_VERSION}"),
            TaskSchemaError::TaskIdText => f.write_str("a task id is 32 lowercase hex digits"),
        }
    }
}

impl std::error::Error for TaskSchemaError {}

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
