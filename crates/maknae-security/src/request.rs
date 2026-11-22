//! The authorization request: subject / resource / action / context (spec §3, §4).
//!
//! Named `Action` per spec §12. §4 lists action as an attribute bag, but the
//! load-bearing part is the name (the grammar's `action(specifier)`); §4 is
//! revisable, so action is modelled as a newtype name here — any action
//! attributes ride in `context`.

use crate::value::{AttrValue, Attributes};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Subject(pub Attributes);

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Resource(pub Attributes);

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Action(pub String);

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Context(pub Attributes);

/// The context attribute naming which boundary a request arrived on.
///
/// Defined HERE, in the seam both sides depend on, rather than as a literal in the
/// kernel and a `const` in each backend. A key whose spelling can drift between the
/// writer and the reader is a decision that silently stops being made — and a
/// filesystem attempt is decided only on `local` (ADR-0009 decision 8).
pub const CONTEXT_DAC_LANE: &str = "dac_lane";

/// The requester's home `~` binds to, resolved per request and stamped only by the kernel (#435).
pub const SUBJECT_HOME: &str = "home";

/// Subject attribute naming who initiated a request; only the kernel stamps it.
pub const SUBJECT_INITIATOR: &str = "initiator";

/// The [`SUBJECT_INITIATOR`] value of a request the kernel makes on its own behalf.
pub const INITIATOR_KERNEL: &str = "kernel";

/// The listener a request arrived on, [`CHANNEL_CLIENT`] or [`CHANNEL_AGENT`]; kernel-stamped.
pub const SUBJECT_CHANNEL: &str = "channel";
pub const CHANNEL_CLIENT: &str = "client";
pub const CHANNEL_AGENT: &str = "agent";

/// The agent id from the verified agent-plane SAN; kernel-stamped.
pub const SUBJECT_AGENT: &str = "agent";

/// The task a request cites and that task's tasker; kernel-stamped.
pub const SUBJECT_TASK: &str = "task";
pub const SUBJECT_TASKER: &str = "tasker";

/// The partition of the cited task's root tasker, from the stored record; kernel-stamped.
pub const SUBJECT_ROOT_TASKER: &str = "root_tasker";

/// The target agent of a `session.task` request.
pub const RESOURCE_AGENT: &str = "agent";

/// Which `session.task` operation the verb is, stamped by the kernel from the verb.
pub const CONTEXT_TASK_OP: &str = "task_op";

/// True only when the caller is the cited task's tasker; a foreign or unknown task is false.
pub const RESOURCE_TASK_OWNED: &str = "task_owned";

/// True only when the caller is the agent holding the cited `Working` task.
pub const RESOURCE_TASK_HELD: &str = "task_held";

/// The cited task's state, or `none` when it is not the caller's.
pub const RESOURCE_TASK_STATE: &str = "task_state";

/// No PEP stamps this; a filesystem attempt carrying it is refused (ADR-0009 decision 8). Owner, mode and gid are never put on a request for a backend to recompute.
pub const RESOURCE_OS_ACCESSIBLE: &str = "os_accessible";

/// Kernel-stamped mutation preparation kind (#158). Never copied from client
/// metadata: a namespace kind means policy authorization to attempt an operation
/// under subject credentials, not OS preapproval from a directory descriptor.
pub const CONTEXT_FS_OPERATION: &str = "fs_operation";

/// The conversation's personal `sensitive.yaml` entries, as an `AttrValue::Set`; kernel-stamped.
pub const CONTEXT_SENSITIVE_PERSONAL: &str = "sensitive.personal";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FsOperation {
    WriteExisting,
    WriteCreate,
    DeleteEntry,
    DeleteTree,
    Mkdir,
    Read,
    Mount,
}

impl FsOperation {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::WriteExisting => "write-existing",
            Self::WriteCreate => "write-create",
            Self::DeleteEntry => "delete-entry",
            Self::DeleteTree => "delete-tree",
            Self::Mkdir => "mkdir",
            Self::Read => "read",
            Self::Mount => "mount",
        }
    }

    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "write-existing" => Some(Self::WriteExisting),
            "write-create" => Some(Self::WriteCreate),
            "delete-entry" => Some(Self::DeleteEntry),
            "delete-tree" => Some(Self::DeleteTree),
            "mkdir" => Some(Self::Mkdir),
            "read" => Some(Self::Read),
            "mount" => Some(Self::Mount),
            _ => None,
        }
    }
}

/// The resource attribute carrying the CONTENT'S CLASSIFICATION MARKING, as a
/// string. Its FIRST token (everything before the first `//`) is ranked by the
/// classification system the enclave selected (`ClassificationPolicy::level_of`
/// is the one normalizer: case-insensitive, separators not normalized); what
/// follows `//` -- caveats, compartments, releasability -- is opaque to the
/// kernel's ceiling operand and belongs to the external DCS library.
///
/// Defined HERE, beside [`RESOURCE_OS_ACCESSIBLE`] and [`CONTEXT_DAC_LANE`], for
/// the same reason those are: a key whose spelling can drift between the writer
/// and the reader is a decision that silently stops being made.
///
/// **Absent means the system's lowest level** (operator ruling 2026-09-06,
/// #148; US `UNCLASSIFIED`, AUS `UNOFFICIAL`): unmarked content is the default
/// level, at or below every ceiling, and flows. Absent is a legitimate,
/// evaluated state, never a silent pass-through -- and never a refusal.
///
/// **The value's CONTRACT, for the writer this key waits for:** a marking of
/// the ENCLAVE'S OWN system whose first token is one of that system's level
/// names (`SECRET//NOFORN` ranks as SECRET; `CUI//SP-PRVCY` as UNCLASSIFIED).
/// A first token the selected system does not carry is refused, unwaivably,
/// under deny-overrides -- naming the compiled-in system that does carry it
/// when one does (ADR-0022 decision 5; the kernel maps nothing between
/// systems). Stamping the marking is the WRITER's job (`rust-dcs`'s
/// `dcs-label` where DCS is installed; #229 otherwise). Nothing populates the
/// key yet.
///
/// **Provenance rule for that writer:** stamped by the trust plane from the
/// OBJECT's own label (a SPIF marking, a filesystem attribute the kernel read),
/// **never from a request attribute a client can supply.** The risk is a
/// client-supplied DOWNGRADE: a marking at or below the ceiling is an abstention,
/// so a client that could write `UNCLASSIFIED` over `TOP SECRET` would remove a
/// mandatory refusal -- the inform-but-not-authorize inversion AGENTS.md
/// principle 2 forbids.
pub const RESOURCE_CLASSIFICATION: &str = "classification";

pub const RESOURCE_TOOL_ENTRY: &str = "tool.entry";
pub const RESOURCE_TOOL_PROGRAM: &str = "tool.program";
pub const RESOURCE_TOOL_ARGV: &str = "tool.argv";
pub const RESOURCE_BINDING_KINDS: &str = "binding.kinds";
pub const ENTRY_LABEL_PREFIX: &str = "entry.";

/// Which boundary a request arrived on.
///
/// **Derived from the accepting listener and from nothing else.** Never from a request
/// field, a header, or a session claim — anything that lets a local request present as
/// remote escapes OS DAC entirely, which ADR-0009 calls the single most important
/// control in its design. It is an argument to request construction precisely so there
/// is no code path by which client-supplied content could reach it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Lane {
    /// The on-host client plane: the subject is a `SO_PEERCRED` uid on this machine,
    /// so OS DAC is meaningful and can be asked (ADR-0006 decision 4).
    Local,
    /// Through the gateway: the subject is an OIDC principal with no uid, no process,
    /// and no descriptors on this host (ADR-0006 decisions 5 and 7). OS DAC is
    /// structurally inapplicable — which is NOT the same as unknown.
    Remote,
}

impl Lane {
    /// The stamped value. Closed vocabulary: a backend that does not recognise the
    /// string must fail closed rather than treat it as absent.
    pub fn as_str(self) -> &'static str {
        match self {
            Lane::Local => "local",
            Lane::Remote => "remote",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Request {
    pub subject: Subject,
    pub resource: Resource,
    pub action: Action,
    pub context: Context,
}

pub const RESOURCE_BOUND_PREFIX: &str = "bound.";
pub const GIT_BOUND_FIELDS: [&str; 4] = ["server", "base", "head", "change"];

pub fn bound_key(kind: &str, field: &str) -> String {
    format!("{RESOURCE_BOUND_PREFIX}{kind}.{field}")
}

/// One git binding's values, as the trust plane stamps them under `bound.git.*`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GitBoundValues {
    pub server: String,
    pub base: String,
    pub head: Option<String>,
    pub change: Option<u64>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum BoundEncodingError {
    NotAList,
    Misaligned,
    Empty,
    MissingField,
}

/// One `List` per field of [`GIT_BOUND_FIELDS`], index-aligned with `bindings`;
/// `""` is an absent field. No bindings stamps no key.
pub fn encode_git_bound(bindings: &[GitBoundValues]) -> Vec<(String, AttrValue)> {
    if bindings.is_empty() {
        return Vec::new();
    }
    let column = |field: fn(&GitBoundValues) -> String| {
        AttrValue::List(bindings.iter().map(field).collect())
    };
    let columns = [
        column(|b| b.server.clone()),
        column(|b| b.base.clone()),
        column(|b| b.head.clone().unwrap_or_default()),
        column(|b| b.change.map(|c| c.to_string()).unwrap_or_default()),
    ];
    GIT_BOUND_FIELDS
        .iter()
        .zip(columns)
        .map(|(field, list)| (bound_key("git", field), list))
        .collect()
}

/// The inverse of [`encode_git_bound`]: per binding, the present fields as
/// `("git.<field>", value)`; `server` and `base` are never absent. No `bound.git.*` key
/// at all is no bindings.
pub fn decode_git_bound(
    resource: &Attributes,
) -> Result<Vec<Vec<(String, String)>>, BoundEncodingError> {
    let mut columns = Vec::with_capacity(GIT_BOUND_FIELDS.len());
    for field in GIT_BOUND_FIELDS {
        match resource.get(&bound_key("git", field)) {
            None => columns.push(None),
            Some(AttrValue::List(values)) => columns.push(Some(values.as_slice())),
            Some(_) => return Err(BoundEncodingError::NotAList),
        }
    }
    if columns.iter().all(Option::is_none) {
        return Ok(Vec::new());
    }
    let columns = columns
        .into_iter()
        .collect::<Option<Vec<_>>>()
        .ok_or(BoundEncodingError::Misaligned)?;
    let len = columns[0].len();
    if columns.iter().any(|c| c.len() != len) {
        return Err(BoundEncodingError::Misaligned);
    }
    if len == 0 {
        return Err(BoundEncodingError::Empty);
    }
    if GIT_BOUND_FIELDS
        .iter()
        .zip(&columns)
        .any(|(field, c)| matches!(*field, "server" | "base") && c.iter().any(String::is_empty))
    {
        return Err(BoundEncodingError::MissingField);
    }
    Ok((0..len)
        .map(|i| {
            GIT_BOUND_FIELDS
                .iter()
                .zip(&columns)
                .filter(|(_, column)| !column[i].is_empty())
                .map(|(field, column)| (format!("git.{field}"), column[i].clone()))
                .collect()
        })
        .collect())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The lane vocabulary is a CLOSED set: a filesystem attempt is decided only on
    /// `local` (ADR-0009 decision 8). Swap these two strings and every remote request
    /// is judged as a local subject — so the spelling is asserted, not assumed.
    #[test]
    fn the_lane_vocabulary_is_pinned_in_both_directions() {
        assert_eq!(Lane::Local.as_str(), "local");
        assert_eq!(Lane::Remote.as_str(), "remote");
        assert_ne!(Lane::Local.as_str(), Lane::Remote.as_str());
        assert_eq!(CONTEXT_DAC_LANE, "dac_lane");
        assert_eq!(SUBJECT_HOME, "home");
    }

    #[test]
    fn the_kernel_initiator_spelling_is_pinned() {
        assert_eq!(SUBJECT_INITIATOR, "initiator");
        assert_eq!(INITIATOR_KERNEL, "kernel");
    }

    #[test]
    fn the_agent_attribute_spellings_are_pinned() {
        assert_eq!(SUBJECT_CHANNEL, "channel");
        assert_eq!(CHANNEL_CLIENT, "client");
        assert_eq!(CHANNEL_AGENT, "agent");
        assert_eq!(SUBJECT_AGENT, "agent");
        assert_eq!(SUBJECT_TASK, "task");
        assert_eq!(SUBJECT_TASKER, "tasker");
        assert_eq!(RESOURCE_AGENT, "agent");
    }

    use crate::value::{AttrValue, Attributes};

    #[test]
    fn request_holds_four_bags_and_action() {
        let mut s = Attributes::new();
        s.insert("id", AttrValue::Str("alex".into()));
        let req = Request {
            subject: Subject(s),
            resource: Resource(Attributes::new()),
            action: Action("egress".into()),
            context: Context(Attributes::new()),
        };
        assert_eq!(req.action.0, "egress");
        assert_eq!(req.subject.0.str("id"), Some("alex"));
    }
}

#[cfg(test)]
mod operation_tests {
    use super::FsOperation;
    #[test]
    fn preparation_terms_have_distinct_exact_spellings() {
        for (operation, spelling) in [
            (FsOperation::WriteExisting, "write-existing"),
            (FsOperation::WriteCreate, "write-create"),
            (FsOperation::DeleteEntry, "delete-entry"),
            (FsOperation::DeleteTree, "delete-tree"),
            (FsOperation::Mkdir, "mkdir"),
            (FsOperation::Read, "read"),
            (FsOperation::Mount, "mount"),
        ] {
            assert_eq!(operation.as_str(), spelling);
            assert_eq!(FsOperation::parse(spelling), Some(operation));
        }
        for unknown in ["", "write", "WriteExisting", "Read", "mkdir "] {
            assert_eq!(FsOperation::parse(unknown), None);
        }
    }
}

#[cfg(test)]
mod bound_tests {
    use super::*;
    use crate::value::{AttrValue, Attributes};

    fn values() -> Vec<GitBoundValues> {
        vec![
            GitBoundValues {
                server: "sentinel.example:8443".into(),
                base: "o/a".into(),
                head: None,
                change: Some(1),
            },
            GitBoundValues {
                server: "sentinel.example:8443".into(),
                base: "o/b".into(),
                head: Some("feature".into()),
                change: None,
            },
        ]
    }

    fn stamped(v: &[GitBoundValues]) -> Attributes {
        let mut a = Attributes::new();
        for (k, list) in encode_git_bound(v) {
            a.insert(k, list);
        }
        a
    }

    fn pairs(p: &[(&str, &str)]) -> Vec<(String, String)> {
        p.iter()
            .map(|(k, v)| ((*k).to_string(), (*v).to_string()))
            .collect()
    }

    #[test]
    fn the_bound_vocabulary_is_pinned() {
        assert_eq!(RESOURCE_BOUND_PREFIX, "bound.");
        assert_eq!(GIT_BOUND_FIELDS, ["server", "base", "head", "change"]);
        assert_eq!(bound_key("git", "change"), "bound.git.change");
    }

    #[test]
    fn git_bound_values_encode_as_index_aligned_lists() {
        let a = stamped(&values());
        assert_eq!(
            a.list("bound.git.server"),
            Some(
                &[
                    "sentinel.example:8443".to_string(),
                    "sentinel.example:8443".into()
                ][..]
            )
        );
        assert_eq!(
            a.list("bound.git.base"),
            Some(&["o/a".to_string(), "o/b".into()][..])
        );
        assert_eq!(
            a.list("bound.git.head"),
            Some(&[String::new(), "feature".into()][..])
        );
        assert_eq!(
            a.list("bound.git.change"),
            Some(&["1".to_string(), String::new()][..])
        );
        assert!(encode_git_bound(&[]).is_empty());
    }

    #[test]
    fn git_bound_values_round_trip_with_absent_fields_omitted() {
        assert_eq!(
            decode_git_bound(&stamped(&values())),
            Ok(vec![
                pairs(&[
                    ("git.server", "sentinel.example:8443"),
                    ("git.base", "o/a"),
                    ("git.change", "1"),
                ]),
                pairs(&[
                    ("git.server", "sentinel.example:8443"),
                    ("git.base", "o/b"),
                    ("git.head", "feature"),
                ]),
            ])
        );
        assert_eq!(decode_git_bound(&Attributes::new()), Ok(Vec::new()));
    }

    #[test]
    fn unequal_or_partial_lists_are_refused() {
        let mut a = stamped(&values());
        a.insert("bound.git.head", AttrValue::List(vec![String::new()]));
        assert_eq!(decode_git_bound(&a), Err(BoundEncodingError::Misaligned));
        let mut partial = Attributes::new();
        partial.insert("bound.git.base", AttrValue::List(vec!["o/a".into()]));
        assert_eq!(
            decode_git_bound(&partial),
            Err(BoundEncodingError::Misaligned)
        );
    }

    #[test]
    fn a_bound_value_that_is_not_a_list_is_refused() {
        for wrong in [
            AttrValue::Str("o/a".into()),
            AttrValue::Set(["o/a".to_string()].into()),
            AttrValue::Int(1),
        ] {
            let mut a = stamped(&values()[..1]);
            a.insert("bound.git.base", wrong);
            assert_eq!(decode_git_bound(&a), Err(BoundEncodingError::NotAList));
        }
    }

    #[test]
    fn a_binding_without_its_server_or_base_is_refused() {
        for blank in [
            |v: &mut GitBoundValues| v.server.clear(),
            |v: &mut GitBoundValues| v.base.clear(),
        ] {
            let mut v = values();
            blank(&mut v[1]);
            assert_eq!(
                decode_git_bound(&stamped(&v)),
                Err(BoundEncodingError::MissingField)
            );
        }
    }

    #[test]
    fn empty_lists_for_a_present_kind_are_refused() {
        let mut a = Attributes::new();
        for field in GIT_BOUND_FIELDS {
            a.insert(bound_key("git", field), AttrValue::List(Vec::new()));
        }
        assert_eq!(decode_git_bound(&a), Err(BoundEncodingError::Empty));
    }
}
