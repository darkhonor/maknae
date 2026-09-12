//! Versioned CBOR request/response contract (spec §3).
use crate::error::ProtoCodecError;
use serde::{Deserialize, Deserializer, Serialize, Serializer};

// PROTOCOL_VERSION STAYS 1 (#77): adding `Verb::Read`/`Payload::ReadContent`/
// `ProtoErrCode::TooLarge` are ADDITIVE CBOR enum variants — no version bump.
// #162 adds `Payload::{ConfigView, Status, SubjectList}` the same way, appended
// at the tail. A client built before them has no subcommand that can elicit
// one. (Corrected 2026-09-02, #181: this comment claimed a newer client
// against an older daemon "gets `NotImplemented` from the `NoBehaviour` arm"
// — false twice over. The older daemon cannot DECODE the unknown `Verb`
// variant at all; that path is the decode-failure class. And `NoBehaviour` is
// reached only after a Permit, which no shipped operand can produce for an
// unbuilt term — see `handler.rs`'s `Dispatch::NoBehaviour` doc.)
// A pre-#77 CLI never sends `Read`, so it keeps interoperating with a #77
// daemon for `ping`/`whoami` (same wire version); only the new read verb
// needs the new CLI. A version bump would be an irreversible hard mutual
// break (strict-equality check both directions) and was NOT authorized.
pub const PROTOCOL_VERSION: u16 = 1;

/// Upper bound on the loop's conversation identifier (#241). Informational
/// only: recorded, never decided on. 32, not 64: it is written into every
/// egress audit record, and the macOS unified-log line cap was measured with
/// this bound (maknae-audit-append `syslog_fmt.rs` tests).
pub const MAX_CONVERSATION_ID_BYTES: usize = 32;

/// `[A-Za-z0-9._-]{1,32}`: it reaches audit records and terminals, so no
/// whitespace, no control bytes, no path separators. Enforced by the kernel
/// before the PDP sees the request; the decoder stays shape-only.
pub fn conversation_id_is_acceptable(id: &str) -> bool {
    !id.is_empty()
        && id.len() <= MAX_CONVERSATION_ID_BYTES
        && id
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'))
}

/// Prompt text: secret-adjacent like file content (`Bytes`), so it zeroizes
/// on drop and `Debug` redacts; unlike `Bytes` it is a CBOR TEXT string,
/// because ACP's `text` is a string and a peer must not have to re-encode.
#[derive(Clone, PartialEq, Eq)]
pub struct SecretText(pub zeroize::Zeroizing<String>);

impl std::fmt::Debug for SecretText {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "<{} bytes>", self.0.len())
    }
}
impl Serialize for SecretText {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&self.0)
    }
}
impl<'de> Deserialize<'de> for SecretText {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        String::deserialize(d).map(|s| SecretText(zeroize::Zeroizing::new(s)))
    }
}

/// ACP content blocks at pin `9f40e018` (`docs/protocol/v1/content.mdx`): the
/// five types, variant names tracking ACP's `type` values. The CBOR tagging is
/// serde's default (externally tagged), NOT ACP's `{"type": …}` JSON shape;
/// the egress process (#240) owns the ACP translation. Only `Text` is admitted
/// in Cooky, in BOTH directions: a prompt carrying another kind is refused
/// before the PDP, and a reply carrying one is refused for delivery after the
/// send is recorded (#153: images defeat structural marking; nothing stamps
/// markings yet, #229). Fields are the ones Maknae would ever read.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum ContentBlock {
    Text {
        text: SecretText,
    },
    Image {
        data: String,
        mime_type: String,
    },
    Audio {
        data: String,
        mime_type: String,
    },
    Resource {
        uri: String,
        text: Option<SecretText>,
    },
    ResourceLink {
        uri: String,
        name: String,
    },
}

impl ContentBlock {
    /// ACP's `type` value for this variant, as a Rust-side label (used in refusal reasons).
    pub fn kind(&self) -> &'static str {
        match self {
            ContentBlock::Text { .. } => "text",
            ContentBlock::Image { .. } => "image",
            ContentBlock::Audio { .. } => "audio",
            ContentBlock::Resource { .. } => "resource",
            ContentBlock::ResourceLink { .. } => "resource_link",
        }
    }
}

/// Upper bound on a proposed tool call's argument payload (#240a). It rides
/// the reply frame and is counted by `reply_capacity`, so it is part of the
/// no-reallocation bound, not a style preference.
pub const MAX_TOOL_CALL_ARGS_BYTES: usize = 4096;
/// Upper bound on the tool name. It reaches audit records and terminals.
pub const MAX_TOOL_CALL_NAME_BYTES: usize = 64;
/// Upper bound on the provider's opaque correlation id for the call.
pub const MAX_TOOL_CALL_ID_BYTES: usize = 64;

/// A tool call the model PROPOSED. It is content, never an instruction: the
/// model informs, the PDP authorizes (`design/model-conduit-policy.md`). There
/// is deliberately no method here that executes anything — under case 4 a reply
/// may say "now call provider:X", and the deputy must be structurally incapable
/// of acting on it. `Proposed` is in the name so a later reader cannot mistake
/// this for a command.
///
/// `arguments` is [`SecretText`], NOT `String`, and that is the load-bearing
/// choice: `PromptReply` derives `Debug`, and `bins/maknae/src/cli.rs` renders
/// a mismatched payload as `{p:?}` into an operator-visible error string. Tool
/// arguments routinely echo prompt content, so a plain `String` would print
/// them to the terminal and the operator's shell history — and would not
/// zeroize on drop either.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProposedToolCall {
    pub name: String,
    pub call_id: String,
    pub arguments: SecretText,
}

/// Shape-only admission for a proposed tool call. Every field is bounded: the
/// payload rides the reply frame and is counted by `reply_capacity`.
pub fn proposed_tool_call_is_acceptable(c: &ProposedToolCall) -> bool {
    !c.name.is_empty()
        && c.name.len() <= MAX_TOOL_CALL_NAME_BYTES
        && !c.call_id.is_empty()
        && c.call_id.len() <= MAX_TOOL_CALL_ID_BYTES
        && c.arguments.0.len() <= MAX_TOOL_CALL_ARGS_BYTES
}

/// The response leg of `session.prompt`. In Cooky the release to the requesting
/// loop is the prompt verdict itself (ADR-0023); the shape exists so #240 has
/// something to fill. `Unavailable` never returns one.
///
/// `tool_calls` is a SIBLING of `blocks`, not a `ContentBlock` variant (#240a
/// D5): a tool call is not *what the model said*, it is *what the model wants
/// done*, which is exactly the inform/authorize line. Folding it into
/// `ContentBlock` would force widening `admitted_reply`'s `NonText` refusal —
/// loosening a security check to carry a new capability.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PromptReply {
    pub blocks: Vec<ContentBlock>,
    pub tool_calls: Vec<ProposedToolCall>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Verb {
    /// The daemon is reachable and serving. Discloses its existence and, via the
    /// response envelope, its protocol version — nothing more.
    Ping,
    /// Return the peer's plane URI SAN and uid as the daemon authenticated them.
    /// It does NOT return the resolved role — it discloses identity, not
    /// entitlement.
    Whoami,
    /// Runtime posture: version, protocol version, listener, policy load time,
    /// active authz backend. A disclosure of trust-plane state — useful to an
    /// operator, and useful to an attacker fingerprinting the deployment.
    AdminStatus,
    /// The effective composed configuration. Discloses deployment shape,
    /// including what the policy permits.
    AdminConfigShow,
    /// Read the audit trail. Permitting it discloses deny reasons and object
    /// paths that ADR-0019 makes audit-only — the one term whose grant re-exports
    /// the trail over the wire. Recipient scoping is an open constraint.
    AdminAuditTail,
    /// Refresh the construction-time username→uid map and re-validate bindings,
    /// without restart. Not a policy re-read: the policy file is already re-read
    /// on every request (the Zero Trust ruling). The genuinely stale state is the
    /// uid map built once at construction — a username edited in afterwards is
    /// unresolvable until this lands. Permitting it lets the holder make a
    /// newly-added host principal effective without a restart — lifting the
    /// restart-scoped boundary #85 §3 relies on — and un-wedge a policy whose
    /// unresolvable name is denying every subject on every term. The file itself
    /// is root-owned, so this term confers no ability to write it.
    AdminPolicyReload,
    /// Enumerate role bindings. Discloses who holds what.
    AdminSubjectList,
    /// Bind a subject to a role. A policy mutation — write-ahead audit applies.
    /// MUST refuse the `adversary` role: containment has its own sanctioned
    /// spelling below, and admitting it here would grant containment to anyone
    /// holding this term while bypassing the constraints written on it. Binding a
    /// username the daemon has not yet resolved fails the WHOLE policy closed
    /// until the uid map is refreshed — one edit naming an unknown user denies
    /// every subject on every term.
    AdminSubjectBind,
    /// Remove a subject's role binding. A policy mutation, and the sharper edge:
    /// unbinding the last admin locks out the WIRE until an out-of-band root edit
    /// of the root-owned policy file — picked up on the next request when the
    /// re-bound identity was resolved at daemon construction. A name new to the
    /// uid map instead fails the whole policy closed until restart (#85 §3), so
    /// the edit can deepen the cliff before it lifts it. A serviceability cliff,
    /// not an unrecoverable one; recovery is local and always available precisely
    /// because it needs no request. MUST refuse the `adversary` role — otherwise
    /// it becomes an unconstrained `admin.release`.
    AdminSubjectUnbind,
    /// Place a subject under containment (deny-all) by operator decision.
    /// Containment IS a role binding (`adversary`) in the shipped model, so this
    /// and `admin.release` are the ONLY sanctioned spellings —
    /// `subject.bind`/`.unbind` refuse that role precisely so the constraints
    /// live in one place.
    AdminContain,
    /// Lift containment. The recovery path for induced containment; must not
    /// depend on the credential that was contained.
    AdminRelease,
    /// Rotate the daemon's own credentials.
    AdminCredentialRotate,
    /// Enumerate the model providers available to the agent runtime. A disclosure
    /// of what destinations exist. Maps to ACP's top-level `providers/list` — an
    /// agent method, so Maknae is the caller. *(Corrected 2026-09-07, ADR-0023:
    /// NOT built in Cooky — the provider registry lives in the trust plane
    /// (#243) and `admin.config.show` is its view; building this needs the same
    /// `GRANTABLE_ACTIONS` extension as `.set`/`.disable` and is #169's later
    /// work; the ACP call toward an external Agent is not built either.)*
    AdminProviderList,
    /// Maknae selecting the agent runtime's model provider — a trust-plane
    /// destination choice, not the agent's preference. Egress on the same axis as
    /// `session.prompt` (#153). *(ADR-0023 decision 3: NOT built in Cooky — the
    /// provider is registered in root-owned `/etc/maknae` YAML (#243) the
    /// subject cannot write, and this term is not grantable (ADR-0010); a wire
    /// term that could re-target egress from the subject's uid would undo that
    /// custody control.)*
    AdminProviderSet,
    /// Remove a provider from the agent's available destinations. Destination
    /// selection by elimination, same axis. *(ADR-0023 decision 3: not built in
    /// Cooky, for the same reason as `admin.provider.set`.)*
    AdminProviderDisable,
    /// Use a trust-plane-held credential on a subject's behalf against an
    /// external service, without the subject ever seeing it — egress with an
    /// irreversible third-party effect. The confused-deputy term — the subject's
    /// reach becomes the daemon's reach unless the credential is scoped to the
    /// subject rather than the daemon (#153 §4 and #168; *corrected 2026-09-07,
    /// ADR-0023 — this said #151, the MCP epic*).
    AdminCredentialBroker,
    /// Enumerate daemon-side session records (connections to `maknaed`, per #115)
    /// — not agent conversations. A disclosure of who is connected.
    AdminSessionList,
    /// End a daemon-side session record. A denial of service by design — the
    /// operator's tool for cutting off a connection, and therefore abusable as
    /// one.
    AdminSessionTerminate,
    /// Begin a conversation with an agent runtime. This is where the agent's tool
    /// authority is provisioned — in an ACP v2 deployment the MCP servers Maknae
    /// hands into the session are named here, making this a capability-granting
    /// call, not bookkeeping. *(ADR-0023: not built in Cooky, where each loop turn
    /// is one connection and one audit session; the kernel holds no conversation
    /// identity spanning connections (multi-frame exchanges within one
    /// connection exist — the mutation lane — the identity does not), and a
    /// conversation that outlives a process is Velveteen's.)*
    SessionNew,
    /// Reattach to an existing conversation. The caller obtains its content and
    /// history — a disclosure, and for a conversation the caller may not have
    /// started, that is the authorization-relevant fact. Inherits the provenance
    /// and high-water mark already on it.
    SessionResume,
    /// End a conversation, leaving its record intact.
    SessionClose,
    /// Destroy conversation state. Irreversible.
    SessionDelete,
    /// Enumerate conversations. Discloses their existence and metadata.
    SessionList,
    /// Branch a conversation. The mechanism #7 proposed for per-subject replies
    /// in a shared audience (#147). The fork inherits the parent's provenance and
    /// high-water mark; forking is never a way to shed them.
    SessionFork,
    /// ~~Send content to an agent runtime.~~ *Corrected 2026-09-07 (ADR-0023
    /// decision 3): the SUBJECT — Maknae's own runtime loop, the ACP Agent,
    /// untrusted, holding no egress credential — asks the trust plane to send
    /// content to the model. The kernel decides, appends the write-ahead
    /// record, hands the turn to the `maknae-egress` process (which holds the
    /// key and makes the call), and returns the reply on the response leg,
    /// which is decided as a release. This REVERSES ACP's
    /// direction, where `session/prompt` is an agent method the Client calls;
    /// the ADR owns the reversal. The user → loop hop is not this term.* This
    /// is EGRESS — content leaving the trust plane toward a model endpoint. The
    /// term #147's destination governance attaches to; its default is #153's.
    /// Un-recallable once sent — which is why it is two-phase, not audited
    /// after the fact. **Operands (#172, Cooky):** `conversation` is the loop's
    /// identifier (#241), bounded by [`conversation_id_is_acceptable`],
    /// informational, never an input to a verdict; `content` is ACP content,
    /// text only in Cooky. Additive payload on the existing variant name.
    SessionPrompt {
        conversation: String,
        content: Vec<ContentBlock>,
    },
    /// Ask the agent to stop work in progress. *(ADR-0023 decision 3: NOT built
    /// in Cooky — the operand names a session and no session identity exists
    /// there; stopping the loop is the subject stopping its own process. #172's
    /// rule — granted wherever `session.prompt` is, never the scarcer grant,
    /// best-effort, never a recall — applies once a session identity exists.)*
    SessionCancel,
    /// Change a conversation-scoped setting. Open: whether any option can
    /// redirect the model endpoint — if so this is a parallel destination surface
    /// to `session.prompt` and must be decided as one (#153). The pinned
    /// reference did not read payload shapes, so this cannot be settled from
    /// artifacts on disk. Until settled, treat it as egress.
    SessionSetconfigoption,
    /// Change the agent's operating mode. ACP v1 only. Open, and
    /// authority-relevant: a mode may gate what the agent may attempt. Until its
    /// domain is pinned, treat it as egress.
    SessionSetmode,
    /// Rehydrate a stored conversation, restoring its content and the provenance
    /// that came with it. ACP v1 only.
    SessionLoad,
    /// Agent output arriving and being relayed onward. A DISCLOSURE on the relay
    /// leg — to whatever audience receives it. *(ADR-0023 decision 3: in Cooky
    /// the model's reply returns to the requesting subject's own loop on the
    /// `session.prompt` response leg, decided as a release by that verdict; a
    /// relay to any OTHER audience is this term and stays #172's.)*
    SessionUpdate,
    /// The agent asking a human to approve something. A UX affordance and NEVER a
    /// PDP verdict — approval proves intent at one moment, never entitlement. The
    /// request itself is a disclosure — what is asked reveals what the agent
    /// holds and intends.
    SessionRequestpermission,
    /// The agent asking a human for structured input. The request itself is a
    /// disclosure — what is asked reveals what the agent holds and is doing.
    SessionElicitCreate,
    /// The human's answer returning to the agent. Content entering the agent's
    /// context from outside the trust plane — inform-but-not-authorize applies.
    SessionElicitComplete,
    /// Summarize or compact conversation history. A derivation: the compacted
    /// form inherits the provenance and high-water mark of everything it derives
    /// from. A summary of restricted content is still restricted, and compaction
    /// must not be a laundering step (#147, #8).
    SessionCompact,
    /// Return file content. A disclosure, gated by #77's audit-then-respond
    /// invariant — the record is durably appended BEFORE any content is released.
    /// Maknae returns bytes; ACP v1's counterpart is text-only — a divergence the
    /// mapping carries.
    Read { path: String },
    /// Create or replace file content. Maknae writes bytes; ACP v1's counterpart
    /// is text-only — the same divergence `fs.read` carries.
    FsWrite {
        path: String,
        content: crate::Bytes,
        mode: crate::WriteMode,
    },
    /// Destroy file content. Irreversible, and the strongest argument for
    /// two-phase audit.
    FsDelete { path: String, recursive: bool },
    /// Relocate content to a new path. A mutation, and a laundering route if
    /// decided against the source alone: deny matching is lexical over paths, so
    /// moving a denied object to a permitted path makes it readable under a rule
    /// that never named it. Decided against BOTH source and destination; a
    /// permitted destination is never a route around a denied source. Applies
    /// equally to `fs.link` and to any future copy term.
    FsMove,
    /// Enumerate directory contents. A disclosure of names, which is a disclosure
    /// even when contents are refused.
    FsList,
    /// File metadata without content. Discloses existence, size and timestamps —
    /// enough to confirm a denied object exists.
    FsStat,
    /// Create a directory. It also creates a destination later terms are decided
    /// against.
    FsMkdir {
        path: String,
        parents: bool,
        /// Intended suffix beneath the delegated existing directory. The daemon
        /// validates every component and decides paths from the descriptor's
        /// kernel-reported location; this sequence supplies no OS authority.
        components: Vec<String>,
    },
    /// Create a symbolic or hard link. A mutation and an aliasing primitive — the
    /// exact class `maknae-io` exists to defend against, and a second laundering
    /// route alongside `fs.move`. Decided against both link and target. Note the
    /// hard-link defence is a per-call-site named requirement in `maknae-io`, not
    /// structural — a PEP that omits it silently reopens the alias.
    FsLink,
    /// Change a file's mode. Can alter preconditions other controls rest on — the
    /// read anchor's own mode requirement among them.
    FsChmod,
    /// Change a file's owner. A distinct precondition from mode: the read anchor
    /// requires a specific owner AND a mode mask, and they are separate checks.
    FsChown,
    /// Start a command. The moment Maknae causes arbitrary code to run at a
    /// subject's request — the highest-consequence term a client can reach. It is
    /// also unbounded egress: a command can send anything anywhere, with less
    /// mediation than `mcp.tool.call`.
    TerminalCreate,
    /// Read a running command's output. A disclosure of whatever the command
    /// produced, bounded by nothing the deny list can see.
    TerminalOutput,
    /// Block until the command exits and return its exit status. A disclosure —
    /// exit status is an oracle over whatever the command inspected.
    TerminalWaitforexit,
    /// Signal a running command.
    TerminalKill,
    /// Release a terminal's resources.
    TerminalRelease,
    /// Write to a running command's stdin. The primitive that turns
    /// `terminal.create` into an interactive shell — what makes a single
    /// permitted command open-ended.
    TerminalInput,
    /// Open a connection to an MCP server, local or external. A destination
    /// decision in itself, and the point where a trust-plane-held credential may
    /// be used on the agent's behalf without the agent ever seeing it.
    /// `admin.credential.broker` is the sanctioned spelling for that brokering:
    /// this term MUST refuse a trust-plane-held credential and defer to it, or a
    /// grant of `mcp` confers brokering without ever touching the term that
    /// carries its constraints.
    McpConnect,
    /// Tear down a connection.
    McpDisconnect,
    /// Carry a tunnelled MCP payload. Bidirectional — the pinned inventory lists
    /// it as both a client and an agent method, so it conveys content in each
    /// direction and is a disclosure inbound and egress outbound. A single grant
    /// covers both.
    McpMessage,
    /// Invoke a tool on a connected server. Brokering the call makes Maknae the
    /// proximate cause of the tool's effect — the decision is over the triple
    /// (server, tool, arguments), and the tool's own consequence model is never a
    /// substitute for the verdict.
    McpToolCall,
    /// Read a resource a server exposes. A disclosure, and the content is
    /// server-authored — provenance travels with it.
    McpResourceRead,
    /// Retrieve a server-supplied prompt. Server-authored content entering the
    /// agent's context — inform-but-not-authorize applies (#8).
    McpPromptGet,
    /// A server asking the client to run a model inference. An inversion, and
    /// EGRESS — content leaving toward a model endpoint on a server's initiative
    /// rather than a subject's.
    McpSamplingCreate,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WhoamiView {
    pub peer_plane_uri_san: String,
    pub peer_uid: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Payload {
    Pong,
    Whoami(WhoamiView),
    /// File content for a permitted `Read` — byte-string on the wire,
    /// zeroize-on-drop, redacting Debug (see [`crate::Bytes`]).
    ReadContent(crate::Bytes),
    /// The effective configuration for a permitted `admin.config.show`:
    /// section → (dotted field path → rendered value).
    ///
    /// **Values arrive here ALREADY REDACTED.** The disclosure rule lives in
    /// `maknae_config::effective_view` — deny-by-default over a code-declared
    /// allowlist, three states (disclosed / masked / omitted-entirely) plus a
    /// `<not set>` marker — and this type deliberately carries none of it:
    /// a second redaction implementation on the wire side is a second thing to
    /// drift. Never construct this from raw configuration.
    ConfigView(std::collections::BTreeMap<String, std::collections::BTreeMap<String, String>>),
    /// Runtime posture for a permitted `admin.status`.
    Status(StatusView),
    /// Role bindings for a permitted `admin.subject.list`: role → members, as
    /// the PDP resolves them RIGHT NOW. Never a boot snapshot -- bindings are
    /// re-read per request, so a snapshot would report authorization state the
    /// PDP is no longer using, and disclosing stale authz is worse than none.
    SubjectList(Vec<RoleBindingView>),
    /// Durable policy authorization for a subject-side attempt, never OS approval.
    MutationAttempt(crate::MutationGrant),
    /// An existing-file replacement completed under daemon observation and its
    /// completion record was durably appended. Namespace reports use MutationAck.
    MutationComplete,
    /// The provider's reply to a permitted `session.prompt` (#172): released to
    /// the requesting loop only on the PDP's Permit and after the outcome record
    /// landed. Text only in Cooky; `Unavailable` never produces one.
    PromptReply(PromptReply),
}

/// What `admin.status` discloses. Every field is deployment SHAPE the operator
/// needs to debug with, and none is a credential.
///
/// The wire doc for this verb warns it is "useful to an operator, and useful to
/// an attacker fingerprinting the deployment" -- true, and it is why the term
/// ships UNGRANTED and admin-only. Once an operator has granted it to an admin
/// role, withholding the daemon's own version from them protects nobody: any
/// peer that completed a handshake already knows the protocol version, and the
/// socket path is the one the caller is already connected to.
///
/// NOT "config.show discloses it anyway" — the grants are INDEPENDENT, so a
/// role granted only `admin.status` never gets `config.show` and that argument
/// cannot carry this field. (An earlier note here went further and said
/// `config.show` discloses nothing of the sort on a default deployment. False:
/// `effective_view` folds the RESOLVED default in regardless of the file.)
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StatusView {
    /// The daemon's crate version.
    pub version: String,
    /// The wire protocol version this daemon speaks.
    pub protocol_version: u16,
    /// The listening socket path.
    pub listener: String,
    /// Which authorization backend decided this request (`Authorizer::
    /// backend_name`). An operator debugging a verdict needs to know WHICH
    /// PDP produced it; with the DCS library present this is not `-basic`.
    pub authz_backend: String,
    /// Which classification SYSTEM this enclave operates under
    /// (`core.handling.policy`, ADR-0022): the name the kernel's registry
    /// selected at boot -- `US` unless the operator declared another this
    /// build carries. An operator reading a ceiling refusal needs to know
    /// which ladder ranked it.
    pub classification_policy: String,
}

/// One role and the identities bound to it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RoleBindingView {
    pub role: String,
    pub members: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ProtoErrCode {
    /// Declared for the decode-refusal class and currently EMITTED NOWHERE
    /// (#181, honest-record note 2026-09-02, corrected same day by diff-CR):
    /// the decode-failure path audits the refusal and CLOSES with no response
    /// frame at all (`run.rs`, the decode arm); `BadRequest` is emitted only
    /// by the post-decode lexical pre-gate on `Read`. This variant is dead,
    /// kept additive. A record that claims behaviour that does not occur is
    /// the defect class #181 removed — and the first draft of THIS doc line
    /// did exactly that, claiming the decode path answers `BadRequest`.
    UnknownVerb,
    Unauthorized,
    BadRequest,
    Internal,
    /// A permitted read whose content exceeds the daemon's frame budget —
    /// delivery refused, never truncated (spec D5).
    TooLarge,
    /// An enumerated term the daemon decided and PERMITTED, but whose behaviour
    /// is not built. Returned ONLY after a Permit — a denied caller receives
    /// `Unauthorized` and learns nothing about implementation state (#67 D7).
    /// EMITTED NOWHERE since the 2026-09-02 wire ruling (#181): a permitted
    /// unbuilt term now answers `Unauthorized` like every refusal — build
    /// state is not a wire disclosure on any path. Dead, kept additive, same
    /// honest-record treatment as `UnknownVerb` below.
    NotImplemented,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProtoError {
    pub code: ProtoErrCode,
    pub message: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum RespResult {
    Ok(Payload),
    Err(ProtoError),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Request {
    pub protocol_version: u16,
    pub verb: Verb,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Response {
    pub protocol_version: u16,
    pub result: RespResult,
}

fn enc<T: Serialize>(v: &T) -> Result<Vec<u8>, ProtoCodecError> {
    let mut buf = Vec::new();
    ciborium::into_writer(v, &mut buf).map_err(|e| ProtoCodecError::Encode(e.to_string()))?;
    Ok(buf)
}
pub fn encode_request(r: &Request) -> Result<Vec<u8>, ProtoCodecError> {
    enc(r)
}
/// Encode content-bearing requests without reallocating secret bytes or
/// exceeding the configured frame budget, including the CBOR envelope.
pub fn encode_request_zeroizing(
    r: &Request,
    max_bytes: usize,
) -> Result<zeroize::Zeroizing<Vec<u8>>, ProtoCodecError> {
    let mut buf = zeroize::Zeroizing::new(vec![0; max_bytes]);
    let mut writer = std::io::Cursor::new(buf.as_mut_slice());
    ciborium::into_writer(r, &mut writer).map_err(|e| ProtoCodecError::Encode(e.to_string()))?;
    let len = writer.position() as usize;
    buf.truncate(len);
    Ok(buf)
}
pub fn encode_response(r: &Response) -> Result<Vec<u8>, ProtoCodecError> {
    enc(r)
}
pub fn encode_mutation_report(r: &crate::MutationReport) -> Result<Vec<u8>, ProtoCodecError> {
    enc(r)
}
pub fn encode_mutation_ack(r: &crate::MutationAck) -> Result<Vec<u8>, ProtoCodecError> {
    enc(r)
}

fn decode_followup<T: serde::de::DeserializeOwned>(mut bytes: &[u8]) -> Result<T, ProtoCodecError> {
    let value =
        ciborium::from_reader(&mut bytes).map_err(|e| ProtoCodecError::Decode(e.to_string()))?;
    if !bytes.is_empty() {
        return Err(ProtoCodecError::Decode(
            "trailing mutation frame data".into(),
        ));
    }
    Ok(value)
}
pub fn decode_mutation_report(bytes: &[u8]) -> Result<crate::MutationReport, ProtoCodecError> {
    decode_followup(bytes)
}
pub fn decode_mutation_ack(bytes: &[u8]) -> Result<crate::MutationAck, ProtoCodecError> {
    decode_followup(bytes)
}
/// Encode into a pre-sized zeroizing buffer — the read path's encode (spec
/// D5: zeroization preserved to the wire). Pre-sizing prevents realloc from
/// leaving un-zeroized partial copies of content in freed heap; `capacity`
/// should be the frame budget plus envelope margin. Ping/Whoami keep the
/// plain [`encode_response`].
pub fn encode_response_zeroizing(
    r: &Response,
    capacity: usize,
) -> Result<zeroize::Zeroizing<Vec<u8>>, ProtoCodecError> {
    let mut buf = zeroize::Zeroizing::new(Vec::with_capacity(capacity));
    ciborium::into_writer(r, &mut *buf).map_err(|e| ProtoCodecError::Encode(e.to_string()))?;
    Ok(buf)
}
/// Encode a request into a zeroizing buffer. The codec lives here, with the
/// rest of the wire, so `maknae-kernel` needs no CBOR dependency of its own —
/// a new dependency in the TCB is a security decision, not a convenience.
pub fn encode_egress_frame_request(
    r: &crate::EgressFrameRequest,
) -> Result<zeroize::Zeroizing<Vec<u8>>, ProtoCodecError> {
    let mut buf = zeroize::Zeroizing::new(Vec::new());
    ciborium::into_writer(r, &mut *buf)
        .map_err(|e| ProtoCodecError::Encode(e.to_string()))?;
    Ok(buf)
}

pub fn decode_egress_frame_request(b: &[u8]) -> Result<crate::EgressFrameRequest, ProtoCodecError> {
    ciborium::from_reader(b).map_err(|e| ProtoCodecError::Decode(e.to_string()))
}

pub fn encode_egress_frame_reply(
    r: &crate::EgressFrameReply,
) -> Result<zeroize::Zeroizing<Vec<u8>>, ProtoCodecError> {
    let mut buf = zeroize::Zeroizing::new(Vec::new());
    ciborium::into_writer(r, &mut *buf)
        .map_err(|e| ProtoCodecError::Encode(e.to_string()))?;
    Ok(buf)
}

pub fn decode_egress_frame_reply(b: &[u8]) -> Result<crate::EgressFrameReply, ProtoCodecError> {
    ciborium::from_reader(b).map_err(|e| ProtoCodecError::Decode(e.to_string()))
}

pub fn decode_request(b: &[u8]) -> Result<Request, ProtoCodecError> {
    let r: Request =
        ciborium::from_reader(b).map_err(|e| ProtoCodecError::Decode(e.to_string()))?;
    if r.protocol_version != PROTOCOL_VERSION {
        return Err(ProtoCodecError::UnsupportedVersion(r.protocol_version));
    }
    Ok(r)
}
pub fn decode_response(b: &[u8]) -> Result<Response, ProtoCodecError> {
    let r: Response =
        ciborium::from_reader(b).map_err(|e| ProtoCodecError::Decode(e.to_string()))?;
    if r.protocol_version != PROTOCOL_VERSION {
        return Err(ProtoCodecError::UnsupportedVersion(r.protocol_version));
    }
    Ok(r)
}

#[cfg(test)]
mod tests {
    #[test]
    fn request_secret_encoding_enforces_actual_frame_limit() {
        let request = Request {
            protocol_version: PROTOCOL_VERSION,
            verb: Verb::FsWrite {
                path: "/projects/frame-limit".into(),
                content: crate::Bytes::new(zeroize::Zeroizing::new(vec![0, 255, 17])),
                mode: crate::WriteMode::Existing,
            },
        };
        let expected = encode_request(&request).unwrap();
        let encoded = encode_request_zeroizing(&request, expected.len()).unwrap();
        assert_eq!(&*encoded, &expected);
        assert_eq!(decode_request(&encoded).unwrap(), request);
        assert!(encode_request_zeroizing(&request, expected.len() - 1).is_err());
        assert!(encode_request_zeroizing(&request, 0).is_err());
    }
    use super::*;

    fn text(s: &str) -> ContentBlock {
        ContentBlock::Text {
            text: SecretText(zeroize::Zeroizing::new(s.to_string())),
        }
    }

    #[test]
    fn session_prompt_round_trips_and_debug_redacts_content() {
        let req = Request {
            protocol_version: PROTOCOL_VERSION,
            verb: Verb::SessionPrompt {
                conversation: "conv-1".into(),
                content: vec![text("the secret plan")],
            },
        };
        let bytes = encode_request(&req).unwrap();
        assert_eq!(decode_request(&bytes).unwrap(), req);
        let dbg = format!("{:?}", req.verb);
        assert!(
            !dbg.contains("secret plan"),
            "content leaked through Debug: {dbg}"
        );
        assert!(
            dbg.contains("conv-1") && dbg.contains("<15 bytes>"),
            "{dbg}"
        );
    }

    #[test]
    fn secret_text_is_a_cbor_text_string_not_a_byte_string() {
        // ACP's `text` is a string; a byte-string would make every ACP peer re-encode.
        let mut buf = Vec::new();
        ciborium::into_writer(&SecretText(zeroize::Zeroizing::new("ab".into())), &mut buf).unwrap();
        assert_eq!(buf, [0x62, b'a', b'b'], "major type 3 (text), length 2");
    }

    #[test]
    fn every_acp_content_block_kind_decodes_and_names_itself() {
        let blocks = vec![
            text("t"),
            ContentBlock::Image {
                data: "AA==".into(),
                mime_type: "image/png".into(),
            },
            ContentBlock::Audio {
                data: "AA==".into(),
                mime_type: "audio/wav".into(),
            },
            ContentBlock::Resource {
                uri: "file:///x".into(),
                text: Some(SecretText(zeroize::Zeroizing::new("body".into()))),
            },
            ContentBlock::ResourceLink {
                uri: "https://x".into(),
                name: "x".into(),
            },
        ];
        assert_eq!(
            blocks.iter().map(ContentBlock::kind).collect::<Vec<_>>(),
            ["text", "image", "audio", "resource", "resource_link"]
        );
        let req = Request {
            protocol_version: PROTOCOL_VERSION,
            verb: Verb::SessionPrompt {
                conversation: "c".into(),
                content: blocks,
            },
        };
        let bytes = encode_request(&req).unwrap();
        assert_eq!(decode_request(&bytes).unwrap(), req);
    }

    #[test]
    fn conversation_id_grammar_is_bounded() {
        assert!(conversation_id_is_acceptable("a"));
        assert!(conversation_id_is_acceptable("conv-2026.09.08_x"));
        assert!(conversation_id_is_acceptable(
            &"a".repeat(MAX_CONVERSATION_ID_BYTES)
        ));
        for bad in ["", "has space", "é", "a/b", "a\tb"] {
            assert!(!conversation_id_is_acceptable(bad), "{bad:?}");
        }
        assert!(!conversation_id_is_acceptable(
            &"a".repeat(MAX_CONVERSATION_ID_BYTES + 1)
        ));
    }

    #[test]
    fn prompt_reply_payload_round_trips_and_redacts() {
        let resp = Response {
            protocol_version: PROTOCOL_VERSION,
            result: RespResult::Ok(Payload::PromptReply(PromptReply { tool_calls: vec![],
                blocks: vec![text("hi there")],
            })),
        };
        let bytes = encode_response(&resp).unwrap();
        assert_eq!(decode_response(&bytes).unwrap(), resp);
        assert!(!format!("{resp:?}").contains("hi there"));
    }

    #[test]
    fn the_other_session_verbs_keep_their_unit_encoding_and_the_version_is_one() {
        for (v, name) in [
            (Verb::SessionCancel, &b"SessionCancel"[..]),
            (Verb::SessionUpdate, &b"SessionUpdate"[..]),
        ] {
            let bytes = encode_request(&Request {
                protocol_version: PROTOCOL_VERSION,
                verb: v,
            })
            .unwrap();
            // Unit variants encode as the bare variant-name text string inside the request map.
            assert!(bytes.windows(name.len()).any(|w| w == name));
        }
        assert_eq!(PROTOCOL_VERSION, 1);
    }

    #[test]
    fn an_unknown_verb_name_fails_to_decode() {
        // Spec §6 test 28: an unknown verb is a codec error, refused before any behaviour.
        // NOT red-first: decode_request already refuses an unknown variant; this pins the obligation.
        use ciborium::value::Value;
        let mut buf = Vec::new();
        ciborium::into_writer(
            &Value::Map(vec![
                (
                    Value::Text("protocol_version".into()),
                    Value::Integer(1.into()),
                ),
                (
                    Value::Text("verb".into()),
                    Value::Text("SessionGhost".into()),
                ),
            ]),
            &mut buf,
        )
        .unwrap();
        assert!(decode_request(&buf).is_err());
    }
    #[test]
    fn mutation_operands_round_trip_without_exposing_content_in_debug() {
        let verbs = [
            Verb::FsWrite {
                path: "/home/u/projects/x".into(),
                content: crate::Bytes::new(zeroize::Zeroizing::new(
                    b"private-mutation-158".to_vec(),
                )),
                mode: crate::WriteMode::CreateExclusive,
            },
            Verb::FsDelete {
                path: "/home/u/projects/x".into(),
                recursive: true,
            },
            Verb::FsMkdir {
                path: "/home/u/projects/a/b".into(),
                parents: true,
                components: vec!["a".into(), "b".into()],
            },
        ];
        for verb in verbs {
            assert!(!format!("{verb:?}").contains("private-mutation-158"));
            let req = Request {
                protocol_version: PROTOCOL_VERSION,
                verb,
            };
            assert_eq!(decode_request(&encode_request(&req).unwrap()).unwrap(), req);
        }
    }

    #[test]
    fn mutation_followups_round_trip_and_refuse_trailing_messages() {
        let id = crate::MutationId {
            session_id: 7,
            intent_seq: 2,
        };
        let report = crate::MutationReport::Finished {
            id,
            next_index: 1,
            outcome: crate::ReportedFinish::Success,
            stopped_at: None,
        };
        let bytes = encode_mutation_report(&report).unwrap();
        assert_eq!(decode_mutation_report(&bytes).unwrap(), report);
        let mut doubled = bytes.clone();
        doubled.extend_from_slice(&bytes);
        assert!(decode_mutation_report(&doubled).is_err());
        assert!(decode_mutation_report(&[0xff]).is_err());
        let ack = crate::MutationAck { id, next_index: 1 };
        let mut bytes = encode_mutation_ack(&ack).unwrap();
        assert_eq!(decode_mutation_ack(&bytes).unwrap(), ack);
        bytes.push(0);
        assert!(decode_mutation_ack(&bytes).is_err());
        assert!(decode_mutation_ack(&[0xff]).is_err());
        let grant = Payload::MutationAttempt(crate::MutationGrant {
            id,
            scope: crate::MutationScope::Exact {
                path: "/home/u/projects/x".into(),
                effect: crate::ReportedEffect::CreatedFile,
            },
            limits: crate::MutationLimits {
                max_effects: 1,
                max_depth: 1,
                deadline_ms: 5000,
            },
        });
        for payload in [grant, Payload::MutationComplete] {
            let response = Response {
                protocol_version: PROTOCOL_VERSION,
                result: RespResult::Ok(payload),
            };
            assert_eq!(
                decode_response(&encode_response(&response).unwrap()).unwrap(),
                response
            );
        }
    }

    #[test]
    fn request_round_trips() {
        let r = Request {
            protocol_version: PROTOCOL_VERSION,
            verb: Verb::Whoami,
        };
        let bytes = encode_request(&r).unwrap();
        let back = decode_request(&bytes).unwrap();
        assert_eq!(back.verb, Verb::Whoami);
        assert_eq!(back.protocol_version, PROTOCOL_VERSION);
    }
    #[test]
    fn response_round_trips() {
        let r = Response {
            protocol_version: PROTOCOL_VERSION,
            result: RespResult::Ok(Payload::Whoami(WhoamiView {
                peer_plane_uri_san: "maknae://d/plane/cli".into(),
                peer_uid: 501,
            })),
        };
        let bytes = encode_response(&r).unwrap();
        match decode_response(&bytes).unwrap().result {
            RespResult::Ok(Payload::Whoami(w)) => {
                assert_eq!(w.peer_uid, 501);
            }
            _ => panic!("wrong variant"),
        }
    }
    #[test]
    fn decode_rejects_wrong_version() {
        let mut r = Request {
            protocol_version: 999,
            verb: Verb::Ping,
        };
        let bytes = {
            let mut b = Vec::new();
            ciborium::into_writer(&r, &mut b).unwrap();
            b
        };
        assert!(matches!(
            decode_request(&bytes),
            Err(ProtoCodecError::UnsupportedVersion(999))
        ));
        r.protocol_version = PROTOCOL_VERSION; // silence unused-mut on some toolchains
        let _ = r;
    }
    #[test]
    fn decode_response_rejects_wrong_version() {
        let r = Response {
            protocol_version: 999,
            result: RespResult::Ok(Payload::Pong),
        };
        let bytes = {
            let mut b = Vec::new();
            ciborium::into_writer(&r, &mut b).unwrap();
            b
        };
        assert!(matches!(
            decode_response(&bytes),
            Err(ProtoCodecError::UnsupportedVersion(999))
        ));
    }
    #[test]
    fn decode_rejects_malformed_cbor() {
        assert!(matches!(
            decode_request(&[0xff, 0xff, 0xff]),
            Err(ProtoCodecError::Decode(_))
        ));
    }
    #[test]
    fn decode_response_rejects_malformed_cbor() {
        assert!(matches!(
            decode_response(&[0xff, 0xff, 0xff]),
            Err(ProtoCodecError::Decode(_))
        ));
    }

    /// A type whose `Serialize` impl always errors — the only way to exercise
    /// `enc`'s `Encode` branch, since `ciborium::into_writer` never fails for
    /// this crate's own well-formed types.
    struct AlwaysFailsToSerialize;
    impl Serialize for AlwaysFailsToSerialize {
        fn serialize<S: serde::Serializer>(&self, _s: S) -> Result<S::Ok, S::Error> {
            Err(serde::ser::Error::custom("deliberate test failure"))
        }
    }
    #[test]
    fn enc_surfaces_serialize_failure_as_encode_error() {
        assert!(matches!(
            enc(&AlwaysFailsToSerialize),
            Err(ProtoCodecError::Encode(_))
        ));
    }
    mod v2 {
        use super::super::*;
        use zeroize::Zeroizing;

        #[test]
        fn read_verb_round_trips_with_path() {
            let r = Request {
                protocol_version: PROTOCOL_VERSION,
                verb: Verb::Read {
                    path: "/home/op/notes.txt".into(),
                },
            };
            let back = decode_request(&encode_request(&r).unwrap()).unwrap();
            assert_eq!(
                back.verb,
                Verb::Read {
                    path: "/home/op/notes.txt".into()
                }
            );
        }

        #[test]
        fn read_content_round_trips_bytes() {
            let r = Response {
                protocol_version: PROTOCOL_VERSION,
                result: RespResult::Ok(Payload::ReadContent(crate::Bytes(Zeroizing::new(vec![
                    0xff, 0x00,
                ])))),
            };
            match decode_response(&encode_response(&r).unwrap())
                .unwrap()
                .result
            {
                RespResult::Ok(Payload::ReadContent(b)) => assert_eq!(*b.0, vec![0xff, 0x00]),
                other => panic!("wrong variant: {other:?}"),
            }
        }

        #[test]
        fn too_large_code_round_trips() {
            let r = Response {
                protocol_version: PROTOCOL_VERSION,
                result: RespResult::Err(ProtoError {
                    code: ProtoErrCode::TooLarge,
                    message: "resource too large".into(),
                }),
            };
            match decode_response(&encode_response(&r).unwrap())
                .unwrap()
                .result
            {
                RespResult::Err(e) => assert_eq!(e.code, ProtoErrCode::TooLarge),
                other => panic!("wrong variant: {other:?}"),
            }
        }

        #[test]
        fn adding_read_is_additive_no_version_bump() {
            // #77 stays on wire version 1: PROTOCOL_VERSION is 1, so a pre-#77
            // CLI's Ping (version 1, the unchanged verbs) still decodes on a
            // #77 daemon — no hard break — and the NEW Read verb round-trips at
            // the SAME version.
            assert_eq!(PROTOCOL_VERSION, 1, "no unauthorized wire bump");
            let ping = Request {
                protocol_version: 1,
                verb: Verb::Ping,
            };
            let mut b = Vec::new();
            ciborium::into_writer(&ping, &mut b).unwrap();
            assert_eq!(decode_request(&b).unwrap().verb, Verb::Ping);

            let read = Request {
                protocol_version: 1,
                verb: Verb::Read {
                    path: "/home/op/x".into(),
                },
            };
            let mut b = Vec::new();
            ciborium::into_writer(&read, &mut b).unwrap();
            assert_eq!(
                decode_request(&b).unwrap().verb,
                Verb::Read {
                    path: "/home/op/x".into()
                }
            );
        }

        #[test]
        fn a_genuinely_wrong_version_still_refuses_cleanly() {
            // The version guard still exists for a real mismatch (a future
            // deliberate bump, or garbage) — typed, never a panic.
            let req = Request {
                protocol_version: 999,
                verb: Verb::Ping,
            };
            let mut b = Vec::new();
            ciborium::into_writer(&req, &mut b).unwrap();
            assert!(matches!(
                decode_request(&b),
                Err(ProtoCodecError::UnsupportedVersion(999))
            ));
        }

        #[test]
        fn encode_response_zeroizing_carries_content_and_does_not_grow() {
            let content = vec![0xabu8; 1000];
            let r = Response {
                protocol_version: PROTOCOL_VERSION,
                result: RespResult::Ok(Payload::ReadContent(crate::Bytes(Zeroizing::new(
                    content.clone(),
                )))),
            };
            let cap = 1000 + 1024;
            let buf = encode_response_zeroizing(&r, cap).unwrap();
            // Pre-sizing held: no realloc means capacity is exactly what we asked.
            assert_eq!(
                buf.capacity(),
                cap,
                "encode grew the buffer — realloc leaves un-zeroized copies"
            );
            // And the content actually rides inside.
            let back = decode_response(&buf).unwrap();
            match back.result {
                RespResult::Ok(Payload::ReadContent(b)) => assert_eq!(*b.0, content),
                other => panic!("wrong variant: {other:?}"),
            }
        }
    }

    // ---- #240a Task 1: tool-call proposals ------------------------------
    // RED before ProposedToolCall exists: these do not compile, which is the
    // correct RED for a type that must be introduced.

    /// The disclosure guard. `PromptReply` derives `Debug`, and that is safe
    /// today ONLY because `ContentBlock::Text.text` is `SecretText`.
    /// `bins/maknae/src/cli.rs:493` formats a `Payload::PromptReply(_)` as
    /// `{p:?}` into an operator-visible protocol-error string, so a derived
    /// `Debug` over a plain `String` would print model-proposed tool-call
    /// arguments — which routinely echo prompt content — to the terminal and
    /// the operator's shell history.
    #[test]
    fn a_proposed_tool_call_debug_redacts_its_arguments() {
        let c = ProposedToolCall {
            name: "read_file".into(),
            call_id: "call_1".into(),
            arguments: SecretText(zeroize::Zeroizing::new(
                "{\"path\":\"/etc/maknae/authz.yaml\"}".into(),
            )),
        };
        let rendered = format!("{c:?}");
        assert!(
            !rendered.contains("authz.yaml"),
            "tool-call arguments leaked into Debug: {rendered}"
        );
        assert!(
            rendered.contains("bytes"),
            "expected the <N bytes> redaction, got: {rendered}"
        );
        // The whole reply, as the CLI actually renders it.
        let reply = PromptReply {
            blocks: vec![],
            tool_calls: vec![c],
        };
        assert!(!format!("{reply:?}").contains("authz.yaml"));
    }

    #[test]
    fn a_tool_call_reply_round_trips() {
        let reply = PromptReply {
            blocks: vec![],
            tool_calls: vec![ProposedToolCall {
                name: "read_file".into(),
                call_id: "call_1".into(),
                arguments: SecretText(zeroize::Zeroizing::new("{}".into())),
            }],
        };
        let mut buf = Vec::new();
        ciborium::into_writer(&reply, &mut buf).unwrap();
        let back: PromptReply = ciborium::from_reader(&buf[..]).unwrap();
        assert_eq!(back, reply);
    }

    #[test]
    fn a_tool_call_over_the_arg_bound_is_refused() {
        let c = ProposedToolCall {
            name: "x".into(),
            call_id: "c".into(),
            arguments: SecretText(zeroize::Zeroizing::new(
                "a".repeat(MAX_TOOL_CALL_ARGS_BYTES + 1),
            )),
        };
        assert!(!proposed_tool_call_is_acceptable(&c));
        let ok = ProposedToolCall {
            arguments: SecretText(zeroize::Zeroizing::new("a".repeat(MAX_TOOL_CALL_ARGS_BYTES))),
            ..c
        };
        assert!(proposed_tool_call_is_acceptable(&ok));
    }
}
