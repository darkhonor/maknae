//! The `maknaed` ↔ `maknae-egress` socket frames (#240a).
//!
//! The kernel resolves `provider:<name>` and puts the RESOLVED record on the
//! frame (#240a D1): egress parses no provider registry and therefore cannot
//! drift from the kernel's view of it. One parser, one source of truth — the
//! failure that created `maknae-io` was each site re-implementing the checks.
//!
//! `destination` rides on EVERY request and is never process-global (#240a
//! I1). The kernel already computes it per request, and per-request selection
//! is what lets several providers — and several per-user endpoints — work
//! without reshaping anything here.
//!
//! There is deliberately NO `delegated_from` field. Request origin has no
//! carrier today (ADR-0024) and #241 owns closing that; a slot for an unbuilt
//! mechanism is the ADR-0023 failure.

use serde::{Deserialize, Serialize};

/// What the kernel hands the egress deputy for one decided `session.prompt`.
///
/// `Debug` is hand-written: it must reproduce neither the prompt content, nor
/// `key_vault_path`, nor the sealed key's bytes. `destination` IS shown — it is
/// the audit-correlation handle and appears in records already.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EgressFrameRequest {
    /// `provider:<name>`, per request, never process-global (#240a I1).
    pub destination: String,
    /// The resolved OpenAI-compatible base URL.
    pub endpoint: String,
    /// The resolved model identifier.
    pub model: String,
    /// The KV v2 secret path holding this provider's key, **RELATIVE to the
    /// mount the deputy has in its own `egress-bounds.yaml`** and without the
    /// `data/` segment (#308). The deputy validates it against its configured
    /// prefix and then composes `<mount>/data/<path>` itself — so the mount is
    /// never on the wire, and the KV v2 API artifact appears in no
    /// configuration file.
    pub key_vault_path: String,
    /// The field name inside that secret (#308). **Per request, not a deputy
    /// constant**, for the same reason `destination` is: two providers may
    /// store their keys under different field names, and a constant fails the
    /// moment there are two. Before #308 the only field name in the tree was a
    /// test fixture's `api_key`.
    pub key_field: String,
    pub sealed_key: crate::SealedKey,
    /// The provider's reasoning level, when the registry sets one (#242).
    /// Absent is omitted from the encoding, so a frame without it decodes as
    /// `None`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reasoning_effort: Option<String>,
    /// The kernel's `egress.deadline_ms`, so the deputy can refuse a call it could not finish in time.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub deadline_ms: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub output_tokens: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub output_tokens_field: Option<OutputTokensField>,
    /// The loop's identifier (#241). Informational, never decided on.
    pub conversation: String,
    /// The transcript leaving the trust plane (#241). Roles per `crate::Turn`;
    /// there is no `System` variant, so the trusted preamble the deputy
    /// prepends is the only system message.
    pub turns: Vec<crate::Turn>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OutputTokensField {
    MaxCompletionTokens,
    MaxTokens,
}

impl std::fmt::Debug for EgressFrameRequest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // `<N turns>` is pluralised unconditionally, so a one-turn frame
        // prints `<1 turns>`. Deliberate, not an oversight: this is a
        // redaction marker in a `{:?}`, and the plural-only form is what keeps
        // the pinned literal in the test below a single exact string. A
        // singular branch would buy grammar in a debug line at the cost of a
        // second expected text to pin.
        f.debug_struct("EgressFrameRequest")
            .field("destination", &self.destination)
            .field("endpoint", &self.endpoint)
            .field("model", &self.model)
            .field("key_vault_path", &"<omitted>")
            // Omitted for the same reason as the path: a field NAME is not a
            // secret, but together with the path it describes exactly where a
            // credential is kept, and nothing needs it in a log line.
            .field("key_field", &"<omitted>")
            .field("sealed_key", &self.sealed_key)
            .field("reasoning_effort", &self.reasoning_effort)
            .field("output_tokens", &self.output_tokens)
            .field("output_tokens_field", &self.output_tokens_field)
            .field("conversation", &self.conversation)
            .field("turns", &format_args!("<{} turns>", self.turns.len()))
            .finish()
    }
}

/// The deputy's answer to a prompt frame: the provider's reply, or why it is unusable.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EgressFrameReply {
    Reply(crate::PromptReply),
    Unusable {
        defect: crate::ReplyDefect,
        usage: Option<crate::Usage>,
    },
}

/// One frame on the kernel → deputy socket.
#[derive(Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EgressFrame {
    Prompt(EgressFrameRequest),
    Mint(MintRequest),
    Revoke(RevokeRequest),
    Reach(ReachRequest),
}

/// One reply on the deputy → kernel socket.
#[derive(Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EgressSocketReply {
    Prompt(EgressFrameReply),
    Mint(MintReply),
    Revoke(RevokeReply),
    Reach(ReachReply),
    /// The deputy had no free slot: the frame was read and discarded, and nothing left the host.
    AtCapacity,
    /// Refused before any provider or forge I/O.
    RefusedBeforeSend,
}

pub const MINT_MAX_SETS: usize = 8;
pub const MINT_MAX_REPOS_PER_SET: usize = 50;
pub const MINT_MAX_PERMISSIONS_PER_SET: usize = 6;

/// A request to mint one credential per permission set for a task's agent.
///
/// `kind` is `maknae_config::CredentialKind`'s spelling: this crate does not depend on
/// `maknae-config`.
#[derive(PartialEq, Eq, Serialize, Deserialize)]
pub struct MintRequest {
    pub task: String,
    pub agent: String,
    pub class: String,
    pub kind: String,
    pub app: String,
    pub sets: Vec<PermissionSet>,
}

impl std::fmt::Debug for MintRequest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MintRequest")
            .field("task", &self.task)
            .field("agent", &self.agent)
            .field("class", &self.class)
            .field("kind", &self.kind)
            .field("app", &self.app)
            .field("sets", &format_args!("<{} sets>", self.sets.len()))
            .finish()
    }
}

#[derive(Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PermissionSet {
    pub repositories: Vec<String>,
    #[serde(deserialize_with = "permissions_without_duplicates")]
    pub permissions: std::collections::BTreeMap<GithubPermission, AccessLevel>,
}

fn permissions_without_duplicates<'de, D: serde::Deserializer<'de>>(
    d: D,
) -> Result<std::collections::BTreeMap<GithubPermission, AccessLevel>, D::Error> {
    struct V;
    impl<'de> serde::de::Visitor<'de> for V {
        type Value = std::collections::BTreeMap<GithubPermission, AccessLevel>;
        fn expecting(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
            f.write_str("a map of GitHub permissions, each named once")
        }
        fn visit_map<A: serde::de::MapAccess<'de>>(
            self,
            mut m: A,
        ) -> Result<Self::Value, A::Error> {
            let mut out = std::collections::BTreeMap::new();
            while let Some((k, v)) = m.next_entry::<GithubPermission, AccessLevel>()? {
                if out.insert(k, v).is_some() {
                    return Err(serde::de::Error::custom(format_args!(
                        "duplicate permission {}",
                        k.as_str()
                    )));
                }
            }
            Ok(out)
        }
    }
    d.deserialize_map(V)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GithubPermission {
    Contents,
    PullRequests,
    Issues,
    Checks,
    Statuses,
    Metadata,
}

impl GithubPermission {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Contents => "contents",
            Self::PullRequests => "pull_requests",
            Self::Issues => "issues",
            Self::Checks => "checks",
            Self::Statuses => "statuses",
            Self::Metadata => "metadata",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AccessLevel {
    Read,
    Write,
}

#[derive(PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MintReply {
    Minted(Vec<SealedCredential>),
    Refused(MintRefusal),
}

impl std::fmt::Debug for MintReply {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Minted(c) => write!(f, "Minted(<{} credentials>)", c.len()),
            Self::Refused(r) => f.debug_tuple("Refused").field(r).finish(),
        }
    }
}

/// One minted credential: `for_agent` sealed to the agent, `for_revocation` to the deputy.
#[derive(PartialEq, Eq, Serialize, Deserialize)]
pub struct SealedCredential {
    pub set: u8,
    pub expires_at: String,
    pub for_agent: crate::SealedCredentialBytes,
    pub for_revocation: crate::SealedCredentialBytes,
}

impl std::fmt::Debug for SealedCredential {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SealedCredential")
            .field("set", &self.set)
            .field("expires_at", &self.expires_at)
            .field("for_agent", &self.for_agent)
            .field("for_revocation", &self.for_revocation)
            .finish()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MintRefusal {
    Request,
    Signer,
    Forge(ForgeStatus),
    Mismatch,
    Recipient,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ForgeStatus {
    Unauthorized,
    Forbidden,
    NotFound,
    Unprocessable,
    Other,
}

#[derive(PartialEq, Eq, Serialize, Deserialize)]
pub struct RevokeRequest {
    pub task: String,
    pub agent: String,
    pub class: String,
    pub kind: String,
    pub app: String,
    pub set: u8,
    pub for_revocation: crate::SealedCredentialBytes,
}

impl std::fmt::Debug for RevokeRequest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RevokeRequest")
            .field("task", &self.task)
            .field("agent", &self.agent)
            .field("class", &self.class)
            .field("kind", &self.kind)
            .field("app", &self.app)
            .field("set", &self.set)
            .field("for_revocation", &self.for_revocation)
            .finish()
    }
}

#[derive(Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RevokeReply {
    Revoked,
    AlreadyGone,
    Refused(MintRefusal),
}

pub const REACH_ASKS_MAX: usize = 8;
pub const REACH_CREDENTIALS_MAX: usize = 8;
/// The most any text field of a reach frame may be, its seal's AAD field bound.
pub const REACH_FIELD_MAX_BYTES: usize = 1024;

/// One binding's repositories, asked of one side. `head` is the change's head repository when known.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RepoAsk {
    pub base: String,
    pub change: Option<u64>,
    pub head: Option<String>,
}

/// An agent's forge credential, as `maknae_config::CredentialKind`'s spelling and its entry's name.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CredentialRef {
    pub kind: String,
    pub name: String,
}

/// Whose reach a frame observes: the tasker's, through their sealed token, or the agent's.
#[derive(PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum ReachSide {
    Tasker {
        tasker: String,
        expected_path: String,
        key_field: String,
        nonce: String,
        sealed: crate::SealedKey,
    },
    Agent {
        agent: String,
        credentials: Vec<CredentialRef>,
    },
}

impl std::fmt::Debug for ReachSide {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Tasker {
                tasker,
                expected_path: _,
                key_field: _,
                nonce: _,
                sealed,
            } => f
                .debug_struct("Tasker")
                .field("tasker", tasker)
                .field("expected_path", &"<omitted>")
                .field("key_field", &"<omitted>")
                .field("nonce", &"<omitted>")
                .field("sealed", sealed)
                .finish(),
            Self::Agent { agent, credentials } => f
                .debug_struct("Agent")
                .field("agent", agent)
                .field("credentials", credentials)
                .finish(),
        }
    }
}

/// A request to observe one side's reach on `server` for 1..=[`REACH_ASKS_MAX`] bindings.
#[derive(PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, try_from = "ReachRequestWire")]
pub struct ReachRequest {
    server: String,
    provider: String,
    deadline_ms: u64,
    side: ReachSide,
    asks: Vec<RepoAsk>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ReachRequestWire {
    server: String,
    provider: String,
    deadline_ms: u64,
    side: ReachSide,
    asks: Vec<RepoAsk>,
}

impl TryFrom<ReachRequestWire> for ReachRequest {
    type Error = crate::ProtoCodecError;
    fn try_from(w: ReachRequestWire) -> Result<Self, crate::ProtoCodecError> {
        Self::new(w.server, w.provider, w.deadline_ms, w.side, w.asks)
    }
}

fn reach_text_is_acceptable(s: &str) -> bool {
    !s.is_empty() && s.len() <= REACH_FIELD_MAX_BYTES
}

fn reach_request_refusal(
    server: &str,
    provider: &str,
    deadline_ms: u64,
    side: &ReachSide,
    asks: &[RepoAsk],
) -> Result<(), &'static str> {
    if !crate::server_is_acceptable(server) {
        return Err("reach `server` is not a lowercase host[:port]");
    }
    if !reach_text_is_acceptable(provider) {
        return Err("reach `provider` is empty or too long");
    }
    if deadline_ms == 0 {
        return Err("reach `deadline_ms` is zero");
    }
    if !(1..=REACH_ASKS_MAX).contains(&asks.len()) {
        return Err("reach `asks` is not 1..=8 entries");
    }
    if asks.iter().enumerate().any(|(i, a)| asks[..i].contains(a)) {
        return Err("a duplicate reach ask");
    }
    let path = crate::repository_path_is_acceptable;
    if asks.iter().any(|a| {
        !path(&a.base) || a.head.as_deref().is_some_and(|h| !path(h)) || a.change == Some(0)
    }) {
        return Err("a reach ask is not a repository path and positive change");
    }
    match side {
        ReachSide::Tasker {
            tasker,
            expected_path,
            key_field,
            nonce,
            sealed: _,
        } => {
            if ![tasker, expected_path, key_field]
                .iter()
                .all(|s| reach_text_is_acceptable(s))
            {
                return Err("a reach tasker field is empty or too long");
            }
            if !crate::sealed::forge_nonce_is_acceptable(nonce) {
                return Err("reach `nonce` is not 32 lowercase hex digits");
            }
        }
        ReachSide::Agent { agent, credentials } => {
            if !reach_text_is_acceptable(agent) {
                return Err("reach `agent` is empty or too long");
            }
            if !(1..=REACH_CREDENTIALS_MAX).contains(&credentials.len()) {
                return Err("reach `credentials` is not 1..=8 entries");
            }
            if credentials
                .iter()
                .any(|c| !reach_text_is_acceptable(&c.kind) || !reach_text_is_acceptable(&c.name))
            {
                return Err("a reach credential field is empty or too long");
            }
            if credentials
                .iter()
                .enumerate()
                .any(|(i, c)| credentials[..i].contains(c))
            {
                return Err("a duplicate reach credential");
            }
        }
    }
    Ok(())
}

impl ReachRequest {
    pub fn new(
        server: String,
        provider: String,
        deadline_ms: u64,
        side: ReachSide,
        asks: Vec<RepoAsk>,
    ) -> Result<Self, crate::ProtoCodecError> {
        reach_request_refusal(&server, &provider, deadline_ms, &side, &asks)
            .map_err(|why| crate::ProtoCodecError::Encode(why.into()))?;
        Ok(Self {
            server,
            provider,
            deadline_ms,
            side,
            asks,
        })
    }

    pub fn server(&self) -> &str {
        &self.server
    }

    pub fn provider(&self) -> &str {
        &self.provider
    }

    pub fn deadline_ms(&self) -> u64 {
        self.deadline_ms
    }

    pub fn side(&self) -> &ReachSide {
        &self.side
    }

    pub fn asks(&self) -> &[RepoAsk] {
        &self.asks
    }
}

impl std::fmt::Debug for ReachRequest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ReachRequest")
            .field("server", &self.server)
            .field("provider", &self.provider)
            .field("deadline_ms", &self.deadline_ms)
            .field("side", &self.side)
            .field("asks", &self.asks)
            .finish()
    }
}

/// What one side was observed able to do for one ask, index-aligned with the request's asks.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, try_from = "RepoObservationWire")]
pub struct RepoObservation {
    base: crate::ForgeOps,
    head_path: Option<String>,
    head: crate::ForgeOps,
    head_gone: bool,
    covered: bool,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RepoObservationWire {
    base: crate::ForgeOps,
    head_path: Option<String>,
    head: crate::ForgeOps,
    head_gone: bool,
    covered: bool,
}

impl TryFrom<RepoObservationWire> for RepoObservation {
    type Error = crate::ProtoCodecError;
    fn try_from(w: RepoObservationWire) -> Result<Self, crate::ProtoCodecError> {
        Self::new(w.base, w.head_path, w.head, w.head_gone, w.covered)
    }
}

impl RepoObservation {
    pub fn new(
        base: crate::ForgeOps,
        head_path: Option<String>,
        head: crate::ForgeOps,
        head_gone: bool,
        covered: bool,
    ) -> Result<Self, crate::ProtoCodecError> {
        let refuse = |why: &str| Err(crate::ProtoCodecError::Encode(why.into()));
        if base.contains(crate::ForgeOp::PushHead) {
            return refuse("an observation's base ops hold `PushHead`");
        }
        if head_path
            .as_deref()
            .is_some_and(|h| !crate::repository_path_is_acceptable(h))
        {
            return refuse("an observation's `head_path` is not a repository path");
        }
        if head_path.is_none() && !head.is_empty() {
            return refuse("an observation has head ops without a `head_path`");
        }
        if head_gone && head_path.is_some() {
            return refuse("an observation's head is both gone and named");
        }
        Ok(Self {
            base,
            head_path,
            head,
            head_gone,
            covered,
        })
    }

    pub fn base(&self) -> crate::ForgeOps {
        self.base
    }

    pub fn head_path(&self) -> Option<&str> {
        self.head_path.as_deref()
    }

    pub fn head(&self) -> crate::ForgeOps {
        self.head
    }

    pub fn head_gone(&self) -> bool {
        self.head_gone
    }

    pub fn covered(&self) -> bool {
        self.covered
    }
}

/// 1..=[`REACH_ASKS_MAX`] observations, checked at construction and at decode.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(transparent)]
pub struct Observations(Vec<RepoObservation>);

impl Observations {
    pub fn new(list: Vec<RepoObservation>) -> Result<Self, crate::ProtoCodecError> {
        if !(1..=REACH_ASKS_MAX).contains(&list.len()) {
            return Err(crate::ProtoCodecError::Encode(format!(
                "reach observations are not 1..={REACH_ASKS_MAX} entries"
            )));
        }
        Ok(Self(list))
    }

    pub fn as_slice(&self) -> &[RepoObservation] {
        &self.0
    }
}

impl<'de> Deserialize<'de> for Observations {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        Self::new(Vec::deserialize(d)?).map_err(serde::de::Error::custom)
    }
}

#[derive(Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReachReply {
    Observed(Observations),
    NoForgeCredential,
    Refused(ReachRefusal),
}

/// Why a reach frame was refused. Closed: a new class is a new variant and a wire change.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReachRefusal {
    Request,
    Seal,
    Login,
    NotFound,
    Unauthorized,
    Forbidden,
    Moved,
    Upstream,
    Unanswered,
    Shape,
    Suspended,
    AmbiguousCredential,
    Signer,
}

/// The largest request frame that crosses the kernel→deputy socket, stated
/// ONCE for both ends (#240, review round 4): the kernel refuses to WRITE a
/// larger one (a pre-send failure, so the trail says nothing left), and the
/// deputy refuses to READ one (checked against the declared length before
/// any allocation). Two copies of `1024 * 1024` drifted apart in review.
pub const EGRESS_REQUEST_FRAME_MAX_BYTES: usize = 16_842_752;

/// The fixed buffer a request frame is encoded INTO when the caller has not
/// measured the frame itself: allocated once, written once, never grown
/// (#241, codex round 1 critical 3). The encoder began at
/// `Zeroizing<Vec::new()>` and grew, and every realloc frees a partly-written
/// buffer while `Zeroizing` wipes only the allocation that survives to the
/// drop — measured 18850 bytes of capacity for an 18434-byte frame, so a
/// dozen intermediate buffers each holding a prefix of the content. Harmless
/// while a frame was one short prompt; not harmless once a step's `Tool` turns
/// carry kernel-served file content, which is what the runtime loop routes
/// through here.
///
/// **It is the cap EXACTLY.** *(Corrected 2026-09-22, codex round 2 item C:
/// this was the cap plus one page, `1_052_672`, and the page was there so an
/// over-cap frame would meet the KERNEL's operator-readable cap refusal rather
/// than dying inside the encoder. That worked only within the page: a frame
/// further over the cap — 2 MiB over, say — still died in the encoder as
/// `failed to write whole buffer`, with no size, no cap and no operator line.
/// Measured and observed RED. The kernel now calls
/// [`crate::egress_frame_encoded_len`] BEFORE it allocates, so its own
/// refusal is what every over-cap size meets and the headroom has nothing left
/// to protect.)*
///
/// The production caller no longer uses this const at all — it passes the
/// measured length. It remains as the bound for a caller that cannot measure
/// first, and the cap is the only defensible value for one: a buffer larger
/// than the cap can only produce a frame nobody may send.
pub const EGRESS_REQUEST_FRAME_ENCODE_BYTES: usize = EGRESS_REQUEST_FRAME_MAX_BYTES;

/// The largest reply frame that crosses the deputy→kernel socket, stated ONCE
/// for both ends: the kernel refuses to READ a larger one (checked against the
/// declared length before any allocation, `maknae-kernel`'s
/// `EGRESS_MAX_REPLY_FRAME_BYTES`, which aliases this const so the two cannot
/// drift). Mirrors [`EGRESS_REQUEST_FRAME_MAX_BYTES`] on the other leg.
pub const EGRESS_REPLY_FRAME_MAX_BYTES: usize = 1024 * 1024;

/// The fixed buffer a reply frame is encoded INTO: allocated once, written
/// once, never grown (#241, codex round 2 item B). The reply encoder began at
/// `Zeroizing<Vec::new()>` and grew, and every realloc frees a partly-written
/// buffer while `Zeroizing` wipes only the allocation that survives to the
/// drop. The reply is not just provider prose: `ContentBlock::Text.text` is
/// `SecretText` because a model that read a file quotes that content straight
/// back, so the same finding the request encoder carried applies here.
///
/// The cap PLUS one page, for the reason [`EGRESS_REQUEST_FRAME_ENCODE_BYTES`]
/// gave before its counting pass removed the need there — and which still
/// holds on this leg, because the reply's cap is refused by the KERNEL, on the
/// declared length, with its own operator-readable message
/// (`deputy declared a N-byte reply frame over the M-byte cap`). Sized at
/// exactly the cap this buffer would shadow that refusal: a marginally-over
/// reply would die inside the deputy's encoder and the kernel's branch would
/// answer only a lying length prefix. One page of headroom keeps the kernel's
/// refusal the one a marginally-over reply meets; a reply past the headroom is
/// a [`crate::ProtoCodecError::Encode`] in the deputy, before a byte is
/// written, so nothing fails open either way.
///
/// Written OUT rather than as `EGRESS_REPLY_FRAME_MAX_BYTES + 4096`, which is
/// what it is, for the measurement the request const records: `cargo mutants`
/// replaces that `+` with `*`, and a 4 GiB `vec![0; …]` in the encoder times
/// the whole test binary out instead of failing an assertion. The relation to
/// the cap is pinned in the tests below, where no mutation reaches.
pub const EGRESS_REPLY_FRAME_ENCODE_BYTES: usize = 1_052_672;

/// Shape admission for a whole frame. The
/// only production caller is the DEPUTY — `maknae-egress`'s `handle::decide`,
/// before it will act on a decoded frame. The kernel does not call this: it
/// applies the subset piecemeal on the prompt leg (`turn_is_acceptable` per
/// turn, in
/// `maknae-kernel`'s `egress`), because it composes the frame rather than
/// receiving one. Deliberately shape-only either way: whether this subject may
/// reach this destination was decided by the PDP long before the frame
/// existed.
pub fn egress_frame_request_is_acceptable(r: &EgressFrameRequest) -> bool {
    crate::conversation_id_is_acceptable(&r.conversation)
        && !r.destination.is_empty()
        && !r.endpoint.is_empty()
        && !r.model.is_empty()
        && !r.key_vault_path.is_empty()
        && !r.key_field.is_empty()
        && r.reasoning_effort.as_deref().is_none_or(|e| !e.is_empty())
        && r.output_tokens
            .is_none_or(crate::output_tokens_is_acceptable)
        && (r.output_tokens_field.is_none() || r.output_tokens.is_some())
        && !r.turns.is_empty()
        && r.turns.iter().all(crate::turn_is_acceptable)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::SealedCredentialBytes;
    use std::collections::BTreeMap;
    use zeroize::Zeroizing;

    #[test]
    fn an_unusable_reply_round_trips_with_and_without_usage() {
        for usage in [
            None,
            Some(crate::Usage {
                prompt_tokens: 7,
                completion_tokens: Some(3),
            }),
        ] {
            for defect in crate::ReplyDefect::ALL {
                let r = EgressSocketReply::Prompt(EgressFrameReply::Unusable { defect, usage });
                let buf =
                    crate::encode_egress_socket_reply(&r, EGRESS_REPLY_FRAME_ENCODE_BYTES).unwrap();
                assert_eq!(crate::decode_egress_socket_reply(&buf).unwrap(), r);
            }
        }
    }

    /// By VALUE: a mutant turning `1024 * 1024` into 2048 or 1 survives every
    /// symbolic use on both ends.
    #[test]
    fn the_request_frame_cap_is_sixteen_mebibytes_and_a_margin_by_value() {
        assert_eq!(EGRESS_REQUEST_FRAME_MAX_BYTES, 16_842_752);
        assert_eq!(EGRESS_REQUEST_FRAME_MAX_BYTES, 16 * 1024 * 1024 + 64 * 1024);
        // By VALUE too, and its relation to the cap stated separately
        // (corrected 2026-09-22, codex round 2 item C: this asserted the cap
        // plus one page, and the page is gone — the kernel measures the frame
        // before it allocates, so no headroom is needed to keep the kernel's
        // own cap refusal from being shadowed by an encoder overflow).
        assert_eq!(EGRESS_REQUEST_FRAME_ENCODE_BYTES, 16_842_752);
        assert_eq!(
            EGRESS_REQUEST_FRAME_ENCODE_BYTES, EGRESS_REQUEST_FRAME_MAX_BYTES,
            "a buffer larger than the cap can only produce a frame nobody may send"
        );
    }

    /// The reply's bound, pinned by the SAME three relations as the request's
    /// above and for the same reasons: by value, as the cap plus one page, and
    /// by the difference. The kernel's own `EGRESS_MAX_REPLY_FRAME_BYTES` IS
    /// this cap (it aliases this const), so the two ends cannot drift.
    #[test]
    fn the_reply_frame_cap_is_one_mebibyte_by_value() {
        assert_eq!(EGRESS_REPLY_FRAME_MAX_BYTES, 1_048_576);
        assert_eq!(EGRESS_REPLY_FRAME_ENCODE_BYTES, 1_048_576 + 4096);
        assert_eq!(
            EGRESS_REPLY_FRAME_ENCODE_BYTES,
            EGRESS_REPLY_FRAME_MAX_BYTES + 4096,
            "the encode buffer IS the cap plus one page; the const is spelled out, so this is what ties the two together"
        );
        assert_eq!(
            EGRESS_REPLY_FRAME_ENCODE_BYTES - EGRESS_REPLY_FRAME_MAX_BYTES,
            4096,
            "one page of headroom, so the KERNEL's named reply-cap refusal is what a marginally-over reply meets"
        );
    }

    fn text(s: &str) -> crate::ContentBlock {
        crate::ContentBlock::Text {
            text: crate::SecretText(Zeroizing::new(s.into())),
        }
    }

    fn req(conversation: &str, turns: Vec<crate::Turn>) -> EgressFrameRequest {
        EgressFrameRequest {
            deadline_ms: None,
            destination: "provider:openai".into(),
            endpoint: "https://api.example.test/v1".into(),
            model: "some-model".into(),
            key_vault_path: "maknae/providers/openai".into(),
            key_field: "api-key".into(),
            sealed_key: crate::SealedKey::new(vec![0x5a; crate::SEALED_KEY_MIN_BYTES]).unwrap(),
            reasoning_effort: None,
            conversation: conversation.into(),
            turns,
            output_tokens: None,
            output_tokens_field: None,
        }
    }

    /// The frame carries prompt content out of the trust plane. Its `Debug`
    /// must not reproduce it — nor the Vault path that names where the
    /// provider credential lives.
    #[test]
    fn an_egress_frame_debug_redacts_prompt_content_and_the_key_path() {
        let r = req(
            "conv1",
            vec![crate::Turn::User {
                content: vec![text("the president flies at 0300")],
            }],
        );
        let d = format!("{r:?}");
        assert!(!d.contains("0300"), "prompt content leaked: {d}");
        assert!(!d.contains("secret/data"), "key path leaked: {d}");
        assert!(
            d.contains("provider:openai"),
            "destination should be visible: {d}"
        );
        assert!(
            d.contains("<1 turns>"),
            "the turn count should be shown: {d}"
        );
        assert!(
            d.contains(&format!(
                "SealedKey(<{} bytes>)",
                crate::SEALED_KEY_MIN_BYTES
            )),
            "the sealed key shows only its length: {d}"
        );
        assert!(!d.contains("90, 90"), "sealed bytes leaked: {d}");
    }

    #[test]
    fn a_frame_round_trips() {
        let r = req(
            "conv1",
            vec![crate::Turn::User {
                content: vec![text("hello")],
            }],
        );
        let mut buf = Vec::new();
        ciborium::into_writer(&r, &mut buf).unwrap();
        let back: EgressFrameRequest = ciborium::from_reader(&buf[..]).unwrap();
        assert_eq!(back, r);
    }

    /// Shape admission is the DEPUTY's — `handle::decide` is its only
    /// production caller, and it runs before the deputy writes anything to the
    /// provider. `conversation` reuses the existing bound rather than
    /// inventing a second one.
    #[test]
    fn an_over_long_conversation_is_refused() {
        let ok = req(
            &"a".repeat(crate::MAX_CONVERSATION_ID_BYTES),
            vec![crate::Turn::User {
                content: vec![text("x")],
            }],
        );
        assert!(egress_frame_request_is_acceptable(&ok));
        let bad = req(
            &"a".repeat(crate::MAX_CONVERSATION_ID_BYTES + 1),
            vec![crate::Turn::User {
                content: vec![text("x")],
            }],
        );
        assert!(!egress_frame_request_is_acceptable(&bad));
    }

    #[test]
    fn the_reply_cap_and_its_field_round_trip_and_a_field_without_a_cap_is_malformed() {
        let mut r = req(
            "conv1",
            vec![crate::Turn::User {
                content: vec![text("x")],
            }],
        );
        r.output_tokens = Some(8);
        r.output_tokens_field = Some(OutputTokensField::MaxTokens);
        assert!(egress_frame_request_is_acceptable(&r));
        let mut buf = Vec::new();
        ciborium::into_writer(&r, &mut buf).unwrap();
        let back: EgressFrameRequest = ciborium::from_reader(&buf[..]).unwrap();
        assert_eq!(
            (back.output_tokens, back.output_tokens_field),
            (Some(8), Some(OutputTokensField::MaxTokens))
        );
        r.output_tokens = None;
        assert!(!egress_frame_request_is_acceptable(&r));
        r.output_tokens = Some(0);
        r.output_tokens_field = None;
        assert!(!egress_frame_request_is_acceptable(&r));
    }

    #[test]
    fn reasoning_effort_round_trips_is_omitted_when_absent_and_must_be_non_empty() {
        let mut r = req(
            "conv1",
            vec![crate::Turn::User {
                content: vec![text("x")],
            }],
        );
        let mut absent = Vec::new();
        ciborium::into_writer(&r, &mut absent).unwrap();
        let v: ciborium::Value = ciborium::from_reader(&absent[..]).unwrap();
        let keys: Vec<_> = v
            .as_map()
            .unwrap()
            .iter()
            .filter_map(|(k, _)| k.as_text())
            .collect();
        assert!(!keys.contains(&"reasoning_effort"), "{keys:?}");
        r.reasoning_effort = Some("none".into());
        assert!(egress_frame_request_is_acceptable(&r));
        let mut buf = Vec::new();
        ciborium::into_writer(&r, &mut buf).unwrap();
        let back: EgressFrameRequest = ciborium::from_reader(&buf[..]).unwrap();
        assert_eq!(back.reasoning_effort.as_deref(), Some("none"));
        let old: EgressFrameRequest = ciborium::from_reader(&absent[..]).unwrap();
        assert_eq!(old.reasoning_effort, None);
        r.reasoning_effort = Some(String::new());
        assert!(!egress_frame_request_is_acceptable(&r));
    }

    #[test]
    fn an_empty_turns_frame_is_refused() {
        assert!(!egress_frame_request_is_acceptable(&req("conv1", vec![])));
    }

    /// The new `all(turn_is_acceptable)` conjunct, on its own. Every other
    /// `req()` site carries only `User` turns, which always pass shape
    /// admission, and cargo-mutants emits no operator on the `all(..)`
    /// sub-expression — so without this row the conjunct could be deleted with
    /// the suite green (AGENTS.md principle 5).
    #[test]
    fn a_frame_whose_turn_fails_shape_admission_is_refused() {
        let over = crate::ProposedToolCall {
            name: "read_file".into(),
            call_id: "c1".into(),
            arguments: crate::SecretText(zeroize::Zeroizing::new(
                "a".repeat(crate::MAX_TOOL_CALL_ARGS_BYTES + 1),
            )),
            refused: None,
        };
        let mut r = req(
            "conv1",
            vec![crate::Turn::User {
                content: vec![text("q")],
            }],
        );
        r.turns.push(crate::Turn::Assistant {
            reasoning: None,
            content: vec![],
            tool_calls: vec![over],
        });
        assert!(!egress_frame_request_is_acceptable(&r));
    }

    /// codex round 1, critical 3. The request encoder began at
    /// `Zeroizing<Vec::new()>` and GREW: every realloc frees a partly-written
    /// buffer, and `Zeroizing` wipes only the allocation that survives to the
    /// drop. Harmless while a frame was one short prompt; not harmless once a
    /// step's `Tool` turns carry kernel-served file content, which is exactly
    /// what the runtime loop routes through here. One fixed preallocation, no
    /// growth, and the bytes on the wire unchanged.
    #[test]
    fn the_request_encoder_writes_one_preallocation_and_never_grows() {
        // Two results in one step, each over 8 KiB — the trace codex gave.
        let big = "x".repeat(9 * 1024);
        let r = EgressFrame::Prompt(req(
            "conv1",
            vec![
                crate::Turn::Tool {
                    call_id: "c1".into(),
                    content: vec![text(&big)],
                },
                crate::Turn::Tool {
                    call_id: "c2".into(),
                    content: vec![text(&big)],
                },
            ],
        ));
        let buf = crate::encode_egress_frame(&r, EGRESS_REQUEST_FRAME_ENCODE_BYTES).unwrap();
        // Byte-identical to what the growing encoder produced: this is a
        // buffer change, not a wire change.
        let mut reference = Vec::new();
        ciborium::into_writer(&r, &mut reference).unwrap();
        assert_eq!(&buf[..], &reference[..]);
        assert!(
            buf.len() > 18 * 1024,
            "both results must be in there: {}",
            buf.len()
        );
        // The ONE allocation it was given, still — a grown buffer reports the
        // doubling sequence it climbed, never the preallocation.
        assert_eq!(buf.capacity(), EGRESS_REQUEST_FRAME_ENCODE_BYTES);
        // The bound is enforced, not decorative: one byte short of what the
        // frame needs is the codec's own error, never a silent realloc. The
        // exact length is the discriminator — it is the largest bound that
        // fails under a `<`-shaped mutant and the smallest that succeeds.
        assert!(matches!(
            crate::encode_egress_frame(&r, buf.len() - 1),
            Err(crate::ProtoCodecError::Encode(_))
        ));
        assert_eq!(
            crate::encode_egress_frame(&r, buf.len()).unwrap().len(),
            buf.len()
        );
    }

    /// codex round 2, item C. The kernel's cap refusal carries the measured
    /// size and the cap, and an operator `eprintln!`; the encoder's overflow
    /// carries `failed to write whole buffer` and nothing else. Which one an
    /// over-cap frame meets was decided by 4 KiB of buffer headroom, so a
    /// frame 2 MiB over the cap got the codec string. The counting pass is
    /// what makes the length knowable before anything is allocated.
    #[test]
    fn the_counting_pass_is_the_encoder_length_at_every_size() {
        // Small, and a frame FAR over the cap — the case the fixed buffer
        // cannot encode at all, and the reason this function exists.
        for n in [
            8usize,
            9 * 1024,
            EGRESS_REQUEST_FRAME_MAX_BYTES + 2 * 1024 * 1024,
        ] {
            let r = EgressFrame::Prompt(req(
                "conv1",
                vec![crate::Turn::Tool {
                    call_id: "c1".into(),
                    content: vec![text(&"x".repeat(n))],
                }],
            ));
            let counted = crate::egress_frame_encoded_len(&r).unwrap();
            // The oracle is the ENCODER, not a second length formula: any
            // divergence would put the kernel's refusal on the wrong side of
            // the cap by exactly that amount.
            let mut reference = Vec::new();
            ciborium::into_writer(&r, &mut reference).unwrap();
            assert_eq!(counted, reference.len(), "n = {n}");
            assert!(counted > n, "n = {n}: the content must be in the count");
            // And the count is what the fixed-buffer encoder needs: exactly
            // the measured length succeeds, one byte less does not.
            if n <= 9 * 1024 {
                assert_eq!(
                    crate::encode_egress_frame(&r, counted).unwrap().len(),
                    counted
                );
                assert!(matches!(
                    crate::encode_egress_frame(&r, counted - 1),
                    Err(crate::ProtoCodecError::Encode(_))
                ));
            }
        }
    }

    #[test]
    fn the_request_codec_round_trips_and_refuses_garbage() {
        let r = EgressFrame::Prompt(req(
            "conv1",
            vec![crate::Turn::User {
                content: vec![text("hello")],
            }],
        ));
        let buf = crate::encode_egress_frame(&r, EGRESS_REQUEST_FRAME_ENCODE_BYTES).unwrap();
        assert_eq!(crate::decode_egress_frame(&buf).unwrap(), r);
        assert!(crate::decode_egress_frame(&[0xffu8, 0xff, 0xff]).is_err());
    }

    /// codex round 2, item B — the request encoder's finding, on the reply.
    /// The reply carries the provider's prose AND whatever kernel-served
    /// content the model quoted back (`ContentBlock::Text.text` is already
    /// `SecretText`), and this encoder still began at `Zeroizing<Vec::new()>`
    /// and grew: every realloc frees a partly-written copy, and `Zeroizing`
    /// wipes only the allocation that lives to the drop.
    #[test]
    fn the_reply_encoder_writes_one_preallocation_and_never_grows() {
        // Over 8 KiB of quoted content — the size codex's trace used on the
        // request leg, and what a model echoing a read file produces here.
        let big = "y".repeat(9 * 1024);
        let r = EgressSocketReply::Prompt(EgressFrameReply::Reply(crate::PromptReply {
            reasoning: None,
            blocks: vec![text(&big), text(&big)],
            tool_calls: vec![],
            usage: None,
        }));
        let buf = crate::encode_egress_socket_reply(&r, EGRESS_REPLY_FRAME_ENCODE_BYTES).unwrap();
        // Byte-identical to what the growing encoder produced: a buffer
        // change, not a wire change.
        let mut reference = Vec::new();
        ciborium::into_writer(&r, &mut reference).unwrap();
        assert_eq!(&buf[..], &reference[..]);
        assert!(
            buf.len() > 18 * 1024,
            "both blocks must be in there: {}",
            buf.len()
        );
        // The ONE allocation it was given, still — a grown buffer reports the
        // doubling sequence it climbed, never the preallocation.
        assert_eq!(buf.capacity(), EGRESS_REPLY_FRAME_ENCODE_BYTES);
        // The bound is enforced, not decorative: one byte short of what the
        // frame needs is the codec's own error — never a panic, and never a
        // silent realloc. The exact length is the discriminator.
        assert!(matches!(
            crate::encode_egress_socket_reply(&r, buf.len() - 1),
            Err(crate::ProtoCodecError::Encode(_))
        ));
        assert_eq!(
            crate::encode_egress_socket_reply(&r, buf.len())
                .unwrap()
                .len(),
            buf.len()
        );
    }

    #[test]
    fn a_stub_crosses_the_egress_frame_reply_intact() {
        let stub = crate::ProposedToolCall {
            name: "write_file".into(),
            call_id: "c".into(),
            arguments: crate::SecretText(zeroize::Zeroizing::new(String::new())),
            refused: Some(crate::CallRefusal::ArgumentsOverBound { bytes: 70_000 }),
        };
        let r = EgressSocketReply::Prompt(EgressFrameReply::Reply(crate::PromptReply {
            reasoning: None,
            blocks: vec![text("ok")],
            tool_calls: vec![stub.clone()],
            usage: None,
        }));
        let buf = crate::encode_egress_socket_reply(&r, EGRESS_REPLY_FRAME_ENCODE_BYTES).unwrap();
        match crate::decode_egress_socket_reply(&buf).unwrap() {
            EgressSocketReply::Prompt(EgressFrameReply::Reply(p)) => {
                assert_eq!(p.tool_calls, vec![stub])
            }
            other => panic!("unexpected {other:?}"),
        }
    }

    #[test]
    fn the_reply_codec_round_trips_and_refuses_garbage() {
        let r = EgressSocketReply::Prompt(EgressFrameReply::Reply(crate::PromptReply {
            reasoning: None,
            blocks: vec![text("ok")],
            tool_calls: vec![],
            usage: None,
        }));
        let buf = crate::encode_egress_socket_reply(&r, EGRESS_REPLY_FRAME_ENCODE_BYTES).unwrap();
        assert_eq!(crate::decode_egress_socket_reply(&buf).unwrap(), r);
        assert!(crate::decode_egress_socket_reply(&[0xffu8, 0xff, 0xff]).is_err());
    }

    #[test]
    fn a_refusal_before_send_round_trips_and_carries_nothing_but_its_tag() {
        let r = EgressSocketReply::RefusedBeforeSend;
        let buf = crate::encode_egress_socket_reply(&r, EGRESS_REPLY_FRAME_ENCODE_BYTES).unwrap();
        assert_eq!(crate::decode_egress_socket_reply(&buf).unwrap(), r);
        let mut tag_only = Vec::new();
        ciborium::into_writer(&"refused_before_send", &mut tag_only).unwrap();
        assert_eq!(&buf[..], &tag_only[..]);
        let reply = EgressSocketReply::Prompt(EgressFrameReply::Reply(crate::PromptReply {
            reasoning: None,
            blocks: vec![],
            tool_calls: vec![],
            usage: None,
        }));
        assert_ne!(reply, r);
    }

    #[test]
    fn an_at_capacity_refusal_round_trips_as_its_own_tag() {
        let r = EgressSocketReply::AtCapacity;
        let buf = crate::encode_egress_socket_reply(&r, EGRESS_REPLY_FRAME_ENCODE_BYTES).unwrap();
        assert_eq!(crate::decode_egress_socket_reply(&buf).unwrap(), r);
        let mut tag_only = Vec::new();
        ciborium::into_writer(&"at_capacity", &mut tag_only).unwrap();
        assert_eq!(&buf[..], &tag_only[..]);
        assert_ne!(r, EgressSocketReply::RefusedBeforeSend);
    }

    /// Every field of the shape check earns its place: drop any one and a
    /// malformed frame reaches the deputy.
    #[test]
    fn every_required_field_is_checked() {
        let base = req(
            "conv1",
            vec![crate::Turn::User {
                content: vec![text("x")],
            }],
        );
        for (label, bad) in [
            (
                "destination",
                EgressFrameRequest {
                    destination: String::new(),
                    ..base.clone()
                },
            ),
            (
                "endpoint",
                EgressFrameRequest {
                    endpoint: String::new(),
                    ..base.clone()
                },
            ),
            (
                "model",
                EgressFrameRequest {
                    model: String::new(),
                    ..base.clone()
                },
            ),
            (
                "key_vault_path",
                EgressFrameRequest {
                    key_vault_path: String::new(),
                    ..base.clone()
                },
            ),
            (
                "key_field",
                EgressFrameRequest {
                    key_field: String::new(),
                    ..base.clone()
                },
            ),
        ] {
            assert!(
                !egress_frame_request_is_acceptable(&bad),
                "{label} unchecked"
            );
        }
        assert!(egress_frame_request_is_acceptable(&base));
    }

    #[test]
    fn a_frame_whose_sealed_key_is_outside_its_bounds_does_not_decode() {
        let r = req(
            "conv1",
            vec![crate::Turn::User {
                content: vec![text("x")],
            }],
        );
        let good = crate::encode_egress_frame(
            &EgressFrame::Prompt(r.clone()),
            EGRESS_REQUEST_FRAME_ENCODE_BYTES,
        )
        .unwrap();
        assert_eq!(
            crate::decode_egress_frame(&good).unwrap(),
            EgressFrame::Prompt(r.clone())
        );
        let unmodified = ciborium::Value::serialized(&EgressFrame::Prompt(r.clone())).unwrap();
        let mut same = Vec::new();
        ciborium::into_writer(&unmodified, &mut same).unwrap();
        assert_eq!(
            crate::decode_egress_frame(&same).unwrap(),
            EgressFrame::Prompt(r),
            "the Value round trip alone must not be what breaks the frame"
        );
        for len in [
            crate::SEALED_KEY_MIN_BYTES - 1,
            crate::SEALED_KEY_MAX_BYTES + 1,
        ] {
            let mut v = unmodified.clone();
            let ciborium::Value::Map(outer) = &mut v else {
                panic!("a frame encodes as a map");
            };
            let ciborium::Value::Map(fields) = &mut outer[0].1 else {
                panic!("a prompt frame's request encodes as a map");
            };
            let slot = fields
                .iter_mut()
                .find(|(k, _)| k.as_text() == Some("sealed_key"))
                .expect("the frame carries sealed_key");
            slot.1 = ciborium::Value::Bytes(vec![0x5a; len]);
            let mut bad = Vec::new();
            ciborium::into_writer(&v, &mut bad).unwrap();
            let msg = crate::decode_egress_frame(&bad)
                .expect_err("an out-of-bounds sealed key")
                .to_string();
            assert!(
                msg.contains(&format!("invalid length {len}"))
                    && msg.contains("a sealed key of 127..=1150 bytes"),
                "{len}: {msg}"
            );
        }
    }

    fn prompt_frame() -> EgressFrame {
        EgressFrame::Prompt(req(
            "conv1",
            vec![crate::Turn::User {
                content: vec![text("hello")],
            }],
        ))
    }

    fn sealed(n: usize, b: u8) -> SealedCredentialBytes {
        SealedCredentialBytes::new(vec![b; n]).unwrap()
    }

    fn mint() -> MintRequest {
        MintRequest {
            task: "task-1".into(),
            agent: "coder".into(),
            class: "github".into(),
            kind: "github-app-installation".into(),
            app: "maknae-bot".into(),
            sets: vec![
                PermissionSet {
                    repositories: vec!["maknae".into(), "maknae-docs".into()],
                    permissions: BTreeMap::from([
                        (GithubPermission::Contents, AccessLevel::Write),
                        (GithubPermission::PullRequests, AccessLevel::Write),
                        (GithubPermission::Metadata, AccessLevel::Read),
                    ]),
                },
                PermissionSet {
                    repositories: vec!["infra".into()],
                    permissions: BTreeMap::from([
                        (GithubPermission::Issues, AccessLevel::Read),
                        (GithubPermission::Checks, AccessLevel::Read),
                        (GithubPermission::Statuses, AccessLevel::Read),
                    ]),
                },
            ],
        }
    }

    fn revoke() -> RevokeRequest {
        RevokeRequest {
            task: "task-1".into(),
            agent: "coder".into(),
            class: "github".into(),
            kind: "github-app-installation".into(),
            app: "maknae-bot".into(),
            set: 1,
            for_revocation: sealed(crate::SEALED_KEY_MIN_BYTES, 0x52),
        }
    }

    fn frame_bytes(f: &EgressFrame) -> Vec<u8> {
        crate::encode_egress_frame(f, EGRESS_REQUEST_FRAME_ENCODE_BYTES)
            .unwrap()
            .to_vec()
    }

    fn cbor(v: &ciborium::Value) -> Vec<u8> {
        let mut out = Vec::new();
        ciborium::into_writer(v, &mut out).unwrap();
        out
    }

    fn field<'a>(v: &'a mut ciborium::Value, name: &str) -> &'a mut ciborium::Value {
        let ciborium::Value::Map(m) = v else {
            panic!("not a map: {v:?}");
        };
        &mut m
            .iter_mut()
            .find(|(k, _)| k.as_text() == Some(name))
            .unwrap_or_else(|| panic!("no {name}"))
            .1
    }

    #[test]
    fn a_prompt_frame_round_trips_inside_the_enum() {
        let buf = frame_bytes(&prompt_frame());
        assert_eq!(crate::decode_egress_frame(&buf).unwrap(), prompt_frame());
        let v: ciborium::Value = ciborium::from_reader(&buf[..]).unwrap();
        let outer = v.as_map().unwrap();
        assert_eq!(outer.len(), 1);
        assert_eq!(outer[0].0.as_text(), Some("prompt"));
        let EgressFrame::Prompt(inner) = prompt_frame() else {
            unreachable!()
        };
        let mut bare = Vec::new();
        ciborium::into_writer(&inner, &mut bare).unwrap();
        assert_eq!(cbor(&outer[0].1), bare);
        assert!(
            crate::decode_egress_frame(&bare).is_err(),
            "an untagged request must not decode as a frame"
        );
    }

    #[test]
    fn a_mint_frame_round_trips_and_permissions_are_closed() {
        let f = EgressFrame::Mint(mint());
        let buf = frame_bytes(&f);
        assert_eq!(crate::decode_egress_frame(&buf).unwrap(), f);
        let r = EgressFrame::Revoke(revoke());
        assert_eq!(crate::decode_egress_frame(&frame_bytes(&r)).unwrap(), r);

        for (p, wire) in [
            (GithubPermission::Contents, "contents"),
            (GithubPermission::PullRequests, "pull_requests"),
            (GithubPermission::Issues, "issues"),
            (GithubPermission::Checks, "checks"),
            (GithubPermission::Statuses, "statuses"),
            (GithubPermission::Metadata, "metadata"),
        ] {
            assert_eq!(
                ciborium::Value::serialized(&p).unwrap().as_text(),
                Some(wire)
            );
            assert_eq!(p.as_str(), wire);
        }
        for (l, wire) in [(AccessLevel::Read, "read"), (AccessLevel::Write, "write")] {
            assert_eq!(
                ciborium::Value::serialized(&l).unwrap().as_text(),
                Some(wire)
            );
        }

        let with = |name: &str, level: &str| {
            let mut v: ciborium::Value = ciborium::from_reader(&buf[..]).unwrap();
            let sets = field(field(&mut v, "mint"), "sets");
            let ciborium::Value::Array(sets) = sets else {
                panic!("sets is an array");
            };
            let ciborium::Value::Map(perms) = field(&mut sets[1], "permissions") else {
                panic!("permissions is a map");
            };
            perms.push((name.into(), level.into()));
            crate::decode_egress_frame(&cbor(&v))
        };
        assert!(with("contents", "write").is_ok(), "the control must decode");
        let msg = with("administration", "read")
            .expect_err("administration is not a permission Maknae mints")
            .to_string();
        assert!(msg.contains("administration"), "{msg}");
        assert!(
            with("contents", "admin").is_err(),
            "access levels are closed"
        );
    }

    #[test]
    fn a_duplicate_permission_key_fails_to_decode() {
        let buf = frame_bytes(&EgressFrame::Mint(mint()));
        let mut v: ciborium::Value = ciborium::from_reader(&buf[..]).unwrap();
        let ciborium::Value::Array(sets) = field(field(&mut v, "mint"), "sets") else {
            panic!("sets is an array");
        };
        let ciborium::Value::Map(perms) = field(&mut sets[1], "permissions") else {
            panic!("permissions is a map");
        };
        perms.push(("issues".into(), "write".into()));
        let msg = crate::decode_egress_frame(&cbor(&v))
            .expect_err("issues: read then issues: write")
            .to_string();
        assert!(msg.contains("duplicate permission issues"), "{msg}");
    }

    #[test]
    fn permissions_that_are_not_a_map_are_refused_naming_the_shape() {
        use serde::de::IntoDeserializer;
        let d: serde::de::value::StrDeserializer<'_, serde::de::value::Error> =
            "contents".into_deserializer();
        let msg = permissions_without_duplicates(d).unwrap_err().to_string();
        assert!(
            msg.contains("a map of GitHub permissions, each named once"),
            "{msg}"
        );
    }

    #[test]
    fn sealed_credential_bytes_outside_the_seal_bounds_do_not_decode() {
        for n in [crate::SEALED_KEY_MIN_BYTES, crate::SEALED_KEY_MAX_BYTES] {
            let got: SealedCredentialBytes =
                ciborium::from_reader(&cbor(&ciborium::Value::Bytes(vec![3; n]))[..]).unwrap();
            assert_eq!(got.as_bytes(), vec![3u8; n]);
            assert_eq!(sealed(n, 3), got);
        }
        for n in [
            0,
            crate::SEALED_KEY_MIN_BYTES - 1,
            crate::SEALED_KEY_MAX_BYTES + 1,
        ] {
            let msg = ciborium::from_reader::<SealedCredentialBytes, _>(
                &cbor(&ciborium::Value::Bytes(vec![3; n]))[..],
            )
            .expect_err("out of bounds")
            .to_string();
            assert!(
                msg.contains(&format!("invalid length {n}"))
                    && msg.contains("a sealed credential of 127..=1150 bytes"),
                "{n}: {msg}"
            );
            assert!(SealedCredentialBytes::new(vec![3; n]).is_err(), "{n}");
        }
        assert!(ciborium::from_reader::<SealedCredentialBytes, _>(
            &cbor(&ciborium::Value::Text(
                "x".repeat(crate::SEALED_KEY_MIN_BYTES)
            ))[..]
        )
        .is_err());

        let mut v: ciborium::Value =
            ciborium::from_reader(&frame_bytes(&EgressFrame::Revoke(revoke()))[..]).unwrap();
        *field(field(&mut v, "revoke"), "for_revocation") =
            ciborium::Value::Bytes(vec![3; crate::SEALED_KEY_MAX_BYTES + 1]);
        assert!(crate::decode_egress_frame(&cbor(&v)).is_err());

        let reply = EgressSocketReply::Mint(MintReply::Minted(vec![SealedCredential {
            set: 0,
            expires_at: "2026-11-19T10:00:00Z".into(),
            for_agent: sealed(crate::SEALED_KEY_MIN_BYTES, 1),
            for_revocation: sealed(crate::SEALED_KEY_MIN_BYTES, 2),
        }]));
        let buf =
            crate::encode_egress_socket_reply(&reply, EGRESS_REPLY_FRAME_ENCODE_BYTES).unwrap();
        assert_eq!(crate::decode_egress_socket_reply(&buf).unwrap(), reply);
        let mut v: ciborium::Value = ciborium::from_reader(&buf[..]).unwrap();
        let ciborium::Value::Array(creds) = field(field(&mut v, "mint"), "minted") else {
            panic!("minted is an array");
        };
        *field(&mut creds[0], "for_agent") =
            ciborium::Value::Bytes(vec![1; crate::SEALED_KEY_MIN_BYTES - 1]);
        assert!(crate::decode_egress_socket_reply(&cbor(&v)).is_err());
    }

    #[test]
    fn mint_and_revoke_debug_show_lengths_and_counts_only() {
        assert_eq!(
            format!("{:?}", mint()),
            r#"MintRequest { task: "task-1", agent: "coder", class: "github", kind: "github-app-installation", app: "maknae-bot", sets: <2 sets> }"#
        );
        assert_eq!(
            format!("{:?}", revoke()),
            r#"RevokeRequest { task: "task-1", agent: "coder", class: "github", kind: "github-app-installation", app: "maknae-bot", set: 1, for_revocation: SealedCredentialBytes(<127 bytes>) }"#
        );
        let cred = SealedCredential {
            set: 0,
            expires_at: "2026-11-19T10:00:00Z".into(),
            for_agent: sealed(200, 0x41),
            for_revocation: sealed(300, 0x42),
        };
        assert_eq!(
            format!("{cred:?}"),
            r#"SealedCredential { set: 0, expires_at: "2026-11-19T10:00:00Z", for_agent: SealedCredentialBytes(<200 bytes>), for_revocation: SealedCredentialBytes(<300 bytes>) }"#
        );
        assert_eq!(
            format!("{:?}", MintReply::Minted(vec![cred])),
            "Minted(<1 credentials>)"
        );
        assert_eq!(
            format!(
                "{:?}",
                MintReply::Refused(MintRefusal::Forge(ForgeStatus::NotFound))
            ),
            "Refused(Forge(NotFound))"
        );
        assert_eq!(
            format!("{:?}", sealed(crate::SEALED_KEY_MAX_BYTES, 0x43)),
            "SealedCredentialBytes(<1150 bytes>)"
        );
    }

    #[test]
    fn the_mint_bounds_are_pinned_by_value() {
        assert_eq!(
            (
                MINT_MAX_SETS,
                MINT_MAX_REPOS_PER_SET,
                MINT_MAX_PERMISSIONS_PER_SET
            ),
            (8, 50, 6)
        );
    }

    #[test]
    fn refusals_round_trip_on_both_credential_replies() {
        for refusal in [
            MintRefusal::Request,
            MintRefusal::Signer,
            MintRefusal::Mismatch,
            MintRefusal::Recipient,
            MintRefusal::Forge(ForgeStatus::Unauthorized),
            MintRefusal::Forge(ForgeStatus::Forbidden),
            MintRefusal::Forge(ForgeStatus::NotFound),
            MintRefusal::Forge(ForgeStatus::Unprocessable),
            MintRefusal::Forge(ForgeStatus::Other),
        ] {
            for r in [
                EgressSocketReply::Mint(MintReply::Refused(refusal)),
                EgressSocketReply::Revoke(RevokeReply::Refused(refusal)),
            ] {
                let buf =
                    crate::encode_egress_socket_reply(&r, EGRESS_REPLY_FRAME_ENCODE_BYTES).unwrap();
                assert_eq!(crate::decode_egress_socket_reply(&buf).unwrap(), r);
            }
        }
        for r in [
            EgressSocketReply::Revoke(RevokeReply::Revoked),
            EgressSocketReply::Revoke(RevokeReply::AlreadyGone),
        ] {
            let buf =
                crate::encode_egress_socket_reply(&r, EGRESS_REPLY_FRAME_ENCODE_BYTES).unwrap();
            assert_eq!(crate::decode_egress_socket_reply(&buf).unwrap(), r);
        }
    }

    const NONCE: &str = "0123456789abcdef0123456789abcdef";
    const VAULT_PATH: &str = "users/alice/forges/github.example";
    const KEY_FIELD: &str = "forge_token_field";

    fn ask(base: &str, change: Option<u64>, head: Option<&str>) -> RepoAsk {
        RepoAsk {
            base: base.into(),
            change,
            head: head.map(Into::into),
        }
    }

    fn asks(n: usize) -> Vec<RepoAsk> {
        (0..n)
            .map(|i| ask(&format!("o/r{i}"), Some(7), None))
            .collect()
    }

    fn tasker_side() -> ReachSide {
        ReachSide::Tasker {
            tasker: "alice".into(),
            expected_path: VAULT_PATH.into(),
            key_field: KEY_FIELD.into(),
            nonce: NONCE.into(),
            sealed: crate::SealedKey::new(vec![0xa7; crate::SEALED_KEY_MIN_BYTES]).unwrap(),
        }
    }

    fn cred(i: usize) -> CredentialRef {
        CredentialRef {
            kind: "kind-a".into(),
            name: format!("entry{i}"),
        }
    }

    fn agent_side(n: usize) -> ReachSide {
        ReachSide::Agent {
            agent: "hobi".into(),
            credentials: (0..n).map(cred).collect(),
        }
    }

    fn reach(side: ReachSide, asks: Vec<RepoAsk>) -> Result<ReachRequest, crate::ProtoCodecError> {
        ReachRequest::new("forge.example".into(), "p".into(), 20_000, side, asks)
    }

    fn observation(head: Option<&str>) -> RepoObservation {
        let ops = |o: &[crate::ForgeOp]| o.iter().copied().collect::<crate::ForgeOps>();
        RepoObservation::new(
            ops(&[crate::ForgeOp::Read, crate::ForgeOp::Merge]),
            head.map(Into::into),
            if head.is_some() {
                ops(&[crate::ForgeOp::PushHead])
            } else {
                crate::ForgeOps::EMPTY
            },
            false,
            true,
        )
        .unwrap()
    }

    fn reach_replies() -> Vec<EgressSocketReply> {
        let mut out = vec![
            EgressSocketReply::Reach(ReachReply::Observed(
                Observations::new(vec![observation(Some("fork/r")), observation(None)]).unwrap(),
            )),
            EgressSocketReply::Reach(ReachReply::Observed(
                Observations::new((0..REACH_ASKS_MAX).map(|_| observation(None)).collect())
                    .unwrap(),
            )),
            EgressSocketReply::Reach(ReachReply::Observed(
                Observations::new(vec![RepoObservation::new(
                    crate::ForgeOps::EMPTY,
                    None,
                    crate::ForgeOps::EMPTY,
                    true,
                    false,
                )
                .unwrap()])
                .unwrap(),
            )),
            EgressSocketReply::Reach(ReachReply::NoForgeCredential),
        ];
        out.extend(
            REACH_REFUSALS
                .iter()
                .map(|r| EgressSocketReply::Reach(ReachReply::Refused(*r))),
        );
        out
    }

    fn reply_bytes(r: &EgressSocketReply) -> Vec<u8> {
        crate::encode_egress_socket_reply(r, EGRESS_REPLY_FRAME_ENCODE_BYTES)
            .unwrap()
            .to_vec()
    }

    #[test]
    fn reach_frames_round_trip_and_bound_their_asks() {
        assert_eq!((REACH_ASKS_MAX, REACH_CREDENTIALS_MAX), (8, 8));
        for f in [
            reach(tasker_side(), asks(1)).unwrap(),
            reach(tasker_side(), asks(REACH_ASKS_MAX)).unwrap(),
            reach(agent_side(1), vec![ask("o/r", Some(3), Some("fork/r"))]).unwrap(),
            reach(agent_side(REACH_CREDENTIALS_MAX), asks(2)).unwrap(),
        ] {
            let f = EgressFrame::Reach(f);
            assert_eq!(crate::decode_egress_frame(&frame_bytes(&f)).unwrap(), f);
        }
        for r in reach_replies() {
            assert_eq!(
                crate::decode_egress_socket_reply(&reply_bytes(&r)).unwrap(),
                r
            );
        }

        let refused = |what: &str, r: Result<ReachRequest, crate::ProtoCodecError>| {
            assert!(r.is_err(), "{what} must be refused");
        };
        refused("no asks", reach(tasker_side(), asks(0)));
        refused(
            "a ninth ask",
            reach(tasker_side(), asks(REACH_ASKS_MAX + 1)),
        );
        refused(
            "a duplicate ask",
            reach(tasker_side(), vec![ask("o/r", None, None); 2]),
        );
        refused(
            "a bad base",
            reach(tasker_side(), vec![ask("o", None, None)]),
        );
        refused(
            "a bad head",
            reach(tasker_side(), vec![ask("o/r", Some(1), Some("../x"))]),
        );
        refused(
            "change zero",
            reach(tasker_side(), vec![ask("o/r", Some(0), None)]),
        );
        refused("no credentials", reach(agent_side(0), asks(1)));
        refused(
            "a ninth credential",
            reach(agent_side(REACH_CREDENTIALS_MAX + 1), asks(1)),
        );
        refused(
            "a duplicate credential",
            reach(
                ReachSide::Agent {
                    agent: "hobi".into(),
                    credentials: vec![cred(0), cred(0)],
                },
                asks(1),
            ),
        );
        refused(
            "an empty agent",
            reach(
                ReachSide::Agent {
                    agent: String::new(),
                    credentials: vec![cred(0)],
                },
                asks(1),
            ),
        );
        let tasker_with = |edit: fn(&mut ReachSide)| {
            let mut side = tasker_side();
            edit(&mut side);
            reach(side, asks(1))
        };
        refused(
            "an upper-case nonce",
            tasker_with(|s| {
                if let ReachSide::Tasker { nonce, .. } = s {
                    *nonce = NONCE.to_uppercase();
                }
            }),
        );
        refused(
            "an empty path",
            tasker_with(|s| {
                if let ReachSide::Tasker { expected_path, .. } = s {
                    expected_path.clear();
                }
            }),
        );
        refused(
            "an oversized key field",
            tasker_with(|s| {
                if let ReachSide::Tasker { key_field, .. } = s {
                    *key_field = "k".repeat(REACH_FIELD_MAX_BYTES + 1);
                }
            }),
        );
        refused(
            "a bad server",
            ReachRequest::new(
                "Forge.Example".into(),
                "p".into(),
                1,
                tasker_side(),
                asks(1),
            ),
        );
        refused(
            "an empty provider",
            ReachRequest::new(
                "forge.example".into(),
                String::new(),
                1,
                tasker_side(),
                asks(1),
            ),
        );
        refused(
            "a zero deadline",
            ReachRequest::new(
                "forge.example".into(),
                "p".into(),
                0,
                tasker_side(),
                asks(1),
            ),
        );

        let tampered = |f: ReachRequest, edit: &dyn Fn(&mut ciborium::Value)| {
            let mut v: ciborium::Value =
                ciborium::from_reader(&frame_bytes(&EgressFrame::Reach(f))[..]).unwrap();
            edit(field(&mut v, "reach"));
            crate::decode_egress_frame(&cbor(&v))
        };
        let resize = |name: &'static str, n: usize| {
            move |v: &mut ciborium::Value| {
                let target = if name == "credentials" {
                    field(field(field(v, "side"), "agent"), name)
                } else {
                    field(v, name)
                };
                let ciborium::Value::Array(a) = target else {
                    panic!("{name} is an array");
                };
                let first = a[0].clone();
                a.clear();
                a.extend((0..n).map(|i| {
                    let mut e = first.clone();
                    *field(&mut e, if name == "asks" { "base" } else { "name" }) =
                        format!("o/r{i}").into();
                    e
                }));
            }
        };
        let tf = || reach(tasker_side(), asks(1)).unwrap();
        let af = || reach(agent_side(1), asks(1)).unwrap();
        assert!(
            tampered(tf(), &resize("asks", 2)).is_ok(),
            "the control decodes"
        );
        assert!(tampered(tf(), &resize("asks", 0)).is_err());
        assert!(tampered(tf(), &resize("asks", REACH_ASKS_MAX + 1)).is_err());
        assert!(
            tampered(af(), &resize("credentials", 2)).is_ok(),
            "the control decodes"
        );
        assert!(tampered(af(), &resize("credentials", 0)).is_err());
        assert!(tampered(af(), &resize("credentials", REACH_CREDENTIALS_MAX + 1)).is_err());
        assert!(tampered(tf(), &|v| {
            let ciborium::Value::Map(m) = v else {
                unreachable!()
            };
            m.push(("extra".into(), 1.into()));
        })
        .is_err());

        let observed = |edit: &dyn Fn(&mut ciborium::Value)| {
            let r = &reach_replies()[0];
            let mut v: ciborium::Value = ciborium::from_reader(&reply_bytes(r)[..]).unwrap();
            edit(field(field(&mut v, "reach"), "observed"));
            crate::decode_egress_socket_reply(&cbor(&v))
        };
        let nth = |v: &mut ciborium::Value, i: usize| -> ciborium::Value {
            let ciborium::Value::Array(a) = v else {
                unreachable!()
            };
            a[i].clone()
        };
        let set = |v: &mut ciborium::Value, i: usize, name: &str, to: ciborium::Value| {
            let ciborium::Value::Array(a) = v else {
                unreachable!()
            };
            *field(&mut a[i], name) = to;
        };
        let resize_obs = |n: usize| {
            move |v: &mut ciborium::Value| {
                let first = nth(v, 1);
                *v = ciborium::Value::Array(vec![first; n]);
            }
        };
        assert!(observed(&|_| {}).is_ok(), "the control decodes");
        assert!(observed(&resize_obs(0)).is_err());
        assert!(observed(&resize_obs(REACH_ASKS_MAX + 1)).is_err());
        let push_head = u8::from(crate::ForgeOps::from_iter([crate::ForgeOp::PushHead]));
        assert!(observed(&|v| set(v, 1, "base", push_head.into())).is_err());
        assert!(observed(&|v| set(v, 1, "head", push_head.into())).is_err());
        assert!(observed(&|v| set(v, 0, "head_gone", true.into())).is_err());
        assert!(observed(&|v| set(v, 0, "head_path", "fork".into())).is_err());
        assert!(observed(&|v| set(v, 1, "base", 0x20.into())).is_err());
    }

    #[test]
    fn a_reach_frame_debug_omits_the_sealed_token_and_path() {
        let f = EgressFrame::Reach(reach(tasker_side(), vec![ask("o/r", Some(7), None)]).unwrap());
        let shown = format!("{f:?}");
        assert_eq!(
            shown,
            r#"Reach(ReachRequest { server: "forge.example", provider: "p", deadline_ms: 20000, side: Tasker { tasker: "alice", expected_path: "<omitted>", key_field: "<omitted>", nonce: "<omitted>", sealed: SealedKey(<127 bytes>) }, asks: [RepoAsk { base: "o/r", change: Some(7), head: None }] })"#
        );
        for secret in [VAULT_PATH, KEY_FIELD, NONCE, "a7", "167"] {
            assert!(!shown.contains(secret), "{secret} leaked: {shown}");
        }
    }

    fn texts(v: &ciborium::Value, keys: &mut std::collections::BTreeSet<String>) {
        match v {
            ciborium::Value::Map(m) => {
                for (k, e) in m {
                    keys.insert(k.as_text().expect("a text key").to_owned());
                    texts(e, keys);
                }
            }
            ciborium::Value::Array(a) => a.iter().for_each(|e| texts(e, keys)),
            ciborium::Value::Text(t) => {
                keys.insert(t.clone());
            }
            _ => {}
        }
    }

    #[test]
    fn no_forge_native_type_appears_in_reach_frames() {
        let mut seen = std::collections::BTreeSet::new();
        for f in [
            reach(tasker_side(), vec![ask("o/r", Some(7), Some("f/r"))]).unwrap(),
            reach(agent_side(1), asks(1)).unwrap(),
        ] {
            let v = ciborium::from_reader(&frame_bytes(&EgressFrame::Reach(f))[..]).unwrap();
            texts(&v, &mut seen);
        }
        for r in reach_replies() {
            texts(
                &ciborium::from_reader(&reply_bytes(&r)[..]).unwrap(),
                &mut seen,
            );
        }
        let data = [
            "forge.example",
            "p",
            "alice",
            VAULT_PATH,
            KEY_FIELD,
            NONCE,
            "o/r",
            "f/r",
            "fork/r",
            "hobi",
            "kind-a",
            "entry0",
        ];
        let vocabulary: std::collections::BTreeSet<String> = seen
            .into_iter()
            .filter(|t| !data.contains(&t.as_str()) && !t.starts_with("o/r"))
            .collect();
        let expected = [
            "reach",
            "server",
            "provider",
            "deadline_ms",
            "side",
            "asks",
            "tasker",
            "expected_path",
            "key_field",
            "nonce",
            "sealed",
            "agent",
            "credentials",
            "kind",
            "name",
            "base",
            "change",
            "head",
            "observed",
            "head_path",
            "head_gone",
            "covered",
            "no_forge_credential",
            "refused",
            "request",
            "seal",
            "login",
            "not_found",
            "unauthorized",
            "forbidden",
            "moved",
            "upstream",
            "unanswered",
            "shape",
            "suspended",
            "ambiguous_credential",
            "signer",
        ];
        assert_eq!(
            vocabulary,
            expected.iter().map(|s| s.to_string()).collect(),
            "the reach frames' vocabulary is pinned"
        );
        for word in vocabulary {
            for native in [
                "github",
                "gitlab",
                "installation",
                "pull",
                "permission",
                "jwt",
                "app",
                "repos",
                "role",
                "admin",
                "maintain",
                "triage",
                "push",
                "merge",
            ] {
                assert!(!word.contains(native), "`{word}` is forge-native");
            }
        }
    }

    const REACH_REFUSALS: [ReachRefusal; 13] = [
        ReachRefusal::Request,
        ReachRefusal::Seal,
        ReachRefusal::Login,
        ReachRefusal::NotFound,
        ReachRefusal::Unauthorized,
        ReachRefusal::Forbidden,
        ReachRefusal::Moved,
        ReachRefusal::Upstream,
        ReachRefusal::Unanswered,
        ReachRefusal::Shape,
        ReachRefusal::Suspended,
        ReachRefusal::AmbiguousCredential,
        ReachRefusal::Signer,
    ];

    #[test]
    fn reach_refusal_is_closed() {
        let wire = |r: ReachRefusal| match r {
            ReachRefusal::Request => "request",
            ReachRefusal::Seal => "seal",
            ReachRefusal::Login => "login",
            ReachRefusal::NotFound => "not_found",
            ReachRefusal::Unauthorized => "unauthorized",
            ReachRefusal::Forbidden => "forbidden",
            ReachRefusal::Moved => "moved",
            ReachRefusal::Upstream => "upstream",
            ReachRefusal::Unanswered => "unanswered",
            ReachRefusal::Shape => "shape",
            ReachRefusal::Suspended => "suspended",
            ReachRefusal::AmbiguousCredential => "ambiguous_credential",
            ReachRefusal::Signer => "signer",
        };
        let names: std::collections::BTreeSet<_> =
            REACH_REFUSALS.iter().map(|r| wire(*r)).collect();
        assert_eq!(names.len(), REACH_REFUSALS.len());
        for r in REACH_REFUSALS {
            let v = ciborium::Value::serialized(&r).unwrap();
            assert_eq!(v.as_text(), Some(wire(r)));
            assert_eq!(v.deserialized::<ReachRefusal>().unwrap(), r);
        }
        for unknown in ["rate_limited", "other", "Request", ""] {
            assert!(
                ciborium::Value::Text(unknown.into())
                    .deserialized::<ReachRefusal>()
                    .is_err(),
                "`{unknown}` is not a refusal"
            );
        }
        let refused = reply_bytes(&EgressSocketReply::Reach(ReachReply::Refused(
            ReachRefusal::Signer,
        )));
        let mut v: ciborium::Value = ciborium::from_reader(&refused[..]).unwrap();
        *field(field(&mut v, "reach"), "refused") = "teapot".into();
        assert!(crate::decode_egress_socket_reply(&cbor(&v)).is_err());
    }
}
