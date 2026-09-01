//! Versioned CBOR request/response contract (spec §3).
use crate::error::ProtoCodecError;
use serde::{Deserialize, Serialize};

// PROTOCOL_VERSION STAYS 1 (#77): adding `Verb::Read`/`Payload::ReadContent`/
// `ProtoErrCode::TooLarge` are ADDITIVE CBOR enum variants — no version bump.
// #162 adds `Payload::{ConfigView, Status, SubjectList}` the same way, appended
// at the tail. A client built before them has no subcommand that can elicit
// one; a newer client against an older daemon gets `NotImplemented` from the
// `NoBehaviour` arm.
// A pre-#77 CLI never sends `Read`, so it keeps interoperating with a #77
// daemon for `ping`/`whoami` (same wire version); only the new read verb
// needs the new CLI. A version bump would be an irreversible hard mutual
// break (strict-equality check both directions) and was NOT authorized.
pub const PROTOCOL_VERSION: u16 = 1;

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
    /// agent method, so Maknae is the caller.
    AdminProviderList,
    /// Maknae selecting the agent runtime's model provider — a trust-plane
    /// destination choice, not the agent's preference. Egress on the same axis as
    /// `session.prompt` (#153).
    AdminProviderSet,
    /// Remove a provider from the agent's available destinations. Destination
    /// selection by elimination, same axis.
    AdminProviderDisable,
    /// Use a trust-plane-held credential on a subject's behalf against an
    /// external service, without the subject ever seeing it — egress with an
    /// irreversible third-party effect. The confused-deputy term — the subject's
    /// reach becomes the daemon's reach unless the credential is scoped to the
    /// subject rather than the daemon (#151).
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
    /// call, not bookkeeping.
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
    /// Send content to an agent runtime. This is EGRESS — content leaving the
    /// trust plane toward a model endpoint. The term #147's destination
    /// governance attaches to; its default is #153's. Un-recallable once sent —
    /// which is why it is two-phase, not audited after the fact.
    SessionPrompt,
    /// Ask the agent to stop work in progress.
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
    /// leg — to whatever audience receives it.
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
    FsWrite,
    /// Destroy file content. Irreversible, and the strongest argument for
    /// two-phase audit.
    FsDelete,
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
    FsMkdir,
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
}

/// One role and the identities bound to it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RoleBindingView {
    pub role: String,
    pub members: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ProtoErrCode {
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
pub fn encode_response(r: &Response) -> Result<Vec<u8>, ProtoCodecError> {
    enc(r)
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
    use super::*;
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
}
