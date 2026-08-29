# Model Context Protocol (MCP) — Protocol Reference & Multi-Version Assessment

| | |
|---|---|
| **Status** | Reference record — the base facts behind Maknae's MCP alignment (issues #151, #177–#180). **No dispositions ratified beyond the operator rulings noted inline.** |
| **Date** | 2026-08-29 |
| **Subject** | [`modelcontextprotocol/modelcontextprotocol`](https://github.com/modelcontextprotocol/modelcontextprotocol) — the Model Context Protocol specification. **PINNED at HEAD `ca4ab3027f7c844cd3039c956438d72e8253f7f5`.** Live docs: https://modelcontextprotocol.io |
| **Method** | **Read-only** via the GitHub API at the pinned commit. Read in full: `docs/specification/2026-07-28/{basic/versioning,deprecated,changelog,basic/patterns/mrtr}.mdx`, the `## Major changes` sections of the `2025-11-25`, `2025-06-18` and `2025-03-26` changelogs, and grep-scoped normative text from `2026-07-28/server/tools.mdx` and `client/sampling.mdx`. For §13, the version constants of the TypeScript, Python and Rust SDKs, `openai/codex`'s `rmcp` pin, and the conformance suite's README — read on 2026-08-29 at repository HEAD, **not pinned**, since the point of that section is current ecosystem state. **NOT read:** the `schema.mdx` payloads, the transport binding pages in full, the authorization pages in full, the registry, and the `draft` revision. No clone, no install, no execution. |
| **Audience** | Maknae team (dual-audience: human reviewers and AI agents) |
| **Purpose** | Record the MCP facts Maknae's `mcp.*` vocabulary and future broker depend on, **pinned by commit**, so this research is never re-run from scratch — and so a stale recollection of MCP is never designed against. Discharges the AGENTS.md prerequisite recorded on #177–#180. |

## 1. Why this record exists

AGENTS.md requires a protocol reference be pinned into `design/references/` **before** designing against it; #151 repeats the requirement in its own body (*"pin the MCP spec in `design/references/` BEFORE designing — the ACP near-miss is the precedent"*). Issues #177–#180 were written citing MCP but recorded the missing assessment as a hard prerequisite. **This is that assessment.**

It exists in the same spirit as `2026-08-28-acp-protocol-assessment.md`, and its headline finding is of the same kind but larger.

## 2. The headline — read this before anything else

**MCP is not one protocol with a version number. It is two architectural eras with an incompatible boundary between them.**

The `2026-07-28` revision removes the `initialize` handshake and protocol-level sessions entirely. The specification's own terminology (`basic/versioning.mdx`):

- **Modern** — protocol versions that convey version, identity, and capabilities as **per-request metadata** (revision `2026-07-28` and later).
- **Legacy** — protocol versions that establish a session with an `initialize` **handshake** (`2025-11-25` and earlier).
- **Dual-era** — an implementation that supports both.

> There is no negotiation handshake. Every request carries its protocol version, and the server accepts or rejects each request independently.

**A single-era implementation cannot talk to the other era.** That is stated, not inferred — see the compatibility matrix in §4.

## 3. Version inventory

Revisions present at the pin, under `docs/specification/`:

| Revision | Notable for |
|---|---|
| `2024-11-05` | The original. HTTP+SSE transport. |
| `2025-03-26` | OAuth 2.1 authorization framework; **Streamable HTTP replaces HTTP+SSE**; JSON-RPC batching added; tool annotations added. |
| `2025-06-18` | **Batching removed** (added one revision earlier); structured tool output; **elicitation added**; MCP servers classified as OAuth Resource Servers; **RFC 8707 Resource Indicators required**; `MCP-Protocol-Version` header required on HTTP. |
| `2025-11-25` | OIDC Discovery; icons; incremental scope consent; **URL-mode elicitation**; **tool calling in sampling**; Client ID Metadata Documents; experimental tasks. **Last legacy revision.** |
| `2026-07-28` | **The era break.** Stateless; no `initialize`; `server/discover`; MRTR; `subscriptions/listen`; `ping` / `logging/setLevel` removed; tasks moved to an extension; Roots, Sampling and Logging deprecated. |
| `draft` | Not read. Non-authoritative. |

**Note the churn signal:** JSON-RPC batching was **added in `2025-03-26` and removed in `2025-06-18`** — one revision's lifetime. A feature present in the spec is not evidence it will persist.

## 4. The compatibility matrix — verbatim from `basic/versioning.mdx`

| Client | Server | Outcome |
|---|---|---|
| Modern | Modern | **Works.** `server/discover` optional; mismatches surface as `UnsupportedProtocolVersionError` and the client retries. |
| Modern | Legacy | **Fails.** The server may reject, stay silent, or *"even process an era-ambiguous method under legacy semantics."* |
| Dual-era | Modern | **Works.** |
| Dual-era | Legacy | **Works.** Falls back to `initialize`. |
| Legacy | Modern | **Fails.** *"Legacy clients have no fall-forward mechanism."* |
| Legacy | Dual-era | **Works.** |
| Legacy | Legacy | Works per the legacy revision. |

**Only a dual-era implementation interoperates with both.** Two of seven combinations fail outright.

**The `Modern → Legacy` failure mode is the dangerous one for a security product**: a legacy server *"may even process an era-ambiguous method under legacy semantics."* A request can be **acted on under semantics the caller did not intend**, silently. That is precisely the *"semantic break behind a stable wire"* AGENTS.md's protocol-discipline rule names — *"on a policy protocol, that is how a deny silently becomes a permit."*

### Era detection

Era is *"a property of the server, not of an individual request."* Clients probe:
- **stdio** — send `server/discover`; fall back on any error that is not a recognized modern error.
- **Streamable HTTP** — attempt a modern request; inspect the body of a `400 Bad Request` before falling back.

A recognized modern JSON-RPC error (e.g. `UnsupportedProtocolVersionError`, code **`-32022`**) identifies a modern server. Anything else identifies a legacy one. Clients **SHOULD** cache the era for the server-process (stdio) or origin (HTTP) lifetime, **MAY** persist it across restarts, and re-probe if the cached assumption fails.

**For Maknae this cached era determination is security-relevant state**, not a performance optimisation: it selects which semantics a request is interpreted under.

## 5. Deprecated features — the registry at the pin

From `2026-07-28/deprecated.mdx`. A Deprecated feature *"remains part of the specification but is scheduled for removal: new implementations **SHOULD NOT** adopt it."*

| Feature | SEP | Deprecated in | Migration path | Earliest removal |
|---|---|---|---|---|
| **Roots** | SEP-2577 | `2026-07-28` | Tool parameters, resource URIs, or server configuration | First revision on/after 2027-07-28 |
| **Sampling** | SEP-2577 | `2026-07-28` | **Integrate directly with LLM provider APIs** | First revision on/after 2027-07-28 |
| **Logging** | SEP-2577 | `2026-07-28` | `stderr` (stdio) or OpenTelemetry | First revision on/after 2027-07-28 |
| **Dynamic Client Registration** | PR #2858 | `2026-07-28` | Client ID Metadata Documents | First revision on/after 2027-07-28 |
| `includeContext: "thisServer"` / `"allServers"` | SEP-2596 | `2025-11-25` | Omit, or use `"none"` | Follows Sampling |
| **HTTP+SSE transport** | SEP-2596 | `2025-03-26` | Streamable HTTP | Three months after SEP-2596 reaches Final |

**Nothing has been removed under this policy yet.** Deprecated features remain functional during the window.

**This settles the open question recorded on #180.** Sampling is deprecated **as a whole feature**, not in part. The migration path is to bypass MCP for model access entirely.

## 6. `2026-07-28` — what actually changed

Condensed from `changelog.mdx` §Major changes. Every item is a compatibility fact.

1. **Protocol-level sessions removed**, including `Mcp-Session-Id`. List endpoints no longer vary per connection. Cross-call state uses *"explicit, server-minted handles passed as ordinary tool arguments."* (SEP-2567)
2. **`initialize` / `notifications/initialized` removed — MCP is stateless.** Version, client capabilities, and identity move to `_meta` (`io.modelcontextprotocol/protocolVersion`, `/clientCapabilities`, `/clientInfo`). (SEP-2575)
3. **`server/discover` added — servers MUST implement it.** Advertises supported versions, capabilities, identity. (SEP-2575)
4. **`resources/subscribe` / `unsubscribe` and the HTTP GET endpoint replaced by `subscriptions/listen`** — one long-lived POST-response stream, opt-in by notification type. (SEP-2575)
5. **`ping`, `logging/setLevel`, and `notifications/roots/list_changed` removed.** Log level is now per-request via `_meta`. (SEP-2575)
6. **Tasks moved out of core into the `io.modelcontextprotocol/tasks` extension**, redesigned. (SEP-2663)
7. **MRTR replaces server-initiated requests.** See §7 — the largest change for Maknae.
8. **All results carry a required `resultType`** (`"complete"` or `"input_required"`). Clients **MUST** treat results from earlier-protocol servers that omit it as `"complete"`. (SEP-2322)
9. **SSE stream resumability and message redelivery removed.** A broken stream loses the in-flight request; clients **MUST** re-issue with a new request ID. (SEP-2575)

Minor changes of note: an `extensions` capability map with mandatory-prefix identifiers; OpenTelemetry trace-context conventions in `_meta`; **tools SHOULD be returned in deterministic order**; required `Mcp-Method` / `Mcp-Name` headers on HTTP POST; required `ttlMs` and `cacheScope` on list/read results; resource-not-found error renumbered `-32002` → `-32602`; **an error-code allocation policy** reserving `-32020`–`-32099` for the spec.

## 7. MRTR — the change that most affects Maknae

`basic/patterns/mrtr.mdx`, in its own words:

> Multi Round-Trip Requests (MRTR) was introduced in this version. This replaces the previous approach of sending server-initiated requests. Servers **MUST** send server-to-client requests (such as `roots/list`, `sampling/createMessage`, or `elicitation/create`) using the MRTR pattern. The previous pattern of server-initiated requests is no longer supported. **This is a breaking change.**

The flow: the client sends a request; the server responds with an `InputRequiredResult` (`resultType: "input_required"`) whose `inputRequests` field names what it needs; the client gathers it and **retries the original request** carrying `inputResponses`; the server completes.

The stated motivation is to avoid *"requiring a shared storage layer across server instances or requiring stateful load balancing."*

**Why this matters here:** in the legacy era, `sampling/createMessage` and `elicitation/create` are **requests the server initiates**. In the modern era they are **a result type plus a client retry**. Maknae's vocabulary enumerated `mcp.sampling.create` as a term the daemon decides on — a shape that reflects the legacy model. Under modern MCP there is no inbound server-initiated call to decide; there is a result field to interpret and a retry to authorize.

**Consequence: the `mcp.*` term shapes in #177–#180 are era-dependent, and the assessment does not resolve that. It is design work those issues must now do.**

## 8. Authorization posture across versions

Not read in full; recorded because #168 (credential brokering) depends on it.

- `2025-03-26` — OAuth 2.1 framework introduced.
- `2025-06-18` — MCP servers classified as **OAuth Resource Servers**; **RFC 8707 Resource Indicators required of clients** *"to prevent malicious servers from obtaining access tokens"*; protected-resource metadata discovery.
- `2025-11-25` — OIDC Discovery; incremental scope consent via `WWW-Authenticate`; **Client ID Metadata Documents** as the recommended registration mechanism; RFC 9728 alignment.
- `2026-07-28` — `iss` validation per RFC 9207 required; `application_type` required in DCR; **client credentials bound to their issuing authorization server** — clients **MUST** key persisted credentials by issuer, **MUST NOT** reuse across authorization servers, and **MUST** re-register when the AS changes; **DCR deprecated** in favour of Client ID Metadata Documents.

**The `2026-07-28` credential-binding rule is directly on point for #168's subject-scoping requirement** and should be read in full before that issue is implemented.

## 9. Normative text Maknae's design already relies on

Read at the pin, quoted because #178 and #179 cite them:

- `server/tools.mdx`: *"For trust & safety and security, clients **MUST** consider tool annotations to be untrusted unless they come from trusted servers."*
- `server/tools.mdx`: *"For trust & safety and security, there **SHOULD** always be a human in the loop with the ability to deny tool invocations."*
- `client/sampling.mdx`: *"For trust & safety and security, there **SHOULD** always be a human in the loop with the ability to deny sampling requests."*
- `server/tools.mdx`: a tool's `inputSchema` **MUST** be a valid JSON Schema object (not `null`); tool names **SHOULD** be 1–128 characters and case-sensitive.

**MCP's own specification states the untrusted-annotation rule as a MUST.** #178's structural exclusion of annotations from the PDP path is conformance, not Maknae opinion.

## 10. Items of direct interest to open Maknae work

**#180 (`mcp.sampling.create`)** — the deprecation question is **settled: Sampling is deprecated as a whole**, migration path *"integrate directly with LLM provider APIs."* Combined with MRTR removing the server-initiated shape the term was written against, the disposition recorded on #180 — *"do not implement; declare no `sampling` capability; record the decision"* — is now the well-supported reading. **Operator decision, not the agent's.**

**#179 (`mcp.resource.read` / `.prompt.get` / `.message`)** — `resources/subscribe`/`unsubscribe` no longer exist in the modern era; `subscriptions/listen` replaces them. #179 already lists subscriptions as a non-goal, which holds. The `mcp.message` term maps to ACP's tunnelling method, not to anything in MCP — a distinction #177 already draws.

**#177 (`mcp.connect` / `.disconnect`)** — in the modern era there is **no connection to establish**: no `initialize`, no session, no `Mcp-Session-Id`. A "connection" is a transport-level fact (a stdio process, an HTTP origin) plus a cached era determination. **The term's meaning is era-dependent** and #177's design must account for it.

**#178 (`mcp.tool.call`)** — least affected. `tools/call` persists across all revisions read. The untrusted-annotation MUST strengthens it.

**#151 (the `maknae-mcp` epic)** — the multi-version burden is the epic's largest unscoped cost. See §11.

**#153 (LLM interface configuration)** — Sampling's migration path is *"integrate directly with LLM provider APIs,"* which is #153's subject. The deprecation removes a competing path and makes #153 the only one.

## 11. The multi-version support burden — the operator's question

**Operator input (2026-08-29):** building the Security MCP required supporting **up to four different releases**, because *"the latest isn't always complete or compatible with all agents."* This record confirms that experience generalises, and that MCP's situation is worse than a version-skew problem.

**Facts bearing on it:**

1. **Dual-era is the only interoperable posture.** Modern-only fails against every server built before `2026-07-28`; legacy-only fails against modern servers and *"has no fall-forward mechanism."*
2. **SDK and harness adoption lags the spec.** Measured in **§12** — modern-era support is uneven across the official SDKs and no handshake-era negotiation default has moved past `2025-11-25`.
3. **A feature's presence is not evidence of persistence.** JSON-RPC batching lived one revision. Roots, Sampling, Logging and DCR are deprecated with an earliest removal of *the first revision released on or after 2027-07-28*.
4. **Each supported revision is a distinct decision surface.** This is the Maknae-specific finding and the sharpest one in this record: a term decided under one revision's semantics may mean something materially different under another. Elicitation is the worked example — a **server-initiated request** in `2025-06-18`, gaining **URL mode** in `2025-11-25`, becoming **a result type plus a client retry** in `2026-07-28`. A policy written against one shape does not obviously hold against the others.

**The consequence for a reference monitor:** supporting N revisions means the deny list must hold under N sets of semantics, and the PDP must know which set a given request is being interpreted under. **The cached era determination (§4) therefore becomes an input to authorization**, not merely to transport. A wrong or stale era cache is a wrong semantics selection.

**Not decided here.** Which revisions Maknae supports is an operator decision with a real cost curve. **§12 supplies the measurement**; the choice remains the operator's.

## 12. Ecosystem measurement — what is actually implemented

**Operator input (2026-08-29):** *"The SDKs implement most. The agent harnesses do not. I had a lot of issues with Codex compatibility when Claude Code worked fine."* Measured against the SDK and harness repositories on 2026-08-29. **This section supplies the measurement §11 item 2 defers to.**

### Modern-era adoption is uneven, and no negotiation default has moved

**Corrected 2026-08-29 after review:** an earlier draft of this section claimed *"every official SDK's `LATEST` is `2025-11-25`."* **That is false for the Python SDK**, whose `LATEST_PROTOCOL_VERSION` is `2026-07-28`. The three SDKs sit at three different levels of modern-era adoption, and flattening them lost the distinction the support-set decision actually turns on.

| SDK | Handshake-era support | Modern (`2026-07-28`) support | Negotiation default |
|---|---|---|---|
| **TypeScript** | `2024-10-07` … `2025-11-25` | **absent** from `SUPPORTED_PROTOCOL_VERSIONS` | `DEFAULT_NEGOTIATED_PROTOCOL_VERSION = '2025-03-26'` |
| **Rust (`rmcp`)** | `2024-11-05` … `2025-11-25` | **known but not preferred** — `V_2026_07_28` exists, and `STANDARD_HEADERS = V_2026_07_28`, but `LATEST = V_2025_11_25` | `LATEST = 2025-11-25` |
| **Python** | `2024-11-05` … `2025-11-25` | **full** — `MODERN_PROTOCOL_VERSIONS = ("2026-07-28",)`, and `LATEST_PROTOCOL_VERSION` (any era) **is** `2026-07-28` | handshake `2025-11-25`; `server/discover` probe `2026-07-28` |

**Two claims survive the correction, and they are the load-bearing ones:**

1. **No SDK's handshake-era negotiation default exceeds `2025-11-25`**, and TypeScript's is three revisions below that at `2025-03-26`. Python states this explicitly in its own docstrings: `LATEST_HANDSHAKE_VERSION` is *"the client's offer and server's counter-offer default"* (`2025-11-25`), while `LATEST_MODERN_VERSION` is *"the `server/discover` probe default"* (`2026-07-28`). **The era determines the default, and the legacy default has not moved.**
2. **TypeScript cannot speak the modern era at all** — `2026-07-28` is not in its supported set. It carries reserved `_meta` keys commented *"for the per-request envelope (protocol revision 2026-07-28)"*, so the plumbing is being laid, but the revision is not yet offered.

**The consequence for a support-set decision is unchanged and now better grounded:** a `2026-07-28`-only implementation is unreachable by any TypeScript-SDK peer today, and is reached by a Python-SDK peer only on the modern probe path. Legacy-era support is not optional.

### The published spec set is not the deployed set

The TypeScript SDK supports **`2024-10-07`**, a revision that **does not exist in `docs/specification/` at the pin**. The set of versions in the wild is not the set of versions in the spec repository, in both directions. A support matrix derived from the spec alone is incomplete.

### The Python SDK models this best

Its `version.py` carries a comment worth reproducing, because it names a trap Maknae could walk into:

> Date-string protocol revisions happen to sort lexicographically, but versions are an enumerated set, not an ordered scalar: future identifiers are not guaranteed to be date-shaped, and unrecognized peer strings must compare conservatively instead of accidentally (e.g. `"zzz" > "2025-11-25"`).

**Do not treat protocol versions as ordered.** They are an enumerated set. Comparing them as strings is a correctness bug waiting on a non-date identifier.

### `rmcp` parses unknown protocol versions permissively — fail-open

`ProtocolVersion`'s `Deserialize` matches the five known revisions and, for anything else:

```rust
_ => {}
}
Ok(ProtocolVersion(Cow::Owned(s)))
```

**An unrecognized version string parses successfully** rather than erroring. For a general-purpose SDK that is a defensible tolerance; **for a fail-closed reference monitor it is the wrong default.** If Maknae consumes `rmcp`, rejecting unknown versions is Maknae's obligation and cannot be delegated to the type. This is the same class as ADR-0021's fail-closed rulings and the `advesary`-typo rule in `binding.rs`: an unrecognized token must refuse, never pass through.

### An official Rust SDK exists, and adopting it is a TCB decision

`modelcontextprotocol/rust-sdk` (crate `rmcp`) is the official Rust implementation. **Whether Maknae consumes it or implements the protocol itself is a real decision, not a convenience choice**, because of ADR-0002's static Rust TCB: an SDK in the trust plane is TCB surface, and its dependency tree is `deny.toml`'s problem (**#156** asks exactly whether `cargo-deny` sees the whole surface). The permissive-parse finding above is one concrete reason the answer is not automatic.

### Harness lag — a mechanism consistent with the operator's experience

**Codex pins `rmcp = "=3.1.3"`** — an exact version pin in `codex-rs/Cargo.toml`, consumed through its own `codex-rmcp-client` crate. Its MCP behaviour is therefore frozen at that release. `rmcp` 3.1.3 knows all five revisions with `LATEST = 2025-11-25`.

**A hypothesis, not a verified root cause:** the TypeScript SDK carries `DEFAULT_NEGOTIATED_PROTOCOL_VERSION = '2025-03-26'` — a deliberately conservative fallback — while `rmcp` offers `LATEST = 2025-11-25`. A client built on the TypeScript SDK therefore degrades to a three-revisions-older baseline by default, where a Rust-SDK client does not. Against a server whose negotiation is strict or whose support stops earlier, that asymmetry produces exactly the shape the operator observed: **one harness works, another fails, against the same server.**

**What would verify it:** capturing the negotiated version on both sides against a specific failing server. Recorded as a hypothesis so it is neither relied on nor lost.

**The general lesson stands regardless of the mechanism:** harness compatibility is not derivable from the specification, and is not derivable from SDK capability either. It is a property of what a given harness pins and what it offers, and it must be tested rather than reasoned about.

### There is an official conformance suite — use it

`modelcontextprotocol/conformance` (`@modelcontextprotocol/conformance`) is a maintained framework that tests **both client and server implementations** against the spec, with named scenarios and suites:

```
npx @modelcontextprotocol/conformance server --url http://localhost:3000/mcp
npx @modelcontextprotocol/conformance client --command "<client>" --suite auth
```

**This is an external, spec-authored test harness for exactly the surface #151 would build**, and it exists in the role Maknae's own gates play internally. Whatever support set is chosen, conformance runs against it are the evidence — and per the `negative-control` discipline, a conformance run that has never been observed failing proves nothing.

### What this means for choosing a support set

Not decided here; recorded so the decision is made against measurement rather than the spec's own recommendation.

- **`2026-07-28`-only is not viable today.** No official SDK defaults to it.
- **`2025-11-25` is the handshake-era ceiling** — the newest revision every SDK reaches, and the negotiation default for Python and Rust.
- **`2025-03-26` is the de-facto floor** for broad interop, because the TypeScript SDK degrades to it by default.
- **`2026-07-28` is reachable today only against a Python-SDK peer**, and only on the modern path. TypeScript does not offer it; Rust knows it but does not prefer it.
- **Dual-era support is what buys forward compatibility**, and the Python SDK's explicit handshake/modern split is the model worth copying.
- Each added revision is **a decision surface**, not just a codec path (§11 item 4). The cost is in the PDP, not the parser.

## 13. Limits of this record

- The `schema.mdx` payloads were **not** read; type-level detail (exact field names beyond those quoted, optionality, enum members) is **not** established here.
- The transport binding pages (`stdio`, `streamable-http`) were read only through the versioning page's summaries; their normative detail is **not** captured.
- The authorization pages were **not** read in full; §8 is assembled from changelog entries and is a pointer, not a substitute.
- The `draft` revision was **not** read and is non-authoritative.
- **Harness behaviour is inferred from pins and SDK constants, not observed.** §12's harness-lag mechanism is explicitly a hypothesis; no client/server negotiation was captured on the wire.
- The conformance suite was **not run**; its existence and interface are recorded, its coverage is not assessed.
- **Maknae's role (MCP client, MCP server, or both) is not settled by this record.** #151 contemplates both — brokering outbound to servers, and being a front door that Claude Code / Codex / Cursor speak MCP to directly. The era and version obligations differ by role, and that is design work.
