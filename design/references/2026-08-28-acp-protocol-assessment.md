# Agent Client Protocol (ACP) — Protocol Reference & v1/v2 Assessment

| | |
|---|---|
| **Status** | Reference record — the base facts behind Maknae's ACP alignment (issue #67). **No dispositions ratified beyond the operator rulings noted inline.** |
| **Date** | 2026-08-28 |
| **Subject** | [`agentclientprotocol/agent-client-protocol`](https://github.com/agentclientprotocol/agent-client-protocol) — the open Agent Client Protocol. **PINNED at HEAD `9f40e018012a2634af9ecab1d89157561fcffba5` (2026-08-28T05:26:57Z).** Releases at read time: **`schema-v1.21.0`** (stable, 2026-08-20) and **`schema-v2.0.0-alpha.3`** (pre-release, 2026-08-20). |
| **Method** | **Read-only** via the GitHub API. Read in full: `schema/{v1,v2}/meta.json`, `schema/{v1,v2}/meta.unstable.json`, `schema/v2/CHANGELOG.md`, `docs/announcements/acp-v2-draft.mdx`, and `docs/protocol/v2/migration.mdx` (grep-scoped to the fs/terminal/MCP question). **NOT read:** the `schema.json` / `schema.unstable.json` payloads themselves (246–420 KB each), the v1 protocol docs, and the RFD collection. No clone, no install, no execution. |
| **Audience** | Maknae team (dual-audience: human reviewers and AI agents) |
| **Purpose** | Record the ACP facts that Maknae's action-class taxonomy and future gateway depend on, **pinned by commit**, so this research is never re-run from scratch — and so a stale recollection of ACP is never designed against. |

## 1. Why this record exists

Maknae's action-class taxonomy is ACP-anchored by operator ruling (2026-08-14, issue #67): *evaluate the published standard; adopt no framework's implementation.* PR #141 shipped that taxonomy — `liveness` / `admin.*` / `acp.session` / `acp.fs` / `acp.terminal`, closed vocabulary *(renamed to `session` / `fs` / `terminal` by #67; the `acp.` prefix bound capability domains to a protocol version v2 removes)*, exact-segment matching (`crates/maknae-authz-basic/src/decide.rs`). **That anchoring is only sound if the anchor is known precisely and by version.** It was not: the design work of 2026-08-28 was proceeding on a recollection of ACP that predated a major-version draft.

## 2. Which role is Maknae? — read this before anything else

ACP defines two roles: the **Agent** (does the work) and the **Client** (the host that provides capabilities to it). `fs/read_text_file` is a **clientMethod** — the *Client* implements it and the *Agent* calls it.

**Maknae is the Client.**

That is precisely why the shipped taxonomy carries filesystem and terminal capability classes and a live filesystem-read action (`Class::AcpFs`/`acp.fs.read` at the time of this record; renamed to `Class::Fs`/`fs.read` by #67): Maknae implements the client-side capability surface, and every agent call into it is a reference-monitor decision. It maps exactly onto core principle 1 — *the agent runtime is untrusted by design*.

**Consequence for positioning:** Maknae writes the **host side of an open protocol**. Any conforming ACP Agent interoperates — no vendor is a dependency, and no vendor SDK is on the critical path.

## 3. Method inventories, verbatim (the load-bearing table)

From `schema/{v1,v2}/meta.json` (stable) and `meta.unstable.json` (unstable):

| Client method | v1 stable | v1 unstable | v2 stable | v2 unstable |
|---|---|---|---|---|
| `session/request_permission` | yes | yes | yes | yes |
| `session/update` | yes | yes | yes | yes |
| `elicitation/create`, `elicitation/complete` | yes | yes | yes | yes |
| `fs/read_text_file`, `fs/write_text_file` | yes | yes | **NO** | **NO** |
| `terminal/create`, `terminal/output`, `terminal/release`, `terminal/wait_for_exit`, `terminal/kill` | yes | yes | **NO** | **NO** |
| `mcp/connect`, `mcp/message`, `mcp/disconnect` | no | yes | no | yes |

**v1 agent methods (stable):** `initialize`, `authenticate`, `session/new`, `session/load`, `session/set_mode`, `session/set_config_option`, `session/prompt`, `session/cancel`, `session/list`, `session/delete`, `session/resume`, `session/close`, `logout`.

**v2 agent methods (stable):** `initialize`, `auth/login`, `session/new`, `session/set_config_option`, `session/prompt`, `session/cancel`, `session/list`, `session/delete`, `session/resume`, `session/close`, `auth/logout`. *(`authenticate` → `auth/login`; `logout` → `auth/logout`; `session/load` and `session/set_mode` dropped.)*

**Unstable-only agent methods (both versions):** `providers/list|set|disable`, `mcp/message`, `session/fork`, `nes/start|suggest|accept|reject|close` (next-edit-suggestions), `document/didOpen|didChange|didClose|didSave|didFocus`.

**Protocol methods (both):** `$/cancel_request`.

## 4. v1 and v2 are two different integration models, not two dialects

Verified from `docs/protocol/v2/migration.mdx`:

> **"3. The Client file system, terminal execution, and session modes APIs are gone.** Agent-owned terminal output is a separate display-only v2 surface; **use client-provided MCP servers when the Agent needs Client-side tools.**"

> `fs/read_text_file`, `fs/write_text_file` → **Removed**. `terminal/create|output|release|wait_for_exit|kill` → **Removed**.

> *"The v1 Client capabilities `fs` and `terminal` are removed entirely... **Stable v2 currently defines no standard Client capability fields.** Agent-owned terminal display is baseline behavior, not a Client execution capability."*

> *"A Client may use an isolated terminal emulator, but it only needs to provide a safe sanitized transcript fallback. **The surface is display-only**: it has no input, resize, interrupt, kill, wait, release, or execution semantics."*

| | v1 | v2 |
|---|---|---|
| Maknae's role | **ACP Client** — implements `fs/*` and `terminal/*`, mediating every agent call | the Client capability surface **does not exist** |
| Where mediation lives | ACP client methods | **MCP servers** the Client provides into the session (`mcpServers` on `session/new`, now optional) |
| Who executes | the Client (mediated) | **the Agent** |

## 5. The trust-model divergence — the most important line in the migration guide

> **"Approval authorizes the Agent to execute the command; it never asks the Client to execute it."**

**ACP v2 assumes the Agent is trusted to execute. Maknae's core principle 1 holds that the agent runtime is untrusted.** These are opposed trust models.

It is not fatal: v2's own stated answer — *"use client-provided MCP servers when the Agent needs Client-side tools"* — is the escape hatch, and it makes **MCP the trust boundary in a v2 deployment**. But it is recorded here because it is the kind of assumption that is otherwise discovered during an integration test, not during design.

**Open, unanswered:** in a v2 deployment Maknae is an MCP server. What does that do to ADR-0005's sole-PDP locus, to the `maknae-proto` wire contract, and to the gateway design (#117)?

## 6. Version-support posture (answers "is 1.x supported long-term?")

From `docs/announcements/acp-v2-draft.mdx` (published 2026-07-20; author Ben Brandt, ACP Lead Maintainer, Zed Industries):

> **"Adding v2 support should not mean dropping v1. v1-only peers will remain common for some time, so implementers should support both versions side by side. We are working on making this easier to express in the various SDKs."**

> *"**v2 is a Draft**... various pieces can, and will, change before stabilization. As you start implementing it, gate your implementation behind the version negotiation **AND** feature flags. Don't ship it by default in production until we are closer to stabilization."*

> *"...relying on our RFD process... to guide new features landing in **both v1 and v2** as we move forward."*

**Assessment: parallel support is stated guidance, not a dated commitment.** "For some time" carries no end date, and no formal LTS or deprecation policy was found in the material read. The RFD-feeds-both-versions statement is the stronger signal of genuine parallel life.

**Operator ruling (2026-08-28, issue #67):** Maknae builds for **both**, selected by a Maknae configuration setting, until 2.0.0 finalizes — which is expected to land during Maknae's own development. This matches upstream's published guidance directly.

## 7. Governance signals

The canonical org is now the neutral **`agentclientprotocol`** (the `zed-industries/...` path still resolves). The repository carries `GOVERNANCE.md` (pointing to a published governance model), `MAINTAINERS.md`, `CONTRIBUTING.md`, a `CODE_OF_CONDUCT.md`, an RFD process with 30+ RFDs, and a `docs/announcements/` stream including a lead-maintainer announcement and a transports working group. **This strengthens the 2026-08-14 basis for the ruling** — ACP is a governed open standard with a public change process, not a single vendor's wire format.

## 8. Items of direct interest to open Maknae work

- **`session/fork`** (unstable, both versions) is the mechanism issue #7 proposed for shared channels — *"fork context and reply per subject."* Directly relevant to #147's audience-cardinality problem.
- **`session/request_permission` is ACP's approval seam.** Per the FrontierAgent assessment (2026-08-28, §3.7), human approval is **UX and never authorization**. Maknae must map it as a PEP affordance and never as a PDP verdict. v2 makes it more general (its own `title`/`description`, extensible `subject`), which widens the surface but does not change the rule.
- **`elicitation/create` / `elicitation/complete`** are stable in both versions — the Agent soliciting input. A disclosure-adjacent surface that has had no Maknae analysis.
- **Session lifecycle is richer than the current taxonomy reflects:** `session/{new,list,resume,close,delete,fork}` plus v1's `load`/`set_mode`.
- **v2 forward-compatibility convention:** enum-like values accept unknown variants with a `_` prefix for implementation-specific extensions. Relevant to any Maknae extension that must survive an ACP peer that does not know it.

## 9. Limits of this record

The JSON schemas themselves were not read — only the method inventories, the v2 changelog, the v2 announcement, and a grep-scoped pass over the v2 migration guide. Payload shapes, capability negotiation details, transport bindings, and the v1 protocol documentation are **not** covered here. Anyone designing to a specific method's parameters must read the schema at the pinned commit. GitHub content is mutable; every quotation above is from the pinned HEAD or the named release artifacts as they existed on 2026-08-28.
