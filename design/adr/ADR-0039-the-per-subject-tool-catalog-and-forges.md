# ADR-0039: The per-subject tool catalog and forges — the kernel compiles each subject's tools from the site's `tools.yaml`, its grants and a `maknae.yaml` `forges:` section into a `maknae-graph` graph; clients pull it by a digest stamp and use it as a hint, never as authority

- **Status:** Accepted (maintainer-ruled 2026-11-21)
- **Date:** 2026-11-21
- **Deciders:** Alex Ackerman (maintainer)
- **Raised by:** [#674](https://github.com/darkhonor/maknae/issues/674) (PR 2.5)
- **Amends:** [ADR-0037](ADR-0037-task-bindings-labels-and-tool-authorization.md) decisions 3 and 5; [ADR-0029](ADR-0029-kernel-enforcement-state-graph.md) (the vocabulary seam); [ADR-0033](ADR-0033-agent-identity-admission-and-tasks.md) amendment 2026-11-17, statement 2 (the tasks right)
- **Builds on:** [ADR-0036](ADR-0036-the-tool-model.md) (the tool model and `tools.yaml`); [ADR-0037](ADR-0037-task-bindings-labels-and-tool-authorization.md) (bindings, the filtered view, the reach check); [ADR-0029](ADR-0029-kernel-enforcement-state-graph.md) (`maknae-graph` and format v1); [ADR-0028](ADR-0028-per-user-model-providers-and-kernel-blind-credentials.md) (the `providers:` section, the precedent for `forges:`); [ADR-0032](ADR-0032-per-subject-restrictions.md) (per-subject lists)

## Context

[ADR-0037](ADR-0037-task-bindings-labels-and-tool-authorization.md) decision 5 says the model sees a filtered view of the tools its subject may call, and decision 3 says a client recognizes links only to a server "authorized by site configuration". Neither said how a client learns either fact. The clients (the operator's CLI and `maknae-agentd`) may not read `/etc/maknae`: `tools.yaml` lies under it in the shipped `sensitive.yaml`, and a client is untrusted ([ADR-0009](ADR-0009-subject-side-os-dac-evaluation.md)). No kernel verb returns a subject's tools, and no function enumerates a subject's `Tool(...)` grants: grants are matched only against a concrete call.

Nothing kernel-side names an authorized git server either. `binds:` holds binding kinds only. `minting.yaml` is unreadable to `maknaed`, covers GitHub only and names API hosts, not the hosts that appear in links. An entry's `network.sites` is fence: it is per entry, mixes API and crate hosts, carries no port, and ADR-0037 decision 5 forbids showing it to the model.

The maintainer's framing of the purpose, 2026-11-21: *"helping to inform models so models have less to hallucinate on, which is key for smaller models."* A small model in an airgap offered a short, true menu invents fewer tools and less syntax.

## Decision

1. **The catalog informs the model; it is never authority** (maintainer, 2026-11-21). `maknaed` decides every call as though the catalog did not exist. No decision path reads it, and the kernel never accepts a graph from a client. A pattern the catalog lists can still be refused, and a client that lists the wrong thing gains nothing by it.

2. **The catalog is compiled from the site's `/etc/maknae/tools.yaml`, never from the `/usr/share/maknae` library** (maintainer, 2026-11-21), together with the subject's grants and `forges:` (decision 6). No client reads `tools.yaml`, `maknae.yaml` or policy to build a catalog or to recognize a binding. A client still reads its own enrollment, CA and agent files, as before.

3. **The catalog is a `maknae-graph` graph in a shared `catalog` vocabulary, and one crate serves the kernel and the clients** (maintainer, 2026-11-21). The kernel builds the graph and sends its format-v1 bytes; each client decodes them against the same schema with the same codec and walks them with the same functions. Nothing defines the schema twice.
   - **Nodes:** `ENTRY` (key: the entry name; attributes: `description` when present, `executes_workspace`, `output`), `PROGRAM` (key: `<entry>/<program>`), `PATTERN` (decision 7), `BINDING_KIND` (key: `git`), `FORGE` (key: the forge name; attributes: `host`, `provider`), and `SHAPE`, reserved for #674 PR 3 and emitted by nothing yet.
   - **Edges:** `ENTRY -runs-> PROGRAM`, `PROGRAM -granted-> PATTERN`, `ENTRY -binds-> BINDING_KIND`, `BINDING_KIND -served_by-> FORGE`.
   - **The fence is outside the vocabulary.** No node kind or attribute carries a credential class, an App name, an image, a volume, a network site, `deny_args`, resources, `lifetime_max` or `isolation`, and a test pins the node kinds and attribute names against an allowlist. An entry whose name happens to equal a credential class's name is emitted only as the entry's name.
   - The catalog is not kernel enforcement state and holds no secret, so it does not live in the kernel space.
   - **Rejected:** a typed `maknae-proto` payload from which each client builds its own graph, which defines the schema twice; and clients that derive the catalog from `/etc/maknae`, which is the read this decision removes.

4. **Delivery is pull with a digest stamp** (maintainer, 2026-11-21).
   - A new verb, `tool.catalog`, returns `Payload::ToolCatalog { digest, graph }`: the subject's graph as format-v1 bytes and their SHA-256. The verb and payload are additive CBOR variants; `PROTOCOL_VERSION` is unchanged.
   - `Response` gains `catalog_digest`, omitted from the encoding when absent. It is set on the replies clients already poll, and only there: **every `TaskClaim` reply** (idle, delivered, follow-ups, closed or held), which `maknae-agentd` polls every 5 s, and **the `session.new` reply**, which starts each CLI conversation. Every other reply is byte-identical to before.
   - `maknae-agentd` fetches on its first stamped claim and again whenever a claim's stamp differs from the digest it holds. The CLI fetches on demand, with `maknae tools`. Nothing consumes the `session.new` stamp until [#479](https://github.com/darkhonor/maknae/issues/479). A fetch that is refused, or a graph that does not match its digest or does not decode, leaves the client with **no catalog**, never a stale one it cannot verify, and the client keeps working without a menu. The agent fetches at most once per new digest, not once per poll, unless a fetch got no reply (residual 7).
   - **The bound.** `TOOL_CATALOG_MAX_BYTES` is the control frame's response maximum less a 1024-byte envelope, and a test proves a catalog of that size fits the frame. A larger catalog is refused, never truncated, and the build stops as soon as its graph keys and pattern text pass the bound, before the graph is built or encoded.
   - **Rejected:** a server push channel. Every exchange today is client-initiated, one request per connection.

5. **The digest is computed from content only.** The graph is built with a fixed revision, fixed node and edge revisions and provenance, and node and edge identifiers assigned in sorted order of kind and key, so its bytes, and therefore its digest, change only when its content changes. A reload that changes nothing a subject sees leaves that subject's stamp unchanged. The kernel caches each subject's catalog and digest inside the installed policy snapshot, so stamping a reply is a lookup; a new snapshot starts with an empty cache.

6. **Authorized forges are a `maknae.yaml` `forges:` section beside `providers:`** (maintainer, 2026-11-21), with the same custody: root-owned and read by the kernel.

   ```yaml
   forges:
     - { name: github, kind: git, host: github.com,       provider: github }
     - { name: lab,    kind: git, host: gitlab.lab.local, provider: gitlab }
   ```

   - `name` is `[a-z0-9-]{1,64}` and unique; `kind` is a binding kind (`git` only today); `host` is `host[:port]`, validated by the grammar the provider endpoints use, with an optional port; `provider` is a closed set (`github`, `gitlab`) that tells a client which link forms to recognize.
   - At most 32 entries. An unknown key, a malformed entry or a duplicate name refuses start, as a malformed `providers:` does.
   - **Restart-only.** A `SIGHUP` reload does not re-read `forges:`, so a cached catalog never carries forges older than the running configuration.
   - `admin.config.show` discloses the section, under the disclosure manifest and the `config-disclosure-drift` gate.
   - **Forge hosts are link servers, not [ADR-0037](ADR-0037-task-bindings-labels-and-tool-authorization.md)'s fenced sites** (maintainer, 2026-11-21). They are sent in every catalog whose entries bind `git`, so a client can recognize a link and refuse one to an unauthorized server. A forge grants no network reach: container network sites stay fenced, decided per `CONNECT`, and never sent. The same list is what #168 slice 4's intake check validates a binding's server against.
   - **A per-user `~/.maknae/forges.yaml` lands with [#479](https://github.com/darkhonor/maknae/issues/479)** (maintainer, 2026-11-21), for a person's own CLI-session bindings. It will be snapshotted per conversation, as the personal `sensitive.yaml` is, and add recognition only, never reach. Tasks do not need it: an agent reaches only forges where the site gave it a credential, so the site list is complete for tasks.
   - **A per-role forge grant (`destinations: forge:<name>`) is not built.** A task's reach is already bounded by the provider access of both its tasker and its agent.

7. **Enumeration.** `maknae-authz-basic` enumerates a subject's catalog from the installed snapshot.
   - **The lists** are the ones the PDP evaluates, in its order: the site list or the subject's replacing list ([ADR-0032](ADR-0032-per-subject-restrictions.md)), and for an agent its `policy.yaml` list. They come from a read-only accessor over the PDP's own list selection, and a test pins that its stages are the lists the PDP uses. The PDP's decision functions are unchanged.
   - **`PATTERN` nodes are the entry's own ceiling subcommand patterns from `tools.yaml` that some effective allow overlaps.** Two patterns overlap when some argv could match both, compared position by position: a literal overlaps an equal literal or a wildcard, `prefix*` overlaps a token with that prefix, a final `*` absorbs the rest, and a bound value overlaps anything. The model sees the true allowed forms (a posting entry's exact review shapes, not the grant's `pr review *`). #674 PR 3's shapes replace these patterns.
   - **A ceiling pattern is dropped only when a deny provably covers it:** the same entry and program, and every argv the pattern admits also matches the deny. Otherwise it stays.
   - An entry appears iff it is enabled and keeps at least one pattern.
   - **An agent's catalog leaves out entries refused in tasks:** those whose credential class's kind implements no reach check ([ADR-0037](ADR-0037-task-bindings-labels-and-tool-authorization.md) decision 7) and those whose credential names a class that does not exist. Entries with `credential: none` stay. The model is not offered a tool its task will refuse.
   - **A contained subject, an adversary or a subject that holds no role gets an empty catalog.** `tool.catalog` builds through one snapshot that both admits the subject and enumerates its catalog; a subject that snapshot does not admit is refused.
   - **`tool.invoke` is not required.** It is not grantable until #674 PR 3 or #479, and requiring it would empty every catalog.

8. **`tool.catalog` is a decided, subject-limitable action term.** The shipped `authz.yaml` grants it to `admin` and `user`; `guest` holds no grant. It joins every agent's built-in tasks right ([ADR-0033](ADR-0033-agent-identity-admission-and-tasks.md), amendment 2026-11-17), because an agent needs its menu to work, so an agent `policy.yaml` whose `actions.deny` covers it refuses to load, as one covering a session action does. A subject without the grant still receives stamps; a stamp is not a grant, and its client stops asking after one refusal per digest. The trail record for `tool.catalog` cites the digest, never the graph bytes. The disclosure gate classifies the payload as subject-scoped opaque bytes released only on a `tool.catalog` permit, as it does a prompt reply; that the fence stays out of those bytes is pinned by a sentinel test over the encoded catalog, not by the disclosure manifest.

9. **Clients.** `maknae-loop` owns the one client holder, used by `maknae-agentd`, and the one verifier (`catalog::verify`: the digest check, then the decode), which the holder and `maknae tools` both call. The walk functions `entries`, `entries_for_binding`, `forges` and `patterns` live in `maknae-graph`'s `catalog` module, beside the schema, not on the holder. The first human-visible consumer is `maknae tools`, which lists the subject's entries and patterns from the catalog. The model menu ([#479](https://github.com/darkhonor/maknae/issues/479)) and binding recognition (#168 slice 4) consume the holder later.

## Consequences

- **Residuals.**
  1. **Enumeration is conservative.** A catalog may list a pattern that a concrete call still refuses: a deny that refuses only some argv a pattern admits, a positional deny, a bound value the call does not carry, or a mandatory operand. The kernel decides the call, and the refusal says "not available".
  2. **A reload racing a reply delays the change by at most one poll.** The stamp is taken from the snapshot installed when the reply is written, so a reload that lands just after is seen on the next `TaskClaim` reply, about 5 s later.
  3. **A catalog is only as fresh as the client's last fetch.** An agent sees a change within one poll. `maknae tools` fetches afresh each time it runs; no CLI conversation holds a catalog until #479.
  4. **The client side is untrusted.** A compromised client can ignore, alter or invent a catalog; it gains no authority by doing so, because nothing decides from it. The catalog bounds what an honest client offers a model, not what a subject can ask for.
  5. **An entry's `description` is administrator text sent to the model.** The vocabulary keeps the fence's fields out, but it cannot stop an administrator writing a credential class or a site into a description.
  6. **A rejected catalog is dropped silently.** A reply whose bytes do not match its digest, or that does not decode, leaves the agent with no catalog and no diagnostic. The catalog is a hint, and the only cause would be a kernel defect.
  7. **Only an answered fetch that yields no catalog suppresses a refetch.** A refusal, a reply frame that does not decode, a digest mismatch or a graph that does not decode leaves the agent with no catalog until its stamp next changes. A fetch that got no complete reply frame (a connection, I/O, timeout or end-of-stream error) is retried on the next claim, so its pace is the poll's. An accepted catalog suppresses nothing: if it arrived under another stamp, that stamp is fetched when it next appears.
- **The tasks right grows.** An existing agent `policy.yaml` that denies `tool.*` or `tool.catalog` stops loading after this change, with the reason named.
- **Built (#674 PR 2.5):** `forges:`; pattern rendering, overlap and cover; the `catalog` vocabulary and its walks; the enumeration and per-snapshot cache; the verb, payload, stamp and bound; the decision arm and grants; the client holder, the verifier and `maknae tools`. **Owed:** shapes (#674 PR 3; the `SHAPE` node kind is reserved and nothing emits it); the CLI and run-path consumers, among them the model menu, the `session.new` stamp and the per-user `forges.yaml` (#479); binding recognition and reach against `forges:` (#168 slice 4).
- **Amended in place:** [ADR-0037](ADR-0037-task-bindings-labels-and-tool-authorization.md) decision 3 (the authorized server is `forges:`) and decision 5 (the filtered view reaches clients as this catalog); [ADR-0029](ADR-0029-kernel-enforcement-state-graph.md) (the `catalog` vocabulary uses the seam it names); [ADR-0033](ADR-0033-agent-identity-admission-and-tasks.md) amendment 2026-11-17, statement 2 (the tasks right includes `tool.catalog`).

## Security control mapping (informative; per ADR-0001)

| Property | Control | Status |
|---|---|---|
| The catalog is never an input to a decision; the kernel never accepts one from a client | NIST SP 800-53 rev 5 AC-3 (access enforcement) | Implements |
| A subject's catalog lists only entries its own grants overlap; contained subjects and adversaries get none | AC-6 (least privilege) | Implements |
| No credential class, image, site, volume or argument denial enters the catalog's vocabulary | AC-4 (information flow enforcement) | Implements |
| `tool.catalog` is decided per request and its record cites the digest, never the bytes | AU-3 (content of audit records) | Implements |

## References

- [ADR-0009](ADR-0009-subject-side-os-dac-evaluation.md), [ADR-0028](ADR-0028-per-user-model-providers-and-kernel-blind-credentials.md), [ADR-0029](ADR-0029-kernel-enforcement-state-graph.md), [ADR-0032](ADR-0032-per-subject-restrictions.md), [ADR-0033](ADR-0033-agent-identity-admission-and-tasks.md), [ADR-0036](ADR-0036-the-tool-model.md), [ADR-0037](ADR-0037-task-bindings-labels-and-tool-authorization.md)
- [#674](https://github.com/darkhonor/maknae/issues/674), [#479](https://github.com/darkhonor/maknae/issues/479), [#168](https://github.com/darkhonor/maknae/issues/168)
