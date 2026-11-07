# ADR-0032: Per-subject restrictions — the `subjects:` section, action patterns, and the site deny floor

- **Status:** Accepted (maintainer-ruled 2026-11-07)
- **Date:** 2026-11-07
- **Deciders:** Alex Ackerman (maintainer)
- **Raised by:** [#608](https://github.com/darkhonor/maknae/issues/608), part of the Agent Daemon work in [#472](https://github.com/darkhonor/maknae/issues/472)

## Context

Before #608, `authz.yaml` decided by role alone. Every account bound to `user` held the same file permission set, the same action grants and the same model choice, and the only way to give one account less was to give it a different role. Roles are compiled in (`Role { Admin, User, Guest, Adversary }`) and carry structural meaning: `guest` and `adversary` take no grants, and `admin` holds the disclosure verbs. A role is the wrong unit for "this account may read its projects but not delete them" or "this account may prompt one model only".

The Agent Daemon (#472, [ADR-0024](ADR-0024-tenancy-model-and-agent-identity.md) decision 6) makes the gap concrete. Each agent is its own service account with its own uid, and several agents on one host each need a different scope: one reads a source tree, another writes a notes directory, a third prompts a single model. Without a per-account limit, every agent bound to `user` would hold the whole site permission set.

The policy language also named actions only by exact term. A home user who wants an account to hold every file action had to list `fs.read`, `fs.write`, `fs.delete` and `fs.mkdir`, while an enterprise wants exactly that explicitness. One language has to serve both.

## Decision

### 1. `authz.yaml` gains a `subjects:` section, keyed by account name

`subjects:` maps an account name to an entry with up to three keys, each optional:

- `permissions: {allow, deny}` — path patterns in the `permissions:` grammar;
- `actions: {allow, deny}` — action patterns (decision 2);
- `models: {allow}` — `"<provider>/<model>"`, split on the first `/`.

Unknown keys at any level refuse the load. The key is additive, so `schema_version` stays `1`, and roles stay compiled in: `subjects:` declares no role and binds none. An entry only narrows. It never grants an action the subject's role does not hold: `session.prompt` still needs the role's grant, and file actions still need `admin` or `user`. A policy that does not compile refuses boot and is refused on reload, which keeps the previous snapshot. *Failure it prevents:* without a per-account entry, the only narrower scope is another role, and roles are a fixed, structural set.

### 2. Action patterns: an exact term or a family wildcard, everywhere policy names actions

An action entry is an exact term (`fs.read`, `session.prompt`, `admin.status`) or a family wildcard `<family>.*` (`fs.*`, `admin.*`, `session.*`, `terminal.*`, `mcp.*`). The families are the closed action-class vocabulary of `maknae-authz-basic`. A home user writes `fs.*`; an enterprise lists exact terms; both write the same language. The same patterns apply in a subject's `actions:` and in `roles.<role>.allow` and `deny`.

A wildcard is expanded **at compile**, against the binary's compiled action vocabulary (the grantable terms plus `fs.read`, `fs.write`, `fs.delete` and `fs.mkdir`), so the decision path compares exact terms only, and each citation keeps the entry as written. A family with no members today (`terminal.*`, `mcp.*`) expands to nothing and is accepted.

**A wildcard covers the members a later binary adds to its family.** An enterprise that wants no such growth lists exact terms. *Failure it prevents:* a wildcard frozen at the terms that existed when the policy was written would silently stop matching the family it names, and a home policy would need editing at every release.

`kernel` and `liveness` terms and families are refused in every list. `admin.whoami` is outside every subject limit, as `liveness` is: it is not in the action vocabulary, so an `actions:` list cannot name it and no list can revoke it. Every subject can always ask who it is.

In `roles:`, expansion keeps the existing role rule: a role may hold only what it could hold before (`user`: `session.prompt` only), so `user` with `admin.*` is refused at load exactly as `user` with `admin.status` is, and `admin` with `admin.*` expands to the seven grantable admin terms. `fs` terms stay ungrantable in roles, because paths decide file access. An error in `roles:` is reported as before, so the existing messages do not change.

### 3. Deny beats allow, whatever the specificity

Patterns expand first; then a deny removes its terms from the allow list. There is no most-specific-wins rule, in role grants and in a subject's `actions:` alike:

- `allow: [admin.*]` with `deny: [admin.contain]` is every admin action except `admin.contain`;
- `deny: [admin.*]` with `allow: [admin.status]` is no admin action;
- `allow: [fs.*]` with `deny: [fs.delete]` is every file action except delete.

*Failure it prevents:* a most-specific-wins rule makes a reader resolve precedence between entries to know what a list grants; deny-overrides is the rule the composition already uses ([ADR-0008](ADR-0008-authorization-composition-contract.md)), so a list reads the same way the PDP decides.

### 4. A subject's `permissions:` replaces the site allow set; the site deny set is a floor

When a subject's entry has `permissions`, its `allow` replaces the site `allow` for that subject, the site `deny` always applies, and the subject's own `deny` adds to it. Deny is decided first (site deny together with subject deny), then the subject's allow. Without `permissions`, the site set applies as before. `~` is always the requesting subject's own home, and the operating system still confines the subject to what its uid and gid can reach.

The floor exists for credentials. The shipped site deny set covers `~/.ssh`, `~/.gnupg`, `~/.vault-token`, `~/.maknae` and the other credential paths. Keeping it under every subject means a subject's own credentials can never be read through Maknae's file tools into a conversation and sent to a model. The subject's own processes still use them through the operating system (an agent's `ssh`, its Vault calls), which Maknae's path rules do not govern. *Failure it prevents:* a per-subject allow set that also replaced the deny set would let one careless `allow: ["Read(~/**)"]` expose that account's keys to its model provider.

### 5. A subject's `actions:` limits actions before the role decides

When an entry has `actions`, then for a subject whose role is `admin`, `user` or `guest`, an action in the `admin`, `session`, `fs`, `terminal` or `mcp` family, other than `admin.whoami`, that the expanded `allow` list does not contain, or that the expanded `deny` list does, is denied before the role's own rules run. An `actions:` entry with only `deny` therefore permits no limited action. The check comes after the containment short-circuit, so a contained subject's audit record still says it was contained. For file actions, the action check runs before the path check, so `fs.write`, `fs.delete` and `fs.mkdir` can be told apart although they share the `Write` path capability. Without `actions`, there is no per-subject action limit. The limit never grants. It is evaluated in its own arm of the role match because the containment-ordering gate (`ci/gates/containment-ordering.sh`) allows no code between role resolution and that match.

### 6. A subject's `models:` limits which model a prompt may use

When an entry has `models`, a `session.prompt` whose admitted `<provider>/<model>` is not listed is denied. The kernel stamps the admitted pair as the request's `model` resource attribute, beside `destination`; the `Authorizer` contract ([ADR-0004](ADR-0004-modular-authorization-architecture.md)) is unchanged. Without `models`, there is no per-subject model limit; the site `providers:` list ([ADR-0028](ADR-0028-per-user-model-providers-and-kernel-blind-credentials.md)) and the role's `destinations:` still bound the prompt.

### 7. Inert entries, exactly as for a binding

- A `models:` entry naming a provider or model that is not on the authorized site list is inert. Admission already refuses an unlisted pair, and no rule refuses across files, as for `destinations:`.
- An account name that does not resolve (after `userdel`, or after an agent is de-enrolled) makes its entry inert, decided per subject as `bindings.yaml` treats an absent name. Only a failed lookup refuses the whole load, as for bindings.
- Two names that resolve to the same uid refuse the load, because the entry that applies would be ambiguous.

*Failure it prevents:* refusing the whole policy because one account was removed would let a routine account deletion stop every decision on the host.

### 8. Citations without a graph schema change

Each written role entry, exact or wildcard, is one rule node keyed `rule:roles.<role>:<effect>:<i>` (`i` is the entry's index as written), with one `matches` edge per term it expands to; a grant cites the entry as written. Each subject's path patterns become rule nodes keyed `rule:subjects.<name>.permissions:<effect>:<i>`, linked to their section by `declared_by` only, because the schema has no subject-to-rule edge; a path verdict matched by a subject pattern cites that rule, and a deny by the site floor cites the site rule. An action-limit or model-limit refusal cites no rule node, as an absent-from-allowlist destination refusal does; its reason names the subject, the action or model, and the `subjects` section. The graph format and its schema ([ADR-0029](ADR-0029-kernel-enforcement-state-graph.md)) are unchanged, and policy stays in memory (ADR-0029 decision 2).

### 9. Agents never hold `admin`, in code (constraint on [#609](https://github.com/darkhonor/maknae/issues/609))

An agent can never be bound to the `admin` role: the binding is refused at enrollment and at every identity-layer rebuild, as a binding into `adversary` is refused. The PDP denies every `admin.*` action for an enrolled agent's uid before the role's rules and before any grant, so neither `roles:` nor `subjects:` can lift it. The one exception is `admin.whoami`, which only reports the caller's own identity. This is built in #609, where agents are enrolled; it is recorded here because it constrains every later change to roles and subjects. *Failure it prevents:* an agent is driven by model output, and an agent holding the disclosure or containment verbs could be steered by injected content into reading the configuration or releasing a contained subject. A policy file is the wrong place for that guarantee, because one edit would remove it.

Also for #609: an agent subject without a `permissions` entry holds no file access through Maknae's tools, under the site floor.

## Consequences

- One policy file expresses both a home policy (`actions: {allow: [fs.*]}`) and an enterprise one (exact terms), and the runbook (Chapter 3 §7) shows both.
- A policy that names a family will act on actions a later release adds to it. That is the stated behaviour of a wildcard, not drift.
- The decision path stays exact; only compile does pattern work. The golden matrices and the shipped-policy decision vectors pin the verdicts.
- Tools beyond the action vocabulary are not limited here: a subject's actions are the verbs the kernel actually sees, and there is no control over an unverifiable tool name. What a tool is, and how one is limited, is the slot left for the tool registry of [#477](https://github.com/darkhonor/maknae/issues/477). Terms it adds to a family are covered by a wildcard over that family (decision 2).

## Related

ADR-0004, ADR-0008, ADR-0024, ADR-0028, ADR-0029, #472, #477, #608, #609.
