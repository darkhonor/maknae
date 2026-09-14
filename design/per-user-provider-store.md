# Per-user provider configuration, and whether a database belongs in the configuration path

**Status: OPEN DISCUSSION.** Nothing here is ratified, scheduled, or committed to. This document exists to **pin the idea and its candidate shapes with a date**, in the register of [`model-conduit-policy.md`](model-conduit-policy.md), [`self-development.md`](self-development.md) and [`secrets-custody-tiers.md`](secrets-custody-tiers.md): frame the problem, record what is already true, name the open questions, decide later.

**Date opened:** 2026-09-13. **Originator:** Alex Ackerman ([@darkhonor](https://github.com/darkhonor)) — the idea, the refinement that makes it work, and the file-stays-authoritative framing are the maintainer's. **Deciders (eventual):** the maintainer.

**This is not active work.** The current milestone is Cooky (epic [#244](https://github.com/darkhonor/maknae/issues/244)); nothing here preempts it and **no issue is opened by this document**. It is adjacent to [#306](https://github.com/darkhonor/maknae/pull/306)'s open questions 15 (*where does the per-user part live, and is it configuration at all?*) and 17 (*what identifies an authorized source?*), and it is the concrete proposal those questions were holding space for.

## The idea

**A user should be able to use only the providers they have defined, from among those the system has authorized.** The maintainer's shape, 2026-09-13:

1. The **authorized list** of providers lives in **file configuration** under `/etc/maknae`, root-owned, exactly as today.
2. A **database loads that authorized list from the file** and **presents it to users**.
3. **Users define their own providers** from among the authorized set.
4. The **egress deputy leverages the database** for provider access.

The load-bearing part is item 1, and it is what makes the rest tractable: **the file remains the authority for what is authorized; the database is a projection of it plus per-user selections.** A database that *defined* authorization would put the policy that decides who may read the policy behind a network service, reverse [ADR-0005](adr/ADR-0005-enforcement-locus-tcb-boundary.md) decision 5, and make availability a dependency of *deciding*. None of that applies to a projection.

## What is already true in the code

Recorded first, because it changes what is being asked for.

1. **Per-role destination allowlists ship today.** `authz.yaml`'s `destinations:` maps a **role** to an allowlist of `provider:<name>` (`crates/maknae-config/src/authz.rs`), deny-by-default, absent-or-empty refusing every role. This is the *authorized set*, already file-resident and already decided per request by the PDP.
2. **The frame is per-request and kernel-resolved.** `EgressFrameRequest` carries `destination`, `endpoint`, `model`, `key_vault_path` and (since [#308](https://github.com/darkhonor/maknae/issues/308)) `key_field` — *"per request, never process-global (#240a I1)"*. The kernel resolves the provider record and hands the deputy the resolved values.
3. **The deputy deliberately reads almost nothing.** Its only configuration input is `/etc/maknae/egress-bounds.yaml` — `kv_mount`, `key_vault_path_prefix` and, since #240b, a `vault` block (`addr`, optional `approle_mount`) *(corrected 2026-09-14: this said "two keys")*; beside it the deputy reads its own credential set, `egress/maknae-egress-approle-id` and `egress/vault-ca.crt`, and its SecretID from `$CREDENTIALS_DIRECTORY`. The stated invariant (`crates/maknae-config/src/bounds.rs`): *"egress reads no policy and no registry; it may read its own operating bounds."*
4. **Per-role disclosure of configuration already exists.** `admin.config.show` plus the `disclose`/`omit` manifest, with an exact-inventory gate (`ci/gates/config-disclosure-drift.sh`) proving every field has a recorded decision. "Restrict who sees what by role" is, for configuration, a solved problem in this codebase.
5. **The credential layer is already plural and per-request.** `KeySource` is a seam (`read(mount, path, field)`), the cache is keyed on that triple, and `keys.rs`'s own header records why: *"At boot is single-provider thinking and fails the moment there are two."*
6. **Row-level security is already in the family, but not in the kernel.** ADR-0005 decision 6 has the knowledge lake's session label *"reused for RLS"* — while decision 5 states that Maknae *"reads only its own config (`/etc/maknae`); the standalone knowledge lake is prior-art reference — never cloned, mounted, or read at runtime."* The precedent exists and the boundary is deliberate.
7. **The only single-valued thing is the `provider` config block.** It is a map, not a sequence, and has been since [#243](https://github.com/darkhonor/maknae/issues/243). ADR-0023 pinned one provider for Cooky.
8. **Migration discipline is already owed.** [#268](https://github.com/darkhonor/maknae/issues/268) — *"migrations discipline for configuration and loop state, written before the first one is needed."* This proposal is plausibly the first one needed.

## What the refinement fixes, stated plainly

An earlier version of this discussion argued against putting policy in a database. **Those objections do not apply to the maintainer's refined shape**, and the difference is worth recording so the earlier reasoning is not cited against this:

| objection to "policy in a DB" | why the projection shape avoids it |
|---|---|
| the config **is** the policy that decides who may read the config — a bootstrap circularity | authorization is still decided from the file; the DB never defines it |
| ADR-0005 decision 5 says Maknae reads only its own config | still true: the authorized set is read from `/etc/maknae` |
| availability becomes a dependency of *deciding* | a projection can be stale or absent without changing any verdict |
| RLS restricts what the **database** returns to a **DB role**, not what Maknae discloses to a **subject** | for *presentation* that is exactly the right tool, because presentation is not enforcement |

**The last row is the substantive change.** RLS as an *enforcement* mechanism requires the database to see the subject — per-subject DB credentials, the confused-deputy problem ([#168](https://github.com/darkhonor/maknae/issues/168)). RLS as a *presentation* mechanism — "show this user the providers they may use" — is honest, read-only, and costs nothing in enforcement authority. **The distinction to hold onto: a DB row is never a grant.**

## The one half that does not survive as stated: the deputy reading the database

Item 4 — *"the egress agent can leverage the database for provider access"* — is where I would push back, for three reasons that are specific rather than general.

1. **It reverses the deputy's parsing-surface invariant on purpose-built ground.** The deputy holds the provider credential and owns the only route out. #240a gave it one tiny document and nothing else, precisely so that the most dangerous process in the system parses the least. A database client is a connection, credentials to reach credentials, TLS that must go through the pinned FIPS provider, and a registry to read — the invariant's exact negation.
2. **It creates a second resolver for one value.** The kernel resolves the provider record from the file; the deputy would resolve it from the database. They can disagree. That is the [#216](https://github.com/darkhonor/maknae/issues/216) defect — `enroll` wrote `principal.home` one way, the kernel resolved it another, and every `fs.read` was denied — and the fix there was to *stop having two resolvers*.
3. **It buys nothing the frame does not already carry.** The frame is already per-request and already kernel-resolved. Anything the deputy would learn from the database, the kernel can put on the frame — which is how `key_field` was added in #308 rather than giving the deputy a second source.

**The candidate that keeps the benefit and drops the cost: the KERNEL reads the store; the deputy stays a dumb executor.** The kernel already reads configuration and already decides; it resolves the subject's selected provider and puts it on the frame exactly as today. The database becomes a kernel-side store, the frame contract is unchanged, the deputy keeps its two-key document, and there is one resolver.

**The exception worth examining rather than dismissing** is the custody inversion from `model-conduit-policy.md`: if a user's *credential* should never be visible to the administrator's plane, then something other than the kernel must dereference it, and that is the one argument for the deputy reaching a per-user store directly. That argument is #306's question 22 and is explicitly unresolved there; it should not be settled as a side effect of choosing a configuration store.

## The engine choice is not obvious, and it follows from where enforcement lives

If **enforcement stays with the PDP** — which every consideration above says it must — then the database's RLS is only ever doing **presentation**. That reframes the engine question:

- **Postgres** gives real RLS and costs a **network service**: a port, a connection, credentials, TLS through the FIPS provider, availability, and a **second front door** into trust-plane data alongside the peercred-authenticated UDS.
- **SQLite** (embedded, pure-Rust drivers available) gives the relational model and per-user rows with **no network service and no second front door** — and **no RLS**, so per-user visibility would be enforced by the application, i.e. by the PDP.

**If RLS is only presentation, the PDP is already the enforcer, and SQLite may be the better fit.** That is a genuine conclusion rather than a preference: the feature Postgres is being chosen *for* is the feature the architecture says must not be load-bearing. Stated as a question below, not a decision.

## What this would NOT do

- **It would not make a database row an authorization.** The authorized set is the file's; a row outside it is inert, and the kernel must validate a user's selection against the **file** rather than against the projection — otherwise a direct `UPDATE` becomes privilege escalation.
- **It would not remove `/etc/maknae`.** Ownership and permission rules, the root-required sections, the classification ceiling and the audit sink stay file-resident.
- **It would not give users an endpoint of their own choosing.** `endpoint` is the release decision (`model-conduit-policy.md`); a user selects among authorized destinations and never defines one.
- **It would not make the store's availability a decision input.** A projection that is stale, empty or unreachable must degrade to "this user has selected nothing", never to "this user may use anything".

## Open questions

Numbered for citation; none are answered.

1. **Is the projection rebuilt at boot, or maintained?** A boot-time rebuild from the file is simple and cannot drift for long, but cannot reflect a file edit without a restart. A maintained projection needs a change-detection path and an answer for what a divergent row means.
2. **What validates a user's selection — the file or the projection?** It must be the file, or a database write is a privilege escalation. Where does that check run: the kernel's boot gate, per request, or both? Note the boot gate cannot validate rows that appear later.
3. **What is the write path for a user's own selection, and what authenticates it?** Today the only way into the trust plane is the UDS with `SO_PEERCRED` and live-session checks. A user writing their own row needs an authenticated path; if that is a DB connection, it is a second front door with its own credential problem — and if it is a Maknae verb, the database is an implementation detail rather than an interface.
4. **Postgres or SQLite — i.e. is RLS load-bearing?** If presentation-only, SQLite costs less and removes the network service. If RLS must enforce, the database has to see the subject, which is question 3's credential problem and [#168](https://github.com/darkhonor/maknae/issues/168)'s.
5. **Does the deputy ever read the store?** Recommended no, with the kernel resolving onto the frame. The one counter-argument is per-user credential custody (#306 question 22), which must not be settled here by accident.
6. **What does the audit record say?** A release decision names the destination. If a *selection* came from a projection, the record should be able to say which provider a subject selected and that it was inside the authorized set — otherwise an investigator cannot reconstruct why a given destination was reached. [ADR-0019](adr/ADR-0019-audit-record-model.md) would carry it.
7. **Does this make `provider` plural, and is that ADR-0023's amendment?** It presupposes several authorized providers, which is #306's question 14. This document does not decide it.
8. **What is the migration story, given [#268](https://github.com/darkhonor/maknae/issues/268)?** A schema in the trust plane is the first real migration Maknae would own, and #268 asked for the discipline to exist *before* the first one is needed.
9. **What does the dormancy test say?** ADR-0024: *"if a single-subject deployment has to do something it would not otherwise do, the mechanism is wrong."* A HomeLab operator who is the only user must not have to provision a database to register one provider. Is the store optional-with-file-fallback, or is the file path the single-user shape and the store the multi-user one — and if so, do both paths get exercised?

## Provenance

Originating discussion: maintainer and assistant, 2026-09-13, during Cooky and unrelated to the work in flight. **The maintainer's contributions:** the idea of per-user provider configuration restricted to a system-authorized set; the question of whether a Rust-interfaced database could restrict visibility by role; and — the refinement that makes the whole thing tractable — that **the database loads the authorized list from the file configuration and presents it**, rather than owning it, with policy and provider configuration layered over a file that stays authoritative.

**The assistant's contributions, as proposals in discussion:** the distinction between RLS as presentation and RLS as enforcement, and that enforcement would require the database to see the subject (#168); that a DB row must never be a grant and the kernel must validate selections against the file; the objection to the deputy reading the store, with the kernel-resolves-onto-the-frame alternative; that the engine choice follows from where enforcement lives, and that SQLite may therefore fit better than Postgres precisely because RLS should not be load-bearing; and the dormancy-test and audit-record questions. An earlier round of the same discussion argued against putting policy in a database at all; the objections that the refined shape answers are tabulated above rather than deleted, so the earlier reasoning is not later cited against this.
