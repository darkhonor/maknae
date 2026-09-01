# ADR-0010: Action-scoped grants — the `roles:` surface, its precedence, and what Phase 1 deliberately withholds

- **Status:** **Proposed — and staying Proposed** (operator ruling 2026-08-31).
  Not a pending signature: this ADR is **expected to change as the rest of the
  verb vocabulary is built**, and it is deliberately not being accepted until it
  has been tested against terms that are not disclosure-only. Three of roughly
  sixty verbs are grantable today; the decisions below were reasoned from those
  three, which is a narrow base for a contract that will eventually govern all
  of them.
- **Date:** 2026-08-31
- **Author:** implementing agent (#162) · **Ratifier:** deferred by operator ruling
- **Operator rulings recorded 2026-08-31:** decisions **4** (admin-only, and the
  correction to why), **13** (no `actions:` level), **14** (`permissions:` stays
  separate) and **15** (`admin.config.show` discloses the full effective
  configuration with secret values masked). Held Proposed regardless — these
  settle four questions, not the design.

> **Read this before building on anything below.** The decisions here are
> **provisional**, not settled constraints. State-changing terms
> (`admin.contain`, `admin.credential.broker`, `admin.policy.reload`), the
> `session.*`, `terminal.*` and `mcp.*` classes, and any term that takes an
> operand will each test assumptions that three read-only `admin.*` terms could
> not. Where one of them breaks a decision here, **the decision is what gives
> way** — correct it in place with a date, per the discipline `AGENTS.md` sets
> for itself. Do not treat a numbered decision below as a reason not to change
> the design; treat it as the reasoning that was available when only three
> terms existed.
>
> What is NOT provisional is the shipped behaviour: deny-overrides composition,
> containment preceding the class match, the deny reason staying off the wire,
> and Phase 1 disclosing nothing. Those are enforced by gates and tests, not by
> this document.

## Context

`authz.yaml`'s grammar is a durable operator-facing contract — `maknae-config/src/authz.rs` treats it as one, and the `verb-vocabulary-drift` gate inventories every term it can name — yet no ADR governed it. Two surfaces already lived there: `permissions:`, which decides **path** access by capability pattern, and `bindings:` (#85), which maps identities to roles. Neither decides an **action**.

That gap had a concrete cost. `maknae-authz-basic`'s admin arm was keyed to the single built term `admin.whoami`, with the rest of `Class::Admin` answering `NotApplicable`. The comment on that arm named the problem precisely: a class-granular permit would grant `admin.contain`, `admin.credential.broker` and `admin.policy.reload` off an arm that keys nothing. So the vocabulary could grow, but nothing could be granted without granting everything — and the alternative, hard-wiring each term into the arm, makes every new term a code change and gives the operator no say at all.

Three `admin.*` terms are disclosure-only: `admin.status`, `admin.config.show`, `admin.subject.list`. They read state; they change none. They are the right first population for a per-action grant surface precisely because getting them wrong discloses rather than destroys.

## Decision

**1. A third top-level surface, `roles:`, decides actions. It does not extend either existing surface.**

```yaml
roles:
  admin:
    allow: ["admin.status"]
    deny:  ["admin.config.show"]
```

`permissions:` keeps deciding paths and `bindings:` keeps deciding identity→role. An operator asking "who may do what" now has one place to look per question, and the three questions stay separable. Merging actions into `permissions:` was rejected: its entries are capability-over-glob patterns (`Read(~/**)`), and an action term is neither a capability nor a glob. It would have meant either a `Pattern` variant that matches no path, or overloading the existing ones — and `Pattern` is the type the path matcher exhausts.

**2. `Pattern` gains no variant.** Action terms are a separate closed vocabulary with a separate matcher (`ActionGrants::evaluate3_action`). Adding a non-path variant to the path pattern type would put a value into `decide_fs`'s reach that it cannot meaningfully answer.

**3. The surface is role-keyed at its root, so a role-independent grant is ungrammatical.** The brief asked for no global grant block; this is stronger than a convention against one. There is no position in the grammar where a grant can be written without naming the role it belongs to, and `ActionGrants::evaluate3_action` takes the role key as its first argument for the same reason — a one-argument form would let a future `Role::User` arm receive admin's grants by omission, which is the same flattening one layer further down, where no test would see it.

**4. `admin.*` terms stay admin-only** (operator ruling 2026-08-31). `user`, `guest` and `adversary` are real roles; `Role::from_key` returns `Some` for each, so the admin-only rule is a second check. Writing one into `roles:` gets `RoleNotSupportedYet`, not `UnknownRole` — collapsing the two would tell an operator their correct spelling was a typo.

A site that wants a person to hold `admin.*` **moves that person into the admin role**; it does not grant admin terms to `user`. That is the intended path, and it is simpler than a per-role disclosure matrix.

> **The framing this ADR originally gave decision 4 was wrong, and the correction matters more than the decision.** It said the restriction is lifted by "a decision about what a non-admin role may disclose." That assumes the four roles are the model. They are not: **`admin` / `user` / `guest` / `adversary` are the DEFAULT SHIPPED roles, not the universe of roles.** The end state is site-defined roles, and this issue's code makes the role vocabulary arbitrary — `Role::from_key` is a closed four-arm match, and `RoleNotSupportedYet` exists only because of it.
>
> **So what this constrains is not who may disclose what; it is sites defining their own roles.** That constraint is a Phase-1 artifact and is expected to go. When it does, `Role::from_key`, `UnknownRole` and `RoleNotSupportedYet` all change shape together, and decision 3's role-keying is what makes that survivable — grants are already keyed by role name rather than by a hard-wired enum position.

**5. The grantable set is code-defined and unconfigurable.** `GRANTABLE_ACTIONS` is a constant in `decide.rs`. A term outside it refuses at load with the term named. `roles:` can therefore never reach a verb the decide arm does not consult, and an operator cannot grant a term the system has no arm for and then reasonably believe it took effect.

**6. `admin.whoami` is pinned OUT of that set at compile time.** It has its own unconditional arm for admins. Routing it through grants would mean an empty `roles:` block silently revokes it — a downgrade of working behaviour from a file that says nothing about `whoami`. The pin is a `const` assertion, so the mistake cannot reach a test run.

**7. Within a role, deny beats allow; above the role, ADR-0020 deny-overrides is unchanged.** The action operand answers three-valued — `AllowMatch`, `DenyMatch { source }`, `NoMatch` — and `NoMatch` is an **absence**, not a refusal: deny-by-default happens once, at `finalize`, so "no grant" stays distinguishable from an explicit deny in the audit record. A grant is a discretionary (DAC/RBAC) `Permit` and composes as one: it can never waive a mandatory `Deny`, and it never reaches a contained subject, because `Role::Adversary` denies upstream of the class match.

**8. Boot names the offending term; a per-request refusal stays anonymous.** `finish_new` returns `UnknownRole` / `RoleNotSupportedYet` / `UnknownActionTerm` with the token, into the journal where an operator is reading. The per-request path — reachable because `decide` re-reads the policy per request rather than holding a snapshot — returns `Verdict::Indeterminate` and tells the caller nothing. Both refuse; only the diagnostic differs. Symmetry here would leak policy content to a caller.

**9. The deny reason names the term in the audit trail and never on the wire.** `Verdict::Deny { reason: "denied by role grant admin.status" }` reaches the audit record; the wire receives the static "not authorized". This is the hazard the path operand already carries — where the reason embeds a filesystem path — applied to a new reason.

**10. Absent `roles:` and empty `roles:` behave identically, and the parsed field is a plain map, not an `Option`.** Unlike `bindings:`, whose presence suppresses defaults, grants are purely additive: there is nothing for an empty block to suppress. An `Option` would make the `None`↔`Some(empty)` mutant undetectable **by construction** — reported MISSED under ADR-0016's zero-missed rule with no killable test available to fix it.

**11. Downgrade is a fail-closed cliff, and that is the intended behaviour.** A policy file containing `roles:` refuses to load on any daemon predating this change: `check_known_keys` is an unknown-key gate at every level. An operator who writes grants and then downgrades gets a boot refusal naming `roles`, not a daemon that runs while silently ignoring their grants. This is the correct direction to fail, and it is the reason the unknown-key gate exists.

**12. Phase 1 shipped the decision path and zero operator-visible capability.** `dispatch_verb` returned `NoBehaviour` for all three terms, so a granted `admin.status` produced a genuine `Permit`, a genuine audit record with `posture: "not-implemented"`, and disclosed nothing. This was pinned by test, so Phase 2 could not wire a disclosure without the pin turning red and forcing the question — what may a given role actually see — to be answered deliberately rather than inherited from the grant that already exists.

> **Corrected in place 2026-08-31 — the pin has since fired, once, and this decision no longer holds for all three terms.** `admin.config.show` gained a dispatch (`Dispatch::ConfigShowRequested`) and now returns a `ConfigView`; the pin went red exactly as designed and was narrowed to `admin.status` and `admin.subject.list`, which keep it. **Decision 15 below is what answered the question for `config.show`** — read it before relying on anything in this paragraph.
>
> This correction is made in the decision itself rather than only in decision 15, because appending was the mistake: `AGENTS.md` §Conventions says a semantic correction goes in the artifact, and the failure it names is precisely a reader who stops at the superseded text. A reader who stopped here concluded the term discloses nothing, thirty lines above the decision that says it discloses most of the configuration.

**13. There is no `actions:` level. The grammar is `roles.<role>.{allow, deny}`** (operator ruling 2026-08-31).

The level was introduced speculatively, to leave room for a `paths:` or `resources:` sibling beside `actions:`. Decision 14 rules that universal path permissions stay in `permissions:`, which removes the only sibling it was reserving space for. A nesting level held open for a guest who is not coming is verbosity every operator pays for and no one spends.

Removing it also collapsed two parse paths into one: an entry with no lists and an entry with an empty list block were distinct arms reaching the same empty grant, and are now a single arm with a single test.

```yaml
roles:
  admin:
    allow: ["admin.status"]
    deny:  ["admin.config.show"]
```

**14. Two grant surfaces now ship, and one of them is still role-blind. Recorded as a deviation, not a win.**

Decision 3 says a role-independent grant is ungrammatical, and that is true of `roles:`. It is **not** true of the file: `permissions:` remains a live, global, role-blind grant surface — `Read(~/**)` applies to every role that reaches the `fs.read` arm. So against brief §6's "no global block", the system as shipped has one.

**Operator ruling 2026-08-31: leave them separate.** A *universal* permission — one that holds for every role, by construction, with no per-role list to audit — is a solid use case in its own right, not merely the state we happen to be in. Folding path grants into `roles:` would lose that property and would change the meaning of every existing `permissions:` block. Revisitable; not now.

**15. `admin.config.show` discloses the FULL effective configuration, with secret VALUES masked** (operator ruling 2026-08-31). Not a curated subset: the effective composed settings as the daemon actually resolved them, which is what makes the term worth having for an operator debugging a deployment.

Secret values are replaced by a presence marker — `<value set>` — so the disclosure says **that** a setting is configured without saying **what** it is.

**How that is implemented, and the correction that got it there.** The mechanism is deny-by-default over a code-declared allowlist (`DISCLOSABLE`), not a denylist of names that look secret: a denylist defaults every FUTURE field to disclosed and depends on whoever adds one remembering to classify it, which is the `~/.ssh/id_*` shape this project has already rejected once.

> **Corrected 2026-08-31, after review.** The first implementation shipped that mechanism with a ONE-ENTRY allowlist, which honoured the mechanism and quietly failed this ruling — an operator would have seen `core.deployment_id` and nothing else, from a decision that says "full effective set". Deny-by-default and the ruling are only in tension if the classification work is skipped. Every field **the schema reference (`docs/configuration.md` §4/§5) defines** is now classified individually — disclosed, masked, or omitted. *(Corrected again 2026-09-01: the allowlist was first built by reading this crate's Rust parsers, which cannot see `core.schema_version` or `core.identity.*` — those are carried verbatim for their consumers, so no parser in `maknae-config` names them. The documented minimal config consists of little else, so masking them reproduced the very "operator sees almost nothing" failure this banner was written about, on the exact shape the docs tell operators to write. **The authority is the UNION, and naming a single artifact is what went wrong twice.**)*

> **Corrected again 2026-09-01.** The banner above named `docs/configuration.md` as *the* authority. It documents `core` (§4) and `lake` (§5) and nothing else — it is silent on `vault`, `transport`, `audit` and `principal`, which `boot.rs` registers today and which hold thirteen of the nineteen disclosed entries and the suppression the whole mechanism was built for. So the second banner sent the next author to an empty grep, exactly as the first sent them to a parser that names nothing.
>
> **The fix is not a third instruction.** `ci/gates/config-disclosure-drift.sh` enumerates the surface — every field of the declared config structs must carry a recorded decision; the code's two lists must agree with the manifest exactly in both directions; the SURFACE inventory is cross-checked against the `SectionSpec` registrations in `boot.rs`, with the number resolved asserted equal to the number registered, so a registration form the gate cannot read is a hard failure rather than a silent gap; each entry declares its field count, so a dropped field or a dropped entry changes a number someone must edit deliberately; and a field whose TYPE is a SUBTREE — a config struct, an enum, a `HashMap`/`BTreeMap`, `serde_json::Value`, or this crate's own map-bearing `Value` — must carry its own coverage, because a scalar turning into one of those otherwise changes no count at all. *(Precise scope, recorded because an over-broad claim is what this gate replaced: sections carried **verbatim** — `core.*`, `lake` — belong to no struct, so their manifest rows are not gate-derived. Adding to `DISCLOSABLE` is still caught in both directions. What is NOT gate-derived and rests on review: a new verbatim `core.*` key, and a deployer-invented key inside any section — no section parser rejects unknown keys within its own block, so `vault: { my_notes: … }` loads and its key name is disclosed with the value masked.)* Adding a config field without deciding its disclosure now fails CI. The completeness of this control no longer rests on prose telling someone where to look, because that prose has been wrong every time it was written. None of the disclosed fields carry secret material, because Maknae's secrets are not in `maknae.yaml` at all (they arrive via `$CREDENTIALS_DIRECTORY` and sealed files under `private/`, which this view never reads). What deny-by-default still buys is that a field added *tomorrow* masks until someone classifies it too.
>
> **Also corrected: settings the daemon resolved but the file never stated.** `transport:` is absent from the shipped skeleton, so it is absent from the `Document` — while the daemon is very much running on its defaults. Reporting no `transport` section tells an operator those settings do not exist, which is worse than masking them. Resolved values are folded in at boot (`Document::merge_resolved`) under the same classification. "As the daemon actually resolved them" is the phrase in this ruling, and the first implementation did not honour it.

**The view has THREE disclosure states, not two** — a distinction added 2026-09-01 after review, and the reason this decision could not be read correctly before:

| state | rendering | when |
|---|---|---|
| disclosed | the value | the path is on `DISCLOSABLE` |
| **masked** | `<value set>` | a value withheld, but the key's presence is unremarkable |
| **omitted** | *the key does not appear at all* | the field's mere EXISTENCE is the disclosure (`SUPPRESSED`) |

plus `<not set>` for a field that is present-but-valueless or resolved to nothing — distinct from masked, because "not configured" and "configured, not shown" are different answers to the operator's question.

**Omission exists because masking was not enough.** `vault.insecure_plaintext_secret_path` appears only on a host enrolled with `--insecure-plaintext-secret`; showing its key while masking its value still discloses that the host keeps an AppRole SecretID in plaintext on disk. `core.handling.*` is the same shape: the ceiling block is absent unless a deployment configured an above-baseline one, so a masked key announces that it did. `audit.au3_1` is the third: its sub-paths are deployer-authored strings with no schema, so a code-declared path allowlist is structurally incapable of enumerating them, and "unclassified therefore withheld" silently degraded to "unclassified therefore the key NAME ships". **`lake` is the other subtree in that condition** — registered but inert, its keys and shape unvalidated (`docs/configuration.md` §5) — and it was carried as a mask while this paragraph said "that subtree alone". Corrected 2026-09-01: the wording was the reason the sibling case sat unfixed.

**All four are omitted by prefix**, so a leaf added under any of them later is covered without anyone remembering. Three are genuine subtrees (`core.handling`, `audit.au3_1`, `lake`); `vault.insecure_plaintext_secret_path` is a single leaf whose *existence* is the signal. *(The count read "all three" until 2026-09-01 — appended to without recounting, in the same sentence whose earlier wording this paragraph is correcting. That is the failure mode being described, committed while describing it.)*

**Withheld, each with its reason** (recorded next to the list in `document.rs`, because "absent from the list" and "considered and withheld" are different states and only one survives review): `audit.au3_1` — **omitted, above** (not merely masked; the first decision applied the value rule to a key problem). `audit.siem` — an offload endpoint with no schema, no validator and no consumer, whose common real-world shapes embed a credential in the URL. `core.handling.*` — omitted, above. `lake` — **omitted, above**; "no parser reads it" is the premise of that conclusion, not of masking.

This is the ruling Phase 2 was blocked on. It settles `admin.config.show`; `admin.status`'s and `admin.subject.list`'s response shapes remain open, and neither is a disclosure question of the same weight.

**16. `admin.status` discloses version, protocol version, listener, and the deciding backend.** All four are deployment shape, none is a credential. The verb's own wire doc warns it is *"useful to an operator, and useful to an attacker fingerprinting the deployment"* — true, and it is why the term ships **ungranted** and admin-only. Once an operator has granted it, withholding the daemon's own version from them protects nobody: any peer that completed a handshake already knows the protocol version, and the socket path is disclosed by `admin.config.show` on the same reasoning. `authz_backend` is asked of the PDP rather than hardcoded — with the classification library present the deciding backend is not `-basic`, and an operator debugging a verdict needs to know which one produced it. **`ConjunctionAuthorizer` implements it too**, joining its operands' names: taking the `unknown` default there would have made this field useless in the one deployment that motivates disclosing it. Correspondingly, `subjects()` on the composed authorizer answers **only when exactly one operand can enumerate** — two answering operands are two different claims about who holds what, and this layer has no basis to pick one or merge them; under deny-overrides a merged list would not describe the composed decision either.

**17. `admin.subject.list` reads bindings LIVE, through the seam — never from a boot snapshot.** This is the one place Phase 3 could not reuse the `config.show` pattern. The configuration is fixed until restart, so redacting it once at boot is correct. **Bindings are not**: `decide` re-reads the policy per request precisely so a containment edit bites on the next one, and a boot snapshot would report authorization state the PDP is no longer using. Disclosing *stale* authorization state is worse than disclosing none.

So `Authorizer` gains two defaulted, object-safe methods — `subjects()` and `backend_name()` — rather than the kernel reading policy itself, which would put policy parsing back inside the TCB the seam exists to keep it out of ([ADR-0004](ADR-0004-modular-authorization-architecture.md)). `subjects()` returns `Option`: `None` means *this backend cannot enumerate*, which the kernel reports as unavailable and **never as an empty list** — "no bindings exist" is a different and dangerous claim. `-basic` returns `None` on any failure to read or validate, for the same reason.

It reports what the **policy file binds**. The default-role fallback — an enrolled uid resolving to admin when no `bindings:` key is present — is a decision rule, not a binding, and listing it as one would tell an operator a binding exists that they could then look for in the file and fail to find.

## Consequences

- Building a remaining term means adding behaviour behind the arm that already decides. The `NoBehaviour` pin is what made that a decision rather than a side effect. *(Corrected 2026-09-01: this said it "still covers `admin.status` and `admin.subject.list`". It does not — the pin fired a second time when those two gained dispatches, and is **retired**: there are no grantable terms left for it to cover, so keeping it would keep a test that asserts nothing. What replaces it is a per-term dispatch assertion plus a check that the ungrantable rest of `admin.*` still has no behaviour. The first half of this bullet was rewritten in the same commit that retired the pin; the second half was edited around.)*

  > *Corrected 2026-09-01: this bullet called that a "migration contract" and reasoned about grants "written today keeping their meaning". **Nobody has written any.** Maknae is pre-release in a private repo with no users, no deployments, and no `roles:` key in anything shipped — so there is nothing to migrate and no compatibility to preserve. That framing is the breaking-change topic the operator ruled out (see AGENTS.md), reappearing in different words. The grammar and this design can be changed outright, by whoever needs to, without a migration story.*
- Adding a fourth grantable term is a code change (`GRANTABLE_ACTIONS`), a `grantable` row in `verb-manifest.txt`, **and** an `action` row for the same term — the gate enforces `grantable ⊆ action`, so a grant cannot name something no request will ever carry. All three are gated; none can be forgotten quietly.
- The shipped `packaging/common/authz.yaml` gains no `roles:` key: nothing ships granted. The three terms' `action` rows read `not-granted-but-grantable`, distinguishing them from `admin.contain` and its siblings, which are `not-granted` and can never be granted at all — an auditor reading the primary row must not get the wrong answer.
- `roles:` is a fourth closed vocabulary in `verb-vocabulary-drift`, inventoried exactly in both directions like the other three.
- Granting `user` or `guest` requires superseding decision 4 — deliberately, since it is a disclosure decision and not an implementation one.

## References

- #162; #67 spec D3 (individual decidability); #85 (`bindings:`, `Match3`)
- [ADR-0020](ADR-0020-access-control-model-and-vocabulary.md) — deny-overrides composition, DAC/RBAC vocabulary
- [ADR-0008](ADR-0008-authorization-composition-contract.md) — no operand fails open; unknown vocabulary denies
- [ADR-0004](ADR-0004-modular-authorization-architecture.md) — the `maknae-security` seam
- [ADR-0016](ADR-0016-risk-tiered-test-coverage.md) — the zero-missed rule behind decision 10
- `crates/maknae-config/src/authz.rs` (grammar); `crates/maknae-authz-basic/src/decide.rs` (`GRANTABLE_ACTIONS`, the arm); `crates/maknae-authz-basic/src/lib.rs` (`validate_grants`)
- `ci/gates/verb-vocabulary-drift.sh`, `ci/gates/verb-manifest.txt`
