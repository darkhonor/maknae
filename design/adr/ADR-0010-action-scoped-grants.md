# ADR-0010: Action-scoped grants — the `roles:` surface, its precedence, and what Phase 1 deliberately withholds

- **Status:** Accepted (2026-08-31)
- **Date:** 2026-08-31
- **Deciders:** Alex Ackerman (operator)

## Context

`authz.yaml`'s grammar is a durable operator-facing contract — `maknae-config/src/authz.rs` treats it as one, and the `verb-vocabulary-drift` gate inventories every term it can name — yet no ADR governed it. Two surfaces already lived there: `permissions:`, which decides **path** access by capability pattern, and `bindings:` (#85), which maps identities to roles. Neither decides an **action**.

That gap had a concrete cost. `maknae-authz-basic`'s admin arm was keyed to the single built term `admin.whoami`, with the rest of `Class::Admin` answering `NotApplicable`. The comment on that arm named the problem precisely: a class-granular permit would grant `admin.contain`, `admin.credential.broker` and `admin.policy.reload` off an arm that keys nothing. So the vocabulary could grow, but nothing could be granted without granting everything — and the alternative, hard-wiring each term into the arm, makes every new term a code change and gives the operator no say at all.

Three `admin.*` terms are disclosure-only: `admin.status`, `admin.config.show`, `admin.subject.list`. They read state; they change none. They are the right first population for a per-action grant surface precisely because getting them wrong discloses rather than destroys.

## Decision

**1. A third top-level surface, `roles:`, decides actions. It does not extend either existing surface.**

```yaml
roles:
  admin:
    actions:
      allow: ["admin.status"]
      deny:  ["admin.config.show"]
```

`permissions:` keeps deciding paths and `bindings:` keeps deciding identity→role. An operator asking "who may do what" now has one place to look per question, and the three questions stay separable. Merging actions into `permissions:` was rejected: its entries are capability-over-glob patterns (`Read(~/**)`), and an action term is neither a capability nor a glob. It would have meant either a `Pattern` variant that matches no path, or overloading the existing ones — and `Pattern` is the type the path matcher exhausts.

**2. `Pattern` gains no variant.** Action terms are a separate closed vocabulary with a separate matcher (`ActionGrants::evaluate3_action`). Adding a non-path variant to the path pattern type would put a value into `decide_fs`'s reach that it cannot meaningfully answer.

**3. The surface is role-keyed at its root, so a role-independent grant is ungrammatical.** The brief asked for no global grant block; this is stronger than a convention against one. There is no position in the grammar where a grant can be written without naming the role it belongs to, and `ActionGrants::evaluate3_action` takes the role key as its first argument for the same reason — a one-argument form would let a future `Role::User` arm receive admin's grants by omission, which is the same flattening one layer further down, where no test would see it.

**4. Phase 1 grants for `admin` only, and refuses the other roles by NAME.** `user`, `guest` and `adversary` are real roles; `Role::from_key` returns `Some` for each. Writing one into `roles:` gets `RoleNotSupportedYet`, not `UnknownRole` — collapsing the two would tell an operator their correct spelling was a typo. What lifts the restriction is a decision about what a non-admin role may disclose, not an implementation detail; the check is one match arm.

**5. The grantable set is code-defined and unconfigurable.** `GRANTABLE_ACTIONS` is a constant in `decide.rs`. A term outside it refuses at load with the term named. `roles:` can therefore never reach a verb the decide arm does not consult, and an operator cannot grant a term the system has no arm for and then reasonably believe it took effect.

**6. `admin.whoami` is pinned OUT of that set at compile time.** It has its own unconditional arm for admins. Routing it through grants would mean an empty `roles:` block silently revokes it — a downgrade of working behaviour from a file that says nothing about `whoami`. The pin is a `const` assertion, so the mistake cannot reach a test run.

**7. Within a role, deny beats allow; above the role, ADR-0020 deny-overrides is unchanged.** The action operand answers three-valued — `AllowMatch`, `DenyMatch { source }`, `NoMatch` — and `NoMatch` is an **absence**, not a refusal: deny-by-default happens once, at `finalize`, so "no grant" stays distinguishable from an explicit deny in the audit record. A grant is a discretionary (DAC/RBAC) `Permit` and composes as one: it can never waive a mandatory `Deny`, and it never reaches a contained subject, because `Role::Adversary` denies upstream of the class match.

**8. Boot names the offending term; a per-request refusal stays anonymous.** `finish_new` returns `UnknownRole` / `RoleNotSupportedYet` / `UnknownActionTerm` with the token, into the journal where an operator is reading. The per-request path — reachable because `decide` re-reads the policy per request rather than holding a snapshot — returns `Verdict::Indeterminate` and tells the caller nothing. Both refuse; only the diagnostic differs. Symmetry here would leak policy content to a caller.

**9. The deny reason names the term in the audit trail and never on the wire.** `Verdict::Deny { reason: "denied by role grant admin.status" }` reaches the audit record; the wire receives the static "not authorized". This is the hazard the path operand already carries — where the reason embeds a filesystem path — applied to a new reason.

**10. Absent `roles:` and empty `roles:` behave identically, and the parsed field is a plain map, not an `Option`.** Unlike `bindings:`, whose presence suppresses defaults, grants are purely additive: there is nothing for an empty block to suppress. An `Option` would make the `None`↔`Some(empty)` mutant undetectable **by construction** — reported MISSED under ADR-0016's zero-missed rule with no killable test available to fix it.

**11. Downgrade is a fail-closed cliff, and that is the intended behaviour.** A policy file containing `roles:` refuses to load on any daemon predating this change: `check_known_keys` is an unknown-key gate at every level. An operator who writes grants and then downgrades gets a boot refusal naming `roles`, not a daemon that runs while silently ignoring their grants. This is the correct direction to fail, and it is the reason the unknown-key gate exists.

**12. Phase 1 ships the decision path and zero operator-visible capability.** `dispatch_verb` returns `NoBehaviour` for all three terms, so a granted `admin.status` produces a genuine `Permit`, a genuine audit record with `posture: "not-implemented"`, and discloses nothing. This is pinned by test, so Phase 2 cannot wire a disclosure without the pin turning red and forcing the question — what may a given role actually see — to be answered deliberately rather than inherited from the grant that already exists.

## Consequences

- The migration contract for Phase 2 is: add the behaviour behind the arm that already decides. Grants written today keep their meaning; what changes is what a permit produces. The `NoBehaviour` pin is what makes that a decision rather than a side effect.
- Adding a fourth grantable term is a code change (`GRANTABLE_ACTIONS`) plus a `verb-manifest.txt` row. Both are gated, so neither can be forgotten quietly.
- The shipped `packaging/common/authz.yaml` gains no `roles:` key. Nothing ships granted, and the manifest's `action` rows keep `not-granted`.
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
