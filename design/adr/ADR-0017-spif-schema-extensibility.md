# ADR-0017: SPIF schema & multi-system extensibility contract

- **Status:** Proposed (consolidates the SPIF-schema decisions accreted across ADR-0008 amendments; ratification gated with EPIC #33 Day-1 completeness alongside ADR-0008)
- **Date:** 2026-08-08
- **Deciders:** Alex Ackerman (operator), Claude (pair)
- **Addresses:** EPIC #33 issue #31 (SPIF cross-marking constraint system — grows the SPIF schema); consolidates SPIF-schema decisions from #25 (`home_nation`), #26 (coalition registry), #27 (`classified_floor`), and #31 (`expandable`, constraint table, regime semantics).
- **Relationship:** ADR-0008 (classification lattice & dominance engine) *consumes* the SPIF; it will point to this ADR for "what a SPIF declares" at the epic-end ADR-0008 consolidation (no such pointer exists in ADR-0008 yet). This ADR is the schema of the consumed input — NOT the lattice/decision logic (ADR-0008), NOT SPIF *generation* / cross-surface oracle independence (ADR-0013 / #18), NOT storage/label integrity (ADR-0004). SPIF generation and provenance are out of scope here: this ADR governs what a *validated* SPIF may declare and how the engine consumes it.

## Context

The SPIF (Security Policy Information File) is `maknae-dcs-core`'s consumed **Tier-0 input**: the machine-readable rulebook that parameterizes every decision. ADR-0008 §1 fixed the principle that policy lives in the SPIF, not the engine ("category *kind* lives in the SPIF, not on the label"). Since then the SPIF schema has accreted across issues — `levels`, `categories`, the global coalition registry, `home_nation` (#25), `classified_floor` (#27), `expandable` (#31 scaffold) — and #31 grows it materially again (a cross-marking constraint table and regime-dependent absence semantics).

Two forces make this worth consolidating into one ADR now:

1. **The distinguishing thesis.** The engine's value — and the potentially-patentable element (operator direction, recorded in ADR-0008's #27 amendment) — is that *one* engine adjudicates *multiple national classification systems by data alone*. That thesis lives or dies in the SPIF schema. It is the **contract to maintain**, not a fact already fully achieved: the schema methods (`rank`, `is_classified`) carry no policy constant, but `validate_label` and the controls axis still hold US literals today (§1a) — naming that gap honestly is precisely how the schema avoids quietly baking in US structure.
2. **Relitigation.** SPIF-schema decisions are currently scattered as amendments across ADR-0008. Per the operator's ADR principle — *collapse information where it helps an external reviewer and our future selves stop relitigating* — the SPIF schema has become a coherent subject that deserves one home.

## Decision

### 1. The extensibility contract (governing principle)

> **A foreign classification system is expressed ENTIRELY as data — per-SPIF declarations plus global versioned registries — never as US structure in engine code.**

Operationally, this partitions every design choice in the SPIF/decision surface into exactly one of two buckets:

- **Structural (engine code, system-agnostic):** the *kinds* of thing a policy can express — an ordered set of levels; typed categories (containment / predicate / permissive / informative / list-controlled); a coalition→member decomposition; a "home nation"; a "classified floor"; a roll-up-expandable flag; a **constraint kind** (mandatory-coupling, mutual-exclusion, level-restriction); a **regime** with a declared absence polarity. These are structure. They describe the *shape* of a policy, not any policy's content.
- **Data (system-specific), in one of two stores:** every nameable value.
  - *Per-SPIF:* levels and their order; category tags and kinds; the home nation; the classified floor; the roll-up-expandable tetragraphs; the specific couplings/exclusions/level-restrictions; the regimes and each one's absence polarity.
  - *Global versioned registry (not per-SPIF):* coalition tetragraph→member decomposition (`expand_tetra` reads `registry::expand_coalition`, ignoring the SPIF — D1, #26), and the ISO-3166 nation world-view. Membership is a versioned fact shared across policies, not a per-policy declaration.

  All of it is US-specific today and foreign-specific tomorrow — none of it is engine code.

**The stop-and-reconsider rule:** if a proposed constraint *kind* cannot be structured generically — i.e. it is only meaningful for the US system and has no system-agnostic shape — that is a signal to stop and redesign, not to hard-code it. A US-only *value* is fine (it is data); a US-only *structure* is a defect.

**Known gap — the controls axis does NOT yet satisfy this contract (§1a).** The contract above is the target and the review checklist; it is not a claim that the engine wholly meets it today. The dissemination-controls axis is the one place it does not — see §1a.

### 1a. Known gap: the controls axis is US-shaped structure in code (contract not yet met)

Honesty required by the contract itself: the `ControlMarking` axis is currently **structure**, not data, and it is **US-shaped**.

- `ControlMarking` (`crates/maknae-dcs-core/src/controls.rs`) is a **closed 18-variant enum** — its own doc states "adding a control is a deliberate ADR amendment," i.e. a recompile. A foreign system cannot declare its own control vocabulary.
- `CHAINS` (`crates/maknae-dcs-core/src/controls.rs`) hard-codes **US IC-Register precedence** (`ORCON > ORCON-USGOV`, `NODIS > EXDIS`, …) as an engine `const`.
- `validate_label` (`crates/maknae-dcs-core/src/label.rs`, the `(0e)` block from #48) matches `ControlMarking::Orcon/OrconUsGov/Relido` **literals** — a US policy constant live in the decision path *today* (gate-4 re-runs it).

The #31 Part-1 constraint table (§3) relocates co-occurrence *rules* (e.g. `ORCON ⊻ RELIDO`) to data, but it does **not** by itself make the control *vocabulary* or its *precedence* declarable — those remain a closed engine enum + const. Per §1's own stop-and-reconsider rule ("a US-only *structure* is a defect"), this is the defect to resolve for true multi-system support: the control vocabulary and its precedence chains must become SPIF/registry **data** (a closed-enum→declared-set migration), tracked as its own follow-up (see Consequences). Until then, the honest status is: **schema methods (`rank`, `is_classified`, `expand_tetra`) carry no policy constant; `validate_label`/controls still do.**

**Fail-closed remains orthogonal.** Extensibility never weakens the deny-by-default posture: an unknown level/tag/token/regime/constraint resolves to `Deny`/`Indeterminate`, for every system.

### 2. The current SPIF schema (consolidated; each field tagged structural-slot / data)

| Slot (structural) | Data a SPIF declares | Origin |
|---|---|---|
| `policy: PolicyId` | the policy authority identity (`"US"`, `"NATO"`, `"AUS"`, …) | ADR-0008 |
| `levels: [ordinal]` | the ordered classification levels (low→high); `rank()` is position-based, never a hard-coded scale | ADR-0008 |
| `categories: tag → CategoryKind` | which category tags exist and each one's satisfaction *kind* (Restrictive / RestrictivePredicate / Permissive / Informative / ListControlled) | ADR-0008 |
| coalition registry (global) | tetragraph → member-nation decomposition (expand-or-deny) | #26 |
| `home_nation: Option<nation>` | the policy's own nation (FGI gate) | #25 |
| `classified_floor: Option<level>` | the level at/above which a classification is CLASSIFIED (`is_classified`); fail-closed when undeclared | #27 |
| `expandable: {tetragraph}` | which tetragraphs may expand for common-country banner roll-up (landed field; enforcement is #31 §3) | #31 |

Every one is a *slot*; every value is *data*. `rank`, `is_classified`, `is_expandable_for_rollup` read the SPIF; `expand_tetra` reads the **global** coalition registry (not the SPIF, D1) — none carries a policy *literal*. Caveats to record (not hidden assumptions):
- **`classified_floor` assumes a top-contiguous classified set** — `is_classified` = `rank ≥ rank(floor)`, so it presumes every classified level ranks above every unclassified/CUI level (ADR-0008 names this for US). A system whose "classified" set is non-contiguous in rank order is not expressible by a single floor; it would need an explicit classified-level *set* (a schema extension, not assumed today).
- **`home_nation` is a single nation** — a non-national authority (NATO) leaves it undeclared; a multi-home authority wanting FGI gating over a *set* is not expressible today.
- **The controls axis is NOT in this table** because it is not yet SPIF data — it is a closed engine enum (§1a). Its inclusion here is deferred to the controls-vocabulary-as-data follow-up.

### 3. Forward-declared #31 growth slots (structural; filled by #31 Parts 1 & 4)

Declared here as structure so the extensibility contract governs them before the code lands; the specific rows/values are SPIF data delivered by the parts:

- **Constraint table (Part 1).** A SPIF-declared table of typed constraints over markings, evaluated fail-closed by `validate_label`. Constraint **kinds** (structural): `RequiresCoupling{ if_present, then_required }`, `MutualExclusion{ set }`, `LevelRestriction{ marking, allowed_levels | floor }`. Rows (data): e.g. US declares `ORCON ⊻ RELIDO`, `HCS ⇒ NOFORN`. New constraints arrive by SPIF update, not recompile. The existing ad-hoc US checks that are *pure* co-occurrence/level rules (e.g. ORCON×RELIDO from #48, ORCON-classified-only) migrate into this table as its first data rows — same validated semantics, moved code→data, which *exercises* the extensibility path. Decision mechanisms that are **not** co-occurrence rules (DISPLAY ONLY's display relation + emission, NAF's subtractive releasability, ORCON obligation emission) are NOT constraint-table entries and remain in the decision engine.
- **Regime + absence semantics (Part 4).** A SPIF declares its **regimes** and each regime's **absence polarity** (structural): classified-regime absent-releasability → `REL {owners}` (current, correct); a permissive regime (US CUI) may declare absent-marking → default-open within an authorized scope. The engine stops hard-coding one polarity; UNKNOWN regime → fail-closed.

### 4. Worked example — a foreign system as data only (controls axis excepted, §1a)

The same engine, the same schema slots, zero US assumptions. *Illustrative* NATO SPIF (values are representative, not an authoritative NATO policy encoding — the point is that every slot accepts foreign data):

```
policy            = "NATO"
levels            = [NR, NC, NS, CTS]        # NATO RESTRICTED < CONFIDENTIAL < SECRET < COSMIC TOP SECRET
classified_floor  = NR                        # all four levels here are classified — NATO RESTRICTED is itself a classification, so the floor is the lowest level (a fuller NATO SPIF would add NATO UNCLASSIFIED ranking BELOW NR); top-contiguous ✓
home_nation       = (none)                    # NATO is not a nation → slot simply left undeclared
categories        = { ATOMAL: Restrictive, ... }
constraint table  = [ LevelRestriction{ marking: BOHEMIA, allowed_levels: [CTS] } ]  # "BOHEMIA only with COSMIC TOP SECRET" — a marking⇒level rule
regimes           = [ classified{ absence: REL{owners} } ]
# coalition membership: NOT declared here — it is a GLOBAL registry fact
#   (data/*.json); a NATO tetragraph decomposes via registry::expand_coalition,
#   the same store the US SPIF uses. Adding NATO's tetragraphs = a registry data
#   update, not a code change and not a per-SPIF field.
```

Most of this required no NATO-shaped code path: `home_nation` is simply undeclared (a non-national authority); `levels` is a different ordered set; the constraint row is different data in the same `LevelRestriction` kind; coalitions resolve through the shared global registry. A US rule like RD/FRD (an Atomic Energy Act construct with no NATO analogue) is *absent* from this SPIF — the engine must never assume RD/FRD exists; it is US data, declared only by the US SPIF. Likewise the US "classified" vs "CUI" regimes are US data; NATO declares its own regime set.

**Honest limit of this example:** it deliberately does not exercise dissemination *controls*. NATO markings such as ATOMAL are shown as a `Restrictive` category, which works, but a NATO control with its own precedence (analogous to how ORCON/RELIDO/NODIS behave for the US) could **not** be declared as data today — that is the §1a controls-axis gap, not a hole this example papers over. When the controls vocabulary becomes data, this example gains a `controls` block; until then, the example is honest about what the schema does and does not yet cover.

## Consequences

- **Positive.** The multi-system thesis is now falsifiable on one page (the §4 worked example); the SPIF schema has a single relitigation-proof home; the extensibility contract (§1) is a concrete review checklist every subsequent SPIF-growth change must pass (structural kind, data value, fail-closed).
- **Cost / risk.** Folding pure ad-hoc US checks into the constraint table (Part 1) is a refactor with identical semantics but a real blast radius; it is scoped as its own #31 child with the usual gates. Getting a constraint *kind* wrong (too US-shaped) is the primary design risk — the §1 stop-and-reconsider rule is the guard.
- **Out of scope (explicit).** SPIF *generation* and cross-surface oracle independence (ADR-0013 / #18) — a real, separate correlated-failure concern — is NOT addressed here; this ADR governs the schema a validated SPIF may declare, not where the SPIF comes from. Storage/label integrity (ADR-0004) and the lattice/decision logic (ADR-0008) are likewise separate.
- **Follow-up (controls vocabulary as data).** §1a's gap — the closed `ControlMarking` enum + `CHAINS` precedence + `validate_label` control literals — is the primary un-met part of the contract. Making the control vocabulary and its precedence SPIF/registry-declarable (a closed-enum→declared-set migration) is its own tracked child; #31 Part 1 narrows the gap (co-occurrence rules → data) but does not close it. Flag filed for the operator to scope.
- **Supersession.** The SPIF-schema notes in ADR-0008 (the `classified_floor` note, the SPIF-as-Tier-0-input framing) are consolidated here by reference; ADR-0008 retains the *decision* logic and will point to this ADR for the *schema* at the epic-end consolidation. Full reconciliation of ADR-0008's SPIF text into this ADR is part of that consolidation.

## References

ADR-0008 (lattice/decision; #6); ADR-0013/#18 (SPIF generation oracle independence — separate); ADR-0004 (storage/label integrity); EPIC #33 issues #25/#26/#27/#31; IC Register / DoDM marking policy (the source of the US SPIF's *data*, validated per-constraint as each #31 part lands).
