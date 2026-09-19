# ADR-0025: FIPS 140-3 validation is a design goal, not a constraint — Maknae builds on the AWS-LC-FIPS 4.x module while it is under CMVP review

- **Status:** Accepted (maintainer-ruled 2026-09-19)
- **Date:** 2026-09-19
- **Deciders:** Alex Ackerman (maintainer)
- **Supersedes** the standing control recorded in [#259](https://github.com/darkhonor/maknae/issues/259) — the `aws-lc-rs >=1.17.3, <1.18.0` pin in `crates/maknae-vault/Cargo.toml` and its mirrored `.github/dependabot.yml` ignores — and the "validated module line" claim wherever this repository made it. It does **not** disturb the [2026-09-13 ruling](../../packaging/isolation-contract.md) that any AWS-LC-FIPS **3.x** implementation was approved; that ruling settled a question about a line Maknae no longer ships.

## Context

`maknae-vault` pinned `aws-lc-rs` below 1.18 as a **compliance control**, not as dependency hygiene. The reasoning was recorded in the manifest, in `.github/dependabot.yml`, in `packaging/isolation-contract.md`, in ADR-0002's SC-13 row and in #259: aws-lc-rs 1.18 moves the `fips` backend from the AWS-LC-FIPS **3.x** module (CMVP certificates **#5314** static / **#5298** dynamic, on the validated list) to **4.x** (submitted, Modules In Process), and ASD STIG **APSC-DV-001860 (CAT I)** requires a module on the validated list.

**The pin then blocked a published TLS vulnerability from being fixed.** [RUSTSEC-2026-0285](https://rustsec.org/advisories/RUSTSEC-2026-0285) — TLS 1.3 handshake messages incorrectly accepted across encryption-level boundaries — is fixed in rustls **0.23.45**, and 0.23.45 requires `aws-lc-rs >=1.18`, exactly the range the pin excluded. Measured 2026-09-15 (#320):

```
$ cargo update -p rustls --precise 0.23.45 --dry-run
all possible versions conflict with previously selected packages
  previously selected package `aws-lc-rs v1.17.3`
    ... which satisfies dependency `aws-lc-rs = ">=1.17.3, <1.18.0"` of package `maknae-vault`
```

*(Transcript abridged — cargo's five leading lines (`error: failed to select a version for `aws-lc-rs`.`, the `rustls v0.23.45` requirement chain, and the `versions that meet the requirements ^1.18 are:` line), a second requirement-chain line, the trailing `failed to select a version for `aws-lc-rs` which could resolve this conflict` summary, and the crate paths are all trimmed. **Re-observed 2026-09-19** against a clean `main` worktree, unchanged, including the `v1.17.3` cargo reports as the previously-selected package: it names the requirement's floor, not `Cargo.lock`'s resolved `1.17.4`. A review round flagged the version as impossible by reading the lockfile; running the command settled it.)*

`cargo deny check advisories` was therefore red on `main` and on every open branch, with **no fix available to an agent** — per #320's CI observation of 2026-09-14, PR #317 failed at that step and every gate after it was skipped, so CI held no gate evidence at all. **The advisory's own measured severity, stated here because this ADR asks for precision elsewhere:** `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N`, and the advisory text says *"the handshake transcript is still authenticated, so a network-position attacker cannot use this to alter or complete a handshake; the practical effect is that a peer could send handshake messages that should be encrypted in plaintext without rustls rejecting the connection."* It is a confidentiality-only, low-severity defect — **not** a handshake break, and nothing here should be read as claiming one. **The forcing function was never its blast radius.** It was that a *fail-closed* gate went red on every branch with no fix an agent could reach: under [ADR-0016](ADR-0016-risk-tiered-test-coverage.md) and this project's fail-closed doctrine, a red gate stops the work whatever the CVSS says. The choice was between an `ignore` entry parking a live advisory and moving module lines. `rcgen` 0.14.10 was stuck behind the same bound from the other side, for the same reason.

**The premise underneath the pin was itself wrong for this project.** Maknae is a personal project: **no authorization boundary, no ATO, no program office, no assessor, no contractual security obligation.** The DoD posture is a design target so the system *can* be fielded, not a compliance regime in force — the repository's own standing guidance says so. The pin had been imported from **Microkosmos**, where the compliance posture is genuinely different, and it was carried here as though the obligation came with it.

The maintainer, 2026-09-19:

> *"Maknae does NOT have the same compliance posture as Microkosmos and it's silly to try and justify it otherwise. The design goal is the same (FIPS Validated), but it's a goal not a constraint."*

and, on whether the 4.x certificate should be tracked as a watch:

> *"We don't need to be FIPS Validated because there is no CAT I."*

This also completes reasoning the maintainer had already applied to this exact dependency. When an agent proposed narrowing the pin's claim on 2026-09-12, they declined, because **keeping an older crypto library with known vulnerabilities is worse than upgrading within the vendor's approved channel** — a frozen, validated, *vulnerable* module is the wrong posture, not the safe one. That reasoning was given about patch levels *inside* the 3.x line; RUSTSEC-2026-0285 is the case where honouring it requires crossing to 4.x.

## Decision

### 1. FIPS 140-3 validation is a DESIGN GOAL for Maknae, not a constraint in force

Maknae is built so that it *can* be fielded where FIPS 140-3 is required — FIPS-capable crypto, one provider, a fail-closed runtime assertion, no OS-crypto dependency. It does not claim to satisfy a validation requirement today, and **no in-repo control may be justified solely by a compliance obligation this project does not carry.** APSC-DV-001860 and its peers bind a system fielded under an ASD STIG obligation. Maknae is not such a system; a deployment that is one inherits that decision, with the tradeoff documented for it (decision 5).

### 2. Maknae builds on the AWS-LC-FIPS 4.x module line

`crates/maknae-vault/Cargo.toml` requires `aws-lc-rs = "1.18"` — floor `>=1.18.0`, and **no ceiling of our own**, though cargo's implicit caret still caps it at `<2.0.0`, which is cargo's bound rather than a control of ours. It resolves `aws-lc-fips-sys` 0.14.x — the 4.x module. The mirrored `rcgen` **compliance** ceiling and both `.github/dependabot.yml` ignore rules are removed with it. (`rcgen` reads `">=0.14.9, <0.15"`: for a 0.x crate that upper bound is exactly cargo's caret, identical to `rcgen = "0.14.9"`, spelled out so the floor is visible. The floor is the control; the ceiling is cargo's semantics, as with `aws-lc-rs` above.) `aws-lc-rs` stays a **named** dependency of `maknae-vault` so the workspace resolves one version and the posture has one documented home.

### 3. The permitted claim, everywhere in this repository

> **Maknae is built on the AWS-LC-FIPS 4.x module line, which is submitted and under CMVP review.**

Never "validated", never "validated here", never a bare citation of #5314 or #5298 for the shipped artifact. Upstream `aws-lc/crypto/fipsmodule/FIPS.md` (read 2026-09-19) lists **v4.0 static** and **v4.0 dynamic** under *Modules In Process* at "Review". **SC-13 evidence is now incomplete on two axes** — the module's certificate *and* the operational environment — where before it was incomplete on the environment alone. Certificates #5314/#5298 describe the line Maknae shipped until 2026-09-19 and are retained in the documents as history, not as a current citation.

### 4. Security currency beats a frozen certificate

When a published vulnerability's only fix requires moving within the vendor's supported channel, **take the fix**. An `ignore` entry parking a live TLS advisory so a certificate claim can be preserved is the worse outcome, and for this project it would preserve a claim nothing requires. This generalises the maintainer's 2026-09-12 reasoning from patch levels to module lines.

### 5. The v4.0 certificate is NOT tracked

There is **no watch issue, no review date and nothing owed.** If NIST issues the certificate, it licenses an upgrade to the *claim* (decision 3) and nothing else — **no version change** follows from it, and no one is obliged to notice. Do not file a watch; do not propose restoring the pin. *(This is the same disposition, for the same reason, as the 2026-09-13 ruling that the 3.1.0-vs-3.6.0 module-version mapping is not a finding and is not tracked.)* A deploying organization with a genuine validation obligation may re-pin to a validated line at that time — that is their decision, made with their own knowledge of which vulnerabilities they are choosing to carry.

## Consequences

**Measured on the move** (2026-09-19, Linux x86_64, Rust 1.98.1): `aws-lc-rs` 1.17.4 → **1.18.1**, `aws-lc-fips-sys` 0.13.17 → **0.14.2**, `rustls` 0.23.43 → **0.23.45**, `rustls-webpki` 0.103.13 → 0.103.15, `rcgen` 0.14.9 → **0.14.10**, `pem` 3.0.6 → 4.0.0. `cargo deny check` → `advisories ok, bans ok, licenses ok, sources ok`. Full workspace tests green.

**What does not change, and this is the load-bearing part.** The **runtime `.fips()` assertion** remains the gate and still passes (`fips_glue::tests::asserts_fips_true_on_this_build`). It proves the **FIPS build** — the module compiled in FIPS mode with its power-on self-tests passing — and it never proved a certificate: its value is identical on a validated module and on one under review. Dependency-tree hygiene was never the control and is not weakened. Likewise unchanged: the static (Linux) / dynamic (macOS) **module split**, since upstream submitted v4.0 as the same two modules; the macOS **dylib packaging obligation** and its absolute-install-name pinning (#227); and the `rustls-no-provider` feature discipline in `maknae-vault` and `maknae-llm`, which keeps exactly one provider in the process.

**The dylib basename moves with the crate version** on macOS: `libaws_lc_fips_0_13_17_crypto.dylib` → `libaws_lc_fips_0_14_2_crypto.dylib`. *(The rule is measured, the `.dylib` name is derived from it: this host is Linux, where both artifacts are present as `libaws_lc_fips_0_13_17_crypto.a` and `libaws_lc_fips_0_14_2_crypto.a` under `target/debug/build/aws-lc-fips-sys-*/out/build/artifacts/`. The macOS dynamic form has not been observed on a Mac in this change; CI's `darwin-native` lane and the `.pkg` smoke test are where it is.)* `packaging/macos/build-pkg.sh` globs it and `smoke.sh` normalises it before comparing the bill of materials, so the packaging *logic* needed no change — only the quoted measurements in the docs did. (The two packaging scripts are in the corrected list below for a different reason: the hazard wording they print, not the dylib handling.)

**Documents corrected in place, dated, per the in-artifact rule. A round-2 review caught this list asserting completeness while omitting three live claim sites — including the standards register itself — so it now names every **claim site** this change corrects — and claims nothing beyond that. It is not an inventory of touched files: `Cargo.lock`, `THIRD-PARTY-NOTICES.md` and the ten SVGs that moved only by their shared provenance stamp are covered elsewhere in this ADR and in the commit bodies, not here:** `crates/maknae-vault/Cargo.toml` (both comment blocks), `.github/dependabot.yml`, `crates/maknae-vault/src/fips.rs`, `crates/maknae-llm/Cargo.toml`, `packaging/isolation-contract.md`, `packaging/macos/README.md`, ADR-0002's SC-13 row, ADR-0009's FIPS parenthetical, the `design/references/2026-08-30-fips-supply-chain-visibility.md` record (its method and OS-crypto-independence findings never turned on certificate status and stand; its `ring`-reachability premise does **not**, and §1, §3 and §6 are each corrected in place — earlier drafts of this ADR and of that addendum claimed the record was otherwise untouched, then that it was wrong by one section; it is wrong in three, which is the third time in this change that a completeness claim outran the sweep behind it), **`AGENTS.md`** (a standing ruling, so the pin is not proposed again), **`design/adr/README.md`** (this registry row), **`ci/gates/darwin-cross-check.sh`** (a dated version note on a quoted measurement), **`design/diagrams/standards-profile.toml`** and its rendered SVG, **`packaging/macos/build-pkg.sh`**, **`packaging/macos/smoke.sh`**, **`.github/workflows/ci.yml`**, **`deny.toml`** (a dated measurement that `ring` has left the graph, with the ban decision left to the maintainer), **`packaging/common/maknaed.service`** (the same BoringCrypto misnomer, in a shipped unit file) and **`design/references/2026-08-21-agent-deck-assessment.md`** and **`CONTRIBUTING.md`** (a dated pointer on the stale #198-era cross-check count, which a new contributor reads before anything else).

**The standards register is the one that mattered most, and the one the first pass missed.** `design/diagrams/README.md` names `standards-profile.toml` as where standards claims live — *"curated, reviewable, every row citing evidence"*, explicitly in preference to *"prose scattered across ADRs"*. Its FIPS 140-3 row claimed `version = "aws-lc-fips (BoringCrypto module)"` with no CMVP qualifier (and named the wrong module: AWS-LC-FIPS is not BoringCrypto). Correcting nine prose documents while leaving the designated register asserting the struck claim would have left the contradiction in the one artifact built to be authoritative about it. The row now reads `AWS-LC-FIPS 4.x — in CMVP review` and cites this ADR. **`status` stays `enforced` deliberately**, per that file's own definitions: what is mechanically enforced is that the process runs the FIPS provider or refuses to start. The certificate state is not a `status` value and now lives in `version`, where the rendered StdV-1 shows it. Each of them links back here: this ADR is the decision of record, and the manifest comment mirrors it rather than replacing it.

**What a future FIPS-obligated deployment does.** Re-pin `aws-lc-rs` to the validated line available at that time, accept the vulnerabilities that line carries, and record the tradeoff — the inverse of this decision, made by the party that actually holds the obligation.

**Cost accepted.** Maknae cannot claim a validated cryptographic module until the v4.0 certificate issues, and nobody is watching for it. That is the deliberate price of not carrying a compliance obligation this project does not have.
