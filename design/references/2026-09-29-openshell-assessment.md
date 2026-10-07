# NVIDIA OpenShell — Assessment Against Maknae

| | |
|---|---|
| **Status** | Assessment record. It informs decisions on runtime-loop confinement, egress, policy verification, audit export and SCRM. It creates no roadmap commitment and supersedes no ADR. |
| **Date** | 2026-09-29 |
| **Subject** | [`NVIDIA/OpenShell`](https://github.com/NVIDIA/OpenShell) at commit [`1358941`](https://github.com/NVIDIA/OpenShell/tree/1358941b818d4126a7374aaf5216d87fc960e122) (2026-09-28, the day NVIDIA announced the Open Agent Safety Platform). A Rust sandbox runtime for autonomous agents; Apache-2.0. |
| **Method** | The repository was mirrored with `git clone` outside this tree and **read only**: nothing was built, installed, pulled or executed. Four parallel readings covered (1) enforcement and sandbox, (2) policy and verification, (3) egress, credentials and audit, and (4) provenance, supply chain and integration; each cited the mirror by path and line. Load-bearing claims were then re-verified by hand, and a fresh-context critical review checked both the OpenShell and the Maknae claims against source. Public web material is context only and is marked as such. The platform's hardware half (Sentry on BlueField-4) is closed and was not assessed. Line numbers are to the pinned commit and may drift by a line or two. |
| **Audience** | Maknae team (dual-audience: human reviewers and AI agents) |

## 1. Executive disposition and provenance (read first)

OpenShell is the most serious agent-security runtime this project has assessed. It shares Maknae's central premise: the agent cannot police itself, so enforcement must sit where the agent cannot reach it. Its supervisor "never executes inside the agent workload" (`architecture/sandbox.md:13`). It is written in Rust by a large, accountable US vendor.

It is worth studying closely, and parts of it are worth composing with. It is **not** a replacement for any part of Maknae's trust plane, and it should not enter Maknae's supply chain.

The two projects answer different questions:

- **OpenShell confines a program.** It puts the agent in a sandbox: a container or VM, plus Landlock, seccomp, and an egress proxy that holds the credentials. It decides network egress per request. Filesystem access is a start-time allowlist, with no per-access filesystem decision and no filesystem audit.
- **Maknae authorizes a subject.** One static decision point, `maknaed`, decides and write-ahead-records every verb the loop asks for: each file read and write, each model turn. It decides against the subject's role and a mandatory classification ceiling. On a packaged install, the key is in Vault under the egress deputy's own AppRole, it is in memory only in the deputy, and no file readable by the operator's uid holds a credential that reaches it. That is file custody, with a stated limit (§8).
- **What Maknae does not do yet is confine the loop.** The loop runs unconfined as the subject's uid, and its direct I/O is invisible to the trail (ADR-0023 decisions 2 and 6). Confinement is exactly what OpenShell is good at.

So the two are complementary more than competing (§5).

**Provenance.** The provenance posture is materially stronger than that of any previous external subject in `design/references/`.

- **Owner and license.** NVIDIA Corporation, a US company (`LICENSE:1`). Apache-2.0, with SPDX headers.
- **Governance.**
  - There is a public governance document and a maintainer council, and DCO sign-off is enforced (`GOVERNANCE.md`, `MAINTAINERS.md`, `.github/workflows/dco.yml`).
  - There are 13 maintainers: 10 list NVIDIA and 3 list Red Hat. These affiliations are self-stated. Nationality was not assessed, and names were not used as a proxy for it.
- **Release provenance.**
  - Sigstore build-provenance attestations cover the tarball, `.deb`, `.rpm` and wheel artifacts (`.github/workflows/release-tag.yml:515-523`), and VM kernels in a separate workflow (`release-vm-kernel.yml`).
  - Container images carry BuildKit provenance and an SBOM rather than `actions/attest` (`.github/actions/build-docker-image/action.yml:73-74`).
  - Every third-party GitHub Action is pinned by SHA. Vulnerability reports go to NVIDIA PSIRT (`SECURITY.md`).
- **Maturity.**
  - The first commit was on 2026-01-29, and the repository has 1,554 commits.
  - There have been 115 `v0.0.x` releases since 2026-03-13.
  - The stable `v0.1.x` line began four days before this assessment.

**Two SCRM facts decide the posture for a DoD-adjacent audience.**

1. **Telemetry to NVIDIA is on by default.**
   - The `telemetry` Cargo feature is a default feature (`crates/openshell-core/Cargo.toml:49`).
   - At runtime it is on unless `OPENSHELL_TELEMETRY_ENABLED` is set to false (`crates/openshell-core/src/telemetry.rs:326`, `value.unwrap_or("true")`).
   - It posts to `https://events.telemetry.data.nvidia.com/v1.1/events/json` (`telemetry.rs:27`).
   - **The README understates what is sent.** It says telemetry does not collect "provider or model names" (`README.md:85`), but the payload includes the provider *vendor type*. That field is a closed enum: `anthropic`, `openai`, `claude`, `codex`, … with a `Custom` catch-all (`telemetry.rs:197-222, 501`).
   - A telemetry-free build exists (`--no-default-features --features defaults-without-telemetry`, `crates/openshell-gateway/Cargo.toml:67-75`), and the choice between the two is enforced at compile time.
2. **The TCB is large and contains native code.**
   - `Cargo.lock` has 805 packages; Maknae's has 277.
   - The workspace sets `unsafe_code = "warn"` (`Cargo.toml:150`). There are 461 `unsafe {` blocks under `crates/*/src`, roughly 200 of them in `#[cfg(test)]` modules. That count is from grep and is approximate.
   - C and C++ sit in or beside the trusted path:
     - the C++ Z3 solver, linked into the gateway through the prover;
     - libkrun, embedded and loaded with `dlopen(RTLD_GLOBAL)`;
     - QEMU.
   - Maknae links native code too: the AWS-LC crypto module (C and assembly, ADR-0002). What differs is how much, and where it sits.

**Disposition.**

- **Learn** from the design (§4).
- **Compose** only at the edges, where OpenShell sits *outside* Maknae's trust boundary (§5).
- **Do not** vendor, link or depend on OpenShell code. That includes the prover and its Z3, and any in-process use of its Rego engine.
- Any operational composition needs its own authorized SCRM evaluation, pinned by attested digest, with telemetry compiled out.

## 2. What OpenShell is

There are three runtime components (`architecture/README.md:9-15`):

- **CLI**: untrusted.
- **Gateway**: the control plane. It holds durable state and policy storage, runs the proposal inbox, keeps credentials behind drivers (a local database, Kubernetes secrets or Vault), and hosts the policy prover and relays. It "does not make per-request egress decisions" (`architecture/security-policy.md:3-6`).
- **Supervisor**: the local security boundary. It holds the admitted policy and the credentials, runs the egress proxy with an embedded Rego engine (Microsoft's `regorus`), intercepts TLS and injects credentials (`crates/openshell-supervisor-network/src/lib.rs:4-9`).
  - `architecture/sandbox.md:13` places it outside the workload ("It never executes inside the agent workload").
  - `architecture/README.md:11` says it "runs inside every sandbox workload". The two architecture documents contradict each other (§6).

Inside the workload, a trusted `openshell-sandbox` runtime shares the agent's uid. It installs a seccomp listener and a mandatory Landlock baseline, then launches the agent child with zero capabilities and `no_new_privs` (`sandbox.md:9-22`).

The enforcement layers (`sandbox.md:159-170`):

1. **A mandatory outer network fence**, validated as driver evidence before launch (`sandbox.md:105-128`): Docker or Podman with no network, a Kubernetes NetworkPolicy with zero egress, or a VM with no NIC.
2. **A seccomp user-notification broker** that virtualizes inet sockets and holds `connect()` until the supervisor decides (`sandbox.md:229-249`).
3. **Landlock.** A mandatory ABI-3 baseline plus an optional workload filesystem policy.
4. **The policy proxy**, which applies:
   - destination checks, with SSRF and cloud-metadata blocking;
   - the calling binary's identity, a SHA-256 of `/proc/<pid>/exe` pinned on first use;
   - L7 rules for REST, GraphQL, JSON-RPC and MCP;
   - credential injection by placeholder substitution.

Platforms (`docs/about/support-matrix.mdx`):

- **Linux** is the only real sandbox. It requires Landlock ABI 3 (6.2+) and seccomp user-notification, both probed before admission. A disabled Landlock LSM fails the launch closed (`support-matrix.mdx:166-172`).
- **macOS** runs agents only inside a Linux VM (Docker Desktop, or libkrun on Hypervisor.framework). A native non-Linux sandbox `apply()` exists: it logs "not yet implemented" and returns `Ok(())` (`crates/openshell-sandbox/src/sandbox/mod.rs:20-38`). That path is latent; no supported configuration runs the sandbox runtime natively off Linux.
- **Windows.** WSL2 support is experimental. Native Windows (MXC) is a separate, weaker model still under RFC review.
- **Hardware.** The repository never mentions Vera or BlueField. The hardware monitor, Sentry, is a separate and closed product.

## 3. The comparison table

The verdicts are:

- **OVERLAP**: both do it, and they converge.
- **LEARN**: OpenShell does it well, and Maknae should take the idea.
- **INTEGRATE**: compose the two at an edge.
- **AVOID**: do not follow OpenShell here.
- **MAKNAE STRONGER**: Maknae's current ADRs already do this better.
- **GAP**: Maknae is weaker today.

| # | Dimension | OpenShell | Maknae (current ADRs and code) | Verdict |
|---|---|---|---|---|
| 1 | Core premise | The supervisor holds credentials and policy and "never executes inside the agent workload" (`sandbox.md:13`). | The agent runtime is untrusted by design, and `maknaed` is the sole PDP (ADR-0005; ADR-0023 decision 2). | **OVERLAP** |
| 2 | What is decided | Per-request decisions cover **network egress**. The filesystem is a start-time Landlock allowlist: no per-access decision, no audit. Execution is bounded by the same allowlist (Landlock `Execute`), with no per-exec decision or audit on Linux (the native Windows driver emits per-launch process events). | **Every verb the loop asks for** is decided and write-ahead-recorded: each `fs.read` page, `fs.write` and `session.prompt` turn (ADR-0009, ADR-0019, ADR-0023). `fs.delete` and `fs.mkdir` are decided and recorded the same way, reached through the CLI rather than the loop's two tools. Maknae has no execution verb (the `terminal.*` verbs are unbuilt) and does not bound what the loop itself executes. | **MAKNAE STRONGER** for mediation of what the loop *asks for*; **OpenShell stronger** on bounding execution |
| 3 | Containment of a compromised agent | The outer fence blocks direct egress. Landlock, seccomp, zero capabilities and `no_new_privs` all apply. The in-workload runtime is protected from an agent with the same uid: `PR_SET_DUMPABLE 0`, a child seccomp filter denying ptrace and `process_vm_*`, and signals via pidfd. | **None.** The loop runs unconfined as the subject's uid. An altered loop can open sockets and read anything the user can (ADR-0023 decisions 2 and 6; ADR-0009's mutation extension). | **GAP → LEARN / INTEGRATE** (§4.1, §5.1) |
| 4 | Access-control model | On the data plane, attribute matching over (binary, host, port, method, path, MCP tool), with no subject or object security attributes. On the management plane, OIDC RBAC (Admin and User). No MAC, no classification, no releasability. | RBAC (`maknae-authz-basic`) composed with a **mandatory** classification-ceiling operand under deny-overrides. No role bypasses clearance (ADR-0008, ADR-0020, ADR-0022). ABAC through the DCS library. | **MAKNAE STRONGER** |
| 5 | Composition | L4 is a union of allows. Deny-overrides applies only inside L7, **scoped per binary** (`sandbox-policy.rego:240-272`). A gateway-wide policy *replaces* the sandbox policy. Hard-coded IP and port blocks always win. | Deny-overrides, independent of order. `Indeterminate` blocks and is never masked by a peer `Permit` (`crates/maknae-security/src/compose.rs`, `combine`; ADR-0008 §3). | **MAKNAE STRONGER** |
| 6 | Default posture | L4 denies by default. **L7 defaults to `audit`, which forwards requests the rules deny** (`l7/mod.rs:314-318`; `l7/relay.rs:1195`). The optional workload filesystem policy defaults to **best effort**: if it cannot be built, the workload runs without it, the mandatory baseline still applies, and an alert is raised (`openshell-core/src/policy.rs:89-93`; `openshell-sandbox/.../linux/landlock.rs:248-281, 362-390`). The gateway applies RBAC (`openshell-admin`/`openshell-user` roles, `openshell-server/src/cli.rs:213-226`) only when OIDC is configured. Whether unauthenticated callers get in depends on configuration: once any authenticator is configured, an unauthenticated user request is refused unless the operator sets `allow_unauthenticated_users`, which the Helm values mark UNSAFE; with no authenticator of any kind configured and mTLS user auth off, every gRPC caller becomes an unauthenticated dev principal holding the admin and user roles (`multiplex.rs:963-973`) (`openshell-server/src/multiplex.rs:1014-1040`; `deploy/helm/openshell/values.yaml:425-429`). The published gateway image binds `0.0.0.0` inside its container (`deploy/docker/Dockerfile.gateway:24`), and NVIDIA's container recipe publishes it on host loopback only, with TLS disabled (`docs/how-it-works/gateways/container-deployment.mdx:58, 66`). | Deny by default at the decision point, with no advisory mode for authorization, and no operand may fail open (ADR-0008 §4). Unknown keys are refused in every parsed section (#210), except `lake` and `core.identity`, which stay open by direction (configuration §3). An absent classification ceiling resolves to the system's lowest level, so only unmarked or lowest-level content flows (configuration §4.1). Not every setting refuses a wrong shape: a shape-tolerant `audit.jsonl_path` falls back to its default, a `core` typo in a CLI-side `maknae.yaml` is not caught, and a non-map `core` boots at the lowest level (configuration §3). | **AVOID** (the L7 audit default) / **MAKNAE STRONGER** at the decision point |
| 7 | Who can change policy | Operators, through the gateway. The sandbox's supervisor identity can persist a network-policy revision through `UpdateConfig`'s "sandbox policy sync" (`crates/openshell-server/src/grpc/policy.rs:2384-2408, 4009-4110`). Once a baseline policy exists, that path cannot change static fields (`validate_static_fields_unchanged`, `:4027`); before one exists, image discovery may persist a complete policy for repair, which does not by itself authorize workload activation (`:4020-4031`; `security-policy.md:166-170`). Provider-derived entries are stripped (`:4010-4015`). Policy can also be **proposed** by two proposers: the agent (RFC 0002, off by default) and a mechanistic mapper that turns the sandbox's own denied connections into proposals whatever that setting says (`security-policy.md:286-300`). In `auto` mode, a proposal from either is approved when the prover delta and the security notes are both empty (`security-policy.md:323-341`). | `authz.yaml` is root-owned and re-read on every request *(corrected 2026-10-07, #489: it is now compiled into the PDP's snapshot at start and at each `SIGHUP` reload, not re-read per request)*. There is no in-band policy mutation, and the engine is fixed in the binary (ADR-0002; ADR-0008 §1). Content from the agent may inform a decision but never authorize one (AGENTS.md principle 2). | **AVOID** (agent-driven policy with auto-approval; the enforcement point persisting policy) |
| 8 | Policy verification | A Z3-based **containment checker** proves `Allowed(candidate) ⊆ Allowed(boundary)` and gives counterexamples. It returns one of four results, and only `Within` authorizes. It fails closed on timeout and refuses REST that is not enforced (`crates/openshell-prover/src/containment.rs`). It has runtime-parity tests, but **it is not wired to the gateway**. The **proposal prover** that gates auto-approval asserts fixed facts to Z3, which is constant evaluation, not symbolic search. It has no parity test. It **ignores reach to hosts that hold no credential** (`queries.rs:116`: "Un-credentialed reach is not a tracked risk"), ignores `spawns`, and treats `audit` as enforced (`crates/openshell-prover/src/policy.rs:72-74`). | Golden policy matrices, a risk-tiered coverage contract with mutation testing, and the negative-control gate (ADR-0016). **No formal verification of policy containment, and no ADR commits to one.** ADR-0003's Cedar evaluator verification is superseded by ADR-0004, where Cedar is an optional backend, and it concerned the evaluator, not the operator's policies (ADR-0003:41). | **LEARN** (the containment contract; parity tests) / **AVOID** (the proposal prover's framing) |
| 9 | Egress to the model | The agent speaks native provider HTTP. The proxy terminates TLS with a per-sandbox CA injected into the workload's trust store (no name constraints are set: `l7/tls.rs:42-63`). After the destination and L7 checks, it swaps a placeholder for the real key (`sandbox.md:352-387`). No dedicated control point for the model path exists in software. | The agent never speaks to the provider. `session.prompt` goes to `maknaed`, which decides and records it. The egress deputy (`_maknae-egress`, with its own Vault AppRole) holds the key and makes the call (ADR-0023 decision 3). | **MAKNAE STRONGER**: key custody, no interception CA, and the agent never sees provider responses such as token refreshes |
| 10 | Other network egress | Full mediation: the seccomp broker, the fence, DNS through a local resolver with synthetic-address pinning, and SSRF and metadata blocking (`sandbox.md:229-340`). | A kernel-side allowlist for platform flows, plus credential custody. For the loop's own sockets there is at most best-effort nftables (`packaging/isolation-contract.md`, egress rows). | **GAP → LEARN / INTEGRATE** |
| 11 | Process identity | A SHA-256 of `/proc/<pid>/exe`, pinned on first use, re-validated against a race-checked snapshot. Rego authorizes by **path, or any ancestor's path**, so anything an allowed binary spawns inherits its grants. The check can be disabled. | The uid only (`SO_PEERCRED` on Linux, `LOCAL_PEERCRED` on macOS). No binary identity (ADR-0023 decision 3; #115). | **LEARN** (the race-checked snapshot) / **AVOID** (ancestor inheritance, identity by path, pinning on first use) |
| 12 | Filesystem mechanism | Landlock inode rules from a pinned root. The baseline that runs opens each child of `/` relative to a pinned root fd with `O_PATH\|O_NOFOLLOW` and skips symlinks (`openshell-sandbox/src/sandbox/linux/landlock.rs:135-222`). A variant that also re-checks dev/ino before and after the open exists in `openshell-isolation-interface/src/linux/landlock.rs:76-133`, but nothing in production calls it. No deny patterns, no globs. | Delegated no-access descriptors, decisions on the kernel-reported path, the `nlink==1` proof, deny lists, and `maknae-io` anchor-relative resolution (ADR-0009; ADR-0021). Read-before-write (#388). | **Different goals.** OpenShell enforces against a hostile process; Maknae decides and audits each access. **LEARN** (a Landlock self-protection baseline for the loop) |
| 13 | Credentials | Stored in an encrypted local database (AES-256-GCM through aws-lc-rs), whose **key-encryption key may come from an environment variable** (`openshell-driver-db-credstore/src/lib.rs:531-545`), or in Kubernetes secrets, or in Vault (a token held as a plain `String`). Onboarding harvests keys from the operator's **host environment** (`openshell-providers/src/discovery.rs`). `zeroize` is used only for `SecretJwt`. The secret resolver has a hand-written, redacting `Debug` (`openshell-core/src/secrets.rs:197-210`). | Keys live in Vault only. A plaintext key in configuration is refused (`ProviderPlaintextKey`). Secret-class buffers are zeroized from allocation and never grow, with an inventory of the exceptions (ADR-0026). | **MAKNAE STRONGER** / **OVERLAP** (the redacting `Debug`) |
| 14 | Audit | OCSF v1.8 events through `tracing`. They are written **after the fact**. The JSONL output is **off by default**, non-blocking (it can drop lines under backpressure), kept as at most three daily files, and written to the supervisor's own `/var/log` (on Docker and Podman a size-capped tmpfs, on Kubernetes an `emptyDir`, so the records go when the supervisor does), which on Docker, Podman and Kubernetes is private to the supervisor's container or pod, not the agent's (`crates/openshell-supervisor/src/main.rs:347-356`). If that directory cannot be opened, the writer is dropped silently (`.ok()`), so the file sink fails open. The docs say the file is inside the sandbox; the code places it outside. No cryptographic integrity. OTLP export is available when configured. There is a schema-downgrade path for older SIEMs. | Intent is recorded before every effect, then the outcome. A failure of the primary sink is fail-closed: no disclosure without a durable record. The trail holds a content digest, never the content (ADR-0019). **Maknae has no cryptographic audit integrity either.** The `integrity{prev_hash, sig}` envelope is reserved, and AU-9(3)/AU-10 is a tracked gap (ADR-0019 decision 2; #82). | **MAKNAE STRONGER** (write-ahead and fail-closed) / **shared gap** (integrity) / **INTEGRATE** (OCSF as a projection, §5.2) |
| 15 | Refusal information to the agent | When enabled, deny responses carry `next_steps` and `agent_guidance` so the agent can continue through the proposal loop (`security-policy.md:300-302`). | The refusal on the wire is generic, and the deny reason is audit-only (ADR-0023 decision 4; the 2026-09-02 wire ruling). | **MAKNAE STRONGER** for a classified audience |
| 16 | TCB and `unsafe` | `unsafe_code = "warn"`, with about 460 `unsafe {` blocks under `crates/*/src` (roughly 200 in test modules). No confinement gate. C and C++ (Z3, libkrun, QEMU) in or beside the TCB. | `unsafe_code = "forbid"` in every member except `maknae-sys`, which gives a per-function safety argument, has gates and negative controls (ADR-0027). First-party code is all Rust. **The linked AWS-LC crypto module is C and assembly** (ADR-0002), with a recorded native-code visibility gap (`design/references/2026-08-30-fips-supply-chain-visibility.md`). | **MAKNAE STRONGER** for first-party `unsafe` confinement; both link native code |
| 17 | Supply chain | `deny.toml` has `yanked = "warn"`, checks only direct dependencies for being unmaintained, allows a broad set of licenses, and ignores four advisories. 805 packages. The installer checks a SHA-256 fetched from the same origin, not a signature. Actions are pinned by SHA. Sigstore attestations. CodeQL, Trivy, zizmor and dependency review in CI. | `deny.toml` has `yanked = "deny"` and `unsound = "all"`, bans native-tls and openssl-sys, and allows 7 licenses. 277 packages. AGENTS.md requires every pin to be documented; at least one is not yet (`yaml-rust2 = "=0.13.0"` in `crates/maknae-config/Cargo.toml`). Actions are pinned by SHA. Automated signed releases are open (#188; package signing #96). | **MAKNAE STRONGER** (dependency policy) / **OVERLAP** (SHA-pinned Actions) / **LEARN** (Sigstore attestation of release artifacts) |
| 18 | Test discipline | Unit tests, E2E across drivers, GPU E2E, conformance suites, and runtime-parity tests for the containment checker. No mutation testing and no Rust coverage gate. No fuzzing or property tests. | A fail-closed, risk-tiered coverage contract; cargo-mutants on the listed crates; the negative-control gate; reproduce-first; blind review (ADR-0016; AGENTS.md principles 4-6). **Maknae has no fuzzing or property tests either**, although its CBOR decode sits on a trust boundary. | **MAKNAE STRONGER** (coverage and mutation) / **shared gap** (fuzzing) / **LEARN** (parity tests; multi-driver E2E) |
| 19 | Platforms | Linux native. macOS only through a Linux VM, and Windows through an experimental model. | Linux, and **native macOS as a production target** (AGENTS.md; the isolation contract), with each macOS delta recorded as a platform fact. | **A different bet.** OpenShell offers nothing to copy for confinement on native macOS. |
| 20 | Extension surface | Versioned gRPC extension points: gateway interceptors on the control plane, supervisor middleware on data-plane HTTP requests and responses, credential and compute drivers, and an isolation-backend trait. Interceptors see operations with secret-marked fields omitted recursively. `fail_open` is an operator option. | A narrow, versioned authorization seam with a fixed composition point (ADR-0004). No extension that can be plugged in at runtime. | **LEARN** (omitting secret fields by proto option; a versioned extension handshake) / **AVOID** (operator-selectable `fail_open` on validation) |
| 21 | Telemetry | On by default and sent to NVIDIA. The README understates what is sent (§1). | No telemetry and no phone-home. SIEM offload is a host agent tailing the JSONL (ADR-0019). | **AVOID** / **MAKNAE STRONGER** |
| 22 | Rules for agent-authored work | `AGENTS.md`: plans go in a gitignored in-repo directory "without asking". "Never mention Claude or any AI agent … no Co-Authored-By", which is not enforced: 15 such trailers across 5 commits (Claude, Cursor, Copilot Autofix). A vouch gate for first-time contributors. | Plans never in the repo, not even gitignored. `Co-Authored-By` kept; session links banned. TDD, reproduce-first, blind review. | **LEARN** (the vouch gate) / otherwise **MAKNAE STRONGER** |

## 4. What OpenShell does well — LEARN FROM

### 4.1 An outer fence beneath a finer mediator that can fail

OpenShell never relies on its proxy alone.
- **The fence.** A structural fence makes direct egress impossible: a container with no network, or a VM with no NIC.
- **Checked before start.** The fence is **reported as driver evidence and checked before the workload starts** (`sandbox.md:105-128`).
- **Refined inside.** The seccomp broker and the proxy refine within it. If the broker misses a syscall, "the outer fence still blocks direct egress" (`sandbox.md:306-308`).

**Maknae consideration.** This is the right shape for confining the loop, which Maknae does not do today (row 3; ADR-0023 decision 6 records the loop's direct I/O as "recorded, not solved"):
- Run `maknae agent` where direct egress is structurally impossible and only `maknaed`'s Unix socket is reachable. The deputy then becomes the *only* route to a model, not merely the *expected* one.
- ADR-0023's residual, that direct I/O is invisible to the trail, then shrinks to whatever the confinement admits.
- If such a layer is adopted, it should qualify its kernel features before admitting the workload, and fail closed. That means copying OpenShell's pre-admission probing, not its best-effort default for the optional filesystem policy.

The same evidence bears on shell execution. Whether a spawned command runs inside an isolation boundary is parked by maintainer ruling pending research (#175, `terminal.create`). OpenShell is one data point for that research:
- **Granularity.** It uses one long-lived container or VM per session, not a container per command.
- **Confines rather than classifies.** It confines and mediates the whole process instead of pattern-matching command lines.
- **Fail closed at launch.** It checks the boundary before launch and refuses to start without it.
- **macOS.** It confines on macOS only inside a Linux VM.

This record informs that research and does not decide it.

### 4.2 The containment checker's result contract

`check_within_boundary` returns exactly one of `Within | Exceeds | Unsupported | Inconclusive`, and only `Within` authorizes.
- A timeout, an unknown result or a resource limit gives `Inconclusive`.
- An unmodelled shape gives `Unsupported`.
- Each result names the domains it covered (`crates/openshell-prover/README.md:56-69`; `containment.rs:185-219, 480-490`).

**Maknae consideration.** If Maknae ever adds a check that a new `authz.yaml` stays within a ceiling document, this is the API shape to copy. It fails closed by construction, and it is honest about what it did not model. Maknae has no such check today and no ADR commits to one (row 8).

### 4.3 Parity tests between a verifier and the enforcer — and what happens without them

`crates/openshell-prover/tests/runtime_parity.rs` tests the containment checker's model against the real Rego engine. That is Maknae's principle 5 (test the real decision path) applied to a verifier.

The sharper lesson is the other half. The **proposal prover**, the one that actually gates auto-approval, has no parity test, and it diverges from the runtime:
- it treats `audit` as enforced (`crates/openshell-prover/src/policy.rs:72-74`);
- it ignores `spawns`.

The runtime forwards under `audit`, and grants spawned children through ancestor-path matching, which the prover's unused `spawns` field was meant to model. Any Maknae verifier needs parity tests that are proven able to fail, per the negative-control gate.

### 4.4 Recompute derived authority in full

Credential provenance is recomputed from scratch on every evaluation, because "a delta-based derivation would let a series of individually valid edits reach a state no single edit would have admitted" (`security-policy.md:157-158`). Two related mechanisms back it up:
- A review token binds an approval to the candidate *and its live inputs*, and the candidate is recomputed if those inputs change before approval (`security-policy.md:320-322`).
- Connections pinned to an older policy generation are closed (`security-policy.md:110-114`).

Policy edits themselves can be merged incrementally (`grpc/policy.rs:3950-3970`). What is always recomputed is the *derived* authority.

**Maknae consideration.** This is a general rule worth writing into the ADR that eventually governs `admin.policy.reload` (#164): derive authority from the whole policy every time, and close or re-decide anything admitted under an older generation.

### 4.5 A race-checked identity snapshot

`openshell-binary-identity`:
- hashes the *opened* `/proc/<pid>/exe` object;
- snapshots pid, ppid, start time, dev, ino, size, mtime and ctime;
- **re-validates the snapshot after hashing**, to reject races (`crates/openshell-binary-identity/src/lib.rs:245-303`).

**Maknae consideration.** The technique is sound and fits `maknae-io`'s descriptor discipline. OpenShell's use of it is not sound (§6.5). If Maknae ever keys a decision on process identity (the ADR-0006 per-process binding, #115), take the technique and leave the semantics.

### 4.6 A trusted helper that protects itself from an agent with the same uid

`openshell-sandbox` runs as the agent's uid, yet the agent cannot tamper with it. It uses:
- `PR_SET_DUMPABLE 0`;
- a child seccomp program denying ptrace, `process_vm_*`, `pidfd_*`, `kcmp`, and signals aimed at the helper;
- a Landlock baseline that hides the helper's state directory;
- signals sent through pidfds, so PID reuse cannot redirect them.

Sources: `openshell-sandbox/src/main.rs:190-191`; `openshell-isolation-interface/src/linux/child_seccomp.rs`; `sandbox.md:191-198, 936-944`.

**Maknae consideration.** Maknae's CLI and loop share the subject's uid by design. On Linux, a Landlock baseline built this way could keep a compromised loop away from state it does not need. The loop does need the CLI's SecretID and certificate (ADR-0023 decision 2), so hiding those means a separate credential-holding helper that authenticates on the loop's behalf — which is what `openshell-sandbox` is to its agent. Landlock is Linux-only. On a packaged install the audit files are already out of reach, being kernel-owned `0700`; in the development shape the trail is the operator's own file.

### 4.7 Honest conformance language

RFC 0012 says: "Treat conformance as behavioral, not as a security-strength rating" (`rfc/0012-isolation-backend/README.md:367`). It names each backend's weaker guarantees, such as native Windows lacking per-connection binary identity.

This is the discipline of Maknae's isolation contract, and a good model for how a Maknae loop-confinement backend should describe itself on each platform.

### 4.8 Release provenance

- Sigstore build-provenance attestations on release packages (`release-tag.yml:515-523`), with `gh attestation verify` documented for VM kernels (`release-vm-kernel.yml`).
- A vouch gate that auto-closes a first-time contributor's PR until a maintainer vouches for them (`.github/VOUCHED.td`).

**Maknae consideration.** Both are cheap to adopt. The attestations fit #188 (automated signed release builds) and #96 (package signing).

## 5. Where the two can be composed — INTEGRATE

These are candidates for the maintainer to rule on, not commitments. Each keeps OpenShell **outside** Maknae's trust boundary, so no Maknae control rests on OpenShell (the external-authority doctrine: another project informs, never governs).

### 5.1 OpenShell as an outer sandbox around the untrusted loop (Linux)

**The setup.** Run `maknae agent` inside an OpenShell sandbox:
- no providers and no network policy;
- a container placement: the mandatory outer fence as a container with no network (a VM guest would not get host `AF_UNIX` connectivity or a meaningful `SO_PEERCRED`), plus an empty `network_policies`, so L4 denies every destination. Gateway-delivered policy always runs in proxy mode (`crates/openshell-core/src/policy.rs:114-121`), so the stricter block-mode seccomp is not selectable this way. Whether a bind-mounted `AF_UNIX` socket passes the seccomp broker and the Landlock baseline is not established here and would need testing;
- `maknaed`'s socket bind-mounted in;
- `proposal_approval_mode` pinned to manual at gateway scope, or a `validate` interceptor that rejects proposal chunks, because in `auto` mode the loop's own denied connections become approved grants (§6.1);
- no gateway-global policy, since a global policy replaces the sandbox policy (row 5).

The loop can then reach only `maknaed`, and the deputy becomes the only route to a model.

**What must be settled first:**
- **Where `maknaed` runs.** Outside the sandbox. The sandbox's uid, as `maknaed` sees it through `SO_PEERCRED`, must be the enrolled subject. If the sandbox runs in a user namespace, the mapping must be established so the peer uid is the host uid Maknae enrolled.
- **Admission.** ADR-0006 decision 4's target model admits a connection only from a process in its own logind session with `Class=user`, with `maknae` group membership re-resolved from the host user database (#115). A container process has no such session, so that model would refuse the sandboxed loop until it gains an equivalent. On macOS, a loop inside a VM cannot present `LOCAL_PEERCRED` to a host `maknaed` socket at all.
- **The loop's credential.** It holds the CLI SecretID and certificate (ADR-0023 decision 2). These would have to be mounted into a workload that a third party manages, so a Maknae credential enters that workload.
- **No double credential holding.** OpenShell's own credential injection must stay unused, so no credential is held by both.
- **OpenShell's own components.** Its supervisor, gateway and telemetry become infrastructure that Maknae neither trusts nor certifies.
- **macOS.** There the loop would run inside OpenShell's Linux VM, which cuts against Maknae's native-macOS target.

**Verdict:** a plausible defence-in-depth layer on Linux for deployments that already run OpenShell. It is not a substitute for the confinement §4.1 describes, if Maknae adopts one, which would need an answer on both platforms.

### 5.2 OCSF as a projection of Maknae's audit record

OCSF v1.8 is becoming a common SIEM shape. Maknae could emit an OCSF *projection* of its canonical record:
- API Activity (6003) for verbs;
- Detection Finding for denials.

The ADR-0019 record stays primary, and OCSF never becomes the AU-3 surface. This fits #223's export seam. `openshell-ocsf` is Apache-2.0 pure Rust but emits through `tracing`, so **implement the schema independently** rather than depending on the crate (§1).

### 5.3 Maknae as a veto service for an OpenShell deployment

OpenShell's `GatewayInterceptor` has three phases (`rfc/0010-gateway-interceptors/README.md:141-145`):
- **`validate`** can only reject;
- **`modify_operation`** can change an operation, including stamping a sandbox policy and selecting a provider profile;
- **`post_commit`** notifies.

`SupervisorMiddleware` can allow, deny or transform data-plane HTTP traffic that the proxy terminates and parses, including endpoints with no `protocol` set.
- **Requests.** It runs before credential injection (`rfc/0009-supervisor-middleware/README.md:142-164`).
- **Responses.** A later addition, not reflected in RFC 0009's text, runs it on HTTP responses before the sandbox receives them (`HttpResponsePreReturn`, `proto/supervisor_middleware.proto:43-45`; called from the relay at `crates/openshell-supervisor-network/src/l7/relay.rs:1333`; `docs/extensibility/supervisor-middleware/operations.mdx`).
- **What it does not see:** `tls: skip` hosts; opaque TCP and non-HTTP traffic; binary, control and upstream-to-client WebSocket frames; response bodies that are compressed, partial or marked `no-transform`; and `101` upgrade responses.

`maknaed` could bind as a **`validate`-phase interceptor and a deny-only middleware**, configured `fail_closed`:
- It would veto sandbox creation, policy changes and provider selection against Maknae's RBAC and classification ceiling. Policy content can only be judged where it is submitted or edited (`SubmitPolicyAnalysis`, `EditDraftChunk`, `UpdateConfig`); approval requests carry only chunk IDs (`proto/openshell.proto`, `ApproveDraftChunkRequest`).
- It would veto HTTP content against the ceiling in both directions: refusing content marked above the declared level from leaving through an OpenShell proxy, and refusing such content before the sandbox receives it in a response.
  - **The outbound check is a spillage tripwire, not containment.** The marking it ranks sits in bytes the untrusted agent wrote, so a compromised agent can strip the banner, encode the body, or compress it. Content the agent can author may inform a decision but never authorize one (AGENTS.md principle 2). The inbound check is sounder, because upstream content is not agent-authored.
  - **Bind whole-body inspection.** Under `fail_closed`, a deny-only binding that requests whole-body inspection makes compressed, partial and `no-transform` responses refused rather than delivered unseen. A streamed-body mode could deliver bytes before deciding (`docs/extensibility/supervisor-middleware/operations.mdx`). On the hosts it selects, a `fail_closed` middleware denies non-HTTP TCP it cannot inspect. Once a WebSocket upgrade is allowed, however, binary frames are relayed whatever the middleware's failure policy says, and text frames are inspected only if the middleware implements the WebSocket message operation (`crates/openshell-supervisor-network/src/l7/websocket.rs:844-870`; `rfc/0009-supervisor-middleware/README.md:148-152`). A ceiling veto would therefore have to cover every allowed host, which rules out any `tls: skip` endpoint, and deny the WebSocket upgrade request itself on each of them. This assessment has not established every path the middleware does not see; any real integration would need that analysis first.

It should not bind in `modify_operation`, which can widen an operation. It could not be OpenShell's sole PDP, because the embedded Rego engine stays authoritative for reachability. Deny-overrides composition makes that acceptable. **The integration must refuse `fail_open`.**

This is the most interesting commercial composition: Maknae's classification-aware decisions layered onto NVIDIA's runtime. It is also a new external interface, and so a security decision to take deliberately (AGENTS.md principle 3).

## 6. What to avoid — AVOID

1. **Letting the agent author its own authority.**
   - RFC 0002 lets the agent read its policy and denials, and submit proposals.
   - `auto` mode approves a proposal when the prover delta and the security notes are both empty.
   - The proposal prover does not track reach to a host with no credential (`crates/openshell-prover/src/queries.rs:116`).
   - The security notes (`crates/openshell-server/src/grpc/policy.rs`, `generate_security_notes`) flag uninspected credentials, internal or private IP-literal destinations, wildcard hosts, private or internal `allowed_ips`, hostless `allowed_ips`, ports above 49152, and common database ports. They do not flag an exact public hostname on an ordinary port.
   - Agent-authored proposals cannot request `protocol: tcp` or `tls: skip` (`security-policy.md:305-309`). That check applies to agent-authored chunks only (`crates/openshell-server/src/grpc/policy.rs:5017`).
   - The **mechanistic** proposer runs whether or not agent proposals are enabled, and `auto` mode is proposer-agnostic (`security-policy.md:286-300, 323`; test `mechanistic_proposal_with_empty_delta_also_auto_approves`, `grpc/policy.rs:16020`). When it observed HTTP it proposes `protocol: rest` with `enforcement: enforce`, restricted to the sampled method and path rules (`crates/openshell-supervisor/src/mechanistic_mapper.rs:129-139`). Otherwise it proposes an endpoint with no protocol (`:141-148`). Such an endpoint keeps explicit-proxy behavior, not transparent capture (`security-policy.md:310-311`), and on the explicit proxy's CONNECT path non-TLS, non-HTTP bytes are relayed raw when no L7 route applies (`crates/openshell-supervisor-network/src/proxy.rs:3196-3207`).
   - So **in `auto` mode, the agent can obtain a grant just by attempting a connection.** It attempts, for example, `nc evil.example 22`; the attempt is denied; the mapper proposes it; the prover finds no credential and the notes find nothing; the grant is approved without a human. If the agent then reaches the sandbox's explicit proxy (CONNECT), that traffic is relayed uninspected. That is agent-driven content becoming a grant, which AGENTS.md principle 2 forbids.
   - The unsafe state is `auto` mode itself. Leaving agent proposals off does not close it. With the default manual approval, every proposal waits for a human (`security-policy.md:323-341`). OpenShell's governance-interceptor example (`examples/governance-interceptor/README.md`) denies any request carrying proposed chunks, from either proposer, and bans `auto`.
2. **Letting the enforcement point persist policy.**
   - The supervisor's sandbox-policy sync writes a network-policy revision without going through the draft and approval flow.
   - It is gated: static fields cannot change, provider-derived entries are stripped, and the revision does not by itself authorize workload activation (row 7).
   - It is still a policy-write capability held by the enforcement point, bounded by the isolation of the supervisor's credential. Maknae keeps policy authority with root and the operator (ADR-0002; ADR-0005).
3. **Fail-open states reachable through defaults, configuration or platform.**
   - L7 `audit` is the default.
   - The optional workload filesystem policy is best effort by default.
   - An operator can set `allow_unauthenticated_users`, which the Helm values mark UNSAFE, and a gateway configured with no authenticator of any kind, and with mTLS user auth off, admits every gRPC caller as an unauthenticated dev principal (`multiplex.rs:1014-1040`). That principal holds the admin and user roles and scope `openshell:all` (`multiplex.rs:963-973`), so it is effectively an administrator. More generally, role checks exist only when OIDC is configured (`multiplex.rs:246`): an mTLS-authenticated user without OIDC is also unchecked by role, and is treated as platform administrator at workspace scope (`crates/openshell-server/src/lib.rs:353-355`). The gateway's HTTP routes were not traced. Which authenticators a given deployment recipe ends up with, and so who can reach an open gateway, was not traced by this assessment.
   - An operator can choose "auth-only" gateway mode by setting both role names empty (`auth/authz.rs:25-31`).
   - An operator can choose `fail_open` on validation interceptors.
   - A latent non-Linux `apply()` returns `Ok`.

   Maknae's counterpart is that no operand may fail open and every refusal fails closed (principle 4; ADR-0008 §4).
4. **Calling constant evaluation "formal verification."** The proposal prover asserts fixed facts to Z3, so nothing is searched. If Maknae ever claims formal verification of policy (SA-17(1)), the claim must name exactly what is solved symbolically and what is looked up. The same applies to a verifier whose model diverges from the enforcer (§4.3).
5. **Identity by path, ancestry or first use.**
   - Authorizing by executable path, or by *any ancestor's* path, lets everything an allowed binary spawns inherit its grants. That includes interpreters such as `python3`.
   - Pinning a digest on first use catches a swap during the sandbox's life, not a binary trojaned before first use.
6. **A TLS interception CA with no name constraints** in the workload's trust store (`crates/openshell-supervisor-network/src/l7/tls.rs:42-63`; the CA's private key stays in the supervisor). If Maknae ever inspects TLS on the loop's behalf, constrain the CA to the names it inspects.
7. **Audit and telemetry.**
   - An audit sink that is off by default, that drops lines under backpressure, and that is silently disabled if its directory cannot be opened.
   - Telemetry that is on by default and goes to a vendor endpoint.
8. **Key handling.** A key-encryption key in the environment, and keys harvested from the operator's shell.
9. **Documents that contradict the code, and each other.** This is the failure AGENTS.md's in-place-correction rule exists for:
   - the telemetry README against `telemetry.rs`;
   - RFC 0009 ("response-body scanning" out of scope) against the response middleware the relay now runs;
   - `architecture/README.md` against `sandbox.md` on where the supervisor runs;
   - `compute-runtimes.md` against `sandbox.md` on VM status, Podman conversion, namespaces and capabilities;
   - the observability docs ("inside the sandbox") against the supervisor's log writer, which writes to the supervisor's own `/var/log`.

## 7. Where Maknae is stronger under its current ADRs

- **Complete mediation of what the loop asks for.** Every file operation and model turn is a decision with a write-ahead record (ADR-0009, ADR-0019). OpenShell decides egress only; it bounds execution by its filesystem allowlist but decides and audits no individual action.
- **Mandatory controls no role can bypass.** Deny-overrides with an always-present classification-ceiling operand, and no clearance bypass for admins or the kernel (ADR-0008, ADR-0020, ADR-0022). OpenShell has no labels and no MAC; its "org ceiling" is RFC direction only.
- **Inform, never authorize.** No path leads from agent-supplied content to a grant (AGENTS.md principle 2). OpenShell's `auto` mode is such a path.
- **Credential custody by absence.**
  - The loop never composes a provider request.
  - It never sees a raw provider response: headers, token refreshes, or anything the deputy has not validated into a bounded reply.
  - It holds no placeholder that a crafted request can spend (ADR-0023 decision 3).
  - Its trust store holds no interception CA.
- **Write-ahead, fail-closed audit.** Intent is recorded before the effect, a failure of the primary sink blocks the effect, and the record holds a digest but never the content (ADR-0019). Neither project has cryptographic audit integrity yet (§8).
- **Confined first-party `unsafe`, and a fail-closed dependency policy** (ADR-0002, ADR-0027; `deny.toml`). Both projects link native crypto.
- **A fail-closed test discipline.** Risk-tiered coverage, mutation testing, negative controls and blind review (ADR-0016; AGENTS.md).
- **Native macOS as a production target**, with each platform delta stated (the isolation contract).

## 8. Where Maknae is weaker — honest gaps

- **The loop is unconfined.** A compromised loop can open sockets and read anything the subject can. Maknae mediates what the loop *asks* the kernel for, not what the loop *does* (ADR-0023 decisions 2 and 6 say so plainly). OpenShell's fence, Landlock and seccomp answer this on Linux (§4.1, §5.1).
- **No mediation of the loop's own sockets**, beyond best-effort nftables (the isolation contract).
- **The custody check is manual.** "No egress credential is readable by the operator uid" is checked by hand; the automated assertion is not built (`packaging/isolation-contract.md`, egress rows).
- **No process identity finer than the uid** (ADR-0023 decision 3; #115).
- **No formal verification of policy containment**, and no ADR commits to one (row 8).
- **No cryptographic audit integrity.** AU-9(3)/AU-10 is a tracked gap (ADR-0019 decision 2; #82).
- **Native code in the TCB.** The linked AWS-LC module is C and assembly, and the native-code visibility gap is recorded (`2026-08-30-fips-supply-chain-visibility.md`).
- **No fuzzing or property tests**, although CBOR decoding sits on a trust boundary. ADR-0002 lists "property tests" among its SA-11 evidence, and `design/container-architecture.md` names `proptest`; neither is in the tree, so that mapping is stale and needs correcting in place. (ADR-0002's SA-17(1) row, by contrast, was already reconciled by its 2026-08-22 amendment.)
- **Published release signing is not yet in place.** A notarized Developer ID macOS `.pkg` has been built (`packaging/macos/README.md`); automated signed releases (#188) and deb/rpm signing (#96) remain open.
- **Custody has stated limits.** On every packaged install, Linux and macOS alike, the operator's own `maknae-enroll` token can mint a `maknae-egress` SecretID in Vault, which lies outside the file-custody claim (runbook Chapter 4 step 13; ADR-0023 decision 3). In the development shape, custody does not hold at all (ADR-0023 decision 3). And the claim holds against the operator's uid, not against root, a sudoer, or a macOS administrator who approves the keychain dialog (ADR-0018 decision 6; runbook Chapter 4 step 13).
- **No OCSF or other standard audit projection** (#223).

## 9. Open questions for the maintainer

1. **Loop confinement.** Should Maknae specify its own loop confinement per platform (§4.1), with OpenShell's layering as the reference design? The execution-isolation question in #175 stays parked by ruling; §4.1 records OpenShell as research input to it. Separately, should the OpenShell outer-sandbox composition (§5.1) be documented as a supported Linux deployment option?
2. **OCSF.** Should #223 name OCSF as a target projection (§5.2)?
3. **Maknae as an OpenShell veto service (§5.3).** Is it worth an evaluation as a product direction, including the inbound check (refusing above-ceiling content before it reaches the sandbox)? How OpenShell's callers (OIDC users, sandbox principals) map to Maknae's enrolled subjects is unresolved. It would be a new external interface.
4. **Formal verification.** Should Maknae open a decision on verifying policy containment, with the containment-contract shape (§4.2) as its API?
5. **Fuzzing.** Should the CBOR decoders get fuzz or property testing, given they sit on a trust boundary (§8)?
6. **SCRM.** If any composition goes ahead, it needs a separately authorized evaluation, pinned by attested digest and with telemetry compiled out. Who owns that evaluation?

## 10. Sources

Pinned repository evidence (commit [`1358941`](https://github.com/NVIDIA/OpenShell/tree/1358941b818d4126a7374aaf5216d87fc960e122)):

- **Architecture:** [`architecture/README.md`](https://github.com/NVIDIA/OpenShell/blob/1358941b818d4126a7374aaf5216d87fc960e122/architecture/README.md), [`architecture/sandbox.md`](https://github.com/NVIDIA/OpenShell/blob/1358941b818d4126a7374aaf5216d87fc960e122/architecture/sandbox.md), [`architecture/security-policy.md`](https://github.com/NVIDIA/OpenShell/blob/1358941b818d4126a7374aaf5216d87fc960e122/architecture/security-policy.md), [`architecture/compute-runtimes.md`](https://github.com/NVIDIA/OpenShell/blob/1358941b818d4126a7374aaf5216d87fc960e122/architecture/compute-runtimes.md), [`docs/about/support-matrix.mdx`](https://github.com/NVIDIA/OpenShell/blob/1358941b818d4126a7374aaf5216d87fc960e122/docs/about/support-matrix.mdx)
- **RFCs:** [0001 core architecture](https://github.com/NVIDIA/OpenShell/tree/1358941b818d4126a7374aaf5216d87fc960e122/rfc/0001-core-architecture), [0002 agent-driven policy management](https://github.com/NVIDIA/OpenShell/tree/1358941b818d4126a7374aaf5216d87fc960e122/rfc/0002-agent-driven-policy-management), [0005 egress adapter](https://github.com/NVIDIA/OpenShell/tree/1358941b818d4126a7374aaf5216d87fc960e122/rfc/0005-sandbox-proxy-egress-adapter), [0009 supervisor middleware](https://github.com/NVIDIA/OpenShell/tree/1358941b818d4126a7374aaf5216d87fc960e122/rfc/0009-supervisor-middleware), [0010 gateway interceptors](https://github.com/NVIDIA/OpenShell/tree/1358941b818d4126a7374aaf5216d87fc960e122/rfc/0010-gateway-interceptors), [0012 isolation backend](https://github.com/NVIDIA/OpenShell/tree/1358941b818d4126a7374aaf5216d87fc960e122/rfc/0012-isolation-backend), [0013 native Windows](https://github.com/NVIDIA/OpenShell/tree/1358941b818d4126a7374aaf5216d87fc960e122/rfc/0013-native-windows-mxc)
- **Policy and prover:** [`crates/openshell-policy-schema/src/lib.rs`](https://github.com/NVIDIA/OpenShell/blob/1358941b818d4126a7374aaf5216d87fc960e122/crates/openshell-policy-schema/src/lib.rs), [`crates/openshell-supervisor-network/data/sandbox-policy.rego`](https://github.com/NVIDIA/OpenShell/blob/1358941b818d4126a7374aaf5216d87fc960e122/crates/openshell-supervisor-network/data/sandbox-policy.rego), [`crates/openshell-supervisor-network/src/l7/mod.rs`](https://github.com/NVIDIA/OpenShell/blob/1358941b818d4126a7374aaf5216d87fc960e122/crates/openshell-supervisor-network/src/l7/mod.rs), [`crates/openshell-server/src/grpc/policy.rs`](https://github.com/NVIDIA/OpenShell/blob/1358941b818d4126a7374aaf5216d87fc960e122/crates/openshell-server/src/grpc/policy.rs), [`crates/openshell-prover/src/queries.rs`](https://github.com/NVIDIA/OpenShell/blob/1358941b818d4126a7374aaf5216d87fc960e122/crates/openshell-prover/src/queries.rs), [`crates/openshell-prover/src/containment.rs`](https://github.com/NVIDIA/OpenShell/blob/1358941b818d4126a7374aaf5216d87fc960e122/crates/openshell-prover/src/containment.rs), [`crates/openshell-prover/README.md`](https://github.com/NVIDIA/OpenShell/blob/1358941b818d4126a7374aaf5216d87fc960e122/crates/openshell-prover/README.md)
- **Sandbox:** [`crates/openshell-sandbox/src/sandbox/mod.rs`](https://github.com/NVIDIA/OpenShell/blob/1358941b818d4126a7374aaf5216d87fc960e122/crates/openshell-sandbox/src/sandbox/mod.rs), [`crates/openshell-core/src/policy.rs`](https://github.com/NVIDIA/OpenShell/blob/1358941b818d4126a7374aaf5216d87fc960e122/crates/openshell-core/src/policy.rs), [`crates/openshell-binary-identity/src/lib.rs`](https://github.com/NVIDIA/OpenShell/blob/1358941b818d4126a7374aaf5216d87fc960e122/crates/openshell-binary-identity/src/lib.rs), [`crates/openshell-server/src/cli.rs`](https://github.com/NVIDIA/OpenShell/blob/1358941b818d4126a7374aaf5216d87fc960e122/crates/openshell-server/src/cli.rs)
- **Egress, credentials and audit:** [`crates/openshell-supervisor-network/src/l7/tls.rs`](https://github.com/NVIDIA/OpenShell/blob/1358941b818d4126a7374aaf5216d87fc960e122/crates/openshell-supervisor-network/src/l7/tls.rs), [`crates/openshell-core/src/secrets.rs`](https://github.com/NVIDIA/OpenShell/blob/1358941b818d4126a7374aaf5216d87fc960e122/crates/openshell-core/src/secrets.rs), [`crates/openshell-driver-db-credstore/src/lib.rs`](https://github.com/NVIDIA/OpenShell/blob/1358941b818d4126a7374aaf5216d87fc960e122/crates/openshell-driver-db-credstore/src/lib.rs), [`crates/openshell-ocsf/src/lib.rs`](https://github.com/NVIDIA/OpenShell/blob/1358941b818d4126a7374aaf5216d87fc960e122/crates/openshell-ocsf/src/lib.rs)
- **Telemetry:** [`crates/openshell-core/src/telemetry.rs`](https://github.com/NVIDIA/OpenShell/blob/1358941b818d4126a7374aaf5216d87fc960e122/crates/openshell-core/src/telemetry.rs), [`crates/openshell-core/Cargo.toml`](https://github.com/NVIDIA/OpenShell/blob/1358941b818d4126a7374aaf5216d87fc960e122/crates/openshell-core/Cargo.toml), [`README.md`](https://github.com/NVIDIA/OpenShell/blob/1358941b818d4126a7374aaf5216d87fc960e122/README.md)
- **Governance and supply chain:** [`GOVERNANCE.md`](https://github.com/NVIDIA/OpenShell/blob/1358941b818d4126a7374aaf5216d87fc960e122/GOVERNANCE.md), [`MAINTAINERS.md`](https://github.com/NVIDIA/OpenShell/blob/1358941b818d4126a7374aaf5216d87fc960e122/MAINTAINERS.md), [`SECURITY.md`](https://github.com/NVIDIA/OpenShell/blob/1358941b818d4126a7374aaf5216d87fc960e122/SECURITY.md), [`deny.toml`](https://github.com/NVIDIA/OpenShell/blob/1358941b818d4126a7374aaf5216d87fc960e122/deny.toml), [`AGENTS.md`](https://github.com/NVIDIA/OpenShell/blob/1358941b818d4126a7374aaf5216d87fc960e122/AGENTS.md), [`.github/workflows/release-tag.yml`](https://github.com/NVIDIA/OpenShell/blob/1358941b818d4126a7374aaf5216d87fc960e122/.github/workflows/release-tag.yml)
- **Further code cited above:** [`crates/openshell-supervisor/src/mechanistic_mapper.rs`](https://github.com/NVIDIA/OpenShell/blob/1358941b818d4126a7374aaf5216d87fc960e122/crates/openshell-supervisor/src/mechanistic_mapper.rs), [`crates/openshell-supervisor/src/main.rs`](https://github.com/NVIDIA/OpenShell/blob/1358941b818d4126a7374aaf5216d87fc960e122/crates/openshell-supervisor/src/main.rs), [`crates/openshell-supervisor-network/src/proxy.rs`](https://github.com/NVIDIA/OpenShell/blob/1358941b818d4126a7374aaf5216d87fc960e122/crates/openshell-supervisor-network/src/proxy.rs), [`crates/openshell-supervisor-network/src/l7/relay.rs`](https://github.com/NVIDIA/OpenShell/blob/1358941b818d4126a7374aaf5216d87fc960e122/crates/openshell-supervisor-network/src/l7/relay.rs), [`crates/openshell-server/src/multiplex.rs`](https://github.com/NVIDIA/OpenShell/blob/1358941b818d4126a7374aaf5216d87fc960e122/crates/openshell-server/src/multiplex.rs), [`crates/openshell-server/src/auth/authz.rs`](https://github.com/NVIDIA/OpenShell/blob/1358941b818d4126a7374aaf5216d87fc960e122/crates/openshell-server/src/auth/authz.rs), [`crates/openshell-sandbox/src/sandbox/linux/landlock.rs`](https://github.com/NVIDIA/OpenShell/blob/1358941b818d4126a7374aaf5216d87fc960e122/crates/openshell-sandbox/src/sandbox/linux/landlock.rs), [`crates/openshell-sandbox/src/sandbox/linux/seccomp.rs`](https://github.com/NVIDIA/OpenShell/blob/1358941b818d4126a7374aaf5216d87fc960e122/crates/openshell-sandbox/src/sandbox/linux/seccomp.rs), [`crates/openshell-isolation-interface/src/linux/child_seccomp.rs`](https://github.com/NVIDIA/OpenShell/blob/1358941b818d4126a7374aaf5216d87fc960e122/crates/openshell-isolation-interface/src/linux/child_seccomp.rs), [`crates/openshell-sandbox/src/main.rs`](https://github.com/NVIDIA/OpenShell/blob/1358941b818d4126a7374aaf5216d87fc960e122/crates/openshell-sandbox/src/main.rs), [`crates/openshell-providers/src/discovery.rs`](https://github.com/NVIDIA/OpenShell/blob/1358941b818d4126a7374aaf5216d87fc960e122/crates/openshell-providers/src/discovery.rs), [`crates/openshell-prover/src/policy.rs`](https://github.com/NVIDIA/OpenShell/blob/1358941b818d4126a7374aaf5216d87fc960e122/crates/openshell-prover/src/policy.rs), [`crates/openshell-prover/tests/runtime_parity.rs`](https://github.com/NVIDIA/OpenShell/blob/1358941b818d4126a7374aaf5216d87fc960e122/crates/openshell-prover/tests/runtime_parity.rs), [`deploy/docker/Dockerfile.gateway`](https://github.com/NVIDIA/OpenShell/blob/1358941b818d4126a7374aaf5216d87fc960e122/deploy/docker/Dockerfile.gateway), [`docs/how-it-works/gateways/container-deployment.mdx`](https://github.com/NVIDIA/OpenShell/blob/1358941b818d4126a7374aaf5216d87fc960e122/docs/how-it-works/gateways/container-deployment.mdx)

Public context, which is not evidence for any code claim above:

- [NVIDIA Newsroom: Open Agent Safety Platform](https://nvidianews.nvidia.com/news/open-agent-safety-platform) (2026-09-28)
- [NVIDIA Technical Blog: continuous in-silicon agent monitoring](https://developer.nvidia.com/blog/nvidia-open-agent-safety-platform-a-reference-for-continuous-in-silicon-agent-monitoring/)
- [Red Hat Developer: layered sandboxing for AI agents with OpenShift and OpenShell](https://developers.redhat.com/articles/2026/07/16/layered-sandboxing-ai-agents-openshift-and-openshell)
- [cncf/sandbox#522](https://github.com/cncf/sandbox/issues/522): the CNCF sandbox application, voted but not yet concluded as of 2026-09-29
