# ADR-0036: The tool model — the kernel authorizes, the front end executes in a container; a Maknae-native `tools.yaml`; network only through `maknae-proxy`; per-tool credential classes; secrets reach tools, never the model

- **Status:** Accepted (maintainer-ruled 2026-11-18)
- **Date:** 2026-11-18
- **Deciders:** Alex Ackerman (maintainer)
- **Raised by:** [#420](https://github.com/darkhonor/maknae/issues/420) (decisions 3, 4, 10 and 12), [#477](https://github.com/darkhonor/maknae/issues/477)
- **Amends:** [ADR-0023](ADR-0023-runtime-loop-role-and-placement.md) decisions 2, 4 and 6; [ADR-0024](ADR-0024-tenancy-model-and-agent-identity.md) decision 6 and its workspace residual
- **Builds on:** [ADR-0035](ADR-0035-policy-enforcement-points-placement-and-trust-tiers.md) (PEP placement and trust tiers)

## Context

Rabbithole's acceptance ([#420](https://github.com/darkhonor/maknae/issues/420)) is an agent reviewing a real pull request with `gh`, `git` and `cargo`, with every tool invocation decided and audited. The tool model has been open since 2026-09-30, and it blocks [#477](https://github.com/darkhonor/maknae/issues/477), [#479](https://github.com/darkhonor/maknae/issues/479), [#480](https://github.com/darkhonor/maknae/issues/480), [#481](https://github.com/darkhonor/maknae/issues/481) and [#483](https://github.com/darkhonor/maknae/issues/483).

Two threats shape it. The model is of uncertain origin and chooses the commands. And a pull request's own code runs when it is built: `build.rs`, procedural macros and tests run as whoever runs `cargo`. A tool run directly on the host as a user hands both of them that user's whole account. So the maintainer's direction is that the kernel **authorizes** each invocation and never executes one, the process that asked runs it under its own uid (so there is a kernel trail and a system trail), and containment is a container with focused mounts. Kubernetes is the next deployment profile, so nothing decided here may assume a single host.

Three approaches were surveyed: a host fence (bubblewrap or systemd sandboxing of host tools), a host container (rootless Podman), and a Kubernetes sandbox pod ([Agent Sandbox](https://github.com/kubernetes-sigs/agent-sandbox), a Kubernetes SIG Apps project). The host fence varies by distribution and has no Kubernetes analogue. The host container maps onto Kubernetes. This ADR takes the host container for Rabbithole and Kubernetes as the second backend of the same configuration.

**Measured, 2026-11-18** (rootless Podman 5.4.2 on a Debian 13 test host, 4 vCPU; a STIG'd RHEL 10 test host):

- **Per-invocation cost.** With the image already pulled, starting a container costs 61 to 129 ms. With the cargo registry and target directories as persistent volumes, a warm `cargo clippy --workspace --all-targets` took 189 ms in the container against 116 ms on the host, and one changed file then took 3.7 s. Without persistent volumes every invocation is a cold build (68.5 s).
- **Image bases.** No free image covers a Maknae build as published; `aws-lc-fips-sys` needs cmake, Go and perl on top of a Rust image.
  - **Wolfi** (Chainguard's free `rust:latest-dev`, per its published catalogue): release builds link, but every debug and test binary that links the FIPS module fails. Wolfi's gcc 16 emits six absolute relocations against `.text` in aws-lc's `bcm.o`, and Wolfi's gcc passes `-z text`, which makes them fatal. An optimized build of the module did not help. Linking with `-C relocation-model=static` succeeded, and the resulting test binary then failed the FIPS integrity self-test at start-up. So no flag makes Wolfi work.
  - **UBI 10 and Rocky Linux 10** (gcc 14): debug test builds and release builds both succeed, with 0 `TEXTREL` in the four release binaries and in a debug FIPS test binary, which also passes its self-test. The images as built were 3.27 GB (UBI 10) and 2.28 GB (Rocky 10). UBI's free repositories are a subset of RHEL with no EPEL.
- **Network fencing.** The goal is a container that can reach the proxy and nothing else.
  - pasta, Podman's default rootless network, cannot do it: forwarding the proxy's port needs pasta's TCP handler, and with the handler on, the container reached `1.1.1.1:443` directly by IP.
  - An internal Podman network (`--internal`), plus a relay run inside Podman's rootless network namespace on that network's gateway address, works. Through the relay the tool reached `api.github.com` and `git ls-remote` succeeded, and the proxy refused `example.com`. Direct TCP by IP, DNS by name and over UDP, IPv6, the host's LAN address, the gateway's other ports and Podman's host address were all blocked. Starting a container on the internal network cost 200 ms against 114 ms with no network.
- **STIG'd RHEL 10.** `user.max_user_namespaces=0` stops rootless Podman, and fapolicyd blocks `crun` until it is trusted.

## Decision

1. **The kernel authorizes; the front end executes.** For each tool call the model makes, the front end (`maknae` for an operator, `maknae-agentd` for an agent) asks `maknaed`. The kernel decides and records intent. On a Permit the front end starts the tool's container under its own uid, carries out the decision's obligations ([ADR-0035](ADR-0035-policy-enforcement-points-placement-and-trust-tiers.md) decision 3), and reports the outcome, which the kernel records. This extends [ADR-0023](ADR-0023-runtime-loop-role-and-placement.md) decision 4 (the subject's process does the work) to tool containers. A trusted launcher, a privileged component that would be the only path to the container runtime, was considered and rejected: what it would add, enforcement against a compromised front end, is better delivered by the runtime and infrastructure tier ([ADR-0035](ADR-0035-policy-enforcement-points-placement-and-trust-tiers.md) decision 2).

2. **Containers are the default for tool invocation. Terminal (host) execution is configurable and disabled by default.** It is a single site setting in the global configuration (for example `tools.terminal.enabled: false`), not a per-tool or per-user field, and only the host administrator can enable it.

3. **Rabbithole scope: local front ends only.** Tool execution is for `maknae` and `maknae-agentd` on the same host as `maknaed`. Remote and mobile front ends belong to the gateway ([#117](https://github.com/darkhonor/maknae/issues/117)), another milestone.

4. **Agent tools run as the agent's uid, and taskers are separated by partition.** The partition operand ([ADR-0008](ADR-0008-authorization-composition-contract.md), amendment 2026-11-11) already separates taskers inside the agent's home. A tasked tool's work is never mounted outside the tasker's partition: the workspace mount lies inside `tasks/users/<uid>` or `tasks/agents/<id>` for the task's tasker. Per-tasker workspace uids ([#476](https://github.com/darkhonor/maknae/issues/476)) are retired: starting a process as another uid needs a privilege the untrusted Agent Daemon must not hold, and the partition already gives the separation.

5. **The operator's tool workspace is chosen from a closed set.** The global configuration offers the set; the operator's own Maknae configuration picks one.
   - `current`: the folder the session started in. It is refused when that folder is the operator's home or any folder above it, so the home cannot come back through `current`.
   - `path`: one named folder, for example `/opt/Development`. The operator must have OS access and Maknae file-policy access to it.
   - `home` is not an option: a home holds secrets nobody thought to list.
   - **Protected folders** are the `sensitive.yaml` lists (the host's and the person's) and a fixed set of system folders (`/etc`, `/usr`, `/var/lib/maknae` and similar). The rule works both ways. A workspace that is, or sits inside, a protected folder is refused. A protected folder inside the workspace is masked: an empty read-only mount on Podman, an `emptyDir` on Kubernetes. Without the mask, a mounted workspace would hand the tool's code a path the `sensitive` operand denies to `fs.read`.

6. **The launch shape is an obligation.** `maknaed` compiles `tools.yaml`. A Permit carries an obligation naming the decided tool entry and a digest of its compiled shape, with the per-call values: subcommand and arguments, workspace, task, and the per-invocation proxy identity. The front end renders the shape for its backend.
   - **Launch parity** (#420 decision 10): a test proves that the rendered Podman invocation and the rendered Kubernetes manifest both match the decided shape (image digest, mounts, uid, network, credential, limits).
   - **What parity proves.** It proves the renderer is correct, not that a given launch was faithful. Toward a compromised front end the launch shape is enforced only by the tiers beneath it: on hosts, the uid network rule, and later SELinux and the RuntimeClass; on Kubernetes, an admission policy that checks the pod against the kernel-generated template. On Podman nothing besides the front end checks the shape's digest. That is part of this ADR's residual.

7. **`/etc/maknae/tools.yaml` is Maknae-native and backend-neutral.**
   - Entries speak in intents: the image and its verification, `isolation: container | vm` (a minimum; the backend chooses a runtime that meets it), the network intent, volume roles, resources, commands (an allowlist of subcommands, argument denials, a timeout and an output cap), the lifetime, `executes_workspace` (decision 8), and what goes back to the model (decision 14).
   - No host paths, no runtime names, no Kubernetes or Podman field names. Volume sources are bound once per site and per backend, outside the tool entries.
   - **Precedence.** `tools.yaml` is the ceiling. Policy grants within it in the existing grammar (`Tool(cargo test *)` beside `Read(~/tasks/**)`), per user, role or agent, and both compile into the kernel graph. The composition's deny-overrides with the mandatory operands applies as usual. A policy grant for a tool that `tools.yaml` lacks or disables loads and grants nothing, and `maknaed` warns at load; refusing to load would make removing a tool break every policy that names it, and deny-by-default already keeps it safe.
   - **Backends.** Rootless Podman on a host. Agent Sandbox on Kubernetes, pinned to its `v1beta1` API (`agents.x-k8s.io`, `extensions.agents.x-k8s.io`; read 2026-11-18 at release v1.0.11, per the project's repository): the renderer emits a `SandboxTemplate` whose `runtimeClassName` is the Maknae RuntimeClass or a class the site chooses. CI renders every shipped entry for both backends and validates the Kubernetes output against the pinned schema, so a field that cannot be expressed on Kubernetes fails the day it is added.
   - **No exec into running sandboxes.** One container (one pod) per invocation; warm pools are a site optimization. This keeps `design/references/2026-11-15-agent-sandbox-assessment.md` §5.1(3): no router and no in-sandbox daemon.

   An example, with the classes of decision 13:

   ```yaml
   schema_version: 1
   credential_classes:
     github-task:
       kind: github-app-installation   # minted per task, narrowed by GitHub
       delivery: env:GH_TOKEN
     vault-invocation:
       kind: vault-child-token         # minted per invocation from the subject's own token
       policies: [kv-read-infra]
       delivery: env:VAULT_TOKEN
   tools:
     rust-fetch:
       enabled: true
       image: { ref: ghcr.io/<org>/maknae-rust-build@sha256:…, verify: { signature: required, sbom: required } }
       isolation: container
       executes_workspace: false
       network: { via: maknae-proxy, sites: [github.com, api.github.com, index.crates.io, static.crates.io] }
       workspace: rw
       volumes: { shared_tools: { access: ro }, cargo_registry: { access: rw, scope: uid } }
       credential: github-task
       output_to_model: redacted
       resources: { cpus: 2, memory: 2Gi }
       commands:
         gh:    { subcommands: ["pr view *", "pr diff *", "pr checkout *"], timeout: 5m, output: 4MiB }
         git:   { subcommands: ["fetch *", "checkout *"], deny_args: ["-c*", "--config*"], timeout: 5m, output: 4MiB }
         cargo: { subcommands: ["fetch --locked*"], timeout: 10m, output: 4MiB }
     rust-build:
       enabled: true
       image: { ref: ghcr.io/<org>/maknae-rust-build@sha256:…, verify: { signature: required, sbom: required } }
       isolation: container
       executes_workspace: true
       network: none
       workspace: rw
       volumes: { shared_tools: { access: ro }, cargo_registry: { access: ro, scope: uid }, cargo_target: { access: rw, scope: uid } }
       credential: none
       output_to_model: redacted
       resources: { cpus: 4, memory: 8Gi }
       commands:
         cargo: { subcommands: ["build *", "check *", "clippy *", "test *", "fmt --check*"], deny_args: ["--config*", "-Z*", "+*"], timeout: 30m, output: 16MiB }
       lifetime: { max: 30m }
     vault:
       enabled: true
       image: { ref: <registry>/vault-cli@sha256:…, verify: { signature: required } }
       isolation: container
       executes_workspace: false
       network: { via: maknae-proxy, sites: [vault.example.internal] }
       workspace: rw
       credential: vault-invocation
       output_to_model: status_only
       commands:
         vault: { subcommands: ["kv get *", "read *"], timeout: 2m, output: 1MiB }
   ```

8. **Maknae bounds what workspace code can do; it does not judge whether that code is trustworthy.** Maknae cannot control the code an operator brings in or is tasked with. Its job is that everything inside Maknae is bounded and policy-decided. Outside Maknae, the operating system and the use of the same code are not Maknae's to govern.
   - An entry declares `executes_workspace: true` when its tool runs code from the workspace: cargo's `build.rs`, procedural macros and tests; Terraform's providers and `data "external"`; Packer's provisioners.
   - **Validator rule:** an entry with `executes_workspace: true` that holds a credential and has network must name its sites explicitly, with no wildcard. If the workspace's code steals the credential, the channel it can use is at most that credential's own provider, through connections each decided, on the trail.
   - **Where a tool can separate its steps, the entries do.** `rust-fetch` above has network and a credential and runs no workspace code; `rust-build` runs the workspace's code with no network and no credential, and with the registry cache read-only, so build-time code cannot tamper with the sources the next build trusts. Tools that cannot separate (`terraform plan`, `packer build`) hold a narrowed, short-lived credential and named sites in one entry.
   - Two alternatives were rejected: a `runs_untrusted_code` flag forbidding network and credentials outright (it cannot express Terraform or Packer), and letting the session decide whether workspace code is trusted (Maknae cannot know whose code is trustworthy).

9. **A tool reaches the network only through `maknae-proxy`.** Tools never get a direct route. `maknae-proxy` (`design/egress-and-tool-execution.md` §6) asks `maknaed` about every `CONNECT` ([ADR-0035](ADR-0035-policy-enforcement-points-placement-and-trust-tiers.md) decision 5) and chains to the site's upstream proxy where one is required.
   - **On Podman:** the tool container joins an internal Podman network. The front end runs a relay inside Podman's rootless network namespace, listening on that network's gateway address and forwarding to `maknae-proxy` through Podman's host address. Tools use `HTTPS_PROXY=http://<gateway>:<port>`. The relay is part of the front end (Rust, the subject's uid) and adds no trust: the decision is the proxy's, per connection. A long-lived proxy container per user was considered and rejected: it is a second component per user, and the relay needs none.
   - **On Kubernetes:** a NetworkPolicy allowing egress only to the `maknae-proxy` Service. Under the Maknae RuntimeClass the route is a virtual socket.

10. **Two fences, two threats.**
    - The internal network fences the tool's code, for both front ends.
    - The host network rule keyed on uid (`design/egress-and-tool-execution.md` §7) fences a compromised `maknae-agentd`: the agent's uid can reach only `maknae-proxy`. It applies to enrolled agent accounts only, because installing Maknae changes nobody's own traffic.
    - The operator gets no uid rule by default. The operator can already reach the network from their own terminal, and the internal network fences the tool's code.

11. **Proxy identity.** The per-invocation proxy identity (`design/egress-and-tool-execution.md` §6.1, carried in the proxy URL) is the link from a `CONNECT` to the decided invocation: it names the invocation, its task and its subject for `maknaed`. Through the relay, the proxy sees a host-side socket owned by the subject's uid, so the check that the peer socket's uid matches the run-as uid plausibly holds there too. That is a requirement the implementation must demonstrate; if it does not hold, the identity alone links the connection and the gap is named. For each decision, `maknae-proxy` sends `maknaed` the invocation identity, the target host and the port.

12. **Caches are separated by uid.** A persistent cache is allowed only when one uid's cache is never another's: one registry cache and one build-output cache per uid. Without persistent caches every invocation is a cold build; with a cache shared across uids, one user's tool could plant content another user's build trusts. The registry cache is mounted read-write only in entries that do not execute workspace code.

13. **Credentials are per tool, and never one-size-fits-all.** A tool entry's `credential` is `none` or the name of a **credential class** defined once per site. A class declares:
    - **delivery:** the plug-in point the tool already supports (a token environment variable, git's credential helper, cargo's credential provider, `.netrc`, or a file);
    - **source:** minted per task or per invocation, or stored;
    - **narrowing:** whether the provider enforces the task's scope, or only Maknae does; the trail records which;
    - **lifetime:** whether it expires on its own or must be revoked when the task ends, with a failed revocation recorded as an outcome;
    - **minting authority:** where the key that mints it lives.

    A front end holds a credential only to mint it and deliver it to the tool container (decision 14 keeps it from the model). A credential goes into an entry only under decision 8's validator rule. The first classes:

    | Class | Source | Narrowed by | Lifetime | Where it fits |
    |---|---|---|---|---|
    | GitHub App installation token | minted per task | GitHub: the task's repositories and permissions | expires within an hour | the default for GitHub at every tier |
    | Machine-user bot account with a personal access token | stored | Maknae only | until rotated | a supported fallback |
    | GitLab project access token | minted per task | GitLab: the project | revoked at task end; GitLab's expiry is set by the day | GitLab Self-Managed and Dedicated at any tier, GitLab.com at Premium or Ultimate (per GitLab's documentation, read 2026-11-18) |
    | GitLab service account or bot token | stored | Maknae only | until rotated | GitLab.com Free |
    | Vault child token | minted per invocation from the subject's own Vault token | Vault: a child's policies are a subset of its parent's, so minting fails, and the call is denied, when the subject lacks the policy | the invocation's timeout; revoked when the outcome is recorded | `vault`, and the credential `terraform` and `packer` use to fetch others |
    | Vault dynamic secret | leased per task from a secrets engine | Vault | the lease; revoked at task end | cloud and database credentials |

    Where each minting key lives, and the per-forge detail, belong to [#168](https://github.com/darkhonor/maknae/issues/168). This decision supersedes #168's scope item 3, under which a tool container held no token and the Egress Daemon added GitHub's `Authorization` header: that would have required the Egress Daemon to terminate TLS for tool traffic, which decision 9's proxy, deciding each tunnel, does not do.

14. **Secrets reach tools, never the model.**
    - A credential reaches a container only through its class's delivery, and is never placed in arguments the model writes.
    - What the model gets back is set per entry: `full`, `redacted` or `status_only`. **The default is `redacted`.** The front end strips every credential value it delivered for the invocation (the minted token, the child token, a lease's secret values) from stdout and stderr before the output is released, and replaces each with a marker saying a Maknae-managed credential was redacted. The model therefore knows a credential was provided and used, and does not keep asking whether the user supplied one.
    - `status_only` is required for entries whose purpose is to reveal secrets (`vault kv get`, `vault read`, `terraform output -raw`): the model learns whether the call succeeded. A value the tool writes into the workspace is then governed by the kernel's file operands (`sensitive.yaml`, the ceiling) if the model later asks to read it.
    - The release of tool output to the model is a release the kernel decides ([ADR-0023](ADR-0023-runtime-loop-role-and-placement.md)), so the mandatory operands apply to it as well.

15. **No Maknae socket in a tool container,** on any backend: not the kernel's client socket or Agent Daemon socket, not the Egress Daemon's. The container's own namespaces keep the tool's code from the kernel only if the sockets never enter them.

16. **The tool-image contract.** An image is acceptable when it runs as non-root with a read-only root filesystem; honors `HTTPS_PROXY`; takes credentials through a standard plug-in point; is published by digest, signed, with an SBOM (#420 decision 12); and needs no shell from Maknae and no in-image agent. The image source stays configurable per entry: a home lab uses Maknae's reference image, an enterprise mirrors or rebuilds into its own registry.

17. **The reference build image is `maknae-rust-build`,** in its own public repository, built and signed on hosted CI runners and kept current by automated dependency updates. It is based on Rocky Linux 10 (UBI 10 is the proven fallback; Wolfi fails as measured above). It carries the build tools (gcc 14, cmake, Go, perl, git) and **no Rust toolchain**: rustup and the toolchain pinned by `rust-toolchain.toml` come from the shared tools volume, read-only, so the image never decides the Rust version. Its name carries no third party's marks. The tested sample set starts with `gh`, `git` and `cargo`, then `vault`, `terraform` and `packer`. A tool or language joins the known-acceptable list only after it is measured in the reference image, with the date and result recorded.

18. **Trusted host infrastructure, named.** The tool fence relies on components Maknae does not author: Podman (Go), crun and pasta (C), netavark and aardvark-dns (Rust); on Kubernetes, the cluster, its network plugin, and Kata (whose `runtime-rs` and `virtiofsd` are Rust). [ADR-0002](ADR-0002-kernel-is-rust.md)'s rule covers Maknae-authored code. These are trusted host infrastructure, in the same class as the Linux kernel, systemd and SELinux. The RPM installs fapolicyd trust and SELinux policy for them where the host needs it.

19. **Host prerequisites.** Rootless Podman needs user namespaces; a STIG'd host that sets `user.max_user_namespaces=0` needs its security officer's exemption. That setting stays the site's decision, and a preflight reports it. The RPM ships the fapolicyd trust and the SELinux policy.

20. **macOS is a supported platform, and its tool execution is a staged gap, not a reduced profile.** Tool execution, the uid network rule and the relay are Linux-first for Rabbithole. macOS tool execution is tracked in [#478](https://github.com/darkhonor/maknae/issues/478).

21. **The model gets one new tool that requests a tool invocation.** It is an additive verb; its name stays open (`design/egress-and-tool-execution.md` §10 item 3) and is settled with [#479](https://github.com/darkhonor/maknae/issues/479). It joins [ADR-0023](ADR-0023-runtime-loop-role-and-placement.md) decision 6's list of tools when #479 lands. Not built.

## Consequences

- **Residuals.**
  - A compromised `maknae-agentd` can run commands as the agent's uid without asking the kernel. It is fenced by the uid network rule now, and by SELinux domain confinement and the RuntimeClass later.
  - A compromised `maknae` front end is the operator's own uid, which can already act from a terminal.
  - On Podman nothing besides the front end checks the launch shape's digest (decision 6).
  - On Debian and Ubuntu the kernel's view of the peer is path-based ([ADR-0035](ADR-0035-policy-enforcement-points-placement-and-trust-tiers.md) decision 4).
- **#420 decisions settled:** 3 (the tool model) by decisions 1, 2 and 7; 4 (workspace uids) by decision 4; 10 (launch parity) by decision 6; 12 (image provenance) by decisions 16 and 17.
- **#477 is satisfied** by this ADR. **#476 is retired as written:** there are no workspace uids; the workspace is the tasker's partition.
- **Owed, none built:** the additive wire field and the kernel's forward class for obligations ([ADR-0035](ADR-0035-policy-enforcement-points-placement-and-trust-tiers.md) decision 3); `maknae-proxy`; the relay; both renderers and the parity test; the credential classes; output redaction; the reference image repository; the model-facing tool (decision 21).
- **Longer-term:** the network impact of terminal tool calls, where the route is a default rather than a fence, is studied under [#175](https://github.com/darkhonor/maknae/issues/175).
- **Amended in place:** [ADR-0023](ADR-0023-runtime-loop-role-and-placement.md) decisions 2, 4 and 6; [ADR-0024](ADR-0024-tenancy-model-and-agent-identity.md) decision 6 and its workspace residual. `design/egress-and-tool-execution.md`, the README and the diagrams are brought to the current state.
- `design/references/2026-11-15-agent-sandbox-assessment.md` keeps its wording about #477's tier option, under the history rule for references.

## References

- [ADR-0035](ADR-0035-policy-enforcement-points-placement-and-trust-tiers.md) (PEP placement); [ADR-0023](ADR-0023-runtime-loop-role-and-placement.md) and [ADR-0024](ADR-0024-tenancy-model-and-agent-identity.md) (amended); [ADR-0008](ADR-0008-authorization-composition-contract.md) (the partition operand); [ADR-0033](ADR-0033-agent-identity-admission-and-tasks.md) (agent tasks); [ADR-0034](ADR-0034-the-models-file-boundary.md) (`sensitive.yaml`); [ADR-0002](ADR-0002-kernel-is-rust.md); [ADR-0006](ADR-0006-client-authentication-model.md)
- `design/egress-and-tool-execution.md` (`maknae-proxy`, credential adapters, enforcement by tier); `design/references/2026-11-15-agent-sandbox-assessment.md`
- [#420](https://github.com/darkhonor/maknae/issues/420), [#477](https://github.com/darkhonor/maknae/issues/477), [#476](https://github.com/darkhonor/maknae/issues/476), [#168](https://github.com/darkhonor/maknae/issues/168), [#147](https://github.com/darkhonor/maknae/issues/147), [#175](https://github.com/darkhonor/maknae/issues/175), [#478](https://github.com/darkhonor/maknae/issues/478), [#479](https://github.com/darkhonor/maknae/issues/479)
- Provenance only: Kubernetes Agent Sandbox (`kubernetes-sigs/agent-sandbox`, v1beta1 at v1.0.11, read 2026-11-18); GitLab's documentation on project access tokens, service accounts and fine-grained tokens (read 2026-11-18); Chainguard's free image catalogue and the Wolfi distribution (read 2026-11-18).
