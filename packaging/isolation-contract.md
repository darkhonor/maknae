# Maknae Isolation Contract

This file is the **normative** isolation contract. Its source is §4 of the topology design
spec (`~/claude-memory/maknae/specs/2026-08-03-maknae-rust-workspace-topology-design.md`).
Two tables follow: the **property × profile** table (which `ci/gates/isolation-contract-lint.sh`
checks — every non-`deferred` cell must carry a `✓<check>` token) and the **crate × binary
matrix** (the human-readable statement of the P1/P2 capability-separation property).

Profiles not yet enabled (K8s) carry `deferred` cells and are exempt from the lint until enabled.

## Property × profile

| Property | Host-native Linux (MVP reference) | Host-native macOS (dev; reduced) | Compose/Podman | K8s |
|---|---|---|---|---|
| Trust-plane process isolation | `_maknae`; systemd `ProtectSystem=strict`/`NoNewPrivileges`/cap-drop/seccomp ✓`systemd-analyze security` threshold in smoke | `_maknae` daemon; launchd (no seccomp — delta) ✓plist lint + perms smoke | non-root, RO rootfs ✓compose lint (`user:`,`read_only:`) | `deferred` |
| Channel auth (session) | mTLS over UDS + peer-creds ✓§7(3) negative suite | same ✓same | mTLS internal net ✓same | `deferred` |
| Plane identity issuance | each plane → own AppRole+policy → own `pki/sign` cert; keypair local, memory-only (§4) ✓per-plane Vault-policy scope test (a plane's SecretID signs only its own role) + memory-only source-grep (Microkosmos) | same ✓same | same ✓same | `deferred` |
| Egress: platform flows | enforcing = **credential custody** (model/API keys + MCP OAuth tokens exist only in `maknaed`) + kernel-side authority-map allowlist ✓demo 4 **+ custody assertion: no egress credential readable by operator uid (install + CI)**; nftables defense-in-depth ✓ruleset assertion (best-effort — see honest statement) | kernel-side allowlist + custody ✓custody assertion | internal nets; proxy-only ✓compose network lint | `deferred` |
| Lake corpus (read-only curated mount) | consumer-only `ro` mount (§2.9); CLI reads directly; **boot classification-match gate** (lake.yaml ceiling ≤ Maknae authorization) else fail closed ✓demo 1 boot-gate paired assertion (dominated lake mounts; over-ceiling lake refuses) + `ro` mount-perms check | same ✓same | read-only volume ✓mount-flag lint | `deferred` |
| Persona/workspace | operator-uid files loaded by CLI; presentation/config content, session-floor-classified (§5); untrusted-plane residual (container-arch §1.5 residual clause) ✓payload-floor vector §7(1) | same ✓same | `deferred` | `deferred` |
| State-store access | localhost socket; service role (no DDL) vs DDL-owner (offline only, §2.10); RLS ✓demo 2 + role-privilege audit query | same ✓same | network-scoped ✓same | `deferred` |
| Tier-0 authority config | kernel-owned `0600`; signed-git; instance ceiling + operator record + authority map ✓perms check + signature verify at load | same ✓same | kernel-only volume ✓lint | `deferred` |
| Trust-plane credentials | `_maknae`-owned `0600` ✓perms + negative read as operator uid | same ✓same | kernel-only secret ✓lint | `deferred` |
| Runtime-plane credentials (CLI SecretID + cert/key) | operator-uid; SecretID file `0o400`; CLI-generated key, memory-only cert; CLI's Vault policy signs **only** `plane/cli` ✓perms + per-plane policy-scope test (CLI SecretID cannot sign `plane/kernel`) | same ✓same | per-container identity ✓same | `deferred` |
| Audit protection | kernel-owned `0700`; `chattr +a` **on the audit directory; the daemon appends to a single open fd it holds across the session** (rotation owed, ADR-0007) ✓`lsattr` assertion | `chflags sappnd` where securelevel permits ✓`ls -lO` | kernel-only volume ✓volume lint | `deferred` |
| Config protection | kernel-owned `0600` (no append attr — upgrades edit) ✓perms check | same ✓same | kernel-only volume ✓lint | `deferred` |
| Tokki packaging (MAC/trust install lifecycle) | deb/rpm (checksummed; signing #96) install the hardened unit + MAC policy + shipped DAC default. **SELinux** enforce-clean PROVEN (Rocky 10) ✓`getenforce` + scoped denial-clean run + fapolicyd-clean run. **AppArmor** profiles load ✓`aa-status`; serve-time enforce-clean pending #94 | `deferred (#76)` | `deferred` | `deferred (#81)` |

## Crate × binary matrix

The P1/P2 gates (`ci/gates/`) enforce this. "forbidden" = the gates fail if the edge ever appears.
"via X" = reached transitively through crate X. (The lint above skips this table by column count.)

| Crate | maknaed | maknae | maknae-spifc |
|---|---|---|---|
| maknae-kernel (priv) | linked | forbidden | — |
| maknae-subject-ctx-mint (priv) | via kernel | forbidden | — |
| maknae-audit-append (priv) | via kernel | forbidden | — |
| maknae-spif-compile (priv) | — | forbidden | linked |
| maknae-proto | via kernel | linked | — |
| maknae-spif | via kernel | — | — |
| maknae-subject-ctx | via kernel | — | — |
| maknae-audit | via kernel | — | — |
| maknae-vault | linked | linked | — |
| maknae-config | via kernel | linked | — |
| maknae-llm | linked | — | — |
| maknae-mcp | linked | linked | — |
