# Secrets Custody by Deployment Tier — Design Note

| | |
|---|---|
| **Status** | **Design note, not an ADR.** Captures a discussion the maintainer opened on 2026-09-08 after the Jarvis-class field survey. Records the properties, the alternatives graded against them, and a candidate shape. **No decision is taken here**; the maintainer has said the question is not ready for an ADR. When it is, this note is the input, and the ADR supersedes it. |
| **Date** | 2026-09-08 |
| **Prompted by** | The [Jarvis-class field survey](references/2026-09-08-jarvis-class-survey.md) §3.4 (no surveyed project uses a secrets server; every one ends with the value in the agent's process or its tool's environment) and HashiCorp's validated pattern *Secure AI agent authentication using HashiCorp Vault dynamic secrets* (Lynch and Panchal; Enterprise tier; https://developer.hashicorp.com/validated-patterns/vault/ai-agent-identity-with-hashicorp-vault). |
| **Question** | Maknae uses an external HashiCorp Vault by design. Vault is uncommon outside enterprises. What are the acceptable alternatives for the HomeLab and small-business tiers, and what exactly would be given up? |
| **Authority** | ADR-0005 (enforcement locus), ADR-0006 (clients never reach Vault; the daemon is the sole door), ADR-0007 (key custody: memory-only, fail-closed, per-plane), ADR-0022 (the three deployment tiers by name), ADR-0023 (the egress process under its own account and Vault principal), #168 (`admin.credential.broker`), #240, #243. This note contradicts none of them; it asks whether the *store* gets the substitution axis the *bootstrap* already has. |

## 1. What already exists, so the discussion starts from the code

Maknae is not "Vault for everything" today. Two layers are distinct:

- **The bootstrap credential**, the per-plane SecretID that lets a plane reach Vault, already has a substitution axis in [`crates/maknae-vault/src/secret_source.rs`](../crates/maknae-vault/src/secret_source.rs): systemd `LoadCredentialEncrypted` delivered through `$CREDENTIALS_DIRECTORY` on Linux (the hardware-root-of-trust path), a Secure-Enclave-sealed blob on macOS, the Keychain for the CLI, and an operator-opted-in plaintext path recorded in code as *"the weakest posture, last resort, never a silent default."* Resolution is pure and mutation-hardened; the ordering is fail-closed and testable.
- **The store** is Vault only: plane certificates from the PKI mounts in [`deploy/vault-pki/`](../deploy/vault-pki/) and, since #243, the provider key from the `maknae-kv` KV v2 mount, referenced by `provider.key_vault_path` and never present in configuration.

ADR-0022 already names three deployment tiers, HomeLab, small business, enclave, for the classification system. The same three are the natural tiers here, and reusing the names avoids a second vocabulary.

## 2. The properties, separated from the product

Reading ADR-0005, ADR-0006, ADR-0007 and #168 together, Maknae requires five things of a secrets layer:

1. **The agent never holds the value.** The egress process does, memory-only, fail-closed (ADR-0023).
2. **Access is by principal.** The egress account may read the provider key; the loop's account, the CLI, and every other process on the host may not.
3. **Reads are audited somewhere Maknae does not control.**
4. **Rotation and revocation without redeploying.**
5. **Dynamic, leased credentials with attribution** where the destination supports them (#168's brokering against databases, cloud APIs, SSH targets).

Vault provides all five. **Properties 1 and 2 are the model; 3 to 5 are the enterprise posture.** A tier that gives up 3 to 5 is a weaker posture, stated as such. A tier that gives up 1 or 2 is not Maknae.

## 3. Alternatives, graded against the five

| Store | 1 agent never holds | 2 by principal | 3 external audit | 4 rotation | 5 dynamic | Notes |
|---|---|---|---|---|---|---|
| **systemd credentials** (`LoadCredentialEncrypted`, TPM-bound, per-unit `$CREDENTIALS_DIRECTORY`) | yes | yes, by service unit | no | re-encrypt and restart | no | Linux only. Delivered as a file only that service can read, never in the environment: the stub-file injection NanoClaw bought a commercial gateway to obtain. Maknae already reads it. |
| **macOS Keychain + Secure Enclave** | yes | partial: per-account keychain and per-binary ACL, not a service account | no | manual | no | macOS is a production target, so this must be first-class. The `_maknae-egress` account (#227) gets its own keychain. |
| **OpenBao** (Linux Foundation fork of Vault's last MPL release; MPL-2.0; v2.6.2, 2026-08-18) | yes | yes, by auth method and policy | yes | yes | yes | Same API, auth methods, PKI and KV engines as Vault; single binary with file storage. Nothing in `deploy/vault-pki` or `maknae-vault` depends on an Enterprise-only endpoint (to be confirmed by test, not by reading). |
| **Vault** (HashiCorp; Business Source License since 2023; the validated pattern's tier is Enterprise or HCP) | yes | yes | yes | yes | yes | Functionally the same as OpenBao at the open tier. The license is not OSI open source, which matters for what the project recommends and for what a government adopter may deploy. |
| **Bitwarden / Vaultwarden, 1Password Connect** | no | **no**: they authenticate a user, not a service, and have no principal-reads-path policy | partial | yes | no | The HomeLab and SMB favourites, and what Hermes and ZeroClaw integrate. Fine as where the operator keeps master material; wrong as the store the egress process reads. |
| **sops / age files** with the key in TPM or Keychain | partial | **no**: reduces to file permissions | no | manual | no | systemd-creds without the per-service delivery. Not better than what exists. |
| **Cloud KMS / secrets managers** | yes | yes | yes | yes | yes | Not local; the enclave tier's other option. Out of scope for the two tiers asked about. |
| **Plaintext with a permission bit** | no | no | no | no | no | Where every surveyed project ended up. Already labeled in Maknae's code as never a silent default; it should not be a tier. |

## 4. A candidate shape, for discussion only

One contract, three tiers, the store declared by the operator in root-owned configuration the way the classification system is declared, and a mismatch between the declaration and what the host can actually provide being a boot refusal.

| Tier (ADR-0022 names) | Store | Bootstrap | Given up, stated plainly |
|---|---|---|---|
| **HomeLab**, single host | systemd credentials on Linux; Keychain with Secure Enclave on macOS | the same mechanism; no SecretID exists because there is no server to reach | external audit, dynamic secrets, rotation without touching the host |
| **Small business**, a few hosts | OpenBao, single node, file storage, PKI and KV exactly as today | systemd credentials or Keychain holding the OpenBao credential | nothing an SMB needs; Enterprise features |
| **Enclave** | Vault Enterprise or HCP; the validated pattern: JWT auth against kernel-issued tokens, dynamic secrets, correlation into Vault's audit | as today, plus the JWT path | nothing |

The contract itself is small: *read a named secret for a named principal, fail closed, memory only, and report a source kind into the boot evidence record* so the acceptance run (#242) can quote which tier a host is actually on. `provider.key_vault_path` becomes a reference resolved by the tier's store, which is the `SecretRef` shape OpenClaw uses (a typed reference with a named source, never a value); the disclosure gate already suppresses it.

## 5. What the HashiCorp pattern adds at the enclave tier

The pattern's contribution is identity chaining, not custody mechanics. Mapped onto Maknae:

- **Its On-Behalf-Of token is Maknae's subject context** (ADR-0007, `maknae-subject-ctx-mint`), with a stronger issuer: the kernel mints it, the agent never performs the exchange. ADR-0005 forbids the agent doing what the pattern's agent does, and that is the better design.
- **JWT auth instead of AppRole for the egress principal.** Vault (and OpenBao) can validate a kernel-signed token bound to `azp = maknae-egress` carrying the subject id and session id, and map it to policy through external identity groups. Policy becomes per subject and per session with no standing role credential on disk. JWT auth and identity groups are open-tier features, not Enterprise. This would amend ADR-0007's custody note and belongs to the ADR when it is written.
- **One header.** `X-Correlation-ID` on every Vault request from the egress process, carrying Maknae's session id and the audit record id of the authorizing decision, so Vault's audit log and Maknae's trail join on one key and a reviewer can prove which decision caused which read from a log Maknae does not control.
- **Dynamic secrets where they exist.** There is no Vault secrets engine for OpenAI or Anthropic; the provider key in #243 is static by nature, and attribution there comes from the audit join, not the credential. For what #168 brokers later, dynamic per-request credentials with a lease are the default; the pattern's own note is the reason: static roles with rotation *"may blur attribution."*
- **The named threat.** The pattern is built on the confused-deputy problem; its reference repository is `confused-deputy-aws`. #168 records that it lacks a citation for the term. This pattern is not a standard, but it is vendor-validated prior art naming the same threat with the same shape.

## 6. Two cautions to carry into the ADR

- **The HomeLab tier must not become "plaintext with a permission bit."** That is where every project in the survey ended up. The existing opt-in plaintext path stays what the code calls it, and the boot record refuses to describe a plaintext-backed host as anything else.
- **The tier is declared, never discovered.** Runtime discovery of "what secrets backend is available" is the fail-open pattern the survey documented in four projects (a sandbox that auto-detects and degrades to a no-op is the same shape). The operator declares; the host either provides it or boot refuses.

## 7. Open questions the ADR would have to answer

- Whether the store contract lives in `maknae-vault` (renamed, since one implementation would not be Vault) or in a new crate behind the existing `maknae-io`-style rule that I/O has one home.
- Whether OpenBao is a tested target in CI (a container in the Linux lane) or a documented one. The license finding argues for tested.
- What the macOS tier's principal boundary really is when the store is a keychain and not a service account, and whether the `_maknae-egress` keychain ACL is enough for property 2 or whether it needs the Secure Enclave key to be non-exportable per binary.
- Whether the enclave tier's JWT path replaces AppRole entirely or sits beside it for the CLI, given ADR-0006's direction that clients never reach Vault at all.
- How the boot evidence names the tier and the source kind, and whether `admin.status` (#214) reports it.

## 8. References

- Jarvis-class field survey §3.4, §3.5 and the NanoClaw profile: [`references/2026-09-08-jarvis-class-survey.md`](references/2026-09-08-jarvis-class-survey.md)
- HashiCorp validated pattern: https://developer.hashicorp.com/validated-patterns/vault/ai-agent-identity-with-hashicorp-vault ; reference implementation https://github.com/panchal-ravi/confused-deputy-aws
- OpenBao: https://github.com/openbao/openbao (MPL-2.0; v2.6.2 on 2026-08-18) ; Vault: https://github.com/hashicorp/vault (Business Source License 1.1 since 2023-08)
- systemd credentials: https://systemd.io/CREDENTIALS/
- Maknae: [ADR-0005](adr/ADR-0005-enforcement-locus-tcb-boundary.md) · [ADR-0006](adr/ADR-0006-client-authentication-model.md) · [ADR-0007](adr/ADR-0007-key-and-signature-model.md) · [ADR-0022](adr/ADR-0022-classification-policy-as-data.md) · [ADR-0023](adr/ADR-0023-runtime-loop-role-and-placement.md) · `crates/maknae-vault/src/secret_source.rs` · #168 · #227 · #240 · #242 · #243
