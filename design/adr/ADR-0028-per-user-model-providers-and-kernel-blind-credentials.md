# ADR-0028: Per-user model providers with kernel-blind credentials

- **Status:** Accepted (maintainer-ruled 2026-09-30 and 2026-10-01, issue #153). The decisions below are the maintainer's rulings. Mechanism details not stated here — file names beyond those given, the sealed-blob layout, time-to-live values — belong to the implementing pull requests.
- **Date:** 2026-10-01
- **Deciders:** Alex Ackerman (maintainer)
- **Amends:** [ADR-0023](ADR-0023-runtime-loop-role-and-placement.md) decisions 2 and 3; [ADR-0006](ADR-0006-client-authentication-model.md) decisions 1 and 2 and two of its Consequences, for local users only; [ADR-0005](ADR-0005-enforcement-locus-tcb-boundary.md) decision 4's custody bullet and `maknae-vault` crate contract; [ADR-0018](ADR-0018-local-plane-authorization-deployment-model.md) decision 4 (the CLI's standing SecretID) and decision 6 (the Egress Daemon's keychain item). ADR-0023 is still Proposed; its ratification covers it as amended here.

## Terms

- **Egress Daemon:** the `maknae-egress` process, running as `_maknae-egress`, which makes the outbound model call (ADR-0023 decision 3).
- **Agent Daemon:** a planned service running an agent loop under its own local account on behalf of the users who task it (milestone Rabbithole, epic #420). It is not built, and no ADR yet ratifies it.

## Context

Maknae registers exactly one model provider, in the root-owned `provider` block (`crates/maknae-config/src/provider.rs`; ADR-0023 decision 3). The client never names a destination: `maknaed` inserts `provider:<name>` (`crates/maknae-kernel/src/handler.rs`). The Egress Daemon reads the key from Vault with its own AppRole, under a policy covering every key beneath one prefix (`deploy/vault-pki/main.tf`, `bins/maknae-egress/src/keys_vault.rs`), and every enrolled human logs in to Vault through one shared `maknae` AppRole (`deploy/vault-pki/main.tf`).

That shape serves one person. It fails every deployment with more than one user — a HomeLab household, a small business, an enterprise:

1. **Everyone shares one model and one key.**
2. **The Egress Daemon can read every key.** A process acting for many users holds a grant over all of their credentials, the confused-deputy shape #153 §4 describes.
3. **Vault cannot tell users apart.** One shared AppRole means Vault's audit log names the role, not the person.

Two constraints already hold: `maknaed` never opens a subject's files (#365, #369, #371), and prompt content still transits `maknaed` (#417, not decided here).

## Decision

### 1. The authorized set is root-owned configuration, and may be empty

`/etc/maknae` (or a root-owned `config.d/` member) declares **zero or more** providers. Each has a `name` (the destination id, `provider:<name>`), an `endpoint`, the **models allowed** at that endpoint, and endpoint behaviour (`reasoning_effort`, `output_tokens_field`). With zero providers every `session.prompt` is refused. `authz.yaml` `destinations:` is unchanged: the authorized set says what exists; `destinations:` says which roles may use it; `maknaed` decides both on every request. No database is introduced.

### 2. Each user chooses from the authorized set, per request

Each local user declares zero or more entries in `~/.maknae/providers.yaml`: a label, an authorized provider, a model on its list, the key's location below the user's own Vault subtree, and the model's budget. One entry is the default; `maknae agent --provider <label>` selects another. The client sends its choice with each `session.prompt` as **additive** fields; `PROTOCOL_VERSION` and `schema_version` are unchanged. `maknaed` refuses a provider outside the authorized set, a model outside its list, and a provider the subject's role is not granted. A user with no entries has no model access: the client refuses before sending, and the enforcing controls are the authorized set, the role's grant and the key's existence in the user's own Vault subtree.

### 3. Keys live only in Vault, under a path derived from the requester

A user's key is at `<kv_mount>/data/<user_prefix>/<username>/<subpath>`, field `<key_field>`. The Vault address, the user authentication method and mount (`vault.user_auth`, whose `type` is `userpass` today), `kv_mount` and `user_prefix` are root-owned. **`maknaed` derives `<username>` from the connecting peer's uid**, never from the request, and refuses to build a path for an account whose name is not one lower-case, bounded, safe path segment (Vault userpass lower-cases usernames, so a mixed-case account could never match its own policy). The user owns everything below their username — `subpath` and `key_field` — which `maknaed` checks for shape. No key is stored in a local file or an environment variable.

### 4. A user's key is read with that user's own Vault identity

- **Local humans authenticate with Vault userpass, their single Vault identity.** It replaces the shared `maknae` CLI AppRole for key access and, while the local channel still uses a client certificate, for minting it. The Vault username equals the local username; a mismatch fails closed. One templated policy confines every user to their own subtree by the userpass alias name, and sets `min_wrapping_ttl` on the key's data path, so Vault answers a read of a key only with a single-use wrapping token; the documented key-loading procedure follows Vault's measured behaviour, which may require wrapping on writes to that path as well. `maknae login` obtains a token from a terminal prompt and stores only the token, with the custody the CLI credential already has. An LDAP or OIDC mount can later supply an equivalent identity to an equivalent policy.
- **Machines use a HashiCorp-recommended machine method.** This ADR fixes only the Agent Daemon's Vault authentication method — AppRole, with a literal policy on its own account's subtree; TLS-certificate authentication is later hardening. Its standing as a subject, against [ADR-0024](ADR-0024-tenancy-model-and-agent-identity.md) decision 2 ("an agent runtime holds no identity of its own"), is decided in its own ADR.
- `maknaed` keeps its AppRole and gains no key access.

### 5. The kernel never holds a key or a Vault token

For each turn the client makes a **response-wrapped** read of its key with its own token and receives a single-use, short-lived wrapping token. It **seals** that token to the Egress Daemon's P-384 public key (ephemeral ECDH, HKDF-SHA-384, AES-256-GCM), with associated data binding the conversation, provider, model, the full expected Vault path and the key field. `maknaed` carries the sealed bytes, decides on metadata only, and forwards them with the path it authorized. Two controls keep the kernel from opening them: the private key exists only in the Egress Daemon's custody, and `maknaed` does not link the crate that opens a seal (`maknae-seal`), which a CI gate will enforce. `maknaed` does link `maknae-vault`, whose lookup and unwrap calls reach a key only with a wrapping token, which `maknaed` only ever carries sealed and never sees in the clear. The Egress Daemon opens the seal, confirms with Vault that the wrapping token's `creation_path` is exactly the authorized path, unwraps it, uses the key for that one call and zeroizes it. It keeps no key cache.

The client reads the Egress Daemon's public key from its own `~/.maknae`, never through `maknaed`, so the kernel cannot substitute a key of its own. Publishing the public key to a user is an administrative step that does not rotate the key pair; rotating it republishes to every user. The mechanism is the implementing PR's.

Measured 2026-10-01 with OpenSSL 3.6.4 on Apple Silicon (`openssl speed`): P-384 ECDH 0.14 ms per operation; AES-256-GCM on a wrapping-token-sized input under 1 µs. The shipped path uses `aws-lc-rs`; its timing test lands with the implementation.

### 6. The Egress Daemon has no provider and no Vault identity of its own

It acts only on behalf of a user, within the authorized set, using what a single-use wrapping token opens. Its AppRole, SecretID and KV read policy are removed. It holds the sealing key pair: the private key in its own custody (a systemd encrypted credential on Linux; on macOS the System keychain item of ADR-0018 decision 6, whose contents change from a SecretID to this key), the public key published to each user as decision 5 describes.

## Consequences

- **A user's own processes can read that user's key** — accepted by ruling. The user's Vault identity reads the key, so any process running as the user can make a wrapped read of its own, unwrap it and call the provider without `maknaed`. That includes the untrusted loop, a modified client, and anything a model-directed write causes to run as the user (for example a git hook written under an allowed path). Such a read fails no turn. This removes the custody property ADR-0023 decision 2 and `packaging/isolation-contract.md`'s custody row asserted for the loop; the contract changes with the implementing PR. What remains: every read of a key is a wrapped read in Vault's audit log under the user's own identity, so correlating those reads with `session.prompt` records in Maknae's trail can detect a read no turn accounts for. Nothing performs that correlation yet; it is tracked as its own issue. The key is the user's own.
- **No user can read another user's key.** Vault enforces it on each user's own identity through the templated policy.
- **The Egress Daemon still sees each active user's key in plaintext, one call at a time.** A compromised Egress Daemon harvests the keys used while it is compromised. It no longer holds a standing grant over keys not in use.
- **Revocation takes effect on the next turn when the user's tokens are revoked.** Deleting a userpass user alone refuses renewal but leaves issued tokens valid until they expire.
- **Humans log in again when their token reaches its maximum lifetime,** including during a long `maknae agent` session, where the SecretID was hands-free.
- **The associated data does not bind the prompt content.** `maknaed`, a trusted component, could attach a user's sealed token to content of its choosing; binding content is left to #417's direct path.
- **The trail records the user, the provider and the model** — never the key's path, field, wrapping token or sealed bytes.
- **User enrollment issues no shared SecretID** and **gains administrative steps**: the Vault administrator creates each userpass user, and the Egress Daemon's public key is published to each user; the templated policy lives in `deploy/vault-pki`.
- **Each turn adds three Vault round trips** (wrapped read, lookup, unwrap): milliseconds against a model turn.
- **Content is not addressed.** Prompt content still transits `maknaed` (#417).
- **One Vault server serves one Maknae instance.**
- **ADR-0006 stays the target for remote clients,** and its certless local channel (decision 4, #114, #116) is unaffected. #116 no longer removes the local user's Vault identity or token; the shared `cli` AppRole is removed by this ADR's implementation instead.
- **Out of scope:** OAuth, a native Messages API client, non-text modalities, capability declaration, local-versus-remote destination classes (#153); destination governance (#147); the shipped `session.prompt` default (#67, #152).

## Security control mapping (informative; per ADR-0001)

| Property | Control | Status |
|---|---|---|
| Each user reads only their own key, enforced by Vault on the user's identity | NIST SP 800-53 rev 5 AC-3 (access enforcement), AC-6 (least privilege) | Implements, once built |
| Local humans individually identified to Vault; shared CLI AppRole removed | IA-2 (identification and authentication), IA-5 (authenticator management) | Strengthens, once built |
| Keys never at rest outside Vault; plaintext only inside the Egress Daemon for one call, then zeroized | SC-28 (protection of information at rest), SC-4 (information in shared system resources) | Implements, once built |
| The credential crosses `maknaed` only sealed to the Egress Daemon and bound to its request | SC-8 (transmission confidentiality and integrity), SC-12 (key establishment), SC-13 (cryptographic protection) | Implements, once built |
| The Egress Daemon holds no standing credential grant | AC-6 (least privilege) | Strengthens, once built |
| The trail names user, provider and model, never key material | AU-3 (content of audit records), AU-9 (protection of audit information) | Implements, once built |
| Key reads outside a turn are detectable | SI-4 (system monitoring), by correlating Vault's audit device with Maknae's trail | Enables detection; the correlation is not built (tracked issue) |

## References

- Issue [#153](https://github.com/darkhonor/maknae/issues/153); [ADR-0001](ADR-0001-adopt-architecture-decision-records.md); [ADR-0005](ADR-0005-enforcement-locus-tcb-boundary.md); [ADR-0006](ADR-0006-client-authentication-model.md); [ADR-0018](ADR-0018-local-plane-authorization-deployment-model.md); [ADR-0023](ADR-0023-runtime-loop-role-and-placement.md); [ADR-0024](ADR-0024-tenancy-model-and-agent-identity.md); [ADR-0025](ADR-0025-fips-validation-is-a-goal-not-a-constraint.md); [ADR-0026](ADR-0026-memory-hygiene-boundary.md); [per-user-provider-store](../per-user-provider-store.md).
- HashiCorp Vault v1.21 documentation: the userpass auth method (the identity alias is the lower-cased username); ACL policy templating (`identity.entity.aliases.<mount accessor>.name`) and `min_wrapping_ttl`; response wrapping (`sys/wrapping/lookup` is unauthenticated and reports `creation_path`; `sys/wrapping/unwrap` authenticates with the wrapping token; validate `creation_path` before unwrapping).
