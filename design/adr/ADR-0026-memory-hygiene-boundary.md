# ADR-0026: The memory-hygiene boundary — Maknae-owned buffers of secret-class bytes zeroize; third-party codec and transport intermediates are a named residual

- **Status:** Accepted (maintainer-ruled 2026-09-22 — Option A, Cooky burn-down row 5; written 2026-09-25)
- **Date:** 2026-09-25
- **Deciders:** Alex Ackerman (maintainer)
- **Raised by:** [#342](https://github.com/darkhonor/maknae/issues/342), from `codex exec` round 2 on #241 (PR #341)

## Context

**Amended 2026-09-26 (#365):** this paragraph and decision 1.

Secret-class bytes, for this ADR — kernel-served file content (`Bytes` on the kernel wire) and the model's write content (`SecretText` inside tool-call arguments, and the CLI's own `Bytes`), prompt and reply text (`SecretText`), and the provider key — cross two codecs and one transport Maknae does not own, and they are held by three Maknae processes: `maknaed`, `maknae-egress`, and the subject's `maknae` / `maknae agent`. #241 established the rule for the buffers Maknae owns — zeroizing from allocation, never growing — and applied it to the kernel↔deputy frame buffers in both directions (the fixed-size encoders `encode_egress_frame_request` / `encode_egress_frame_reply` in `crates/maknae-proto/src/wire.rs`, the kernel's zeroizing reply read) and to the provider request's Maknae-owned types (`SecretText` through `ChatMessage`, a zeroizing owner for the model's write bytes, the deputy's `text_of` in `crates/maknae-deputy/src/call.rs`, allocated once at the exact byte sum inside `Zeroizing`). It did not reach the provider reply inside `maknae-llm`, the client leg, or the provider key's path (decision 1). **Out of this ADR's scope, and not inventoried here:** the Vault authentication material the planes and `maknae enroll` hold. The holding types keep the AppRole SecretID and the plane PKI leaf key in `Zeroizing` (`crates/maknae-vault/src/auth.rs`, `client.rs`), and the operator token is taken and dropped as `Zeroizing` (`operator.rs::new`, from `enroll::intake_token`); plain copies exist around them — among others, `VaultToken.client_token` (a plain `String` in `auth.rs`), `intake_token`'s `read_to_string` copy, the SecretIDs' YAML hand-off between `maknae enroll` and its helper (`ProvisionJob::to_yaml`, the helper's stdin `read_to_string`, `from_yaml`), the `--insecure-plaintext-secret` `to_vec`, every copy handed to vaultrs, its `X-Vault-Token` header and rustls's `CertifiedKey`. A separate decision inventories that material; this ADR does not. Its custody is [ADR-0018](ADR-0018-local-plane-authorization-deployment-model.md)'s and [ADR-0023](ADR-0023-runtime-loop-role-and-placement.md)'s, and its in-memory hygiene is a separate decision this ADR does not pre-empt. What lies inside dependencies for the bytes in scope, verified against the tree and ciborium 0.2.2's source on 2026-09-25:

1. **CBOR decode.** Every secret-class decode is `ciborium::from_reader` (`crates/maknae-proto/src/wire.rs`): `decode_request`, called from the kernel (`crates/maknae-kernel/src/run.rs`), which carries the prompt's `SecretText`; `decode_response`, called from the client (`bins/maknae/src/cli.rs`), which carries `Payload::ReadContent(Bytes)` — served file content; and the egress frame decoders. `SecretText`'s `Deserialize` is `String::deserialize`, which serde routes to `deserialize_string`; `Bytes` calls `deserialize_byte_buf` directly. In ciborium 0.2.2 (`src/de/mod.rs`) both build an **owned** buffer for every length — `String::new()` + `push_str`, `Vec::new()` + `extend_from_slice` — pulling chunks through a 4 KiB scratch. `from_reader` puts that scratch on its own stack (`[0; 4096]`) and does not wipe it; the public `from_reader_with_buffer` takes the scratch from the caller, so which scratch is used is Maknae's choice of entry point. So: the scratch keeps the most recent chunks decoded; a value over 4096 bytes, or an indefinite-length one delivered in segments, grows its buffer and may free each earlier copy unwiped; and a decode error drops the plain buffer before `Zeroizing` wraps it.
2. **Provider request.** `maknae_llm::chat_completion` (`crates/maknae-llm/src/client.rs`) sends the transcript with reqwest's `.json(req)`: `serde_json::to_vec` into a growing `Vec`, then a plainly owned HTTP body, then hyper's and rustls's write buffers (hyper may copy again depending on vectored-write support).
3. **Provider reply.** The reply arrives through rustls plaintext buffers, hyper's read buffers and reqwest's `chunk()` `Bytes`, and is un-escaped through serde_json's scratch buffer before it reaches Maknae's own types — in the deputy, and again in `maknae agent` when it parses tool arguments (`crates/maknae-agent/src/route.rs`).
4. **The provider key.** It is fetched with `vaultrs::kv2::read` (reqwest and serde_json again) into a plain `BTreeMap<String, String>` in `crates/maknae-vault/src/kv_io.rs`, copied out into `Zeroizing`, and the map dropped unwiped; then reqwest's `bearer_auth` builds the `Authorization` value with `format!("Bearer {token}")` — a plain `String`, then a `HeaderValue` (reqwest 0.13, `src/async_impl/request.rs`); `set_sensitive` does not zeroize the header storage. The key is in the deputy's memory in plain form on the Vault fetch and on the provider request.

Closing the third-party part of 1–4 means a bounded, non-growing CBOR string and byte-string decoder in `maknae-proto` (ciborium's growth and error path are inside ciborium; its scratch is not) and a request body type whose drop zeroizes (reqwest's `Body::from(Vec)` does not). That is a platform decision, not a slice of the loop, which is why #241 stopped at the crate boundary and asked for a ruling.

## Decision

### 1. The rule, and the Maknae-owned sites that do not meet it yet

Every buffer **Maknae owns** that holds secret-class bytes — in `maknaed`, `maknae-egress`, or the subject's `maknae` / `maknae agent` — **must** be zeroizing from allocation and must not grow. A new Maknae-owned buffer on a secret-class path that is a plain `String`/`Vec`, or that reallocates, is a defect from this ADR on. The sites that predate the rule and do not meet it, verified 2026-09-25:

| site | what it holds | shape today |
|---|---|---|
| `crates/maknae-llm/src/client.rs`, the reply body | the whole provider reply (write content; served content the model quoted back) | plain `Vec<u8>`, `extend_from_slice` per chunk — grows, freed unwiped |
| `crates/maknae-llm/src/wire.rs`, the response DTOs (`RespMessage.content`, `RespToolFn.arguments`) | reply text and tool arguments | plain `String`s filled by serde_json before `to_prompt_reply` wraps them; dropped plain on an error; `#[derive(Debug)]` |
| `crates/maknae-proto/src/frame.rs`, `read_frame` | any frame body, including `ReadContent(Bytes)` on the client leg (`bins/maknae/src/cli.rs`, `decode_response`) | `std::mem::take` out of the `Zeroizing` wrapper — the caller gets a plain `Vec` |
| `crates/maknae-proto/src/wire.rs`, `encode_response_zeroizing` | responses, including served content | `Zeroizing<Vec>` over `with_capacity`; callers pre-size it (`reply_capacity`, `content_len + FRAME_ENVELOPE_MARGIN` in `run.rs`) but a mis-sized cap grows silently instead of erroring — `encode_egress_frame_request`'s doc calls it the weaker discipline |
| `crates/maknae-agent/src/drive.rs`, `text_of` | the model's reply text, bound for the subject's own terminal (may echo served content) | plain `String`, `push_str` per block — grows; the code calls the asymmetry deliberate, this ADR grants no exemption |
| `bins/maknae/src/cli.rs`, `Agent { prompt: String }` | the subject's initial prompt, from the command line | plain `String` owned by clap and `agent::run`; `Transcript::new` makes a zeroizing copy and the original is dropped unwiped |
| `crates/maknae-vault/src/kv_io.rs`, the KV read | the provider key and every other field of the secret | plain `BTreeMap<String, String>` from vaultrs, dropped unwiped after the key is copied into `Zeroizing` |
| `crates/maknae-proto/src/wire.rs`, the secret-class `ciborium::from_reader` call sites (`decode_request`, `decode_response`, the egress frame decoders; `decode_followup` carries only mutation paths, ids, indices and outcome enums) | the most recent 4 KiB chunks decoded | `from_reader`'s own stack scratch, never wiped; `from_reader_with_buffer` would take a Maknae-owned, zeroizing one |

Each is converted by the change that next touches it, or filed as its own issue after the Cooky freeze at the maintainer's word. Until then they are **known**, not disputed.

### 2. The residual — the authoritative list

| where | what stays unwiped |
|---|---|
| ciborium 0.2.2 (`decode_request`, `decode_response`, the egress frame decoders) | the growth copies of a value over 4096 bytes or of an indefinite-length value delivered in segments (each segment is appended separately), if freed; the plain owned buffer on a decode error (the scratch is decision 1's — Maknae chooses the entry point) |
| rustls on the client↔kernel plane (`crates/maknae-vault/src/stream.rs`, both directions) | the TLS record and plaintext buffers (`ChunkVecBuffer`) for every frame, direct-read content included |
| reqwest `.json()` → `serde_json::to_vec` → hyper / rustls (request) | the serialized provider request and its growth copies, the body for its lifetime, the transport's write buffers |
| rustls / hyper / reqwest `chunk()` (reply) | the transport's plaintext read buffers and each reply chunk |
| serde_json string un-escaping (deputy reply; `maknae agent` tool arguments) | the scratch behind any escaped string |
| vaultrs `kv2::read` (reqwest + serde_json) | the fetched secret, key included, in the transport and parser buffers |
| reqwest `bearer_auth` | the provider key in a plain `HeaderValue` for the request's lifetime |

A new third-party path that carries secret-class bytes is added here in the change that introduces it. **Option A** of #342: accept the boundary; no new dependency, no fork.

### 3. The threat-model sentence

A reader of a live `maknaed`, `maknae-egress` or subject-process memory — or of swap, or of a core dump where the host takes one (neither systemd unit sets `LimitCORE=0` and nothing sets `PR_SET_DUMPABLE`, so a Linux host's own core policy decides; the launchd plist does not pin a core limit, so launchd's default, soft limit 0 on a stock system, decides) — obtains recent secret-class bytes from the buffers in decisions 1 and 2: prompt and reply text, write content and the provider key, which the provider sees anyway; and served file content — on the agent path the provider sees it too, as tool results; on the direct `maknae read` path nothing outside the host ever does. The Vault authentication material named out of scope above is exposed the same way. Maknae does not defend a process against a reader of its own memory. What bounds such a reader is process isolation — separate service uids and the credential custody [ADR-0023](ADR-0023-runtime-loop-role-and-placement.md) puts on them — and that bound holds today only on a packaged Linux install; it is open on macOS (#227) and the custody assertion is not yet built (#242). Zeroization narrows what a later reader finds, and it is applied wherever decision 1 is met.

### 4. Not decided here

Option B (own the codec and the body) and Option C (B for the kernel↔deputy CBOR leg only, since the provider leg's bytes leave the trust boundary by design) stay candidates; the #241 review's recommendation to consider C first stands. `LimitCORE=0` on both units (and its launchd equivalent) is the obvious cheap narrowing of decision 3 and is likewise unfiled. Nothing is filed while the Cooky milestone is frozen; whoever takes any of it up cites this ADR and carries a T1 change's mutation-gate obligations.

## Consequences

- **Positive:** one home for the claim. A reviewer who finds an unwiped intermediate checks decision 2 before filing, and an unwiped Maknae-owned buffer checks decision 1's table — a listed site is known, an unlisted one is a defect or a missing row, and either way it is recorded here.
- **Accepted:** the residual is real, and it is larger than "the codec": a memory read, a core dump or swap yields recent prompt text, served file content (including on the direct read path), write content and, in the deputy, the provider key — and, outside this ADR's scope, the Vault authentication material the planes and `maknae enroll` hold. This was already true for prompt text since the prompt leg shipped (#172, #240, #264); the ADR names it rather than narrows it.
- **Obligation on later work:** a change that touches a decision-1 site converts it and removes the row; a change that adds or removes a third-party path on a secret-class route updates decision 2 in the same PR.

## Security control mapping (informative; per ADR-0001)

| Property | Control | Status |
|---|---|---|
| Secret-class bytes wiped from Maknae-owned buffers on free; no growth copies | NIST SP 800-53 SC-4 (information in shared system resources) | **Partial** — met on the kernel↔deputy frame buffers (encode and read) and the provider request's Maknae-owned types (#241); the eight Maknae-owned sites listed in decision 1, the `from_reader` scratch among them, do not meet it; the decision-2 residual is inside dependencies; Vault authentication material is out of scope and not inventoried here (its holding types zeroize; plain copies exist around them — see Context) |
| Memory readers bounded by process isolation and custody | AC-6 (least privilege — separate service uids), SC-39 (process isolation) | Implemented on packaged Linux (`_maknae`, `_maknae-egress`); open on macOS (#227); the custody assertion is unbuilt (#242) |
| Post-mortem memory (core dumps) | SC-4 | **Not implemented** — Maknae pins nothing on either platform (no `LimitCORE`, no `PR_SET_DUMPABLE`, no launchd limit); the host's policy decides; accepted under decision 3, candidate follow-up |

## References

- #342 (this decision), #241 / PR #341 (the egress request leg), #172 / #240 / #264 (the prompt leg's history), #227 / #242 (custody's platform preconditions)
- `crates/maknae-proto/src/wire.rs` — `SecretText`, `decode_request` / `decode_response` callers, `encode_response_zeroizing`; `crates/maknae-proto/src/bytes.rs` — `Bytes`; `crates/maknae-proto/src/frame.rs` — `read_frame`
- `crates/maknae-llm/src/client.rs` — `chat_completion`, the reply body; `crates/maknae-llm/src/wire.rs` — the response DTOs; `crates/maknae-deputy/src/call.rs` — `text_of`; `crates/maknae-agent/src/drive.rs` — `text_of`; `crates/maknae-agent/src/route.rs` — tool-argument parsing; `crates/maknae-vault/src/kv_io.rs` — the KV read
- ciborium 0.2.2, `src/de/mod.rs` — `from_reader`, `from_reader_with_buffer`, `deserialize_string`, `deserialize_byte_buf`; reqwest 0.13, `src/async_impl/request.rs` — `bearer_auth`
