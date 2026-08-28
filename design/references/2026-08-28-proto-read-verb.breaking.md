# Break-note: `Verb::Read` added to the `maknaed`↔`maknae` protocol (#77)

**Date:** 2026-08-28 · **Wire version:** unchanged — `PROTOCOL_VERSION` stays **1**.

Per AGENTS.md *Protocol/daemon-contract discipline* ("bump the protocol version **or** file a break-note, and run an old-daemon/new-client interop check"), this records the additive protocol change made by #77 **without** a version bump.

## What changed (all additive CBOR enum variants)

- `Verb::Read { path: String }` — the read verb.
- `Payload::ReadContent(Bytes)` — file content (CBOR byte string, zeroizing).
- `ProtoErrCode::TooLarge` — a permitted read exceeding the frame budget.

## Compatibility matrix

| client → daemon | outcome |
|---|---|
| pre-#77 (v1) CLI → #77 daemon | **works** for `ping`/`whoami` (same wire version); cannot invoke `read` (no such subcommand). |
| #77 CLI → pre-#77 daemon | `ping`/`whoami` work; a `read` request fails **closed** — the old daemon's `decode_request` cannot deserialize the unknown `Read` variant → `ProtoCodecError::Decode` (a typed error, never a panic, never a silent misread). |
| #77 CLI ↔ #77 daemon | full function. |

No existing verb's shape or meaning changes, so there is **no semantic break behind a stable wire** (the class AGENTS.md flags as most dangerous). The version guard remains for a *future, deliberate* bump.

## Why no bump

A `PROTOCOL_VERSION` bump uses strict-equality checks in both directions, making it an **irreversible hard mutual break**: every existing CLI would fail against the new daemon until reinstalled. That was neither necessary nor authorized. The additive path keeps pre-#77 clients working for the unchanged verbs — strictly less disruptive and reversible.

## Interop check (satisfies the discipline)

`crates/maknae-proto/src/wire.rs`:
- `adding_read_is_additive_no_version_bump` — a v1 `Ping` and the new `Read` both round-trip at version 1.
- `a_genuinely_wrong_version_still_refuses_cleanly` — a real version mismatch (999) is still a typed `UnsupportedVersion`, not garbage.

Live-observed 2026-08-28 on Rocky 10: a stale pre-#77 CLI against an (erroneously) version-2 daemon produced `frame truncated` — the exact hard-break symptom a bump causes. Reverting to version 1 removes it.
