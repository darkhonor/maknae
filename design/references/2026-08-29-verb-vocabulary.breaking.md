# Break-note — the action vocabulary (#67)

**Date:** 2026-08-29 · **Change:** `maknae-proto` gains **54 additive `Verb` variants** (57 total) and `ProtoErrCode::NotImplemented`. **`PROTOCOL_VERSION` STAYS 1.**

AGENTS.md requires a protocol/daemon-contract change to either bump the version **or** file a break-note plus an interop check. A bump is operator-authorization-only and is the wrong call here (it is an irreversible hard mutual break — the #77 incident). **This note is the discharge.**

## Why the variants are additive

`Verb` is an externally-tagged serde enum over CBOR, encoded **by variant name**, not by index. Adding variants therefore changes no existing encoding:

- **Old client → new daemon:** the old client can only construct `Ping`/`Whoami`/`Read`, whose wire keys are unchanged. It keeps working for every verb it knows.
- **New client → old daemon:** a new verb reaches an old daemon as an unknown variant and fails `decode_request` with a typed codec error — fail-closed, and audited under the `decode` pseudo-action with the caller's uid.

**The three shipped variants keep their Rust identifiers deliberately.** The identifier IS the CBOR key, so renaming `Read` to `FsRead` under the new naming rule would have silently broken every deployed CLI with no version bump and no compile error. `handler.rs::the_shipped_variants_keep_their_wire_keys` pins the exact CBOR text header for all three; it was observed failing against a `#[serde(rename)]` mutation.

## Consequences to know

- **`ProtoErrCode::NotImplemented` is additive forward only.** A pre-change client that invokes a term the daemon has since retired to a NOOP cannot decode the new code and surfaces a codec error. That is accepted: the *daemon* still decides and audits the attempt, which is the point of retiring a verb to a NOOP rather than deleting it (spec R3).
- **`[N]` variants are parameterless, and parameterising one later is BOTH a wire break AND an R4 semantic break.** The parameterlessness *is* the term's current decided semantics: with no `path` attribute, `decide_fs` returns `Indeterminate` → Deny. Adding the parameter would flip the verdict Deny → Permit against the shipped `Read(~/**)` with no policy edit. Any such change needs a break-note, an interop check, **and a test proving the verdict did not flip**.

## Interop evidence

`maknae-proto`'s `adding_read_is_additive_no_version_bump` and `a_genuinely_wrong_version_still_refuses_cleanly` retained and green; `the_shipped_variants_keep_their_wire_keys` added and mutation-proven. **Not yet run: a live old-daemon/new-client check on the Linux hosts.** Owed before the acceptance sign-off, not before merge — no shipped client can construct a new verb, so the only reachable interop path is the one the retained tests cover.
