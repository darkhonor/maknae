//! maknae-llm — OpenAI-compatible chat-completions client.
//! *(Corrected 2026-09-07, ADR-0023 decision 3: linked into the `maknae-egress`
//! process — §3.2's egress proxy as a process — NOT into `maknaed`; this line
//! previously said "maknaed-linked; egress terminates there", which would have
//! put outbound TLS and provider-response parsing inside the sole PDP. ADR-0023
//! is the component ADR this stub was gated on.)*
//! SCAFFOLD STUB. Body: #240 (spec §2.8).
pub const CRATE_MARKER: &str = "maknae-llm";
