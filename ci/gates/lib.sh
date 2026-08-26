#!/usr/bin/env bash
# Shared constants for the capability-separation gates (spec §3 P1/P2).
PRIVILEGED_CRATES=(maknae-kernel maknae-subject-ctx-mint maknae-audit-append maknae-spif-compile maknae-authz-basic)
UNTRUSTED_BIN="maknae"
# Per-consumer allowlist: which privileged crate each trust-plane binary may DIRECTLY depend on
# (mirrors packaging/isolation-contract.md crate×binary matrix). maknaed gets the kernel (which
# itself carries mint/append transitively); the setup-only tool gets ONLY the compiler. Anything
# else — incl. maknaed pulling the compiler, or spifc pulling kernel — fails P1.
TRUST_CONSUMER_ALLOW=("maknaed=maknae-kernel" "maknae-spifc=maknae-spif-compile")
