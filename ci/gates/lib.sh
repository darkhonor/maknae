#!/usr/bin/env bash
# Shared constants for the capability-separation gates (spec §3 P1/P2).
PRIVILEGED_CRATES=(maknae-kernel maknae-subject-ctx-mint maknae-audit-append maknae-spif-compile)
UNTRUSTED_BIN="maknae"
# Trust-plane consumers that MAY depend on privileged crates (the daemon + the setup tool).
# Everything else — shared library crates AND the untrusted CLI — must not.
TRUST_CONSUMERS=(maknaed maknae-spifc)
