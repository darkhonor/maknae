#!/usr/bin/env bash
# Shared constants for the capability-separation gates (spec §3 P1/P2).
PRIVILEGED_CRATES=(maknae-kernel maknae-subject-ctx-mint maknae-audit-append maknae-spif-compile maknae-authz-basic)
UNTRUSTED_BINS=(maknae maknae-agentd)
# P2-loop (#629): unreachable through normal dependencies from every TRUSTED_ROOTS member.
LOOP_CRATES=(maknae-loop maknae-agent)
TRUSTED_ROOTS=(maknaed maknae-egress maknae-spifc "${PRIVILEGED_CRATES[@]}")
# Per-consumer allowlist: which privileged crate each trust-plane binary may DIRECTLY depend on
# (mirrors packaging/isolation-contract.md crate×binary matrix). maknaed gets the kernel (which
# itself carries mint/append transitively); the setup-only tool gets ONLY the compiler. Anything
# else — incl. maknaed pulling the compiler, or spifc pulling kernel — fails P1.
TRUST_CONSUMER_ALLOW=("maknaed=maknae-kernel" "maknae-spifc=maknae-spif-compile")
SYS_CRATE="maknae-sys"
SYS_CONSUMER_ALLOW=(maknae-io)

# The build entry points build-invocation-lint scans; extra `find` terms widen the set for a
# caller. A non-zero status is a scan error, never an empty result (#219).
build_surface_files() {
  local root="$1" out="$2"; shift 2
  find "$root" -type d \( -name target -o -name '.claude' -o -path '*/ci/gates' \) -prune -o -type f \
    \( -path '*/.github/workflows/*.yml' -o -path '*/.github/workflows/*.yaml' \
       -o -name 'Dockerfile*' -o -name 'justfile' -o -name 'Justfile' \
       -o -name 'Makefile' -o -name 'makefile' -o -name 'GNUmakefile' -o -name '*.mk' \
       -o -name '*.sh' "$@" \) -print > "$out"
}

# One logical line per shell command: a trailing backslash joins the next line.
# No `--` before the file: this awk reads `--` as a FILENAME. Callers pass absolute paths
# (from `build_surface_files` on an absolute root), so none begins with a dash.
join_continuations() {
  awk '{ if (sub(/\\[[:space:]]*$/,"")) { buf = buf $0 " " } else { print buf $0; buf = "" } } END { if (buf != "") print buf }' \
    "$1" > "$2"
}
