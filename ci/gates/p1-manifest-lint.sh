#!/usr/bin/env bash
set -euo pipefail
here="$(cd "$(dirname "$0")" && pwd)"; source "$here/lib.sh"
root="${1:-$(git rev-parse --show-toplevel)}"; fail=0

grep -qE '^[[:space:]]*resolver[[:space:]]*=[[:space:]]*"3"' "$root/Cargo.toml" || { echo "FAIL: root Cargo.toml missing resolver = \"3\""; fail=1; }
grep -qE '^[[:space:]]*default-members' "$root/Cargo.toml" && { echo "FAIL: root Cargo.toml declares default-members (forbidden, spec §3)"; fail=1; }

# Dependency checks via `cargo metadata` — normalizes inline AND table TOML forms.
# No optional privileged dep anywhere; only trust-plane consumers (lib.sh TRUST_CONSUMERS)
# and the privileged crates themselves may depend on a privileged crate.
# The metadata is captured FIRST, keeping its stderr, so a failing invocation
# reports the reason (#219). It was `cargo metadata … 2>/dev/null | python3 …`:
# cargo's diagnostic went to /dev/null, python then got an empty stdin and died
# with a `JSONDecodeError` traceback, and the gate exited 1 having printed no
# FAIL line at all -- a mute failure, unprobeable by `expect_reject`, which
# requires one. Demonstrated with `members = ["nope"]`.
#
# The streams are captured SEPARATELY, never merged with `2>&1`. cargo writes
# the metadata JSON to stdout and its diagnostics to stderr, so merging them
# would splice any warning cargo chose to emit -- an unused `[patch]`, a
# manifest key a newer cargo starts objecting to -- straight into the document
# python then parses, turning a warning into a parse failure. REPRODUCED, not
# hypothetical: with a stray key in `$CARGO_HOME/config.toml`, `cargo metadata`
# exits 0 and writes `warning: unused config key …` to stderr, which under a
# merged capture prefixes the JSON and kills `json.load`.
tmp="$(mktemp -d)"; trap 'rm -rf "$tmp"' EXIT
if ! cargo metadata --manifest-path "$root/Cargo.toml" --no-deps --format-version 1 \
     > "$tmp/meta.json" 2> "$tmp/meta.err"; then
  echo "FAIL: cargo metadata failed under '$root' — the package set could not be"
  echo "  resolved, so nothing was examined. cargo said:"
  head -5 < "$tmp/meta.err" | sed 's/^/    /'
  fail=1
elif ! python3 "$here/p1_check.py" "${PRIVILEGED_CRATES[*]}" "${TRUST_CONSUMER_ALLOW[*]}" < "$tmp/meta.json"; then
  fail=1
fi

# Reported for the same reason the other #219 gates report theirs: the floor in
# `p1_check.py` catches a TOTAL collapse, and `negative-control` cross-checks
# this number against the member manifests on disk, which catches a workspace
# the resolver silently stopped covering. `$tmp/meta.json` is already written,
# so this costs one more parse.
#
# Guarded on `$fail`, not merely on the file being non-empty: a `cargo metadata`
# that exits non-zero AFTER flushing partial stdout leaves a non-empty file that
# never parsed, and the inline `json.load` below would then die under `set -e`
# with a traceback -- the mute-failure shape this change exists to remove.
npkg=0
if [ "$fail" -eq 0 ] && [ -s "$tmp/meta.json" ]; then
  # No `except: print(0)` swallow. This only runs after the metadata parsed
  # cleanly for `p1_check.py`, so a failure here is a real one and must not be
  # rendered as a count of zero -- which would read as a legitimate empty
  # workspace, the exact confusion this issue is about.
  npkg="$(python3 -c 'import json,sys; print(len(json.load(sys.stdin)["packages"]))' < "$tmp/meta.json")"
fi
[ "$fail" -eq 0 ] && echo "p1-manifest-lint: ok ($npkg packages examined)"
exit "$fail"
