#!/usr/bin/env bash
set -euo pipefail
# #332 — REFUSE a package payload that still carries extended attributes.
#
# WHY THIS GATE EXISTS, and why it verifies by RE-READING rather than by exit
# status. `pkgbuild` serialises an AppleDouble `._name` sibling INTO the payload
# for every entry carrying an extended attribute, and those become REAL INSTALLED
# FILES under /usr/local — BOM rows, owned and left behind, which `uninstall.sh`
# knows nothing about. build-pkg.sh tried to prevent that with `xattr -rc`, and
# that line is INERT.
#
# MEASURED 2026-09-20 on macOS 26.6.2 (Apple Silicon), calling the syscall
# directly rather than trusting the CLI:
#
#     removexattr(com.apple.provenance) -> rc=0  errno=0   attribute STILL PRESENT
#
# removexattr(2) specifies "On success, 0 is returned. On failure, -1 is returned
# and the global variable errno is set." The KERNEL reports success and does
# nothing, so `xattr(1)` is not swallowing an error — there is no error to
# swallow, and NO EXIT STATUS ANYWHERE CAN DETECT THIS. Re-reading the attribute
# list is the only verification the kernel leaves available. Control, proving the
# tooling is otherwise sound: `xattr -w com.example.test` then `-d` removes
# cleanly; only com.apple.provenance resists.
#
# THE ROOT CAUSE IS THE RESPONSIBLE APPLICATION of the writing process — not
# macOS 26, not APFS, not pkgbuild. Proven end to end: same pkgbuild, same host,
# same filesystem, same payload shape, changing only who ran it —
#   built by an agent session -> BOM has 9 rows, 4 of them `._`
#   built inside a launchd job -> BOM is clean, and `xattr -r -l` returned empty
# There is no in-session escape for a tagged writer: `>`, cp, install, ditto,
# tee, dd, python3, sed, touch, mkdir — and even mv/rename and a plain append —
# all re-tag.
#
# Two other doors are closed, so nobody reopens them:
#   * `pkgbuild --filter` cannot reach the entries. The man page says filters
#     exclude "any path in the root which matches", and the `._` entries are
#     never paths in the root — they are synthesised during serialisation.
#   * `--preserve-xattr` (undocumented, present in the binary) only stamps
#     PackageInfo; the BOM is byte-identical with and without it.
#
# Usage: payload-xattr-clean.sh <dir>
# Target override in argv, matching isolation-contract-lint / p1-manifest-lint /
# build-invocation-lint, so negative-control.sh can point it at a fixture. A
# floor nobody can probe is not a control.

target="${1:-}"
[ -n "$target" ] || { echo "FAIL: no target directory given (usage: payload-xattr-clean.sh <dir>)"; exit 2; }

# REFUSE on missing tooling rather than reporting ok. `xattr(1)` is a macOS tool;
# on any other platform this gate has attested nothing, and saying so is the
# difference between a control and a decoration (smoke.sh applies the same rule).
command -v xattr >/dev/null 2>&1 \
  || { echo "FAIL: xattr(1) not available — this gate cannot attest anything on $(uname -s)"; exit 2; }

[ -e "$target" ] || { echo "FAIL: $target does not exist"; exit 1; }
[ -d "$target" ] || { echo "FAIL: $target is not a directory"; exit 1; }
# READABLE, not merely present: an unreadable directory makes `find` print its own
# error and yields no entries, which would otherwise look identical to "clean".
[ -r "$target" ] || { echo "FAIL: $target is not readable — a tree that cannot be read has not been checked"; exit 1; }

fail=0

# The payload ROOT's own attributes are checked, but are NOT counted as an entry:
# the root maps to `.` in the BOM and has no sibling position of its own, while
# the floor below must be able to see an EMPTY payload. Counting the root would
# make `examined` >= 1 unconditionally and the floor unreachable.
root_attrs="$(xattr -s "$target" 2>/dev/null || true)"
if [ -n "$root_attrs" ]; then
  echo "FAIL: extended attribute on the payload root $target: $(printf '%s' "$root_attrs" | tr '\n' ' ')"
  fail=1
fi

examined=0
# -print0 / read -d '', because a payload path may contain whitespace, and
# `xattr -s` so a symlink's OWN attributes are read rather than its target's (a
# dangling link would otherwise error and be skipped silently).
#
# The loop runs in THIS shell — process substitution, never a pipe — so the
# counters survive it. A `while ... | read` would count in a subshell and the
# floor below would always read zero.
while IFS= read -r -d '' p; do
  examined=$((examined+1))
  attrs="$(xattr -s "$p" 2>/dev/null || true)"
  if [ -n "$attrs" ]; then
    echo "FAIL: extended attribute on $p: $(printf '%s' "$attrs" | tr '\n' ' ')"
    fail=1
  fi
done < <(find "$target" -mindepth 1 -print0)

# THE FLOOR (#219 class, and the precise defect #332 is about): a control that
# examined nothing has found nothing. `xattr -rc` exited 0 having done no work,
# and nothing noticed for as long as it took someone to read a BOM.
if [ "$examined" -eq 0 ]; then
  echo "FAIL: examined ZERO entries under $target."
  echo "  The directory is present but empty, so 'no entry carries an extended"
  echo "  attribute' is not a finding — there were no entries to check."
  exit 1
fi

if [ "$fail" -ne 0 ]; then
  cat >&2 <<'REMEDY'

  WHY THIS FAILED, and what to do about it:

  Extended attributes survived the strip. `pkgbuild` will serialise each one as
  an AppleDouble `._name` sibling INTO the payload, where it becomes a real
  installed file that uninstall.sh does not know about.

  If the attribute is com.apple.provenance, it CANNOT BE REMOVED — removexattr(2)
  returns success and leaves it in place. It is attached per-write by the
  RESPONSIBLE APPLICATION of the process doing the writing, so the fix is to
  build from a context whose responsible application is Apple-signed:

      Terminal.app, a launchd job, or CI.

  A build driven by an agent session, an editor's integrated terminal, or a
  third-party terminal emulator tags every file and directory it writes, and no
  amount of stripping inside that session will clear it.
REMEDY
  exit 1
fi

echo "payload-xattr-clean: ok ($examined entries examined, none carry extended attributes)"
