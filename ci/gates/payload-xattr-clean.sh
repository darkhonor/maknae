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
# THE ATTRIBUTE IS ATTACHED ON WRITE, and an interactive macOS session cannot
# avoid it. CORRECTED 2026-09-21: an earlier revision of this comment blamed the
# "responsible application" and named Terminal.app as a clean context. THAT IS
# FALSE. Measured on the maintainer's host (SIP enabled) in a shell whose lineage
# is Terminal.app -> login -> -zsh: `touch`, `>`, `mkdir`, `install -d` and
# `mktemp -d` ALL produce the attribute, in EVERY location tried — /tmp, $TMPDIR,
# $HOME, /var/tmp and the repo working tree. Staging elsewhere does not help.
#
# Copying spreads it further: `install`, `cp` and `ditto` PROPAGATE a source
# file's extended attributes to the destination (`cp -X` and
# `ditto --norsrc --noextattr` do not), so a tagged build input contaminates the
# payload even before the writing process adds its own.
#
# TWO contexts have been measured to produce a CLEAN payload, and only two:
#   * a launchd-spawned process on the maintainer's host
#   * a GitHub Actions macos-26 runner, which reports SIP DISABLED
# The second is consistent with the attribute being SIP-protected, but causation
# is NOT proven here — it is recorded as the material difference, not the cause.
# That uncertainty is exactly why this gate runs in CI rather than being assumed:
# the runner image's SIP posture is GitHub's to change.
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

# AN ENTRY THAT COULD NOT BE INSPECTED HAS NOT BEEN ATTESTED CLEAN.
#
# CORRECTED 2026-09-21 (blind review of PR #336). Every query below previously
# read `"$(xattr -s "$p" 2>/dev/null || true)"`, which discards the exit status
# and leaves an empty string — indistinguishable from "this entry has no
# extended attributes". REPRODUCED with an `xattr` shim that fails every query:
# the gate printed `ok (4 entries examined, none carry extended attributes)` and
# exited 0, having attested nothing.
#
# That is the SAME defect class this gate exists to catch — a control reporting
# success while doing no work — reintroduced inside the fix for it. Every query
# now captures its status separately and REFUSES on an inspection error.
work="$(mktemp -d "${TMPDIR:-/tmp}/maknae-pxc.XXXXXXXX")"
trap 'rm -rf -- "$work"' EXIT INT TERM

# The payload ROOT's own attributes are checked, but are NOT counted as an entry:
# the root maps to `.` in the BOM and has no sibling position of its own, while
# the floor below must be able to see an EMPTY payload. Counting the root would
# make `examined` >= 1 unconditionally and the floor unreachable.
if ! root_attrs="$(xattr -s "$target" 2>&1)"; then
  echo "FAIL: cannot READ the extended attributes of the payload root $target: $root_attrs"
  echo "  An entry that could not be inspected has not been attested clean."
  exit 1
fi
if [ -n "$root_attrs" ]; then
  echo "FAIL: extended attribute on the payload root $target: $(printf '%s' "$root_attrs" | tr '\n' ' ')"
  fail=1
fi

# DISCOVERY IS CHECKED TOO. The walk previously fed the loop through process
# substitution, which discards `find`'s exit status: a walk that failed PARTWAY
# — after emitting some entries — left a short list that passed the floor and
# scored `ok`. The listing is materialised first so the status is observable.
# (`rc=0; cmd || rc=$?` keeps the failure out of `set -e`'s reach.)
find_rc=0
find "$target" -mindepth 1 -print0 > "$work/list" 2>"$work/err" || find_rc=$?
if [ "$find_rc" -ne 0 ]; then
  echo "FAIL: the directory walk of $target FAILED (find exit $find_rc): $(head -3 "$work/err")"
  echo "  A partial walk would under-count, and an under-count can still clear"
  echo "  the floor below — so discovery failing is itself a refusal, never an"
  echo "  empty payload."
  exit 1
fi

examined=0
# -print0 / read -d '', because a payload path may contain whitespace, and
# `xattr -s` so a symlink's OWN attributes are read rather than its target's.
#
# The loop runs in THIS shell — redirected from a file, never a pipe — so the
# counters survive it. A `while ... | read` would count in a subshell and the
# floor below would always read zero.
while IFS= read -r -d '' p; do
  examined=$((examined+1))
  if ! attrs="$(xattr -s "$p" 2>&1)"; then
    echo "FAIL: cannot READ the extended attributes of $p: $attrs"
    fail=1
    continue
  fi
  if [ -n "$attrs" ]; then
    echo "FAIL: extended attribute on $p: $(printf '%s' "$attrs" | tr '\n' ' ')"
    fail=1
  fi
done < "$work/list"

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
  returns success and leaves it in place.

  THIS IS EXPECTED ON AN INTERACTIVE macOS HOST and is not something you can fix
  locally. Every interactive session measured attaches it to everything it
  writes, in every location, Terminal.app included. Packaging therefore happens
  in the RELEASE workflow:

      .github/workflows/release.yml  (tag `v*`, or run it by hand with a version)

  It builds the .pkg and runs smoke.sh phase 1, publishing the package as a build
  artifact. Download that artifact if you need a .pkg to install or to run
  phase 2 against.

  If you are seeing this IN CI, do not work around it: the runner has started
  tagging writes, the packaging context is no longer clean, and a package built
  there would ship AppleDouble files into /usr/local.
REMEDY
  exit 1
fi

echo "payload-xattr-clean: ok ($examined entries examined, none carry extended attributes)"
