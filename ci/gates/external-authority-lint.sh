#!/usr/bin/env bash
# External-authority lint (#34) — no Maknae rule may rest on another project's
# decision document.
#
# Operator doctrine (2026-08-04, design/adr/README.md): an ADR in another
# project is NOT authoritative for Maknae. If a decision made elsewhere matters
# here, we make it here. External documents may be cited as provenance or
# inspiration; never as the authority a Maknae rule rests on.
#
# The failure this prevents: the KLC opened §7 with "Following the Knowledge
# Lake's authority-line model", which made another repository's ADR the
# authority for a Maknae rule — and left the rule exposed to that project's
# edits, which is how RL#1 findings #55-#58 (drift between Maknae's summary and
# the Lake original) happened. Wording alone is the whole control here, so the
# wording is what gets checked.
#
# The rule: a line naming an external project's decision document must ALSO
# carry a provenance qualifier. Naming the project is fine. Resting on it is not.
set -euo pipefail
cd "$(dirname "$0")/../.."

# Historical records. Do not rewrite what was said at the time; the sweep's job
# is to confirm nothing NORMATIVE points into them as authority (verified
# separately — see #34 site 4).
EXEMPT_RE='^(design/reference-implementation-autopsy\.md|design/reviews/|design/adr/README\.md)'
#            ^ adr/README.md STATES the doctrine, so it must name the projects.

# An external project's decision document, named as such.
EXTERNAL_RE='(Knowledge Lake.{0,40}ADR|Lake ADR-|Microkosmos ADR|Security-MCP.{0,20}adr|knowledgebase.{0,20}ADR|mpe-es/[a-z-]+.{0,20}ADR)'

# Any of these on the same line demotes the citation to provenance.
QUALIFIER_RE='(provenance|informed (this|the)|never authority|not authoritative|Precedent is|inspired by|derived from|that project.s number|In-housed)'

# find, not `git ls-files`: the negative-control fixture is a bare directory,
# and a gate that only runs inside a repo cannot be proven to fire outside one.
#
# THE CORPUS'S OWN SOUNDNESS, established before its contents are trusted (#219).
# This was `find design … 2>/dev/null` with a trailing `|| true`, which discarded
# the error text, the exit status, AND the empty case at once: a tree with no
# `design/` produced an empty list and reported `ok`. `design/` is the corpus
# this gate exists to scan, so failing to list it is an error, not an empty
# result.
# `-L -type f`. `-type f` alone keeps a DIRECTORY named `*.md` out of the corpus
# -- without it `grep` returns 2 on the directory and the read-the-status check
# reports `could not read`, a hard failure naming the wrong cause. (Measured:
# BSD grep also exits 2 on a directory operand, so that was a wrong-diagnostic
# bug, not the BSD/GNU divergence it first looked like.) `-L` is what keeps a
# SYMLINKED design doc IN: `-type f` alone uses `lstat`, so a symlink to a real
# `.md` is `-type l` and would silently never be scanned -- an unscanned
# normative document in the gate whose whole subject is wording.
if ! design_md=$(find -L design -type f -name '*.md'); then
  echo "FAIL external-authority-lint: could not list design/ — the corpus this"
  echo "  gate scans. A corpus that cannot be read has not been cleared."
  exit 1
fi
# `AGENTS.md` and `README.md` are REQUIRED, not optional. `AGENTS.md` carries
# the very authority doctrine this gate enforces, so losing it to a rename must
# not quietly shrink the corpus to 27 and still report `ok`.
#
# They were tolerated (`2>/dev/null || true`) only because the negative-control
# fixture had neither, i.e. an artifact of what could be fixtured rather than a
# property of the corpus -- the same excuse `isolation-contract-lint` stopped
# accepting in this change when it took a root override so its floor could be
# probed. The fixture now creates both, so the requirement is enforced AND
# probeable. No `2>/dev/null` survives on any CODE line of this gate -- the only
# remaining mentions are in these comments, describing what was removed.
missing=""
for r in AGENTS.md README.md; do [ -f "$r" ] || missing="$missing $r"; done
if [ -n "$missing" ]; then
  echo "FAIL external-authority-lint: required root document(s) absent:$missing"
  echo "  These carry the authority doctrine this gate enforces; a corpus that"
  echo "  has lost them has not been cleared."
  exit 1
fi
root_md=$(printf '%s\n' AGENTS.md README.md)

files=$(printf '%s\n%s\n' "$design_md" "$root_md" | grep -v '^$' | grep -Ev "$EXEMPT_RE" || true)

# FLOOR. Zero files after exemptions is not "nothing to check", it is "nothing
# was checked" -- and this gate's whole subject is wording, so an empty corpus
# clears every rule in the repo by default. The real tree always has at least
# AGENTS.md and README.md unexempted, and the fixture always has its one design
# doc, so one is the legitimate minimum on every input this gate has.
scanned=$(printf '%s\n' "$files" | grep -c . || true)
if [ "$scanned" -eq 0 ]; then
  echo "FAIL external-authority-lint: scanned ZERO files."
  echo "  Nothing was examined, so 'no unqualified external citation' is not a"
  echo "  finding. An exemption pattern that swallowed the whole corpus is the"
  echo "  reachable cause; the required root documents are checked above."
  exit 1
fi

bad=0
while IFS= read -r f; do
  [ -n "$f" ] || continue
  # The per-file read's OWN status, for the same reason as the corpus listing
  # above -- and this is the call that does the actual checking. It was
  # `< <(grep … || true)`, which collapses grep's ERROR (2) into its no-match
  # (1): an unreadable `design/*.md` carrying a real unqualified citation was
  # cleared at rc 0 while the success line counted it as scanned, so the count
  # asserted more than the gate had examined. `--` guards a path that could
  # begin with a dash.
  set +e
  hits=$(grep -nEi -e "$EXTERNAL_RE" -- "$f"); grc=$?
  set -e
  if [ "$grc" -gt 1 ]; then
    echo "FAIL external-authority-lint: could not read '$f' (grep exit $grc)."
    echo "  A file that cannot be read has not been cleared, and must not be"
    echo "  counted as scanned."
    exit 1
  fi
  while IFS=: read -r n line; do
    [ -n "$n" ] || continue
    if ! printf '%s' "$line" | grep -Eqi "$QUALIFIER_RE"; then
      echo "FAIL external-authority-lint: $f:$n cites an external project's decision document with no provenance qualifier"
      echo "    $(printf '%s' "$line" | cut -c1-140)"
      bad=1
    fi
  done <<< "$hits"
done <<< "$files"

if [ "$bad" -ne 0 ]; then
  echo
  echo "Each site must either restate the decision as Maknae's own, or carry a"
  echo "provenance qualifier — e.g. 'Provenance, never authority: X informed this'."
  echo "See design/adr/README.md § Authority rule, and issue #34."
  exit 1
fi
echo "external-authority-lint: ok ($scanned files scanned)"
