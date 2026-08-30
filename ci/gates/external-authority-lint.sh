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
files=$( { find design -name '*.md' 2>/dev/null; ls AGENTS.md README.md 2>/dev/null; } \
        | grep -Ev "$EXEMPT_RE" || true)

bad=0
while IFS= read -r f; do
  [ -n "$f" ] || continue
  while IFS=: read -r n line; do
    [ -n "$n" ] || continue
    if ! printf '%s' "$line" | grep -Eqi "$QUALIFIER_RE"; then
      echo "FAIL external-authority-lint: $f:$n cites an external project's decision document with no provenance qualifier"
      echo "    $(printf '%s' "$line" | cut -c1-140)"
      bad=1
    fi
  done < <(grep -nEi "$EXTERNAL_RE" "$f" || true)
done <<< "$files"

if [ "$bad" -ne 0 ]; then
  echo
  echo "Each site must either restate the decision as Maknae's own, or carry a"
  echo "provenance qualifier — e.g. 'Provenance, never authority: X informed this'."
  echo "See design/adr/README.md § Authority rule, and issue #34."
  exit 1
fi
echo "external-authority-lint: ok"
