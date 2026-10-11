#!/usr/bin/env bash
# containment-ordering (#165): the Adversary arm is decided before any class arm, and
# the identity hop reads `contained` before `binds`.
set -euo pipefail
export LC_ALL=C
root="${1:-$(git rev-parse --show-toplevel)}"
src="$root/crates/maknae-authz-basic/src"
failed=0
fail() { echo "FAIL: $*"; failed=1; }

lex() {
  awk '
    BEGIN { q = sprintf("%c", 39) }
    /^#\[cfg\(test\)\]/ { exit }
    {
      line = $0; out = ""; n = length(line); i = 1
      while (i <= n) {
        c = substr(line, i, 1); d = substr(line, i + 1, 1)
        if (depth > 0) {
          if (c == "/" && d == "*") { depth++; i += 2; continue }
          if (c == "*" && d == "/") { depth--; i += 2; continue }
          i++; continue
        }
        if (instr) {
          if (c == "\\") { i += 2; continue }
          if (c == "\"") { instr = 0; out = out "\"" }
          i++; continue
        }
        if (c == "/" && d == "/") break
        if (c == "/" && d == "*") { depth = 1; i += 2; continue }
        if (c == "\"") { instr = 1; out = out "\""; i++; continue }
        if (c == "r" && substr(line, i - 1, 1) !~ /[A-Za-z0-9_]/ && substr(line, i + 1) ~ /^#*"/) {
          print "LEX-ERROR raw string literal at line " NR; bad = 1; exit
        }
        if (c == q) {
          if (d == "\\") {
            j = index(substr(line, i + 2), q)
            if (j == 0) { print "LEX-ERROR char literal at line " NR; bad = 1; exit }
            out = out q q; i += j + 2; continue
          }
          if (substr(line, i + 2, 1) == q) { out = out q q; i += 3; continue }
        }
        out = out c; i++
      }
      print NR "\t" out
    }
    END {
      if (bad) exit 2
      if (instr || depth > 0) { print "LEX-ERROR unterminated string or block comment"; exit 2 }
    }
  ' "$1"
}

defs() {
  FN="$2" awk -F '\t' '
    BEGIN { pat = "(^|[^A-Za-z0-9_])fn[[:space:]]+" ENVIRON["FN"] "[[:space:]]*[(<]" }
    { body = $0; sub(/^[^\t]*\t/, "", body); t = body }
    !inside && match(body, pat) { inside = 1; k++; depth = 0; opened = 0; t = substr(body, RSTART); rest = substr(t, 2); start = NR }
    inside && NR != start { rest = body }
    inside {
      print k "\t" $1 "\t" body
      if (!opened && index(t, ";") && !index(t, "{")) { print "DEF-ERROR " ENVIRON["FN"] " has no body at line " $1; bad = 1; exit }
      o = gsub(/\{/, "{", t); c = gsub(/\}/, "}", t)
      if (o > 0) opened = 1
      depth += o - c
      if (opened && depth <= 0) {
        inside = 0
        if (rest ~ pat) { print "DEF-ERROR a second " ENVIRON["FN"] " starts on line " $1; bad = 1; exit }
      }
    }
    END { if (bad) exit 2; if (inside) { print "DEF-ERROR " ENVIRON["FN"] " body never closes"; exit 2 } }
  ' <<<"$1"
}

load() {
  local name="$1" file="$2" out
  lexed=""
  if [ ! -f "$file" ]; then
    fail "$name: $file is missing"
    return
  fi
  if ! out="$(lex "$file")"; then
    fail "$name: cannot lex $file: $(grep '^LEX-ERROR' <<<"$out" || true)"
    return
  fi
  if [ -z "$out" ]; then
    fail "$name: the production half of $file is empty"
    return
  fi
  lexed="$out"
}

load decide.rs "$src/decide.rs"
decide_lexed="$lexed"
load binding.rs "$src/binding.rs"
binding_lexed="$lexed"

if [ -n "$decide_lexed" ]; then
  if ! d="$(defs "$decide_lexed" decide_loaded_cited)"; then
    fail "cannot extract decide_loaded_cited: $(grep '^DEF-ERROR' <<<"$d" || true)"
  else
    ndefs="$(cut -f1 <<<"$d" | sort -u | grep -c . || true)"
    if [ "$ndefs" != 1 ]; then
      fail "expected exactly one fn decide_loaded_cited in the production half of decide.rs, found $ndefs"
    else
      awk -F '\t' '
        function word(s, w) { return s ~ ("(^|[^A-Za-z0-9_])" w "([^A-Za-z0-9_]|$)") }
        function out(m) { print "FAIL: " m; rc = 1 }
        function norm(s) { gsub(/[[:space:]]+/, " ", s); sub(/^ /, "", s); sub(/ $/, "", s); return s }
        function arm_pattern(p, line) {
          p = norm(p)
          if (p ~ /^Role::Adversary( if .*)?$/) { advarm = line; return 1 }
          if (p !~ /^Role::(Admin|User|Guest)( ?\| ?Role::(Admin|User|Guest))*( if .*)?$/)
            out("an arm before Role::Adversary must name roles other than Adversary (line " ln[line] ")")
          return 0
        }
        { n++; ln[n] = $2; t = $0; sub(/^[^\t]*\t[^\t]*\t/, "", t); tx[n] = t }
        END {
          for (i = 1; i <= n; i++) {
            if (index(tx[i], "#[")) out("an attribute inside decide_loaded_cited cannot be read lexically (line " ln[i] ")")
            if (tx[i] ~ /(^|[^A-Za-z0-9_])match[[:space:]]+role[[:space:]]*\{/) { mr++; mrl = i }
            if (index(tx[i], "role_for(")) { rf++; rfl = i }
            if (tx[i] ~ /^[[:space:]]*Role::Adversary[[:space:]]*(if[[:space:]].*)?=>/) { adv++; advl = i }
            if (tx[i] ~ /(^|[^A-Za-z0-9_])match[[:space:]]+class([^A-Za-z0-9_]|$)/ && !mcl) mcl = i
          }
          if (mr != 1) { out("decide_loaded_cited must hold exactly one `match role {`, found " mr + 0); exit rc }
          if (rf > 1) { out("decide_loaded_cited calls role_for( " rf " times; cannot tell which resolves the role"); exit rc }
          if (adv != 1) { out("exactly one Role::Adversary arm in decide_loaded_cited, found " adv + 0); exit rc }
          if (!mcl) { out("decide_loaded_cited holds no `match class`; cannot place the class arms"); exit rc }
          if (advl >= mcl) out("Role::Adversary must precede every class arm in decide_loaded_cited")
          if (tx[advl] ~ /^[[:space:]]*Role::Adversary[[:space:]]*if[[:space:]]/) out("the Role::Adversary arm in decide_loaded_cited must not carry a guard")

          bound = rf ? rfl : mrl
          kern = 0
          for (i = 1; i < bound; i++) {
            t = tx[i]
            if (index(t, "class_of(") || word(t, "match[[:space:]]+class") || index(t, "Class::") || index(t, "req.action")) {
              if (t ~ /^[[:space:]]*if[[:space:]]+class_of\(&req\.action\.0\)[[:space:]]*==[[:space:]]*Some\(Class::Kernel\)[[:space:]]*\{[[:space:]]*$/ && !kern) kern = i
              else out("only the kernel early return may evaluate a class before role resolution (line " ln[i] ")")
            }
          }
          for (i = 1; i < bound; i++) {
            if (!word(tx[i], "return")) continue
            if (index(tx[i], "return undecided(Verdict::Indeterminate)")) continue
            if (kern && i == kern + 1 && tx[i] ~ /^[[:space:]]*return[[:space:]]+undecided\(kernel_decided\(req\)\);[[:space:]]*$/) continue
            out("before role resolution only an Indeterminate or the kernel return may leave decide_loaded_cited (line " ln[i] ")")
          }
          rebind = "(^|[^A-Za-z0-9_])let[[:space:]]+([^=]*[^A-Za-z0-9_.])?role([^A-Za-z0-9_]|$)"
          for (i = 1; i <= n; i++) {
            t = tx[i]
            if ((t ~ rebind || t ~ /^[[:space:]]*role[[:space:]]*=[^=]/) && !(rf && i == rfl))
              out("the role is rebound outside its role_for( resolution in decide_loaded_cited (line " ln[i] ")")
          }
          if (rf) {
            if (rfl > mrl) out("role_for( is called after `match role {` in decide_loaded_cited")
            if (tx[rfl] !~ /^[[:space:]]*let[[:space:]]+role[[:space:]]*=/) out("the role_for( line must bind `role` in decide_loaded_cited (line " ln[rfl] ")")
            for (i = rfl; i < mrl; i++) {
              t = tx[i]
              if (t ~ /(^|[^A-Za-z0-9_])Role::/) out("a Role is named between role resolution and `match role {` (line " ln[i] ")")
              if (word(t, "if")) out("a condition sits between role resolution and `match role {` (line " ln[i] ")")
              if (index(t, "class_of(") || word(t, "class") || index(t, "Class::") || index(t, "req.action")) {
                if (t !~ /^[[:space:]]*let[[:space:]]+class[[:space:]]*=[[:space:]]*class_of\(&req\.action\.0\);[[:space:]]*$/)
                  out("only `let class = class_of(&req.action.0);` may read the class or action between role resolution and `match role {` (line " ln[i] ")")
              }
              if (word(t, "return")) {
                p = i - 1
                while (p > rfl && tx[p] ~ /^[[:space:]]*$/) p--
                if (!index(t, "return undecided(Verdict::NotApplicable") || !(index(t, "Resolution::NoRole") || tx[p] ~ /^[[:space:]]*Resolution::NoRole[[:space:]]*=>[[:space:]]*\{[[:space:]]*$/))
                  out("only the NoRole arm may return between role resolution and `match role {` (line " ln[i] ")")
              }
            }
          }

          s = tx[mrl]; match(s, /(^|[^A-Za-z0-9_])match[[:space:]]+role[[:space:]]*\{/)
          start = RSTART + RLENGTH
          state = "pat"; pat = ""; body = ""; depth = 0; advarm = 0; done = 0
          for (i = mrl; i <= n && !done; i++) {
            s = tx[i]; L = length(s)
            for (j = (i == mrl ? start : 1); j <= L && !done; j++) {
              ch = substr(s, j, 1)
              if (state == "pat") {
                if (depth == 0 && ch == "}") { done = 1; break }
                if (depth == 0 && ch == "=" && substr(s, j + 1, 1) == ">") {
                  j++
                  isadv = arm_pattern(pat, patline)
                  pat = ""; body = ""; state = "bodystart"; continue
                }
                if (ch ~ /[([{]/) depth++
                else if (ch ~ /[])}]/) depth--
                if (pat == "" && ch ~ /[[:space:]]/) continue
                if (pat == "") patline = i
                pat = pat ch
                continue
              }
              if (state == "bodystart") {
                if (ch ~ /[[:space:]]/) continue
                if (ch == "{") { state = "block"; depth = 1; body = body ch; continue }
                state = "expr"; depth = 0
              }
              if (state == "aftblock") {
                if (ch ~ /[[:space:]]/) continue
                if (isadv) { done = 1; break }
                state = "pat"; depth = 0
                if (ch == ",") continue
                j--; continue
              }
              body = body ch
              if (ch ~ /[([{]/) depth++
              else if (ch ~ /[])}]/) {
                depth--
                if (state == "block" && depth == 0) { state = "aftblock"; continue }
                if (state == "expr" && depth < 0) { done = 1; break }
              }
              if (state == "expr" && depth == 0 && ch == ",") {
                if (isadv) { done = 1; break }
                state = "pat"; continue
              }
            }
            if (state == "pat" && pat != "") pat = pat " "
            if (state != "pat") body = body " "
          }
          if (!advarm) { out("the Role::Adversary arm is not an arm of `match role {` in decide_loaded_cited"); exit rc }
          if (advarm != advl) out("the Role::Adversary arm is not an arm of `match role {` (line " ln[advl] ")")
          if (word(body, "req") || word(body, "class") || index(body, "Class::") || index(body, "class_of(") || word(body, "if") || word(body, "match") || index(body, "permit"))
            out("the Role::Adversary arm must decide without reading the request or its class")
          exit rc
        }
      ' <<<"$d" || failed=1
    fi
  fi
fi

if [ -n "$binding_lexed" ]; then
  for fn in role_for as_subject_bindings entries; do
    if ! b="$(defs "$binding_lexed" "$fn")"; then
      fail "cannot extract $fn: $(grep '^DEF-ERROR' <<<"$b" || true)"
      continue
    fi
    if [ -z "$b" ]; then
      fail "fn $fn not found in the production half of binding.rs"
      continue
    fi
    FN="$fn" awk -F '\t' '
      function tok(s, w) { return s ~ ("(^|[^A-Za-z0-9_])" w "([^A-Za-z0-9_]|$)") }
      function out(m) { print "FAIL: " m; rc = 1 }
      {
        k = $1; t = $0; sub(/^[^\t]*\t[^\t]*\t/, "", t); $3 = t
        if (!(k in seen)) { seen[k] = 1; order[++nk] = k }
        if (index($3, "#[")) attr[k] = $2
        if (tok($3, "CONTAINED") && !(k in c)) c[k] = $2
        if (tok($3, "BINDS") && !(k in b)) b[k] = $2
      }
      END {
        f = ENVIRON["FN"]
        if (!(1 in c) && !(1 in b)) out(f " reads neither CONTAINED nor BINDS")
        for (j = 1; j <= nk; j++) {
          k = order[j]
          if (!(k in c) && !(k in b)) continue
          if (k in attr) out("an attribute inside " f " cannot be read lexically (line " attr[k] ")")
          if ((k in b) && (!(k in c) || c[k] + 0 >= b[k] + 0)) out("CONTAINED must be read before BINDS in " f)
        }
        exit rc
      }
    ' <<<"$b" || failed=1
  done
fi

if [ "$failed" -ne 0 ]; then
  exit 1
fi
echo "containment-ordering: ok"
