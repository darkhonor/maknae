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
  STRICT="$2" awk '
    BEGIN { q = sprintf("%c", 39); hi = sprintf("%c", 128) }
    cut {
      if (NR == cut + 1) { if ($0 != "mod tests {") { print "LEX-ERROR #[cfg(test)] at line " cut " is not followed by `mod tests {`"; bad = 1; exit } ; next }
      if ($0 ~ /^[[:space:]]*$/) next
      if (last != "") { print "LEX-ERROR code follows the test module at line " NR; bad = 1; exit }
      if ($0 !~ /^[[:space:]]/) last = $0
      next
    }
    /^#\[cfg\(test\)\][[:space:]]*$/ { cut = NR; next }
    ENVIRON["STRICT"] != "" && /^#\[cfg/ { print "LEX-ERROR a column-0 #[cfg outside the test module at line " NR; bad = 1; exit }
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
        start = (i == 1 || substr(line, i - 1, 1) !~ /[A-Za-z0-9_]/)
        if (start && match(substr(line, i), /^[bc]?r#*"/)) {
          print "LEX-ERROR raw string literal (prefix " substr(line, i, RLENGTH - 1) ") at line " NR; bad = 1; exit
        }
        if (c == "\"") { instr = 1; out = out "\""; i++; continue }
        if (c == q) {
          if (d == "\\") {
            j = index(substr(line, i + 3), q)
            if (j == 0) { print "LEX-ERROR char literal at line " NR; bad = 1; exit }
            out = out q q; i += j + 3; continue
          }
          if (d != "" && substr(line, i + 2, 1) == q) { out = out q q; i += 3; continue }
          if (d >= hi) {
            j = index(substr(line, i + 1), q)
            if (j < 2 || j > 5) { print "LEX-ERROR char literal at line " NR; bad = 1; exit }
            out = out q q; i += j + 1; continue
          }
        }
        out = out c; i++
      }
      print NR "\t" out
    }
    END {
      if (bad) exit 2
      if (cut && last != "}") { print "LEX-ERROR the test module does not close at the end of the file"; exit 2 }
      if (instr || depth > 0) { print "LEX-ERROR unterminated string or block comment"; exit 2 }
    }
  ' "$1"
}

defs() {
  FN="$2" awk -F '\t' '
    BEGIN { pat = "(^|[^A-Za-z0-9_])fn[[:space:]]+" ENVIRON["FN"] "[[:space:]]*[(<]" }
    { body = $0; sub(/^[^\t]*\t/, "", body); t = body }
    !inside && match(body, pat) {
      inside = 1; k++; depth = 0; opened = 0; t = substr(body, RSTART); rest = substr(t, 2); start = NR
      if (prev ~ /^[[:space:]]*#!?\[/ || index(substr(body, 1, RSTART), "#[")) { print "DEF-ERROR an attribute above fn " ENVIRON["FN"] " at line " $1; bad = 1; exit }
    }
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
    body !~ /^[[:space:]]*$/ { prev = body }
    END { if (bad) exit 2; if (inside) { print "DEF-ERROR " ENVIRON["FN"] " body never closes"; exit 2 } }
  ' <<<"$1"
}

load() {
  local name="$1" file="$2" strict="$3" out
  lexed=""
  if [ ! -f "$file" ]; then
    fail "$name: $file is missing"
    return
  fi
  if ! out="$(lex "$file" "$strict")"; then
    fail "$name: cannot lex $file: $(grep '^LEX-ERROR' <<<"$out" || true)"
    return
  fi
  if [ -z "$out" ]; then
    fail "$name: the production half of $file is empty"
    return
  fi
  lexed="$out"
}

extract() {
  local name="$1" text="$2" out
  extracted=""
  if ! out="$(defs "$text" "$name")"; then
    fail "cannot extract $name: $(grep '^DEF-ERROR' <<<"$out" || true)"
    return 1
  fi
  extracted="$out"
}

ndefs() { cut -f1 <<<"$1" | sort -u | grep -c . || true; }

load decide.rs "$src/decide.rs" strict
decide_lexed="$lexed"
load binding.rs "$src/binding.rs" strict
binding_lexed="$lexed"
load lib.rs "$src/lib.rs" ""
lib_lexed="$lexed"

if [ -n "$lib_lexed" ]; then
  awk -F '\t' '
    function out(m) { print "FAIL: " m; rc = 1 }
    {
      t = $0; sub(/^[^\t]*\t/, "", t)
      if (t ~ /(^|[^A-Za-z0-9_])use[[:space:]]+(.*[^A-Za-z0-9_])?decide([^A-Za-z0-9_]|$)/) out("lib.rs imports from decide (line " $1 ")")
      while (match(t, /(^|[^A-Za-z0-9_])decide::[a-z_][A-Za-z0-9_]*/)) {
        name = substr(t, RSTART, RLENGTH); sub(/^.*decide::/, "", name)
        if (name == "decide_loaded_cited") cited++
        else if (name != "decide_loaded_with_role") out("lib.rs calls decide::" name "; only decide_loaded_cited and decide_loaded_with_role may be entry points (line " $1 ")")
        t = substr(t, RSTART + RLENGTH)
      }
    }
    END { if (!cited) out("lib.rs never calls decide::decide_loaded_cited("); exit rc }
  ' <<<"$lib_lexed" || failed=1
fi

if [ -n "$decide_lexed" ] && extract decide_loaded_with_role "$decide_lexed"; then
  if [ "$(ndefs "$extracted")" != 1 ]; then
    fail "expected exactly one fn decide_loaded_with_role in the production half of decide.rs"
  elif ! grep -qE '^[[:space:]]*let d = decide_loaded_cited\(lp, principal, req\);[[:space:]]*$' <<<"$(cut -f3- <<<"$extracted")"; then
    fail "decide_loaded_with_role must call decide_loaded_cited(lp, principal, req)"
  fi
fi

if [ -n "$decide_lexed" ] && extract decide_loaded_cited "$decide_lexed"; then
  d="$extracted"
  if [ "$(ndefs "$d")" != 1 ]; then
    fail "expected exactly one fn decide_loaded_cited in the production half of decide.rs, found $(ndefs "$d")"
  else
    awk -F '\t' '
      function word(s, w) { return s ~ ("(^|[^A-Za-z0-9_])" w "([^A-Za-z0-9_]|$)") }
      function out(m) { print "FAIL: " m; rc = 1 }
      function trim(s) { sub(/^[[:space:]]+/, "", s); sub(/[[:space:]]+$/, "", s); return s }
      function norm(s) { gsub(/[[:space:]]+/, " ", s); return trim(s) }
      function arm_pattern(p, line) {
        p = norm(p)
        if (p ~ /^Role::Adversary( if .*)?$/) { advarm = line; return 1 }
        if (p !~ /^Role::(Admin|User|Guest)( ?\| ?Role::(Admin|User|Guest))*( if .*)?$/)
          out("an arm before Role::Adversary must name roles other than Adversary (line " ln[line] ": `" p "`)")
        return 0
      }
      { n++; ln[n] = $2; t = $0; sub(/^[^\t]*\t[^\t]*\t/, "", t); tx[n] = t }
      END {
        for (i = 1; i <= n; i++) {
          t = tx[i]
          if (index(t, "#[")) out("an attribute inside decide_loaded_cited cannot be read lexically (line " ln[i] ")")
          if (t ~ /(^|[^A-Za-z0-9_])match[[:space:]]+role[[:space:]]*\{/) { mr++; mrl = i }
          if (index(t, "role_for(")) { rf++; rfl = i }
          if (t ~ /^[[:space:]]*Role::Adversary[[:space:]]*(if[[:space:]].*)?=>/) { adv++; advl = i }
          if (t ~ /(^|[^A-Za-z0-9_])match[[:space:]]+class([^A-Za-z0-9_]|$)/ && !mcl) mcl = i
          if (t ~ /\|[[:space:]]*(mut[[:space:]]+)?role[[:space:]]*[|,:]/ || t ~ /,[[:space:]]*(mut[[:space:]]+)?role[[:space:]]*(:[^|]*)?\|/ || t ~ /(^|[^A-Za-z0-9_])role[[:space:]]*@/ || t ~ /(^|[^A-Za-z0-9_])role[[:space:]]*=>/)
            out("role is bound by a closure, a pattern or an arm in decide_loaded_cited (line " ln[i] ")")
          if ((t ~ /(^|[^A-Za-z0-9_])let[[:space:]]+([^=]*[^A-Za-z0-9_.])?role([^A-Za-z0-9_]|$)/ || t ~ /^[[:space:]]*role[[:space:]]*=[^=]/) && !index(t, "role_for("))
            out("the role is rebound outside its role_for( resolution in decide_loaded_cited (line " ln[i] ")")
        }
        if (mr != 1) { out("decide_loaded_cited must hold exactly one `match role {`, found " mr + 0); exit rc }
        if (rf != 1) { out("decide_loaded_cited must call role_for( exactly once, found " rf + 0); exit rc }
        if (adv != 1) { out("exactly one Role::Adversary arm in decide_loaded_cited, found " adv + 0); exit rc }
        if (!mcl) { out("decide_loaded_cited holds no `match class`; cannot place the class arms"); exit rc }
        if (trim(tx[mrl]) != "let (verdict, cited) = match role {") out("the `match role {` line must be `let (verdict, cited) = match role {` (line " ln[mrl] ")")
        if (trim(tx[rfl]) != "let role = match lp.roles.role_for(uid, principal.uid) {") out("the role_for( line must be `let role = match lp.roles.role_for(uid, principal.uid) {` (line " ln[rfl] ")")
        if (rfl > mrl) { out("role_for( is called after `match role {` in decide_loaded_cited"); exit rc }
        if (advl >= mcl) out("Role::Adversary must precede every class arm in decide_loaded_cited")
        if (tx[advl] ~ /^[[:space:]]*Role::Adversary[[:space:]]*if[[:space:]]/) out("the Role::Adversary arm in decide_loaded_cited must not carry a guard")

        kern = 0
        for (i = 1; i < rfl; i++) {
          t = tx[i]
          if (index(t, "class_of(") || word(t, "match[[:space:]]+class") || index(t, "Class::") || index(t, "req.action")) {
            if (t ~ /^[[:space:]]*if[[:space:]]+class_of\(&req\.action\.0\)[[:space:]]*==[[:space:]]*Some\(Class::Kernel\)[[:space:]]*\{[[:space:]]*$/ && !kern) kern = i
            else out("only the kernel early return may evaluate a class before role resolution (line " ln[i] ")")
          }
          if (!word(t, "return")) continue
          if (index(t, "return undecided(Verdict::Indeterminate)")) continue
          if (kern && i == kern + 1 && t ~ /^[[:space:]]*return[[:space:]]+undecided\(kernel_decided\(req\)\);[[:space:]]*$/) continue
          out("before role resolution only an Indeterminate or the kernel return may leave decide_loaded_cited (line " ln[i] ")")
        }

        split("Resolution::Role(r) => r,|Resolution::NoRole => {|return undecided(Verdict::NotApplicable {|note: Some(\"\".into()),|})|}|};|let class = class_of(&req.action.0);", allow, "|")
        for (a in allow) between[allow[a]] = 1
        for (i = rfl + 1; i < mrl; i++) {
          t = trim(tx[i])
          if (t == "" || (t in between)) continue
          out("between role resolution and `match role {` only the Resolution arms and `let class = class_of(&req.action.0);` may appear (line " ln[i] ": `" t "`)")
        }

        s = tx[mrl]; match(s, /(^|[^A-Za-z0-9_])match[[:space:]]+role[[:space:]]*\{/)
        from = RSTART + RLENGTH
        depth = 1; closel = 0
        for (i = mrl; i <= n && !closel; i++) {
          s = tx[i]
          for (j = (i == mrl ? from : 1); j <= length(s); j++) {
            ch = substr(s, j, 1)
            if (ch == "{") depth++
            else if (ch == "}" && --depth == 0) { closel = i; break }
          }
        }
        if (!closel || trim(tx[closel]) != "};") out("`match role {` must close with `};` in decide_loaded_cited")
        else {
          want = "Decided {|verdict,|role: Some(role.key()),|cited,|}|}"
          got = ""
          for (i = closel + 1; i <= n; i++) { t = trim(tx[i]); if (t != "") got = got (got == "" ? "" : "|") t }
          if (got != want) out("after `match role {` closes, decide_loaded_cited must end in exactly `Decided { verdict, role: Some(role.key()), cited }`")
        }

        state = "pat"; pat = ""; body = ""; depth = 0; advarm = 0; done = 0
        for (i = mrl; i <= n && !done; i++) {
          s = tx[i]; L = length(s)
          for (j = (i == mrl ? from : 1); j <= L && !done; j++) {
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
        if (!index(body, "Verdict::Deny") || tolower(body) ~ /permit/)
          out("the Role::Adversary arm must be a Verdict::Deny and never a permit")
        if (word(body, "req") || word(body, "class") || index(body, "Class::") || index(body, "class_of(") || word(body, "if") || word(body, "match"))
          out("the Role::Adversary arm must decide without reading the request or its class")
        exit rc
      }
    ' <<<"$d" || failed=1
  fi
fi

if [ -n "$binding_lexed" ]; then
  for fn in role_for as_subject_bindings entries; do
    extract "$fn" "$binding_lexed" || continue
    if [ -z "$extracted" ]; then
      fail "fn $fn not found in the production half of binding.rs"
      continue
    fi
    FN="$fn" awk -F '\t' '
      function trim(s) { sub(/^[[:space:]]+/, "", s); sub(/[[:space:]]+$/, "", s); return s }
      function tok(s, w) { return s ~ ("(^|[^A-Za-z0-9_])" w "([^A-Za-z0-9_]|$)") }
      function out(m) { print "FAIL: " m; rc = 1 }
      {
        k = $1; t = $0; sub(/^[^\t]*\t[^\t]*\t/, "", t)
        if (!(k in cnt)) order[++nk] = k
        cnt[k]++; ln[k, cnt[k]] = $2; tx[k, cnt[k]] = t
      }
      function delegator(k,   i, got, f) {
        f = ENVIRON["FN"]; got = ""
        for (i = 2; i <= cnt[k]; i++) if (trim(tx[k, i]) != "") got = got "\n" trim(tx[k, i])
        return got ~ ("^\nmatch self \\{\n#\\[cfg\\(test\\)\\]\nRoles::File\\([a-z_]+\\) => [^\n]*,\nRoles::Graph\\(g\\) => g\\." f "\\([a-z_, ]*\\),\n\\}\n\\}$")
      }
      END {
        f = ENVIRON["FN"]
        if (f == "role_for") branch = "return Resolution::Role(Role::Adversary);"
        else if (f == "as_subject_bindings") branch = "Some(ADVERSARY.to_string())"
        else branch = "ListedSubject {|uid: Some(uid),|names: claimed,|state: SubjectState::Contained,|}"
        nd = 0; nr = 0
        for (j = 1; j <= nk; j++) {
          k = order[j]
          if (delegator(k)) { nd++; continue }
          nr++
          c = 0; b = 0; nc = 0
          for (i = 1; i <= cnt[k]; i++) {
            t = tx[k, i]
            if (i > 1 && index(t, "#[")) out("an attribute inside " f " cannot be read lexically (line " ln[k, i] ")")
            if (tok(t, "CONTAINED")) { nc++; if (!c) c = i }
            if (tok(t, "BINDS") && !b) b = i
          }
          if (!c && !b) { out(f " reads neither CONTAINED nor BINDS"); continue }
          if (!c || (b && b <= c)) { out("CONTAINED must be read before BINDS in " f); continue }
          if (nc != 1 || trim(tx[k, c]) !~ /^((let role = )|(\} else ))?if self\.graph\.out_edges\((subject|s)\.id, CONTAINED\)\.next\(\)\.is_some\(\) \{$/) {
            out(f " must read CONTAINED once, as `if self.graph.out_edges(…, CONTAINED).next().is_some() {` (line " ln[k, c] ")")
            continue
          }
          depth = 0; endl = 0
          for (i = c; i <= cnt[k] && !endl; i++) {
            s = tx[k, i]
            for (p = (i == c ? index(s, "is_some()") : 1); p <= length(s); p++) {
              ch = substr(s, p, 1)
              if (ch == "{") depth++
              else if (ch == "}" && --depth == 0) { endl = i; break }
            }
          }
          got = ""
          for (i = c + 1; i < endl; i++) { t = trim(tx[k, i]); if (t != "") got = got (got == "" ? "" : "|") t }
          if (!endl || got != branch) out("the CONTAINED branch of " f " must be exactly `" branch "` (line " ln[k, c] ")")
          if (b && b <= endl) out("CONTAINED must be read before BINDS in " f)
        }
        if (nr == 0) out("fn " f " in binding.rs is only the Roles delegator")
        if (nr > 1) out("more than one fn " f " that is not the Roles delegator")
        if (nd > 1) out("more than one Roles delegator for " f)
        exit rc
      }
    ' <<<"$extracted" || failed=1
  done
fi

if [ "$failed" -ne 0 ]; then
  exit 1
fi
echo "containment-ordering: ok"
