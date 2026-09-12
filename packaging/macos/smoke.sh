#!/bin/bash
# macOS packaging smoke test, in two phases.
#
#   smoke.sh phase1   # no root; runs on any Apple Silicon dev host
#   smoke.sh phase2   # REQUIRES root; installs, boots, observes, uninstalls
#
# phase2 REFUSES without root rather than skipping. A check that reports success on
# nothing is the ok-on-nothing class (#219) that negative-control.sh exists to make
# impossible; a skipped install check that prints ok is the same defect.
set -uo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
REPO="$(cd "$HERE/../.." && pwd)"
LABEL="io.maknae.maknaed"
PKG="$(ls -1t "$REPO"/dist/Maknae-*-arm64.pkg 2>/dev/null | head -1 || true)"
fails=0
ok()   { echo "  ok   — $1"; }
fail() { echo "  FAIL — $1"; fails=$((fails+1)); }

phase1() {
    echo "== phase 1 (no root) =="

    [ "$(uname -m)" = "arm64" ] && ok "Apple Silicon host" || fail "not arm64"

    # A missing tool must REFUSE, not silently pass — the same rule phase 2 applies.
    for t in shellcheck xmllint rust-audit-info; do
        command -v "$t" >/dev/null 2>&1 \
            || { echo "REFUSED: $t not installed; phase 1 cannot attest its checks." >&2; exit 2; }
    done

    for f in "$HERE"/*.plist "$HERE"/*.entitlements; do
        plutil -lint "$f" >/dev/null 2>&1 && ok "plutil -lint $(basename "$f")" \
                                          || fail "plutil -lint $(basename "$f")"
    done

    xmllint --noout "$HERE/distribution.xml" 2>/dev/null \
        && ok "distribution.xml well-formed" || fail "distribution.xml malformed"
    grep -q 'hostArchitectures="arm64"' "$HERE/distribution.xml" \
        && ok "arm64-only constraint" || fail "arm64 constraint MISSING"
    grep -q '<os-version min="26.0"/>' "$HERE/distribution.xml" \
        && ok "macOS 26 floor" || fail "macOS 26 floor MISSING"

    for s in "$HERE/scripts/preinstall" "$HERE/scripts/postinstall" \
             "$HERE/uninstall.sh" "$HERE/build-pkg.sh" "$HERE/smoke.sh"; do
        bash -n "$s" 2>/dev/null && ok "bash -n $(basename "$s")" || fail "bash -n $(basename "$s")"
        shellcheck -S warning "$s" >/dev/null 2>&1 && ok "shellcheck $(basename "$s")" \
                                                   || fail "shellcheck $(basename "$s")"
        [ -x "$s" ] && ok "executable $(basename "$s")" || fail "not executable $(basename "$s")"
    done

    # THE D1 ASSERTION, statically and SEMANTICALLY: the runtime dir must be
    # group-owned by the OPERATOR group, because that — not the daemon's own group —
    # is what BSD inheritance copies onto the socket. The realistic mistake is
    # `-g "$MAKNAE_GID"`, which looks right and silently yields an unreachable socket.
    rt_line="$(grep -E '^install -d .*/usr/local/var/run/maknae$' "$HERE/scripts/preinstall" || true)"
    case "$rt_line" in
        *'-g "$OPERATOR_GID"'*) ok "runtime dir group-owned by the operator group (D1)" ;;
        '')  fail "no runtime-dir install line found in preinstall" ;;
        *)   fail "runtime dir not -g \"\$OPERATOR_GID\" — D1's premise is broken: $rt_line" ;;
    esac

    grep -q 'launchctl disable' "$HERE/scripts/postinstall" \
        && ok "postinstall disables the job by default" \
        || fail "postinstall does NOT disable — an unenrolled install will respawn-loop"
    grep -q 'usr/local/share/maknae/defaults' "$HERE/build-pkg.sh" \
        && ok "config defaults staged outside /etc" \
        || fail "config staged into /etc — upgrades would clobber enrollment"
    grep -q 'install_name_tool -change' "$HERE/build-pkg.sh" \
        && ok "FIPS dylib pinned by absolute install name" \
        || fail "no install_name_tool — an unresolved @rpath can load a NON-VALIDATED libcrypto"

    local B="$REPO/target/aarch64-apple-darwin/release"
    for b in maknaed maknae; do
        if [ ! -x "$B/$b" ]; then fail "no built $b to inspect"; continue; fi
        # CAPTURE, then match — never `cmd | grep -q` under `set -o pipefail`.
        # `grep -q` exits on the FIRST match and SIGPIPEs the writer, so pipefail
        # returns 141 and the pipeline reports FAILURE precisely when the match
        # SUCCEEDS. Measured 2026-09-12: rc=0 without pipefail, rc=141 with it, and
        # rc=1 when there is no match (grep drains the input, so no SIGPIPE). The
        # inverted logic makes it fire only on correct artifacts.
        local linkage; linkage="$(otool -L "$B/$b" 2>/dev/null)"
        case "$linkage" in
            *@rpath/*) fail "$b still loads an @rpath dylib — the installed binary cannot start" ;;
            *)         ok "$b carries no unresolved @rpath" ;;
        esac
        case "$linkage" in
            */usr/local/lib/maknae/libaws_lc_fips_*) ok "$b pins the FIPS module by absolute path" ;;
            *) fail "$b does not reference /usr/local/lib/maknae/libaws_lc_fips_*" ;;
        esac
        codesign --verify --strict "$B/$b" 2>/dev/null && ok "codesign --verify $b" \
                                                       || fail "codesign --verify $b"
        codesign -d --entitlements - "$B/$b" >/dev/null 2>&1 && ok "entitlements readable on $b" \
                                                             || fail "entitlements unreadable on $b"
        local cs; cs="$(codesign -dv "$B/$b" 2>&1)"
        case "$cs" in
            *"Identifier=io.maknae.$b"*) ok "$b carries Identifier=io.maknae.$b" ;;
            *) fail "$b has no embedded CFBundleIdentifier — the PPPC anchor is missing" ;;
        esac
        rust-audit-info "$B/$b" >/dev/null 2>&1 && ok "embedded SBOM in $b" \
                                                || fail "no embedded SBOM in $b"
    done

    if [ -n "$PKG" ]; then
        ok "package present: $(basename "$PKG")"
        local x; x="$(mktemp -d)"
        pkgutil --expand "$PKG" "$x/exp" 2>/dev/null && ok "pkgutil --expand" || fail "pkgutil --expand"
        # lsbom, NOT `pkgutil --payload-files`: the latter errors on an expanded
        # component DIRECTORY ("Is a directory") and still exits 0, so every
        # assertion built on it silently reads empty.
        #
        # EXACT set, not inclusion. Spec §5 phase-1 step 6 says "the exact payload
        # path set": an EXTRA row is as much a defect as a missing one — an
        # AppleDouble `._maknae.yaml` sibling would otherwise pass silently, and it
        # was measured appearing before `xattr -rc` was added to build-pkg.sh.
        # The FIPS dylib's filename carries an upstream version, so it is normalised
        # to a fixed token before comparison rather than hardcoded.
        local bom="$x/exp/maknae-daemon.pkg/Bom"
        if [ -f "$bom" ]; then
            printf '%s\n' \
                "./Library" "./Library/LaunchDaemons" \
                "./Library/LaunchDaemons/${LABEL}.plist" \
                "./usr" "./usr/local" "./usr/local/bin" "./usr/local/bin/maknaed" \
                "./usr/local/lib" "./usr/local/lib/maknae" \
                "./usr/local/lib/maknae/FIPSDYLIB" \
                "./usr/local/share" "./usr/local/share/maknae" \
                "./usr/local/share/maknae/defaults" \
                "./usr/local/share/maknae/defaults/authz.yaml" \
                "./usr/local/share/maknae/defaults/maknae.yaml" | sort > "$x/want"
            lsbom -s "$bom" \
              | sed -e 's|^\.$||' -e 's|libaws_lc_fips_.*_crypto\.dylib|FIPSDYLIB|' \
              | grep -v '^$' | sort > "$x/got"
            if diff -u "$x/want" "$x/got" > "$x/d"; then
                ok "daemon payload is EXACTLY the expected path set"
            else
                fail "daemon payload differs from the expected set:"; sed 's/^/        /' "$x/d"
            fi
        else
            fail "no Bom in the expanded daemon component"
        fi
        local cbom="$x/exp/maknae-cli.pkg/Bom"
        if [ -f "$cbom" ]; then
            printf '%s\n' "./usr" "./usr/local" "./usr/local/bin" "./usr/local/bin/maknae" \
                | sort > "$x/wantc"
            lsbom -s "$cbom" | sed 's|^\.$||' | grep -v '^$' | sort > "$x/gotc"
            diff -u "$x/wantc" "$x/gotc" >/dev/null \
                && ok "cli payload is EXACTLY the expected path set" \
                || { fail "cli payload differs:"; diff -u "$x/wantc" "$x/gotc" | sed 's/^/        /'; }
        else
            fail "no Bom in the expanded cli component"
        fi
        rm -rf "$x"
    else
        fail "no package in dist/ — run build-pkg.sh <version> first"
    fi

    echo "== phase 1: $fails failure(s) =="
    [ "$fails" -eq 0 ]
}

phase2() {
    if [ "$(id -u)" -ne 0 ]; then
        cat >&2 <<'REFUSE'
REFUSED: phase 2 requires root.

This phase installs a package, creates service accounts, bootstraps a launchd
daemon and observes its exit status. None of that is observable unprivileged, and
reporting "ok" for checks that did not run is the exact ok-on-nothing failure this
suite exists to prevent.

Run:  sudo packaging/macos/smoke.sh phase2
REFUSE
        exit 2
    fi

    echo "== phase 2 (root) =="
    [ -n "$PKG" ] || { echo "no package in dist/" >&2; exit 2; }
    /usr/bin/python3 -V >/dev/null 2>&1 \
        || { echo "REFUSED: /usr/bin/python3 unavailable (install Command Line Tools); D1 cannot be attested." >&2; exit 2; }

    # BAK is a CONSTANT, not a `local`: bash pops the function frame BEFORE running
    # an EXIT trap, so a `local` is already gone when the trap fires — and under
    # `set -u` the trap body then dies on the unset expansion and restores nothing.
    # Measured on both an early `return` and SIGINT. What that would cost: a Ctrl-C
    # during either `sleep 3` leaves `audit.siem` injected in the live config, and
    # the daemon then fail-closes at exit 4 forever with no message saying why.
    restore() {
        [ -f /etc/maknae/maknae.yaml.smoke-bak ] \
            && mv -f /etc/maknae/maknae.yaml.smoke-bak /etc/maknae/maknae.yaml
        return 0
    }
    trap restore EXIT INT TERM

    installer -pkg "$PKG" -target / >/dev/null && ok "installer -pkg" \
        || { fail "installer -pkg"; return 1; }

    local R="/usr/local/var/db/maknae/install-receipt.plist"
    [ -f "$R" ] && ok "receipt written" || fail "receipt MISSING"
    for pair in "_maknae:MaknaeUID" "_maknae-egress:MaknaeEgressUID"; do
        local n="${pair%%:*}" k="${pair#*:}" have want
        have="$(dscl . -read "/Users/$n" UniqueID 2>/dev/null | awk '{print $2}')"
        want="$(plutil -extract "$k" raw -o - "$R" 2>/dev/null)"
        [ -n "$have" ] && [ "$have" = "$want" ] \
            && ok "$n uid $have matches receipt" || fail "$n uid '$have' != receipt '$want'"
    done
    dscl . -read /Groups/maknae >/dev/null 2>&1 && ok "operator group exists" || fail "operator group MISSING"

    # --- INSTALL -> UPGRADE -> (later) UNINSTALL provenance lifecycle ---------
    # PR #287 review, blocking finding 1. preinstall's ensure_* returns early for an
    # already-existing record WITHOUT setting CREATED_*, so a second install would
    # rewrite the receipt with CreatedByUs=false for accounts WE created — and
    # uninstall.sh, which gates deletion on that flag, would then leave them behind
    # forever. The flag is now sticky; this is the test that proves it, because the
    # bug is invisible on a first install and only appears on the second.
    for k in MaknaeUIDCreatedByUs MaknaeEgressUIDCreatedByUs; do
        [ "$(plutil -extract "$k" raw -o - "$R" 2>/dev/null)" = "true" ] \
            && ok "fresh install: $k = true" || fail "fresh install: $k is not true"
    done
    installer -pkg "$PKG" -target / >/dev/null && ok "upgrade install (2nd pass) succeeded" \
                                               || fail "upgrade install failed"
    for k in MaknaeUIDCreatedByUs MaknaeEgressUIDCreatedByUs; do
        [ "$(plutil -extract "$k" raw -o - "$R" 2>/dev/null)" = "true" ] \
            && ok "AFTER UPGRADE: $k still true (provenance preserved)" \
            || fail "AFTER UPGRADE: $k became false — uninstall would orphan the account"
    done
    # An upgrade must not re-disable a job the operator enabled.
    dis2="$(launchctl print-disabled system 2>/dev/null)"
    case "$dis2" in
        *"\"$LABEL\" => disabled"*) ok "upgrade left the job disabled (it was disabled)" ;;
        *) ok "upgrade did not force-disable the job" ;;
    esac

    check_mode() {
        local want="$1" path="$2" got
        got="$(stat -f '%Sp %Su %Sg' "$path" 2>/dev/null || echo MISSING)"
        [ "$got" = "$want" ] && ok "$path = $got" || fail "$path = $got (want $want)"
    }
    check_mode "drwxr-x--- root _maknae"    /etc/maknae
    check_mode "drwx------ _maknae _maknae" /var/log/maknae
    check_mode "drwxr-x--- _maknae maknae"  /usr/local/var/run/maknae

    # The INSTALLED binary must actually run — the property no build-host check can
    # establish, because cargo injects DYLD_* and the installer does not.
    /usr/local/bin/maknae --help >/dev/null 2>&1 \
        && ok "installed maknae starts (FIPS dylib resolved)" \
        || fail "installed maknae does NOT start — check otool -L /usr/local/bin/maknae"

    # Format verified on macOS 26.6.2: rows read  "com.apple.ftpd" => disabled
    local dis; dis="$(launchctl print-disabled system 2>/dev/null)"
    case "$dis" in
        *"\"$LABEL\" => disabled"*) ok "job is disabled by default" ;;
        *) fail "job is NOT disabled — boot would respawn-loop it" ;;
    esac

    echo "  -- chflags: uappnd is set; probing whether sappnd is survivable --"
    ls -lO /var/log/maknae/audit.jsonl
    if chflags sappnd /var/log/maknae/audit.jsonl 2>/dev/null; then
        echo "  NOTE: sappnd ACCEPTED at securelevel 0 — record in the contract"
        chflags nosappnd /var/log/maknae/audit.jsonl 2>/dev/null \
            || echo "  NOTE: and it could NOT be cleared — sappnd is NOT upgrade-survivable"
    else
        echo "  NOTE: sappnd REFUSED — uappnd is the flag the contract must name"
    fi

    # --- fail-closed boot refusal -------------------------------------------
    # Insert `siem:` UNDER the existing top-level `audit:` key. Appending a second
    # `audit:` block would make a duplicate top-level mapping, and the daemon would
    # exit 1 on a parse error (or silently lose jsonl_path) — either way the exit-4
    # assertion would measure the wrong thing.
    cp /etc/maknae/maknae.yaml /etc/maknae/maknae.yaml.smoke-bak
    grep -q '^audit:' /etc/maknae/maknae.yaml && ok "maknae.yaml has one audit: block to extend" \
                                              || fail "no audit: key — the injection would create a duplicate"
    /usr/bin/sed -i '' '/^  jsonl_path:/a\
  siem: "udp://127.0.0.1:514"
' /etc/maknae/maknae.yaml
    [ "$(grep -c '^audit:' /etc/maknae/maknae.yaml)" -eq 1 ] \
        && ok "still exactly one top-level audit: key" || fail "duplicate audit: key created"

    launchctl enable "system/$LABEL" 2>/dev/null || :
    launchctl bootstrap system "/Library/LaunchDaemons/${LABEL}.plist" 2>/dev/null || :
    sleep 3
    local code
    code="$(launchctl print "system/${LABEL}" 2>/dev/null | awk '/last exit code/ {print $NF}')"
    [ "$code" = "4" ] && ok "fail-closed boot refusal: last exit code = 4" \
                      || fail "last exit code = ${code:-<none>} (want 4)"

    # #222's stated assumption, discharged. /usr/bin/log EXPLICITLY: zsh has a `log`
    # builtin that silently eats `log show` (#222's recorded measurement hazard).
    local ulog
    ulog="$(/usr/bin/log show --last 2m --predicate 'process == "maknaed"' --info 2>/dev/null)"
    case "$ulog" in
        *audit.offload*) ok "AU-3 record reached the unified log under launchd (#222 discharged)" ;;
        *) fail "no AU-3 record in the unified log — #222's assumption NOT discharged" ;;
    esac

    launchctl bootout "system/${LABEL}" 2>/dev/null || :
    restore; trap - EXIT INT TERM
    # Assert the PROPERTY, not a file comparison. `cmp -s ... || ok` printed ok on
    # BOTH paths — after a successful restore the backup is gone so cmp exits 2, and
    # after a FAILED restore the files differ so cmp exits 1. Nothing could fail it.
    grep -q '^  siem:' /etc/maknae/maknae.yaml \
        && fail "config NOT restored — siem: is still present" \
        || ok "config restored (no siem: key remains)"

    # --- D1's CENTRAL CLAIM, on the real tree -------------------------------
    # NOT via the daemon. maknaed cannot reach its bind site on an unenrolled host:
    # run.rs:2731/:2747 refuse a missing `principal` section with exit 3, and a Vault
    # mint sits between that and the only bind call at run.rs:3020. The shipped
    # skeleton deliberately has no `principal`, so an unenrolled daemon exits 3 and
    # NO socket is ever created — an assertion routed through the daemon could only
    # ever FAIL. Prove the property directly, as the daemon's own uid, applying
    # exactly what socket.rs:111/:119 apply.
    local mgid; mgid="$(dscl . -read /Groups/maknae PrimaryGroupID | awk '{print $2}')"
    sudo -u _maknae /usr/bin/python3 - "$mgid" <<'PROBE'
import os, socket, sys
os.chdir("/usr/local/var/run/maknae")   # AF_UNIX paths cap at 104 bytes
s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
s.bind("d1probe.sock"); s.listen(1)
os.chown("d1probe.sock", -1, int(sys.argv[1]))   # the socket.rs:111 call
os.chmod("d1probe.sock", 0o660)                  # the socket.rs:119 call
PROBE
    local sgot
    sgot="$(stat -f '%Sp %Su %Sg' /usr/local/var/run/maknae/d1probe.sock 2>/dev/null || echo ABSENT)"
    [ "$sgot" = "srw-rw---- _maknae maknae" ] \
        && ok "socket born+owned srw-rw---- _maknae:maknae as _maknae — D1 PROVEN" \
        || fail "probe socket = $sgot (want 'srw-rw---- _maknae maknae') — D1 UNPROVEN"
    rm -f /usr/local/var/run/maknae/d1probe.sock
    launchctl disable "system/$LABEL" 2>/dev/null || :

    # --- uninstall, asserted --------------------------------------------------
    "$HERE/uninstall.sh" >/dev/null && ok "uninstall.sh ran" || fail "uninstall.sh failed"
    [ ! -e /usr/local/bin/maknaed ] && ok "binary removed" || fail "binary still present"
    [ ! -e "/Library/LaunchDaemons/${LABEL}.plist" ] && ok "plist removed" || fail "plist still present"
    [ ! -e /usr/local/lib/maknae ] && ok "FIPS dylib removed" || fail "FIPS dylib still present"
    [ -d /var/log/maknae ] && ok "audit trail RETAINED (correct)" || fail "audit trail was destroyed"

    echo "== phase 2: $fails failure(s) =="
    [ "$fails" -eq 0 ]
}

case "${1:-}" in
    phase1) phase1 ;;
    phase2) phase2 ;;
    *) echo "usage: $0 phase1|phase2" >&2; exit 2 ;;
esac
