#!/bin/bash
# Remove a macOS Maknae install. macOS has no native pkg uninstall, so this ships as
# part of the product.
#
# RETAINS /var/log/maknae and /etc/maknae. The audit trail is not the installer's to
# destroy — an uninstall that erases it erases the evidence of everything that ran.
# The enrollment is NOT reusable: its System-keychain items and its published seal.pub
# are deleted, so a reinstall needs `sudo maknae enroll`.
set -euo pipefail
[ "$(id -u)" -eq 0 ] || { echo "must run as root (sudo)" >&2; exit 1; }

RECEIPT="/usr/local/var/db/maknae/install-receipt.plist"

print_rc() { local rc=0; launchctl print "system/$1" >/dev/null 2>&1 || rc=$?; echo "$rc"; }
for LABEL in io.maknae.maknaed io.maknae.maknae-egress; do
    rc="$(print_rc "$LABEL")"
    case "$rc" in
        113) continue ;;
        0) : ;;
        *) echo "maknae: cannot tell whether $LABEL is loaded (launchctl print exit $rc) — refusing to uninstall" >&2
           exit 1 ;;
    esac
    launchctl bootout "system/${LABEL}" || :
    for _ in 1 2 3 4 5 6 7 8 9 10; do
        sleep 0.5
        rc="$(print_rc "$LABEL")"
        [ "$rc" != 113 ] || break
    done
    [ "$rc" = 113 ] || {
        echo "maknae: $LABEL is still loaded after bootout (launchctl print exit $rc) — refusing to uninstall" >&2
        exit 1
    }
done

# Clear our own `launchctl disable` so the external disabled database is not left
# holding an entry for a label we removed — it survives reboots and would silently
# suppress a later reinstall.
for LABEL in io.maknae.maknaed io.maknae.maknae-egress; do
    launchctl enable "system/${LABEL}" 2>/dev/null || :
    rm -f "/Library/LaunchDaemons/${LABEL}.plist"
done

rm -f /usr/local/bin/maknaed /usr/local/bin/maknae /usr/local/bin/maknae-egress
rm -rf /usr/local/var/run/maknae /usr/local/var/log/maknae /usr/local/share/maknae
rm -rf /usr/local/var/run/maknae-egress /usr/local/var/log/maknae-egress
rm -rf /usr/local/lib/maknae

# Before the accounts go: the ACE names _maknae-egress and must still resolve.
chmod -a "user:_maknae-egress allow list,search" /etc/maknae 2>/dev/null || :
ace_left=false
if [ -e /etc/maknae ]; then
    if ! led="$(ls -led /etc/maknae)"; then
        ace_left=true
    elif grep -Eqx ' *[0-9]+: user:_maknae-egress allow list,search' <<<"$led"; then
        ace_left=true
    elif grep -Eq '^ *[0-9]+: user:[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12} ' <<<"$led"; then
        ace_left=true
    fi
fi

kc_left=""
for s in io.maknae.maknaed io.maknae.maknae-egress; do
    rc=0
    security delete-generic-password -a secret-id -s "$s" /Library/Keychains/System.keychain >/dev/null 2>&1 || rc=$?
    [ "$rc" -ne 44 ] || [ -f /Library/Keychains/System.keychain ] || rc="44, no System keychain file"
    case "$rc" in
        0|44) : ;;
        *) echo "WARNING: could not delete the $s keychain item (exit $rc)" >&2
           kc_left="$kc_left $s" ;;
    esac
done

SEAL_PUB_DIR="/Library/Application Support/Maknae/pki"
rm -f "$SEAL_PUB_DIR/seal.pub" 2>/dev/null || :
rmdir "$SEAL_PUB_DIR" "${SEAL_PUB_DIR%/pki}" 2>/dev/null || :
seal_left=false
[ ! -e "$SEAL_PUB_DIR/seal.pub" ] || seal_left=true

# --- accounts: only the ones WE created ------------------------------------
# TWO conditions, not one. An id match alone is NOT proof the account is ours:
# preinstall's ensure_* returns the EXISTING id when the record was already present,
# so the receipt would record an id merely OBSERVED and the id would match — and we
# would delete a pre-existing `_maknae` this installer never created. The
# CreatedByUs booleans are the actual record of what we allocated.
receipt_val() { plutil -extract "$1" raw -o - "$RECEIPT" 2>/dev/null; }
if [ -f "$RECEIPT" ]; then
    for quad in "_maknae:MaknaeUID:MaknaeGID:Maknae" \
                "_maknae-egress:MaknaeEgressUID:MaknaeEgressGID:MaknaeEgress"; do
        name="${quad%%:*}"; r="${quad#*:}"; ukey="${r%%:*}"; r="${r#*:}"
        gkey="${r%%:*}"; pfx="${r#*:}"
        # `plutil -extract <missing-key>` exits 1. Without these fallbacks a receipt
        # from an older build would abort under `set -e` AFTER the plist, binaries
        # and /usr/local/share were removed but BEFORE accounts and pkgutil
        # --forget. Half-torn-down is worse than either end state.
        want_u="$(receipt_val "$ukey" || true)";  want_g="$(receipt_val "$gkey" || true)"
        mine_u="$(receipt_val "${pfx}UIDCreatedByUs" || echo false)"
        mine_g="$(receipt_val "${pfx}GIDCreatedByUs" || echo false)"
        have_u="$(dscl . -read "/Users/$name" UniqueID 2>/dev/null | awk '{print $2}')" || true
        have_g="$(dscl . -read "/Groups/$name" PrimaryGroupID 2>/dev/null | awk '{print $2}')" || true
        if [ "$mine_u" != "true" ]; then
            echo "KEEP: /Users/$name pre-existed this install — not ours to delete" >&2
        elif [ -n "${have_u:-}" ] && [ "$have_u" = "$want_u" ]; then
            dscl . -delete "/Users/$name" || :
        elif [ -n "${have_u:-}" ]; then
            echo "KEEP: /Users/$name has uid $have_u, receipt says $want_u — re-numbered, leaving it" >&2
        fi
        if [ "$mine_g" != "true" ]; then
            echo "KEEP: /Groups/$name pre-existed this install — not ours to delete" >&2
        elif [ -n "${have_g:-}" ] && [ "$have_g" = "$want_g" ]; then
            dscl . -delete "/Groups/$name" || :
        elif [ -n "${have_g:-}" ]; then
            echo "KEEP: /Groups/$name has gid $have_g, receipt says $want_g — re-numbered, leaving it" >&2
        fi
    done
    # The `maknae` OPERATOR group is deliberately left alone: an operator may have
    # been added to it by hand and other tooling may rely on it.
    rm -f "$RECEIPT"; rmdir /usr/local/var/db/maknae 2>/dev/null || :
else
    echo "WARNING: no receipt at $RECEIPT — accounts NOT removed (cannot prove they are ours)." >&2
fi

for pkgid in io.maknae.daemon io.maknae.cli; do
    pkgutil --pkgs | grep -qx "$pkgid" && pkgutil --forget "$pkgid" || :
done

# Clear append-only so the operator CAN remove the trail if they choose to.
chflags nouappnd /var/log/maknae/audit.jsonl 2>/dev/null || :

echo "RETAINED: /var/log/maknae and /etc/maknae; remove by hand for a full teardown."
[ "$ace_left" = false ] || echo "FAILED: /etc/maknae still carries, or could not be read back for, the deputy's ACE or an orphaned user:<UUID> ACE" >&2
[ -z "$kc_left" ] || echo "FAILED: System-keychain item(s) remain:$kc_left" >&2
[ "$seal_left" = false ] || echo "FAILED: $SEAL_PUB_DIR/seal.pub remains" >&2
if [ -n "$kc_left" ] || [ "$ace_left" != false ] || [ "$seal_left" != false ]; then
    exit 1
fi
echo "Removed."
