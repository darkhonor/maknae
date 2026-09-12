#!/bin/bash
# Remove a macOS Maknae install. macOS has no native pkg uninstall, so this ships as
# part of the product.
#
# RETAINS /var/log/maknae and /etc/maknae. The audit trail is not the installer's to
# destroy — an uninstall that erases it erases the evidence of everything that ran —
# and the config holds an enrollment the operator may be re-using.
set -euo pipefail
[ "$(id -u)" -eq 0 ] || { echo "must run as root (sudo)" >&2; exit 1; }

LABEL="io.maknae.maknaed"
PLIST="/Library/LaunchDaemons/${LABEL}.plist"
RECEIPT="/usr/local/var/db/maknae/install-receipt.plist"

if launchctl print "system/${LABEL}" >/dev/null 2>&1; then
    launchctl bootout "system/${LABEL}" || :
fi
# Clear our own `launchctl disable` so the external disabled database is not left
# holding an entry for a label we removed — it survives reboots and would silently
# suppress a later reinstall.
launchctl enable "system/${LABEL}" 2>/dev/null || :
rm -f "$PLIST"

rm -f /usr/local/bin/maknaed /usr/local/bin/maknae
rm -rf /usr/local/var/run/maknae /usr/local/var/log/maknae /usr/local/share/maknae
rm -rf /usr/local/lib/maknae

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

echo "Removed. RETAINED: /var/log/maknae (audit trail) and /etc/maknae (config)."
echo "Remove them by hand if you intend a full teardown."
exit 0
