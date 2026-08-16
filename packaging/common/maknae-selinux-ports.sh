#!/bin/bash
# Label the operator's Vault TCP port with maknae_vault_port_t so maknaed_t may
# name_connect to it under SELinux enforcement. Without this the daemon's
# connect to Vault is denied and it cannot AppRole-auth.
#
#   maknae-selinux-ports.sh add    <port>   (default 8200)
#   maknae-selinux-ports.sh remove <port>
set -euo pipefail
action="${1:-add}"
port="${2:-8200}"
command -v semanage >/dev/null || {
    echo "semanage not found (install policycoreutils-python-utils)" >&2
    exit 1
}
case "$action" in
    add)
        # Try to add; if the port is already defined, only MODIFY it when it is
        # unlabeled-by-us — never clobber a foreign policy's label on that port
        # (e.g. a base type on 443). `semanage port -m` keys on (proto,port) and
        # ignores the current -t, so an unconditional -m would reassign it.
        if semanage port -a -t maknae_vault_port_t -p tcp "$port" 2>/dev/null; then
            :
        elif semanage port -l | awk '$1=="maknae_vault_port_t"' | grep -qw "$port"; then
            :  # already ours — idempotent no-op
        else
            owner=$(semanage port -l | awk -v p="$port" '$2=="tcp" { n=split($3,a,", "); for(i=1;i<=n;i++) if(a[i]==p) print $1 }' | head -1)
            echo "ERROR: tcp/$port is already labeled '${owner:-unknown}', not maknae_vault_port_t." >&2
            echo "       Refusing to reassign a foreign label. Choose an unlabeled Vault port." >&2
            exit 3
        fi
        ;;
    remove)
        # is-ours guard: `semanage port -d` keys on (proto,port) and ignores -t,
        # so only delete if the label is actually maknae_vault_port_t — never
        # clobber a foreign local customization on the same port.
        if semanage port -l | awk '$1=="maknae_vault_port_t"' | grep -qw "$port"; then
            semanage port -d -t maknae_vault_port_t -p tcp "$port"
        else
            echo "port $port not labeled maknae_vault_port_t; leaving untouched" >&2
        fi
        ;;
    *)
        echo "usage: $0 {add|remove} <port>" >&2
        exit 2
        ;;
esac
