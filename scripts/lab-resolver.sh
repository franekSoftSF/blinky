#!/usr/bin/env bash
#
# Blinky lab - point a machine's resolver at the domain controller.
#
#     sudo bash lab-resolver.sh 172.16.5.10
#     sudo bash lab-resolver.sh 172.16.5.10 --realm blinky.lab
#
# Run on anything that has to resolve the realm: the CMS host, a Linux client,
# and the controller itself.
#
# This exists as its own script because the machines that need it cannot all
# reach it any other way. join-lab.sh does the same work, but only for a
# machine being joined - and the CMS host is a Docker host that never joins,
# while the controller is the thing being joined to. Both still have to resolve
# the realm, and on a fresh VMware or cloud image neither does.
#
# What goes wrong without it:
#
#   A public resolver in netplan. The per-link nameserver beats the global one
#   for anything routed over that link, so a perfectly correct
#   /etc/systemd/resolved.conf is read and then ignored. The realm resolves
#   only by luck, reverse lookups go to a resolver that will never answer for
#   RFC 1918 space, and every name canonicalisation waits for a timeout - so
#   the symptom is slowness in things with no visible connection to DNS.
#
#   Seen on all three machines of the 172.16.5.0/24 rebuild, each shipped with
#   8.8.8.8 by the VMware customisation engine.

set -euo pipefail

DC_IP="${1:-}"
shift || true

REALM=""

while [[ $# -gt 0 ]]; do
    case "$1" in
        --realm) REALM="$2"; shift 2 ;;
        *) echo "unknown argument: $1" >&2; exit 2 ;;
    esac
done

[[ $EUID -eq 0 ]] || { echo "Run this with sudo." >&2; exit 2; }

[[ "$DC_IP" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]] || {
    cat >&2 <<'EOF'
usage: lab-resolver.sh <domain-controller-address> [--realm <realm>]

The controller is named by address, not by name: this script runs before the
machine can resolve names, which is the whole reason it runs.
EOF
    exit 2
}

realm_lower="$(echo "${REALM:-$(hostname -d)}" | tr '[:upper:]' '[:lower:]')"

[[ -n "$realm_lower" ]] || {
    echo "No realm: this machine has no domain part and --realm was not given." >&2
    exit 2
}

say()  { printf '\n\033[1m%s\033[0m\n' "$*"; }
note() { printf '  %s\n' "$*"; }

# Is the controller this very machine? Then it resolves through its own Samba
# on the loopback, and the global resolver configuration provision-dc.sh wrote
# is correct as it stands - overwriting it with the machine's own external
# address would work today and break the moment that address changes.
is_self=false
if ip -4 -o addr show scope global | grep -q " ${DC_IP}/"; then
    is_self=true
fi

say "resolver"

if $is_self; then
    note "$DC_IP is this machine - leaving its own resolver configuration alone"
else
    mkdir -p /etc/systemd/resolved.conf.d
    cat > /etc/systemd/resolved.conf.d/blinky-lab.conf <<EOF
[Resolve]
DNS=$DC_IP
Domains=~$realm_lower
EOF
    systemctl restart systemd-resolved
    note "systemd-resolved sends $realm_lower to $DC_IP"
fi

# The per-link nameserver. This is the one that actually decides, and the one
# an image ships wrong.
say "netplan"

link_target="$DC_IP"
changed=false

for plan in /etc/netplan/*.yaml; do
    [[ -f "$plan" ]] || continue

    grep -q 'nameservers:' "$plan" || continue
    grep -A 4 'nameservers:' "$plan" | grep -q "$link_target" && {
        note "$(basename "$plan") already points at $link_target"
        continue
    }

    cp "$plan" "$plan.before-blinky"

    python3 - "$plan" "$link_target" <<'PY' || { note "could not rewrite $plan - check it by hand"; continue; }
import re, sys

path, dc = sys.argv[1], sys.argv[2]
text = open(path, encoding="utf-8").read()

def fix(match):
    head, body = match.group(1), match.group(2)
    indent = re.match(r"\s*", body).group(0)
    return head + indent + "- " + dc + "\n"

new = re.sub(r"(nameservers:\n(?:\s+search:\n(?:\s+- .*\n)+)?\s+addresses:\n)((?:\s+- .*\n)+)",
             fix, text)

if new != text:
    open(path, "w", encoding="utf-8").write(new)
PY

    note "$(basename "$plan") now points at $link_target (copy kept alongside)"
    changed=true
done

# A cloud-init file that still asks for DHCP will hand the link a resolver
# again at the next boot, and it wins or loses purely on how the filenames
# sort. That is not a property worth depending on.
for plan in /etc/netplan/*.yaml; do
    [[ -f "$plan" ]] || continue
    if grep -q 'dhcp4: *true' "$plan" && [[ "$(basename "$plan")" == 50-cloud-init.yaml ]]; then
        note "note: $(basename "$plan") still requests DHCP - a later file overrides it"
        note "      today, but only because of how the names sort"
    fi
done

if $changed; then
    # The addresses are static here, so applying does not move the address this
    # session is running over.
    netplan apply 2>/dev/null || true
    sleep 2
fi

# ------------------------------------------------------------------- check

say "what resolves now"

fail=false

current="$(resolvectl status 2>/dev/null | awk '/Current DNS Server:/ {print $4; exit}')"
note "current resolver  ${current:-unknown}"

if host -t SRV "_ldap._tcp.$realm_lower" >/dev/null 2>&1; then
    note "realm             _ldap._tcp.$realm_lower answers"
else
    note "realm             _ldap._tcp.$realm_lower DOES NOT ANSWER"
    fail=true
fi

# Forwarding, which is a separate thing and fails separately: the realm can
# resolve perfectly while everything else does not, and the first symptom is
# that apt stops working.
if host -t A archive.ubuntu.com >/dev/null 2>&1; then
    note "the internet     forwarding works"
else
    note "the internet     NOT FORWARDING - apt will fail on this machine"
    note "                 check 'dns forwarder' in the controller's smb.conf;"
    note "                 a loopback address there is a dead end"
    fail=true
fi

if $fail; then
    echo
    echo "The resolver is not yet usable. Nothing that follows will work." >&2
    exit 1
fi
