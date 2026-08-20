#!/usr/bin/env bash
#
# Blinky lab - join a Linux machine to the domain.
#
#     sudo bash join-lab.sh 172.16.1.10
#
# For every machine in the lab that is not the domain controller: the Docker
# host, the Ubuntu client, anything added later. Run it before installing
# anything else on the box.
#
# It does the two things that make a domain join fail in ways that read like
# something else entirely, and then the join itself.
#
#   DNS   A member that resolves the realm through the house router cannot find
#         the SRV records the join looks for. The failure reads like a network
#         problem and is a name-resolution one.
#
#   Time  Kerberos rejects a skew over five minutes and says nothing about
#         clocks when it does. Both machines sync to the DC, which is the only
#         clock in the lab that has to be right.

set -euo pipefail

DC_IP="${1:-}"
REALM="${REALM:-BLINKY.LAB}"

say() { printf '\n\033[1m%s\033[0m\n' "$*"; }

[[ $EUID -eq 0 ]] || { echo "Run this with sudo." >&2; exit 2; }

if [[ -z "$DC_IP" ]]; then
    echo "usage: sudo bash join-lab.sh <domain controller address>" >&2
    exit 2
fi

realm_lower="$(echo "$REALM" | tr '[:upper:]' '[:lower:]')"

say "1/5  packages"

apt-get update -qq
DEBIAN_FRONTEND=noninteractive apt-get install -y -qq \
    realmd sssd sssd-tools adcli krb5-user samba-common-bin \
    oddjob oddjob-mkhomedir packagekit chrony dnsutils >/dev/null

say "2/5  dns via the domain controller"

mkdir -p /etc/systemd/resolved.conf.d
cat > /etc/systemd/resolved.conf.d/blinky-lab.conf <<EOF
[Resolve]
DNS=$DC_IP
Domains=~$realm_lower
EOF

systemctl restart systemd-resolved

# Checked rather than assumed: everything below depends on this working, and a
# failure here is cheap to explain and expensive to discover later.
if ! host -t SRV "_ldap._tcp.$realm_lower" >/dev/null 2>&1; then
    cat >&2 <<EOF

The realm's SRV records do not resolve through $DC_IP.

    host -t SRV _ldap._tcp.$realm_lower

Until that answers, a join will fail with something that sounds like a network
fault. Check that the DC is up and that its own DNS is serving the realm.
EOF
    exit 4
fi

say "3/5  time from the domain controller"

# The DC is the lab's clock. Not the pool: two sources that disagree by six
# minutes fail Kerberos on one machine and not the other, which is a miserable
# thing to chase.
cat > /etc/chrony/conf.d/blinky-lab.conf <<EOF
server $DC_IP iburst prefer
EOF

systemctl restart chrony
sleep 2
chronyc makestep >/dev/null 2>&1 || true
chronyc sources 2>/dev/null | tail -3 || true

say "4/5  join $REALM"

if realm list 2>/dev/null | grep -q "$realm_lower"; then
    echo "already joined"
elif [[ ! -t 0 ]]; then
    # Piped in, so this can run unattended:
    #
    #     ssh dc 'sudo sed -n "s/^password *//p" /root/blinky-lab-dc.txt' |
    #         ssh member 'sudo bash join-lab.sh 172.16.1.10'
    #
    # The value goes from one root-only file into one command and is never
    # echoed, never stored here, and never reaches a scrollback.
    if ! realm join --user=Administrator --unattended "$realm_lower"; then
        echo "The unattended join was refused. Run it by hand:" >&2
        echo "    sudo realm join --user=Administrator $realm_lower" >&2
        exit 5
    fi
else
    echo "Administrator's password for $REALM (from /root/blinky-lab-dc.txt on the DC):"
    realm join --user=Administrator "$realm_lower"
fi

# Home directories on first login, and login without typing the realm every
# time. Neither is required to join and both are required to be usable.
pam-auth-update --enable mkhomedir >/dev/null 2>&1 || true
sed -i 's/^use_fully_qualified_names = True/use_fully_qualified_names = False/' \
    /etc/sssd/sssd.conf 2>/dev/null || true
systemctl restart sssd

say "5/5  check"

realm list | head -8

echo
echo "A domain user, resolved through sssd:"
id "Administrator@$realm_lower" 2>&1 | head -2 || true

cat <<EOF

Joined. What this machine still needs depends on what it is:

  the Docker host   ./scripts/dev-certs.sh --force --host \$(hostname -f)
                    docker compose up -d --build

  a client          the agent, and for Linux that is patch 0017 - the agent
                    talks to readers through winscard.dll and does not run here
                    yet. A Windows client takes the MSI from scripts/build-msi.sh.
EOF
