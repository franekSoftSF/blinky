#!/usr/bin/env bash
#
# Blinky lab - a Samba AD DC that forwards another domain's names to that domain's DNS.
#
#     sudo bash scripts/samba-conditional-forwarder.sh --zone ad.digitalworkspace.pl --forwarder 172.16.2.10
#     sudo bash scripts/samba-conditional-forwarder.sh --rollback
#
# Run on the domain controller. Take a snapshot of the VM first: this moves the
# controller's DNS from Samba's internal server to BIND9 with Samba's DLZ module.
#
# Why the move: Samba's internal DNS has one global forwarder and no per-zone
# forwarding. BY-DC01 forwarded everything to 8.8.8.8, which answers
# ad.digitalworkspace.pl with a public wildcard address, so BY-CACMS - which asks
# BY-DC01 - could not reach ADC01 by name, and a trust between the two domains needs
# each to find the other's controllers through SRV records. BIND keeps serving
# blinky.lab out of Samba's database through the DLZ module, and holds a forward zone
# for the other domain.
#
# Written for Ubuntu 24.04 with Samba 4.19 and BIND 9.18. Not yet run: the first run
# is on BY-DC01, and --rollback puts Samba's internal DNS back.

set -euo pipefail

ZONE=""
FORWARDERS=()
UPSTREAM="8.8.8.8"
RECURSION="172.16.0.0/16"
ROLLBACK=0

while [[ $# -gt 0 ]]; do
    case "$1" in
        --zone) ZONE="$2"; shift 2 ;;
        --forwarder) FORWARDERS+=("$2"); shift 2 ;;
        --upstream) UPSTREAM="$2"; shift 2 ;;
        --recursion-from) RECURSION="$2"; shift 2 ;;
        --rollback) ROLLBACK=1; shift ;;
        *) echo "unknown argument: $1" >&2; exit 2 ;;
    esac
done

[[ $EUID -eq 0 ]] || { echo "Run with sudo." >&2; exit 2; }
command -v samba-tool >/dev/null || { echo "This is not a Samba AD DC." >&2; exit 2; }

REALM="$(testparm -s --parameter-name=realm 2>/dev/null | tr '[:upper:]' '[:lower:]')"
[[ -n "$REALM" ]] || { echo "No realm in smb.conf." >&2; exit 2; }

MARK="# blinky: DNS served by BIND9_DLZ"

say() { echo "==> $*"; }

check_dns() {
    local failed=0
    for name in "$REALM SOA" "_ldap._tcp.dc._msdcs.$REALM SRV" "$@"; do
        # shellcheck disable=SC2086
        answer="$(dig @127.0.0.1 $name +short +time=3 +tries=1 2>/dev/null | head -1)"
        printf '  %-55s %s\n' "$name" "${answer:-NO ANSWER}"
        [[ -n "$answer" ]] || failed=1
    done
    return $failed
}

# ------------------------------------------------------------------------ rollback

if [[ $ROLLBACK -eq 1 ]]; then
    say "back to Samba's internal DNS"
    systemctl disable --now named 2>/dev/null || true
    samba_upgradedns --dns-backend=SAMBA_INTERNAL
    sed -i "/^$MARK$/d; /^[[:space:]]*server services = -dns$/d" /etc/samba/smb.conf
    systemctl restart samba-ad-dc
    sleep 5
    check_dns || { echo "Samba's DNS does not answer yet; journalctl -u samba-ad-dc" >&2; exit 1; }
    echo "Done. BIND's configuration is left in /etc/bind and does nothing while named is disabled."
    exit 0
fi

# ------------------------------------------------------------------------ forward

[[ -n "$ZONE" && ${#FORWARDERS[@]} -gt 0 ]] || {
    echo "usage: samba-conditional-forwarder.sh --zone <domain> --forwarder <ip> [--forwarder <ip>]" >&2
    echo "       [--upstream 8.8.8.8] [--recursion-from 172.16.0.0/16] | --rollback" >&2
    exit 2
}

for f in "${FORWARDERS[@]}"; do
    [[ "$f" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]] || { echo "--forwarder is an IPv4 address: $f" >&2; exit 2; }
    dig @"$f" "$ZONE" SOA +short +time=3 +tries=1 >/dev/null 2>&1 \
        && [[ -n "$(dig @"$f" "$ZONE" SOA +short +time=3 +tries=1)" ]] \
        || { echo "$f does not answer for $ZONE - nothing was changed." >&2; exit 3; }
done

backup="/root/samba-dns-before-bind.$(date +%Y%m%d-%H%M%S)"
say "backup in $backup"
mkdir -p "$backup"
cp -a /etc/samba/smb.conf "$backup/"
[[ -d /etc/bind ]] && cp -a /etc/bind "$backup/"
samba-tool domain backup offline --targetdir="$backup" >/dev/null

say "bind9"
DEBIAN_FRONTEND=noninteractive apt-get install -y -q bind9 bind9utils dnsutils >/dev/null

# samba_upgradedns picks the DLZ module for the BIND it finds, so BIND is installed
# first. It also writes the keytab BIND uses to accept Kerberos-signed updates.
say "samba_upgradedns --dns-backend=BIND9_DLZ"
samba_upgradedns --dns-backend=BIND9_DLZ

cat > /etc/bind/named.conf.options <<EOF
// Written by Blinky's samba-conditional-forwarder.sh.
options {
    directory "/var/cache/bind";
    listen-on-v6 { none; };

    // Domain members update their own records, signed with Kerberos.
    tkey-gssapi-keytab "/var/lib/samba/bind-dns/dns.keytab";
    minimal-responses yes;

    // The lab's networks may recurse through this controller; nobody else may.
    allow-query { any; };
    allow-recursion { 127.0.0.1; $RECURSION; };

    forwarders { $UPSTREAM; };

    // A private zone under a public, signed parent fails validation once forwarded:
    // digitalworkspace.pl is public, ad.digitalworkspace.pl is not.
    dnssec-validation no;
};
EOF

forwarders="$(printf '%s; ' "${FORWARDERS[@]}")"

cat > /etc/bind/named.conf.local <<EOF
// Written by Blinky's samba-conditional-forwarder.sh.

// This controller's own zones, from Samba's database.
include "/var/lib/samba/bind-dns/named.conf";

// Another domain's names, from that domain's DNS and from nowhere else.
zone "$ZONE" {
    type forward;
    forward only;
    forwarders { $forwarders};
};
EOF

named-checkconf || { echo "named-checkconf refused the configuration; $backup has what was there." >&2; exit 4; }

say "Samba stops serving DNS"
if ! grep -q "^[[:space:]]*server services = -dns$" /etc/samba/smb.conf; then
    sed -i "/^\[global\]/a $MARK\n\tserver services = -dns" /etc/samba/smb.conf
fi

systemctl restart samba-ad-dc
systemctl enable named >/dev/null 2>&1
systemctl restart named
sleep 5

say "checks"
if ! check_dns "$ZONE SOA"; then
    echo >&2
    echo "Something does not answer. journalctl -u named -n 50 first - an AppArmor denial on" >&2
    echo "/var/lib/samba/bind-dns is the usual one - and --rollback to go back." >&2
    exit 1
fi

# The controller registering its own records through BIND proves the keytab and the
# DLZ module end to end, which a lookup does not.
if samba_dnsupdate >/dev/null 2>&1; then
    echo "  samba_dnsupdate                                        ok"
else
    echo "  samba_dnsupdate failed - lookups work, dynamic updates do not; samba_dnsupdate --verbose" >&2
    exit 1
fi

echo
echo "Done. $ZONE goes to ${FORWARDERS[*]}; everything else outside $REALM to $UPSTREAM."
