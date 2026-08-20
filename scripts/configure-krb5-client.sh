#!/usr/bin/env bash
#
# Blinky lab - a krb5.conf that names the realm, on a domain-joined client.
#
#     sudo bash configure-krb5-client.sh --realm BLINKY.LAB --kdc by-dc01.blinky.lab
#     sudo bash configure-krb5-client.sh --anchors /path/to/chain.pem
#
# realmd joins a machine and leaves /etc/krb5.conf as the stock MIT sample -
# ATHENA.MIT.EDU, Stanford, CMU - with default_realm patched in and nothing
# else. kinit still works, because a principal carries its own realm. Anything
# that has to work the realm out from a *hostname* does not:
#
#   dns_lookup_realm sends the library up the domain tree looking for a
#   _kerberos TXT record - _kerberos.by-dc01.blinky.lab, _kerberos.blinky.lab,
#   _kerberos.lab - and the ones nobody answers cost five seconds each, twice.
#
# The visible failure was a domain login at the console: the password was
# accepted and then the session was refused a minute later. SSSD's ad access
# provider reads GPOs from SYSVOL over SMB, SMB needs a service ticket for
# cifs/<dc>, that needs the hostname mapped to a realm, and the mapping was
# being asked of DNS. gpo_child timed out, and PAM turned that into
#
#     pam_sss(gdm-password:account): Access denied for user X: 4 (System error)
#
# which names neither Kerberos nor DNS.
#
# So [domain_realm] is spelled out and dns_lookup_realm turned off. The KDC is
# still found by SRV record - that part works and is worth keeping.
#
# --anchors also sets up PKINIT, which is what the smart cards are for. Without
# pkinit_anchors the client refuses its own KDC's certificate, and the error it
# gives - "No pkinit_anchors supplied" - is reported even when the real problem
# was an ordinary mistyped password.

set -euo pipefail

REALM="${REALM:-}"
KDC=""
ANCHORS=""
PKCS11="${PKCS11:-}"

while [[ $# -gt 0 ]]; do
    case "$1" in
        --realm) REALM="$2"; shift 2 ;;
        --kdc) KDC="$2"; shift 2 ;;
        --anchors) ANCHORS="$2"; shift 2 ;;
        --pkcs11) PKCS11="$2"; shift 2 ;;
        *) echo "unknown argument: $1" >&2; exit 2 ;;
    esac
done

[[ $EUID -eq 0 ]] || { echo "Run this with sudo: it writes /etc/krb5.conf." >&2; exit 2; }

# Left to itself, umask can make /etc/krb5.conf root-only, and every user on
# the machine then gets "Permission denied while initializing Kerberos 5
# library" - a message about permissions that reads like one about Kerberos.
# This lab has been bitten by exactly that three times.
umask 022

if [[ -z "$REALM" ]]; then
    REALM="$(hostname -d | tr '[:lower:]' '[:upper:]')"
fi

[[ -n "$REALM" ]] || { echo "No realm given and this host has no domain." >&2; exit 2; }

domain="$(echo "$REALM" | tr '[:upper:]' '[:lower:]')"

if [[ -z "$KDC" ]]; then
    KDC="$(dig +short -t SRV "_kerberos._tcp.$domain" | awk '{print $4}' | sed 's/\.$//' | head -1)"
fi

[[ -n "$KDC" ]] || { echo "No KDC given and no _kerberos._tcp.$domain SRV record." >&2; exit 3; }

say() { printf '\n\033[1m%s\033[0m\n' "$*"; }

# ------------------------------------------------------------------ anchors

pkinit_realm=""
pkinit_libdefaults=""

if [[ -n "$ANCHORS" ]]; then
    [[ -f "$ANCHORS" ]] || { echo "No such file: $ANCHORS" >&2; exit 2; }

    install -d -m 755 /etc/blinky
    install -m 644 "$ANCHORS" /etc/blinky/ca-chain.pem

    pkinit_realm="        pkinit_anchors = FILE:/etc/blinky/ca-chain.pem"

    if [[ -z "$PKCS11" ]]; then
        PKCS11="$(ls /usr/lib/*/opensc-pkcs11.so /usr/lib/*/pkcs11/opensc-pkcs11.so 2>/dev/null | head -1)"
    fi

    if [[ -n "$PKCS11" ]]; then
        pkinit_libdefaults="    pkinit_identities = PKCS11:$PKCS11"
    fi
fi

# ------------------------------------------------------------------- write

say "writing /etc/krb5.conf for $REALM"

[[ -f /etc/krb5.conf && ! -f /etc/krb5.conf.before-blinky ]] &&
    cp /etc/krb5.conf /etc/krb5.conf.before-blinky

cat > /etc/krb5.conf <<EOF
# Written by scripts/configure-krb5-client.sh. The file this replaced is at
# /etc/krb5.conf.before-blinky.

[libdefaults]
    default_realm = $REALM

    # Off, and this is the point of the file. Left on, mapping a hostname to a
    # realm goes looking for _kerberos TXT records up the domain tree, and the
    # queries nobody answers cost five seconds each - which surfaces as an SMB
    # session setup that hangs and a domain login refused a minute after the
    # password was accepted.
    dns_lookup_realm = false

    # On: the KDC is found by SRV record, which is how a domain is supposed to
    # work and which lets a second DC be added without touching this file.
    dns_lookup_kdc = true

    # No reverse lookups when canonicalising a service principal. A lab
    # without a complete reverse zone otherwise builds principals nobody has.
    rdns = false
    dns_canonicalize_hostname = false

    forwardable = true
    proxiable = true
    ccache_type = 4
    kdc_timesync = 1
    fcc-mit-ticketflags = true

    # TCP. A Kerberos ticket for a user in several groups carries a PAC that
    # does not fit a datagram, and the retry over TCP is a delay on every
    # login.
    udp_preference_limit = 0
$pkinit_libdefaults

[realms]
    $REALM = {
        kdc = $KDC
        admin_server = $KDC
        default_domain = $domain
$pkinit_realm
    }

[domain_realm]
    .$domain = $REALM
    $domain = $REALM
EOF

chmod 644 /etc/krb5.conf

# ------------------------------------------------------------------- check

say "checking"

echo "  realm       $REALM"
echo "  kdc         $KDC"
[[ -n "$ANCHORS" ]] && echo "  anchors     /etc/blinky/ca-chain.pem"
[[ -n "$PKCS11" && -n "$ANCHORS" ]] && echo "  pkcs11      $PKCS11"

# The check that matters, and the one that was failing: how long does it take
# to map a host to a realm and ask for a service ticket. Before this file it
# was tens of seconds; it should now be milliseconds.
if command -v kvno >/dev/null && klist -s 2>/dev/null; then
    start=$(date +%s%N)
    if kvno "cifs/$KDC" >/dev/null 2>&1; then
        echo "  cifs ticket $(( ($(date +%s%N) - start) / 1000000 ))ms"
    fi
fi

if systemctl is-active --quiet sssd; then
    say "restarting sssd so it drops what it cached while this was broken"
    systemctl restart sssd
    sleep 3
    systemctl is-active sssd
fi

cat <<EOF

Try a domain login again. If the console still refuses one, the next thing to
read is /var/log/sssd/gpo_child.log - the ad access provider fetches GPOs from
SYSVOL over SMB, and a failure there is reported to PAM as "System error"
rather than as anything about SMB.
EOF
