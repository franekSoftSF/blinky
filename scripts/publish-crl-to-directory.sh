#!/usr/bin/env bash
#
# Blinky - keep the revocation lists in the Samba directory current.
#
#     sudo bash publish-crl-to-directory.sh --url http://by-ca-cms.blinky.lab
#     sudo bash publish-crl-to-directory.sh --url http://... --install-timer
#
# Run on the domain controller. Fetches both lists from the distribution point
# and puts them where the things that read them look.
#
# This exists because a short-lived CRL is only safe if it is republished. The
# issuing CA's list is good for hours, not months, and an expired CRL does not
# fail open - it breaks every chain built under it. A copy written into the
# directory once and never again stops a smart-card logon overnight, and the
# error a client reports is about trust rather than about a stale file.
#
# Three destinations, because three different things read a CRL and none of
# them fetches a URL:
#
#   certificateRevocationList   on the issuing CA's directory object. This is
#   authorityRevocationList     what a domain member checks. The schema makes
#                               both mandatory and rejects them empty.
#   tls crlfile                 what smbd checks, from disk.
#   the KDC's copy              what PKINIT checks, from disk.
#
# Nothing is published unless it parses and is still valid. Replacing a good
# list with a truncated download is the one way this could make things worse
# than doing nothing.

set -euo pipefail

URL=""
REALM="${REALM:-$(hostname -d | tr '[:lower:]' '[:upper:]')}"
INSTALL_TIMER=0
INTERVAL="${INTERVAL:-hourly}"

while [[ $# -gt 0 ]]; do
    case "$1" in
        --url) URL="$2"; shift 2 ;;
        --realm) REALM="$2"; shift 2 ;;
        --interval) INTERVAL="$2"; shift 2 ;;
        --install-timer) INSTALL_TIMER=1; shift ;;
        *) echo "unknown argument: $1" >&2; exit 2 ;;
    esac
done

[[ $EUID -eq 0 ]] || { echo "Run this with sudo: it writes to the directory." >&2; exit 2; }
[[ -n "$URL" ]] || { echo "usage: publish-crl-to-directory.sh --url http://<ca-host>" >&2; exit 2; }

URL="${URL%/}"

command -v samba-tool >/dev/null || { echo "This is not a Samba DC." >&2; exit 3; }

realm_lower="$(echo "$REALM" | tr '[:upper:]' '[:lower:]')"
basedn="DC=${realm_lower//./,DC=}"
services="CN=Public Key Services,CN=Services,CN=Configuration,$basedn"
SAM=/var/lib/samba/private/sam.ldb
tls=/var/lib/samba/private/tls

say() { printf '\n\033[1m%s\033[0m\n' "$*"; }

# ------------------------------------------------------------- install timer

if [[ $INSTALL_TIMER -eq 1 ]]; then
    say "installing the timer"

    install -m 755 "$(readlink -f "$0")" /usr/local/sbin/blinky-publish-crl

    cat > /etc/systemd/system/blinky-crl.service <<EOF
[Unit]
Description=Publish Blinky's revocation lists into the directory
After=samba-ad-dc.service
Wants=network-online.target

[Service]
Type=oneshot
ExecStart=/usr/local/sbin/blinky-publish-crl --url $URL --realm $REALM
EOF

    cat > /etc/systemd/system/blinky-crl.timer <<EOF
[Unit]
Description=Keep Blinky's revocation lists current

[Timer]
OnCalendar=$INTERVAL
# So a controller that was off over the weekend republishes at once rather
# than waiting for the next tick with an expired list in the directory.
Persistent=true
AccuracySec=1min

[Install]
WantedBy=timers.target
EOF

    systemctl daemon-reload
    systemctl enable --now blinky-crl.timer

    echo "  runs $INTERVAL; next: $(systemctl show blinky-crl.timer -p NextElapseUSecRealtime --value)"
fi

# -------------------------------------------------------------------- fetch

say "fetching from $URL"

work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

fetch() {
    local name="$1" out="$2"

    if ! curl -fsS --max-time 30 "$URL/pki/$name" -o "$out"; then
        echo "  $name  could not be fetched" >&2
        return 1
    fi

    # Parsed before it is trusted. A truncated download is still a file, and
    # publishing one would replace a good list with something no client can
    # read - worse than leaving the old one alone.
    if ! openssl crl -in "$out" -inform DER -noout 2>/dev/null; then
        echo "  $name  is not a revocation list" >&2
        return 1
    fi

    local next
    next="$(openssl crl -in "$out" -inform DER -noout -nextupdate | cut -d= -f2)"

    if [[ $(date -d "$next" +%s) -le $(date +%s) ]]; then
        echo "  $name  has already expired ($next) - not publishing it" >&2
        return 1
    fi

    echo "  $name  valid until $next"
    return 0
}

fetch issuing.crl "$work/issuing.crl" || exit 4

# The root's list is optional: a single-tier CA has none, and a two-tier one
# that has not been re-signed yet does not publish it. Its absence is not a
# reason to leave the issuing list stale.
have_root=0
fetch root.crl "$work/root.crl" 2>/dev/null && have_root=1

# --------------------------------------------------------------- to the disk

say "to disk"

install -d -m 755 "$tls"
install -m 644 "$work/issuing.crl" "$tls/issuing.crl"
echo "  $tls/issuing.crl"

if [[ $have_root -eq 1 ]]; then
    install -m 644 "$work/root.crl" "$tls/root.crl"
    echo "  $tls/root.crl"
fi

# smb.conf points at one file. Told once; changing it later is a person's job,
# not this script's.
if ! grep -q "tls crlfile" /etc/samba/smb.conf; then
    cat <<EOF

  smb.conf has no "tls crlfile". Add it under [global] and reload:

      tls crlfile = $tls/issuing.crl
EOF
fi

# ---------------------------------------------------------- to the directory

say "to the directory"

publish() {
    local dn="$1" crl="$2" label="$3"

    if ! ldbsearch -H "$SAM" -b "$dn" -s base dn >/dev/null 2>&1; then
        echo "  $label  no such object yet - run blinky-samba-setup.sh first" >&2
        return 0
    fi

    cat > "$work/change.ldif" <<LDIF
dn: $dn
changetype: modify
replace: certificateRevocationList
certificateRevocationList:: $(base64 -w0 < "$crl")
-
replace: authorityRevocationList
authorityRevocationList:: $(base64 -w0 < "$crl")
LDIF

    if ldbmodify -H "$SAM" "$work/change.ldif" >/dev/null; then
        echo "  $label  published"
    else
        echo "  $label  FAILED" >&2
        return 1
    fi
}

# The issuing CA's own object, wherever it was published under NTAuth, and the
# root's under Certification Authorities. Both are found by name rather than
# assumed, because blinky-samba-setup.sh names them after the certificates.
publish "CN=NTAuthCertificates,$services" "$work/issuing.crl" "NTAuth"

if [[ $have_root -eq 1 ]]; then
    while read -r dn; do
        [[ -n "$dn" ]] || continue
        publish "$dn" "$work/root.crl" "root (${dn%%,*})"
    done < <(ldbsearch -H "$SAM" -b "CN=Certification Authorities,$services" \
                 "(objectClass=certificationAuthority)" dn 2>/dev/null |
             awk '/^dn: /{print substr($0, 5)}')
fi

cat <<EOF

Done. Both lists are on disk and in the directory.

The issuing list is short-lived on purpose, so this has to keep running:

    sudo bash $(basename "$0") --url $URL --install-timer

An expired CRL does not fail open. It breaks every chain built under it, and
the client reports that as a problem with trust.
EOF
