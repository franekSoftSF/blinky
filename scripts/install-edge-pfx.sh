#!/usr/bin/env bash
#
# Blinky - give the edge a certificate from the organisation's own CA, delivered
# as a PFX, so browsers and agents on domain machines trust the console and the
# agent listener without anybody importing Blinky's chain first.
#
#     sudo bash scripts/install-edge-pfx.sh --pfx /tmp/blinky-cms.pfx
#     sudo bash scripts/install-edge-pfx.sh --pfx /tmp/blinky-cms.pfx \
#         --password-file /root/pfx.password --host blinky-cms.ad.digitalworkspace.pl
#
# Without --password-file it asks for the password; a password given as an
# argument would sit in ps and in shell history, which is what a file avoids.
#
# Export the PFX from Windows with "Include all certificates in the certification
# path": a bare leaf makes every client report "unable to verify the first
# certificate", a missing intermediate that importing the root does not fix.
#
# Run from the installation, as root. The old pair is kept beside the new one,
# and the edge is restarted, because nginx reads its certificate once at start
# and a replaced file otherwise changes nothing that is running.

set -euo pipefail

start="$PWD"
cd "$(dirname "$0")/.."

# nginx in owasp/modsecurity-crs runs as 101 and the API as 10001 - see
# install-server.sh, which grants the same files the same way.
EDGE_GID="${EDGE_GID:-101}"
BLINKY_GID=10001

PFX="" PASSWORD_FILE="" HOST="" RESTART=1

while [[ $# -gt 0 ]]; do
    case "$1" in
        --pfx) PFX="$2"; shift 2 ;;
        --password-file) PASSWORD_FILE="$2"; shift 2 ;;
        --host) HOST="$2"; shift 2 ;;
        --no-restart) RESTART=0; shift ;;
        *) echo "unknown argument: $1" >&2; exit 2 ;;
    esac
done

absolute() { [[ -z "$1" || "$1" = /* ]] && echo "$1" || echo "$start/$1"; }
PFX="$(absolute "$PFX")"
PASSWORD_FILE="$(absolute "$PASSWORD_FILE")"

[[ -n "$PFX" ]] || {
    echo "usage: install-edge-pfx.sh --pfx <file.pfx> [--password-file <file>] [--host <name>] [--no-restart]" >&2
    exit 2
}
[[ $EUID -eq 0 ]] || { echo "Run with sudo: the edge key is readable by root and nginx alone." >&2; exit 2; }
[[ -f "$PFX" ]] || { echo "No such file: $PFX" >&2; exit 2; }
[[ -f docker-compose.yml && -d certs ]] || { echo "Not an installation: no certs/ beside docker-compose.yml." >&2; exit 2; }

say()  { printf '\n\033[1m%s\033[0m\n' "$*"; }
note() { printf '  %s\n' "$*"; }
fail() { printf '  FAIL  %s\n' "$*" >&2; exit 3; }

# The name the certificate has to carry. The one the current certificate was
# issued for is the one agents were installed against, so it is the default.
if [[ -z "$HOST" && -f certs/edge.crt ]]; then
    HOST="$(openssl x509 -in certs/edge.crt -noout -ext subjectAltName 2>/dev/null |
        grep -o 'DNS:[^,]*' | cut -d: -f2 | tr -d ' ' | grep '\.' | grep -v '^localhost' | head -n1)"
fi
[[ -n "$HOST" ]] || { echo "No --host and no current certificate to take it from." >&2; exit 2; }

umask 077
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

if [[ -n "$PASSWORD_FILE" ]]; then
    [[ -f "$PASSWORD_FILE" ]] || { echo "No such file: $PASSWORD_FILE" >&2; exit 2; }
    head -n1 "$PASSWORD_FILE" | tr -d '\r\n' > "$work/pass"
else
    read -r -s -p "PFX password: " pfx_password; echo
    printf '%s' "$pfx_password" > "$work/pass"
    unset pfx_password
fi

say "1/4  reading $(basename "$PFX")"

# A PFX exported by Windows is often still RC2/3DES, which OpenSSL 3 refuses
# without the legacy provider, and the refusal reads like a wrong password.
pkcs12() { openssl pkcs12 -in "$PFX" -passin "file:$work/pass" "$@"; }
legacy=""
if ! pkcs12 -noout 2>/dev/null; then
    if pkcs12 -legacy -noout 2>/dev/null; then
        legacy="-legacy"
        note "legacy encryption (RC2/3DES) - read with the legacy provider"
    else
        fail "cannot open the PFX - wrong password, or not a PFX"
    fi
fi

pkcs12 $legacy -nocerts -nodes 2>/dev/null | openssl pkey -out "$work/edge.key" 2>/dev/null ||
    fail "the PFX holds no private key - export it with the key"
pkcs12 $legacy -clcerts -nokeys 2>/dev/null | openssl x509 -out "$work/leaf.crt" 2>/dev/null ||
    fail "the PFX holds no certificate for that key"
pkcs12 $legacy -cacerts -nokeys 2>/dev/null |
    sed -n '/-----BEGIN CERTIFICATE-----/,/-----END CERTIFICATE-----/p' > "$work/chain.crt"

note "subject  $(openssl x509 -in "$work/leaf.crt" -noout -subject | sed 's/^subject=//')"
note "issuer   $(openssl x509 -in "$work/leaf.crt" -noout -issuer | sed 's/^issuer=//')"
note "expires  $(openssl x509 -in "$work/leaf.crt" -noout -enddate | sed 's/^notAfter=//')"
note "chain    $(grep -c 'BEGIN CERTIFICATE' "$work/chain.crt" || true) certificate(s) besides the leaf"

say "2/4  checking it is fit for $HOST"

[[ "$(openssl x509 -in "$work/leaf.crt" -noout -pubkey)" == "$(openssl pkey -in "$work/edge.key" -pubout)" ]] ||
    fail "the key does not belong to the certificate"
note "ok    the key belongs to the certificate"

openssl x509 -in "$work/leaf.crt" -noout -checkend 0 >/dev/null || fail "the certificate has expired"
openssl x509 -in "$work/leaf.crt" -noout -checkend 2592000 >/dev/null ||
    note "WARN  it expires within 30 days"
note "ok    it is in date"

# Browsers ignore the CN and have for years; only the SAN counts.
openssl x509 -in "$work/leaf.crt" -noout -checkhost "$HOST" | grep -q 'does match' ||
    fail "$HOST is not in its subject alternative names - browsers and agents will refuse it"
note "ok    it names $HOST"

eku="$(openssl x509 -in "$work/leaf.crt" -noout -ext extendedKeyUsage 2>/dev/null || true)"
if [[ -n "$eku" ]] && ! grep -q 'TLS Web Server Authentication' <<<"$eku"; then
    fail "its extended key usage has no Server Authentication - the template is wrong"
fi
note "ok    it may be used by a server"

if [[ -s "$work/chain.crt" ]]; then
    if openssl verify -partial_chain -CAfile "$work/chain.crt" "$work/leaf.crt" >/dev/null 2>&1; then
        note "ok    the chain in the PFX verifies it"
    else
        fail "the certificates in the PFX do not chain to the leaf"
    fi
else
    note "WARN  no chain in the PFX - clients without the intermediate will not verify it."
    note "      Re-export with \"Include all certificates in the certification path\"."
fi

say "3/4  installing"

stamp="$(date +%Y%m%d-%H%M%S)"
for f in edge.crt edge.key; do
    [[ -f "certs/$f" ]] && cp -p "certs/$f" "certs/$f.before-pfx.$stamp"
done
[[ -f certs/edge.crt.before-pfx.$stamp ]] && note "previous pair kept as certs/edge.*.before-pfx.$stamp"

# Leaf first, then the intermediates: nginx sends the file as the chain. A
# self-signed root in it is dead weight a client ignores, so it is left out.
{
    cat "$work/leaf.crt"
    if [[ -s "$work/chain.crt" ]]; then
        awk '/-----BEGIN CERTIFICATE-----/{n++} {print > (dir "/c" n ".pem")}' dir="$work" "$work/chain.crt"
        for c in "$work"/c*.pem; do
            [[ "$(openssl x509 -in "$c" -noout -subject | sed 's/^subject=//')" == \
               "$(openssl x509 -in "$c" -noout -issuer | sed 's/^issuer=//')" ]] && continue
            openssl x509 -in "$c"
        done
    fi
} > "$work/edge.crt"

install -m 644 -o root -g "$BLINKY_GID" "$work/edge.crt" certs/edge.crt
install -m 640 -o root -g "$EDGE_GID" "$work/edge.key" certs/edge.key
note "certs/edge.crt  leaf and intermediates, readable"
note "certs/edge.key  root and nginx ($EDGE_GID) only"

say "4/4  the edge"

if [[ $RESTART -eq 0 ]]; then
    note "not restarted (--no-restart) - nginx keeps serving the old certificate until it is"
    exit 0
fi

docker compose restart edge >/dev/null
for _ in $(seq 1 20); do
    served="$(echo | openssl s_client -connect 127.0.0.1:8443 -servername "$HOST" 2>/dev/null |
        openssl x509 -noout -fingerprint -sha256 2>/dev/null || true)"
    [[ -n "$served" ]] && break
    sleep 1
done
wanted="$(openssl x509 -in certs/edge.crt -noout -fingerprint -sha256)"

if [[ "$served" == "$wanted" ]]; then
    note "ok    8443 serves the new certificate"
else
    echo "  FAIL  8443 does not serve the new certificate (served: ${served:-nothing})" >&2
    echo "        Back out: cp -p certs/edge.crt.before-pfx.$stamp certs/edge.crt;" \
         "cp -p certs/edge.key.before-pfx.$stamp certs/edge.key; docker compose restart edge" >&2
    exit 4
fi

cat <<EOF

  A connector or an agent that pinned the previous certificate's thumbprint
  has to be given the new one:

      ${wanted#*=}
EOF
