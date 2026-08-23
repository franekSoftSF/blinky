#!/usr/bin/env bash
#
# Blinky - the edge's TLS certificate, from the CA this installation actually
# uses.
#
#     sudo CA_PASSWORD=... bash issue-edge-cert.sh --host by-cacms.blinky.lab
#     sudo CA_PASSWORD=... bash issue-edge-cert.sh --host cms.example.com --host 10.0.0.5
#
# Replaces what dev-certs.sh produces for the two listeners that face the
# network. dev-certs.sh says of itself that it is not for anything that
# matters, and it is right: it mints a throwaway CA called "Blinky development
# CA" that has nothing to do with the issuing CA every certificate this system
# hands out is chained to. A lab then has two unrelated trust roots, and the
# one protecting the agent's connection is the one nobody manages.
#
# It also writes the chain, not the leaf alone.
#
# nginx sends exactly what ssl_certificate contains. Given a bare leaf from a
# two-tier CA it sends a bare leaf, and every client fails with "unable to
# verify the first certificate" - because the intermediate is missing, not
# because the anchor is untrusted. Adding the anchor to the client's store does
# not help, which is what makes this one expensive to diagnose. The file
# written here is leaf followed by issuing CA: the client supplies the root,
# the server supplies everything between.
#
# Seen with openssl s_client against BY-CACMS:9443.

set -euo pipefail

cd "$(dirname "$0")/.."

CA_DIR="${CA_DIR:-ca}"
OUT_DIR="${OUT_DIR:-certs}"
DAYS="${DAYS:-825}"
PUBLIC_URL="${CA_PUBLIC_URL:-}"
hosts=()

while [[ $# -gt 0 ]]; do
    case "$1" in
        --host) hosts+=("$2"); shift 2 ;;
        --days) DAYS="$2"; shift 2 ;;
        --ca) CA_DIR="$2"; shift 2 ;;
        --out) OUT_DIR="$2"; shift 2 ;;
        --public-url) PUBLIC_URL="$2"; shift 2 ;;
        *) echo "unknown argument: $1" >&2; exit 2 ;;
    esac
done

[[ -f "$CA_DIR/issuing.p12" ]] || {
    echo "No issuing CA in $CA_DIR - nothing to sign with." >&2
    echo "This script is for an installation using Blinky's own CA." >&2
    exit 3
}

[[ -n "${CA_PASSWORD:-}" ]] || {
    echo "CA_PASSWORD is not set, and the issuing key is inside a PKCS#12." >&2
    exit 2
}

# 825 days is the longest a public CA may issue for and the longest several
# clients will accept. Nothing enforces it on a private CA, which is exactly
# why it is worth matching: a certificate that outlives what a browser or a
# .NET client will accept fails on the client and looks like a server fault.
say()  { printf '\n\033[1m%s\033[0m\n' "$*"; }
note() { printf '  %s\n' "$*"; }

work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

# The issuing key, out of the PKCS#12 and into a directory that goes away when
# this exits. It never touches $OUT_DIR, where a stray copy would be readable
# by every container that mounts it.
openssl pkcs12 -in "$CA_DIR/issuing.p12" -passin "pass:$CA_PASSWORD" \
    -nocerts -nodes -out "$work/issuing.key" 2>/dev/null || {
    echo "The issuing PKCS#12 would not open with CA_PASSWORD." >&2
    exit 4
}

# Names. localhost and 127.0.0.1 always, so that a check run on the machine
# itself keeps working, and every name or address given on the command line.
sans=("DNS:localhost" "IP:127.0.0.1")

for h in "${hosts[@]}"; do
    if [[ "$h" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
        sans+=("IP:$h")
    else
        sans+=("DNS:$h")

        # The short name too. A Windows machine reaching a server by its
        # NetBIOS name presents that name for verification, and a certificate
        # that carries only the FQDN is refused for a reason that says nothing
        # about names.
        short="${h%%.*}"
        [[ "$short" != "$h" ]] && sans+=("DNS:$short")
    fi
done

san_list="$(IFS=,; echo "${sans[*]}")"

say "issuing an edge certificate"
note "names: $san_list"

openssl req -newkey rsa:2048 -nodes \
    -keyout "$work/edge.key" -out "$work/edge.csr" \
    -subj "/CN=${hosts[0]:-localhost}/O=Blinky" 2>/dev/null

{
    echo "basicConstraints=critical,CA:FALSE"
    echo "keyUsage=critical,digitalSignature,keyEncipherment"
    echo "extendedKeyUsage=serverAuth"
    echo "subjectKeyIdentifier=hash"
    echo "authorityKeyIdentifier=keyid:always"
    echo "subjectAltName=$san_list"

    # Where somebody checks whether this certificate was revoked. Without it a
    # compromised edge key can only be dealt with by replacing the CA.
    if [[ -n "$PUBLIC_URL" ]]; then
        echo "crlDistributionPoints=URI:$PUBLIC_URL/pki/issuing.crl"
        echo "authorityInfoAccess=caIssuers;URI:$PUBLIC_URL/pki/issuing.crt"
    fi
} > "$work/edge.ext"

openssl x509 -req -in "$work/edge.csr" -days "$DAYS" \
    -CA "$CA_DIR/issuing.crt" -CAkey "$work/issuing.key" -CAcreateserial \
    -out "$work/edge.crt" -extfile "$work/edge.ext" 2>/dev/null

# Leaf then issuer. Order matters: a client reads this as a path and stops at
# the first certificate it cannot follow.
cat "$work/edge.crt" "$CA_DIR/issuing.crt" > "$OUT_DIR/edge.crt"
install -m 640 "$work/edge.key" "$OUT_DIR/edge.key"

note "subject: $(openssl x509 -in "$work/edge.crt" -noout -subject | sed 's/^subject=//')"
note "issuer:  $(openssl x509 -in "$work/edge.crt" -noout -issuer | sed 's/^issuer=//')"
note "expires: $(openssl x509 -in "$work/edge.crt" -noout -enddate | cut -d= -f2-)"

# Verified against the anchor rather than announced. A chain that does not
# build is the whole failure this script exists to prevent, and finding out
# here costs nothing.
if openssl verify -CAfile "$CA_DIR/anchor.crt" -untrusted "$CA_DIR/issuing.crt" \
        "$work/edge.crt" >/dev/null 2>&1; then
    note "chain:   verifies to $CA_DIR/anchor.crt"
else
    echo "  WARNING: this certificate does not chain to $CA_DIR/anchor.crt" >&2
    exit 5
fi
