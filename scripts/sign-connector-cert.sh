#!/usr/bin/env bash
#
# Blinky - sign an ADCS connector's client certificate with the agent CA.
#
#     bash scripts/sign-connector-cert.sh --csr hzcs01-connector.csr > hzcs01-connector.crt
#
# Run on the machine holding certs/agent-ca.key - the Docker host. Prints the
# certificate to stdout and its SHA-256 fingerprint to stderr.
#
# Why the agent CA: the connector dials the agents' listener, 9443, and that is the
# anchor the edge verifies client certificates against there. A second anchor on
# the same listener would be a second population nginx cannot tell apart from the
# first, which is exactly the job Blinky:Adcs:Connector:ClientFingerprints does in
# the API instead - so the fingerprint printed below goes there, and until it does
# this certificate is refused on the connector routes like any workstation's.
#
# The key was made on the CA server by scripts/new-connector-request.ps1 and stays
# there, non-exportable. Only the request travels.

set -euo pipefail

# Paths given on the command line are the caller's, read before moving to the
# repository, where certs/ is.
start="$PWD"
cd "$(dirname "$0")/.."

CSR=""
DAYS="${DAYS:-365}"
CERTS="${CERTS:-certs}"

while [[ $# -gt 0 ]]; do
    case "$1" in
        --csr) CSR="$2"; shift 2 ;;
        --days) DAYS="$2"; shift 2 ;;
        --certs) CERTS="$2"; shift 2 ;;
        *) echo "unknown argument: $1" >&2; exit 2 ;;
    esac
done

[[ -z "$CSR" || "$CSR" = /* ]] || CSR="$start/$CSR"

[[ -n "$CSR" ]] || { echo "usage: sign-connector-cert.sh --csr <file> [--days 365]" >&2; exit 2; }
[[ -f "$CSR" ]] || { echo "No such request: $CSR" >&2; exit 2; }
[[ -f "$CERTS/agent-ca.crt" && -f "$CERTS/agent-ca.key" ]] || {
    echo "No agent CA in $CERTS/ - this runs on the Docker host, beside the stack." >&2
    exit 3
}

# certreq writes a request with Windows line endings and, unless told otherwise, as
# base64 without armour. openssl reads the armoured form only.
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

tr -d '\r' < "$CSR" > "$work/request.pem"

grep -q "BEGIN NEW CERTIFICATE REQUEST\|BEGIN CERTIFICATE REQUEST" "$work/request.pem" || {
    echo "$CSR is not a PEM certificate request." >&2
    exit 4
}

# The request's own signature, before anything is signed on its behalf.
openssl req -in "$work/request.pem" -noout -verify >/dev/null 2>&1 || {
    echo "The request's own signature does not verify." >&2
    exit 4
}

# The same extensions AgentCertificateAuthority gives an agent: a client, nothing
# more. The subject is the request's, because nothing registers a connector - its
# identity is the fingerprint, not the name.
{
    echo "basicConstraints=critical,CA:FALSE"
    echo "keyUsage=critical,digitalSignature"
    echo "extendedKeyUsage=clientAuth"
    echo "subjectKeyIdentifier=hash"
    echo "authorityKeyIdentifier=keyid:always"
} > "$work/connector.ext"

openssl x509 -req -in "$work/request.pem" -days "$DAYS" \
    -CA "$CERTS/agent-ca.crt" -CAkey "$CERTS/agent-ca.key" -CAcreateserial -CAserial "$work/serial" \
    -sha256 -out "$work/connector.crt" -extfile "$work/connector.ext" 2>/dev/null

openssl verify -CAfile "$CERTS/agent-ca.crt" "$work/connector.crt" >/dev/null 2>&1 || {
    echo "The signed certificate does not chain to $CERTS/agent-ca.crt." >&2
    exit 5
}

fingerprint="$(openssl x509 -in "$work/connector.crt" -noout -fingerprint -sha256 | cut -d= -f2 | tr -d ':')"

{
    echo "subject:     $(openssl x509 -in "$work/connector.crt" -noout -subject | sed 's/^subject=//')"
    echo "expires:     $(openssl x509 -in "$work/connector.crt" -noout -enddate | cut -d= -f2-)"
    echo "sha256:      $fingerprint"
    echo
    echo "Add it to the API, then restart the api container:"
    echo "  ADCS_CONNECTOR_CLIENT_FINGERPRINTS=$fingerprint"
} >&2

cat "$work/connector.crt"
