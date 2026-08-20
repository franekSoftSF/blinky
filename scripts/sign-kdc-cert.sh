#!/usr/bin/env bash
#
# Blinky lab - sign a KDC certificate with the built-in CA.
#
#     bash sign-kdc-cert.sh --csr kdc.csr --realm BLINKY.LAB --dc by-dc01.blinky.lab
#
# Run on the machine holding ca/. Prints the certificate to stdout.
#
# Smart-card logon against a Samba KDC is PKINIT, and PKINIT will not start
# until the KDC itself holds a certificate with three things the ordinary
# server profile does not have:
#
#   EKU 1.3.6.1.5.2.3.5     id-pkinit-KPKdc. A TLS server certificate is not a
#                           KDC certificate however good it looks.
#   dNSName                 the DC's own name.
#   otherName 1.3.6.1.5.2.2 id-pkinit-san, carrying krbtgt/REALM@REALM as a
#                           KRB5PrincipalName. This is the one that has to be
#                           hand-built: openssl has no shorthand for it, and a
#                           certificate without it is refused by clients with a
#                           message about trust rather than about a name.

set -euo pipefail

CSR=""
REALM=""
DC=""
CA_DIR="${CA_DIR:-ca}"
DAYS="${DAYS:-825}"

while [[ $# -gt 0 ]]; do
    case "$1" in
        --csr) CSR="$2"; shift 2 ;;
        --realm) REALM="$2"; shift 2 ;;
        --dc) DC="$2"; shift 2 ;;
        --ca) CA_DIR="$2"; shift 2 ;;
        *) echo "unknown argument: $1" >&2; exit 2 ;;
    esac
done

[[ -n "$CSR" && -n "$REALM" && -n "$DC" ]] || {
    echo "usage: sign-kdc-cert.sh --csr <file> --realm <REALM> --dc <fqdn>" >&2
    exit 2
}

[[ -f "$CA_DIR/issuing.p12" ]] || {
    echo "No issuing CA in $CA_DIR. Run scripts/new-ca.sh first." >&2
    exit 3
}

password="${CA_PASSWORD:-$(grep '^CA_PASSWORD=' .env 2>/dev/null | cut -d= -f2-)}"
password="${password:-blinky}"

work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

openssl pkcs12 -in "$CA_DIR/issuing.p12" -passin "pass:$password" \
    -nokeys -clcerts -out "$work/issuer.crt" 2>/dev/null
openssl pkcs12 -in "$CA_DIR/issuing.p12" -passin "pass:$password" \
    -nocerts -nodes -out "$work/issuer.key" 2>/dev/null

# The KRB5PrincipalName, spelled out. There is no openssl shorthand for
# id-pkinit-san, so the ASN.1 is written by hand:
#
#   KRB5PrincipalName ::= SEQUENCE {
#       realm         [0] Realm,
#       principalName [1] PrincipalName }
#
#   PrincipalName ::= SEQUENCE {
#       name-type     [0] Int32,
#       name-string   [1] SEQUENCE OF KerberosString }
#
# name-type 2 is NT-SRV-INST, which is what a krbtgt service principal is.
cat > "$work/kdc.cnf" <<EOF
[kdc]
basicConstraints = critical,CA:FALSE
keyUsage = critical,digitalSignature,keyEncipherment
extendedKeyUsage = 1.3.6.1.5.2.3.5
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid,issuer
subjectAltName = @san

[san]
DNS.1 = $DC
otherName.1 = 1.3.6.1.5.2.2;SEQUENCE:principal

[principal]
realm = EXP:0,GeneralString:$REALM
name = EXP:1,SEQUENCE:principal_name

[principal_name]
type = EXP:0,INTEGER:2
strings = EXP:1,SEQUENCE:principal_strings

[principal_strings]
one = GeneralString:krbtgt
two = GeneralString:$REALM
EOF

openssl x509 -req \
    -in "$CSR" \
    -CA "$work/issuer.crt" \
    -CAkey "$work/issuer.key" \
    -CAcreateserial \
    -days "$DAYS" \
    -sha256 \
    -extfile "$work/kdc.cnf" \
    -extensions kdc 2>/dev/null
