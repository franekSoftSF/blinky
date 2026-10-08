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
#   otherName 1.3.6.1.4.1.311.25.1
#                           the GUID of the DC's NTDS Settings object, which is
#                           what a *Windows* client looks at. Not the computer
#                           object's GUID - different object, different value,
#                           and the wrong one fails the same way as none.
#
# Three extended key usages rather than one. id-pkinit-KPKdc alone satisfies
# RFC 4556 and an MIT client; a Windows client also expects the certificate to
# look like a server certificate it could have talked to. See
# https://wiki.samba.org/index.php/Samba_AD_Smart_Card_Login.

set -euo pipefail

CSR=""
REALM=""
DC=""
DC_GUID=""
PUBLIC_URL=""
CA_DIR="${CA_DIR:-ca}"
DAYS="${DAYS:-825}"

while [[ $# -gt 0 ]]; do
    case "$1" in
        --csr) CSR="$2"; shift 2 ;;
        --realm) REALM="$2"; shift 2 ;;
        --dc) DC="$2"; shift 2 ;;
        --dc-guid) DC_GUID="$2"; shift 2 ;;
        --public-url) PUBLIC_URL="$2"; shift 2 ;;
        --ca) CA_DIR="$2"; shift 2 ;;
        *) echo "unknown argument: $1" >&2; exit 2 ;;
    esac
done

[[ -n "$CSR" && -n "$REALM" && -n "$DC" ]] || {
    echo "usage: sign-kdc-cert.sh --csr <file> --realm <REALM> --dc <fqdn>" >&2
    echo "               [--dc-guid <NTDS Settings objectGUID>] [--public-url <http://...>]" >&2
    exit 2
}

PUBLIC_URL="${PUBLIC_URL%/}"

# The GUID of the DC's *NTDS Settings* object, not of its computer object -
# they are different objects with different GUIDs, and a Windows client
# checking a KDC certificate looks at this one:
#
#     ldbsearch -H /var/lib/samba/private/sam.ldb #         -b "CN=Configuration,DC=..." "(objectClass=nTDSDSA)" objectGUID
#
# Stored little-endian in its first three groups, which is how it is written
# into the certificate: what goes in is the raw sixteen bytes as the directory
# holds them, not the printed form.
guid_hex=""
if [[ -n "$DC_GUID" ]]; then
    g="${DC_GUID//-/}"
    [[ ${#g} -eq 32 ]] || { echo "--dc-guid is not a GUID: $DC_GUID" >&2; exit 2; }

    guid_hex="${g:6:2}${g:4:2}${g:2:2}${g:0:2}${g:10:2}${g:8:2}${g:14:2}${g:12:2}${g:16:16}"
fi

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
# Three of them, not one. id-pkinit-KPKdc alone is what an MIT client wants;
# a Windows client checking a KDC also expects the certificate to look like a
# server certificate it could have talked to, which is what the Samba wiki's
# clientAuth, serverAuth, pkInitKDC amounts to. Issuing only the first is
# correct by RFC 4556 and refused in practice.
extra_san=""
if [[ -n "$guid_hex" ]]; then
    extra_san="otherName.2 = 1.3.6.1.4.1.311.25.1;FORMAT:HEX,OCTETSTRING:$guid_hex"
fi

distribution=""
if [[ -n "$PUBLIC_URL" ]]; then
    distribution="crlDistributionPoints = URI:$PUBLIC_URL/pki/issuing.crl
authorityInfoAccess = caIssuers;URI:$PUBLIC_URL/pki/issuing.crt"
fi

cat > "$work/kdc.cnf" <<EOF
[kdc]
basicConstraints = critical,CA:FALSE
keyUsage = critical,digitalSignature,keyEncipherment
extendedKeyUsage = 1.3.6.1.5.5.7.3.1,1.3.6.1.5.5.7.3.2,1.3.6.1.5.2.3.5
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid,issuer
subjectAltName = @san
$distribution

[san]
DNS.1 = $DC
otherName.1 = 1.3.6.1.5.2.2;SEQUENCE:principal
$extra_san

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
