#!/usr/bin/env bash
#
# Blinky - publish the CA into a Samba4 directory and give the KDC a
# certificate. Patch 0061.
#
#     sudo bash blinky-samba-setup.sh --chain chain.pem
#     sudo bash blinky-samba-setup.sh --chain chain.pem --kdc-cert kdc.crt
#
# Run on the domain controller. Two passes: the first publishes the CA and
# writes a certificate request for the KDC, the second installs the signed
# certificate that came back.
#
# This is a separate command rather than part of anything's startup, because
# writing to the Configuration NC of a directory is not something a service
# should do on boot.
#
# Three things, and the second is the one people miss:
#
#   Certification Authorities   makes the chain trusted by domain members.
#   NTAuthCertificates          makes a certificate acceptable *for logon*. A
#                               chain that is trusted but not in NTAuth fails
#                               with "the smartcard certificate used for
#                               authentication was not trusted", which sounds
#                               like the first problem and is not.
#   The KDC certificate         PKINIT will not start without it.

set -euo pipefail

CHAIN=""
KDC_CERT=""
CRL_ROOT=""
CRL_ISSUING=""
REALM="${REALM:-$(hostname -d | tr '[:lower:]' '[:upper:]')}"

while [[ $# -gt 0 ]]; do
    case "$1" in
        --chain) CHAIN="$2"; shift 2 ;;
        --crl-root) CRL_ROOT="$2"; shift 2 ;;
        --crl-issuing) CRL_ISSUING="$2"; shift 2 ;;
        --kdc-cert) KDC_CERT="$2"; shift 2 ;;
        --realm) REALM="$2"; shift 2 ;;
        *) echo "unknown argument: $1" >&2; exit 2 ;;
    esac
done

say() { printf '\n\033[1m%s\033[0m\n' "$*"; }

[[ $EUID -eq 0 ]] || { echo "Run this with sudo." >&2; exit 2; }

command -v samba-tool >/dev/null || { echo "This is not a Samba DC." >&2; exit 3; }

realm_lower="$(echo "$REALM" | tr '[:upper:]' '[:lower:]')"
basedn="DC=${realm_lower//./,DC=}"
config="CN=Configuration,$basedn"
services="CN=Public Key Services,CN=Services,$config"
dc_fqdn="$(hostname -f)"

private=/var/lib/samba/private/tls
SAM=/var/lib/samba/private/sam.ldb

# ---------------------------------------------------------------- publish

if [[ -n "$CHAIN" ]]; then
    [[ -f "$CHAIN" ]] || { echo "No such file: $CHAIN" >&2; exit 2; }

    [[ -n "$CRL_ROOT" && -n "$CRL_ISSUING" ]] || {
        cat >&2 <<'EOF'
--crl-root and --crl-issuing are required.

The schema makes authorityRevocationList and certificateRevocationList
mandatory on a certificationAuthority object, and it rejects them empty. So a
CRL from each tier has to come along with the certificates - Samba will not
create the object without one, and the error it gives names the attribute
rather than the reason.

Produce them where the CA keys are:

    bash scripts/export-ca-for-directory.sh
EOF
        exit 2
    }

    say "publishing the chain into $services"

    work="$(mktemp -d)"
    trap 'rm -rf "$work"' EXIT

    csplit -sz -f "$work/cert-" -b "%02d.pem" "$CHAIN" '/-----BEGIN CERTIFICATE-----/' '{*}'

    for pem in "$work"/cert-*.pem; do
        subject="$(openssl x509 -in "$pem" -noout -subject)"
        issuer="$(openssl x509 -in "$pem" -noout -issuer)"
        certificate="$(openssl x509 -in "$pem" -outform DER | base64 -w0)"

        # Self-signed is the root: it goes where domain members look for
        # trusted roots. Everything else is an issuing CA and belongs in
        # NTAuth, which is what makes a certificate usable for logon rather
        # than merely trusted - a chain that is trusted and not in NTAuth fails
        # with "the smartcard certificate used for authentication was not
        # trusted", which sounds like the first problem and is not.
        if [[ "${subject#subject=}" == "${issuer#issuer=}" ]]; then
            name="$(openssl x509 -in "$pem" -noout -subject -nameopt multiline |
                awk -F' = ' '/commonName/ {print $2; exit}')"
            dn="CN=$name,CN=Certification Authorities,$services"
            crl="$(base64 -w0 < "$CRL_ROOT")"
            role="root"
        else
            dn="CN=NTAuthCertificates,$services"
            crl="$(base64 -w0 < "$CRL_ISSUING")"
            role="NTAuth"
        fi

        cn="${dn#CN=}"
        cn="${cn%%,*}"

        if ldbsearch -H "$SAM" -b "$dn" -s base dn >/dev/null 2>&1; then
            action="ldbmodify"
            cat > "$work/change.ldif" <<LDIF
dn: $dn
changetype: modify
replace: cACertificate
cACertificate:: $certificate
LDIF
        else
            action="ldbadd"

            # The two revocation lists are mandatory on this object class and
            # rejected when empty, which is why a CRL from each tier has to
            # travel with the certificates.
            cat > "$work/change.ldif" <<LDIF
dn: $dn
changetype: add
objectClass: top
objectClass: certificationAuthority
cn: $cn
cACertificate:: $certificate
authorityRevocationList:: $crl
certificateRevocationList:: $crl
LDIF
        fi

        # Not silenced. The first version of this swallowed the error and
        # printed "already present, or could not be written", which is a
        # sentence that tells an operator nothing - and it was wrong both
        # times: nothing had been written at all.
        if "$action" -H "$SAM" "$work/change.ldif" >/dev/null; then
            echo "  $role  <- ${subject#subject=}"
        else
            echo "  $role  FAILED for ${subject#subject=}" >&2
            exit 4
        fi
    done
fi

# ------------------------------------------------------------ kdc request

if [[ -z "$KDC_CERT" ]]; then
    say "certificate request for the KDC"

    mkdir -p "$private"

    if [[ ! -f "$private/kdc.key" ]]; then
        openssl genrsa -out "$private/kdc.key" 3072 2>/dev/null
        chmod 600 "$private/kdc.key"
    fi

    openssl req -new -key "$private/kdc.key" -sha256 \
        -subj "/CN=$dc_fqdn" -out /tmp/kdc.csr 2>/dev/null

    cat <<EOF

  /tmp/kdc.csr

Sign it where the CA lives, then come back with the result:

    scp $(hostname):/tmp/kdc.csr .
    bash scripts/sign-kdc-cert.sh --csr kdc.csr --realm $REALM --dc $dc_fqdn > kdc.crt
    scp kdc.crt $(hostname):/tmp/
    sudo bash blinky-samba-setup.sh --kdc-cert /tmp/kdc.crt
EOF
    exit 0
fi

# ------------------------------------------------------------ kdc install

say "installing the KDC certificate"

[[ -f "$KDC_CERT" ]] || { echo "No such file: $KDC_CERT" >&2; exit 2; }

# Checked before it is installed. A certificate without id-pkinit-KPKdc looks
# perfectly good in a viewer and PKINIT refuses it, complaining about trust.
if ! openssl x509 -in "$KDC_CERT" -noout -ext extendedKeyUsage 2>/dev/null |
        grep -q "1.3.6.1.5.2.3.5"; then
    echo "This certificate has no KDC Authentication EKU (1.3.6.1.5.2.3.5)." >&2
    echo "PKINIT will refuse it, and the message will be about trust." >&2
    exit 4
fi

cp "$KDC_CERT" "$private/kdc.crt"
chmod 644 "$private/kdc.crt"

systemctl restart samba-ad-dc
sleep 4
systemctl is-active samba-ad-dc

cat <<EOF

  key    $private/kdc.key
  cert   $private/kdc.crt

The KDC has a certificate. A client can now try PKINIT:

    kinit -X X509_user_identity=PKCS11:/usr/lib/x86_64-linux-gnu/opensc-pkcs11.so \\
          user@$REALM
EOF
