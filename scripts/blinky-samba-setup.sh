#!/usr/bin/env bash
#
# Blinky - publish the CA into a Samba4 directory and give the KDC a
# certificate. Patch 0061.
#
#     sudo bash blinky-samba-setup.sh --from-url http://by-cacms.blinky.lab
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
#   The KDC certificate         PKINIT will not start without it - and holding
#                               one is not the same as using it. Samba has to
#                               be told, in its own krb5.conf, with a [kdc]
#                               section that names the identity and the
#                               anchors. A controller can sit for a day with a
#                               perfectly good certificate and no [kdc] section
#                               at all, and every explanation offered for the
#                               failed logon will be about the card.

set -euo pipefail

CHAIN=""
FROM_URL=""
KDC_CERT=""
CRL_ROOT=""
CRL_ISSUING=""
REALM="${REALM:-$(hostname -d | tr '[:lower:]' '[:upper:]')}"

while [[ $# -gt 0 ]]; do
    case "$1" in
        --chain) CHAIN="$2"; shift 2 ;;

        # Everything from the CMS host over HTTP, instead of three files
        # somebody has to copy. The same addresses the certificates name as
        # their distribution point, so if this works the clients will be able
        # to fetch them too - which is worth knowing here rather than later.
        --from-url) FROM_URL="$2"; shift 2 ;;
        --crl-root) CRL_ROOT="$2"; shift 2 ;;
        --crl-issuing) CRL_ISSUING="$2"; shift 2 ;;
        --kdc-cert) KDC_CERT="$2"; shift 2 ;;
        --realm) REALM="$2"; shift 2 ;;
        *) echo "unknown argument: $1" >&2; exit 2 ;;
    esac
done

say() { printf '\n\033[1m%s\033[0m\n' "$*"; }

# ---------------------------------------------------------------- from url

if [[ -n "$FROM_URL" ]]; then
    FROM_URL="${FROM_URL%/}"

    downloads="$(mktemp -d)"
    trap 'rm -rf "$downloads"' EXIT

    echo "fetching from $FROM_URL/pki/"

    get() {
        local name="$1" out="$2" required="$3"

        if curl -fsS --max-time 30 "$FROM_URL/pki/$name" -o "$out"; then
            echo "  $name"
            return 0
        fi

        if [[ "$required" == "required" ]]; then
            echo "  $name could not be fetched, and nothing works without it" >&2
            echo "  Is the CMS up, and does this machine resolve that name?" >&2
            exit 4
        fi

        echo "  $name is not published - carrying on without it"
        return 1
    }

    get chain.pem "$downloads/chain.pem" required && CHAIN="$downloads/chain.pem"
    get issuing.crl "$downloads/issuing.crl" required && CRL_ISSUING="$downloads/issuing.crl"

    # The root's list is absent when the root is somebody else's, which is a
    # supported arrangement rather than a fault - see install-server.sh.
    if get root.crl "$downloads/root.crl" optional; then
        CRL_ROOT="$downloads/root.crl"
    else
        # Samba's schema makes authorityRevocationList mandatory and rejects it
        # empty, so the issuing list stands in. It is a true statement about a
        # list that exists, which an empty one would not be.
        CRL_ROOT="$downloads/issuing.crl"
    fi
fi

[[ $EUID -eq 0 ]] || { echo "Run this with sudo." >&2; exit 2; }

command -v samba-tool >/dev/null || { echo "This is not a Samba DC." >&2; exit 3; }

realm_lower="$(echo "$REALM" | tr '[:upper:]' '[:lower:]')"
basedn="DC=${realm_lower//./,DC=}"
config="CN=Configuration,$basedn"
services="CN=Public Key Services,CN=Services,$config"
dc_fqdn="$(hostname -f)"

# Already ends in tls - Samba keeps its TLS material there. Uses below join
# to it directly; adding another "tls/" produces /private/tls/tls, which is
# created happily and then read by nothing.
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

Fetch them from the CMS instead of copying files about:

    sudo bash blinky-samba-setup.sh --from-url http://<cms-host>

That reads the same addresses the certificates name as their distribution
point, so if it works here the clients will manage it too.
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
# Either spelling. openssl prints the friendly name when it recognises the OID
# and the OID when it does not, and which one you get depends on the version -
# so a check for the number alone rejects a perfectly good certificate, which
# is exactly what this did the first time it ran.
if ! openssl x509 -in "$KDC_CERT" -noout -ext extendedKeyUsage 2>/dev/null |
        grep -qE "1\.3\.6\.1\.5\.2\.3\.5|Signing KDC Response"; then
    echo "This certificate has no KDC Authentication EKU (1.3.6.1.5.2.3.5)." >&2
    echo "PKINIT will refuse it, and the message will be about trust." >&2
    exit 4
fi

cp "$KDC_CERT" "$private/kdc.crt"
chmod 644 "$private/kdc.crt"

# The full chain beside it. PKINIT presents what it is given, and a client that
# does not already hold the issuing CA cannot build a path from a leaf alone -
# which it reports as the KDC certificate being untrusted, sending everybody to
# look at anchors instead of at what was sent.
install -d -m 755 "$private"

if [[ -n "$CHAIN" && -f "$CHAIN" ]]; then
    cat "$private/kdc.crt" "$CHAIN" > "$private/kdc-chain.pem"
    chmod 644 "$private/kdc-chain.pem"
    identity="$private/kdc-chain.pem"

    install -m 644 "$CHAIN" "$private/ca-chain.pem"
else
    identity="$private/kdc.crt"
fi

anchors="$private/ca-chain.pem"

[[ -f "$anchors" ]] || {
    echo "No anchor chain at $anchors. Pass --chain so PKINIT has something to" >&2
    echo "check client certificates against." >&2
    exit 4
}

# ------------------------------------------------------------ enable pkinit

say "enabling PKINIT"

# A certificate the KDC never reads is a certificate that does nothing. Samba
# does not turn PKINIT on because material appeared in its directory: it has to
# be told, in its own krb5.conf, and /etc/krb5.conf has to be a copy of that
# file rather than a different one that happens to work for kinit.
#
# Found on 21 August 2026. The KDC had held a certificate for a day, there was
# no [kdc] section anywhere, and every explanation offered for the failed logon
# was about the card.
samba_krb5="$private/krb5.conf"

# Rewritten rather than appended to, so running this twice does not leave two
# [kdc] sections with different paths in them.
if grep -q "^\[kdc\]" "$samba_krb5" 2>/dev/null; then
    sed -i '/^\[kdc\]/,$d' "$samba_krb5"
fi

cat >> "$samba_krb5" <<KRB
[kdc]
    # The dash is not a typo: Samba spells this one with a hyphen and
    # everything around it with underscores.
    enable-pkinit = yes
    pkinit_identity = FILE:$identity,$private/kdc.key
    pkinit_anchors = FILE:$anchors

    # The client is named by what is inside its certificate rather than by
    # where the certificate was found - which is what the UPN and the SID
    # extension are for.
    pkinit_principal_in_certificate = yes

    # A certificate without the KDC Authentication EKU is refused rather than
    # accepted on the strength of looking right.
    pkinit_require_eku = true

    # The Windows 2000 form is off, and the binding it needs is required
    # wherever it is used at all. Both together: half of this pair is a
    # downgrade waiting to be asked for.
    pkinit_win2k = no
    pkinit_win2k_require_binding = yes
KRB

# Anchors at the top level too, for this machine acting as a client.
if ! sed -n '/^\[libdefaults\]/,/^\[/p' "$samba_krb5" | grep -q pkinit_anchors; then
    sed -i "/^\[libdefaults\]/a\    pkinit_anchors = FILE:$anchors" "$samba_krb5"
fi

# A copy, not a symbolic link. Samba rewrites its own file, and a link means
# the system file changes underneath everything that has already read it.
cp "$samba_krb5" /etc/krb5.conf
chmod 644 /etc/krb5.conf

# The revocation list smbd checks, once one has been published here.
if [[ -f "$private/issuing.crl" ]] &&
        ! grep -q "tls crlfile" /etc/samba/smb.conf; then
    # Spaces rather than a tab: sed's "a" strips the backslash and leaves
    # the letter, which would write "ttls crlfile" and be ignored as an
    # unknown parameter.
    sed -i "/^\[global\]/a\\    tls crlfile = $private/issuing.crl" /etc/samba/smb.conf
    say "smb.conf now points at the revocation list"
fi

systemctl restart samba-ad-dc
sleep 4
systemctl is-active samba-ad-dc

# Checked rather than claimed. "PKINIT is enabled" is a line that was written;
# whether Samba could load what it points at is a different question.
if journalctl -u samba-ad-dc --since "-1 min" --no-pager 2>/dev/null |
        grep -qiE "pkinit.*(fail|error)|Failed to load"; then
    echo
    echo "  Samba logged a PKINIT problem on startup:" >&2
    echo "      journalctl -u samba-ad-dc --since '-2 min'" >&2
fi

cat <<EOF

  key       $private/kdc.key
  cert      $private/kdc.crt
  identity  $identity
  anchors   $anchors

PKINIT is enabled and /etc/krb5.conf is a copy of Samba's own. A client can now
try it:

    kinit -X X509_user_identity=PKCS11:/usr/lib/x86_64-linux-gnu/opensc-pkcs11.so \
          user@$REALM

If that works and a Windows logon still does not, the difference is the
revocation check. Keep the directory's lists current:

    sudo bash scripts/publish-crl-to-directory.sh --url <ca-url> --install-timer
EOF
