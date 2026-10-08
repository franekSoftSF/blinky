#!/usr/bin/env bash
# Creates a certificate authority for the built-in backend, in either shape.
#
#     ./scripts/new-ca.sh --topology two-tier --name "Blinky Lab"    # default
#     ./scripts/new-ca.sh --topology single   --name "Blinky Demo"
#
# two-tier   an offline root that signs one issuing CA. The root's key is
#            written here so it can be moved somewhere else and deleted; the
#            stack only ever loads the issuing CA.
#
# single     one self-signed CA that is both the anchor and the issuer. Right
#            for a lab, a demo or an air-gapped rig, and wrong for anything
#            whose lifetime is measured in years - see docs/04-pki-backends.md.
#
# Output, under ca/ by default:
#   ca/anchor.crt        what clients must trust
#   ca/issuing.crt       what signs end entities, and what belongs in NTAuth
#   ca/issuing.p12       the issuing key, for the `file` key tier
#   ca/chain.pem         issuing then anchor, in that order
#   ca/root.key          two-tier only. MOVE THIS OFF THE MACHINE.
set -euo pipefail

# Git Bash rewrites anything that looks like a path, so /CN=x arrives at openssl
# as C:/Program Files/Git/CN=x. No-op everywhere else.
export MSYS_NO_PATHCONV=1
export MSYS2_ARG_CONV_EXCL='*'

cd "$(dirname "$0")/.."

topology="two-tier"
name="Blinky"
outdir="ca"
force=""

# The password that protects the issuing key's PKCS#12, from the environment.
#
# install-server.sh generates one per installation and hands it over this way
# rather than as an argument, because an argument is visible in ps for as long
# as this runs and stays in shell history afterwards.
#
# It used to pass CA_PASSWORD in the environment while this script read only
# --password and quietly fell back to the literal below. Every CA built by the
# installer was therefore protected by the word "blinky" while its .env
# recorded a strong generated password that opened nothing. The services could
# not read their own signing key, and the failure named a password without
# saying which one.
password="${CA_PASSWORD:-}"

while [ $# -gt 0 ]; do
    case "$1" in
        --topology) topology="$2"; shift 2 ;;
        --name) name="$2"; shift 2 ;;
        --out) outdir="$2"; shift 2 ;;
        --password) password="$2"; shift 2 ;;
        --force) force="yes"; shift ;;
        *) echo "unknown argument: $1" >&2; exit 2 ;;
    esac
done

case "$topology" in
    single|two-tier) ;;
    *) echo "--topology must be single or two-tier" >&2; exit 2 ;;
esac

# A default exists so that a throwaway CA in a test needs no ceremony, but it
# is announced rather than assumed. A signing key protected by a word written
# in this file is not protected, and the one thing that must never happen
# quietly is that.
if [ -z "$password" ]; then
    password="blinky"
    cat >&2 <<'WARN'

  This CA's private key is protected by the built-in password "blinky".
  That is fine for a throwaway and is not protection anywhere else.
  Set CA_PASSWORD to choose one.

WARN
fi

mkdir -p "$outdir"

if [ -f "$outdir/issuing.crt" ] && [ -z "$force" ]; then
    echo "$outdir already holds a CA; pass --force to replace it"
    exit 0
fi

echo "==> $topology certificate authority: $name"

if [ "$topology" = "single" ]; then
    openssl req -x509 -newkey rsa:4096 -nodes -days 3650 \
        -keyout "$outdir/issuing.key" -out "$outdir/issuing.crt" \
        -subj "/CN=$name CA/O=$name" \
        -addext "basicConstraints=critical,CA:TRUE,pathlen:0" \
        -addext "keyUsage=critical,keyCertSign,cRLSign" \
        -addext "subjectKeyIdentifier=hash"

    cp "$outdir/issuing.crt" "$outdir/anchor.crt"
    cat "$outdir/issuing.crt" > "$outdir/chain.pem"
else
    # pathlen counts the intermediates that may FOLLOW a certificate, so in a
    # two-tier hierarchy the root needs pathlen:1 - one intermediate follows it
    # - and the issuing CA gets pathlen:0. Putting 0 on the root instead says
    # "sign nothing but end entities", and every chain through the issuing CA
    # is rejected with "basic constraints not satisfied", which sounds like a
    # problem with the leaf.
    openssl req -x509 -newkey rsa:4096 -nodes -days 7300 \
        -keyout "$outdir/root.key" -out "$outdir/anchor.crt" \
        -subj "/CN=$name Root CA/O=$name" \
        -addext "basicConstraints=critical,CA:TRUE,pathlen:1" \
        -addext "keyUsage=critical,keyCertSign,cRLSign" \
        -addext "subjectKeyIdentifier=hash"

    openssl req -newkey rsa:4096 -nodes \
        -keyout "$outdir/issuing.key" -out "$outdir/issuing.csr" \
        -subj "/CN=$name Issuing CA/O=$name"

    # Identifiers, always. A leaf's authority key identifier points at the
    # issuer's subject key identifier, and without one a chain is built by
    # name - which works until two CAs share one. Distribution points are
    # added by scripts/resign-issuing-ca.sh, where the public address is
    # known.
    printf 'basicConstraints=critical,CA:TRUE,pathlen:0
keyUsage=critical,keyCertSign,cRLSign
subjectKeyIdentifier=hash
authorityKeyIdentifier=keyid:always
' \
        > "$outdir/issuing.ext"

    openssl x509 -req -in "$outdir/issuing.csr" -days 3650 \
        -CA "$outdir/anchor.crt" -CAkey "$outdir/root.key" -CAcreateserial \
        -out "$outdir/issuing.crt" -extfile "$outdir/issuing.ext"

    rm -f "$outdir/issuing.csr" "$outdir/issuing.ext"

    cat "$outdir/issuing.crt" "$outdir/anchor.crt" > "$outdir/chain.pem"

    # The root's revocation list, signed here because here is the only place it
    # can ever be signed.
    #
    # The root key does not go to an online service - that is the entire reason
    # for having two tiers - so no worker, no scheduled job and no API call can
    # produce this file. It is made at the moment the root exists, and remade by
    # hand on the rare day an issuing CA is revoked.
    #
    # It is empty, and that is the point. Windows and PKINIT both refuse a chain
    # whose revocation status cannot be established, and Samba's AD wants
    # authorityRevocationList present and non-empty as DER. An empty list that
    # verifies answers "has this been revoked" with a signed "no"; no list at
    # all answers "I cannot tell", which is refused.
    #
    # Without it the CDP named in the issuing certificate returns 404, and on a
    # workstation that surfaces as a logon refused for revocation reasons, three
    # steps away from this file.
    : > "$outdir/root-index.txt"
    echo 1000 > "$outdir/root-crlnumber"

    cat > "$outdir/root-crl.cnf" <<CNF
[ ca ]
default_ca = root_ca

[ root_ca ]
database         = $outdir/root-index.txt
crlnumber        = $outdir/root-crlnumber
certificate      = $outdir/anchor.crt
private_key      = $outdir/root.key
default_md       = sha256

# Long, because refreshing it means bringing the root key back out. Short
# enough that a list nobody maintains announces itself by expiring rather than
# staying silently trusted for a decade.
default_crl_days = 180
CNF

    openssl ca -config "$outdir/root-crl.cnf" -gencrl -out "$outdir/root.crl.pem" 2>/dev/null

    openssl crl -in "$outdir/root.crl.pem" -outform DER -out "$outdir/root.crl"

    rm -f "$outdir"/root.crl.pem "$outdir"/root-crl.cnf "$outdir"/root-index.txt*
    rm -f "$outdir"/root-crlnumber*
fi

openssl pkcs12 -export -out "$outdir/issuing.p12" \
    -inkey "$outdir/issuing.key" -in "$outdir/issuing.crt" \
    -passout "pass:$password" -name "$name issuing CA"

rm -f "$outdir/issuing.key"

echo
openssl x509 -in "$outdir/anchor.crt" -noout -subject -issuer
echo
openssl verify -CAfile "$outdir/anchor.crt" "$outdir/issuing.crt" \
    || echo "WARNING: the issuing certificate does not verify against the anchor"

if [ "$topology" = "two-tier" ]; then
    if [ -s "$outdir/root.crl" ]; then
        echo "root revocation list valid until $(openssl crl -in "$outdir/root.crl" -inform DER -noout -nextupdate | cut -d= -f2-)"
    else
        echo "WARNING: no root revocation list - the root's distribution point will 404"
    fi
fi

echo
if [ "$topology" = "two-tier" ]; then
    echo "MOVE $outdir/root.key OFF THIS MACHINE and delete it here."
    echo "It is the only thing that can issue a replacement for the issuing CA,"
    echo "and the only reason two tiers are worth the trouble."
fi
echo "$outdir/ is ignored by git. Development material - not for anything real."
