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
password="blinky"
force=""

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
        -addext "keyUsage=critical,keyCertSign,cRLSign"

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
        -addext "keyUsage=critical,keyCertSign,cRLSign"

    openssl req -newkey rsa:4096 -nodes \
        -keyout "$outdir/issuing.key" -out "$outdir/issuing.csr" \
        -subj "/CN=$name Issuing CA/O=$name"

    printf 'basicConstraints=critical,CA:TRUE,pathlen:0\nkeyUsage=critical,keyCertSign,cRLSign\n' \
        > "$outdir/issuing.ext"

    openssl x509 -req -in "$outdir/issuing.csr" -days 3650 \
        -CA "$outdir/anchor.crt" -CAkey "$outdir/root.key" -CAcreateserial \
        -out "$outdir/issuing.crt" -extfile "$outdir/issuing.ext"

    rm -f "$outdir/issuing.csr" "$outdir/issuing.ext"

    cat "$outdir/issuing.crt" "$outdir/anchor.crt" > "$outdir/chain.pem"
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

echo
if [ "$topology" = "two-tier" ]; then
    echo "MOVE $outdir/root.key OFF THIS MACHINE and delete it here."
    echo "It is the only thing that can issue a replacement for the issuing CA,"
    echo "and the only reason two tiers are worth the trouble."
fi
echo "$outdir/ is ignored by git. Development material - not for anything real."
