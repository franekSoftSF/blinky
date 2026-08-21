#!/usr/bin/env bash
#
# Blinky - re-sign an existing issuing CA so it carries the extensions it
# should have had, and produce the root's revocation list.
#
#     bash scripts/resign-issuing-ca.sh --public-url http://ca.example
#
# Run where ca/ is. Keeps the key; only the certificate around it changes.
#
# scripts/new-ca.sh used to give the issuing CA nothing but basicConstraints
# and keyUsage. No subject key identifier, no authority key identifier, no
# authority information access, no CRL distribution point. Every one of those
# is optional in X.509 and none of them is optional in practice:
#
#   subjectKeyIdentifier   is what a leaf's authority key identifier points at.
#                          Without it a chain is built by name, which works
#                          until two CAs share one.
#   authorityKeyIdentifier says which root signed this, by key rather than by
#                          name.
#   authorityInfoAccess    is where a machine that holds neither certificate
#                          goes to find the root.
#   crlDistributionPoints  is where somebody checks whether this CA itself was
#                          revoked. Windows reports its absence as
#                          CERT_TRUST_REVOCATION_STATUS_UNKNOWN on the whole
#                          chain, which refuses a smart-card logon.
#
# The key does not change, so certificates already issued keep chaining and
# keep validating. What does change is this certificate's thumbprint - so
# wherever it was published, it has to be published again:
#
#   - NTAuthCertificates in the directory (scripts/blinky-samba-setup.sh)
#   - Intermediate Certification Authorities on every Windows client
#
# A root CRL comes out of the same run. A self-signed root does not need a
# distribution point of its own, but the issuing CA's points at one, and
# Samba's certificationAuthority object will not be created without a CRL from
# each tier - the schema makes authorityRevocationList mandatory and rejects it
# empty.

set -euo pipefail

CA_DIR="${CA_DIR:-ca}"
PUBLIC_URL=""
ROOT_CRL_DAYS="${ROOT_CRL_DAYS:-365}"
DAYS="${DAYS:-3650}"

while [[ $# -gt 0 ]]; do
    case "$1" in
        --ca) CA_DIR="$2"; shift 2 ;;
        --public-url) PUBLIC_URL="$2"; shift 2 ;;
        --days) DAYS="$2"; shift 2 ;;
        *) echo "unknown argument: $1" >&2; exit 2 ;;
    esac
done

[[ -n "$PUBLIC_URL" ]] || {
    cat >&2 <<'EOF'
--public-url is required.

It is the address written into the certificate as its distribution point, so
it has to be one a relying party can reach: a name their DNS resolves, over
HTTP rather than HTTPS. A client fetching revocation cannot be asked to
validate a certificate first.

    bash scripts/resign-issuing-ca.sh --public-url http://by-ca-cms.blinky.lab
EOF
    exit 2
}

PUBLIC_URL="${PUBLIC_URL%/}"

for f in root.key anchor.crt issuing.key issuing.crt; do
    [[ -f "$CA_DIR/$f" ]] || {
        echo "$CA_DIR/$f is missing. This re-signs a two-tier CA that already exists;" >&2
        echo "use scripts/new-ca.sh to create one." >&2
        exit 3
    }
done

say() { printf '\n\033[1m%s\033[0m\n' "$*"; }

password="${CA_PASSWORD:-$(grep '^CA_PASSWORD=' .env 2>/dev/null | cut -d= -f2-)}"
password="${password:-blinky}"

work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

# ------------------------------------------------------------------ re-sign

say "re-signing the issuing CA"

before="$(openssl x509 -in "$CA_DIR/issuing.crt" -noout -fingerprint -sha1 | cut -d= -f2)"

# The subject is copied from the certificate being replaced rather than
# rebuilt, so the new one is the same CA by name as well as by key. A changed
# subject would orphan every certificate already issued.
subject="$(openssl x509 -in "$CA_DIR/issuing.crt" -noout -subject -nameopt compat | sed 's/^subject=//')"

openssl req -new -key "$CA_DIR/issuing.key" -subj "$subject" -out "$work/issuing.csr"

cat > "$work/issuing.ext" <<EOF
basicConstraints=critical,CA:TRUE,pathlen:0
keyUsage=critical,keyCertSign,cRLSign
subjectKeyIdentifier=hash
authorityKeyIdentifier=keyid:always
authorityInfoAccess=caIssuers;URI:$PUBLIC_URL/pki/root.crt
crlDistributionPoints=URI:$PUBLIC_URL/pki/root.crl
EOF

openssl x509 -req -in "$work/issuing.csr" -days "$DAYS" -sha256 \
    -CA "$CA_DIR/anchor.crt" -CAkey "$CA_DIR/root.key" -CAcreateserial \
    -out "$work/issuing.crt" -extfile "$work/issuing.ext" 2>/dev/null

# Checked before it replaces anything. A re-signed CA whose key no longer
# matches its certificate takes the whole installation down at the next
# issuance, and the error will be about a signature rather than about this.
key_modulus="$(openssl rsa -in "$CA_DIR/issuing.key" -noout -modulus | sha256sum)"
crt_modulus="$(openssl x509 -in "$work/issuing.crt" -noout -modulus | sha256sum)"

[[ "$key_modulus" == "$crt_modulus" ]] || {
    echo "The re-signed certificate does not match the key. Nothing was changed." >&2
    exit 4
}

openssl verify -CAfile "$CA_DIR/anchor.crt" "$work/issuing.crt" >/dev/null || {
    echo "The re-signed certificate does not verify against the root. Nothing was changed." >&2
    exit 4
}

cp "$work/issuing.crt" "$CA_DIR/issuing.crt"
cat "$CA_DIR/issuing.crt" "$CA_DIR/anchor.crt" > "$CA_DIR/chain.pem"

openssl pkcs12 -export -out "$CA_DIR/issuing.p12" \
    -inkey "$CA_DIR/issuing.key" -in "$CA_DIR/issuing.crt" \
    -certfile "$CA_DIR/anchor.crt" -passout "pass:$password"

after="$(openssl x509 -in "$CA_DIR/issuing.crt" -noout -fingerprint -sha1 | cut -d= -f2)"

# ----------------------------------------------------------------- root crl

say "the root's revocation list"

# openssl needs a CA database to emit a CRL, and a root that has revoked
# nothing needs an empty one. Built here rather than kept, because the only
# thing it holds is "nothing has been revoked" and a stale copy of that is
# worse than none.
mkdir -p "$work/db"
: > "$work/db/index.txt"
echo 1000 > "$work/db/crlnumber"

cat > "$work/root.cnf" <<EOF
[ca]
default_ca = root

[root]
database = $work/db/index.txt
crlnumber = $work/db/crlnumber
certificate = $CA_DIR/anchor.crt
private_key = $CA_DIR/root.key
default_md = sha256
default_crl_days = $ROOT_CRL_DAYS
EOF

openssl ca -config "$work/root.cnf" -gencrl -out "$work/root.crl.pem" 2>/dev/null
openssl crl -in "$work/root.crl.pem" -outform DER -out "$CA_DIR/root.crl"

# --------------------------------------------------------------------- done

say "done"

echo "  issuing CA was  $before"
echo "  issuing CA now  $after"
echo "  root CRL        $CA_DIR/root.crl, valid $ROOT_CRL_DAYS days"
echo
openssl x509 -in "$CA_DIR/issuing.crt" -noout -ext \
    subjectKeyIdentifier,authorityKeyIdentifier,authorityInfoAccess,crlDistributionPoints \
    2>/dev/null | sed 's/^/  /'

cat <<EOF

The key did not change, so certificates already issued still chain and still
verify. The thumbprint did, so this certificate has to be published again
wherever it was published before:

    on the DC     sudo bash blinky-samba-setup.sh --chain chain.pem \\
                      --crl-root root.crl --crl-issuing issuing.crl
    on a client   the Intermediate Certification Authorities store

Restart the API so it loads the new certificate:

    docker compose restart api
EOF
