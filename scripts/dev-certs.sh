#!/usr/bin/env bash
# Development certificates for the edge. Not for production, not for anything
# that matters - the keys are written unencrypted next to the certificates.
#
#     ./scripts/dev-certs.sh                          # localhost only
#     ./scripts/dev-certs.sh --host blinky.lab --host 10.0.0.5
#     ./scripts/dev-certs.sh --force --host blinky.lab
#
# Every --host is added to the edge certificate's subject alternative names, as
# a DNS name or an IP address depending on what it looks like. localhost and
# 127.0.0.1 are always included, so a stack that also has to work from the
# machine it runs on keeps working.
#
# Produces:
#   certs/dev-ca.crt|key      signs the edge certificate; give this to clients
#   certs/edge.crt|key        TLS for both listeners
#   certs/agent-ca.crt|key    the CA the edge trusts for agent client certs
#   certs/test-agent.crt|key  one client certificate, for the smoke test
#
# The edge certificate is signed by a small CA rather than being self-signed,
# because the moment the agent and the backend are on different machines the
# agent has to either trust something or check nothing. One CA file it can pin
# is the first of those; --accept-any-server-certificate is the second, and
# that flag is for a laptop, not for a lab.
#
# Run from the repository root. Git Bash is fine on Windows.
set -euo pipefail

# Git Bash rewrites anything that looks like a path, so /CN=localhost arrives at
# openssl as C:/Program Files/Git/CN=localhost. No-op everywhere else.
export MSYS_NO_PATHCONV=1
export MSYS2_ARG_CONV_EXCL='*'

cd "$(dirname "$0")/.."

force=""
hosts=()

while [ $# -gt 0 ]; do
    case "$1" in
        --force) force="yes"; shift ;;
        --host) hosts+=("$2"); shift 2 ;;
        *) echo "unknown argument: $1" >&2; exit 2 ;;
    esac
done

mkdir -p certs
cd certs

if [ -f edge.crt ] && [ -z "$force" ]; then
    echo "certs already exist; pass --force to regenerate"
    exit 0
fi

# Always usable from the machine the stack runs on.
san="DNS:localhost,DNS:edge,IP:127.0.0.1"
for host in ${hosts[@]+"${hosts[@]}"}; do
    [ -z "$host" ] && continue
    if printf '%s' "$host" | grep -qE '^[0-9]+(\.[0-9]+){3}$'; then
        san="$san,IP:$host"
    else
        san="$san,DNS:$host"
    fi
done

echo "==> development CA"
openssl req -x509 -newkey rsa:2048 -nodes -days 825 \
    -keyout dev-ca.key -out dev-ca.crt \
    -subj "/CN=Blinky development CA/O=Blinky development" \
    -addext "basicConstraints=critical,CA:TRUE,pathlen:0" \
    -addext "keyUsage=critical,keyCertSign,cRLSign"

echo "==> edge TLS certificate"
echo "    subject alternative names: $san"
openssl req -newkey rsa:2048 -nodes \
    -keyout edge.key -out edge.csr \
    -subj "/CN=blinky-edge/O=Blinky development"

printf 'subjectAltName=%s\nkeyUsage=digitalSignature,keyEncipherment\nextendedKeyUsage=serverAuth\n' \
    "$san" > edge.ext

openssl x509 -req -in edge.csr -days 825 \
    -CA dev-ca.crt -CAkey dev-ca.key -CAcreateserial \
    -out edge.crt -extfile edge.ext

rm -f edge.csr edge.ext

echo "==> agent CA"
openssl req -x509 -newkey rsa:2048 -nodes -days 825 \
    -keyout agent-ca.key -out agent-ca.crt \
    -subj "/CN=Blinky development agent CA/O=Blinky development" \
    -addext "basicConstraints=critical,CA:TRUE,pathlen:0" \
    -addext "keyUsage=critical,keyCertSign,cRLSign"

echo "==> test agent client certificate"
openssl req -newkey rsa:2048 -nodes \
    -keyout test-agent.key -out test-agent.csr \
    -subj "/CN=test-agent.blinky.invalid/O=Blinky development"

printf 'keyUsage=digitalSignature\nextendedKeyUsage=clientAuth\n' > test-agent.ext

openssl x509 -req -in test-agent.csr -days 825 \
    -CA agent-ca.crt -CAkey agent-ca.key -CAcreateserial \
    -out test-agent.crt -extfile test-agent.ext

rm -f test-agent.csr test-agent.ext

echo
echo "done. certs/ is ignored by git and must never be reused anywhere real."
echo
echo "Copy certs/dev-ca.crt to each agent machine and point the agent at it:"
echo "    Agent__ServerCertificateAuthorityPath=/path/to/dev-ca.crt"
