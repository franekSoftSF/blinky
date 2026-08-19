#!/usr/bin/env bash
# Development certificates for the edge. Not for production, not for anything
# that matters - the keys are written unencrypted next to the certificates.
#
# Produces:
#   certs/edge.crt|key        TLS for both listeners, CN=localhost
#   certs/agent-ca.crt|key    the CA the edge trusts for agent client certs
#   certs/test-agent.crt|key  one client certificate, for the smoke test
#
# Run from the repository root. Git Bash is fine on Windows.
set -euo pipefail

# Git Bash rewrites anything that looks like a path, so /CN=localhost arrives at
# openssl as C:/Program Files/Git/CN=localhost. No-op everywhere else.
export MSYS_NO_PATHCONV=1
export MSYS2_ARG_CONV_EXCL='*'

cd "$(dirname "$0")/.."
mkdir -p certs
cd certs

if [ -f edge.crt ] && [ "${1:-}" != "--force" ]; then
    echo "certs already exist; pass --force to regenerate"
    exit 0
fi

echo "==> edge TLS certificate"
openssl req -x509 -newkey rsa:2048 -nodes -days 825 \
    -keyout edge.key -out edge.crt \
    -subj "/CN=localhost/O=Blinky development" \
    -addext "subjectAltName=DNS:localhost,DNS:edge,IP:127.0.0.1" \
    -addext "keyUsage=digitalSignature,keyEncipherment" \
    -addext "extendedKeyUsage=serverAuth"

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

printf 'keyUsage=digitalSignature
extendedKeyUsage=clientAuth
' > test-agent.ext

openssl x509 -req -in test-agent.csr -days 825 \
    -CA agent-ca.crt -CAkey agent-ca.key -CAcreateserial \
    -out test-agent.crt \
    -extfile test-agent.ext

rm -f test-agent.csr test-agent.ext

echo
echo "done. certs/ is ignored by git and must never be reused anywhere real."
