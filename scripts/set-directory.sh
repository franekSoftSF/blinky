#!/usr/bin/env bash
#
# Blinky - point an installed stack at a directory, or at a different one.
#
#     sudo bash scripts/set-directory.sh \
#         --host ADC01.ad.digitalworkspace.pl --address 172.16.2.10 \
#         --base-dn DC=ad,DC=digitalworkspace,DC=pl --source ActiveDirectory \
#         --bind-dn svc-blinky-ldap@ad.digitalworkspace.pl \
#         --bind-password-file /root/ad-ldap.password \
#         --ca-file digitalworkspace-chain.pem --netbios AD
#
# Run from the installation, as root: .env is root's alone. install-server.sh sets the
# directory on a fresh host; this changes it on one that is running, which is what
# pointing a Samba4 lab stack at a Windows domain for ADCS needed.
#
# Nothing is written until the directory has been reached over TLS with the chain and
# the name given here. The API's own failure for a wrong anchor or name is "The LDAP
# server is unavailable" in twenty milliseconds, with the port open the whole time.
#
# --address pins the host name to an address for the API container alone. Needed where
# the Docker host resolves the directory's name somewhere else: BY-CACMS asks BY-DC01,
# which forwards ad.digitalworkspace.pl to a public wildcard, and a domain controller's
# LDAPS certificate names the controller, so its address alone does not verify.

set -euo pipefail

start="$PWD"
cd "$(dirname "$0")/.."

HOST="" ADDRESS="" PORT="636" BASE_DN="" SOURCE="ActiveDirectory"
BIND_DN="" PASSWORD_FILE="" CA_FILE="" NETBIOS="" RESTART=1

while [[ $# -gt 0 ]]; do
    case "$1" in
        --host) HOST="$2"; shift 2 ;;
        --address) ADDRESS="$2"; shift 2 ;;
        --port) PORT="$2"; shift 2 ;;
        --base-dn) BASE_DN="$2"; shift 2 ;;
        --source) SOURCE="$2"; shift 2 ;;
        --bind-dn) BIND_DN="$2"; shift 2 ;;
        --bind-password-file) PASSWORD_FILE="$2"; shift 2 ;;
        --ca-file) CA_FILE="$2"; shift 2 ;;
        --netbios) NETBIOS="$2"; shift 2 ;;
        --no-restart) RESTART=0; shift ;;
        *) echo "unknown argument: $1" >&2; exit 2 ;;
    esac
done

absolute() { [[ -z "$1" || "$1" = /* ]] && echo "$1" || echo "$start/$1"; }
PASSWORD_FILE="$(absolute "$PASSWORD_FILE")"
CA_FILE="$(absolute "$CA_FILE")"

[[ -n "$HOST" && -n "$BASE_DN" && -n "$CA_FILE" ]] || {
    echo "usage: set-directory.sh --host <name in its certificate> --base-dn <DN> --ca-file <PEM chain>" >&2
    echo "       [--address <IPv4>] [--port 636] [--source ActiveDirectory|Samba4]" >&2
    echo "       [--bind-dn <UPN or DN> --bind-password-file <file>] [--netbios <DOMAIN>] [--no-restart]" >&2
    exit 2
}

[[ $EUID -eq 0 ]] || { echo "Run with sudo: .env is readable by root alone." >&2; exit 2; }
[[ -f .env ]] || { echo "No .env in $PWD - run this in an installation." >&2; exit 2; }
[[ -f "$CA_FILE" ]] || { echo "No such CA file: $CA_FILE" >&2; exit 2; }
[[ "$SOURCE" == ActiveDirectory || "$SOURCE" == Samba4 ]] || { echo "--source is ActiveDirectory or Samba4." >&2; exit 2; }
[[ -z "$ADDRESS" || "$ADDRESS" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]] || { echo "--address is an IPv4 address." >&2; exit 2; }

PASSWORD=""
if [[ -n "$BIND_DN" ]]; then
    [[ -f "$PASSWORD_FILE" ]] || { echo "--bind-dn needs --bind-password-file, and a password is never an argument." >&2; exit 2; }
    PASSWORD="$(head -n1 "$PASSWORD_FILE" | tr -d '\r')"
    [[ -n "$PASSWORD" ]] || { echo "$PASSWORD_FILE is empty." >&2; exit 2; }

    # Written single-quoted, because docker compose interpolates \$ in an unquoted .env
    # value and a password with a dollar sign would arrive shortened, as a bind that
    # fails for a reason nobody would look for in the password.
    [[ "$PASSWORD" != *"'"* ]] || { echo "The password contains a single quote, which .env cannot hold literally." >&2; exit 2; }
fi

# ------------------------------------------------------------------ the check first

echo "==> TLS to $HOST:$PORT${ADDRESS:+ at $ADDRESS}, verified against $CA_FILE"

check="$(timeout 15 openssl s_client \
    -connect "${ADDRESS:-$HOST}:$PORT" -servername "$HOST" \
    -verify_hostname "$HOST" -CAfile "$CA_FILE" -verify_return_error </dev/null 2>&1 || true)"

if ! grep -q "Verify return code: 0 (ok)" <<<"$check"; then
    echo "Refused: the directory did not verify, so nothing was changed." >&2
    grep -E "verify error|Verify return code|connect:|errno|Name or service" <<<"$check" | sed 's/^/  /' >&2 || true
    echo "A wrong --host is 'hostname mismatch'; a wrong --ca-file is 'unable to get local issuer certificate';" >&2
    echo "a name that resolves elsewhere needs --address." >&2
    exit 4
fi

subject="$(openssl x509 -noout -ext subjectAltName <<<"$check" 2>/dev/null | tail -n1 | sed 's/^ *//')"
echo "  verified: ${subject:-certificate names $HOST}"

# ------------------------------------------------------------------ then the change

backup=".env.before-directory.$(date +%Y%m%d-%H%M%S)"
cp -p .env "$backup"
echo "==> .env (the previous one is $backup)"

# Any character a value can hold, including the | and & a sed replacement would eat.
set_value() {
    local key="$1"
    VALUE="$2" awk -v key="$key" '
        BEGIN { value = ENVIRON["VALUE"] }
        index($0, key "=") == 1 { print key "=" value; done = 1; next }
        { print }
        END { if (!done) print key "=" value }
    ' .env > .env.new
    cat .env.new > .env
    rm -f .env.new
}

group="$(stat -c %G certs)"
install -m 644 -o root -g "$group" "$CA_FILE" certs/directory-ca.pem
echo "  certs/directory-ca.pem"

set_value DIRECTORY_HOST "$HOST"
set_value DIRECTORY_PORT "$PORT"
set_value DIRECTORY_BASE_DN "'$BASE_DN'"
set_value DIRECTORY_SOURCE "$SOURCE"
set_value DIRECTORY_USE_TLS true
set_value DIRECTORY_BIND_DN "'$BIND_DN'"
set_value DIRECTORY_BIND_PASSWORD "'$PASSWORD'"
set_value DIRECTORY_NETBIOS_DOMAIN "$NETBIOS"
set_value LDAPTLS_CACERT /etc/blinky/certs/directory-ca.pem
echo "  DIRECTORY_HOST=$HOST, DIRECTORY_BASE_DN=$BASE_DN, DIRECTORY_SOURCE=$SOURCE"
echo "  DIRECTORY_BIND_DN=${BIND_DN:-(Kerberos)}, password ${PASSWORD:+from $PASSWORD_FILE}"
echo "  DIRECTORY_NETBIOS_DOMAIN=${NETBIOS:-(read from the directory)}"

if [[ -n "$ADDRESS" ]]; then
    cat > docker-compose.directory.yml <<EOF
# Written by scripts/set-directory.sh. The directory's name, pinned for the API
# container, because this host resolves it somewhere else. Remove this file and
# COMPOSE_FILE from .env to go back to DNS.
services:
  api:
    extra_hosts:
      - "$HOST:$ADDRESS"
EOF
    chmod 644 docker-compose.directory.yml
    set_value COMPOSE_FILE docker-compose.yml:docker-compose.directory.yml
    echo "  docker-compose.directory.yml: $HOST -> $ADDRESS, in the api container"
elif grep -q "^COMPOSE_FILE=docker-compose.yml:docker-compose.directory.yml$" .env; then
    sed -i '/^COMPOSE_FILE=docker-compose.yml:docker-compose.directory.yml$/d' .env
    rm -f docker-compose.directory.yml
    echo "  the pinned address is gone; the name is resolved by DNS again"
fi

docker compose config >/dev/null || {
    echo "docker compose rejected the result; $backup is the previous .env." >&2
    exit 5
}

if [[ $RESTART -eq 1 ]]; then
    echo "==> docker compose up -d"
    docker compose up -d 2>&1 | grep -E "Recreated|Started|Error" || true
    echo
    echo "Then, from the console or with the operator token: POST /api/directory/test,"
    echo "and /api/directory/test-resolve for somebody who should be found."
fi
