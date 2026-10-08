#!/usr/bin/env bash
# One enrolment token, for a lab and for the smoke test.
#
#     ./scripts/new-enrol-token.sh                              # agent, 1 day, 1 use
#     ./scripts/new-enrol-token.sh --name "sala 12" --uses 30 --days 7
#     ./scripts/new-enrol-token.sh --purpose connector --name by-adcs01
#
# Prints the token on stdout and nothing else, so it can be captured:
#
#     TOKEN=$(./scripts/new-enrol-token.sh --uses 1)
#
# This writes the row with psql inside the compose stack rather than through
# the API, because the API wants an operator session with a password and a TOTP
# code and neither belongs in a script. **The console is the way to make these**
# (Administracja / Zetony, patch 0102); this exists so that the lab and
# smoke-test.sh do not need a human to paste something first. The audit row it
# writes says which it was.
#
# It is a development convenience and it shows: anybody who can run docker
# compose on the host can already read .env, so this grants nothing new.
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$root"

name="lab"
purpose="Agent"
days=1
uses=1
domain=

while [ $# -gt 0 ]; do
    case "$1" in
        --name) name="$2"; shift 2 ;;
        --purpose)
            case "$2" in
                agent|Agent) purpose="Agent" ;;
                connector|Connector|adcs) purpose="AdcsConnector" ;;
                *) echo "--purpose is agent or connector" >&2; exit 2 ;;
            esac
            shift 2 ;;
        --days) days="$2"; shift 2 ;;
        --uses) uses="$2"; shift 2 ;;
        --domain) domain="$2"; shift 2 ;;
        --forever) days=0; shift ;;
        --unlimited) uses=0; shift ;;
        -h|--help) sed -n '2,20p' "$0"; exit 0 ;;
        *) echo "unknown argument: $1" >&2; exit 2 ;;
    esac
done

# 32 bytes, URL-safe base64, no padding - the same shape the API generates, so
# a token minted here is indistinguishable from one made in the console.
# The carriage return matters. openssl on Windows ends its output CRLF, and a
# token carrying a \r hashes differently from the value somebody then pastes:
# the row and the token stop agreeing, and every enrolment with it is refused
# as "no such token". That is how this line came to name three characters.
token="$(openssl rand -base64 32 | tr '+/' '-_' | tr -d '=\r\n')"
hash="$(printf '%s' "$token" | openssl dgst -sha256 -hex | awk '{print $NF}')"

expires="now() + interval '$days days'"
[ "$days" = "0" ] && expires="null"

max_uses="$uses"
[ "$uses" = "0" ] && max_uses="null"

allowed="null"
[ -n "$domain" ] && allowed="'$domain'"

sql="
insert into enrolment_tokens
    (id, name, purpose, token_hash, expires_at, max_uses, uses, allowed_domain, created_by, created_at)
values
    (gen_random_uuid(), '$name', '$purpose', '$hash', $expires, $max_uses, 0, $allowed,
     'script:new-enrol-token', now());

insert into audit_events
    (id, occurred_at, event_type, actor, subject_type, detail, is_exempt_from_retention)
values
    (gen_random_uuid(), now(), 'enrolment-token.created', 'script:new-enrol-token', 'EnrolmentToken',
     '{\"name\":\"$name\",\"purpose\":\"$purpose\",\"made\":\"by scripts/new-enrol-token.sh\"}', false);
"

docker compose exec -T postgres psql \
    -U "${POSTGRES_USER:-blinky}" -d "${POSTGRES_DB:-blinky}" -v ON_ERROR_STOP=1 -q <<EOF
$sql
EOF

echo "$token"
