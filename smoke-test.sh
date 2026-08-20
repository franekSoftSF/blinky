#!/usr/bin/env bash
# Proves the edge does what docs/01-architecture.md claims: blocks attacks on
# the console listener, does not block our own protocol on the agent listener,
# and refuses an agent with no client certificate.
#
# The API is a skeleton, so "not blocked" shows up as 404 from the API rather
# than 200. That is the point: 403 comes from the edge, 404 comes from behind
# it, and the difference is the whole test.
#
# Requests run from a container on the compose network rather than from the
# host, because Windows curl is built against Schannel and cannot load a PEM
# client certificate - the mTLS checks would fail for a reason that has nothing
# to do with the edge. One host-side check covers port publishing.
set -uo pipefail

cd "$(dirname "$0")"

NETWORK="${COMPOSE_PROJECT_NAME:-blinky}_default"
CURL_IMAGE="curlimages/curl:latest"
CONSOLE="https://edge:8443"
AGENT="https://edge:9443"

pass=0
fail=0

check() {
    local name="$1" expected="$2" actual="$3"
    if [ "$actual" = "$expected" ]; then
        printf '  ok    %-54s %s\n' "$name" "$actual"
        pass=$((pass + 1))
    else
        printf '  FAIL  %-54s got %s, expected %s\n' "$name" "$actual" "$expected"
        fail=$((fail + 1))
    fi
}

# Status code, seen from inside the compose network.
status() {
    MSYS_NO_PATHCONV=1 docker run --rm --network "$NETWORK" \
        -v "$(pwd)/certs:/certs:ro" "$CURL_IMAGE" \
        -sk -o /dev/null -w '%{http_code}' "$@" 2>/dev/null
}

if ! docker network inspect "$NETWORK" >/dev/null 2>&1; then
    echo "compose network $NETWORK not found - run: docker compose up -d"
    exit 1
fi

echo "console listener - WAF blocking"
check "health is served" 200 \
    "$(status "$CONSOLE/health")"
check "SQL injection in the query string is blocked" 403 \
    "$(status --get --data-urlencode "id=1' OR '1'='1" "$CONSOLE/health")"
check "path traversal is blocked" 403 \
    "$(status "$CONSOLE/health?f=../../etc/passwd")"
check "agent identity cannot be forged from the console" 401 \
    "$(status -H 'X-Client-Verify: SUCCESS' "$CONSOLE/api/agents/whoami")"

echo
echo "agent listener - mTLS"
check "no client certificate is refused" 400 \
    "$(status "$AGENT/api/agents/whoami")"
check "valid client certificate is identified" 200 \
    "$(status --cert /certs/test-agent.crt --key /certs/test-agent.key \
        "$AGENT/api/agents/whoami")"
check "an attack here is logged, not blocked (DetectionOnly)" 404 \
    "$(status --cert /certs/test-agent.crt --key /certs/test-agent.key \
        --get --data-urlencode "id=1' OR '1'='1" "$AGENT/api/jobs/next")"
check "a PKCS#10 body reaches the API, not the rule set" 404 \
    "$(status --cert /certs/test-agent.crt --key /certs/test-agent.key -X POST \
        -H 'Content-Type: application/pkcs10' \
        --data-binary @/certs/test-agent.crt "$AGENT/api/credentials/issue")"

echo
echo "api"
check "the schema validates against the database" '"valid":true' \
    "$(MSYS_NO_PATHCONV=1 docker run --rm --network "$NETWORK" "$CURL_IMAGE" \
        -sk "$CONSOLE/health" 2>/dev/null | grep -o '"valid":true' || echo missing)"

echo
echo "host"
check "console port is published" 200 \
    "$(curl -sk -o /dev/null -w '%{http_code}' \
        "https://localhost:${CONSOLE_PORT:-8443}/health")"

echo
if [ "$fail" -eq 0 ]; then
    echo "all $pass checks passed"
else
    echo "$fail of $((pass + fail)) checks failed"
fi
exit $((fail > 0))
