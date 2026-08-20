#!/usr/bin/env bash
#
# Blinky lab - stand up the CA and the CMS on this machine.
#
#     sudo bash provision-cms.sh
#
# Docker, the repository, the certificates, the secrets, the CA and the stack.
# Run on a machine that is going to be nothing but Blinky.
#
# The secrets are generated here and never committed. .env is written with
# permissions that keep it to root, because it holds the database password, the
# bootstrap token, the operator token and the key that protects every escrowed
# PUK - see docs/06-security.md.

set -euo pipefail

REPO="${REPO:-https://github.com/franekSoftSF/blinky.git}"
REALM="${REALM:-blinky.lab}"

# A checkout the person who runs this already has wins over a fresh one in
# /opt. They can pull it afterwards without sudo, which is the difference
# between updating the lab and asking somebody to update the lab.
if [[ -z "${TARGET:-}" ]]; then
    if [[ -n "${SUDO_USER:-}" && -d "/home/$SUDO_USER/blinky/.git" ]]; then
        TARGET="/home/$SUDO_USER/blinky"
    else
        TARGET="/opt/blinky"
    fi
fi

# Every name and address anything will use to reach this machine has to be in
# the certificate. A name missing here surfaces much later as an agent that
# will not connect, and the error talks about trust rather than about a name.
FQDN="${FQDN:-$(hostname -s | tr '[:upper:]' '[:lower:]').$REALM}"
ADDRESS="${ADDRESS:-$(hostname -I | awk '{print $1}')}"

say() { printf '\n\033[1m%s\033[0m\n' "$*"; }

[[ $EUID -eq 0 ]] || { echo "Run this with sudo." >&2; exit 2; }

say "1/6  docker"

if ! command -v docker >/dev/null 2>&1; then
    apt-get update -qq
    DEBIAN_FRONTEND=noninteractive apt-get install -y -qq \
        ca-certificates curl gnupg git openssl >/dev/null

    install -m 0755 -d /etc/apt/keyrings
    curl -fsSL https://download.docker.com/linux/ubuntu/gpg |
        gpg --dearmor -o /etc/apt/keyrings/docker.gpg
    chmod a+r /etc/apt/keyrings/docker.gpg

    echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] \
https://download.docker.com/linux/ubuntu $(. /etc/os-release && echo "$VERSION_CODENAME") stable" \
        > /etc/apt/sources.list.d/docker.list

    apt-get update -qq
    DEBIAN_FRONTEND=noninteractive apt-get install -y -qq \
        docker-ce docker-ce-cli containerd.io docker-buildx-plugin \
        docker-compose-plugin >/dev/null
fi

systemctl enable --now docker >/dev/null

# So the person who runs this can use docker afterwards without sudo. Takes
# effect at their next login, which is worth saying rather than leaving them to
# find out.
if [[ -n "${SUDO_USER:-}" ]]; then
    usermod -aG docker "$SUDO_USER"
fi

docker --version

say "2/6  repository"

if [[ -d "$TARGET/.git" ]]; then
    git -C "$TARGET" pull --ff-only
else
    git clone --quiet "$REPO" "$TARGET"
fi

cd "$TARGET"

say "3/6  secrets"

if [[ -f .env ]]; then
    echo ".env exists - keeping it. Delete it to start over."
else
    # Generated, never committed, and root-only. This file holds the database
    # password, the bootstrap token, the operator token, and the key that
    # protects every escrowed PUK.
    umask 077
    cat > .env <<EOF
POSTGRES_DB=blinky
POSTGRES_USER=blinky
POSTGRES_PASSWORD=$(openssl rand -base64 24 | tr -d '/+=')
CONSOLE_PORT=8443
AGENT_PORT=9443
BOOTSTRAP_TOKEN=$(openssl rand -base64 24 | tr -d '/+=')
OPERATOR_TOKEN=$(openssl rand -base64 24 | tr -d '/+=')
CA_PASSWORD=$(openssl rand -base64 18 | tr -d '/+=')
PUK_KEK=$(openssl rand -base64 32)
EOF
    echo "written, root only"
fi

say "4/6  certificates for $FQDN and $ADDRESS"

# The IP is in there because until the DC is serving the realm, the name does
# not resolve and the address is the only way in.
bash scripts/dev-certs.sh --force \
    --host "$FQDN" \
    --host "$ADDRESS" \
    --host "$(hostname -s)" \
    --host localhost

say "5/6  certificate authority"

if [[ -f ca/issuing.p12 ]]; then
    echo "ca/ exists - keeping it. A new CA would orphan every certificate issued so far."
else
    # Two tiers, because that is the shape a real deployment has and the one
    # where pathlen is easy to get wrong - better to have it wrong here than in
    # production. See docs/04-pki-backends.md.
    bash scripts/new-ca.sh --topology two-tier \
        --name "Blinky Lab" \
        --password "$(grep '^CA_PASSWORD=' .env | cut -d= -f2-)"
fi

say "6/6  start"

docker compose up -d --build

sleep 5
docker compose ps --format '{{.Service}}\t{{.Status}}'

cat <<EOF

  console   https://$FQDN:8443   (also https://$ADDRESS:8443)
  agents    https://$FQDN:9443
  secrets   $TARGET/.env         (root only)

Copy the CA that signs this machine's own certificate to every client - without
it nothing will trust the backend:

    scp $TARGET/certs/dev-ca.crt <client>:/tmp/

Smoke test:

    cd $TARGET && BLINKY_HOST=$ADDRESS ./smoke-test.sh
EOF
