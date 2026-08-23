#!/usr/bin/env bash
#
# Blinky lab - stand up the CA and the CMS on this machine.
#
#     sudo bash provision-cms.sh
#     sudo bash provision-cms.sh \
#         --directory-host by-dc01.blinky.lab \
#         --directory-base-dn DC=blinky,DC=lab \
#         --directory-bind-dn "CN=svc-blinky-ldap,CN=Users,DC=blinky,DC=lab" \
#         --directory-bind-password-file /root/svc-ldap.password
#
# Arguments beyond the first are handed to scripts/install-server.sh.
#
# Docker, the repository, and the certificates this machine answers to. Then
# scripts/install-server.sh, which does everything Blinky-specific.
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

say "1/4  docker"

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

say "2/4  repository"

if [[ -d "$TARGET/.git" ]]; then
    git -C "$TARGET" pull --ff-only
else
    git clone --quiet "$REPO" "$TARGET"
fi

cd "$TARGET"

say "3/4  certificates for $FQDN and $ADDRESS"

# Before install-server.sh, because it will keep whatever it finds and the
# names have to be right the first time. Every name and address anything
# will use to reach this machine has to be in the certificate: one missing
# here surfaces much later as an agent that will not connect, with an error
# about trust rather than about a name.
#
# The IP is in there because until the DC is serving the realm, the name
# does not resolve and the address is the only way in.
bash scripts/dev-certs.sh --force \
    --host "$FQDN" \
    --host "$ADDRESS" \
    --host "$(hostname -s)" \
    --host localhost

say "4/4  Blinky"

# Delegated rather than repeated. install-server.sh creates the service
# account, generates every secret, sets up and re-signs the CA, fixes the
# ownership that decides whether a container can read its own key material,
# starts the stack and checks it.
#
# This script used to do all of that itself, differently: an .env without a
# publication address or CRL settings, no blinky account, no pki directory,
# and an issuing CA with no subject key identifier and no distribution
# point. A machine provisioned that way reproduces, from scratch, every
# problem of 21 August - and the failures it produces name none of their
# causes.
# Anything else this was given goes straight through. Without that, the
# directory arguments - and every other option install-server.sh grew -
# are unreachable from the script people actually run, and the settings
# they configure end up hand-edited into .env after the fact. Which is the
# failure install-server.sh exists to prevent.
bash scripts/install-server.sh --hostname "$FQDN" "$@"

cat <<EOF

  console   https://$FQDN:8443   (also https://$ADDRESS:8443)
  agents    https://$FQDN:9443
  pki       http://$FQDN/pki/    (revocation list and CA certificate)
  secrets   $TARGET/.env         (root only)

Copy the CA that signs this machine's own certificate to every client -
without it nothing will trust the backend:

    scp $TARGET/certs/dev-ca.crt <client>:/tmp/

Then, on the domain controller:

    sudo bash scripts/blinky-samba-setup.sh --from-url http://$FQDN

EOF
