#!/usr/bin/env bash
#
# Blinky lab - provision the Samba4 domain controller.
#
#     sudo bash provision-dc.sh
#
# Run once, on a machine that is going to be nothing but a domain controller.
# It installs Samba, provisions the domain, and then does the three things
# docs/09-lab.md calls not optional and easy to get wrong: time, DNS, and
# writing the realm down.
#
# Refuses to run twice. A second provision over the first produces a domain
# that half works, and the failures point at everything except the cause.

set -euo pipefail

REALM="${REALM:-BLINKY.LAB}"
DOMAIN="${DOMAIN:-BLINKY}"

# Where the DC forwards anything that is not the realm.
#
# A loopback address is refused, and that is not caution. On a second run this
# reads the configuration the first run left behind: /etc/resolv.conf by then
# points at systemd-resolved's stub on 127.0.0.53, which this same script
# switched off to give Samba port 53. Samba then forwards to an address where
# nothing is listening, the DC resolves its own realm perfectly and nothing
# else, and apt stops working on the machine that is meant to be rebuilt.
#
# Seen doing exactly that on the second provision of BY-DC01.
detect_forwarder() {
    local candidate
    candidate="$(resolvectl status 2>/dev/null |
        awk '/Current DNS Server:/ {print $4; exit}')"

    case "$candidate" in
        127.*|::1|"") return 1 ;;
        *) echo "$candidate" ;;
    esac
}

FORWARDER="${FORWARDER:-$(detect_forwarder || echo 1.1.1.1)}"

say() { printf '\n\033[1m%s\033[0m\n' "$*"; }

[[ $EUID -eq 0 ]] || { echo "Run this with sudo." >&2; exit 2; }

if [[ -f /var/lib/samba/private/sam.ldb ]]; then
    cat >&2 <<'EOF'
This machine is already a domain controller. Provisioning again on top of an
existing directory produces something that half works and fails later in ways
that point everywhere except here.

To start over deliberately:
    systemctl stop samba-ad-dc
    rm -rf /var/lib/samba/* /etc/samba/smb.conf
EOF
    exit 3
fi

say "1/6  time"

# Kerberos rejects a skew over five minutes and says nothing about clocks when
# it does. The DC is the source for the rest of the lab, so it has to be right
# before anything else is true.
apt-get update -qq
apt-get install -y -qq chrony >/dev/null
systemctl enable --now chrony >/dev/null
chronyc makestep >/dev/null 2>&1 || true
timedatectl | sed -n '1,3p'

say "2/6  packages"

# DEBIAN_FRONTEND so the samba package does not stop to ask about a realm it is
# about to be told properly by samba-tool.
DEBIAN_FRONTEND=noninteractive apt-get install -y -qq \
    samba smbclient ldb-tools krb5-user winbind libpam-winbind libnss-winbind \
    dnsutils >/dev/null

# An AD DC runs one daemon. The file-server ones fight it for the same sockets
# and the error message is about a port, not about a role.
systemctl disable --now smbd nmbd winbind >/dev/null 2>&1 || true
systemctl unmask samba-ad-dc >/dev/null 2>&1 || true

say "3/6  provision $REALM"

# The stock config is a file server's. samba-tool writes the right one and will
# not overwrite this.
mv /etc/samba/smb.conf /etc/samba/smb.conf.stock 2>/dev/null || true

password="$(openssl rand -base64 18 | tr -d '/+=' | head -c 20)Aa1!"

samba-tool domain provision \
    --realm="$REALM" \
    --domain="$DOMAIN" \
    --server-role=dc \
    --dns-backend=SAMBA_INTERNAL \
    --adminpass="$password" \
    --use-rfc2307 \
    --option="ad dc functional level = 2016"

# Root-only, because it is the domain administrator's password and the
# alternative is a terminal scrollback nobody clears.
umask 077
cat > /root/blinky-lab-dc.txt <<EOF
realm       $REALM
domain      $DOMAIN
admin       Administrator
password    $password
provisioned $(date -Is)
EOF

cp /var/lib/samba/private/krb5.conf /etc/krb5.conf

say "4/6  dns"

# Every member machine has to resolve the realm through this DC. Doing that
# starts with the DC resolving itself - and systemd-resolved's stub on
# 127.0.0.53 has to get out of the way of Samba's own server on 53.
mkdir -p /etc/systemd/resolved.conf.d
cat > /etc/systemd/resolved.conf.d/blinky-dc.conf <<EOF
[Resolve]
DNS=127.0.0.1
Domains=~$(echo "$REALM" | tr '[:upper:]' '[:lower:]')
DNSStubListener=no
EOF

ln -sf /run/systemd/resolve/resolv.conf /etc/resolv.conf
systemctl restart systemd-resolved

# Samba forwards everything that is not the realm.
if ! grep -q 'dns forwarder' /etc/samba/smb.conf; then
    sed -i "/^\[global\]/a\\        dns forwarder = $FORWARDER" /etc/samba/smb.conf
fi

say "5/6  start"

systemctl enable --now samba-ad-dc >/dev/null
sleep 3
systemctl is-active samba-ad-dc

say "6/6  check"

realm_lower="$(echo "$REALM" | tr '[:upper:]' '[:lower:]')"

samba-tool domain info 127.0.0.1

echo
echo "SRV records the members will look for:"
host -t SRV "_ldap._tcp.$realm_lower" 127.0.0.1 || true
host -t SRV "_kerberos._udp.$realm_lower" 127.0.0.1 || true

echo
echo "Kerberos:"
echo "$password" | kinit Administrator@"$REALM" 2>&1 | head -2 || true
klist 2>/dev/null | head -4 || true
kdestroy 2>/dev/null || true

cat <<EOF

  realm       $REALM
  domain      $DOMAIN
  credentials /root/blinky-lab-dc.txt   (root only)

Next, from docs/09-lab.md:
  - point every other machine's DNS at $(hostname -I | awk '{print $1}')
  - sync their clocks to this host
  - join the Windows client, then install the agent MSI on it
EOF
