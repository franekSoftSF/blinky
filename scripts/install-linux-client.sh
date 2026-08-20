#!/usr/bin/env bash
#
# Blinky lab - everything a Linux client needs to test with a smart card.
#
#     sudo bash install-linux-client.sh
#
# Run after join-lab.sh. This is the reader stack, the PIV tooling, and the two
# pieces that make a token useful for logging in rather than only for looking
# at: PKINIT for Kerberos, and pam_pkcs11 for local authentication.
#
# It does not install the Blinky agent. That is patch 0017 - the agent talks to
# readers through winscard.dll and does not run here yet.

set -euo pipefail

REALM="${REALM:-BLINKY.LAB}"

say() { printf '\n\033[1m%s\033[0m\n' "$*"; }

[[ $EUID -eq 0 ]] || { echo "Run this with sudo." >&2; exit 2; }

say "1/4  the reader"

# pcscd is the daemon everything else talks to; libccid is the driver for
# essentially every USB reader, including the one inside a YubiKey. Without the
# driver the daemon runs happily and sees nothing, which reads like a dead
# token.
DEBIAN_FRONTEND=noninteractive apt-get update -qq
DEBIAN_FRONTEND=noninteractive apt-get install -y -qq \
    pcscd libpcsclite1 libccid pcsc-tools usbutils >/dev/null

systemctl enable --now pcscd >/dev/null 2>&1 || true

say "2/4  PIV tooling"

# opensc gives pkcs11-tool and the PKCS#11 module; yubikey-manager gives ykman,
# which is the independent oracle this project checks its own reads against.
DEBIAN_FRONTEND=noninteractive apt-get install -y -qq \
    opensc opensc-pkcs11 yubikey-manager yubico-piv-tool gnutls-bin >/dev/null

say "3/4  Kerberos with a certificate"

# PKINIT is the cheaper rung of the phase 2 gate: it proves the certificate on
# the card is one the KDC accepts, without needing a Windows client to blame
# when it does not work.
DEBIAN_FRONTEND=noninteractive apt-get install -y -qq \
    krb5-pkinit libpam-pkcs11 >/dev/null

say "4/4  check"

systemctl is-active pcscd || true

echo
echo "Readers this machine can see:"
timeout 10 pcsc_scan -c 2>/dev/null | grep -iE "reader|card" | head -5 ||
    echo "  none - plug a token in, or pass one through to this VM"

echo
echo "PKCS#11 modules:"
ls /usr/lib/*/opensc-pkcs11.so /usr/lib/*/pkcs11/opensc-pkcs11.so 2>/dev/null | head -2

cat <<EOF

Installed. What this gets you:

  pcsc_scan                     watch a reader, live
  opensc-tool --list-readers    what the PC/SC layer sees
  piv-tool --serial             the token's serial, from the PIV applet
  ykman piv info                slots, policies, PIN retries

  kinit -X X509_user_identity=PKCS11:$(ls /usr/lib/*/opensc-pkcs11.so 2>/dev/null | head -1) \\
        user@$REALM

The last one is the phase 2 gate's cheaper rung: it proves the certificate on
the card is one the KDC accepts. It needs the KDC to hold a PKINIT certificate
and to trust Blinky's CA - both manual LDAP writes until patch 0061, described
in docs/04-pki-backends.md.
EOF
