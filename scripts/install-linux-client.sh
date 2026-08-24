#!/usr/bin/env bash
#
# Blinky lab - everything a Linux client needs to test with a smart card.
#
#     sudo bash install-linux-client.sh
#     sudo bash install-linux-client.sh --desktop --anchors chain.pem
#
# Run after join-lab.sh. This is the reader stack, the PIV tooling, and the two
# pieces that make a token useful for logging in rather than only for looking
# at: PKINIT for Kerberos, and pam_pkcs11 for local authentication.
#
# It does not install the Blinky agent. That is patch 0017 - the agent talks to
# readers through winscard.dll and does not run here yet.

set -euo pipefail

REALM="${REALM:-BLINKY.LAB}"
DESKTOP=0
ANCHORS=""
REMOTE_READER=0

while [[ $# -gt 0 ]]; do
    case "$1" in
        # A machine with no desktop has no logon screen, and a smart-card logon
        # is a thing that happens at one. Found the hard way: the client was
        # joined, correct, and had nothing but a text console to prove it on.
        --desktop) DESKTOP=1; shift ;;

        # The CA chain, so PKINIT can check the KDC's certificate. Without it
        # the client refuses its own KDC and reports "No pkinit_anchors
        # supplied" - even when the real problem was a mistyped password.
        --anchors) ANCHORS="$2"; shift 2 ;;

        # Lets a session that is not sitting at this machine reach the reader.
        #
        # pcscd asks polkit, and polkit says yes to an active local session and
        # no to everything else. That is the right default: a reader is a thing
        # on somebody's desk, and a card in it belongs to whoever is standing
        # there. A person logging in at the greeter is unaffected either way.
        #
        # It is wrong for a machine driven over SSH, which is every machine in
        # this lab. Without it, opensc reports "No smart card readers found" for
        # a reader that is plugged in, working, and visible to root - a message
        # about hardware for what is entirely a question of authorisation.
        #
        # Off unless asked for, because it is a real widening: anybody who can
        # open a shell as this user can then talk to whatever card is in the
        # reader.
        --allow-remote-reader) REMOTE_READER=1; shift ;;

        --realm) REALM="$2"; shift 2 ;;
        *) echo "unknown argument: $1" >&2; exit 2 ;;
    esac
done

say() { printf '\n\033[1m%s\033[0m\n' "$*"; }

[[ $EUID -eq 0 ]] || { echo "Run this with sudo." >&2; exit 2; }

say "the reader"

# pcscd is the daemon everything else talks to; libccid is the driver for
# essentially every USB reader, including the one inside a YubiKey. Without the
# driver the daemon runs happily and sees nothing, which reads like a dead
# token.
DEBIAN_FRONTEND=noninteractive apt-get update -qq
DEBIAN_FRONTEND=noninteractive apt-get install -y -qq \
    pcscd libpcsclite1 libccid pcsc-tools usbutils >/dev/null

systemctl enable --now pcscd >/dev/null 2>&1 || true

say "PIV tooling"

# opensc gives pkcs11-tool and the PKCS#11 module; yubikey-manager gives ykman,
# which is the independent oracle this project checks its own reads against.
DEBIAN_FRONTEND=noninteractive apt-get install -y -qq \
    opensc opensc-pkcs11 yubikey-manager yubico-piv-tool gnutls-bin >/dev/null

say "Kerberos packages"

# PKINIT is the cheaper rung of the phase 2 gate: it proves the certificate on
# the card is one the KDC accepts, without needing a Windows client to blame
# when it does not work.
DEBIAN_FRONTEND=noninteractive apt-get install -y -qq \
    krb5-pkinit libpam-pkcs11 \
    libengine-pkcs11-openssl libnss3-tools sssd-tools >/dev/null

if [[ $DESKTOP -eq 1 ]]; then
    say "a desktop to log into"

    # ubuntu-desktop-minimal rather than the full one: this is a machine for
    # proving a card works, not somebody's workstation, and the difference is
    # about a gigabyte of things nobody here will open.
    DEBIAN_FRONTEND=noninteractive apt-get install -y -qq \
        ubuntu-desktop-minimal >/dev/null

    systemctl set-default graphical.target >/dev/null

    # gdm lists local accounts and offers "Not listed?" for everybody else. A
    # domain user types their name there; without this note somebody stares at
    # a list their account is not on and concludes the join failed.
    cat <<'EOF'

  A domain user does not appear in the list on the greeter. Choose
  "Not listed?" and type the account name.

EOF
fi

if [[ $REMOTE_READER -eq 1 ]]; then
    say "the reader, from a session that is not at this machine"

    install -d -m 755 /etc/polkit-1/rules.d

    cat > /etc/polkit-1/rules.d/50-blinky-pcsc.rules <<'RULE'
// Lets members of "sudo" reach the card reader from any session, including
// one arrived at over SSH.
//
// pcscd's default is to allow an active local session and refuse the rest,
// which is right for a workstation: the card is in a reader on somebody's
// desk. This file is for a machine being driven remotely, and it is a real
// widening - anybody who can open a shell as one of these users can talk to
// whatever card is in the reader.
//
// Written by scripts/install-linux-client.sh --allow-remote-reader. Delete
// the file and restart pcscd to put the default back.
polkit.addRule(function(action, subject) {
    if ((action.id == "org.debian.pcsc-lite.access_pcsc" ||
         action.id == "org.debian.pcsc-lite.access_card") &&
        subject.isInGroup("sudo")) {
        return polkit.Result.YES;
    }
});
RULE

    systemctl restart polkit 2>/dev/null || true
    systemctl restart pcscd 2>/dev/null || true

    echo "  members of 'sudo' can now reach the reader over SSH"
    echo "  delete /etc/polkit-1/rules.d/50-blinky-pcsc.rules to undo it"
fi

if [[ -n "$ANCHORS" ]]; then
    say "PKINIT anchors"

    [[ -f "$ANCHORS" ]] || { echo "No such file: $ANCHORS" >&2; exit 2; }

    bash "$(dirname "$0")/configure-krb5-client.sh" \
        --realm "$REALM" --anchors "$ANCHORS" 2>&1 | sed 's/^/  /'

    # Logging in with the card, not merely getting a ticket with one.
    #
    # On a domain-joined Ubuntu the thing in the PAM stack is sssd, not
    # pam_pkcs11 - common-auth calls pam_sss.so. Installing libpam-pkcs11 and
    # stopping there, which this script used to do, leaves a component nobody
    # configures and nothing consults, while the greeter asks for a card and
    # has nowhere to take it. What that looks like is GDM repeating "Please
    # (re)insert (different) Smartcard" at a card it can read perfectly.
    #
    # Three things, and Ubuntu ships the third: the CA sssd checks the card's
    # certificate against, the switch that makes it look at cards at all, and a
    # PAM profile that puts it in the stack. Following Omnissa's Horizon guide
    # for Ubuntu with SSSD, which is the same arrangement.
    say "logging in with the card"

    install -d -m 755 /etc/sssd/pki
    install -m 644 "$ANCHORS" /etc/sssd/pki/sssd_auth_ca_db.pem
    echo "  /etc/sssd/pki/sssd_auth_ca_db.pem"

    if [[ -f /etc/sssd/sssd.conf ]]; then
        cp /etc/sssd/sssd.conf /etc/sssd/sssd.conf.before-blinky

        if ! grep -q "^pam_cert_auth" /etc/sssd/sssd.conf; then
            if grep -q "^\[pam\]" /etc/sssd/sssd.conf; then
                sed -i "/^\[pam\]/a pam_cert_auth = True" /etc/sssd/sssd.conf
            else
                printf '\n[pam]\npam_cert_auth = True\n' >> /etc/sssd/sssd.conf
            fi

            echo "  sssd.conf: pam_cert_auth = True"
        else
            echo "  sssd.conf already asks for certificate authentication"
        fi

        chmod 600 /etc/sssd/sssd.conf
    else
        echo "  no /etc/sssd/sssd.conf - is this machine joined?" >&2
    fi

    # Optional rather than required: a card that will not read must not become
    # the only way into a machine, least of all while this is being set up.
    pam-auth-update --enable sss-smart-card-optional >/dev/null 2>&1 &&
        echo "  PAM: sss-smart-card-optional" ||
        echo "  PAM profile sss-smart-card-optional is not on this release" >&2

    systemctl restart sssd 2>/dev/null || true
fi

say "check"

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
the card is one the KDC accepts, without needing a Windows client to blame when
it does not.

It needs the KDC to hold a PKINIT certificate and to trust the CA. Both are
done on the domain controller by:

    sudo bash blinky-samba-setup.sh --from-url http://<cms-host>
    sudo bash blinky-samba-setup.sh --kdc-cert kdc.crt

and the second of those is what turns PKINIT on. A KDC holding a certificate
that nothing reads is a KDC that does not do PKINIT.
EOF
