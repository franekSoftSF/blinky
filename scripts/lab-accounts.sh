#!/usr/bin/env bash
#
# Blinky lab - the accounts a deployment actually needs.
#
#     sudo bash lab-accounts.sh
#     sudo bash lab-accounts.sh --user jkowalski --display "Jan Kowalski"
#
# Run on the domain controller, after provision-dc.sh.
#
# Two things, and the first is the one that gets skipped:
#
#   A service account for reading the directory. Blinky reads people out of AD
#   to resolve a UPN and a SID, and it never writes. An ordinary domain user
#   can already read what it needs - Authenticated Users have read on the
#   attributes involved - so the right account for this is a plain one with no
#   rights added at all. That is the whole point: the easiest account in the
#   world to ask a directory administrator for, and the easiest to audit.
#
#   A cardholder who is not an administrator. The first live issuance in this
#   lab was to Administrator, because that was the account that existed. It
#   proves the mechanism and proves nothing about the policy - an administrator
#   is a member of everything and can do everything, so a certificate that
#   works for one tells you very little. A plain user with a UPN is the honest
#   test.
#
# Both get a password generated here and written to a root-only file. Neither
# is printed.

set -euo pipefail

REALM="${REALM:-$(hostname -d | tr '[:lower:]' '[:upper:]')}"
SERVICE_ACCOUNT="${SERVICE_ACCOUNT:-svc-blinky-ldap}"
GROUP="${GROUP:-Card Holders}"
USER=""
DISPLAY=""

while [[ $# -gt 0 ]]; do
    case "$1" in
        --user) USER="$2"; shift 2 ;;
        --display) DISPLAY="$2"; shift 2 ;;
        --service-account) SERVICE_ACCOUNT="$2"; shift 2 ;;
        --group) GROUP="$2"; shift 2 ;;
        --realm) REALM="$2"; shift 2 ;;
        *) echo "unknown argument: $1" >&2; exit 2 ;;
    esac
done

[[ $EUID -eq 0 ]] || { echo "Run this with sudo." >&2; exit 2; }
command -v samba-tool >/dev/null || { echo "This is not a Samba DC." >&2; exit 3; }

realm_lower="$(echo "$REALM" | tr '[:upper:]' '[:lower:]')"
basedn="DC=${realm_lower//./,DC=}"
SAM=/var/lib/samba/private/sam.ldb
SECRETS=/root/blinky-lab-accounts.txt

# No administrator credentials anywhere in this script. samba-tool run as root
# on the controller writes to the local database directly, so asking for a
# password here would be a field that looks load-bearing and is not.

say()  { printf '\n\033[1m%s\033[0m\n' "$*"; }
note() { printf '  %s\n' "$*"; }

# A password the directory will accept without an argument about complexity,
# and that nobody has to type. Long, mixed, and generated - the three
# properties a service account's password should have and a person's cannot.
generate() {
    printf '%sAa1!' "$(openssl rand -base64 24 | tr -d '/+=' | head -c 24)"
}

umask 077
touch "$SECRETS"

exists() { samba-tool user list 2>/dev/null | grep -qx "$1"; }

# ---------------------------------------------------------- service account

say "the account that reads the directory"

if exists "$SERVICE_ACCOUNT"; then
    note "$SERVICE_ACCOUNT exists - leaving it and its password alone"
else
    service_password="$(generate)"

    samba-tool user create "$SERVICE_ACCOUNT" "$service_password" \
        --description="Blinky reads the directory as this account. Read-only by design." \
        >/dev/null

    # Never expires. A service account whose password ages out takes the
    # integration down some weeks later, at a moment nobody connects to a
    # password policy - and the error is about a bind, not about an expiry.
    samba-tool user setexpiry "$SERVICE_ACCOUNT" --noexpiry >/dev/null

    cat >> "$SECRETS" <<EOF

service account $SERVICE_ACCOUNT
dn              CN=$SERVICE_ACCOUNT,CN=Users,$basedn
password        $service_password
created         $(date -Is)
EOF

    note "created, password in $SECRETS"
fi

# No rights are granted here, and that is deliberate rather than unfinished.
# Reading a person's name, UPN and objectSid needs nothing beyond what any
# authenticated account already has. If a future patch writes to the directory
# it gets its own account and its own delegation - see docs/04, patch 0035.
note "no rights granted: reading needs none, and writing gets its own account"

# ------------------------------------------------------------- a cardholder

if [[ -n "$USER" ]]; then
    say "a cardholder who is not an administrator"

    if exists "$USER"; then
        note "$USER exists - leaving it alone"
    else
        user_password="$(generate)"
        display="${DISPLAY:-$USER}"

        samba-tool user create "$USER" "$user_password" \
            --given-name="${display%% *}" \
            --surname="${display##* }" \
            --use-username-as-cn \
            >/dev/null

        cat >> "$SECRETS" <<EOF

cardholder      $USER
upn             $USER@$realm_lower
password        $user_password
created         $(date -Is)
EOF

        note "created, password in $SECRETS"
    fi

    # The UPN, explicitly. samba-tool does not set one, and a certificate
    # without a UPN in its subject alternative name is refused for logon - by
    # which point the missing attribute is three steps behind the error.
    current_upn="$(ldbsearch -H "$SAM" "(sAMAccountName=$USER)" userPrincipalName 2>/dev/null |
        awk '/^userPrincipalName: /{print $2; exit}')"

    if [[ -z "$current_upn" ]]; then
        cat > /tmp/blinky-upn.$$ <<LDIF
dn: CN=$USER,CN=Users,$basedn
changetype: modify
add: userPrincipalName
userPrincipalName: $USER@$realm_lower
LDIF
        ldbmodify -H "$SAM" /tmp/blinky-upn.$$ >/dev/null &&
            note "userPrincipalName set to $USER@$realm_lower"
        rm -f /tmp/blinky-upn.$$
    else
        note "userPrincipalName already $current_upn"
    fi

    # A group, so the console's "test these people" button has a real set to
    # point at rather than a list somebody types.
    if ! samba-tool group list 2>/dev/null | grep -qx "$GROUP"; then
        samba-tool group add "$GROUP" \
            --description="People Blinky issues cards to." >/dev/null
        note "group '$GROUP' created"
    fi

    samba-tool group addmembers "$GROUP" "$USER" >/dev/null 2>&1 || true
    note "$USER is in '$GROUP'"
fi

# -------------------------------------------------------------------- check

say "what the directory now says"

for account in "$SERVICE_ACCOUNT" ${USER:+"$USER"}; do
    upn="$(ldbsearch -H "$SAM" "(sAMAccountName=$account)" userPrincipalName 2>/dev/null |
        awk '/^userPrincipalName: /{print $2; exit}')"
    sid="$(ldbsearch -H "$SAM" "(sAMAccountName=$account)" objectSid 2>/dev/null |
        awk '/^objectSid: /{print $2; exit}')"

    printf '  %-20s upn=%-28s sid=%s\n' \
        "$account" "${upn:-none}" "${sid:-none}"
done

chmod 600 "$SECRETS"

cat <<EOF

Passwords are in $SECRETS, readable by root only.

For the CMS host's .env - the bind DN, not the password, which is read from
that file when you need it:

    DIRECTORY_HOST=$(hostname -f)
    DIRECTORY_BASE_DN=$basedn
    DIRECTORY_SOURCE=Samba4
    DIRECTORY_BIND_DN=CN=$SERVICE_ACCOUNT,CN=Users,$basedn

Leaving DIRECTORY_BIND_DN empty instead binds with the container's own Kerberos
credentials, which is better where it can be arranged: no password travels and
none is stored.
EOF
