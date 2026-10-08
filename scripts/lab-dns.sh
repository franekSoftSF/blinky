#!/usr/bin/env bash
#
# Blinky lab - name a machine that will never name itself.
#
#     sudo bash lab-dns.sh --add by-cacms 172.16.5.11
#     sudo bash lab-dns.sh --add by-win-client01 172.16.5.51
#     sudo bash lab-dns.sh --list
#
# Run on the domain controller.
#
# A machine that joins the domain registers its own A record and keeps it up to
# date. Everything else does not: the CMS host is a Docker host and not a
# domain member, a printer is a printer, and an appliance answers to a name
# somebody has to write down. Those records have to be created, and doing it by
# hand is how one gets forgotten and something fails later with an error about
# trust rather than about a name.
#
# Adds the PTR as well, in the reverse zone. A missing PTR is invisible until
# something canonicalises a host name, and then it is not an error but a wait -
# every lookup runs to a timeout, and the symptom is slowness somewhere that
# has no obvious connection to DNS.

set -euo pipefail

REALM="${REALM:-$(hostname -d | tr '[:lower:]' '[:upper:]')}"
ACTION=""
NAME=""
ADDRESS=""
PASSWORD="${DC_PASSWORD:-}"

while [[ $# -gt 0 ]]; do
    case "$1" in
        --add) ACTION="add"; NAME="$2"; ADDRESS="$3"; shift 3 ;;
        --remove) ACTION="remove"; NAME="$2"; shift 2 ;;
        --list) ACTION="list"; shift ;;
        --realm) REALM="$2"; shift 2 ;;
        --password) PASSWORD="$2"; shift 2 ;;
        *) echo "unknown argument: $1" >&2; exit 2 ;;
    esac
done

[[ $EUID -eq 0 ]] || { echo "Run this with sudo." >&2; exit 2; }
[[ -n "$ACTION" ]] || {
    cat >&2 <<'EOF'
usage:
    lab-dns.sh --add <name> <address>     name a machine, forward and reverse
    lab-dns.sh --remove <name>            take the name away
    lab-dns.sh --list                     what is in the zone

The name is the short one - "by-cacms", not "by-cacms.blinky.lab". The realm
comes from this machine's own domain unless --realm says otherwise.
EOF
    exit 2
}

command -v samba-tool >/dev/null || { echo "This is not a Samba DC." >&2; exit 3; }

realm_lower="$(echo "$REALM" | tr '[:upper:]' '[:lower:]')"

# The administrator password, from where provision-dc.sh left it: a root-only
# file, because the alternative is a terminal scrollback nobody clears. Read
# rather than asked for, and never echoed.
if [[ -z "$PASSWORD" && -f /root/blinky-lab-dc.txt ]]; then
    PASSWORD="$(awk '/^password /{print $2; exit}' /root/blinky-lab-dc.txt)"
fi

[[ -n "$PASSWORD" ]] || {
    cat >&2 <<'EOF'
No administrator password.

provision-dc.sh leaves it in /root/blinky-lab-dc.txt. If that file is gone,
pass --password or set DC_PASSWORD.
EOF
    exit 2
}

dns() { samba-tool dns "$@" -U Administrator --password="$PASSWORD"; }

# "Is there already a record?" - a question whose answer may legitimately be no.
#
# samba-tool exits non-zero when a name does not exist. Under set -e with
# pipefail that turns an ordinary "no" into a fatal error at the very
# assignment that asks the question, and because the query's stderr is
# discarded the script dies immediately after announcing what it was about to
# do. It reads as a success that quietly did nothing.
#
# Seen creating the first record for BY-CACMS: the header printed, no record
# was created, and the exit status was swallowed by a pipe to tail.
lookup() {
    local zone="$1" name="$2" type="$3"

    dns query 127.0.0.1 "$zone" "$name" "$type" 2>/dev/null |
        awk -v t="$type: " 'index($0, t) {print $2; exit}' | cut -d' ' -f1 || true
}

say() { printf '\n\033[1m%s\033[0m\n' "$*"; }

# --------------------------------------------------------------------- list

if [[ "$ACTION" == "list" ]]; then
    say "$realm_lower"
    dns query 127.0.0.1 "$realm_lower" @ ALL 2>/dev/null |
        grep -E "^  Name=|A: " | sed 's/^/  /'
    exit 0
fi

[[ -n "$NAME" ]] || { echo "A name is required." >&2; exit 2; }

# Short name, whatever was typed. A record created as "host.domain" inside the
# zone answers to "host.domain.domain", which resolves for nobody.
NAME="${NAME%%.*}"

# ------------------------------------------------------------------- remove

if [[ "$ACTION" == "remove" ]]; then
    say "removing $NAME.$realm_lower"

    existing="$(lookup "$realm_lower" "$NAME" A)"

    if [[ -z "$existing" ]]; then
        echo "  no such record"
        exit 0
    fi

    dns delete 127.0.0.1 "$realm_lower" "$NAME" A "$existing" >/dev/null
    echo "  $NAME.$realm_lower was $existing, now gone"
    exit 0
fi

# ---------------------------------------------------------------------- add

[[ "$ADDRESS" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]] || {
    echo "'$ADDRESS' is not an IPv4 address." >&2
    exit 2
}

say "$NAME.$realm_lower -> $ADDRESS"

# Replaced rather than added when one exists. Two A records for one name is a
# machine that answers on one address half the time, which is worse than either
# address being wrong.
existing="$(lookup "$realm_lower" "$NAME" A)"

if [[ -n "$existing" ]]; then
    if [[ "$existing" == "$ADDRESS" ]]; then
        echo "  already there"
    else
        dns update 127.0.0.1 "$realm_lower" "$NAME" A "$existing" "$ADDRESS" >/dev/null
        echo "  was $existing, now $ADDRESS"
    fi
else
    dns add 127.0.0.1 "$realm_lower" "$NAME" A "$ADDRESS" >/dev/null
    echo "  added"
fi

# ------------------------------------------------------------------- the ptr

IFS=. read -r o1 o2 o3 o4 <<< "$ADDRESS"
zone="$o3.$o2.$o1.in-addr.arpa"

if ! dns zoneinfo 127.0.0.1 "$zone" >/dev/null 2>&1; then
    dns zonecreate 127.0.0.1 "$zone" >/dev/null 2>&1 &&
        echo "  reverse zone $zone created"
fi

if dns zoneinfo 127.0.0.1 "$zone" >/dev/null 2>&1; then
    # Deleted first where one exists, because a PTR pointing at two names is a
    # reverse lookup that answers differently each time it is asked.
    old="$(lookup "$zone" "$o4" PTR)"

    if [[ -n "$old" ]]; then
        dns delete 127.0.0.1 "$zone" "$o4" PTR "$old" >/dev/null 2>&1 || true
    fi

    dns add 127.0.0.1 "$zone" "$o4" PTR "$NAME.$realm_lower." >/dev/null 2>&1 &&
        echo "  reverse $ADDRESS -> $NAME.$realm_lower"
else
    echo "  no reverse zone for $zone and it could not be created - forward only"
fi

# ------------------------------------------------------------------- check

# Asked of the running server rather than of the database, because the record
# that matters is the one a member machine can actually resolve.
#
# The previous form could not report a failure: host writes its error to stderr
# and exits non-zero, but the awk downstream succeeds on empty input, so the
# "|| echo not answering" fallback was unreachable. A check that has no way of
# saying no is decoration.
answer() {
    local got
    got="$(host "$1" 127.0.0.1 2>/dev/null | awk -v k="$2" 'index($0, k) {print $NF; exit}')"
    printf '%s' "${got:-not answering}"
}

forward="$(answer "$NAME.$realm_lower" 'has address')"

echo
echo "  forward  $forward"
echo "  reverse  $(answer "$ADDRESS" 'domain name pointer')"

# Non-zero when the name does not resolve, so a caller running this as one step
# of a sequence stops here instead of three steps further on, where the error
# will be about a trust or a certificate and not about a missing name.
if [[ "$forward" == "not answering" ]]; then
    echo
    echo "  $NAME.$realm_lower was not created - nothing will find it." >&2
    exit 1
fi
