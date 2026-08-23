#!/usr/bin/env bash
#
# Blinky - install the server on a fresh machine.
#
#     sudo bash scripts/install-server.sh
#     sudo bash scripts/install-server.sh --hostname by-cacms.blinky.lab
#
#     sudo bash scripts/install-server.sh \
#         --issuing-p12 issuing.p12 --anchor corporate-root.crt \
#         --edge-cert wildcard.crt --edge-key wildcard.key
#
#     sudo bash scripts/install-server.sh \
#         --directory-host by-dc01.blinky.lab \
#         --directory-base-dn DC=blinky,DC=lab \
#         --directory-bind-dn "CN=svc-blinky-ldap,CN=Users,DC=blinky,DC=lab" \
#         --directory-bind-password-file /root/svc-ldap.password
#
# scripts/lab-accounts.sh creates that account on the domain controller and
# leaves its password in /root/blinky-lab-accounts.txt. Copy the one line, not
# the file.
#
# Creates the service account, generates every secret, sets up the CA, starts
# the stack and checks it. Idempotent: run it again and it changes what is
# wrong and leaves what is right, including every secret it already generated.
#
# Neither certificate authority has to be Blinky's. An organisation that
# already has a root gives Blinky an issuing CA under it and keeps the root
# where it is - which is the correct arrangement and the one this should not
# ask anybody to abandon. Infrastructure TLS is separable the same way: the
# self-signed pair is a convenience for a lab, not a design.
#
# This exists because doing it by hand went wrong in the same four ways every
# time:
#
#   - .env written a line at a time, so a value was missing until something
#     failed for a reason that named neither the value nor the file
#   - directories owned by root that a container running as an ordinary user
#     cannot read, reported as "does not hold a CA" rather than as a permission
#   - the root key readable by a container that has no business holding it
#   - passwords typed by a person, which means remembered by a person, which
#     means the same one twice
#
# Nothing here is interactive and nothing here prints a secret. What it
# generates goes into a file only root can read, and the file says where.

set -euo pipefail

# The uid the containers run as - see docker/dotnet/Dockerfile. The host
# account is given the same number on purpose: a bind mount carries numbers,
# not names, and "the container cannot write here" is otherwise a puzzle rather
# than a permission.
BLINKY_UID=10001
BLINKY_GID=10001

# The uid the edge container runs as. Not ours to choose: it comes from
# owasp/modsecurity-crs:nginx, and it appears here as a bare number because a
# number is all a bind mount carries across a container boundary.
EDGE_GID="${EDGE_GID:-101}"

HOSTNAME_FQDN=""
CA_NAME="${CA_NAME:-Blinky}"
IMPORT_P12=""
IMPORT_P12_PASSWORD=""
IMPORT_ANCHOR=""
EDGE_CERT=""
EDGE_CERT_REPLACED=0
EDGE_KEY=""
DIRECTORY_HOST=""
DIRECTORY_BASE_DN=""
DIRECTORY_BIND_DN=""
DIRECTORY_BIND_PASSWORD=""
DIRECTORY_SOURCE="Samba4"
DIRECTORY_TLS="true"
FORCE_SECRETS=0
SKIP_UP=0

while [[ $# -gt 0 ]]; do
    case "$1" in
        --hostname) HOSTNAME_FQDN="$2"; shift 2 ;;
        --ca-name) CA_NAME="$2"; shift 2 ;;

        # An issuing CA that came from somewhere else - a corporate root, an
        # offline ceremony, an HSM export. Blinky signs with it and never sees
        # the root key, which is the arrangement a real organisation already has
        # and should not be asked to abandon in order to run this.
        --issuing-p12) IMPORT_P12="$2"; shift 2 ;;
        --issuing-p12-password) IMPORT_P12_PASSWORD="$2"; shift 2 ;;
        --anchor) IMPORT_ANCHOR="$2"; shift 2 ;;

        # Infrastructure TLS from a real CA rather than the self-signed pair.
        --edge-cert) EDGE_CERT="$2"; shift 2 ;;
        --edge-key) EDGE_KEY="$2"; shift 2 ;;

        # The directory Blinky reads people out of, so that a logon certificate
        # can carry a SID somebody read rather than typed. Read-only: the
        # account named here needs nothing but read, which is what makes it an
        # easy thing to ask a directory administrator for.
        #
        # Set here rather than hand-edited into .env afterwards. A value added
        # to that file a line at a time is a value that is missing until
        # something fails for a reason that names neither the value nor the
        # file - which is the failure this whole script exists to prevent.
        --directory-host) DIRECTORY_HOST="$2"; shift 2 ;;
        --directory-base-dn) DIRECTORY_BASE_DN="$2"; shift 2 ;;
        --directory-bind-dn) DIRECTORY_BIND_DN="$2"; shift 2 ;;
        # A file, not a value. A password given as an argument is visible in
        # ps for as long as this runs and stays in shell history afterwards -
        # and the whole point of the account it belongs to is that it is easy
        # to hand over safely.
        --directory-bind-password-file)
            [[ -f "$2" ]] || { echo "No such file: $2" >&2; exit 2; }
            DIRECTORY_BIND_PASSWORD="$(head -n1 "$2")"
            shift 2 ;;

        # Still accepted, because a pipeline sometimes has nowhere to put a
        # file. Named so the cost is visible at the call site.
        --directory-bind-password-unsafe) DIRECTORY_BIND_PASSWORD="$2"; shift 2 ;;
        --directory-source) DIRECTORY_SOURCE="$2"; shift 2 ;;

        # For a directory that does not offer StartTLS. Refused in combination
        # with a bind password, because that is a password in the clear.
        --directory-no-tls) DIRECTORY_TLS="false"; shift ;;
        --regenerate-secrets) FORCE_SECRETS=1; shift ;;
        --no-start) SKIP_UP=1; shift ;;
        *) echo "unknown argument: $1" >&2; exit 2 ;;
    esac
done

[[ $EUID -eq 0 ]] || { echo "Run this with sudo." >&2; exit 2; }

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$root"

# Left to itself, umask can make .env and the CA readable by nobody, or by
# everybody. This lab has been bitten by both.
umask 077

say()  { printf '\n\033[1m%s\033[0m\n' "$*"; }
note() { printf '  %s\n' "$*"; }

[[ -n "$HOSTNAME_FQDN" ]] || HOSTNAME_FQDN="$(hostname -f 2>/dev/null || hostname)"

# ------------------------------------------------------------------ 1. user

say "1/6  the service account"

if id blinky >/dev/null 2>&1; then
    note "blinky exists (uid $(id -u blinky))"

    if [[ "$(id -u blinky)" != "$BLINKY_UID" ]]; then
        cat >&2 <<EOF

  blinky has uid $(id -u blinky) and the containers run as $BLINKY_UID.

  Bind mounts carry numbers rather than names, so the two have to agree. Either
  change the account's uid, or change the Dockerfile - but not neither, because
  the failure is a container that cannot read a directory it can see.
EOF
        exit 3
    fi
else
    groupadd --gid "$BLINKY_GID" blinky 2>/dev/null || true

    # No login, no home, no shell. It exists to own files.
    useradd --uid "$BLINKY_UID" --gid "$BLINKY_GID" \
        --no-create-home --shell /usr/sbin/nologin \
        --comment "Blinky credential management" blinky

    note "created blinky (uid $BLINKY_UID)"
fi

# Whoever is running this keeps being able to drive docker afterwards.
if getent group docker >/dev/null && [[ -n "${SUDO_USER:-}" ]]; then
    if ! id -nG "$SUDO_USER" | grep -qw docker; then
        usermod -aG docker "$SUDO_USER"
        note "$SUDO_USER added to the docker group - log out and back in"
    fi
fi

# --------------------------------------------------------------- 2. secrets

say "2/6  secrets"

secret() { openssl rand -base64 "${1:-24}" | tr -d '\n=' | tr '+/' '-_'; }

if [[ -f .env && $FORCE_SECRETS -eq 0 ]]; then
    note ".env exists - keeping every value already in it"
else
    [[ -f .env ]] && cp .env ".env.replaced-$(date +%Y%m%d%H%M%S)"
    : > .env
fi

# Added only when absent, so a re-run fills gaps without rotating anything.
# Rotating a secret in place is not a small act: POSTGRES_PASSWORD locks the
# database out of itself, PUK_KEK makes every escrowed PUK undecryptable, and
# neither failure says so.
ensure() {
    local key="$1" value="$2"

    if grep -q "^$key=" .env 2>/dev/null; then
        return
    fi

    printf '%s=%s\n' "$key" "$value" >> .env
    note "$key generated"
}

# For values passed on the command line. Unlike ensure, this replaces: a
# directory host typed wrongly the first time has to be fixable by running the
# script again, and "it keeps whatever is there" would make that impossible.
set_value() {
    local key="$1" value="$2"

    if grep -q "^$key=" .env 2>/dev/null; then
        # The delimiter is a vertical bar because a distinguished name is full
        # of commas and equals signs and a base DN is full of neither of these.
        sed -i "s|^$key=.*|$key=$value|" .env
    else
        printf '%s=%s\n' "$key" "$value" >> .env
    fi
}

ensure POSTGRES_DB blinky
ensure POSTGRES_USER blinky
ensure POSTGRES_PASSWORD "$(secret 24)"

# What an agent presents once, to get an identity it then uses instead.
ensure BOOTSTRAP_TOKEN "$(secret 24)"

# What the console and any operator tooling presents on every call.
ensure OPERATOR_TOKEN "$(secret 24)"

# The CA's PKCS#12 password. Not a person's password: nothing types it.
ensure CA_PASSWORD "$(secret 24)"

# The key that encrypts every escrowed PUK. Exactly 32 bytes, base64, because
# it is an AES-256 key rather than a passphrase - and if this is ever lost,
# every escrowed PUK is lost with it.
ensure PUK_KEK "$(openssl rand -base64 32)"

# The address written into every certificate as its distribution point. Has to
# be one a relying party resolves, over HTTP - see CaPublication.
ensure CA_PUBLIC_URL "http://$HOSTNAME_FQDN"

ensure CRL_VALIDITY_HOURS 8
ensure CRL_REFRESH_HOURS 2

if [[ -n "$DIRECTORY_HOST" ]]; then
    [[ -n "$DIRECTORY_BASE_DN" ]] || {
        echo "--directory-host needs --directory-base-dn: a search with no base" >&2
        echo "searches nothing." >&2
        exit 2
    }

    # A simple bind sends the password, so it may not cross an unencrypted
    # connection. Refused here rather than at the first search, where the
    # message would be about a bind and not about this decision.
    if [[ -n "$DIRECTORY_BIND_PASSWORD" && "$DIRECTORY_TLS" != "true" ]]; then
        echo "A bind password over an unencrypted connection would send it in the" >&2
        echo "clear. Drop --directory-no-tls, or leave the bind DN empty and let it" >&2
        echo "bind with Kerberos." >&2
        exit 2
    fi

    set_value DIRECTORY_HOST "$DIRECTORY_HOST"
    set_value DIRECTORY_BASE_DN "$DIRECTORY_BASE_DN"
    set_value DIRECTORY_SOURCE "$DIRECTORY_SOURCE"
    set_value DIRECTORY_BIND_DN "$DIRECTORY_BIND_DN"
    set_value DIRECTORY_BIND_PASSWORD "$DIRECTORY_BIND_PASSWORD"
    set_value DIRECTORY_USE_TLS "$DIRECTORY_TLS"

    if [[ -n "$DIRECTORY_BIND_DN" ]]; then
        note "directory $DIRECTORY_HOST, binding as $DIRECTORY_BIND_DN"
    else
        note "directory $DIRECTORY_HOST, binding with Kerberos - no password stored"
    fi
fi

chown root:root .env
chmod 600 .env

note "$(grep -c '=' .env) values in .env, readable by root only"

# ------------------------------------------------------------------- 3. ca

say "3/6  certificate authority"

ca_password="$(grep '^CA_PASSWORD=' .env | cut -d= -f2-)"
public_url="$(grep '^CA_PUBLIC_URL=' .env | cut -d= -f2-)"

if [[ -n "$IMPORT_P12" ]]; then
    [[ -f "$IMPORT_P12" ]] || { echo "No such file: $IMPORT_P12" >&2; exit 2; }
    [[ -n "$IMPORT_ANCHOR" && -f "$IMPORT_ANCHOR" ]] || {
        echo "--issuing-p12 needs --anchor: the root it chains to." >&2
        exit 2
    }

    install -d -m 750 ca

    # Re-wrapped with the password from .env, so nothing else has to know the
    # one the file arrived with - and that one is not written down here.
    openssl pkcs12 -in "$IMPORT_P12" -passin "pass:$IMPORT_P12_PASSWORD" -nodes 2>/dev/null |
        openssl pkcs12 -export -out ca/issuing.p12 -passout "pass:$ca_password" 2>/dev/null || {
            echo "Could not read $IMPORT_P12 - wrong password?" >&2
            exit 3
        }

    cp "$IMPORT_ANCHOR" ca/anchor.crt
    openssl pkcs12 -in ca/issuing.p12 -passin "pass:$ca_password" -nokeys -clcerts \
        -out ca/issuing.crt 2>/dev/null
    cat ca/issuing.crt ca/anchor.crt > ca/chain.pem

    openssl verify -CAfile ca/anchor.crt ca/issuing.crt >/dev/null 2>&1 || {
        echo "The issuing CA does not verify against the anchor given." >&2
        exit 3
    }

    note "imported: $(openssl x509 -in ca/issuing.crt -noout -subject | sed 's/^subject=//')"
    note "anchored: $(openssl x509 -in ca/anchor.crt -noout -subject | sed 's/^subject=//')"

    # No root CRL, and that is correct rather than missing. Blinky signs the
    # issuing CA's list because it holds that key; the root's list belongs to
    # whoever holds the root, and publishing an empty one here would be this
    # installation making a statement about a CA it does not run.
    #
    # /pki/root.crl answers 404 in this arrangement, and the imported issuing
    # certificate should carry a distribution point pointing wherever its own
    # root publishes.
    note "root CRL: not ours - the root is external and publishes its own"

    # Not re-signed. Adding extensions to somebody else's intermediate needs
    # their root key, which is the whole reason it is theirs. If it arrived
    # without a distribution point that is for them to fix, and worth saying
    # rather than silently issuing under it.
    for ext in crlDistributionPoints authorityInfoAccess; do
        openssl x509 -in ca/issuing.crt -noout -ext "$ext" >/dev/null 2>&1 || cat <<EOF

  The imported issuing CA has no $ext.

  Certificates issued under it will still chain, and Windows will still report
  CERT_TRUST_REVOCATION_STATUS_UNKNOWN for the CA itself - which refuses a
  smart-card logon. Ask whoever issued it for one that carries it; this script
  cannot add it, because that needs their root key.

EOF
    done
elif [[ -f ca/issuing.p12 ]]; then
    note "ca/ exists - keeping it"

    CA_PASSWORD="$ca_password" bash scripts/resign-issuing-ca.sh \
        --public-url "$public_url" 2>&1 |
        grep -E "issuing CA (was|now)|root CRL" | sed 's/^/  /' || true
else
    CA_PASSWORD="$ca_password" \
        bash scripts/new-ca.sh --name "$CA_NAME" --topology two-tier >/dev/null
    note "two-tier CA created: $CA_NAME Root CA, $CA_NAME Issuing CA"

    # Anything already published belongs to the CA that just stopped existing.
    #
    # A revocation list outlives the key that signed it as a file, and a
    # replaced CA leaves one behind that fetches perfectly and verifies against
    # nothing. That is worse than no list at all: a 404 makes a client say it
    # cannot determine revocation, while a stale list is taken as an answer
    # right up to the moment something checks the signature - and then the
    # failure is about revocation, several steps away from this directory.
    #
    # Seen on BY-CACMS, where the installer called the list published because
    # something answered on the URL.
    if compgen -G "pki/*.crl" >/dev/null; then
        rm -f pki/*.crl
        note "cleared the lists the previous CA had published"
    fi

    CA_PASSWORD="$ca_password" bash scripts/resign-issuing-ca.sh \
        --public-url "$public_url" 2>&1 |
        grep -E "issuing CA (was|now)|root CRL" | sed 's/^/  /' || true
fi

if [[ -n "$EDGE_CERT" ]]; then
    [[ -f "$EDGE_CERT" && -f "$EDGE_KEY" ]] || {
        echo "--edge-cert needs --edge-key, and both have to exist." >&2
        exit 2
    }

    install -d -m 750 certs
    install -m 640 "$EDGE_CERT" certs/edge.crt
    install -m 640 "$EDGE_KEY" certs/edge.key

    openssl x509 -in certs/edge.crt -noout -checkend 0 >/dev/null 2>&1 ||
        note "WARNING: the certificate given has already expired"

    note "edge certificate: $(openssl x509 -in certs/edge.crt -noout -subject | sed 's/^subject=//')"
elif [[ ! -f certs/edge.crt ]]; then
    # The name agents and browsers actually use has to be in the certificate,
    # or every connection fails on the name rather than on the trust - and the
    # message says the certificate is invalid, which sends people to the CA.
    # dev-certs.sh first, because it also mints the CA the edge trusts for
    # agent client certificates and one test client - neither of which the
    # issuing CA produces. Its edge certificate is then replaced.
    bash scripts/dev-certs.sh --host "$HOSTNAME_FQDN" >/dev/null 2>&1 || true

    # The edge's own certificate, from the CA this installation uses.
    #
    # What dev-certs.sh leaves behind is signed by a throwaway called "Blinky
    # development CA", unrelated to the issuing CA everything else chains to.
    # The lab then has two trust roots, and the one protecting the agent's
    # connection is the one nobody manages or revokes. It also hands nginx a
    # bare leaf, so every client reports "unable to verify the first
    # certificate" - a missing intermediate, which adding the anchor to the
    # client's store does not fix.
    #
    # Only when this installation has its own CA. An external issuing CA gets
    # asked for the edge certificate through --edge-cert instead; nothing here
    # can sign on its behalf.
    if [[ -f ca/issuing.p12 ]]; then
        if CA_PASSWORD="$ca_password" bash scripts/issue-edge-cert.sh                 --host "$HOSTNAME_FQDN" --host "$(hostname -I | awk '{print $1}')"                 --public-url "$public_url" 2>&1 | sed 's/^/  /'; then
            note "edge certificate issued by $CA_NAME Issuing CA, chain included"
            EDGE_CERT_REPLACED=1
        else
            note "could not issue an edge certificate - the development one stands"
        fi
    else
        note "edge certificates generated for $HOSTNAME_FQDN (development CA)"
    fi
else
    if ! openssl x509 -in certs/edge.crt -noout -text 2>/dev/null |
            grep -q "$HOSTNAME_FQDN"; then
        cat <<EOF

  certs/edge.crt does not carry $HOSTNAME_FQDN. Agents connecting by that name
  will refuse it, and the error will be about the certificate rather than about
  the name. To replace it:

      bash scripts/dev-certs.sh --force --host $HOSTNAME_FQDN

EOF
    fi
fi

# ----------------------------------------------------------- 4. permissions

say "4/6  who can read what"

install -d -o "$BLINKY_UID" -g "$BLINKY_GID" -m 755 pki

# The containers read the CA through a read-only mount. They need the issuing
# key to sign with and the certificates to publish; they do not need the root
# key, and a two-tier CA whose root key is readable by an online service is a
# single-tier CA with extra steps.
chown root:root ca
chmod 750 ca

for f in anchor.crt chain.pem issuing.crt issuing.p12 root.crl; do
    [[ -f "ca/$f" ]] || continue
    chown "root:$BLINKY_GID" "ca/$f"
    chmod 640 "ca/$f"
done

chgrp "$BLINKY_GID" ca

for f in root.key anchor.srl issuing.key; do
    [[ -f "ca/$f" ]] || continue
    chown root:root "ca/$f"
    chmod 600 "ca/$f"
done

note "ca/     issuing material readable by blinky, root key not"
note "pki/    writable by blinky - the published revocation list lives here"

if [[ -d certs ]]; then
    chown -R "root:$BLINKY_GID" certs
    chmod 640 certs/* 2>/dev/null || true

    # Traversable but not listable. The edge opens its files by path and never
    # reads the directory, so nothing here needs to be enumerable.
    chmod 751 certs

    # The edge is a third-party image - owasp/modsecurity-crs:nginx - and runs
    # as its own uid, nginx 101, which is neither root nor blinky. It is not
    # ours to change, so the three files it opens are granted to it by number.
    #
    # Without this, nginx fails at startup with "cannot load certificate ...
    # Permission denied", the whole edge exits, and every check that follows
    # reports 000 rather than a refusal - so the installation looks like a
    # network fault instead of a file mode. Seen on BY-CACMS.
    for f in edge.crt edge.key agent-ca.crt; do
        [[ -f "certs/$f" ]] || continue
        chown "root:$EDGE_GID" "certs/$f"
        chmod 640 "certs/$f"
    done

    note "certs/  readable by blinky; the edge's three by nginx ($EDGE_GID)"
fi

# --------------------------------------------------------------- 5. the app

if [[ $SKIP_UP -eq 1 ]]; then
    say "5/6  skipped (--no-start)"
else
    say "5/6  starting"

    docker compose up -d --build 2>&1 | grep -E "Started|Error" | sed 's/^/  /' || true

    # nginx reads its certificate once, at startup, and the certificate lives
    # on a bind mount. Replacing the file changes nothing that is already
    # running, and "docker compose up -d" leaves a container alone when its
    # configuration has not changed - so a freshly issued certificate sits on
    # disk while the edge keeps presenting the old one, indefinitely.
    #
    # Caught with openssl s_client, which still showed the development
    # certificate several minutes after the installer reported issuing a new
    # one. Nothing in the output was wrong; the two facts simply belonged to
    # different processes.
    if [[ $EDGE_CERT_REPLACED -eq 1 ]]; then
        docker compose restart edge >/dev/null 2>&1 &&
            note "edge restarted so it picks up the new certificate"
    fi
fi

# ----------------------------------------------------------------- 6. check

say "6/6  checking"

ok=0
fail=0

check() {
    local what="$1" got="$2" want="$3"

    if [[ "$got" == "$want" ]]; then
        printf '  ok    %-46s %s\n' "$what" "$got"
        ok=$((ok + 1))
    else
        printf '  FAIL  %-46s got %s, wanted %s\n' "$what" "$got" "$want"
        fail=$((fail + 1))
    fi
}

if [[ $SKIP_UP -eq 0 ]]; then
    # Waited for rather than slept through. The API validates its schema and
    # the worker publishes its first list before either answers usefully, and
    # how long that takes depends on the machine.
    for _ in $(seq 1 30); do
        [[ "$(curl -sk -o /dev/null -w '%{http_code}'             "https://localhost:${CONSOLE_PORT:-8443}/health" 2>/dev/null)" == "200" ]] && break
        sleep 2
    done

    # Anything that exited, named before the checks run.
    #
    # curl reports 000 for "nothing answered", which is the same code for a
    # container that never started, one still starting, and a firewall. Every
    # check below then fails with a number that describes none of them - and
    # the installation reads as a network fault when it is a container that
    # died with a perfectly clear message in its own log.
    #
    # Seen on BY-CACMS: nginx could not read its certificate and the edge
    # exited, so four checks reported 000 and none of them said so.
    dead="$(docker compose ps -a --format '{{.Service}} {{.Status}}' 2>/dev/null |
        awk '/Exited|Restarting/ {print $1}' || true)"

    if [[ -n "$dead" ]]; then
        echo
        for svc in $dead; do
            printf '  %s is not running. Its last words:
' "$svc"
            docker compose logs --tail 3 "$svc" 2>&1 | sed 's/^/      /'
        done
        echo
    fi

    check "the console answers" \
        "$(curl -sk -o /dev/null -w '%{http_code}' "https://localhost:${CONSOLE_PORT:-8443}/health")" 200

    check "the CA certificate is published" \
        "$(curl -s -o /dev/null -w '%{http_code}' "http://localhost:${PKI_PORT:-80}/pki/issuing.crt")" 200

    check "the revocation list is published" \
        "$(curl -s -o /dev/null -w '%{http_code}' "http://localhost:${PKI_PORT:-80}/pki/issuing.crl")" 200

    # Fetched is not the same as valid. A list signed by a CA that has since
    # been replaced still answers 200, and every client believes it until one
    # verifies the signature. Asking here costs one openssl call and moves that
    # discovery from a workstation's logon refusal to this line.
    crl_ok=no
    if curl -s "http://localhost:${PKI_PORT:-80}/pki/issuing.crl" -o /tmp/blinky-check.crl 2>/dev/null; then
        # The text, not the exit status. "openssl crl -CAfile" prints
        # "verify failure" and then exits 0 - so a check written the obvious
        # way passes on a list that verifies against nothing, which is the
        # exact failure this check was added to catch. It did, on the first
        # run of this very block.
        case "$(openssl crl -in /tmp/blinky-check.crl -inform DER -CAfile ca/issuing.crt -noout 2>&1)" in
            *"verify OK"*) crl_ok=yes ;;
        esac
    fi
    rm -f /tmp/blinky-check.crl

    check "that list was signed by this CA" "$crl_ok" yes

    check "the root's list is published" \
        "$(curl -s -o /dev/null -w '%{http_code}' "http://localhost:${PKI_PORT:-80}/pki/root.crl")" 200

    # The one that catches today's mistake: a container that cannot read the CA
    # reports "does not hold a CA", which sends somebody to look at the CA.
    check "the API can read the CA" \
        "$(docker compose exec -T api sh -c 'head -c1 /etc/blinky/ca/issuing.p12 >/dev/null 2>&1 && echo yes || echo no')" yes

    check "the API cannot read the root key" \
        "$(docker compose exec -T api sh -c 'head -c1 /etc/blinky/ca/root.key >/dev/null 2>&1 && echo yes || echo no')" no

    check "the worker can write the revocation list" \
        "$(docker compose exec -T worker sh -c 'test -w /var/lib/blinky/pki && echo yes || echo no')" yes
fi

echo
if [[ $fail -eq 0 ]]; then
    printf '  \033[1mall %d checks passed\033[0m\n' "$ok"
else
    printf '  \033[1m%d of %d checks failed\033[0m\n' "$fail" "$((ok + fail))"
fi

cat <<EOF

Secrets are in $root/.env, readable by root only. To read one:

    sudo grep ^BOOTSTRAP_TOKEN= $root/.env

Nothing else on this machine needs them, and nothing prints them. If one has to
travel - a bootstrap token to a workstation - it travels once and the agent
never needs it again.

The certificate authority in use:

    $(if [[ -f ca/root.key ]]; then
        echo "Blinky's own, both tiers. It signs the issuing CA's revocation"
        echo "    list and the root's, and publishes both under /pki."
      else
        echo "an issuing CA from elsewhere. Blinky signs and publishes its"
        echo "    revocation list; the root's belongs to whoever holds the root,"
        echo "    and /pki/root.crl answers 404 here on purpose."
      fi)

What this did not do, because it needs a domain controller:

    publish the chain into the directory    scripts/blinky-samba-setup.sh
    give the KDC a certificate              scripts/sign-kdc-cert.sh
    keep the directory's CRLs current       scripts/publish-crl-to-directory.sh

EOF

[[ $fail -eq 0 ]] || exit 1
