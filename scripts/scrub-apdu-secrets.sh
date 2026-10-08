#!/usr/bin/env bash
#
# Blinky - remove APDU hex from stored job results.
#
#     bash scripts/scrub-apdu-secrets.sh --dry-run
#     bash scripts/scrub-apdu-secrets.sh
#
# One-off, for databases written before the transmit failure message was
# redacted.
#
# A failed SCardTransmit used to be reported with the whole command in hex.
# On a VERIFY that is
#
#     SCardTransmit(0020008008323538303235FFFF) failed: 0x80100068
#
# and 323538303235 is the user's PIN in ASCII. The message went into
# jobs.result, which is a database column, which is a backup, which is a
# support bundle.
#
# The code no longer produces these - see ApduRedaction. This is for the rows
# that already exist. It replaces the hex and keeps the sentence around it,
# because the reason the job failed is worth keeping and the command is not.
#
# Prints what it would change first. Run it with --dry-run, read the output,
# then run it again.

set -euo pipefail

cd "$(dirname "${BASH_SOURCE[0]}")/.."

DRY_RUN=0
[[ "${1:-}" == "--dry-run" ]] && DRY_RUN=1

compose() {
    if docker compose ps >/dev/null 2>&1; then
        docker compose "$@"
    else
        sudo docker compose "$@"
    fi
}

psql() {
    compose exec -T postgres psql -U "${POSTGRES_USER:-blinky}" \
        -d "${POSTGRES_DB:-blinky}" -v ON_ERROR_STOP=1 "$@"
}

# Any run of hex long enough to be a data field, inside the SCardTransmit(...)
# the message names. Deliberately blunt: this is not the place to be clever
# about which instruction carried which secret.
pattern='SCardTransmit\([0-9A-Fa-f]{6,}\)'

# jobs.result is jsonb, so the match and the replacement both go through text
# and the result is cast back. The replacement contains no quote, backslash or
# control character, so what goes back in is still valid JSON.

echo "Rows holding an APDU:"
psql -c "select id, type, state, created_at
         from jobs
         where result::text ~ '$pattern'
         order by created_at;"

if [[ $DRY_RUN -eq 1 ]]; then
    echo
    echo "What they would become:"
    psql -c "select id,
                    regexp_replace(result::text, '$pattern',
                                   'SCardTransmit(<redacted>)', 'g') as result
             from jobs
             where result::text ~ '$pattern';"
    echo
    echo "Nothing was changed. Run without --dry-run to apply."
    exit 0
fi

psql -c "update jobs
         set result = regexp_replace(result::text, '$pattern',
                                     'SCardTransmit(<redacted>)', 'g')::jsonb
         where result::text ~ '$pattern';"

echo
echo "Remaining rows with an APDU (should be none):"
psql -t -c "select count(*) from jobs where result::text ~ '$pattern';"

cat <<'EOF'

Done for this database. Two things it does not reach:

  - a backup taken before now
  - the agent's own log on the workstation, C:\ProgramData\Blinky\logs

Both held the same message. If this was a real PIN rather than a lab one, it
should be changed rather than chased.
EOF
