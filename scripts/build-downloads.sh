#!/usr/bin/env bash
#
# Blinky - build what the console offers for download (0105).
#
#     bash scripts/build-downloads.sh 0.5.0
#     bash scripts/build-downloads.sh 0.5.0 --no-build          # from artifacts/ as they are
#     bash scripts/build-downloads.sh 0.5.0 --publish sysadmin@blinky-cms.ad.digitalworkspace.pl
#
# Windows, with wix, for the MSIs. Writes downloads/ with the connector MSI, the
# agent MSI, the scripts that install them and downloads.json, which lists each
# file with its SHA-256. The console shows that list to a signed-in operator and
# Install-BlinkyConnector.ps1 checks the MSI against it.
#
# --publish copies the folder to ~/blinky/downloads on the server, which the API
# mounts read-only. Nothing restarts: the manifest is read on every request.

set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
version="${1:-0.1.0}"
shift || true

build=1
publish=""

while [[ $# -gt 0 ]]; do
    case "$1" in
        --no-build) build=0; shift ;;
        --publish) publish="$2"; shift 2 ;;
        *) echo "unknown argument: $1" >&2; exit 2 ;;
    esac
done

out="$root/downloads"
artifacts="$root/artifacts"

if [[ $build -eq 1 ]]; then
    bash "$root/scripts/build-connector-msi.sh" "$version"
    bash "$root/scripts/build-msi.sh" "$version"
fi

connector="$artifacts/blinky-adcs-connector-$version.msi"
agent="$artifacts/blinky-agent-$version.msi"

for file in "$connector" "$agent"; do
    [[ -f "$file" ]] || { echo "missing: $file - build it, or drop --no-build" >&2; exit 1; }
done

rm -rf "$out"
mkdir -p "$out"

# kind|source|description - the description is the console's language.
entries=(
    "connector|$connector|Konektor ADCS: wydawanie przez Microsoft CA i odczyt Active Directory, na serwerze w domenie"
    "script|$root/scripts/Install-BlinkyConnector.ps1|Instalacja konektora: sprawdza MSI i zaufanie, certyfikat agenta enrolmentu, konto uslugi i token"
    "agent|$agent|Agent Blinky na stacje robocza: czytnik, karta, tray"
    "script|$root/scripts/install-windows-client.ps1|Instalacja stacji: lancuch Blinky, minidriver Yubico, polityka logowania ECC, agent"
    "script|$root/scripts/enable-ecc-smartcard-logon.ps1|Polityka logowania karta z kluczem ECC (wywolywany przez instalacje stacji)"
)

revision="$(git -C "$root" rev-parse --short HEAD 2>/dev/null || echo unknown)"
if ! git -C "$root" diff --quiet HEAD 2>/dev/null; then
    revision="$revision-dirty"
fi

json_escape() { sed -e 's/\\/\\\\/g' -e 's/"/\\"/g' <<<"$1"; }

{
    printf '{\n  "built": "%s",\n  "revision": "%s",\n  "files": [\n' \
        "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$revision"

    first=1
    for entry in "${entries[@]}"; do
        IFS='|' read -r kind source description <<<"$entry"
        name="$(basename "$source")"

        # LF scripts stay LF; a .ps1 is read by PowerShell either way.
        cp "$source" "$out/$name"

        size="$(stat -c %s "$out/$name")"
        sha="$(sha256sum "$out/$name" | cut -d' ' -f1 | tr '[:lower:]' '[:upper:]')"

        [[ $first -eq 1 ]] || printf ',\n'
        first=0
        printf '    {"file": "%s", "kind": "%s", "version": "%s", "size": %s, "sha256": "%s", "description": "%s"}' \
            "$name" "$kind" "$version" "$size" "$sha" "$(json_escape "$description")"
    done

    printf '\n  ]\n}\n'
} > "$out/downloads.json"

echo
echo "  $out"
ls -la "$out" | tail -n +2 | sed 's/^/    /'

if [[ -n "$publish" ]]; then
    echo
    echo "publishing to $publish:~/blinky/downloads ..."
    ssh "$publish" 'mkdir -p ~/blinky/downloads.new'
    scp -q "$out"/* "$publish:blinky/downloads.new/"

    # File by file into the same directory, the manifest last. Not the directory in
    # one rename: the API's bind mount holds the directory itself, and a renamed one
    # leaves the running container looking at the old, deleted copy.
    ssh "$publish" 'cd ~/blinky && mkdir -p downloads \
        && for f in downloads.new/*; do n="$(basename "$f")"; [ "$n" = downloads.json ] || mv -f "$f" "downloads/$n"; done \
        && mv -f downloads.new/downloads.json downloads/downloads.json \
        && for f in downloads/*; do n="$(basename "$f")"; grep -q "\"file\": \"$n\"" downloads/downloads.json || [ "$n" = downloads.json ] || rm -f "$f"; done \
        && rmdir downloads.new'
    echo "  published"
fi
