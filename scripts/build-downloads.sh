#!/usr/bin/env bash
#
# Blinky - build what the console offers for download (0105).
#
#     bash scripts/build-downloads.sh 0.5.0 --server blinky-cms.ad.digitalworkspace.pl
#     bash scripts/build-downloads.sh 0.5.0 --server blinky-cms.ad.digitalworkspace.pl --no-build
#     bash scripts/build-downloads.sh 0.5.0 --server blinky-cms.ad.digitalworkspace.pl \
#         --publish sysadmin@172.16.5.11
#
# Run it from Git Bash, not from PowerShell's "bash", which is WSL: WSL has no
# copy of the SSH key the server knows, and --publish then asks for a password
# nobody has.
#
# Windows, with wix, for the MSIs. Writes downloads/ with two packages - one zip
# for a workstation, one for the connector's server - and every file in them on
# its own, plus downloads.json listing each with its SHA-256.
#
# --server is the name clients reach this deployment by, and goes into the
# packages as blinky-server.json. The install scripts read it, so nothing in them
# names a server: the first version of install-windows-client.ps1 said
# by-cacms.blinky.lab, and a workstation in another domain enrolled against a
# name that did not resolve.
#
# --publish copies the folder to ~/blinky/downloads on the server, which the API
# mounts read-only. Nothing restarts: the manifest is read on every request.

set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
version="${1:-0.1.0}"
shift || true

build=1
publish=""
server=""

while [[ $# -gt 0 ]]; do
    case "$1" in
        --no-build) build=0; shift ;;
        --publish) publish="$2"; shift 2 ;;
        --server) server="$2"; shift 2 ;;
        *) echo "unknown argument: $1" >&2; exit 2 ;;
    esac
done

[[ -n "$server" ]] || {
    echo "--server is required: the name workstations and the connector reach this deployment by." >&2
    exit 2
}

command -v python >/dev/null 2>&1 || { echo "python is needed to write the manifest and the zips" >&2; exit 1; }

out="$root/downloads"
artifacts="$root/artifacts"

if [[ $build -eq 1 ]]; then
    bash "$root/scripts/build-connector-msi.sh" "$version"
    bash "$root/scripts/build-msi.sh" "$version"
fi

revision="$(git -C "$root" rev-parse --short HEAD 2>/dev/null || echo unknown)"
if ! git -C "$root" diff --quiet HEAD 2>/dev/null; then
    revision="$revision-dirty"
fi

rm -rf "$out"
mkdir -p "$out"

python - "$root" "$out" "$artifacts" "$version" "$server" "$revision" <<'PY'
import hashlib, json, os, shutil, sys, zipfile
from datetime import datetime, timezone

root, out, artifacts, version, server, revision = sys.argv[1:]

def scripts(name):
    return os.path.join(root, 'scripts', name)

# kind, source, description - the description is the console's language.
files = [
    ('connector', os.path.join(artifacts, f'blinky-adcs-connector-{version}.msi'),
     'Konektor ADCS: wydawanie przez Microsoft CA i odczyt Active Directory, na serwerze w domenie'),
    ('script', scripts('Install-BlinkyConnector.ps1'),
     'Instalacja konektora: sprawdza MSI i zaufanie, certyfikat agenta enrolmentu, konto uslugi i token'),
    ('agent', os.path.join(artifacts, f'blinky-agent-{version}.msi'),
     'Agent Blinky na stacje robocza: czytnik, karta, tray'),
    ('script', scripts('install-windows-client.ps1'),
     'Instalacja stacji: lancuch, minidriver Yubico, polityka logowania ECC, agent'),
    ('script', scripts('enable-ecc-smartcard-logon.ps1'),
     'Polityka logowania karta z kluczem ECC (wywolywany przez instalacje stacji)'),
]

for _, source, _ in files:
    if not os.path.isfile(source):
        sys.exit(f'missing: {source} - build it, or drop --no-build')

# What the install scripts read instead of an address written into them.
config = {
    'server': server,
    'agentsUrl': f'https://{server}:9443',
    'pkiUrl': f'http://{server}',
    'consoleUrl': f'https://{server}:8443',
}
config_path = os.path.join(out, 'blinky-server.json')
with open(config_path, 'w', encoding='utf-8', newline='\n') as f:
    json.dump(config, f, indent=2)
    f.write('\n')
files.append(('config', config_path, f'Adres serwera dla skryptow instalacji: {server}'))

def entry(kind, path, description):
    with open(path, 'rb') as f:
        digest = hashlib.sha256(f.read()).hexdigest().upper()
    return {'file': os.path.basename(path), 'kind': kind, 'version': version,
            'size': os.path.getsize(path), 'sha256': digest, 'description': description}

def manifest(entries):
    return {'built': datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ'),
            'revision': revision, 'server': server, 'files': entries}

entries = []
for kind, source, description in files:
    target = os.path.join(out, os.path.basename(source))
    if os.path.abspath(source) != os.path.abspath(target):
        shutil.copyfile(source, target)
    entries.append(entry(kind, target, description))

# Each package carries the list of its own files, which is what the install
# scripts check the MSI against; the served list then adds the packages.
inner = json.dumps(manifest(entries), indent=2) + '\n'

packages = [
    (f'blinky-workstation-{version}.zip',
     ['blinky-agent-%s.msi' % version, 'install-windows-client.ps1', 'enable-ecc-smartcard-logon.ps1',
      'blinky-server.json'],
     f'Paczka stacji: rozpakuj, uruchom install-windows-client.ps1 jako administrator. Serwer {server}'),
    (f'blinky-connector-{version}.zip',
     ['blinky-adcs-connector-%s.msi' % version, 'Install-BlinkyConnector.ps1', 'blinky-server.json'],
     f'Paczka konektora: rozpakuj na serwerze w domenie, uruchom Install-BlinkyConnector.ps1. Serwer {server}'),
]

served = []
for name, members, description in packages:
    path = os.path.join(out, name)
    with zipfile.ZipFile(path, 'w', zipfile.ZIP_DEFLATED) as z:
        for member in members:
            z.write(os.path.join(out, member), member)
        z.writestr('downloads.json', inner)
    served.append(entry('package', path, description))

with open(os.path.join(out, 'downloads.json'), 'w', encoding='utf-8', newline='\n') as f:
    f.write(json.dumps(manifest(served + entries), indent=2) + '\n')
PY

echo
echo "  $out  (server: $server)"
ls -la "$out" | tail -n +4 | sed 's/^/    /'

if [[ -n "$publish" ]]; then
    echo
    echo "publishing to $publish:~/blinky/downloads ..."
    ssh "$publish" 'rm -rf ~/blinky/downloads.new && mkdir -p ~/blinky/downloads.new'
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
