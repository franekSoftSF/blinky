#!/usr/bin/env bash
#
# Blinky - build the ADCS connector MSI (0105).
#
#     bash scripts/build-connector-msi.sh 0.5.0
#
# Windows only, with the wix global tool, like build-msi.sh: the connector is
# net10.0-windows and the MSI is WiX. Self-contained, so the CA server needs no
# .NET runtime - a server beside a Microsoft CA is the last machine anybody
# wants to install a runtime on - and not single-file, so the native libraries
# stay beside the executable where the service can load them.
#
# Unsigned. Sign with signtool before the file leaves a lab.

set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
version="${1:-0.1.0}"
out="$root/artifacts"

revision="$(git -C "$root" rev-parse --short HEAD 2>/dev/null || echo unknown)"
if ! git -C "$root" diff --quiet HEAD 2>/dev/null; then
    revision="$revision-dirty"
    echo "note: building from a tree with uncommitted changes; the version says -dirty"
fi

if ! command -v wix >/dev/null 2>&1; then
    echo "wix is not installed. dotnet tool install --global wix" >&2
    exit 1
fi

publish="$out/publish/connector"
rm -rf "$publish"
mkdir -p "$publish"

echo "publishing the connector self-contained ..."
dotnet publish "$root/src/Blinky.AdcsConnector" \
    -c Release \
    -r win-x64 \
    --self-contained true \
    -p:PublishSingleFile=false \
    -p:Version="$version" \
    -p:InformationalVersion="$version+$revision" \
    -o "$publish" \
    --nologo -v q

# The repository's appsettings.Development.json is for a bench; a CA server that
# happens to have DOTNET_ENVIRONMENT set must not pick it up.
rm -f "$publish/appsettings.Development.json"

echo "packaging ..."
wix extension add -g WixToolset.Util.wixext/5.0.2 >/dev/null 2>&1 || true
msi="$out/blinky-adcs-connector-$version.msi"
wix build "$root/installer/connector.wxs" \
    -arch x64 \
    -ext WixToolset.Util.wixext \
    -d "Version=$version" \
    -d "ConnectorPublish=$(cygpath -w "$publish")" \
    -o "$(cygpath -w "$msi")"

echo
echo "  $msi"
echo
echo "Install with Install-BlinkyConnector.ps1 from the console's downloads, or:"
echo "  msiexec /i blinky-adcs-connector-$version.msi /qn \\"
echo "          APIURL=https://blinky.example:9443 JOINTOKEN=... \\"
echo "          SERVICEDOMAIN=AD SERVICEUSER=svc_blinky SERVICEPASSWORD=..."
