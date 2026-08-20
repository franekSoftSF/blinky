#!/usr/bin/env bash
#
# Blinky - build the agent MSI.
#
#     scripts/build-msi.sh [version]
#
# Publishes the service and the tray self-contained, then packages both.
#
# Self-contained on purpose. A framework-dependent build is a few megabytes
# against a couple of hundred, and costs the .NET Desktop Runtime on every
# workstation before the agent will start - a prerequisite that has to be
# deployed first, in the right order, to machines whose whole point is that
# nobody visits them. The megabytes are cheaper than the phone calls.
#
# The MSI is not signed. An unsigned MSI is a SmartScreen prompt and, under
# some policies, a refusal - sign it before it goes near a fleet:
#
#     signtool sign /fd sha256 /tr <timestamp-url> /td sha256 /a blinky-agent.msi

set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
version="${1:-0.1.0}"
out="$root/artifacts"

if ! command -v wix >/dev/null 2>&1; then
    echo "wix is not installed. dotnet tool install --global wix" >&2
    exit 1
fi

rm -rf "$out/publish"
mkdir -p "$out/publish"

echo "publishing self-contained (this is the slow part) ..."

for project in "Blinky.Agent.Service:agent" "Blinky.Agent.Ui:ui"; do
    name="${project%%:*}"
    folder="${project##*:}"

    dotnet publish "$root/src/$name" \
        -c Release \
        -r win-x64 \
        --self-contained true \
        -p:PublishSingleFile=false \
        -o "$out/publish/$folder" \
        --nologo -v q
done

echo "packaging ..."

# Pinned. An unpinned add resolves to a version built for a newer WiX and
# fails with "could not find expected package root folder wixext5".
wix extension add -g WixToolset.Util.wixext/5.0.2 >/dev/null 2>&1 || true

wix build "$root/installer/agent.wxs" \
    -ext WixToolset.Util.wixext \
    -d "Version=$version" \
    -d "AgentPublish=$(cygpath -w "$out/publish/agent")" \
    -d "UiPublish=$(cygpath -w "$out/publish/ui")" \
    -o "$(cygpath -w "$out/blinky-agent-$version.msi")"

echo
echo "  $out/blinky-agent-$version.msi"
echo
echo "Install unattended:"
echo "  msiexec /i blinky-agent-$version.msi /qn \\"
echo "          BACKEND=https://blinky.lab:9443 DOMAIN=blinky.lab \\"
echo "          BOOTSTRAPTOKEN=... SERVERCA=C:\\certs\\backend-ca.crt"
