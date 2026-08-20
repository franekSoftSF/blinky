#!/usr/bin/env bash
#
# Blinky - run the agent and its window from a copy, so building does not fight
# with running.
#
#     scripts/lab-agent.sh start
#     scripts/lab-agent.sh stop
#     scripts/lab-agent.sh restart
#
# Why this exists. Running the agent straight out of bin/Debug locks the
# assemblies it is using, and every build after that spends ten retries of one
# second per locked file before failing:
#
#     MSB3027: ... Przekroczono liczbę ponownych prób 10 ... locked by:
#     Blinky.Agent.Service (4300)
#
# Measured on this bench: 2.8 seconds for an incremental build with nothing
# running, against 16 seconds ending in failure with the agent up. It reads as a
# slow build and is not one - it is a build waiting for a file it will never get.
#
# Publishing to .lab/ makes the running copy a different set of files from the
# ones the compiler writes, and the collision stops existing.

set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
lab="$root/.lab"

command="${1:-start}"

stop() {
    # Nothing to report if they were not running: this is called before every
    # start as well.
    powershell.exe -NoProfile -Command \
        "Get-Process -Name 'Blinky.Agent.Service','Blinky.Agent.Ui' -ErrorAction SilentlyContinue |
         Stop-Process -Force" >/dev/null 2>&1 || true

    echo "stopped"
}

start() {
    stop

    echo "publishing to .lab ..."

    dotnet publish "$root/src/Blinky.Agent.Service" -c Debug -o "$lab/agent" --nologo -v q
    dotnet publish "$root/src/Blinky.Agent.Ui" -c Debug -o "$lab/ui" --nologo -v q

    # The identity lives beside the published copies rather than inside them:
    # a republish overwrites everything in those directories, and an agent that
    # loses its certificate enrols again as a second row for the same machine.
    export Agent__IdentityDirectory="${AGENT_IDENTITY:-$lab/identity}"
    export Agent__BackendUrl="${AGENT_BACKEND:-https://localhost:9443}"
    export Agent__Hostname="${AGENT_HOSTNAME:-devbox}"
    export Agent__Domain="${AGENT_DOMAIN:-corp.example}"
    export Agent__ServerCertificateAuthorityPath="${AGENT_SERVER_CA:-$root/certs/dev-ca.crt}"
    export Agent__PollIntervalSeconds="${AGENT_POLL:-120}"

    mkdir -p "$Agent__IdentityDirectory"

    echo "starting the service and the tray ..."

    # Start-Process rather than a bash background job with a redirect: a
    # detached Windows process writing to a redirected handle buffers, and the
    # log stays empty until it exits - which, for a service, is never. This was
    # an empty agent.log next to a perfectly healthy agent.
    powershell.exe -NoProfile -Command         "Start-Process -FilePath '$(cygpath -w "$lab/agent/Blinky.Agent.Service.exe")'                        -RedirectStandardOutput '$(cygpath -w "$lab/agent.log")'                        -RedirectStandardError  '$(cygpath -w "$lab/agent.err.log")'                        -WindowStyle Hidden" >/dev/null

    # The tray talks to the service over a pipe the service creates, and the
    # client waits for it to appear - so the order here does not matter.
    powershell.exe -NoProfile -Command \
        "Start-Process -FilePath '$(cygpath -w "$lab/ui/Blinky.Agent.Ui.exe")'" >/dev/null

    echo
    echo "  service log   $lab/agent.log"
    echo "  identity      $Agent__IdentityDirectory"
    echo
    echo "The tray icon is by the clock. Builds no longer collide with this."
}

case "$command" in
    start)   start ;;
    stop)    stop ;;
    restart) start ;;
    *)
        echo "usage: $(basename "$0") [start|stop|restart]" >&2
        exit 2
        ;;
esac
