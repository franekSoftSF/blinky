<#
.SYNOPSIS
    Installs the Blinky agent as a Windows service, with its tray window
    starting in every user session.

.DESCRIPTION
    Run elevated. This creates a service and writes to HKLM, which is the whole
    point: the agent has to own a card reader in session 0, and the tray has to
    appear for whoever logs in.

    The split is not decoration. The service runs as LocalSystem because that is
    what can hold a reader and write to the machine certificate store, and
    LocalSystem cannot draw a window. The tray runs as the person and cannot
    touch a card. They meet on a named pipe granted to INTERACTIVE and
    LocalSystem, and to nothing else.

.PARAMETER Backend
    The agents listener, normally https://blinky.example:9443.

.PARAMETER Domain
    Required, and never derived. The service runs as LocalSystem, whose
    UserDomainName is the machine name - guessing produces a second, orphaned
    agent row per machine.

.PARAMETER BootstrapToken
    Needed once, for the first start. Written to %ProgramData%\Blinky\agent.json,
    which is created with SYSTEM and Administrators only - %ProgramFiles% would
    have handed every local user a read of it.

.PARAMETER ServerCertificateAuthority
    The CA that signed the backend's certificate, as a .crt. Without it the
    agent will not check who it is talking to.

.EXAMPLE
    .\install-agent.ps1 -Backend https://blinky.lab:9443 -Domain corp.example `
                        -BootstrapToken abc123 -ServerCertificateAuthority C:\certs\ca.crt
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)] [string] $Backend,
    [Parameter(Mandatory = $true)] [string] $Domain,
    [string] $BootstrapToken,
    [string] $ServerCertificateAuthority,
    [string] $InstallRoot = "$env:ProgramFiles\Blinky",
    [switch] $Uninstall
)

$ErrorActionPreference = 'Stop'

$serviceName = 'BlinkyAgent'
$runKey = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run'
$runValue = 'BlinkyAgentUi'
$stateRoot = "$env:ProgramData\Blinky"

function Assert-Elevated {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($identity)

    if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        throw "Run this elevated: it creates a service and writes to HKLM."
    }
}

function Remove-Agent {
    if (Get-Service -Name $serviceName -ErrorAction SilentlyContinue) {
        Stop-Service -Name $serviceName -Force -ErrorAction SilentlyContinue
        sc.exe delete $serviceName | Out-Null
        Write-Host "service removed"
    }

    Remove-ItemProperty -Path $runKey -Name $runValue -ErrorAction SilentlyContinue
    Get-Process -Name 'Blinky.Agent.Ui' -ErrorAction SilentlyContinue | Stop-Process -Force

    # The identity and the log stay. An uninstall that took the certificate with
    # it would make a version upgrade look like a new machine, and split one
    # workstation's history across two agent rows.
    Write-Host "removed. $stateRoot was left alone - it holds this machine's identity."
}

Assert-Elevated

if ($Uninstall) {
    Remove-Agent
    return
}

$repository = Split-Path -Parent $PSScriptRoot

Write-Host "publishing..."

dotnet publish "$repository\src\Blinky.Agent.Service" -c Release -o "$InstallRoot\agent" --nologo -v q
dotnet publish "$repository\src\Blinky.Agent.Ui" -c Release -o "$InstallRoot\ui" --nologo -v q

# Before the service starts, so the first thing it writes lands in a directory
# that is already locked down rather than one it has to fix afterwards.
New-Item -ItemType Directory -Path $stateRoot -Force | Out-Null

$settings = [ordered]@{
    Agent = [ordered]@{
        BackendUrl = $Backend
        Domain     = $Domain
        Hostname   = $env:COMPUTERNAME.ToLowerInvariant()
    }
}

if ($BootstrapToken) { $settings.Agent.BootstrapToken = $BootstrapToken }

if ($ServerCertificateAuthority) {
    Copy-Item $ServerCertificateAuthority "$stateRoot\backend-ca.crt" -Force
    $settings.Agent.ServerCertificateAuthorityPath = "$stateRoot\backend-ca.crt"
} else {
    Write-Warning ("No -ServerCertificateAuthority. The agent will refuse to trust the " +
                   "backend until one is configured; it does not fall back to trusting " +
                   "anything.")
}

$settings | ConvertTo-Json -Depth 5 | Set-Content "$stateRoot\agent.json" -Encoding UTF8

# The agent locks these down itself on every start, but the token is on disk
# from this moment and the service has not run yet.
$acl = New-Object System.Security.AccessControl.DirectorySecurity
$acl.SetAccessRuleProtection($true, $false)

foreach ($sid in 'S-1-5-18', 'S-1-5-32-544') {
    $account = New-Object System.Security.Principal.SecurityIdentifier($sid)
    $acl.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule(
        $account, 'FullControl', 'ContainerInherit,ObjectInherit', 'None', 'Allow')))
}

Set-Acl -Path $stateRoot -AclObject $acl

Remove-Agent

New-Service -Name $serviceName `
            -BinaryPathName "`"$InstallRoot\agent\Blinky.Agent.Service.exe`"" `
            -DisplayName 'Blinky agent' `
            -Description 'Manages PIV credentials on tokens attached to this machine.' `
            -StartupType Automatic | Out-Null

# LocalSystem, explicitly rather than by default, because this is the reason the
# whole session 0 split exists: it can hold a reader and write to the machine
# certificate store, and it cannot draw a window.
sc.exe config $serviceName obj= LocalSystem | Out-Null

# Restart twice on failure, then stop trying. An agent that cannot start is not
# fixed by starting it again every minute for a week.
sc.exe failure $serviceName reset= 86400 actions= restart/60000/restart/300000/none/0 | Out-Null

Start-Service -Name $serviceName

# HKLM rather than HKCU: the tray belongs to the machine's installation, and it
# has to appear for whoever logs in next, not only for whoever installed it.
Set-ItemProperty -Path $runKey -Name $runValue `
                 -Value "`"$InstallRoot\ui\Blinky.Agent.Ui.exe`""

Write-Host ""
Write-Host "  service     $serviceName (LocalSystem, automatic)"
Write-Host "  tray        starts at logon, for every user"
Write-Host "  settings    $stateRoot\agent.json"
Write-Host "  log         $stateRoot\logs\agent-*.log"
Write-Host "  identity    the machine certificate store - certlm.msc, Personal"
Write-Host ""
Write-Host "The tray appears at the next logon. Start it now with:"
Write-Host "  & '$InstallRoot\ui\Blinky.Agent.Ui.exe'"
