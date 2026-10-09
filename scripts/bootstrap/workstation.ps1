<#
.SYNOPSIS
    Installs or updates the Blinky agent on this workstation, fetched from the server (0110).

.DESCRIPTION
    Elevated, on the workstation:

        irm https://__BLINKY_SERVER__:9443/install/workstation.ps1 | iex

    or saved, to pass options:

        .\workstation.ps1 -Token <agent token> -EnableEccLogon -Schedule

    A workstation whose agent is enrolled fetches with that agent's certificate and is
    asked for nothing. A new one fetches with an agent enrolment token from the console
    (Administracja / Zetony) and enrols with the same token. The package is checked
    against the SHA-256 the server lists, unpacked, and handed to the
    install-windows-client.ps1 inside it.

    -Schedule leaves a daily task, as SYSTEM, that runs this again with -Quiet: it
    updates the agent when the server holds a newer one and does nothing otherwise.

    Until 0110 an installer reached a workstation only through an operator's browser and
    a copy by hand, and PC-0001 stayed on 0.5.3 with 0.5.6 published.
#>
[CmdletBinding()]
param(
    [string] $Token,
    [switch] $EnableEccLogon,
    [switch] $Schedule,
    [switch] $Force,
    [switch] $Quiet
)

$ErrorActionPreference = 'Stop'
$server = '__BLINKY_SERVER__'
$base = "https://${server}:9443"
$work = Join-Path $env:ProgramData 'Blinky\updates'

function Say($text) { if (-not $Quiet) { Write-Host $text -ForegroundColor Cyan } }

$principal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw 'Run this elevated: it installs a service.'
}

# Windows PowerShell 5.1 still offers TLS 1.0 first; the edge speaks 1.2 and 1.3.
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

# Who is asking: this machine's agent, if it has enrolled, else the token.
$identity = Get-ChildItem Cert:\LocalMachine\My -ErrorAction SilentlyContinue |
    Where-Object { $_.FriendlyName -like 'Blinky agent *' -and $_.HasPrivateKey -and $_.NotAfter -gt (Get-Date) } |
    Sort-Object NotAfter -Descending | Select-Object -First 1

if (-not $identity -and -not $Token) {
    if ($Quiet) { throw 'This machine has no enrolled agent and no token was given.' }
    $secure = Read-Host 'Agent enrolment token (console: Administracja / Zetony, purpose agent)' -AsSecureString
    $Token = [Runtime.InteropServices.Marshal]::PtrToStringBSTR([Runtime.InteropServices.Marshal]::SecureStringToBSTR($secure))
}

$request = @{ UseBasicParsing = $true }
if ($identity) { $request.Certificate = $identity } else { $request.Headers = @{ 'X-Blinky-Enrolment-Token' = $Token } }

Say "Blinky server: $base"
$manifest = (Invoke-RestMethod -Uri "$base/api/machine-downloads/workstation" @request).manifest
$package = @($manifest.files) | Where-Object { $_.kind -eq 'package' -and $_.file -like 'blinky-workstation-*' } | Select-Object -First 1
if (-not $package) { throw 'The server publishes no workstation package. An operator builds one with build-downloads.sh.' }

# The installed agent's version, from what the MSI registered.
$installed = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*' -ErrorAction SilentlyContinue |
    Where-Object { $_.DisplayName -eq 'Blinky agent' } | Select-Object -First 1 -ExpandProperty DisplayVersion

if ($installed -and -not $Force -and ([version]$installed -ge [version]$package.version)) {
    Say "Agent $installed is current (the server has $($package.version))."
} else {
    Say "Installing agent $($package.version)$(if ($installed) { " over $installed" })"

    New-Item -ItemType Directory -Force -Path $work | Out-Null
    $zip = Join-Path $work $package.file
    Invoke-WebRequest -Uri "$base/api/machine-downloads/workstation/$($package.file)" -OutFile $zip @request

    $hash = (Get-FileHash $zip -Algorithm SHA256).Hash
    if ($hash -ne $package.sha256) {
        Remove-Item $zip -Force
        throw "SHA-256 of $($package.file) is $hash and the server lists $($package.sha256). Nothing was installed."
    }

    $unpacked = Join-Path $work ([IO.Path]::GetFileNameWithoutExtension($package.file))
    Remove-Item $unpacked -Recurse -Force -ErrorAction SilentlyContinue
    Expand-Archive $zip -DestinationPath $unpacked -Force

    $arguments = @{}
    if (-not $identity -and $Token) { $arguments.BootstrapToken = $Token }
    if ($EnableEccLogon) { $arguments.EnableEccLogon = $true }

    & (Join-Path $unpacked 'install-windows-client.ps1') @arguments
    Remove-Item $zip -Force -ErrorAction SilentlyContinue
}

if ($Schedule) {
    # The task runs a saved copy of this script, fetched again so it is the server's
    # current one, as SYSTEM - which reads the agent's certificate in LocalMachine\My.
    $saved = Join-Path $env:ProgramData 'Blinky\Update-BlinkyAgent.ps1'
    Invoke-WebRequest -Uri "$base/install/workstation.ps1" -OutFile $saved -UseBasicParsing

    $action = New-ScheduledTaskAction -Execute 'powershell.exe' `
        -Argument "-NoProfile -ExecutionPolicy Bypass -File `"$saved`" -Quiet"
    $trigger = New-ScheduledTaskTrigger -Daily -At 3am -RandomDelay (New-TimeSpan -Hours 2)
    Register-ScheduledTask -TaskName 'Blinky agent update' -Action $action -Trigger $trigger `
        -User 'SYSTEM' -RunLevel Highest -Force | Out-Null
    Say 'Scheduled: the agent updates itself daily from the server (task "Blinky agent update").'
}
