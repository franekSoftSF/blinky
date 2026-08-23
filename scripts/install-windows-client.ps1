<#
.SYNOPSIS
    Installs the Blinky agent on a domain-joined Windows client in the lab.

.DESCRIPTION
    Run elevated, from the folder holding blinky-agent-*.msi and dev-ca.crt.

    Three things, in an order that matters:

      1. The lab CA into the machine's trusted roots. Without it the agent
         refuses to talk to the backend - and refusing is correct, so the
         failure looks like a broken agent rather than a missing certificate.

      2. The MSI, with the backend, the realm and the bootstrap token as
         properties. The token is passed as an MSI property that is already
         listed in MSIHIDDENPROPERTIES. That covers the property dumps but
         not the command line msiexec echoes at the top of the log, so the
         log is scrubbed afterwards.

      3. The tray, started for this session. It normally appears at the next
         logon, from HKLM\...\Run.

.PARAMETER BootstrapToken
    From BOOTSTRAP_TOKEN in .env on the CMS host, which is root-only:

        ssh sysadmin@by-cacms.blinky.lab 'sudo grep ^BOOTSTRAP_TOKEN= ~/blinky/.env'

.EXAMPLE
    .\install-windows-client.ps1 -BootstrapToken abc123
#>

[CmdletBinding()]
param(
    [string] $BootstrapToken,
    [string] $Backend,
    [string] $Domain,
    [string] $Msi = "$PSScriptRoot\blinky-agent-0.2.9.msi",
    [string] $CaCertificate = "$PSScriptRoot\dev-ca.crt"
)

$ErrorActionPreference = 'Stop'

$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
if (-not (New-Object Security.Principal.WindowsPrincipal($identity)).IsInRole(
        [Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw "Run this elevated: it installs a service and writes to HKLM."
}

# What this machine was told last time. An upgrade should not make somebody
# find the backend URL again, and it should not make them paste a bootstrap
# token that the agent stopped needing the moment it enrolled - a token typed
# once a day ends up in shell history, on a memory stick and in a chat window.
$settings = 'HKLM:\SOFTWARE\Blinky\Agent'
$existing = if (Test-Path $settings) { Get-ItemProperty $settings } else { $null }

function Prefer($given, $remembered, $fallback) {
    if ($given) { return $given }
    if ($remembered) { return $remembered }
    return $fallback
}

$Backend = Prefer $Backend $existing.BackendUrl 'https://by-cacms.blinky.lab:9443'
$Domain  = Prefer $Domain  $existing.Domain     'blinky.lab'

# The token buys an identity and is useless afterwards. An agent that already
# holds one - a certificate in the machine store, named for it - is upgrading
# rather than enrolling, and should not be asked for it again.
$enrolled = @(Get-ChildItem Cert:\LocalMachine\My -ErrorAction SilentlyContinue |
    Where-Object { $_.FriendlyName -like 'Blinky agent *' }).Count -gt 0

if (-not $BootstrapToken) {
    $BootstrapToken = $existing.BootstrapToken

    if (-not $BootstrapToken -and -not $enrolled) {
        throw @'
This machine has no agent identity and no bootstrap token to get one with.

Pass -BootstrapToken on the first install. It is remembered afterwards, and an
upgrade then needs no arguments at all:

    ssh sysadmin@by-cacms.blinky.lab "sudo grep ^BOOTSTRAP_TOKEN= ~/blinky/.env"
'@
    }
}

foreach ($file in $Msi, $CaCertificate) {
    if (-not (Test-Path $file)) { throw "Not found: $file" }
}

Write-Host "`n1/3  trusting the lab CA"

# LocalMachine\Root, because the service runs as LocalSystem and a root in the
# installing user's store would be invisible to it.
Import-Certificate -FilePath $CaCertificate `
                   -CertStoreLocation Cert:\LocalMachine\Root | Out-Null

Write-Host "     $((Get-PfxCertificate $CaCertificate).Subject)"

Write-Host "`n2/3  installing the agent"
Write-Host "     backend  $Backend"
Write-Host "     domain   $Domain"
Write-Host ("     token    " + $(
    if ($PSBoundParameters.ContainsKey('BootstrapToken')) { 'given on the command line' }
    elseif ($BootstrapToken) { 'remembered from the last install' }
    else { 'not needed - this machine already has an identity' }))

$log = "$env:TEMP\blinky-agent-install.log"

$arguments = @(
    '/i', "`"$Msi`"",
    '/qn',
    '/l*v', "`"$log`"",
    "BACKEND=$Backend",
    "DOMAIN=$Domain",
    "SERVERCA=$CaCertificate"
)

# Only when there is one. Passing an empty property writes an empty registry
# value over whatever was there, which on an upgrade would take away the token
# a machine might still need if its identity is ever lost.
if ($BootstrapToken) {
    $arguments += "BOOTSTRAPTOKEN=$BootstrapToken"
}

$result = Start-Process msiexec.exe -ArgumentList $arguments -Wait -PassThru

if ($result.ExitCode -ne 0) {
    throw "msiexec returned $($result.ExitCode). The log is at $log"
}

# MSIHIDDENPROPERTIES keeps the token out of the property dumps, and cannot
# keep it out of the command line msiexec echoes into the first lines of the
# log. So the log is scrubbed rather than trusted or deleted: a bootstrap token
# sitting in %TEMP% is one anybody on the machine can read, and the rest of the
# log is what anyone diagnosing a failed install needs.
if ($BootstrapToken -and
    (Select-String -Path $log -Pattern ([regex]::Escape($BootstrapToken)) -Quiet)) {
    # UTF-16, which is what msiexec writes and what Get-Content has to be told.
    (Get-Content $log -Raw -Encoding Unicode).Replace($BootstrapToken, '<redacted>') |
        Set-Content $log -Encoding Unicode -NoNewline

    Write-Host "     installed; the token was in the log and has been redacted"
} else {
    Write-Host "     installed; the token is not in the installer log"
}

Write-Host "`n3/3  starting the tray for this session"

$tray = "$env:ProgramFiles\Blinky\ui\Blinky.Agent.Ui.exe"
if (Test-Path $tray) { Start-Process $tray }

Start-Sleep -Seconds 6

Get-Service BlinkyAgent | Format-List Name, Status, StartType

@"

  service   BlinkyAgent (LocalSystem)
  log       C:\ProgramData\Blinky\logs\agent-*.log
  identity  certlm.msc, Personal - "Blinky agent {id}" once it has enrolled

If the log says the backend cannot be trusted, the CA above did not take. If it
says the name does not resolve, this machine's DNS is not pointed at the domain
controller.
"@
