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
         listed in MSIHIDDENPROPERTIES, so it does not reach the installer log.

      3. The tray, started for this session. It normally appears at the next
         logon, from HKLM\...\Run.

.PARAMETER BootstrapToken
    From BOOTSTRAP_TOKEN in .env on the CMS host, which is root-only:

        ssh sysadmin@172.16.1.11 'sudo grep ^BOOTSTRAP_TOKEN= ~/blinky/.env'

.EXAMPLE
    .\install-windows-client.ps1 -BootstrapToken abc123
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)] [string] $BootstrapToken,
    [string] $Backend = 'https://by-ca-cms.blinky.lab:9443',
    [string] $Domain = 'blinky.lab',
    [string] $Msi = "$PSScriptRoot\blinky-agent-0.2.0.msi",
    [string] $CaCertificate = "$PSScriptRoot\dev-ca.crt"
)

$ErrorActionPreference = 'Stop'

$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
if (-not (New-Object Security.Principal.WindowsPrincipal($identity)).IsInRole(
        [Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw "Run this elevated: it installs a service and writes to HKLM."
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

$log = "$env:TEMP\blinky-agent-install.log"

$arguments = @(
    '/i', "`"$Msi`"",
    '/qn',
    '/l*v', "`"$log`"",
    "BACKEND=$Backend",
    "DOMAIN=$Domain",
    "BOOTSTRAPTOKEN=$BootstrapToken",
    "SERVERCA=$CaCertificate"
)

$result = Start-Process msiexec.exe -ArgumentList $arguments -Wait -PassThru

if ($result.ExitCode -ne 0) {
    throw "msiexec returned $($result.ExitCode). The log is at $log"
}

# The token is a property, and properties reach the log unless hidden. It is in
# MSIHIDDENPROPERTIES, and this checks that rather than trusting it - a
# bootstrap token sitting in %TEMP% is one anybody on the machine can read.
if (Select-String -Path $log -Pattern ([regex]::Escape($BootstrapToken)) -Quiet) {
    Write-Warning "The bootstrap token appears in $log - delete it."
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
