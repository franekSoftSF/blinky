<#
.SYNOPSIS
    Installs or updates the Blinky ADCS connector on this server, fetched from Blinky (0110).

.DESCRIPTION
    Elevated, on the member server beside the CA:

        irm https://__BLINKY_SERVER__:9443/install/connector.ps1 | iex

    or saved, to pass options:

        .\connector.ps1 -Token <connector token> -ServiceAccount AD\svc_blinky -EnrolmentAgentThumbprint <thumbprint>

    Always with a connector enrolment token from the console (Administracja / Zetony,
    purpose Konektor ADCS): the connector's own certificate lives in its service account's
    store, out of reach of the administrator running this. A token whose uses are spent
    still fetches until it expires, so the one that enrolled the connector also upgrades it.

    On an upgrade the service account and the enrolment agent come from what the
    previous install left in HKLM\SOFTWARE\Blinky\AdcsConnector, and the token is not
    written to the registry again: the connector already has its certificate.
#>
[CmdletBinding()]
param(
    [string] $Token,
    [string] $ServiceAccount,
    [string] $EnrolmentAgentThumbprint,
    [string] $EnrolmentAgentTemplate,
    [string] $CaConfig,
    [switch] $Force
)

$ErrorActionPreference = 'Stop'
$server = '__BLINKY_SERVER__'
$base = "https://${server}:9443"
$work = Join-Path $env:ProgramData 'Blinky\updates'
$settings = 'HKLM:\SOFTWARE\Blinky\AdcsConnector'

$principal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw 'Run this elevated: it installs a service.'
}

[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

if (-not $Token) {
    $secure = Read-Host 'Connector enrolment token (console: Administracja / Zetony, purpose Konektor ADCS)' -AsSecureString
    $Token = [Runtime.InteropServices.Marshal]::PtrToStringBSTR([Runtime.InteropServices.Marshal]::SecureStringToBSTR($secure))
}

$request = @{ UseBasicParsing = $true; Headers = @{ 'X-Blinky-Enrolment-Token' = $Token } }

Write-Host "Blinky server: $base" -ForegroundColor Cyan
$manifest = (Invoke-RestMethod -Uri "$base/api/machine-downloads/connector" @request).manifest
$package = @($manifest.files) | Where-Object { $_.kind -eq 'package' -and $_.file -like 'blinky-connector-*' } | Select-Object -First 1
if (-not $package) { throw 'The server publishes no connector package. An operator builds one with build-downloads.sh.' }

$installed = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*' -ErrorAction SilentlyContinue |
    Where-Object { $_.DisplayName -eq 'Blinky ADCS connector' } | Select-Object -First 1 -ExpandProperty DisplayVersion

if ($installed -and -not $Force -and ([version]$installed -ge [version]$package.version)) {
    Write-Host "Connector $installed is current (the server has $($package.version))." -ForegroundColor Cyan
    return
}

# What the previous install was told, so an upgrade asks only for the account's password.
$previous = if (Test-Path $settings) { Get-ItemProperty $settings } else { $null }
if (-not $ServiceAccount -and $previous.ServiceAccount) { $ServiceAccount = $previous.ServiceAccount }
if (-not $EnrolmentAgentThumbprint -and -not $EnrolmentAgentTemplate -and $previous.EnrolmentAgentThumbprint) {
    $EnrolmentAgentThumbprint = $previous.EnrolmentAgentThumbprint
}
if (-not $ServiceAccount) { $ServiceAccount = Read-Host 'Service account (DOMAIN\user, or DOMAIN\gmsa$)' }

Write-Host "Installing connector $($package.version)$(if ($installed) { " over $installed" })" -ForegroundColor Cyan

New-Item -ItemType Directory -Force -Path $work | Out-Null
$zip = Join-Path $work $package.file
Invoke-WebRequest -Uri "$base/api/machine-downloads/connector/$($package.file)" -OutFile $zip @request

$hash = (Get-FileHash $zip -Algorithm SHA256).Hash
if ($hash -ne $package.sha256) {
    Remove-Item $zip -Force
    throw "SHA-256 of $($package.file) is $hash and the server lists $($package.sha256). Nothing was installed."
}

$unpacked = Join-Path $work ([IO.Path]::GetFileNameWithoutExtension($package.file))
Remove-Item $unpacked -Recurse -Force -ErrorAction SilentlyContinue
Expand-Archive $zip -DestinationPath $unpacked -Force

$arguments = @{ ServiceAccount = $ServiceAccount }
if (-not $installed) { $arguments.JoinToken = $Token }
if ($EnrolmentAgentThumbprint) { $arguments.EnrolmentAgentThumbprint = $EnrolmentAgentThumbprint }
if ($EnrolmentAgentTemplate) { $arguments.EnrolmentAgentTemplate = $EnrolmentAgentTemplate }
if ($CaConfig) { $arguments.CaConfig = $CaConfig }

& (Join-Path $unpacked 'Install-BlinkyConnector.ps1') @arguments
Remove-Item $zip -Force -ErrorAction SilentlyContinue
