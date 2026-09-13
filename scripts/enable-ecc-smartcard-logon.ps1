<#
.SYNOPSIS
    Lets Windows offer an ECC smart-card certificate at the logon screen.

.DESCRIPTION
    Run elevated on the workstation. Sets the value behind the Group Policy setting
    "Allow ECC certificates to be used for logon and authentication":

        HKLM\SOFTWARE\Policies\Microsoft\Windows\SmartCardCredentialProvider
            EnumerateECCCerts = 1 (DWORD)

    Without it an ECC credential that is present, valid and correctly chained produces
    "no valid certificates were found on this smart card", while certutil -scinfo reports
    a missing keyset for a key the card itself describes happily. Neither message
    mentions a policy, and the card is what everybody suspects first - see
    ParseAlgorithm in Blinky.Agent.Service, which is why the agent defaults to RSA 2048.

    A domain GPO that sets the same value wins at the next policy refresh. In a domain
    that means the GPO is the right place, and this script is for a lab workstation or
    for proving the setting before somebody writes the GPO.

    Takes effect at the next logon screen: sign out, or restart.

.PARAMETER Undo
    Removes the value, which is Windows' default: RSA certificates only.

.EXAMPLE
    .\enable-ecc-smartcard-logon.ps1
.EXAMPLE
    .\enable-ecc-smartcard-logon.ps1 -Undo
#>
[CmdletBinding()]
param(
    [switch] $Undo
)

$ErrorActionPreference = 'Stop'

$principal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw 'Run this in an elevated PowerShell: the value is under HKLM.'
}

$key = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\SmartCardCredentialProvider'
$name = 'EnumerateECCCerts'

function Current {
    $value = Get-ItemProperty -Path $key -Name $name -ErrorAction SilentlyContinue
    if ($null -eq $value) { '(not set - RSA only)' } else { $value.$name }
}

Write-Host "before      $name = $(Current)"

if ($Undo) {
    if (Test-Path $key) {
        Remove-ItemProperty -Path $key -Name $name -ErrorAction SilentlyContinue
    }
}
else {
    if (-not (Test-Path $key)) {
        New-Item -Path $key -Force | Out-Null
    }

    New-ItemProperty -Path $key -Name $name -PropertyType DWord -Value 1 -Force | Out-Null
}

Write-Host "after       $name = $(Current)"

# Said rather than discovered: a domain GPO quietly putting the old value back an hour
# later reads like the script not having worked.
$gpo = & gpresult.exe /scope computer /z 2>$null | Select-String -SimpleMatch 'SmartCardCredentialProvider'
if ($gpo) {
    Write-Warning 'A Group Policy on this machine also sets SmartCardCredentialProvider values, and will win at the next refresh.'
}

Write-Host 'next        sign out or restart, then the logon screen offers ECC certificates on the card'
