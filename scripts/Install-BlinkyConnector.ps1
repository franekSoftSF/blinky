<#
.SYNOPSIS
    Installs the Blinky ADCS connector on a domain member beside a Microsoft CA (0105).

.DESCRIPTION
    Run elevated, from the folder holding the MSI downloaded from the Blinky console
    (Pobieranie). In order:

      1. checks this is a domain member and the MSI is the one the console listed
         (SHA-256 against downloads.json, when it is beside the MSI);
      2. checks the Blinky server answers on its agents' address with a certificate
         this machine trusts - nothing is pinned, so trust is the check;
      3. finds the enrolment agent certificate, or requests one for this computer, and
         lets the service account use its key;
      4. installs the MSI with the connector enrolment token, as the service account;
      5. waits for the service to enrol itself and start polling.

    The connector also reads Active Directory for the server (0104), as the same
    account, so the server needs DIRECTORY_VIA=Connector and no LDAP password.

.PARAMETER ApiUrl
    The Blinky server's agents' address, https://<name>:9443.

.PARAMETER JoinToken
    A connector enrolment token from the console, Administracja / Zetony, purpose
    "connector". Asked for when not given. Spent at the first start.

.PARAMETER ServiceAccount
    DOMAIN\user, or DOMAIN\gmsa$ for a group managed service account (no password).

.PARAMETER EnrolmentAgentThumbprint
    An enrolment agent certificate already in LocalMachine\My.

.PARAMETER KeyAlreadyGranted
    The service account was given Read on the agent key by hand (certlm.msc, Manage
    Private Keys), for a key with no file to grant - in a TPM, for one.

.PARAMETER EnrolmentAgentTemplate
    With no thumbprint: the template to request a computer-bound enrolment agent
    certificate from, e.g. MachineEnrollmentAgent. MS-CONN01$ needs Enroll on it.

.EXAMPLE
    .\Install-BlinkyConnector.ps1 -ApiUrl https://blinky-cms.ad.digitalworkspace.pl:9443 `
        -ServiceAccount AD\svc_blinky -EnrolmentAgentTemplate MachineEnrollmentAgent
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)] [string] $ApiUrl,
    [string] $JoinToken,
    [Parameter(Mandatory)] [string] $ServiceAccount,
    [string] $EnrolmentAgentThumbprint,
    [string] $EnrolmentAgentTemplate,
    [string] $CaConfig,
    [string] $Msi,
    [switch] $KeyAlreadyGranted
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$RegistryKey = 'HKLM:\SOFTWARE\Blinky\AdcsConnector'
$ServiceName = 'BlinkyAdcsConnector'
$LogFolder = Join-Path $env:ProgramData 'Blinky\AdcsConnector\logs'

function Step($text) { Write-Host "`n$text" -ForegroundColor Cyan }
function Ok($text) { Write-Host "  ok    $text" -ForegroundColor Green }
function Fail($text) { Write-Host "  FAIL  $text" -ForegroundColor Red; exit 1 }

$principal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Fail 'Run this elevated: it installs a service and grants a key.'
}

# ------------------------------------------------------------------ 1. this machine
Step '1/5  this machine and the package'

$computer = Get-CimInstance Win32_ComputerSystem
if (-not $computer.PartOfDomain) {
    Fail 'This machine is not a domain member. The connector asks the CA and reads the directory as a domain account.'
}
Ok "$($env:COMPUTERNAME).$($computer.Domain)"

if ($ServiceAccount -notmatch '^([^\\]+)\\([^\\]+)$') { Fail 'ServiceAccount is DOMAIN\user, or DOMAIN\gmsa$.' }
$serviceDomain = $Matches[1]
$serviceUser = $Matches[2]
$isGmsa = $serviceUser.EndsWith('$')

$here = Split-Path -Parent $MyInvocation.MyCommand.Path
if (-not $Msi) {
    $Msi = Get-ChildItem $here -Filter 'blinky-adcs-connector-*.msi' |
        Sort-Object LastWriteTime -Descending | Select-Object -First 1 -ExpandProperty FullName
}
if (-not $Msi -or -not (Test-Path $Msi)) { Fail "No blinky-adcs-connector-*.msi beside this script; download it from the console." }

$manifest = Join-Path (Split-Path -Parent $Msi) 'downloads.json'
$hash = (Get-FileHash $Msi -Algorithm SHA256).Hash
if (Test-Path $manifest) {
    $listed = (Get-Content $manifest -Raw | ConvertFrom-Json).files |
        Where-Object { $_.file -eq (Split-Path -Leaf $Msi) }
    if (-not $listed) { Fail "$(Split-Path -Leaf $Msi) is not in downloads.json." }
    if ($listed.sha256 -ne $hash) { Fail "SHA-256 of $(Split-Path -Leaf $Msi) is $hash, and the console lists $($listed.sha256)." }
    Ok "$(Split-Path -Leaf $Msi), SHA-256 matches the console's list"
} else {
    Ok "$(Split-Path -Leaf $Msi), SHA-256 $hash - compare it with the console's downloads page"
}

# ------------------------------------------------------------------ 2. the server
Step "2/5  the Blinky server at $ApiUrl"

$uri = [Uri]$ApiUrl
if ($uri.Scheme -ne 'https') { Fail 'ApiUrl is https: what comes back on it is PKIData to sign as the enrolment agent.' }

try {
    # /healthz answers on the agents' listener without a client certificate. A trust
    # failure here is the same one the service would hit, said in front of a person.
    $health = Invoke-WebRequest -Uri "$($uri.GetLeftPart('Authority'))/healthz" -UseBasicParsing -TimeoutSec 15
    Ok "answers $($health.StatusCode), and this machine trusts its certificate"
} catch {
    Fail ("Cannot reach $ApiUrl with a certificate this machine trusts: $($_.Exception.Message). " +
          'Its certificate has to chain to a root in LocalMachine\Root and name ' + $uri.Host + '.')
}

# ------------------------------------------------------------------ 3. the enrolment agent
Step '3/5  the enrolment agent certificate'

$agent = $null
if ($EnrolmentAgentThumbprint) {
    $agent = Get-ChildItem Cert:\LocalMachine\My | Where-Object { $_.Thumbprint -eq ($EnrolmentAgentThumbprint -replace '[^0-9A-Fa-f]', '').ToUpper() }
    if (-not $agent) { Fail "No certificate $EnrolmentAgentThumbprint in LocalMachine\My." }
} elseif ($EnrolmentAgentTemplate) {
    try {
        $agent = (Get-Certificate -Template $EnrolmentAgentTemplate -CertStoreLocation Cert:\LocalMachine\My).Certificate
    } catch {
        Fail "The CA refused $EnrolmentAgentTemplate for $($env:COMPUTERNAME)`$: $($_.Exception.Message). Grant the computer Enroll on that template."
    }
} else {
    # The Certificate Request Agent EKU, which is what makes a certificate one.
    $agent = Get-ChildItem Cert:\LocalMachine\My |
        Where-Object { $_.HasPrivateKey -and $_.NotAfter -gt (Get-Date) -and ($_.EnhancedKeyUsageList.ObjectId -contains '1.3.6.1.4.1.311.20.2.1') } |
        Sort-Object NotAfter -Descending | Select-Object -First 1
    if (-not $agent) {
        Fail 'No enrolment agent certificate in LocalMachine\My. Give -EnrolmentAgentTemplate to request one, or -EnrolmentAgentThumbprint.'
    }
}

if (-not $agent.HasPrivateKey) { Fail "$($agent.Thumbprint) has no private key on this machine." }
if ($agent.EnhancedKeyUsageList.ObjectId -notcontains '1.3.6.1.4.1.311.20.2.1') {
    Fail "$($agent.Thumbprint) carries no Certificate Request Agent usage, so the CA will not take its signature."
}
Ok "$($agent.Subject), $($agent.Thumbprint), until $($agent.NotAfter.ToString('yyyy-MM-dd'))"

# The key is the computer's; the service account needs to use it, not own it.
#
# Found by its unique container name, searched for under every provider's folder
# rather than assumed to be in one: the first version looked only in Crypto\Keys and
# RSA\MachineKeys, and MS-CONN01's agent key was in neither. The name comes from .NET
# where it can say, and from certutil otherwise - matched by shape, because certutil
# prints its labels in the language of the server.
function Get-KeyContainerNames($certificate) {
    $names = New-Object System.Collections.Generic.List[string]
    try {
        $rsa = [System.Security.Cryptography.X509Certificates.RSACertificateExtensions]::GetRSAPrivateKey($certificate)
        if ($rsa -is [System.Security.Cryptography.RSACng]) { $names.Add($rsa.Key.UniqueName) }
        elseif ($null -ne $rsa -and $rsa.PSObject.Properties['CspKeyContainerInfo']) {
            $names.Add($rsa.CspKeyContainerInfo.UniqueKeyContainerName)
        }
    } catch { }
    try {
        $ec = [System.Security.Cryptography.X509Certificates.ECDsaCertificateExtensions]::GetECDsaPrivateKey($certificate)
        if ($ec -is [System.Security.Cryptography.ECDsaCng]) { $names.Add($ec.Key.UniqueName) }
    } catch { }
    $dump = & certutil.exe -store My $certificate.Thumbprint 2>$null
    foreach ($match in [regex]::Matches(($dump -join "`n"), '[0-9a-fA-F]{32}_[0-9a-fA-F]{8}-[0-9a-fA-F-]{27}')) {
        $names.Add($match.Value)
    }
    $names | Where-Object { $_ } | Select-Object -Unique
}

$crypto = Join-Path $env:ProgramData 'Microsoft\Crypto'
$keyFile = $null
$containers = @(Get-KeyContainerNames $agent)
foreach ($name in $containers) {
    $keyFile = Get-ChildItem $crypto -Recurse -File -Force -ErrorAction SilentlyContinue |
        Where-Object { $_.Name -eq $name -or $_.BaseName -eq $name } |
        Select-Object -First 1 -ExpandProperty FullName
    if ($keyFile) { break }
}

if ($keyFile) {
    & icacls.exe $keyFile /grant "${ServiceAccount}:R" | Out-Null
    if ($LASTEXITCODE -ne 0) { Fail "Could not grant $ServiceAccount read on $keyFile." }
    Ok "$ServiceAccount may use its key ($keyFile)"
} elseif ($KeyAlreadyGranted) {
    Ok "key access for $ServiceAccount granted by hand (-KeyAlreadyGranted)"
} else {
    $provider = (& certutil.exe -store My $agent.Thumbprint 2>$null | Select-String -Pattern 'Provider|Dostawca' | Select-Object -First 1)
    Fail ("No file for the private key of $($agent.Thumbprint) under $crypto (container: " +
          "$(if ($containers) { $containers -join ', ' } else { 'not reported' }); $provider). " +
          "A key in a TPM or a smart card has no file. Grant it by hand - certlm.msc, Personal, the " +
          "certificate, All Tasks, Manage Private Keys, add $ServiceAccount with Read - then run this " +
          'again with -KeyAlreadyGranted.')
}

# ------------------------------------------------------------------ 4. the MSI
Step '4/5  installing'

$existing = Get-Service $ServiceName -ErrorAction SilentlyContinue
if (-not $JoinToken -and -not $existing) {
    $secure = Read-Host 'Connector enrolment token (console: Administracja / Zetony, purpose connector)' -AsSecureString
    $JoinToken = [Runtime.InteropServices.Marshal]::PtrToStringBSTR([Runtime.InteropServices.Marshal]::SecureStringToBSTR($secure))
}

$password = ''
if (-not $isGmsa) {
    $credential = Get-Credential -UserName $ServiceAccount -Message "Password of $ServiceAccount, for the service"
    $password = $credential.GetNetworkCredential().Password
}

$log = Join-Path $env:TEMP 'blinky-adcs-connector-install.log'
$arguments = @('/i', "`"$Msi`"", '/qn', '/l*v', "`"$log`"",
    "APIURL=`"$ApiUrl`"", "SERVICEDOMAIN=`"$serviceDomain`"", "SERVICEUSER=`"$serviceUser`"")
if ($password) { $arguments += "SERVICEPASSWORD=`"$password`"" }
if ($JoinToken) { $arguments += "JOINTOKEN=`"$JoinToken`"" }
if ($CaConfig) { $arguments += "CACONFIG=`"$CaConfig`"" }

$process = Start-Process msiexec.exe -ArgumentList $arguments -Wait -PassThru
$password = $null
$JoinToken = $null
if ($process.ExitCode -notin 0, 3010) { Fail "msiexec answered $($process.ExitCode); the log is $log." }
Ok "installed; log $log"

# Written after the MSI, which cannot know which agent certificate this script found.
Set-ItemProperty $RegistryKey -Name EnrolmentAgentThumbprint -Value $agent.Thumbprint
Set-ItemProperty $RegistryKey -Name EnrolmentAgentStore -Value 'LocalMachine'
Restart-Service $ServiceName
Ok 'enrolment agent configured, service restarted'

# ------------------------------------------------------------------ 5. enrolled?
Step '5/5  the connector enrolling and polling'

$deadline = (Get-Date).AddMinutes(2)
$seen = $null
while ((Get-Date) -lt $deadline) {
    Start-Sleep -Seconds 5
    $latest = Get-ChildItem $LogFolder -Filter 'connector-*.log' -ErrorAction SilentlyContinue |
        Sort-Object LastWriteTime -Descending | Select-Object -First 1
    if ($latest) {
        $seen = Select-String -Path $latest.FullName -Pattern 'Polling .* for calls|Enrolment attempt|refused this connector|no certificate and no enrolment token' |
            Select-Object -Last 1
        if ($seen -and $seen.Line -match 'Polling') { break }
    }
}

if ($seen -and $seen.Line -match 'Polling') {
    Ok $seen.Line.Trim()
    Write-Host "`nDone. In the console the connector is listed; on the server set DIRECTORY_VIA=Connector to read AD through it." -ForegroundColor Green
} else {
    $last = if ($seen) { $seen.Line.Trim() } else { 'nothing logged yet' }
    Fail "Not polling after two minutes. Last word from the connector: $last. Logs: $LogFolder"
}
