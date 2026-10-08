<#
.SYNOPSIS
    Lab: enrols a directory account onto a token through the API, the way a console
    enrolment page will once it exists.

.DESCRIPTION
    Signs in as an operator - the password and the code are typed here and go only to
    the API - creates the cardholder from the directory if it is not on file, and asks
    the named agent to enrol the token. Then follows the job until it finishes.

    The session is the console's own: the blinky_session cookie, and blinky_csrf echoed
    in X-Blinky-Csrf on every POST. The first version of this script read a bearer
    token out of the sign-in body, which 0101 removed, and named by-cacms.blinky.lab,
    which no longer exists; it failed against both before it asked anything.

    The token gets a new key in the slot. Nothing is asked twice: check the serial.

.PARAMETER Console
    https://<server>:8443. Read from blinky-server.json beside this script when not given.

.PARAMETER TokenSerial
    The YubiKey's serial. May be left out when the server knows exactly one token.

.EXAMPLE
    .\lab-enrol.ps1 -Account s.frankiewicz -Agent PC-0001 -Console https://blinky-cms.ad.digitalworkspace.pl:8443
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)] [string] $Account,
    [Parameter(Mandatory)] [string] $Agent,
    [long] $TokenSerial,
    [string] $Console,
    [string] $Slot = '9A',
    [string] $Profile = 'smartcard-logon',
    [ValidateSet('Rsa2048', 'EccP256')] [string] $KeyAlgorithm = 'Rsa2048',
    [string] $Operator = 'superadmin'
)

$ErrorActionPreference = 'Stop'

if (-not $Console) {
    $package = Join-Path $PSScriptRoot 'blinky-server.json'
    if (Test-Path $package) { $Console = (Get-Content $package -Raw | ConvertFrom-Json).consoleUrl }
}
if (-not $Console) { throw 'No server: pass -Console https://<server>:8443.' }
$Console = $Console.TrimEnd('/')

$web = New-Object Microsoft.PowerShell.Commands.WebRequestSession

function Csrf {
    $cookie = $web.Cookies.GetCookies([Uri]$Console) | Where-Object { $_.Name -eq 'blinky_csrf' }
    if ($cookie) { $cookie.Value } else { $null }
}

function Call([string] $Method, [string] $Path, $Body) {
    $arguments = @{ Method = $Method; Uri = "$Console$Path"; WebSession = $web; ContentType = 'application/json' }
    if ($Method -ne 'GET' -and (Csrf)) { $arguments.Headers = @{ 'X-Blinky-Csrf' = (Csrf) } }
    if ($null -ne $Body) { $arguments.Body = ($Body | ConvertTo-Json -Depth 5) }

    try {
        Invoke-RestMethod @arguments
    }
    catch {
        $detail = $_.ErrorDetails.Message
        throw "$Method $Path failed: $($_.Exception.Message) $detail"
    }
}

# ------------------------------------------------------------------ sign in

Write-Host "console    $Console"
$user = Read-Host "operator [$Operator]"
if ($user) { $Operator = $user }

$secure = Read-Host 'password' -AsSecureString
$password = [Runtime.InteropServices.Marshal]::PtrToStringUni(
    [Runtime.InteropServices.Marshal]::SecureStringToGlobalAllocUnicode($secure))
$code = Read-Host 'code from the authenticator'

$signedIn = Call POST '/api/auth/sign-in' @{ username = $Operator; password = $password; totpCode = $code }
$password = $null

if ($signedIn.outcome -ne 'signed-in' -or -not (Csrf)) {
    throw ("Not signed in: $($signedIn.outcome). A new password and the authenticator are set up in " +
           'the console at the first sign-in; finish that there, then run this again.')
}

Write-Host "signed in  $Operator"

# ------------------------------------------------------------------ what the server sees

$overview = Call GET '/api/console/overview'

$wanted = $Agent.ToLowerInvariant()
$agentRow = @($overview.agents) | Where-Object {
    $_.hostname.ToLowerInvariant() -eq $wanted -or "$($_.hostname).$($_.domain)".ToLowerInvariant() -eq $wanted
} | Select-Object -First 1
if (-not $agentRow) { throw "No agent called $Agent. Known: $((@($overview.agents) | ForEach-Object { "$($_.hostname).$($_.domain)" }) -join ', ')" }

# The slot as the card has it now, not as the last job left the server's record. A
# failed enrolment can leave a generated key behind; only an inventory turns that into
# KeyPresent, which is the one state the server lets the agent generate over.
$inventory = Call POST '/api/jobs/inventory' @{ agentId = $agentRow.id; reason = "lab-$(Get-Date -Format yyyyMMddHHmmss)" }
Write-Host "inventory  $($inventory.id) $($inventory.state)"

$inventoryDeadline = (Get-Date).AddMinutes(2)
do {
    Start-Sleep -Seconds 3
    $overview = Call GET '/api/console/overview'
    $inventoryJob = @($overview.jobs) | Where-Object { $_.id -eq $inventory.id }
} while ($inventoryJob.state -notin 'Succeeded', 'Failed', 'Expired', 'Cancelled' -and (Get-Date) -lt $inventoryDeadline)

Write-Host "           $($inventoryJob.state)"

if (-not $TokenSerial) {
    $known = @($overview.tokens)
    if ($known.Count -ne 1) {
        throw "Pass -TokenSerial: the server knows $($known.Count) tokens ($(($known.serial) -join ', '))."
    }
    $TokenSerial = $known[0].serial
}

$tokenRow = @($overview.tokens) | Where-Object { $_.serial -eq $TokenSerial }
if (-not $tokenRow) { throw "The server has not seen token $TokenSerial. Plug it into $Agent and wait for a heartbeat." }

$slotRow = @($overview.slots) | Where-Object { $_.tokenSerial -eq $TokenSerial -and $_.slotId -eq $Slot }

Write-Host "agent      $($agentRow.hostname).$($agentRow.domain) $($agentRow.version), $($agentRow.state), last seen $($agentRow.lastHeartbeatAt)"
Write-Host "token      $TokenSerial, firmware $($tokenRow.firmwareVersion), $($tokenRow.state)"
Write-Host "slot       $Slot is $($slotRow.state)"

# ------------------------------------------------------------------ the cardholder

$people = Call GET "/api/cardholders?q=$([uri]::EscapeDataString($Account))"
$list = if ($people.items) { $people.items } elseif ($people.cardholders) { $people.cardholders } else { $people }
$cardholder = @($list) | Where-Object { $_.upn -and $_.upn.ToLowerInvariant().StartsWith($Account.ToLowerInvariant() + '@') } | Select-Object -First 1

if (-not $cardholder) {
    # Read from the directory - through the ADCS connector where DIRECTORY_VIA=Connector -
    # so the UPN and the SID are the directory's, not typed.
    $cardholder = Call POST '/api/cardholders' @{ directoryAccount = $Account }
    Write-Host "cardholder created from the directory"
}

Write-Host "cardholder $($cardholder.displayName) <$($cardholder.upn)> $($cardholder.objectSid)"

if (-not $cardholder.objectSid) { throw "$Account has no objectSid on file, and a logon certificate needs one." }

# ------------------------------------------------------------------ the job

$job = Call POST '/api/jobs/enrol' @{
    agentId      = $agentRow.id
    tokenSerial  = $TokenSerial
    slotId       = $Slot
    profileName  = $Profile
    displayName  = $cardholder.displayName
    cardholderId = $cardholder.id
    keyAlgorithm = $KeyAlgorithm
    reason       = "lab-$(Get-Date -Format yyyyMMddHHmmss)"
}

Write-Host "job        $($job.id) $($job.state) (created: $($job.created))"
Write-Host 'waiting    the agent on the workstation will ask for the PIN'

$deadline = (Get-Date).AddMinutes(10)
do {
    Start-Sleep -Seconds 5
    $current = @((Call GET '/api/console/overview').jobs) | Where-Object { $_.id -eq $job.id }
    Write-Host "           $($current.state) $($current.result)"
} while ($current.state -notin 'Succeeded', 'Failed', 'Expired', 'Cancelled' -and (Get-Date) -lt $deadline)

$credential = @((Call GET '/api/console/overview').credentials) |
    Where-Object { $_.tokenSerial -eq $TokenSerial -and $_.slotId -eq $Slot } |
    Sort-Object notAfter -Descending | Select-Object -First 1

if ($credential) {
    Write-Host "credential $($credential.subjectDn), $($credential.state), until $($credential.notAfter)"
}
