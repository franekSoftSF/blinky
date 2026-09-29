<#
.SYNOPSIS
    Lab: enrols a directory account onto a token through the API, the way a console
    enrolment page will once it exists.

.DESCRIPTION
    Signs in as an operator - the password and the code are typed here and go only to
    the API - creates the cardholder from the directory if it is not on file, and asks
    the named agent to enrol the token. Then follows the job until it finishes.

    The token gets a new key in the slot. Nothing is asked twice: check the serial.

.EXAMPLE
    .\lab-enrol.ps1 -Account s.frankiewicz -Agent vdf001 -TokenSerial 39218739
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)] [string] $Account,
    [Parameter(Mandatory)] [string] $Agent,
    [Parameter(Mandatory)] [long] $TokenSerial,
    [string] $Console = 'https://by-cacms.blinky.lab:8443',
    [string] $Slot = '9A',
    [string] $Profile = 'smartcard-logon',
    [ValidateSet('Rsa2048', 'EccP256')] [string] $KeyAlgorithm = 'Rsa2048',
    [string] $Operator = $env:USERNAME
)

$ErrorActionPreference = 'Stop'

function Call([string] $Method, [string] $Path, $Body, [string] $Token) {
    $headers = @{}
    if ($Token) { $headers.Authorization = "Bearer $Token" }

    $arguments = @{ Method = $Method; Uri = "$Console$Path"; Headers = $headers; ContentType = 'application/json' }
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

$user = Read-Host "operator [$Operator]"
if ($user) { $Operator = $user }

$secure = Read-Host 'password' -AsSecureString
$password = [Runtime.InteropServices.Marshal]::PtrToStringUni(
    [Runtime.InteropServices.Marshal]::SecureStringToGlobalAllocUnicode($secure))
$code = Read-Host 'code from the authenticator (Enter if none)'

$signedIn = Call POST '/api/auth/sign-in' @{ username = $Operator; password = $password; totpCode = $code }
$password = $null

if (-not $signedIn.token) {
    throw "Signed in without a session: $($signedIn | ConvertTo-Json -Compress). Finish the sign-in in the console first."
}

$token = $signedIn.token
Write-Host "signed in  $Operator"

# ------------------------------------------------------------------ what the server sees

$overview = Call GET '/api/console/overview' $null $token

$agentRow = $overview.agents | Where-Object { $_.hostname -eq $Agent.ToLowerInvariant() }
if (-not $agentRow) { throw "No agent called $Agent. Known: $(($overview.agents.hostname) -join ', ')" }

# The slot as the card has it now, not as the last job left the server's record. A
# failed enrolment can leave a generated key behind; only an inventory turns that into
# KeyPresent, which is the one state the server lets the agent generate over.
$inventory = Call POST '/api/jobs/inventory' @{ agentId = $agentRow.id; reason = "lab-$(Get-Date -Format yyyyMMddHHmmss)" } $token
Write-Host "inventory  $($inventory.id) $($inventory.state)"

$inventoryDeadline = (Get-Date).AddMinutes(2)
do {
    Start-Sleep -Seconds 3
    $overview = Call GET '/api/console/overview' $null $token
    $inventoryJob = $overview.jobs | Where-Object { $_.id -eq $inventory.id }
} while ($inventoryJob.state -notin 'Succeeded', 'Failed', 'Expired', 'Cancelled' -and (Get-Date) -lt $inventoryDeadline)

Write-Host "           $($inventoryJob.state)"

$tokenRow = $overview.tokens | Where-Object { $_.serial -eq $TokenSerial }
if (-not $tokenRow) { throw "The server has not seen token $TokenSerial. Plug it into $Agent and wait for a heartbeat." }

$slotRow = $overview.slots | Where-Object { $_.tokenSerial -eq $TokenSerial -and $_.slotId -eq $Slot }

Write-Host "agent      $($agentRow.hostname).$($agentRow.domain), $($agentRow.state), last seen $($agentRow.lastHeartbeatAt)"
Write-Host "token      $TokenSerial, firmware $($tokenRow.firmwareVersion), $($tokenRow.state)"
Write-Host "slot       $Slot is $($slotRow.state)"

# ------------------------------------------------------------------ the cardholder

$people = Call GET "/api/cardholders?q=$([uri]::EscapeDataString($Account))" $null $token
$list = if ($people.items) { $people.items } elseif ($people.cardholders) { $people.cardholders } else { $people }
$cardholder = @($list) | Where-Object { $_.upn -and $_.upn.ToLowerInvariant().StartsWith($Account.ToLowerInvariant() + '@') } | Select-Object -First 1

if (-not $cardholder) {
    $cardholder = Call POST '/api/cardholders' @{ directoryAccount = $Account } $token
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
    cardholderId = $cardholder.id
    keyAlgorithm = $KeyAlgorithm
    reason       = "lab-$(Get-Date -Format yyyyMMddHHmmss)"
} $token

Write-Host "job        $($job.id) $($job.state) (created: $($job.created))"
Write-Host 'waiting    the agent on the workstation will ask for the PIN'

$deadline = (Get-Date).AddMinutes(10)
do {
    Start-Sleep -Seconds 5
    $current = (Call GET '/api/console/overview' $null $token).jobs | Where-Object { $_.id -eq $job.id }
    Write-Host "           $($current.state) $($current.result)"
} while ($current.state -notin 'Succeeded', 'Failed', 'Expired', 'Cancelled' -and (Get-Date) -lt $deadline)

$credential = (Call GET '/api/console/overview' $null $token).credentials |
    Where-Object { $_.tokenSerial -eq $TokenSerial -and $_.slotId -eq $Slot } |
    Sort-Object notAfter -Descending | Select-Object -First 1

if ($credential) {
    Write-Host "credential $($credential.subjectDn), $($credential.state), until $($credential.notAfter)"
}
