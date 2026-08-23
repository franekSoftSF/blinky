<#
.SYNOPSIS
    Installs the Blinky agent on a domain-joined Windows client in the lab.

.DESCRIPTION
    Run elevated, from the folder holding blinky-agent-*.msi.

    The chain is downloaded; nothing has to be placed next to this script.

    Three things, in an order that matters:

      1. The chain, from http://<cms>/pki/ - the same unauthenticated listener
         that serves the revocation list. Both halves go in, and to different
         places: the root into LocalMachine\Root, the issuing CA into
         LocalMachine\CA.

         Both matter, for different reasons. Without the root the agent refuses
         to talk to the backend, and refusing is correct - so the failure looks
         like a broken agent rather than a missing certificate. Without the
         issuing CA, TLS still works, because a server sends its own chain -
         but smart-card logon does not, because the workstation has to build a
         path for a certificate on the card and nobody sends it the
         intermediate. certutil -scinfo then calls the chain incomplete and the
         logon is refused for a reason that names trust.

         They are checked against each other before either is trusted.

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

    # Where the chain comes from. Plain HTTP on purpose: this is the same
    # listener that serves the revocation list, and a machine fetching the
    # certificates it needs in order to trust anything cannot be asked to
    # validate a certificate first. What protects these is that they are
    # checked after they arrive, not how they travelled.
    [string] $PkiUrl = 'http://by-cacms.blinky.lab',

    # For a workstation with no route to the CMS: a copy of root.crt taken
    # there by hand. issuing.crt is then expected beside it.
    [string] $CaCertificate
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

if (-not (Test-Path $Msi)) { throw "Not found: $Msi" }

if ($CaCertificate -and -not (Test-Path $CaCertificate)) {
    throw "Not found: $CaCertificate"
}

Write-Host "`n1/3  trusting the lab CA"

# Fetched rather than carried. The chain used to have to be copied next to this
# script by hand, and the file it looked for - dev-ca.crt - stopped being the
# CA that signs anything the moment the edge started using the real issuing CA.
# A stale anchor placed by hand fails as "the agent will not connect", which
# reads as a broken agent.
$work = Join-Path $env:TEMP "blinky-chain"
New-Item -ItemType Directory -Force -Path $work | Out-Null

$rootFile    = Join-Path $work 'root.crt'
$issuingFile = Join-Path $work 'issuing.crt'

if ($CaCertificate) {
    Copy-Item $CaCertificate $rootFile -Force

    $beside = Join-Path (Split-Path -Parent $CaCertificate) 'issuing.crt'
    if (Test-Path $beside) { Copy-Item $beside $issuingFile -Force }

    Write-Host "     from $CaCertificate"
}
else {
    Write-Host "     from $PkiUrl/pki/"

    try {
        Invoke-WebRequest "$PkiUrl/pki/root.crt"    -OutFile $rootFile    -UseBasicParsing
        Invoke-WebRequest "$PkiUrl/pki/issuing.crt" -OutFile $issuingFile -UseBasicParsing
    }
    catch {
        throw @"
Could not fetch the chain from $PkiUrl/pki/.

    $($_.Exception.Message)

That address is plain HTTP on port 80 of the CMS host and needs no
credentials. If this machine cannot reach it, take root.crt and issuing.crt
there by hand and pass -CaCertificate.
"@
    }
}

$root = [Security.Cryptography.X509Certificates.X509Certificate2]::new($rootFile)

# Checked before it is trusted. Importing into LocalMachine\Root tells this
# machine to believe everything the holder of that key ever signs, so the one
# thing worth doing first is confirming the two files are actually a pair -
# a fetch that silently returned a login page or somebody else's CA would
# otherwise be installed as an anchor without a word.
if (Test-Path $issuingFile) {
    $issuing = [Security.Cryptography.X509Certificates.X509Certificate2]::new($issuingFile)

    $chain = [Security.Cryptography.X509Certificates.X509Chain]::new()
    $chain.ChainPolicy.RevocationMode    = 'NoCheck'
    $chain.ChainPolicy.VerificationFlags = 'AllowUnknownCertificateAuthority'
    $chain.ChainPolicy.ExtraStore.Add($root) | Out-Null

    if (-not $chain.Build($issuing) -or
            $chain.ChainElements[$chain.ChainElements.Count - 1].Certificate.Thumbprint -ne $root.Thumbprint) {
        throw "issuing.crt does not chain to root.crt. Refusing to trust either."
    }
}

# LocalMachine\Root, because the service runs as LocalSystem and a root in the
# installing user's store would be invisible to it.
Import-Certificate -FilePath $rootFile `
                   -CertStoreLocation Cert:\LocalMachine\Root | Out-Null

# The anchor the agent pins, written as PEM whatever arrived.
#
# /pki/root.crt is DER - that is what an authority information access address
# is supposed to serve, and what Windows expects from a .crt. The agent read
# PEM only and refused to start at all: "the certificate contents do not
# contain a PEM with a CERTIFICATE label", for a file that was a perfectly good
# certificate. Newer agents take either; this keeps the ones already installed
# working, and costs four lines.
$rootPem = Join-Path $work 'root.pem'

@(
    '-----BEGIN CERTIFICATE-----'
    [Convert]::ToBase64String($root.RawData, 'InsertLineBreaks')
    '-----END CERTIFICATE-----'
) | Set-Content -Path $rootPem -Encoding ascii

Write-Host "     root     $($root.Subject)"
Write-Host "     thumb    $($root.Thumbprint)"

# The intermediate, into the intermediate store rather than Root.
#
# A server sends its own chain, so TLS works without this. Smart-card logon
# does not: the workstation builds the path for a certificate on the card
# itself, and nobody sends it the issuing CA. Without this, certutil -scinfo
# reports the chain as incomplete and the logon is refused for a reason that
# names trust and not a missing certificate.
if (Test-Path $issuingFile) {
    Import-Certificate -FilePath $issuingFile `
                       -CertStoreLocation Cert:\LocalMachine\CA | Out-Null

    Write-Host "     issuing  $($issuing.Subject)"
}
else {
    Write-Host "     issuing  not present - smart-card logon will fail on chain building"
}

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
    "SERVERCA=$rootPem"
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
