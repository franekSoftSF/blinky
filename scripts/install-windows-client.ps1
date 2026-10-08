<#
.SYNOPSIS
    Installs the Blinky agent on a domain-joined Windows client in the lab.

.DESCRIPTION
    Run elevated, from the unpacked blinky-workstation-*.zip downloaded from the
    console (Pobieranie). The package carries the MSI, this script and
    blinky-server.json, which names the server it came from - so a run needs no
    address and, after the first, no arguments at all (0105).

    No server is written into this script any more. It said by-cacms.blinky.lab,
    and a workstation in ad.digitalworkspace.pl installed from it enrolled against
    a name that no longer resolved; worse, the address was then remembered in the
    registry and preferred over anything given later.

    The chain is downloaded; nothing has to be placed next to this script.

    Five things, in an order that matters:

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

      2. Yubico's smart-card minidriver, when -Minidriver is given or a
         YubiKey*Minidriver*.msi lies beside this script. The inbox PIV
         minidriver produced no key container on BY-WIN-CLIENT01, so a
         certificate written to the card never reached the user's store. The
         MSI's Authenticode signature has to be valid and Yubico's before it
         runs. Other smart-card middleware - HID ActivClient - claims the card
         instead and is reported.

      3. ECC certificates at the logon screen, with -EnableEccLogon. Runs
         enable-ecc-smartcard-logon.ps1 from beside this script.

      4. The MSI, with the backend, the realm and the bootstrap token as
         properties. The token is passed as an MSI property that is already
         listed in MSIHIDDENPROPERTIES. That covers the property dumps but
         not the command line msiexec echoes at the top of the log, so the
         log is scrubbed afterwards.

      5. The tray, started for this session. It normally appears at the next
         logon, from HKLM\...\Run.

.PARAMETER BootstrapToken
    From the console: Administracja / Zetony, "Nowy zeton" - the value is shown
    once, and the token carries its own term and the number of machines it may
    enrol (0102). It used to come out of .env on the CMS host, where it was one
    value for every machine and never expired.

.PARAMETER Minidriver
    Yubico's minidriver MSI, from Yubico's "Smart Card Drivers and Tools" download
    page. Defaults to the newest YubiKey*Minidriver*.msi beside this script; with
    neither, the step is skipped and says so.

.PARAMETER EnableEccLogon
    Lets Windows offer ECC certificates at logon. Needed for a card enrolled with
    ECCP256; RSA 2048 does not need it.

.PARAMETER Server
    The Blinky server's name, for a run without blinky-server.json beside it:
    the agents' address is https://<Server>:9443 and the chain comes from
    http://<Server>/pki/.

.EXAMPLE
    # From the unpacked package: asks for the token, everything else is in it.
    .\install-windows-client.ps1

.EXAMPLE
    .\install-windows-client.ps1 -BootstrapToken abc123

.EXAMPLE
    # A workstation in the AD domain behind ADCS: everything, in one run.
    .\install-windows-client.ps1 -BootstrapToken abc123 -Domain ad.digitalworkspace.pl -EnableEccLogon
#>

[CmdletBinding()]
param(
    [string] $BootstrapToken,
    [string] $Server,
    [string] $Backend,
    [string] $Domain,
    # The newest one beside this script, rather than a version written here.
    # A default naming one particular build is a line somebody has to remember
    # to edit, and the failure when they do not is an installer that quietly
    # deploys the previous agent.
    [string] $Msi = (Get-ChildItem "$PSScriptRoot\blinky-agent-*.msi" -ErrorAction SilentlyContinue |
        Sort-Object LastWriteTime -Descending | Select-Object -First 1).FullName,

    # Where the chain comes from. Plain HTTP on purpose: this is the same
    # listener that serves the revocation list, and a machine fetching the
    # certificates it needs in order to trust anything cannot be asked to
    # validate a certificate first. What protects these is that they are
    # checked after they arrive, not how they travelled.
    [string] $PkiUrl,

    # For a workstation with no route to the CMS: a copy of root.crt taken
    # there by hand. issuing.crt is then expected beside it.
    [string] $CaCertificate,

    [string] $Minidriver = (Get-ChildItem "$PSScriptRoot\YubiKey*Minidriver*.msi" -ErrorAction SilentlyContinue |
        Sort-Object LastWriteTime -Descending | Select-Object -First 1).FullName,

    [switch] $EnableEccLogon
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

# The server: given here, else the package's blinky-server.json, else what this
# machine was told last time. The package wins over the registry on purpose - a
# package downloaded from a server is that server's word about itself, and the
# remembered value is how a dead address survived a reinstall.
$package = Join-Path $PSScriptRoot 'blinky-server.json'
$fromPackage = if (Test-Path $package) { Get-Content $package -Raw | ConvertFrom-Json } else { $null }

if ($Server) {
    if (-not $Backend) { $Backend = "https://${Server}:9443" }
    if (-not $PkiUrl) { $PkiUrl = "http://$Server" }
}
if ($fromPackage) {
    if (-not $Backend) { $Backend = $fromPackage.agentsUrl }
    if (-not $PkiUrl) { $PkiUrl = $fromPackage.pkiUrl }
}
if (-not $Backend) { $Backend = $existing.BackendUrl }

if (-not $Backend) {
    throw @'
No Blinky server to install against.

Run this from the unpacked blinky-workstation-*.zip downloaded from the console
(Pobieranie): blinky-server.json in it names the server. Or pass -Server.
'@
}

# The chain comes from the same host over plain HTTP, unless said otherwise.
if (-not $PkiUrl -and -not $CaCertificate) { $PkiUrl = 'http://' + ([Uri]$Backend).Host }

Write-Host "Blinky server: $Backend" -ForegroundColor Cyan
# The domain this machine is joined to before the lab's default. Not the service
# account's UserDomainName, which for LocalSystem is the machine name - that is
# the guess install-agent.ps1 refuses - but the join itself, which is a fact.
$joined = Get-CimInstance Win32_ComputerSystem
$Domain  = Prefer $Domain  $existing.Domain $(if ($joined.PartOfDomain) { $joined.Domain.ToLowerInvariant() } else { $null })
if (-not $Domain) { throw 'This machine is not joined to a domain and no -Domain was given.' }

# The token buys an identity and is useless afterwards. An agent that already
# holds one - a certificate in the machine store, named for it - is upgrading
# rather than enrolling, and should not be asked for it again.
$enrolled = @(Get-ChildItem Cert:\LocalMachine\My -ErrorAction SilentlyContinue |
    Where-Object { $_.FriendlyName -like 'Blinky agent *' }).Count -gt 0

if (-not $BootstrapToken) {
    $BootstrapToken = $existing.BootstrapToken

    if (-not $BootstrapToken -and -not $enrolled) {
        # Asked rather than refused: a token typed at a prompt stays out of shell
        # history, which a -BootstrapToken on the command line does not.
        $secure = Read-Host 'Agent enrolment token (console: Administracja / Zetony, purpose agent)' -AsSecureString
        $BootstrapToken = [Runtime.InteropServices.Marshal]::PtrToStringBSTR(
            [Runtime.InteropServices.Marshal]::SecureStringToBSTR($secure))

        if (-not $BootstrapToken) {
            throw 'This machine has no agent identity, and no enrolment token was given to get one.'
        }
    }
}

if (-not $Msi -or -not (Test-Path $Msi)) { throw "No blinky-agent-*.msi beside this script: $Msi" }

# Against the package's own list, when it is there: the same check the connector's
# installer makes, so a file that changed on the way is not installed as an agent.
$manifest = Join-Path (Split-Path -Parent $Msi) 'downloads.json'
if (Test-Path $manifest) {
    $listed = (Get-Content $manifest -Raw | ConvertFrom-Json).files |
        Where-Object { $_.file -eq (Split-Path -Leaf $Msi) }
    $hash = (Get-FileHash $Msi -Algorithm SHA256).Hash
    if (-not $listed) { throw "$(Split-Path -Leaf $Msi) is not in downloads.json." }
    if ($listed.sha256 -ne $hash) {
        throw "SHA-256 of $(Split-Path -Leaf $Msi) is $hash, and the package lists $($listed.sha256)."
    }
    Write-Host "$(Split-Path -Leaf $Msi): SHA-256 matches the package" -ForegroundColor Cyan
}

if ($CaCertificate -and -not (Test-Path $CaCertificate)) {
    throw "Not found: $CaCertificate"
}

# Checked before anything is installed, so a missing file stops the run rather
# than leaving a machine half set up.
$eccScript = Join-Path $PSScriptRoot 'enable-ecc-smartcard-logon.ps1'
if ($EnableEccLogon -and -not (Test-Path $eccScript)) {
    throw "-EnableEccLogon needs enable-ecc-smartcard-logon.ps1 beside this script: $eccScript"
}

Write-Host "`n1/5  trusting the lab CA"

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

Write-Host "`n2/5  Yubico minidriver"

$uninstall = @('HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*',
               'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*')
$installedSoftware = Get-ItemProperty $uninstall -ErrorAction SilentlyContinue | Where-Object DisplayName

# Reported, not removed: uninstalling somebody's middleware is not this script's
# decision, and the symptom it causes - a certificate written to the card that never
# appears in the user's store - is one nobody connects to it.
$other = $installedSoftware | Where-Object DisplayName -match 'ActivClient|ActivIdentity|SafeNet Authentication Client'
foreach ($o in $other) {
    Write-Warning "$($o.DisplayName) is installed. It binds the YubiKey to its own minidriver, and certificates written to the card then do not reach the certificate store."
}

$present = $installedSoftware | Where-Object DisplayName -match 'YubiKey.*Minidriver' | Select-Object -First 1
$restartOwed = $false

if ($Minidriver) {
    if (-not (Test-Path $Minidriver)) { throw "Not found: $Minidriver" }

    # A driver that handles the card's keys goes on this machine only if Yubico signed
    # it. A renamed download, a truncated one, or somebody else's MSI with the right
    # name all stop here.
    $signature = Get-AuthenticodeSignature -FilePath $Minidriver
    if ($signature.Status -ne 'Valid' -or $signature.SignerCertificate.Subject -notmatch 'Yubico') {
        throw "$Minidriver is not validly signed by Yubico: $($signature.Status), $($signature.SignerCertificate.Subject)"
    }

    Write-Host "     msi      $(Split-Path -Leaf $Minidriver)"
    Write-Host "     signed   $($signature.SignerCertificate.Subject)"
    if ($present) { Write-Host "     before   $($present.DisplayName) $($present.DisplayVersion)" }

    $minidriverLog = "$env:TEMP\yubikey-minidriver-install.log"
    $installed = Start-Process msiexec.exe -Wait -PassThru -ArgumentList @(
        '/i', "`"$Minidriver`"", '/qn', '/norestart', '/l*v', "`"$minidriverLog`"")

    # 3010 is success with a restart owed, which the end of this script says.
    switch ($installed.ExitCode) {
        0       { Write-Host "     installed" }
        3010    { Write-Host "     installed; Windows wants a restart before the minidriver is used"; $restartOwed = $true }
        default { throw "The minidriver's msiexec returned $($installed.ExitCode). The log is at $minidriverLog" }
    }
}
elseif ($present) {
    Write-Host "     already  $($present.DisplayName) $($present.DisplayVersion)"
}
else {
    Write-Warning ("No YubiKey*Minidriver*.msi beside this script and none installed. Enrolment " +
                   "works without it; a certificate reaching the user's store and smart-card " +
                   "logon may not. Download it from Yubico and run this again with -Minidriver.")
}

Write-Host "`n3/5  ECC certificates at logon"

if ($EnableEccLogon) {
    & $eccScript
}
else {
    Write-Host "     skipped  RSA cards need nothing; pass -EnableEccLogon for ECCP256"
}

Write-Host "`n4/5  installing the agent"
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

Write-Host "`n5/5  starting the tray for this session"

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

if ($restartOwed -or $EnableEccLogon) {
    Write-Host "Restart before the first smart-card logon: the minidriver and the logon policy are read at startup."
}
