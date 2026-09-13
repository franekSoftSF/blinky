<#
Blinky - the ADCS connector's client certificate request, made where the key will live.

    .\new-connector-request.ps1 -Out C:\Blinky\hzcs01-connector.csr
    # sign it on the Docker host with scripts/sign-connector-cert.sh, copy the .crt back, then:
    .\new-connector-request.ps1 -Accept C:\Blinky\hzcs01-connector.crt

Run as an administrator on the server the connector runs on. The key is generated in
LocalMachine\My by the Microsoft Software Key Storage Provider and marked not
exportable, so it never exists anywhere but here - which is the reason for taking a
request to the agent CA rather than a PKCS#12 from it.

Accepting prints the two values the connector's configuration needs. The service
account then needs read access to the key: certlm.msc, the certificate, All Tasks,
Manage Private Keys. That grant is left to whoever administers this server, on purpose.
#>
[CmdletBinding(DefaultParameterSetName = 'Request')]
param(
    [Parameter(ParameterSetName = 'Request', Mandatory)] [string] $Out,
    [Parameter(ParameterSetName = 'Request')] [string] $Subject = "CN=$($env:COMPUTERNAME.ToLowerInvariant()), OU=Blinky ADCS connector",
    [Parameter(ParameterSetName = 'Accept', Mandatory)] [string] $Accept
)

$ErrorActionPreference = 'Stop'

if ($PSCmdlet.ParameterSetName -eq 'Accept') {
    # certreq -accept pairs the certificate with the pending key it was requested with,
    # in the store the request was made in.
    & certreq.exe -accept -machine -q $Accept | Out-Null
    if ($LASTEXITCODE -ne 0) { throw "certreq -accept failed with $LASTEXITCODE." }

    # Windows PowerShell 5.1 is what a server has, so .NET Framework APIs only.
    $certificate = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2($Accept)
    $installed = Get-Item "Cert:\LocalMachine\My\$($certificate.Thumbprint)"

    if (-not $installed.HasPrivateKey) { throw 'The certificate was installed without its key.' }

    $sha256 = [BitConverter]::ToString([System.Security.Cryptography.SHA256]::Create().ComputeHash($installed.RawData)).Replace("-", "")

    Write-Host "installed   $($installed.Subject), expires $($installed.NotAfter.ToString('yyyy-MM-dd'))"
    Write-Host "config      Connector:Api:ClientCertificate:Thumbprint = $($installed.Thumbprint)"
    Write-Host "api         Blinky:Adcs:Connector:ClientFingerprints   = $sha256"
    return
}

$inf = @"
[Version]
Signature = "`$Windows NT`$"

[NewRequest]
Subject = "$Subject"
KeyAlgorithm = RSA
KeyLength = 2048
ProviderName = "Microsoft Software Key Storage Provider"
MachineKeySet = TRUE
Exportable = FALSE
HashAlgorithm = SHA256
KeyUsage = 0x80
RequestType = PKCS10

[EnhancedKeyUsageExtension]
OID = 1.3.6.1.5.5.7.3.2
"@

$infPath = [System.IO.Path]::GetTempFileName()

try {
    Set-Content -Path $infPath -Value $inf -Encoding ascii
    & certreq.exe -new -q $infPath $Out | Out-Null
    if ($LASTEXITCODE -ne 0) { throw "certreq -new failed with $LASTEXITCODE." }
}
finally {
    Remove-Item $infPath -ErrorAction SilentlyContinue
}

Write-Host "request     $Out"
Write-Host "subject     $Subject"
Write-Host "next        sign it on the Docker host: bash scripts/sign-connector-cert.sh --csr <file> > <file>.crt"
