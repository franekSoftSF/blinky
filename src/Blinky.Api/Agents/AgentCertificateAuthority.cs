using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace Blinky.Api.Agents;

/// <summary>
/// Issues the client certificates agents authenticate with.
/// </summary>
/// <remarks>
/// A separate authority from the one that issues credentials onto tokens, and
/// separate on purpose: this one says "this machine is in the fleet", which is
/// a much weaker claim than "this person holds this key on hardware". Mixing
/// them would let a compromised agent certificate mean something it should not.
/// </remarks>
public sealed class AgentCertificateAuthority(X509Certificate2 issuer, TimeSpan lifetime)
{
    private static readonly Oid ClientAuthentication = new("1.3.6.1.5.5.7.3.2");

    public string IssuerSubject => issuer.Subject;

    public static AgentCertificateAuthority Load(string certificatePath, string keyPath,
        TimeSpan lifetime)
    {
        if (!File.Exists(certificatePath) || !File.Exists(keyPath))
        {
            throw new FileNotFoundException(
                $"The agent CA is missing: expected {certificatePath} and {keyPath}. "
                + "Run scripts/dev-certs.sh, or point Blinky:AgentCa at real material.");
        }

        var issuer = X509Certificate2.CreateFromPemFile(certificatePath, keyPath);

        return new AgentCertificateAuthority(issuer, lifetime);
    }

    /// <summary>
    /// Signs a certificate request from an agent. The subject comes from the
    /// registration, never from the request: a machine may prove it holds a
    /// key, but it does not get to choose what it is called.
    /// </summary>
    public X509Certificate2 Issue(CertificateRequest request, string hostname, string domain)
    {
        var subject = new X500DistinguishedName(
            $"CN={hostname}.{domain}, OU=Blinky agents");

        var certificate = new CertificateRequest(subject, request.PublicKey,
            HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);

        certificate.CertificateExtensions.Add(
            new X509BasicConstraintsExtension(false, false, 0, true));
        certificate.CertificateExtensions.Add(
            new X509KeyUsageExtension(X509KeyUsageFlags.DigitalSignature, true));
        certificate.CertificateExtensions.Add(
            new X509EnhancedKeyUsageExtension([ClientAuthentication], false));
        certificate.CertificateExtensions.Add(
            new X509SubjectKeyIdentifierExtension(request.PublicKey, false));

        var serialNumber = RandomNumberGenerator.GetBytes(16);
        serialNumber[0] &= 0x7F;

        // Backdated slightly so a workstation whose clock runs fast does not
        // reject its own certificate - but never before the issuer itself is
        // valid. A CA created minutes ago would otherwise make every enrolment
        // fail with an exception for the first five minutes of its life, which
        // is exactly when somebody is standing up a lab and trying it.
        var notBefore = DateTimeOffset.UtcNow.AddMinutes(-5);
        if (notBefore < issuer.NotBefore)
        {
            notBefore = issuer.NotBefore;
        }

        var notAfter = notBefore.Add(lifetime);
        if (notAfter > issuer.NotAfter)
        {
            // An agent certificate outliving its issuer is a certificate that
            // stops working without anything having expired.
            notAfter = issuer.NotAfter;
        }

        // Short-lived and rotated automatically, so a leaked agent certificate
        // expires on its own rather than needing to be noticed first.
        return certificate.Create(issuer, notBefore, notAfter, serialNumber);
    }
}
