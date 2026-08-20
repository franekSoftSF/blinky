using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Blinky.Api.Agents;

namespace Blinky.UnitTests;

/// <summary>
/// The end-to-end enrolment path needs a database and a running edge, and is
/// covered by `smoke-test.sh`. These are the properties of the issued
/// certificate itself, which need neither.
/// </summary>
public sealed class AgentCertificateAuthorityTests
{
    [Fact]
    public void The_subject_comes_from_the_registration_not_from_the_request()
    {
        // The security property this class exists for. A machine may prove it
        // holds a key; it does not get to choose what it is called, or every
        // agent could enrol as any other.
        var authority = BuildAuthority();
        var request = RequestNaming("CN=domain-controller.corp.example, OU=Domain Admins");

        using var issued = authority.Issue(request, "ws01", "corp.example");

        Assert.Equal("CN=ws01.corp.example, OU=Blinky agents", issued.Subject);
        Assert.DoesNotContain("Domain Admins", issued.Subject, StringComparison.Ordinal);
    }

    [Fact]
    public void The_certificate_is_for_client_authentication_only()
    {
        var authority = BuildAuthority();

        using var issued = authority.Issue(RequestNaming("CN=whatever"), "ws01", "corp.example");

        var eku = issued.Extensions.OfType<X509EnhancedKeyUsageExtension>().Single();
        Assert.Single(eku.EnhancedKeyUsages);
        Assert.Equal("1.3.6.1.5.5.7.3.2", eku.EnhancedKeyUsages[0].Value);
    }

    [Fact]
    public void The_certificate_cannot_sign_other_certificates()
    {
        // An agent certificate that is a CA would let one compromised
        // workstation mint identities for the whole fleet.
        var authority = BuildAuthority();

        using var issued = authority.Issue(RequestNaming("CN=whatever"), "ws01", "corp.example");

        var constraints = issued.Extensions.OfType<X509BasicConstraintsExtension>().Single();
        Assert.False(constraints.CertificateAuthority);

        var usage = issued.Extensions.OfType<X509KeyUsageExtension>().Single();
        Assert.False(usage.KeyUsages.HasFlag(X509KeyUsageFlags.KeyCertSign));
    }

    [Fact]
    public void The_certificate_is_short_lived()
    {
        // Ninety days and rotated automatically, so a leaked agent certificate
        // expires on its own rather than needing to be noticed first.
        var authority = BuildAuthority();

        using var issued = authority.Issue(RequestNaming("CN=whatever"), "ws01", "corp.example");

        var lifetime = issued.NotAfter - issued.NotBefore;
        Assert.InRange(lifetime.TotalDays, 89, 91);
    }

    [Fact]
    public void Serial_numbers_are_random_rather_than_sequential()
    {
        var authority = BuildAuthority();

        using var first = authority.Issue(RequestNaming("CN=a"), "ws01", "corp.example");
        using var second = authority.Issue(RequestNaming("CN=b"), "ws02", "corp.example");

        Assert.NotEqual(first.SerialNumber, second.SerialNumber);
        Assert.True(first.GetSerialNumber().Length >= 8);
    }

    [Fact]
    public void A_missing_agent_ca_is_reported_with_the_paths_it_looked_at()
    {
        // This is the first thing that goes wrong on a fresh clone, so the
        // message names the file and the script that creates it.
        var error = Assert.Throws<FileNotFoundException>(() =>
            AgentCertificateAuthority.Load("no-such.crt", "no-such.key", TimeSpan.FromDays(90)));

        Assert.Contains("no-such.crt", error.Message, StringComparison.Ordinal);
        Assert.Contains("dev-certs.sh", error.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void A_certificate_never_starts_before_the_issuer_does()
    {
        // The backdating that tolerates a fast workstation clock must not
        // reach past the CA's own start. A CA created a moment ago otherwise
        // makes every enrolment throw for the first five minutes of its life -
        // which is precisely when somebody is standing up a lab.
        var authority = BuildAuthority(issuerValidFrom: DateTimeOffset.UtcNow);

        using var issued = authority.Issue(RequestNaming("CN=whatever"), "ws01", "corp.example");

        Assert.True(issued.NotBefore >= issued.NotBefore.ToUniversalTime().AddMinutes(-1));
        Assert.InRange(issued.NotAfter - issued.NotBefore, TimeSpan.Zero, TimeSpan.FromDays(91));
    }

    [Fact]
    public void A_certificate_never_outlives_the_issuer()
    {
        // Otherwise it stops working with nothing having expired, which reads
        // as a bug in everything except the certificate.
        var authority = BuildAuthority(issuerValidUntil: DateTimeOffset.UtcNow.AddDays(10));

        using var issued = authority.Issue(RequestNaming("CN=whatever"), "ws01", "corp.example");

        Assert.True(issued.NotAfter <= DateTime.UtcNow.AddDays(11));
    }

    private static AgentCertificateAuthority BuildAuthority(
        DateTimeOffset? issuerValidFrom = null, DateTimeOffset? issuerValidUntil = null)
    {
        using var key = RSA.Create(2048);
        var request = new CertificateRequest("CN=Test agent CA", key,
            HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);

        request.CertificateExtensions.Add(new X509BasicConstraintsExtension(true, true, 0, true));
        request.CertificateExtensions.Add(
            new X509KeyUsageExtension(X509KeyUsageFlags.KeyCertSign, true));

        var issuer = request.CreateSelfSigned(
            issuerValidFrom ?? DateTimeOffset.UtcNow.AddDays(-1),
            issuerValidUntil ?? DateTimeOffset.UtcNow.AddYears(5));

        return new AgentCertificateAuthority(issuer, TimeSpan.FromDays(90));
    }

    private static CertificateRequest RequestNaming(string subject)
    {
        var key = RSA.Create(2048);

        return new CertificateRequest(subject, key, HashAlgorithmName.SHA256,
            RSASignaturePadding.Pkcs1);
    }
}
