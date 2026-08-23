using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Blinky.Agent.Service;

namespace Blinky.UnitTests;

/// <summary>
/// The pinned trust anchor is read from a file, and that file turns up in both
/// encodings.
/// </summary>
/// <remarks>
/// DER is what an authority information access address serves and what Windows
/// expects from a .crt; PEM is what a chain.pem holds and what an export by
/// hand produces. Reading only one of them meant the service failed to start -
/// not the connection, the whole host - with a message about a missing PEM
/// label for a file that was a perfectly good certificate.
/// </remarks>
public class BackendAnchorTests
{
    private static X509Certificate2 SomeCertificate()
    {
        using var key = RSA.Create(2048);

        var request = new CertificateRequest(
            "CN=Anchor Under Test", key, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);

        return request.CreateSelfSigned(
            DateTimeOffset.UtcNow.AddMinutes(-5), DateTimeOffset.UtcNow.AddDays(1));
    }

    [Fact]
    public void A_pem_anchor_is_accepted()
    {
        using var certificate = SomeCertificate();
        var path = Path.GetTempFileName();

        try
        {
            File.WriteAllText(path, certificate.ExportCertificatePem());

            using var client = new BackendClient(new Uri("https://example.invalid"), path);

            Assert.Equal(new Uri("https://example.invalid"), client.Backend);
        }
        finally
        {
            File.Delete(path);
        }
    }

    [Fact]
    public void A_der_anchor_is_accepted()
    {
        using var certificate = SomeCertificate();
        var path = Path.GetTempFileName();

        try
        {
            File.WriteAllBytes(path, certificate.Export(X509ContentType.Cert));

            using var client = new BackendClient(new Uri("https://example.invalid"), path);

            Assert.Equal(new Uri("https://example.invalid"), client.Backend);
        }
        finally
        {
            File.Delete(path);
        }
    }

    /// <summary>
    /// And something that is neither still fails, rather than being accepted as
    /// an anchor nobody chose.
    /// </summary>
    [Fact]
    public void Anything_else_is_refused()
    {
        var path = Path.GetTempFileName();

        try
        {
            File.WriteAllText(path, "this is not a certificate");

            Assert.ThrowsAny<CryptographicException>(() =>
                new BackendClient(new Uri("https://example.invalid"), path));
        }
        finally
        {
            File.Delete(path);
        }
    }
}
