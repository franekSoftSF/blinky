using System.IO.Compression;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Blinky.Piv;

namespace Blinky.UnitTests;

/// <summary>
/// Certificate parsing has never run against hardware: all four slots were
/// empty on all three tokens on the bench. These cases build the PIV data
/// object by hand so the path is covered before a card ever holds one.
/// </summary>
public sealed class CertificateObjectTests
{
    [Fact]
    public void A_plain_certificate_object_yields_the_der()
    {
        var certificate = SelfSigned();
        var der = certificate.RawData;

        var extracted = PivSession.ExtractCertificate(BuildObject(der, compressed: false));

        Assert.NotNull(extracted);
        Assert.Equal(Convert.ToHexString(der), Convert.ToHexString(extracted!));
    }

    [Fact]
    public void A_gzipped_certificate_object_is_decompressed()
    {
        // Tag 71 bit 0 says the DER arrived gzipped. Missing it produces
        // "not a certificate" on a card that is perfectly fine.
        var certificate = SelfSigned();
        var der = certificate.RawData;

        var extracted = PivSession.ExtractCertificate(BuildObject(der, compressed: true));

        Assert.NotNull(extracted);
        Assert.Equal(Convert.ToHexString(der), Convert.ToHexString(extracted!));
    }

    [Fact]
    public void The_extracted_der_parses_back_into_the_same_certificate()
    {
        var certificate = SelfSigned();

        var extracted = PivSession.ExtractCertificate(
            BuildObject(certificate.RawData, compressed: false));
        var parsed = X509CertificateLoader.LoadCertificate(extracted!);

        Assert.Equal(certificate.Thumbprint, parsed.Thumbprint);
    }

    [Fact]
    public void An_object_with_no_certificate_tag_yields_null()
    {
        Assert.Null(PivSession.ExtractCertificate([0x53, 0x03, 0x71, 0x01, 0x00]));
    }

    [Fact]
    public void An_empty_object_yields_null()
    {
        Assert.Null(PivSession.ExtractCertificate([]));
    }

    private static X509Certificate2 SelfSigned()
    {
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var request = new CertificateRequest("CN=Blinky test", key, HashAlgorithmName.SHA256);

        return request.CreateSelfSigned(
            DateTimeOffset.UnixEpoch, DateTimeOffset.UnixEpoch.AddYears(10));
    }

    /// <summary>Wraps DER the way a PIV data object does: 53 { 70 der, 71 info, FE }.</summary>
    private static byte[] BuildObject(byte[] der, bool compressed)
    {
        var payload = der;

        if (compressed)
        {
            using var output = new MemoryStream();
            using (var gzip = new GZipStream(output, CompressionMode.Compress, leaveOpen: true))
            {
                gzip.Write(der);
            }

            payload = output.ToArray();
        }

        var inner = new List<byte>();
        inner.Add(0x70);
        inner.AddRange(Length(payload.Length));
        inner.AddRange(payload);
        inner.AddRange([0x71, 0x01, (byte)(compressed ? 0x01 : 0x00)]);
        inner.AddRange([0xFE, 0x00]);

        var outer = new List<byte> { 0x53 };
        outer.AddRange(Length(inner.Count));
        outer.AddRange(inner);

        return [.. outer];
    }

    private static byte[] Length(int length) => length switch
    {
        < 0x80 => [(byte)length],
        <= 0xFF => [0x81, (byte)length],
        _ => [0x82, (byte)(length >> 8), (byte)(length & 0xFF)],
    };
}
