using Blinky.Piv;

namespace Blinky.UnitTests;

/// <summary>
/// The public key a card returns from GENERATE ASYMMETRIC KEY PAIR, in both
/// shapes it comes in.
/// </summary>
/// <remarks>
/// RSA was never exercised: the agent had EccP256 written into it, so the only
/// response anyone ever decoded was the ECC one - and that one worked by
/// accident. 7F49 is a single two-byte tag, the parser read it as tag 7F with
/// a length of 0x49, and for ECC that length overran the buffer, got clamped
/// to what was left, and the caller's [1..] skipped exactly the byte that
/// needed skipping. An RSA response is longer, nothing overruns, and the
/// parser walked into the middle of the modulus - then reported "the generated
/// key response has no tag 81" for a key sitting right there in the bytes.
/// </remarks>
public class PublicKeyTemplateTests
{
    /// <summary>An RSA 2048 response, shaped as a card sends it.</summary>
    private static byte[] RsaResponse()
    {
        // A modulus with the high bit set, as a real one has.
        var modulus = new byte[256];
        modulus[0] = 0xC0;
        for (var i = 1; i < modulus.Length; i++)
        {
            modulus[i] = (byte)(i * 7 % 251 + 1);
        }

        var body = new List<byte>();

        body.Add(0x81);                      // modulus
        body.AddRange([0x82, 0x01, 0x00]);   // long-form length: 256
        body.AddRange(modulus);

        body.Add(0x82);                      // public exponent
        body.Add(0x03);
        body.AddRange([0x01, 0x00, 0x01]);   // 65537

        var response = new List<byte> { 0x7F, 0x49 };

        // The template's own length, long form, because it is over 255.
        response.AddRange([0x82, (byte)(body.Count >> 8), (byte)(body.Count & 0xFF)]);
        response.AddRange(body);

        return [.. response];
    }

    /// <summary>An ECC P-256 response, shaped as a card sends it.</summary>
    private static byte[] EccResponse()
    {
        // A real point: an arbitrary one is not on the curve, and .NET refuses
        // to import it - which would make this test fail for a reason that has
        // nothing to do with parsing.
        using var ecdsa = System.Security.Cryptography.ECDsa.Create(
            System.Security.Cryptography.ECCurve.NamedCurves.nistP256);

        var parameters = ecdsa.ExportParameters(false);

        var point = new byte[65];
        point[0] = 0x04;
        parameters.Q.X!.CopyTo(point, 1);
        parameters.Q.Y!.CopyTo(point, 33);

        var body = new List<byte> { 0x86, (byte)point.Length };
        body.AddRange(point);

        var response = new List<byte> { 0x7F, 0x49, (byte)body.Count };
        response.AddRange(body);

        return [.. response];
    }

    [Fact]
    public void The_template_is_one_two_byte_tag()
    {
        var parsed = Tlv.ParseBer(RsaResponse());

        Assert.True(parsed.ContainsKey(0x7F49),
            "7F49 is a single tag; reading it as 7F with a length of 0x49 walks "
            + "into the value.");

        Assert.False(parsed.ContainsKey(0x7F));
    }

    [Fact]
    public void An_rsa_key_decodes()
    {
        var key = PublicKeyDecoder.Decode(RsaResponse(), PivAlgorithm.Rsa2048);

        Assert.Equal(PivAlgorithm.Rsa2048, key.Algorithm);

        using var rsa = System.Security.Cryptography.RSA.Create();
        rsa.ImportSubjectPublicKeyInfo(key.SubjectPublicKeyInfo, out _);

        Assert.Equal(2048, rsa.KeySize);
        Assert.Equal([0x01, 0x00, 0x01], rsa.ExportParameters(false).Exponent);
    }

    /// <summary>
    /// And the one that used to work by accident still works on purpose.
    /// </summary>
    [Fact]
    public void An_ecc_key_decodes()
    {
        var key = PublicKeyDecoder.Decode(EccResponse(), PivAlgorithm.EccP256);

        Assert.Equal(PivAlgorithm.EccP256, key.Algorithm);
        Assert.NotEmpty(key.SubjectPublicKeyInfo);
    }
}
