using System.Formats.Asn1;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace Blinky.Piv;

/// <summary>
/// Lets .NET build a certificate request whose signature is made by the token.
/// </summary>
/// <remarks>
/// <para>
/// This is what makes a PKCS#10 proof rather than paperwork. The private key
/// exists only inside the card; the request is assembled here, the digest goes
/// to the card, and the signature comes back. Nothing anywhere holds the key.
/// </para>
/// <para>
/// Implementing <see cref="X509SignatureGenerator"/> rather than assembling the
/// request by hand means .NET's own ASN.1 writes the structure. There is no
/// good reason to hand-roll DER next to a library that already does it
/// correctly.
/// </para>
/// </remarks>
public sealed class PivSignatureGenerator(
    PivSession session,
    PivSlot slot,
    PivPublicKey publicKey) : X509SignatureGenerator
{
    private const string EcdsaWithSha256 = "1.2.840.10045.4.3.2";
    private const string EcdsaWithSha384 = "1.2.840.10045.4.3.3";
    private const string Sha256WithRsa = "1.2.840.113549.1.1.11";
    private const string Sha256 = "2.16.840.1.101.3.4.2.1";

    private bool IsEcc => publicKey.Algorithm is PivAlgorithm.EccP256 or PivAlgorithm.EccP384;

    /// <summary>
    /// The key the card generated. .NET calls this when it needs to put the
    /// public key into a request it is building.
    /// </summary>
    protected override PublicKey BuildPublicKey()
    {
        var key = publicKey.Create();

        return key switch
        {
            ECDsa ecdsa => new PublicKey(ecdsa),
            RSA rsa => new PublicKey(rsa),
            _ => throw new PivProtocolException(
                $"{publicKey.Algorithm} cannot be turned into an X.509 public key here."),
        };
    }

    public override byte[] GetSignatureAlgorithmIdentifier(HashAlgorithmName hashAlgorithm)
    {
        var writer = new AsnWriter(AsnEncodingRules.DER);

        using (writer.PushSequence())
        {
            if (IsEcc)
            {
                writer.WriteObjectIdentifier(publicKey.Algorithm is PivAlgorithm.EccP384
                    ? EcdsaWithSha384
                    : EcdsaWithSha256);
            }
            else
            {
                writer.WriteObjectIdentifier(Sha256WithRsa);

                // RSA signature algorithms carry an explicit NULL parameter.
                // Omitting it produces a structure some verifiers accept and
                // others do not, which is the worst of both.
                writer.WriteNull();
            }
        }

        return writer.Encode();
    }

    public override byte[] SignData(byte[] data, HashAlgorithmName hashAlgorithm)
    {
        var digest = SHA256.HashData(data);

        if (IsEcc)
        {
            // The card returns a DER SEQUENCE of r and s, which is exactly what
            // an X.509 signature field wants.
            return session.SignWithSlot(slot, publicKey.Algorithm, digest);
        }

        return session.SignWithSlot(slot, publicKey.Algorithm, PadForRsa(digest));
    }

    /// <summary>
    /// Builds the EMSA-PKCS1-v1_5 block the card expects. A PIV card signing
    /// with RSA performs the raw operation and nothing else — the padding is
    /// the caller's job, and getting it wrong produces a signature that
    /// verifies nowhere.
    /// </summary>
    private byte[] PadForRsa(byte[] digest)
    {
        var writer = new AsnWriter(AsnEncodingRules.DER);

        using (writer.PushSequence())
        {
            using (writer.PushSequence())
            {
                writer.WriteObjectIdentifier(Sha256);
                writer.WriteNull();
            }

            writer.WriteOctetString(digest);
        }

        var digestInfo = writer.Encode();
        var modulusBytes = publicKey.Algorithm switch
        {
            PivAlgorithm.Rsa1024 => 128,
            PivAlgorithm.Rsa2048 => 256,
            PivAlgorithm.Rsa3072 => 384,
            PivAlgorithm.Rsa4096 => 512,
            _ => throw new PivProtocolException(
                $"{publicKey.Algorithm} is not an RSA algorithm."),
        };

        // 00 01 FF...FF 00 || DigestInfo
        var block = new byte[modulusBytes];
        block[0] = 0x00;
        block[1] = 0x01;

        var padding = modulusBytes - digestInfo.Length - 3;
        for (var i = 0; i < padding; i++)
        {
            block[2 + i] = 0xFF;
        }

        block[2 + padding] = 0x00;
        digestInfo.CopyTo(block, 3 + padding);

        return block;
    }
}
