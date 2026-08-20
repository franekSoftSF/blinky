using System.Formats.Asn1;
using System.Security.Cryptography;

namespace Blinky.Piv;

/// <summary>
/// The operations that change a token.
/// </summary>
/// <remarks>
/// Kept apart from the read path in a separate file for one reason: everything
/// here can destroy something. A key generated over an existing one cannot be
/// recovered, and a PIN verified with the wrong value moves a counter that only
/// a PUK can move back.
/// </remarks>
public partial class PivSession
{
    private const byte InsGeneralAuthenticate = 0x87;
    private const byte InsGenerateKeyPair = 0x47;
    private const byte InsPutData = 0xDB;

    /// <summary>
    /// Proves to the card that we hold the management key, and makes the card
    /// prove the same back.
    /// </summary>
    /// <remarks>
    /// Three steps: ask the card for a witness, return it decrypted along with
    /// a challenge of our own, and check the card's answer is that challenge
    /// encrypted. The second half is what a substituted card cannot fake.
    /// </remarks>
    public void AuthenticateManagementKey(ManagementKey managementKey)
    {
        var algorithm = (byte)managementKey.Algorithm;

        // 7C 02 80 00 - "give me a witness".
        var witnessResponse = Connection.Send(new ApduCommand(InsGeneralAuthenticate,
            p1: algorithm, p2: ManagementKeySlot,
            data: new byte[] { 0x7C, 0x02, 0x80, 0x00 }, le: 0));

        PivStatus.ThrowIfFailed(witnessResponse.Status, "GENERAL AUTHENTICATE (witness)");

        var witness = Unwrap(witnessResponse.Data, 0x80)
            ?? throw new PivProtocolException("The card returned no witness to decrypt.");

        var decrypted = managementKey.Decrypt(witness);
        var challenge = RandomNumberGenerator.GetBytes(managementKey.BlockSize);

        // 7C .. 80 <decrypted witness> 81 <our challenge>
        var payload = new List<byte> { 0x7C, (byte)(4 + decrypted.Length + challenge.Length) };
        payload.Add(0x80);
        payload.Add((byte)decrypted.Length);
        payload.AddRange(decrypted);
        payload.Add(0x81);
        payload.Add((byte)challenge.Length);
        payload.AddRange(challenge);

        var response = Connection.Send(new ApduCommand(InsGeneralAuthenticate,
            p1: algorithm, p2: ManagementKeySlot, data: payload.ToArray(), le: 0));

        if (response.Status.Value == StatusWord.SecurityStatusNotSatisfied)
        {
            throw new PivAuthenticationFailedException(
                "The card rejected the management key. It is neither the value supplied nor, "
                + "if this was the factory key, still at the factory value.");
        }

        PivStatus.ThrowIfFailed(response.Status, "GENERAL AUTHENTICATE (challenge)");

        var answer = Unwrap(response.Data, 0x82)
            ?? throw new PivProtocolException("The card returned no answer to the challenge.");

        // The card proving itself. Skipping this check would leave a swapped
        // or emulated card indistinguishable from the real one.
        if (!CryptographicOperations.FixedTimeEquals(answer, managementKey.Encrypt(challenge)))
        {
            throw new PivAuthenticationFailedException(
                "The card answered the challenge incorrectly. It does not hold this "
                + "management key, whatever it accepted.");
        }
    }

    /// <summary>
    /// Verifies the PIN. A wrong value costs an attempt, and the exception says
    /// how many are left.
    /// </summary>
    public void VerifyPin(ReadOnlySpan<char> pin)
    {
        // PIV pads the PIN to eight bytes with FF.
        Span<byte> padded = stackalloc byte[8];
        padded.Fill(0xFF);

        var written = System.Text.Encoding.ASCII.GetBytes(pin, padded);
        if (written is < 6 or > 8)
        {
            throw new ArgumentException("A PIV PIN is between six and eight characters.",
                nameof(pin));
        }

        var response = Connection.Send(new ApduCommand(InsVerify, p2: PinSlot,
            data: padded.ToArray()));

        if (response.Status.RetriesLeft is { } remaining)
        {
            throw new PivVerificationFailedException(response.Status, "VERIFY PIN", remaining);
        }

        PivStatus.ThrowIfFailed(response.Status, "VERIFY PIN");
    }

    /// <summary>
    /// Generates a key pair in a slot and returns its public key.
    /// </summary>
    /// <remarks>
    /// <b>Destroys whatever the slot held.</b> There is no undo and no copy: the
    /// private key never existed anywhere else. The caller is expected to have
    /// checked the slot first — see <see cref="ReadInventory"/>.
    /// </remarks>
    public PivPublicKey GenerateKeyPair(PivSlot slot, PivAlgorithm algorithm,
        PinPolicy pinPolicy = PinPolicy.Unknown, TouchPolicy touchPolicy = TouchPolicy.Unknown)
    {
        var data = new List<byte> { 0xAC, 0x03, 0x80, 0x01, (byte)algorithm };

        if (pinPolicy is not PinPolicy.Unknown)
        {
            data[1] += 3;
            data.AddRange([0xAA, 0x01, (byte)pinPolicy]);
        }

        if (touchPolicy is not TouchPolicy.Unknown)
        {
            data[1] += 3;
            data.AddRange([0xAB, 0x01, (byte)touchPolicy]);
        }

        var response = Connection.Send(new ApduCommand(InsGenerateKeyPair,
            p1: 0x00, p2: slot.Id, data: data.ToArray(), le: 0));

        PivStatus.ThrowIfFailed(response.Status, $"GENERATE KEY PAIR {slot}");

        return PublicKeyDecoder.Decode(response.Data, algorithm);
    }

    /// <summary>
    /// Signs one block with the key in a slot.
    /// </summary>
    /// <remarks>
    /// The input is a digest for ECDSA, or a fully padded PKCS#1 block for RSA.
    /// If the slot's touch policy asks for it the card blinks here and this call
    /// does not return until a finger arrives or it times out — which is normal,
    /// not a hang. See docs/03-piv-layer.md.
    /// </remarks>
    public byte[] SignWithSlot(PivSlot slot, PivAlgorithm algorithm, ReadOnlySpan<byte> block)
    {
        var payload = new List<byte>();
        var inner = new List<byte> { 0x82, 0x00, 0x81 };

        AppendLength(inner, block.Length);
        inner.AddRange(block);

        payload.Add(0x7C);
        AppendLength(payload, inner.Count);
        payload.AddRange(inner);

        var response = Connection.Send(new ApduCommand(InsGeneralAuthenticate,
            p1: (byte)algorithm, p2: slot.Id, data: payload.ToArray(), le: 0));

        if (response.Status.Value == StatusWord.SecurityStatusNotSatisfied)
        {
            throw new PivAuthenticationFailedException(
                $"Slot {slot} refused to sign: its PIN policy has not been satisfied.");
        }

        PivStatus.ThrowIfFailed(response.Status, $"GENERAL AUTHENTICATE (sign {slot})");

        return Unwrap(response.Data, 0x82)
            ?? throw new PivProtocolException("The card returned no signature.");
    }

    /// <summary>
    /// Writes a certificate into a slot's data object.
    /// </summary>
    /// <remarks>
    /// The first thing in this library that sends more than one APDU of data,
    /// so the outbound chaining in <see cref="PivConnection"/> runs here for
    /// real. Requires the management key to have been authenticated.
    /// </remarks>
    public void PutCertificate(PivSlot slot, byte[] der)
    {
        var tag = slot.CertificateObject
            ?? throw new ArgumentException($"Slot {slot} holds no certificate object.",
                nameof(slot));

        // 70 <der>, 71 01 00 (not compressed), FE 00
        var inner = new List<byte> { 0x70 };
        AppendLength(inner, der.Length);
        inner.AddRange(der);
        inner.AddRange([0x71, 0x01, 0x00, 0xFE, 0x00]);

        var body = new List<byte> { 0x53 };
        AppendLength(body, inner.Count);
        body.AddRange(inner);

        var data = new List<byte> { 0x5C, (byte)tag.Length };
        data.AddRange(tag);
        data.AddRange(body);

        var response = Connection.Send(new ApduCommand(InsPutData,
            p1: 0x3F, p2: 0xFF, data: data.ToArray()));

        if (response.Status.Value == StatusWord.SecurityStatusNotSatisfied)
        {
            throw new PivAuthenticationFailedException(
                $"Writing to slot {slot} needs the management key authenticated first.");
        }

        PivStatus.ThrowIfFailed(response.Status, $"PUT DATA {slot}");
    }

    /// <summary>Appends a BER length: short form, or 81/82 as needed.</summary>
    internal static void AppendLength(List<byte> target, int length)
    {
        switch (length)
        {
            case < 0x80:
                target.Add((byte)length);
                break;
            case <= 0xFF:
                target.Add(0x81);
                target.Add((byte)length);
                break;
            default:
                target.Add(0x82);
                target.Add((byte)(length >> 8));
                target.Add((byte)(length & 0xFF));
                break;
        }
    }

    /// <summary>Pulls one tag out of a 7C-wrapped dynamic authentication template.</summary>
    private static byte[]? Unwrap(byte[] response, byte tag)
    {
        var outer = Tlv.ParseBer(response);
        if (!outer.TryGetValue(0x7C, out var template))
        {
            return null;
        }

        return Tlv.ParseBer(template).TryGetValue(tag, out var value) ? value : null;
    }
}

/// <summary>
/// The card refused because a PIN or the management key has not been
/// satisfied — as opposed to the command being wrong.
/// </summary>
public sealed class PivAuthenticationFailedException(string message) : PivException(
    new StatusWord(StatusWord.SecurityStatusNotSatisfied), "authentication", message);

/// <summary>
/// A public key read off a card.
/// </summary>
/// <remarks>
/// Named PivPublicKey rather than PublicKey on purpose: the X.509 namespace
/// already has one, and a type that shadows it in this file would be a small
/// trap for every later reader.
/// </remarks>
public sealed record PivPublicKey(PivAlgorithm Algorithm, byte[] SubjectPublicKeyInfo)
{
    public AsymmetricAlgorithm Create()
    {
        if (Algorithm is PivAlgorithm.EccP256 or PivAlgorithm.EccP384)
        {
            var ecdsa = ECDsa.Create();
            ecdsa.ImportSubjectPublicKeyInfo(SubjectPublicKeyInfo, out _);

            return ecdsa;
        }

        var rsa = RSA.Create();
        rsa.ImportSubjectPublicKeyInfo(SubjectPublicKeyInfo, out _);

        return rsa;
    }
}

/// <summary>Turns the card's <c>7F49</c> template into a SubjectPublicKeyInfo.</summary>
internal static class PublicKeyDecoder
{
    public static PivPublicKey Decode(byte[] response, PivAlgorithm algorithm)
    {
        var outer = Tlv.ParseBer(response);

        // The template is 7F49, a two-byte tag the single-byte parser sees as
        // 7F followed by a length; unwrap whichever shape arrives.
        var template = outer.TryGetValue(0x7F, out var nested)
            ? Tlv.ParseBer(nested[1..])
            : outer;

        return algorithm switch
        {
            PivAlgorithm.EccP256 or PivAlgorithm.EccP384 =>
                new PivPublicKey(algorithm, EncodeEcc(Require(template, 0x86), algorithm)),
            PivAlgorithm.Rsa1024 or PivAlgorithm.Rsa2048 or PivAlgorithm.Rsa3072
                or PivAlgorithm.Rsa4096 =>
                new PivPublicKey(algorithm,
                    EncodeRsa(Require(template, 0x81), Require(template, 0x82))),
            _ => throw new PivProtocolException(
                $"{algorithm} public keys are not decoded by this build."),
        };
    }

    private static byte[] Require(Dictionary<byte, byte[]> template, byte tag) =>
        template.TryGetValue(tag, out var value)
            ? value
            : throw new PivProtocolException(
                $"The generated key response has no tag {tag:X2}.");

    private static byte[] EncodeEcc(byte[] point, PivAlgorithm algorithm)
    {
        var curve = algorithm is PivAlgorithm.EccP384
            ? ECCurve.NamedCurves.nistP384
            : ECCurve.NamedCurves.nistP256;

        var size = (point.Length - 1) / 2;

        using var ecdsa = ECDsa.Create(new ECParameters
        {
            Curve = curve,
            Q = new ECPoint
            {
                X = point[1..(1 + size)],
                Y = point[(1 + size)..],
            },
        });

        return ecdsa.ExportSubjectPublicKeyInfo();
    }

    private static byte[] EncodeRsa(byte[] modulus, byte[] exponent)
    {
        using var rsa = RSA.Create(new RSAParameters
        {
            Modulus = modulus,
            Exponent = exponent,
        });

        return rsa.ExportSubjectPublicKeyInfo();
    }
}
