using System.Security.Cryptography;

namespace Blinky.Piv;

/// <summary>
/// The management key, and the mutual authentication that proves both sides
/// hold it.
/// </summary>
/// <remarks>
/// <para>
/// Mutual, not one-way, and that matters: the card proves it holds the key as
/// well. A one-way check would let a substituted or emulated card accept
/// whatever it was sent, and the first thing written afterwards would be a
/// key generation on a device nobody has verified.
/// </para>
/// <para>
/// The algorithm is read from the card, never derived from the firmware
/// version. Firmware below 5.7 ships 3DES and 5.7 or later ships AES-192, and
/// both are in the field — see docs/08-hardware-notes.md.
/// </para>
/// </remarks>
public sealed class ManagementKey
{
    /// <summary>The factory value, the same bytes for 3DES and for AES-192.</summary>
    public static readonly byte[] FactoryDefault =
    [
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
    ];

    private readonly byte[] key;

    public ManagementKey(byte[] key, PivAlgorithm algorithm)
    {
        Algorithm = algorithm;
        BlockSize = algorithm switch
        {
            PivAlgorithm.TripleDes => 8,
            PivAlgorithm.Aes128 or PivAlgorithm.Aes192 or PivAlgorithm.Aes256 => 16,
            _ => throw new ArgumentException(
                $"{algorithm} is not a management key algorithm.", nameof(algorithm)),
        };

        var expected = algorithm switch
        {
            PivAlgorithm.TripleDes => 24,
            PivAlgorithm.Aes128 => 16,
            PivAlgorithm.Aes192 => 24,
            PivAlgorithm.Aes256 => 32,
            _ => 0,
        };

        if (key.Length != expected)
        {
            throw new ArgumentException(
                $"A {algorithm} management key is {expected} bytes, not {key.Length}.",
                nameof(key));
        }

        this.key = key;
    }

    public PivAlgorithm Algorithm { get; }

    /// <summary>Cipher block size: 8 for 3DES, 16 for AES.</summary>
    public int BlockSize { get; }

    /// <summary>The factory key, in whichever algorithm the card reports.</summary>
    public static ManagementKey Default(PivAlgorithm algorithm) => algorithm switch
    {
        PivAlgorithm.TripleDes or PivAlgorithm.Aes192 =>
            new ManagementKey(FactoryDefault, algorithm),
        PivAlgorithm.Aes128 => new ManagementKey(FactoryDefault[..16], algorithm),
        PivAlgorithm.Aes256 =>
            new ManagementKey([.. FactoryDefault, .. FactoryDefault[..8]], algorithm),
        _ => throw new ArgumentException($"{algorithm} is not a management key algorithm.",
            nameof(algorithm)),
    };

    /// <summary>
    /// The data field of a SET MANAGEMENT KEY command: the algorithm, then the
    /// key under tag 9B.
    /// </summary>
    /// <remarks>
    /// Built here rather than by exposing the bytes, so the one operation that
    /// has to put a management key on the wire is the only thing that can see
    /// one. The enum values are the PIV algorithm identifiers, so the first
    /// byte is the algorithm itself.
    /// </remarks>
    /// <summary>
    /// A key of the length this card's algorithm needs, from longer key
    /// material.
    /// </summary>
    /// <remarks>
    /// The server derives one fixed length for every token, because it has not
    /// asked the card what it is and cannot: firmware below 5.7 wants 3DES and
    /// 5.7 or later wants AES-192, and both are in the field. The agent has
    /// asked, so the agent cuts.
    ///
    /// Taking a prefix of HKDF output is sound - producing more bytes and using
    /// some of them is what its counter mode is for - and it means the same
    /// derived secret gives the right key whichever algorithm the card turns
    /// out to hold.
    /// </remarks>
    public static ManagementKey FromSecret(ReadOnlySpan<byte> secret, PivAlgorithm algorithm)
    {
        var needed = algorithm switch
        {
            PivAlgorithm.TripleDes or PivAlgorithm.Aes192 => 24,
            PivAlgorithm.Aes128 => 16,
            PivAlgorithm.Aes256 => 32,
            _ => throw new ArgumentException(
                $"{algorithm} is not a management key algorithm.", nameof(algorithm)),
        };

        if (secret.Length < needed)
        {
            throw new ArgumentException(
                $"A {algorithm} key needs {needed} bytes and the secret is {secret.Length}.",
                nameof(secret));
        }

        return new ManagementKey(secret[..needed].ToArray(), algorithm);
    }

    internal byte[] SetCommandData()
    {
        var data = new byte[3 + key.Length];

        data[0] = (byte)Algorithm;
        data[1] = 0x9B;                    // the card management key slot
        data[2] = (byte)key.Length;
        key.CopyTo(data, 3);

        return data;
    }

    /// <summary>
    /// The key wrapped for the PRINTED object, in the encoding a YubiKey
    /// minidriver and ykman both read: 88 wrapping 89 wrapping the bytes.
    /// </summary>
    /// <remarks>
    /// Writing it there is what makes a card manageable by Blinky and by that
    /// driver at the same time. The driver takes ownership of a card whose
    /// management key it does not recognise - random key, PUK blocked - and a
    /// card that has been through that is one Blinky can no longer touch. A
    /// card that already keeps its key here is a card it leaves alone.
    /// </remarks>
    internal byte[] PrintedObjectValue()
    {
        var inner = new byte[2 + key.Length];
        inner[0] = 0x89;
        inner[1] = (byte)key.Length;
        key.CopyTo(inner, 2);

        var outer = new byte[2 + inner.Length];
        outer[0] = 0x88;
        outer[1] = (byte)inner.Length;
        inner.CopyTo(outer, 2);

        return outer;
    }

    internal byte[] Encrypt(ReadOnlySpan<byte> block) => Transform(block, encrypt: true);

    internal byte[] Decrypt(ReadOnlySpan<byte> block) => Transform(block, encrypt: false);

    /// <summary>
    /// ECB with no padding, one block at a time. That is what the card does,
    /// and the mode is not a choice made here.
    /// </summary>
    private byte[] Transform(ReadOnlySpan<byte> block, bool encrypt)
    {
        if (block.Length != BlockSize)
        {
            throw new PivProtocolException(
                $"A {Algorithm} block is {BlockSize} bytes; got {block.Length}.");
        }

        if (Algorithm is PivAlgorithm.TripleDes)
        {
            return TripleDesEde(block, encrypt);
        }

        using var aes = Aes.Create();
        aes.Key = key;

        return encrypt
            ? aes.EncryptEcb(block, PaddingMode.None)
            : aes.DecryptEcb(block, PaddingMode.None);
    }

    /// <summary>
    /// Three-key DES-EDE, assembled from three DES operations rather than from
    /// <c>TripleDES</c>.
    /// </summary>
    /// <remarks>
    /// <b>Not a preference — a necessity.</b> The PIV factory management key is
    /// <c>010203040506070801020304050607080102030405060708</c>: the same eight
    /// bytes three times. That is a degenerate 3DES key, equivalent to single
    /// DES, and .NET refuses it outright with "known weak key for TripleDES".
    /// So every factory-default token below firmware 5.7 - a third of the
    /// tokens on this bench - would be unreachable through the obvious API.
    ///
    /// The weakness is real; the key is also what is on the card, and refusing
    /// to speak to it does not make anything safer. Personalisation replaces it
    /// with a diversified value at first contact, which is the actual answer.
    /// </remarks>
    private byte[] TripleDesEde(ReadOnlySpan<byte> block, bool encrypt)
    {
#pragma warning disable SYSLIB0021, CA5351 // See the remarks: this is the card's key, not our choice.
        using var des = DES.Create();
        des.Mode = CipherMode.ECB;
        des.Padding = PaddingMode.None;

        byte[] Step(byte[] input, int offset, bool forward)
        {
            des.Key = key[offset..(offset + 8)];

            return forward
                ? des.EncryptEcb(input, PaddingMode.None)
                : des.DecryptEcb(input, PaddingMode.None);
        }

        var buffer = block.ToArray();

        return encrypt
            ? Step(Step(Step(buffer, 0, true), 8, false), 16, true)
            : Step(Step(Step(buffer, 16, false), 8, true), 0, false);
#pragma warning restore SYSLIB0021, CA5351
    }
}
