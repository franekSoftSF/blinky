using Blinky.Piv;

namespace Blinky.UnitTests;

/// <summary>
/// The management key a card keeps behind its PIN, in the encoding Yubico uses.
/// </summary>
/// <remarks>
/// This matters because of what the YubiKey minidriver does when it is
/// installed: it takes ownership of the card, replaces the factory management
/// key with a random one, stores it in the PRINTED object, and blocks the PUK.
///
/// That driver is required for smart-card logon on Windows - the inbox PIV
/// minidriver would not produce a key container for a card that met every
/// requirement in SP 800-73 - so a card that can log on is, from then on, a
/// card whose management key is here. A CMS that only knows the factory key
/// can issue to a card exactly once, before the workstation is set up, and
/// never touch it again.
///
/// Seen on token 23673995: enrolment worked, then the driver was installed for
/// the logon test, and the next revocation failed with SW 6982 on a card that
/// had been perfectly manageable an hour earlier.
/// </remarks>
public class ProtectedManagementKeyTests
{
    /// <summary>53 { 88 { 89 &lt;key&gt; } }, as ykman --protect writes it.</summary>
    private static byte[] PrintedObject(byte[] key)
    {
        var inner = new List<byte> { 0x89, (byte)key.Length };
        inner.AddRange(key);

        var protectedData = new List<byte> { 0x88, (byte)inner.Count };
        protectedData.AddRange(inner);

        var outer = new List<byte> { 0x53, (byte)protectedData.Count };
        outer.AddRange(protectedData);

        return [.. outer];
    }

    /// <summary>
    /// What Blinky writes, Blinky can read back.
    /// </summary>
    /// <remarks>
    /// The two sides are separate code - one builds the object, the other
    /// parses it - and a mismatch between them is a card written in an
    /// encoding nothing understands, discovered on the next write, which
    /// fails on the management key.
    /// </remarks>
    [Theory]
    [InlineData(PivAlgorithm.TripleDes, 24)]
    [InlineData(PivAlgorithm.Aes192, 24)]
    [InlineData(PivAlgorithm.Aes128, 16)]
    [InlineData(PivAlgorithm.Aes256, 32)]
    public void What_is_written_can_be_read(PivAlgorithm algorithm, int length)
    {
        var bytes = new byte[length];
        for (var i = 0; i < length; i++)
        {
            bytes[i] = (byte)(i * 3 + 1);
        }

        var original = new ManagementKey(bytes, algorithm);

        // The PRINTED object as the card holds it: the 53 wrapper around what
        // the key produced.
        var value = ManagementKeyTestAccess.PrintedObjectValue(original);
        var stored = new List<byte> { 0x53, (byte)value.Length };
        stored.AddRange(value);

        var parsed = ProtectedManagementKey.Parse([.. stored], algorithm);

        Assert.NotNull(parsed);
        Assert.Equal(algorithm, parsed.Algorithm);
        Assert.Equal(original.BlockSize, parsed.BlockSize);

        // Same key, proven by both encrypting a block to the same thing rather
        // than by reading the bytes, which neither class exposes.
        var block = new byte[original.BlockSize];
        Assert.Equal(
            ManagementKeyTestAccess.Encrypt(original, block),
            ManagementKeyTestAccess.Encrypt(parsed, block));
    }

    [Fact]
    public void The_key_is_read_out_of_the_printed_object()
    {
        var key = new byte[24];
        for (var i = 0; i < key.Length; i++)
        {
            key[i] = (byte)(i + 0x40);
        }

        var parsed = ProtectedManagementKey.Parse(
            PrintedObject(key), PivAlgorithm.TripleDes);

        Assert.NotNull(parsed);
        Assert.Equal(PivAlgorithm.TripleDes, parsed.Algorithm);
    }

    /// <summary>
    /// A card that keeps something else there is a card with no protected key,
    /// not an error.
    /// </summary>
    /// <remarks>
    /// The object is meant for what is printed on the face of a card, and a
    /// card really may hold that. Treating anything unrecognised as a failure
    /// would refuse to work with a card that is simply not using this
    /// convention.
    /// </remarks>
    [Fact]
    public void Anything_else_reads_as_no_key()
    {
        Assert.Null(ProtectedManagementKey.Parse([], PivAlgorithm.TripleDes));

        // A PRINTED object holding actual printed information.
        Assert.Null(ProtectedManagementKey.Parse(
            [0x53, 0x06, 0x01, 0x04, (byte)'J', (byte)'a', (byte)'n', 0xFE],
            PivAlgorithm.TripleDes));
    }
}

/// <summary>
/// The data field of SET MANAGEMENT KEY.
/// </summary>
/// <remarks>
/// Worth pinning down because there is no second chance at it. The command
/// replaces the key the card will demand from then on, and a payload the card
/// misreads leaves a card demanding something nobody knows - not recoverable,
/// not resettable without wiping the PIV application and everything on it.
/// </remarks>
public class SetManagementKeyPayloadTests
{
    [Theory]
    [InlineData(PivAlgorithm.TripleDes, 24, 0x03)]
    [InlineData(PivAlgorithm.Aes192, 24, 0x0A)]
    [InlineData(PivAlgorithm.Aes128, 16, 0x08)]
    [InlineData(PivAlgorithm.Aes256, 32, 0x0C)]
    public void It_is_the_algorithm_then_the_key_under_9b(
        PivAlgorithm algorithm, int length, byte algorithmByte)
    {
        var bytes = new byte[length];
        for (var i = 0; i < length; i++)
        {
            bytes[i] = (byte)(0x80 + i);
        }

        var data = ManagementKeyTestAccess.SetCommandData(
            new ManagementKey(bytes, algorithm));

        Assert.Equal(algorithmByte, data[0]);
        Assert.Equal(0x9B, data[1]);           // the card management slot
        Assert.Equal((byte)length, data[2]);
        Assert.Equal(bytes, data[3..]);
        Assert.Equal(3 + length, data.Length);
    }
}
