namespace Blinky.Piv;

/// <summary>
/// A command APDU, before encoding. ISO 7816-4 cases 1 to 4.
/// </summary>
/// <remarks>
/// <see cref="Data"/> may be longer than a single APDU allows; splitting it
/// across chained commands is <see cref="PivConnection"/>'s job, not the
/// caller's. See docs/03-piv-layer.md.
/// </remarks>
public sealed record ApduCommand
{
    /// <summary>The most data one APDU can carry in the short form.</summary>
    public const int MaxDataPerApdu = 255;

    /// <summary>Set on CLA to mark a command as "more blocks follow".</summary>
    public const byte ChainingBit = 0x10;

    public ApduCommand(byte ins, byte p1 = 0x00, byte p2 = 0x00,
        ReadOnlyMemory<byte> data = default, int? le = null, byte cla = 0x00)
    {
        if (le is < 0 or > 256)
        {
            throw new ArgumentOutOfRangeException(nameof(le), le,
                "Le must be between 0 and 256, where 0 means 256.");
        }

        Cla = cla;
        Ins = ins;
        P1 = p1;
        P2 = p2;
        Data = data;
        Le = le;
    }

    public byte Cla { get; init; }

    public byte Ins { get; init; }

    public byte P1 { get; init; }

    public byte P2 { get; init; }

    public ReadOnlyMemory<byte> Data { get; init; }

    /// <summary>Expected response length. 0 means "up to 256", the PIV idiom.</summary>
    public int? Le { get; init; }

    /// <summary>
    /// Encodes one APDU. Throws when the data does not fit, because a silently
    /// truncated command is worse than a failed one.
    /// </summary>
    public byte[] Encode()
    {
        var data = Data.Span;
        if (data.Length > MaxDataPerApdu)
        {
            throw new InvalidOperationException(
                $"{data.Length} bytes do not fit in one APDU; use PivConnection, which chains.");
        }

        var length = 4 + (data.Length > 0 ? 1 + data.Length : 0) + (Le.HasValue ? 1 : 0);
        var apdu = new byte[length];

        apdu[0] = Cla;
        apdu[1] = Ins;
        apdu[2] = P1;
        apdu[3] = P2;

        var offset = 4;
        if (data.Length > 0)
        {
            apdu[offset++] = (byte)data.Length;
            data.CopyTo(apdu.AsSpan(offset));
            offset += data.Length;
        }

        if (Le.HasValue)
        {
            apdu[offset] = (byte)(Le.Value == 256 ? 0 : Le.Value);
        }

        return apdu;
    }

    public override string ToString() =>
        $"{Ins:X2} P1={P1:X2} P2={P2:X2} Lc={Data.Length}"
        + (Le.HasValue ? $" Le={Le.Value:X2}" : string.Empty);
}
