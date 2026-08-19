namespace Blinky.Piv;

/// <summary>
/// An ISO 7816 status word, as returned by the PIV applet.
/// </summary>
/// <remarks>
/// Every failure is reported with its status word verbatim. "Enrolment failed"
/// with no SW is not a diagnosis, and these failures happen on someone else's
/// desk. See docs/03-piv-layer.md.
/// </remarks>
public readonly record struct StatusWord(ushort Value)
{
    public const ushort Success = 0x9000;
    public const ushort SecurityStatusNotSatisfied = 0x6982;
    public const ushort AuthenticationMethodBlocked = 0x6983;
    public const ushort IncorrectParameters = 0x6A80;
    public const ushort FileNotFound = 0x6A82;
    public const ushort ReferencedDataNotFound = 0x6A88;
    public const ushort WrongLength = 0x6700;
    public const ushort InstructionNotSupported = 0x6D00;

    public bool IsSuccess => Value == Success;

    /// <summary>True for 61xx, meaning the card has more data to hand over.</summary>
    public bool HasMoreData => (Value & 0xFF00) == 0x6100;

    /// <summary>For 61xx, the number of bytes GET RESPONSE should ask for.</summary>
    public byte AvailableBytes => (byte)(Value & 0x00FF);

    /// <summary>
    /// For 63Cx, the number of PIN attempts left. Null for every other status
    /// word, including <see cref="AuthenticationMethodBlocked"/> - blocked is
    /// not "zero retries", it is a different condition with a different remedy.
    /// </summary>
    public int? RetriesLeft => (Value & 0xFFF0) == 0x63C0 ? Value & 0x000F : null;

    /// <summary>True when the slot is simply empty, which is not an error.</summary>
    public bool IsEmptySlot => Value is FileNotFound or ReferencedDataNotFound;

    public static StatusWord FromResponse(ReadOnlySpan<byte> response) =>
        response.Length < 2
            ? throw new ArgumentException(
                $"Response too short to contain a status word ({response.Length} bytes).",
                nameof(response))
            : new StatusWord((ushort)((response[^2] << 8) | response[^1]));

    public override string ToString() => Value.ToString("X4");
}
