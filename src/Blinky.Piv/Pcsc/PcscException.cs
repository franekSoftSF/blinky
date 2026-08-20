namespace Blinky.Piv.Pcsc;

/// <summary>A failure from the smart card resource manager, not from the card.</summary>
public sealed class PcscException(uint code, string operation)
    : Exception($"{operation} failed: 0x{code:X8} ({Describe(code)})")
{
    public uint Code { get; } = code;

    public bool IsNoCard => Code is NoSmartCard or RemovedCard;

    internal const uint NoSmartCard = 0x8010000C;
    internal const uint RemovedCard = 0x80100069;
    internal const uint SharingViolation = 0x8010000B;
    internal const uint NoReadersAvailable = 0x8010002E;
    internal const uint ReaderUnavailable = 0x80100017;
    internal const uint ResetCard = 0x80100068;

    internal static void ThrowIfFailed(int code, string operation)
    {
        if (code != 0)
        {
            throw new PcscException((uint)code, operation);
        }
    }

    private static string Describe(uint code) => code switch
    {
        NoSmartCard => "no card in the reader",
        RemovedCard => "the card was removed",
        SharingViolation => "another process holds the card exclusively",
        NoReadersAvailable => "no readers available",
        ReaderUnavailable => "the reader is unavailable",
        ResetCard => "the card was reset - the applet must be selected again",
        _ => "see the SCARD_ error codes",
    };
}
