namespace Blinky.Piv.Pcsc;

/// <summary>A failure from the smart card resource manager, not from the card.</summary>
public sealed class PcscException(uint code, string operation)
    : Exception($"{operation} failed: 0x{code:X8} ({Describe(code)})")
{
    public uint Code { get; } = code;

    public bool IsNoCard => Code is NoSmartCard or RemovedCard;

    /// <summary>
    /// This machine has no working smart card plumbing at the moment.
    /// </summary>
    /// <remarks>
    /// Not a fault. Windows starts the Smart Card service from a device
    /// arrival trigger, so a workstation with nothing plugged in answers
    /// <c>SCARD_E_NO_SERVICE</c> to the very first call and goes on doing so
    /// until a reader appears. A caller that polls needs to know the
    /// difference between this and a reader that broke.
    /// </remarks>
    public bool IsNoReaderStack => Code is NoService or ServiceStopped or NoReadersAvailable;

    internal const uint NoSmartCard = 0x8010000C;
    internal const uint RemovedCard = 0x80100069;
    internal const uint SharingViolation = 0x8010000B;
    internal const uint NoReadersAvailable = 0x8010002E;
    internal const uint ReaderUnavailable = 0x80100017;
    internal const uint ResetCard = 0x80100068;
    internal const uint NoService = 0x8010001D;
    internal const uint ServiceStopped = 0x8010001E;

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
        NoService => "the Smart Card service is not running - Windows starts it "
                     + "when a reader is plugged in",
        ServiceStopped => "the Smart Card service stopped",
        ReaderUnavailable => "the reader is unavailable",
        ResetCard => "the card was reset - the applet must be selected again",
        _ => "see the SCARD_ error codes",
    };
}
