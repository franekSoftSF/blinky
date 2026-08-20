namespace Blinky.Piv;

/// <summary>
/// One exchange with a card, and nothing else. Chaining, GET RESPONSE and the
/// mapping of status words to exceptions all sit above this, so the same logic
/// is exercised by tests against a recorded transcript and by the agent against
/// a reader.
/// </summary>
public interface IApduTransport : IDisposable
{
    /// <summary>Human-readable source, for log lines and failure messages.</summary>
    string Description { get; }

    /// <summary>Sends one already-encoded APDU and returns what came back.</summary>
    ApduResponse Transmit(ReadOnlySpan<byte> apdu);

    /// <summary>
    /// Marks a sequence that must not be interleaved with another process.
    /// On PC/SC this is a card transaction; on a replay transport it does
    /// nothing. Disposing ends it.
    /// </summary>
    IDisposable BeginTransaction();
}
