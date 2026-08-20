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

    /// <summary>
    /// Gets a usable handle back after the card was reset underneath us, and
    /// says whether it worked.
    /// </summary>
    /// <remarks>
    /// On Windows the card is shared with the smart card service, any
    /// installed minidriver and the logon screen, and any of them can reset
    /// it between two of our commands. The caller has to select the applet
    /// again afterwards - this only restores the connection.
    /// <para>
    /// A transport with nothing to reconnect says false, and the layer above
    /// reports the original failure rather than inventing a recovery.
    /// </para>
    /// </remarks>
    bool Reconnect() => false;
}
