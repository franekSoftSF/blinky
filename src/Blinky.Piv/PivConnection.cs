using Blinky.Piv.Pcsc;

namespace Blinky.Piv;

/// <summary>
/// Everything between "one APDU in, one APDU out" and a usable command: command
/// chaining outbound, GET RESPONSE inbound, and status words turned into typed
/// exceptions.
/// </summary>
/// <remarks>
/// Deliberately transport-agnostic. The tests drive it with a recorded
/// transcript and the agent drives it with a reader, so the chaining and error
/// handling that matter in the field are the ones covered by tests.
/// </remarks>
public sealed class PivConnection(IApduTransport transport, bool ownsTransport = true) : IDisposable
{
    /// <summary>The PIV application identifier, truncated as the standard allows.</summary>
    public static readonly byte[] PivAid = [0xA0, 0x00, 0x00, 0x03, 0x08];

    private const byte InsSelect = 0xA4;
    private const byte InsGetResponse = 0xC0;

    private bool disposed;

    public IApduTransport Transport { get; } = transport;

    /// <summary>Starts a sequence that must not interleave with another process.</summary>
    public IDisposable BeginTransaction() => Transport.BeginTransaction();

    /// <summary>
    /// Selects the PIV application. Returns false when the card has no PIV
    /// applet - a virtual reader, or a card that is simply something else -
    /// because that is a normal thing to find in a reader list, not a failure.
    /// </summary>
    public bool SelectPiv()
    {
        var response = SendOnce(new ApduCommand(InsSelect, p1: 0x04, p2: 0x00, data: PivAid, le: 0));
        return response.IsSuccess;
    }

    /// <summary>
    /// Sends a command, chaining the request if it is too long for one APDU and
    /// collecting the response across as many GET RESPONSE calls as the card
    /// asks for. Does not throw on a non-success status word.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Retried once when the card is reset underneath us. On Windows the card
    /// is shared with the smart card service, any installed minidriver and the
    /// logon screen, and any of them can reset it between two of our commands
    /// - a transaction stops them interleaving, not resetting. What comes back
    /// is <c>SCARD_W_RESET_CARD</c>, and what it means is that the connection
    /// survived and the applet selection did not.
    /// </para>
    /// <para>
    /// Seen on 20 August 2026: an enrolment generated a key on the card and
    /// then failed at the PIN verification, leaving a key in slot 9A with no
    /// certificate. The recovery - reconnect, select the applet, send it again
    /// - is defined by the standard, and not doing it turned a hiccup into a
    /// half-provisioned token.
    /// </para>
    /// <para>
    /// Once. A card resetting twice in one command is not a card having a bad
    /// moment, and retrying at it would hide that.
    /// </para>
    /// </remarks>
    public ApduResponse Send(ApduCommand command)
    {
        ObjectDisposedException.ThrowIf(disposed, this);

        try
        {
            return SendOnce(command);
        }
        catch (PcscException reset) when (reset.Code == PcscException.ResetCard)
        {
            if (!Transport.Reconnect() || !SelectPiv())
            {
                throw;
            }

            return SendOnce(command);
        }
    }

    private ApduResponse SendOnce(ApduCommand command)
    {
        var data = command.Data;
        var collected = new List<byte>();

        // Outbound chaining: every block but the last carries CLA | 0x10.
        while (data.Length > ApduCommand.MaxDataPerApdu)
        {
            var block = data[..ApduCommand.MaxDataPerApdu];
            var partial = command with
            {
                Cla = (byte)(command.Cla | ApduCommand.ChainingBit),
                Data = block,
                Le = null,
            };

            var acknowledgement = Transport.Transmit(partial.Encode());
            if (!acknowledgement.IsSuccess)
            {
                // A card that rejects a middle block will not accept the rest;
                // stopping here reports the real status rather than a confusing
                // failure several blocks later.
                return acknowledgement;
            }

            data = data[ApduCommand.MaxDataPerApdu..];
        }

        var response = Transport.Transmit((command with { Data = data }).Encode());
        collected.AddRange(response.Data);

        var status = response.Status;

        while (true)
        {
            // 6Cxx: the card wants the same command back with the right Le.
            if (status.ExpectedLength is { } expected)
            {
                response = Transport.Transmit((command with { Data = data, Le = expected }).Encode());
                collected.Clear();
                collected.AddRange(response.Data);
                status = response.Status;
                continue;
            }

            // 61xx: more data waiting.
            if (status.HasMoreData)
            {
                response = Transport.Transmit(
                    new ApduCommand(InsGetResponse, le: status.AvailableBytes).Encode());
                collected.AddRange(response.Data);
                status = response.Status;
                continue;
            }

            break;
        }

        return new ApduResponse([.. collected], status);
    }

    /// <summary>
    /// Sends a command and returns its data, throwing a typed exception unless
    /// the card said 9000.
    /// </summary>
    public byte[] SendChecked(ApduCommand command, string operation)
    {
        var response = Send(command);
        PivStatus.ThrowIfFailed(response.Status, operation);
        return response.Data;
    }

    public void Dispose()
    {
        if (disposed)
        {
            return;
        }

        disposed = true;
        if (ownsTransport)
        {
            Transport.Dispose();
        }
    }
}
