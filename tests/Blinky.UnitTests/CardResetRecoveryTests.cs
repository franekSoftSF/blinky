using Blinky.Piv;
using Blinky.Piv.Pcsc;

namespace Blinky.UnitTests;

/// <summary>
/// A card reset mid-command is recoverable, and used not to be recovered from.
/// </summary>
/// <remarks>
/// On 20 August 2026 an enrolment on BY-WIN-CLIENT01 generated a key on the
/// card and then failed at the PIN verification with <c>SCARD_W_RESET_CARD</c>,
/// leaving a key in slot 9A with no certificate against it. On Windows the
/// card is shared with the smart card service, any installed minidriver and
/// the logon screen; a transaction stops them interleaving commands, not
/// resetting the card.
/// </remarks>
public sealed class CardResetRecoveryTests
{
    private const uint ResetCard = 0x80100068;

    [Fact]
    public void A_reset_is_recovered_by_selecting_the_applet_again()
    {
        var transport = new ResettingTransport(resetsOnCommand: 1);

        using var connection = new PivConnection(transport);
        var response = connection.Send(new ApduCommand(0x20, p2: 0x80, data: new byte[] { 1, 2, 3, 4 }));

        Assert.True(response.IsSuccess);
        Assert.Equal(1, transport.Reconnects);

        // The applet has to be selected again - that is what the reset threw
        // away, and sending the command without it would get 6A82 or worse.
        Assert.Contains(transport.Sent, c => c.Length > 1 && c[1] == 0xA4);
    }

    [Fact]
    public void The_command_is_sent_again_after_the_applet_is_reselected()
    {
        var transport = new ResettingTransport(resetsOnCommand: 1);

        using var connection = new PivConnection(transport);
        connection.Send(new ApduCommand(0x20, p2: 0x80, data: new byte[] { 1, 2, 3, 4 }));

        // VERIFY, twice: the one that met the reset and the one that did not.
        Assert.Equal(2, transport.Sent.Count(c => c.Length > 1 && c[1] == 0x20));
    }

    [Fact]
    public void A_card_that_keeps_resetting_reports_the_failure()
    {
        // Once is a hiccup. Twice in one command is a fault, and retrying at
        // it would hide the fault rather than survive it.
        var transport = new ResettingTransport(resetsOnCommand: 1, alsoResetsAfterRecovery: true);

        using var connection = new PivConnection(transport);

        var ex = Assert.Throws<PcscException>(() =>
            connection.Send(new ApduCommand(0x20, p2: 0x80, data: new byte[] { 1, 2, 3, 4 })));

        Assert.Equal(ResetCard, ex.Code);
    }

    [Fact]
    public void A_transport_that_cannot_reconnect_reports_the_original_failure()
    {
        var transport = new ResettingTransport(resetsOnCommand: 1) { CanReconnect = false };

        using var connection = new PivConnection(transport);

        var ex = Assert.Throws<PcscException>(() =>
            connection.Send(new ApduCommand(0x20, p2: 0x80, data: new byte[] { 1, 2, 3, 4 })));

        Assert.Equal(ResetCard, ex.Code);
        Assert.Equal(0, transport.Sent.Count(c => c.Length > 1 && c[1] == 0xA4));
    }

    /// <summary>Throws a reset on a chosen command, then behaves.</summary>
    private sealed class ResettingTransport(int resetsOnCommand, bool alsoResetsAfterRecovery = false)
        : IApduTransport
    {
        private int commands;
        private bool recovered;

        public string Description => "a card that gets reset";

        public bool CanReconnect { get; init; } = true;

        public int Reconnects { get; private set; }

        public List<byte[]> Sent { get; } = [];

        public ApduResponse Transmit(ReadOnlySpan<byte> apdu)
        {
            commands++;
            Sent.Add(apdu.ToArray());

            if (commands == resetsOnCommand || (alsoResetsAfterRecovery && recovered
                                                && apdu.Length > 1 && apdu[1] == 0x20))
            {
                throw new PcscException(ResetCard, "SCardTransmit(<redacted>)");
            }

            return new ApduResponse([], new StatusWord(0x9000));
        }

        public IDisposable BeginTransaction() => new Nothing();

        public bool Reconnect()
        {
            Reconnects++;
            recovered = true;
            return CanReconnect;
        }

        public void Dispose()
        {
        }

        private sealed class Nothing : IDisposable
        {
            public void Dispose()
            {
            }
        }
    }
}
