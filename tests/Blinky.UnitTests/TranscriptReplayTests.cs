using Blinky.Piv;

namespace Blinky.UnitTests;

/// <summary>
/// Drives <see cref="PivConnection"/> through the exact sequence the probe sent
/// to three real YubiKeys. The transport is strict about command bytes, so this
/// fails if the library would talk to a card differently than the hardware run
/// that validated the approach.
/// </summary>
public sealed class TranscriptReplayTests
{
    private const string Fixture = "piv-inventory.transcript.json";

    [Fact]
    public void The_recorded_sequence_replays_exactly()
    {
        var transport = TranscriptTransport.FromFixture(Fixture);
        using var connection = new PivConnection(transport);

        foreach (var exchange in transport.Exchanges.ToList())
        {
            var response = connection.Send(Rebuild(exchange.Command));

            Assert.Equal(exchange.Status, response.Status.Value);
            Assert.Equal(Convert.ToHexString(exchange.Response),
                Convert.ToHexString(response.Data));
        }

        Assert.Equal(0, transport.Remaining);
    }

    [Fact]
    public void Selecting_the_applet_succeeds_on_a_card_and_fails_on_a_virtual_reader()
    {
        // The capture contains both: a Windows Hello virtual reader answering
        // 6A82, and three YubiKeys answering 9000. Neither is an error.
        var transport = TranscriptTransport.FromFixture(Fixture);

        var select = Convert.ToHexString(
            new ApduCommand(0xA4, p1: 0x04, data: PivConnection.PivAid, le: 0).Encode());

        var selects = transport.Exchanges
            .Where(e => Convert.ToHexString(e.Command) == select)
            .ToList();

        Assert.Contains(selects, e => e.Status == 0x9000);
        Assert.Contains(selects, e => e.Status == 0x6A82);
    }

    [Fact]
    public void The_fixture_still_contains_the_status_words_the_error_map_claims()
    {
        // If a re-capture quietly drops a status word, the replay would still
        // pass while covering less. This states what the fixture is for.
        var transport = TranscriptTransport.FromFixture(Fixture);
        var statuses = transport.Exchanges.Select(e => e.Status).ToHashSet();

        Assert.Contains((ushort)0x9000, statuses);
        Assert.Contains((ushort)0x6A82, statuses);
        Assert.Contains((ushort)0x6A88, statuses);
        Assert.Contains((ushort)0x6A80, statuses);
        Assert.Contains(statuses, s => (s & 0xFFF0) == 0x63C0);
    }

    [Fact]
    public void No_serial_number_from_a_real_token_is_in_the_fixture()
    {
        // The repository is public. Serials are replaced at capture time; this
        // fails loudly if somebody drops in a raw transcript.
        var transport = TranscriptTransport.FromFixture(Fixture);

        // Matched by command bytes, not by label: labels are cosmetic and the
        // probe has renamed them once already.
        var getSerial = Convert.ToHexString(new ApduCommand(0xF8, le: 0).Encode());

        var serials = transport.Exchanges
            .Where(e => Convert.ToHexString(e.Command) == getSerial && e.Status == 0x9000)
            .Select(e => Convert.ToHexString(e.Response))
            .ToList();

        Assert.NotEmpty(serials);
        Assert.All(serials, s => Assert.StartsWith("00BADA5", s, StringComparison.Ordinal));
    }

    private static ApduCommand Rebuild(byte[] apdu)
    {
        var (cla, ins, p1, p2) = (apdu[0], apdu[1], apdu[2], apdu[3]);

        if (apdu.Length == 4)
        {
            return new ApduCommand(ins, p1, p2, cla: cla);
        }

        if (apdu.Length == 5)
        {
            return new ApduCommand(ins, p1, p2, le: apdu[4], cla: cla);
        }

        var lc = apdu[4];
        var hasLe = apdu.Length == 5 + lc + 1;

        return new ApduCommand(ins, p1, p2, apdu.AsMemory(5, lc), hasLe ? apdu[^1] : null, cla);
    }
}
