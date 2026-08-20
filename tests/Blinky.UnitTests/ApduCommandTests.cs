using Blinky.Piv;

namespace Blinky.UnitTests;

public sealed class ApduCommandTests
{
    [Fact]
    public void Case_1_is_header_only()
    {
        // VERIFY with no data: the read-only way to ask for the retry counter.
        var apdu = new ApduCommand(0x20, p2: 0x80).Encode();

        Assert.Equal("00200080", Convert.ToHexString(apdu));
    }

    [Fact]
    public void Case_2_appends_le()
    {
        var apdu = new ApduCommand(0xF7, p2: 0x9B, le: 0).Encode();

        Assert.Equal("00F7009B00", Convert.ToHexString(apdu));
    }

    [Fact]
    public void Case_3_appends_lc_and_data()
    {
        var apdu = new ApduCommand(0xDB, p1: 0x3F, p2: 0xFF, data: new byte[] { 0x01, 0x02 }).Encode();

        Assert.Equal("00DB3FFF020102", Convert.ToHexString(apdu));
    }

    [Fact]
    public void Case_4_carries_both()
    {
        var apdu = new ApduCommand(0xA4, p1: 0x04, data: PivConnection.PivAid, le: 0).Encode();

        Assert.Equal("00A4040005A00000030800", Convert.ToHexString(apdu));
    }

    [Fact]
    public void Le_of_256_is_encoded_as_zero()
    {
        var apdu = new ApduCommand(0xC0, le: 256).Encode();

        Assert.Equal("00C0000000", Convert.ToHexString(apdu));
    }

    [Fact]
    public void Encoding_more_than_one_apdu_of_data_is_refused()
    {
        // Silently truncating a certificate write would produce a card that
        // holds half a certificate and a job that reported success.
        var command = new ApduCommand(0xDB, data: new byte[256]);

        var error = Assert.Throws<InvalidOperationException>(() => command.Encode());
        Assert.Contains("chains", error.Message, StringComparison.OrdinalIgnoreCase);
    }

    [Theory]
    [InlineData(-1)]
    [InlineData(257)]
    public void Impossible_le_is_refused(int le)
    {
        Assert.Throws<ArgumentOutOfRangeException>(() => new ApduCommand(0xC0, le: le));
    }

    [Fact]
    public void Every_recorded_command_round_trips_through_the_encoder()
    {
        // Decode each command the probe actually sent to real hardware, rebuild
        // it, and require the same bytes back. This is what ties the encoder to
        // the capture rather than to my idea of the capture.
        var transcript = TranscriptTransport.FromFixture("piv-inventory.transcript.json");

        Assert.NotEmpty(transcript.Exchanges);

        foreach (var exchange in transcript.Exchanges)
        {
            var rebuilt = Decode(exchange.Command).Encode();

            Assert.Equal(Convert.ToHexString(exchange.Command), Convert.ToHexString(rebuilt));
        }
    }

    private static ApduCommand Decode(byte[] apdu)
    {
        var cla = apdu[0];
        var ins = apdu[1];
        var p1 = apdu[2];
        var p2 = apdu[3];

        if (apdu.Length == 4)
        {
            return new ApduCommand(ins, p1, p2, cla: cla);
        }

        if (apdu.Length == 5)
        {
            return new ApduCommand(ins, p1, p2, le: apdu[4], cla: cla);
        }

        var lc = apdu[4];
        var data = apdu.AsMemory(5, lc);
        var hasLe = apdu.Length == 5 + lc + 1;

        return new ApduCommand(ins, p1, p2, data, hasLe ? apdu[^1] : null, cla);
    }
}
