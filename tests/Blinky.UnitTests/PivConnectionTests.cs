using Blinky.Piv;
using Exchange = Blinky.UnitTests.TranscriptTransport.Exchange;

namespace Blinky.UnitTests;

public sealed class PivConnectionTests
{
    [Fact]
    public void More_data_available_is_collected_across_get_response()
    {
        // 61xx never appeared in the hardware capture because every response
        // fitted one APDU over T=1. It will appear the moment a certificate is
        // read, so it is built by hand rather than left to chance.
        var transport = TranscriptTransport.Scripted(
            new Exchange("GET DATA", Hex("00CB3FFF055C035FC10500"), Hex("AABB"), 0x6103),
            new Exchange("GET RESPONSE", Hex("00C0000003"), Hex("CCDDEE"), 0x9000));

        using var connection = new PivConnection(transport);
        var response = connection.Send(new ApduCommand(0xCB, 0x3F, 0xFF,
            Hex("5C035FC105"), le: 0));

        Assert.Equal("AABBCCDDEE", Convert.ToHexString(response.Data));
        Assert.True(response.IsSuccess);
        Assert.Equal(0, transport.Remaining);
    }

    [Fact]
    public void Several_rounds_of_get_response_are_collected_in_order()
    {
        var transport = TranscriptTransport.Scripted(
            new Exchange("GET DATA", Hex("00CB3FFF055C035FC10500"), Hex("01"), 0x6102),
            new Exchange("GET RESPONSE", Hex("00C0000002"), Hex("0203"), 0x6101),
            new Exchange("GET RESPONSE", Hex("00C0000001"), Hex("04"), 0x9000));

        using var connection = new PivConnection(transport);
        var response = connection.Send(new ApduCommand(0xCB, 0x3F, 0xFF,
            Hex("5C035FC105"), le: 0));

        Assert.Equal("01020304", Convert.ToHexString(response.Data));
    }

    [Fact]
    public void Wrong_length_is_retried_with_the_length_the_card_asked_for()
    {
        // 6Cxx comes from T=0 readers. The retry replaces the collected data
        // rather than appending to it - appending would silently double it.
        var transport = TranscriptTransport.Scripted(
            new Exchange("GET METADATA", Hex("00F7009B00"), [], 0x6C04),
            new Exchange("GET METADATA retried", Hex("00F7009B04"), Hex("01020304"), 0x9000));

        using var connection = new PivConnection(transport);
        var response = connection.Send(new ApduCommand(0xF7, p2: 0x9B, le: 0));

        Assert.Equal("01020304", Convert.ToHexString(response.Data));
        Assert.Equal(0, transport.Remaining);
    }

    [Fact]
    public void Long_data_is_chained_with_the_chaining_bit_on_every_block_but_the_last()
    {
        // Writing an RSA-2048 certificate is the real case: it does not fit in
        // one APDU and the card must not be left holding half of it.
        var payload = new byte[300];
        for (var i = 0; i < payload.Length; i++)
        {
            payload[i] = (byte)i;
        }

        var first = new byte[] { 0x10, 0xDB, 0x3F, 0xFF, 0xFF }
            .Concat(payload[..255]).ToArray();
        var second = new byte[] { 0x00, 0xDB, 0x3F, 0xFF, 0x2D }
            .Concat(payload[255..]).ToArray();

        var transport = TranscriptTransport.Scripted(
            new Exchange("PUT DATA block 1", first, [], 0x9000),
            new Exchange("PUT DATA block 2", second, [], 0x9000));

        using var connection = new PivConnection(transport);
        var response = connection.Send(new ApduCommand(0xDB, 0x3F, 0xFF, payload));

        Assert.True(response.IsSuccess);
        Assert.Equal(0, transport.Remaining);
    }

    [Fact]
    public void A_rejected_block_stops_the_chain_and_reports_that_status()
    {
        // Continuing after a refused block would report a failure from several
        // blocks later, which is a much harder thing to read in a log.
        var payload = new byte[300];
        var first = new byte[] { 0x10, 0xDB, 0x3F, 0xFF, 0xFF }
            .Concat(payload[..255]).ToArray();

        var transport = TranscriptTransport.Scripted(
            new Exchange("PUT DATA block 1", first, [], 0x6982));

        using var connection = new PivConnection(transport);
        var response = connection.Send(new ApduCommand(0xDB, 0x3F, 0xFF, payload));

        Assert.Equal(0x6982, response.Status.Value);
        Assert.Equal(0, transport.Remaining);
    }

    [Fact]
    public void Send_checked_throws_the_typed_exception()
    {
        var transport = TranscriptTransport.Scripted(
            new Exchange("ATTEST", Hex("00F99A0000"), [], 0x6A80));

        using var connection = new PivConnection(transport);

        Assert.Throws<PivIncorrectParametersException>(
            () => connection.SendChecked(new ApduCommand(0xF9, 0x9A, le: 0), "ATTEST 9A"));
    }

    [Fact]
    public void A_response_too_short_for_a_status_word_is_a_protocol_error()
    {
        Assert.Throws<ArgumentException>(() => ApduResponse.Parse([0x01]));
    }

    [Fact]
    public void Using_a_disposed_connection_is_refused()
    {
        var connection = new PivConnection(TranscriptTransport.Scripted());
        connection.Dispose();

        Assert.Throws<ObjectDisposedException>(() => connection.Send(new ApduCommand(0xFD)));
    }

    private static byte[] Hex(string hex) => Convert.FromHexString(hex);
}
