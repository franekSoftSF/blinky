using Blinky.Piv;

namespace Blinky.UnitTests;

public sealed class TlvTests
{
    [Fact]
    public void Metadata_for_a_pin_decodes_to_algorithm_default_flag_and_retries()
    {
        // Straight off the 5.7.2 on the bench: PIN, not default, 8 of 8.
        var metadata = ParseSimple("0101FF05010006020808");

        Assert.Equal("FF", Convert.ToHexString(metadata[0x01]));
        Assert.Equal("00", Convert.ToHexString(metadata[0x05]));
        Assert.Equal("0808", Convert.ToHexString(metadata[0x06]));
    }

    [Fact]
    public void Biometric_metadata_carries_one_retry_byte_not_two()
    {
        // Tag 06 means "attempts remaining" here and "total, remaining" in the
        // PIN slot. Reading it the same way in both places is off by one.
        var metadata = ParseSimple("070101060103080100");

        Assert.Equal("01", Convert.ToHexString(metadata[0x07]));
        Assert.Single(metadata[0x06]);
        Assert.Equal(3, metadata[0x06][0]);
        Assert.Equal("00", Convert.ToHexString(metadata[0x08]));
    }

    [Fact]
    public void Ber_handles_a_two_byte_length()
    {
        var value = new byte[300];
        var encoded = new byte[] { 0x70, 0x82, 0x01, 0x2C }.Concat(value).ToArray();

        var parsed = ParseBer(encoded);

        Assert.Equal(300, parsed[0x70].Length);
    }

    [Fact]
    public void A_truncated_value_is_returned_short_rather_than_throwing()
    {
        // A short read should surface as a missing field upstream, not as an
        // exception from a parser several layers down.
        var parsed = ParseBer([0x70, 0x10, 0x01, 0x02]);

        Assert.Equal(2, parsed[0x70].Length);
    }

    private static Dictionary<byte, byte[]> ParseSimple(string hex) =>
        Tlv.ParseSimple(Convert.FromHexString(hex));

    private static Dictionary<byte, byte[]> ParseBer(byte[] data) => Tlv.ParseBer(data);
}
