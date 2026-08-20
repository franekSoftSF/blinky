using Blinky.Piv;

namespace Blinky.UnitTests;

public sealed class FirmwareVersionTests
{
    [Fact]
    public void Version_is_parsed_from_three_bytes()
    {
        Assert.Equal(new FirmwareVersion(5, 7, 2),
            FirmwareVersion.Parse([0x05, 0x07, 0x02]));
    }

    [Fact]
    public void A_short_response_is_a_protocol_error()
    {
        Assert.Throws<PivProtocolException>(() => FirmwareVersion.Parse([0x05, 0x07]));
    }

    [Theory]
    [InlineData(5, 2, 7, false)]
    [InlineData(5, 3, 0, true)]
    [InlineData(5, 4, 3, true)]
    public void Metadata_needs_5_3(byte major, byte minor, byte patch, bool expected)
    {
        Assert.Equal(expected, new FirmwareVersion(major, minor, patch).SupportsMetadata);
    }

    [Theory]
    [InlineData(5, 4, 3, false)]
    [InlineData(5, 6, 9, false)]
    [InlineData(5, 7, 0, true)]
    [InlineData(5, 7, 2, true)]
    public void Aes_management_keys_arrive_in_5_7(byte major, byte minor, byte patch, bool expected)
    {
        // Both sides of this boundary are on the bench: 5.4.3 reports 3DES,
        // 5.7.1 and 5.7.2 report AES-192.
        Assert.Equal(expected,
            new FirmwareVersion(major, minor, patch).DefaultsToAesManagementKey);
    }

    [Fact]
    public void Ordering_compares_component_by_component()
    {
        Assert.True(new FirmwareVersion(5, 7, 1) > new FirmwareVersion(5, 6, 9));
        Assert.True(new FirmwareVersion(5, 7, 1) < new FirmwareVersion(5, 7, 2));
        Assert.True(new FirmwareVersion(5, 7, 2) >= new FirmwareVersion(5, 7, 2));
    }
}
