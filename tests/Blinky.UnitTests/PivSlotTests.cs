using Blinky.Piv;

namespace Blinky.UnitTests;

public sealed class PivSlotTests
{
    [Theory]
    [InlineData(0x9A, "5FC105")]
    [InlineData(0x9C, "5FC10A")]
    [InlineData(0x9D, "5FC10B")]
    [InlineData(0x9E, "5FC101")]
    public void Credential_slots_map_to_their_data_objects(byte id, string expected)
    {
        var slot = PivSlot.Credentials.Single(s => s.Id == id);

        Assert.Equal(expected, Convert.ToHexString(slot.CertificateObject!));
    }

    [Theory]
    [InlineData(0x82, "5FC10D")]
    [InlineData(0x83, "5FC10E")]
    [InlineData(0x95, "5FC120")]
    public void Retired_slots_run_in_order_from_5FC10D(byte id, string expected)
    {
        // Off by one here and rotating a 9D key writes the new certificate over
        // an old one, which is how a mail archive stops opening.
        var slot = PivSlot.Retired().Single(s => s.Id == id);

        Assert.Equal(expected, Convert.ToHexString(slot.CertificateObject!));
    }

    [Fact]
    public void There_are_twenty_retired_slots()
    {
        Assert.Equal(20, PivSlot.Retired().Count());
    }

    [Fact]
    public void The_attestation_slot_has_no_certificate_object()
    {
        Assert.Null(PivSlot.Attestation.CertificateObject);
    }
}
