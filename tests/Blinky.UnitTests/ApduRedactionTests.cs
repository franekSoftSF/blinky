using Blinky.Piv;

namespace Blinky.UnitTests;

/// <summary>
/// The PIN must not survive a failed transmit. This is the test for a leak
/// that reached the database: an enrolment on 20 August 2026 failed at the
/// VERIFY, and the job result stored the whole command - PIN included.
/// </summary>
public sealed class ApduRedactionTests
{
    // The exact command from that failure. 00 20 00 80 is VERIFY against the
    // PIV PIN, 08 is the length, and the eight bytes are "258025" in ASCII
    // padded with FF - which is to say, somebody's PIN.
    private static readonly byte[] VerifyWithAPin =
        [0x00, 0x20, 0x00, 0x80, 0x08, 0x32, 0x35, 0x38, 0x30, 0x32, 0x35, 0xFF, 0xFF];

    [Fact]
    public void A_pin_does_not_appear_in_the_description()
    {
        var described = ApduRedaction.Describe(VerifyWithAPin);

        Assert.DoesNotContain("323538303235", described, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("258025", described, StringComparison.Ordinal);
    }

    [Fact]
    public void The_header_survives_because_it_is_what_names_the_operation()
    {
        var described = ApduRedaction.Describe(VerifyWithAPin);

        // Class, instruction, both parameters and the length: enough to say
        // "the PIN verification failed" without saying what the PIN was.
        Assert.StartsWith("0020008008", described, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("8 bytes withheld", described, StringComparison.Ordinal);
    }

    [Theory]
    [InlineData(0x24)] // CHANGE REFERENCE DATA - old PIN and new one together
    [InlineData(0x2C)] // RESET RETRY COUNTER - the PUK, and the PIN it sets
    [InlineData(0x87)] // GENERAL AUTHENTICATE - management key witness
    [InlineData(0xDB)] // PUT DATA - a new management key on its way to the card
    public void Every_instruction_that_carries_a_secret_is_withheld(byte instruction)
    {
        byte[] apdu = [0x00, instruction, 0x00, 0x80, 0x04, 0xDE, 0xAD, 0xBE, 0xEF];

        var described = ApduRedaction.Describe(apdu);

        Assert.DoesNotContain("DEADBEEF", described, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("withheld", described, StringComparison.Ordinal);
    }

    [Fact]
    public void An_ordinary_command_is_shown_in_full()
    {
        // SELECT the PIV applet. Nothing secret, and the AID is the first
        // thing worth seeing when a card answers oddly.
        byte[] select =
            [0x00, 0xA4, 0x04, 0x00, 0x09, 0xA0, 0x00, 0x00, 0x03, 0x08, 0x00, 0x00, 0x10, 0x00];

        Assert.Equal(Convert.ToHexString(select), ApduRedaction.Describe(select));
    }

    [Fact]
    public void A_header_with_no_data_is_shown_in_full()
    {
        byte[] getSerial = [0x00, 0xF8, 0x00, 0x00];

        Assert.Equal("00F80000", ApduRedaction.Describe(getSerial));
    }

    [Fact]
    public void A_long_body_is_cut_rather_than_filling_the_message()
    {
        // A certificate on its way to a slot. Two kilobytes of hex in an error
        // message is a way of hiding the error.
        var write = new byte[5 + 2000];
        write[1] = 0xA4; // not on the secret list, so length is what limits it

        var described = ApduRedaction.Describe(write);

        Assert.Contains("(2000 bytes)", described, StringComparison.Ordinal);
        Assert.True(described.Length < 200);
    }
}
