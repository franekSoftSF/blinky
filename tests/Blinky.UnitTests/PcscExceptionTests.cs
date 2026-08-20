using Blinky.Piv.Pcsc;

namespace Blinky.UnitTests;

/// <summary>
/// The codes that separate "this machine has no reader" from "the reader
/// broke". The agent polls every minute, and telling the two apart is the
/// difference between one line in the log and one line per minute forever.
/// </summary>
public sealed class PcscExceptionTests
{
    // 0x8010001D, seen on BY-WIN-CLIENT01 with nothing plugged in: Windows
    // starts the Smart Card service from a reader arrival trigger, so this is
    // the answer to the very first call on a workstation that has never had a
    // token in it.
    [Theory]
    [InlineData(0x8010001DU)] // SCARD_E_NO_SERVICE
    [InlineData(0x8010001EU)] // SCARD_E_SERVICE_STOPPED
    [InlineData(0x8010002EU)] // SCARD_E_NO_READERS_AVAILABLE
    public void No_reader_stack_is_not_a_fault(uint code)
    {
        var ex = new PcscException(code, "SCardEstablishContext");

        Assert.True(ex.IsNoReaderStack);
        Assert.False(ex.IsNoCard);
    }

    // A reader that is present and unhappy. These have to stay loud: a token
    // held by another program, or one that vanished mid-operation, is
    // something a person can act on.
    [Theory]
    [InlineData(0x8010000BU)] // SCARD_E_SHARING_VIOLATION
    [InlineData(0x80100017U)] // SCARD_E_READER_UNAVAILABLE
    [InlineData(0x8010000CU)] // SCARD_E_NO_SMARTCARD
    public void A_present_reader_failing_is_still_a_fault(uint code)
    {
        var ex = new PcscException(code, "SCardConnect");

        Assert.False(ex.IsNoReaderStack);
    }

    [Fact]
    public void The_message_names_the_operation_and_says_what_happened()
    {
        var ex = new PcscException(0x8010001DU, "SCardEstablishContext");

        Assert.Contains("SCardEstablishContext", ex.Message);
        Assert.Contains("0x8010001D", ex.Message);

        // The point of describing this one: "the Smart Card service is not
        // running" sends somebody to plug a token in. The bare code sends them
        // to a search engine.
        Assert.Contains("Smart Card service", ex.Message);
    }
}
