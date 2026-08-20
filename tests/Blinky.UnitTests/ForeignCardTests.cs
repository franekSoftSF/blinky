using Blinky.Piv;
using Exchange = Blinky.UnitTests.TranscriptTransport.Exchange;

namespace Blinky.UnitTests;

/// <summary>
/// A PIV card that is not a YubiKey. Built from what an HID Crescendo Key V3
/// actually answered on the bench: SELECT succeeds, the PIN retry counter reads
/// back, and every Yubico instruction returns 6D00.
/// </summary>
/// <remarks>
/// Blinky manages YubiKey 5 in this version. The point of these cases is that
/// a card it cannot manage must be recognised and reported, never mistaken for
/// a broken YubiKey and never quietly dropped - an operator who plugs in a card
/// and sees nothing happen cannot tell that from a dead agent.
/// </remarks>
public sealed class ForeignCardTests
{
    private const string SelectPiv = "00A4040005A00000030800";
    private const string GetVersion = "00FD000000";
    private const string GetSerial = "00F8000000";
    private const string Attest9A = "00F99A0000";
    private const string GetAttestationCertificate = "00CB3FFF055C035FFF0100";

    [Fact]
    public void The_applet_selects_but_the_card_is_not_a_yubikey()
    {
        var session = ForeignCard(
            new Exchange("SELECT", Hex(SelectPiv), Hex("61114F0600001000010079074F05A000000308"), 0x9000),
            new Exchange("GET SERIAL", Hex(GetSerial), [], 0x6D00));

        Assert.True(session.Select());
        Assert.False(session.IsYubiKey());
    }

    [Fact]
    public void Firmware_is_unknown_rather_than_guessed()
    {
        var session = ForeignCard(
            new Exchange("GET VERSION", Hex(GetVersion), [], 0x6D00));

        Assert.Equal(FirmwareVersion.Unknown, session.GetFirmwareVersion());
    }

    [Fact]
    public void Attestation_is_absent_rather_than_an_error()
    {
        // This was a real bug: ATTEST is a Yubico instruction, and 6D00 was not
        // in the list of "nothing to attest" status words. An ordinary
        // Crescendo turned an inventory pass into an exception.
        var session = ForeignCard(
            new Exchange("ATTEST", Hex(Attest9A), [], 0x6D00));

        Assert.Null(session.Attest(PivSlot.Authentication));
    }

    [Fact]
    public void The_attestation_certificate_slot_is_absent_rather_than_an_error()
    {
        var session = ForeignCard(
            new Exchange("GET DATA F9", Hex(GetAttestationCertificate), [], 0x6D00));

        Assert.Null(session.GetAttestationCertificate());
    }

    [Fact]
    public void The_pin_retry_counter_still_reads_because_it_is_standard_piv()
    {
        // Six attempts, which is what the card on the bench reported. The empty
        // VERIFY probe is standard PIV, not a Yubico extension, so this is the
        // one thing that does work.
        var session = ForeignCard(
            new Exchange("VERIFY", Hex("00200080"), [], 0x63C6),
            new Exchange("GET METADATA 80", Hex("00F7008000"), [], 0x6D00));

        var pin = session.GetPinMetadata();

        Assert.Equal(6, pin.RemainingRetries);
        Assert.Equal(PinState.Set, pin.State);
    }

    [Fact]
    public void Metadata_that_cannot_be_asked_for_is_null_not_a_default()
    {
        var session = ForeignCard(
            new Exchange("GET METADATA 9B", Hex("00F7009B00"), [], 0x6D00));

        Assert.Null(session.GetManagementKeyMetadata());
    }

    private static PivSession ForeignCard(params Exchange[] exchanges) =>
        new(new PivConnection(TranscriptTransport.Scripted(exchanges)));

    private static byte[] Hex(string hex) => Convert.FromHexString(hex);
}
