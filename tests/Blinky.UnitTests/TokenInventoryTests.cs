using Blinky.Piv;

namespace Blinky.UnitTests;

/// <summary>
/// Reads the three tokens from the recorded capture through the real read path
/// and checks what it concluded about each. This is the semantic half of patch
/// 0011: the byte level is guarded by the strict replay, and this is about
/// whether the library draws the right conclusions from those bytes.
/// </summary>
public sealed class TokenInventoryTests
{
    private const string Fixture = "piv-inventory.transcript.json";

    private static TokenInventory Read(uint fakeSerial)
    {
        foreach (var card in TranscriptTransport.Cards(Fixture))
        {
            var session = new PivSession(new PivConnection(card, ownsTransport: false));
            if (!session.Select())
            {
                continue;
            }

            var inventory = session.ReadInventory();
            if (inventory.SerialNumber == fakeSerial)
            {
                return inventory;
            }
        }

        throw new InvalidOperationException($"No card with serial {fakeSerial} in the capture.");
    }

    [Fact]
    public void A_reader_with_no_piv_applet_is_skipped_rather_than_failing()
    {
        // The capture opens with a Windows Hello virtual reader answering 6A82.
        // Every machine with Hello enabled has one.
        var cards = TranscriptTransport.Cards(Fixture);

        var selected = cards
            .Select(card => new PivSession(new PivConnection(card, ownsTransport: false)).Select())
            .ToList();

        Assert.Contains(false, selected);
        Assert.Equal(3, selected.Count(ok => ok));
    }

    [Fact]
    public void The_bio_token_is_read_correctly()
    {
        var token = Read(0x00BADA55);

        Assert.Equal(new FirmwareVersion(5, 7, 2), token.Firmware);
        Assert.Equal(PivAlgorithm.Aes192, token.ManagementKey!.Algorithm);
        Assert.True(token.ManagementKey.IsDefault);

        Assert.True(token.IsBiometric);
        Assert.True(token.Biometrics!.FingerprintsEnrolled);
        Assert.Equal(3, token.Biometrics.AttemptsRemaining);
        Assert.False(token.Biometrics.TemporaryPinSet);

        // Its PIN has been changed from the factory value and given 8 retries.
        Assert.Equal(PinState.Set, token.Pin.State);
        Assert.Equal(8, token.Pin.TotalRetries);
        Assert.Equal(8, token.Pin.RemainingRetries);
    }

    [Fact]
    public void A_bio_token_has_no_puk_and_that_is_not_a_blocked_puk()
    {
        // The distinction the whole personalisation rule rests on: this token
        // is unrecoverable by design, not broken.
        var token = Read(0x00BADA55);

        Assert.Equal(PinState.NotConfigured, token.Puk.State);
        Assert.True(token.Puk.IsUnrecoverable);
        Assert.NotEqual(PinState.Blocked, token.Puk.State);
    }

    [Fact]
    public void The_5_7_token_reports_an_aes_management_key()
    {
        var token = Read(0x00BADA56);

        Assert.Equal(new FirmwareVersion(5, 7, 1), token.Firmware);
        Assert.Equal(PivAlgorithm.Aes192, token.ManagementKey!.Algorithm);
        Assert.Null(token.Biometrics);
        Assert.False(token.IsBiometric);
    }

    [Fact]
    public void The_5_4_token_reports_a_3des_management_key()
    {
        // Same code, same commands, different answer. An agent that assumed
        // either algorithm would fail on one of these two tokens.
        var token = Read(0x00BADA57);

        Assert.Equal(new FirmwareVersion(5, 4, 3), token.Firmware);
        Assert.Equal(PivAlgorithm.TripleDes, token.ManagementKey!.Algorithm);
        Assert.True(token.ManagementKey.IsDefault);
    }

    [Theory]
    [InlineData(0x00BADA56u)]
    [InlineData(0x00BADA57u)]
    public void Factory_tokens_report_default_credentials_with_three_retries(uint serial)
    {
        var token = Read(serial);

        Assert.Equal(PinState.Default, token.Pin.State);
        Assert.Equal(3, token.Pin.TotalRetries);
        Assert.Equal(3, token.Pin.RemainingRetries);

        Assert.Equal(PinState.Default, token.Puk.State);
        Assert.False(token.Puk.IsUnrecoverable);
    }

    [Theory]
    [InlineData(0x00BADA55u)]
    [InlineData(0x00BADA56u)]
    [InlineData(0x00BADA57u)]
    public void Every_credential_slot_on_the_bench_is_empty(uint serial)
    {
        // All three tokens are blank in PIV. Certificate parsing and
        // attestation are therefore still unexercised on hardware, which is
        // stated in STATUS.md rather than hidden behind a green suite.
        var token = Read(serial);

        Assert.Equal(4, token.Slots.Count);
        Assert.All(token.Slots, slot =>
        {
            Assert.True(slot.IsEmpty);
            Assert.False(slot.HasCertificate);
            Assert.Null(slot.CertificateDer);
        });
    }
}
