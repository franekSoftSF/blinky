using System.Security.Cryptography.X509Certificates;
using Blinky.Piv;

namespace Blinky.UnitTests;

/// <summary>
/// The other capture is three blank tokens. This one is a single 5.7.1 with a
/// key and a certificate written into slot 9A by <c>ykman</c>, which is the
/// half of patch 0011's definition of done that blank tokens cannot cover:
/// reading a certificate off a card, and the response chaining that a
/// certificate forces.
/// </summary>
public sealed class ProvisionedTokenTests
{
    private const string Fixture = "piv-provisioned.transcript.json";

    private static TokenInventory Read()
    {
        var card = TranscriptTransport.Cards(Fixture)
            .Select(c => new PivSession(new PivConnection(c, ownsTransport: false)))
            .First(session => session.Select());

        return card.ReadInventory();
    }

    [Fact]
    public void The_certificate_in_9a_is_read_and_parses()
    {
        var slot = Read().Slots.Single(s => s.Slot == PivSlot.Authentication);

        Assert.True(slot.HasCertificate);
        Assert.NotNull(slot.CertificateDer);

        var certificate = X509CertificateLoader.LoadCertificate(slot.CertificateDer!);
        Assert.Equal("CN=blinky-test", certificate.Subject);
    }

    [Fact]
    public void The_key_metadata_matches_what_was_written()
    {
        // ykman generated an ECC P-256 key with PIN policy Once and no touch.
        // The card is asked; nothing here is inferred from the certificate.
        var slot = Read().Slots.Single(s => s.Slot == PivSlot.Authentication);

        Assert.NotNull(slot.Metadata);
        Assert.Equal(PivAlgorithm.EccP256, slot.Metadata!.Algorithm);
        Assert.Equal(KeyOrigin.Generated, slot.Metadata.Origin);
        Assert.Equal(PinPolicy.Once, slot.Metadata.PinPolicy);
        Assert.Equal(TouchPolicy.Never, slot.Metadata.TouchPolicy);
    }

    [Fact]
    public void A_slot_with_a_key_is_not_reported_as_empty()
    {
        var token = Read();

        Assert.False(token.Slots.Single(s => s.Slot == PivSlot.Authentication).IsEmpty);
        Assert.All(
            token.Slots.Where(s => s.Slot != PivSlot.Authentication),
            slot => Assert.True(slot.IsEmpty));
    }

    [Fact]
    public void Reading_the_certificate_really_did_chain_on_hardware()
    {
        // Until this capture, 61xx existed only in hand-built cases: every
        // response from a blank token fitted a single APDU. A PIV data object
        // holding even a P-256 certificate does not, so this is the proof that
        // the GET RESPONSE path works against a card and not just a fake.
        var exchanges = TranscriptTransport.FromFixture(Fixture).Exchanges;

        var chained = exchanges.Where(e => (e.Status & 0xFF00) == 0x6100).ToList();
        Assert.NotEmpty(chained);

        var getResponse = exchanges
            .Where(e => e.Command.Length >= 2 && e.Command[0] == 0x00 && e.Command[1] == 0xC0)
            .ToList();
        Assert.NotEmpty(getResponse);

        // 256 bytes, then the 61 the card said were left.
        Assert.Equal(256, chained[0].Response.Length);
        Assert.Equal(0x3D, chained[0].Status & 0x00FF);
        Assert.Equal(0x3D, getResponse[0].Response.Length);
    }

    [Fact]
    public void The_management_key_is_still_the_factory_one()
    {
        // ykman authenticated with the default key rather than replacing it, so
        // this token is provisioned but not personalised - exactly the state
        // patch 0025 has to refuse to issue onto.
        var token = Read();

        Assert.Equal(PivAlgorithm.Aes192, token.ManagementKey!.Algorithm);
        Assert.True(token.ManagementKey.IsDefault);
    }
}
