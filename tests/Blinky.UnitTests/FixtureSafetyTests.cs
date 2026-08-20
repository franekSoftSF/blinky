using Blinky.Piv;

namespace Blinky.UnitTests;

/// <summary>
/// The repository is public and the fixtures are real captures from real
/// tokens. These tests are the guard on that, and they exist because the first
/// attempt at it leaked: filtering the ATTEST command out of a written
/// transcript left its GET RESPONSE continuations behind, and two thirds of an
/// attestation certificate went into a file destined for a commit.
/// </summary>
public sealed class FixtureSafetyTests
{
    public static TheoryData<string> Fixtures =>
    [
        "piv-inventory.transcript.json",
        "piv-provisioned.transcript.json",
    ];

    [Theory]
    [MemberData(nameof(Fixtures))]
    public void No_real_serial_number_survives_in_a_fixture(string fixture)
    {
        var getSerial = Convert.ToHexString(new ApduCommand(0xF8, le: 0).Encode());

        var serials = TranscriptTransport.FromFixture(fixture).Exchanges
            .Where(e => Convert.ToHexString(e.Command) == getSerial && e.Status == 0x9000)
            .Select(e => Convert.ToHexString(e.Response))
            .ToList();

        Assert.NotEmpty(serials);
        Assert.All(serials, s => Assert.StartsWith("00BADA5", s, StringComparison.Ordinal));
    }

    [Theory]
    [MemberData(nameof(Fixtures))]
    public void No_attestation_data_is_in_a_fixture(string fixture)
    {
        // An attestation certificate carries the device's real serial in
        // extension 1.3.6.1.4.1.41482.13.2 and identifies one physical token.
        // The probe stops recording around it rather than filtering afterwards.
        var attest = Convert.ToHexString(
            new ApduCommand(0xF9, PivSlot.Authentication.Id, le: 0).Encode());

        var exchanges = TranscriptTransport.FromFixture(fixture).Exchanges;

        Assert.DoesNotContain(exchanges, e => Convert.ToHexString(e.Command) == attest
                                              && e.Response.Length > 0);

        var attestationBytes = exchanges
            .Where(e => e.Label.StartsWith("ATTEST", StringComparison.Ordinal))
            .Sum(e => e.Response.Length);

        Assert.Equal(0, attestationBytes);
    }
}
