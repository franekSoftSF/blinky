using Blinky.Directory;

namespace Blinky.UnitTests;

/// <summary>
/// The SID, from the bytes LDAP hands over to the form everything else uses.
/// </summary>
/// <remarks>
/// Worth its own tests because the structure carries two endiannesses: a
/// six-byte authority big-endian, then 32-bit sub-authorities little-endian.
/// Getting one of them backwards produces a SID that looks entirely reasonable
/// and belongs to nobody — which then goes into a logon certificate and fails
/// three weeks later with a message about trust.
/// </remarks>
public sealed class SecurityIdentifierTests
{
    // The Administrator of BLINKY.LAB, as the directory holds it. The bytes
    // were derived from the printed form independently rather than by this
    // code, so this test is not checking itself.
    private static readonly byte[] Administrator =
    [
        0x01, 0x05, 0x00, 0x00, 0x00, 0x00, 0x00, 0x05,
        0x15, 0x00, 0x00, 0x00,
        0x5F, 0x52, 0xF0, 0x11,
        0x16, 0x15, 0x6A, 0x64,
        0x06, 0x92, 0x15, 0x94,
        0x50, 0x04, 0x00, 0x00,
    ];

    [Fact]
    public void A_real_sid_formats_the_way_the_directory_prints_it()
    {
        Assert.Equal("S-1-5-21-300962399-1684673814-2484441606-1104",
            SecurityIdentifier.Format(Administrator));
    }

    [Fact]
    public void The_well_known_local_system_sid_survives_the_round_trip()
    {
        // S-1-5-18. One sub-authority, and the shortest thing that is still a
        // SID - which is where an off-by-one in the length check would show.
        byte[] localSystem = [0x01, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x05, 0x12, 0x00, 0x00, 0x00];

        Assert.Equal("S-1-5-18", SecurityIdentifier.Format(localSystem));
    }

    [Fact]
    public void A_truncated_sid_is_refused_rather_than_shortened()
    {
        // Dropping the last sub-authority would otherwise format as the domain
        // rather than the person: S-1-5-21-…-2484441606 instead of …-1104.
        // That is a valid-looking SID belonging to somebody else.
        var truncated = Administrator[..^4];

        Assert.Null(SecurityIdentifier.Format(truncated));
    }

    [Theory]
    [InlineData(new byte[0])]
    [InlineData(new byte[] { 0x01, 0x05 })]
    [InlineData(new byte[] { 0x02, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x05, 0x12, 0x00, 0x00, 0x00 })]
    public void Anything_that_is_not_a_sid_is_null_rather_than_a_plausible_lie(byte[] bytes)
    {
        Assert.Null(SecurityIdentifier.Format(bytes));
    }

    [Theory]
    [InlineData("S-1-5-21-300962399-1684673814-2484441606-1104")]
    [InlineData("S-1-5-18")]
    [InlineData("s-1-5-18")]
    public void What_a_directory_prints_is_accepted(string sid)
    {
        Assert.True(SecurityIdentifier.LooksValid(sid));
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("   ")]
    [InlineData("S-1-5")]                      // no sub-authority
    [InlineData("S-2-5-18")]                   // revision that does not exist
    [InlineData("X-1-5-18")]                   // not a SID at all
    [InlineData("S-1-5-21-abc-1104")]          // a word where a number goes
    [InlineData("S-1-5-21--1104")]             // negative, which is not a thing
    public void What_somebody_typed_by_hand_is_caught_at_the_boundary(string? sid)
    {
        // The boundary is where this has to fail. Stored, it fails at a logon
        // weeks later and the message is about trust rather than about a field
        // somebody mistyped.
        Assert.False(SecurityIdentifier.LooksValid(sid));
    }
}
