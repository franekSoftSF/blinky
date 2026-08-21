using Blinky.Piv;

namespace Blinky.UnitTests;

/// <summary>
/// The two objects that decide whether Windows can use the card at all.
/// </summary>
/// <remarks>
/// Written against the encodings in SP 800-73-4. The failure they fix was
/// <c>certutil -scinfo</c> on BY-WIN-CLIENT01 building the whole chain from
/// the card, printing the subject and the UPN, and then returning
/// <c>NTE_BAD_KEYSET</c> — a key container that does not exist, for a key that
/// does.
/// </remarks>
public sealed class PivCardObjectsTests
{
    [Fact]
    public void The_chuid_carries_a_fasc_n_a_guid_and_an_expiry()
    {
        var chuid = PivCardObjects.BuildChuid(new DateOnly(2036, 1, 2));

        var tags = TagsIn(chuid);

        Assert.Equal(25, tags[0x30].Length);  // FASC-N, fixed width
        Assert.Equal(16, tags[0x34].Length);  // GUID
        Assert.Equal("20360102", System.Text.Encoding.ASCII.GetString(tags[0x35]));

        // Present and empty, both of them: an issuer signature nothing here
        // produces, and the LRC that PIV defines as always empty.
        Assert.Empty(tags[0x3E]);
        Assert.Empty(tags[0xFE]);
    }

    [Fact]
    public void Every_card_gets_its_own_guid()
    {
        // Windows tells one card from another by this. Two cards sharing a
        // GUID are one card as far as the operating system is concerned, so a
        // derived or fixed value would be a bug that only shows up on the
        // second token.
        var first = TagsIn(PivCardObjects.BuildChuid(new DateOnly(2036, 1, 1)))[0x34];
        var second = TagsIn(PivCardObjects.BuildChuid(new DateOnly(2036, 1, 1)))[0x34];

        Assert.NotEqual(first, second);
    }

    [Fact]
    public void The_capability_container_says_it_is_a_piv_card()
    {
        var ccc = PivCardObjects.BuildCapabilityContainer();

        var tags = TagsIn(ccc);
        var identifier = tags[0xF0];

        Assert.Equal(21, identifier.Length);

        // The GSC-IS issuer identifier that marks this as a PIV card. The
        // fourteen bytes after it are per card.
        Assert.Equal(new byte[] { 0xA0, 0x00, 0x00, 0x01, 0x16, 0xFF, 0x02 },
            identifier[..7]);

        Assert.Equal(new byte[] { 0x21 }, tags[0xF1]); // container version 2.1
        Assert.Equal(new byte[] { 0x21 }, tags[0xF2]); // grammar version 2.1
        Assert.Equal(new byte[] { 0x10 }, tags[0xF5]); // PIV data model
    }

    [Fact]
    public void Every_card_gets_its_own_card_identifier()
    {
        var first = TagsIn(PivCardObjects.BuildCapabilityContainer())[0xF0];
        var second = TagsIn(PivCardObjects.BuildCapabilityContainer())[0xF0];

        Assert.NotEqual(first, second);
    }

    [Theory]
    [InlineData(true, true, "CHUID and CCC")]
    [InlineData(true, false, "CHUID")]
    [InlineData(false, true, "CCC")]
    [InlineData(false, false, "nothing")]
    public void What_was_written_says_so_in_words(bool chuid, bool ccc, string expected)
    {
        var written = new CardIdentityWritten(chuid, ccc);

        Assert.Equal(expected, written.ToString());
        Assert.Equal(chuid || ccc, written.Anything);
    }

    /// <summary>Flat single-byte-tag TLV, which is all either object uses.</summary>
    private static Dictionary<byte, byte[]> TagsIn(byte[] data)
    {
        var tags = new Dictionary<byte, byte[]>();

        for (var i = 0; i < data.Length;)
        {
            var tag = data[i++];
            var length = data[i++];
            tags[tag] = data[i..(i + length)];
            i += length;
        }

        return tags;
    }
}
