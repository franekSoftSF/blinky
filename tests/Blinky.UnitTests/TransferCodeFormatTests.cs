using Blinky.Contracts;

namespace Blinky.UnitTests;

/// <summary>
/// Laying out a transfer code the way it is read aloud.
/// </summary>
/// <remarks>
/// The field an operator types an offline unblock code into formats as they
/// type. Typing the separators by hand works - the decoder discards
/// punctuation - but a field that looks like it wants them invites somebody to
/// supply them, and every character typed is one that can go in wrong. This is
/// a code being read from one screen to another, out loud.
/// </remarks>
public class TransferCodeFormatTests
{
    [Fact]
    public void It_groups_in_fours()
    {
        Assert.Equal("64V3-8D9Q-68WK-J0", TransferCode.Format("64V38D9Q68WKJ0"));
    }

    /// <summary>Separators somebody typed are not doubled.</summary>
    [Fact]
    public void Punctuation_already_there_is_not_repeated()
    {
        Assert.Equal("64V3-8D9Q-68WK-J0", TransferCode.Format("64V3-8D9Q-68WK-J0"));
        Assert.Equal("64V3-8D9Q-68WK-J0", TransferCode.Format("64V3 8D9Q 68WK J0"));
    }

    /// <summary>
    /// The characters people confuse reading aloud are resolved here exactly as
    /// the decoder resolves them.
    /// </summary>
    /// <remarks>
    /// This matters more than it looks. A field that shows something the
    /// decoder would read differently is worse than a field that shows
    /// nothing: the operator sees what they believe they typed, and the
    /// failure arrives later with no clue which character went wrong.
    /// </remarks>
    [Theory]
    [InlineData("IL0O", "1100")]
    [InlineData("iloO", "1100")]
    public void Confusable_characters_resolve_the_same_way_as_the_decoder(
        string typed, string expected)
    {
        Assert.Equal(expected, TransferCode.Normalise(typed));

        // And the decoder agrees, which is the property that has to hold.
        Assert.Equal(TransferCode.Normalise(typed), TransferCode.Normalise(expected));
    }

    [Fact]
    public void Nothing_typed_is_nothing_shown()
    {
        Assert.Equal(string.Empty, TransferCode.Format(null));
        Assert.Equal(string.Empty, TransferCode.Format(""));
        Assert.Equal(string.Empty, TransferCode.Format("---"));
    }

    /// <summary>A partial code formats as far as it goes.</summary>
    /// <remarks>
    /// The field reformats on every keystroke, so most of what this sees is
    /// half a code.
    /// </remarks>
    [Theory]
    [InlineData("6", "6")]
    [InlineData("64V", "64V")]
    [InlineData("64V3", "64V3")]
    [InlineData("64V38", "64V3-8")]
    public void A_half_typed_code_is_laid_out_as_far_as_it_goes(string typed, string expected)
    {
        Assert.Equal(expected, TransferCode.Format(typed));
    }

    /// <summary>What is shown decodes to what was meant.</summary>
    [Fact]
    public void Formatting_does_not_change_what_the_code_decodes_to()
    {
        var bytes = new byte[] { 0x01, 0x23, 0x45, 0x67, 0x89 };
        var code = TransferCode.Encode(bytes);

        Assert.Equal(bytes, TransferCode.Decode(TransferCode.Format(code)));
    }
}
