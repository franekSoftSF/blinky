using System.Text;
using Blinky.Contracts;

namespace Blinky.UnitTests;

/// <summary>
/// The codes that travel down a telephone, and the rotation both ends work out
/// without talking to each other.
/// </summary>
public sealed class OfflineUnblockTests
{
    [Fact]
    public void A_challenge_survives_the_round_trip()
    {
        var nonce = new byte[] { 1, 2, 3, 4, 5 };

        var challenge = OfflineUnblock.Challenge(29177301, nonce);
        var read = OfflineUnblock.ReadChallenge(challenge);

        Assert.NotNull(read);
        Assert.Equal(29177301, read.Value.Serial);
        Assert.Equal(nonce, read.Value.Nonce);
    }

    [Fact]
    public void A_response_survives_the_round_trip() =>
        Assert.Equal("48210937", OfflineUnblock.ReadResponse(OfflineUnblock.Response("48210937")));

    [Fact]
    public void A_code_is_grouped_and_typed_back_in_any_shape()
    {
        var code = OfflineUnblock.Response("48210937");

        Assert.Contains("-", code, StringComparison.Ordinal);

        // However somebody types it back: without the dashes, in lower case,
        // with stray spaces from reading it off a note.
        Assert.Equal("48210937", OfflineUnblock.ReadResponse(code.Replace("-", "",
            StringComparison.Ordinal)));
        Assert.Equal("48210937", OfflineUnblock.ReadResponse(code.ToLowerInvariant()));
        Assert.Equal("48210937", OfflineUnblock.ReadResponse(" " + code + " "));
    }

    [Fact]
    public void A_single_wrong_character_is_refused_rather_than_decoded()
    {
        // The entire reason these are not eight bare digits. A mistyped code
        // that reaches the card spends one of three PUK attempts.
        var code = OfflineUnblock.Response("48210937");

        var typo = new StringBuilder(code.Replace("-", "", StringComparison.Ordinal));
        typo[0] = typo[0] == '7' ? '9' : '7';

        Assert.Null(OfflineUnblock.ReadResponse(typo.ToString()));
    }

    [Fact]
    public void Two_characters_swapped_are_refused()
    {
        // The second most common transcription error, and the one an unweighted
        // checksum would wave through.
        var code = OfflineUnblock.Response("48210937")
            .Replace("-", string.Empty, StringComparison.Ordinal);

        var swapped = new StringBuilder(code);
        (swapped[1], swapped[2]) = (swapped[2], swapped[1]);

        if (code[1] != code[2])
        {
            Assert.Null(OfflineUnblock.ReadResponse(swapped.ToString()));
        }
    }

    [Theory]
    [InlineData('I', '1')]
    [InlineData('l', '1')]
    [InlineData('O', '0')]
    public void Letters_people_hear_as_digits_are_folded(char typed, char meant)
    {
        // Crockford's alphabet has no I, L, O or U precisely so these can be
        // folded rather than rejected: somebody will type what they think they
        // heard.
        var code = OfflineUnblock.Response("11001100")
            .Replace("-", string.Empty, StringComparison.Ordinal);

        if (!code.Contains(meant, StringComparison.Ordinal))
        {
            return;
        }

        var confused = code.Replace(meant, typed);

        Assert.Equal(OfflineUnblock.ReadResponse(code), OfflineUnblock.ReadResponse(confused));
    }

    [Fact]
    public void Nonsense_is_refused_rather_than_throwing()
    {
        // Reached from a text box on a telephone call.
        Assert.Null(OfflineUnblock.ReadResponse(null));
        Assert.Null(OfflineUnblock.ReadResponse(string.Empty));
        Assert.Null(OfflineUnblock.ReadResponse("hello there"));
        Assert.Null(OfflineUnblock.ReadChallenge("!!!!"));
        Assert.Null(OfflineUnblock.ReadChallenge("ABC"));
    }

    [Fact]
    public void Both_sides_derive_the_same_replacement()
    {
        // The whole point: no network between them, and no need for one.
        var challenge = OfflineUnblock.Challenge(29177301, [9, 8, 7, 6, 5]);

        var server = PukDerivation.Next("12345678", challenge);
        var agent = PukDerivation.Next("12345678", challenge);

        Assert.Equal(server, agent);
        Assert.Equal(8, server.Length);
        Assert.True(server.All(char.IsAsciiDigit));
    }

    [Fact]
    public void The_replacement_survives_the_shape_a_person_typed_the_challenge_in()
    {
        var challenge = OfflineUnblock.Challenge(29177301, [9, 8, 7, 6, 5]);

        Assert.Equal(
            PukDerivation.Next("12345678", challenge),
            PukDerivation.Next("12345678",
                challenge.Replace("-", string.Empty, StringComparison.Ordinal).ToLowerInvariant()));
    }

    [Fact]
    public void A_different_challenge_derives_a_different_replacement()
    {
        // Otherwise one overheard code would unblock the same token for ever.
        var first = OfflineUnblock.Challenge(29177301, [1, 1, 1, 1, 1]);
        var second = OfflineUnblock.Challenge(29177301, [2, 2, 2, 2, 2]);

        Assert.NotEqual(PukDerivation.Next("12345678", first),
            PukDerivation.Next("12345678", second));
    }

    [Fact]
    public void A_different_puk_derives_a_different_replacement() =>
        Assert.NotEqual(
            PukDerivation.Next("12345678", "ABCD-EFGH"),
            PukDerivation.Next("87654321", "ABCD-EFGH"));
}
