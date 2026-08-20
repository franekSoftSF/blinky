using Blinky.Contracts;

namespace Blinky.UnitTests;

/// <summary>
/// The rules a new PIN has to satisfy, which run in two places and must agree
/// in both: the window explains them while somebody types, the service applies
/// them before anything reaches the card.
/// </summary>
public sealed class PinRulesTests
{
    private static readonly PinComplexityPolicy Policy = PinComplexityPolicy.Default;

    [Theory]
    [InlineData("284917")]
    [InlineData("40718")]
    [InlineData("90462813")]
    public void An_ordinary_pin_is_accepted(string pin)
    {
        // Five characters is short for a PIN and still legal PIV; the policy
        // decides the minimum, and the default is six.
        var expected = pin.Length >= Policy.MinimumLength;

        Assert.Equal(expected, PinRules.Check(pin, Policy).IsAcceptable);
    }

    [Fact]
    public void The_factory_pin_is_refused_by_name()
    {
        // The most common PIN on any fleet that has not been personalised, and
        // it also happens to be a run - the more specific reason must win, so
        // the message says what is actually wrong.
        Assert.Equal(PinRefusal.FactoryDefault,
            PinRules.Check(PinComplexityPolicy.FactoryPin, Policy).Refusal);
    }

    [Theory]
    [InlineData("111111")]
    [InlineData("00000000")]
    public void A_single_repeated_digit_is_refused(string pin) =>
        Assert.Equal(PinRefusal.RepeatedDigit, PinRules.Check(pin, Policy).Refusal);

    [Theory]
    [InlineData("234567")]
    [InlineData("654321")]
    [InlineData("98765432")]
    public void A_straight_run_is_refused_in_either_direction(string pin) =>
        Assert.Equal(PinRefusal.Sequence, PinRules.Check(pin, Policy).Refusal);

    [Theory]
    [InlineData("135791")]
    [InlineData("246813")]
    public void A_pattern_that_is_not_a_run_of_one_is_allowed(string pin) =>
        Assert.True(PinRules.Check(pin, Policy).IsAcceptable);

    [Fact]
    public void A_pin_equal_to_the_puk_is_refused_when_the_puk_is_in_hand()
    {
        // Only checkable during an unblock, which is the one flow where the
        // PUK is present. Allowing it would mean unblocking restores the PIN
        // that was just rejected.
        Assert.Equal(PinRefusal.SameAsPuk,
            PinRules.Check("284917", Policy, puk: "284917").Refusal);

        Assert.True(PinRules.Check("284917", Policy).IsAcceptable);
    }

    [Fact]
    public void Part_of_the_serial_printed_on_the_token_is_refused()
    {
        // The number is on the outside of the object the PIN protects.
        Assert.Equal(PinRefusal.TokenSerial,
            PinRules.Check("291773", Policy, tokenSerial: 29177301).Refusal);
    }

    [Theory]
    [InlineData("12345")]
    [InlineData("")]
    public void Too_short_is_reported_as_too_short(string pin) =>
        Assert.Equal(PinRefusal.TooShort, PinRules.Check(pin, Policy).Refusal);

    [Fact]
    public void Nine_characters_is_refused_rather_than_truncated()
    {
        // PIV carries the PIN in eight bytes. Silently taking the first eight
        // would set a PIN nobody typed.
        Assert.Equal(PinRefusal.TooLong, PinRules.Check("123456789", Policy).Refusal);
    }

    [Fact]
    public void Letters_are_refused_by_default_and_allowed_by_policy()
    {
        Assert.Equal(PinRefusal.NotDigits, PinRules.Check("28a917", Policy).Refusal);

        // A card accepts more than digits; software that reads the card later
        // often does not. So it is a deployment choice, not a prohibition.
        Assert.True(PinRules.Check("28a917", Policy with { DigitsOnly = false }).IsAcceptable);
    }

    [Fact]
    public void A_null_pin_is_a_refusal_rather_than_a_crash()
    {
        // Reached from a pipe, where any field can be absent.
        Assert.Equal(PinRefusal.TooShort, PinRules.Check(null, Policy).Refusal);
    }

    [Fact]
    public void Every_refusal_carries_a_sentence_somebody_can_act_on()
    {
        string[] bad = ["", "12345", "123456789", "111111", "234567", "28a917"];

        foreach (var pin in bad)
        {
            var verdict = PinRules.Check(pin, Policy);

            Assert.False(verdict.IsAcceptable);
            Assert.False(string.IsNullOrWhiteSpace(verdict.Explanation));
            Assert.EndsWith(".", verdict.Explanation.Trim(), StringComparison.Ordinal);
        }
    }
}
