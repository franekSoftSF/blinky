namespace Blinky.Contracts;

/// <summary>
/// What counts as an acceptable PIN, as the backend publishes it.
/// </summary>
/// <remarks>
/// <para>
/// The policy travels; the PIN does not. A PIN never leaves the workstation —
/// not to be checked, not to be stored, not ever — so the rule cannot be
/// applied where the rule is kept. The backend sends the rules, the agent
/// applies them, and the backend never learns what it approved.
/// </para>
/// <para>
/// See docs/10-agent-ui.md and docs/06-security.md.
/// </para>
/// </remarks>
public sealed record PinComplexityPolicy(
    int MinimumLength = 6,
    int MaximumLength = 8,
    bool DigitsOnly = true,
    bool ForbidDefault = true,
    bool ForbidRepeatedDigit = true,
    bool ForbidSequence = true,
    bool ForbidTokenSerial = true)
{
    /// <summary>What ships when the backend has said nothing.</summary>
    public static PinComplexityPolicy Default { get; } = new();

    /// <summary>
    /// The PIN every PIV token leaves the factory with, and therefore the most
    /// common PIN on any fleet that has not been personalised.
    /// </summary>
    public const string FactoryPin = "123456";
}

/// <summary>Why a PIN was refused, or that it was not.</summary>
public enum PinRefusal
{
    None,
    TooShort,
    TooLong,
    NotDigits,
    FactoryDefault,
    RepeatedDigit,
    Sequence,
    SameAsPuk,
    TokenSerial,
}

/// <summary>The answer, and a sentence a person can act on.</summary>
public sealed record PinVerdict(PinRefusal Refusal, string Explanation)
{
    public bool IsAcceptable => Refusal == PinRefusal.None;

    public static PinVerdict Acceptable { get; } = new(PinRefusal.None, "This PIN is acceptable.");
}

/// <summary>
/// Applies a <see cref="PinComplexityPolicy"/>. Used by the window while somebody types
/// and by the service before anything reaches the card.
/// </summary>
/// <remarks>
/// <para>
/// In both places on purpose. The window is where the rule gets explained; the
/// service is where it gets enforced. A rule checked only in the window is a
/// rule that the next window does not have.
/// </para>
/// <para>
/// These rules catch a PIN that is obviously bad. They cannot catch a birthday,
/// a name, or a PIN reused from somewhere else, and a screen listing them
/// invites the belief that anything passing them is a good PIN. It is a PIN
/// that is not obviously bad, and the wording says so.
/// </para>
/// </remarks>
public static class PinRules
{
    /// <param name="puk">
    /// Supplied only where it is already in hand — an unblock. A PIN equal to
    /// the PUK means unblocking restores the value that was just rejected.
    /// </param>
    public static PinVerdict Check(string? pin, PinComplexityPolicy policy, long? tokenSerial = null,
        string? puk = null)
    {
        pin ??= string.Empty;

        if (pin.Length < policy.MinimumLength)
        {
            return new PinVerdict(PinRefusal.TooShort,
                $"A PIN needs at least {policy.MinimumLength} characters.");
        }

        if (pin.Length > policy.MaximumLength)
        {
            // Not a policy choice: PIV carries the PIN in eight bytes.
            return new PinVerdict(PinRefusal.TooLong,
                $"A PIN cannot be longer than {policy.MaximumLength} characters.");
        }

        if (policy.DigitsOnly && !pin.All(char.IsAsciiDigit))
        {
            return new PinVerdict(PinRefusal.NotDigits,
                "Digits only. A card accepts more, but software that reads the card later "
                + "often does not.");
        }

        if (policy.ForbidDefault && pin == PinComplexityPolicy.FactoryPin)
        {
            return new PinVerdict(PinRefusal.FactoryDefault,
                "That is the PIN the token left the factory with.");
        }

        if (policy.ForbidRepeatedDigit && pin.Distinct().Count() == 1)
        {
            return new PinVerdict(PinRefusal.RepeatedDigit,
                "Every character is the same one.");
        }

        if (policy.ForbidSequence && IsRun(pin))
        {
            return new PinVerdict(PinRefusal.Sequence,
                "That is a straight run of digits.");
        }

        if (puk is not null && pin == puk)
        {
            return new PinVerdict(PinRefusal.SameAsPuk,
                "The PIN and the PUK cannot match: unblocking would restore the PIN that was "
                + "just rejected.");
        }

        if (policy.ForbidTokenSerial && tokenSerial is { } serial
            && serial.ToString(System.Globalization.CultureInfo.InvariantCulture).Contains(pin,
                StringComparison.Ordinal))
        {
            // The serial is printed on the object the PIN protects.
            return new PinVerdict(PinRefusal.TokenSerial,
                "That is part of the serial number printed on the token.");
        }

        return PinVerdict.Acceptable;
    }

    /// <summary>Ascending or descending by one, in either direction.</summary>
    private static bool IsRun(string pin)
    {
        if (pin.Length < 2 || !pin.All(char.IsAsciiDigit))
        {
            return false;
        }

        var step = pin[1] - pin[0];
        if (step is not (1 or -1))
        {
            return false;
        }

        for (var i = 2; i < pin.Length; i++)
        {
            if (pin[i] - pin[i - 1] != step)
            {
                return false;
            }
        }

        return true;
    }
}
