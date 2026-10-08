using System.Security.Cryptography;

namespace Blinky.Fido;

/// <summary>Provisional FIDO2 PINs.</summary>
public static class Fido2Pin
{
    /// <summary>
    /// What a key with PIN complexity enforcement refuses: fewer than four distinct
    /// digits, or a straight run up or down like 123456. Refusing them here costs
    /// nothing; letting the key refuse them costs a round trip and, on a key that
    /// counts the attempt, a retry.
    /// </summary>
    public static bool IsTrivial(string pin)
    {
        if (pin.Distinct().Count() < Math.Min(4, pin.Length))
        {
            return true;
        }

        var steps = pin.Zip(pin.Skip(1), (a, b) => ((b - a) % 10 + 10) % 10).Distinct().ToList();

        return steps is [1] or [9];
    }

    /// <summary>Digits from a CSPRNG, never starting with 0 and never trivial.</summary>
    /// <remarks>
    /// No leading zero: KeyEnroll's reason was spreadsheets, Blinky's is a person
    /// reading it off a screen and typing it into a phone that drops it.
    /// </remarks>
    public static string Generate(int length)
    {
        if (length is < 4 or > 63)
        {
            throw new ArgumentOutOfRangeException(nameof(length), "CTAP allows 4 to 63.");
        }

        while (true)
        {
            var digits = new char[length];
            digits[0] = (char)('1' + RandomNumberGenerator.GetInt32(9));

            for (var i = 1; i < length; i++)
            {
                digits[i] = (char)('0' + RandomNumberGenerator.GetInt32(10));
            }

            var pin = new string(digits);

            if (!IsTrivial(pin))
            {
                return pin;
            }
        }
    }
}
