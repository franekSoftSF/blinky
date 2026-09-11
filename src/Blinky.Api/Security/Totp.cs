using System.Globalization;
using System.Security.Cryptography;
using System.Text;

namespace Blinky.Api.Security;

/// <summary>
/// Time-based one-time passwords, RFC 6238.
/// </summary>
/// <remarks>
/// Written here rather than taken from a package, for the same reason the
/// password hash is: this is forty lines of HMAC and a counter, and the test
/// vectors in RFC 6238 appendix B say whether it is right. A dependency would
/// have to be trusted; this can be checked.
/// <para>
/// HMAC-SHA1 is the default and is not a mistake. It is what every
/// authenticator application actually implements, and the construction does
/// not depend on SHA-1's collision resistance. A deployment that wants SHA-256
/// can have it, and will find that half the telephones on the desk cannot.
/// </para>
/// </remarks>
public static class Totp
{
    public const int DefaultDigits = 6;
    public const int DefaultPeriodSeconds = 30;

    private const string Base32Alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

    /// <summary>
    /// A fresh shared secret, base32, twenty bytes of randomness.
    /// </summary>
    /// <remarks>
    /// Twenty because that is what HMAC-SHA1's block handling wants and what
    /// every authenticator expects; longer buys nothing here.
    /// </remarks>
    public static string NewSecret() => ToBase32(RandomNumberGenerator.GetBytes(20));

    /// <summary>
    /// The code for one counter step. <paramref name="digits"/> is a parameter
    /// so the RFC's own eight-digit vectors can be run against this.
    /// </summary>
    public static string Compute(byte[] key, long counter, int digits = DefaultDigits,
        HashAlgorithmName? algorithm = null)
    {
        ArgumentNullException.ThrowIfNull(key);

        if (digits is < 6 or > 8)
        {
            throw new ArgumentOutOfRangeException(nameof(digits),
                "RFC 6238 defines six to eight digits.");
        }

        Span<byte> message = stackalloc byte[8];

        for (var i = 7; i >= 0; i--)
        {
            message[i] = (byte)(counter & 0xFF);
            counter >>= 8;
        }

        Span<byte> mac = stackalloc byte[64];
        var name = algorithm ?? HashAlgorithmName.SHA1;

        var written = name == HashAlgorithmName.SHA256
            ? HMACSHA256.HashData(key, message, mac)
            : name == HashAlgorithmName.SHA512
                ? HMACSHA512.HashData(key, message, mac)
                : HMACSHA1.HashData(key, message, mac);

        // Dynamic truncation, RFC 4226 section 5.4: the low nibble of the last
        // byte picks where to read, which is what stops the code being a fixed
        // window onto the MAC.
        var offset = mac[written - 1] & 0x0F;

        var binary = ((mac[offset] & 0x7F) << 24)
                     | ((mac[offset + 1] & 0xFF) << 16)
                     | ((mac[offset + 2] & 0xFF) << 8)
                     | (mac[offset + 3] & 0xFF);

        var modulus = (int)Math.Pow(10, digits);

        return (binary % modulus).ToString(CultureInfo.InvariantCulture).PadLeft(digits, '0');
    }

    /// <summary>The counter step a moment falls in.</summary>
    public static long CounterAt(DateTimeOffset moment, int periodSeconds = DefaultPeriodSeconds) =>
        moment.ToUnixTimeSeconds() / periodSeconds;

    /// <summary>
    /// Whether a code is valid at a moment, allowing for clock drift.
    /// </summary>
    /// <remarks>
    /// <paramref name="driftSteps"/> is stated rather than generous. Each step
    /// either side widens the window a code is accepted in by thirty seconds in
    /// both directions, so one step means a code lives for a minute and a half.
    /// Two is already three and a half minutes of an attacker's guesses being
    /// worth more than they should be.
    /// <para>
    /// This does not stop a code being used twice: that needs a record of what
    /// has been spent, which is 0087. Anything relying on single use before
    /// then is relying on something that is not here.
    /// </para>
    /// </remarks>
    public static bool Verify(string secret, string code, DateTimeOffset moment,
        int driftSteps = 1, int digits = DefaultDigits,
        int periodSeconds = DefaultPeriodSeconds)
    {
        if (string.IsNullOrWhiteSpace(secret) || string.IsNullOrWhiteSpace(code))
        {
            return false;
        }

        var presented = code.Trim().Replace(" ", string.Empty, StringComparison.Ordinal);

        if (presented.Length != digits || !presented.All(char.IsAsciiDigit))
        {
            return false;
        }

        byte[] key;

        try
        {
            key = FromBase32(secret);
        }
        catch (FormatException)
        {
            return false;
        }

        var counter = CounterAt(moment, periodSeconds);
        var accepted = false;

        // Every candidate is compared, and the loop does not stop at the first
        // match. A comparison that returns early leaks which step matched
        // through how long the request took.
        for (var step = -driftSteps; step <= driftSteps; step++)
        {
            var candidate = Compute(key, counter + step, digits);

            accepted |= CryptographicOperations.FixedTimeEquals(
                Encoding.ASCII.GetBytes(candidate), Encoding.ASCII.GetBytes(presented));
        }

        CryptographicOperations.ZeroMemory(key);

        return accepted;
    }

    /// <summary>
    /// The <c>otpauth://</c> URI an authenticator reads from a QR code.
    /// </summary>
    /// <remarks>
    /// The issuer appears twice on purpose: once in the label for applications
    /// that only read that, and once as a parameter for the ones that do it
    /// properly. Without it every account in the list says the account name and
    /// nothing about which system it belongs to.
    /// </remarks>
    public static string ProvisioningUri(string issuer, string account, string secret)
    {
        var label = $"{Uri.EscapeDataString(issuer)}:{Uri.EscapeDataString(account)}";

        return $"otpauth://totp/{label}?secret={secret}"
               + $"&issuer={Uri.EscapeDataString(issuer)}"
               + $"&algorithm=SHA1&digits={DefaultDigits}&period={DefaultPeriodSeconds}";
    }

    public static string ToBase32(ReadOnlySpan<byte> data)
    {
        var output = new StringBuilder(((data.Length + 4) / 5) * 8);
        int buffer = 0, bits = 0;

        foreach (var b in data)
        {
            buffer = (buffer << 8) | b;
            bits += 8;

            while (bits >= 5)
            {
                output.Append(Base32Alphabet[(buffer >> (bits - 5)) & 31]);
                bits -= 5;
            }
        }

        if (bits > 0)
        {
            output.Append(Base32Alphabet[(buffer << (5 - bits)) & 31]);
        }

        return output.ToString();
    }

    public static byte[] FromBase32(string text)
    {
        var output = new List<byte>(text.Length * 5 / 8);
        int buffer = 0, bits = 0;

        foreach (var c in text)
        {
            if (c == '=' || char.IsWhiteSpace(c))
            {
                continue;
            }

            var index = Base32Alphabet.IndexOf(char.ToUpperInvariant(c));

            if (index < 0)
            {
                throw new FormatException($"'{c}' is not base32.");
            }

            buffer = (buffer << 5) | index;
            bits += 5;

            if (bits >= 8)
            {
                output.Add((byte)((buffer >> (bits - 8)) & 0xFF));
                bits -= 8;
            }
        }

        return [.. output];
    }
}
