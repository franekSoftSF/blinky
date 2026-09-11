using System.Globalization;
using System.Security.Cryptography;

namespace Blinky.Api.Security;

/// <summary>
/// Password verification for console accounts.
/// </summary>
/// <remarks>
/// PBKDF2-HMAC-SHA256 out of .NET rather than Argon2id out of a package. Argon2
/// is the better function and this is the house rule from
/// docs/STATUS.md winning anyway: less third-party cryptography in the path
/// that matters. PBKDF2 with a high count is accepted by every guideline that
/// names a number, and the format below carries its own cost so raising it
/// later is a configuration change rather than a migration.
/// <para>
/// This is not the PIN rule bending. A PIN is never stored in any form because
/// it authenticates a person to a card that counts its own attempts; a password
/// authenticates a person to this server, and a server that cannot check a
/// password cannot offer password sign-in at all.
/// </para>
/// </remarks>
public static class PasswordHash
{
    /// <summary>
    /// Iterations for a hash written today. Raising it does not invalidate
    /// anything already stored - see <see cref="NeedsRehash"/>.
    /// </summary>
    public const int DefaultIterations = 210_000;

    private const int SaltBytes = 16;
    private const int HashBytes = 32;
    private const string Prefix = "pbkdf2-sha256";

    /// <summary>
    /// <c>pbkdf2-sha256$iterations$salt$hash</c>, both parts base64.
    /// </summary>
    public static string Create(string password, int iterations = DefaultIterations)
    {
        ArgumentException.ThrowIfNullOrEmpty(password);

        if (iterations < 1)
        {
            throw new ArgumentOutOfRangeException(nameof(iterations),
                "A hash with no work in it is a hash in name only.");
        }

        var salt = RandomNumberGenerator.GetBytes(SaltBytes);
        var hash = Derive(password, salt, iterations);

        return string.Create(CultureInfo.InvariantCulture,
            $"{Prefix}${iterations}${Convert.ToBase64String(salt)}${Convert.ToBase64String(hash)}");
    }

    /// <summary>
    /// Constant time in the comparison, and false rather than an exception for
    /// anything malformed.
    /// </summary>
    /// <remarks>
    /// A stored value that does not parse is a refusal, not a crash: the row
    /// may have been written by a version that is gone, and an account nobody
    /// can sign into is a better outcome than an endpoint that throws on a
    /// field an attacker cannot see anyway.
    /// </remarks>
    public static bool Verify(string password, string stored)
    {
        if (string.IsNullOrEmpty(password) || string.IsNullOrEmpty(stored))
        {
            return false;
        }

        var parts = stored.Split('$');

        if (parts.Length != 4
            || !string.Equals(parts[0], Prefix, StringComparison.Ordinal)
            || !int.TryParse(parts[1], NumberStyles.None, CultureInfo.InvariantCulture,
                out var iterations)
            || iterations < 1)
        {
            return false;
        }

        byte[] salt;
        byte[] expected;

        try
        {
            salt = Convert.FromBase64String(parts[2]);
            expected = Convert.FromBase64String(parts[3]);
        }
        catch (FormatException)
        {
            return false;
        }

        if (salt.Length == 0 || expected.Length == 0)
        {
            return false;
        }

        var actual = Rfc2898DeriveBytes.Pbkdf2(password, salt, iterations,
            HashAlgorithmName.SHA256, expected.Length);

        return CryptographicOperations.FixedTimeEquals(actual, expected);
    }

    /// <summary>
    /// True when a stored hash was made with less work than we now do.
    /// </summary>
    /// <remarks>
    /// Checked after a successful sign-in, which is the only moment the plain
    /// password exists to re-hash with. A deployment that raises the cost then
    /// upgrades accounts as their owners appear, rather than locking out
    /// everybody who has not been seen recently.
    /// </remarks>
    public static bool NeedsRehash(string stored, int iterations = DefaultIterations)
    {
        var parts = stored.Split('$');

        return parts.Length != 4
               || !string.Equals(parts[0], Prefix, StringComparison.Ordinal)
               || !int.TryParse(parts[1], NumberStyles.None, CultureInfo.InvariantCulture,
                   out var stored_iterations)
               || stored_iterations < iterations;
    }

    private static byte[] Derive(string password, byte[] salt, int iterations) =>
        Rfc2898DeriveBytes.Pbkdf2(password, salt, iterations, HashAlgorithmName.SHA256, HashBytes);
}
