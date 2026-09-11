using System.Security.Cryptography;
using System.Text;

namespace Blinky.Api.Security;

/// <summary>
/// The token a signed-in console holds, and the fingerprint the database keeps.
/// </summary>
/// <remarks>
/// Split out so the rule is in one place: the value goes to the client exactly
/// once, and what is stored can identify a session without being able to
/// become one.
/// </remarks>
public static class SessionTokens
{
    /// <summary>
    /// Thirty-two bytes, base64url, no padding.
    /// </summary>
    /// <remarks>
    /// url-safe because this travels in headers and, during development, in
    /// places that mangle <c>+</c> and <c>/</c>. Unpadded because a trailing
    /// <c>=</c> survives exactly as far as the first thing that trims it.
    /// </remarks>
    public static string New() =>
        Base64Url(RandomNumberGenerator.GetBytes(32));

    /// <summary>Lower-case hex of SHA-256. What the row holds.</summary>
    public static string Fingerprint(string token) =>
        Convert.ToHexStringLower(SHA256.HashData(Encoding.UTF8.GetBytes(token)));

    private static string Base64Url(byte[] data) =>
        Convert.ToBase64String(data)
            .Replace('+', '-')
            .Replace('/', '_')
            .TrimEnd('=');
}
