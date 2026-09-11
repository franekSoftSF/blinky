using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace Blinky.AdcsConnector;

/// <summary>
/// Who may ask this connector for a certificate.
/// </summary>
/// <remarks>
/// <para>
/// A list of SHA-256 fingerprints, and nothing else. Not an issuer, not a
/// subject name, not a chain: the caller is one API, it stays one API, and
/// trusting an issuer instead would mean that every certificate that issuer
/// ever signs can ask this connector to enrol on a stranger's behalf. A
/// fingerprint cannot be widened by somebody else's decision.
/// </para>
/// <para>
/// SHA-256 rather than <see cref="X509Certificate2.Thumbprint"/>, which is
/// SHA-1. The property is convenient and is the reason SHA-1 fingerprints are
/// still pasted into configuration files in 2026; a fingerprint is a security
/// decision written down, and this one is written down in a hash that is not
/// collision-broken.
/// </para>
/// </remarks>
public sealed class ClientCertificateGate
{
    private readonly HashSet<string> allowed;

    public ClientCertificateGate(IEnumerable<string> fingerprints) =>
        allowed = [.. fingerprints.Select(Normalise).Where(value => value.Length > 0)];

    /// <summary>
    /// True when nothing was configured. Refused at startup rather than here:
    /// an empty list is not "allow everybody", and a connector that starts with
    /// one would be a DCOM bridge to a Microsoft CA listening on a network port
    /// for anybody who asks.
    /// </summary>
    public bool IsEmpty => allowed.Count == 0;

    public int Count => allowed.Count;

    /// <summary>Upper case hex, separators and whitespace removed.</summary>
    /// <remarks>
    /// Because a fingerprint reaches configuration by being copied out of
    /// something - certutil prints it in lower case with spaces, the Windows
    /// certificate dialog puts spaces between the bytes, and openssl uses
    /// colons. Refusing those would be refusing every way anybody actually has
    /// of obtaining the value.
    /// </remarks>
    public static string Normalise(string? fingerprint)
    {
        if (fingerprint is null)
        {
            return string.Empty;
        }

        return string.Concat(fingerprint.Where(char.IsAsciiHexDigit)).ToUpperInvariant();
    }

    public static string FingerprintOf(X509Certificate2 certificate) =>
        certificate.GetCertHashString(HashAlgorithmName.SHA256);

    /// <summary>
    /// Whether this caller is one of the allowed ones, and when not, why.
    /// </summary>
    /// <remarks>
    /// Validity is checked here and not left to the TLS handshake. The
    /// handshake was told to accept any certificate on purpose - see
    /// <c>Program</c> - so nothing else is looking at the dates, and an expired
    /// client certificate whose fingerprint is still in the list would
    /// otherwise keep working indefinitely.
    /// </remarks>
    public bool Allows(X509Certificate2? certificate, TimeProvider clock, out string reason)
    {
        if (certificate is null)
        {
            reason = "No client certificate was presented.";

            return false;
        }

        var now = clock.GetUtcNow();

        if (now < certificate.NotBefore.ToUniversalTime()
            || now > certificate.NotAfter.ToUniversalTime())
        {
            reason = "The client certificate is outside its validity period.";

            return false;
        }

        if (!allowed.Contains(FingerprintOf(certificate)))
        {
            reason = "The client certificate is not one this connector was told to accept.";

            return false;
        }

        reason = string.Empty;

        return true;
    }
}
