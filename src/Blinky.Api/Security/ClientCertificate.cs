using System.Security.Cryptography.X509Certificates;

namespace Blinky.Api.Security;

/// <summary>
/// The client certificate the edge verified, as forwarded to the API.
/// </summary>
/// <remarks>
/// The API never terminates TLS. It trusts these headers only because
/// api:8080 is not published outside the compose network and the edge
/// overwrites whatever a client sent - see docs/01-architecture.md. Publishing
/// the API directly would turn this into a forgeable identity.
/// </remarks>
public static class ClientCertificate
{
    public const string VerifyHeader = "X-Client-Verify";
    public const string CertificateHeader = "X-Client-Cert";

    /// <summary>The verified certificate, or null when there is none.</summary>
    public static X509Certificate2? From(HttpRequest request)
    {
        if (!string.Equals(request.Headers[VerifyHeader], "SUCCESS",
                StringComparison.OrdinalIgnoreCase))
        {
            return null;
        }

        var escaped = request.Headers[CertificateHeader].ToString();
        if (string.IsNullOrEmpty(escaped))
        {
            return null;
        }

        try
        {
            return X509Certificate2.CreateFromPem(Uri.UnescapeDataString(escaped));
        }
        catch
        {
            return null;
        }
    }
}
