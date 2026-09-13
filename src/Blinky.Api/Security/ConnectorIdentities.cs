using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace Blinky.Api.Security;

/// <summary>
/// Which client certificates are ADCS connectors, and the rule that keeps the two
/// kinds of machine certificate apart.
/// </summary>
/// <remarks>
/// <para>
/// A connector's certificate chains to the same agent CA as every workstation's,
/// because that is the anchor the edge verifies on 9443. So the chain says "a
/// machine this deployment issued to" and nothing more, and a fingerprint list is
/// what says "the one that holds the enrolment agent's calls". Trusting the chain
/// alone would let any enrolled workstation collect PKIData to be signed and CMCs
/// to be submitted.
/// </para>
/// <para>
/// It cuts the other way too: a connector's certificate is not an agent, has no
/// row, and is refused on every agent route by the lookup that already refuses
/// strangers.
/// </para>
/// </remarks>
public sealed class ConnectorIdentities(IReadOnlySet<string> fingerprints)
{
    public static ConnectorIdentities None { get; } = new(new HashSet<string>());

    public bool Any => fingerprints.Count > 0;

    public static bool IsConnectorRoute(PathString path) =>
        path.StartsWithSegments("/api/adcs/connector", StringComparison.OrdinalIgnoreCase);

    public bool Accepts(X509Certificate2 certificate, out string fingerprint)
    {
        fingerprint = certificate.GetCertHashString(HashAlgorithmName.SHA256);

        return fingerprints.Contains(fingerprint);
    }
}
