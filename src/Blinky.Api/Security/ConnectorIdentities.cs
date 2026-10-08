using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Blinky.Api.Persistence;
using Blinky.Domain.Entities;
using NHibernate.Linq;

namespace Blinky.Api.Security;

/// <summary>
/// Which client certificates are ADCS connectors, and the rule that keeps the two
/// kinds of machine certificate apart.
/// </summary>
/// <remarks>
/// <para>
/// A connector's certificate chains to the same agent CA as every workstation's,
/// because that is the anchor the edge verifies on 9443. So the chain says "a
/// machine this deployment issued to" and nothing more, and the registration is
/// what says "the one that holds the enrolment agent's calls". Trusting the chain
/// alone would let any enrolled workstation collect PKIData to be signed.
/// </para>
/// <para>
/// It cuts the other way too: a connector's certificate is not an agent, has no
/// agent row, and is refused on every agent route by the lookup that already
/// refuses strangers.
/// </para>
/// <para>
/// The list used to be <c>ADCS_CONNECTOR_FINGERPRINT</c> in <c>.env</c>: copied
/// by hand after running a tool, invisible to the console, and impossible to
/// withdraw without editing a file on the server and restarting the API. It is
/// rows now (0102), written by the enrolment that issued the certificate, so
/// nobody types a fingerprint and withdrawing one takes a second.
/// </para>
/// </remarks>
public sealed class ConnectorIdentities(Database database)
{
    public static bool IsConnectorRoute(PathString path) =>
        path.StartsWithSegments("/api/adcs/connector", StringComparison.OrdinalIgnoreCase);

    /// <summary>What a registration is keyed on: SHA-256, upper-case hex.</summary>
    public static string FingerprintOf(X509Certificate2 certificate)
    {
        ArgumentNullException.ThrowIfNull(certificate);

        return certificate.GetCertHashString(HashAlgorithmName.SHA256);
    }

    public bool Accepts(X509Certificate2 certificate, out string fingerprint)
    {
        fingerprint = FingerprintOf(certificate);
        var presented = fingerprint;

        using var session = database.OpenSession();

        // Read on every connector request rather than cached at start: a
        // connector withdrawn from the console has to stop working in the
        // second somebody decides it should, not at the next restart. The
        // connector makes a handful of calls per enrolment, so this is an
        // indexed lookup against a table with one or two rows in it.
        var row = session.Query<ConnectorRegistration>()
            .SingleOrDefault(c => c.Fingerprint == presented);

        return row is { RevokedAt: null };
    }
}
