namespace Blinky.Pki.BuiltIn;

/// <summary>
/// Where a relying party is told to look: the CRL, and the CA that signed the
/// certificate it is holding.
/// </summary>
/// <remarks>
/// <para>
/// These become the CRL distribution point and the authority information
/// access extension on everything the CA issues. They are addresses rather
/// than files: whoever validates the certificate is not this machine, and
/// usually is not on this network at the moment they need them.
/// </para>
/// <para>
/// <b>HTTP, not HTTPS.</b> A relying party that has to validate a certificate
/// in order to fetch the thing that tells it whether the certificate is valid
/// has a problem it cannot get out of. Every public CA publishes revocation
/// over plain HTTP for this reason, and the CRL is signed, so the transport
/// is not what protects it.
/// </para>
/// <para>
/// LDAP is deliberately not offered. It works, ADCS uses it, and it only works
/// for a client that is already in the domain — which excludes the Linux
/// clients this project has to serve and any machine being enrolled before it
/// joins.
/// </para>
/// </remarks>
/// <param name="CrlUrls">
/// Where the current CRL is published. More than one is allowed and they are
/// tried in order.
/// </param>
/// <param name="CaIssuerUrls">
/// Where the issuing CA certificate is published, in DER.
/// </param>
public sealed record CaPublication(
    IReadOnlyList<string> CrlUrls,
    IReadOnlyList<string> CaIssuerUrls)
{
    /// <summary>
    /// Builds the pair from one base address, using the paths this project
    /// serves them at.
    /// </summary>
    /// <remarks>
    /// A convenience, and the shape a deployment usually wants: one host name
    /// to get right rather than two URLs to keep in step. Anything more
    /// elaborate — a CDN, a second distribution point — constructs the record
    /// directly.
    /// </remarks>
    public static CaPublication? FromBaseUrl(string? baseUrl)
    {
        if (string.IsNullOrWhiteSpace(baseUrl))
        {
            return null;
        }

        var root = baseUrl.TrimEnd('/');

        return new CaPublication(
            [$"{root}/pki/issuing.crl"],
            [$"{root}/pki/issuing.crt"]);
    }
}
