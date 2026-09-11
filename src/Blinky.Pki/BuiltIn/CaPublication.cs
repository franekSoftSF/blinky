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
    /// Where an OCSP responder answers for this CA. Empty unless a deployment
    /// names one.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Not derived from the base address, and not a positional member, because
    /// there is no responder in this stack yet - that is 0041a, and it is not
    /// written. What is here is the half that cannot wait for it: authority
    /// information access is fixed when the certificate is issued, so a card
    /// personalised before this URL exists is never checked over OCSP, and the
    /// only correction is to issue again and take the card back off the person
    /// holding it. Deciding the address now costs a setting; deciding it later
    /// costs a visit to every holder.
    /// </para>
    /// <para>
    /// Empty by default for the same reason the base address is optional. An
    /// address in the extension that nothing answers turns a check a relying
    /// party would have skipped into one that waits and then fails, and
    /// validators disagree about whether to fall back to the CRL. Set this in
    /// the change that starts the responder, not before.
    /// </para>
    /// </remarks>
    public IReadOnlyList<string> OcspUrls { get; init; } = [];

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
    public static CaPublication? FromBaseUrl(string? baseUrl, string? ocspUrl = null)
    {
        if (string.IsNullOrWhiteSpace(baseUrl))
        {
            return null;
        }

        var root = baseUrl.TrimEnd('/');

        return new CaPublication(
            [$"{root}/pki/issuing.crl"],
            [$"{root}/pki/issuing.crt"])
        {
            // Given whole rather than assembled from the base address. A
            // responder is allowed to be somewhere else entirely - a different
            // host, a different port, a service somebody else runs - and a
            // deployment that has one usually does put it there.
            OcspUrls = string.IsNullOrWhiteSpace(ocspUrl)
                ? []
                : [ocspUrl.TrimEnd('/')],
        };
    }
}
