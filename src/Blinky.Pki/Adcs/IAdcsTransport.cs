using Blinky.Contracts;

namespace Blinky.Pki.Adcs;

/// <summary>
/// How a Microsoft CA is reached. Two implementations, one config value apart.
/// </summary>
/// <remarks>
/// <para>
/// CES/CEP over HTTPS from the container (0031), and the DCOM connector beside
/// the CA (0032). <see cref="AdcsCertificateAuthority"/> is written once against
/// this and knows which is in use only by its <see cref="Description"/> - see
/// docs/04-pki-backends.md and docs/15-adcs-connector.md.
/// </para>
/// <para>
/// The vocabulary is the connector's wire contract from
/// <c>Blinky.Contracts</c> rather than a second set of types. Not laziness: the
/// records describe what a Microsoft CA was asked and what it answered, which is
/// the same question whichever protocol carried it, and a translating layer in
/// between is where the two transports would stop behaving identically.
/// </para>
/// </remarks>
public interface IAdcsTransport
{
    /// <summary>
    /// What this is, for the console and the logs. "connector at
    /// https://ca.example:8444", never a bare "adcs".
    /// </summary>
    string Description { get; }

    /// <summary>
    /// What the CA is and what this account may do there. Asked at registration
    /// rather than at the first enrolment - 0033.
    /// </summary>
    Task<AdcsDescribeResponse> DescribeAsync(CancellationToken ct = default);

    /// <param name="request">DER. A CMC for enrol-on-behalf-of.</param>
    /// <param name="attributes">
    /// The attribute string ADCS parses, newline separated. This is where the
    /// template is named.
    /// </param>
    Task<AdcsSubmitResponse> SubmitAsync(
        byte[] request, AdcsRequestFormat format, string? attributes,
        CancellationToken ct = default);

    /// <summary>Collect a request a certificate manager has since approved.</summary>
    Task<AdcsSubmitResponse> RetrieveAsync(int requestId, CancellationToken ct = default);

    Task<AdcsRevokeResponse> RevokeAsync(
        string serialNumber, int reason, DateTimeOffset? effectiveAt,
        CancellationToken ct = default);

    /// <summary>
    /// The template object as the requesting account sees it - 0033.
    /// </summary>
    /// <remarks>
    /// On the transport because both transports can answer it: the connector reads
    /// the directory as the integration account, and CEP returns the same
    /// attributes for the templates the caller may enrol for.
    /// </remarks>
    Task<AdcsTemplateInfo> DescribeTemplateAsync(string name, CancellationToken ct = default);
}
