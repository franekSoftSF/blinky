using System.Text.Json.Serialization;

namespace Blinky.Contracts;

/// <summary>
/// The wire between <c>AdcsCertificateAuthority</c> and
/// <c>Blinky.AdcsConnector</c>. See docs/15-adcs-connector.md.
/// </summary>
/// <remarks>
/// Versioned separately from <see cref="Protocol"/> because the two ends move
/// independently: the connector is installed next to a customer's CA and
/// upgraded by whoever owns that server, while the API upgrades with the
/// stack. Tying them to one number would mean a container upgrade silently
/// requiring a change on a machine nobody here can reach.
/// </remarks>
public static class AdcsTransport
{
    public const int SchemaVersion = 1;

    public const int MinimumSupportedVersion = 1;

    public const int MaximumSupportedVersion = 1;

    /// <summary>Carried on every request so a mismatch is refused, not guessed.</summary>
    public const string SchemaHeader = "X-Blinky-Adcs-Schema";

    public static bool IsSupported(int schemaVersion) =>
        schemaVersion >= MinimumSupportedVersion && schemaVersion <= MaximumSupportedVersion;
}

/// <summary>What the connector is being handed.</summary>
/// <remarks>
/// A CMC is the only format enrol-on-behalf-of can use, because the enrolment
/// agent's signature has nowhere to live in a bare PKCS#10. Pkcs10 exists for
/// the self-enrolment case and for proving the transport works before 0030 can
/// build a CMC.
/// </remarks>
/// <remarks>
/// Written as a name on the wire, unlike the job enums, and the converter is on
/// the type rather than in either host's serialiser options so that both ends
/// agree without being configured to. The far end of this wire is a service on
/// somebody else's Windows server, and the person diagnosing it will be reading
/// the body in a terminal: <c>"Denied"</c> tells them what happened and
/// <c>2</c> does not.
/// </remarks>
[JsonConverter(typeof(JsonStringEnumConverter<AdcsRequestFormat>))]
public enum AdcsRequestFormat
{
    Pkcs10,
    Cmc,
}

/// <summary>
/// The CA's answer to a submission, in the CA's own vocabulary.
/// </summary>
/// <remarks>
/// These are <c>CR_DISP_*</c> and the numbers are Microsoft's, not ours. They
/// are kept rather than folded into success/failure because
/// <see cref="UnderSubmission"/> is neither: the request is pending manager
/// approval and will be answered by a person, possibly tomorrow. The values are
/// kept even though the wire carries the name, because they are what
/// <c>ICertRequest3</c> returns and a drift here would read a denial as an
/// issuance.
/// </remarks>
[JsonConverter(typeof(JsonStringEnumConverter<AdcsDisposition>))]
public enum AdcsDisposition
{
    Incomplete = 0,
    Error = 1,
    Denied = 2,
    Issued = 3,
    IssuedOutOfBand = 4,
    UnderSubmission = 5,
    Revoked = 6,
}

/// <param name="Request">DER, base64 without a PEM header.</param>
/// <param name="CaConfig">
/// <c>HOST\CA common name</c>. Null means the connector's configured default,
/// which is the normal case; a deployment with two CAs on one host sets it.
/// </param>
/// <param name="Attributes">
/// The attribute string ADCS parses, newline separated - in practice
/// <c>CertificateTemplate:Name</c>. Assembled by the caller and passed through
/// untouched, because the set of attributes a template understands is the CA's
/// business and not something to enumerate here.
/// </param>
public sealed record AdcsSubmitRequest(
    int SchemaVersion,
    string Request,
    AdcsRequestFormat Format,
    string? Attributes = null,
    string? CaConfig = null);

/// <param name="Certificate">
/// Base64 DER, present only for <see cref="AdcsDisposition.Issued"/>.
/// </param>
/// <param name="Chain">
/// Base64 PKCS#7 holding the issued certificate and everything above it. The
/// caller needs the chain and asking the CA for it costs one flag, whereas
/// rebuilding it on a Linux container that does not trust the issuer costs a
/// configuration nobody remembers to make.
/// </param>
/// <param name="StatusMessage">
/// The CA's own disposition message. Passed through verbatim: "The request
/// subject name is invalid or too long" is worth more to whoever is reading a
/// failure than anything this code could write instead.
/// </param>
public sealed record AdcsSubmitResponse(
    AdcsDisposition Disposition,
    int RequestId,
    string? Certificate = null,
    string? Chain = null,
    string? StatusMessage = null,
    int? HResult = null);

/// <summary>Collect a request a certificate manager has since approved.</summary>
public sealed record AdcsRetrieveRequest(
    int SchemaVersion,
    int RequestId,
    string? CaConfig = null);

/// <param name="SerialNumber">
/// Lowercase hex, no separators, exactly as the CA's database holds it.
/// </param>
/// <param name="Reason">A CRL reason code. -1 un-revokes a held certificate.</param>
/// <param name="EffectiveAt">
/// When the revocation takes effect; null means now. ADCS accepts a past date
/// and a future one, and both are legitimate: a token reported lost on Friday
/// was lost on Friday.
/// </param>
public sealed record AdcsRevokeRequest(
    int SchemaVersion,
    string SerialNumber,
    int Reason,
    DateTimeOffset? EffectiveAt = null,
    string? CaConfig = null);

public sealed record AdcsRevokeResponse(
    bool Revoked,
    string? StatusMessage = null,
    int? HResult = null);

/// <summary>
/// What this connector is in front of, asked at backend registration rather
/// than discovered by failing an enrolment - 0033.
/// </summary>
/// <param name="AdminAvailable">
/// Whether <c>ICertAdmin2</c> answered. Revocation needs it and it needs the
/// service account to hold *Issue and Manage Certificates*, which is a
/// separate grant from *Request Certificates* and is routinely missing.
/// Reported here so the console can say revocation is unavailable instead of
/// offering a button that fails.
/// </param>
public sealed record AdcsDescribeResponse(
    int SchemaVersion,
    string ConnectorVersion,
    string CaConfig,
    string CaName,
    bool AdminAvailable,
    string? CertificateChain = null,
    IReadOnlyList<string>? Templates = null);

/// <summary>
/// A refusal, with a reason a person can act on. Never carries the request.
/// </summary>
public sealed record AdcsProblem(string Reason, string? Detail = null);
