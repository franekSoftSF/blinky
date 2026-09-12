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
/// <param name="EnrolmentAgent">
/// The enrolment agent this connector signs with, or null when it holds none -
/// which is the normal state for a connector in front of a CES deployment, and a
/// misconfiguration for one that is expected to sign.
/// </param>
public sealed record AdcsDescribeResponse(
    int SchemaVersion,
    string ConnectorVersion,
    string CaConfig,
    string CaName,
    bool AdminAvailable,
    string? CertificateChain = null,
    IReadOnlyList<string>? Templates = null,
    AdcsEnrolmentAgentInfo? EnrolmentAgent = null);

/// <summary>
/// What the container may know about an enrolment agent key it cannot touch.
/// </summary>
/// <remarks>
/// Facts read from the key where it lives rather than assumed from where that
/// is. A key in a Windows store can be exportable or not, decided by the flag it
/// was imported with and by nothing about the file it came from - measured, see
/// docs/15. Reporting "on the Windows server" as if that settled custody would be
/// the claim this project refuses to make about SoftHSM.
/// </remarks>
/// <param name="Certificate">Base64 DER, without the key.</param>
/// <param name="Source">
/// "store: CurrentUser\My" or "file: C:\...". A file is a laboratory
/// arrangement on this side exactly as it is on the container's.
/// </param>
/// <param name="Exportable">
/// Whether the key's own export policy allows it to leave. Null when the provider
/// does not say, which is not the same as false.
/// </param>
/// <param name="Provider">
/// The key storage provider by name - "Microsoft Platform Crypto Provider" is a
/// TPM, "Microsoft Software Key Storage Provider" is a file under the account's
/// profile protected by DPAPI, and the difference is the whole question.
/// </param>
public sealed record AdcsEnrolmentAgentInfo(
    string Certificate,
    string Source,
    bool? Exportable,
    string? Provider);

/// <summary>
/// Sign a CMC's <c>PKIData</c> as the enrolment agent this connector holds.
/// </summary>
/// <remarks>
/// The connector signs and decides nothing else. Who the certificate is for and
/// against which template is decided on the container side and arrives already
/// built; the connector refuses anything that is not a <c>PKIData</c> carrying
/// exactly one certification request, so that holding a client certificate buys a
/// signature over an enrolment and not over arbitrary bytes. See
/// docs/15-adcs-connector.md.
/// </remarks>
/// <param name="PkiData">Base64 DER of the <c>PKIData</c>, not the CMS around it.</param>
public sealed record AdcsSignRequest(int SchemaVersion, string PkiData);

/// <param name="SignedData">Base64 DER of the CMS SignedData - the CMC itself.</param>
public sealed record AdcsSignResponse(string SignedData);

/// <summary>
/// A refusal, with a reason a person can act on. Never carries the request.
/// </summary>
public sealed record AdcsProblem(string Reason, string? Detail = null);

/// <summary>
/// What the directory says about one certificate template, read by whoever can
/// read it - the connector, as the integration account.
/// </summary>
/// <remarks>
/// <para>
/// Everything 0033 has to refuse is on the template object itself, so this is the
/// template object and nothing interpreted. The container decides what is wrong
/// with it; the connector only reads, because the decision is the same whichever
/// transport produced the facts - CEP returns the same attributes.
/// </para>
/// <para>
/// Nullable fields mean "could not be read", never "false". A registration check
/// that turned an unreadable attribute into a refusal would refuse correct
/// templates on every estate that restricts read access to the Configuration
/// partition, and one that turned it into a pass would pass broken ones.
/// </para>
/// </remarks>
/// <param name="Found">False when no template of that name exists in the forest.</param>
/// <param name="NameFlags">
/// <c>msPKI-Certificate-Name-Flag</c>. Bit 0x1 is "supply in the request", which
/// is the setting that removes the SID extension.
/// </param>
/// <param name="AuthorizedSignatures">
/// <c>msPKI-RA-Signature</c>: how many authorised signatures the CA demands.
/// Zero means the CA issues on the requester's own authority, and an enrolment
/// agent's signature is then decoration.
/// </param>
/// <param name="SignaturePolicies">
/// <c>msPKI-RA-Application-Policies</c>, as stored. Version 4 templates encode
/// more than OIDs into this attribute, so it is passed through rather than parsed.
/// </param>
/// <param name="AccountMayEnroll">
/// Whether the account the connector runs as holds Enroll on the template, from
/// its security descriptor and that account's own groups. Null when the
/// descriptor could not be read.
/// </param>
/// <param name="MinimalKeySize">
/// <c>msPKI-Minimal-Key-Size</c>, in bits. The CA compares a request's key length
/// with it whatever the algorithm, so a P-256 key against the default 2048 is
/// denied as too short. Added after exactly that denial on the lab CA.
/// </param>
public sealed record AdcsTemplateInfo(
    string Name,
    bool Found,
    string? DisplayName = null,
    int? SchemaVersion = null,
    int? NameFlags = null,
    int? AuthorizedSignatures = null,
    IReadOnlyList<string>? SignaturePolicies = null,
    IReadOnlyList<string>? ExtendedKeyUsages = null,
    bool? AccountMayEnroll = null,
    string? Account = null,
    int? MinimalKeySize = null);
