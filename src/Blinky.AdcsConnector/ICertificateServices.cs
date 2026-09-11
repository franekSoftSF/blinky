using Blinky.Contracts;

namespace Blinky.AdcsConnector;

/// <summary>
/// The four things this connector asks a Microsoft CA to do.
/// </summary>
/// <remarks>
/// An interface over COM so the HTTP surface can be exercised without a CA. It
/// is not an abstraction over "a certificate authority" - that already exists,
/// one layer up and on the other side of the wire, and duplicating it here is
/// how the two transports would drift apart.
/// </remarks>
public interface ICertificateServices
{
    CaDescription Describe(string? caConfig, CancellationToken ct);

    SubmissionOutcome Submit(
        byte[] request, AdcsRequestFormat format, string? attributes, string? caConfig,
        CancellationToken ct);

    SubmissionOutcome Retrieve(int requestId, string? caConfig, CancellationToken ct);

    RevocationOutcome Revoke(
        string serialNumber, int reason, DateTimeOffset? effectiveAt, string? caConfig,
        CancellationToken ct);
}

/// <param name="Certificate">DER. Null unless the disposition is issued.</param>
/// <param name="Chain">PKCS#7 holding the certificate and its issuers.</param>
public sealed record SubmissionOutcome(
    AdcsDisposition Disposition,
    int RequestId,
    byte[]? Certificate,
    byte[]? Chain,
    string? StatusMessage,
    int? HResult);

public sealed record RevocationOutcome(bool Revoked, string? StatusMessage, int? HResult);

/// <param name="AdminAvailable">
/// Whether the service account may manage certificates, which is what
/// revocation needs and is granted separately from enrolment.
/// </param>
/// <param name="Templates">
/// Best effort, and null when it could not be established. Absence means
/// unknown, never empty.
/// </param>
public sealed record CaDescription(
    string CaConfig,
    string CaName,
    bool AdminAvailable,
    byte[]? CertificateChain,
    IReadOnlyList<string>? Templates);

/// <summary>
/// Raised when the CA refuses or cannot be reached. Carries the CA's own words.
/// </summary>
public sealed class CertificateServiceException(string message, int? hresult = null,
    Exception? inner = null) : Exception(message, inner)
{
    public int? CaHResult { get; } = hresult;
}
