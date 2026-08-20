namespace Blinky.Pki;

/// <summary>
/// One interface, two very different things behind it: a CA that runs in this
/// process, and a Microsoft CA driven through an enrolment agent.
/// </summary>
/// <remarks>
/// The differences are not hidden - they leak through
/// <see cref="DescribeAsync"/> in a form a caller can act on, rather than
/// through an exception at issuance time. See docs/04-pki-backends.md.
/// </remarks>
public interface ICertificateAuthority
{
    /// <summary>The configured instance this speaks for.</summary>
    string Name { get; }

    Task<CaCapabilities> DescribeAsync(CancellationToken ct = default);

    Task<IssuedCertificate> IssueAsync(CertificateRequestContext context,
        CancellationToken ct = default);

    Task RevokeAsync(RevocationRequest request, CancellationToken ct = default);

    /// <summary>
    /// The current revocation list, or null when this backend does not publish
    /// one - ADCS keeps its own, and pretending otherwise would put a link in
    /// the console to a file nobody writes.
    /// </summary>
    Task<CrlDocument?> GetCrlAsync(CancellationToken ct = default);
}

/// <summary>Raised when a request cannot be turned into a certificate.</summary>
public class CertificateAuthorityException(string message, Exception? inner = null)
    : Exception(message, inner);

/// <summary>
/// Raised when the request is well formed but policy refuses it. Separate from
/// <see cref="CertificateAuthorityException"/> because one of these is somebody
/// asking for something they may not have, and the other is a fault.
/// </summary>
public sealed class IssuancePolicyException(string message) : CertificateAuthorityException(message);
