using System.Security.Cryptography.X509Certificates;
using Blinky.Domain;

namespace Blinky.Pki;

/// <summary>
/// Everything a certificate authority is asked to consider. Assembled by the
/// server, never by the agent.
/// </summary>
/// <param name="Pkcs10">The certificate request, signed by the card.</param>
/// <param name="Attestation">
/// Already verified against a pinned Yubico root. A backend receiving this may
/// assume the key is on genuine hardware; nothing here re-checks it, which is
/// why the type carries a verdict rather than raw certificates.
/// </param>
public sealed record CertificateRequestContext(
    byte[] Pkcs10,
    AttestedKey Attestation,
    CardholderIdentity Subject,
    IssuanceProfile Profile);

/// <summary>What the attestation established, once it was believed.</summary>
public sealed record AttestedKey(
    long TokenSerial,
    string SlotId,
    byte[] PublicKeyInfo,
    string? PinPolicy,
    string? TouchPolicy);

/// <summary>Who the certificate is for.</summary>
/// <remarks>
/// <see cref="ObjectSid"/> is not decoration. Since the KB5014754 enforcement
/// change a domain controller will not accept a logon certificate on the UPN
/// alone - see docs/04-pki-backends.md.
/// </remarks>
public sealed record CardholderIdentity(
    string DisplayName,
    string? Upn,
    string? ObjectSid,
    string? DistinguishedName);

/// <summary>What to issue. The database's profile, flattened for the CA.</summary>
public sealed record IssuanceProfile(
    string Name,
    string SlotId,
    string KeyAlgorithm,
    int ValidityDays,
    IReadOnlyList<string> ExtendedKeyUsages,
    bool IncludeUpnSan,
    bool IncludeSidExtension,
    string? SubjectTemplate = null,
    string? AdcsTemplateName = null);

/// <summary>A certificate, and the chain a client will need with it.</summary>
public sealed record IssuedCertificate(
    X509Certificate2 Certificate,
    IReadOnlyList<X509Certificate2> Chain)
{
    public string SerialNumber => Certificate.SerialNumber;

    public string CertificatePem => Certificate.ExportCertificatePem();
}

public sealed record RevocationRequest(
    string SerialNumber,
    X509RevocationReason Reason,
    string? Comment = null);

public enum X509RevocationReason
{
    Unspecified = 0,
    KeyCompromise = 1,
    CaCompromise = 2,
    AffiliationChanged = 3,
    Superseded = 4,
    CessationOfOperation = 5,
    CertificateHold = 6,
}

/// <summary>A published revocation list, with when it stops being usable.</summary>
public sealed record CrlDocument(byte[] Der, DateTimeOffset ThisUpdate, DateTimeOffset NextUpdate)
{
    /// <summary>
    /// An expired CRL breaks every chain built under it, which is how a root
    /// CRL nobody renews takes a working PKI down months later.
    /// </summary>
    public bool IsExpired(DateTimeOffset now) => now >= NextUpdate;
}

/// <summary>
/// What a backend can and cannot do, so the console greys out what is
/// unavailable instead of discovering the limit by failing an issuance in front
/// of a user.
/// </summary>
public sealed record CaCapabilities(
    CaBackend Backend,
    bool SupportsSuppliedSubject,
    bool SupportsRevocation,
    bool PublishesCrl,
    bool AddsSidExtension,
    IReadOnlySet<string> Algorithms)
{
    /// <summary>
    /// True when this backend can produce a certificate a domain controller
    /// will accept for logon. False is not a defect - it means the
    /// configuration cannot, and says so before anybody enrols.
    /// </summary>
    public bool CanIssueSmartCardLogon => AddsSidExtension;
}
