namespace Blinky.Contracts;

/// <summary>
/// What an agent saw on a token. Facts, not conclusions.
/// </summary>
/// <remarks>
/// The agent reports what the card said and the server decides what it means.
/// The clearest case is a token with no PUK: on a Bio Multi-protocol that is
/// the factory state and perfectly fine, on anything else it means somebody
/// removed the recovery path. Both look identical from the card - the
/// difference is whether biometrics are present - and deciding it on the
/// workstation would put a policy judgement on the least trusted machine in
/// the system.
/// </remarks>
public sealed record TokenInventoryReport(
    int SchemaVersion,
    long Serial,
    string ReaderName,
    string? FirmwareVersion,
    string? FormFactor,
    bool IsFipsDevice,
    string? AttestationThumbprint,
    bool AttestationVerified,
    CredentialReport Pin,
    CredentialReport Puk,
    BiometricReport? Biometrics,
    ManagementKeyReport? ManagementKey,
    IReadOnlyList<SlotReport> Slots)
{
    public static TokenInventoryReport Empty(long serial, string reader) =>
        new(Protocol.SchemaVersion, serial, reader, null, null, false, null, false,
            CredentialReport.Unknown, CredentialReport.Unknown, null, null, []);
}

/// <summary>
/// A PIN or PUK, as the card describes it. <see cref="TotalRetries"/> of zero
/// means the credential does not exist - which is not the same as no attempts
/// remaining, and routes to a completely different place.
/// </summary>
public sealed record CredentialReport(
    bool? IsDefault,
    bool IsBlocked,
    int? RemainingRetries,
    int? TotalRetries)
{
    /// <summary>Firmware too old to be asked. Distinct from "not set".</summary>
    public static CredentialReport Unknown => new(null, false, null, null);
}

/// <summary>On-card biometric comparison. Null when the token has none.</summary>
public sealed record BiometricReport(
    bool FingerprintsEnrolled,
    int? AttemptsRemaining,
    bool TemporaryPinSet);

/// <summary>
/// The management key's algorithm as the card reports it, never as the firmware
/// version implies. Both 3DES and AES-192 tokens are in the field.
/// </summary>
public sealed record ManagementKeyReport(
    string Algorithm,
    bool IsDefault,
    string TouchPolicy);

/// <summary>One slot, and whatever is in it.</summary>
public sealed record SlotReport(
    string SlotId,
    bool HasKey,
    bool HasCertificate,
    string? KeyAlgorithm,
    string? PinPolicy,
    string? TouchPolicy,
    string? PublicKeySha256,
    string? CertificateSubject,
    string? CertificateThumbprint,
    DateTimeOffset? NotBefore,
    DateTimeOffset? NotAfter,

    // Trailing and optional: the backend has never needed the issuer, and the
    // tray does - a certificate is only reassuring once you can see who signed
    // it.
    string? CertificateIssuer = null);

/// <summary>
/// A card that speaks PIV but is not something Blinky can manage.
/// </summary>
/// <remarks>
/// Reported rather than skipped. An operator who plugs in a card and sees
/// nothing happen has no way to tell that from a broken agent, and "nothing
/// happened" is the hardest support call there is.
/// </remarks>
public sealed record UnsupportedCardReport(
    string ReaderName,
    string Reason,
    int? PinRetriesLeft);

/// <summary>What the server says back after taking a report.</summary>
public sealed record InventoryAccepted(
    Guid TokenId,
    string TokenState,
    string PukState,
    bool IsUnrecoverable,
    bool IsNewToken);
