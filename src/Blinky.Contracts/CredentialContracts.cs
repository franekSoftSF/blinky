namespace Blinky.Contracts;

/// <summary>
/// What an agent submits to have a certificate issued.
/// </summary>
/// <remarks>
/// The attestation travels as certificates, not as a verdict. The agent has
/// already checked it — and the server checks it again, against its own pinned
/// root, because a workstation vouching for its own hardware is not evidence.
/// See docs/06-security.md.
/// </remarks>
public sealed record IssueCredentialRequest(
    int SchemaVersion,
    long TokenSerial,
    string SlotId,
    string ProfileName,
    string CertificateSigningRequestPem,
    string AttestationPem,
    string AttestationIntermediatePem,
    CardholderRequest Cardholder);

/// <summary>Who the credential is for, as the job carried it.</summary>
public sealed record CardholderRequest(
    string DisplayName,
    string? Upn,
    string? ObjectSid);

/// <summary>The certificate, and what to write it into.</summary>
public sealed record IssuedCredential(
    Guid CredentialId,
    string SlotId,
    string CertificatePem,
    string IssuerSubject,
    string SerialNumber,
    DateTimeOffset NotAfter);

/// <summary>
/// Confirmation that the certificate reached the card.
/// </summary>
/// <remarks>
/// A separate call on purpose. Between issuance and this, a certificate exists
/// at the CA that the token does not have — and the gap is the only way to see
/// that leak. See docs/02-data-model.md.
/// </remarks>
public sealed record CredentialInstalled(Guid CredentialId, string Thumbprint);
