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

/// <summary>
/// The PUK a card is holding and the one that will replace it.
/// </summary>
/// <remarks>
/// <para>
/// Both in one answer because the agent needs the second before it can spend
/// the first: unblock with the current value, then change the PUK to the next,
/// inside a single transaction with the card. A second round trip would put a
/// network between two APDUs that must not be separated.
/// </para>
/// <para>
/// This never reaches a window and is never written down. It exists for the
/// length of one card operation in the service. See docs/10-agent-ui.md.
/// </para>
/// </remarks>
public sealed record PukMaterial(Guid CheckoutId, string CurrentPuk, string NextPuk);

/// <summary>
/// The management key material for one token, on its way to the agent holding
/// that token.
/// </summary>
/// <param name="Configured">
/// False when the deployment derives no management key at all, which leaves
/// cards on the factory value. Not an error - it is the state every card is in
/// until this is rolled out - and the agent needs to be able to tell it apart
/// from a call that failed.
/// </param>
/// <param name="Secret">
/// Base64. Long enough for any management key algorithm; the agent takes what
/// its own card reports needing, because only the agent has asked it.
/// </param>
public sealed record ManagementKeySecret(bool Configured, string? Secret);

/// <summary>The card took the replacement; escrow may promote it.</summary>
public sealed record PukRotated(Guid CheckoutId);
