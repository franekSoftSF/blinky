namespace Blinky.Domain;

/// <summary>
/// Credential lifecycle. <see cref="Issued"/> and <see cref="Installed"/> are
/// two states on purpose: between them a certificate exists at the CA that the
/// card has not received, and that gap is the only way to see the leak.
/// </summary>
public enum CredentialState
{
    Requested,
    KeyGenerated,
    CsrSubmitted,
    Issued,
    Installed,
    Active,
    Expiring,
    Superseded,
    Revoked,
    Expired,
    Failed,
}
