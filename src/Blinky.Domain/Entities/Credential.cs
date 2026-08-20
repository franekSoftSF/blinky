namespace Blinky.Domain.Entities;

/// <summary>
/// One issued certificate bound to one slot. Immutable once issued: renewal
/// creates a new row and points it at this one.
/// </summary>
public class Credential
{
    public virtual Guid Id { get; protected set; }

    public virtual Token Token { get; set; } = null!;

    public virtual string SlotId { get; set; } = string.Empty;

    public virtual CertificateProfile? Profile { get; set; }

    public virtual CaInstance? CaInstance { get; set; }

    public virtual string? SerialNumber { get; set; }

    public virtual string? IssuerDn { get; set; }

    public virtual string? SubjectDn { get; set; }

    public virtual DateTime? NotBefore { get; set; }

    public virtual DateTime? NotAfter { get; set; }

    /// <summary>
    /// The join between what the CA signed and what the card proved it holds.
    /// Renewal, revocation and stale-slot detection all key off this rather
    /// than the certificate serial: the serial is the CA's opinion, the public
    /// key is the card's.
    /// </summary>
    public virtual byte[]? PublicKeySha256 { get; set; }

    public virtual Guid? AttestationId { get; set; }

    public virtual CredentialState State { get; set; } = CredentialState.Requested;

    public virtual Credential? Supersedes { get; set; }

    public virtual string? RevocationReason { get; set; }

    public virtual DateTime? RevokedAt { get; set; }

    public virtual DateTime CreatedAt { get; set; }

    public virtual DateTime UpdatedAt { get; set; }
}
