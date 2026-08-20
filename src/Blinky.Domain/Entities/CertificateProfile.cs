namespace Blinky.Domain.Entities;

/// <summary>What to issue, and onto which slot.</summary>
public class CertificateProfile
{
    public virtual Guid Id { get; protected set; }

    public virtual string Name { get; set; } = string.Empty;

    public virtual CaInstance CaInstance { get; set; } = null!;

    public virtual string SlotId { get; set; } = string.Empty;

    public virtual string KeyAlgorithm { get; set; } = string.Empty;

    /// <summary>Checked against the attestation before the CA is called.</summary>
    public virtual string? RequiredPinPolicy { get; set; }

    public virtual string? RequiredTouchPolicy { get; set; }

    public virtual int ValidityDays { get; set; }

    public virtual string? SubjectTemplate { get; set; }

    public virtual string? SanTemplate { get; set; }

    /// <summary>Extended key usages, as OIDs. Stored as jsonb.</summary>
    public virtual string ExtendedKeyUsages { get; set; } = "[]";

    /// <summary>Only meaningful for the ADCS backend.</summary>
    public virtual string? AdcsTemplateName { get; set; }

    public virtual bool IsEnabled { get; set; } = true;

    public virtual DateTime CreatedAt { get; set; }

    public virtual DateTime UpdatedAt { get; set; }
}
