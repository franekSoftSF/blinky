namespace Blinky.Domain.Entities;

/// <summary>A configured certificate authority.</summary>
public class CaInstance
{
    public virtual Guid Id { get; protected set; }

    public virtual string Name { get; set; } = string.Empty;

    public virtual CaBackend Backend { get; set; }

    /// <summary>
    /// Immutable once set. Changing it would leave already-issued certificates
    /// chaining to an anchor this instance no longer claims, so a different
    /// topology is a different instance - see docs/04-pki-backends.md.
    /// </summary>
    public virtual CaTopology Topology { get; set; } = CaTopology.TwoTier;

    /// <summary>Backend-specific settings. jsonb.</summary>
    public virtual string Configuration { get; set; } = "{}";

    /// <summary>The chain, PEM, root last.</summary>
    public virtual string? CertificateChainPem { get; set; }

    public virtual string? CrlUrl { get; set; }

    public virtual string? OcspUrl { get; set; }

    public virtual bool IsEnabled { get; set; } = true;

    public virtual DateTime CreatedAt { get; set; }

    public virtual DateTime UpdatedAt { get; set; }
}
