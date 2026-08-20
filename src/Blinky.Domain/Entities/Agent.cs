namespace Blinky.Domain.Entities;

/// <summary>One installed workstation agent.</summary>
public class Agent
{
    public virtual Guid Id { get; protected set; }

    public virtual string Hostname { get; set; } = string.Empty;

    /// <summary>
    /// Required, and not guessable from the machine: the agent runs as
    /// LocalSystem, whose UserDomainName is the machine name. Guessing produces
    /// a second, orphaned row.
    /// </summary>
    public virtual string Domain { get; set; } = string.Empty;

    public virtual string? Version { get; set; }

    public virtual string? ClientCertificateThumbprint { get; set; }

    public virtual AgentState State { get; set; } = AgentState.Enrolled;

    public virtual DateTime? LastHeartbeatAt { get; set; }

    public virtual DateTime CreatedAt { get; set; }

    public virtual DateTime UpdatedAt { get; set; }
}
