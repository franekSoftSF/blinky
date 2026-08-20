namespace Blinky.Domain.Entities;

/// <summary>
/// Append-only. Retention is a policy setting, but revocation and PUK
/// disclosure are exempt from it - those are the events worth alerting on and
/// the ones that must survive the token being lost.
/// </summary>
public class AuditEvent
{
    public virtual Guid Id { get; protected set; }

    public virtual DateTime OccurredAt { get; set; }

    /// <summary>Dotted event name, e.g. "credential.revoked".</summary>
    public virtual string EventType { get; set; } = string.Empty;

    public virtual string? Actor { get; set; }

    public virtual string? SubjectType { get; set; }

    public virtual Guid? SubjectId { get; set; }

    public virtual long? TokenSerial { get; set; }

    /// <summary>Event detail. jsonb.</summary>
    public virtual string Detail { get; set; } = "{}";

    /// <summary>True for events retention must not remove.</summary>
    public virtual bool IsExemptFromRetention { get; set; }
}
