using Blinky.Contracts;

namespace Blinky.Domain.Entities;

/// <summary>One unit of work for one agent.</summary>
public class Job
{
    public virtual Guid Id { get; protected set; }

    public virtual JobType Type { get; set; }

    public virtual JobState State { get; set; } = JobState.Pending;

    public virtual long? TokenSerial { get; set; }

    public virtual Guid? AgentId { get; set; }

    public virtual Guid? CardholderId { get; set; }

    public virtual int Attempt { get; set; }

    /// <summary>
    /// Unique. Re-creating the same logical job returns the existing row rather
    /// than a second one, which is what makes at-least-once delivery safe.
    /// </summary>
    public virtual string IdempotencyKey { get; set; } = string.Empty;

    /// <summary>Protocol-versioned payload. jsonb.</summary>
    public virtual string Payload { get; set; } = "{}";

    public virtual string? Result { get; set; }

    /// <summary>
    /// A lease, not a lock: the watchdog returns expired leases to Pending, so
    /// a workstation that loses power does not hold work forever.
    /// </summary>
    public virtual DateTime? LeaseExpiresAt { get; set; }

    public virtual DateTime DeadlineAt { get; set; }

    public virtual DateTime CreatedAt { get; set; }

    public virtual DateTime UpdatedAt { get; set; }
}
