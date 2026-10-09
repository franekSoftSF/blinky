namespace Blinky.Domain.Entities;

/// <summary>
/// Somebody at a workstation asked for a passkey on the key in their reader.
/// </summary>
/// <remarks>
/// <para>
/// A request and not a job. Work is created by an operator and never by an
/// agent: the workstation can say "this person wants one", and only a person
/// in the console turns that into a ceremony, choosing the provider and the PIN
/// rules as they would for any other passkey. See docs/10-agent-ui.md.
/// </para>
/// <para>
/// History, so created and moved through its states, never edited and never
/// deleted.
/// </para>
/// </remarks>
public class PasskeyRequest
{
    public virtual Guid Id { get; protected set; }

    public virtual long TokenSerial { get; set; }

    /// <summary>The token's holder when it was asked. The passkey is for them.</summary>
    public virtual Cardholder Cardholder { get; set; } = null!;

    /// <summary>The workstation that asked, and the one the job will be given to.</summary>
    public virtual Guid AgentId { get; set; }

    public virtual PasskeyRequestState State { get; protected set; } = PasskeyRequestState.Pending;

    /// <summary>Set on approval: the job that carries the ceremony.</summary>
    public virtual Guid? JobId { get; protected set; }

    /// <summary>The operator who decided.</summary>
    public virtual string? DecidedBy { get; protected set; }

    /// <summary>Why it was refused. Shown at the workstation.</summary>
    public virtual string? RejectionReason { get; protected set; }

    public virtual DateTime? DecidedAt { get; protected set; }

    public virtual DateTime CreatedAt { get; set; }

    public virtual DateTime UpdatedAt { get; set; }

    public virtual void Approve(Guid jobId, string operatorName, DateTime nowUtc)
    {
        Decide(operatorName, nowUtc);
        JobId = jobId;
        State = PasskeyRequestState.Approved;
    }

    public virtual void Reject(string reason, string operatorName, DateTime nowUtc)
    {
        if (string.IsNullOrWhiteSpace(reason))
        {
            throw new ArgumentException("Refusing a passkey request needs a reason.", nameof(reason));
        }

        Decide(operatorName, nowUtc);
        RejectionReason = reason;
        State = PasskeyRequestState.Rejected;
    }

    private void Decide(string operatorName, DateTime nowUtc)
    {
        if (State != PasskeyRequestState.Pending)
        {
            throw new InvalidOperationException($"This request was already {State}.");
        }

        DecidedBy = operatorName;
        DecidedAt = nowUtc;
        UpdatedAt = nowUtc;
    }
}
