namespace Blinky.Domain.Entities;

/// <summary>Who gets which profiles, and under what conditions.</summary>
public class IssuancePolicy
{
    public virtual Guid Id { get; protected set; }

    public virtual string Name { get; set; } = string.Empty;

    /// <summary>Directory group whose members this policy covers.</summary>
    public virtual string? DirectoryGroup { get; set; }

    /// <summary>Profile names, jsonb.</summary>
    public virtual string ProfileNames { get; set; } = "[]";

    /// <summary>
    /// Whether a token with no PUK may be personalised. Off by default: a Bio
    /// is accepted on its own merits, but any other token with the PUK removed
    /// means somebody deleted the recovery path and nobody wrote down why.
    /// </summary>
    public virtual bool AllowUnrecoverableTokens { get; set; }

    public virtual bool IsEnabled { get; set; } = true;

    public virtual DateTime CreatedAt { get; set; }

    public virtual DateTime UpdatedAt { get; set; }
}
