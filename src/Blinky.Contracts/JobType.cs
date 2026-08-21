namespace Blinky.Contracts;

/// <summary>Kinds of work the job engine carries. See docs/02-data-model.md.</summary>
public enum JobType
{
    Inventory,
    Enroll,
    Renew,
    Revoke,
    UnblockPin,
    RotateMgmtKey,
    ResetCard,

    /// <summary>
    /// Rebuild the revocation list and publish it. Server-side: there is no
    /// card and no agent, and an agent that claimed one would hold it until
    /// the lease expired without ever being able to do it.
    /// </summary>
    PublishCrl,
}

/// <summary>
/// Which side runs a job.
/// </summary>
/// <remarks>
/// In one place because two sides have to agree: the API will not hand a
/// server-side job to an agent asking for work, and the worker will not claim
/// one meant for a card. Getting that wrong is not a visible failure - the job
/// is claimed, held for the length of a lease, and returned to the queue by the
/// watchdog, forever.
/// </remarks>
public static class JobTypes
{
    /// <summary>Work that needs a card, and so an agent to reach it.</summary>
    public static bool IsForAgent(JobType type) => type is not JobType.PublishCrl;

    /// <summary>Work the deployment does to itself.</summary>
    public static bool IsMaintenance(JobType type) => !IsForAgent(type);
}
