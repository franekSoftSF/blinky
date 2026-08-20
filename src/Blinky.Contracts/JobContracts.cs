namespace Blinky.Contracts;

/// <summary>
/// A unit of work, as the agent receives it.
/// </summary>
/// <remarks>
/// A script, not a verb. The server decides the sequence and the agent executes
/// it, so a failure names the step rather than the job — "enrolment failed" is
/// not a diagnosis — and changing the sequence reaches the whole fleet without
/// shipping a new agent. See docs/05-agent-protocol.md.
/// </remarks>
public sealed record JobEnvelope(
    int SchemaVersion,
    Guid JobId,
    JobType Type,
    string IdempotencyKey,
    DateTimeOffset DeadlineAt,
    long? TokenSerial,
    IReadOnlyList<JobStep> Steps)
{
    /// <summary>
    /// Nothing in here is ever a PIN. The payload is stored in the database,
    /// and a PIN in a database is a PIN that exists.
    /// </summary>
    public static JobEnvelope Inventory(Guid jobId, string idempotencyKey,
        DateTimeOffset deadline) =>
        new(Protocol.SchemaVersion, jobId, JobType.Inventory, idempotencyKey, deadline, null,
            [new JobStep("ReadAllReaders")]);
}

/// <summary>One instruction in a job.</summary>
public sealed record JobStep(string Op, IReadOnlyDictionary<string, string>? Arguments = null)
{
    public string? Argument(string name) =>
        Arguments is not null && Arguments.TryGetValue(name, out var value) ? value : null;
}

/// <summary>What the agent says while a job is running.</summary>
public sealed record JobProgress(
    Guid JobId,
    int Attempt,
    JobState State,
    string? Step = null,
    string? Detail = null);

/// <summary>How a job ended.</summary>
public sealed record JobResult(
    Guid JobId,
    int Attempt,
    bool Succeeded,
    string? FailedStep = null,
    string? Detail = null,
    string? StatusWord = null);

/// <summary>What the server says when an agent asks for work.</summary>
public sealed record JobClaim(JobEnvelope Job, DateTimeOffset LeaseExpiresAt, int Attempt);
