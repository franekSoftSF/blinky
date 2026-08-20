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

    /// <summary>
    /// Take a credential off a token and destroy its key.
    /// </summary>
    /// <remarks>
    /// The way a credential Blinky issued gets removed. The agent refuses to
    /// delete one on its own — doing so would leave this server holding a
    /// credential it believes is installed — so the order comes from here, and
    /// the record is corrected when the job reports back. That is the whole
    /// difference between a withdrawal and a divergence.
    /// </remarks>
    public static JobEnvelope Recycle(Guid jobId, string idempotencyKey,
        DateTimeOffset deadline, long tokenSerial, string slotId) =>
        new(Protocol.SchemaVersion, jobId, JobType.Revoke, idempotencyKey, deadline, tokenSerial,
        [
            new JobStep("RecycleSlot", new Dictionary<string, string>(StringComparer.Ordinal)
            {
                ["slot"] = slotId,
            }),
        ]);

    /// <summary>
    /// One step, not eight. Generate, attest, sign, issue and write all share a
    /// single PC/SC transaction on the workstation: a verified PIN and an
    /// authenticated management key are lost the moment the card is released,
    /// so phases that were scheduled separately would each have to ask for the
    /// PIN again or keep it somewhere. The agent <b>reports</b> the phases
    /// instead, which is where the diagnostic value was. This corrects
    /// docs/05-agent-protocol.md.
    /// </summary>
    /// <remarks>
    /// Still no PIN in here, and there never will be: this payload is stored in
    /// the database.
    /// </remarks>
    public static JobEnvelope Enrolment(Guid jobId, string idempotencyKey,
        DateTimeOffset deadline, long tokenSerial, string slotId, string profile,
        string displayName, string? upn, string? objectSid) =>
        new(Protocol.SchemaVersion, jobId, JobType.Enroll, idempotencyKey, deadline,
            tokenSerial,
        [
            new JobStep("EnrolCredential", new Dictionary<string, string>(StringComparer.Ordinal)
            {
                ["slot"] = slotId,
                ["profile"] = profile,
                ["displayName"] = displayName,
                ["upn"] = upn ?? string.Empty,
                ["objectSid"] = objectSid ?? string.Empty,
            }),
        ]);
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
