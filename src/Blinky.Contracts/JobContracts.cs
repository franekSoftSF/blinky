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
    IReadOnlyList<JobStep> Steps,
    JobContext? Context = null)
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
        string displayName, string? upn, string? objectSid,
        string? keyAlgorithm = null, bool replaceKey = false, JobContext? context = null) =>
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

                // Which key the card generates. Empty means the agent's own
                // default, so an older agent that does not read this is not
                // handed something it will ignore silently.
                ["keyAlgorithm"] = keyAlgorithm ?? string.Empty,

                // Permission to generate over a key that is already in the
                // slot. Granted by the server only for a key the server put
                // there and has since revoked - never for one it does not
                // recognise.
                ["replaceKey"] = replaceKey ? "true" : string.Empty,
            }),
        ], context);

    /// <summary>
    /// Prepare a key and run one WebAuthn ceremony on it for a provider the agent
    /// does not need to know. The challenge is not in here - see <see cref="Fido2Ready"/>.
    /// </summary>
    /// <param name="tokenSerial">Null when any key will do; the agent reports which one it was.</param>
    public static JobEnvelope ProvisionFido2(Guid jobId, string idempotencyKey,
        DateTimeOffset deadline, long? tokenSerial, Fido2Provisioning provisioning,
        JobContext? context = null) =>
        new(Protocol.VersionFor(JobType.ProvisionFido2Credential), jobId,
            JobType.ProvisionFido2Credential, idempotencyKey, deadline, tokenSerial,
            [provisioning.ToStep()], context);
}

/// <summary>
/// What a job is, in words a person at the workstation can follow (0084a).
/// </summary>
/// <remarks>
/// <para>
/// For the issuance window and nothing else: the agent never decides anything
/// on it. Additive, so an older agent ignores it and the protocol version does
/// not move.
/// </para>
/// <para>
/// Names, not secrets. The cardholder's name and UPN are already in an
/// enrolment's step arguments; the operator's name is the one thing new here,
/// and it is what a person asked for a PIN by a window most needs to see -
/// that somebody they can call started this.
/// </para>
/// </remarks>
public sealed record JobContext(
    string Operation,
    string? Holder = null,
    string? HolderUpn = null,
    string? RequestedBy = null,
    string? Profile = null,
    string? Provider = null,
    string? Login = null)
{
    public const string EnrolCard = "EnrolCard";
    public const string Passkey = "Passkey";
}

/// <summary>
/// The steps a person sees for each job type that needs them, in order (0084a).
/// </summary>
/// <remarks>
/// One list for the agent's window and the console's job view, so the two
/// cannot describe the same job differently. The names are the step names the
/// agent already reports in <see cref="JobProgress.Step"/>. A step may be
/// skipped - a card already personalised has no PersonaliseCard - and may come
/// early (VerifyUser when the key sits behind the PIN); a window marks what it
/// is told and does not assume the order was kept.
/// </remarks>
public static class JobSteps
{
    public static readonly IReadOnlyList<string> Enrolment =
    [
        "AuthenticateManagementKey",
        "PersonaliseCard",
        "ChoosePin",
        "GenerateKey",
        "Attest",
        "VerifyUser",
        "BuildAndSignCsr",
        "SubmitToCa",
        "WriteCertificate",
    ];

    public static readonly IReadOnlyList<string> Passkey =
    [
        Fido2Steps.OpenKey,
        Fido2Steps.Pin,
        Fido2Steps.MinPinLength,
        Fido2Steps.Challenge,
        Fido2Steps.Touch,
        Fido2Steps.Register,
        Fido2Steps.ForcePinChange,
    ];

    /// <summary>Null for a job nobody needs to watch - an inventory, a recycle.</summary>
    public static IReadOnlyList<string>? For(JobType type) => type switch
    {
        JobType.Enroll => Enrolment,
        JobType.ProvisionFido2Credential => Passkey,
        _ => null,
    };
}

/// <summary>The passkey ceremony's step names, as the agent reports them.</summary>
public static class Fido2Steps
{
    public const string OpenKey = "Fido2OpenKey";
    public const string Pin = "Fido2Pin";
    public const string MinPinLength = "Fido2MinPinLength";
    public const string Challenge = "Fido2Challenge";
    public const string Touch = "Fido2Touch";
    public const string Register = "Fido2Register";
    public const string ForcePinChange = "Fido2ForcePinChange";
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
