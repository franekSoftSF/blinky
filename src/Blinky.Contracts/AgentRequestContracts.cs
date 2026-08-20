namespace Blinky.Contracts;

/// <summary>
/// The channel the person opens, rather than the one that opens on them.
/// </summary>
/// <remarks>
/// <para>
/// A second pipe, deliberately, rather than more traffic on
/// <see cref="AgentPipe"/>. That one carries <b>answers</b>: the service asks
/// for a PIN and waits. This one carries <b>requests</b>: somebody clicked. The
/// two have opposite initiators and opposite failure modes — a prompt nobody
/// answers must time out, a request nobody made must never arrive — and one
/// pipe doing both would have to tell them apart on every read.
/// </para>
/// <para>
/// Same access control as the prompt pipe: <c>INTERACTIVE</c> and
/// <c>LocalSystem</c>. That ACL now guards rather more than it used to. See
/// docs/10-agent-ui.md.
/// </para>
/// </remarks>
public static class AgentRequestPipe
{
    public const string Name = "Blinky.Agent.Requests";
}

/// <summary>Something the person at the keyboard asked for.</summary>
public sealed record AgentRequest(
    string Op,
    long? TokenSerial = null,
    string? SlotId = null)
{
    /// <summary>Everything on the readers of this machine, read now.</summary>
    public const string ListTokens = "ListTokens";

    /// <summary>Change the PIN, given the current one.</summary>
    public const string ChangePin = "ChangePin";

    /// <summary>Set a new PIN using the PUK.</summary>
    public const string UnblockPin = "UnblockPin";

    /// <summary>The rules a new PIN has to satisfy on this deployment.</summary>
    public const string GetPinPolicy = "GetPinPolicy";
}

/// <summary>
/// The values a person typed, carried no further than the service.
/// </summary>
/// <remarks>
/// A separate record from <see cref="AgentRequest"/> so that the request can be
/// logged and this cannot. Nothing in here is written anywhere, at any level,
/// ever.
/// </remarks>
public sealed record AgentSecrets(
    string? CurrentPin = null,
    string? NewPin = null,
    string? Puk = null);

/// <summary>A request and its secrets, as one line on the pipe.</summary>
public sealed record AgentRequestEnvelope(AgentRequest Request, AgentSecrets? Secrets = null);

/// <summary>What the service says back.</summary>
public sealed record AgentResponse(
    bool Succeeded,
    string? Error = null,
    IReadOnlyList<TokenView>? Tokens = null,
    PinComplexityPolicy? PinComplexityPolicy = null,
    int? AttemptsRemaining = null)
{
    public static AgentResponse Failed(string error, int? attemptsRemaining = null) =>
        new(false, error, AttemptsRemaining: attemptsRemaining);
}

/// <summary>A token on a reader of this machine, as the tray shows it.</summary>
public sealed record TokenView(
    long Serial,
    string ReaderName,
    string? FirmwareVersion,
    int? PinAttemptsRemaining,
    bool HasPuk,
    IReadOnlyList<SlotView> Slots);

/// <summary>
/// One slot, read from the card.
/// </summary>
/// <remarks>
/// <paramref name="HasKeyWithoutCertificate"/> is not a fault and not nothing:
/// it is the residue of an enrolment that failed after generating, and it is
/// the reason a retry into that slot will be refused rather than quietly
/// destroying what is there.
/// </remarks>
public sealed record SlotView(
    string SlotId,
    string? Subject,
    string? Issuer,
    DateTimeOffset? NotAfter,
    string? KeyAlgorithm,
    bool HasKeyWithoutCertificate)
{
    /// <summary>Days left, negative once it has expired. Null with no certificate.</summary>
    public int? DaysRemaining => NotAfter is { } expiry
        ? (int)Math.Floor((expiry - DateTimeOffset.UtcNow).TotalDays)
        : null;
}
