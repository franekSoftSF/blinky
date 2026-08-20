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
/// <remarks>
/// <paramref name="SlotId"/> carries the challenge on an offline unblock. That
/// is a reuse of a field meant for something else, and it is here rather than
/// in <see cref="AgentSecrets"/> for a reason: a challenge is a serial and a
/// random number, safe to log, and the secrets record exists precisely so that
/// nothing in it is ever logged.
/// </remarks>
public sealed record AgentRequest(
    string Op,
    long? TokenSerial = null,
    string? SlotId = null)
{
    /// <summary>Everything on the readers of this machine, read now.</summary>
    public const string ListTokens = "ListTokens";

    /// <summary>Change the PIN, given the current one.</summary>
    public const string ChangePin = "ChangePin";

    /// <summary>
    /// Unblock a PIN.
    /// </summary>
    /// <remarks>
    /// Carries a new PIN and no PUK. The PUK is not the user's to know: the
    /// service fetches it, spends it and replaces it, all without it reaching
    /// this side of the pipe. See docs/10-agent-ui.md.
    /// </remarks>
    public const string UnblockPin = "UnblockPin";

    /// <summary>
    /// Ask for the code to read down a telephone.
    /// </summary>
    /// <remarks>
    /// Costs nothing and touches no card: it is a serial and a random number.
    /// The token only finds out anything happened when the answer comes back.
    /// </remarks>
    public const string OfflineChallenge = "OfflineChallenge";

    /// <summary>Unblock with the code an operator read back.</summary>
    public const string UnblockOffline = "UnblockOffline";

    /// <summary>Read one slot's certificate off the card.</summary>
    public const string ReadCertificate = "ReadCertificate";

    /// <summary>
    /// Remove a slot's certificate. The key stays where it is.
    /// </summary>
    public const string DeleteCertificate = "DeleteCertificate";

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

    /// <remarks>
    /// The code an operator read out. It carries a PUK, so it belongs in here
    /// with the other things that are never logged — not in the request beside
    /// the operation name.
    /// </remarks>
    string? OfflineResponse = null);

/// <summary>A request and its secrets, as one line on the pipe.</summary>
public sealed record AgentRequestEnvelope(AgentRequest Request, AgentSecrets? Secrets = null);

/// <summary>What the service says back.</summary>
public sealed record AgentResponse(
    bool Succeeded,
    string? Error = null,
    IReadOnlyList<TokenView>? Tokens = null,
    PinComplexityPolicy? PinComplexityPolicy = null,
    int? AttemptsRemaining = null,

    /// <summary>The code to read down a telephone.</summary>
    string? Challenge = null,

    /// <summary>One slot's certificate, PEM encoded.</summary>
    string? CertificatePem = null)
{
    public static AgentResponse Failed(string error, int? attemptsRemaining = null) =>
        new(false, error, AttemptsRemaining: attemptsRemaining);
}

/// <summary>
/// What the card can do about fingerprints, said out loud.
/// </summary>
/// <remarks>
/// Four values rather than a flag, because the difference between "this token
/// has no sensor" and "this token has a sensor and nobody has enrolled a
/// finger" is the difference between a fact and a thing the user can fix.
/// Showing nothing in the second case — which is what a boolean does — leaves
/// somebody looking at a Bio wondering why it is behaving like an ordinary key.
/// </remarks>
public enum BiometricAvailability
{
    /// <summary>No on-card comparison. The card said so, not the model name.</summary>
    NotSupported,

    /// <summary>A sensor, and no fingerprint enrolled on it yet.</summary>
    NotEnrolled,

    Enrolled,

    /// <summary>Match attempts exhausted. The PIN is the way in until it is reset.</summary>
    Blocked,
}

/// <summary>
/// Whether Blinky put what is in this slot there.
/// </summary>
/// <remarks>
/// Three values rather than a boolean, and the third is the important one. The
/// answer comes from comparing the key on the card against what the backend
/// holds, so a backend that cannot be reached means <b>unknown</b> — not
/// unmanaged. A two-valued version would relabel every certificate in the
/// fleet as foreign the moment the network went down, which is the one moment
/// nobody should be told their credential is suspect.
/// </remarks>
public enum SlotManagement
{
    /// <summary>The backend could not be asked.</summary>
    Unknown,

    /// <summary>Blinky issued this and the key on the card matches.</summary>
    Managed,

    /// <summary>Something else put this here — <c>ykman</c>, another CMS, a person.</summary>
    Unmanaged,

    /// <summary>Nothing in the slot.</summary>
    Empty,
}

/// <summary>A token on a reader of this machine, as the tray shows it.</summary>
public sealed record TokenView(
    long Serial,
    string ReaderName,
    string? FirmwareVersion,
    int? PinAttemptsRemaining,
    bool HasPuk,
    IReadOnlyList<SlotView> Slots,

    // Everything below is what the management panel needs to stop guessing.
    // A screen that shows "change the PIN" without saying the PIN is still the
    // factory one has left out the only urgent thing on it.
    bool PinIsDefault = false,
    bool PukIsDefault = false,
    int? PukAttemptsRemaining = null,
    bool ManagementKeyIsDefault = false,
    string? ManagementKeyAlgorithm = null,

    /// <remarks>
    /// From an attestation and nowhere else, so it is present only on a token
    /// that holds a key. Absent is absent: a model name inferred from a
    /// firmware version would be a guess in a column people read as fact.
    /// </remarks>
    string? FormFactor = null,
    bool IsFipsDevice = false,
    bool FingerprintsEnrolled = false,
    BiometricAvailability Biometrics = BiometricAvailability.NotSupported,
    int? BiometricAttemptsRemaining = null);

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
    bool HasKeyWithoutCertificate,
    SlotManagement Management = SlotManagement.Unknown,

    /// <remarks>
    /// What the card demands before it will use the private key: a PIN, a
    /// fingerprint, or - and this is the one worth seeing - nothing at all.
    /// </remarks>
    string? PinPolicy = null,
    string? TouchPolicy = null,

    /// <remarks>
    /// The public half, as a hash. Never the key itself: it is not secret, but
    /// a screen full of base64 is not information either. This is what a person
    /// compares against a certificate when they are asking whether the two
    /// belong together.
    /// </remarks>
    string? PublicKeySha256 = null)
{
    /// <summary>Days left, negative once it has expired. Null with no certificate.</summary>
    public int? DaysRemaining => NotAfter is { } expiry
        ? (int)Math.Floor((expiry - DateTimeOffset.UtcNow).TotalDays)
        : null;
}
