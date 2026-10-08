using System.Buffers.Text;
using System.Text.Json;
using Blinky.Contracts;
using Blinky.Domain;
using Blinky.Domain.Entities;
using Blinky.Passkeys;

namespace Blinky.Api.Passkeys;

/// <summary>
/// The API's half of a passkey ceremony: ask the provider when the key is ready,
/// check what comes back, register it, and later take it away again.
/// </summary>
/// <remarks>
/// <para>
/// Every provider call is made here and nowhere else. The agent never speaks to
/// Entra or Okta; it is told rpId, origin and challenge, and answers with what the
/// key produced.
/// </para>
/// <para>
/// Three orderings matter and each has a test. The row is moved to
/// <see cref="PasskeyCredentialState.Provisioned"/> and saved <b>before</b> the
/// provider is asked to register, so a crash in between leaves a visible row
/// rather than a credential nobody knows about. A ceremony that does not finish is
/// cancelled at the provider, so Okta is not left holding a pending factor the next
/// attempt trips on. And a revocation deletes at the provider <b>before</b> it marks
/// the row, so "revoked" here never describes a credential that still works.
/// </para>
/// </remarks>
public sealed class PasskeyProvisioningService(
    PasskeyDirectories directories,
    IPasskeyStore store,
    ILogger<PasskeyProvisioningService> logger,
    TimeProvider? time = null)
{
    private static readonly JsonSerializerOptions Json = new(JsonSerializerDefaults.Web);
    private readonly TimeProvider clock = time ?? TimeProvider.System;

    private DateTime Now => clock.GetUtcNow().UtcDateTime;

    /// <summary>
    /// Resolves the user at the provider and records the request. Called before
    /// the job is created, so a typo in a login is refused in the console rather
    /// than after somebody has found a key and plugged it in.
    /// </summary>
    public async Task<PasskeyUser> ResolveAsync(string directoryName, string identifier, CancellationToken ct)
    {
        var directory = Directory(directoryName);

        if (!directory.Capabilities.SupportsRegistration)
        {
            throw new PasskeyFlowException(422, "registration-unsupported",
                $"{directory.Name} accepts no registration on a user's behalf.");
        }

        return await Provider(() => directory.FindUserAsync(identifier, ct))
               ?? throw new PasskeyFlowException(404, "no-such-user",
                   $"{directory.Name} has no single user matching '{identifier}'.");
    }

    /// <summary>Checks a PIN policy against what the provider can do.</summary>
    public void Check(string directoryName, Fido2PinPolicy pin)
    {
        if (pin.Mode is Fido2PinMode.ProviderDelivers && !Directory(directoryName).Capabilities.PinDeliveryByProvider)
        {
            throw new PasskeyFlowException(422, "pin-delivery-unsupported",
                $"{directoryName} does not deliver PINs to users; choose OperatorSets or ProvisionalRandom.");
        }
    }

    /// <summary>The row that goes with a job just created. Idempotent on the job.</summary>
    public PasskeyCredential Record(Guid jobId, string directoryName, PasskeyUser user, Guid? cardholderId,
        long? tokenSerial, string actor)
    {
        if (store.ForJob(jobId) is { } existing)
        {
            return existing;
        }

        var now = Now;
        var passkey = new PasskeyCredential
        {
            Directory = directoryName,
            ProviderUserId = user.Id,
            ProviderLogin = user.Login,
            Cardholder = cardholderId is { } id ? store.Cardholder(id) : null,
            TokenSerial = tokenSerial,
            JobId = jobId,
            CreatedAt = now,
            UpdatedAt = now,
        };

        store.Save(passkey, Audit("passkey.requested", actor, passkey, new { directory = directoryName, login = user.Login }));
        return passkey;
    }

    /// <summary>
    /// The key is ready: ask the provider for a challenge, and hand it to the agent.
    /// </summary>
    /// <remarks>
    /// Asked for only now - the challenge's lifetime is the provider's and starts
    /// when it is asked. A repeated Ready (a retried attempt, a lost answer) cancels
    /// the challenge already issued before asking for another, so a job retried
    /// three times leaves one pending factor at Okta and not three.
    /// </remarks>
    public async Task<Fido2CeremonyRequest> ReadyAsync(Guid agentId, Guid jobId, Fido2Ready ready, CancellationToken ct)
    {
        if (!Protocol.IsSupported(ready.SchemaVersion))
        {
            throw new PasskeyFlowException(400, "unsupported-version", $"Protocol {ready.SchemaVersion} is not spoken here.");
        }

        var (job, passkey) = Owned(agentId, jobId);

        if (job.TokenSerial is { } expected && ready.TokenSerial is { } reported && expected != reported)
        {
            throw new PasskeyFlowException(409, "wrong-key",
                $"The job is for key {expected}, and key {reported} is in the reader.");
        }

        var directory = Directory(passkey.Directory);
        var user = new PasskeyUser(passkey.ProviderUserId, passkey.ProviderLogin);

        if (passkey.State is PasskeyCredentialState.ChallengeIssued)
        {
            await CancelQuietlyAsync(directory, passkey, ct);
        }

        Move(passkey, PasskeyCredentialState.KeyReady);
        passkey.TokenSerial = ready.TokenSerial ?? passkey.TokenSerial;
        passkey.Aaguid = ready.Aaguid;
        passkey.ProviderReference = null;
        store.Save(passkey);

        PendingRegistration pending;

        try
        {
            pending = await directory.BeginRegistrationAsync(user, ct);
        }
        catch (PasskeyDirectoryException e)
        {
            Fail(passkey, $"{directory.Name} gave no challenge: {e.Message}");
            throw new PasskeyFlowException(502, "provider", e.Message);
        }

        var options = pending.Options;
        var challenge = Base64Url.EncodeToString(options.Challenge);
        // Whichever comes first. A challenge that outlives its job is one the agent
        // can no longer report on.
        var jobDeadline = new DateTimeOffset(DateTime.SpecifyKind(job.DeadlineAt, DateTimeKind.Utc));
        var deadline = options.Deadline < jobDeadline ? options.Deadline : jobDeadline;

        try
        {
            Move(passkey, PasskeyCredentialState.ChallengeIssued);
            passkey.CeremonyId = Fido2CeremonyRequest.IdFor(jobId, challenge);
            passkey.Challenge = challenge;
            passkey.Origin = options.Origin;
            passkey.ChallengeDeadlineAt = deadline.UtcDateTime;
            passkey.ProviderReference = pending.ProviderReference;
            store.Save(passkey, Audit("passkey.challenge-issued", agentId.ToString(), passkey,
                new { rpId = options.RpId, origin = options.Origin, deadline }));
        }
        catch
        {
            // Not recorded means not known about: the provider's half has to go too.
            await CancelQuietlyAsync(directory, pending.Handle, ct);
            throw;
        }

        return new Fido2CeremonyRequest(
            passkey.CeremonyId.Value, jobId, directory.Name,
            options.RpId, options.RpName, options.Origin, challenge,
            Base64Url.EncodeToString(options.UserHandle), options.UserName, options.UserDisplayName,
            options.Algorithms, options.ExcludeCredentials.Select(c => Base64Url.EncodeToString(c)).ToList(),
            options.ResidentKey, options.UserVerification, options.AuthenticatorAttachment, options.Attestation,
            options.Extensions.HmacCreateSecret, options.Extensions.CredentialProtectionPolicy,
            options.Extensions.EnforceCredentialProtectionPolicy, deadline);
    }

    /// <summary>What the key produced: check it, register it, say how it went.</summary>
    public async Task<Fido2Registered> ResultAsync(Guid agentId, Guid jobId, Fido2CeremonyResult result,
        CancellationToken ct)
    {
        if (!Protocol.IsSupported(result.SchemaVersion))
        {
            throw new PasskeyFlowException(400, "unsupported-version", $"Protocol {result.SchemaVersion} is not spoken here.");
        }

        var (_, passkey) = Owned(agentId, jobId);

        if (passkey.CeremonyId != result.CeremonyId)
        {
            throw new PasskeyFlowException(409, "stale-ceremony",
                "This result answers a challenge that is no longer the current one. Ask for a new one.");
        }

        // The same result posted twice - the answer was lost on the way back. The
        // first one decided; the second is told what it decided.
        if (passkey.State is PasskeyCredentialState.Registered or PasskeyCredentialState.Revoked)
        {
            return new Fido2Registered(result.CeremonyId, true, passkey.ProviderMethodId, null);
        }

        if (passkey.State is PasskeyCredentialState.Failed)
        {
            return new Fido2Registered(result.CeremonyId, false, null, passkey.FailureReason);
        }

        var directory = Directory(passkey.Directory);
        var handle = new RegistrationHandle(new PasskeyUser(passkey.ProviderUserId, passkey.ProviderLogin),
            passkey.ProviderReference);

        if (passkey.ChallengeDeadlineAt is { } deadline && Now > deadline)
        {
            // Retryable: the job is alive, the key is still there, and a fresh
            // challenge is one Ready away. Failing the row would make a person who
            // was slow with an unfamiliar PIN start again from the console.
            await CancelQuietlyAsync(directory, handle, ct);
            Move(passkey, PasskeyCredentialState.KeyReady);
            passkey.ProviderReference = null;
            store.Save(passkey, Audit("passkey.challenge-expired", agentId.ToString(), passkey, new { deadline }));

            throw new PasskeyFlowException(409, "challenge-expired",
                "The challenge expired before the key answered. Send Ready again for a new one.");
        }

        byte[] clientData, attestation, credentialId;

        try
        {
            clientData = Base64Url.DecodeFromChars(result.ClientDataJson);
            attestation = Base64Url.DecodeFromChars(result.AttestationObject);
            credentialId = Base64Url.DecodeFromChars(result.CredentialId);
        }
        catch (FormatException)
        {
            throw new PasskeyFlowException(400, "malformed", "The result is not unpadded base64url.");
        }

        if (ClientDataProblem(clientData, passkey) is { } problem)
        {
            // Not sent to the provider at all. A clientDataJSON naming another
            // challenge or another origin is either a bug in the agent or somebody
            // replaying one, and in both cases the provider's refusal would say
            // less than this does.
            await CancelQuietlyAsync(directory, handle, ct);
            Fail(passkey, problem, agentId.ToString());
            return new Fido2Registered(result.CeremonyId, false, null, problem);
        }

        Move(passkey, PasskeyCredentialState.Provisioned);
        passkey.CredentialId = result.CredentialId;
        passkey.Aaguid = result.Aaguid;
        passkey.KeyName = result.KeyName;
        passkey.AttestationObject = attestation;
        passkey.PinSetByAgent = result.PinSetByAgent;
        passkey.TokenSerial = result.TokenSerial ?? passkey.TokenSerial;
        store.Save(passkey);

        RegisteredPasskey registered;

        try
        {
            registered = await directory.CompleteRegistrationAsync(handle,
                new AttestationResponse(credentialId, clientData, attestation), result.KeyName, ct);
        }
        catch (PasskeyDirectoryException e)
        {
            await CancelQuietlyAsync(directory, handle, ct);
            Fail(passkey, $"{directory.Name} refused the registration: {e.Message}", agentId.ToString());
            return new Fido2Registered(result.CeremonyId, false, null, e.Message);
        }

        Move(passkey, PasskeyCredentialState.Registered);
        passkey.ProviderMethodId = registered.MethodId;
        passkey.ProviderReference = null;
        store.Save(passkey, Audit("passkey.registered", agentId.ToString(), passkey,
            new { methodId = registered.MethodId, keyName = result.KeyName, pinSetByAgent = result.PinSetByAgent }));

        logger.LogInformation("Passkey {Id} registered at {Directory} for {Login} as {MethodId}",
            passkey.Id, passkey.Directory, passkey.ProviderLogin, registered.MethodId);

        return new Fido2Registered(result.CeremonyId, true, registered.MethodId, null);
    }

    /// <summary>
    /// The job ended. A ceremony still open when it did - the agent failed, the key
    /// was pulled - is cancelled at the provider and the row failed with the
    /// agent's reason.
    /// </summary>
    public async Task JobEndedAsync(Guid jobId, JobResult result, CancellationToken ct)
    {
        if (store.ForJob(jobId) is not { } passkey
            || passkey.State is PasskeyCredentialState.Registered or PasskeyCredentialState.Revoked
                or PasskeyCredentialState.Failed)
        {
            return;
        }

        if (passkey.State is PasskeyCredentialState.ChallengeIssued or PasskeyCredentialState.Provisioned
            && directories.Find(passkey.Directory) is { } directory)
        {
            await CancelQuietlyAsync(directory, passkey, ct);
        }

        Fail(passkey, result.Succeeded
            ? "The job finished without the passkey being registered."
            : $"The job failed{(result.FailedStep is null ? "" : $" at {result.FailedStep}")}: {result.Detail}");
    }

    /// <summary>
    /// Where one passkey is, for the console to show while a ceremony runs. The
    /// row's state is the step - waiting for the key, the challenge out, the
    /// provider deciding - and the job's state says whether anybody is still on it.
    /// </summary>
    /// <remarks>
    /// No attestation and no challenge in it: the console needs to say where things
    /// are, not to hold what the key produced.
    /// </remarks>
    public PasskeyStatus Status(Guid id)
    {
        var passkey = store.Get(id) ?? throw new PasskeyFlowException(404, "no-such-passkey", "No such passkey.");
        var job = passkey.JobId is { } jobId ? store.Job(jobId) : null;

        return new PasskeyStatus(passkey.Id, passkey.Directory, passkey.ProviderLogin, passkey.State.ToString(),
            job?.State.ToString(), passkey.TokenSerial, passkey.KeyName, passkey.PinSetByAgent,
            passkey.ProviderMethodId, passkey.FailureReason, passkey.ChallengeDeadlineAt, passkey.RegisteredAt,
            passkey.RevokedAt);
    }

    /// <summary>
    /// Deletes at the provider, then marks the row. A provider that answers 404
    /// already agrees, and that is recorded rather than treated as a failure.
    /// </summary>
    public async Task<PasskeyCredential> RevokeAsync(Guid id, string reason, string actor, CancellationToken ct)
    {
        var passkey = store.Get(id) ?? throw new PasskeyFlowException(404, "no-such-passkey", "No such passkey.");

        if (passkey.State is not PasskeyCredentialState.Registered || passkey.ProviderMethodId is not { } methodId)
        {
            throw new PasskeyFlowException(409, "not-registered",
                $"A passkey that is {passkey.State} has nothing at the provider to revoke.");
        }

        var directory = Directory(passkey.Directory);
        var alreadyGone = false;

        try
        {
            await directory.DeleteAsync(new PasskeyUser(passkey.ProviderUserId, passkey.ProviderLogin), methodId, ct);
        }
        catch (PasskeyDirectoryException e) when (e.Status == 404)
        {
            alreadyGone = true;
        }
        catch (PasskeyDirectoryException e)
        {
            // Not marked: the credential still works, and the row must keep saying so.
            throw new PasskeyFlowException(502, "provider", $"{directory.Name} did not delete it: {e.Message}");
        }

        passkey.MoveTo(PasskeyCredentialState.Revoked, Now, reason);
        store.Save(passkey, Audit("passkey.revoked", actor, passkey,
            new { reason, methodId, alreadyGoneAtProvider = alreadyGone }, exempt: true));

        return passkey;
    }

    /// <summary>
    /// The database and the provider side by side, disagreement shown rather than
    /// resolved. A method at the provider that Blinky never made is not an error -
    /// the user may have enrolled a key of their own - but it is shown.
    /// </summary>
    public async Task<IReadOnlyList<PasskeyListing>> ListAsync(string directoryName, PasskeyUser user, CancellationToken ct)
    {
        var directory = Directory(directoryName);
        var ours = store.ForUser(directory.Name, user.Id);
        var theirs = await Provider(() => directory.ListAsync(user, ct));

        var listing = new List<PasskeyListing>();

        foreach (var row in ours)
        {
            var match = row.ProviderMethodId is { } m ? theirs.FirstOrDefault(t => t.MethodId == m) : null;
            var drift = row.State switch
            {
                PasskeyCredentialState.Registered when match is null => PasskeyDrift.MissingAtProvider,
                PasskeyCredentialState.Revoked when match is not null => PasskeyDrift.StillAtProvider,
                _ => PasskeyDrift.InSync,
            };

            listing.Add(new PasskeyListing(row.Id, row.ProviderMethodId, row.KeyName ?? match?.DisplayName,
                row.State.ToString(), row.TokenSerial, row.Aaguid ?? match?.Aaguid, row.CreatedAt, drift,
                match?.Status));
        }

        var known = ours.Select(r => r.ProviderMethodId).OfType<string>().ToHashSet(StringComparer.Ordinal);

        listing.AddRange(theirs.Where(t => !known.Contains(t.MethodId)).Select(t => new PasskeyListing(
            null, t.MethodId, t.DisplayName, null, null, t.Aaguid, t.Created?.UtcDateTime, PasskeyDrift.ProviderOnly,
            t.Status)));

        return listing;
    }

    private (Job, PasskeyCredential) Owned(Guid agentId, Guid jobId)
    {
        var job = store.Job(jobId);

        if (job is null || job.Type != JobType.ProvisionFido2Credential)
        {
            throw new PasskeyFlowException(404, "no-such-job", "No FIDO2 job with that id.");
        }

        if (job.AgentId != agentId)
        {
            throw new PasskeyFlowException(403, "not-yours", "This job is not yours.");
        }

        if (job.State is JobState.Succeeded or JobState.Failed or JobState.Expired or JobState.Cancelled)
        {
            throw new PasskeyFlowException(409, "job-ended", $"The job is {job.State}.");
        }

        var passkey = store.ForJob(jobId)
                      ?? throw new PasskeyFlowException(409, "no-passkey", "The job has no passkey record.");

        return (job, passkey);
    }

    private static string? ClientDataProblem(byte[] bytes, PasskeyCredential passkey)
    {
        try
        {
            using var doc = JsonDocument.Parse(bytes);
            var root = doc.RootElement;
            string? Text(string name) => root.TryGetProperty(name, out var v) && v.ValueKind == JsonValueKind.String
                ? v.GetString() : null;

            if (Text("type") != "webauthn.create")
            {
                return $"clientDataJSON is of type '{Text("type")}', not webauthn.create.";
            }

            if (Text("challenge") != passkey.Challenge)
            {
                return "clientDataJSON carries a different challenge from the one issued.";
            }

            if (Text("origin") != passkey.Origin)
            {
                return $"clientDataJSON names origin '{Text("origin")}', and '{passkey.Origin}' was issued.";
            }

            if (root.TryGetProperty("crossOrigin", out var cross) && cross.ValueKind == JsonValueKind.True)
            {
                return "clientDataJSON says crossOrigin, which no ceremony here ever is.";
            }

            return null;
        }
        catch (JsonException)
        {
            return "clientDataJSON is not JSON.";
        }
    }

    private IPasskeyDirectory Directory(string name) =>
        directories.Find(name) ?? throw new PasskeyFlowException(404, "no-such-directory",
            $"No passkey provider called '{name}' is configured.");

    private void Move(PasskeyCredential passkey, PasskeyCredentialState next)
    {
        try
        {
            passkey.MoveTo(next, Now);
        }
        catch (InvalidOperationException e)
        {
            throw new PasskeyFlowException(409, "wrong-state", e.Message);
        }
    }

    private void Fail(PasskeyCredential passkey, string reason, string actor = "api")
    {
        passkey.MoveTo(PasskeyCredentialState.Failed, Now, reason);
        passkey.ProviderReference = null;
        store.Save(passkey, Audit("passkey.failed", actor, passkey, new { reason }));
        logger.LogWarning("Passkey {Id} for {Login} at {Directory} failed: {Reason}",
            passkey.Id, passkey.ProviderLogin, passkey.Directory, reason);
    }

    private Task CancelQuietlyAsync(IPasskeyDirectory directory, PasskeyCredential passkey, CancellationToken ct) =>
        CancelQuietlyAsync(directory, new RegistrationHandle(
            new PasskeyUser(passkey.ProviderUserId, passkey.ProviderLogin), passkey.ProviderReference), ct);

    private async Task CancelQuietlyAsync(IPasskeyDirectory directory, RegistrationHandle handle, CancellationToken ct)
    {
        try
        {
            await directory.CancelRegistrationAsync(handle, ct);
        }
        catch (PasskeyDirectoryException e)
        {
            // Logged, not thrown: the failure being handled is the one worth
            // reporting. What is left behind shows up in the drift listing.
            logger.LogWarning("Could not cancel a pending registration at {Directory} for {Login}: {Error}",
                directory.Name, handle.User.Login, e.Message);
        }
    }

    private static async Task<T> Provider<T>(Func<Task<T>> call)
    {
        try
        {
            return await call();
        }
        catch (PasskeyDirectoryException e)
        {
            throw new PasskeyFlowException(502, "provider", e.Message);
        }
    }

    private AuditEvent Audit(string type, string actor, PasskeyCredential passkey, object detail, bool exempt = false) =>
        new()
        {
            OccurredAt = Now,
            EventType = type,
            Actor = actor,
            SubjectType = nameof(PasskeyCredential),
            SubjectId = passkey.Id == Guid.Empty ? null : passkey.Id,
            TokenSerial = passkey.TokenSerial,
            Detail = JsonSerializer.Serialize(detail, Json),
            IsExemptFromRetention = exempt,
        };
}

/// <summary>A refusal with an HTTP status and a code a console or an agent can act on.</summary>
public sealed class PasskeyFlowException(int status, string code, string message) : Exception(message)
{
    public int Status { get; } = status;

    public string Code { get; } = code;
}

public enum PasskeyDrift
{
    InSync,

    /// <summary>Registered here, gone at the provider: somebody removed it there.</summary>
    MissingAtProvider,

    /// <summary>Revoked here, still at the provider: a revocation that did not take.</summary>
    StillAtProvider,

    /// <summary>At the provider, never made by Blinky.</summary>
    ProviderOnly,
}

/// <summary>One passkey, as the console follows it.</summary>
/// <param name="PinSetByAgent">Whether a PIN was set on the workstation. Never what it was.</param>
public sealed record PasskeyStatus(
    Guid Id,
    string Directory,
    string Login,
    string State,
    string? JobState,
    long? TokenSerial,
    string? KeyName,
    bool PinSetByAgent,
    string? MethodId,
    string? FailureReason,
    DateTime? ChallengeDeadlineAt,
    DateTime? RegisteredAt,
    DateTime? RevokedAt);

/// <summary>
/// A provider the console names and cannot use, with the reason. Google today: it
/// accepts no attestation on a user's behalf, and leaving it out of the list would
/// let somebody assume it was simply not configured.
/// </summary>
public sealed record AnalysisOnlyDirectory(string Name, string Reason)
{
    public static readonly IReadOnlyList<AnalysisOnlyDirectory> All =
    [
        new("Google Workspace",
            "Google exposes no API that accepts a passkey registered on a user's behalf; users enrol their own keys. See docs/12 section 7."),
    ];
}

/// <param name="Id">Blinky's row, null for a provider-only method.</param>
/// <param name="ProviderStatus">Okta's factor status; a pending one is a ceremony nobody cleaned up.</param>
public sealed record PasskeyListing(
    Guid? Id,
    string? MethodId,
    string? Name,
    string? State,
    long? TokenSerial,
    Guid? Aaguid,
    DateTime? CreatedAt,
    PasskeyDrift Drift,
    string? ProviderStatus);
