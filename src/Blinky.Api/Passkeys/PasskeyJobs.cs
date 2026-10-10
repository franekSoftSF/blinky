using Blinky.Api.Jobs;
using Blinky.Api.Persistence;
using Blinky.Contracts;
using Blinky.Domain.Entities;
using Blinky.Passkeys;

namespace Blinky.Api.Passkeys;

/// <summary>A passkey for somebody, at a named provider, on a key at a workstation.</summary>
/// <param name="User">UPN, login or provider id. Optional when a cardholder with a UPN is named.</param>
/// <param name="TokenSerial">Null when any key plugged into the agent will do.</param>
public sealed record PasskeyJobRequest(
    string Directory,
    string? User = null,
    Guid? CardholderId = null,
    Guid? AgentId = null,
    long? TokenSerial = null,
    Fido2PinMode PinMode = Fido2PinMode.ProvisionalRandom,
    int MinPinLength = 6,
    bool ForceChangePin = true,
    string? KeyName = null,
    bool AppendSerial = true,
    string? Reason = null);

/// <summary>What a request became: the job, whether it is new, the row, and who it is for.</summary>
public sealed record PasskeyJobCreated(Job Job, bool Created, PasskeyCredential Passkey, PasskeyUser User);

/// <summary>
/// Turns a request into a <c>ProvisionFido2Credential</c> job and its passkey row.
/// </summary>
/// <remarks>
/// One place, for every way the work gets asked for: the operator's form, and an
/// operator approving a request a workstation sent. The user is resolved at the
/// provider before any job exists, so a login that is not there is refused before
/// anybody goes to find a key - whichever door the request came through.
/// </remarks>
public sealed class PasskeyJobs(JobService jobs, Database database, PasskeyProvisioningService passkeys)
{
    public async Task<PasskeyJobCreated> CreateAsync(PasskeyJobRequest request, string actor, CancellationToken ct)
    {
        var identifier = request.User;
        string? holder = null;

        if (request.CardholderId is { } personId)
        {
            using var people = database.OpenSession();
            var person = people.Get<Cardholder>(personId)
                         ?? throw new PasskeyFlowException(404, "no-such-cardholder", "There is no cardholder with that id.");

            identifier ??= person.Upn;
            holder = person.DisplayName;
        }

        if (string.IsNullOrWhiteSpace(identifier))
        {
            throw new PasskeyFlowException(400, "no-user", "Name the user, or a cardholder with a UPN.");
        }

        var pin = new Fido2PinPolicy(request.PinMode, request.MinPinLength, request.ForceChangePin);
        passkeys.Check(request.Directory, pin);

        var user = await passkeys.ResolveAsync(request.Directory, identifier, ct);
        var provisioning = new Fido2Provisioning(request.Directory, holder ?? user.DisplayName, pin,
            request.KeyName ?? "YubiKey", request.AppendSerial);

        // Directory, user, key and reason: the same request twice is one job,
        // and a new attempt after a failure is the operator's to ask for.
        var key = $"fido2:{request.Directory}:{user.Id}:{request.TokenSerial?.ToString() ?? "any"}"
                  + $":{request.Reason ?? "initial"}";

        var (job, created) = jobs.Create(JobType.ProvisionFido2Credential, key,
            id => JobEnvelope.ProvisionFido2(id, key, DateTimeOffset.UtcNow.AddHours(1),
                request.TokenSerial, provisioning,
                new JobContext(JobContext.Passkey, holder ?? user.DisplayName, null, actor,
                    Provider: request.Directory, Login: user.Login)),
            request.AgentId, cardholderId: request.CardholderId);

        var passkey = passkeys.Record(job.Id, request.Directory, user, request.CardholderId,
            request.TokenSerial, actor);

        return new PasskeyJobCreated(job, created, passkey, user);
    }
}
