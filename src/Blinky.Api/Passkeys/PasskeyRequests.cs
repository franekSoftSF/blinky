using System.Text.Json;
using Blinky.Api.Persistence;
using Blinky.Contracts;
using Blinky.Domain;
using Blinky.Domain.Entities;
using NHibernate.Linq;

namespace Blinky.Api.Passkeys;

/// <summary>What an operator chooses when saying yes - everything the workstation did not.</summary>
public sealed record PasskeyRequestApproval(
    string Directory,
    Fido2PinMode PinMode = Fido2PinMode.ProvisionalRandom,
    int MinPinLength = 6,
    bool ForceChangePin = true,
    string? KeyName = null,
    bool AppendSerial = true);

/// <summary>A request as the console lists it.</summary>
public sealed record PasskeyRequestRow(
    Guid Id,
    long TokenSerial,
    Guid CardholderId,
    string Holder,
    string? Upn,
    Guid AgentId,
    string? Workstation,
    string State,
    Guid? JobId,
    string? DecidedBy,
    string? RejectionReason,
    DateTime CreatedAt,
    DateTime? DecidedAt);

/// <summary>
/// Passkey requests from workstations, and an operator's answer to them (0109).
/// </summary>
/// <remarks>
/// <para>
/// The workstation asks and the console decides. Approval goes through
/// <see cref="PasskeyJobs"/>, the same door as the operator's own form, with the
/// request's id as the reason: approving the same request twice is one job,
/// and the job is given to the agent that asked, not to whichever agent polls
/// first.
/// </para>
/// <para>
/// The holder comes from the token, not from the workstation. Nothing on the
/// agent side knows who is signed in, and a name typed into a tray would be a
/// claim anybody at that keyboard could make; a token issued to somebody is a
/// fact the console recorded when it was issued.
/// </para>
/// </remarks>
public sealed class PasskeyRequests(Database database, PasskeyJobs jobs)
{
    private static readonly JsonSerializerOptions Json = new(JsonSerializerDefaults.Web);

    private static DateTime Now => DateTime.UtcNow;

    /// <summary>Records a request for the token, or returns the one already pending.</summary>
    public PasskeyRequestView Ask(Guid agentId, long serial)
    {
        using var session = database.OpenSession();
        using var transaction = session.BeginTransaction();

        var pending = session.Query<PasskeyRequest>()
            .Where(r => r.TokenSerial == serial && r.State == PasskeyRequestState.Pending)
            .OrderByDescending(r => r.CreatedAt)
            .FirstOrDefault();

        if (pending is not null)
        {
            return View(pending);
        }

        var token = session.Query<Token>().SingleOrDefault(t => t.Serial == serial)
                    ?? throw new PasskeyFlowException(404, "unknown-token",
                        "Blinky does not know this key. It has to be issued from the console first.");

        var holder = token.Cardholder
                     ?? throw new PasskeyFlowException(409, "no-holder",
                         "This key is not issued to anybody, so there is nobody to make a passkey for.");

        var request = new PasskeyRequest
        {
            TokenSerial = serial,
            Cardholder = holder,
            AgentId = agentId,
            CreatedAt = Now,
            UpdatedAt = Now,
        };

        session.Save(request);
        session.Save(Audit("passkey-request.asked", agentId.ToString(), request,
            new { holder = holder.Upn ?? holder.DisplayName }));

        transaction.Commit();

        return View(request);
    }

    /// <summary>The newest request for a token, whatever its state.</summary>
    public PasskeyRequestView? Latest(long serial)
    {
        using var session = database.OpenSession();

        var latest = session.Query<PasskeyRequest>()
            .Where(r => r.TokenSerial == serial)
            .OrderByDescending(r => r.CreatedAt)
            .FirstOrDefault();

        return latest is null ? null : View(latest);
    }

    public IReadOnlyList<PasskeyRequestRow> List(PasskeyRequestState? state)
    {
        using var session = database.OpenSession();

        var query = session.Query<PasskeyRequest>().Fetch(r => r.Cardholder).AsQueryable();

        if (state is { } wanted)
        {
            query = query.Where(r => r.State == wanted);
        }

        var requests = query.OrderByDescending(r => r.CreatedAt).Take(200).ToList();

        var agentIds = requests.Select(r => r.AgentId).Distinct().ToList();
        var hosts = session.Query<Agent>()
            .Where(a => agentIds.Contains(a.Id))
            .ToList()
            .ToDictionary(a => a.Id, a => a.Hostname);

        return requests.Select(r => new PasskeyRequestRow(
                r.Id, r.TokenSerial, r.Cardholder.Id, r.Cardholder.DisplayName, r.Cardholder.Upn,
                r.AgentId, hosts.GetValueOrDefault(r.AgentId), r.State.ToString(), r.JobId,
                r.DecidedBy, r.RejectionReason, r.CreatedAt, r.DecidedAt))
            .ToList();
    }

    /// <summary>
    /// Says yes: the job first, then the request marked. A failure in between
    /// leaves the request pending, and approving again finds the same job by
    /// its idempotency key rather than making a second.
    /// </summary>
    public async Task<PasskeyJobCreated> ApproveAsync(Guid id, PasskeyRequestApproval approval, string actor,
        CancellationToken ct)
    {
        var request = Pending(id);

        var created = await jobs.CreateAsync(new PasskeyJobRequest(
            approval.Directory,
            CardholderId: request.Cardholder.Id,
            AgentId: request.AgentId,
            TokenSerial: request.TokenSerial,
            PinMode: approval.PinMode,
            MinPinLength: approval.MinPinLength,
            ForceChangePin: approval.ForceChangePin,
            KeyName: approval.KeyName,
            AppendSerial: approval.AppendSerial,
            Reason: $"request-{request.Id}"), actor, ct);

        Decide(id, actor, r => r.Approve(created.Job.Id, actor, Now), "passkey-request.approved",
            new { directory = approval.Directory, job = created.Job.Id });

        return created;
    }

    public void Reject(Guid id, string reason, string actor)
    {
        if (string.IsNullOrWhiteSpace(reason))
        {
            throw new PasskeyFlowException(400, "no-reason", "Say why: the reason is shown at the workstation.");
        }

        Pending(id);
        Decide(id, actor, r => r.Reject(reason, actor, Now), "passkey-request.rejected", new { reason });
    }

    private PasskeyRequest Pending(Guid id)
    {
        using var session = database.OpenSession();

        var request = session.Query<PasskeyRequest>().Fetch(r => r.Cardholder).SingleOrDefault(r => r.Id == id)
                      ?? throw new PasskeyFlowException(404, "no-such-request", "There is no passkey request with that id.");

        return request.State == PasskeyRequestState.Pending
            ? request
            : throw new PasskeyFlowException(409, "already-decided", $"This request was already {request.State}.");
    }

    private void Decide(Guid id, string actor, Action<PasskeyRequest> decide, string eventType, object detail)
    {
        using var session = database.OpenSession();
        using var transaction = session.BeginTransaction();

        var request = session.Get<PasskeyRequest>(id)!;

        try
        {
            decide(request);
        }
        catch (InvalidOperationException e)
        {
            // Two operators answering at once: the second one finds it decided.
            throw new PasskeyFlowException(409, "already-decided", e.Message);
        }

        session.Update(request);
        session.Save(Audit(eventType, actor, request, detail));

        transaction.Commit();
    }

    private static PasskeyRequestView View(PasskeyRequest request) =>
        new(request.Id, request.TokenSerial, request.State.ToString(), request.RejectionReason,
            request.CreatedAt, request.DecidedAt);

    private static AuditEvent Audit(string type, string actor, PasskeyRequest request, object detail) =>
        new()
        {
            OccurredAt = Now,
            EventType = type,
            Actor = actor,
            SubjectType = nameof(PasskeyRequest),
            SubjectId = request.Id,
            TokenSerial = request.TokenSerial,
            Detail = JsonSerializer.Serialize(detail, Json),
        };
}
