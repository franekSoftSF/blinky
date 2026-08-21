using System.Text.Json;
using Blinky.Api.Persistence;
using Blinky.Contracts;
using Blinky.Domain.Entities;
using NHibernate.Linq;

namespace Blinky.Api.Jobs;

/// <summary>
/// Creates work, hands it out, and takes back what happened.
/// </summary>
/// <remarks>
/// <para>
/// Delivery is at least once; execution must be at most once where it matters.
/// The two mechanisms for that are an idempotency key, so the same logical job
/// cannot become two rows, and a <b>lease</b> rather than a lock, so a
/// workstation that loses power does not hold work for ever.
/// </para>
/// <para>
/// The API hands out work. It never decides on its own that work exists — that
/// is the worker's job, and keeping it there is why the worker is a single
/// replica. See docs/01-architecture.md.
/// </para>
/// </remarks>
public sealed class JobService(Database database, ILogger<JobService> logger)
{
    private static readonly JsonSerializerOptions Json = new(JsonSerializerDefaults.Web);

    /// <summary>
    /// Marks what a completed revocation took off the token.
    /// </summary>
    /// <remarks>
    /// The slot goes back to <c>Empty</c> and the credential to <c>Revoked</c>.
    /// Revoked rather than deleted: the row is the history of a credential that
    /// existed, and an audit that cannot say what was withdrawn is not an audit.
    /// </remarks>
    private void Withdraw(NHibernate.ISession session, Job job)
    {
        var envelope = JsonSerializer.Deserialize<JobEnvelope>(job.Payload, Json);

        var slotId = envelope?.Steps.FirstOrDefault()?.Argument("slot");

        if (slotId is null || job.TokenSerial is not { } serial)
        {
            return;
        }

        var now = DateTime.UtcNow;
        var withdrawn = false;

        foreach (var credential in session.Query<Credential>()
                     .Where(c => c.Token.Serial == serial && c.SlotId == slotId)
                     .ToList()
                     .Where(c => c.State is not Blinky.Domain.CredentialState.Revoked))
        {
            credential.State = Blinky.Domain.CredentialState.Revoked;

            // Both of these, not just the state. A credential marked revoked
            // with no timestamp is one the revocation list has to guess about,
            // and "when" is what a relying party is told - a CRL entry carries
            // a revocation date whether or not anybody recorded one.
            credential.RevokedAt = now;
            credential.RevocationReason ??= Blinky.Pki.X509RevocationReason.Superseded.ToString();
            credential.UpdatedAt = now;
            session.Update(credential);

            withdrawn = true;

            logger.LogInformation("Credential {Serial} in slot {Slot} of token {Token} was "
                                  + "withdrawn", credential.SerialNumber, slotId, serial);
        }

        // Now, not at the next scheduled publication. A credential taken off a
        // card that is still good on every revocation list for another two
        // hours is a credential that still works.
        if (withdrawn)
        {
            RequestCrlPublication($"recycled:{serial}:{slotId}");
        }

        var slot = session.Query<Slot>()
            .SingleOrDefault(s => s.Token.Serial == serial && s.SlotId == slotId);

        if (slot is not null)
        {
            slot.State = Blinky.Domain.SlotState.Empty;
            slot.Credential = null;
            slot.UpdatedAt = now;
            session.Update(slot);
        }
    }

    /// <summary>How long a claimed job stays claimed before the watchdog takes it back.</summary>
    public static readonly TimeSpan LeaseDuration = TimeSpan.FromMinutes(5);

    /// <summary>
    /// A job waiting for a person has a much longer deadline. A prompt for a
    /// PIN or a finger is not a hung APDU, and reaping it would fail every
    /// enrolment on a touch-policy profile.
    /// </summary>
    public static readonly TimeSpan AwaitingUserLease = TimeSpan.FromMinutes(30);

    /// <summary>
    /// Creates a job, or returns the existing one with the same idempotency
    /// key. Re-creating is not an error: a retry after a timeout must not
    /// produce a second job for the same intent.
    /// </summary>
    /// <remarks>
    /// <paramref name="buildEnvelope"/> receives the row's identifier, because
    /// the envelope has to carry the same one. An envelope built with an
    /// identifier of its own would leave the agent reporting progress against
    /// a job that does not exist - and, since a rejected report was ignored,
    /// doing the work and calling it a success while the row sat untouched
    /// until the watchdog reclaimed it.
    /// </remarks>
    /// <summary>
    /// Asks for the revocation list to be rebuilt and published now.
    /// </summary>
    /// <remarks>
    /// <para>
    /// A revocation that waits for the next scheduled publication is a
    /// certificate that still works. Two hours is a reasonable interval for
    /// keeping a list fresh and an unreasonable one for a card somebody
    /// reported lost this morning.
    /// </para>
    /// <para>
    /// A request rather than the work: this process does not build the list.
    /// The worker does, from one place, and it polls for these in seconds. The
    /// API asking is the same shape as an operator asking for an enrolment -
    /// a row, claimed and reported on like any other.
    /// </para>
    /// <para>
    /// Keyed on what caused it, so the same revocation asked for twice is one
    /// job. Bounded by the number of revocations, which is the right number of
    /// rows for something that has to be auditable anyway.
    /// </para>
    /// </remarks>
    public void RequestCrlPublication(string cause)
    {
        var (_, created) = Create(JobType.PublishCrl, $"publish-crl:{cause}",
            id => new JobEnvelope(Protocol.SchemaVersion, id, JobType.PublishCrl,
                $"publish-crl:{cause}", DateTimeOffset.UtcNow.AddHours(1), null, []),
            deadline: TimeSpan.FromHours(1));

        if (created)
        {
            logger.LogInformation("Asked for the revocation list to be republished ({Cause})",
                cause);
        }
    }

    public (Job Job, bool Created) Create(JobType type, string idempotencyKey,
        Func<Guid, JobEnvelope> buildEnvelope, Guid? agentId = null, TimeSpan? deadline = null)
    {
        using var session = database.OpenSession();
        using var transaction = session.BeginTransaction();

        var existing = session.Query<Job>().SingleOrDefault(j => j.IdempotencyKey == idempotencyKey);
        if (existing is not null)
        {
            return (existing, false);
        }

        var now = DateTime.UtcNow;
        var job = new Job
        {
            Type = type,
            State = JobState.Pending,
            IdempotencyKey = idempotencyKey,
            AgentId = agentId,
            Payload = "{}",
            DeadlineAt = now.Add(deadline ?? TimeSpan.FromHours(1)),
            CreatedAt = now,
            UpdatedAt = now,
        };

        session.Save(job);

        // Now that the row has its identifier, the envelope can carry it.
        var envelope = buildEnvelope(job.Id);
        job.TokenSerial = envelope.TokenSerial;
        job.Payload = JsonSerializer.Serialize(envelope, Json);

        session.Update(job);
        transaction.Commit();

        logger.LogInformation("Job {JobId} created: {Type} ({Key})", job.Id, type, idempotencyKey);

        return (job, true);
    }

    /// <summary>
    /// Hands one job to an agent and takes a lease on it.
    /// </summary>
    /// <remarks>
    /// A job addressed to a particular agent goes only to that agent;
    /// everything else is fair game. The claim is a single transaction, so two
    /// agents polling at once cannot both take the same row.
    /// </remarks>
    public JobClaim? Claim(Guid agentId)
    {
        using var session = database.OpenSession();
        using var transaction = session.BeginTransaction();

        var now = DateTime.UtcNow;

        // Server-side work is filtered out here rather than left for the agent
        // to reject. An agent that claims a job it cannot do holds it for the
        // length of a lease, hands it back to the watchdog, and takes it again
        // - a loop with no error in it and no progress either.
        //
        // Written as an exclusion list rather than a call into JobTypes so the
        // provider can translate it: NHibernate has to turn this into SQL, and
        // a method it does not know becomes a table scan in memory.
        var job = session.Query<Job>()
            .Where(j => j.State == JobState.Pending
                        && j.DeadlineAt > now
                        && j.Type != JobType.PublishCrl
                        && (j.AgentId == null || j.AgentId == agentId))
            .OrderBy(j => j.CreatedAt)
            .FirstOrDefault();

        if (job is null)
        {
            return null;
        }

        job.State = JobState.Claimed;
        job.AgentId = agentId;
        job.Attempt += 1;
        job.LeaseExpiresAt = now.Add(LeaseDuration);
        job.UpdatedAt = now;

        session.Update(job);
        transaction.Commit();

        var envelope = JsonSerializer.Deserialize<JobEnvelope>(job.Payload, Json)
                       ?? throw new InvalidOperationException(
                           $"Job {job.Id} has an unreadable payload.");

        return new JobClaim(envelope, job.LeaseExpiresAt!.Value, job.Attempt);
    }

    /// <summary>
    /// Records a state change from the agent, and extends the lease.
    /// </summary>
    /// <returns>False when the job is not this agent's to report on.</returns>
    public bool Report(Guid agentId, JobProgress progress)
    {
        using var session = database.OpenSession();
        using var transaction = session.BeginTransaction();

        var job = session.Get<Job>(progress.JobId);
        if (job is null || job.AgentId != agentId)
        {
            return false;
        }

        var now = DateTime.UtcNow;

        job.State = progress.State;
        job.UpdatedAt = now;
        job.LeaseExpiresAt = now.Add(progress.State is JobState.AwaitingUser
            ? AwaitingUserLease
            : LeaseDuration);

        session.Update(job);
        transaction.Commit();

        logger.LogInformation("Job {JobId} is {State}{Step}", job.Id, progress.State,
            progress.Step is null ? string.Empty : $" at {progress.Step}");

        return true;
    }

    /// <summary>
    /// Takes the outcome. Idempotent on attempt: a retried submission after a
    /// network timeout is a no-op rather than a second ending.
    /// </summary>
    public bool Complete(Guid agentId, JobResult result)
    {
        using var session = database.OpenSession();
        using var transaction = session.BeginTransaction();

        var job = session.Get<Job>(result.JobId);
        if (job is null || job.AgentId != agentId)
        {
            return false;
        }

        if (job.State is JobState.Succeeded or JobState.Failed && job.Attempt == result.Attempt)
        {
            return true;
        }

        var now = DateTime.UtcNow;

        // A withdrawal that reached the card has to reach the record too. This
        // was the whole argument for making the agent refuse a tray-driven
        // delete: a credential gone from the token and still reading Installed
        // here is the divergence, whoever created it. Observed doing exactly
        // that before this existed.
        if (result.Succeeded && job.Type == JobType.Revoke)
        {
            Withdraw(session, job);
        }

        job.State = result.Succeeded ? JobState.Succeeded : JobState.Failed;
        job.Result = JsonSerializer.Serialize(result, Json);
        job.LeaseExpiresAt = null;
        job.UpdatedAt = now;

        session.Update(job);

        session.Save(new AuditEvent
        {
            OccurredAt = now,
            EventType = result.Succeeded ? "job.succeeded" : "job.failed",
            Actor = agentId.ToString(),
            SubjectType = nameof(Job),
            SubjectId = job.Id,
            TokenSerial = job.TokenSerial,
            Detail = job.Result,
        });

        transaction.Commit();

        return true;
    }
}
