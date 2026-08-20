using Blinky.Contracts;
using Blinky.Domain.Entities;
using Blinky.Infrastructure;
using NHibernate;
using NHibernate.Linq;

namespace Blinky.Worker;

/// <summary>
/// Takes back work that nobody is doing any more.
/// </summary>
/// <remarks>
/// <para>
/// A claimed job carries a lease, not a lock. An agent that loses power in the
/// middle of one cannot release anything, so the only thing that can is the
/// server, and this is it.
/// </para>
/// <para>
/// Single replica by design. Two of these racing would return the same job
/// twice and hand one credential's work to two workstations — which is also
/// why the worker container is a single replica and the API never does this.
/// </para>
/// </remarks>
public sealed class JobWatchdog(
    ISessionFactory sessionFactory,
    ILogger<JobWatchdog> logger,
    TimeSpan interval) : BackgroundService
{
    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        logger.LogInformation("Job watchdog running every {Interval}", interval);

        while (!stoppingToken.IsCancellationRequested)
        {
            try
            {
                Sweep();
            }
            catch (Exception ex)
            {
                // A database that is briefly unavailable is not a reason to
                // stop reaping for the rest of the process's life.
                logger.LogWarning("Watchdog sweep failed: {Message}", ex.Message);
            }

            try
            {
                await Task.Delay(interval, stoppingToken);
            }
            catch (OperationCanceledException)
            {
                break;
            }
        }
    }

    /// <summary>One pass: expired leases go back, jobs past their deadline die.</summary>
    public int Sweep()
    {
        using var session = sessionFactory.OpenSession();
        using var transaction = session.BeginTransaction();

        var now = DateTime.UtcNow;
        var touched = 0;

        var abandoned = session.Query<Job>()
            .Where(j => j.LeaseExpiresAt != null
                        && j.LeaseExpiresAt < now
                        && (j.State == JobState.Claimed
                            || j.State == JobState.Running
                            || j.State == JobState.AwaitingUser))
            .ToList();

        foreach (var job in abandoned)
        {
            // Back to Pending, not to Failed. The work still needs doing, and
            // the attempt counter is what stops it retrying for ever.
            job.State = JobState.Pending;
            job.LeaseExpiresAt = null;
            job.UpdatedAt = now;

            session.Update(job);
            touched++;

            logger.LogWarning("Job {JobId} lease expired on attempt {Attempt}; returned to the queue",
                job.Id, job.Attempt);
        }

        var expired = session.Query<Job>()
            .Where(j => j.DeadlineAt < now
                        && j.State != JobState.Succeeded
                        && j.State != JobState.Failed
                        && j.State != JobState.Expired
                        && j.State != JobState.Cancelled)
            .ToList();

        foreach (var job in expired)
        {
            job.State = JobState.Expired;
            job.LeaseExpiresAt = null;
            job.UpdatedAt = now;

            session.Update(job);
            session.Save(new AuditEvent
            {
                OccurredAt = now,
                EventType = "job.expired",
                SubjectType = nameof(Job),
                SubjectId = job.Id,
                TokenSerial = job.TokenSerial,
                Detail = $$"""{"attempts":{{job.Attempt}}}""",
            });

            touched++;

            logger.LogWarning("Job {JobId} passed its deadline after {Attempt} attempts",
                job.Id, job.Attempt);
        }

        transaction.Commit();

        return touched;
    }
}
