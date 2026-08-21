using Blinky.Contracts;
using Blinky.Domain.Entities;
using NHibernate;
using NHibernate.Linq;

namespace Blinky.Worker;

/// <summary>
/// Creates the jobs nobody asks for.
/// </summary>
/// <remarks>
/// <para>
/// Recurring work used to be a loop in the API doing the thing directly. That
/// works and is invisible: nothing appears in the console, a failure is a log
/// line, there are no attempts, no lease, no watchdog, and no record that it
/// ever ran. The job engine already provides all of that, and the way to get
/// it is to make the work a job.
/// </para>
/// <para>
/// So this schedules rather than does. It writes a row and the runner picks it
/// up, which means a scheduled task and an operator-requested one are the same
/// kind of thing all the way down — visible in the same list, retried by the
/// same watchdog, reported the same way.
/// </para>
/// <para>
/// <b>The idempotency key carries the period.</b> A restart, a second replica
/// or a clock that jumps produces the same key and therefore the same job
/// rather than a second one. That is the whole reason the engine has
/// idempotency keys, and it is what makes "generate work on a timer" safe
/// without a lock anywhere.
/// </para>
/// </remarks>
public sealed class ScheduledJobs(
    ISessionFactory sessions,
    ScheduleOptions options,
    ILogger<ScheduledJobs> logger) : BackgroundService
{
    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        logger.LogInformation(
            "Scheduler running: the revocation list is republished every {Interval}",
            options.CrlInterval);

        while (!stoppingToken.IsCancellationRequested)
        {
            try
            {
                Schedule(JobType.PublishCrl, options.CrlInterval, options.CrlDeadline);
            }
            catch (Exception ex) when (ex is not OperationCanceledException)
            {
                logger.LogError(ex, "Could not schedule work");
            }

            try
            {
                await Task.Delay(options.Tick, stoppingToken);
            }
            catch (OperationCanceledException)
            {
                return;
            }
        }
    }

    /// <summary>
    /// Makes sure this period's job exists.
    /// </summary>
    private void Schedule(JobType type, TimeSpan every, TimeSpan deadline)
    {
        var now = DateTime.UtcNow;

        // The period this instant falls in, as a number. Two ticks inside one
        // period build the same key and so create one job; the next period
        // builds a different one.
        var period = now.Ticks / every.Ticks;
        var key = $"schedule:{type}:{period}";

        using var session = sessions.OpenSession();
        using var transaction = session.BeginTransaction();

        if (session.Query<Job>().Any(j => j.IdempotencyKey == key))
        {
            return;
        }

        var job = new Job
        {
            Type = type,
            State = JobState.Pending,
            IdempotencyKey = key,
            Payload = "{}",

            // Deliberately short. A missed publication is picked up by the next
            // period, and a job still queued when its successor arrives is one
            // nobody is going to run - better expired than accumulating.
            DeadlineAt = now.Add(deadline),
            CreatedAt = now,
            UpdatedAt = now,
        };

        session.Save(job);
        transaction.Commit();

        logger.LogInformation("Scheduled {Type} for this period ({Key})", type, key);
    }
}

/// <param name="Tick">
/// How often to look. Well under the shortest interval, so a period is never
/// stepped over.
/// </param>
/// <param name="CrlInterval">How often the revocation list is republished.</param>
/// <param name="CrlDeadline">
/// How long one of those jobs stays worth running.
/// </param>
public sealed record ScheduleOptions(
    TimeSpan Tick,
    TimeSpan CrlInterval,
    TimeSpan CrlDeadline);
