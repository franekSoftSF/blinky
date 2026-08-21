using Blinky.Contracts;
using Blinky.Domain.Entities;
using Blinky.Pki;
using NHibernate;
using NHibernate.Linq;
using DomainCredentialState = Blinky.Domain.CredentialState;

namespace Blinky.Worker;

/// <summary>
/// Runs the jobs no agent can: the ones with no card at the other end.
/// </summary>
/// <remarks>
/// <para>
/// The same engine as everything else. A maintenance job is claimed, held on a
/// lease, reports a result and is retried by the watchdog if this process dies
/// holding it — which is the point of putting it here rather than in a loop of
/// its own.
/// </para>
/// <para>
/// In the worker because the worker is the one replica that owns work which
/// must happen exactly once. Two of these building a revocation list at the
/// same time would both be right and one would win, which is not a
/// catastrophe; two of them scheduling would be worse. Either way, one.
/// </para>
/// </remarks>
public sealed class MaintenanceRunner(
    ISessionFactory sessions,
    ICertificateAuthority authority,
    MaintenanceOptions options,
    ILogger<MaintenanceRunner> logger) : BackgroundService
{
    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        while (!stoppingToken.IsCancellationRequested)
        {
            try
            {
                while (await RunOneAsync(stoppingToken))
                {
                    // Drain: a restart can leave several periods queued and
                    // there is no reason to spread them over minutes.
                }
            }
            catch (Exception ex) when (ex is not OperationCanceledException)
            {
                logger.LogError(ex, "Maintenance failed");
            }

            try
            {
                await Task.Delay(options.Poll, stoppingToken);
            }
            catch (OperationCanceledException)
            {
                return;
            }
        }
    }

    /// <returns>True when there was one to run, so the caller can look again.</returns>
    private async Task<bool> RunOneAsync(CancellationToken ct)
    {
        Job? job;
        var now = DateTime.UtcNow;

        using (var session = sessions.OpenSession())
        using (var transaction = session.BeginTransaction())
        {
            job = session.Query<Job>()
                .Where(j => j.State == JobState.Pending
                            && j.Type == JobType.PublishCrl
                            && j.DeadlineAt > now)
                .OrderBy(j => j.CreatedAt)
                .FirstOrDefault();

            if (job is null)
            {
                return false;
            }

            job.State = JobState.Running;
            job.Attempt += 1;
            job.LeaseExpiresAt = now.AddMinutes(5);
            job.UpdatedAt = now;

            session.Update(job);
            transaction.Commit();
        }

        try
        {
            var summary = await PublishCrlAsync(ct);
            Finish(job.Id, JobState.Succeeded, summary);
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            // Named in the record rather than only in the log, so the console
            // can say what went wrong without anybody reading a container.
            Finish(job.Id, JobState.Failed, ex.Message);
            logger.LogError(ex, "Publishing the revocation list failed");
        }

        return true;
    }

    private void Finish(Guid id, JobState state, string detail)
    {
        using var session = sessions.OpenSession();
        using var transaction = session.BeginTransaction();

        if (session.Get<Job>(id) is not { } job)
        {
            return;
        }

        job.State = state;
        job.Result = System.Text.Json.JsonSerializer.Serialize(new
        {
            succeeded = state is JobState.Succeeded,
            detail,
        });
        job.LeaseExpiresAt = null;
        job.UpdatedAt = DateTime.UtcNow;

        session.Update(job);
        transaction.Commit();
    }

    /// <summary>
    /// Replays every revoked credential onto the list and writes it out.
    /// </summary>
    /// <remarks>
    /// Rebuilt from the database rather than accumulated, because the store it
    /// fills is in-process and forgets everything when this restarts — and a
    /// revocation list that quietly forgets who was revoked is worse than none,
    /// since everybody trusts it. The credential rows are the record; this is a
    /// projection of them.
    /// </remarks>
    private async Task<string> PublishCrlAsync(CancellationToken ct)
    {
        var replayed = 0;

        using (var session = sessions.OpenSession())
        {
            var revoked = session.Query<Credential>()
                .Where(c => c.RevokedAt != null || c.State == DomainCredentialState.Revoked)
                .ToList();

            foreach (var credential in revoked)
            {
                if (string.IsNullOrEmpty(credential.SerialNumber))
                {
                    // Revoked before it was ever issued: no serial number, and
                    // so nothing for a relying party to check.
                    continue;
                }

                var reason = Enum.TryParse<X509RevocationReason>(
                    credential.RevocationReason, ignoreCase: true, out var parsed)
                    ? parsed
                    : X509RevocationReason.Unspecified;

                await authority.RevokeAsync(
                    new RevocationRequest(credential.SerialNumber, reason), ct);

                replayed++;
            }
        }

        var crl = await authority.GetCrlAsync(ct)
                  ?? throw new InvalidOperationException(
                      "This CA publishes no revocation list, so nothing was written.");

        WriteAtomically(options.File, crl.Der);

        return $"{replayed} certificate(s), valid until {crl.NextUpdate:u}";
    }

    /// <summary>
    /// Writes beside the target and renames over it.
    /// </summary>
    /// <remarks>
    /// A reader that opens the file mid-write gets half a CRL, and half a CRL
    /// does not parse — which a relying party reports as a revocation check
    /// that failed rather than as a file that was busy.
    /// </remarks>
    private void WriteAtomically(string path, byte[] der)
    {
        var directory = Path.GetDirectoryName(path);
        if (!string.IsNullOrEmpty(directory))
        {
            Directory.CreateDirectory(directory);
        }

        var temporary = path + ".new";
        File.WriteAllBytes(temporary, der);
        File.Move(temporary, path, overwrite: true);

        logger.LogDebug("Revocation list written to {Path} ({Bytes} bytes)", path, der.Length);
    }
}

/// <param name="Poll">How often to look for maintenance work.</param>
/// <param name="File">Where the revocation list is written, as DER.</param>
public sealed record MaintenanceOptions(TimeSpan Poll, string File);
