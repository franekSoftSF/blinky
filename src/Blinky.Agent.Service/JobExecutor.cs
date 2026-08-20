using Blinky.Contracts;

namespace Blinky.Agent.Service;

/// <summary>
/// Runs the steps of a job and says what happened to each one.
/// </summary>
/// <remarks>
/// <para>
/// A failure names the step. "Enrolment failed" is not a diagnosis; "step 3
/// GenerateKey returned 6982" is, and these failures are read off someone
/// else's screen.
/// </para>
/// <para>
/// An operation the agent does not recognise is <b>refused</b>, not skipped.
/// Skipping would let a newer server quietly get a partial job done by an older
/// agent, and nothing would say so.
/// </para>
/// </remarks>
public sealed class JobExecutor(
    InventoryCollector collector,
    ICardEnrolment? enrolment,
    ICardSlots? cards,
    ILogger<JobExecutor> logger)
{
    public async Task<JobResult> ExecuteAsync(JobEnvelope job, BackendClient backend,
        int attempt, CancellationToken ct)
    {
        if (!Protocol.IsSupported(job.SchemaVersion))
        {
            return new JobResult(job.JobId, attempt, false, null,
                $"this agent speaks protocol {Protocol.MinimumSupportedVersion} to "
                + $"{Protocol.MaximumSupportedVersion}, and the job is version "
                + $"{job.SchemaVersion}");
        }

        // Every step is checked before any of them runs. Announcing a step and
        // then discovering it is unknown would leave a job half done with the
        // server told it had started.
        if (job.Steps.FirstOrDefault(s => !Supported.Contains(s.Op)) is { } unknown)
        {
            logger.LogError("Job {JobId}: this agent does not know the step {Op}",
                job.JobId, unknown.Op);

            return new JobResult(job.JobId, attempt, false, unknown.Op,
                "UnsupportedOperation: this agent does not know this step");
        }

        foreach (var step in job.Steps)
        {
            await backend.ReportProgressAsync(
                new JobProgress(job.JobId, attempt, JobState.Running, step.Op), ct);

            try
            {
                await RunAsync(job, step, backend, attempt, ct);
            }
            catch (Piv.PivException ex)
            {
                // The status word goes back verbatim. Without it "enrolment
                // failed" is all anybody gets.
                return new JobResult(job.JobId, attempt, false, step.Op, ex.Message,
                    ex.Status.ToString());
            }
            catch (Exception ex)
            {
                return new JobResult(job.JobId, attempt, false, step.Op, ex.Message);
            }
        }

        return new JobResult(job.JobId, attempt, true);
    }

    /// <summary>
    /// Every operation this agent knows. A server that sends anything else is
    /// newer than this agent, and the job is refused rather than partly done.
    /// </summary>
    public static readonly IReadOnlySet<string> Supported =
        new HashSet<string>(StringComparer.Ordinal)
        {
            "ReadAllReaders", "EnrolCredential", "RecycleSlot",
        };

    private async Task RunAsync(JobEnvelope job, JobStep step, BackendClient backend,
        int attempt, CancellationToken ct)
    {
        switch (step.Op)
        {
            case "ReadAllReaders":
            {
                var sweep = collector.ReadAll();

                foreach (var report in sweep.Tokens)
                {
                    await backend.ReportInventoryAsync(report, ct);
                }

                logger.LogInformation("Inventory step read {Tokens} tokens and {Unsupported} "
                                      + "cards this version cannot manage",
                    sweep.Tokens.Count, sweep.Unsupported.Count);

                return;
            }

            case "EnrolCredential":
            {
                if (enrolment is null)
                {
                    throw new InvalidOperationException(
                        "This agent cannot enrol: it needs a card reader and an interactive "
                        + "session, and this build has neither on this platform.");
                }

                await enrolment!.EnrolAsync(job, step, backend, attempt, ct);
                return;
            }

            case "RecycleSlot":
            {
                if (cards is null)
                {
                    throw new InvalidOperationException(
                        "This agent cannot reach a card reader on this platform.");
                }

                var serial = job.TokenSerial
                             ?? throw new InvalidOperationException(
                                 "A recycle names its token.");

                // ordered: the backend asked, so the guard that stops a person
                // deleting a credential Blinky issued does not apply. The
                // server is the thing that guard protects, and it is the one
                // asking.
                var result = await cards.DeleteCertificateAsync(serial, step.Argument("slot"),
                    alsoTheKey: true, ct, ordered: true);

                if (!result.Succeeded)
                {
                    throw new InvalidOperationException(result.Error ?? "the slot was not cleared");
                }

                return;
            }

            default:
                // Unreachable: the step list is checked before anything runs.
                throw new InvalidOperationException($"Unhandled step {step.Op}");
        }
    }
}
