using System.Diagnostics;
using Blinky.Contracts;
using Blinky.Piv.Pcsc;

namespace Blinky.Agent.Service;

/// <summary>
/// The agent's loop: make sure it has an identity, then keep telling the
/// backend what is in the readers.
/// </summary>
public sealed class AgentWorker(
    AgentOptions options,
    IAgentIdentity identity,
    InventoryCollector collector,
    JobExecutor executor,
    CardGate gate,
    BackendClient backend,
    ILogger<AgentWorker> logger) : BackgroundService
{
    private readonly HashSet<string> reportedUnsupported = new(StringComparer.OrdinalIgnoreCase);

    private static readonly string Version =
        FileVersionInfo.GetVersionInfo(typeof(AgentWorker).Assembly.Location).ProductVersion
        ?? "0.0.0";

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        if (!PcscContext.IsSupported)
        {
            logger.LogError("This build talks to readers through winscard.dll and is "
                            + "Windows-only. The agent has nothing to do here.");
            return;
        }

        if (options.ServerCertificateAuthorityPath is null or "" && options.AcceptAnyServerCertificate)
        {
            logger.LogWarning("The backend's certificate is not being checked. "
                              + "Set Agent:ServerCertificateAuthorityPath once the backend is "
                              + "not on this machine.");
        }

        Guid agentId;
        try
        {
            agentId = await EnsureIdentityAsync(backend, stoppingToken);
        }
        catch (Exception ex)
        {
            // Without an identity there is nothing useful to do, and retrying
            // in a tight loop would only make the log unreadable.
            logger.LogError(ex, "The agent could not obtain an identity");
            return;
        }

        logger.LogInformation("Agent {AgentId} started, polling every {Interval}s",
            agentId, options.PollIntervalSeconds);

        while (!stoppingToken.IsCancellationRequested)
        {
            await PollAsync(backend, agentId, stoppingToken);

            try
            {
                await Task.Delay(TimeSpan.FromSeconds(options.PollIntervalSeconds), stoppingToken);
            }
            catch (OperationCanceledException)
            {
                break;
            }
        }
    }

    /// <summary>
    /// Drains whatever work is waiting. The doorbell is an optimisation, never
    /// a correctness requirement - a poll finds the same work a second later.
    /// </summary>
    /// <returns>True when at least one job ran, so the caller can re-read.</returns>
    private async Task<bool> RunClaimedJobsAsync(BackendClient backend, CancellationToken ct)
    {
        var ranSomething = false;

        while (!ct.IsCancellationRequested)
        {
            var claim = await backend.ClaimJobAsync(ct);
            if (claim is null)
            {
                return ranSomething;
            }

            ranSomething = true;

            logger.LogInformation("Claimed job {JobId} ({Type}), attempt {Attempt}, "
                                  + "lease until {Lease:HH:mm:ss}",
                claim.Job.JobId, claim.Job.Type, claim.Attempt, claim.LeaseExpiresAt);

            var result = await executor.ExecuteAsync(claim.Job, backend, claim.Attempt, ct);

            try
            {
                await backend.CompleteJobAsync(result, ct);
            }
            catch (Exception ex)
            {
                // Work that the server did not record is work that will be
                // done again. Saying so is the difference between a retry and
                // a mystery.
                logger.LogError("Job {JobId} ran but the backend did not record the outcome: "
                                + "{Message}", claim.Job.JobId, ex.Message);

                return ranSomething;
            }

            logger.LogInformation("Job {JobId} {Outcome}{Step}", claim.Job.JobId,
                result.Succeeded ? "succeeded" : "failed",
                result.FailedStep is null ? string.Empty : $" at {result.FailedStep}");
        }

        return ranSomething;
    }

    private async Task<Guid> EnsureIdentityAsync(BackendClient backend, CancellationToken ct)
    {
        if (identity.Exists)
        {
            var existing = identity.ReadId();
            backend.Authenticate(identity.Load());

            // Where it came from, every time. The same machine run once as a
            // service and once by hand uses two different stores and enrols
            // twice, and without this line that is a mystery rather than a
            // sentence.
            logger.LogInformation("Using the existing identity {AgentId} from {Where}",
                existing, identity.Description);
            return existing;
        }

        if (string.IsNullOrWhiteSpace(options.BootstrapToken))
        {
            throw new InvalidOperationException(
                "No identity on disk and no bootstrap token configured. Set "
                + "Agent:BootstrapToken, or install with the MSI property.");
        }

        logger.LogInformation("Enrolling {Hostname}.{Domain} with {Backend}",
            options.Hostname, options.Domain, options.BackendUrl);

        var (agentId, certificatePem, key) = await backend.EnrolAsync(
            options.Hostname, options.Domain, options.BootstrapToken, ct);

        using (key)
        {
            identity.Store(agentId, certificatePem, key);
        }

        backend.Authenticate(identity.Load());

        return agentId;
    }

    /// <summary>
    /// Replaces the certificate before it expires.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Checked on every poll rather than only at startup: a workstation that
    /// stays up for months would otherwise sail past its expiry, and the ones
    /// that stay up longest are the ones nobody visits.
    /// </para>
    /// <para>
    /// <b>Before expiry, never after.</b> An expired certificate does not get a
    /// second chance here, and that is deliberate rather than an omission: the
    /// edge verifies client certificates during the TLS handshake, so an
    /// expired one cannot reach this endpoint at all. Accepting one would mean
    /// loosening verification at the edge for every request in order to rescue
    /// the few agents that slept through a month of warnings. Those re-enrol
    /// with a bootstrap token, which is the cost of having been switched off
    /// for ninety days.
    /// </para>
    /// <para>
    /// A failure is logged and shrugged off. There is a month of runway, the
    /// next poll tries again, and an agent that stops working because a renewal
    /// failed once would be worse than the problem.
    /// </para>
    /// </remarks>
    private async Task RenewIfDueAsync(BackendClient backend, Guid agentId, CancellationToken ct)
    {
        DateTime expires;
        DateTime issued;

        using (var current = identity.Load())
        {
            expires = current.NotAfter;
            issued = current.NotBefore;
        }

        var remaining = expires - DateTime.Now;

        if (remaining > TimeSpan.FromDays(options.RenewCertificateWithinDays))
        {
            return;
        }

        // A window wider than the certificate's own life means every
        // certificate is always due, and the agent renews on every poll -
        // observed doing exactly that, twice in thirty-one seconds, with the
        // window set to a year against a ninety-day certificate. The window is
        // a deployment setting and somebody will get it wrong; a certificate
        // issued today is not renewed again today whatever it says.
        if (DateTime.Now - issued < MinimumCertificateAge)
        {
            logger.LogWarning("The certificate expires in {Days} days, which is inside the "
                              + "renewal window, but it was issued {Age} ago - not renewing. "
                              + "Agent:RenewCertificateWithinDays looks wider than the "
                              + "certificates this backend issues.",
                (int)remaining.TotalDays, DateTime.Now - issued);

            return;
        }

        logger.LogInformation("The agent certificate expires in {Days} days; renewing",
            (int)remaining.TotalDays);

        try
        {
            var (certificatePem, key) = await backend.RenewAsync(agentId, ct);

            using (key)
            {
                identity.Store(agentId, certificatePem, key);
            }

            // Re-authenticated immediately: the backend moved the recorded
            // thumbprint when it issued, so the old certificate stops being
            // accepted from this moment and the next call must use the new one.
            backend.Authenticate(identity.Load());
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            logger.LogError("The agent certificate could not be renewed, {Days} days before "
                            + "it expires: {Message}", (int)remaining.TotalDays, ex.Message);
        }
    }

    /// <summary>
    /// How new is too new to replace. Guards against a renewal window wider
    /// than the certificate lifetime, which otherwise renews on every poll.
    /// </summary>
    private static readonly TimeSpan MinimumCertificateAge = TimeSpan.FromHours(12);

    private async Task PollAsync(BackendClient backend, Guid agentId, CancellationToken ct)
    {
        try
        {
            InventorySweep sweep;
            using (await gate.AcquireAsync(ct))
            {
                sweep = collector.ReadAll();
            }

            await RenewIfDueAsync(backend, agentId, ct);

            await backend.HeartbeatAsync(agentId, Version,
                [.. sweep.Tokens.Select(r => r.ReaderName)], sweep.Unsupported, ct);

            foreach (var card in sweep.Unsupported)
            {
                // Once per reader per run of the service: repeating it every
                // poll would bury everything else in the log.
                if (reportedUnsupported.Add(card.ReaderName))
                {
                    logger.LogWarning("Reader {Reader}: {Reason}", card.ReaderName, card.Reason);
                }
            }

            // Re-read when a job ran, because a job is precisely the thing that
            // changes what is on the card. Reporting the sweep taken at the top
            // of this method would post a picture from before the enrolment and
            // overwrite the state the enrolment just produced - a slot that
            // holds a certificate, recorded as empty, 50ms after it was
            // recorded as provisioned.
            if (await RunClaimedJobsAsync(backend, ct))
            {
                using var reread = await gate.AcquireAsync(ct);
                sweep = collector.ReadAll();
            }

            foreach (var report in sweep.Tokens)
            {
                var accepted = await backend.ReportInventoryAsync(report, ct);

                if (accepted is null)
                {
                    logger.LogWarning("The backend refused the report for token {Serial}",
                        report.Serial);
                    continue;
                }

                logger.LogInformation(
                    "Token {Serial} is {State} (puk={Puk}{Unrecoverable}){New}",
                    report.Serial, accepted.TokenState, accepted.PukState,
                    accepted.IsUnrecoverable ? ", unrecoverable" : string.Empty,
                    accepted.IsNewToken ? " - first time seen" : string.Empty);
            }
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            // The backend being unreachable is a normal condition on a laptop,
            // not something to fill a log with stack traces over.
            logger.LogWarning("Poll failed: {Message}", ex.Message);
        }
    }
}

/// <summary>Everything the agent needs to be told.</summary>
public sealed class AgentOptions
{
    public Uri BackendUrl { get; set; } = new("https://localhost:9443");

    /// <summary>
    /// Required, and never derived: the service runs as LocalSystem, whose
    /// UserDomainName is the machine name, so guessing produces a second
    /// orphaned agent row per machine.
    /// </summary>
    public string Domain { get; set; } = string.Empty;

    public string Hostname { get; set; } = Environment.MachineName.ToLowerInvariant();

    public string? BootstrapToken { get; set; }

    public int PollIntervalSeconds { get; set; } = 60;

    /// <summary>
    /// How long to wait for somebody to answer a prompt. Generous: a person
    /// walking back to their desk is not a failure.
    /// </summary>
    public int PromptTimeoutSeconds { get; set; } = 120;

    /// <summary>
    /// The CA that signed the backend's certificate. Copy `certs/dev-ca.crt`
    /// from the stack, or point at whatever signs it for real.
    /// </summary>
    public string? ServerCertificateAuthorityPath { get; set; }

    /// <summary>
    /// Single-machine bench only: check nothing about the backend. Ignored when
    /// a certificate authority is configured.
    /// </summary>
    public bool AcceptAnyServerCertificate { get; set; }

    public string? IdentityDirectory { get; set; }

    /// <summary>
    /// The rules a new PIN has to satisfy. Configuration for now; patch 0047
    /// has the backend publish it, because a rule that each workstation keeps
    /// its own copy of is several rules.
    /// </summary>
    public PinComplexityPolicy PinPolicy { get; set; } = PinComplexityPolicy.Default;

    /// <summary>
    /// How close to expiry the agent replaces its own certificate.
    /// </summary>
    /// <remarks>
    /// A month by default: long enough that a laptop switched off for a
    /// fortnight still renews itself, short enough that a certificate is not
    /// replaced for a third of its life. Configurable because a deployment
    /// issuing shorter certificates needs a shorter window — and because a
    /// renewal that only happens once a quarter is otherwise untestable
    /// without waiting a quarter.
    /// </remarks>
    public int RenewCertificateWithinDays { get; set; } = 30;
}
