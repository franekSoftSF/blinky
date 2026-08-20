using System.Diagnostics;
using Blinky.Piv.Pcsc;

namespace Blinky.Agent.Service;

/// <summary>
/// The agent's loop: make sure it has an identity, then keep telling the
/// backend what is in the readers.
/// </summary>
public sealed class AgentWorker(
    AgentOptions options,
    AgentIdentity identity,
    InventoryCollector collector,
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

        using var backend = new BackendClient(options.BackendUrl, options.AcceptAnyServerCertificate);

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

    private async Task<Guid> EnsureIdentityAsync(BackendClient backend, CancellationToken ct)
    {
        if (identity.Exists)
        {
            var existing = identity.ReadId();
            backend.Authenticate(identity.Load());

            logger.LogInformation("Using the existing identity {AgentId}", existing);
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

    private async Task PollAsync(BackendClient backend, Guid agentId, CancellationToken ct)
    {
        try
        {
            var sweep = collector.ReadAll();

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

    /// <summary>Development only: trust a self-signed backend certificate.</summary>
    public bool AcceptAnyServerCertificate { get; set; }

    public string? IdentityDirectory { get; set; }
}
