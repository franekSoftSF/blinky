namespace Blinky.Agent.Service;

/// <summary>
/// Claims jobs, drives the card, reports results. Skeleton until patch 0015.
/// </summary>
public sealed class AgentWorker(ILogger<AgentWorker> logger) : BackgroundService
{
    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        logger.LogInformation("Agent started (not yet enrolled, no reader watcher)");

        while (!stoppingToken.IsCancellationRequested)
        {
            await Task.Delay(TimeSpan.FromMinutes(1), stoppingToken);
        }
    }
}
